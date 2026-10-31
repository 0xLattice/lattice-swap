//! Runs a [`Machine`] against real nodes and a real counterparty.

use std::collections::HashMap;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Write};
use std::mem::discriminant;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use bitcoin::{Amount, FeeRate, OutPoint, Transaction, Txid};
use swap_bitcoin::{Spend, Swap};
use swap_nexus_tx::rpc::Client;

use crate::bitcoind::{self, Bitcoin};
use crate::transport::Transport;
use crate::{Action, BitcoinView, Event, Machine, Message, NexusView, NexusWatch, Outcome};
use crate::{SecretBytes, Spent};

/// The format of a state file. A file of another version is refused: its
/// signatures may be over transactions this build no longer makes.
pub const STATE_VERSION: u32 = 2;

/// One JSON file per swap, replaced atomically: written to a temporary
/// file, synced, then renamed over the old one. It holds the party's
/// secrets, and [`STATE_VERSION`].
pub struct Store {
    path: PathBuf,
    swap_id: [u8; 32],
}

impl Store {
    pub fn new(directory: &Path, swap_id: [u8; 32]) -> Self {
        let path = directory.join(format!("{}.json", hex::encode(swap_id)));
        Self { path, swap_id }
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Saves the state of a new swap; fails if the file exists, so a swap
    /// started twice keeps its first secrets.
    fn create<M: Machine>(&self, state: &M) -> io::Result<()> {
        let temporary = self.write_temporary(state)?;
        // A hard link, unlike a rename, never replaces its target.
        let linked = fs::hard_link(&temporary, &self.path);
        fs::remove_file(&temporary)?;
        linked?;
        self.sync_directory()
    }

    /// Fails on a file of another [`STATE_VERSION`].
    pub fn load<M: Machine>(&self) -> io::Result<Option<M>> {
        match self.load_value()? {
            Some(state) => serde_json::from_value(state)
                .map(Some)
                .map_err(io::Error::other),
            None => Ok(None),
        }
    }

    /// The saved state as JSON, for a caller that reads it before it knows
    /// the machine, such as which side the swap is. Fails like [`load`] on
    /// a file of another [`STATE_VERSION`].
    ///
    /// [`load`]: Store::load
    pub fn load_value(&self) -> io::Result<Option<serde_json::Value>> {
        let bytes = match fs::read(&self.path) {
            Ok(bytes) => bytes,
            Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(None),
            Err(e) => return Err(e),
        };
        let mut file: serde_json::Value =
            serde_json::from_slice(&bytes).map_err(io::Error::other)?;
        let version = &file["version"];
        if version.as_u64() != Some(STATE_VERSION.into()) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!(
                    "{}: state version {version}, but this build reads only {STATE_VERSION}: \
                     finish the swap with the build that started it",
                    self.path.display()
                ),
            ));
        }
        Ok(Some(file["state"].take()))
    }

    fn save<M: Machine>(&self, state: &M) -> io::Result<()> {
        let temporary = self.write_temporary(state)?;
        fs::rename(&temporary, &self.path)?;
        self.sync_directory()
    }

    fn write_temporary<M: Machine>(&self, state: &M) -> io::Result<PathBuf> {
        let temporary = self.path.with_extension("json.tmp");
        let mut options = OpenOptions::new();
        options.write(true).create(true).truncate(true);
        #[cfg(unix)]
        std::os::unix::fs::OpenOptionsExt::mode(&mut options, 0o600);
        let mut file = options.open(&temporary)?;
        let file_state = serde_json::json!({"version": STATE_VERSION, "state": state});
        file.write_all(&serde_json::to_vec_pretty(&file_state).map_err(io::Error::other)?)?;
        file.sync_all()?;
        Ok(temporary)
    }

    /// A rename or link is durable once its directory is.
    fn sync_directory(&self) -> io::Result<()> {
        if let Some(directory) = self.path.parent() {
            File::open(directory)?.sync_all()?;
        }
        Ok(())
    }
}

/// Feeds a machine what its nodes and its counterparty show, and does what
/// it asks. The state is saved after every step that changes it, before
/// any of the step's actions, so nothing is sent, broadcast or submitted
/// that a restart would not know about.
///
/// A swap transaction that pays this party (redeem and punish for the
/// seller, refund for the buyer) is bumped by CPFP while it waits
/// unconfirmed, in the mempool or refused by it: a child spends its payout
/// into the party's bitcoind wallet, and the two go to the node as a
/// package. Its target feerate is the node's estimate, a conservative one
/// within `margin` blocks of the spend's deadline (`t1` for redeem, `t2`
/// for refund), and for a transaction the mempool refused at least
/// [`Bitcoin::floor`]: enough to get in, replacing a conflicting package
/// such as the seller's punish against our refund. The target is read when
/// the transaction is first seen, at every new block, and whenever the
/// mempool newly refuses it. A transaction in the mempool is bumped
/// whenever the target is above its own feerate and above the last bump's,
/// whose child the new one replaces; a refused one, which needs a package
/// whatever its own feerate, whenever the target is above the last bump's.
/// A bump that fails, as for a payout the wallet cannot sign for, is
/// logged and tried again at the next block. Cancel pays both parties'
/// 2-of-2 and is never bumped: a stuck cancel only delays the swap. The
/// last bumps are kept in memory, so after a restart a waiting transaction
/// is bumped at once, unless the package a child already made with it in
/// the mempool, as one bumped before the restart, pays the target.
///
/// The buyer is safe only while its refund confirms before `t2`; after it,
/// contesting the seller's punish is best effort. The punish leaf takes
/// the seller's signature alone, so the seller can spend the cancel output
/// with a transaction of any shape: a version 2 one with two children
/// cannot be replaced at any fee. The caps below bound what this party
/// pays.
pub struct Driver<M, B, T> {
    state: M,
    bitcoin: B,
    nexus: Client,
    /// `None` once the session failed; the swap goes on from the chains.
    transport: Option<T>,
    store: Store,
    /// How long one round waits for a message; also the polling interval.
    pub poll: Duration,
    /// How long a counterparty may stay quiet before anything is at stake.
    pub message_timeout: Duration,
    /// The seller's Nexus wallet key, which signs the NEX lock: set it
    /// before running a seller. Kept here and never in the state file.
    pub nex_key: Option<SecretBytes>,
    /// The feerate a bump pays for when the node has no estimate, as on
    /// regtest.
    pub fallback_fee_rate: FeeRate,
    /// The most a bump pays for: a higher target is clamped to it. For a
    /// small swap this binds after `max_fee_fraction` does, if at all: a
    /// rate cap knows nothing of what the payout is worth.
    pub max_fee_rate: FeeRate,
    /// The share of a spend's payout its child may pay in fees, from 0 to
    /// 1; [`Driver::run_until`] refuses any other value. The default, all
    /// of it but dust, holds for every spend this driver bumps: a redeem
    /// once broadcast may be in some mempool, so `s` may be public, and
    /// losing it then loses the BTC and the NEX; a refund lost to punish
    /// loses the BTC; and the seller bumps punish only while no refund
    /// shows, when the buyer is away and the NEX it locked is out of reach
    /// anyway. Any BTC kept beats none.
    pub max_fee_fraction: f64,
    /// Our swap transactions waiting unconfirmed, by txid.
    waiting: HashMap<Txid, Waiting>,
    /// Transactions broadcast since the last Bitcoin view, and whether the
    /// node refused each.
    broadcast: Vec<(Transaction, bool)>,
}

impl<M: Machine, B: Bitcoin, T: Transport> Driver<M, B, T> {
    /// A new swap: saves `state` and carries out `actions` (the buyer's
    /// hello). Fails if `store` already holds a swap.
    pub fn start(
        state: M,
        actions: Vec<Action>,
        bitcoin: B,
        nexus: Client,
        transport: Option<T>,
        store: Store,
    ) -> io::Result<Self> {
        store.create(&state)?;
        let mut driver = Self::with(state, bitcoin, nexus, transport, store);
        for action in actions {
            driver.act(action)?;
        }
        Ok(driver)
    }

    /// The swap saved in `store`, carried on from where it stopped.
    pub fn resume(
        bitcoin: B,
        nexus: Client,
        transport: Option<T>,
        store: Store,
    ) -> io::Result<Self> {
        let state = store
            .load()?
            .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "no saved swap"))?;
        Ok(Self::with(state, bitcoin, nexus, transport, store))
    }

    fn with(state: M, bitcoin: B, nexus: Client, transport: Option<T>, store: Store) -> Self {
        Self {
            state,
            bitcoin,
            nexus,
            transport,
            store,
            poll: Duration::from_millis(250),
            message_timeout: Duration::from_secs(60),
            nex_key: None,
            fallback_fee_rate: FeeRate::from_sat_per_vb_u32(10),
            max_fee_rate: FeeRate::from_sat_per_vb_u32(1_000),
            max_fee_fraction: 1.0,
            waiting: HashMap::new(),
            broadcast: vec![],
        }
    }

    pub fn state(&self) -> &M {
        &self.state
    }

    pub fn run(&mut self) -> io::Result<Outcome> {
        let outcome = self.run_until(|_| false)?;
        Ok(outcome.expect("only an outcome ends an unconditional run"))
    }

    /// Runs until the swap ends, returning how, or until `stop` holds for
    /// the state, returning `None`. Fails at once if `max_fee_fraction` is
    /// not between 0 and 1.
    pub fn run_until(&mut self, stop: impl Fn(&M) -> bool) -> io::Result<Option<Outcome>> {
        if !(0.0..=1.0).contains(&self.max_fee_fraction) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!(
                    "max_fee_fraction {} is not between 0 and 1",
                    self.max_fee_fraction
                ),
            ));
        }
        let mut since = Instant::now();
        let mut kind = discriminant(&self.state);
        loop {
            if let Some(outcome) = self.state.outcome() {
                return Ok(Some(outcome));
            }
            if stop(&self.state) {
                return Ok(None);
            }
            if let Some(message) = self.receive() {
                self.apply(Event::Message(message))?;
            }
            if self.state.awaits_message() && since.elapsed() > self.message_timeout {
                self.apply(Event::Timeout)?;
            }
            self.observe_bitcoin()?;
            self.observe_nexus()?;
            if discriminant(&self.state) != kind {
                kind = discriminant(&self.state);
                since = Instant::now();
            }
        }
    }

    fn receive(&mut self) -> Option<Message> {
        let Some(transport) = &mut self.transport else {
            std::thread::sleep(self.poll);
            return None;
        };
        match transport.recv(self.poll) {
            Ok(Some(bytes)) => {
                let message = Message::decode(&bytes, self.store.swap_id);
                if message.is_none() {
                    warn("dropped a message that is not for this swap");
                }
                message
            }
            Ok(None) => None,
            Err(e) => {
                warn(&format!("session ended: {e}"));
                self.transport = None;
                None
            }
        }
    }

    fn observe_bitcoin(&mut self) -> io::Result<()> {
        let watch = self.state.watch();
        let Some((swap, lock)) = watch.bitcoin else {
            return Ok(());
        };
        match bitcoin_view(&self.bitcoin, &swap, lock) {
            Ok(view) => {
                let height = view.height;
                let urgent = urgent(&swap, lock, &view, watch.margin);
                let mut waiting: Vec<(Transaction, bool)> = [&view.lock_spend, &view.cancel_spend]
                    .into_iter()
                    .flatten()
                    .filter(|spent| spent.confirmations == 0)
                    .map(|spent| (spent.tx.clone(), false))
                    .collect();
                self.apply(Event::Bitcoin(view))?;
                // What the machine broadcast was not in the view at all.
                waiting.append(&mut self.broadcast);
                self.bump(&swap, lock, height, &urgent, waiting);
                Ok(())
            }
            Err(e) => {
                warn(&e.to_string());
                Ok(())
            }
        }
    }

    /// Bumps each of our swap transactions in `waiting`, each marked with
    /// whether the mempool refused it, when its target is due and above the
    /// last bump's, and forgets those no longer waiting. `urgent` are the
    /// spends near their deadline.
    fn bump(
        &mut self,
        swap: &Swap,
        lock: OutPoint,
        height: u32,
        urgent: &[Spend],
        waiting: Vec<(Transaction, bool)>,
    ) {
        let own: Vec<(Txid, Spend)> = self
            .state
            .own_spends()
            .iter()
            .map(|&spend| (swap.unsigned_tx(lock, spend).compute_txid(), spend))
            .collect();
        let mut still = HashMap::new();
        for (tx, refused) in waiting {
            let txid = tx.compute_txid();
            let Some(&(_, spend)) = own.iter().find(|(own, _)| *own == txid) else {
                continue;
            };
            if still.contains_key(&txid) {
                continue;
            }
            let last = self.waiting.get(&txid).copied();
            let urgent = urgent.contains(&spend);
            // A failure is tried again at the next block, or, a few times, at
            // the next poll once a deadline is near: a block may be all that
            // is left.
            let due = last.is_none_or(|last| {
                height > last.height
                    || refused && !last.refused
                    || last.failed && urgent && last.retries < URGENT_RETRIES
            });
            let mut now = last.unwrap_or(Waiting {
                height,
                refused,
                rate: FeeRate::ZERO,
                failed: false,
                retries: 0,
                clamped: None,
            });
            now.refused = refused;
            if due {
                now.retries = match last {
                    Some(last) if last.height == height => last.retries.saturating_add(1),
                    _ => 0,
                };
                now.height = height;
                let fee = swap.fee(spend);
                let result = match self.target(&tx, fee, refused, urgent, &mut now.clamped) {
                    Ok(Some(rate)) if rate > now.rate => match self.bitcoin.package_rate(&tx) {
                        Ok(Some(pooled)) if pooled >= rate => Ok(pooled),
                        Ok(_) => self.bump_one(&tx, fee, rate).map(|()| rate),
                        Err(e) => Err(e),
                    },
                    Ok(_) => Ok(now.rate),
                    Err(e) => Err(e),
                };
                match result {
                    Ok(rate) => {
                        now.rate = rate;
                        now.failed = false;
                    }
                    // Logged once, then tried again quietly at every block.
                    Err(e) => {
                        if !now.failed {
                            warn(&format!("bump {txid}: {e}"));
                        }
                        now.failed = true;
                    }
                }
            }
            still.insert(txid, now);
        }
        self.waiting = still;
    }

    /// The feerate to raise `tx`, which pays `fee`, to, clamped to
    /// `max_fee_rate`; `None` if `tx` is in the mempool and already pays it
    /// alone. A refused `tx` needs a package whatever it pays. A clamp is
    /// logged once per target, the last kept in `clamped`.
    fn target(
        &self,
        tx: &Transaction,
        fee: Amount,
        refused: bool,
        urgent: bool,
        clamped: &mut Option<FeeRate>,
    ) -> bitcoind::Result<Option<FeeRate>> {
        let mut rate = self
            .bitcoin
            .fee_rate(urgent)?
            .unwrap_or(self.fallback_fee_rate);
        if refused {
            rate = rate.max(self.bitcoin.floor(tx)?);
        }
        if rate > self.max_fee_rate {
            if *clamped != Some(rate) {
                warn(&format!(
                    "bump {}: target {rate} clamped to max_fee_rate {}",
                    tx.compute_txid(),
                    self.max_fee_rate
                ));
            }
            *clamped = Some(rate);
            rate = self.max_fee_rate;
        }
        let alone = rate.fee_vb(tx.vsize() as u64);
        Ok((refused || alone.is_some_and(|alone| alone > fee)).then_some(rate))
    }

    /// Bumps `tx`, which pays `fee`, to `rate`, its child paying at most
    /// `max_fee_fraction` of the payout.
    fn bump_one(&self, tx: &Transaction, fee: Amount, rate: FeeRate) -> bitcoind::Result<()> {
        let payout = tx.output[0].value.to_sat() as f64;
        let max = Amount::from_sat((payout * self.max_fee_fraction) as u64);
        self.bitcoin.bump(tx, fee, rate, max).map(drop)
    }

    fn observe_nexus(&mut self) -> io::Result<()> {
        let Some(watch) = self.state.watch().nexus else {
            return Ok(());
        };
        match nexus_view(&self.nexus, &watch) {
            Ok(Some(view)) => self.apply(Event::Nexus(view)),
            // The tip moved while the view was read: read again next time.
            Ok(None) => Ok(()),
            Err(e) => {
                warn(&format!("nexus: {e}"));
                Ok(())
            }
        }
    }

    fn apply(&mut self, event: Event) -> io::Result<()> {
        let (next, actions) = self.state.clone().step(event);
        if serde_json::to_value(&next)? != serde_json::to_value(&self.state)? {
            self.store.save(&next)?;
        }
        self.state = next;
        for action in actions {
            self.act(action)?;
        }
        Ok(())
    }

    fn act(&mut self, action: Action) -> io::Result<()> {
        match action {
            Action::Send(message) => {
                if let Some(transport) = &mut self.transport {
                    match transport.send(&message.encode(self.store.swap_id)) {
                        Ok(()) => self.apply(Event::Sent)?,
                        Err(e) => {
                            warn(&format!("session ended: {e}"));
                            self.transport = None;
                        }
                    }
                }
            }
            Action::FundLock {
                script_pubkey,
                amount,
            } => {
                // Before anything is at stake: a wallet that cannot fund
                // ends the swap.
                let funding = self
                    .bitcoin
                    .fund_lock(&script_pubkey, amount)
                    .map_err(io::Error::other)?;
                self.apply(Event::Funded(funding))?;
            }
            Action::Broadcast(tx) => {
                let refused = match self.bitcoin.broadcast(&tx) {
                    Ok(()) => false,
                    Err(e) => {
                        warn(&format!("broadcast {}: {e}", tx.compute_txid()));
                        true
                    }
                };
                self.broadcast.push((tx, refused));
            }
            Action::SignNex(body) => match &self.nex_key {
                Some(key) => {
                    let mut transaction = swap_nexus_tx::Transaction::new(body);
                    transaction.sign(&key.signing_key());
                    self.apply(Event::NexSigned(transaction))?;
                }
                None => warn("no Nexus key to sign with"),
            },
            // The machine watches the transaction by its CID: the answer
            // adds nothing.
            Action::Submit(transaction) => {
                if let Err(e) = self.nexus.submit(&transaction) {
                    warn(&format!("nexus submit {}: {e}", transaction.cid()));
                }
            }
        }
        Ok(())
    }
}

/// How many times a failed bump near its deadline is tried again within one
/// block, a poll apart.
pub(crate) const URGENT_RETRIES: u8 = 8;

/// A swap transaction of ours waiting unconfirmed.
#[derive(Clone, Copy)]
struct Waiting {
    /// The tip when its target was last read.
    height: u32,
    /// Whether the mempool refused it at the last view.
    refused: bool,
    /// What the last bump that went through raised it to.
    rate: FeeRate,
    /// Whether the last attempt to bump it failed: it is tried again.
    failed: bool,
    /// Attempts since the first at `height`.
    retries: u8,
    /// The last target clamped to `max_fee_rate`, already logged.
    clamped: Option<FeeRate>,
}

/// Our spends within `margin` blocks of their deadline: redeem once the
/// lock is `t1 - margin` deep, refund once cancel is `t2 - margin` deep.
fn urgent(swap: &Swap, lock: OutPoint, view: &BitcoinView, margin: u16) -> Vec<Spend> {
    let near = |depth: Option<u32>, deadline: u16| {
        depth.is_some_and(|depth| depth + u32::from(margin) >= u32::from(deadline))
    };
    let cancel = swap.unsigned_tx(lock, Spend::Cancel).compute_txid();
    let cancel_depth = view
        .lock_spend
        .as_ref()
        .filter(|spent| spent.tx.compute_txid() == cancel && spent.confirmations > 0)
        .map(|spent| spent.confirmations);
    let p = swap.params();
    [
        (Spend::Redeem, near(view.funding, p.t1)),
        (Spend::Refund, near(cancel_depth, p.t2)),
    ]
    .into_iter()
    .filter_map(|(spend, near)| near.then_some(spend))
    .collect()
}

fn warn(what: &str) {
    eprintln!("lattice-swap: {what}");
}

/// Only the swap's own transactions can spend the lock output, and their
/// txids are fixed before any is signed, so each is looked up by txid. The
/// same holds for the cancel output but for punish: its leaf takes the
/// seller's signature alone, so the seller can spend through it with any
/// transaction. Only when cancel is in a block, neither refund nor punish
/// shows, and the cancel output is spent anyway, is the spender searched
/// for.
pub fn bitcoin_view(
    bitcoin: &impl Bitcoin,
    swap: &Swap,
    lock: OutPoint,
) -> bitcoind::Result<BitcoinView> {
    let height = bitcoin.height()?;
    let funding = bitcoin.transaction(lock.txid)?.map(|(_, depth)| depth);
    let spent = |spends: [Spend; 2]| -> bitcoind::Result<Option<Spent>> {
        for spend in spends {
            let txid = swap.unsigned_tx(lock, spend).compute_txid();
            if let Some((tx, confirmations)) = bitcoin.transaction(txid)? {
                return Ok(Some(Spent { tx, confirmations }));
            }
        }
        Ok(None)
    };
    let lock_spend = spent([Spend::Redeem, Spend::Cancel])?;
    let mut cancel_spend = spent([Spend::Refund, Spend::Punish])?;
    let cancel = swap.unsigned_tx(lock, Spend::Cancel).compute_txid();
    if let Some(Spent { tx, confirmations }) = &lock_spend {
        if cancel_spend.is_none() && *confirmations > 0 && tx.compute_txid() == cancel {
            // Punish can be mined no earlier than `t2` blocks after cancel.
            let mined = (height + 1).saturating_sub(*confirmations);
            let from = mined + u32::from(swap.params().t2);
            cancel_spend = bitcoin
                .spender(OutPoint::new(cancel, 0), from)?
                .map(|(tx, confirmations)| Spent { tx, confirmations });
        }
    }
    Ok(BitcoinView {
        height,
        funding,
        lock_spend,
        cancel_spend,
    })
}

/// The lock account is read before the watched transaction: a lock that
/// has signed something, read first, shows that transaction mined in the
/// later read if it is ours. The view is one tip's: `None` if the tip
/// moved while it was read, so no read in it comes from another block.
/// That needs the operator port, whose `/health` is never cached; a public
/// read port caches it, and would let the reads straddle two tips.
fn nexus_view(
    client: &Client,
    watch: &NexusWatch,
) -> swap_nexus_tx::rpc::Result<Option<NexusView>> {
    let health = client.health()?;
    let own = client.account(&watch.own_address)?;
    let lock = client.account(&watch.lock_address)?;
    let min_relay_fee = client.min_relay_fee()?;
    let watched = match &watch.cid {
        Some(cid) => match client.transaction(cid)? {
            Some(transaction) => Some((transaction, client.confirmations(cid)?)),
            None => None,
        },
        None => None,
    };
    let block_at = match watch.block_at {
        Some(height) => client.block_hash(height)?,
        None => None,
    };
    let after = client.health()?;
    if (after.height, &after.tip) != (health.height, &health.tip) {
        return Ok(None);
    }
    Ok(Some(NexusView {
        health,
        own,
        lock,
        min_relay_fee,
        watched,
        block_at,
    }))
}
