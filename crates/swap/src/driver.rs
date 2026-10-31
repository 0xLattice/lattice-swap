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
                    "{}: state version {version}, but this build reads only {STATE_VERSION}",
                    self.path.display()
                ),
            ));
        }
        serde_json::from_value(file["state"].take())
            .map(Some)
            .map_err(io::Error::other)
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
/// seller, refund for the buyer) is bumped by CPFP as soon as it is seen
/// unconfirmed, in the mempool or refused by it, if the node's estimate is
/// above its own feerate: a child spends its payout into the party's
/// bitcoind wallet, and the two go to the node as a package. While it waits
/// it is bumped again every `bump_after` blocks at the current estimate; a
/// new child replaces the last only if it pays more. A payout the wallet
/// cannot sign for is not bumped, and a failed bump is only logged. Cancel
/// pays both parties' 2-of-2 and is never bumped: a stuck cancel only
/// delays the swap. The wait is counted in memory, so after a restart a
/// waiting transaction is bumped at once.
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
    /// Blocks between bumps of a swap transaction still waiting; 0 bumps it
    /// at every new block.
    pub bump_after: u32,
    /// The feerate a bump pays for when the node has no estimate, as on
    /// regtest.
    pub fallback_fee_rate: FeeRate,
    /// The most a bump pays for: a higher estimate is clamped to it.
    pub max_fee_rate: FeeRate,
    /// Our swap transactions waiting unconfirmed, by txid, with the height
    /// at which this driver last bumped each, or first saw it wait.
    waiting: HashMap<Txid, u32>,
    /// Transactions broadcast since the last Bitcoin view.
    broadcast: Vec<Transaction>,
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
            bump_after: 3,
            fallback_fee_rate: FeeRate::from_sat_per_vb_u32(10),
            max_fee_rate: FeeRate::from_sat_per_vb_u32(1_000),
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
    /// the state, returning `None`.
    pub fn run_until(&mut self, stop: impl Fn(&M) -> bool) -> io::Result<Option<Outcome>> {
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
        let Some((swap, lock)) = self.state.watch().bitcoin else {
            return Ok(());
        };
        match bitcoin_view(&self.bitcoin, &swap, lock) {
            Ok(view) => {
                let height = view.height;
                let mut waiting: Vec<Transaction> = [&view.lock_spend, &view.cancel_spend]
                    .into_iter()
                    .flatten()
                    .filter(|spent| spent.confirmations == 0)
                    .map(|spent| spent.tx.clone())
                    .collect();
                self.apply(Event::Bitcoin(view))?;
                // What the machine broadcast was not in the view at all.
                waiting.append(&mut self.broadcast);
                self.bump(&swap, lock, height, waiting);
                Ok(())
            }
            Err(e) => {
                warn(&e.to_string());
                Ok(())
            }
        }
    }

    /// Bumps each of our swap transactions in `waiting` the first time it is
    /// seen, then once every `bump_after` blocks, never twice in a block,
    /// and forgets those no longer waiting.
    fn bump(&mut self, swap: &Swap, lock: OutPoint, height: u32, waiting: Vec<Transaction>) {
        let own: Vec<Txid> = self
            .state
            .own_spends()
            .iter()
            .map(|&spend| swap.unsigned_tx(lock, spend).compute_txid())
            .collect();
        let mut still = HashMap::new();
        for tx in waiting {
            let txid = tx.compute_txid();
            if !own.contains(&txid) || still.contains_key(&txid) {
                continue;
            }
            let since = match self.waiting.get(&txid) {
                Some(&since) if height < since + self.bump_after.max(1) => since,
                _ => {
                    self.bump_one(&tx, swap.params().fee);
                    height
                }
            };
            still.insert(txid, since);
        }
        self.waiting = still;
    }

    /// Bumps `tx`, which pays `fee`, to the node's estimate if that is above
    /// its own feerate.
    fn bump_one(&self, tx: &Transaction, fee: Amount) {
        let txid = tx.compute_txid();
        let rate = match self.bitcoin.fee_rate() {
            Ok(rate) => rate.unwrap_or(self.fallback_fee_rate),
            Err(e) => return warn(&format!("bump {txid}: {e}")),
        };
        let rate = if rate > self.max_fee_rate {
            warn(&format!(
                "bump {txid}: estimate {rate} clamped to max_fee_rate {}",
                self.max_fee_rate
            ));
            self.max_fee_rate
        } else {
            rate
        };
        if rate
            .fee_vb(tx.vsize() as u64)
            .is_none_or(|alone| alone <= fee)
        {
            return;
        }
        if let Err(e) = self.bitcoin.bump(tx, fee, rate) {
            warn(&format!("bump {txid}: {e}"));
        }
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
                if let Err(e) = self.bitcoin.broadcast(&tx) {
                    warn(&format!("broadcast {}: {e}", tx.compute_txid()));
                }
                self.broadcast.push(tx);
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
