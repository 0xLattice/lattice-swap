//! Runs a [`Machine`] against real nodes and a real counterparty.

use std::collections::HashMap;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Write};
use std::mem::discriminant;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use bitcoin::{Amount, BlockHash, FeeRate, OutPoint, Transaction, Txid};
use swap_bitcoin::{Spend, Swap};
use swap_nexus_tx::rpc::Client;

use crate::bitcoind::{self, Bitcoin};
use crate::transport::Transport;
use crate::{view, SecretBytes, Spent};
use crate::{Action, BitcoinView, Event, Machine, Message, NexusView, NexusWatch, Outcome, Rejoin};

pub use crate::STATE_VERSION;

/// One JSON file per swap, replaced atomically: written to a temporary
/// file, synced, then renamed over the old one. It holds the party's
/// secrets, and [`STATE_VERSION`]. A driver holds an exclusive lock on a
/// sibling `.lock` file for as long as it runs, so no two run one swap.
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

    /// Locks the swap for this process until the file returned is dropped;
    /// fails if another holds it.
    fn lock(&self) -> io::Result<File> {
        let path = self.path.with_extension("lock");
        let mut options = OpenOptions::new();
        options.write(true).create(true).truncate(false);
        #[cfg(unix)]
        std::os::unix::fs::OpenOptionsExt::mode(&mut options, 0o600);
        let file = options.open(&path)?;
        match file.try_lock() {
            Ok(()) => Ok(file),
            Err(fs::TryLockError::WouldBlock) => Err(io::Error::new(
                io::ErrorKind::WouldBlock,
                format!(
                    "{} is in use: another lattice-swap runs this swap",
                    self.path.display()
                ),
            )),
            Err(fs::TryLockError::Error(e)) => Err(e),
        }
    }

    /// Saves the state of a new swap; fails if the file exists, so a swap
    /// started twice keeps its first secrets.
    pub fn create<M: Machine>(&self, state: &M) -> io::Result<()> {
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
        let mut file = create_temporary(&temporary)?;
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

/// `temporary` made anew, readable by its owner alone. One left by a crash,
/// or planted: removed, never followed. A new file, made here, is the only
/// one written; anything put back in between fails the open.
pub(crate) fn create_temporary(temporary: &Path) -> io::Result<File> {
    match fs::remove_file(temporary) {
        Err(e) if e.kind() != io::ErrorKind::NotFound => return Err(e),
        _ => {}
    }
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    std::os::unix::fs::OpenOptionsExt::mode(&mut options, 0o600);
    options.open(temporary)
}

/// Answers at once: a new session given how to meet ([`Rejoin`]) once one
/// is open, why an attempt failed once one has, or else nothing yet. See
/// [`Driver::reconnect`].
pub type Reconnect<T> = Box<dyn FnMut(&Rejoin) -> Option<io::Result<T>> + Send>;

/// Why the Nexus node will not do yet, if it will not: see
/// [`Driver::nexus_check`].
pub type NexusCheck = Box<dyn FnMut(&Client) -> Result<(), String> + Send>;

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
    /// `None` once the session failed; the swap goes on from the chains,
    /// and from `reconnect`, if set, while the machine still needs one.
    transport: Option<T>,
    /// A new session to the counterparty, while the machine has none and
    /// [`Machine::rejoin`] asks for one. Each new one is first sent
    /// [`Machine::resend`]; a failed attempt is logged, as the views' are.
    /// See [`crate::transport::in_background`].
    pub reconnect: Option<Reconnect<T>>,
    /// Asked of the Nexus node at every read of the chains, after Bitcoin's,
    /// while set: a swap resumed reads Nexus only while its node passes, so
    /// nothing is concluded from a node on another Nexus, or one that keeps
    /// no past state, and a node that fails a moment fails no Bitcoin spend.
    /// A failure skips the round's Nexus view, and is warned of as a failing
    /// view is; the round that passes again says so.
    pub nexus_check: Option<NexusCheck>,
    /// The genesis of the Nexus the node must follow, compared on every
    /// view, while set: the view of a node on another Nexus is skipped as
    /// a failed [`Driver::nexus_check`] is. Read from the `/api/chain/info`
    /// the view reads anyway.
    pub nexus_genesis: Option<String>,
    /// Why the last Nexus read failed, worded as it is logged, while it
    /// fails; cleared once a read passes, or while Nexus is not watched.
    /// For an app's status to show, as the browser's driver shows it.
    pub nexus_warning: Arc<Mutex<Option<String>>>,
    /// How long a round's Nexus check, view and the submits it leads to
    /// may take: every request ends by then, and one past it is not asked,
    /// so a slow or silent Nexus node delays the next Bitcoin round by this
    /// at most. A submit cut short is asked again at the next view.
    pub nexus_budget: Duration,
    /// When the round under way must be done with Nexus by, while it reads
    /// it.
    nexus_round: Option<Instant>,
    store: Store,
    /// The least time between two reads of the chains. Messages are taken
    /// as they come in between: however many the counterparty sends, the
    /// nodes are read no more often, so it cannot spend their rate limits.
    pub poll: Duration,
    /// How long a counterparty may stay quiet before anything is at stake.
    pub message_timeout: Duration,
    /// The seller's Nexus wallet key, which signs the NEX lock: set it
    /// before running a seller. Kept here and never in the state file.
    pub nex_key: Option<SecretBytes>,
    /// The feerate a bump, and the lock funding, pays for when the node has
    /// no estimate, as on regtest or a freshly synced node.
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
    /// loses the BTC; and the seller bumps punish only from `t2`, against
    /// no refund or one only in the mempool, which missed `t2`: lost, that
    /// BTC is the buyer's while the NEX may be too. Any BTC kept beats
    /// none.
    pub max_fee_fraction: f64,
    /// The oldest a Bitcoin tip may be for a view not to be stale: see
    /// [`bitcoin_view`]. A node that stalled, or that someone cut off from
    /// the network, shows the redeem window still open after it closed: on
    /// a stale view the seller starts no redeem and locks no NEX, and the
    /// driver warns, once it has lasted [`WARN_AGAIN`] and again every
    /// [`WARN_AGAIN`], until the node catches up. Every other spend, and
    /// every bump, goes on: a stale view at worst delays them.
    pub max_tip_age: Duration,
    /// The time now: the clock a tip is aged by, and stale or failing views
    /// are timed by. The system's; tests set their own.
    pub clock: fn() -> SystemTime,
    /// Our swap transactions waiting unconfirmed, by txid.
    waiting: HashMap<Txid, Waiting>,
    /// Transactions broadcast since the last Bitcoin view, and whether the
    /// node refused each.
    broadcast: Vec<(Transaction, bool)>,
    /// The last failure to read a Bitcoin view, or why the views are
    /// stale, and when it was logged.
    view_failed: Option<(String, SystemTime)>,
    /// Since when the Bitcoin views have been stale.
    stale_since: Option<SystemTime>,
    /// The last failure to submit a Nexus transaction, and when it was
    /// logged.
    submit_failed: Option<(String, SystemTime)>,
    /// The last failed attempt to rejoin, and when it was logged.
    rejoin_failed: Option<(String, SystemTime)>,
    /// The last failure of `nexus_check`, and when it was logged.
    check_failed: Option<(String, SystemTime)>,
    /// The tip, and when this driver first saw it, in seconds since the
    /// Unix epoch. Kept in memory only: after a restart, the tip is first
    /// seen then.
    first_seen: Option<(BlockHash, u64)>,
    /// The punish's child as last read, and the tip it was read at.
    punish_child: Option<(BlockHash, Option<Spent>)>,
    /// Held while the driver lives: see [`Store`].
    _lock: File,
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
        let lock = store.lock()?;
        store.create(&state)?;
        let mut driver = Self::with(state, bitcoin, nexus, transport, store, lock);
        for action in actions {
            driver.act(action)?;
        }
        Ok(driver)
    }

    /// The swap saved in `store`, carried on from where it stopped
    /// ([`Machine::resumed`]).
    pub fn resume(
        bitcoin: B,
        nexus: Client,
        transport: Option<T>,
        store: Store,
    ) -> io::Result<Self> {
        let lock = store.lock()?;
        let state: M = store
            .load()?
            .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "no saved swap"))?;
        Ok(Self::with(
            state.resumed(),
            bitcoin,
            nexus,
            transport,
            store,
            lock,
        ))
    }

    fn with(
        state: M,
        bitcoin: B,
        nexus: Client,
        transport: Option<T>,
        store: Store,
        lock: File,
    ) -> Self {
        Self {
            state,
            bitcoin,
            nexus,
            transport,
            reconnect: None,
            nexus_check: None,
            nexus_genesis: None,
            nexus_warning: Arc::default(),
            nexus_budget: NEXUS_BUDGET,
            nexus_round: None,
            store,
            poll: Duration::from_millis(250),
            message_timeout: Duration::from_secs(60),
            nex_key: None,
            fallback_fee_rate: FeeRate::from_sat_per_vb_u32(10),
            max_fee_rate: FeeRate::from_sat_per_vb_u32(1_000),
            max_fee_fraction: 1.0,
            max_tip_age: Duration::from_secs(90 * 60),
            clock: SystemTime::now,
            waiting: HashMap::new(),
            broadcast: vec![],
            view_failed: None,
            stale_since: None,
            submit_failed: None,
            rejoin_failed: None,
            check_failed: None,
            first_seen: None,
            punish_child: None,
            _lock: lock,
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
        let mut read_at = Instant::now();
        loop {
            if let Some(outcome) = self.state.outcome() {
                return Ok(Some(outcome));
            }
            if stop(&self.state) {
                return Ok(None);
            }
            self.rejoin()?;
            if let Some(message) = self.receive(read_at.saturating_duration_since(Instant::now())) {
                self.apply(Event::Message(message))?;
            }
            if self.state.awaits_message() && since.elapsed() > self.message_timeout {
                self.apply(Event::Timeout)?;
            }
            if Instant::now() >= read_at {
                self.observe_bitcoin()?;
                self.observe_nexus()?;
                read_at = Instant::now() + self.poll;
            }
            if discriminant(&self.state) != kind {
                kind = discriminant(&self.state);
                since = Instant::now();
            }
        }
    }

    /// Takes a new session from `reconnect` while the machine needs one
    /// and has none, and sends again what the counterparty may have missed.
    fn rejoin(&mut self) -> io::Result<()> {
        let (None, Some(reconnect)) = (&self.transport, &mut self.reconnect) else {
            return Ok(());
        };
        let Some(rejoin) = self.state.rejoin() else {
            return Ok(());
        };
        match reconnect(&rejoin) {
            None => {}
            Some(Err(e)) => warn_again(
                &mut self.rejoin_failed,
                format!("rejoin: {e}"),
                (self.clock)(),
            ),
            Some(Ok(transport)) => {
                warn("session rejoined");
                self.rejoin_failed = None;
                self.transport = Some(transport);
                if let Some(message) = self.state.resend() {
                    self.act(Action::Send(message))?;
                }
            }
        }
        Ok(())
    }

    /// A message, if one comes within `wait`.
    fn receive(&mut self, wait: Duration) -> Option<Message> {
        let Some(transport) = &mut self.transport else {
            std::thread::sleep(wait);
            return None;
        };
        match transport.recv(wait) {
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
        let now = (self.clock)();
        let view = bitcoin_view(
            &self.bitcoin,
            &swap,
            lock,
            self.max_tip_age,
            now,
            &mut self.first_seen,
        );
        match view {
            // The tip moved while the view was read: read again next round.
            Ok(None) => Ok(()),
            Ok(Some(mut view)) => {
                // Read once a tip, and only for the seller, whose loss it
                // counts: a search walks blocks.
                if self.state.own_spends().contains(&Spend::Punish) {
                    let tip = self.first_seen.map(|(hash, _)| hash);
                    match &self.punish_child {
                        Some((at, child)) if Some(*at) == tip => view.punish_child = child.clone(),
                        _ => match punish_child(&self.bitcoin, &swap, lock, &view) {
                            Ok(child) => {
                                view.punish_child = child.clone();
                                self.punish_child = tip.map(|tip| (tip, child));
                            }
                            // The rest of the view still stands: the seller
                            // weighs giving `s` once the child is read.
                            Err(e) => {
                                warn_again(&mut self.view_failed, e.to_string(), now);
                                view.punish_child_unread = true;
                            }
                        },
                    }
                }
                match &view.stale {
                    // A node lags its headers for a moment at every block:
                    // logged only once it lasts.
                    Some(why) => {
                        let since = *self.stale_since.get_or_insert(now);
                        if elapsed(since, now) >= WARN_AGAIN {
                            warn_again(&mut self.view_failed, why.clone(), now);
                        }
                    }
                    None => {
                        self.stale_since = None;
                        // A failed read of the child is warned of again
                        // only after a while.
                        if !view.punish_child_unread {
                            self.view_failed = None;
                        }
                    }
                }
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
                warn_again(&mut self.view_failed, e.to_string(), now);
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
            // Near its deadline, a failure or a clamp is logged again at
            // every block, not only once.
            let again = urgent && last.is_none_or(|last| height > last.height);
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
                let clamped = &mut now.clamped;
                let result = match self.target(&tx, fee, refused, urgent, again, clamped) {
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
                    // Logged once, then tried again quietly at every block
                    // until the deadline nears.
                    Err(e) => {
                        if !now.failed || again {
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
    /// logged once per target, the last kept in `clamped`, and `again`.
    fn target(
        &self,
        tx: &Transaction,
        fee: Amount,
        refused: bool,
        urgent: bool,
        again: bool,
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
            if *clamped != Some(rate) || again {
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
            self.warn_nexus(None);
            return Ok(());
        };
        self.nexus_round = Some(Instant::now() + self.nexus_budget);
        self.nexus.set_deadline(self.nexus_round);
        let observed = self.read_nexus(watch);
        self.nexus_round = None;
        self.nexus.set_deadline(None);
        observed
    }

    /// The round's Nexus check and view of `watch`, and what they lead to,
    /// under [`Driver::nexus_budget`].
    fn read_nexus(&mut self, watch: NexusWatch) -> io::Result<()> {
        let genesis = self.nexus_genesis.as_deref();
        let read = match &mut self.nexus_check {
            Some(check) => check(&self.nexus).map(|()| nexus_view(&self.nexus, &watch, genesis)),
            None => Ok(nexus_view(&self.nexus, &watch, genesis)),
        };
        match read {
            Err(e) | Ok(Ok(Err(e))) => {
                let e = format!("nexus: {e}: Nexus is not read until it passes; Bitcoin goes on");
                self.warn_nexus(Some(e.clone()));
                warn_again(&mut self.check_failed, e, (self.clock)());
                Ok(())
            }
            Ok(Err(e)) => {
                let e = format!("nexus: {e}");
                warn(&e);
                self.warn_nexus(Some(e));
                Ok(())
            }
            Ok(Ok(Ok(view))) => {
                self.warn_nexus(None);
                if self.check_failed.take().is_some() {
                    warn("nexus: the node passes its check: Nexus is read again");
                }
                match view {
                    Some(view) => self.apply(Event::Nexus(view)),
                    // The tip moved while the view was read: read again next
                    // time.
                    None => Ok(()),
                }
            }
        }
    }

    fn warn_nexus(&self, warning: Option<String>) {
        // Poisoned or not, the swap goes on.
        *self.nexus_warning.lock().unwrap_or_else(|p| p.into_inner()) = warning;
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
                // ends the swap. Funded at bitcoind's estimate, else the
                // fallback rate, never below the node's mempool minimum,
                // and not capped by `max_fee_rate`. Never the wallet's own
                // estimate: a fresh node has none, and without
                // `-fallbackfee` its wallet then funds nothing.
                let funding = self
                    .bitcoin
                    .fee_rate(false)
                    .map(|estimate| estimate.unwrap_or(self.fallback_fee_rate))
                    .and_then(|rate| self.bitcoin.fund_lock(&script_pubkey, amount, rate))
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
            // adds nothing. Bounded by what is left of the round's Nexus
            // budget, as its view led to it; else by a budget of its own.
            Action::Submit(transaction) => {
                let round = self.nexus_round;
                let deadline = round.unwrap_or_else(|| Instant::now() + self.nexus_budget);
                self.nexus.set_deadline(Some(deadline));
                let submitted = self.nexus.submit(&transaction);
                self.nexus.set_deadline(round);
                match submitted {
                    Ok(_) => self.submit_failed = None,
                    Err(e) => {
                        let e = format!("nexus submit {}: {e}", transaction.cid());
                        // Cut short by the round's budget, which reads left
                        // too little of.
                        let e = match self.nexus_round {
                            Some(end) if Instant::now() >= end => {
                                format!("{e}; raise the Nexus budget (--nexus-budget)")
                            }
                            _ => e,
                        };
                        warn_again(&mut self.submit_failed, e, (self.clock)());
                    }
                }
            }
        }
        Ok(())
    }
}

/// [`Driver::nexus_budget`]'s default: time for a view's dozen reads of a
/// public node across the internet, a few hundred milliseconds each, and a
/// submit, and little next to a Bitcoin block. A node farther away, as over
/// Tor, may need more: its views fail, and Nexus is not read, until the
/// budget is raised.
pub const NEXUS_BUDGET: Duration = Duration::from_secs(10);

/// How many times a failed bump near its deadline is tried again within one
/// block, a poll apart.
pub(crate) const URGENT_RETRIES: u8 = 8;

/// How often a failure to read a Bitcoin view, or to submit a Nexus
/// transaction, that lasts is logged again, and how long stale views last
/// before they are logged.
pub(crate) const WARN_AGAIN: Duration = Duration::from_secs(60);

/// Logs `e` when it differs from `last`, and again every [`WARN_AGAIN`]
/// while it lasts.
fn warn_again(last: &mut Option<(String, SystemTime)>, e: String, now: SystemTime) {
    let again = last
        .as_ref()
        .is_none_or(|(last, at)| *last != e || elapsed(*at, now) >= WARN_AGAIN);
    if again {
        warn(&e);
        *last = Some((e, now));
    }
}

/// The time from `since` to `now`; none if the clock went back.
fn elapsed(since: SystemTime, now: SystemTime) -> Duration {
    now.duration_since(since).unwrap_or_default()
}

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
        depth.is_some_and(|depth| depth.saturating_add(margin.into()) >= u32::from(deadline))
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
    #[cfg(test)]
    WARNINGS.with(|warnings| warnings.borrow_mut().push(what.into()));
    eprintln!("lattice-swap: {what}");
}

#[cfg(test)]
thread_local! {
    /// What this thread's drivers warned, for the tests.
    pub(crate) static WARNINGS: std::cell::RefCell<Vec<String>> = const {
        std::cell::RefCell::new(Vec::new())
    };
}

/// The view [`view::Lookups`] asks for, aged by [`view::stale`] with
/// `max_tip_age` at `now`; `None` if the tip moved while it was read, as
/// web/driver's `bitcoinView` reads one.
pub fn bitcoin_view(
    bitcoin: &impl Bitcoin,
    swap: &Swap,
    lock: OutPoint,
    max_tip_age: Duration,
    now: SystemTime,
    first_seen: &mut Option<(BlockHash, u64)>,
) -> bitcoind::Result<Option<BitcoinView>> {
    let tip = bitcoin.tip()?;
    let height = tip.height;
    let lookups = view::Lookups::new(swap, lock);
    let funding = bitcoin
        .transaction(lookups.lock.txid)?
        .map(|(_, depth)| depth);
    let spent = |txids: [Txid; 2]| -> bitcoind::Result<Option<Spent>> {
        for txid in txids {
            if let Some((tx, confirmations)) = bitcoin.transaction(txid)? {
                return Ok(Some(Spent { tx, confirmations }));
            }
        }
        Ok(None)
    };
    let lock_spend = spent(lookups.lock_spends)?;
    let mut cancel_spend = spent(lookups.cancel_spends)?;
    if let Some(from) = lookups.search_from(height, &lock_spend, &cancel_spend) {
        cancel_spend = bitcoin
            .spender(lookups.cancel_output, from)?
            .map(|(tx, confirmations)| Spent { tx, confirmations });
    }
    for (spent, outpoint) in [
        (&lock_spend, lookups.lock),
        (&cancel_spend, lookups.cancel_output),
    ] {
        if let Some(spent) = spent.as_ref().filter(|s| !view::spends(&s.tx, outpoint)) {
            return Err(bitcoind::Error(format!(
                "{} does not spend {outpoint}",
                spent.tx.compute_txid()
            )));
        }
    }
    // Each depth was read against the tip of its read: one tip, or none.
    if bitcoin.tip()?.hash != tip.hash {
        return Ok(None);
    }
    let now = now
        .duration_since(UNIX_EPOCH)
        .map_or(0, |now| now.as_secs());
    let stale = view::stale(&tip, max_tip_age.as_secs(), now, first_seen);
    Ok(Some(BitcoinView {
        height,
        funding,
        lock_spend,
        cancel_spend,
        stale,
        punish_child: None,
        punish_child_unread: false,
    }))
}

/// What spends the payout of the swap's punish, output 0, once that punish
/// is in a block ([`BitcoinView::punish_child`]): searched for from the
/// punish's block up.
fn punish_child(
    bitcoin: &impl Bitcoin,
    swap: &Swap,
    lock: OutPoint,
    view: &BitcoinView,
) -> bitcoind::Result<Option<Spent>> {
    let punish = view::Lookups::new(swap, lock).cancel_spends[1];
    let Some(spent) = (view.cancel_spend.as_ref())
        .filter(|spent| spent.confirmations > 0 && spent.tx.compute_txid() == punish)
    else {
        return Ok(None);
    };
    let mined = (view.height + 1).saturating_sub(spent.confirmations);
    let child = bitcoin.spender(OutPoint::new(punish, 0), mined)?;
    Ok(child.map(|(tx, confirmations)| Spent { tx, confirmations }))
}

/// The lock account is read before the watched transaction: a lock that
/// has signed something, read first, shows that transaction mined in the
/// later read if it is ours. The view is one tip's: `None` unless
/// [`view::one_tip`] holds, so no read in it comes from another block. A
/// node on another Nexus than `genesis`, if given, is refused (`Ok(Err)`)
/// at its first read, which names its genesis.
fn nexus_view(
    client: &Client,
    watch: &NexusWatch,
    genesis: Option<&str>,
) -> swap_nexus_tx::rpc::Result<Result<Option<NexusView>, String>> {
    use swap_nexus_tx::rpc::parse;
    use swap_nexus_tx::rpc::Error;
    let chain_info = client.chain_info()?;
    if let Some(expected) = genesis {
        if let Err(refusal) = view::nexus_genesis(&chain_info, expected) {
            return Ok(Err(refusal.to_string()));
        }
    }
    let min_relay_fee = parse::min_relay_fee(&chain_info).map_err(Error::Malformed)?;
    let health = client.health()?;
    let own = client.account(&watch.own_address)?;
    let lock = client.account(&watch.lock_address)?;
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
    if !view::one_tip(&health, &after) {
        return Ok(Ok(None));
    }
    Ok(Ok(Some(NexusView {
        health,
        own,
        lock,
        min_relay_fee,
        watched,
        block_at,
    })))
}
