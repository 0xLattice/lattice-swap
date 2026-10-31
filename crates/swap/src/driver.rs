//! Runs a [`Machine`] against real nodes and a real counterparty.

use std::fs::{self, File, OpenOptions};
use std::io::{self, Write};
use std::mem::discriminant;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use bitcoin::OutPoint;
use swap_bitcoin::{Spend, Swap};
use swap_nexus_tx::rpc::Client;

use crate::bitcoind::{self, Bitcoin};
use crate::transport::Transport;
use crate::{Action, BitcoinView, Event, Machine, Message, NexusView, NexusWatch, Outcome};
use crate::{SecretBytes, Spent};

/// One JSON file per swap, replaced atomically: written to a temporary
/// file, synced, then renamed over the old one. It holds the party's
/// secrets.
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

    pub fn load<M: Machine>(&self) -> io::Result<Option<M>> {
        match fs::read(&self.path) {
            Ok(bytes) => serde_json::from_slice(&bytes)
                .map(Some)
                .map_err(io::Error::other),
            Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(e),
        }
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
        file.write_all(&serde_json::to_vec_pretty(state).map_err(io::Error::other)?)?;
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
            Ok(view) => self.apply(Event::Bitcoin(view)),
            Err(e) => {
                warn(&e.to_string());
                Ok(())
            }
        }
    }

    fn observe_nexus(&mut self) -> io::Result<()> {
        let Some(watch) = self.state.watch().nexus else {
            return Ok(());
        };
        match nexus_view(&self.nexus, &watch) {
            Ok(view) => self.apply(Event::Nexus(view)),
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
/// later read if it is ours. The tip is read after both accounts, so a
/// block that moved them is at or below the tip the view reports.
fn nexus_view(client: &Client, watch: &NexusWatch) -> swap_nexus_tx::rpc::Result<NexusView> {
    let own = client.account(&watch.own_address)?;
    let lock = client.account(&watch.lock_address)?;
    let health = client.health()?;
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
    Ok(NexusView {
        health,
        own,
        lock,
        min_relay_fee,
        watched,
        block_at,
    })
}
