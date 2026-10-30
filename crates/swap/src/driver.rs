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
use crate::{Action, BitcoinView, Event, Machine, Message, NexusView, NexusWatch, Outcome, Spent};

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
        let temporary = self.path.with_extension("json.tmp");
        let mut options = OpenOptions::new();
        options.write(true).create(true).truncate(true);
        #[cfg(unix)]
        std::os::unix::fs::OpenOptionsExt::mode(&mut options, 0o600);
        let mut file = options.open(&temporary)?;
        file.write_all(&serde_json::to_vec_pretty(state).map_err(io::Error::other)?)?;
        file.sync_all()?;
        fs::rename(&temporary, &self.path)?;
        // The rename is durable once the directory is.
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
}

impl<M: Machine, B: Bitcoin, T: Transport> Driver<M, B, T> {
    /// A new swap: saves `state` and carries out `actions` (the buyer's
    /// hello).
    pub fn start(
        state: M,
        actions: Vec<Action>,
        bitcoin: B,
        nexus: Client,
        transport: Option<T>,
        store: Store,
    ) -> io::Result<Self> {
        store.save(&state)?;
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
                // Act on a message against the chain as it is now: the
                // seller's redeem window is judged on a fresh height.
                self.observe_bitcoin()?;
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
                    if let Err(e) = transport.send(&message.encode(self.store.swap_id)) {
                        warn(&format!("session ended: {e}"));
                        self.transport = None;
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
            Action::Submit(transaction) => match self.nexus.submit(&transaction) {
                Ok(cid) => self.apply(Event::Submitted(cid))?,
                Err(e) => warn(&format!("nexus submit: {e}")),
            },
        }
        Ok(())
    }
}

fn warn(what: &str) {
    eprintln!("lattice-swap: {what}");
}

fn bitcoin_view(
    bitcoin: &impl Bitcoin,
    swap: &Swap,
    lock: OutPoint,
) -> bitcoind::Result<BitcoinView> {
    let height = bitcoin.height()?;
    let funding = bitcoin.confirmations(lock.txid)?;
    // Nothing spends the lock before the block that confirms it.
    let from = match funding {
        Some(depth) if depth > 0 => height + 1 - depth,
        _ => height + 1,
    };
    let spent = |outpoint| -> bitcoind::Result<Option<Spent>> {
        let Some(tx) = bitcoin.spending_tx(outpoint, from)? else {
            return Ok(None);
        };
        let confirmations = bitcoin.confirmations(tx.compute_txid())?.unwrap_or(0);
        Ok(Some(Spent { tx, confirmations }))
    };
    let lock_spend = spent(lock)?;
    let cancel = OutPoint::new(swap.unsigned_tx(lock, Spend::Cancel).compute_txid(), 0);
    let cancel_spend = match &lock_spend {
        Some(spend) if spend.tx.compute_txid() == cancel.txid => spent(cancel)?,
        _ => None,
    };
    Ok(BitcoinView {
        funding,
        lock_spend,
        cancel_spend,
    })
}

fn nexus_view(client: &Client, watch: &NexusWatch) -> swap_nexus_tx::rpc::Result<NexusView> {
    let watched = match &watch.cid {
        Some(cid) => match client.transaction(cid)? {
            Some(transaction) => Some((transaction, client.confirmations(cid)?)),
            None => None,
        },
        None => None,
    };
    Ok(NexusView {
        health: client.health()?,
        own: client.account(&watch.own_address)?,
        lock: client.account(&watch.lock_address)?,
        watched,
    })
}
