//! A buyer's wallet and swap for an app: what the browser's web/driver
//! (`Wallet` in wallet.js, `Buyer` in driver.js) does, natively, over the
//! native [`Driver`]. The app funds a swap from a single-key wallet of its
//! own ([`crate::wallet`]), as eigenwallet funds one from its internal
//! wallet, and reads Bitcoin through an [`Esplora`] and Nexus through its
//! own node's RPC.
//!
//! [`Wallet::prepare`] saves a swap of an offer, nothing sent. Its
//! [`Buy::run`] waits until the wallet's spendable balance pays for the
//! lock, takes the offer, then drives the swap to its end; [`Buy::cancel`]
//! drops it while it has not taken its offer. One swap runs at a time, and
//! the wallet withdraws nothing while one does. A swap that has taken its
//! offer carries on after a restart from [`Wallet::running`] and
//! [`Wallet::resume`].
//!
//! Everything is kept in one directory: the wallet key as `wallet.json`,
//! each swap's record as `<swap id>.record`, as the browser keeps them in
//! its store, and, once a swap has taken its offer, the driver's swap file
//! and session file beside it. The recovery file, [`Wallet::backup`] and
//! [`Wallet::restore`], is the browser's, so a wallet and its swaps move
//! between the two either way. `wallet.json` is itself a recovery file
//! holding no swap.

use std::fs;
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use bitcoin::address::NetworkUnchecked;
use bitcoin::{Address, FeeRate, Network, Txid};
use ed25519_dalek::SigningKey;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use swap_nexus_tx::rpc::Client;

use crate::bitcoind::Bitcoin;
use crate::driver::{bitcoin_view, Driver, Store};
use crate::esplora::Esplora;
use crate::offer::{self, check_offer, Offer, Place, Policy};
use crate::session::{self, check_nex_address, Result, Session, SessionFile, TIMEOUT};
use crate::transport::{Ivy, Relayed};
use crate::wallet::{self, Key};
use crate::{Action, Buyer, Machine, Outcome, Seller, STATE_VERSION};

/// The default Esplora for each network: mempool.space's. Regtest has
/// none.
pub fn default_esplora(network: Network) -> Option<&'static str> {
    match network {
        Network::Bitcoin => Some("https://mempool.space/api"),
        Network::Testnet => Some("https://mempool.space/testnet/api"),
        Network::Testnet4 => Some("https://mempool.space/testnet4/api"),
        Network::Signet => Some("https://mempool.space/signet/api"),
        _ => None,
    }
}

/// A recovery file's format.
const FORMAT: &str = "lattice-swap-wallet";
/// The wallet key's file.
const WALLET: &str = "wallet.json";
/// The blocks the offer's fee floor reads an estimate for, as the CLI's.
const FEE_TARGET: &str = "6";
/// About ten minutes a Bitcoin block.
const BLOCK: Duration = Duration::from_secs(600);

/// Where the wallet lives and what it reads.
#[derive(Clone, Debug)]
pub struct Config {
    /// The wallet's directory.
    pub dir: PathBuf,
    pub network: Network,
    /// The Esplora API, e.g. [`default_esplora`]'s: trusted for what it
    /// shows.
    pub esplora: String,
    /// The Nexus node's RPC, and its cookie file, read again whenever the
    /// node restarts.
    pub nexus: String,
    pub nexus_cookie: PathBuf,
    /// The CID of the genesis of the Nexus to trade on.
    pub nexus_genesis: String,
    /// Between two rounds of reads: the driver's poll.
    pub poll: Duration,
    /// How long the seller may stay quiet before anything is at stake.
    pub message_timeout: Duration,
    /// The oldest a Bitcoin tip may be for a view not to be stale.
    pub max_tip_age: Duration,
}

impl Config {
    /// The browser's settings, but where to read from.
    pub fn new(
        dir: PathBuf,
        network: Network,
        esplora: String,
        nexus: String,
        nexus_cookie: PathBuf,
        nexus_genesis: String,
    ) -> Self {
        Self {
            dir,
            network,
            esplora,
            nexus,
            nexus_cookie,
            nexus_genesis,
            poll: Duration::from_secs(10),
            message_timeout: Duration::from_secs(60),
            max_tip_age: Duration::from_secs(90 * 60),
        }
    }
}

/// A swap's record, as the browser keeps it in its store: the offer and the
/// policy it was prepared with, its state until it takes its offer, the
/// hello to send once it does, whether it has, and where the NEX goes.
/// What else a record holds is kept as it is.
#[derive(Clone, Debug, Serialize, Deserialize)]
struct Record {
    swap_id: String,
    offer: Value,
    policy: Value,
    /// The state as JSON text. Once the offer is taken, the swap file's is
    /// the swap's.
    state: String,
    pending: Vec<Action>,
    taken: bool,
    #[serde(default)]
    nex_address: Option<String>,
    #[serde(flatten)]
    rest: serde_json::Map<String, Value>,
}

/// A recovery file.
#[derive(Serialize, Deserialize)]
struct Recovery {
    format: String,
    network: Network,
    wallet: String,
    swaps: Vec<Value>,
}

/// Whether a buyer's state has ended: `Punished` keeps its secrets, for a
/// resume to ask the seller for `s` again.
fn ended(state: &Value) -> bool {
    matches!(state, Value::String(name) if name == "Done")
        || state.get("Done").is_some()
        || state.get("Punished").is_some()
}

/// A buyer's state as a swap file holds it, as the CLI's `resume` reads
/// one: refused if it is a seller's.
fn buyer_state(state: Value) -> Result<Buyer> {
    if state["ClaimingNex"]["setup"]["side"] != "Buyer"
        && serde_json::from_value::<Seller>(state.clone()).is_ok()
    {
        return Err("not a buyer’s swap".into());
    }
    Ok(serde_json::from_value(state).map_err(|e| format!("not a swap state: {e}"))?)
}

/// Writes `bytes` to `path` whole, readable by its owner alone: written to
/// a temporary file, synced, then renamed over it.
fn write(path: &Path, bytes: &[u8]) -> io::Result<()> {
    let temporary = path.with_extension("tmp");
    let mut options = fs::OpenOptions::new();
    options.write(true).create(true).truncate(true);
    #[cfg(unix)]
    std::os::unix::fs::OpenOptionsExt::mode(&mut options, 0o600);
    let mut file = options.open(&temporary)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    fs::rename(&temporary, path)
}

/// The buyer's wallet: its key, and the swaps in its directory.
pub struct Wallet {
    config: Config,
    key: Key,
    /// Held while the wallet's outputs are counted on, as the browser's
    /// swap lock and eigenwallet's `SwapLock`: a withdrawal, a swap
    /// prepared, or one taking its offer until it is saved as taken.
    lock: Mutex<()>,
}

impl Wallet {
    /// The wallet in `config.dir`, its key made and saved first if there is
    /// none.
    pub fn open(config: Config) -> Result<Arc<Self>> {
        fs::create_dir_all(&config.dir)?;
        let path = config.dir.join(WALLET);
        if !path.exists() {
            let key = Key::new(&config.network.to_string())?;
            // Never over a key made since: as Bitcoin Core's `createwallet`
            // refuses to overwrite a wallet.
            let mut options = fs::OpenOptions::new();
            options.write(true).create_new(true);
            #[cfg(unix)]
            std::os::unix::fs::OpenOptionsExt::mode(&mut options, 0o600);
            match options.open(&path) {
                Ok(mut file) => {
                    file.write_all(&Self::key_file(&config, &key)?)?;
                    file.sync_all()?;
                }
                Err(e) if e.kind() == io::ErrorKind::AlreadyExists => {}
                Err(e) => return Err(e.into()),
            }
        }
        let held: Recovery = serde_json::from_slice(&fs::read(&path)?)
            .map_err(|e| format!("{}: {e}", path.display()))?;
        if held.network != config.network {
            return Err(format!(
                "{} is a wallet for {}, not {}",
                path.display(),
                held.network,
                config.network
            )
            .into());
        }
        let key = Key::of(&held.wallet, &config.network.to_string())?;
        Ok(Arc::new(Self {
            config,
            key,
            lock: Mutex::new(()),
        }))
    }

    fn key_file(config: &Config, key: &Key) -> Result<Vec<u8>> {
        Ok(serde_json::to_vec(&Recovery {
            format: FORMAT.into(),
            network: config.network,
            wallet: key.wif.clone(),
            swaps: vec![],
        })?)
    }

    /// Where the buyer deposits.
    pub fn address(&self) -> &str {
        &self.key.address
    }

    pub fn config(&self) -> &Config {
        &self.config
    }

    fn exclusive(&self) -> MutexGuard<'_, ()> {
        self.lock
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    fn esplora(&self) -> Esplora {
        Esplora::new(&self.config.esplora, self.key.clone(), TIMEOUT)
    }

    fn nexus(&self) -> Result<Client> {
        Ok(
            Client::from_cookie_file(&self.config.nexus, &self.config.nexus_cookie, TIMEOUT)
                .map_err(|e| format!("{}: {e}", self.config.nexus_cookie.display()))?,
        )
    }

    /// `(confirmed, unconfirmed)`, in sat: what the wallet can spend, and
    /// what is on its way to it.
    pub fn balance(&self) -> Result<(u64, u64)> {
        Ok(self.esplora().balance()?)
    }

    /// Whether the spendable balance funds a swap of `btc_amount` sat at
    /// today's fee rate, and the balance a funding with change needs.
    pub fn need(&self, btc_amount: u64) -> Result<(bool, u64)> {
        let esplora = self.esplora();
        let rate = esplora.wallet_rate()?;
        Ok(wallet::need(esplora.spendable()?, btc_amount, rate))
    }

    fn record_path(&self, swap_id: &str) -> PathBuf {
        self.config.dir.join(format!("{swap_id}.record"))
    }

    fn store(&self, swap_id: &str) -> Result<Store> {
        session::swap_store(&self.config.dir.join(format!("{swap_id}.json")))
    }

    fn record(&self, swap_id: &str) -> Result<Option<Record>> {
        match fs::read(self.record_path(swap_id)) {
            Ok(bytes) => Ok(Some(serde_json::from_slice(&bytes)?)),
            Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(e.into()),
        }
    }

    fn save(&self, record: &Record) -> Result<()> {
        Ok(write(
            &self.record_path(&record.swap_id),
            &serde_json::to_vec(record)?,
        )?)
    }

    /// The swap ids in the directory.
    pub fn swaps(&self) -> Result<Vec<String>> {
        let mut ids = vec![];
        for entry in fs::read_dir(&self.config.dir)? {
            let name = entry?.file_name();
            if let Some(id) = name.to_str().and_then(|name| name.strip_suffix(".record")) {
                ids.push(id.to_string());
            }
        }
        ids.sort();
        Ok(ids)
    }

    /// Whether the swap has taken its offer: its record says so, or the
    /// driver has saved its swap file.
    fn taken(&self, record: &Record) -> Result<bool> {
        Ok(record.taken || self.store(&record.swap_id)?.path().exists())
    }

    /// The swap's state now: its swap file's once it has one.
    fn state(&self, record: &Record) -> Result<Value> {
        match self.store(&record.swap_id)?.load_value()? {
            Some(state) => Ok(state),
            None => Ok(serde_json::from_str(&record.state)?),
        }
    }

    fn is_running(&self, record: &Record) -> Result<bool> {
        Ok(self.taken(record)? && !ended(&self.state(record)?))
    }

    /// The swap that has taken its offer and not ended, if any: one swap
    /// runs at a time.
    pub fn running(&self) -> Result<Option<String>> {
        for id in self.swaps()? {
            if let Some(record) = self.record(&id)? {
                if self.is_running(&record)? {
                    return Ok(Some(id));
                }
            }
        }
        Ok(None)
    }

    /// Sends the whole spendable balance to `address`, less its fee: the
    /// txid. Not while a swap runs, whose funding spends the same outputs.
    pub fn withdraw(&self, address: &str) -> Result<Txid> {
        let _lock = self.exclusive();
        if let Some(running) = self.running()? {
            return Err(
                format!("refused: swap {running} is running, and funds from this wallet").into(),
            );
        }
        let to = address
            .parse::<Address<NetworkUnchecked>>()?
            .require_network(self.config.network)?
            .script_pubkey();
        let esplora = self.esplora();
        let utxos = esplora.spendable()?;
        if utxos.is_empty() {
            return Err("refused: the wallet holds nothing spendable".into());
        }
        let swept = wallet::sweep(&self.key.wif, &utxos, to, esplora.wallet_rate()?)?;
        esplora.broadcast(&swept.tx)?;
        Ok(swept.tx.compute_txid())
    }

    /// The recovery file, `(name, file)`, as the browser's: the wallet key
    /// and every swap not yet ended, as each stands now.
    pub fn backup(&self) -> Result<(String, String)> {
        let mut swaps = vec![];
        for id in self.swaps()? {
            let Some(record) = self.record(&id)? else {
                continue;
            };
            let state = self.state(&record)?;
            if ended(&state) {
                continue;
            }
            let mut swap = serde_json::to_value(&record)?;
            swap["state"] = state;
            swap["version"] = STATE_VERSION.into();
            swaps.push(swap);
        }
        let file = Recovery {
            format: FORMAT.into(),
            network: self.config.network,
            wallet: self.key.wif.clone(),
            swaps,
        };
        Ok((
            format!("lattice-swap-{}.json", self.address()),
            serde_json::to_string(&file)?,
        ))
    }

    /// The wallet in a recovery `file`, from this or the browser's backup,
    /// put in `config.dir` with its swaps, but those it holds already.
    /// Refuses a directory that holds another wallet, whose key it would
    /// lose, a swap it holds untaken that the file holds taken, and a file
    /// whose unfinished swap would run beside another: one swap at a time.
    pub fn restore(config: Config, file: &str) -> Result<Arc<Self>> {
        let backup: Recovery = serde_json::from_str(file).map_err(|_| "not a recovery file")?;
        if backup.format != FORMAT {
            return Err("not a recovery file".into());
        }
        if backup.network != config.network {
            return Err(
                format!("the file is for {}, not {}", backup.network, config.network).into(),
            );
        }
        let key = Key::of(&backup.wallet, &config.network.to_string())?;
        fs::create_dir_all(&config.dir)?;
        let path = config.dir.join(WALLET);
        if path.exists() {
            let held = Wallet::open(config.clone())?;
            if held.key.wif != key.wif {
                return Err("refused: the directory holds another wallet".into());
            }
        }
        let mut restored = vec![];
        for mut swap in backup.swaps {
            // The state version and side checked as the CLI's `resume`
            // checks them.
            let version = swap["version"].take();
            if version.as_u64() != Some(STATE_VERSION.into()) {
                return Err(format!(
                    "state version {version}, but this build reads only {STATE_VERSION}"
                )
                .into());
            }
            // One that ended has nothing to carry on, and a buyer's `Done`
            // reads as a seller's too.
            if ended(&swap["state"]) {
                continue;
            }
            let state = buyer_state(swap["state"].take())?;
            swap["state"] = serde_json::to_string(&state)?.into();
            if let Value::Object(fields) = &mut swap {
                fields.remove("version");
            }
            let record: Record = serde_json::from_value(swap)?;
            restored.push((record, state));
        }
        let wallet = Arc::new(Self {
            config: config.clone(),
            key: key.clone(),
            lock: Mutex::new(()),
        });
        let _lock = wallet.exclusive();
        let mut added = vec![];
        for (record, state) in restored {
            match wallet.record(&record.swap_id)? {
                None => added.push((record, state)),
                Some(held) if !wallet.taken(&held)? && record.taken => {
                    return Err(format!(
                        "refused: the directory holds swap {} untaken, and the file holds it taken",
                        record.swap_id
                    )
                    .into())
                }
                Some(_) => {}
            }
        }
        let mut runs = vec![];
        if let Some(running) = wallet.running()? {
            runs.push(running);
        }
        for (record, _) in &added {
            if record.taken {
                runs.push(record.swap_id.clone());
            }
        }
        if runs.len() > 1 {
            return Err(format!(
                "refused: swaps {} would both run; one swap at a time",
                runs.join(" and ")
            )
            .into());
        }
        if !path.exists() {
            write(&path, &Self::key_file(&config, &key)?)?;
        }
        for (record, state) in added {
            if record.taken {
                let store = wallet.store(&record.swap_id)?;
                store.create(&state)?;
                let offer: Offer = serde_json::from_value(record.offer.clone())?;
                SessionFile {
                    offer,
                    key: None,
                    listen: None,
                }
                .save(&store)?;
            }
            wallet.save(&record)?;
        }
        drop(_lock);
        Wallet::open(config)
    }

    /// Why this wallet refuses `offer` under `policy`, as the CLI's `take`
    /// would, at the Esplora's estimate and the node's relay floor.
    fn check(&self, offer: &Offer, policy: &Policy, nexus: &Client) -> Result<()> {
        let estimate = self.esplora().estimate(FEE_TARGET)?;
        let per_kvb = estimate.map(|rate| (rate * 1000.0).ceil() as u64);
        let floor = offer::btc_fee_floor(per_kvb, policy.bounds.min_btc_fee_rate)?;
        let nex_floor = offer::nex_fee_floor(policy.bounds.min_nex_fee, nexus.min_relay_fee()?);
        let genesis = &self.config.nexus_genesis;
        Ok(check_offer(
            offer,
            policy,
            self.config.network,
            genesis,
            floor,
            nex_floor,
        )?)
    }

    /// Refuses a Nexus node on another Nexus than the config's, or one that
    /// cannot say how deep a transaction is.
    fn check_nexus(&self, nexus: &Client) -> Result<()> {
        Ok(session::check_nexus(nexus, &self.config.nexus_genesis)?
            .map_err(|refusal| refusal.to_string())?)
    }

    /// A swap of `offer`, an offer's text, that the buyer agreed to by
    /// `policy`, funded from this wallet: its record saved, nothing sent.
    /// The NEX goes to `nex_address`, a refund to the wallet. Refuses the
    /// offer as the CLI's `take` would, and while another swap runs. A swap
    /// prepared before that never took its offer is dropped: nothing was
    /// sent for it.
    pub fn prepare(self: &Arc<Self>, offer: &str, policy: Value, nex_address: &str) -> Result<Buy> {
        let decoded = Offer::decode(offer)?;
        let parsed: Policy = serde_json::from_value(policy.clone())?;
        check_nex_address(nex_address)?;
        let _lock = self.exclusive();
        if let Some(running) = self.running()? {
            return Err(format!("refused: swap {running} is running; one swap at a time").into());
        }
        let nexus = self.nexus()?;
        self.check_nexus(&nexus)?;
        self.check(&decoded, &parsed, &nexus)?;
        for id in self.swaps()? {
            if let Some(record) = self.record(&id)? {
                if !self.taken(&record)? {
                    fs::remove_file(self.record_path(&id))?;
                }
            }
        }
        let terms = decoded.terms(parsed.btc_amount);
        let (buyer, pending) =
            Buyer::start(terms, self.key.script_pubkey.clone(), nex_address.into())
                .map_err(|refusal| format!("refused: {refusal:?}"))?;
        let record = Record {
            swap_id: hex::encode(decoded.template.swap_id),
            offer: serde_json::to_value(&decoded)?,
            policy,
            state: serde_json::to_string(&buyer)?,
            pending,
            taken: false,
            nex_address: Some(nex_address.into()),
            rest: Default::default(),
        };
        self.save(&record)?;
        Ok(Buy::new(self.clone(), record))
    }

    /// The swap `swap_id` in the directory, carried on from where it
    /// stopped. Its session, if it had one, is gone: the swap goes on from
    /// the chains and, while it needs one, a new session to the seller.
    pub fn resume(self: &Arc<Self>, swap_id: &str) -> Result<Buy> {
        let record = self
            .record(swap_id)?
            .ok_or_else(|| format!("no swap {swap_id} in {}", self.config.dir.display()))?;
        Ok(Buy::new(self.clone(), record))
    }
}

/// One swap of the wallet's: [`Wallet::prepare`]d or resumed.
pub struct Buy {
    wallet: Arc<Wallet>,
    record: Mutex<Record>,
    cancelled: AtomicBool,
    /// Why the offer could not be taken, once it cannot.
    gone: Mutex<Option<String>>,
    /// The last failure, if any.
    warning: Mutex<Option<String>>,
}

impl Buy {
    fn new(wallet: Arc<Wallet>, record: Record) -> Self {
        Self {
            wallet,
            record: Mutex::new(record),
            cancelled: AtomicBool::new(false),
            gone: Mutex::new(None),
            warning: Mutex::new(None),
        }
    }

    fn record(&self) -> MutexGuard<'_, Record> {
        self.record
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    pub fn swap_id(&self) -> String {
        self.record().swap_id.clone()
    }

    fn gone(&self, why: String) -> Result<()> {
        *self.gone.lock().unwrap_or_else(|p| p.into_inner()) = Some(why);
        let id = self.swap_id();
        Ok(fs::remove_file(self.wallet.record_path(&id))?)
    }

    /// Cancels the swap while it has not taken its offer, as eigenwallet's
    /// GUI lets its user cancel while it waits for the deposit: its record
    /// dropped, and [`Buy::run`] returns `None`. Under the wallet's lock,
    /// which a take holds from before it dials until the swap is saved as
    /// taken, so it comes either before the take, which then never dials,
    /// or after it, and refuses.
    pub fn cancel(&self) -> Result<()> {
        let _lock = self.wallet.exclusive();
        let record = self.record().clone();
        let held = self.wallet.record(&record.swap_id)?;
        if self.wallet.taken(&record)? || held.as_ref().is_some_and(|held| held.taken) {
            return Err(format!(
                "refused: swap {} has taken its offer; it runs on to its end or its refund",
                record.swap_id
            )
            .into());
        }
        // Only this swap's record: a later `prepare` of the same offer may
        // hold the id, and it is that swap's to cancel.
        if held.is_some_and(|held| held.state == record.state) {
            fs::remove_file(self.wallet.record_path(&record.swap_id))?;
        }
        self.cancelled.store(true, Ordering::SeqCst);
        Ok(())
    }

    /// Runs the swap until it ends, its offer is gone, it is cancelled, or
    /// `stop` holds: the outcome, once it ends. Until it has taken its
    /// offer, it waits for the wallet to fund the lock, a round each
    /// `poll`, a failed round its [`Buy::status`]'s warning. Then the
    /// driver runs it, and an error that stops the driver is returned: run
    /// it again, as the CLI's `resume`.
    pub fn run(&self, stop: impl Fn() -> bool) -> Result<Option<Outcome>> {
        let wallet = &self.wallet;
        let mut driver = loop {
            let record = self.record().clone();
            if self.cancelled.load(Ordering::SeqCst) || self.gone.lock().unwrap().is_some() {
                return Ok(None);
            }
            if stop() {
                return Ok(None);
            }
            if wallet.taken(&record)? {
                let store = wallet.store(&record.swap_id)?;
                break session::resume::<Buyer, _>(wallet.esplora(), wallet.nexus()?, store)?;
            }
            match self.take() {
                Ok(Some(driver)) => break driver,
                Ok(None) => {}
                Err(e) => *self.warning.lock().unwrap() = Some(e.to_string()),
            }
            let start = Instant::now();
            while start.elapsed() < wallet.config.poll && !stop() {
                std::thread::sleep(Duration::from_millis(50).min(wallet.config.poll));
            }
        };
        driver.poll = wallet.config.poll;
        driver.message_timeout = wallet.config.message_timeout;
        driver.max_tip_age = wallet.config.max_tip_age;
        // As the browser funds and prices its own spends: the Esplora's
        // estimate, else the relay floor.
        driver.fallback_fee_rate = FeeRate::from_sat_per_vb_u32(1);
        Ok(driver.run_until(|_| stop())?)
    }

    /// Takes the offer once the wallet's spendable balance pays for the
    /// lock: judged again first, at today's fees. Under the wallet's lock
    /// until it is saved as taken, so nothing else spends the outputs it
    /// counted. The driver, once taken.
    fn take(&self) -> Result<Option<Driver<Buyer, Esplora, Session>>> {
        let wallet = &self.wallet;
        let _lock = wallet.exclusive();
        if self.cancelled.load(Ordering::SeqCst) {
            return Ok(None);
        }
        let mut record = self.record().clone();
        if let Some(running) = wallet.running()? {
            return Err(format!("refused: swap {running} is running; one swap at a time").into());
        }
        // Only while the directory still holds this record, which a later
        // `prepare` drops.
        let held = wallet.record(&record.swap_id)?;
        if held.is_none_or(|held| held.state != record.state) {
            *self.gone.lock().unwrap() =
                Some("refused: this swap was dropped when another was prepared".into());
            return Ok(None);
        }
        let policy: Policy = serde_json::from_value(record.policy.clone())?;
        let (enough, _) = wallet.need(policy.btc_amount)?;
        if !enough {
            return Ok(None);
        }
        let offer: Offer = serde_json::from_value(record.offer.clone())?;
        let nexus = wallet.nexus()?;
        wallet.check_nexus(&nexus)?;
        wallet.check(&offer, &policy, &nexus)?;
        let config = ivy::Config::new(SigningKey::from_bytes(&offer.buyer_session));
        let opened = offer.seller_key().map_err(Into::into).and_then(|seller| {
            Ok::<Session, Box<dyn std::error::Error>>(match offer.place()? {
                Place::Address(address) => {
                    Box::new(Ivy::connect(address, &config, seller, TIMEOUT)?)
                }
                Place::Relay(relay) => {
                    let id = hex::encode(offer.template.swap_id);
                    Box::new(Ivy::<Relayed>::connect_relayed(
                        &relay, &id, &config, seller, TIMEOUT,
                    )?)
                }
            })
        });
        // Once, as the CLI's `take` fails: nothing of the swap was sent.
        let mut transport = match opened {
            Ok(transport) => transport,
            Err(e) => {
                self.gone(format!("the offer is gone: {e}"))?;
                return Ok(None);
            }
        };
        // The amount asked for: the seller fixes the terms, which must be
        // the ones the machine started on.
        if let Err(e) = session::request_terms(&mut transport, &offer, &policy) {
            self.gone(format!("the offer is gone: {e}"))?;
            return Ok(None);
        }
        let buyer: Buyer = serde_json::from_str(&record.state)?;
        let pending = std::mem::take(&mut record.pending);
        let rejoin = SessionFile {
            offer,
            key: None,
            listen: None,
        };
        let store = wallet.store(&record.swap_id)?;
        let driver = session::start(
            buyer,
            pending,
            wallet.esplora(),
            nexus,
            transport,
            store,
            rejoin,
            None,
        )?;
        record.taken = true;
        wallet.save(&record)?;
        *self.record() = record;
        Ok(Some(driver))
    }

    /// Where the swap is, for an app to show, as the browser's
    /// `Buyer.status()` shows it: `swapId`, `step`, `outcome`, `wallet`,
    /// `need`, `confirmations`, `deadlines`, `mustStayOpen`,
    /// `backupCovers`, `running`, the amounts, `nexAddress`, `tip` and
    /// `warning`. Reads the wallet's balance and, once the lock is agreed,
    /// a Bitcoin view; Nexus confirmations are not read (`nexLock` null).
    pub fn status(&self) -> Result<Value> {
        let wallet = &self.wallet;
        let record = self.record().clone();
        let taken = wallet.taken(&record)?;
        let state = wallet.state(&record)?;
        let buyer: Buyer = serde_json::from_value(state.clone())?;
        let esplora = wallet.esplora();
        let (confirmed, unconfirmed) = esplora.balance()?;
        let policy: Policy = serde_json::from_value(record.policy.clone())?;
        let need = match taken {
            true => None,
            false => Some(wallet.need(policy.btc_amount)?.1),
        };
        let (view, tip) = match buyer.watch().bitcoin {
            Some((swap, lock)) => {
                let view = bitcoin_view(
                    &esplora,
                    &swap,
                    lock,
                    wallet.config.max_tip_age,
                    SystemTime::now(),
                    &mut None,
                )?;
                let height = view.height;
                (Some(view), Some(height))
            }
            None => (None, None),
        };
        let machine = crate::status::buyer_status(&buyer, view.as_ref());
        let offer: Offer = serde_json::from_value(record.offer.clone())?;
        let terms = match buyer.terms() {
            Some(terms) => terms.clone(),
            None => offer.terms(policy.btc_amount),
        };
        let phase = machine["phase"].as_str().unwrap_or_default().to_string();
        let gone = self.gone.lock().unwrap().clone();
        let step = if self.cancelled.load(Ordering::SeqCst) {
            "cancelled".into()
        } else if gone.is_some() {
            "offer-gone".into()
        } else if !taken {
            "fund-wallet".into()
        } else {
            match phase.as_str() {
                "swapped" | "punished" | "drained" | "aborted" => "done".into(),
                phase => phase.to_string(),
            }
        };
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |now| now.as_millis() as u64);
        let at = |height: &Value| {
            let height = height.as_u64()?;
            let blocks = height.saturating_sub(u64::from(tip.unwrap_or(0)));
            let eta = now + blocks * BLOCK.as_millis() as u64;
            Some(json!({"height": height, "eta": eta}))
        };
        let deadlines = &machine["deadlines"];
        let deadlines = match at(&deadlines["cancel"]) {
            Some(cancel) if !ended(&state) => json!({
                "cancel": cancel,
                "refund": {"from": deadlines["refund"], "until": deadlines["punish"]},
                "punish": at(&deadlines["punish"]),
            }),
            _ => json!({"cancel": null, "refund": null, "punish": null}),
        };
        let confirmations = &machine["confirmations"];
        Ok(json!({
            "swapId": record.swap_id,
            "step": step,
            "outcome": ended(&state).then_some(phase.as_str()),
            "wallet": {"address": wallet.address(), "confirmed": confirmed, "unconfirmed": unconfirmed},
            "need": need,
            "confirmations": {
                "funding": confirmations["funding"],
                "lockSpend": confirmations["lock_spend"],
                "cancelSpend": confirmations["cancel_spend"],
                "nexLock": null,
            },
            "deadlines": deadlines,
            "mustStayOpen": machine["must_stay_open"] == true || phase == "refunding",
            "backupCovers": machine["backup_covers"],
            "running": taken && !ended(&state),
            "btc_amount": terms.btc_amount.to_sat(),
            "price": policy.price,
            "nex_amount": terms.nex_amount,
            "btc_confirmations": terms.btc_confirmations,
            "nex_confirmations": terms.nex_confirmations,
            "nexAddress": record.nex_address,
            "tip": tip,
            "warning": gone.or_else(|| self.warning.lock().unwrap().clone()),
        }))
    }
}
