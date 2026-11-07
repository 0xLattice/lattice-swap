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
//! [`Wallet::resume`]; a punished one, from [`Wallet::punished`], asks the
//! seller for `s` once each launch it is resumed.
//!
//! Everything is kept in one directory: the wallet key as `wallet.json`,
//! each swap's record as `<swap id>.record`, as the browser keeps them in
//! its store, and, once a swap has taken its offer, the driver's swap file
//! and session file beside it. The recovery file, [`Wallet::backup`] and
//! [`Wallet::restore`], is the browser's, so a wallet and its swaps move
//! between the two either way. `wallet.json` is itself a recovery file
//! holding no swap. One [`Wallet`] holds the directory at a time.

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
use crate::driver::{bitcoin_view, Driver, NexusCheck, Store};
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
/// The file whose lock a [`Wallet`] holds the directory by.
const LOCK: &str = "wallet.lock";
/// The blocks the offer's fee floor reads an estimate for, as the CLI's.
const FEE_TARGET: &str = "6";
/// Between two rounds of reads: slow enough for a public node's rate
/// limits, as the browser's.
pub const POLL: Duration = Duration::from_secs(10);
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
    /// node restarts; with no cookie, a node's public read port, which must
    /// take submits, as the CLI's public Nexus.
    pub nexus: String,
    pub nexus_cookie: Option<PathBuf>,
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
    /// The browser's settings, but where to read from: `nexus_cookie` a
    /// cookie file, or `None` for a public read port.
    pub fn new(
        dir: PathBuf,
        network: Network,
        esplora: String,
        nexus: String,
        nexus_cookie: impl Into<Option<PathBuf>>,
        nexus_genesis: String,
    ) -> Self {
        Self {
            dir,
            network,
            esplora,
            nexus,
            nexus_cookie: nexus_cookie.into(),
            nexus_genesis,
            poll: POLL,
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

/// Whether a swap's state has ended: `Punished` keeps a buyer's secrets,
/// for a resume to ask the seller for `s` again, and a seller's until the
/// buyer claims, which may be never; neither spends from the wallet again.
pub fn ended(state: &Value) -> bool {
    matches!(state, Value::String(name) if name == "Done")
        || state.get("Done").is_some()
        || state.get("Punished").is_some()
}

/// The directory held for one [`Wallet`], as bitcoind holds its data
/// directory by the lock on its `.lock` file and refuses to start beside
/// another, and as the browser holds its wallet by a Web Lock. Released
/// when the file is dropped, or its process ends.
fn hold(config: &Config) -> Result<fs::File> {
    fs::create_dir_all(&config.dir)?;
    let file = fs::OpenOptions::new()
        .create(true)
        .truncate(false)
        .write(true)
        .open(config.dir.join(LOCK))?;
    match file.try_lock() {
        Ok(()) => Ok(file),
        Err(fs::TryLockError::WouldBlock) => Err(format!(
            "refused: the wallet in {} is open elsewhere",
            config.dir.display()
        )
        .into()),
        Err(fs::TryLockError::Error(e)) => Err(e.into()),
    }
}

/// The key in the directory's `wallet.json`, if it holds one.
fn read_key(config: &Config) -> Result<Option<Key>> {
    let path = config.dir.join(WALLET);
    let bytes = match fs::read(&path) {
        Ok(bytes) => bytes,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(e.into()),
    };
    let held: Recovery =
        serde_json::from_slice(&bytes).map_err(|e| format!("{}: {e}", path.display()))?;
    if held.network != config.network {
        return Err(format!(
            "{} is a wallet for {}, not {}",
            path.display(),
            held.network,
            config.network
        )
        .into());
    }
    Ok(Some(Key::of(&held.wallet, &config.network.to_string())?))
}

/// `key` saved as the directory's `wallet.json` unless it holds one
/// already, never over it, as git puts an object file: written whole to a
/// temporary file, then linked to its name, which fails if the name is
/// taken, the directory synced. The key the directory then holds.
pub(crate) fn put_key(config: &Config, key: &Key) -> Result<Key> {
    let temporary = config.dir.join(format!("{WALLET}.tmp"));
    let mut options = fs::OpenOptions::new();
    options.write(true).create(true).truncate(true);
    #[cfg(unix)]
    std::os::unix::fs::OpenOptionsExt::mode(&mut options, 0o600);
    let mut file = options.open(&temporary)?;
    file.write_all(&serde_json::to_vec(&Recovery {
        format: FORMAT.into(),
        network: config.network,
        wallet: key.wif.clone(),
        swaps: vec![],
    })?)?;
    file.sync_all()?;
    match fs::hard_link(&temporary, config.dir.join(WALLET)) {
        Err(e) if e.kind() != io::ErrorKind::AlreadyExists => return Err(e.into()),
        _ => {}
    }
    fs::remove_file(&temporary)?;
    #[cfg(unix)]
    fs::File::open(&config.dir)?.sync_all()?;
    Ok(read_key(config)?.ok_or("wallet.json is gone")?)
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
    /// Across processes, [`hold`] keeps any other `Wallet` out of the
    /// directory.
    lock: Mutex<()>,
    _held: fs::File,
}

impl Wallet {
    /// The wallet in `config.dir`, its key made and saved first if there is
    /// none.
    /// Refused while another `Wallet` holds the directory.
    pub fn open(config: Config) -> Result<Arc<Self>> {
        let held = hold(&config)?;
        let key = match read_key(&config)? {
            Some(key) => key,
            None => put_key(&config, &Key::new(&config.network.to_string())?)?,
        };
        Ok(Arc::new(Self {
            config,
            key,
            lock: Mutex::new(()),
            _held: held,
        }))
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

    /// The wallet's Bitcoin, through the config's Esplora.
    pub fn esplora(&self) -> Esplora {
        Esplora::new(&self.config.esplora, self.key.clone(), TIMEOUT)
    }

    /// The Nexus node's RPC, which reads its cookie file again on a 401,
    /// and fails each request while there is none; with no cookie, a
    /// public read port, its tip read live.
    pub(crate) fn nexus(&self) -> Client {
        let Some(cookie) = &self.config.nexus_cookie else {
            return Client::public(&self.config.nexus, TIMEOUT);
        };
        Client::from_cookie_file(&self.config.nexus, cookie, TIMEOUT)
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

    /// The swaps that ended punished, which keep their secrets: resumed,
    /// each asks the seller for `s` once more, as the CLI's `resume` and
    /// the browser's `Buyer.resume` ask, and as eigenwallet asks its ASB
    /// to redeem cooperatively on every resume.
    pub fn punished(&self) -> Result<Vec<String>> {
        let mut ids = vec![];
        for id in self.swaps()? {
            if let Some(record) = self.record(&id)? {
                if self.state(&record)?.get("Punished").is_some() {
                    ids.push(id);
                }
            }
        }
        Ok(ids)
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
        let held = hold(&config)?;
        let another = || Err("refused: the directory holds another wallet".into());
        if read_key(&config)?.is_some_and(|held| held.wif != key.wif) {
            return another();
        }
        let mut restored = vec![];
        let mut ids = std::collections::BTreeSet::new();
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
            // Its id names its files: the offer's, once each.
            let offer = Offer::decode(&record.offer.to_string())?;
            if record.swap_id != hex::encode(offer.template.swap_id) {
                return Err(format!("swap {:?} is not its offer's", record.swap_id).into());
            }
            if !ids.insert(record.swap_id.clone()) {
                return Err(format!("swap {} is in the file twice", record.swap_id).into());
            }
            restored.push((record, state, offer));
        }
        let wallet = Arc::new(Self {
            config: config.clone(),
            key: key.clone(),
            lock: Mutex::new(()),
            _held: held,
        });
        let _lock = wallet.exclusive();
        // Those it lacks, and taken ones whose swap file a restore that
        // stopped part way never made.
        let mut added = vec![];
        for (record, state, offer) in restored {
            let store = wallet.store(&record.swap_id)?;
            match wallet.record(&record.swap_id)? {
                None => added.push((record, state, offer)),
                Some(held) if !wallet.taken(&held)? && record.taken => {
                    return Err(format!(
                        "refused: the directory holds swap {} untaken, and the file holds it taken",
                        record.swap_id
                    )
                    .into())
                }
                Some(held) if held.taken && record.taken && !store.path().exists() => {
                    added.push((record, state, offer))
                }
                Some(_) => {}
            }
        }
        let mut runs = std::collections::BTreeSet::new();
        runs.extend(wallet.running()?);
        for (record, _, _) in &added {
            if record.taken {
                runs.insert(record.swap_id.clone());
            }
        }
        if runs.len() > 1 {
            let runs: Vec<_> = runs.into_iter().collect();
            return Err(format!(
                "refused: swaps {} would both run; one swap at a time",
                runs.join(" and ")
            )
            .into());
        }
        if put_key(&config, &key)?.wif != key.wif {
            return another();
        }
        // The record first: a swap is listed before it can run.
        for (record, state, offer) in added {
            wallet.save(&record)?;
            if record.taken {
                let store = wallet.store(&record.swap_id)?;
                store.create(&state)?;
                SessionFile {
                    offer,
                    key: None,
                    listen: None,
                }
                .save(&store)?;
            }
        }
        drop(_lock);
        Ok(wallet)
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

    /// Refuses a public node that takes no transactions, as the CLI's
    /// `check_nexus`, then a Nexus node on another Nexus than the config's,
    /// or one that cannot say how deep a transaction is.
    pub(crate) fn check_nexus(&self, nexus: &Client) -> Result<()> {
        if let Some(why) = self.takes_no_transactions(nexus)? {
            return Err(format!(
                "refused: {why}: give a public node that does, or your own with its cookie"
            )
            .into());
        }
        self.check_nexus_chain(nexus)
    }

    /// Why a public node takes no transactions, if it takes none.
    fn takes_no_transactions(&self, nexus: &Client) -> Result<Option<String>> {
        let none =
            self.config.nexus_cookie.is_none() && nexus.chain_info()?["acceptsSubmit"] != true;
        Ok(none.then(|| format!("{} takes no transactions", self.config.nexus)))
    }

    /// Refuses a Nexus node on another Nexus than the config's, or one that
    /// cannot say how deep a transaction is.
    fn check_nexus_chain(&self, nexus: &Client) -> Result<()> {
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
        self.esplora().check_network(self.config.network)?;
        let nexus = self.nexus();
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
    /// The last failure, if any; once the driver runs a resumed swap, why
    /// its Nexus node will not do, as its `nexus_check` last found.
    warning: Arc<Mutex<Option<String>>>,
}

impl Buy {
    fn new(wallet: Arc<Wallet>, record: Record) -> Self {
        Self {
            wallet,
            record: Mutex::new(record),
            cancelled: AtomicBool::new(false),
            gone: Mutex::new(None),
            warning: Arc::default(),
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
                // As the CLI's `resume` checks a swap and its node, and
                // the browser's `#checkNexus`.
                let buyer: Buyer = serde_json::from_value(wallet.state(&record)?)?;
                let genesis = &wallet.config.nexus_genesis;
                if let Some(terms) = buyer.terms().filter(|t| &t.nexus_genesis != genesis) {
                    return Err(format!(
                        "refused: swap {} trades on the Nexus of genesis {}, not {genesis}",
                        record.swap_id, terms.nexus_genesis
                    )
                    .into());
                }
                let nexus = wallet.nexus();
                let check = match buyer.resumed().outcome() {
                    None => {
                        wallet.esplora().check_network(wallet.config.network)?;
                        Some(self.resumed_check())
                    }
                    Some(_) => None,
                };
                let store = wallet.store(&record.swap_id)?;
                let mut driver = session::resume::<Buyer, _>(wallet.esplora(), nexus, store)?;
                driver.nexus_check = check;
                break driver;
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
        let outcome = driver.run_until(|_| stop())?;
        if outcome.is_some() {
            *self.warning.lock().unwrap() = None;
        }
        Ok(outcome)
    }

    /// The driver's `nexus_check` for a taken swap resumed, as the CLI's
    /// `resume` and the browser's `#checkNexus` check its node, but never
    /// refusing it: the swap's cancel, refund and the rest are Bitcoin's,
    /// and go on whatever the node does. Nexus is read only once the node
    /// passes; until then the status's warning says why, and while a public
    /// node takes no transactions, that the swap's Nexus submits fail.
    fn resumed_check(&self) -> NexusCheck {
        let wallet = self.wallet.clone();
        let warning = self.warning.clone();
        let checked = wallet.clone();
        let mut chain = session::check_once(move |nexus| checked.check_nexus_chain(nexus));
        Box::new(move |nexus| {
            let gated = chain(nexus);
            let unread = gated
                .as_ref()
                .err()
                .map(|e| format!("nexus: {e}: Nexus is not read until it passes; Bitcoin goes on"));
            let no_submits = wallet
                .takes_no_transactions(nexus)
                .ok()
                .flatten()
                .map(|why| {
                    format!("{why}: the swap's Bitcoin side goes on, its Nexus submits fail")
                });
            let why: Vec<String> = unread.into_iter().chain(no_submits).collect();
            *warning.lock().unwrap() = (!why.is_empty()).then(|| why.join("; "));
            gated
        })
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
        let nexus = wallet.nexus();
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
    /// a Bitcoin view. Nexus is not read: `nexLock` is the claim's depth
    /// as the state last saw it while `received`, else null.
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
        // None while the tip moves under the read, as the browser's
        // status keeps no view until it reads one.
        let view = match buyer.watch().bitcoin {
            Some((swap, lock)) => bitcoin_view(
                &esplora,
                &swap,
                lock,
                wallet.config.max_tip_age,
                SystemTime::now(),
                &mut None,
            )?,
            None => None,
        };
        let tip = view.as_ref().map(|view| view.height);
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
                "nexLock": confirmations["claim"],
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
