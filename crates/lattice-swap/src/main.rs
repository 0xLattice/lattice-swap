//! `lattice-swap`: one side of a NEX<->BTC swap, run against the operator's
//! own bitcoind and lattice-node.
//!
//! The seller runs `offer`: it listens, and prints an offer for the buyer.
//! The two agree off-tool, and the buyer runs `take` on that offer, which
//! dials the seller. Each side then runs its [`Driver`] until the swap ends,
//! saving its state to a swap file that `resume` carries on from after a
//! restart and `status` reads.

use std::cell::RefCell;
use std::fs;
use std::io::{self, Read, Write};
use std::net::{SocketAddr, TcpListener};
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::time::Duration;

use bitcoin::address::NetworkUnchecked;
use bitcoin::{Address, Amount, Network, ScriptBuf};
use clap::{Args, Parser, Subcommand};
use ed25519_dalek::SigningKey;
use rand_core::{OsRng, RngCore};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use swap::bitcoind::{Bitcoin, Bitcoind};
use swap::driver::{Driver, Store};
use swap::transport::{Ivy, PeerKey, Transport};
use swap::{Buyer, Machine, SecretBytes, Seller, Terms};
use swap_nexus_tx::rpc::Client;

type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;

/// Bounds each call to a node, the dial, and each send to the counterparty.
const TIMEOUT: Duration = Duration::from_secs(30);
/// Holds the seller's Nexus wallet key when no key file is given.
const NEX_KEY_ENV: &str = "LATTICE_SWAP_NEX_KEY";
/// Holds the password for `--btc-user`.
const BTC_PASSWORD_ENV: &str = "LATTICE_SWAP_BTC_PASSWORD";
/// A Nexus block is about this many Bitcoin blocks.
const BTC_BLOCKS_PER_NEXUS_BLOCK: u64 = 6;

#[derive(Parser)]
#[command(
    name = "lattice-swap",
    version,
    about = "Atomic swaps between NEX and BTC"
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Sell NEX for BTC. Prints an offer, one line, to hand to the buyer
    /// privately, waits for the buyer to dial, then runs the swap to its end.
    Offer(OfferArgs),
    /// Buy NEX with BTC: dials the seller an offer names and runs the swap
    /// to its end.
    Take(TakeArgs),
    /// Carries on a swap from its swap file until it ends. There is no
    /// session: the rest runs from the chains alone, and a swap still
    /// waiting on a message cancels and refunds once its timelocks allow.
    Resume(SwapFileArgs),
    /// The same as `resume`. A swap cancels and refunds by itself once its
    /// timelocks allow, so there is no separate step: this runs the swap
    /// until it ends.
    Refund(SwapFileArgs),
    /// Prints a swap's state and outcome from its swap file. Asks no node.
    Status {
        /// The swap file, `<swap id>.json`.
        swap_file: PathBuf,
    },
}

/// Defaults are this tool's settings, not protocol rules.
#[derive(Args)]
struct TermsArgs {
    /// BTC to receive, in satoshis.
    #[arg(long)]
    btc_amount: u64,
    /// Paid by each Bitcoin swap transaction, in satoshis.
    #[arg(long)]
    btc_fee: u64,
    /// NEX to sell.
    #[arg(long)]
    nex_amount: u64,
    /// Paid by the NEX lock and by the claim from it.
    #[arg(long)]
    nex_fee: u64,
    /// Bitcoin blocks after the lock confirms before cancel is valid; at
    /// least btc-confirmations + 6 x (nex-confirmations + 1) + margin.
    #[arg(long, default_value_t = 288)]
    t1: u16,
    /// Bitcoin blocks after cancel confirms before punish is valid.
    #[arg(long, default_value_t = 144)]
    t2: u16,
    /// How deep the BTC lock must be before the NEX is locked.
    #[arg(long, default_value_t = 6)]
    btc_confirmations: u32,
    /// How deep the NEX lock and the claims must be.
    #[arg(long, default_value_t = 24)]
    nex_confirmations: u64,
    /// Bitcoin blocks of slack before a timelock.
    #[arg(long, default_value_t = 12)]
    margin: u16,
}

impl TermsArgs {
    fn terms(&self, swap_id: [u8; 32]) -> Terms {
        Terms {
            swap_id,
            btc_amount: Amount::from_sat(self.btc_amount),
            btc_fee: Amount::from_sat(self.btc_fee),
            nex_amount: self.nex_amount,
            nex_fee: self.nex_fee,
            t1: self.t1,
            t2: self.t2,
            btc_confirmations: self.btc_confirmations,
            nex_confirmations: self.nex_confirmations,
            margin: self.margin,
        }
    }
}

#[derive(Args)]
struct NodeArgs {
    /// bitcoind's RPC URL, without the wallet path.
    #[arg(long, default_value = "http://127.0.0.1:8332")]
    btc_url: String,
    /// The bitcoind wallet that funds the lock or receives the BTC.
    #[arg(long)]
    btc_wallet: String,
    /// bitcoind's cookie file, or any file holding `user:password`.
    #[arg(long, required_unless_present = "btc_user")]
    btc_cookie: Option<PathBuf>,
    /// A bitcoind RPC user, whose password is read from
    /// LATTICE_SWAP_BTC_PASSWORD.
    #[arg(long, conflicts_with = "btc_cookie")]
    btc_user: Option<String>,
    /// bitcoin, testnet, signet or regtest.
    #[arg(long, default_value_t = Network::Bitcoin)]
    btc_network: Network,
    /// The lattice-node's RPC base URL.
    #[arg(long)]
    nexus_url: String,
    /// The lattice-node's RPC cookie file.
    #[arg(long)]
    nexus_cookie: PathBuf,
}

impl NodeArgs {
    fn bitcoin(&self) -> Result<Bitcoind> {
        let auth = match (&self.btc_cookie, &self.btc_user) {
            (Some(path), _) => read(path)?,
            (None, Some(user)) => {
                let password = std::env::var(BTC_PASSWORD_ENV)
                    .map_err(|_| format!("--btc-user needs {BTC_PASSWORD_ENV}"))?;
                format!("{user}:{password}")
            }
            (None, None) => return Err("--btc-cookie or --btc-user is required".into()),
        };
        let url = format!(
            "{}/wallet/{}",
            self.btc_url.trim_end_matches('/'),
            self.btc_wallet
        );
        Ok(Bitcoind::new(&url, &auth, self.btc_network, TIMEOUT))
    }

    fn nexus(&self) -> Result<Client> {
        Ok(Client::new(
            &self.nexus_url,
            &read(&self.nexus_cookie)?,
            TIMEOUT,
        ))
    }

    /// A fresh address from the wallet, as the script that pays it.
    fn payout(&self, bitcoin: &Bitcoind) -> Result<ScriptBuf> {
        let address = bitcoin.call("getnewaddress", json!([]))?;
        let address: Address<NetworkUnchecked> = address
            .as_str()
            .ok_or("getnewaddress returned no address")?
            .parse()?;
        Ok(address.require_network(self.btc_network)?.script_pubkey())
    }
}

#[derive(Args)]
struct NexKeyArgs {
    /// A file holding the seller's Nexus wallet key, its Ed25519 seed in
    /// hex; or set LATTICE_SWAP_NEX_KEY. It never reaches the swap file.
    #[arg(long)]
    nex_key_file: Option<PathBuf>,
}

impl NexKeyArgs {
    fn load(&self) -> Result<SecretBytes> {
        let hex = match &self.nex_key_file {
            Some(path) => read(path)?,
            None => std::env::var(NEX_KEY_ENV).map_err(|_| {
                format!("the seller needs its Nexus key: --nex-key-file or {NEX_KEY_ENV}")
            })?,
        };
        let mut seed = [0u8; 32];
        hex::decode_to_slice(hex.trim(), &mut seed)
            .map_err(|_| "the Nexus key is not 32 bytes of hex")?;
        Ok(SecretBytes(seed))
    }
}

#[derive(Args)]
struct OfferArgs {
    #[command(flatten)]
    terms: TermsArgs,
    /// Where to listen for the buyer.
    #[arg(long)]
    listen: SocketAddr,
    /// The address the buyer dials, if not the one listened on.
    #[arg(long)]
    advertise: Option<SocketAddr>,
    /// Seconds to wait for the buyer to dial.
    #[arg(long, default_value_t = 600)]
    wait: u64,
    /// The directory the swap file goes in.
    #[arg(long, default_value = ".")]
    dir: PathBuf,
    #[command(flatten)]
    nodes: NodeArgs,
    #[command(flatten)]
    key: NexKeyArgs,
}

#[derive(Args)]
struct TakeArgs {
    /// A file holding the offer, or `-` to read it from standard input.
    offer: PathBuf,
    /// Where the NEX is paid.
    #[arg(long)]
    nex_address: String,
    /// The fewest Nexus confirmations of the NEX lock this buyer accepts.
    #[arg(long, default_value_t = 24)]
    min_nex_confirmations: u64,
    /// The directory the swap file goes in.
    #[arg(long, default_value = ".")]
    dir: PathBuf,
    #[command(flatten)]
    nodes: NodeArgs,
}

#[derive(Args)]
struct SwapFileArgs {
    /// The swap file, `<swap id>.json`.
    swap_file: PathBuf,
    #[command(flatten)]
    nodes: NodeArgs,
    #[command(flatten)]
    key: NexKeyArgs,
}

/// The least `t1` this tool runs: the BTC lock `btc_confirmations` deep,
/// then the NEX lock mined and `nex_confirmations` deep, at about six
/// Bitcoin blocks a Nexus block, still `margin` blocks before cancel.
fn t1_floor(terms: &Terms) -> u64 {
    let nexus =
        BTC_BLOCKS_PER_NEXUS_BLOCK.saturating_mul(terms.nex_confirmations.saturating_add(1));
    u64::from(terms.btc_confirmations)
        .saturating_add(nexus)
        .saturating_add(u64::from(terms.margin))
}

/// Terms this tool runs: they can work, and `t1` leaves time for both locks.
fn check_terms(terms: &Terms) -> std::result::Result<(), String> {
    if !terms.check() {
        return Err(
            "the terms cannot work: confirmations must be at least 1, the margin at \
                    least 2, t1 and t2 above btc_confirmations + margin, and nex_amount above \
                    nex_fee"
                .into(),
        );
    }
    let floor = t1_floor(terms);
    if u64::from(terms.t1) < floor {
        return Err(format!(
            "t1 is {}, below {floor}: btc_confirmations + 6 x (nex_confirmations + 1) + margin",
            terms.t1
        ));
    }
    Ok(())
}

/// What the buyer needs to take the swap: the terms, where the seller
/// listens and its key, and the session key the seller made for the buyer,
/// the only one it accepts. Whoever holds an offer can take it.
#[derive(Debug, PartialEq, Serialize, Deserialize)]
struct Offer {
    terms: Terms,
    address: SocketAddr,
    seller: String,
    #[serde(with = "hex::serde")]
    buyer_session: [u8; 32],
}

impl Offer {
    fn encode(&self) -> String {
        serde_json::to_string(self).expect("offers serialize")
    }

    fn decode(text: &str) -> Result<Self> {
        let offer: Offer =
            serde_json::from_str(text.trim()).map_err(|e| format!("not an offer: {e}"))?;
        offer.seller_key()?;
        Ok(offer)
    }

    fn seller_key(&self) -> Result<PeerKey> {
        Ok(PeerKey::from_hex(&self.seller).ok_or("the offer's seller key is not a key")?)
    }
}

/// A Nexus address as Lattice prints one: a CIDv1, dag-cbor, sha2-256, in
/// lowercase base32. NEX paid to anything else is lost.
fn check_nex_address(text: &str) -> Result<()> {
    let binary = text
        .strip_prefix('b')
        .and_then(|rest| {
            data_encoding::BASE32_NOPAD
                .decode(rest.to_ascii_uppercase().as_bytes())
                .ok()
        })
        .filter(|binary| binary.len() == 36 && binary.starts_with(&[0x01, 0x71, 0x12, 0x20]));
    match binary {
        Some(_) if text == text.to_ascii_lowercase() => Ok(()),
        _ => Err(format!("{text} is not a Nexus address").into()),
    }
}

fn offer(args: OfferArgs) -> Result<()> {
    let key = args.key.load()?;
    let terms = args.terms.terms(random32());
    check_terms(&terms)?;
    let bitcoin = args.nodes.bitcoin()?;
    let nexus = args.nodes.nexus()?;
    let redeem = args.nodes.payout(&bitcoin)?;
    let punish = args.nodes.payout(&bitcoin)?;
    let seller = Seller::new(terms.clone(), key.nex_address(), redeem, punish)
        .map_err(|refusal| format!("refused: {refusal:?}"))?;
    fs::create_dir_all(&args.dir)?;
    let store = Store::new(&args.dir, terms.swap_id);

    let listener = TcpListener::bind(args.listen)?;
    let config = ivy::Config::new(SigningKey::from_bytes(&random32()));
    let buyer_session = random32();
    let buyer = ivy::Config::new(SigningKey::from_bytes(&buyer_session)).peer_key();
    let offer = Offer {
        terms,
        address: args.advertise.unwrap_or(listener.local_addr()?),
        seller: config.peer_key().hex(),
        buyer_session,
    };
    println!("{}", offer.encode());
    io::stdout().flush()?;
    log("waiting for the buyer");
    let transport = Ivy::accept(
        listener,
        &config,
        buyer,
        Duration::from_secs(args.wait),
        TIMEOUT,
    )?;
    log(&format!("swap file {}", store.path().display()));
    let mut driver = Driver::start(seller, vec![], bitcoin, nexus, Some(transport), store)?;
    driver.nex_key = Some(key);
    run(driver)
}

fn take(args: TakeArgs) -> Result<()> {
    let text = if args.offer == Path::new("-") {
        let mut text = String::new();
        io::stdin().read_to_string(&mut text)?;
        text
    } else {
        read(&args.offer)?
    };
    let offer = Offer::decode(&text)?;
    check_terms(&offer.terms)?;
    if offer.terms.nex_confirmations < args.min_nex_confirmations {
        return Err(format!(
            "the offer asks {} Nexus confirmations, fewer than {}",
            offer.terms.nex_confirmations, args.min_nex_confirmations
        )
        .into());
    }
    check_nex_address(&args.nex_address)?;
    let bitcoin = args.nodes.bitcoin()?;
    let nexus = args.nodes.nexus()?;
    let refund = args.nodes.payout(&bitcoin)?;
    let (buyer, actions) = Buyer::start(offer.terms.clone(), refund, args.nex_address)
        .map_err(|refusal| format!("refused: {refusal:?}"))?;
    fs::create_dir_all(&args.dir)?;
    let store = Store::new(&args.dir, offer.terms.swap_id);

    let config = ivy::Config::new(SigningKey::from_bytes(&offer.buyer_session));
    let transport = Ivy::connect(offer.address, &config, offer.seller_key()?, TIMEOUT)?;
    log(&format!("swap file {}", store.path().display()));
    run(Driver::start(
        buyer,
        actions,
        bitcoin,
        nexus,
        Some(transport),
        store,
    )?)
}

fn resume(args: SwapFileArgs) -> Result<()> {
    let store = swap_store(&args.swap_file)?;
    let bitcoin = args.nodes.bitcoin()?;
    let nexus = args.nodes.nexus()?;
    match Saved::load(store.path())? {
        Saved::Seller(seller) => {
            let key = match seller.outcome() {
                Some(_) => None,
                None => Some(args.key.load()?),
            };
            let mut driver = Driver::<Seller, _, Ivy>::resume(bitcoin, nexus, None, store)?;
            driver.nex_key = key;
            run(driver)
        }
        Saved::Buyer(_) => run(Driver::<Buyer, _, Ivy>::resume(
            bitcoin, nexus, None, store,
        )?),
    }
}

fn status(swap_file: &Path) -> Result<()> {
    let path = swap_store(swap_file)?;
    let (role, state, outcome) = match Saved::load(path.path())? {
        Saved::Seller(seller) => ("seller", state_name(&seller), seller.outcome()),
        Saved::Buyer(buyer) => ("buyer", state_name(&buyer), buyer.outcome()),
    };
    match outcome {
        // Both sides end in the same state, which does not say whose it is.
        Some(outcome) => println!("state: {state}\noutcome: {outcome:?}"),
        None => println!("role: {role}\nstate: {state}"),
    }
    Ok(())
}

/// Runs the swap to its end, logging each state it reaches.
fn run<M: Machine, B: Bitcoin, T: Transport>(mut driver: Driver<M, B, T>) -> Result<()> {
    let last = RefCell::new(String::new());
    let outcome = driver.run_until(|state| {
        let name = state_name(state);
        if *last.borrow() != name {
            log(&name);
            *last.borrow_mut() = name;
        }
        false
    })?;
    let outcome = outcome.expect("only an outcome ends a run that never stops");
    println!("outcome: {outcome:?}");
    Ok(())
}

/// A swap file as the driver saved it.
enum Saved {
    Seller(Seller),
    Buyer(Buyer),
}

impl Saved {
    /// Both machines have `ClaimingNex` and `Done`. A claim names its side;
    /// a swap that is done no longer needs one.
    fn load(path: &Path) -> Result<Self> {
        let value: Value = serde_json::from_str(&read(path)?)?;
        if value["ClaimingNex"]["setup"]["side"] != "Buyer" {
            if let Ok(seller) = serde_json::from_value(value.clone()) {
                return Ok(Saved::Seller(seller));
            }
        }
        let buyer = serde_json::from_value(value)
            .map_err(|e| format!("{} is not a swap file: {e}", path.display()))?;
        Ok(Saved::Buyer(buyer))
    }
}

/// The store a swap file belongs to: the driver names each by its swap id.
fn swap_store(path: &Path) -> Result<Store> {
    let swap_id = path
        .file_stem()
        .filter(|_| path.extension().is_some_and(|e| e == "json"))
        .and_then(|stem| hex::decode(stem.to_str()?).ok())
        .and_then(|bytes| <[u8; 32]>::try_from(bytes).ok())
        .ok_or_else(|| format!("{} is not named <swap id>.json", path.display()))?;
    let directory = match path.parent() {
        Some(parent) if !parent.as_os_str().is_empty() => parent,
        _ => Path::new("."),
    };
    Ok(Store::new(directory, swap_id))
}

/// The name of a machine's state: its variant.
fn state_name<M: Machine>(state: &M) -> String {
    match serde_json::to_value(state) {
        Ok(Value::Object(map)) => map.keys().next().cloned().unwrap_or_default(),
        Ok(Value::String(name)) => name,
        _ => String::new(),
    }
}

fn read(path: &Path) -> Result<String> {
    fs::read_to_string(path).map_err(|e| format!("{}: {e}", path.display()).into())
}

fn random32() -> [u8; 32] {
    let mut bytes = [0u8; 32];
    OsRng.fill_bytes(&mut bytes);
    bytes
}

fn log(what: &str) {
    eprintln!("lattice-swap: {what}");
}

fn main() -> ExitCode {
    let result = match Cli::parse().command {
        Command::Offer(args) => offer(args),
        Command::Take(args) => take(args),
        Command::Resume(args) | Command::Refund(args) => resume(args),
        Command::Status { swap_file } => status(&swap_file),
    };
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            log(&e.to_string());
            ExitCode::FAILURE
        }
    }
}

#[cfg(test)]
mod tests;
