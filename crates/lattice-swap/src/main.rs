//! `lattice-swap`: one side of a NEX<->BTC swap, run against public nodes
//! by default, mempool.space's Esplora and a public Nexus read node, or the
//! operator's own bitcoind or Esplora and lattice-node, each chain on its
//! own.
//!
//! The seller runs `offer`: it listens, or lists the offer on a relay, and
//! prints an offer for the buyer. The buyer runs `take` on that offer, which
//! dials the seller, or reaches it through the relay. Each side then runs
//! its [`Driver`] until the swap ends, meeting the other again whenever
//! their session is lost, and
//! saving its state to a swap file that `resume` carries on from after a
//! restart and `status` reads.
//!
//! A relay's operator runs `relay-dir add` to list the relay on the relay
//! directory, where takers find relays, and `relay-dir remove` to unlist it.

use std::cell::RefCell;
use std::collections::BTreeMap;
use std::fs;
use std::io::{self, Read, Write};
use std::net::{SocketAddr, TcpListener};
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::sync::Arc;
use std::time::Duration;

use bitcoin::address::NetworkUnchecked;
use bitcoin::{Address, Amount, FeeRate, Network, OutPoint, Script, ScriptBuf, Transaction, Txid};
use clap::{Args, Parser, Subcommand};
use ed25519_dalek::SigningKey;
use rand_core::{OsRng, RngCore};
use serde_json::json;
use swap::app::{self, Wallet};
use swap::bitcoind::{Bitcoin, Bitcoind, Tip};
use swap::driver::{Driver, NexusCheck, Store};
use swap::esplora::Esplora;
use swap::offer::{self, check_offer, Answer, Bounds, Offer, Place, Policy, Quote, Template};
use swap::session::{
    check_nex_address, state_name, swap_store, Result, Saved, Session, SessionFile, TIMEOUT,
};
use swap::transport::{Ivy, Transport};
use swap::{relay_dir, Buyer, Machine, Message, Outcome, SecretBytes, Seller, Terms};
use swap_nexus_tx::rpc::{parse, Client};
use swap_nexus_tx::{relay_dir_action, TransactionBody};
/// Holds the seller's Nexus wallet key when no key file is given.
const NEX_KEY_ENV: &str = "LATTICE_SWAP_NEX_KEY";
/// Holds the password for `--btc-user`.
const BTC_PASSWORD_ENV: &str = "LATTICE_SWAP_BTC_PASSWORD";
/// The blocks the buyer's fee estimate aims to confirm in.
const FEE_TARGET: u16 = 6;
/// The public Nexus node read by default: a read port that takes submits.
const PUBLIC_NEXUS: &str = "https://lattice-mainnet-read.fly.dev";
/// The relay directory's chain, by default: testnet's.
const RELAY_DIR_CHAIN: &str = "Nexus/testnet/swap-relays";
/// What a seller is told without its Nexus key.
const NO_KEY: &str = "the seller needs its Nexus key: --nex-key-file or LATTICE_SWAP_NEX_KEY";

#[derive(Parser)]
#[command(
    name = "lattice-swap",
    version,
    about = "Atomic swaps between NEX and BTC",
    after_help = "Exit status of offer, take and resume: 0 Swapped, 3 Refunded, 4 Punished, \
                  5 Drained, 6 Aborted; 1 an error stopped the tool before the swap ended, and \
                  if the swap file exists it prints how to resume; 2 bad arguments. status \
                  exits 0 once it reads the swap file."
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Sell NEX for BTC. Prints an offer, one line, to hand to the buyer
    /// privately or lists it on a relay, waits for the buyer, then runs the
    /// swap to its end.
    Offer(OfferArgs),
    /// Buy NEX with BTC: dials the seller an offer names, or reaches it
    /// through the offer's relay, and runs the swap to its end.
    Take(TakeArgs),
    /// Carries on a swap from its swap file until it ends, from the chains
    /// and, while the swap still needs one, a new session to the other
    /// party. A swap still waiting on a message cancels and refunds once its
    /// timelocks allow, so `refund` is this same command. A punished buyer
    /// asks the seller for its key share once on each resume, and claims
    /// the NEX with it; a punished seller, here or in `offer`, keeps
    /// running to give it until the buyer has claimed or the lock never
    /// landed. Stopped before then, it answers again once resumed.
    #[command(visible_alias = "refund")]
    Resume(SwapFileArgs),
    /// Prints the address and balance of the wallet a swap on an Esplora
    /// pays its BTC to, and funds a buyer's lock from: `wallet.json` in
    /// --dir, made there by the first such swap or by this. With
    /// --withdraw, first sends all it can spend to that address. Refused
    /// while a swap in --dir runs; with --withdraw, also while one has not
    /// ended.
    Wallet(WalletArgs),
    /// Prints a swap's state and outcome from its swap file. Asks no node.
    Status {
        /// The swap file, `<swap id>.json`.
        swap_file: PathBuf,
    },
    /// Lists a relay on the relay directory, the chain takers find relays
    /// on, under the key's account, or unlists it. Each account lists one
    /// relay, and only the account's key writes it.
    #[command(subcommand)]
    RelayDir(RelayDirCommand),
}

#[derive(Subcommand)]
enum RelayDirCommand {
    /// Lists the relay at --url, in place of the one the account lists now.
    Add {
        /// The relay's base URL: `https://`, to a public host.
        #[arg(long)]
        url: String,
        #[command(flatten)]
        write: RelayDirArgs,
    },
    /// Unlists the account's relay.
    Remove(RelayDirArgs),
}

/// A write to the relay directory, paid for by the account that makes it,
/// sent to a node that hosts the directory's chain.
#[derive(Args)]
struct RelayDirArgs {
    /// A file holding the account's key, readable by its owner alone: its
    /// Ed25519 seed in hex, or a key file `lattice key generate` writes.
    #[arg(long)]
    key: PathBuf,
    /// The relay directory's chain path.
    #[arg(long, default_value = RELAY_DIR_CHAIN)]
    chain: String,
    /// The fee paid on that chain, from the account's balance there. A
    /// node whose relay floor is higher refuses it, and so does this tool.
    #[arg(long, default_value_t = 0)]
    fee: u64,
    /// The URL of a node that hosts --chain, required as no default node
    /// does: a public read port, which must take submits, or with
    /// --nexus-cookie your own lattice-node's RPC.
    #[arg(long)]
    nexus_url: String,
    /// Your own lattice-node's RPC cookie file, with its --nexus-url.
    #[arg(long, requires = "nexus_url")]
    nexus_cookie: Option<PathBuf>,
}

/// Defaults are this tool's settings, not protocol rules.
#[derive(Args)]
struct TermsArgs {
    /// The price, in sats per NEX, 1 NEX = 1,000,000 base units.
    #[arg(long)]
    price: u64,
    /// The least BTC to receive, in satoshis.
    #[arg(long)]
    min_btc_amount: u64,
    /// The most BTC to receive, in satoshis.
    #[arg(long)]
    max_btc_amount: u64,
    /// Paid by each Bitcoin swap transaction, in satoshis.
    #[arg(long)]
    btc_fee: u64,
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
    #[arg(long, default_value_t = 12)]
    nex_confirmations: u64,
    /// Bitcoin blocks of slack before a timelock.
    #[arg(long, default_value_t = 12)]
    margin: u16,
}

impl TermsArgs {
    fn quote(&self) -> Quote {
        Quote {
            price: self.price,
            min_btc_amount: self.min_btc_amount,
            max_btc_amount: self.max_btc_amount,
        }
    }

    fn template(&self, swap_id: [u8; 32], nexus_genesis: String) -> Template {
        Template {
            swap_id,
            btc_fee: Amount::from_sat(self.btc_fee),
            nex_fee: self.nex_fee,
            t1: self.t1,
            t2: self.t2,
            btc_confirmations: self.btc_confirmations,
            nex_confirmations: self.nex_confirmations,
            margin: self.margin,
            nexus_genesis,
        }
    }
}

/// Each chain is read through a public node unless its flags name your own:
/// Bitcoin through mempool.space's Esplora for --btc-network, or --esplora,
/// or your bitcoind with --btc-wallet; Nexus through the public read node,
/// or --nexus-url, your own node's RPC with --nexus-cookie.
#[derive(Args, Clone)]
struct NodeArgs {
    /// Your own Esplora API, as a mempool instance serves one, e.g.
    /// `http://127.0.0.1:3006/api`, instead of mempool.space's. On an
    /// Esplora, the BTC is paid to, and a buyer's lock funded from, the
    /// wallet in the swap's directory: see `lattice-swap wallet`.
    #[arg(long, conflicts_with_all = ["btc_url", "btc_wallet", "btc_cookie", "btc_user"])]
    esplora: Option<String>,
    /// bitcoind's RPC URL, without the wallet path; http://127.0.0.1:8332
    /// if left out.
    #[arg(long, requires = "btc_wallet")]
    btc_url: Option<String>,
    /// The bitcoind wallet that funds the lock or receives the BTC: your
    /// own bitcoind, instead of an Esplora.
    #[arg(long, requires = "btc_auth")]
    btc_wallet: Option<String>,
    /// bitcoind's cookie file, or any file holding `user:password`.
    #[arg(long, group = "btc_auth", requires = "btc_wallet")]
    btc_cookie: Option<PathBuf>,
    /// A bitcoind RPC user, whose password is read from
    /// LATTICE_SWAP_BTC_PASSWORD.
    #[arg(
        long,
        group = "btc_auth",
        conflicts_with = "btc_cookie",
        requires = "btc_wallet"
    )]
    btc_user: Option<String>,
    /// bitcoin, testnet, testnet4, signet or regtest.
    #[arg(long, default_value_t = Network::Bitcoin)]
    btc_network: Network,
    /// The Nexus node's URL: a public read port, which must take submits,
    /// or with --nexus-cookie your own lattice-node's RPC.
    #[arg(long, default_value = PUBLIC_NEXUS)]
    nexus_url: String,
    /// Your own lattice-node's RPC cookie file, with its --nexus-url.
    #[arg(long, requires = "nexus_url")]
    nexus_cookie: Option<PathBuf>,
    /// The CID of the genesis block of the Nexus to trade on: the
    /// lattice-node must follow that chain. Mainnet's by default.
    #[arg(long, default_value = swap_nexus_tx::MAINNET_GENESIS)]
    nexus_genesis: String,
    /// Lets `offer` and `take` trade mainnet NEX for BTC on another
    /// --btc-network than bitcoin, whose coins are worth nothing: only to
    /// test with tiny amounts. Refused without it.
    #[arg(long)]
    test_btc_for_mainnet_nex: bool,
}

impl NodeArgs {
    /// The Bitcoin to swap on, which must be one a swap can rely on: the
    /// bitcoind, or the Esplora over the wallet in `dir`, held open while
    /// the swap runs. Says which.
    fn bitcoin(&self, dir: &Path) -> Result<Btc> {
        let bitcoin = self.open_bitcoin(dir)?;
        bitcoin.check(self.btc_network)??;
        Ok(bitcoin)
    }

    /// [`NodeArgs::bitcoin`], not yet checked.
    fn open_bitcoin(&self, dir: &Path) -> Result<Btc> {
        let Some(wallet) = &self.btc_wallet else {
            let url = esplora_url(self.esplora.as_deref(), self.btc_network)?;
            let whose = if self.public_bitcoin() {
                "public"
            } else {
                "your node"
            };
            log(&format!("bitcoin: {whose} {url}"));
            // Only the Esplora and the directory are read: Nexus is this
            // tool's own.
            let config = app::Config::new(
                dir.into(),
                self.btc_network,
                url,
                String::new(),
                None,
                String::new(),
            );
            let wallet = Wallet::open(config)?;
            return Ok(Btc::Esplora(wallet.esplora(), wallet));
        };
        let auth = match (&self.btc_cookie, &self.btc_user) {
            (Some(path), _) => read(path)?,
            (None, Some(user)) => {
                let password = std::env::var(BTC_PASSWORD_ENV)
                    .map_err(|_| format!("--btc-user needs {BTC_PASSWORD_ENV}"))?;
                format!("{user}:{password}")
            }
            (None, None) => return Err("--btc-cookie or --btc-user is required".into()),
        };
        log(&format!("bitcoin: your node {}", self.btc_url()));
        let bitcoin = Bitcoind::new(&self.wallet_url(wallet), &auth, self.btc_network, TIMEOUT);
        Ok(Btc::Node(bitcoin))
    }

    fn btc_url(&self) -> &str {
        self.btc_url.as_deref().unwrap_or("http://127.0.0.1:8332")
    }

    /// The wallet's RPC URL, its name percent-escaped.
    fn wallet_url(&self, wallet: &str) -> String {
        let wallet: String = wallet
            .bytes()
            .map(|b| match b {
                b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' | b'_' | b'~' => {
                    char::from(b).to_string()
                }
                _ => format!("%{b:02X}"),
            })
            .collect();
        format!("{}/wallet/{wallet}", self.btc_url().trim_end_matches('/'))
    }

    /// Whether Bitcoin is read through mempool.space's Esplora: by
    /// default, or named by --esplora.
    fn public_bitcoin(&self) -> bool {
        self.btc_wallet.is_none()
            && self.esplora.as_deref().is_none_or(|url| {
                Some(url.trim_end_matches('/')) == app::default_esplora(self.btc_network)
            })
    }

    /// Whether Nexus is read through a public read port.
    fn public_nexus(&self) -> bool {
        self.nexus_cookie.is_none()
    }

    /// Whether either chain is read through a public node.
    fn public(&self) -> bool {
        self.public_bitcoin() || self.public_nexus()
    }

    /// The driver's poll: the app's on a public node, whose rate limits
    /// reads every 250 ms would run into; else the driver's own.
    fn poll(&self) -> Option<Duration> {
        self.public().then_some(app::POLL)
    }

    /// Says what `trusts` says of each chain read through a public node.
    fn trust(&self, trusts: [&str; 2]) {
        if self.public_bitcoin() {
            log(trusts[0]);
        }
        if self.public_nexus() {
            log(trusts[1]);
        }
    }

    /// A client for the Nexus node: your lattice-node's RPC, which reads
    /// its cookie file again on a 401, as the node writes a new cookie at
    /// every restart, and fails each request while there is none; else a
    /// public read port, with no cookie. Says which.
    fn nexus(&self) -> Client {
        let Some(cookie) = &self.nexus_cookie else {
            log(&format!("nexus: public {}", self.nexus_url));
            return Client::public(&self.nexus_url, TIMEOUT);
        };
        log(&format!("nexus: your node {}", self.nexus_url));
        Client::from_cookie_file(&self.nexus_url, cookie, TIMEOUT)
    }

    /// Refuses a public node that takes no transactions, then a Nexus
    /// node on another Nexus than `--nexus-genesis` names, or one that
    /// cannot say how deep a transaction is: see
    /// [`swap::session::check_nexus`].
    fn check_nexus(&self, client: &Client) -> Result<()> {
        if let Some(why) = self.takes_no_transactions(client)? {
            return Err(format!(
                "refused: {why}: give a public node that does, or your own with --nexus-cookie"
            )
            .into());
        }
        self.check_nexus_chain(client)
    }

    /// As [`NodeArgs::check_nexus`], for a swap resumed, which it never
    /// refuses: a taken swap's cancel, refund, redeem and punish are
    /// Bitcoin's, and a node that fails, even for a moment, must not stop
    /// them. The driver's [`nexus_check`](swap::driver::Driver::nexus_check),
    /// asked at every read, under its Nexus budget, until the node passes,
    /// Nexus unread till then, and its genesis compared on every view
    /// after. A public node that takes no transactions is warned of, asked
    /// until it answers once, its Nexus submits failing.
    fn resumed_check(&self) -> NexusCheck {
        let genesis = self.nexus_genesis.clone();
        let mut chain =
            swap::session::check_once(move |client| check_nexus_chain(client, &genesis));
        let nodes = self.clone();
        let mut told = false;
        Box::new(move |client| {
            let gated = chain(client);
            if !told {
                if let Ok(takes_none) = nodes.takes_no_transactions(client) {
                    told = true;
                    if let Some(why) = takes_none {
                        log(&format!(
                            "{why}: the swap's Bitcoin side goes on, its Nexus submits fail"
                        ));
                    }
                }
            }
            gated
        })
    }

    /// Why a public node takes no transactions, if it takes none.
    fn takes_no_transactions(&self, client: &Client) -> Result<Option<String>> {
        let none = self.nexus_cookie.is_none() && client.chain_info()?["acceptsSubmit"] != true;
        Ok(none.then(|| format!("{} takes no transactions", self.nexus_url)))
    }

    /// Refuses a Nexus node on another Nexus than `--nexus-genesis` names,
    /// or one that cannot say how deep a transaction is.
    fn check_nexus_chain(&self, client: &Client) -> Result<()> {
        check_nexus_chain(client, &self.nexus_genesis)
    }
}

/// Refuses a Nexus node on another Nexus than `genesis`, the one
/// `--nexus-genesis` names, or one that cannot say how deep a transaction
/// is.
fn check_nexus_chain(client: &Client, genesis: &str) -> Result<()> {
    use swap_nexus_tx::rpc::parse::NodeRefusal;
    swap::session::check_nexus(client, genesis)?.map_err(|refusal| {
        match refusal {
            NodeRefusal::OtherNexus { .. } => {
                format!("{refusal}, the one --nexus-genesis names")
            }
            NodeRefusal::NoPastState => {
                format!("{refusal}: run it with --state all and --block-bodies all")
            }
            NodeRefusal::Malformed(_) => refusal.to_string(),
        }
        .into()
    })
}

/// The Esplora at `given`, else mempool.space's for `network`.
fn esplora_url(given: Option<&str>, network: Network) -> Result<String> {
    match given.or(app::default_esplora(network)) {
        Some(url) => Ok(url.into()),
        None => Err(format!(
            "{network} has no public Esplora: give --esplora, or --btc-wallet for your bitcoind"
        )
        .into()),
    }
}

/// What each side trusts a public node for, Bitcoin's then Nexus's, said
/// of each chain it reads through one.
const SELLER_TRUSTS: [&str; 2] = [
    "the seller trusts mempool.space for how deep the buyer's BTC lock is: keep \
     --max-btc-amount small",
    "the seller trusts the public Nexus node for its claim of the NEX back on a refund: keep \
     --max-btc-amount small",
];
const BUYER_TRUSTS: [&str; 2] = [
    "the buyer trusts mempool.space to show Bitcoin in time to refund: keep --btc-amount small",
    "the buyer trusts the public Nexus node for how deep the seller's NEX lock is: keep \
     --btc-amount small",
];

/// The Bitcoin a party swaps on: its own bitcoind and wallet, or an
/// Esplora over the wallet in its swap's directory, held open while it
/// runs, as an app holds it.
enum Btc {
    Node(Bitcoind),
    /// The wallet held, as its lock keeps other swaps and a withdrawal out
    /// of the directory.
    Esplora(Esplora, Arc<Wallet>),
}

impl Btc {
    /// Whether a swap can rely on this Bitcoin, as
    /// [`Bitcoind::check_node`] and [`Esplora::check_network`] say: refused
    /// (`Ok(Err)`), or not told yet (`Err`).
    fn check(&self, network: Network) -> swap::bitcoind::Result<swap::bitcoind::Result<()>> {
        match self {
            Btc::Node(bitcoind) => bitcoind.check_node(),
            Btc::Esplora(esplora, _) => esplora.check_network(network),
        }
    }
}

/// `$body`, with `$bitcoin` the [`Btc`]'s own client.
macro_rules! either {
    ($btc:expr, $bitcoin:ident => $body:expr) => {
        match $btc {
            Btc::Node($bitcoin) => $body,
            Btc::Esplora($bitcoin, _) => $body,
        }
    };
}

impl Bitcoin for Btc {
    fn broadcast(&self, tx: &Transaction) -> swap::bitcoind::Result<()> {
        either!(self, b => b.broadcast(tx))
    }
    fn tip(&self) -> swap::bitcoind::Result<Tip> {
        either!(self, b => b.tip())
    }
    fn transaction(&self, txid: Txid) -> swap::bitcoind::Result<Option<(Transaction, u32)>> {
        either!(self, b => b.transaction(txid))
    }
    fn spender(
        &self,
        outpoint: OutPoint,
        from: u32,
    ) -> swap::bitcoind::Result<Option<(Transaction, u32)>> {
        either!(self, b => b.spender(outpoint, from))
    }
    fn fund_lock(
        &self,
        script: &Script,
        amount: Amount,
        fee_rate: FeeRate,
    ) -> swap::bitcoind::Result<Transaction> {
        either!(self, b => b.fund_lock(script, amount, fee_rate))
    }
    fn fee_rate(&self, urgent: bool) -> swap::bitcoind::Result<Option<FeeRate>> {
        either!(self, b => b.fee_rate(urgent))
    }
    fn floor(&self, parent: &Transaction) -> swap::bitcoind::Result<FeeRate> {
        either!(self, b => b.floor(parent))
    }
    fn package_rate(&self, parent: &Transaction) -> swap::bitcoind::Result<Option<FeeRate>> {
        either!(self, b => b.package_rate(parent))
    }
    fn bump(
        &self,
        parent: &Transaction,
        fee: Amount,
        rate: FeeRate,
        max: Amount,
    ) -> swap::bitcoind::Result<Txid> {
        either!(self, b => b.bump(parent, fee, rate, max))
    }
}

impl Btc {
    /// Where the BTC is paid, as its script: a fresh address from the
    /// bitcoind wallet, or the Esplora wallet's own.
    fn payout(&self, network: Network) -> Result<ScriptBuf> {
        let bitcoin = match self {
            Btc::Node(bitcoin) => bitcoin,
            Btc::Esplora(esplora, _) => return Ok(esplora.key().script_pubkey.clone()),
        };
        let address = bitcoin.call("getnewaddress", json!([]))?;
        let address: Address<NetworkUnchecked> = address
            .as_str()
            .ok_or("getnewaddress returned no address")?
            .parse()?;
        Ok(address.require_network(network)?.script_pubkey())
    }

    /// The conservative fee estimate for `FEE_TARGET` blocks, in sat/kvB,
    /// if there is one.
    fn fee_estimate(&self) -> Result<Option<u64>> {
        match self {
            Btc::Node(bitcoin) => {
                let estimate =
                    bitcoin.call("estimatesmartfee", json!([FEE_TARGET, "CONSERVATIVE"]))?;
                match estimate["feerate"].as_f64() {
                    Some(btc) => Ok(Some(Amount::from_btc(btc)?.to_sat())),
                    None => Ok(None),
                }
            }
            // As the app reads its floor.
            Btc::Esplora(esplora, _) => Ok(esplora
                .estimate(&FEE_TARGET.to_string())?
                .map(|rate| (rate * 1000.0).ceil() as u64)),
        }
    }
}

#[derive(Args)]
struct NexKeyArgs {
    /// A file holding the seller's Nexus wallet key, its Ed25519 seed in
    /// hex, readable by its owner alone; or set LATTICE_SWAP_NEX_KEY. It
    /// never reaches the swap file.
    #[arg(long)]
    nex_key_file: Option<PathBuf>,
}

impl NexKeyArgs {
    fn load(&self) -> Result<SecretBytes> {
        Ok(self.given()?.ok_or(NO_KEY)?)
    }

    /// The key, if one is given.
    fn given(&self) -> Result<Option<SecretBytes>> {
        let hex = match &self.nex_key_file {
            Some(path) => return key_file(path).map(Some),
            None => match std::env::var(NEX_KEY_ENV) {
                Ok(hex) => hex,
                Err(_) => return Ok(None),
            },
        };
        nex_key(&hex).map(Some)
    }
}

/// The Nexus key in `path`, which only its owner may read.
fn key_file(path: &Path) -> Result<SecretBytes> {
    owner_only(path)?;
    nex_key(&read(path)?)
}

/// The key in `path`, which only its owner may read: its seed in hex, as
/// [`key_file`] reads it, or a key file `lattice key generate` writes,
/// `{"privateKey", "publicKey", ...}`, the seed in hex beside its Multikey,
/// which must be the seed's.
fn relay_dir_key(path: &Path) -> Result<SecretBytes> {
    owner_only(path)?;
    let text = read(path)?;
    if !text.trim_start().starts_with('{') {
        return nex_key(&text);
    }
    #[derive(serde::Deserialize)]
    #[serde(rename_all = "camelCase")]
    struct KeyFile {
        private_key: String,
        public_key: String,
    }
    let file: KeyFile = serde_json::from_str(&text)
        .map_err(|e| format!("{}: not a lattice key file: {e}", path.display()))?;
    let key = nex_key(&file.private_key)?;
    let public = SigningKey::from_bytes(&key.0).verifying_key().to_bytes();
    if swap_nexus_tx::multikey_hex(&public) != file.public_key.to_ascii_lowercase() {
        return Err(format!("{}: its publicKey is not its privateKey's", path.display()).into());
    }
    Ok(key)
}

/// A Nexus key: its Ed25519 seed in hex.
fn nex_key(hex: &str) -> Result<SecretBytes> {
    let mut seed = [0u8; 32];
    hex::decode_to_slice(hex.trim(), &mut seed)
        .map_err(|_| "the Nexus key is not 32 bytes of hex")?;
    Ok(SecretBytes(seed))
}

/// How the driver bumps, by CPFP from their payout, the swap transactions
/// that pay this party, how old a Bitcoin tip it trusts, and how long it
/// gives Nexus each round. The defaults are the driver's.
#[derive(Args)]
struct BumpArgs {
    /// The most a bump pays for, in sat/vB.
    #[arg(long, value_parser = sat_per_vb, default_value = "1000")]
    max_fee_rate: FeeRate,
    /// The feerate, in sat/vB, a bump, and the buyer's lock funding, pays
    /// for when bitcoind has no fee estimate, as on regtest or a freshly
    /// synced node. The lock funding pays bitcoind's estimate, else this,
    /// never below the node's mempool minimum, and is not capped by
    /// --max-fee-rate.
    #[arg(long, value_parser = sat_per_vb, default_value = "10")]
    fallback_fee_rate: FeeRate,
    /// The share of a payout, from 0 to 1, its bump may pay in fees; 1 is
    /// all of it but dust.
    #[arg(long, value_parser = fee_fraction, default_value = "1")]
    max_fee_fraction: f64,
    /// The oldest, in minutes, a Bitcoin tip may be, since its block time
    /// or since this tool first saw it, whichever is earlier, for the
    /// seller to start a redeem or lock its NEX on it.
    #[arg(long, default_value_t = 90)]
    max_tip_age: u64,
    /// The most, in seconds, a round's Nexus requests may take, its reads
    /// and the submits they lead to: a slow or silent Nexus node delays
    /// the next look at Bitcoin by this at most. Raise it for a node far
    /// away, as over Tor, whose dozen reads a round take longer. From 1
    /// to 3600.
    #[arg(
        long,
        default_value_t = swap::driver::NEXUS_BUDGET.as_secs(),
        value_parser = clap::value_parser!(u64).range(1..=3600)
    )]
    nexus_budget: u64,
}

impl BumpArgs {
    fn apply<M: Machine, B: Bitcoin, T: Transport>(&self, driver: &mut Driver<M, B, T>) {
        driver.max_fee_rate = self.max_fee_rate;
        driver.fallback_fee_rate = self.fallback_fee_rate;
        driver.max_fee_fraction = self.max_fee_fraction;
        driver.max_tip_age = Duration::from_secs(self.max_tip_age.saturating_mul(60));
        driver.nexus_budget = Duration::from_secs(self.nexus_budget);
    }
}

fn sat_per_vb(text: &str) -> std::result::Result<FeeRate, String> {
    let rate: u64 = text.parse().map_err(|e| format!("{e}"))?;
    FeeRate::from_sat_per_vb(rate).ok_or_else(|| format!("{rate} sat/vB is too high"))
}

/// The driver refuses a fraction that is not between 0 and 1, NaN among
/// them; this refuses it before anything starts.
fn fee_fraction(text: &str) -> std::result::Result<f64, String> {
    let fraction: f64 = text.parse().map_err(|e| format!("{e}"))?;
    if !(0.0..=1.0).contains(&fraction) {
        return Err(format!("{fraction} is not between 0 and 1"));
    }
    Ok(fraction)
}

/// Refuses a key file anyone but its owner can open.
#[cfg(unix)]
fn owner_only(path: &Path) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    let mode = fs::metadata(path)
        .map_err(|e| format!("{}: {e}", path.display()))?
        .permissions()
        .mode();
    if mode & 0o077 != 0 {
        return Err(format!(
            "{} is open to others (mode {:o}): chmod 600 it",
            path.display(),
            mode & 0o777
        )
        .into());
    }
    Ok(())
}

#[cfg(not(unix))]
fn owner_only(_: &Path) -> Result<()> {
    Ok(())
}

/// A relay of the seller's own, run in this process for as long as it
/// runs: `offer` lists on it beside any --relay, so a seller with a
/// reachable address depends on no one else's relay for buyers to find it,
/// and `resume` serves it again, so a buyer that took the offer there can
/// meet the seller again there. Anyone can list offers on it too.
#[derive(Args)]
struct ServeRelayArgs {
    /// Where to run the relay. Needs --serve-relay-url.
    #[arg(long, requires = "serve_relay_url")]
    serve_relay: Option<SocketAddr>,
    /// The http:// or https:// URL buyers reach --serve-relay at, as
    /// --advertise is the address they dial: the offer listed there names
    /// it. Put TLS in front of the relay for https://.
    #[arg(long, requires = "serve_relay")]
    serve_relay_url: Option<String>,
}

impl ServeRelayArgs {
    /// The flags as given, for `resume` to be given them again: none if
    /// no relay is served.
    fn flags(&self) -> String {
        match (self.serve_relay, &self.serve_relay_url) {
            (Some(listen), Some(url)) => format!(" --serve-relay {listen} --serve-relay-url {url}"),
            _ => String::new(),
        }
    }
}

#[derive(Args)]
struct OfferArgs {
    #[command(flatten)]
    terms: TermsArgs,
    /// Where to listen for the buyer.
    #[arg(
        long,
        required_unless_present_any = ["relay", "serve_relay"],
        conflicts_with = "serve_relay"
    )]
    listen: Option<SocketAddr>,
    /// The address the buyer dials, if not the one listened on. Required
    /// when listening on an unspecified address, such as 0.0.0.0.
    #[arg(long, conflicts_with = "serve_relay")]
    advertise: Option<SocketAddr>,
    /// A relay, by its http:// or https:// URL, to list the offer on and
    /// meet the buyer through, instead of listening. Anyone can list the
    /// relay's offers and take one. Give it again to list on several: the
    /// buyer that takes the offer on one withdraws it from the others, and
    /// the offer printed names the first.
    #[arg(long, conflicts_with_all = ["listen", "advertise"])]
    relay: Vec<String>,
    #[command(flatten)]
    serve: ServeRelayArgs,
    /// Seconds to wait for the buyer to dial.
    #[arg(long, default_value_t = 600)]
    wait: u64,
    /// The fee rate, in sat/vB, that each Bitcoin swap transaction must pay
    /// when bitcoind has no fee estimate, as on regtest. Otherwise its
    /// conservative estimate for 6 blocks is the floor: cancel, which the
    /// seller needs to reclaim its NEX, pays btc-fee and is never bumped.
    #[arg(long)]
    min_btc_fee_rate: Option<u64>,
    /// The least nex-fee to offer, and the Nexus node's minRelayFee if
    /// higher: the NEX lock and the claim from it pay nex-fee, and a fee
    /// this node pools may still be below what the network relays.
    #[arg(long, default_value_t = 1)]
    min_nex_fee: u64,
    /// The directory the swap file goes in.
    #[arg(long, default_value = ".")]
    dir: PathBuf,
    #[command(flatten)]
    nodes: NodeArgs,
    #[command(flatten)]
    key: NexKeyArgs,
    #[command(flatten)]
    bump: BumpArgs,
}

#[derive(Args)]
struct TakeArgs {
    /// A file holding the offer, or `-` to read it from standard input.
    offer: PathBuf,
    /// Where the NEX is paid.
    #[arg(long)]
    nex_address: String,
    #[command(flatten)]
    policy: PolicyArgs,
    /// The directory the swap file goes in.
    #[arg(long, default_value = ".")]
    dir: PathBuf,
    #[command(flatten)]
    nodes: NodeArgs,
    #[command(flatten)]
    bump: BumpArgs,
}

/// What the buyer agreed to, and its bounds on every other term: `take`
/// refuses an offer outside them. Defaults are this tool's settings.
#[derive(Args)]
struct PolicyArgs {
    /// The BTC to pay, in satoshis, in the offer's range; the most it
    /// takes if left out, as eigenwallet swaps up to its seller's maximum.
    #[arg(long)]
    btc_amount: Option<u64>,
    /// The price agreed to, in sats per NEX, 1 NEX = 1,000,000 base units.
    #[arg(long)]
    price: u64,
    /// The most each Bitcoin swap transaction may pay, in satoshis.
    #[arg(long, default_value_t = Bounds::DEFAULT.max_btc_fee)]
    max_btc_fee: u64,
    /// The most the NEX lock and the claim from it may pay.
    #[arg(long, default_value_t = Bounds::DEFAULT.max_nex_fee)]
    max_nex_fee: u64,
    /// The least the NEX lock and the claim from it may pay, and the Nexus
    /// node's minRelayFee if higher: a fee this node pools may still be
    /// below what the network relays.
    #[arg(long, default_value_t = Bounds::DEFAULT.min_nex_fee)]
    min_nex_fee: u64,
    /// The most Bitcoin blocks the BTC stays locked before cancel.
    #[arg(long, default_value_t = Bounds::DEFAULT.max_t1)]
    max_t1: u16,
    /// The fewest Bitcoin blocks after cancel confirms before punish is
    /// valid.
    #[arg(long, default_value_t = Bounds::DEFAULT.min_t2)]
    min_t2: u16,
    /// The fewest Bitcoin confirmations the offer may ask.
    #[arg(long, default_value_t = Bounds::DEFAULT.min_btc_confirmations)]
    min_btc_confirmations: u32,
    /// The most Bitcoin confirmations the offer may ask. Once it has signed
    /// the redeem, the buyer refunds only when cancel is this deep.
    #[arg(long, default_value_t = Bounds::DEFAULT.max_btc_confirmations)]
    max_btc_confirmations: u32,
    /// The fewest Bitcoin blocks the refund has to confirm in before punish
    /// is valid, once the buyer has signed the redeem: t2 -
    /// btc-confirmations.
    #[arg(long, default_value_t = Bounds::DEFAULT.min_refund_window)]
    min_refund_window: u16,
    /// The fee rate, in sat/vB, that each Bitcoin swap transaction must pay
    /// when bitcoind has no fee estimate, as on regtest. Otherwise its
    /// conservative estimate for 6 blocks is the floor.
    #[arg(long)]
    min_btc_fee_rate: Option<u64>,
    /// The fewest Nexus confirmations of the NEX lock this buyer accepts.
    #[arg(long, default_value_t = Bounds::DEFAULT.min_nex_confirmations)]
    min_nex_confirmations: u64,
    /// The fewest Bitcoin blocks of slack before a timelock.
    #[arg(long, default_value_t = Bounds::DEFAULT.min_margin)]
    min_margin: u16,
}

impl PolicyArgs {
    /// The policy for taking `offer`.
    fn policy(&self, offer: &Offer) -> Policy {
        Policy {
            btc_amount: self.btc_amount.unwrap_or(offer.quote.max_btc_amount),
            price: self.price,
            bounds: Bounds {
                max_btc_fee: self.max_btc_fee,
                max_nex_fee: self.max_nex_fee,
                min_nex_fee: self.min_nex_fee,
                max_t1: self.max_t1,
                min_t2: self.min_t2,
                min_btc_confirmations: self.min_btc_confirmations,
                max_btc_confirmations: self.max_btc_confirmations,
                min_refund_window: self.min_refund_window,
                min_btc_fee_rate: self.min_btc_fee_rate,
                min_nex_confirmations: self.min_nex_confirmations,
                min_margin: self.min_margin,
                ..Bounds::DEFAULT
            },
        }
    }
}

#[derive(Args)]
struct SwapFileArgs {
    /// The swap file, `<swap id>.json`.
    swap_file: PathBuf,
    #[command(flatten)]
    serve: ServeRelayArgs,
    #[command(flatten)]
    nodes: NodeArgs,
    #[command(flatten)]
    key: NexKeyArgs,
    #[command(flatten)]
    bump: BumpArgs,
}

/// The least `btc_fee` the buyer takes, in satoshis: what the node's
/// conservative estimate, or else `fallback` sat/vB, asks of every swap
/// spend.
fn btc_fee_floor(bitcoin: &Btc, fallback: Option<u64>) -> Result<u64> {
    let node = match bitcoin {
        Btc::Node(_) => "bitcoind",
        Btc::Esplora(..) => "the Esplora",
    };
    Ok(offer::btc_fee_floor(bitcoin.fee_estimate()?, fallback)
        .map_err(|_| format!("{node} has no fee estimate: give --min-btc-fee-rate"))?)
}

/// [`offer::nex_fee_floor`] at its Nexus node's relay floor.
fn nex_fee_floor(nexus: &Client, least: u64) -> Result<u64> {
    Ok(offer::nex_fee_floor(least, nexus.min_relay_fee()?))
}

/// Refuses an address the buyer cannot dial: an unspecified `--advertise`,
/// or an unspecified `--listen` without one.
fn check_listen(listen: SocketAddr, advertise: Option<SocketAddr>) -> Result<()> {
    match advertise {
        Some(advertise) if advertise.ip().is_unspecified() => {
            Err(format!("--advertise {advertise} is no address to dial").into())
        }
        None if listen.ip().is_unspecified() => {
            Err(format!("--listen {listen} is no address to dial: give --advertise").into())
        }
        _ => Ok(()),
    }
}

/// The key resume runs with: required while the swap `signs` the NEX lock,
/// and, if given, the key of `address`, which the swap sells from: a lock
/// signed with any other never verifies.
fn seller_key(
    address: Option<&str>,
    signs: bool,
    key: Option<SecretBytes>,
) -> Result<Option<SecretBytes>> {
    match (address, key) {
        (Some(address), Some(key)) if address != key.nex_address() => Err(format!(
            "the Nexus key is for {}, but the swap sells from {address}",
            key.nex_address()
        )
        .into()),
        (_, None) if signs => Err(NO_KEY.into()),
        (_, key) => Ok(key),
    }
}

/// The server `relay` names, to tell two spellings of one relay apart:
/// its scheme and host in lowercase, its port unless the scheme's default,
/// and its path without trailing slashes, as a URL parser compares them.
fn relay_server(relay: &str) -> String {
    let (scheme, rest) = relay.split_once("://").unwrap_or(("", relay));
    let scheme = scheme.to_ascii_lowercase();
    let (host, path) = rest.split_once('/').unwrap_or((rest, ""));
    let host = host.to_ascii_lowercase();
    let host = match scheme.as_str() {
        "http" => host.strip_suffix(":80"),
        "https" => host.strip_suffix(":443"),
        _ => None,
    }
    .unwrap_or(&host);
    format!("{scheme}://{host}/{}", path.trim_end_matches('/'))
}

/// `relays` with each server once, first spelling first: a relay given
/// twice would list the offer once, and refuse it again every [`RETRY`]
/// for good as listed already.
///
/// [`RETRY`]: swap::transport::RETRY
fn distinct_relays(relays: Vec<String>) -> Vec<String> {
    let mut seen = std::collections::HashSet::new();
    (relays.into_iter())
        .filter(|relay| seen.insert(relay_server(relay)))
        .collect()
}

fn offer(mut args: OfferArgs) -> Result<Outcome> {
    args.relay = distinct_relays(args.relay);
    if let Some(listen) = args.listen {
        check_listen(listen, args.advertise)?;
    }
    offer::check_networks(
        args.nodes.btc_network,
        &args.nodes.nexus_genesis,
        args.nodes.test_btc_for_mainnet_nex,
    )?;
    let template = args
        .terms
        .template(random32(), args.nodes.nexus_genesis.clone());
    let swap_id = template.swap_id;
    let quote = args.terms.quote();
    template.check(&quote)?;
    let key = args.key.load()?;
    let bitcoin = args.nodes.bitcoin(&args.dir)?;
    let floor = btc_fee_floor(&bitcoin, args.min_btc_fee_rate)?;
    if template.btc_fee.to_sat() < floor {
        return Err(format!(
            "btc_fee is {} sat, below the {floor} sat the node's fee rate asks of cancel and \
             refund",
            template.btc_fee.to_sat()
        )
        .into());
    }
    let nexus = args.nodes.nexus();
    args.nodes.check_nexus(&nexus)?;
    let floor = nex_fee_floor(&nexus, args.min_nex_fee)?;
    if template.nex_fee < floor {
        return Err(format!(
            "nex_fee is {}, below {floor}, --min-nex-fee or the node's minRelayFee: a fee \
             the network does not relay leaves the NEX lock unmined",
            template.nex_fee
        )
        .into());
    }
    args.nodes.trust(SELLER_TRUSTS);
    let redeem = bitcoin.payout(args.nodes.btc_network)?;
    let punish = bitcoin.payout(args.nodes.btc_network)?;
    fs::create_dir_all(&args.dir)?;
    let store = Store::new(&args.dir, swap_id);

    let listener = args.listen.map(TcpListener::bind).transpose()?;
    let served = match (args.serve.serve_relay, &args.serve.serve_relay_url) {
        (Some(listen), Some(url)) => Some((serve_relay(listen)?, &url[..])),
        _ => None,
    };
    let relays = relays_dialled(&args.relay, served);
    let named: Vec<String> = relays.iter().map(|(_, named)| named.clone()).collect();
    let place = match (&listener, named.first()) {
        (_, Some(relay)) => Place::Relay(relay.clone()),
        (Some(listener), None) => Place::Address(args.advertise.unwrap_or(listener.local_addr()?)),
        (None, None) => return Err("give --listen or --relay".into()),
    };
    let session = SigningKey::from_bytes(&random32());
    let config = ivy::Config::new(session.clone());
    let buyer_session = random32();
    let buyer = ivy::Config::new(SigningKey::from_bytes(&buyer_session)).peer_key();
    let offer = Offer::new(
        quote,
        template,
        args.nodes.btc_network,
        place,
        &session,
        buyer_session,
    );
    println!("{}", offer.encode());
    io::stdout().flush()?;
    let wait = Duration::from_secs(args.wait);
    let mut start = Start {
        bitcoin,
        nexus,
        nexus_genesis: args.nodes.nexus_genesis.clone(),
        store,
        nex_key: Some(key.clone()),
        bump: &args.bump,
        poll: args.nodes.poll(),
        serve: String::new(),
    };
    // The seller fixes the terms at the amount the buyer asks for, then
    // starts its machine on them.
    let seller = |terms: Terms| {
        Seller::new(terms, key.nex_address(), redeem, punish)
            .map_err(|refusal| format!("refused: {refusal:?}"))
    };
    let mut rejoin = SessionFile {
        listen: listener.as_ref().map(TcpListener::local_addr).transpose()?,
        offer: offer.clone(),
        key: Some(hex::encode(session.to_bytes())),
    };
    match (listener, relays.is_empty()) {
        (_, false) => {
            log(&format!(
                "listing the offer on {}, waiting for the buyer",
                named.join(", ")
            ));
            let offers = listed_on(&offer, &named);
            let encoded: Vec<String> = offers.iter().map(Offer::encode).collect();
            let listings: Vec<(&str, &str)> = (relays.iter().map(|(dialed, _)| &dialed[..]))
                .zip(encoded.iter().map(String::as_str))
                .collect();
            let (taken, mut transport) =
                Ivy::accept_relayed_on(&listings, &config, buyer, wait, TIMEOUT)?;
            // The two meet again on the relay the buyer took it on, the
            // only one its offer names.
            rejoin.offer = offers[taken].clone();
            let (through, serve) = rejoin_through(&relays, taken, &args.serve);
            start.serve = serve;
            let terms = answer_request(&mut transport, &offer)?;
            let transport = Box::new(transport);
            start.run(seller(terms)?, vec![], transport, rejoin, None, through)
        }
        (Some(listener), true) => {
            log("waiting for the buyer");
            let kept = listener.try_clone()?;
            let mut transport = Ivy::accept(listener, &config, buyer, wait, TIMEOUT)?;
            let terms = answer_request(&mut transport, &offer)?;
            start.run(
                seller(terms)?,
                vec![],
                Box::new(transport),
                rejoin,
                Some(kept),
                None,
            )
        }
        (None, true) => unreachable!("a place was found"),
    }
}

/// The relays to list on, each as the seller dials it and as its offer
/// names it: every one of `relays`, and the relay it serves, if any, which
/// it dials at the first and its offer names by the second. A relay of the
/// served one's server is listed on once, as the served one, whose dialling
/// does not leave the machine.
fn relays_dialled(relays: &[String], served: Option<(String, &str)>) -> Vec<(String, String)> {
    let serves = served.as_ref().map(|(_, url)| relay_server(url));
    let mut dialled: Vec<(String, String)> = (relays.iter())
        .filter(|relay| Some(relay_server(relay)) != serves)
        .map(|relay| (relay.clone(), relay.clone()))
        .collect();
    dialled.extend(served.map(|(local, url)| (local, url.to_string())));
    dialled
}

/// How the seller meets the buyer again once it took the offer on
/// `relays[taken]` ([`relays_dialled`]), and what `resume` needs given
/// again to: on the relay it serves, through its own machine, as the URL
/// the offer names may not lead back to it, and the --serve-relay flags;
/// on any other, as its offer names it, and no flags, as `resume` refuses
/// to serve a relay the swap does not meet at.
fn rejoin_through(
    relays: &[(String, String)],
    taken: usize,
    serve: &ServeRelayArgs,
) -> (Option<String>, String) {
    // The served relay is the one [`relays_dialled`] puts last: told
    // apart by place, as its URL may be the very address it is dialled at.
    if serve.serve_relay.is_none() || taken + 1 != relays.len() {
        return (None, String::new());
    }
    (Some(relays[taken].0.clone()), serve.flags())
}

/// How many sellers the relay `offer --serve-relay` runs holds at once,
/// listed or swapping, as `swap-relay` holds by default.
const SERVED_RELAY_OFFERS: usize = 10_000;

/// Runs a swap-relay on `listen`, on a thread of its own, until this
/// process ends: the relay's own router, as `swap-relay` serves it. Binds
/// before it returns, so an address in use fails the offer at once.
/// Returns the URL this process reaches it at, on its own machine.
fn serve_relay(listen: SocketAddr) -> Result<String> {
    let listener = TcpListener::bind(listen)?;
    listener.set_nonblocking(true)?;
    let mut local = listener.local_addr()?;
    if local.ip().is_unspecified() {
        local.set_ip(match local {
            SocketAddr::V4(_) => std::net::Ipv4Addr::LOCALHOST.into(),
            SocketAddr::V6(_) => std::net::Ipv6Addr::LOCALHOST.into(),
        });
    }
    let relay = Arc::new(swap_relay::Relay {
        board: swap_relay::board::Board::new(SERVED_RELAY_OFFERS),
        rejoins: swap_relay::board::Board::new(SERVED_RELAY_OFFERS),
    });
    let runtime = tokio::runtime::Runtime::new()?;
    std::thread::Builder::new().spawn(move || {
        let served = runtime.block_on(async {
            let listener = tokio::net::TcpListener::from_std(listener)?;
            swap_relay::serve(listener, relay).await
        });
        if let Err(e) = served {
            log(&format!("the relay on {listen} stopped: {e}"));
        }
    })?;
    log(&format!("serving a relay on {listen}"));
    Ok(format!("http://{local}"))
}

/// `offer` as listed on each of `relays`, naming it: one swap, one swap id
/// and one set of keys, and only the relay differs, which the seller does
/// not sign, so each copy verifies. A buyer takes the copy on the relay it
/// reads, and reaches the seller, and meets it again, there.
fn listed_on(offer: &Offer, relays: &[String]) -> Vec<Offer> {
    relays
        .iter()
        .map(|relay| Offer {
            relay: Some(relay.clone()),
            ..offer.clone()
        })
        .collect()
}

/// The terms the seller of `offer` fixes at the buyer's request, which
/// comes first on `transport`, once it has answered it with them; or why
/// it refused, once it has answered that.
fn answer_request<T: Transport>(transport: &mut T, offer: &Offer) -> Result<Terms> {
    let swap_id = offer.template.swap_id;
    let message = transport
        .recv(TIMEOUT)?
        .and_then(|payload| Message::decode(&payload, swap_id));
    let Some(Message::Request { btc_amount, price }) = message else {
        return Err("the buyer sent no request".into());
    };
    let answer = offer.answer(btc_amount, price);
    transport.send(&Message::Answer(answer.clone()).encode(swap_id))?;
    match answer {
        Answer::Terms(terms) => {
            log(&format!(
                "selling {} base units for {btc_amount} sat",
                terms.nex_amount
            ));
            Ok(terms)
        }
        Answer::Refused(why) => {
            Err(format!("refused the buyer's request for {btc_amount} sat: {why}").into())
        }
    }
}

/// What a swap starts on, once the session is up.
struct Start<'a> {
    bitcoin: Btc,
    nexus: Client,
    nexus_genesis: String,
    store: Store,
    nex_key: Option<SecretBytes>,
    bump: &'a BumpArgs,
    poll: Option<Duration>,
    /// The --serve-relay flags `resume` needs given again, for its hint:
    /// none unless the buyer took the offer on the relay served.
    serve: String,
}

impl Start<'_> {
    /// Runs `machine`, which asks for `actions` first, over `transport` to
    /// the swap's end, meeting the counterparty again by `rejoin` whenever
    /// the session is lost: the seller on `listener`, if it listens, or on
    /// the relay at `through`, if given ([`SessionFile::through`]).
    fn run<M: Machine>(
        self,
        machine: M,
        actions: Vec<swap::Action>,
        transport: Session,
        rejoin: SessionFile,
        listener: Option<TcpListener>,
        through: Option<String>,
    ) -> Result<Outcome> {
        let swap_file = self.store.path().to_path_buf();
        let driver = swap::session::start_through(
            machine,
            actions,
            self.bitcoin,
            self.nexus,
            &self.nexus_genesis,
            transport,
            self.store,
            rejoin,
            listener,
            through,
        );
        let mut driver = driver.map_err(|e| resume_hint(&swap_file, &self.serve, e))?;
        driver.nex_key = self.nex_key;
        run(&swap_file, &self.serve, Ok(driver), self.bump, self.poll)
    }
}

fn take(args: TakeArgs) -> Result<Outcome> {
    let text = if args.offer == Path::new("-") {
        let mut text = String::new();
        io::stdin().read_to_string(&mut text)?;
        text
    } else {
        read(&args.offer)?
    };
    let offer = Offer::decode(&text)?;
    check_nex_address(&args.nex_address)?;
    let store = Store::new(&args.dir, offer.template.swap_id);
    if store.path().exists() {
        return Err(resume_hint(
            store.path(),
            "",
            "this offer was taken already: its swap file exists".into(),
        ));
    }
    let bitcoin = args.nodes.bitcoin(&args.dir)?;
    // As the app's: a swap not ended may yet broadcast a funding it signed
    // from the wallet. Only on an Esplora, whose wallet made --dir.
    if let Btc::Esplora(..) = &bitcoin {
        if let Some(swap_id) = unended(&args.dir)? {
            return Err(format!(
                "refused: swap {swap_id} has not ended, and may yet spend from this wallet: \
                 resume it first; one swap at a time"
            )
            .into());
        }
    }
    let floor = btc_fee_floor(&bitcoin, args.policy.min_btc_fee_rate)?;
    let nexus = args.nodes.nexus();
    args.nodes.check_nexus(&nexus)?;
    let nex_floor = nex_fee_floor(&nexus, args.policy.min_nex_fee)?;
    let (network, genesis) = (args.nodes.btc_network, &args.nodes.nexus_genesis);
    let mut policy = args.policy.policy(&offer);
    policy.bounds.test_btc_for_mainnet_nex = args.nodes.test_btc_for_mainnet_nex;
    check_offer(&offer, &policy, network, genesis, floor, nex_floor)?;
    if let Btc::Esplora(_, wallet) = &bitcoin {
        // As the app's, before the offer is taken, at the rate the driver
        // funds the lock at: the estimate, else --fallback-fee-rate, never
        // below 1 sat/vB.
        let rate = (bitcoin.fee_rate(false)?)
            .unwrap_or(args.bump.fallback_fee_rate)
            .to_sat_per_vb_ceil()
            .max(1);
        let spendable = wallet.esplora().spendable()?;
        let (enough, needed) = swap::wallet::need(spendable, policy.btc_amount, rate);
        if !enough {
            let (confirmed, _) = wallet.balance()?;
            return Err(format!(
                "refused: the wallet's {confirmed} sat confirmed does not fund the lock: \
                 deposit to {} until it holds {needed} sat",
                wallet.address()
            )
            .into());
        }
    }
    args.nodes.trust(BUYER_TRUSTS);
    let refund = bitcoin.payout(network)?;
    fs::create_dir_all(&args.dir)?;

    log(&offer.describe());
    log(&format!(
        "taking {} sat for {} base units",
        policy.btc_amount,
        offer.quote.nex_amount(policy.btc_amount)
    ));
    let swap_file = store.path().to_path_buf();
    let driver = swap::session::take(
        offer,
        &policy,
        network,
        genesis,
        floor,
        nex_floor,
        refund,
        args.nex_address,
        bitcoin,
        nexus,
        store,
    )
    .map_err(|e| resume_hint(&swap_file, "", e))?;
    run(&swap_file, "", Ok(driver), &args.bump, args.nodes.poll())
}

fn resume(args: SwapFileArgs) -> Result<Outcome> {
    let store = swap_store(&args.swap_file)?;
    let swap_file = store.path().to_path_buf();
    let dir = swap_file.parent().expect("a swap file is in a directory");
    let saved = Saved::load(&store)?;
    let flag = &args.nodes.nexus_genesis;
    if let Some(genesis) = saved.nexus_genesis().filter(|genesis| genesis != flag) {
        return Err(format!(
            "refused: {} trades on the Nexus of genesis {genesis}, not {flag}, the one \
             --nexus-genesis names: resume it with --nexus-genesis {genesis}",
            swap_file.display()
        )
        .into());
    }
    // The relay the seller serves, as it reaches it on its own machine.
    let mut served = None;
    if args.serve.serve_relay.is_some() && matches!(saved, Saved::Buyer(_)) {
        return Err(format!(
            "refused: {} is a buyer's swap, and only the seller serves its relay: \
             leave out --serve-relay",
            swap_file.display()
        )
        .into());
    }
    if let (Some(listen), Some(url)) = (args.serve.serve_relay, &args.serve.serve_relay_url) {
        // A relay the two would not meet at would serve no one this swap.
        let session = SessionFile::load(&store)?;
        let relay = session.and_then(|session| session.offer.relay);
        if relay.as_deref() != Some(url) {
            return Err(format!(
                "refused: {} meets the other party at {}, not {url}",
                swap_file.display(),
                relay.as_deref().unwrap_or("no relay")
            )
            .into());
        }
        served = Some(serve_relay(listen)?);
    }
    match saved {
        Saved::Seller(seller) => {
            let given = args.key.given()?;
            let key = seller_key(seller.nex_address(), seller.signs_nex(), given)?;
            let bitcoin = resume_bitcoin(&args.nodes, dir, seller.redeem_payout())?;
            let nexus = args.nodes.nexus();
            let check = seller.outcome().is_none().then(|| {
                args.nodes.trust(SELLER_TRUSTS);
                args.nodes.resumed_check()
            });
            let driver = swap::session::resume_through::<Seller, _>(bitcoin, nexus, store, served);
            run(
                &swap_file,
                &args.serve.flags(),
                driver.map(|mut driver| {
                    driver.nex_key = key;
                    driver.nexus_check = check;
                    driver.nexus_genesis = Some(flag.clone());
                    driver
                }),
                &args.bump,
                args.nodes.poll(),
            )
        }
        Saved::Buyer(buyer) => {
            // A punished buyer asks the seller for `s` again.
            let buyer = buyer.resumed();
            let bitcoin = resume_bitcoin(&args.nodes, dir, buyer.refund_payout())?;
            let nexus = args.nodes.nexus();
            let check = buyer.outcome().is_none().then(|| {
                args.nodes.trust(BUYER_TRUSTS);
                args.nodes.resumed_check()
            });
            let driver = swap::session::resume::<Buyer, _>(bitcoin, nexus, store);
            let driver = driver.map(|mut driver| {
                driver.nexus_check = check;
                driver.nexus_genesis = Some(flag.clone());
                driver
            });
            run(&swap_file, "", driver, &args.bump, args.nodes.poll())
        }
    }
}

/// The Bitcoin to resume a swap in `dir` on whose BTC is paid to
/// `payout`. A swap file does not say which Bitcoin it was made on: on an
/// Esplora, one that does not pay the wallet in `dir`, as one made on a
/// bitcoind does, is refused, and no wallet is made for it; on a bitcoind,
/// one that does not pay its wallet, as one made on an Esplora does, is
/// refused too. A Bitcoin that cannot answer yet, down or erring for a
/// moment, is asked again `retry` apart, with a warning, until it answers:
/// the swap's cancel, refund and punish wait on it, not on the user to run
/// `resume` again. A bitcoind wallet not loaded or locked is warned of,
/// not waited on: those spends need no wallet, only their fee bumps do.
fn resume_bitcoin(nodes: &NodeArgs, dir: &Path, payout: Option<&Script>) -> Result<Btc> {
    resume_bitcoin_every(nodes, dir, payout, app::POLL)
}

/// [`resume_bitcoin`], asking again `retry` apart.
fn resume_bitcoin_every(
    nodes: &NodeArgs,
    dir: &Path,
    payout: Option<&Script>,
    retry: Duration,
) -> Result<Btc> {
    let refused = || {
        format!(
            "refused: the swap does not pay the wallet in {}: resume it with the Bitcoin \
             flags it was made with, --btc-wallet and its node's for a bitcoind",
            dir.display()
        )
    };
    if nodes.btc_wallet.is_none() && !dir.join("wallet.json").exists() {
        return Err(refused().into());
    }
    let bitcoin = nodes.open_bitcoin(dir)?;
    if let (Btc::Esplora(esplora, _), Some(payout)) = (&bitcoin, payout) {
        if esplora.key().script_pubkey.as_script() != payout {
            return Err(refused().into());
        }
    }
    let check = || -> swap::bitcoind::Result<Result<()>> {
        let Btc::Node(bitcoind) = &bitcoin else {
            return Ok(bitcoin.check(nodes.btc_network)?.map_err(Into::into));
        };
        if let Err(refusal) = bitcoind.check_chain()? {
            return Ok(Err(refusal.into()));
        }
        // Cancel, refund and punish are signed already: broadcast and
        // read, they need no wallet, and only bumps do. A wallet not
        // loaded or locked is warned of, never waited on, its bumps
        // failing, loudly, until it is back; and while it is not, only a
        // wallet's answer that the swap does not pay it refuses.
        let ready = match bitcoind.check_wallet() {
            Ok(Err(refusal)) => return Ok(Err(refusal.into())),
            Ok(Ok(())) => true,
            Err(e) => {
                log(&format!(
                    "{e}: the swap goes on, its fee bumps fail until the wallet is loaded \
                     and unlocked"
                ));
                false
            }
        };
        match payout.map(|payout| bitcoind.owns(payout)) {
            Some(Ok(false)) => Ok(Err(format!(
                "refused: the swap does not pay the bitcoind wallet {}: resume it with the \
                 Bitcoin flags it was made with, none or --esplora for the wallet in {}",
                nodes.btc_wallet.as_deref().unwrap_or_default(),
                dir.display()
            )
            .into())),
            Some(Err(e)) if ready => Err(e),
            Some(_) | None => Ok(Ok(())),
        }
    };
    loop {
        match check() {
            Ok(checked) => return checked.map(|()| bitcoin),
            Err(e) => {
                log(&format!(
                    "bitcoin: {e}: asked again in {}s",
                    retry.as_secs_f64()
                ));
                std::thread::sleep(retry);
            }
        }
    }
}

#[derive(Args)]
struct WalletArgs {
    /// The directory the wallet and its swaps are in.
    #[arg(long, default_value = ".")]
    dir: PathBuf,
    /// Sends all the wallet can spend, less the fee, to this address.
    #[arg(long)]
    withdraw: Option<String>,
    /// Your own Esplora API, instead of mempool.space's.
    #[arg(long)]
    esplora: Option<String>,
    /// bitcoin, testnet, testnet4, signet or regtest.
    #[arg(long, default_value_t = Network::Bitcoin)]
    btc_network: Network,
}

/// The wallet's address and balance, after its withdrawal if asked for:
/// what the app's wallet shows and does.
fn wallet(args: WalletArgs) -> Result<()> {
    let network = args.btc_network;
    let url = esplora_url(args.esplora.as_deref(), network)?;
    let config = app::Config::new(
        args.dir.clone(),
        network,
        url,
        String::new(),
        None,
        String::new(),
    );
    // Refused while a swap runs in the directory, which holds it open.
    let wallet = Wallet::open(config)?;
    wallet.esplora().check_network(network)??;
    if let Some(to) = &args.withdraw {
        if let Some(swap_id) = unended(&args.dir)? {
            return Err(format!(
                "refused: swap {swap_id} has not ended, and may yet spend from this wallet: \
                 resume it first"
            )
            .into());
        }
        println!("withdrawn: {}", wallet.withdraw(to)?);
    }
    let (confirmed, unconfirmed) = wallet.balance()?;
    println!("address: {}", wallet.address());
    println!("balance: {confirmed} sat, {unconfirmed} sat unconfirmed");
    Ok(())
}

/// Takes the key's account's entry on the relay directory to --url, or
/// none for `remove`: reads what the entry holds at the chain's tip, the
/// write's old value, then signs and submits the write, paying the fee
/// from the account's balance on that chain. Does nothing if the entry
/// already holds it. A URL that is not one the directory's readers list,
/// `https://` to a public host, is refused.
fn relay_dir_write(command: RelayDirCommand) -> Result<()> {
    let (args, url) = match command {
        RelayDirCommand::Add { url, write } => {
            if relay_dir::relay_url(&url).is_none() {
                return Err(format!(
                    "refused: {url} is not an https:// URL to a public host, which readers skip"
                )
                .into());
            }
            (write, Some(url))
        }
        RelayDirCommand::Remove(write) => (write, None),
    };
    let key = relay_dir_key(&args.key)?;
    let account = key.nex_address();
    let chain: Vec<String> = args.chain.split('/').map(String::from).collect();
    let nexus = match &args.nexus_cookie {
        Some(cookie) => Client::from_cookie_file(&args.nexus_url, cookie, TIMEOUT),
        None => Client::public(&args.nexus_url, TIMEOUT),
    };
    let info = nexus.chain_info_of(&chain)?;
    if info["chain"] != json!(chain) {
        return Err(format!("{} answered for another chain: {info}", args.nexus_url).into());
    }
    if args.nexus_cookie.is_none() && info["acceptsSubmit"] != true {
        return Err(format!("refused: {} takes no transactions", args.nexus_url).into());
    }
    let tip = parse::tip(&info)?.1.ok_or("the chain has no tip yet")?;
    let fee = args.fee;
    let floor = parse::min_relay_fee(&info)?;
    if floor > fee {
        return Err(format!(
            "refused: {} pools no fee below {floor}, above the fee of {fee}: \
             pass --fee {floor} to pay it",
            args.nexus_url
        )
        .into());
    }
    // A Volume holds many nodes: one already read is not asked for again.
    let mut held = BTreeMap::new();
    let key_name = format!("{}{account}", relay_dir::PREFIX);
    let current = relay_dir::value(&tip, &key_name, |cid| {
        if !held.contains_key(cid) {
            held.extend(nexus.volume(cid, &chain).map_err(|e| e.to_string())?);
        }
        held.get(cid)
            .cloned()
            .ok_or(format!("the node's Volume {cid} lacks its root"))
    })?;
    let Some(action) = relay_dir_action(&account, current, url) else {
        println!(
            "unchanged: {account}'s entry on {} already holds that",
            args.chain
        );
        return Ok(());
    };
    // A node with a tip answers 404 for an account it has never seen, as
    // `lattice tx` takes it: nonce 0, no balance.
    let funds = match nexus.account_of(&account, &chain) {
        Err(swap_nexus_tx::rpc::Error::Status { status: 404, .. }) => swap_nexus_tx::rpc::Account {
            balance: 0,
            nonce: 0,
        },
        funds => funds?,
    };
    if funds.balance < fee {
        return Err(format!(
            "{account} holds {} on {}, less than the fee of {fee}",
            funds.balance, args.chain
        )
        .into());
    }
    let body = TransactionBody::write(&account, vec![action], fee, funds.nonce, chain)
        .ok_or("the fee does not fit")?;
    let mut transaction = swap_nexus_tx::Transaction::new(body);
    transaction.sign(&SigningKey::from_bytes(&key.0));
    let cid = nexus.submit(&transaction)?;
    println!(
        "submitted: {cid}, fee {fee}; unconfirmed until a block holds it, and refused \
         there if the entry changed since it was read"
    );
    Ok(())
}

/// A swap in `dir` that has not ended, as the app judges it, if any.
fn unended(dir: &Path) -> Result<Option<String>> {
    for entry in fs::read_dir(dir)? {
        let path = entry?.path();
        let Ok(store) = swap_store(&path) else {
            continue;
        };
        if matches!(store.load_value()?, Some(state) if !app::ended(&state)) {
            let stem = path.file_stem().unwrap_or_default();
            return Ok(Some(stem.to_string_lossy().into()));
        }
    }
    Ok(None)
}

fn status(swap_file: &Path) -> Result<()> {
    let (role, state, outcome) = match Saved::load(&swap_store(swap_file)?)? {
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

/// Runs the swap to its end, bumping as `bump` says, reading the chains
/// at most once each `poll` if given, logging each state it reaches. On an error once the swap
/// file exists, says how to carry on.
fn run<M: Machine, B: Bitcoin, T: Transport>(
    swap_file: &Path,
    serve: &str,
    driver: io::Result<Driver<M, B, T>>,
    bump: &BumpArgs,
    poll: Option<Duration>,
) -> Result<Outcome> {
    let last = RefCell::new(String::new());
    let outcome = driver
        .and_then(|mut driver| {
            bump.apply(&mut driver);
            if let Some(poll) = poll {
                driver.poll = poll;
            }
            driver.run_until(|state| {
                let name = state_name(state);
                if *last.borrow() != name {
                    log(&name);
                    *last.borrow_mut() = name;
                }
                false
            })
        })
        .map_err(|e| resume_hint(swap_file, serve, e.into()))?;
    let outcome = outcome.expect("only an outcome ends a run that never stops");
    println!("outcome: {outcome:?}");
    Ok(outcome)
}

/// The error, and how to carry on if the swap file exists.
/// `serve` is the --serve-relay flags given, if any, which `resume` needs
/// again to meet a buyer that took the offer on the relay they serve.
fn resume_hint(
    swap_file: &Path,
    serve: &str,
    error: Box<dyn std::error::Error>,
) -> Box<dyn std::error::Error> {
    if !swap_file.exists() {
        return error;
    }
    format!(
        "{error}\nto carry on, run with the same flags, the node and key flags and \
         --max-fee-rate, --fallback-fee-rate, --max-fee-fraction, --max-tip-age and \
         --nexus-budget: \
         lattice-swap resume {}{serve}",
        swap_file.display()
    )
    .into()
}

/// The exit status of a swap that ended: 0 only when it swapped.
fn exit_code(outcome: Outcome) -> u8 {
    match outcome {
        Outcome::Swapped => 0,
        Outcome::Refunded => 3,
        Outcome::Punished => 4,
        Outcome::Drained => 5,
        Outcome::Aborted(_) => 6,
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

/// Runs the command, to its exit status.
fn exit_status(command: Command) -> Result<u8> {
    match command {
        Command::Offer(args) => offer(args).map(exit_code),
        Command::Take(args) => take(args).map(exit_code),
        Command::Resume(args) => resume(args).map(exit_code),
        Command::Wallet(args) => wallet(args).map(|()| 0),
        Command::Status { swap_file } => status(&swap_file).map(|()| 0),
        Command::RelayDir(command) => relay_dir_write(command).map(|()| 0),
    }
}

fn main() -> ExitCode {
    match exit_status(Cli::parse().command) {
        Ok(code) => ExitCode::from(code),
        Err(e) => {
            log(&e.to_string());
            ExitCode::FAILURE
        }
    }
}

#[cfg(test)]
mod tests;
