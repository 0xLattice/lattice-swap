//! `lattice-swap`: one side of a NEX<->BTC swap, run against the operator's
//! own bitcoind and lattice-node.
//!
//! The seller runs `offer`: it listens, or lists the offer on a relay, and
//! prints an offer for the buyer. The buyer runs `take` on that offer, which
//! dials the seller, or reaches it through the relay. Each side then runs
//! its [`Driver`] until the swap ends,
//! saving its state to a swap file that `resume` carries on from after a
//! restart and `status` reads.

use std::cell::RefCell;
use std::fs;
use std::io::{self, Read, Write};
use std::net::{SocketAddr, TcpListener};
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::time::{Duration, Instant};

use bitcoin::address::NetworkUnchecked;
use bitcoin::{Address, Amount, FeeRate, Network, ScriptBuf};
use clap::{Args, Parser, Subcommand};
use ed25519_dalek::{Signer, SigningKey, VerifyingKey};
use rand_core::{OsRng, RngCore};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use swap::bitcoind::{Bitcoin, Bitcoind};
use swap::driver::{Driver, Store};
use swap::transport::{Ivy, PeerKey, Relayed, Transport};
use swap::{btc_fee_at, Buyer, Machine, Outcome, SecretBytes, Seller, Terms};
use swap_nexus_tx::rpc::Client;

type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;

/// Bounds each call to a node, the dial, and each send to the counterparty.
const TIMEOUT: Duration = Duration::from_secs(30);
/// Holds the seller's Nexus wallet key when no key file is given.
const NEX_KEY_ENV: &str = "LATTICE_SWAP_NEX_KEY";
/// Holds the password for `--btc-user`.
const BTC_PASSWORD_ENV: &str = "LATTICE_SWAP_BTC_PASSWORD";
/// The blocks the buyer's fee estimate aims to confirm in.
const FEE_TARGET: u16 = 6;
/// The least time between two tries to hand a refund to a watchtower: a
/// relay that is down, or has not yet seen cancel, is not asked again at
/// every poll.
const WATCH_RETRY: Duration = Duration::from_secs(60);
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
    /// Carries on a swap from its swap file until it ends. There is no
    /// session: the rest runs from the chains alone, and a swap still
    /// waiting on a message cancels and refunds once its timelocks allow,
    /// so `refund` is this same command.
    #[command(visible_alias = "refund")]
    Resume(SwapFileArgs),
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
    fn terms(&self, swap_id: [u8; 32], nexus_genesis: String) -> Terms {
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
            nexus_genesis,
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
    /// bitcoin, testnet, testnet4, signet or regtest.
    #[arg(long, default_value_t = Network::Bitcoin)]
    btc_network: Network,
    /// The lattice-node's RPC base URL.
    #[arg(long)]
    nexus_url: String,
    /// The lattice-node's RPC cookie file.
    #[arg(long)]
    nexus_cookie: PathBuf,
    /// The CID of the genesis block of the Nexus to trade on: the
    /// lattice-node must follow that chain. Mainnet's by default.
    #[arg(long, default_value = swap_nexus_tx::MAINNET_GENESIS)]
    nexus_genesis: String,
}

impl NodeArgs {
    /// A client for bitcoind, which must be one a swap can rely on.
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
        let bitcoin = Bitcoind::new(&self.wallet_url(), &auth, self.btc_network, TIMEOUT);
        bitcoin.check_node()?;
        Ok(bitcoin)
    }

    /// The wallet's RPC URL, its name percent-escaped.
    fn wallet_url(&self) -> String {
        let wallet: String = self
            .btc_wallet
            .bytes()
            .map(|b| match b {
                b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' | b'_' | b'~' => {
                    char::from(b).to_string()
                }
                _ => format!("%{b:02X}"),
            })
            .collect();
        format!("{}/wallet/{wallet}", self.btc_url.trim_end_matches('/'))
    }

    fn nexus(&self) -> Result<Client> {
        Ok(Client::new(
            &self.nexus_url,
            &read(&self.nexus_cookie)?,
            TIMEOUT,
        ))
    }

    /// Refuses a lattice-node on another Nexus than `--nexus-genesis`
    /// names, where a NEX lock is worthless; then one that cannot say how
    /// deep a transaction is. It works that out from past blocks and the
    /// state after them, which a node run with `--state tip` or `none`, or
    /// `--block-bodies none`, does not keep: every NEX lock would look
    /// unmined, and every claim drained. Its read of an account after the
    /// block halfway up the chain shows whether it keeps that state; a chain
    /// too short to tell passes.
    fn check_nexus(&self, client: &Client) -> Result<()> {
        let genesis = client.genesis()?;
        if genesis != self.nexus_genesis {
            return Err(format!(
                "refused: the Nexus node follows the chain of genesis {genesis}, not {}, the \
                 one --nexus-genesis names",
                self.nexus_genesis
            )
            .into());
        }
        let height = client.health()?.height;
        if height < 2 {
            return Ok(());
        }
        let block = client
            .block_hash(height.div_ceil(2))?
            .ok_or("the Nexus node has no block halfway up its chain")?;
        match client.account_at(&swap_nexus_tx::address(&[0; 32]), &block)? {
            Some(_) => Ok(()),
            None => Err(
                "the Nexus node keeps no state of past blocks, so it cannot tell how deep a \
                 transaction is: run it with --state all and --block-bodies all"
                    .into(),
            ),
        }
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
            Some(path) => {
                owner_only(path)?;
                read(path)?
            }
            None => match std::env::var(NEX_KEY_ENV) {
                Ok(hex) => hex,
                Err(_) => return Ok(None),
            },
        };
        let mut seed = [0u8; 32];
        hex::decode_to_slice(hex.trim(), &mut seed)
            .map_err(|_| "the Nexus key is not 32 bytes of hex")?;
        Ok(Some(SecretBytes(seed)))
    }
}

/// How the driver bumps, by CPFP from their payout, the swap transactions
/// that pay this party, and how old a Bitcoin tip it trusts. The defaults
/// are the driver's.
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
}

impl BumpArgs {
    fn apply<M: Machine, B: Bitcoin, T: Transport>(&self, driver: &mut Driver<M, B, T>) {
        driver.max_fee_rate = self.max_fee_rate;
        driver.fallback_fee_rate = self.fallback_fee_rate;
        driver.max_fee_fraction = self.max_fee_fraction;
        driver.max_tip_age = Duration::from_secs(self.max_tip_age.saturating_mul(60));
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

#[derive(Args)]
struct OfferArgs {
    #[command(flatten)]
    terms: TermsArgs,
    /// Where to listen for the buyer.
    #[arg(long, required_unless_present = "relay")]
    listen: Option<SocketAddr>,
    /// The address the buyer dials, if not the one listened on. Required
    /// when listening on an unspecified address, such as 0.0.0.0.
    #[arg(long)]
    advertise: Option<SocketAddr>,
    /// A relay, by its http:// or https:// URL, to list the offer on and
    /// meet the buyer through, instead of listening. Anyone can list the
    /// relay's offers and take one.
    #[arg(long, conflicts_with_all = ["listen", "advertise"])]
    relay: Option<String>,
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
    /// The relay, by its URL, whose watchtower gets the cancel and the
    /// signed refund, to broadcast the refund once cancel is in a block if
    /// this buyer is offline then; the offer's relay by default. They are handed
    /// over only once the buyer gives up on the swap without signing the
    /// redeem: before that, the refund would let a seller take both coins.
    #[arg(long)]
    watchtower: Option<String>,
    /// Hand the refund to no watchtower.
    #[arg(long, conflicts_with = "watchtower")]
    no_watchtower: bool,
    #[command(flatten)]
    nodes: NodeArgs,
    #[command(flatten)]
    bump: BumpArgs,
}

/// What the buyer agreed to, and its bounds on every other term: `take`
/// refuses an offer outside them. Defaults are this tool's settings.
#[derive(Args)]
struct PolicyArgs {
    /// The BTC agreed to pay, in satoshis.
    #[arg(long)]
    btc_amount: u64,
    /// The NEX agreed to buy.
    #[arg(long)]
    nex_amount: u64,
    /// The most each Bitcoin swap transaction may pay, in satoshis.
    #[arg(long, default_value_t = 10_000)]
    max_btc_fee: u64,
    /// The most the NEX lock and the claim from it may pay.
    #[arg(long, default_value_t = 1_000)]
    max_nex_fee: u64,
    /// The least the NEX lock and the claim from it may pay, and the Nexus
    /// node's minRelayFee if higher: a fee this node pools may still be
    /// below what the network relays.
    #[arg(long, default_value_t = 1)]
    min_nex_fee: u64,
    /// The most Bitcoin blocks the BTC stays locked before cancel.
    #[arg(long, default_value_t = 288)]
    max_t1: u16,
    /// The fewest Bitcoin blocks after cancel confirms before punish is
    /// valid.
    #[arg(long, default_value_t = 144)]
    min_t2: u16,
    /// The fewest Bitcoin confirmations the offer may ask.
    #[arg(long, default_value_t = 6)]
    min_btc_confirmations: u32,
    /// The most Bitcoin confirmations the offer may ask. Once it has signed
    /// the redeem, the buyer refunds only when cancel is this deep.
    #[arg(long, default_value_t = 12)]
    max_btc_confirmations: u32,
    /// The fewest Bitcoin blocks the refund has to confirm in before punish
    /// is valid, once the buyer has signed the redeem: t2 -
    /// btc-confirmations.
    #[arg(long, default_value_t = 72)]
    min_refund_window: u16,
    /// The fee rate, in sat/vB, that each Bitcoin swap transaction must pay
    /// when bitcoind has no fee estimate, as on regtest. Otherwise its
    /// conservative estimate for 6 blocks is the floor.
    #[arg(long)]
    min_btc_fee_rate: Option<u64>,
    /// The fewest Nexus confirmations of the NEX lock this buyer accepts.
    #[arg(long, default_value_t = 24)]
    min_nex_confirmations: u64,
    /// The fewest Bitcoin blocks of slack before a timelock.
    #[arg(long, default_value_t = 6)]
    min_margin: u16,
}

#[derive(Args)]
struct SwapFileArgs {
    /// The swap file, `<swap id>.json`.
    swap_file: PathBuf,
    /// A buyer's: the relay whose watchtower gets the cancel and the signed
    /// refund once the buyer gives up, as `take --watchtower`. None unless
    /// given.
    #[arg(long)]
    watchtower: Option<String>,
    #[command(flatten)]
    nodes: NodeArgs,
    #[command(flatten)]
    key: NexKeyArgs,
    #[command(flatten)]
    bump: BumpArgs,
}

/// The least `btc_fee` the buyer takes, in satoshis: what bitcoind's
/// conservative estimate, or else `fallback` sat/vB, asks of every swap
/// spend.
fn btc_fee_floor(bitcoin: &Bitcoind, fallback: Option<u64>) -> Result<u64> {
    let estimate = bitcoin.call("estimatesmartfee", json!([FEE_TARGET, "CONSERVATIVE"]))?;
    let per_kvb = match estimate["feerate"].as_f64() {
        Some(btc) => Amount::from_btc(btc)?.to_sat(),
        None => fallback
            .ok_or("bitcoind has no fee estimate: give --min-btc-fee-rate")?
            .saturating_mul(1000),
    };
    Ok(btc_fee_at(per_kvb))
}

/// The least `nex_fee` a party runs: `least`, or its Nexus node's relay
/// floor if higher. A node's floor alone is not the network's: one that
/// pools a fee its peers do not relay leaves the NEX lock, or the claim,
/// unmined.
fn nex_fee_floor(nexus: &Client, least: u64) -> Result<u64> {
    Ok(least.max(nexus.min_relay_fee()?))
}

/// An offer the buyer takes: terms that work, on its Bitcoin network and
/// its Nexus, the amounts it agreed to, a Bitcoin fee of at least
/// `btc_fee_floor`, a Nexus fee of at least `nex_fee_floor`, and every
/// other term within its bounds.
fn check_offer(
    offer: &Offer,
    policy: &PolicyArgs,
    network: Network,
    nexus_genesis: &str,
    btc_fee_floor: u64,
    nex_fee_floor: u64,
) -> std::result::Result<(), String> {
    let terms = &offer.terms;
    terms.check()?;
    let refused = |why: String| Err(format!("refused: the offer {why}"));
    if offer.btc_network != network {
        return refused(format!("is on {}, not {network}", offer.btc_network));
    }
    if terms.nexus_genesis != nexus_genesis {
        return refused(format!(
            "is on the Nexus of genesis {}, not {nexus_genesis}",
            terms.nexus_genesis
        ));
    }
    if terms.btc_amount.to_sat() != policy.btc_amount {
        return refused(format!(
            "asks {} sat, not {}",
            terms.btc_amount.to_sat(),
            policy.btc_amount
        ));
    }
    if terms.nex_amount != policy.nex_amount {
        return refused(format!(
            "sells {} NEX, not {}",
            terms.nex_amount, policy.nex_amount
        ));
    }
    if terms.btc_fee.to_sat() > policy.max_btc_fee {
        return refused(format!(
            "pays {} sat a Bitcoin transaction, above {}",
            terms.btc_fee.to_sat(),
            policy.max_btc_fee
        ));
    }
    if terms.btc_fee.to_sat() < btc_fee_floor {
        return refused(format!(
            "pays {} sat a Bitcoin transaction, below the {btc_fee_floor} sat its node's fee \
             rate asks",
            terms.btc_fee.to_sat()
        ));
    }
    if terms.nex_fee > policy.max_nex_fee {
        return refused(format!(
            "pays {} NEX a Nexus transaction, above {}",
            terms.nex_fee, policy.max_nex_fee
        ));
    }
    if terms.nex_fee < nex_fee_floor {
        return refused(format!(
            "pays {} NEX a Nexus transaction, below {nex_fee_floor}, --min-nex-fee or its \
             node's minRelayFee",
            terms.nex_fee
        ));
    }
    if terms.t1 > policy.max_t1 {
        return refused(format!("has t1 {}, above {}", terms.t1, policy.max_t1));
    }
    if terms.t2 < policy.min_t2 {
        return refused(format!("has t2 {}, below {}", terms.t2, policy.min_t2));
    }
    if terms.btc_confirmations < policy.min_btc_confirmations {
        return refused(format!(
            "asks {} Bitcoin confirmations, fewer than {}",
            terms.btc_confirmations, policy.min_btc_confirmations
        ));
    }
    if terms.btc_confirmations > policy.max_btc_confirmations {
        return refused(format!(
            "asks {} Bitcoin confirmations, more than {}",
            terms.btc_confirmations, policy.max_btc_confirmations
        ));
    }
    let window = u64::from(terms.t2).saturating_sub(u64::from(terms.btc_confirmations));
    if window < u64::from(policy.min_refund_window) {
        return refused(format!(
            "leaves {window} blocks to refund in, t2 - btc_confirmations, fewer than {}",
            policy.min_refund_window
        ));
    }
    if terms.nex_confirmations < policy.min_nex_confirmations {
        return refused(format!(
            "asks {} Nexus confirmations, fewer than {}",
            terms.nex_confirmations, policy.min_nex_confirmations
        ));
    }
    if terms.margin < policy.min_margin {
        return refused(format!(
            "has margin {}, below {}",
            terms.margin, policy.min_margin
        ));
    }
    Ok(())
}

/// What the buyer needs to take the swap: the terms, among them the Nexus
/// the seller trades on, where the seller listens or the relay it waits on,
/// its key, and the session key the seller made for the buyer, the only one
/// it accepts. Whoever holds an offer can take it. The Nexus in the terms is
/// only a courtesy: a buyer on another refuses before it locks anything, but
/// the buyer's safety is its own node's check against its own
/// `--nexus-genesis`.
///
/// The seller signs the terms and the network with its key, which the
/// buyer's session then authenticates: a relay, or anyone the offer passes
/// through, cannot hand the buyer other terms for the seller's key. Without
/// it, the terms each machine checks alone, such as the confirmations and
/// the margin, could differ between the two and neither would refuse. The
/// rest needs no signature: another address, relay or buyer session key
/// reaches no seller, or one that refuses the buyer.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
struct Offer {
    terms: Terms,
    btc_network: Network,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    address: Option<SocketAddr>,
    /// The relay the seller waits on, by its URL, which pairs a buyer with
    /// it by the swap id.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    relay: Option<String>,
    seller: String,
    #[serde(with = "hex::serde")]
    buyer_session: [u8; 32],
    #[serde(with = "hex::serde")]
    signature: [u8; 64],
}

/// What the seller signs: the terms and the network, tagged.
fn signed(terms: &Terms, network: Network) -> Vec<u8> {
    serde_json::to_vec(&("lattice-swap offer", terms, network)).expect("terms serialize")
}

impl Offer {
    /// The offer, signed by `seller`, whose key it names.
    fn new(
        terms: Terms,
        btc_network: Network,
        place: Place,
        seller: &SigningKey,
        buyer_session: [u8; 32],
    ) -> Self {
        let (address, relay) = match place {
            Place::Address(address) => (Some(address), None),
            Place::Relay(relay) => (None, Some(relay)),
        };
        let mut offer = Offer {
            terms,
            btc_network,
            address,
            relay,
            seller: hex::encode(seller.verifying_key().to_bytes()),
            buyer_session,
            signature: [0; 64],
        };
        offer.sign(seller);
        offer
    }

    fn sign(&mut self, seller: &SigningKey) {
        self.signature = seller
            .sign(&signed(&self.terms, self.btc_network))
            .to_bytes();
    }

    fn encode(&self) -> String {
        serde_json::to_string(self).expect("offers serialize")
    }

    /// The offer in `text`, if it is one, says where to find the seller,
    /// and the seller signed its terms.
    fn decode(text: &str) -> Result<Self> {
        let offer: Offer =
            serde_json::from_str(text.trim()).map_err(|e| format!("not an offer: {e}"))?;
        let key = offer.seller_key()?;
        offer.place()?;
        let key = VerifyingKey::from_bytes(key.as_bytes()).expect("a peer key is a key");
        let signature = ed25519_dalek::Signature::from_bytes(&offer.signature);
        key.verify_strict(&signed(&offer.terms, offer.btc_network), &signature)
            .map_err(|_| "the offer's terms are not signed by its seller")?;
        Ok(offer)
    }

    /// Where the seller is: an address or a relay, not both.
    fn place(&self) -> Result<Place> {
        match (self.address, &self.relay) {
            (Some(address), None) => Ok(Place::Address(address)),
            (None, Some(relay)) => Ok(Place::Relay(relay.clone())),
            _ => Err("the offer must name an address or a relay, not both".into()),
        }
    }

    fn seller_key(&self) -> Result<PeerKey> {
        Ok(PeerKey::from_hex(&self.seller).ok_or("the offer's seller key is not a key")?)
    }

    /// The terms, for the buyer to read before it dials.
    fn describe(&self) -> String {
        let t = &self.terms;
        format!(
            "taking {} sat for {} NEX on {}: fees {} sat and {} NEX, t1 {}, t2 {}, \
             {} Bitcoin and {} Nexus confirmations, margin {}; {}",
            t.btc_amount.to_sat(),
            t.nex_amount,
            self.btc_network,
            t.btc_fee.to_sat(),
            t.nex_fee,
            t.t1,
            t.t2,
            t.btc_confirmations,
            t.nex_confirmations,
            t.margin,
            match self.place() {
                Ok(Place::Address(address)) => format!("dialling {address}"),
                Ok(Place::Relay(relay)) => format!("through the relay {relay}"),
                Err(e) => e.to_string(),
            }
        )
    }
}

/// Where the buyer finds the seller.
enum Place {
    Address(SocketAddr),
    Relay(String),
}

/// A Nexus address as Lattice prints one: a CIDv1, dag-cbor, sha2-256, in
/// lowercase base32. NEX paid to anything else is lost.
fn check_nex_address(text: &str) -> Result<()> {
    if !swap_nexus_tx::is_cid(text) {
        return Err(format!("{text} is not a Nexus address").into());
    }
    Ok(())
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

fn offer(args: OfferArgs) -> Result<Outcome> {
    if let Some(listen) = args.listen {
        check_listen(listen, args.advertise)?;
    }
    let terms = args
        .terms
        .terms(random32(), args.nodes.nexus_genesis.clone());
    terms.check()?;
    let key = args.key.load()?;
    let bitcoin = args.nodes.bitcoin()?;
    let floor = btc_fee_floor(&bitcoin, args.min_btc_fee_rate)?;
    if terms.btc_fee.to_sat() < floor {
        return Err(format!(
            "btc_fee is {} sat, below the {floor} sat the node's fee rate asks of cancel and \
             refund",
            terms.btc_fee.to_sat()
        )
        .into());
    }
    let nexus = args.nodes.nexus()?;
    args.nodes.check_nexus(&nexus)?;
    let floor = nex_fee_floor(&nexus, args.min_nex_fee)?;
    if terms.nex_fee < floor {
        return Err(format!(
            "nex_fee is {}, below {floor}, --min-nex-fee or the node's minRelayFee: a fee \
             the network does not relay leaves the NEX lock unmined",
            terms.nex_fee
        )
        .into());
    }
    let redeem = args.nodes.payout(&bitcoin)?;
    let punish = args.nodes.payout(&bitcoin)?;
    let seller = Seller::new(terms.clone(), key.nex_address(), redeem, punish)
        .map_err(|refusal| format!("refused: {refusal:?}"))?;
    fs::create_dir_all(&args.dir)?;
    let store = Store::new(&args.dir, terms.swap_id);

    let listener = args.listen.map(TcpListener::bind).transpose()?;
    let place = match (&listener, &args.relay) {
        (_, Some(relay)) => Place::Relay(relay.clone()),
        (Some(listener), None) => Place::Address(args.advertise.unwrap_or(listener.local_addr()?)),
        (None, None) => return Err("give --listen or --relay".into()),
    };
    let session = SigningKey::from_bytes(&random32());
    let config = ivy::Config::new(session.clone());
    let buyer_session = random32();
    let buyer = ivy::Config::new(SigningKey::from_bytes(&buyer_session)).peer_key();
    let offer = Offer::new(
        terms,
        args.nodes.btc_network,
        place,
        &session,
        buyer_session,
    );
    println!("{}", offer.encode());
    io::stdout().flush()?;
    let wait = Duration::from_secs(args.wait);
    let start = Start {
        bitcoin,
        nexus,
        store,
        nex_key: Some(key),
        bump: &args.bump,
    };
    match (listener, &args.relay) {
        (_, Some(relay)) => {
            log(&format!(
                "listing the offer on {relay}, waiting for the buyer"
            ));
            let transport =
                Ivy::accept_relayed(relay, &offer.encode(), &config, buyer, wait, TIMEOUT)?;
            start.run(seller, vec![], transport, |_| {})
        }
        (Some(listener), None) => {
            log("waiting for the buyer");
            let transport = Ivy::accept(listener, &config, buyer, wait, TIMEOUT)?;
            start.run(seller, vec![], transport, |_| {})
        }
        (None, None) => unreachable!("a place was found"),
    }
}

/// What a swap starts on, once the session is up.
struct Start<'a> {
    bitcoin: Bitcoind,
    nexus: Client,
    store: Store,
    nex_key: Option<SecretBytes>,
    bump: &'a BumpArgs,
}

impl Start<'_> {
    /// Runs `machine`, which asks for `actions` first, over `transport` to
    /// the swap's end, calling `see` on every state it reaches.
    fn run<M: Machine, T: Transport>(
        self,
        machine: M,
        actions: Vec<swap::Action>,
        transport: T,
        see: impl Fn(&M),
    ) -> Result<Outcome> {
        let swap_file = self.store.path().to_path_buf();
        log(&format!("swap file {}", swap_file.display()));
        let driver = Driver::start(
            machine,
            actions,
            self.bitcoin,
            self.nexus,
            Some(transport),
            self.store,
        );
        let driver = driver.map(|mut driver| {
            driver.nex_key = self.nex_key;
            driver
        });
        run(&swap_file, driver, self.bump, see)
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
    let store = Store::new(&args.dir, offer.terms.swap_id);
    if store.path().exists() {
        return Err(resume_hint(
            store.path(),
            "this offer was taken already: its swap file exists".into(),
        ));
    }
    let bitcoin = args.nodes.bitcoin()?;
    let floor = btc_fee_floor(&bitcoin, args.policy.min_btc_fee_rate)?;
    let nexus = args.nodes.nexus()?;
    args.nodes.check_nexus(&nexus)?;
    let nex_floor = nex_fee_floor(&nexus, args.policy.min_nex_fee)?;
    let (network, genesis) = (args.nodes.btc_network, &args.nodes.nexus_genesis);
    check_offer(&offer, &args.policy, network, genesis, floor, nex_floor)?;
    let refund = args.nodes.payout(&bitcoin)?;
    let (buyer, actions) = Buyer::start(offer.terms.clone(), refund, args.nex_address)
        .map_err(|refusal| format!("refused: {refusal:?}"))?;
    fs::create_dir_all(&args.dir)?;

    let config = ivy::Config::new(SigningKey::from_bytes(&offer.buyer_session));
    log(&offer.describe());
    let seller = offer.seller_key()?;
    let watchtower = match (&args.watchtower, &offer.relay) {
        _ if args.no_watchtower => None,
        (Some(url), _) | (None, Some(url)) => Some(url.clone()),
        (None, None) => None,
    };
    let watchtower = RefCell::new(Watchtower::new(watchtower, args.nodes.btc_network));
    let see = |buyer: &Buyer| watchtower.borrow_mut().see(buyer);
    let start = Start {
        bitcoin,
        nexus,
        store,
        nex_key: None,
        bump: &args.bump,
    };
    match offer.place()? {
        Place::Address(address) => {
            let transport = Ivy::connect(address, &config, seller, TIMEOUT)?;
            start.run(buyer, actions, transport, see)
        }
        Place::Relay(relay) => {
            let id = hex::encode(offer.terms.swap_id);
            let transport = Ivy::<Relayed>::connect_relayed(&relay, &id, &config, seller, TIMEOUT)?;
            start.run(buyer, actions, transport, see)
        }
    }
}

/// Hands the buyer's cancel and signed refund to the watchtower at `relay`
/// once the buyer gives up without signing the redeem, the only time it is
/// safe to: see [`Buyer::watchtower`].
struct Watchtower {
    relay: Option<String>,
    network: Network,
    posted: bool,
    tried: Option<Instant>,
}

impl Watchtower {
    fn new(relay: Option<String>, network: Network) -> Self {
        Self {
            relay,
            network,
            posted: false,
            tried: None,
        }
    }

    fn see(&mut self, buyer: &Buyer) {
        let Some(relay) = &self.relay else { return };
        if self.posted
            || self
                .tried
                .is_some_and(|tried| tried.elapsed() < WATCH_RETRY)
        {
            return;
        }
        let (Some((cancel, refund)), Some(terms)) = (buyer.watchtower(), buyer.terms()) else {
            return;
        };
        self.tried = Some(Instant::now());
        let watch = json!({
            "network": self.network,
            "cancel": bitcoin::consensus::encode::serialize_hex(&cancel),
            "refund": bitcoin::consensus::encode::serialize_hex(&refund),
            // How deep the refund must be before the watch is done.
            "depth": terms.btc_confirmations,
        });
        let url = format!("{}/watch", relay.trim_end_matches('/'));
        match ureq::post(&url).timeout(TIMEOUT).send_json(watch) {
            Ok(_) => {
                self.posted = true;
                log(&format!("handed the refund to the watchtower at {relay}"));
            }
            Err(ureq::Error::Status(code, response)) => log(&format!(
                "the watchtower at {relay} refused the refund: {code} {}",
                response.into_string().unwrap_or_default()
            )),
            Err(e) => log(&format!("the watchtower at {relay}: {e}")),
        }
    }
}

fn resume(args: SwapFileArgs) -> Result<Outcome> {
    let store = swap_store(&args.swap_file)?;
    let swap_file = store.path().to_path_buf();
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
    match saved {
        Saved::Seller(seller) => {
            let given = args.key.given()?;
            let key = seller_key(seller.nex_address(), seller.signs_nex(), given)?;
            let bitcoin = args.nodes.bitcoin()?;
            let nexus = args.nodes.nexus()?;
            if seller.outcome().is_none() {
                args.nodes.check_nexus(&nexus)?;
            }
            let driver = Driver::<Seller, _, Ivy>::resume(bitcoin, nexus, None, store);
            run(
                &swap_file,
                driver.map(|mut driver| {
                    driver.nex_key = key;
                    driver
                }),
                &args.bump,
                |_| {},
            )
        }
        Saved::Buyer(buyer) => {
            let bitcoin = args.nodes.bitcoin()?;
            let nexus = args.nodes.nexus()?;
            if buyer.outcome().is_none() {
                args.nodes.check_nexus(&nexus)?;
            }
            let watchtower = Watchtower::new(args.watchtower, args.nodes.btc_network);
            let watchtower = RefCell::new(watchtower);
            run(
                &swap_file,
                Driver::<Buyer, _, Ivy>::resume(bitcoin, nexus, None, store),
                &args.bump,
                |buyer| watchtower.borrow_mut().see(buyer),
            )
        }
    }
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

/// Runs the swap to its end, bumping as `bump` says, logging each state it
/// reaches and showing it to `see`. On an error once the swap file exists,
/// says how to carry on.
fn run<M: Machine, B: Bitcoin, T: Transport>(
    swap_file: &Path,
    driver: io::Result<Driver<M, B, T>>,
    bump: &BumpArgs,
    see: impl Fn(&M),
) -> Result<Outcome> {
    let last = RefCell::new(String::new());
    let outcome = driver
        .and_then(|mut driver| {
            bump.apply(&mut driver);
            driver.run_until(|state| {
                see(state);
                let name = state_name(state);
                if *last.borrow() != name {
                    log(&name);
                    *last.borrow_mut() = name;
                }
                false
            })
        })
        .map_err(|e| resume_hint(swap_file, e.into()))?;
    let outcome = outcome.expect("only an outcome ends a run that never stops");
    println!("outcome: {outcome:?}");
    Ok(outcome)
}

/// The error, and how to carry on if the swap file exists.
fn resume_hint(swap_file: &Path, error: Box<dyn std::error::Error>) -> Box<dyn std::error::Error> {
    if !swap_file.exists() {
        return error;
    }
    format!(
        "{error}\nto carry on, run with the same flags, the node and key flags and \
         --max-fee-rate, --fallback-fee-rate, --max-fee-fraction and --max-tip-age: \
         lattice-swap resume {}",
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

/// A swap file as the driver saved it.
enum Saved {
    Seller(Seller),
    Buyer(Buyer),
}

impl Saved {
    /// Both machines have `ClaimingNex` and `Done`. A claim names its side;
    /// a swap that is done no longer needs one. Fails on a file of another
    /// state version, as the driver would.
    fn load(store: &Store) -> Result<Self> {
        let path = store.path();
        let value = match store.load_value() {
            Ok(Some(value)) => value,
            Ok(None) => return Err(format!("{}: no such swap file", path.display()).into()),
            // Names the file and the versions.
            Err(e) if e.kind() == io::ErrorKind::InvalidData => return Err(e.into()),
            Err(e) => return Err(format!("{}: {e}", path.display()).into()),
        };
        if value["ClaimingNex"]["setup"]["side"] != "Buyer" {
            if let Ok(seller) = serde_json::from_value(value.clone()) {
                return Ok(Saved::Seller(seller));
            }
        }
        let buyer = serde_json::from_value(value)
            .map_err(|e| format!("{} is not a swap file: {e}", path.display()))?;
        Ok(Saved::Buyer(buyer))
    }

    /// The Nexus the swap trades on, until it ends.
    fn nexus_genesis(&self) -> Option<&str> {
        let terms = match self {
            Saved::Seller(seller) => seller.terms(),
            Saved::Buyer(buyer) => buyer.terms(),
        };
        terms.map(|terms| terms.nexus_genesis.as_str())
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

/// Runs the command, to its exit status.
fn exit_status(command: Command) -> Result<u8> {
    match command {
        Command::Offer(args) => offer(args).map(exit_code),
        Command::Take(args) => take(args).map(exit_code),
        Command::Resume(args) => resume(args).map(exit_code),
        Command::Status { swap_file } => status(&swap_file).map(|()| 0),
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
