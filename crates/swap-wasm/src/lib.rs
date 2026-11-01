//! The swap machines for a browser. Everything crosses as JSON text, in the
//! shapes serde gives the `swap` types, and no call does I/O: the page feeds
//! each [`Event`] it sees and carries out the [`Action`]s it gets back.
//!
//! A step returns `{"state", "actions", "outcome", "awaits_message"}`. The
//! page keeps `state` and passes it to the next step, and asks
//! `watchSeller` or `watchBuyer` what to observe for it. It judges what it
//! fetched by the driver's own rules: [`bitcoin_stale`],
//! [`cancel_search_from`] and [`nexus_one_tip`]. [`backup`] wraps a state
//! as a swap file `lattice-swap resume` reads, and [`restore`] reads one
//! back.
//!
//! For a buyer in a browser, without a wallet or nodes of its own: it reads
//! an offer by [`decode_offer`] and judges it by [`check_offer`], talks to
//! the seller over [`session::Ivy`], funds the lock from a deposit address
//! ([`deposit`]), builds its Nexus view by [`nexus_view`], hands a relay its
//! refund by [`watch_request`], and shows where it is by [`buyer_status`].

mod deposit;
mod session;

use std::str::FromStr;

use bitcoin::secp256k1::{Secp256k1, SecretKey};
use bitcoin::{Address, CompressedPublicKey, Network, PrivateKey, ScriptBuf};
use ed25519_dalek::SigningKey;
use rand_core::{OsRng, RngCore};
use serde_json::{json, Value};
use swap::offer::{self, Offer, Policy};
use swap::view::{self, Lookups, Tip};
use swap::STATE_VERSION;
use swap::{BitcoinView, Buyer, Event, Machine, Message, NexusView, SecretBytes, Seller, Spent};
use swap_nexus_tx::rpc::{parse as answer, Health};
use swap_nexus_tx::{Transaction, TransactionBody};
use wasm_bindgen::prelude::*;

/// Errors reach JavaScript as the thrown string.
type Result<T> = std::result::Result<T, String>;

/// A seller's swap with fresh secrets: its state. `nex_address` holds the
/// NEX to sell; the payouts are scripts in hex.
#[wasm_bindgen(js_name = newSeller)]
pub fn new_seller(
    terms: &str,
    nex_address: &str,
    redeem_payout: &str,
    punish_payout: &str,
) -> Result<String> {
    let seller = Seller::new(
        parse(terms)?,
        nex_address.into(),
        script(redeem_payout)?,
        script(punish_payout)?,
    )
    .map_err(|refusal| format!("refused: {refusal:?}"))?;
    text(&seller)
}

/// A buyer's swap with fresh secrets, and the hello that opens it: a step.
/// The NEX arrives at `nex_address`; the refund payout is a script in hex.
#[wasm_bindgen(js_name = startBuyer)]
pub fn start_buyer(terms: &str, refund_payout: &str, nex_address: &str) -> Result<String> {
    let (buyer, actions) = Buyer::start(parse(terms)?, script(refund_payout)?, nex_address.into())
        .map_err(|refusal| format!("refused: {refusal:?}"))?;
    stepped(&buyer, &actions)
}

/// Why `terms` are refused, as `newSeller` and `startBuyer` refuse them,
/// or null if they are not.
#[wasm_bindgen(js_name = checkTerms)]
pub fn check_terms(terms: &str) -> Result<Option<String>> {
    Ok(parse::<swap::Terms>(terms)?.check().err())
}

/// Feeds `event` to a seller's `state`: a step.
#[wasm_bindgen(js_name = stepSeller)]
pub fn step_seller(state: &str, event: &str) -> Result<String> {
    step::<Seller>(state, event)
}

/// Feeds `event` to a buyer's `state`: a step.
#[wasm_bindgen(js_name = stepBuyer)]
pub fn step_buyer(state: &str, event: &str) -> Result<String> {
    step::<Buyer>(state, event)
}

fn step<M: Machine>(state: &str, event: &str) -> Result<String> {
    let machine: M = parse(state)?;
    let event: Event = parse(event)?;
    let (machine, actions) = machine.step(event);
    stepped(&machine, &actions)
}

fn stepped<M: Machine>(machine: &M, actions: &[swap::Action]) -> Result<String> {
    text(&json!({
        "state": machine,
        "actions": actions,
        "outcome": machine.outcome(),
        "awaits_message": machine.awaits_message(),
    }))
}

/// A state as the swap file the driver writes: `{"name", "file"}`, where
/// `name` is `<swap id>.json`, the name `lattice-swap resume` needs.
/// Refuses anything but a seller's or buyer's state, and a finished swap,
/// which no longer names its swap id. A buyer funding from a deposit
/// address gives its key, as WIF, as `deposit`: the file keeps it, and
/// `lattice-swap resume` ignores it.
#[wasm_bindgen]
pub fn backup(state: &str, deposit: Option<String>) -> Result<String> {
    let (_, state, terms) = machine(parse(state)?)?;
    let terms = terms.ok_or("the swap is over: there is nothing to resume")?;
    let mut file = json!({"version": STATE_VERSION, "state": state});
    if let Some(deposit) = deposit {
        file["deposit"] = deposit.into();
    }
    text(&json!({
        "name": format!("{}.json", hex::encode(terms.swap_id)),
        "file": text(&file)?,
    }))
}

/// A swap file's state and its side: `{"side": "seller" | "buyer",
/// "state", "deposit"}`, `deposit` the key [`backup`] kept, or null.
/// Refuses a file of another state version, as the driver does.
#[wasm_bindgen]
pub fn restore(file: &str) -> Result<String> {
    let mut file: Value = parse(file)?;
    let version = &file["version"];
    if version.as_u64() != Some(STATE_VERSION.into()) {
        return Err(format!(
            "state version {version}, but this build reads only {STATE_VERSION}"
        ));
    }
    let (side, state, _) = machine(file["state"].take())?;
    text(&json!({"side": side, "state": state, "deposit": file["deposit"]}))
}

/// A state's side, the state, and its terms until the swap ends.
fn machine(state: Value) -> Result<(&'static str, Value, Option<swap::Terms>)> {
    // As `lattice-swap resume` tells them apart: both machines have
    // `ClaimingNex` and `Done`, and a claim names its side.
    if state["ClaimingNex"]["setup"]["side"] != "Buyer" {
        if let Ok(seller) = serde_json::from_value::<Seller>(state.clone()) {
            return Ok(("seller", state, seller.terms().cloned()));
        }
    }
    let buyer = serde_json::from_value::<Buyer>(state.clone())
        .map_err(|e| format!("not a swap state: {e}"))?;
    Ok(("buyer", state, buyer.terms().cloned()))
}

/// What to observe for a seller's `state`: `{"bitcoin", "nexus",
/// "margin"}`. `bitcoin`, once the lock is agreed, is what a view looks up
/// (`lock`, `lock_spends`, `cancel_spends`, `cancel_output`, `t2`), and
/// `nexus` the addresses to read, the `cid` to report as `watched` and the
/// height whose block to report as `block_at`; each null when not watched.
#[wasm_bindgen(js_name = watchSeller)]
pub fn watch_seller(state: &str) -> Result<String> {
    watch::<Seller>(state)
}

/// What to observe for a buyer's `state`, as [`watch_seller`].
#[wasm_bindgen(js_name = watchBuyer)]
pub fn watch_buyer(state: &str) -> Result<String> {
    watch::<Buyer>(state)
}

fn watch<M: Machine>(state: &str) -> Result<String> {
    let watch = parse::<M>(state)?.watch();
    text(&json!({
        "bitcoin": watch.bitcoin.map(|(swap, lock)| Lookups::new(&swap, lock)),
        "nexus": watch.nexus,
        "margin": watch.margin,
    }))
}

/// Why a Bitcoin view is stale, as the driver judges it: `{"tip",
/// "first_seen", "max_tip_age", "now"}` in, the last two in seconds and
/// `first_seen` the `[hash, seconds]` the last call returned or null;
/// `{"stale", "first_seen"}` out, `stale` the reason or null, for the
/// view's `stale` and the next call.
#[wasm_bindgen(js_name = bitcoinStale)]
pub fn bitcoin_stale(input: &str) -> Result<String> {
    #[derive(serde::Deserialize)]
    struct Input {
        tip: Tip,
        first_seen: Option<(bitcoin::BlockHash, u64)>,
        max_tip_age: u64,
        now: u64,
    }
    let mut input: Input = parse(input)?;
    let stale = view::stale(
        &input.tip,
        input.max_tip_age,
        input.now,
        &mut input.first_seen,
    );
    text(&json!({"stale": stale, "first_seen": input.first_seen}))
}

/// The lowest block to search for the cancel output's spender in, or null
/// if the view need not search: `{"lookups", "height", "lock_spend",
/// "cancel_spend"}` in, `lookups` from a watch and the spends as found by
/// it.
#[wasm_bindgen(js_name = cancelSearchFrom)]
pub fn cancel_search_from(input: &str) -> Result<String> {
    #[derive(serde::Deserialize)]
    struct Input {
        lookups: Lookups,
        height: u32,
        lock_spend: Option<Spent>,
        cancel_spend: Option<Spent>,
    }
    let input: Input = parse(input)?;
    let from = input
        .lookups
        .search_from(input.height, &input.lock_spend, &input.cancel_spend);
    text(&from)
}

/// Whether two `/health` reads, before and after the rest of a Nexus view,
/// are at one tip: if not, the view is dropped and read again.
#[wasm_bindgen(js_name = nexusOneTip)]
pub fn nexus_one_tip(before: &str, after: &str) -> Result<bool> {
    let (before, after): (Health, Health) = (parse(before)?, parse(after)?);
    Ok(view::one_tip(&before, &after))
}

/// The least `btc_fee`, in satoshis, at which cancel and refund pay
/// `per_kvb` sat/kvB, given as a JSON number: the floor the CLI holds an
/// offer's fee to, at the page's own fee estimate.
#[wasm_bindgen(js_name = btcFeeAt)]
pub fn btc_fee_at(per_kvb: &str) -> Result<String> {
    text(&swap::btc_fee_at(parse(per_kvb)?))
}

/// A message as the CLI sends it, for the swap `swap_id` (hex).
#[wasm_bindgen(js_name = encodeMessage)]
pub fn encode_message(message: &str, swap_id: &str) -> Result<Vec<u8>> {
    Ok(parse::<Message>(message)?.encode(swap_id_bytes(swap_id)?))
}

/// The message in `bytes`, if it is one for the swap `swap_id`; else
/// undefined.
#[wasm_bindgen(js_name = decodeMessage)]
pub fn decode_message(bytes: &[u8], swap_id: &str) -> Result<Option<String>> {
    Message::decode(bytes, swap_id_bytes(swap_id)?)
        .map(|message| text(&message))
        .transpose()
}

pub(crate) fn swap_id_bytes(swap_id: &str) -> Result<[u8; 32]> {
    let mut bytes = [0u8; 32];
    hex::decode_to_slice(swap_id.trim(), &mut bytes)
        .map_err(|_| "the swap id is not 32 bytes of hex")?;
    Ok(bytes)
}

/// A fresh Nexus key: `{"seed", "address"}`, the seed as hex.
#[wasm_bindgen(js_name = newNexKey)]
pub fn new_nex_key() -> Result<String> {
    let seed = SecretBytes(random32());
    text(&json!({"seed": hex::encode(seed.0), "address": seed.nex_address()}))
}

/// A fresh Bitcoin key on `network` (`bitcoin`, `testnet`, `signet` or
/// `regtest`) and the P2WPKH output it owns: `{"wif", "script_pubkey",
/// "address"}`.
#[wasm_bindgen(js_name = newBitcoinKey)]
pub fn new_bitcoin_key(network: &str) -> Result<String> {
    let network = Network::from_str(network).map_err(|e| e.to_string())?;
    let secret = SecretKey::from_slice(&random32()).map_err(|e| e.to_string())?;
    bitcoin_key(PrivateKey::new(secret, network), network)
}

/// The key `wif`, on `network`, as [`new_bitcoin_key`] gives one.
#[wasm_bindgen(js_name = bitcoinKeyOf)]
pub fn bitcoin_key_of(wif: &str, network: &str) -> Result<String> {
    let network = Network::from_str(network).map_err(|e| e.to_string())?;
    let key = PrivateKey::from_wif(wif.trim()).map_err(|e| e.to_string())?;
    if key.network != network.into() {
        return Err(format!("the key is not for {network}"));
    }
    bitcoin_key(key, network)
}

fn bitcoin_key(key: PrivateKey, network: Network) -> Result<String> {
    let public = CompressedPublicKey(key.inner.public_key(&Secp256k1::signing_only()));
    let address = Address::p2wpkh(&public, network);
    text(&json!({
        "wif": key.to_wif(),
        "script_pubkey": address.script_pubkey(),
        "address": address.to_string(),
    }))
}

/// Whether `text` is spelled as Lattice spells a CID, as a Nexus address
/// is: NEX paid to anything else is lost.
#[wasm_bindgen(js_name = isCid)]
pub fn is_cid(text: &str) -> bool {
    swap_nexus_tx::is_cid(text)
}

/// An address nobody holds, whose account after a past block shows
/// whether a Nexus node keeps the state of past blocks, as the CLI asks.
#[wasm_bindgen(js_name = nexusProbeAddress)]
pub fn nexus_probe_address() -> String {
    swap_nexus_tx::address(&[0; 32])
}

/// The output script, in hex, that pays `address` on `network`; refuses
/// an address of another network.
#[wasm_bindgen(js_name = scriptOf)]
pub fn script_of(address: &str, network: &str) -> Result<String> {
    let network = Network::from_str(network).map_err(|e| e.to_string())?;
    let address = Address::from_str(address.trim()).map_err(|e| e.to_string())?;
    let address = address
        .require_network(network)
        .map_err(|e| e.to_string())?;
    Ok(address.script_pubkey().to_hex_string())
}

/// Answers a seller's `SignNex`: the body signed with the Nexus key whose
/// seed is `seed`, as the transaction for `NexSigned`.
#[wasm_bindgen(js_name = signNex)]
pub fn sign_nex(seed: &str, body: &str) -> Result<String> {
    let mut bytes = [0u8; 32];
    hex::decode_to_slice(seed.trim(), &mut bytes).map_err(|_| "the seed is not 32 bytes of hex")?;
    let body: TransactionBody = parse(body)?;
    let mut transaction = Transaction::new(body);
    transaction.sign(&SigningKey::from_bytes(&bytes));
    text(&transaction)
}

/// The offer in `text`, as the CLI's `take` reads one: it names where to
/// find the seller, and the seller signed its terms (strictly). The offer
/// as JSON.
#[wasm_bindgen(js_name = decodeOffer)]
pub fn decode_offer(text: &str) -> Result<String> {
    self::text(&Offer::decode(text)?)
}

/// Why a buyer refuses an offer, as the CLI's `take` refuses it, or null.
/// `{"offer", "policy", "network", "nexus_genesis", "fee_estimate",
/// "min_relay_fee"}` in: the policy as [`Policy`], its bounds defaulting to
/// the CLI's; `fee_estimate` the estimate for 6 blocks in sat/kvB, or null
/// where there is none; `min_relay_fee` the Nexus node's.
#[wasm_bindgen(js_name = checkOffer)]
pub fn check_offer(input: &str) -> Result<Option<String>> {
    #[derive(serde::Deserialize)]
    struct Input {
        offer: Offer,
        policy: Policy,
        network: Network,
        nexus_genesis: String,
        fee_estimate: Option<u64>,
        min_relay_fee: u64,
    }
    let input: Input = parse(input)?;
    let bounds = &input.policy.bounds;
    let floor = match offer::btc_fee_floor(input.fee_estimate, bounds.min_btc_fee_rate) {
        Ok(floor) => floor,
        Err(why) => return Ok(Some(why)),
    };
    let nex_floor = offer::nex_fee_floor(bounds.min_nex_fee, input.min_relay_fee);
    Ok(offer::check_offer(
        &input.offer,
        &input.policy,
        input.network,
        &input.nexus_genesis,
        floor,
        nex_floor,
    )
    .err())
}

/// A Nexus view from the node's answers, read in the order
/// [`swap::view`] gives: `{"health", "own", "lock", "chain_info",
/// "watched", "block_at", "health_after"}`, each a route's JSON as the
/// node answered it. `own` and `lock` are `/api/state/account/:address`,
/// `chain_info` is `/api/chain/info`, and `block_at` is
/// `/api/block/:height`, null if not asked or unknown. `watched`, if
/// watched, is `{"before", "health", "after"}`: the transaction read, then
/// `/health`, then the transaction again, each transaction null where the
/// node holds none. The view as JSON, or null if the two healths are not
/// at one tip.
#[wasm_bindgen(js_name = nexusView)]
pub fn nexus_view(reads: &str) -> Result<Option<String>> {
    let reads: Value = parse(reads)?;
    let health = answer::health(&reads["health"])?;
    let after = answer::health(&reads["health_after"])?;
    if !view::one_tip(&health, &after) {
        return Ok(None);
    }
    let watched = &reads["watched"];
    let watched = match &watched["before"] {
        Value::Null => None,
        before => {
            let status = answer::transaction(before)?;
            let height = answer::health(&watched["health"])?.height;
            let after = match &watched["after"] {
                Value::Null => None,
                after => Some(answer::transaction(after)?),
            };
            let after = after.and_then(|after| after.block);
            let depth = answer::confirmations(status.block.as_ref(), height, after.as_ref());
            Some((status, depth))
        }
    };
    let block_at = match &reads["block_at"] {
        Value::Null => None,
        block => Some(answer::block_hash(block)?),
    };
    text(&NexusView {
        health,
        own: answer::account(&reads["own"])?,
        lock: answer::account(&reads["lock"])?,
        min_relay_fee: answer::min_relay_fee(&reads["chain_info"])?,
        watched,
        block_at,
    })
    .map(Some)
}

/// The body to `POST /transactions` a Nexus node for `transaction`, from a
/// `Submit` action.
#[wasm_bindgen(js_name = nexusSubmitBody)]
pub fn nexus_submit_body(transaction: &str) -> Result<String> {
    text(&parse::<swap_nexus_tx::Transaction>(transaction)?.to_submit_json())
}

/// What to `POST /watch` a relay for a buyer's `state` on the Bitcoin
/// `network`, or null: the CLI's condition, [`Buyer::watchtower`].
#[wasm_bindgen(js_name = watchRequest)]
pub fn watch_request(state: &str, network: &str) -> Result<Option<String>> {
    let network = Network::from_str(network).map_err(|e| e.to_string())?;
    parse::<Buyer>(state)?
        .watch_request(network)
        .map(|watch| text(&watch))
        .transpose()
}

/// Where a buyer's swap is, for a page to show: `{"phase",
/// "awaits_message", "must_stay_open", "cancel_at", "punish_at"}`, given its `state` and the
/// last Bitcoin view, or null. `phase` is `locking` until the NEX lock is
/// trusted, `finishing` once the redeem is signed, `refunding` once it
/// cancels, then the outcome: `swapped`, `refunded`, `punished`, `drained`
/// or `aborted`. `must_stay_open` holds while the redeem is signed and the
/// swap not settled: nothing but this page refunds or claims for it then.
/// `cancel_at` is the Bitcoin height from which cancel can be broadcast,
/// once the lock is in a block; `punish_at` the height from which the
/// seller can punish, once cancel is, which the refund must beat.
#[wasm_bindgen(js_name = buyerStatus)]
pub fn buyer_status(state: &str, view: Option<String>) -> Result<String> {
    let buyer: Buyer = parse(state)?;
    let view: Option<BitcoinView> = view.as_deref().map(parse).transpose()?;
    let value: Value = parse(state)?;
    let redeem_signed = |field: &Value| !field["redeem"].is_null();
    let (phase, must_stay_open) = match &value {
        Value::Object(state) => match state.iter().next() {
            Some((name, inner)) => match name.as_str() {
                "AwaitRedeem" | "ClaimingNex" => ("finishing", true),
                "Cancelling" => ("refunding", redeem_signed(inner)),
                "Done" => (outcome(inner), false),
                _ => ("locking", false),
            },
            None => return Err("not a buyer's state".into()),
        },
        _ => return Err("not a buyer's state".into()),
    };
    let (mut cancel_at, mut punish_at) = (None, None);
    if let (Some((swap, lock)), Some(view), Some(terms)) =
        (buyer.watch().bitcoin, view, buyer.terms())
    {
        // Mined `depth` deep at `view.height`: in block `height + 1 - depth`.
        let mined = |depth: u32| (depth > 0).then(|| view.height + 1 - depth);
        if let Some(lock_height) = view.funding.and_then(mined) {
            cancel_at = Some(lock_height + u32::from(terms.t1) - 1);
        }
        let cancel = Lookups::new(&swap, lock).lock_spends[1];
        let cancelled = view
            .lock_spend
            .filter(|spent| spent.tx.compute_txid() == cancel);
        if let Some(cancel_height) = cancelled.and_then(|spent| mined(spent.confirmations)) {
            punish_at = Some(cancel_height + u32::from(terms.t2) - 1);
        }
    }
    text(&json!({
        "phase": phase,
        "awaits_message": buyer.awaits_message(),
        "must_stay_open": must_stay_open,
        "cancel_at": cancel_at,
        "punish_at": punish_at,
    }))
}

/// An outcome's name, as `buyer_status` gives it.
fn outcome(outcome: &Value) -> &'static str {
    match outcome.as_str() {
        Some("Swapped") => "swapped",
        Some("Refunded") => "refunded",
        Some("Punished") => "punished",
        Some("Drained") => "drained",
        _ => "aborted",
    }
}

pub(crate) fn parse<T: serde::de::DeserializeOwned>(json: &str) -> Result<T> {
    serde_json::from_str(json).map_err(|e| e.to_string())
}

pub(crate) fn text<T: serde::Serialize>(value: &T) -> Result<String> {
    serde_json::to_string(value).map_err(|e| e.to_string())
}

fn script(hex: &str) -> Result<ScriptBuf> {
    ScriptBuf::from_hex(hex).map_err(|e| e.to_string())
}

fn random32() -> [u8; 32] {
    let mut bytes = [0u8; 32];
    OsRng.fill_bytes(&mut bytes);
    bytes
}

#[cfg(test)]
mod tests;
