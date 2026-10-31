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

use std::str::FromStr;

use bitcoin::secp256k1::{Secp256k1, SecretKey};
use bitcoin::{Address, CompressedPublicKey, Network, PrivateKey, ScriptBuf};
use ed25519_dalek::SigningKey;
use rand_core::{OsRng, RngCore};
use serde_json::{json, Value};
use swap::view::{self, Lookups, Tip};
use swap::{Buyer, Event, Machine, Message, SecretBytes, Seller, Spent, STATE_VERSION};
use swap_nexus_tx::rpc::Health;
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
/// which no longer names its swap id.
#[wasm_bindgen]
pub fn backup(state: &str) -> Result<String> {
    let (_, state, terms) = machine(parse(state)?)?;
    let terms = terms.ok_or("the swap is over: there is nothing to resume")?;
    text(&json!({
        "name": format!("{}.json", hex::encode(terms.swap_id)),
        "file": text(&json!({"version": STATE_VERSION, "state": state}))?,
    }))
}

/// A swap file's state and its side: `{"side": "seller" | "buyer",
/// "state"}`. Refuses a file of another state version, as the driver does.
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
    text(&json!({"side": side, "state": state}))
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

fn swap_id_bytes(swap_id: &str) -> Result<[u8; 32]> {
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
    let key = PrivateKey::new(secret, network);
    let public = CompressedPublicKey(secret.public_key(&Secp256k1::signing_only()));
    let address = Address::p2wpkh(&public, network);
    text(&json!({
        "wif": key.to_wif(),
        "script_pubkey": address.script_pubkey(),
        "address": address.to_string(),
    }))
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

fn parse<T: serde::de::DeserializeOwned>(json: &str) -> Result<T> {
    serde_json::from_str(json).map_err(|e| e.to_string())
}

fn text<T: serde::Serialize>(value: &T) -> Result<String> {
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
