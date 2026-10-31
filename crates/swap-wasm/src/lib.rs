//! The swap machines for a browser. Everything crosses as JSON text, in the
//! shapes serde gives the `swap` types, and no call does I/O: the page feeds
//! each [`Event`] it sees and carries out the [`Action`]s it gets back.
//!
//! A step returns `{"state", "actions", "outcome", "awaits_message"}`. The
//! page keeps `state` and passes it to the next step. [`backup`] wraps a
//! state as a swap file `lattice-swap resume` reads, and [`restore`] reads
//! one back.

use std::str::FromStr;

use bitcoin::secp256k1::{Secp256k1, SecretKey};
use bitcoin::{Address, CompressedPublicKey, Network, PrivateKey, ScriptBuf};
use ed25519_dalek::SigningKey;
use rand_core::{OsRng, RngCore};
use serde_json::{json, Value};
use swap::{Buyer, Event, Machine, SecretBytes, Seller, STATE_VERSION};
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

/// A state as the swap file the driver writes.
#[wasm_bindgen]
pub fn backup(state: &str) -> Result<String> {
    let state: Value = parse(state)?;
    text(&json!({"version": STATE_VERSION, "state": state}))
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
    let state = file["state"].take();
    // As `lattice-swap resume` tells them apart: both machines have
    // `ClaimingNex` and `Done`, and a claim names its side.
    if state["ClaimingNex"]["setup"]["side"] != "Buyer"
        && serde_json::from_value::<Seller>(state.clone()).is_ok()
    {
        return text(&json!({"side": "seller", "state": state}));
    }
    serde_json::from_value::<Buyer>(state.clone()).map_err(|e| format!("not a swap file: {e}"))?;
    text(&json!({"side": "buyer", "state": state}))
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
