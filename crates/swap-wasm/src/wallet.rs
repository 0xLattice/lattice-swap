//! The page's own Bitcoin wallet: [`swap::wallet`], with JSON in and out.
//! A swap funds its lock from the wallet's balance, any change goes back to
//! it, and so does the swap's refund; [`wallet_sweep`] withdraws the
//! balance to any address.
//!
//! The page reads the key's outputs and a fee rate, in whole sat/vB, from
//! its Esplora; nothing here does I/O.

use bitcoin::ScriptBuf;
use serde::Deserialize;
use serde_json::json;
use swap::wallet::{self, Signed, Utxo};
use wasm_bindgen::prelude::*;

use crate::{parse, text, Result};

fn answer(signed: &Signed) -> Result<String> {
    text(&json!({
        "tx": bitcoin::consensus::encode::serialize_hex(&signed.tx),
        "txid": signed.tx.compute_txid(),
        "fee": signed.fee,
    }))
}

/// Whether the wallet's `utxos` can fund a lock of `amount` at
/// `fee_rate`, and the balance a funding with change needs from as many
/// outputs: [`wallet::need`]. `{"utxos", "amount", "fee_rate"}` in,
/// `{"enough", "need"}` out.
#[wasm_bindgen(js_name = walletNeed)]
pub fn wallet_need(input: &str) -> Result<String> {
    #[derive(Deserialize)]
    struct Input {
        utxos: Vec<Utxo>,
        amount: u64,
        fee_rate: u64,
    }
    let input: Input = parse(input)?;
    let (enough, need) = wallet::need(input.utxos, input.amount, input.fee_rate);
    text(&json!({"enough": enough, "need": need}))
}

/// The funding transaction for `FundLock`: [`wallet::fund`]. `{"wif",
/// "utxos", "script_pubkey", "amount", "fee_rate"}` in; `{"tx", "txid",
/// "fee"}` out.
#[wasm_bindgen(js_name = walletFund)]
pub fn wallet_fund(input: &str) -> Result<String> {
    #[derive(Deserialize)]
    struct Input {
        wif: String,
        utxos: Vec<Utxo>,
        script_pubkey: ScriptBuf,
        amount: u64,
        fee_rate: u64,
    }
    let input: Input = parse(input)?;
    answer(&wallet::fund(
        &input.wif,
        input.utxos,
        input.script_pubkey,
        input.amount,
        input.fee_rate,
    )?)
}

/// Everything in the wallet's `utxos` to `script_pubkey`, less the fee at
/// `fee_rate`: [`wallet::sweep`]. `{"wif", "utxos", "script_pubkey",
/// "fee_rate"}` in, `{"tx", "txid", "fee"}` out.
#[wasm_bindgen(js_name = walletSweep)]
pub fn wallet_sweep(input: &str) -> Result<String> {
    #[derive(Deserialize)]
    struct Input {
        wif: String,
        utxos: Vec<Utxo>,
        script_pubkey: ScriptBuf,
        fee_rate: u64,
    }
    let input: Input = parse(input)?;
    answer(&wallet::sweep(
        &input.wif,
        &input.utxos,
        input.script_pubkey,
        input.fee_rate,
    )?)
}
