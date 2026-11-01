//! The page's own Bitcoin wallet, as eigenwallet keeps an internal one: a
//! single P2WPKH key the buyer deposits to. A swap funds its lock from the
//! wallet's balance, any change goes back to it, and so does the swap's
//! refund; [`wallet_sweep`] withdraws the balance to any address.
//!
//! The page reads the key's outputs and a fee rate, in whole sat/vB, from
//! its Esplora; nothing here does I/O.

use bitcoin::hashes::Hash;
use bitcoin::secp256k1::{Message as Digest, PublicKey, Secp256k1};
use bitcoin::sighash::{EcdsaSighashType, SighashCache};
use bitcoin::transaction::{predict_weight, InputWeightPrediction, Version};
use bitcoin::{absolute, Amount, CompressedPublicKey, OutPoint, PrivateKey, ScriptBuf, Sequence};
use bitcoin::{Transaction, TxIn, TxOut, Txid, Witness};
use serde::Deserialize;
use serde_json::json;
use wasm_bindgen::prelude::*;

use crate::{parse, text, Result};

/// An output the wallet key holds.
#[derive(Clone, Copy, Deserialize)]
struct Utxo {
    txid: Txid,
    vout: u32,
    value: u64,
}

/// The wallet key, and the P2WPKH output script it owns.
fn key(wif: &str) -> Result<(PrivateKey, PublicKey, ScriptBuf)> {
    let key = PrivateKey::from_wif(wif).map_err(|e| e.to_string())?;
    let public = key.public_key(&Secp256k1::signing_only()).inner;
    let script = ScriptBuf::new_p2wpkh(&CompressedPublicKey(public).wpubkey_hash());
    Ok((key, public, script))
}

/// The fee, at `rate` sat/vB, of a transaction spending `inputs` of the
/// wallet's outputs into outputs of scripts `outputs` bytes long, signed.
fn fee(inputs: usize, outputs: &[usize], rate: u64) -> u64 {
    predict_weight(
        vec![InputWeightPrediction::P2WPKH_MAX; inputs],
        outputs.iter().copied(),
    )
    .to_vbytes_ceil()
    .saturating_mul(rate)
}

/// `inputs`, all the wallet's, into `outputs`, signed.
fn signed(wif: &str, inputs: &[Utxo], outputs: Vec<TxOut>) -> Result<Transaction> {
    let (key, public, script) = key(wif)?;
    let mut tx = Transaction {
        version: Version::TWO,
        lock_time: absolute::LockTime::ZERO,
        input: inputs
            .iter()
            .map(|utxo| TxIn {
                previous_output: OutPoint::new(utxo.txid, utxo.vout),
                sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
                ..Default::default()
            })
            .collect(),
        output: outputs,
    };
    let secp = Secp256k1::signing_only();
    let mut cache = SighashCache::new(tx.clone());
    for (i, utxo) in inputs.iter().enumerate() {
        let sighash = cache
            .p2wpkh_signature_hash(
                i,
                &script,
                Amount::from_sat(utxo.value),
                EcdsaSighashType::All,
            )
            .map_err(|e| e.to_string())?;
        let signature = bitcoin::ecdsa::Signature::sighash_all(
            secp.sign_ecdsa(&Digest::from_digest(sighash.to_byte_array()), &key.inner),
        );
        tx.input[i].witness = Witness::p2wpkh(&signature, &public);
    }
    Ok(tx)
}

fn total(utxos: &[Utxo]) -> u64 {
    utxos.iter().map(|utxo| utxo.value).sum()
}

fn answer(tx: &Transaction, spent: u64) -> Result<String> {
    let paid = spent - tx.output.iter().map(|out| out.value.to_sat()).sum::<u64>();
    text(&json!({
        "tx": bitcoin::consensus::encode::serialize_hex(tx),
        "txid": tx.compute_txid(),
        "fee": paid,
    }))
}

/// A P2TR output script, as the lock's is, and a P2WPKH one, as the
/// wallet's change is, in bytes.
const LOCK: usize = 34;
const CHANGE: usize = 22;

/// How many of `utxos`, sorted largest first, pay `amount` and the fee at
/// `rate` of a funding without change: the fewest, as BDK's
/// `LargestFirstCoinSelection` picks them; none if all of them cannot.
fn pick(utxos: &[Utxo], amount: u64, rate: u64) -> Option<usize> {
    (1..=utxos.len()).find(|&n| total(&utxos[..n]) >= amount + fee(n, &[LOCK], rate))
}

fn largest_first(mut utxos: Vec<Utxo>) -> Vec<Utxo> {
    utxos.sort_by_key(|utxo| std::cmp::Reverse(utxo.value));
    utxos
}

/// Whether the wallet's `utxos` can fund a lock of `amount` at
/// `fee_rate`, and the balance a funding with change needs from as many
/// outputs: what the page asks the buyer to deposit. `{"utxos", "amount",
/// "fee_rate"}` in, `{"enough", "need"}` out.
#[wasm_bindgen(js_name = walletNeed)]
pub fn wallet_need(input: &str) -> Result<String> {
    #[derive(Deserialize)]
    struct Input {
        utxos: Vec<Utxo>,
        amount: u64,
        fee_rate: u64,
    }
    let input: Input = parse(input)?;
    let utxos = largest_first(input.utxos);
    let enough = pick(&utxos, input.amount, input.fee_rate).is_some();
    let inputs = utxos.len().max(1);
    let need = input.amount + fee(inputs, &[LOCK, CHANGE], input.fee_rate);
    text(&json!({"enough": enough, "need": need}))
}

/// The funding transaction for `FundLock`: `amount` to the lock's
/// `script_pubkey` from the wallet's `utxos`, picked largest first, at
/// `fee_rate`, the change back to the wallet; change below dust goes to the
/// fee, as BDK drops it. `{"wif", "utxos", "script_pubkey", "amount",
/// "fee_rate"}` in; `{"tx", "txid", "fee"}` out. Refuses `utxos` that
/// cannot pay for it.
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
    let (_, _, wallet) = key(&input.wif)?;
    let (amount, rate) = (input.amount, input.fee_rate);
    let utxos = largest_first(input.utxos);
    let n = pick(&utxos, amount, rate).ok_or_else(|| {
        format!(
            "the wallet's {} sat cannot fund the lock at {rate} sat/vB",
            total(&utxos)
        )
    })?;
    let picked = &utxos[..n];
    let total = total(picked);
    let lock = input.script_pubkey;
    let lock_len = lock.len();
    let mut outputs = vec![TxOut {
        value: Amount::from_sat(amount),
        script_pubkey: lock,
    }];
    let change = total.checked_sub(amount + fee(n, &[lock_len, wallet.len()], rate));
    if let Some(change) = change.filter(|change| *change >= wallet.minimal_non_dust().to_sat()) {
        outputs.push(TxOut {
            value: Amount::from_sat(change),
            script_pubkey: wallet,
        });
    }
    answer(&signed(&input.wif, picked, outputs)?, total)
}

/// Everything in the wallet's `utxos` to `script_pubkey`, less the fee at
/// `fee_rate`: a withdrawal, as a wallet's "send max" builds one.
/// `{"wif", "utxos", "script_pubkey", "fee_rate"}` in, `{"tx", "txid",
/// "fee"}` out.
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
    let total = total(&input.utxos);
    let fee = fee(
        input.utxos.len(),
        &[input.script_pubkey.len()],
        input.fee_rate,
    );
    let value = total
        .checked_sub(fee)
        .filter(|value| *value >= input.script_pubkey.minimal_non_dust().to_sat())
        .ok_or_else(|| format!("the wallet's {total} sat do not pay for their own withdrawal"))?;
    let output = TxOut {
        value: Amount::from_sat(value),
        script_pubkey: input.script_pubkey,
    };
    answer(&signed(&input.wif, &input.utxos, vec![output])?, total)
}
