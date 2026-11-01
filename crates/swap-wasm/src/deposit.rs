//! Funding the lock from a deposit address, for a buyer without a wallet:
//! the page shows the address of a fresh key, and once the deposit
//! confirms it sweeps it into the swap's BTC lock, as `Bitcoin::fund_lock`
//! builds and signs a funding transaction natively.
//!
//! The funding pays any change back to the deposit key, and a child sends
//! that change on to the buyer's refund address. The child is how a stuck
//! funding is bumped: by CPFP. RBF would change the funding's txid, which
//! the seller's cancel and refund signatures are made against, so a
//! replaced funding could never be refunded. The child spends only our own
//! output, so it can itself be replaced at a higher fee.
//!
//! Every fee rate here is in whole sat/vB. A deposit that cannot pay for
//! the funding at the asked rate, or holds more than twice the quote, which
//! is a mistake and not a fee, is refunded whole, less its fee, and no swap
//! starts.

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

/// An output the deposit key holds.
#[derive(Clone, Copy, Deserialize)]
struct Utxo {
    txid: Txid,
    vout: u32,
    value: u64,
}

/// How much headroom over its fees the quote holds, for the fee rate to
/// rise before the deposit confirms, and for a bump: twice the fees.
const HEADROOM: u64 = 2;

/// The deposit key, and the P2WPKH output script it owns.
fn key(wif: &str) -> Result<(PrivateKey, PublicKey, ScriptBuf)> {
    let key = PrivateKey::from_wif(wif).map_err(|e| e.to_string())?;
    let public = key.public_key(&Secp256k1::signing_only()).inner;
    let script = ScriptBuf::new_p2wpkh(&CompressedPublicKey(public).wpubkey_hash());
    Ok((key, public, script))
}

/// The most vbytes a transaction spending `inputs` deposit outputs into
/// `outputs` takes, signed.
fn vsize(inputs: usize, outputs: &[&ScriptBuf]) -> u64 {
    predict_weight(
        vec![InputWeightPrediction::P2WPKH_MAX; inputs],
        outputs.iter().map(|script| script.len()),
    )
    .to_vbytes_ceil()
}

/// Its fee at `rate` sat/vB.
fn fee(inputs: usize, outputs: &[&ScriptBuf], rate: u64) -> u64 {
    vsize(inputs, outputs).saturating_mul(rate)
}

/// `inputs`, all the deposit key's, into `outputs`, signed.
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

fn hex(tx: &Transaction) -> String {
    bitcoin::consensus::encode::serialize_hex(tx)
}

/// What to deposit for a swap of `btc_amount`: the amount and the fees of
/// the funding and of the child that returns its change, at `fee_rate`,
/// with [`HEADROOM`]. `{"btc_amount", "fee_rate", "deposit_wif",
/// "refund_script"}` in, satoshis out, as a JSON number.
#[wasm_bindgen(js_name = depositQuote)]
pub fn deposit_quote(input: &str) -> Result<String> {
    #[derive(Deserialize)]
    struct Input {
        btc_amount: u64,
        fee_rate: u64,
        deposit_wif: String,
        refund_script: ScriptBuf,
    }
    let input: Input = parse(input)?;
    let (_, _, change) = key(&input.deposit_wif)?;
    let fees = fee(1, &[&lock_script(), &change], input.fee_rate)
        + fee(1, &[&input.refund_script], input.fee_rate);
    text(&(input.btc_amount + HEADROOM * fees))
}

/// A P2TR output script, the size of the lock's.
fn lock_script() -> ScriptBuf {
    ScriptBuf::from_bytes([[0x51, 0x20].as_slice(), &[0; 32]].concat())
}

/// Why the deposit `utxos` are refunded rather than swapped, or null:
/// they cannot pay `btc_amount` and the funding at `fee_rate`, or hold
/// more than twice the `quote` shown. `{"utxos", "btc_amount", "quote",
/// "fee_rate"}` in.
#[wasm_bindgen(js_name = depositRefused)]
pub fn deposit_refused(input: &str) -> Result<Option<String>> {
    #[derive(Deserialize)]
    struct Input {
        utxos: Vec<Utxo>,
        btc_amount: u64,
        quote: u64,
        fee_rate: u64,
    }
    let input: Input = parse(input)?;
    let total = total(&input.utxos);
    let least = input.btc_amount + fee(input.utxos.len(), &[&lock_script()], input.fee_rate);
    Ok(if input.utxos.is_empty() {
        Some("nothing was deposited".into())
    } else if total < least {
        Some(format!(
            "the deposit holds {total} sat, below the {least} the swap and its funding at {} \
             sat/vB need",
            input.fee_rate
        ))
    } else if total > input.quote.saturating_mul(2) {
        Some(format!(
            "the deposit holds {total} sat, more than twice the {} asked",
            input.quote
        ))
    } else {
        None
    })
}

/// The funding transaction for `FundLock`: the deposit `utxos` into
/// `amount` at the lock's `script_pubkey`, at `fee_rate`, the change, if it
/// pays for its own way on, back to the deposit key. `{"wif", "utxos",
/// "script_pubkey", "amount", "fee_rate", "refund_script"}` in;
/// `{"tx", "fee", "change"}` out, `change` the change's `{"vout",
/// "value"}` or null.
#[wasm_bindgen(js_name = fundLock)]
pub fn fund_lock(input: &str) -> Result<String> {
    #[derive(Deserialize)]
    struct Input {
        wif: String,
        utxos: Vec<Utxo>,
        script_pubkey: ScriptBuf,
        amount: u64,
        fee_rate: u64,
        refund_script: ScriptBuf,
    }
    let input: Input = parse(input)?;
    let (_, _, deposit) = key(&input.wif)?;
    let total = total(&input.utxos);
    let n = input.utxos.len();
    let rate = input.fee_rate;
    let lock = TxOut {
        value: Amount::from_sat(input.amount),
        script_pubkey: input.script_pubkey.clone(),
    };
    let with_change = fee(n, &[&input.script_pubkey, &deposit], rate);
    // Change too small to pay its child and leave the refund address more
    // than dust goes to the fee.
    let least_change =
        input.refund_script.minimal_non_dust().to_sat() + fee(1, &[&input.refund_script], rate);
    let change = total
        .checked_sub(input.amount + with_change)
        .filter(|change| *change >= least_change);
    let mut outputs = vec![lock];
    if let Some(change) = change {
        outputs.push(TxOut {
            value: Amount::from_sat(change),
            script_pubkey: deposit,
        });
    } else if total < input.amount + fee(n, &[&input.script_pubkey], rate) {
        return Err(format!(
            "the deposit, {total} sat, cannot fund the lock at {rate} sat/vB"
        ));
    }
    let tx = signed(&input.wif, &input.utxos, outputs)?;
    let paid = total - tx.output.iter().map(|out| out.value.to_sat()).sum::<u64>();
    text(&json!({
        "tx": hex(&tx),
        "fee": paid,
        "change": change.map(|value| json!({"vout": 1, "value": value})),
    }))
}

/// The child that sends the funding's change to `refund_script`, paying
/// enough that it and the funding, which paid `funding_fee`, together pay
/// `fee_rate`: never less than its own share, and never so much that the
/// refund address gets dust. `{"wif", "funding", "funding_fee", "change",
/// "refund_script", "fee_rate"}` in, `change` as [`fund_lock`] gave it;
/// `{"tx", "fee"}` out.
#[wasm_bindgen(js_name = changeChild)]
pub fn change_child(input: &str) -> Result<String> {
    #[derive(Deserialize)]
    struct Change {
        vout: u32,
        value: u64,
    }
    #[derive(Deserialize)]
    struct Input {
        wif: String,
        #[serde(deserialize_with = "tx")]
        funding: Transaction,
        funding_fee: u64,
        change: Change,
        refund_script: ScriptBuf,
        fee_rate: u64,
    }
    let input: Input = parse(input)?;
    let rate = input.fee_rate;
    let child = vsize(1, &[&input.refund_script]);
    let own = child.saturating_mul(rate);
    let package = (input.funding.weight().to_vbytes_ceil() + child).saturating_mul(rate);
    let most = input
        .change
        .value
        .saturating_sub(input.refund_script.minimal_non_dust().to_sat());
    let paid = package.saturating_sub(input.funding_fee).max(own).min(most);
    let utxo = Utxo {
        txid: input.funding.compute_txid(),
        vout: input.change.vout,
        value: input.change.value,
    };
    let output = TxOut {
        value: Amount::from_sat(input.change.value - paid),
        script_pubkey: input.refund_script,
    };
    let tx = signed(&input.wif, &[utxo], vec![output])?;
    text(&json!({"tx": hex(&tx), "fee": paid}))
}

/// The deposit `utxos` back to `refund_script`, less the fee at
/// `fee_rate`. `{"wif", "utxos", "refund_script", "fee_rate"}` in,
/// `{"tx", "txid"}` out.
#[wasm_bindgen(js_name = refundDeposit)]
pub fn refund_deposit(input: &str) -> Result<String> {
    #[derive(Deserialize)]
    struct Input {
        wif: String,
        utxos: Vec<Utxo>,
        refund_script: ScriptBuf,
        fee_rate: u64,
    }
    let input: Input = parse(input)?;
    let total = total(&input.utxos);
    let fee = fee(input.utxos.len(), &[&input.refund_script], input.fee_rate);
    let back = total
        .checked_sub(fee)
        .filter(|back| *back >= input.refund_script.minimal_non_dust().to_sat())
        .ok_or_else(|| format!("the deposit, {total} sat, does not pay for its own refund"))?;
    let output = TxOut {
        value: Amount::from_sat(back),
        script_pubkey: input.refund_script,
    };
    let tx = signed(&input.wif, &input.utxos, vec![output])?;
    text(&json!({"tx": hex(&tx), "txid": tx.compute_txid()}))
}

fn tx<'de, D: serde::Deserializer<'de>>(
    deserializer: D,
) -> std::result::Result<Transaction, D::Error> {
    let hex = String::deserialize(deserializer)?;
    bitcoin::consensus::encode::deserialize_hex(&hex).map_err(serde::de::Error::custom)
}
