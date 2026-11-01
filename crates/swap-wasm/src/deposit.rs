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
//! The swap's own refund pays the deposit key too, and a child of it sends
//! it on the same way: a refund stuck in the mempool, which must confirm
//! before the seller can punish, is bumped by CPFP like the funding, but at
//! a rate of its own, [`refund_rate`]. A refund a watchtower broadcast,
//! with the buyer away, waits at the deposit key until the buyer is back
//! to send it on.
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

/// The sources' `estimates`, in sat/vB, but those that are none or no rate.
fn known(estimates: Vec<Option<f64>>) -> impl Iterator<Item = f64> {
    estimates
        .into_iter()
        .flatten()
        .filter(|rate| rate.is_finite() && *rate >= 0.0)
}

/// `rate` in whole sat/vB, `fallback` if none, never below 1 sat/vB, the
/// default relay floor.
fn whole(rate: Option<f64>, fallback: u64) -> u64 {
    // An estimate is never near 2^64 sat/vB; `as` saturates if it were.
    rate.map_or(fallback, |rate| rate.ceil() as u64).max(1)
}

/// The rate, in whole sat/vB, a spend from the deposit key pays: the
/// lowest of the Bitcoin sources' `estimates`, in sat/vB, null where one
/// has none; `fallback` where none has one; never below 1 sat/vB, the
/// default relay floor. Then, unless this is the quote's own rate, never
/// above [`HEADROOM`] times `quote_rate`, the rate the quote was made at,
/// whose fees the deposit holds that many times over.
///
/// The lowest, since the rate is spent: one source that answers high would
/// otherwise spend the deposit on fees, and one that answers low only slows
/// the spend. The bound holds even when every source answers high, as one
/// alone does while the other is down. A rate risen past it leaves the
/// spend waiting rather than paying more than the deposit was asked to hold
/// for it. This is the rate of the funding, of its child and of a deposit
/// sent back: a slow one only delays. The swap's refund is not one of
/// them: see [`refund_rate`]. `{"estimates", "fallback", "quote_rate"}` in,
/// `quote_rate` absent or null for the quote; the rate out, as a JSON
/// number.
#[wasm_bindgen(js_name = feeRate)]
pub fn fee_rate(input: &str) -> Result<String> {
    #[derive(Deserialize)]
    struct Input {
        estimates: Vec<Option<f64>>,
        fallback: u64,
        #[serde(default)]
        quote_rate: Option<u64>,
    }
    let input: Input = parse(input)?;
    let rate = whole(known(input.estimates).reduce(f64::min), input.fallback);
    let cap = input
        .quote_rate
        .map_or(u64::MAX, |quote| quote.saturating_mul(HEADROOM));
    text(&rate.min(cap))
}

/// Fewer blocks than this left before the seller can punish, and the
/// refund's rate doubles at each block: an estimate aims at six blocks, as
/// the driver asks for one, and no longer answers for the time left. By
/// `punish_at` it has doubled this many times, 64-fold.
const URGENT: u32 = 6;

/// The rate, in whole sat/vB, the child of the swap's refund pays for the
/// two, at each bump, and the spend that sends on a refund a watchtower
/// broadcast.
///
/// - The base: the highest of the sources' `estimates`, `fallback` where
///   none has one, never below 1 sat/vB; but never above [`HEADROOM`]
///   times the higher of `quote_rate` and the lowest estimate.
/// - With fewer than [`URGENT`] blocks left before `punish_at`, at `tip`,
///   doubled at each block: 64-fold at `punish_at`. Past it, doubled on at
///   each block, bounded by nothing but what the refund holds, less dust,
///   which [`change_child`] keeps: a refund burnt to fees costs the buyer
///   no more than a punish.
///
/// `punish_at` and `tip` are of the view every source showed alike, never
/// one source's. So a source that answers high pays at most [`HEADROOM`]
/// times what the other, or the quote, asks for; one that answers low is
/// outbid by the escalation, block by agreed block; and no source alone
/// can hasten it, by a tip ahead or a cancel mined early. Not
/// [`fee_rate`]'s rule: a funding that is slow only delays the swap, but a
/// refund still unconfirmed at `punish_at` lets the seller punish and take
/// the BTC whole. `{"estimates", "fallback", "quote_rate", "punish_at",
/// "tip"}` in, the last two absent or null where unknown; the rate out, as
/// a JSON number.
#[wasm_bindgen(js_name = refundRate)]
pub fn refund_rate(input: &str) -> Result<String> {
    #[derive(Deserialize)]
    struct Input {
        estimates: Vec<Option<f64>>,
        fallback: u64,
        quote_rate: u64,
        #[serde(default)]
        punish_at: Option<u32>,
        #[serde(default)]
        tip: Option<u32>,
    }
    let input: Input = parse(input)?;
    let known: Vec<f64> = known(input.estimates).collect();
    let highest = whole(known.iter().copied().reduce(f64::max), input.fallback);
    let lowest = whole(known.iter().copied().reduce(f64::min), input.fallback);
    let base = highest.min(input.quote_rate.max(lowest).saturating_mul(HEADROOM));
    let doublings = match (input.punish_at, input.tip) {
        (Some(punish_at), Some(tip)) => tip.saturating_add(URGENT).saturating_sub(punish_at),
        _ => 0,
    };
    text(&base.saturating_mul(1u64.checked_shl(doublings).unwrap_or(u64::MAX)))
}

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
/// `{"tx", "fee"}` out.
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
    text(&json!({"tx": hex(&tx), "fee": paid}))
}

/// The child that sends what `parent` pays the deposit key on to
/// `refund_script`, paying enough that it and `parent`, which paid
/// `parent_fee`, together pay `fee_rate`: never less than its own share, and
/// never so much that the refund address gets dust. `parent` is the funding,
/// whose change it returns, or the swap's refund, which pays the deposit key
/// so that a refund stuck in the mempool can be bumped. `{"wif", "parent",
/// "parent_fee", "refund_script", "fee_rate"}` in; `{"tx", "txid", "fee"}`
/// out, or null if `parent` pays the deposit key nothing.
#[wasm_bindgen(js_name = changeChild)]
pub fn change_child(input: &str) -> Result<Option<String>> {
    #[derive(Deserialize)]
    struct Input {
        wif: String,
        #[serde(deserialize_with = "tx")]
        parent: Transaction,
        parent_fee: u64,
        refund_script: ScriptBuf,
        fee_rate: u64,
    }
    let input: Input = parse(input)?;
    let (_, _, deposit) = key(&input.wif)?;
    let Some((vout, change)) = (input.parent.output.iter().enumerate())
        .find(|(_, out)| out.script_pubkey == deposit)
        .map(|(vout, out)| (vout as u32, out.value.to_sat()))
    else {
        return Ok(None);
    };
    let rate = input.fee_rate;
    let child = vsize(1, &[&input.refund_script]);
    let own = child.saturating_mul(rate);
    let package = (input.parent.weight().to_vbytes_ceil() + child).saturating_mul(rate);
    let most = change.saturating_sub(input.refund_script.minimal_non_dust().to_sat());
    let paid = package.saturating_sub(input.parent_fee).max(own).min(most);
    let utxo = Utxo {
        txid: input.parent.compute_txid(),
        vout,
        value: change,
    };
    let output = TxOut {
        value: Amount::from_sat(change - paid),
        script_pubkey: input.refund_script,
    };
    let tx = signed(&input.wif, &[utxo], vec![output])?;
    text(&json!({"tx": hex(&tx), "txid": tx.compute_txid(), "fee": paid})).map(Some)
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
