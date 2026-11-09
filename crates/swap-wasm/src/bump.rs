//! The buyer's refund bumped by CPFP, as the native driver bumps it:
//! [`swap::bump`], with JSON in and out. The page reads its Esplora as the
//! native [`swap::esplora`] reads one, and submits the package to its
//! `POST /txs/package`; nothing here does I/O. Feerates cross as sat/kwu.
//!
//! Each round after the Bitcoin view, [`buyer_bumps`] says which of the
//! waiting transactions are the buyer's own and due; for each due one the
//! page reads the estimate, and the floor ([`bump_floor`]) for one the
//! mempool refused, for [`bump_target`]; once that is above the last
//! bump's, it reads what the package pays ([`package_rate`]) and, if less,
//! submits the parent with [`bump_child`]. As the native app's driver: the
//! estimate for 1 block near the refund's deadline, else 2, else the relay
//! floor, clamped to [`swap::bump::MAX_FEE_RATE`], the child paying at most
//! [`swap::bump::MAX_FEE_FRACTION`] of the refund.

use std::collections::HashMap;

use bitcoin::consensus::encode::{deserialize_hex, serialize_hex};
use bitcoin::{Amount, FeeRate, Transaction, Txid};
use serde::Deserialize;
use serde_json::json;
use swap::bump::{self, Waiting, MAX_FEE_FRACTION, MAX_FEE_RATE, MIN_RELAY};
use swap::wallet::Key;
use swap::{BitcoinView, Buyer, Machine};
use wasm_bindgen::prelude::*;

use crate::{parse, text, Result};

/// A transaction as an Esplora's `/tx/:txid` shows it: its fee and weight.
#[derive(Clone, Copy, Deserialize)]
struct Shown {
    fee: u64,
    weight: u64,
}

impl Shown {
    fn paid(self) -> (u64, u64) {
        (self.fee, self.weight.div_ceil(4))
    }
}

fn tx(hex: &str) -> Result<Transaction> {
    deserialize_hex(hex.trim()).map_err(|e| e.to_string())
}

/// What a round does with each of the buyer's own transactions waiting
/// unconfirmed, as the native driver's bump: `{"state", "view", "waiting",
/// "last"}` in, `view` the Bitcoin view the round fed the machine,
/// `waiting` `[hex, refused]` pairs, the view's unconfirmed spends and what
/// the machine broadcast since the last view, `refused` if the mempool
/// refused it, and `last` what the last round kept, by txid. Out, for each
/// of the buyer's own: `{"txid", "tx", "input", "fee", "refused",
/// "urgent", "again", "due", "now"}`, `input` the outpoint it spends, `fee`
/// in sat what it pays, `now` what to keep for it, once due with `rate` and
/// `failed` set from how its bump went. Those left out are forgotten.
#[wasm_bindgen(js_name = buyerBumps)]
pub fn buyer_bumps(input: &str) -> Result<String> {
    #[derive(Deserialize)]
    struct Input {
        state: Buyer,
        view: BitcoinView,
        waiting: Vec<(String, bool)>,
        #[serde(default)]
        last: HashMap<Txid, Waiting>,
    }
    let input: Input = parse(input)?;
    let watch = input.state.watch();
    let Some((swap, lock)) = watch.bitcoin else {
        return text(&json!([]));
    };
    let urgent = bump::urgent(&swap, lock, &input.view, watch.margin);
    let own: Vec<_> = (input.state.own_spends().iter())
        .map(|&spend| (swap.unsigned_tx(lock, spend).compute_txid(), spend))
        .collect();
    let mut rounds = vec![];
    let mut seen = vec![];
    for (hex, refused) in input.waiting {
        let parent = tx(&hex)?;
        let txid = parent.compute_txid();
        let Some(&(_, spend)) = own.iter().find(|(own, _)| *own == txid) else {
            continue;
        };
        if seen.contains(&txid) {
            continue;
        }
        seen.push(txid);
        let urgent = urgent.contains(&spend);
        let round = bump::schedule(
            input.last.get(&txid).copied(),
            input.view.height,
            refused,
            urgent,
        );
        rounds.push(json!({
            "txid": txid,
            "tx": hex.trim(),
            "input": parent.input[0].previous_output.to_string(),
            "fee": swap.fee(spend).to_sat(),
            "refused": refused,
            "urgent": urgent,
            "again": round.again,
            "due": round.due,
            "now": round.now,
        }));
    }
    text(&rounds)
}

/// The feerate to raise a waiting transaction to, as the native driver's
/// target: `{"tx", "fee", "estimate", "floor", "again", "clamped"}` in,
/// `estimate` the Esplora's in sat/vB for 1 block if urgent, else 2, or
/// null, `floor` from [`bump_floor`] if the mempool refused it, else null,
/// and `clamped` the `now`'s. `{"target", "clamped", "warning"}` out:
/// `target` null if it pays it alone, `clamped` to keep, and the clamp to
/// warn of, if any.
#[wasm_bindgen(js_name = bumpTarget)]
pub fn bump_target(input: &str) -> Result<String> {
    #[derive(Deserialize)]
    struct Input {
        tx: String,
        fee: u64,
        estimate: Option<f64>,
        floor: Option<FeeRate>,
        again: bool,
        clamped: Option<FeeRate>,
    }
    let mut input: Input = parse(input)?;
    // The relay floor where there is no estimate: the native app's
    // `fallback_fee_rate`, as it funds and prices its own spends.
    let (target, warning) = bump::target(
        &tx(&input.tx)?,
        Amount::from_sat(input.fee),
        input.estimate.map(bump::per_vb),
        MIN_RELAY,
        input.floor,
        MAX_FEE_RATE,
        input.again,
        &mut input.clamped,
    );
    text(&json!({"target": target, "clamped": input.clamped, "warning": warning}))
}

/// The floor a transaction the mempool refused is raised to, as the native
/// Esplora's: `{"wif", "network", "tx", "other", "spent"}` in, `other` the
/// unconfirmed transaction spending its input, as `/tx/:txid` shows it, or
/// null where there is none but itself, and `spent` the hex of the
/// transaction whose output it spends. The relay floor without `other`.
#[wasm_bindgen(js_name = bumpFloor)]
pub fn bump_floor(input: &str) -> Result<String> {
    #[derive(Deserialize)]
    struct Input {
        wif: String,
        network: String,
        tx: String,
        other: Option<Shown>,
        spent: Option<String>,
    }
    let input: Input = parse(input)?;
    let Some(other) = input.other else {
        return text(&MIN_RELAY);
    };
    let parent = tx(&input.tx)?;
    let outpoint = parent.input[0].previous_output;
    let spent = tx(input
        .spent
        .as_deref()
        .ok_or("the spent transaction is missing")?)?;
    if spent.compute_txid() != outpoint.txid {
        return Err(format!("the spent transaction is not {}", outpoint.txid));
    }
    let paid = (spent.output.get(outpoint.vout as usize))
        .ok_or_else(|| format!("no output {outpoint}"))?
        .value
        .to_sat();
    let key = Key::of(&input.wif, &input.network)?;
    let package = bump::package_vsize(&key, &parent)?;
    text(&bump::floor(&parent, paid, other.paid(), package)?)
}

/// What a transaction pays with the unconfirmed child spending its payout,
/// as the native Esplora's package rate: `{"parent", "child"}` in, each as
/// `/tx/:txid` shows it, `child` null if there is none.
#[wasm_bindgen(js_name = packageRate)]
pub fn package_rate(input: &str) -> Result<String> {
    #[derive(Deserialize)]
    struct Input {
        parent: Shown,
        child: Option<Shown>,
    }
    let input: Input = parse(input)?;
    let (fee, vsize) = input.parent.paid();
    text(&bump::package_rate(
        fee,
        vsize,
        input.child.map(Shown::paid),
    ))
}

/// The signed child that raises a transaction paying the wallet to `rate`,
/// as the native Esplora's bump: `{"wif", "network", "tx", "fee", "rate",
/// "last"}` in, `fee` what it pays, in sat, and `last` the unconfirmed
/// child spending its payout already, as `/tx/:txid` shows it, or null. The
/// child's hex out, to submit after the parent to `POST /txs/package`.
#[wasm_bindgen(js_name = bumpChild)]
pub fn bump_child(input: &str) -> Result<String> {
    #[derive(Deserialize)]
    struct Input {
        wif: String,
        network: String,
        tx: String,
        fee: u64,
        rate: FeeRate,
        last: Option<Shown>,
    }
    let input: Input = parse(input)?;
    let key = Key::of(&input.wif, &input.network)?;
    let parent = tx(&input.tx)?;
    let max = bump::max_fee(&parent, MAX_FEE_FRACTION);
    let fee = Amount::from_sat(input.fee);
    let last = input.last.map(Shown::paid);
    let child = bump::child(&key, &parent, fee, input.rate, max, last)?;
    Ok(serialize_hex(&child))
}
