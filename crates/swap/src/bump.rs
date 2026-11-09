//! Bumping a swap transaction that pays this party by CPFP, with no I/O:
//! which transactions wait, when each is due, the feerate it is raised to,
//! and the child that raises it. The native driver ([`crate::driver`]) and
//! its Esplora ([`crate::esplora`]) bump by these, and so does the
//! browser's driver, web/driver, through swap-wasm: each reads its own
//! backend and submits the package.

use bitcoin::{Amount, FeeRate, OutPoint, Transaction};
use serde::{Deserialize, Serialize};
use swap_bitcoin::{Spend, Swap};

use crate::wallet::{self, Key};
use crate::BitcoinView;

/// Bitcoin Core's default relay floor, and incremental relay feerate.
pub const MIN_RELAY: FeeRate = FeeRate::from_sat_per_vb_u32(1);

/// The most a bump pays for by default: a higher target is clamped to it.
pub const MAX_FEE_RATE: FeeRate = FeeRate::from_sat_per_vb_u32(1_000);

/// The share of a spend's payout its child may pay in fees by default: all
/// of it but dust.
pub const MAX_FEE_FRACTION: f64 = 1.0;

/// How many times a failed bump near its deadline is tried again within one
/// block, a poll apart.
pub const URGENT_RETRIES: u8 = 8;

/// A swap transaction of ours waiting unconfirmed.
#[derive(Clone, Copy, Debug, Serialize, Deserialize)]
pub struct Waiting {
    /// The tip when its target was last read.
    pub height: u32,
    /// Whether the mempool refused it at the last view.
    pub refused: bool,
    /// What the last bump that went through raised it to.
    pub rate: FeeRate,
    /// Whether the last attempt to bump it failed: it is tried again.
    pub failed: bool,
    /// Attempts since the first at `height`.
    pub retries: u8,
    /// The last target clamped to the most a bump pays for, already logged.
    pub clamped: Option<FeeRate>,
}

/// What a round does with one waiting transaction.
#[derive(Clone, Copy, Debug)]
pub struct Round {
    /// What it is kept as: once due, the caller sets `rate` and `failed`
    /// from how the bump went.
    pub now: Waiting,
    /// Whether its target is read and, if above the last bump's, it is
    /// bumped.
    pub due: bool,
    /// Whether a failure or a clamp is logged again, though logged before:
    /// near its deadline, at every block.
    pub again: bool,
}

/// The round for a transaction waiting at `height`, last kept as `last`,
/// `refused` by the mempool, near its deadline if `urgent`. A failure is
/// tried again at the next block, or, a few times, at the next poll once a
/// deadline is near: a block may be all that is left.
pub fn schedule(last: Option<Waiting>, height: u32, refused: bool, urgent: bool) -> Round {
    let again = urgent && last.is_none_or(|last| height > last.height);
    let due = last.is_none_or(|last| {
        height > last.height
            || refused && !last.refused
            || last.failed && urgent && last.retries < URGENT_RETRIES
    });
    let mut now = last.unwrap_or(Waiting {
        height,
        refused,
        rate: FeeRate::ZERO,
        failed: false,
        retries: 0,
        clamped: None,
    });
    now.refused = refused;
    if due {
        now.retries = match last {
            Some(last) if last.height == height => last.retries.saturating_add(1),
            _ => 0,
        };
        now.height = height;
    }
    Round { now, due, again }
}

/// The feerate to raise `tx`, of `vsize` vbytes, which pays `fee`, to:
/// `estimate`, else
/// `fallback`, at least `floor` if the mempool refused it, clamped to
/// `max`; `None` if it was not refused and already pays it alone. A
/// refused `tx` needs a package whatever it pays. A clamp is logged once
/// per target, the last kept in `clamped`, and `again`: the warning, if
/// any, comes back.
#[allow(clippy::too_many_arguments)]
pub fn target(
    tx: &Transaction,
    vsize: u64,
    fee: Amount,
    estimate: Option<FeeRate>,
    fallback: FeeRate,
    floor: Option<FeeRate>,
    max: FeeRate,
    again: bool,
    clamped: &mut Option<FeeRate>,
) -> (Option<FeeRate>, Option<String>) {
    let mut rate = estimate.unwrap_or(fallback);
    if let Some(floor) = floor {
        rate = rate.max(floor);
    }
    let mut warning = None;
    if rate > max {
        if *clamped != Some(rate) || again {
            warning = Some(format!(
                "bump {}: target {rate} clamped to max_fee_rate {max}",
                tx.compute_txid(),
            ));
        }
        *clamped = Some(rate);
        rate = max;
    }
    let alone = rate.fee_vb(vsize);
    let target = (floor.is_some() || alone.is_some_and(|alone| alone > fee)).then_some(rate);
    (target, warning)
}

/// The most the child bumping `tx` pays: `fraction` of its payout.
pub fn max_fee(tx: &Transaction, fraction: f64) -> Amount {
    Amount::from_sat((tx.output[0].value.to_sat() as f64 * fraction) as u64)
}

/// Our spends within `margin` blocks of their deadline: redeem once the
/// lock is `t1 - margin` deep, refund once cancel is `t2 - margin` deep.
pub fn urgent(swap: &Swap, lock: OutPoint, view: &BitcoinView, margin: u16) -> Vec<Spend> {
    let near = |depth: Option<u32>, deadline: u16| {
        depth.is_some_and(|depth| depth.saturating_add(margin.into()) >= u32::from(deadline))
    };
    let cancel = swap.unsigned_tx(lock, Spend::Cancel).compute_txid();
    let cancel_depth = view
        .lock_spend
        .as_ref()
        .filter(|spent| spent.tx.compute_txid() == cancel && spent.confirmations > 0)
        .map(|spent| spent.confirmations);
    let p = swap.params();
    [
        (Spend::Redeem, near(view.funding, p.t1)),
        (Spend::Refund, near(cancel_depth, p.t2)),
    ]
    .into_iter()
    .filter_map(|(spend, near)| near.then_some(spend))
    .collect()
}

/// The least a child of `own` vbytes pays to replace one of `last_size`
/// that paid `base`: Core takes a replacement that pays the old fee and its
/// own relay at the incremental rate, at a feerate above the old one.
pub fn replacing(base: Amount, last_size: u64, own: u64, incremental: FeeRate) -> Option<Amount> {
    let more = base.checked_add(incremental.fee_vb(own)?)?;
    let above = (1000 * base.to_sat() / last_size.max(1) + 1).div_ceil(4);
    Some(more.max(FeeRate::from_sat_per_kwu(above).fee_vb(own)?))
}

/// A feerate of `rate` sat/vB, as an Esplora's `/fee-estimates` gives one,
/// rounded up to a whole sat/kwu.
pub fn per_vb(rate: f64) -> FeeRate {
    FeeRate::from_sat_per_kwu((rate * 250.0).ceil() as u64)
}

/// `fee` over `vsize`, rounded up.
fn over(fee: u64, vsize: u64) -> FeeRate {
    FeeRate::from_sat_per_kwu((fee * 250).div_ceil(vsize.max(1)))
}

/// An Esplora's floor for `parent`, of `vsize` vbytes, which the mempool
/// refused while
/// `other`, `(fee, vsize)`, unconfirmed, spends its input, worth `paid`:
/// enough for `parent` and a child of `package_vsize` vbytes in all to
/// replace it, above `parent`'s own feerate. An Esplora shows no
/// descendants, so only the conflict's own fee counts.
pub fn floor(
    parent: &Transaction,
    vsize: u64,
    paid: u64,
    other: (u64, u64),
    package_vsize: u64,
) -> Result<FeeRate, String> {
    let (other_fee, other_vsize) = other;
    let fee = (parent.output.iter())
        .try_fold(paid, |left, out| left.checked_sub(out.value.to_sat()))
        .ok_or("the parent pays out more than its input")?;
    let beat = over(other_fee, other_vsize)
        .max(over(other_fee, package_vsize))
        .max(over(fee, vsize));
    let above = beat.to_sat_per_kwu() + MIN_RELAY.to_sat_per_kwu();
    Ok(MIN_RELAY.max(FeeRate::from_sat_per_kwu(above)))
}

/// The feerate of a parent paying `fee` over `vsize` with `child`, `(fee,
/// vsize)`, the unconfirmed one spending its payout, if any: rounded down,
/// as it is compared with a target the package must meet.
pub fn package_rate(fee: u64, vsize: u64, child: Option<(u64, u64)>) -> FeeRate {
    let (fee, size) = match child {
        Some((child_fee, child_vsize)) => (fee + child_fee, vsize + child_vsize),
        None => (fee, vsize),
    };
    FeeRate::from_sat_per_kwu(fee * 250 / size.max(1))
}

/// The child that raises `parent`, of `vsize` vbytes, which pays `paid`,
/// to `rate`, spending its payout to `key` and paying at most `max`:
/// signed by `key`, which only a payout to it can be. `last`, `(fee,
/// vsize)`, is the unconfirmed child spending the payout already, which
/// this one must pay enough to replace, up to [`MAX_FEE_RATE`] over the
/// package: what a node shows of `last` is not ours to vouch for.
pub fn child(
    key: &Key,
    parent: &Transaction,
    vsize: u64,
    paid: Amount,
    rate: FeeRate,
    max: Amount,
    last: Option<(u64, u64)>,
) -> Result<Transaction, String> {
    let size = package_vsize(key, parent, vsize)?;
    let package = |rate: FeeRate| {
        rate.fee_vb(size + 1)
            .and_then(|package| package.checked_sub(paid))
    };
    let mut fee = package(rate).ok_or_else(|| format!("feerate {rate}"))?;
    if let Some((last_fee, last_vsize)) = last {
        let own = size - vsize + 1;
        let replace = replacing(Amount::from_sat(last_fee), last_vsize, own, MIN_RELAY)
            .ok_or_else(|| format!("the last child's fee {last_fee}"))?;
        let cap = package(MAX_FEE_RATE).unwrap_or(Amount::ZERO);
        fee = fee.max(replace.min(cap));
    }
    let change = key.script_pubkey.clone();
    let spendable = parent.output[0]
        .value
        .checked_sub(change.minimal_non_dust())
        .ok_or("the payout is dust")?;
    let fee = fee.min(max).min(spendable);
    let child = swap_bitcoin::cpfp(parent, change, fee).expect("change above dust");
    sign_child(key, parent, child)
}

/// `child`, spending `parent`'s payout, signed by `key`; only a payout to
/// it can be bumped.
fn sign_child(key: &Key, parent: &Transaction, child: Transaction) -> Result<Transaction, String> {
    let payout = &parent.output[0];
    if payout.script_pubkey != key.script_pubkey {
        return Err(format!(
            "the payout of {} is not this wallet's",
            parent.compute_txid()
        ));
    }
    wallet::sign(&key.wif, child, &[payout.value.to_sat()])
}

/// `parent`, of `vsize` vbytes, and a child signed by `key` spending its
/// payout, in vbytes.
pub fn package_vsize(key: &Key, parent: &Transaction, vsize: u64) -> Result<u64, String> {
    let change = key.script_pubkey.clone();
    let child = swap_bitcoin::cpfp(parent, change, Amount::ZERO).ok_or("the payout is dust")?;
    Ok(vsize + sign_child(key, parent, child)?.vsize() as u64)
}
