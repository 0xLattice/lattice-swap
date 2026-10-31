//! The rules a view of the chains is read by, apart from the reading: the
//! driver reads its nodes and applies them, and a browser that fetched the
//! same data itself applies the same ones.
//!
//! A Bitcoin view starts from the [`Tip`], aged by [`stale`]. What it looks
//! up are [`Lookups`]: the funding, then the first of each pair of spends
//! the node holds, and the cancel output's spender only when
//! [`Lookups::search_from`] says so. A Nexus view reads the health, the own
//! account, the lock account, then the watched transaction, and the health
//! again: it is one view only if [`one_tip`] holds for the two.

use bitcoin::{BlockHash, OutPoint, Txid};
use serde::{Deserialize, Serialize};
use swap_bitcoin::{Spend, Swap};
use swap_nexus_tx::rpc::Health;

use crate::Spent;

/// A node's tip, as `getblockchaininfo` reports it.
#[derive(Clone, Copy, Debug, Serialize, Deserialize)]
pub struct Tip {
    /// The height of the last block the node has.
    pub height: u32,
    /// The height of the best header chain it knows.
    pub headers: u32,
    /// The tip block's time, in seconds since the Unix epoch.
    pub time: u64,
    /// The tip block's hash.
    pub hash: BlockHash,
}

/// Why a view on `tip` is [`crate::BitcoinView::stale`], if it is: the
/// node lags the best header chain it knows, or its tip is more than
/// `max_tip_age` seconds old at `now`, since its block time or since
/// `first_seen`, when this machine first saw it, whichever is earlier. A
/// block time alone is the miner's to set, up to two hours ahead.
/// `first_seen` is updated to the tip. A node that stalled, or is fed by
/// someone who cut it off, would show the redeem window still open after it
/// closed.
pub fn stale(
    tip: &Tip,
    max_tip_age: u64,
    now: u64,
    first_seen: &mut Option<(BlockHash, u64)>,
) -> Option<String> {
    let seen = match *first_seen {
        Some((hash, at)) if hash == tip.hash => at,
        _ => first_seen.insert((tip.hash, now)).1,
    };
    let age = now.saturating_sub(tip.time.min(seen));
    if tip.headers > tip.height {
        Some(format!(
            "the node has blocks to {} of headers to {}: no redeem or NEX lock starts until it \
             catches up",
            tip.height, tip.headers
        ))
    } else if age > max_tip_age {
        Some(format!(
            "the node's tip, block {}, is {} minutes old: no redeem or NEX lock starts until it \
             has a fresh one, since a stalled or cut-off node hides the swap's deadlines",
            tip.height,
            age / 60
        ))
    } else {
        None
    }
}

/// What a Bitcoin view of a swap looks up. Only the swap's own
/// transactions can spend the lock output, and their txids are fixed
/// before any is signed, so each is looked up by txid. The same holds for
/// the cancel output but for punish: its leaf takes the seller's signature
/// alone, so the seller can spend through it with any transaction.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Lookups {
    /// The lock output: the funding is its transaction.
    pub lock: OutPoint,
    /// Redeem, then cancel: the first the node holds is
    /// [`crate::BitcoinView::lock_spend`].
    pub lock_spends: [Txid; 2],
    /// Refund, then punish: the first the node holds is
    /// [`crate::BitcoinView::cancel_spend`].
    pub cancel_spends: [Txid; 2],
    /// The cancel output, whose spender [`Lookups::search_from`] may ask
    /// for.
    pub cancel_output: OutPoint,
    /// Punish can be mined no earlier than `t2` blocks after cancel.
    pub t2: u16,
}

impl Lookups {
    pub fn new(swap: &Swap, lock: OutPoint) -> Self {
        let txid = |spend| swap.unsigned_tx(lock, spend).compute_txid();
        Self {
            lock,
            lock_spends: [txid(Spend::Redeem), txid(Spend::Cancel)],
            cancel_spends: [txid(Spend::Refund), txid(Spend::Punish)],
            cancel_output: OutPoint::new(txid(Spend::Cancel), 0),
            t2: swap.params().t2,
        }
    }

    /// The lowest block to search for the cancel output's spender in, at a
    /// tip of `height`, if it must be searched for: cancel is in a block,
    /// neither refund nor punish shows, and the output may still be spent.
    pub fn search_from(
        &self,
        height: u32,
        lock_spend: &Option<Spent>,
        cancel_spend: &Option<Spent>,
    ) -> Option<u32> {
        let Spent { tx, confirmations } = lock_spend.as_ref()?;
        if cancel_spend.is_some()
            || *confirmations == 0
            || tx.compute_txid() != self.cancel_output.txid
        {
            return None;
        }
        let mined = (height + 1).saturating_sub(*confirmations);
        Some(mined.saturating_add(self.t2.into()))
    }
}

/// Two reads of a Nexus node's health are at one tip: every read between
/// them comes from that tip's block. Only the operator port's `/health` is
/// never cached; a public read port's would let the reads straddle two
/// tips.
pub fn one_tip(before: &Health, after: &Health) -> bool {
    (after.height, &after.tip) == (before.height, &before.tip)
}
