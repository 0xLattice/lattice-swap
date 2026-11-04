//! Where a buyer's swap is, for a page or an app to show.

use serde_json::{json, Value};

use crate::view::Lookups;
use crate::{BitcoinView, Buyer, Machine, Outcome, Spent};

/// Where a buyer's swap is, given its state and the last Bitcoin `view`,
/// if any: `{"phase", "awaits_message", "must_stay_open", "confirmations",
/// "deadlines", "backup_covers", "terms"}`.
///
/// - `phase` is `swapping` until the redeem is signed, `finishing` from
///   then, `refunding` once it cancels, then the outcome: `swapped`,
///   `refunded`, `punished`, `drained` or `aborted`. A punished buyer
///   asking the seller for `s`, or claiming with it, is `finishing`.
/// - `must_stay_open` is [`Buyer::must_stay_open`].
/// - `confirmations`: `{"funding", "lock_spend", "cancel_spend"}` as the
///   view shows them, each null where it shows none.
/// - `deadlines`: `{"cancel", "refund", "punish"}`, each the first Bitcoin
///   block that can hold it, once the lock is in a block. Cancel is valid
///   `t1` blocks after the lock, punish `t2` after cancel; the refund goes
///   out once cancel is `btc_confirmations` deep. Until cancel is in a block, `refund` and `punish` are
///   the earliest they could be. The refund must be in a block before
///   `punish`.
/// - `backup_covers`: `lock` once the state is one the funding may have
///   been broadcast from, whose backup can cancel and refund the lock; else
///   `wallet`, a backup that holds the wallet key and no more than it.
/// - `terms`: the swap's [`crate::Terms`] as the state holds them, until it
///   ends; null once it has.
pub fn buyer_status(buyer: &Buyer, view: Option<&BitcoinView>) -> Value {
    let phase = match buyer {
        Buyer::AwaitRedeem { .. } | Buyer::ClaimingNex(_) | Buyer::AskingShare { .. } => {
            "finishing"
        }
        Buyer::Cancelling { .. } => "refunding",
        Buyer::Done(outcome) => self::outcome(outcome),
        Buyer::Punished { .. } => "punished",
        _ => "swapping",
    };
    let (mut cancel, mut refund, mut punish) = (None, None, None);
    if let (Some((swap, lock)), Some(view), Some(terms)) =
        (buyer.watch().bitcoin, view, buyer.terms())
    {
        // `depth` deep at `view.height`: in block `height + 1 - depth`.
        let mined = |depth: u32| (depth > 0).then(|| view.height + 1 - depth);
        if let Some(lock_height) = view.funding.and_then(mined) {
            let at = lock_height + u32::from(terms.t1);
            cancel = Some(at);
            punish = Some(at + u32::from(terms.t2));
        }
        let cancel_txid = Lookups::new(&swap, lock).lock_spends[1];
        let cancelled = (view.lock_spend.as_ref())
            .filter(|spent| spent.tx.compute_txid() == cancel_txid)
            .and_then(|spent| mined(spent.confirmations));
        if let Some(cancel_height) = cancelled {
            punish = Some(cancel_height + u32::from(terms.t2));
        }
        // The buyer refunds once cancel is `btc_confirmations` deep: into
        // the next block.
        refund = cancelled
            .or(cancel)
            .map(|cancel| cancel + terms.btc_confirmations);
    }
    let backup_covers = match buyer {
        Buyer::AwaitNexLock { .. }
        | Buyer::AwaitRedeem { .. }
        | Buyer::Cancelling { .. }
        | Buyer::ClaimingNex(_) => "lock",
        _ => "wallet",
    };
    let depth = |spent: &Option<Spent>| spent.as_ref().map(|spent| spent.confirmations);
    json!({
        "phase": phase,
        "awaits_message": buyer.awaits_message(),
        "must_stay_open": buyer.must_stay_open(),
        "confirmations": {
            "funding": view.and_then(|view| view.funding),
            "lock_spend": view.and_then(|view| depth(&view.lock_spend)),
            "cancel_spend": view.and_then(|view| depth(&view.cancel_spend)),
        },
        "deadlines": {"cancel": cancel, "refund": refund, "punish": punish},
        "backup_covers": backup_covers,
        "terms": buyer.terms(),
    })
}

/// An outcome's name, as `buyer_status` gives it.
fn outcome(outcome: &Outcome) -> &'static str {
    match outcome {
        Outcome::Swapped => "swapped",
        Outcome::Refunded => "refunded",
        Outcome::Punished => "punished",
        Outcome::Drained => "drained",
        Outcome::Aborted(_) => "aborted",
    }
}
