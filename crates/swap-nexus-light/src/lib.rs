//! A Nexus light client for the swap buyer: it checks a NEX lock against
//! Nexus proof of work, so the browser need not trust the read node that
//! serves the bytes.
//!
//! Sans-IO. The caller fetches `GET /volumes/<cid>` archives from any node
//! and passes the bytes in; nothing here does I/O, and it builds for
//! `wasm32-unknown-unknown`.
//!
//! # Security model
//!
//! A read node can lie in two ways: show a chain that is not Nexus, or show
//! state that the chain does not commit to. [`verify_chain`] binds every
//! header to its CID, checks its proof of work, its spec and its difficulty
//! schedule, links it to its parent, and checks the run against the
//! buyer's clock; [`prove_account`] binds every state node from a verified
//! `postState` down to the account's entries. What is left is the cost of a
//! fake chain, and when it has to be paid.
//!
//! ## What a forged run must satisfy
//!
//! - **The floor.** Every header from the lock block up to the tip meets
//!   the caller's work floor (`target <= floor`), so `N` blocks above the
//!   lock cost at least `N` times the floor's work, whoever mines them. The
//!   buyer picks `N` and the floor from what the BTC at stake is worth;
//!   [`DEFAULT_WORK_FLOOR`] is the default.
//! - **The schedule.** Every header carries the pinned spec
//!   ([`MAINNET_SPEC`]), and its `nextTarget` is exactly Lattice's ASERT
//!   target at its own height and timestamp, from the pinned anchor (block
//!   1: [`MAINNET_ANCHOR_HEIGHT`], [`MAINNET_ANCHOR_TIMESTAMP`],
//!   [`MAINNET_ANCHOR_TARGET`]; and the spec's [`MAINNET_TARGET_BLOCK_TIME`]
//!   and [`MAINNET_HALF_LIFE`]), as `validateNextTarget` requires. Each
//!   header's target is no easier than its parent's `nextTarget`. So a
//!   header's difficulty is not the forger's choice: it is what the schedule
//!   says for that height at that time.
//! - **The clock.** Every timestamp is at most [`MAX_FUTURE_MS`] (2 h) past
//!   the buyer's clock, and the tip's is at most [`MAX_TIP_AGE_MS`] (6 h)
//!   before it. A run cannot be dated into the past, where the schedule
//!   says nothing about now, and one shown once is refused six hours after
//!   its tip: it cannot be mined at leisure and replayed, it is good for one
//!   window.
//!
//! Together: at the height the real chain has reached, the schedule at
//! this moment asks a forger for exactly the work it asks of Nexus's own
//! miners for their next block, in the same hours, which is the cost of
//! attacking Nexus itself. And it is a race: the lock pays the joint key
//! `(s + b)·G`, where `b` is the buyer's key for this swap, so no block
//! above a forged lock can be mined before the swap begins, and all `N`
//! must be mined before the buyer's deadline.
//!
//! ## The floor still binds
//!
//! The run starts at the lock, not at block 1, so its heights are what the
//! headers claim. A height lower than the real one is behind schedule, and
//! the schedule eases it by a doubling per half-life (120 blocks): a fake
//! low height buys an easier target. The floor is what stops that: however
//! easy the schedule makes a height, the header's target must still meet
//! the floor, so a run claiming a height low enough for the schedule to
//! ease it past the floor is refused.
//!
//! So a forger pays, per block, the harder of the floor and the schedule
//! at the height it claims, and claims the height where the two meet. That
//! leaves the floor as the bound on cost, and the schedule as the bound on
//! timing. On 2026-11-01 the live tip, height 5990, was at about 2^44.2
//! hashes a block; at that moment the schedule met [`DEFAULT_WORK_FLOOR`]
//! (2^42) at height 5724. A forger claiming heights from about 5724 paid
//! the floor, a 4.7-fold discount on the real difficulty and no more.
//!
//! ## What is still open
//!
//! - **The height is not pinned.** That discount, real difficulty over the
//!   floor, is the remaining gap. Closing it needs a height the buyer can
//!   trust, such as a checkpoint and every header from it, or the height
//!   the buyer saw when the swap began; nothing here holds one. A buyer who
//!   wants more margin raises the floor toward the real difficulty, at the
//!   cost of stalling sooner if hashrate falls.
//! - **Timestamps in the allowed future.** A forger may stamp its blocks up
//!   to 2 h ahead of the buyer's clock: that is behind schedule by up to 2
//!   h, which eases a block by at most `2^(2 / 120)`, about 1.2%, and lets
//!   a run be shown up to 2 h before its tip's time. Honest nodes never
//!   serve a block from their own future (`timestamp <= now`), so the slack
//!   is only for the buyer's clock.
//! - **When the work was done.** The clock checks timestamps, not when the
//!   hashes were computed: a run stamped for a window can be mined at any
//!   time before it. What stops mining long in advance is the swap's own
//!   key, above; what stops reuse is the 6 h expiry.
//! - **The tip's age.** A tip may be 6 h old. An older timestamp is ahead
//!   of schedule, so harder at a given height, not easier; what the 6 h
//!   gives a forger is time: a run stays usable for up to 8 h (2 h early,
//!   6 h late) around its tip's timestamp.
//! - **The buyer's clock.** If it runs more than 2 h slow or 6 h fast,
//!   honest tips are refused: liveness, not funds.
//!
//! If Nexus hashrate falls below the floor, honest blocks stop meeting it,
//! no lock reaches depth, and the swap times out and refunds. That costs
//! liveness, never funds. Nor is anything checked that only an honest
//! node's view could check (that the chain shown is the heaviest one): a
//! node can withhold, which the swap's timeouts cover, but it cannot forge
//! without paying the floor per block, in the window it shows.
//!
//! [`ChainParams`] carries the spec and the schedule, with mainnet as its
//! default, so a testnet or regtest chain can be verified with its own.

mod cbor;
mod chain;
mod schedule;
mod state;

use sha2::{Digest, Sha256};

pub use chain::{verify_chain, VerifiedBlock, VerifiedChain};
pub use schedule::{
    ChainParams, MAINNET_ANCHOR_HEIGHT, MAINNET_ANCHOR_TARGET, MAINNET_ANCHOR_TIMESTAMP,
    MAINNET_HALF_LIFE, MAINNET_SPEC, MAINNET_TARGET_BLOCK_TIME,
};
pub use state::{prove_account, Account};

/// A 256-bit unsigned integer, big-endian. Byte arrays compare
/// lexicographically, which for equal widths is numeric order.
pub type U256 = [u8; 32];

/// The default per-block work floor, as a target: `2^214 - 1`, so every
/// block meeting it took `2^42` hashes on average.
///
/// The user's choice is a quarter of mainnet's difficulty on 2026-11-01:
/// blocks 5955..=5986 carried targets from `0x1077df…` (2^43.96 hashes) to
/// `0xe180ff…` (2^44.18 hashes), so a quarter is about 2^42.2 hashes. The
/// floor rounds that down to 2^42, a little easier, which leaves honest
/// blocks room above it.
pub const DEFAULT_WORK_FLOOR: U256 = {
    let mut floor = [0xff; 32];
    floor[0] = 0;
    floor[1] = 0;
    floor[2] = 0;
    floor[3] = 0;
    floor[4] = 0;
    floor[5] = 0x3f;
    floor
};

/// How far past the caller's clock a header may be stamped: two hours.
///
/// Lattice has no protocol drift constant: a node defers a block stamped
/// after its own clock (`ValidationContext.permits`, `timestamp <= now`)
/// until real time reaches it. So an honest node serves no block from its
/// future, and this slack is only for the buyer's clock running slow; two
/// hours is Bitcoin's future-time limit, and generous for a browser. It
/// buys a forger little: a timestamp two hours later eases the schedule by
/// `2^(2 / 120)`, about 1.2%.
pub const MAX_FUTURE_MS: i64 = 2 * 60 * 60 * 1000;

/// How long before the caller's clock the tip may be stamped: six hours,
/// six target block times.
///
/// Block gaps are about exponential, so an honest tip on schedule is older
/// than this about `e^-6` (0.25%) of the time, and a buyer refused for it
/// waits for the next block or retries. Without it a forger stamps a whole
/// chain in the past, where the schedule has nothing to say about now.
pub const MAX_TIP_AGE_MS: i64 = 6 * 60 * 60 * 1000;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Error {
    /// Bytes that do not hash to the CID they were given under.
    CidMismatch { cid: String },
    /// Bytes that are not the node they should be.
    Malformed(&'static str),
    /// A header whose hash misses its target.
    InsufficientWork { cid: String },
    /// A header easier than the caller's work floor.
    BelowFloor { cid: String },
    /// A header under a spec other than the pinned one.
    WrongSpec { cid: String },
    /// A header whose `nextTarget` is not the difficulty schedule's at its
    /// height and timestamp, or that sits below the schedule's anchor.
    OffSchedule { cid: String },
    /// A header stamped later than [`MAX_FUTURE_MS`] past the caller's clock.
    FutureTimestamp { cid: String },
    /// A tip stamped earlier than [`MAX_TIP_AGE_MS`] before the caller's
    /// clock.
    StaleTip { cid: String },
    /// A header that does not follow the next one as its parent.
    BrokenLink { cid: String, reason: &'static str },
    /// A node the walk needs that was not given. Never read as
    /// absence: absence is only what the bound trie shows.
    Missing { cid: String },
}

impl core::fmt::Display for Error {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Error::CidMismatch { cid } => write!(f, "bytes do not hash to {cid}"),
            Error::Malformed(why) => write!(f, "malformed: {why}"),
            Error::InsufficientWork { cid } => write!(f, "{cid}: hash above target"),
            Error::BelowFloor { cid } => write!(f, "{cid}: target above the work floor"),
            Error::WrongSpec { cid } => write!(f, "{cid}: not the pinned spec"),
            Error::OffSchedule { cid } => write!(f, "{cid}: nextTarget off the schedule"),
            Error::FutureTimestamp { cid } => write!(f, "{cid}: timestamp in the future"),
            Error::StaleTip { cid } => write!(f, "{cid}: tip too old"),
            Error::BrokenLink { cid, reason } => write!(f, "{cid}: {reason}"),
            Error::Missing { cid } => write!(f, "{cid}: not given"),
        }
    }
}

impl std::error::Error for Error {}

/// Lattice's one standard CID for `bytes`: CIDv1, dag-cbor, sha2-256,
/// multibase base32 (`b`, lowercase, unpadded).
pub fn cid_of(bytes: &[u8]) -> String {
    let mut binary = vec![0x01, 0x71, 0x12, 0x20];
    binary.extend_from_slice(&Sha256::digest(bytes));
    format!(
        "b{}",
        data_encoding::BASE32_NOPAD
            .encode(&binary)
            .to_ascii_lowercase()
    )
}

/// Whether `cid` is the standard CID, spelled canonically
/// (Lattice's `CIDIdentity.isStandard`).
fn is_standard_cid(cid: &str) -> bool {
    let Some(rest) = cid.strip_prefix('b') else {
        return false;
    };
    let Ok(binary) = data_encoding::BASE32_NOPAD.decode(rest.to_ascii_uppercase().as_bytes())
    else {
        return false;
    };
    binary.len() == 36
        && binary.starts_with(&[0x01, 0x71, 0x12, 0x20])
        && format!(
            "b{}",
            data_encoding::BASE32_NOPAD
                .encode(&binary)
                .to_ascii_lowercase()
        ) == cid
}

/// Splits a `/volumes/<cid>` archive (`u16 n, {u16 cidLen, cid, u32 len,
/// bytes}*`, big-endian) into its entries, each checked to hash to its CID.
pub fn parse_archive(archive: &[u8]) -> Result<Vec<(String, Vec<u8>)>, Error> {
    let mut at = 0usize;
    let mut take = |n: usize| -> Result<&[u8], Error> {
        // Checked: on wasm32 `usize` is 32 bits, and `n` can be `u32::MAX`.
        let end = at
            .checked_add(n)
            .ok_or(Error::Malformed("truncated archive"))?;
        let out = archive
            .get(at..end)
            .ok_or(Error::Malformed("truncated archive"))?;
        at = end;
        Ok(out)
    };
    let count = u16::from_be_bytes(take(2)?.try_into().unwrap());
    let mut entries = Vec::with_capacity(count as usize);
    for _ in 0..count {
        let cid_len = u16::from_be_bytes(take(2)?.try_into().unwrap()) as usize;
        let cid = core::str::from_utf8(take(cid_len)?)
            .map_err(|_| Error::Malformed("archive CID not UTF-8"))?
            .to_owned();
        let len = u32::from_be_bytes(take(4)?.try_into().unwrap()) as usize;
        let bytes = take(len)?.to_vec();
        if cid_of(&bytes) != cid {
            return Err(Error::CidMismatch { cid });
        }
        entries.push((cid, bytes));
    }
    if at != archive.len() {
        return Err(Error::Malformed("trailing archive bytes"));
    }
    Ok(entries)
}

/// The link under `key` of a node: a `{"rawCID": …}` map naming a standard
/// CID, unencrypted.
fn link(node: &cbor::Value, key: &str) -> Result<String, Error> {
    let link = node.get(key).ok_or(Error::Malformed("missing link"))?;
    if link.get("encryptionInfo").is_some() {
        return Err(Error::Malformed("encrypted link"));
    }
    match link.get("rawCID") {
        Some(cbor::Value::Text(cid)) if is_standard_cid(cid) => Ok(cid.clone()),
        _ => Err(Error::Malformed("link not a standard CID")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[cfg(target_arch = "wasm32")]
    use wasm_bindgen_test::wasm_bindgen_test as test;

    #[test]
    fn default_floor_is_two_to_the_214_minus_one() {
        let mut expected = [0u8; 32];
        // 2^214 - 1: the low 214 bits set.
        for bit in 0..214 {
            expected[31 - bit / 8] |= 1 << (bit % 8);
        }
        assert_eq!(DEFAULT_WORK_FLOOR, expected);
    }

    #[test]
    fn standard_cid_spelling() {
        let cid = cid_of(b"x");
        assert!(is_standard_cid(&cid));
        assert!(!is_standard_cid(&cid.to_ascii_uppercase()));
        assert!(!is_standard_cid(&cid[1..]));
        assert!(!is_standard_cid(&cid[..cid.len() - 1]));
        // Upper case after the multibase `b`: the same bytes, not canonical.
        assert!(!is_standard_cid(&format!(
            "b{}",
            cid[1..].to_ascii_uppercase()
        )));
        // The standard prefix with a digest a byte too long.
        let mut long = vec![0x01, 0x71, 0x12, 0x20];
        long.extend([7; 33]);
        let long = format!(
            "b{}",
            data_encoding::BASE32_NOPAD
                .encode(&long)
                .to_ascii_lowercase()
        );
        assert!(!is_standard_cid(&long));
    }

    #[test]
    fn archive_entry_must_hash_to_its_cid() {
        let bytes = b"\xa0".to_vec();
        let cid = cid_of(&bytes);
        let mut archive = vec![0, 1];
        archive.extend((cid.len() as u16).to_be_bytes());
        archive.extend(cid.as_bytes());
        archive.extend((bytes.len() as u32).to_be_bytes());
        archive.extend(&bytes);
        assert_eq!(parse_archive(&archive).unwrap(), vec![(cid.clone(), bytes)]);

        let mut forged = archive.clone();
        *forged.last_mut().unwrap() = 0x80;
        assert_eq!(parse_archive(&forged), Err(Error::CidMismatch { cid }));

        let mut trailing = archive.clone();
        trailing.push(0);
        assert!(parse_archive(&trailing).is_err());
        assert!(parse_archive(&archive[..archive.len() - 1]).is_err());
    }

    #[test]
    fn archive_length_past_the_end_is_refused() {
        // An entry claiming `u32::MAX` bytes: on wasm32 `at + len` would
        // overflow `usize`; it is a truncated archive, never a panic.
        let cid = cid_of(b"x");
        let mut archive = vec![0, 1];
        archive.extend((cid.len() as u16).to_be_bytes());
        archive.extend(cid.as_bytes());
        archive.extend(u32::MAX.to_be_bytes());
        archive.push(b'x');
        assert_eq!(
            parse_archive(&archive),
            Err(Error::Malformed("truncated archive"))
        );
    }
}
