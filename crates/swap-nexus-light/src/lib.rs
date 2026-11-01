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
//! header to its CID, checks its proof of work and links it to its parent;
//! [`prove_account`] binds every state node from a verified `postState` down
//! to the account's entries. What is left is the cost of a fake chain, and
//! that is measured in work, not blocks.
//!
//! Every header from the lock block up to the tip must meet the caller's
//! work floor (`target <= floor`), so a run of `N` such blocks above the
//! lock costs at least `N` times the work of `floor` to forge, whoever
//! forges it. No checkpoint, genesis or difficulty schedule is needed for
//! that bound: a lying node must grind the blocks it shows. The buyer
//! picks `N` and the floor from what the BTC at stake is worth;
//! [`DEFAULT_WORK_FLOOR`] is the default floor.
//!
//! If Nexus hashrate falls below the floor, honest blocks stop meeting it,
//! no lock reaches depth, and the swap times out and refunds. That costs
//! liveness, never funds.
//!
//! The difficulty schedule (ASERT) is not checked: it is anchored at block
//! 1, so checking it means holding the chain back to block 1 or a
//! checkpoint, and the floor already prices every block shown. Nor is
//! anything checked that only an honest node's view could check (that the
//! chain shown is the heaviest one): a node can withhold, which the swap's
//! timeouts cover, but it cannot forge without paying the floor per block.

mod cbor;
mod chain;
mod state;

use sha2::{Digest, Sha256};

pub use chain::{verify_chain, VerifiedBlock, VerifiedChain};
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
    let mut at = 0;
    let mut take = |n: usize| -> Result<&[u8], Error> {
        let end = at + n;
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
}
