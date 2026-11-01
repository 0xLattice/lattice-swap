//! Header checks: CID binding, proof of work (Lattice's
//! `makeProofOfWorkPreimage` and `validateProofOfWork`), the work floor, the
//! pinned spec, the parent link rules of `headerAdmission` that a header and
//! its parent decide alone, the difficulty schedule (`validateNextTarget`),
//! and the caller's clock.

use sha2::{Digest, Sha256};

use crate::cbor::{self, Value};
use crate::{cid_of, is_standard_cid, link, ChainParams, Error, U256};

/// The only header version Lattice admits (`Block.currentVersion`).
const BLOCK_VERSION: u64 = 1;

/// A header that passed every check.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedBlock {
    pub cid: String,
    pub height: u64,
    pub timestamp: i64,
    pub target: U256,
    /// The state this block commits to after its transactions: the root
    /// [`crate::prove_account`] walks from.
    pub post_state: String,
}

/// A run of headers, tip first, each the parent of the one before it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedChain {
    pub blocks: Vec<VerifiedBlock>,
}

impl VerifiedChain {
    pub fn tip(&self) -> &VerifiedBlock {
        &self.blocks[0]
    }

    /// How many verified blocks sit at or above the block `cid`, itself
    /// included: 1 for the tip. Every one met the floor, so this times the
    /// floor's work is what forging it would cost.
    pub fn depth_of(&self, cid: &str) -> Option<usize> {
        self.blocks.iter().position(|b| b.cid == cid).map(|i| i + 1)
    }
}

struct Header {
    parent: Option<String>,
    target: U256,
    next_target: U256,
    prev_state: String,
    post_state: String,
    height: u64,
    timestamp: i64,
}

/// Verifies `headers` (CID and raw header bytes), tip first, back through
/// parent links, against the chain `params` and the caller's clock `now_ms`
/// (Unix milliseconds).
///
/// Each header must hash to its CID, carry its proof of work, meet `floor`
/// (`target <= floor`), carry `params.spec`, and follow the next header as
/// its parent: the parent's CID, height + 1, a later timestamp, the
/// parent's `postState` as its `prevState`, and a target no easier than the
/// parent's `nextTarget`. Its `nextTarget` must be the schedule's at its
/// own height and timestamp ([`ChainParams::next_target`]), and its
/// timestamp at most [`crate::MAX_FUTURE_MS`] past `now_ms`. The tip must be
/// stamped at least `now_ms -` [`crate::MAX_TIP_AGE_MS`]. The last header's
/// own parent is not checked.
pub fn verify_chain(
    headers: &[(String, Vec<u8>)],
    floor: &U256,
    params: &ChainParams,
    now_ms: i64,
) -> Result<VerifiedChain, Error> {
    if headers.is_empty() {
        return Err(Error::Malformed("no headers"));
    }
    let decoded = headers
        .iter()
        .map(|(cid, bytes)| check_header(cid, bytes, floor, &params.spec))
        .collect::<Result<Vec<_>, _>>()?;
    for (i, pair) in decoded.windows(2).enumerate() {
        let (child, parent) = (&pair[0], &pair[1]);
        let broken = |reason| Error::BrokenLink {
            cid: headers[i].0.clone(),
            reason,
        };
        if child.parent.as_deref() != Some(headers[i + 1].0.as_str()) {
            return Err(broken("parent is not the next header"));
        }
        if parent.height.checked_add(1) != Some(child.height) {
            return Err(broken("height is not the parent's + 1"));
        }
        if child.timestamp <= parent.timestamp {
            return Err(broken("timestamp not after the parent's"));
        }
        if child.prev_state != parent.post_state {
            return Err(broken("prevState is not the parent's postState"));
        }
        if child.target > parent.next_target {
            return Err(broken("target easier than the parent's nextTarget"));
        }
    }
    let latest = now_ms.saturating_add(crate::MAX_FUTURE_MS);
    for ((cid, _), h) in headers.iter().zip(&decoded) {
        // `validateNextTarget`, with the anchor pinned instead of walked to.
        if h.height < params.anchor_height
            || h.next_target != params.next_target(h.height, h.timestamp)
        {
            return Err(Error::OffSchedule { cid: cid.clone() });
        }
        if h.timestamp > latest {
            return Err(Error::FutureTimestamp { cid: cid.clone() });
        }
    }
    if decoded[0].timestamp < now_ms.saturating_sub(crate::MAX_TIP_AGE_MS) {
        return Err(Error::StaleTip {
            cid: headers[0].0.clone(),
        });
    }
    let blocks = headers
        .iter()
        .zip(decoded)
        .map(|((cid, _), h)| VerifiedBlock {
            cid: cid.clone(),
            height: h.height,
            timestamp: h.timestamp,
            target: h.target,
            post_state: h.post_state,
        })
        .collect();
    Ok(VerifiedChain { blocks })
}

fn check_header(cid: &str, bytes: &[u8], floor: &U256, spec_pin: &str) -> Result<Header, Error> {
    if cid_of(bytes) != cid {
        return Err(Error::CidMismatch {
            cid: cid.to_owned(),
        });
    }
    let node = cbor::decode(bytes)?;
    let uint = |key| match node.get(key) {
        Some(Value::Uint(n)) => Ok(*n),
        _ => Err(Error::Malformed("header integer")),
    };
    let target_of = |key| match node.get(key) {
        Some(Value::Text(text)) => parse_u256(text),
        _ => Err(Error::Malformed("header target")),
    };

    let version = uint("version")?;
    if version != BLOCK_VERSION {
        return Err(Error::Malformed("header version"));
    }
    let parent = match node.get("parent") {
        None => None,
        Some(_) => Some(link(&node, "parent")?),
    };
    let transactions = link(&node, "transactions")?;
    let target = target_of("target")?;
    let next_target = target_of("nextTarget")?;
    let spec = link(&node, "spec")?;
    let parent_state = link(&node, "parentState")?;
    let prev_state = link(&node, "prevState")?;
    let post_state = link(&node, "postState")?;
    let children = link(&node, "children")?;
    let height = uint("height")?;
    let timestamp = match node.get("timestamp") {
        Some(Value::Uint(n)) => i64::try_from(*n).ok(),
        Some(Value::Neg(n)) => i64::try_from(*n).ok().map(|n| -1 - n),
        _ => None,
    }
    .ok_or(Error::Malformed("header timestamp"))?;
    let reward_recipient = match node.get("rewardRecipient") {
        None => None,
        // `hasWellFormedRewardRecipient`: a canonical address.
        Some(Value::Text(address)) if is_standard_cid(address) => Some(address.as_str()),
        Some(_) => return Err(Error::Malformed("header rewardRecipient")),
    };
    let nonce = uint("nonce")?;

    // `makeProofOfWorkPreimage`: every field, 0x00-separated, then the nonce.
    let mut preimage = Vec::with_capacity(512);
    for field in [
        version.to_string().as_bytes(),
        parent.as_deref().unwrap_or("").as_bytes(),
        transactions.as_bytes(),
        hex64(&target).as_bytes(),
        hex64(&next_target).as_bytes(),
        spec.as_bytes(),
        parent_state.as_bytes(),
        prev_state.as_bytes(),
        post_state.as_bytes(),
        children.as_bytes(),
        height.to_string().as_bytes(),
        timestamp.to_string().as_bytes(),
    ] {
        preimage.extend_from_slice(field);
        preimage.push(0);
    }
    // Absent: nothing; present: 0x01 then the address. Then the separator.
    if let Some(address) = reward_recipient {
        preimage.push(1);
        preimage.extend_from_slice(address.as_bytes());
    }
    preimage.push(0);
    preimage.extend_from_slice(&nonce.to_be_bytes());
    let hash: U256 = Sha256::digest(&preimage).into();

    // `validateProofOfWork`: target > 0 and hash <= target.
    if target == [0; 32] || hash > target {
        return Err(Error::InsufficientWork {
            cid: cid.to_owned(),
        });
    }
    if target > *floor {
        return Err(Error::BelowFloor {
            cid: cid.to_owned(),
        });
    }
    if spec != spec_pin {
        return Err(Error::WrongSpec {
            cid: cid.to_owned(),
        });
    }
    Ok(Header {
        parent,
        target,
        next_target,
        prev_state,
        post_state,
        height,
        timestamp,
    })
}

/// Lattice's UInt256 text: optional `0x`, then 1 to 64 hex digits.
fn parse_u256(text: &str) -> Result<U256, Error> {
    let digits = text
        .strip_prefix("0x")
        .or_else(|| text.strip_prefix("0X"))
        .unwrap_or(text)
        .as_bytes();
    if digits.is_empty() || digits.len() > 64 {
        return Err(Error::Malformed("UInt256 length"));
    }
    let mut out = [0u8; 32];
    for (i, digit) in digits.iter().rev().enumerate() {
        let nibble = (*digit as char)
            .to_digit(16)
            .ok_or(Error::Malformed("UInt256 digit"))? as u8;
        out[31 - i / 2] |= nibble << (4 * (i % 2));
    }
    Ok(out)
}

/// `UInt256.toHexString`: 64 lowercase hex digits.
fn hex64(value: &U256) -> String {
    value.iter().map(|b| format!("{b:02x}")).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn u256_text() {
        let mut one = [0u8; 32];
        one[31] = 1;
        assert_eq!(parse_u256("0x1"), Ok(one));
        assert_eq!(parse_u256("1"), Ok(one));
        assert_eq!(parse_u256("0X01"), Ok(one));
        let mut x = [0u8; 32];
        x[30] = 0xab;
        x[31] = 0xcd;
        assert_eq!(parse_u256("0xAbCd"), Ok(x));
        assert_eq!(parse_u256(&format!("0x{}", "f".repeat(64))), Ok([0xff; 32]));
        assert!(parse_u256(&format!("0x1{}", "0".repeat(64))).is_err());
        assert!(parse_u256("0x").is_err());
        assert!(parse_u256("0xg").is_err());
        assert!(parse_u256("+1").is_err());
        assert_eq!(hex64(&x), format!("{}abcd", "0".repeat(60)));
    }
}
