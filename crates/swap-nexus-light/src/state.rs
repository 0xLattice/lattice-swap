//! Account lookup in a committed state: `LatticeState.accountState`, a
//! cashew `VolumeMerkleDictionaryImpl<UInt64>` whose trie edges are each a
//! separate CID-addressed node (`VolumeRadixNodeImpl`).
//!
//! The walk is cashew's `MerkleDictionary.get(key:)` and `RadixNode.get(key:)`:
//! the dictionary picks the child by the key's first character; a node
//! answers its value when the key equals its prefix, nothing when the key
//! does not start with its prefix, and otherwise picks the child by the next
//! character of what is left. State keys are visible ASCII (Lattice's
//! `isDeterministicKeyAtom`), so characters are bytes, and any node that is
//! not plain ASCII is refused rather than compared.

use std::collections::HashMap;

use crate::cbor::{self, Value};
use crate::{cid_of, is_standard_cid, link, Error};

/// What a state commits to for one account. `nonce` is the stored nonce,
/// `None` when the account has never sent a transaction; its next
/// transaction carries [`Account::next_nonce`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Account {
    /// 0 when the state holds no balance entry.
    pub balance: u64,
    pub nonce: Option<u64>,
}

impl Account {
    /// Lattice's `nextExpectedNonce(afterStored:)`: 0 for an account that
    /// never transacted, else the stored nonce + 1.
    pub fn next_nonce(&self) -> Option<u64> {
        match self.nonce {
            None => Some(0),
            Some(n) => n.checked_add(1),
        }
    }
}

/// Lattice's `AccountStateHeader.nonceKeyPrefix`.
const NONCE_KEY_PREFIX: &str = "_nonce_";

/// Reads `address`'s balance and nonce from the state `state_root` (a
/// verified block's `postState`). `nodes` are state nodes by CID, as
/// [`crate::parse_archive`] gives them out of `/volumes/<cid>` responses;
/// each is checked to hash to its CID. A node the walk needs that `nodes`
/// lack is an error, never an absent entry.
pub fn prove_account(
    state_root: &str,
    nodes: &[(String, Vec<u8>)],
    address: &str,
) -> Result<Account, Error> {
    // `CryptoUtils.isValidAddress`: a standard CID, spelled canonically.
    // That also rules out every reserved key (`isReservedAccountKey`: the
    // `_nonce_` prefix), so a nonce entry is never read as a balance.
    if !is_standard_cid(address) {
        return Err(Error::Malformed("address not a standard CID"));
    }
    let mut by_cid = HashMap::new();
    for (cid, bytes) in nodes {
        if cid_of(bytes) != *cid {
            return Err(Error::CidMismatch { cid: cid.clone() });
        }
        by_cid.insert(cid.as_str(), bytes);
    }
    let get = |cid: &str| -> Result<Value, Error> {
        let bytes = by_cid.get(cid).ok_or_else(|| Error::Missing {
            cid: cid.to_owned(),
        })?;
        cbor::decode(bytes)
    };

    let state = get(state_root)?;
    // `LatticeState` decodes all four roots.
    for key in ["generalState", "depositState", "receiptState"] {
        link(&state, key)?;
    }
    let accounts = get(&link(&state, "accountState")?)?;
    if !matches!(accounts.get("count"), Some(Value::Uint(_))) {
        return Err(Error::Malformed("dictionary count"));
    }

    let root_children = children(&accounts)?;
    let lookup = |key: &str| -> Result<Option<u64>, Error> {
        let key = key.as_bytes();
        // `MerkleDictionary.get(key:)`: the child under the first character,
        // asked for the whole key.
        let Some(mut cid) = root_children.get(&key[0]).cloned() else {
            return Ok(None);
        };
        let mut rest = key;
        // `RadixNode.get(key:)`.
        loop {
            let node = get(&cid)?;
            let prefix = match node.get("prefix") {
                Some(Value::Text(p)) if p.bytes().all(is_key_byte) => p.as_bytes(),
                _ => return Err(Error::Malformed("trie prefix")),
            };
            let value = match node.get("value") {
                None | Some(Value::Null) => None,
                Some(Value::Uint(n)) => Some(*n),
                Some(_) => return Err(Error::Malformed("trie value")),
            };
            let node_children = children(&node)?;
            if rest == prefix {
                return Ok(value);
            }
            if !rest.starts_with(prefix) {
                return Ok(None);
            }
            // Not empty: `rest` starts with `prefix` and is not it.
            rest = &rest[prefix.len()..];
            match node_children.get(&rest[0]) {
                Some(next) => cid = next.clone(),
                None => return Ok(None),
            }
        }
    };

    Ok(Account {
        balance: lookup(address)?.unwrap_or(0),
        nonce: lookup(&format!("{NONCE_KEY_PREFIX}{address}"))?,
    })
}

/// A dictionary or trie node's child links by character, as cashew's
/// `decodeChildren` reads them: each entry a one-character visible-ASCII
/// key and a standard link, no character twice.
fn children(node: &Value) -> Result<HashMap<u8, String>, Error> {
    let Some(Value::Array(entries)) = node.get("children") else {
        return Err(Error::Malformed("trie children"));
    };
    let mut out = HashMap::with_capacity(entries.len());
    for entry in entries {
        let key = match entry.get("key") {
            Some(Value::Text(k)) if k.len() == 1 && is_key_byte(k.as_bytes()[0]) => k.as_bytes()[0],
            _ => return Err(Error::Malformed("trie child key")),
        };
        if out.insert(key, link(entry, "value")?).is_some() {
            return Err(Error::Malformed("repeated trie child key"));
        }
    }
    Ok(out)
}

fn is_key_byte(b: u8) -> bool {
    (0x21..=0x7e).contains(&b)
}
