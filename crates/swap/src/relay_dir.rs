//! The relay directory: the relays listed on its chain, read from one of its
//! blocks by CID, from whoever serves it.
//!
//! Nexus commits a child chain's block under `child/<directory>` as
//! `<block CID>@<parent state CID>`. Given that value, as read from a Nexus
//! state the caller trusts, a [`Listing`] asks for the block, then its post
//! state, then the general-state trie down to [`PREFIX`] and every node under
//! it, and takes a node only if its bytes are the ones its CID names: so
//! whoever served them, the list is the chain's. It does no I/O: the caller
//! fetches what [`Listing::wants`] names and hands it over by
//! [`Listing::give`], or [`list`] does both with a fetch it is given.
//!
//! The trie is cashew's Merkle dictionary: the root is `{count, children}`
//! and every other node `{prefix, value?, children}`, a child
//! `{key, value: {rawCID}}` filed under the first character of its prefix;
//! a stored key is the prefixes on its path joined. The walk is
//! moniker-sdk's `list` (`src/records/state.mjs`).
//!
//! A listing reads at most [`MAX_ENTRIES`] entries, so a directory of any
//! size costs a bounded read. It reads each node's children in random
//! order, so where it stops does not depend on key order. An entry whose
//! value is not an `https://` URL is skipped.

use ciborium::Value;
use rand_core::{OsRng, RngCore};
use serde::{Deserialize, Serialize};
use swap_nexus_tx::{cid, is_cid};

/// The key family the directory's policy allows: `relay/<account>`.
pub const PREFIX: &str = "relay/";

/// The most entries a listing reads.
pub const MAX_ENTRIES: usize = 512;

/// A relay as its account lists it.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Relay {
    pub account: String,
    /// Its base URL, as [`url::Url`] spells it.
    pub url: String,
}

/// A listing under way: the nodes still to read, and what was read.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Listing {
    pending: Vec<(String, Node)>,
    entries: usize,
    relays: Vec<Relay>,
}

/// What a pending node is to the walk.
#[derive(Clone, Debug, Serialize, Deserialize)]
enum Node {
    Block,
    State,
    /// On the way down to `rest`, under the key `path`.
    Toward {
        path: String,
        rest: String,
    },
    /// Under [`PREFIX`], under the key `path`.
    Under {
        path: String,
    },
}

impl Listing {
    /// A listing of the block `commitment` names: `<block CID>@<parent state
    /// CID>`, split as Lattice splits it, at its one `@`.
    pub fn new(commitment: &str) -> Result<Self, String> {
        let parts: Vec<_> = commitment.split('@').collect();
        match parts[..] {
            [block, parent] if is_cid(block) && !parent.is_empty() => Ok(Self {
                pending: vec![(block.into(), Node::Block)],
                entries: 0,
                relays: Vec::new(),
            }),
            _ => Err(format!(
                "{commitment} is not a child commitment, <block CID>@<parent state CID>"
            )),
        }
    }

    /// The CIDs of the nodes still to read, the next first; none once the
    /// listing is done. Any may be fetched and given in any order.
    pub fn wants(&self) -> Vec<String> {
        let mut wants: Vec<String> = Vec::new();
        for (cid, _) in self.pending.iter().rev() {
            if !wants.contains(cid) {
                wants.push(cid.clone());
            }
        }
        wants
    }

    /// The relays read so far: all of them, up to [`MAX_ENTRIES`] entries,
    /// once [`Listing::wants`] is empty.
    pub fn relays(&self) -> &[Relay] {
        &self.relays
    }

    /// Reads `bytes` as the node `cid` names. Refuses bytes that are not the
    /// ones it names, and a node that is not what the walk expects there; a
    /// node not wanted is ignored.
    pub fn give(&mut self, cid: &str, bytes: &[u8]) -> Result<(), String> {
        if !self.pending.iter().any(|(wanted, _)| wanted == cid) {
            return Ok(());
        }
        if self::cid(bytes) != cid {
            return Err(format!(
                "the bytes given for {cid} are not the ones it names"
            ));
        }
        let node: Value =
            ciborium::from_reader(bytes).map_err(|e| format!("{cid} is not DAG-CBOR: {e}"))?;
        let (reads, pending) = std::mem::take(&mut self.pending)
            .into_iter()
            .partition(|(wanted, _)| wanted == cid);
        self.pending = pending;
        for (_, at) in reads {
            self.read(at, &node)
                .ok_or_else(|| format!("{cid} is not the node the directory has there"))?;
        }
        Ok(())
    }

    fn read(&mut self, at: Node, node: &Value) -> Option<()> {
        match at {
            Node::Block => self.pending.push((link(node, "postState")?, Node::State)),
            Node::State => self.pending.push((
                link(node, "generalState")?,
                Node::Toward {
                    path: String::new(),
                    rest: PREFIX.into(),
                },
            )),
            Node::Toward { mut path, rest } => {
                let prefix = prefix(node)?;
                let rest = if let Some(rest) = rest.strip_prefix(prefix) {
                    rest
                } else if prefix.starts_with(&rest) {
                    ""
                } else {
                    return Some(());
                };
                path.push_str(prefix);
                if rest.is_empty() {
                    return self.under(path, node);
                }
                let first = rest.chars().next()?;
                let child = children(node)?
                    .into_iter()
                    .find(|(key, _)| key.chars().eq([first]));
                if let Some((_, cid)) = child {
                    let rest = rest.into();
                    self.pending.push((cid, Node::Toward { path, rest }));
                }
            }
            Node::Under { mut path } => {
                path.push_str(prefix(node)?);
                self.under(path, node)?;
            }
        }
        Some(())
    }

    /// Takes the entry at `node`, under the key `path`, then queues its
    /// children in random order, or stops at [`MAX_ENTRIES`].
    fn under(&mut self, path: String, node: &Value) -> Option<()> {
        // Stopped already, by another read of the same node.
        if self.entries == MAX_ENTRIES {
            return Some(());
        }
        if let Some(value) = field(node, "value") {
            let value = value.as_text()?;
            self.entries += 1;
            let url = url::Url::parse(value)
                .ok()
                .filter(|url| url.scheme() == "https");
            if let (Some(account), Some(url)) = (path.strip_prefix(PREFIX), url) {
                self.relays.push(Relay {
                    account: account.into(),
                    url: url.into(),
                });
            }
            if self.entries == MAX_ENTRIES {
                self.pending.clear();
                return Some(());
            }
        }
        let mut children = children(node)?;
        // Fisher-Yates.
        for i in (1..children.len()).rev() {
            let j = (OsRng.next_u64() % (i as u64 + 1)) as usize;
            children.swap(i, j);
        }
        for (_, cid) in children {
            let path = path.clone();
            self.pending.push((cid, Node::Under { path }));
        }
        Some(())
    }
}

/// The relays listed in the block `commitment` names, each node fetched by
/// `fetch` from its CID.
pub fn list(
    commitment: &str,
    mut fetch: impl FnMut(&str) -> Result<Vec<u8>, String>,
) -> Result<Vec<Relay>, String> {
    let mut listing = Listing::new(commitment)?;
    while let Some(cid) = listing.wants().into_iter().next() {
        let bytes = fetch(&cid)?;
        listing.give(&cid, &bytes)?;
    }
    Ok(listing.relays)
}

fn field<'a>(node: &'a Value, name: &str) -> Option<&'a Value> {
    node.as_map()?
        .iter()
        .find(|(key, _)| key.as_text() == Some(name))
        .map(|(_, value)| value)
}

/// The CID a link field names: `{rawCID}`.
fn link(node: &Value, name: &str) -> Option<String> {
    Some(field(field(node, name)?, "rawCID")?.as_text()?.into())
}

/// A trie node's prefix; the root has none.
fn prefix(node: &Value) -> Option<&str> {
    field(node, "prefix").map_or(Some(""), Value::as_text)
}

/// A trie node's children: each one's key and CID.
fn children(node: &Value) -> Option<Vec<(String, String)>> {
    field(node, "children")?
        .as_array()?
        .iter()
        .map(|child| {
            Some((
                field(child, "key")?.as_text()?.into(),
                link(child, "value")?,
            ))
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use std::collections::{BTreeMap, BTreeSet};

    use super::*;
    #[cfg(target_arch = "wasm32")]
    use wasm_bindgen_test::wasm_bindgen_test as test;

    fn text(text: &str) -> Value {
        Value::Text(text.into())
    }

    fn map(entries: Vec<(&str, Value)>) -> Value {
        Value::Map(entries.into_iter().map(|(k, v)| (text(k), v)).collect())
    }

    fn to_link(cid: &str) -> Value {
        map(vec![("rawCID", text(cid))])
    }

    /// Nodes by CID, as a host serves them.
    #[derive(Default)]
    struct Store(BTreeMap<String, Vec<u8>>);

    impl Store {
        fn put(&mut self, node: Value) -> String {
            let mut bytes = Vec::new();
            ciborium::into_writer(&node, &mut bytes).unwrap();
            let cid = cid(&bytes);
            self.0.insert(cid.clone(), bytes);
            cid
        }

        /// The children of a node over `entries`, keys relative to it.
        fn children(&mut self, entries: &[(String, String)]) -> Value {
            let mut groups: BTreeMap<char, Vec<(String, String)>> = BTreeMap::new();
            for entry in entries {
                let first = entry.0.chars().next().unwrap();
                groups.entry(first).or_default().push(entry.clone());
            }
            let children = groups
                .into_iter()
                .map(|(first, group)| {
                    let cid = self.node(&group);
                    map(vec![
                        ("key", text(&first.to_string())),
                        ("value", to_link(&cid)),
                    ])
                })
                .collect();
            Value::Array(children)
        }

        /// The node over `entries`, which share a first character.
        fn node(&mut self, entries: &[(String, String)]) -> String {
            let mut prefix = entries[0].0.clone();
            for (key, _) in entries {
                let common = prefix.chars().zip(key.chars()).take_while(|(a, b)| a == b);
                prefix = common.map(|(a, _)| a).collect();
            }
            let mut fields = vec![("prefix", text(&prefix))];
            let mut below = Vec::new();
            for (key, value) in entries {
                match &key[prefix.len()..] {
                    "" => fields.push(("value", text(value))),
                    rest => below.push((rest.to_string(), value.clone())),
                }
            }
            fields.push(("children", self.children(&below)));
            self.put(map(fields))
        }

        /// A block whose general state holds `entries`, and its commitment.
        fn block(&mut self, entries: &[(String, String)]) -> String {
            let children = self.children(entries);
            let count = Value::Integer(entries.len().into());
            let root = self.put(map(vec![("count", count), ("children", children)]));
            let state = self.put(map(vec![("generalState", to_link(&root))]));
            let block = self.put(map(vec![
                ("postState", to_link(&state)),
                ("height", Value::Integer(1.into())),
            ]));
            format!("{block}@{state}")
        }

        fn list(&self, commitment: &str) -> Result<Vec<Relay>, String> {
            list(commitment, |cid| {
                self.0.get(cid).cloned().ok_or(format!("no {cid}"))
            })
        }
    }

    fn account(i: u32) -> String {
        let mut key = [0; 32];
        key[..4].copy_from_slice(&i.to_be_bytes());
        swap_nexus_tx::address(&key)
    }

    fn entry(key: impl Into<String>, value: &str) -> (String, String) {
        (key.into(), value.into())
    }

    #[test]
    fn lists_every_relay_and_nothing_else() {
        let (one, two, plain, junk) = (account(1), account(2), account(3), account(4));
        let entries = [
            entry(format!("relay/{one}"), "https://one.example"),
            entry(format!("relay/{two}"), "https://Two.example/"),
            entry(format!("relay/{plain}"), "http://plain.example"),
            entry(format!("relay/{junk}"), "not a url"),
            entry("relay", "https://no-account.example"),
            entry("relax/x", "https://other.example"),
            entry(format!("user/{one}/name"), "https://user.example"),
            entry("child/x", "https://child.example"),
        ];
        let mut store = Store::default();
        let commitment = store.block(&entries);
        let mut relays = store.list(&commitment).unwrap();
        relays.sort_by(|a, b| a.account.cmp(&b.account));
        let mut expected = vec![
            Relay {
                account: one,
                url: "https://one.example/".into(),
            },
            Relay {
                account: two,
                url: "https://two.example/".into(),
            },
        ];
        expected.sort_by(|a, b| a.account.cmp(&b.account));
        assert_eq!(relays, expected);

        // An empty directory lists nothing.
        let commitment = store.block(&[entry("child/x", "1")]);
        assert_eq!(store.list(&commitment).unwrap(), []);
    }

    #[test]
    fn a_node_is_only_the_bytes_its_cid_names() {
        let mut store = Store::default();
        let commitment =
            store.block(&[entry(format!("relay/{}", account(1)), "https://a.example")]);
        let mut listing = Listing::new(&commitment).unwrap();
        let block = listing.wants().remove(0);
        let (other, bytes) = store.0.iter().find(|(cid, _)| **cid != block).unwrap();
        assert!(listing.give(&block, bytes).is_err());
        assert_eq!(listing.wants(), std::slice::from_ref(&block));
        listing.give(&block, &store.0[&block]).unwrap();
        assert_ne!(listing.wants(), [block]);
        // A node in the block's place that is no block.
        let mut listing = Listing::new(&format!("{other}@x")).unwrap();
        assert!(listing.give(other, bytes).is_err());
    }

    #[test]
    fn stops_at_max_entries_wherever_key_order_puts_them() {
        let entries: Vec<_> = (0..MAX_ENTRIES as u32 + 88)
            .map(|i| entry(format!("relay/{}", account(i)), "https://r.example"))
            .collect();
        let mut store = Store::default();
        let commitment = store.block(&entries);
        let listed = || -> BTreeSet<String> {
            let relays = store.list(&commitment).unwrap();
            assert_eq!(relays.len(), MAX_ENTRIES);
            relays.into_iter().map(|relay| relay.account).collect()
        };
        let first_by_key: BTreeSet<String> = entries
            .iter()
            .map(|(key, _)| key[PREFIX.len()..].to_string())
            .collect::<BTreeSet<_>>()
            .into_iter()
            .take(MAX_ENTRIES)
            .collect();
        let (a, b) = (listed(), listed());
        assert_eq!(a.len(), MAX_ENTRIES);
        assert_ne!(a, b, "two listings cut the same entries");
        assert_ne!(a, first_by_key);
    }

    #[test]
    fn a_commitment_is_a_block_cid_and_a_parent_state() {
        let block = account(1);
        assert!(Listing::new(&format!("{block}@{block}")).is_ok());
        for commitment in [
            String::new(),
            block.clone(),
            format!("{block}@"),
            format!("@{block}"),
            format!("{block}@{block}@{block}"),
            format!("x@{block}"),
        ] {
            assert!(Listing::new(&commitment).is_err(), "{commitment}");
        }
    }
}
