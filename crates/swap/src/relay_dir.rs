//! The relay directory: the relays listed on its chain, read from one of its
//! blocks by CID, from whoever serves it.
//!
//! Given a block CID, a [`Listing`] asks for the block, then its post
//! state, then the general-state trie down to [`PREFIX`] and every node under
//! it, and takes a node only if its bytes are the ones its CID names, so
//! whoever served them cannot change what that block lists. It does no I/O:
//! the caller fetches what [`Listing::wants`] names and hands it over by
//! [`Listing::give`], or [`list`] does both with a fetch it is given, and
//! [`list_hosted`] starts from the tip a node hosting the directory's chain
//! reports.
//!
//! Which block to start from is the word of the node asked for the tip: it
//! is not tied to Nexus's proof of work, as merged mining commits a child
//! block only in each parent block's children, not in a state a reader can
//! ask about. A node cannot change the bytes of a block it names, but it can
//! name an old block or one it made up, so the list is as good as the node
//! asked, and the directory's policy holds for it only when that node checks
//! the chain. A false list can hide relays or name useless ones, which is a
//! matter of finding offers, not of funds: every offer is signed by its
//! seller. So a reader asks its user's own node when it has one, and falls
//! back to relays of its own.
//!
//! The trie is cashew's Merkle dictionary: the root is `{count, children}`
//! and every other node `{prefix, value?, children}`, a child
//! `{key, value: {rawCID}}` filed under the first character of its prefix;
//! a stored key is the prefixes on its path joined. The walk is
//! moniker-sdk's `list` (`src/records/state.mjs`).
//!
//! A listing reads at most [`MAX_ENTRIES`] entries and [`MAX_NODES`] nodes
//! of at most [`MAX_NODE_BYTES`] bytes and [`MAX_CHILDREN`] children each,
//! each CID once, and no key longer than the policy allows, so a directory
//! of any size or shape costs a bounded read. It reads each node's children
//! in random order, so where it stops does not depend on key order. An entry
//! is skipped unless its account is an address and its value an `https://`
//! URL with no user info, whose host is not a literal name or address of
//! this machine or a private network (a name may still resolve to one).
//! Under [`PREFIX`], a malformed entry or child is skipped, not refused. A
//! linked node no host serves, bytes that are not DAG-CBOR or a node over the
//! caps still fail the whole listing: no honest directory chain holds one,
//! and the block's author decides its content anyway, so a caller that gets
//! no list falls back to relays of its own.

use std::collections::BTreeSet;
use std::net::{IpAddr, Ipv4Addr};

use ciborium::Value;
use rand_core::{OsRng, RngCore};
use serde::{Deserialize, Serialize};
#[cfg(feature = "native")]
use swap_nexus_tx::rpc::{parse, Client};
use swap_nexus_tx::{cid, is_cid};
use url::{Host, Url};

/// The key family the directory's policy allows: `relay/<account>`.
pub const PREFIX: &str = swap_nexus_tx::RELAY_DIR_PREFIX;

/// The most entries a listing reads.
pub const MAX_ENTRIES: usize = 512;

/// The longest key the directory's policy allows.
const MAX_KEY_BYTES: usize = 512;

/// The most bytes a node may have. The directory's policy caps a value at
/// 16 KiB and a key at 512 bytes, and a node holds one value, one prefix and
/// at most [`MAX_CHILDREN`] short links, so an honest node is well under
/// this.
pub const MAX_NODE_BYTES: usize = 32 * 1024;

/// The most children a node may have. Cashew files a node's children by the
/// first character of their prefixes, so an honest node has one per
/// character that follows it, and an address is base32: 32 at most.
pub const MAX_CHILDREN: usize = 64;

/// The longest key a listing descends to: below it, a branch is not read.
const MAX_PATH_BYTES: usize = PREFIX.len() + MAX_KEY_BYTES;

/// The most nodes a listing reads. In cashew's trie every node but the root
/// has a nonempty prefix, so a path below the root holds at most
/// [`MAX_PATH_BYTES`] nodes the listing descends from, and one past them it
/// reads but does not descend; and a node with no value has at least two
/// children, so a subtree read whole has fewer such nodes than entries.
/// Read in the order [`Listing::wants`] names them, depth-first, by the time
/// a listing stops every node it read is an entry, a valueless node of a
/// subtree read whole, or on the path to the node it reads next; the block,
/// its state and the trie's root are three more. A trie of another shape,
/// which only a hostile block holds, is cut off here.
pub const MAX_NODES: usize = 2 * MAX_ENTRIES + MAX_PATH_BYTES + 1 + 3;

/// The most nodes [`value`] reads: the block, its state, the trie's root,
/// and one node for each byte of the longest key, as in cashew's trie every
/// node below the root has a nonempty prefix.
pub const MAX_VALUE_NODES: usize = MAX_PATH_BYTES + 3;

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
    /// Every CID ever queued: each is read once.
    queued: BTreeSet<String>,
    nodes: usize,
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
    /// A listing of the directory's block `block` names, a block CID.
    pub fn new(block: &str) -> Result<Self, String> {
        if !is_cid(block) {
            return Err(format!("{block} is not a block CID"));
        }
        Ok(Self {
            pending: vec![(block.into(), Node::Block)],
            queued: BTreeSet::from([block.into()]),
            nodes: 0,
            entries: 0,
            relays: Vec::new(),
        })
    }

    /// The CIDs of the nodes still to read, the next first; none once the
    /// listing is done. Any may be fetched and given in any order, but
    /// [`MAX_NODES`] is reached before [`MAX_ENTRIES`] on an honest trie
    /// only out of this order, which is depth-first.
    pub fn wants(&self) -> Vec<String> {
        self.pending
            .iter()
            .rev()
            .map(|(cid, _)| cid.clone())
            .collect()
    }

    /// The relays read so far: all of them, up to [`MAX_ENTRIES`] entries
    /// and [`MAX_NODES`] nodes, once [`Listing::wants`] is empty.
    pub fn relays(&self) -> &[Relay] {
        &self.relays
    }

    /// Reads `bytes` as the node `cid` names. Refuses bytes that are not the
    /// ones it names, more than [`MAX_NODE_BYTES`] of them, a node with more
    /// than [`MAX_CHILDREN`] children, and a node above [`PREFIX`] that is
    /// not what the walk expects there; a node not wanted is ignored.
    pub fn give(&mut self, cid: &str, bytes: &[u8]) -> Result<(), String> {
        let Some(at) = self.pending.iter().position(|(wanted, _)| wanted == cid) else {
            return Ok(());
        };
        if bytes.len() > MAX_NODE_BYTES {
            return Err(format!(
                "{cid} is {} bytes, more than a node of the directory's",
                bytes.len()
            ));
        }
        if self::cid(bytes) != cid {
            return Err(format!(
                "the bytes given for {cid} are not the ones it names"
            ));
        }
        let node: Value =
            ciborium::from_reader(bytes).map_err(|e| format!("{cid} is not DAG-CBOR: {e}"))?;
        let (_, at) = self.pending.remove(at);
        self.read(at, &node)
            .ok_or_else(|| format!("{cid} is not the node the directory has there"))?;
        self.nodes += 1;
        if self.nodes == MAX_NODES {
            self.pending.clear();
        }
        Ok(())
    }

    fn read(&mut self, at: Node, node: &Value) -> Option<()> {
        match at {
            Node::Block => self.queue(link(node, "postState")?, Node::State),
            Node::State => self.queue(
                link(node, "generalState")?,
                Node::Toward {
                    path: String::new(),
                    rest: PREFIX.into(),
                },
            ),
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
                    self.queue(cid, Node::Toward { path, rest });
                }
            }
            Node::Under { mut path } => {
                // A malformed node is skipped, as an entry would be.
                let Some(prefix) = prefix(node) else {
                    return Some(());
                };
                path.push_str(prefix);
                self.under(path, node)?;
            }
        }
        Some(())
    }

    /// Takes the entry at `node`, under the key `path`, then queues its
    /// children in random order, or stops at [`MAX_ENTRIES`]. Below
    /// [`MAX_PATH_BYTES`] nothing is read. None only for a node with more
    /// than [`MAX_CHILDREN`] children.
    fn under(&mut self, path: String, node: &Value) -> Option<()> {
        if path.len() > MAX_PATH_BYTES {
            return Some(());
        }
        if let Some(value) = field(node, "value") {
            self.entries += 1;
            let value = value.as_text().unwrap_or_default();
            let account = path.strip_prefix(PREFIX).filter(|account| is_cid(account));
            if let (Some(account), Some(url)) = (account, relay_url(value)) {
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
        // A child that is not `{key, value: {rawCID}}` is skipped.
        let mut children: Vec<_> = match field(node, "children").and_then(Value::as_array) {
            Some(children) if children.len() > MAX_CHILDREN => return None,
            Some(children) => children.iter().filter_map(child).collect(),
            None => Vec::new(),
        };
        // Fisher-Yates.
        for i in (1..children.len()).rev() {
            let j = (OsRng.next_u64() % (i as u64 + 1)) as usize;
            children.swap(i, j);
        }
        for (_, cid) in children {
            let path = path.clone();
            self.queue(cid, Node::Under { path });
        }
        Some(())
    }

    /// Queues the node `cid` names, unless it was queued before. A node is
    /// read once: in cashew's trie two places hold one node only if their
    /// subtrees are the same below them, the same key ends with the same
    /// values, and the entries of the place read second go unlisted.
    fn queue(&mut self, cid: String, at: Node) {
        if self.queued.insert(cid.clone()) {
            self.pending.push((cid, at));
        }
    }
}

/// `value` as a relay's base URL: `https://`, no user info, and a host that
/// is not literally this machine or a private network: `localhost`, or an
/// address outside the public unicast ranges. A name is not resolved.
pub fn relay_url(value: &str) -> Option<Url> {
    let url = Url::parse(value).ok()?;
    let local_ip = |ip: IpAddr| match ip {
        IpAddr::V4(ip) => !public_v4(ip),
        // IPv4-mapped and IPv4-compatible (`::a.b.c.d`, `::1` among them).
        IpAddr::V6(ip) => match ip.to_ipv4() {
            Some(ip) => !public_v4(ip),
            None => {
                ip.is_loopback()
                    || ip.is_unspecified()
                    || ip.is_unique_local()
                    || ip.is_unicast_link_local()
                    || ip.is_multicast()
            }
        },
    };
    let local = match url.host()? {
        Host::Domain(domain) => {
            let domain = domain.trim_end_matches('.');
            domain == "localhost" || domain.ends_with(".localhost")
        }
        Host::Ipv4(ip) => local_ip(IpAddr::V4(ip)),
        Host::Ipv6(ip) => local_ip(IpAddr::V6(ip)),
    };
    let plain = url.username().is_empty() && url.password().is_none();
    (url.scheme() == "https" && plain && !local).then_some(url)
}

/// Whether `ip` is a unicast address beyond this machine and its private
/// network: not `0.0.0.0/8`, loopback, private, carrier-grade NAT
/// (`100.64.0.0/10`), link-local, broadcast or multicast.
fn public_v4(ip: Ipv4Addr) -> bool {
    let [a, b, ..] = ip.octets();
    let shared = a == 100 && b & 0xc0 == 64;
    !(a == 0
        || ip.is_loopback()
        || ip.is_private()
        || shared
        || ip.is_link_local()
        || ip.is_broadcast()
        || ip.is_multicast())
}

/// The relays listed in the block `block` names, each node fetched by
/// `fetch` from its CID.
pub fn list(
    block: &str,
    mut fetch: impl FnMut(&str) -> Result<Vec<u8>, String>,
) -> Result<Vec<Relay>, String> {
    let mut listing = Listing::new(block)?;
    while let Some((cid, _)) = listing.pending.last() {
        let cid = cid.clone();
        let bytes = fetch(&cid)?;
        listing.give(&cid, &bytes)?;
    }
    Ok(listing.relays)
}

/// The relays listed at the tip of the directory's chain `chain`, as `node`,
/// which hosts it, reports the tip, each node read from its Volumes by
/// [`hosted_volumes`] and checked against its CID.
#[cfg(feature = "native")]
pub fn list_hosted(node: &Client, chain: &[String]) -> Result<Vec<Relay>, String> {
    let info = node.chain_info_of(chain).map_err(|e| e.to_string())?;
    if info["chain"] != serde_json::json!(chain) {
        return Err(format!("the node answered for another chain: {info}"));
    }
    let tip = parse::tip(&info)?.1.ok_or("the chain has no tip yet")?;
    list(&tip, hosted_volumes(node, chain))
}

/// A fetch of a node by CID from the Volumes `node` holds for the chain
/// `chain`. A Volume holds many nodes: the others are kept, by [`held`], so
/// they are not asked for again.
#[cfg(feature = "native")]
pub fn hosted_volumes<'a>(
    node: &'a Client,
    chain: &'a [String],
) -> impl FnMut(&str) -> Result<Vec<u8>, String> + 'a {
    let mut kept = std::collections::BTreeMap::new();
    move |cid| match kept.remove(cid) {
        Some(bytes) => Ok(bytes),
        None => {
            let volume = node.volume(cid, chain).map_err(|e| e.to_string())?;
            held(&mut kept, cid, volume).ok_or(format!("the node's Volume {cid} lacks its root"))
        }
    }
}

/// The node `cid` names out of `volume`, a Volume rooted at it, keeping its
/// other nodes in `kept`. The node serving the Volume picks what else it
/// holds, so a node is kept only if it could be read, at most
/// [`MAX_NODE_BYTES`] bytes that are the ones its CID names, and only while
/// `kept` holds fewer than [`MAX_NODES`], as many as a listing reads: a
/// hostile node's filler costs at most that much memory, however many
/// answers it pads. A node dropped is asked for again if read.
#[cfg(any(feature = "native", test))]
fn held(
    kept: &mut std::collections::BTreeMap<String, Vec<u8>>,
    cid: &str,
    mut volume: std::collections::BTreeMap<String, Vec<u8>>,
) -> Option<Vec<u8>> {
    let root = volume.remove(cid)?;
    for (other, bytes) in volume {
        if kept.len() == MAX_NODES {
            break;
        }
        if bytes.len() <= MAX_NODE_BYTES && self::cid(&bytes) == other {
            kept.insert(other, bytes);
        }
    }
    Some(root)
}

/// The value of `key` in the general state the block `block` enters, or
/// `None` if it has none: a walk down the trie from the block, each node
/// fetched by `fetch` from its CID and refused unless its bytes are the ones
/// it names. A node it cannot read as a trie node ends the walk at no value:
/// a write whose old value is wrong is refused by the chain anyway.
///
/// It reads at most [`MAX_VALUE_NODES`] nodes of at most [`MAX_NODE_BYTES`]
/// bytes each, as a [`Listing`] does, and fails beyond them.
pub fn value(
    block: &str,
    key: &str,
    mut fetch: impl FnMut(&str) -> Result<Vec<u8>, String>,
) -> Result<Option<String>, String> {
    let mut read = 0;
    let mut node = |cid: &str| -> Result<Value, String> {
        read += 1;
        if read > MAX_VALUE_NODES {
            return Err(format!(
                "the walk to {key} reads more than {MAX_VALUE_NODES} nodes"
            ));
        }
        let bytes = fetch(cid)?;
        if bytes.len() > MAX_NODE_BYTES {
            return Err(format!(
                "{cid} is {} bytes, more than a node of the directory's",
                bytes.len()
            ));
        }
        if self::cid(&bytes) != cid {
            return Err(format!(
                "the bytes given for {cid} are not the ones it names"
            ));
        }
        ciborium::from_reader(&bytes[..]).map_err(|e| format!("{cid} is not DAG-CBOR: {e}"))
    };
    let not_found = |cid: &str| format!("{cid} is not the node the chain has there");
    let state = link(&node(block)?, "postState").ok_or_else(|| not_found(block))?;
    let mut at = link(&node(&state)?, "generalState").ok_or_else(|| not_found(&state))?;
    let mut rest = key;
    loop {
        let trie = node(&at)?;
        let Some(after) = prefix(&trie).and_then(|prefix| rest.strip_prefix(prefix)) else {
            return Ok(None);
        };
        rest = after;
        let Some(first) = rest.chars().next() else {
            return Ok(field(&trie, "value")
                .and_then(Value::as_text)
                .map(String::from));
        };
        let child = children(&trie)
            .unwrap_or_default()
            .into_iter()
            .find(|(key, _)| key.chars().eq([first]));
        let Some((_, cid)) = child else {
            return Ok(None);
        };
        at = cid;
    }
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

/// A trie node's children, each one's key and CID: at most
/// [`MAX_CHILDREN`], each well formed.
fn children(node: &Value) -> Option<Vec<(String, String)>> {
    let children = field(node, "children")?.as_array()?;
    (children.len() <= MAX_CHILDREN).then_some(())?;
    children.iter().map(child).collect()
}

/// A child: `{key, value: {rawCID}}`.
fn child(child: &Value) -> Option<(String, String)> {
    Some((
        field(child, "key")?.as_text()?.into(),
        link(child, "value")?,
    ))
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

        /// A block whose general state holds `entries`, and its CID.
        fn block(&mut self, entries: &[(String, String)]) -> String {
            let children = self.children(entries);
            self.commit(children)
        }

        /// A block whose general state's root has `children`, and its CID.
        fn commit(&mut self, children: Value) -> String {
            let count = Value::Integer(0.into());
            let root = self.put(map(vec![("count", count), ("children", children)]));
            let state = self.put(map(vec![("generalState", to_link(&root))]));
            self.put(map(vec![
                ("postState", to_link(&state)),
                ("height", Value::Integer(1.into())),
            ]))
        }

        fn list(&self, block: &str) -> Result<Vec<Relay>, String> {
            self.counted(block).map(|(relays, _)| relays)
        }

        /// The relays listed, and how many nodes were fetched.
        fn counted(&self, block: &str) -> Result<(Vec<Relay>, usize), String> {
            let mut fetched = 0;
            let relays = list(block, |cid| {
                fetched += 1;
                self.0.get(cid).cloned().ok_or(format!("no {cid}"))
            })?;
            Ok((relays, fetched))
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
            entry("relay/alice", "https://not-an-address.example"),
            entry(format!("relay/{one}/x"), "https://run-on.example"),
            entry(format!("relay/{}", account(5)), "https://127.0.0.1"),
            entry("relax/x", "https://other.example"),
            entry(format!("user/{one}/name"), "https://user.example"),
            entry("child/x", "https://child.example"),
        ];
        let mut store = Store::default();
        let block = store.block(&entries);
        let mut relays = store.list(&block).unwrap();
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
        let block = store.block(&[entry("child/x", "1")]);
        assert_eq!(store.list(&block).unwrap(), []);
    }

    #[test]
    fn value_reads_one_key_whatever_it_holds() {
        let (one, two) = (account(1), account(2));
        let entries = [
            entry(format!("relay/{one}"), "https://one.example"),
            entry(format!("relay/{one}x"), "not a url"),
            entry("relay/", "short"),
            entry(format!("user/{two}"), "x"),
        ];
        let mut store = Store::default();
        let block = store.block(&entries);
        let read = |key: &str| {
            super::value(&block, key, |cid| {
                store.0.get(cid).cloned().ok_or(format!("no {cid}"))
            })
        };
        assert_eq!(
            read(&format!("relay/{one}")).unwrap().as_deref(),
            Some("https://one.example")
        );
        assert_eq!(
            read(&format!("relay/{one}x")).unwrap().as_deref(),
            Some("not a url")
        );
        assert_eq!(read("relay/").unwrap().as_deref(), Some("short"));
        for absent in [
            format!("relay/{two}"),
            format!("relay/{one}xy"),
            format!("relay/{}", &one[..10]),
            "relay".into(),
            "".into(),
        ] {
            assert_eq!(read(&absent).unwrap(), None, "{absent}");
        }

        // Bytes that are not the node's are refused.
        let refused = super::value(&block, "relay/", |_| Ok(b"\xa0".to_vec()));
        assert!(refused.unwrap_err().contains("not the ones it names"));
    }

    /// A chain of nodes with empty prefixes, which only a hostile block
    /// holds, is read up to [`MAX_VALUE_NODES`]; a node over
    /// [`MAX_NODE_BYTES`] is refused.
    #[test]
    fn value_reads_a_bounded_walk() {
        let key = format!("relay/{}", account(1));
        let mut store = Store::default();
        let chain = |store: &mut Store, empty: usize, value: &str| {
            let mut at = store.put(map(vec![
                ("prefix", text(&key)),
                ("value", text(value)),
                ("children", Value::Array(vec![])),
            ]));
            for _ in 0..empty {
                let child = map(vec![("key", text("r")), ("value", to_link(&at))]);
                at = store.put(map(vec![
                    ("prefix", text("")),
                    ("children", Value::Array(vec![child])),
                ]));
            }
            let child = map(vec![("key", text("r")), ("value", to_link(&at))]);
            store.commit(Value::Array(vec![child]))
        };
        let read = |store: &Store, block: &str| {
            super::value(block, &key, |cid| {
                store.0.get(cid).cloned().ok_or(format!("no {cid}"))
            })
        };
        // Block, state, root, the empty nodes and the entry.
        let most = chain(&mut store, MAX_VALUE_NODES - 4, "https://r.example");
        assert_eq!(
            read(&store, &most).unwrap().as_deref(),
            Some("https://r.example")
        );
        let over = chain(&mut store, MAX_VALUE_NODES - 3, "https://r.example");
        assert!(read(&store, &over).unwrap_err().contains("more than"));

        let big = "x".repeat(MAX_NODE_BYTES);
        let block = chain(&mut store, 0, &big);
        assert!(read(&store, &block)
            .unwrap_err()
            .contains("bytes, more than"));
    }

    #[test]
    fn a_relay_url_is_https_to_a_public_host() {
        for url in [
            "https://relay.example",
            "https://relay.example:8443/base",
            "https://8.8.8.8",
            "https://[2606:4700::1111]",
            "https://100.128.0.1",
            "https://relay.example.",
        ] {
            assert!(relay_url(url).is_some(), "{url}");
        }
        for url in [
            "http://relay.example",
            "wss://relay.example",
            "https://user@relay.example",
            "https://user:pass@relay.example",
            "https://localhost",
            "https://relay.localhost",
            "https://127.0.0.1",
            "https://0.0.0.0",
            "https://10.0.0.1",
            "https://172.16.0.1",
            "https://192.168.1.1",
            "https://169.254.169.254",
            "https://[::1]",
            "https://[::]",
            "https://[fd00::1]",
            "https://[fe80::1]",
            "https://[::ffff:127.0.0.1]",
            "https://[::ffff:10.0.0.1]",
            "https://localhost.",
            "https://localhost..",
            "https://relay.localhost.",
            "https://[::127.0.0.1]",
            "https://[::10.0.0.1]",
            "https://100.64.0.1",
            "https://100.127.255.255",
            "https://0.1.2.3",
            "https://255.255.255.255",
            "https://224.0.0.1",
            "https://[ff02::1]",
        ] {
            assert!(relay_url(url).is_none(), "{url}");
        }
    }

    /// `{key, value: {rawCID}}`, a child under `key`.
    fn child(key: &str, cid: &str) -> Value {
        map(vec![("key", text(key)), ("value", to_link(cid))])
    }

    /// The root's one child: the node `relay/`, over `children`.
    fn under_prefix(store: &mut Store, children: Vec<Value>) -> String {
        let prefix = store.put(map(vec![
            ("prefix", text(PREFIX)),
            ("children", Value::Array(children)),
        ]));
        store.commit(Value::Array(vec![child("r", &prefix)]))
    }

    #[test]
    fn a_node_named_many_times_is_read_once() {
        // Each level's node has every child the next level's one node.
        let mut store = Store::default();
        let mut below = store.put(map(vec![
            ("prefix", text("z")),
            ("children", Value::Array(vec![])),
        ]));
        for _ in 0..20 {
            let children = (0..16).map(|_| child("z", &below)).collect();
            below = store.put(map(vec![
                ("prefix", text("z")),
                ("children", Value::Array(children)),
            ]));
        }
        let block = under_prefix(&mut store, vec![child("z", &below)]);
        let (relays, fetched) = store.counted(&block).unwrap();
        assert_eq!(relays, []);
        // The block, its state, the root, `relay/` and the 21 levels.
        assert_eq!(fetched, 25);
    }

    #[test]
    fn a_valueless_chain_stops_at_the_longest_key() {
        let mut store = Store::default();
        let mut below = store.put(map(vec![
            ("prefix", text("q")),
            ("children", Value::Array(vec![])),
        ]));
        for _ in 0..2 * MAX_NODES {
            below = store.put(map(vec![
                ("prefix", text("q")),
                ("children", Value::Array(vec![child("q", &below)])),
            ]));
        }
        let block = under_prefix(&mut store, vec![child("q", &below)]);
        let (relays, fetched) = store.counted(&block).unwrap();
        assert_eq!(relays, []);
        // The block, its state, the root, `relay/`, and one node a byte down
        // to the first key longer than the longest.
        assert_eq!(fetched, 4 + MAX_PATH_BYTES - PREFIX.len() + 1);
    }

    #[test]
    fn a_trie_of_more_nodes_than_its_entries_need_is_cut_off() {
        // 40 valueless nodes of 40 valueless nodes each.
        let mut store = Store::default();
        let middles = (0..40)
            .map(|i| {
                let leaves = (0..40)
                    .map(|j| {
                        let key = format!("l{i}-{j}");
                        child(&key[..1], &trie_node(&mut store, &key, None, vec![]))
                    })
                    .collect::<Vec<_>>();
                let key = format!("m{i}");
                let middle = trie_node(&mut store, &key, None, leaves);
                child(&key[..1], &middle)
            })
            .collect();
        let block = under_prefix(&mut store, middles);
        let (relays, fetched) = store.counted(&block).unwrap();
        assert_eq!(relays, []);
        assert_eq!(fetched, MAX_NODES);
    }

    /// A node under `relay/`: `prefix`, `value` if any, and `children`.
    fn trie_node(
        store: &mut Store,
        prefix: &str,
        value: Option<Value>,
        children: Vec<Value>,
    ) -> String {
        let mut fields = vec![("prefix", text(prefix))];
        fields.extend(value.map(|value| ("value", value)));
        fields.push(("children", Value::Array(children)));
        store.put(map(fields))
    }

    #[test]
    fn a_node_over_the_caps_is_refused() {
        let mut store = Store::default();
        let big = store.put(map(vec![("padding", text(&"x".repeat(MAX_NODE_BYTES)))]));
        let mut listing = Listing::new(&big).unwrap();
        assert!(listing.give(&big, &store.0[&big]).is_err());

        let leaf = trie_node(&mut store, "q", None, vec![]);
        let fan = |n| {
            (0..n)
                .map(|i| child(&format!("{i}"), &leaf))
                .collect::<Vec<_>>()
        };
        let at_most = under_prefix(&mut store, fan(MAX_CHILDREN));
        assert!(store.list(&at_most).is_ok());
        let over = under_prefix(&mut store, fan(MAX_CHILDREN + 1));
        assert!(store.list(&over).is_err());
    }

    #[test]
    fn a_branch_below_the_longest_key_is_not_read() {
        let mut store = Store::default();
        let step = "q".repeat(100);
        let mut below = trie_node(
            &mut store,
            &step,
            Some(text("https://deep.example")),
            vec![],
        );
        for _ in 0..20 {
            below = trie_node(&mut store, &step, None, vec![child("q", &below)]);
        }
        let block = under_prefix(&mut store, vec![child("q", &below)]);
        let (relays, fetched) = store.counted(&block).unwrap();
        assert_eq!(relays, []);
        // The block, its state, the root, `relay/`, and the chain down to
        // the first node whose key is longer than the longest.
        assert_eq!(fetched, 4 + MAX_PATH_BYTES.div_ceil(100));
    }

    #[test]
    fn a_malformed_entry_under_the_prefix_is_skipped() {
        let mut store = Store::default();
        let good = account(1);
        let leaf = trie_node(
            &mut store,
            &good,
            Some(text("https://good.example")),
            vec![],
        );
        let number = trie_node(&mut store, "d", Some(Value::Integer(1.into())), vec![]);
        let shapeless = store.put(text("not a node"));
        let block = under_prefix(
            &mut store,
            vec![
                child(&good[..1], &leaf),
                map(vec![("key", text("c"))]),
                child("d", &number),
                child("e", &shapeless),
            ],
        );
        let relays = store.list(&block).unwrap();
        assert_eq!(relays.len(), 1);
        assert_eq!(relays[0].account, good);

        // Above it, a node of the wrong shape is still refused.
        let wrong = store.put(map(vec![("prefix", Value::Integer(1.into()))]));
        let block = store.commit(Value::Array(vec![child("r", &wrong)]));
        assert!(store.list(&block).is_err());
    }

    #[test]
    fn a_node_is_only_the_bytes_its_cid_names() {
        let mut store = Store::default();
        let block = store.block(&[entry(format!("relay/{}", account(1)), "https://a.example")]);
        let mut listing = Listing::new(&block).unwrap();
        let block = listing.wants().remove(0);
        let (other, bytes) = store.0.iter().find(|(cid, _)| **cid != block).unwrap();
        assert!(listing.give(&block, bytes).is_err());
        assert_eq!(listing.wants(), std::slice::from_ref(&block));
        listing.give(&block, &store.0[&block]).unwrap();
        assert_ne!(listing.wants(), [block]);
        // A node in the block's place that is no block.
        let mut listing = Listing::new(other).unwrap();
        assert!(listing.give(other, bytes).is_err());
    }

    #[test]
    fn stops_at_max_entries_wherever_key_order_puts_them() {
        let entries: Vec<_> = (0..MAX_ENTRIES as u32 + 88)
            .map(|i| entry(format!("relay/{}", account(i)), "https://r.example"))
            .collect();
        let mut store = Store::default();
        let block = store.block(&entries);
        let listed = || -> BTreeSet<String> {
            let relays = store.list(&block).unwrap();
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

    /// A Volume's other nodes are kept only if they are the bytes their CIDs
    /// name, of at most [`MAX_NODE_BYTES`], and only up to [`MAX_NODES`].
    #[test]
    fn a_volume_keeps_only_nodes_it_could_read() {
        let bytes = |i: usize| format!("node {i}").into_bytes();
        let node = |i: usize| (cid(&bytes(i)), bytes(i));
        let (root, root_bytes) = node(0);
        let (good, good_bytes) = node(1);
        let big = vec![b'x'; MAX_NODE_BYTES + 1];
        let mut volume = BTreeMap::from([
            (root.clone(), root_bytes.clone()),
            (good.clone(), good_bytes.clone()),
            (node(2).0, bytes(3)),
            (cid(&big), big),
        ]);
        let mut kept = BTreeMap::new();
        assert_eq!(held(&mut kept, &root, volume.clone()), Some(root_bytes));
        assert_eq!(kept, BTreeMap::from([(good, good_bytes)]));
        volume.remove(&root);
        assert_eq!(held(&mut kept, &root, volume), None, "no root");

        // Filler past MAX_NODES is dropped, however many answers bring it.
        let mut kept = BTreeMap::new();
        for answer in 0..3 {
            let filler = (0..MAX_NODES).map(|i| node(1 + answer * MAX_NODES + i));
            let volume = filler.chain([node(0)]).collect();
            held(&mut kept, &root, volume).unwrap();
            assert_eq!(kept.len(), MAX_NODES);
        }
    }

    #[test]
    fn a_listing_starts_from_a_block_cid() {
        let block = account(1);
        assert!(Listing::new(&block).is_ok());
        for block in [
            String::new(),
            "x".into(),
            format!("{block}@{block}"),
            format!("{block}@"),
            format!("@{block}"),
        ] {
            assert!(Listing::new(&block).is_err(), "{block}");
        }
    }
}
