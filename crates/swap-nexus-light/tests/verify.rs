//! Golden vectors from live mainnet (`fixtures/mainnet`: the `/volumes/<cid>`
//! archives of 32 consecutive headers, tip first in `chain.txt`, and the
//! tip state's path to the tip's reward address, `account.txt`), and every
//! way a lying node could bend them.

use std::path::PathBuf;

use ciborium::Value;
use swap_nexus_light::{
    cid_of, parse_archive, prove_account, verify_chain, Account, Error, DEFAULT_WORK_FLOOR,
};

const ANY_TARGET: [u8; 32] = [0xff; 32];

fn fixtures() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/mainnet")
}

fn lines(name: &str) -> Vec<String> {
    std::fs::read_to_string(fixtures().join(name))
        .unwrap()
        .lines()
        .map(str::to_owned)
        .collect()
}

/// Every node in every fixture archive, by CID.
fn nodes() -> Vec<(String, Vec<u8>)> {
    let mut out: Vec<_> = std::fs::read_dir(fixtures())
        .unwrap()
        .map(|e| e.unwrap().path())
        .filter(|path| path.extension().is_some_and(|x| x == "vol"))
        .flat_map(|path| parse_archive(&std::fs::read(path).unwrap()).unwrap())
        .collect();
    out.sort();
    out.dedup();
    out
}

fn archive_of(cid: &str) -> Vec<u8> {
    std::fs::read(fixtures().join(format!("{cid}.vol"))).unwrap()
}

/// The live headers, tip first, each taken out of its own archive.
fn live_headers() -> Vec<(String, Vec<u8>)> {
    lines("chain.txt")
        .into_iter()
        .map(|cid| {
            let entries = parse_archive(&archive_of(&cid)).unwrap();
            let bytes = entries.into_iter().find(|(c, _)| *c == cid).unwrap().1;
            (cid, bytes)
        })
        .collect()
}

fn decode(bytes: &[u8]) -> Value {
    ciborium::from_reader(bytes).unwrap()
}

fn encode(value: &Value) -> Vec<u8> {
    let mut out = Vec::new();
    ciborium::into_writer(value, &mut out).unwrap();
    out
}

fn field<'a>(node: &'a mut Value, key: &str) -> &'a mut Value {
    node.as_map_mut()
        .unwrap()
        .iter_mut()
        .find(|(k, _)| k.as_text() == Some(key))
        .map(|(_, v)| v)
        .unwrap()
}

fn get<'a>(node: &'a Value, key: &str) -> Option<&'a Value> {
    node.as_map()
        .unwrap()
        .iter()
        .find(|(k, _)| k.as_text() == Some(key))
        .map(|(_, v)| v)
}

fn link(cid: &str) -> Value {
    Value::Map(vec![(
        Value::Text("rawCID".into()),
        Value::Text(cid.into()),
    )])
}

fn map(entries: Vec<(&str, Value)>) -> Value {
    Value::Map(
        entries
            .into_iter()
            .map(|(k, v)| (Value::Text(k.into()), v))
            .collect(),
    )
}

/// A node encoded, under its own CID.
fn bound(node: &Value) -> (String, Vec<u8>) {
    let bytes = encode(node);
    (cid_of(&bytes), bytes)
}

// ---- live mainnet ----

#[test]
fn live_chain_verifies() {
    let headers = live_headers();
    assert_eq!(headers.len(), 32);
    let chain = verify_chain(&headers, &DEFAULT_WORK_FLOOR).unwrap();
    assert_eq!(chain.tip().height, 5986);
    assert_eq!(chain.blocks.last().unwrap().height, 5955);
    for (block, (cid, _)) in chain.blocks.iter().zip(&headers) {
        assert_eq!(block.cid, *cid);
    }
    assert_eq!(chain.tip().post_state, lines("account.txt")[0]);
    assert_eq!(chain.depth_of(&headers[31].0), Some(32));
    assert_eq!(chain.depth_of(&headers[0].0), Some(1));
    assert_eq!(chain.depth_of("bafy-not-there"), None);
}

#[test]
fn live_ciborium_round_trip() {
    // The forgeries below re-encode live nodes with ciborium; this pins
    // that re-encoding an untouched node gives back the same bytes.
    for (_, bytes) in live_headers() {
        assert_eq!(encode(&decode(&bytes)), bytes);
    }
}

#[test]
fn live_account_proves() {
    let account = lines("account.txt");
    let (root, address) = (&account[0], &account[1]);
    let proved = prove_account(root, &nodes(), address).unwrap();
    assert_eq!(account[2], proved.balance.to_string());
    // The reward address never sent a transaction: no `_nonce_` entry.
    assert_eq!(account[3], "None");
    assert_eq!(
        proved,
        Account {
            balance: 25_165_824,
            nonce: None
        }
    );
    assert_eq!(proved.next_nonce(), Some(0));
}

#[test]
fn live_absent_account_is_zero() {
    let root = &lines("account.txt")[0];
    // A well-formed address no one holds; the live trie proves it absent.
    let nobody = cid_of(b"nobody");
    assert_eq!(
        prove_account(root, &nodes(), &nobody).unwrap(),
        Account {
            balance: 0,
            nonce: None
        }
    );
}

// ---- headers that must be refused ----

#[test]
fn flipped_header_byte_is_refused() {
    let mut headers = live_headers();
    let last = headers[5].1.len() - 1;
    headers[5].1[last] ^= 1;
    assert_eq!(
        verify_chain(&headers, &DEFAULT_WORK_FLOOR),
        Err(Error::CidMismatch {
            cid: headers[5].0.clone()
        })
    );
}

#[test]
fn wrong_cid_is_refused() {
    let mut headers = live_headers();
    headers[3].0 = headers[4].0.clone();
    assert!(matches!(
        verify_chain(&headers, &DEFAULT_WORK_FLOOR),
        Err(Error::CidMismatch { .. })
    ));
}

#[test]
fn hash_above_target_is_refused() {
    let mut headers = live_headers();
    let mut node = decode(&headers[0].1);
    let Value::Integer(nonce) = field(&mut node, "nonce") else {
        panic!()
    };
    *nonce = (u64::try_from(*nonce).unwrap() + 1).into();
    headers[0] = bound(&node);
    assert_eq!(
        verify_chain(&headers[..1], &DEFAULT_WORK_FLOOR),
        Err(Error::InsufficientWork {
            cid: headers[0].0.clone()
        })
    );
}

#[test]
fn zero_target_is_refused() {
    let (cid, bytes) = bound(&synthetic_chain(1, |_, _| {}).remove(0));
    let mut node = decode(&bytes);
    *field(&mut node, "target") = Value::Text("0x0".into());
    let header = bound(&node);
    assert_ne!(header.0, cid);
    assert_eq!(
        verify_chain(std::slice::from_ref(&header), &ANY_TARGET),
        Err(Error::InsufficientWork { cid: header.0 })
    );
}

#[test]
fn target_above_floor_is_refused() {
    let headers = live_headers();
    // The oldest live block is the easiest; a floor just under its target.
    let mut node = decode(&headers[31].1);
    let Value::Text(target) = field(&mut node, "target").clone() else {
        panic!()
    };
    let mut floor = [0u8; 32];
    let digits = format!("{:0>64}", &target[2..]);
    for (i, byte) in floor.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&digits[2 * i..2 * i + 2], 16).unwrap();
    }
    assert_eq!(
        verify_chain(&headers, &floor).map(|c| c.blocks.len()),
        Ok(32)
    );
    floor[10] -= 1;
    assert_eq!(
        verify_chain(&headers, &floor),
        Err(Error::BelowFloor {
            cid: headers[31].0.clone()
        })
    );
}

#[test]
fn broken_parent_link_is_refused() {
    let mut headers = live_headers();
    headers.remove(10);
    assert_eq!(
        verify_chain(&headers, &DEFAULT_WORK_FLOOR),
        Err(Error::BrokenLink {
            cid: headers[9].0.clone(),
            reason: "parent is not the next header"
        })
    );
}

#[test]
fn reordered_headers_are_refused() {
    let mut headers = live_headers();
    headers.reverse();
    assert!(matches!(
        verify_chain(&headers, &DEFAULT_WORK_FLOOR),
        Err(Error::BrokenLink { .. })
    ));
}

/// A chain of `n` easy (any-hash) headers, tip first, after `edit` changes
/// each one (given its index from the tip). Linked by CID after the edits.
fn synthetic_chain(n: usize, edit: impl Fn(usize, &mut Value)) -> Vec<Value> {
    let some = |tag: &str| link(&cid_of(tag.as_bytes()));
    let state = |h: usize| cid_of(format!("state {h}").as_bytes());
    let mut out: Vec<Value> = Vec::new();
    let mut parent: Option<String> = None;
    for h in 0..n {
        let mut entries = vec![
            ("version", Value::Integer(1.into())),
            ("transactions", some("txs")),
            ("target", Value::Text(format!("0x{}", "f".repeat(64)))),
            ("nextTarget", Value::Text(format!("0x{}", "f".repeat(64)))),
            ("spec", some("spec")),
            ("parentState", some("parent state")),
            ("prevState", link(&state(h))),
            ("postState", link(&state(h + 1))),
            ("children", some("children")),
            ("height", Value::Integer((h as u64 + 100).into())),
            ("timestamp", Value::Integer((1_000 + h as i64).into())),
            ("nonce", Value::Integer(0.into())),
        ];
        if let Some(p) = &parent {
            entries.push(("parent", link(p)));
        }
        let mut node = map(entries);
        edit(n - 1 - h, &mut node);
        parent = Some(bound(&node).0);
        out.push(node);
    }
    out.reverse();
    out
}

fn bind_all(nodes: &[Value]) -> Vec<(String, Vec<u8>)> {
    nodes.iter().map(bound).collect()
}

#[test]
fn synthetic_chain_verifies() {
    let headers = bind_all(&synthetic_chain(4, |_, _| {}));
    let chain = verify_chain(&headers, &ANY_TARGET).unwrap();
    assert_eq!(chain.tip().height, 103);
    // One header is a run on its own: its parent is not checked.
    assert!(verify_chain(&headers[..1], &ANY_TARGET).is_ok());
    assert_eq!(
        verify_chain(&[], &ANY_TARGET),
        Err(Error::Malformed("no headers"))
    );
}

/// Refused at `headers[at]`, the child side of the first bad link.
fn refused_link(at: usize, edit: impl Fn(usize, &mut Value), reason: &'static str) {
    let headers = bind_all(&synthetic_chain(4, edit));
    assert_eq!(
        verify_chain(&headers, &ANY_TARGET),
        Err(Error::BrokenLink {
            cid: headers[at].0.clone(),
            reason
        })
    );
}

#[test]
fn prev_state_not_parent_post_state_is_refused() {
    refused_link(
        1,
        |i, node| {
            if i == 1 {
                *field(node, "prevState") = link(&cid_of(b"elsewhere"));
            }
        },
        "prevState is not the parent's postState",
    );
}

#[test]
fn non_increasing_timestamp_is_refused() {
    for ts in [1_001, 1_000] {
        refused_link(
            1,
            move |i, node| {
                if i == 1 {
                    *field(node, "timestamp") = Value::Integer(ts.into());
                }
            },
            "timestamp not after the parent's",
        );
    }
}

#[test]
fn wrong_height_is_refused() {
    refused_link(
        0,
        |i, node| {
            if i == 1 {
                *field(node, "height") = Value::Integer(103.into());
            }
        },
        "height is not the parent's + 1",
    );
}

#[test]
fn changed_spec_is_refused() {
    refused_link(
        0,
        |i, node| {
            if i == 1 {
                *field(node, "spec") = link(&cid_of(b"other spec"));
            }
        },
        "spec differs from the parent's",
    );
}

#[test]
fn target_easier_than_parent_next_target_is_refused() {
    refused_link(
        1,
        |i, node| {
            if i == 2 {
                *field(node, "nextTarget") = Value::Text(format!("0x{}", "f".repeat(63)));
            }
        },
        "target easier than the parent's nextTarget",
    );
}

#[test]
fn malformed_headers_are_refused() {
    let edits: [(&str, Value); 5] = [
        ("version", Value::Integer(2.into())),
        ("spec", Value::Text("bafy".into())),
        ("prevState", link("QmNotStandard")),
        ("target", Value::Text("0xzz".into())),
        ("rewardRecipient", Value::Text("not an address".into())),
    ];
    for (key, value) in edits {
        let mut node = synthetic_chain(1, |_, _| {}).remove(0);
        match node
            .as_map_mut()
            .unwrap()
            .iter_mut()
            .find(|(k, _)| k.as_text() == Some(key))
        {
            Some((_, v)) => *v = value,
            None => node
                .as_map_mut()
                .unwrap()
                .push((Value::Text(key.into()), value)),
        }
        assert!(
            matches!(
                verify_chain(&[bound(&node)], &ANY_TARGET),
                Err(Error::Malformed(_))
            ),
            "{key}"
        );
    }
    let mut node = synthetic_chain(1, |_, _| {}).remove(0);
    let encrypted = map(vec![
        ("rawCID", Value::Text(cid_of(b"x"))),
        ("encryptionInfo", Value::Text("key".into())),
    ]);
    *field(&mut node, "postState") = encrypted;
    assert_eq!(
        verify_chain(&[bound(&node)], &ANY_TARGET),
        Err(Error::Malformed("encrypted link"))
    );
}

// ---- state that must be refused ----

/// The live trie node holding the reward address's balance.
fn balance_node() -> (String, Value) {
    let address = &lines("account.txt")[1];
    for (cid, bytes) in nodes() {
        let node = decode(&bytes);
        if let Some(Value::Text(prefix)) = get(&node, "prefix") {
            if address.ends_with(prefix.as_str()) && get(&node, "value").is_some() {
                return (cid, node);
            }
        }
    }
    panic!("no balance node in the fixtures");
}

/// The fixture nodes with the one under `cid` swapped for `node`.
fn swapped(cid: &str, node: (String, Vec<u8>)) -> Vec<(String, Vec<u8>)> {
    let mut out: Vec<_> = nodes().into_iter().filter(|(c, _)| c != cid).collect();
    out.push(node);
    out
}

#[test]
fn forged_state_node_is_refused() {
    let account = lines("account.txt");
    let (cid, mut node) = balance_node();
    *field(&mut node, "value") = Value::Integer(u64::MAX.into());
    let forged = swapped(&cid, (cid.clone(), encode(&node)));
    assert_eq!(
        prove_account(&account[0], &forged, &account[1]),
        Err(Error::CidMismatch { cid })
    );
}

#[test]
fn trie_that_lies_about_absence_is_refused() {
    let account = lines("account.txt");
    let (cid, mut node) = balance_node();
    // The node with its value dropped, bound to its own (new) CID, served
    // in place of the real one: the walk cannot find the committed node.
    node.as_map_mut()
        .unwrap()
        .retain(|(k, _)| k.as_text() != Some("value"));
    let lie = swapped(&cid, bound(&node));
    assert_eq!(
        prove_account(&account[0], &lie, &account[1]),
        Err(Error::Missing { cid: cid.clone() })
    );
    // Leaving the node out reads as missing too, never as a zero balance.
    let withheld: Vec<_> = nodes().into_iter().filter(|(c, _)| *c != cid).collect();
    assert_eq!(
        prove_account(&account[0], &withheld, &account[1]),
        Err(Error::Missing { cid })
    );
}

#[test]
fn unbound_state_root_is_refused() {
    let account = lines("account.txt");
    let root = cid_of(b"some other state");
    assert_eq!(
        prove_account(&root, &nodes(), &account[1]),
        Err(Error::Missing { cid: root })
    );
}

/// A small state: accounts `bafyA` (balance 1, nonce 7) and `bafyB`
/// (balance 2), the two balance keys split under the prefix `bafy`.
fn small_state(edit_split: impl Fn(&mut Value)) -> (String, Vec<(String, Vec<u8>)>) {
    let leaf = |prefix: &str, value: u64| {
        map(vec![
            ("prefix", Value::Text(prefix.into())),
            ("value", Value::Integer(value.into())),
            ("children", Value::Array(vec![])),
        ])
    };
    let entry =
        |key: &str, cid: &str| map(vec![("key", Value::Text(key.into())), ("value", link(cid))]);
    let a = bound(&leaf("A", 1));
    let b = bound(&leaf("B", 2));
    let mut split = map(vec![
        ("prefix", Value::Text("bafy".into())),
        (
            "children",
            Value::Array(vec![entry("A", &a.0), entry("B", &b.0)]),
        ),
    ]);
    edit_split(&mut split);
    let split = bound(&split);
    let nonce = bound(&leaf("_nonce_bafyA", 7));
    let accounts = bound(&map(vec![
        ("count", Value::Integer(3.into())),
        (
            "children",
            Value::Array(vec![entry("_", &nonce.0), entry("b", &split.0)]),
        ),
    ]));
    let other = link(&cid_of(b"other"));
    let state = bound(&map(vec![
        ("accountState", link(&accounts.0)),
        ("generalState", other.clone()),
        ("depositState", other.clone()),
        ("receiptState", other),
    ]));
    let root = state.0.clone();
    let nodes = [state, accounts, split, a, b, nonce];
    (root, nodes.to_vec())
}

#[test]
fn small_state_lookups() {
    let (root, nodes) = small_state(|_| {});
    let at = |address: &str| prove_account(&root, &nodes, address);
    assert_eq!(
        at("bafyA"),
        Ok(Account {
            balance: 1,
            nonce: Some(7)
        })
    );
    assert_eq!(at("bafyA").unwrap().next_nonce(), Some(8));
    assert_eq!(
        at("bafyB"),
        Ok(Account {
            balance: 2,
            nonce: None
        })
    );
    // A key the split's prefix rules out, one under a missing child, one
    // ending at the valueless split, one past a leaf.
    for absent in ["bxfy", "bafyC", "bafy", "bafyAA", "c"] {
        assert_eq!(
            at(absent),
            Ok(Account {
                balance: 0,
                nonce: None
            }),
            "{absent}"
        );
    }
    assert!(matches!(at("a/b"), Err(Error::Malformed(_))));
    assert!(matches!(at(""), Err(Error::Malformed(_))));
    assert!(matches!(at("bafy\u{212a}"), Err(Error::Malformed(_))));
}

#[test]
fn malformed_trie_nodes_are_refused() {
    let entry = |key: &str| {
        map(vec![
            ("key", Value::Text(key.into())),
            ("value", link(&cid_of(b"x"))),
        ])
    };
    type Edit = Box<dyn Fn(&mut Value)>;
    let edits: Vec<Edit> = vec![
        // The same character twice (cashew's `decodeChildren` throws).
        Box::new(move |n| {
            field(n, "children")
                .as_array_mut()
                .unwrap()
                .push(entry("A"))
        }),
        // A key longer than one character.
        Box::new(move |n| {
            field(n, "children")
                .as_array_mut()
                .unwrap()
                .push(entry("CD"))
        }),
        // A prefix outside visible ASCII.
        Box::new(|n| *field(n, "prefix") = Value::Text("bafy\u{212a}".into())),
        // A value that is not an integer.
        Box::new(|n| {
            n.as_map_mut()
                .unwrap()
                .push((Value::Text("value".into()), Value::Text("1".into())))
        }),
    ];
    for edit in edits {
        let (root, nodes) = small_state(edit);
        assert!(matches!(
            prove_account(&root, &nodes, "bafyA"),
            Err(Error::Malformed(_))
        ));
    }
}
