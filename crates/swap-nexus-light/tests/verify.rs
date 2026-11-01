//! Golden vectors from live mainnet (`fixtures/mainnet`: the `/volumes/<cid>`
//! archives of 32 consecutive headers, tip first in `chain.txt`, and the
//! tip state's path to the tip's reward address, `account.txt`; and in
//! `fixtures/mainnet/fresh`, header-only archives fetched later: 8
//! consecutive headers up to the tip, `run.txt`, and headers from block 1
//! on, `singles.txt`), and every way a lying node could bend them.

use std::path::PathBuf;

use ciborium::Value;
use swap_nexus_light::{
    cid_of, parse_archive, prove_account, verify_chain, Account, ChainParams, Error,
    DEFAULT_WORK_FLOOR, MAINNET_SPEC, MAX_FUTURE_MS, MAX_TIP_AGE_MS, U256,
};

const ANY_TARGET: [u8; 32] = [0xff; 32];

fn fixtures() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/mainnet")
}

fn mainnet() -> ChainParams {
    ChainParams::default()
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

/// The headers listed in `dir/list`, each taken out of its own archive.
fn headers_in(dir: &str, list: &str) -> Vec<(String, Vec<u8>)> {
    lines(&format!("{dir}/{list}"))
        .into_iter()
        .map(|cid| {
            let file = fixtures().join(format!("{dir}/{cid}.vol"));
            let entries = parse_archive(&std::fs::read(file).unwrap()).unwrap();
            let bytes = entries.into_iter().find(|(c, _)| *c == cid).unwrap().1;
            (cid, bytes)
        })
        .collect()
}

/// The live headers, tip first.
fn live_headers() -> Vec<(String, Vec<u8>)> {
    headers_in(".", "chain.txt")
}

/// The live tip's timestamp: "now" for the live chain.
fn live_now() -> i64 {
    timestamp_of(&live_headers()[0].1)
}

fn timestamp_of(header: &[u8]) -> i64 {
    let node = decode(header);
    i64::try_from(get(&node, "timestamp").unwrap().as_integer().unwrap()).unwrap()
}

fn verify_live(headers: &[(String, Vec<u8>)]) -> Result<swap_nexus_light::VerifiedChain, Error> {
    verify_chain(headers, &DEFAULT_WORK_FLOOR, &mainnet(), live_now())
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
    let chain = verify_live(&headers).unwrap();
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

fn u256_of(text: &str) -> U256 {
    let digits = format!("{:0>64}", text.trim_start_matches("0x"));
    let mut out = [0u8; 32];
    for (i, byte) in out.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&digits[2 * i..2 * i + 2], 16).unwrap();
    }
    out
}

fn hex_text(value: &U256) -> Value {
    Value::Text(format!(
        "0x{}",
        value.iter().map(|b| format!("{b:02x}")).collect::<String>()
    ))
}

/// Every live header in the fixtures: the 32-block run, the fresh run to a
/// later tip, and the fresh headers from block 1 on.
fn every_live_header() -> Vec<(String, Vec<u8>)> {
    let mut all = live_headers();
    all.extend(headers_in("fresh", "run.txt"));
    all.extend(headers_in("fresh", "singles.txt"));
    all
}

#[test]
fn live_next_targets_follow_the_schedule() {
    // Golden vectors: Lattice's `calculateAsertTarget` at each header's own
    // height and timestamp, against the `nextTarget` mainnet committed.
    let mut heights = Vec::new();
    for (cid, bytes) in every_live_header() {
        let node = decode(&bytes);
        let height = u64::try_from(get(&node, "height").unwrap().as_integer().unwrap()).unwrap();
        let committed = u256_of(get(&node, "nextTarget").unwrap().as_text().unwrap());
        assert_eq!(
            mainnet().next_target(height, timestamp_of(&bytes)),
            committed,
            "{cid} at {height}"
        );
        assert_eq!(
            get(&node, "spec").unwrap(),
            &link(MAINNET_SPEC),
            "{cid} at {height}"
        );
        heights.push(height);
    }
    heights.sort();
    heights.dedup();
    assert_eq!(heights.len(), 48);
    assert_eq!((heights[0], *heights.last().unwrap()), (1, 5990));
}

#[test]
fn fresh_live_headers_verify() {
    let run = headers_in("fresh", "run.txt");
    let now = timestamp_of(&run[0].1);
    let chain = verify_chain(&run, &DEFAULT_WORK_FLOOR, &mainnet(), now).unwrap();
    assert_eq!(
        (chain.tip().height, chain.blocks.last().unwrap().height),
        (5990, 5983)
    );
    // The early headers are far easier than the floor; alone, each still
    // carries its proof of work, the spec and its scheduled `nextTarget`.
    for header in headers_in("fresh", "singles.txt") {
        let now = timestamp_of(&header.1);
        let chain = verify_chain(std::slice::from_ref(&header), &ANY_TARGET, &mainnet(), now);
        assert!(chain.is_ok(), "{}: {chain:?}", header.0);
    }
}

#[test]
fn future_timestamp_is_refused() {
    let headers = live_headers();
    let now = live_now() - MAX_FUTURE_MS;
    assert!(verify_chain(&headers, &DEFAULT_WORK_FLOOR, &mainnet(), now).is_ok());
    assert_eq!(
        verify_chain(&headers, &DEFAULT_WORK_FLOOR, &mainnet(), now - 1),
        Err(Error::FutureTimestamp {
            cid: headers[0].0.clone()
        })
    );
}

#[test]
fn stale_tip_is_refused() {
    let headers = live_headers();
    let now = live_now() + MAX_TIP_AGE_MS;
    assert!(verify_chain(&headers, &DEFAULT_WORK_FLOOR, &mainnet(), now).is_ok());
    assert_eq!(
        verify_chain(&headers, &DEFAULT_WORK_FLOOR, &mainnet(), now + 1),
        Err(Error::StaleTip {
            cid: headers[0].0.clone()
        })
    );
}

#[test]
fn wrong_spec_is_refused() {
    let headers = live_headers();
    let other = ChainParams {
        spec: cid_of(b"some other chain's spec"),
        ..mainnet()
    };
    assert_eq!(
        verify_chain(&headers, &DEFAULT_WORK_FLOOR, &other, live_now()),
        Err(Error::WrongSpec {
            cid: headers[0].0.clone()
        })
    );
}

#[test]
fn live_chain_under_another_schedule_is_refused() {
    // The same spec, the anchor an hour later: every live `nextTarget`
    // moves, so the tip is off the schedule.
    let headers = live_headers();
    let shifted = ChainParams {
        anchor_timestamp: mainnet().anchor_timestamp + 3_600_000,
        ..mainnet()
    };
    assert_eq!(
        verify_chain(&headers, &DEFAULT_WORK_FLOOR, &shifted, live_now()),
        Err(Error::OffSchedule {
            cid: headers[0].0.clone()
        })
    );
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
        verify_live(&headers),
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
        verify_live(&headers),
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
        verify_live(&headers[..1]),
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
        synthetic(std::slice::from_ref(&header), &ANY_TARGET),
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
        verify_chain(&headers, &floor, &mainnet(), live_now()).map(|c| c.blocks.len()),
        Ok(32)
    );
    floor[10] -= 1;
    assert_eq!(
        verify_chain(&headers, &floor, &mainnet(), live_now()),
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
        verify_live(&headers),
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
        verify_live(&headers),
        Err(Error::BrokenLink { .. })
    ));
}

/// The schedule the synthetic headers follow: anchored at their first
/// height and timestamp with the maximum target, one block a millisecond,
/// so a header on schedule carries the maximum as its `nextTarget`.
fn synthetic_params() -> ChainParams {
    ChainParams {
        spec: cid_of(b"spec"),
        anchor_height: 100,
        anchor_timestamp: 1_000,
        anchor_target: [0xff; 32],
        target_block_time: 1,
        half_life: 120,
    }
}

/// The clock the synthetic headers are checked at.
const SYNTHETIC_NOW: i64 = 1_000;

fn synthetic(
    headers: &[(String, Vec<u8>)],
    floor: &U256,
) -> Result<swap_nexus_light::VerifiedChain, Error> {
    verify_chain(headers, floor, &synthetic_params(), SYNTHETIC_NOW)
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
    let chain = synthetic(&headers, &ANY_TARGET).unwrap();
    assert_eq!(chain.tip().height, 103);
    // One header is a run on its own: its parent is not checked.
    assert!(synthetic(&headers[..1], &ANY_TARGET).is_ok());
    assert_eq!(
        synthetic(&[], &ANY_TARGET),
        Err(Error::Malformed("no headers"))
    );
}

/// Refused at `headers[at]`, the child side of the first bad link.
fn refused_link(at: usize, edit: impl Fn(usize, &mut Value), reason: &'static str) {
    let headers = bind_all(&synthetic_chain(4, edit));
    assert_eq!(
        synthetic(&headers, &ANY_TARGET),
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
    let headers = bind_all(&synthetic_chain(4, |i, node| {
        if i == 1 {
            *field(node, "spec") = link(&cid_of(b"other spec"));
        }
    }));
    assert_eq!(
        synthetic(&headers, &ANY_TARGET),
        Err(Error::WrongSpec {
            cid: headers[1].0.clone()
        })
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

/// One synthetic header at `height` and `timestamp`, whose target is the
/// maximum (any hash meets it) and whose `nextTarget` is `next_target`.
fn lone_header(height: u64, timestamp: i64, next_target: &U256) -> (String, Vec<u8>) {
    let mut node = synthetic_chain(1, |_, _| {}).remove(0);
    *field(&mut node, "height") = Value::Integer(height.into());
    *field(&mut node, "timestamp") = Value::Integer(timestamp.into());
    *field(&mut node, "nextTarget") = hex_text(next_target);
    bound(&node)
}

#[test]
fn next_target_off_by_one_is_refused() {
    // Ten blocks in ten-twelfths of a half-life: a twelfth of a doubling
    // harder than the anchor, so not saturated either way.
    let scheduled = synthetic_params().next_target(110, 1_000);
    assert!(scheduled < [0xff; 32] && scheduled > [0; 32]);
    let exact = lone_header(110, 1_000, &scheduled);
    assert!(synthetic(std::slice::from_ref(&exact), &ANY_TARGET).is_ok());
    // One below and one above, as 256-bit integers.
    let step = |by_one: fn(u8) -> (u8, bool)| {
        let mut out = scheduled;
        for byte in out.iter_mut().rev() {
            let (next, carry) = by_one(*byte);
            *byte = next;
            if !carry {
                break;
            }
        }
        out
    };
    let low = step(|b| b.overflowing_sub(1));
    let high = step(|b| b.overflowing_add(1));
    assert!(low < scheduled && scheduled < high);
    for off in [low, high] {
        let header = lone_header(110, 1_000, &off);
        assert_eq!(
            synthetic(std::slice::from_ref(&header), &ANY_TARGET),
            Err(Error::OffSchedule { cid: header.0 })
        );
    }
}

#[test]
fn height_below_the_anchor_is_refused() {
    // Below the anchor Lattice's function answers the anchor's target, which
    // this header carries; the schedule still does not cover it.
    let header = lone_header(99, 1_000, &[0xff; 32]);
    assert_eq!(
        synthetic(std::slice::from_ref(&header), &ANY_TARGET),
        Err(Error::OffSchedule { cid: header.0 })
    );
}

#[test]
fn fake_low_height_is_refused_by_the_floor() {
    // A mainnet header claiming height 2 at the live tip's time: far behind
    // schedule, so the schedule eases it to the maximum target, and a header
    // at that target is cheap. It is consistent with the schedule; the floor
    // is what refuses it.
    let now = live_now();
    let mut node = synthetic_chain(1, |_, _| {}).remove(0);
    let eased = mainnet().next_target(2, now);
    assert_eq!(eased, [0xff; 32]);
    *field(&mut node, "spec") = link(MAINNET_SPEC);
    *field(&mut node, "height") = Value::Integer(2.into());
    *field(&mut node, "timestamp") = Value::Integer(now.into());
    *field(&mut node, "target") = hex_text(&eased);
    *field(&mut node, "nextTarget") = hex_text(&eased);
    let header = bound(&node);
    let one = std::slice::from_ref(&header);
    assert!(verify_chain(one, &ANY_TARGET, &mainnet(), now).is_ok());
    assert_eq!(
        verify_chain(one, &DEFAULT_WORK_FLOOR, &mainnet(), now),
        Err(Error::BelowFloor { cid: header.0 })
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
                synthetic(&[bound(&node)], &ANY_TARGET),
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
        synthetic(&[bound(&node)], &ANY_TARGET),
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

/// Two standard addresses that part after the `bafyrei` every standard CID
/// starts with, and a third under each kind of absence: `c` shares `a`'s
/// eighth character and differs later, `d`'s eighth character is neither.
fn small_addresses() -> [String; 4] {
    let cids: Vec<String> = (0u32..)
        .map(|i| cid_of(&i.to_be_bytes()))
        .take(64)
        .collect();
    let at7 = |c: &String| c.as_bytes()[7];
    let a = cids[0].clone();
    let b = cids.iter().find(|c| at7(c) != at7(&a)).unwrap().clone();
    let c = cids[1..]
        .iter()
        .find(|c| at7(c) == at7(&a))
        .unwrap()
        .clone();
    let d = cids
        .iter()
        .find(|c| at7(c) != at7(&a) && at7(c) != at7(&b))
        .unwrap()
        .clone();
    [a, b, c, d]
}

/// A small state: accounts `a` (balance 1, nonce 7) and `b` (balance 2),
/// the two balance keys split under the prefix `bafyrei`.
fn small_state(edit_split: impl Fn(&mut Value)) -> (String, Vec<(String, Vec<u8>)>) {
    let [a, b, ..] = small_addresses();
    let leaf = |prefix: &str, value: u64| {
        map(vec![
            ("prefix", Value::Text(prefix.into())),
            ("value", Value::Integer(value.into())),
            ("children", Value::Array(vec![])),
        ])
    };
    let entry =
        |key: &str, cid: &str| map(vec![("key", Value::Text(key.into())), ("value", link(cid))]);
    let leaf_a = bound(&leaf(&a[7..], 1));
    let leaf_b = bound(&leaf(&b[7..], 2));
    let mut split = map(vec![
        ("prefix", Value::Text("bafyrei".into())),
        (
            "children",
            Value::Array(vec![entry(&a[7..8], &leaf_a.0), entry(&b[7..8], &leaf_b.0)]),
        ),
    ]);
    edit_split(&mut split);
    let split = bound(&split);
    let nonce = bound(&leaf(&format!("_nonce_{a}"), 7));
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
    let nodes = [state, accounts, split, leaf_a, leaf_b, nonce];
    (root, nodes.to_vec())
}

#[test]
fn small_state_lookups() {
    let [a, b, c, d] = small_addresses();
    let (root, nodes) = small_state(|_| {});
    let at = |address: &str| prove_account(&root, &nodes, address);
    assert_eq!(
        at(&a),
        Ok(Account {
            balance: 1,
            nonce: Some(7)
        })
    );
    assert_eq!(at(&a).unwrap().next_nonce(), Some(8));
    assert_eq!(
        at(&b),
        Ok(Account {
            balance: 2,
            nonce: None
        })
    );
    // A key a leaf's prefix rules out, and one under a missing child.
    for absent in [&c, &d] {
        assert_eq!(
            at(absent),
            Ok(Account {
                balance: 0,
                nonce: None
            }),
            "{absent}"
        );
    }
}

#[test]
fn non_address_keys_are_refused() {
    let [a, ..] = small_addresses();
    let (root, nodes) = small_state(|_| {});
    let at = |address: &str| prove_account(&root, &nodes, address);
    // The reserved nonce key of `a`, which the state does hold (as 7):
    // read as an address it would come back as a balance of 7.
    let reserved = format!("_nonce_{a}");
    for key in [
        reserved.as_str(),
        "_nonce_",
        "bafy",
        "a/b",
        "",
        &a.to_ascii_uppercase(),
        &a[..a.len() - 1],
        &format!("{a}\u{212a}"),
    ] {
        assert_eq!(
            at(key),
            Err(Error::Malformed("address not a standard CID")),
            "{key}"
        );
    }
}

#[test]
fn oversized_node_is_refused() {
    let [a, ..] = small_addresses();
    // The state root padded past the cap with an extra entry.
    let (_, mut nodes) = small_state(|_| {});
    let mut state = decode(&nodes[0].1);
    state.as_map_mut().unwrap().push((
        Value::Text("pad".into()),
        Value::Text("x".repeat(64 * 1024)),
    ));
    nodes[0] = bound(&state);
    assert_eq!(
        prove_account(&nodes[0].0.clone(), &nodes, &a),
        Err(Error::Malformed("node too large"))
    );
    // At the cap it decodes (and the extra key is ignored): the padding's
    // own key and text header take 7 bytes.
    let (_, mut nodes) = small_state(|_| {});
    let mut state = decode(&nodes[0].1);
    let room = 64 * 1024 - nodes[0].1.len() - 7;
    state
        .as_map_mut()
        .unwrap()
        .push((Value::Text("pad".into()), Value::Text("x".repeat(room))));
    nodes[0] = bound(&state);
    assert_eq!(nodes[0].1.len(), 64 * 1024);
    assert!(prove_account(&nodes[0].0.clone(), &nodes, &a).is_ok());
    // A header, likewise.
    let mut header = synthetic_chain(1, |_, _| {}).remove(0);
    header.as_map_mut().unwrap().push((
        Value::Text("pad".into()),
        Value::Text("x".repeat(64 * 1024)),
    ));
    assert_eq!(
        synthetic(&[bound(&header)], &ANY_TARGET),
        Err(Error::Malformed("node too large"))
    );
}

#[test]
fn malformed_trie_nodes_are_refused() {
    let entry = |key: &str| {
        map(vec![
            ("key", Value::Text(key.into())),
            ("value", link(&cid_of(b"x"))),
        ])
    };
    // The split's child key toward `a`.
    let a_key = small_addresses()[0][7..8].to_owned();
    type Edit = Box<dyn Fn(&mut Value)>;
    let edits: Vec<Edit> = vec![
        // The same character twice (cashew's `decodeChildren` throws).
        Box::new(move |n| {
            field(n, "children")
                .as_array_mut()
                .unwrap()
                .push(entry(&a_key))
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
        let [a, ..] = small_addresses();
        let refusal = prove_account(&root, &nodes, &a);
        assert!(matches!(refusal, Err(Error::Malformed(_))), "{refusal:?}");
        assert_ne!(refusal, Err(Error::Malformed("address not a standard CID")));
    }
}
