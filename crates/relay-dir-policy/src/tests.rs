//! The policy on hand-made writes, in contexts laid out as the Lattice host
//! lays them out.
//!
//! With CONTEXT_DIR set, every context is recorded with its verdict, so that
//! a host check (Follows' `policy/host-check`) can replay them through
//! Lattice's own evaluator.

use std::sync::atomic::{AtomicUsize, Ordering};

use ciborium::Value;

use super::*;

const PATH: [&str; 3] = ["Nexus", "testnet", "swap-relays"];

/// The `i`th of many well-formed addresses, without deriving a key for each.
fn address(i: u32) -> String {
    const BASE32: &[u8] = b"abcdefghijklmnopqrstuvwxyz234567";
    let digits: String = (0..50)
        .rev()
        .map(|place| BASE32[(i.checked_shr(5 * place).unwrap_or(0) % 32) as usize] as char)
        .collect();
    format!("bafyreia{digits}a")
}

fn alice() -> String {
    address(1)
}

fn bob() -> String {
    address(2)
}

fn relay(account: &str) -> String {
    format!("relay/{account}")
}

const URL: &str = "https://relay.example";

/// A general-state action: `key` from `old` to `new`.
fn action(key: &str, old: Option<&str>, new: Option<&str>) -> Value {
    let mut entries = vec![(text("key"), text(key))];
    entries.extend(old.map(|old| (text("oldValue"), text(old))));
    entries.extend(new.map(|new| (text("newValue"), text(new))));
    Value::Map(entries)
}

fn text(text: &str) -> Value {
    Value::Text(text.into())
}

fn texts<S: AsRef<str>>(items: &[S]) -> Value {
    Value::Array(items.iter().map(|item| text(item.as_ref())).collect())
}

fn body(actions: Vec<Value>, signers: &[String], account_actions: Vec<Value>) -> Vec<u8> {
    let body = Value::Map(vec![
        (text("accountActions"), Value::Array(account_actions)),
        (text("actions"), Value::Array(actions)),
        (text("depositActions"), Value::Array(vec![])),
        (text("receiptActions"), Value::Array(vec![])),
        (text("withdrawalActions"), Value::Array(vec![])),
        (text("signers"), texts(signers)),
        (text("nonce"), Value::Integer(0.into())),
        (text("chainPath"), texts(&PATH)),
    ]);
    let mut bytes = Vec::new();
    ciborium::into_writer(&body, &mut bytes).unwrap();
    bytes
}

/// The transaction-scope context for an encoded body, as the host writes it.
fn context(body: Option<&[u8]>) -> Vec<u8> {
    let mut bytes = b"LWPCTX".to_vec();
    // Encoding version, ABI version, transaction scope.
    bytes.extend([0, 2, 0, 1, 0]);
    bytes.extend(100u64.to_be_bytes()); // height
    bytes.extend([0; 8]); // timestamp
                          // Stand-in chain spec bytes; the policy skips them.
    bytes.extend(3u32.to_be_bytes());
    bytes.extend([0xa0; 3]);
    bytes.extend((PATH.len() as u32).to_be_bytes());
    for segment in PATH {
        bytes.extend((segment.len() as u32).to_be_bytes());
        bytes.extend(segment.as_bytes());
    }
    match body {
        None => bytes.push(0),
        Some(body) => {
            bytes.push(1);
            bytes.extend((body.len() as u32).to_be_bytes());
            bytes.extend(body);
        }
    }
    // No action, no action index.
    bytes.extend([0, 0]);
    bytes
}

/// The verdict as the module's entrypoint gives it, with as much scratch.
fn verdict(context: &[u8]) -> bool {
    let mut scratch = vec![0; lattice_policy_rules::signer_words(context.len() / 61).unwrap()];
    validate(context, &mut scratch)
}

fn accepts_with(actions: Vec<Value>, signers: &[String], account_actions: Vec<Value>) -> bool {
    static RECORDED: AtomicUsize = AtomicUsize::new(0);
    let context = context(Some(&body(actions, signers, account_actions)));
    let accepted = verdict(&context);
    if let Some(directory) = std::env::var_os("CONTEXT_DIR") {
        let directory = std::path::Path::new(&directory);
        std::fs::create_dir_all(directory).unwrap();
        let n = RECORDED.fetch_add(1, Ordering::Relaxed);
        let name = format!("{n:03}-{}.bin", if accepted { "accept" } else { "reject" });
        std::fs::write(directory.join(name), &context).unwrap();
    }
    accepted
}

/// Signed by Alice alone.
fn accepts(actions: Vec<Value>) -> bool {
    accepts_with(actions, &[alice()], vec![])
}

#[test]
fn an_account_lists_relists_and_unlists_its_relay() {
    let key = relay(&alice());
    assert!(accepts(vec![action(&key, None, Some(URL))]));
    assert!(accepts(vec![action(
        &key,
        Some(URL),
        Some("https://other.example")
    )]));
    assert!(accepts(vec![action(&key, Some(URL), None)]));
}

#[test]
fn nobody_writes_or_deletes_another_accounts_relay() {
    let (alices, bobs) = (relay(&alice()), relay(&bob()));
    assert!(!accepts(vec![action(&bobs, None, Some(URL))]));
    assert!(!accepts(vec![action(&bobs, Some(URL), None)]));
    assert!(!accepts(vec![
        action(&alices, None, Some(URL)),
        action(&bobs, None, Some(URL)),
    ]));
    // Signed by both, each writes their own.
    let both = [alice(), bob()];
    let actions = || {
        vec![
            action(&alices, None, Some(URL)),
            action(&bobs, None, Some(URL)),
        ]
    };
    assert!(accepts_with(actions(), &both, vec![]));
}

#[test]
fn only_an_accounts_relay_is_a_record() {
    let a = alice();
    for account in ["alice", &a.to_uppercase(), &format!("{a}x"), &a[1..], ""] {
        assert!(
            !accepts(vec![action(&relay(account), None, Some(URL))]),
            "{account}"
        );
    }
    for key in [
        format!("relay/{a}/x"),
        format!("relays/{a}"),
        format!("Relay/{a}"),
        format!("relay{a}"),
        format!("user/{a}/relay"),
        format!("follows/{a}/{}", bob()),
        "relay/".into(),
        "relay".into(),
        "".into(),
    ] {
        assert!(!accepts(vec![action(&key, None, Some(URL))]), "{key}");
    }
    // One bad action rejects the whole write.
    assert!(!accepts(vec![
        action(&relay(&a), None, Some(URL)),
        action(&format!("user/{a}/profile"), None, Some("{}")),
    ]));
}

#[test]
fn a_value_written_is_at_most_max_value_bytes() {
    let key = relay(&alice());
    let at_most = "x".repeat(MAX_VALUE_BYTES);
    let over = "x".repeat(MAX_VALUE_BYTES + 1);
    assert!(accepts(vec![action(&key, None, Some(&at_most))]));
    assert!(!accepts(vec![action(&key, None, Some(&over))]));
    assert!(accepts(vec![action(&key, Some(&at_most), None)]));
}

#[test]
fn values_mean_nothing_else_to_the_chain() {
    let key = relay(&alice());
    for value in ["", "not a url", "http://relay.example", "{\"since\":1}"] {
        assert!(accepts(vec![action(&key, None, Some(value))]), "{value}");
    }
}

#[test]
fn coin_actions_pass_untouched() {
    let coin = |owner: String, delta: i64| {
        Value::Map(vec![
            (text("owner"), Value::Text(owner)),
            (text("delta"), Value::Integer(delta.into())),
        ])
    };
    assert!(accepts_with(
        vec![],
        &[alice()],
        vec![coin(alice(), -5), coin(bob(), 5)]
    ));
}

#[test]
fn a_malformed_or_missing_body_is_rejected() {
    assert!(!verdict(&context(None)));
    assert!(!verdict(&context(Some(&[0xa0, 0x00]))));
    assert!(!verdict(&[1, 2, 3]));
}
