//! The JSON surface, natively and in wasm.

use super::*;
use bitcoin::hashes::Hash;
use bitcoin::{Amount, OutPoint, Txid};
use deposit::{change_child, deposit_quote, deposit_refused, fee_rate, fund_lock, refund_deposit};
use ed25519_dalek::SigningKey;
use session::Ivy;
use swap::Terms;
#[cfg(target_arch = "wasm32")]
use wasm_bindgen_test::wasm_bindgen_test as test;

fn terms() -> String {
    text(&Terms {
        swap_id: [1; 32],
        btc_amount: Amount::from_sat(1_000_000),
        btc_fee: Amount::from_sat(1_000),
        nex_amount: 500_000,
        nex_fee: 100,
        t1: 20,
        t2: 20,
        btc_confirmations: 1,
        nex_confirmations: 1,
        margin: 3,
        nexus_genesis: "genesis".into(),
    })
    .unwrap()
}

fn json(text: &str) -> Value {
    serde_json::from_str(text).unwrap()
}

/// The one message among `step`'s actions, as the event that delivers it.
fn delivered(step: &Value) -> String {
    let actions = step["actions"].as_array().unwrap();
    assert_eq!(actions.len(), 1);
    text(&json!({"Message": actions[0]["Send"]})).unwrap()
}

fn payout() -> String {
    json(&new_bitcoin_key("regtest").unwrap())["script_pubkey"]
        .as_str()
        .unwrap()
        .into()
}

#[test]
fn the_hellos_cross_as_json() {
    let seller_key = json(&new_nex_key().unwrap());
    let seller = new_seller(
        &terms(),
        seller_key["address"].as_str().unwrap(),
        &payout(),
        &payout(),
    )
    .unwrap();
    let buyer = json(&start_buyer(&terms(), &payout(), "buyer-payout").unwrap());
    assert_eq!(buyer["awaits_message"], true);

    let seller = json(&step_seller(&seller, &delivered(&buyer)).unwrap());
    assert!(seller["actions"][0]["Send"]["SellerHello"].is_object());
    assert!(seller["state"]["AwaitLockProposal"].is_object());

    let buyer = json(&step_buyer(&text(&buyer["state"]).unwrap(), &delivered(&seller)).unwrap());
    let fund = &buyer["actions"][0]["FundLock"];
    assert_eq!(fund["amount"], 1_000_000);
    assert!(fund["script_pubkey"].is_string());
    assert_eq!(buyer["outcome"], Value::Null);
}

#[test]
fn a_backup_restores_its_side_and_state() {
    let seller = new_seller(&terms(), "seller", &payout(), &payout()).unwrap();
    let backed_up = json(&backup(&seller, None).unwrap());
    assert_eq!(backed_up["name"], format!("{}.json", hex::encode([1; 32])));
    let restored = json(&restore(backed_up["file"].as_str().unwrap()).unwrap());
    assert_eq!(restored["side"], "seller");
    assert_eq!(restored["state"], json(&seller));

    let buyer = json(&start_buyer(&terms(), &payout(), "buyer-payout").unwrap());
    let state = text(&buyer["state"]).unwrap();
    let restored = json(&restore(&file(&state)).unwrap());
    assert_eq!(restored["side"], "buyer");
    assert_eq!(restored["state"], buyer["state"]);

    let other = json!({"version": STATE_VERSION + 1, "state": json(&seller)});
    assert!(restore(&other.to_string()).is_err());
}

/// A backup's file.
fn file(state: &str) -> String {
    json(&backup(state, None).unwrap())["file"]
        .as_str()
        .unwrap()
        .into()
}

#[test]
fn only_a_running_swap_is_backed_up() {
    assert!(backup("{}", None).is_err());
    assert!(backup(r#"{"AwaitBuyerHello": {}}"#, None).is_err());
    let done = text(&json!({"Done": "Swapped"})).unwrap();
    assert!(backup(&done, None).unwrap_err().contains("over"));
}

/// Both machines claim in `ClaimingNex`, with the same claim: its setup
/// names the side.
#[test]
fn a_claim_restores_to_its_own_side() {
    let (seller, buyer) = hellos();
    for (state, side) in [(seller, "seller"), (buyer["state"].clone(), "buyer")] {
        let setup = state.as_object().unwrap().values().next().unwrap().clone();
        let claim = json!({"ClaimingNex": {
            "setup": setup,
            "other": hex::encode([2; 32]),
            "lock": "Seen",
            "passed_at": null,
            "claim": null,
            "punished": false,
        }});
        let restored = json(&restore(&file(&claim.to_string())).unwrap());
        assert_eq!(restored["side"], side);
        assert_eq!(restored["state"], claim);
    }
}

/// The seller's state once the hellos are exchanged, and the buyer's step
/// that answers them.
fn hellos() -> (Value, Value) {
    let seller = new_seller(&terms(), "seller", &payout(), &payout()).unwrap();
    let buyer = json(&start_buyer(&terms(), &payout(), "buyer-payout").unwrap());
    let seller = json(&step_seller(&seller, &delivered(&buyer)).unwrap());
    let buyer = json(&step_buyer(&text(&buyer["state"]).unwrap(), &delivered(&seller)).unwrap());
    (seller["state"].clone(), buyer)
}

#[test]
fn refused_terms_are_an_error() {
    let mut terms = json(&terms());
    terms["margin"] = json!(1);
    let terms = terms.to_string();
    assert_eq!(
        new_seller(&terms, "seller", &payout(), &payout()),
        Err("refused: Terms".into())
    );
    assert!(start_buyer(&terms, &payout(), "buyer-payout").is_err());
    let why = check_terms(&terms).unwrap().unwrap();
    assert!(why.contains("margin"), "{why}");
    assert_eq!(check_terms(&self::terms()), Ok(None));
}

#[test]
fn a_bitcoin_key_owns_its_address() {
    let key = json(&new_bitcoin_key("signet").unwrap());
    let wif = PrivateKey::from_wif(key["wif"].as_str().unwrap()).unwrap();
    let public = CompressedPublicKey::from_private_key(&Secp256k1::new(), &wif).unwrap();
    let address = Address::p2wpkh(&public, Network::Signet);
    assert_eq!(key["address"], address.to_string());
    assert_eq!(
        key["script_pubkey"],
        address.script_pubkey().to_hex_string()
    );
    assert!(new_bitcoin_key("moon").is_err());
}

#[test]
fn a_signed_nex_body_verifies_under_its_key() {
    let key = json(&new_nex_key().unwrap());
    let body =
        TransactionBody::transfer(key["address"].as_str().unwrap(), "lock", 10, 1, 0).unwrap();
    let signed: Transaction =
        parse(&sign_nex(key["seed"].as_str().unwrap(), &text(&body).unwrap()).unwrap()).unwrap();
    assert_eq!(signed.body, body);
    assert!(signed.verify());
}

#[test]
fn generated_keys_differ() {
    assert_ne!(
        json(&new_nex_key().unwrap())["seed"],
        json(&new_nex_key().unwrap())["seed"]
    );
    assert_ne!(
        json(&new_bitcoin_key("regtest").unwrap())["wif"],
        json(&new_bitcoin_key("regtest").unwrap())["wif"]
    );
}

#[test]
fn a_bitcoin_key_is_for_its_network() {
    for (network, kind) in [
        ("bitcoin", bitcoin::NetworkKind::Main),
        ("signet", bitcoin::NetworkKind::Test),
    ] {
        let key = json(&new_bitcoin_key(network).unwrap());
        let wif = PrivateKey::from_wif(key["wif"].as_str().unwrap()).unwrap();
        assert_eq!(wif.network, kind, "{network}");
    }
}

/// Terms below the CLI's floors are refused here too.
#[test]
fn terms_below_the_floors_are_refused() {
    let refused = |edit: &dyn Fn(&mut Value)| {
        let mut terms = json(&terms());
        edit(&mut terms);
        let terms = terms.to_string();
        let seller = new_seller(&terms, "seller", &payout(), &payout());
        let buyer = start_buyer(&terms, &payout(), "buyer-payout");
        assert_eq!(seller.is_err(), buyer.is_err());
        seller.is_err()
    };
    // 1 + 6 x (1 + 1) + 3.
    assert!(!refused(&|terms| terms["t1"] = json!(16)));
    assert!(refused(&|terms| terms["t1"] = json!(15)));
    // Two fees of 1000 above the dust limit, 546.
    assert!(!refused(&|terms| terms["btc_amount"] = json!(2_546)));
    assert!(refused(&|terms| terms["btc_amount"] = json!(2_545)));
}

/// The fee floor at the page's own rate is the CLI's.
#[test]
fn the_fee_floor_is_the_clis() {
    assert_eq!(btc_fee_at("1000"), Ok(swap::btc_fee_at(1_000).to_string()));
    assert_eq!(btc_fee_at("1000").unwrap(), "163");
    assert!(btc_fee_at("-1").is_err());
}

/// The envelope the CLI sends, byte for byte, natively and in wasm.
#[test]
fn messages_match_the_clis() {
    let funding = bitcoin::Transaction {
        version: bitcoin::transaction::Version::TWO,
        lock_time: bitcoin::absolute::LockTime::ZERO,
        input: vec![bitcoin::TxIn {
            previous_output: OutPoint::new(Txid::from_byte_array([3; 32]), 1),
            ..Default::default()
        }],
        output: vec![bitcoin::TxOut {
            value: Amount::from_sat(1_000),
            script_pubkey: ScriptBuf::new(),
        }],
    };
    let message = Message::LockProposal {
        lock: OutPoint::new(funding.compute_txid(), 0),
        funding,
    };
    let id = hex::encode([1; 32]);
    let encoded = encode_message(&text(&message).unwrap(), &id).unwrap();
    assert_eq!(encoded, message.encode([1; 32]));
    // As the native build encodes it.
    let golden = concat!(
        r#"{"swap_id":"0101010101010101010101010101010101010101010101010101010101010101","m"#,
        r#"essage":{"LockProposal":{"funding":"02000000010303030303030303030303030303030303"#,
        r#"0303030303030303030303030303030100000000ffffffff01e8030000000000000000000000","l"#,
        r#"ock":"13a0e925c82bc22c95876413c2b2a5b41fb0d74de37be4a4d463d135b56a60ad:0"}}}"#,
    );
    assert_eq!(encoded, golden.as_bytes());
    let decoded = decode_message(&encoded, &id).unwrap().unwrap();
    assert_eq!(json(&decoded), json(&text(&message).unwrap()));
    assert_eq!(decode_message(&encoded, &hex::encode([2; 32])), Ok(None));
    assert_eq!(decode_message(b"junk", &id), Ok(None));
    assert!(encode_message(&text(&message).unwrap(), "01").is_err());
}

/// Once the lock is agreed, both sides watch its output and look up the
/// same spends; the buyer, told the NEX lock, watches it on Nexus.
#[test]
fn a_watch_names_what_to_observe() {
    let (seller, buyer) = hellos();
    let seller = text(&seller).unwrap();
    let nothing = json(&watch_seller(&seller).unwrap());
    assert_eq!(nothing["bitcoin"], Value::Null);
    assert_eq!(nothing["nexus"], Value::Null);

    let fund = &buyer["actions"][0]["FundLock"];
    let funding = bitcoin::Transaction {
        version: bitcoin::transaction::Version::TWO,
        lock_time: bitcoin::absolute::LockTime::ZERO,
        input: vec![bitcoin::TxIn {
            previous_output: OutPoint::new(Txid::from_byte_array([3; 32]), 1),
            // Signed: segwit.
            witness: bitcoin::Witness::from_slice(&[[0u8; 72].as_slice(), &[2u8; 33]]),
            ..Default::default()
        }],
        output: vec![bitcoin::TxOut {
            value: Amount::from_sat(fund["amount"].as_u64().unwrap()),
            script_pubkey: script(fund["script_pubkey"].as_str().unwrap()).unwrap(),
        }],
    };
    let funded = text(&json!({"Funded": bitcoin::consensus::encode::serialize_hex(&funding)}));
    let buyer = json(&step_buyer(&text(&buyer["state"]).unwrap(), &funded.unwrap()).unwrap());
    let seller = json(&step_seller(&seller, &delivered(&buyer)).unwrap());
    let buyer = json(&step_buyer(&text(&buyer["state"]).unwrap(), &delivered(&seller)).unwrap());
    let signatures = delivered(&buyer);
    let sent = text(&json!("Sent")).unwrap();
    let buyer = json(&step_buyer(&text(&buyer["state"]).unwrap(), &sent).unwrap());
    let seller = json(&step_seller(&text(&seller["state"]).unwrap(), &signatures).unwrap());

    let buyer_state = text(&buyer["state"]).unwrap();
    let watched = json(&watch_buyer(&buyer_state).unwrap());
    let lock = OutPoint::new(funding.compute_txid(), 0);
    assert_eq!(watched["bitcoin"]["lock"], lock.to_string());
    assert_eq!(watched["bitcoin"]["t2"], 20);
    let cancel = watched["bitcoin"]["lock_spends"][1].as_str().unwrap();
    assert_eq!(watched["bitcoin"]["cancel_output"], format!("{cancel}:0"));
    assert_eq!(watched["margin"], 3);
    assert_eq!(watched["nexus"], Value::Null);
    let seller_watched = json(&watch_seller(&text(&seller["state"]).unwrap()).unwrap());
    assert_eq!(seller_watched["bitcoin"], watched["bitcoin"]);
    assert_eq!(seller_watched["nexus"], Value::Null);

    let lock_cid = swap_nexus_tx::address(&[5; 32]);
    let cid = text(&json!({"Message": {"NexLocked": {"cid": lock_cid}}})).unwrap();
    let buyer = json(&step_buyer(&buyer_state, &cid).unwrap());
    let watched = json(&watch_buyer(&text(&buyer["state"]).unwrap()).unwrap());
    let nexus = &watched["nexus"];
    assert_eq!(nexus["cid"], lock_cid);
    assert_eq!(nexus["own_address"], "buyer-payout");
    assert!(nexus["lock_address"].is_string());
    assert_eq!(nexus["block_at"], Value::Null);
}

#[test]
fn a_tip_is_aged_as_the_driver_ages_it() {
    let hash = |n: u8| bitcoin::BlockHash::from_byte_array([n; 32]).to_string();
    let tip = json!({"height": 100, "headers": 100, "time": 10_000, "hash": hash(1)});
    let stale = |tip: &Value, first_seen: Value, now: u64| {
        let input = json!({"tip": tip, "first_seen": first_seen, "max_tip_age": 600, "now": now});
        json(&bitcoin_stale(&input.to_string()).unwrap())
    };
    let fresh = stale(&tip, Value::Null, 10_600);
    assert_eq!(fresh["stale"], Value::Null);
    assert_eq!(fresh["first_seen"], json!([hash(1), 10_600]));
    let old = stale(&tip, Value::Null, 10_601);
    assert!(old["stale"].as_str().unwrap().contains("10 minutes old"));
    // A block time ahead of the clock: aged from when it was first seen.
    let ahead = json!({"height": 100, "headers": 100, "time": 99_999, "hash": hash(1)});
    assert!(stale(&ahead, json!([hash(1), 9_000]), 10_000)["stale"].is_string());
    assert_eq!(
        stale(&ahead, json!([hash(2), 9_000]), 10_000)["first_seen"],
        json!([hash(1), 10_000])
    );
    let lagging = json!({"height": 100, "headers": 101, "time": 10_000, "hash": hash(1)});
    let lags = stale(&lagging, Value::Null, 10_000);
    assert!(lags["stale"].as_str().unwrap().contains("headers to 101"));
}

#[test]
fn the_cancel_output_is_searched_only_behind_a_mined_cancel() {
    let txid = |n: u8| Txid::from_byte_array([n; 32]);
    let cancel = bitcoin::Transaction {
        version: bitcoin::transaction::Version::TWO,
        lock_time: bitcoin::absolute::LockTime::ZERO,
        input: vec![],
        output: vec![],
    };
    let lookups = Lookups {
        lock: OutPoint::new(txid(1), 0),
        lock_spends: [txid(2), cancel.compute_txid()],
        cancel_spends: [txid(3), txid(4)],
        cancel_output: OutPoint::new(cancel.compute_txid(), 0),
        t2: 10,
    };
    let hex = bitcoin::consensus::encode::serialize_hex(&cancel);
    let from = |confirmations: u32, cancel_spend: Value| {
        let input = json!({
            "lookups": lookups,
            "height": 120,
            "lock_spend": {"tx": hex, "confirmations": confirmations},
            "cancel_spend": cancel_spend,
        });
        json(&cancel_search_from(&input.to_string()).unwrap())
    };
    // Mined at 120 - 5 + 1: punish no earlier than 10 blocks on.
    assert_eq!(from(5, Value::Null), json!(126));
    assert_eq!(from(0, Value::Null), Value::Null);
    let refund = json!({"tx": hex, "confirmations": 0});
    assert_eq!(from(5, refund), Value::Null);
    // A mined redeem leaves no cancel output.
    let other = Lookups {
        lock_spends: [txid(2), txid(5)],
        cancel_output: OutPoint::new(txid(5), 0),
        ..lookups
    };
    let input = json!({
        "lookups": other,
        "height": 120,
        "lock_spend": {"tx": hex, "confirmations": 5},
        "cancel_spend": null,
    });
    assert_eq!(cancel_search_from(&input.to_string()), Ok("null".into()));
}

#[test]
fn a_nexus_view_is_one_tips() {
    let health = |height: u64, tip: &str| {
        let health =
            json!({"phase": "active", "height": height, "best_header_height": height, "tip": tip});
        health.to_string()
    };
    assert_eq!(nexus_one_tip(&health(5, "a"), &health(5, "a")), Ok(true));
    assert_eq!(nexus_one_tip(&health(5, "a"), &health(6, "a")), Ok(false));
    assert_eq!(nexus_one_tip(&health(5, "a"), &health(5, "b")), Ok(false));
}

/// An offer signed as the CLI's `offer` signs it.
fn signed_offer(relay: &str) -> Offer {
    let key = SigningKey::from_bytes(&[4; 32]);
    let terms = parse(&terms()).unwrap();
    let place = swap::offer::Place::Relay(relay.into());
    Offer::new(terms, Network::Regtest, place, &key, [7; 32])
}

#[test]
fn an_offer_is_read_only_as_its_seller_signed_it() {
    let offer = signed_offer("http://relay.example");
    let decoded = json(&decode_offer(&offer.encode()).unwrap());
    assert_eq!(decoded, json(&text(&offer).unwrap()));
    let mut changed = offer.clone();
    changed.terms.margin += 1;
    let refused = decode_offer(&changed.encode()).unwrap_err();
    assert!(refused.contains("not signed by its seller"), "{refused}");
    assert!(decode_offer("{}").is_err());
}

#[test]
fn an_offer_is_judged_by_the_clis_policy() {
    let offer = signed_offer("http://relay.example");
    let check = |policy: Value, fee_estimate: Value| {
        let input = json!({
            "offer": offer,
            "policy": policy,
            "network": "regtest",
            "nexus_genesis": "genesis",
            "fee_estimate": fee_estimate,
            "min_relay_fee": 1,
        });
        check_offer(&input.to_string()).unwrap()
    };
    // The bounds the regtest terms need, the rest the CLI's defaults.
    let policy = json!({
        "btc_amount": 1_000_000, "nex_amount": 500_000, "max_t1": 20, "min_t2": 20,
        "min_btc_confirmations": 1, "min_nex_confirmations": 1, "min_margin": 3,
        "min_refund_window": 19,
    });
    assert_eq!(check(policy.clone(), json!(1_000)), None);
    let mut other = policy.clone();
    other["nex_amount"] = json!(1);
    assert!(check(other, json!(1_000))
        .unwrap()
        .contains("sells 500000 NEX"));
    // A fee rate at which cancel and refund pay more than the offer's fee.
    let refused = check(policy.clone(), json!(100_000)).unwrap();
    assert!(refused.contains("below the"), "{refused}");
    // No estimate, and no floor given: refused, as `take` refuses.
    assert!(check(policy.clone(), Value::Null)
        .unwrap()
        .contains("no fee estimate"));
    let mut floored = policy;
    floored["min_btc_fee_rate"] = json!(1);
    assert_eq!(check(floored, Value::Null), None);
}

/// The browser's session against the seller's side of ivy-core, the bytes
/// cut anywhere as a relay may cut them.
#[test]
fn the_session_carries_swap_messages_both_ways() {
    use ivy_core::{frame, Config, Message as Record, Responder};
    let seller = Config::new(SigningKey::from_bytes(&[4; 32]));
    let id = hex::encode([1; 32]);
    let mut ivy = Ivy::new(&hex::encode([7; 32]), &seller.peer_key().hex(), &id).unwrap();
    assert!(!ivy.is_open());
    let hello = ivy.outbound();
    let buyer = Config::new(SigningKey::from_bytes(&[7; 32])).peer_key();
    let (waiting, reply) = Responder::new(&seller)
        .receive(&hello[4..], |key| *key == buyer, &mut OsRng)
        .unwrap();
    let reply = frame(&reply);
    assert!(ivy.receive(&reply[..3]).unwrap().is_empty());
    assert!(ivy.receive(&reply[3..]).unwrap().is_empty());
    assert!(ivy.is_open());
    let finish = ivy.outbound();
    let mut session = waiting.receive(&finish[4..]).unwrap();

    let message = Message::NexLocked {
        cid: swap_nexus_tx::address(&[5; 32]),
    };
    let sealed = |session: &mut ivy_core::Session, topic: &str, payload: Vec<u8>| {
        frame(
            &session
                .seal(&Record::PeerMessage {
                    topic: topic.into(),
                    payload,
                })
                .unwrap(),
        )
    };
    let mut bytes = sealed(&mut session, swap::TOPIC, message.encode([1; 32]));
    // Another topic, and another swap's, are dropped.
    bytes.extend(sealed(&mut session, "other", message.encode([1; 32])));
    bytes.extend(sealed(&mut session, swap::TOPIC, message.encode([2; 32])));
    bytes.extend(frame(&session.seal(&Record::Ping(9)).unwrap()));
    let (a, b) = bytes.split_at(10);
    assert!(ivy.receive(a).unwrap().is_empty());
    let received = ivy.receive(b).unwrap();
    assert_eq!(received.len(), 1);
    assert_eq!(json(&received[0]), json(&text(&message).unwrap()));
    // The ping is answered.
    let pong = ivy.outbound();
    assert_eq!(session.open(&pong[4..]).unwrap(), Some(Record::Pong(9)));

    ivy.send(&text(&message).unwrap()).unwrap();
    let out = ivy.outbound();
    let Some(Record::PeerMessage { topic, payload }) = session.open(&out[4..]).unwrap() else {
        panic!("a message");
    };
    assert_eq!(topic, swap::TOPIC);
    assert_eq!(payload, message.encode([1; 32]));
    // A record the seller did not sign ends the session.
    let mut forged = sealed(&mut session, swap::TOPIC, message.encode([1; 32]));
    let last = forged.len() - 1;
    forged[last] ^= 1;
    assert!(ivy.receive(&forged).is_err());
}

#[test]
fn a_session_to_another_key_never_opens() {
    use ivy_core::{frame, Config, Responder};
    let impostor = Config::new(SigningKey::from_bytes(&[5; 32]));
    let seller = Config::new(SigningKey::from_bytes(&[4; 32])).peer_key();
    let mut ivy = Ivy::new(&hex::encode([7; 32]), &seller.hex(), &hex::encode([1; 32])).unwrap();
    let hello = ivy.outbound();
    // It cannot even answer a hello addressed to another key.
    assert!(Responder::new(&impostor)
        .receive(&hello[4..], |_| true, &mut OsRng)
        .is_err());
    let (_, reply) = Responder::new(&Config::new(SigningKey::from_bytes(&[4; 32])))
        .receive(&hello[4..], |_| true, &mut OsRng)
        .unwrap();
    let mut reply = frame(&reply);
    let last = reply.len() - 1;
    reply[last] ^= 1;
    assert!(ivy.receive(&reply).is_err());
    assert!(!ivy.is_open());
}

/// The node's answers as its routes give them.
fn node_health(height: u64, tip: &str) -> Value {
    json!({"phase": "active", "height": height.to_string(),
           "bestHeaderHeight": height.to_string(), "tipCID": tip})
}

fn node_transaction(height: Option<u64>) -> Value {
    let mut tx = json!({
        "accountActions": [{"owner": "lock", "delta": "500000"}],
        "depositActions": [], "receiptActions": [], "withdrawalActions": [],
        "signers": ["seller"], "nonce": "0", "chainPath": ["Nexus"],
    });
    if let Some(height) = height {
        tx["blockHeight"] = json!(height.to_string());
        tx["blockHash"] = json!(format!("block{height}"));
    }
    tx
}

#[test]
fn a_nexus_view_is_read_as_the_driver_reads_one() {
    let account = json!({"balance": "500000", "nonce": "0"});
    let reads = |after: Value, watched: Value| {
        json!({
            "health": node_health(10, "tip10"),
            "own": {"balance": "0", "nonce": "0"},
            "lock": account,
            "chain_info": {"minRelayFee": "3"},
            "watched": watched,
            "block_at": null,
            "health_after": after,
        })
        .to_string()
    };
    let watched = |before: Value, after: Value| json!({"before": before, "health": node_health(10, "tip10"), "after": after});
    let mined = watched(node_transaction(Some(8)), node_transaction(Some(8)));
    let view: NexusView = parse(
        &nexus_view(&reads(node_health(10, "tip10"), mined.clone()))
            .unwrap()
            .unwrap(),
    )
    .unwrap();
    assert_eq!(view.lock.balance, 500_000);
    assert_eq!(view.min_relay_fee, 3);
    let (status, depth) = view.watched.unwrap();
    assert_eq!(status.body.account_actions[0].delta, 500_000);
    assert_eq!(depth, Some(3));
    // The tip moved under the reads: no view.
    assert_eq!(
        nexus_view(&reads(node_health(11, "tip11"), mined)),
        Ok(None)
    );
    // Its block changed between the two reads of it: not deep at all.
    let moved = watched(node_transaction(Some(8)), node_transaction(Some(9)));
    let view: NexusView = parse(
        &nexus_view(&reads(node_health(10, "tip10"), moved))
            .unwrap()
            .unwrap(),
    )
    .unwrap();
    assert_eq!(view.watched.unwrap().1, None);
    // Mined in a block above the tip /health reports, which a public read
    // port serves from a cache: read at two tips, no view.
    let ahead = watched(node_transaction(Some(11)), node_transaction(Some(11)));
    assert_eq!(
        nexus_view(&reads(node_health(10, "tip10"), ahead)),
        Ok(None)
    );
    // Unknown to the node, or not watched.
    let unknown = watched(Value::Null, Value::Null);
    let view: NexusView = parse(
        &nexus_view(&reads(node_health(10, "tip10"), unknown))
            .unwrap()
            .unwrap(),
    )
    .unwrap();
    assert!(view.watched.is_none());
    // A transaction the node lists with other actions is refused, as the
    // native client refuses it.
    let mut other = node_transaction(Some(8));
    other["depositActions"] = json!([{}]);
    let other = watched(other.clone(), other);
    assert!(nexus_view(&reads(node_health(10, "tip10"), other)).is_err());
}

#[test]
fn a_submit_body_is_the_native_clients() {
    let key = json(&new_nex_key().unwrap());
    let body =
        TransactionBody::transfer(key["address"].as_str().unwrap(), "lock", 10, 1, 0).unwrap();
    let signed = sign_nex(key["seed"].as_str().unwrap(), &text(&body).unwrap()).unwrap();
    let transaction: Transaction = parse(&signed).unwrap();
    assert_eq!(
        json(&nexus_submit_body(&signed).unwrap()),
        transaction.to_submit_json()
    );
}

#[test]
fn a_backup_keeps_the_deposit_key() {
    let buyer = json(&start_buyer(&terms(), &payout(), "buyer-payout").unwrap());
    let state = text(&buyer["state"]).unwrap();
    let wif = json(&new_bitcoin_key("regtest").unwrap())["wif"].clone();
    let browser = json!({"deposit": wif, "relay": "https://relay.example", "quote_rate": 7});
    let file = json(&backup(&state, Some(browser.to_string())).unwrap())["file"].clone();
    let restored = json(&restore(file.as_str().unwrap()).unwrap());
    assert_eq!(restored["browser"], browser);
    assert_eq!(restored["state"], buyer["state"]);
    let restored = json(&restore(&self::file(&state)).unwrap());
    assert_eq!(restored["browser"], Value::Null);
    assert!(backup(&state, Some(r#"{"deposit": 1}"#.into())).is_err());
}

#[test]
fn a_buyer_shows_where_its_swap_is() {
    let status = |state: Value| json(&buyer_status(&state.to_string(), None, false).unwrap());
    let (_, buyer) = hellos();
    let locking = status(buyer["state"].clone());
    assert_eq!(locking["phase"], "locking");
    assert_eq!(locking["must_stay_open"], false);
    assert_eq!(locking["cancel_at"], Value::Null);
    assert_eq!(status(json!({"Done": "Swapped"}))["phase"], "swapped");
    assert_eq!(
        status(json!({"Done": {"Aborted": "Timeout"}}))["phase"],
        "aborted"
    );
    assert!(buyer_status("[]", None, false).is_err());
}

/// One deposit of `value` to the key `wif`.
fn utxos(value: u64) -> Value {
    json!([{"txid": Txid::from_byte_array([9; 32]), "vout": 1, "value": value}])
}

/// Whether input 0 of `tx` is signed by `wif`, spending `value`.
fn signed_by(tx: &bitcoin::Transaction, wif: &str, value: u64) -> bool {
    use bitcoin::sighash::{EcdsaSighashType, SighashCache};
    let key = PrivateKey::from_wif(wif).unwrap();
    let secp = Secp256k1::new();
    let public = CompressedPublicKey::from_private_key(&secp, &key).unwrap();
    let script = ScriptBuf::new_p2wpkh(&public.wpubkey_hash());
    let sighash = SighashCache::new(tx)
        .p2wpkh_signature_hash(0, &script, Amount::from_sat(value), EcdsaSighashType::All)
        .unwrap();
    let witness = &tx.input[0].witness;
    let signature = bitcoin::ecdsa::Signature::from_slice(witness.nth(0).unwrap()).unwrap();
    let message = bitcoin::secp256k1::Message::from_digest(sighash.to_byte_array());
    witness.nth(1) == Some(&public.to_bytes()[..])
        && secp
            .verify_ecdsa(&message, &signature.signature, &public.0)
            .is_ok()
}

fn hex_tx(hex: &Value) -> bitcoin::Transaction {
    bitcoin::consensus::encode::deserialize_hex(hex.as_str().unwrap()).unwrap()
}

/// A deposit funds the lock as the buyer's machine takes it: the agreed
/// amount at the lock, every input segwit, the change back to the
/// deposit key, which a child sends on to the refund address.
#[test]
fn a_deposit_funds_the_lock_and_returns_its_change() {
    let (_, buyer) = hellos();
    let fund = &buyer["actions"][0]["FundLock"];
    let key = json(&new_bitcoin_key("regtest").unwrap());
    let wif = key["wif"].as_str().unwrap();
    let refund = payout();
    let funded = |value: u64, rate: u64| {
        let input = json!({
            "wif": wif, "utxos": utxos(value), "script_pubkey": fund["script_pubkey"],
            "amount": fund["amount"], "fee_rate": rate, "refund_script": refund,
        });
        fund_lock(&input.to_string()).map(|funded| json(&funded))
    };
    let funded_ = funded(1_100_000, 5).unwrap();
    let funding = hex_tx(&funded_["tx"]);
    assert!(signed_by(&funding, wif, 1_100_000));
    assert_eq!(funding.output[0].value.to_sat(), 1_000_000);
    assert_eq!(
        funding.output[1].script_pubkey.to_hex_string(),
        key["script_pubkey"]
    );
    let fee = funded_["fee"].as_u64().unwrap();
    assert!(fee >= 5 * funding.vsize() as u64, "{fee}");
    assert_eq!(funding.output[1].value.to_sat(), 100_000 - fee);
    let event = text(&json!({"Funded": funded_["tx"]})).unwrap();
    let state = text(&buyer["state"]).unwrap();
    let stepped = json(&step_buyer(&state, &event).unwrap());
    assert!(
        stepped["state"]["AwaitSellerSignatures"].is_object(),
        "{stepped}"
    );

    // The child: the two together pay the rate asked.
    let child = |rate: u64| {
        let input = json!({
            "wif": wif, "parent": funded_["tx"], "parent_fee": fee,
            "refund_script": refund, "fee_rate": rate,
        });
        json(&change_child(&input.to_string()).unwrap().unwrap())
    };
    for rate in [5, 50] {
        let paid = child(rate);
        let tx = hex_tx(&paid["tx"]);
        assert!(signed_by(&tx, wif, 100_000 - fee));
        assert_eq!(
            tx.input[0].previous_output,
            OutPoint::new(funding.compute_txid(), 1)
        );
        assert_eq!(tx.output[0].script_pubkey.to_hex_string(), refund);
        let package = (funding.vsize() + tx.vsize()) as u64;
        let total = fee + paid["fee"].as_u64().unwrap();
        assert!(total >= rate * package, "{rate}: {total} for {package} vB");
        assert!(
            total < (rate + 1) * package + 10,
            "{rate}: {total} for {package} vB"
        );
    }
    // Never more than the change but dust.
    let all = child(1_000_000);
    assert_eq!(hex_tx(&all["tx"]).output[0].value.to_sat(), 294);

    // Change too small to pay its own child goes to the fee; a deposit
    // that cannot pay the funding is refused.
    let exact = funded(1_000_000 + 1_400, 5).unwrap();
    assert_eq!(hex_tx(&exact["tx"]).output.len(), 1);
    let none = json!({
        "wif": wif, "parent": exact["tx"], "parent_fee": 1_400,
        "refund_script": refund, "fee_rate": 5,
    });
    assert_eq!(change_child(&none.to_string()).unwrap(), None, "no change");
    assert_eq!(exact["fee"], 1_400);
    assert!(funded(1_000_000 + 100, 5).is_err());
}

#[test]
fn a_deposit_that_does_not_fit_is_refunded() {
    let key = json(&new_bitcoin_key("regtest").unwrap());
    let wif = key["wif"].as_str().unwrap();
    let refund = payout();
    let quote = deposit_quote(
        &json!({"btc_amount": 1_000_000, "fee_rate": 10, "deposit_wif": wif, "refund_script": refund})
            .to_string(),
    )
    .unwrap();
    let quote: u64 = parse(&quote).unwrap();
    assert!(
        quote > 1_000_000 + 2 * 10 * 150 && quote < 1_000_000 + 2 * 10 * 400,
        "{quote}"
    );
    let refused = |utxos: Value, rate: u64| {
        let input =
            json!({"utxos": utxos, "btc_amount": 1_000_000, "quote": quote, "fee_rate": rate});
        deposit_refused(&input.to_string()).unwrap()
    };
    assert_eq!(refused(utxos(quote), 10), None);
    assert_eq!(refused(utxos(2 * quote), 10), None);
    assert!(refused(utxos(2 * quote + 1), 10).unwrap().contains("twice"));
    assert!(refused(utxos(1_000_000 + 100), 10)
        .unwrap()
        .contains("below"));
    // At a rate risen past the quote's headroom.
    assert!(refused(utxos(quote), 100).unwrap().contains("below"));
    assert!(refused(json!([]), 10).unwrap().contains("nothing"));
    // Two deposits count together.
    let two = json!([
        {"txid": Txid::from_byte_array([9; 32]), "vout": 0, "value": 600_000},
        {"txid": Txid::from_byte_array([8; 32]), "vout": 1, "value": quote - 600_000},
    ]);
    assert_eq!(refused(two, 10), None);

    let back = |value: u64| {
        let input =
            json!({"wif": wif, "utxos": utxos(value), "refund_script": refund, "fee_rate": 10});
        refund_deposit(&input.to_string())
    };
    let back50 = json(&back(50_000).unwrap());
    let tx: bitcoin::Transaction =
        bitcoin::consensus::encode::deserialize_hex(back50["tx"].as_str().unwrap()).unwrap();
    assert_eq!(back50["txid"], tx.compute_txid().to_string());
    assert!(signed_by(&tx, wif, 50_000));
    assert_eq!(tx.output.len(), 1);
    assert_eq!(tx.output[0].script_pubkey.to_hex_string(), refund);
    assert!(tx.output[0].value.to_sat() >= 50_000 - 10 * (tx.vsize() as u64 + 1));
    assert!(back(1_000).is_err(), "it would leave dust");
}

/// A spend pays the lowest source's estimate, bounded by twice the quote's
/// rate: one source that answers high spends nothing more.
#[test]
fn a_spend_pays_the_lowest_estimate_within_the_quotes_headroom() {
    let rate = |input: Value| -> u64 { parse(&fee_rate(&input.to_string()).unwrap()).unwrap() };
    let spend =
        |estimates: Value| rate(json!({"estimates": estimates, "fallback": 10, "quote_rate": 10}));
    assert_eq!(spend(json!([2, 9000])), 2);
    assert_eq!(spend(json!([9000, 2.2])), 3);
    assert_eq!(spend(json!([500, 9000])), 20, "the quote's headroom");
    assert_eq!(spend(json!([null, 9000])), 20, "one source alone");
    assert_eq!(spend(json!([null, 12])), 12);
    assert_eq!(spend(json!([null, null])), 10, "the fallback");
    assert_eq!(spend(json!([0.2, 5])), 1, "the relay floor");
    // The quote's own rate is bounded by nothing but the lowest estimate.
    assert_eq!(rate(json!({"estimates": [500, 9000], "fallback": 10})), 500);
    assert_eq!(
        rate(json!({"estimates": [], "fallback": 10, "quote_rate": null})),
        10
    );
}

/// A Nexus node is judged as the CLI judges one: its genesis, its chain,
/// and whether it keeps the state of past blocks.
#[test]
fn a_nexus_node_is_checked_as_the_cli_checks_one() {
    let health = |height: u64| json!({"phase": "active", "height": height.to_string()});
    assert_eq!(nexus_probe_height(&health(1).to_string()).unwrap(), "null");
    assert_eq!(nexus_probe_height(&health(9).to_string()).unwrap(), "5");
    let check = |chain: Value, genesis: &str, height: u64, past_state: Value| {
        let input = json!({
            "genesis": "genesis",
            "chain_info": {"chain": chain, "genesisHash": genesis},
            "health": health(height),
            "past_state": past_state,
        });
        check_nexus(&input.to_string()).unwrap()
    };
    let nexus = || json!(["Nexus"]);
    assert_eq!(check(nexus(), "genesis", 10, json!(true)), None);
    assert_eq!(
        check(nexus(), "genesis", 1, Value::Null),
        None,
        "too short to tell"
    );
    let other = check(nexus(), "other", 10, json!(true)).unwrap();
    assert!(other.contains("genesis other, not genesis"), "{other}");
    let child = check(json!(["Nexus", "Child"]), "genesis", 10, json!(true)).unwrap();
    assert!(child.contains("not the Nexus chain"), "{child}");
    for past_state in [json!(false), Value::Null] {
        let forgetful = check(nexus(), "genesis", 10, past_state).unwrap();
        assert!(forgetful.contains("no state of past blocks"), "{forgetful}");
    }
}

#[test]
fn an_address_pays_its_script_on_its_network_only() {
    let key = json(&new_bitcoin_key("regtest").unwrap());
    let address = key["address"].as_str().unwrap();
    assert_eq!(script_of(address, "regtest").unwrap(), key["script_pubkey"]);
    assert!(script_of(address, "bitcoin").is_err());
    assert!(script_of("nonsense", "regtest").is_err());
}

/// The offer the driver's JavaScript tests take, as its seller signed it:
/// the relay, which the signature does not cover, they point at their own.
#[cfg(not(target_arch = "wasm32"))]
#[test]
fn the_drivers_test_offer_is_signed() {
    let path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../web/driver/test/offer.json"
    );
    let offer = signed_offer("http://relay.invalid").encode();
    if std::env::var_os("WRITE_FIXTURES").is_some() {
        std::fs::write(path, &offer).unwrap();
    }
    assert_eq!(std::fs::read_to_string(path).unwrap(), offer);
}
