//! The JSON surface, natively and in wasm.

use super::*;
use bitcoin::hashes::Hash;
use bitcoin::{Amount, OutPoint, Txid};
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
    let backed_up = json(&backup(&seller).unwrap());
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
    json(&backup(state).unwrap())["file"]
        .as_str()
        .unwrap()
        .into()
}

#[test]
fn only_a_running_swap_is_backed_up() {
    assert!(backup("{}").is_err());
    assert!(backup(r#"{"AwaitBuyerHello": {}}"#).is_err());
    let done = text(&json!({"Done": "Swapped"})).unwrap();
    assert!(backup(&done).unwrap_err().contains("over"));
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
