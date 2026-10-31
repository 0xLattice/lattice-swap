//! The JSON surface, natively and in wasm.

use super::*;
use bitcoin::Amount;
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
    let restored = json(&restore(&backup(&seller).unwrap()).unwrap());
    assert_eq!(restored["side"], "seller");
    assert_eq!(restored["state"], json(&seller));

    let buyer = json(&start_buyer(&terms(), &payout(), "buyer-payout").unwrap());
    let state = text(&buyer["state"]).unwrap();
    let restored = json(&restore(&backup(&state).unwrap()).unwrap());
    assert_eq!(restored["side"], "buyer");
    assert_eq!(restored["state"], buyer["state"]);

    let other = json!({"version": STATE_VERSION + 1, "state": json(&seller)});
    assert!(restore(&other.to_string()).is_err());
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
