//! Lattice 54.2.1's conformance vectors (see `vectors/README.md`).

use ciborium::Value as Cbor;
use ed25519_dalek::SigningKey;
use serde_json::Value;
use swap_nexus_tx::{
    address, cid, multikey_hex, signed_bytes, verify, AccountAction, Transaction, TransactionBody,
};

fn vectors(name: &str) -> Vec<Value> {
    let path = format!("{}/tests/vectors/{name}.json", env!("CARGO_MANIFEST_DIR"));
    let file: Value = serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap();
    assert_eq!(file["version"], 1);
    file["vectors"].as_array().unwrap().clone()
}

fn text(v: &Value) -> &str {
    v.as_str().unwrap()
}

/// A body from a vector's readable `value`, or `None` if it uses an action
/// kind this crate does not build.
fn body_from_json(value: &Value) -> Option<TransactionBody> {
    for kind in [
        "actions",
        "depositActions",
        "receiptActions",
        "withdrawalActions",
    ] {
        if !value[kind].as_array().unwrap().is_empty() {
            return None;
        }
    }
    let strings = |v: &Value| {
        v.as_array()
            .unwrap()
            .iter()
            .map(|s| text(s).into())
            .collect()
    };
    Some(TransactionBody {
        account_actions: value["accountActions"]
            .as_array()
            .unwrap()
            .iter()
            .map(|a| AccountAction {
                owner: text(&a["owner"]).into(),
                delta: a["delta"].as_i64().unwrap(),
            })
            .collect(),
        signers: strings(&value["signers"]),
        nonce: value["nonce"].as_u64().unwrap(),
        chain_path: strings(&value["chainPath"]),
    })
}

/// The same from DAG-CBOR bytes, through a generic CBOR decoder.
fn body_from_cbor(bytes: &[u8]) -> Option<TransactionBody> {
    fn to_json(v: Cbor) -> Value {
        match v {
            Cbor::Integer(n) => Value::from(i64::try_from(i128::from(n)).unwrap()),
            Cbor::Text(t) => Value::from(t),
            Cbor::Array(items) => Value::Array(items.into_iter().map(to_json).collect()),
            Cbor::Map(entries) => Value::Object(
                entries
                    .into_iter()
                    .map(|(k, v)| (k.into_text().unwrap(), to_json(v)))
                    .collect(),
            ),
            other => panic!("unexpected CBOR {other:?}"),
        }
    }
    body_from_json(&to_json(ciborium::from_reader(bytes).unwrap()))
}

fn private_key_for(public_multikey: &str) -> SigningKey {
    let entry = vectors("addresses")
        .into_iter()
        .find(|v| v["publicKey"] == public_multikey)
        .expect("signing vector key is in addresses.json");
    let seed: [u8; 32] = hex::decode(text(&entry["privateKey"]))
        .unwrap()
        .try_into()
        .unwrap();
    SigningKey::from_bytes(&seed)
}

#[test]
fn transaction_bodies_encode_byte_for_byte() {
    let mut skipped = Vec::new();
    for v in vectors("encoding")
        .iter()
        .filter(|v| v["type"] == "TransactionBody")
    {
        let Some(body) = body_from_json(&v["value"]) else {
            skipped.push(text(&v["name"]).to_string());
            continue;
        };
        assert_eq!(
            hex::encode(body.to_dag_cbor()),
            text(&v["dagCborHex"]),
            "{}",
            v["name"]
        );
        assert_eq!(body.cid(), text(&v["cid"]), "{}", v["name"]);
    }
    assert_eq!(
        skipped,
        [
            "transaction-body/action",
            "transaction-body/deposit-action",
            "transaction-body/receipt-action",
            "transaction-body/withdrawal-action",
        ],
        "only the action kinds this crate does not build are skipped"
    );
}

#[test]
fn every_cid_vector_hashes_its_bytes() {
    for v in vectors("encoding") {
        let bytes = hex::decode(text(&v["dagCborHex"])).unwrap();
        assert_eq!(cid(&bytes), text(&v["cid"]), "{}", v["name"]);
    }
}

#[test]
fn addresses_derive_byte_for_byte() {
    for v in vectors("addresses") {
        let key: [u8; 32] = hex::decode(text(&v["publicKeyEd25519Hex"]))
            .unwrap()
            .try_into()
            .unwrap();
        assert_eq!(multikey_hex(&key), text(&v["publicKey"]), "{}", v["name"]);
        assert_eq!(address(&key), text(&v["address"]), "{}", v["name"]);
        let node = hex::decode(text(&v["publicKeyNodeDagCborHex"])).unwrap();
        assert_eq!(cid(&node), text(&v["address"]), "{}", v["name"]);
        if let Some(seed) = v["privateKey"].as_str() {
            let seed: [u8; 32] = hex::decode(seed).unwrap().try_into().unwrap();
            let derived = SigningKey::from_bytes(&seed).verifying_key().to_bytes();
            assert_eq!(derived, key, "{}", v["name"]);
        }
    }
}

#[test]
fn signing_vectors_reproduce_and_negatives_fail() {
    let all = vectors("signing");
    let mut positives = 0;
    for v in &all {
        let name = text(&v["name"]);
        let (message, public_key, signature) = (
            text(&v["message"]),
            text(&v["publicKey"]),
            text(&v["signature"]),
        );
        let valid = v["valid"].as_bool().unwrap();

        let verdict = if v["scheme"] == "transaction" {
            let bytes = hex::decode(text(&v["transactionBodyDagCborHex"])).unwrap();
            let body = body_from_cbor(&bytes).expect(name);
            assert_eq!(body.to_dag_cbor(), bytes, "{name}: re-encode");
            assert_eq!(body.cid(), text(&v["transactionBodyCid"]), "{name}");
            verify(&body.signing_preimage(), public_key, signature)
        } else {
            verify(message, public_key, signature)
        };
        assert_eq!(verdict, valid, "{name}: verification");

        if valid {
            positives += 1;
            assert_eq!(
                hex::encode(signed_bytes(message)),
                text(&v["signedBytesHex"])
            );
            let key = private_key_for(public_key);
            if v["scheme"] == "transaction" {
                let bytes = hex::decode(text(&v["transactionBodyDagCborHex"])).unwrap();
                let body = body_from_cbor(&bytes).unwrap();
                assert_eq!(body.signing_preimage(), message, "{name}: preimage");
                assert_eq!(hex::encode(body.signed_bytes()), text(&v["signedBytesHex"]));
                let mut transaction = Transaction::new(body);
                transaction.sign(&key);
                assert_eq!(transaction.signatures[public_key], signature, "{name}");
            } else {
                use ed25519_dalek::Signer;
                let ours = key.sign(&signed_bytes(message)).to_bytes();
                assert_eq!(hex::encode(ours), signature, "{name}");
            }
        }
    }
    assert_eq!(positives, 4);
}

#[test]
fn two_signer_transaction_needs_both_signatures() {
    let all = vectors("signing");
    let signer = |who: &str| {
        all.iter()
            .find(|v| v["name"] == format!("transaction/two-signers/{who}"))
            .unwrap()
    };
    let (alice, carol) = (signer("alice"), signer("carol"));
    let bytes = hex::decode(text(&alice["transactionBodyDagCborHex"])).unwrap();
    let mut transaction = Transaction::new(body_from_cbor(&bytes).unwrap());
    for v in [alice, carol] {
        transaction
            .signatures
            .insert(text(&v["publicKey"]).into(), text(&v["signature"]).into());
    }
    assert!(transaction.verify());
    transaction.signatures.remove(text(&carol["publicKey"]));
    assert!(!transaction.verify());
}
