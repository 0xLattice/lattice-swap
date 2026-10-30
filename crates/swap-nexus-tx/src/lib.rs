//! Nexus transactions for the swap: the transfers that lock NEX at the joint
//! key's address and claim it from there.
//!
//! Encoding, addresses and signing match Lattice 54.2.1 (cashew 5.0.3 DAG-CBOR)
//! byte for byte; `tests/vectors` holds Lattice's own conformance vectors.
//! Only account actions (transfers) are built here: the body's other action
//! lists are always empty.

mod cbor;
pub mod rpc;

use std::collections::BTreeMap;

use cbor::Value;
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use sha2::{Digest, Sha256};
use swap_nexus::JointKey;

/// Every signed message is this prefix followed by the message text.
pub const SIGNATURE_DOMAIN: &str = "lattice-tx-v1:";
const TRANSACTION_DOMAIN: &str = "lattice-tx-v1";
const ED25519_MULTIKEY_PREFIX: &str = "ed01";

/// The CID Lattice gives DAG-CBOR bytes: CIDv1, dag-cbor, sha2-256, printed as
/// multibase base32 (`b`, lowercase, no padding).
pub fn cid(dag_cbor: &[u8]) -> String {
    let mut binary = vec![0x01, 0x71, 0x12, 0x20];
    binary.extend_from_slice(&Sha256::digest(dag_cbor));
    let base32 = data_encoding::BASE32_NOPAD.encode(&binary);
    format!("b{}", base32.to_ascii_lowercase())
}

/// The Multikey hex Lattice names an Ed25519 key by.
pub fn multikey_hex(public_key: &[u8; 32]) -> String {
    format!("{ED25519_MULTIKEY_PREFIX}{}", hex::encode(public_key))
}

/// The account address of an Ed25519 key: the CID of its `PublicKey` node,
/// `{"key": <multikey hex>}`.
pub fn address(public_key: &[u8; 32]) -> String {
    cid(&public_key_node(&multikey_hex(public_key)))
}

fn public_key_node(multikey: &str) -> Vec<u8> {
    Value::Map(vec![("key", Value::Text(multikey.into()))]).encode()
}

/// One balance change. Negative is a debit, which its owner must sign.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AccountAction {
    pub owner: String,
    pub delta: i64,
}

/// A `TransactionBody` whose only actions are account actions.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TransactionBody {
    pub account_actions: Vec<AccountAction>,
    /// Addresses whose keys sign; every debited owner must be one.
    pub signers: Vec<String>,
    /// The first signer's next nonce.
    pub nonce: u64,
    pub chain_path: Vec<String>,
}

impl TransactionBody {
    /// Moves `amount` from `from` to `to` on Nexus and leaves `fee` to the
    /// miner. Lattice has no fee field: the fee is what the debits exceed the
    /// credits by. `None` if the debit does not fit an `i64`.
    pub fn transfer(from: &str, to: &str, amount: u64, fee: u64, nonce: u64) -> Option<Self> {
        let debit = i64::try_from(amount.checked_add(fee)?).ok()?;
        Some(Self {
            account_actions: vec![
                AccountAction {
                    owner: from.into(),
                    delta: -debit,
                },
                AccountAction {
                    owner: to.into(),
                    delta: debit - fee as i64,
                },
            ],
            signers: vec![from.into()],
            nonce,
            chain_path: vec!["Nexus".into()],
        })
    }

    pub fn to_dag_cbor(&self) -> Vec<u8> {
        let texts =
            |items: &[String]| Value::Array(items.iter().cloned().map(Value::Text).collect());
        let empty = || Value::Array(Vec::new());
        let account_actions = self
            .account_actions
            .iter()
            .map(|action| {
                Value::Map(vec![
                    ("owner", Value::Text(action.owner.clone())),
                    ("delta", Value::Int(action.delta.into())),
                ])
            })
            .collect();
        Value::Map(vec![
            ("accountActions", Value::Array(account_actions)),
            ("actions", empty()),
            ("depositActions", empty()),
            ("receiptActions", empty()),
            ("withdrawalActions", empty()),
            ("signers", texts(&self.signers)),
            ("nonce", Value::Int(self.nonce.into())),
            ("chainPath", texts(&self.chain_path)),
        ])
        .encode()
    }

    pub fn cid(&self) -> String {
        cid(&self.to_dag_cbor())
    }

    /// The text a signer signs (after [`SIGNATURE_DOMAIN`]). It binds the
    /// chain path and nonce beside the body CID, which already commits to them.
    pub fn signing_preimage(&self) -> String {
        let body_cid = self.cid();
        let mut lines = vec![
            format!("domain:{}:{TRANSACTION_DOMAIN}", TRANSACTION_DOMAIN.len()),
            format!("chainPath.count:{}", self.chain_path.len()),
        ];
        for component in &self.chain_path {
            lines.push(format!(
                "chainPath.component:{}:{component}",
                component.len()
            ));
        }
        lines.push(format!("nonce:{}", self.nonce));
        lines.push(format!("bodyCID:{}:{body_cid}", body_cid.len()));
        lines.join("\n")
    }

    /// The exact bytes an Ed25519 signature on this body covers.
    pub fn signed_bytes(&self) -> Vec<u8> {
        signed_bytes(&self.signing_preimage())
    }

    /// The body as `POST /transactions` takes it: 64-bit integers are
    /// decimal strings.
    pub fn to_wire_json(&self) -> serde_json::Value {
        let account_actions: Vec<_> = self
            .account_actions
            .iter()
            .map(|a| serde_json::json!({"owner": a.owner, "delta": a.delta.to_string()}))
            .collect();
        serde_json::json!({
            "accountActions": account_actions,
            "actions": [],
            "depositActions": [],
            "receiptActions": [],
            "withdrawalActions": [],
            "signers": self.signers,
            "nonce": self.nonce.to_string(),
            "chainPath": self.chain_path,
        })
    }
}

/// `UTF8(SIGNATURE_DOMAIN + message)`.
pub fn signed_bytes(message: &str) -> Vec<u8> {
    format!("{SIGNATURE_DOMAIN}{message}").into_bytes()
}

/// Lattice's `CryptoUtils.verify`: `public_key` must be canonical Ed25519
/// Multikey hex and `signature` lowercase hex, each the one spelling Lattice
/// accepts. Verification is cofactorless and refuses a non-canonical `S`, as
/// BoringSSL does.
pub fn verify(message: &str, public_key: &str, signature: &str) -> bool {
    let Some(key) = public_key
        .strip_prefix(ED25519_MULTIKEY_PREFIX)
        .and_then(lowercase_hex::<32>)
    else {
        return false;
    };
    let Some(signature) = lowercase_hex::<64>(signature) else {
        return false;
    };
    let Ok(key) = VerifyingKey::from_bytes(&key) else {
        return false;
    };
    key.verify(&signed_bytes(message), &Signature::from_bytes(&signature))
        .is_ok()
}

fn lowercase_hex<const N: usize>(text: &str) -> Option<[u8; N]> {
    let bytes: [u8; N] = hex::decode(text).ok()?.try_into().ok()?;
    (hex::encode(bytes) == text).then_some(bytes)
}

/// A body and its signatures, keyed by signer Multikey hex.
#[derive(Clone, Debug)]
pub struct Transaction {
    pub body: TransactionBody,
    pub signatures: BTreeMap<String, String>,
}

impl Transaction {
    pub fn new(body: TransactionBody) -> Self {
        Self {
            body,
            signatures: BTreeMap::new(),
        }
    }

    /// Signs with an ordinary Ed25519 key (deterministic, RFC 8032).
    pub fn sign(&mut self, key: &SigningKey) {
        let signature = key.sign(&self.body.signed_bytes()).to_bytes();
        self.add_signature(&key.verifying_key().to_bytes(), &signature);
    }

    /// Signs for the lock address with the joint key.
    pub fn sign_joint(&mut self, key: &JointKey) {
        let signature = key.sign(&self.body.signed_bytes());
        self.add_signature(&key.public_key(), &signature);
    }

    pub fn add_signature(&mut self, public_key: &[u8; 32], signature: &[u8; 64]) {
        self.signatures
            .insert(multikey_hex(public_key), hex::encode(signature));
    }

    /// Every signature verifies, the signing keys' addresses are exactly the
    /// body's signers, and every debited owner is a signer.
    pub fn verify(&self) -> bool {
        let preimage = self.body.signing_preimage();
        let mut signed = Vec::new();
        for (key, signature) in &self.signatures {
            if !verify(&preimage, key, signature) {
                return false;
            }
            signed.push(cid(&public_key_node(key)));
        }
        let mut signers = self.body.signers.clone();
        signed.sort();
        signers.sort();
        signers.dedup();
        let debits_signed = self
            .body
            .account_actions
            .iter()
            .all(|a| a.delta >= 0 || signers.contains(&a.owner));
        signed == signers && signers.len() == self.body.signers.len() && debits_signed
    }

    /// The request body of `POST /transactions`.
    pub fn to_submit_json(&self) -> serde_json::Value {
        serde_json::json!({
            "transaction": {
                "signatures": self.signatures,
                "body": self.body.to_wire_json(),
            }
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use swap_nexus::KeyShare;

    fn key(byte: u8) -> SigningKey {
        SigningKey::from_bytes(&[byte; 32])
    }

    fn addr(key: &SigningKey) -> String {
        address(&key.verifying_key().to_bytes())
    }

    #[test]
    fn transfer_leaves_the_fee_as_surplus() {
        let body = TransactionBody::transfer("a", "b", 100, 7, 3).unwrap();
        let deltas: Vec<i64> = body.account_actions.iter().map(|a| a.delta).collect();
        assert_eq!(deltas, [-107, 100]);
        assert_eq!(body.signers, ["a"]);
        assert!(TransactionBody::transfer("a", "b", i64::MAX as u64, 1, 0).is_none());
        assert!(TransactionBody::transfer("a", "b", u64::MAX, 1, 0).is_none());
    }

    #[test]
    fn signed_transfer_verifies_and_tampering_breaks_it() {
        let alice = key(1);
        let body = TransactionBody::transfer(&addr(&alice), &addr(&key(2)), 5, 1, 0).unwrap();
        let mut transaction = Transaction::new(body);
        transaction.sign(&alice);
        assert!(transaction.verify());

        let mut tampered = transaction.clone();
        tampered.body.account_actions[1].delta += 1;
        assert!(!tampered.verify());

        let mut wrong_key = Transaction::new(transaction.body.clone());
        wrong_key.sign(&key(2));
        assert!(
            !wrong_key.verify(),
            "signer set must match the signing keys"
        );
    }

    #[test]
    fn joint_key_spends_its_address() {
        let joint = JointKey::from_shares(&KeyShare::random(), &KeyShare::random());
        let lock = address(&joint.public_key());
        let body = TransactionBody::transfer(&lock, &addr(&key(3)), 5, 1, 0).unwrap();
        let mut transaction = Transaction::new(body);
        transaction.sign_joint(&joint);
        assert!(transaction.verify());
    }

    #[test]
    fn wire_json_spells_64_bit_integers_as_strings() {
        let body = TransactionBody::transfer("a", "b", 5, 1, 9).unwrap();
        let wire = body.to_wire_json();
        assert_eq!(wire["nonce"], "9");
        assert_eq!(wire["accountActions"][0]["delta"], "-6");
        assert_eq!(wire["chainPath"], serde_json::json!(["Nexus"]));
    }
}
