//! Nexus side of a NEX<->BTC atomic swap.
//!
//! The NEX lock address belongs to the Ed25519 key `(s + b)·G`, where `s` and
//! `b` are the two parties' key shares. Neither share can sign for it alone;
//! whoever learns both signs an ordinary Lattice transaction with the summed
//! scalar. Lattice verifies standard Ed25519, which never sees how the scalar
//! was formed, so signing here starts from a raw scalar instead of an RFC 8032
//! seed.

use curve25519_dalek::constants::ED25519_BASEPOINT_TABLE;
use curve25519_dalek::edwards::{CompressedEdwardsY, EdwardsPoint};
use curve25519_dalek::scalar::Scalar;
use ed25519_dalek::hazmat::{raw_sign, ExpandedSecretKey};
use ed25519_dalek::VerifyingKey;
use rand_core::{OsRng, RngCore};
use sha2::{Digest, Sha512};
use zeroize::{Zeroize, Zeroizing};

/// One party's secret key share.
///
/// Always below 2^252, so the same integer is also a valid secp256k1 scalar:
/// the cross-curve proof binds this share to its Bitcoin-side adaptor point.
pub struct KeyShare(Scalar);

impl KeyShare {
    pub fn random() -> Self {
        loop {
            let mut bytes = [0u8; 32];
            OsRng.fill_bytes(&mut bytes);
            bytes[31] &= 0x0f;
            let share = Self::from_bytes(bytes);
            bytes.zeroize();
            if let Some(share) = share {
                return share;
            }
        }
    }

    /// Little-endian bytes of a nonzero scalar below 2^252.
    pub fn from_bytes(bytes: [u8; 32]) -> Option<Self> {
        if bytes[31] & 0xf0 != 0 {
            return None;
        }
        let scalar = Option::<Scalar>::from(Scalar::from_canonical_bytes(bytes))?;
        (scalar != Scalar::ZERO).then_some(Self(scalar))
    }

    pub fn to_bytes(&self) -> [u8; 32] {
        self.0.to_bytes()
    }

    pub fn public(&self) -> EdwardsPoint {
        &self.0 * ED25519_BASEPOINT_TABLE
    }
}

impl Drop for KeyShare {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

/// The lock address key, computed from the two public shares.
///
/// `None` if either share or the sum is the identity or has a small-order
/// component: such a lock key is not `x·G` for the joint secret, and
/// cofactorless verifiers (BoringSSL) would reject most honest signatures,
/// stranding the NEX. This does not stop a rogue key (`b·G = X - a·G`); the
/// counterparty's share is only safe to use after its cross-curve proof
/// verifies.
pub fn joint_public_key(a: &EdwardsPoint, b: &EdwardsPoint) -> Option<[u8; 32]> {
    let sum = a + b;
    let usable = |p: &EdwardsPoint| p.is_torsion_free() && !p.is_small_order();
    (usable(a) && usable(b) && usable(&sum)).then(|| sum.compress().to_bytes())
}

/// The spending key for the lock address, once both shares are known.
pub struct JointKey {
    secret: Scalar,
    public: CompressedEdwardsY,
}

impl JointKey {
    pub fn from_shares(a: &KeyShare, b: &KeyShare) -> Self {
        let secret = a.0 + b.0;
        let public = (&secret * ED25519_BASEPOINT_TABLE).compress();
        Self { secret, public }
    }

    pub fn public_key(&self) -> [u8; 32] {
        self.public.to_bytes()
    }

    /// Ed25519 signature over `message`: the exact bytes Lattice verifies
    /// (`lattice-tx-v1:` followed by the transaction's signing preimage).
    /// Deterministic, as RFC 8032: signed again, the same message gives the
    /// same signature, so the same transaction under the same CID.
    pub fn sign(&self, message: &[u8]) -> [u8; 64] {
        sign_with_scalar(&self.secret, message)
    }
}

impl Drop for JointKey {
    fn drop(&mut self) {
        self.secret.zeroize();
    }
}

/// RFC 8032 Ed25519 signing (§5.1.6) from a raw scalar. With no seed to
/// expand, the hash prefix that RFC 8032 takes from the seed's SHA-512 is
/// taken from the scalar's, under a domain tag: the nonce
/// `SHA-512(prefix || message)` is then a function of the key and the
/// message, as in RFC 8032. The same message signs to the same bytes; another
/// message, or another key, gets another nonce. The public key is the
/// scalar's own, never passed in: a signature under a mismatched public key
/// would leak the key (RUSTSEC-2022-0093).
fn sign_with_scalar(secret: &Scalar, message: &[u8]) -> [u8; 64] {
    let digest: Zeroizing<[u8; 64]> = Zeroizing::new(
        Sha512::new()
            .chain_update(b"lattice-swap/joint-key/hash-prefix")
            .chain_update(secret.as_bytes())
            .finalize()
            .into(),
    );
    let key = ExpandedSecretKey {
        scalar: *secret,
        hash_prefix: digest[..32].try_into().expect("32 bytes"),
    };
    let public = VerifyingKey::from(&key);
    raw_sign::<Sha512>(&key, message, &public).to_bytes()
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signature, VerifyingKey};

    const MESSAGE: &[u8] = b"lattice-tx-v1:domain:13:lattice-tx-v1";

    fn verifies(public: [u8; 32], message: &[u8], signature: [u8; 64]) -> bool {
        VerifyingKey::from_bytes(&public)
            .unwrap()
            .verify_strict(message, &Signature::from_bytes(&signature))
            .is_ok()
    }

    #[test]
    fn joint_key_signature_verifies_under_the_lock_key() {
        let (a, b) = (KeyShare::random(), KeyShare::random());
        let joint = JointKey::from_shares(&a, &b);
        assert_eq!(
            joint.public_key(),
            joint_public_key(&a.public(), &b.public()).unwrap()
        );
        assert!(verifies(joint.public_key(), MESSAGE, joint.sign(MESSAGE)));
    }

    #[test]
    fn lock_key_rejects_small_order_and_identity_shares() {
        use curve25519_dalek::constants::EIGHT_TORSION;
        use curve25519_dalek::traits::Identity;
        let a = KeyShare::random().public();
        let b = KeyShare::random().public();
        let torsion = EIGHT_TORSION[1];
        assert!(joint_public_key(&a, &(b + torsion)).is_none());
        assert!(joint_public_key(&a, &torsion).is_none());
        assert!(joint_public_key(&a, &EdwardsPoint::identity()).is_none());
        assert!(joint_public_key(&a, &-a).is_none());
    }

    #[test]
    fn one_share_cannot_sign_for_the_lock_key() {
        let (a, b) = (KeyShare::random(), KeyShare::random());
        let lock_key = JointKey::from_shares(&a, &b).public;
        let forged = sign_with_scalar(&a.0, MESSAGE);
        assert!(!verifies(lock_key.to_bytes(), MESSAGE, forged));
    }

    #[test]
    fn signature_does_not_carry_to_another_message() {
        let joint = JointKey::from_shares(&KeyShare::random(), &KeyShare::random());
        let signature = joint.sign(MESSAGE);
        assert!(!verifies(
            joint.public_key(),
            b"lattice-tx-v1:other",
            signature
        ));
    }

    #[test]
    fn signing_is_deterministic() {
        let (a, b) = (KeyShare::random(), KeyShare::random());
        let first = JointKey::from_shares(&a, &b).sign(MESSAGE);
        let again = JointKey::from_shares(&a, &b).sign(MESSAGE);
        assert_eq!(first, again);
    }

    #[test]
    fn nonces_differ_by_message_and_by_key() {
        let (a, b) = (KeyShare::random(), KeyShare::random());
        let r = |secret: &Scalar, message: &[u8]| sign_with_scalar(secret, message)[..32].to_vec();
        assert_ne!(r(&a.0, MESSAGE), r(&a.0, b"lattice-tx-v1:other"));
        assert_ne!(r(&a.0, MESSAGE), r(&b.0, MESSAGE));
    }

    #[test]
    fn shares_stay_below_2_pow_252() {
        for _ in 0..256 {
            assert_eq!(KeyShare::random().to_bytes()[31] & 0xf0, 0);
        }
    }

    #[test]
    fn share_bytes_reject_zero_and_out_of_range() {
        assert!(KeyShare::from_bytes([0; 32]).is_none());
        let mut high = [0u8; 32];
        high[31] = 0x10;
        assert!(KeyShare::from_bytes(high).is_none());
        let mut one = [0u8; 32];
        one[0] = 1;
        assert_eq!(KeyShare::from_bytes(one).unwrap().to_bytes(), one);
    }
}
