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
use rand_core::{OsRng, RngCore};
use sha2::{Digest, Sha512};
use zeroize::Zeroize;

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
pub fn joint_public_key(a: &EdwardsPoint, b: &EdwardsPoint) -> [u8; 32] {
    (a + b).compress().to_bytes()
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
    pub fn sign(&self, message: &[u8]) -> [u8; 64] {
        sign_with_scalar(&self.secret, &self.public, message)
    }
}

impl Drop for JointKey {
    fn drop(&mut self) {
        self.secret.zeroize();
    }
}

fn sign_with_scalar(secret: &Scalar, public: &CompressedEdwardsY, message: &[u8]) -> [u8; 64] {
    // The nonce mixes fresh randomness with the key and message, so it is
    // never reused even if the random source repeats. A reused nonce would
    // leak the joint key.
    let mut entropy = [0u8; 32];
    OsRng.fill_bytes(&mut entropy);
    let mut nonce = Scalar::from_hash(
        Sha512::new()
            .chain_update(entropy)
            .chain_update(secret.to_bytes())
            .chain_update(message),
    );
    entropy.zeroize();

    let r = (&nonce * ED25519_BASEPOINT_TABLE).compress();
    let k = Scalar::from_hash(
        Sha512::new()
            .chain_update(r.as_bytes())
            .chain_update(public.as_bytes())
            .chain_update(message),
    );
    let s = nonce + k * secret;
    nonce.zeroize();

    let mut signature = [0u8; 64];
    signature[..32].copy_from_slice(r.as_bytes());
    signature[32..].copy_from_slice(s.as_bytes());
    signature
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
            joint_public_key(&a.public(), &b.public())
        );
        assert!(verifies(joint.public_key(), MESSAGE, joint.sign(MESSAGE)));
    }

    #[test]
    fn one_share_cannot_sign_for_the_lock_key() {
        let (a, b) = (KeyShare::random(), KeyShare::random());
        let lock_key = JointKey::from_shares(&a, &b).public;
        let forged = sign_with_scalar(&a.0, &lock_key, MESSAGE);
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
    fn nonces_are_fresh() {
        let joint = JointKey::from_shares(&KeyShare::random(), &KeyShare::random());
        assert_ne!(joint.sign(MESSAGE)[..32], joint.sign(MESSAGE)[..32]);
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
