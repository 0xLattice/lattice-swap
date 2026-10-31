//! Key setup for a NEX<->BTC swap.
//!
//! Each party picks one secret key share below 2^252. On Nexus it is an
//! Ed25519 scalar, half of the lock key; on Bitcoin the same integer is a
//! secp256k1 scalar, the adaptor secret that a claim on Bitcoin reveals.
//! Before either side locks anything, each proves to the other that its two
//! public points share one secret it knows. Without that proof a party
//! could publish a Bitcoin adaptor point that does not open the NEX, or a
//! Nexus point chosen to cancel the other's share.
//!
//! The two curves write scalars in opposite byte orders: Ed25519
//! little-endian, secp256k1 big-endian. Every conversion goes through this
//! crate.
//!
//! The proof comes from `sigma_fun`, which works over the
//! `curve25519-dalek-ng` fork; Ed25519 values cross into it as bytes.

use curve25519_dalek::edwards::{CompressedEdwardsY, EdwardsPoint};
use curve25519_dalek_ng as ng;
use rand_chacha::ChaCha20Rng;
use rand_core::OsRng;
use secp256kfun::marker::{NonZero, Normal, Public, Secrecy, Secret, ZeroChoice};
use secp256kfun::{Point, Scalar, G};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256, Sha512};
use sigma_fun::ext::dl_secp256k1_ed25519_eq::{CrossCurveDLEQ, CrossCurveDLEQProof};
use sigma_fun::HashTranscript;
use std::sync::LazyLock;
use swap_nexus::{joint_public_key, KeyShare};
use zeroize::Zeroizing;

type ProofSystem = CrossCurveDLEQ<HashTranscript<Sha256, ChaCha20Rng>>;

/// The proof system, with second generators no one knows the discrete log
/// of.
static PROOF_SYSTEM: LazyLock<ProofSystem> =
    LazyLock::new(|| ProofSystem::new(secp256k1_generator(), ed25519_generator()));

fn secp256k1_generator() -> Point {
    Point::hash_to_curve_sswu::<Sha256>(b"H", b"lattice-swap/dleq/secp256k1/v1").normalize()
}

/// The first point in the prime-order subgroup found by hashing a fixed
/// label and a counter.
fn ed25519_generator() -> ng::edwards::EdwardsPoint {
    (0u32..)
        .find_map(|counter| {
            let hash = Sha512::new()
                .chain_update(b"lattice-swap/dleq/ed25519/v1")
                .chain_update(counter.to_be_bytes())
                .finalize();
            let point = ng::edwards::CompressedEdwardsY::from_slice(&hash[..32])
                .decompress()?
                .mul_by_cofactor();
            (!point.is_small_order()).then_some(point)
        })
        .expect("some counter lands on the curve")
}

/// One party's share as public points on both curves.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PublicShare {
    /// Half of the Nexus lock key.
    pub ed25519: EdwardsPoint,
    /// The Bitcoin adaptor point.
    pub secp256k1: Point,
}

/// What a party sends: its public share and the proof that both points
/// share one secret.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ShareProof {
    ed25519: [u8; 32],
    secp256k1: Point,
    proof: CrossCurveDLEQProof,
}

impl ShareProof {
    /// Proves `share`. Takes several hundred milliseconds.
    pub fn new(share: &KeyShare) -> Self {
        let bytes = Zeroizing::new(share.to_bytes());
        let secret = Zeroizing::new(
            ng::scalar::Scalar::from_canonical_bytes(*bytes).expect("key shares are canonical"),
        );
        let (proof, (secp256k1, ed25519)) = PROOF_SYSTEM.prove(&secret, &mut OsRng);
        Self {
            ed25519: ed25519.compress().to_bytes(),
            secp256k1,
            proof,
        }
    }

    /// The prover's public share, if the proof holds and both points are
    /// usable: the Ed25519 point in the prime-order subgroup and not of
    /// small order.
    pub fn verify(&self) -> Option<PublicShare> {
        let ed25519 = usable_ed25519(self.ed25519)?;
        let claim = ng::edwards::CompressedEdwardsY(self.ed25519).decompress()?;
        PROOF_SYSTEM
            .verify(&self.proof, (self.secp256k1, claim))
            .then_some(PublicShare {
                ed25519,
                secp256k1: self.secp256k1,
            })
    }
}

/// The point `bytes` encode, if it is usable as a share: in the
/// prime-order subgroup and not of small order. A torsion component would
/// carry into the lock key, which no pair of scalars could then sign for.
fn usable_ed25519(bytes: [u8; 32]) -> Option<EdwardsPoint> {
    let point = CompressedEdwardsY(bytes).decompress()?;
    (point.is_torsion_free() && !point.is_small_order()).then_some(point)
}

impl PublicShare {
    /// The Nexus lock key for this share and the counterparty's. None if
    /// the counterparty sent back our own share: neither party alone may
    /// know the lock key's secret.
    pub fn lock_key(&self, other: &PublicShare) -> Option<[u8; 32]> {
        if self.ed25519 == other.ed25519 || self.secp256k1 == other.secp256k1 {
            return None;
        }
        joint_public_key(&self.ed25519, &other.ed25519)
    }
}

/// `share` as the secp256k1 scalar: the same integer, big-endian.
pub fn secp256k1_scalar(share: &KeyShare) -> Scalar<Secret, NonZero> {
    let mut bytes = Zeroizing::new(share.to_bytes());
    bytes.reverse();
    Scalar::from_bytes(*bytes)
        .and_then(|scalar| scalar.non_zero())
        .expect("key shares are nonzero and below the secp256k1 order")
}

/// The counterparty's key share, from the secp256k1 scalar recovered on
/// Bitcoin: None unless it is the share behind `expected` on both curves.
pub fn share_from_secp256k1(
    scalar: &Scalar<impl Secrecy, impl ZeroChoice>,
    expected: &PublicShare,
) -> Option<KeyShare> {
    let mut bytes = Zeroizing::new(scalar.to_bytes());
    bytes.reverse();
    let share = KeyShare::from_bytes(*bytes)?;
    (share.public() == expected.ed25519 && secp256k1_point(&share) == expected.secp256k1)
        .then_some(share)
}

/// `share`'s secp256k1 point.
pub fn secp256k1_point(share: &KeyShare) -> Point<Normal, Public, NonZero> {
    secp256kfun::g!({ secp256k1_scalar(share) } * G).normalize()
}

#[cfg(test)]
mod tests {
    use super::*;
    use curve25519_dalek::constants::ED25519_BASEPOINT_TABLE;

    #[test]
    fn a_proof_ties_both_points_to_the_share() {
        let share = KeyShare::random();
        let proof = ShareProof::new(&share);
        let public = proof.verify().expect("an honest proof verifies");
        assert_eq!(public.ed25519, share.public());
        assert_eq!(public.secp256k1, secp256k1_point(&share));
    }

    #[test]
    fn a_proof_for_other_points_fails() {
        let (a, b) = (KeyShare::random(), KeyShare::random());
        let mut proof = ShareProof::new(&a);
        // Swap in b's secp256k1 point: the claim no longer matches the proof.
        proof.secp256k1 = secp256k1_point(&b);
        assert!(proof.verify().is_none());
        let mut proof = ShareProof::new(&a);
        proof.ed25519 = b.public().compress().to_bytes();
        assert!(proof.verify().is_none());
    }

    #[test]
    fn ed25519_points_with_torsion_are_refused() {
        use curve25519_dalek::constants::EIGHT_TORSION;
        let point = KeyShare::random().public();
        assert_eq!(usable_ed25519(point.compress().to_bytes()), Some(point));
        // The identity is torsion-free but of small order.
        assert!(usable_ed25519(EIGHT_TORSION[0].compress().to_bytes()).is_none());
        for torsion in &EIGHT_TORSION[1..] {
            // A point with a torsion component, and a small-order point.
            assert!(usable_ed25519((point + torsion).compress().to_bytes()).is_none());
            assert!(usable_ed25519(torsion.compress().to_bytes()).is_none());
        }
    }

    /// Two builds that derive different generators cannot verify each
    /// other's proofs.
    #[test]
    fn the_generators_are_pinned() {
        assert_eq!(
            hex(&secp256k1_generator().to_bytes()),
            "0231fec8a8da0398e3fd2de3e2a6db0c6d0282f053f303c3bf425653800e264b66"
        );
        assert_eq!(
            hex(ed25519_generator().compress().as_bytes()),
            "914cfa94d58753eb0c0acdeea58064cff5a13f40e40e8978e9750ec5afd8437f"
        );
    }

    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{b:02x}")).collect()
    }

    #[test]
    fn a_mirrored_share_gives_no_lock_key() {
        let public = ShareProof::new(&KeyShare::random()).verify().unwrap();
        assert!(public.lock_key(&public).is_none());
    }

    #[test]
    fn a_share_mirrored_on_either_curve_gives_no_lock_key() {
        let (a, b) = (
            ShareProof::new(&KeyShare::random()).verify().unwrap(),
            ShareProof::new(&KeyShare::random()).verify().unwrap(),
        );
        assert!(a.lock_key(&b).is_some());
        let secp_mirror = PublicShare {
            secp256k1: a.secp256k1,
            ..b
        };
        assert!(a.lock_key(&secp_mirror).is_none());
        let ed_mirror = PublicShare {
            ed25519: a.ed25519,
            ..b
        };
        assert!(a.lock_key(&ed_mirror).is_none());
    }

    #[test]
    fn proofs_survive_serialization() {
        let share = KeyShare::random();
        let json = serde_json::to_string(&ShareProof::new(&share)).unwrap();
        let proof: ShareProof = serde_json::from_str(&json).unwrap();
        assert_eq!(proof.verify().unwrap().ed25519, share.public());
    }

    /// The byte-order pitfall: the same integer is little-endian on
    /// Ed25519 and big-endian on secp256k1.
    #[test]
    fn scalars_change_byte_order_between_curves() {
        let mut le = [0u8; 32];
        le[0] = 0x01;
        le[1] = 0x02;
        le[31] = 0x0a;
        let share = KeyShare::from_bytes(le).unwrap();
        let mut be = [0u8; 32];
        be[31] = 0x01;
        be[30] = 0x02;
        be[0] = 0x0a;
        assert_eq!(secp256k1_scalar(&share).to_bytes(), be);
        // 0x0a00..0201 times each generator, computed independently.
        let ed = &curve25519_dalek::Scalar::from_bytes_mod_order(le) * ED25519_BASEPOINT_TABLE;
        assert_eq!(share.public(), ed);
        let secp = Scalar::<Secret, NonZero>::from_bytes(be).unwrap();
        assert_eq!(
            secp256k1_point(&share),
            secp256kfun::g!(secp * G).normalize()
        );
        // And back from a scalar recovered on Bitcoin.
        let public = PublicShare {
            ed25519: share.public(),
            secp256k1: secp256k1_point(&share),
        };
        let recovered = share_from_secp256k1(&secp256k1_scalar(&share), &public).unwrap();
        assert_eq!(recovered.to_bytes(), le);
    }

    #[test]
    fn only_the_expected_share_is_recovered() {
        let (share, other) = (KeyShare::random(), KeyShare::random());
        let public = ShareProof::new(&share).verify().unwrap();
        assert!(share_from_secp256k1(&secp256k1_scalar(&other), &public).is_none());
        // Negated, as BIP340 parity handling might leave it.
        assert!(share_from_secp256k1(&-secp256k1_scalar(&share), &public).is_none());
        let mut be = [0u8; 32];
        be[0] = 0x10;
        let high = Scalar::<Secret, NonZero>::from_bytes(be).unwrap();
        assert!(share_from_secp256k1(&high, &public).is_none());
    }

    #[test]
    fn a_recovered_share_must_match_both_points() {
        let (share, other) = (KeyShare::random(), KeyShare::random());
        let scalar = secp256k1_scalar(&share);
        let public = PublicShare {
            ed25519: share.public(),
            secp256k1: secp256k1_point(&share),
        };
        assert!(share_from_secp256k1(&scalar, &public).is_some());
        let wrong_ed25519 = PublicShare {
            ed25519: other.public(),
            ..public
        };
        assert!(share_from_secp256k1(&scalar, &wrong_ed25519).is_none());
        let wrong_secp256k1 = PublicShare {
            secp256k1: secp256k1_point(&other),
            ..public
        };
        assert!(share_from_secp256k1(&scalar, &wrong_secp256k1).is_none());
    }

    #[test]
    fn both_parties_compute_the_same_lock_key() {
        let (s, b) = (KeyShare::random(), KeyShare::random());
        let (seller, buyer) = (
            ShareProof::new(&s).verify().unwrap(),
            ShareProof::new(&b).verify().unwrap(),
        );
        assert_eq!(seller.lock_key(&buyer), buyer.lock_key(&seller));
        assert_eq!(
            seller.lock_key(&buyer).unwrap(),
            swap_nexus::JointKey::from_shares(&s, &b).public_key()
        );
    }
}
