//! Bitcoin side of a NEX<->BTC atomic swap.
//!
//! The buyer locks BTC in a Taproot output that only the seller's key `A` and
//! the buyer's key `B` can spend together. From there one of four
//! transactions moves it:
//!
//! - `Redeem` pays the seller. The buyer's signature on it is an adaptor
//!   signature encrypted to the seller's Nexus share point `S`, so publishing
//!   it reveals `s`, which the buyer needs to claim the NEX.
//! - `Cancel` moves the BTC to the cancel output once `t1` blocks have passed
//!   since the lock confirmed. Both parties sign it during setup.
//! - `Refund` returns the BTC from the cancel output to the buyer. The seller's
//!   signature on it is encrypted to the buyer's share point `T_b`, so the
//!   refund reveals `b`, which lets the seller take back the NEX.
//! - `Punish` pays the cancel output to the seller alone after another `t2`
//!   blocks, if the buyer never refunds.
//!
//! Every output uses the BIP341 NUMS point as its internal key, so every spend
//! is a script-path spend. Each transaction pays one fixed absolute fee.
//!
//! The fee is fixed when the swap is set up. Each spend has exactly one
//! output, so the party it pays raises its feerate by CPFP: a child that
//! spends the payout itself (see [`cpfp`]), sent with it as a package and
//! replaced by a higher-paying child to bump again. Redeem and punish pay the
//! seller, refund pays the buyer, and nobody else can spend those outputs.
//! The spends are version 3 (TRUC) transactions, which Bitcoin Core relays as
//! 1-parent-1-child packages:
//!
//! - An unconfirmed TRUC transaction has at most one unconfirmed child, of at
//!   most 1000 vB, and only its payee can make one, so nobody else can pin it
//!   with a large child. Only a TRUC transaction may pay less than the
//!   minimum relay feerate, and only in a package that pays for it.
//! - Cancel cannot be bumped: its only output is the cancel output, which
//!   only both parties together, or the seller after `t2` blocks, can spend.
//!   A cancel that sits unconfirmed only delays the swap, since `t2` counts
//!   from cancel's confirmation.
//! - A pending redeem cannot be displaced by the buyer. After `t1` the
//!   buyer's only spends of the lock are cancel alone, which pays exactly
//!   redeem's fee where a replacement must pay more, and cancel with refund
//!   as one package, which [`Swap::new`] keeps strictly below redeem's
//!   feerate ([`Error::Outbid`]). No larger package exists: refund's child
//!   would be a grandchild of an unconfirmed cancel, which TRUC forbids, and
//!   punish needs cancel `t2` deep, so it never joins a cancel package. Once
//!   redeem is bumped it is only further ahead.
//! - A pending refund can be displaced only by punish, once cancel is `t2`
//!   deep: nothing else spends the cancel output but the 2-of-2.
//! - After `t2`, refund and punish both spend the cancel output, and each
//!   party bumps its own: a fee race between the two owners.
//! - A TRUC transaction spends no unconfirmed non-TRUC output. Redeem and
//!   cancel spend the lock, which is confirmed before either is sent.
//!
//! Rules for whoever drives these transactions:
//!
//! - The buyer funds the lock with exactly `amount` to `lock_script_pubkey`,
//!   from segwit inputs only, so the lock txid cannot be malleated after the
//!   cancel and refund signatures are made.
//! - Both parties use fresh shares and keys for every swap.
//! - The seller stops trying to redeem a safe margin before `t1`: a redeem
//!   still unconfirmed when cancel becomes valid can lose the race while `s`
//!   is already public.
//! - The buyer refunds a safe margin before `t2`, or the seller can punish.
//! - Both parties watch the mempool, not only blocks. A redeem in the mempool
//!   already reveals `s`, and a refund in the mempool already reveals `b`.

use bitcoin::absolute::LockTime;
use bitcoin::hashes::Hash;
use bitcoin::opcodes::all::{OP_CHECKSIG, OP_CHECKSIGVERIFY, OP_CSV, OP_DROP};
use bitcoin::script::Builder;
use bitcoin::secp256k1::{Secp256k1, XOnlyPublicKey};
use bitcoin::sighash::{Prevouts, SighashCache};
use bitcoin::taproot::{LeafVersion, TapLeafHash, TaprootBuilder, TaprootSpendInfo};
use bitcoin::transaction::Version;
use bitcoin::{
    Amount, OutPoint, ScriptBuf, Sequence, TapSighashType, Transaction, TxIn, TxOut, Witness,
};
use rand_core::OsRng;
use schnorr_fun::adaptor::{Adaptor, EncryptedSign};
use schnorr_fun::fun::nonce::{GlobalRng, Synthetic};
use schnorr_fun::{Message, Schnorr};
use sha2::Sha256;

pub use bitcoin;
pub use schnorr_fun;
pub use schnorr_fun::adaptor::EncryptedSignature;
pub use schnorr_fun::fun::marker::EvenY;
pub use schnorr_fun::fun::{KeyPair, Point, Scalar};
pub use schnorr_fun::Signature;

/// The BIP341 "H" point: a key nobody knows the discrete log of.
const NUMS: [u8; 32] = [
    0x50, 0x92, 0x9b, 0x74, 0xc1, 0xa0, 0x49, 0x54, 0xb7, 0x8b, 0x4b, 0x60, 0x35, 0xe9, 0x7a, 0x5e,
    0x07, 0x8a, 0x5a, 0x0f, 0x28, 0xec, 0x96, 0xd5, 0x47, 0xbf, 0xee, 0x9a, 0xce, 0x80, 0x3a, 0xc0,
];

/// Everything both parties agree on before the buyer funds the lock.
#[derive(Clone, Debug)]
pub struct Params {
    /// Seller's Bitcoin signing key `A`.
    pub seller: Point<EvenY>,
    /// Buyer's Bitcoin signing key `B`.
    pub buyer: Point<EvenY>,
    /// Seller's Nexus share point `S = s·G`; encrypts the redeem signature.
    pub seller_share: Point,
    /// Buyer's Nexus share point `T_b = b·G`; encrypts the refund signature.
    pub buyer_share: Point,
    /// Value of the lock output.
    pub amount: Amount,
    /// Absolute fee paid by each transaction.
    pub fee: Amount,
    /// Blocks after the lock confirms before cancel is valid.
    pub t1: u16,
    /// Blocks after cancel confirms before punish is valid.
    pub t2: u16,
    /// Where redeem pays the seller.
    pub redeem_payout: ScriptBuf,
    /// Where refund pays the buyer.
    pub refund_payout: ScriptBuf,
    /// Where punish pays the seller.
    pub punish_payout: ScriptBuf,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Spend {
    Redeem,
    Cancel,
    Refund,
    Punish,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Party {
    Seller,
    Buyer,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    /// A timelock is zero.
    Timelock,
    /// After fees, an output would be dust or negative.
    Amount,
    /// The fee is below 1 sat/vB for the largest of the four spends.
    Fee,
    /// Cancel and refund together would pay at least redeem's feerate, so
    /// the buyer could replace a pending redeem after `t1` with them.
    Outbid,
    /// `A == B` or `S == T_b`.
    Keys,
    /// This party's signature does not verify.
    Signature(Party),
    /// The spend needs a signature that was not given, or was given one it
    /// does not take.
    Signatures,
    /// The transaction is not the expected spend, or its signature is not the
    /// decryption of the given adaptor signature.
    Recovery,
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Error::Timelock => write!(f, "timelocks must be at least one block"),
            Error::Amount => write!(f, "amount does not cover fees above dust"),
            Error::Fee => write!(f, "fee is below the minimum relay fee"),
            Error::Outbid => write!(
                f,
                "cancel and refund would outbid redeem: the refund payout is too short"
            ),
            Error::Keys => write!(f, "the two parties' keys or shares are equal"),
            Error::Signature(party) => write!(f, "{party:?} signature does not verify"),
            Error::Signatures => write!(f, "wrong set of signatures for this spend"),
            Error::Recovery => write!(f, "no secret to recover from this transaction"),
        }
    }
}

impl std::error::Error for Error {}

type Bip340 = Schnorr<Sha256, Synthetic<Sha256, GlobalRng<OsRng>>>;

/// The swap's scripts and transactions, derived from [`Params`].
pub struct Swap {
    params: Params,
    two_of_two: ScriptBuf,
    cancel_leaf: ScriptBuf,
    punish_leaf: ScriptBuf,
    lock: TaprootSpendInfo,
    cancel: TaprootSpendInfo,
    schnorr: Bip340,
}

impl Swap {
    /// Fails if the parties' keys or shares coincide, a timelock is zero, any
    /// payout would be dust after fees, the fee is below 1 sat/vB for any
    /// spend (a refund that cannot relay would strand the BTC), or cancel
    /// and refund would outbid redeem (see [`Error::Outbid`]).
    pub fn new(params: Params) -> Result<Self, Error> {
        if params.seller == params.buyer || params.seller_share == params.buyer_share {
            return Err(Error::Keys);
        }
        if params.t1 == 0 || params.t2 == 0 {
            return Err(Error::Timelock);
        }
        let last = params
            .amount
            .checked_sub(params.fee)
            .and_then(|a| a.checked_sub(params.fee))
            .ok_or(Error::Amount)?;
        let payouts = [
            &params.redeem_payout,
            &params.refund_payout,
            &params.punish_payout,
        ];
        if payouts.iter().any(|s| last < s.minimal_non_dust()) {
            return Err(Error::Amount);
        }

        let a = xonly(&params.seller);
        let b = xonly(&params.buyer);
        let two_of_two = Builder::new()
            .push_x_only_key(&a)
            .push_opcode(OP_CHECKSIGVERIFY)
            .push_x_only_key(&b)
            .push_opcode(OP_CHECKSIG)
            .into_script();
        let cancel_leaf = Builder::new()
            .push_int(params.t1.into())
            .push_opcode(OP_CSV)
            .push_opcode(OP_DROP)
            .push_x_only_key(&a)
            .push_opcode(OP_CHECKSIGVERIFY)
            .push_x_only_key(&b)
            .push_opcode(OP_CHECKSIG)
            .into_script();
        let punish_leaf = Builder::new()
            .push_int(params.t2.into())
            .push_opcode(OP_CSV)
            .push_opcode(OP_DROP)
            .push_x_only_key(&a)
            .push_opcode(OP_CHECKSIG)
            .into_script();

        let lock = two_leaves(&two_of_two, &cancel_leaf);
        let cancel = two_leaves(&two_of_two, &punish_leaf);
        let swap = Self {
            params,
            two_of_two,
            cancel_leaf,
            punish_leaf,
            lock,
            cancel,
            schnorr: Bip340::default(),
        };

        // Size each spend with placeholder signatures: the witness has the
        // same shape and size once signed.
        let [redeem, cancel, refund, punish] =
            [Spend::Redeem, Spend::Cancel, Spend::Refund, Spend::Punish].map(|spend| {
                let buyer = (spend != Spend::Punish).then_some([0; 64]);
                let mut tx = swap.unsigned_tx(OutPoint::null(), spend);
                tx.input[0].witness = swap.witness(spend, [0; 64], buyer);
                tx.vsize() as u64
            });
        let largest = redeem.max(cancel).max(refund).max(punish);
        if swap.params.fee < Amount::from_sat(largest) {
            return Err(Error::Fee);
        }
        // Refund has no timelock, so after `t1` the buyer can send cancel
        // and refund as one package, paying two fees, against a redeem still
        // pending, whose `s` it has already read. Bitcoin Core takes the
        // package if it improves the mempool's feerate diagram, which it
        // does at an equal feerate too: it pays more in total, and the
        // diagram it replaces is flat past redeem. So the package's feerate,
        // 2·fee/(cancel + refund), must be strictly below redeem's,
        // fee/redeem. Core's feerates are over these same integer vsizes.
        if cancel + refund <= 2 * redeem {
            return Err(Error::Outbid);
        }
        Ok(swap)
    }

    pub fn params(&self) -> &Params {
        &self.params
    }

    /// The output the buyer funds with exactly `amount`.
    pub fn lock_script_pubkey(&self) -> ScriptBuf {
        ScriptBuf::new_p2tr_tweaked(self.lock.output_key())
    }

    /// The spend without its witness. `lock` is the funded lock output.
    /// Its one output is the payout, or for cancel the cancel output.
    pub fn unsigned_tx(&self, lock: OutPoint, spend: Spend) -> Transaction {
        let p = &self.params;
        let (input, sequence, payout) = match spend {
            Spend::Redeem => (lock, Sequence::MAX, p.redeem_payout.clone()),
            Spend::Cancel => (lock, Sequence::from_height(p.t1), self.cancel_output()),
            Spend::Refund => (
                self.cancel_outpoint(lock),
                Sequence::MAX,
                p.refund_payout.clone(),
            ),
            Spend::Punish => (
                self.cancel_outpoint(lock),
                Sequence::from_height(p.t2),
                p.punish_payout.clone(),
            ),
        };
        Transaction {
            version: Version::non_standard(3),
            lock_time: LockTime::ZERO,
            input: vec![TxIn {
                previous_output: input,
                script_sig: ScriptBuf::new(),
                sequence,
                witness: Witness::new(),
            }],
            output: vec![TxOut {
                value: self.spent_value(spend) - p.fee,
                script_pubkey: payout,
            }],
        }
    }

    /// BIP341 script-path sighash (`SIGHASH_DEFAULT`) of the spend.
    pub fn sighash(&self, lock: OutPoint, spend: Spend) -> [u8; 32] {
        self.sighash_of(&self.unsigned_tx(lock, spend), spend)
    }

    /// `tx`, whose one input spends the cancel output, signed by the seller
    /// alone through the punish leaf. That leaf takes no other signature, so
    /// the seller can sign any such transaction, whatever it pays, and not
    /// only the punish that [`Swap::finalize`] builds. For tests: it checks
    /// nothing, and panics if `tx` has no input.
    #[doc(hidden)]
    pub fn sign_punish_leaf(&self, mut tx: Transaction, key: &KeyPair<EvenY>) -> Transaction {
        let sighash = self.sighash_of(&tx, Spend::Punish);
        let signature = self.schnorr.sign(key, Message::raw(&sighash));
        tx.input[0].witness = self.witness(Spend::Punish, signature.to_bytes(), None);
        tx
    }

    /// The sighash of `tx`, whose one input spends what `spend` spends,
    /// through the same leaf.
    fn sighash_of(&self, tx: &Transaction, spend: Spend) -> [u8; 32] {
        let script_pubkey = match spend {
            Spend::Redeem | Spend::Cancel => self.lock_script_pubkey(),
            Spend::Refund | Spend::Punish => self.cancel_output(),
        };
        let prevout = TxOut {
            value: self.spent_value(spend),
            script_pubkey,
        };
        let leaf_hash = TapLeafHash::from_script(self.leaf(spend), LeafVersion::TapScript);
        SighashCache::new(tx)
            .taproot_script_spend_signature_hash(
                0,
                &Prevouts::All(&[prevout]),
                leaf_hash,
                TapSighashType::Default,
            )
            .expect("one input with its prevout")
            .to_byte_array()
    }

    /// An ordinary BIP340 signature on the spend.
    pub fn sign(&self, lock: OutPoint, spend: Spend, key: &KeyPair<EvenY>) -> Signature {
        let sighash = self.sighash(lock, spend);
        self.schnorr.sign(key, Message::raw(&sighash))
    }

    pub fn verify(&self, lock: OutPoint, spend: Spend, signer: Party, sig: &Signature) -> bool {
        let sighash = self.sighash(lock, spend);
        self.schnorr
            .verify(&self.key(signer), Message::raw(&sighash), sig)
    }

    /// The adaptor signature for `Redeem` (by the buyer, encrypted to `S`) or
    /// `Refund` (by the seller, encrypted to `T_b`). `None` for other spends.
    pub fn encrypted_sign(
        &self,
        lock: OutPoint,
        spend: Spend,
        key: &KeyPair<EvenY>,
    ) -> Option<EncryptedSignature> {
        let (_, encryption_key) = self.adaptor(spend)?;
        let sighash = self.sighash(lock, spend);
        Some(
            self.schnorr
                .encrypted_sign(key, &encryption_key, Message::raw(&sighash)),
        )
    }

    /// Checks that `encrypted` decrypts, under the spend's share point, to a
    /// valid signature on the spend by the party who should have made it.
    pub fn verify_encrypted(
        &self,
        lock: OutPoint,
        spend: Spend,
        encrypted: &EncryptedSignature,
    ) -> bool {
        let Some((signer, encryption_key)) = self.adaptor(spend) else {
            return false;
        };
        let sighash = self.sighash(lock, spend);
        self.schnorr.verify_encrypted_signature(
            &self.key(signer),
            &encryption_key,
            Message::raw(&sighash),
            encrypted,
        )
    }

    /// Decrypts an adaptor signature with a share secret. Only call this on a
    /// signature that passed [`Swap::verify_encrypted`]; publishing the result
    /// reveals `secret` to whoever made `encrypted`.
    pub fn decrypt(&self, secret: &Scalar, encrypted: &EncryptedSignature) -> Signature {
        self.schnorr.decrypt_signature(*secret, encrypted.clone())
    }

    /// The spend with its witness, ready to broadcast. `buyer` is `None` for
    /// `Punish` and required otherwise. Both signatures are verified first.
    pub fn finalize(
        &self,
        lock: OutPoint,
        spend: Spend,
        seller: &Signature,
        buyer: Option<&Signature>,
    ) -> Result<Transaction, Error> {
        if (spend == Spend::Punish) != buyer.is_none() {
            return Err(Error::Signatures);
        }
        if !self.verify(lock, spend, Party::Seller, seller) {
            return Err(Error::Signature(Party::Seller));
        }
        if let Some(buyer) = buyer {
            if !self.verify(lock, spend, Party::Buyer, buyer) {
                return Err(Error::Signature(Party::Buyer));
            }
        }

        let mut tx = self.unsigned_tx(lock, spend);
        tx.input[0].witness =
            self.witness(spend, seller.to_bytes(), buyer.map(Signature::to_bytes));
        Ok(tx)
    }

    /// The share secret revealed by a published `Redeem` (gives `s`) or
    /// `Refund` (gives `b`), given the adaptor signature that the party now
    /// learning it made earlier. The on-chain signature is verified first.
    pub fn recover_secret(
        &self,
        lock: OutPoint,
        spend: Spend,
        encrypted: &EncryptedSignature,
        published: &Transaction,
    ) -> Result<Scalar, Error> {
        let (signer, encryption_key) = self.adaptor(spend).ok_or(Error::Recovery)?;
        if published.compute_txid() != self.unsigned_tx(lock, spend).compute_txid() {
            return Err(Error::Recovery);
        }
        // Witness: [sig_B, sig_A, script, control block].
        let index = match signer {
            Party::Buyer => 0,
            Party::Seller => 1,
        };
        let sig = published.input[0]
            .witness
            .nth(index)
            .and_then(|bytes| <[u8; 64]>::try_from(bytes).ok())
            .and_then(Signature::from_bytes)
            .ok_or(Error::Signature(signer))?;
        if !self.verify(lock, spend, signer, &sig) {
            return Err(Error::Signature(signer));
        }
        self.schnorr
            .recover_decryption_key(&encryption_key, encrypted, &sig)
            .ok_or(Error::Recovery)
    }

    /// The script checks A first, so A's signature must be on top of the
    /// stack: the last element before the script.
    fn witness(&self, spend: Spend, seller: [u8; 64], buyer: Option<[u8; 64]>) -> Witness {
        let leaf = self.leaf(spend);
        let tree = match spend {
            Spend::Redeem | Spend::Cancel => &self.lock,
            Spend::Refund | Spend::Punish => &self.cancel,
        };
        let control = tree
            .control_block(&(leaf.clone(), LeafVersion::TapScript))
            .expect("leaf is in the tree");
        let mut witness = Witness::new();
        if let Some(buyer) = buyer {
            witness.push(buyer);
        }
        witness.push(seller);
        witness.push(leaf.as_bytes());
        witness.push(control.serialize());
        witness
    }

    fn cancel_output(&self) -> ScriptBuf {
        ScriptBuf::new_p2tr_tweaked(self.cancel.output_key())
    }

    fn cancel_outpoint(&self, lock: OutPoint) -> OutPoint {
        OutPoint::new(self.unsigned_tx(lock, Spend::Cancel).compute_txid(), 0)
    }

    /// Value of the output the spend consumes.
    fn spent_value(&self, spend: Spend) -> Amount {
        match spend {
            Spend::Redeem | Spend::Cancel => self.params.amount,
            Spend::Refund | Spend::Punish => self.params.amount - self.params.fee,
        }
    }

    fn leaf(&self, spend: Spend) -> &ScriptBuf {
        match spend {
            Spend::Redeem | Spend::Refund => &self.two_of_two,
            Spend::Cancel => &self.cancel_leaf,
            Spend::Punish => &self.punish_leaf,
        }
    }

    fn key(&self, party: Party) -> Point<EvenY> {
        match party {
            Party::Seller => self.params.seller,
            Party::Buyer => self.params.buyer,
        }
    }

    /// Who makes the adaptor signature for a spend, and to which point.
    fn adaptor(&self, spend: Spend) -> Option<(Party, Point)> {
        match spend {
            Spend::Redeem => Some((Party::Buyer, self.params.seller_share)),
            Spend::Refund => Some((Party::Seller, self.params.buyer_share)),
            Spend::Cancel | Spend::Punish => None,
        }
    }
}

/// A CPFP child of `parent`, unsigned: it spends the parent's payout,
/// output 0, and pays all of it but `fee` to `change`. Only the payee can
/// sign it. `None` if the change would be dust. Version 3, like its parent;
/// with one input and one output it stays far below the 1000 vB a TRUC
/// child may weigh. A child paying more replaces it.
pub fn cpfp(parent: &Transaction, change: ScriptBuf, fee: Amount) -> Option<Transaction> {
    let value = parent.output[0]
        .value
        .checked_sub(fee)
        .filter(|value| *value >= change.minimal_non_dust())?;
    Some(Transaction {
        version: Version::non_standard(3),
        lock_time: LockTime::ZERO,
        input: vec![TxIn {
            previous_output: OutPoint::new(parent.compute_txid(), 0),
            script_sig: ScriptBuf::new(),
            sequence: Sequence::MAX,
            witness: Witness::new(),
        }],
        output: vec![TxOut {
            value,
            script_pubkey: change,
        }],
    })
}

fn xonly(point: &Point<EvenY>) -> XOnlyPublicKey {
    XOnlyPublicKey::from_slice(&point.to_xonly_bytes()).expect("a valid point")
}

fn two_leaves(first: &ScriptBuf, second: &ScriptBuf) -> TaprootSpendInfo {
    let nums = XOnlyPublicKey::from_slice(&NUMS).expect("NUMS is on the curve");
    TaprootBuilder::new()
        .add_leaf(1, first.clone())
        .and_then(|b| b.add_leaf(1, second.clone()))
        .expect("two leaves at depth 1")
        .finalize(&Secp256k1::verification_only(), nums)
        .expect("complete tree")
}

#[cfg(test)]
mod tests {
    use super::*;
    use bitcoin::{Txid, WPubkeyHash};
    use sha2::Digest;

    fn key(n: u8) -> KeyPair<EvenY> {
        let mut bytes = [0u8; 32];
        bytes[31] = n;
        KeyPair::new_xonly(Scalar::from_bytes(bytes).unwrap().non_zero().unwrap())
    }

    fn payout() -> ScriptBuf {
        ScriptBuf::new_p2wpkh(&WPubkeyHash::from_byte_array([7; 20]))
    }

    fn params() -> Params {
        Params {
            seller: key(1).public_key(),
            buyer: key(2).public_key(),
            seller_share: key(3).public_key().normalize(),
            buyer_share: key(4).public_key().normalize(),
            amount: Amount::from_sat(100_000_000),
            fee: Amount::from_sat(1_000),
            t1: 288,
            t2: 144,
            redeem_payout: payout(),
            refund_payout: payout(),
            punish_payout: payout(),
        }
    }

    fn lock() -> OutPoint {
        OutPoint::new(Txid::from_byte_array([9; 32]), 0)
    }

    fn rejects(params: Params) -> Error {
        Swap::new(params).err().expect("rejected")
    }

    #[test]
    fn nums_is_the_hash_of_the_generator() {
        let g = schnorr_fun::fun::G.normalize().to_bytes_uncompressed();
        assert_eq!(<[u8; 32]>::from(Sha256::digest(g)), NUMS);
    }

    #[test]
    fn lock_output_key_is_pinned() {
        let swap = Swap::new(params()).unwrap();
        assert_eq!(
            swap.lock.output_key().to_x_only_public_key().to_string(),
            "9e6d383919aaf9fb2afab873372f44a7ce3573363068f630f05385e25e9ec67c"
        );
    }

    #[test]
    fn amount_must_cover_two_fees_above_dust() {
        let dust = payout().minimal_non_dust().to_sat();
        let fee = params().fee.to_sat();
        let with = |amount| Params {
            amount: Amount::from_sat(amount),
            ..params()
        };
        assert_eq!(rejects(with(fee - 1)), Error::Amount);
        assert_eq!(rejects(with(2 * fee - 1)), Error::Amount);
        assert_eq!(rejects(with(2 * fee + dust - 1)), Error::Amount);
        assert!(Swap::new(with(2 * fee + dust)).is_ok());
    }

    /// Nothing a third party can spend: each spend's one output pays its
    /// owner, and cancel's only output needs both parties, or the seller
    /// once cancel is `t2` deep.
    #[test]
    fn every_spend_is_truc_with_one_output_its_owner_spends() {
        let script = |n| ScriptBuf::new_p2wpkh(&WPubkeyHash::from_byte_array([n; 20]));
        let swap = Swap::new(Params {
            redeem_payout: script(1),
            refund_payout: script(2),
            punish_payout: script(3),
            ..params()
        })
        .unwrap();
        for (spend, payout) in [
            (Spend::Redeem, script(1)),
            (Spend::Cancel, swap.cancel_output()),
            (Spend::Refund, script(2)),
            (Spend::Punish, script(3)),
        ] {
            let tx = swap.unsigned_tx(lock(), spend);
            assert_eq!(tx.version, Version::non_standard(3));
            assert_eq!(tx.output.len(), 1, "{spend:?}");
            assert_eq!(tx.output[0].script_pubkey, payout, "{spend:?}");
            assert_eq!(swap.spent_value(spend) - tx.output[0].value, params().fee);
        }
        // The cancel output has no key path, and its leaves are the 2-of-2
        // and punish, which waits `t2` blocks: no unconfirmed cancel has a
        // child either party makes alone.
        assert_eq!(swap.cancel.internal_key().serialize(), NUMS);
        let leaves: Vec<&ScriptBuf> = swap.cancel.script_map().keys().map(|(s, _)| s).collect();
        assert_eq!(leaves.len(), 2);
        assert!(leaves.contains(&&swap.two_of_two));
        assert!(leaves.contains(&&swap.punish_leaf));
        assert!(swap.params().t2 > 0);
        let punish = swap.unsigned_tx(lock(), Spend::Punish);
        assert_eq!(
            punish.input[0].sequence,
            Sequence::from_height(swap.params().t2)
        );
        let refund = swap.unsigned_tx(lock(), Spend::Refund);
        let cancel = swap.unsigned_tx(lock(), Spend::Cancel);
        assert_eq!(
            refund.input[0].previous_output,
            OutPoint::new(cancel.compute_txid(), 0)
        );
    }

    #[test]
    fn a_child_spends_the_payout_and_keeps_above_dust() {
        let swap = Swap::new(params()).unwrap();
        let redeem = swap.unsigned_tx(lock(), Spend::Redeem);
        let value = redeem.output[0].value;
        let dust = payout().minimal_non_dust();
        let child = cpfp(&redeem, payout(), Amount::from_sat(500)).unwrap();
        assert_eq!(child.version, Version::non_standard(3));
        assert_eq!(
            child.input[0].previous_output,
            OutPoint::new(redeem.compute_txid(), 0)
        );
        assert_eq!(child.output[0].value, value - Amount::from_sat(500));
        assert!(cpfp(&redeem, payout(), value - dust).is_some());
        assert!(cpfp(&redeem, payout(), value - dust + Amount::ONE_SAT).is_none());
    }

    #[test]
    fn timelocks_must_be_nonzero() {
        assert_eq!(rejects(Params { t1: 0, ..params() }), Error::Timelock);
        assert_eq!(rejects(Params { t2: 0, ..params() }), Error::Timelock);
    }

    #[test]
    fn parties_must_differ() {
        let p = params();
        let same_key = Params {
            buyer: p.seller,
            ..params()
        };
        let same_share = Params {
            buyer_share: p.seller_share,
            ..params()
        };
        assert_eq!(rejects(same_key), Error::Keys);
        assert_eq!(rejects(same_share), Error::Keys);
    }

    #[test]
    fn fee_covers_one_sat_per_vbyte_of_the_largest_signed_spend() {
        let swap = Swap::new(params()).unwrap();
        let (seller, buyer) = (key(1), key(2));
        let largest = [Spend::Redeem, Spend::Cancel, Spend::Refund, Spend::Punish]
            .into_iter()
            .map(|spend| {
                let a = swap.sign(lock(), spend, &seller);
                let b = (spend != Spend::Punish).then(|| swap.sign(lock(), spend, &buyer));
                let tx = swap.finalize(lock(), spend, &a, b.as_ref()).unwrap();
                tx.vsize() as u64
            })
            .max()
            .unwrap();
        let with = |fee| Params {
            fee: Amount::from_sat(fee),
            ..params()
        };
        assert_eq!(rejects(with(0)), Error::Fee);
        assert_eq!(rejects(with(largest - 1)), Error::Fee);
        assert!(Swap::new(with(largest)).is_ok());
    }

    /// Accepted exactly when cancel and refund, signed, weigh more than two
    /// redeems: then their package pays a lower feerate than redeem alone.
    #[test]
    fn cancel_and_refund_must_pay_below_redeems_feerate() {
        let p2tr = |n| {
            let key = bitcoin::key::TweakedPublicKey::dangerous_assume_tweaked(xonly(
                &key(n).public_key(),
            ));
            ScriptBuf::new_p2tr_tweaked(key)
        };
        // A witness v2 program two bytes shorter than P2TR: at t1 = 288 it
        // makes cancel and refund exactly two redeems.
        let short = ScriptBuf::from_bytes([[0x52, 30].as_slice(), &[1; 30]].concat());
        // Cancel plus refund, less two redeems, in vbytes.
        let cases = [
            (payout(), payout(), 14),
            (p2tr(9), p2tr(10), 2),
            (payout(), p2tr(9), 26),
            (p2tr(9), payout(), -10),
            (p2tr(9), short, 0),
        ];
        let (seller, buyer) = (key(1), key(2));
        for (redeem_payout, refund_payout, margin) in cases {
            let p = Params {
                redeem_payout,
                refund_payout,
                ..params()
            };
            // Payouts are in no script, so a swap with these params signs
            // as one that `new` would build.
            let vsize = |spend| {
                let swap = Swap {
                    params: p.clone(),
                    ..Swap::new(params()).unwrap()
                };
                let a = swap.sign(lock(), spend, &seller);
                let b = swap.sign(lock(), spend, &buyer);
                swap.finalize(lock(), spend, &a, Some(&b)).unwrap().vsize() as i64
            };
            let signed = vsize(Spend::Cancel) + vsize(Spend::Refund) - 2 * vsize(Spend::Redeem);
            assert_eq!(signed, margin, "{p:?}");
            match Swap::new(p) {
                Ok(_) => assert!(margin > 0),
                Err(e) => assert_eq!((e, margin > 0), (Error::Outbid, false)),
            }
        }
    }

    #[test]
    fn finalize_takes_exactly_the_spend_signers() {
        let swap = Swap::new(params()).unwrap();
        let (seller, buyer) = (key(1), key(2));

        // Valid signatures, wrong count: punish is A alone, redeem needs both.
        let a = swap.sign(lock(), Spend::Punish, &seller);
        let b = swap.sign(lock(), Spend::Punish, &buyer);
        assert_eq!(
            swap.finalize(lock(), Spend::Punish, &a, Some(&b)),
            Err(Error::Signatures)
        );
        let a = swap.sign(lock(), Spend::Redeem, &seller);
        assert_eq!(
            swap.finalize(lock(), Spend::Redeem, &a, None),
            Err(Error::Signatures)
        );
    }
}
