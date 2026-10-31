//! A NEX<->BTC swap end to end.
//!
//! The seller has NEX and wants BTC; the buyer has BTC and wants NEX. Each
//! side runs a [`Seller`] or [`Buyer`]: a state machine that takes an
//! [`Event`] (a message, what the chains show, a timeout) and returns the
//! next state and the [`Action`]s to take. The machines do no I/O. A
//! [`driver::Driver`] feeds them from a Bitcoin node, a Nexus node and an
//! ivy session, carries out their actions, and writes their state to disk
//! before any action, so a party that restarts picks up where it stopped.
//!
//! The order of a swap:
//!
//! 1. B -> S `BuyerHello`, S -> B `SellerHello`: Bitcoin keys, key shares
//!    with their cross-curve proofs, payout scripts.
//! 2. B -> S `LockProposal`: the funding transaction, unsigned. B has
//!    signed it but keeps it until it holds S's signatures.
//! 3. S -> B `SellerSignatures`: S's cancel signature and its refund
//!    adaptor signature. B -> S `BuyerSignatures`: B's cancel signature;
//!    then B broadcasts the funding transaction.
//! 4. Once the lock is `btc_confirmations` deep, S transfers `nex_amount`
//!    to the lock address and, once that is mined, sends `NexLocked`.
//! 5. B checks the NEX lock on its own node, then sends `RedeemSignature`,
//!    its redeem adaptor signature.
//! 6. S redeems the BTC, which reveals `s`; B claims the NEX.
//!
//! If S never redeems, B cancels after `t1` and refunds, which reveals
//! `b`, and S claims its NEX back. If B never refunds, S punishes after
//! `t2` and keeps the BTC.
//!
//! A seller that signed a NEX lock at nonce `n` and then learned `b` keeps
//! the shares and waits in `ClaimingNex` while the lock address holds less
//! than `nex_amount`:
//! the lock can still land until the seller's nonce passes `n`. If its node
//! refused that lock for good, the operator ends the wait by spending once
//! from the seller's Nexus wallet, at nonce `n`, with any transaction. Once
//! that is mined, and the seller's node still shows it after the tip has
//! moved `nex_confirmations` blocks without a reorg below where it was first
//! seen, the lock can never land, and the swap ends `Refunded`. Until then a
//! reorg could take that spend back and let the lock land.
//!
//! A buyer whose node never shows its funding transaction rebroadcasts it
//! and waits, keeping its secrets: other nodes may still hold the funding
//! and confirm it, and only those secrets can then refund it. The operator
//! ends the wait by spending one of the funding's inputs elsewhere; once
//! that is `btc_confirmations` deep the funding can no longer confirm and
//! the swap file can be discarded.
//!
//! Every timelock counts blocks after a confirmation, so every deadline here
//! is a number of confirmations: a transaction with a relative timelock of
//! `t` blocks can be broadcast once the output it spends is `t` deep.

pub mod bitcoind;
mod buyer;
pub mod driver;
mod seller;
pub mod transport;

pub use buyer::Buyer;
pub use seller::Seller;

use bitcoin::consensus::encode::{deserialize_hex, serialize_hex};
use bitcoin::{Amount, OutPoint, ScriptBuf, Transaction};
use curve25519_dalek::edwards::CompressedEdwardsY;
use rand_core::OsRng;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use swap_bitcoin::{EncryptedSignature, EvenY, KeyPair, Params, Point, Scalar, Signature};
use swap_bitcoin::{Party, Spend, Swap};
use swap_core::{secp256k1_point, secp256k1_scalar, share_from_secp256k1};
use swap_core::{PublicShare, ShareProof};
use swap_nexus::{JointKey, KeyShare};
use swap_nexus_tx::rpc::{Account, Health, TransactionStatus};
use swap_nexus_tx::{address, TransactionBody};

/// The ivy topic every swap message travels on.
pub const TOPIC: &str = "lattice-swap/v1";

/// What both parties agreed to off-band, before either says anything here.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Terms {
    /// Random, fresh for every swap; every message carries it.
    #[serde(with = "hex::serde")]
    pub swap_id: [u8; 32],
    #[serde(with = "bitcoin::amount::serde::as_sat")]
    pub btc_amount: Amount,
    /// Paid by each Bitcoin swap transaction, twice by redeem.
    #[serde(with = "bitcoin::amount::serde::as_sat")]
    pub btc_fee: Amount,
    pub nex_amount: u64,
    /// Paid by the NEX lock and by the claim from it.
    pub nex_fee: u64,
    /// Blocks after the lock confirms before cancel is valid. A short `t1`
    /// favours the buyer.
    pub t1: u16,
    /// Blocks after cancel confirms before punish is valid. A short `t2`
    /// favours the seller.
    pub t2: u16,
    pub btc_confirmations: u32,
    pub nex_confirmations: u64,
    /// Blocks of slack before a timelock: the seller stops redeeming once
    /// the lock is `t1 - margin + 1` deep, `margin - 1` blocks before
    /// cancel can be broadcast, so a redeem it sends has time to confirm.
    /// At least 2: a block can land between the view the seller judges the
    /// window on and its broadcast.
    pub margin: u16,
}

impl Terms {
    /// Whether the terms can work at all. Each party also checks them
    /// against its own policy before starting.
    pub fn check(&self) -> bool {
        let margin = u32::from(self.margin);
        self.btc_confirmations >= 1
            && self.nex_confirmations >= 1
            && self.margin >= 2
            && self.btc_confirmations + margin < u32::from(self.t1)
            // The buyer refunds once cancel is `btc_confirmations` deep, and
            // the refund needs time to confirm before punish is valid.
            && self.btc_confirmations + margin < u32::from(self.t2)
            && self.nex_amount > self.nex_fee
    }

    /// The seller may no longer broadcast the redeem: the lock is
    /// `t1 - margin + 1` deep, so the tip is `lock height + t1 - margin`.
    fn redeem_closed(&self, view: &BitcoinView) -> bool {
        view.funding.unwrap_or(0) > u32::from(self.t1 - self.margin)
    }

    /// Cancel may be broadcast.
    fn cancel_due(&self, view: &BitcoinView) -> bool {
        view.funding.unwrap_or(0) >= u32::from(self.t1)
    }
}

/// The messages, in the order they are sent.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum Message {
    BuyerHello {
        key: Point<EvenY>,
        share: Box<ShareProof>,
        refund_payout: ScriptBuf,
    },
    SellerHello {
        key: Point<EvenY>,
        share: Box<ShareProof>,
        redeem_payout: ScriptBuf,
        punish_payout: ScriptBuf,
    },
    /// The funding transaction without its witnesses: its txid is final,
    /// but the seller cannot broadcast it.
    LockProposal {
        #[serde(with = "hex_tx")]
        funding: Transaction,
        lock: OutPoint,
    },
    SellerSignatures {
        cancel: Signature,
        refund: EncryptedSignature,
    },
    BuyerSignatures {
        cancel: Signature,
    },
    /// The CID of the transaction that funded the NEX lock.
    NexLocked {
        cid: String,
    },
    RedeemSignature {
        redeem: EncryptedSignature,
    },
}

#[derive(Serialize, Deserialize)]
struct Envelope {
    #[serde(with = "hex::serde")]
    swap_id: [u8; 32],
    message: Message,
}

impl Message {
    pub fn encode(&self, swap_id: [u8; 32]) -> Vec<u8> {
        let envelope = Envelope {
            swap_id,
            message: self.clone(),
        };
        serde_json::to_vec(&envelope).expect("messages serialize")
    }

    /// The message in `bytes`, if it is one and belongs to `swap_id`.
    pub fn decode(bytes: &[u8], swap_id: [u8; 32]) -> Option<Self> {
        let envelope: Envelope = serde_json::from_slice(bytes).ok()?;
        (envelope.swap_id == swap_id).then_some(envelope.message)
    }
}

/// Something the driver saw. The machines act only on these.
#[derive(Clone, Debug)]
pub enum Event {
    Message(Message),
    Bitcoin(BitcoinView),
    Nexus(NexusView),
    /// The buyer's wallet built and signed the funding transaction.
    Funded(Transaction),
    /// The seller's Nexus wallet signed the transaction asked for.
    NexSigned(swap_nexus_tx::Transaction),
    /// The last message went out on the session.
    Sent,
    /// The counterparty went quiet before anything was at stake.
    Timeout,
}

/// Something a machine wants done. Every action that can fail is asked for
/// again on the next observation until what it was for is seen, so the
/// driver only logs failures.
#[allow(clippy::large_enum_variant)] // Short-lived: carried out as soon as made.
#[derive(Clone, Debug)]
pub enum Action {
    Send(Message),
    /// Build and sign, but do not broadcast, a transaction from the
    /// buyer's wallet paying `amount` to `script_pubkey`.
    FundLock {
        script_pubkey: ScriptBuf,
        amount: Amount,
    },
    Broadcast(Transaction),
    /// Sign with the seller's Nexus wallet key, which the state never
    /// holds, and answer with [`Event::NexSigned`].
    SignNex(TransactionBody),
    Submit(swap_nexus_tx::Transaction),
}

/// The swap's Bitcoin transactions as one node sees them.
#[derive(Clone, Debug)]
pub struct BitcoinView {
    /// The height of the tip.
    pub height: u32,
    /// Confirmations of the funding transaction: `None` if unseen, 0 in
    /// the mempool.
    pub funding: Option<u32>,
    /// What spends the lock output, in the mempool or a block.
    pub lock_spend: Option<Spent>,
    /// What spends the cancel output, if cancel spent the lock.
    pub cancel_spend: Option<Spent>,
}

#[derive(Clone, Debug)]
pub struct Spent {
    pub tx: Transaction,
    /// 0 in the mempool.
    pub confirmations: u32,
}

/// Nexus as one node sees it.
#[derive(Clone, Debug)]
pub struct NexusView {
    pub health: Health,
    /// The party's own address: the seller's funds, the buyer's payout.
    pub own: Account,
    /// The lock address at the tip.
    pub lock: Account,
    /// The smallest fee the node pools.
    pub min_relay_fee: u64,
    /// The transaction the machine watches, if it watches one and the node
    /// holds it, with its confirmations.
    pub watched: Option<(TransactionStatus, Option<u64>)>,
    /// The CID of the canonical block at [`NexusWatch::block_at`], if the
    /// machine asked for one and the node has it.
    pub block_at: Option<String>,
}

/// How a swap ended.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum Outcome {
    /// Stopped before anything was at stake.
    Aborted(Refusal),
    /// The buyer has the NEX; the seller has the BTC.
    Swapped,
    /// The buyer has its BTC back; the seller its NEX, if it locked any.
    Refunded,
    /// The seller took the BTC through punish.
    Punished,
    /// This party learned the joint key, but the lock was already spent.
    Drained,
}

/// Why a swap stopped before anything was at stake.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum Refusal {
    Terms,
    ShareProof,
    /// The counterparty sent back our own share or key.
    MirroredShare,
    /// `swap_bitcoin::Swap` refused the agreed parameters.
    Parameters,
    Funding,
    Signature,
    Timeout,
}

/// This party's secrets for one swap: fresh for every swap.
#[derive(Clone, Serialize, Deserialize)]
struct Secrets {
    #[serde(with = "hex::serde")]
    share: [u8; 32],
    #[serde(with = "hex::serde")]
    bitcoin: [u8; 32],
}

impl Secrets {
    fn random() -> Self {
        Self {
            share: KeyShare::random().to_bytes(),
            bitcoin: Scalar::random(&mut OsRng).to_bytes(),
        }
    }

    fn share(&self) -> KeyShare {
        KeyShare::from_bytes(self.share).expect("a key share")
    }

    fn key(&self) -> KeyPair<EvenY> {
        let scalar = Scalar::from_bytes(self.bitcoin)
            .and_then(|s| s.non_zero())
            .expect("a nonzero scalar");
        KeyPair::new_xonly(scalar)
    }

    fn public_share(&self) -> PublicShare {
        let share = self.share();
        PublicShare {
            ed25519: share.public(),
            secp256k1: secp256k1_point(&share),
        }
    }
}

/// A Nexus wallet's Ed25519 seed.
#[derive(Clone)]
pub struct SecretBytes(pub [u8; 32]);

impl SecretBytes {
    /// The Nexus address of these bytes as an Ed25519 seed.
    pub fn nex_address(&self) -> String {
        address(&self.signing_key().verifying_key().to_bytes())
    }

    fn signing_key(&self) -> ed25519_dalek::SigningKey {
        ed25519_dalek::SigningKey::from_bytes(&self.0)
    }
}

/// Which side of the swap this party is on.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
enum Side {
    Seller,
    Buyer,
}

/// Everything both sides know once the hellos are exchanged, and this
/// side's secrets.
#[derive(Clone, Serialize, Deserialize)]
pub struct Setup {
    terms: Terms,
    side: Side,
    secrets: Secrets,
    /// The counterparty's Bitcoin key.
    other_key: Point<EvenY>,
    /// The counterparty's share, on both curves.
    #[serde(with = "hex::serde")]
    other_ed25519: [u8; 32],
    other_secp256k1: Point,
    redeem_payout: ScriptBuf,
    refund_payout: ScriptBuf,
    punish_payout: ScriptBuf,
    /// This party's Nexus address: where the seller's NEX comes from and
    /// returns to, or where the buyer's arrives.
    nex_address: String,
}

struct Payouts {
    redeem: ScriptBuf,
    refund: ScriptBuf,
    punish: ScriptBuf,
}

impl Setup {
    /// Checks the counterparty's hello: its share proof, that it did not
    /// mirror ours, and that the Bitcoin transactions can be built.
    fn new(
        terms: Terms,
        side: Side,
        secrets: Secrets,
        other_key: Point<EvenY>,
        other_share: &ShareProof,
        payouts: Payouts,
        nex_address: String,
    ) -> Result<Self, Refusal> {
        let other = other_share.verify().ok_or(Refusal::ShareProof)?;
        if secrets.public_share().lock_key(&other).is_none()
            || other_key == secrets.key().public_key()
        {
            return Err(Refusal::MirroredShare);
        }
        let setup = Self {
            terms,
            side,
            secrets,
            other_key,
            other_ed25519: other.ed25519.compress().to_bytes(),
            other_secp256k1: other.secp256k1,
            redeem_payout: payouts.redeem,
            refund_payout: payouts.refund,
            punish_payout: payouts.punish,
            nex_address,
        };
        Swap::new(setup.params()).map_err(|_| Refusal::Parameters)?;
        Ok(setup)
    }

    fn params(&self) -> Params {
        let own_key = self.secrets.key().public_key();
        let own_share = self.secrets.public_share().secp256k1;
        let ((seller, seller_share), (buyer, buyer_share)) = match self.side {
            Side::Seller => ((own_key, own_share), (self.other_key, self.other_secp256k1)),
            Side::Buyer => ((self.other_key, self.other_secp256k1), (own_key, own_share)),
        };
        Params {
            seller,
            buyer,
            seller_share,
            buyer_share,
            amount: self.terms.btc_amount,
            fee: self.terms.btc_fee,
            t1: self.terms.t1,
            t2: self.terms.t2,
            redeem_payout: self.redeem_payout.clone(),
            refund_payout: self.refund_payout.clone(),
            punish_payout: self.punish_payout.clone(),
        }
    }

    fn swap(&self) -> Swap {
        Swap::new(self.params()).expect("checked when the setup was made")
    }

    fn other_share(&self) -> PublicShare {
        PublicShare {
            ed25519: CompressedEdwardsY(self.other_ed25519)
                .decompress()
                .expect("checked when the setup was made"),
            secp256k1: self.other_secp256k1,
        }
    }

    fn lock_address(&self) -> String {
        let key = self
            .secrets
            .public_share()
            .lock_key(&self.other_share())
            .expect("checked when the setup was made");
        address(&key)
    }

    /// Which swap transaction spent an output, and how deep it is.
    fn spend(&self, lock: OutPoint, spent: &Option<Spent>) -> Option<(Spend, u32)> {
        let spent = spent.as_ref()?;
        let swap = self.swap();
        let txid = spent.tx.compute_txid();
        [Spend::Redeem, Spend::Cancel, Spend::Refund, Spend::Punish]
            .into_iter()
            .find(|&spend| swap.unsigned_tx(lock, spend).compute_txid() == txid)
            .map(|spend| (spend, spent.confirmations))
    }

    /// Cancel with both signatures; `other` is the counterparty's.
    fn cancel(&self, lock: OutPoint, other: &Signature) -> Transaction {
        let swap = self.swap();
        let own = swap.sign(lock, Spend::Cancel, &self.secrets.key());
        let (seller, buyer) = match self.side {
            Side::Seller => (&own, other),
            Side::Buyer => (other, &own),
        };
        swap.finalize(lock, Spend::Cancel, seller, Some(buyer))
            .expect("both cancel signatures were verified")
    }

    /// The counterparty's share, from a redeem or refund it published and
    /// the adaptor signature we gave it. `None` unless it is exactly the
    /// share it proved at the start.
    fn recover(
        &self,
        lock: OutPoint,
        spend: Spend,
        adaptor: &EncryptedSignature,
        tx: &Transaction,
    ) -> Option<[u8; 32]> {
        let scalar = self.swap().recover_secret(lock, spend, adaptor, tx).ok()?;
        share_from_secp256k1(&scalar, &self.other_share()).map(|share| share.to_bytes())
    }

    fn decrypt(&self, adaptor: &EncryptedSignature) -> Signature {
        let secret = secp256k1_scalar(&self.secrets.share());
        self.swap().decrypt(&secret, adaptor)
    }
}

/// The lock output of a funding transaction: exactly one output pays the
/// lock script, with exactly the agreed amount, and no input carries a
/// scriptSig, which a segwit spend never needs.
fn lock_output(swap: &Swap, funding: &Transaction) -> Option<OutPoint> {
    let script = swap.lock_script_pubkey();
    let mut paying = (0..)
        .zip(&funding.output)
        .filter(|(_, out)| out.script_pubkey == script);
    let (vout, out) = paying.next()?;
    let only = paying.next().is_none();
    (only
        && out.value == swap.params().amount
        && funding.input.iter().all(|i| i.script_sig.is_empty()))
    .then(|| OutPoint::new(funding.compute_txid(), vout))
}

/// Whether the NEX lock can be trusted: the transaction the seller named
/// is on Nexus, credits the lock address at least `nex_amount` across all
/// its account actions, and is deep enough; the lock address holds at least
/// `nex_amount` and has never signed; and the node is synced.
fn nex_lock_holds(terms: &Terms, lock_address: &str, view: &NexusView) -> bool {
    let Some((tx, confirmations)) = &view.watched else {
        return false;
    };
    let credited: i128 = tx
        .body
        .account_actions
        .iter()
        .filter(|action| action.owner == lock_address)
        .map(|action| i128::from(action.delta))
        .sum();
    tx.body.chain_path == ["Nexus"]
        && credited >= i128::from(terms.nex_amount)
        && confirmations.is_some_and(|c| c >= terms.nex_confirmations)
        && view.lock.balance >= terms.nex_amount
        && view.lock.nonce == 0
        && synced(&view.health)
}

/// The node is active and has executed the best chain it knows.
fn synced(health: &Health) -> bool {
    health.phase == "active" && health.best_header_height == Some(health.height)
}

/// What the claimer knows of the NEX lock, which decides whether an empty
/// lock address is final.
#[derive(Clone, Copy, Serialize, Deserialize)]
enum Lock {
    /// The seller never signed one: an empty lock stays empty.
    Unsigned,
    /// The seller signed one at this nonce of its own. It can still land
    /// until the seller's nonce moves past it, and stays past it
    /// `nex_confirmations` blocks on one chain.
    Signed(u64),
    /// The buyer saw it confirmed: it is waited for.
    Seen,
}

/// Claiming the lock address once both shares are known.
#[derive(Clone, Serialize, Deserialize)]
pub struct Claim {
    setup: Setup,
    /// The counterparty's recovered share.
    #[serde(with = "hex::serde")]
    other: [u8; 32],
    lock: Lock,
    /// The Nexus tip, height and block CID, at which a synced node first
    /// showed a `Signed` lock that can no longer land: the seller's nonce
    /// past it, and the lock address short of `nex_amount`. Cleared once it
    /// shows otherwise, or that block leaves the canonical chain.
    #[serde(default)]
    passed_at: Option<(u64, String)>,
    /// The claim, signed once and submitted again, byte for byte, until it
    /// is mined. The joint key signs with fresh randomness: signed again,
    /// it would be another transaction under another CID.
    claim: Option<swap_nexus_tx::Transaction>,
}

#[allow(clippy::large_enum_variant)] // Short-lived: matched on as soon as made.
enum Claimed {
    Pending(Claim, Vec<Action>),
    /// The claim is `nex_confirmations` deep.
    Done,
    /// Nothing was locked, and nothing can be any more.
    Empty,
    /// Someone else spent the lock.
    Drained,
}

impl Claim {
    fn new(setup: Setup, other: [u8; 32], lock: Lock) -> Self {
        Self {
            setup,
            other,
            lock,
            passed_at: None,
            claim: None,
        }
    }

    /// Transfers `nex_amount`, less the fee, from the lock address to this
    /// party: the lock's first and only transaction, nonce 0.
    fn step(mut self, event: Event) -> Claimed {
        let Event::Nexus(view) = event else {
            return Claimed::Pending(self, vec![]);
        };
        let terms = &self.setup.terms;
        let depth = view.watched.as_ref().and_then(|(_, depth)| *depth);
        if let Some(claim) = &self.claim {
            return match depth {
                Some(depth) if depth >= terms.nex_confirmations => Claimed::Done,
                Some(_) => Claimed::Pending(self, vec![]),
                // The lock signed something, and it is not our claim.
                None if view.lock.nonce > 0 => Claimed::Drained,
                None => {
                    let submit = vec![Action::Submit(claim.clone())];
                    Claimed::Pending(self, submit)
                }
            };
        }
        if view.lock.nonce > 0 {
            return Claimed::Drained;
        }
        // Only a synced node shows the lock as it is.
        if !synced(&view.health) {
            return Claimed::Pending(self, vec![]);
        }
        // The claim is signed once, and debits exactly the `nex_amount` the
        // lock credits: never the momentary balance, whose extra dust a
        // reorg can take back and leave the claim refused forever.
        let fee = terms.nex_fee.max(view.min_relay_fee);
        if view.lock.balance >= terms.nex_amount && terms.nex_amount > fee {
            let claim = self.transaction(terms.nex_amount - fee, fee);
            self.claim = Some(claim.clone());
            return Claimed::Pending(self, vec![Action::Submit(claim)]);
        }
        // Below `nex_amount` the lock never landed: anyone may send it dust.
        let short = view.lock.balance < terms.nex_amount;
        let empty = match self.lock {
            Lock::Unsigned => short,
            // The seller's nonce moved past its lock, which did not credit
            // the lock address: the lock can never land, unless a reorg takes
            // back what moved the nonce. That must hold `nex_confirmations`
            // blocks of the tip. A reorg below the tip it was first seen at,
            // even one between two views, replaces that block: the count
            // starts again.
            Lock::Signed(nonce) if short && view.own.nonce > nonce => {
                let reorged = self
                    .passed_at
                    .as_ref()
                    .is_some_and(|(_, tip)| view.block_at.as_ref() != Some(tip));
                if reorged || self.passed_at.is_none() {
                    let tip = view.health.tip.clone();
                    self.passed_at = tip.map(|tip| (view.health.height, tip));
                }
                self.passed_at
                    .as_ref()
                    .is_some_and(|(since, _)| view.health.height >= since + terms.nex_confirmations)
            }
            Lock::Signed(_) => {
                self.passed_at = None;
                false
            }
            Lock::Seen => false,
        };
        if empty {
            Claimed::Empty
        } else {
            Claimed::Pending(self, vec![])
        }
    }

    fn transaction(&self, amount: u64, fee: u64) -> swap_nexus_tx::Transaction {
        let other = KeyShare::from_bytes(self.other).expect("a recovered share");
        let key = JointKey::from_shares(&self.setup.secrets.share(), &other);
        let body = TransactionBody::transfer(
            &self.setup.lock_address(),
            &self.setup.nex_address,
            amount,
            fee,
            0,
        )
        .expect("the amount is positive and fits");
        let mut transaction = swap_nexus_tx::Transaction::new(body);
        transaction.sign_joint(&key);
        transaction
    }

    fn watch(&self) -> Watch {
        let mut nexus = self.setup.watch_nexus(self.claim.as_ref().map(|c| c.cid()));
        if let Some(watch) = &mut nexus {
            watch.block_at = self.passed_at.as_ref().map(|(height, _)| *height);
        }
        Watch {
            bitcoin: None,
            nexus,
            margin: self.setup.terms.margin,
        }
    }
}

/// A party's side of the swap: [`Seller`] or [`Buyer`].
pub trait Machine: Clone + Serialize + serde::de::DeserializeOwned {
    /// The next state, and what to do before anything else is fed in.
    fn step(self, event: Event) -> (Self, Vec<Action>);
    /// How the swap ended, once it has.
    fn outcome(&self) -> Option<Outcome>;
    /// Nothing is at stake yet and the machine waits on the counterparty:
    /// if it stays quiet, the driver sends [`Event::Timeout`].
    fn awaits_message(&self) -> bool;
    fn watch(&self) -> Watch;
    /// The swap transactions that pay this side, which the driver bumps by
    /// CPFP from their payout while they wait unconfirmed. Never cancel,
    /// whose output only both parties together can spend.
    fn own_spends(&self) -> &'static [Spend];
}

/// What a driver should watch for a machine in its current state.
pub struct Watch {
    /// The swap and its lock output, once the lock is agreed.
    pub bitcoin: Option<(Swap, OutPoint)>,
    pub nexus: Option<NexusWatch>,
    /// [`Terms::margin`]: within this many blocks of its deadline a spend
    /// is bumped to a conservative estimate.
    pub margin: u16,
}

pub struct NexusWatch {
    pub lock_address: String,
    pub own_address: String,
    /// The transaction to report in [`NexusView::watched`].
    pub cid: Option<String>,
    /// The height whose block to report in [`NexusView::block_at`].
    pub block_at: Option<u64>,
}

impl Setup {
    fn watch_nexus(&self, cid: Option<String>) -> Option<NexusWatch> {
        Some(NexusWatch {
            lock_address: self.lock_address(),
            own_address: self.nex_address.clone(),
            cid,
            block_at: None,
        })
    }
}

/// A Bitcoin transaction as consensus hex.
mod hex_tx {
    use super::*;
    use serde::de::Error;

    pub fn serialize<S: Serializer>(tx: &Transaction, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&serialize_hex(tx))
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(
        deserializer: D,
    ) -> Result<Transaction, D::Error> {
        let hex = String::deserialize(deserializer)?;
        deserialize_hex(&hex).map_err(D::Error::custom)
    }
}

#[cfg(test)]
mod tests;
