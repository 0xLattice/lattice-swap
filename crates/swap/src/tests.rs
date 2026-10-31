//! Both machines against each other, with the chains made up: every path,
//! and a counterparty that cheats at each step.

use std::cell::RefCell;
use std::rc::Rc;
use std::time::Duration;

use super::*;
use crate::bitcoind::Bitcoin;
use crate::driver::{Driver, Store};
use crate::transport::Transport;
use bitcoin::hashes::Hash;
use bitcoin::{FeeRate, Script, TxIn, TxOut, Txid, WPubkeyHash, Witness};
use serde_json::json;
use swap_nexus_tx::rpc::{Client, Inclusion};

const SELLER_NEX: SecretBytes = SecretBytes([7; 32]);
const BUYER_NEX: &str = "buyer-payout";

fn terms() -> Terms {
    Terms {
        swap_id: [1; 32],
        btc_amount: Amount::from_sat(1_000_000),
        btc_fee: Amount::from_sat(1_000),
        nex_amount: 500_000,
        nex_fee: 100,
        t1: 20,
        t2: 10,
        btc_confirmations: 1,
        nex_confirmations: 1,
        margin: 3,
    }
}

fn payout(n: u8) -> ScriptBuf {
    ScriptBuf::new_p2wpkh(&WPubkeyHash::from_byte_array([n; 20]))
}

fn sends(actions: &[Action]) -> Vec<Message> {
    actions
        .iter()
        .filter_map(|a| match a {
            Action::Send(m) => Some(m.clone()),
            _ => None,
        })
        .collect()
}

fn sent(actions: &[Action]) -> Message {
    let [message] = &sends(actions)[..] else {
        panic!("expected one message in {actions:?}");
    };
    message.clone()
}

fn broadcasts(actions: &[Action]) -> Vec<Transaction> {
    actions
        .iter()
        .filter_map(|a| match a {
            Action::Broadcast(tx) => Some(tx.clone()),
            _ => None,
        })
        .collect()
}

fn submitted(actions: &[Action]) -> swap_nexus_tx::Transaction {
    match actions {
        [Action::Submit(tx)] => tx.clone(),
        _ => panic!("expected one submission in {actions:?}"),
    }
}

fn message(m: Message) -> Event {
    Event::Message(m)
}

/// A signed funding transaction from one segwit input, with change.
fn funding(actions: &[Action]) -> Transaction {
    let [Action::FundLock {
        script_pubkey,
        amount,
    }] = actions
    else {
        panic!("expected a funding request in {actions:?}");
    };
    Transaction {
        version: bitcoin::transaction::Version::TWO,
        lock_time: bitcoin::absolute::LockTime::ZERO,
        input: vec![TxIn {
            previous_output: OutPoint::new(Txid::from_byte_array([3; 32]), 1),
            script_sig: ScriptBuf::new(),
            sequence: bitcoin::Sequence::MAX,
            witness: Witness::from_slice(&[[0u8; 72].as_slice(), &[2u8; 33]]),
        }],
        output: vec![
            TxOut {
                value: Amount::from_sat(40_000),
                script_pubkey: payout(9),
            },
            TxOut {
                value: *amount,
                script_pubkey: script_pubkey.clone(),
            },
        ],
    }
}

/// The lock at `funding` confirmations, mined at height 101.
fn btc(
    funding: u32,
    lock_spend: Option<(&Transaction, u32)>,
    cancel_spend: Option<(&Transaction, u32)>,
) -> Event {
    let spent = |s: Option<(&Transaction, u32)>| {
        s.map(|(tx, confirmations)| Spent {
            tx: tx.clone(),
            confirmations,
        })
    };
    Event::Bitcoin(BitcoinView {
        height: 100 + funding,
        funding: Some(funding),
        lock_spend: spent(lock_spend),
        cancel_spend: spent(cancel_spend),
    })
}

fn healthy() -> Health {
    synced_at(10)
}

/// The CID the made-up Nexus chain shows at every height: it never reorgs.
const BLOCK: &str = "bafyblock";

fn synced_at(height: u64) -> Health {
    Health {
        phase: "active".into(),
        height,
        best_header_height: Some(height),
        tip: Some(BLOCK.into()),
    }
}

fn syncing() -> Health {
    Health {
        best_header_height: Some(11),
        ..healthy()
    }
}

fn nexus(lock: Account, watched: Option<(TransactionStatus, Option<u64>)>) -> Event {
    nexus_at(healthy(), account(10_000_000, 3), lock, watched)
}

fn nexus_at(
    health: Health,
    own: Account,
    lock: Account,
    watched: Option<(TransactionStatus, Option<u64>)>,
) -> Event {
    Event::Nexus(NexusView {
        health,
        own,
        lock,
        min_relay_fee: 0,
        watched,
        block_at: Some(BLOCK.into()),
    })
}

/// The seller's wallet answering its request to sign.
fn signed_nex(actions: &[Action]) -> Event {
    let [Action::SignNex(body)] = actions else {
        panic!("expected a request to sign in {actions:?}");
    };
    let mut transaction = swap_nexus_tx::Transaction::new(body.clone());
    transaction.sign(&SELLER_NEX.signing_key());
    Event::NexSigned(transaction)
}

/// A party saved to disk and loaded again.
fn restart<M: Machine>(machine: &M) -> M {
    serde_json::from_str(&serde_json::to_string(machine).unwrap()).unwrap()
}

fn account(balance: u64, nonce: u64) -> Account {
    Account { balance, nonce }
}

fn mined(body: TransactionBody, depth: u64) -> Option<(TransactionStatus, Option<u64>)> {
    let status = TransactionStatus {
        body,
        block: Some(Inclusion {
            height: 10 + 1 - depth,
            hash: BLOCK.into(),
        }),
    };
    Some((status, Some(depth)))
}

/// Both parties after the hellos, the lock proposal and the signatures:
/// the buyer has broadcast the funding transaction.
struct Locked {
    seller: Seller,
    buyer: Buyer,
}

fn hellos() -> (Seller, Buyer, Vec<Action>) {
    hellos_with(terms())
}

fn new_seller(terms: Terms) -> Seller {
    Seller::new(terms, SELLER_NEX.nex_address(), payout(1), payout(2)).unwrap()
}

fn hellos_with(terms: Terms) -> (Seller, Buyer, Vec<Action>) {
    let seller = new_seller(terms.clone());
    let (buyer, actions) = Buyer::start(terms, payout(3), BUYER_NEX.into()).unwrap();
    let (seller, actions) = seller.step(message(sent(&actions)));
    let (buyer, actions) = buyer.step(message(sent(&actions)));
    (seller, buyer, actions)
}

fn locked() -> Locked {
    locked_with(terms())
}

fn locked_with(terms: Terms) -> Locked {
    let (seller, buyer, actions) = hellos_with(terms);
    let funding = funding(&actions);
    let (buyer, actions) = buyer.step(Event::Funded(funding.clone()));
    let Message::LockProposal {
        funding: unsigned, ..
    } = sent(&actions)
    else {
        panic!("a lock proposal");
    };
    assert!(
        unsigned.input[0].witness.is_empty(),
        "sent without witnesses"
    );
    let (seller, actions) = seller.step(message(sent(&actions)));
    let (buyer, actions) = buyer.step(message(sent(&actions)));
    // The buyer sends its cancel signature, then broadcasts.
    let signatures = sent(&actions);
    assert!(broadcasts(&actions).is_empty(), "not before they are sent");
    let (buyer, broadcast) = buyer.step(Event::Sent);
    assert_eq!(broadcasts(&broadcast), [funding]);
    let (seller, none) = seller.step(message(signatures));
    assert!(none.is_empty());
    assert!(matches!(seller, Seller::AwaitFunding { .. }));
    Locked { seller, buyer }
}

impl Locked {
    fn swap(&self) -> (Swap, OutPoint) {
        self.buyer.watch().bitcoin.unwrap()
    }

    fn lock_address(&self) -> String {
        let cid = Message::NexLocked { cid: "bafy".into() };
        let (buyer, _) = self.buyer.clone().step(message(cid));
        buyer.watch().nexus.unwrap().lock_address
    }

    /// The seller signs and submits its NEX lock; it is not mined yet.
    fn nex_signed(self) -> (Seller, Buyer, swap_nexus_tx::Transaction) {
        let (seller, actions) = self.seller.step(btc(2, None, None));
        assert!(actions.is_empty());
        let (seller, actions) = seller.step(nexus(account(0, 0), None));
        let (seller, actions) = seller.step(signed_nex(&actions));
        (seller, self.buyer, submitted(&actions))
    }

    /// The seller's NEX lock is mined and the buyer has its CID.
    fn nex_locked(self) -> (Seller, Buyer, swap_nexus_tx::Transaction) {
        let (seller, buyer, lock) = self.nex_signed();
        let (seller, actions) =
            seller.step(nexus(account(500_000, 0), mined(lock.body.clone(), 1)));
        let cid = sent(&actions);
        assert!(matches!(&cid, Message::NexLocked { cid } if *cid == lock.cid()));
        let (buyer, _) = buyer.step(message(cid));
        (seller, buyer, lock)
    }
}

#[test]
fn a_swap_completes() {
    let locked = locked();
    let (swap, lock) = locked.swap();
    let lock_address = locked.lock_address();
    let (seller, buyer, nex_lock) = locked.nex_locked();
    assert_eq!(
        nex_lock.body,
        TransactionBody::transfer(&SELLER_NEX.nex_address(), &lock_address, 500_000, 100, 3)
            .unwrap(),
        "nex_amount to the lock, at the seller's next nonce"
    );
    assert!(nex_lock.verify());

    // The buyer checks the lock on its node and sends its redeem signature.
    let (buyer, actions) = buyer.step(nexus(account(500_000, 0), mined(nex_lock.body.clone(), 1)));
    let (seller, none) = seller.step(btc(2, None, None));
    assert!(none.is_empty());
    let (seller, none) = seller.step(message(sent(&actions)));
    assert!(none.is_empty(), "the redeem waits for a fresh view");
    let (seller, actions) = seller.step(btc(2, None, None));
    let [redeem] = &broadcasts(&actions)[..] else {
        panic!("the seller redeems");
    };
    assert_eq!(
        redeem.compute_txid(),
        swap.unsigned_tx(lock, Spend::Redeem).compute_txid()
    );

    // The redeem, still in the mempool, gives the buyer `s`.
    let (buyer, none) = buyer.step(btc(3, Some((redeem, 0)), None));
    assert!(none.is_empty());
    let (buyer, actions) = buyer.step(nexus(account(500_000, 0), None));
    let claim = submitted(&actions);
    assert_eq!(
        claim.body,
        TransactionBody::transfer(&lock_address, BUYER_NEX, 499_900, 100, 0).unwrap()
    );
    assert!(claim.verify(), "signed with the joint key");
    let (buyer, _) = buyer.step(nexus(account(0, 1), mined(claim.body.clone(), 1)));
    assert_eq!(buyer.outcome(), Some(Outcome::Swapped));

    let (seller, _) = seller.step(btc(4, Some((redeem, 1)), None));
    assert_eq!(seller.outcome(), Some(Outcome::Swapped));
}

#[test]
fn the_seller_stops_redeeming_at_the_margin() {
    let (seller, buyer, nex_lock) = locked().nex_locked();
    let (_, actions) = buyer.step(nexus(account(500_000, 0), mined(nex_lock.body, 1)));
    let redeem = sent(&actions);

    // t1 = 20, margin = 3: the lock 17 deep (tip = lock height + 16) is the
    // last chance.
    let (open, _) = seller.clone().step(btc(17, None, None));
    let (open, _) = open.step(message(redeem.clone()));
    let (_, actions) = open.step(btc(17, None, None));
    assert_eq!(broadcasts(&actions).len(), 1);

    let (closed, actions) = seller.step(btc(18, None, None));
    assert!(matches!(closed, Seller::Cancelling { .. }));
    assert!(actions.is_empty(), "cancel is not valid yet");
    let (closed, actions) = closed.step(message(redeem));
    assert!(actions.is_empty(), "no redeem once the window closed");
    let (closed, actions) = closed.step(btc(19, None, None));
    assert!(actions.is_empty(), "cancel is not valid one block early");
    let (_, actions) = closed.step(btc(20, None, None));
    assert_eq!(broadcasts(&actions).len(), 1, "cancel at t1");
}

#[test]
fn no_redeem_signature_cancels_refunds_and_reclaims_the_nex() {
    let locked = locked();
    let (swap, lock) = locked.swap();
    let lock_address = locked.lock_address();
    let (seller, buyer, _) = locked.nex_locked();
    assert!(matches!(seller, Seller::AwaitRedeemSignature { .. }));

    // Nobody signs; at t1 both broadcast the same cancel.
    let (seller, from_seller) = seller.step(btc(20, None, None));
    let (buyer, from_buyer) = buyer.step(btc(20, None, None));
    let [cancel] = &broadcasts(&from_seller)[..] else {
        panic!("the seller cancels");
    };
    let [same] = &broadcasts(&from_buyer)[..] else {
        panic!("the buyer cancels");
    };
    assert_eq!(same.compute_txid(), cancel.compute_txid());
    let (early, _) = locked_buyer_at_t1_minus_one();
    assert!(
        early.is_empty(),
        "the buyer does not cancel one block early"
    );

    // The buyer refunds only once cancel is in a block.
    let (buyer, actions) = buyer.step(btc(21, Some((cancel, 0)), None));
    assert!(actions.is_empty());
    let (buyer, actions) = buyer.step(btc(22, Some((cancel, 1)), None));
    let [refund] = &broadcasts(&actions)[..] else {
        panic!("the buyer refunds");
    };
    assert_eq!(
        refund.compute_txid(),
        swap.unsigned_tx(lock, Spend::Refund).compute_txid()
    );

    // The refund in the mempool gives the seller `b`; it claims its NEX back.
    let (seller, _) = seller.step(btc(22, Some((cancel, 1)), Some((refund, 0))));
    let (seller, actions) = seller.step(nexus(account(500_000, 0), None));
    let claim = submitted(&actions);
    let home = SELLER_NEX.nex_address();
    assert_eq!(
        claim.body,
        TransactionBody::transfer(&lock_address, &home, 499_900, 100, 0).unwrap()
    );
    assert!(claim.verify());
    let (seller, _) = seller.step(nexus(account(0, 1), mined(claim.body, 1)));
    assert_eq!(seller.outcome(), Some(Outcome::Refunded));

    let (buyer, _) = buyer.step(btc(23, Some((cancel, 2)), Some((refund, 1))));
    assert_eq!(buyer.outcome(), Some(Outcome::Refunded));
}

#[test]
fn a_silent_buyer_is_punished_after_t2() {
    let (seller, _, _) = locked().nex_locked();
    let (seller, actions) = seller.step(btc(20, None, None));
    let [cancel] = &broadcasts(&actions)[..] else {
        panic!("cancel");
    };
    let (seller, actions) = seller.step(btc(29, Some((cancel, 9)), None));
    assert!(actions.is_empty(), "punish needs t2 = 10");
    let (seller, actions) = seller.step(btc(30, Some((cancel, 10)), None));
    let [punish] = &broadcasts(&actions)[..] else {
        panic!("punish");
    };
    let (seller, _) = seller.step(btc(31, Some((cancel, 11)), Some((punish, 1))));
    assert_eq!(seller.outcome(), Some(Outcome::Punished));
}

#[test]
fn a_seller_that_never_signed_a_lock_ends_with_nothing_to_claim() {
    let locked = locked();
    let (seller, _) = locked.seller.step(btc(2, None, None));
    // Its node never shows itself synced: no nonce, so no lock.
    let (seller, actions) = seller.step(nexus_at(syncing(), account(0, 0), account(0, 0), None));
    assert!(actions.is_empty());
    let (seller, _) = seller.step(btc(18, None, None));
    let (cancel, refund) = cancel_and_refund(locked.buyer);
    let (seller, _) = seller.step(btc(21, Some((&cancel, 1)), Some((&refund, 0))));
    let (seller, actions) = seller.step(nexus(account(0, 0), None));
    assert!(actions.is_empty());
    assert_eq!(seller.outcome(), Some(Outcome::Refunded));
}

/// The buyer, never having signed the redeem, cancels at t1 and refunds.
fn cancel_and_refund(buyer: Buyer) -> (Transaction, Transaction) {
    let (buyer, actions) = buyer.step(btc(20, None, None));
    let [cancel] = &broadcasts(&actions)[..] else {
        panic!("cancel");
    };
    let (_, actions) = buyer.step(btc(21, Some((cancel, 1)), None));
    let [refund] = &broadcasts(&actions)[..] else {
        panic!("refund");
    };
    (cancel.clone(), refund.clone())
}

/// What a buyer with the NEX lock's CID does the block before cancel.
fn locked_buyer_at_t1_minus_one() -> (Vec<Action>, Buyer) {
    let (_, buyer, _) = locked().nex_locked();
    let (buyer, actions) = buyer.step(btc(19, None, None));
    (actions, buyer)
}

#[test]
fn state_survives_a_restart() {
    let (seller, buyer, nex_lock) = locked().nex_locked();
    let (buyer, actions) = buyer.step(nexus(account(500_000, 0), mined(nex_lock.body, 1)));
    let restored = restart(&buyer);
    let (seller, _) = seller.step(btc(2, None, None));
    let seller = restart(&seller);
    let (seller, _) = seller.step(message(sent(&actions)));
    let seller = restart(&seller);
    assert!(matches!(seller, Seller::Redeeming { .. }));
    let (_, actions) = seller.step(btc(3, None, None));
    let redeem = &broadcasts(&actions)[0];
    let (buyer, _) = restored.step(btc(3, Some((redeem, 1)), None));
    let (_, actions) = buyer.step(nexus(account(500_000, 0), None));
    assert!(submitted(&actions).verify(), "the restored buyer claims");
}

#[test]
fn messages_carry_the_swap_id() {
    let m = Message::NexLocked { cid: "bafy".into() };
    let bytes = m.encode([1; 32]);
    assert!(Message::decode(&bytes, [1; 32]).is_some());
    assert!(Message::decode(&bytes, [2; 32]).is_none());
}

// A counterparty that cheats.

#[test]
fn a_bad_share_proof_aborts() {
    let seller = new_seller(terms());
    let (_, actions) = Buyer::start(terms(), payout(3), BUYER_NEX.into()).unwrap();
    let Message::BuyerHello {
        key,
        share,
        refund_payout,
    } = sent(&actions)
    else {
        panic!("a hello");
    };
    // The proof with another share's secp256k1 point.
    let other = ShareProof::new(&KeyShare::random());
    let mut forged = serde_json::to_value(&share).unwrap();
    forged["secp256k1"] = serde_json::to_value(&other).unwrap()["secp256k1"].clone();
    let hello = Message::BuyerHello {
        key,
        share: serde_json::from_value(forged).unwrap(),
        refund_payout,
    };
    let (seller, actions) = seller.step(message(hello));
    assert_eq!(
        seller.outcome(),
        Some(Outcome::Aborted(Refusal::ShareProof))
    );
    assert!(actions.is_empty());
}

#[test]
fn a_mirrored_share_aborts() {
    let (buyer, actions) = Buyer::start(terms(), payout(3), BUYER_NEX.into()).unwrap();
    let Message::BuyerHello { key, share, .. } = sent(&actions) else {
        panic!("a hello");
    };
    let mirrored = Message::SellerHello {
        key,
        share,
        redeem_payout: payout(1),
        punish_payout: payout(2),
    };
    let (buyer, actions) = buyer.step(message(mirrored));
    assert_eq!(
        buyer.outcome(),
        Some(Outcome::Aborted(Refusal::MirroredShare))
    );
    assert!(actions.is_empty(), "nothing funded");
}

#[test]
fn a_wrong_redeem_adaptor_signature_is_not_redeemed() {
    let (seller, buyer, nex_lock) = locked().nex_locked();
    let (_, actions) = buyer.step(nexus(account(500_000, 0), mined(nex_lock.body, 1)));
    let Message::RedeemSignature { mut redeem } = sent(&actions) else {
        panic!("a redeem signature");
    };
    redeem.s_hat = schnorr_fun::fun::s!(redeem.s_hat + 1).public();
    let (seller, _) = seller.step(btc(2, None, None));
    let (seller, actions) = seller.step(message(Message::RedeemSignature { redeem }));
    assert!(actions.is_empty());
    assert!(matches!(seller, Seller::AwaitRedeemSignature { .. }));
}

#[test]
fn a_wrong_refund_adaptor_signature_aborts_before_funding() {
    let (seller, buyer, actions) = hellos();
    let (buyer, actions) = buyer.step(Event::Funded(funding(&actions)));
    let (_, actions) = seller.step(message(sent(&actions)));
    let Message::SellerSignatures { cancel, mut refund } = sent(&actions) else {
        panic!("signatures");
    };
    refund.s_hat = schnorr_fun::fun::s!(refund.s_hat + 1).public();
    let (buyer, actions) = buyer.step(message(Message::SellerSignatures { cancel, refund }));
    assert_eq!(buyer.outcome(), Some(Outcome::Aborted(Refusal::Signature)));
    assert!(actions.is_empty(), "the funding stays unbroadcast");
}

/// The seller's answer to the buyer's lock proposal with `edit` applied.
fn proposal_answer(edit: impl FnOnce(&mut Transaction)) -> Seller {
    let (seller, buyer, actions) = hellos();
    let (_, actions) = buyer.step(Event::Funded(funding(&actions)));
    let Message::LockProposal { mut funding, .. } = sent(&actions) else {
        panic!("a proposal");
    };
    edit(&mut funding);
    let lock = OutPoint::new(funding.compute_txid(), 1);
    seller
        .step(message(Message::LockProposal { funding, lock }))
        .0
}

#[test]
fn a_funding_transaction_that_pays_wrong_is_refused() {
    let funding = Some(Outcome::Aborted(Refusal::Funding));
    assert!(matches!(
        proposal_answer(|_| {}),
        Seller::AwaitBuyerSignatures { .. }
    ));
    let short = proposal_answer(|tx| tx.output[1].value -= Amount::from_sat(1));
    assert_eq!(short.outcome(), funding);
    let doubled = proposal_answer(|tx| tx.output[0] = tx.output[1].clone());
    assert_eq!(doubled.outcome(), funding, "two outputs pay the lock");
    let legacy = proposal_answer(|tx| tx.input[0].script_sig = ScriptBuf::from_bytes(vec![0x51]));
    assert_eq!(legacy.outcome(), funding, "an input with a scriptSig");
}

#[test]
fn the_buyer_refuses_its_own_non_segwit_funding() {
    let (_, buyer, actions) = hellos();
    let mut funding = funding(&actions);
    funding.input[0].witness.clear();
    let (buyer, actions) = buyer.step(Event::Funded(funding));
    assert_eq!(buyer.outcome(), Some(Outcome::Aborted(Refusal::Funding)));
    assert!(actions.is_empty());
}

#[test]
fn the_buyer_signs_only_for_a_real_nex_lock() {
    let locked = locked();
    let lock_address = locked.lock_address();
    let (_, buyer, nex_lock) = locked.nex_locked();
    let holds = |lock: Account, watched, health: Health| {
        let event = nexus_at(health, account(0, 0), lock, watched);
        let (_, actions) = buyer.clone().step(event);
        !sends(&actions).is_empty()
    };
    let good = || mined(nex_lock.body.clone(), 1);
    assert!(holds(account(500_000, 0), good(), healthy()));

    // A CID naming an unrelated confirmed transaction.
    let home = SELLER_NEX.nex_address();
    let unrelated = TransactionBody::transfer(&home, "someone-else", 500_000, 100, 9).unwrap();
    assert!(!holds(account(500_000, 0), mined(unrelated, 6), healthy()));
    // Credits split over several actions count together.
    let mut split = TransactionBody::transfer(&home, &lock_address, 250_000, 100, 3).unwrap();
    split.account_actions.push(split.account_actions[1].clone());
    split.account_actions[0].delta = -500_100;
    assert!(holds(
        account(500_000, 0),
        mined(split.clone(), 1),
        healthy()
    ));
    split.account_actions[2].delta -= 1;
    assert!(!holds(account(500_000, 0), mined(split, 1), healthy()));
    // A lock that has already signed something.
    assert!(!holds(account(500_000, 1), good(), healthy()));
    // Too shallow, too small, another chain, or a node still syncing.
    let shallow = mined(nex_lock.body.clone(), 1).map(|(tx, _)| (tx, None));
    assert!(!holds(account(500_000, 0), shallow, healthy()));
    assert!(!holds(account(499_999, 0), good(), healthy()));
    let mut child = nex_lock.body.clone();
    child.chain_path.push("Child".into());
    assert!(!holds(account(500_000, 0), mined(child, 1), healthy()));
    assert!(!holds(account(500_000, 0), good(), syncing()));
}

// The review's findings, each pinned.

/// The seller's node took its lock but the answer was lost, and the lock
/// was mined only after the buyer refunded. The seller keeps `s` and `b`
/// until the lock can no longer land, and claims it back when it does.
#[test]
fn a_lock_whose_answer_was_lost_is_still_claimed_back() {
    let locked = locked();
    let lock_address = locked.lock_address();
    let (seller, buyer, lock) = locked.nex_signed();
    assert_eq!(lock.body.nonce, 3, "the nonce the synced node showed");

    // Restarted, and on a node that has moved on: the same bytes again,
    // never a lock at a new nonce.
    let seller = restart(&seller);
    let moved_on = nexus_at(healthy(), account(9_000_000, 4), account(0, 0), None);
    let (seller, actions) = seller.step(moved_on);
    assert_eq!(submitted(&actions), lock);
    assert_eq!(seller.watch().nexus.unwrap().cid, Some(lock.cid()));

    let (seller, _) = seller.step(btc(18, None, None));
    assert!(matches!(seller, Seller::Cancelling { .. }));
    let (cancel, refund) = cancel_and_refund(buyer);
    let (seller, _) = seller.step(btc(21, Some((&cancel, 1)), Some((&refund, 0))));
    assert!(matches!(seller, Seller::ClaimingNex(_)));

    // An empty lock is not final while the lock can still land: the
    // seller's nonce has not passed it, or the node is not synced.
    let lagging = nexus_at(healthy(), account(0, 3), account(0, 0), None);
    let (seller, actions) = seller.step(lagging);
    assert!(actions.is_empty());
    assert_eq!(seller.outcome(), None, "the lock's nonce is unused");
    let syncing = nexus_at(syncing(), account(0, 4), account(0, 0), None);
    let (seller, actions) = seller.step(syncing);
    assert!(actions.is_empty());
    assert_eq!(seller.outcome(), None, "the node is still syncing");

    // Once the seller's nonce has passed it with nothing at the lock, for
    // `nex_confirmations` blocks, it never will.
    let passed = nexus_at(healthy(), account(0, 4), account(0, 0), None);
    let (done, _) = seller.clone().step(passed);
    assert_eq!(done.outcome(), None, "not yet a block deep");
    let deeper = nexus_at(synced_at(11), account(0, 4), account(0, 0), None);
    let (done, _) = done.step(deeper);
    assert_eq!(done.outcome(), Some(Outcome::Refunded));

    // The lock lands: the seller claims it back.
    let landed = nexus_at(healthy(), account(0, 4), account(500_000, 0), None);
    let (seller, actions) = seller.step(landed);
    let claim = submitted(&actions);
    let home = SELLER_NEX.nex_address();
    assert_eq!(
        claim.body,
        TransactionBody::transfer(&lock_address, &home, 499_900, 100, 0).unwrap()
    );
    let (seller, _) = seller.step(nexus(account(0, 1), mined(claim.body, 1)));
    assert_eq!(seller.outcome(), Some(Outcome::Refunded));
}

/// The node took the claim but the answer was lost: the claim is the one
/// transaction it signed, submitted again until it is mined.
#[test]
fn a_claim_whose_answer_was_lost_ends_swapped() {
    let (buyer, actions) = buyer_claiming().step(nexus(account(500_000, 0), None));
    let claim = submitted(&actions);
    assert_eq!(buyer.watch().nexus.unwrap().cid, Some(claim.cid()));
    // Dropped, or never answered: the same bytes again.
    let buyer = restart(&buyer);
    let (buyer, actions) = buyer.step(nexus(account(500_000, 0), None));
    assert_eq!(submitted(&actions), claim);
    // Pooled: nothing to do.
    let pooled = mined(claim.body.clone(), 1).map(|(tx, _)| (tx, None));
    let (buyer, actions) = buyer.step(nexus(account(500_000, 0), pooled));
    assert_eq!(submitted(&actions), claim);
    let (buyer, _) = buyer.step(nexus(account(0, 1), mined(claim.body, 1)));
    assert_eq!(buyer.outcome(), Some(Outcome::Swapped));
}

/// A redeem signature that arrives on a stale view is only kept: the
/// redeem goes out on the next view, and only if it shows the window open.
#[test]
fn a_redeem_signature_waits_for_a_fresh_view() {
    let (seller, buyer, nex_lock) = locked().nex_locked();
    let (_, actions) = buyer.step(nexus(account(500_000, 0), mined(nex_lock.body, 1)));
    // The seller's last view is 2 deep; the chain is really 18 deep.
    let (seller, _) = seller.step(btc(2, None, None));
    let (seller, actions) = seller.step(message(sent(&actions)));
    assert!(actions.is_empty(), "no redeem on the stale view");
    assert!(matches!(seller, Seller::Redeeming { .. }));

    let (open, actions) = seller.clone().step(btc(17, None, None));
    assert_eq!(broadcasts(&actions).len(), 1, "the window is open");
    // Not seen yet, and the window closed: not again.
    let (closed, actions) = open.step(btc(18, None, None));
    assert!(actions.is_empty());
    assert!(matches!(closed, Seller::Cancelling { .. }));
    let (closed, actions) = seller.step(btc(18, None, None));
    assert!(actions.is_empty(), "the window closed");
    assert!(matches!(closed, Seller::Cancelling { .. }));
}

#[test]
fn terms_leave_room_for_a_block_and_for_the_refund() {
    assert!(terms().check());
    let margin_one = Terms {
        margin: 1,
        ..terms()
    };
    assert!(!margin_one.check(), "a block can land before the redeem");
    // The buyer refunds on a cancel `btc_confirmations` deep, `margin`
    // blocks before punish.
    let tight = Terms {
        btc_confirmations: 7,
        t1: 30,
        ..terms()
    };
    assert!(!tight.check(), "7 + 3 = t2");
    assert!(Terms { t2: 11, ..tight }.check());
}

/// Once the seller holds its redeem signature, the buyer refunds only on
/// a cancel `btc_confirmations` deep.
#[test]
fn a_buyer_that_signed_the_redeem_refunds_on_a_deep_cancel() {
    let deep = Terms {
        btc_confirmations: 2,
        ..terms()
    };
    let (_, buyer, nex_lock) = locked_with(deep.clone()).nex_locked();
    let (signed, _) = buyer
        .clone()
        .step(nexus(account(500_000, 0), mined(nex_lock.body, 1)));
    assert!(matches!(signed, Buyer::AwaitRedeem { .. }));
    let (signed, actions) = signed.step(btc(20, None, None));
    let [cancel] = &broadcasts(&actions)[..] else {
        panic!("cancel");
    };
    let (signed, actions) = signed.step(btc(21, Some((cancel, 1)), None));
    assert!(actions.is_empty(), "one block of cancel is not enough");
    let (_, actions) = signed.step(btc(22, Some((cancel, 2)), None));
    assert_eq!(broadcasts(&actions).len(), 1, "the refund");

    // A buyer that never signed it has nothing a reorg could take.
    let (unsigned, _) = buyer.step(btc(20, None, None));
    let (_, actions) = unsigned.step(btc(21, Some((cancel, 1)), None));
    assert_eq!(broadcasts(&actions).len(), 1, "the refund");
}

#[test]
fn the_claim_pays_at_least_the_node_relay_fee() {
    let buyer = buyer_claiming();
    let lock_address = buyer.lock_address().unwrap();
    let event = Event::Nexus(NexusView {
        min_relay_fee: 250,
        ..nexus_view(nexus(account(500_000, 0), None))
    });
    let (_, actions) = buyer.step(event);
    assert_eq!(
        submitted(&actions).body,
        TransactionBody::transfer(&lock_address, BUYER_NEX, 499_750, 250, 0).unwrap()
    );
}

fn nexus_view(event: Event) -> NexusView {
    let Event::Nexus(view) = event else {
        panic!("a Nexus view");
    };
    view
}

/// The buyer, having seen the redeem, about to claim.
fn buyer_claiming() -> Buyer {
    let (seller, buyer, nex_lock) = locked().nex_locked();
    let (buyer, actions) = buyer.step(nexus(account(500_000, 0), mined(nex_lock.body, 1)));
    let (seller, _) = seller.step(message(sent(&actions)));
    let (_, actions) = seller.step(btc(2, None, None));
    let redeem = &broadcasts(&actions)[0];
    let (buyer, _) = buyer.step(btc(3, Some((redeem, 0)), None));
    assert!(matches!(buyer, Buyer::ClaimingNex(_)));
    buyer
}

/// A lock that has signed something the claimer did not: drained, with
/// nothing submitted.
#[test]
fn a_lock_spent_by_someone_else_is_drained() {
    let (buyer, actions) = buyer_claiming().step(nexus(account(500_000, 1), None));
    assert!(actions.is_empty());
    assert_eq!(buyer.outcome(), Some(Outcome::Drained));
}

#[test]
fn the_seller_waits_blocks_not_seconds_for_the_funding() {
    let seller = locked().seller;
    let view = |height, funding| {
        Event::Bitcoin(BitcoinView {
            height,
            funding,
            lock_spend: None,
            cancel_spend: None,
        })
    };
    let unseen = |height| view(height, None);
    let (seller, _) = seller.step(unseen(100));
    let (seller, _) = seller.step(Event::Timeout);
    assert!(matches!(seller, Seller::AwaitFunding { .. }), "no clock");
    assert!(!seller.awaits_message());
    let (seller, _) = seller.step(unseen(119));
    assert!(matches!(seller, Seller::AwaitFunding { .. }));
    let (stopped, actions) = seller.clone().step(unseen(120));
    assert!(actions.is_empty());
    assert_eq!(stopped.outcome(), Some(Outcome::Aborted(Refusal::Timeout)));
    // In the mempool, it is waited for.
    let (seller, _) = seller.step(view(130, Some(0)));
    assert!(matches!(seller, Seller::AwaitFunding { .. }));
}

#[test]
fn the_buyer_broadcasts_the_funding_only_once_its_signatures_are_out() {
    let (seller, buyer, actions) = hellos();
    let funding = funding(&actions);
    let (buyer, actions) = buyer.step(Event::Funded(funding.clone()));
    let (_, actions) = seller.step(message(sent(&actions)));
    let (buyer, actions) = buyer.step(message(sent(&actions)));
    assert!(matches!(sent(&actions), Message::BuyerSignatures { .. }));
    assert!(broadcasts(&actions).is_empty());
    // The session failed: nothing sent, so the buyer stops.
    let (stopped, actions) = buyer.clone().step(Event::Timeout);
    assert!(actions.is_empty());
    assert_eq!(stopped.outcome(), Some(Outcome::Aborted(Refusal::Timeout)));
    let (_, actions) = buyer.step(Event::Sent);
    assert_eq!(broadcasts(&actions), [funding]);
}

#[test]
fn the_seller_signs_its_lock_only_on_a_synced_node() {
    let (seller, _) = locked().seller.step(btc(2, None, None));
    assert!(matches!(seller, Seller::LockingNex { .. }));
    let stale = nexus_at(syncing(), account(10_000_000, 2), account(0, 0), None);
    let (seller, actions) = seller.step(stale);
    assert!(actions.is_empty());
    let inactive = Health {
        phase: "syncing".into(),
        ..healthy()
    };
    let (seller, actions) = seller.step(nexus_at(inactive, account(0, 2), account(0, 0), None));
    assert!(actions.is_empty());
    let (_, actions) = seller.step(nexus(account(0, 0), None));
    let Event::NexSigned(lock) = signed_nex(&actions) else {
        unreachable!();
    };
    assert_eq!(lock.body.nonce, 3);
}

/// The seller's Nexus wallet key is never in its state file.
#[test]
fn the_seller_state_never_holds_its_nexus_key() {
    let key = hex::encode(SELLER_NEX.0);
    let unsaved = |seller: &Seller| !serde_json::to_string(seller).unwrap().contains(&key);
    assert!(unsaved(&new_seller(terms())));
    assert!(unsaved(&hellos().0));
    let locked = locked();
    assert!(unsaved(&locked.seller));
    let (seller, _, _) = locked.nex_signed();
    assert!(unsaved(&seller));
}

/// A wallet that answers with another transaction than the lock is not
/// submitted.
#[test]
fn the_seller_submits_only_the_lock_it_asked_for() {
    let (seller, _) = locked().seller.step(btc(2, None, None));
    let (seller, actions) = seller.step(nexus(account(0, 0), None));
    let Event::NexSigned(lock) = signed_nex(&actions) else {
        unreachable!();
    };
    let mut other = lock.body.clone();
    other.account_actions[1].owner = "someone-else".into();
    let mut wrong = swap_nexus_tx::Transaction::new(other);
    wrong.sign(&SELLER_NEX.signing_key());
    let (seller, actions) = seller.step(Event::NexSigned(wrong));
    assert!(actions.is_empty());
    let unsigned = swap_nexus_tx::Transaction::new(lock.body.clone());
    let (seller, actions) = seller.step(Event::NexSigned(unsigned));
    assert!(actions.is_empty());
    let (_, actions) = seller.step(Event::NexSigned(lock.clone()));
    assert_eq!(submitted(&actions), lock);
}

#[test]
fn a_wrong_cancel_signature_aborts_before_funding() {
    let (seller, buyer, actions) = hellos();
    let (buyer, actions) = buyer.step(Event::Funded(funding(&actions)));
    let (_, actions) = seller.step(message(sent(&actions)));
    let Message::SellerSignatures { mut cancel, refund } = sent(&actions) else {
        panic!("signatures");
    };
    cancel.s = schnorr_fun::fun::s!(cancel.s + 1).public();
    let (buyer, actions) = buyer.step(message(Message::SellerSignatures { cancel, refund }));
    assert_eq!(buyer.outcome(), Some(Outcome::Aborted(Refusal::Signature)));
    assert!(actions.is_empty());
}

#[test]
fn a_funding_transaction_with_two_lock_outputs_is_refused() {
    let (seller, buyer, actions) = hellos();
    let (_, actions) = buyer.step(Event::Funded(funding(&actions)));
    let Message::LockProposal { mut funding, .. } = sent(&actions) else {
        panic!("a proposal");
    };
    // The first of two outputs paying the lock.
    funding.output[0] = funding.output[1].clone();
    let lock = OutPoint::new(funding.compute_txid(), 0);
    let (seller, _) = seller.step(message(Message::LockProposal { funding, lock }));
    assert_eq!(seller.outcome(), Some(Outcome::Aborted(Refusal::Funding)));
}

#[test]
fn a_swap_cannot_be_started_twice() {
    let start = |seller: Seller, directory: &std::path::Path| {
        let client = Client::new("http://127.0.0.1:9", "", Duration::from_secs(1));
        let store = Store::new(directory, terms().swap_id);
        Driver::<_, _, Offline>::start(seller, vec![], Offline, client, None, store).map(drop)
    };
    let directory = tempfile::tempdir().unwrap();
    let first = new_seller(terms());
    start(first.clone(), directory.path()).unwrap();
    let again = start(new_seller(terms()), directory.path()).unwrap_err();
    assert_eq!(again.kind(), std::io::ErrorKind::AlreadyExists);
    let saved: Seller = Store::new(directory.path(), terms().swap_id)
        .load()
        .unwrap()
        .unwrap();
    assert_eq!(
        serde_json::to_string(&saved).unwrap(),
        serde_json::to_string(&first).unwrap(),
        "the first swap's secrets are kept"
    );
}

// The re-review's findings, each pinned.

/// The claim debits exactly the `nex_amount` the lock credited: dust on
/// top, which a reorg may take back, stays behind.
#[test]
fn the_claim_takes_exactly_the_locked_amount() {
    let buyer = buyer_claiming();
    let lock_address = buyer.lock_address().unwrap();
    let (_, actions) = buyer.clone().step(nexus(account(500_007, 0), None));
    assert_eq!(
        submitted(&actions).body,
        TransactionBody::transfer(&lock_address, BUYER_NEX, 499_900, 100, 0).unwrap()
    );
    // Dust alone is not the lock.
    let (buyer, actions) = buyer.step(nexus(account(7, 0), None));
    assert!(actions.is_empty());
    assert_eq!(buyer.outcome(), None);
}

/// A lock that never landed is empty whatever dust anyone sends the
/// address: dust must not keep the seller waiting forever.
#[test]
fn dust_does_not_keep_an_empty_lock_open() {
    let locked = locked();
    let (seller, _) = locked.seller.step(btc(18, None, None));
    let (cancel, refund) = cancel_and_refund(locked.buyer);
    let (seller, _) = seller.step(btc(21, Some((&cancel, 1)), Some((&refund, 0))));
    assert!(matches!(seller, Seller::ClaimingNex(_)));
    // More than any fee, less than the lock.
    let (seller, actions) = seller.step(nexus(account(499_999, 0), None));
    assert!(actions.is_empty());
    assert_eq!(seller.outcome(), Some(Outcome::Refunded));
}

/// A lock holding `nex_amount`, while the node's relay fee would take all
/// of it, is neither claimed nor empty: the seller submits nothing and keeps
/// waiting with its shares.
#[test]
fn a_lock_too_small_to_claim_is_not_empty() {
    let locked = locked();
    let (seller, _) = locked.seller.step(btc(18, None, None));
    let (cancel, refund) = cancel_and_refund(locked.buyer);
    let (seller, _) = seller.step(btc(21, Some((&cancel, 1)), Some((&refund, 0))));
    assert!(matches!(seller, Seller::ClaimingNex(_)));
    let costly = Event::Nexus(NexusView {
        health: healthy(),
        own: account(10_000_000, 3),
        lock: account(500_000, 0),
        min_relay_fee: 500_000,
        watched: None,
        block_at: None,
    });
    let (seller, actions) = seller.step(costly);
    assert!(actions.is_empty());
    assert_eq!(seller.outcome(), None);
}

/// The buyer saw the lock confirmed: if it vanishes, a reorg took it, and
/// the buyer keeps its shares to claim it when it comes back.
#[test]
fn a_lock_the_buyer_saw_is_waited_for() {
    let buyer = buyer_claiming();
    let (buyer, actions) = buyer.step(nexus(account(0, 0), None));
    assert!(actions.is_empty());
    assert_eq!(buyer.outcome(), None, "the lock was reorged out");
    let (buyer, _) = buyer.step(nexus(account(0, 0), None));
    let (_, actions) = buyer.step(nexus(account(500_000, 0), None));
    assert!(submitted(&actions).verify(), "the lock is back: claimed");
}

/// The seller names its lock only once it is mined, never while it is
/// only pooled.
#[test]
fn the_seller_names_its_lock_only_once_mined() {
    let (seller, _, lock) = locked().nex_signed();
    let pooled = mined(lock.body.clone(), 1).map(|(tx, _)| (tx, None));
    let (seller, actions) = seller.step(nexus(account(500_000, 0), pooled));
    assert!(sends(&actions).is_empty());
    assert_eq!(submitted(&actions), lock);
    assert!(matches!(seller, Seller::LockingNex { .. }));
    let (_, actions) = seller.step(nexus(account(500_000, 0), mined(lock.body.clone(), 1)));
    assert!(matches!(sent(&actions), Message::NexLocked { .. }));
}

/// A funding the buyer's node never shows is broadcast again, and waited
/// for with the secrets kept, however long it takes.
#[test]
fn a_buyer_whose_funding_does_not_show_keeps_its_secrets() {
    // Its own node may have dropped a funding that others still hold and
    // can yet confirm: stopping would discard the keys its refund needs.
    let buyer = locked().buyer;
    assert!(matches!(buyer, Buyer::AwaitNexLock { .. }));
    let view = |height| {
        Event::Bitcoin(BitcoinView {
            height,
            funding: None,
            lock_spend: None,
            cancel_spend: None,
        })
    };
    let (buyer, actions) = buyer.step(view(100));
    assert_eq!(broadcasts(&actions).len(), 1, "broadcast again");
    let (buyer, actions) = buyer.step(view(10_000));
    assert!(matches!(buyer, Buyer::AwaitNexLock { .. }));
    assert_eq!(broadcasts(&actions).len(), 1, "still broadcasting");
    assert_eq!(buyer.outcome(), None);
}

/// A buyer whose cancel output the seller spent through the punish leaf with
/// a transaction of its own, not the agreed punish, is punished all the
/// same, and stops refunding once it sees that spend.
#[test]
fn a_punish_of_the_sellers_own_making_ends_punished() {
    let locked = locked();
    let (swap, lock) = locked.swap();
    let (_, buyer, _) = locked.nex_locked();
    let (buyer, actions) = buyer.step(btc(20, None, None));
    let [cancel] = &broadcasts(&actions)[..] else {
        panic!("cancel");
    };
    let mut punish = swap.unsigned_tx(lock, Spend::Punish);
    punish.output[0] = TxOut {
        value: Amount::from_sat(990_000),
        script_pubkey: payout(9),
    };
    // In the mempool, a refund may still replace it.
    let (buyer, actions) = buyer.step(btc(31, Some((cancel, 11)), Some((&punish, 0))));
    let [refund] = &broadcasts(&actions)[..] else {
        panic!("refund");
    };
    assert_eq!(
        refund.input[0].previous_output,
        punish.input[0].previous_output
    );
    assert_eq!(buyer.outcome(), None);
    let (buyer, actions) = buyer.step(btc(32, Some((cancel, 12)), Some((&punish, 1))));
    assert!(actions.is_empty(), "no refund once it is in a block");
    assert_eq!(buyer.outcome(), Some(Outcome::Punished));
}

/// The same from the seller's side: a punish of its own making ends it
/// punished, and while that punish is in the mempool it broadcasts nothing
/// that would conflict with it.
#[test]
fn the_seller_ends_on_a_punish_of_its_own_making() {
    let locked = locked();
    let (swap, lock) = locked.swap();
    let (seller, _, _) = locked.nex_locked();
    let (seller, actions) = seller.step(btc(20, None, None));
    let [cancel] = &broadcasts(&actions)[..] else {
        panic!("cancel");
    };
    let mut punish = swap.unsigned_tx(lock, Spend::Punish);
    punish.output[0].script_pubkey = payout(9);
    let (seller, actions) = seller.step(btc(31, Some((cancel, 11)), Some((&punish, 0))));
    assert!(actions.is_empty(), "no punish against its own");
    assert_eq!(seller.outcome(), None);
    let (seller, actions) = seller.step(btc(32, Some((cancel, 12)), Some((&punish, 1))));
    assert!(actions.is_empty());
    assert_eq!(seller.outcome(), Some(Outcome::Punished));
}

/// A seller that first sees the buyer's refund already deep still reads it
/// as a refund, recovers `b` and claims its NEX back.
#[test]
fn a_refund_first_seen_deep_is_still_a_refund() {
    let locked = locked();
    let (seller, buyer, _) = locked.nex_locked();
    let (seller, _) = seller.step(btc(18, None, None));
    let (cancel, refund) = cancel_and_refund(buyer);
    let (seller, actions) = seller.step(btc(40, Some((&cancel, 20)), Some((&refund, 10))));
    assert!(actions.is_empty());
    assert!(matches!(seller, Seller::ClaimingNex(_)));
}

/// The seller, having signed its lock at nonce 3 and learned `b`, waits
/// with the lock address empty.
fn seller_claiming_a_signed_lock(terms: Terms) -> Seller {
    let locked = locked_with(terms);
    let (seller, buyer, lock) = locked.nex_signed();
    assert_eq!(lock.body.nonce, 3);
    let (seller, _) = seller.step(btc(18, None, None));
    let (cancel, refund) = cancel_and_refund(buyer);
    let (seller, _) = seller.step(btc(21, Some((&cancel, 1)), Some((&refund, 0))));
    assert!(matches!(seller, Seller::ClaimingNex(_)));
    seller
}

/// A seller whose nonce passed its signed lock ends empty only once that
/// held over `nex_confirmations` blocks of the tip: a reorg shallower than
/// that could take back what moved the nonce and let the lock land.
#[test]
fn a_passed_nonce_must_hold_nex_confirmations_blocks() {
    let deep = Terms {
        nex_confirmations: 3,
        ..terms()
    };
    let seller = seller_claiming_a_signed_lock(deep);
    let at = |height, nonce| nexus_at(synced_at(height), account(0, nonce), account(0, 0), None);

    let (seller, _) = seller.step(at(10, 4));
    let seller = restart(&seller);
    assert_eq!(seller.watch().nexus.unwrap().block_at, Some(10));
    let (seller, _) = seller.step(at(12, 4));
    assert_eq!(seller.outcome(), None, "two blocks are not three");
    let (done, _) = seller.clone().step(at(13, 4));
    assert_eq!(done.outcome(), Some(Outcome::Refunded));

    // A reorg between two views replaced the block at 10: even with the
    // nonce still past, the count starts again.
    let reorged = Event::Nexus(NexusView {
        block_at: Some("bafyother".into()),
        ..nexus_view(at(13, 4))
    });
    let (moved, _) = seller.clone().step(reorged);
    assert_eq!(moved.outcome(), None);
    assert_eq!(moved.watch().nexus.unwrap().block_at, Some(13));
    let (moved, _) = moved.step(at(15, 4));
    assert_eq!(moved.outcome(), None, "counted from 13, not 10");
    let (moved, _) = moved.step(at(16, 4));
    assert_eq!(moved.outcome(), Some(Outcome::Refunded));

    // A reorg took back what moved the nonce: the count starts again.
    let (seller, _) = seller.step(at(12, 3));
    assert_eq!(seller.outcome(), None);
    let (seller, _) = seller.step(at(13, 4));
    let (seller, _) = seller.step(at(15, 4));
    assert_eq!(seller.outcome(), None, "counted from 13, not 10");
    let (done, _) = seller.clone().step(at(16, 4));
    assert_eq!(done.outcome(), Some(Outcome::Refunded));

    // So it does when the lock shows up, too costly to claim yet.
    let costly = Event::Nexus(NexusView {
        min_relay_fee: 500_000,
        ..nexus_view(nexus_at(
            synced_at(15),
            account(0, 4),
            account(500_000, 0),
            None,
        ))
    });
    let (seller, actions) = seller.step(costly);
    assert!(actions.is_empty());
    let (seller, _) = seller.step(at(16, 4));
    assert_eq!(seller.outcome(), None, "counted from 16, not 13");
    let (done, _) = seller.step(at(19, 4));
    assert_eq!(done.outcome(), Some(Outcome::Refunded));
}

// Fee bumping, against a made-up node.

/// A Bitcoin node the test moves by hand. The lock is mined at height 101,
/// as in [`btc`]; whatever is in `mempool` waits unconfirmed.
#[derive(Default)]
struct Node {
    height: u32,
    lock: Option<Txid>,
    mempool: Vec<Transaction>,
    /// Transactions in blocks, with the height of each block.
    mined: Vec<(Transaction, u32)>,
    estimate: Option<FeeRate>,
    /// The conservative estimate for a spend near its deadline, if not
    /// `estimate`.
    urgent: Option<FeeRate>,
    /// What [`Bitcoin::floor`] answers, in sat/vB.
    floor: u32,
    /// Refuse every broadcast, as a mempool holding a better conflict does.
    refuse: bool,
    /// How many of the next bumps fail.
    failing: u32,
    /// Each bump asked of the node, whether it failed or not: the parent,
    /// the height, the feerate and the most the child may pay.
    bumps: Vec<(Txid, u32, FeeRate, Amount)>,
}

#[derive(Clone, Default)]
struct Fake(Rc<RefCell<Node>>);

impl Bitcoin for Fake {
    fn broadcast(&self, tx: &Transaction) -> crate::bitcoind::Result<()> {
        let mut node = self.0.borrow_mut();
        if node.refuse {
            return Err(crate::bitcoind::Error("insufficient fee".into()));
        }
        node.mempool.push(tx.clone());
        Ok(())
    }
    fn height(&self) -> crate::bitcoind::Result<u32> {
        Ok(self.0.borrow().height)
    }
    fn transaction(&self, txid: Txid) -> crate::bitcoind::Result<Option<(Transaction, u32)>> {
        let node = self.0.borrow();
        if node.lock == Some(txid) {
            return Ok(Some((node.mempool[0].clone(), node.height - 100)));
        }
        if let Some((tx, at)) = node.mined.iter().find(|(tx, _)| tx.compute_txid() == txid) {
            return Ok(Some((tx.clone(), node.height + 1 - at)));
        }
        let pooled = node.mempool.iter().find(|tx| tx.compute_txid() == txid);
        Ok(pooled.map(|tx| (tx.clone(), 0)))
    }
    fn spender(&self, _: OutPoint, _: u32) -> crate::bitcoind::Result<Option<(Transaction, u32)>> {
        Ok(None)
    }
    fn fund_lock(&self, _: &Script, _: Amount) -> crate::bitcoind::Result<Transaction> {
        unreachable!()
    }
    fn fee_rate(&self, urgent: bool) -> crate::bitcoind::Result<Option<FeeRate>> {
        let node = self.0.borrow();
        Ok(node.urgent.filter(|_| urgent).or(node.estimate))
    }
    fn floor(&self, _: &Transaction) -> crate::bitcoind::Result<FeeRate> {
        Ok(FeeRate::from_sat_per_vb_u32(self.0.borrow().floor))
    }
    fn bump(
        &self,
        parent: &Transaction,
        _: Amount,
        rate: FeeRate,
        max: Amount,
    ) -> crate::bitcoind::Result<Txid> {
        let mut node = self.0.borrow_mut();
        let height = node.height;
        node.bumps.push((parent.compute_txid(), height, rate, max));
        if node.failing > 0 {
            node.failing -= 1;
            return Err(crate::bitcoind::Error("wallet locked".into()));
        }
        Ok(Txid::all_zeros())
    }
}

struct Offline;

impl Bitcoin for Offline {
    fn broadcast(&self, _: &Transaction) -> crate::bitcoind::Result<()> {
        unreachable!()
    }
    fn height(&self) -> crate::bitcoind::Result<u32> {
        unreachable!()
    }
    fn transaction(&self, _: Txid) -> crate::bitcoind::Result<Option<(Transaction, u32)>> {
        unreachable!()
    }
    fn spender(&self, _: OutPoint, _: u32) -> crate::bitcoind::Result<Option<(Transaction, u32)>> {
        unreachable!()
    }
    fn fund_lock(&self, _: &Script, _: Amount) -> crate::bitcoind::Result<Transaction> {
        unreachable!()
    }
    fn fee_rate(&self, _: bool) -> crate::bitcoind::Result<Option<FeeRate>> {
        unreachable!()
    }
    fn floor(&self, _: &Transaction) -> crate::bitcoind::Result<FeeRate> {
        unreachable!()
    }
    fn bump(
        &self,
        _: &Transaction,
        _: Amount,
        _: FeeRate,
        _: Amount,
    ) -> crate::bitcoind::Result<Txid> {
        unreachable!()
    }
}

impl Transport for Offline {
    fn send(&mut self, _: &[u8]) -> std::io::Result<()> {
        unreachable!()
    }
    fn recv(&mut self, _: Duration) -> std::io::Result<Option<Vec<u8>>> {
        unreachable!()
    }
}

/// Watches a locked swap, with `role`'s view of which spends are its own,
/// and broadcasts `broadcast`, if any, at every view.
#[derive(Clone, Serialize, Deserialize)]
struct Watching<R> {
    watcher: Buyer,
    role: R,
    broadcast: Option<Transaction>,
}

impl<R: Machine> Machine for Watching<R> {
    fn step(self, event: Event) -> (Self, Vec<Action>) {
        let actions = match (&event, &self.broadcast) {
            (Event::Bitcoin(_), Some(tx)) => vec![Action::Broadcast(tx.clone())],
            _ => vec![],
        };
        (self, actions)
    }
    fn outcome(&self) -> Option<Outcome> {
        None
    }
    fn awaits_message(&self) -> bool {
        false
    }
    fn watch(&self) -> Watch {
        let watch = self.watcher.watch();
        Watch {
            bitcoin: watch.bitcoin,
            nexus: None,
            margin: watch.margin,
        }
    }
    fn own_spends(&self) -> &'static [Spend] {
        self.role.own_spends()
    }
}

/// Runs `machine`'s driver for one poll at each of `heights`, and returns
/// the bumps it asked for.
fn bumps<M: Machine>(
    machine: M,
    node: &Fake,
    heights: &[u32],
    set: impl FnOnce(&mut Driver<M, Fake, Offline>),
) -> Vec<(Txid, u32, FeeRate, Amount)> {
    bumps_with(machine, node, set, |poll, node| match heights.get(poll) {
        Some(&height) => {
            node.height = height;
            true
        }
        None => false,
    })
}

/// Runs `machine`'s driver, changing the node with `each` before every poll
/// until it returns false, and returns the bumps it asked for.
fn bumps_with<M: Machine>(
    machine: M,
    node: &Fake,
    set: impl FnOnce(&mut Driver<M, Fake, Offline>),
    each: impl Fn(usize, &mut Node) -> bool,
) -> Vec<(Txid, u32, FeeRate, Amount)> {
    let directory = tempfile::tempdir().unwrap();
    let store = Store::new(directory.path(), terms().swap_id);
    let client = Client::new("http://127.0.0.1:9", "", Duration::from_secs(1));
    let mut driver = Driver::start(machine, vec![], node.clone(), client, None, store).unwrap();
    driver.poll = Duration::from_millis(1);
    set(&mut driver);
    let polls = std::cell::Cell::new(0);
    let stopped = driver.run_until(|_| {
        let more = each(polls.get(), &mut node.0.borrow_mut());
        polls.set(polls.get() + 1);
        !more
    });
    assert!(stopped.unwrap().is_none());
    node.0.borrow().bumps.clone()
}

/// A node whose mempool holds `spends` of a locked swap, and estimates
/// `estimate` sat/vB.
fn pooled(locked: &Locked, spends: &[Spend], estimate: u32) -> Fake {
    let (swap, lock) = locked.swap();
    let funding = Transaction {
        version: bitcoin::transaction::Version::TWO,
        lock_time: bitcoin::absolute::LockTime::ZERO,
        input: vec![],
        output: vec![],
    };
    let mut mempool = vec![funding];
    mempool.extend(spends.iter().map(|&spend| swap.unsigned_tx(lock, spend)));
    Fake(Rc::new(RefCell::new(Node {
        lock: Some(lock.txid),
        mempool,
        estimate: Some(FeeRate::from_sat_per_vb_u32(estimate)),
        ..Node::default()
    })))
}

fn txids(locked: &Locked, spends: &[Spend]) -> Vec<Txid> {
    let (swap, lock) = locked.swap();
    spends
        .iter()
        .map(|&spend| swap.unsigned_tx(lock, spend).compute_txid())
        .collect()
}

/// Each party bumps only what pays it: the seller its redeem and punish,
/// the buyer its refund, and neither ever bumps cancel.
#[test]
fn each_party_bumps_only_what_pays_it() {
    fn bumped<R: Machine>(locked: &Locked, role: R, spends: &[Spend]) -> Vec<Txid> {
        let node = pooled(locked, spends, 50);
        let watcher = locked.buyer.clone();
        let watching = Watching {
            watcher,
            role,
            broadcast: None,
        };
        let bumps = bumps(watching, &node, &[105], |_| {});
        bumps.into_iter().map(|(txid, ..)| txid).collect()
    }
    let locked = locked();
    let (seller, buyer) = (locked.seller.clone(), locked.buyer.clone());
    use Spend::*;
    assert_eq!(
        bumped(&locked, seller.clone(), &[Redeem, Refund]),
        txids(&locked, &[Redeem])
    );
    assert_eq!(
        bumped(&locked, buyer.clone(), &[Redeem, Refund]),
        txids(&locked, &[Refund])
    );
    assert_eq!(
        bumped(&locked, seller, &[Cancel, Punish]),
        txids(&locked, &[Punish])
    );
    assert_eq!(bumped(&locked, buyer, &[Cancel, Punish]), []);
}

/// The seller's driver watching `locked`, as the buyer's view, with
/// `broadcast` broadcast at every view.
fn seller_watching(locked: &Locked, broadcast: Option<Transaction>) -> Watching<Seller> {
    Watching {
        watcher: locked.buyer.clone(),
        role: locked.seller.clone(),
        broadcast,
    }
}

/// Bumped when first seen, then again only at a new block whose estimate
/// is above the last bump's, however often the driver polls.
#[test]
fn a_waiting_spend_is_rebumped_only_when_a_new_block_raises_its_target() {
    let locked = locked();
    let node = pooled(&locked, &[Spend::Redeem], 50);
    let polls = [
        (105, 50),
        (105, 60),
        (106, 50),
        (106, 60),
        (107, 60),
        (108, 70),
    ];
    let bumps = bumps_with(
        seller_watching(&locked, None),
        &node,
        |_| {},
        |poll, node| {
            let Some(&(height, estimate)) = polls.get(poll) else {
                return false;
            };
            node.height = height;
            node.estimate = Some(FeeRate::from_sat_per_vb_u32(estimate));
            true
        },
    );
    let bumps: Vec<_> = bumps
        .into_iter()
        .map(|(_, height, rate, _)| (height, rate.to_sat_per_vb_ceil()))
        .collect();
    assert_eq!(bumps, [(105, 50), (107, 60), (108, 70)]);
}

/// A spend the mempool refuses is raised to the node's floor, not only the
/// estimate, and at once whenever it is newly refused, as when the other
/// party's package displaced it, without waiting for a block.
#[test]
fn a_refused_spend_is_raised_to_the_floor_at_once() {
    let locked = locked();
    let (swap, lock) = locked.swap();
    let refund = swap.unsigned_tx(lock, Spend::Refund);
    let node = pooled(&locked, &[Spend::Cancel], 10);
    let watching = Watching {
        watcher: locked.buyer.clone(),
        role: locked.buyer.clone(),
        broadcast: Some(refund.clone()),
    };
    // (height, refused, floor)
    let polls = [
        (105, true, 30),
        (105, true, 30),
        (105, false, 30),
        (105, true, 45),
        (106, true, 45),
        (107, true, 50),
    ];
    let txid = refund.compute_txid();
    let bumps = bumps_with(
        watching,
        &node,
        |_| {},
        |poll, node| {
            let Some(&(height, refuse, floor)) = polls.get(poll) else {
                return false;
            };
            node.height = height;
            node.refuse = refuse;
            node.floor = floor;
            // Refused: displaced from the mempool.
            node.mempool
                .retain(|tx| !refuse || tx.compute_txid() != txid);
            true
        },
    );
    let bumps: Vec<_> = bumps
        .into_iter()
        .map(|(bumped, height, rate, _)| (bumped, height, rate.to_sat_per_vb_ceil()))
        .collect();
    assert_eq!(bumps, [(txid, 105, 30), (txid, 105, 45), (txid, 107, 50)]);
}

/// A bump pays at most `max_fee_rate`, and nothing when the estimate is
/// not above what the spend already pays; its child pays at most
/// `max_fee_fraction` of the payout, all of it by default.
#[test]
fn a_bump_pays_the_estimate_up_to_the_caps() {
    let locked = locked();
    let (swap, lock) = locked.swap();
    let payout = swap.unsigned_tx(lock, Spend::Redeem).output[0].value;
    let bumped = |estimate, set: &dyn Fn(&mut Driver<_, Fake, Offline>)| {
        let node = pooled(&locked, &[Spend::Redeem], estimate);
        let bumps = bumps(seller_watching(&locked, None), &node, &[105], set);
        bumps
            .into_iter()
            .map(|(.., rate, max)| (rate.to_sat_per_vb_ceil(), max))
            .collect::<Vec<_>>()
    };
    assert_eq!(bumped(50, &|_| {}), [(50, payout)]);
    assert_eq!(bumped(5_000, &|_| {}), [(1_000, payout)], "the default cap");
    let rate = |driver: &mut Driver<_, Fake, Offline>| {
        driver.max_fee_rate = FeeRate::from_sat_per_vb_u32(30);
    };
    assert_eq!(bumped(50, &rate), [(30, payout)]);
    let quarter = |driver: &mut Driver<_, Fake, Offline>| driver.max_fee_fraction = 0.25;
    assert_eq!(bumped(50, &quarter), [(50, payout / 4)]);
    // The redeem alone pays more than 1 sat/vB.
    assert_eq!(bumped(1, &|_| {}), []);
}

/// A redeem sent at the last block the window is open is bumped at once,
/// long before cancel is valid.
#[test]
fn a_redeem_sent_at_the_last_open_block_is_bumped_before_t1() {
    let (seller, buyer, nex_lock) = locked().nex_locked();
    let (_, actions) = buyer.step(nexus(account(500_000, 0), mined(nex_lock.body, 1)));
    // t1 = 20, margin = 3: the lock 17 deep is the last chance.
    let (seller, _) = seller.step(btc(17, None, None));
    let (seller, _) = seller.step(message(sent(&actions)));
    let (swap, lock) = seller.watch().bitcoin.unwrap();
    let redeem = swap.unsigned_tx(lock, Spend::Redeem).compute_txid();
    let funding = Transaction {
        version: bitcoin::transaction::Version::TWO,
        lock_time: bitcoin::absolute::LockTime::ZERO,
        input: vec![],
        output: vec![],
    };
    let node = Fake(Rc::new(RefCell::new(Node {
        lock: Some(lock.txid),
        mempool: vec![funding],
        estimate: Some(FeeRate::from_sat_per_vb_u32(50)),
        ..Node::default()
    })));
    // A block every poll, until the lock is t1 deep.
    let bumps = bumps(seller, &node, &[117, 118, 119], |_| {});
    assert_eq!(node.0.borrow().mempool[1].compute_txid(), redeem);
    assert_eq!(
        bumps.first().map(|&(txid, height, ..)| (txid, height)),
        Some((redeem, 117))
    );
}

/// A state file of another format is refused, not misread.
#[test]
fn a_state_file_of_another_version_is_refused() {
    let directory = tempfile::tempdir().unwrap();
    let store = Store::new(directory.path(), terms().swap_id);
    let client = Client::new("http://127.0.0.1:9", "", Duration::from_secs(1));
    let seller = new_seller(terms());
    Driver::<_, _, Offline>::start(seller, vec![], Offline, client, None, store).unwrap();
    let store = Store::new(directory.path(), terms().swap_id);
    assert!(store.load::<Seller>().unwrap().is_some());

    let saved: serde_json::Value =
        serde_json::from_slice(&std::fs::read(store.path()).unwrap()).unwrap();
    // The state alone, as a caller reads it to tell the side.
    let state = store.load_value().unwrap().unwrap();
    assert_eq!(state, saved["state"]);
    assert!(state.get("AwaitBuyerHello").is_some(), "{state}");
    for other in [json!(crate::driver::STATE_VERSION + 1), json!(null)] {
        let mut file = saved.clone();
        file["version"] = other;
        std::fs::write(store.path(), serde_json::to_vec(&file).unwrap()).unwrap();
        let refused = store.load::<Seller>().err().expect("refused");
        assert_eq!(refused.kind(), std::io::ErrorKind::InvalidData);
        assert!(refused
            .to_string()
            .contains("finish the swap with the build that started it"));
        let refused = store.load_value().expect_err("refused");
        assert_eq!(refused.kind(), std::io::ErrorKind::InvalidData);
    }
    // A file from before versions: the state itself, at the top.
    std::fs::write(store.path(), serde_json::to_vec(&saved["state"]).unwrap()).unwrap();
    assert!(store.load::<Seller>().is_err());
    assert!(store.load_value().is_err());
}

/// A bump that fails records nothing: the spend stays due and is bumped
/// again at the next poll, without waiting for a block.
#[test]
fn a_failed_bump_is_tried_again_at_the_next_poll() {
    let locked = locked();
    let node = pooled(&locked, &[Spend::Redeem], 50);
    node.0.borrow_mut().failing = 1;
    let bumps = bumps(
        seller_watching(&locked, None),
        &node,
        &[105, 105, 105],
        |_| {},
    );
    let bumps: Vec<_> = bumps
        .into_iter()
        .map(|(_, height, rate, _)| (height, rate.to_sat_per_vb_ceil()))
        .collect();
    assert_eq!(bumps, [(105, 50), (105, 50)]);
}

/// Within `margin` blocks of its deadline a spend is bumped to the
/// conservative estimate: redeem as the lock nears `t1`, refund as cancel
/// nears `t2`.
#[test]
fn the_target_rises_near_the_deadline() {
    let locked = locked();
    let (swap, lock) = locked.swap();
    let urgent = |node: &Fake| {
        let mut node = node.0.borrow_mut();
        node.urgent = Some(FeeRate::from_sat_per_vb_u32(80));
    };
    let rates = |bumps: Vec<(Txid, u32, FeeRate, Amount)>| -> Vec<(u32, u64)> {
        bumps
            .into_iter()
            .map(|(_, height, rate, _)| (height, rate.to_sat_per_vb_ceil()))
            .collect()
    };

    // t1 = 20, margin = 3: the lock 17 deep, at 117, is 3 blocks short.
    let node = pooled(&locked, &[Spend::Redeem], 50);
    urgent(&node);
    let got = bumps(
        seller_watching(&locked, None),
        &node,
        &[115, 116, 117],
        |_| {},
    );
    assert_eq!(rates(got), [(115, 50), (117, 80)]);

    // t2 = 10: cancel, mined at 121, is 7 deep at 127.
    let node = pooled(&locked, &[Spend::Refund], 50);
    urgent(&node);
    let cancel = swap.unsigned_tx(lock, Spend::Cancel);
    node.0.borrow_mut().mined.push((cancel, 121));
    let watching = Watching {
        watcher: locked.buyer.clone(),
        role: locked.buyer.clone(),
        broadcast: None,
    };
    let got = bumps(watching, &node, &[125, 126, 127], |_| {});
    assert_eq!(rates(got), [(125, 50), (127, 80)]);
}

/// A refused spend needs a package, as against a conflict, even when the
/// target is below what it pays alone.
#[test]
fn a_refused_spend_is_bumped_below_its_own_feerate() {
    let locked = locked();
    let (swap, lock) = locked.swap();
    let refund = swap.unsigned_tx(lock, Spend::Refund);
    let own = swap.fee(Spend::Refund).to_sat() / refund.vsize() as u64;
    assert!(own > 2, "{own} sat/vB");
    let node = pooled(&locked, &[Spend::Cancel], 1);
    {
        let mut node = node.0.borrow_mut();
        node.refuse = true;
        node.floor = 2;
    }
    let watching = Watching {
        watcher: locked.buyer.clone(),
        role: locked.buyer.clone(),
        broadcast: Some(refund.clone()),
    };
    let bumps = bumps(watching, &node, &[105], |_| {});
    let bumps: Vec<_> = bumps
        .into_iter()
        .map(|(txid, _, rate, _)| (txid, rate.to_sat_per_vb_ceil()))
        .collect();
    assert_eq!(bumps, [(refund.compute_txid(), 2)]);
}

/// A child may pay a share of the payout from 0 to 1, nothing else.
#[test]
fn a_fee_fraction_outside_zero_to_one_is_refused() {
    for fraction in [f64::NAN, -0.1, 1.5] {
        let directory = tempfile::tempdir().unwrap();
        let store = Store::new(directory.path(), terms().swap_id);
        let client = Client::new("http://127.0.0.1:9", "", Duration::from_secs(1));
        let seller = new_seller(terms());
        let mut driver =
            Driver::<_, _, Offline>::start(seller, vec![], Offline, client, None, store).unwrap();
        driver.max_fee_fraction = fraction;
        let refused = driver.run_until(|_| true).expect_err("refused");
        assert_eq!(
            refused.kind(),
            std::io::ErrorKind::InvalidInput,
            "{fraction}"
        );
    }
}

/// The seller holding the redeem at the last open block, and the redeem.
fn seller_redeeming() -> (Seller, Transaction, Transaction) {
    let (seller, buyer, nex_lock) = locked().nex_locked();
    let (swap, lock) = seller.watch().bitcoin.unwrap();
    let (_, actions) = buyer.step(nexus(account(500_000, 0), mined(nex_lock.body, 1)));
    let (seller, _) = seller.step(btc(17, None, None));
    let (seller, _) = seller.step(message(sent(&actions)));
    let (seller, actions) = seller.step(btc(17, None, None));
    let [redeem] = &broadcasts(&actions)[..] else {
        panic!("the seller redeems");
    };
    (
        seller,
        redeem.clone(),
        swap.unsigned_tx(lock, Spend::Cancel),
    )
}

/// A redeem the seller once saw may have revealed `s`: when it vanishes
/// after the window closed, as on a reorg, it is sent again, even against
/// a cancel in the mempool, and the seller gives up on it only once a
/// cancel is in a block.
#[test]
fn a_redeem_once_seen_is_never_abandoned() {
    let (seller, redeem, cancel) = seller_redeeming();
    let (seller, none) = seller.step(btc(17, Some((&redeem, 0)), None));
    assert!(none.is_empty());
    let seller = restart(&seller);
    let (seller, actions) = seller.step(btc(19, None, None));
    assert_eq!(broadcasts(&actions), std::slice::from_ref(&redeem));
    assert!(matches!(seller, Seller::Redeeming { .. }));
    let (seller, actions) = seller.step(btc(20, Some((&cancel, 0)), None));
    assert_eq!(broadcasts(&actions), std::slice::from_ref(&redeem));
    assert!(matches!(seller, Seller::Redeeming { .. }));
    let (seller, _) = seller.step(btc(21, Some((&cancel, 1)), None));
    assert!(matches!(seller, Seller::Cancelling { .. }));
}

/// A redeem never seen may never have gone out: once the window closes,
/// the seller cancels instead.
#[test]
fn a_redeem_never_seen_is_abandoned_when_the_window_closes() {
    let (seller, _, _) = seller_redeeming();
    // As saved before `seen` existed: the field is missing, and false.
    let mut saved = serde_json::to_value(&seller).unwrap();
    let fields = saved["Redeeming"].as_object_mut().unwrap();
    assert_eq!(fields.remove("seen"), Some(json!(false)));
    let seller: Seller = serde_json::from_value(saved).unwrap();
    let (seller, actions) = seller.step(btc(19, None, None));
    assert!(broadcasts(&actions).is_empty());
    assert!(matches!(seller, Seller::Cancelling { .. }));
}
