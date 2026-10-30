//! Both machines against each other, with the chains made up: every path,
//! and a counterparty that cheats at each step.

use super::*;
use bitcoin::hashes::Hash;
use bitcoin::{TxIn, TxOut, Txid, WPubkeyHash, Witness};
use swap_nexus_tx::rpc::Inclusion;

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
        funding: Some(funding),
        lock_spend: spent(lock_spend),
        cancel_spend: spent(cancel_spend),
    })
}

fn healthy() -> Health {
    Health {
        phase: "active".into(),
        height: 10,
        best_header_height: Some(10),
    }
}

fn nexus(lock: Account, watched: Option<(TransactionStatus, Option<u64>)>) -> Event {
    Event::Nexus(NexusView {
        health: healthy(),
        own: Account {
            balance: 10_000_000,
            nonce: 3,
        },
        lock,
        watched,
    })
}

fn account(balance: u64, nonce: u64) -> Account {
    Account { balance, nonce }
}

fn mined(body: TransactionBody, depth: u64) -> Option<(TransactionStatus, Option<u64>)> {
    let status = TransactionStatus {
        body,
        block: Some(Inclusion {
            height: 10 + 1 - depth,
            hash: "bafyblock".into(),
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
    let seller = Seller::new(terms(), SELLER_NEX, payout(1), payout(2)).unwrap();
    let (buyer, actions) = Buyer::start(terms(), payout(3), BUYER_NEX.into()).unwrap();
    let (seller, actions) = seller.step(message(sent(&actions)));
    let (buyer, actions) = buyer.step(message(sent(&actions)));
    (seller, buyer, actions)
}

fn locked() -> Locked {
    let (seller, buyer, actions) = hellos();
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
    assert_eq!(broadcasts(&actions), [funding]);
    let (seller, none) = seller.step(message(sent(&actions)));
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

    /// The seller locks NEX and the buyer has the CID.
    fn nex_locked(self) -> (Seller, Buyer, swap_nexus_tx::Transaction) {
        let (seller, actions) = self.seller.step(btc(1, None, None));
        assert!(actions.is_empty());
        let (seller, actions) = seller.step(nexus(account(0, 0), None));
        let lock = submitted(&actions);
        let (seller, actions) = seller.step(Event::Submitted("bafylock".into()));
        let (buyer, _) = self.buyer.step(message(sent(&actions)));
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
    let (seller, actions) = seller.step(message(sent(&actions)));
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
    let (buyer, _) = buyer.step(Event::Submitted("bafyclaim".into()));
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
    let (_, actions) = open.step(message(redeem.clone()));
    assert_eq!(broadcasts(&actions).len(), 1);

    let (closed, actions) = seller.step(btc(18, None, None));
    assert!(matches!(closed, Seller::Cancelling { .. }));
    assert!(actions.is_empty(), "cancel is not valid yet");
    let (closed, actions) = closed.step(message(redeem));
    assert!(actions.is_empty(), "no redeem once the window closed");
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
    let (seller, _) = seller.step(Event::Submitted("bafyclaim".into()));
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
fn a_seller_that_never_locks_ends_with_nothing_to_claim() {
    let locked = locked();
    let (seller, _) = locked.seller.step(btc(1, None, None));
    // Its node refuses the lock: no CID, so nothing was locked.
    let (seller, actions) = seller.step(nexus(account(0, 0), None));
    submitted(&actions);
    let (seller, _) = seller.step(btc(18, None, None));
    let (buyer, actions) = locked.buyer.step(btc(20, None, None));
    let [cancel] = &broadcasts(&actions)[..] else {
        panic!("cancel");
    };
    let (_, actions) = buyer.step(btc(21, Some((cancel, 1)), None));
    let [refund] = &broadcasts(&actions)[..] else {
        panic!("refund");
    };
    let (seller, _) = seller.step(btc(21, Some((cancel, 1)), Some((refund, 0))));
    let (seller, actions) = seller.step(nexus(account(0, 0), None));
    assert!(actions.is_empty());
    assert_eq!(seller.outcome(), Some(Outcome::Refunded));
}

#[test]
fn state_survives_a_restart() {
    let (seller, buyer, nex_lock) = locked().nex_locked();
    let (buyer, actions) = buyer.step(nexus(account(500_000, 0), mined(nex_lock.body, 1)));
    let restored: Buyer = serde_json::from_str(&serde_json::to_string(&buyer).unwrap()).unwrap();
    let (seller, _) = seller.step(btc(2, None, None));
    let restored_seller: Seller =
        serde_json::from_str(&serde_json::to_string(&seller).unwrap()).unwrap();
    let (_, actions) = restored_seller.step(message(sent(&actions)));
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
    let seller = Seller::new(terms(), SELLER_NEX, payout(1), payout(2)).unwrap();
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
        let event = Event::Nexus(NexusView {
            health,
            own: account(0, 0),
            lock,
            watched,
        });
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
    let syncing = Health {
        best_header_height: Some(11),
        ..healthy()
    };
    assert!(!holds(account(500_000, 0), good(), syncing));
}
