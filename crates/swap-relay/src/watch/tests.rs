use std::collections::HashMap;

use bitcoin::{Amount, ScriptBuf, WScriptHash, Witness};
use swap_bitcoin::{EvenY, KeyPair, Params, Scalar, Spend, Swap};

use super::*;

fn key(n: u8) -> KeyPair<EvenY> {
    let mut bytes = [0u8; 32];
    bytes[31] = n;
    KeyPair::new_xonly(Scalar::from_bytes(bytes).unwrap().non_zero().unwrap())
}

fn swap() -> Swap {
    let payout = ScriptBuf::new_p2wsh(&WScriptHash::all_zeros());
    Swap::new(Params {
        seller: key(1).public_key(),
        buyer: key(2).public_key(),
        seller_share: key(3).public_key().normalize(),
        buyer_share: key(4).public_key().normalize(),
        amount: Amount::from_sat(1_000_000),
        fee: Amount::from_sat(1_000),
        t1: 15,
        t2: 6,
        redeem_payout: payout.clone(),
        refund_payout: payout.clone(),
        punish_payout: payout,
    })
    .unwrap()
}

fn lock() -> OutPoint {
    OutPoint::new(Txid::from_byte_array([7; 32]), 0)
}

/// `spend` of `swap`, signed by both parties, with fresh nonces.
fn signed_by_both(swap: &Swap, spend: Spend) -> Transaction {
    let seller = swap.sign(lock(), spend, &key(1));
    let buyer = swap.sign(lock(), spend, &key(2));
    swap.finalize(lock(), spend, &seller, Some(&buyer)).unwrap()
}

fn watch() -> Watch {
    let swap = swap();
    Watch {
        network: Network::Regtest,
        cancel: signed_by_both(&swap, Spend::Cancel),
        refund: signed_by_both(&swap, Spend::Refund),
        depth: 3,
    }
}

#[derive(Default)]
struct Fake {
    /// Where each transaction is: `None` in the mempool.
    seen: HashMap<Txid, Option<u32>>,
    spenders: HashMap<OutPoint, (Txid, Option<u32>)>,
    broadcasts: Mutex<Vec<Transaction>>,
    tip: u32,
}

impl Fake {
    /// A chain that has seen `watch`'s cancel: in a block at `height`, or
    /// with `None` in the mempool.
    fn with_cancel(watch: &Watch, height: Option<u32>) -> Self {
        let mut chain = Fake::default();
        chain.seen.insert(watch.cancel.compute_txid(), height);
        chain
    }
}

impl Chain for Fake {
    fn tip(&self) -> io::Result<u32> {
        Ok(self.tip)
    }
    fn transaction(&self, txid: Txid) -> io::Result<Option<Option<u32>>> {
        Ok(self.seen.get(&txid).copied())
    }
    fn spender(&self, outpoint: OutPoint) -> io::Result<Option<(Txid, Option<u32>)>> {
        Ok(self.spenders.get(&outpoint).copied())
    }
    fn broadcast(&self, tx: &Transaction) -> io::Result<()> {
        self.broadcasts.lock().unwrap().push(tx.clone());
        Ok(())
    }
}

#[test]
fn a_watch_must_chain_cancel_and_refund() {
    let network = Network::Regtest;
    assert_eq!(watch().check(network), Ok(()));
    let refused = |change: fn(&mut Watch)| {
        let mut watch = watch();
        change(&mut watch);
        watch.check(network).unwrap_err()
    };
    assert!(refused(|w| w.network = Network::Bitcoin).contains("watches regtest"));
    assert!(refused(|w| w.depth = 0).contains("depth"));
    assert!(refused(|w| w.cancel.input.clear()).contains("cancel must"));
    assert!(refused(|w| {
        let extra = w.cancel.input[0].clone();
        w.cancel.input.push(extra);
    })
    .contains("cancel must"));
    assert!(refused(|w| {
        let extra = w.refund.input[0].clone();
        w.refund.input.push(extra);
    })
    .contains("the refund must"));
    assert!(refused(|w| w.refund.input[0].previous_output = lock()).contains("does not spend"));
    assert!(refused(|w| w.refund.input[0].previous_output.vout = 1).contains("does not spend"));
}

fn item(tx: &Transaction, i: usize) -> Vec<u8> {
    tx.input[0].witness.nth(i).unwrap().to_vec()
}

/// `tx` with witness item `i` replaced by `with`.
fn rewitness(tx: &mut Transaction, i: usize, with: Vec<u8>) {
    let mut items: Vec<Vec<u8>> = tx.input[0].witness.iter().map(<[u8]>::to_vec).collect();
    items[i] = with;
    tx.input[0].witness = Witness::from_slice(&items);
}

/// Anyone who knows the swap knows the unsigned refund, whose txid is the
/// real one's: such a refund, or one signed wrong, is refused, so it cannot
/// stand in for the buyer's.
#[test]
fn only_a_refund_signed_by_both_keys_is_watched() {
    let swap = swap();
    let refused = |change: &dyn Fn(&mut Transaction)| {
        let mut watch = watch();
        change(&mut watch.refund);
        let refused = watch.check(Network::Regtest).unwrap_err();
        assert!(refused.contains("not signed"), "{refused}");
    };
    refused(&|tx| tx.input[0].witness = Witness::new());
    refused(&|tx| tx.input[0].witness = Witness::from_slice(&[item(tx, 0)]));
    for i in 0..2 {
        refused(&|tx| {
            let mut signature = item(tx, i);
            signature[10] ^= 1;
            rewitness(tx, i, signature);
        });
    }
    // Both signatures one key's.
    refused(&|tx| {
        let seller = item(tx, 1);
        rewitness(tx, 0, seller);
    });
    // Another spend's signatures, through the same leaf.
    let redeem = signed_by_both(&swap, Spend::Redeem);
    refused(&|tx| {
        rewitness(tx, 0, item(&redeem, 0));
        rewitness(tx, 1, item(&redeem, 1));
    });
    // A leaf of another shape, and a control block of another tree.
    let punish = swap.sign_punish_leaf(swap.unsigned_tx(lock(), Spend::Punish), &key(1));
    refused(&|tx| rewitness(tx, 2, item(&punish, 1)));
    let cancel = signed_by_both(&swap, Spend::Cancel);
    refused(&|tx| rewitness(tx, 3, item(&cancel, 3)));
}

/// A 2-of-2 leaf of the right shape, but not one the cancel output commits
/// to, is refused: its keys could be anyone's.
#[test]
fn a_refund_through_a_leaf_the_output_does_not_commit_to_is_refused() {
    let mut watch = watch();
    let mut leaf = item(&watch.refund, 2);
    leaf.swap(1, 35);
    rewitness(&mut watch.refund, 2, leaf);
    let refused = watch.check(Network::Regtest).unwrap_err();
    assert!(refused.contains("not signed"), "{refused}");
}

#[test]
fn a_planted_refund_is_refused_and_the_buyers_is_watched() {
    let dir = tempfile::tempdir().unwrap();
    let tower = Watchtower::open(Network::Regtest, dir.path(), 10).unwrap();
    let genuine = watch();
    let chain = Fake::with_cancel(&genuine, Some(100));
    // The seller plants the unsigned refund, of the same txid, first.
    let mut planted = genuine.clone();
    planted.refund.input[0].witness = Witness::new();
    assert_eq!(planted.refund.compute_txid(), genuine.refund.compute_txid());
    assert!(matches!(
        tower.add(planted, &chain),
        Err(Refusal::Invalid(_))
    ));
    let wtxid = tower.add(genuine.clone(), &chain).unwrap();
    assert_eq!(wtxid, genuine.refund.compute_wtxid());
    let chain = Fake {
        tip: 100,
        ..Fake::with_cancel(&genuine, Some(100))
    };
    tower.round(&chain);
    assert_eq!(*chain.broadcasts.lock().unwrap(), vec![genuine.refund]);
}

/// Two refunds of one swap, each validly signed, have one txid and two
/// wtxids: neither keeps the other out.
#[test]
fn two_valid_refunds_are_both_held() {
    let dir = tempfile::tempdir().unwrap();
    let tower = Watchtower::open(Network::Regtest, dir.path(), 10).unwrap();
    let first = watch();
    let mut second = first.clone();
    second.refund = signed_by_both(&swap(), Spend::Refund);
    assert_eq!(first.refund.compute_txid(), second.refund.compute_txid());
    assert_ne!(first.refund.compute_wtxid(), second.refund.compute_wtxid());
    let chain = Fake::with_cancel(&first, None);
    tower.add(second, &chain).unwrap();
    tower.add(first.clone(), &chain).unwrap();
    // The same one again is held once.
    tower.add(first, &chain).unwrap();
    assert_eq!(tower.len(), 2);
    assert_eq!(fs::read_dir(dir.path()).unwrap().count(), 2);
}

/// A watch costs a real cancel: one Esplora has not seen is refused, to be
/// asked again, as is one Esplora could not be asked about.
#[test]
fn a_watch_needs_its_cancel_seen() {
    struct Down;
    impl Chain for Down {
        fn tip(&self) -> io::Result<u32> {
            Err(io::Error::other("down"))
        }
        fn transaction(&self, _: Txid) -> io::Result<Option<Option<u32>>> {
            Err(io::Error::other("down"))
        }
        fn spender(&self, _: OutPoint) -> io::Result<Option<(Txid, Option<u32>)>> {
            Err(io::Error::other("down"))
        }
        fn broadcast(&self, _: &Transaction) -> io::Result<()> {
            Err(io::Error::other("down"))
        }
    }
    let dir = tempfile::tempdir().unwrap();
    let tower = Watchtower::open(Network::Regtest, dir.path(), 10).unwrap();
    let watch = watch();
    assert!(matches!(
        tower.add(watch.clone(), &Fake::default()),
        Err(Refusal::Unseen)
    ));
    assert!(matches!(
        tower.add(watch.clone(), &Down),
        Err(Refusal::Chain(_))
    ));
    assert!(tower.is_empty());
    // In the mempool is enough.
    let chain = Fake::with_cancel(&watch, None);
    tower.add(watch, &chain).unwrap();
    assert_eq!(tower.len(), 1);
}

#[test]
fn the_refund_goes_out_once_cancel_is_in_a_block_and_its_output_unspent_there() {
    let watch = watch();
    let refund = watch.refund.compute_txid();
    let output = watch.cancel_output();
    let at = |chain: &Fake, tip| step(&watch, tip, chain).unwrap();

    // No cancel yet, then cancel in the mempool.
    assert_eq!(at(&Fake::default(), 100), Step::Wait);
    assert_eq!(at(&Fake::with_cancel(&watch, None), 100), Step::Wait);
    // In a block: at once, however deep `depth` asks the spend to be.
    let mut chain = Fake::with_cancel(&watch, Some(100));
    assert_eq!(at(&chain, 100), Step::Broadcast);
    // Our refund pending: nothing to do.
    chain.spenders.insert(output, (refund, None));
    assert_eq!(at(&chain, 100), Step::Wait);
    // Anything else pending, such as a punish, the refund may replace.
    let punish = Txid::from_byte_array([9; 32]);
    chain.spenders.insert(output, (punish, None));
    assert_eq!(at(&chain, 100), Step::Broadcast);
    // In a block, until it is 3 deep.
    chain.spenders.insert(output, (refund, Some(103)));
    assert_eq!(at(&chain, 104), Step::Wait);
    assert_eq!(at(&chain, 105), Step::Done);
    // A punish deep enough ends the watch too: nothing more can be done.
    chain.spenders.insert(output, (punish, Some(103)));
    assert_eq!(at(&chain, 105), Step::Done);
}

/// Without the redeem signature nothing but cancel can spend the lock:
/// whatever Esplora says spends it, the watch waits for cancel.
#[test]
fn only_the_cancel_outputs_spend_ends_a_watch() {
    let watch = watch();
    let mut chain = Fake::default();
    let other = Txid::from_byte_array([8; 32]);
    chain.spenders.insert(lock(), (other, Some(100)));
    assert_eq!(step(&watch, 200, &chain).unwrap(), Step::Wait);
}

#[test]
fn watches_survive_a_restart_until_done() {
    let dir = tempfile::tempdir().unwrap();
    let network = Network::Regtest;
    let tower = Watchtower::open(network, dir.path(), 10).unwrap();
    let watch = watch();
    let mut chain = Fake {
        tip: 100,
        ..Fake::with_cancel(&watch, None)
    };
    let wtxid = tower.add(watch.clone(), &chain).unwrap();
    drop(tower);

    let tower = Watchtower::open(network, dir.path(), 10).unwrap();
    assert_eq!(tower.len(), 1);
    tower.round(&chain);
    assert!(
        chain.broadcasts.lock().unwrap().is_empty(),
        "in the mempool"
    );
    chain.seen.insert(watch.cancel.compute_txid(), Some(100));
    tower.round(&chain);
    assert_eq!(
        *chain.broadcasts.lock().unwrap(),
        vec![watch.refund.clone()]
    );

    let txid = watch.refund.compute_txid();
    chain
        .spenders
        .insert(watch.cancel_output(), (txid, Some(101)));
    chain.tip = 103;
    tower.round(&chain);
    assert!(tower.is_empty());
    assert!(!dir.path().join(format!("{wtxid}.json")).exists());
    assert_eq!(fs::read_dir(dir.path()).unwrap().count(), 0);
    let tower = Watchtower::open(network, dir.path(), 10).unwrap();
    assert!(tower.is_empty());
}

/// A watch read back is checked again, its network among the rest.
#[test]
fn a_watch_on_disk_for_another_network_is_refused() {
    let dir = tempfile::tempdir().unwrap();
    let tower = Watchtower::open(Network::Regtest, dir.path(), 10).unwrap();
    let watch = watch();
    let chain = Fake::with_cancel(&watch, None);
    tower.add(watch, &chain).unwrap();
    drop(tower);
    let refused = Watchtower::open(Network::Signet, dir.path(), 10)
        .err()
        .unwrap();
    assert!(refused.to_string().contains("watches signet"), "{refused}");
}

#[test]
fn the_watchtower_holds_at_most_max_and_only_valid_watches() {
    let dir = tempfile::tempdir().unwrap();
    let tower = Watchtower::open(Network::Regtest, dir.path(), 1).unwrap();
    let watch = watch();
    let chain = Fake::with_cancel(&watch, None);
    let mut other = watch.clone();
    other.refund = signed_by_both(&swap(), Spend::Refund);
    let mut invalid = watch.clone();
    invalid.depth = 0;
    assert!(matches!(
        tower.add(invalid, &chain),
        Err(Refusal::Invalid(_))
    ));
    tower.add(watch, &chain).unwrap();
    assert!(matches!(tower.add(other, &chain), Err(Refusal::Full)));
    assert_eq!(fs::read_dir(dir.path()).unwrap().count(), 1);
}
