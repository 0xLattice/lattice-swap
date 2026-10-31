use std::cell::RefCell;
use std::collections::HashMap;

use bitcoin::hashes::Hash;
use bitcoin::{absolute, transaction, Amount, ScriptBuf, Sequence, TxIn, TxOut, Witness};

use super::*;

fn spending(outpoint: OutPoint, value: u64) -> Transaction {
    Transaction {
        version: transaction::Version::TWO,
        lock_time: absolute::LockTime::ZERO,
        input: vec![TxIn {
            previous_output: outpoint,
            script_sig: ScriptBuf::new(),
            sequence: Sequence::MAX,
            witness: Witness::new(),
        }],
        output: vec![TxOut {
            value: Amount::from_sat(value),
            script_pubkey: ScriptBuf::new(),
        }],
    }
}

fn lock() -> OutPoint {
    OutPoint::new(Txid::from_byte_array([7; 32]), 0)
}

fn watch() -> Watch {
    let cancel = spending(lock(), 99_000);
    let refund = spending(OutPoint::new(cancel.compute_txid(), 0), 98_000);
    Watch {
        network: Network::Regtest,
        cancel,
        refund,
        depth: 3,
    }
}

#[derive(Default)]
struct Fake {
    confirmed: HashMap<Txid, u32>,
    spenders: HashMap<OutPoint, (Txid, Option<u32>)>,
    broadcasts: RefCell<Vec<Txid>>,
    tip: u32,
}

impl Chain for Fake {
    fn tip(&self) -> io::Result<u32> {
        Ok(self.tip)
    }
    fn confirmed(&self, txid: Txid) -> io::Result<Option<u32>> {
        Ok(self.confirmed.get(&txid).copied())
    }
    fn spender(&self, outpoint: OutPoint) -> io::Result<Option<(Txid, Option<u32>)>> {
        Ok(self.spenders.get(&outpoint).copied())
    }
    fn broadcast(&self, tx: &Transaction) -> io::Result<()> {
        self.broadcasts.borrow_mut().push(tx.compute_txid());
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

#[test]
fn the_refund_goes_out_once_cancel_is_deep_and_its_output_unspent_in_a_block() {
    let watch = watch();
    let cancel = watch.cancel.compute_txid();
    let refund = watch.refund.compute_txid();
    let output = OutPoint::new(cancel, 0);
    let mut chain = Fake::default();
    let at = |chain: &Fake, tip| step(&watch, tip, chain).unwrap();

    // No cancel yet.
    assert_eq!(at(&chain, 100), Step::Wait);
    // Cancel at 100 is 3 deep at 102, not at 101.
    chain.confirmed.insert(cancel, 100);
    chain.spenders.insert(lock(), (cancel, Some(100)));
    assert_eq!(at(&chain, 101), Step::Wait);
    assert_eq!(at(&chain, 102), Step::Broadcast);
    // Our refund pending: nothing to do.
    chain.spenders.insert(output, (refund, None));
    assert_eq!(at(&chain, 102), Step::Wait);
    // Anything else pending, such as a punish, the refund may replace.
    let punish = Txid::from_byte_array([9; 32]);
    chain.spenders.insert(output, (punish, None));
    assert_eq!(at(&chain, 102), Step::Broadcast);
    // In a block, until it is 3 deep.
    chain.spenders.insert(output, (refund, Some(103)));
    assert_eq!(at(&chain, 104), Step::Wait);
    assert_eq!(at(&chain, 105), Step::Done);
    // A punish deep enough ends the watch too: nothing more can be done.
    chain.spenders.insert(output, (punish, Some(103)));
    assert_eq!(at(&chain, 105), Step::Done);
}

#[test]
fn a_redeem_deep_enough_ends_the_watch() {
    let watch = watch();
    let mut chain = Fake::default();
    let redeem = Txid::from_byte_array([8; 32]);
    chain.spenders.insert(lock(), (redeem, None));
    assert_eq!(step(&watch, 100, &chain).unwrap(), Step::Wait);
    chain.spenders.insert(lock(), (redeem, Some(100)));
    assert_eq!(step(&watch, 101, &chain).unwrap(), Step::Wait);
    assert_eq!(step(&watch, 102, &chain).unwrap(), Step::Done);
    // The lock spent by cancel never ends the watch, even while cancel's
    // own status is not yet seen.
    let cancel = watch.cancel.compute_txid();
    chain.spenders.insert(lock(), (cancel, Some(100)));
    assert_eq!(step(&watch, 200, &chain).unwrap(), Step::Wait);
}

#[test]
fn watches_survive_a_restart_until_done() {
    let dir = tempfile::tempdir().unwrap();
    let network = Network::Regtest;
    let tower = Watchtower::open(network, dir.path(), 10).unwrap();
    let watch = watch();
    let txid = tower.add(watch.clone()).unwrap();
    assert_eq!(txid, watch.refund.compute_txid());
    // Taken twice, held once.
    tower.add(watch.clone()).unwrap();
    assert_eq!(tower.len(), 1);
    drop(tower);

    let tower = Watchtower::open(network, dir.path(), 10).unwrap();
    assert_eq!(tower.len(), 1);
    let cancel = watch.cancel.compute_txid();
    let mut chain = Fake {
        tip: 102,
        ..Fake::default()
    };
    chain.confirmed.insert(cancel, 100);
    tower.round(&chain);
    assert_eq!(*chain.broadcasts.borrow(), vec![txid]);

    let output = OutPoint::new(cancel, 0);
    chain.spenders.insert(output, (txid, Some(103)));
    chain.tip = 105;
    tower.round(&chain);
    assert!(tower.is_empty());
    assert_eq!(fs::read_dir(dir.path()).unwrap().count(), 0);
    let tower = Watchtower::open(network, dir.path(), 10).unwrap();
    assert!(tower.is_empty());
}

#[test]
fn the_watchtower_holds_at_most_max_and_only_valid_watches() {
    let dir = tempfile::tempdir().unwrap();
    let tower = Watchtower::open(Network::Regtest, dir.path(), 1).unwrap();
    let mut other = watch();
    other.refund.output[0].value = Amount::from_sat(1);
    let mut invalid = watch();
    invalid.depth = 0;
    assert!(matches!(tower.add(invalid), Err(Refusal::Invalid(_))));
    tower.add(watch()).unwrap();
    assert!(matches!(tower.add(other), Err(Refusal::Full)));
    assert_eq!(fs::read_dir(dir.path()).unwrap().count(), 1);
}
