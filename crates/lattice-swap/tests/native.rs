//! The native buyer's Bitcoin, `swap::esplora`, against the Esplora shim
//! over a regtest bitcoind: what it reads, its single-key wallet's funding,
//! and its fee bumps through `POST /txs/package`.

use std::time::Duration;

use bitcoin::hashes::Hash;
use bitcoin::transaction::Version;
use bitcoin::{absolute, Amount, FeeRate, OutPoint, ScriptBuf, Sequence};
use bitcoin::{Transaction, TxIn, TxOut, WPubkeyHash, Witness};
use corepc_node::{Conf, Node};
use serde_json::json;
use swap::bitcoind::{Bitcoin, Bitcoind};
use swap::esplora::Esplora;
use swap::wallet::{self, Key};

mod esplora;

const TIMEOUT: Duration = Duration::from_secs(10);

fn bitcoind(node: &Node) -> Bitcoind {
    let cookie = std::fs::read_to_string(&node.params.cookie_file).unwrap();
    Bitcoind::new(&node.rpc_url(), &cookie, bitcoin::Network::Regtest, TIMEOUT)
}

fn mine(node: &Node, blocks: usize) {
    let miner = node.client.new_address().unwrap();
    node.client.generate_to_address(blocks, &miner).unwrap();
}

/// A version 3 transaction spending the wallet's `utxo` of `value` into
/// `to`, all but `fee`: a parent whose payout, output 0, the wallet can
/// bump, as it can a refund to it.
fn parent(key: &Key, utxo: OutPoint, value: u64, to: ScriptBuf, fee: u64) -> Transaction {
    let tx = Transaction {
        version: Version::non_standard(3),
        lock_time: absolute::LockTime::ZERO,
        input: vec![TxIn {
            previous_output: utxo,
            script_sig: ScriptBuf::new(),
            sequence: Sequence::MAX,
            witness: Witness::new(),
        }],
        output: vec![TxOut {
            value: Amount::from_sat(value - fee),
            script_pubkey: to,
        }],
    };
    wallet::sign(&key.wif, tx, &[value]).unwrap()
}

#[test]
fn esplora_reads_funds_and_bumps() {
    let mut conf = Conf::default();
    conf.args.push("-txindex");
    let node = Node::from_downloaded_with_conf(&conf).expect("start bitcoind");
    mine(&node, 101);
    let rpc = bitcoind(&node);
    let key = Key::new("regtest").unwrap();
    let esplora = Esplora::new(&esplora::esplora(bitcoind(&node)), key.clone(), TIMEOUT);

    // The tip, its own headers: Esplora shows no header chain ahead.
    let tip = esplora.tip().unwrap();
    assert_eq!(tip.height, 101);
    assert_eq!(tip.headers, 101);
    let best = rpc.call("getbestblockhash", json!([])).unwrap();
    assert_eq!(tip.hash.to_string(), best.as_str().unwrap());
    // Regtest has no estimate.
    assert_eq!(esplora.fee_rate(false).unwrap(), None);
    assert_eq!(esplora.wallet_rate().unwrap(), 1);

    // A deposit, spendable once in a block.
    let deposit = rpc
        .call("sendtoaddress", json!([key.address, 1.0]))
        .unwrap()
        .as_str()
        .unwrap()
        .parse()
        .unwrap();
    let (_, depth) = esplora.transaction(deposit).unwrap().unwrap();
    assert_eq!(depth, 0, "in the mempool");
    assert_eq!(esplora.balance().unwrap(), (0, 100_000_000));
    assert!(esplora.spendable().unwrap().is_empty());
    mine(&node, 1);
    assert_eq!(esplora.balance().unwrap(), (100_000_000, 0));
    let [utxo] = &esplora.spendable().unwrap()[..] else {
        panic!("one output");
    };
    assert_eq!(utxo.txid, deposit);

    // The lock funded from it, at the rate asked, the change back.
    let lock = ScriptBuf::new_p2wpkh(&WPubkeyHash::from_byte_array([7; 20]));
    let rate = FeeRate::from_sat_per_vb_u32(3);
    let funding = esplora
        .fund_lock(&lock, Amount::from_sat(10_000_000), rate)
        .unwrap();
    assert_eq!(funding.output[0].script_pubkey, lock);
    assert_eq!(funding.output[1].script_pubkey, key.script_pubkey);
    let paid: u64 = funding.output.iter().map(|o| o.value.to_sat()).sum();
    let fee = 100_000_000 - paid;
    assert!(fee >= 3 * funding.vsize() as u64, "{fee}");
    assert!(fee < 4 * funding.vsize() as u64, "{fee}");
    esplora.broadcast(&funding).unwrap();
    let txid = funding.compute_txid();
    assert_eq!(esplora.transaction(txid).unwrap().unwrap().1, 0);
    mine(&node, 2);
    let (seen, depth) = esplora.transaction(txid).unwrap().unwrap();
    assert_eq!((seen, depth), (funding.clone(), 2));
    let spent = OutPoint::new(deposit, utxo.vout);
    assert_eq!(
        esplora.spender(spent, 0).unwrap(),
        Some((funding.clone(), 2))
    );
    assert_eq!(esplora.spender(OutPoint::new(txid, 0), 0).unwrap(), None);
    let unknown = bitcoin::Txid::from_byte_array([9; 32]);
    assert_eq!(esplora.transaction(unknown).unwrap(), None);
    // A broadcast the node refuses fails with its reason.
    let conflict = parent(&key, spent, utxo.value, lock.clone(), 1_000);
    let refused = esplora.broadcast(&conflict).unwrap_err();
    assert!(refused.0.contains("400"), "{refused}");

    // A parent at 1 sat/vB paying the wallet, bumped by CPFP as a package.
    let change = OutPoint::new(txid, 1);
    let value = funding.output[1].value.to_sat();
    let low = parent(&key, change, value, key.script_pubkey.clone(), 200);
    esplora.broadcast(&low).unwrap();
    let own = FeeRate::from_sat_per_kwu(200 * 250 / low.vsize() as u64);
    assert_eq!(esplora.package_rate(&low).unwrap(), Some(own));
    assert_eq!(
        esplora.floor(&low).unwrap(),
        FeeRate::from_sat_per_vb_u32(1)
    );
    let max = Amount::from_sat(100_000);
    for target in [10, 20] {
        let target = FeeRate::from_sat_per_vb_u32(target);
        let child = esplora
            .bump(&low, Amount::from_sat(200), target, max)
            .unwrap();
        let rate = esplora.package_rate(&low).unwrap().unwrap();
        assert!(rate >= target, "{rate} below {target}");
        let pool = rpc.call("getrawmempool", json!([])).unwrap();
        assert!(pool.as_array().unwrap().contains(&json!(child.to_string())));
    }
    // A lower target still replaces the last child, which pays more.
    let twenty = esplora.package_rate(&low).unwrap().unwrap();
    let ten = FeeRate::from_sat_per_vb_u32(10);
    esplora.bump(&low, Amount::from_sat(200), ten, max).unwrap();
    assert!(esplora.package_rate(&low).unwrap().unwrap() > twenty);
    // Capped by `max` below what replacing it takes: the node refuses.
    let capped = FeeRate::from_sat_per_vb_u32(1_000);
    let refused = esplora.bump(&low, Amount::from_sat(200), capped, Amount::from_sat(4_000));
    assert!(refused.is_err_and(|e| e.0.contains("/txs/package")));

    // Another spend of its input, unconfirmed: the floor is its feerate
    // and the incremental relay feerate over it.
    let rival = parent(&key, change, value, key.script_pubkey.clone(), 5_000);
    let beat = (200 * 250u64).div_ceil(low.vsize() as u64);
    assert_eq!(
        esplora.floor(&rival).unwrap(),
        FeeRate::from_sat_per_kwu(beat + 250)
    );

    // Mined: in no mempool.
    mine(&node, 1);
    assert_eq!(esplora.package_rate(&low).unwrap(), None);

    // Only a payout to the wallet is bumped.
    let payout = OutPoint::new(low.compute_txid(), 0);
    let elsewhere = parent(&key, payout, low.output[0].value.to_sat(), lock, 200);
    let refused = esplora.bump(&elsewhere, Amount::from_sat(200), ten, max);
    assert!(refused.is_err_and(|e| e.0.contains("not this wallet's")));
}
