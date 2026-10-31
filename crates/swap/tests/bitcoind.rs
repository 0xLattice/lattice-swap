//! The bitcoind client against a real regtest bitcoind.

use std::time::Duration;

use bitcoin::{Address, Amount, Network, OutPoint, Txid};
use corepc_node::{Conf, Node};
use serde_json::json;
use swap::bitcoind::{Bitcoin, Bitcoind};
use swap::driver::bitcoin_view;
use swap_bitcoin::{EvenY, KeyPair, Params, Scalar, Spend, Swap};

/// A regtest bitcoind with `-txindex`, 101 blocks mined to its wallet, and
/// a client for it.
fn regtest() -> (Node, Bitcoind) {
    let mut conf = Conf::default();
    conf.args.push("-txindex");
    let node = Node::from_downloaded_with_conf(&conf).expect("start bitcoind");
    let miner = node.client.new_address().unwrap();
    node.client.generate_to_address(101, &miner).unwrap();
    let cookie = std::fs::read_to_string(&node.params.cookie_file).unwrap();
    let rpc = Bitcoind::new(
        &node.rpc_url_with_wallet("default"),
        &cookie,
        Network::Regtest,
        Duration::from_secs(10),
    );
    (node, rpc)
}

/// A transaction mined in a block that a reorg then took away, and that a
/// conflicting transaction replaced, is gone: `-txindex` still finds it in
/// the old block, but it is in neither the mempool nor the active chain.
#[test]
fn a_transaction_reorged_out_and_replaced_is_gone() {
    let (node, rpc) = regtest();
    let miner = node.client.new_address().unwrap();
    let call = |method: &str, params| rpc.call(method, params).unwrap();

    let to = node.client.new_address().unwrap();
    let sent = call("sendtoaddress", json!([to.to_string(), 1.0]));
    let tx1: Txid = sent.as_str().unwrap().parse().unwrap();
    let block = call("generatetoaddress", json!([1, miner.to_string()]))[0].clone();
    assert_eq!(rpc.transaction(tx1).unwrap().unwrap().1, 1);

    // Reorged out: back in the mempool.
    call("invalidateblock", json!([block]));
    assert_eq!(rpc.transaction(tx1).unwrap().unwrap().1, 0);

    // Replaced by a conflicting transaction, which is mined instead.
    let bumped = call("bumpfee", json!([tx1.to_string()]));
    let tx2: Txid = bumped["txid"].as_str().unwrap().parse().unwrap();
    node.client.generate_to_address(2, &miner).unwrap();
    assert_eq!(rpc.transaction(tx2).unwrap().unwrap().1, 2);
    let stale = call("getrawtransaction", json!([tx1.to_string(), 1]));
    assert_eq!(stale["blockhash"], block, "the index still holds it");
    assert!(rpc.transaction(tx1).unwrap().is_none());
}

fn key(n: u8) -> KeyPair<EvenY> {
    let mut bytes = [0u8; 32];
    bytes[31] = n;
    KeyPair::new_xonly(Scalar::from_bytes(bytes).unwrap().non_zero().unwrap())
}

/// The seller can spend the cancel output through the punish leaf with a
/// transaction of its own, paying elsewhere and another fee: the view
/// finds it, in the mempool and then in a block.
#[test]
fn a_punish_of_the_sellers_own_making_shows_in_the_view() {
    let (node, rpc) = regtest();
    let miner = node.client.new_address().unwrap();
    let mine = |n| drop(node.client.generate_to_address(n, &miner).unwrap());
    let payout = node.client.new_address().unwrap().script_pubkey();
    let (seller, buyer) = (key(1), key(2));
    let swap = Swap::new(Params {
        seller: seller.public_key(),
        buyer: buyer.public_key(),
        seller_share: key(3).public_key().normalize(),
        buyer_share: key(4).public_key().normalize(),
        amount: Amount::from_sat(1_000_000),
        fee: Amount::from_sat(1_000),
        t1: 2,
        t2: 3,
        redeem_payout: payout.clone(),
        refund_payout: payout.clone(),
        punish_payout: payout,
    })
    .unwrap();

    let script = swap.lock_script_pubkey();
    let address = Address::from_script(&script, Network::Regtest).unwrap();
    let sent = rpc.call("sendtoaddress", json!([address.to_string(), 0.01]));
    let funding: Txid = sent.unwrap().as_str().unwrap().parse().unwrap();
    let (tx, _) = rpc.transaction(funding).unwrap().unwrap();
    let vout = tx.output.iter().position(|o| o.script_pubkey == script);
    let lock = OutPoint::new(funding, vout.unwrap() as u32);
    mine(2);

    let a = swap.sign(lock, Spend::Cancel, &seller);
    let b = swap.sign(lock, Spend::Cancel, &buyer);
    let cancel = swap.finalize(lock, Spend::Cancel, &a, Some(&b)).unwrap();
    rpc.broadcast(&cancel).unwrap();
    mine(3);
    let view = bitcoin_view(&rpc, &swap, lock).unwrap();
    assert_eq!(view.lock_spend.unwrap().confirmations, 3);
    assert!(view.cancel_spend.is_none(), "the cancel output is unspent");

    let mut punish = swap.unsigned_tx(lock, Spend::Punish);
    punish.output[0].value -= Amount::from_sat(1_000);
    punish.output[0].script_pubkey = node.client.new_address().unwrap().script_pubkey();
    let punish = swap.sign_punish_leaf(punish, &seller);
    assert_ne!(
        punish.compute_txid(),
        swap.unsigned_tx(lock, Spend::Punish).compute_txid()
    );
    rpc.broadcast(&punish).unwrap();
    let spent = |depth| {
        let spent = bitcoin_view(&rpc, &swap, lock)
            .unwrap()
            .cancel_spend
            .unwrap();
        assert_eq!(spent.tx.compute_txid(), punish.compute_txid());
        assert_eq!(spent.confirmations, depth);
    };
    spent(0);
    mine(1);
    spent(1);
    mine(1);
    spent(2);
}
