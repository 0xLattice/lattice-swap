//! The bitcoind client against a real regtest bitcoind.

use std::time::Duration;

use bitcoin::{Network, Txid};
use corepc_node::{Conf, Node};
use serde_json::json;
use swap::bitcoind::{Bitcoin, Bitcoind};

/// A transaction mined in a block that a reorg then took away, and that a
/// conflicting transaction replaced, is gone: `-txindex` still finds it in
/// the old block, but it is in neither the mempool nor the active chain.
#[test]
fn a_transaction_reorged_out_and_replaced_is_gone() {
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
