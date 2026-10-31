//! The bitcoind client, and the driver's fee bumping, against a real
//! regtest bitcoind.

use std::time::{Duration, Instant};

use bitcoin::{Address, Amount, FeeRate, Network, OutPoint, ScriptBuf, Transaction, Txid};
use corepc_node::{Conf, Node};
use rand_core::OsRng;
use serde::{Deserialize, Serialize};
use serde_json::json;
use swap::bitcoind::{Bitcoin, Bitcoind};
use swap::driver::{bitcoin_view, Driver, Store};
use swap::transport::Ivy;
use swap::{Action, Event, Machine, Outcome, Watch};
use swap_bitcoin::{EvenY, KeyPair, Params, Scalar, Spend, Swap};
use swap_nexus_tx::rpc::Client;

/// A regtest bitcoind with `-txindex`, 101 blocks mined to its wallet, and
/// a client for it.
fn regtest() -> (Node, Bitcoind) {
    let node = start(&[]);
    let rpc = rpc(&node, "default");
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

/// Broadcasts a signed redeem until it confirms, as the seller's machine
/// does, and leaves the rest to the driver.
#[derive(Clone, Serialize, Deserialize)]
struct Redeems {
    /// Seller and buyer keys, then their shares.
    keys: [[u8; 32]; 4],
    payout: ScriptBuf,
    lock: OutPoint,
    redeem: Transaction,
    confirmed: bool,
}

impl Redeems {
    fn key(&self, n: usize) -> KeyPair<EvenY> {
        let scalar = Scalar::from_bytes(self.keys[n])
            .unwrap()
            .non_zero()
            .unwrap();
        KeyPair::new_xonly(scalar)
    }

    fn swap(&self) -> Swap {
        Swap::new(Params {
            seller: self.key(0).public_key(),
            buyer: self.key(1).public_key(),
            seller_share: self.key(2).public_key().normalize(),
            buyer_share: self.key(3).public_key().normalize(),
            amount: Amount::from_sat(100_000_000),
            fee: Amount::from_sat(1_000),
            t1: 3,
            t2: 2,
            redeem_payout: self.payout.clone(),
            refund_payout: self.payout.clone(),
            punish_payout: self.payout.clone(),
        })
        .unwrap()
    }

    /// A swap paying `payout`, its lock funded and mined once, and its
    /// redeem signed. Returns it and the signed cancel.
    fn funded(node: &Node, payout: ScriptBuf) -> (Self, Transaction) {
        let mut machine = Redeems {
            keys: [(); 4].map(|_| Scalar::random(&mut OsRng).to_bytes()),
            payout,
            lock: OutPoint::null(),
            redeem: empty(),
            confirmed: false,
        };
        let swap = machine.swap();
        let address = Address::from_script(&swap.lock_script_pubkey(), Network::Regtest).unwrap();
        let funding = node
            .client
            .send_to_address(&address, swap.params().amount)
            .unwrap()
            .txid()
            .unwrap();
        let raw = node.client.get_raw_transaction(funding).unwrap();
        let vout = raw
            .transaction()
            .unwrap()
            .output
            .iter()
            .position(|out| out.script_pubkey == swap.lock_script_pubkey());
        machine.lock = OutPoint::new(funding, vout.unwrap() as u32);
        let miner = node.client.new_address().unwrap();
        node.client.generate_to_address(1, &miner).unwrap();
        let (lock, seller, buyer) = (machine.lock, machine.key(0), machine.key(1));
        let signed = |spend| {
            let a = swap.sign(lock, spend, &seller);
            let b = swap.sign(lock, spend, &buyer);
            swap.finalize(lock, spend, &a, Some(&b)).unwrap()
        };
        machine.redeem = signed(Spend::Redeem);
        (machine, signed(Spend::Cancel))
    }
}

fn empty() -> Transaction {
    Transaction {
        version: bitcoin::transaction::Version::TWO,
        lock_time: bitcoin::absolute::LockTime::ZERO,
        input: vec![],
        output: vec![],
    }
}

impl Machine for Redeems {
    fn step(mut self, event: Event) -> (Self, Vec<Action>) {
        let Event::Bitcoin(view) = event else {
            return (self, vec![]);
        };
        match view.lock_spend {
            None => {
                let broadcast = Action::Broadcast(self.redeem.clone());
                return (self, vec![broadcast]);
            }
            Some(spent) => self.confirmed = spent.confirmations > 0,
        }
        (self, vec![])
    }

    fn outcome(&self) -> Option<Outcome> {
        self.confirmed.then_some(Outcome::Swapped)
    }

    fn awaits_message(&self) -> bool {
        false
    }

    fn watch(&self) -> Watch {
        Watch {
            bitcoin: Some((self.swap(), self.lock)),
            nexus: None,
        }
    }

    fn own_spends(&self) -> &'static [Spend] {
        &[Spend::Redeem]
    }
}

fn start(args: &[&'static str]) -> Node {
    let mut conf = Conf::default();
    conf.args.push("-txindex");
    conf.args.extend(args);
    let node = Node::from_downloaded_with_conf(&conf).expect("start bitcoind");
    let miner = node.client.new_address().unwrap();
    node.client.generate_to_address(101, &miner).unwrap();
    node
}

fn rpc(node: &Node, wallet: &str) -> Bitcoind {
    let cookie = std::fs::read_to_string(&node.params.cookie_file).unwrap();
    Bitcoind::new(
        &node.rpc_url_with_wallet(wallet),
        &cookie,
        Network::Regtest,
        Duration::from_secs(10),
    )
}

fn pooled(rpc: &Bitcoind, txid: Txid) -> bool {
    rpc.call("getmempoolentry", json!([txid.to_string()]))
        .is_ok()
}

/// A block with none of the mempool in it.
fn mine_empty(node: &Node) {
    let miner = node.client.new_address().unwrap();
    let rpc = rpc(node, "default");
    rpc.call("generateblock", json!([miner.to_string(), []]))
        .unwrap();
}

/// A new wallet with no coins at all, and a script paying it.
fn empty_wallet(node: &Node, name: &str) -> (Bitcoind, ScriptBuf) {
    rpc(node, "default")
        .call("createwallet", json!([name]))
        .unwrap();
    let wallet = rpc(node, name);
    let address = wallet.call("getnewaddress", json!([])).unwrap();
    let address: Address<bitcoin::address::NetworkUnchecked> =
        address.as_str().unwrap().parse().unwrap();
    let coins = wallet.call("listunspent", json!([0])).unwrap();
    assert_eq!(coins, json!([]));
    (wallet, address.assume_checked().script_pubkey())
}

/// Miners here skip anything below 8 sat/vB, which the agreed fee is not:
/// redeem waits in the mempool until the driver bumps it, from the payout,
/// into a wallet that had no coins.
#[test]
fn the_driver_bumps_a_stalled_redeem_from_its_payout() {
    let node = start(&["-blockmintxfee=0.00008"]);
    let (_, payout) = empty_wallet(&node, "seller");
    let (machine, _) = Redeems::funded(&node, payout);
    let redeem = machine.redeem.compute_txid();
    assert!(Amount::from_sat(1_000) < Amount::from_sat(8 * machine.redeem.vsize() as u64));

    let nexus = Client::new("http://127.0.0.1:9", "", Duration::from_secs(1));
    let directory = tempfile::tempdir().unwrap();
    let store = Store::new(directory.path(), [7; 32]);
    let bitcoin = rpc(&node, "seller");
    let mut driver =
        Driver::<_, _, Ivy>::start(machine, vec![], bitcoin, nexus, None, store).unwrap();
    driver.fallback_fee_rate = FeeRate::from_sat_per_vb_u32(25);
    let party = std::thread::spawn(move || driver.run().unwrap());

    let miner = node.client.new_address().unwrap();
    let deadline = Instant::now() + Duration::from_secs(60);
    while !party.is_finished() {
        assert!(Instant::now() < deadline, "redeem never confirmed");
        std::thread::sleep(Duration::from_millis(500));
        node.client.generate_to_address(1, &miner).unwrap();
    }
    assert_eq!(party.join().unwrap(), Outcome::Swapped);
    let payout: serde_json::Value = node
        .client
        .call("gettxout", &[redeem.to_string().into(), 0.into()])
        .unwrap();
    assert!(payout.is_null(), "the payout was spent by the bump");
}

/// The first child spends the payout, so a wallet with no other coins bumps
/// again by replacing that child with one paying more.
#[test]
fn a_rebump_replaces_the_child_from_a_wallet_with_no_coins() {
    let node = start(&[]);
    let (seller, payout) = empty_wallet(&node, "seller");
    let (machine, _) = Redeems::funded(&node, payout);
    let redeem = machine.redeem;
    let fee = Amount::from_sat(1_000);
    seller.broadcast(&redeem).unwrap();

    let first = seller
        .bump(&redeem, fee, FeeRate::from_sat_per_vb_u32(10))
        .unwrap();
    assert!(pooled(&seller, first));
    let second = seller
        .bump(&redeem, fee, FeeRate::from_sat_per_vb_u32(50))
        .unwrap();
    assert!(pooled(&seller, second));
    assert!(!pooled(&seller, first), "replaced");
    assert!(pooled(&seller, redeem.compute_txid()));
}

/// Cancel pays what redeem pays and has no output either party can spend
/// alone: once `t1` passes with redeem still waiting, the buyer can
/// neither replace it with cancel nor bump cancel past it.
#[test]
fn a_cancel_cannot_displace_a_waiting_redeem() {
    let node = start(&[]);
    let (machine, cancel) =
        Redeems::funded(&node, node.client.new_address().unwrap().script_pubkey());
    let seller = rpc(&node, "default");
    let (buyer, _) = empty_wallet(&node, "buyer");
    let redeem = machine.redeem.compute_txid();
    seller.broadcast(&machine.redeem).unwrap();
    // The lock is one deep; t1 = 3, and a block more to be sure.
    for _ in 0..3 {
        mine_empty(&node);
    }
    assert!(pooled(&seller, redeem), "redeem still waiting at t1");

    let replaced = seller.broadcast(&cancel).unwrap_err().to_string();
    assert!(replaced.contains("insufficient fee"), "{replaced}");
    let bumped = buyer.bump(
        &cancel,
        Amount::from_sat(1_000),
        FeeRate::from_sat_per_vb_u32(100),
    );
    assert!(bumped.is_err());
    assert!(pooled(&seller, redeem));
}
