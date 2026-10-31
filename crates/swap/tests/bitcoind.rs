//! The bitcoind client, and the driver's fee bumping, against a real
//! regtest bitcoind.

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime};

use bitcoin::consensus::encode::{deserialize_hex, serialize_hex};
use bitcoin::{Address, Amount, FeeRate, Network, OutPoint, ScriptBuf, Transaction, TxOut, Txid};
use corepc_node::{Conf, Node};
use rand_core::OsRng;
use serde::{Deserialize, Serialize};
use serde_json::json;
use swap::bitcoind::{Bitcoin, Bitcoind};
use swap::driver::{bitcoin_view, Driver, Store};
use swap::transport::Ivy;
use swap::{
    Action, BitcoinView, Buyer, Event, Machine, Outcome, SecretBytes, Seller, Terms, Watch,
};
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

/// A node with a synced `-txindex`, on the client's chain, with a wallet
/// that signs, passes the check; any other is refused by name.
#[test]
fn the_node_check_requires_a_txindex() {
    let (node, indexed) = regtest();
    let deadline = Instant::now() + Duration::from_secs(30);
    while let Err(e) = indexed.check_node() {
        assert!(Instant::now() < deadline, "{e}");
        std::thread::sleep(Duration::from_millis(100));
    }
    let cookie = std::fs::read_to_string(&node.params.cookie_file).unwrap();
    let url = node.rpc_url_with_wallet("default");
    let mainnet = Bitcoind::new(&url, &cookie, Network::Bitcoin, Duration::from_secs(10));
    let refused = mainnet.check_node().unwrap_err();
    assert!(refused.to_string().contains("not main"), "{refused}");
    let refused = rpc(&node, "absent").check_node().unwrap_err();
    assert!(refused.to_string().contains("no such wallet"), "{refused}");
    indexed
        .call("createwallet", json!(["watching", true]))
        .unwrap();
    let refused = rpc(&node, "watching").check_node().unwrap_err();
    assert!(refused.to_string().contains("cannot sign"), "{refused}");
    let bare = Node::from_downloaded_with_conf(&Conf::default()).expect("start bitcoind");
    let refused = rpc(&bare, "default").check_node().unwrap_err();
    assert!(refused.to_string().contains("-txindex"), "{refused}");
}

/// A node at genesis, whose tip is years old, shows a stale view; once
/// it mines a block, a fresh one.
#[test]
fn a_stale_tip_shows_a_stale_view() {
    let node = start_bare(&[]);
    let rpc = rpc(&node, "default");
    let payout = node.client.new_address().unwrap().script_pubkey();
    let swap = Swap::new(Params {
        seller: key(1).public_key(),
        buyer: key(2).public_key(),
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
    let mut first_seen = None;
    let view = bitcoin_view(
        &rpc,
        &swap,
        OutPoint::null(),
        AGE,
        SystemTime::now(),
        &mut first_seen,
    )
    .unwrap();
    let stale = view.stale.unwrap();
    assert!(stale.contains("minutes old"), "{stale}");
    let miner = node.client.new_address().unwrap();
    node.client.generate_to_address(1, &miner).unwrap();
    let view = bitcoin_view(
        &rpc,
        &swap,
        OutPoint::null(),
        AGE,
        SystemTime::now(),
        &mut first_seen,
    )
    .unwrap();
    assert_eq!(view.height, 1);
    assert_eq!(view.stale, None);
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
    let view = bitcoin_view(&rpc, &swap, lock, AGE, SystemTime::now(), &mut None).unwrap();
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
        let spent = bitcoin_view(&rpc, &swap, lock, AGE, SystemTime::now(), &mut None)
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
    amount: Amount,
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
            amount: self.amount,
            fee: Amount::from_sat(1_000),
            t1: 3,
            t2: 2,
            redeem_payout: self.payout.clone(),
            refund_payout: self.payout.clone(),
            punish_payout: self.payout.clone(),
        })
        .unwrap()
    }

    /// A swap of 1 BTC paying `payout`, its lock funded and mined once, and
    /// its redeem signed. Returns it and the signed cancel.
    fn funded(node: &Node, payout: ScriptBuf) -> (Self, Transaction) {
        Self::funded_with(node, payout, Amount::ONE_BTC)
    }

    fn funded_with(node: &Node, payout: ScriptBuf, amount: Amount) -> (Self, Transaction) {
        Self::funded_many(node, payout, amount, 1).remove(0)
    }

    /// `n` such swaps of `amount`, their locks mined in one block.
    fn funded_many(
        node: &Node,
        payout: ScriptBuf,
        amount: Amount,
        n: usize,
    ) -> Vec<(Self, Transaction)> {
        let machines: Vec<_> = (0..n)
            .map(|_| {
                let mut machine = Redeems {
                    keys: [(); 4].map(|_| Scalar::random(&mut OsRng).to_bytes()),
                    payout: payout.clone(),
                    amount,
                    lock: OutPoint::null(),
                    redeem: empty(),
                    confirmed: false,
                };
                let swap = machine.swap();
                let script = swap.lock_script_pubkey();
                let address = Address::from_script(&script, Network::Regtest).unwrap();
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
                    .position(|out| out.script_pubkey == script);
                machine.lock = OutPoint::new(funding, vout.unwrap() as u32);
                machine
            })
            .collect();
        let miner = node.client.new_address().unwrap();
        node.client.generate_to_address(1, &miner).unwrap();
        machines
            .into_iter()
            .map(|mut machine| {
                let swap = machine.swap();
                let (lock, seller, buyer) = (machine.lock, machine.key(0), machine.key(1));
                let signed = |spend| {
                    let a = swap.sign(lock, spend, &seller);
                    let b = swap.sign(lock, spend, &buyer);
                    swap.finalize(lock, spend, &a, Some(&b)).unwrap()
                };
                machine.redeem = signed(Spend::Redeem);
                (machine, signed(Spend::Cancel))
            })
            .collect()
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
            margin: 0,
        }
    }

    fn own_spends(&self) -> &'static [Spend] {
        &[Spend::Redeem]
    }
}

/// The driver's default `max_tip_age`.
const AGE: Duration = Duration::from_secs(90 * 60);

/// A regtest bitcoind with `-txindex` and `args`, its wallet holding 101
/// blocks' coins.
fn start(args: &[&'static str]) -> Node {
    let node = start_bare(args);
    let miner = node.client.new_address().unwrap();
    node.client.generate_to_address(101, &miner).unwrap();
    node
}

/// A regtest bitcoind with `-txindex` and `args`, at genesis. Tried a few
/// times: under a parallel test run, bitcoind can fail to come up.
fn start_bare(args: &[&'static str]) -> Node {
    let mut conf = Conf::default();
    conf.args.extend(args);
    start_with(conf)
}

/// A regtest bitcoind with `-txindex` and `conf`, at genesis.
fn start_with(mut conf: Conf) -> Node {
    conf.args.push("-txindex");
    let mut tries = 0;
    loop {
        match Node::from_downloaded_with_conf(&conf) {
            Ok(node) => return node,
            Err(e) if tries == 2 => panic!("start bitcoind: {e}"),
            Err(_) => tries += 1,
        }
    }
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

/// Miners here skip anything below 20 sat/vB, which redeem's two fees are
/// not: redeem waits in the mempool until the driver bumps it, from the
/// payout, into a wallet that had no coins. The node's wallet funds the
/// lock at 50 sat/vB, so the lock is mined.
#[test]
fn the_driver_bumps_a_stalled_redeem_from_its_payout() {
    let node = start(&["-blockmintxfee=0.0002", "-fallbackfee=0.0005"]);
    let (_, payout) = empty_wallet(&node, "seller");
    let (machine, _) = Redeems::funded(&node, payout);
    let redeem = machine.redeem.compute_txid();
    assert!(Amount::from_sat(2_000) < Amount::from_sat(20 * machine.redeem.vsize() as u64));

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

/// A redeem below the mempool's minimum feerate is refused alone. The
/// driver raises it to that minimum, though the estimate is below the
/// redeem's own feerate, and it confirms.
#[test]
fn the_driver_raises_a_refused_redeem_to_the_mempool_minimum() {
    let node = start(&["-minrelaytxfee=0.0002"]);
    let (seller, payout) = empty_wallet(&node, "seller");
    let (machine, _) = Redeems::funded(&node, payout);
    let refused = seller.broadcast(&machine.redeem).unwrap_err().to_string();
    assert!(refused.contains("min relay fee not met"), "{refused}");
    let low = FeeRate::from_sat_per_vb_u32(2);
    assert!(low.fee_vb(machine.redeem.vsize() as u64).unwrap() < Amount::from_sat(2_000));

    let nexus = Client::new("http://127.0.0.1:9", "", Duration::from_secs(1));
    let directory = tempfile::tempdir().unwrap();
    let store = Store::new(directory.path(), [7; 32]);
    let mut driver =
        Driver::<_, _, Ivy>::start(machine, vec![], seller, nexus, None, store).unwrap();
    driver.fallback_fee_rate = low;
    let party = std::thread::spawn(move || driver.run().unwrap());
    let miner = node.client.new_address().unwrap();
    let deadline = Instant::now() + Duration::from_secs(60);
    while !party.is_finished() {
        assert!(Instant::now() < deadline, "redeem never confirmed");
        std::thread::sleep(Duration::from_millis(500));
        node.client.generate_to_address(1, &miner).unwrap();
    }
    assert_eq!(party.join().unwrap(), Outcome::Swapped);
}

/// The first child spends the payout, so a wallet with no other coins bumps
/// again by replacing that child with one paying more.
#[test]
fn a_rebump_replaces_the_child_from_a_wallet_with_no_coins() {
    let node = start(&[]);
    let (seller, payout) = empty_wallet(&node, "seller");
    let (machine, _) = Redeems::funded(&node, payout);
    let redeem = machine.redeem;
    let fee = Amount::from_sat(2_000);
    seller.broadcast(&redeem).unwrap();

    let all = redeem.output[0].value;
    let first = seller
        .bump(&redeem, fee, FeeRate::from_sat_per_vb_u32(10), all)
        .unwrap();
    assert!(pooled(&seller, first));
    let second = seller
        .bump(&redeem, fee, FeeRate::from_sat_per_vb_u32(50), all)
        .unwrap();
    assert!(pooled(&seller, second));
    assert!(!pooled(&seller, first), "replaced");
    assert!(pooled(&seller, redeem.compute_txid()));
    // A sat more over the package is less than the incremental feerate on
    // the child: the child pays that instead.
    let third = seller
        .bump(&redeem, fee, FeeRate::from_sat_per_kwu(50 * 250 + 1), all)
        .unwrap();
    assert!(pooled(&seller, third));
    assert!(!pooled(&seller, second), "replaced");
}

/// A child is priced a vbyte over the package it was sized with, whose
/// signature can come out a byte shorter than its own: every package pays
/// its target, and most, whose signature came out as long as the sized
/// one's, a vbyte more. Priced at the sized package, about one in 70 fell a
/// vbyte short.
#[test]
fn every_bumped_package_pays_its_target() {
    let node = start(&[]);
    let (seller, payout) = empty_wallet(&node, "seller");
    let target = FeeRate::from_sat_per_vb_u32(25);
    let amount = Amount::from_sat(100_000);
    // Twenty at a time: the wallet chains no more unconfirmed sends.
    let machines = (0..10).flat_map(|_| Redeems::funded_many(&node, payout.clone(), amount, 20));
    let mut over = 0;
    for (machine, _) in machines {
        let (redeem, fee) = (&machine.redeem, machine.swap().fee(Spend::Redeem));
        seller
            .bump(redeem, fee, target, redeem.output[0].value)
            .unwrap();
        let txid = redeem.compute_txid().to_string();
        let entry = seller.call("getmempoolentry", json!([txid])).unwrap();
        let paid = entry["fees"]["descendant"].as_f64().unwrap();
        let paid = Amount::from_btc(paid).unwrap();
        let size = entry["descendantsize"].as_u64().unwrap();
        assert!(paid >= target.fee_vb(size).unwrap(), "{paid} for {size} vB");
        over += usize::from(paid >= target.fee_vb(size + 1).unwrap());
    }
    assert!(over > 100, "{over} of 200 a vbyte over");
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
        cancel.output[0].value,
    );
    assert!(bumped.is_err());
    assert!(pooled(&seller, redeem));
}

/// A payout the child cannot cover is spent to all but dust rather than
/// not bumped, and the child pays no more than it may.
#[test]
fn a_bump_past_the_payout_leaves_dust_and_keeps_to_its_cap() {
    let node = start(&[]);
    let (seller, payout) = empty_wallet(&node, "seller");
    let (machine, _) = Redeems::funded_with(&node, payout, Amount::from_sat(20_000));
    let redeem = machine.redeem;
    let (fee, value) = (Amount::from_sat(2_000), redeem.output[0].value);
    seller.broadcast(&redeem).unwrap();
    let rate = FeeRate::from_sat_per_vb_u32(500);
    assert!(rate.fee_vb(250).unwrap() > value, "more than the payout");
    let change = |child| {
        let (tx, _) = seller.transaction(child).unwrap().unwrap();
        tx.output[0].clone()
    };

    let capped = seller
        .bump(&redeem, fee, rate, Amount::from_sat(5_000))
        .unwrap();
    assert_eq!(value - change(capped).value, Amount::from_sat(5_000));
    let all = seller.bump(&redeem, fee, rate, value).unwrap();
    let left = change(all);
    assert_eq!(left.value, left.script_pubkey.minimal_non_dust());
    assert!(pooled(&seller, all) && !pooled(&seller, capped));
}

/// Bitcoin Core takes both targets the driver asks for.
#[test]
fn the_node_takes_both_estimate_targets() {
    let (_node, rpc) = regtest();
    assert!(
        rpc.fee_rate(false).unwrap().is_none(),
        "regtest has no data"
    );
    assert!(rpc.fee_rate(true).unwrap().is_none(), "regtest has no data");
}

/// Fails its first bump, as a wallet still locked would, unless `failed`
/// says it has, and passes the rest to bitcoind, counting in `failures`
/// the bumps bitcoind fails.
struct Flaky {
    inner: Bitcoind,
    failed: std::cell::Cell<bool>,
    failures: Arc<AtomicUsize>,
}

impl Bitcoin for Flaky {
    fn broadcast(&self, tx: &Transaction) -> swap::bitcoind::Result<()> {
        self.inner.broadcast(tx)
    }
    fn tip(&self) -> swap::bitcoind::Result<swap::bitcoind::Tip> {
        self.inner.tip()
    }
    fn transaction(&self, txid: Txid) -> swap::bitcoind::Result<Option<(Transaction, u32)>> {
        self.inner.transaction(txid)
    }
    fn spender(
        &self,
        outpoint: OutPoint,
        from: u32,
    ) -> swap::bitcoind::Result<Option<(Transaction, u32)>> {
        self.inner.spender(outpoint, from)
    }
    fn fund_lock(
        &self,
        script: &bitcoin::Script,
        amount: Amount,
        fee_rate: Option<FeeRate>,
    ) -> swap::bitcoind::Result<Transaction> {
        self.inner.fund_lock(script, amount, fee_rate)
    }
    fn fee_rate(&self, urgent: bool) -> swap::bitcoind::Result<Option<FeeRate>> {
        self.inner.fee_rate(urgent)
    }
    fn floor(&self, parent: &Transaction) -> swap::bitcoind::Result<FeeRate> {
        self.inner.floor(parent)
    }
    fn package_rate(&self, parent: &Transaction) -> swap::bitcoind::Result<Option<FeeRate>> {
        self.inner.package_rate(parent)
    }
    fn bump(
        &self,
        parent: &Transaction,
        fee: Amount,
        rate: FeeRate,
        max: Amount,
    ) -> swap::bitcoind::Result<Txid> {
        if !self.failed.replace(true) {
            return Err(swap::bitcoind::Error("wallet locked".into()));
        }
        let bumped = self.inner.bump(parent, fee, rate, max);
        if bumped.is_err() {
            self.failures.fetch_add(1, Ordering::Relaxed);
        }
        bumped
    }
}

/// A redeem the mempool refuses alone, whose first bump fails: the driver
/// tries again, and it confirms.
#[test]
fn a_transient_bump_failure_is_retried() {
    let node = start(&["-minrelaytxfee=0.0002"]);
    let (seller, payout) = empty_wallet(&node, "seller");
    let (machine, _) = Redeems::funded(&node, payout);
    assert!(seller.broadcast(&machine.redeem).is_err(), "refused alone");
    let nexus = Client::new("http://127.0.0.1:9", "", Duration::from_secs(1));
    let directory = tempfile::tempdir().unwrap();
    let store = Store::new(directory.path(), [7; 32]);
    let flaky = Flaky {
        inner: seller,
        failed: std::cell::Cell::new(false),
        failures: Arc::default(),
    };
    let mut driver =
        Driver::<_, _, Ivy>::start(machine, vec![], flaky, nexus, None, store).unwrap();
    driver.fallback_fee_rate = FeeRate::from_sat_per_vb_u32(2);
    let party = std::thread::spawn(move || driver.run().unwrap());
    let miner = node.client.new_address().unwrap();
    let deadline = Instant::now() + Duration::from_secs(30);
    while !party.is_finished() {
        assert!(Instant::now() < deadline, "redeem never confirmed");
        std::thread::sleep(Duration::from_millis(500));
        node.client.generate_to_address(1, &miner).unwrap();
    }
    assert_eq!(party.join().unwrap(), Outcome::Swapped);
}

/// A driver restarted while the redeem it bumped waits knows nothing of
/// that bump. It finds the package the child made in the mempool, at the
/// target already, and leaves it, at that block and the next: a child at
/// the same rate could not replace it.
#[test]
fn a_restarted_driver_leaves_a_package_at_its_target() {
    let node = start(&[]);
    let (seller, payout) = empty_wallet(&node, "seller");
    let (machine, _) = Redeems::funded(&node, payout);
    let payout = json!([[{"txid": machine.redeem.compute_txid(), "vout": 0}]]);
    let child = || {
        let spending = seller.call("gettxspendingprevout", payout.clone()).unwrap();
        spending[0]["spendingtxid"].as_str().map(String::from)
    };
    let nexus = || Client::new("http://127.0.0.1:9", "", Duration::from_secs(1));
    let directory = tempfile::tempdir().unwrap();
    let store = || Store::new(directory.path(), [7; 32]);
    let fallback = FeeRate::from_sat_per_vb_u32(25);

    let mut driver = Driver::<_, _, Ivy>::start(
        machine,
        vec![],
        rpc(&node, "seller"),
        nexus(),
        None,
        store(),
    )
    .unwrap();
    driver.poll = Duration::from_millis(10);
    driver.fallback_fee_rate = fallback;
    let deadline = Instant::now() + Duration::from_secs(30);
    driver
        .run_until(|_| {
            assert!(Instant::now() < deadline, "never bumped");
            child().is_some()
        })
        .unwrap();
    let bumped = child();
    drop(driver);

    let failures = Arc::<AtomicUsize>::default();
    let flaky = Flaky {
        inner: rpc(&node, "seller"),
        failed: std::cell::Cell::new(true),
        failures: failures.clone(),
    };
    let mut driver = Driver::<Redeems, _, Ivy>::resume(flaky, nexus(), None, store()).unwrap();
    driver.poll = Duration::from_millis(10);
    driver.fallback_fee_rate = fallback;
    let polls = std::cell::Cell::new(0);
    driver
        .run_until(|_| {
            polls.set(polls.get() + 1);
            if polls.get() == 20 {
                mine_empty(&node);
            }
            polls.get() > 40
        })
        .unwrap();
    assert_eq!(failures.load(Ordering::Relaxed), 0);
    assert_eq!(child(), bumped, "the child is the first driver's");
}

fn sent(actions: &[Action]) -> swap::Message {
    let [Action::Send(message)] = actions else {
        panic!("one message: {actions:?}");
    };
    message.clone()
}

/// After `t2` the seller can contest a pending refund with its punish and a
/// child paying more. The buyer's driver, running the real buyer, sees its
/// refund refused and outbids that package from the refund's payout, so
/// the refund confirms.
#[test]
fn the_buyers_driver_outbids_a_punish_package_with_its_refund() {
    contest_a_refund(|seller, punish| {
        let rate = FeeRate::from_sat_per_vb_u32(30);
        seller
            .bump(
                punish,
                Amount::from_sat(1_000),
                rate,
                punish.output[0].value,
            )
            .unwrap();
    });
}

/// The same against a punish pinned with a child near the 1000 vB TRUC
/// allows, at a low feerate: replacing it means paying that child's whole
/// fee over a package about a quarter its size, which the buyer's driver
/// does.
#[test]
fn the_buyers_driver_outbids_a_punish_pinned_by_a_large_child() {
    contest_a_refund(|seller, punish| {
        let outputs = 28;
        let scripts: Vec<ScriptBuf> = (0..outputs)
            .map(|_| {
                let address = seller.call("getnewaddress", json!([])).unwrap();
                let address: Address<bitcoin::address::NetworkUnchecked> =
                    address.as_str().unwrap().parse().unwrap();
                address.assume_checked().script_pubkey()
            })
            .collect();
        let payout = &punish.output[0];
        let sign = |child: &Transaction| {
            let prevtxs = json!([{
                "txid": punish.compute_txid(),
                "vout": 0,
                "scriptPubKey": payout.script_pubkey.to_hex_string(),
                "amount": payout.value.to_btc(),
            }]);
            let signed = seller
                .call(
                    "signrawtransactionwithwallet",
                    json!([serialize_hex(child), prevtxs]),
                )
                .unwrap();
            deserialize_hex::<Transaction>(signed["hex"].as_str().unwrap()).unwrap()
        };
        let mut child = swap_bitcoin::cpfp(punish, scripts[0].clone(), Amount::ZERO).unwrap();
        let pay = |fee: Amount| -> Vec<TxOut> {
            let each = (payout.value - fee) / outputs;
            let out = |script: &ScriptBuf| TxOut {
                value: each,
                script_pubkey: script.clone(),
            };
            scripts.iter().map(out).collect()
        };
        child.output = pay(Amount::ZERO);
        let child_size = sign(&child).vsize() as u64;
        assert!(child_size > 900 && child_size <= 1_000, "{child_size} vB");
        let size = punish.vsize() as u64 + child_size;
        let package = FeeRate::from_sat_per_vb_u32(12).fee_vb(size).unwrap();
        child.output = pay(package - Amount::from_sat(1_000));
        let child = sign(&child);
        let hexes = [punish, &child].map(serialize_hex);
        let result = seller.call("submitpackage", json!([hexes])).unwrap();
        assert_eq!(result["package_msg"], "success", "{result}");
    });
}

/// Runs the real buyer under its driver to a refund pending at `t2`, then
/// has `punish` send the seller's punish, with a child, against it, and
/// waits for the refund to take the cancel output back and confirm. The
/// seller is the real seller machine, stepped by hand, whose punish the
/// test sends as a seller ignoring the refund would.
fn contest_a_refund(punish: impl FnOnce(&Bitcoind, &Transaction)) {
    let node = start(&[]);
    let default = rpc(&node, "default");
    let (seller_rpc, seller_payout) = empty_wallet(&node, "seller");
    let (buyer_rpc, refund_payout) = empty_wallet(&node, "buyer");
    let address = buyer_rpc.call("getnewaddress", json!([])).unwrap();
    default
        .call("sendtoaddress", json!([address, 1.0]))
        .unwrap();
    let miner = node.client.new_address().unwrap();
    let mine = |blocks| drop(node.client.generate_to_address(blocks, &miner).unwrap());
    mine(1);

    let terms = Terms {
        swap_id: [5; 32],
        btc_amount: Amount::from_sat(1_000_000),
        btc_fee: Amount::from_sat(1_000),
        nex_amount: 1_000,
        nex_fee: 0,
        t1: 6,
        t2: 6,
        btc_confirmations: 1,
        nex_confirmations: 1,
        margin: 2,
        nexus_genesis: swap_nexus_tx::MAINNET_GENESIS.into(),
    };
    let seller_nex = SecretBytes([3; 32]).nex_address();
    let seller = Seller::new(
        terms.clone(),
        seller_nex,
        seller_payout.clone(),
        seller_payout,
    );
    let (buyer, actions) = Buyer::start(terms, refund_payout, "buyer".into()).unwrap();
    let step = |machine: Seller, actions: &[Action]| machine.step(Event::Message(sent(actions)));
    let (seller, actions) = step(seller.unwrap(), &actions);
    let (buyer, actions) = buyer.step(Event::Message(sent(&actions)));
    let [Action::FundLock {
        script_pubkey,
        amount,
    }] = &actions[..]
    else {
        panic!("fund the lock: {actions:?}");
    };
    let funding = buyer_rpc.fund_lock(script_pubkey, *amount, None).unwrap();
    let (buyer, actions) = buyer.step(Event::Funded(funding));
    let (seller, actions) = step(seller, &actions);
    let (buyer, actions) = buyer.step(Event::Message(sent(&actions)));
    let (seller, _) = step(seller, &actions);
    let (buyer, actions) = buyer.step(Event::Sent);
    let (swap, lock) = buyer.watch().bitcoin.unwrap();
    let txid = |spend| swap.unsigned_tx(lock, spend).compute_txid();
    let (cancel, refund, punish_txid) = (
        txid(Spend::Cancel),
        txid(Spend::Refund),
        txid(Spend::Punish),
    );

    let directory = tempfile::tempdir().unwrap();
    let store = Store::new(directory.path(), [5; 32]);
    let nexus = Client::new("http://127.0.0.1:9", "", Duration::from_secs(1));
    let mut driver =
        Driver::<_, _, Ivy>::start(buyer, actions, buyer_rpc, nexus, None, store).unwrap();
    driver.fallback_fee_rate = FeeRate::from_sat_per_vb_u32(10);
    let party = std::thread::spawn(move || driver.run().unwrap());
    let wait = |what: &str, done: &dyn Fn() -> bool| {
        let deadline = Instant::now() + Duration::from_secs(60);
        while !done() {
            if party.is_finished() {
                assert!(done(), "{what}: the driver stopped");
                break;
            }
            assert!(Instant::now() < deadline, "{what}");
            std::thread::sleep(Duration::from_millis(250));
        }
    };

    // The buyer gives up at `t1` and cancels; once cancel is in a block it
    // refunds, and its driver bumps the refund. No block takes it.
    wait("cancel", &|| {
        mine(1);
        default
            .transaction(cancel)
            .unwrap()
            .is_some_and(|(_, depth)| depth > 0)
    });
    wait("refund", &|| pooled(&default, refund));
    while default.transaction(cancel).unwrap().unwrap().1 < 6 {
        mine_empty(&node);
    }
    assert!(pooled(&default, refund), "refund pending at t2");

    // The seller ignores it and punishes, with a child paying 30 sat/vB.
    let view = BitcoinView {
        cancel_spend: None,
        ..bitcoin_view(&seller_rpc, &swap, lock, AGE, SystemTime::now(), &mut None).unwrap()
    };
    let (_, actions) = seller.step(Event::Bitcoin(view));
    let [Action::Broadcast(tx)] = &actions[..] else {
        panic!("punish: {actions:?}");
    };
    assert_eq!(tx.compute_txid(), punish_txid);
    // Taken, it replaced the refund; the buyer's driver may already have
    // outbid it again.
    punish(&seller_rpc, tx);

    // Without a block, the buyer's driver takes the cancel output back.
    wait("refund back", &|| pooled(&default, refund));
    assert!(!pooled(&default, punish_txid));
    wait("refunded", &|| {
        mine(1);
        party.is_finished()
    });
    assert_eq!(party.join().unwrap(), Outcome::Refunded);
    assert!(default.transaction(refund).unwrap().unwrap().1 > 0);
}

/// A fresh node has no fee estimate, and without `-fallbackfee`, as on
/// mainnet, its wallet funds nothing at its own estimate. The buyer's
/// driver funds the lock at its fallback rate, which the wallet pays.
#[test]
fn the_buyers_driver_funds_the_lock_without_an_estimate_or_fallbackfee() {
    let mut conf = Conf::default();
    conf.args.retain(|arg| !arg.starts_with("-fallbackfee"));
    let node = start_with(conf);
    let miner = node.client.new_address().unwrap();
    node.client.generate_to_address(101, &miner).unwrap();
    let wallet = rpc(&node, "default");
    assert_eq!(wallet.fee_rate(false).unwrap(), None, "no estimate");

    let terms = Terms {
        swap_id: [6; 32],
        btc_amount: Amount::from_sat(1_000_000),
        btc_fee: Amount::from_sat(1_000),
        nex_amount: 1_000,
        nex_fee: 1,
        t1: 6,
        t2: 6,
        btc_confirmations: 1,
        nex_confirmations: 1,
        margin: 2,
        nexus_genesis: swap_nexus_tx::MAINNET_GENESIS.into(),
    };
    let payout = node.client.new_address().unwrap().script_pubkey();
    let seller_nex = SecretBytes([3; 32]).nex_address();
    let seller = Seller::new(terms.clone(), seller_nex, payout.clone(), payout.clone());
    let (buyer, actions) = Buyer::start(terms.clone(), payout, "buyer".into()).unwrap();
    let (_, actions) = seller.unwrap().step(Event::Message(sent(&actions)));
    let (buyer, actions) = buyer.step(Event::Message(sent(&actions)));
    let [Action::FundLock {
        script_pubkey,
        amount,
    }] = &actions[..]
    else {
        panic!("fund the lock: {actions:?}");
    };
    let refused = wallet.fund_lock(script_pubkey, *amount, None).unwrap_err();
    assert!(refused.to_string().contains("Fallbackfee"), "{refused}");

    let directory = tempfile::tempdir().unwrap();
    let store = Store::new(directory.path(), terms.swap_id);
    let client = Client::new("http://127.0.0.1:9", "", Duration::from_secs(1));
    let mut driver = Driver::<_, _, Ivy>::start(buyer, actions, wallet, client, None, store);
    let driver = driver.as_mut().unwrap();
    let Buyer::AwaitSellerSignatures { funding, .. } = driver.state() else {
        panic!("funded: {:?}", serde_json::to_value(driver.state()));
    };
    let rpc = rpc(&node, "default");
    let accepted = rpc
        .call("testmempoolaccept", json!([[serialize_hex(funding)]]))
        .unwrap();
    assert_eq!(accepted[0]["allowed"], true, "{accepted}");
    let fee = Amount::from_btc(accepted[0]["fees"]["base"].as_f64().unwrap()).unwrap();
    let vsize = accepted[0]["vsize"].as_u64().unwrap();
    let rate = fee.to_sat() as f64 / vsize as f64;
    assert!(
        (9.9..11.0).contains(&rate),
        "{rate} sat/vB, not the fallback 10"
    );
}
