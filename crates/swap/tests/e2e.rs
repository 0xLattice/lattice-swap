//! Whole swaps: a seller and a buyer in this process, each on its own
//! thread, talking over an ivy session on localhost, against a regtest
//! bitcoind and a lattice-node in Docker. The test, not the parties, mines
//! blocks on both chains.
//!
//! Ignored by a plain `cargo test`; run with `NEXUS_NODE_IMAGE` naming the
//! node image and `-- --ignored`. The node's RPC listens on loopback only,
//! so its container shares the host's network.

use std::net::TcpListener;
use std::process::Command;
use std::sync::{Arc, Mutex};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use bitcoin::address::NetworkUnchecked;
use bitcoin::{Address, Amount, Denomination, FeeRate, Network, ScriptBuf};
use corepc_node::{Conf, Node};
use ed25519_dalek::SigningKey;
use rand_core::{OsRng, RngCore};
use serde_json::{json, Value};
use swap::bitcoind::Bitcoind;
use swap::driver::{Driver, Store};
use swap::transport::{Ivy, PeerKey};
use swap::{Buyer, Outcome, SecretBytes, Seller, Terms};
use swap_nexus_tx::rpc::Client;
use swap_nexus_tx::{address, Transaction, TransactionBody};

const TIMEOUT: Duration = Duration::from_secs(10);
/// Nexus's block reward over its first halving interval.
const REWARD: u64 = 1_048_576;
const BTC_AMOUNT: Amount = Amount::from_sat(50_000_000);
const BTC_FEE: Amount = Amount::from_sat(1_000);
const NEX_AMOUNT: u64 = 1_000_000;
/// What the buyer's wallet starts with.
const BUYER_BTC: Amount = Amount::ONE_BTC;

/// Below every swap transaction's own feerate, as the fallback for
/// regtest's missing estimate and as the cap: nothing is bumped, and each
/// costs exactly `BTC_FEE`.
const NO_BUMP: FeeRate = FeeRate::from_sat_per_vb_u32(1);

fn random32() -> [u8; 32] {
    let mut bytes = [0u8; 32];
    OsRng.fill_bytes(&mut bytes);
    bytes
}

fn free_port() -> u16 {
    TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

fn wait_for<T>(what: &str, mut poll: impl FnMut() -> Option<T>) -> T {
    let deadline = Instant::now() + Duration::from_secs(120);
    loop {
        if let Some(value) = poll() {
            return value;
        }
        assert!(Instant::now() < deadline, "timed out waiting for {what}");
        thread::sleep(Duration::from_millis(250));
    }
}

/// A lattice-node in Docker, as in swap-nexus-tx's node test.
struct Nexus {
    container: String,
    url: String,
    cookie: String,
}

impl Nexus {
    fn start() -> Self {
        let image =
            std::env::var("NEXUS_NODE_IMAGE").expect("NEXUS_NODE_IMAGE names the node image");
        let (rpc, p2p) = (free_port(), free_port());
        let script = format!(
            "lattice-node --data-directory /tmp/d --identity-key /tmp/p.key \
             --listen-port {p2p} --rpc-port {rpc} --websocket-port 0 --no-default-peers"
        );
        let out = Command::new("docker")
            .args([
                "run",
                "-d",
                "--network",
                "host",
                "--platform",
                "linux/amd64",
            ])
            .args(["--entrypoint", "sh", &image, "-c", &script])
            .output()
            .unwrap();
        assert!(
            out.status.success(),
            "{}",
            String::from_utf8_lossy(&out.stderr)
        );
        // Built first, so the container goes even if the node never starts.
        let mut nexus = Nexus {
            container: String::from_utf8(out.stdout).unwrap().trim().to_string(),
            url: format!("http://127.0.0.1:{rpc}"),
            cookie: String::new(),
        };
        nexus.cookie = wait_for("node cookie", || {
            let out = Command::new("docker")
                .args(["exec", &nexus.container, "cat", "/tmp/d/.cookie"])
                .output()
                .unwrap();
            out.status
                .success()
                .then(|| String::from_utf8(out.stdout).unwrap())
        });
        wait_for("node RPC", || nexus.client().min_relay_fee().ok());
        nexus
    }

    fn client(&self) -> Client {
        Client::new(&self.url, &self.cookie, TIMEOUT)
    }

    fn balance(&self, address: &str) -> u64 {
        self.client().account(address).unwrap().balance
    }

    /// Transactions waiting in the node's pool.
    fn pending(&self) -> u64 {
        let token = base64_cookie(&self.cookie);
        let json: Value = ureq::get(&format!("{}/api/mempool", self.url))
            .set("Authorization", &format!("Basic {token}"))
            .timeout(TIMEOUT)
            .call()
            .unwrap()
            .into_json()
            .unwrap();
        match &json["count"] {
            Value::String(count) => count.parse().unwrap(),
            count => count.as_u64().expect("a count"),
        }
    }

    /// Mines one block, paying its reward and fees to `recipient` or, with
    /// `None`, burning them, and waits until the node executes it.
    fn mine(&self, recipient: Option<&str>) {
        let client = self.client();
        let height = client.health().unwrap().height;
        let mut args: Vec<String> = [
            "exec",
            &self.container,
            "lattice-mining-coordinator",
            "--node",
            &self.url,
            "--rpc-cookie-file",
            "/tmp/d/.cookie",
            "--workers",
            "1",
            "--batch-size",
            "1000",
            "--once",
        ]
        .map(String::from)
        .to_vec();
        if let Some(address) = recipient {
            args.extend(["--recipient".into(), format!("Nexus={address}")]);
        }
        wait_for("a mined block", || {
            if client.health().unwrap().height > height {
                return Some(());
            }
            let out = Command::new("docker").args(&args).output().unwrap();
            assert!(
                out.status.success(),
                "{}",
                String::from_utf8_lossy(&out.stderr)
            );
            None
        });
    }
}

impl Drop for Nexus {
    fn drop(&mut self) {
        let _ = Command::new("docker")
            .args(["rm", "-f", &self.container])
            .output();
    }
}

fn base64_cookie(cookie: &str) -> String {
    use base64::Engine;
    base64::engine::general_purpose::STANDARD.encode(cookie.trim())
}

/// Both chains, and the parties' wallets and keys for one swap.
struct World {
    bitcoind: Node,
    miner: Address,
    nexus: Nexus,
    directory: tempfile::TempDir,
    terms: Terms,
    seller_nex: SecretBytes,
    buyer_nex: String,
    seller_wallet: Bitcoind,
    buyer_wallet: Bitcoind,
}

/// How the test mines Bitcoin while a scenario runs.
#[derive(Clone, Copy)]
enum Pace {
    /// A block whenever the mempool holds something: time stands still
    /// otherwise.
    OnDemand,
    /// A block every round: time passes.
    Steady,
}

impl World {
    /// `seller_blocks` Nexus blocks pay the seller.
    fn new(seller_blocks: usize) -> Self {
        let mut conf = Conf::default();
        conf.args.push("-txindex");
        let bitcoind = Node::from_downloaded_with_conf(&conf).expect("start bitcoind");
        let miner = bitcoind.client.new_address().unwrap();
        bitcoind.client.generate_to_address(101, &miner).unwrap();
        let nexus = Nexus::start();

        let seller_nex = SecretBytes(random32());
        for _ in 0..seller_blocks {
            nexus.mine(Some(&seller_nex.nex_address()));
        }
        let buyer_nex = address(
            &SigningKey::from_bytes(&random32())
                .verifying_key()
                .to_bytes(),
        );

        let mut world = World {
            seller_wallet: wallet(&bitcoind, "seller"),
            buyer_wallet: wallet(&bitcoind, "buyer"),
            bitcoind,
            miner,
            nexus,
            directory: tempfile::tempdir().unwrap(),
            terms: Terms {
                swap_id: random32(),
                btc_amount: BTC_AMOUNT,
                btc_fee: BTC_FEE,
                nex_amount: NEX_AMOUNT,
                nex_fee: 0,
                t1: 20,
                t2: 10,
                btc_confirmations: 1,
                nex_confirmations: 1,
                margin: 3,
            },
            seller_nex,
            buyer_nex,
        };
        world.terms.nex_fee = world.nexus.client().min_relay_fee().unwrap();
        let buyer = world.address(&world.buyer_wallet);
        world
            .bitcoind
            .client
            .send_to_address(&buyer, BUYER_BTC)
            .unwrap();
        world.mine_btc(1);
        assert_eq!(btc_balance(&world.buyer_wallet), BUYER_BTC);
        world
    }

    fn address(&self, wallet: &Bitcoind) -> Address {
        let address = wallet.call("getnewaddress", json!([])).unwrap();
        let address: Address<NetworkUnchecked> = address.as_str().unwrap().parse().unwrap();
        address.assume_checked()
    }

    fn script(&self, wallet: &Bitcoind) -> ScriptBuf {
        self.address(wallet).script_pubkey()
    }

    fn mine_btc(&self, blocks: usize) {
        self.bitcoind
            .client
            .generate_to_address(blocks, &self.miner)
            .unwrap();
    }

    fn bitcoin(&self, wallet: &str) -> Bitcoind {
        wallet_client(&self.bitcoind, wallet)
    }

    fn store(&self, party: &str) -> Store {
        let directory = self.directory.path().join(party);
        std::fs::create_dir_all(&directory).unwrap();
        Store::new(&directory, self.terms.swap_id)
    }

    /// Mines until `done`: Bitcoin at `pace`, Nexus whenever its pool holds
    /// something and `nexus` is set.
    fn drive(&self, pace: Pace, nexus: bool, done: impl Fn() -> bool) {
        let deadline = Instant::now() + Duration::from_secs(600);
        while !done() {
            assert!(Instant::now() < deadline, "the scenario timed out");
            let mempool = bitcoind_call(&self.bitcoind, "getmempoolinfo", json!([]));
            if matches!(pace, Pace::Steady) || mempool["size"].as_u64() > Some(0) {
                self.mine_btc(1);
            }
            if nexus && self.nexus.pending() > 0 {
                self.nexus.mine(None);
            }
            thread::sleep(Duration::from_millis(400));
        }
    }

    /// The fee the buyer's wallet paid to fund the lock.
    fn funding_fee(&self) -> Amount {
        let sends = self
            .buyer_wallet
            .call("listtransactions", json!(["*", 100]))
            .unwrap();
        let fees: Vec<f64> = sends
            .as_array()
            .unwrap()
            .iter()
            .filter(|tx| tx["category"] == "send")
            .map(|tx| tx["fee"].as_f64().unwrap())
            .collect();
        assert_eq!(fees.len(), 1, "one payment: the funding transaction");
        Amount::from_float_in(-fees[0], Denomination::Bitcoin).unwrap()
    }
}

fn bitcoind_call(node: &Node, method: &str, params: Value) -> Value {
    wallet_client(node, "").call(method, params).unwrap()
}

fn wallet_client(node: &Node, wallet: &str) -> Bitcoind {
    let cookie = std::fs::read_to_string(&node.params.cookie_file).unwrap();
    let url = match wallet {
        "" => node.rpc_url(),
        wallet => node.rpc_url_with_wallet(wallet),
    };
    Bitcoind::new(&url, &cookie, Network::Regtest, TIMEOUT)
}

fn wallet(node: &Node, name: &str) -> Bitcoind {
    node.create_wallet(name).unwrap();
    wallet_client(node, name)
}

/// The wallet's confirmed balance.
fn btc_balance(wallet: &Bitcoind) -> Amount {
    let balances = wallet.call("getbalances", json!([])).unwrap();
    let trusted = balances["mine"]["trusted"].as_f64().unwrap();
    Amount::from_float_in(trusted, Denomination::Bitcoin).unwrap()
}

type Party<M> = JoinHandle<(Option<Outcome>, M)>;

/// The two ends of an ivy session about to be opened.
struct Session {
    listener: TcpListener,
    seller: ivy::Config,
    buyer: ivy::Config,
}

impl Session {
    fn new() -> Self {
        Session {
            listener: TcpListener::bind("127.0.0.1:0").unwrap(),
            seller: ivy::Config::new(SigningKey::from_bytes(&random32())),
            buyer: ivy::Config::new(SigningKey::from_bytes(&random32())),
        }
    }
}

fn seller_peer(session: &Session) -> PeerKey {
    session.seller.peer_key()
}

/// Runs the seller until it ends or `stop` holds.
fn spawn_seller(
    world: &World,
    listener: TcpListener,
    config: ivy::Config,
    buyer: PeerKey,
    stop: impl Fn(&Seller) -> bool + Send + 'static,
) -> Party<Seller> {
    let seller = Seller::new(
        world.terms.clone(),
        world.seller_nex.nex_address(),
        world.script(&world.seller_wallet),
        world.script(&world.seller_wallet),
    )
    .unwrap();
    let (bitcoin, nexus, store) = (
        world.bitcoin("seller"),
        world.nexus.client(),
        world.store("seller"),
    );
    let key = world.seller_nex.clone();
    thread::spawn(move || {
        let transport = Ivy::accept(listener, &config, buyer, TIMEOUT * 6, TIMEOUT).unwrap();
        let mut driver =
            Driver::start(seller, vec![], bitcoin, nexus, Some(transport), store).unwrap();
        driver.nex_key = Some(key);
        driver.fallback_fee_rate = NO_BUMP;
        driver.max_fee_rate = NO_BUMP;
        let outcome = driver.run_until(stop).unwrap();
        (outcome, driver.state().clone())
    })
}

/// Runs the buyer until it ends or `stop` holds.
fn spawn_buyer(
    world: &World,
    seller: (std::net::SocketAddr, PeerKey),
    config: ivy::Config,
    stop: impl Fn(&Buyer) -> bool + Send + 'static,
) -> Party<Buyer> {
    let (buyer, actions) = Buyer::start(
        world.terms.clone(),
        world.script(&world.buyer_wallet),
        world.buyer_nex.clone(),
    )
    .unwrap();
    let (bitcoin, nexus, store) = (
        world.bitcoin("buyer"),
        world.nexus.client(),
        world.store("buyer"),
    );
    thread::spawn(move || {
        let transport = Ivy::connect(seller.0, &config, seller.1, TIMEOUT).unwrap();
        let mut driver =
            Driver::start(buyer, actions, bitcoin, nexus, Some(transport), store).unwrap();
        driver.fallback_fee_rate = NO_BUMP;
        driver.max_fee_rate = NO_BUMP;
        let outcome = driver.run_until(stop).unwrap();
        (outcome, driver.state().clone())
    })
}

/// The buyer brought back from its state file, with no session.
fn resume_buyer(world: &World) -> Party<Buyer> {
    let (bitcoin, nexus, store) = (
        world.bitcoin("buyer"),
        world.nexus.client(),
        world.store("buyer"),
    );
    thread::spawn(move || {
        let mut driver = Driver::<Buyer, _, Ivy>::resume(bitcoin, nexus, None, store).unwrap();
        driver.fallback_fee_rate = NO_BUMP;
        driver.max_fee_rate = NO_BUMP;
        let outcome = driver.run().unwrap();
        (Some(outcome), driver.state().clone())
    })
}

/// Starts both parties. `buyer_stop` ends the buyer early, as if killed.
/// Returns them and a slot that learns the lock address.
fn start(
    world: &World,
    buyer_stop: impl Fn(&Buyer) -> bool + Send + 'static,
) -> (Party<Seller>, Party<Buyer>, Arc<Mutex<Option<String>>>) {
    let session = Session::new();
    let seller_at = (
        session.listener.local_addr().unwrap(),
        seller_peer(&session),
    );
    let buyer_key = session.buyer.peer_key();
    let seller = spawn_seller(world, session.listener, session.seller, buyer_key, |_| {
        false
    });
    let lock = Arc::new(Mutex::new(None));
    let slot = lock.clone();
    let buyer = spawn_buyer(world, seller_at, session.buyer, move |state| {
        if let Some(address) = state.lock_address() {
            slot.lock().unwrap().get_or_insert(address);
        }
        buyer_stop(state)
    });
    (seller, buyer, lock)
}

fn finished<M>(party: &Party<M>) -> bool {
    party.is_finished()
}

fn outcome<M>(party: Party<M>) -> (Option<Outcome>, M) {
    party.join().expect("the party ran to the end")
}

fn lock_address(slot: &Arc<Mutex<Option<String>>>) -> String {
    slot.lock()
        .unwrap()
        .clone()
        .expect("the buyer learned the lock address")
}

#[test]
#[ignore = "needs Docker and NEXUS_NODE_IMAGE"]
fn happy_path() {
    let world = World::new(2);
    let (seller, buyer, lock) = start(&world, |_| false);
    world.drive(Pace::OnDemand, true, || {
        finished(&seller) && finished(&buyer)
    });
    assert_eq!(outcome(seller).0, Some(Outcome::Swapped));
    assert_eq!(outcome(buyer).0, Some(Outcome::Swapped));

    let fee = world.terms.nex_fee;
    let n = &world.nexus;
    assert_eq!(n.balance(&world.buyer_nex), NEX_AMOUNT - fee);
    assert_eq!(
        n.balance(&world.seller_nex.nex_address()),
        2 * REWARD - NEX_AMOUNT - fee
    );
    assert_eq!(n.balance(&lock_address(&lock)), 0);
    assert_eq!(btc_balance(&world.seller_wallet), BTC_AMOUNT - BTC_FEE);
    assert_eq!(
        btc_balance(&world.buyer_wallet),
        BUYER_BTC - BTC_AMOUNT - world.funding_fee()
    );
}

#[test]
#[ignore = "needs Docker and NEXUS_NODE_IMAGE"]
fn seller_never_locks_nex() {
    // The seller holds no NEX: its node refuses the lock every time.
    let world = World::new(0);
    let (seller, buyer, lock) = start(&world, |_| false);
    world.drive(Pace::Steady, true, || finished(&buyer));
    assert_eq!(outcome(buyer).0, Some(Outcome::Refunded));
    // The seller signed a lock at nonce 0, so it cannot tell it will never
    // land, and keeps the shares to claim it, until its nonce moves on and
    // stays moved `nex_confirmations` blocks.
    assert!(!finished(&seller));
    let n = &world.nexus;
    let seller_nex = world.seller_nex.nex_address();
    n.mine(Some(&seller_nex));
    let fee = world.terms.nex_fee;
    let elsewhere = address(&[9; 32]);
    let body = TransactionBody::transfer(&seller_nex, &elsewhere, 1, fee, 0).unwrap();
    let mut spend = Transaction::new(body);
    spend.sign(&SigningKey::from_bytes(&world.seller_nex.0));
    n.client().submit(&spend).unwrap();
    // The seller ends only once that spend has stayed mined while the tip
    // moved `nex_confirmations` blocks, so Nexus mines with an empty pool.
    wait_for("the seller to end", || {
        if finished(&seller) {
            return Some(());
        }
        n.mine(None);
        None
    });
    assert_eq!(outcome(seller).0, Some(Outcome::Refunded));

    assert_eq!(n.balance(&world.buyer_nex), 0);
    assert_eq!(n.balance(&seller_nex), REWARD - 1 - fee);
    assert_eq!(n.balance(&lock_address(&lock)), 0);
    assert_eq!(btc_balance(&world.seller_wallet), Amount::ZERO);
    assert_eq!(
        btc_balance(&world.buyer_wallet),
        BUYER_BTC - world.funding_fee() - BTC_FEE * 2
    );
}

#[test]
#[ignore = "needs Docker and NEXUS_NODE_IMAGE"]
fn buyer_never_sends_redeem_signature() {
    let world = World::new(2);
    let (seller, buyer, lock) = start(&world, |_| false);
    // Nexus stalls with the lock still pending, so the seller never names
    // it and the buyer never signs: it cancels and refunds at t1.
    world.drive(Pace::Steady, false, || finished(&buyer));
    assert_eq!(outcome(buyer).0, Some(Outcome::Refunded));
    // Nexus moves again; the seller, which learned `b` from the refund,
    // claims its NEX back.
    world.drive(Pace::OnDemand, true, || finished(&seller));
    assert_eq!(outcome(seller).0, Some(Outcome::Refunded));

    let fee = world.terms.nex_fee;
    let n = &world.nexus;
    assert_eq!(n.balance(&world.buyer_nex), 0);
    assert_eq!(
        n.balance(&world.seller_nex.nex_address()),
        2 * REWARD - 2 * fee
    );
    assert_eq!(n.balance(&lock_address(&lock)), 0);
    assert_eq!(btc_balance(&world.seller_wallet), Amount::ZERO);
    assert_eq!(
        btc_balance(&world.buyer_wallet),
        BUYER_BTC - world.funding_fee() - BTC_FEE * 2
    );
}

#[test]
#[ignore = "needs Docker and NEXUS_NODE_IMAGE"]
fn buyer_offline_after_the_lock_is_punished() {
    let world = World::new(2);
    let (seller, buyer, lock) = start(&world, |state| matches!(state, Buyer::AwaitNexLock { .. }));
    world.drive(Pace::Steady, true, || finished(&seller));
    assert_eq!(outcome(seller).0, Some(Outcome::Punished));
    assert_eq!(outcome(buyer).0, None, "the buyer went offline");
    // Back online, the buyer finds it was punished.
    let buyer = resume_buyer(&world);
    world.drive(Pace::OnDemand, false, || finished(&buyer));
    assert_eq!(outcome(buyer).0, Some(Outcome::Punished));

    let fee = world.terms.nex_fee;
    let n = &world.nexus;
    assert_eq!(n.balance(&world.buyer_nex), 0);
    assert_eq!(
        n.balance(&world.seller_nex.nex_address()),
        2 * REWARD - NEX_AMOUNT - fee
    );
    // Neither party can ever move it: nobody learned the other's share.
    assert_eq!(n.balance(&lock_address(&lock)), NEX_AMOUNT);
    assert_eq!(btc_balance(&world.seller_wallet), BTC_AMOUNT - BTC_FEE * 2);
    assert_eq!(
        btc_balance(&world.buyer_wallet),
        BUYER_BTC - BTC_AMOUNT - world.funding_fee()
    );
}

#[test]
#[ignore = "needs Docker and NEXUS_NODE_IMAGE"]
fn buyer_restarts_from_its_state_file() {
    let world = World::new(2);
    // Killed right after sending its redeem signature.
    let (seller, buyer, lock) = start(&world, |state| matches!(state, Buyer::AwaitRedeem { .. }));
    world.drive(Pace::OnDemand, true, || finished(&seller));
    assert_eq!(outcome(seller).0, Some(Outcome::Swapped));
    let (stopped, state) = outcome(buyer);
    assert_eq!(stopped, None);
    assert!(matches!(state, Buyer::AwaitRedeem { .. }));

    // Restored from disk, it finds the redeem on chain and claims.
    let buyer = resume_buyer(&world);
    world.drive(Pace::OnDemand, true, || finished(&buyer));
    assert_eq!(outcome(buyer).0, Some(Outcome::Swapped));

    let fee = world.terms.nex_fee;
    let n = &world.nexus;
    assert_eq!(n.balance(&world.buyer_nex), NEX_AMOUNT - fee);
    assert_eq!(
        n.balance(&world.seller_nex.nex_address()),
        2 * REWARD - NEX_AMOUNT - fee
    );
    assert_eq!(n.balance(&lock_address(&lock)), 0);
    assert_eq!(btc_balance(&world.seller_wallet), BTC_AMOUNT - BTC_FEE);
    assert_eq!(
        btc_balance(&world.buyer_wallet),
        BUYER_BTC - BTC_AMOUNT - world.funding_fee()
    );
}
