//! Whole swaps: a seller and a buyer in this process, each on its own
//! thread, talking over an ivy session on localhost, against a regtest
//! bitcoind and a lattice-node in Docker. The test, not the parties, mines
//! blocks on both chains.
//!
//! Ignored by a plain `cargo test`; run with `NEXUS_NODE_IMAGE` naming the
//! node image and `-- --ignored`. The node's RPC listens on loopback only,
//! so its container shares the host's network.

use std::cell::Cell;
use std::net::TcpListener;
use std::process::Command;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use bitcoin::address::NetworkUnchecked;
use bitcoin::{Address, Amount, Denomination, FeeRate, Network, ScriptBuf, Txid};
use corepc_node::{Conf, Node};
use ed25519_dalek::SigningKey;
use rand_core::{OsRng, RngCore};
use serde_json::{json, Value};
use swap::bitcoind::{Bitcoin, Bitcoind};
use swap::driver::{Driver, Store};
use swap::transport::{Ivy, PeerKey};
use swap::{Buyer, Machine, Outcome, SecretBytes, Seller, Terms};
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
/// costs exactly `BTC_FEE`, but redeem, which pays two.
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

/// A lattice-node in Docker, as in swap-nexus-tx's node test. Its cookie
/// is copied out to `cookie_file`, which the parties' clients read again
/// when the node refuses theirs, as they would a mounted data directory.
/// It dials no one but the peer named in `/tmp/peer`, if any, so a test
/// can partition two nodes and join them again.
struct Nexus {
    container: String,
    p2p: u16,
    url: String,
    cookie: String,
    cookie_file: tempfile::NamedTempFile,
}

impl Nexus {
    fn start() -> Self {
        let image =
            std::env::var("NEXUS_NODE_IMAGE").expect("NEXUS_NODE_IMAGE names the node image");
        let (rpc, p2p) = (free_port(), free_port());
        let script = format!(
            "exec lattice-node --data-directory /tmp/d --identity-key /tmp/p.key \
             --listen-port {p2p} --rpc-port {rpc} --websocket-port 0 --no-default-peers \
             --peer-target 0 --peer-search-interval 0 $(cat /tmp/peer 2>/dev/null)"
        );
        let out = Command::new("docker")
            .args([
                "run",
                "-d",
                // Forwards `docker stop`'s SIGTERM to the node.
                "--init",
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
            p2p,
            url: format!("http://127.0.0.1:{rpc}"),
            cookie: String::new(),
            cookie_file: tempfile::NamedTempFile::new().unwrap(),
        };
        nexus.copy_cookie();
        nexus
    }

    /// Waits for a cookie other than the one held, copies it out, and waits
    /// for the RPC to take it.
    fn copy_cookie(&mut self) {
        let old = std::mem::take(&mut self.cookie);
        self.cookie = wait_for("node cookie", || {
            let out = Command::new("docker")
                .args(["exec", &self.container, "cat", "/tmp/d/.cookie"])
                .output()
                .unwrap();
            let cookie = String::from_utf8(out.stdout).unwrap();
            (out.status.success() && !cookie.is_empty() && cookie != old).then_some(cookie)
        });
        std::fs::write(self.cookie_file.path(), &self.cookie).unwrap();
        wait_for("node RPC", || self.client().min_relay_fee().ok());
    }

    /// Stops the node with SIGTERM, as an operator's `docker stop` does,
    /// and starts it again. It keeps its chain and writes a new cookie.
    fn restart(&mut self) {
        let docker = |args: &[&str]| {
            let out = Command::new("docker").args(args).output().unwrap();
            assert!(
                out.status.success(),
                "{}",
                String::from_utf8_lossy(&out.stderr)
            );
            String::from_utf8(out.stdout).unwrap()
        };
        docker(&["stop", "--time", "30", &self.container]);
        let code = docker(&[
            "inspect",
            "--format",
            "{{.State.ExitCode}}",
            &self.container,
        ]);
        assert_ne!(code.trim(), "137", "the node ended on SIGTERM, not SIGKILL");
        docker(&["start", &self.container]);
        self.copy_cookie();
    }

    /// Restarts the node peered with `with` alone, or, with `None`, with
    /// no one: a partition.
    fn peer(&mut self, with: Option<&Nexus>) {
        let peer = with.map_or(String::new(), |other| {
            format!("--peer {}@127.0.0.1:{}", other.peer_key(), other.p2p)
        });
        let write = format!("echo '{peer}' > /tmp/peer");
        let out = Command::new("docker")
            .args(["exec", &self.container, "sh", "-c", &write])
            .output()
            .unwrap();
        assert!(out.status.success());
        self.restart();
    }

    /// The node's overlay key, from its identity key.
    fn peer_key(&self) -> String {
        let out = Command::new("docker")
            .args(["exec", &self.container, "cat", "/tmp/p.key"])
            .output()
            .unwrap();
        let secret: [u8; 32] = hex::decode(String::from_utf8(out.stdout).unwrap().trim())
            .unwrap()
            .try_into()
            .unwrap();
        hex::encode(SigningKey::from_bytes(&secret).verifying_key().to_bytes())
    }

    /// The block the node acts on.
    fn tip(&self) -> Option<String> {
        self.client().health().unwrap().tip
    }

    /// Waits until the node acts on `other`'s tip.
    fn follow(&self, other: &Nexus) {
        wait_for("the nodes to agree", || {
            let tip = other.tip();
            (tip.is_some() && self.tip() == tip).then_some(())
        });
    }

    /// Mines until the node is two blocks past `other`'s height: a
    /// heavier branch, the blocks here all costing about the same work.
    fn outmine(&self, other: &Nexus) {
        let height = other.client().health().unwrap().height;
        while self.client().health().unwrap().height < height + 2 {
            self.mine(None);
        }
    }

    fn client(&self) -> Client {
        Client::from_cookie_file(&self.url, self.cookie_file.path(), TIMEOUT)
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
    /// The most the seller's driver bumps to: `NO_BUMP` unless a test needs
    /// a bump.
    seller_max_fee_rate: FeeRate,
    /// How much less NEX than `nex_amount` the seller locks: a seller that
    /// agreed to less than the buyer, or cheats.
    short_lock: u64,
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
        Self::with_args(seller_blocks, &[])
    }

    /// [`World::new`], bitcoind started with `args`.
    fn with_args(seller_blocks: usize, args: &[&'static str]) -> Self {
        let mut conf = Conf::default();
        conf.args.push("-txindex");
        conf.args.extend(args);
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
                nexus_genesis: swap_nexus_tx::MAINNET_GENESIS.into(),
            },
            seller_nex,
            buyer_nex,
            seller_max_fee_rate: NO_BUMP,
            short_lock: 0,
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

    /// A block with none of the mempool in it: a miner leaving it out.
    fn mine_empty(&self) {
        bitcoind_call(
            &self.bitcoind,
            "generateblock",
            json!([self.miner.to_string(), []]),
        );
    }

    /// Takes the tip block away, its transactions back to the mempool;
    /// returns its hash and the one transaction in it but the coinbase.
    fn reorg_out_tip(&self) -> (String, Txid) {
        let tip = bitcoind_call(&self.bitcoind, "getbestblockhash", json!([]));
        let block = bitcoind_call(&self.bitcoind, "getblock", json!([tip]));
        let txs = block["tx"].as_array().unwrap();
        assert_eq!(txs.len(), 2, "the coinbase and one spend: {block}");
        let tx = txs[1].as_str().unwrap().parse().unwrap();
        bitcoind_call(&self.bitcoind, "invalidateblock", json!([tip]));
        (tip.as_str().unwrap().into(), tx)
    }

    fn pooled(&self, txid: Txid) -> bool {
        wallet_client(&self.bitcoind, "")
            .call("getmempoolentry", json!([txid.to_string()]))
            .is_ok()
    }

    /// The transactions in the mempool.
    fn mempool(&self) -> Vec<Txid> {
        let pool = bitcoind_call(&self.bitcoind, "getrawmempool", json!([]));
        let txids = pool.as_array().unwrap().iter();
        txids
            .map(|txid| txid.as_str().unwrap().parse().unwrap())
            .collect()
    }

    /// Drops every transaction in the mempool, as a node started with
    /// `-mempoolexpiry=1` drops those an hour old: its clock jumps two hours
    /// ahead, and the next transaction it takes expires them.
    fn expire_mempool(&self) {
        let chain = bitcoind_call(&self.bitcoind, "getblockchaininfo", json!([]));
        let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap();
        let time = now.as_secs().max(chain["time"].as_u64().unwrap()) + 2 * 3600;
        bitcoind_call(&self.bitcoind, "setmocktime", json!([time]));
        let pooled = self.mempool();
        self.bitcoind
            .client
            .send_to_address(&self.miner, Amount::from_sat(10_000))
            .unwrap();
        assert!(pooled.iter().all(|txid| !self.pooled(*txid)), "expired");
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
    let mut terms = world.terms.clone();
    terms.nex_amount -= world.short_lock;
    let seller = Seller::new(
        terms,
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
    let (key, max_fee_rate) = (world.seller_nex.clone(), world.seller_max_fee_rate);
    thread::spawn(move || {
        let transport = Ivy::accept(listener, &config, buyer, TIMEOUT * 6, TIMEOUT).unwrap();
        let mut driver =
            Driver::start(seller, vec![], bitcoin, nexus, Some(transport), store).unwrap();
        driver.nex_key = Some(key);
        driver.fallback_fee_rate = NO_BUMP;
        driver.max_fee_rate = max_fee_rate;
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

/// [`resume_buyer`], `watch` shown every state it steps to.
fn resume_buyer_watched(world: &World, watch: impl Fn(&Buyer) + Send + 'static) -> Party<Buyer> {
    let (bitcoin, nexus, store) = (
        world.bitcoin("buyer"),
        world.nexus.client(),
        world.store("buyer"),
    );
    thread::spawn(move || {
        let mut driver = Driver::<Buyer, _, Ivy>::resume(bitcoin, nexus, None, store).unwrap();
        driver.fallback_fee_rate = NO_BUMP;
        driver.max_fee_rate = NO_BUMP;
        let outcome = driver
            .run_until(|state| {
                watch(state);
                false
            })
            .unwrap();
        (outcome, driver.state().clone())
    })
}

/// The seller brought back from its state file, with no session.
fn resume_seller(world: &World) -> Party<Seller> {
    let (bitcoin, nexus, store) = (
        world.bitcoin("seller"),
        world.nexus.client(),
        world.store("seller"),
    );
    let (key, max_fee_rate) = (world.seller_nex.clone(), world.seller_max_fee_rate);
    thread::spawn(move || {
        let mut driver = Driver::<Seller, _, Ivy>::resume(bitcoin, nexus, None, store).unwrap();
        driver.nex_key = Some(key);
        driver.fallback_fee_rate = NO_BUMP;
        driver.max_fee_rate = max_fee_rate;
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
    start_with(world, |_| false, buyer_stop)
}

/// [`start`], `seller_stop` ending the seller early.
fn start_with(
    world: &World,
    seller_stop: impl Fn(&Seller) -> bool + Send + 'static,
    buyer_stop: impl Fn(&Buyer) -> bool + Send + 'static,
) -> (Party<Seller>, Party<Buyer>, Arc<Mutex<Option<String>>>) {
    let session = Session::new();
    let seller_at = (
        session.listener.local_addr().unwrap(),
        seller_peer(&session),
    );
    let buyer_key = session.buyer.peer_key();
    let seller = spawn_seller(
        world,
        session.listener,
        session.seller,
        buyer_key,
        seller_stop,
    );
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
    assert_eq!(btc_balance(&world.seller_wallet), BTC_AMOUNT - BTC_FEE * 2);
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
    // The seller stops once punished, where it would wait to give `s`.
    let (seller, buyer, lock) = start_with(
        &world,
        |state| matches!(state, Seller::Punished { .. }),
        |state| matches!(state, Buyer::AwaitNexLock { .. }),
    );
    world.drive(Pace::Steady, true, || finished(&seller));
    assert!(matches!(outcome(seller).1, Seller::Punished { .. }));
    assert_eq!(outcome(buyer).0, None, "the buyer went offline");
    // Back online, the buyer finds it was punished, and with no seller to
    // ask for `s`, its run ends so.
    let buyer = resume_buyer(&world);
    world.drive(Pace::OnDemand, false, || finished(&buyer));
    let (ended, state) = outcome(buyer);
    assert_eq!(ended, Some(Outcome::Punished));
    assert!(matches!(state, Buyer::Punished { .. }), "its secrets kept");

    let fee = world.terms.nex_fee;
    let n = &world.nexus;
    assert_eq!(n.balance(&world.buyer_nex), 0);
    assert_eq!(
        n.balance(&world.seller_nex.nex_address()),
        2 * REWARD - NEX_AMOUNT - fee
    );
    // Nobody learned the other's share: the NEX stays until the seller
    // gives `s`.
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
    assert_eq!(btc_balance(&world.seller_wallet), BTC_AMOUNT - BTC_FEE * 2);
    assert_eq!(
        btc_balance(&world.buyer_wallet),
        BUYER_BTC - BTC_AMOUNT - world.funding_fee()
    );
}

#[test]
#[ignore = "needs Docker and NEXUS_NODE_IMAGE"]
fn a_refund_reorged_out_past_t2_loses_to_the_punish() {
    let mut world = World::new(2);
    // Two confirmations, so the one-block reorg below is one the terms
    // allow for: a refund one block deep is not yet final.
    world.terms.btc_confirmations = 2;
    // The seller's driver bumps its punish as far as it takes to replace a
    // pending refund; the buyer's never above the refund's own feerate.
    world.seller_max_fee_rate = FeeRate::from_sat_per_vb_u32(50);
    // The seller goes offline as it gives up the redeem, so it never sees
    // the refund before `t2`.
    let (seller, buyer, lock) = start_with(
        &world,
        |state| matches!(state, Seller::Cancelling { .. }),
        |_| false,
    );
    // Nexus stalls with the lock pending; the buyer cancels at t1 and
    // refunds once cancel is two deep. Stopped as the refund is one deep.
    world.drive(Pace::Steady, false, || {
        finished(&seller) && btc_balance(&world.buyer_wallet) > BUYER_BTC - BTC_AMOUNT
    });
    assert!(matches!(outcome(seller).1, Seller::Cancelling { .. }));
    assert!(!finished(&buyer), "a refund one deep is not yet final");

    // The refund's block is reorged out, and a miner leaves the refund out
    // of every block until cancel is past `t2`.
    let (_, refund) = world.reorg_out_tip();
    for _ in 0..world.terms.t2 {
        world.mine_empty();
    }
    assert!(world.pooled(refund));
    // Back online, the seller learns `b` from the pending refund and
    // punishes, bumping its punish as a package that replaces the refund.
    let seller = resume_seller(&world);
    wait_for("the punish to replace the refund", || {
        (!world.pooled(refund)).then_some(())
    });
    // The buyer's refund cannot take the output back, and with no seller to
    // ask for `s`, it ends punished; the seller claims the NEX back with
    // `b` beside the punish.
    world.drive(Pace::Steady, true, || finished(&seller) && finished(&buyer));
    assert_eq!(outcome(seller).0, Some(Outcome::Punished));
    assert_eq!(outcome(buyer).0, Some(Outcome::Punished));

    let fee = world.terms.nex_fee;
    let n = &world.nexus;
    assert_eq!(n.balance(&world.buyer_nex), 0);
    assert_eq!(
        n.balance(&world.seller_nex.nex_address()),
        2 * REWARD - 2 * fee
    );
    assert_eq!(n.balance(&lock_address(&lock)), 0);
    // The punish's payout, less the child that bumped it.
    let punished = BTC_AMOUNT - BTC_FEE * 2;
    let seller_btc = btc_balance(&world.seller_wallet);
    assert!(
        seller_btc < punished && seller_btc > punished - Amount::from_sat(20_000),
        "{seller_btc}"
    );
    assert_eq!(
        btc_balance(&world.buyer_wallet),
        BUYER_BTC - BTC_AMOUNT - world.funding_fee()
    );
}

#[test]
#[ignore = "needs Docker and NEXUS_NODE_IMAGE"]
fn a_redeem_reorged_out_after_the_buyer_has_s_is_sent_again() {
    let mut world = World::with_args(2, &["-mempoolexpiry=1"]);
    // Two confirmations: a redeem one block deep is not yet final.
    world.terms.btc_confirmations = 2;
    // The seller goes offline once its redeem is out; the buyer learns `s`
    // from it and claims.
    let claiming = Arc::new(AtomicBool::new(false));
    let flag = claiming.clone();
    let (seller, buyer, lock) = start_with(
        &world,
        |state| matches!(state, Seller::Redeeming { seen: true, .. }),
        move |state| {
            if matches!(state, Buyer::ClaimingNex(_) | Buyer::Done(Outcome::Swapped)) {
                flag.store(true, Ordering::SeqCst);
            }
            false
        },
    );
    world.drive(Pace::Steady, true, || finished(&seller));
    assert!(matches!(
        outcome(seller).1,
        Seller::Redeeming { seen: true, .. }
    ));
    if !world.mempool().is_empty() {
        world.mine_btc(1);
    }
    // The buyer has `s` from the first redeem, before any reorg.
    wait_for("the buyer to claim", || {
        claiming.load(Ordering::SeqCst).then_some(())
    });

    // The redeem's block is reorged out, and the redeem dropped from the
    // mempool: only the seller can send it again.
    let (block, redeem) = world.reorg_out_tip();
    world.expire_mempool();
    let seller = resume_seller(&world);
    world.drive(Pace::Steady, true, || finished(&seller) && finished(&buyer));
    assert_eq!(outcome(seller).0, Some(Outcome::Swapped));
    assert_eq!(outcome(buyer).0, Some(Outcome::Swapped));
    let mined = bitcoind_call(
        &world.bitcoind,
        "getrawtransaction",
        json!([redeem.to_string(), 1]),
    );
    assert_ne!(mined["blockhash"].as_str(), Some(block.as_str()));
    assert!(mined["confirmations"].as_u64() >= Some(2), "{mined}");

    let fee = world.terms.nex_fee;
    let n = &world.nexus;
    assert_eq!(n.balance(&world.buyer_nex), NEX_AMOUNT - fee);
    assert_eq!(
        n.balance(&world.seller_nex.nex_address()),
        2 * REWARD - NEX_AMOUNT - fee
    );
    assert_eq!(n.balance(&lock_address(&lock)), 0);
    assert_eq!(btc_balance(&world.seller_wallet), BTC_AMOUNT - BTC_FEE * 2);
    assert_eq!(
        btc_balance(&world.buyer_wallet),
        BUYER_BTC - BTC_AMOUNT - world.funding_fee()
    );
}

/// Runs both parties until the redeem signature has passed and both go
/// offline: the buyer has sent it, the seller has broadcast its redeem.
/// The redeem is then dropped from the mempool, seen by no one, and at t1
/// the buyer, back, cancels. Returns the buyer, the lock address slot and
/// the redeem, with the cancel pending.
fn cancel_pending_after_the_redeem_dropped(
    world: &World,
) -> (Party<Buyer>, Arc<Mutex<Option<String>>>, Txid) {
    let (seller, buyer, lock) = start_with(
        world,
        |state| matches!(state, Seller::Redeeming { seen: true, .. }),
        |state| matches!(state, Buyer::AwaitRedeem { .. }),
    );
    // Bitcoin stands still once the NEX lock is submitted, so no block
    // takes the redeem; only Nexus moves.
    world.drive(Pace::OnDemand, false, || world.nexus.pending() > 0);
    wait_for("the redeem", || {
        if finished(&seller) && finished(&buyer) {
            return Some(());
        }
        if world.nexus.pending() > 0 {
            world.nexus.mine(None);
        }
        None
    });
    assert!(matches!(
        outcome(seller).1,
        Seller::Redeeming { seen: true, .. }
    ));
    assert!(matches!(outcome(buyer).1, Buyer::AwaitRedeem { .. }));
    let [redeem] = world.mempool()[..] else {
        panic!("the redeem alone is pending");
    };

    world.expire_mempool();
    world.mine_btc(world.terms.t1.into());
    let buyer = resume_buyer(world);
    wait_for("the cancel", || (!world.mempool().is_empty()).then_some(()));
    assert!(!world.pooled(redeem));
    (buyer, lock, redeem)
}

#[test]
#[ignore = "needs Docker and NEXUS_NODE_IMAGE"]
fn a_redeem_replaces_the_pending_cancel() {
    let world = World::with_args(2, &["-mempoolexpiry=1"]);
    let (buyer, lock, redeem) = cancel_pending_after_the_redeem_dropped(&world);
    // The seller, back with the cancel still pending, sends its redeem
    // against it, which pays twice cancel's fee and replaces it; the buyer
    // finds `s` in it and claims.
    let seller = resume_seller(&world);
    wait_for("the redeem against the cancel", || {
        world.pooled(redeem).then_some(())
    });
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
    assert_eq!(btc_balance(&world.seller_wallet), BTC_AMOUNT - BTC_FEE * 2);
    assert_eq!(
        btc_balance(&world.buyer_wallet),
        BUYER_BTC - BTC_AMOUNT - world.funding_fee()
    );
}

#[test]
#[ignore = "needs Docker and NEXUS_NODE_IMAGE"]
fn a_cancel_mined_before_the_redeem_returns_refunds_both() {
    let world = World::with_args(2, &["-mempoolexpiry=1"]);
    let (buyer, lock, redeem) = cancel_pending_after_the_redeem_dropped(&world);
    // The cancel is mined before the seller is back: its redeem can no
    // longer land, the buyer refunds, and the seller, which learns `b`
    // from the refund, claims its NEX back.
    world.mine_btc(1);
    let seller = resume_seller(&world);
    world.drive(Pace::OnDemand, true, || {
        finished(&seller) && finished(&buyer)
    });
    assert_eq!(outcome(seller).0, Some(Outcome::Refunded));
    assert_eq!(outcome(buyer).0, Some(Outcome::Refunded));
    assert!(world.bitcoin("").transaction(redeem).unwrap().is_none());

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
fn a_short_nex_lock_is_never_redeemed() {
    let mut world = World::new(2);
    world.short_lock = 1;
    let signed = Arc::new(AtomicBool::new(false));
    let flag = signed.clone();
    let (seller, buyer, lock) = start(&world, move |state| {
        if matches!(state, Buyer::AwaitRedeem { .. }) {
            flag.store(true, Ordering::SeqCst);
        }
        false
    });
    // The short lock lands and is named, but the buyer never signs the
    // redeem: it cancels and refunds at t1.
    let locked = Cell::new(0);
    world.drive(Pace::Steady, true, || {
        if let Some(address) = lock.lock().unwrap().clone() {
            locked.set(locked.get().max(world.nexus.balance(&address)));
        }
        finished(&buyer)
    });
    assert_eq!(outcome(buyer).0, Some(Outcome::Refunded));
    assert_eq!(locked.get(), NEX_AMOUNT - 1, "the short lock landed");
    assert!(
        !signed.load(Ordering::SeqCst),
        "the redeem was never signed"
    );
    // The seller, which learned `b` from the refund, claims its NEX back.
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
fn a_redeem_below_the_mempool_minimum_is_bumped_into_a_block() {
    // The mempool takes nothing below 20 sat/vB alone, which redeem's two
    // fees are; the buyer's driver funds the lock at that minimum, and the
    // miner's wallet pays 50 sat/vB.
    let mut world = World::with_args(2, &["-minrelaytxfee=0.0002", "-fallbackfee=0.0005"]);
    world.seller_max_fee_rate = FeeRate::from_sat_per_vb_u32(25);
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
    // The redeem's payout, less the child that bumped it.
    let redeemed = BTC_AMOUNT - BTC_FEE * 2;
    let seller_btc = btc_balance(&world.seller_wallet);
    assert!(
        seller_btc < redeemed && seller_btc > redeemed - Amount::from_sat(20_000),
        "{seller_btc}"
    );
    assert_eq!(
        btc_balance(&world.buyer_wallet),
        BUYER_BTC - BTC_AMOUNT - world.funding_fee()
    );
}

#[test]
#[ignore = "needs Docker and NEXUS_NODE_IMAGE"]
fn a_swap_completes_across_a_nexus_node_restart() {
    let mut world = World::new(2);
    let (seller, buyer, lock) = start(&world, |_| false);
    // Restarted once the NEX lock is in, before the buyer claims it.
    world.drive(Pace::OnDemand, true, || {
        let address = lock.lock().unwrap().clone();
        address.is_some_and(|address| world.nexus.balance(&address) == NEX_AMOUNT)
    });
    let height = world.nexus.client().health().unwrap().height;
    world.nexus.restart();
    assert!(world.nexus.client().health().unwrap().height >= height);
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
    assert_eq!(btc_balance(&world.seller_wallet), BTC_AMOUNT - BTC_FEE * 2);
    assert_eq!(
        btc_balance(&world.buyer_wallet),
        BUYER_BTC - BTC_AMOUNT - world.funding_fee()
    );
}

/// A second node, peered with `world`'s and at its tip.
fn fork_node(world: &World) -> Nexus {
    let mut fork = Nexus::start();
    fork.peer(Some(&world.nexus));
    world.nexus.follow(&fork);
    fork
}

/// Mines a heavier branch on `fork`, cut off from `world`'s node, then
/// joins the two: the swap's node reorgs onto it.
fn reorg_onto(world: &World, fork: &mut Nexus) {
    fork.outmine(&world.nexus);
    fork.peer(Some(&world.nexus));
    world.nexus.follow(fork);
}

/// Mines Bitcoin on demand and Nexus every round, so a claim gets deep with
/// nothing else pending, until both parties end.
fn mine_until_ended(world: &World, seller: &Party<Seller>, buyer: &Party<Buyer>) {
    wait_for("the swap to end", || {
        if finished(seller) && finished(buyer) {
            return Some(());
        }
        if !world.mempool().is_empty() {
            world.mine_btc(1);
        }
        world.nexus.mine(None);
        None
    });
}

/// The buyer's phases as `buyer_status` shows them, each once in a row,
/// and the claims it watches.
#[derive(Clone, Default)]
struct Trail {
    phases: Arc<Mutex<Vec<String>>>,
    claims: Arc<Mutex<Vec<String>>>,
}

impl Trail {
    /// Records `state`; returns its phase.
    fn record(&self, state: &Buyer) -> String {
        let status = swap::status::buyer_status(state, None);
        let phase = status["phase"].as_str().unwrap().to_string();
        let mut phases = self.phases.lock().unwrap();
        if phases.last() != Some(&phase) {
            phases.push(phase.clone());
        }
        let cid = state.watch().nexus.and_then(|watch| watch.cid);
        if let (Buyer::ClaimingNex(_), Some(cid)) = (state, cid) {
            let mut claims = self.claims.lock().unwrap();
            if !claims.contains(&cid) {
                claims.push(cid);
            }
        }
        phase
    }
}

#[test]
#[ignore = "needs Docker and NEXUS_NODE_IMAGE"]
fn a_claim_reorged_out_is_sent_again() {
    let mut world = World::new(2);
    // Two confirmations: a claim one block deep is received, not final.
    // t1 leaves time for the deeper lock.
    world.terms.nex_confirmations = 2;
    world.terms.t1 = world.terms.t1_floor().try_into().unwrap();
    let mut fork = fork_node(&world);
    // The buyer stops once received, so nothing sends the claim while the
    // reorg below takes it out.
    let trail = Trail::default();
    let first = trail.clone();
    let (seller, buyer, lock) = start(&world, move |state| first.record(state) == "received");
    // The lock lands one deep, and both nodes have it; then they part, and
    // the swap's node takes the lock to two deep and the claim to one.
    world.drive(Pace::OnDemand, true, || {
        let address = lock.lock().unwrap().clone();
        address.is_some_and(|address| world.nexus.balance(&address) == NEX_AMOUNT)
    });
    fork.follow(&world.nexus);
    fork.peer(None);
    world.nexus.mine(None);
    world.drive(Pace::OnDemand, true, || finished(&buyer));
    let (stopped, state) = outcome(buyer);
    assert_eq!(stopped, None);
    assert!(matches!(state, Buyer::ClaimingNex(_)));
    assert_eq!(
        world.nexus.balance(&world.buyer_nex),
        NEX_AMOUNT - world.terms.nex_fee
    );

    // A heavier branch without the claim; the lock under it stays.
    reorg_onto(&world, &mut fork);
    // The node returns the claim to its pool, which does not outlive a
    // restart; the fork, which may hold it too, is cut off again first.
    fork.peer(None);
    world.nexus.restart();
    assert_eq!(world.nexus.pending(), 0, "only the buyer can send it again");
    assert_eq!(world.nexus.balance(&world.buyer_nex), 0);
    assert_eq!(world.nexus.balance(&lock_address(&lock)), NEX_AMOUNT);
    // Back, the buyer finds the claim gone, sends it again, and the swap
    // ends once it is two deep.
    let again = trail.clone();
    let buyer = resume_buyer_watched(&world, move |state| {
        again.record(state);
    });
    mine_until_ended(&world, &seller, &buyer);
    assert_eq!(outcome(seller).0, Some(Outcome::Swapped));
    assert_eq!(outcome(buyer).0, Some(Outcome::Swapped));
    let phases = trail.phases.lock().unwrap();
    let from = phases.iter().position(|phase| phase == "received").unwrap();
    assert_eq!(
        phases[from..],
        ["received", "finishing", "received"],
        "{phases:?}"
    );
    assert_eq!(
        trail.claims.lock().unwrap().len(),
        1,
        "one claim, sent again"
    );

    let fee = world.terms.nex_fee;
    let n = &world.nexus;
    assert_eq!(n.balance(&world.buyer_nex), NEX_AMOUNT - fee);
    assert_eq!(
        n.balance(&world.seller_nex.nex_address()),
        2 * REWARD - NEX_AMOUNT - fee
    );
    assert_eq!(n.balance(&lock_address(&lock)), 0);
    assert_eq!(btc_balance(&world.seller_wallet), BTC_AMOUNT - BTC_FEE * 2);
    assert_eq!(
        btc_balance(&world.buyer_wallet),
        BUYER_BTC - BTC_AMOUNT - world.funding_fee()
    );
}

#[test]
#[ignore = "needs Docker and NEXUS_NODE_IMAGE"]
fn a_nex_lock_reorged_out_is_signed_for_once_deep_again() {
    let mut world = World::new(2);
    // Two confirmations: a lock one block deep is not yet signed for. t1
    // leaves time for the deeper lock.
    world.terms.nex_confirmations = 2;
    world.terms.t1 = world.terms.t1_floor().try_into().unwrap();
    let mut fork = fork_node(&world);
    // The two nodes part before the swap.
    fork.peer(None);
    // Whether the buyer signed, how many states it stepped to, and the
    // lock the seller named.
    let signed = Arc::new(AtomicBool::new(false));
    let steps = Arc::new(AtomicUsize::new(0));
    let named = Arc::new(Mutex::new(None));
    let (flag, count, slot) = (signed.clone(), steps.clone(), named.clone());
    let (seller, buyer, lock) = start(&world, move |state| {
        count.fetch_add(1, Ordering::SeqCst);
        match state {
            Buyer::AwaitNexLock { .. } => {
                *slot.lock().unwrap() = state.watch().nexus.and_then(|watch| watch.cid);
            }
            Buyer::AwaitRedeem { .. } => flag.store(true, Ordering::SeqCst),
            _ => {}
        }
        false
    });
    // The lock lands one deep on the swap's node alone.
    world.drive(Pace::OnDemand, true, || {
        let address = lock.lock().unwrap().clone();
        address.is_some_and(|address| world.nexus.balance(&address) == NEX_AMOUNT)
    });
    // A heavier branch without it: the node takes the lock back to its
    // pool.
    reorg_onto(&world, &mut fork);
    let address = lock_address(&lock);
    assert_eq!(world.nexus.balance(&address), 0);
    assert!(world.nexus.pending() > 0, "the lock back in the pool");
    // It lands again, one deep: still not enough to sign for. For five
    // seconds the node is synced and shows it one deep, and the buyer,
    // stepping on its views all along, does not sign.
    world.nexus.mine(None);
    assert_eq!(world.nexus.balance(&address), NEX_AMOUNT);
    let cid = named
        .lock()
        .unwrap()
        .clone()
        .expect("the seller named the lock");
    let client = world.nexus.client();
    let (before, until) = (
        steps.load(Ordering::SeqCst),
        Instant::now() + Duration::from_secs(5),
    );
    while Instant::now() < until {
        let health = client.health().unwrap();
        assert!(
            health.phase == "active" && health.best_header_height == Some(health.height),
            "{health:?}"
        );
        assert_eq!(client.confirmations(&cid).unwrap(), Some(1));
        assert!(!signed.load(Ordering::SeqCst), "signed for a shallow lock");
        thread::sleep(Duration::from_millis(250));
    }
    assert!(
        steps.load(Ordering::SeqCst) >= before + 10,
        "the buyer stepped"
    );
    // Two deep on the new branch, the buyer signs, and the swap ends once
    // its claim is two deep.
    mine_until_ended(&world, &seller, &buyer);
    assert_eq!(outcome(seller).0, Some(Outcome::Swapped));
    assert_eq!(outcome(buyer).0, Some(Outcome::Swapped));

    let fee = world.terms.nex_fee;
    let n = &world.nexus;
    assert_eq!(n.balance(&world.buyer_nex), NEX_AMOUNT - fee);
    assert_eq!(
        n.balance(&world.seller_nex.nex_address()),
        2 * REWARD - NEX_AMOUNT - fee
    );
    assert_eq!(n.balance(&address), 0);
    assert_eq!(btc_balance(&world.seller_wallet), BTC_AMOUNT - BTC_FEE * 2);
    assert_eq!(
        btc_balance(&world.buyer_wallet),
        BUYER_BTC - BTC_AMOUNT - world.funding_fee()
    );
}
