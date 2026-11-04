//! Whole swaps through the `lattice-swap` binary: `offer` and `take` as two
//! processes, meeting directly or through a relay run here, killed and
//! carried on with `resume`, against a regtest bitcoind and a lattice-node
//! in Docker, each test its own. The test, not the parties, mines blocks on
//! both chains.
//!
//! The browser's buyer, web/driver run in Node, takes offers here too,
//! through an Esplora shim over the regtest bitcoind and the node's public
//! read port; web/driver/build.sh builds what it loads first. So does the
//! native one an app runs, `swap::app`, in this process, through the same
//! shim and the node's RPC, and each carries on a swap from the other's
//! recovery file.
//!
//! Ignored by a plain `cargo test`; run with `NEXUS_NODE_IMAGE` naming the
//! node image and `-- --ignored`. The node's RPC listens on loopback only,
//! so its container shares the host's network.

use std::io::{BufRead, BufReader, Read};
use std::net::TcpListener;
use std::path::PathBuf;
use std::process::{Child, Command, ExitStatus, Output, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use bitcoin::{Amount, Denomination, Network};
use corepc_node::{Conf, Node};
use ed25519_dalek::SigningKey;
use rand_core::{OsRng, RngCore};
use serde_json::{json, Value};
use swap::app::{self, Wallet};
use swap::bitcoind::Bitcoind;
use swap::{Outcome, SecretBytes};
use swap_nexus_tx::address;
use swap_nexus_tx::rpc::Client;
use swap_relay::board::Board;
use swap_relay::Relay;

mod esplora;

const TIMEOUT: Duration = Duration::from_secs(10);
/// Nexus's block reward over its first halving interval.
const REWARD: u64 = 1_048_576;
const BTC_AMOUNT: Amount = Amount::from_sat(50_000_000);
const BTC_FEE: Amount = Amount::from_sat(1_000);
/// Below every swap transaction's own feerate, as the fallback for
/// regtest's missing estimate and as the cap: nothing is bumped, and each
/// costs exactly `BTC_FEE`, but redeem, which pays two.
const NO_BUMP: [&str; 4] = ["--fallback-fee-rate", "1", "--max-fee-rate", "1"];
/// The seller's quote: satoshis a NEX of 10^6 base units, and the range it
/// takes, which `BTC_AMOUNT` is inside of and below the top of. A sat
/// below 50 a base unit: `BTC_AMOUNT` buys 1000000.02 base units, so 1 sat
/// of it buys nothing.
const PRICE: u64 = 49_999_999;
const MIN_BTC_AMOUNT: Amount = Amount::from_sat(10_000_000);
const MAX_BTC_AMOUNT: Amount = Amount::from_sat(60_000_000);
/// What `BTC_AMOUNT` buys at `PRICE`, rounded down.
const NEX_AMOUNT: u64 = 1_000_000;
/// What the buyer's wallet holds before a swap.
const BUYER_BTC: Amount = Amount::from_sat(100_000_000);

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

/// A relay on loopback: its URL and the relay.
fn relay() -> (String, Arc<Relay>) {
    let relay = Arc::new(Relay {
        board: Board::new(10),
        rejoins: Board::new(10),
    });
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let url = format!("http://{}", listener.local_addr().unwrap());
    listener.set_nonblocking(true).unwrap();
    let serving = relay.clone();
    thread::spawn(move || {
        let runtime = tokio::runtime::Runtime::new().unwrap();
        runtime.block_on(async {
            let listener = tokio::net::TcpListener::from_std(listener).unwrap();
            swap_relay::serve(listener, serving).await.unwrap();
        });
    });
    (url, relay)
}

/// A lattice-node in Docker, as in the swap crate's end-to-end tests.
struct Nexus {
    container: String,
    url: String,
    /// The public read port, which also takes submits, unthrottled.
    public: String,
    cookie: String,
}

impl Nexus {
    fn start() -> Self {
        let image =
            std::env::var("NEXUS_NODE_IMAGE").expect("NEXUS_NODE_IMAGE names the node image");
        let (rpc, p2p, public) = (free_port(), free_port(), free_port());
        let script = format!(
            "lattice-node --data-directory /tmp/d --identity-key /tmp/p.key \
             --listen-port {p2p} --rpc-port {rpc} --websocket-port 0 --no-default-peers \
             --public-read-port {public} --public-submit --public-read-rate 0 \
             --public-read-expensive-rate 0 --public-read-max-rate 0 --public-submit-rate 0"
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
            public: format!("http://127.0.0.1:{public}"),
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
        use base64::Engine;
        let token = base64::engine::general_purpose::STANDARD.encode(self.cookie.trim());
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

fn wallet_client(node: &Node, wallet: &str) -> Bitcoind {
    let cookie = std::fs::read_to_string(&node.params.cookie_file).unwrap();
    let url = match wallet {
        "" => node.rpc_url(),
        wallet => node.rpc_url_with_wallet(wallet),
    };
    Bitcoind::new(&url, &cookie, Network::Regtest, TIMEOUT)
}

/// The fee the buyer's wallet paid to fund the lock: its one payment.
fn funding_fee(buyer: &Bitcoind) -> Amount {
    let sends = buyer.call("listtransactions", json!(["*", 100])).unwrap();
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

/// The wallet's confirmed balance.
fn btc_balance(wallet: &Bitcoind) -> Amount {
    let balances = wallet.call("getbalances", json!([])).unwrap();
    let trusted = balances["mine"]["trusted"].as_f64().unwrap();
    Amount::from_float_in(trusted, Denomination::Bitcoin).unwrap()
}

/// A party's process, killed if the test ends first.
struct Party(Child);

impl Drop for Party {
    fn drop(&mut self) {
        let _ = self.0.kill();
    }
}

fn lattice_swap() -> Command {
    Command::new(env!("CARGO_BIN_EXE_lattice-swap"))
}

fn stdout(child: &mut Child) -> String {
    let mut text = String::new();
    child
        .stdout
        .take()
        .unwrap()
        .read_to_string(&mut text)
        .unwrap();
    text
}

/// A regtest bitcoind with a seller wallet and a buyer wallet holding 1
/// BTC, a Nexus node whose first two blocks pay the seller, and a
/// directory for each party's swap file.
struct World {
    bitcoind: Node,
    miner: bitcoin::Address,
    nexus: Nexus,
    /// The genesis of the node's Nexus, which a dev build may pin other than
    /// mainnet's: both parties are told it, and the default stays mainnet's.
    nexus_genesis: String,
    seller_nex: SecretBytes,
    buyer_nex: String,
    nex_fee: u64,
    directory: tempfile::TempDir,
    nexus_cookie: PathBuf,
    key_file: PathBuf,
}

impl World {
    fn new() -> Self {
        let mut conf = Conf::default();
        conf.args.push("-txindex");
        let bitcoind = Node::from_downloaded_with_conf(&conf).expect("start bitcoind");
        let miner = bitcoind.client.new_address().unwrap();
        bitcoind.client.generate_to_address(101, &miner).unwrap();
        for name in ["seller", "buyer"] {
            bitcoind.create_wallet(name).unwrap();
        }
        let buyer_btc = wallet_client(&bitcoind, "buyer")
            .call("getnewaddress", json!([]))
            .unwrap();
        wallet_client(&bitcoind, "default")
            .call("sendtoaddress", json!([buyer_btc, BUYER_BTC.to_btc()]))
            .unwrap();
        bitcoind.client.generate_to_address(1, &miner).unwrap();
        // The parties refuse a node whose index is still catching up.
        wait_for("the txindex", || {
            wallet_client(&bitcoind, "buyer").check_node().ok()
        });

        let nexus = Nexus::start();
        let seller_nex = SecretBytes(random32());
        for _ in 0..2 {
            nexus.mine(Some(&seller_nex.nex_address()));
        }
        let buyer_nex = address(
            &SigningKey::from_bytes(&random32())
                .verifying_key()
                .to_bytes(),
        );
        let nex_fee = nexus.client().min_relay_fee().unwrap();
        let nexus_genesis = nexus.client().genesis().unwrap();
        eprintln!("node genesis {nexus_genesis}");

        let directory = tempfile::tempdir().unwrap();
        let nexus_cookie = directory.path().join("nexus.cookie");
        std::fs::write(&nexus_cookie, &nexus.cookie).unwrap();
        let key_file = directory.path().join("nex.key");
        std::fs::write(&key_file, hex::encode(seller_nex.0)).unwrap();
        std::fs::set_permissions(
            &key_file,
            std::os::unix::fs::PermissionsExt::from_mode(0o600),
        )
        .unwrap();
        World {
            bitcoind,
            miner,
            nexus,
            nexus_genesis,
            seller_nex,
            buyer_nex,
            nex_fee,
            directory,
            nexus_cookie,
            key_file,
        }
    }

    /// What `side`, which names its wallet and its directory, passes to
    /// reach its nodes.
    fn node_args(&self, side: &str) -> Vec<String> {
        let args = [
            "--btc-url",
            &self.bitcoind.rpc_url(),
            "--btc-wallet",
            side,
            "--btc-cookie",
            self.bitcoind.params.cookie_file.to_str().unwrap(),
            "--btc-network",
            "regtest",
            "--nexus-url",
            &self.nexus.url,
            "--nexus-cookie",
            self.nexus_cookie.to_str().unwrap(),
            "--nexus-genesis",
            &self.nexus_genesis,
        ];
        args.map(String::from).to_vec()
    }

    fn dir(&self, side: &str) -> PathBuf {
        self.directory.path().join(side)
    }

    fn swap_file(&self, side: &str, swap_id: &str) -> PathBuf {
        self.dir(side).join(format!("{swap_id}.json"))
    }

    /// The state `side`'s swap file holds; empty before it exists.
    fn state(&self, side: &str, swap_id: &str) -> String {
        let Ok(text) = std::fs::read_to_string(self.swap_file(side, swap_id)) else {
            return String::new();
        };
        match &serde_json::from_str::<Value>(&text).unwrap()["state"] {
            Value::Object(state) => state.keys().next().unwrap().clone(),
            Value::String(state) => state.clone(),
            state => panic!("a state: {state}"),
        }
    }

    /// The seller's `offer`, with small timelocks for regtest, and the
    /// buyer's `take` on it: the two parties, the swap id, and the rest of
    /// the seller's output once it ends. `t1` is at least the tool's floor
    /// of 1 + 6 x (`nex_confirmations` + 1) + 3.
    fn start(&self, t1: u16, nex_confirmations: u64) -> (Party, Party, String, JoinHandle<String>) {
        self.start_on(t1, nex_confirmations, None)
    }

    /// [`World::start`], the seller listing its offer on the relay at
    /// `relay`, if given, where the buyer finds it.
    fn start_on(
        &self,
        t1: u16,
        nex_confirmations: u64,
        relay: Option<&str>,
    ) -> (Party, Party, String, JoinHandle<String>) {
        let (seller, offer, swap_id, seller_out) = self.offer_on(t1, nex_confirmations, relay);
        let offer_file = self.directory.path().join("offer");
        std::fs::write(&offer_file, &offer).unwrap();
        let (t1, nex_fee) = (t1.to_string(), self.nex_fee.to_string());
        let buyer = Party(
            lattice_swap()
                .arg("take")
                .arg(&offer_file)
                .args(["--nex-address", &self.buyer_nex])
                .args(["--btc-amount", &BTC_AMOUNT.to_sat().to_string()])
                .args(["--price", &PRICE.to_string()])
                .args(["--max-btc-fee", &BTC_FEE.to_sat().to_string()])
                .args(["--max-nex-fee", &nex_fee])
                .args([
                    "--max-t1",
                    &t1,
                    "--min-t2",
                    "10",
                    "--min-refund-window",
                    "9",
                ])
                .args(["--min-margin", "3"])
                // Regtest has no fee estimate.
                .args(["--min-btc-fee-rate", "1"])
                .args(NO_BUMP)
                .args(["--min-btc-confirmations", "1"])
                .args(["--min-nex-confirmations", "1"])
                .arg("--dir")
                .arg(self.dir("buyer"))
                .args(self.node_args("buyer"))
                .stdout(Stdio::piped())
                .spawn()
                .unwrap(),
        );
        (seller, buyer, swap_id, seller_out)
    }

    /// The seller's side of [`World::start_on`]: the seller, its offer as
    /// the buyer reads it, the swap id, and the rest of its output.
    fn offer_on(
        &self,
        t1: u16,
        nex_confirmations: u64,
        relay: Option<&str>,
    ) -> (Party, String, String, JoinHandle<String>) {
        let (t1, nex_confirmations) = (t1.to_string(), nex_confirmations.to_string());
        let nex_fee = self.nex_fee.to_string();
        let place = match relay {
            Some(relay) => ["--relay", relay],
            None => ["--listen", "127.0.0.1:0"],
        };
        let mut seller = Party(
            lattice_swap()
                .arg("offer")
                .args(place)
                .args(["--price", &PRICE.to_string()])
                .args(["--min-btc-amount", &MIN_BTC_AMOUNT.to_sat().to_string()])
                .args(["--max-btc-amount", &MAX_BTC_AMOUNT.to_sat().to_string()])
                .args(["--btc-fee", &BTC_FEE.to_sat().to_string()])
                // Regtest has no fee estimate.
                .args(["--min-btc-fee-rate", "1"])
                .args(["--nex-fee", &nex_fee])
                .args(["--t1", &t1, "--t2", "10", "--margin", "3"])
                .args(["--btc-confirmations", "1"])
                .args(["--nex-confirmations", &nex_confirmations])
                .args(NO_BUMP)
                .arg("--dir")
                .arg(self.dir("seller"))
                .arg("--nex-key-file")
                .arg(&self.key_file)
                .args(self.node_args("seller"))
                .stdout(Stdio::piped())
                .spawn()
                .unwrap(),
        );
        let mut offer = String::new();
        let mut reader = BufReader::new(seller.0.stdout.take().unwrap());
        reader.read_line(&mut offer).unwrap();
        let swap_id = serde_json::from_str::<Value>(&offer).unwrap()["template"]["swap_id"]
            .as_str()
            .unwrap()
            .to_string();
        if let Some(relay) = relay {
            // The buyer takes it from the board, as the relay lists it.
            let listed = wait_for("the offer listed", || {
                let offers: Value = ureq::get(&format!("{relay}/offers"))
                    .call()
                    .unwrap()
                    .into_json()
                    .unwrap();
                offers.as_array().unwrap().first().cloned()
            });
            assert_eq!(listed["template"]["swap_id"], swap_id.as_str());
            offer = listed.to_string();
        }
        // The rest of the seller's output, read as it comes so it never
        // blocks.
        let seller_out = thread::spawn(move || {
            let mut rest = String::new();
            reader.read_to_string(&mut rest).unwrap();
            rest
        });
        (seller, offer, swap_id, seller_out)
    }

    /// `resume` on `side`'s swap file, the seller with its key file.
    fn resume(&self, side: &str, swap_id: &str) -> Party {
        let mut command = lattice_swap();
        command
            .arg("resume")
            .arg(self.swap_file(side, swap_id))
            .args(NO_BUMP)
            .args(self.node_args(side))
            .stdout(Stdio::piped());
        if side == "seller" {
            command.arg("--nex-key-file").arg(&self.key_file);
        }
        Party(command.spawn().unwrap())
    }

    /// Mines until `done`. `steady`, a block on each chain every round, so
    /// time passes; otherwise a block whenever its pool holds something.
    /// Nexus only while `nexus` holds, asked after its pool: what entered
    /// the pool before `nexus` turned false is not mined.
    fn drive(&self, steady: bool, nexus: impl Fn() -> bool, mut done: impl FnMut() -> bool) {
        let deadline = Instant::now() + Duration::from_secs(600);
        while !done() {
            assert!(Instant::now() < deadline, "the swap timed out");
            let mempool = wallet_client(&self.bitcoind, "")
                .call("getmempoolinfo", json!([]))
                .unwrap();
            if steady || mempool["size"].as_u64() > Some(0) {
                self.bitcoind
                    .client
                    .generate_to_address(1, &self.miner)
                    .unwrap();
            }
            if (steady || self.nexus.pending() > 0) && nexus() {
                self.nexus.mine(None);
            }
            thread::sleep(Duration::from_millis(400));
        }
    }

    /// Drives until `party` exits, and how.
    fn finish(&self, party: &mut Party, steady: bool, nexus: bool) -> ExitStatus {
        let mut status = None;
        self.drive(
            steady,
            || nexus,
            || {
                status = party.0.try_wait().unwrap();
                status.is_some()
            },
        );
        status.unwrap()
    }
}

/// Kills `party` and waits for it to go.
fn kill(party: &mut Party) {
    party.0.kill().unwrap();
    party.0.wait().unwrap();
}

#[test]
#[ignore = "needs Docker and NEXUS_NODE_IMAGE"]
fn happy_path_through_the_binary() {
    let world = World::new();
    let (mut seller, mut buyer, swap_id, seller_out) = world.start(20, 1);

    // Mines whenever either pool holds something, until both parties exit.
    let (mut seller_done, mut buyer_done) = (None, None);
    world.drive(
        false,
        || true,
        || {
            seller_done = seller_done.or(seller.0.try_wait().unwrap());
            buyer_done = buyer_done.or(buyer.0.try_wait().unwrap());
            seller_done.is_some() && buyer_done.is_some()
        },
    );
    assert!(seller_done.unwrap().success());
    assert!(buyer_done.unwrap().success());
    assert_eq!(seller_out.join().unwrap(), "outcome: Swapped\n");
    assert_eq!(stdout(&mut buyer.0), "outcome: Swapped\n");

    let nex_fee = world.nex_fee;
    assert_eq!(world.nexus.balance(&world.buyer_nex), NEX_AMOUNT - nex_fee);
    assert_eq!(
        world.nexus.balance(&world.seller_nex.nex_address()),
        2 * REWARD - NEX_AMOUNT - nex_fee
    );
    // Redeem pays two fees.
    let seller_wallet = wallet_client(&world.bitcoind, "seller");
    assert_eq!(btc_balance(&seller_wallet), BTC_AMOUNT - BTC_FEE * 2);
    let buyer_wallet = wallet_client(&world.bitcoind, "buyer");
    assert_eq!(
        btc_balance(&buyer_wallet),
        BUYER_BTC - BTC_AMOUNT - funding_fee(&buyer_wallet)
    );

    // `status` reads each swap file and asks no node.
    for side in ["seller", "buyer"] {
        let Output { status, stdout, .. } = lattice_swap()
            .arg("status")
            .arg(world.swap_file(side, &swap_id))
            .output()
            .unwrap();
        assert!(status.success());
        assert_eq!(
            String::from_utf8(stdout).unwrap(),
            "state: Done\noutcome: Swapped\n"
        );
    }
}

/// Both parties killed once the NEX is locked, before the buyer signs the
/// redeem: `resume` refunds the buyer, then claims the seller's NEX back.
#[test]
#[ignore = "needs Docker and NEXUS_NODE_IMAGE"]
fn killed_before_the_redeem_both_resume_to_a_refund() {
    let world = World::new();
    // Two Nexus confirmations, with Nexus mined only while its pool holds
    // something: the NEX lock lands and stays one deep, so the buyer never
    // signs the redeem, and the seller never redeems.
    let (mut seller, mut buyer, swap_id, seller_out) = world.start(24, 2);
    world.drive(
        false,
        || true,
        || world.state("seller", &swap_id) == "AwaitRedeemSignature",
    );
    assert_eq!(world.state("buyer", &swap_id), "AwaitNexLock");
    kill(&mut seller);
    kill(&mut buyer);
    seller_out.join().unwrap();

    // The buyer alone, as time passes: it cancels at t1 and refunds.
    let mut buyer = world.resume("buyer", &swap_id);
    let status = world.finish(&mut buyer, true, false);
    assert_eq!(status.code(), Some(3), "{status}");
    assert_eq!(stdout(&mut buyer.0), "outcome: Refunded\n");

    // The seller learns `b` from the refund and claims its NEX back.
    let mut seller = world.resume("seller", &swap_id);
    let status = world.finish(&mut seller, true, true);
    assert_eq!(status.code(), Some(3), "{status}");
    assert_eq!(stdout(&mut seller.0), "outcome: Refunded\n");

    let nex_fee = world.nex_fee;
    assert_eq!(world.nexus.balance(&world.buyer_nex), 0);
    assert_eq!(
        world.nexus.balance(&world.seller_nex.nex_address()),
        2 * REWARD - 2 * nex_fee
    );
    let seller_wallet = wallet_client(&world.bitcoind, "seller");
    assert_eq!(btc_balance(&seller_wallet), Amount::ZERO);
    // Back but for the fees of the funding, the cancel and the refund.
    let buyer_wallet = wallet_client(&world.bitcoind, "buyer");
    assert_eq!(
        btc_balance(&buyer_wallet),
        BUYER_BTC - funding_fee(&buyer_wallet) - BTC_FEE * 2
    );
}

/// The buyer gone before it signed the redeem, and past `t2`: the seller
/// cancels, punishes, and stays. The buyer's `resume` finds itself punished,
/// meets the seller again, is given `s` and claims the NEX with it, as
/// eigenwallet's CLI redeems cooperatively after a punish; the seller ends
/// once the lock address has signed.
#[test]
#[ignore = "needs Docker and NEXUS_NODE_IMAGE"]
fn a_punished_buyer_resumes_and_is_given_the_nex() {
    let world = World::new();
    // As in `killed_before_the_redeem_both_resume_to_a_refund`: the NEX
    // lock stays one deep of two, so the buyer never signs the redeem.
    let (mut seller, mut buyer, swap_id, seller_out) = world.start(24, 2);
    world.drive(
        false,
        || true,
        || world.state("seller", &swap_id) == "AwaitRedeemSignature",
    );
    assert_eq!(world.state("buyer", &swap_id), "AwaitNexLock");
    kill(&mut buyer);

    // Time passes without the buyer: cancel at t1, punish at t2.
    world.drive(
        true,
        || false,
        || world.state("seller", &swap_id) == "Punished",
    );
    let mut rounds = 0;
    world.drive(
        true,
        || false,
        || {
            rounds += 1;
            rounds > 5
        },
    );
    assert!(
        seller.0.try_wait().unwrap().is_none(),
        "the punished seller stays"
    );

    let mut buyer = world.resume("buyer", &swap_id);
    let (mut seller_done, mut buyer_done) = (None, None);
    // Steady: the claim must reach two deep, past an empty pool.
    world.drive(
        true,
        || true,
        || {
            seller_done = seller_done.or(seller.0.try_wait().unwrap());
            buyer_done = buyer_done.or(buyer.0.try_wait().unwrap());
            seller_done.is_some() && buyer_done.is_some()
        },
    );
    assert!(buyer_done.unwrap().success(), "{buyer_done:?}");
    assert_eq!(stdout(&mut buyer.0), "outcome: Swapped\n");
    assert_eq!(seller_done.unwrap().code(), Some(4));
    assert_eq!(seller_out.join().unwrap(), "outcome: Punished\n");
    assert_eq!(
        world.nexus.balance(&world.buyer_nex),
        NEX_AMOUNT - world.nex_fee
    );
    // Punish pays the BTC less cancel's fee and its own.
    let seller_wallet = wallet_client(&world.bitcoind, "seller");
    assert_eq!(btc_balance(&seller_wallet), BTC_AMOUNT - BTC_FEE * 2);
}

/// The buyer killed once it has seen the redeem and is claiming the NEX:
/// `resume` carries on from that claim to the swap.
#[test]
#[ignore = "needs Docker and NEXUS_NODE_IMAGE"]
fn buyer_killed_after_the_redeem_resumes_to_the_swap() {
    let world = World::new();
    let (mut seller, mut buyer, swap_id, seller_out) = world.start(20, 1);
    // Nexus stops once the seller holds the redeem signature: the buyer's
    // claim waits in the pool.
    let redeeming = || {
        matches!(
            world.state("seller", &swap_id).as_str(),
            "Redeeming" | "Done"
        )
    };
    world.drive(
        false,
        || !redeeming(),
        || world.state("buyer", &swap_id) == "ClaimingNex",
    );
    kill(&mut buyer);
    let status = world.finish(&mut seller, false, false);
    assert!(status.success(), "{status}");
    assert_eq!(seller_out.join().unwrap(), "outcome: Swapped\n");

    let mut buyer = world.resume("buyer", &swap_id);
    let status = world.finish(&mut buyer, false, true);
    assert!(status.success(), "{status}");
    assert_eq!(stdout(&mut buyer.0), "outcome: Swapped\n");
    assert_eq!(
        world.nexus.balance(&world.buyer_nex),
        NEX_AMOUNT - world.nex_fee
    );
}

/// The seller lists its offer on a relay instead of listening; the buyer
/// takes it from the relay's board, and the two swap through the relay.
#[test]
#[ignore = "needs Docker and NEXUS_NODE_IMAGE"]
fn happy_path_through_a_relay() {
    let world = World::new();
    let (url, relay) = relay();
    let (mut seller, mut buyer, _, seller_out) = world.start_on(20, 1, Some(&url));
    let (mut seller_done, mut buyer_done) = (None, None);
    world.drive(
        false,
        || true,
        || {
            seller_done = seller_done.or(seller.0.try_wait().unwrap());
            buyer_done = buyer_done.or(buyer.0.try_wait().unwrap());
            seller_done.is_some() && buyer_done.is_some()
        },
    );
    assert!(seller_done.unwrap().success());
    assert!(buyer_done.unwrap().success());
    assert_eq!(seller_out.join().unwrap(), "outcome: Swapped\n");
    assert_eq!(stdout(&mut buyer.0), "outcome: Swapped\n");
    assert_eq!(
        world.nexus.balance(&world.buyer_nex),
        NEX_AMOUNT - world.nex_fee
    );
    // Taken, the offer left the board.
    assert!(relay.board.offers().is_empty());
}

/// The buyer killed once its BTC lock is in a block, before the seller's
/// NEX lock lands: the CID the seller sends goes nowhere. `resume` meets the
/// seller again at the relay, gets the CID, and the swap completes.
#[test]
#[ignore = "needs Docker and NEXUS_NODE_IMAGE"]
fn a_buyer_killed_after_the_lock_rejoins_through_the_relay_to_the_swap() {
    let world = World::new();
    let (url, _relay) = relay();
    let (mut seller, mut buyer, swap_id, seller_out) = world.start_on(20, 1, Some(&url));
    // No Nexus block until the buyer is gone: the NEX lock waits in the pool.
    world.drive(
        false,
        || false,
        || world.state("seller", &swap_id) == "LockingNex",
    );
    assert_eq!(world.state("buyer", &swap_id), "AwaitNexLock");
    kill(&mut buyer);
    world.drive(
        false,
        || true,
        || world.state("seller", &swap_id) == "AwaitRedeemSignature",
    );

    let mut buyer = world.resume("buyer", &swap_id);
    let (mut seller_done, mut buyer_done) = (None, None);
    world.drive(
        false,
        || true,
        || {
            seller_done = seller_done.or(seller.0.try_wait().unwrap());
            buyer_done = buyer_done.or(buyer.0.try_wait().unwrap());
            seller_done.is_some() && buyer_done.is_some()
        },
    );
    assert_eq!(seller_out.join().unwrap(), "outcome: Swapped\n");
    assert_eq!(stdout(&mut buyer.0), "outcome: Swapped\n");
    assert_eq!(
        world.nexus.balance(&world.buyer_nex),
        NEX_AMOUNT - world.nex_fee
    );
}

/// The seller, listening on TCP, killed once the buyer's BTC lock is in a
/// block, before its NEX lock lands. `resume` reads its session file,
/// listens again where it did, and takes the buyer back, which dials it
/// again under its rejoin key; the CID reaches the buyer and the swap
/// completes.
#[test]
#[ignore = "needs Docker and NEXUS_NODE_IMAGE"]
fn a_seller_killed_after_the_lock_resumes_and_the_buyer_rejoins_over_tcp() {
    let world = World::new();
    let (mut seller, mut buyer, swap_id, seller_out) = world.start_on(20, 1, None);
    // No Nexus block until the seller is gone: the NEX lock waits in the
    // pool.
    world.drive(
        false,
        || false,
        || world.state("seller", &swap_id) == "LockingNex",
    );
    assert_eq!(world.state("buyer", &swap_id), "AwaitNexLock");
    kill(&mut seller);
    seller_out.join().unwrap();

    let mut seller = world.resume("seller", &swap_id);
    let (mut seller_done, mut buyer_done) = (None, None);
    world.drive(
        false,
        || true,
        || {
            seller_done = seller_done.or(seller.0.try_wait().unwrap());
            buyer_done = buyer_done.or(buyer.0.try_wait().unwrap());
            seller_done.is_some() && buyer_done.is_some()
        },
    );
    assert_eq!(stdout(&mut seller.0), "outcome: Swapped\n");
    assert_eq!(stdout(&mut buyer.0), "outcome: Swapped\n");
    assert_eq!(
        world.nexus.balance(&world.buyer_nex),
        NEX_AMOUNT - world.nex_fee
    );
}

/// The browser's buyer: web/driver in Node, its wallet and swap kept in
/// files.
fn browser(mode: &str, config: &std::path::Path) -> Party {
    let script = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../web/driver/test/e2e-buyer.js"
    );
    Party(
        Command::new("node")
            .arg(script)
            .arg(mode)
            .arg(config)
            .stdout(Stdio::piped())
            .spawn()
            .expect("node, with web/driver built"),
    )
}

impl World {
    /// The browser's config for taking `offer`, as listed: its Esplora
    /// shim, the node's public read port, and the CLI buyer's bounds.
    fn browser_config(&self, offer: &str, t1: u16) -> PathBuf {
        let config = json!({
            "dir": self.dir("browser"),
            "esplora": esplora::esplora(wallet_client(&self.bitcoind, "")),
            "nexus": self.nexus.public,
            "genesis": self.nexus_genesis,
            "offer": offer,
            "policy": self.buyer_policy(t1),
            "nex_address": self.buyer_nex,
        });
        let path = self.directory.path().join("browser.json");
        std::fs::write(&path, config.to_string()).unwrap();
        path
    }

    /// The CLI buyer's bounds, as the browser and the native buyer take
    /// them.
    fn buyer_policy(&self, t1: u16) -> Value {
        json!({
            "btc_amount": BTC_AMOUNT.to_sat(), "price": PRICE,
            "max_btc_fee": BTC_FEE.to_sat(), "max_nex_fee": self.nex_fee,
            "max_t1": t1, "min_t2": 10, "min_refund_window": 9, "min_margin": 3,
            "min_btc_fee_rate": 1, "min_btc_confirmations": 1, "min_nex_confirmations": 1,
        })
    }

    /// The browser prepares the offer in `config`, and the buyer's bitcoind
    /// wallet funds the browser's wallet with what it asks: the buyer, its
    /// wallet's address, and the rest of its output.
    fn browser_take(&self, config: &std::path::Path) -> (Party, String, JoinHandle<String>) {
        let mut buyer = browser("take", config);
        let mut reader = BufReader::new(buyer.0.stdout.take().unwrap());
        let mut line = String::new();
        reader.read_line(&mut line).unwrap();
        let wallet: Value = serde_json::from_str(&line).expect("the wallet");
        let amount = Amount::from_sat(wallet["need"].as_u64().unwrap());
        wallet_client(&self.bitcoind, "buyer")
            .call("sendtoaddress", json!([wallet["address"], amount.to_btc()]))
            .unwrap();
        let rest = thread::spawn(move || {
            let mut rest = String::new();
            reader.read_to_string(&mut rest).unwrap();
            rest
        });
        (buyer, wallet["address"].as_str().unwrap().into(), rest)
    }

    /// The state the browser's store holds for `swap_id`; empty before it
    /// holds one.
    fn browser_state(&self, swap_id: &str) -> String {
        let path = self.dir("browser").join(format!("swap:{swap_id}.json"));
        let Ok(text) = std::fs::read_to_string(path) else {
            return String::new();
        };
        let record: Value = serde_json::from_str(&text).unwrap();
        match serde_json::from_str::<Value>(record["state"].as_str().unwrap()).unwrap() {
            Value::Object(state) => state.keys().next().unwrap().clone(),
            state => panic!("a state: {state}"),
        }
    }

    /// What the buyer's bitcoind holds at `address` in blocks.
    fn received(&self, address: &str) -> Amount {
        let received = wallet_client(&self.bitcoind, "")
            .call(
                "scantxoutset",
                json!(["start", [format!("addr({address})")]]),
            )
            .unwrap();
        Amount::from_btc(received["total_amount"].as_f64().unwrap()).unwrap()
    }
}

/// The browser's buyer takes a CLI seller's offer from a relay, funded
/// from its wallet, and swaps; the change stays in its wallet.
#[test]
#[ignore = "needs Docker, NEXUS_NODE_IMAGE and web/driver built"]
fn the_browser_swaps_through_a_relay() {
    let world = World::new();
    let (url, relay) = relay();
    let (mut seller, offer, _, seller_out) = world.offer_on(20, 1, Some(&url));
    let config = world.browser_config(&offer, 20);
    let (mut buyer, wallet, buyer_out) = world.browser_take(&config);
    let (mut seller_done, mut buyer_done) = (None, None);
    world.drive(
        false,
        || true,
        || {
            seller_done = seller_done.or(seller.0.try_wait().unwrap());
            buyer_done = buyer_done.or(buyer.0.try_wait().unwrap());
            seller_done.is_some() && buyer_done.is_some()
        },
    );
    assert!(seller_done.unwrap().success());
    assert!(buyer_done.unwrap().success());
    assert_eq!(seller_out.join().unwrap(), "outcome: Swapped\n");
    assert_eq!(buyer_out.join().unwrap(), "outcome: swapped\n");
    assert_eq!(
        world.nexus.balance(&world.buyer_nex),
        NEX_AMOUNT - world.nex_fee
    );
    let seller_wallet = wallet_client(&world.bitcoind, "seller");
    assert_eq!(btc_balance(&seller_wallet), BTC_AMOUNT - BTC_FEE * 2);
    // The deposit less the lock and the funding's fee: under 1000 sat.
    let change = world.received(&wallet);
    assert!(change < Amount::from_sat(1_000), "{change}");
    assert!(relay.board.offers().is_empty());
}

/// The seller goes once the NEX is locked: the browser cancels at t1 and
/// refunds to its wallet.
#[test]
#[ignore = "needs Docker, NEXUS_NODE_IMAGE and web/driver built"]
fn the_browser_refunds_to_its_wallet_when_the_seller_goes() {
    let world = World::new();
    let (url, _relay) = relay();
    let (mut seller, offer, swap_id, seller_out) = world.offer_on(24, 2, Some(&url));
    let config = world.browser_config(&offer, 24);
    let (mut buyer, wallet, buyer_out) = world.browser_take(&config);
    world.drive(
        false,
        || true,
        || world.state("seller", &swap_id) == "AwaitRedeemSignature",
    );
    kill(&mut seller);
    seller_out.join().unwrap();
    let status = world.finish(&mut buyer, true, false);
    assert!(status.success(), "{status}");
    assert_eq!(buyer_out.join().unwrap(), "outcome: refunded\n");
    // The lock less cancel's and refund's fees, back in the wallet.
    let held = world.received(&wallet);
    assert!(held >= BTC_AMOUNT - BTC_FEE * 2, "{held}");
    assert!(held < BTC_AMOUNT, "{held}");
    assert_eq!(world.nexus.balance(&world.buyer_nex), 0);
}

/// The browser's page closed once its BTC lock is in a block, before the
/// seller's NEX lock lands, and opened again from its recovery file: it
/// meets the seller again at the relay, gets the CID it missed, and swaps.
#[test]
#[ignore = "needs Docker, NEXUS_NODE_IMAGE and web/driver built"]
fn the_browser_reloaded_after_the_lock_rejoins_to_the_swap() {
    let world = World::new();
    let (url, _relay) = relay();
    let (mut seller, offer, swap_id, seller_out) = world.offer_on(20, 1, Some(&url));
    let config = world.browser_config(&offer, 20);
    let (mut buyer, _, _) = world.browser_take(&config);
    world.drive(
        false,
        || false,
        || world.state("seller", &swap_id) == "LockingNex",
    );
    assert_eq!(world.browser_state(&swap_id), "AwaitNexLock");
    wait_for("the recovery file", || {
        world.dir("browser").join("backup").exists().then_some(())
    });
    kill(&mut buyer);
    world.drive(
        false,
        || true,
        || world.state("seller", &swap_id) == "AwaitRedeemSignature",
    );

    let mut buyer = browser("restore", &config);
    let (mut seller_done, mut buyer_done) = (None, None);
    world.drive(
        false,
        || true,
        || {
            seller_done = seller_done.or(seller.0.try_wait().unwrap());
            buyer_done = buyer_done.or(buyer.0.try_wait().unwrap());
            seller_done.is_some() && buyer_done.is_some()
        },
    );
    assert_eq!(seller_out.join().unwrap(), "outcome: Swapped\n");
    assert_eq!(stdout(&mut buyer.0), "outcome: swapped\n");
    assert_eq!(
        world.nexus.balance(&world.buyer_nex),
        NEX_AMOUNT - world.nex_fee
    );
}

/// The browser killed once it has seen the redeem and is claiming the NEX:
/// a fresh store restored from its recovery file carries on to the swap.
#[test]
#[ignore = "needs Docker, NEXUS_NODE_IMAGE and web/driver built"]
fn the_browser_killed_restores_from_its_recovery_file() {
    let world = World::new();
    let (url, _relay) = relay();
    let (mut seller, offer, swap_id, seller_out) = world.offer_on(20, 1, Some(&url));
    let config = world.browser_config(&offer, 20);
    let (mut buyer, _, _) = world.browser_take(&config);
    // Nexus stops once the seller holds the redeem signature: the claim
    // waits in the pool.
    let redeeming = || {
        matches!(
            world.state("seller", &swap_id).as_str(),
            "Redeeming" | "Done"
        )
    };
    world.drive(
        false,
        || !redeeming(),
        || world.browser_state(&swap_id) == "ClaimingNex",
    );
    kill(&mut buyer);
    let status = world.finish(&mut seller, false, false);
    assert!(status.success(), "{status}");
    assert_eq!(seller_out.join().unwrap(), "outcome: Swapped\n");

    let mut buyer = browser("restore", &config);
    let status = world.finish(&mut buyer, false, true);
    assert!(status.success(), "{status}");
    assert_eq!(stdout(&mut buyer.0), "outcome: swapped\n");
    assert_eq!(
        world.nexus.balance(&world.buyer_nex),
        NEX_AMOUNT - world.nex_fee
    );
}

/// The native buyer, `swap::app`, running a swap on a thread of this
/// process; stopped if the test ends first.
struct Native {
    wallet: Arc<Wallet>,
    stop: Arc<AtomicBool>,
    run: Option<JoinHandle<Result<Option<Outcome>, String>>>,
}

impl Native {
    fn start(wallet: Arc<Wallet>, buy: app::Buy) -> Self {
        let stop = Arc::new(AtomicBool::new(false));
        let stopping = stop.clone();
        let run = thread::spawn(move || {
            buy.run(|| stopping.load(Ordering::SeqCst))
                .map_err(|e| e.to_string())
        });
        Native {
            wallet,
            stop,
            run: Some(run),
        }
    }

    fn done(&self) -> bool {
        self.run.as_ref().is_none_or(JoinHandle::is_finished)
    }

    /// How the run ended.
    fn outcome(&mut self) -> Result<Option<Outcome>, String> {
        self.run.take().unwrap().join().unwrap()
    }

    /// Stops the run where it is, as an app closed, and waits for it.
    fn close(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        assert_eq!(self.outcome(), Ok(None));
    }
}

impl Drop for Native {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
    }
}

impl World {
    /// The native buyer's wallet in `dir`, through an Esplora shim over the
    /// regtest bitcoind and the node's RPC.
    fn native_config(&self, dir: &str) -> app::Config {
        let mut config = app::Config::new(
            self.dir(dir),
            Network::Regtest,
            esplora::esplora(wallet_client(&self.bitcoind, "")),
            self.nexus.url.clone(),
            self.nexus_cookie.clone(),
            self.nexus_genesis.clone(),
        );
        config.poll = Duration::from_millis(500);
        config
    }

    /// The native buyer prepares `offer`, its wallet is funded with what
    /// it needs, and it runs: the buyer and its wallet's address.
    fn native_take(&self, offer: &str, t1: u16) -> (Native, String) {
        let wallet = Wallet::open(self.native_config("native")).unwrap();
        let buy = wallet
            .prepare(offer, self.buyer_policy(t1), &self.buyer_nex)
            .unwrap();
        let status = buy.status().unwrap();
        assert_eq!(status["step"], "fund-wallet");
        let need = Amount::from_sat(status["need"].as_u64().unwrap());
        assert_eq!(
            need,
            Amount::from_sat(wallet.need(BTC_AMOUNT.to_sat()).unwrap().1)
        );
        let address = wallet.address().to_string();
        wallet_client(&self.bitcoind, "buyer")
            .call("sendtoaddress", json!([address, need.to_btc()]))
            .unwrap();
        (Native::start(wallet, buy), address)
    }

    /// The native buyer in `dir` opened again, as an app at launch, and the
    /// swap it runs resumed.
    fn native_resume(&self, dir: &str) -> Native {
        let wallet = Wallet::open(self.native_config(dir)).unwrap();
        let id = wallet.running().unwrap().expect("a swap that runs");
        let buy = wallet.resume(&id).unwrap();
        Native::start(wallet, buy)
    }

    /// Drives until the seller and `buyer` both end: the seller's output
    /// and the buyer's outcome.
    fn finish_both(
        &self,
        seller: &mut Party,
        buyer: &mut Native,
        seller_out: JoinHandle<String>,
    ) -> (String, Result<Option<Outcome>, String>) {
        let mut seller_done = None;
        self.drive(
            false,
            || true,
            || {
                seller_done = seller_done.or(seller.0.try_wait().unwrap());
                seller_done.is_some() && buyer.done()
            },
        );
        (seller_out.join().unwrap(), buyer.outcome())
    }
}

/// The native buyer takes a CLI seller's offer from a relay, funded from
/// its wallet, and swaps; the change stays in its wallet.
#[test]
#[ignore = "needs Docker and NEXUS_NODE_IMAGE"]
fn the_native_buyer_swaps_through_a_relay() {
    let world = World::new();
    let (url, relay) = relay();
    let (mut seller, offer, swap_id, seller_out) = world.offer_on(20, 1, Some(&url));
    let (mut buyer, wallet) = world.native_take(&offer, 20);
    let (seller_out, outcome) = world.finish_both(&mut seller, &mut buyer, seller_out);
    assert_eq!(seller_out, "outcome: Swapped\n");
    assert_eq!(outcome, Ok(Some(Outcome::Swapped)));
    assert_eq!(
        world.nexus.balance(&world.buyer_nex),
        NEX_AMOUNT - world.nex_fee
    );
    let seller_wallet = wallet_client(&world.bitcoind, "seller");
    assert_eq!(btc_balance(&seller_wallet), BTC_AMOUNT - BTC_FEE * 2);
    // The deposit less the lock and the funding's fee: under 1000 sat.
    let change = world.received(&wallet);
    assert!(change < Amount::from_sat(1_000), "{change}");
    assert!(relay.board.offers().is_empty());
    // Ended: nothing runs, and its status says so.
    let ended = buyer.wallet.resume(&swap_id).unwrap().status().unwrap();
    assert_eq!(ended["step"], "done");
    assert_eq!(ended["outcome"], "swapped");
    assert_eq!(buyer.wallet.running().unwrap(), None);
}

/// The native buyer closed once its BTC lock is in a block, before the
/// seller's NEX lock lands: opened again, as an app at launch, it finds the
/// swap that runs, meets the seller again at the relay, gets the CID it
/// missed, and swaps.
#[test]
#[ignore = "needs Docker and NEXUS_NODE_IMAGE"]
fn the_native_buyer_closed_after_the_lock_resumes_at_launch() {
    let world = World::new();
    let (url, _relay) = relay();
    let (mut seller, offer, swap_id, seller_out) = world.offer_on(20, 1, Some(&url));
    let (mut buyer, _) = world.native_take(&offer, 20);
    world.drive(
        false,
        || false,
        || world.state("seller", &swap_id) == "LockingNex",
    );
    assert_eq!(world.state("native", &swap_id), "AwaitNexLock");
    buyer.close();
    // The app closed: its wallet lets go of the directory.
    drop(buyer);
    world.drive(
        false,
        || true,
        || world.state("seller", &swap_id) == "AwaitRedeemSignature",
    );

    let mut buyer = world.native_resume("native");
    let (seller_out, outcome) = world.finish_both(&mut seller, &mut buyer, seller_out);
    assert_eq!(seller_out, "outcome: Swapped\n");
    assert_eq!(outcome, Ok(Some(Outcome::Swapped)));
    assert_eq!(
        world.nexus.balance(&world.buyer_nex),
        NEX_AMOUNT - world.nex_fee
    );
}

/// The seller goes once the NEX is locked: the native buyer cancels at t1
/// and refunds to its wallet.
#[test]
#[ignore = "needs Docker and NEXUS_NODE_IMAGE"]
fn the_native_buyer_refunds_to_its_wallet_when_the_seller_goes() {
    let world = World::new();
    let (url, _relay) = relay();
    let (mut seller, offer, swap_id, seller_out) = world.offer_on(24, 2, Some(&url));
    let (mut buyer, wallet) = world.native_take(&offer, 24);
    world.drive(
        false,
        || true,
        || world.state("seller", &swap_id) == "AwaitRedeemSignature",
    );
    kill(&mut seller);
    seller_out.join().unwrap();
    // The deadlines show, as the browser's do.
    let status = buyer.wallet.resume(&swap_id).unwrap().status().unwrap();
    assert_eq!(status["step"], "swapping");
    assert_eq!(status["backupCovers"], "lock");
    assert!(status["deadlines"]["cancel"]["height"].is_u64(), "{status}");
    world.drive(true, || false, || buyer.done());
    assert_eq!(buyer.outcome(), Ok(Some(Outcome::Refunded)));
    // The lock less cancel's and refund's fees, back in the wallet.
    let held = world.received(&wallet);
    assert!(held >= BTC_AMOUNT - BTC_FEE * 2, "{held}");
    assert!(held < BTC_AMOUNT, "{held}");
    assert_eq!(world.nexus.balance(&world.buyer_nex), 0);
}

/// The browser's page closed once its BTC lock is out: its recovery file,
/// restored natively, carries the swap on to its end.
#[test]
#[ignore = "needs Docker, NEXUS_NODE_IMAGE and web/driver built"]
fn the_browsers_recovery_file_restores_natively() {
    let world = World::new();
    let (url, _relay) = relay();
    let (mut seller, offer, swap_id, seller_out) = world.offer_on(20, 1, Some(&url));
    let config = world.browser_config(&offer, 20);
    let (mut browser, wallet, _) = world.browser_take(&config);
    world.drive(
        false,
        || false,
        || world.state("seller", &swap_id) == "LockingNex",
    );
    let backup = world.dir("browser").join("backup");
    wait_for("the recovery file", || backup.exists().then_some(()));
    kill(&mut browser);

    let file = std::fs::read_to_string(backup).unwrap();
    let restored = Wallet::restore(world.native_config("native"), &file).unwrap();
    assert_eq!(restored.address(), wallet);
    assert_eq!(
        restored.running().unwrap().as_deref(),
        Some(swap_id.as_str())
    );
    drop(restored);
    let mut buyer = world.native_resume("native");
    let (seller_out, outcome) = world.finish_both(&mut seller, &mut buyer, seller_out);
    assert_eq!(seller_out, "outcome: Swapped\n");
    assert_eq!(outcome, Ok(Some(Outcome::Swapped)));
    assert_eq!(
        world.nexus.balance(&world.buyer_nex),
        NEX_AMOUNT - world.nex_fee
    );
}

/// The native buyer closed once its BTC lock is out: its recovery file,
/// restored in the browser, carries the swap on to its end.
#[test]
#[ignore = "needs Docker, NEXUS_NODE_IMAGE and web/driver built"]
fn the_native_recovery_file_restores_in_the_browser() {
    let world = World::new();
    let (url, _relay) = relay();
    let (mut seller, offer, swap_id, seller_out) = world.offer_on(20, 1, Some(&url));
    let (mut buyer, _) = world.native_take(&offer, 20);
    world.drive(
        false,
        || false,
        || world.state("seller", &swap_id) == "LockingNex",
    );
    buyer.close();
    let (_, file) = buyer.wallet.backup().unwrap();
    std::fs::create_dir_all(world.dir("browser")).unwrap();
    std::fs::write(world.dir("browser").join("backup"), file).unwrap();

    let config = world.browser_config(&offer, 20);
    let mut browser = browser("restore", &config);
    let mut seller_done = None;
    world.drive(
        false,
        || true,
        || {
            seller_done = seller_done.or(seller.0.try_wait().unwrap());
            seller_done.is_some() && browser.0.try_wait().unwrap().is_some()
        },
    );
    assert_eq!(seller_out.join().unwrap(), "outcome: Swapped\n");
    assert_eq!(stdout(&mut browser.0), "outcome: swapped\n");
    assert_eq!(
        world.nexus.balance(&world.buyer_nex),
        NEX_AMOUNT - world.nex_fee
    );
}
