//! Whole swaps through the `lattice-swap` binary: `offer` and `take` as two
//! processes, killed and carried on with `resume`, against a regtest
//! bitcoind and a lattice-node in Docker, each test its own. The test, not
//! the parties, mines blocks on both chains.
//!
//! Ignored by a plain `cargo test`; run with `NEXUS_NODE_IMAGE` naming the
//! node image and `-- --ignored`. The node's RPC listens on loopback only,
//! so its container shares the host's network.

use std::io::{BufRead, BufReader, Read};
use std::net::TcpListener;
use std::path::PathBuf;
use std::process::{Child, Command, ExitStatus, Output, Stdio};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use bitcoin::{Amount, Denomination, Network};
use corepc_node::{Conf, Node};
use ed25519_dalek::SigningKey;
use rand_core::{OsRng, RngCore};
use serde_json::{json, Value};
use swap::bitcoind::Bitcoind;
use swap::SecretBytes;
use swap_nexus_tx::address;
use swap_nexus_tx::rpc::Client;

const TIMEOUT: Duration = Duration::from_secs(10);
/// Nexus's block reward over its first halving interval.
const REWARD: u64 = 1_048_576;
const BTC_AMOUNT: Amount = Amount::from_sat(50_000_000);
const BTC_FEE: Amount = Amount::from_sat(1_000);
/// Below every swap transaction's own feerate, as the fallback for
/// regtest's missing estimate and as the cap: nothing is bumped, and each
/// costs exactly `BTC_FEE`, but redeem, which pays two.
const NO_BUMP: [&str; 4] = ["--fallback-fee-rate", "1", "--max-fee-rate", "1"];
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

/// A lattice-node in Docker, as in the swap crate's end-to-end tests.
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
        let (t1, nex_confirmations) = (t1.to_string(), nex_confirmations.to_string());
        let nex_fee = self.nex_fee.to_string();
        let mut seller = Party(
            lattice_swap()
                .args(["offer", "--listen", "127.0.0.1:0"])
                .args(["--btc-amount", &BTC_AMOUNT.to_sat().to_string()])
                .args(["--btc-fee", &BTC_FEE.to_sat().to_string()])
                // Regtest has no fee estimate.
                .args(["--min-btc-fee-rate", "1"])
                .args(["--nex-amount", &NEX_AMOUNT.to_string()])
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
        let swap_id = serde_json::from_str::<Value>(&offer).unwrap()["terms"]["swap_id"]
            .as_str()
            .unwrap()
            .to_string();
        let offer_file = self.directory.path().join("offer");
        std::fs::write(&offer_file, &offer).unwrap();
        // The rest of the seller's output, read as it comes so it never
        // blocks.
        let seller_out = thread::spawn(move || {
            let mut rest = String::new();
            reader.read_to_string(&mut rest).unwrap();
            rest
        });

        let buyer = Party(
            lattice_swap()
                .arg("take")
                .arg(&offer_file)
                .args(["--nex-address", &self.buyer_nex])
                .args(["--btc-amount", &BTC_AMOUNT.to_sat().to_string()])
                .args(["--nex-amount", &NEX_AMOUNT.to_string()])
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
