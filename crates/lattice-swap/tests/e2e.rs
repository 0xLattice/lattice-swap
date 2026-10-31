//! A whole swap through the `lattice-swap` binary: `offer` and `take` as
//! two processes, against a regtest bitcoind and a lattice-node in Docker.
//! The test, not the parties, mines blocks on both chains.
//!
//! Ignored by a plain `cargo test`; run with `NEXUS_NODE_IMAGE` naming the
//! node image and `-- --ignored`. The node's RPC listens on loopback only,
//! so its container shares the host's network.

use std::io::{BufRead, BufReader, Read};
use std::net::TcpListener;
use std::path::Path;
use std::process::{Child, Command, Output, Stdio};
use std::thread;
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
const NEX_AMOUNT: u64 = 1_000_000;

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

/// What both parties pass to reach their nodes.
fn node_args(bitcoind: &Node, wallet: &str, nexus: &Nexus, nexus_cookie: &Path) -> Vec<String> {
    let args = [
        "--btc-url",
        &bitcoind.rpc_url(),
        "--btc-wallet",
        wallet,
        "--btc-cookie",
        bitcoind.params.cookie_file.to_str().unwrap(),
        "--btc-network",
        "regtest",
        "--nexus-url",
        &nexus.url,
        "--nexus-cookie",
        nexus_cookie.to_str().unwrap(),
    ];
    args.map(String::from).to_vec()
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

#[test]
#[ignore = "needs Docker and NEXUS_NODE_IMAGE"]
fn happy_path_through_the_binary() {
    let mut conf = Conf::default();
    conf.args.push("-txindex");
    let bitcoind = Node::from_downloaded_with_conf(&conf).expect("start bitcoind");
    let miner = bitcoind.client.new_address().unwrap();
    bitcoind.client.generate_to_address(101, &miner).unwrap();
    for name in ["seller", "buyer"] {
        bitcoind.create_wallet(name).unwrap();
    }
    let (seller_wallet, buyer_wallet) = (
        wallet_client(&bitcoind, "seller"),
        wallet_client(&bitcoind, "buyer"),
    );
    let buyer_btc = buyer_wallet.call("getnewaddress", json!([])).unwrap();
    wallet_client(&bitcoind, "default")
        .call("sendtoaddress", json!([buyer_btc, 1.0]))
        .unwrap();
    bitcoind.client.generate_to_address(1, &miner).unwrap();

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

    let directory = tempfile::tempdir().unwrap();
    let nexus_cookie = directory.path().join("nexus.cookie");
    std::fs::write(&nexus_cookie, &nexus.cookie).unwrap();
    let key_file = directory.path().join("nex.key");
    std::fs::write(&key_file, hex::encode(seller_nex.0)).unwrap();
    let seller_dir = directory.path().join("seller");
    let buyer_dir = directory.path().join("buyer");

    // Small timelocks for regtest, with a floor of 1 + 6 x 2 + 3 = 16.
    let mut seller = Party(
        lattice_swap()
            .args(["offer", "--listen", "127.0.0.1:0"])
            .args(["--btc-amount", &BTC_AMOUNT.to_sat().to_string()])
            .args(["--btc-fee", &BTC_FEE.to_sat().to_string()])
            .args(["--nex-amount", &NEX_AMOUNT.to_string()])
            .args(["--nex-fee", &nex_fee.to_string()])
            .args(["--t1", "20", "--t2", "10", "--margin", "3"])
            .args(["--btc-confirmations", "1", "--nex-confirmations", "1"])
            .arg("--dir")
            .arg(&seller_dir)
            .arg("--nex-key-file")
            .arg(&key_file)
            .args(node_args(&bitcoind, "seller", &nexus, &nexus_cookie))
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
    let offer_file = directory.path().join("offer");
    std::fs::write(&offer_file, &offer).unwrap();
    // The rest of the seller's output, read as it comes so it never blocks.
    let seller_out = thread::spawn(move || {
        let mut rest = String::new();
        reader.read_to_string(&mut rest).unwrap();
        rest
    });

    let mut buyer = Party(
        lattice_swap()
            .arg("take")
            .arg(&offer_file)
            .args(["--nex-address", &buyer_nex])
            .args(["--min-nex-confirmations", "1"])
            .arg("--dir")
            .arg(&buyer_dir)
            .args(node_args(&bitcoind, "buyer", &nexus, &nexus_cookie))
            .stdout(Stdio::piped())
            .spawn()
            .unwrap(),
    );

    // Mines whenever either pool holds something, until both parties exit.
    let deadline = Instant::now() + Duration::from_secs(600);
    let (mut seller_done, mut buyer_done) = (None, None);
    while seller_done.is_none() || buyer_done.is_none() {
        assert!(Instant::now() < deadline, "the swap timed out");
        seller_done = seller_done.or(seller.0.try_wait().unwrap());
        buyer_done = buyer_done.or(buyer.0.try_wait().unwrap());
        let mempool = wallet_client(&bitcoind, "")
            .call("getmempoolinfo", json!([]))
            .unwrap();
        if mempool["size"].as_u64() > Some(0) {
            bitcoind.client.generate_to_address(1, &miner).unwrap();
        }
        if nexus.pending() > 0 {
            nexus.mine(None);
        }
        thread::sleep(Duration::from_millis(400));
    }
    assert!(seller_done.unwrap().success());
    assert!(buyer_done.unwrap().success());
    assert_eq!(seller_out.join().unwrap(), "outcome: Swapped\n");
    assert_eq!(stdout(&mut buyer.0), "outcome: Swapped\n");

    assert_eq!(nexus.balance(&buyer_nex), NEX_AMOUNT - nex_fee);
    assert_eq!(
        nexus.balance(&seller_nex.nex_address()),
        2 * REWARD - NEX_AMOUNT - nex_fee
    );
    assert_eq!(btc_balance(&seller_wallet), BTC_AMOUNT - BTC_FEE);

    // `status` reads each swap file and asks no node.
    for dir in [&seller_dir, &buyer_dir] {
        let swap_file = dir.join(format!("{swap_id}.json"));
        let Output { status, stdout, .. } = lattice_swap()
            .arg("status")
            .arg(&swap_file)
            .output()
            .unwrap();
        assert!(status.success());
        assert_eq!(
            String::from_utf8(stdout).unwrap(),
            "state: Done\noutcome: Swapped\n"
        );
    }
}
