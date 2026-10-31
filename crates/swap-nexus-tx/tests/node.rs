//! Against a real lattice-node in Docker. Ignored by a plain `cargo test`;
//! run it with `NEXUS_NODE_IMAGE` naming the image (e.g.
//! `ghcr.io/0xlattice/lattice-node:3.2.0`) and `-- --ignored`. Without the
//! image it fails rather than passing untested.
//!
//! The node's RPC listens on loopback only, so the container shares the
//! host's network (`--network host`): Linux, or Docker Desktop with host
//! networking enabled.

use std::net::TcpListener;
use std::process::Command;
use std::time::{Duration, Instant};

use ed25519_dalek::SigningKey;
use rand_core::{OsRng, RngCore};
use swap_nexus::{JointKey, KeyShare};
use swap_nexus_tx::rpc::{Client, Error};
use swap_nexus_tx::{address, Transaction, TransactionBody};

const TIMEOUT: Duration = Duration::from_secs(10);

/// Nexus's block reward over its first halving interval.
const REWARD: u64 = 1_048_576;

struct Node {
    container: String,
    url: String,
    client: Client,
}

impl Node {
    fn start(image: &str) -> Self {
        let (rpc, p2p) = (free_port(), free_port());
        let script = format!(
            "lattice-node --data-directory /tmp/d --identity-key /tmp/p.key \
             --listen-port {p2p} --rpc-port {rpc} --websocket-port 0 --no-default-peers"
        );
        let container = docker(&[
            "run",
            "-d",
            "--network",
            "host",
            "--platform",
            "linux/amd64",
            "--entrypoint",
            "sh",
            image,
            "-c",
            &script,
        ]);
        let url = format!("http://127.0.0.1:{rpc}");
        let mut node = Node {
            client: Client::new(&url, "", TIMEOUT),
            container,
            url,
        };
        let cookie = wait_for("node cookie", || {
            let out = Command::new("docker")
                .args(["exec", &node.container, "cat", "/tmp/d/.cookie"])
                .output()
                .unwrap();
            out.status
                .success()
                .then(|| String::from_utf8(out.stdout).unwrap())
        });
        node.client = Client::new(&node.url, &cookie, TIMEOUT);
        wait_for("node RPC", || node.client.min_relay_fee().ok());
        node
    }

    /// Mines one block, paying its reward and fees to `recipient` or, with
    /// `None`, burning them, and waits until the node executes it.
    fn mine(&self, recipient: Option<&str>) {
        let height = self.client.health().unwrap().height;
        let mut args = vec![
            "exec".to_string(),
            self.container.clone(),
            "lattice-mining-coordinator".into(),
            "--node".into(),
            self.url.clone(),
            "--rpc-cookie-file".into(),
            "/tmp/d/.cookie".into(),
            "--workers".into(),
            "1".into(),
            "--batch-size".into(),
            "1000".into(),
            "--once".into(),
        ];
        if let Some(address) = recipient {
            args.extend(["--recipient".into(), format!("Nexus={address}")]);
        }
        wait_for("a mined block", || {
            if self.client.health().unwrap().height > height {
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
        assert_eq!(self.client.health().unwrap().height, height + 1);
    }

    /// Submits, mines it into a block that burns its fee, and waits until the
    /// node reports it in the tip.
    fn confirm(&self, transaction: &Transaction) -> String {
        let cid = self.client.submit(transaction).unwrap();
        assert_eq!(cid, transaction.cid(), "the node names it as we do");
        assert_eq!(self.client.confirmations(&cid).unwrap(), None);
        self.mine(None);
        // Inclusion is read from the executed chain, which can trail the
        // mining reply.
        let depth = wait_for("inclusion", || self.client.confirmations(&cid).unwrap());
        assert_eq!(depth, 1);
        cid
    }
}

impl Drop for Node {
    fn drop(&mut self) {
        let _ = Command::new("docker")
            .args(["rm", "-f", &self.container])
            .output();
    }
}

fn docker(args: &[&str]) -> String {
    let out = Command::new("docker").args(args).output().unwrap();
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    String::from_utf8(out.stdout).unwrap().trim().into()
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
        std::thread::sleep(Duration::from_millis(250));
    }
}

fn random_key() -> SigningKey {
    let mut seed = [0u8; 32];
    OsRng.fill_bytes(&mut seed);
    SigningKey::from_bytes(&seed)
}

fn addr(key: &SigningKey) -> String {
    address(&key.verifying_key().to_bytes())
}

fn refusal(node: &Node, transaction: &Transaction) -> String {
    match node.client.submit(transaction) {
        Err(Error::Status { status: 400, body }) => body,
        other => panic!("expected a 400 refusal, got {other:?}"),
    }
}

#[test]
#[ignore = "needs Docker and NEXUS_NODE_IMAGE"]
fn node_accepts_transfers_and_joint_key_spends() {
    let image = std::env::var("NEXUS_NODE_IMAGE").expect("NEXUS_NODE_IMAGE names the node image");
    let node = Node::start(&image);
    let health = node.client.health().unwrap();
    assert_eq!(health.phase, "active");
    assert_eq!(health.best_header_height, Some(health.height));
    let fee = node.client.min_relay_fee().unwrap();
    let (a, b, c) = (random_key(), random_key(), random_key());
    let (a_addr, b_addr, c_addr) = (addr(&a), addr(&b), addr(&c));

    // 1. An ordinary transfer, with the relay floor as its fee.
    node.mine(Some(&a_addr));
    node.mine(Some(&a_addr));
    let funded = node.client.account(&a_addr).unwrap();
    assert_eq!((funded.balance, funded.nonce), (2 * REWARD, 0));

    let mut transfer =
        Transaction::new(TransactionBody::transfer(&a_addr, &b_addr, 1_000, fee, 0).unwrap());
    transfer.sign(&a);
    node.confirm(&transfer);
    let sender = node.client.account(&a_addr).unwrap();
    assert_eq!(
        (sender.balance, sender.nonce),
        (2 * REWARD - 1_000 - fee, 1)
    );
    assert_eq!(node.client.account(&b_addr).unwrap().balance, 1_000);

    // 2. Lock at the joint key's address, then claim with the joint key.
    let joint = JointKey::from_shares(&KeyShare::random(), &KeyShare::random());
    let lock = address(&joint.public_key());
    let unseen = node.client.account(&lock).unwrap();
    assert_eq!((unseen.balance, unseen.nonce), (0, 0));
    let mut fund =
        Transaction::new(TransactionBody::transfer(&a_addr, &lock, 50_000, fee, 1).unwrap());
    fund.sign(&a);
    let fund_cid = node.confirm(&fund);
    // What the claimer checks before trusting the lock: the funding
    // transaction's contents and where it was mined.
    let seen = node.client.transaction(&fund_cid).unwrap().unwrap();
    assert_eq!(seen.body, fund.body);
    let block = seen.block.unwrap();
    assert_eq!(block.height, node.client.health().unwrap().height);
    assert!(block.hash.starts_with("bafy"));
    // The tip and the block at its height are named by the same CID; a
    // height past the tip names none.
    let tip = node.client.health().unwrap();
    assert_eq!(tip.tip.as_deref(), Some(block.hash.as_str()));
    assert_eq!(node.client.block_hash(tip.height).unwrap(), tip.tip);
    assert_eq!(node.client.block_hash(tip.height + 1000).unwrap(), None);
    assert!(node.client.transaction(&fund.body.cid()).unwrap().is_none());
    assert_eq!(node.client.account(&lock).unwrap().balance, 50_000);

    let mut claim =
        Transaction::new(TransactionBody::transfer(&lock, &c_addr, 50_000 - fee, fee, 0).unwrap());
    claim.sign_joint(&joint);
    let claim_cid = node.confirm(&claim);
    let locked = node.client.account(&lock).unwrap();
    assert_eq!((locked.balance, locked.nonce), (0, 1));
    assert_eq!(node.client.account(&c_addr).unwrap().balance, 50_000 - fee);
    node.mine(None);
    wait_for("a second confirmation", || {
        (node.client.confirmations(&claim_cid).unwrap() == Some(2)).then_some(())
    });

    // 3. Refusals: a signature by a key that is not the signer, and a body
    // changed after signing.
    let body = TransactionBody::transfer(&b_addr, &c_addr, 10, fee, 0).unwrap();
    let mut wrong_key = Transaction::new(body.clone());
    wrong_key.sign(&c);
    let wrong_key = refusal(&node, &wrong_key);
    eprintln!("wrong key refused: {wrong_key}");

    let mut tampered = Transaction::new(body.clone());
    tampered.sign(&b);
    tampered.body.account_actions[1].delta += 1;
    tampered.body.account_actions[0].delta -= 1;
    let tampered = refusal(&node, &tampered);
    eprintln!("tampered body refused: {tampered}");

    // The same body, signed by its signer, is admitted: the refusals above
    // were the signatures.
    let mut signed = Transaction::new(body);
    signed.sign(&b);
    node.client.submit(&signed).unwrap();
}
