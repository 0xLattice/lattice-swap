//! A blocking client for the few routes of a Lattice node's operator RPC
//! (lattice-node 3.2.0) the swap needs: check which Nexus the node follows
//! and that it is synced, read an account, submit a transaction, and read
//! back a transaction and whether it is mined.
//!
//! The operator port listens on loopback only and takes the node's cookie
//! (`<data-directory>/.cookie`, `__cookie__:<token>`) as HTTP basic auth. It
//! changes at every node restart. Every 64-bit integer on this API is a
//! decimal string.

#[cfg(feature = "native")]
use std::io::Read;
#[cfg(feature = "native")]
use std::time::Duration;
#[cfg(feature = "native")]
use std::{fmt, fs, io, path::Path};

#[cfg(feature = "native")]
use base64::Engine;
use serde::{Deserialize, Serialize};
#[cfg(feature = "native")]
use serde_json::Value;

#[cfg(feature = "native")]
use crate::Transaction;
use crate::{AccountAction, TransactionBody};

#[cfg(feature = "native")]
#[derive(Debug)]
pub enum Error {
    /// The node answered with a non-2xx status; `body` names the refusal
    /// (for a submit: `belowMinRelayFee`, `nonceAhead`, ...).
    Status {
        status: u16,
        body: String,
    },
    Transport(String),
    /// A 2xx answer without the expected field.
    Malformed(String),
    /// An address or transaction CID not spelled as [`crate::cid`] spells
    /// one. It is refused before any request, so it never reaches the URL.
    NotCid(String),
}

#[cfg(feature = "native")]
impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::Status { status, body } => write!(f, "node answered {status}: {body}"),
            Error::Transport(e) => write!(f, "node unreachable: {e}"),
            Error::Malformed(e) => write!(f, "unexpected node answer: {e}"),
            Error::NotCid(text) => write!(f, "not a CID: {text:?}"),
        }
    }
}

#[cfg(feature = "native")]
impl std::error::Error for Error {}

#[cfg(feature = "native")]
pub type Result<T> = std::result::Result<T, Error>;

/// An account at the node's current tip.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Account {
    pub balance: u64,
    /// The nonce the account's next transaction must carry.
    pub nonce: u64,
}

/// `GET /health`: a caller should refuse a node that is not `active` or
/// whose `height` trails `best_header_height` (still syncing).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Health {
    pub phase: String,
    /// Height of the heaviest executed tip, the block the node acts on.
    pub height: u64,
    /// Height of the best header chain the node knows; `None` before any.
    pub best_header_height: Option<u64>,
    /// CID of the block at `height`; `None` before any.
    pub tip: Option<String>,
}

/// A transaction the node holds, as `GET /api/transaction/:cid` shows it.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct TransactionStatus {
    /// Rebuilt from the node's explorer view, which lists account actions,
    /// signers, nonce and chain path but not general `actions`; a transaction
    /// with deposit, receipt or withdrawal actions is an error instead.
    /// Because `actions` may be missing, this is not necessarily the body that
    /// was signed: do not hash or verify it. Use it only to read what the
    /// transaction credits.
    pub body: TransactionBody,
    /// The canonical block that executed it, if any.
    pub block: Option<Inclusion>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Inclusion {
    pub height: u64,
    pub hash: String,
}

/// Every answer this client reads is small; a larger one is refused rather
/// than buffered.
#[cfg(feature = "native")]
const MAX_RESPONSE_BYTES: u64 = 1 << 20;

#[cfg(feature = "native")]
pub struct Client {
    agent: ureq::Agent,
    base: String,
    authorization: String,
}

#[cfg(feature = "native")]
impl Client {
    /// `base` is like `http://127.0.0.1:8080`; `cookie` is the cookie file's
    /// content. `timeout` bounds each request as a whole, so a stalled node
    /// fails the call instead of blocking it.
    pub fn new(base: &str, cookie: &str, timeout: Duration) -> Self {
        let token = base64::engine::general_purpose::STANDARD.encode(cookie.trim());
        Self {
            agent: ureq::AgentBuilder::new().timeout(timeout).build(),
            base: base.trim_end_matches('/').into(),
            authorization: format!("Basic {token}"),
        }
    }

    pub fn from_cookie_file(
        base: &str,
        path: impl AsRef<Path>,
        timeout: Duration,
    ) -> io::Result<Self> {
        Ok(Self::new(base, &fs::read_to_string(path)?, timeout))
    }

    pub fn health(&self) -> Result<Health> {
        parse::health(&self.get("/health")?).map_err(Error::Malformed)
    }

    /// The CID of the canonical block at `height`, or `None` if the node has
    /// none there (404).
    pub fn block_hash(&self, height: u64) -> Result<Option<String>> {
        let json = match self.get(&format!("/api/block/{height}")) {
            Ok(json) => json,
            Err(Error::Status { status: 404, .. }) => return Ok(None),
            Err(e) => return Err(e),
        };
        parse::block_hash(&json).map(Some).map_err(Error::Malformed)
    }

    /// The smallest fee this node pools: a whole-transaction amount (debits
    /// less credits), not a rate. Node policy, not consensus.
    pub fn min_relay_fee(&self) -> Result<u64> {
        parse::min_relay_fee(&self.get("/api/chain/info")?).map_err(Error::Malformed)
    }

    /// The CID of the genesis block of the Nexus the node follows: the block
    /// at height 0 of its canonical root chain, which `/api/chain/info`
    /// names when asked for no other chain.
    pub fn genesis(&self) -> Result<String> {
        let genesis = parse::genesis(&self.chain_info()?).map_err(Error::Malformed)?;
        Ok(cid_path(&genesis)?.into())
    }

    /// `GET /api/chain/info` as the node answered it, for
    /// [`parse::check_node`].
    pub fn chain_info(&self) -> Result<Value> {
        self.get("/api/chain/info")
    }

    /// The account at the tip. The node answers balance 0, nonce 0 for an
    /// address it has never seen; a 404 means it has no executed tip (or is
    /// not a node of this version), so it stays an error.
    pub fn account(&self, address: &str) -> Result<Account> {
        let json = self.get(&format!("/api/state/account/{}", cid_path(address)?))?;
        parse::account(&json).map_err(Error::Malformed)
    }

    /// The account after the block `block_cid`, or `None` if the node has
    /// no state there (404): it does not know the block, or keeps no state
    /// of past blocks.
    pub fn account_at(&self, address: &str, block_cid: &str) -> Result<Option<Account>> {
        let path = format!(
            "/accounts/{}?block={}",
            cid_path(address)?,
            cid_path(block_cid)?
        );
        let json = match self.get(&path) {
            Ok(json) => json,
            Err(Error::Status { status: 404, .. }) => return Ok(None),
            Err(e) => return Err(e),
        };
        parse::account(&json).map(Some).map_err(Error::Malformed)
    }

    /// Submits to the node's pool and returns the transaction CID (of the
    /// signed transaction, not of its body: [`Transaction::cid`]).
    pub fn submit(&self, transaction: &Transaction) -> Result<String> {
        let response = self
            .agent
            .post(&format!("{}/transactions", self.base))
            .set("Authorization", &self.authorization)
            .send_json(transaction.to_submit_json());
        let json = read(response)?;
        json["transactionCID"]
            .as_str()
            .map(String::from)
            .ok_or_else(|| Error::Malformed(format!("no transactionCID in {json}")))
    }

    /// The transaction `transaction_cid` names, or `None` if the node does not
    /// hold it (404: never seen, or not stored here).
    pub fn transaction(&self, transaction_cid: &str) -> Result<Option<TransactionStatus>> {
        let path = format!("/api/transaction/{}", cid_path(transaction_cid)?);
        let json = match self.get(&path) {
            Ok(json) => json,
            Err(Error::Status { status: 404, .. }) => return Ok(None),
            Err(e) => return Err(e),
        };
        parse::transaction(&json)
            .map(Some)
            .map_err(Error::Malformed)
    }

    /// Blocks on top of and including the canonical block that executed
    /// `transaction_cid` (1 = in the tip), or `None` while it is not in the
    /// canonical chain: pending, unknown to this node, or dropped by a reorg.
    ///
    /// The node derives the including block from its canonical chain on every
    /// read, so the answer follows reorgs. The transaction is read before and
    /// after the tip height; if its block changed in between, the chain moved
    /// under the read and the answer is `None`.
    pub fn confirmations(&self, transaction_cid: &str) -> Result<Option<u64>> {
        let block = |client: &Self| -> Result<Option<Inclusion>> {
            Ok(client.transaction(transaction_cid)?.and_then(|tx| tx.block))
        };
        let Some(before) = block(self)? else {
            return Ok(None);
        };
        let height = self.health()?.height;
        Ok(parse::confirmations(
            Some(&before),
            height,
            block(self)?.as_ref(),
        ))
    }

    fn get(&self, path: &str) -> Result<Value> {
        read(
            self.agent
                .get(&format!("{}{path}", self.base))
                .set("Authorization", &self.authorization)
                .call(),
        )
    }
}

#[cfg(feature = "native")]
fn cid_path(text: &str) -> Result<&str> {
    if crate::is_cid(text) {
        Ok(text)
    } else {
        Err(Error::NotCid(text.into()))
    }
}

#[cfg(feature = "native")]
fn read(response: std::result::Result<ureq::Response, ureq::Error>) -> Result<Value> {
    let (status, response) = match response {
        Ok(response) => (None, response),
        Err(ureq::Error::Status(status, response)) => (Some(status), response),
        Err(e) => return Err(Error::Transport(e.to_string())),
    };
    let mut bytes = Vec::new();
    response
        .into_reader()
        .take(MAX_RESPONSE_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|e| Error::Transport(e.to_string()))?;
    if bytes.len() as u64 > MAX_RESPONSE_BYTES {
        return Err(Error::Malformed("answer over 1 MiB".into()));
    }
    match status {
        Some(status) => Err(Error::Status {
            status,
            body: String::from_utf8_lossy(&bytes).into(),
        }),
        None => serde_json::from_slice(&bytes).map_err(|e| Error::Malformed(e.to_string())),
    }
}

/// Reading the node's answers apart from fetching them: [`Client`] reads
/// them so, and so does a browser that fetched the same routes itself.
/// Each takes a route's JSON and fails, naming what is wrong, on one that
/// is not as the node writes it.
pub mod parse {
    use super::{Account, AccountAction, Health, Inclusion, TransactionBody, TransactionStatus};
    use serde_json::Value;

    /// `GET /health`.
    pub fn health(json: &Value) -> Result<Health, String> {
        let best_header_height = match json.get("bestHeaderHeight") {
            Some(_) => Some(decimal(json, "bestHeaderHeight")?),
            None => None,
        };
        Ok(Health {
            phase: json["phase"]
                .as_str()
                .ok_or_else(|| format!("no phase in {json}"))?
                .into(),
            height: decimal(json, "height")?,
            best_header_height,
            tip: json["tipCID"].as_str().map(String::from),
        })
    }

    /// `GET /api/chain/info`, asked for no other chain: the genesis of the
    /// Nexus the node follows, the block at height 0 of its root chain.
    pub fn genesis(json: &Value) -> Result<String, String> {
        if json["chain"] != serde_json::json!(["Nexus"]) {
            return Err(format!("not the Nexus chain: {json}"));
        }
        json["genesisHash"]
            .as_str()
            .map(String::from)
            .ok_or_else(|| format!("no genesisHash in {json}"))
    }

    /// The height of the block after which a node is asked for an account,
    /// to tell whether it keeps the state of past blocks: halfway up its
    /// chain of `height`, or none for a chain too short to tell.
    pub fn past_state_probe(height: u64) -> Option<u64> {
        (height >= 2).then(|| height.div_ceil(2))
    }

    /// Why a node will not do for a swap on the Nexus of `expected_genesis`.
    #[derive(Clone, Debug, PartialEq, Eq)]
    pub enum NodeRefusal {
        /// Its `/api/chain/info` is not a root chain's: what is wrong.
        Malformed(String),
        /// It follows the Nexus of `genesis`, not of `expected`, where a
        /// NEX lock is worthless.
        OtherNexus { genesis: String, expected: String },
        /// It keeps no state of past blocks, so every NEX lock would look
        /// unmined and every claim drained.
        NoPastState,
    }

    impl std::fmt::Display for NodeRefusal {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            match self {
                NodeRefusal::Malformed(e) => write!(f, "unexpected node answer: {e}"),
                NodeRefusal::OtherNexus { genesis, expected } => write!(
                    f,
                    "refused: the Nexus node follows the chain of genesis {genesis}, not {expected}"
                ),
                NodeRefusal::NoPastState => write!(
                    f,
                    "the Nexus node keeps no state of past blocks, so it cannot tell how deep a \
                     transaction is"
                ),
            }
        }
    }

    /// Judges a node for a swap on the Nexus of `expected_genesis`, from
    /// its `/api/chain/info`, its `height`, and `past_state`: whether it
    /// showed an account after the block at [`past_state_probe`], `None`
    /// where there is no such block to ask after. Every swap tool asks the
    /// same of its node, whatever reads it.
    pub fn check_node(
        expected_genesis: &str,
        chain_info: &Value,
        height: u64,
        past_state: Option<bool>,
    ) -> Result<(), NodeRefusal> {
        let genesis = genesis(chain_info).map_err(NodeRefusal::Malformed)?;
        if genesis != expected_genesis {
            let expected = expected_genesis.into();
            return Err(NodeRefusal::OtherNexus { genesis, expected });
        }
        match (past_state_probe(height), past_state) {
            (None, _) | (Some(_), Some(true)) => Ok(()),
            (Some(_), _) => Err(NodeRefusal::NoPastState),
        }
    }

    /// `GET /api/block/:height`: the block's CID.
    pub fn block_hash(json: &Value) -> Result<String, String> {
        json["hash"]
            .as_str()
            .map(String::from)
            .ok_or_else(|| format!("no hash in {json}"))
    }

    /// `GET /api/chain/info`: the smallest fee the node pools.
    pub fn min_relay_fee(json: &Value) -> Result<u64, String> {
        decimal(json, "minRelayFee")
    }

    /// `GET /api/state/account/:address`, or `/accounts/:address?block=`.
    pub fn account(json: &Value) -> Result<Account, String> {
        Ok(Account {
            balance: decimal(json, "balance")?,
            nonce: decimal(json, "nonce")?,
        })
    }

    /// `GET /api/transaction/:cid`.
    pub fn transaction(json: &Value) -> Result<TransactionStatus, String> {
        for kind in ["depositActions", "receiptActions", "withdrawalActions"] {
            if json[kind].as_array().is_none_or(|list| !list.is_empty()) {
                return Err(format!("{kind} not empty in {json}"));
            }
        }
        let strings = |field: &str| -> Result<Vec<String>, String> {
            json[field]
                .as_array()
                .and_then(|list| list.iter().map(|s| s.as_str().map(String::from)).collect())
                .ok_or_else(|| format!("{field} is not a string list in {json}"))
        };
        let account_actions = json["accountActions"]
            .as_array()
            .ok_or_else(|| format!("no accountActions in {json}"))?
            .iter()
            .map(|action| {
                Ok(AccountAction {
                    owner: action["owner"]
                        .as_str()
                        .ok_or_else(|| format!("no owner in {action}"))?
                        .into(),
                    delta: decimal(action, "delta")?,
                })
            })
            .collect::<Result<_, String>>()?;
        let block = match json.get("blockHeight") {
            Some(_) => Some(Inclusion {
                height: decimal(json, "blockHeight")?,
                hash: json["blockHash"]
                    .as_str()
                    .ok_or_else(|| format!("no blockHash in {json}"))?
                    .into(),
            }),
            None => None,
        };
        Ok(TransactionStatus {
            body: TransactionBody {
                account_actions,
                signers: strings("signers")?,
                nonce: decimal(json, "nonce")?,
                chain_path: strings("chainPath")?,
            },
            block,
        })
    }

    /// Blocks on top of and including the canonical block that executed a
    /// transaction, from its block read `before` and `after` the tip
    /// `height`: `None` while it is in no canonical block, or if its block
    /// changed in between, as the chain moved under the reads.
    pub fn confirmations(
        before: Option<&Inclusion>,
        height: u64,
        after: Option<&Inclusion>,
    ) -> Option<u64> {
        let before = before?;
        if after != Some(before) {
            return None;
        }
        height.checked_sub(before.height).map(|depth| depth + 1)
    }

    fn decimal<T: std::str::FromStr>(json: &Value, field: &str) -> Result<T, String> {
        json[field]
            .as_str()
            .and_then(|text| text.parse().ok())
            .ok_or_else(|| format!("{field} is not a decimal string in {json}"))
    }
}

#[cfg(feature = "native")]
#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use std::net::TcpListener;

    /// A client whose node answers every request with `json`.
    fn answering(json: serde_json::Value) -> Client {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let url = format!("http://{}", listener.local_addr().unwrap());
        std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut request = [0u8; 4096];
            let _ = stream.read(&mut request);
            let body = json.to_string();
            let head = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                body.len()
            );
            stream.write_all(head.as_bytes()).unwrap();
            stream.write_all(body.as_bytes()).unwrap();
        });
        Client::new(&url, "cookie", Duration::from_secs(5))
    }

    #[test]
    fn the_tip_and_a_block_are_named_by_cid() {
        let health = serde_json::json!({"phase": "active", "height": "7", "tipCID": "bafytip"});
        assert_eq!(
            answering(health).health().unwrap().tip,
            Some("bafytip".into())
        );
        let block = serde_json::json!({"height": "7", "hash": "bafytip"});
        assert_eq!(
            answering(block).block_hash(7).unwrap(),
            Some("bafytip".into())
        );
    }

    #[test]
    fn the_genesis_is_the_root_chains_and_a_cid() {
        let info = |chain: serde_json::Value, genesis: serde_json::Value| {
            let json = serde_json::json!({"chain": chain, "genesisHash": genesis});
            answering(json).genesis()
        };
        let nexus = || serde_json::json!(["Nexus"]);
        let genesis = crate::MAINNET_GENESIS;
        assert!(crate::is_cid(genesis));
        assert_eq!(info(nexus(), genesis.into()).unwrap(), genesis);
        let child = info(serde_json::json!(["Nexus", "Child"]), genesis.into());
        assert!(matches!(child, Err(Error::Malformed(_))), "{child:?}");
        let none = info(nexus(), serde_json::Value::Null);
        assert!(matches!(none, Err(Error::Malformed(_))), "{none:?}");
        let upper = info(nexus(), genesis.to_ascii_uppercase().into());
        assert!(matches!(upper, Err(Error::NotCid(_))), "{upper:?}");
    }

    #[test]
    fn transactions_with_other_actions_are_refused() {
        let answer = serde_json::json!({
            "accountActions": [{"owner": "a", "delta": "5"}],
            "depositActions": [],
            "receiptActions": [],
            "withdrawalActions": [],
            "signers": ["a"],
            "nonce": "0",
            "chainPath": ["Nexus"],
        });
        let cid = crate::cid(b"transaction");
        let status = answering(answer.clone())
            .transaction(&cid)
            .unwrap()
            .unwrap();
        assert_eq!(status.body.account_actions[0].delta, 5);
        for kind in ["depositActions", "receiptActions", "withdrawalActions"] {
            let mut answer = answer.clone();
            answer[kind] = serde_json::json!([{}]);
            let result = answering(answer).transaction(&cid);
            assert!(
                matches!(result, Err(Error::Malformed(_))),
                "{kind}: {result:?}"
            );
        }
    }

    #[test]
    fn only_canonical_cids_reach_the_url() {
        let cid = crate::cid(b"transaction");
        assert_eq!(cid.len(), 59);
        let address = crate::address(&[7; 32]);
        let account = serde_json::json!({"balance": "5", "nonce": "1"});
        assert_eq!(answering(account).account(&address).unwrap().balance, 5);
        let bad = [
            format!("../{cid}"),
            format!("{}../", &cid[..56]),
            format!("{cid}?x=1"),
            format!("{}?", &cid[..58]),
            format!("{}#", &cid[..58]),
            format!("{}/", &cid[..58]),
            cid[..58].into(),
            format!("{cid}a"),
            format!("{cid}aaaaaaaa"),
            cid.to_ascii_uppercase(),
            format!("b{}", cid[1..].to_ascii_uppercase()),
            format!("B{}", &cid[1..]),
            format!("z{}", &cid[1..]),
            String::new(),
            "b".into(),
            // A CID, but of raw bytes, not dag-cbor.
            format!(
                "b{}",
                data_encoding::BASE32_NOPAD
                    .encode(&[[0x01, 0x55, 0x12, 0x20].as_slice(), &[0; 32]].concat())
                    .to_ascii_lowercase()
            ),
        ];
        // Unreachable: a refused CID never makes a request.
        let client = Client::new("http://127.0.0.1:9", "", Duration::from_secs(1));
        for text in &bad {
            assert!(!crate::is_cid(text), "{text}");
            let result = client.account(text);
            assert!(
                matches!(result, Err(Error::NotCid(_))),
                "{text}: {result:?}"
            );
            let result = client.transaction(text);
            assert!(
                matches!(result, Err(Error::NotCid(_))),
                "{text}: {result:?}"
            );
        }
    }
}
