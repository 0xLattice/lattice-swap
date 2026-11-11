//! A blocking client for the few routes of a Lattice node's operator RPC
//! (lattice-node 3.2.0) the swap needs: check which Nexus the node follows
//! and that it is synced, read an account, submit a transaction, and read
//! back a transaction and whether it is mined; and, for the relay directory,
//! read a chain the node hosts, by its path: its info, an account and the
//! Volumes of its state.
//!
//! The operator port listens on loopback only and takes the node's cookie
//! (`<data-directory>/.cookie`, `__cookie__:<token>`) as HTTP basic auth. It
//! changes at every node restart: a client made from the cookie file reads
//! it again when the node refuses the one it holds. A node's public read
//! port serves the same routes, and `POST /transactions` too when it says
//! `acceptsSubmit`, with no cookie: [`Client::public`]. Every 64-bit integer
//! on this API is a decimal string.

#[cfg(feature = "native")]
use std::io::Read;
#[cfg(feature = "native")]
use std::path::{Path, PathBuf};
#[cfg(feature = "native")]
use std::sync::Mutex;
#[cfg(feature = "native")]
use std::time::{Duration, Instant};
#[cfg(feature = "native")]
use std::{fmt, fs};

#[cfg(feature = "native")]
use base64::Engine;
use std::collections::BTreeMap;

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

/// The most bytes of a Volume archive read: the node's own bound on one.
#[cfg(feature = "native")]
const MAX_VOLUME_BYTES: u64 = 64 << 20;

#[cfg(feature = "native")]
pub struct Client {
    agent: ureq::Agent,
    base: String,
    /// What bounds each request, see [`Client::new`].
    timeout: Duration,
    /// When every request must have ended by, if anything bounds them so:
    /// see [`Client::set_deadline`].
    deadline: Mutex<Option<Instant>>,
    authorization: Mutex<String>,
    /// The cookie file, for a client made from one: read again on a 401,
    /// and before a request while it holds none.
    cookie: Option<PathBuf>,
    /// A public read port's, see [`Client::public`].
    public: bool,
}

#[cfg(feature = "native")]
impl Client {
    /// `base` is like `http://127.0.0.1:8080`; `cookie` is the cookie file's
    /// content. `timeout` bounds each request as a whole, so a stalled node
    /// fails the call instead of blocking it.
    pub fn new(base: &str, cookie: &str, timeout: Duration) -> Self {
        Self {
            // No redirects: a node sends none, and one could move an https
            // node's answers to plain http.
            agent: ureq::AgentBuilder::new()
                .timeout(timeout)
                .redirects(0)
                .build(),
            base: base.trim_end_matches('/').into(),
            timeout,
            deadline: Mutex::new(None),
            authorization: Mutex::new(authorization(cookie)),
            cookie: None,
            public: false,
        }
    }

    /// A client with the cookie in the file at `path`, which it reads again
    /// whenever the node answers 401, and then asks once more: the node
    /// writes a new cookie at every start, so a client that outlives one
    /// restart of its node goes on with the new cookie. Bitcoin Core's
    /// `bitcoin-cli` reads its node's cookie file on every call, and btcd's
    /// `rpcclient` reads it again whenever the file changes. The node
    /// removes the file when it stops: a client made while there is none
    /// holds no cookie, and reads the file before each request until it
    /// has one, each request failing, unasked, while the file is missing.
    pub fn from_cookie_file(base: &str, path: impl AsRef<Path>, timeout: Duration) -> Self {
        let path = path.as_ref();
        let held = fs::read_to_string(path).map(|cookie| authorization(&cookie));
        let mut client = Self::new(base, "", timeout);
        client.authorization = Mutex::new(held.unwrap_or_default());
        client.cookie = Some(path.into());
        client
    }

    /// Bounds every request from now on to end by `deadline`, as well as
    /// by the client's timeout; one asked after it fails at once, unsent.
    /// `None` lifts the bound.
    pub fn set_deadline(&self, deadline: Option<Instant>) {
        *self.deadline.lock().expect("not poisoned") = deadline;
    }

    /// `request` bounded by the client's deadline, if it has one; an error
    /// once that has passed.
    fn bounded(&self, request: ureq::Request) -> Result<ureq::Request> {
        let Some(deadline) = *self.deadline.lock().expect("not poisoned") else {
            return Ok(request);
        };
        match deadline.checked_duration_since(Instant::now()) {
            Some(left) if !left.is_zero() => Ok(request.timeout(left.min(self.timeout))),
            _ => Err(Error::Transport("out of time for this round".into())),
        }
    }

    /// A client for a node's public read port, which takes no cookie.
    pub fn public(base: &str, timeout: Duration) -> Self {
        Self {
            // No redirects, as in `new`.
            agent: ureq::AgentBuilder::new()
                .timeout(timeout)
                .redirects(0)
                .build(),
            base: base.trim_end_matches('/').into(),
            timeout,
            deadline: Mutex::new(None),
            authorization: Mutex::new(String::new()),
            cookie: None,
            public: true,
        }
    }

    /// A public read port answers `/health` from a snapshot up to a few
    /// seconds old and every other read live, so its height and tip are
    /// read live from `/api/chain/info`: a depth worked out against the
    /// snapshot's height would miss a block the other reads show.
    /// `/api/chain/info` names no best header, so the node counts as synced
    /// only if the snapshot was (its best header at its height) and the
    /// live tip has reached that header; otherwise `best_header_height` is
    /// `None`. A snapshot taken while catching up never reads as synced,
    /// even once the live tip reaches the header the snapshot knew.
    pub fn health(&self) -> Result<Health> {
        let mut health = parse::health(&self.get("/health")?).map_err(Error::Malformed)?;
        if self.public {
            let snapshot = (health.height, health.best_header_height);
            (health.height, health.tip) =
                parse::tip(&self.chain_info()?).map_err(Error::Malformed)?;
            health.best_header_height = (snapshot.1 == Some(snapshot.0)
                && health.height >= snapshot.0)
                .then_some(health.height);
        }
        Ok(health)
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
        let json = self.authorized(|authorization| {
            let request = self.bounded(self.agent.post(&format!("{}/transactions", self.base)))?;
            read(authorize(request, authorization).send_json(transaction.to_submit_json()))
        })?;
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

    /// `GET /api/chain/info` of the chain at `chain_path`, which the node
    /// must host, as the node answered it.
    pub fn chain_info_of(&self, chain_path: &[String]) -> Result<Value> {
        json(&self.get_bytes("/api/chain/info", Some(chain_path), MAX_RESPONSE_BYTES)?)
    }

    /// [`Client::account`] on the chain at `chain_path`.
    pub fn account_of(&self, address: &str, chain_path: &[String]) -> Result<Account> {
        let path = format!("/api/state/account/{}", cid_path(address)?);
        let json = json(&self.get_bytes(&path, Some(chain_path), MAX_RESPONSE_BYTES)?)?;
        parse::account(&json).map_err(Error::Malformed)
    }

    /// The nodes of the Volume `cid` roots, held by the node for the chain
    /// at `chain_path`, by CID: [`parse::volume`]. Not checked against
    /// their CIDs.
    pub fn volume(&self, cid: &str, chain_path: &[String]) -> Result<BTreeMap<String, Vec<u8>>> {
        let path = format!("/volumes/{}", cid_path(cid)?);
        let bytes = self.get_bytes(&path, Some(chain_path), MAX_VOLUME_BYTES)?;
        parse::volume(&bytes).map_err(Error::Malformed)
    }

    fn get(&self, path: &str) -> Result<Value> {
        json(&self.get_bytes(path, None, MAX_RESPONSE_BYTES)?)
    }

    /// The answer to `GET path`, of the chain at `chain_path` if given; one
    /// over `limit` bytes is refused.
    fn get_bytes(&self, path: &str, chain_path: Option<&[String]>, limit: u64) -> Result<Vec<u8>> {
        self.authorized(|authorization| {
            let mut request = self.bounded(self.agent.get(&format!("{}{path}", self.base)))?;
            if let Some(chain_path) = chain_path {
                request = request.query("chainPath", &chain_path.join("/"));
            }
            read_bytes(authorize(request, authorization).call(), limit)
        })
    }

    /// `request`'s answer under the cookie held, the cookie file's read
    /// first if it holds none; on a 401, under the cookie file's, read
    /// again, if this client has one.
    fn authorized<T>(&self, request: impl Fn(&str) -> Result<T>) -> Result<T> {
        let mut held = self.authorization.lock().expect("not poisoned").clone();
        if held.is_empty() && self.cookie.is_some() {
            held = self.read_cookie()?;
        }
        match (request(&held), &self.cookie) {
            (Err(Error::Status { status: 401, .. }), Some(_)) => request(&self.read_cookie()?),
            (answer, _) => answer,
        }
    }

    /// The authorization of the cookie file's cookie, now held.
    fn read_cookie(&self) -> Result<String> {
        let path = self.cookie.as_ref().expect("a cookie client");
        let cookie = fs::read_to_string(path)
            .map_err(|e| Error::Transport(format!("{}: {e}", path.display())))?;
        let fresh = authorization(&cookie);
        *self.authorization.lock().expect("not poisoned") = fresh.clone();
        Ok(fresh)
    }
}

/// The basic auth header for `cookie`, the cookie file's content.
#[cfg(feature = "native")]
fn authorization(cookie: &str) -> String {
    let token = base64::engine::general_purpose::STANDARD.encode(cookie.trim());
    format!("Basic {token}")
}

/// `request` with the `authorization` header, unless it is a public
/// client's, which has none.
#[cfg(feature = "native")]
fn authorize(request: ureq::Request, authorization: &str) -> ureq::Request {
    match authorization {
        "" => request,
        authorization => request.set("Authorization", authorization),
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
    json(&read_bytes(response, MAX_RESPONSE_BYTES)?)
}

#[cfg(feature = "native")]
fn json(bytes: &[u8]) -> Result<Value> {
    serde_json::from_slice(bytes).map_err(|e| Error::Malformed(e.to_string()))
}

/// A 2xx answer's bytes, at most `limit` of them; any other status is an
/// error naming the answer.
#[cfg(feature = "native")]
fn read_bytes(
    response: std::result::Result<ureq::Response, ureq::Error>,
    limit: u64,
) -> Result<Vec<u8>> {
    let (status, response) = match response {
        Ok(response) => (None, response),
        Err(ureq::Error::Status(status, response)) => (Some(status), response),
        Err(e) => return Err(Error::Transport(e.to_string())),
    };
    let mut bytes = Vec::new();
    response
        .into_reader()
        .take(limit + 1)
        .read_to_end(&mut bytes)
        .map_err(|e| Error::Transport(e.to_string()))?;
    if bytes.len() as u64 > limit {
        return Err(Error::Malformed(format!("answer over {limit} bytes")));
    }
    match status {
        Some(status) => Err(Error::Status {
            status,
            body: String::from_utf8_lossy(&bytes).into(),
        }),
        None => Ok(bytes),
    }
}

/// Reading the node's answers apart from fetching them: [`Client`] reads
/// them so, and so does a browser that fetched the same routes itself.
/// Each takes a route's JSON and fails, naming what is wrong, on one that
/// is not as the node writes it.
pub mod parse {
    use super::{
        Account, AccountAction, BTreeMap, Health, Inclusion, TransactionBody, TransactionStatus,
    };
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

    /// `GET /api/chain/info`: the height and CID of the executed tip.
    pub fn tip(json: &Value) -> Result<(u64, Option<String>), String> {
        Ok((
            decimal(json, "height")?,
            json["tipCID"].as_str().map(String::from),
        ))
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

    /// `GET /volumes/:cid`: a complete Volume archive as lattice-node frames
    /// it, big-endian: a `u16` count of nodes, then each node's `u16` CID
    /// length, CID, `u32` length and bytes.
    pub fn volume(archive: &[u8]) -> Result<BTreeMap<String, Vec<u8>>, String> {
        fn take<'a>(rest: &mut &'a [u8], n: usize) -> Result<&'a [u8], String> {
            if rest.len() < n {
                return Err("a Volume archive cut short".into());
            }
            let (head, tail) = rest.split_at(n);
            *rest = tail;
            Ok(head)
        }
        let rest = &mut &archive[..];
        let count = u16::from_be_bytes(take(rest, 2)?.try_into().unwrap());
        let mut nodes = BTreeMap::new();
        for _ in 0..count {
            let length = u16::from_be_bytes(take(rest, 2)?.try_into().unwrap());
            let cid = std::str::from_utf8(take(rest, length.into())?)
                .map_err(|_| "a Volume archive's CID is not UTF-8".to_string())?;
            let length = u32::from_be_bytes(take(rest, 4)?.try_into().unwrap());
            let bytes = take(rest, length as usize)?;
            nodes.insert(cid.to_string(), bytes.to_vec());
        }
        if !rest.is_empty() {
            return Err("bytes after a Volume archive".into());
        }
        Ok(nodes)
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
                actions: Vec::new(),
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
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;

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

    /// A node whose cookie is the content of `cookie` as each request
    /// comes in: it answers a request under any other 401, as lattice-node
    /// does, one for a block 404, and any other with a health. Counts the
    /// requests and the 401s.
    fn guarded(cookie: std::path::PathBuf) -> (String, Arc<[AtomicUsize; 2]>) {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let url = format!("http://{}", listener.local_addr().unwrap());
        let counts = Arc::new([AtomicUsize::new(0), AtomicUsize::new(0)]);
        let counted = counts.clone();
        std::thread::spawn(move || {
            for stream in listener.incoming() {
                let mut stream = stream.unwrap();
                let mut request = [0u8; 4096];
                let n = stream.read(&mut request).unwrap();
                let request = String::from_utf8_lossy(&request[..n]).to_string();
                counted[0].fetch_add(1, Ordering::SeqCst);
                let expected = authorization(&fs::read_to_string(&cookie).unwrap());
                let (status, body) = if !request.contains(&format!("Authorization: {expected}\r\n"))
                {
                    counted[1].fetch_add(1, Ordering::SeqCst);
                    ("401 Unauthorized", "")
                } else if request.starts_with("GET /api/block/") {
                    ("404 Not Found", "")
                } else {
                    ("200 OK", r#"{"phase":"active","height":"7"}"#)
                };
                let head = format!(
                    "HTTP/1.1 {status}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                    body.len()
                );
                stream.write_all(head.as_bytes()).unwrap();
                stream.write_all(body.as_bytes()).unwrap();
            }
        });
        (url, counts)
    }

    #[test]
    fn a_volume_archive_is_read_whole() {
        let archive = [
            &[0, 2][..],
            &[0, 2],
            b"ba",
            &[0, 0, 0, 2, 7, 8],
            &[0, 2],
            b"bc",
            &[0, 0, 0, 0],
        ]
        .concat();
        let nodes = parse::volume(&archive).unwrap();
        assert_eq!(nodes.len(), 2);
        assert_eq!(nodes["ba"], [7, 8]);
        assert_eq!(nodes["bc"], [] as [u8; 0]);
        assert!(parse::volume(&archive[..archive.len() - 1]).is_err());
        assert!(parse::volume(&[archive.as_slice(), &[0]].concat()).is_err());
        assert!(parse::volume(&[]).is_err());
    }

    /// A public read port's `/health` is a snapshot that may lag: a public
    /// client reads its height and tip from `/api/chain/info`, sending no
    /// cookie; a cookie client takes `/health`'s.
    #[test]
    fn a_public_client_reads_its_tip_live() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let url = format!("http://{}", listener.local_addr().unwrap());
        std::thread::spawn(move || {
            for stream in listener.incoming() {
                let mut stream = stream.unwrap();
                let mut request = [0u8; 4096];
                let n = stream.read(&mut request).unwrap();
                let request = String::from_utf8_lossy(&request[..n]).to_string();
                let body = if request.starts_with("GET /health ") {
                    r#"{"phase":"active","height":"5","tipCID":"stale"}"#.to_string()
                } else if request.starts_with("GET /api/chain/info ") {
                    let authorized = request.contains("Authorization:");
                    format!(r#"{{"height":"9","tipCID":"live","authorized":{authorized}}}"#)
                } else {
                    String::new()
                };
                let head = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                    body.len()
                );
                stream.write_all(head.as_bytes()).unwrap();
                stream.write_all(body.as_bytes()).unwrap();
            }
        });
        let timeout = Duration::from_secs(5);
        let public = Client::public(&url, timeout);
        let health = public.health().unwrap();
        assert_eq!((health.height, health.tip.as_deref()), (9, Some("live")));
        assert_eq!(public.chain_info().unwrap()["authorized"], false);
        let own = Client::new(&url, "__cookie__:c", timeout);
        assert_eq!(own.health().unwrap().height, 5);
        assert_eq!(own.chain_info().unwrap()["authorized"], true);
    }

    /// A public node whose `/health` snapshot is `health` and whose live
    /// `/api/chain/info` is `info`.
    fn public_node(health: &'static str, info: &'static str) -> Client {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let url = format!("http://{}", listener.local_addr().unwrap());
        std::thread::spawn(move || {
            for stream in listener.incoming() {
                let mut stream = stream.unwrap();
                let mut request = [0u8; 4096];
                let n = stream.read(&mut request).unwrap();
                let request = String::from_utf8_lossy(&request[..n]).to_string();
                let body = if request.starts_with("GET /health ") {
                    health
                } else {
                    info
                };
                let head = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                    body.len()
                );
                stream.write_all(head.as_bytes()).unwrap();
                stream.write_all(body.as_bytes()).unwrap();
            }
        });
        Client::public(&url, Duration::from_secs(5))
    }

    /// `/api/chain/info` names no best header: a public node is synced only
    /// if its `/health` snapshot was and the live tip has reached the
    /// snapshot's best header. A snapshot taken while catching up stays
    /// unsynced even when the live tip reaches the header it knew.
    #[test]
    fn a_public_client_trusts_only_a_synced_snapshot() {
        let synced = |health, info| {
            let health = public_node(health, info).health().unwrap();
            health.best_header_height == Some(health.height)
        };
        let live = r#"{"height":"105","tipCID":"live"}"#;
        // Synced at 100, live past it: synced at the live tip.
        let at_100 = r#"{"phase":"active","height":"100","bestHeaderHeight":"100","tipCID":"t"}"#;
        assert!(synced(at_100, live));
        // Catching up, 100 of 105: still behind, though live reached 105.
        let behind = r#"{"phase":"active","height":"100","bestHeaderHeight":"105","tipCID":"t"}"#;
        assert!(!synced(behind, live));
        // Synced at 110 but the live read trails it.
        let at_110 = r#"{"phase":"active","height":"110","bestHeaderHeight":"110","tipCID":"t"}"#;
        assert!(!synced(at_110, live));
        // No header known.
        let none = r#"{"phase":"active","height":"100","tipCID":"t"}"#;
        assert!(!synced(none, live));
    }

    /// The node writes a new cookie at every start: a client made from the
    /// cookie file goes on under the new one, after one 401; a client given
    /// the cookie itself has no file to read again, and stays refused. Any
    /// other refusal is the node's answer, asked once.
    #[test]
    fn a_client_reads_a_rotated_cookie_again() {
        let dir = std::env::temp_dir().join(format!("swap-cookie-{}", std::process::id()));
        fs::create_dir_all(&dir).unwrap();
        let cookie = dir.join(".cookie");
        fs::write(&cookie, "__cookie__:first").unwrap();
        let (url, counts) = guarded(cookie.clone());
        let [asked, refused] = &*counts;
        let timeout = Duration::from_secs(5);
        let client = Client::from_cookie_file(&url, &cookie, timeout);
        let given = Client::new(&url, "__cookie__:first", timeout);
        assert_eq!(client.health().unwrap().height, 7);
        assert_eq!(given.health().unwrap().height, 7);
        assert_eq!(refused.load(Ordering::SeqCst), 0);

        fs::write(&cookie, "__cookie__:second\n").unwrap();
        assert_eq!(client.health().unwrap().height, 7);
        assert_eq!(refused.load(Ordering::SeqCst), 1);
        // Held from then on: no 401 more.
        assert_eq!(client.health().unwrap().height, 7);
        assert_eq!(refused.load(Ordering::SeqCst), 1);
        let before = asked.load(Ordering::SeqCst);
        assert_eq!(client.block_hash(9).unwrap(), None);
        assert_eq!(asked.load(Ordering::SeqCst), before + 1);
        let stale = given.health();
        assert!(
            matches!(stale, Err(Error::Status { status: 401, .. })),
            "{stale:?}"
        );
        fs::remove_dir_all(&dir).unwrap();
    }

    /// The node removes its cookie file when it stops: a client made while
    /// there is none fails each request, unasked, and goes on under the
    /// cookie the node writes once it is back, with no 401 first.
    #[test]
    fn a_client_made_without_its_cookie_file_reads_it_once_there() {
        let dir = std::env::temp_dir().join(format!("swap-no-cookie-{}", std::process::id()));
        fs::create_dir_all(&dir).unwrap();
        let cookie = dir.join(".cookie");
        let (url, counts) = guarded(cookie.clone());
        let [asked, refused] = &*counts;
        let client = Client::from_cookie_file(&url, &cookie, Duration::from_secs(5));
        let missing = client.health();
        assert!(
            matches!(&missing, Err(Error::Transport(e)) if e.contains(".cookie")),
            "{missing:?}"
        );
        assert_eq!(asked.load(Ordering::SeqCst), 0);

        fs::write(&cookie, "__cookie__:back").unwrap();
        assert_eq!(client.health().unwrap().height, 7);
        assert_eq!(asked.load(Ordering::SeqCst), 1);
        assert_eq!(refused.load(Ordering::SeqCst), 0);
        fs::remove_dir_all(&dir).unwrap();
    }

    /// A request asked once the deadline has passed fails, unsent; one
    /// asked before it ends by it, whatever the client's own timeout.
    #[test]
    fn a_deadline_bounds_every_request() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let url = format!("http://{}", listener.local_addr().unwrap());
        // Takes every connection and never answers.
        std::thread::spawn(move || {
            let held: Vec<_> = listener.incoming().collect();
            drop(held);
        });
        let client = Client::new(&url, "c", Duration::from_secs(30));
        let start = Instant::now();
        client.set_deadline(Some(start + Duration::from_millis(300)));
        assert!(client.health().is_err());
        let took = start.elapsed();
        assert!(took < Duration::from_secs(5), "{took:?}");
        let late = client.health();
        assert!(
            matches!(&late, Err(Error::Transport(e)) if e.contains("out of time")),
            "{late:?}"
        );
        client.set_deadline(None);
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
