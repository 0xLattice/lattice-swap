//! A blocking client for the few routes of a Lattice node's operator RPC
//! (lattice-node 3.2.0) the swap needs: read an account, submit a
//! transaction, and see whether it is mined.
//!
//! The operator port listens on loopback only and takes the node's cookie
//! (`<data-directory>/.cookie`, `__cookie__:<token>`) as HTTP basic auth. It
//! changes at every node restart. Every 64-bit integer on this API is a
//! decimal string.

use std::{fmt, fs, io, path::Path};

use base64::Engine;
use serde_json::Value;

use crate::Transaction;

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
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::Status { status, body } => write!(f, "node answered {status}: {body}"),
            Error::Transport(e) => write!(f, "node unreachable: {e}"),
            Error::Malformed(e) => write!(f, "unexpected node answer: {e}"),
        }
    }
}

impl std::error::Error for Error {}

pub type Result<T> = std::result::Result<T, Error>;

/// An account at the node's current tip.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Account {
    pub balance: u64,
    /// The nonce the account's next transaction must carry.
    pub nonce: u64,
}

pub struct Client {
    base: String,
    authorization: String,
}

impl Client {
    /// `base` is like `http://127.0.0.1:8080`; `cookie` is the cookie file's
    /// content.
    pub fn new(base: &str, cookie: &str) -> Self {
        let token = base64::engine::general_purpose::STANDARD.encode(cookie.trim());
        Self {
            base: base.trim_end_matches('/').into(),
            authorization: format!("Basic {token}"),
        }
    }

    pub fn from_cookie_file(base: &str, path: impl AsRef<Path>) -> io::Result<Self> {
        Ok(Self::new(base, &fs::read_to_string(path)?))
    }

    /// Height of the heaviest executed tip, the block the node acts on.
    pub fn height(&self) -> Result<u64> {
        decimal(&self.get("/health")?, "height")
    }

    /// The smallest fee this node pools: a whole-transaction amount (debits
    /// less credits), not a rate. Node policy, not consensus.
    pub fn min_relay_fee(&self) -> Result<u64> {
        decimal(&self.get("/api/chain/info")?, "minRelayFee")
    }

    /// The account at the tip. An address the chain has never credited is
    /// balance 0, nonce 0.
    pub fn account(&self, address: &str) -> Result<Account> {
        match self.get(&format!("/api/state/account/{address}")) {
            Ok(json) => Ok(Account {
                balance: decimal(&json, "balance")?,
                nonce: decimal(&json, "nonce")?,
            }),
            Err(Error::Status { status: 404, .. }) => Ok(Account {
                balance: 0,
                nonce: 0,
            }),
            Err(e) => Err(e),
        }
    }

    /// Submits to the node's pool and returns the transaction CID (of the
    /// signed transaction, not of its body).
    pub fn submit(&self, transaction: &Transaction) -> Result<String> {
        let response = ureq::post(&format!("{}/transactions", self.base))
            .set("Authorization", &self.authorization)
            .send_json(transaction.to_submit_json());
        let json = read(response)?;
        json["transactionCID"]
            .as_str()
            .map(String::from)
            .ok_or_else(|| Error::Malformed(format!("no transactionCID in {json}")))
    }

    /// Blocks on top of and including the canonical block that executed
    /// `transaction_cid` (1 = in the tip), or `None` while it is not in the
    /// canonical chain: pending, unknown, or dropped by a reorg.
    ///
    /// Read from `GET /api/transaction/:cid`, whose `blockHeight` the node
    /// derives from the canonical chain on each read (cached 3 s), so the
    /// answer follows reorgs.
    pub fn confirmations(&self, transaction_cid: &str) -> Result<Option<u64>> {
        let json = match self.get(&format!("/api/transaction/{transaction_cid}")) {
            Ok(json) => json,
            Err(Error::Status { status: 404, .. }) => return Ok(None),
            Err(e) => return Err(e),
        };
        if json.get("blockHeight").is_none() {
            return Ok(None);
        }
        let included = decimal(&json, "blockHeight")?;
        // Read the tip after the transaction, so a newer tip only adds
        // confirmations; a lower one means the chain reorged in between.
        Ok(self.height()?.checked_sub(included).map(|depth| depth + 1))
    }

    fn get(&self, path: &str) -> Result<Value> {
        read(
            ureq::get(&format!("{}{path}", self.base))
                .set("Authorization", &self.authorization)
                .call(),
        )
    }
}

fn read(response: std::result::Result<ureq::Response, ureq::Error>) -> Result<Value> {
    match response {
        Ok(response) => response
            .into_json()
            .map_err(|e| Error::Malformed(e.to_string())),
        Err(ureq::Error::Status(status, response)) => Err(Error::Status {
            status,
            body: response.into_string().unwrap_or_default(),
        }),
        Err(e) => Err(Error::Transport(e.to_string())),
    }
}

fn decimal(json: &Value, field: &str) -> Result<u64> {
    json[field]
        .as_str()
        .and_then(|text| text.parse().ok())
        .ok_or_else(|| Error::Malformed(format!("{field} is not a decimal string in {json}")))
}
