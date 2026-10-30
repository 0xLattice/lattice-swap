//! A blocking client for the few routes of a Lattice node's operator RPC
//! (lattice-node 3.2.0) the swap needs: check the node is synced, read an
//! account, submit a transaction, and read back a transaction and whether
//! it is mined.
//!
//! The operator port listens on loopback only and takes the node's cookie
//! (`<data-directory>/.cookie`, `__cookie__:<token>`) as HTTP basic auth. It
//! changes at every node restart. Every 64-bit integer on this API is a
//! decimal string.

use std::io::Read;
use std::time::Duration;
use std::{fmt, fs, io, path::Path};

use base64::Engine;
use serde_json::Value;

use crate::{AccountAction, Transaction, TransactionBody};

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

/// `GET /health`: a caller should refuse a node that is not `active` or
/// whose `height` trails `best_header_height` (still syncing).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Health {
    pub phase: String,
    /// Height of the heaviest executed tip, the block the node acts on.
    pub height: u64,
    /// Height of the best header chain the node knows; `None` before any.
    pub best_header_height: Option<u64>,
}

/// A transaction the node holds, as `GET /api/transaction/:cid` shows it.
#[derive(Clone, Debug, PartialEq, Eq)]
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

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Inclusion {
    pub height: u64,
    pub hash: String,
}

/// Every answer this client reads is small; a larger one is refused rather
/// than buffered.
const MAX_RESPONSE_BYTES: u64 = 1 << 20;

pub struct Client {
    agent: ureq::Agent,
    base: String,
    authorization: String,
}

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
        let json = self.get("/health")?;
        let best_header_height = match json.get("bestHeaderHeight") {
            Some(_) => Some(decimal(&json, "bestHeaderHeight")?),
            None => None,
        };
        Ok(Health {
            phase: json["phase"]
                .as_str()
                .ok_or_else(|| Error::Malformed(format!("no phase in {json}")))?
                .into(),
            height: decimal(&json, "height")?,
            best_header_height,
        })
    }

    /// The smallest fee this node pools: a whole-transaction amount (debits
    /// less credits), not a rate. Node policy, not consensus.
    pub fn min_relay_fee(&self) -> Result<u64> {
        decimal(&self.get("/api/chain/info")?, "minRelayFee")
    }

    /// The account at the tip. The node answers balance 0, nonce 0 for an
    /// address it has never seen; a 404 means it has no executed tip (or is
    /// not a node of this version), so it stays an error.
    pub fn account(&self, address: &str) -> Result<Account> {
        let json = self.get(&format!("/api/state/account/{address}"))?;
        Ok(Account {
            balance: decimal(&json, "balance")?,
            nonce: decimal(&json, "nonce")?,
        })
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
        let json = match self.get(&format!("/api/transaction/{transaction_cid}")) {
            Ok(json) => json,
            Err(Error::Status { status: 404, .. }) => return Ok(None),
            Err(e) => return Err(e),
        };
        for kind in ["depositActions", "receiptActions", "withdrawalActions"] {
            if json[kind].as_array().is_none_or(|list| !list.is_empty()) {
                return Err(Error::Malformed(format!("{kind} not empty in {json}")));
            }
        }
        let strings = |field: &str| -> Result<Vec<String>> {
            json[field]
                .as_array()
                .and_then(|list| list.iter().map(|s| s.as_str().map(String::from)).collect())
                .ok_or_else(|| Error::Malformed(format!("{field} is not a string list in {json}")))
        };
        let account_actions = json["accountActions"]
            .as_array()
            .ok_or_else(|| Error::Malformed(format!("no accountActions in {json}")))?
            .iter()
            .map(|action| {
                Ok(AccountAction {
                    owner: action["owner"]
                        .as_str()
                        .ok_or_else(|| Error::Malformed(format!("no owner in {action}")))?
                        .into(),
                    delta: decimal(action, "delta")?,
                })
            })
            .collect::<Result<_>>()?;
        let block = match json.get("blockHeight") {
            Some(_) => Some(Inclusion {
                height: decimal(&json, "blockHeight")?,
                hash: json["blockHash"]
                    .as_str()
                    .ok_or_else(|| Error::Malformed(format!("no blockHash in {json}")))?
                    .into(),
            }),
            None => None,
        };
        Ok(Some(TransactionStatus {
            body: TransactionBody {
                account_actions,
                signers: strings("signers")?,
                nonce: decimal(&json, "nonce")?,
                chain_path: strings("chainPath")?,
            },
            block,
        }))
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
        if block(self)?.as_ref() != Some(&before) {
            return Ok(None);
        }
        Ok(height.checked_sub(before.height).map(|depth| depth + 1))
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

fn decimal<T: std::str::FromStr>(json: &Value, field: &str) -> Result<T> {
    json[field]
        .as_str()
        .and_then(|text| text.parse().ok())
        .ok_or_else(|| Error::Malformed(format!("{field} is not a decimal string in {json}")))
}

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
        let status = answering(answer.clone())
            .transaction("cid")
            .unwrap()
            .unwrap();
        assert_eq!(status.body.account_actions[0].delta, 5);
        for kind in ["depositActions", "receiptActions", "withdrawalActions"] {
            let mut answer = answer.clone();
            answer[kind] = serde_json::json!([{}]);
            let result = answering(answer).transaction("cid");
            assert!(
                matches!(result, Err(Error::Malformed(_))),
                "{kind}: {result:?}"
            );
        }
    }
}
