//! What a party needs from Bitcoin, and a bitcoind JSON-RPC client for it.

use std::fmt;
use std::time::Duration;

use base64::Engine;
use bitcoin::consensus::encode::{deserialize_hex, serialize_hex};
use bitcoin::{Address, Amount, Denomination, Network, Script, Transaction, Txid};
use serde_json::{json, Value};

#[derive(Debug)]
pub struct Error(pub String);

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "bitcoin: {}", self.0)
    }
}

impl std::error::Error for Error {}

pub type Result<T> = std::result::Result<T, Error>;

pub trait Bitcoin {
    fn broadcast(&self, tx: &Transaction) -> Result<()>;
    /// The height of the tip.
    fn height(&self) -> Result<u32>;
    /// The transaction `txid` in the mempool or the chain, with its
    /// confirmations (0 in the mempool); `None` if the node knows neither.
    fn transaction(&self, txid: Txid) -> Result<Option<(Transaction, u32)>>;
    /// A transaction from the wallet paying `amount` to `script`, signed but
    /// not broadcast.
    fn fund_lock(&self, script: &Script, amount: Amount) -> Result<Transaction>;
}

/// bitcoind's JSON-RPC. `transaction` reads any transaction, so the node
/// needs `-txindex`; `fund_lock` needs a wallet, so `url` names one
/// (`http://host:port/wallet/<name>`).
pub struct Bitcoind {
    agent: ureq::Agent,
    url: String,
    authorization: String,
    network: Network,
}

impl Bitcoind {
    /// `cookie` is the content of bitcoind's `.cookie` file (`user:password`).
    /// `timeout` bounds each call.
    pub fn new(url: &str, cookie: &str, network: Network, timeout: Duration) -> Self {
        let token = base64::engine::general_purpose::STANDARD.encode(cookie.trim());
        Self {
            agent: ureq::AgentBuilder::new().timeout(timeout).build(),
            url: url.into(),
            authorization: format!("Basic {token}"),
            network,
        }
    }

    pub fn call(&self, method: &str, params: Value) -> Result<Value> {
        let request = json!({"jsonrpc": "1.0", "id": 0, "method": method, "params": params});
        let response = self
            .agent
            .post(&self.url)
            .set("Authorization", &self.authorization)
            .send_json(request);
        // bitcoind answers an RPC error with an HTTP error status and the
        // error in the body.
        let response = match response {
            Ok(response) | Err(ureq::Error::Status(_, response)) => response,
            Err(e) => return Err(Error(format!("{method}: {e}"))),
        };
        let body: Value = response
            .into_json()
            .map_err(|e| Error(format!("{method}: {e}")))?;
        if !body["error"].is_null() {
            return Err(Error(format!("{method}: {}", body["error"])));
        }
        Ok(body["result"].clone())
    }
}

fn decode<T: bitcoin::consensus::Decodable>(hex: &Value) -> Result<T> {
    let hex = hex
        .as_str()
        .ok_or_else(|| Error(format!("not hex: {hex}")))?;
    deserialize_hex(hex).map_err(|e| Error(e.to_string()))
}

impl Bitcoin for Bitcoind {
    fn broadcast(&self, tx: &Transaction) -> Result<()> {
        self.call("sendrawtransaction", json!([serialize_hex(tx)]))
            .map(drop)
    }

    fn height(&self) -> Result<u32> {
        let height = self.call("getblockcount", json!([]))?;
        height
            .as_u64()
            .and_then(|h| u32::try_from(h).ok())
            .ok_or_else(|| Error(format!("height {height}")))
    }

    fn transaction(&self, txid: Txid) -> Result<Option<(Transaction, u32)>> {
        match self.call("getrawtransaction", json!([txid, 1])) {
            Ok(tx) => {
                let confirmations = tx["confirmations"].as_u64().unwrap_or(0) as u32;
                Ok(Some((decode(&tx["hex"])?, confirmations)))
            }
            // RPC_INVALID_ADDRESS_OR_KEY: no such transaction.
            Err(Error(e)) if e.contains("\"code\":-5") => Ok(None),
            Err(e) => Err(e),
        }
    }

    fn fund_lock(&self, script: &Script, amount: Amount) -> Result<Transaction> {
        let address = Address::from_script(script, self.network)
            .map_err(|e| Error(e.to_string()))?
            .to_string();
        let amount = amount.to_string_in(Denomination::Bitcoin);
        // Reserve the inputs, so the wallet does not spend them elsewhere
        // before the funding transaction is broadcast.
        let options = json!({"lockUnspents": true});
        let funded = self.call(
            "walletcreatefundedpsbt",
            json!([[], [{address: amount}], 0, options]),
        )?;
        let signed = self.call(
            "walletprocesspsbt",
            json!([funded["psbt"], true, "ALL", true, true]),
        )?;
        if signed["complete"] != true {
            return Err(Error(format!("wallet could not sign: {signed}")));
        }
        decode(&signed["hex"])
    }
}
