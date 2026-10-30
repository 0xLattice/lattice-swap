//! What a party needs from Bitcoin, and a bitcoind JSON-RPC client for it.

use std::fmt;
use std::time::Duration;

use base64::Engine;
use bitcoin::consensus::encode::{deserialize_hex, serialize_hex};
use bitcoin::{Address, Amount, Block, Denomination, Network, OutPoint, Script, Transaction, Txid};
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
    /// `None` if the node does not know `txid`; 0 while it is in the
    /// mempool.
    fn confirmations(&self, txid: Txid) -> Result<Option<u32>>;
    /// The transaction spending `outpoint` in the mempool or in a block at
    /// height `from` or above.
    fn spending_tx(&self, outpoint: OutPoint, from: u32) -> Result<Option<Transaction>>;
    /// A transaction from the wallet paying `amount` to `script`, signed but
    /// not broadcast.
    fn fund_lock(&self, script: &Script, amount: Amount) -> Result<Transaction>;
}

/// bitcoind's JSON-RPC. `confirmations` reads any transaction, so the node
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

    fn transaction(&self, txid: Txid) -> Result<Transaction> {
        let hex = self.call("getrawtransaction", json!([txid]))?;
        decode(&hex)
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

    fn confirmations(&self, txid: Txid) -> Result<Option<u32>> {
        match self.call("getrawtransaction", json!([txid, 1])) {
            Ok(tx) => Ok(Some(tx["confirmations"].as_u64().unwrap_or(0) as u32)),
            // RPC_INVALID_ADDRESS_OR_KEY: no such transaction.
            Err(Error(e)) if e.contains("\"code\":-5") => Ok(None),
            Err(e) => Err(e),
        }
    }

    fn spending_tx(&self, outpoint: OutPoint, from: u32) -> Result<Option<Transaction>> {
        let prevout = json!([{"txid": outpoint.txid, "vout": outpoint.vout}]);
        let mempool = self.call("gettxspendingprevout", json!([prevout]))?;
        if let Some(txid) = mempool[0]["spendingtxid"].as_str() {
            let txid = txid.parse().map_err(|e| Error(format!("{e}")))?;
            return self.transaction(txid).map(Some);
        }
        for height in from..=self.height()? {
            let hash = self.call("getblockhash", json!([height]))?;
            let block: Block = decode(&self.call("getblock", json!([hash, 0]))?)?;
            let spend = block.txdata.into_iter().find(|tx| {
                tx.input
                    .iter()
                    .any(|input| input.previous_output == outpoint)
            });
            if spend.is_some() {
                return Ok(spend);
            }
        }
        Ok(None)
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
