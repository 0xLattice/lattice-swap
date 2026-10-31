//! What a party needs from Bitcoin, and a bitcoind JSON-RPC client for it.

use std::fmt;
use std::time::Duration;

use base64::Engine;
use bitcoin::address::NetworkUnchecked;
use bitcoin::consensus::encode::{deserialize_hex, serialize_hex};
use bitcoin::{
    Address, Amount, Block, Denomination, FeeRate, Network, OutPoint, Script, Transaction, Txid,
};
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
    /// confirmations (0 in the mempool); `None` if the node knows neither,
    /// as for a transaction only in a block that left the active chain.
    fn transaction(&self, txid: Txid) -> Result<Option<(Transaction, u32)>>;
    /// What spends `outpoint`, in the mempool or in a block at `from` or
    /// above, with its confirmations; `None` if the mempool and the chain
    /// show `outpoint` unspent, or no such spend is found.
    fn spender(&self, outpoint: OutPoint, from: u32) -> Result<Option<(Transaction, u32)>>;
    /// A transaction from the wallet paying `amount` to `script`, signed but
    /// not broadcast.
    fn fund_lock(&self, script: &Script, amount: Amount) -> Result<Transaction>;
    /// A feerate to confirm within a couple of blocks, if the node has an
    /// estimate.
    fn fee_rate(&self) -> Result<Option<FeeRate>>;
    /// Raises unconfirmed `parent`, which pays `fee`, to `rate` with a CPFP
    /// child spending its payout, output 0, into the wallet, and submits both
    /// as a package; returns the child's txid. A child at a higher rate
    /// replaces the last. Fails if the wallet cannot sign for the payout.
    fn bump(&self, parent: &Transaction, fee: Amount, rate: FeeRate) -> Result<Txid>;
}

/// bitcoind's JSON-RPC. `transaction` reads any transaction, so the node
/// needs `-txindex`; `spender` calls `gettxspendingprevout`, so it needs
/// Bitcoin Core 24 or later; `fund_lock` and `bump` need a wallet, so `url`
/// names one (`http://host:port/wallet/<name>`).
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

    /// The wallet's signature on `child`, which spends `parent`'s payout.
    fn sign_child(&self, parent: &Transaction, child: &Transaction) -> Result<Transaction> {
        let payout = &parent.output[0];
        let prevtxs = json!([{
            "txid": parent.compute_txid(),
            "vout": 0,
            "scriptPubKey": payout.script_pubkey.to_hex_string(),
            "amount": payout.value.to_string_in(Denomination::Bitcoin),
        }]);
        let signed = self.call(
            "signrawtransactionwithwallet",
            json!([serialize_hex(child), prevtxs]),
        )?;
        if signed["complete"] != true {
            return Err(Error(format!("wallet could not sign: {signed}")));
        }
        decode(&signed["hex"])
    }
}

fn btc(value: &Value) -> Result<Amount> {
    value
        .as_f64()
        .and_then(|btc| Amount::from_btc(btc).ok())
        .ok_or_else(|| Error(format!("not an amount: {value}")))
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
                // `-txindex` still finds a transaction whose block left the
                // active chain: with that block's hash and 0 confirmations.
                // A mempool answer has no block hash.
                if !tx["blockhash"].is_null() && confirmations == 0 {
                    return Ok(None);
                }
                Ok(Some((decode(&tx["hex"])?, confirmations)))
            }
            // RPC_INVALID_ADDRESS_OR_KEY: no such transaction.
            Err(Error(e)) if e.contains("\"code\":-5") => Ok(None),
            Err(e) => Err(e),
        }
    }

    fn spender(&self, outpoint: OutPoint, from: u32) -> Result<Option<(Transaction, u32)>> {
        let (txid, vout) = (outpoint.txid, outpoint.vout);
        if !self.call("gettxout", json!([txid, vout, true]))?.is_null() {
            return Ok(None);
        }
        let pooled = self.call(
            "gettxspendingprevout",
            json!([[{"txid": txid, "vout": vout}]]),
        )?;
        if let Some(spender) = pooled[0]["spendingtxid"].as_str() {
            let spender = spender
                .parse()
                .map_err(|e| Error(format!("txid {spender}: {e}")))?;
            return self.transaction(spender);
        }
        let tip = self.height()?;
        for height in from..=tip {
            let hash = self.call("getblockhash", json!([height]))?;
            let block: Block = decode(&self.call("getblock", json!([hash, 0]))?)?;
            let spends = |tx: &&Transaction| tx.input.iter().any(|i| i.previous_output == outpoint);
            if let Some(tx) = block.txdata.iter().find(spends) {
                return Ok(Some((tx.clone(), tip - height + 1)));
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

    fn fee_rate(&self) -> Result<Option<FeeRate>> {
        let estimate = self.call("estimatesmartfee", json!([2]))?;
        // BTC per kvB; absent while the node has too little data.
        if estimate["feerate"].is_null() {
            return Ok(None);
        }
        let per_kvb = btc(&estimate["feerate"])?.to_sat();
        Ok(Some(FeeRate::from_sat_per_kwu(per_kvb.div_ceil(4))))
    }

    fn bump(&self, parent: &Transaction, fee: Amount, rate: FeeRate) -> Result<Txid> {
        // Only the payee can spend the payout: an operator's external
        // payout script is not this wallet's to bump with.
        let payout = Address::from_script(&parent.output[0].script_pubkey, self.network)
            .map_err(|e| Error(format!("payout: {e}")))?;
        let info = self.call("getaddressinfo", json!([payout.to_string()]))?;
        if info["ismine"] != true {
            return Err(Error(format!("payout {payout} is not this wallet's")));
        }
        let change = self.call("getrawchangeaddress", json!([]))?;
        let change = change
            .as_str()
            .and_then(|a| a.parse::<Address<NetworkUnchecked>>().ok())
            .and_then(|a| a.require_network(self.network).ok())
            .ok_or_else(|| Error(format!("change address {change}")))?
            .script_pubkey();
        let child = |fee| {
            swap_bitcoin::cpfp(parent, change.clone(), fee)
                .ok_or_else(|| Error(format!("a {fee} child would leave the payout dust")))
        };

        // Signed once to learn its size, then again paying for it.
        let size = self.sign_child(parent, &child(Amount::ZERO)?)?.vsize() as u64;
        let package = rate.fee_vb(parent.vsize() as u64 + size);
        let own = rate.fee_vb(size);
        let fee = package
            .and_then(|package| package.checked_sub(fee))
            .max(own)
            .ok_or_else(|| Error(format!("feerate {rate}")))?;
        let signed = self.sign_child(parent, &child(fee)?)?;
        let result = self.call(
            "submitpackage",
            json!([[serialize_hex(parent), serialize_hex(&signed)]]),
        )?;
        if result["package_msg"] != "success" {
            return Err(Error(format!("submitpackage: {result}")));
        }
        Ok(signed.compute_txid())
    }
}
