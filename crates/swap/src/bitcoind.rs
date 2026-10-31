//! What a party needs from Bitcoin, and a bitcoind JSON-RPC client for it.

use std::fmt;
use std::sync::Mutex;
use std::time::Duration;

use base64::Engine;
use bitcoin::address::NetworkUnchecked;
use bitcoin::consensus::encode::{deserialize_hex, serialize_hex};
use bitcoin::{
    Address, Amount, Block, Denomination, FeeRate, Network, OutPoint, Script, ScriptBuf,
    Transaction, Txid,
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
    /// estimate; a conservative one for the next block if `urgent`.
    fn fee_rate(&self, urgent: bool) -> Result<Option<FeeRate>>;
    /// The lowest package feerate at which `parent`, which the mempool
    /// refused, would enter it with a child spending its payout: the
    /// mempool's minimum, and if another transaction spends `parent`'s input
    /// there, enough to replace it and its descendants.
    fn floor(&self, parent: &Transaction) -> Result<FeeRate>;
    /// The feerate of `parent` and its descendants in the mempool, as a
    /// child that bumped it made it; `None` if `parent` is not there.
    fn package_rate(&self, parent: &Transaction) -> Result<Option<FeeRate>>;
    /// Raises unconfirmed `parent`, which pays `fee`, to `rate`, above its
    /// own feerate, with a CPFP child spending its payout, output 0, into
    /// the wallet, and submits both as a package; returns the child's txid.
    /// The child pays at most `max`, and less if its change would be dust
    /// otherwise. A child replacing the last pays at least what Bitcoin
    /// Core asks of a replacement: the last's fee and the incremental
    /// feerate on its own size. Fails if the wallet cannot sign for the
    /// payout.
    fn bump(&self, parent: &Transaction, fee: Amount, rate: FeeRate, max: Amount) -> Result<Txid>;
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
    /// The last parent sized for a child: its txid, the change script the
    /// child pays, and the package's vsize. `floor` and `bump`, and every
    /// rebump, reuse them rather than ask for another change address and
    /// sign again.
    sized: Mutex<Option<(Txid, ScriptBuf, u64)>>,
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
            sized: Mutex::new(None),
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

    /// A change script of the wallet for a child of `parent`, and the
    /// package's vsize with that child signed: worked out once per parent.
    fn sized(&self, parent: &Transaction) -> Result<(ScriptBuf, u64)> {
        let txid = parent.compute_txid();
        let mut sized = self.sized.lock().expect("not poisoned");
        if let Some((sized, change, size)) = &*sized {
            if *sized == txid {
                return Ok((change.clone(), *size));
            }
        }
        let change = self.change_for(parent)?;
        let size = self.package_vsize(parent, change.clone())?;
        *sized = Some((txid, change.clone(), size));
        Ok((change, size))
    }

    /// The script of a new change address of the wallet, if the wallet can
    /// sign for `parent`'s payout; only the payee can bump.
    fn change_for(&self, parent: &Transaction) -> Result<ScriptBuf> {
        // An operator's external payout script is not this wallet's to bump
        // with.
        let payout = Address::from_script(&parent.output[0].script_pubkey, self.network)
            .map_err(|e| Error(format!("payout: {e}")))?;
        let info = self.call("getaddressinfo", json!([payout.to_string()]))?;
        if info["ismine"] != true {
            return Err(Error(format!("payout {payout} is not this wallet's")));
        }
        let change = self.call("getrawchangeaddress", json!([]))?;
        Ok(change
            .as_str()
            .and_then(|a| a.parse::<Address<NetworkUnchecked>>().ok())
            .and_then(|a| a.require_network(self.network).ok())
            .ok_or_else(|| Error(format!("change address {change}")))?
            .script_pubkey())
    }

    /// `parent` and a signed child spending its payout, in vbytes.
    fn package_vsize(&self, parent: &Transaction, change: ScriptBuf) -> Result<u64> {
        let child = swap_bitcoin::cpfp(parent, change, Amount::ZERO)
            .ok_or_else(|| Error("the payout is dust".into()))?;
        Ok((parent.vsize() + self.sign_child(parent, &child)?.vsize()) as u64)
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

/// A feerate in BTC/kvB, as bitcoind reports one.
fn per_kvb(value: &Value) -> Result<FeeRate> {
    Ok(FeeRate::from_sat_per_kwu(btc(value)?.to_sat().div_ceil(4)))
}

/// `fee` over `vsize`, rounded up.
fn over(fee: Amount, vsize: u64) -> FeeRate {
    FeeRate::from_sat_per_kwu((fee.to_sat() * 250).div_ceil(vsize.max(1)))
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

    fn fee_rate(&self, urgent: bool) -> Result<Option<FeeRate>> {
        // Bitcoin Core takes targets from 1 block, which it reads as 2, and
        // estimates economically unless asked otherwise.
        let target = match urgent {
            true => json!([1, "conservative"]),
            false => json!([2]),
        };
        let estimate = self.call("estimatesmartfee", target)?;
        // BTC per kvB; absent while the node has too little data.
        if estimate["feerate"].is_null() {
            return Ok(None);
        }
        per_kvb(&estimate["feerate"]).map(Some)
    }

    fn floor(&self, parent: &Transaction) -> Result<FeeRate> {
        let mempool = self.call("getmempoolinfo", json!([]))?;
        let minimum = per_kvb(&mempool["mempoolminfee"])?;
        let input = parent.input[0].previous_output;
        let spending = self.call(
            "gettxspendingprevout",
            json!([[{"txid": input.txid, "vout": input.vout}]]),
        )?;
        let other = match spending[0]["spendingtxid"].as_str() {
            Some(other) if other != parent.compute_txid().to_string() => other,
            _ => return Ok(minimum),
        };
        // Bitcoin Core replaces a package only with one at a better feerate
        // that also pays all of its fees and the incremental feerate on its
        // own size. A low-feerate child of up to 1000 vB under the other
        // spend raises that: the whole fee spread over our smaller package.
        // Best effort: a non-TRUC conflict with two children, which the
        // punish leaf lets the seller make, cannot be replaced at all.
        let entry = self.call("getmempoolentry", json!([other]))?;
        let size = |key: &str| {
            entry[key]
                .as_u64()
                .ok_or_else(|| Error(format!("mempool entry {key}: {entry}")))
        };
        let (own, all) = (
            btc(&entry["fees"]["base"])?,
            btc(&entry["fees"]["descendant"])?,
        );
        let (_, ours) = self.sized(parent)?;
        let beat = over(own, size("vsize")?)
            .max(over(all, size("descendantsize")?))
            .max(over(all, ours));
        let incremental = per_kvb(&mempool["incrementalrelayfee"])?;
        let above = beat.to_sat_per_kwu() + incremental.to_sat_per_kwu();
        Ok(minimum.max(FeeRate::from_sat_per_kwu(above)))
    }

    fn package_rate(&self, parent: &Transaction) -> Result<Option<FeeRate>> {
        let entry = match self.call("getmempoolentry", json!([parent.compute_txid()])) {
            Ok(entry) => entry,
            // RPC_INVALID_ADDRESS_OR_KEY: not in the mempool.
            Err(Error(e)) if e.contains("\"code\":-5") => return Ok(None),
            Err(e) => return Err(e),
        };
        let size = entry["descendantsize"]
            .as_u64()
            .ok_or_else(|| Error(format!("mempool entry descendantsize: {entry}")))?;
        let fees = btc(&entry["fees"]["descendant"])?.to_sat();
        // Rounded down: it is compared with a target the package must meet.
        Ok(Some(FeeRate::from_sat_per_kwu(fees * 250 / size.max(1))))
    }

    fn bump(&self, parent: &Transaction, fee: Amount, rate: FeeRate, max: Amount) -> Result<Txid> {
        // The child pays all the package needs but `fee`, and what replacing
        // the last child takes, short of `max` and of leaving dust.
        let (change, size) = self.sized(parent)?;
        let mut fee = rate
            .fee_vb(size)
            .and_then(|package| package.checked_sub(fee))
            .ok_or_else(|| Error(format!("feerate {rate}")))?;
        let txid = parent.compute_txid();
        let spending = self.call("gettxspendingprevout", json!([[{"txid": txid, "vout": 0}]]))?;
        if let Some(last) = spending[0]["spendingtxid"].as_str() {
            let entry = self.call("getmempoolentry", json!([last]))?;
            let mempool = self.call("getmempoolinfo", json!([]))?;
            let incremental = per_kvb(&mempool["incrementalrelayfee"])?;
            // A vbyte over the sized child's, whose signature may be a byte
            // shorter than this one's.
            let own = size - parent.vsize() as u64 + 1;
            let replace = incremental
                .fee_vb(own)
                .and_then(|more| btc(&entry["fees"]["base"]).ok()?.checked_add(more))
                .ok_or_else(|| Error(format!("mempool entry {last}: {entry}")))?;
            fee = fee.max(replace);
        }
        let spendable = parent.output[0]
            .value
            .checked_sub(change.minimal_non_dust())
            .ok_or_else(|| Error("the payout is dust".into()))?;
        let fee = fee.min(max).min(spendable);
        let child = swap_bitcoin::cpfp(parent, change, fee).expect("change above dust");
        let signed = self.sign_child(parent, &child)?;
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
