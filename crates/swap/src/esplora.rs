//! Bitcoin through an Esplora API, as mempool.space and blockstream.info
//! serve one, over a single-key wallet ([`crate::wallet`]): the browser's
//! web/driver/src/esplora.js, as a [`Bitcoin`] for the native driver.
//!
//! The Esplora is trusted for what it shows, as eigenwallet trusts its
//! Electrum server: it shows its blocks, not a header chain ahead of them,
//! and no mempool minimum or descendants, so [`Bitcoin::floor`] and
//! [`Bitcoin::package_rate`] are worked out from what it does show, at
//! Bitcoin Core's default relay floor of 1 sat/vB. Fee bumps go to its
//! `POST /txs/package`, Bitcoin Core's `submitpackage`, which mempool.space
//! and Blockstream's Esplora serve.
//!
//! The wallet spends only outputs in a block, as Bitcoin Core spends none
//! it received still unconfirmed.

use std::io::Read;
use std::time::Duration;

use bitcoin::consensus::encode::{deserialize_hex, serialize_hex};
use bitcoin::{Amount, BlockHash, FeeRate, Network, OutPoint, Script, Transaction, Txid};
use serde::Deserialize;
use serde_json::Value;

use crate::bitcoind::{Bitcoin, Error, Result, Tip};
use crate::bump::{self, per_vb, MIN_RELAY};
use crate::wallet::{self, Key, Utxo};

/// The blocks a funding's or withdrawal's estimate aims to confirm in, as
/// [`Bitcoin::fee_rate`] asks for a couple of blocks.
const FEE_TARGET: &str = "2";

/// Every answer read is small; a larger one is refused.
const MAX_ANSWER: u64 = 1 << 20;

/// One Esplora API at `url`, e.g. `https://mempool.space/api`, and the
/// wallet key `key`.
pub struct Esplora {
    agent: ureq::Agent,
    url: String,
    key: Key,
}

/// An output paying the wallet, as `/address/:address/utxo` lists one.
#[derive(Deserialize)]
struct Listed {
    txid: Txid,
    vout: u32,
    value: u64,
    status: Status,
}

#[derive(Deserialize)]
struct Status {
    confirmed: bool,
    block_height: Option<u32>,
}

/// A transaction as `/tx/:txid` shows it.
#[derive(Deserialize)]
struct Shown {
    status: Status,
    fee: u64,
    weight: u64,
}

impl Shown {
    fn vsize(&self) -> u64 {
        self.weight.div_ceil(4)
    }
}

/// What spends an output, as `/tx/:txid/outspend/:vout` shows it.
#[derive(Deserialize)]
struct Outspend {
    spent: bool,
    txid: Option<Txid>,
    status: Option<Status>,
}

impl Esplora {
    /// `timeout` bounds each request.
    pub fn new(url: &str, key: Key, timeout: Duration) -> Self {
        Self {
            // No redirects: one could move an https Esplora's reads to
            // plain http, where anyone on the way can change them.
            agent: ureq::AgentBuilder::new()
                .timeout(timeout)
                .redirects(0)
                .build(),
            url: url.trim_end_matches('/').into(),
            key,
        }
    }

    /// Refuses (`Ok(Err)`) an Esplora on another chain than `network`,
    /// whose blocks would never show the swap's transactions: its block 0
    /// must be `network`'s genesis, as bitcoind's `getblockchaininfo` names
    /// its chain. Only a genesis it names tells; any other failure to read
    /// one (`Err`) may pass when asked again.
    pub fn check_network(&self, network: Network) -> Result<Result<()>> {
        let expected = bitcoin::constants::genesis_block(network).block_hash();
        let text = self.get("/block-height/0", false)?.unwrap_or_default();
        let genesis: BlockHash = text
            .trim()
            .parse()
            .map_err(|e| Error(format!("/block-height/0 {text:?}: {e}")))?;
        if genesis != expected {
            return Ok(Err(Error(format!(
                "refused: the Esplora's genesis is {genesis}, not {network}'s {expected}"
            ))));
        }
        Ok(Ok(()))
    }

    pub fn key(&self) -> &Key {
        &self.key
    }

    /// The answer's text; `None` on 404 if `missing` is allowed.
    fn get(&self, path: &str, missing: bool) -> Result<Option<String>> {
        let url = format!("{}{path}", self.url);
        match self.agent.get(&url).call() {
            Ok(response) => text(&url, response).map(Some),
            Err(ureq::Error::Status(404, _)) if missing => Ok(None),
            Err(ureq::Error::Status(status, response)) => {
                Err(Error(format!("{url}: {status} {}", text(&url, response)?)))
            }
            Err(e) => Err(Error(format!("{url}: {e}"))),
        }
    }

    fn json<T: serde::de::DeserializeOwned>(&self, path: &str) -> Result<T> {
        let text = self.get(path, false)?.unwrap_or_default();
        serde_json::from_str(&text).map_err(|e| Error(format!("{path}: {e}")))
    }

    fn shown(&self, txid: Txid) -> Result<Option<Shown>> {
        self.get(&format!("/tx/{txid}"), true)?
            .map(|text| serde_json::from_str(&text).map_err(|e| Error(format!("/tx/{txid}: {e}"))))
            .transpose()
    }

    fn outspend(&self, outpoint: OutPoint) -> Result<Outspend> {
        self.json(&format!("/tx/{}/outspend/{}", outpoint.txid, outpoint.vout))
    }

    /// The unconfirmed transaction spending `outpoint`, if any: its txid
    /// and how it shows.
    fn pooled_spender(&self, outpoint: OutPoint) -> Result<Option<(Txid, Shown)>> {
        let spend = self.outspend(outpoint)?;
        let (true, Some(txid)) = (spend.spent, spend.txid) else {
            return Ok(None);
        };
        if spend.status.is_some_and(|status| status.confirmed) {
            return Ok(None);
        }
        Ok(self.shown(txid)?.map(|shown| (txid, shown)))
    }

    fn post(&self, path: &str, content_type: &str, body: &str) -> Result<String> {
        let url = format!("{}{path}", self.url);
        match self
            .agent
            .post(&url)
            .set("Content-Type", content_type)
            .send_string(body)
        {
            Ok(response) => text(&url, response),
            Err(ureq::Error::Status(status, response)) => {
                Err(Error(format!("{url}: {status} {}", text(&url, response)?)))
            }
            Err(e) => Err(Error(format!("{url}: {e}"))),
        }
    }

    /// What pays the wallet: `(utxo, confirmed)`.
    fn listed(&self) -> Result<Vec<(Utxo, bool)>> {
        let listed: Vec<Listed> = self.json(&format!("/address/{}/utxo", self.key.address))?;
        Ok(listed
            .into_iter()
            .map(|utxo| {
                let Listed {
                    txid, vout, value, ..
                } = utxo;
                (Utxo { txid, vout, value }, utxo.status.confirmed)
            })
            .collect())
    }

    /// The outputs the wallet can spend: those in a block.
    pub fn spendable(&self) -> Result<Vec<Utxo>> {
        Ok(self
            .listed()?
            .into_iter()
            .filter_map(|(utxo, confirmed)| confirmed.then_some(utxo))
            .collect())
    }

    /// `(confirmed, unconfirmed)`, in sat: what the wallet can spend, and
    /// what is on its way to it.
    pub fn balance(&self) -> Result<(u64, u64)> {
        Ok(self
            .listed()?
            .into_iter()
            .fold(
                (0, 0),
                |(confirmed, unconfirmed), (utxo, mined)| match mined {
                    true => (confirmed + utxo.value, unconfirmed),
                    false => (confirmed, unconfirmed + utxo.value),
                },
            ))
    }

    /// The estimate, in sat/vB, to confirm within `blocks`, if the Esplora
    /// has one.
    pub fn estimate(&self, blocks: &str) -> Result<Option<f64>> {
        let estimates: Value = self.json("/fee-estimates")?;
        Ok(estimates[blocks].as_f64())
    }

    /// The feerate the wallet's own spends pay, in whole sat/vB: the
    /// estimate [`Bitcoin::fee_rate`] reads, never below the relay floor,
    /// which is also the rate where there is none, as on regtest: how
    /// Electrum and eigenwallet price their own spends, and the driver's
    /// funding at a `fallback_fee_rate` of 1 sat/vB.
    pub fn wallet_rate(&self) -> Result<u64> {
        let estimate = self.estimate(FEE_TARGET)?.unwrap_or(1.0);
        Ok((estimate.ceil() as u64).max(1))
    }

    fn tip_height(&self) -> Result<u32> {
        let text = self.get("/blocks/tip/height", false)?.unwrap_or_default();
        text.trim()
            .parse()
            .map_err(|e| Error(format!("/blocks/tip/height {text:?}: {e}")))
    }
}

fn text(url: &str, response: ureq::Response) -> Result<String> {
    if (300..400).contains(&response.status()) {
        let to = response.header("location").unwrap_or_default();
        return Err(Error(format!(
            "{url}: {} to {to}, not followed",
            response.status()
        )));
    }
    let mut text = String::new();
    response
        .into_reader()
        .take(MAX_ANSWER)
        .read_to_string(&mut text)
        .map_err(|e| Error(format!("{url}: {e}")))?;
    Ok(text)
}

impl Bitcoin for Esplora {
    fn broadcast(&self, tx: &Transaction) -> Result<()> {
        self.post("/tx", "text/plain", &serialize_hex(tx)).map(drop)
    }

    /// Esplora shows its blocks, not a header chain ahead of them:
    /// `headers` is the tip's own height.
    fn tip(&self) -> Result<Tip> {
        #[derive(Deserialize)]
        struct Block {
            height: u32,
            timestamp: u64,
        }
        let hash = self.get("/blocks/tip/hash", false)?.unwrap_or_default();
        let hash = hash.trim();
        let block: Block = self.json(&format!("/block/{hash}"))?;
        Ok(Tip {
            height: block.height,
            headers: block.height,
            time: block.timestamp,
            hash: hash
                .parse()
                .map_err(|e| Error(format!("tip hash {hash:?}: {e}")))?,
        })
    }

    /// `/tx/:txid` answers 404 for a transaction it never saw, or one only
    /// in a block that left the chain.
    fn transaction(&self, txid: Txid) -> Result<Option<(Transaction, u32)>> {
        let Some(shown) = self.shown(txid)? else {
            return Ok(None);
        };
        let Some(hex) = self.get(&format!("/tx/{txid}/hex"), true)? else {
            return Ok(None);
        };
        let tx: Transaction =
            deserialize_hex(hex.trim()).map_err(|e| Error(format!("/tx/{txid}/hex: {e}")))?;
        // Trusted for where a transaction is, never for what it is: a
        // forged refund would read as a punish.
        if tx.compute_txid() != txid {
            return Err(Error(format!("/tx/{txid}/hex is another transaction")));
        }
        let confirmations = match (shown.status.confirmed, shown.status.block_height) {
            (true, Some(height)) => (self.tip_height()? + 1).saturating_sub(height),
            _ => 0,
        };
        Ok(Some((tx, confirmations)))
    }

    /// Esplora indexes every spend: `from` is not needed.
    fn spender(&self, outpoint: OutPoint, _from: u32) -> Result<Option<(Transaction, u32)>> {
        let spend = self.outspend(outpoint)?;
        match (spend.spent, spend.txid) {
            (true, Some(txid)) => self.transaction(txid),
            _ => Ok(None),
        }
    }

    /// From the wallet's outputs in a block, at `fee_rate` rounded up to a
    /// whole sat/vB and at least the relay floor: Esplora shows no mempool
    /// minimum.
    fn fund_lock(&self, script: &Script, amount: Amount, fee_rate: FeeRate) -> Result<Transaction> {
        let rate = fee_rate.max(MIN_RELAY).to_sat_per_vb_ceil();
        let funded = wallet::fund(
            &self.key.wif,
            self.spendable()?,
            script.into(),
            amount.to_sat(),
            rate,
        )
        .map_err(Error)?;
        Ok(funded.tx)
    }

    fn fee_rate(&self, urgent: bool) -> Result<Option<FeeRate>> {
        let target = if urgent { "1" } else { FEE_TARGET };
        Ok(self.estimate(target)?.map(per_vb))
    }

    /// The relay floor, and if another unconfirmed transaction spends
    /// `parent`'s input, enough to replace it, above `parent`'s own feerate,
    /// as [`Bitcoind`]'s floor works it out: Esplora shows no descendants,
    /// so only the conflict's own fee counts.
    ///
    /// [`Bitcoind`]: crate::bitcoind::Bitcoind
    fn floor(&self, parent: &Transaction) -> Result<FeeRate> {
        let input = parent.input[0].previous_output;
        let other = match self.pooled_spender(input)? {
            Some((txid, shown)) if txid != parent.compute_txid() => shown,
            _ => return Ok(MIN_RELAY),
        };
        let vsize = parent.vsize() as u64;
        let ours = bump::package_vsize(&self.key, parent, vsize).map_err(Error)?;
        let (spent, _) = self
            .transaction(input.txid)?
            .ok_or_else(|| Error(format!("input {input} unseen")))?;
        let paid = spent.output[input.vout as usize].value.to_sat();
        bump::floor(parent, vsize, paid, (other.fee, other.vsize()), ours).map_err(Error)
    }

    /// `parent`'s feerate with the unconfirmed child spending its payout,
    /// if any; `None` once it is in a block, or unseen.
    fn package_rate(&self, parent: &Transaction) -> Result<Option<FeeRate>> {
        let txid = parent.compute_txid();
        let Some(shown) = self.shown(txid)? else {
            return Ok(None);
        };
        if shown.status.confirmed {
            return Ok(None);
        }
        let child = self.pooled_spender(OutPoint::new(txid, 0))?;
        let child = child.map(|(_, child)| (child.fee, child.vsize()));
        Ok(Some(bump::package_rate(shown.fee, shown.vsize(), child)))
    }

    /// As [`Bitcoind`]'s bump, the child signed by the wallet key, the
    /// change back to it ([`bump::child`]), the pair submitted to
    /// `POST /txs/package`.
    ///
    /// [`Bitcoind`]: crate::bitcoind::Bitcoind
    fn bump(&self, parent: &Transaction, fee: Amount, rate: FeeRate, max: Amount) -> Result<Txid> {
        let last = self.pooled_spender(OutPoint::new(parent.compute_txid(), 0))?;
        let last = last.map(|(_, shown)| (shown.fee, shown.vsize()));
        let vsize = parent.vsize() as u64;
        let signed = bump::child(&self.key, parent, vsize, fee, rate, max, last).map_err(Error)?;
        let package = serde_json::json!([serialize_hex(parent), serialize_hex(&signed)]);
        let answer = self.post("/txs/package", "application/json", &package.to_string())?;
        let answer: Value =
            serde_json::from_str(&answer).map_err(|e| Error(format!("/txs/package: {e}")))?;
        if answer["package_msg"] != "success" {
            return Err(Error(format!("/txs/package: {answer}")));
        }
        Ok(signed.compute_txid())
    }
}
