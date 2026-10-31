//! The watchtower: buyers' refunds, broadcast once cancel confirms if the
//! buyer has not.
//!
//! A buyer hands over its cancel and its fully signed refund, which spends
//! the cancel output and pays the buyer alone. The buyer does so only once
//! it has given up on the swap without signing the redeem: the refund
//! reveals the buyer's key share, which a seller that can still redeem
//! could use to take both coins (see `swap::Buyer::watchtower`). The
//! watchtower never broadcasts cancel; it waits for either party to.
//!
//! It reads Bitcoin through an Esplora API, as mempool.space serves one.
//! Each watch is written to its own file before it is accepted, so a
//! restart keeps it, and removed once there is nothing left to do.

use std::collections::BTreeMap;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::time::Duration;

use bitcoin::consensus::encode::{deserialize_hex, serialize_hex};
use bitcoin::{Network, OutPoint, Transaction, Txid};
use serde::{Deserialize, Serialize};

/// What a buyer hands the watchtower.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct Watch {
    /// The Bitcoin network the swap is on.
    pub network: Network,
    /// Cancel, fully signed: it spends the BTC lock.
    #[serde(with = "hex_tx")]
    pub cancel: Transaction,
    /// The refund, fully signed: it spends cancel's output.
    #[serde(with = "hex_tx")]
    pub refund: Transaction,
    /// How deep cancel must be before the refund goes out, and how deep
    /// whatever spends the lock or the cancel output must be before the
    /// watch is done.
    pub depth: u32,
}

impl Watch {
    /// Refuses a watch on another network, or whose transactions do not
    /// chain as cancel and refund do: cancel spends one output, the lock,
    /// and the refund one output of cancel.
    pub fn check(&self, network: Network) -> Result<(), String> {
        if self.network != network {
            return Err(format!(
                "this relay watches {network}, not {}",
                self.network
            ));
        }
        if self.depth == 0 {
            return Err("depth must be at least 1".into());
        }
        if self.cancel.input.len() != 1 {
            return Err("cancel must spend one output, the lock".into());
        }
        let [input] = &self.refund.input[..] else {
            return Err("the refund must spend one output, cancel's".into());
        };
        let spent = input.previous_output;
        let outputs = self.cancel.output.len();
        if spent.txid != self.cancel.compute_txid() || spent.vout as usize >= outputs {
            return Err("the refund does not spend cancel's output".into());
        }
        Ok(())
    }

    fn lock(&self) -> OutPoint {
        self.cancel.input[0].previous_output
    }

    fn cancel_output(&self) -> OutPoint {
        self.refund.input[0].previous_output
    }
}

/// What the watchtower sees of the chain. A height is that of the block a
/// transaction is in; `None` is the mempool.
pub trait Chain {
    fn tip(&self) -> io::Result<u32>;
    /// The height of the block `txid` is in, if it is in one.
    fn confirmed(&self, txid: Txid) -> io::Result<Option<u32>>;
    /// What spends `outpoint`, in the mempool or a block.
    fn spender(&self, outpoint: OutPoint) -> io::Result<Option<(Txid, Option<u32>)>>;
    fn broadcast(&self, tx: &Transaction) -> io::Result<()>;
}

/// What to do about a watch.
#[derive(Debug, PartialEq, Eq)]
pub enum Step {
    Wait,
    Broadcast,
    /// Nothing is left to do: the lock or the cancel output is spent, and
    /// that is `depth` deep.
    Done,
}

/// The refund goes out once cancel is `depth` deep and nothing in a block
/// spends its output: a spend still in the mempool may yet be replaced by
/// the refund, as the buyer's own driver tries. The watch is done once the
/// cancel output's spend is `depth` deep, the refund or the seller's
/// punish, or else the lock's, the seller's redeem.
pub fn step(watch: &Watch, tip: u32, chain: &impl Chain) -> io::Result<Step> {
    let deep = |height: u32| tip.saturating_add(1).saturating_sub(height) >= watch.depth;
    let cancel = watch.cancel.compute_txid();
    match chain.confirmed(cancel)? {
        Some(height) if deep(height) => match chain.spender(watch.cancel_output())? {
            Some((_, Some(height))) if deep(height) => Ok(Step::Done),
            Some((_, Some(_))) => Ok(Step::Wait),
            Some((txid, None)) if txid == watch.refund.compute_txid() => Ok(Step::Wait),
            _ => Ok(Step::Broadcast),
        },
        Some(_) => Ok(Step::Wait),
        None => match chain.spender(watch.lock())? {
            Some((txid, Some(height))) if txid != cancel && deep(height) => Ok(Step::Done),
            _ => Ok(Step::Wait),
        },
    }
}

/// Why a watch is refused.
#[derive(Debug)]
pub enum Refusal {
    Invalid(String),
    /// The watchtower holds as many watches as it may.
    Full,
    Io(io::Error),
}

/// The watches held, each in its own file in `dir`.
pub struct Watchtower {
    network: Network,
    dir: PathBuf,
    /// The most watches held at once. It bounds the memory and the disk
    /// they take, and the Esplora requests each round makes: two or three
    /// a watch.
    max: usize,
    watches: Mutex<BTreeMap<Txid, Watch>>,
}

impl Watchtower {
    /// The watchtower for `network`, with the watches saved in `dir`.
    pub fn open(network: Network, dir: &Path, max: usize) -> io::Result<Self> {
        fs::create_dir_all(dir)?;
        let mut watches = BTreeMap::new();
        for entry in fs::read_dir(dir)? {
            let path = entry?.path();
            if path.extension().is_none_or(|e| e != "json") {
                continue;
            }
            let text = fs::read_to_string(&path)?;
            let watch: Watch = serde_json::from_str(&text).map_err(|e| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("{}: {e}", path.display()),
                )
            })?;
            watches.insert(watch.refund.compute_txid(), watch);
        }
        Ok(Self {
            network,
            dir: dir.to_path_buf(),
            max,
            watches: Mutex::new(watches),
        })
    }

    /// Takes `watch`, once it is on disk; one taken already is taken
    /// again. Returns the refund's txid.
    pub fn add(&self, watch: Watch) -> Result<Txid, Refusal> {
        watch.check(self.network).map_err(Refusal::Invalid)?;
        let txid = watch.refund.compute_txid();
        let mut watches = self.watches.lock().expect("the watches' lock");
        if watches.contains_key(&txid) {
            return Ok(txid);
        }
        if watches.len() >= self.max {
            return Err(Refusal::Full);
        }
        let path = self.path(txid);
        let partial = path.with_extension("partial");
        let text = serde_json::to_vec(&watch).expect("watches serialize");
        let write = || -> io::Result<()> {
            let mut file = fs::File::create(&partial)?;
            io::Write::write_all(&mut file, &text)?;
            file.sync_all()?;
            fs::rename(&partial, &path)
        };
        write().map_err(Refusal::Io)?;
        watches.insert(txid, watch);
        Ok(txid)
    }

    pub fn len(&self) -> usize {
        self.watches.lock().expect("the watches' lock").len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    fn path(&self, txid: Txid) -> PathBuf {
        self.dir.join(format!("{txid}.json"))
    }

    /// One round over every watch: broadcasts the refunds due and forgets
    /// the watches done. A failure is logged, and the watch tried again
    /// next round.
    pub fn round(&self, chain: &impl Chain) {
        let tip = match chain.tip() {
            Ok(tip) => tip,
            Err(e) => return log(&format!("esplora: {e}")),
        };
        let watches: Vec<(Txid, Watch)> = {
            let watches = self.watches.lock().expect("the watches' lock");
            watches.iter().map(|(t, w)| (*t, w.clone())).collect()
        };
        for (txid, watch) in watches {
            match step(&watch, tip, chain) {
                Err(e) => log(&format!("{txid}: esplora: {e}")),
                Ok(Step::Wait) => {}
                Ok(Step::Broadcast) => match chain.broadcast(&watch.refund) {
                    Ok(()) => log(&format!("broadcast refund {txid}")),
                    Err(e) => log(&format!("refund {txid}: {e}")),
                },
                Ok(Step::Done) => {
                    if let Err(e) = fs::remove_file(self.path(txid)) {
                        log(&format!("{txid}: {e}"));
                        continue;
                    }
                    self.watches
                        .lock()
                        .expect("the watches' lock")
                        .remove(&txid);
                    log(&format!("done watching refund {txid}"));
                }
            }
        }
    }

    /// Runs a round every `every`, for good.
    pub fn run(&self, chain: &impl Chain, every: Duration) -> ! {
        loop {
            self.round(chain);
            std::thread::sleep(every);
        }
    }
}

/// An Esplora API at `base`, such as `https://mempool.space/api`.
pub struct Esplora {
    base: String,
    agent: ureq::Agent,
}

impl Esplora {
    pub fn new(base: &str, timeout: Duration) -> Self {
        Self {
            base: base.trim_end_matches('/').to_string(),
            agent: ureq::AgentBuilder::new().timeout(timeout).build(),
        }
    }

    /// `path`, or `None` on a 404.
    fn get(&self, path: &str) -> io::Result<Option<String>> {
        match self.agent.get(&format!("{}{path}", self.base)).call() {
            Ok(response) => response.into_string().map(Some),
            Err(ureq::Error::Status(404, _)) => Ok(None),
            Err(e) => Err(io::Error::other(e.to_string())),
        }
    }
}

#[derive(Deserialize)]
struct Status {
    confirmed: bool,
    block_height: Option<u32>,
}

impl Status {
    fn height(&self) -> Option<u32> {
        self.block_height.filter(|_| self.confirmed)
    }
}

#[derive(Deserialize)]
struct Outspend {
    spent: bool,
    txid: Option<Txid>,
    status: Option<Status>,
}

fn json<T: serde::de::DeserializeOwned>(text: &str) -> io::Result<T> {
    serde_json::from_str(text).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))
}

impl Chain for Esplora {
    fn tip(&self) -> io::Result<u32> {
        let text = self.get("/blocks/tip/height")?.unwrap_or_default();
        text.trim()
            .parse()
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "a tip height"))
    }

    fn confirmed(&self, txid: Txid) -> io::Result<Option<u32>> {
        match self.get(&format!("/tx/{txid}/status"))? {
            Some(text) => Ok(json::<Status>(&text)?.height()),
            None => Ok(None),
        }
    }

    fn spender(&self, outpoint: OutPoint) -> io::Result<Option<(Txid, Option<u32>)>> {
        let path = format!("/tx/{}/outspend/{}", outpoint.txid, outpoint.vout);
        let Some(text) = self.get(&path)? else {
            return Ok(None);
        };
        let outspend: Outspend = json(&text)?;
        match (outspend.spent, outspend.txid) {
            (true, Some(txid)) => Ok(Some((txid, outspend.status.and_then(|s| s.height())))),
            _ => Ok(None),
        }
    }

    fn broadcast(&self, tx: &Transaction) -> io::Result<()> {
        match self
            .agent
            .post(&format!("{}/tx", self.base))
            .send_string(&serialize_hex(tx))
        {
            Ok(_) => Ok(()),
            Err(ureq::Error::Status(code, response)) => Err(io::Error::other(format!(
                "{code}: {}",
                response.into_string().unwrap_or_default()
            ))),
            Err(e) => Err(io::Error::other(e.to_string())),
        }
    }
}

fn log(what: &str) {
    eprintln!("swap-relay: watchtower: {what}");
}

mod hex_tx {
    use super::*;
    use serde::{Deserializer, Serializer};

    pub fn serialize<S: Serializer>(tx: &Transaction, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&serialize_hex(tx))
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(
        deserializer: D,
    ) -> Result<Transaction, D::Error> {
        let hex = String::deserialize(deserializer)?;
        deserialize_hex(&hex).map_err(serde::de::Error::custom)
    }
}

#[cfg(test)]
mod tests;
