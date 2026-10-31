//! The watchtower: buyers' refunds, broadcast once cancel confirms if the
//! buyer has not.
//!
//! A buyer hands over its cancel and its fully signed refund, which spends
//! the cancel output and pays the buyer alone. The buyer does so only once
//! it has given up on the swap without signing the redeem: the refund
//! reveals the buyer's key share, which a seller that can still redeem
//! could use to take both coins (see `swap::Buyer::watchtower`). So no
//! redeem can displace cancel, and the refund goes out as soon as cancel is
//! in a block. The watchtower never broadcasts cancel; it waits for either
//! party to.
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
use bitcoin::hashes::Hash;
use bitcoin::key::TweakedPublicKey;
use bitcoin::secp256k1::{schnorr, Message, Secp256k1};
use bitcoin::sighash::{Prevouts, SighashCache, TapSighashType};
use bitcoin::taproot::{ControlBlock, LeafVersion, TapLeafHash};
use bitcoin::{Network, OutPoint, Script, Transaction, TxOut, Txid, Wtxid, XOnlyPublicKey};
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
    /// How deep the cancel output's spend, the refund or a punish, must be
    /// before the watch is done.
    pub depth: u32,
}

impl Watch {
    /// Refuses a watch on another network; whose transactions do not chain
    /// as cancel and refund do, cancel spending one output, the lock, and
    /// the refund one output of cancel; or whose refund is not signed by
    /// both keys of the 2-of-2 leaf it spends through. A refund that cannot
    /// confirm is refused here, so none can stand in for a valid one.
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
        let prevout = self.cancel.output.get(spent.vout as usize);
        let Some(prevout) = prevout.filter(|_| spent.txid == self.cancel.compute_txid()) else {
            return Err("the refund does not spend cancel's output".into());
        };
        if !signed(&self.refund, prevout) {
            return Err("the refund is not signed by both keys of the output it spends".into());
        }
        Ok(())
    }

    fn cancel_output(&self) -> OutPoint {
        self.refund.input[0].previous_output
    }
}

/// The bytes of the one leaf a refund spends through, `<seller>
/// OP_CHECKSIGVERIFY <buyer> OP_CHECKSIG`, as swap-bitcoin builds it.
const TWO_OF_TWO: usize = 1 + 32 + 1 + 1 + 32 + 1;

/// Whether `tx`'s one input spends `prevout`, a Taproot output, through a
/// 2-of-2 leaf it commits to, with a valid signature by each key: the
/// witness is the second key's signature, the first's, the leaf and the
/// control block, as swap-bitcoin writes it. Signatures are BIP340 over the
/// default sighash.
fn signed(tx: &Transaction, prevout: &TxOut) -> bool {
    let witness = &tx.input[0].witness;
    if witness.len() != 4 {
        return false;
    }
    let item = |i| witness.nth(i).expect("four items");
    let (second, first, leaf, control) = (item(0), item(1), item(2), item(3));
    let shape = leaf.len() == TWO_OF_TWO
        && leaf[0] == 32
        && leaf[33] == 0xad
        && leaf[34] == 32
        && leaf[67] == 0xac;
    if !shape {
        return false;
    }
    let keys = (
        XOnlyPublicKey::from_slice(&leaf[1..33]),
        XOnlyPublicKey::from_slice(&leaf[35..67]),
    );
    let (Ok(a), Ok(b)) = keys else {
        return false;
    };
    let output = &prevout.script_pubkey;
    let output_key = match output.is_p2tr() {
        true => XOnlyPublicKey::from_slice(&output.as_bytes()[2..]),
        false => return false,
    };
    let (Ok(output_key), Ok(control)) = (output_key, ControlBlock::decode(control)) else {
        return false;
    };
    let secp = Secp256k1::verification_only();
    let script = Script::from_bytes(leaf);
    let output_key = TweakedPublicKey::dangerous_assume_tweaked(output_key);
    if control.leaf_version != LeafVersion::TapScript
        || !control.verify_taproot_commitment(&secp, output_key.to_x_only_public_key(), script)
    {
        return false;
    }
    let leaf_hash = TapLeafHash::from_script(script, LeafVersion::TapScript);
    let Ok(sighash) = SighashCache::new(tx).taproot_script_spend_signature_hash(
        0,
        &Prevouts::All(&[prevout]),
        leaf_hash,
        TapSighashType::Default,
    ) else {
        return false;
    };
    let message = Message::from_digest(sighash.to_byte_array());
    let verifies = |signature: &[u8], key: &XOnlyPublicKey| {
        signature.len() == 64
            && schnorr::Signature::from_slice(signature)
                .is_ok_and(|s| secp.verify_schnorr(&s, &message, key).is_ok())
    };
    verifies(first, &a) && verifies(second, &b)
}

/// What the watchtower sees of the chain. A height is that of the block a
/// transaction is in; `None` is the mempool.
pub trait Chain: Send + Sync {
    fn tip(&self) -> io::Result<u32>;
    /// Where `txid` is, if seen: `Some(None)` in the mempool, or the height
    /// of its block.
    fn transaction(&self, txid: Txid) -> io::Result<Option<Option<u32>>>;
    /// What spends `outpoint`, in the mempool or a block.
    fn spender(&self, outpoint: OutPoint) -> io::Result<Option<(Txid, Option<u32>)>>;
    fn broadcast(&self, tx: &Transaction) -> io::Result<()>;
}

/// What to do about a watch.
#[derive(Debug, PartialEq, Eq)]
pub enum Step {
    Wait,
    Broadcast,
    /// Nothing is left to do: the cancel output is spent, `depth` deep.
    Done,
}

/// The refund goes out once cancel is in a block and nothing in a block
/// spends its output: a spend still in the mempool may yet be replaced by
/// the refund, as the buyer's own driver tries. The watch is done once the
/// cancel output's spend is `depth` deep: the refund, or the seller's
/// punish.
pub fn step(watch: &Watch, tip: u32, chain: &dyn Chain) -> io::Result<Step> {
    let deep = |height: u32| tip.saturating_add(1).saturating_sub(height) >= watch.depth;
    match chain.transaction(watch.cancel.compute_txid())? {
        Some(Some(_)) => match chain.spender(watch.cancel_output())? {
            Some((_, Some(height))) if deep(height) => Ok(Step::Done),
            Some((_, Some(_))) => Ok(Step::Wait),
            Some((txid, None)) if txid == watch.refund.compute_txid() => Ok(Step::Wait),
            _ => Ok(Step::Broadcast),
        },
        _ => Ok(Step::Wait),
    }
}

/// Why a watch is refused.
#[derive(Debug)]
pub enum Refusal {
    Invalid(String),
    /// Cancel is in neither Esplora's mempool nor its chain. The buyer sends
    /// it as it gives up, so this passes once it propagates: ask again.
    Unseen,
    /// The watchtower holds as many watches as it may.
    Full,
    /// Esplora could not be asked about cancel: ask again.
    Chain(io::Error),
    Io(io::Error),
}

/// The watches held, each in its own file in `dir`, by the refund's wtxid:
/// two refunds of one swap, each validly signed, are both held.
pub struct Watchtower {
    network: Network,
    dir: PathBuf,
    /// The most watches held at once. It bounds the memory and the disk
    /// they take, and the Esplora requests each round makes: two or three
    /// a watch.
    max: usize,
    watches: Mutex<BTreeMap<Wtxid, Watch>>,
}

impl Watchtower {
    /// The watchtower for `network`, with the watches saved in `dir`, each
    /// checked again as it is read back.
    pub fn open(network: Network, dir: &Path, max: usize) -> io::Result<Self> {
        fs::create_dir_all(dir)?;
        let mut watches = BTreeMap::new();
        for entry in fs::read_dir(dir)? {
            let path = entry?.path();
            if path.extension().is_none_or(|e| e != "json") {
                continue;
            }
            let invalid = |why: String| {
                let why = format!("{}: {why}", path.display());
                io::Error::new(io::ErrorKind::InvalidData, why)
            };
            let text = fs::read_to_string(&path)?;
            let watch: Watch = serde_json::from_str(&text).map_err(|e| invalid(e.to_string()))?;
            watch.check(network).map_err(invalid)?;
            watches.insert(watch.refund.compute_wtxid(), watch);
        }
        Ok(Self {
            network,
            dir: dir.to_path_buf(),
            max,
            watches: Mutex::new(watches),
        })
    }

    /// Takes `watch` once it is on disk, if `chain` has seen its cancel. A
    /// watch then costs whoever makes it a real transaction: a cancel in the
    /// mempool or a block, which spends an output that exists, and whose
    /// output the refund's own keys sign for. One taken already is taken
    /// again. Returns the refund's wtxid.
    pub fn add(&self, watch: Watch, chain: &dyn Chain) -> Result<Wtxid, Refusal> {
        watch.check(self.network).map_err(Refusal::Invalid)?;
        let cancel = watch.cancel.compute_txid();
        if chain.transaction(cancel).map_err(Refusal::Chain)?.is_none() {
            return Err(Refusal::Unseen);
        }
        let wtxid = watch.refund.compute_wtxid();
        let mut watches = self.watches.lock().expect("the watches' lock");
        if watches.contains_key(&wtxid) {
            return Ok(wtxid);
        }
        if watches.len() >= self.max {
            return Err(Refusal::Full);
        }
        let path = self.path(wtxid);
        let partial = path.with_extension("partial");
        let text = serde_json::to_vec(&watch).expect("watches serialize");
        let write = || -> io::Result<()> {
            let mut file = fs::File::create(&partial)?;
            io::Write::write_all(&mut file, &text)?;
            file.sync_all()?;
            fs::rename(&partial, &path)?;
            // The rename, durable too.
            fs::File::open(&self.dir)?.sync_all()
        };
        write().map_err(Refusal::Io)?;
        watches.insert(wtxid, watch);
        Ok(wtxid)
    }

    pub fn len(&self) -> usize {
        self.watches.lock().expect("the watches' lock").len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    fn path(&self, wtxid: Wtxid) -> PathBuf {
        self.dir.join(format!("{wtxid}.json"))
    }

    /// One round over every watch: broadcasts the refunds due and forgets
    /// the watches done. A failure is logged, and the watch tried again
    /// next round.
    pub fn round(&self, chain: &dyn Chain) {
        let tip = match chain.tip() {
            Ok(tip) => tip,
            Err(e) => return log(&format!("esplora: {e}")),
        };
        let watches: Vec<(Wtxid, Watch)> = {
            let watches = self.watches.lock().expect("the watches' lock");
            watches.iter().map(|(t, w)| (*t, w.clone())).collect()
        };
        for (wtxid, watch) in watches {
            match step(&watch, tip, chain) {
                Err(e) => log(&format!("{wtxid}: esplora: {e}")),
                Ok(Step::Wait) => {}
                Ok(Step::Broadcast) => match chain.broadcast(&watch.refund) {
                    Ok(()) => log(&format!("broadcast refund {wtxid}")),
                    Err(e) => log(&format!("refund {wtxid}: {e}")),
                },
                Ok(Step::Done) => {
                    if let Err(e) = fs::remove_file(self.path(wtxid)) {
                        log(&format!("{wtxid}: {e}"));
                        continue;
                    }
                    self.watches
                        .lock()
                        .expect("the watches' lock")
                        .remove(&wtxid);
                    log(&format!("done watching refund {wtxid}"));
                }
            }
        }
    }

    /// Runs a round every `every`, for good.
    pub fn run(&self, chain: &dyn Chain, every: Duration) -> ! {
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

    fn transaction(&self, txid: Txid) -> io::Result<Option<Option<u32>>> {
        match self.get(&format!("/tx/{txid}/status"))? {
            Some(text) => Ok(Some(json::<Status>(&text)?.height())),
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
