//! A buyer's own Bitcoin wallet, as eigenwallet keeps an internal one: a
//! single P2WPKH key the buyer deposits to. A swap funds its lock from the
//! wallet's balance, any change goes back to it, and so does the swap's
//! refund; [`sweep`] withdraws the balance to any address.
//!
//! The caller reads the key's outputs and a fee rate, in whole sat/vB, from
//! its Esplora; nothing here does I/O.

use std::str::FromStr;

use bitcoin::hashes::Hash;
use bitcoin::secp256k1::{Message as Digest, PublicKey, Secp256k1, SecretKey};
use bitcoin::sighash::{EcdsaSighashType, SighashCache};
use bitcoin::transaction::{predict_weight, InputWeightPrediction, Version};
use bitcoin::{absolute, Address, Amount, CompressedPublicKey, Network, OutPoint, PrivateKey};
use bitcoin::{ScriptBuf, Sequence, Transaction, TxIn, TxOut, Txid, Witness};
use rand_core::{OsRng, RngCore};
use serde::{Deserialize, Serialize};

/// An output the wallet key holds.
#[derive(Clone, Copy, Debug, Serialize, Deserialize)]
pub struct Utxo {
    pub txid: Txid,
    pub vout: u32,
    pub value: u64,
}

/// The wallet key, as its WIF, and the P2WPKH output it owns, as its
/// script and address.
#[derive(Clone, Serialize, Deserialize)]
pub struct Key {
    pub wif: String,
    pub script_pubkey: ScriptBuf,
    pub address: String,
}

/// Its address alone: the WIF stays out of logs and panics.
impl std::fmt::Debug for Key {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Key")
            .field("address", &self.address)
            .finish_non_exhaustive()
    }
}

impl Key {
    /// A fresh key on `network` (`bitcoin`, `testnet`, `signet` or
    /// `regtest`).
    pub fn new(network: &str) -> Result<Self, String> {
        let network = Network::from_str(network).map_err(|e| e.to_string())?;
        let mut bytes = [0u8; 32];
        OsRng.fill_bytes(&mut bytes);
        let secret = SecretKey::from_slice(&bytes).map_err(|e| e.to_string())?;
        Ok(Self::of_key(PrivateKey::new(secret, network), network))
    }

    /// The key `wif`, which must be one for `network`.
    pub fn of(wif: &str, network: &str) -> Result<Self, String> {
        let network = Network::from_str(network).map_err(|e| e.to_string())?;
        let key = PrivateKey::from_wif(wif.trim()).map_err(|e| e.to_string())?;
        if key.network != network.into() {
            return Err(format!("the key is not for {network}"));
        }
        Ok(Self::of_key(key, network))
    }

    fn of_key(key: PrivateKey, network: Network) -> Self {
        let public = CompressedPublicKey(key.inner.public_key(&Secp256k1::signing_only()));
        let address = Address::p2wpkh(&public, network);
        Self {
            wif: key.to_wif(),
            script_pubkey: address.script_pubkey(),
            address: address.to_string(),
        }
    }
}

/// A transaction the wallet signed, and the fee it pays.
#[derive(Clone, Debug)]
pub struct Signed {
    pub tx: Transaction,
    pub fee: u64,
}

/// The wallet key, and the P2WPKH output script it owns.
fn key(wif: &str) -> Result<(PrivateKey, PublicKey, ScriptBuf), String> {
    let key = PrivateKey::from_wif(wif).map_err(|e| e.to_string())?;
    let public = key.public_key(&Secp256k1::signing_only()).inner;
    let script = ScriptBuf::new_p2wpkh(&CompressedPublicKey(public).wpubkey_hash());
    Ok((key, public, script))
}

/// The fee, at `rate` sat/vB, of a transaction spending `inputs` of the
/// wallet's outputs into outputs of scripts `outputs` bytes long, signed.
fn fee(inputs: usize, outputs: &[usize], rate: u64) -> u64 {
    predict_weight(
        vec![InputWeightPrediction::P2WPKH_MAX; inputs],
        outputs.iter().copied(),
    )
    .to_vbytes_ceil()
    .saturating_mul(rate)
}

/// `inputs`, all the wallet's, into `outputs`, signed.
fn signed(wif: &str, inputs: &[Utxo], outputs: Vec<TxOut>) -> Result<Signed, String> {
    let tx = Transaction {
        version: Version::TWO,
        lock_time: absolute::LockTime::ZERO,
        input: inputs
            .iter()
            .map(|utxo| TxIn {
                previous_output: OutPoint::new(utxo.txid, utxo.vout),
                sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
                ..Default::default()
            })
            .collect(),
        output: outputs,
    };
    let values: Vec<u64> = inputs.iter().map(|utxo| utxo.value).collect();
    let tx = sign(wif, tx, &values)?;
    let fee = total(inputs) - tx.output.iter().map(|out| out.value.to_sat()).sum::<u64>();
    Ok(Signed { tx, fee })
}

/// `tx`, every input of which spends an output of the wallet's of the value
/// `values` gives it, signed: the wallet's funding and sweeps, and a CPFP
/// child of a payout to the wallet.
pub fn sign(wif: &str, mut tx: Transaction, values: &[u64]) -> Result<Transaction, String> {
    let (key, public, script) = key(wif)?;
    if values.len() != tx.input.len() {
        return Err(format!(
            "{} inputs, {} values",
            tx.input.len(),
            values.len()
        ));
    }
    let secp = Secp256k1::signing_only();
    let mut cache = SighashCache::new(tx.clone());
    for (i, value) in values.iter().enumerate() {
        let sighash = cache
            .p2wpkh_signature_hash(i, &script, Amount::from_sat(*value), EcdsaSighashType::All)
            .map_err(|e| e.to_string())?;
        let signature = bitcoin::ecdsa::Signature::sighash_all(
            secp.sign_ecdsa(&Digest::from_digest(sighash.to_byte_array()), &key.inner),
        );
        tx.input[i].witness = Witness::p2wpkh(&signature, &public);
    }
    Ok(tx)
}

fn total(utxos: &[Utxo]) -> u64 {
    utxos.iter().map(|utxo| utxo.value).sum()
}

/// A P2TR output script, as the lock's is, and a P2WPKH one, as the
/// wallet's change is, in bytes.
const LOCK: usize = 34;
const CHANGE: usize = 22;

/// How many of `utxos`, sorted largest first, pay `amount` and the fee at
/// `rate` of a funding without change: the fewest, as BDK's
/// `LargestFirstCoinSelection` picks them; none if all of them cannot.
fn pick(utxos: &[Utxo], amount: u64, rate: u64) -> Option<usize> {
    (1..=utxos.len()).find(|&n| total(&utxos[..n]) >= amount + fee(n, &[LOCK], rate))
}

fn largest_first(mut utxos: Vec<Utxo>) -> Vec<Utxo> {
    utxos.sort_by_key(|utxo| std::cmp::Reverse(utxo.value));
    utxos
}

/// Whether the wallet's `utxos` can fund a lock of `amount` at `rate`
/// sat/vB, and the balance a funding with change needs from as many
/// outputs: what the buyer is asked to deposit.
pub fn need(utxos: Vec<Utxo>, amount: u64, rate: u64) -> (bool, u64) {
    let utxos = largest_first(utxos);
    let enough = pick(&utxos, amount, rate).is_some();
    let inputs = utxos.len().max(1);
    (enough, amount + fee(inputs, &[LOCK, CHANGE], rate))
}

/// The funding transaction for `FundLock`: `amount` to the lock's `lock`
/// script from the wallet's `utxos`, picked largest first, at `rate`
/// sat/vB, the change back to the wallet; change below dust goes to the
/// fee, as BDK drops it. Refuses `utxos` that cannot pay for it.
pub fn fund(
    wif: &str,
    utxos: Vec<Utxo>,
    lock: ScriptBuf,
    amount: u64,
    rate: u64,
) -> Result<Signed, String> {
    let (_, _, wallet) = key(wif)?;
    let utxos = largest_first(utxos);
    let n = pick(&utxos, amount, rate).ok_or_else(|| {
        format!(
            "the wallet's {} sat cannot fund the lock at {rate} sat/vB",
            total(&utxos)
        )
    })?;
    let picked = &utxos[..n];
    let total = total(picked);
    let lock_len = lock.len();
    let mut outputs = vec![TxOut {
        value: Amount::from_sat(amount),
        script_pubkey: lock,
    }];
    let change = total.checked_sub(amount + fee(n, &[lock_len, wallet.len()], rate));
    if let Some(change) = change.filter(|change| *change >= wallet.minimal_non_dust().to_sat()) {
        outputs.push(TxOut {
            value: Amount::from_sat(change),
            script_pubkey: wallet,
        });
    }
    signed(wif, picked, outputs)
}

/// Everything in the wallet's `utxos` to `to`, less the fee at `rate`
/// sat/vB: a withdrawal, as a wallet's "send max" builds one.
pub fn sweep(wif: &str, utxos: &[Utxo], to: ScriptBuf, rate: u64) -> Result<Signed, String> {
    let total = total(utxos);
    let fee = fee(utxos.len(), &[to.len()], rate);
    let value = total
        .checked_sub(fee)
        .filter(|value| *value >= to.minimal_non_dust().to_sat())
        .ok_or_else(|| format!("the wallet's {total} sat do not pay for their own withdrawal"))?;
    let output = TxOut {
        value: Amount::from_sat(value),
        script_pubkey: to,
    };
    signed(wif, utxos, vec![output])
}
