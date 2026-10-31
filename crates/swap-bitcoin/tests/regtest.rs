//! Every swap path, broadcast to a real regtest bitcoind.

use corepc_node::serde_json::Value;
use corepc_node::{Conf, Node};
use rand_core::OsRng;
use swap_bitcoin::bitcoin::address::NetworkUnchecked;
use swap_bitcoin::bitcoin::consensus::encode::{deserialize_hex, serialize_hex};
use swap_bitcoin::bitcoin::hashes::Hash;
use swap_bitcoin::bitcoin::sighash::{Prevouts, SighashCache};
use swap_bitcoin::bitcoin::taproot::{LeafVersion, TapLeafHash};
use swap_bitcoin::bitcoin::{
    Address, Amount, Denomination, Network, OutPoint, Script, ScriptBuf, Sequence, TapSighashType,
    Transaction, TxOut, Txid, WPubkeyHash,
};
use swap_bitcoin::schnorr_fun;
use swap_bitcoin::{Error, EvenY, KeyPair, Params, Party, Point, Scalar, Spend, Swap};

const T1: u16 = 10;
const T2: u16 = 5;

struct Chain {
    node: Node,
    miner: Address,
}

impl Chain {
    fn start() -> Self {
        Self::start_with(&[])
    }

    /// A node started with extra `args`, such as a fee policy.
    fn start_with(args: &[&'static str]) -> Self {
        let mut conf = Conf::default();
        conf.args.push("-txindex");
        conf.args.extend(args);
        let node = Node::from_downloaded_with_conf(&conf).expect("start bitcoind");
        let miner = node.client.new_address().unwrap();
        let chain = Self { node, miner };
        chain.mine(101);
        chain
    }

    fn mine(&self, blocks: usize) {
        self.node
            .client
            .generate_to_address(blocks, &self.miner)
            .unwrap();
    }

    fn script(&self) -> ScriptBuf {
        self.node.client.new_address().unwrap().script_pubkey()
    }

    /// Pays `amount` to `script` from the node's wallet and confirms it.
    fn fund(&self, script: &ScriptBuf, amount: Amount) -> OutPoint {
        let address = Address::from_script(script, Network::Regtest).unwrap();
        let txid = self
            .node
            .client
            .send_to_address(&address, amount)
            .unwrap()
            .txid()
            .unwrap();
        let vout = self
            .tx(txid)
            .output
            .iter()
            .position(|out| &out.script_pubkey == script)
            .unwrap();
        self.mine(1);
        OutPoint::new(txid, vout as u32)
    }

    fn broadcast(&self, tx: &Transaction) -> Result<Txid, String> {
        let result = self.node.client.send_raw_transaction(tx);
        result
            .map_err(|e| format!("{e:?}"))
            .map(|r| r.0.parse().unwrap())
    }

    fn tx(&self, txid: Txid) -> Transaction {
        let hex: String = self
            .node
            .client
            .call("getrawtransaction", &[txid.to_string().into()])
            .unwrap();
        deserialize_hex(&hex).unwrap()
    }

    fn confirmations(&self, txid: Txid) -> u64 {
        let verbose: Value = self
            .node
            .client
            .call("getrawtransaction", &[txid.to_string().into(), true.into()])
            .unwrap();
        verbose["confirmations"].as_u64().unwrap_or(0)
    }

    /// A CPFP child of `parent` paying `fee` from its payout, which the
    /// node's wallet signs for.
    fn child(&self, parent: &Transaction, fee: Amount) -> Transaction {
        let child = swap_bitcoin::cpfp(parent, self.script(), fee).unwrap();
        let payout = Value::from(vec![corepc_node::serde_json::json!({
            "txid": parent.compute_txid().to_string(),
            "vout": 0,
            "scriptPubKey": parent.output[0].script_pubkey.to_hex_string(),
            "amount": parent.output[0].value.to_string_in(Denomination::Bitcoin),
        })]);
        let signed: Value = self
            .node
            .client
            .call(
                "signrawtransactionwithwallet",
                &[serialize_hex(&child).into(), payout],
            )
            .unwrap();
        assert_eq!(signed["complete"], true, "{signed}");
        deserialize_hex(signed["hex"].as_str().unwrap()).unwrap()
    }

    fn submit_package(&self, parent: &Transaction, child: &Transaction) -> Value {
        let package = vec![serialize_hex(parent), serialize_hex(child)];
        self.node
            .client
            .call("submitpackage", &[package.into()])
            .unwrap()
    }

    /// Mines a block and returns the transaction as it appears on chain.
    fn mine_and_fetch(&self, txid: Txid) -> Transaction {
        self.mine(1);
        let verbose: Value = self
            .node
            .client
            .call("getrawtransaction", &[txid.to_string().into(), true.into()])
            .unwrap();
        assert_eq!(verbose["confirmations"], 1, "{txid} was not mined");
        self.tx(txid)
    }
}

/// Both parties' keys: Bitcoin signing keys and Nexus share secrets.
struct Parties {
    seller: KeyPair<EvenY>,
    buyer: KeyPair<EvenY>,
    s: Scalar,
    b: Scalar,
}

impl Parties {
    fn random() -> Self {
        Self {
            seller: KeyPair::new_xonly(Scalar::random(&mut OsRng)),
            buyer: KeyPair::new_xonly(Scalar::random(&mut OsRng)),
            s: Scalar::random(&mut OsRng),
            b: Scalar::random(&mut OsRng),
        }
    }

    fn params(&self, payout: ScriptBuf) -> Params {
        Params {
            seller: self.seller.public_key(),
            buyer: self.buyer.public_key(),
            seller_share: share_point(&self.s),
            buyer_share: share_point(&self.b),
            amount: Amount::from_sat(100_000_000),
            fee: Amount::from_sat(1_000),
            t1: T1,
            t2: T2,
            redeem_payout: payout.clone(),
            refund_payout: payout.clone(),
            punish_payout: payout,
        }
    }
}

fn share_point(secret: &Scalar) -> Point {
    KeyPair::new(*secret).public_key()
}

// Signature checks that need no chain use a made-up lock outpoint.
fn offline_lock() -> OutPoint {
    OutPoint::new(Txid::from_byte_array([7; 32]), 0)
}

fn offline_payout() -> ScriptBuf {
    ScriptBuf::new_p2wpkh(&WPubkeyHash::from_byte_array([7; 20]))
}

/// A funded swap with one confirmation on the lock.
fn funded() -> (Chain, Parties, Swap, OutPoint) {
    funded_on(Chain::start())
}

fn funded_on(chain: Chain) -> (Chain, Parties, Swap, OutPoint) {
    let parties = Parties::random();
    let swap = Swap::new(parties.params(chain.script())).unwrap();
    let lock = chain.fund(&swap.lock_script_pubkey(), swap.params().amount);
    (chain, parties, swap, lock)
}

/// `tx` with its relative timelock one block short, re-signed by `signers`
/// (in witness order) so that only the script's own CSV can reject it.
fn one_block_short(tx: &Transaction, prevout: TxOut, signers: &[&KeyPair<EvenY>]) -> Transaction {
    let mut tx = tx.clone();
    tx.input[0].sequence = Sequence(tx.input[0].sequence.0 - 1);
    let items = tx.input[0].witness.to_vec();
    let leaf = Script::from_bytes(&items[items.len() - 2]);
    let sighash = SighashCache::new(&tx)
        .taproot_script_spend_signature_hash(
            0,
            &Prevouts::All(&[prevout]),
            TapLeafHash::from_script(leaf, LeafVersion::TapScript),
            TapSighashType::Default,
        )
        .unwrap()
        .to_byte_array();
    let schnorr = schnorr_fun::new_with_deterministic_nonces::<sha2::Sha256>();
    let mut items = items.clone();
    for (item, key) in items.iter_mut().zip(signers) {
        *item = schnorr
            .sign(key, schnorr_fun::Message::raw(&sighash))
            .to_bytes()
            .to_vec();
    }
    tx.input[0].witness = items.into();
    tx
}

/// Version 3 with its one output, broadcast alone at the agreed fee.
fn assert_truc(tx: &Transaction) {
    assert_eq!(tx.version.0, 3);
    assert_eq!(tx.output.len(), 1);
}

fn assert_csv_rejects(chain: &Chain, tx: &Transaction) {
    let err = chain.broadcast(tx).unwrap_err();
    assert!(err.contains("Locktime requirement not satisfied"), "{err}");
}

/// Setup's cancel exchange: each signs, each checks the other's signature,
/// then cancel is broadcast once the lock is `t1` blocks deep and mined.
/// Returns cancel as mined.
fn cancel(chain: &Chain, parties: &Parties, swap: &Swap, lock: OutPoint) -> Transaction {
    let seller_sig = swap.sign(lock, Spend::Cancel, &parties.seller);
    let buyer_sig = swap.sign(lock, Spend::Cancel, &parties.buyer);
    assert!(swap.verify(lock, Spend::Cancel, Party::Seller, &seller_sig));
    assert!(swap.verify(lock, Spend::Cancel, Party::Buyer, &buyer_sig));
    let tx = swap
        .finalize(lock, Spend::Cancel, &seller_sig, Some(&buyer_sig))
        .unwrap();
    assert_truc(&tx);

    // The lock has one confirmation. Cancel can enter block `lock + t1`, so the
    // mempool accepts it once the tip is one below that.
    chain.mine(T1 as usize - 2);
    let early = chain.broadcast(&tx).unwrap_err();
    assert!(early.contains("non-BIP68-final"), "{early}");

    // A cancel asking for one block less passes BIP68 here, so only the
    // leaf's `<t1> CSV` stops it.
    let prevout = TxOut {
        value: swap.params().amount,
        script_pubkey: swap.lock_script_pubkey(),
    };
    let short = one_block_short(&tx, prevout, &[&parties.buyer, &parties.seller]);
    assert_csv_rejects(chain, &short);

    chain.mine(1);
    let txid = chain.broadcast(&tx).unwrap();
    chain.mine_and_fetch(txid)
}

#[test]
fn redeem_pays_seller_and_reveals_s() {
    let (chain, parties, swap, lock) = funded();

    // Buyer -> seller: B's redeem signature encrypted to S.
    let encrypted = swap
        .encrypted_sign(lock, Spend::Redeem, &parties.buyer)
        .unwrap();
    assert!(swap.verify_encrypted(lock, Spend::Redeem, &encrypted));

    // Seller decrypts with s, adds A's signature, broadcasts.
    let buyer_sig = swap.decrypt(&parties.s, &encrypted);
    let seller_sig = swap.sign(lock, Spend::Redeem, &parties.seller);
    let tx = swap
        .finalize(lock, Spend::Redeem, &seller_sig, Some(&buyer_sig))
        .unwrap();
    assert_truc(&tx);
    let txid = chain.broadcast(&tx).unwrap();
    let on_chain = chain.mine_and_fetch(txid);

    // Buyer reads the redeem from the chain and learns s.
    let s = swap
        .recover_secret(lock, Spend::Redeem, &encrypted, &on_chain)
        .unwrap();
    assert_eq!(s, parties.s);

    // The redeem is not a refund: nothing to recover under T_b.
    assert_eq!(
        swap.recover_secret(lock, Spend::Refund, &encrypted, &on_chain),
        Err(Error::Recovery)
    );
}

#[test]
fn cancel_then_refund_reveals_b() {
    let (chain, parties, swap, lock) = funded();

    // Seller -> buyer during setup: A's refund signature encrypted to T_b.
    let encrypted = swap
        .encrypted_sign(lock, Spend::Refund, &parties.seller)
        .unwrap();
    assert!(swap.verify_encrypted(lock, Spend::Refund, &encrypted));

    cancel(&chain, &parties, &swap, lock);

    // Buyer decrypts with b, adds B's signature, broadcasts.
    let seller_sig = swap.decrypt(&parties.b, &encrypted);
    let buyer_sig = swap.sign(lock, Spend::Refund, &parties.buyer);
    let tx = swap
        .finalize(lock, Spend::Refund, &seller_sig, Some(&buyer_sig))
        .unwrap();
    assert_truc(&tx);
    let txid = chain.broadcast(&tx).unwrap();
    let on_chain = chain.mine_and_fetch(txid);

    // Seller reads the refund from the chain and learns b.
    let b = swap
        .recover_secret(lock, Spend::Refund, &encrypted, &on_chain)
        .unwrap();
    assert_eq!(b, parties.b);
}

#[test]
fn cancel_then_punish_after_t2() {
    let (chain, parties, swap, lock) = funded();
    let cancel_tx = cancel(&chain, &parties, &swap, lock);

    let seller_sig = swap.sign(lock, Spend::Punish, &parties.seller);
    let tx = swap
        .finalize(lock, Spend::Punish, &seller_sig, None)
        .unwrap();
    assert_truc(&tx);

    // Cancel has one confirmation; same boundary as cancel itself.
    chain.mine(T2 as usize - 2);
    let early = chain.broadcast(&tx).unwrap_err();
    assert!(early.contains("non-BIP68-final"), "{early}");

    // Same for punish against the leaf's `<t2> CSV`.
    let short = one_block_short(&tx, cancel_tx.output[0].clone(), &[&parties.seller]);
    assert_csv_rejects(&chain, &short);

    chain.mine(1);
    let txid = chain.broadcast(&tx).unwrap();
    chain.mine_and_fetch(txid);
}

/// Below the node's relay feerate a spend is refused alone, but relays and
/// confirms in a package with a child that pays for both.
#[test]
fn a_spend_below_the_relay_feerate_relays_as_a_package() {
    let (chain, parties, swap, lock) = funded_on(Chain::start_with(&["-minrelaytxfee=0.0001"]));
    let encrypted = swap
        .encrypted_sign(lock, Spend::Redeem, &parties.buyer)
        .unwrap();
    let buyer_sig = swap.decrypt(&parties.s, &encrypted);
    let seller_sig = swap.sign(lock, Spend::Redeem, &parties.seller);
    let redeem = swap
        .finalize(lock, Spend::Redeem, &seller_sig, Some(&buyer_sig))
        .unwrap();
    let alone = chain.broadcast(&redeem).unwrap_err();
    assert!(alone.contains("min relay fee not met"), "{alone}");

    let child = chain.child(&redeem, Amount::from_sat(10_000));
    let result = chain.submit_package(&redeem, &child);
    assert_eq!(result["package_msg"], "success", "{result}");
    chain.mine(1);
    assert_eq!(chain.confirmations(redeem.compute_txid()), 1);
}

/// A script of the node's wallet, of `address_type` ("bech32", "bech32m").
fn wallet_script(chain: &Chain, address_type: &str) -> ScriptBuf {
    let address: Value = chain
        .node
        .client
        .call("getnewaddress", &["".into(), address_type.into()])
        .unwrap();
    let address: Address<NetworkUnchecked> = address.as_str().unwrap().parse().unwrap();
    address.assume_checked().script_pubkey()
}

/// After `t1` the buyer holds everything to send cancel and refund as one
/// package against a redeem still pending. With a P2WPKH refund against a
/// P2TR redeem that package pays a higher feerate than redeem and would
/// replace it, so `Swap::new` refuses those payouts. With the tightest
/// payouts it accepts, P2TR both, the package is one vbyte too heavy and
/// the redeem stays.
#[test]
fn cancel_and_refund_cannot_displace_a_pending_redeem() {
    let chain = Chain::start();
    let parties = Parties::random();
    let refused = Params {
        redeem_payout: wallet_script(&chain, "bech32m"),
        refund_payout: wallet_script(&chain, "bech32"),
        ..parties.params(chain.script())
    };
    assert_eq!(Swap::new(refused).err(), Some(Error::Outbid));

    let swap = Swap::new(Params {
        redeem_payout: wallet_script(&chain, "bech32m"),
        refund_payout: wallet_script(&chain, "bech32m"),
        ..parties.params(chain.script())
    })
    .unwrap();
    let lock = chain.fund(&swap.lock_script_pubkey(), swap.params().amount);
    let both = |spend| {
        let a = swap.sign(lock, spend, &parties.seller);
        let b = swap.sign(lock, spend, &parties.buyer);
        swap.finalize(lock, spend, &a, Some(&b)).unwrap()
    };
    let (redeem, cancel, refund) = (
        both(Spend::Redeem),
        both(Spend::Cancel),
        both(Spend::Refund),
    );
    assert_eq!(cancel.vsize() + refund.vsize(), 2 * redeem.vsize() + 1);
    let redeem = chain.broadcast(&redeem).unwrap();
    for _ in 0..T1 {
        let empty = Value::from(Vec::<String>::new());
        let _: Value = chain
            .node
            .client
            .call("generateblock", &[chain.miner.to_string().into(), empty])
            .unwrap();
    }
    assert_eq!(chain.confirmations(redeem), 0, "redeem pending past t1");

    let result = chain.submit_package(&cancel, &refund);
    assert_ne!(result["package_msg"], "success", "{result}");
    assert_eq!(
        result["replaced-transactions"],
        Value::from(Vec::<String>::new())
    );
    chain.mine(1);
    assert_eq!(chain.confirmations(redeem), 1);
}

#[test]
fn redeem_with_one_valid_signature_is_rejected() {
    let (chain, parties, swap, lock) = funded();
    let seller_sig = swap.sign(lock, Spend::Redeem, &parties.seller);
    let buyer_sig = swap.sign(lock, Spend::Redeem, &parties.buyer);
    let valid = swap
        .finalize(lock, Spend::Redeem, &seller_sig, Some(&buyer_sig))
        .unwrap();

    // Swap in a well-formed signature by the right key on the wrong
    // transaction, once for each key.
    let wrong_buyer = swap.sign(lock, Spend::Cancel, &parties.buyer);
    let wrong_seller = swap.sign(lock, Spend::Cancel, &parties.seller);
    for (index, wrong) in [(0, wrong_buyer), (1, wrong_seller)] {
        let mut tx = valid.clone();
        let mut items: Vec<Vec<u8>> = tx.input[0].witness.to_vec();
        items[index] = wrong.to_bytes().to_vec();
        tx.input[0].witness = items.into();
        let err = chain.broadcast(&tx).unwrap_err();
        assert!(err.contains("Invalid Schnorr signature"), "{err}");
    }

    // The library refuses to build it in the first place.
    assert_eq!(
        swap.finalize(lock, Spend::Redeem, &seller_sig, Some(&wrong_buyer)),
        Err(Error::Signature(Party::Buyer))
    );

    // And the untouched transaction still goes through.
    chain.broadcast(&valid).unwrap();
}

#[test]
fn adaptor_signature_to_the_wrong_point_fails() {
    let parties = Parties::random();
    let params = parties.params(offline_payout());
    let swap = Swap::new(params.clone()).unwrap();
    let lock = offline_lock();

    // Same transaction, encrypted to a point other than S.
    let other = Swap::new(Params {
        seller_share: share_point(&Scalar::random(&mut OsRng)),
        ..params
    })
    .unwrap();
    let encrypted = other
        .encrypted_sign(lock, Spend::Redeem, &parties.buyer)
        .unwrap();
    assert!(other.verify_encrypted(lock, Spend::Redeem, &encrypted));
    assert!(!swap.verify_encrypted(lock, Spend::Redeem, &encrypted));

    // Right point, wrong signer: the redeem adaptor must come from B.
    let by_seller = swap
        .encrypted_sign(lock, Spend::Redeem, &parties.seller)
        .unwrap();
    assert!(!swap.verify_encrypted(lock, Spend::Redeem, &by_seller));

    // Cancel and punish take no adaptor signature.
    assert!(swap
        .encrypted_sign(lock, Spend::Cancel, &parties.buyer)
        .is_none());
}

#[test]
fn tampered_signatures_fail() {
    let parties = Parties::random();
    let swap = Swap::new(parties.params(offline_payout())).unwrap();
    let lock = offline_lock();

    let sig = swap.sign(lock, Spend::Cancel, &parties.buyer);
    let mut bytes = sig.to_bytes();
    bytes[63] ^= 1;
    let tampered = swap_bitcoin::Signature::from_bytes(bytes).unwrap();
    assert!(swap.verify(lock, Spend::Cancel, Party::Buyer, &sig));
    assert!(!swap.verify(lock, Spend::Cancel, Party::Buyer, &tampered));
    // A valid signature by the wrong party.
    assert!(!swap.verify(lock, Spend::Cancel, Party::Seller, &sig));

    let mut encrypted = swap
        .encrypted_sign(lock, Spend::Redeem, &parties.buyer)
        .unwrap();
    encrypted.s_hat = swap_bitcoin::schnorr_fun::fun::s!(encrypted.s_hat + 1).public();
    assert!(!swap.verify_encrypted(lock, Spend::Redeem, &encrypted));

    // Decrypting with the wrong secret yields a signature finalize refuses.
    let encrypted = swap
        .encrypted_sign(lock, Spend::Redeem, &parties.buyer)
        .unwrap();
    let wrong = swap.decrypt(&parties.b, &encrypted);
    let seller_sig = swap.sign(lock, Spend::Redeem, &parties.seller);
    assert_eq!(
        swap.finalize(lock, Spend::Redeem, &seller_sig, Some(&wrong)),
        Err(Error::Signature(Party::Buyer))
    );
}
