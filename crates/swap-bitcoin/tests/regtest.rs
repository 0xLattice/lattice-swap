//! Every swap path, broadcast to a real regtest bitcoind.

use corepc_node::serde_json::Value;
use corepc_node::{Conf, Node};
use rand_core::OsRng;
use swap_bitcoin::bitcoin::consensus::encode::deserialize_hex;
use swap_bitcoin::bitcoin::hashes::Hash;
use swap_bitcoin::bitcoin::{
    Address, Amount, Network, OutPoint, ScriptBuf, Transaction, Txid, WPubkeyHash,
};
use swap_bitcoin::{Error, EvenY, KeyPair, Params, Party, Point, Scalar, Spend, Swap};

const T1: u16 = 10;
const T2: u16 = 5;

struct Chain {
    node: Node,
    miner: Address,
}

impl Chain {
    fn start() -> Self {
        let mut conf = Conf::default();
        conf.args.push("-txindex");
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
    let chain = Chain::start();
    let parties = Parties::random();
    let swap = Swap::new(parties.params(chain.script())).unwrap();
    let lock = chain.fund(&swap.lock_script_pubkey(), swap.params().amount);
    (chain, parties, swap, lock)
}

/// Setup's cancel exchange: each signs, each checks the other's signature,
/// then cancel is broadcast once the lock is `t1` blocks deep and mined.
fn cancel(chain: &Chain, parties: &Parties, swap: &Swap, lock: OutPoint) {
    let seller_sig = swap.sign(lock, Spend::Cancel, &parties.seller);
    let buyer_sig = swap.sign(lock, Spend::Cancel, &parties.buyer);
    assert!(swap.verify(lock, Spend::Cancel, Party::Seller, &seller_sig));
    assert!(swap.verify(lock, Spend::Cancel, Party::Buyer, &buyer_sig));
    let tx = swap
        .finalize(lock, Spend::Cancel, &seller_sig, Some(&buyer_sig))
        .unwrap();

    // The lock has one confirmation. Cancel can enter block `lock + t1`, so the
    // mempool accepts it once the tip is one below that.
    chain.mine(T1 as usize - 2);
    let early = chain.broadcast(&tx).unwrap_err();
    assert!(early.contains("non-BIP68-final"), "{early}");
    chain.mine(1);
    let txid = chain.broadcast(&tx).unwrap();
    chain.mine_and_fetch(txid);
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
    cancel(&chain, &parties, &swap, lock);

    let seller_sig = swap.sign(lock, Spend::Punish, &parties.seller);
    let tx = swap
        .finalize(lock, Spend::Punish, &seller_sig, None)
        .unwrap();

    // Cancel has one confirmation; same boundary as cancel itself.
    chain.mine(T2 as usize - 2);
    let early = chain.broadcast(&tx).unwrap_err();
    assert!(early.contains("non-BIP68-final"), "{early}");
    chain.mine(1);
    let txid = chain.broadcast(&tx).unwrap();
    chain.mine_and_fetch(txid);
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
