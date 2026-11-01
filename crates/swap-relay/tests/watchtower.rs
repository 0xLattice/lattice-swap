//! The watchtower on regtest: a buyer that gave up hands over its refund
//! and goes offline; once cancel confirms, the relay, restarted meanwhile,
//! broadcasts the refund, and forgets the watch once it is deep.
//!
//! The relay reads the chain through a small Esplora shim over bitcoind,
//! here in the test: the calls the watchtower makes, answered as Esplora
//! does, `/tx/{txid}/status` unconfirmed even for a txid never seen.

use std::net::TcpListener;
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant, SystemTime};

use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::IntoResponse;
use axum::routing::{get, post};
use axum::{Json, Router};
use bitcoin::consensus::encode::serialize_hex;
use bitcoin::{Amount, FeeRate, Network, Txid};
use corepc_node::{Conf, Node};
use serde_json::{json, Value};
use swap::bitcoind::{Bitcoin, Bitcoind};
use swap::driver::bitcoin_view;
use swap::{Action, Buyer, Event, Machine, Message, SecretBytes, Seller, Terms};
use swap_bitcoin::Spend;
use swap_relay::board::Board;
use swap_relay::watch::{Esplora, Watchtower};
use swap_relay::Relay;

const TIMEOUT: Duration = Duration::from_secs(10);
/// The driver's default `max_tip_age`.
const AGE: Duration = Duration::from_secs(90 * 60);

fn rpc(node: &Node, wallet: &str) -> Bitcoind {
    let cookie = std::fs::read_to_string(&node.params.cookie_file).unwrap();
    let url = match wallet {
        "" => node.rpc_url(),
        wallet => node.rpc_url_with_wallet(wallet),
    };
    Bitcoind::new(&url, &cookie, Network::Regtest, TIMEOUT)
}

/// Serves `router` on loopback, on its own runtime: its URL.
fn serve(router: Router) -> String {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let url = format!("http://{}", listener.local_addr().unwrap());
    listener.set_nonblocking(true).unwrap();
    thread::spawn(move || {
        let runtime = tokio::runtime::Runtime::new().unwrap();
        runtime.block_on(async {
            let listener = tokio::net::TcpListener::from_std(listener).unwrap();
            axum::serve(listener, router).await.unwrap();
        });
    });
    url
}

type Shared = Arc<Bitcoind>;

/// Runs `call` on bitcoind off the runtime.
async fn ask<T: Send + 'static>(
    node: &Shared,
    call: impl FnOnce(&Bitcoind) -> T + Send + 'static,
) -> T {
    let node = node.clone();
    tokio::task::spawn_blocking(move || call(&node))
        .await
        .unwrap()
}

fn height_of(node: &Bitcoind, tx: &Value) -> Option<u64> {
    let hash = tx["blockhash"].as_str()?;
    let header = node.call("getblockheader", json!([hash])).unwrap();
    header["height"].as_u64()
}

fn status(node: &Bitcoind, tx: &Value) -> Value {
    match height_of(node, tx) {
        Some(height) => json!({"confirmed": true, "block_height": height}),
        None => json!({"confirmed": false}),
    }
}

/// What spends `txid:vout`: the mempool first, then every block from the
/// tip down.
fn outspend(node: &Bitcoind, txid: &str, vout: u64) -> Value {
    let unspent = node.call("gettxout", json!([txid, vout, true])).unwrap();
    if !unspent.is_null() {
        return json!({"spent": false});
    }
    let spends = |tx: &Value| {
        tx["vin"].as_array().unwrap().iter().any(|input| {
            input["txid"].as_str() == Some(txid) && input["vout"].as_u64() == Some(vout)
        })
    };
    let pool = node.call("getrawmempool", json!([])).unwrap();
    for spender in pool.as_array().unwrap() {
        let tx = node
            .call("getrawtransaction", json!([spender, true]))
            .unwrap();
        if spends(&tx) {
            return json!({"spent": true, "txid": tx["txid"], "status": {"confirmed": false}});
        }
    }
    let mut hash = node.call("getbestblockhash", json!([])).unwrap();
    while !hash.is_null() {
        let block = node.call("getblock", json!([hash, 2])).unwrap();
        for tx in block["tx"].as_array().unwrap() {
            if spends(tx) {
                let status = json!({"confirmed": true, "block_height": block["height"]});
                return json!({"spent": true, "txid": tx["txid"], "status": status});
            }
        }
        hash = block["previousblockhash"].clone();
    }
    json!({"spent": false})
}

/// The Esplora calls the watchtower makes, answered from `node`.
fn esplora(node: Bitcoind) -> String {
    let router = Router::new()
        .route(
            "/blocks/tip/height",
            get(|State(node): State<Shared>| async move {
                let count = ask(&node, |n| n.call("getblockcount", json!([])).unwrap()).await;
                count.to_string()
            }),
        )
        .route(
            "/tx/{txid}",
            get(
                |State(node): State<Shared>, Path(txid): Path<String>| async move {
                    let answer = ask(&node, move |n| {
                        let tx = n.call("getrawtransaction", json!([txid, true])).ok()?;
                        Some(json!({"txid": tx["txid"], "status": status(n, &tx)}))
                    });
                    match answer.await {
                        Some(tx) => Json(tx).into_response(),
                        None => (StatusCode::NOT_FOUND, "Transaction not found").into_response(),
                    }
                },
            ),
        )
        .route(
            "/tx/{txid}/hex",
            get(
                |State(node): State<Shared>, Path(txid): Path<String>| async move {
                    let hex = ask(&node, move |n| {
                        n.call("getrawtransaction", json!([txid, false])).ok()
                    });
                    match hex.await {
                        Some(hex) => hex.as_str().unwrap().to_string().into_response(),
                        None => (StatusCode::NOT_FOUND, "Transaction not found").into_response(),
                    }
                },
            ),
        )
        .route(
            "/tx/{txid}/status",
            get(
                |State(node): State<Shared>, Path(txid): Path<String>| async move {
                    let status = ask(&node, move |n| {
                        match n.call("getrawtransaction", json!([txid, true])) {
                            Ok(tx) => status(n, &tx),
                            Err(_) => json!({"confirmed": false}),
                        }
                    });
                    Json(status.await)
                },
            ),
        )
        .route(
            "/tx/{txid}/outspend/{vout}",
            get(
                |State(node): State<Shared>, Path((txid, vout)): Path<(String, u64)>| async move {
                    Json(ask(&node, move |n| outspend(n, &txid, vout)).await)
                },
            ),
        )
        .route(
            "/tx",
            post(|State(node): State<Shared>, hex: String| async move {
                let sent = ask(&node, move |n| n.call("sendrawtransaction", json!([hex])));
                match sent.await {
                    Ok(txid) => txid.as_str().unwrap().to_string().into_response(),
                    Err(e) => (StatusCode::BAD_REQUEST, e.to_string()).into_response(),
                }
            }),
        )
        .with_state(Arc::new(node));
    serve(router)
}

fn sent(actions: &[Action]) -> Message {
    let [Action::Send(message)] = actions else {
        panic!("one message: {actions:?}");
    };
    message.clone()
}

fn pooled(node: &Bitcoind, txid: Txid) -> bool {
    node.call("getmempoolentry", json!([txid.to_string()]))
        .is_ok()
}

fn wait_for(what: &str, mut done: impl FnMut() -> bool) {
    let deadline = Instant::now() + Duration::from_secs(60);
    while !done() {
        assert!(Instant::now() < deadline, "timed out waiting for {what}");
        thread::sleep(Duration::from_millis(100));
    }
}

#[test]
fn the_relay_refunds_a_buyer_that_went_offline() {
    let mut conf = Conf::default();
    conf.args.push("-txindex");
    let node = Node::from_downloaded_with_conf(&conf).expect("start bitcoind");
    let miner = node.client.new_address().unwrap();
    let mine = |blocks| drop(node.client.generate_to_address(blocks, &miner).unwrap());
    mine(101);
    let default = rpc(&node, "default");
    let payout = |wallet: &Bitcoind| {
        let address = wallet.call("getnewaddress", json!([])).unwrap();
        let address: bitcoin::Address<bitcoin::address::NetworkUnchecked> =
            address.as_str().unwrap().parse().unwrap();
        address.assume_checked().script_pubkey()
    };

    // The two machines, stepped by hand, to the BTC lock.
    let terms = Terms {
        swap_id: [5; 32],
        btc_amount: Amount::from_sat(1_000_000),
        btc_fee: Amount::from_sat(1_000),
        nex_amount: 1_000,
        nex_fee: 0,
        // The floor: 1 + 6 x (1 + 1) + 2.
        t1: 15,
        t2: 6,
        btc_confirmations: 1,
        nex_confirmations: 1,
        margin: 2,
        nexus_genesis: swap_nexus_tx::MAINNET_GENESIS.into(),
    };
    let seller_nex = SecretBytes([3; 32]).nex_address();
    let seller = Seller::new(
        terms.clone(),
        seller_nex,
        payout(&default),
        payout(&default),
    );
    let refund_payout = payout(&default);
    let (buyer, actions) = Buyer::start(terms, refund_payout.clone(), "buyer".into()).unwrap();
    let step = |machine: Seller, actions: &[Action]| machine.step(Event::Message(sent(actions)));
    let (seller, actions) = step(seller.unwrap(), &actions);
    let (buyer, actions) = buyer.step(Event::Message(sent(&actions)));
    let [Action::FundLock {
        script_pubkey,
        amount,
    }] = &actions[..]
    else {
        panic!("fund the lock: {actions:?}");
    };
    let funding = default
        .fund_lock(script_pubkey, *amount, FeeRate::from_sat_per_vb_u32(10))
        .unwrap();
    let (buyer, actions) = buyer.step(Event::Funded(funding.clone()));
    let (seller, actions) = step(seller, &actions);
    let (buyer, actions) = buyer.step(Event::Message(sent(&actions)));
    let _ = step(seller, &actions);
    let (buyer, actions) = buyer.step(Event::Sent);
    assert!(matches!(&actions[..], [Action::Broadcast(_)]));
    default
        .call("sendrawtransaction", json!([serialize_hex(&funding)]))
        .unwrap();
    mine(1);
    let (swap, lock) = buyer.watch().bitcoin.unwrap();
    // Locked and waiting for the NEX: the refund is handed to no one.
    assert!(buyer.watchtower().is_none());

    // No NEX lock comes. At t1 the buyer gives up and cancels; now, and only
    // now, it hands over its refund.
    mine(14);
    let view = bitcoin_view(&default, &swap, lock, AGE, SystemTime::now(), &mut None).unwrap();
    let (buyer, actions) = buyer.step(Event::Bitcoin(view));
    let [Action::Broadcast(cancel)] = &actions[..] else {
        panic!("cancel: {actions:?}");
    };
    let (watched_cancel, refund) = buyer.watchtower().expect("the buyer gave up");
    // Signed again, with fresh nonces.
    assert_eq!(watched_cancel.compute_txid(), cancel.compute_txid());
    assert_eq!(
        cancel.compute_txid(),
        swap.unsigned_tx(lock, Spend::Cancel).compute_txid()
    );
    assert_eq!(
        refund.compute_txid(),
        swap.unsigned_tx(lock, Spend::Refund).compute_txid()
    );
    assert_eq!(refund.output[0].script_pubkey, refund_payout);

    // The relay takes the watch over HTTP once it sees cancel; the buyer
    // goes offline.
    let esplora_url = esplora(rpc(&node, ""));
    let watches = tempfile::tempdir().unwrap();
    let relay = Arc::new(Relay {
        board: Board::new(10),
        watchtower: Arc::new(Watchtower::open(Network::Regtest, watches.path(), 10).unwrap()),
        chain: Arc::new(Esplora::new(&esplora_url, TIMEOUT)),
    });
    let url = serve(swap_relay::router(relay));
    let watch = json!({
        "network": "regtest",
        "cancel": serialize_hex(cancel),
        "refund": serialize_hex(&refund),
        "depth": 1,
    });
    // The answer, or the status refusing the watch.
    let post = |watch: &Value| match ureq::post(&format!("{url}/watch")).send_json(watch) {
        Ok(answer) => Ok(answer.into_string().unwrap()),
        Err(ureq::Error::Status(status, _)) => Err(status),
        Err(e) => panic!("{e}"),
    };
    // On another network, refused for good.
    let mut mainnet = watch.clone();
    mainnet["network"] = "bitcoin".into();
    assert_eq!(post(&mainnet), Err(400));
    // Before cancel is out, refused for now.
    assert_eq!(post(&watch), Err(503));
    default
        .call("sendrawtransaction", json!([serialize_hex(cancel)]))
        .unwrap();
    // Whoever posts cancel first, stripped of its witness, takes the slot,
    // but the relay keeps Esplora's copy, which can be broadcast again.
    let mut stripped_cancel = cancel.clone();
    stripped_cancel.input[0].witness = bitcoin::Witness::new();
    let mut stripped = watch.clone();
    stripped["cancel"] = serialize_hex(&stripped_cancel).into();
    assert_eq!(post(&stripped), Ok(cancel.compute_txid().to_string()));
    assert_eq!(post(&watch), Ok(cancel.compute_txid().to_string()));
    drop(buyer);

    // The relay restarts: the watch is read back from disk, and watched.
    let tower = Arc::new(Watchtower::open(Network::Regtest, watches.path(), 10).unwrap());
    assert_eq!(tower.len(), 1);
    // Meanwhile cancel expires from the mempool: a fortnight passes, and
    // the next transaction in sweeps it out.
    let now = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    default
        .call("setmocktime", json!([now + 30 * 24 * 60 * 60]))
        .unwrap();
    let address = default.call("getnewaddress", json!([])).unwrap();
    default
        .call("sendtoaddress", json!([address, 0.001]))
        .unwrap();
    assert!(!pooled(&default, cancel.compute_txid()));
    let watcher = tower.clone();
    thread::spawn(move || {
        let esplora = Esplora::new(&esplora_url, TIMEOUT);
        watcher.run(&esplora, Duration::from_millis(200))
    });

    // The relay broadcasts cancel again. No refund while cancel waits in
    // the mempool; once it is in a block, the refund goes out.
    wait_for("cancel again", || pooled(&default, cancel.compute_txid()));
    thread::sleep(Duration::from_secs(1));
    assert!(!pooled(&default, refund.compute_txid()));
    mine(1);
    wait_for("the refund", || pooled(&default, refund.compute_txid()));
    mine(1);
    wait_for("the watch to end", || tower.is_empty());
    let tx = default
        .call(
            "getrawtransaction",
            json!([refund.compute_txid().to_string(), true]),
        )
        .unwrap();
    assert!(tx["confirmations"].as_u64() >= Some(1));
}
