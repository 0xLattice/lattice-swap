//! A small Esplora over bitcoind, for tests: the calls the browser's swap
//! driver makes, answered as Esplora answers them, `/tx/{txid}/status`
//! unconfirmed even for a txid never seen.

use std::net::TcpListener;
use std::sync::{Arc, Mutex};
use std::thread;

use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::IntoResponse;
use axum::routing::{get, post};
use axum::{Json, Router};
use serde_json::{json, Value};
use swap::bitcoind::Bitcoind;

/// Serves `router` on loopback, on its own runtime: its URL.
pub fn serve(router: Router) -> String {
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

/// The Esplora calls the browser's driver makes, answered from `node`.
pub fn esplora(node: Bitcoind) -> String {
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
            "/blocks/tip/hash",
            get(|State(node): State<Shared>| async move {
                let hash = ask(&node, |n| n.call("getbestblockhash", json!([])).unwrap()).await;
                hash.as_str().unwrap().to_string()
            }),
        )
        .route(
            "/block/{hash}",
            get(
                |State(node): State<Shared>, Path(hash): Path<String>| async move {
                    let header = ask(&node, move |n| n.call("getblockheader", json!([hash])).ok());
                    match header.await {
                        Some(header) => Json(json!({
                            "id": header["hash"],
                            "height": header["height"],
                            "timestamp": header["time"],
                        }))
                        .into_response(),
                        None => (StatusCode::NOT_FOUND, "Block not found").into_response(),
                    }
                },
            ),
        )
        // Regtest has no fee estimates; Esplora then answers none.
        .route("/fee-estimates", get(|| async { Json(json!({})) }))
        .route(
            "/address/{address}/utxo",
            get(
                |State(node): State<Shared>, Path(address): Path<String>| async move {
                    Json(ask(&node, move |n| utxos(n, &address)).await)
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

/// The confirmed outputs paying `address`, as Esplora lists them; the
/// mempool's are left out, which the driver never spends. bitcoind runs
/// one scan at a time.
fn utxos(node: &Bitcoind, address: &str) -> Value {
    static SCAN: Mutex<()> = Mutex::new(());
    let _scan = SCAN.lock().unwrap();
    let descriptor = format!("addr({address})");
    let scan = node
        .call("scantxoutset", json!(["start", [descriptor]]))
        .unwrap();
    let utxos: Vec<Value> = scan["unspents"]
        .as_array()
        .unwrap()
        .iter()
        .map(|utxo| {
            let sats = (utxo["amount"].as_f64().unwrap() * 1e8).round() as u64;
            json!({
                "txid": utxo["txid"],
                "vout": utxo["vout"],
                "value": sats,
                "status": {"confirmed": true, "block_height": utxo["height"]},
            })
        })
        .collect();
    Value::Array(utxos)
}
