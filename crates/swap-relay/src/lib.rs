//! A relay for lattice-swap: an offer board and a pipe between the two
//! parties of a swap.
//!
//! The relay holds no keys and no funds. The parties run their ivy session
//! end to end through the pipe, so it sees only ciphertext, and each
//! authenticates the other's key; a buyer checks the seller's signature
//! over the terms of the offer it takes. The relay can drop or delay what
//! it carries, which ends a swap in a refund, but cannot change it.
//!
//! - `GET /offers`: the offers listed, as a JSON array.
//! - `GET /sell`, a WebSocket: the seller's first message is its offer.
//!   The relay answers `listed`, or `refused: <why>` and closes; then
//!   `paired` once a buyer takes the offer, after which the socket carries
//!   the session's bytes, as binary messages, to and from the buyer.
//! - `GET /take/<swap id>`, a WebSocket: pairs the buyer with the seller of
//!   that offer, which leaves the board; 404 if none is listed.

pub mod board;

use std::sync::Arc;
use std::time::{Duration, Instant};

use axum::body::Bytes;
use axum::extract::ws::{Message, WebSocket, WebSocketUpgrade};
use axum::extract::{Path, State};
use axum::http::{header, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use axum::Router;
use tokio::time::{interval, timeout, MissedTickBehavior};

use board::Board;

/// The most bytes one WebSocket message may hold: a piece of the session,
/// which the CLI sends at most 64 KiB at a time. The relay holds a message
/// whole while it passes it on, so this bounds what each pipe holds in each
/// direction. An offer is held to [`board::MAX_OFFER`].
pub const MAX_MESSAGE: usize = 64 * 1024;

/// How long a seller has to send its offer once connected: a connection
/// that lists nothing holds a socket, and no slot on the board.
pub const OFFER_WAIT: Duration = Duration::from_secs(10);

/// How often the relay pings each connection it holds, so a proxy in
/// between sees traffic on a pipe that waits an hour for a confirmation.
pub const PING: Duration = Duration::from_secs(30);

/// How long a connection may go without a word, a pong among them, before
/// the relay closes it: a peer gone with its connection still open would
/// otherwise keep its offer listed, or its pipe, for good.
pub const SILENCE: Duration = PING.saturating_mul(2);

/// The relay's state, shared by every connection.
pub struct Relay {
    pub board: Arc<Board<WebSocket>>,
}

/// The relay's routes.
pub fn router(relay: Arc<Relay>) -> Router {
    Router::new()
        .route("/offers", get(offers))
        .route("/sell", get(sell))
        .route("/take/{id}", get(take))
        .with_state(relay)
}

async fn offers(State(relay): State<Arc<Relay>>) -> Response {
    let body = format!("[{}]", relay.board.offers().join(","));
    ([(header::CONTENT_TYPE, "application/json")], body).into_response()
}

async fn sell(socket: WebSocketUpgrade, State(relay): State<Arc<Relay>>) -> Response {
    socket
        .max_message_size(MAX_MESSAGE)
        .on_upgrade(move |socket| seller(relay, socket))
}

/// Lists the seller's offer, waits for a buyer, then pipes the two.
async fn seller(relay: Arc<Relay>, mut socket: WebSocket) {
    let offer = match timeout(OFFER_WAIT, socket.recv()).await {
        Ok(Some(Ok(Message::Text(offer)))) => offer.to_string(),
        _ => return,
    };
    let mut ticket = match relay.board.list(offer) {
        Ok(ticket) => ticket,
        Err(refusal) => {
            let _ = socket
                .send(Message::Text(format!("refused: {refusal}").into()))
                .await;
            return;
        }
    };
    if socket.send(Message::Text("listed".into())).await.is_err() {
        return;
    }
    let mut ping = pinger();
    let mut heard = Instant::now();
    let buyer = loop {
        tokio::select! {
            buyer = &mut ticket.taker => match buyer {
                Ok(buyer) => break buyer,
                Err(_) => return,
            },
            message = socket.recv() => match message {
                Some(Ok(Message::Ping(_) | Message::Pong(_))) => heard = Instant::now(),
                // The seller left, or said something out of turn.
                _ => return,
            },
            _ = ping.tick() => {
                if heard.elapsed() > SILENCE
                    || socket.send(Message::Ping(Bytes::new())).await.is_err()
                {
                    return;
                }
            }
        }
    };
    if socket.send(Message::Text("paired".into())).await.is_err() {
        return;
    }
    // The seller keeps its slot while the two swap.
    pipe(socket, buyer).await;
    drop(ticket);
}

async fn take(
    Path(id): Path<String>,
    socket: WebSocketUpgrade,
    State(relay): State<Arc<Relay>>,
) -> Response {
    if !relay.board.contains(&id) {
        return (StatusCode::NOT_FOUND, "no such offer").into_response();
    }
    socket
        .max_message_size(MAX_MESSAGE)
        .on_upgrade(move |socket| async move {
            // Another buyer may have taken it since: then this socket is
            // dropped, and closes.
            if let Some(seller) = relay.board.take(&id) {
                let _ = seller.send(socket);
            }
        })
}

/// Carries binary messages between `a` and `b` until either closes, says
/// anything else, cannot be pinged, or is silent past [`SILENCE`].
async fn pipe(mut a: WebSocket, mut b: WebSocket) {
    let mut ping = pinger();
    let mut heard = [Instant::now(); 2];
    loop {
        let (message, to) = tokio::select! {
            message = a.recv() => {
                heard[0] = Instant::now();
                (message, &mut b)
            }
            message = b.recv() => {
                heard[1] = Instant::now();
                (message, &mut a)
            }
            _ = ping.tick() => {
                let ping = || Message::Ping(Bytes::new());
                if heard.iter().any(|heard| heard.elapsed() > SILENCE)
                    || a.send(ping()).await.is_err()
                    || b.send(ping()).await.is_err()
                {
                    break;
                }
                continue;
            }
        };
        match message {
            Some(Ok(Message::Binary(bytes))) => {
                if to.send(Message::Binary(bytes)).await.is_err() {
                    break;
                }
            }
            Some(Ok(Message::Ping(_) | Message::Pong(_))) => {}
            _ => break,
        }
    }
    let _ = a.send(Message::Close(None)).await;
    let _ = b.send(Message::Close(None)).await;
}

fn pinger() -> tokio::time::Interval {
    let mut ping = interval(PING);
    ping.set_missed_tick_behavior(MissedTickBehavior::Delay);
    // The first tick is at once.
    ping.reset();
    ping
}

/// Serves `relay` on `listener` until the process ends.
pub async fn serve(listener: tokio::net::TcpListener, relay: Arc<Relay>) -> std::io::Result<()> {
    axum::serve(listener, router(relay)).await
}
