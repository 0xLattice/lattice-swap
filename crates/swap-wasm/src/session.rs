//! The buyer's ivy session, as the CLI's `Ivy::connect_relayed` runs it,
//! over bytes the page carries: ivy-core does the handshake and seals and
//! opens every record, and this frames them on the relay's byte stream.

use ed25519_dalek::SigningKey;
use ivy_core::{frame, frame_length, Config, Initiator, Message as Record, PeerKey, Session};
use rand_core::OsRng;
use swap::{Message, TOPIC};
use wasm_bindgen::prelude::*;

use crate::{parse, swap_id_bytes, text, Result};

/// The most bytes one WebSocket message carries, as the CLI's `Relayed`
/// writes them: what a relay holds of one.
const RELAY_CHUNK: usize = 64 * 1024;

/// A peer's pings are answered only while less than this waits to be
/// written, as `ivy::Connection` answers them.
const PONG_BACKLOG: usize = 64 * 1024;

/// One session to the seller an offer names. Write [`Ivy::outbound`] to
/// the relay's socket whenever it holds bytes, and pass every binary
/// message from the socket to [`Ivy::receive`]. Any error ends the session:
/// the swap goes on from the chains.
#[wasm_bindgen]
pub struct Ivy {
    /// `None` once open.
    handshake: Option<Initiator<'static>>,
    session: Option<Session>,
    /// The frame limit until the session sets its own.
    max_frame_size: u32,
    /// Bytes received; those before `read_from` are taken.
    inbound: Vec<u8>,
    read_from: usize,
    /// Framed records not yet taken by [`Ivy::outbound`].
    outbound: Vec<u8>,
    swap_id: [u8; 32],
}

#[wasm_bindgen]
impl Ivy {
    /// Opens the handshake to the seller whose key `peer` is, as the
    /// session key `session_key` (hex), both as the offer names them, for
    /// the swap `swap_id` (hex): its hello is the first outbound.
    #[wasm_bindgen(constructor)]
    pub fn new(session_key: &str, peer: &str, swap_id: &str) -> Result<Ivy> {
        let mut seed = [0u8; 32];
        hex::decode_to_slice(session_key.trim(), &mut seed)
            .map_err(|_| "the session key is not 32 bytes of hex")?;
        let peer = PeerKey::from_hex(peer).ok_or("the seller key is not a key")?;
        // The initiator borrows its config for the handshake; the session
        // it opens keeps its own copy. One small config per swap stays.
        let config: &'static Config =
            Box::leak(Box::new(Config::new(SigningKey::from_bytes(&seed))));
        let (handshake, hello) =
            Initiator::start(config, peer, &mut OsRng).map_err(|e| format!("ivy: {e:?}"))?;
        Ok(Ivy {
            handshake: Some(handshake),
            session: None,
            max_frame_size: config.metadata.max_frame_size,
            inbound: Vec::new(),
            read_from: 0,
            outbound: frame(&hello),
            swap_id: swap_id_bytes(swap_id)?,
        })
    }

    /// Whether the handshake is done: messages can be sent.
    #[wasm_bindgen(js_name = isOpen)]
    pub fn is_open(&self) -> bool {
        self.session.is_some()
    }

    /// The next bytes to write, at most one WebSocket message's worth;
    /// empty when nothing waits.
    pub fn outbound(&mut self) -> Vec<u8> {
        let n = self.outbound.len().min(RELAY_CHUNK);
        self.outbound.drain(..n).collect()
    }

    /// Takes bytes from the relay: the swap messages they complete, as
    /// JSON. Anything on another topic, or for another swap, is dropped.
    pub fn receive(&mut self, bytes: &[u8]) -> Result<Vec<String>> {
        self.inbound.extend_from_slice(bytes);
        let mut messages = vec![];
        while let Some(record) = self.take_frame()? {
            let Some(session) = &mut self.session else {
                let handshake = self.handshake.take().ok_or("the session ended")?;
                let (session, finish) = handshake
                    .receive(&record)
                    .map_err(|e| format!("ivy: {e:?}"))?;
                self.outbound.extend_from_slice(&frame(&finish));
                self.max_frame_size = session.max_inbound_frame_size();
                self.session = Some(session);
                continue;
            };
            match session.open(&record).map_err(|e| format!("ivy: {e:?}"))? {
                Some(Record::PeerMessage { topic, payload }) if topic == TOPIC => {
                    if let Some(message) = Message::decode(&payload, self.swap_id) {
                        messages.push(text(&message)?);
                    }
                }
                Some(Record::Ping(nonce)) if self.outbound.len() < PONG_BACKLOG => {
                    let pong = session
                        .seal(&Record::Pong(nonce))
                        .map_err(|e| format!("ivy: {e:?}"))?;
                    self.outbound.extend_from_slice(&frame(&pong));
                }
                _ => {}
            }
        }
        // Keep only what is unread.
        self.inbound.drain(..self.read_from);
        self.read_from = 0;
        Ok(messages)
    }

    /// Seals `message`, a swap message as JSON, as the CLI sends it, onto
    /// the outbound.
    pub fn send(&mut self, message: &str) -> Result<()> {
        let session = self.session.as_mut().ok_or("the session is not open")?;
        let payload = parse::<Message>(message)?.encode(self.swap_id);
        let record = session
            .seal(&Record::PeerMessage {
                topic: TOPIC.into(),
                payload,
            })
            .map_err(|e| format!("ivy: {e:?}"))?;
        self.outbound.extend_from_slice(&frame(&record));
        Ok(())
    }
}

impl Ivy {
    /// The next whole frame's record, if one has arrived.
    fn take_frame(&mut self) -> Result<Option<Vec<u8>>> {
        let unread = &self.inbound[self.read_from..];
        let Some(header) = unread.first_chunk::<4>() else {
            return Ok(None);
        };
        let length =
            frame_length(*header, self.max_frame_size).ok_or("ivy: frame length out of range")?;
        let Some(record) = unread.get(4..4 + length) else {
            return Ok(None);
        };
        let record = record.to_vec();
        self.read_from += 4 + length;
        Ok(Some(record))
    }
}
