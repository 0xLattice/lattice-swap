//! The offer board and the pipe, through a relay on loopback: sellers and
//! buyers run the CLI's own ivy sessions through it.

use std::io;
use std::sync::Arc;
use std::thread;
use std::time::Duration;

use ed25519_dalek::SigningKey;
use swap::transport::{Ivy, PeerKey, Relayed, Transport};
use swap_relay::board::Board;
use swap_relay::Relay;

const TIMEOUT: Duration = Duration::from_secs(10);

/// A relay on loopback, holding at most `max_offers` sellers: its URL.
fn relay(max_offers: usize) -> String {
    let relay = Arc::new(Relay {
        board: Board::new(max_offers),
        rejoins: Board::new(max_offers),
    });
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let url = format!("http://{}", listener.local_addr().unwrap());
    listener.set_nonblocking(true).unwrap();
    thread::spawn(move || {
        let runtime = tokio::runtime::Runtime::new().unwrap();
        runtime.block_on(async {
            let listener = tokio::net::TcpListener::from_std(listener).unwrap();
            swap_relay::serve(listener, relay).await.unwrap();
        });
    });
    url
}

fn offer(id: &str) -> String {
    format!(r#"{{"template":{{"swap_id":"{id}"}},"relay":"here"}}"#)
}

fn id(n: u8) -> String {
    hex::encode([n; 32])
}

fn config(seed: u8) -> ivy::Config {
    ivy::Config::new(SigningKey::from_bytes(&[seed; 32]))
}

fn key(seed: u8) -> PeerKey {
    config(seed).peer_key()
}

fn offers(url: &str) -> Vec<serde_json::Value> {
    ureq::get(&format!("{url}/offers"))
        .call()
        .unwrap()
        .into_json()
        .unwrap()
}

/// A seller, key 1, listing `offer` and waiting for the buyer of key 2.
fn seller(url: &str, offer: String) -> thread::JoinHandle<io::Result<Ivy<Relayed>>> {
    let url = url.to_string();
    thread::spawn(move || Ivy::accept_relayed(&url, &offer, &config(1), key(2), TIMEOUT, TIMEOUT))
}

fn wait_listed(url: &str, count: usize) {
    for _ in 0..200 {
        if offers(url).len() == count {
            return;
        }
        thread::sleep(Duration::from_millis(25));
    }
    panic!("{count} offers never listed");
}

/// A buyer finds the offer on the board, takes it, and the two run an ivy
/// session end to end through the relay, in both directions, with messages
/// larger than one relayed piece.
#[test]
fn a_buyer_takes_a_listed_offer_and_the_two_talk_through_the_relay() {
    let url = relay(10);
    let seller = seller(&url, offer(&id(1)));
    wait_listed(&url, 1);
    assert_eq!(offers(&url)[0]["template"]["swap_id"], id(1));
    // A buyer's page, on another origin, reads the board.
    let listed = ureq::get(&format!("{url}/offers")).call().unwrap();
    assert_eq!(listed.header("access-control-allow-origin"), Some("*"));

    let mut buyer = Ivy::connect_relayed(&url, &id(1), &config(2), key(1), TIMEOUT).unwrap();
    let mut seller = seller.join().unwrap().unwrap();
    // Taken: off the board.
    assert!(offers(&url).is_empty());

    let large = vec![7u8; 3 * swap::transport::RELAY_CHUNK + 5];
    buyer.send(b"hello").unwrap();
    assert_eq!(seller.recv(TIMEOUT).unwrap().unwrap(), b"hello");
    seller.send(&large).unwrap();
    assert_eq!(buyer.recv(TIMEOUT).unwrap().unwrap(), large);

    // A second taker finds nothing.
    let gone = Ivy::connect_relayed(&url, &id(1), &config(2), key(1), TIMEOUT).err();
    assert_eq!(gone.map(|e| e.kind()), Some(io::ErrorKind::NotFound));
}

/// A stranger that takes the offer fails the seller's handshake: the
/// seller lists it again, and the buyer it waits for gets through.
#[test]
fn a_seller_lists_again_past_a_stranger() {
    let url = relay(10);
    let seller = seller(&url, offer(&id(2)));
    wait_listed(&url, 1);
    let stranger = Ivy::connect_relayed(&url, &id(2), &config(3), key(1), TIMEOUT);
    assert!(stranger.is_err());
    wait_listed(&url, 1);
    let mut buyer = Ivy::connect_relayed(&url, &id(2), &config(2), key(1), TIMEOUT).unwrap();
    let mut seller = seller.join().unwrap().unwrap();
    seller.send(b"terms").unwrap();
    assert_eq!(buyer.recv(TIMEOUT).unwrap().unwrap(), b"terms");
}

/// The relay refuses a second listing of one swap id, an offer with no
/// swap id, and any seller past its bound; and a seller that goes takes
/// its offer with it.
#[test]
fn the_board_refuses_what_it_cannot_list() {
    let url = relay(2);
    let first = seller(&url, offer(&id(3)));
    wait_listed(&url, 1);
    let refused = |offer: String| {
        let accepted = Ivy::accept_relayed(&url, &offer, &config(1), key(2), TIMEOUT, TIMEOUT);
        accepted.err().unwrap().to_string()
    };
    let twice = refused(offer(&id(3)));
    assert!(twice.contains("listed already"), "{twice}");
    let junk = refused("{}".into());
    assert!(junk.contains("not an offer"), "{junk}");

    let _second = seller(&url, offer(&id(4)));
    wait_listed(&url, 2);
    let full = refused(offer(&id(5)));
    assert!(full.contains("full"), "{full}");
    drop(first);
}

/// A seller that gives up waiting takes its offer, and its slot, with it.
#[test]
fn a_seller_that_goes_frees_its_slot() {
    let url = relay(1);
    let wait = Duration::from_millis(300);
    for n in [6, 7] {
        let waited = Ivy::accept_relayed(&url, &offer(&id(n)), &config(1), key(2), wait, TIMEOUT)
            .err()
            .unwrap();
        assert_eq!(waited.kind(), io::ErrorKind::TimedOut, "{waited}");
        wait_listed(&url, 0);
    }
}

/// The seller, key 1, waiting at rendezvous `id` for the buyer of key 2.
fn rejoining_seller(url: &str, id: [u8; 32]) -> thread::JoinHandle<io::Result<Ivy<Relayed>>> {
    let url = url.to_string();
    thread::spawn(move || Ivy::accept_rejoined(&url, id, &config(1), key(2), TIMEOUT, TIMEOUT))
}

/// Once a swap's session is lost, its two parties meet again at their
/// rendezvous, whichever comes first, and talk end to end; the offer stays
/// off the board.
#[test]
fn the_two_parties_rejoin_at_their_rendezvous() {
    let url = relay(10);
    let rendezvous = [8; 32];
    for seller_first in [true, false] {
        let (seller, mut buyer) = if seller_first {
            let seller = rejoining_seller(&url, rendezvous);
            thread::sleep(Duration::from_millis(100));
            let buyer =
                Ivy::connect_rejoined(&url, rendezvous, &config(2), key(1), TIMEOUT, TIMEOUT);
            (seller, buyer.unwrap())
        } else {
            let at = url.clone();
            let buyer = thread::spawn(move || {
                Ivy::connect_rejoined(&at, rendezvous, &config(2), key(1), TIMEOUT, TIMEOUT)
            });
            thread::sleep(Duration::from_millis(100));
            let seller = rejoining_seller(&url, rendezvous);
            (seller, buyer.join().unwrap().unwrap())
        };
        let mut seller = seller.join().unwrap().unwrap();
        buyer.send(b"signatures").unwrap();
        assert_eq!(seller.recv(TIMEOUT).unwrap().unwrap(), b"signatures");
        seller.send(b"cid").unwrap();
        assert_eq!(buyer.recv(TIMEOUT).unwrap().unwrap(), b"cid");
        assert!(offers(&url).is_empty());
    }
}

/// A stranger who read the swap id from the board, or the whole offer,
/// cannot stand in for the buyer: the swap id is not the rendezvous, so the
/// seller waiting there never meets it, and the buyer that comes does.
#[test]
fn a_stranger_cannot_rejoin_a_swap() {
    let url = relay(10);
    let (swap_id, rendezvous) = ([1; 32], [8; 32]);
    let seller = rejoining_seller(&url, rendezvous);
    thread::sleep(Duration::from_millis(100));
    let wait = Duration::from_millis(500);
    // The buyer's session key, as an offer on the board shows it, and the
    // seller's key: at the swap id, at another rendezvous, no one comes.
    for at in [swap_id, [9; 32]] {
        let stranger = Ivy::connect_rejoined(&url, at, &config(2), key(1), wait, TIMEOUT);
        assert_eq!(stranger.err().unwrap().kind(), io::ErrorKind::TimedOut);
    }
    let mut buyer =
        Ivy::connect_rejoined(&url, rendezvous, &config(2), key(1), TIMEOUT, TIMEOUT).unwrap();
    let mut seller = seller.join().unwrap().unwrap();
    seller.send(b"cid").unwrap();
    assert_eq!(buyer.recv(TIMEOUT).unwrap().unwrap(), b"cid");
}

/// One who reached the rendezvous anyway, without the seller's key, fails
/// the buyer's handshake.
#[test]
fn only_the_seller_passes_a_rejoin_handshake() {
    let url = relay(10);
    let rendezvous = [8; 32];
    let at = url.clone();
    let impostor = thread::spawn(move || {
        Ivy::accept_rejoined(&at, rendezvous, &config(3), key(2), TIMEOUT, TIMEOUT)
    });
    thread::sleep(Duration::from_millis(100));
    let buyer = Ivy::connect_rejoined(&url, rendezvous, &config(2), key(1), TIMEOUT, TIMEOUT);
    assert!(buyer.is_err());
    assert!(impostor.join().unwrap().is_err());
}

/// A WebSocket to `path` on the relay at `url`, by hand, as a party whose
/// reads and writes the test controls byte by byte.
fn raw_socket(url: &str, path: &str) -> std::net::TcpStream {
    use std::io::{Read, Write};
    let mut socket = std::net::TcpStream::connect(url.trim_start_matches("http://")).unwrap();
    write!(
        socket,
        "GET /{path} HTTP/1.1\r\nHost: relay\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\
         Sec-WebSocket-Version: 13\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n\r\n"
    )
    .unwrap();
    socket.set_read_timeout(Some(TIMEOUT)).unwrap();
    let mut head = Vec::new();
    while !head.ends_with(b"\r\n\r\n") {
        let mut byte = [0];
        socket.read_exact(&mut byte).unwrap();
        head.push(byte[0]);
    }
    assert!(
        head.starts_with(b"HTTP/1.1 101"),
        "{}",
        String::from_utf8_lossy(&head)
    );
    socket
}

/// A client's frame: `opcode`, masked with a zero key.
fn frame(opcode: u8, payload: &[u8]) -> Vec<u8> {
    let mut frame = vec![0x80 | opcode, 0x80 | 127];
    frame.extend_from_slice(&(payload.len() as u64).to_be_bytes());
    frame.extend_from_slice(&[0; 4]);
    frame.extend_from_slice(payload);
    frame
}

/// The relay's next message on `socket` that is not a ping: its opcode and
/// payload.
fn raw_message(socket: &mut std::net::TcpStream) -> io::Result<(u8, Vec<u8>)> {
    use std::io::Read;
    loop {
        let mut header = [0; 2];
        socket.read_exact(&mut header)?;
        let len = match header[1] & 0x7f {
            126 => {
                let mut len = [0; 2];
                socket.read_exact(&mut len)?;
                u16::from_be_bytes(len) as usize
            }
            127 => {
                let mut len = [0; 8];
                socket.read_exact(&mut len)?;
                u64::from_be_bytes(len) as usize
            }
            len => len as usize,
        };
        let mut payload = vec![0; len];
        socket.read_exact(&mut payload)?;
        if header[0] & 0x0f != 9 {
            return Ok((header[0] & 0x0f, payload));
        }
    }
}

fn raw_text(socket: &mut std::net::TcpStream) -> String {
    let (opcode, payload) = raw_message(socket).unwrap();
    assert_eq!(opcode, 1);
    String::from_utf8(payload).unwrap()
}

/// A party that stops reading, its connection still open, does not hold
/// the pipe past [`swap_relay::SILENCE`]: the relay gives up passing a
/// message on to it, and ends the pipe, so the other party, its own pings
/// left unanswered meanwhile, is told the session is gone. Before, the
/// relay waited on the write for good, past its own pings and silence.
#[test]
fn a_buyer_that_stops_reading_ends_the_pipe() {
    one_stops_reading(Stops::Buyer);
}

/// As the buyer, so the seller: the buyer is told within
/// [`swap_relay::SILENCE`], not after the relay's close to the seller, as
/// stuck as its message was, has waited out its own.
#[test]
fn a_seller_that_stops_reading_ends_the_pipe() {
    one_stops_reading(Stops::Seller);
}

enum Stops {
    Buyer,
    Seller,
}

/// Pairs a seller and a buyer; the one that `stops` reads nothing while
/// the other writes until the relay, stuck writing to it, stops reading
/// too. The writer must then be told, within SILENCE of the stuck write,
/// by a close or the connection gone.
fn one_stops_reading(stops: Stops) {
    use std::io::Write;
    let url = relay(10);
    let mut seller = raw_socket(&url, "sell");
    seller
        .write_all(&frame(1, offer(&id(10)).as_bytes()))
        .unwrap();
    assert_eq!(raw_text(&mut seller), "listed");
    let buyer = raw_socket(&url, &format!("take/{}", id(10)));
    assert_eq!(raw_text(&mut seller), "paired");
    let (mut writer, _deaf) = match stops {
        Stops::Buyer => (seller, buyer),
        Stops::Seller => (buyer, seller),
    };

    writer
        .set_write_timeout(Some(Duration::from_secs(2)))
        .unwrap();
    let piece = frame(2, &vec![7; swap_relay::MAX_MESSAGE]);
    while writer.write_all(&piece).is_ok() {}

    let deadline = swap_relay::SILENCE + TIMEOUT;
    writer.set_read_timeout(Some(deadline)).unwrap();
    match raw_message(&mut writer) {
        Ok((8, _)) => {}
        Ok((opcode, _)) => panic!("not a close: {opcode}"),
        Err(e)
            if matches!(
                e.kind(),
                io::ErrorKind::UnexpectedEof | io::ErrorKind::ConnectionReset
            ) => {}
        Err(e) => panic!("the relay held the pipe past {deadline:?}: {e}"),
    }
}

/// A frame that announces more than a message may hold ends the connection
/// at its header: the relay never sets aside room for it, which would let
/// a few connections, each sending one such frame, hold the relay's memory.
#[test]
fn a_frame_past_the_message_bound_ends_the_connection_at_its_header() {
    use std::io::{Read, Write};
    let url = relay(10);
    let mut socket = raw_socket(&url, &format!("rejoin/{}", id(9)));
    socket
        .set_read_timeout(Some(Duration::from_secs(3)))
        .unwrap();

    // A binary frame, masked, of one byte more than a message may hold:
    // its header only.
    let mut header = vec![0x82, 0x80 | 127];
    header.extend_from_slice(&(swap_relay::MAX_MESSAGE as u64 + 1).to_be_bytes());
    header.extend_from_slice(&[0; 4]);
    socket.write_all(&header).unwrap();
    let mut rest = Vec::new();
    match socket.read_to_end(&mut rest) {
        Ok(_) => {}
        Err(e) if e.kind() == io::ErrorKind::ConnectionReset => {}
        Err(e) => panic!("the relay held the connection open, waiting for the frame: {e}"),
    }
}
