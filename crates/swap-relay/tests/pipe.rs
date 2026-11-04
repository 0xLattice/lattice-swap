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
