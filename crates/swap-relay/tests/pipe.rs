//! The offer board and the pipe, through a relay on loopback: sellers and
//! buyers run the CLI's own ivy sessions through it.

use std::io;
use std::sync::Arc;
use std::thread;
use std::time::Duration;

use bitcoin::Network;
use ed25519_dalek::SigningKey;
use swap::transport::{Ivy, PeerKey, Relayed, Transport};
use swap_relay::board::Board;
use swap_relay::watch::Watchtower;
use swap_relay::Relay;

const TIMEOUT: Duration = Duration::from_secs(10);

/// A relay on loopback, holding at most `max_offers` sellers: its URL.
fn relay(max_offers: usize) -> (String, tempfile::TempDir) {
    let watches = tempfile::tempdir().unwrap();
    let relay = Arc::new(Relay {
        board: Board::new(max_offers),
        watchtower: Arc::new(Watchtower::open(Network::Regtest, watches.path(), 10).unwrap()),
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
    (url, watches)
}

fn offer(id: &str) -> String {
    format!(r#"{{"terms":{{"swap_id":"{id}"}},"relay":"here"}}"#)
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
    let (url, _watches) = relay(10);
    let seller = seller(&url, offer(&id(1)));
    wait_listed(&url, 1);
    assert_eq!(offers(&url)[0]["terms"]["swap_id"], id(1));

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
    let (url, _watches) = relay(10);
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
    let (url, _watches) = relay(2);
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
    let (url, _watches) = relay(1);
    let wait = Duration::from_millis(300);
    for n in [6, 7] {
        let waited = Ivy::accept_relayed(&url, &offer(&id(n)), &config(1), key(2), wait, TIMEOUT)
            .err()
            .unwrap();
        assert_eq!(waited.kind(), io::ErrorKind::TimedOut, "{waited}");
        wait_listed(&url, 0);
    }
}
