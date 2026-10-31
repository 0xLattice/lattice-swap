//! The offer board: the offers sellers hold open here, for anyone to list
//! and take.
//!
//! An offer stays listed while its seller's connection does, and leaves when
//! a buyer takes it, so it needs no expiry of its own: a seller that goes
//! away takes its offer with it. Its id is its swap id, fresh for every
//! swap. The board stores the offer as the seller sent it and checks only
//! that it names a swap id: the buyer checks the rest, among it the seller's
//! signature over the terms, so the board need not be trusted with them.

use std::collections::HashMap;
use std::fmt;
use std::sync::{Arc, Mutex};

use tokio::sync::oneshot;

/// The most bytes an offer may hold; a real one holds about 1 KiB. With
/// the most sellers held, it bounds the board's memory.
pub const MAX_OFFER: usize = 4 * 1024;

/// The offers held, each with the way to hand it a buyer's connection `T`.
pub struct Board<T> {
    /// The most sellers connected at once, listed or swapping: each holds a
    /// connection, and a slot from listing until its connection closes. It
    /// bounds the board's memory and the connections it keeps.
    max: usize,
    inner: Mutex<Inner<T>>,
}

struct Inner<T> {
    /// Sellers connected, listed or piping to a buyer.
    held: usize,
    /// Tells listings of one id apart: a seller that lists again once
    /// its first listing was taken holds a new ticket.
    next_ticket: u64,
    listed: HashMap<String, Listing<T>>,
}

struct Listing<T> {
    ticket: u64,
    offer: String,
    taker: oneshot::Sender<T>,
}

/// Why the board refuses an offer.
#[derive(Debug, PartialEq, Eq)]
pub enum Refusal {
    /// Not an offer: no swap id in its terms.
    NotAnOffer(String),
    /// An offer of that swap id is listed already.
    Listed,
    /// The board holds as many sellers as it may.
    Full,
}

impl fmt::Display for Refusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Refusal::NotAnOffer(why) => write!(f, "not an offer: {why}"),
            Refusal::Listed => write!(f, "an offer of this swap id is listed already"),
            Refusal::Full => write!(f, "the board is full"),
        }
    }
}

/// A seller's slot on the board, from listing until it is dropped, when
/// its connection ends: the listing goes, if no buyer took it, and so does
/// the slot.
pub struct Ticket<T> {
    board: Arc<Board<T>>,
    id: String,
    ticket: u64,
    /// The buyer's connection, once one takes the offer.
    pub taker: oneshot::Receiver<T>,
}

impl<T> Ticket<T> {
    pub fn id(&self) -> &str {
        &self.id
    }
}

impl<T> Drop for Ticket<T> {
    fn drop(&mut self) {
        let mut inner = self.board.inner.lock().expect("the board's lock");
        inner.held -= 1;
        if inner
            .listed
            .get(&self.id)
            .is_some_and(|listing| listing.ticket == self.ticket)
        {
            inner.listed.remove(&self.id);
        }
    }
}

/// The swap id `offer` names: `terms.swap_id`, 32 bytes in lowercase hex.
pub fn offer_id(offer: &str) -> Result<String, String> {
    let offer: serde_json::Value = serde_json::from_str(offer).map_err(|e| e.to_string())?;
    let id = offer["terms"]["swap_id"]
        .as_str()
        .ok_or("its terms name no swap id")?;
    let hex = id.len() == 64
        && id
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b));
    if !hex {
        return Err(format!("swap id {id} is not 32 bytes of lowercase hex"));
    }
    Ok(id.to_string())
}

impl<T> Board<T> {
    pub fn new(max: usize) -> Arc<Self> {
        Arc::new(Self {
            max,
            inner: Mutex::new(Inner {
                held: 0,
                next_ticket: 0,
                listed: HashMap::new(),
            }),
        })
    }

    /// Lists `offer` under its swap id.
    pub fn list(self: &Arc<Self>, offer: String) -> Result<Ticket<T>, Refusal> {
        if offer.len() > MAX_OFFER {
            let why = format!("larger than {MAX_OFFER} bytes");
            return Err(Refusal::NotAnOffer(why));
        }
        let id = offer_id(&offer).map_err(Refusal::NotAnOffer)?;
        let mut inner = self.inner.lock().expect("the board's lock");
        if inner.listed.contains_key(&id) {
            return Err(Refusal::Listed);
        }
        if inner.held >= self.max {
            return Err(Refusal::Full);
        }
        let (taker, receiver) = oneshot::channel();
        let ticket = inner.next_ticket;
        inner.next_ticket += 1;
        inner.held += 1;
        inner.listed.insert(
            id.clone(),
            Listing {
                ticket,
                offer,
                taker,
            },
        );
        Ok(Ticket {
            board: self.clone(),
            id,
            ticket,
            taker: receiver,
        })
    }

    /// Takes offer `id` off the board, for one buyer: the way to hand the
    /// seller its connection.
    pub fn take(&self, id: &str) -> Option<oneshot::Sender<T>> {
        let mut inner = self.inner.lock().expect("the board's lock");
        inner.listed.remove(id).map(|listing| listing.taker)
    }

    pub fn contains(&self, id: &str) -> bool {
        let inner = self.inner.lock().expect("the board's lock");
        inner.listed.contains_key(id)
    }

    /// The offers listed, as their sellers sent them.
    pub fn offers(&self) -> Vec<String> {
        let inner = self.inner.lock().expect("the board's lock");
        inner
            .listed
            .values()
            .map(|listing| listing.offer.clone())
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn offer(n: u8) -> String {
        format!(
            r#"{{"terms":{{"swap_id":"{}"}},"relay":"x"}}"#,
            hex::encode([n; 32])
        )
    }

    #[test]
    fn an_offer_is_listed_until_taken_or_withdrawn() {
        let board = Board::<u32>::new(10);
        let mut ticket = board.list(offer(1)).unwrap();
        assert_eq!(ticket.id(), hex::encode([1; 32]));
        assert_eq!(board.offers(), vec![offer(1)]);
        assert!(board.contains(ticket.id()));

        // Taken once: it leaves the board and the seller gets the buyer.
        let taker = board.take(ticket.id()).unwrap();
        assert!(board.take(ticket.id()).is_none());
        assert!(board.offers().is_empty());
        taker.send(7).unwrap();
        assert_eq!(ticket.taker.try_recv().unwrap(), 7);

        // Withdrawn when its seller's connection ends.
        let ticket = board.list(offer(2)).unwrap();
        drop(ticket);
        assert!(board.offers().is_empty());
        assert!(board.take(&hex::encode([2; 32])).is_none());
    }

    #[test]
    fn a_swap_id_is_listed_once() {
        let board = Board::<u32>::new(10);
        let _first = board.list(offer(1)).unwrap();
        assert_eq!(board.list(offer(1)).err(), Some(Refusal::Listed));
    }

    /// A seller whose listing was taken may list the same offer again, and
    /// the end of its first connection leaves the second listed.
    #[test]
    fn an_old_ticket_withdraws_only_its_own_listing() {
        let board = Board::<u32>::new(10);
        let first = board.list(offer(1)).unwrap();
        board.take(first.id()).unwrap();
        let _second = board.list(offer(1)).unwrap();
        drop(first);
        assert_eq!(board.offers(), vec![offer(1)]);
    }

    /// A seller holds its slot while it swaps, after its offer left the
    /// board, and frees it when it goes.
    #[test]
    fn the_board_holds_at_most_max_sellers() {
        let board = Board::<u32>::new(2);
        let a = board.list(offer(1)).unwrap();
        let _b = board.list(offer(2)).unwrap();
        assert_eq!(board.list(offer(3)).err(), Some(Refusal::Full));
        board.take(a.id()).unwrap();
        assert_eq!(board.list(offer(3)).err(), Some(Refusal::Full));
        drop(a);
        board.list(offer(3)).unwrap();
    }

    #[test]
    fn an_offer_is_at_most_max_offer_bytes() {
        let board = Board::<u32>::new(2);
        let id = hex::encode([1; 32]);
        let sized = |n: usize| {
            let offer = format!(r#"{{"terms":{{"swap_id":"{id}"}},"pad":""}}"#);
            offer.replace(
                r#""pad":"""#,
                &format!(r#""pad":"{}""#, "x".repeat(n - offer.len())),
            )
        };
        assert!(matches!(
            board.list(sized(MAX_OFFER + 1)),
            Err(Refusal::NotAnOffer(_))
        ));
        assert_eq!(sized(MAX_OFFER).len(), MAX_OFFER);
        board.list(sized(MAX_OFFER)).unwrap();
    }

    #[test]
    fn an_offer_must_name_its_swap_id() {
        let board = Board::<u32>::new(2);
        for bad in [
            "not json",
            "{}",
            r#"{"terms":{"swap_id":7}}"#,
            r#"{"terms":{"swap_id":"ab"}}"#,
            &format!(r#"{{"terms":{{"swap_id":"{}"}}}}"#, "AB".repeat(32)),
            &format!(r#"{{"terms":{{"swap_id":"{}"}}}}"#, "gg".repeat(32)),
        ] {
            assert!(
                matches!(board.list(bad.into()), Err(Refusal::NotAnOffer(_))),
                "{bad}"
            );
        }
    }
}
