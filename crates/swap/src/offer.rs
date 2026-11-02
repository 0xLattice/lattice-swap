//! The offer a seller hands a buyer, and the buyer's policy on it: the CLI
//! and a browser read and judge an offer by the same code.

use std::net::SocketAddr;

use bitcoin::{Amount, Network};
use ed25519_dalek::{Signer, SigningKey, VerifyingKey};
use ivy_core::PeerKey;
use serde::{Deserialize, Serialize};

use crate::{btc_fee_at, Terms};

/// The seller's price and the BTC it takes at it, as eigenwallet's ASB
/// quotes one (`BidQuote { price, min_quantity, max_quantity }`,
/// eigenwallet/core swap-p2p/src/protocols/quote.rs): the buyer picks an
/// amount in the range, and the seller fixes the terms at it when the buyer
/// takes the offer.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Quote {
    /// Satoshis a NEX, as `BidQuote::price` is the BTC one XMR costs: NEX
    /// has no smaller unit.
    pub price: u64,
    /// The least BTC the seller takes, in satoshis.
    pub min_btc_amount: u64,
    /// The most BTC the seller takes, in satoshis.
    pub max_btc_amount: u64,
}

impl Quote {
    /// The NEX `btc_amount` satoshis buy at the price, rounded down, as
    /// eigenwallet's `Rate::quote` truncates its XMR amount
    /// (swap-feed/src/rate.rs, `Decimal::to_u64`): what is left of
    /// `btc_amount` buys nothing. 0 at a price of 0, which no terms that
    /// work take.
    pub fn nex_amount(&self, btc_amount: u64) -> u64 {
        btc_amount.checked_div(self.price).unwrap_or(0)
    }
}

/// The terms an offer fixes before the buyer picks its amount: all but
/// `btc_amount` and `nex_amount`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Template {
    #[serde(with = "hex::serde")]
    pub swap_id: [u8; 32],
    #[serde(with = "bitcoin::amount::serde::as_sat")]
    pub btc_fee: Amount,
    pub nex_fee: u64,
    pub t1: u16,
    pub t2: u16,
    pub btc_confirmations: u32,
    pub nex_confirmations: u64,
    pub margin: u16,
    pub nexus_genesis: String,
}

impl Template {
    /// The terms of a swap of `btc_amount` satoshis: these, at the NEX
    /// `quote`'s price gives for them.
    pub fn terms(&self, quote: &Quote, btc_amount: u64) -> Terms {
        Terms {
            swap_id: self.swap_id,
            btc_amount: Amount::from_sat(btc_amount),
            btc_fee: self.btc_fee,
            nex_amount: quote.nex_amount(btc_amount),
            nex_fee: self.nex_fee,
            t1: self.t1,
            t2: self.t2,
            btc_confirmations: self.btc_confirmations,
            nex_confirmations: self.nex_confirmations,
            margin: self.margin,
            nexus_genesis: self.nexus_genesis.clone(),
        }
    }

    /// Whether every amount in `quote`'s range can be swapped: the range
    /// is not empty, and the terms work at both its ends, and so in
    /// between, since [`Terms::check`] bounds the amounts only from below
    /// and the debit from above. If not, why.
    pub fn check(&self, quote: &Quote) -> Result<(), String> {
        if quote.min_btc_amount > quote.max_btc_amount {
            return Err(format!(
                "the quote's range is empty: min_btc_amount {} is above max_btc_amount {}",
                quote.min_btc_amount, quote.max_btc_amount
            ));
        }
        for end in [quote.min_btc_amount, quote.max_btc_amount] {
            self.terms(quote, end)
                .check()
                .map_err(|why| format!("at {end} sat, {why}"))?;
        }
        Ok(())
    }
}

/// What the buyer needs to take the swap: the seller's quote and the terms
/// template, among them the Nexus the seller trades on, where the seller
/// listens or the relay it waits on, its key, and the session key the
/// seller made for the buyer, the only one it accepts. Whoever holds an
/// offer can take it. The Nexus in the terms is only a courtesy: a buyer on
/// another refuses before it locks anything, but the buyer's safety is its
/// own node's check against its own `--nexus-genesis`.
///
/// The seller signs the quote, the template and the network with its key,
/// which the buyer's session then authenticates: a relay, or anyone the
/// offer passes through, cannot hand the buyer another price or other terms
/// for the seller's key. Without it, the terms each machine checks alone,
/// such as the confirmations and the margin, could differ between the two
/// and neither would refuse. The rest needs no signature: another address,
/// relay or buyer session key reaches no seller, or one that refuses the
/// buyer.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct Offer {
    pub quote: Quote,
    pub template: Template,
    pub btc_network: Network,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub address: Option<SocketAddr>,
    /// The relay the seller waits on, by its URL, which pairs a buyer with
    /// it by the swap id.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub relay: Option<String>,
    pub seller: String,
    #[serde(with = "hex::serde")]
    pub buyer_session: [u8; 32],
    #[serde(with = "hex::serde")]
    pub signature: [u8; 64],
}

/// What the seller signs: the quote, the template and the network, tagged.
/// The tag names the format: an offer of a fixed amount, signed under
/// `lattice-swap offer`, verifies under no other.
fn signed(quote: &Quote, template: &Template, network: Network) -> Vec<u8> {
    serde_json::to_vec(&("lattice-swap offer 2", quote, template, network))
        .expect("offers serialize")
}

impl Offer {
    /// The offer, signed by `seller`, whose key it names.
    pub fn new(
        quote: Quote,
        template: Template,
        btc_network: Network,
        place: Place,
        seller: &SigningKey,
        buyer_session: [u8; 32],
    ) -> Self {
        let (address, relay) = match place {
            Place::Address(address) => (Some(address), None),
            Place::Relay(relay) => (None, Some(relay)),
        };
        let mut offer = Offer {
            quote,
            template,
            btc_network,
            address,
            relay,
            seller: hex::encode(seller.verifying_key().to_bytes()),
            buyer_session,
            signature: [0; 64],
        };
        offer.sign(seller);
        offer
    }

    pub fn sign(&mut self, seller: &SigningKey) {
        self.signature = seller
            .sign(&signed(&self.quote, &self.template, self.btc_network))
            .to_bytes();
    }

    pub fn encode(&self) -> String {
        serde_json::to_string(self).expect("offers serialize")
    }

    /// The offer in `text`, if it is one, says where to find the seller,
    /// and the seller signed its quote and template.
    pub fn decode(text: &str) -> Result<Self, String> {
        let offer: Offer =
            serde_json::from_str(text.trim()).map_err(|e| format!("not an offer: {e}"))?;
        let key = offer.seller_key()?;
        offer.place()?;
        let key = VerifyingKey::from_bytes(key.as_bytes()).expect("a peer key is a key");
        let signature = ed25519_dalek::Signature::from_bytes(&offer.signature);
        let signed = signed(&offer.quote, &offer.template, offer.btc_network);
        key.verify_strict(&signed, &signature)
            .map_err(|_| "the offer's terms are not signed by its seller")?;
        Ok(offer)
    }

    /// Where the seller is: an address or a relay, not both.
    pub fn place(&self) -> Result<Place, String> {
        match (self.address, &self.relay) {
            (Some(address), None) => Ok(Place::Address(address)),
            (None, Some(relay)) => Ok(Place::Relay(relay.clone())),
            _ => Err("the offer must name an address or a relay, not both".into()),
        }
    }

    pub fn seller_key(&self) -> Result<PeerKey, String> {
        PeerKey::from_hex(&self.seller).ok_or_else(|| "the offer's seller key is not a key".into())
    }

    /// The terms of a swap of `btc_amount` satoshis: the template, at the
    /// NEX the quote's price gives for them.
    pub fn terms(&self, btc_amount: u64) -> Terms {
        self.template.terms(&self.quote, btc_amount)
    }

    /// [`Template::check`] on the offer's quote.
    pub fn check(&self) -> Result<(), String> {
        self.template.check(&self.quote)
    }

    /// The seller's answer to a buyer's request for `btc_amount` satoshis
    /// at `price`, judged against this, its current quote, as eigenwallet's
    /// ASB judges a `SpotPriceRequest` against its latest rate and its
    /// limits before it agrees (swap-p2p/src/protocols/swap_setup/alice.rs,
    /// `run_swap_setup`): the terms at that amount, or why not. A request
    /// at another price is refused: the buyer judged the offer by it.
    pub fn answer(&self, btc_amount: u64, price: u64) -> Answer {
        let q = &self.quote;
        if price != q.price {
            Answer::Refused(Declined::PriceChanged { price: q.price })
        } else if btc_amount < q.min_btc_amount {
            Answer::Refused(Declined::AmountBelowMinimum {
                min: q.min_btc_amount,
            })
        } else if btc_amount > q.max_btc_amount {
            Answer::Refused(Declined::AmountAboveMaximum {
                max: q.max_btc_amount,
            })
        } else {
            Answer::Terms(self.terms(btc_amount))
        }
    }

    /// The terms in the seller's `answer` to the request `policy` makes,
    /// if they are exactly the ones asked for: the template at the
    /// policy's amount and the NEX the signed price gives for it. Then
    /// both sides run on the same terms, as each checks them.
    pub fn check_answer(&self, policy: &Policy, answer: &Answer) -> Result<Terms, String> {
        let terms = match answer {
            Answer::Refused(why) => return Err(format!("refused by the seller: {why}")),
            Answer::Terms(terms) => terms,
        };
        if policy.price != self.quote.price || *terms != self.terms(policy.btc_amount) {
            return Err(format!(
                "refused: the seller's terms are not the ones asked for: {} sat for {} NEX at \
                 {} sat a NEX",
                policy.btc_amount,
                self.quote.nex_amount(policy.btc_amount),
                self.quote.price
            ));
        }
        terms.check()?;
        Ok(terms.clone())
    }

    /// The offer, for the buyer to read before it dials.
    pub fn describe(&self) -> String {
        let (q, t) = (&self.quote, &self.template);
        format!(
            "{} sat a NEX, {} to {} sat, on {}: fees {} sat and {} NEX, t1 {}, t2 {}, {} \
             Bitcoin and {} Nexus confirmations, margin {}; {}",
            q.price,
            q.min_btc_amount,
            q.max_btc_amount,
            self.btc_network,
            t.btc_fee.to_sat(),
            t.nex_fee,
            t.t1,
            t.t2,
            t.btc_confirmations,
            t.nex_confirmations,
            t.margin,
            match self.place() {
                Ok(Place::Address(address)) => format!("dialling {address}"),
                Ok(Place::Relay(relay)) => format!("through the relay {relay}"),
                Err(e) => e,
            }
        )
    }
}

/// The seller's answer to the buyer's [`crate::Message::Request`], as
/// eigenwallet's `SpotPriceResponse` answers a `SpotPriceRequest`
/// (swap-p2p/src/protocols/swap_setup.rs): the terms, or why not.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum Answer {
    Terms(Terms),
    Refused(Declined),
}

/// Why a seller refuses a request, as eigenwallet's `SpotPriceError`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum Declined {
    /// The quote's price is not the one the buyer asked at.
    PriceChanged {
        price: u64,
    },
    AmountBelowMinimum {
        min: u64,
    },
    AmountAboveMaximum {
        max: u64,
    },
}

impl std::fmt::Display for Declined {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Declined::PriceChanged { price } => write!(f, "the price is {price} sat a NEX"),
            Declined::AmountBelowMinimum { min } => write!(f, "the least it takes is {min} sat"),
            Declined::AmountAboveMaximum { max } => write!(f, "the most it takes is {max} sat"),
        }
    }
}

/// Where the buyer finds the seller.
pub enum Place {
    Address(SocketAddr),
    Relay(String),
}

/// What the buyer agreed to, and its bounds on every other term: a buyer
/// refuses an offer outside them.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Policy {
    /// The BTC to pay, in satoshis: what the buyer asks the seller for, in
    /// the offer's range.
    pub btc_amount: u64,
    /// The price agreed to, in satoshis a NEX.
    pub price: u64,
    #[serde(flatten)]
    pub bounds: Bounds,
}

/// A buyer's bounds on the terms it did not agree to itself. A field left
/// out takes its [`Bounds::DEFAULT`]: the tool's settings, not protocol
/// rules.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct Bounds {
    /// The most each Bitcoin swap transaction may pay, in satoshis.
    pub max_btc_fee: u64,
    /// The most the NEX lock and the claim from it may pay.
    pub max_nex_fee: u64,
    /// The least the NEX lock and the claim from it may pay, and the Nexus
    /// node's minRelayFee if higher: a fee one node pools may still be
    /// below what the network relays.
    pub min_nex_fee: u64,
    /// The most Bitcoin blocks the BTC stays locked before cancel.
    pub max_t1: u16,
    /// The fewest Bitcoin blocks after cancel confirms before punish is
    /// valid.
    pub min_t2: u16,
    /// The fewest Bitcoin confirmations the offer may ask.
    pub min_btc_confirmations: u32,
    /// The most Bitcoin confirmations the offer may ask. Once it has signed
    /// the redeem, the buyer refunds only when cancel is this deep.
    pub max_btc_confirmations: u32,
    /// The fewest Bitcoin blocks the refund has to confirm in before punish
    /// is valid, once the buyer has signed the redeem: t2 -
    /// btc_confirmations.
    pub min_refund_window: u16,
    /// The fee rate, in sat/vB, that each Bitcoin swap transaction must pay
    /// when there is no fee estimate, as on regtest. Otherwise the estimate
    /// for 6 blocks is the floor.
    pub min_btc_fee_rate: Option<u64>,
    /// The fewest Nexus confirmations of the NEX lock this buyer accepts.
    pub min_nex_confirmations: u64,
    /// The fewest Bitcoin blocks of slack before a timelock.
    pub min_margin: u16,
}

impl Bounds {
    pub const DEFAULT: Self = Self {
        max_btc_fee: 10_000,
        max_nex_fee: 1_000,
        min_nex_fee: 1,
        max_t1: 288,
        min_t2: 144,
        min_btc_confirmations: 6,
        max_btc_confirmations: 12,
        min_refund_window: 72,
        min_btc_fee_rate: None,
        min_nex_confirmations: 24,
        min_margin: 6,
    };
}

impl Default for Bounds {
    fn default() -> Self {
        Self::DEFAULT
    }
}

/// The least `btc_fee` the buyer takes, in satoshis: what the fee estimate
/// for 6 blocks, `estimate` in sat/kvB, or else `min_btc_fee_rate` sat/vB,
/// asks of every swap spend.
pub fn btc_fee_floor(estimate: Option<u64>, min_btc_fee_rate: Option<u64>) -> Result<u64, String> {
    let per_kvb = match estimate {
        Some(per_kvb) => per_kvb,
        None => min_btc_fee_rate
            .ok_or("there is no fee estimate: give min_btc_fee_rate")?
            .saturating_mul(1000),
    };
    Ok(btc_fee_at(per_kvb))
}

/// The least `nex_fee` a party runs: `least`, or its Nexus node's relay
/// floor if higher. A node's floor alone is not the network's: one that
/// pools a fee its peers do not relay leaves the NEX lock, or the claim,
/// unmined.
pub fn nex_fee_floor(least: u64, min_relay_fee: u64) -> u64 {
    least.max(min_relay_fee)
}

/// An offer the buyer takes: a quote at the price it agreed to, whose range
/// holds the amount it asks for, terms at that amount that work, on its
/// Bitcoin network and its Nexus, a Bitcoin fee of at least
/// `btc_fee_floor`, a Nexus fee of at least `nex_fee_floor`, and every
/// other term within its bounds.
pub fn check_offer(
    offer: &Offer,
    policy: &Policy,
    network: Network,
    nexus_genesis: &str,
    btc_fee_floor: u64,
    nex_fee_floor: u64,
) -> std::result::Result<(), String> {
    offer.check()?;
    let quote = &offer.quote;
    let terms = &offer.terms(policy.btc_amount);
    let refused = |why: String| Err(format!("refused: the offer {why}"));
    if offer.btc_network != network {
        return refused(format!("is on {}, not {network}", offer.btc_network));
    }
    if terms.nexus_genesis != nexus_genesis {
        return refused(format!(
            "is on the Nexus of genesis {}, not {nexus_genesis}",
            terms.nexus_genesis
        ));
    }
    if quote.price != policy.price {
        return refused(format!(
            "asks {} sat a NEX, not {}",
            quote.price, policy.price
        ));
    }
    if policy.btc_amount < quote.min_btc_amount || policy.btc_amount > quote.max_btc_amount {
        return refused(format!(
            "takes {} to {} sat, not {}",
            quote.min_btc_amount, quote.max_btc_amount, policy.btc_amount
        ));
    }
    if terms.btc_fee.to_sat() > policy.bounds.max_btc_fee {
        return refused(format!(
            "pays {} sat a Bitcoin transaction, above {}",
            terms.btc_fee.to_sat(),
            policy.bounds.max_btc_fee
        ));
    }
    if terms.btc_fee.to_sat() < btc_fee_floor {
        return refused(format!(
            "pays {} sat a Bitcoin transaction, below the {btc_fee_floor} sat its node's fee \
             rate asks",
            terms.btc_fee.to_sat()
        ));
    }
    if terms.nex_fee > policy.bounds.max_nex_fee {
        return refused(format!(
            "pays {} NEX a Nexus transaction, above {}",
            terms.nex_fee, policy.bounds.max_nex_fee
        ));
    }
    if terms.nex_fee < nex_fee_floor {
        return refused(format!(
            "pays {} NEX a Nexus transaction, below {nex_fee_floor}, --min-nex-fee or its \
             node's minRelayFee",
            terms.nex_fee
        ));
    }
    if terms.t1 > policy.bounds.max_t1 {
        return refused(format!(
            "has t1 {}, above {}",
            terms.t1, policy.bounds.max_t1
        ));
    }
    if terms.t2 < policy.bounds.min_t2 {
        return refused(format!(
            "has t2 {}, below {}",
            terms.t2, policy.bounds.min_t2
        ));
    }
    if terms.btc_confirmations < policy.bounds.min_btc_confirmations {
        return refused(format!(
            "asks {} Bitcoin confirmations, fewer than {}",
            terms.btc_confirmations, policy.bounds.min_btc_confirmations
        ));
    }
    if terms.btc_confirmations > policy.bounds.max_btc_confirmations {
        return refused(format!(
            "asks {} Bitcoin confirmations, more than {}",
            terms.btc_confirmations, policy.bounds.max_btc_confirmations
        ));
    }
    let window = u64::from(terms.t2).saturating_sub(u64::from(terms.btc_confirmations));
    if window < u64::from(policy.bounds.min_refund_window) {
        return refused(format!(
            "leaves {window} blocks to refund in, t2 - btc_confirmations, fewer than {}",
            policy.bounds.min_refund_window
        ));
    }
    if terms.nex_confirmations < policy.bounds.min_nex_confirmations {
        return refused(format!(
            "asks {} Nexus confirmations, fewer than {}",
            terms.nex_confirmations, policy.bounds.min_nex_confirmations
        ));
    }
    if terms.margin < policy.bounds.min_margin {
        return refused(format!(
            "has margin {}, below {}",
            terms.margin, policy.bounds.min_margin
        ));
    }
    Ok(())
}
