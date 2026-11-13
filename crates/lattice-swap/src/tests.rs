use super::*;
use bitcoin::hashes::Hash;
use bitcoin::{OutPoint, WScriptHash};
use clap::CommandFactory;
use serde_json::Value;
use swap::driver::Reconnect;
use swap::session::request_terms;
use swap::transport::PeerKey;
use swap::{btc_amount_floor, btc_fee_at};
use swap_bitcoin::{KeyPair, Params, Scalar, Spend, Swap};
use swap_nexus_tx::MAINNET_GENESIS as MAINNET;

const NODES: [&str; 6] = [
    "--btc-wallet",
    "w",
    "--btc-cookie",
    "/c",
    "--nexus-url",
    "http://127.0.0.1:1",
];

fn parse(args: &[&str]) -> std::result::Result<Cli, clap::Error> {
    let nexus = ["--nexus-cookie", "/n"];
    Cli::try_parse_from(
        ["lattice-swap"]
            .iter()
            .chain(args)
            .chain(&NODES)
            .chain(&nexus),
    )
}

fn offer_args(extra: &[&str]) -> OfferArgs {
    let mut args = vec![
        "offer",
        "--price",
        "50000000",
        "--min-btc-amount",
        "10000000",
        "--max-btc-amount",
        "50000000",
        "--btc-fee",
        "1000",
        "--nex-fee",
        "10",
        "--listen",
        "127.0.0.1:0",
    ];
    args.extend(extra);
    match parse(&args).unwrap().command {
        Command::Offer(args) => args,
        _ => panic!("an offer"),
    }
}

/// Terms whose floor is 1 + 6 x (1 + 1) + 3 = 16.
fn small(t1: u16) -> Terms {
    terms_of(&small_args(t1))
}

/// The offer of [`small`].
fn small_args(t1: u16) -> OfferArgs {
    offer_args(&[
        "--btc-confirmations",
        "1",
        "--nex-confirmations",
        "1",
        "--margin",
        "3",
        "--t2",
        "10",
        "--t1",
        &t1.to_string(),
    ])
}

/// The terms `args` offer at the most they take.
fn terms_of(args: &OfferArgs) -> Terms {
    let quote = args.terms.quote();
    let template = args.terms.template([7; 32], MAINNET.into());
    template.terms(&quote, quote.max_btc_amount)
}

/// The offer `args` make, signed by `key`.
fn offer_of(args: &OfferArgs, network: Network, place: Place, key: &SigningKey) -> Offer {
    let template = args.terms.template([7; 32], MAINNET.into());
    Offer::new(args.terms.quote(), template, network, place, key, [7; 32])
}

#[test]
fn the_defaults_are_the_agreed_settings_and_pass() {
    let args = offer_args(&[]);
    let terms = terms_of(&args);
    assert_eq!((terms.t1, terms.t2), (288, 144));
    assert_eq!((terms.btc_confirmations, terms.nex_confirmations), (6, 12));
    assert_eq!(terms.btc_amount, Amount::from_sat(50_000_000));
    assert_eq!(terms.nex_amount, 1_000_000);
    assert_eq!(args.nodes.btc_network, Network::Bitcoin);
    let template = args.terms.template([7; 32], MAINNET.into());
    assert_eq!(template.check(&args.terms.quote()), Ok(()));
}

#[test]
fn t1_below_the_floor_is_refused() {
    assert_eq!(small(16).t1_floor(), 16);
    let refused = Terms::check(&small(15)).unwrap_err();
    assert!(refused.contains("below 16"), "{refused}");
}

#[test]
fn t1_at_the_floor_is_accepted() {
    assert_eq!(Terms::check(&small(16)), Ok(()));
}

#[test]
fn terms_that_cannot_work_are_refused() {
    let mut terms = small(16);
    terms.margin = 1;
    assert!(Terms::check(&terms).is_err());
}

#[test]
fn the_floor_does_not_overflow() {
    let mut terms = small(16);
    terms.nex_confirmations = u64::MAX;
    assert!(Terms::check(&terms).is_err());
}

#[test]
fn no_secret_is_taken_as_an_argument() {
    for secret in ["--nex-key", "--btc-password"] {
        let args = ["resume", "x.json", secret, "00"];
        assert!(parse(&args).is_err(), "{secret}");
    }
}

#[test]
fn refund_runs_like_resume() {
    let swap_file = "/s/0707070707070707070707070707070707070707070707070707070707070707.json";
    for command in ["resume", "refund"] {
        let args = ["--nex-key-file", "/k"];
        match parse(&[&[command, swap_file][..], &args].concat())
            .unwrap()
            .command
        {
            Command::Resume(args) => {
                let store = swap_store(&args.swap_file).unwrap();
                assert_eq!(store.path(), Path::new(swap_file));
            }
            _ => panic!("{command}"),
        }
    }
}

#[test]
fn a_swap_file_is_named_by_its_swap_id() {
    assert!(swap_store(Path::new("07.json")).is_err());
    assert!(swap_store(Path::new(&format!("{}.txt", "07".repeat(32)))).is_err());
    let store = swap_store(Path::new(&format!("{}.json", "07".repeat(32)))).unwrap();
    assert_eq!(
        store.path(),
        Path::new(&format!("./{}.json", "07".repeat(32)))
    );
}

fn address() -> Place {
    Place::Address("192.0.2.1:7000".parse().unwrap())
}

#[test]
fn an_offer_parses_back_into_the_same_terms() {
    let key = SigningKey::from_bytes(&random32());
    for place in [address(), Place::Relay("https://relay.example".into())] {
        let args = offer_args(&[]);
        let template = args.terms.template(random32(), MAINNET.into());
        let quote = args.terms.quote();
        let offer = Offer::new(quote, template, Network::Signet, place, &key, random32());
        let text = offer.encode();
        assert!(!text.contains('\n'), "one line");
        assert_eq!(Offer::decode(&format!("{text}\n")).unwrap(), offer);
    }
    // The session authenticates the key the offer names, which signs it.
    let offer = offer_of(&small_args(16), Network::Signet, address(), &key);
    let peer = ivy::Config::new(key).peer_key();
    assert_eq!(offer.seller_key().unwrap(), peer);
}

#[test]
fn an_offer_with_a_bad_seller_key_is_refused() {
    let key = SigningKey::from_bytes(&[1; 32]);
    let mut offer = offer_of(&small_args(16), Network::Bitcoin, address(), &key);
    offer.seller = "00".repeat(31);
    assert!(Offer::decode(&offer.encode()).is_err());
}

/// Whoever carries an offer, a relay among them, cannot change its terms
/// or network for the seller's key without the buyer refusing it: each
/// machine checks some terms alone, which could otherwise differ between
/// the two with neither refusing.
#[test]
fn an_offer_whose_terms_are_changed_is_refused() {
    let key = SigningKey::from_bytes(&[1; 32]);
    let signed = offer_of(&small_args(16), Network::Bitcoin, address(), &key);
    Offer::decode(&signed.encode()).unwrap();
    type Change = (&'static str, fn(&mut Offer));
    let changes: [Change; 4] = [
        ("confirmations", |o| o.template.nex_confirmations -= 1),
        ("margin", |o| o.template.margin += 1),
        ("network", |o| o.btc_network = Network::Testnet),
        ("signature", |o| o.signature[0] ^= 1),
    ];
    for (what, change) in changes {
        let mut offer = signed.clone();
        change(&mut offer);
        let refused = Offer::decode(&offer.encode()).unwrap_err().to_string();
        assert!(
            refused.contains("not signed by its seller"),
            "{what}: {refused}"
        );
    }
    // Signed by another key, which it does not name.
    let mut offer = signed.clone();
    offer.sign(&SigningKey::from_bytes(&[2; 32]));
    assert!(Offer::decode(&offer.encode()).is_err());
    // What needs no signature: another place or buyer session reaches no
    // seller that takes the buyer.
    let mut offer = signed.clone();
    offer.address = None;
    offer.relay = Some("http://elsewhere.example".into());
    offer.buyer_session = [8; 32];
    Offer::decode(&offer.encode()).unwrap();
}

/// One offer listed on several relays: each copy names its own relay and
/// still verifies, on the one swap id and keys, so whichever a buyer takes
/// reaches the same seller, through the relay it read it on.
#[test]
fn an_offer_listed_on_several_relays_names_each() {
    let key = SigningKey::from_bytes(&[1; 32]);
    let relays = ["http://a.example".to_string(), "http://b.example".into()];
    let offer = offer_of(
        &small_args(16),
        Network::Bitcoin,
        Place::Relay(relays[0].clone()),
        &key,
    );
    let copies = listed_on(&offer, &relays);
    assert_eq!(copies.len(), 2);
    for (copy, relay) in copies.iter().zip(&relays) {
        let decoded = Offer::decode(&copy.encode()).unwrap();
        assert!(matches!(decoded.place(), Ok(Place::Relay(at)) if at == *relay));
        assert_eq!(decoded.template, offer.template);
        assert_eq!(decoded.seller, offer.seller);
        assert_eq!(decoded.buyer_session, offer.buyer_session);
    }
    assert_eq!(listed_on(&offer, &relays[..1]), [offer]);
}

/// A relay given twice, in any spelling of the same server, is listed on
/// once: the second listing would be refused as listed already, and tried
/// again for good.
#[test]
fn a_relay_given_twice_is_listed_on_once() {
    let relays = [
        "https://relay.example",
        "HTTPS://Relay.Example:443/",
        "https://relay.example//",
        "https://relay.example:8443",
        "http://relay.example:80",
        "http://relay.example",
        "https://relay.example/path/",
        "https://relay.example/path",
        "https://other.example",
    ];
    let distinct = distinct_relays(relays.iter().map(|relay| relay.to_string()).collect());
    assert_eq!(
        distinct,
        [
            "https://relay.example",
            "https://relay.example:8443",
            "http://relay.example:80",
            "https://relay.example/path/",
            "https://other.example",
        ]
    );
}

#[test]
fn offer_serves_a_relay_at_its_public_url() {
    let base = [
        "offer",
        "--price",
        "1",
        "--min-btc-amount",
        "1",
        "--max-btc-amount",
        "2",
        "--btc-fee",
        "1",
        "--nex-fee",
        "1",
    ];
    let with = |extra: &[&str]| parse(&[&base[..], extra].concat());
    let serve = ["--serve-relay", "0.0.0.0:7500"];
    let url = ["--serve-relay-url", "https://seller.example"];
    let Command::Offer(args) = with(&[&serve[..], &url[..]].concat()).unwrap().command else {
        panic!("an offer");
    };
    assert_eq!(
        args.serve.serve_relay,
        Some("0.0.0.0:7500".parse().unwrap())
    );
    assert_eq!(
        args.serve.serve_relay_url.as_deref(),
        Some("https://seller.example")
    );
    assert!(args.listen.is_none() && args.relay.is_empty());
    let both = [&serve[..], &url[..], &["--relay", "http://r"]].concat();
    assert!(with(&both).is_ok());
    assert!(with(&serve).is_err(), "no URL");
    assert!(with(&url).is_err(), "no relay to name");
    let listening = [&serve[..], &url[..], &["--listen", "127.0.0.1:0"]].concat();
    assert!(with(&listening).is_err());
}

/// A relay on loopback, as `swap-relay` runs one: its URL.
fn other_relay() -> String {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let url = format!("http://{}", listener.local_addr().unwrap());
    listener.set_nonblocking(true).unwrap();
    std::thread::spawn(move || {
        let relay = Arc::new(swap_relay::Relay {
            board: swap_relay::board::Board::new(10),
            rejoins: swap_relay::board::Board::new(10),
        });
        tokio::runtime::Runtime::new().unwrap().block_on(async {
            let listener = tokio::net::TcpListener::from_std(listener).unwrap();
            swap_relay::serve(listener, relay).await.unwrap();
        });
    });
    url
}

fn listed(url: &str) -> Vec<Value> {
    ureq::get(&format!("{url}/offers"))
        .call()
        .unwrap()
        .into_json()
        .unwrap()
}

fn wait_listed(url: &str, count: usize) {
    for _ in 0..200 {
        if listed(url).len() == count {
            return;
        }
        std::thread::sleep(Duration::from_millis(25));
    }
    panic!("{count} offers never listed on {url}");
}

/// The relay the seller serves itself lists its offer naming the public
/// URL, beside another relay; a buyer that takes it there withdraws it from
/// the other, and the seller is not taken twice.
#[test]
fn a_seller_lists_on_the_relay_it_serves_and_another() {
    let served = serve_relay("0.0.0.0:0".parse().unwrap()).unwrap();
    assert!(served.starts_with("http://127.0.0.1:"), "{served}");
    let other = other_relay();
    let key = SigningKey::from_bytes(&[1; 32]);
    let public = "https://seller.example".to_string();
    let offer = offer_of(
        &small_args(16),
        Network::Bitcoin,
        Place::Relay(other.clone()),
        &key,
    );
    let copies = listed_on(&offer, &[other.clone(), public.clone()]);
    let encoded: Vec<String> = copies.iter().map(Offer::encode).collect();
    let buyer_key = SigningKey::from_bytes(&offer.buyer_session);
    let buyer = ivy::Config::new(buyer_key.clone()).peer_key();
    let (at, served_at) = (other.clone(), served.clone());
    let seller = std::thread::spawn(move || {
        let listings = [
            (&at[..], &encoded[0][..]),
            (&served_at[..], &encoded[1][..]),
        ];
        let config = ivy::Config::new(key);
        Ivy::accept_relayed_on(&listings, &config, buyer, TIMEOUT, TIMEOUT)
    });
    wait_listed(&served, 1);
    wait_listed(&other, 1);
    assert_eq!(listed(&served)[0]["relay"], public.as_str());

    let id = hex::encode(offer.template.swap_id);
    let config = ivy::Config::new(buyer_key);
    let seller_key = offer.seller_key().unwrap();
    let mut buyer = Ivy::connect_relayed(&served, &id, &config, seller_key, TIMEOUT).unwrap();
    let (taken, mut seller) = seller.join().unwrap().unwrap();
    assert_eq!(taken, 1, "through the relay it serves");
    wait_listed(&other, 0);
    let again = Ivy::connect_relayed(&other, &id, &config, seller_key, TIMEOUT).err();
    assert_eq!(again.map(|e| e.kind()), Some(io::ErrorKind::NotFound));
    buyer.send(b"request").unwrap();
    assert_eq!(seller.recv(TIMEOUT).unwrap().unwrap(), b"request");
}

#[test]
fn an_offer_names_an_address_or_a_relay() {
    let key = SigningKey::from_bytes(&[1; 32]);
    let mut offer = offer_of(&small_args(16), Network::Bitcoin, address(), &key);
    offer.relay = Some("http://relay.example".into());
    assert!(Offer::decode(&offer.encode()).is_err());
    offer.relay = None;
    offer.address = None;
    assert!(Offer::decode(&offer.encode()).is_err());
}

#[test]
fn offer_listens_or_uses_a_relay() {
    let relay = ["--relay", "http://127.0.0.1:1"];
    let args = offer_args(&[]);
    assert!(args.listen.is_some() && args.relay.is_empty());
    let base: Vec<&str> = [
        "offer",
        "--price",
        "50000000",
        "--min-btc-amount",
        "10000000",
        "--max-btc-amount",
        "50000000",
        "--btc-fee",
        "2000",
        "--nex-fee",
        "1",
    ]
    .to_vec();
    let with = |extra: &[&str]| parse(&[&base[..], extra].concat());
    let Command::Offer(args) = with(&relay).unwrap().command else {
        panic!("an offer");
    };
    assert_eq!(args.relay, ["http://127.0.0.1:1"]);
    let Command::Offer(args) = with(&[&relay[..], &["--relay", "http://127.0.0.1:2"]].concat())
        .unwrap()
        .command
    else {
        panic!("an offer");
    };
    assert_eq!(args.relay, ["http://127.0.0.1:1", "http://127.0.0.1:2"]);
    assert!(with(&[]).is_err(), "neither");
    assert!(with(&[&relay[..], &["--listen", "127.0.0.1:0"]].concat()).is_err());
    assert!(with(&[&relay[..], &["--advertise", "192.0.2.1:7000"]].concat()).is_err());
}

#[test]
fn only_a_nexus_address_is_paid() {
    let address = swap_nexus_tx::address(&[9; 32]);
    assert!(check_nex_address(&address).is_ok());
    assert!(check_nex_address(&address.to_ascii_uppercase()).is_err());
    let upper = format!("b{}", address[1..].to_ascii_uppercase());
    assert!(
        check_nex_address(&upper).is_err(),
        "its digits lowercase too"
    );
    assert!(check_nex_address(&address[..address.len() - 1]).is_err());
    assert!(check_nex_address("bc1qexample").is_err());
}

#[test]
fn an_alias_of_a_nexus_address_is_refused() {
    let address = swap_nexus_tx::address(&[9; 32]);
    // The last digit carries two bits the address leaves zero.
    let digits = "abcdefghijklmnopqrstuvwxyz234567";
    let last = digits.find(address.chars().last().unwrap()).unwrap();
    let alias = format!(
        "{}{}",
        &address[..address.len() - 1],
        &digits[last + 1..last + 2]
    );
    // A decoder that ignored those bits would read it as the same address.
    let mut lenient = data_encoding::BASE32_NOPAD.specification();
    lenient.check_trailing_bits = false;
    let lenient = lenient.encoding().unwrap();
    let decode = |a: &str| lenient.decode(a[1..].to_ascii_uppercase().as_bytes());
    assert_eq!(decode(&alias).unwrap(), decode(&address).unwrap());
    assert!(check_nex_address(&alias).is_err());
}

fn policy(extra: &[&str]) -> (PolicyArgs, Network) {
    let mut args = vec!["take", "offer", "--nex-address", "b", "--price", "50000000"];
    args.extend(extra);
    match parse(&args).unwrap().command {
        Command::Take(args) => (args.policy, args.nodes.btc_network),
        _ => panic!("a take"),
    }
}

/// The default terms, at the default bounds.
fn agreed() -> Offer {
    let mut args = offer_args(&[]);
    args.terms.btc_fee = 10_000;
    args.terms.nex_fee = 1_000;
    let key = SigningKey::from_bytes(&[1; 32]);
    offer_of(&args, Network::Bitcoin, address(), &key)
}

/// The fee floors the policy tests pass: the agreed fees.
const FLOOR: u64 = 10_000;
const NEX_FLOOR: u64 = 1_000;

#[test]
fn take_refuses_any_term_outside_its_policy() {
    let (policy, network) = policy(&[]);
    assert_eq!(
        check_offer(
            &agreed(),
            &policy.policy(&agreed()),
            network,
            MAINNET,
            FLOOR,
            NEX_FLOOR
        ),
        Ok(())
    );
    type Change = (&'static str, fn(&mut Offer));
    let changes: [Change; 16] = [
        ("network", |o| o.btc_network = Network::Testnet),
        ("nexus", |o| {
            o.template.nexus_genesis = swap_nexus_tx::cid(b"dev")
        }),
        ("higher price", |o| o.quote.price += 1),
        ("lower price", |o| o.quote.price -= 1),
        ("below the range", |o| o.quote.max_btc_amount -= 1),
        ("above the range", |o| {
            o.quote.min_btc_amount = 50_000_001;
            o.quote.max_btc_amount = 60_000_000;
        }),
        ("btc fee", |o| o.template.btc_fee += Amount::from_sat(1)),
        ("btc fee floor", |o| {
            o.template.btc_fee -= Amount::from_sat(1)
        }),
        ("nex fee", |o| o.template.nex_fee += 1),
        ("nex fee floor", |o| o.template.nex_fee -= 1),
        ("t1", |o| o.template.t1 += 1),
        ("t2", |o| o.template.t2 -= 1),
        ("btc confirmations", |o| o.template.btc_confirmations -= 1),
        ("max btc confirmations", |o| {
            o.template.btc_confirmations = 13
        }),
        ("nex confirmations", |o| o.template.nex_confirmations -= 1),
        ("margin", |o| o.template.margin = 5),
    ];
    for (what, change) in changes {
        let mut offer = agreed();
        change(&mut offer);
        assert_eq!(offer.check(), Ok(()), "{what}");
        let refused = check_offer(
            &offer,
            &policy.policy(&agreed()),
            network,
            MAINNET,
            FLOOR,
            NEX_FLOOR,
        )
        .unwrap_err();
        assert!(
            refused.starts_with("refused: the offer"),
            "{what}: {refused}"
        );
    }
    // The defaults leave t2 - btc_confirmations = 144 - 6.
    let (policy, network) = self::policy(&["--min-refund-window", "138"]);
    assert_eq!(
        check_offer(
            &agreed(),
            &policy.policy(&agreed()),
            network,
            MAINNET,
            FLOOR,
            NEX_FLOOR
        ),
        Ok(())
    );
    let mut offer = agreed();
    offer.template.btc_confirmations += 1;
    let refused = check_offer(
        &offer,
        &policy.policy(&agreed()),
        network,
        MAINNET,
        FLOOR,
        NEX_FLOOR,
    )
    .unwrap_err();
    assert!(refused.contains("blocks to refund in"), "{refused}");
}

#[test]
fn the_refund_window_defaults_to_half_a_day() {
    let (policy, _) = policy(&[]);
    assert_eq!(policy.max_btc_confirmations, 12);
    assert_eq!(policy.min_refund_window, 72);
    assert_eq!(policy.min_btc_fee_rate, None);
    assert_eq!(policy.min_margin, 6);
}

/// A quote is offered only if every amount in its range can be swapped:
/// the range is not empty and the terms work at both its ends.
#[test]
fn a_quote_works_across_its_whole_range() {
    let offer = agreed();
    assert_eq!(offer.check(), Ok(()));
    let mut empty = agreed();
    empty.quote.min_btc_amount = empty.quote.max_btc_amount + 1;
    let refused = empty.check().unwrap_err();
    assert!(refused.contains("range is empty"), "{refused}");
    // One amount is a range.
    let mut one = agreed();
    one.quote.min_btc_amount = one.quote.max_btc_amount;
    assert_eq!(one.check(), Ok(()));
    // At the least it takes, the NEX must exceed its fee: 1000 NEX at 50
    // sat a NEX is 50000 sat.
    let mut low = agreed();
    low.quote.min_btc_amount = 50_049;
    let refused = low.check().unwrap_err();
    assert!(refused.contains("at 50049 sat"), "{refused}");
    low.quote.min_btc_amount = 50_050;
    assert_eq!(low.check(), Ok(()));
    // At the most, the debit must fit a signed amount.
    let mut high = agreed();
    high.quote.price = 1_000_000;
    high.quote.max_btc_amount = i64::MAX as u64 - 1_000;
    assert_eq!(high.check(), Ok(()));
    high.quote.max_btc_amount += 1;
    let refused = high.check().unwrap_err();
    assert!(
        refused.contains(&format!("at {} sat", high.quote.max_btc_amount)),
        "{refused}"
    );
    // No NEX at a price of 0.
    let mut free = agreed();
    free.quote.price = 0;
    assert!(free.check().is_err());
}

/// The base units an amount buys are rounded down, as eigenwallet's
/// `Rate::quote` truncates: what is left, at most `ceil(price / 10^6) - 1`
/// sat, buys nothing.
#[test]
fn the_nex_is_rounded_down() {
    assert_eq!(swap::offer::BASE_UNITS_PER_NEX, 1_000_000);
    // 3 sat a NEX: a satoshi buys 333333 1/3 base units.
    let quote = Quote {
        price: 3,
        min_btc_amount: 0,
        max_btc_amount: u64::MAX,
    };
    assert_eq!(quote.nex_amount(0), 0);
    assert_eq!(quote.nex_amount(1), 333_333);
    assert_eq!(quote.nex_amount(2), 666_666);
    assert_eq!(quote.nex_amount(3), 1_000_000);
    assert_eq!(quote.nex_amount(10), 3_333_333);
    // Above a satoshi a base unit, the leftover reaches ceil(price / 10^6)
    // - 1 sat: at 2500001 sat a NEX, a base unit costs 2.500001 sat, and 2
    // sat buy none.
    let dear = Quote {
        price: 2_500_001,
        ..quote.clone()
    };
    assert_eq!(dear.nex_amount(2), 0);
    assert_eq!(dear.nex_amount(3), 1);
    assert_eq!(dear.nex_amount(5), 1);
    assert_eq!(dear.nex_amount(6), 2);
    // The product does not overflow: u64::MAX sat at 1 sat a base unit.
    let unit = Quote {
        price: 1_000_000,
        ..quote.clone()
    };
    assert_eq!(unit.nex_amount(u64::MAX), u64::MAX);
    // Beyond u64, at most u64::MAX, which no terms take.
    assert_eq!(quote.nex_amount(u64::MAX / 2), u64::MAX);
    assert_eq!(Quote { price: 0, ..quote }.nex_amount(100), 0);
    // The agreed offer, at 50000000 sat a NEX, 50 sat a base unit: 49 sat
    // left over.
    let terms = agreed().terms(10_000_049);
    assert_eq!(
        (terms.btc_amount.to_sat(), terms.nex_amount),
        (10_000_049, 200_000)
    );
}

/// `take` asks only for an amount in the offer's range, at its price.
#[test]
fn take_asks_only_for_an_amount_in_the_range() {
    let offer = agreed();
    let (policy, network) = policy(&[]);
    for (amount, taken) in [
        (10_000_000, true),
        (50_000_000, true),
        (9_999_999, false),
        (50_000_001, false),
    ] {
        let policy = Policy {
            btc_amount: amount,
            ..policy.policy(&offer)
        };
        let checked = check_offer(&offer, &policy, network, MAINNET, FLOOR, NEX_FLOOR);
        assert_eq!(checked.is_ok(), taken, "{amount}: {checked:?}");
        if !taken {
            let refused = checked.unwrap_err();
            assert!(
                refused.contains("takes 10000000 to 50000000 sat"),
                "{refused}"
            );
        }
    }
}

/// The seller fixes the terms at the amount asked for only while it is in
/// its quote's range and asked at its price.
#[test]
fn the_seller_answers_only_a_request_its_quote_holds() {
    use swap::offer::Declined;
    let offer = agreed();
    assert_eq!(
        offer.answer(10_000_000, 50_000_000),
        Answer::Terms(offer.terms(10_000_000))
    );
    assert_eq!(
        offer.answer(50_000_000, 50_000_000),
        Answer::Terms(offer.terms(50_000_000))
    );
    let refused = |btc, price| match offer.answer(btc, price) {
        Answer::Refused(why) => why,
        Answer::Terms(terms) => panic!("{btc} at {price}: {terms:?}"),
    };
    assert_eq!(
        refused(9_999_999, 50_000_000),
        Declined::AmountBelowMinimum { min: 10_000_000 }
    );
    assert_eq!(
        refused(50_000_001, 50_000_000),
        Declined::AmountAboveMaximum { max: 50_000_000 }
    );
    assert_eq!(
        refused(10_000_000, 49_999_999),
        Declined::PriceChanged { price: 50_000_000 }
    );
    assert_eq!(
        refused(10_000_000, 50_000_001),
        Declined::PriceChanged { price: 50_000_000 }
    );
}

/// The buyer starts only on terms exactly the ones it asked for: its
/// amount, and the NEX the signed price gives for it.
#[test]
fn the_buyer_takes_only_the_terms_it_asked_for() {
    let offer = agreed();
    let (policy, _) = policy(&["--btc-amount", "20000000"]);
    let policy = policy.policy(&offer);
    let asked = offer.terms(20_000_000);
    assert_eq!(asked.nex_amount, 400_000);
    assert_eq!(
        offer.check_answer(&policy, &Answer::Terms(asked.clone())),
        Ok(asked.clone())
    );
    type Change = (&'static str, fn(&mut Terms));
    let changes: [Change; 5] = [
        ("more btc", |t| t.btc_amount += Amount::from_sat(1)),
        ("less nex", |t| t.nex_amount -= 1),
        ("more nex", |t| t.nex_amount += 1),
        ("margin", |t| t.margin += 1),
        ("swap id", |t| t.swap_id[0] ^= 1),
    ];
    for (what, change) in changes {
        let mut terms = asked.clone();
        change(&mut terms);
        let refused = offer
            .check_answer(&policy, &Answer::Terms(terms))
            .unwrap_err();
        assert!(
            refused.contains("not the ones asked for"),
            "{what}: {refused}"
        );
    }
    // Terms at another price than the one signed, though the seller's own.
    let mut repriced = offer.clone();
    repriced.quote.price = 40_000_000;
    let terms = repriced.terms(20_000_000);
    assert!(offer.check_answer(&policy, &Answer::Terms(terms)).is_err());
    let other = Policy {
        price: 40_000_000,
        ..policy.clone()
    };
    assert!(offer.check_answer(&other, &Answer::Terms(asked)).is_err());
    let declined = Answer::Refused(swap::offer::Declined::PriceChanged { price: 60_000_000 });
    let refused = offer.check_answer(&policy, &declined).unwrap_err();
    assert_eq!(
        refused,
        "refused by the seller: the price is 60000000 sat a NEX"
    );
}

/// A session that hands out `inbox` and keeps what is sent.
#[derive(Default)]
struct Scripted {
    inbox: std::collections::VecDeque<Vec<u8>>,
    sent: Vec<Message>,
    swap_id: [u8; 32],
}

impl Transport for Scripted {
    fn send(&mut self, payload: &[u8]) -> io::Result<()> {
        self.sent
            .push(Message::decode(payload, self.swap_id).unwrap());
        Ok(())
    }

    fn recv(&mut self, _: Duration) -> io::Result<Option<Vec<u8>>> {
        Ok(self.inbox.pop_front())
    }
}

/// The request and the answer before either machine starts, as `offer`
/// and `take` exchange them.
#[test]
fn the_terms_are_fixed_before_the_machines_start() {
    let offer = agreed();
    let swap_id = offer.template.swap_id;
    let (policy, _) = policy(&["--btc-amount", "20000000"]);
    let policy = policy.policy(&offer);
    let session = |inbox: Vec<Message>| Scripted {
        inbox: inbox.iter().map(|m| m.encode(swap_id)).collect(),
        sent: vec![],
        swap_id,
    };
    let request = |btc_amount, price| Message::Request { btc_amount, price };

    // The seller answers a request in its quote with the terms at it.
    let mut seller = session(vec![request(20_000_000, 50_000_000)]);
    let terms = answer_request(&mut seller, &offer).unwrap();
    assert_eq!(terms, offer.terms(20_000_000));
    let answered = Message::Answer(Answer::Terms(terms.clone()));
    assert_eq!(seller.sent.len(), 1);
    assert_eq!(seller.sent[0].encode(swap_id), answered.encode(swap_id));
    // And refuses, saying why, one outside it.
    let mut seller = session(vec![request(50_000_001, 50_000_000)]);
    let refused = answer_request(&mut seller, &offer).unwrap_err().to_string();
    assert!(
        refused.contains("the most it takes is 50000000 sat"),
        "{refused}"
    );
    assert!(matches!(
        seller.sent[..],
        [Message::Answer(Answer::Refused(_))]
    ));
    let mut seller = session(vec![request(20_000_000, 49_999_999)]);
    assert!(answer_request(&mut seller, &offer).is_err());
    // A buyer that opens with anything else is refused.
    let mut seller = session(vec![]);
    assert!(answer_request(&mut seller, &offer).is_err());

    // The buyer asks for its amount at the signed price, and takes the
    // terms only if they are the ones it asked for.
    let mut buyer = session(vec![answered]);
    assert_eq!(request_terms(&mut buyer, &offer, &policy).unwrap(), terms);
    assert_eq!(
        buyer.sent[0].encode(swap_id),
        request(20_000_000, 50_000_000).encode(swap_id)
    );
    let mut other = terms.clone();
    other.nex_amount += 1;
    let mut buyer = session(vec![Message::Answer(Answer::Terms(other))]);
    assert!(request_terms(&mut buyer, &offer, &policy).is_err());
    let mut buyer = session(vec![]);
    let refused = request_terms(&mut buyer, &offer, &policy).unwrap_err();
    assert_eq!(refused.to_string(), "the seller sent no answer");
}

#[test]
fn take_refuses_terms_that_cannot_work() {
    let (policy, network) = policy(&["--max-t1", "1000"]);
    let mut offer = agreed();
    offer.template.t1 = 90;
    assert!(
        check_offer(&offer, &policy.policy(&agreed()), network, MAINNET, 0, 0).is_err(),
        "below the floor"
    );
}

/// `take` needs the price agreed to; the amount defaults to the most the
/// offer takes, as eigenwallet's CLI swaps up to its seller's maximum.
#[test]
fn take_requires_the_agreed_price() {
    let args = ["take", "offer", "--nex-address", "b", "--btc-amount", "1"];
    assert!(parse(&args).is_err());
    let (policy, _) = policy(&[]);
    assert_eq!(policy.btc_amount, None);
    assert_eq!(policy.policy(&agreed()).btc_amount, 50_000_000);
    let (policy, _) = self::policy(&["--btc-amount", "10000000"]);
    assert_eq!(policy.policy(&agreed()).btc_amount, 10_000_000);
}

#[test]
fn an_unspecified_listen_address_needs_an_advertised_one() {
    let any = "0.0.0.0:7400".parse().unwrap();
    let any6 = "[::]:7400".parse().unwrap();
    let public = Some("203.0.113.5:7400".parse().unwrap());
    assert!(check_listen(any, None).is_err());
    assert!(check_listen(any6, None).is_err());
    assert!(check_listen(any, public).is_ok());
    assert!(check_listen("127.0.0.1:0".parse().unwrap(), None).is_ok());
    assert!(check_listen(any, Some(any)).is_err());
    assert!(check_listen("127.0.0.1:0".parse().unwrap(), Some(any6)).is_err());
}

#[cfg(unix)]
#[test]
fn a_key_file_others_can_open_is_refused() {
    use std::os::unix::fs::PermissionsExt;
    let file = tempfile::NamedTempFile::new().unwrap();
    fs::write(file.path(), "07".repeat(32)).unwrap();
    let key = NexKeyArgs {
        nex_key_file: Some(file.path().to_path_buf()),
    };
    for mode in [0o640, 0o604, 0o620] {
        fs::set_permissions(file.path(), fs::Permissions::from_mode(mode)).unwrap();
        assert!(key.load().is_err(), "{mode:o}");
    }
    fs::set_permissions(file.path(), fs::Permissions::from_mode(0o600)).unwrap();
    assert_eq!(key.load().unwrap().0, [7; 32]);
}

#[test]
fn a_seller_resumes_only_with_its_own_key() {
    let key = || SecretBytes([7; 32]);
    let address = key().nex_address();
    let other = || Some(SecretBytes([8; 32]));
    for signs in [true, false] {
        let home = Some(&address[..]);
        assert!(seller_key(home, signs, other()).is_err(), "{signs}");
        let ours = seller_key(home, signs, Some(key())).unwrap();
        assert_eq!(ours.unwrap().0, [7; 32], "{signs}");
    }
    let home = Some(&address[..]);
    let refused = seller_key(home, true, None).map(|_| ()).unwrap_err();
    assert_eq!(refused.to_string(), NO_KEY);
    assert!(seller_key(home, false, None).unwrap().is_none());
    assert!(seller_key(None, false, other()).unwrap().is_some());
}

#[test]
fn only_a_swap_exits_zero() {
    let outcomes = [
        Outcome::Swapped,
        Outcome::Refunded,
        Outcome::Punished,
        Outcome::Drained,
        Outcome::Aborted(swap::Refusal::Timeout),
    ];
    let codes = outcomes.map(exit_code);
    assert_eq!(codes, [0, 3, 4, 5, 6]);
    let help = Cli::command().render_help().to_string();
    for (outcome, code) in outcomes.iter().zip(codes) {
        let name = format!("{outcome:?}");
        let name = name.split('(').next().unwrap();
        assert!(help.contains(&format!("{code} {name}")), "{name}");
    }
}

#[test]
fn a_failure_after_the_swap_file_exists_says_how_to_resume() {
    let file = tempfile::NamedTempFile::new().unwrap();
    let hinted = resume_hint(file.path(), "", "lost".into()).to_string();
    let hint = format!(
        "lost\nto carry on, run with the same flags, the node and key flags and \
         --max-fee-rate, --fallback-fee-rate, --max-fee-fraction, --max-tip-age and \
         --nexus-budget: \
         lattice-swap resume {}",
        file.path().display()
    );
    assert_eq!(hinted, hint);
    // A seller that serves its relay is told to serve it again.
    let serve = ServeRelayArgs {
        serve_relay: Some("0.0.0.0:7500".parse().unwrap()),
        serve_relay_url: Some("https://seller.example".into()),
    };
    let hinted = resume_hint(file.path(), &serve.flags(), "lost".into()).to_string();
    assert_eq!(
        hinted,
        format!("{hint} --serve-relay 0.0.0.0:7500 --serve-relay-url https://seller.example")
    );
    let missing = file.path().with_extension("gone");
    assert_eq!(resume_hint(&missing, "", "lost".into()).to_string(), "lost");
}

#[test]
fn the_wallet_name_is_escaped() {
    let args = offer_args(&[]);
    assert_eq!(
        args.nodes.wallet_url("my wallet/../x"),
        "http://127.0.0.1:8332/wallet/my%20wallet%2F..%2Fx"
    );
}

/// A stray connection, or a peer with the wrong key, does not end the
/// wait for the buyer.
#[test]
fn offer_waits_past_a_failed_handshake() {
    use std::net::TcpStream;
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    let seller = ivy::Config::new(SigningKey::from_bytes(&[1; 32]));
    let buyer = ivy::Config::new(SigningKey::from_bytes(&[2; 32]));
    let stranger = ivy::Config::new(SigningKey::from_bytes(&[3; 32]));
    let seller_key = seller.peer_key();
    let buyer_key = buyer.peer_key();
    let accepting = std::thread::spawn(move || {
        Ivy::accept(
            listener,
            &seller,
            buyer_key,
            Duration::from_secs(30),
            Duration::from_secs(5),
        )
        .map(|_| ())
    });
    drop(TcpStream::connect(address).unwrap());
    let _ = Ivy::connect(address, &stranger, seller_key, Duration::from_secs(5));
    let _buyer = Ivy::connect(address, &buyer, seller_key, Duration::from_secs(5)).unwrap();
    accepting.join().unwrap().unwrap();
}

/// Idle connections do not hold up the buyer: handshakes run side by side.
#[test]
fn offer_takes_the_buyer_past_idle_connections() {
    use std::net::TcpStream;
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    let seller = ivy::Config::new(SigningKey::from_bytes(&[1; 32]));
    let buyer = ivy::Config::new(SigningKey::from_bytes(&[2; 32]));
    let (seller_key, buyer_key) = (seller.peer_key(), buyer.peer_key());
    let start = std::time::Instant::now();
    let accepting = std::thread::spawn(move || {
        Ivy::accept(
            listener,
            &seller,
            buyer_key,
            Duration::from_secs(60),
            Duration::from_secs(20),
        )
        .map(|_| ())
    });
    let idle: Vec<_> = (0..8)
        .map(|_| TcpStream::connect(address).unwrap())
        .collect();
    let _buyer = Ivy::connect(address, &buyer, seller_key, Duration::from_secs(5)).unwrap();
    accepting.join().unwrap().unwrap();
    assert!(
        start.elapsed() < Duration::from_secs(10),
        "{:?}",
        start.elapsed()
    );
    drop(idle);
}

/// Waits on `listener` for the buyer `buyer` in a thread, each handshake
/// given `send_timeout`.
fn accepting(
    listener: TcpListener,
    seller: ivy::Config,
    buyer: PeerKey,
    send_timeout: Duration,
) -> std::thread::JoinHandle<io::Result<()>> {
    std::thread::spawn(move || {
        Ivy::accept(
            listener,
            &seller,
            buyer,
            Duration::from_secs(60),
            send_timeout,
        )
        .map(|_| ())
    })
}

/// Whether the seller closes `stream` within five seconds.
fn closed(stream: &mut std::net::TcpStream) -> bool {
    stream
        .set_read_timeout(Some(Duration::from_secs(5)))
        .unwrap();
    stream.read_to_end(&mut vec![]).is_ok()
}

/// Each handshake gets `send_timeout`.
#[test]
fn offer_bounds_each_handshake() {
    use std::net::TcpStream;
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    let seller = ivy::Config::new(SigningKey::from_bytes(&[1; 32]));
    let buyer = ivy::Config::new(SigningKey::from_bytes(&[2; 32]));
    let (seller_key, buyer_key) = (seller.peer_key(), buyer.peer_key());
    let accepting = accepting(listener, seller, buyer_key, Duration::from_secs(1));
    let mut idle = TcpStream::connect(address).unwrap();
    assert!(closed(&mut idle), "an idle handshake times out");
    let _buyer = Ivy::connect(address, &buyer, seller_key, Duration::from_secs(5)).unwrap();
    accepting.join().unwrap().unwrap();
}

/// Past the cap on handshakes from one source a connection evicts that
/// source's oldest, so the buyer gets in past any number of idle ones.
#[test]
fn offer_evicts_the_oldest_handshake() {
    use std::net::TcpStream;
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    let seller = ivy::Config::new(SigningKey::from_bytes(&[1; 32]));
    let buyer = ivy::Config::new(SigningKey::from_bytes(&[2; 32]));
    let (seller_key, buyer_key) = (seller.peer_key(), buyer.peer_key());
    let start = std::time::Instant::now();
    let accepting = accepting(listener, seller, buyer_key, Duration::from_secs(60));
    let mut oldest = TcpStream::connect(address).unwrap();
    std::thread::sleep(Duration::from_millis(200));
    let idle: Vec<_> = (0..2 * swap::transport::HANDSHAKES)
        .map(|_| TcpStream::connect(address).unwrap())
        .collect();
    assert!(closed(&mut oldest), "the oldest is evicted");
    let _buyer = Ivy::connect(address, &buyer, seller_key, Duration::from_secs(5)).unwrap();
    accepting.join().unwrap().unwrap();
    assert!(
        start.elapsed() < Duration::from_secs(20),
        "{:?}",
        start.elapsed()
    );
    drop(idle);
}

/// A handshake that ends leaves the rest in the order they came: the next
/// eviction takes the oldest still waiting.
#[test]
fn an_ended_handshake_keeps_the_oldest_first() {
    use std::net::TcpStream;
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    let seller = ivy::Config::new(SigningKey::from_bytes(&[1; 32]));
    let buyer = ivy::Config::new(SigningKey::from_bytes(&[2; 32]));
    let (seller_key, buyer_key) = (seller.peer_key(), buyer.peer_key());
    let accepting = accepting(listener, seller, buyer_key, Duration::from_secs(60));
    let connect = || {
        let stream = TcpStream::connect(address).unwrap();
        std::thread::sleep(Duration::from_millis(50));
        stream
    };
    let first = connect();
    let mut second = connect();
    let mut idle: Vec<_> = (2..swap::transport::PER_SOURCE)
        .map(|_| connect())
        .collect();
    // The first ends its own handshake, leaving one under the cap of one
    // source, which all of these are.
    drop(first);
    std::thread::sleep(Duration::from_millis(200));
    // The next fills the cap, and the one after evicts the second.
    idle.push(connect());
    idle.push(connect());
    assert!(closed(&mut second), "the oldest still waiting is evicted");
    let _buyer = Ivy::connect(address, &buyer, seller_key, Duration::from_secs(5)).unwrap();
    accepting.join().unwrap().unwrap();
}

/// A bitcoind that passes the node check and answers every other call
/// with `result`.
fn bitcoind(result: Value) -> String {
    node(json!({}), result)
}

/// A bitcoind on mainnet that passes the node check, whose wallet owns
/// every address, but where `replies` names a method and the reply to it,
/// and that answers every other call with `result`.
fn node(replies: Value, result: Value) -> String {
    node_down_for(0, replies, result)
}

/// [`node`], down for its first `down` calls: it answers them 503, with no
/// body, as bitcoind does when its work queue is full.
fn node_down_for(mut down: usize, replies: Value, result: Value) -> String {
    use std::io::BufRead;
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let url = format!("http://{}", listener.local_addr().unwrap());
    std::thread::spawn(move || {
        for stream in listener.incoming() {
            let mut stream = stream.unwrap();
            let mut reader = io::BufReader::new(stream.try_clone().unwrap());
            let mut length = 0;
            loop {
                let mut line = String::new();
                reader.read_line(&mut line).unwrap();
                let header = line.to_ascii_lowercase();
                if let Some(value) = header.strip_prefix("content-length:") {
                    length = value.trim().parse().unwrap();
                }
                if line == "\r\n" || line.is_empty() {
                    break;
                }
            }
            let mut body = vec![0; length];
            reader.read_exact(&mut body).unwrap();
            if down > 0 {
                down -= 1;
                let _ = write!(
                    stream,
                    "HTTP/1.1 503 Service Unavailable\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
                );
                continue;
            }
            let request: Value = serde_json::from_slice(&body).unwrap();
            let method = request["method"].as_str().unwrap();
            let answer = match method {
                "getindexinfo" => json!({"txindex": {"synced": true}}),
                "getnetworkinfo" => json!({"version": 300_200}),
                "getblockchaininfo" => json!({"chain": "main", "initialblockdownload": false}),
                "getwalletinfo" => json!({"private_keys_enabled": true}),
                "getaddressinfo" => json!({"ismine": true}),
                _ => result.clone(),
            };
            let reply = match &replies[method] {
                Value::Null => json!({"result": answer, "error": null}),
                reply => reply.clone(),
            }
            .to_string();
            let _ = write!(
                stream,
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\
                 Content-Length: {}\r\nConnection: close\r\n\r\n{reply}",
                reply.len()
            );
        }
    });
    url
}

/// A payout to an address, which [`node`]'s wallet owns.
fn paid() -> ScriptBuf {
    ScriptBuf::new_p2wpkh(&bitcoin::WPubkeyHash::from_byte_array([1; 20]))
}

/// 10 sat/vB.
fn estimate() -> Value {
    json!({"feerate": 0.0001, "blocks": 6})
}

/// What `lattice-swap` says when `args` stop it, run with the other
/// flags it needs: node files that exist, a bitcoind at `btc_url`, and a
/// lattice-node that keeps past state.
fn refusal(args: &[&str], btc_url: &str) -> String {
    refusal_on(args, btc_url, &nexus_node(10, true))
}

/// [`refusal`], with the lattice-node at `nexus_url`.
fn refusal_on(args: &[&str], btc_url: &str, nexus_url: &str) -> String {
    let cookie = tempfile::NamedTempFile::new().unwrap();
    fs::write(cookie.path(), "user:password").unwrap();
    let cookie = cookie.path().to_str().unwrap();
    let nodes = [
        "--btc-url",
        btc_url,
        "--btc-wallet",
        "w",
        "--btc-cookie",
        cookie,
        "--nexus-url",
        nexus_url,
        "--nexus-cookie",
        cookie,
    ];
    let cli = Cli::try_parse_from(["lattice-swap"].iter().chain(args).chain(&nodes)).unwrap();
    exit_status(cli.command).unwrap_err().to_string()
}

/// `take` on `offer`, paying `address`.
fn take_refusal(offer: &Offer, address: &str, extra: &[&str], btc_url: &str) -> String {
    take_refusal_on(offer, address, extra, btc_url, &nexus_node(10, true))
}

/// [`take_refusal`], with the lattice-node at `nexus_url`.
fn take_refusal_on(
    offer: &Offer,
    address: &str,
    extra: &[&str],
    btc_url: &str,
    nexus_url: &str,
) -> String {
    // Signed again, as the seller would, after the test changed it.
    let mut offer = offer.clone();
    offer.sign(&SigningKey::from_bytes(&[1; 32]));
    let file = tempfile::NamedTempFile::new().unwrap();
    fs::write(file.path(), offer.encode()).unwrap();
    let path = file.path().to_str().unwrap();
    let mut args = vec!["take", path, "--nex-address", address];
    args.extend(["--price", "50000000"]);
    args.extend(extra);
    refusal_on(&args, btc_url, nexus_url)
}

/// The agreed offer, whose seller key is one.
fn takeable() -> Offer {
    agreed()
}

/// Past every check, `take` asks its wallet for an address, which this
/// bitcoind answers with no address.
const PAST_THE_CHECKS: &str = "getnewaddress returned no address";

#[test]
fn take_holds_the_offer_to_its_policy() {
    let address = swap_nexus_tx::address(&[9; 32]);
    let url = bitcoind(estimate());
    assert_eq!(
        take_refusal(&takeable(), &address, &[], &url),
        PAST_THE_CHECKS
    );
    let mut offer = takeable();
    offer.btc_network = Network::Testnet;
    let refused = take_refusal(&offer, &address, &[], &url);
    assert!(refused.starts_with("refused: the offer is on"), "{refused}");
}

#[test]
fn take_pays_only_a_nexus_address() {
    // No bitcoind: the address is checked before any node is asked.
    let refused = take_refusal(&takeable(), "bc1qexample", &[], "http://127.0.0.1:1");
    assert_eq!(refused, "bc1qexample is not a Nexus address");
}

#[test]
fn take_refuses_a_fee_below_its_nodes_estimate() {
    let address = swap_nexus_tx::address(&[9; 32]);
    let floor = btc_fee_at(10_000);
    let mut offer = takeable();
    offer.template.btc_fee = Amount::from_sat(floor - 1);
    let refused = take_refusal(&offer, &address, &[], &bitcoind(estimate()));
    assert!(refused.contains("below the"), "{refused}");
    offer.template.btc_fee = Amount::from_sat(floor);
    let taken = take_refusal(&offer, &address, &[], &bitcoind(estimate()));
    assert_eq!(taken, PAST_THE_CHECKS);

    // With no estimate, as on regtest, the operator names the rate.
    let none = || bitcoind(json!({"errors": ["Insufficient data"], "blocks": 0}));
    let refused = take_refusal(&offer, &address, &[], &none());
    assert!(refused.contains("--min-btc-fee-rate"), "{refused}");
    let rate = ["--min-btc-fee-rate", "10"];
    assert_eq!(
        take_refusal(&offer, &address, &rate, &none()),
        PAST_THE_CHECKS
    );
    let rate = ["--min-btc-fee-rate", "11"];
    let refused = take_refusal(&offer, &address, &rate, &none());
    assert!(refused.contains("below the"), "{refused}");
}

/// At its floor cancel and refund each pay the rate, and at 1 sat/vB the
/// floor is what swap-bitcoin requires.
#[test]
fn the_fee_floor_pays_cancel_and_refund_their_rate() {
    let key = |n: u8| {
        let mut bytes = [0u8; 32];
        bytes[31] = n;
        KeyPair::new_xonly(Scalar::from_bytes(bytes).unwrap().non_zero().unwrap())
    };
    let (seller, buyer) = (key(5), key(6));
    let payout = ScriptBuf::new_p2wsh(&WScriptHash::all_zeros());
    let params = |fee: u64| Params {
        seller: seller.public_key(),
        buyer: buyer.public_key(),
        seller_share: key(7).public_key().normalize(),
        buyer_share: key(8).public_key().normalize(),
        amount: Amount::from_sat(50_000_000),
        fee: Amount::from_sat(fee),
        t1: 288,
        t2: 144,
        redeem_payout: payout.clone(),
        refund_payout: payout.clone(),
        punish_payout: payout.clone(),
    };
    for per_kvb in [1_000, 10_000, 12_345] {
        let swap = Swap::new(params(btc_fee_at(per_kvb))).unwrap();
        let lock = OutPoint::null();
        for spend in [Spend::Cancel, Spend::Refund] {
            let a = swap.sign(lock, spend, &seller);
            let b = swap.sign(lock, spend, &buyer);
            let vsize = swap.finalize(lock, spend, &a, Some(&b)).unwrap().vsize() as u64;
            assert!(
                swap.fee(spend).to_sat() * 1000 >= per_kvb * vsize,
                "{spend:?} at {per_kvb}"
            );
        }
    }
    // The floor's longer timelocks add at most a byte to it.
    let floor = btc_fee_at(1_000);
    let least = (1..=floor).find(|&fee| Swap::new(params(fee)).is_ok());
    assert!(
        least.is_some_and(|least| floor - least <= 1),
        "{least:?} {floor}"
    );
}

/// Terms swap-bitcoin would refuse in setup, for an amount that leaves
/// redeem's payout dust after its two fees, are refused before it.
#[test]
fn an_amount_that_cannot_pay_redeem_is_refused() {
    let fee = Amount::from_sat(1_000);
    let least = btc_amount_floor(fee);
    assert_eq!(least, 2 * 1_000 + 546);
    let mut terms = small(16);
    terms.btc_fee = fee;
    terms.btc_amount = Amount::from_sat(least);
    assert_eq!(Terms::check(&terms), Ok(()));
    terms.btc_amount -= Amount::from_sat(1);
    let refused = Terms::check(&terms).unwrap_err();
    assert!(refused.contains("redeem pays two btc_fee"), "{refused}");
    terms.btc_fee = Amount::MAX;
    assert!(Terms::check(&terms).is_err(), "no overflow");

    // `offer` refuses before it asks any node; `take` before it dials.
    // Either end of the range.
    let mut args = offer_args(&[]);
    args.terms.min_btc_amount = 2_545;
    let refused = offer(args).unwrap_err().to_string();
    assert!(refused.contains("at 2545 sat, btc_amount"), "{refused}");
    let (policy, network) = policy(&["--btc-amount", "20545"]);
    let mut offer = agreed();
    offer.quote.price = 1_000_000;
    offer.quote.min_btc_amount = 2 * 10_000 + 545;
    offer.quote.max_btc_amount = 2 * 10_000 + 545;
    let policy = Policy {
        price: 1_000_000,
        ..policy.policy(&offer)
    };
    let refused = check_offer(&offer, &policy, network, MAINNET, FLOOR, NEX_FLOOR).unwrap_err();
    assert!(refused.contains("redeem pays two btc_fee"), "{refused}");
}

/// The library's `take` checks the offer and the NEX address itself,
/// before it dials anyone: a caller that skips them is refused all the
/// same.
#[test]
fn take_checks_the_offer_itself() {
    let (policy, network) = policy(&[]);
    let directory = tempfile::tempdir().unwrap();
    let unreachable = "http://127.0.0.1:1";
    let take = |offer: Offer, nex_address: &str| {
        let policy = policy.policy(&agreed());
        swap::session::take(
            offer,
            &policy,
            network,
            MAINNET,
            FLOOR,
            NEX_FLOOR,
            ScriptBuf::new(),
            nex_address.into(),
            Bitcoind::new(unreachable, "u:p", network, TIMEOUT),
            Client::new(unreachable, "c", TIMEOUT),
            Store::new(directory.path(), [7; 32]),
        )
        .err()
        .unwrap()
        .to_string()
    };
    let nex = swap_nexus_tx::cid(b"buyer");
    let refused = take(agreed(), "bc1qexample");
    assert!(refused.contains("is not a Nexus address"), "{refused}");
    type Change = (&'static str, fn(&mut Offer));
    let changes: [Change; 5] = [
        ("network", |o| o.btc_network = Network::Testnet),
        ("nexus", |o| {
            o.template.nexus_genesis = swap_nexus_tx::cid(b"dev")
        }),
        ("btc fee", |o| o.template.btc_fee += Amount::from_sat(1)),
        ("nex fee floor", |o| o.template.nex_fee -= 1),
        ("t1", |o| o.template.t1 += 1),
    ];
    for (what, change) in changes {
        let mut offer = agreed();
        change(&mut offer);
        let refused = take(offer, &nex);
        assert!(
            refused.starts_with("refused: the offer"),
            "{what}: {refused}"
        );
    }
    assert!(!Store::new(directory.path(), [7; 32]).path().exists());
}

/// The bump settings default to the driver's, and a fraction the driver
/// would refuse is refused as an argument.
#[test]
fn the_bump_settings_default_to_the_drivers() {
    let (_directory, path) = swap_file(Seller::Done(Outcome::Swapped));
    let unreachable = "http://127.0.0.1:1";
    let bitcoin = || Bitcoind::new(unreachable, "u:p", Network::Regtest, TIMEOUT);
    let nexus = || Client::new(unreachable, "c", TIMEOUT);
    let store = || swap_store(Path::new(&path)).unwrap();
    let mut driver = Driver::<Seller, _, Ivy>::resume(bitcoin(), nexus(), None, store()).unwrap();
    let defaults = |d: &Driver<Seller, Bitcoind, Ivy>| {
        (
            d.max_fee_rate,
            d.fallback_fee_rate,
            d.max_fee_fraction,
            d.max_tip_age,
            d.nexus_budget,
        )
    };
    let before = defaults(&driver);
    offer_args(&[]).bump.apply(&mut driver);
    assert_eq!(defaults(&driver), before);

    let args = offer_args(&[
        "--max-fee-rate",
        "50",
        "--fallback-fee-rate",
        "5",
        "--max-fee-fraction",
        "0.25",
        "--max-tip-age",
        "30",
        "--nexus-budget",
        "25",
    ]);
    args.bump.apply(&mut driver);
    let rate = |sat| FeeRate::from_sat_per_vb(sat).unwrap();
    let age = Duration::from_secs(30 * 60);
    let budget = Duration::from_secs(25);
    assert_eq!(defaults(&driver), (rate(50), rate(5), 0.25, age, budget));
    for fraction in ["0", "1"] {
        assert!(parse(&["resume", "x.json", "--max-fee-fraction", fraction]).is_ok());
    }
    // A budget of none starves every Nexus request; one past an hour is no
    // bound, and a huge one overflows the clock.
    for budget in ["1", "3600"] {
        assert!(parse(&["resume", "x.json", "--nexus-budget", budget]).is_ok());
    }
    for budget in ["0", "3601", "18446744073709551615"] {
        let refused = parse(&["resume", "x.json", "--nexus-budget", budget])
            .err()
            .unwrap()
            .to_string();
        assert!(refused.contains("--nexus-budget"), "{budget}: {refused}");
    }
    for fraction in ["NaN", "-0.1", "1.01", "inf", "x"] {
        let flag = format!("--max-fee-fraction={fraction}");
        let refused = parse(&["resume", "x.json", &flag])
            .err()
            .unwrap()
            .to_string();
        assert!(
            refused.contains("--max-fee-fraction"),
            "{fraction}: {refused}"
        );
    }
    let refused = parse(&["take", "o", "--max-fee-fraction", "2"])
        .err()
        .unwrap()
        .to_string();
    assert!(refused.contains("2 is not between 0 and 1"), "{refused}");
    assert!(parse(&["resume", "x.json", "--max-fee-rate=-1"]).is_err());
    let too_high = (u64::MAX / 250 + 1).to_string();
    assert!(parse(&["resume", "x.json", "--fallback-fee-rate", &too_high]).is_err());

    // A run sets them on its driver, which checks the fraction first. One
    // driver at a time holds the swap.
    drop(driver);
    let mut bump = offer_args(&[]).bump;
    bump.max_fee_fraction = f64::NAN;
    let driver = Driver::<Seller, _, Ivy>::resume(bitcoin(), nexus(), None, store());
    let refused = run(Path::new(&path), "", driver, &bump, None)
        .unwrap_err()
        .to_string();
    assert!(refused.contains("max_fee_fraction NaN"), "{refused}");
}

#[test]
fn offer_refuses_an_address_nobody_can_dial() {
    let mut args = offer_args(&[]);
    args.listen = Some("0.0.0.0:7400".parse().unwrap());
    let refused = offer(args).unwrap_err().to_string();
    assert!(refused.contains("is no address to dial"), "{refused}");
}

/// A swap file in `state` as the driver saves one, in a directory of its
/// own.
fn swap_file<M: Machine>(state: M) -> (tempfile::TempDir, String) {
    let directory = tempfile::tempdir().unwrap();
    let store = Store::new(directory.path(), [7; 32]);
    let path = store.path().to_str().unwrap().to_string();
    let unreachable = "http://127.0.0.1:1";
    let bitcoin = Bitcoind::new(unreachable, "u:p", Network::Regtest, TIMEOUT);
    let nexus = Client::new(unreachable, "c", TIMEOUT);
    Driver::<_, _, Ivy>::start(state, vec![], bitcoin, nexus, None, store).unwrap();
    (directory, path)
}

#[test]
fn status_reads_a_swap_file_the_driver_saved() {
    let cli = |path: &str| status(Path::new(path)).map_err(|e| e.to_string());
    let seller = Seller::new(
        small(16),
        SecretBytes([7; 32]).nex_address(),
        ScriptBuf::new(),
        ScriptBuf::new(),
    )
    .unwrap();
    let (_seller, path) = swap_file(seller);
    assert_eq!(cli(&path), Ok(()));
    assert_eq!(
        Saved::load(&swap_store(Path::new(&path)).unwrap())
            .map(|saved| matches!(saved, Saved::Seller(_)))
            .ok(),
        Some(true)
    );
    let (buyer, _) = Buyer::start(small(16), ScriptBuf::new(), "b".into()).unwrap();
    let (_buyer, path) = swap_file(buyer);
    assert!(matches!(
        Saved::load(&swap_store(Path::new(&path)).unwrap()),
        Ok(Saved::Buyer(_))
    ));

    // A file of another version, or of none, is refused by name.
    let file: Value = serde_json::from_str(&read(Path::new(&path)).unwrap()).unwrap();
    for other in [
        json!({"version": 1, "state": file["state"]}),
        file["state"].clone(),
    ] {
        fs::write(&path, other.to_string()).unwrap();
        let refused = cli(&path).unwrap_err();
        assert!(refused.contains(&path), "{refused}");
        assert!(refused.contains("this build reads only 5"), "{refused}");
    }
    fs::remove_file(&path).unwrap();
    assert_eq!(cli(&path), Err(format!("{path}: no such swap file")));
}

#[cfg(unix)]
fn key_file(seed: u8) -> tempfile::NamedTempFile {
    use std::os::unix::fs::PermissionsExt;
    let file = tempfile::NamedTempFile::new().unwrap();
    fs::write(file.path(), hex::encode([seed; 32])).unwrap();
    fs::set_permissions(file.path(), fs::Permissions::from_mode(0o600)).unwrap();
    file
}

#[cfg(unix)]
#[test]
fn resume_signs_only_with_the_swaps_own_key() {
    let home = SecretBytes([7; 32]).nex_address();
    let seller = Seller::new(small(16), home, ScriptBuf::new(), ScriptBuf::new()).unwrap();
    assert!(seller.signs_nex());
    let (_directory, path) = swap_file(seller);
    let unreachable = "http://127.0.0.1:1";
    let wrong = key_file(8);
    let args = [
        "resume",
        &path,
        "--nex-key-file",
        wrong.path().to_str().unwrap(),
    ];
    let refused = refusal(&args, unreachable);
    assert!(refused.starts_with("the Nexus key is for"), "{refused}");
    assert_eq!(refusal(&["resume", &path], unreachable), NO_KEY);
}

/// A swap that no longer signs resumes without the key, and exits with
/// its outcome.
#[cfg(unix)]
#[test]
fn resume_exits_with_the_outcome_and_needs_no_key_once_signed() {
    let (_directory, path) = swap_file(Seller::Done(Outcome::Refunded));
    let cookie = tempfile::NamedTempFile::new().unwrap();
    let cookie = cookie.path().to_str().unwrap();
    let url = bitcoind(Value::Null);
    let mut args = vec!["lattice-swap", "resume", &path, "--btc-url", &url];
    args.extend(["--btc-wallet", "w", "--btc-cookie", cookie]);
    args.extend([
        "--nexus-url",
        "http://127.0.0.1:1",
        "--nexus-cookie",
        cookie,
    ]);
    let cli = Cli::try_parse_from(&args).unwrap();
    assert_eq!(exit_status(cli.command).unwrap(), 3);
    let key = key_file(8);
    args.extend(["--nex-key-file", key.path().to_str().unwrap()]);
    let cli = Cli::try_parse_from(&args).unwrap();
    assert_eq!(
        exit_status(cli.command).unwrap(),
        3,
        "a done swap names no address"
    );
}

/// `resume --serve-relay` serves the seller's relay again, where a buyer
/// that took the offer there meets it again; one the swap does not meet at
/// is refused before anything is served.
#[cfg(unix)]
#[test]
fn resume_serves_the_relay_the_swap_meets_at() {
    let (_directory, path) = swap_file(Seller::Done(Outcome::Refunded));
    let public = "https://seller.example";
    let mut offer = takeable();
    offer.address = None;
    offer.relay = Some(public.into());
    let session = SessionFile {
        offer,
        key: None,
        listen: None,
    };
    session
        .save(&swap_store(Path::new(&path)).unwrap())
        .unwrap();
    let listen = {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        listener.local_addr().unwrap().to_string()
    };
    let cookie = tempfile::NamedTempFile::new().unwrap();
    let cookie = cookie.path().to_str().unwrap();
    let url = bitcoind(Value::Null);
    let run = |served_at: &str| {
        let mut args = vec!["lattice-swap", "resume", &path, "--btc-url", &url];
        args.extend(["--btc-wallet", "w", "--btc-cookie", cookie]);
        args.extend(["--nexus-url", "http://127.0.0.1:1"]);
        args.extend(["--nexus-cookie", cookie, "--serve-relay", &listen]);
        args.extend(["--serve-relay-url", served_at]);
        exit_status(Cli::try_parse_from(&args).unwrap().command)
    };

    let refused = run("https://other.example").unwrap_err().to_string();
    assert!(
        refused.contains("meets the other party at https://seller.example"),
        "{refused}"
    );
    assert!(ureq::get(&format!("http://{listen}/offers"))
        .call()
        .is_err());

    assert_eq!(run(public).unwrap(), 3);
    let offers: Vec<Value> = ureq::get(&format!("http://{listen}/offers"))
        .call()
        .unwrap()
        .into_json()
        .unwrap();
    assert!(offers.is_empty());
}

/// lattice-node removes its cookie file when it stops: a swap resumed
/// meanwhile still runs, here to its outcome; a new one is refused at
/// once, naming the file.
#[cfg(unix)]
#[test]
fn a_missing_nexus_cookie_stops_only_a_new_swap() {
    let (_directory, path) = swap_file(Seller::Done(Outcome::Refunded));
    let btc_cookie = tempfile::NamedTempFile::new().unwrap();
    let btc_cookie = btc_cookie.path().to_str().unwrap();
    let stopped = tempfile::tempdir().unwrap();
    let absent = stopped.path().join(".cookie");
    let absent = absent.to_str().unwrap();
    let url = bitcoind(estimate());
    let nodes = [
        "--btc-url",
        &url,
        "--btc-wallet",
        "w",
        "--btc-cookie",
        btc_cookie,
        "--nexus-url",
        "http://127.0.0.1:1",
        "--nexus-cookie",
        absent,
    ];
    let run = |args: &[&str]| {
        let cli = Cli::try_parse_from(["lattice-swap"].iter().chain(args).chain(&nodes)).unwrap();
        exit_status(cli.command)
    };
    assert_eq!(run(&["resume", &path]).unwrap(), 3);

    let mut offer = takeable();
    offer.sign(&SigningKey::from_bytes(&[1; 32]));
    let file = tempfile::NamedTempFile::new().unwrap();
    fs::write(file.path(), offer.encode()).unwrap();
    let address = swap_nexus_tx::address(&[9; 32]);
    let take = [
        "take",
        file.path().to_str().unwrap(),
        "--nex-address",
        &address,
        "--price",
        "50000000",
    ];
    let refused = run(&take).unwrap_err().to_string();
    assert!(refused.contains(absent), "{refused}");
}

/// A node without a txindex, older than Bitcoin Core 28, on another
/// chain, or without a wallet that signs is refused by name (`Ok(Err)`);
/// one whose txindex is syncing, in initial block download, without the
/// wallet loaded, or locked fails the check (`Err`), which may pass when
/// asked again.
#[test]
fn a_node_a_swap_cannot_rely_on_is_refused() {
    let check_on = |network: Network, method: &str, result: Value| {
        let url = node(json!({ method: {"result": result} }), Value::Null);
        Bitcoind::new(&url, "u:p", network, TIMEOUT)
            .check_node()
            .map(|checked| checked.map_err(|e| e.to_string()))
            .map_err(|e| e.to_string())
    };
    let check = |method: &str, result: Value| check_on(Network::Bitcoin, method, result);
    let synced = json!({"txindex": {"synced": true, "best_block_height": 7}});
    assert_eq!(check("getindexinfo", synced), Ok(Ok(())));
    assert_eq!(
        check("getnetworkinfo", json!({"version": 280_000})),
        Ok(Ok(()))
    );
    let refused = check("getindexinfo", json!({})).unwrap().unwrap_err();
    assert!(refused.contains("-txindex"), "{refused}");
    let failed = check("getindexinfo", json!({"txindex": {"synced": false}})).unwrap_err();
    assert!(failed.contains("still syncing"), "{failed}");
    let refused = check("getnetworkinfo", json!({"version": 270_000}))
        .unwrap()
        .unwrap_err();
    assert!(refused.contains("Bitcoin Core 28 or later"), "{refused}");

    let on = |chain: &str| json!({"chain": chain, "initialblockdownload": false});
    for (network, chain) in [
        (Network::Bitcoin, "signet"),
        (Network::Testnet, "testnet4"),
        (Network::Testnet4, "test"),
        (Network::Signet, "regtest"),
    ] {
        let refused = check_on(network, "getblockchaininfo", on(chain))
            .unwrap()
            .unwrap_err();
        let expected = format!("on chain \"{chain}\", not {}", network.to_core_arg());
        assert!(refused.contains(&expected), "{refused}");
    }
    assert_eq!(
        check_on(Network::Signet, "getblockchaininfo", on("signet")),
        Ok(Ok(()))
    );
    let downloading = json!({"chain": "main", "initialblockdownload": true});
    let failed = check("getblockchaininfo", downloading).unwrap_err();
    assert!(failed.contains("initial block download"), "{failed}");

    let watching = json!({"private_keys_enabled": false});
    let refused = check("getwalletinfo", watching).unwrap().unwrap_err();
    assert!(refused.contains("the wallet cannot sign"), "{refused}");
    let locked = json!({"private_keys_enabled": true, "unlocked_until": 0});
    let failed = check("getwalletinfo", locked).unwrap_err();
    assert!(failed.contains("the wallet is locked"), "{failed}");
    let unlocked = json!({"private_keys_enabled": true, "unlocked_until": 1_900_000_000});
    assert_eq!(check("getwalletinfo", unlocked), Ok(Ok(())));
    let url = node(
        json!({"getwalletinfo": {"result": null, "error": {
            "code": -18,
            "message": "Requested wallet does not exist or is not loaded",
        }}}),
        Value::Null,
    );
    let refused = Bitcoind::new(&url, "u:p", Network::Bitcoin, TIMEOUT)
        .check_node()
        .unwrap_err()
        .to_string();
    assert!(
        refused.contains("no such wallet loaded") && refused.contains("not loaded"),
        "{refused}"
    );
}

/// `offer`, `take` and `resume` each check the node before anything else
/// asks it.
#[cfg(unix)]
#[test]
fn every_run_checks_its_node() {
    let unindexed = || node(json!({"getindexinfo": {"result": {}}}), Value::Null);
    let address = swap_nexus_tx::address(&[9; 32]);
    let refused = take_refusal(&takeable(), &address, &[], &unindexed());
    assert!(refused.contains("-txindex"), "{refused}");

    let key = key_file(7);
    let mut args = offer_args(&["--nex-key-file", key.path().to_str().unwrap()]);
    args.nodes.btc_url = Some(unindexed());
    let cookie = tempfile::NamedTempFile::new().unwrap();
    args.nodes.btc_cookie = Some(cookie.path().to_path_buf());
    let refused = offer(args).unwrap_err().to_string();
    assert!(refused.contains("-txindex"), "{refused}");

    let (_directory, path) = swap_file(Seller::Done(Outcome::Swapped));
    let refused = refusal(&["resume", &path], &unindexed());
    assert!(refused.contains("-txindex"), "{refused}");
    let (buyer, _) = Buyer::start(small(16), ScriptBuf::new(), "b".into()).unwrap();
    let (_directory, path) = swap_file(buyer);
    let refused = refusal(&["resume", &path], &unindexed());
    assert!(refused.contains("-txindex"), "{refused}");
    // A mainnet buyer resuming against a signet node.
    let signet = json!({"chain": "signet", "initialblockdownload": false});
    let signet = node(
        json!({"getblockchaininfo": {"result": signet}}),
        Value::Null,
    );
    let refused = refusal(&["resume", &path], &signet);
    assert!(refused.contains("not main"), "{refused}");
}

/// `take` again on an offer it took refuses before it asks a node or
/// dials, and says how to carry on.
#[test]
fn take_again_points_at_resume() {
    let offer = takeable();
    let directory = tempfile::tempdir().unwrap();
    let store = Store::new(directory.path(), offer.template.swap_id);
    fs::write(store.path(), "{}").unwrap();
    let address = swap_nexus_tx::address(&[9; 32]);
    let dir = ["--dir", directory.path().to_str().unwrap()];
    let refused = take_refusal(&offer, &address, &dir, "http://127.0.0.1:1");
    assert!(
        refused.starts_with("this offer was taken already"),
        "{refused}"
    );
    let resume = format!("lattice-swap resume {}", store.path().display());
    assert!(refused.ends_with(&resume), "{refused}");
}

/// A claim from either side reads back as that side's.
#[test]
fn a_claiming_swap_file_loads_as_its_side() {
    let payout = || ScriptBuf::new_p2wsh(&WScriptHash::all_zeros());
    let home = SecretBytes([7; 32]).nex_address();
    let seller = Seller::new(small(16), home, payout(), payout()).unwrap();
    let (buyer, hello) = Buyer::start(small(16), payout(), "b".into()).unwrap();
    let message = |actions: Vec<swap::Action>| match actions.into_iter().next() {
        Some(swap::Action::Send(message)) => swap::Event::Message(message),
        _ => panic!("a message to send"),
    };
    let (seller, hello) = seller.step(message(hello));
    let (buyer, _) = buyer.step(message(hello));
    for (setup, side) in [
        (
            serde_json::to_value(&seller).unwrap()["AwaitLockProposal"].take(),
            "Seller",
        ),
        (
            serde_json::to_value(&buyer).unwrap()["AwaitFunded"].take(),
            "Buyer",
        ),
    ] {
        assert_eq!(setup["side"], side);
        let claim = json!({"ClaimingNex": {
            "setup": setup,
            "other": "07".repeat(32),
            "lock": "Seen",
            "claim": null,
        }});
        let directory = tempfile::tempdir().unwrap();
        let store = Store::new(directory.path(), [7; 32]);
        let file = json!({"version": swap::driver::STATE_VERSION, "state": claim});
        fs::write(store.path(), file.to_string()).unwrap();
        let loaded = match Saved::load(&store).unwrap() {
            Saved::Seller(seller) => ("Seller", state_name(&seller)),
            Saved::Buyer(buyer) => ("Buyer", state_name(&buyer)),
        };
        assert_eq!(loaded, (side, "ClaimingNex".to_string()));
    }
}

/// `offer` holds its own `btc_fee` to its node's fee floor, as `take`
/// does: cancel, which the seller needs to reclaim its NEX, pays it as
/// signed.
#[cfg(unix)]
#[test]
fn offer_refuses_a_fee_below_its_nodes_estimate() {
    let key = key_file(7);
    let cookie = tempfile::NamedTempFile::new().unwrap();
    let offered = |fee: u64, rate: Option<u64>, result: Value| {
        let mut args = offer_args(&["--nex-key-file", key.path().to_str().unwrap()]);
        args.terms.btc_fee = fee;
        args.min_btc_fee_rate = rate;
        args.nodes.btc_url = Some(bitcoind(result));
        args.nodes.btc_cookie = Some(cookie.path().to_path_buf());
        args.nodes.nexus_cookie = Some(cookie.path().to_path_buf());
        args.nodes.nexus_url = nexus_node(10, true);
        offer(args).unwrap_err().to_string()
    };
    let floor = btc_fee_at(10_000);
    let refused = offered(floor - 1, None, estimate());
    assert!(refused.contains("below the"), "{refused}");
    assert_eq!(offered(floor, None, estimate()), PAST_THE_CHECKS);
    let none = || json!({"errors": ["Insufficient data"], "blocks": 0});
    let refused = offered(floor, None, none());
    assert!(refused.contains("--min-btc-fee-rate"), "{refused}");
    assert_eq!(offered(floor, Some(10), none()), PAST_THE_CHECKS);
    let refused = offered(floor, Some(11), none());
    assert!(refused.contains("below the"), "{refused}");
}

/// A lattice-node on mainnet's Nexus at `height` whose operator reads
/// answer, but whose read of an account after the block halfway up answers
/// only if it `keeps_state`.
fn nexus_node(height: u64, keeps_state: bool) -> String {
    nexus_node_on(MAINNET, height, keeps_state)
}

/// [`nexus_node`], on the Nexus of `genesis`.
fn nexus_node_on(genesis: &str, height: u64, keeps_state: bool) -> String {
    nexus_node_with(genesis, height, keeps_state, 1)
}

/// [`nexus_node`], pooling fees from `min_relay_fee`.
fn nexus_node_relaying(min_relay_fee: u64) -> String {
    nexus_node_with(MAINNET, 10, true, min_relay_fee)
}

fn nexus_node_with(genesis: &str, height: u64, keeps_state: bool, min_relay_fee: u64) -> String {
    nexus_node_submitting(genesis, height, keeps_state, min_relay_fee, true)
}

/// [`nexus_node_with`], its `/api/chain/info` saying `acceptsSubmit` as
/// `accepts_submit`.
fn nexus_node_submitting(
    genesis: &str,
    height: u64,
    keeps_state: bool,
    min_relay_fee: u64,
    accepts_submit: bool,
) -> String {
    use std::io::BufRead;
    let genesis = genesis.to_string();
    let min_relay_fee = min_relay_fee.to_string();
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let url = format!("http://{}", listener.local_addr().unwrap());
    std::thread::spawn(move || {
        for stream in listener.incoming() {
            let mut stream = stream.unwrap();
            let mut reader = io::BufReader::new(stream.try_clone().unwrap());
            let mut request = String::new();
            reader.read_line(&mut request).unwrap();
            loop {
                let mut line = String::new();
                reader.read_line(&mut line).unwrap();
                if line == "\r\n" || line.is_empty() {
                    break;
                }
            }
            let path = request.split(' ').nth(1).unwrap_or_default();
            let half = format!("/api/block/{}", height.div_ceil(2));
            let block = swap_nexus_tx::cid(b"half");
            let answer = if path == "/api/chain/info" {
                Some(json!({
                    "chain": ["Nexus"],
                    "genesisHash": genesis,
                    "minRelayFee": min_relay_fee,
                    "acceptsSubmit": accepts_submit,
                    "height": height.to_string(),
                }))
            } else if path == "/health" {
                let height = height.to_string();
                Some(json!({"phase": "active", "height": height, "bestHeaderHeight": height}))
            } else if path == half {
                Some(json!({"hash": block}))
            } else if path.starts_with("/accounts/") && path.ends_with(&format!("?block={block}")) {
                keeps_state.then(|| json!({"balance": "0", "nonce": "0"}))
            } else {
                None
            };
            let (status, body) = match answer {
                Some(answer) => ("200 OK", answer.to_string()),
                None => ("404 Not Found", String::new()),
            };
            let _ = write!(
                stream,
                "HTTP/1.1 {status}\r\nContent-Type: application/json\r\n\
                 Content-Length: {}\r\nConnection: close\r\n\r\n{body}",
                body.len()
            );
        }
    });
    url
}

/// A lattice-node that keeps no state of past blocks cannot say how deep
/// a transaction is, so every swap on it would cancel: it is refused.
#[test]
fn a_nexus_node_that_keeps_no_past_state_is_refused() {
    let cookie = tempfile::NamedTempFile::new().unwrap();
    let check = |height, keeps_state| {
        let mut nodes = offer_args(&[]).nodes;
        nodes.nexus_url = nexus_node(height, keeps_state);
        nodes.nexus_cookie = Some(cookie.path().to_path_buf());
        let client = nodes.nexus();
        nodes.check_nexus(&client).map_err(|e| e.to_string())
    };
    assert_eq!(check(10, true), Ok(()));
    let refused = check(10, false).unwrap_err();
    assert!(
        refused.contains("--state all and --block-bodies all"),
        "{refused}"
    );
    assert_eq!(check(1, false), Ok(()), "too short to tell");
}

/// `offer` and `take` each check the lattice-node before they take an
/// address from the wallet; `resume` checks it only to read Nexus (see
/// [`a_resumed_swap_reads_nexus_only_once_its_node_passes`]).
#[cfg(unix)]
#[test]
fn offer_and_take_check_the_nexus_node() {
    let refused = |refusal: String| {
        assert!(refusal.contains("--state all"), "{refusal}");
    };
    let forgetful = || nexus_node(10, false);
    let url = bitcoind(estimate());
    let key = key_file(7);
    let key = key.path().to_str().unwrap();
    let fee = btc_fee_at(10_000).to_string();
    refused(refusal_on(
        &[
            "offer",
            "--price",
            "50000000",
            "--min-btc-amount",
            "10000000",
            "--max-btc-amount",
            "50000000",
            "--btc-fee",
            &fee,
            "--nex-fee",
            "10",
            "--listen",
            "127.0.0.1:0",
            "--nex-key-file",
            key,
        ],
        &url,
        &forgetful(),
    ));
    let address = swap_nexus_tx::address(&[9; 32]);
    refused(take_refusal_on(
        &takeable(),
        &address,
        &[],
        &url,
        &forgetful(),
    ));
}

/// The Nexus genesis defaults to mainnet's, as anchored in Bitcoin, for
/// `offer`, `take` and `resume` alike.
#[test]
fn the_nexus_genesis_defaults_to_mainnets() {
    assert_eq!(
        MAINNET,
        "bafyreiggtg4ezifboyekbf4gxst2jr3mpjqcxsbmopy7w6fp46g4ngpgxa"
    );
    let take = ["take", "o", "--nex-address", "b", "--price", "1"];
    for args in [
        &[
            "offer",
            "--price",
            "1",
            "--min-btc-amount",
            "1",
            "--max-btc-amount",
            "1",
            "--btc-fee",
            "1",
            "--nex-fee",
            "1",
            "--listen",
            "127.0.0.1:0",
        ][..],
        &take,
        &["resume", "f.json"],
    ] {
        let nodes = match parse(args).unwrap().command {
            Command::Offer(args) => args.nodes,
            Command::Take(args) => args.nodes,
            Command::Resume(args) => args.nodes,
            Command::Wallet(_) | Command::Status { .. } | Command::RelayDir(_) => unreachable!(),
        };
        assert_eq!(nodes.nexus_genesis, MAINNET, "{args:?}");
    }
}

/// `offer` and `take` refuse a lattice-node on another Nexus than
/// `--nexus-genesis` names, before they ask it anything else, and run on
/// the one it names; `resume`, a flag naming another Nexus than the swap's.
#[cfg(unix)]
#[test]
fn offer_take_and_resume_refuse_another_nexus() {
    let dev = swap_nexus_tx::cid(b"dev");
    let refused = |refusal: String, genesis: &str, expected: &str| {
        assert!(
            refusal.contains(&format!("genesis {genesis}, not {expected}")),
            "{refusal}"
        );
    };
    // It also keeps no past state: refused for its genesis first.
    let elsewhere = || nexus_node_on(&dev, 10, false);
    let url = bitcoind(estimate());
    let key = key_file(7);
    let key = key.path().to_str().unwrap();
    let fee = btc_fee_at(10_000).to_string();
    let offer = |extra: &[&str], nexus_url: &str| {
        let mut args = vec![
            "offer",
            "--price",
            "50000000",
            "--min-btc-amount",
            "10000000",
            "--max-btc-amount",
            "50000000",
            "--btc-fee",
            &fee,
            "--nex-fee",
            "10",
            "--listen",
            "127.0.0.1:0",
            "--nex-key-file",
            key,
        ];
        args.extend(extra);
        refusal_on(&args, &url, nexus_url)
    };
    refused(offer(&[], &elsewhere()), &dev, MAINNET);
    refused(
        offer(
            &["--nexus-genesis", MAINNET],
            &nexus_node_on(&dev, 10, true),
        ),
        &dev,
        MAINNET,
    );
    let on_dev = ["--nexus-genesis", dev.as_str()];
    refused(offer(&on_dev, &nexus_node(10, true)), MAINNET, &dev);
    assert_eq!(
        offer(&on_dev, &nexus_node_on(&dev, 10, true)),
        PAST_THE_CHECKS
    );

    let address = swap_nexus_tx::address(&[9; 32]);
    let take = |offer: &Offer, extra: &[&str], nexus_url: &str| {
        take_refusal_on(offer, &address, extra, &url, nexus_url)
    };
    refused(take(&takeable(), &[], &elsewhere()), &dev, MAINNET);
    let mut dev_offer = takeable();
    dev_offer.template.nexus_genesis = dev.clone();
    refused(
        take(&dev_offer, &on_dev, &nexus_node(10, true)),
        MAINNET,
        &dev,
    );
    assert_eq!(
        take(&dev_offer, &on_dev, &nexus_node_on(&dev, 10, true)),
        PAST_THE_CHECKS
    );

    // A swap file keeps its Nexus: `resume` refuses a flag naming another
    // before it asks any node.
    let home = SecretBytes([7; 32]).nex_address();
    let on = |genesis: &str| Terms {
        nexus_genesis: genesis.into(),
        ..small(16)
    };
    let mut files = vec![];
    for genesis in [MAINNET, dev.as_str()] {
        let seller = Seller::new(on(genesis), home.clone(), paid(), paid());
        files.push((genesis, swap_file(seller.unwrap())));
        let (buyer, _) = Buyer::start(on(genesis), paid(), "b".into()).unwrap();
        files.push((genesis, swap_file(buyer)));
    }
    for (genesis, (_directory, path)) in &files {
        let resume = |extra: &[&str], nexus_url: &str| {
            let mut args = vec!["resume", path.as_str(), "--nex-key-file", key];
            args.extend(extra);
            refusal_on(&args, &url, nexus_url)
        };
        let other = match *genesis == MAINNET {
            true => dev.as_str(),
            false => MAINNET,
        };
        let kept = resume(&["--nexus-genesis", other], &nexus_node_on(other, 10, true));
        assert!(
            kept.contains(&format!(
                "trades on the Nexus of genesis {genesis}, not {other}"
            )),
            "{kept}"
        );
    }
}

/// Each party holds `nex_fee` to `--min-nex-fee`, 1 by default, and to its
/// Nexus node's minRelayFee if higher: a node that pools a fee of 0 does
/// not make the network relay it.
#[cfg(unix)]
#[test]
fn offer_and_take_refuse_a_nex_fee_below_the_floor() {
    let key = key_file(7);
    let cookie = tempfile::NamedTempFile::new().unwrap();
    let offered = |nex_fee: u64, least: Option<u64>, relay: u64| {
        let mut args = offer_args(&["--nex-key-file", key.path().to_str().unwrap()]);
        args.terms.btc_fee = btc_fee_at(10_000);
        args.terms.nex_fee = nex_fee;
        if let Some(least) = least {
            args.min_nex_fee = least;
        }
        args.nodes.btc_url = Some(bitcoind(estimate()));
        args.nodes.btc_cookie = Some(cookie.path().to_path_buf());
        args.nodes.nexus_cookie = Some(cookie.path().to_path_buf());
        args.nodes.nexus_url = nexus_node_relaying(relay);
        offer(args).unwrap_err().to_string()
    };
    assert_eq!(offer_args(&[]).min_nex_fee, 1);
    let refused = offered(0, None, 0);
    assert!(refused.contains("nex_fee is 0, below 1"), "{refused}");
    assert_eq!(offered(1, None, 0), PAST_THE_CHECKS);
    assert_eq!(offered(0, Some(0), 0), PAST_THE_CHECKS);
    let refused = offered(4, None, 5);
    assert!(refused.contains("nex_fee is 4, below 5"), "{refused}");
    assert_eq!(offered(5, None, 5), PAST_THE_CHECKS);
    let refused = offered(5, Some(6), 5);
    assert!(refused.contains("nex_fee is 5, below 6"), "{refused}");

    let address = swap_nexus_tx::address(&[9; 32]);
    let url = bitcoind(estimate());
    let taken_with = |nex_fee: u64, extra: &[&str], node: &str| {
        let mut offer = takeable();
        offer.template.nex_fee = nex_fee;
        take_refusal_on(&offer, &address, extra, &url, node)
    };
    let taken = |nex_fee: u64, extra: &[&str], relay: u64| {
        taken_with(nex_fee, extra, &nexus_node_relaying(relay))
    };
    assert_eq!(policy(&[]).0.min_nex_fee, 1);
    let refused = taken(0, &[], 0);
    assert!(refused.contains("below 1, --min-nex-fee"), "{refused}");
    assert_eq!(taken(1, &[], 0), PAST_THE_CHECKS);
    assert_eq!(taken(0, &["--min-nex-fee", "0"], 0), PAST_THE_CHECKS);
    let refused = taken(4, &[], 5);
    assert!(refused.contains("below 5, --min-nex-fee"), "{refused}");
    assert_eq!(taken(5, &[], 5), PAST_THE_CHECKS);
    let refused = taken(5, &["--min-nex-fee", "6"], 5);
    assert!(refused.contains("below 6, --min-nex-fee"), "{refused}");

    // A node on another Nexus is refused as that, before the floor it
    // reports is held against the offer.
    let elsewhere = nexus_node_with(&swap_nexus_tx::cid(b"dev"), 10, true, 5);
    let refused = taken_with(1, &[], &elsewhere);
    assert!(
        refused.contains("follows the chain of genesis"),
        "{refused}"
    );
}

/// What a swap meets its counterparty again by is saved beside its swap
/// file, readable by its owner alone, once, and read back as saved; a swap
/// saved without one has none.
#[test]
fn a_session_file_is_saved_beside_the_swap_file() {
    let directory = tempfile::tempdir().unwrap();
    let store = Store::new(directory.path(), [7; 32]);
    assert!(SessionFile::load(&store).unwrap().is_none());
    let key = SigningKey::from_bytes(&random32());
    let offer = offer_of(&small_args(40), Network::Regtest, address(), &key);
    let saved = SessionFile {
        offer: offer.clone(),
        key: Some(hex::encode(key.to_bytes())),
        listen: Some("127.0.0.1:7000".parse().unwrap()),
    };
    saved.save(&store).unwrap();
    assert!(saved.save(&store).is_err(), "never replaced");
    let path = directory
        .path()
        .join(format!("{}.session", "07".repeat(32)));
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = fs::metadata(&path).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o600);
    }
    let loaded = SessionFile::load(&store).unwrap().unwrap();
    assert_eq!(loaded.offer, offer);
    assert_eq!(loaded.key, saved.key);
    assert_eq!(loaded.listen, saved.listen);
}

/// Polls `reconnect` until it opens a session, failing after a while.
fn rejoined(reconnect: &mut Reconnect<Session>, rejoin: &swap::Rejoin) -> Session {
    for _ in 0..1_000 {
        if let Some(Ok(session)) = reconnect(rejoin) {
            return session;
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    panic!("never rejoined");
}

/// Over TCP, a seller resumed from its session file listens again where
/// it did, and the buyer, dialing as `take` saved it, comes back under its
/// rejoin key. A stranger holding the offer, its `buyer_session` key among
/// it, is refused, and the seller waits on for the buyer.
#[test]
fn a_resumed_seller_takes_the_buyer_back_over_tcp_and_no_one_else() {
    let directory = tempfile::tempdir().unwrap();
    let store = Store::new(directory.path(), [7; 32]);
    let listen = TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap();
    let key = SigningKey::from_bytes(&random32());
    let offer = offer_of(
        &small_args(40),
        Network::Regtest,
        Place::Address(listen),
        &key,
    );
    SessionFile {
        offer: offer.clone(),
        key: Some(hex::encode(key.to_bytes())),
        listen: Some(listen),
    }
    .save(&store)
    .unwrap();
    let mut seller = SessionFile::load(&store)
        .unwrap()
        .unwrap()
        .reconnect(None)
        .unwrap();
    let rejoin = swap::Rejoin {
        id: [1; 32],
        key: [2; 32],
    };
    assert!(seller(&rejoin).is_none(), "listening");

    let stranger = ivy::Config::new(SigningKey::from_bytes(&offer.buyer_session));
    let seller_key = offer.seller_key().unwrap();
    assert!(Ivy::connect(listen, &stranger, seller_key, TIMEOUT).is_err());
    assert!(seller(&rejoin).is_none(), "still waiting");

    let mut buyer = SessionFile {
        offer,
        key: None,
        listen: None,
    }
    .reconnect(None)
    .unwrap();
    let mut buyer = rejoined(&mut buyer, &rejoin);
    let mut seller = rejoined(&mut seller, &rejoin);
    buyer.send(b"again").unwrap();
    assert_eq!(
        seller.recv(TIMEOUT).unwrap().as_deref(),
        Some(&b"again"[..])
    );
}

/// A seller resumed with `--serve-relay` meets the buyer again on the
/// relay it serves, dialling it on its own machine, though its session file
/// names the public URL, which need not reach it from there; the buyer
/// comes to that relay from outside, here on loopback in its place.
#[test]
fn a_resumed_seller_rejoins_through_the_relay_it_serves() {
    let served = serve_relay("127.0.0.1:0".parse().unwrap()).unwrap();
    let key = SigningKey::from_bytes(&random32());
    // Nothing answers here.
    let public = "http://127.0.0.1:1".to_string();
    let offer = offer_of(
        &small_args(40),
        Network::Regtest,
        Place::Relay(public.clone()),
        &key,
    );
    let session = SessionFile {
        offer: offer.clone(),
        key: Some(hex::encode(key.to_bytes())),
        listen: None,
    };
    let session = session.through(Some(served.clone()));
    assert_eq!(session.offer.relay.as_deref(), Some(&served[..]));
    let mut seller = session.reconnect(None).unwrap();
    let mut buyer = SessionFile {
        offer: Offer {
            relay: Some(served),
            ..offer
        },
        key: None,
        listen: None,
    }
    .reconnect(None)
    .unwrap();
    let rejoin = swap::Rejoin {
        id: [3; 32],
        key: [4; 32],
    };
    let mut seller_session = None;
    let mut buyer_session = None;
    for _ in 0..1_000 {
        if seller_session.is_none() {
            seller_session = seller(&rejoin).and_then(|opened| opened.ok());
        }
        if buyer_session.is_none() {
            buyer_session = buyer(&rejoin).and_then(|opened| opened.ok());
        }
        if seller_session.is_some() && buyer_session.is_some() {
            break;
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    let (mut seller, mut buyer) = (seller_session.unwrap(), buyer_session.unwrap());
    buyer.send(b"again").unwrap();
    assert_eq!(
        seller.recv(TIMEOUT).unwrap().as_deref(),
        Some(&b"again"[..])
    );
    // Not given a relay, the session goes where its offer says.
    let unchanged = SessionFile {
        offer: offer_of(
            &small_args(40),
            Network::Regtest,
            Place::Relay(public.clone()),
            &key,
        ),
        key: None,
        listen: None,
    }
    .through(None);
    assert_eq!(unchanged.offer.relay, Some(public));
}

/// While `offer` runs, a seller whose buyer took the offer on the relay it
/// serves meets the buyer again there through its own machine, though the
/// session file it saves names the public URL, as the buyer's does.
#[test]
fn a_started_seller_rejoins_through_the_relay_it_serves() {
    struct Quiet;
    impl Transport for Quiet {
        fn send(&mut self, _: &[u8]) -> io::Result<()> {
            Ok(())
        }
        fn recv(&mut self, _: Duration) -> io::Result<Option<Vec<u8>>> {
            Ok(None)
        }
    }
    let served = serve_relay("127.0.0.1:0".parse().unwrap()).unwrap();
    let key = SigningKey::from_bytes(&random32());
    // Nothing answers here.
    let public = "http://127.0.0.1:1".to_string();
    let offer = offer_of(
        &small_args(40),
        Network::Regtest,
        Place::Relay(public.clone()),
        &key,
    );
    let directory = tempfile::tempdir().unwrap();
    let store = Store::new(directory.path(), [7; 32]);
    let unreachable = "http://127.0.0.1:1";
    let driver = swap::session::start_through(
        Seller::Done(Outcome::Refunded),
        vec![],
        Bitcoind::new(unreachable, "u:p", Network::Regtest, TIMEOUT),
        Client::new(unreachable, "c", TIMEOUT),
        MAINNET,
        Box::new(Quiet),
        Store::new(directory.path(), [7; 32]),
        SessionFile {
            offer: offer.clone(),
            key: Some(hex::encode(key.to_bytes())),
            listen: None,
        },
        None,
        Some(served.clone()),
    )
    .unwrap();
    let saved = SessionFile::load(&store).unwrap().unwrap();
    assert_eq!(
        saved.offer.relay,
        Some(public),
        "saved as the offer names it"
    );

    let mut seller = driver.reconnect.unwrap();
    let mut buyer = SessionFile {
        offer: Offer {
            relay: Some(served),
            ..offer
        },
        key: None,
        listen: None,
    }
    .reconnect(None)
    .unwrap();
    let rejoin = swap::Rejoin {
        id: [5; 32],
        key: [6; 32],
    };
    let (mut seller_session, mut buyer_session) = (None, None);
    for _ in 0..1_000 {
        if seller_session.is_none() {
            seller_session = seller(&rejoin).and_then(|opened| opened.ok());
        }
        if buyer_session.is_none() {
            buyer_session = buyer(&rejoin).and_then(|opened| opened.ok());
        }
        if seller_session.is_some() && buyer_session.is_some() {
            break;
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    let (mut seller, mut buyer) = (seller_session.unwrap(), buyer_session.unwrap());
    buyer.send(b"again").unwrap();
    assert_eq!(
        seller.recv(TIMEOUT).unwrap().as_deref(),
        Some(&b"again"[..])
    );
}

/// The relay served is listed on once, as served, though a --relay names
/// its server too: listed on as given, the seller would dial its own
/// relay out and back in, and be refused the second listing.
#[test]
fn the_relay_served_is_listed_on_once() {
    let relays = [
        "https://relay.example".to_string(),
        "HTTPS://Seller.Example/".into(),
    ];
    let local = "http://127.0.0.1:7500".to_string();
    assert_eq!(
        relays_dialled(&relays, Some((local.clone(), "https://seller.example"))),
        [
            (
                "https://relay.example".to_string(),
                "https://relay.example".to_string()
            ),
            (local, "https://seller.example".to_string()),
        ]
    );
    assert_eq!(
        relays_dialled(&relays, None),
        [
            (
                "https://relay.example".to_string(),
                "https://relay.example".to_string()
            ),
            (
                "HTTPS://Seller.Example/".to_string(),
                "HTTPS://Seller.Example/".to_string()
            ),
        ]
    );
}

/// What `offer` runs the swap with once a buyer takes it: on the relay it
/// serves, the rejoin through its own machine and the --serve-relay flags
/// in the resume hint; on another, neither, as `resume` refuses to serve a
/// relay the swap does not meet at.
#[test]
fn only_a_swap_taken_on_the_relay_served_resumes_serving_it() {
    let serve = ServeRelayArgs {
        serve_relay: Some("0.0.0.0:7500".parse().unwrap()),
        serve_relay_url: Some("https://seller.example".into()),
    };
    let local = "http://127.0.0.1:7500".to_string();
    let relays = relays_dialled(
        &["https://relay.example".to_string()],
        Some((local.clone(), "https://seller.example")),
    );
    assert_eq!(rejoin_through(&relays, 0, &serve), (None, String::new()));
    let (through, flags) = rejoin_through(&relays, 1, &serve);
    assert_eq!(through, Some(local));
    assert_eq!(
        flags,
        " --serve-relay 0.0.0.0:7500 --serve-relay-url https://seller.example"
    );
    // A URL that is the very address it is dialled at is the relay served
    // all the same.
    let loopback = "http://127.0.0.1:7500".to_string();
    let serve = ServeRelayArgs {
        serve_relay: Some("127.0.0.1:7500".parse().unwrap()),
        serve_relay_url: Some(loopback.clone()),
    };
    let relays = relays_dialled(
        &["https://relay.example".to_string()],
        Some((loopback.clone(), &loopback)),
    );
    assert_eq!(rejoin_through(&relays, 0, &serve), (None, String::new()));
    assert_eq!(
        rejoin_through(&relays, 1, &serve),
        (
            Some(loopback),
            " --serve-relay 127.0.0.1:7500 --serve-relay-url http://127.0.0.1:7500".into()
        )
    );
}

/// A buyer serves no relay: `resume --serve-relay` on a buyer's swap is
/// refused before anything is served.
#[cfg(unix)]
#[test]
fn resume_refuses_to_serve_a_relay_for_a_buyer() {
    let (buyer, _) = Buyer::start(small(16), ScriptBuf::new(), "b".into()).unwrap();
    let (_directory, path) = swap_file(buyer);
    let listen = {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        listener.local_addr().unwrap().to_string()
    };
    let args = [
        "lattice-swap",
        "resume",
        &path,
        "--serve-relay",
        &listen,
        "--serve-relay-url",
        "https://seller.example",
    ];
    let refused = exit_status(Cli::try_parse_from(args).unwrap().command)
        .unwrap_err()
        .to_string();
    assert!(refused.contains("a buyer's swap"), "{refused}");
    assert!(ureq::get(&format!("http://{listen}/offers"))
        .call()
        .is_err());
}

/// The lattice-node writes a new cookie at every restart: the client
/// offer, take and resume build reads the cookie file again on a 401
/// instead of staying refused.
#[test]
fn the_nexus_client_reads_a_rotated_cookie_again() {
    use std::io::{Read, Write};
    use std::net::TcpListener;
    let dir = tempfile::tempdir().unwrap();
    let cookie = dir.path().join(".cookie");
    fs::write(&cookie, "__cookie__:first").unwrap();
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let url = format!("http://{}", listener.local_addr().unwrap());
    let path = cookie.clone();
    std::thread::spawn(move || {
        use base64::Engine;
        for stream in listener.incoming() {
            let mut stream = stream.unwrap();
            let mut request = [0u8; 4096];
            let n = stream.read(&mut request).unwrap();
            let request = String::from_utf8_lossy(&request[..n]);
            let token = base64::engine::general_purpose::STANDARD
                .encode(fs::read_to_string(&path).unwrap().trim());
            let (status, body) = if request.contains(&format!("Authorization: Basic {token}\r\n")) {
                ("200 OK", r#"{"phase":"active","height":"7"}"#)
            } else {
                ("401 Unauthorized", "")
            };
            let head = format!(
                "HTTP/1.1 {status}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                body.len()
            );
            stream.write_all(head.as_bytes()).unwrap();
            stream.write_all(body.as_bytes()).unwrap();
        }
    });
    let cookie_arg = cookie.to_str().unwrap();
    let cli = Cli::try_parse_from(
        ["lattice-swap", "resume", "/s"]
            .iter()
            .chain(&NODES[..4])
            .chain(&["--nexus-url", &url, "--nexus-cookie", cookie_arg]),
    )
    .unwrap();
    let Command::Resume(args) = cli.command else {
        panic!("not resume")
    };
    let nexus = args.nodes.nexus();
    assert_eq!(nexus.health().unwrap().height, 7);
    fs::write(&cookie, "__cookie__:second\n").unwrap();
    assert_eq!(nexus.health().unwrap().height, 7);
}

/// With no node flags, both chains are read through public nodes: the
/// Esplora for `--btc-network` and the public Nexus read node.
#[test]
fn with_no_node_flags_both_chains_are_public() {
    let args = ["offer", "--price", "1", "--min-btc-amount", "1"];
    let args = [
        &args[..],
        &["--max-btc-amount", "2", "--btc-fee", "1", "--nex-fee", "1"],
    ];
    let args = [
        &["lattice-swap"][..],
        &args.concat(),
        &["--relay", "http://r"],
    ]
    .concat();
    let Command::Offer(offer) = Cli::try_parse_from(&args).unwrap().command else {
        panic!("an offer");
    };
    let nodes = offer.nodes;
    assert_eq!((nodes.btc_wallet, nodes.esplora), (None, None));
    assert_eq!(nodes.nexus_url, PUBLIC_NEXUS);
    assert_eq!(nodes.nexus_cookie, None);
    let url = |network| esplora_url(None, network).map_err(|e| e.to_string());
    assert_eq!(url(Network::Bitcoin).unwrap(), "https://mempool.space/api");
    assert_eq!(
        url(Network::Signet).unwrap(),
        "https://mempool.space/signet/api"
    );
    assert_eq!(
        url(Network::Testnet).unwrap(),
        "https://mempool.space/testnet/api"
    );
    assert!(url(Network::Regtest).unwrap_err().contains("--esplora"));
    assert_eq!(
        esplora_url(Some("http://e"), Network::Regtest).unwrap(),
        "http://e"
    );
}

/// Each chain's own-node flags stand alone: any mix parses, an Esplora
/// and a bitcoind together do not, and a bitcoind needs its wallet and
/// credentials.
#[test]
fn each_chain_is_public_or_your_own_independently() {
    let nodes = |flags: &[&str]| {
        let args = [&["lattice-swap", "resume", "f.json"][..], flags].concat();
        Cli::try_parse_from(&args).map(|cli| match cli.command {
            Command::Resume(args) => args.nodes,
            _ => unreachable!(),
        })
    };
    let bitcoind = ["--btc-wallet", "w", "--btc-cookie", "/c"];
    let own_nexus = ["--nexus-url", "http://n", "--nexus-cookie", "/n"];
    let esplora = ["--esplora", "http://e"];
    assert!(nodes(&[]).unwrap().public());
    assert_eq!(nodes(&[]).unwrap().poll(), Some(app::POLL));
    // Own bitcoind, public Nexus; an own Esplora, own Nexus; both own.
    assert!(nodes(&bitcoind).unwrap().public());
    assert!(nodes(&own_nexus).unwrap().public());
    assert!(!nodes(&[&esplora[..], &own_nexus].concat())
        .unwrap()
        .public());
    assert!(!nodes(&[&bitcoind[..], &own_nexus].concat())
        .unwrap()
        .public());
    let mixed = nodes(&bitcoind).unwrap();
    assert!(!mixed.public_bitcoin() && mixed.public_nexus());
    let mixed = nodes(&own_nexus).unwrap();
    assert!(mixed.public_bitcoin() && !mixed.public_nexus());
    let own = nodes(&[&bitcoind[..], &own_nexus].concat()).unwrap();
    assert_eq!(own.poll(), None);
    // The cookie is your node's: never sent to the public one.
    assert!(nodes(&["--nexus-cookie", "/n"]).is_err(), "no URL");
    // A public Nexus at another URL is still public.
    let other = nodes(&["--nexus-url", "http://n"]).unwrap();
    assert!(other.public() && other.nexus_cookie.is_none());

    assert!(nodes(&[&esplora[..], &bitcoind].concat()).is_err());
    assert!(nodes(&[&esplora[..], &["--btc-url", "http://b"]].concat()).is_err());
    assert!(nodes(&["--btc-wallet", "w"]).is_err(), "no credentials");
    assert!(nodes(&["--btc-cookie", "/c"]).is_err(), "no wallet");
    assert!(nodes(&["--btc-user", "u"]).is_err(), "no wallet");
    assert!(nodes(&["--btc-url", "http://b"]).is_err(), "no wallet");
    // mempool.space named by --esplora is still public, with its trust
    // note and the poll its rate limits ask for.
    for url in ["https://mempool.space/api", "https://mempool.space/api/"] {
        let named = nodes(&["--esplora", url]).unwrap();
        assert!(named.public_bitcoin() && named.public(), "{url}");
    }
    let named = nodes(&[
        "--esplora",
        "https://mempool.space/signet/api",
        "--btc-network",
        "signet",
    ]);
    assert!(named.unwrap().public_bitcoin());
    let own = nodes(&[&esplora[..], &own_nexus].concat()).unwrap();
    assert!(!own.public_bitcoin());
    let both = ["--btc-wallet", "w", "--btc-cookie", "/c", "--btc-user", "u"];
    assert!(nodes(&both).is_err());
    let user = nodes(&["--btc-wallet", "w", "--btc-user", "u"]).unwrap();
    assert_eq!(user.btc_user.as_deref(), Some("u"));
}

/// A public Nexus node is refused for a new swap unless it takes submits;
/// your own node's RPC is not asked.
#[test]
fn a_public_nexus_node_must_take_submits() {
    let check = |accepts: bool, cookie: Option<PathBuf>| {
        let mut nodes = offer_args(&[]).nodes;
        nodes.nexus_url = nexus_node_submitting(MAINNET, 10, true, 1, accepts);
        nodes.nexus_cookie = cookie;
        let client = nodes.nexus();
        nodes.check_nexus(&client).map_err(|e| e.to_string())
    };
    assert_eq!(check(true, None), Ok(()));
    let refused = check(false, None).unwrap_err();
    assert!(refused.contains("takes no transactions"), "{refused}");
    let cookie = tempfile::NamedTempFile::new().unwrap();
    assert_eq!(check(false, Some(cookie.path().into())), Ok(()));
}

/// A resumed swap is never refused for its Nexus node, as its Bitcoin side
/// must go on: the driver's check, through a public node that takes no
/// transactions, fails while the node is down, on another Nexus, or keeps
/// no past state, each time asked, and passes once the node does, never to
/// read it again.
#[test]
fn a_resumed_swap_reads_nexus_only_once_its_node_passes() {
    let mut nodes = offer_args(&[]).nodes;
    nodes.nexus_url = nexus_node_submitting(MAINNET, 10, true, 1, false);
    nodes.nexus_cookie = None;
    let good = nodes.nexus();
    let down = Client::public("http://127.0.0.1:9", TIMEOUT);
    let other = swap_nexus_tx::cid(b"other");
    let elsewhere = Client::public(&nexus_node_submitting(&other, 10, true, 1, false), TIMEOUT);
    let forgetful = Client::public(
        &nexus_node_submitting(MAINNET, 10, false, 1, false),
        TIMEOUT,
    );
    // Made asking no node: the check is the driver's, under its budget.
    let mut check = nodes.resumed_check();
    for _ in 0..2 {
        let failed = check(&down).unwrap_err();
        assert!(failed.contains("127.0.0.1:9"), "{failed}");
        let failed = check(&elsewhere).unwrap_err();
        assert!(
            failed.contains(&format!("genesis {other}, not {MAINNET}")),
            "{failed}"
        );
        let failed = check(&forgetful).unwrap_err();
        assert!(failed.contains("--state all"), "{failed}");
    }
    assert_eq!(check(&good), Ok(()));
    assert_eq!(check(&down), Ok(()), "passed once, not read again");
}

/// `wallet --withdraw` is refused while a swap in the directory has not
/// ended; a punished one has.
#[test]
fn a_swap_not_ended_is_found() {
    let (directory, _) = swap_file(Seller::Done(Outcome::Swapped));
    assert_eq!(unended(directory.path()).unwrap(), None);
    let seller = Seller::new(
        small(16),
        SecretBytes([7; 32]).nex_address(),
        ScriptBuf::new(),
        ScriptBuf::new(),
    )
    .unwrap();
    let (directory, path) = swap_file(seller);
    assert_eq!(unended(directory.path()).unwrap(), Some("07".repeat(32)));

    // A punished seller waits only for the buyer's claim, which may never
    // come, and spends nothing more from the wallet: ended, as the app's.
    let mut file: Value = serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
    let state = file["state"].as_object_mut().unwrap();
    let (_, inner) = state.iter().next().unwrap();
    file["state"] = json!({ "Punished": inner.clone() });
    fs::write(&path, serde_json::to_vec(&file).unwrap()).unwrap();
    assert_eq!(unended(directory.path()).unwrap(), None);
}

/// An Esplora whose block 0 is `network`'s genesis, and that has nothing
/// else.
fn esplora_of(network: Network) -> String {
    esplora_down_for(0, network)
}

/// [`esplora_of`], down for its first `down` requests: it answers them
/// 503.
fn esplora_down_for(mut down: usize, network: Network) -> String {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let url = format!("http://{}", listener.local_addr().unwrap());
    let genesis = bitcoin::constants::genesis_block(network)
        .block_hash()
        .to_string();
    std::thread::spawn(move || {
        for stream in listener.incoming() {
            let mut stream = stream.unwrap();
            let mut request = [0u8; 4096];
            let n = stream.read(&mut request).unwrap();
            let (status, body) = if down > 0 {
                down -= 1;
                ("503 Service Unavailable", "down")
            } else if request[..n].starts_with(b"GET /block-height/0 ") {
                ("200 OK", genesis.as_str())
            } else {
                ("404 Not Found", "")
            };
            let _ = write!(
                stream,
                "HTTP/1.1 {status}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                body.len()
            );
        }
    });
    url
}

/// A swap file says nothing of the Bitcoin it was made on: resumed on an
/// Esplora, a swap that does not pay the wallet in its directory, as one
/// made on a bitcoind does not, is refused, and no wallet is made for it.
#[test]
fn resume_on_an_esplora_takes_only_a_swap_paying_its_wallet() {
    let (buyer, _) = Buyer::start(small(16), ScriptBuf::new(), "b".into()).unwrap();
    let (directory, path) = swap_file(buyer);
    let dir = directory.path();
    let cli = Cli::try_parse_from(["lattice-swap", "resume", &path]).unwrap();
    let Command::Resume(args) = cli.command else {
        panic!("not resume")
    };
    let refused = resume(args).unwrap_err().to_string();
    assert!(refused.contains("does not pay the wallet"), "{refused}");
    assert!(!dir.join("wallet.json").exists());

    let esplora = esplora_of(Network::Regtest);
    let cli = Cli::try_parse_from([
        "lattice-swap",
        "resume",
        &path,
        "--esplora",
        &esplora,
        "--btc-network",
        "regtest",
    ])
    .unwrap();
    let Command::Resume(args) = cli.command else {
        panic!("not resume")
    };
    let config = app::Config::new(
        dir.into(),
        Network::Regtest,
        esplora,
        String::new(),
        None,
        String::new(),
    );
    let paid = Wallet::open(config)
        .unwrap()
        .esplora()
        .key()
        .script_pubkey
        .clone();
    let refused = match resume_bitcoin(&args.nodes, dir, Some(&ScriptBuf::new())) {
        Ok(_) => panic!("a swap not paying the wallet was resumed"),
        Err(e) => e.to_string(),
    };
    assert!(refused.contains("does not pay the wallet"), "{refused}");
    assert!(resume_bitcoin(&args.nodes, dir, Some(&paid)).is_ok());
}

/// A resumed swap's Bitcoin that cannot answer yet, down or erring for a
/// moment, is asked again until it does; one that answers it is on another
/// chain, or that the swap does not pay its wallet, is refused at once.
#[test]
fn resume_asks_a_failing_bitcoin_again_and_refuses_a_wrong_one() {
    let retry = Duration::from_millis(10);
    let (buyer, _) = Buyer::start(small(16), ScriptBuf::new(), "b".into()).unwrap();
    let (directory, path) = swap_file(buyer);
    let dir = directory.path();
    let on_esplora = |url: &str| {
        let args = ["lattice-swap", "resume", &path, "--esplora", url];
        let cli = Cli::try_parse_from([&args[..], &["--btc-network", "regtest"]].concat());
        let Command::Resume(args) = cli.unwrap().command else {
            panic!("not resume")
        };
        args.nodes
    };
    let nodes = on_esplora(&esplora_down_for(2, Network::Regtest));
    let wallet_pays = {
        let bitcoin = nodes.open_bitcoin(dir).unwrap();
        let Btc::Esplora(esplora, _) = &bitcoin else {
            panic!("an Esplora")
        };
        esplora.key().script_pubkey.clone()
    };
    assert!(resume_bitcoin_every(&nodes, dir, Some(&wallet_pays), retry).is_ok());
    let nodes = on_esplora(&esplora_of(Network::Signet));
    let refused = match resume_bitcoin_every(&nodes, dir, Some(&wallet_pays), retry) {
        Ok(_) => panic!("an Esplora on another chain was taken"),
        Err(e) => e.to_string(),
    };
    assert!(refused.contains("not regtest's"), "{refused}");

    let cookie = tempfile::NamedTempFile::new().unwrap();
    fs::write(cookie.path(), "user:password").unwrap();
    let on_bitcoind = |url: &str, network: &str| {
        let cli = Cli::try_parse_from([
            "lattice-swap",
            "resume",
            "f.json",
            "--btc-url",
            url,
            "--btc-wallet",
            "w",
            "--btc-cookie",
            cookie.path().to_str().unwrap(),
            "--btc-network",
            network,
        ]);
        let Command::Resume(args) = cli.unwrap().command else {
            panic!("not resume")
        };
        args.nodes
    };
    let down = on_bitcoind(&node_down_for(2, Value::Null, Value::Null), "bitcoin");
    assert!(resume_bitcoin_every(&down, dir, Some(&paid()), retry).is_ok());
    let elsewhere = on_bitcoind(&node(Value::Null, Value::Null), "signet");
    let refused = match resume_bitcoin_every(&elsewhere, dir, Some(&paid()), retry) {
        Ok(_) => panic!("a bitcoind on another chain was taken"),
        Err(e) => e.to_string(),
    };
    assert!(refused.contains("not signet"), "{refused}");
}

/// Resumed on a bitcoind, a swap that does not pay its wallet, as one
/// made on an Esplora does not, is refused, and says how to resume it.
#[test]
fn resume_on_a_bitcoind_takes_only_a_swap_paying_its_wallet() {
    let directory = tempfile::tempdir().unwrap();
    let dir = directory.path();
    let cookie = tempfile::NamedTempFile::new().unwrap();
    fs::write(cookie.path(), "user:password").unwrap();
    let resume_on = |ismine: bool| {
        let url = node(
            json!({"getaddressinfo": {"result": {"ismine": ismine}}}),
            Value::Null,
        );
        let cli = Cli::try_parse_from([
            "lattice-swap",
            "resume",
            "f.json",
            "--btc-url",
            &url,
            "--btc-wallet",
            "w",
            "--btc-cookie",
            cookie.path().to_str().unwrap(),
        ])
        .unwrap();
        let Command::Resume(args) = cli.command else {
            panic!("not resume")
        };
        args.nodes
    };
    assert!(resume_bitcoin(&resume_on(true), dir, Some(&paid())).is_ok());
    for (ismine, payout) in [(false, paid()), (true, ScriptBuf::new())] {
        let refused = match resume_bitcoin(&resume_on(ismine), dir, Some(&payout)) {
            Ok(_) => panic!("a swap not paying the wallet was resumed"),
            Err(e) => e.to_string(),
        };
        assert!(
            refused.contains("does not pay the bitcoind wallet w")
                && refused.contains("flags it was made with"),
            "{refused}"
        );
    }
    // A swap that has ended pays no one.
    assert!(resume_bitcoin(&resume_on(false), dir, None).is_ok());
}

/// Resumed on a bitcoind whose wallet is locked or not loaded, a swap
/// goes on at once: its cancel, refund and punish are signed already, and
/// only their bumps need the wallet. A locked wallet the swap does not pay
/// is refused still.
#[test]
fn resume_on_a_bitcoind_does_not_wait_for_its_wallet() {
    let directory = tempfile::tempdir().unwrap();
    let dir = directory.path();
    let cookie = tempfile::NamedTempFile::new().unwrap();
    fs::write(cookie.path(), "user:password").unwrap();
    let resume_on = |replies: Value| {
        let cli = Cli::try_parse_from([
            "lattice-swap",
            "resume",
            "f.json",
            "--btc-url",
            &node(replies, Value::Null),
            "--btc-wallet",
            "w",
            "--btc-cookie",
            cookie.path().to_str().unwrap(),
        ])
        .unwrap();
        let Command::Resume(args) = cli.command else {
            panic!("not resume")
        };
        args.nodes
    };
    let locked = json!({"private_keys_enabled": true, "unlocked_until": 0});
    let not_loaded = json!({"result": null, "error": {
        "code": -18,
        "message": "Requested wallet does not exist or is not loaded",
    }});
    let never = Duration::from_secs(3600);
    let locked_mine = resume_on(json!({"getwalletinfo": {"result": locked}}));
    assert!(resume_bitcoin_every(&locked_mine, dir, Some(&paid()), never).is_ok());
    let unloaded = resume_on(json!({
        "getwalletinfo": not_loaded,
        "getaddressinfo": not_loaded,
    }));
    assert!(resume_bitcoin_every(&unloaded, dir, Some(&paid()), never).is_ok());
    let locked_not_mine = resume_on(json!({
        "getwalletinfo": {"result": locked},
        "getaddressinfo": {"result": {"ismine": false}},
    }));
    let refused = match resume_bitcoin_every(&locked_not_mine, dir, Some(&paid()), never) {
        Ok(_) => panic!("a swap not paying the wallet was resumed"),
        Err(e) => e.to_string(),
    };
    assert!(
        refused.contains("does not pay the bitcoind wallet w"),
        "{refused}"
    );
}

/// On an Esplora, `take` is refused while a swap in the directory has not
/// ended, as the app's: it may yet broadcast a funding it signed from the
/// wallet.
#[test]
fn take_on_an_esplora_waits_for_the_last_swap_to_end() {
    let (buyer, _) = Buyer::start(small(16), ScriptBuf::new(), "b".into()).unwrap();
    let directory = tempfile::tempdir().unwrap();
    let store = Store::new(directory.path(), [8; 32]);
    let unreachable = "http://127.0.0.1:1";
    let bitcoin = Bitcoind::new(unreachable, "u:p", Network::Regtest, TIMEOUT);
    let nexus = Client::new(unreachable, "c", TIMEOUT);
    Driver::<_, _, Ivy>::start(buyer, vec![], bitcoin, nexus, None, store).unwrap();
    let offer = offer_of(
        &small_args(16),
        Network::Regtest,
        address(),
        &SigningKey::from_bytes(&[1; 32]),
    );
    let offer_file = directory.path().join("offer");
    fs::write(&offer_file, offer.encode()).unwrap();
    let nex_address = SecretBytes([7; 32]).nex_address();
    let esplora = esplora_of(Network::Regtest);
    let cli = Cli::try_parse_from([
        "lattice-swap",
        "take",
        offer_file.to_str().unwrap(),
        "--nex-address",
        &nex_address,
        "--price",
        "50000000",
        "--dir",
        directory.path().to_str().unwrap(),
        "--esplora",
        &esplora,
        "--btc-network",
        "regtest",
    ])
    .unwrap();
    let Command::Take(args) = cli.command else {
        panic!("not take")
    };
    let refused = take(args).unwrap_err().to_string();
    assert!(
        refused.contains(&format!("swap {} has not ended", "08".repeat(32))),
        "{refused}"
    );
}

/// `offer` refuses mainnet NEX for BTC on another network than Bitcoin's,
/// before it asks any node, unless --test-btc-for-mainnet-nex opts in.
#[test]
fn offer_refuses_mainnet_nex_for_test_btc_unless_opted_in() {
    let refused = offer(offer_args(&["--btc-network", "signet"]))
        .unwrap_err()
        .to_string();
    assert!(
        refused.contains("refused: mainnet NEX for signet BTC"),
        "{refused}"
    );
    // Opted in, it goes on to the next check, here a range below the
    // floor, before any node.
    let mut args = offer_args(&["--btc-network", "signet", "--test-btc-for-mainnet-nex"]);
    args.terms.min_btc_amount = 2_545;
    let refused = offer(args).unwrap_err().to_string();
    assert!(refused.contains("at 2545 sat, btc_amount"), "{refused}");
    // On another Nexus, or on Bitcoin, there is nothing to opt in to.
    let mut args = offer_args(&["--btc-network", "signet"]);
    args.nodes.nexus_genesis = swap_nexus_tx::cid(b"dev");
    args.terms.min_btc_amount = 2_545;
    let refused = offer(args).unwrap_err().to_string();
    assert!(refused.contains("at 2545 sat, btc_amount"), "{refused}");
}

/// `take`, and the library's, refuse an offer of mainnet NEX for BTC on
/// another network than Bitcoin's, unless the policy opts in, as
/// --test-btc-for-mainnet-nex does.
#[test]
fn take_refuses_mainnet_nex_for_test_btc_unless_opted_in() {
    let mut args = offer_args(&[]);
    args.terms.btc_fee = 10_000;
    args.terms.nex_fee = 1_000;
    let key = SigningKey::from_bytes(&[1; 32]);
    let offer = offer_of(&args, Network::Signet, address(), &key);
    let take = |extra: &[&str]| {
        let mut extra = extra.to_vec();
        extra.extend(["--btc-network", "signet"]);
        let mut args = vec!["take", "offer", "--nex-address", "b", "--price", "50000000"];
        args.extend(extra);
        let Command::Take(args) = parse(&args).unwrap().command else {
            panic!("a take")
        };
        let mut policy = args.policy.policy(&offer);
        policy.bounds.test_btc_for_mainnet_nex = args.nodes.test_btc_for_mainnet_nex;
        check_offer(
            &offer,
            &policy,
            args.nodes.btc_network,
            MAINNET,
            FLOOR,
            NEX_FLOOR,
        )
    };
    let refused = take(&[]).unwrap_err();
    assert!(
        refused.starts_with("refused: mainnet NEX for signet BTC"),
        "{refused}"
    );
    assert_eq!(take(&["--test-btc-for-mainnet-nex"]), Ok(()));

    let (policy, _) = policy(&[]);
    let directory = tempfile::tempdir().unwrap();
    let unreachable = "http://127.0.0.1:1";
    let refused = swap::session::take(
        offer,
        &policy.policy(&agreed()),
        Network::Signet,
        MAINNET,
        FLOOR,
        NEX_FLOOR,
        ScriptBuf::new(),
        swap_nexus_tx::cid(b"buyer"),
        Bitcoind::new(unreachable, "u:p", Network::Signet, TIMEOUT),
        Client::new(unreachable, "c", TIMEOUT),
        Store::new(directory.path(), [7; 32]),
    )
    .err()
    .unwrap()
    .to_string();
    assert!(
        refused.contains("refused: mainnet NEX for signet BTC"),
        "{refused}"
    );
}

/// A node hosting the relay directory at `RELAY_DIR_CHAIN`, whose tip lists
/// `listed` for `account`, pooling no fee below `floor`: it serves the
/// chain's info, the Volumes of the tip's block and state, and the account,
/// at balance 100 and nonce 6 (any other a 404), only when asked for that
/// chain, and records each transaction submitted.
fn relay_dir_node(
    floor: u64,
    account: &str,
    listed: Option<&str>,
) -> (String, Arc<std::sync::Mutex<Vec<Value>>>) {
    relay_dir_node_with(floor, account, listed, |_, _| {})
}

/// [`relay_dir_node`], its chain info and the nodes of the block's Volume,
/// the block first, as `tweak` leaves them.
fn relay_dir_node_with(
    floor: u64,
    account: &str,
    listed: Option<&str>,
    tweak: impl FnOnce(&mut Value, &mut Vec<(String, Vec<u8>)>),
) -> (String, Arc<std::sync::Mutex<Vec<Value>>>) {
    use ciborium::Value as Cbor;
    use std::io::BufRead;
    use std::sync::Mutex;
    let text = |text: &str| Cbor::Text(text.into());
    let map = |entries: Vec<(&str, Cbor)>| {
        Cbor::Map(entries.into_iter().map(|(k, v)| (text(k), v)).collect())
    };
    let mut nodes = Vec::new();
    let mut put = |node: Cbor| {
        let mut bytes = Vec::new();
        ciborium::into_writer(&node, &mut bytes).unwrap();
        let cid = swap_nexus_tx::cid(&bytes);
        nodes.push((cid.clone(), bytes));
        cid
    };
    let link = |cid: &str| map(vec![("rawCID", text(cid))]);
    let children = match listed {
        Some(url) => {
            let entry = put(map(vec![
                ("prefix", text(&format!("relay/{account}"))),
                ("value", text(url)),
                ("children", Cbor::Array(vec![])),
            ]));
            vec![map(vec![("key", text("r")), ("value", link(&entry))])]
        }
        None => vec![],
    };
    let count = Cbor::Integer(0.into());
    let root = put(map(vec![
        ("count", count),
        ("children", Cbor::Array(children)),
    ]));
    let state = put(map(vec![("generalState", link(&root))]));
    let block = put(map(vec![("postState", link(&state))]));
    // The block a Volume of its own, the state's nodes one under the state.
    let archive = |nodes: &[(String, Vec<u8>)]| {
        let mut archive = (nodes.len() as u16).to_be_bytes().to_vec();
        for (cid, bytes) in nodes {
            archive.extend((cid.len() as u16).to_be_bytes());
            archive.extend(cid.as_bytes());
            archive.extend((bytes.len() as u32).to_be_bytes());
            archive.extend(bytes);
        }
        archive
    };
    let (block_node, state_nodes) = nodes.split_last().unwrap();
    let chain: Vec<&str> = RELAY_DIR_CHAIN.split('/').collect();
    let mut info = json!({
        "chain": chain, "tipCID": block, "height": "5",
        "acceptsSubmit": true, "minRelayFee": floor.to_string(),
    });
    let mut block_volume = vec![block_node.clone()];
    tweak(&mut info, &mut block_volume);
    let volumes = [
        (block.clone(), archive(&block_volume)),
        (state.clone(), archive(state_nodes)),
    ];
    let account = account.to_string();
    let submitted = Arc::new(Mutex::new(Vec::new()));
    let recorded = submitted.clone();
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let url = format!("http://{}", listener.local_addr().unwrap());
    std::thread::spawn(move || {
        for stream in listener.incoming() {
            let mut stream = io::BufReader::new(stream.unwrap());
            let mut line = String::new();
            stream.read_line(&mut line).unwrap();
            let mut length = 0;
            loop {
                let mut header = String::new();
                stream.read_line(&mut header).unwrap();
                if let Some(n) = header.to_ascii_lowercase().strip_prefix("content-length:") {
                    length = n.trim().parse().unwrap();
                }
                if header == "\r\n" {
                    break;
                }
            }
            let mut body = vec![0; length];
            stream.read_exact(&mut body).unwrap();
            let target = line.split(' ').nth(1).unwrap();
            let (path, query) = target.split_once('?').unwrap_or((target, ""));
            let chained = query == "chainPath=Nexus%2Fswap-relays";
            let found: Option<Vec<u8>> = match path.strip_prefix("/volumes/") {
                _ if path == "/transactions" => {
                    recorded
                        .lock()
                        .unwrap()
                        .push(serde_json::from_slice(&body).unwrap());
                    Some(json!({"transactionCID": "bafy"}).to_string().into())
                }
                _ if !chained => None,
                Some(cid) => volumes
                    .iter()
                    .find(|(root, _)| root == cid)
                    .map(|(_, archive)| archive.clone()),
                None if path == "/api/chain/info" => Some(info.to_string().into()),
                None if path == format!("/api/state/account/{account}") => {
                    Some(json!({"balance": "100", "nonce": "6"}).to_string().into())
                }
                None => None,
            };
            let (status, body) = match found {
                Some(body) => ("200 OK", body),
                None => ("404 Not Found", Vec::new()),
            };
            let head = format!(
                "HTTP/1.1 {status}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                body.len()
            );
            let stream = stream.get_mut();
            stream.write_all(head.as_bytes()).unwrap();
            stream.write_all(&body).unwrap();
        }
    });
    (url, submitted)
}

/// `relay-dir add` and `remove` read the account's entry, then write it from
/// that value, paying --fee from the account at its nonce; a fee below the
/// node's floor, a write that changes nothing, or a URL readers skip, sends
/// none.
#[test]
fn relay_dir_writes_from_the_value_listed() {
    use std::os::unix::fs::PermissionsExt;
    let seed = [5; 32];
    let account = SecretBytes(seed).nex_address();
    let key = tempfile::NamedTempFile::new().unwrap();
    fs::write(key.path(), hex::encode(seed)).unwrap();
    fs::set_permissions(key.path(), fs::Permissions::from_mode(0o600)).unwrap();
    let old = "https://old.example";
    let run = |listed: Option<&str>, args: &[&str]| {
        let (url, submitted) = relay_dir_node(4, &account, listed);
        let key = key.path().to_str().unwrap();
        let flags = ["--key", key, "--nexus-url", &url];
        let cli = Cli::try_parse_from(
            ["lattice-swap", "relay-dir"]
                .iter()
                .chain(args)
                .chain(&flags),
        )
        .unwrap();
        let Command::RelayDir(command) = cli.command else {
            unreachable!()
        };
        let result = relay_dir_write(command).map_err(|e| e.to_string());
        let submitted = submitted.lock().unwrap().clone();
        (result, submitted)
    };
    let written = |submitted: &[Value]| {
        assert_eq!(submitted.len(), 1);
        submitted[0]["transaction"]["body"].clone()
    };

    let (result, submitted) = run(Some(old), &["add", "--url", "https://new.example/x"]);
    let refused = result.unwrap_err();
    assert!(refused.ends_with("pass --fee 4 to pay it"), "{refused}");
    assert!(submitted.is_empty());
    let (result, submitted) = run(
        Some(old),
        &["add", "--url", "https://new.example/x", "--fee", "4"],
    );
    result.unwrap();
    let body = written(&submitted);
    assert_eq!(
        body["actions"],
        json!([{"key": format!("relay/{account}"), "oldValue": old, "newValue": "https://new.example/x"}])
    );
    assert_eq!(
        body["accountActions"],
        json!([{"owner": account, "delta": "-4"}])
    );
    assert_eq!(body["nonce"], "6");
    assert_eq!(body["signers"], json!([account]));
    assert_eq!(
        body["chainPath"],
        json!(["Nexus", "swap-relays"])
    );

    let (result, submitted) = run(None, &["add", "--url", old, "--fee", "10"]);
    result.unwrap();
    let body = written(&submitted);
    assert_eq!(
        body["actions"],
        json!([{"key": format!("relay/{account}"), "newValue": old}])
    );
    assert_eq!(body["accountActions"][0]["delta"], "-10");

    let (result, submitted) = run(Some(old), &["remove", "--fee", "4"]);
    result.unwrap();
    assert_eq!(
        written(&submitted)["actions"],
        json!([{"key": format!("relay/{account}"), "oldValue": old}])
    );

    for (listed, args) in [
        (Some(old), &["add", "--url", old, "--fee", "4"][..]),
        (None, &["remove", "--fee", "4"]),
    ] {
        let (result, submitted) = run(listed, args);
        result.unwrap();
        assert!(submitted.is_empty(), "{args:?}");
    }

    let (result, submitted) = run(Some(old), &["add", "--url", "https://user@relay.example"]);
    assert!(result.unwrap_err().starts_with("refused: "));
    assert!(submitted.is_empty());
    for url in [
        "http://relay.example",
        "https://127.0.0.1",
        "https://localhost",
    ] {
        let (result, _) = run(None, &["add", "--url", url]);
        assert!(result.unwrap_err().starts_with("refused: "), "{url}");
    }

    let (result, submitted) = run(None, &["remove", "--chain", "Nexus/other"]);
    assert!(result.unwrap_err().contains("404"));
    assert!(submitted.is_empty());
}

/// `relay-dir list` reads the relays at the tip the node reports, from the
/// node's Volumes; a node not hosting --chain lists nothing.
#[test]
fn relay_dir_lists_from_the_tip_the_node_reports() {
    let account = SecretBytes([5; 32]).nex_address();
    let parse = |args: &[&str]| {
        let cli =
            Cli::try_parse_from(["lattice-swap", "relay-dir", "list"].iter().chain(args)).unwrap();
        let Command::RelayDir(RelayDirCommand::List(args)) = cli.command else {
            unreachable!()
        };
        args
    };
    let chain: Vec<String> = RELAY_DIR_CHAIN.split('/').map(String::from).collect();
    let (url, _) = relay_dir_node(0, &account, Some("https://relay.example"));
    let node = Client::public(&url, TIMEOUT);
    assert_eq!(
        relay_dir::list_hosted(&node, &chain).unwrap(),
        [relay_dir::Relay {
            account: account.clone(),
            url: "https://relay.example/".into()
        }]
    );
    relay_dir_list(parse(&["--nexus-url", &url])).unwrap();
    let (url, _) = relay_dir_node(0, &account, None);
    let node = Client::public(&url, TIMEOUT);
    assert_eq!(relay_dir::list_hosted(&node, &chain).unwrap(), []);
    relay_dir_list(parse(&["--nexus-url", &url])).unwrap();
    let refused = relay_dir_list(parse(&["--nexus-url", &url, "--chain", "Nexus/other"]));
    assert!(refused.unwrap_err().to_string().contains("404"));

    // A node answering for another chain, or with no tip or a tip that is
    // no CID, lists nothing.
    let list = |tweak: &dyn Fn(&mut Value)| {
        let (url, _) = relay_dir_node_with(0, &account, None, |info, _| tweak(info));
        relay_dir::list_hosted(&Client::public(&url, TIMEOUT), &chain).unwrap_err()
    };
    let refused = list(&|info| info["chain"] = json!(["Nexus", "other"]));
    assert!(refused.contains("answered for another chain"), "{refused}");
    let refused = list(&|info| info["tipCID"] = Value::Null);
    assert!(refused.contains("no tip yet"), "{refused}");
    let refused = list(&|info| info["tipCID"] = json!("x@y"));
    assert!(refused.contains("not a block CID"), "{refused}");
}

/// A Volume's nodes besides its root are kept only if they are the bytes
/// their CIDs name, at most `MAX_NODE_BYTES`: a node padding the block's
/// Volume with a false copy of the state, or with an oversized node, does
/// not change the list.
#[test]
fn relay_dir_lists_past_a_padded_volume() {
    let account = SecretBytes([5; 32]).nex_address();
    let chain: Vec<String> = RELAY_DIR_CHAIN.split('/').map(String::from).collect();
    let (url, _) =
        relay_dir_node_with(0, &account, Some("https://relay.example"), |info, nodes| {
            // A false copy of the block's state, `{postState: {rawCID}}`, which
            // would fail the walk if kept.
            let block: Value = {
                let block: ciborium::Value = ciborium::from_reader(&nodes[0].1[..]).unwrap();
                serde_json::to_value(block).unwrap()
            };
            let state = block["postState"]["rawCID"].as_str().unwrap().to_string();
            assert!(info["tipCID"] != state);
            nodes.push((state, b"\xa0".to_vec()));
            let big = vec![0xf6; relay_dir::MAX_NODE_BYTES + 1];
            nodes.push((swap_nexus_tx::cid(&big), big));
        });
    assert_eq!(
        relay_dir::list_hosted(&Client::public(&url, TIMEOUT), &chain).unwrap(),
        [relay_dir::Relay {
            account,
            url: "https://relay.example/".into()
        }]
    );
}

/// `relay-dir --key` reads a seed in hex or a key file `lattice key
/// generate` writes, `{address, privateKey, publicKey}`, refusing one whose
/// public key is not its private key's; `--nexus-url` has no default.
#[test]
fn relay_dir_reads_either_key_file() {
    use std::os::unix::fs::PermissionsExt;
    let seed = [5; 32];
    let public = SigningKey::from_bytes(&seed).verifying_key().to_bytes();
    let multikey = swap_nexus_tx::multikey_hex(&public);
    let key_file = |text: String| {
        let file = tempfile::NamedTempFile::new().unwrap();
        fs::write(file.path(), text).unwrap();
        fs::set_permissions(file.path(), fs::Permissions::from_mode(0o600)).unwrap();
        file
    };
    let lattice = |public_key: &str| {
        json!({
            "address": swap_nexus_tx::address(&public),
            "privateKey": hex::encode(seed),
            "publicKey": public_key,
        })
        .to_string()
    };
    for text in [
        hex::encode(seed),
        format!("{}\n", hex::encode(seed)),
        lattice(&multikey),
    ] {
        let file = key_file(text.clone());
        assert_eq!(relay_dir_key(file.path()).unwrap().0, seed, "{text}");
    }
    let other = swap_nexus_tx::multikey_hex(&[9; 32]);
    let refused = relay_dir_key(key_file(lattice(&other)).path());
    let refused = refused.err().unwrap().to_string();
    assert!(refused.contains("not its privateKey's"), "{refused}");
    assert!(relay_dir_key(key_file("{}".into()).path()).is_err());

    // A lattice key file writes as the seed does.
    let file = key_file(lattice(&multikey));
    let account = SecretBytes(seed).nex_address();
    let (url, submitted) = relay_dir_node(0, &account, None);
    let path = file.path().to_str().unwrap();
    let args = ["relay-dir", "remove", "--key", path, "--nexus-url", &url];
    let cli = Cli::try_parse_from(["lattice-swap"].iter().chain(&args)).unwrap();
    let Command::RelayDir(command) = cli.command else {
        unreachable!()
    };
    relay_dir_write(command).unwrap();
    assert!(submitted.lock().unwrap().is_empty(), "nothing listed");
    let (url, submitted) = relay_dir_node(0, &account, None);
    let args = [
        "relay-dir",
        "add",
        "--url",
        "https://r.example",
        "--key",
        path,
        "--nexus-url",
        &url,
    ];
    let cli = Cli::try_parse_from(["lattice-swap"].iter().chain(&args)).unwrap();
    let Command::RelayDir(command) = cli.command else {
        unreachable!()
    };
    relay_dir_write(command).unwrap();
    assert_eq!(
        submitted.lock().unwrap()[0]["transaction"]["body"]["signers"],
        json!([account])
    );

    // An account the node has never seen is at nonce 0, with no balance:
    // enough for a write that pays no fee.
    let (url, submitted) = relay_dir_node(0, "another", None);
    let args = [
        "relay-dir",
        "add",
        "--url",
        "https://r.example",
        "--key",
        path,
        "--nexus-url",
        &url,
    ];
    let cli = Cli::try_parse_from(["lattice-swap"].iter().chain(&args)).unwrap();
    let Command::RelayDir(command) = cli.command else {
        unreachable!()
    };
    relay_dir_write(command).unwrap();
    let body = submitted.lock().unwrap()[0]["transaction"]["body"].clone();
    assert_eq!(body["nonce"], "0");
    assert_eq!(body["accountActions"], json!([]));

    let args = ["lattice-swap", "relay-dir", "remove", "--key", path];
    assert!(
        Cli::try_parse_from(args).is_err(),
        "--nexus-url is required"
    );
}
