use super::*;
use bitcoin::hashes::Hash;
use bitcoin::{OutPoint, WScriptHash};
use clap::CommandFactory;
use swap::btc_amount_floor;
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
        "--btc-amount",
        "50000000",
        "--btc-fee",
        "1000",
        "--nex-amount",
        "1000000",
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
    let args = offer_args(&[
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
    ]);
    args.terms.terms([7; 32], MAINNET.into())
}

#[test]
fn the_defaults_are_the_agreed_settings_and_pass() {
    let args = offer_args(&[]);
    let terms = args.terms.terms([7; 32], MAINNET.into());
    assert_eq!((terms.t1, terms.t2), (288, 144));
    assert_eq!((terms.btc_confirmations, terms.nex_confirmations), (6, 24));
    assert_eq!(terms.btc_amount, Amount::from_sat(50_000_000));
    assert_eq!(args.nodes.btc_network, Network::Bitcoin);
    assert_eq!(Terms::check(&terms), Ok(()));
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
        let terms = offer_args(&[]).terms.terms(random32(), MAINNET.into());
        let offer = Offer::new(terms, Network::Signet, place, &key, random32());
        let text = offer.encode();
        assert!(!text.contains('\n'), "one line");
        assert_eq!(Offer::decode(&format!("{text}\n")).unwrap(), offer);
    }
    // The session authenticates the key the offer names, which signs it.
    let offer = Offer::new(small(16), Network::Signet, address(), &key, [7; 32]);
    let peer = ivy::Config::new(key).peer_key();
    assert_eq!(offer.seller_key().unwrap(), peer);
}

#[test]
fn an_offer_with_a_bad_seller_key_is_refused() {
    let key = SigningKey::from_bytes(&[1; 32]);
    let mut offer = Offer::new(small(16), Network::Bitcoin, address(), &key, [7; 32]);
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
    let signed = Offer::new(small(16), Network::Bitcoin, address(), &key, [7; 32]);
    Offer::decode(&signed.encode()).unwrap();
    type Change = (&'static str, fn(&mut Offer));
    let changes: [Change; 4] = [
        ("confirmations", |o| o.terms.nex_confirmations -= 1),
        ("margin", |o| o.terms.margin += 1),
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

#[test]
fn an_offer_names_an_address_or_a_relay() {
    let key = SigningKey::from_bytes(&[1; 32]);
    let mut offer = Offer::new(small(16), Network::Bitcoin, address(), &key, [7; 32]);
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
    assert!(args.listen.is_some() && args.relay.is_none());
    let base: Vec<&str> = [
        "offer",
        "--btc-amount",
        "50000000",
        "--btc-fee",
        "2000",
        "--nex-amount",
        "1000000",
        "--nex-fee",
        "1",
    ]
    .to_vec();
    let with = |extra: &[&str]| parse(&[&base[..], extra].concat());
    let Command::Offer(args) = with(&relay).unwrap().command else {
        panic!("an offer");
    };
    assert_eq!(args.relay.as_deref(), Some("http://127.0.0.1:1"));
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
    let mut args = vec![
        "take",
        "offer",
        "--nex-address",
        "b",
        "--btc-amount",
        "50000000",
        "--nex-amount",
        "1000000",
    ];
    args.extend(extra);
    match parse(&args).unwrap().command {
        Command::Take(args) => (args.policy, args.nodes.btc_network),
        _ => panic!("a take"),
    }
}

/// The default terms, at the default bounds.
fn agreed() -> Offer {
    let mut terms = offer_args(&[]).terms.terms([7; 32], MAINNET.into());
    terms.btc_fee = Amount::from_sat(10_000);
    terms.nex_fee = 1_000;
    let key = SigningKey::from_bytes(&[1; 32]);
    Offer::new(terms, Network::Bitcoin, address(), &key, [7; 32])
}

/// The fee floors the policy tests pass: the agreed fees.
const FLOOR: u64 = 10_000;
const NEX_FLOOR: u64 = 1_000;

#[test]
fn take_refuses_any_term_outside_its_policy() {
    let (policy, network) = policy(&[]);
    assert_eq!(
        check_offer(&agreed(), &policy, network, MAINNET, FLOOR, NEX_FLOOR),
        Ok(())
    );
    type Change = (&'static str, fn(&mut Offer));
    let changes: [Change; 16] = [
        ("network", |o| o.btc_network = Network::Testnet),
        ("nexus", |o| {
            o.terms.nexus_genesis = swap_nexus_tx::cid(b"dev")
        }),
        ("more btc", |o| o.terms.btc_amount += Amount::from_sat(1)),
        ("less btc", |o| o.terms.btc_amount -= Amount::from_sat(1)),
        ("more nex", |o| o.terms.nex_amount += 1),
        ("less nex", |o| o.terms.nex_amount -= 1),
        ("btc fee", |o| o.terms.btc_fee += Amount::from_sat(1)),
        ("btc fee floor", |o| o.terms.btc_fee -= Amount::from_sat(1)),
        ("nex fee", |o| o.terms.nex_fee += 1),
        ("nex fee floor", |o| o.terms.nex_fee -= 1),
        ("t1", |o| o.terms.t1 += 1),
        ("t2", |o| o.terms.t2 -= 1),
        ("btc confirmations", |o| o.terms.btc_confirmations -= 1),
        ("max btc confirmations", |o| o.terms.btc_confirmations = 13),
        ("nex confirmations", |o| o.terms.nex_confirmations -= 1),
        ("margin", |o| o.terms.margin = 5),
    ];
    for (what, change) in changes {
        let mut offer = agreed();
        change(&mut offer);
        assert_eq!(Terms::check(&offer.terms), Ok(()), "{what}");
        let refused = check_offer(&offer, &policy, network, MAINNET, FLOOR, NEX_FLOOR).unwrap_err();
        assert!(
            refused.starts_with("refused: the offer"),
            "{what}: {refused}"
        );
    }
    // The defaults leave t2 - btc_confirmations = 144 - 6.
    let (policy, network) = self::policy(&["--min-refund-window", "138"]);
    assert_eq!(
        check_offer(&agreed(), &policy, network, MAINNET, FLOOR, NEX_FLOOR),
        Ok(())
    );
    let mut offer = agreed();
    offer.terms.btc_confirmations += 1;
    let refused = check_offer(&offer, &policy, network, MAINNET, FLOOR, NEX_FLOOR).unwrap_err();
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

#[test]
fn take_refuses_terms_that_cannot_work() {
    let (policy, network) = policy(&["--max-t1", "1000"]);
    let mut offer = agreed();
    offer.terms.t1 = 100;
    assert!(
        check_offer(&offer, &policy, network, MAINNET, 0, 0).is_err(),
        "below the floor"
    );
}

#[test]
fn take_requires_the_agreed_amounts() {
    for amount in ["--btc-amount", "--nex-amount"] {
        let args = ["take", "offer", "--nex-address", "b", amount, "1"];
        assert!(parse(&args).is_err(), "{amount}");
    }
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
    let hinted = resume_hint(file.path(), "lost".into()).to_string();
    let hint = format!(
        "lost\nto carry on, run with the same flags, the node and key flags and \
         --max-fee-rate, --fallback-fee-rate, --max-fee-fraction and --max-tip-age: \
         lattice-swap resume {}",
        file.path().display()
    );
    assert_eq!(hinted, hint);
    let missing = file.path().with_extension("gone");
    assert_eq!(resume_hint(&missing, "lost".into()).to_string(), "lost");
}

#[test]
fn the_wallet_name_is_escaped() {
    let mut args = offer_args(&[]);
    args.nodes.btc_wallet = "my wallet/../x".into();
    assert_eq!(
        args.nodes.wallet_url(),
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

/// A bitcoind on mainnet that passes the node check, but where `replies`
/// names a method and the reply to it, and that answers every other call
/// with `result`.
fn node(replies: Value, result: Value) -> String {
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
            let request: Value = serde_json::from_slice(&body).unwrap();
            let method = request["method"].as_str().unwrap();
            let answer = match method {
                "getindexinfo" => json!({"txindex": {"synced": true}}),
                "getnetworkinfo" => json!({"version": 300_200}),
                "getblockchaininfo" => json!({"chain": "main", "initialblockdownload": false}),
                "getwalletinfo" => json!({"private_keys_enabled": true}),
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
    args.extend(["--btc-amount", "50000000", "--nex-amount", "1000000"]);
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
    offer.terms.btc_fee = Amount::from_sat(floor - 1);
    let refused = take_refusal(&offer, &address, &[], &bitcoind(estimate()));
    assert!(refused.contains("below the"), "{refused}");
    offer.terms.btc_fee = Amount::from_sat(floor);
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
    let mut args = offer_args(&[]);
    args.terms.btc_amount = 2_545;
    let refused = offer(args).unwrap_err().to_string();
    assert!(refused.contains("redeem pays two btc_fee"), "{refused}");
    let (policy, network) = policy(&[]);
    let mut offer = agreed();
    offer.terms.btc_amount = Amount::from_sat(2 * 10_000 + 545);
    let refused = check_offer(&offer, &policy, network, MAINNET, FLOOR, NEX_FLOOR).unwrap_err();
    assert!(refused.contains("redeem pays two btc_fee"), "{refused}");
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
    ]);
    args.bump.apply(&mut driver);
    let rate = |sat| FeeRate::from_sat_per_vb(sat).unwrap();
    let age = Duration::from_secs(30 * 60);
    assert_eq!(defaults(&driver), (rate(50), rate(5), 0.25, age));
    for fraction in ["0", "1"] {
        assert!(parse(&["resume", "x.json", "--max-fee-fraction", fraction]).is_ok());
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
    let refused = run(Path::new(&path), driver, &bump, |_| {})
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

/// A node without a synced txindex, older than Bitcoin Core 28, on
/// another chain, in initial block download, or without a wallet that
/// signs is refused by name.
#[test]
fn a_node_a_swap_cannot_rely_on_is_refused() {
    let check_on = |network: Network, method: &str, result: Value| {
        let url = node(json!({ method: {"result": result} }), Value::Null);
        Bitcoind::new(&url, "u:p", network, TIMEOUT)
            .check_node()
            .map_err(|e| e.to_string())
    };
    let check = |method: &str, result: Value| check_on(Network::Bitcoin, method, result);
    let synced = json!({"txindex": {"synced": true, "best_block_height": 7}});
    assert_eq!(check("getindexinfo", synced), Ok(()));
    assert_eq!(check("getnetworkinfo", json!({"version": 280_000})), Ok(()));
    let refused = check("getindexinfo", json!({})).unwrap_err();
    assert!(refused.contains("-txindex"), "{refused}");
    let refused = check("getindexinfo", json!({"txindex": {"synced": false}})).unwrap_err();
    assert!(refused.contains("still syncing"), "{refused}");
    let refused = check("getnetworkinfo", json!({"version": 270_000})).unwrap_err();
    assert!(refused.contains("Bitcoin Core 28 or later"), "{refused}");

    let on = |chain: &str| json!({"chain": chain, "initialblockdownload": false});
    for (network, chain) in [
        (Network::Bitcoin, "signet"),
        (Network::Testnet, "testnet4"),
        (Network::Testnet4, "test"),
        (Network::Signet, "regtest"),
    ] {
        let refused = check_on(network, "getblockchaininfo", on(chain)).unwrap_err();
        let expected = format!("on chain \"{chain}\", not {}", network.to_core_arg());
        assert!(refused.contains(&expected), "{refused}");
    }
    assert_eq!(
        check_on(Network::Signet, "getblockchaininfo", on("signet")),
        Ok(())
    );
    let downloading = json!({"chain": "main", "initialblockdownload": true});
    let refused = check("getblockchaininfo", downloading).unwrap_err();
    assert!(refused.contains("initial block download"), "{refused}");

    let watching = json!({"private_keys_enabled": false});
    let refused = check("getwalletinfo", watching).unwrap_err();
    assert!(refused.contains("the wallet cannot sign"), "{refused}");
    let locked = json!({"private_keys_enabled": true, "unlocked_until": 0});
    let refused = check("getwalletinfo", locked).unwrap_err();
    assert!(refused.contains("the wallet is locked"), "{refused}");
    let unlocked = json!({"private_keys_enabled": true, "unlocked_until": 1_900_000_000});
    assert_eq!(check("getwalletinfo", unlocked), Ok(()));
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
    args.nodes.btc_url = unindexed();
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
    let store = Store::new(directory.path(), offer.terms.swap_id);
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
        args.nodes.btc_url = bitcoind(result);
        args.nodes.btc_cookie = Some(cookie.path().to_path_buf());
        args.nodes.nexus_cookie = cookie.path().to_path_buf();
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
        nodes.nexus_cookie = cookie.path().to_path_buf();
        let client = nodes.nexus().unwrap();
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

/// `offer`, `take` and `resume` of a swap still running each check the
/// lattice-node, and `offer` and `take` before they take an address from
/// the wallet.
#[cfg(unix)]
#[test]
fn offer_take_and_resume_check_the_nexus_node() {
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
            "--btc-amount",
            "50000000",
            "--btc-fee",
            &fee,
            "--nex-amount",
            "1000000",
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
    let home = SecretBytes([7; 32]).nex_address();
    let seller = Seller::new(small(16), home, ScriptBuf::new(), ScriptBuf::new()).unwrap();
    let (_directory, path) = swap_file(seller);
    refused(refusal_on(
        &["resume", &path, "--nex-key-file", key],
        &url,
        &forgetful(),
    ));
    let (buyer, _) = Buyer::start(small(16), ScriptBuf::new(), "b".into()).unwrap();
    let (_directory, path) = swap_file(buyer);
    refused(refusal_on(&["resume", &path], &url, &forgetful()));
}

/// The Nexus genesis defaults to mainnet's, as anchored in Bitcoin, for
/// `offer`, `take` and `resume` alike.
#[test]
fn the_nexus_genesis_defaults_to_mainnets() {
    assert_eq!(
        MAINNET,
        "bafyreiggtg4ezifboyekbf4gxst2jr3mpjqcxsbmopy7w6fp46g4ngpgxa"
    );
    let take = [
        "take",
        "o",
        "--nex-address",
        "b",
        "--btc-amount",
        "1",
        "--nex-amount",
        "1",
    ];
    for args in [
        &[
            "offer",
            "--btc-amount",
            "1",
            "--btc-fee",
            "1",
            "--nex-amount",
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
            Command::Status { .. } => unreachable!(),
        };
        assert_eq!(nodes.nexus_genesis, MAINNET, "{args:?}");
    }
}

/// `offer`, `take` and `resume` refuse a lattice-node on another Nexus than
/// `--nexus-genesis` names, before they ask it anything else, and run on
/// the one it names.
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
            "--btc-amount",
            "50000000",
            "--btc-fee",
            &fee,
            "--nex-amount",
            "1000000",
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
    dev_offer.terms.nexus_genesis = dev.clone();
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
    // before it asks any node, then a node on another than the flag's.
    let home = SecretBytes([7; 32]).nex_address();
    let on = |genesis: &str| Terms {
        nexus_genesis: genesis.into(),
        ..small(16)
    };
    let mut files = vec![];
    for genesis in [MAINNET, dev.as_str()] {
        let seller = Seller::new(
            on(genesis),
            home.clone(),
            ScriptBuf::new(),
            ScriptBuf::new(),
        );
        files.push((genesis, swap_file(seller.unwrap())));
        let (buyer, _) = Buyer::start(on(genesis), ScriptBuf::new(), "b".into()).unwrap();
        files.push((genesis, swap_file(buyer)));
    }
    for (genesis, (_directory, path)) in &files {
        let resume = |extra: &[&str], nexus_url: &str| {
            let mut args = vec!["resume", path.as_str(), "--nex-key-file", key];
            args.extend(extra);
            refusal_on(&args, &url, nexus_url)
        };
        let (flag, other) = match *genesis == MAINNET {
            true => (vec![], dev.as_str()),
            false => (on_dev.to_vec(), MAINNET),
        };
        let kept = resume(&["--nexus-genesis", other], &nexus_node_on(other, 10, true));
        assert!(
            kept.contains(&format!(
                "trades on the Nexus of genesis {genesis}, not {other}"
            )),
            "{kept}"
        );
        refused(
            resume(&flag, &nexus_node_on(other, 10, true)),
            other,
            genesis,
        );
        // Past the genesis, the next check is the node's past state.
        let next = resume(&flag, &nexus_node_on(genesis, 10, false));
        assert!(next.contains("--state all"), "{next}");
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
        args.nodes.btc_url = bitcoind(estimate());
        args.nodes.btc_cookie = Some(cookie.path().to_path_buf());
        args.nodes.nexus_cookie = cookie.path().to_path_buf();
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
        offer.terms.nex_fee = nex_fee;
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
