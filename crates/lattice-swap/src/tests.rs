use super::*;
use clap::CommandFactory;

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
    args.terms.terms([7; 32])
}

#[test]
fn the_defaults_are_the_agreed_settings_and_pass() {
    let args = offer_args(&[]);
    let terms = args.terms.terms([7; 32]);
    assert_eq!((terms.t1, terms.t2), (288, 144));
    assert_eq!((terms.btc_confirmations, terms.nex_confirmations), (6, 24));
    assert_eq!(terms.btc_amount, Amount::from_sat(50_000_000));
    assert_eq!(args.nodes.btc_network, Network::Bitcoin);
    assert_eq!(check_terms(&terms), Ok(()));
}

#[test]
fn t1_below_the_floor_is_refused() {
    assert_eq!(t1_floor(&small(16)), 16);
    let refused = check_terms(&small(15)).unwrap_err();
    assert!(refused.contains("below 16"), "{refused}");
}

#[test]
fn t1_at_the_floor_is_accepted() {
    assert_eq!(check_terms(&small(16)), Ok(()));
}

#[test]
fn terms_that_cannot_work_are_refused() {
    let mut terms = small(16);
    terms.margin = 1;
    assert!(check_terms(&terms).is_err());
}

#[test]
fn the_floor_does_not_overflow() {
    let mut terms = small(16);
    terms.nex_confirmations = u64::MAX;
    assert!(check_terms(&terms).is_err());
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

#[test]
fn an_offer_parses_back_into_the_same_terms() {
    let offer = Offer {
        terms: offer_args(&[]).terms.terms(random32()),
        btc_network: Network::Signet,
        address: "192.0.2.1:7000".parse().unwrap(),
        seller: ivy::Config::new(SigningKey::from_bytes(&random32()))
            .peer_key()
            .hex(),
        buyer_session: random32(),
    };
    let text = offer.encode();
    assert!(!text.contains('\n'), "one line");
    assert_eq!(Offer::decode(&format!("{text}\n")).unwrap(), offer);
}

#[test]
fn an_offer_with_a_bad_seller_key_is_refused() {
    let offer = Offer {
        terms: small(16),
        btc_network: Network::Bitcoin,
        address: "192.0.2.1:7000".parse().unwrap(),
        seller: "00".repeat(31),
        buyer_session: [7; 32],
    };
    assert!(Offer::decode(&offer.encode()).is_err());
}

#[test]
fn only_a_nexus_address_is_paid() {
    let address = swap_nexus_tx::address(&[9; 32]);
    assert!(check_nex_address(&address).is_ok());
    assert!(check_nex_address(&address.to_ascii_uppercase()).is_err());
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
    let mut terms = offer_args(&[]).terms.terms([7; 32]);
    terms.btc_fee = Amount::from_sat(10_000);
    terms.nex_fee = 1_000;
    Offer {
        terms,
        btc_network: Network::Bitcoin,
        address: "192.0.2.1:7000".parse().unwrap(),
        seller: "00".repeat(32),
        buyer_session: [7; 32],
    }
}

/// The fee floor the policy tests pass: the agreed fee.
const FLOOR: u64 = 10_000;

#[test]
fn take_refuses_any_term_outside_its_policy() {
    let (policy, network) = policy(&[]);
    assert_eq!(check_offer(&agreed(), &policy, network, FLOOR), Ok(()));
    type Change = (&'static str, fn(&mut Offer));
    let changes: [Change; 13] = [
        ("network", |o| o.btc_network = Network::Testnet),
        ("more btc", |o| o.terms.btc_amount += Amount::from_sat(1)),
        ("less btc", |o| o.terms.btc_amount -= Amount::from_sat(1)),
        ("more nex", |o| o.terms.nex_amount += 1),
        ("less nex", |o| o.terms.nex_amount -= 1),
        ("btc fee", |o| o.terms.btc_fee += Amount::from_sat(1)),
        ("btc fee floor", |o| o.terms.btc_fee -= Amount::from_sat(1)),
        ("nex fee", |o| o.terms.nex_fee += 1),
        ("t1", |o| o.terms.t1 += 1),
        ("t2", |o| o.terms.t2 -= 1),
        ("btc confirmations", |o| o.terms.btc_confirmations -= 1),
        ("max btc confirmations", |o| o.terms.btc_confirmations = 13),
        ("nex confirmations", |o| o.terms.nex_confirmations -= 1),
    ];
    for (what, change) in changes {
        let mut offer = agreed();
        change(&mut offer);
        assert_eq!(check_terms(&offer.terms), Ok(()), "{what}");
        let refused = check_offer(&offer, &policy, network, FLOOR).unwrap_err();
        assert!(
            refused.starts_with("refused: the offer"),
            "{what}: {refused}"
        );
    }
    // The defaults leave t2 - btc_confirmations = 144 - 6.
    let (policy, network) = self::policy(&["--min-refund-window", "138"]);
    assert_eq!(check_offer(&agreed(), &policy, network, FLOOR), Ok(()));
    let mut offer = agreed();
    offer.terms.btc_confirmations += 1;
    let refused = check_offer(&offer, &policy, network, FLOOR).unwrap_err();
    assert!(refused.contains("blocks to refund in"), "{refused}");
}

#[test]
fn the_refund_window_defaults_to_half_a_day() {
    let (policy, _) = policy(&[]);
    assert_eq!(policy.max_btc_confirmations, 12);
    assert_eq!(policy.min_refund_window, 72);
    assert_eq!(policy.min_btc_fee_rate, None);
}

#[test]
fn take_refuses_terms_that_cannot_work() {
    let (policy, network) = policy(&["--max-t1", "1000"]);
    let mut offer = agreed();
    offer.terms.t1 = 100;
    assert!(
        check_offer(&offer, &policy, network, 0).is_err(),
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
        "lost\nto carry on, run with the same node and key flags: lattice-swap resume {}",
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

/// Past the cap on handshakes at once a connection is dropped, and each
/// handshake gets `send_timeout`, so the buyer gets in once idle ones end.
#[test]
fn offer_bounds_each_handshake() {
    use std::net::TcpStream;
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    let seller = ivy::Config::new(SigningKey::from_bytes(&[1; 32]));
    let buyer = ivy::Config::new(SigningKey::from_bytes(&[2; 32]));
    let (seller_key, buyer_key) = (seller.peer_key(), buyer.peer_key());
    let accepting = std::thread::spawn(move || {
        Ivy::accept(
            listener,
            &seller,
            buyer_key,
            Duration::from_secs(60),
            Duration::from_secs(2),
        )
        .map(|_| ())
    });
    let start = std::time::Instant::now();
    let idle: Vec<_> = (0..swap::transport::HANDSHAKES)
        .map(|_| TcpStream::connect(address).unwrap())
        .collect();
    std::thread::sleep(Duration::from_millis(500));
    let full = Ivy::connect(address, &buyer, seller_key, Duration::from_secs(5));
    assert!(full.is_err(), "no room while every handshake is taken");
    std::thread::sleep(Duration::from_secs(2));
    let _buyer = Ivy::connect(address, &buyer, seller_key, Duration::from_secs(5)).unwrap();
    accepting.join().unwrap().unwrap();
    assert!(
        start.elapsed() < Duration::from_secs(20),
        "{:?}",
        start.elapsed()
    );
    drop(idle);
}

/// A bitcoind that answers every call with `result`.
fn bitcoind(result: Value) -> String {
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
            let reply = json!({"result": result, "error": null}).to_string();
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
/// flags it needs: node files that exist, and a bitcoind at `btc_url`.
fn refusal(args: &[&str], btc_url: &str) -> String {
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
        "http://127.0.0.1:1",
        "--nexus-cookie",
        cookie,
    ];
    let cli = Cli::try_parse_from(["lattice-swap"].iter().chain(args).chain(&nodes)).unwrap();
    exit_status(cli.command).unwrap_err().to_string()
}

/// `take` on `offer`, paying `address`.
fn take_refusal(offer: &Offer, address: &str, extra: &[&str], btc_url: &str) -> String {
    let file = tempfile::NamedTempFile::new().unwrap();
    fs::write(file.path(), offer.encode()).unwrap();
    let path = file.path().to_str().unwrap();
    let mut args = vec!["take", path, "--nex-address", address];
    args.extend(["--btc-amount", "50000000", "--nex-amount", "1000000"]);
    args.extend(extra);
    refusal(&args, btc_url)
}

/// The agreed offer, with a seller key that is one.
fn takeable() -> Offer {
    let mut offer = agreed();
    offer.seller = ivy::Config::new(SigningKey::from_bytes(&[1; 32]))
        .peer_key()
        .hex();
    offer
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

/// At its floor every spend pays the rate, redeem two fees and the others
/// one, and at 1 sat/vB the floor is what swap-bitcoin requires.
#[test]
fn the_fee_floor_pays_every_spend_its_rate() {
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
        for spend in [Spend::Redeem, Spend::Cancel, Spend::Refund, Spend::Punish] {
            let a = swap.sign(lock, spend, &seller);
            let b = (spend != Spend::Punish).then(|| swap.sign(lock, spend, &buyer));
            let vsize = swap.finalize(lock, spend, &a, b.as_ref()).unwrap().vsize() as u64;
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
    assert_eq!(check_terms(&terms), Ok(()));
    terms.btc_amount -= Amount::from_sat(1);
    let refused = check_terms(&terms).unwrap_err();
    assert!(refused.contains("redeem pays two btc_fee"), "{refused}");
    terms.btc_fee = Amount::MAX;
    assert!(check_terms(&terms).is_err(), "no overflow");

    // `offer` refuses before it asks any node; `take` before it dials.
    let mut args = offer_args(&[]);
    args.terms.btc_amount = 2_545;
    let refused = offer(args).unwrap_err().to_string();
    assert!(refused.contains("redeem pays two btc_fee"), "{refused}");
    let (policy, network) = policy(&[]);
    let mut offer = agreed();
    offer.terms.btc_amount = Amount::from_sat(2 * 10_000 + 545);
    let refused = check_offer(&offer, &policy, network, FLOOR).unwrap_err();
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
        (d.max_fee_rate, d.fallback_fee_rate, d.max_fee_fraction)
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
    ]);
    args.bump.apply(&mut driver);
    let rate = |sat| FeeRate::from_sat_per_vb(sat).unwrap();
    assert_eq!(defaults(&driver), (rate(50), rate(5), 0.25));
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

    // A run sets them on its driver, which checks the fraction first.
    let mut bump = offer_args(&[]).bump;
    bump.max_fee_fraction = f64::NAN;
    let driver = Driver::<Seller, _, Ivy>::resume(bitcoin(), nexus(), None, store());
    let refused = run(Path::new(&path), driver, &bump)
        .unwrap_err()
        .to_string();
    assert!(refused.contains("max_fee_fraction NaN"), "{refused}");
}

#[test]
fn offer_refuses_an_address_nobody_can_dial() {
    let mut args = offer_args(&[]);
    args.listen = "0.0.0.0:7400".parse().unwrap();
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
        assert!(refused.contains("this build reads only 2"), "{refused}");
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
    let mut args = vec!["lattice-swap", "resume", &path];
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
