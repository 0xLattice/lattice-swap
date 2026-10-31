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

#[test]
fn take_refuses_any_term_outside_its_policy() {
    let (policy, network) = policy(&[]);
    assert_eq!(check_offer(&agreed(), &policy, network), Ok(()));
    type Change = (&'static str, fn(&mut Offer));
    let changes: [Change; 11] = [
        ("network", |o| o.btc_network = Network::Testnet),
        ("more btc", |o| o.terms.btc_amount += Amount::from_sat(1)),
        ("less btc", |o| o.terms.btc_amount -= Amount::from_sat(1)),
        ("more nex", |o| o.terms.nex_amount += 1),
        ("less nex", |o| o.terms.nex_amount -= 1),
        ("btc fee", |o| o.terms.btc_fee += Amount::from_sat(1)),
        ("nex fee", |o| o.terms.nex_fee += 1),
        ("t1", |o| o.terms.t1 += 1),
        ("t2", |o| o.terms.t2 -= 1),
        ("btc confirmations", |o| o.terms.btc_confirmations -= 1),
        ("nex confirmations", |o| o.terms.nex_confirmations -= 1),
    ];
    for (what, change) in changes {
        let mut offer = agreed();
        change(&mut offer);
        assert_eq!(check_terms(&offer.terms), Ok(()), "{what}");
        let refused = check_offer(&offer, &policy, network).unwrap_err();
        assert!(
            refused.starts_with("refused: the offer"),
            "{what}: {refused}"
        );
    }
}

#[test]
fn take_refuses_terms_that_cannot_work() {
    let (policy, network) = policy(&["--max-t1", "1000"]);
    let mut offer = agreed();
    offer.terms.t1 = 100;
    assert!(
        check_offer(&offer, &policy, network).is_err(),
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
    let key = SecretBytes([7; 32]);
    let seller = Seller::new(
        small(16),
        key.nex_address(),
        ScriptBuf::new(),
        ScriptBuf::new(),
    )
    .unwrap();
    assert!(seller_key(&seller, SecretBytes([8; 32])).is_err());
    assert_eq!(seller_key(&seller, key).unwrap().0, [7; 32]);
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
        "lost\nresume with: lattice-swap resume {}",
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
