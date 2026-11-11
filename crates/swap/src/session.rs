//! What a party runs a swap on beyond its machine and driver: the session to
//! the counterparty and the file it rejoins by, the buyer's take of an
//! offer, and the swap file a party resumes from.

use std::fs;
use std::io::{self, Write};
use std::net::{SocketAddr, TcpListener};
use std::path::{Path, PathBuf};
use std::time::Duration;

use bitcoin::{Network, ScriptBuf};
use ed25519_dalek::SigningKey;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use swap_nexus_tx::rpc::parse::NodeRefusal;
use swap_nexus_tx::rpc::{self, Client};

use crate::bitcoind::Bitcoin;
use crate::driver::{Driver, NexusCheck, Reconnect, Store};
use crate::offer::{check_offer, Offer, Place, Policy};
use crate::transport::{Ivy, Relayed, Transport};
use crate::{Action, Buyer, Machine, Message, Seller, Terms};

pub type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;

/// Bounds each call to a node, the dial, and each send to the counterparty.
pub const TIMEOUT: Duration = Duration::from_secs(30);

/// A session of either kind.
pub type Session = Box<dyn Transport + Send>;

/// How long one attempt to rejoin waits for the counterparty, at the relay
/// or listening, before the next.
const REJOIN_WAIT: Duration = Duration::from_secs(60);

/// How a party meets its counterparty again once their session is lost,
/// saved beside the swap file, as `<swap id>.session`, so `resume` can:
/// the offer, and for the seller the session key it names, in hex, and the
/// address it listened on, if not on a relay. The seller dials no one: it
/// listens again, or waits at the relay; the buyer dials the seller, or
/// comes to the relay. Readable by its owner alone.
#[derive(Clone, Serialize, Deserialize)]
pub struct SessionFile {
    pub offer: Offer,
    pub key: Option<String>,
    pub listen: Option<SocketAddr>,
}

impl SessionFile {
    fn path(store: &Store) -> PathBuf {
        store.path().with_extension("session")
    }

    pub fn save(&self, store: &Store) -> Result<()> {
        let mut options = fs::OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        std::os::unix::fs::OpenOptionsExt::mode(&mut options, 0o600);
        let mut file = options.open(Self::path(store))?;
        file.write_all(&serde_json::to_vec(self)?)?;
        Ok(file.sync_all()?)
    }

    /// `None` for a swap saved without one.
    pub fn load(store: &Store) -> Result<Option<Self>> {
        match fs::read(Self::path(store)) {
            Ok(bytes) => Ok(Some(serde_json::from_slice(&bytes)?)),
            Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(e.into()),
        }
    }

    /// The same session, meeting the counterparty on the relay at `relay`,
    /// if given, rather than at the URL its offer names: a seller's own
    /// relay, which it reaches on its own machine, where that URL, routed
    /// out and back in, may not reach it. The relay is only where to go;
    /// the session's keys and rendezvous are the same anywhere.
    pub fn through(mut self, relay: Option<String>) -> Self {
        if relay.is_some() {
            self.offer.relay = relay;
        }
        self
    }

    /// Opens sessions to the counterparty for [`Driver::reconnect`]: the
    /// seller's on `listener` if it listens, else on the one it listened
    /// on. The buyer comes back under the rejoin key ([`crate::Rejoin`]),
    /// and the seller takes no other.
    pub fn reconnect(&self, listener: Option<TcpListener>) -> Result<Reconnect<Session>> {
        let offer = &self.offer;
        let place = offer.place()?;
        let Some(key) = &self.key else {
            let seller = offer.seller_key()?;
            return Ok(crate::transport::in_background(move |rejoin| {
                let config = ivy::Config::new(SigningKey::from_bytes(&rejoin.key));
                Ok(match &place {
                    Place::Relay(relay) => Box::new(Ivy::connect_rejoined(
                        relay,
                        rejoin.id,
                        &config,
                        seller,
                        REJOIN_WAIT,
                        TIMEOUT,
                    )?) as Session,
                    Place::Address(address) => {
                        Box::new(Ivy::connect(*address, &config, seller, TIMEOUT)?)
                    }
                })
            }));
        };
        let mut seed = [0u8; 32];
        hex::decode_to_slice(key, &mut seed).map_err(|_| "the session key is not hex")?;
        let listener = match (listener, self.listen) {
            (Some(listener), _) => Some(listener),
            (None, Some(listen)) => Some(TcpListener::bind(listen)?),
            (None, None) => None,
        };
        Ok(crate::transport::in_background(move |rejoin| {
            let config = ivy::Config::new(SigningKey::from_bytes(&seed));
            let buyer = ivy::Config::new(SigningKey::from_bytes(&rejoin.key)).peer_key();
            Ok(match (&listener, &place) {
                (Some(listener), _) => Box::new(Ivy::accept(
                    listener.try_clone()?,
                    &config,
                    buyer,
                    REJOIN_WAIT,
                    TIMEOUT,
                )?) as Session,
                (None, Place::Relay(relay)) => Box::new(Ivy::accept_rejoined(
                    relay,
                    rejoin.id,
                    &config,
                    buyer,
                    REJOIN_WAIT,
                    TIMEOUT,
                )?),
                (None, Place::Address(_)) => {
                    return Err(io::Error::other("the seller listens nowhere"))
                }
            })
        }))
    }
}

/// The terms the seller of `offer` fixes at the request `policy` makes on
/// `transport`, if they are exactly the ones asked for.
pub fn request_terms<T: Transport>(
    transport: &mut T,
    offer: &Offer,
    policy: &Policy,
) -> Result<Terms> {
    let swap_id = offer.template.swap_id;
    let request = Message::Request {
        btc_amount: policy.btc_amount,
        price: policy.price,
    };
    transport.send(&request.encode(swap_id))?;
    let message = transport
        .recv(TIMEOUT)?
        .and_then(|payload| Message::decode(&payload, swap_id));
    let Some(Message::Answer(answer)) = message else {
        return Err("the seller sent no answer".into());
    };
    Ok(offer.check_answer(policy, &answer)?)
}

/// A driver for `machine`, which asks for `actions` first, over `transport`,
/// meeting the counterparty again by `rejoin`, saved beside the swap file,
/// whenever the session is lost: the seller on `listener`, if it listens.
/// Its Nexus node is checked to follow the Nexus of `nexus_genesis` at
/// every view, as a resumed swap's is: see [`Driver::nexus_genesis`].
#[allow(clippy::too_many_arguments)]
pub fn start<M: Machine, B: Bitcoin>(
    machine: M,
    actions: Vec<Action>,
    bitcoin: B,
    nexus: Client,
    nexus_genesis: &str,
    transport: Session,
    store: Store,
    rejoin: SessionFile,
    listener: Option<TcpListener>,
) -> Result<Driver<M, B, Session>> {
    start_through(
        machine,
        actions,
        bitcoin,
        nexus,
        nexus_genesis,
        transport,
        store,
        rejoin,
        listener,
        None,
    )
}

/// [`start`], meeting the counterparty again on the relay at `relay`, if
/// given ([`SessionFile::through`]); `rejoin` is saved as it is, naming
/// the relay the offer does.
#[allow(clippy::too_many_arguments)]
pub fn start_through<M: Machine, B: Bitcoin>(
    machine: M,
    actions: Vec<Action>,
    bitcoin: B,
    nexus: Client,
    nexus_genesis: &str,
    transport: Session,
    store: Store,
    rejoin: SessionFile,
    listener: Option<TcpListener>,
    relay: Option<String>,
) -> Result<Driver<M, B, Session>> {
    log(&format!("swap file {}", store.path().display()));
    let reconnect = rejoin.clone().through(relay).reconnect(listener)?;
    rejoin.save(&store)?;
    let mut driver = Driver::start(machine, actions, bitcoin, nexus, Some(transport), store)?;
    driver.reconnect = Some(reconnect);
    driver.nexus_genesis = Some(nexus_genesis.into());
    Ok(driver)
}

/// Takes `offer` as `policy` says, once [`check_offer`] passes it on
/// `network` and the Nexus of `nexus_genesis` at the fee floors, and
/// `nex_address` is a Nexus address: dials the seller, or reaches it
/// through the offer's relay, asks for the policy's amount, and starts the
/// buyer on the terms the seller fixes, once they are the ones asked for,
/// refunding to `refund` and paid the NEX at `nex_address`.
#[allow(clippy::too_many_arguments)]
pub fn take<B: Bitcoin>(
    offer: Offer,
    policy: &Policy,
    network: Network,
    nexus_genesis: &str,
    btc_fee_floor: u64,
    nex_fee_floor: u64,
    refund: ScriptBuf,
    nex_address: String,
    bitcoin: B,
    nexus: Client,
    store: Store,
) -> Result<Driver<Buyer, B, Session>> {
    check_nex_address(&nex_address)?;
    check_offer(
        &offer,
        policy,
        network,
        nexus_genesis,
        btc_fee_floor,
        nex_fee_floor,
    )?;
    let config = ivy::Config::new(SigningKey::from_bytes(&offer.buyer_session));
    let seller = offer.seller_key()?;
    let mut transport: Session = match offer.place()? {
        Place::Address(address) => Box::new(Ivy::connect(address, &config, seller, TIMEOUT)?),
        Place::Relay(relay) => {
            let id = hex::encode(offer.template.swap_id);
            Box::new(Ivy::<Relayed>::connect_relayed(
                &relay, &id, &config, seller, TIMEOUT,
            )?)
        }
    };
    let terms = request_terms(&mut transport, &offer, policy)?;
    let (buyer, actions) = Buyer::start(terms, refund, nex_address)
        .map_err(|refusal| format!("refused: {refusal:?}"))?;
    let rejoin = SessionFile {
        offer,
        key: None,
        listen: None,
    };
    start(
        buyer,
        actions,
        bitcoin,
        nexus,
        nexus_genesis,
        transport,
        store,
        rejoin,
        None,
    )
}

/// A driver carrying on the swap saved in `store`, from where it stopped
/// ([`Machine::resumed`]). While the swap still needs its session, it
/// meets the counterparty again by what was saved beside the swap file;
/// without that, or if the seller cannot listen where it did, the swap
/// goes on from the chains alone.
pub fn resume<M: Machine, B: Bitcoin>(
    bitcoin: B,
    nexus: Client,
    store: Store,
) -> io::Result<Driver<M, B, Session>> {
    resume_through(bitcoin, nexus, store, None)
}

/// [`resume`], meeting the counterparty again on the relay at `relay`, if
/// given ([`SessionFile::through`]).
pub fn resume_through<M: Machine, B: Bitcoin>(
    bitcoin: B,
    nexus: Client,
    store: Store,
    relay: Option<String>,
) -> io::Result<Driver<M, B, Session>> {
    let rejoin = SessionFile::load(&store).map(|rejoin| rejoin.map(|rejoin| rejoin.through(relay)));
    let mut driver = Driver::<M, B, Session>::resume(bitcoin, nexus, None, store)?;
    if driver.state().rejoin().is_some() {
        driver.reconnect = reconnect(rejoin);
    }
    Ok(driver)
}

fn reconnect(rejoin: Result<Option<SessionFile>>) -> Option<Reconnect<Session>> {
    let rejoin = rejoin.and_then(|rejoin| match rejoin {
        Some(rejoin) => rejoin.reconnect(None).map(Some),
        None => Ok(None),
    });
    match rejoin {
        Ok(Some(reconnect)) => Some(reconnect),
        Ok(None) => {
            log("no session file: the swap goes on from the chains");
            None
        }
        Err(e) => {
            log(&format!(
                "cannot rejoin, the swap goes on from the chains: {e}"
            ));
            None
        }
    }
}

/// Why the node `client` asks is no node to trade on the Nexus of
/// `genesis` through, if it is not, as [`check_node`](rpc::parse::check_node)
/// says: one on another Nexus, where a NEX lock is worthless; then one that
/// cannot say how deep a transaction is. It works that out from past blocks
/// and the state after them, which a node run with `--state tip` or `none`,
/// or `--block-bodies none`, does not keep: every NEX lock would look
/// unmined, and every claim drained. Its read of an account after the block
/// halfway up the chain shows whether it keeps that state; a chain too
/// short to tell passes.
pub fn check_nexus(
    client: &Client,
    genesis: &str,
) -> rpc::Result<std::result::Result<(), NodeRefusal>> {
    use swap_nexus_tx::rpc::parse::{check_node, past_state_probe};
    let chain_info = client.chain_info()?;
    let height = client.health()?.height;
    let past_state = match past_state_probe(height) {
        None => None,
        Some(at) => Some(match client.block_hash(at)? {
            Some(block) => client
                .account_at(&swap_nexus_tx::address(&[0; 32]), &block)?
                .is_some(),
            None => false,
        }),
    };
    Ok(check_node(genesis, &chain_info, height, past_state))
}

/// A [`Driver::nexus_check`] for a swap resumed: asks `check`, such as
/// [`check_nexus`] made an error, until it passes once, and nothing after.
pub fn check_once(mut check: impl FnMut(&Client) -> Result<()> + Send + 'static) -> NexusCheck {
    let mut passed = false;
    Box::new(move |client| {
        if !passed {
            check(client).map_err(|e| e.to_string())?;
            passed = true;
        }
        Ok(())
    })
}

/// A Nexus address as Lattice prints one: a CIDv1, dag-cbor, sha2-256, in
/// lowercase base32. NEX paid to anything else is lost.
pub fn check_nex_address(text: &str) -> Result<()> {
    if !swap_nexus_tx::is_cid(text) {
        return Err(format!("{text} is not a Nexus address").into());
    }
    Ok(())
}

/// A swap file as the driver saved it.
pub enum Saved {
    Seller(Seller),
    Buyer(Buyer),
}

impl Saved {
    /// Both machines have `ClaimingNex` and `Done`. A claim names its side;
    /// a swap that is done no longer needs one. Fails on a file of another
    /// state version, as the driver would.
    pub fn load(store: &Store) -> Result<Self> {
        let path = store.path();
        let value = match store.load_value() {
            Ok(Some(value)) => value,
            Ok(None) => return Err(format!("{}: no such swap file", path.display()).into()),
            // Names the file and the versions.
            Err(e) if e.kind() == io::ErrorKind::InvalidData => return Err(e.into()),
            Err(e) => return Err(format!("{}: {e}", path.display()).into()),
        };
        if value["ClaimingNex"]["setup"]["side"] != "Buyer" {
            if let Ok(seller) = serde_json::from_value(value.clone()) {
                return Ok(Saved::Seller(seller));
            }
        }
        let buyer = serde_json::from_value(value)
            .map_err(|e| format!("{} is not a swap file: {e}", path.display()))?;
        Ok(Saved::Buyer(buyer))
    }

    /// The Nexus the swap trades on, until it ends.
    pub fn nexus_genesis(&self) -> Option<&str> {
        let terms = match self {
            Saved::Seller(seller) => seller.terms(),
            Saved::Buyer(buyer) => buyer.terms(),
        };
        terms.map(|terms| terms.nexus_genesis.as_str())
    }
}

/// The store a swap file belongs to: the driver names each by its swap id.
pub fn swap_store(path: &Path) -> Result<Store> {
    let swap_id = path
        .file_stem()
        .filter(|_| path.extension().is_some_and(|e| e == "json"))
        .and_then(|stem| hex::decode(stem.to_str()?).ok())
        .and_then(|bytes| <[u8; 32]>::try_from(bytes).ok())
        .ok_or_else(|| format!("{} is not named <swap id>.json", path.display()))?;
    let directory = match path.parent() {
        Some(parent) if !parent.as_os_str().is_empty() => parent,
        _ => Path::new("."),
    };
    Ok(Store::new(directory, swap_id))
}

/// The name of a machine's state: its variant.
pub fn state_name<M: Machine>(state: &M) -> String {
    match serde_json::to_value(state) {
        Ok(Value::Object(map)) => map.keys().next().cloned().unwrap_or_default(),
        Ok(Value::String(name)) => name,
        _ => String::new(),
    }
}

fn log(what: &str) {
    eprintln!("lattice-swap: {what}");
}
