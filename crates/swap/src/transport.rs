//! How the parties talk: any [`Transport`], here an ivy session, over TCP
//! or over a relay's WebSocket.

use std::future::{poll_fn, Future};
use std::io;
use std::net::{IpAddr, SocketAddr};
use std::pin::{pin, Pin};
use std::task::{Context, Poll};
use std::time::{Duration, Instant};

use futures_util::{Sink, Stream};
use ivy::{Config, Connection};
use ivy_core::Message as Record;
pub use ivy_core::PeerKey;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::net::TcpStream;
use tokio::runtime::Runtime;
use tokio::time::{sleep, timeout};
use tokio_tungstenite::tungstenite::{self, Message as Frame};
use tokio_tungstenite::{MaybeTlsStream, WebSocketStream};

use crate::{Rejoin, TOPIC};

/// The most handshakes [`Ivy::accept`] runs at once.
pub const HANDSHAKES: usize = 64;
/// The most of them from one [`source`].
pub const PER_SOURCE: usize = 4;
/// How long [`Ivy::accept`] waits after a failed accept.
pub const ACCEPT_PAUSE: Duration = Duration::from_millis(100);

/// An authenticated channel to the counterparty. Every call has a
/// deadline.
pub trait Transport {
    fn send(&mut self, payload: &[u8]) -> io::Result<()>;
    /// The next payload, or `None` if none arrives within `wait`.
    fn recv(&mut self, wait: Duration) -> io::Result<Option<Vec<u8>>>;
}

/// A session of either kind, as one driver's.
impl<T: Transport + ?Sized> Transport for Box<T> {
    fn send(&mut self, payload: &[u8]) -> io::Result<()> {
        (**self).send(payload)
    }

    fn recv(&mut self, wait: Duration) -> io::Result<Option<Vec<u8>>> {
        (**self).recv(wait)
    }
}

/// How often an [`Ivy`] session pings the counterparty.
pub const PING: Duration = Duration::from_secs(15);
/// How many pings in a row may go unanswered before an [`Ivy`] session
/// counts as lost: as OpenSSH's `ServerAliveInterval` and its default
/// `ServerAliveCountMax`.
pub const PINGS_MISSED: u32 = 3;
/// The most messages an [`Ivy`] session holds that [`Ivy::recv`] has not
/// taken: past them it stops reading, so a peer that floods it costs it
/// no more.
pub const INBOX: usize = 16;

/// An ivy session over TCP, or over a relay's WebSocket ([`Relayed`]),
/// for the blocking driver. Messages on other topics are skipped.
///
/// The session runs on a thread of its own, which reads it all the time:
/// it answers the counterparty's pings, and holds what arrives for
/// [`Ivy::recv`], however long the driver is busy elsewhere, a slow node
/// among it, as libp2p's swarm answers pings apart from the application in
/// eigenwallet. It pings the counterparty every [`PING`], and ends the
/// session once [`PINGS_MISSED`] pings in a row go unanswered: one whose
/// other end is gone without a word, a laptop asleep or a NAT that forgot
/// it, reads as quiet and not as closed, and only a keepalive tells the two
/// apart. The next call then fails, and so does every one after.
pub struct Ivy<S = TcpStream> {
    commands: tokio::sync::mpsc::UnboundedSender<Command>,
    inbox: std::sync::mpsc::Receiver<io::Result<Vec<u8>>>,
    send_timeout: Duration,
    _stream: std::marker::PhantomData<fn() -> S>,
}

enum Command {
    /// A payload, where to say how its send went, and when [`Ivy::send`]
    /// gives up on it: it is written by then or never.
    Send(
        Vec<u8>,
        std::sync::mpsc::Sender<io::Result<()>>,
        std::time::Instant,
    ),
    Ping(Duration),
}

impl<S: AsyncRead + AsyncWrite + Unpin + Send + 'static> Ivy<S> {
    /// Hands `connection`, with `runtime`, whose reactor it is on, to the
    /// session's own thread.
    fn new(
        runtime: Runtime,
        connection: Connection<S>,
        send_timeout: Duration,
    ) -> io::Result<Self> {
        let (commands, received) = tokio::sync::mpsc::unbounded_channel();
        let (deliver, inbox) = std::sync::mpsc::sync_channel(INBOX);
        std::thread::Builder::new().spawn(move || {
            let ended = runtime.block_on(serve(connection, received, &deliver, send_timeout));
            // Told last: the driver may be busy, and nothing else waits.
            if let Err(e) = ended {
                _ = deliver.send(Err(e));
            }
        })?;
        Ok(Self {
            commands,
            inbox,
            send_timeout,
            _stream: std::marker::PhantomData,
        })
    }

    /// Pings every `ping` instead of every [`PING`], for the tests.
    pub fn set_ping(&mut self, ping: Duration) {
        _ = self.commands.send(Command::Ping(ping));
    }
}

/// Runs the session until it fails, or until its [`Ivy`] is dropped.
async fn serve<S: AsyncRead + AsyncWrite + Unpin>(
    mut connection: Connection<S>,
    mut commands: tokio::sync::mpsc::UnboundedReceiver<Command>,
    deliver: &std::sync::mpsc::SyncSender<io::Result<Vec<u8>>>,
    send_timeout: Duration,
) -> io::Result<()> {
    let mut ping = PING;
    let mut pinged = tokio::time::Instant::now();
    // Since when a ping has gone out with nothing heard after it.
    let mut unanswered: Option<tokio::time::Instant> = None;
    loop {
        tokio::select! {
            command = commands.recv() => match command {
                None => return Ok(()),
                Some(Command::Ping(every)) => ping = every,
                Some(Command::Send(payload, done, deadline)) => {
                    let deadline = tokio::time::Instant::from_std(deadline);
                    // Never begun past its deadline, so nothing is written
                    // once its caller has been told it failed; one cut off
                    // ends the session, which would finish writing it.
                    let sent = if tokio::time::Instant::now() >= deadline {
                        Err(timed_out("send timed out"))
                    } else {
                        tokio::time::timeout_at(deadline, connection.send(TOPIC, &payload))
                            .await
                            .unwrap_or_else(|_| Err(timed_out("send timed out")))
                    };
                    let failed = sent.as_ref().err().map(|e| io::Error::new(e.kind(), e.to_string()));
                    _ = done.send(sent);
                    if let Some(e) = failed {
                        return Err(e);
                    }
                }
            },
            // Cancel-safe: a message cut off is kept for the next call.
            message = connection.recv_message() => {
                unanswered = None;
                let Record::PeerMessage { topic, payload } = message? else {
                    continue;
                };
                if topic != TOPIC {
                    continue;
                }
                let mut held = Ok(payload);
                loop {
                    match deliver.try_send(held) {
                        Ok(()) => break,
                        // A full inbox stalls pings and sends too: only a
                        // peer that floods it gets here, and it may lose
                        // the session it floods.
                        Err(std::sync::mpsc::TrySendError::Full(again)) => {
                            held = again;
                            sleep(Duration::from_millis(10)).await;
                        }
                        Err(std::sync::mpsc::TrySendError::Disconnected(_)) => return Ok(()),
                    }
                }
            }
            () = tokio::time::sleep_until(pinged + ping) => {
                if unanswered.is_some_and(|since| since.elapsed() >= ping * PINGS_MISSED) {
                    return Err(timed_out("the counterparty stopped answering"));
                }
                timeout(send_timeout, connection.send_message(&Record::Ping(0)))
                    .await
                    .map_err(|_| timed_out("a ping timed out"))??;
                pinged = tokio::time::Instant::now();
                unanswered.get_or_insert(pinged);
            }
        }
    }
}

impl Ivy {
    /// Dials `address`, which must hold `peer`'s key.
    pub fn connect(
        address: SocketAddr,
        config: &Config,
        peer: PeerKey,
        send_timeout: Duration,
    ) -> io::Result<Self> {
        let runtime = runtime()?;
        let connection = runtime.block_on(async {
            let stream = timeout(send_timeout, TcpStream::connect(address))
                .await
                .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "connect timed out"))??;
            ivy::connect(stream, config, peer).await
        })?;
        Self::new(runtime, connection, send_timeout)
    }

    /// Takes connections on `listener` until one completes the handshake
    /// as `peer`, dropping any other. Waits at most `wait` in all, and each
    /// handshake at most `send_timeout`. Handshakes run side by side, at
    /// most [`PER_SOURCE`] from one source and [`HANDSHAKES`] in all; a
    /// connection beyond them evicts the oldest, from its own source while
    /// that one is full, so a flood from one source cannot push out
    /// another's. A failed accept, such as one out of file descriptors, is
    /// logged, and accepting goes on after [`ACCEPT_PAUSE`].
    pub fn accept(
        listener: std::net::TcpListener,
        config: &Config,
        peer: PeerKey,
        wait: Duration,
        send_timeout: Duration,
    ) -> io::Result<Self> {
        let runtime = runtime()?;
        listener.set_nonblocking(true)?;
        let connection = runtime.block_on(async {
            let listener = tokio::net::TcpListener::from_std(listener)?;
            let mut expired = pin!(sleep(wait));
            // Oldest first, each with its source.
            let mut handshakes: Vec<(IpAddr, Pin<Box<_>>)> = Vec::new();
            let mut paused: Option<Pin<Box<tokio::time::Sleep>>> = None;
            poll_fn(|cx| {
                loop {
                    if let Some(pause) = &mut paused {
                        if pause.as_mut().poll(cx).is_pending() {
                            break;
                        }
                        paused = None;
                    }
                    let (stream, from) = match listener.poll_accept(cx) {
                        Poll::Pending => break,
                        Poll::Ready(Ok(accepted)) => accepted,
                        // It may fail again at once, as while out of file
                        // descriptors: pause rather than spin.
                        Poll::Ready(Err(e)) => {
                            eprintln!("lattice-swap: accept: {e}");
                            paused = Some(Box::pin(sleep(ACCEPT_PAUSE)));
                            continue;
                        }
                    };
                    let from = source(from.ip());
                    let sources: Vec<_> = handshakes.iter().map(|(from, _)| *from).collect();
                    if let Some(i) = evicted(&sources, from) {
                        drop(handshakes.remove(i));
                    }
                    let accept = ivy::accept(stream, config, move |key| *key == peer);
                    handshakes.push((from, Box::pin(timeout(send_timeout, accept))));
                }
                let mut i = 0;
                while i < handshakes.len() {
                    match handshakes[i].1.as_mut().poll(cx) {
                        Poll::Ready(Ok(Ok(connection))) => return Poll::Ready(Ok(connection)),
                        Poll::Ready(_) => drop(handshakes.remove(i)),
                        Poll::Pending => i += 1,
                    }
                }
                expired
                    .as_mut()
                    .poll(cx)
                    .map(|()| Err(io::Error::new(io::ErrorKind::TimedOut, "no peer dialed")))
            })
            .await
        })?;
        Self::new(runtime, connection, send_timeout)
    }
}

/// Where a connection comes from, for [`PER_SOURCE`]: its IPv4 address,
/// or its IPv6 /64, which one host commonly holds whole.
pub(crate) fn source(ip: IpAddr) -> IpAddr {
    match ip.to_canonical() {
        IpAddr::V6(ip) => IpAddr::V6((u128::from(ip) & !(u128::MAX >> 64)).into()),
        ip => ip,
    }
}

/// Which pending handshake, of `sources` oldest first, a new one from
/// `from` evicts: the oldest from `from` if it has [`PER_SOURCE`], or else
/// the oldest of all if there are [`HANDSHAKES`].
pub(crate) fn evicted(sources: &[IpAddr], from: IpAddr) -> Option<usize> {
    if sources.iter().filter(|s| **s == from).count() >= PER_SOURCE {
        return sources.iter().position(|s| *s == from);
    }
    (sources.len() >= HANDSHAKES).then_some(0)
}

fn runtime() -> io::Result<Runtime> {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
}

impl<S> Transport for Ivy<S> {
    fn send(&mut self, payload: &[u8]) -> io::Result<()> {
        let (done, sent) = std::sync::mpsc::channel();
        let deadline = Instant::now() + self.send_timeout;
        self.commands
            .send(Command::Send(payload.to_vec(), done, deadline))
            .map_err(|_| ended())?;
        // The session's own deadline comes first.
        match sent.recv_timeout(self.send_timeout + Duration::from_secs(1)) {
            Ok(sent) => sent,
            Err(std::sync::mpsc::RecvTimeoutError::Timeout) => Err(timed_out("send timed out")),
            Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => Err(ended()),
        }
    }

    fn recv(&mut self, wait: Duration) -> io::Result<Option<Vec<u8>>> {
        match self.inbox.recv_timeout(wait) {
            Ok(received) => received.map(Some),
            Err(std::sync::mpsc::RecvTimeoutError::Timeout) => Ok(None),
            Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => Err(ended()),
        }
    }
}

fn ended() -> io::Error {
    io::Error::new(io::ErrorKind::ConnectionAborted, "the session ended")
}

/// The most bytes [`Relayed`] puts in one WebSocket message. A relay holds
/// a message whole while it passes it on, so this is what one costs it.
pub const RELAY_CHUNK: usize = 64 * 1024;

/// A relay's WebSocket as a byte stream: what is written goes out as binary
/// messages of at most [`RELAY_CHUNK`] bytes, and what arrives in them is
/// read back in order. The relay pipes them to the other party, so the ivy
/// session runs end to end through it: the relay sees only ciphertext, and
/// each side authenticates the other's key.
pub struct Relayed {
    socket: WebSocketStream<MaybeTlsStream<TcpStream>>,
    /// Received and not yet read.
    inbound: Vec<u8>,
    read_from: usize,
}

impl Ivy<Relayed> {
    /// Lists `offer` on the relay at `relay`, an `http://` or `https://`
    /// URL, and waits, at most `wait` in all, for a buyer the relay pairs
    /// with it to complete the handshake as `peer`, each handshake within
    /// `send_timeout`. A pairing that fails the handshake is dropped and the
    /// offer listed again, as [`Ivy::accept`] drops a stranger. Fails if the
    /// relay refuses the offer.
    pub fn accept_relayed(
        relay: &str,
        offer: &str,
        config: &Config,
        peer: PeerKey,
        wait: Duration,
        send_timeout: Duration,
    ) -> io::Result<Self> {
        Self::accept_relayed_on(&[(relay, offer)], config, peer, wait, send_timeout)
            .map(|(_, session)| session)
    }

    /// As [`Ivy::accept_relayed`], on several relays at once: `listings`
    /// names each relay and the offer listed there. The first relay to pair
    /// a buyer wins, and the others' connections are closed at once, which
    /// withdraws the offer from their boards: the seller has one swap to
    /// run, so a second buyer must not take it elsewhere meanwhile. A
    /// pairing that fails the handshake lists the offer on every relay
    /// again, those that failed before among them. A relay that is down,
    /// refuses the offer or drops its connection is logged and left out
    /// until then; fails only once every relay has. Returns which of
    /// `listings` the buyer came through, where the two meet again.
    pub fn accept_relayed_on(
        listings: &[(&str, &str)],
        config: &Config,
        peer: PeerKey,
        wait: Duration,
        send_timeout: Duration,
    ) -> io::Result<(usize, Self)> {
        let runtime = runtime()?;
        let urls = listings
            .iter()
            .map(|(relay, _)| relay_url(relay, "sell"))
            .collect::<io::Result<Vec<_>>>()?;
        let (taken, connection) = runtime.block_on(async {
            let deadline = tokio::time::Instant::now() + wait;
            loop {
                // Each relay's listing, with its index, until it pairs.
                let mut listed: Vec<(usize, Pin<Box<_>>)> = (urls.iter().zip(listings))
                    .map(|(url, (_, offer))| Box::pin(list(url, offer, send_timeout)))
                    .enumerate()
                    .collect();
                let paired = poll_fn(|cx| {
                    let mut i = 0;
                    while i < listed.len() {
                        match listed[i].1.as_mut().poll(cx) {
                            Poll::Pending => i += 1,
                            Poll::Ready(Ok(socket)) => {
                                return Poll::Ready(Ok((listed[i].0, socket)))
                            }
                            Poll::Ready(Err(e)) if listed.len() == 1 => return Poll::Ready(Err(e)),
                            Poll::Ready(Err(e)) => {
                                let relay = listings[listed[i].0].0;
                                eprintln!("lattice-swap: not listed on {relay}: {e}");
                                drop(listed.remove(i));
                            }
                        }
                    }
                    Poll::Pending
                });
                let (taken, socket) = tokio::time::timeout_at(deadline, paired)
                    .await
                    .map_err(|_| timed_out("no peer dialed"))??;
                // Withdrawn from the other boards for the handshake.
                drop(listed);
                let accept = ivy::accept(Relayed::new(socket), config, |key| *key == peer);
                match timeout(send_timeout, accept).await {
                    Ok(Ok(connection)) => return io::Result::Ok((taken, connection)),
                    Ok(Err(e)) => eprintln!("lattice-swap: a relayed handshake failed: {e}"),
                    Err(_) => eprintln!("lattice-swap: a relayed handshake timed out"),
                }
            }
        })?;
        Ok((taken, Self::new(runtime, connection, send_timeout)?))
    }

    /// Asks the relay at `relay` to pair this party with the seller that
    /// listed offer `id` there, which must hold `peer`'s key.
    pub fn connect_relayed(
        relay: &str,
        id: &str,
        config: &Config,
        peer: PeerKey,
        send_timeout: Duration,
    ) -> io::Result<Self> {
        let runtime = runtime()?;
        let url = relay_url(relay, &format!("take/{id}"))?;
        let connection = runtime.block_on(async {
            let socket = dial(&url, send_timeout).await?;
            ivy::connect(Relayed::new(socket), config, peer).await
        })?;
        Self::new(runtime, connection, send_timeout)
    }

    /// Meets the buyer at rendezvous `id` on the relay at `relay`
    /// ([`Machine::rejoin`]), waiting there at most `wait`, and completes the
    /// handshake as [`Ivy::accept_relayed`] does.
    ///
    /// [`Machine::rejoin`]: crate::Machine::rejoin
    pub fn accept_rejoined(
        relay: &str,
        id: [u8; 32],
        config: &Config,
        peer: PeerKey,
        wait: Duration,
        send_timeout: Duration,
    ) -> io::Result<Self> {
        let runtime = runtime()?;
        let connection = runtime.block_on(async {
            let socket = meet(relay, id, wait, send_timeout).await?;
            let accept = ivy::accept(Relayed::new(socket), config, |key| *key == peer);
            timeout(send_timeout, accept)
                .await
                .map_err(|_| timed_out("the handshake timed out"))?
        })?;
        Self::new(runtime, connection, send_timeout)
    }

    /// Meets the seller, which must hold `peer`'s key, at rendezvous `id`
    /// on the relay at `relay`, waiting there at most `wait`.
    pub fn connect_rejoined(
        relay: &str,
        id: [u8; 32],
        config: &Config,
        peer: PeerKey,
        wait: Duration,
        send_timeout: Duration,
    ) -> io::Result<Self> {
        let runtime = runtime()?;
        let connection = runtime.block_on(async {
            let socket = meet(relay, id, wait, send_timeout).await?;
            let connect = ivy::connect(Relayed::new(socket), config, peer);
            timeout(send_timeout, connect)
                .await
                .map_err(|_| timed_out("the handshake timed out"))?
        })?;
        Self::new(runtime, connection, send_timeout)
    }
}

/// The relay's socket at `url`, its `/sell`, once it has listed `offer`
/// and paired a buyer with it.
async fn list(
    url: &str,
    offer: &str,
    send_timeout: Duration,
) -> io::Result<WebSocketStream<MaybeTlsStream<TcpStream>>> {
    let mut socket = dial(url, send_timeout).await?;
    send_text(&mut socket, offer).await?;
    match timeout(send_timeout, text(&mut socket)).await {
        Err(_) => Err(timed_out("the relay did not answer")),
        Ok(Ok(reply)) if reply == "listed" => Ok(()),
        Ok(Ok(reply)) => Err(io::Error::other(format!("the relay: {reply}"))),
        Ok(Err(e)) => Err(e),
    }?;
    match text(&mut socket).await? {
        reply if reply == "paired" => Ok(socket),
        reply => Err(io::Error::other(format!("the relay: {reply}"))),
    }
}

/// The relay's socket at rendezvous `id`, once the other party has come.
async fn meet(
    relay: &str,
    id: [u8; 32],
    wait: Duration,
    send_timeout: Duration,
) -> io::Result<WebSocketStream<MaybeTlsStream<TcpStream>>> {
    let url = relay_url(relay, &format!("rejoin/{}", hex::encode(id)))?;
    let mut socket = dial(&url, send_timeout).await?;
    match timeout(wait, text(&mut socket)).await {
        Err(_) => Err(timed_out("the counterparty did not come")),
        Ok(Ok(reply)) if reply == "paired" => Ok(socket),
        Ok(Ok(reply)) => Err(io::Error::other(format!("the relay: {reply}"))),
        Ok(Err(e)) => Err(e),
    }
}

/// How long [`in_background`] waits after a failed attempt.
pub const RETRY: Duration = Duration::from_secs(5);

/// `connect`, which opens a session given how to meet ([`Rejoin`]) and may
/// block, as [`Driver::reconnect`] takes it: on its own thread, one attempt
/// at a time and the next [`RETRY`] after a failure, so the driver goes on
/// watching the chains meanwhile.
///
/// [`Driver::reconnect`]: crate::driver::Driver::reconnect
pub fn in_background<T: Send + 'static>(
    connect: impl Fn(&Rejoin) -> io::Result<T> + Send + Sync + 'static,
) -> crate::driver::Reconnect<T> {
    let connect = std::sync::Arc::new(connect);
    let mut attempt: Option<std::thread::JoinHandle<io::Result<T>>> = None;
    let mut failed: Option<Instant> = None;
    Box::new(move |rejoin| {
        if let Some(done) = attempt.take_if(|a| a.is_finished()) {
            let result = done
                .join()
                .unwrap_or_else(|_| Err(io::Error::other("the attempt panicked")));
            failed = result.is_err().then(Instant::now);
            return Some(result);
        }
        if attempt.is_some() || failed.is_some_and(|at| at.elapsed() < RETRY) {
            return None;
        }
        let (connect, rejoin) = (connect.clone(), rejoin.clone());
        attempt = Some(std::thread::spawn(move || connect(&rejoin)));
        None
    })
}

/// `path` at the relay at `relay`, as a WebSocket URL.
pub fn relay_url(relay: &str, path: &str) -> io::Result<String> {
    let relay = relay.trim_end_matches('/');
    let socket = if let Some(rest) = relay.strip_prefix("https://") {
        format!("wss://{rest}")
    } else if let Some(rest) = relay.strip_prefix("http://") {
        format!("ws://{rest}")
    } else {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("{relay} is not an http:// or https:// URL"),
        ));
    };
    Ok(format!("{socket}/{path}"))
}

fn timed_out(what: &str) -> io::Error {
    io::Error::new(io::ErrorKind::TimedOut, what)
}

async fn dial(
    url: &str,
    send_timeout: Duration,
) -> io::Result<WebSocketStream<MaybeTlsStream<TcpStream>>> {
    match timeout(send_timeout, tokio_tungstenite::connect_async(url)).await {
        Err(_) => Err(timed_out("the relay did not answer")),
        Ok(Ok((socket, _))) => Ok(socket),
        Ok(Err(tungstenite::Error::Http(response))) if response.status() == 404 => Err(
            io::Error::new(io::ErrorKind::NotFound, "the relay holds no such offer"),
        ),
        Ok(Err(e)) => Err(io::Error::other(format!("the relay: {e}"))),
    }
}

async fn send_text(
    socket: &mut WebSocketStream<MaybeTlsStream<TcpStream>>,
    text: &str,
) -> io::Result<()> {
    use futures_util::SinkExt;
    socket
        .send(Frame::text(text))
        .await
        .map_err(io::Error::other)
}

/// The relay's next word, skipping pings.
async fn text(socket: &mut WebSocketStream<MaybeTlsStream<TcpStream>>) -> io::Result<String> {
    use futures_util::StreamExt;
    loop {
        match socket.next().await {
            Some(Ok(Frame::Text(text))) => return Ok(text.to_string()),
            Some(Ok(Frame::Ping(_) | Frame::Pong(_))) => continue,
            Some(Ok(Frame::Close(Some(close)))) => {
                return Err(io::Error::other(format!("the relay: {}", close.reason)))
            }
            Some(Err(e)) => return Err(io::Error::other(e)),
            _ => {
                return Err(io::Error::new(
                    io::ErrorKind::ConnectionAborted,
                    "the relay closed the connection",
                ))
            }
        }
    }
}

impl Relayed {
    fn new(socket: WebSocketStream<MaybeTlsStream<TcpStream>>) -> Self {
        Self {
            socket,
            inbound: Vec::new(),
            read_from: 0,
        }
    }
}

impl AsyncRead for Relayed {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        while this.read_from == this.inbound.len() {
            match Pin::new(&mut this.socket).poll_next(cx) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(Some(Ok(Frame::Binary(bytes)))) => {
                    this.inbound = bytes.into();
                    this.read_from = 0;
                }
                // Pings are answered by the socket itself.
                Poll::Ready(Some(Ok(Frame::Ping(_) | Frame::Pong(_)))) => {}
                Poll::Ready(Some(Ok(Frame::Text(_) | Frame::Frame(_)))) => {
                    return Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "the relay sent text in the session",
                    )))
                }
                // The end of the stream.
                Poll::Ready(None | Some(Ok(Frame::Close(_)))) => return Poll::Ready(Ok(())),
                Poll::Ready(Some(Err(e))) => return Poll::Ready(Err(io::Error::other(e))),
            }
        }
        let n = buf.remaining().min(this.inbound.len() - this.read_from);
        buf.put_slice(&this.inbound[this.read_from..this.read_from + n]);
        this.read_from += n;
        Poll::Ready(Ok(()))
    }
}

impl AsyncWrite for Relayed {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let socket = &mut self.get_mut().socket;
        if let Err(e) = std::task::ready!(Pin::new(&mut *socket).poll_ready(cx)) {
            return Poll::Ready(Err(io::Error::other(e)));
        }
        let n = buf.len().min(RELAY_CHUNK);
        let frame = Frame::binary(buf[..n].to_vec());
        Poll::Ready(
            Pin::new(socket)
                .start_send(frame)
                .map(|()| n)
                .map_err(io::Error::other),
        )
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().socket)
            .poll_flush(cx)
            .map_err(io::Error::other)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().socket)
            .poll_close(cx)
            .map_err(io::Error::other)
    }
}
