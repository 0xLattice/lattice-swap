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
pub use ivy_core::PeerKey;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::net::TcpStream;
use tokio::runtime::Runtime;
use tokio::time::{sleep, timeout};
use tokio_tungstenite::tungstenite::{self, Message as Frame};
use tokio_tungstenite::{MaybeTlsStream, WebSocketStream};

use crate::TOPIC;

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

/// An ivy session over TCP, or over a relay's WebSocket ([`Relayed`]),
/// with its own single-threaded runtime so the blocking driver can use it.
/// Messages on other topics are skipped.
pub struct Ivy<S = TcpStream> {
    runtime: Runtime,
    connection: Connection<S>,
    send_timeout: Duration,
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
        Ok(Self {
            runtime,
            connection,
            send_timeout,
        })
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
        Ok(Self {
            runtime,
            connection,
            send_timeout,
        })
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

impl<S: AsyncRead + AsyncWrite + Unpin> Transport for Ivy<S> {
    fn send(&mut self, payload: &[u8]) -> io::Result<()> {
        // The timer is made inside the runtime, which drives it.
        let send = self.connection.send(TOPIC, payload);
        self.runtime
            .block_on(async { timeout(self.send_timeout, send).await })
            .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "send timed out"))?
    }

    fn recv(&mut self, wait: Duration) -> io::Result<Option<Vec<u8>>> {
        let deadline = Instant::now() + wait;
        loop {
            let left = deadline.saturating_duration_since(Instant::now());
            // `recv` is cancel-safe: a message cut off by the deadline is
            // kept for the next call.
            let recv = self.connection.recv();
            match self.runtime.block_on(async { timeout(left, recv).await }) {
                Err(_) => return Ok(None),
                Ok(Err(e)) => return Err(e),
                Ok(Ok((topic, payload))) if topic == TOPIC => return Ok(Some(payload)),
                Ok(Ok(_)) => continue,
            }
        }
    }
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
        let runtime = runtime()?;
        let url = relay_url(relay, "sell")?;
        let connection = runtime.block_on(async {
            let deadline = tokio::time::Instant::now() + wait;
            loop {
                let paired = async {
                    let mut socket = dial(&url, send_timeout).await?;
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
                };
                let socket = tokio::time::timeout_at(deadline, paired)
                    .await
                    .map_err(|_| timed_out("no peer dialed"))??;
                let accept = ivy::accept(Relayed::new(socket), config, |key| *key == peer);
                match timeout(send_timeout, accept).await {
                    Ok(Ok(connection)) => return io::Result::Ok(connection),
                    Ok(Err(e)) => eprintln!("lattice-swap: a relayed handshake failed: {e}"),
                    Err(_) => eprintln!("lattice-swap: a relayed handshake timed out"),
                }
            }
        })?;
        Ok(Self {
            runtime,
            connection,
            send_timeout,
        })
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
        Ok(Self {
            runtime,
            connection,
            send_timeout,
        })
    }
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
