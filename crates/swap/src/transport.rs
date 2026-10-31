//! How the parties talk: any [`Transport`], here an ivy session.

use std::future::{poll_fn, Future};
use std::io;
use std::net::{IpAddr, SocketAddr};
use std::pin::{pin, Pin};
use std::task::Poll;
use std::time::{Duration, Instant};

use ivy::{Config, Connection};
pub use ivy_core::PeerKey;
use tokio::net::TcpStream;
use tokio::runtime::Runtime;
use tokio::time::{sleep, timeout};

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

/// An ivy session over TCP, with its own single-threaded runtime so the
/// blocking driver can use it. Messages on other topics are skipped.
pub struct Ivy {
    runtime: Runtime,
    connection: Connection<TcpStream>,
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
            // Oldest first, with their sources.
            let mut sources = Vec::new();
            let mut handshakes = Vec::new();
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
                    if let Some(i) = evicted(&sources, from) {
                        sources.remove(i);
                        drop(handshakes.remove(i));
                    }
                    let accept = ivy::accept(stream, config, move |key| *key == peer);
                    sources.push(from);
                    handshakes.push(Box::pin(timeout(send_timeout, accept)));
                }
                let mut i = 0;
                while i < handshakes.len() {
                    match handshakes[i].as_mut().poll(cx) {
                        Poll::Ready(Ok(Ok(connection))) => return Poll::Ready(Ok(connection)),
                        Poll::Ready(_) => {
                            sources.remove(i);
                            drop(handshakes.remove(i));
                        }
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

impl Transport for Ivy {
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
