//! How the parties talk: any [`Transport`], here an ivy session.

use std::future::{poll_fn, Future};
use std::io;
use std::net::SocketAddr;
use std::pin::pin;
use std::task::Poll;
use std::time::{Duration, Instant};

use ivy::{Config, Connection};
pub use ivy_core::PeerKey;
use tokio::net::TcpStream;
use tokio::runtime::Runtime;
use tokio::time::{sleep_until, timeout, timeout_at};

use crate::TOPIC;

/// The most handshakes [`Ivy::accept`] runs at once.
pub const HANDSHAKES: usize = 16;

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
    /// most [`HANDSHAKES`] at once; a connection beyond them is dropped.
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
            let deadline = tokio::time::Instant::now() + wait;
            let mut expired = pin!(sleep_until(deadline));
            let mut handshakes = Vec::new();
            poll_fn(|cx| {
                while let Poll::Ready(accepted) = listener.poll_accept(cx) {
                    let (stream, _) = accepted?;
                    if handshakes.len() < HANDSHAKES {
                        let cap = deadline.min(tokio::time::Instant::now() + send_timeout);
                        let accept = ivy::accept(stream, config, move |key| *key == peer);
                        handshakes.push(Box::pin(timeout_at(cap, accept)));
                    }
                }
                let mut i = 0;
                while i < handshakes.len() {
                    match handshakes[i].as_mut().poll(cx) {
                        Poll::Ready(Ok(Ok(connection))) => return Poll::Ready(Ok(connection)),
                        Poll::Ready(_) => drop(handshakes.swap_remove(i)),
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
