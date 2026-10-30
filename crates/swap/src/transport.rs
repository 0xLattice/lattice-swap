//! How the parties talk: any [`Transport`], here an ivy session.

use std::io;
use std::net::SocketAddr;
use std::time::{Duration, Instant};

use ivy::{Config, Connection};
pub use ivy_core::PeerKey;
use tokio::net::TcpStream;
use tokio::runtime::Runtime;
use tokio::time::timeout;

use crate::TOPIC;

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

    /// Takes the next connection on `listener` and accepts it only from
    /// `peer`. Waits at most `wait` for it.
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
            let (stream, _) = timeout(wait, listener.accept())
                .await
                .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "no peer dialed"))??;
            ivy::accept(stream, config, |key| *key == peer).await
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
