//! `swap-relay`: the relay lattice-swap parties can meet through.

use std::net::SocketAddr;
use std::path::PathBuf;
use std::process::ExitCode;
use std::sync::Arc;
use std::time::Duration;

use bitcoin::Network;
use clap::Parser;
use swap_relay::board::Board;
use swap_relay::watch::{Chain, Esplora, Watchtower};
use swap_relay::Relay;

/// Bounds each Esplora request.
const ESPLORA_TIMEOUT: Duration = Duration::from_secs(30);

#[derive(Parser)]
#[command(name = "swap-relay", version, about = "A relay for lattice-swap")]
struct Args {
    /// Where to listen.
    #[arg(long, default_value = "127.0.0.1:7500")]
    listen: SocketAddr,
    /// The Bitcoin network the watchtower watches: bitcoin, testnet,
    /// testnet4, signet or regtest.
    #[arg(long, default_value_t = Network::Bitcoin)]
    network: Network,
    /// The Esplora API the watchtower reads Bitcoin from and broadcasts
    /// refunds to; mempool.space's for the network by default, none for
    /// regtest.
    #[arg(long)]
    esplora: Option<String>,
    /// The directory the watches are kept in, one file each.
    #[arg(long, default_value = "watches")]
    watches: PathBuf,
    /// Seconds between the watchtower's rounds over its watches.
    #[arg(long, default_value_t = 60)]
    poll: u64,
    /// The most sellers held at once, their offers listed or swapping: each
    /// holds a connection, and its offer is kept in memory.
    #[arg(long, default_value_t = 10_000)]
    max_offers: usize,
    /// The most watches held at once: each is kept in memory and on disk,
    /// and costs two or three Esplora requests a round.
    #[arg(long, default_value_t = 10_000)]
    max_watches: usize,
}

/// mempool.space's Esplora API for `network`.
fn mempool_space(network: Network) -> Option<&'static str> {
    match network {
        Network::Bitcoin => Some("https://mempool.space/api"),
        Network::Testnet => Some("https://mempool.space/testnet/api"),
        Network::Testnet4 => Some("https://mempool.space/testnet4/api"),
        Network::Signet => Some("https://mempool.space/signet/api"),
        _ => None,
    }
}

fn main() -> ExitCode {
    let args = Args::parse();
    match run(args) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("swap-relay: {e}");
            ExitCode::FAILURE
        }
    }
}

fn run(args: Args) -> Result<(), Box<dyn std::error::Error>> {
    let esplora = match &args.esplora {
        Some(url) => url.clone(),
        None => mempool_space(args.network)
            .ok_or_else(|| format!("give --esplora: there is no default for {}", args.network))?
            .to_string(),
    };
    let watchtower = Arc::new(Watchtower::open(
        args.network,
        &args.watches,
        args.max_watches,
    )?);
    eprintln!(
        "swap-relay: watching {} refunds on {} through {esplora}",
        watchtower.len(),
        args.network
    );
    let chain: Arc<dyn Chain> = Arc::new(Esplora::new(&esplora, ESPLORA_TIMEOUT));
    let (watcher, reader) = (watchtower.clone(), chain.clone());
    let every = Duration::from_secs(args.poll);
    std::thread::spawn(move || watcher.run(&*reader, every));

    let relay = Arc::new(Relay {
        board: Board::new(args.max_offers),
        watchtower,
        chain,
    });
    let runtime = tokio::runtime::Runtime::new()?;
    runtime.block_on(async {
        let listener = tokio::net::TcpListener::bind(args.listen).await?;
        eprintln!("swap-relay: listening on {}", listener.local_addr()?);
        swap_relay::serve(listener, relay).await
    })?;
    Ok(())
}
