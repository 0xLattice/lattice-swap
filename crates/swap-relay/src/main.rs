//! `swap-relay`: the relay lattice-swap parties can meet through.

use std::net::SocketAddr;
use std::process::ExitCode;
use std::sync::Arc;

use clap::Parser;
use swap_relay::board::Board;
use swap_relay::Relay;

#[derive(Parser)]
#[command(name = "swap-relay", version, about = "A relay for lattice-swap")]
struct Args {
    /// Where to listen.
    #[arg(long, default_value = "127.0.0.1:7500")]
    listen: SocketAddr,
    /// The most sellers held at once, their offers listed or swapping: each
    /// holds a connection, and its offer is kept in memory.
    #[arg(long, default_value_t = 10_000)]
    max_offers: usize,
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
    let relay = Arc::new(Relay {
        board: Board::new(args.max_offers),
    });
    let runtime = tokio::runtime::Runtime::new()?;
    runtime.block_on(async {
        let listener = tokio::net::TcpListener::bind(args.listen).await?;
        eprintln!("swap-relay: listening on {}", listener.local_addr()?);
        swap_relay::serve(listener, relay).await
    })?;
    Ok(())
}
