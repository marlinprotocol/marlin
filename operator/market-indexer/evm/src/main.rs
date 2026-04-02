mod evm;

use std::time::Duration;

use anyhow::{Context, Result, anyhow};
use clap::Parser;
use diesel::Connection;
use diesel::PgConnection;
use std::thread::sleep;
use tracing::{error, warn};
use tracing_subscriber::EnvFilter;
use tracing_subscriber::filter::LevelFilter;

use evm::EvmProvider;

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    /// RPC URL
    #[arg(short, long)]
    rpc: String,

    /// Market contract address
    #[arg(short, long)]
    contract: String,

    /// Provider address
    #[arg(short, long)]
    provider: String,

    /// Start block for log parsing
    #[arg(short, long)]
    start_block: Option<u64>,

    /// Size of block range for fetching logs
    #[arg(long, default_value = "500")]
    range_size: u64,
}

fn run() -> Result<()> {
    let args = Args::parse();

    let database_url = std::env::var("DATABASE_URL").context("DATABASE_URL must be set")?;
    let mut conn = PgConnection::establish(&database_url)
        .map_err(|_| anyhow!("Error connecting to {}", database_url))?;

    let mut rpc_client = EvmProvider {
        rpc_url: args
            .rpc
            .parse()
            .context("Failed to parse provided RPC URL")?,
        contract: args
            .contract
            .parse()
            .context("Failed to parse contract into ethereum address")?,
        rt: tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()?
            .into(),
    };

    loop {
        let res = indexer_framework::run(
            &mut conn,
            &mut rpc_client,
            args.provider.clone(),
            args.start_block,
            args.range_size,
        );

        if let Err(e) = res {
            error!(error = %e, "Indexer error, retrying after delay");
            sleep(Duration::from_secs(30));
        } else {
            warn!("Indexer returned unexpectedly, restarting");
            sleep(Duration::from_secs(5));
        }
    }
}

fn main() -> Result<()> {
    let mut filter = EnvFilter::new("info");
    if let Ok(var) = std::env::var("RUST_LOG") {
        filter = filter.add_directive(
            var.parse()
                .context("Failed to parse the RUST_LOG value set in environment")?,
        );
    }
    tracing_subscriber::fmt()
        .with_max_level(LevelFilter::INFO)
        .with_env_filter(filter)
        .init();

    let _ = run().inspect_err(|e| error!(?e, "run error"));

    Ok(())
}
