use anyhow::Context;
use anyhow::Result;
use anyhow::anyhow;
use clap::Parser;
use diesel::Connection;
use diesel::PgConnection;
use diesel::RunQueryDsl;
use diesel_migrations::EmbeddedMigrations;
use diesel_migrations::MigrationHarness;
use diesel_migrations::embed_migrations;

use cvm_indexer::AlloyProvider;
use cvm_indexer::event_loop;
use cvm_indexer::start_from;
use tracing::debug;
use tracing::error;
use tracing::info;
use tracing_subscriber::EnvFilter;

#[derive(Parser, Debug)]
#[command(version, about, long_about = None)]
struct Args {
    /// RPC URL
    #[arg(short, long)]
    rpc: String,

    /// Market contract
    #[arg(short, long)]
    contract: String,

    /// Start block for log parsing
    #[arg(short, long)]
    start_block: u64,

    /// Size of block range for fetching logs
    #[arg(long, default_value = "2000")]
    range_size: u64,
}

pub const MIGRATIONS: EmbeddedMigrations = embed_migrations!("./migrations");

fn run() -> Result<()> {
    let args = Args::parse();

    let mut database_url = std::env::var("DATABASE_URL").context("DATABASE_URL must be set")?;
    if !database_url.contains("?") {
        database_url += "?";
    }
    if !database_url.ends_with('?') {
        database_url += "&";
    }
    if !database_url.contains("connect_timeout=") {
        database_url += "connect_timeout=5";
    }

    let mut conn = PgConnection::establish(&database_url)
        .map_err(|_| anyhow!("Error connecting to {}", database_url))?;
    diesel::sql_query(
        "
        SET statement_timeout = '5s';
        SET lock_timeout = '3s';
        SET idle_in_transaction_session_timeout = '10s';
        ",
    )
    .execute(&mut conn)
    .context("failed to set db timeouts")?;

    // apply pending migrations
    info!("Applying pending migrations");
    conn.run_pending_migrations(MIGRATIONS)
        // error is not sized, pain to handle the usual way
        .expect("failed to apply migrations");
    info!("Applied pending migrations");

    let mut provider = AlloyProvider {
        url: args.rpc.parse()?,
        contract: args.contract.parse()?,
        rt: tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()?,
    };
    let is_start_set = start_from(&mut conn, args.start_block)?;
    debug!("is_start_set: {}", is_start_set);
    event_loop(&mut conn, &mut provider, args.range_size)
}

fn main() -> Result<()> {
    // seems messy, see if there is a better way
    let mut filter = EnvFilter::new("info");
    if let Ok(var) = std::env::var("RUST_LOG") {
        filter = filter.add_directive(var.parse()?);
    }
    tracing_subscriber::fmt()
        .with_max_level(tracing::Level::INFO)
        .with_env_filter(filter)
        .init();

    let _ = run().inspect_err(|e| error!(?e, "run error"));

    Ok(())
}
