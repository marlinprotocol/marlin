use std::fs;
use std::net::SocketAddr;

use anyhow::{Context, Result};
use clap::Parser;
use tracing::Instrument;
use tracing::{error, info, info_span};
use tracing_subscriber::EnvFilter;

use cp::aws;
use cp::market;
use cp::server;

#[derive(Parser)]
#[clap(author, version, about, long_about = None)]
/// Control plane for Oyster
struct Cli {
    /// AWS profile
    #[clap(long, value_parser)]
    profile: String,

    /// AWS keypair name
    #[clap(long, value_parser)]
    key_name: String,

    /// AWS regions
    #[clap(long, value_parser, default_value = "ap-south-1")]
    regions: String,

    /// Market DB url
    #[clap(long, value_parser)]
    db_url: String,

    /// Rates location
    #[clap(long, value_parser)]
    rates: String,

    /// Bandwidth Rates location
    #[clap(long, value_parser)]
    bandwidth: String,

    /// Chain id
    #[clap(long, value_parser)]
    chain_id: String,

    /// Contract address
    #[clap(long, value_parser)]
    contract: String,

    /// Provider address
    #[clap(long, value_parser)]
    provider: String,

    /// Blacklist location
    #[clap(long, value_parser, default_value = "")]
    blacklist: String,

    /// Whitelist location
    #[clap(long, value_parser, default_value = "")]
    whitelist: String,

    /// Address Blacklist location
    #[clap(long, value_parser, default_value = "")]
    address_blacklist: String,

    /// Address Whitelist location
    #[clap(long, value_parser, default_value = "")]
    address_whitelist: String,

    /// Metadata server port
    #[clap(long, value_parser, default_value = "8080")]
    port: u16,
}

async fn run() -> Result<()> {
    let cli = Cli::parse();

    info!(?cli.profile);
    info!(?cli.key_name);
    info!(?cli.db_url);
    info!(?cli.rates);
    info!(?cli.bandwidth);
    info!(?cli.contract);
    info!(?cli.provider);
    info!(?cli.blacklist);
    info!(?cli.whitelist);
    info!(?cli.address_blacklist);
    info!(?cli.address_whitelist);
    info!(?cli.port);

    let regions: Vec<String> = cli.regions.split(',').map(|r| r.into()).collect();

    let eif_whitelist = if !cli.whitelist.is_empty() {
        let eif_whitelist_vec: Vec<String> = parse_file(cli.whitelist)
            .await
            .context("Failed to parse eif whitelist")?;
        // leak memory to get static references
        // will be cleaned up once program exits
        // alternative to OnceCell equivalents
        let eif_whitelist = &*Box::leak(eif_whitelist_vec.into_boxed_slice());

        Some(eif_whitelist)
    } else {
        None
    };
    let eif_blacklist = if !cli.blacklist.is_empty() {
        let eif_blacklist_vec: Vec<String> = parse_file(cli.blacklist)
            .await
            .context("Failed to parse eif blacklist")?;
        // leak memory to get static references
        // will be cleaned up once program exits
        // alternative to OnceCell equivalents
        let eif_blacklist = &*Box::leak(eif_blacklist_vec.into_boxed_slice());

        Some(eif_blacklist)
    } else {
        None
    };

    let aws = aws::Aws::new(
        cli.profile,
        &regions,
        cli.key_name,
        eif_whitelist,
        eif_blacklist,
    )
    .await;

    aws.key_setup(&regions)
        .await
        .context("Failed to setup key")?;

    let compute_rates = parse_compute_rates_file(cli.rates)
        .await
        .context("failed to parse computes rates file")?;
    let bandwidth_rates = parse_bandwidth_rates_file(cli.bandwidth)
        .await
        .context("failed to parse bandwidth rates file")?;

    let address_whitelist_vec: Vec<String> = parse_file(cli.address_whitelist)
        .await
        .context("Failed to parse address whitelist")?;
    let address_blacklist_vec: Vec<String> = parse_file(cli.address_blacklist)
        .await
        .context("Failed to parse address blacklist")?;

    // leak memory to get static references
    // will be cleaned up once program exits
    // alternative to OnceCell equivalents
    let compute_rates: &'static [market::RegionalRates] =
        Box::leak(compute_rates.into_boxed_slice());
    let bandwidth_rates: &'static [market::GBRateCard] =
        Box::leak(bandwidth_rates.into_boxed_slice());
    let address_whitelist: &'static [String] = Box::leak(address_whitelist_vec.into_boxed_slice());
    let address_blacklist: &'static [String] = Box::leak(address_blacklist_vec.into_boxed_slice());
    let regions: &'static [String] = Box::leak(regions.into_boxed_slice());

    // Initialize job registry for terminated jobs
    let job_registry = market::JobRegistry::new(cli.db_url.clone()).await?;

    // Start periodic job registry persistence task
    let registry_clone = job_registry.clone();
    tokio::spawn(async move {
        registry_clone.run_periodic_save(10).await; // Save every 10 seconds
    });

    let job_id = market::JobId {
        id: 0,
        operator: cli.provider.clone(),
        contract: cli.contract.clone(),
        chain: cli.chain_id.clone(),
    };

    tokio::spawn(
        server::serve(
            aws.clone(),
            regions,
            compute_rates,
            bandwidth_rates,
            SocketAddr::from(([0, 0, 0, 0], cli.port)),
            job_id.clone(),
        )
        .instrument(info_span!("server")),
    );

    market::main_task(
        aws,
        cli.db_url,
        regions,
        compute_rates,
        bandwidth_rates,
        address_whitelist,
        address_blacklist,
        job_id,
        job_registry,
    )
    .instrument(info_span!("main"))
    .await;
}

async fn parse_file(filepath: String) -> Result<Vec<String>> {
    if filepath.is_empty() {
        return Ok(Vec::new());
    }

    let contents = fs::read_to_string(filepath).context("Error reading file")?;
    let lines: Vec<String> = contents.lines().map(|s| s.to_string()).collect();

    Ok(lines)
}

async fn parse_compute_rates_file(filepath: String) -> Result<Vec<market::RegionalRates>> {
    if filepath.is_empty() {
        return Ok(Vec::new());
    }

    let contents = fs::read_to_string(filepath).context("Error reading file")?;
    let rates: Vec<market::RegionalRates> =
        serde_json::from_str(&contents).context("failed to parse rates file")?;

    Ok(rates)
}

async fn parse_bandwidth_rates_file(filepath: String) -> Result<Vec<market::GBRateCard>> {
    if filepath.is_empty() {
        return Ok(Vec::new());
    }

    let contents = fs::read_to_string(filepath).context("Error reading file")?;
    let rates: Vec<market::GBRateCard> =
        serde_json::from_str(&contents).context("failed to parse rates file")?;

    Ok(rates)
}

#[tokio::main]
async fn main() -> Result<()> {
    // seems messy, see if there is a better way
    let mut filter = EnvFilter::new("info,aws_config=warn");
    if let Ok(var) = std::env::var("RUST_LOG") {
        filter = filter.add_directive(var.parse()?);
    }
    tracing_subscriber::fmt()
        .with_max_level(tracing::Level::INFO)
        .with_env_filter(filter)
        .init();

    let _ = run().await.inspect_err(|e| error!(?e, "run error"));

    Ok(())
}
