use crate::args::wallet::WalletArgs;
use crate::deployment::{Deployment, get_deployment_adapter};
use anyhow::{Context, Result, anyhow};
use clap::Args;
use tracing::info;

/// Stop an Oyster CVM instance
#[derive(Args)]
pub struct StopArgs {
    /// Deployment (e.g. arb, sui, bsc)
    #[arg(long, default_value = "arb")]
    deployment: Deployment,

    /// Job ID
    #[arg(short = 'j', long, required = true)]
    job_id: u64,

    #[command(flatten)]
    wallet: WalletArgs,

    /// RPC URL (optional)
    #[arg(long)]
    rpc: Option<String>,

    /// Auth token (optional for sui rpc)
    #[arg(long)]
    auth_token: Option<String>,

    /// Gas coin ID for Sui chain transactions (optional, will be chosen automatically from user's account via simulation results)
    #[arg(long)]
    gas_coin: Option<String>,
}

pub async fn stop_oyster_instance(args: StopArgs) -> Result<()> {
    let job_id = args.job_id;
    let wallet_private_key = &args.wallet.load_required()?;

    info!("Stopping oyster instance with:");
    info!("  Job ID: {}", job_id);

    let mut deployment_adapter =
        get_deployment_adapter(args.deployment, args.rpc, Some(wallet_private_key))
            .context("Failed to create deployment adapter")?;

    info!(
        "Signer address: {:?}",
        deployment_adapter.get_sender_address().await?
    );

    // Check if job exists
    let job_data = deployment_adapter.get_job_data_if_exists(job_id).await?;
    if job_data.is_none() {
        return Err(anyhow!("Job {} does not exist", job_id));
    }

    // Close job
    info!("Initiating job close...");
    deployment_adapter.job_close(job_id).await?;

    info!("Instance stopped successfully!");
    Ok(())
}
