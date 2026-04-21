use crate::args::wallet::WalletArgs;
use crate::deployment::{Deployment, get_deployment_adapter};
use anyhow::{Context, Result, anyhow};
use clap::Args;
use tracing::info;

/// Close an existing job
#[derive(Args)]
pub struct CloseArgs {
    /// Job ID
    #[arg(long, required = true)]
    job_id: u64,

    /// Deployment
    #[arg(long, help_heading = "Deployment options", default_value = "arb")]
    deployment: Deployment,

    /// RPC URL
    #[arg(long, help_heading = "RPC options")]
    rpc: Option<String>,

    #[command(flatten)]
    wallet: WalletArgs,
}

pub async fn close_job(args: CloseArgs) -> Result<()> {
    let job_id = args.job_id;
    let wallet_private_key = args
        .wallet
        .load_required()
        .context("Wallet parameter is required")?;

    info!("Closing job with id {job_id}");

    let mut deployment_adapter =
        get_deployment_adapter(args.deployment, args.rpc, Some(&wallet_private_key))
            .context("Failed to create deployment adapter")?;

    info!(
        "Signer address: {:?}",
        deployment_adapter
            .get_sender_address()
            .await
            .context("Failed to get sender address")?
    );

    // Check if job exists
    let Some(_) = deployment_adapter
        .get_job_data_if_exists(job_id)
        .await
        .context("Failed to query job data")?
    else {
        return Err(anyhow!("Job {} does not exist", job_id));
    };

    // Close job
    info!("Initiating job close...");
    deployment_adapter
        .job_close(job_id)
        .await
        .context("Failed to make close transaction")?;
    info!("Job closed successfully!");

    Ok(())
}
