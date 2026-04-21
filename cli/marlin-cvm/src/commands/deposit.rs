use crate::args::wallet::WalletArgs;
use crate::deployment::{Deployment, get_deployment_adapter};
use crate::utils::format_usdc;
use anyhow::{Context, Result, anyhow};
use clap::Args;
use tracing::info;

/// Deposit funds into an existing job
#[derive(Args)]
pub struct DepositArgs {
    /// Job ID
    #[arg(short, long, required = true)]
    job_id: u64,

    /// Amount to deposit in USDC (e.g. 0.0123)
    #[arg(short, long, required = true)]
    amount: f64,

    /// Deployment
    #[arg(long, help_heading = "Deployment options", default_value = "arb")]
    deployment: Deployment,

    /// RPC URL
    #[arg(long, help_heading = "RPC options")]
    rpc: Option<String>,

    #[command(flatten)]
    wallet: WalletArgs,
}

pub async fn deposit_to_job(args: DepositArgs) -> Result<()> {
    info!("Starting deposit...");

    let amount = (args.amount * 1000000f64) as u64;
    let wallet_private_key = &args.wallet.load_required()?;
    let job_id = args.job_id;

    let mut deployment_adapter =
        get_deployment_adapter(args.deployment, args.rpc, Some(wallet_private_key))
            .context("Failed to create deployment adapter")?;

    // Check if job exists
    let Some(_) = deployment_adapter
        .get_job_data_if_exists(job_id)
        .await
        .context("Failed to query job data")?
    else {
        return Err(anyhow!("Job {} does not exist", job_id));
    };

    // Deposit into job
    info!("Depositing: {:.6} USDC", format_usdc(amount));
    deployment_adapter
        .job_deposit(job_id, amount)
        .await
        .context("Failed to make deposit transaction")?;
    info!("Deposit successful!");

    Ok(())
}
