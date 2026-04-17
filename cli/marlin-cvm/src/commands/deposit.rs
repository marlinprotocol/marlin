use crate::args::wallet::WalletArgs;
use crate::deployment::{Deployment, get_deployment_adapter};
use crate::utils::format_usdc;
use anyhow::{Context, Result, anyhow};
use clap::Args;
use tracing::info;

/// Deposit funds to an existing job
#[derive(Args)]
pub struct DepositArgs {
    /// Deployment (e.g. arb, sui, bsc)
    #[arg(long, default_value = "arb")]
    deployment: Deployment,

    /// Job ID
    #[arg(short, long, required = true)]
    job_id: u64,

    /// Amount to deposit in USDC (e.g. 0.0123)
    #[arg(short, long, required = true)]
    amount: f64,

    #[command(flatten)]
    wallet: WalletArgs,

    /// RPC URL (optional)
    #[arg(long)]
    rpc: Option<String>,
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
    let job_data = deployment_adapter.get_job_data_if_exists(job_id).await?;
    if job_data.is_none() {
        return Err(anyhow!("Job {} does not exist", job_id));
    }

    info!("Depositing: {:.6} USDC", format_usdc(amount));

    // Call jobDeposit function
    deployment_adapter.job_deposit(job_id, amount).await?;

    info!("Deposit successful!");

    Ok(())
}
