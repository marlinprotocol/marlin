use crate::args::wallet::WalletArgs;
use crate::deployment::adapter::JobTransactionKind;
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
    job_id: String,

    /// Amount to deposit in USDC (e.g. 1000000 = 1 USDC since USDC has 6 decimal places)
    #[arg(short, long, required = true)]
    amount: u64,

    #[command(flatten)]
    wallet: WalletArgs,

    /// RPC URL (optional)
    #[arg(long)]
    rpc: Option<String>,

    /// Auth token (optional for sui rpc)
    #[arg(long)]
    auth_token: Option<String>,

    /// USDC coin ID for Sui chain based enclave payment (optional, will be picked automatically from user's account if not provided)
    #[arg(long)]
    usdc_coin: Option<String>,

    /// Gas coin ID for Sui chain transactions (optional, will be chosen automatically from user's account via simulation results)
    #[arg(long)]
    gas_coin: Option<String>,
}

pub async fn deposit_to_job(args: DepositArgs) -> Result<()> {
    info!("Starting deposit...");

    let amount = args.amount;
    let wallet_private_key = &args.wallet.load_required()?;
    let job_id = args.job_id;

    let mut deployment_adapter = get_deployment_adapter(args.deployment, args.rpc);

    // Setup provider
    let provider = deployment_adapter
        .create_provider_with_wallet(wallet_private_key)
        .await
        .context("Failed to create provider")?;

    // Check if job exists
    let job_data = deployment_adapter
        .get_job_data_if_exists(job_id.clone(), &provider)
        .await?;
    if job_data.is_none() {
        return Err(anyhow!("Job {} does not exist", job_id));
    }

    info!("Depositing: {:.6} USDC", format_usdc(amount));

    // First approve USDC transfer
    let funds = deployment_adapter.prepare_funds(amount, &provider).await?;

    let job_deposit_transaction = deployment_adapter
        .create_job_transaction(
            JobTransactionKind::Deposit { job_id, amount },
            Some(funds),
            &provider,
        )
        .await?;

    // Call jobDeposit function
    let _ = deployment_adapter
        .send_transaction(false, job_deposit_transaction, &provider)
        .await?;

    info!("Deposit successful!");

    Ok(())
}
