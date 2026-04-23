use crate::args::wallet::WalletArgs;
use crate::configs::global::EXTRA_DECIMALS;
use crate::deployment::{Deployment, get_deployment_adapter};
use crate::utils::format_usdc;
use anyhow::{Context, Result, anyhow};
use clap::Args;
use std::time::{SystemTime, UNIX_EPOCH};
use tracing::{debug, info};

/// Withdraw funds from an existing job
#[derive(Args)]
pub struct WithdrawArgs {
    /// Job ID
    #[arg(short, long, required = true)]
    job_id: u64,

    /// Amount to withdraw in USDC (e.g. 0.01234)
    #[arg(short, long)]
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

impl WithdrawArgs {
    pub async fn run(self) -> Result<()> {
        let args = self;
        info!("Starting withdrawal...");

        let job_id = args.job_id;
        let wallet_private_key = &args.wallet.load_required()?;
        let amount = (args.amount * 1000000f64) as u64;

        let mut deployment_adapter =
            get_deployment_adapter(args.deployment, args.rpc, Some(wallet_private_key))
                .context("Failed to create deployment adapter")?;

        info!(
            "Signer address: {:?}",
            deployment_adapter
                .get_sender_address()
                .await
                .context("Should never happen, adapter does not have signer")?
        );

        // Check if job exists
        let Some(job_data) = deployment_adapter
            .get_job_data_if_exists(job_id)
            .await
            .context("Failed to query job data")?
        else {
            return Err(anyhow!("Job {} does not exist", job_id));
        };

        // Calculate current balance after accounting for elapsed time
        let current_balance =
            calculate_current_balance(job_data.balance, job_data.rate, job_data.last_settled)
                .context("Failed to compute current balance")?;

        if current_balance == 0 {
            info!("Cannot withdraw. Job is already expired.");
            return Ok(());
        }

        info!("Current balance: {:.6} USDC", format_usdc(current_balance));

        if amount > current_balance {
            return Err(anyhow!(
                "Cannot withdraw {:.6} USDC: maximum withdrawable amount is {:.6} USDC",
                format_usdc(amount),
                format_usdc(current_balance),
            ));
        }

        // Withdraw from job
        info!("Withdrawing: {:.6} USDC", format_usdc(amount));
        deployment_adapter
            .job_withdraw(job_id, amount)
            .await
            .context("Failed to make withdrawal transaction")?;
        info!("Withdrawal successful!");

        Ok(())
    }
}

// Calculate the current balance after accounting for time elapsed since last settlement
fn calculate_current_balance(balance: u64, rate: u64, last_settled: u64) -> Result<u64> {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .context("Failed to get current time")?
        .as_secs();

    if last_settled > now {
        return Err(anyhow!("Last settled time is in the future"));
    }

    let elapsed_seconds = now.saturating_sub(last_settled);
    debug!(
        "Time calculation: now={}, last_settled={}, elapsed_seconds={}",
        now, last_settled, elapsed_seconds
    );

    // Calculate amount used since last settlement
    let amount_used = rate
        .checked_mul(elapsed_seconds)
        .ok_or_else(|| anyhow!("Failed to calculate amount used"))?
        .div_ceil(10u64.pow(EXTRA_DECIMALS));

    debug!(
        "Balance calculation: balance={}, rate={}, amount_used={}",
        balance, rate, amount_used
    );

    // Calculate and return current balance after deducting used amount
    Ok(balance.saturating_sub(amount_used))
}
