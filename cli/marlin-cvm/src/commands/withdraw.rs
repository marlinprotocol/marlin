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
    /// Deployment (e.g. arb, sui, bsc)
    #[arg(long, default_value = "arb")]
    deployment: Deployment,

    /// Job ID
    #[arg(short, long, required = true)]
    job_id: u64,

    /// Amount to withdraw in USDC (e.g. 0.01234)
    #[arg(short, long, required_unless_present = "max")]
    amount: Option<f64>,

    /// Withdraw all remaining balance
    #[arg(long, conflicts_with = "amount")]
    max: bool,

    #[command(flatten)]
    wallet: WalletArgs,

    /// RPC URL (optional)
    #[arg(long)]
    rpc: Option<String>,
}

pub async fn withdraw_from_job(args: WithdrawArgs) -> Result<()> {
    let job_id = args.job_id;
    let wallet_private_key = &args.wallet.load_required()?;
    let max = args.max;
    let amount = args.amount.map(|x| (x * 1000000f64) as u64);

    info!("Starting withdrawal process...");

    let mut deployment_adapter =
        get_deployment_adapter(args.deployment, args.rpc, Some(wallet_private_key))
            .context("Failed to create deployment adapter")?;

    info!(
        "Signer address: {:?}",
        deployment_adapter.get_sender_address().await?
    );

    // Check if job exists
    let Some(job_data) = deployment_adapter.get_job_data_if_exists(job_id).await? else {
        return Err(anyhow!("Job {} does not exist", job_id));
    };

    // Scale down rate by extra_decimals
    let scaled_rate = job_data.rate / 10u64.pow(EXTRA_DECIMALS);

    // Calculate current balance after accounting for elapsed time
    let current_balance =
        calculate_current_balance(job_data.balance, scaled_rate, job_data.last_settled)?;

    if current_balance == 0 {
        info!("Cannot withdraw. Job is already expired.");
        return Ok(());
    }

    info!("Current balance: {:.6} USDC", format_usdc(current_balance));

    // Determine withdrawal amount (in USDC with 6 decimals)
    let withdraw_amount = if max {
        info!("Maximum withdrawal requested");
        current_balance
    } else {
        let amount =
            amount.ok_or_else(|| anyhow!("Amount must be specified when not using --max"))?;
        if amount > current_balance {
            return Err(anyhow!(
                "Cannot withdraw {:.6} USDC: maximum withdrawable amount is {:.6} USDC",
                format_usdc(amount),
                format_usdc(current_balance),
            ));
        }
        amount
    };

    info!(
        "Initiating withdrawal of {:.6} USDC",
        format_usdc(withdraw_amount)
    );

    // Withdraw from job
    deployment_adapter
        .job_withdraw(job_id, withdraw_amount)
        .await?;

    info!("Withdrawal successful!");
    Ok(())
}

/// Calculate the current balance after accounting for time elapsed since last settlement
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
        .ok_or_else(|| anyhow!("Failed to calculate amount used"))?;

    debug!(
        "Balance calculation: balance={}, rate={}, amount_used={}",
        balance, rate, amount_used
    );

    // If amount used is greater than balance, return 0
    if amount_used >= balance {
        debug!(
            "Usage ({}) exceeds balance ({}), returning 0",
            amount_used, balance
        );
        return Ok(0);
    }

    // Calculate and return current balance after deducting used amount
    balance.checked_sub(amount_used).ok_or_else(|| {
        anyhow!(
            "Failed to calculate current balance: amount_used ({}) is greater than balance ({})",
            amount_used,
            balance
        )
    })
}
