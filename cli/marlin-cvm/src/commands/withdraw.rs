use crate::args::wallet::WalletArgs;
use crate::configs::global::{EXTRA_DECIMALS, MIN_WITHDRAW_AMOUNT};
use crate::deployment::adapter::JobTransactionKind;
use crate::deployment::{Deployment, get_deployment_adapter};
use crate::utils::format_usdc;
use anyhow::{Context, Result, anyhow};
use clap::Args;
use std::time::{SystemTime, UNIX_EPOCH};
use tracing::{debug, info};

// Withdrawal Settings
const BUFFER_MINUTES: u64 = 7; // Required buffer time in minutes

/// Withdraw funds from an existing job
#[derive(Args)]
pub struct WithdrawArgs {
    /// Deployment (e.g. arb, sui, bsc)
    #[arg(long, default_value = "arb")]
    deployment: Deployment,

    /// Job ID
    #[arg(short, long, required = true)]
    job_id: String,

    /// Amount to withdraw in USDC (e.g. 1000000 = 1 USDC since USDC has 6 decimal places)
    #[arg(short, long, required_unless_present = "max")]
    amount: Option<u64>,

    /// Withdraw all remaining balance
    #[arg(long, conflicts_with = "amount")]
    max: bool,

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

pub async fn withdraw_from_job(args: WithdrawArgs) -> Result<()> {
    let job_id = args.job_id;
    let wallet_private_key = &args.wallet.load_required()?;
    let max = args.max;
    let amount = args.amount;

    info!("Starting withdrawal process...");

    let mut deployment_adapter = get_deployment_adapter(args.deployment, args.rpc);

    // Setup provider
    let provider = deployment_adapter
        .create_provider_with_wallet(wallet_private_key)
        .await
        .context("Failed to create provider")?;

    info!(
        "Signer address: {:?}",
        deployment_adapter.get_sender_address()
    );

    let Some(job_data) = deployment_adapter
        .get_job_data_if_exists(job_id.clone(), &provider)
        .await?
    else {
        return Err(anyhow!("Job {} does not exist", job_id));
    };

    // Check if balance is zero
    if job_data.balance == 0 {
        return Err(anyhow!("Cannot withdraw: job balance is 0 USDC"));
    }

    // Scale down rate by extra_decimals
    let scaled_rate = job_data.rate / 10u64.pow(EXTRA_DECIMALS);

    // Calculate required buffer balance (5 minutes worth of rate)
    let buffer_seconds = BUFFER_MINUTES * 60;
    let buffer_balance = scaled_rate
        .checked_mul(buffer_seconds)
        .ok_or_else(|| anyhow!("Failed to calculate buffer balance"))?;

    // Calculate current balance after accounting for elapsed time
    let current_balance =
        calculate_current_balance(job_data.balance, scaled_rate, job_data.last_settled)?;

    if current_balance == 0 {
        info!("Cannot withdraw. Job is already expired.");
        return Ok(());
    }

    info!(
        "Current balance: {:.6} USDC, Required buffer: {:.6} USDC",
        format_usdc(current_balance),
        format_usdc(buffer_balance)
    );

    // Calculate maximum withdrawable amount (in USDC with 6 decimals)
    let max_withdrawable = if current_balance > buffer_balance {
        current_balance
            .checked_sub(buffer_balance)
            .ok_or_else(|| anyhow!("Failed to calculate withdrawable amount"))?
    } else {
        return Err(anyhow!(
            "Cannot withdraw: current balance ({:.6} USDC) is less than required buffer ({:.6} USDC)",
            format_usdc(current_balance),
            format_usdc(buffer_balance)
        ));
    };

    // Determine withdrawal amount (in USDC with 6 decimals)
    let amount_u256 = if max {
        info!("Maximum withdrawal requested");
        max_withdrawable
    } else {
        let amount =
            amount.ok_or_else(|| anyhow!("Amount must be specified when not using --max"))?;
        if amount < MIN_WITHDRAW_AMOUNT {
            return Err(anyhow!(
                "Amount must be at least {} (0.000001 USDC)",
                MIN_WITHDRAW_AMOUNT
            ));
        }
        if amount > max_withdrawable {
            return Err(anyhow!(
                "Cannot withdraw {:.6} USDC: maximum withdrawable amount is {:.6} USDC (need to maintain {:.6} USDC buffer)",
                format_usdc(amount),
                format_usdc(max_withdrawable),
                format_usdc(buffer_balance)
            ));
        }
        amount
    };

    info!(
        "Initiating withdrawal of {:.6} USDC",
        format_usdc(amount_u256)
    );

    // Call jobWithdraw function with amount in USDC
    let job_withdraw_transaction = deployment_adapter
        .create_job_transaction(
            JobTransactionKind::Withdraw {
                job_id,
                amount: amount_u256,
            },
            None,
            &provider,
        )
        .await?;
    let _ = deployment_adapter
        .send_transaction(false, job_withdraw_transaction, &provider)
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
