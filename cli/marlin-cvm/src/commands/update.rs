use crate::arch::Arch;
use crate::args::init_params::InitParamsArgs;
use crate::args::wallet::WalletArgs;
use crate::deployment::{Deployment, get_deployment_adapter};
use anyhow::{Context, Result, anyhow};
use clap::Args;
use tracing::info;

/// Update existing deployments
#[derive(Args)]
pub struct UpdateArgs {
    /// Job ID
    #[arg(long)]
    job_id: u64,

    /// New URL of the enclave image
    #[arg(long)]
    image_url: Option<String>,

    /// Preset for init params (e.g. blue)
    #[arg(long, default_value = "blue")]
    preset: String,

    /// Platform architecture (e.g. amd64, arm64)
    #[arg(long, default_value = "arm64")]
    arch: Arch,

    /// New init params
    #[command(flatten)]
    init_params: InitParamsArgs,

    /// Deployment
    #[arg(long, help_heading = "Deployment options", default_value = "arb")]
    deployment: Deployment,

    /// RPC URL
    #[arg(long, help_heading = "RPC options")]
    rpc: Option<String>,

    #[command(flatten)]
    wallet: WalletArgs,
}

pub async fn update_job(args: UpdateArgs) -> Result<()> {
    let wallet_private_key = &args.wallet.load_required()?;
    let job_id = args.job_id;
    let image_url = args.image_url;

    let mut deployment_adapter =
        get_deployment_adapter(args.deployment, args.rpc, Some(wallet_private_key))
            .context("Failed to create deployment adapter")?;

    // Check if job exists
    let Some(job_data) = deployment_adapter.get_job_data_if_exists(job_id).await? else {
        return Err(anyhow!("Job {} does not exist", job_id));
    };

    let mut metadata = serde_json::from_str::<serde_json::Value>(&job_data.metadata)?;
    info!(
        "Original metadata: {}",
        serde_json::to_string_pretty(&metadata)?
    );

    if let Some(image_url) = image_url {
        metadata["url"] = serde_json::Value::String(image_url);
    }

    if let Some(init_params) = args
        .init_params
        .load(args.preset, args.arch)
        .context("Failed to load init params")?
    {
        metadata["init_params"] = init_params.into();
    }

    info!(
        "Updated metadata: {}",
        serde_json::to_string_pretty(&metadata)?
    );

    // Update job
    deployment_adapter
        .job_metadata_update(job_id, serde_json::to_string(&metadata)?)
        .await?;

    Ok(())
}
