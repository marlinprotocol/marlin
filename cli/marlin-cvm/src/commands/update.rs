use crate::arch::Arch;
use crate::args::init_params::InitParamsArgs;
use crate::args::wallet::WalletArgs;
use crate::deployment::{Deployment, get_deployment_adapter};
use anyhow::{Context, Result, anyhow};
use clap::Args;
use tracing::info;

/// Update existing job
#[derive(Args)]
pub struct UpdateArgs {
    /// Job ID
    #[arg(long)]
    job_id: u64,

    /// New AMI ID for the CVM
    #[arg(long)]
    image: Option<String>,

    /// New init params
    #[command(flatten)]
    init_params: InitParamsArgs,

    /// Preset for parameters (e.g. blue)
    #[arg(long)]
    preset: Option<String>,

    /// CVM architecture
    #[arg(long)]
    arch: Option<Arch>,

    /// Deployment
    #[arg(long, help_heading = "Deployment options", default_value = "arb")]
    deployment: Deployment,

    /// RPC URL
    #[arg(long, help_heading = "RPC options")]
    rpc: Option<String>,

    #[command(flatten)]
    wallet: WalletArgs,
}

impl UpdateArgs {
    pub async fn run(self) -> Result<()> {
        let args = self;
        let wallet_private_key = &args.wallet.load_required()?;
        let job_id = args.job_id;
        let image = args.image;

        let mut deployment_adapter =
            get_deployment_adapter(args.deployment, args.rpc, Some(wallet_private_key))
                .context("Failed to create deployment adapter")?;

        // Check if job exists
        let Some(job_data) = deployment_adapter
            .get_job_data_if_exists(job_id)
            .await
            .context("Failed to query job data")?
        else {
            return Err(anyhow!("Job {} does not exist", job_id));
        };

        let mut metadata = ciborium::from_reader::<Vec<(ciborium::Value, ciborium::Value)>, _>(
            job_data.metadata.as_slice(),
        )
        .context("Failed to decode metadata as cbor map")?;

        if let Some(image) = image {
            if let Some(entry) = metadata.iter_mut().find(|v| v.0 == "image".into()) {
                entry.1 = image.into();
            } else {
                metadata.push(("image".into(), image.into()));
            }
        }

        if let Some(init_params) = args
            .init_params
            .load(args.preset, args.arch)
            .context("Failed to load init params")?
        {
            if let Some(entry) = metadata.iter_mut().find(|v| v.0 == "init_params".into()) {
                entry.1 = init_params.into();
            } else {
                metadata.push(("init_params".into(), init_params.into()));
            }
        }

        let mut cbor = Vec::new();
        ciborium::into_writer(&metadata, &mut cbor).context("failed to serialize metadata")?;

        // Update job
        info!("Updating metadata...");
        deployment_adapter
            .job_metadata_update(job_id, cbor)
            .await
            .context("Failed to make metadata update transaction")?;
        info!("Update successful!");

        Ok(())
    }
}
