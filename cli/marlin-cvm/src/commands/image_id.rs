use alloy::signers::k256::sha2::{Digest, Sha256};
use anyhow::{Context, Result};
use base64::{Engine, prelude::BASE64_STANDARD};
use clap::Args;
use tracing::{info, warn};

use crate::{
    arch::Arch,
    args::{
        init_params::{InitParamsArgs, InitParamsList},
        pcr::preset_to_pcr_preset,
    },
};

/// Get Image ID
#[derive(Args, Debug)]
pub struct ImageArgs {
    /// Preset for parameters (e.g. blue)
    #[arg(long)]
    preset: Option<String>,

    /// Platform architecture
    #[arg(long)]
    arch: Option<Arch>,

    #[command(flatten)]
    init_params: InitParamsArgs,
}

impl ImageArgs {
    pub fn run(self) -> Result<()> {
        let args = self;
        let pcr_args = args.init_params.pcrs.clone();
        let digest = args
        .init_params
        .load(args.preset.clone(), args.arch.clone())
        .context("Failed to load init params")?
        .map(|init_param_b64| -> Result<Vec<u8>> {
            let init_param_cbor = BASE64_STANDARD.decode(init_param_b64)
                .context("Failed to decode init params from base64")?;

            let init_param: InitParamsList = ciborium::from_reader(init_param_cbor.as_slice())
                .context("Failed to parse init params as cbor")?;
            let digest = BASE64_STANDARD
                .decode(init_param.digest)
                .context("Failed to decode digest")?;
            Ok(digest)
        })
        .transpose()
        .inspect_err(|e| {
            warn!("Error extracting digest from init params, proceeding without an extracted digest: {e:#}")
        })
        .unwrap_or(None);

        let pcrs = pcr_args
            .load_required(
                args.preset
                    .as_ref()
                    .zip(args.arch.as_ref())
                    .and_then(|(preset, arch)| preset_to_pcr_preset(preset, arch)),
                digest.as_deref(),
            )
            .context("Failed to load PCRs")?;

        // compute image id
        let mut hasher = Sha256::new();
        // bitflags denoting what pcrs are part of the computation
        // this one has 4-15
        hasher.update((4..=15).fold(0u32, |acc, x| acc | (1 << x)).to_be_bytes());
        hasher.update(pcrs.as_flattened());
        let image_id: [u8; 32] = hasher.finalize().into();

        let hex_image_id = hex::encode(image_id);

        info!("Image ID: {}", hex_image_id);

        Ok(())
    }
}
