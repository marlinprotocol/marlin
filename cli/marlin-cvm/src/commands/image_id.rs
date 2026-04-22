use alloy::signers::k256::sha2::{Digest, Sha256};
use anyhow::{Context, Result};
use base64::{Engine, prelude::BASE64_STANDARD};
use clap::Args;
use k256::sha2::Sha384;
use tracing::info;

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

pub fn compute_image_id(args: ImageArgs) -> Result<()> {
    let pcrs = args
        .init_params
        .pcrs
        .clone()
        .load_required(
            args.preset
                .as_ref()
                .zip(args.arch.as_ref())
                .and_then(|(preset, arch)| preset_to_pcr_preset(preset, arch)),
            None,
        )
        .context("Failed to load PCRs")?;
    let mut pcr16 = [0u8; 48];
    if let Some(init_param_b64) = args
        .init_params
        .load(args.preset, args.arch)
        .context("Failed to load init params")?
    {
        let init_param_json = String::from_utf8(BASE64_STANDARD.decode(init_param_b64)?)?;

        let init_param: InitParamsList = serde_json::from_str(&init_param_json)?;
        let digest = BASE64_STANDARD.decode(init_param.digest)?;

        let mut pcr_hasher = Sha384::new();
        pcr_hasher.update([0u8; 48]);
        pcr_hasher.update(digest);
        pcr16 = pcr_hasher.finalize().into();
    };

    // TODO: measure digest into pcrs

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
