use anyhow::{Context, Result, anyhow, bail};
use clap::Args;
use serde_json;
use tracing::info;

use crate::types::Platform;

#[derive(Args, Debug, Clone)]
#[group(multiple = true)]
pub struct PcrArgs {
    /// Preset PCRs for known enclave images
    #[arg(long, conflicts_with_all = ["pcr_json"])]
    pub pcr_preset: Option<String>,

    /// Path to PCR JSON file
    #[arg(long, conflicts_with_all = ["pcr_preset"])]
    pub pcr_json: Option<String>,
}

impl PcrArgs {
    pub fn load(self, default_preset: Option<String>) -> Result<Option<[Option<[u8; 48]>; 12]>> {
        if let Some(ref path) = self.pcr_json {
            let file = std::fs::File::open(path)?;
            let parsed = serde_json::from_reader::<_, serde_json::Value>(file)
                .context("Failed to parse PCR JSON file")?;
            let measurements = parsed
                .as_object()
                .context("Failed to parse contents as object")?
                .get("Measurements")
                .ok_or(anyhow!("Failed to find measurements"))?
                .as_object()
                .context("Failed to parse measurements as object")?;

            let pcrs = (4..=15)
                .map(|i| {
                    measurements
                        .get(&format!("PCR{i}"))
                        .map(|v| {
                            hex::decode(
                                v.as_str()
                                    .context("Failed to parse measurement as string")?,
                            )
                            .context("Failed to decode measurement as hex")?
                            .try_into()
                            .map_err(|_| anyhow!("Measurement too long"))
                        })
                        .transpose()
                })
                .collect::<Result<Vec<Option<[u8; 48]>>>>()
                .context("Failed to parse measurements")?
                .try_into()
                .map_err(|_| anyhow!("Should never happen, wrong measurements size"))?;

            return Ok(Some(pcrs));
        }

        if let Some(ref name) = self.pcr_preset.or(default_preset) {
            info!(name, "PCR preset");
            return match name.as_str() {
                _ => bail!("Unknown PCR preset"),
            };
        }

        Ok(None)
    }

    pub fn load_required(self, default_preset: Option<String>) -> Result<[Option<[u8; 48]>; 12]> {
        self.load(default_preset)
            .transpose()
            .ok_or(anyhow!("Pcrs parameter is required."))?
    }
}

pub fn preset_to_pcr_preset(preset: &str, _arch: &Platform) -> Option<String> {
    match preset {
        _ => None,
    }
    .map(str::to_owned)
}
