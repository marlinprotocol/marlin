use anyhow::{Context, Result, anyhow, bail};
use clap::{Args, ValueEnum, builder::PossibleValue};
use serde_json;
use tracing::info;

use crate::arch::Arch;

// TODO: Handle dynamic PCRs with app digests

#[derive(Args, Debug, Clone)]
#[group(multiple = true)]
pub struct PcrArgs {
    /// Preset PCRs for known enclave images
    #[arg(long, help_heading = "PCRs options", conflicts_with_all = ["pcr_json"])]
    pub pcr_preset: Option<PcrPreset>,

    /// Path to PCR JSON file
    #[arg(long, help_heading = "PCRs options", conflicts_with_all = ["pcr_preset"])]
    pub pcr_json: Option<String>,
}

impl PcrArgs {
    pub fn load(self, default_preset: Option<PcrPreset>) -> Result<[Option<[u8; 48]>; 12]> {
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

            return Ok(pcrs);
        }

        if let Some(ref preset) = self.pcr_preset.or(default_preset) {
            info!(preset = preset.as_str(), "PCR preset");
            return match preset {
                _ => bail!("Unknown PCR preset"),
            };
        }

        Ok([None; 12])
    }

    pub fn load_required(self, default_preset: Option<PcrPreset>) -> Result<[[u8; 48]; 12]> {
        self.load(default_preset)
            .context("Failed to get pcrs")?
            .into_iter()
            .filter_map(|x| x)
            .collect::<Box<_>>()
            .as_ref()
            .try_into()
            .map_err(|_| {
                anyhow!(
                    "Specify one of pcr-preset or pcr-json{}",
                    default_preset
                        .map(|x| format!(": preset {} is not recognized", x.as_str()))
                        .unwrap_or(String::new())
                )
            })
    }
}

pub fn preset_to_pcr_preset(preset: &str, _arch: &Arch) -> Option<PcrPreset> {
    match preset {
        _ => None,
    }
}

#[derive(Debug, Clone, Copy)]
pub enum PcrPreset {}

impl PcrPreset {
    fn as_str(&self) -> &'static str {
        match self {
            _ => "None",
        }
    }
}

impl ValueEnum for PcrPreset {
    fn value_variants<'a>() -> &'a [Self] {
        &[]
    }

    fn to_possible_value(&self) -> Option<PossibleValue> {
        Some(self.as_str().into())
    }
}
