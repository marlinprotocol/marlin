use anyhow::{Context, Result, anyhow, bail};
use clap::{Args, ValueEnum, builder::PossibleValue};
use k256::sha2::{Digest, Sha384};
use serde_json;
use tracing::info;

use crate::arch::Arch;

#[derive(Args, Debug, Clone)]
#[group(multiple = true)]
pub struct PcrArgs {
    /// Preset PCRs for known enclave images
    #[arg(long, help_heading = "PCRs options", conflicts_with_all = ["pcr_json"])]
    pub pcr_preset: Option<PcrPreset>,

    /// Path to PCR JSON file
    #[arg(long, help_heading = "PCRs options", conflicts_with_all = ["pcr_preset"])]
    pub pcr_json: Option<String>,

    /// Initialization parameters digest to extend PCR15 with
    #[arg(long, help_heading = "PCRs options")]
    pub digest: Option<String>,
}

impl PcrArgs {
    fn load_without_digest(
        self,
        default_preset: Option<PcrPreset>,
    ) -> Result<[Option<[u8; 48]>; 12]> {
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

    pub fn load(
        self,
        default_preset: Option<PcrPreset>,
        force_digest: Option<&[u8]>,
    ) -> Result<[Option<[u8; 48]>; 12]> {
        let args_digest = self
            .digest
            .as_ref()
            .map(hex::decode)
            .transpose()
            .context("Failed to hex decode digest")?;
        if let Some(ref args_digest) = args_digest
            && let Some(force_digest) = force_digest
            && args_digest.as_slice() != force_digest
        {
            bail!("Digest parameter does not match expected digest");
        }
        let digest = args_digest.as_deref().or(force_digest);

        let mut pcrs = self.load_without_digest(default_preset)?;
        let Some(digest) = digest else {
            return Ok(pcrs);
        };

        let Some(pcr) = pcrs[11] else {
            bail!("PCR15 is required in order to extend with digest");
        };

        let mut hasher = Sha384::new_with_prefix(pcr);
        hasher.update(digest);
        pcrs[11] = Some(hasher.finalize().into());

        Ok(pcrs)
    }

    pub fn load_required(
        self,
        default_preset: Option<PcrPreset>,
        force_digest: Option<&[u8]>,
    ) -> Result<[[u8; 48]; 12]> {
        self.load(default_preset, force_digest)
            .context("Failed to get pcrs")?
            .into_iter()
            .flatten()
            .collect::<Box<_>>()
            .as_ref()
            .try_into()
            .map_err(|_| {
                anyhow!(
                    "Specify one of pcr-preset or pcr-json{}",
                    default_preset
                        .map(|x| format!(": preset {} is not recognized", x.as_str()))
                        .unwrap_or_default()
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
