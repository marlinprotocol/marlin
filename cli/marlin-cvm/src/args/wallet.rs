use std::fs;

use anyhow::{Context, Result, anyhow};
use clap::Args;

#[derive(Args, Debug)]
#[group(multiple = true)]
pub struct WalletArgs {
    /// Wallet private key for transaction signing
    /// [Hex (without prefix '0x') for EVM chains]
    /// [Base64 OR Bech32 (with prefix 'suiprivkey') encoded 33-byte private key (flag || private_key) for Sui chain]
    #[arg(long, help_heading = "Wallet options", conflicts_with = "wallet_file")]
    wallet_private_key: Option<String>,

    /// Wallet private key file containing the private key encoded the same as the
    /// wallet-private-key option
    #[arg(
        long,
        help_heading = "Wallet options",
        conflicts_with = "wallet_private_key"
    )]
    wallet_file: Option<String>,
}

impl WalletArgs {
    pub fn load(&self) -> Result<Option<String>> {
        if let Some(ref key) = self.wallet_private_key {
            return Ok(Some(key.into()));
        }

        if let Some(ref path) = self.wallet_file {
            return Ok(Some(
                fs::read_to_string(path).context("Failed to read private key file")?,
            ));
        }

        Ok(None)
    }

    pub fn load_required(&self) -> Result<String> {
        self.load()
            .transpose()
            .ok_or(anyhow!("Specify one of wallet-private-key or wallet-file."))?
    }
}
