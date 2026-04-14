use clap::{ValueEnum, builder::PossibleValue};

use crate::{
    configs::arb::{ARBITRUM_ONE_RPC_URL, OYSTER_MARKET_ADDRESS, USDC_ADDRESS},
    deployment::{adapter::DeploymentAdapter, evm::EvmAdapter},
};

pub mod adapter;
pub mod evm;

#[derive(Clone, Debug)]
pub enum Deployment {
    Arb,
}

impl Deployment {
    pub fn as_str(&self) -> &'static str {
        match self {
            Deployment::Arb => "arb",
        }
    }
}

impl ValueEnum for Deployment {
    fn value_variants<'a>() -> &'a [Self] {
        &[Self::Arb]
    }

    fn to_possible_value(&self) -> Option<PossibleValue> {
        Some(self.as_str().into())
    }
}

pub fn get_deployment_adapter(
    chain_type: Deployment,
    rpc_url: Option<String>,
) -> Box<dyn DeploymentAdapter> {
    match chain_type {
        Deployment::Arb => Box::new(EvmAdapter {
            rpc_url: rpc_url.unwrap_or(ARBITRUM_ONE_RPC_URL.to_owned()),
            market_address: OYSTER_MARKET_ADDRESS.to_owned(),
            usdc_address: USDC_ADDRESS.to_owned(),
            sender_address: None,
        }),
    }
}
