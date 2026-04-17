use anyhow::{Context, Result};
use async_trait::async_trait;
use clap::{ValueEnum, builder::PossibleValue};

use crate::configs::arb;

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
    deployment: Deployment,
    rpc_url: Option<String>,
    wallet_private_key: Option<&str>,
) -> Result<Box<dyn DeploymentAdapter>> {
    match deployment {
        Deployment::Arb => Ok(Box::new(
            evm::EvmAdapter::new(
                rpc_url.unwrap_or(arb::RPC_URL.to_owned()),
                arb::MARKET_ADDRESS.to_owned(),
                arb::USDC_ADDRESS.to_owned(),
                wallet_private_key,
            )
            .context("Failed to create evm adapter for arb")?,
        )),
    }
}

#[derive(Debug, Clone)]
pub struct JobData {
    pub metadata: String,
    pub balance: u64,
    pub rate: u64,
    pub last_settled: u64,
}

#[async_trait]
pub trait DeploymentAdapter: Send + Sync {
    async fn get_sender_address(&self) -> Result<String>;
    async fn get_operator_cp(&self, operator: &str) -> Result<String>;
    async fn get_job_data_if_exists(&self, job_id: u64) -> Result<Option<JobData>>;

    // return job id
    async fn job_create(
        &mut self,
        metadata: &str,
        operator: &str,
        rate: u64,
        balance: u64,
    ) -> Result<u64>;
    async fn job_deposit(&mut self, job_id: u64, amount: u64) -> Result<()>;
    async fn job_withdraw(&mut self, job_id: u64, amount: u64) -> Result<()>;
    async fn job_close(&mut self, job_id: u64) -> Result<()>;
    async fn job_metadata_update(&mut self, job_id: u64, new_metadata: String) -> Result<()>;
}
