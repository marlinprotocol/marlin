use alloy::rpc::types::TransactionRequest;
use anyhow::Result;
use async_trait::async_trait;

use crate::deployment::evm::EvmProvider;

#[derive(Clone)]
pub enum ChainProvider {
    Evm(EvmProvider),
}

#[derive(Debug, Clone)]
pub enum ChainTransaction {
    Evm(Box<TransactionRequest>),
}

#[derive(Debug, Clone)]
pub enum ChainFunds {
    Evm(()),
}

#[derive(Debug, Clone)]
pub struct JobData {
    pub metadata: String,
    pub balance: u64,
    pub rate: u64,
    pub last_settled: u64,
}

#[derive(Debug, Clone)]
pub enum JobTransactionKind {
    Create {
        metadata: String,
        operator: String,
        rate: u64,
        balance: u64,
    },
    Deposit {
        job_id: String,
        amount: u64,
    },
    ReviseRate {
        job_id: String,
        rate: u64,
    },
    Close {
        job_id: String,
    },
    Update {
        job_id: String,
        metadata: String,
    },
    Withdraw {
        job_id: String,
        amount: u64,
    },
}

#[async_trait]
pub trait DeploymentAdapter: Send + Sync {
    async fn create_provider_with_wallet(
        &mut self,
        wallet_private_key: &str,
    ) -> Result<ChainProvider>;

    async fn get_operator_cp(&self, operator: &str, provider: &ChainProvider) -> Result<String>;
    async fn get_job_data_if_exists(
        &self,
        job_id: String,
        provider: &ChainProvider,
    ) -> Result<Option<JobData>>;

    async fn prepare_funds(&self, amount_usdc: u64, provider: &ChainProvider)
    -> Result<ChainFunds>;
    async fn create_job_transaction(
        &self,
        kind: JobTransactionKind,
        fund: Option<ChainFunds>,
        provider: &ChainProvider,
    ) -> Result<ChainTransaction>;
    async fn send_transaction(
        &self,
        is_create_job: bool,
        transaction: ChainTransaction,
        provider: &ChainProvider,
    ) -> Result<Option<String>>;

    fn get_sender_address(&self) -> String;
}
