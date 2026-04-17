use anyhow::Result;
use async_trait::async_trait;

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
    async fn job_revise_rate(&mut self, job_id: u64, rate: u64) -> Result<()>;
    async fn job_close(&mut self, job_id: u64) -> Result<()>;
    async fn job_metadata_update(&mut self, job_id: u64, new_metadata: String) -> Result<()>;
}
