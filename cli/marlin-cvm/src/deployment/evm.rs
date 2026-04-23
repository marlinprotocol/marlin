use std::{str::FromStr, time::Duration};

use alloy::{
    network::EthereumWallet,
    primitives::{Address, B256, U256},
    providers::{Provider, ProviderBuilder},
    rpc::types::TransactionReceipt,
    signers::local::PrivateKeySigner,
    sol,
    sol_types::SolEvent,
};
use anyhow::{Context, Result, anyhow, bail};
use async_trait::async_trait;
use reqwest::Url;
use tokio::time::{Instant, sleep};
use tracing::info;

use super::{DeploymentAdapter, JobData};

sol!(
    #[allow(missing_docs)]
    #[sol(rpc)]
    Market,
    "src/abis/Market.json"
);

sol!(
    #[allow(missing_docs)]
    #[sol(rpc)]
    Token,
    "src/abis/Token.json"
);

pub struct EvmAdapter {
    pub rpc_url: Url,
    pub market_address: Address,
    pub usdc_address: Address,
    pub signer: Option<PrivateKeySigner>,
}

impl EvmAdapter {
    pub fn new(
        rpc_url: String,
        market_address: String,
        usdc_address: String,
        wallet_private_key: Option<&str>,
    ) -> Result<Self> {
        Ok(EvmAdapter {
            rpc_url: rpc_url.parse().context("Failed to parse rpc url")?,
            market_address: market_address
                .parse()
                .context("Failed to parse market address")?,
            usdc_address: usdc_address
                .parse()
                .context("Failed to parse usdc address")?,
            signer: wallet_private_key
                .map(|key| {
                    key.parse::<PrivateKeySigner>()
                        .context("Failed to parse wallet key")
                })
                .transpose()?,
        })
    }

    async fn watch(provider: impl Provider, tx_hash: B256, timeout: u64) -> Result<()> {
        let end = Instant::now() + Duration::from_secs(timeout);
        loop {
            tokio::select! {
                tx = provider.get_transaction_by_hash(tx_hash) => {
                    let tx = tx.context("Failed to get transaction by hash")?;
                    if let Some(tx) = tx && tx.block_hash.is_some() {
                        return Ok(())
                    };
                    // tx not found
                    sleep(Duration::from_secs(1)).await;
                    continue;
                }
                _ = sleep(end.duration_since(Instant::now())) => {
                    bail!("Timed out waiting for transaction");
                }
            }
        }
    }

    async fn get_receipt(
        provider: impl Provider,
        tx_hash: B256,
        timeout: u64,
    ) -> Result<TransactionReceipt> {
        let end = Instant::now() + Duration::from_secs(timeout);
        loop {
            tokio::select! {
                tx = provider.get_transaction_receipt(tx_hash) => {
                    let tx = tx.context("Failed to get transaction by hash")?;
                    if let Some(tx) = tx && tx.block_hash.is_some() {
                        return Ok(tx)
                    };
                    // tx not found
                    sleep(Duration::from_secs(1)).await;
                    continue;
                }
                _ = sleep(end.duration_since(Instant::now())) => {
                    bail!("Timed out waiting for transaction");
                }
            }
        }
    }
}

#[async_trait]
impl DeploymentAdapter for EvmAdapter {
    async fn get_sender_address(&self) -> Result<String> {
        Ok(self
            .signer
            .as_ref()
            .ok_or(anyhow!("No signer set"))?
            .address()
            .to_checksum(None))
    }

    async fn get_operator_cp(&self, operator: &str) -> Result<String> {
        let provider = ProviderBuilder::new()
            .disable_recommended_fillers()
            .connect_http(self.rpc_url.clone());
        let operator_address =
            Address::from_str(operator).context("Failed to parse operator address")?;

        // Create contract instance
        let market = Market::new(self.market_address, provider);

        // Call providers function to get CP URL
        let cp_url = market.providers(operator_address).call().await?;

        Ok(cp_url)
    }

    async fn get_job_data_if_exists(&self, job_id: u64) -> Result<Option<JobData>> {
        let provider = ProviderBuilder::new()
            .disable_recommended_fillers()
            .connect_http(self.rpc_url.clone());

        // Create contract instance
        let market = Market::new(self.market_address, provider);

        // Check if job exists
        let job = market
            .jobs(job_id)
            .call()
            .await
            .context("Failed to fetch job details")?;

        if job.owner == Address::ZERO {
            return Ok(None);
        }

        Ok(Some(JobData {
            metadata: job.metadata.to_vec(),
            balance: job.balance,
            rate: job.rate,
            last_settled: job.lastSettled,
        }))
    }

    async fn job_create(
        &mut self,
        metadata: Vec<u8>,
        operator: &str,
        rate: u64,
        balance: u64,
    ) -> Result<u64> {
        let signer = self.signer.clone().ok_or(anyhow!("Signer is required"))?;
        let signer_address = signer.address();
        let provider = ProviderBuilder::new()
            .disable_recommended_fillers()
            .with_simple_nonce_management()
            .with_gas_estimation()
            .fetch_chain_id()
            .wallet(EthereumWallet::from(signer))
            .connect_http(self.rpc_url.clone());
        let usdc = Token::new(self.usdc_address, &provider);

        // Get the current allowance
        let current_allowance = usdc
            .allowance(signer_address, self.market_address)
            .call()
            .await
            .context("Failed to get current USDC allowance")?;

        // Only approve if the current allowance is less than the required amount
        if current_allowance < balance {
            info!(
                "Current allowance ({}) is less than required amount ({}), approving USDC transfer...",
                current_allowance, balance
            );
            let tx = usdc
                .approve(self.market_address, U256::from(balance))
                .send()
                .await
                .context("Failed to send USDC approval transaction")?;
            info!("Transaction sent, waiting for receipt: {:?}", tx.tx_hash());
            Self::watch(&provider, *tx.tx_hash(), 60)
                .await
                .context("Failed to get receipt, transaction might still have been included")?;
            info!("Transaction included: {:?}", tx.tx_hash());
        } else {
            info!(
                "Current allowance ({}) is sufficient for the required amount ({}), skipping approval",
                current_allowance, balance
            );
        }

        let market = Market::new(self.market_address, &provider);

        // Create jobOpen call
        info!("Sending jobOpen transaction...");
        let tx = market
            .jobOpen(
                metadata.into(),
                operator
                    .parse()
                    .context(anyhow!("Failed to parse operator address"))?,
                rate,
                balance,
            )
            .send()
            .await
            .context("Failed to send transaction")?;
        info!("Transaction sent, waiting for receipt: {:?}", tx.tx_hash());
        let receipt = Self::get_receipt(&provider, *tx.tx_hash(), 60)
            .await
            .context("Failed to get receipt, transaction might still have been included")?;
        info!("Transaction included: {:?}", tx.tx_hash());

        // Calculate event signature hash
        let job_opened_topic = Market::MarketJobOpened::SIGNATURE_HASH;

        // Look for JobOpened event
        for log in receipt.inner.logs().iter() {
            if log.topics()[0] == job_opened_topic {
                info!("Found JobOpened event");
                return Ok(u64::from_be_bytes(
                    // SAFETY: slice is the correct size
                    log.topics()[1].0[24..32].try_into().unwrap(),
                ));
            }
        }

        // If we can't find the JobOpened event
        info!("No JobOpened event found. All topics:");
        for log in receipt.inner.logs().iter() {
            info!("Event topics: {:?}", log.topics());
        }

        return Err(anyhow!(
            "Could not find JobOpened event in transaction receipt"
        ));
    }

    async fn job_deposit(&mut self, job_id: u64, amount: u64) -> Result<()> {
        let signer = self.signer.clone().ok_or(anyhow!("Signer is required"))?;
        let signer_address = signer.address();
        let provider = ProviderBuilder::new()
            .disable_recommended_fillers()
            .with_simple_nonce_management()
            .with_gas_estimation()
            .fetch_chain_id()
            .wallet(EthereumWallet::from(signer))
            .connect_http(self.rpc_url.clone());
        let usdc = Token::new(self.usdc_address, &provider);

        // Get the current allowance
        let current_allowance = usdc
            .allowance(signer_address, self.market_address)
            .call()
            .await
            .context("Failed to get current USDC allowance")?;

        // Only approve if the current allowance is less than the required amount
        if current_allowance < amount {
            info!(
                "Current allowance ({}) is less than required amount ({}), approving USDC transfer...",
                current_allowance, amount
            );
            let tx = usdc
                .approve(self.market_address, U256::from(amount))
                .send()
                .await
                .context("Failed to send USDC approval transaction")?;
            info!("Transaction sent, waiting for receipt: {:?}", tx.tx_hash());
            Self::watch(&provider, *tx.tx_hash(), 60)
                .await
                .context("Failed to get receipt, transaction might still have been included")?;
            info!("Transaction included: {:?}", tx.tx_hash());
        } else {
            info!(
                "Current allowance ({}) is sufficient for the required amount ({}), skipping approval",
                current_allowance, amount
            );
        }

        let market = Market::new(self.market_address, &provider);

        info!("Sending jobDeposit transaction...");
        let tx = market
            .jobDeposit(job_id, amount)
            .send()
            .await
            .context("Failed to send transaction")?;
        info!("Transaction sent, waiting for receipt: {:?}", tx.tx_hash());
        Self::watch(&provider, *tx.tx_hash(), 60)
            .await
            .context("Failed to get receipt, transaction might still have been included")?;
        info!("Transaction included: {:?}", tx.tx_hash());

        Ok(())
    }

    async fn job_withdraw(&mut self, job_id: u64, amount: u64) -> Result<()> {
        let signer = self.signer.clone().ok_or(anyhow!("Signer is required"))?;
        let provider = ProviderBuilder::new()
            .disable_recommended_fillers()
            .with_simple_nonce_management()
            .with_gas_estimation()
            .fetch_chain_id()
            .wallet(EthereumWallet::from(signer))
            .connect_http(self.rpc_url.clone());

        let market = Market::new(self.market_address, &provider);

        info!("Sending jobWithdraw transaction...");
        let tx = market
            .jobWithdraw(job_id, amount)
            .send()
            .await
            .context("Failed to send transaction")?;
        info!("Transaction sent, waiting for receipt: {:?}", tx.tx_hash());
        Self::watch(&provider, *tx.tx_hash(), 60)
            .await
            .context("Failed to get receipt, transaction might still have been included")?;
        info!("Transaction included: {:?}", tx.tx_hash());

        Ok(())
    }

    async fn job_close(&mut self, job_id: u64) -> Result<()> {
        let signer = self.signer.clone().ok_or(anyhow!("Signer is required"))?;
        let provider = ProviderBuilder::new()
            .disable_recommended_fillers()
            .with_simple_nonce_management()
            .with_gas_estimation()
            .fetch_chain_id()
            .wallet(EthereumWallet::from(signer))
            .connect_http(self.rpc_url.clone());

        let market = Market::new(self.market_address, &provider);

        info!("Sending jobClose transaction...");
        let tx = market
            .jobClose(job_id)
            .send()
            .await
            .context("Failed to send transaction")?;
        info!("Transaction sent, waiting for receipt: {:?}", tx.tx_hash());
        Self::watch(&provider, *tx.tx_hash(), 60)
            .await
            .context("Failed to get receipt, transaction might still have been included")?;
        info!("Transaction included: {:?}", tx.tx_hash());

        Ok(())
    }

    async fn job_metadata_update(&mut self, job_id: u64, new_metadata: Vec<u8>) -> Result<()> {
        let signer = self.signer.clone().ok_or(anyhow!("Signer is required"))?;
        let provider = ProviderBuilder::new()
            .disable_recommended_fillers()
            .with_simple_nonce_management()
            .with_gas_estimation()
            .fetch_chain_id()
            .wallet(EthereumWallet::from(signer))
            .connect_http(self.rpc_url.clone());

        let market = Market::new(self.market_address, &provider);

        info!("Sending jobMetadataUpdate transaction...");
        let tx = market
            .jobMetadataUpdate(job_id, new_metadata.into())
            .send()
            .await
            .context("Failed to send transaction")?;
        info!("Transaction sent, waiting for receipt: {:?}", tx.tx_hash());
        Self::watch(&provider, *tx.tx_hash(), 60)
            .await
            .context("Failed to get receipt, transaction might still have been included")?;
        info!("Transaction included: {:?}", tx.tx_hash());

        Ok(())
    }
}
