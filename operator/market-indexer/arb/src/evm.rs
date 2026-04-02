use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::Duration;

use alloy::hex::ToHexExt;
use alloy::network::Ethereum;
use alloy::primitives::Address;
use alloy::providers::{Provider, RootProvider};
use alloy::rpc::types::Filter;
use alloy::rpc::types::eth::Log;
use alloy::sol;
use alloy::sol_types::SolEvent;
use alloy::transports::http::reqwest::Url;
use anyhow::{Context, Result};
use indexer_framework::chain::{ChainHandler, FromLog};
use indexer_framework::events::*;
use tokio_retry::Retry;
use tokio_retry::strategy::{ExponentialBackoff, jitter};

sol!(
    #[allow(missing_docs)]
    #[sol(rpc)]
    Market,
    "./abi/Market.json"
);

#[derive(Debug, Clone)]
pub struct ArbLog(pub Log);

impl FromLog for ArbLog {
    fn to_job_event(&self) -> Result<Option<JobEvent>> {
        match self.0.topic0() {
            Some(&Market::JobOpened::SIGNATURE_HASH) => {
                let decoded_data = Market::JobOpened::decode_log(&self.0.inner)
                    .context("Failed to abi decode JobOpened event data")?
                    .data;

                Ok(Some(JobEvent::Opened(JobOpened {
                    job_id: decoded_data.job.encode_hex_with_prefix(),
                    owner: decoded_data.owner.encode_hex_with_prefix(),
                    provider: decoded_data.provider.encode_hex_with_prefix(),
                    metadata: decoded_data.metadata,
                    rate: decoded_data.rate,
                    balance: decoded_data.balance,
                    timestamp: decoded_data.timestamp.saturating_to(),
                })))
            }
            Some(&Market::JobClosed::SIGNATURE_HASH) => {
                let decoded_data = Market::JobClosed::decode_log(&self.0.inner)
                    .context("Failed to abi decode JobClosed event data")?
                    .data;

                Ok(Some(JobEvent::Closed(JobClosed {
                    job_id: decoded_data.job.encode_hex_with_prefix(),
                })))
            }
            Some(&Market::JobSettled::SIGNATURE_HASH) => {
                let decoded_data = Market::JobSettled::decode_log(&self.0.inner)
                    .context("Failed to abi decode JobSettled event data")?
                    .data;

                Ok(Some(JobEvent::Settled(JobSettled {
                    job_id: decoded_data.job.encode_hex_with_prefix(),
                    amount: decoded_data.amount,
                    timestamp: decoded_data.timestamp.saturating_to(),
                })))
            }
            Some(&Market::JobDeposited::SIGNATURE_HASH) => {
                let decoded_data = Market::JobDeposited::decode_log(&self.0.inner)
                    .context("Failed to abi decode JobDeposited event data")?
                    .data;

                Ok(Some(JobEvent::Deposited(JobDeposited {
                    job_id: decoded_data.job.encode_hex_with_prefix(),
                    from: decoded_data.from.encode_hex_with_prefix(),
                    amount: decoded_data.amount,
                })))
            }
            Some(&Market::JobWithdrew::SIGNATURE_HASH) => {
                let decoded_data = Market::JobWithdrew::decode_log(&self.0.inner)
                    .context("Failed to abi decode JobWithdrew event data")?
                    .data;

                Ok(Some(JobEvent::Withdrew(JobWithdrew {
                    job_id: decoded_data.job.encode_hex_with_prefix(),
                    to: decoded_data.to.encode_hex_with_prefix(),
                    amount: decoded_data.amount,
                })))
            }
            Some(&Market::JobReviseRateInitiated::SIGNATURE_HASH) => {
                let decoded_data =
                    Market::JobReviseRateInitiated::decode_log(&self.0.inner)
                        .context("Failed to abi decode JobReviseRateInitiated event data")?
                        .data;

                Ok(Some(JobEvent::ReviseRateInitiated(
                    JobReviseRateInitiated {
                        job_id: decoded_data.job.encode_hex_with_prefix(),
                        new_rate: decoded_data.newRate,
                    },
                )))
            }
            Some(&Market::JobReviseRateCancelled::SIGNATURE_HASH) => {
                let decoded_data =
                    Market::JobReviseRateCancelled::decode_log(&self.0.inner)
                        .context("Failed to abi decode JobReviseRateCancelled event data")?
                        .data;

                Ok(Some(JobEvent::ReviseRateCancelled(
                    JobReviseRateCancelled {
                        job_id: decoded_data.job.encode_hex_with_prefix(),
                    },
                )))
            }
            Some(&Market::JobReviseRateFinalized::SIGNATURE_HASH) => {
                let decoded_data =
                    Market::JobReviseRateFinalized::decode_log(&self.0.inner)
                        .context("Failed to abi decode JobReviseRateFinalized event data")?
                        .data;

                Ok(Some(JobEvent::ReviseRateFinalized(
                    JobReviseRateFinalized {
                        job_id: decoded_data.job.encode_hex_with_prefix(),
                        new_rate: decoded_data.newRate,
                    },
                )))
            }
            Some(&Market::JobMetadataUpdated::SIGNATURE_HASH) => {
                let decoded_data = Market::JobMetadataUpdated::decode_log(&self.0.inner)
                    .context("Failed to abi decode JobMetadataUpdated event data")?
                    .data;

                Ok(Some(JobEvent::MetadataUpdated(JobMetadataUpdated {
                    job_id: decoded_data.job.encode_hex_with_prefix(),
                    new_metadata: decoded_data.metadata,
                })))
            }
            _ => Ok(None), // unknown event, skip
        }
    }
}

#[derive(Clone)]
pub struct ArbProvider {
    pub rpc_url: Url,
    pub contract: Address,
    pub rt: Arc<tokio::runtime::Runtime>,
}

impl ChainHandler for ArbProvider {
    type RawLog = ArbLog;

    fn fetch_chain_id(&mut self) -> Result<String> {
        self.rt.block_on(async {
            let provider = RootProvider::<Ethereum>::new_http(self.rpc_url.clone());
            let chain_id = Retry::spawn(
                ExponentialBackoff::from_millis(500)
                    .max_delay(Duration::from_secs(10))
                    .map(jitter),
                || async { provider.get_chain_id().await },
            )
            .await
            .context("Failed to fetch chain ID from the RPC")?;
            Ok(chain_id.to_string())
        })
    }

    fn fetch_latest_block(&mut self) -> Result<u64> {
        self.rt.block_on(async {
            let provider = RootProvider::<Ethereum>::new_http(self.rpc_url.clone());
            let block_number = Retry::spawn(
                ExponentialBackoff::from_millis(500)
                    .max_delay(Duration::from_secs(10))
                    .map(jitter),
                || async { provider.get_block_number().await },
            )
            .await
            .context("Failed to fetch latest block number from the RPC")?;
            Ok(block_number)
        })
    }

    fn fetch_logs_and_group_by_block(
        &self,
        start_block: u64,
        end_block: u64,
    ) -> Result<BTreeMap<u64, Vec<ArbLog>>> {
        self.rt.block_on(async {
            let provider = Arc::new(RootProvider::<Ethereum>::new_http(self.rpc_url.clone()));
            let logs = Retry::spawn(
                ExponentialBackoff::from_millis(500)
                    .max_delay(Duration::from_secs(10))
                    .map(jitter),
                || async {
                    provider
                        .get_logs(
                            &Filter::new()
                                .events(vec![
                                    Market::JobOpened::SIGNATURE,
                                    Market::JobSettled::SIGNATURE,
                                    Market::JobClosed::SIGNATURE,
                                    Market::JobDeposited::SIGNATURE,
                                    Market::JobWithdrew::SIGNATURE,
                                    Market::JobReviseRateInitiated::SIGNATURE,
                                    Market::JobReviseRateCancelled::SIGNATURE,
                                    Market::JobReviseRateFinalized::SIGNATURE,
                                    Market::JobMetadataUpdated::SIGNATURE,
                                ])
                                .from_block(start_block)
                                .to_block(end_block)
                                .address(self.contract),
                        )
                        .await
                },
            )
            .await
            .context(format!(
                "Failed to fetch logs for block range ({}, {}) from the RPC",
                start_block, end_block
            ))?;

            let mut block_logs: BTreeMap<u64, Vec<ArbLog>> = BTreeMap::new();
            for log in logs {
                if let Some(block_number) = log.block_number {
                    block_logs
                        .entry(block_number)
                        .or_default()
                        .push(ArbLog(log));
                }
            }

            Ok(block_logs)
        })
    }
}
