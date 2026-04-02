use std::sync::Arc;
use std::time::Duration;

use alloy::hex::ToHexExt;
use alloy::network::Ethereum;
use alloy::primitives::Address;
use alloy::providers::{Provider, RootProvider};
use alloy::rpc::types::Filter;
use alloy::sol;
use alloy::sol_types::SolEvent;
use alloy::transports::http::reqwest::Url;
use anyhow::{Context, Result};
use indexer_framework::chain::ChainHandler;
use indexer_framework::events::*;
use tokio_retry::Retry;
use tokio_retry::strategy::{ExponentialBackoff, jitter};

sol!(
    #[allow(missing_docs)]
    #[sol(rpc)]
    Market,
    "./abi/Market.json"
);

#[derive(Clone)]
pub struct EvmProvider {
    pub rpc_url: Url,
    pub contract: Address,
    pub rt: Arc<tokio::runtime::Runtime>,
}

impl ChainHandler for EvmProvider {
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

    fn fetch_logs(&self, start_block: u64, end_block: u64) -> Result<Vec<JobEvent>> {
        self.rt.block_on(async {
            let provider = RootProvider::<Ethereum>::new_http(self.rpc_url.clone());
            let logs = Retry::spawn(
                ExponentialBackoff::from_millis(500)
                    .max_delay(Duration::from_secs(10))
                    .map(jitter),
                || async {
                    provider
                        .get_logs(
                            &Filter::new()
                                .events(vec![
                                    Market::MarketJobOpened::SIGNATURE,
                                    Market::MarketJobSettled::SIGNATURE,
                                    Market::MarketJobClosed::SIGNATURE,
                                    Market::MarketJobDeposited::SIGNATURE,
                                    Market::MarketJobWithdrew::SIGNATURE,
                                    Market::MarketJobRateRevised::SIGNATURE,
                                    Market::MarketJobMetadataUpdated::SIGNATURE,
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

            let mut events = Vec::new();

            for log in logs {
                match log.topic0() {
                    Some(&Market::MarketJobOpened::SIGNATURE_HASH) => {
                        let decoded = Market::MarketJobOpened::decode_log(&log.inner)
                            .context("Failed to decode MarketJobOpened")?;
                        let data = decoded.data;
                        events.push(JobEvent::Opened(JobOpened {
                            job_id: data.jobId,
                            owner: data.owner.encode_hex_with_prefix(),
                            provider: data.provider.encode_hex_with_prefix(),
                            metadata: data.metadata,
                            timestamp: data.timestamp,
                        }));
                    }
                    Some(&Market::MarketJobClosed::SIGNATURE_HASH) => {
                        let decoded = Market::MarketJobClosed::decode_log(&log.inner)
                            .context("Failed to decode MarketJobClosed")?;
                        let data = decoded.data;
                        events.push(JobEvent::Closed(JobClosed {
                            job_id: data.jobId,
                            timestamp: data.timestamp,
                        }));
                    }
                    Some(&Market::MarketJobSettled::SIGNATURE_HASH) => {
                        let decoded = Market::MarketJobSettled::decode_log(&log.inner)
                            .context("Failed to decode MarketJobSettled")?;
                        let data = decoded.data;
                        events.push(JobEvent::Settled(JobSettled {
                            job_id: data.jobId,
                            amount: data.amount,
                            timestamp: data.timestamp,
                            to: data.to.encode_hex_with_prefix(),
                        }));
                    }
                    Some(&Market::MarketJobDeposited::SIGNATURE_HASH) => {
                        let decoded = Market::MarketJobDeposited::decode_log(&log.inner)
                            .context("Failed to decode MarketJobDeposited")?;
                        let data = decoded.data;
                        events.push(JobEvent::Deposited(JobDeposited {
                            job_id: data.jobId,
                            from: data.from.encode_hex_with_prefix(),
                            amount: data.amount,
                            timestamp: data.timestamp,
                        }));
                    }
                    Some(&Market::MarketJobWithdrew::SIGNATURE_HASH) => {
                        let decoded = Market::MarketJobWithdrew::decode_log(&log.inner)
                            .context("Failed to decode MarketJobWithdrew")?;
                        let data = decoded.data;
                        events.push(JobEvent::Withdrew(JobWithdrew {
                            job_id: data.jobId,
                            to: data.to.encode_hex_with_prefix(),
                            amount: data.amount,
                            timestamp: data.timestamp,
                        }));
                    }
                    Some(&Market::MarketJobRateRevised::SIGNATURE_HASH) => {
                        let decoded = Market::MarketJobRateRevised::decode_log(&log.inner)
                            .context("Failed to decode MarketJobRateRevised")?;
                        let data = decoded.data;
                        events.push(JobEvent::RateRevised(JobRateRevised {
                            job_id: data.jobId,
                            new_rate: data.newRate,
                            timestamp: data.timestamp,
                        }));
                    }
                    Some(&Market::MarketJobMetadataUpdated::SIGNATURE_HASH) => {
                        let decoded = Market::MarketJobMetadataUpdated::decode_log(&log.inner)
                            .context("Failed to decode MarketJobMetadataUpdated")?;
                        let data = decoded.data;
                        events.push(JobEvent::MetadataUpdated(JobMetadataUpdated {
                            job_id: data.jobId,
                            metadata: data.metadata,
                            timestamp: data.timestamp,
                        }));
                    }
                    _ => {}
                }
            }
            Ok(events)
        })
    }
}
