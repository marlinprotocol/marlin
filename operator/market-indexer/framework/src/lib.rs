pub mod chain;
pub mod events;
pub(crate) mod models;
pub(crate) mod repository;
pub(crate) mod schema;

use std::cmp::min;
use std::time::Duration;

use anyhow::{Context, Result, anyhow};
use diesel::PgConnection;
use tracing::{debug, info, instrument, trace, warn};

use chain::{ChainHandler, transform_block_logs_into_records};

// Define generic trait for safe integer conversions
pub trait SaturatingConvert<T> {
    fn saturating_to(self) -> T;
}

// usize -> i64
impl SaturatingConvert<i64> for usize {
    fn saturating_to(self) -> i64 {
        if self > i64::MAX as usize {
            i64::MAX
        } else {
            self as i64
        }
    }
}

// u64 -> i64
impl SaturatingConvert<i64> for u64 {
    fn saturating_to(self) -> i64 {
        if self > i64::MAX as u64 {
            i64::MAX
        } else {
            self as i64
        }
    }
}

// i64 -> u64
impl SaturatingConvert<u64> for i64 {
    fn saturating_to(self) -> u64 {
        if self < 0 { 0 } else { self as u64 }
    }
}

const BATCH_THRESHOLD: usize = 100;

// TODO: add custom errors
#[instrument(level = "info", skip_all, parent = None)]
pub fn run(
    conn: &mut PgConnection,
    rpc_client: &mut impl ChainHandler,
    provider: String,
    mut start_block: Option<i64>,
    range_size: u64,
) -> Result<()> {
    let mut last_processed_block_id = repository::get_last_processed_block(conn)
        .context("Missing last processed block (possible DB corruption)")?;

    if let Some(block) = start_block {
        if block <= last_processed_block_id {
            warn!(
                "Provided start block {} is behind the last processed block {}, starting from the later!",
                block, last_processed_block_id
            );
            start_block = None;
        } else {
            last_processed_block_id = block - 1;
        }
    }

    info!(
        last_processed_block_id,
        "Resuming from last processed block"
    );

    let chain_id = rpc_client
        .fetch_chain_id()
        .context("RPC chain ID fetch failed")?;

    let updated = repository::update_indexer_state(conn, chain_id.clone(), start_block)
        .context("Failed to update indexer state in the DB")?;

    info!("Indexer state updated: {}", updated == 1);

    if range_size == 0 {
        return Err(anyhow!("Range size must not be zero"));
    }

    let mut active_job_ids =
        repository::get_active_jobs(conn).context("Failed to fetch active job IDs from the DB")?;

    loop {
        let latest_block = rpc_client
            .fetch_latest_block()
            .context("RPC latest block fetch failed")?;
        let latest_block_i64: i64 = latest_block.saturating_to();

        debug!(latest_block, "Fetched latest block from RPC");

        if latest_block_i64 < last_processed_block_id {
            // warn!(db_block = last_processed_block_id, rpc_block = latest_block_i64, "RPC is behind DB (possible rollback)");
            return Err(anyhow!(
                "RPC {} is behind DB {} (possible rollback)",
                latest_block_i64,
                last_processed_block_id
            ));
        }

        if latest_block_i64 == last_processed_block_id {
            trace!("Up-to-date with RPC, sleeping 5s");
            std::thread::sleep(Duration::from_secs(5));
            continue;
        }

        let start_block: u64 = (last_processed_block_id + 1).saturating_to();
        let end_block = min(start_block + range_size - 1, latest_block);
        info!(start_block, end_block, "Fetching new block range");

        let block_logs = rpc_client
            .fetch_logs_and_group_by_block(start_block, end_block)
            .context("Failed to fetch logs from the chain")?;
        info!(start_block, end_block, "Processing block range");

        let mut end_block_num = last_processed_block_id;
        let mut batch_records = Vec::new();

        for block_number in start_block..=end_block {
            let empty = Vec::new();

            let records = transform_block_logs_into_records(
                &provider,
                block_logs.get(&block_number).unwrap_or(&empty),
                &mut active_job_ids,
            )
            .context("Failed to transform block logs into DB records")?;

            debug!(
                block_number,
                events_count = records.len(),
                "Processing block logs"
            );

            end_block_num = block_number.saturating_to();
            batch_records.extend(records);

            if batch_records.len() >= BATCH_THRESHOLD {
                let (inserted_batch, updated) =
                    repository::insert_batch(conn, batch_records.clone(), end_block_num)
                        .context("DB insert failed for block batch")?;

                debug!(end_block_num, inserted_batch, "Inserted block logs");
                trace!("Last processed block updated: {}", updated == 1);

                batch_records.clear();
                last_processed_block_id = end_block_num;
            }
        }

        if end_block_num > last_processed_block_id {
            let (inserted_batch, updated) =
                repository::insert_batch(conn, batch_records.clone(), end_block_num)
                    .context("DB insert failed for block batch")?;

            debug!(end_block_num, inserted_batch, "Inserted block logs");
            trace!("Last processed block updated: {}", updated == 1);
        }

        last_processed_block_id = end_block_num;
    }
}
