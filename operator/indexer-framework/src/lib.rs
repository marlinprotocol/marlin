pub mod chain;
pub mod events;
pub(crate) mod models;
pub(crate) mod schema;

use std::collections::HashSet;

use anyhow::{Context, Result, anyhow};
use diesel::{Connection, ExpressionMethods, PgConnection, QueryDsl, RunQueryDsl};
use diesel_migrations::{EmbeddedMigrations, MigrationHarness, embed_migrations};
use tracing::{info, instrument, warn};

use chain::ChainHandler;

use crate::{
    events::JobEvent,
    models::{JobEventName, JobEventRecord},
};

const MIGRATIONS: EmbeddedMigrations = embed_migrations!("./migrations");

// TODO: add custom errors
#[instrument(level = "info", skip_all, parent = None)]
pub fn run(
    conn: &mut PgConnection,
    rpc_client: &mut impl ChainHandler,
    provider: String,
    start_block: Option<u64>,
    range_size: u64,
) -> Result<()> {
    diesel::sql_query(
        "
        SET statement_timeout = '5s';
        SET lock_timeout = '3s';
        SET idle_in_transaction_session_timeout = '10s';
        ",
    )
    .execute(conn)
    .context("failed to set db timeouts")?;

    // apply migrations
    info!("Applying pending migrations");
    conn.run_pending_migrations(MIGRATIONS)
        .map_err(|e| anyhow::anyhow!("Migrations failed: {}", e))?;
    info!("Applied pending migrations");

    // handle start block
    if let Some(start_block) = start_block {
        start_from(conn, start_block)?;
    }

    // fetch last updated block from the db
    let mut last_updated = schema::sync::table
        .select(schema::sync::block)
        .limit(1)
        .load::<i64>(conn)
        .context("failed to fetch last updated block")?
        .into_iter()
        .last()
        .ok_or(anyhow!(
            "no last updated block found, should never happen unless the database is corrupted"
        ))? as u64;

    info!(block = last_updated, "Resuming from last processed block");

    let mut active_job_ids =
        get_active_jobs(conn).context("Failed to fetch active job IDs from the DB")?;

    loop {
        // fetch latest block from the rpc
        let latest_block = rpc_client
            .fetch_latest_block()
            .context("RPC latest block fetch failed")?;

        info!(block = latest_block, "latest block");

        // should not really ever be true
        // effectively means the rpc was rolled back
        if latest_block < last_updated {
            return Err(anyhow!(
                "RPC {} is behind DB {} (possible rollback)",
                latest_block,
                last_updated
            ));
        }

        // start from the next block to what has already been processed
        let start_block = last_updated + 1;
        // cap block range using range_size
        // might need some babysitting during initial sync
        let end_block = std::cmp::min(start_block + range_size - 1, latest_block);

        info!(start_block, end_block, "Fetching new block range");

        let block_logs = rpc_client
            .fetch_logs(start_block, end_block)
            .context("Failed to fetch logs from the chain")?;

        info!(start_block, end_block, "Processing block range");

        let records = transform_events_into_records(&provider, &block_logs, &mut active_job_ids)
            .context("Failed to transform block logs into DB records")?;

        // execute db writes within a transaction for consistency
        // NOTE: diesel transactions are synchronous, async is not allowed inside
        // might be limiting for certain things like making rpc queries while processing logs
        // using a temporary tokio runtime is a possibility
        conn.transaction(|conn| {
            diesel::insert_into(schema::job_events::table)
                .values(&records)
                .execute(conn)
                .context("failed to insert records")?;
            diesel::update(schema::sync::table)
                .set(schema::sync::block.eq(end_block as i64))
                .execute(conn)
                .context("failed to update latest block")
        })?;

        last_updated = end_block;
    }
}

fn get_active_jobs(conn: &mut PgConnection) -> Result<HashSet<u64>> {
    use crate::models::JobEventName;
    use schema::job_events;

    let opened_jobs = job_events::table
        .select(job_events::job_id)
        .filter(job_events::event_name.eq(JobEventName::Opened))
        .load::<i64>(conn)
        .context("Failed to query opened jobs")?;

    let closed_jobs = job_events::table
        .select(job_events::job_id)
        .filter(job_events::event_name.eq(JobEventName::Closed))
        .load::<i64>(conn)
        .context("Failed to query closed jobs")?;

    let mut active_jobs_set: HashSet<u64> = opened_jobs.into_iter().map(|x| x as u64).collect();
    for closed_job in closed_jobs {
        active_jobs_set.remove(&(closed_job as u64));
    }

    Ok(active_jobs_set)
}

fn transform_events_into_records(
    provider: &str,
    job_events: &[JobEvent],
    active_jobs: &mut HashSet<u64>,
) -> Result<Vec<JobEventRecord>> {
    let mut job_event_records = vec![];

    for job_event in job_events.iter() {
        match job_event {
            JobEvent::Opened(event) => {
                // Check if provider matches the target
                if !event.provider.eq_ignore_ascii_case(provider) {
                    continue;
                }

                active_jobs.insert(event.job_id);
                job_event_records.push(JobEventRecord {
                    job_id: event.job_id as i64,
                    event_name: JobEventName::Opened,
                    event_data: serde_json::to_value(event)
                        .context("Failed to JSON serialize JobOpened event data")?,
                });
            }
            JobEvent::Closed(event) => {
                if !active_jobs.contains(&event.job_id) {
                    continue;
                }

                active_jobs.remove(&event.job_id);
                job_event_records.push(JobEventRecord {
                    job_id: event.job_id as i64,
                    event_name: JobEventName::Closed,
                    event_data: serde_json::to_value(event)
                        .context("Failed to JSON serialize JobClosed event data")?,
                });
            }
            JobEvent::Settled(event) => {
                if !active_jobs.contains(&event.job_id) {
                    continue;
                }

                job_event_records.push(JobEventRecord {
                    job_id: event.job_id as i64,
                    event_name: JobEventName::Settled,
                    event_data: serde_json::to_value(event)
                        .context("Failed to JSON serialize JobSettled event data")?,
                });
            }
            JobEvent::Deposited(event) => {
                if !active_jobs.contains(&event.job_id) {
                    continue;
                }

                job_event_records.push(JobEventRecord {
                    job_id: event.job_id as i64,
                    event_name: JobEventName::Deposited,
                    event_data: serde_json::to_value(event)
                        .context("Failed to JSON serialize JobDeposited event data")?,
                });
            }
            JobEvent::Withdrew(event) => {
                if !active_jobs.contains(&event.job_id) {
                    continue;
                }

                job_event_records.push(JobEventRecord {
                    job_id: event.job_id as i64,
                    event_name: JobEventName::Withdrew,
                    event_data: serde_json::to_value(event)
                        .context("Failed to JSON serialize JobWithdrew event data")?,
                });
            }
            JobEvent::RateRevised(event) => {
                if !active_jobs.contains(&event.job_id) {
                    continue;
                }

                job_event_records.push(JobEventRecord {
                    job_id: event.job_id as i64,
                    event_name: JobEventName::RateRevised,
                    event_data: serde_json::to_value(event)
                        .context("Failed to JSON serialize JobRateRevised event data")?,
                });
            }
            JobEvent::MetadataUpdated(event) => {
                if !active_jobs.contains(&event.job_id) {
                    continue;
                }

                job_event_records.push(JobEventRecord {
                    job_id: event.job_id as i64,
                    event_name: JobEventName::MetadataUpdated,
                    event_data: serde_json::to_value(event)
                        .context("Failed to JSON serialize JobMetadataUpdated event data")?,
                });
            }
        };
    }

    Ok(job_event_records)
}

pub fn start_from(conn: &mut PgConnection, start: u64) -> Result<bool> {
    // set start block if it is less than existing
    diesel::update(schema::sync::table)
        .filter(schema::sync::block.lt(start as i64 - 1))
        .set(schema::sync::block.eq(start as i64 - 1))
        .execute(conn)
        .map(|x| x > 0)
        .context("failed to set start block")
}
