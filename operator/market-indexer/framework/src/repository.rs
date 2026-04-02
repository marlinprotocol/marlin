use std::collections::HashSet;

use anyhow::{Context, Result};
use diesel::prelude::*;

use crate::models::JobEventRecord;
use crate::schema::{indexer_state, job_events};

pub fn update_indexer_state(
    conn: &mut PgConnection,
    chain_id_val: String,
    start_block: Option<i64>,
) -> Result<u64> {
    let rows_affected = match start_block {
        Some(block) => diesel::update(indexer_state::table.find(1))
            .set((
                indexer_state::chain_id.eq(chain_id_val),
                indexer_state::last_processed_block.eq(block - 1),
            ))
            .execute(conn)
            .context("Failed to execute update query in 'indexer state' table")?,
        None => diesel::update(indexer_state::table.find(1))
            .set(indexer_state::chain_id.eq(chain_id_val))
            .execute(conn)
            .context("Failed to execute update query in 'indexer state' table")?,
    };

    Ok(rows_affected as u64)
}

pub fn get_last_processed_block(conn: &mut PgConnection) -> Result<i64> {
    let last_processed_block = indexer_state::table
        .select(indexer_state::last_processed_block)
        .filter(indexer_state::id.eq(1))
        .first::<i64>(conn)
        .context("Failed to query last processed block from 'indexer_state' table")?;

    Ok(last_processed_block)
}

pub fn get_active_jobs(conn: &mut PgConnection) -> Result<HashSet<String>> {
    use crate::models::JobEventName;

    let opened_jobs: Vec<String> = job_events::table
        .select(job_events::job_id)
        .filter(job_events::event_name.eq(JobEventName::Opened))
        .load(conn)
        .context("Failed to query opened jobs")?;

    let closed_jobs: Vec<String> = job_events::table
        .select(job_events::job_id)
        .filter(job_events::event_name.eq(JobEventName::Closed))
        .load(conn)
        .context("Failed to query closed jobs")?;

    let mut active_jobs_set: HashSet<String> = opened_jobs.into_iter().collect();
    for closed_job in closed_jobs {
        active_jobs_set.remove(&closed_job);
    }

    Ok(active_jobs_set)
}

pub fn insert_batch(
    conn: &mut PgConnection,
    records: Vec<JobEventRecord>,
    block: i64,
) -> Result<(u64, u64)> {
    conn.transaction::<_, diesel::result::Error, _>(|conn| {
        let inserted_batch = diesel::insert_into(job_events::table)
            .values(&records)
            .execute(conn)?;

        let updated = diesel::update(indexer_state::table.find(1))
            .set(indexer_state::last_processed_block.eq(block))
            .execute(conn)?;

        Ok((inserted_batch as u64, updated as u64))
    })
    .context("Transaction failed")
}
