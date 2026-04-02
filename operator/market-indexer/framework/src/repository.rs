use std::collections::HashSet;

use anyhow::{Context, Result};
use diesel::prelude::*;
use diesel::r2d2::{ConnectionManager, Pool};
use diesel_migrations::{embed_migrations, EmbeddedMigrations, MigrationHarness};

use crate::models::JobEventRecord;
use crate::schema::{indexer_state, job_events};

pub const MIGRATIONS: EmbeddedMigrations = embed_migrations!("../framework/migrations");

#[derive(Clone)]
pub struct Repository {
    pub pool: Pool<ConnectionManager<PgConnection>>,
}



impl Repository {
    pub async fn new(db_url: String) -> Result<Self> {
        let manager = ConnectionManager::<PgConnection>::new(db_url);
        let pool = Pool::builder()
            .max_size(5)
            .build(manager)
            .context("Failed to create the connection pool")?;

        Ok(Self { pool })
    }

    pub async fn apply_migrations(&self) -> Result<()> {
        let pool = self.pool.clone();
        tokio::task::spawn_blocking(move || {
            let mut conn = pool.get().context("Failed to get connection")?;
            conn.run_pending_migrations(MIGRATIONS)
                .map_err(|e| anyhow::anyhow!("Migrations failed: {}", e))?;
            Ok::<(), anyhow::Error>(())
        })
        .await
        .context("Task panicked")??;

        Ok(())
    }

    pub async fn update_indexer_state(
        &self,
        chain_id_val: String,
        extra_decimals_val: i64,
        start_block: Option<i64>,
    ) -> Result<u64> {
        let pool = self.pool.clone();
        tokio::task::spawn_blocking(move || {
            let mut conn = pool.get().context("Failed to get connection")?;

            let rows_affected = match start_block {
                Some(block) => {
                    diesel::update(indexer_state::table.find(1))
                        .set((
                            indexer_state::chain_id.eq(chain_id_val),
                            indexer_state::extra_decimals.eq(extra_decimals_val),
                            indexer_state::last_processed_block.eq(block - 1),
                            indexer_state::updated_at.eq(diesel::dsl::now),
                        ))
                        .execute(&mut conn)
                        .context("Failed to execute update query in 'indexer state' table")?
                }
                None => {
                    diesel::update(indexer_state::table.find(1))
                        .set((
                            indexer_state::chain_id.eq(chain_id_val),
                            indexer_state::extra_decimals.eq(extra_decimals_val),
                            indexer_state::updated_at.eq(diesel::dsl::now),
                        ))
                        .execute(&mut conn)
                        .context("Failed to execute update query in 'indexer state' table")?
                }
            };

            Ok(rows_affected as u64)
        })
        .await
        .context("Task panicked")?
    }

    pub async fn get_last_processed_block(&self) -> Result<i64> {
        let pool = self.pool.clone();
        tokio::task::spawn_blocking(move || {
            let mut conn = pool.get().context("Failed to get connection")?;
            
            let last_processed_block = indexer_state::table
                .select(indexer_state::last_processed_block)
                .filter(indexer_state::id.eq(1))
                .first::<i64>(&mut conn)
                .context("Failed to query last processed block from 'indexer_state' table")?;
                
            Ok(last_processed_block)
        })
        .await
        .context("Task panicked")?
    }

    pub async fn get_active_jobs(&self) -> Result<HashSet<String>> {
        let pool = self.pool.clone();
        tokio::task::spawn_blocking(move || {
            use crate::models::JobEventName;
            
            let mut conn = pool.get().context("Failed to get connection")?;

            let opened_jobs: Vec<String> = job_events::table
                .select(job_events::job_id)
                .filter(job_events::event_name.eq(JobEventName::Opened))
                .load(&mut conn)
                .context("Failed to query opened jobs")?;
                
            let closed_jobs: Vec<String> = job_events::table
                .select(job_events::job_id)
                .filter(job_events::event_name.eq(JobEventName::Closed))
                .load(&mut conn)
                .context("Failed to query closed jobs")?;

            let mut active_jobs_set: HashSet<String> = opened_jobs.into_iter().collect();
            for closed_job in closed_jobs {
                active_jobs_set.remove(&closed_job);
            }

            Ok(active_jobs_set)
        })
        .await
        .context("Task panicked")?
    }

    pub async fn insert_batch(
        &self,
        records: Vec<JobEventRecord>,
        block: i64,
    ) -> Result<(u64, u64)> {
        let pool = self.pool.clone();
        tokio::task::spawn_blocking(move || {
            let mut conn = pool.get().context("Failed to get connection")?;
            
            conn.transaction::<_, diesel::result::Error, _>(|conn| {
                let inserted_batch = diesel::insert_into(job_events::table)
                    .values(&records)
                    .execute(conn)?;

                let updated = diesel::update(indexer_state::table.find(1))
                    .set((
                        indexer_state::last_processed_block.eq(block),
                        indexer_state::updated_at.eq(diesel::dsl::now),
                    ))
                    .execute(conn)?;

                Ok((inserted_batch as u64, updated as u64))
            })
            .context("Transaction failed")
        })
        .await
        .context("Task panicked")?
    }
}