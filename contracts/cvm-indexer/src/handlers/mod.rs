use alloy::rpc::types::Log;
use anyhow::Result;
use anyhow::anyhow;
use diesel::PgConnection;
use ethp::event;
use tracing::warn;
use tracing::{info, instrument};

mod provider_added;
use provider_added::handle_provider_added;

mod provider_removed;
use provider_removed::handle_provider_removed;

mod provider_updated;
use provider_updated::handle_provider_updated;

mod job_opened;
use job_opened::handle_job_opened;

mod job_settled;
use job_settled::handle_job_settled;

mod job_closed;
use job_closed::handle_job_closed;

mod job_deposited;
use job_deposited::handle_job_deposited;

mod job_withdrew;
use job_withdrew::handle_job_withdrew;

mod job_revise_rate_initiated;
use job_revise_rate_initiated::handle_job_revise_rate_initiated;

mod job_revise_rate_cancelled;
use job_revise_rate_cancelled::handle_job_revise_rate_cancelled;

mod job_revise_rate_finalized;
use job_revise_rate_finalized::handle_job_revise_rate_finalized;

mod job_metadata_updated;
use job_metadata_updated::handle_job_metadata_updated;

mod lock_created;
use lock_created::handle_lock_created;

mod lock_deleted;
use lock_deleted::handle_lock_deleted;

// provider logs
static PROVIDER_ADDED: [u8; 32] = event!("MarketProviderAdded(address,uint64,string)");
static PROVIDER_REMOVED: [u8; 32] = event!("MarketProviderRemoved(address,uint64)");
static PROVIDER_UPDATED: [u8; 32] = event!("MarketProviderUpdated(address,uint64,string,string)");

// job logs
static JOB_OPENED: [u8; 32] = event!("MarketJobOpened(uint64,uint64,string,address,address)");
static JOB_SETTLED: [u8; 32] = event!("MarketJobSettled(uint64,uint64,uint64,address)");
static JOB_CLOSED: [u8; 32] = event!("MarketJobClosed(uint64,uint64)");
static JOB_DEPOSITED: [u8; 32] = event!("MarketJobDeposited(uint64,uint64,uint64,address)");
static JOB_WITHDREW: [u8; 32] = event!("MarketJobWithdrew(uint64,uint64,uint64,address)");
static JOB_RATE_REVISED: [u8; 32] = event!("MarketJobRateRevised(uint64,uint64,uint64)");
static JOB_METADATA_UPDATED: [u8; 32] = event!("MarketJobMetadataUpdated(uint64,uint64,string)");

// token logs
static TOKEN_DEPOSITED: [u8; 32] = event!("MarketTokenDeposited(uint64,uint64,address,uint64)");
static CREDIT_TOKEN_DEPOSITED: [u8; 32] =
    event!("MarketCreditTokenDeposited(uint64,uint64,address,uint64)");
static TOKEN_WITHDREW: [u8; 32] = event!("MarketTokenWithdrew(uint64,uint64,address,uint64)");
static CREDIT_TOKEN_WITHDREW: [u8; 32] =
    event!("MarketCreditTokenWithdrew(uint64,uint64,address,uint64)");
static TOKEN_SETTLED: [u8; 32] = event!("MarketTokenSettled(uint64,uint64,address,uint64)");
static CREDIT_TOKEN_SETTLED: [u8; 32] =
    event!("MarketCreditTokenSettled(uint64,uint64,address,uint64)");

// ignored logs
static INITIALIZED: [u8; 32] = event!("Initialized(uint8)");
static UPGRADED: [u8; 32] = event!("Upgraded(address)");
static ROLE_GRANTED: [u8; 32] = event!("RoleGranted(bytes32,address,address)");
static NOTICE_PERIOD_UPDATED: [u8; 32] = event!("MarketNoticePeriodUpdated(uint64,uint64)");
static TOKEN_UPDATED: [u8; 32] = event!("MarketTokenUpdated(address,address)");
static CREDIT_TOKEN_UPDATED: [u8; 32] = event!("MarketCreditTokenUpdated(address,address)");

#[instrument(
    level = "info",
    skip_all,
    parent = None,
    fields(block = log.block_number, idx = log.log_index, tx = ?log.transaction_hash)
)]
pub fn handle_log(conn: &mut PgConnection, log: Log) -> Result<()> {
    info!(?log, "processing");

    let log_type = log
        .topic0()
        .ok_or(anyhow!("log does not have topic0, should never happen"))?;

    if log_type == PROVIDER_ADDED {
        handle_provider_added(conn, log)
    } else if log_type == PROVIDER_REMOVED {
        handle_provider_removed(conn, log)
    } else if log_type == PROVIDER_UPDATED {
        handle_provider_updated(conn, log)
    } else if log_type == JOB_OPENED {
        handle_job_opened(conn, log)
    } else if log_type == JOB_SETTLED {
        handle_job_settled(conn, log)
    } else if log_type == JOB_CLOSED {
        handle_job_closed(conn, log, provider)
    } else if log_type == JOB_DEPOSITED {
        handle_job_deposited(conn, log)
    } else if log_type == JOB_WITHDREW {
        handle_job_withdrew(conn, log)
    } else if log_type == JOB_REVISE_RATE_INITIATED {
        handle_job_revise_rate_initiated(conn, log)
    } else if log_type == JOB_REVISE_RATE_CANCELLED {
        handle_job_revise_rate_cancelled(conn, log)
    } else if log_type == JOB_REVISE_RATE_FINALIZED {
        handle_job_revise_rate_finalized(conn, log, provider)
    } else if log_type == JOB_METADATA_UPDATED {
        handle_job_metadata_updated(conn, log)
    } else if log_type == LOCK_CREATED {
        handle_lock_created(conn, log)
    } else if log_type == LOCK_DELETED {
        handle_lock_deleted(conn, log)
    } else if log_type == UPGRADED
        || log_type == LOCK_WAIT_TIME_UPDATED
        || log_type == ROLE_GRANTED
        || log_type == TOKEN_UPDATED
        || log_type == INITIALIZED
    {
        info!(?log_type, "ignoring log type");
        Ok(())
    } else {
        warn!(?log_type, "unknown log type");
        Ok(())
    }
}

#[cfg(test)]
mod test_utils {
    mod test_db;

    pub use test_db::TestDb;
}
