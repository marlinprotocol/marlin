use crate::schema::jobs;
use crate::schema::rate_revisions;
use alloy::rpc::types::Log;
use alloy::sol_types::SolValue;
use anyhow::Context;
use anyhow::Result;
use diesel::ExpressionMethods;
use diesel::PgConnection;
use diesel::QueryDsl;
use diesel::RunQueryDsl;
use tracing::{info, instrument};

#[instrument(level = "info", skip_all, parent = None, fields(block = log.block_number, idx = log.log_index))]
pub fn handle_job_rate_revised(conn: &mut PgConnection, log: Log) -> Result<()> {
    info!(?log, "processing");

    let id = u64::from_be_bytes(log.topics()[1].0[24..32].try_into().unwrap()) as i64;
    let (timestamp_u64, new_rate_u64) = <(u64, u64)>::abi_decode_sequence(&log.data().data)?;

    let timestamp =
        std::time::SystemTime::UNIX_EPOCH + std::time::Duration::from_secs(timestamp_u64);
    let new_rate = new_rate_u64 as i64;

    let block = log
        .block_number
        .ok_or(anyhow::anyhow!("did not get block from log"))?;
    let idx = log
        .log_index
        .ok_or(anyhow::anyhow!("did not get index from log"))?;

    // we want to update if job exists and is not closed
    // we want to error out if job does not exist or is closed

    info!(id, new_rate, "revising job rate");

    // target sql:
    // SELECT balance FROM jobs
    // WHERE id = <id> AND is_closed = false;
    let balance = jobs::table
        .filter(jobs::id.eq(&id))
        .filter(jobs::is_closed.eq(false))
        .select(jobs::balance)
        .get_result::<i64>(conn);

    let Ok(balance) = balance else {
        // !!! should never happen
        // the only reason this would happen is if the job does not exist or is closed
        // we error out for now, can consider just moving on
        return Err(anyhow::anyhow!("failed to find balance for job"));
    };

    let duration = if new_rate > 0 {
        std::time::Duration::from_secs((balance as u64).saturating_div(new_rate as u64))
    } else {
        std::time::Duration::from_secs(0)
    };

    let expires_at = timestamp + duration;

    info!(id, ?balance, ?new_rate, ?expires_at, "computed expires_at");

    // target sql:
    // UPDATE jobs
    // SET rate = <new_rate>, expires_at = <expires_at>
    // WHERE id = <id>
    // AND is_closed = false;
    let count = diesel::update(jobs::table)
        .set((jobs::rate.eq(new_rate), jobs::expires_at.eq(expires_at)))
        .filter(jobs::id.eq(&id))
        // we want to detect if job is closed
        // we do it by only updating rows where is_closed is false
        // and later checking if any rows were updated
        .filter(jobs::is_closed.eq(false))
        .execute(conn)
        .context("failed to update job rate")?;

    if count != 1 {
        // !!! should never happen
        // we have failed to make any changes
        // the only real condition is when the job does not exist or is closed
        // we error out for now, can consider just moving on
        return Err(anyhow::anyhow!("could not find job"));
    }

    // target sql:
    // INSERT INTO rate_revisions (job, value, block, idx, timestamp)
    // VALUES (<id>, <new_rate>, <block>, <idx>, <timestamp>);
    diesel::insert_into(rate_revisions::table)
        .values((
            rate_revisions::job.eq(id),
            rate_revisions::value.eq(new_rate),
            rate_revisions::block.eq(block as i64),
            rate_revisions::idx.eq(idx as i64),
            rate_revisions::timestamp.eq(timestamp),
        ))
        .execute(conn)
        .context("failed to insert rate revision")?;

    info!(id, new_rate, "revised job rate");

    Ok(())
}

#[cfg(test)]
mod tests {
    use alloy::primitives::U256;
    use alloy::{primitives::LogData, rpc::types::Log};
    use anyhow::Result;
    use diesel::QueryDsl;
    use ethp::keccak256;
    use std::time::{Duration, SystemTime, UNIX_EPOCH};

    use crate::handlers::JOB_RATE_REVISED;
    use crate::handlers::handle_log;
    use crate::handlers::test_utils::TestDb;

    use super::*;

    #[test]
    fn test_revise_rate_for_existing_job() -> Result<()> {
        let mut db = TestDb::new();
        let conn = &mut db.conn;

        let contract = "0x1111111111111111111111111111111111111111".parse()?;

        let other_ts = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs() / 2;
        let other_st = UNIX_EPOCH + Duration::from_secs(other_ts);

        diesel::insert_into(jobs::table)
            .values((
                jobs::id.eq(123456789i64),
                jobs::owner.eq("0xbBbBBBBbbBBBbbbBbbBbbbbBBbBbbbbBbBbbBBbB"),
                jobs::provider.eq("0xaAaAaAaaAaAaAaaAaAAAAAAAAaaaAaAaAaaAaaAa"),
                jobs::metadata.eq("some metadata"),
                jobs::rate.eq(100i64),
                jobs::balance.eq(1000i64),
                jobs::last_settled_at.eq(other_st),
                jobs::created_at.eq(other_st),
                jobs::is_closed.eq(false),
                jobs::expires_at.eq(other_st),
            ))
            .execute(conn)?;

        assert_eq!(jobs::table.count().get_result(conn), Ok(1));
        assert_eq!(
            jobs::table.select(jobs::all_columns).first(conn),
            Ok((
                123456789i64,
                "some metadata".to_owned(),
                "0xbBbBBBBbbBBBbbbBbbBbbbbBBbBbbbbBbBbbBBbB".to_owned(),
                "0xaAaAaAaaAaAaAaaAaAAAAAAAAaaaAaAaAaaAaaAa".to_owned(),
                100i64,
                1000i64,
                other_st,
                other_st,
                other_st,
                false,
            ))
        );
        assert_eq!(rate_revisions::table.count().get_result(conn), Ok(0));

        let now_ts = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
        let now_st = UNIX_EPOCH + Duration::from_secs(now_ts);

        // log under test
        let log = Log {
            block_hash: Some(keccak256!("some block").into()),
            block_number: Some(42),
            block_timestamp: None,
            log_index: Some(69),
            transaction_hash: Some(keccak256!("some tx").into()),
            transaction_index: Some(420),
            removed: false,
            inner: alloy::primitives::Log {
                address: contract,
                data: LogData::new(
                    vec![JOB_RATE_REVISED.into(), U256::from(123456789).into()],
                    (now_ts, 20u64).abi_encode_sequence().into(), // New rate is 20
                )
                .unwrap(),
            },
        };

        handle_log(conn, log)?;

        assert_eq!(jobs::table.count().get_result(conn), Ok(1));
        assert_eq!(
            jobs::table.select(jobs::all_columns).first(conn),
            Ok((
                123456789i64,
                "some metadata".to_owned(),
                "0xbBbBBBBbbBBBbbbBbbBbbbbBBbBbbbbBbBbbBBbB".to_owned(),
                "0xaAaAaAaaAaAaAaaAaAAAAAAAAaaaAaAaAaaAaaAa".to_owned(),
                20i64,   // New rate
                1000i64, // Balance unchanged
                other_st,
                now_st + std::time::Duration::from_secs(50), // 1000 / 20 = 50 seconds from timestamp
                other_st,
                false,
            ))
        );

        assert_eq!(rate_revisions::table.count().get_result(conn), Ok(1));
        assert_eq!(
            rate_revisions::table
                .select(rate_revisions::all_columns)
                .first(conn),
            Ok((Some(123456789i64), 20i64, now_st, 42i64, 69i64))
        );

        Ok(())
    }

    #[test]
    fn test_revise_rate_for_non_existent_job() -> Result<()> {
        let mut db = TestDb::new();
        let conn = &mut db.conn;

        let contract = "0x1111111111111111111111111111111111111111".parse()?;

        assert_eq!(jobs::table.count().get_result(conn), Ok(0));
        assert_eq!(rate_revisions::table.count().get_result(conn), Ok(0));

        let now_ts = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();

        // log under test
        let log = Log {
            block_hash: Some(keccak256!("some block").into()),
            block_number: Some(42),
            block_timestamp: None,
            log_index: Some(69),
            transaction_hash: Some(keccak256!("some tx").into()),
            transaction_index: Some(420),
            removed: false,
            inner: alloy::primitives::Log {
                address: contract,
                data: LogData::new(
                    vec![JOB_RATE_REVISED.into(), U256::from(123456789).into()],
                    (now_ts, 20u64).abi_encode_sequence().into(),
                )
                .unwrap(),
            },
        };

        let res = handle_log(conn, log);

        assert_eq!(
            format!("{:?}", res.unwrap_err()),
            "failed to find balance for job"
        );
        assert_eq!(jobs::table.count().get_result(conn), Ok(0));

        Ok(())
    }

    #[test]
    fn test_revise_rate_for_closed_job() -> Result<()> {
        let mut db = TestDb::new();
        let conn = &mut db.conn;

        let contract = "0x1111111111111111111111111111111111111111".parse()?;

        let other_ts = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs() / 2;
        let other_st = UNIX_EPOCH + Duration::from_secs(other_ts);

        diesel::insert_into(jobs::table)
            .values((
                jobs::id.eq(123456789i64),
                jobs::owner.eq("0xbBbBBBBbbBBBbbbBbbBbbbbBBbBbbbbBbBbbBBbB"),
                jobs::provider.eq("0xaAaAaAaaAaAaAaaAaAAAAAAAAaaaAaAaAaaAaaAa"),
                jobs::metadata.eq("some metadata"),
                jobs::rate.eq(100i64),
                jobs::balance.eq(1000i64),
                jobs::last_settled_at.eq(other_st),
                jobs::created_at.eq(other_st),
                jobs::is_closed.eq(true),
                jobs::expires_at.eq(other_st),
            ))
            .execute(conn)?;

        assert_eq!(jobs::table.count().get_result(conn), Ok(1));
        assert_eq!(
            jobs::table.select(jobs::all_columns).first(conn),
            Ok((
                123456789i64,
                "some metadata".to_owned(),
                "0xbBbBBBBbbBBBbbbBbbBbbbbBBbBbbbbBbBbbBBbB".to_owned(),
                "0xaAaAaAaaAaAaAaaAaAAAAAAAAaaaAaAaAaaAaaAa".to_owned(),
                100i64,
                1000i64,
                other_st,
                other_st,
                other_st,
                true,
            ))
        );
        assert_eq!(rate_revisions::table.count().get_result(conn), Ok(0));

        let now_ts = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();

        // log under test
        let log = Log {
            block_hash: Some(keccak256!("some block").into()),
            block_number: Some(42),
            block_timestamp: None,
            log_index: Some(69),
            transaction_hash: Some(keccak256!("some tx").into()),
            transaction_index: Some(420),
            removed: false,
            inner: alloy::primitives::Log {
                address: contract,
                data: LogData::new(
                    vec![JOB_RATE_REVISED.into(), U256::from(123456789).into()],
                    (now_ts, 20u64).abi_encode_sequence().into(),
                )
                .unwrap(),
            },
        };

        let res = handle_log(conn, log);

        assert_eq!(
            format!("{:?}", res.unwrap_err()),
            "failed to find balance for job"
        );
        assert_eq!(jobs::table.count().get_result(conn), Ok(1));
        assert_eq!(rate_revisions::table.count().get_result(conn), Ok(0)); // No rate revision recorded

        Ok(())
    }
}
