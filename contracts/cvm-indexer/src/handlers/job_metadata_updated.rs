use crate::schema::jobs;
use alloy::rpc::types::Log;
use alloy::sol_types::SolValue;
use anyhow::Context;
use anyhow::Result;
use diesel::ExpressionMethods;
use diesel::PgConnection;
use diesel::RunQueryDsl;
use tracing::{info, instrument};

#[instrument(level = "info", skip_all, parent = None, fields(block = log.block_number, idx = log.log_index))]
pub fn handle_job_metadata_updated(conn: &mut PgConnection, log: Log) -> Result<()> {
    info!(?log, "processing");

    let id = u64::from_be_bytes(log.topics()[1].0[24..32].try_into().unwrap()) as i64;
    let (_timestamp, metadata) = <(u64, String)>::abi_decode_sequence(&log.data().data)?;

    // we want to update if job exists and is not closed
    // we want to error out if job does not exist or is closed

    info!(id, ?metadata, "updating job metadata");

    // target sql:
    // UPDATE jobs
    // SET metadata = "<metadata>"
    // WHERE id = <id>
    // AND is_closed = false;
    let count = diesel::update(jobs::table)
        .set(jobs::metadata.eq(&metadata))
        .filter(jobs::id.eq(&id))
        // we want to detect if job is closed
        // we do it by only updating rows where is_closed is false
        // and later checking if any rows were updated
        .filter(jobs::is_closed.eq(false))
        .execute(conn)
        .context("failed to update job")?;

    if count != 1 {
        // !!! should never happen
        // we have failed to make any changes
        // the only real condition is when the job does not exist or is closed
        // we error out for now, can consider just moving on
        return Err(anyhow::anyhow!("could not find job"));
    }

    info!(id, ?metadata, "updated job metadata");

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

    use crate::handlers::JOB_METADATA_UPDATED;
    use crate::handlers::handle_log;
    use crate::handlers::test_utils::TestDb;

    use super::*;

    #[test]
    fn test_job_metadata_update() -> Result<()> {
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
                    vec![JOB_METADATA_UPDATED.into(), U256::from(123456789).into()],
                    (now_ts, "some random metadata".to_string())
                        .abi_encode_sequence()
                        .into(),
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
                "some random metadata".to_owned(),
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

        Ok(())
    }

    #[test]
    fn test_job_metadata_update_for_non_existent_job() -> Result<()> {
        let mut db = TestDb::new();
        let conn = &mut db.conn;

        let contract = "0x1111111111111111111111111111111111111111".parse()?;

        assert_eq!(jobs::table.count().get_result(conn), Ok(0));

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
                    vec![JOB_METADATA_UPDATED.into(), U256::from(123456789).into()],
                    (now_ts, "some random metadata".to_string())
                        .abi_encode_sequence()
                        .into(),
                )
                .unwrap(),
            },
        };

        let res = handle_log(conn, log);

        assert_eq!(format!("{:?}", res.unwrap_err()), "could not find job");
        assert_eq!(jobs::table.count().get_result(conn), Ok(0));

        Ok(())
    }

    #[test]
    fn test_job_metadata_update_for_closed_job() -> Result<()> {
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
                    vec![JOB_METADATA_UPDATED.into(), U256::from(123456789).into()],
                    (now_ts, "some random metadata".to_string())
                        .abi_encode_sequence()
                        .into(),
                )
                .unwrap(),
            },
        };

        let res = handle_log(conn, log);

        assert_eq!(format!("{:?}", res.unwrap_err()), "could not find job");
        assert_eq!(jobs::table.count().get_result(conn), Ok(1));

        Ok(())
    }
}
