use std::ops::Sub;

use crate::schema::jobs;
use crate::schema::settlements;
use alloy::rpc::types::Log;
use alloy::sol_types::SolValue;
use anyhow::Context;
use anyhow::Result;
use diesel::ExpressionMethods;
use diesel::PgConnection;
use diesel::RunQueryDsl;
use tracing::{info, instrument};

#[instrument(level = "info", skip_all, parent = None, fields(block = log.block_number, idx = log.log_index))]
pub fn handle_job_settled(conn: &mut PgConnection, log: Log) -> Result<()> {
    info!(?log, "processing");

    let id = u64::from_be_bytes(log.topics()[1].0[24..32].try_into().unwrap()) as i64;
    let (timestamp_u64, amount_u64) = <(u64, u64)>::abi_decode_sequence(&log.data().data)?;

    let timestamp =
        std::time::SystemTime::UNIX_EPOCH + std::time::Duration::from_secs(timestamp_u64);
    let amount = amount_u64 as i64;

    let block = log
        .block_number
        .ok_or(anyhow::anyhow!("did not get block from log"))?;
    let idx = log
        .log_index
        .ok_or(anyhow::anyhow!("did not get index from log"))?;

    // we want to update job and create a settlement if job exists and is not closed
    // we want to error out if job does not exist or is closed

    info!(id, amount, ?timestamp, block, "settling job");

    // target sql:
    // UPDATE jobs
    // SET
    //     balance = balance - <amount>
    //     last_settled_at = <timestamp>
    // WHERE id = '<id>'
    // AND is_closed = false;
    let count = diesel::update(jobs::table)
        .set((
            jobs::balance.eq(jobs::balance.sub(amount)),
            jobs::last_settled_at.eq(timestamp),
        ))
        .filter(jobs::id.eq(id))
        .filter(jobs::is_closed.eq(false))
        .execute(conn)
        .context("failed to update job")?;

    if count != 1 {
        return Err(anyhow::anyhow!("could not find job"));
    }

    // target sql:
    // INSERT INTO settlements (job, amount, timestamp, block, idx)
    // VALUES (<id>, <amount>, <timestamp>, <block>, <idx>);
    diesel::insert_into(settlements::table)
        .values((
            settlements::job.eq(id),
            settlements::amount.eq(amount),
            settlements::timestamp.eq(timestamp),
            settlements::block.eq(block as i64),
            settlements::idx.eq(idx as i64),
        ))
        .execute(conn)
        .context("failed to insert settlement")?;

    info!(id, amount, ?timestamp, "settled job");

    Ok(())
}

#[cfg(test)]
mod tests {
    use alloy::primitives::{Address, U256};
    use alloy::{primitives::LogData, rpc::types::Log};
    use anyhow::Result;
    use diesel::QueryDsl;
    use ethp::keccak256;
    use std::time::{SystemTime, UNIX_EPOCH};

    use crate::handlers::JOB_SETTLED;
    use crate::handlers::handle_log;
    use crate::handlers::test_utils::TestDb;

    use super::*;

    #[test]
    fn test_settle_existing_job() -> Result<()> {
        let mut db = TestDb::new();
        let conn = &mut db.conn;

        let contract = "0x1111111111111111111111111111111111111111".parse()?;

        let other_duration = SystemTime::now().duration_since(UNIX_EPOCH)? / 2;
        let other_st = UNIX_EPOCH + other_duration;

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
        assert_eq!(settlements::table.count().get_result(conn), Ok(0));

        let now_duration = SystemTime::now().duration_since(UNIX_EPOCH)?;
        let now_ts = now_duration.as_secs();
        let now_st = UNIX_EPOCH + std::time::Duration::from_secs(now_ts);

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
                    vec![
                        JOB_SETTLED.into(),
                        U256::from(123456789).into(),
                        "0xCcCcCcCCcCcCcCcCcCcCcCcCcCcCcCcCcCcCcCcC"
                            .parse::<Address>()?
                            .into_word(),
                    ],
                    (now_ts, 200u64).abi_encode_sequence().into(),
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
                100i64,
                800i64,
                now_st,
                other_st,
                other_st,
                false,
            ))
        );

        assert_eq!(settlements::table.count().get_result(conn), Ok(1));
        assert_eq!(
            settlements::table
                .select(settlements::all_columns)
                .first(conn),
            Ok((Some(123456789i64), 200i64, now_st, 42i64, 69i64))
        );

        Ok(())
    }

    #[test]
    fn test_settle_non_existent_job() -> Result<()> {
        let mut db = TestDb::new();
        let conn = &mut db.conn;

        let contract = "0x1111111111111111111111111111111111111111".parse()?;

        assert_eq!(jobs::table.count().get_result(conn), Ok(0));
        assert_eq!(settlements::table.count().get_result(conn), Ok(0));

        let now_duration = SystemTime::now().duration_since(UNIX_EPOCH)?;
        let now_ts = now_duration.as_secs();

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
                    vec![
                        JOB_SETTLED.into(),
                        U256::from(123456789).into(),
                        "0xCcCcCcCCcCcCcCcCcCcCcCcCcCcCcCcCcCcCcCcC"
                            .parse::<Address>()?
                            .into_word(),
                    ],
                    (now_ts, 200u64).abi_encode_sequence().into(),
                )
                .unwrap(),
            },
        };

        let res = handle_log(conn, log);

        assert_eq!(format!("{:?}", res.unwrap_err()), "could not find job");
        assert_eq!(jobs::table.count().get_result(conn), Ok(0));
        assert_eq!(settlements::table.count().get_result(conn), Ok(0));

        Ok(())
    }

    #[test]
    fn test_settle_closed_job() -> Result<()> {
        let mut db = TestDb::new();
        let conn = &mut db.conn;

        let contract = "0x1111111111111111111111111111111111111111".parse()?;

        let other_duration = SystemTime::now().duration_since(UNIX_EPOCH)? / 2;
        let other_st = UNIX_EPOCH + other_duration;

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

        let now_duration = SystemTime::now().duration_since(UNIX_EPOCH)?;
        let now_ts = now_duration.as_secs();

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
                    vec![
                        JOB_SETTLED.into(),
                        U256::from(123456789).into(),
                        "0xCcCcCcCCcCcCcCcCcCcCcCcCcCcCcCcCcCcCcCcC"
                            .parse::<Address>()?
                            .into_word(),
                    ],
                    (now_ts, 200u64).abi_encode_sequence().into(),
                )
                .unwrap(),
            },
        };

        let res = handle_log(conn, log);

        assert_eq!(format!("{:?}", res.unwrap_err()), "could not find job");
        assert_eq!(jobs::table.count().get_result(conn), Ok(1));
        assert_eq!(settlements::table.count().get_result(conn), Ok(0));

        Ok(())
    }
}
