use std::ops::Add;

use crate::schema::job_transactions;
use crate::schema::jobs;
use alloy::rpc::types::Log;
use alloy::sol_types::SolValue;
use anyhow::Context;
use anyhow::Result;
use anyhow::anyhow;
use diesel::ExpressionMethods;
use diesel::PgConnection;
use diesel::QueryDsl;
use diesel::RunQueryDsl;
use diesel::data_types::PgInterval;
use tracing::{info, instrument};

#[instrument(level = "info", skip_all, parent = None, fields(block = log.block_number, idx = log.log_index))]
pub fn handle_job_deposited(conn: &mut PgConnection, log: Log) -> Result<()> {
    info!(?log, "processing");

    let id = u64::from_be_bytes(log.topics()[1].0[24..32].try_into().unwrap()) as i64;
    let (timestamp_u64, amount_u64) = <(u64, u64)>::abi_decode_sequence(&log.data().data)?;

    let timestamp =
        std::time::SystemTime::UNIX_EPOCH + std::time::Duration::from_secs(timestamp_u64);
    let amount = amount_u64 as i64;

    let block = log
        .block_number
        .ok_or(anyhow!("did not get block from log"))?;
    let idx = log.log_index.ok_or(anyhow!("did not get index from log"))?;
    let tx_hash = log
        .transaction_hash
        .ok_or(anyhow!("did not get tx hash from log"))?
        .to_string();

    // we want to update if job exists and is not closed
    // we want to error out if job does not exist or is closed

    info!(id, amount, "depositing into job");

    // target sql:
    // SELECT rate FROM jobs
    // WHERE id = "<id>"
    // AND is_closed = false;
    let rate = jobs::table
        .select(jobs::rate)
        .filter(jobs::id.eq(&id))
        .filter(jobs::is_closed.eq(false))
        .get_result::<i64>(conn);

    let Ok(rate) = rate else {
        // !!! should never happen
        // the only reason this would happen is if the job does not exist or is closed
        // we error out for now, can consider just moving on
        return Err(anyhow::anyhow!("failed to find rate for job"));
    };

    let additional_duration = if rate != 0 {
        std::time::Duration::from_secs((amount as u64).saturating_div(rate as u64))
    } else {
        std::time::Duration::from_secs(0)
    };

    info!(id, ?rate, ?additional_duration, "duration added");

    // target sql:
    // UPDATE jobs
    // SET
    //     balance = balance + <amount>,
    //     expires_at = expires_at + <additional_duration>
    // WHERE id = <id>
    // AND is_closed = false;
    let count = diesel::update(jobs::table)
        .set((
            jobs::balance.eq(jobs::balance.add(amount)),
            jobs::expires_at.eq(jobs::expires_at.add(PgInterval::from_microseconds(
                additional_duration.as_micros().clamp(0, i64::MAX as u128) as i64,
            ))),
        ))
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

    // target sql:
    // INSERT INTO job_transactions (block, idx, job, amount, is_deposit, tx_hash, timestamp)
    // VALUES (<block>, <idx>, <job>, <amount>, true, <tx_hash>, <timestamp>);
    diesel::insert_into(job_transactions::table)
        .values((
            job_transactions::block.eq(block as i64),
            job_transactions::idx.eq(idx as i64),
            job_transactions::tx_hash.eq(tx_hash),
            job_transactions::job.eq(&id),
            job_transactions::amount.eq(&amount),
            job_transactions::is_deposit.eq(true),
            job_transactions::timestamp.eq(timestamp),
        ))
        .execute(conn)
        .context("failed to create deposit")?;

    info!(id, amount, "deposited into job");

    Ok(())
}

#[cfg(test)]
mod tests {
    use alloy::hex::ToHexExt;
    use alloy::primitives::{Address, U256};
    use alloy::{primitives::LogData, rpc::types::Log};
    use anyhow::Result;
    use diesel::QueryDsl;
    use ethp::keccak256;
    use std::time::{SystemTime, UNIX_EPOCH};

    use crate::handlers::JOB_DEPOSITED;
    use crate::handlers::handle_log;
    use crate::handlers::test_utils::TestDb;

    use super::*;

    #[test]
    fn test_deposit_into_existing_job() -> Result<()> {
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
        assert_eq!(job_transactions::table.count().get_result(conn), Ok(0));

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
                        JOB_DEPOSITED.into(),
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
                1200i64, // 1000 + 200
                other_st,
                other_st + std::time::Duration::from_secs(2), // 200 amount / 100 rate = 2 seconds added
                other_st,
                false,
            ))
        );

        assert_eq!(job_transactions::table.count().get_result(conn), Ok(1));
        assert_eq!(
            job_transactions::table
                .select(job_transactions::all_columns)
                .first(conn),
            Ok((
                123456789i64,
                200i64,
                true,
                now_st,
                keccak256!("some tx").encode_hex_with_prefix(),
                42i64,
                69i64,
            ))
        );

        Ok(())
    }

    #[test]
    fn test_deposit_into_non_existent_job() -> Result<()> {
        let mut db = TestDb::new();
        let conn = &mut db.conn;

        let contract = "0x1111111111111111111111111111111111111111".parse()?;

        assert_eq!(jobs::table.count().get_result(conn), Ok(0));
        assert_eq!(job_transactions::table.count().get_result(conn), Ok(0));

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
                        JOB_DEPOSITED.into(),
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

        assert_eq!(
            format!("{:?}", res.unwrap_err()),
            "failed to find rate for job"
        );
        assert_eq!(jobs::table.count().get_result(conn), Ok(0));
        assert_eq!(job_transactions::table.count().get_result(conn), Ok(0));

        Ok(())
    }

    #[test]
    fn test_deposit_into_closed_job() -> Result<()> {
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
        assert_eq!(job_transactions::table.count().get_result(conn), Ok(0));

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
                        JOB_DEPOSITED.into(),
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

        assert_eq!(
            format!("{:?}", res.unwrap_err()),
            "failed to find rate for job"
        );
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

        assert_eq!(job_transactions::table.count().get_result(conn), Ok(0));

        Ok(())
    }
}
