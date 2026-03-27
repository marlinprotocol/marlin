use crate::schema::jobs;
use alloy::primitives::Address;
use alloy::rpc::types::Log;
use alloy::sol_types::SolValue;
use anyhow::Context;
use anyhow::Result;
use diesel::ExpressionMethods;
use diesel::PgConnection;
use diesel::RunQueryDsl;
use tracing::warn;
use tracing::{info, instrument};

#[instrument(level = "info", skip_all, parent = None, fields(block = log.block_number, idx = log.log_index))]
pub fn handle_job_opened(conn: &mut PgConnection, log: Log) -> Result<()> {
    info!(?log, "processing");

    let id = u64::from_be_bytes(log.topics()[1].0[24..32].try_into().unwrap()) as i64;
    let owner = Address::from_word(log.topics()[2]).to_checksum(None);
    let provider = Address::from_word(log.topics()[3]).to_checksum(None);
    let (timestamp_u64, metadata) = <(u64, String)>::abi_decode_sequence(&log.data().data)?;

    let timestamp =
        std::time::SystemTime::UNIX_EPOCH + std::time::Duration::from_secs(timestamp_u64);

    // we want to insert if job does not exist
    // we want to error out if job already exists

    info!(id, owner, provider, metadata, ?timestamp, "creating job");

    // target sql:
    // INSERT INTO jobs (id, metadata, owner, provider, rate, balance, last_settled_at, created_at, is_closed, expires_at)
    // VALUES ("<id>", "<metadata>", "<owner>", "<provider>", 0, 0, "<timestamp>", "<timestamp>", false, "<timestamp>");
    diesel::insert_into(jobs::table)
        .values((
            jobs::id.eq(id),
            jobs::metadata.eq(&metadata),
            jobs::owner.eq(&owner),
            jobs::provider.eq(&provider),
            jobs::rate.eq(0),
            jobs::balance.eq(0),
            jobs::last_settled_at.eq(timestamp),
            jobs::created_at.eq(timestamp),
            jobs::is_closed.eq(false),
            jobs::expires_at.eq(timestamp),
        ))
        .execute(conn)
        .context("failed to create job")?;

    info!(id, owner, provider, metadata, ?timestamp, "created job");

    Ok(())
}

#[cfg(test)]
mod tests {
    use std::time::{Duration, SystemTime, UNIX_EPOCH};

    use alloy::primitives::U256;
    use alloy::{primitives::LogData, rpc::types::Log};
    use anyhow::Result;
    use diesel::QueryDsl;
    use ethp::keccak256;

    use crate::handlers::JOB_OPENED;
    use crate::handlers::handle_log;
    use crate::handlers::test_utils::TestDb;

    use super::*;

    #[test]
    fn test_create_new_job_in_empty_db() -> Result<()> {
        // setup
        let mut db = TestDb::new();
        let conn = &mut db.conn;

        let contract = "0x1111111111111111111111111111111111111111".parse()?;

        assert_eq!(jobs::table.count().get_result(conn), Ok(0));

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
                    vec![
                        JOB_OPENED.into(),
                        U256::from(123456789).into(),
                        "0xbBbBBBBbbBBBbbbBbbBbbbbBBbBbbbbBbBbbBBbB"
                            .parse::<Address>()?
                            .into_word(),
                        "0xaAaAaAaaAaAaAaaAaAAAAAAAAaaaAaAaAaaAaaAa"
                            .parse::<Address>()?
                            .into_word(),
                    ],
                    (now_ts, "some metadata".to_string())
                        .abi_encode_sequence()
                        .into(),
                )
                .unwrap(),
            },
        };

        // use handle_log instead of concrete handler to test dispatch
        handle_log(conn, log)?;

        // checks
        assert_eq!(jobs::table.count().get_result(conn), Ok(1));
        assert_eq!(
            jobs::table.select(jobs::all_columns).first(conn),
            Ok((
                123456789i64,
                "some metadata".to_owned(),
                "0xbBbBBBBbbBBBbbbBbbBbbbbBBbBbbbbBbBbbBBbB".to_owned(),
                "0xaAaAaAaaAaAaAaaAaAAAAAAAAaaaAaAaAaaAaaAa".to_owned(),
                0i64,
                0i64,
                now_st,
                now_st,
                now_st,
                false,
            ))
        );

        Ok(())
    }

    #[test]
    fn test_create_new_job_in_populated_db() -> Result<()> {
        // setup
        let mut db = TestDb::new();
        let conn = &mut db.conn;

        let contract = "0x1111111111111111111111111111111111111111".parse()?;

        let other_ts = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs() / 2;
        let other_st = UNIX_EPOCH + Duration::from_secs(other_ts);

        diesel::insert_into(jobs::table)
            .values((
                jobs::id.eq(987654321i64),
                jobs::owner.eq("0xbBbBBBBbbBBBbbbBbbBbbbbBBbBbbbbBbBbbBBbB"),
                jobs::provider.eq("0xaAaAaAaaAaAaAaaAaAAAAAAAAaaaAaAaAaaAaaAa"),
                jobs::metadata.eq("some other metadata"),
                jobs::rate.eq(100i64),
                jobs::balance.eq(1000i64),
                jobs::last_settled_at.eq(other_st),
                jobs::created_at.eq(other_st),
                jobs::is_closed.eq(false),
                jobs::expires_at.eq(other_st),
            ))
            .execute(conn)?;

        assert_eq!(jobs::table.count().get_result(conn), Ok(1));

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
                    vec![
                        JOB_OPENED.into(),
                        U256::from(123456789).into(),
                        "0xbBbBBBBbbBBBbbbBbbBbbbbBBbBbbbbBbBbbBBbB"
                            .parse::<Address>()?
                            .into_word(),
                        "0xaAaAaAaaAaAaAaaAaAAAAAAAAaaaAaAaAaaAaaAa"
                            .parse::<Address>()?
                            .into_word(),
                    ],
                    (now_ts, "some metadata".to_string())
                        .abi_encode_sequence()
                        .into(),
                )
                .unwrap(),
            },
        };

        // use handle_log instead of concrete handler to test dispatch
        handle_log(conn, log)?;

        // checks
        assert_eq!(jobs::table.count().get_result(conn), Ok(2));
        assert_eq!(
            jobs::table
                .select(jobs::all_columns)
                .order_by(jobs::id)
                .load(conn),
            Ok(vec![
                (
                    123456789i64,
                    "some metadata".to_owned(),
                    "0xbBbBBBBbbBBBbbbBbbBbbbbBBbBbbbbBbBbbBBbB".to_owned(),
                    "0xaAaAaAaaAaAaAaaAaAAAAAAAAaaaAaAaAaaAaaAa".to_owned(),
                    0i64,
                    0i64,
                    now_st,
                    now_st,
                    now_st,
                    false,
                ),
                (
                    987654321i64,
                    "some other metadata".to_owned(),
                    "0xbBbBBBBbbBBBbbbBbbBbbbbBBbBbbbbBbBbbBBbB".to_owned(),
                    "0xaAaAaAaaAaAaAaaAaAAAAAAAAaaaAaAaAaaAaaAa".to_owned(),
                    100i64,
                    1000i64,
                    other_st,
                    other_st,
                    other_st,
                    false,
                )
            ])
        );

        Ok(())
    }

    #[test]
    fn test_create_new_job_when_it_already_exists() -> Result<()> {
        // setup
        let mut db = TestDb::new();
        let conn = &mut db.conn;

        let contract = "0x1111111111111111111111111111111111111111".parse()?;

        let now_ts = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
        let now_st = UNIX_EPOCH + Duration::from_secs(now_ts);

        diesel::insert_into(jobs::table)
            .values((
                jobs::id.eq(123456789i64),
                jobs::owner.eq("0xbBbBBBBbbBBBbbbBbbBbbbbBBbBbbbbBbBbbBBbB"),
                jobs::provider.eq("0xaAaAaAaaAaAaAaaAaAAAAAAAAaaaAaAaAaaAaaAa"),
                jobs::metadata.eq("some metadata"),
                jobs::rate.eq(0i64),
                jobs::balance.eq(0i64),
                jobs::last_settled_at.eq(now_st),
                jobs::created_at.eq(now_st),
                jobs::is_closed.eq(false),
                jobs::expires_at.eq(now_st),
            ))
            .execute(conn)?;

        assert_eq!(jobs::table.count().get_result(conn), Ok(1));

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
                        JOB_OPENED.into(),
                        U256::from(123456789).into(),
                        "0xbBbBBBBbbBBBbbbBbbBbbbbBBbBbbbbBbBbbBBbB"
                            .parse::<Address>()?
                            .into_word(),
                        "0xaAaAaAaaAaAaAaaAaAAAAAAAAaaaAaAaAaaAaaAa"
                            .parse::<Address>()?
                            .into_word(),
                    ],
                    (now_ts, "some metadata".to_string())
                        .abi_encode_sequence()
                        .into(),
                )
                .unwrap(),
            },
        };

        // use handle_log instead of concrete handler to test dispatch
        let res = handle_log(conn, log);

        // checks
        assert_eq!(
            format!("{:?}", res.unwrap_err()),
            "failed to create job\n\nCaused by:\n    duplicate key value violates unique constraint \"jobs_pkey\""
        );
        assert_eq!(jobs::table.count().get_result(conn), Ok(1));

        Ok(())
    }
}
