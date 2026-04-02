// @generated automatically by Diesel CLI.

pub mod sql_types {
    #[derive(diesel::query_builder::QueryId, diesel::sql_types::SqlType)]
    #[diesel(postgres_type(name = "event_name"))]
    pub struct EventName;
}

diesel::table! {
    use diesel::sql_types::*;
    use super::sql_types::EventName;

    indexer_state (id) {
        id -> Int4,
        #[max_length = 66]
        chain_id -> Nullable<Varchar>,
        extra_decimals -> Nullable<Int8>,
        last_processed_block -> Int8,
        updated_at -> Nullable<Timestamptz>,
    }
}

diesel::table! {
    use diesel::sql_types::*;
    use super::sql_types::EventName;

    job_events (id) {
        id -> Int8,
        #[max_length = 66]
        job_id -> Varchar,
        event_name -> EventName,
        event_data -> Jsonb,
        indexer_process_time -> Nullable<Timestamptz>,
    }
}

diesel::table! {
    use diesel::sql_types::*;
    use super::sql_types::EventName;

    terminated_jobs (job_id) {
        #[max_length = 66]
        job_id -> Varchar,
        terminated_at -> Nullable<Timestamptz>,
    }
}

diesel::allow_tables_to_appear_in_same_query!(
    indexer_state,
    job_events,
    terminated_jobs,
);
