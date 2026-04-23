// @generated automatically by Diesel CLI.

pub mod sql_types {
    #[derive(diesel::sql_types::SqlType, diesel::query_builder::QueryId)]
    #[diesel(postgres_type(name = "event_name"))]
    pub struct EventName;
}

diesel::table! {
    use diesel::sql_types::*;
    use super::sql_types::EventName;

    job_events (id) {
        id -> Int8,
        job_id -> Int8,
        event_name -> EventName,
        event_data -> Bytea,
    }
}

diesel::table! {
    sync (block) {
        block -> Int8,
    }
}

diesel::table! {
    terminated_jobs (job_id) {
        job_id -> Int8,
    }
}

diesel::allow_tables_to_appear_in_same_query!(job_events, sync, terminated_jobs,);
