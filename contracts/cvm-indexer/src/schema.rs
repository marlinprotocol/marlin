// @generated automatically by Diesel CLI.

diesel::table! {
    _sqlx_migrations (version) {
        version -> Int8,
        description -> Text,
        installed_on -> Timestamptz,
        success -> Bool,
        checksum -> Bytea,
        execution_time -> Int8,
    }
}

diesel::table! {
    indexer_state (id) {
        id -> Int4,
        last_processed_block -> Int8,
        updated_at -> Nullable<Timestamptz>,
    }
}

diesel::table! {
    job_events (id) {
        id -> Int8,
        #[max_length = 66]
        job_id -> Varchar,
        #[max_length = 255]
        event_name -> Varchar,
        event_data -> Jsonb,
        indexer_process_time -> Nullable<Timestamptz>,
    }
}

diesel::table! {
    job_transactions (block, idx) {
        job -> Int8,
        amount -> Int8,
        is_deposit -> Bool,
        timestamp -> Timestamp,
        #[max_length = 66]
        tx_hash -> Bpchar,
        block -> Int8,
        idx -> Int8,
    }
}

diesel::table! {
    jobs (id) {
        id -> Int8,
        metadata -> Text,
        #[max_length = 42]
        owner -> Bpchar,
        #[max_length = 42]
        provider -> Bpchar,
        rate -> Int8,
        balance -> Int8,
        last_settled_at -> Timestamp,
        expires_at -> Timestamp,
        created_at -> Timestamp,
        is_closed -> Bool,
    }
}

diesel::table! {
    providers (id) {
        #[max_length = 42]
        id -> Bpchar,
        cp -> Text,
        registered_at -> Timestamp,
        is_active -> Bool,
    }
}

diesel::table! {
    rate_revisions (block, idx) {
        job -> Nullable<Int8>,
        value -> Int8,
        timestamp -> Timestamp,
        block -> Int8,
        idx -> Int8,
    }
}

diesel::table! {
    settlements (block, idx) {
        job -> Nullable<Int8>,
        amount -> Int8,
        timestamp -> Timestamp,
        block -> Int8,
        idx -> Int8,
    }
}

diesel::table! {
    sync (block) {
        block -> Int8,
    }
}

diesel::joinable!(job_transactions -> jobs (job));
diesel::joinable!(rate_revisions -> jobs (job));
diesel::joinable!(settlements -> jobs (job));

diesel::allow_tables_to_appear_in_same_query!(
    _sqlx_migrations,
    indexer_state,
    job_events,
    job_transactions,
    jobs,
    providers,
    rate_revisions,
    settlements,
    sync,
);
