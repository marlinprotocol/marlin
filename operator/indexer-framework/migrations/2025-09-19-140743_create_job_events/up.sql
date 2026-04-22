CREATE TYPE event_name AS ENUM (
    'Opened', 
    'Closed', 
    'Deposited', 
    'Settled', 
    'MetadataUpdated', 
    'Withdrew', 
    'RateRevised'
);

CREATE TABLE job_events (
    id BIGSERIAL PRIMARY KEY,
    job_id BIGINT NOT NULL,
    event_name event_name NOT NULL,
    event_data BYTEA NOT NULL
);

CREATE INDEX idx_job_events_event_name_job_id ON job_events (event_name, job_id);
