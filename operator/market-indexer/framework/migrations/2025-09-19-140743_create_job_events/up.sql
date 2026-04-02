CREATE TABLE job_events (
    id BIGSERIAL PRIMARY KEY,
    job_id VARCHAR(66) NOT NULL,
    event_name event_name NOT NULL,
    event_data JSONB NOT NULL,
    indexer_process_time TIMESTAMPTZ DEFAULT now()
);

CREATE INDEX idx_job_events_event_name_job_id ON job_events (event_name, job_id);