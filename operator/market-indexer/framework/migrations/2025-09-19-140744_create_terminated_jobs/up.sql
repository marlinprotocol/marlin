CREATE TABLE terminated_jobs (
    job_id VARCHAR(66) PRIMARY KEY,
    terminated_at TIMESTAMPTZ DEFAULT now()
);