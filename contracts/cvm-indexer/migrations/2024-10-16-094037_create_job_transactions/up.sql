CREATE TABLE job_transactions (
  job BIGINT NOT NULL REFERENCES jobs (id),
  amount BIGINT NOT NULL,
  is_deposit BOOL NOT NULL,
  timestamp TIMESTAMP NOT NULL,
  tx_hash CHAR(66) NOT NULL,
  block BIGINT NOT NULL,
  idx BIGINT NOT NULL,
  PRIMARY KEY(block, idx)
);

CREATE INDEX job_transactions_job_idx ON job_transactions (job);
