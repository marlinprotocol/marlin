CREATE TABLE settlements (
  job BIGINT REFERENCES jobs (id),
  amount BIGINT NOT NULL,
  timestamp TIMESTAMP NOT NULL,
  block BIGINT NOT NULL,
  idx BIGINT NOT NULL,
  PRIMARY KEY(block, idx)
);

CREATE INDEX settlements_job_idx ON settlements (job);
