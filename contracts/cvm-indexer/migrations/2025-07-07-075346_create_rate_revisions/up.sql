CREATE TABLE rate_revisions (
  job BIGINT REFERENCES jobs (id),
  value BIGINT NOT NULL,
  timestamp TIMESTAMP NOT NULL,
  block BIGINT NOT NULL,
  idx BIGINT NOT NULL,
  PRIMARY KEY(block, idx)
);

CREATE INDEX rate_revisions_job_idx ON rate_revisions (job);
