CREATE TABLE jobs (
  id BIGINT PRIMARY KEY,
  metadata TEXT NOT NULL,
  owner CHAR(42) NOT NULL,
  provider CHAR(42) NOT NULL,
  rate BIGINT NOT NULL,
  balance BIGINT NOT NULL,
  last_settled_at TIMESTAMP NOT NULL,
  expires_at TIMESTAMP NOT NULL,
  created_at TIMESTAMP NOT NULL,
  is_closed BOOLEAN NOT NULL
);

CREATE INDEX jobs_owner_idx ON jobs (owner);
CREATE INDEX jobs_provider_idx ON jobs (provider);
CREATE INDEX jobs_created_at_idx ON jobs (created_at);
CREATE INDEX jobs_is_closed_idx ON jobs (is_closed);
