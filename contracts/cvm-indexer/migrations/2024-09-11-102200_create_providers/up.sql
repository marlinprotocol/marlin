CREATE TABLE providers (
  id BIGINT PRIMARY KEY,
  cp TEXT NOT NULL,
  is_active BOOL NOT NULL,
  registered_at TIMESTAMP NOT NULL
);

CREATE INDEX providers_is_active_idx ON providers (is_active);
