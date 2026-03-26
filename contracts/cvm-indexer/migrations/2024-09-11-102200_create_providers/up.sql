CREATE TABLE providers (
  id CHAR(42) PRIMARY KEY,
  cp TEXT NOT NULL,
  registered_at TIMESTAMP NOT NULL,
  is_active BOOL NOT NULL
);

CREATE INDEX providers_is_active_idx ON providers (is_active);
