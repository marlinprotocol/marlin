CREATE TABLE indexer_state (
    id INT PRIMARY KEY,
    chain_id VARCHAR(66),
    extra_decimals BIGINT,
    last_processed_block BIGINT NOT NULL,
    updated_at TIMESTAMPTZ DEFAULT now()
);

-- Initial values
INSERT INTO indexer_state (id, last_processed_block) VALUES (1, -1);

SELECT diesel_manage_updated_at('indexer_state');
