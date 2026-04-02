CREATE TABLE indexer_state (
    id INT PRIMARY KEY,
    chain_id VARCHAR(66),
    last_processed_block BIGINT NOT NULL
);

-- Initial values
INSERT INTO indexer_state (id, last_processed_block) VALUES (1, -1);
