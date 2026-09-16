CREATE TABLE IF NOT EXISTS storm_eye_renewals (
    id BIGINT PRIMARY KEY CHECK (id = 1),
    txid BYTEA NOT NULL UNIQUE,
    request BYTEA NOT NULL,
    contract_script BYTEA NOT NULL,
    contract_data BYTEA NOT NULL,
    block_height BIGINT NOT NULL
);
