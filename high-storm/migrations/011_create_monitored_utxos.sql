CREATE TABLE IF NOT EXISTS indexer_cursors (
    rule_set TEXT PRIMARY KEY,
    block_height BIGINT NOT NULL,
    block_hash BYTEA NOT NULL
);

CREATE TABLE IF NOT EXISTS monitored_utxos (
    txid BYTEA NOT NULL,
    output_index BIGINT NOT NULL,
    asset_kind TEXT NOT NULL,
    amount BIGINT NOT NULL,
    script_pubkey BYTEA NOT NULL,
    auth_method TEXT NOT NULL,
    auth_data BYTEA NOT NULL,
    account_owner_pubkey BYTEA NOT NULL,
    burning_fee_txid BYTEA NOT NULL,
    burning_fee_output_index BIGINT NOT NULL,
    block_height BIGINT NOT NULL,
    status TEXT NOT NULL,
    status_block_height BIGINT NOT NULL,
    burn_txid BYTEA,
    PRIMARY KEY (txid, output_index)
);

CREATE INDEX IF NOT EXISTS monitored_utxos_status_height_idx
    ON monitored_utxos (status, block_height);

CREATE INDEX IF NOT EXISTS monitored_utxos_burning_fee_idx
    ON monitored_utxos (burning_fee_txid, burning_fee_output_index);