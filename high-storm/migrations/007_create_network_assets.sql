CREATE TABLE network_assets (
    kind TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    asset_id BYTEA NOT NULL UNIQUE,
    reissuance_token_id BYTEA UNIQUE,
    entropy BYTEA,
    issuance_txid BYTEA NOT NULL UNIQUE,
    issuance_tx BYTEA,
    contract_script BYTEA NOT NULL,
    supply BIGINT NOT NULL,
    created_at_block BIGINT NOT NULL,
    status TEXT NOT NULL CHECK (status IN ('pending', 'active')),
    CHECK (status = 'pending' OR issuance_tx IS NULL)
);