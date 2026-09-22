CREATE TABLE network_asset_chain_history (
    block_height BIGINT NOT NULL CHECK (block_height >= 0),
    block_hash BYTEA NOT NULL,
    asset_kind TEXT NOT NULL,
    previous_script BYTEA NOT NULL,
    previous_data BYTEA,
    next_script BYTEA NOT NULL,
    next_data BYTEA,
    PRIMARY KEY (block_height, asset_kind)
);