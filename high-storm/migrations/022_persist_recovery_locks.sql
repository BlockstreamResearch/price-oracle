CREATE TABLE chain_recovery_droplet_locks (
    xonly_pubkey BYTEA PRIMARY KEY,
    block_height BIGINT NOT NULL CHECK (block_height >= 0),
    transaction_bytes BYTEA NOT NULL
);