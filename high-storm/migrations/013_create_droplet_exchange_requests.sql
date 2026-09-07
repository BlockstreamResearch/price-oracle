CREATE TABLE droplet_exchange_requests (
    xonly_pubkey BYTEA PRIMARY KEY,
    pset BYTEA NOT NULL,
    signing_hash BYTEA NOT NULL,
    requested_at_block BIGINT NOT NULL CHECK (requested_at_block >= 0),
    status TEXT NOT NULL CHECK (status IN ('pending', 'completed', 'failed')),
    completed_txid BYTEA,
    last_error TEXT
);