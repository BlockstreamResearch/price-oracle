CREATE TABLE droplet_exchange_request_history (
    xonly_pubkey BYTEA NOT NULL,
    pset BYTEA NOT NULL,
    signing_hash BYTEA NOT NULL,
    requested_at_block BIGINT NOT NULL CHECK (requested_at_block >= 0),
    status TEXT NOT NULL CHECK (status IN ('pending', 'completed', 'failed')),
    completed_txid BYTEA,
    last_error TEXT,
    PRIMARY KEY (xonly_pubkey, requested_at_block, signing_hash)
);

CREATE INDEX droplet_exchange_request_history_member_block_idx
    ON droplet_exchange_request_history (xonly_pubkey, requested_at_block DESC);
