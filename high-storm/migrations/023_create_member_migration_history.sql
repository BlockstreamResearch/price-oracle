ALTER TABLE chain_recovery_state
ADD COLUMN safe_halted BIGINT NOT NULL DEFAULT 0 CHECK (safe_halted IN (0, 1));

ALTER TABLE chain_recovery_state
ADD COLUMN halt_reason TEXT;

ALTER TABLE chain_recovery_state
ADD COLUMN migration_paused BIGINT NOT NULL DEFAULT 0 CHECK (migration_paused IN (0, 1));

ALTER TABLE chain_recovery_droplet_locks
ADD COLUMN amount BIGINT NOT NULL DEFAULT 0 CHECK (amount >= 0);

ALTER TABLE droplets
ADD COLUMN exchange_amount BIGINT NOT NULL DEFAULT 0 CHECK (exchange_amount >= 0);

CREATE TABLE network_member_migrations (
    request_hash BYTEA PRIMARY KEY,
    execution_txid BYTEA NOT NULL UNIQUE,
    block_height BIGINT NOT NULL CHECK (block_height >= 0),
    block_hash BYTEA NOT NULL,
    asset_kind TEXT NOT NULL,
    previous_script BYTEA NOT NULL,
    previous_data BYTEA,
    next_script BYTEA NOT NULL,
    next_data BYTEA,
    previous_coordinator_public_key TEXT NOT NULL,
    next_coordinator_public_key TEXT NOT NULL
);

CREATE TABLE network_member_migration_peers (
    request_hash BYTEA NOT NULL,
    snapshot_kind TEXT NOT NULL CHECK (snapshot_kind IN ('previous', 'next')),
    peer_order BIGINT NOT NULL CHECK (peer_order >= 0),
    public_key TEXT NOT NULL,
    socket_address TEXT,
    last_seen BIGINT,
    status TEXT NOT NULL,
    discovery BIGINT NOT NULL CHECK (discovery IN (0, 1)),
    PRIMARY KEY (request_hash, snapshot_kind, peer_order),
    FOREIGN KEY (request_hash) REFERENCES network_member_migrations(request_hash)
);

CREATE INDEX network_member_migrations_block_height
ON network_member_migrations(block_height);