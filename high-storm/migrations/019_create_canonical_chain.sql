CREATE TABLE canonical_blocks (
    block_height BIGINT PRIMARY KEY CHECK (block_height >= 0),
    block_hash BYTEA NOT NULL UNIQUE,
    parent_hash BYTEA NOT NULL
);

CREATE TABLE chain_recovery_state (
    id BIGINT PRIMARY KEY CHECK (id = 1),
    recovering BIGINT NOT NULL DEFAULT 0 CHECK (recovering IN (0, 1)),
    fork_height BIGINT,
    CHECK (fork_height IS NULL OR fork_height >= 0)
);

INSERT INTO chain_recovery_state (id, recovering, fork_height)
VALUES (1, 0, NULL);