CREATE TABLE IF NOT EXISTS network_user_requests (
    request_hash BYTEA PRIMARY KEY,
    request BYTEA NOT NULL,
    block_height BIGINT NOT NULL,
    status TEXT NOT NULL,
    payload BYTEA
);