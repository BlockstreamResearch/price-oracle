CREATE TABLE IF NOT EXISTS voting_requests (
    message_hash BYTEA PRIMARY KEY,
    message BYTEA NOT NULL,
    block_height BIGINT NOT NULL,
    approved_at_block_height BIGINT
);

CREATE TABLE IF NOT EXISTS voting_approvals (
    voting_request_hash BYTEA NOT NULL,
    public_key BYTEA NOT NULL,
    message BYTEA NOT NULL,
    block_height BIGINT NOT NULL,
    PRIMARY KEY (voting_request_hash, public_key),
    FOREIGN KEY (voting_request_hash) REFERENCES voting_requests(message_hash) ON DELETE CASCADE
);