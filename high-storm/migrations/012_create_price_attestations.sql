-- The latest attestation held per (node, feed), this node's own among them.
-- Its own row is what requirement 6 persists: a restarted node does not attest
-- again until it holds a strictly newer observation.
CREATE TABLE IF NOT EXISTS price_attestations (
    public_key BYTEA NOT NULL,
    feed_id BIGINT NOT NULL,
    price BIGINT NOT NULL,
    decimals BIGINT NOT NULL,
    received_at BIGINT NOT NULL,
    valid_until BIGINT NOT NULL,
    signature BYTEA NOT NULL,
    PRIMARY KEY (public_key, feed_id)
);

-- Reads are by feed, which the (public_key, feed_id) primary key cannot serve.
CREATE INDEX IF NOT EXISTS price_attestations_feed_idx
    ON price_attestations (feed_id);
