CREATE TABLE IF NOT EXISTS network_peers (
    peer_order BIGINT NOT NULL,
    public_key TEXT PRIMARY KEY,
    socket_address TEXT,
    last_seen BIGINT,
    status TEXT NOT NULL,
    discovery BIGINT NOT NULL
);