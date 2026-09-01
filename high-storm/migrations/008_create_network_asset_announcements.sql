CREATE TABLE network_asset_announcements (
    kind TEXT NOT NULL REFERENCES network_assets(kind) ON DELETE CASCADE,
    peer_public_key BYTEA NOT NULL,
    announced_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (kind, peer_public_key)
);