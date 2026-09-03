CREATE TABLE IF NOT EXISTS network_user_request_fee_utxos (
    txid BYTEA NOT NULL,
    output_index BIGINT NOT NULL,
    request_hash BYTEA NOT NULL REFERENCES network_user_requests(request_hash) ON DELETE CASCADE,
    PRIMARY KEY (txid, output_index)
);

CREATE INDEX IF NOT EXISTS network_user_request_fee_utxos_request_hash_idx
    ON network_user_request_fee_utxos (request_hash);