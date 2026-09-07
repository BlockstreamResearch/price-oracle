CREATE TABLE droplets (
    xonly_pubkey BYTEA PRIMARY KEY,
    amount BIGINT NOT NULL CHECK (amount >= 0),
    block_height BIGINT NOT NULL CHECK (block_height >= 0),
    exchange_locked BIGINT NOT NULL DEFAULT 0 CHECK (exchange_locked IN (0, 1)),
    last_tx BYTEA
);

CREATE TABLE treasury_utxos (
    txid BYTEA NOT NULL,
    output_index BIGINT NOT NULL,
    amount BIGINT NOT NULL CHECK (amount >= 0),
    block_height BIGINT NOT NULL CHECK (block_height >= 0),
    PRIMARY KEY (txid, output_index)
);