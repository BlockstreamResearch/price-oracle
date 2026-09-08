ALTER TABLE voting_requests ADD COLUMN proposer_public_key BYTEA;
ALTER TABLE voting_requests ADD COLUMN execution_started BIGINT NOT NULL DEFAULT 0 CHECK (execution_started IN (0, 1));
ALTER TABLE voting_requests ADD COLUMN execution_transaction BYTEA;
ALTER TABLE voting_requests ADD COLUMN execution_txid BYTEA;