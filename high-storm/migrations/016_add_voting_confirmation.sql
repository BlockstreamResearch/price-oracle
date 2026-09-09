ALTER TABLE voting_requests ADD COLUMN execution_request BYTEA;
ALTER TABLE voting_requests ADD COLUMN execution_confirmed BIGINT NOT NULL DEFAULT 0 CHECK (execution_confirmed IN (0, 1));

UPDATE voting_requests SET execution_confirmed = 1 WHERE execution_txid IS NOT NULL;
