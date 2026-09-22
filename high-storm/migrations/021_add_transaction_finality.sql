ALTER TABLE network_user_requests ADD COLUMN execution_tx BYTEA;
ALTER TABLE network_user_requests ADD COLUMN included_at_block BIGINT;
ALTER TABLE network_user_requests ADD COLUMN included_block_hash BYTEA;

ALTER TABLE voting_requests ADD COLUMN execution_included_at_block BIGINT;
ALTER TABLE voting_requests ADD COLUMN execution_included_block_hash BYTEA;

ALTER TABLE storm_eye_renewals ADD COLUMN included_at_block BIGINT;
ALTER TABLE storm_eye_renewals ADD COLUMN included_block_hash BYTEA;