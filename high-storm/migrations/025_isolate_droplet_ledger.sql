ALTER TABLE droplets
ADD COLUMN deficit BIGINT NOT NULL DEFAULT 0 CHECK (deficit >= 0);

ALTER TABLE chain_recovery_state
ADD COLUMN droplets_halt_height BIGINT CHECK (droplets_halt_height IS NULL OR droplets_halt_height >= 0);

ALTER TABLE chain_recovery_state
ADD COLUMN droplets_halt_reason TEXT;
