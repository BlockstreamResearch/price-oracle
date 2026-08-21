ALTER TABLE network_state ADD COLUMN coordinator_public_key TEXT;

UPDATE network_state
SET coordinator_public_key = (
    SELECT public_key
    FROM network_peers
    ORDER BY peer_order
    LIMIT 1
)
WHERE coordinator_public_key IS NULL;