-- The Blockstream price API refreshes its quotes hourly, far less often than
-- the source data validity duration allows, so nearly every observation would
-- be rejected as expired. It starts frozen on each feed it prices (LBTC/USD,
-- USDT/USD, EURX/USD, DEPIX/USD) until the operator unfreezes it. Frozen as of
-- 2026-10-13T00:00:00Z, when that was decided.
INSERT INTO frozen_price_sources (feed_id, source, frozen_at) VALUES
    (0, 'blockstream', 1791849600),
    (1, 'blockstream', 1791849600),
    (2, 'blockstream', 1791849600),
    (3, 'blockstream', 1791849600)
ON CONFLICT (feed_id, source) DO NOTHING;
