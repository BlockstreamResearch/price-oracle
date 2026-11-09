-- The price sources this node's operator froze. Freezing is local to this
-- node, so only it records it; a source left out of this table is Active, and
-- polling alone tells whether it drops. A source is named, not numbered: the
-- order sources are polled in may change between versions, and its name may not.
CREATE TABLE IF NOT EXISTS frozen_price_sources (
    feed_id BIGINT NOT NULL,
    source TEXT NOT NULL,
    frozen_at BIGINT NOT NULL,
    PRIMARY KEY (feed_id, source)
);
