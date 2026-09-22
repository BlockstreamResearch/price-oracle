pub const VALIDITY_WINDOW: u64 = 300;
pub const SOURCE_DATA_VALIDITY_DURATION: u64 = 300;
pub const MAX_CLOCK_SKEW: u64 = 5;
pub const POLLING_INTERVAL: u64 = 60;
pub const MAX_POLLING_ERROR_NUM: u32 = 5;
pub const POLLING_RETRY_TIME: u64 = 60;
pub const BACKOFF_CAP: u64 = 30;

/// One percent, in basis points: how far an instructed rate may differ from
/// the value a signer holds itself before the signer refuses to sign it.
pub const MAX_ACCEPT_DEVIATION_FEED_BPS: u64 = 100;
