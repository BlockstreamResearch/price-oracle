use snow::params::NoiseParams;
use std::{sync::LazyLock, time::Duration};

pub(super) const STORM_AUTO_BIND_SOCKET_ADDRESS: &str = "0.0.0.0:0";
pub(super) const NOISE_MAX_PLAINTEXT_SIZE: usize = 65_535 - 16;
pub(super) const MAX_INBOUND_CONNECTIONS: usize = 128;
pub(super) const MAX_PROVISIONAL_CONNECTIONS: usize = 16;
pub(super) const MAX_CONCURRENT_OUTBOUND_CONNECTIONS: usize = 16;
pub(super) const OUTBOUND_QUEUE_CAPACITY: usize = 64;
pub(super) const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
pub(super) const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);
pub(super) const CONNECTION_IDLE_TIMEOUT: Duration = Duration::from_secs(120);
pub(super) const WRITE_TIMEOUT: Duration = Duration::from_secs(10);
pub(super) const MESSAGE_CLOCK_SKEW: Duration = Duration::from_secs(5 * 60);
pub(super) const REPLAY_CACHE_CAPACITY: usize = 256;
pub(super) const PROTOCOL_VERSION: u32 = 1;

// Snow's P256 resolver slot is replaced with secp256k1 by crypto::noise_builder.
pub(super) static NOISE_PARAMS: LazyLock<NoiseParams> = LazyLock::new(|| {
    "Noise_IK_P256_AESGCM_SHA256"
        .parse()
        .expect("valid snow parameters")
});
pub(super) const NOISE_PROLOGUE: &[u8] = b"
On the dawn of creation, the last rays of the first star to die forced the last wind to awaken the first storm.
";
