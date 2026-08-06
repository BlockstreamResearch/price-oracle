use snow::params::NoiseParams;
use std::sync::LazyLock;

pub(super) const STORM_AUTO_BIND_SOCKET_ADDRESS: &str = "0.0.0.0:0";
pub(super) const NOISE_MAX_PLAINTEXT_SIZE: usize = 65_535 - 16;
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
