use std::path::Path;

use ed25519_dalek::SecretKey;
use post::pow::randomx::RandomXFlag;
use serde_with::{base64::Base64, serde_as};
use tracing::info;

/// RandomX modes of operation
///
/// They are interchangeable as they give the same results but have different
/// purpose and memory requirements.
#[derive(Debug, Default, Copy, Clone, serde::Deserialize)]
pub enum RandomXMode {
    /// Fast mode for proving. Requires 2080 MiB of memory.
    Fast,
    /// Light mode for verification. Requires only 256 MiB of memory, but runs significantly slower
    #[default]
    Light,
}

impl From<RandomXMode> for RandomXFlag {
    fn from(val: RandomXMode) -> Self {
        match val {
            RandomXMode::Fast => RandomXFlag::get_recommended_flags() | RandomXFlag::FLAG_FULL_MEM,
            RandomXMode::Light => RandomXFlag::get_recommended_flags(),
        }
    }
}

fn max_concurrency() -> usize {
    std::thread::available_parallelism()
        .expect("fetching number of cores")
        .get()
}

#[serde_as]
#[derive(serde::Deserialize, Clone)]
pub struct Config {
    /// The address to listen on for incoming requests.
    pub listen: std::net::SocketAddr,

    /// The maximum number of requests to process in parallel.
    /// Typically set to the number of cores, which is the default (if not set).
    #[serde(default = "max_concurrency")]
    pub max_concurrent_requests: usize,

    #[serde_as(as = "Base64")]
    /// The base64-encoded secret key used to sign the proofs.
    /// It's 256-bit key as defined in [RFC8032 § 5.1.5].
    pub signing_key: SecretKey,
    pub post_cfg: post::config::ProofConfig,
    pub init_cfg: post::config::InitConfig,

    #[serde(default)]
    pub randomx_mode: RandomXMode,

    #[serde(
        default,
        deserialize_with = "duration_str::deserialize_option_duration_chrono"
    )]
    /// The time after which the certificates expire.
    pub certificate_expiration: Option<chrono::Duration>,

    /// Address to expose metrics on.
    /// Metrics are disabled if not configured.
    pub metrics: Option<std::net::SocketAddr>,
}

pub fn get_configuration(config_path: &Path) -> Result<Config, config::ConfigError> {
    info!("loading configuration from {config_path:?}");

    let config = config::Config::builder()
        .add_source(config::File::from(config_path).required(true))
        .add_source(config::Environment::with_prefix("CERTIFIER").try_parsing(true))
        .build()?;

    config.try_deserialize()
}
