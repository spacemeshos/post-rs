use std::path::Path;

use ed25519_dalek::SecretKey;
use serde_with::{base64::Base64, serde_as};
use tracing::info;

#[serde_as]
#[derive(serde::Deserialize, Clone)]
pub struct Config {
    pub listen: std::net::SocketAddr,
    #[serde_as(as = "Base64")]
    /// The base64-encoded secret key used to sign the proofs.
    /// It's 256-bit key as defined in [RFC8032 § 5.1.5].
    pub signing_key: SecretKey,
    pub post_cfg: post::config::ProofConfig,
    pub init_cfg: post::config::InitConfig,

    /// Whether to enable metrics on /metrics.
    pub metrics: bool,
}

pub fn get_configuration(config_path: &Path) -> Result<Config, config::ConfigError> {
    info!("loading configuration from {config_path:?}");

    let config = config::Config::builder()
        .add_source(config::File::from(config_path).required(true))
        .add_source(config::Environment::with_prefix("CERTIFIER").try_parsing(true))
        .build()?;

    config.try_deserialize()
}
