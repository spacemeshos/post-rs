use std::path::PathBuf;

use clap::Args;

/// TLS configuration
///
/// Either all fields must be specified or none
#[derive(Args, Debug, Clone)]
#[group(required = false)]
pub struct Tls {
    /// CA certificate
    #[arg(long, required = false)]
    pub ca_cert: PathBuf,
    #[arg(long, required = false)]
    pub cert: PathBuf,
    #[arg(long, required = false)]
    pub key: PathBuf,
    /// domain name to verify the certificate of server against
    #[arg(long, default_value = "localhost")]
    pub domain: String,
}
