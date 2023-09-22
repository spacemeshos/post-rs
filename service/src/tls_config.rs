use std::path::PathBuf;

use clap::Args;

/// TLS configuration
///
/// Either all fields must be specified or none
#[derive(Args, Debug, Clone)]
#[group(required = false)]
pub(crate) struct Tls {
    /// CA certificate
    #[arg(long, required = false)]
    pub(crate) ca_cert: PathBuf,
    #[arg(long, required = false)]
    pub(crate) cert: PathBuf,
    #[arg(long, required = false)]
    pub(crate) key: PathBuf,
}
