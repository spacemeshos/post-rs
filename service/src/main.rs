use std::{fs::read_to_string, net::SocketAddr, path::PathBuf, sync::Arc, time::Duration};

use clap::{Args, Parser, ValueEnum};
use eyre::Context;
use tokio::net::TcpListener;
use tonic::transport::{Certificate, Identity};

use post::pow::randomx::RandomXFlag;
use post_service::{client, operator};

/// Post Service
#[derive(Parser, Debug)]
#[command(version, about)]
struct Cli {
    /// directory of POST data
    #[arg(short, long)]
    dir: PathBuf,
    /// address to connect to
    #[arg(short, long)]
    address: String,
    /// time to wait before reconnecting to the node
    #[arg(long, default_value = "5", value_parser = |secs: &str| secs.parse().map(Duration::from_secs))]
    reconnect_interval_s: Duration,

    #[command(flatten, next_help_heading = "POST configuration")]
    post_config: PostConfig,

    #[command(flatten, next_help_heading = "POST settings")]
    post_settings: PostSettings,

    #[command(flatten, next_help_heading = "TLS configuration")]
    tls: Option<Tls>,

    /// address to listen on for operator service
    /// the operator service is disabled if not specified
    #[arg(long)]
    operator_address: Option<SocketAddr>,
}

#[derive(Args, Debug)]
/// POST configuration - network parameters
struct PostConfig {
    /// K1 specifies the difficulty for a label to be a candidate for a proof
    #[arg(long, default_value = "26")]
    k1: u32,
    /// K2 is the number of labels below the required difficulty required for a proof
    #[arg(long, default_value = "37")]
    k2: u32,
    /// K3 is the size of the subset of proof indices that is validated
    #[arg(long, default_value = "37")]
    k3: u32,
    /// difficulty for the nonce proof of work (aka "k2pow")
    #[arg(
        long,
        default_value = "000dfb23b0979b4b000000000000000000000000000000000000000000000000",
        value_parser(parse_difficulty)
    )]
    pow_difficulty: [u8; 32],
    /// scrypt parameters for initialization
    #[command(flatten)]
    scrypt: ScryptParams,
}

impl From<PostConfig> for post::config::Config {
    fn from(val: PostConfig) -> Self {
        post::config::Config {
            k1: val.k1,
            k2: val.k2,
            k3: val.k3,
            pow_difficulty: val.pow_difficulty,
            scrypt: post::ScryptParams::new(
                val.scrypt.n.ilog2() as u8 - 1,
                val.scrypt.r.ilog2() as u8,
                val.scrypt.p.ilog2() as u8,
            ),
        }
    }
}

/// Scrypt parameters for initialization
#[derive(Args, Debug)]
struct ScryptParams {
    /// scrypt N parameter
    #[arg(short, default_value_t = 8192)]
    n: usize,
    /// scrypt R parameter
    #[arg(short, default_value_t = 1)]
    r: usize,
    /// scrypt P parameter
    #[arg(short, default_value_t = 1)]
    p: usize,
}

#[derive(Args, Debug)]
/// POST proof generation settings
struct PostSettings {
    /// number of threads to use
    /// '0' means use all available threads
    #[arg(long, default_value_t = 1)]
    threads: usize,
    /// number of nonces to attempt in single pass over POS data
    ///
    /// Each group of 16 nonces requires a separate PoW. Must be a multiple of 16.
    ///
    /// Higher value gives a better chance to find a proof within less passes over the POS data,
    /// but also slows down the process.
    #[arg(long, default_value_t = 128, value_parser(parse_nonces))]
    nonces: usize,
    /// modes of operation for RandomX
    #[arg(long, default_value_t = RandomXMode::Fast)]
    randomx_mode: RandomXMode,
}

/// RandomX modes of operation
///
/// They are interchangeable as they give the same results but have different
/// purpose and memory requirements.
#[derive(Debug, Copy, Clone, Eq, PartialEq, ValueEnum)]
enum RandomXMode {
    /// Fast mode for proving. Requires 2080 MiB of memory.
    Fast,
    /// Light mode for verification. Requires only 256 MiB of memory, but runs significantly slower
    Light,
}

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
    /// defaults to server hostname
    #[arg(long)]
    pub domain: Option<String>,
}

impl std::fmt::Display for RandomXMode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.to_possible_value().unwrap().get_name().fmt(f)
    }
}

impl From<RandomXMode> for RandomXFlag {
    fn from(val: RandomXMode) -> Self {
        match val {
            RandomXMode::Fast => RandomXFlag::get_recommended_flags() | RandomXFlag::FLAG_FULL_MEM,
            RandomXMode::Light => RandomXFlag::get_recommended_flags(),
        }
    }
}

fn parse_nonces(arg: &str) -> eyre::Result<usize> {
    let nonces = arg.parse()?;
    eyre::ensure!(nonces % 16 == 0, "nonces must be multiple of 16");
    eyre::ensure!(nonces / 16 <= 256, format!("max nonces is {}", 256 * 16));
    Ok(nonces)
}

fn parse_difficulty(arg: &str) -> eyre::Result<[u8; 32]> {
    hex::decode(arg)?
        .as_slice()
        .try_into()
        .wrap_err("invalid difficulty length")
}

#[tokio::main]
async fn main() -> eyre::Result<()> {
    let args = Cli::parse();

    let env = env_logger::Env::default().filter_or("RUST_LOG", "info");
    env_logger::init_from_env(env);

    log::info!("POST network parameters: {:?}", args.post_config);
    log::info!("POST proving settings: {:?}", args.post_settings);

    let service = post_service::service::PostService::new(
        args.dir,
        args.post_config.into(),
        args.post_settings.nonces,
        args.post_settings.threads,
        args.post_settings.randomx_mode.into(),
    )
    .wrap_err("creating Post Service")?;

    let tls = if let Some(tls) = args.tls {
        log::info!(
            "configuring TLS: server: (CA cert: {}, domain: {:?}), client: (cert: {}, key: {})",
            tls.ca_cert.display(),
            tls.domain,
            tls.cert.display(),
            tls.key.display(),
        );
        let server_ca_cert = read_to_string(tls.ca_cert)?;
        let cert = read_to_string(tls.cert)?;
        let key = read_to_string(tls.key)?;
        Some((
            tls.domain,
            Certificate::from_pem(server_ca_cert),
            Identity::from_pem(cert, key),
        ))
    } else {
        log::info!("not configuring TLS");
        None
    };

    let service = Arc::new(service);

    if let Some(address) = args.operator_address {
        let listener = TcpListener::bind(address).await?;
        tokio::spawn(operator::OperatorServer::run(listener, service.clone()));
    }

    let client = client::ServiceClient::new(args.address, args.reconnect_interval_s, tls, service)?;
    client.run().await
}
