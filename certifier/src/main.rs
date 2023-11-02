use std::path::PathBuf;

use clap::{arg, Parser, Subcommand};
use ed25519_dalek::SigningKey;
use tracing::info;
use tracing_log::LogTracer;
use tracing_subscriber::{EnvFilter, FmtSubscriber};

#[derive(Parser, Debug)]
#[command(version)]
struct Cli {
    #[arg(
        short,
        long,
        default_value = "config.yml",
        env("CERTIFIER_CONFIG_PATH")
    )]
    config_path: PathBuf,

    #[command(subcommand)]
    cmd: Option<Commands>,
}

#[derive(Subcommand, Debug)]
enum Commands {
    /// generate keypair and write it to standard out.
    /// the keypair is encoded as json
    GenerateKeys,
}

fn generate_keys() -> Result<(), Box<dyn std::error::Error>> {
    let signing_key: SigningKey = SigningKey::generate(&mut rand::rngs::OsRng);

    #[serde_with::serde_as]
    #[derive(serde::Serialize)]
    struct KeyPair {
        #[serde_as(as = "serde_with::base64::Base64")]
        public_key: [u8; ed25519_dalek::PUBLIC_KEY_LENGTH],
        #[serde_as(as = "serde_with::base64::Base64")]
        secret_key: [u8; ed25519_dalek::SECRET_KEY_LENGTH],
    }

    let keypair = KeyPair {
        public_key: signing_key.verifying_key().to_bytes(),
        secret_key: signing_key.to_bytes(),
    };

    serde_json::to_writer_pretty(std::io::stdout(), &keypair)?;
    Ok(())
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = Cli::parse();

    if let Some(Commands::GenerateKeys) = args.cmd {
        return generate_keys();
    }

    LogTracer::init()?;
    let env_filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("INFO"));
    let subscriber = FmtSubscriber::builder()
        .with_env_filter(env_filter)
        .finish();
    tracing::subscriber::set_global_default(subscriber)?;

    let config = certifier::configuration::get_configuration(&args.config_path)?;
    let signer = SigningKey::from_bytes(&config.signing_key);

    info!(
        "listening on: {:?}, pubkey: {:?}",
        config.listen,
        signer.verifying_key()
    );
    info!("using POST configuration: {:?}", config.post_cfg);

    let app: axum::Router = certifier::certifier::new(config.post_cfg, signer);

    axum::Server::bind(&config.listen)
        .serve(app.into_make_service())
        .await?;
    Ok(())
}
