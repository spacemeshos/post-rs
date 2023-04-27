use std::{error::Error, io::Write, path::PathBuf, time};

use base64::{engine::general_purpose, Engine};
use scrypt_ocl::Scrypter;

use clap::{Args, Parser, Subcommand};

/// Initialize labels on GPU
#[derive(Parser)]
#[command(author, version, about, long_about = None, args_conflicts_with_subcommands = true)]
struct Cli {
    #[command(subcommand)]
    command: Option<Commands>,

    #[clap(flatten)]
    initialize: Initialize,
}

#[derive(Subcommand)]
enum Commands {
    /// does testing things
    Initialize(Initialize),
    ListProviders,
}

#[derive(Args)]
struct Initialize {
    /// Scrypt N parameter
    #[arg(short, long, default_value_t = 8192)]
    n: usize,

    /// Number of labels to initialize
    #[arg(short, long, default_value_t = 20480 * 30)]
    labels: usize,

    /// Base64-encoded node ID
    #[arg(long, default_value = "hBGTHs44tav7YR87sRVafuzZwObCZnK1Z/exYpxwqSQ=")]
    node_id: String,

    /// Base64-encoded commitment ATX ID
    #[arg(long, default_value = "ZuxocVjIYWfv7A/K1Lmm8+mNsHzAZaWVpbl5+KINx+I=")]
    commitment_atx_id: String,

    /// Path to output file
    #[arg(long, default_value = "labels.bin")]
    output: PathBuf,
}

fn initialize(
    n: usize,
    labels: usize,
    node_id: String,
    commitment_atx_id: String,
    output: PathBuf,
) {
    println!("Initializing {labels} labels into {:?}", output.as_path());

    let node_id = general_purpose::STANDARD.decode(node_id).unwrap();
    let commitment_atx_id = general_purpose::STANDARD.decode(commitment_atx_id).unwrap();

    let commitment = post::initialize::calc_commitment(
        &node_id.try_into().unwrap(),
        &commitment_atx_id.try_into().unwrap(),
    );

    let mut scrypter = Scrypter::new(None, n, &commitment, Some([0xFFu8; 32])).unwrap();
    let mut out_labels = vec![0u8; labels * 16];

    let now = time::Instant::now();
    let vrf_nonce = scrypter.scrypt(0..labels as u64, &mut out_labels).unwrap();
    let elapsed = now.elapsed();
    println!(
            "Initializing {} labels took {} seconds. Speed: {:.0} labels/sec ({:.2} MB/sec, vrf_nonce: {vrf_nonce:?})",
            labels,
            elapsed.as_secs(),
            labels as f64 / elapsed.as_secs_f64(),
            labels as f64 * 16.0 / elapsed.as_secs_f64() / 1024.0 / 1024.0
        );

    let mut file = std::fs::File::create(output).unwrap();
    file.write_all(&out_labels).unwrap();
}

fn list_providers() -> Result<(), Box<dyn Error>> {
    let providers = scrypt_ocl::get_providers()?;
    println!("Found {} providers", providers.len());
    for provider in providers {
        println!("Provider: {}", provider);
    }
    Ok(())
}

fn main() -> Result<(), Box<dyn Error>> {
    let args = Cli::parse();

    match args
        .command
        .unwrap_or(Commands::Initialize(args.initialize))
    {
        Commands::Initialize(Initialize {
            n,
            labels,
            node_id,
            commitment_atx_id,
            output,
        }) => initialize(n, labels, node_id, commitment_atx_id, output),
        Commands::ListProviders => list_providers()?,
    }

    Ok(())
}
