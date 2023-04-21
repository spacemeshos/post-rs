use std::path::PathBuf;

use base64::{engine::general_purpose, Engine as _};
use clap::{Args, Parser};
use post::{
    compression::{decompress_indexes, required_bits},
    metadata::{self, ProofMetadata},
    prove::generate_proof,
    verification::{verify, VerifyingParams},
    ScryptParams,
};

#[derive(Parser)]
#[command(author, version, about, long_about = None)]
struct Cli {
    /// Path to POST directory
    #[arg(short, long)]
    post_dir: PathBuf,

    /// Challenge to prove
    /// Value must be base64 encoded
    #[arg(short, long)]
    challenge: String,

    #[arg(long)]
    k1: u32,

    #[arg(long)]
    k3: u32,

    #[arg(long)]
    k2: u32,

    #[arg(long)]
    k2_pow_difficulty: u64,

    #[arg(long)]
    k3_pow_difficulty: u64,
}

// value_parser

#[derive(Debug, Args, Clone)]
struct Config {
    #[arg(long)]
    k1: u8,
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cli = Cli::parse();

    let cfg = post::config::Config {
        k1: cli.k1,
        k2: cli.k2,
        k3: cli.k3,
        k2_pow_difficulty: cli.k2_pow_difficulty,
        k3_pow_difficulty: cli.k3_pow_difficulty,
        pow_scrypt: ScryptParams::new(6, 0, 0),
        scrypt: ScryptParams::new(12, 0, 0),
    };

    let challenge = general_purpose::STANDARD
        .decode(&cli.challenge)?
        .as_slice()
        .try_into()?;

    println!("Challenge: {:?}", challenge);

    let metadata = metadata::load(&cli.post_dir)?;
    println!("POST metadata: {metadata:?}");

    // Generate a proof
    let proof = generate_proof(&cli.post_dir, &challenge, cfg, 10, 2).unwrap();
    println!("Generated proof: {proof:?}");
    println!(
        "Decompressed label indices: {:?}",
        decompress_indexes(
            &proof.indices,
            required_bits(metadata.labels_per_unit * metadata.num_units as u64)
        )
        .collect::<Vec<_>>()
    );

    // Verify the proof
    let metadata = ProofMetadata {
        node_id: metadata.node_id,
        commitment_atx_id: metadata.commitment_atx_id,
        challenge,
        num_units: metadata.num_units,
        labels_per_unit: metadata.labels_per_unit,
    };
    match verify(
        &proof,
        &metadata,
        VerifyingParams::new(&metadata, &cfg).unwrap(),
        0,
    ) {
        Ok(_) => println!("Proof verified"),
        Err(e) => return Err(format!("Proof verification failed: {}", e).into()),
    }
    Ok(())
}
