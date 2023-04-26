use std::{error::Error, path::Path};

use base64::{engine::general_purpose, Engine};
use clap::Parser;
use post::ScryptParams;

/// Initialize labels on CPU
#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
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
}

fn main() -> Result<(), Box<dyn Error>> {
    let args = Args::parse();
    let label_count = args.labels;

    let node_id = general_purpose::STANDARD.decode(args.node_id).unwrap();
    let commitment_atx_id = general_purpose::STANDARD
        .decode(args.commitment_atx_id)
        .unwrap();

    let now = std::time::Instant::now();

    post::initialize::initialize(
        Path::new("./"),
        &node_id.try_into().unwrap(),
        &commitment_atx_id.try_into().unwrap(),
        label_count as u64,
        1,
        label_count as u64,
        ScryptParams::new(args.n.ilog2() as u8 - 1, 0, 0),
    )?;

    let elapsed = now.elapsed();

    println!(
        "Scrypting {} labels took {} seconds. Speed: {:.0} labels/sec ({:.2} MB/sec)",
        label_count,
        elapsed.as_secs(),
        label_count as f64 / elapsed.as_secs_f64(),
        label_count as f64 * 16.0 / elapsed.as_secs_f64() / 1024.0 / 1024.0
    );
    Ok(())
}
