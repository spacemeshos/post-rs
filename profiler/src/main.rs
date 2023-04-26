use std::{
    error::Error,
    path::{Path, PathBuf},
    time,
};

use clap::Parser;
use post::{
    prove::{Prover, Prover8_56, ProvingParams},
    ScryptParams,
};
use rayon::prelude::{ParallelBridge, ParallelIterator};
use serde::Serialize;

/// Profiler to measure performance of generating the proof of space
/// with different parameters.
#[derive(Parser, Debug)]
#[command(version)]
struct Args {
    /// File to read data from. It doesn't need to contain properly initialized POS data.
    /// Will create a new file if it doesn't exist.
    #[arg(long, default_value = "./data.bin")]
    data_file: PathBuf,

    /// Amount of data to read from the file in GiB.
    #[arg(long, default_value_t = 8)]
    data_size_gib: u64,

    /// Number of threads to use.
    /// '0' means use all available threads
    #[arg(short, long, default_value_t = 1)]
    threads: usize,

    /// Number of nonces to attempt in single pass over POS data.
    ///
    /// Higher value gives a better chance to find a proof within less passes over the POS data,
    /// but also slows down the process.
    #[arg(short, long, default_value_t = 16)]
    nonces: u32,

    // Difficulty factor of k2_pow.
    #[arg(long, default_value_t = u64::MAX)]
    k2_pow_difficulty: u64,
    // Difficulty factor of k3_pow.
    #[arg(long, default_value_t = u64::MAX)]
    k3_pow_difficulty: u64,
}

#[derive(Debug, Serialize)]
struct PerfResult {
    time_s: f64,
    speed_gib_s: f64,
}

// Create a file with given size
fn file_data(path: &Path, size: u64) -> Result<std::fs::File, std::io::Error> {
    let file = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .open(path)?;
    file.set_len(size)?;
    Ok(file)
}

fn main() -> Result<(), Box<dyn Error>> {
    let args = Args::parse();

    let challenge = b"hello world, challenge me!!!!!!!";
    let batch_size = 1024 * 1024;
    let params = ProvingParams {
        pow_scrypt: ScryptParams::new(6, 0, 0),
        difficulty: 0, // impossible to find a proof
        k2_pow_difficulty: args.k2_pow_difficulty,
        k3_pow_difficulty: args.k3_pow_difficulty,
    };

    let total_size = args.data_size_gib * 1024 * 1024 * 1024;
    let file = file_data(&args.data_file, total_size)?;
    let reader = post::reader::read_from(file, batch_size, total_size);

    let prover = Prover8_56::new(challenge, 0..args.nonces, params)?;

    let consume = |_, _| None;

    let start = time::Instant::now();
    match args.threads {
        1 => reader.for_each(|batch| {
            prover.prove(&batch.data, batch.pos, consume);
        }),
        0 => reader.par_bridge().for_each(|batch| {
            prover.prove(&batch.data, batch.pos, consume);
        }),
        n => {
            let pool = rayon::ThreadPoolBuilder::new()
                .num_threads(n)
                .build()
                .unwrap();
            pool.install(|| {
                reader.par_bridge().for_each(|batch| {
                    prover.prove(&batch.data, batch.pos, consume);
                })
            });
        }
    }
    let elapsed = start.elapsed();

    let result = PerfResult {
        time_s: elapsed.as_secs_f64(),
        speed_gib_s: args.data_size_gib as f64 / elapsed.as_secs_f64(),
    };
    println!("{}", serde_json::to_string_pretty(&result).unwrap());

    Ok(())
}
