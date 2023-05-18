use std::{
    error::Error,
    path::{Path, PathBuf},
    time::{self, Duration},
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
    /// File to read data from.
    /// It doesn't need to contain properly initialized POS data.
    /// Will create a new file if it doesn't exist.
    #[arg(long, default_value = "/tmp/data.bin")]
    data_file: PathBuf,

    /// The size of POST data to bench over in GiB
    #[arg(long, default_value_t = 1)]
    data_size: u64,

    /// How long to run the benchmark in seconds.
    /// It will run for at least this long,
    /// going through the same data multiple times if necessary.
    #[arg(long, default_value_t = 10)]
    duration: u64,

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
    env_logger::init();
    let args = Args::parse();

    let challenge = b"hello world, challenge me!!!!!!!";
    let batch_size = 1024 * 1024;
    let params = ProvingParams {
        pow_scrypt: ScryptParams::new(6, 0, 0),
        difficulty: 0, // impossible to find a proof
        k2_pow_difficulty: args.k2_pow_difficulty,
    };

    let total_size = args.data_size * 1024 * 1024 * 1024;

    let prover = Prover8_56::new(challenge, 0..args.nonces, params)?;

    let consume = |_, _| None;

    let start = time::Instant::now();
    let mut iterations = 0;
    loop {
        if start.elapsed() >= Duration::from_secs(args.duration) {
            break;
        }
        let file = file_data(&args.data_file, total_size)?;
        let reader = post::reader::read_from(file, batch_size, total_size);
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
        iterations += 1;
    }
    let elapsed = start.elapsed();

    let result = PerfResult {
        time_s: elapsed.as_secs_f64(),
        speed_gib_s: iterations as f64 * args.data_size as f64 / elapsed.as_secs_f64(),
    };
    println!("{}", serde_json::to_string_pretty(&result).unwrap());

    Ok(())
}
