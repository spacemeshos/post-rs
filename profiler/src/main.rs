use std::{
    cmp::min,
    error::Error,
    io::{BufReader, BufWriter, Seek, SeekFrom, Write},
    path::{Path, PathBuf},
    time::{self, Duration},
};

use clap::Parser;
use post::{
    pow,
    prove::{Prover, Prover8_56, ProvingParams},
};
use rand::RngCore;
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
}

#[derive(Debug, Serialize)]
struct PerfResult {
    time_s: f64,
    speed_gib_s: f64,
}

// Prepare file for benchmarking, possibly appending random data to it if needed.
fn prepare_data_file(path: &Path, size: u64) -> eyre::Result<()> {
    let file_exists = path.exists();

    let file = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .open(path)?;

    let file_size = file.metadata()?.len();
    if file_size < size {
        let mut remaining_to_write = size - file_size;
        let mut f: BufWriter<std::fs::File> = BufWriter::new(file);
        f.seek(SeekFrom::End(0))?;
        let can_write = !file_exists
            || inquire::Confirm::new(&format!(
                "Will append random {remaining_to_write}B to file, are you sure?"
            ))
            .with_default(false)
            .prompt()?;

        eyre::ensure!(
            can_write,
            "File is too small and refused to write random data"
        );

        let mut rng = rand::thread_rng();
        let mut buf = vec![0; 1024 * 1024];

        while remaining_to_write > 0 {
            let to_write = min(buf.len() as u64, remaining_to_write);
            let mut buf = &mut buf[..to_write as usize];
            rng.fill_bytes(&mut buf);
            f.write_all(&buf)?;
            remaining_to_write -= to_write;
        }
    }
    Ok(())
}

fn main() -> Result<(), Box<dyn Error>> {
    env_logger::init();
    let args = Args::parse();

    let total_size = args.data_size * 1024 * 1024 * 1024;
    prepare_data_file(&args.data_file, total_size)?;

    let challenge = b"hello world, challenge me!!!!!!!";
    let batch_size = 1024 * 1024;
    let params = ProvingParams {
        difficulty: 0, // impossible to find a proof
        pow_difficulty: [0xFF; 32],
    };

    let pool = rayon::ThreadPoolBuilder::new()
        .num_threads(args.threads)
        .build()
        .unwrap();
    let mut pow_prover = pow::MockProver::new();
    pow_prover.expect_prove().returning(|_, _, _| Ok(0));
    let prover = Prover8_56::new(challenge, 0..args.nonces, params, &pow_prover)?;

    let consume = |_, _| None;

    let start = time::Instant::now();
    let mut iterations = 0;
    while start.elapsed() < Duration::from_secs(args.duration) {
        let file = std::fs::OpenOptions::new()
            .read(true)
            .open(&args.data_file)?;

        let reader = post::reader::read_from(BufReader::new(file), batch_size, total_size);
        pool.install(|| {
            reader.par_bridge().for_each(|batch| {
                prover.prove(&batch.data, batch.pos, consume);
            })
        });

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
