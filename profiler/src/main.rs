mod util;

use std::{
    cmp::min,
    env::temp_dir,
    error::Error,
    fs::OpenOptions,
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
    /// Will create a new file in temporary directory if it doesn't exist.
    #[arg(long)]
    data_file: Option<PathBuf>,

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
    let file = OpenOptions::new().write(true).create(true).open(path)?;

    let file_size = file.metadata()?.len();
    if file_size < size {
        let mut remaining_to_write = size - file_size;
        let mut f: BufWriter<std::fs::File> = BufWriter::new(file);
        f.seek(SeekFrom::End(0))?;

        let mut rng = rand::thread_rng();
        let mut buf = vec![0; 1024 * 1024];

        while remaining_to_write > 0 {
            let to_write = min(buf.len() as u64, remaining_to_write);
            let buf = &mut buf[..to_write as usize];
            rng.fill_bytes(buf);
            f.write_all(buf)?;
            remaining_to_write -= to_write;
        }
    }
    Ok(())
}

fn main() -> Result<(), Box<dyn Error>> {
    env_logger::init();
    let args = Args::parse();

    let challenge = b"hello world, challenge me!!!!!!!";
    let batch_size = 1024 * 1024;
    let total_size = args.data_size * 1024 * 1024 * 1024;
    let params = ProvingParams {
        difficulty: 0, // impossible to find a proof
        pow_difficulty: [0xFF; 32],
    };

    let file_path = args
        .data_file
        .unwrap_or_else(|| temp_dir().join("profiler_data.bin"));
    prepare_data_file(&file_path, total_size)?;

    let pool = rayon::ThreadPoolBuilder::new()
        .num_threads(args.threads)
        .build()?;

    let mut pow_prover = pow::MockProver::new();
    pow_prover.expect_prove().returning(|_, _, _| Ok(0));
    let prover = Prover8_56::new(challenge, 0..args.nonces, params, &pow_prover)?;

    let mut total_time = time::Duration::from_secs(0);
    let mut processed = 0;

    while total_time < Duration::from_secs(args.duration) {
        let file = util::open_without_cache(&file_path)?;
        let reader = post::reader::read_from(BufReader::new(file), batch_size, total_size);
        let start = time::Instant::now();
        pool.install(|| {
            reader.par_bridge().for_each(|batch| {
                prover.prove(&batch.data, batch.pos, |_, _| None);
            })
        });
        total_time += start.elapsed();
        processed += args.data_size;
    }

    let result = PerfResult {
        time_s: total_time.as_secs_f64(),
        speed_gib_s: processed as f64 / total_time.as_secs_f64(),
    };
    println!("{}", serde_json::to_string_pretty(&result)?);

    Ok(())
}
