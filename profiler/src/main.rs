mod util;

use std::{
    cmp::min,
    env::temp_dir,
    fs::OpenOptions,
    io::{BufReader, BufWriter, Seek, SeekFrom, Write},
    path::{Path, PathBuf},
    time::{self, Duration},
};

use clap::{Args, Parser, Subcommand, ValueEnum};
use eyre::Context;
use post::{
    pow::{self, randomx, Prover as PowProver},
    prove::{Prover, Prover8_56, ProvingParams},
    reader::BatchingReader,
};
use rand::RngCore;
use rayon::prelude::{ParallelBridge, ParallelIterator};
use serde::Serialize;

/// Profiler to measure the performance of generating the proof of space time
/// given the parameters.
#[derive(Parser)]
#[command(author, version, about, long_about = None, args_conflicts_with_subcommands = true)]
struct Cli {
    #[command(subcommand)]
    command: Option<Commands>,

    #[clap(flatten)]
    default: ProvingArgs,
}

#[derive(Subcommand)]
enum Commands {
    /// Bench proving speed.
    /// Measures how fast PoST proving algorithm runs over the data given the arguments.
    Proving(ProvingArgs),
    /// Bench proof of work.
    Pow(PowArgs),
}

#[derive(Args, Debug)]
struct ProvingArgs {
    /// File to read data from.
    /// It doesn't need to contain properly initialized POS data.
    ///
    /// Will create a new file in temporary directory if not provided or it doesn't exist.
    ///
    /// WARNING: the contents of the file might be overwritten.
    ///
    /// NOTE: On MacOS, the file MUST NOT be in chache already or the benchmark will give wrong results.
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
    #[arg(short, long, default_value_t = 4)]
    threads: usize,

    /// Number of nonces to attempt in single pass over POS data.
    ///
    /// Higher value gives a better chance to find a proof within less passes over the POS data,
    /// but also slows down the process.
    ///
    /// Must be a multiple of 16.
    #[arg(short, long, default_value_t = 64, value_parser(parse_nonces))]
    nonces: u32,
}

#[derive(Args, Debug)]
struct PowArgs {
    /// Iterations to run the benchmark for.
    /// The more, the more accurate the result is.
    #[arg(long, short, default_value_t = 5)]
    iterations: usize,

    /// Number of threads to use.
    /// '0' means use all available threads
    #[arg(short, long, default_value_t = 1)]
    threads: usize,

    /// Number of nonces to attempt in single pass over POS data.
    ///
    /// Each group of 16 nonces requires a separate PoW. Must be a multiple of 16.
    ///
    /// Higher value gives a better chance to find a proof within less passes over the POS data,
    /// but also slows down the process.
    #[arg(short, long, default_value_t = 64, value_parser(parse_nonces))]
    nonces: u32,

    /// Number of units of initialized POS data.
    #[arg(long, default_value_t = 4)]
    num_units: u32,

    /// PoW difficulty, a network parameter
    ///
    /// It's a base parameter for 1 space unit. The actual difficulty for PoW is scaled by
    /// the number of initialized space units (the more the harder).
    #[arg(
        short,
        long,
        default_value = "000dfb23b0979b4b000000000000000000000000000000000000000000000000",
        value_parser(parse_difficulty)
    )]
    difficulty: [u8; 32],

    /// Modes of operation for RandomX.
    ///
    /// They are interchangeable as they give the same results but have different
    /// purpose and memory requirements.
    #[arg(long, default_value_t = RandomXMode::Fast)]
    randomx_mode: RandomXMode,

    /// Use large pages for RandomX.
    ///
    /// This requires enabling large pages in the OS.
    /// Follow instructions here: https://xmrig.com/docs/miner/hugepages
    #[arg(long, default_value_t = false)]
    randomx_large_pages: bool,
}

#[derive(Debug, Copy, Clone, Eq, PartialEq, ValueEnum)]
enum RandomXMode {
    /// Fast mode for proving. Requires 2080 MiB of memory.
    Fast,
    /// Light mode for verification. Requires only 256 MiB of memory, but runs significantly slower
    Light,
}

impl std::fmt::Display for RandomXMode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.to_possible_value().unwrap().get_name().fmt(f)
    }
}

fn parse_nonces(arg: &str) -> eyre::Result<u32> {
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

#[derive(Debug, Serialize)]
struct PerfResult {
    time_s: f64,
    speed_gib_s: f64,
}

// Prepare file for benchmarking, possibly appending random data to it if needed.
fn prepare_data_file(path: &Path, size: u64) -> eyre::Result<()> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)
            .wrap_err_with(|| format!("creating directory {}", parent.display()))?;
    }
    let file = OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(false)
        .open(path)
        .wrap_err_with(|| format!("opening profiler data file {}", path.display()))?;

    // Disable caching on Mac
    #[cfg(target_os = "macos")]
    {
        use std::os::fd::AsRawFd;
        let ret = unsafe { libc::fcntl(file.as_raw_fd(), libc::F_NOCACHE, 1 as libc::c_int) };
        eyre::ensure!(ret == 0, format!("fcntl(F_NOCACHE) failed: {ret}"));
    }

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

fn main() -> eyre::Result<()> {
    env_logger::init();
    let args = Cli::parse();

    match args.command.unwrap_or(Commands::Proving(args.default)) {
        Commands::Proving(args) => proving(args),
        Commands::Pow(args) => pow(args),
    }
}

/// Bench proving speed (going over POS data).
fn proving(args: ProvingArgs) -> eyre::Result<()> {
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
    pow_prover.expect_prove().returning(|_, _, _, _| Ok(0));
    let prover = Prover8_56::new(challenge, 0..args.nonces, params, &pow_prover, &[7; 32])?;

    let mut total_time = time::Duration::from_secs(0);
    let mut processed = 0;

    while total_time < Duration::from_secs(args.duration) {
        let file = util::open_without_cache(&file_path)?;
        let reader = BatchingReader::new(BufReader::new(file), 0, batch_size, total_size);
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

#[derive(Debug, Serialize)]
struct PowPerfResult {
    /// Time to initialize RandomX VM
    randomx_vm_init_time: time::Duration,
    /// Average time of PoW
    average_time: time::Duration,
    /// Number of iterations ran
    iterations: usize,
}

/// Bench K2 Proof of Work
fn pow(args: PowArgs) -> eyre::Result<()> {
    eprintln!(
        "Benchmarking PoW for 1 space unit and 16 nonces (the result will be scaled automatically to {} units and {} nonces).",
        args.num_units, args.nonces,
    );

    let mut randomx_flags = match args.randomx_mode {
        RandomXMode::Fast => {
            randomx::RandomXFlag::get_recommended_flags() | randomx::RandomXFlag::FLAG_FULL_MEM
        }
        RandomXMode::Light => randomx::RandomXFlag::get_recommended_flags(),
    };
    if args.randomx_large_pages {
        eprintln!("Using large pages for RandomX");
        randomx_flags |= randomx::RandomXFlag::FLAG_LARGE_PAGES;
    }
    eprintln!("RandomX flags: {}", randomx_flags);

    eprintln!("Initializing RandomX VMs...");
    let start = time::Instant::now();
    let prover = randomx::PoW::new(randomx_flags)?;
    let randomx_vm_init_time = start.elapsed();
    eprintln!("Done initializing RandomX VMs in {randomx_vm_init_time:.2?}");

    let mut durations = Vec::new();
    let pool = rayon::ThreadPoolBuilder::new()
        .num_threads(args.threads)
        .build()?;

    pool.install(|| -> eyre::Result<()> {
        for i in 0..args.iterations {
            let start = time::Instant::now();
            prover.prove(7, &i.to_le_bytes(), &args.difficulty, &[7; 32])?;
            let duration = start.elapsed();
            eprintln!(
                "[{i}]: {duration:.2?} (scaled: {:.2?})",
                duration * args.nonces / 16 * args.num_units
            );
            durations.push(duration);
        }
        Ok(())
    })?;

    let total = durations.iter().sum::<time::Duration>() * (args.nonces / 16) * args.num_units;
    println!(
        "{}",
        serde_json::to_string_pretty(&PowPerfResult {
            randomx_vm_init_time,
            average_time: total / durations.len() as u32,
            iterations: durations.len(),
        })?
    );

    Ok(())
}

#[cfg(test)]
mod tests {
    #[test]
    fn prepare_data_file() {
        let temp_dir = tempfile::tempdir().unwrap();
        // it creates a missing direcory 'subdir'
        let file_path = temp_dir.path().join("subdir").join("file.bin");
        assert!(!file_path.exists());
        super::prepare_data_file(&file_path, 1024).unwrap();
        assert!(file_path.exists());
        assert!(file_path.is_file());
        assert_eq!(file_path.metadata().unwrap().len(), 1024);
    }
}
