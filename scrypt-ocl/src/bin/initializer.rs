use std::{
    io::{Read, Seek},
    path::PathBuf,
    time,
};

use base64::{engine::general_purpose, Engine};
use eyre::Context;
use ocl::DeviceType;
use post::{
    initialize::{CpuInitializer, Initialize},
    ScryptParams,
};
use rand::seq::IteratorRandom;
use rayon::prelude::{ParallelBridge, ParallelIterator};
use scrypt_ocl::{OpenClInitializer, ProviderId};

use clap::{Args, Parser, Subcommand};

/// Initialize labels on GPU
#[derive(Parser)]
#[command(author, version, about, long_about = None, args_conflicts_with_subcommands = true)]
struct Cli {
    #[command(subcommand)]
    command: Option<Commands>,

    #[clap(flatten)]
    initialize: InitializeArgs,
}

#[derive(Subcommand)]
enum Commands {
    /// does testing things
    Initialize(InitializeArgs),
    ListProviders,
    VerifyData(VerifyData),
}

#[derive(Args)]
struct InitializeArgs {
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

    /// Provider ID to use
    /// Use `initializer list-providers` to list available providers.
    /// If not specified, the first available provider will be used.
    #[arg(long)]
    provider: Option<u32>,
}

#[derive(Args)]
struct VerifyData {
    /// Scrypt N parameter
    #[arg(short, long, default_value_t = 8192)]
    n: usize,
    /// Path to file with POST data to verify
    #[arg(short, long)]
    input: PathBuf,
    /// Fraction of data (in %) to initialize
    #[arg(short, long, default_value_t = 5.0)]
    fraction: f64,
    /// Index of first label in file
    #[arg(long, default_value_t = 0)]
    first_label_index: u64,
    /// Base64-encoded node ID
    #[arg(long, default_value = "hBGTHs44tav7YR87sRVafuzZwObCZnK1Z/exYpxwqSQ=")]
    node_id: String,
    /// Base64-encoded commitment ATX ID
    #[arg(long, default_value = "ZuxocVjIYWfv7A/K1Lmm8+mNsHzAZaWVpbl5+KINx+I=")]
    commitment_atx_id: String,
}

fn calc_commitment(node_id: &str, commitment_atx_id: &str) -> eyre::Result<[u8; 32]> {
    let node_id = general_purpose::STANDARD.decode(node_id)?;
    let commitment_atx_id = general_purpose::STANDARD.decode(commitment_atx_id)?;

    Ok(post::initialize::calc_commitment(
        node_id
            .as_slice()
            .try_into()
            .wrap_err("nodeID should be 32B")?,
        commitment_atx_id
            .as_slice()
            .try_into()
            .wrap_err("commitment ATX ID should be 32B")?,
    ))
}

fn verify_data(args: VerifyData) -> eyre::Result<()> {
    let commitment = calc_commitment(&args.node_id, &args.commitment_atx_id)?;

    // open intput file for reading
    let mut input_file = std::fs::File::open(args.input)?;
    // read input file size
    let input_file_size = input_file.metadata()?.len();
    let labels_in_file = input_file_size / 16;
    let labels_to_verify = (labels_in_file as f64 * (args.fraction / 100.0)) as usize;
    let scrypt_params = ScryptParams::new(args.n.ilog2() as u8 - 1, 0, 0);

    let mut rng = rand::thread_rng();
    (0..labels_in_file)
        .choose_multiple(&mut rng, labels_to_verify)
        .into_iter()
        .map(|index| {
            let mut label = [0u8; 16];
            input_file
                .seek(std::io::SeekFrom::Start(index * 16))
                .unwrap();
            input_file.read_exact(&mut label).unwrap();
            (index, label)
        })
        .par_bridge()
        .map(|(index, label)| -> eyre::Result<()> {
            let mut expected_label = [0u8; 16];
            let label_index = index + args.first_label_index;
            CpuInitializer::new(scrypt_params)
                .initialize_to(
                    &mut expected_label.as_mut_slice(),
                    &commitment,
                    label_index..label_index + 1,
                    None,
                )
                .expect("initializing label");

            eyre::ensure!(
                label == expected_label,
                "label at index {index} mismatch: {label:?} != {expected_label:?}"
            );
            Ok(())
        })
        .collect::<Result<Vec<_>, _>>()?;

    println!("Data verified successfully");
    Ok(())
}

fn initialize(
    n: usize,
    labels: usize,
    node_id: String,
    commitment_atx_id: String,
    output: PathBuf,
    provider_id: Option<ProviderId>,
) -> eyre::Result<()> {
    println!("Initializing {labels} labels into {:?}", output.as_path());

    let mut scrypter = OpenClInitializer::new(provider_id, n, Some(DeviceType::GPU))?;

    let now = time::Instant::now();
    let vrf_nonce = scrypter
        .initialize(
            &output,
            node_id.as_bytes().try_into().unwrap(),
            commitment_atx_id.as_bytes().try_into().unwrap(),
            labels as u64,
            1,
            labels as u64,
            Some([0xFFu8; 32]),
        )
        .map_err(|e| eyre::eyre!("initializing: {}", e))?;

    let elapsed = now.elapsed();
    println!(
            "Initializing {} labels took {} seconds. Speed: {:.0} labels/sec ({:.2} MB/sec, vrf_nonce: {vrf_nonce:?})",
            labels,
            elapsed.as_secs(),
            labels as f64 / elapsed.as_secs_f64(),
            labels as f64 * 16.0 / elapsed.as_secs_f64() / 1024.0 / 1024.0
        );

    Ok(())
}

fn list_providers() -> eyre::Result<()> {
    let providers = scrypt_ocl::get_providers(None)?;
    println!("Found {} providers", providers.len());
    for (id, provider) in providers.iter().enumerate() {
        println!("{id}: {provider}");
    }
    Ok(())
}

fn main() -> eyre::Result<()> {
    let args = Cli::parse();

    match args
        .command
        .unwrap_or(Commands::Initialize(args.initialize))
    {
        Commands::Initialize(InitializeArgs {
            n,
            labels,
            node_id,
            commitment_atx_id,
            output,
            provider,
        }) => initialize(
            n,
            labels,
            node_id,
            commitment_atx_id,
            output,
            provider.map(ProviderId),
        )?,
        Commands::ListProviders => list_providers()?,
        Commands::VerifyData(v) => verify_data(v)?,
    }

    Ok(())
}
