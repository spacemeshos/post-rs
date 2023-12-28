use std::sync::atomic::AtomicBool;

use criterion::{criterion_group, criterion_main, Criterion};
use post::{
    config::{InitConfig, ProofConfig, ScryptParams},
    initialize::{CpuInitializer, Initialize},
    metadata::ProofMetadata,
    pow::randomx::{PoW, RandomXFlag},
    prove::generate_proof,
    verification::{Mode, Verifier},
};
#[cfg(not(windows))]
use pprof::criterion::{Output, PProfProfiler};
use tempfile::tempdir;

fn verifying(c: &mut Criterion) {
    let challenge = b"hello world, challenge me!!!!!!!";
    let datadir = tempdir().unwrap();

    let cfg = ProofConfig {
        k1: 199,
        k2: 37,
        pow_difficulty: [0xFF; 32],
    };
    let init_cfg = InitConfig {
        min_num_units: 1,
        max_num_units: 1,
        labels_per_unit: 200,
        scrypt: ScryptParams::new(8192, 1, 1),
    };

    let metadata = CpuInitializer::new(init_cfg.scrypt)
        .initialize(
            datadir.path(),
            &[0u8; 32],
            &[0u8; 32],
            init_cfg.labels_per_unit,
            1,
            init_cfg.labels_per_unit,
            None,
        )
        .unwrap();

    let pow_flags = RandomXFlag::get_recommended_flags();
    // Generate a proof
    let stop = AtomicBool::new(false);
    let proof = generate_proof(datadir.path(), challenge, cfg, 32, 1, pow_flags, stop).unwrap();
    let metadata = ProofMetadata::new(metadata, *challenge);

    // Bench verifying the proof
    let verifier = Verifier::new(Box::new(PoW::new(pow_flags).unwrap()));
    c.bench_function("verify", |b| {
        b.iter(|| {
            verifier
                .verify(&proof, &metadata, &cfg, &init_cfg, Mode::All)
                .expect("proof should be valid");
        });
    });
}

#[cfg(not(windows))]
fn config() -> Criterion {
    Criterion::default().with_profiler(PProfProfiler::new(100, Output::Flamegraph(None)))
}
#[cfg(windows)]
fn config() -> Criterion {
    Criterion::default()
}

criterion_group!(
    name = benches;
    config = config();
    targets=verifying
);

criterion_main!(benches);
