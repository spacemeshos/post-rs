use criterion::{criterion_group, criterion_main, BatchSize, BenchmarkId, Criterion};

use post::pow::{
    randomx::{PoW, RandomXFlag},
    PowVerifier, Prover,
};
#[cfg(not(windows))]
use pprof::criterion::{Output, PProfProfiler};
use rayon::ThreadPoolBuilder;

fn bench_pow(c: &mut Criterion) {
    let difficulty = &[
        0x00, 0xdf, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0xff,
    ];

    let flags = RandomXFlag::get_recommended_flags();
    let prover = PoW::new(flags).unwrap();

    let mut group = c.benchmark_group("pow");

    for threads in [0, 1] {
        let pool = ThreadPoolBuilder::new()
            .num_threads(threads)
            .build()
            .unwrap();
        group.bench_function(
            BenchmarkId::from_parameter(format!("threads={threads}")),
            |b| {
                b.iter_batched(
                    rand::random,
                    |nonce| {
                        pool.install(|| prover.prove(nonce, b"challeng", difficulty, None).unwrap())
                    },
                    BatchSize::SmallInput,
                )
            },
        );
    }
}

fn verify_pow_light_stateless(c: &mut Criterion) {
    let flags = RandomXFlag::get_recommended_flags();
    c.bench_function("verify_pow_light_stateless", |b| {
        b.iter_batched(
            rand::random,
            |pow| {
                let prover = PoW::new(flags).unwrap();
                prover
                    .verify(pow, 7, b"challeng", &[0xFFu8; 32], None)
                    .unwrap();
            },
            BatchSize::SmallInput,
        )
    });
}

fn verify_pow_light(c: &mut Criterion) {
    let flags = RandomXFlag::get_recommended_flags();
    let prover = PoW::new(flags).unwrap();

    c.bench_function("verify_pow_light", |b| {
        b.iter_batched(
            rand::random,
            |pow| {
                prover
                    .verify(pow, 7, b"challeng", &[0xFFu8; 32], None)
                    .unwrap();
            },
            BatchSize::SmallInput,
        )
    });
}

fn verify_pow_fast(c: &mut Criterion) {
    let flags = RandomXFlag::get_recommended_flags() | RandomXFlag::FLAG_FULL_MEM;
    let prover = PoW::new(flags).unwrap();

    c.bench_function("verify_pow_fast", |b| {
        b.iter_batched(
            rand::random,
            |pow| {
                prover
                    .verify(pow, 7, b"challeng", &[0xFFu8; 32], None)
                    .unwrap();
            },
            BatchSize::SmallInput,
        )
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
    targets=
        bench_pow,
        verify_pow_light_stateless,
        verify_pow_light,
        verify_pow_fast
);

criterion_main!(benches);
