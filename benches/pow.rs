use criterion::{black_box, criterion_group, criterion_main, BatchSize, BenchmarkId, Criterion};

use post::pow::{PowProver, RandomXFlag};
use pprof::criterion::{Output, PProfProfiler};
use rayon::ThreadPoolBuilder;

fn bench_pow(c: &mut Criterion) {
    let difficulty = &[
        0x00, 0xdf, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0xff,
    ];

    let flags = RandomXFlag::get_recommended_flags();
    let prover = PowProver::new(flags).unwrap();

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
                    || rand::random(),
                    |nonce| pool.install(|| prover.prove(nonce, b"challeng", difficulty).unwrap()),
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
            || rand::random(),
            |pow| {
                let prover = PowProver::new(flags).unwrap();
                prover.verify(pow, 7, b"challeng", &[0xFFu8; 32]).unwrap();
            },
            BatchSize::SmallInput,
        )
    });
}

fn verify_pow_light(c: &mut Criterion) {
    let flags = RandomXFlag::get_recommended_flags();
    let prover = PowProver::new(flags).unwrap();

    c.bench_function("verify_pow_light", |b| {
        b.iter_batched(
            || rand::random(),
            |pow| {
                prover.verify(pow, 7, b"challeng", &[0xFFu8; 32]).unwrap();
            },
            BatchSize::SmallInput,
        )
    });
}

fn verify_pow_fast(c: &mut Criterion) {
    let flags = RandomXFlag::get_recommended_flags() | RandomXFlag::FLAG_FULL_MEM;
    let prover = PowProver::new(flags).unwrap();

    c.bench_function("verify_pow_fast", |b| {
        b.iter_batched(
            || rand::random(),
            |pow| {
                prover.verify(pow, 7, b"challeng", &[0xFFu8; 32]).unwrap();
            },
            BatchSize::SmallInput,
        )
    });
}

fn randomx_dataset_init(c: &mut Criterion) {
    let flags = RandomXFlag::get_recommended_flags() | RandomXFlag::FLAG_FULL_MEM;

    c.bench_function("randomx_dataset_init", |b| {
        b.iter(|| {
            let cache = randomx_rs::RandomXCache::new(flags, black_box(b"key")).unwrap();
            let dataset = randomx_rs::RandomXDataset::new(flags, cache, 0).unwrap();
            black_box(dataset);
        })
    });
}

criterion_group!(
    name = benches;
    config = Criterion::default().with_profiler(PProfProfiler::new(100, Output::Flamegraph(None)));
    targets=
        bench_pow,
        verify_pow_light_stateless,
        verify_pow_light,
        verify_pow_fast,
        randomx_dataset_init
);

criterion_main!(benches);
