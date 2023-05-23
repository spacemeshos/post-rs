use criterion::{criterion_group, criterion_main, BatchSize, BenchmarkId, Criterion};

use itertools::iproduct;
use pprof::criterion::{Output, PProfProfiler};
use rayon::ThreadPoolBuilder;
use scrypt_jane::scrypt::ScryptParams;

fn bench_k2_pow(c: &mut Criterion) {
    // Base pow difficulty threshold
    // Will be scaled up by the benchmark to see if time scales linearly
    let difficulty_threshold = 891576961504;

    let mut group = c.benchmark_group("k2_pow");

    for (scale, threads) in iproduct!([1000, 100], [0, 1]) {
        let threshold = difficulty_threshold * scale;
        let pool = ThreadPoolBuilder::new()
            .num_threads(threads)
            .build()
            .unwrap();
        group.bench_with_input(
            BenchmarkId::from_parameter(format!(
                "scale={scale}/threshold={threshold}/threads={threads}"
            )),
            &(threshold),
            |b, &threshold| {
                b.iter_batched(
                    || rand::random(),
                    |nonce| {
                        pool.install(|| {
                            post::pow::find_k2_pow(
                                b"hello world, CHALLENGE me!!!!!!!",
                                nonce,
                                ScryptParams::new(6, 0, 0),
                                threshold,
                            )
                        })
                    },
                    BatchSize::SmallInput,
                )
            },
        );
    }
}

criterion_group!(
    name = benches;
    config = Criterion::default().with_profiler(PProfProfiler::new(100, Output::Flamegraph(None)));
    targets=bench_k2_pow
);

criterion_main!(benches);
