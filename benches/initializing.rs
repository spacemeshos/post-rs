use std::io;

use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion};
use post::initialize::initialize_to;
use pprof::criterion::{Output, PProfProfiler};

use rayon::prelude::{ParallelBridge, ParallelIterator};
use scrypt_jane::scrypt::ScryptParams;

fn initialize(c: &mut Criterion) {
    let num_labels = 1000;
    let step_size = 1;

    let mut group = c.benchmark_group("initializing");
    group.throughput(criterion::Throughput::Bytes(num_labels * 16));
    for threads in itertools::iproduct!([0]) {
        group.bench_with_input(BenchmarkId::new("scrypt", threads), &threads, |b, &n| {
            b.iter(|| {
                let pool = rayon::ThreadPoolBuilder::new()
                    .num_threads(n)
                    .build()
                    .unwrap();
                pool.install(|| {
                    (0..num_labels)
                        .step_by(step_size)
                        .par_bridge()
                        .for_each(|label| {
                            initialize_to(
                                &mut io::sink(),
                                &[0u8; 32],
                                label..label + step_size as u64,
                                ScryptParams::new(12, 0, 0),
                            )
                            .unwrap();
                        });
                });
            });
        });
    }
}

criterion_group!(
    name = benches;
    config = Criterion::default().with_profiler(PProfProfiler::new(1000, Output::Flamegraph(None)));
    targets=initialize,
);

criterion_main!(benches);
