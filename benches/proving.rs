use std::hint::black_box;

use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion};
use post::{prove::Prover, prove::Prover8_56, prove::ProvingParams};
#[cfg(not(windows))]
use pprof::criterion::{Output, PProfProfiler};
use rand::{thread_rng, RngCore};
use rayon::prelude::{ParallelBridge, ParallelIterator};

const KIB: usize = 1024;
const MIB: usize = 1024 * KIB;

const CHALLENGE: &[u8; 32] = b"hello world, CHALLENGE me!!!!!!!";

fn threads_to_str(threads: usize) -> String {
    if threads == 0 {
        "auto".into()
    } else {
        threads.to_string()
    }
}

fn prover_bench(c: &mut Criterion) {
    let mut group = c.benchmark_group("proving");

    let mut data = vec![0; 64 * MIB];
    thread_rng().fill_bytes(&mut data);
    group.throughput(criterion::Throughput::Bytes(data.len() as u64));

    let chunk_size = 64 * KIB;
    let params = ProvingParams {
        difficulty: 0,              // impossible to find a proof
        pow_difficulty: [0xFF; 32], // extremely easy to find pow nonce
        pow_flags: post::pow::randomx::RandomXFlag::get_recommended_flags(),
    };

    for (nonces, threads) in itertools::iproduct!(
        [16, 32, 64],
        [1, 0] // 0 == automatic
    ) {
        group.bench_with_input(
            BenchmarkId::new(
                format!("chunk={}KiB", chunk_size as f64 / KIB as f64),
                format!("nonces={nonces}/threads={}", threads_to_str(threads)),
            ),
            &(nonces, threads),
            |b, &(nonces, threads)| {
                let prover = Prover8_56::new(CHALLENGE, 0..nonces, params.clone()).unwrap();
                b.iter(|| {
                    let f = black_box(|_, _| None);
                    match threads {
                        1 => data.chunks_exact(chunk_size).for_each(|chunk| {
                            prover.prove(chunk, 0, f);
                        }),
                        0 => data
                            .chunks_exact(chunk_size)
                            .par_bridge()
                            .for_each(|chunk| {
                                prover.prove(chunk, 0, f);
                            }),
                        n => {
                            let pool = rayon::ThreadPoolBuilder::new()
                                .num_threads(n)
                                .build()
                                .unwrap();
                            pool.install(|| {
                                data.chunks_exact(chunk_size)
                                    .par_bridge()
                                    .for_each(|chunk| {
                                        prover.prove(chunk, 0, f);
                                    })
                            });
                        }
                    }
                });
            },
        );
    }
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
    targets=prover_bench,
);

criterion_main!(benches);
