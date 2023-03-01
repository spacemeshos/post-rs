use std::hint::black_box;

use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion};
use lazy_static::lazy_static;
use post::Prover;
use pprof::criterion::{Output, PProfProfiler};
use rand::{thread_rng, RngCore};
use rayon::prelude::{ParallelBridge, ParallelIterator};

const KIB: usize = 1024;
const MIB: usize = 1024 * KIB;

const CHALLENGE: &[u8; 32] = b"hello world, CHALLENGE me!!!!!!!";

lazy_static! {
    static ref DATA: Vec<u8> = {
        let mut data = vec![0; 32 * MIB];
        thread_rng().fill_bytes(&mut data);
        data
    };
}

fn threads_to_str(threads: usize) -> String {
    if threads == 0 {
        "auto".into()
    } else {
        threads.to_string()
    }
}

fn prover_bench(c: &mut Criterion) {
    let mut group = c.benchmark_group("proving");
    group.throughput(criterion::Throughput::Bytes(DATA.len() as u64));

    let chunk_size = 64 * KIB;

    for (nonces, threads) in itertools::iproduct!(
        [2, 20, 200],
        [0, 1] // 0 == automatic
    ) {
        group.bench_with_input(
            BenchmarkId::new(
                format!("D=8/B=16/chunk={}KiB", chunk_size as f64 / KIB as f64),
                format!("nonces={nonces}/threads={}", threads_to_str(threads)),
            ),
            &(nonces, threads),
            |b, &(nonces, threads)| {
                let prover = post::ConstDProver::new(CHALLENGE, 0, 0..nonces);
                b.iter(|| {
                    let f = black_box(|_, _| false);
                    match threads {
                        1 => DATA.chunks(chunk_size).for_each(|chunk| {
                            prover.prove(chunk, 0, f);
                        }),
                        0 => DATA.chunks(chunk_size).par_bridge().for_each(|chunk| {
                            prover.prove(chunk, 0, f);
                        }),
                        n => {
                            let pool = rayon::ThreadPoolBuilder::new()
                                .num_threads(n)
                                .build()
                                .unwrap();
                            pool.install(|| {
                                DATA.chunks(chunk_size).par_bridge().for_each(|chunk| {
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

fn var_b_prover_bench(c: &mut Criterion) {
    let mut group = c.benchmark_group("proving");
    group.throughput(criterion::Throughput::Bytes(DATA.len() as u64));

    let chunk_size = 64 * KIB;

    for (nonces, threads, param_b) in itertools::iproduct!(
        [2, 20, 200],
        [0, 1], // 0 == automatic
        [8]
    ) {
        group.bench_with_input(
            BenchmarkId::new(
                format!("D=8/chunk={}KiB", chunk_size as f64 / KIB as f64),
                format!(
                    "B={param_b}/nonces={nonces}/threads={}",
                    threads_to_str(threads)
                ),
            ),
            &(nonces, threads, param_b),
            |b, &(nonces, threads, param_b)| {
                let prover = post::ConstDVarBProver::new(CHALLENGE, 0, 0..nonces, param_b);
                b.iter(|| {
                    let f = black_box(|_, _| false);
                    match threads {
                        1 => DATA.chunks(chunk_size).for_each(|chunk| {
                            prover.prove(chunk, 0, f);
                        }),
                        0 => DATA.chunks(chunk_size).par_bridge().for_each(|chunk| {
                            prover.prove(chunk, 0, f);
                        }),
                        n => {
                            let pool = rayon::ThreadPoolBuilder::new()
                                .num_threads(n)
                                .build()
                                .unwrap();
                            pool.install(|| {
                                DATA.chunks(chunk_size).par_bridge().for_each(|chunk| {
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

criterion_group!(
    name = benches;
    config = Criterion::default().with_profiler(PProfProfiler::new(1000, Output::Flamegraph(None)));
    targets=
        prover_bench,
        var_b_prover_bench,
);

criterion_main!(benches);
