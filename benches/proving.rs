use std::hint::black_box;

use criterion::{criterion_group, criterion_main, Criterion};
use lazy_static::lazy_static;
use post::{reader::BatchingReader, Prover};
use pprof::criterion::{Output, PProfProfiler};
use rand::{thread_rng, RngCore};

const MB: usize = 1024 * 1024;
const CHALLENGE: &[u8; 32] = b"hello world, CHALLENGE me!!!!!!!";

lazy_static! {
    static ref DATA: Vec<u8> = {
        let mut data = vec![0; 32 * MB];
        thread_rng().fill_bytes(&mut data);
        data
    };
}

fn prover_bench<const N: usize>(c: &mut Criterion) {
    let mut group = c.benchmark_group("proving/const-D");

    let mut prover = post::ConstDProver::new(CHALLENGE, 0, 0..N as u32);

    group.throughput(criterion::Throughput::Bytes(DATA.len() as u64));
    group.bench_function(
        format!("nonces={N}/D=8/B=16/aes={}", prover.required_aeses()),
        |b| {
            b.iter(|| {
                let reader = BatchingReader::new(DATA.as_slice(), 0, 128 * 1024);
                let f = black_box(|_, _| false);
                assert!(prover.prove(reader, f).is_ok());
            });
        },
    );
}

fn var_b_prover_bench<const N: usize, const B: usize>(c: &mut Criterion) {
    let mut group = c.benchmark_group("proving/const-D");

    let mut prover = post::ConstDVarBProver::new(CHALLENGE, 0, 0..N as u32, B);

    group.throughput(criterion::Throughput::Bytes(DATA.len() as u64));
    group.bench_function(
        format!("nonces={N}/D=8/B={B}/aes={}", prover.required_aeses()),
        |b| {
            b.iter(|| {
                let reader = BatchingReader::new(DATA.as_slice(), 0, 128 * 1024);
                let f = black_box(|_, _| false);
                assert!(prover.prove(reader, f).is_ok());
            });
        },
    );
}

criterion_group!(
    name = benches;
    config = Criterion::default().with_profiler(PProfProfiler::new(1000, Output::Flamegraph(None)));
    targets=
        prover_bench::<2>, prover_bench::<20>, prover_bench::<200>,
        var_b_prover_bench::<2, 8>, var_b_prover_bench::<20, 8>, var_b_prover_bench::<200, 8>,
);

criterion_main!(benches);
