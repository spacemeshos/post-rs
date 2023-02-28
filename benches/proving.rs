use std::hint::black_box;

use criterion::{criterion_group, criterion_main, Criterion};
use lazy_static::lazy_static;
use post::{reader::BatchingReader, Prover};
use pprof::criterion::{Output, PProfProfiler};
use rand::{thread_rng, RngCore};

const MB: usize = 1024 * 1024;
const GB: usize = MB * 1024;
const TB: usize = GB * 1024;
const PB: usize = TB * 1024;
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

/// Calculatee the number of bytes to use for the difficulty check.
/// - num_labels is the number of labels contained in the PoST data.
/// - b is a network parameter that defines the number of labels used in one AES Block.
fn calc_d(num_labels: u64, b: usize) -> usize {
    (((num_labels as f64).log2() - (b as f64).log2()) / 8.0).ceil() as usize
}

fn var_d_prover_bench<const N: usize, const POS_SIZE: usize>(c: &mut Criterion) {
    let mut group = c.benchmark_group("proving/variable-D/linearizing");

    let d = calc_d(POS_SIZE as u64, 16);

    let mut prover = post::VarDProver::new(CHALLENGE, 0, 0..N as u32, d);

    group.throughput(criterion::Throughput::Bytes(DATA.len() as u64));
    group.bench_function(
        format!(
            "nonces={N}/D={d}/B=16/aes={}/POS={}TB",
            prover.required_aeses(),
            POS_SIZE as f64 / TB as f64
        ),
        |b| {
            b.iter(|| {
                let reader = BatchingReader::new(DATA.as_slice(), 0, 128 * 1024);
                let f = black_box(|_, _| false);
                assert!(prover.prove(reader, f).is_ok());
            });
        },
    );
}

fn var_d_prover_bench_v2<const N: usize, const POS_SIZE: usize>(c: &mut Criterion) {
    let mut group = c.benchmark_group("proving/variable-D/non-linearizing");

    let d = calc_d(POS_SIZE as u64, 16);

    let mut prover = post::VarDProver2::new(CHALLENGE, 0, 0..N as u32, d);

    group.throughput(criterion::Throughput::Bytes(DATA.len() as u64));
    group.bench_function(
        format!(
            "nonces={N}/D={d}/B=16/aes={}/POS={}TB",
            prover.required_aeses(),
            POS_SIZE as f64 / TB as f64
        ),
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
        var_d_prover_bench::<2, {256*GB}>, var_d_prover_bench::<20, {256*GB}>,
        var_d_prover_bench::<2, {10*TB}>, var_d_prover_bench::<20, {10*TB}>,
        var_d_prover_bench::<2, {PB}>, var_d_prover_bench::<20, {PB}>,
        var_d_prover_bench::<200, {256*GB}>, var_d_prover_bench::<200, {10*TB}>,

        var_d_prover_bench_v2::<20, {10*TB}>, var_d_prover_bench_v2::<200, {10*TB}>,

        prover_bench::<2>, prover_bench::<20>, prover_bench::<200>,

        var_b_prover_bench::<2, 8>, var_b_prover_bench::<20, 8>, var_b_prover_bench::<200, 8>,
);

criterion_main!(benches);
