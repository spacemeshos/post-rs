use std::{hint::black_box, sync::mpsc};

use criterion::{criterion_group, criterion_main, Criterion};
use rand::{thread_rng, RngCore};

fn aes_benchmark(c: &mut Criterion) {
    let mut group = c.benchmark_group("aes");

    let challenge = b"dsadassdada12311";
    let mut data: Vec<u8> = vec![0; 128 << 20];
    thread_rng().fill_bytes(&mut data);

    group.throughput(criterion::Throughput::Bytes(data.len() as u64));
    group.bench_function("prove1", |b| {
        b.iter(|| {
            let (tx, rx) = mpsc::channel();
            post::prove(&data, challenge, 0, &tx);
            black_box(rx)
        });
    });
    group.bench_function("prove4", |b| {
        b.iter(|| {
            let (tx, rx) = mpsc::channel();
            post::prove_many(4, &data, challenge, 0, &tx);
            black_box(rx);
        });
    });
}

criterion_group!(benches, aes_benchmark);
criterion_main!(benches);
