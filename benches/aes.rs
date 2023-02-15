use std::{hint::black_box, sync::mpsc, thread};

use criterion::{criterion_group, criterion_main, Criterion};
use rand::{thread_rng, RngCore};

fn aes_benchmark(c: &mut Criterion) {
    let mut group = c.benchmark_group("aes");

    let challenge = b"dsadassdada12311";
    let mut data: Vec<u8> = vec![0; 512 << 20];
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
            prove_many(4, &data, challenge, 0, &tx);
            black_box(rx);
        });
    });
}

pub fn prove_many(
    t: usize,
    stream: &[u8],
    challenge: &[u8; 16],
    d: u64,
    tx: &mpsc::Sender<(u64, u64)>,
) {
    thread::scope(|s| {
        let chunk = stream.len() / t;
        for i in 0..t {
            let tx = tx.clone();
            let stream = &stream[i * chunk..(i + 1) * chunk];
            s.spawn(move || post::prove(stream, challenge, d, &tx));
        }
    })
}

criterion_group!(benches, aes_benchmark);
criterion_main!(benches);
