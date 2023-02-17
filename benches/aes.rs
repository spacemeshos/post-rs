use std::hint::black_box;

use criterion::{criterion_group, criterion_main, Criterion};
use rand::{thread_rng, RngCore};

fn prover_bench<const N: usize>(c: &mut Criterion) {
    let mut group = c.benchmark_group("aes");

    let challenge = b"dsadassdada12311";
    let mut data: Vec<u8> = vec![0; 512 << 20];
    thread_rng().fill_bytes(&mut data);
    let mut prover: post::Prover<N> = post::Prover::new(challenge, 0);

    let name = (N * 2).to_string();
    group.throughput(criterion::Throughput::Bytes(data.len() as u64));
    group.bench_function(name, |b| {
        b.iter(|| {
            let f = black_box(|_, _| Ok(()));
            prover.prove(&data, f);
        });
    });
}

criterion_group!(
    benches,
    prover_bench::<1>,
    prover_bench::<2>,
    prover_bench::<3>,
    prover_bench::<5>,
    prover_bench::<10>,
);
criterion_main!(benches);
