#![feature(slice_as_chunks)]

use blake3::Hasher;
use criterion::{criterion_group, criterion_main, Criterion};
use rand::{thread_rng, RngCore};

fn criterion_benchmark(c: &mut Criterion) {
    let mut group = c.benchmark_group("blake3");

    let challenge = b"challlenegeeeee32131231312312111";
    let size: usize = 32 << 20;
    let mut stream: Vec<u8> = vec![0; size];
    thread_rng().fill_bytes(&mut stream);

    group.throughput(criterion::Throughput::Bytes(size as u64));
    group.bench_function("blake3", |b| {
        b.iter(|| prove(&stream, &challenge, 0));
    });
}

criterion_group!(benches, criterion_benchmark);
criterion_main!(benches);

fn as_u40(b: &[u8]) -> u64 {
    (b[0] as u64)
        | (b[1] as u64) << 8
        | (b[2] as u64) << 16
        | (b[3] as u64) << 24
        | (b[4] as u64) << 32
}

fn prove(stream: &[u8], challenge: &[u8; 32], d: u64) {
    let mut hasher = Hasher::new();
    let mut out: Vec<u8> = vec![0; 85];
    let (chunks, _) = stream.as_chunks::<16>();
    for chunk in chunks {
        hasher.update(challenge);
        hasher.update(chunk);
        hasher.finalize_xof().fill(out.as_mut_slice());
        hasher.reset();
        // this seems to have very insignificant impact
        // might be optimized away
        for _ in 0..20 {
            if as_u40(&out[0..5]) <= d {

            }
        }
    }
}
