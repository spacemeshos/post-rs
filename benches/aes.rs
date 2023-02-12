use std::hint::black_box;

use aes::{
    cipher::{generic_array::GenericArray, BlockEncrypt, KeyInit},
    Aes128,
};
use criterion::{criterion_group, criterion_main, Criterion};
use rand::{thread_rng, RngCore};
use std::thread::scope;

fn aes_benchmark(c: &mut Criterion) {
    let mut group = c.benchmark_group("aes");

    let challenge = b"dsadassdada12311";
    let mut data: Vec<u8> = vec![0; 128 << 20];
    thread_rng().fill_bytes(&mut data);

    group.throughput(criterion::Throughput::Bytes(data.len() as u64));
    group.bench_function("prove1", |b| {
        b.iter(|| {
            black_box(prove1(&data, challenge, 0));
        });
    });
    group.bench_function("prove1_workers2", |b| {
        b.iter(|| {
            let workers = 2;
            let chunk = data.len() / workers;
            scope(|s| {
                for i in 0..workers {
                    let chunk = &data[i*chunk..(i+1)*chunk];
                    s.spawn(|| black_box(prove1(chunk, challenge, 0)));
                }
            });
        });
    });
}

fn as_u40(b: &[u8]) -> u64 {
    (b[0] as u64)
        | (b[1] as u64) << 8
        | (b[2] as u64) << 16
        | (b[3] as u64) << 24
        | (b[4] as u64) << 32
}

fn as_u34(b: &[u8], i: usize) -> u64 {
    const MASK: u64 = u64::MAX >> 28;
    let start = i / 8;
    (as_u40(&b[start..start + 5]) >> i % 8) & MASK
}

fn prove1(stream: &[u8], challenge: &[u8; 16], d: u64) -> Vec<usize> {
    let mut indices = vec![];
    let mut output = vec![0u8; 96];
    let ciphers: Vec<Aes128> = (0..6)
        .into_iter()
        .map(|i| {
            let mut key = challenge.clone();
            key[15] = i;
            Aes128::new(&GenericArray::from(key))
        })
        .collect();

    for i in 0..(stream.len() / 16) {
        let labels = GenericArray::from_slice(&stream[i * 16..(i + 1) * 16]);
        for (j, cipher) in (&ciphers).iter().enumerate() {
            cipher.encrypt_block_b2b(labels, (&mut output[j * 16..(j + 1) * 16]).into())
        }
        for j in 0..20 {
            if as_u34(&output, j * 34) <= d {
                indices.push(i)
            }
        }
    }
    indices
}


criterion_group!(benches, aes_benchmark);
criterion_main!(benches);
