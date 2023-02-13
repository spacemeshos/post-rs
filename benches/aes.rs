use std::hint::black_box;

use aes::{
    cipher::{generic_array::GenericArray, BlockEncrypt, KeyInit},
    Aes128,
};
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
            black_box(prove1(&data, challenge, 0));
        });
    });
}

fn prove1(stream: &[u8], challenge: &[u8; 16], d: u64) -> Vec<usize> {
    let mut indices = vec![];
    let mut output = [0u8; 96];
    let ciphers: Vec<Aes128> = (0..6)
        .map(|i| {
            let mut key = challenge.clone();
            key[15] = i as u8;
            Aes128::new(&GenericArray::from(key))
        })
        .collect();

    for i in 0..(stream.len() / 16) {
        let labels = GenericArray::from_slice(&stream[i * 16..(i + 1) * 16]);
        for (j, cipher) in ciphers.iter().enumerate() {
            cipher.encrypt_block_b2b(labels, (&mut output[j * 16..(j + 1) * 16]).into())
        }
        unsafe {
            let (_, ints, _) = output.align_to::<u32>();
            for j in 0..20 {
                if ints[j] as u64 <= d {
                    indices.push(i)
                }
            }
        }
    }
    indices
}

criterion_group!(benches, aes_benchmark);
criterion_main!(benches);
