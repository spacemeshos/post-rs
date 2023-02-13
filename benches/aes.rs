use std::{hint::black_box, sync::mpsc, thread};

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
            let (tx, rx) = mpsc::channel();
            prove1(&data, challenge, 0, tx);
            black_box(rx)
        });
    });
    group.bench_function("prove4", |b| {
        b.iter(|| {
            let (tx, rx) = mpsc::channel();
            prove_many(4, &data, challenge, 0, tx);
            black_box(rx);
        });
    });
}

fn prove_many(t: usize, stream: &[u8], challenge: &[u8; 16], d: u64, tx: mpsc::Sender<(u64, u64)>) {
    thread::scope(|s| {
        let chunk = stream.len() / t;
        for i in 0..t {
            let tx = tx.clone();
            let stream = &stream[i * chunk..(i + 1) * chunk];
            s.spawn(|| prove1(stream, challenge, d, tx));
        }
    })
}

fn prove1(stream: &[u8], challenge: &[u8; 16], d: u64, send: mpsc::Sender<(u64, u64)>) {
    let mut output = [0u8; 96];
    let ciphers: Vec<Aes128> = (0..6)
        .map(|i| {
            let mut key = challenge.clone();
            key[15] = i as u8;
            Aes128::new(&key.into())
        })
        .collect();

    for i in 0..(stream.len() / 16) {
        let labels = (&stream[i * 16..(i + 1) * 16]).into();
        for (j, cipher) in ciphers.iter().enumerate() {
            cipher.encrypt_block_b2b(labels, (&mut output[j * 16..(j + 1) * 16]).into())
        }
        unsafe {
            let (_, ints, _) = output.align_to::<u32>();
            for j in 0..20 {
                if ints[j] as u64 <= d {
                    match send.send((j as u64, i as u64)) {
                        Ok(()) => {}
                        Err(_) => return,
                    }
                }
            }
        };
    }
}

criterion_group!(benches, aes_benchmark);
criterion_main!(benches);
