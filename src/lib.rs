use aes::{
    cipher::{BlockEncrypt, KeyInit},
    Aes128,
};
use std::{sync::mpsc, thread};

fn as_u40(b: &[u8]) -> u64 {
    (b[0] as u64)
        | (b[1] as u64) << 8
        | (b[2] as u64) << 16
        | (b[3] as u64) << 24
        | (b[4] as u64) << 32
}

fn as_u34(b: &[u8], i: usize) -> u64 {
    const MASK: u64 = u64::MAX >> 30;
    let start = i / 8;
    (as_u40(&b[start..start + 5]) >> i % 8) & MASK
}

pub fn prove(stream: &[u8], challenge: &[u8; 16], d: u64, tx: mpsc::Sender<(u64, u64)>) {
    let mut output = [0u8; 112];
    let ciphers: Vec<Aes128> = (0..7)
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
        for j in 0..20 {
            if as_u40(&output[j*5..]) as u64 <= d {
                match tx.send((j as u64, i as u64)) {
                    Ok(()) => {}
                    Err(_) => return,
                }
            }
        }
    }
}

pub fn prove_many(
    t: usize,
    stream: &[u8],
    challenge: &[u8; 16],
    d: u64,
    tx: mpsc::Sender<(u64, u64)>,
) {
    thread::scope(|s| {
        let chunk = stream.len() / t;
        for i in 0..t {
            let tx = tx.clone();
            let stream = &stream[i * chunk..(i + 1) * chunk];
            s.spawn(|| prove(stream, challenge, d, tx));
        }
    })
}
