use aes::{
    cipher::{BlockEncrypt, KeyInit},
    Aes128,
};
use std::{sync::mpsc, thread};

pub fn prove(stream: &[u8], challenge: &[u8; 16], d: u64, tx: mpsc::Sender<(u64, u64)>) {
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
                    match tx.send((j as u64, i as u64)) {
                        Ok(()) => {}
                        Err(_) => return,
                    }
                }
            }
        };
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
