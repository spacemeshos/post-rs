use aes::{
    cipher::{BlockEncrypt, KeyInit},
    Aes128,
};
use std::{sync::mpsc, thread};

pub fn prove(stream: &[u8], challenge: &[u8; 16], d: u64, tx: mpsc::Sender<(u64, u64)>) {
    let mut output = [0u8; 16 * 6];
    let ciphers: Vec<Aes128> = (0..6)
        .map(|i: u32| {
            let mut key = [0u8; 16];
            key[..12].copy_from_slice(&challenge[..12]);
            key[12..].copy_from_slice(&i.to_le_bytes());
            Aes128::new(&key.into())
        })
        .collect();

    for i in 0..(stream.len() / 16) {
        let labels = (&stream[i * 16..(i + 1) * 16]).into();
        for (j, cipher) in ciphers.iter().enumerate() {
            cipher.encrypt_block_b2b(labels, (&mut output[j * 16..(j + 1) * 16]).into())
        }
        unsafe {
            // this can target only systems with little endian, which is most of them
            // on big endian systems we will have to copy.
            let (_, ints, _) = output.align_to::<u64>();
            for j in 0..12 {
                if ints[j] <= d {
                    match tx.send((j as u64, i as u64)) {
                        Ok(()) => {}
                        Err(_) => return,
                    }
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
