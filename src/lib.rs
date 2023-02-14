use aes::{
    cipher::{BlockEncrypt, KeyInit},
    Aes128,
};
use std::{sync::mpsc, thread};

pub mod verify;

pub fn prove(stream: &[u8], challenge: &[u8; 16], d: u64, tx: &mpsc::Sender<(u64, u64)>) {
    const BLOCKS: usize = 6; // number of aes calls per iteration
    const OUTPUTS: usize = 12; // number of outputs from aes BLOCKS

    let mut output = [0u8; 16 * BLOCKS];
    let ciphers: Vec<Aes128> = (0..BLOCKS as u32)
        .map(|i: u32| {
            let mut key = [0u8; 16];
            key[..12].copy_from_slice(&challenge[..12]);
            key[12..].copy_from_slice(&i.to_le_bytes());
            Aes128::new(&key.into())
        })
        .collect();

    for i in 0..(stream.len() / 16) {
        // there is of by 1 error
        let labels = (&stream[i * 16..(i + 1) * 16]).into();
        for (j, cipher) in ciphers.iter().enumerate() {
            cipher.encrypt_block_b2b(labels, (&mut output[j * 16..(j + 1) * 16]).into());
        }
        unsafe {
            let (_, ints, _) = output.align_to::<u64>();
            for j in 0..OUTPUTS {
                if ints[j].to_le() <= d {
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
    tx: &mpsc::Sender<(u64, u64)>,
) {
    thread::scope(|s| {
        let chunk = stream.len() / t;
        for i in 0..t {
            let tx = tx.clone();
            let stream = &stream[i * chunk..(i + 1) * chunk];
            s.spawn(move || prove(stream, challenge, d, &tx));
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sanity() {
        let (tx, rx) = mpsc::channel();
        let challenge = b"dsadsadasdsaaaaa";
        let iterations = 3;
        let stream = vec![0u8; 16 * iterations];
        prove(&stream, &challenge, u64::MAX, &tx);
        drop(tx);
        let rst: Vec<(u64, u64)> = rx.into_iter().collect();
        assert_eq!(rst.len(), 12 * iterations);
        println!("{:?}", rst);
    }
}
