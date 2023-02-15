use aes::{
    cipher::{BlockEncrypt, KeyInit},
    Aes128,
};
use cipher::block_padding::NoPadding;
use std::sync::mpsc;

const BLOCK_SIZE: usize = 16; // size of the aes block
const BATCH: usize = 8; // will use encrypt8 asm method

pub struct Prover<const N: usize = 1> {
    ciphers: [Aes128; N],
    output: [u8; BLOCK_SIZE * BATCH],
    d: u64,
}

impl<const N: usize> Prover<N> {
    pub fn new(challenge: &[u8; 16], d: u64) -> Self {
        let ciphers: [Aes128; N] = (0..N as u32)
            .map(|i: u32| {
                let mut key = [0u8; BLOCK_SIZE];
                key[..12].copy_from_slice(&challenge[..12]);
                key[12..].copy_from_slice(&i.to_le_bytes());
                Aes128::new(&key.into())
            })
            .collect::<Vec<_>>()
            .try_into()
            .unwrap();
        let output = [0u8; BLOCK_SIZE * BATCH];
        Prover { ciphers, output, d }
    }

    pub fn prove(&mut self, stream: &[u8], tx: &mpsc::Sender<(u64, u64)>) {
        for i in 0..stream.len() / (BLOCK_SIZE * BATCH) {
            let chunk = &stream[i * BLOCK_SIZE * BATCH..(i + 1) * BLOCK_SIZE * BATCH];
            for (j, cipher) in self.ciphers.iter().enumerate() {
                cipher
                    .encrypt_padded_b2b::<NoPadding>(chunk, &mut self.output)
                    .unwrap();
                unsafe {
                    let (_, ints, _) = self.output.align_to::<u64>();
                    for (out_i, out) in ints.iter().enumerate() {
                        if out.to_le() <= self.d {
                            let j = j * 2;
                            let i = i * 8 + out_i;
                            match tx.send(((j + i % 2) as u64, (i / 2) as u64)) {
                                Ok(()) => {}
                                Err(_) => return,
                            }
                        }
                    }
                }
            }
        }
    }
}

pub fn prove(stream: &[u8], challenge: &[u8; 16], d: u64, tx: &mpsc::Sender<(u64, u64)>) {
    let mut prover = Prover::<1>::new(challenge, d);
    prover.prove(stream, tx);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sanity() {
        let (tx, rx) = mpsc::channel();
        let challenge = b"dsadsadasdsaaaaa";
        let stream = vec![0u8; 16 * 8];
        prove(&stream, &challenge, u64::MAX, &tx);
        drop(tx);
        let rst: Vec<(u64, u64)> = rx.into_iter().collect();
        assert_eq!(rst.len(), 16);
        assert_eq!(
            rst,
            vec![
                (0, 0),
                (1, 0),
                (0, 1),
                (1, 1),
                (0, 2),
                (1, 2),
                (0, 3),
                (1, 3),
                (0, 4),
                (1, 4),
                (0, 5),
                (1, 5),
                (0, 6),
                (1, 6),
                (0, 7),
                (1, 7)
            ],
        );
    }
}
