use aes::{
    cipher::{BlockEncrypt, KeyInit},
    Aes128,
};
use cipher::block_padding::NoPadding;
use std::sync::mpsc;

const CIPHERS: usize = 6; // each cipher produces two nonces
const BLOCK_SIZE: usize = 16; // size of the aes block
const BATCHED_BLOCKS: usize = 8; // number of aes blocks. will use encrypt8 asm method

pub struct Prover {
    ciphers: [Aes128; CIPHERS],
    output: [u8; BLOCK_SIZE * BATCHED_BLOCKS],
}

impl Prover {
    pub fn new(challenge: &[u8; 16]) -> Self {
        let ciphers: [Aes128; CIPHERS] = (0..CIPHERS as u32)
            .map(|i: u32| {
                let mut key = [0u8; BLOCK_SIZE];
                key[..12].copy_from_slice(&challenge[..12]);
                key[12..].copy_from_slice(&i.to_le_bytes());
                Aes128::new(&key.into())
            })
            .collect::<Vec<_>>()
            .try_into()
            .unwrap();
        let output = [0u8; BLOCK_SIZE * BATCHED_BLOCKS];
        Prover { ciphers, output }
    }

    pub fn prove(&mut self, stream: &[u8], d: u64, tx: &mpsc::Sender<(u64, u64)>) {
        for i in 0..stream.len() / (BLOCK_SIZE * BATCHED_BLOCKS) {
            let chunk =
                &stream[i * BLOCK_SIZE * BATCHED_BLOCKS..(i + 1) * BLOCK_SIZE * BATCHED_BLOCKS];
            for (j, cipher) in self.ciphers.iter().enumerate() {
                cipher
                    .encrypt_padded_b2b::<NoPadding>(chunk, &mut self.output)
                    .unwrap();
                unsafe {
                    let (_, ints, _) = self.output.align_to::<u64>();
                    for (out_i, out) in ints.iter().enumerate() {
                        if out.to_le() <= d {
                            let j = j * 2;
                            let i = i * 8 + out_i;
                            match tx.send(((j + i % 2) as u64, i as u64)) {
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
    let mut prover = Prover::new(challenge);
    prover.prove(stream, d, tx);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sanity() {
        let (tx, rx) = mpsc::channel();
        let challenge = b"dsadsadasdsaaaaa";
        let iterations = 8;
        let stream = vec![0u8; 16 * iterations];
        prove(&stream, &challenge, u64::MAX, &tx);
        drop(tx);
        let rst: Vec<(u64, u64)> = rx.into_iter().collect();
        assert_eq!(rst.len(), 12 * iterations);
        println!("{:?}", rst);
    }
}
