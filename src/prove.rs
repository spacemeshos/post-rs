use aes::{
    cipher::{BlockEncrypt, KeyInit},
    Aes128,
};
use std::{sync::mpsc};

pub fn prove(stream: &[u8], challenge: &[u8; 16], d: u64, tx: &mpsc::Sender<(u64, u64)>) {
    const BLOCKS: usize = 6; // number of aes calls per iteration
    const AES_BLOCK: usize = 16;
    const OUTPUTS: usize = 12; // number of outputs from aes BLOCKS

    let mut output = [0u8; AES_BLOCK * BLOCKS];
    let ciphers: Vec<Aes128> = (0..BLOCKS as u32)
        .map(|i: u32| {
            let mut key = [0u8; AES_BLOCK];
            key[..12].copy_from_slice(&challenge[..12]);
            key[12..].copy_from_slice(&i.to_le_bytes());
            Aes128::new(&key.into())
        })
        .collect();
    
    for (i, chunk) in stream.chunks(AES_BLOCK).enumerate() {
        let labels = chunk.into();
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