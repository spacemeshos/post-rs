use aes::{
    cipher::{BlockEncrypt, KeyInit},
    Aes128, Aes256,
};
use cipher::{block_padding::NoPadding, generic_array::GenericArray};

use std::{iter::repeat, ops::Range};
use streaming_iterator::StreamingIterator;

use crate::reader::Batch;

const BLOCK_SIZE: usize = 16; // size of the aes block
const AES_BATCH: usize = 8; // will use encrypt8 asm method
const CHUNK_SIZE: usize = BLOCK_SIZE * AES_BATCH;

#[derive(Debug)]
pub struct Proof {
    pub nonce: u32,
    pub indicies: Vec<u64>,
}

pub trait Prover {
    fn prove<F, BatchStream>(&mut self, stream: BatchStream, consume: F) -> eyre::Result<()>
    where
        F: FnMut(u32, u64) -> bool,
        BatchStream: StreamingIterator<Item = Batch>;

    fn required_aeses(&self) -> usize;
}

struct AesCipher {
    pub aes: Aes128,
    pub nonce: u32,
}

impl AesCipher {
    fn new(challenge: &[u8; 32], nonce: u32) -> Self {
        let key_cipher = Aes256::new(challenge.into());
        let mut key = [0u8; BLOCK_SIZE];
        key[0..4].copy_from_slice(&nonce.to_le_bytes());
        key_cipher.encrypt_block(&mut key.into());
        Self {
            aes: Aes128::new(&key.into()),
            nonce,
        }
    }
}

pub struct ConstDProver {
    ciphers: Vec<AesCipher>,
    difficulty: u64,
}

impl ConstDProver {
    pub fn new(challenge: &[u8; 32], difficulty: u64, nonces: Range<u32>) -> Self {
        ConstDProver {
            ciphers: nonces
                .step_by(2) // each cipher encodes 2 nonces
                .map(|n| AesCipher::new(challenge, n))
                .collect(),
            difficulty,
        }
    }
}

impl Prover for ConstDProver {
    fn required_aeses(&self) -> usize {
        self.ciphers.len()
    }

    fn prove<F, BatchStream>(&mut self, mut stream: BatchStream, mut consume: F) -> eyre::Result<()>
    where
        F: FnMut(u32, u64) -> bool,
        BatchStream: StreamingIterator<Item = Batch>,
    {
        let mut u64s = [0u64; CHUNK_SIZE / 8];

        while let Some(batch) = stream.next() {
            let stream = &batch.data;
            let mut index = batch.index;
            for chunk in stream.as_slice().chunks(CHUNK_SIZE) {
                for cipher in &self.ciphers {
                    cipher
                        .aes
                        .encrypt_padded_b2b::<NoPadding>(chunk, bytemuck::cast_slice_mut(&mut u64s))
                        .unwrap();

                    for (i, out) in u64s.into_iter().enumerate() {
                        if out.to_le() <= self.difficulty {
                            let nonce = cipher.nonce * 2 + i as u32 % 2;
                            let index = index + (i / 2) as u64;
                            let stop = consume(nonce, index);
                            if stop {
                                return Ok(());
                            }
                        }
                    }
                }
                index += AES_BATCH as u64;
            }
        }
        Ok(())
    }
}

pub struct ConstDVarBProver {
    ciphers: Vec<AesCipher>,
    difficulty: u64,
    b: usize,
}

impl ConstDVarBProver {
    pub fn new(challenge: &[u8; 32], difficulty: u64, nonces: Range<u32>, b: usize) -> Self {
        // Every cipher contains output for 2 nonces.
        let num_ciphers = nonces.len() / 2;
        ConstDVarBProver {
            ciphers: nonces
                .take(num_ciphers) // each cipher encodes 2 nonces
                .map(|n| AesCipher::new(challenge, n))
                .collect(),
            difficulty,
            b,
        }
    }
}

impl Prover for ConstDVarBProver {
    fn required_aeses(&self) -> usize {
        self.ciphers.len()
    }

    fn prove<F, BatchStream>(&mut self, mut stream: BatchStream, mut consume: F) -> eyre::Result<()>
    where
        F: FnMut(u32, u64) -> bool,
        BatchStream: StreamingIterator<Item = Batch>,
    {
        let mut labels = [GenericArray::from([0u8; 16]); 8];
        let mut blocks = [GenericArray::from([0u8; 16]); 8];

        while let Some(batch) = stream.next() {
            let stream = &batch.data;
            let mut index = batch.index;
            for chunk in stream.as_slice().chunks(self.b * AES_BATCH) {
                for (i, block) in chunk.chunks(self.b).enumerate() {
                    let slice = labels[i].as_mut_slice();
                    slice[0..block.len()].copy_from_slice(block);
                }

                for cipher in &self.ciphers {
                    cipher.aes.encrypt_blocks_b2b(&labels, &mut blocks).unwrap();

                    for (i, block) in blocks.iter().flat_map(|b| b.chunks_exact(8)).enumerate() {
                        let val = u64::from_le_bytes(block.try_into().unwrap());
                        if val <= self.difficulty {
                            let nonce = cipher.nonce + i as u32 % 2;
                            let index = index + (i / 2) as u64;
                            let stop = consume(nonce, index);
                            if stop {
                                return Ok(());
                            }
                        }
                    }
                }
                index += AES_BATCH as u64;
            }
        }
        Ok(())
    }
}

pub struct VarDProver {
    ciphers: Vec<AesCipher>,
    difficulty: u64,
    d: usize,
    nonces: Range<u32>,
}

impl VarDProver {
    pub fn new(challenge: &[u8; 32], difficulty: u64, nonces: Range<u32>, d: usize) -> Self {
        let num_ciphers = ((nonces.len() * d) as f64 / BLOCK_SIZE as f64).ceil() as u32;
        // FIXME(brozansk): fix the range below. It's len is OK, but the values are not.
        VarDProver {
            ciphers: (nonces.start..nonces.start + num_ciphers)
                .map(|n| AesCipher::new(challenge, n))
                .collect(),
            difficulty,
            d,
            nonces,
        }
    }
}

impl Prover for VarDProver {
    fn required_aeses(&self) -> usize {
        self.ciphers.len()
    }

    fn prove<F, BatchStream>(&mut self, mut stream: BatchStream, mut consume: F) -> eyre::Result<()>
    where
        F: FnMut(u32, u64) -> bool,
        BatchStream: StreamingIterator<Item = Batch>,
    {
        let mut bytes = (0..self.ciphers.len())
            .map(|_| [0u8; CHUNK_SIZE])
            .collect::<Vec<_>>();

        let dvals_size = self.nonces.len() * self.d;
        let aes_out_size = self.ciphers.len() * BLOCK_SIZE;
        let needed_size = dvals_size - self.d + 8;
        // required extra bytes to be able to load an u64 from linearized's bytes.
        let u64_alignment = if needed_size > aes_out_size {
            Some(needed_size - aes_out_size)
        } else {
            None
        };

        // Buffers that will keep linearized output from all ciphers per
        // each labels block in AES_BATCH.
        // It "rotates" the `bytes` from:
        // bytes[0] = [<CIPHER_0-BLOCK_0>, ..., <CIPHER_0-BLOCK_N-1>]
        // ...
        // bytes[C-1] = [<CIPHER_C-BLOCK_0>, ..., <CIPHER_C-BLOCK_N-1>]
        // To:
        // linearized[0] = [<CIPHER_0-BLOCK_0>, ..., <CIPHER_C-1-BLOCK_0>]
        // linearized[N-1] = [<CIPHER_0-BLOCK_N-1>, ..., <CIPHER_C-1-BLOCK_N-1>]
        // Where:
        //  - `C` - the number of ciphers used
        //  - `N` - the number of blocks in AES_BATCH
        //
        // Rotation is required to be able to extract u64 values from AES' outputs
        // when the values are on AES buffers' boundary.
        // Note: It can be done without linearization but it's faster.
        let mut linearized = (0..AES_BATCH)
            .map(|_| Vec::with_capacity(needed_size))
            .collect::<Vec<Vec<u8>>>();
        let mask = (1u64 << (self.d * 8)) - 1;

        while let Some(batch) = stream.next() {
            let stream = &batch.data;
            let mut index = batch.index;
            for chunk in stream.as_slice().chunks(CHUNK_SIZE) {
                for buf in &mut linearized {
                    buf.clear();
                }

                for (id, cipher) in self.ciphers.iter().enumerate() {
                    cipher
                        .aes
                        .encrypt_padded_b2b::<NoPadding>(chunk, &mut bytes[id])
                        .unwrap();

                    for (out, block) in bytes[id].chunks(16).zip(&mut linearized) {
                        block.extend_from_slice(out);
                    }
                }

                // Extend each buf in `linearized` if needed to safely build u64 from &[u8] for the last value.
                if let Some(size) = u64_alignment {
                    for buf in &mut linearized {
                        buf.extend(repeat(0).take(size));
                    }
                }

                for (label_block_id, buf) in linearized.iter().enumerate() {
                    for (offset, nonce) in (0..).step_by(self.d).zip(self.nonces.clone()) {
                        let val =
                            u64::from_le_bytes(buf[offset..offset + 8].try_into().unwrap()) & mask;
                        if val <= self.difficulty {
                            let stop = consume(nonce, index + label_block_id as u64);
                            if stop {
                                return Ok(());
                            }
                        }
                    }
                }

                index += AES_BATCH as u64;
            }
        }
        Ok(())
    }
}

// Variant of `VarDProver` that doesn't linearize the hashed data for every label block
pub struct VarDProver2(VarDProver);

impl VarDProver2 {
    pub fn new(challenge: &[u8; 32], difficulty: u64, nonces: Range<u32>, d: usize) -> Self {
        VarDProver2(VarDProver::new(challenge, difficulty, nonces, d))
    }
}

impl Prover for VarDProver2 {
    fn required_aeses(&self) -> usize {
        self.0.ciphers.len()
    }

    fn prove<F, BatchStream>(&mut self, mut stream: BatchStream, mut consume: F) -> eyre::Result<()>
    where
        F: FnMut(u32, u64) -> bool,
        BatchStream: StreamingIterator<Item = Batch>,
    {
        let mut bytes = (0..self.0.ciphers.len())
            .map(|_| [0u8; CHUNK_SIZE])
            .collect::<Vec<_>>();

        let d = self.0.d;
        let mask = (1u64 << (d * 8)) - 1;
        let mut u64buf = [0u8; 8];

        while let Some(batch) = stream.next() {
            let stream = &batch.data;
            let mut index = batch.index;
            for chunk in stream.as_slice().chunks(CHUNK_SIZE) {
                for (id, cipher) in self.0.ciphers.iter().enumerate() {
                    cipher
                        .aes
                        .encrypt_padded_b2b::<NoPadding>(chunk, &mut bytes[id])
                        .unwrap();
                }

                for block_id in 0..AES_BATCH {
                    for (nonce_id, nonce) in self.0.nonces.clone().enumerate() {
                        let offset = nonce_id * d;

                        let val = {
                            let lsb_out_id = offset / 16;
                            let msb_out_id = (offset + d - 1) / 16;
                            let of = offset % 16;

                            let lsb = &bytes[lsb_out_id][block_id * 16..(block_id + 1) * 16];

                            if of + 8 < 16 {
                                // 8B value fits entirely in single AES block
                                u64::from_le_bytes(lsb[of..of + 8].try_into().unwrap())
                            } else {
                                let in_lsb = d.min(16 - of);
                                u64buf[..in_lsb].copy_from_slice(&lsb[of..of + in_lsb]);

                                if in_lsb < d {
                                    // Need to copy some bytes from the next AES block
                                    let in_msb = d - in_lsb;
                                    let msb =
                                        &bytes[msb_out_id][block_id * 16..(block_id + 1) * 16];
                                    u64buf[in_lsb..in_lsb + in_msb].copy_from_slice(&msb[..in_msb]);
                                }

                                u64::from_le_bytes(u64buf)
                            }
                        };
                        let val = val & mask;
                        if val <= self.0.difficulty {
                            let stop = consume(nonce, index + block_id as u64);
                            if stop {
                                return Ok(());
                            }
                        }
                    }
                }

                index += AES_BATCH as u64;
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use rand::{thread_rng, RngCore};
    use streaming_iterator::IntoStreamingIterator;

    use crate::difficulty::proving_difficulty;

    use super::*;

    #[test]
    fn sanity() {
        let (tx, rx) = std::sync::mpsc::channel();
        let challenge = b"hello world, challenge me!!!!!!!";
        let stream = [Batch {
            data: vec![0u8; 16 * 8],
            index: 0,
        }];
        let mut prover = ConstDProver::new(challenge, u64::MAX, 0..1);
        let res = prover.prove(stream.into_streaming_iter(), |nonce, index| -> bool {
            tx.send((nonce, index)).is_err()
        });
        assert!(res.is_ok());
        drop(tx);
        let rst: Vec<(u32, u64)> = rx.into_iter().collect();
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

    #[test]
    /// Test if indicies in a proof are distributed more less uniformly across the whole input range.
    fn indicies_distribution() {
        let challenge = b"hello world, challenge me!!!!!!!";

        const NUM_LABELS: usize = 1024 * 1024;
        const K1: u32 = 1000;
        const K2: usize = 1000;
        let difficulty = proving_difficulty(NUM_LABELS as u64, 16, K1).unwrap();

        let mut data = vec![0u8; NUM_LABELS];
        thread_rng().fill_bytes(&mut data);

        let mut start_nonce = 0;
        let mut end_nonce = start_nonce + 20;
        let proof = loop {
            let stream = [Batch {
                data: data.clone(),
                index: 0,
            }];

            let mut indicies = HashMap::<u32, Vec<u64>>::new();
            let mut found_nonce = None;

            let mut prover = ConstDProver::new(challenge, difficulty, start_nonce..end_nonce);
            prover
                .prove(stream.into_streaming_iter(), |nonce, index| -> bool {
                    let vec = indicies.entry(nonce).or_default();
                    vec.push(index);
                    if vec.len() >= K2 {
                        found_nonce = Some(nonce);
                        return true;
                    }
                    false
                })
                .unwrap();
            if let Some(nonce) = found_nonce {
                break Proof {
                    nonce,
                    // SAFETY: unwrap will never fail as we know that the key is present.
                    indicies: indicies.remove(&nonce).unwrap(),
                };
            }
            (start_nonce, end_nonce) = (end_nonce, end_nonce + 20);
        };

        // verify distribution
        let buckets = 10;
        let expected = K2 / buckets;
        let bucket_id = |idx: u64| -> u64 { idx / (NUM_LABELS as u64 / 16 / buckets as u64) };

        let buckets =
            proof
                .indicies
                .into_iter()
                .fold(HashMap::<u64, usize>::new(), |mut buckets, idx| {
                    *buckets.entry(bucket_id(idx)).or_default() += 1;
                    buckets
                });

        for (id, occurences) in buckets {
            let deviation_from_expected =
                (occurences as isize - expected as isize) as f64 / expected as f64;
            // VERY rough check. The point is to make sure if indexes are not concentrated in any bucket.
            assert!(
                deviation_from_expected.abs() <= 1.0,
                "Too big deviation in proof indexes distribution in bucket {id}: {deviation_from_expected} ({occurences} indexes of {expected} expected)"
            );
        }
    }
}
