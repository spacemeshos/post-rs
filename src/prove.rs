use aes::cipher::BlockEncrypt;
use cipher::{block_padding::NoPadding, generic_array::GenericArray};
use eyre::Context;
use scrypt_jane::scrypt::ScryptParams;

use std::{collections::HashMap, ops::Range, path::Path};

use crate::{
    cipher::AesCipher, config::Config, difficulty::proving_difficulty, metadata, reader::read_data,
};

const BLOCK_SIZE: usize = 16; // size of the aes block
const AES_BATCH: usize = 8; // will use encrypt8 asm method
const CHUNK_SIZE: usize = BLOCK_SIZE * AES_BATCH;

#[derive(Debug)]
pub struct Proof {
    pub nonce: u32,
    pub indicies: Vec<u64>,
}

pub trait Prover {
    fn prove<F>(&self, batch: &[u8], index: u64, consume: F) -> Option<u32>
    where
        F: FnMut(u32, u64) -> bool;

    fn required_aeses(&self) -> usize;
}

pub struct ConstDProver {
    ciphers: Vec<AesCipher>,
    difficulty: u64,
}

impl ConstDProver {
    pub fn new(
        challenge: &[u8; 32],
        difficulty: u64,
        nonces: Range<u32>,
        params: ScryptParams,
    ) -> Self {
        let start = nonces.start / 2;
        let end = 1.max(nonces.end / 2);
        ConstDProver {
            ciphers: (start..end)
                .map(|n| AesCipher::new(challenge, n, params))
                .collect(),
            difficulty,
        }
    }
}

impl Prover for ConstDProver {
    fn required_aeses(&self) -> usize {
        self.ciphers.len()
    }

    fn prove<F>(&self, batch: &[u8], mut index: u64, mut consume: F) -> Option<u32>
    where
        F: FnMut(u32, u64) -> bool,
    {
        let mut u64s = [0u64; CHUNK_SIZE / 8];

        for chunk in batch.chunks_exact(CHUNK_SIZE) {
            for cipher in &self.ciphers {
                cipher
                    .aes
                    .encrypt_padded_b2b::<NoPadding>(chunk, bytemuck::cast_slice_mut(&mut u64s))
                    .unwrap();

                for (i, out) in u64s.iter().enumerate() {
                    if out.to_le() <= self.difficulty {
                        let nonce = cipher.nonce * 2 + i as u32 % 2;
                        let index = index + (i / 2) as u64;
                        let stop = consume(nonce, index);
                        if stop {
                            return Some(nonce);
                        }
                    }
                }
            }
            index += AES_BATCH as u64;
        }

        None
    }
}

pub struct ConstDVarBProver {
    ciphers: Vec<AesCipher>,
    difficulty: u64,
    b: usize,
}

impl ConstDVarBProver {
    pub fn new(
        challenge: &[u8; 32],
        difficulty: u64,
        nonces: Range<u32>,
        b: usize,
        params: ScryptParams,
    ) -> Self {
        // Every cipher contains output for 2 nonces.
        let num_ciphers = nonces.len() / 2;
        ConstDVarBProver {
            ciphers: nonces
                .take(num_ciphers)
                .map(|n| AesCipher::new(challenge, n, params))
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

    fn prove<F>(&self, batch: &[u8], mut index: u64, mut consume: F) -> Option<u32>
    where
        F: FnMut(u32, u64) -> bool,
    {
        let mut labels = [GenericArray::from([0u8; 16]); 8];
        let mut blocks = [GenericArray::from([0u8; 16]); 8];

        for chunk in batch.chunks_exact(self.b * AES_BATCH) {
            for (i, block) in chunk.chunks_exact(self.b).enumerate() {
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
                            return Some(nonce);
                        }
                    }
                }
            }
            index += AES_BATCH as u64;
        }
        None
    }
}

pub fn generate_proof(datadir: &Path, challenge: &[u8; 32], cfg: Config) -> eyre::Result<Proof> {
    let metadata = metadata::load(datadir).wrap_err("loading metadata")?;

    let num_labels = metadata.num_units as u64 * metadata.labels_per_unit;
    let difficulty = proving_difficulty(num_labels, cfg.b, cfg.k1)?;
    println!("Difficulty: {difficulty:08X}, num_labels: {num_labels}");

    let mut start_nonce = 0;
    let mut end_nonce = start_nonce + cfg.n;
    let aes_pow_params = ScryptParams::new(8, 0, 0);

    loop {
        println!("Generating proof for nonces ({start_nonce}..{end_nonce})");

        for batch in read_data(datadir, 1024 * 1024) {
            let mut indicies = HashMap::<u32, Vec<u64>>::new();

            let prover = ConstDProver::new(
                challenge,
                difficulty,
                start_nonce..end_nonce,
                aes_pow_params,
            );
            let nonce = prover.prove(&batch.data, batch.index, |nonce, index| -> bool {
                let vec = indicies.entry(nonce).or_default();
                vec.push(index);
                if vec.len() >= cfg.k2 as usize {
                    return true;
                }
                false
            });
            if let Some(nonce) = nonce {
                return Ok(Proof {
                    nonce,
                    // SAFETY: unwrap will never fail as we know that the key is present.
                    indicies: indicies.remove(&nonce).unwrap(),
                });
            }
        }

        (start_nonce, end_nonce) = (end_nonce, end_nonce + cfg.n);
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use rand::{thread_rng, RngCore};

    use crate::difficulty::proving_difficulty;

    use super::*;

    #[test]
    fn sanity() {
        let (tx, rx) = std::sync::mpsc::channel();
        let challenge = b"hello world, challenge me!!!!!!!";
        let aes_pow_params = ScryptParams::new(8, 0, 0);
        let prover = ConstDProver::new(challenge, u64::MAX, 0..1, aes_pow_params);
        let res = prover.prove(&[0u8; 16 * 8], 0, |nonce, index| -> bool {
            tx.send((nonce, index)).is_err()
        });
        assert!(res.is_none());
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
        let aes_pow_params = ScryptParams::new(8, 0, 0);

        let proof = loop {
            let mut indicies = HashMap::<u32, Vec<u64>>::new();
            let mut found_nonce = None;

            let prover = ConstDProver::new(
                challenge,
                difficulty,
                start_nonce..end_nonce,
                aes_pow_params,
            );
            prover
                .prove(&data, 0, |nonce, index| -> bool {
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

    #[test]
    fn proving() {
        let challenge = b"hello world, CHALLENGE me!!!!!!!";

        let num_labels = 1e6 as usize;
        let k1 = 1000;
        let k2 = 1000;
        let difficulty = proving_difficulty(num_labels as u64, 16, k1).unwrap();
        let aes_pow_params = ScryptParams::new(8, 0, 0);
        let mut data = vec![0u8; num_labels];
        thread_rng().fill_bytes(&mut data);

        let prover = ConstDProver::new(challenge, difficulty, 0..20, aes_pow_params);

        let mut indicies = HashMap::<u32, Vec<u64>>::new();

        let nonce = prover
            .prove(&data, 0, |nonce, index| -> bool {
                let vec = indicies.entry(nonce).or_default();
                vec.push(index);
                if vec.len() >= k2 {
                    return true;
                }
                false
            })
            .unwrap();

        let indicies = indicies.remove(&nonce).unwrap();
        assert_eq!(k2, indicies.len());
        assert!(nonce < 20);

        // Verify if all indicies really satisfy difficulty
        let cipher = AesCipher::new(challenge, nonce / 2, aes_pow_params);
        let mut out = [0u64; 2];

        for idx in indicies {
            let idx = idx as usize;
            cipher.aes.encrypt_block_b2b(
                data[idx * 16..(idx + 1) * 16].into(),
                bytemuck::cast_slice_mut(out.as_mut_slice()).into(),
            );

            assert!(out[(nonce % 2) as usize] <= difficulty);
        }
    }
}
