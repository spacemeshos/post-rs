//! Generating [proofs](Proof) that the _Proof Of Space_ data is still held, given the challenge.
//!
//! # parameters
//! Proof generation is configured via [Config](crate::config::Config).
//!
//! # proving algorithm
//! TODO: describe the algorithm
//! ## k2 proof of work
//! TODO: explain
//! ## k3 proof of work
//! TODO: explain

use aes::cipher::block_padding::NoPadding;
use aes::cipher::BlockEncrypt;
use eyre::Context;
use scrypt_jane::scrypt::ScryptParams;
use std::{collections::HashMap, ops::Range, path::Path};

use crate::{
    cipher::AesCipher, compression::compress_indexes, config::Config,
    difficulty::proving_difficulty, metadata, reader::read_data,
};

const BLOCK_SIZE: usize = 16; // size of the aes block
const AES_BATCH: usize = 8; // will use encrypt8 asm method
const CHUNK_SIZE: usize = BLOCK_SIZE * AES_BATCH;

#[derive(Debug)]
pub struct Proof {
    pub nonce: u32,
    pub indicies: Vec<u64>,
    pub k2_pow: u64,
    pub k3_pow: u64,
}

#[derive(Debug, Clone)]
pub struct ProvingParams {
    pub difficulty: u64,
    pub k2_pow_difficulty: u64,
    pub k3_pow_difficulty: u64,
    pub scrypt: ScryptParams,
}

pub trait Prover {
    fn prove<F>(&self, batch: &[u8], index: u64, consume: F) -> Option<(u32, Vec<u64>)>
    where
        F: FnMut(u32, u64) -> Option<Vec<u64>>;

    fn get_k2_pow(&self, nonce: u32) -> Option<u64>;
}

pub struct ConstDProver {
    ciphers: Vec<AesCipher>,
    difficulty: u64,
}

impl ConstDProver {
    pub fn new(challenge: &[u8; 32], nonces: Range<u32>, params: ProvingParams) -> Self {
        let start = nonces.start / 2;
        let end = 1.max(nonces.end / 2);
        ConstDProver {
            ciphers: (start..end)
                .map(|n| AesCipher::new(challenge, n, params.scrypt, params.k2_pow_difficulty))
                .collect(),
            difficulty: params.difficulty,
        }
    }

    fn cipher(&self, nonce: u32) -> Option<&AesCipher> {
        self.ciphers.get((nonce as usize / 2) % self.ciphers.len())
    }
}

impl Prover for ConstDProver {
    fn get_k2_pow(&self, nonce: u32) -> Option<u64> {
        self.cipher(nonce).map(|aes| aes.k2_pow)
    }

    fn prove<F>(&self, batch: &[u8], mut index: u64, mut consume: F) -> Option<(u32, Vec<u64>)>
    where
        F: FnMut(u32, u64) -> Option<Vec<u64>>,
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
                        let nonce = cipher.nonce_group * 2 + i as u32 % 2;
                        let index = index + (i / 2) as u64;
                        if let Some(indexes) = consume(nonce, index) {
                            return Some((nonce, indexes));
                        }
                    }
                }
            }
            index += AES_BATCH as u64;
        }

        None
    }
}

/// Generate a proof that data is still held, given the challenge.
pub fn generate_proof(datadir: &Path, challenge: &[u8; 32], cfg: Config) -> eyre::Result<Proof> {
    let metadata = metadata::load(datadir).wrap_err("loading metadata")?;

    let num_labels = metadata.num_units as u64 * metadata.labels_per_unit;
    let difficulty = proving_difficulty(num_labels, cfg.k1)?;

    let mut start_nonce = 0;
    let mut end_nonce = start_nonce + cfg.n;

    let params = ProvingParams {
        scrypt: ScryptParams::new(12, 0, 0),
        difficulty,
        k2_pow_difficulty: cfg.k2_pow_difficulty,
        k3_pow_difficulty: cfg.k3_pow_difficulty,
    };

    loop {
        for batch in read_data(datadir, 1024 * 1024) {
            let mut indexes = HashMap::<u32, Vec<u64>>::new();

            let prover = ConstDProver::new(challenge, start_nonce..end_nonce, params.clone());
            let result = prover.prove(&batch.data, batch.index, |nonce, index| {
                let vec = indexes.entry(nonce).or_default();
                vec.push(index);
                if vec.len() >= cfg.k2 as usize {
                    return Some(std::mem::take(vec));
                }
                None
            });
            if let Some((nonce, indexes)) = result {
                let num_labels = metadata.num_units as u64 * metadata.labels_per_unit;
                let required_bits = num_labels.ilog2() as usize + 1;
                let compressed_indexes = compress_indexes(&indexes, required_bits);
                let k3_pow = crate::pow::find_k3_pow(
                    challenge,
                    nonce,
                    &compressed_indexes,
                    params.scrypt,
                    params.k3_pow_difficulty,
                    prover.cipher(nonce).unwrap().k2_pow,
                );
                return Ok(Proof {
                    nonce,
                    // TODO(poszu) include compressed indexes once we move verification to this library.
                    indicies: indexes,
                    k2_pow: prover.get_k2_pow(nonce).unwrap(),
                    k3_pow,
                });
            }
        }

        (start_nonce, end_nonce) = (end_nonce, end_nonce + cfg.n);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::difficulty::proving_difficulty;
    use rand::{thread_rng, RngCore};
    use std::{collections::HashMap, iter::repeat};

    #[test]
    fn sanity() {
        let (tx, rx) = std::sync::mpsc::channel();
        let challenge = b"hello world, challenge me!!!!!!!";
        let params = ProvingParams {
            scrypt: ScryptParams::new(8, 0, 0),
            difficulty: u64::MAX,
            k2_pow_difficulty: u64::MAX,
            k3_pow_difficulty: u64::MAX,
        };
        let prover = ConstDProver::new(challenge, 0..1, params);
        let res = prover.prove(&[0u8; 16 * 8], 0, |nonce, index| {
            let _ = tx.send((nonce, index));
            None
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

        let mut data = vec![0u8; NUM_LABELS * 16];
        thread_rng().fill_bytes(&mut data);

        let mut start_nonce = 0;
        let mut end_nonce = start_nonce + 20;
        let params = ProvingParams {
            scrypt: ScryptParams::new(8, 0, 0),
            difficulty: proving_difficulty(NUM_LABELS as u64, K1).unwrap(),
            k2_pow_difficulty: u64::MAX,
            k3_pow_difficulty: u64::MAX,
        };

        let indexes = loop {
            let mut indicies = HashMap::<u32, Vec<u64>>::new();

            let prover = ConstDProver::new(challenge, start_nonce..end_nonce, params.clone());

            let result = prover.prove(&data, 0, |nonce, index| {
                let vec = indicies.entry(nonce).or_default();
                vec.push(index);
                if vec.len() >= K2 {
                    return Some(std::mem::take(vec));
                }
                None
            });
            if let Some((_, indexes)) = result {
                break indexes;
            }
            (start_nonce, end_nonce) = (end_nonce, end_nonce + 20);
        };

        // verify distribution
        let buckets = 10;
        let expected = K2 / buckets;
        let bucket_id = |idx: u64| -> u64 { idx / (NUM_LABELS as u64 / 16 / buckets as u64) };

        let buckets = indexes
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

        let num_labels = 1e5 as usize;
        let k1 = 1000;
        let k2 = 1000;
        let params = ProvingParams {
            scrypt: ScryptParams::new(8, 0, 0),
            difficulty: proving_difficulty(num_labels as u64, k1).unwrap(),
            k2_pow_difficulty: u64::MAX,
            k3_pow_difficulty: u64::MAX,
        };
        let mut data = vec![0u8; num_labels * 16];
        thread_rng().fill_bytes(&mut data);

        let prover = ConstDProver::new(challenge, 0..20, params.clone());

        let mut indicies = HashMap::<u32, Vec<u64>>::new();

        let (nonce, indexes) = prover
            .prove(&data, 0, |nonce, index| {
                let vec = indicies.entry(nonce).or_default();
                vec.push(index);
                if vec.len() >= k2 {
                    return Some(std::mem::take(vec));
                }
                None
            })
            .unwrap();

        assert_eq!(k2, indexes.len());
        assert!(nonce < 20);

        // Verify if all indicies really satisfy difficulty
        let cipher = prover.cipher(nonce).unwrap();
        let mut out = [0u64; 2];

        for idx in indexes {
            let idx = idx as usize;
            cipher.aes.encrypt_block_b2b(
                data[idx * 16..(idx + 1) * 16].into(),
                bytemuck::cast_slice_mut(out.as_mut_slice()).into(),
            );

            assert!(out[(nonce % 2) as usize] <= params.difficulty);
        }
    }

    #[test]
    fn proving_vector() {
        let challenge = b"hello world, CHALLENGE me!!!!!!!";

        let num_labels = 128;
        let k1 = 4;
        let k2 = 32;
        let params = ProvingParams {
            scrypt: ScryptParams::new(8, 0, 0),
            difficulty: proving_difficulty(num_labels as u64, k1).unwrap(),
            k2_pow_difficulty: u64::MAX,
            k3_pow_difficulty: u64::MAX,
        };
        let data = repeat(0..=11) // it's important for range len to not be a multiple of AES block
            .flatten()
            .take(num_labels * 16)
            .collect::<Vec<u8>>();

        let prover = ConstDProver::new(challenge, 0..20, params);

        let mut indexes = HashMap::<u32, Vec<u64>>::new();

        let (nonce, indexes) = prover
            .prove(&data, 0, |nonce, index| {
                let vec = indexes.entry(nonce).or_default();
                vec.push(index);
                if vec.len() >= k2 {
                    return Some(std::mem::take(vec));
                }
                None
            })
            .unwrap();
        assert_eq!(2, nonce);

        assert_eq!(
            &[
                2, 5, 8, 11, 14, 17, 20, 23, 26, 29, 32, 35, 38, 41, 44, 47, 50, 53, 56, 59, 62,
                65, 68, 71, 74, 77, 80, 83, 86, 89, 92, 95
            ],
            indexes.as_slice()
        );
    }
}
