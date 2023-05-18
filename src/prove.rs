//! Generating [proofs](Proof) that the _Proof Of Space_ data is still held, given the challenge.
//!
//! # parameters
//! Proof generation is configured via [Config](crate::config::Config).
//!
//! # proving algorithm
//! TODO: describe the algorithm
//! ## k2 proof of work
//! TODO: explain

use aes::cipher::block_padding::NoPadding;
use aes::cipher::BlockEncrypt;
use eyre::Context;
use rayon::prelude::{ParallelBridge, ParallelIterator};
use scrypt_jane::scrypt::ScryptParams;
use std::{collections::HashMap, ops::Range, path::Path, sync::Mutex};

use crate::{
    cipher::AesCipher,
    compression::{compress_indices, required_bits},
    config::Config,
    difficulty::proving_difficulty,
    metadata::{self, PostMetadata},
    reader::read_data,
};

const LABEL_SIZE: usize = 16;
const BLOCK_SIZE: usize = 16; // size of the aes block
const AES_BATCH: usize = 8; // will use encrypt8 asm method
const CHUNK_SIZE: usize = BLOCK_SIZE * AES_BATCH;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Proof {
    pub nonce: u32,
    pub indices: Vec<u8>,
    pub k2_pow: u64,
}

impl Proof {
    pub fn new(nonce: u32, indices: &[u64], keep_bits: usize, k2_pow: u64) -> Self {
        Self {
            nonce,
            indices: compress_indices(indices, keep_bits),
            k2_pow,
        }
    }
}

#[derive(Debug, Clone)]
pub struct ProvingParams {
    pub difficulty: u64,
    pub k2_pow_difficulty: u64,
    pub pow_scrypt: ScryptParams,
}

impl ProvingParams {
    pub fn new(metadata: &PostMetadata, cfg: &Config) -> eyre::Result<Self> {
        let num_labels = metadata.num_units as u64 * metadata.labels_per_unit;
        Ok(Self {
            difficulty: proving_difficulty(cfg.k1, num_labels)?,
            k2_pow_difficulty: cfg.k2_pow_difficulty / metadata.num_units as u64,
            pow_scrypt: cfg.pow_scrypt,
        })
    }
}

pub trait Prover {
    fn prove<F>(&self, batch: &[u8], index: u64, consume: F) -> Option<(u32, Vec<u64>)>
    where
        F: FnMut(u32, u64) -> Option<Vec<u64>>;

    fn get_k2_pow(&self, nonce: u32) -> Option<u64>;
}

// Calculate nonce value given nonce group and its offset within the group.
#[inline(always)]
fn calc_nonce(nonce_group: u32, per_aes: u32, offset: usize) -> u32 {
    nonce_group * per_aes + (offset as u32 % per_aes)
}

#[inline(always)]
fn calc_nonce_group(nonce: u32, per_aes: u32) -> usize {
    (nonce / per_aes) as usize
}

#[inline(always)]
fn nonce_group_range(nonces: Range<u32>, per_aes: u32) -> Range<u32> {
    let start_group = nonces.start / per_aes;
    let end_group = std::cmp::max(start_group + 1, (nonces.end + per_aes - 1) / per_aes);
    start_group..end_group
}

pub struct Prover8_56 {
    ciphers: Vec<AesCipher>,
    lazy_ciphers: Vec<AesCipher>,
    difficulty_msb: u8,
    difficulty_lsb: u64,
}

impl Prover8_56 {
    pub(crate) const NONCES_PER_AES: u32 = 16;

    pub fn new(
        challenge: &[u8; 32],
        nonces: Range<u32>,
        params: ProvingParams,
    ) -> eyre::Result<Self> {
        // TODO consider to relax it to allow any range of nonces
        eyre::ensure!(
            nonces.start % Self::NONCES_PER_AES == 0,
            "nonces must start at a multiple of 16"
        );
        eyre::ensure!(
            !nonces.is_empty() && nonces.len() % Self::NONCES_PER_AES as usize == 0,
            "nonces must be a multiple of 16"
        );
        let ciphers: Vec<AesCipher> = nonce_group_range(nonces.clone(), Self::NONCES_PER_AES)
            .map(|nonce_group| {
                AesCipher::new(
                    challenge,
                    nonce_group,
                    params.pow_scrypt,
                    params.k2_pow_difficulty,
                )
            })
            .collect();

        let lazy_ciphers = nonces
            .map(|nonce| {
                let nonce_group = calc_nonce_group(nonce, Self::NONCES_PER_AES);
                AesCipher::new_lazy(
                    challenge,
                    nonce,
                    nonce_group as u32,
                    ciphers[nonce_group % ciphers.len()].k2_pow,
                )
            })
            .collect();

        let (difficulty_msb, difficulty_lsb) = Self::split_difficulty(params.difficulty);
        Ok(Self {
            ciphers,
            lazy_ciphers,
            difficulty_msb,
            difficulty_lsb,
        })
    }

    pub(crate) fn split_difficulty(difficulty: u64) -> (u8, u64) {
        ((difficulty >> 56) as u8, difficulty & 0x00ff_ffff_ffff_ffff)
    }

    #[inline(always)]
    fn cipher(&self, nonce: u32) -> Option<&AesCipher> {
        self.ciphers
            .get(calc_nonce_group(nonce, Self::NONCES_PER_AES) % self.ciphers.len())
    }

    #[inline(always)]
    fn lazy_cipher(&self, nonce: u32) -> Option<&AesCipher> {
        self.lazy_ciphers
            .get(nonce as usize % self.lazy_ciphers.len())
    }

    /// LSB part of the difficulty is checked with second sequence of AES ciphers.
    fn check_lsb<F>(
        &self,
        label: &[u8],
        nonce: u32,
        nonce_offset: usize,
        base_index: u64,
        mut consume: F,
    ) -> Option<(u32, Vec<u64>)>
    where
        F: FnMut(u32, u64) -> Option<Vec<u64>>,
    {
        let mut out = [0u64; 2];

        self.lazy_cipher(nonce)
            .unwrap()
            .aes
            .encrypt_block_b2b(label.into(), bytemuck::cast_slice_mut(&mut out).into());

        let lsb = out[0].to_le() & 0x00ff_ffff_ffff_ffff;
        if lsb < self.difficulty_lsb {
            let index = base_index + (nonce_offset / Self::NONCES_PER_AES as usize) as u64;
            if let Some(indexes) = consume(nonce, index) {
                return Some((nonce, indexes));
            }
        }
        None
    }
}

impl Prover for Prover8_56 {
    fn get_k2_pow(&self, nonce: u32) -> Option<u64> {
        self.cipher(nonce).map(|aes| aes.k2_pow)
    }

    fn prove<F>(&self, batch: &[u8], mut index: u64, mut consume: F) -> Option<(u32, Vec<u64>)>
    where
        F: FnMut(u32, u64) -> Option<Vec<u64>>,
    {
        let mut u8s = [0u8; CHUNK_SIZE];

        for chunk in batch.chunks_exact(CHUNK_SIZE) {
            for cipher in &self.ciphers {
                _ = cipher.aes.encrypt_padded_b2b::<NoPadding>(chunk, &mut u8s);

                for (offset, &msb) in u8s.iter().enumerate() {
                    if msb <= self.difficulty_msb {
                        if msb == self.difficulty_msb {
                            // Check LSB
                            let nonce =
                                calc_nonce(cipher.nonce_group, Self::NONCES_PER_AES, offset);
                            let label_offset = offset / Self::NONCES_PER_AES as usize * LABEL_SIZE;
                            if let Some(p) = self.check_lsb(
                                &chunk[label_offset..label_offset + LABEL_SIZE],
                                nonce,
                                offset,
                                index,
                                &mut consume,
                            ) {
                                return Some(p);
                            }
                        } else {
                            // valid label
                            let index = index + (offset as u32 / Self::NONCES_PER_AES) as u64;
                            let nonce =
                                calc_nonce(cipher.nonce_group, Self::NONCES_PER_AES, offset);
                            if let Some(indexes) = consume(nonce, index) {
                                return Some((nonce, indexes));
                            }
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
pub fn generate_proof(
    datadir: &Path,
    challenge: &[u8; 32],
    cfg: Config,
    nonces: usize,
    threads: usize,
) -> eyre::Result<Proof> {
    let metadata = metadata::load(datadir).wrap_err("loading metadata")?;
    let params = ProvingParams::new(&metadata, &cfg)?;

    let mut start_nonce = 0;
    let mut end_nonce = start_nonce + nonces as u32;

    loop {
        let indexes = Mutex::new(HashMap::<u32, Vec<u64>>::new());
        let prover = Prover8_56::new(challenge, start_nonce..end_nonce, params.clone())
            .wrap_err("creating prover")?;

        let pool = rayon::ThreadPoolBuilder::new()
            .num_threads(threads)
            .build()
            .wrap_err("building thread pool")?;

        let result = pool.install(|| {
            read_data(datadir, 1024 * 1024, metadata.max_file_size)
                .par_bridge()
                .find_map_any(|batch| {
                    prover.prove(
                        &batch.data,
                        batch.pos / BLOCK_SIZE as u64,
                        |nonce, index| {
                            let mut indexes = indexes.lock().unwrap();
                            let vec = indexes.entry(nonce).or_default();
                            vec.push(index);
                            if vec.len() >= cfg.k2 as usize {
                                return Some(std::mem::take(vec));
                            }
                            None
                        },
                    )
                })
        });

        if let Some((nonce, indexes)) = result {
            let num_labels = metadata.num_units as u64 * metadata.labels_per_unit;
            let required_bits = required_bits(num_labels);
            let compressed_indices = compress_indices(&indexes, required_bits);

            return Ok(Proof {
                nonce,
                indices: compressed_indices,
                k2_pow: prover.get_k2_pow(nonce).unwrap(),
            });
        }

        (start_nonce, end_nonce) = (end_nonce, end_nonce + nonces as u32);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{compression::decompress_indexes, difficulty::proving_difficulty};
    use rand::{thread_rng, RngCore};
    use std::{collections::HashMap, iter::repeat};

    #[test]
    fn creating_proof() {
        let indices = vec![0, 1, 2, 3, 4, 5, 6, 7, 8];
        let keep_bits = 4;
        let proof = Proof::new(7, &indices, keep_bits, 77);
        assert_eq!(7, proof.nonce);
        assert_eq!(77, proof.k2_pow);
        assert_eq!(
            indices,
            decompress_indexes(&proof.indices, keep_bits)
                .take(indices.len())
                .collect::<Vec<_>>()
        );
    }

    #[test]
    fn creating_prover() {
        let meta = PostMetadata {
            labels_per_unit: 1000,
            num_units: 1,
            max_file_size: 1024,
            ..Default::default()
        };
        let cfg = Config {
            k1: 279,
            k2: 300,
            k3: 65,
            k2_pow_difficulty: u64::MAX,
            pow_scrypt: ScryptParams::new(1, 0, 0),
            scrypt: ScryptParams::new(1, 0, 0),
        };
        assert!(Prover8_56::new(&[0; 32], 0..16, ProvingParams::new(&meta, &cfg).unwrap()).is_ok());
        assert!(
            Prover8_56::new(&[0; 32], 16..32, ProvingParams::new(&meta, &cfg).unwrap()).is_ok()
        );

        assert!(Prover8_56::new(&[0; 32], 0..0, ProvingParams::new(&meta, &cfg).unwrap()).is_err());
        assert!(
            Prover8_56::new(&[0; 32], 1..16, ProvingParams::new(&meta, &cfg).unwrap()).is_err()
        );
    }
    /// Test that PoW thresholds are scaled with num_units.
    #[test]
    fn scaling_pows_thresholds() {
        let cfg = Config {
            k1: 32,
            k2: 32,
            k3: 10,
            k2_pow_difficulty: u64::MAX / 100,
            pow_scrypt: ScryptParams::new(1, 0, 0),
            scrypt: ScryptParams::new(2, 0, 0),
        };
        let metadata = PostMetadata {
            num_units: 10,
            labels_per_unit: 100,
            max_file_size: 1,
            node_id: [0u8; 32],
            commitment_atx_id: [0u8; 32],
            nonce: None,
            last_position: None,
        };

        let params = ProvingParams::new(&metadata, &cfg).unwrap();
        assert_eq!(
            cfg.k2_pow_difficulty / metadata.num_units as u64,
            params.k2_pow_difficulty
        );
    }

    #[test]
    fn sanity() {
        let (tx, rx) = std::sync::mpsc::channel();
        let challenge = b"hello world, challenge me!!!!!!!";
        let params = ProvingParams {
            pow_scrypt: ScryptParams::new(1, 0, 0),
            difficulty: u64::MAX,
            k2_pow_difficulty: u64::MAX,
        };
        let prover = Prover8_56::new(challenge, 0..Prover8_56::NONCES_PER_AES, params).unwrap();
        let res = prover.prove(&[0u8; 8 * LABEL_SIZE], 0, |nonce, index| {
            let _ = tx.send((nonce, index));
            None
        });
        assert!(res.is_none());
        drop(tx);
        let rst: Vec<(u32, u64)> = rx.into_iter().collect();
        assert_eq!(
            (0..8)
                .flat_map(move |x| (0..Prover8_56::NONCES_PER_AES).zip(std::iter::repeat(x)))
                .collect::<Vec<_>>(),
            rst,
        );
    }

    #[test]
    /// Test if indicies in a proof are distributed more less uniformly across the whole input range.
    fn indicies_distribution() {
        let challenge = b"hello world, challenge me!!!!!!!";

        const NUM_LABELS: usize = 1024 * 1024;
        const K1: u32 = 1000;
        const K2: usize = 1000;

        let mut data = vec![0u8; NUM_LABELS * LABEL_SIZE];
        thread_rng().fill_bytes(&mut data);

        let mut start_nonce = 0;
        let mut end_nonce = start_nonce + Prover8_56::NONCES_PER_AES;
        let params = ProvingParams {
            pow_scrypt: ScryptParams::new(1, 0, 0),
            difficulty: proving_difficulty(K1, NUM_LABELS as u64).unwrap(),
            k2_pow_difficulty: u64::MAX,
        };

        let indexes = loop {
            let mut indicies = HashMap::<u32, Vec<u64>>::new();

            let prover =
                Prover8_56::new(challenge, start_nonce..end_nonce, params.clone()).unwrap();

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
        let bucket_id = |idx: u64| -> u64 { idx / (NUM_LABELS / LABEL_SIZE / buckets) as u64 };

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
    fn proving_vector() {
        let challenge = b"hello world, CHALLENGE me!!!!!!!";

        let num_labels = 128;
        let k1 = 4;
        let k2 = 32;
        let params = ProvingParams {
            pow_scrypt: ScryptParams::new(8, 0, 0),
            difficulty: proving_difficulty(k1, num_labels as u64).unwrap(),
            k2_pow_difficulty: u64::MAX,
        };
        let data = repeat(0..=11) // it's important for range len to not be a multiple of AES block
            .flatten()
            .take(num_labels * LABEL_SIZE)
            .collect::<Vec<u8>>();

        let prover = Prover8_56::new(challenge, 0..Prover8_56::NONCES_PER_AES, params).unwrap();

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
        assert_eq!(3, nonce);

        assert_eq!(
            &[
                0, 3, 6, 9, 12, 15, 18, 21, 24, 27, 30, 33, 36, 39, 42, 45, 48, 51, 54, 57, 60, 63,
                66, 69, 72, 75, 78, 81, 84, 87, 90, 93
            ],
            indexes.as_slice()
        );
    }

    #[test]
    fn calculating_nonce_group_range() {
        assert_eq!(0..1, nonce_group_range(0..1, 16));
        assert_eq!(0..1, nonce_group_range(0..4, 16));
        assert_eq!(0..1, nonce_group_range(0..16, 16));
        assert_eq!(0..2, nonce_group_range(0..17, 16));
        assert_eq!(0..2, nonce_group_range(0..18, 16));
        assert_eq!(0..2, nonce_group_range(0..32, 16));
        assert_eq!(0..2, nonce_group_range(1..17, 16));
        assert_eq!(0..2, nonce_group_range(15..17, 16));
        assert_eq!(1..2, nonce_group_range(16..17, 16));
        assert_eq!(1..3, nonce_group_range(30..48, 16));
        assert_eq!(2..3, nonce_group_range(47..48, 16));
    }

    #[test]
    fn nonce_group_for_nonce() {
        assert_eq!(0, calc_nonce_group(0, 16));
        assert_eq!(0, calc_nonce_group(1, 16));
        assert_eq!(0, calc_nonce_group(15, 16));
        assert_eq!(1, calc_nonce_group(16, 16));
        assert_eq!(1, calc_nonce_group(17, 16));
        assert_eq!(1, calc_nonce_group(31, 16));
        assert_eq!(2, calc_nonce_group(32, 16));
    }
}
