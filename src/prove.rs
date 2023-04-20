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

#[derive(Debug)]
pub struct Proof {
    pub nonce: u32,
    pub indices: Vec<u8>,
    pub k2_pow: u64,
    pub k3_pow: u64,
}

impl Proof {
    pub fn new(nonce: u32, indices: &[u64], keep_bits: usize, k2_pow: u64, k3_pow: u64) -> Self {
        Self {
            nonce,
            indices: compress_indices(indices, keep_bits),
            k2_pow,
            k3_pow,
        }
    }
}

#[derive(Debug, Clone)]
pub struct ProvingParams {
    pub difficulty: u64,
    pub k2_pow_difficulty: u64,
    pub k3_pow_difficulty: u64,
    pub pow_scrypt: ScryptParams,
}

impl ProvingParams {
    pub fn new(metadata: &PostMetadata, cfg: &Config) -> eyre::Result<Self> {
        let num_labels = metadata.num_units as u64 * metadata.labels_per_unit;
        Ok(Self {
            difficulty: proving_difficulty(num_labels, cfg.k1)?,
            k2_pow_difficulty: cfg.k2_pow_difficulty / metadata.num_units as u64,
            k3_pow_difficulty: cfg.k3_pow_difficulty / metadata.num_units as u64,
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
#[inline]
fn calc_nonce(nonce_group: u32, per_aes: u32, offset: usize) -> u32 {
    nonce_group * per_aes + (offset as u32 % per_aes)
}

#[inline]
fn calc_nonce_group(nonce: u32, per_aes: u32) -> usize {
    (nonce / per_aes) as usize
}

fn nonce_group_range(nonces: Range<u32>, per_aes: u32) -> Range<u32> {
    let start_group = nonces.start / per_aes;
    let end_group = std::cmp::max(start_group + 1, (nonces.end + per_aes - 1) / per_aes);
    start_group..end_group
}

pub struct Prover64_0 {
    ciphers: Vec<AesCipher>,
    difficulty: u64,
}

impl Prover64_0 {
    const NONCES_PER_AES: u32 = 2;

    pub fn new(challenge: &[u8; 32], nonces: Range<u32>, params: ProvingParams) -> Self {
        Prover64_0 {
            ciphers: nonce_group_range(nonces, Self::NONCES_PER_AES)
                .map(|n| AesCipher::new(challenge, n, params.pow_scrypt, params.k2_pow_difficulty))
                .collect(),
            difficulty: params.difficulty,
        }
    }

    fn cipher(&self, nonce: u32) -> Option<&AesCipher> {
        self.ciphers
            .get(calc_nonce_group(nonce, Self::NONCES_PER_AES) % self.ciphers.len())
    }
}

impl Prover for Prover64_0 {
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
                _ = cipher
                    .aes
                    .encrypt_padded_b2b::<NoPadding>(chunk, bytemuck::cast_slice_mut(&mut u64s));

                for (offset, val) in u64s.iter().enumerate() {
                    if val.to_le() < self.difficulty {
                        let nonce = calc_nonce(cipher.nonce_group, Self::NONCES_PER_AES, offset);
                        let index = index + (offset as u32 / Self::NONCES_PER_AES) as u64;
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

pub struct Prover8_56 {
    ciphers: Vec<AesCipher>,
    lazy_ciphers: Vec<AesCipher>,
    difficulty_msb: u8,
    difficulty_lsb: u64,
}

impl Prover8_56 {
    const NONCES_PER_AES: u32 = 16;
    const NONCES_PER_LAZY_AES: usize = 2;

    pub fn new(challenge: &[u8; 32], nonces: Range<u32>, params: ProvingParams) -> Self {
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
            .step_by(Self::NONCES_PER_LAZY_AES) // We can fit 2 nonces in a single AES cipher.
            .map(|nonce| {
                let nonce_group = calc_nonce_group(nonce, Self::NONCES_PER_AES);
                AesCipher::new_lazy(
                    challenge,
                    nonce,
                    nonce_group as u32,
                    ciphers[nonce_group].k2_pow,
                )
            })
            .collect();

        Self {
            ciphers,
            lazy_ciphers,
            difficulty_msb: (params.difficulty >> 56) as u8,
            difficulty_lsb: params.difficulty & 0x00ff_ffff_ffff_ffff,
        }
    }

    fn cipher(&self, nonce: u32) -> Option<&AesCipher> {
        self.ciphers
            .get(calc_nonce_group(nonce, Self::NONCES_PER_AES) % self.ciphers.len())
    }

    fn check_lsb<F>(
        &self,
        label: &[u8],
        nonce_group: u32,
        nonce_offset: usize,
        base_index: u64,
        mut consume: F,
    ) -> Option<(u32, Vec<u64>)>
    where
        F: FnMut(u32, u64) -> Option<Vec<u64>>,
    {
        // Second half of the difficulty is checked with the shadow ciphers.
        let mut out = [0u64; 2];
        let nonce = calc_nonce(nonce_group, Self::NONCES_PER_AES, nonce_offset);
        let lazy_nonce_group = calc_nonce_group(nonce, Self::NONCES_PER_LAZY_AES as u32);

        self.lazy_ciphers[lazy_nonce_group % self.lazy_ciphers.len()]
            .aes
            .encrypt_block_b2b(label.into(), bytemuck::cast_slice_mut(&mut out).into());

        // to_le() is free on little-endian machines.
        let out_idx = nonce as usize % Self::NONCES_PER_LAZY_AES;
        if (out[out_idx].to_le() & 0x00ff_ffff_ffff_ffff) < self.difficulty_lsb {
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
                            let label_offset = offset / Self::NONCES_PER_AES as usize;
                            if let Some(p) = self.check_lsb(
                                &chunk[label_offset..label_offset + LABEL_SIZE],
                                cipher.nonce_group,
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

pub struct Prover16_48 {
    ciphers: Vec<AesCipher>,
    lazy_ciphers: Vec<AesCipher>,
    difficulty_msb: u16,
    difficulty_lsb: u64,
}

impl Prover16_48 {
    const NONCES_PER_AES: u32 = 8;
    const NONCES_PER_LAZY_AES: usize = 2;

    pub fn new(challenge: &[u8; 32], nonces: Range<u32>, params: ProvingParams) -> Self {
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
            .step_by(Self::NONCES_PER_LAZY_AES) // We can fit 2 nonces in a single AES cipher.
            .map(|nonce| {
                let nonce_group = calc_nonce_group(nonce, Self::NONCES_PER_AES);
                AesCipher::new_lazy(
                    challenge,
                    nonce,
                    nonce_group as u32,
                    ciphers[nonce_group].k2_pow,
                )
            })
            .collect();

        Self {
            ciphers,
            lazy_ciphers,
            difficulty_msb: (params.difficulty >> 48) as u16,
            difficulty_lsb: params.difficulty & 0x0000_ffff_ffff_ffff,
        }
    }

    fn cipher(&self, nonce: u32) -> Option<&AesCipher> {
        self.ciphers
            .get(calc_nonce_group(nonce, Self::NONCES_PER_AES) % self.ciphers.len())
    }

    fn check_lsb<F>(
        &self,
        label: &[u8],
        nonce_group: u32,
        nonce_offset: usize,
        base_index: u64,
        mut consume: F,
    ) -> Option<(u32, Vec<u64>)>
    where
        F: FnMut(u32, u64) -> Option<Vec<u64>>,
    {
        // Second half of the difficulty is checked with the shadow ciphers.
        let mut out = [0u64; 2];
        let nonce = calc_nonce(nonce_group, Self::NONCES_PER_AES, nonce_offset);
        let lazy_nonce_group = calc_nonce_group(nonce, Self::NONCES_PER_LAZY_AES as u32);

        self.lazy_ciphers[lazy_nonce_group % self.lazy_ciphers.len()]
            .aes
            .encrypt_block_b2b(label.into(), bytemuck::cast_slice_mut(&mut out).into());

        // to_le() is free on little-endian machines.
        let out_idx = nonce as usize % Self::NONCES_PER_LAZY_AES;
        if (out[out_idx].to_le() & 0x0000_ffff_ffff_ffff) < self.difficulty_lsb {
            let index = base_index + (nonce_offset / Self::NONCES_PER_AES as usize) as u64;
            if let Some(indexes) = consume(nonce, index) {
                return Some((nonce, indexes));
            }
        }
        None
    }
}

impl Prover for Prover16_48 {
    fn get_k2_pow(&self, nonce: u32) -> Option<u64> {
        self.cipher(nonce).map(|aes| aes.k2_pow)
    }

    fn prove<F>(&self, batch: &[u8], mut index: u64, mut consume: F) -> Option<(u32, Vec<u64>)>
    where
        F: FnMut(u32, u64) -> Option<Vec<u64>>,
    {
        let mut u16s = [0u16; CHUNK_SIZE / 2];

        for chunk in batch.chunks_exact(CHUNK_SIZE) {
            for cipher in &self.ciphers {
                _ = cipher
                    .aes
                    .encrypt_padded_b2b::<NoPadding>(chunk, bytemuck::cast_slice_mut(&mut u16s));

                for (offset, msb) in u16s.iter().enumerate() {
                    let msb = msb.to_le();
                    if msb <= self.difficulty_msb {
                        if msb == self.difficulty_msb {
                            // Check LSB
                            let label_offset = offset / Self::NONCES_PER_AES as usize;
                            if let Some(p) = self.check_lsb(
                                &chunk[label_offset..label_offset + LABEL_SIZE],
                                cipher.nonce_group,
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

pub struct Prover32_32 {
    ciphers: Vec<AesCipher>,
    lazy_ciphers: Vec<AesCipher>,
    difficulty_msb: u32,
    difficulty_lsb: u32,
}

impl Prover32_32 {
    const NONCES_PER_AES: u32 = 4;
    const NONCES_PER_LAZY_AES: usize = 4;

    pub fn new(challenge: &[u8; 32], nonces: Range<u32>, params: ProvingParams) -> Self {
        let ciphers: Vec<AesCipher> = nonce_group_range(nonces.clone(), Self::NONCES_PER_AES)
            .map(|n| AesCipher::new(challenge, n, params.pow_scrypt, params.k2_pow_difficulty))
            .collect();

        let lazy_ciphers = nonces
            .step_by(Self::NONCES_PER_LAZY_AES) // We can fit 2 nonces in a single AES cipher.
            .map(|nonce| {
                let nonce_group = calc_nonce_group(nonce, Self::NONCES_PER_AES);
                AesCipher::new_lazy(
                    challenge,
                    nonce,
                    nonce_group as u32,
                    ciphers[nonce_group].k2_pow,
                )
            })
            .collect();

        Self {
            ciphers,
            lazy_ciphers,
            difficulty_msb: (params.difficulty >> 32) as u32,
            difficulty_lsb: params.difficulty as u32,
        }
    }

    fn cipher(&self, nonce: u32) -> Option<&AesCipher> {
        self.ciphers
            .get(calc_nonce_group(nonce, Self::NONCES_PER_AES) % self.ciphers.len())
    }

    fn check_lsb<F>(
        &self,
        label: &[u8],
        nonce_group: u32,
        nonce_offset: usize,
        base_index: u64,
        mut consume: F,
    ) -> Option<(u32, Vec<u64>)>
    where
        F: FnMut(u32, u64) -> Option<Vec<u64>>,
    {
        // Second half of the difficulty is checked with the shadow ciphers.
        let mut out = [0u32; Self::NONCES_PER_LAZY_AES];
        let nonce = calc_nonce(nonce_group, Self::NONCES_PER_AES, nonce_offset);
        let lazy_nonce_group = calc_nonce_group(nonce, Self::NONCES_PER_LAZY_AES as u32);

        self.lazy_ciphers[lazy_nonce_group % self.lazy_ciphers.len()]
            .aes
            .encrypt_block_b2b(label.into(), bytemuck::cast_slice_mut(&mut out).into());

        // to_le() is free on little-endian machines.
        let out_idx = nonce as usize % Self::NONCES_PER_LAZY_AES;
        if out[out_idx].to_le() < self.difficulty_lsb {
            let index = base_index + (nonce_offset / Self::NONCES_PER_AES as usize) as u64;
            if let Some(indexes) = consume(nonce, index) {
                return Some((nonce, indexes));
            }
        }
        None
    }
}

impl Prover for Prover32_32 {
    fn get_k2_pow(&self, nonce: u32) -> Option<u64> {
        self.cipher(nonce).map(|aes| aes.k2_pow)
    }

    fn prove<F>(&self, batch: &[u8], mut index: u64, mut consume: F) -> Option<(u32, Vec<u64>)>
    where
        F: FnMut(u32, u64) -> Option<Vec<u64>>,
    {
        let mut u32s = [0u32; CHUNK_SIZE / 4];

        for chunk in batch.chunks_exact(CHUNK_SIZE) {
            for cipher in &self.ciphers {
                cipher
                    .aes
                    .encrypt_padded_b2b::<NoPadding>(chunk, bytemuck::cast_slice_mut(&mut u32s))
                    .unwrap();

                for (offset, msb) in u32s.iter().enumerate() {
                    let msb = msb.to_le();
                    if msb <= self.difficulty_msb {
                        if msb == self.difficulty_msb {
                            // Check LSB
                            let label_offset = offset / Self::NONCES_PER_AES as usize;
                            if let Some(p) = self.check_lsb(
                                &chunk[label_offset..label_offset + LABEL_SIZE],
                                cipher.nonce_group,
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
        let prover = Prover64_0::new(challenge, start_nonce..end_nonce, params.clone());

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
            let k3_pow = crate::pow::find_k3_pow(
                challenge,
                nonce,
                &compressed_indices,
                params.pow_scrypt,
                params.k3_pow_difficulty,
                prover.cipher(nonce).unwrap().k2_pow,
            );
            return Ok(Proof {
                nonce,
                indices: compressed_indices,
                k2_pow: prover.get_k2_pow(nonce).unwrap(),
                k3_pow,
            });
        }

        (start_nonce, end_nonce) = (end_nonce, end_nonce + nonces as u32);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::difficulty::proving_difficulty;
    use rand::{thread_rng, RngCore};
    use std::{collections::HashMap, iter::repeat};

    /// Test that PoW thresholds are scaled with num_units.
    #[test]
    fn scaling_pows_thresholds() {
        let cfg = Config {
            k1: 32,
            k2: 32,
            k3: 10,
            k2_pow_difficulty: u64::MAX / 100,
            k3_pow_difficulty: u64::MAX / 8,
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
        assert_eq!(
            cfg.k3_pow_difficulty / metadata.num_units as u64,
            params.k3_pow_difficulty
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
            k3_pow_difficulty: u64::MAX,
        };
        let prover = Prover64_0::new(challenge, 0..1, params);
        let res = prover.prove(&[0u8; 8 * BLOCK_SIZE], 0, |nonce, index| {
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

        let mut data = vec![0u8; NUM_LABELS * LABEL_SIZE];
        thread_rng().fill_bytes(&mut data);

        let mut start_nonce = 0;
        let mut end_nonce = start_nonce + 20;
        let params = ProvingParams {
            pow_scrypt: ScryptParams::new(1, 0, 0),
            difficulty: proving_difficulty(NUM_LABELS as u64, K1).unwrap(),
            k2_pow_difficulty: u64::MAX,
            k3_pow_difficulty: u64::MAX,
        };

        let indexes = loop {
            let mut indicies = HashMap::<u32, Vec<u64>>::new();

            let prover = Prover64_0::new(challenge, start_nonce..end_nonce, params.clone());

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
    fn proving() {
        let challenge = b"hello world, CHALLENGE me!!!!!!!";

        let num_labels = 1e5 as usize;
        let k1 = 1000;
        let k2 = 1000;
        let params = ProvingParams {
            pow_scrypt: ScryptParams::new(1, 0, 0),
            difficulty: proving_difficulty(num_labels as u64, k1).unwrap(),
            k2_pow_difficulty: u64::MAX,
            k3_pow_difficulty: u64::MAX,
        };
        let mut data = vec![0u8; num_labels * LABEL_SIZE];
        thread_rng().fill_bytes(&mut data);

        let prover = Prover64_0::new(challenge, 0..20, params.clone());

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
                data[idx * BLOCK_SIZE..(idx + 1) * BLOCK_SIZE].into(),
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
            pow_scrypt: ScryptParams::new(8, 0, 0),
            difficulty: proving_difficulty(num_labels as u64, k1).unwrap(),
            k2_pow_difficulty: u64::MAX,
            k3_pow_difficulty: u64::MAX,
        };
        let data = repeat(0..=11) // it's important for range len to not be a multiple of AES block
            .flatten()
            .take(num_labels * LABEL_SIZE)
            .collect::<Vec<u8>>();

        let prover = Prover64_0::new(challenge, 0..20, params);

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
