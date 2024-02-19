//! Generating [proofs](Proof) that the _Proof Of Space_ data is still held, given the challenge.
//!
//! # parameters
//! Proof generation is configured via [Config](crate::config::Config).
//!
//! # proving algorithm
//! TODO: describe the algorithm
//! ## k2 proof of work
//! TODO: explain

use std::borrow::{Borrow, Cow};

use std::sync::{
    atomic::{AtomicBool, Ordering},
    Mutex,
};
use std::{collections::HashMap, ops::Range, path::Path, time::Instant};

use aes::cipher::block_padding::NoPadding;
use aes::cipher::BlockEncrypt;
use eyre::Context;
use mockall::automock;
use primitive_types::U256;
use randomx_rs::RandomXFlag;
use rayon::prelude::{ParallelBridge, ParallelIterator};
use serde::{Deserialize, Serialize};
use serde_with::{base64::Base64, serde_as};

use crate::config;
use crate::{
    cipher::AesCipher,
    compression::{compress_indices, required_bits},
    config::ProofConfig,
    difficulty::proving_difficulty,
    metadata::{self, PostMetadata},
    pow,
    reader::read_data,
};

const LABEL_SIZE: usize = 16;
const BLOCK_SIZE: usize = 16; // size of the aes block
const AES_BATCH: usize = 8; // will use encrypt8 asm method
const CHUNK_SIZE: usize = BLOCK_SIZE * AES_BATCH;

#[serde_as]
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
pub struct Proof<'a> {
    pub nonce: u32,
    #[serde_as(as = "Base64")]
    pub indices: Cow<'a, [u8]>,
    pub pow: u64,
}

impl Proof<'static> {
    pub fn new(nonce: u32, indices: &[u64], num_labels: u64, pow: u64) -> Self {
        Self {
            nonce,
            indices: Cow::Owned(compress_indices(indices, required_bits(num_labels))),
            pow,
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub struct ProvingParams {
    pub difficulty: u64,
    pub pow_difficulty: [u8; 32],
}

impl ProvingParams {
    pub fn new(metadata: &PostMetadata, cfg: &ProofConfig) -> eyre::Result<Self> {
        let num_labels = metadata.num_units as u64 * metadata.labels_per_unit;
        let mut pow_difficulty = [0u8; 32];
        let difficulty_scaled = U256::from_big_endian(&cfg.pow_difficulty) / metadata.num_units;
        difficulty_scaled.to_big_endian(&mut pow_difficulty);
        Ok(Self {
            difficulty: proving_difficulty(cfg.k1, num_labels).map_err(|e| eyre::eyre!(e))?,
            pow_difficulty,
        })
    }
}

#[automock]
pub trait ProgressReporter {
    fn new_nonce_group(&self, nonces: Range<u32>);
    fn finished_chunk(&self, position: u64, len: usize);
}

pub struct NoopProgressReporter {}

impl ProgressReporter for NoopProgressReporter {
    fn new_nonce_group(&self, _: Range<u32>) {}
    fn finished_chunk(&self, _: u64, _: usize) {}
}

pub trait Prover {
    fn prove<F>(&self, batch: &[u8], index: u64, consume: F) -> Option<(u32, Vec<u64>)>
    where
        F: FnMut(u32, u64) -> Option<Vec<u64>>;

    fn get_pow(&self, nonce: u32) -> Option<u64>;
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

#[derive(Debug)]
pub struct Prover8_56 {
    ciphers: Vec<AesCipher>,
    lazy_ciphers: Vec<AesCipher>,
    difficulty_msb: u8,
    difficulty_lsb: u64,
}

impl Prover8_56 {
    pub(crate) const NONCES_PER_AES: u32 = 16;

    pub fn new<P: pow::Prover>(
        challenge: &[u8; 32],
        nonces: Range<u32>,
        params: ProvingParams,
        pow_prover: &P,
        miner_id: &[u8; 32],
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
        log::info!("calculating proof of work for nonces {nonces:?}",);
        let ciphers: Vec<AesCipher> = nonce_group_range(nonces.clone(), Self::NONCES_PER_AES)
            .map(|nonce_group| {
                log::debug!("calculating proof of work for nonce group {nonce_group}");
                let pow = pow_prover.prove(
                    nonce_group.try_into()?,
                    challenge[..8].try_into().unwrap(),
                    &params.pow_difficulty,
                    miner_id,
                )?;
                log::debug!("proof of work: {pow}");

                Ok(AesCipher::new(challenge, nonce_group, pow))
            })
            .collect::<eyre::Result<_>>()?;

        let lazy_ciphers = nonces
            .map(|nonce| {
                let nonce_group = calc_nonce_group(nonce, Self::NONCES_PER_AES);
                AesCipher::new_lazy(
                    challenge,
                    nonce,
                    nonce_group as u32,
                    ciphers[nonce_group % ciphers.len()].pow,
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
    fn get_pow(&self, nonce: u32) -> Option<u64> {
        self.cipher(nonce).map(|aes| aes.pow)
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
#[allow(clippy::too_many_arguments)]
pub fn generate_proof<Reporter, Stopper>(
    datadir: &Path,
    challenge: &[u8; 32],
    cfg: ProofConfig,
    nonces_size: usize,
    cores: config::Cores,
    pow_flags: RandomXFlag,
    stop: Stopper,
    reporter: Reporter,
) -> eyre::Result<Proof<'static>>
where
    Stopper: Borrow<AtomicBool>,
    Reporter: ProgressReporter + Send + Sync,
{
    let stop = stop.borrow();
    let metadata = metadata::load(datadir).wrap_err("loading metadata")?;
    let params = ProvingParams::new(&metadata, &cfg)?;
    log::info!("generating proof with PoW flags: {pow_flags:?} and params: {params:?}");
    let pow_prover = pow::randomx::PoW::new(pow_flags)?;

    let mut nonces = 0..nonces_size as u32;

    let pool = create_thread_pool(cores).wrap_err("building thread pool")?;

    let total_time = Instant::now();
    loop {
        if stop.load(Ordering::Relaxed) {
            eyre::bail!("proof generation was stopped");
        }
        reporter.new_nonce_group(nonces.clone());

        let indexes = Mutex::new(HashMap::<u32, Vec<u64>>::new());

        let pow_time = Instant::now();
        let prover = pool.install(|| {
            let miner_id = &metadata.node_id;
            Prover8_56::new(challenge, nonces.clone(), params, &pow_prover, miner_id)
                .wrap_err("creating prover")
        })?;

        let pow_secs = pow_time.elapsed().as_secs();
        let pow_mins = pow_secs / 60;
        log::info!("finished k2pow in {pow_mins}m {}s", pow_secs % 60);

        let read_time = Instant::now();
        let data_reader = read_data(datadir, 1024 * 1024, metadata.max_file_size)?;
        log::info!("started reading POST data");
        let result = pool.install(|| {
            data_reader
                .par_bridge()
                .take_any_while(|_| !stop.load(Ordering::Relaxed))
                .find_map_any(|batch| {
                    let res = prover.prove(
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
                    );
                    reporter.finished_chunk(batch.pos, batch.data.len());

                    res
                })
        });
        let read_secs = read_time.elapsed().as_secs();
        let read_mins = read_secs / 60;
        log::info!(
            "finished reading POST data in {read_mins}m {}s",
            read_secs % 60
        );

        if let Some((nonce, indices)) = result {
            let num_labels = metadata.num_units as u64 * metadata.labels_per_unit;
            let pow = prover.get_pow(nonce).unwrap();

            let total_secs = total_time.elapsed().as_secs();
            let total_mins = total_secs / 60;

            log::info!("found proof for nonce: {nonce}, pow: {pow} with {indices:?} indices. It took {total_mins}m {}s", total_secs % 60);
            return Ok(Proof::new(nonce, &indices, num_labels, pow));
        }

        nonces = nonces.end..(nonces.end + nonces_size as u32);
    }
}

fn create_thread_pool(
    cores: config::Cores,
) -> Result<rayon::ThreadPool, rayon::ThreadPoolBuildError> {
    let pool_builder = rayon::ThreadPoolBuilder::new();
    match cores {
        config::Cores::All => pool_builder.build(),
        config::Cores::Any(n) => pool_builder.num_threads(n).build(),
        config::Cores::Pin(mut cores) => pool_builder
            .num_threads(cores.len())
            .spawn_handler(move |thread| {
                let mut b = std::thread::Builder::new();
                if let Some(name) = thread.name() {
                    b = b.name(name.to_owned());
                }
                if let Some(stack_size) = thread.stack_size() {
                    b = b.stack_size(stack_size);
                }
                let core_id = cores.pop();
                b.spawn(move || {
                    if let Some(core_id) = core_id {
                        if !core_affinity::set_for_current(core_affinity::CoreId { id: core_id }) {
                            log::warn!("failed to set core affinity for thread to {}", core_id);
                        }
                    }
                    thread.run()
                })?;
                Ok(())
            })
            .build(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{compression::decompress_indexes, difficulty::proving_difficulty};
    use mockall::predicate::{always, eq};
    use rand::{thread_rng, RngCore};
    use std::{collections::HashMap, iter::repeat};

    #[test]
    fn creating_proof() {
        let indices = vec![0, 1, 2, 3, 4, 5, 6, 7, 8];
        let keep_bits = 4;
        let proof = Proof::new(7, &indices, 9, 77);
        assert_eq!(7, proof.nonce);
        assert_eq!(77, proof.pow);
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
        let cfg = ProofConfig {
            k1: 279,
            k2: 300,
            pow_difficulty: [0xFF; 32],
        };
        let params = ProvingParams::new(&meta, &cfg).unwrap();
        let mut pow_prover = pow::MockProver::new();

        pow_prover
            .expect_prove()
            .with(eq(0), eq([0; 8]), eq(cfg.pow_difficulty), always())
            .once()
            .returning(|_, _, _, _| Ok(0));
        assert!(Prover8_56::new(&[0; 32], 0..16, params, &pow_prover, &meta.node_id).is_ok());

        pow_prover
            .expect_prove()
            .with(eq(1), eq([0; 8]), eq(cfg.pow_difficulty), always())
            .once()
            .returning(|_, _, _, _| Ok(0));
        assert!(Prover8_56::new(&[0; 32], 16..32, params, &pow_prover, &meta.node_id).is_ok());

        assert!(Prover8_56::new(&[0; 32], 0..0, params, &pow_prover, &meta.node_id).is_err());
        assert!(Prover8_56::new(&[0; 32], 1..16, params, &pow_prover, &meta.node_id).is_err());
    }

    #[test]
    fn creating_prover_fails_pow() {
        let meta = PostMetadata {
            labels_per_unit: 1000,
            num_units: 1,
            max_file_size: 1024,
            ..Default::default()
        };
        let cfg = ProofConfig {
            k1: 279,
            k2: 300,
            pow_difficulty: [0xFF; 32],
        };
        let mut pow_prover = pow::MockProver::new();
        pow_prover
            .expect_prove()
            .once()
            .returning(|_, _, _, _| Err(pow::Error::PoWNotFound));
        let params = ProvingParams::new(&meta, &cfg).unwrap();
        assert!(Prover8_56::new(&[0; 32], 0..16, params, &pow_prover, &meta.node_id).is_err());
    }

    /// Test that PoW threshold is scaled with num_units.
    #[test]
    fn scaling_pows_thresholds() {
        let cfg = ProofConfig {
            k1: 32,
            k2: 32,
            pow_difficulty: [0x0F; 32],
        };
        let metadata = PostMetadata {
            num_units: 1,
            labels_per_unit: 100,
            max_file_size: 1,
            node_id: [0u8; 32],
            commitment_atx_id: [0u8; 32],
            nonce: None,
            last_position: None,
        };
        {
            let params = ProvingParams::new(&metadata, &cfg).unwrap();
            assert_eq!(params.pow_difficulty, cfg.pow_difficulty);
        }
        {
            let params = ProvingParams::new(
                &PostMetadata {
                    num_units: 10,
                    ..metadata
                },
                &cfg,
            )
            .unwrap();
            assert!(params.pow_difficulty < cfg.pow_difficulty);
        }
    }

    #[test]
    fn sanity() {
        let (tx, rx) = std::sync::mpsc::channel();
        let challenge = b"hello world, challenge me!!!!!!!";
        let params = ProvingParams {
            difficulty: u64::MAX,
            pow_difficulty: [0xFF; 32],
        };
        let mut pow_prover = pow::MockProver::new();
        pow_prover.expect_prove().returning(|_, _, _, _| Ok(0));

        let prover = Prover8_56::new(
            challenge,
            0..Prover8_56::NONCES_PER_AES,
            params,
            &pow_prover,
            &[7; 32],
        )
        .unwrap();
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
            difficulty: proving_difficulty(K1, NUM_LABELS as u64).unwrap(),
            pow_difficulty: [0xFF; 32],
        };
        let mut pow_prover = pow::MockProver::new();
        pow_prover.expect_prove().returning(|_, _, _, _| Ok(0));

        let indexes = loop {
            let mut indicies = HashMap::<u32, Vec<u64>>::new();

            let prover = Prover8_56::new(
                challenge,
                start_nonce..end_nonce,
                params,
                &pow_prover,
                &[7; 32],
            )
            .unwrap();

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
            difficulty: proving_difficulty(k1, num_labels as u64).unwrap(),
            pow_difficulty: [0xFF; 32],
        };
        let mut pow_prover = pow::MockProver::new();
        pow_prover
            .expect_prove()
            .once()
            .returning(|_, _, _, _| Ok(0));
        let data = repeat(0..=11) // it's important for range len to not be a multiple of AES block
            .flatten()
            .take(num_labels * LABEL_SIZE)
            .collect::<Vec<u8>>();

        let prover = Prover8_56::new(
            challenge,
            0..Prover8_56::NONCES_PER_AES,
            params,
            &pow_prover,
            &[7; 32],
        )
        .unwrap();

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

    #[test]
    fn creating_thread_pool() {
        let pool = create_thread_pool(config::Cores::All).unwrap();
        assert_eq!(
            std::thread::available_parallelism().unwrap().get(),
            pool.current_num_threads()
        );
        let pool = create_thread_pool(config::Cores::Any(4)).unwrap();
        assert_eq!(4, pool.current_num_threads());
        let pool = create_thread_pool(config::Cores::Pin(vec![0, 1, 2])).unwrap();
        assert_eq!(3, pool.current_num_threads());
    }
}
