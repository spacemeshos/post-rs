pub use randomx_rs::RandomXFlag;
use randomx_rs::{RandomXCache, RandomXDataset, RandomXError, RandomXVM};
use rayon::prelude::{IntoParallelIterator, ParallelIterator};
use std::sync::atomic::{AtomicUsize, Ordering};
use thread_local::ThreadLocal;

use super::{Error, PowVerifier, Prover};

const RANDOMX_CACHE_KEY: &[u8] = b"spacemesh-randomx-cache-key";

impl From<randomx_rs::RandomXError> for Error {
    fn from(e: randomx_rs::RandomXError) -> Self {
        Error::Internal(Box::new(e))
    }
}

pub struct PoW {
    cache: Option<RandomXCache>,
    dataset: Option<RandomXDataset>,
    flags: RandomXFlag,
    vms: ThreadLocal<RandomXVM>,
}

impl PoW {
    pub fn new(flags: RandomXFlag) -> Result<PoW, Error> {
        log::debug!("initializing RandomX");
        let cache = RandomXCache::new(flags, RANDOMX_CACHE_KEY)?;
        let (cache, dataset) = if flags.contains(RandomXFlag::FLAG_FULL_MEM) {
            (None, Some(RandomXDataset::new(flags, cache, 0)?))
        } else {
            (Some(cache), None)
        };
        log::debug!("RandomX initialized");

        Ok(Self {
            cache,
            dataset,
            flags,
            vms: ThreadLocal::new(),
        })
    }

    fn get_vm(&self) -> Result<&RandomXVM, RandomXError> {
        self.vms
            .get_or_try(|| RandomXVM::new(self.flags, self.cache.clone(), self.dataset.clone()))
    }
}

impl Prover for PoW {
    fn prove(
        &self,
        nonce_group: u8,
        challenge: &[u8; 8],
        difficulty: &[u8; 32],
        miner_id: &[u8; 32],
    ) -> Result<u64, Error> {
        let pow_input = [
            [0u8; 7].as_slice(),
            [nonce_group].as_slice(),
            challenge,
            miner_id,
        ]
        .concat();

        let iterations = AtomicUsize::new(0);
        let (pow_nonce, _) = (0..2u64.pow(56))
            .into_par_iter()
            .map_init(
                || -> Result<_, Error> { Ok((self.get_vm()?, pow_input.clone())) },
                |state, pow_nonce| {
                    if let Ok((vm, pow_input)) = state {
                        pow_input[0..7].copy_from_slice(&pow_nonce.to_le_bytes()[0..7]);
                        let hash = vm.calculate_hash(pow_input.as_slice()).ok()?;
                        iterations.fetch_add(1, Ordering::Relaxed); // Increment the iteration counter atomically
                        Some((pow_nonce, hash))
                    } else {
                        None
                    }
                },
            )
            .filter_map(|res| res)
            .find_any(|(_, hash)| hash.as_slice() < difficulty.as_slice())
            .ok_or(Error::PoWNotFound)?;

        let total_iterations = iterations.load(Ordering::Relaxed);
        log::debug!("Took {total_iterations:?} PoW iterations to find a valid nonce");

        Ok(pow_nonce)
    }

    fn par(&self) -> bool {
        false
    }
}

impl PowVerifier for PoW {
    fn verify(
        &self,
        pow: u64,
        nonce_group: u8,
        challenge: &[u8; 8],
        difficulty: &[u8; 32],
        miner_id: &[u8; 32],
    ) -> Result<(), Error> {
        let pow_input = [
            &pow.to_le_bytes()[0..7],
            [nonce_group].as_slice(),
            challenge,
            miner_id,
        ]
        .concat();

        let vm = self.get_vm()?;
        let hash = vm.calculate_hash(pow_input.as_slice())?;

        if hash.as_slice() >= difficulty.as_slice() {
            return Err(Error::InvalidPoW);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use crate::pow::PowVerifier;

    use super::*;

    #[test]
    fn test_pow() {
        let nonce = 7;
        let challenge = b"hello!!!";
        let difficulty = &[
            0x0f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0xff, 0xff, 0xff, 0xff,
        ];
        let prover = PoW::new(RandomXFlag::get_recommended_flags()).unwrap();
        let pow = prover
            .prove(nonce, challenge, difficulty, &[6; 32])
            .unwrap();
        prover
            .verify(pow, nonce, challenge, difficulty, &[6; 32])
            .unwrap();
    }

    #[test]
    fn test_pow_miner_id_matters() {
        let nonce = 7;
        let challenge = b"hello!!!";
        let difficulty = &[
            0x0f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0xff, 0xff, 0xff, 0xff,
        ];
        let prover = PoW::new(RandomXFlag::get_recommended_flags()).unwrap();

        let pool = rayon::ThreadPoolBuilder::new()
            .num_threads(1)
            .build()
            .unwrap();
        let pow = pool
            .install(|| prover.prove(nonce, challenge, difficulty, &[1; 32]))
            .unwrap();
        prover
            .verify(pow, nonce, challenge, difficulty, &[2; 32])
            .unwrap_err();
    }

    #[test]
    fn reject_invalid_pow() {
        let prover = PoW::new(RandomXFlag::get_recommended_flags()).unwrap();
        // difficulty 0 is impossible to be met
        assert!(prover
            .verify(0, 0, b"challeng", &[0; 32], &[6; 32])
            .is_err());
    }

    #[test]
    fn different_cache_key_gives_different_hash() {
        let input = b"hello world";
        let flags = RandomXFlag::get_recommended_flags();

        let cache = RandomXCache::new(flags, b"key0").unwrap();
        let vm = RandomXVM::new(flags, Some(cache), None).unwrap();
        let hash_0 = vm.calculate_hash(input).unwrap();

        let cache = RandomXCache::new(flags, b"key1").unwrap();
        let vm = RandomXVM::new(flags, Some(cache), None).unwrap();
        let hash_1 = vm.calculate_hash(input).unwrap();

        assert_ne!(hash_0, hash_1);
    }

    #[test]
    fn get_recommended_flags() {
        dbg!(RandomXFlag::get_recommended_flags());
    }
}
