//! Proof of Work algorithm
//!
//! The PoW is required to prevent grinding on nonces
//! when looking for a proof. Without it a malicious actor
//! with a powerful enough computer could try many nonces
//! at the same time. In effect a proof could be found
//! without actually holding the whole POST data.

pub use randomx_rs::RandomXFlag;
use randomx_rs::{RandomXCache, RandomXDataset, RandomXError, RandomXVM};
use rayon::prelude::{IntoParallelIterator, ParallelIterator};
use thiserror::Error;

const RANDOMX_CACHE_KEY: &[u8] = b"spacemesh-randomx-cache-key";

pub struct PowProver {
    cache: Option<randomx_rs::RandomXCache>,
    dataset: Option<randomx_rs::RandomXDataset>,
    flags: RandomXFlag,
}

impl PowProver {
    pub fn new(flags: RandomXFlag) -> Result<PowProver, Error> {
        let cache = RandomXCache::new(flags, RANDOMX_CACHE_KEY)?;
        let (cache, dataset) = if flags.contains(RandomXFlag::FLAG_FULL_MEM) {
            (None, Some(RandomXDataset::new(flags, cache, 0)?))
        } else {
            (Some(cache), None)
        };

        Ok(Self {
            cache,
            dataset,
            flags,
        })
    }

    fn new_vm(&self) -> Result<RandomXVM, RandomXError> {
        RandomXVM::new(self.flags, self.cache.clone(), self.dataset.clone())
    }

    pub fn prove(
        &self,
        nonce_group: u8,
        challenge: &[u8; 8],
        difficulty: &[u8; 32],
    ) -> Result<u64, Error> {
        let pow_input = [[0u8; 7].as_slice(), [nonce_group].as_slice(), challenge].concat();

        let (pow_nonce, _) = (0..2u64.pow(56))
            .into_par_iter()
            .map_init(
                || -> Result<_, Error> { Ok((self.new_vm()?, pow_input.clone())) },
                |state, pow_nonce| {
                    if let Ok((vm, pow_input)) = state {
                        pow_input[0..7].copy_from_slice(&pow_nonce.to_le_bytes()[0..7]);
                        let hash = vm.calculate_hash(pow_input.as_slice()).ok()?;
                        Some((pow_nonce, hash))
                    } else {
                        None
                    }
                },
            )
            .filter_map(|res| res)
            .find_any(|(_, hash)| hash.as_slice() < difficulty)
            .ok_or(Error::PoWNotFound)?;

        Ok(pow_nonce)
    }

    pub fn verify(
        &self,
        pow: u64,
        nonce_group: u8,
        challenge: &[u8; 8],
        difficulty: &[u8; 32],
    ) -> Result<(), Error> {
        let pow_input = [
            &pow.to_le_bytes()[0..7],
            [nonce_group].as_slice(),
            challenge,
        ]
        .concat();
        let vm = self.new_vm()?;
        let hash = vm.calculate_hash(pow_input.as_slice())?;

        if hash.as_slice() >= difficulty {
            return Err(Error::InvalidPoW {
                hash: hash.try_into().unwrap(),
                difficulty: *difficulty,
            });
        }
        Ok(())
    }
}

#[derive(Error, Debug)]
pub enum Error {
    #[error("Proof of work is invalid: {hash:?} >= {difficulty:?}")]
    InvalidPoW {
        hash: [u8; 32],
        difficulty: [u8; 32],
    },
    #[error("Fail in RandomX: {0}")]
    RandomXError(#[from] randomx_rs::RandomXError),
    #[error("Proof of work not found")]
    PoWNotFound,
}

#[cfg(test)]
mod tests {
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
        let prover = PowProver::new(RandomXFlag::get_recommended_flags()).unwrap();
        let pow = prover.prove(nonce, challenge, difficulty).unwrap();
        prover.verify(pow, nonce, challenge, difficulty).unwrap();
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
