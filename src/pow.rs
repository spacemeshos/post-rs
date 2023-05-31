//! Proof of Work algorithm
//!
//! The PoW is required to prevent grinding on nonces
//! when looking for a proof. Without it a malicious actor
//! with a powerful enough computer could try many nonces
//! at the same time. In effect a proof could be found
//! without actually holding the whole POST data.

pub use randomx_rs::RandomXFlag;
use randomx_rs::{RandomXCache, RandomXDataset, RandomXVM};
use rayon::prelude::{IntoParallelIterator, ParallelIterator};
use thiserror::Error;

const RANDOMX_CACHE_KEY: &[u8] = b"spacemesh-randomx-cache-key";

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

fn create_vm(flags: RandomXFlag) -> Result<RandomXVM, Error> {
    let cache = RandomXCache::new(flags, RANDOMX_CACHE_KEY)?;
    let (cache, dataset) = if flags.contains(RandomXFlag::FLAG_FULL_MEM) {
        (None, Some(RandomXDataset::new(flags, cache, 0)?))
    } else {
        (Some(cache), None)
    };
    RandomXVM::new(flags, cache, dataset).map_err(Error::from)
}

pub fn verify_pow(
    pow_nonce: u64,
    challenge: &[u8; 8],
    nonce_group: u8,
    difficulty: &[u8; 32],
    flags: RandomXFlag,
) -> Result<(), Error> {
    let vm = create_vm(flags)?;
    verify_pow_with_vm(pow_nonce, challenge, nonce_group, difficulty, &vm)
}

/// Verify proof of work with a pre-initialized VM.
pub fn verify_pow_with_vm(
    pow_nonce: u64,
    challenge: &[u8; 8],
    nonce_group: u8,
    difficulty: &[u8; 32],
    vm: &RandomXVM,
) -> Result<(), Error> {
    let pow_input = [
        &pow_nonce.to_le_bytes()[0..7],
        [nonce_group].as_slice(),
        challenge,
    ]
    .concat();

    let hash = vm.calculate_hash(pow_input.as_slice())?;

    if hash.as_slice() >= difficulty {
        return Err(Error::InvalidPoW {
            hash: hash.try_into().unwrap(),
            difficulty: *difficulty,
        });
    }
    Ok(())
}

pub fn find_pow(
    challenge: &[u8; 8],
    nonce_group: u8,
    difficulty: &[u8; 32],
    flags: RandomXFlag,
) -> Result<u64, Error> {
    let pow_input = [[0u8; 7].as_slice(), [nonce_group].as_slice(), challenge].concat();

    let cache = RandomXCache::new(flags, RANDOMX_CACHE_KEY)?;
    let (cache, dataset) = if flags.contains(RandomXFlag::FLAG_FULL_MEM) {
        (None, Some(RandomXDataset::new(flags, cache, 0)?))
    } else {
        (Some(cache), None)
    };

    let (pow_nonce, _) = (0..2u64.pow(56))
        .into_par_iter()
        .map_init(
            || -> Result<_, Error> {
                let vm = RandomXVM::new(flags, cache.clone(), dataset.clone())?;
                Ok((vm, pow_input.clone()))
            },
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

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;
    proptest! {
        #[test]
        fn test_pow(nonce: u8, challenge: [u8; 8]) {
                let difficulty = &[
                    0x0f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                    0xff, 0xff, 0xff, 0xff,
                ];
                let pow = find_pow(&challenge, nonce, difficulty, RandomXFlag::get_recommended_flags()).unwrap();
                verify_pow(pow, &challenge, nonce, difficulty, RandomXFlag::get_recommended_flags()).unwrap();
            }
    }

    #[test]
    fn randomx_hash_fast_vs_light() {
        let input = b"hello world";

        let flags = RandomXFlag::get_recommended_flags() | RandomXFlag::FLAG_FULL_MEM;
        let cache = RandomXCache::new(flags, RANDOMX_CACHE_KEY).unwrap();
        let dataset = RandomXDataset::new(flags, cache, 0).unwrap();
        let fast_vm = RandomXVM::new(flags, None, Some(dataset)).unwrap();

        let flags = RandomXFlag::get_recommended_flags();
        let cache = RandomXCache::new(flags, RANDOMX_CACHE_KEY).unwrap();
        let light_vm = RandomXVM::new(flags, Some(cache), None).unwrap();

        let fast = fast_vm.calculate_hash(input).unwrap();
        let light = light_vm.calculate_hash(input).unwrap();
        assert_eq!(fast, light);
    }

    #[test]
    fn get_recommended_flags() {
        dbg!(RandomXFlag::get_recommended_flags());
    }
}
