//! Scrypt-based proof of work
//! Deprecated - replaced by RandomX PoW,
//! verification is kept for backwards compatibility on existing testnet.
//! To be removed before the genesis.
use scrypt_jane::scrypt::{scrypt, ScryptParams};

use super::Error;

pub(crate) fn verify(
    pow: u64,
    nonce: u32,
    challenge: &[u8; 32],
    params: ScryptParams,
    difficulty: u64,
) -> Result<(), Error> {
    if hash_k2_pow(challenge, nonce, params, pow) >= difficulty {
        Err(Error::InvalidPoW)
    } else {
        Ok(())
    }
}

#[inline(always)]
fn hash_k2_pow(challenge: &[u8; 32], nonce: u32, params: ScryptParams, k2_pow: u64) -> u64 {
    // Note: the call in loop is inlined and the concat is optimized as loop-invariant.
    let input = [challenge.as_slice(), &nonce.to_le_bytes()].concat();
    let mut output = [0u8; 8];

    scrypt(&input, &k2_pow.to_le_bytes(), params, &mut output);
    u64::from_le_bytes(output)
}

#[cfg(test)]
pub fn find_k2_pow(
    challenge: &[u8; 32],
    nonce_group: u32,
    params: ScryptParams,
    difficulty: u64,
) -> Result<u64, Error> {
    use rayon::prelude::{IntoParallelIterator, ParallelIterator};

    (0u64..u64::MAX)
        .into_par_iter()
        .find_any(|&k2_pow| hash_k2_pow(challenge, nonce_group, params, k2_pow) < difficulty)
        .ok_or(Error::PoWNotFound)
}

#[cfg(test)]
mod tests {
    use super::*;

    use proptest::prelude::*;
    proptest! {
        #[test]
        fn test_k2_pow(nonce: u32) {
            let difficulty = 0x7FFF_FFFF_FFFF_FFFF;
            let k2_pow = find_k2_pow(&[0; 32], nonce, ScryptParams::new(2,0,0), difficulty).expect("should find a solution");
            assert!(hash_k2_pow(&[0; 32], nonce, ScryptParams::new(2,0,0), k2_pow) < difficulty);
            verify(k2_pow, nonce, &[0; 32], ScryptParams::new(2,0,0), difficulty).unwrap();
        }
    }
}
