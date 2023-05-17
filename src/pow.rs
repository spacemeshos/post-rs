//! Proof of Work algorithms
//!
//! PoW for K2 is required to prevent grinding on nonces
//! when looking for a proof. Without it a malicious actor
//! with a powerful enough computer could try many nonces
//! at the same time. In effect a proof could be found
//! without actually holding the whole POST data.
use rayon::prelude::*;
use scrypt_jane::scrypt::{scrypt, ScryptParams};

pub fn find_k2_pow(challenge: &[u8; 32], nonce: u32, params: ScryptParams, difficulty: u64) -> u64 {
    (0u64..u64::MAX)
        .into_par_iter()
        .find_first(|&k2_pow| hash_k2_pow(challenge, nonce, params, k2_pow) < difficulty)
        .expect("looking for k2pow")
}

#[inline(always)]
pub(crate) fn hash_k2_pow(
    challenge: &[u8; 32],
    nonce: u32,
    params: ScryptParams,
    k2_pow: u64,
) -> u64 {
    // Note: the call in loop is inlined and the concat is optimized as loop-invariant.
    let input = [challenge.as_slice(), &nonce.to_le_bytes()].concat();
    let mut output = [0u8; 8];

    scrypt(&input, &k2_pow.to_le_bytes(), params, &mut output);
    u64::from_le_bytes(output)
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;
    proptest! {
        #[test]
        fn test_k2_pow(nonce: u32) {
            let difficulty = 0x7FFF_FFFF_FFFF_FFFF;
            let k2_pow = find_k2_pow(&[0; 32], nonce, ScryptParams::new(2,0,0), difficulty);
            assert!(hash_k2_pow(&[0; 32], nonce, ScryptParams::new(2,0,0), k2_pow) < difficulty);
        }
    }
}
