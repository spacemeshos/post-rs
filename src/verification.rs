//! # Proof verification
//!
//! ## Steps to verify a proof:
//!
//! 1. verify k2_pow
//! 2. verify k3_pow
//! 3. verify number of indices == K2
//! 4. select K3 indices
//! 5. verify each of K3 selected indices satisfy difficulty (inferred from K1)
//!
//! ## Selecting subset of K3 proven indices
//!
//! ```text
//! seed = concat(ch, nonce, all_indices, k2pow, k3pow)
//! random_bytes = blake3(seed) // infinite blake output
//! for (j:=0; j<K3; j++)
//!   max_allowed = u16::MAX - (u16::MAX % (K2 - j))
//!   do {
//!     rand_num = random_bytes.read_u16_le()
//!   } while rand_num > max_allowed;
//!
//!   index = rand_num % (K2 - j)
//!   if validate_label(all_indices[index]) is INVALID
//!     return INVALID
//!   all_indices[index] = all_indices[k2-j-1]
//! return true
//! ```
//!
//! ## Verifying K3 indexes
//!
//! We must check if every index satisfies the difficulty condition.
//! To do so, we must repeat similar work as proving. Steps:
//! 1. Initialize AES cipher for proof's nonce.
//! 2. For each index:
//!     - replicate the label it points to,
//!     - encrypt it with AES,
//!     - convert AES output to u64,
//!     - compare it with difficulty.
use cipher::BlockEncrypt;
use itertools::Itertools;
use rayon::prelude::{ParallelBridge, ParallelIterator};
use scrypt_jane::scrypt::{self, ScryptParams};

use crate::{
    cipher::AesCipher,
    compression::{decompress_indexes, required_bits},
    difficulty::proving_difficulty,
    initialize::calc_commitment,
    metadata::ProofMetadata,
    pow::{hash_k2_pow, hash_k3_pow},
    prove::Proof,
    random_values_gen::FisherYatesShuffle,
};

#[inline]
fn generate_label(commitment: &[u8; 32], params: ScryptParams, index: u64) -> [u8; 16] {
    let mut data = [0u8; 72];
    data[0..32].copy_from_slice(commitment);
    data[32..40].copy_from_slice(&index.to_le_bytes());

    let mut label = [0u8; 16];
    scrypt::scrypt(&data, &[], params, &mut label);
    label
}

#[derive(Debug, Clone, Copy)]
pub struct VerifyingParams {
    pub difficulty: u64,
    pub k2: u32,
    pub k3: u32,
    pub k2_pow_difficulty: u64,
    pub k3_pow_difficulty: u64,
    pub pow_scrypt: ScryptParams,
    pub scrypt: ScryptParams,
}

impl VerifyingParams {
    pub fn new(num_labels: u64, cfg: crate::config::Config) -> eyre::Result<Self> {
        Ok(Self {
            difficulty: proving_difficulty(num_labels, cfg.k1)?,
            k2: cfg.k2,
            k3: cfg.k3,
            k2_pow_difficulty: cfg.k2_pow_difficulty,
            k3_pow_difficulty: cfg.k3_pow_difficulty,
            pow_scrypt: cfg.pow_scrypt,
            scrypt: cfg.scrypt,
        })
    }
}

/// Verify if a proof is valid.
///
/// Arguments:
///
/// * `proof`: The proof that to verify
/// * `metadata`: ProofMetadata
/// * `params`: VerifyingParams
/// * `threads`: The number of threads to use for verification.
pub fn verify(
    proof: &Proof,
    metadata: &ProofMetadata,
    params: VerifyingParams,
    threads: usize,
) -> Result<(), String> {
    let challenge = metadata.challenge;

    // Verify K2 PoW
    let nonce_group = proof.nonce / 2;
    let k2_pow_value = hash_k2_pow(&challenge, nonce_group, params.pow_scrypt, proof.k2_pow);
    if k2_pow_value >= params.k2_pow_difficulty {
        return Err(format!(
            "k2 pow is invalid: {k2_pow_value} >= {}",
            params.k2_pow_difficulty
        ));
    }

    // Verify K3 PoW
    let k3_pow_value = hash_k3_pow(
        &challenge,
        proof.nonce,
        &proof.indices,
        params.pow_scrypt,
        proof.k2_pow,
        proof.k3_pow,
    );
    if k3_pow_value >= params.k3_pow_difficulty {
        return Err(format!(
            "k3 pow is invalid: {k3_pow_value} >= {}",
            params.k3_pow_difficulty
        ));
    }

    // Verify the number of indices against K2
    let num_lables = metadata.num_units as u64 * metadata.labels_per_unit;
    let bits_per_index = required_bits(num_lables);
    let expected_indices_len = expected_indices_bytes(required_bits(num_lables), params.k2);
    if proof.indices.len() != expected_indices_len {
        return Err(format!(
            "indices length is invalid ({} != {expected_indices_len})",
            proof.indices.len()
        ));
    }

    let indices_unpacked = decompress_indexes(&proof.indices, bits_per_index).collect_vec();
    let commitment = calc_commitment(&metadata.node_id, &metadata.commitment_atx_id);
    let nonce_group = proof.nonce / 2;
    let cipher = AesCipher::new_with_k2pow(&challenge, nonce_group, proof.k2_pow);
    let output_index = (proof.nonce % 2) as usize;

    // Select K3 indices
    let seed = &[
        challenge.as_slice(),
        &proof.nonce.to_le_bytes(),
        proof.indices.as_slice(),
        &proof.k2_pow.to_le_bytes(),
        &proof.k3_pow.to_le_bytes(),
    ];

    let k3_indices = FisherYatesShuffle::new(indices_unpacked, seed).take(params.k3 as usize);

    let pool = rayon::ThreadPoolBuilder::new()
        .num_threads(threads)
        .build()
        .unwrap();

    pool.install(|| {
        k3_indices.par_bridge().try_for_each(|index| {
            let mut u64s = [0u64; 2];
            let label = generate_label(&commitment, params.scrypt, index);
            cipher.aes.encrypt_block_b2b(
                &label.into(),
                bytemuck::cast_slice_mut::<u64, u8>(&mut u64s).into(),
            );

            let value = u64s[output_index].to_le();
            if value > params.difficulty {
                return Err(format!(
                    "value for index: {index} doesn't satisfy difficulty: {value} > {} (label: {label:?})",
                    params.difficulty
                ));
            }
            Ok(())
        })
    })
}

fn next_multiple_of(n: usize, mult: usize) -> usize {
    let r = n % mult;
    if r == 0 {
        n
    } else {
        n + (mult - r)
    }
}

/// Calculate the expected length of compressed indices.
fn expected_indices_bytes(required_bits: usize, k2: u32) -> usize {
    let total_bits = required_bits * k2 as usize;
    next_multiple_of(total_bits, 8) / 8
}

#[cfg(test)]
mod tests {
    use scrypt_jane::scrypt::ScryptParams;

    use crate::{
        metadata::ProofMetadata,
        pow::{find_k2_pow, find_k3_pow},
        prove::Proof,
    };

    use super::{expected_indices_bytes, next_multiple_of, verify, VerifyingParams};

    #[test]
    fn test_next_mutliple_of() {
        assert_eq!(0, next_multiple_of(0, 8));
        assert_eq!(8, next_multiple_of(3, 8));
    }

    #[test]
    fn test_expected_indices_len() {
        assert_eq!(1, expected_indices_bytes(1, 8));
        assert_eq!(4, expected_indices_bytes(3, 10));
        assert_eq!(10, expected_indices_bytes(8, 10));
    }

    #[test]
    fn reject_empty_proof() {
        let challenge = [0u8; 32];
        let scrypt_params = ScryptParams::new(1, 0, 0);
        let params = VerifyingParams {
            difficulty: u64::MAX,
            k2: 10,
            k3: 10,
            k2_pow_difficulty: u64::MAX / 16,
            k3_pow_difficulty: u64::MAX / 16,
            pow_scrypt: scrypt_params,
            scrypt: scrypt_params,
        };

        let k2_pow = find_k2_pow(&challenge, 0, params.scrypt, params.k2_pow_difficulty);
        let k3_pow = find_k3_pow(
            &challenge,
            0,
            &[],
            params.scrypt,
            params.k3_pow_difficulty,
            k2_pow,
        );
        let fake_proof = Proof {
            nonce: 0,
            indices: vec![],
            k2_pow,
            k3_pow,
        };
        let fake_metadata = ProofMetadata {
            node_id: [0u8; 32],
            commitment_atx_id: [0u8; 32],
            challenge,
            num_units: 10,
            labels_per_unit: 2048,
        };

        assert!(verify(&fake_proof, &fake_metadata, params, 1).is_err());
    }
}
