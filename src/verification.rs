//! # Proof verification
//!
//! ## Steps to verify a proof:
//!
//! 1. verify k2_pow
//! 2. verify number of indices == K2
//! 3. select K3 indices
//! 4. verify each of K3 selected indices satisfy difficulty (inferred from K1)
//!
//! ## Selecting subset of K3 proven indices
//!
//! ```text
//! seed = concat(ch, nonce, indices, k2pow)
//! random_bytes = blake3(seed) // infinite blake output
//! for (index=0; index<K3; index++) {
//!   remaining = K2 - index
//!   max_allowed = u16::MAX - (u16::MAX % remaining)
//!   do {
//!     rand_num = random_bytes.read_u16_le()
//!   } while rand_num >= max_allowed;
//!
//!   to_swap = (rand_num % remaining) + index
//!   indices.swap(index, to_swap)
//! }
//! ```
//! indices[0..K3] now contains randomly picked values
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
use std::cmp::Ordering;

use cipher::BlockEncrypt;
use itertools::Itertools;
use scrypt_jane::scrypt::ScryptParams;

use crate::{
    cipher::AesCipher,
    compression::{decompress_indexes, required_bits},
    config::Config,
    difficulty::proving_difficulty,
    initialize::{calc_commitment, generate_label},
    metadata::ProofMetadata,
    pow::hash_k2_pow,
    prove::{Proof, Prover8_56},
    random_values_gen::RandomValuesIterator,
};

const NONCES_PER_AES: u32 = Prover8_56::NONCES_PER_AES;

#[derive(Debug, Clone, Copy)]
pub struct VerifyingParams {
    pub difficulty: u64,
    pub k2: u32,
    pub k3: u32,
    pub k2_pow_difficulty: u64,
    pub pow_scrypt: ScryptParams,
    pub scrypt: ScryptParams,
}

impl VerifyingParams {
    pub fn new(metadata: &ProofMetadata, cfg: &Config) -> eyre::Result<Self> {
        let num_labels = metadata.num_units as u64 * metadata.labels_per_unit;
        Ok(Self {
            difficulty: proving_difficulty(cfg.k1, num_labels)?,
            k2: cfg.k2,
            k3: cfg.k3,
            k2_pow_difficulty: cfg.k2_pow_difficulty / metadata.num_units as u64,
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
) -> Result<(), String> {
    let challenge = metadata.challenge;

    // Verify K2 PoW
    let nonce_group = proof.nonce / NONCES_PER_AES;
    let k2_pow_value = hash_k2_pow(&challenge, nonce_group, params.pow_scrypt, proof.k2_pow);
    if k2_pow_value >= params.k2_pow_difficulty {
        return Err(format!(
            "k2 pow is invalid: {k2_pow_value} >= {}",
            params.k2_pow_difficulty
        ));
    }

    // Verify the number of indices against K2
    let num_lables = metadata.num_units as u64 * metadata.labels_per_unit;
    let bits_per_index = required_bits(num_lables);
    let expected_indices_len = expected_indices_bytes(bits_per_index, params.k2);
    if proof.indices.len() != expected_indices_len {
        return Err(format!(
            "indices length is invalid ({} != {expected_indices_len})",
            proof.indices.len()
        ));
    }

    let indices_unpacked = decompress_indexes(&proof.indices, bits_per_index)
        .take(params.k2 as usize)
        .collect_vec();
    let commitment = calc_commitment(&metadata.node_id, &metadata.commitment_atx_id);
    let nonce_group = proof.nonce / NONCES_PER_AES;
    let cipher = AesCipher::new_with_k2pow(&challenge, nonce_group, proof.k2_pow);
    let lazy_cipher = AesCipher::new_lazy(&challenge, proof.nonce, nonce_group, proof.k2_pow);
    let (difficulty_msb, difficulty_lsb) = Prover8_56::split_difficulty(params.difficulty);

    let output_index = (proof.nonce % NONCES_PER_AES) as usize;

    // Select K3 indices
    let seed = &[
        challenge.as_slice(),
        &proof.nonce.to_le_bytes(),
        proof.indices.as_slice(),
        &proof.k2_pow.to_le_bytes(),
    ];

    let k3_indices = RandomValuesIterator::new(indices_unpacked, seed).take(params.k3 as usize);

    k3_indices.into_iter().try_for_each(|index| {
        let mut output = [0u8; 16];
        let label = generate_label(&commitment, params.scrypt, index);
        cipher.aes.encrypt_block_b2b(
            &label.into(),
            (&mut output).into(),
        );

        let msb = output[output_index];
        match msb.cmp(&difficulty_msb) {
            Ordering::Less => {
                // valid
            },
            Ordering::Greater => {
                // invalid
                return Err(format!(
                    "MSB value for index: {index} doesn't satisfy difficulty: {msb} > {difficulty_msb} (label: {label:?})",
                ));
            },
            Ordering::Equal => {
                // Need to check LSB
                let mut output = [0u64; 2];
                lazy_cipher.aes.encrypt_block_b2b(
                    &label.into(),
                    bytemuck::cast_slice_mut(&mut output).into(),
                );
                let lsb = output[0].to_le() & 0x00ff_ffff_ffff_ffff;
                if lsb >= difficulty_lsb {
                    return Err(format!(
                        "LSB value for index: {index} doesn't satisfy difficulty: {lsb} >= {difficulty_lsb} (label: {label:?})",
                    ));
                }
            }
        }
        Ok(())
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

    use crate::{metadata::ProofMetadata, pow::find_k2_pow, prove::Proof};

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
    fn reject_invalid_proof() {
        let challenge = [0u8; 32];
        let scrypt_params = ScryptParams::new(1, 0, 0);
        let params = VerifyingParams {
            difficulty: u64::MAX,
            k2: 10,
            k3: 10,
            k2_pow_difficulty: u64::MAX / 16,
            pow_scrypt: scrypt_params,
            scrypt: scrypt_params,
        };

        let k2_pow = find_k2_pow(&challenge, 0, params.scrypt, params.k2_pow_difficulty);
        let fake_metadata = ProofMetadata {
            node_id: [0u8; 32],
            commitment_atx_id: [0u8; 32],
            challenge,
            num_units: 10,
            labels_per_unit: 2048,
        };
        {
            let empty_proof = Proof {
                nonce: 0,
                indices: vec![],
                k2_pow,
            };
            assert!(verify(&empty_proof, &fake_metadata, params).is_err());
        }
        {
            let proof_with_not_enough_indices = Proof {
                nonce: 0,
                indices: vec![1, 2, 3],
                k2_pow,
            };
            assert!(verify(&proof_with_not_enough_indices, &fake_metadata, params).is_err());
        }
        {
            let proof_with_invalid_k2_pow = Proof {
                nonce: 0,
                indices: vec![1, 2, 3],
                k2_pow: params.k2_pow_difficulty,
            };
            assert!(verify(&proof_with_invalid_k2_pow, &fake_metadata, params).is_err());
        }
        {
            let proof_with_invalid_k3_pow = Proof {
                nonce: 0,
                indices: vec![1, 2, 3],
                k2_pow,
            };
            assert!(verify(&proof_with_invalid_k3_pow, &fake_metadata, params).is_err());
        }
    }
}
