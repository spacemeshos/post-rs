use cipher::BlockEncrypt;
use rayon::prelude::{ParallelBridge, ParallelIterator};
use scrypt_jane::scrypt::{self, ScryptParams};

use crate::{
    cipher::AesCipher,
    compression::{decompress_indexes, required_bits},
    initialize::calc_commitment,
    metadata::ProofMetadata,
    pow::{hash_k2_pow, hash_k3_pow},
    Proof,
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
    pub k2_pow_difficulty: u64,
    pub k3_pow_difficulty: u64,
    pub scrypt: ScryptParams,
}

/// Verify if a proof is valid.
///
/// Arguments:
///
/// * `proof`: The proof that we're verifying.
/// * `metadata`: ProofMetadata
/// * `params`: VerifyingParams
/// * `threads`: The number of threads to use for verification.
///
/// Returns:
///
/// A boolean value.
pub fn verify(
    proof: &Proof,
    metadata: &ProofMetadata,
    params: VerifyingParams,
    threads: usize,
) -> Result<(), String> {
    let challenge = metadata.challenge;

    // Verify K2 PoW
    let nonce_group = proof.nonce / 2;
    let k2_pow_value = hash_k2_pow(&challenge, nonce_group, params.scrypt, proof.k2_pow);
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
        params.scrypt,
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

    let indexes = decompress_indexes(&proof.indices, bits_per_index);
    let commitment = calc_commitment(&metadata.node_id, &metadata.commitment_atx_id);

    let nonce_group = proof.nonce / 2;
    let cipher = AesCipher::new_with_k2pow(&challenge, nonce_group, proof.k2_pow);
    let output_index = (proof.nonce % 2) as usize;

    let pool = rayon::ThreadPoolBuilder::new()
        .num_threads(threads)
        .build()
        .unwrap();

    pool.install(|| {
        indexes.par_bridge().try_for_each(|index| {
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
        verification::{expected_indices_bytes, next_multiple_of, verify},
        Proof,
    };

    use super::VerifyingParams;

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
            k2_pow_difficulty: u64::MAX / 16,
            k3_pow_difficulty: u64::MAX / 16,
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
