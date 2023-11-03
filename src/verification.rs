//! # Proof verification
//!
//! ## Steps to verify a proof:
//!
//! 1. verify PoW
//! 2. verify number of indices == K2
//! 3. select K3 indices
//! 4. verify each of K3 selected indices satisfy difficulty (inferred from K1)
//!
//! ## Selecting subset of K3 proven indices
//!
//! ```text
//! seed = concat(ch, nonce, indices, pow)
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

use crate::{
    cipher::AesCipher,
    compression::{decompress_indexes, required_bits},
    config::{InitConfig, ProofConfig},
    difficulty::{proving_difficulty, scale_pow_difficulty},
    initialize::{calc_commitment, generate_label},
    metadata::ProofMetadata,
    pow::PowVerifier,
    prove::{Proof, Prover8_56},
    random_values_gen::RandomValuesIterator,
};

const NONCES_PER_AES: u32 = Prover8_56::NONCES_PER_AES;

pub struct Verifier {
    pow_verifier: Box<dyn PowVerifier + Send + Sync>,
}

#[derive(thiserror::Error, Debug)]
pub enum Error {
    #[error("nonce group (0) out of bounds (max 255)")]
    NonceGroupOutOfBounds(u32),
    #[error("invalid proof of work")]
    InvalidPoW(#[from] crate::pow::Error),
    #[error("invalid number of indices (expected: {expected}, got: {got})")]
    InvalidIndicesLen { expected: usize, got: usize },
    #[error("MSB value for index: {index} doesn't satisfy difficulty: {msb} > {difficulty_msb} (label: {label:?})")]
    InvalidMsb {
        index: u64,
        msb: u8,
        difficulty_msb: u8,
        label: [u8; 16],
    },
    #[error("LSB value for index: {index} doesn't satisfy difficulty: {lsb} >= {difficulty_lsb} (label: {label:?})")]
    InvalidLsb {
        index: u64,
        lsb: u64,
        difficulty_lsb: u64,
        label: [u8; 16],
    },
    #[error(transparent)]
    InvalidMetadata(#[from] MetadataValidationError),
    #[error("invalid number of labels: (0)")]
    InvalidNumLabels(String),
}

#[derive(thiserror::Error, Debug)]
pub enum MetadataValidationError {
    #[error("numunits too small: {got} < {min}")]
    NumUnitsTooSmall { min: u32, got: u32 },
    #[error("numunits too large: {got} < {max}")]
    NumUnitsTooLarge { max: u32, got: u32 },
    #[error("invalid labels_per_unit: {got} != {expected}")]
    LabelsPerUnitInvalid { expected: u64, got: u64 },
}

pub fn verify_metadata(
    metadata: &ProofMetadata,
    init_cfg: &InitConfig,
) -> Result<(), MetadataValidationError> {
    if metadata.num_units < init_cfg.min_num_units {
        return Err(MetadataValidationError::NumUnitsTooSmall {
            min: init_cfg.min_num_units,
            got: metadata.num_units,
        });
    }
    if metadata.num_units > init_cfg.max_num_units {
        return Err(MetadataValidationError::NumUnitsTooLarge {
            max: init_cfg.max_num_units,
            got: metadata.num_units,
        });
    }
    if metadata.labels_per_unit != init_cfg.labels_per_unit {
        return Err(MetadataValidationError::LabelsPerUnitInvalid {
            expected: init_cfg.labels_per_unit,
            got: metadata.labels_per_unit,
        });
    }
    Ok(())
}

impl Verifier {
    pub fn new(pow_verifier: Box<dyn PowVerifier + Send + Sync>) -> Self {
        Self { pow_verifier }
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
        &self,
        proof: &Proof,
        metadata: &ProofMetadata,
        cfg: &ProofConfig,
        init_cfg: &InitConfig,
    ) -> Result<(), Error> {
        verify_metadata(metadata, init_cfg)?;

        let challenge = metadata.challenge;
        let pow_difficulty = scale_pow_difficulty(&cfg.pow_difficulty, metadata.num_units);

        // Verify K2 PoW
        let nonce_group = proof.nonce / NONCES_PER_AES;
        self.pow_verifier.verify(
            proof.pow,
            nonce_group
                .try_into()
                .map_err(|_| Error::NonceGroupOutOfBounds(nonce_group))?,
            &challenge[..8].try_into().unwrap(),
            &pow_difficulty,
            &metadata.node_id,
        )?;

        // Verify the number of indices against K2
        let num_labels = metadata.num_units as u64 * init_cfg.labels_per_unit;
        let bits_per_index = required_bits(num_labels);
        let expected = expected_indices_bytes(bits_per_index, cfg.k2);
        if proof.indices.len() != expected {
            return Err(Error::InvalidIndicesLen {
                expected,
                got: proof.indices.len(),
            });
        }

        let indices_unpacked = decompress_indexes(&proof.indices, bits_per_index)
            .take(cfg.k2 as usize)
            .collect_vec();
        let commitment = calc_commitment(&metadata.node_id, &metadata.commitment_atx_id);
        let cipher = AesCipher::new(&challenge, nonce_group, proof.pow);
        let lazy_cipher = AesCipher::new_lazy(&challenge, proof.nonce, nonce_group, proof.pow);

        let difficulty = proving_difficulty(cfg.k1, num_labels).map_err(Error::InvalidNumLabels)?;
        let (difficulty_msb, difficulty_lsb) = Prover8_56::split_difficulty(difficulty);

        let output_index = (proof.nonce % NONCES_PER_AES) as usize;

        // Select K3 indices
        let seed = &[
            challenge.as_slice(),
            &proof.nonce.to_le_bytes(),
            proof.indices.as_ref(),
            &proof.pow.to_le_bytes(),
        ];

        let k3_indices = RandomValuesIterator::new(indices_unpacked, seed).take(cfg.k3 as usize);

        k3_indices.into_iter().try_for_each(|index| {
            let mut output = [0u8; 16];
            let label = generate_label(&commitment, init_cfg.scrypt, index);
            cipher
                .aes
                .encrypt_block_b2b(&label.into(), (&mut output).into());

            let msb = output[output_index];
            match msb.cmp(&difficulty_msb) {
                Ordering::Less => {
                    // valid
                }
                Ordering::Greater => {
                    return Err(Error::InvalidMsb {
                        index,
                        msb,
                        difficulty_msb,
                        label,
                    })
                }
                Ordering::Equal => {
                    // Need to check LSB
                    let mut output = [0u64; 2];
                    lazy_cipher.aes.encrypt_block_b2b(
                        &label.into(),
                        bytemuck::cast_slice_mut(&mut output).into(),
                    );
                    let lsb = output[0].to_le() & 0x00ff_ffff_ffff_ffff;
                    if lsb >= difficulty_lsb {
                        return Err(Error::InvalidLsb {
                            index,
                            lsb,
                            difficulty_lsb,
                            label,
                        });
                    }
                }
            }
            Ok(())
        })
    }
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
    use std::borrow::Cow;

    use crate::{
        config::{InitConfig, ProofConfig, ScryptParams},
        metadata::ProofMetadata,
        pow::MockPowVerifier,
        prove::Proof,
        verification::Error,
    };

    use super::{expected_indices_bytes, next_multiple_of, Verifier};

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
    fn reject_invalid_pow() {
        let cfg = ProofConfig {
            k1: 3,
            k2: 3,
            k3: 3,
            pow_difficulty: [0xFF; 32],
        };
        let init_cfg = InitConfig {
            min_num_units: 1,
            max_num_units: 10,
            labels_per_unit: 2048,
            scrypt: ScryptParams::new(2, 1, 1),
        };

        let fake_metadata = ProofMetadata {
            node_id: [0; 32],
            commitment_atx_id: [0; 32],
            challenge: [0; 32],
            num_units: 10,
            labels_per_unit: 2048,
        };
        let mut pow_verifier = Box::new(MockPowVerifier::new());
        pow_verifier
            .expect_verify()
            .returning(|_, _, _, _, _| Err(crate::pow::Error::InvalidPoW));
        let verifier = Verifier::new(pow_verifier);
        let result = verifier.verify(
            &Proof {
                nonce: 0,
                indices: Cow::from(vec![1, 2, 3]),
                pow: 0,
            },
            &fake_metadata,
            &cfg,
            &init_cfg,
        );
        assert!(matches!(result, Err(Error::InvalidPoW(_))));
    }

    #[test]
    fn reject_invalid_proof() {
        let pcfg = ProofConfig {
            k1: 10,
            k2: 10,
            k3: 10,
            pow_difficulty: [0xFF; 32],
        };
        let icfg = InitConfig {
            min_num_units: 1,
            max_num_units: 10,
            labels_per_unit: 2048,
            scrypt: ScryptParams::new(4, 1, 1),
        };

        let fake_metadata = ProofMetadata {
            node_id: [0u8; 32],
            commitment_atx_id: [0u8; 32],
            challenge: [0u8; 32],
            num_units: 10,
            labels_per_unit: 2048,
        };
        let mut pow_verifier = Box::new(MockPowVerifier::new());
        pow_verifier
            .expect_verify()
            .returning(|_, _, _, _, _| Ok(()));
        let verifier = Verifier::new(pow_verifier);
        {
            let empty_proof = Proof {
                nonce: 0,
                indices: Cow::from(vec![]),
                pow: 0,
            };
            let result = verifier.verify(&empty_proof, &fake_metadata, &pcfg, &icfg);
            assert!(matches!(
                result,
                Err(Error::InvalidIndicesLen {
                    expected: _,
                    got: 0
                })
            ));
        }
        {
            let nonce_out_of_bounds_proof = Proof {
                nonce: 256 * 16,
                indices: Cow::from(vec![]),
                pow: 0,
            };
            let res = verifier.verify(&nonce_out_of_bounds_proof, &fake_metadata, &pcfg, &icfg);
            assert!(matches!(res, Err(Error::NonceGroupOutOfBounds(256))));
        }
        {
            let proof_with_not_enough_indices = Proof {
                nonce: 0,
                indices: Cow::from(vec![1, 2, 3]),
                pow: 0,
            };
            let result =
                verifier.verify(&proof_with_not_enough_indices, &fake_metadata, &pcfg, &icfg);
            assert!(matches!(
                result,
                Err(Error::InvalidIndicesLen {
                    expected: _,
                    got: 3
                })
            ));
        }
    }

    #[test]
    fn verify_metadata() {
        let valid_meta = ProofMetadata {
            node_id: [0; 32],
            commitment_atx_id: [0; 32],
            challenge: [0; 32],
            num_units: 1,
            labels_per_unit: 100,
        };
        let init_cfg = InitConfig {
            min_num_units: 1,
            max_num_units: 10,
            labels_per_unit: 100,
            scrypt: ScryptParams::new(2, 1, 1),
        };
        assert!(super::verify_metadata(&valid_meta, &init_cfg).is_ok());
        {
            let num_units_small = ProofMetadata {
                num_units: 0,
                ..valid_meta
            };
            assert!(super::verify_metadata(&num_units_small, &init_cfg).is_err());
        }
        {
            let num_units_large = ProofMetadata {
                num_units: 99,
                ..valid_meta
            };
            assert!(super::verify_metadata(&num_units_large, &init_cfg).is_err());
        }
        {
            let invalid_labels_per_unit = ProofMetadata {
                labels_per_unit: 99,
                ..valid_meta
            };
            assert!(super::verify_metadata(&invalid_labels_per_unit, &init_cfg).is_err());
        }
    }
}
