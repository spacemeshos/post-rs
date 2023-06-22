use aes::cipher::{generic_array::GenericArray, KeyInit};
use aes::Aes128;

#[derive(Debug)]
pub(crate) struct AesCipher {
    pub(crate) aes: Aes128,
    pub(crate) nonce_group: u32,
    pub(crate) pow: u64,
}

impl AesCipher {
    /// Create new AES cipher for the given challenge and nonce.
    /// AES key = blake3(challenge, nonce_group, pow)
    pub(crate) fn new(challenge: &[u8; 32], nonce_group: u32, pow: u64) -> Self {
        let mut hasher = blake3::Hasher::new();
        hasher.update(challenge);
        hasher.update(&nonce_group.to_le_bytes());
        hasher.update(&pow.to_le_bytes());
        Self {
            aes: Aes128::new(GenericArray::from_slice(
                &hasher.finalize().as_bytes()[..16],
            )),
            nonce_group,
            pow,
        }
    }

    pub(crate) fn new_lazy(challenge: &[u8; 32], nonce: u32, nonce_group: u32, pow: u64) -> Self {
        let mut hasher = blake3::Hasher::new();
        hasher.update(challenge);
        hasher.update(&nonce_group.to_le_bytes());
        hasher.update(&pow.to_le_bytes());
        hasher.update(&nonce.to_le_bytes());
        Self {
            aes: Aes128::new(GenericArray::from_slice(
                &hasher.finalize().as_bytes()[..16],
            )),
            nonce_group,
            pow,
        }
    }
}

#[cfg(test)]
mod tests {
    use aes::cipher::{generic_array::GenericArray, BlockEncrypt};
    use proptest::prelude::*;

    use crate::cipher::AesCipher;

    proptest! {
        #[test]
        fn different_nonces_give_different_ciphers(a: u32, b: u32, challenge: [u8; 32], data: [u8; 16]) {
            let data = GenericArray::from(data);
            let cipher1 = AesCipher::new(&challenge, a, 0);
            let cipher2 = AesCipher::new(&challenge, b, 0);

            let mut out1 = GenericArray::from([0u8; 16]);
            cipher1.aes.encrypt_block_b2b(&data, &mut out1);

            let mut out2 = GenericArray::from([0u8; 16]);
            cipher2.aes.encrypt_block_b2b(&data, &mut out2);

            if a != b {
                assert_ne!(out1, out2);
            } else {
                assert_eq!(out1, out2);
            }
        }
        #[test]
        fn different_challenges_give_different_ciphers(challenge1: [u8; 32], challenge2: [u8; 32], nonce: u32, data: [u8; 16]) {
            let data = GenericArray::from(data);
            let cipher1 = AesCipher::new(&challenge1, nonce, 0);
            let cipher2 = AesCipher::new(&challenge2, nonce, 0);

            let mut out1 = GenericArray::from([0u8; 16]);
            cipher1.aes.encrypt_block_b2b(&data, &mut out1);

            let mut out2 = GenericArray::from([0u8; 16]);
            cipher2.aes.encrypt_block_b2b(&data, &mut out2);

            if challenge1 != challenge2 {
                assert_ne!(out1, out2);
            } else {
                assert_eq!(out1, out2);
            }
        }
    }
}
