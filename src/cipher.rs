use aes::Aes128;
use cipher::KeyInit;
use scrypt_jane::scrypt::{scrypt, ScryptParams};

#[derive(Debug)]
pub(crate) struct AesCipher {
    pub(crate) aes: Aes128,
    pub(crate) nonce: u32,
}

impl AesCipher {
    pub(crate) fn new(challenge: &[u8; 32], nonce: u32, params: ScryptParams) -> Self {
        let mut key = [0u8; 16];
        scrypt(challenge, &nonce.to_le_bytes(), params, &mut key);

        Self {
            aes: Aes128::new(&key.into()),
            nonce,
        }
    }
}

#[cfg(test)]
mod tests {
    use cipher::{generic_array::GenericArray, BlockEncrypt};
    use proptest::prelude::*;
    use scrypt_jane::scrypt::ScryptParams;

    use crate::cipher::AesCipher;

    proptest! {
        #[test]
        fn different_nonces_give_different_ciphers(a: u32, b: u32, challenge: [u8; 32], data: [u8; 16]) {
            let params = ScryptParams::new(8, 0, 0);
            let data = GenericArray::from(data);
            let cipher1 = AesCipher::new(&challenge, a, params);
            let cipher2 = AesCipher::new(&challenge, b, params);

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
            let params = ScryptParams::new(8, 0, 0);
            let data = GenericArray::from(data);
            let cipher1 = AesCipher::new(&challenge1, nonce, params);
            let cipher2 = AesCipher::new(&challenge2, nonce, params);

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
