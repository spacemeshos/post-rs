use aes::{
    cipher::{BlockEncrypt, KeyInit},
    Aes128,
};

pub struct Proof {
    nonce: u64,
    indices: [u64; 725],
}

fn work_oracle(_i: u64) -> u8 {
    0
}

pub fn verify(challenge: &[u8; 16], d: u64, proof: &Proof) -> bool {
    let mut key = [0u8; 16];
    key[..12].copy_from_slice(&challenge[..12]);
    key[12..].copy_from_slice(&proof.nonce.to_le_bytes());
    let cipher = Aes128::new(&key.into());

    let mut output = [0u8; 16];
    let output_index = proof.nonce as usize % 2;

    for i in proof.indices.into_iter() {
        let labels = (i..i + 16).map(|i| work_oracle(i)).collect();
        cipher.encrypt_block_b2b(&labels, (&mut output).into());
        unsafe {
            let (_, ints, _) = output.align_to::<u64>();
            if ints[output_index].to_le() > d {
                return false;
            }
        }
    }
    true
}
