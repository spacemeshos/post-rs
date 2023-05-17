//! Proof of Work algorithms
//!
//! PoW for K2 is required to prevent grinding on nonces
//! when looking for a proof. Without it a malicious actor
//! with a powerful enough computer could try many nonces
//! at the same time. In effect a proof could be found
//! without actually holding the whole POST data.
use randomx_rs::{RandomXCache, RandomXDataset, RandomXFlag, RandomXVM};
use rayon::prelude::{IntoParallelIterator, ParallelIterator};
use scrypt_jane::scrypt::{scrypt, ScryptParams};

pub fn find_k2_pow(challenge: &[u8; 32], nonce: u32, params: ScryptParams, difficulty: u64) -> u64 {
    (0u64..u64::MAX)
        .into_par_iter()
        .find_any(|&k2_pow| hash_k2_pow(challenge, nonce, params, k2_pow) < difficulty)
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

struct RandomXState {
    cache: RandomXCache,
    dataset: RandomXDataset,
    vm: RandomXVM,
}

pub fn find_k2_pow_randomx(
    nonce_group: u8,
    challenge: &[u8; 8],
    difficulty: &[u8; 32],
) -> Option<(u64, Vec<u8>)> {
    let pool = rayon::ThreadPoolBuilder::new()
        .num_threads(1)
        .build()
        .unwrap();

    let pow_input = [[0u8; 7].as_slice(), [nonce_group].as_slice(), challenge].concat();

    let k2pow = pool.install(|| {
        (0u64..2u64.pow(56))
            .into_par_iter()
            .map_init(
                || -> Result<_, Box<dyn Error>> {
                    println!("initializing randomx");
                    let cache = RandomXCache::new(
                        RandomXFlag::FLAG_ARGON2_AVX2,
                        format!("key: {:?}", std::thread::current().id()).as_bytes(),
                    )?;
                    let dataset = RandomXDataset::new(RandomXFlag::FLAG_ARGON2, &cache, 0)?;
                    let vm = RandomXVM::new(
                        RandomXFlag::FLAG_FULL_MEM
                            | RandomXFlag::FLAG_HARD_AES
                            | RandomXFlag::FLAG_JIT,
                        Some(&cache),
                        Some(&dataset),
                    )?;

                    Ok((RandomXState { cache, dataset, vm }, pow_input.clone()))
                },
                |state, k2_pow| {
                    let hash = if let Ok((rx, pow_input)) = state {
                        pow_input[0..7].copy_from_slice(&k2_pow.to_le_bytes()[0..7]);
                        rx.vm.calculate_hash(pow_input.as_slice()).ok()
                    } else {
                        None
                    };
                    (k2_pow, hash)
                },
            )
            .filter_map(|(k2_pow, hash)| hash.map(|hash| (k2_pow, hash)))
            .find_first(|(_, hash)| hash.as_slice() < difficulty)
    });

    k2pow
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

    #[test]
    fn test_randomx() {
        use std::time::Instant;

        const TRIES: u8 = 2;
        const CH: [u8; 8] = [1, 2, 3, 4, 5, 6, 7, 8];

        let k2_difficulty: [u8; 32] = [
            0x00, 0x00, 0xdf, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0xff, 0xff, 0xff, 0xff,
        ];

        let start = Instant::now();
        for nonce_group in 0..TRIES {
            let start = Instant::now();
            let nonce_group = nonce_group + 1;
            let k2pow = find_k2_pow_randomx(nonce_group, &CH, &k2_difficulty).unwrap();

            println!(
                "nonce {nonce_group}, duration {:.2}: {k2pow:?}",
                start.elapsed().as_secs_f64()
            );
        }
        println!(
            "Average duration: {:.2}",
            start.elapsed().as_secs_f64() / TRIES as f64
        );
    }
}
