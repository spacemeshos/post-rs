use std::hint::black_box;

#[allow(unused_imports)]
use post::{
    difficulty,
    prove::{Prover, Prover16_48, Prover64_0, Prover8_56},
    prove::{Prover32_32, ProvingParams},
};

use rand::{rngs::mock::StepRng, RngCore};
use scrypt_jane::scrypt::ScryptParams;

const KIB: usize = 1024;
const MIB: usize = 1024 * KIB;

fn main() {
    let mut data = vec![0; 4096 * MIB];
    StepRng::new(0, 1).fill_bytes(&mut data);

    // A 256Gib post
    let num_labels = 256u64 * 1024 * 1024 * 1024 / 16;
    let labels_in_test = data.len() as u64 / 16;
    let k1 = 279;
    let parallel_nonces = 16;
    println!(
        "Assuming {num_labels} labels, but going through {labels_in_test} ({} MiB) only",
        data.len() / MIB
    );
    println!(
        "With K1={k1}, expecting to find {} good labels per nonce ({} total)",
        k1 * labels_in_test / num_labels,
        k1 * labels_in_test / num_labels * parallel_nonces as u64
    );

    let challenge = b"hello world, CHALLENGE me!!!!!!!";

    let difficulty = difficulty::proving_difficulty(num_labels, k1 as u32).unwrap();
    let params = ProvingParams {
        pow_scrypt: ScryptParams::new(0, 0, 0),
        difficulty,
        k2_pow_difficulty: u64::MAX, // extremely easy to find k2_pow
        k3_pow_difficulty: u64::MAX,
    };

    // 8/56:
    let prover = Prover8_56::new(challenge, 0..parallel_nonces, params.clone());
    let start = std::time::Instant::now();
    let mut good = 0;
    for i in 0..10 {
        prover.prove(&data, black_box(i), |_, _| {
            good += 1;
            None
        });
    }
    println!(
        "[8/56] speed: {:.0} MiB/s, found: {good} good labels",
        10.0 * data.len() as f64 / start.elapsed().as_secs_f64() / MIB as f64,
    );

    // 16/48:
    let prover = Prover16_48::new(challenge, 0..parallel_nonces, params.clone());
    let start = std::time::Instant::now();
    let mut good = 0;
    for i in 0..10 {
        prover.prove(&data, black_box(i), |_, _| {
            good += 1;
            None
        });
    }
    println!(
        "[16/48] speed: {:.0} MiB/s, found: {good} good labels",
        10.0 * data.len() as f64 / start.elapsed().as_secs_f64() / MIB as f64,
    );

    // 32/32:
    let prover = Prover32_32::new(challenge, 0..parallel_nonces, params.clone());
    let start = std::time::Instant::now();
    let mut good = 0;
    for i in 0..10 {
        prover.prove(&data, black_box(i), |_, _| {
            good += 1;
            None
        });
    }
    println!(
        "[32/32] speed: {:.0} MiB/s, found: {good} good labels",
        10.0 * data.len() as f64 / start.elapsed().as_secs_f64() / MIB as f64,
    );

    // 64/0:
    let prover = Prover64_0::new(challenge, 0..parallel_nonces, params);
    let start = std::time::Instant::now();
    let mut good = 0;
    for i in 0..10 {
        prover.prove(&data, black_box(i), |_, _| {
            good += 1;
            None
        });
    }
    println!(
        "[64/0] speed: {:.0} MiB/s, found: {good} good labels",
        10.0 * data.len() as f64 / start.elapsed().as_secs_f64() / MIB as f64,
    );
}
