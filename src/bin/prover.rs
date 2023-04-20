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

fn bench<T: Prover>(name: &str, prover: T, data: &[u8], iterations: u64) {
    let mut good = 0;
    let start = std::time::Instant::now();
    for i in 0..iterations {
        prover.prove(data, i, |_, _| {
            good += 1;
            black_box(None)
        });
    }
    let took = start.elapsed().as_secs_f64();
    println!(
        "{name:7} speed: {:.0} MiB/s, found: {} good labels",
        iterations as f64 * data.len() as f64 / took / MIB as f64,
        good / iterations,
    );
}

fn main() {
    let iterations = 5;
    let parallel_nonces = 16;
    let k1 = 279;

    let mut data = vec![0; 4096 * MIB];
    StepRng::new(0, 1).fill_bytes(&mut data);

    // A 256Gib post
    let num_labels = 256u64 * 1024 * 1024 * 1024 / 16;
    let labels_in_test = data.len() as u64 / 16;
    println!(
        "Assuming {num_labels} labels, but going through {labels_in_test} ({} MiB) only",
        data.len() / MIB
    );
    println!(
        "With K1={k1}, expecting to find {:.2} good labels per nonce ({:.2} total)",
        (k1 * labels_in_test) as f64 / num_labels as f64,
        (k1 * labels_in_test * parallel_nonces as u64) as f64 / num_labels as f64
    );

    let challenge = b"hello world, CHALLENGE me!!!!!!!";

    let difficulty = difficulty::proving_difficulty(num_labels, k1 as u32).unwrap();
    let params = ProvingParams {
        pow_scrypt: ScryptParams::new(0, 0, 0),
        difficulty,
        k2_pow_difficulty: u64::MAX, // extremely easy to find k2_pow
        k3_pow_difficulty: u64::MAX,
    };

    bench(
        "[8/56]",
        Prover8_56::new(challenge, 0..parallel_nonces, params.clone()),
        &data,
        iterations,
    );

    bench(
        "[16/48]",
        Prover16_48::new(challenge, 0..parallel_nonces, params.clone()),
        &data,
        iterations,
    );

    bench(
        "[32/32]",
        Prover32_32::new(challenge, 0..parallel_nonces, params.clone()),
        &data,
        iterations,
    );

    bench(
        "[64/0]",
        Prover64_0::new(challenge, 0..parallel_nonces, params),
        &data,
        iterations,
    );
}
