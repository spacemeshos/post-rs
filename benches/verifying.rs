use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion};
use post::{
    metadata::ProofMetadata,
    prove::Proof,
    verification::{verify, VerifyingParams},
};
use pprof::criterion::{Output, PProfProfiler};

use scrypt_jane::scrypt::ScryptParams;

fn threads_to_str(threads: usize) -> String {
    if threads == 0 {
        "auto".into()
    } else {
        threads.to_string()
    }
}

fn verifying(c: &mut Criterion) {
    let challenge = b"hello world, challenge me!!!!!!!";
    let metadata = ProofMetadata {
        node_id: [0u8; 32],
        commitment_atx_id: [0u8; 32],
        challenge: *challenge,
        num_units: 1,
        labels_per_unit: 1024 * 1024 * 1024,
    };
    let num_labels = metadata.num_units as u64 * metadata.labels_per_unit;

    for (k2, k3, threads) in itertools::iproduct!(
        [200u32, 2000],
        [25u32, 50],
        [0, 1] // 0 == automatic
    ) {
        c.bench_with_input(
            BenchmarkId::new(
                "verify",
                format!("k2={k2}/k3={k3}/threads={}", threads_to_str(threads)),
            ),
            &(k2, k3, threads),
            |b, &(k2, k3, threads)| {
                let proof = Proof::new(
                    0,
                    (0..k2 as u64).collect::<Vec<u64>>().as_slice(),
                    num_labels.ilog2() as usize + 1,
                    0,
                    0,
                );
                let params = VerifyingParams {
                    difficulty: u64::MAX,
                    k2,
                    k3,
                    k2_pow_difficulty: u64::MAX,
                    k3_pow_difficulty: u64::MAX,
                    pow_scrypt: ScryptParams::new(6, 0, 0),
                    scrypt: ScryptParams::new(12, 0, 0),
                };

                b.iter(|| {
                    let result = verify(&proof, &metadata, params, threads);
                    assert_eq!(Ok(()), result, "proof is not valid");
                });
            },
        );
    }
}

criterion_group!(
    name = benches;
    config = Criterion::default().with_profiler(PProfProfiler::new(1000, Output::Flamegraph(None)));
    targets=verifying
);

criterion_main!(benches);
