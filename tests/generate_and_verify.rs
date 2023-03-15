use post::{
    difficulty::proving_difficulty, generate_proof, initialize::initialize,
    metadata::ProofMetadata, verification::verify,
};
use scrypt_jane::scrypt::ScryptParams;
use tempfile::tempdir;

#[test]
fn test_generate_and_verify() {
    // Initialize some data
    let challenge = b"hello world, challenge me!!!!!!!";
    let num_labels = 256;
    let datadir = tempdir().unwrap();

    let cfg = post::config::Config {
        k1: 32,
        k2: 32,
        k2_pow_difficulty: u64::MAX / 8,
        k3_pow_difficulty: u64::MAX / 8,
        scrypt: ScryptParams::new(1, 0, 0),
    };

    let metadata = initialize(
        datadir.path(),
        &[0u8; 32],
        &[0u8; 32],
        num_labels,
        1,
        cfg.scrypt,
    )
    .unwrap();

    // Generate a proof
    let proof = generate_proof(datadir.path(), challenge, cfg, 10).unwrap();

    // Verify the proof
    let params = post::verification::VerifyingParams {
        difficulty: proving_difficulty(num_labels, cfg.k1).unwrap(),
        k2: cfg.k2,
        k2_pow_difficulty: cfg.k2_pow_difficulty,
        k3_pow_difficulty: cfg.k3_pow_difficulty,
        scrypt: cfg.scrypt,
    };
    let valid = verify(
        &proof,
        &ProofMetadata {
            node_id: metadata.node_id,
            commitment_atx_id: metadata.commitment_atx_id,
            challenge: *challenge,
            num_units: metadata.num_units,
            labels_per_unit: metadata.labels_per_unit,
        },
        params,
        0,
    );

    assert_eq!(Ok(()), valid, "proof is not valid");
}
