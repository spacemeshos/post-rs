use post::{
    initialize::{CpuInitializer, Initialize},
    metadata::ProofMetadata,
    prove::generate_proof,
    verification::{verify, VerifyingParams},
};
use scrypt_jane::scrypt::ScryptParams;
use tempfile::tempdir;

#[test]
fn test_generate_and_verify() {
    // Initialize some data
    let challenge = b"hello world, challenge me!!!!!!!";
    let labels_per_unit = 256 * 16;
    let datadir = tempdir().unwrap();

    let cfg = post::config::Config {
        k1: 23,
        k2: 32,
        k3: 10,
        k2_pow_difficulty: u64::MAX / 8,
        pow_scrypt: ScryptParams::new(1, 0, 0),
        scrypt: ScryptParams::new(0, 0, 0),
    };

    let metadata = CpuInitializer::new(cfg.scrypt)
        .initialize(
            datadir.path(),
            &[0u8; 32],
            &[0u8; 32],
            labels_per_unit,
            31,
            labels_per_unit,
            None,
        )
        .unwrap();

    // Generate a proof
    let proof = generate_proof(datadir.path(), challenge, cfg, 32, 1).unwrap();

    // Verify the proof
    let metadata = ProofMetadata {
        node_id: metadata.node_id,
        commitment_atx_id: metadata.commitment_atx_id,
        challenge: *challenge,
        num_units: metadata.num_units,
        labels_per_unit: metadata.labels_per_unit,
    };
    let valid = verify(
        &proof,
        &metadata,
        VerifyingParams::new(&metadata, &cfg).unwrap(),
    );
    assert_eq!(Ok(()), valid, "proof is not valid");

    // Check that the proof is invalid if we modify one index
    let mut invalid_proof = proof;
    invalid_proof.indices[0] += 2;
    let valid = verify(
        &invalid_proof,
        &metadata,
        VerifyingParams::new(&metadata, &cfg).unwrap(),
    );
    assert!(valid.is_err(), "proof should be invalid");
}

#[test]
/// With small unit size, the difficulty MSB != 0 which
/// triggers different conditionals in the verifier.
fn test_generate_and_verify_difficulty_msb_not_zero() {
    // Initialize some data
    let challenge = b"hello world, challenge me!!!!!!!";
    let labels_per_unit = 200;
    let datadir = tempdir().unwrap();

    let cfg = post::config::Config {
        k1: 20,
        k2: 30,
        k3: 30,
        k2_pow_difficulty: u64::MAX,
        pow_scrypt: ScryptParams::new(0, 0, 0),
        scrypt: ScryptParams::new(0, 0, 0),
    };

    let metadata = CpuInitializer::new(cfg.scrypt)
        .initialize(
            datadir.path(),
            &[0u8; 32],
            &[0u8; 32],
            labels_per_unit,
            2,
            labels_per_unit,
            None,
        )
        .unwrap();

    // Generate a proof
    let proof = generate_proof(datadir.path(), challenge, cfg, 32, 1).unwrap();

    // Verify the proof
    let metadata = ProofMetadata {
        node_id: metadata.node_id,
        commitment_atx_id: metadata.commitment_atx_id,
        challenge: *challenge,
        num_units: metadata.num_units,
        labels_per_unit: metadata.labels_per_unit,
    };
    let valid = verify(
        &proof,
        &metadata,
        VerifyingParams::new(&metadata, &cfg).unwrap(),
    );
    assert_eq!(Ok(()), valid, "proof is not valid");

    // Check that the proof is invalid if we modify one index
    let mut invalid_proof = proof;
    invalid_proof.indices[0] += 1;
    let valid = verify(
        &invalid_proof,
        &metadata,
        VerifyingParams::new(&metadata, &cfg).unwrap(),
    );
    assert!(valid.is_err(), "proof should be invalid");
}
