use post::{
    initialize::initialize,
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
        k3_pow_difficulty: u64::MAX / 8,
        pow_scrypt: ScryptParams::new(1, 0, 0),
        scrypt: ScryptParams::new(0, 0, 0),
    };

    let metadata = initialize(
        datadir.path(),
        &[0u8; 32],
        &[0u8; 32],
        labels_per_unit,
        31,
        labels_per_unit,
        cfg.scrypt,
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
        0,
    );

    assert_eq!(Ok(()), valid, "proof is not valid");
}
