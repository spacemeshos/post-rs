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
    let num_labels = 256;
    let datadir = tempdir().unwrap();

    let cfg = post::config::Config {
        k1: 32,
        k2: 32,
        k3: 10,
        k2_pow_difficulty: u64::MAX / 8,
        k3_pow_difficulty: u64::MAX / 8,
        pow_scrypt: ScryptParams::new(1, 0, 0),
        scrypt: ScryptParams::new(2, 0, 0),
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
    let valid = verify(
        &proof,
        &ProofMetadata {
            node_id: metadata.node_id,
            commitment_atx_id: metadata.commitment_atx_id,
            challenge: *challenge,
            num_units: metadata.num_units,
            labels_per_unit: metadata.labels_per_unit,
        },
        VerifyingParams::new(num_labels, cfg).unwrap(),
        0,
    );

    assert_eq!(Ok(()), valid, "proof is not valid");
}
