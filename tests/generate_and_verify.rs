use std::{borrow::Cow, sync::atomic::AtomicBool};

use post::{
    compression::{compress_indices, decompress_indexes, required_bits},
    config::{InitConfig, ScryptParams},
    initialize::{CpuInitializer, Initialize},
    metadata::ProofMetadata,
    pow::randomx::{PoW, RandomXFlag},
    prove::{self, generate_proof, Proof},
    verification::{Error, Mode, Verifier},
};
use tempfile::tempdir;

#[test]
fn test_generate_and_verify() {
    // Initialize some data
    let challenge = b"hello world, challenge me!!!!!!!";
    let datadir = tempdir().unwrap();

    let cfg = post::config::ProofConfig {
        k1: 23,
        k2: 32,
        pow_difficulty: [0xFF; 32],
    };
    let init_cfg = InitConfig {
        min_num_units: 1,
        max_num_units: 1000,
        labels_per_unit: 256 * 16,
        scrypt: ScryptParams::new(2, 1, 1),
    };

    let metadata = CpuInitializer::new(init_cfg.scrypt)
        .initialize(
            datadir.path(),
            &[77; 32],
            &[0u8; 32],
            init_cfg.labels_per_unit,
            31,
            1000,
            None,
        )
        .unwrap();

    let pow_flags = RandomXFlag::get_recommended_flags();
    // Generate a proof
    let stop = AtomicBool::new(false);
    let mut reporter = prove::MockProgressReporter::new();
    reporter.expect_new_nonce_group().once().return_const(());
    reporter.expect_finished_chunk().times(1..).return_const(());

    let proof = generate_proof(
        datadir.path(),
        challenge,
        cfg,
        32,
        1,
        pow_flags,
        stop,
        reporter,
    )
    .unwrap();

    // Verify the proof
    let metadata = ProofMetadata::new(metadata, *challenge);
    let verifier = Verifier::new(Box::new(PoW::new(pow_flags).unwrap()));
    verifier
        .verify(&proof, &metadata, &cfg, &init_cfg, Mode::All)
        .expect("proof should be valid");

    // Check that the proof is invalid if we modify one index
    let bits = required_bits(metadata.num_units as u64 * init_cfg.labels_per_unit);
    let mut indices = decompress_indexes(&proof.indices, bits).collect::<Vec<_>>();
    indices[7] ^= u64::MAX;
    let invalid_proof = Proof {
        indices: Cow::Owned(compress_indices(&indices, bits)),
        ..proof
    };

    // verify all indices
    let result = verifier.verify(&invalid_proof, &metadata, &cfg, &init_cfg, Mode::All);
    assert!(matches!(
        result,
        Err(Error::InvalidMsb { index_id, .. }) if index_id == 7
    ));

    // verify subset of all indices
    let mode = Mode::Subset {
        k3: cfg.k2 as _,
        seed: &[],
    };
    let result = verifier.verify(&invalid_proof, &metadata, &cfg, &init_cfg, mode);
    assert!(matches!(
        result,
        Err(Error::InvalidMsb { index_id, .. }) if index_id == 7
    ));

    // verify subset of 1 index - pass as doesn't hit the invalid index
    let mode = Mode::Subset { k3: 1, seed: &[] };
    let result = verifier.verify(&invalid_proof, &metadata, &cfg, &init_cfg, mode);
    assert!(result.is_ok());

    // verify subset of indices - fail as hits the invalid index
    let mode = Mode::Subset {
        k3: cfg.k2 as usize - 1,
        seed: &[],
    };
    let result = verifier.verify(&invalid_proof, &metadata, &cfg, &init_cfg, mode);
    assert!(matches!(
        result,
        Err(Error::InvalidMsb { index_id, .. }) if index_id == 7
    ));
}

#[test]
/// With small unit size, the difficulty MSB != 0 which
/// triggers different conditionals in the verifier.
fn test_generate_and_verify_difficulty_msb_not_zero() {
    // Initialize some data
    let challenge = b"hello world, challenge me!!!!!!!";
    let datadir = tempdir().unwrap();

    let cfg = post::config::ProofConfig {
        k1: 20,
        k2: 30,
        pow_difficulty: [0xFF; 32],
    };
    let init_cfg = InitConfig {
        min_num_units: 1,
        max_num_units: 1000,
        labels_per_unit: 200,
        scrypt: ScryptParams::new(2, 1, 1),
    };

    let metadata = CpuInitializer::new(init_cfg.scrypt)
        .initialize(
            datadir.path(),
            &[0u8; 32],
            &[0u8; 32],
            init_cfg.labels_per_unit,
            2,
            init_cfg.labels_per_unit,
            None,
        )
        .unwrap();

    let pow_flags = RandomXFlag::get_recommended_flags();
    // Generate a proof
    let stop = AtomicBool::new(false);
    let proof = generate_proof(
        datadir.path(),
        challenge,
        cfg,
        32,
        1,
        pow_flags,
        stop,
        prove::NoopProgressReporter {},
    )
    .unwrap();

    // Verify the proof
    let metadata = ProofMetadata::new(metadata, *challenge);
    let verifier = Verifier::new(Box::new(PoW::new(pow_flags).unwrap()));
    verifier
        .verify(&proof, &metadata, &cfg, &init_cfg, Mode::All)
        .expect("proof should be valid");

    // Check that the proof is invalid if we modify one index
    let bits = required_bits(metadata.num_units as u64 * init_cfg.labels_per_unit);
    let mut indices = decompress_indexes(&proof.indices, bits).collect::<Vec<_>>();
    indices[4] ^= u64::MAX;
    let invalid_proof = Proof {
        indices: Cow::Owned(compress_indices(&indices, bits)),
        ..proof
    };

    let result = verifier.verify(
        &invalid_proof,
        &metadata,
        &cfg,
        &init_cfg,
        Mode::One { index: 4 },
    );
    assert!(matches!(
        result,
        Err(Error::InvalidMsb { index_id, .. }) if index_id == 4
    ));
}
