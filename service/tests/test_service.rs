use std::{thread::sleep, time::Duration};

use post::{
    config::{InitConfig, ProofConfig, ScryptParams},
    initialize::{CpuInitializer, Initialize},
    metadata::ProofMetadata,
    pow::randomx::RandomXFlag,
};
use post_service::{client::PostService, service::ProofGenState};

#[test]
fn test_generate_and_verify() {
    // Initialize some data
    let datadir = tempfile::tempdir().unwrap();

    let cfg = ProofConfig {
        k1: 8,
        k2: 4,
        k3: 4,
        pow_difficulty: [0xFF; 32],
    };
    let init_cfg = InitConfig {
        min_num_units: 1,
        max_num_units: 1000,
        labels_per_unit: 256,
        scrypt: ScryptParams::new(2, 1, 1),
    };

    let metadata = CpuInitializer::new(init_cfg.scrypt)
        .initialize(
            datadir.path(),
            &[0xBE; 32],
            &[0xCE; 32],
            init_cfg.labels_per_unit,
            4,
            init_cfg.labels_per_unit,
            None,
        )
        .unwrap();

    let pow_flags = RandomXFlag::get_recommended_flags();

    // Generate a proof
    let service = post_service::service::PostService::new(
        datadir.into_path(),
        cfg,
        init_cfg,
        16,
        1,
        pow_flags,
    )
    .unwrap();

    let (proof, metadata) = loop {
        if let ProofGenState::Finished { proof } = service.gen_proof(vec![0xCA; 32]).unwrap() {
            break (proof, metadata);
        }
        sleep(Duration::from_millis(10));
    };

    // Verify the proof
    service
        .verify_proof(&proof, &ProofMetadata::new(metadata, [0xCA; 32]), &[])
        .expect("proof should be valid");
}

#[test]
fn reject_invalid_challenge() {
    // Initialize some data
    let datadir = tempfile::tempdir().unwrap();

    let cfg = ProofConfig {
        k1: 8,
        k2: 4,
        k3: 4,
        pow_difficulty: [0xFF; 32],
    };
    let init_cfg = InitConfig {
        min_num_units: 1,
        max_num_units: 1000,
        labels_per_unit: 256,
        scrypt: ScryptParams::new(2, 1, 1),
    };

    CpuInitializer::new(init_cfg.scrypt)
        .initialize(
            datadir.path(),
            &[0xBE; 32],
            &[0xCE; 32],
            init_cfg.labels_per_unit,
            4,
            init_cfg.labels_per_unit,
            None,
        )
        .unwrap();

    // Generate a proof
    let service = post_service::service::PostService::new(
        datadir.into_path(),
        cfg,
        init_cfg,
        16,
        1,
        RandomXFlag::get_recommended_flags(),
    )
    .unwrap();
    assert!(service.gen_proof(vec![0xCA; 5]).is_err());
}

#[test]
fn cannot_run_parallel_proof_gens() {
    // Initialize some data
    let datadir = tempfile::tempdir().unwrap();

    let cfg = ProofConfig {
        k1: 8,
        k2: 4,
        k3: 4,
        pow_difficulty: [0xFF; 32],
    };
    let init_cfg = InitConfig {
        min_num_units: 1,
        max_num_units: 1000,
        labels_per_unit: 256,
        scrypt: ScryptParams::new(2, 1, 1),
    };

    CpuInitializer::new(init_cfg.scrypt)
        .initialize(
            datadir.path(),
            &[0xBE; 32],
            &[0xCE; 32],
            init_cfg.labels_per_unit,
            4,
            init_cfg.labels_per_unit,
            None,
        )
        .unwrap();

    // Generate a proof
    let service = post_service::service::PostService::new(
        datadir.into_path(),
        cfg,
        init_cfg,
        16,
        1,
        RandomXFlag::get_recommended_flags(),
    )
    .unwrap();

    let result = service.gen_proof(vec![0xAA; 32]);
    assert!(matches!(result, Ok(ProofGenState::InProgress)));
    // Try to generate another proof with a different challenge
    assert!(service.gen_proof(vec![0xBB; 5]).is_err());
    // Try again with the same challenge
    assert!(matches!(result, Ok(ProofGenState::InProgress)));
}
