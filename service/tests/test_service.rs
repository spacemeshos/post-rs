use std::{thread::sleep, time::Duration};

use post::{
    config::{ProofConfig, ScryptParams},
    initialize::{CpuInitializer, Initialize},
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
        pow_difficulty: [0xFF; 32],
    };
    let scrypt = ScryptParams::new(2, 1, 1);

    CpuInitializer::new(scrypt)
        .initialize(datadir.path(), &[0xBE; 32], &[0xCE; 32], 156, 4, 256, None)
        .unwrap();

    let pow_flags = RandomXFlag::get_recommended_flags();

    // Generate a proof
    let service = post_service::service::PostService::new(
        datadir.into_path(),
        cfg,
        scrypt,
        16,
        post::config::Cores::Any(1),
        pow_flags,
    )
    .unwrap();

    let proof = loop {
        if let ProofGenState::Finished { proof } = service.gen_proof(&[0xCA; 32]).unwrap() {
            break proof;
        }
        sleep(Duration::from_millis(10));
    };

    // Verify the proof
    service
        .verify_proof(&proof, &[0xCA; 32])
        .expect("proof should be valid");
}

#[test]
fn reject_invalid_challenge() {
    // Initialize some data
    let datadir = tempfile::tempdir().unwrap();

    let cfg = ProofConfig {
        k1: 8,
        k2: 4,
        pow_difficulty: [0xFF; 32],
    };
    let scrypt = ScryptParams::new(2, 1, 1);

    CpuInitializer::new(scrypt)
        .initialize(datadir.path(), &[0xBE; 32], &[0xCE; 32], 256, 4, 256, None)
        .unwrap();

    // Generate a proof
    let service = post_service::service::PostService::new(
        datadir.into_path(),
        cfg,
        scrypt,
        16,
        post::config::Cores::Any(1),
        RandomXFlag::get_recommended_flags(),
    )
    .unwrap();
    assert!(service.gen_proof(&[0xCA; 5]).is_err());
}

#[test]
fn cannot_run_parallel_proof_gens() {
    // Initialize some data
    let datadir = tempfile::tempdir().unwrap();

    let cfg = ProofConfig {
        k1: 8,
        k2: 4,
        pow_difficulty: [0xFF; 32],
    };
    let scrypt = ScryptParams::new(2, 1, 1);

    CpuInitializer::new(scrypt)
        .initialize(datadir.path(), &[0xBE; 32], &[0xCE; 32], 256, 4, 256, None)
        .unwrap();

    // Generate a proof
    let service = post_service::service::PostService::new(
        datadir.into_path(),
        cfg,
        scrypt,
        16,
        post::config::Cores::Any(1),
        RandomXFlag::get_recommended_flags(),
    )
    .unwrap();

    let result = service.gen_proof(&[0xAA; 32]);
    assert!(matches!(result, Ok(ProofGenState::InProgress)));
    // Try to generate another proof with a different challenge
    assert!(service.gen_proof(&[0xBB; 5]).is_err());
    // Try again with the same challenge
    assert!(matches!(result, Ok(ProofGenState::InProgress)));
}
