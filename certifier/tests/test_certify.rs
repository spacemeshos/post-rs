use std::{future::IntoFuture, net::SocketAddr, str::FromStr, sync::atomic::AtomicBool};

use certifier::{certifier::CertifyRequest, configuration::RandomXMode};
use ed25519_dalek::SigningKey;
use post::{
    config::{InitConfig, ProofConfig, ScryptParams},
    initialize::{CpuInitializer, Initialize},
    metadata::ProofMetadata,
    pow::randomx::RandomXFlag,
    prove::generate_proof,
};
use reqwest::StatusCode;
use tokio::net::TcpListener;

#[tokio::test]
async fn test_certificate_post_proof() {
    // Initialize some data
    let challenge = b"hello world, challenge me!!!!!!!";
    let datadir = tempfile::tempdir().unwrap();

    let cfg = ProofConfig {
        k1: 20,
        k2: 10,
        k3: 10,
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

    // Generate a proof
    let pow_flags = RandomXFlag::get_recommended_flags();
    let stop = AtomicBool::new(false);
    let proof = generate_proof(datadir.path(), challenge, cfg, 32, 1, pow_flags, stop).unwrap();
    let metadata = ProofMetadata::new(metadata, *challenge);

    // Spawn the certifier service
    let signer = SigningKey::generate(&mut rand::rngs::OsRng);
    let app = certifier::certifier::new(cfg, init_cfg, signer, RandomXMode::Light);
    let listener = TcpListener::bind(SocketAddr::from_str("127.0.0.1:0").unwrap())
        .await
        .unwrap();
    let addr = listener.local_addr().unwrap();
    let server = axum::serve(listener, app.into_make_service());
    tokio::spawn(server.into_future());

    let client = reqwest::Client::new();

    // Certify with a valid proof
    let req = CertifyRequest { proof, metadata };
    let response = client
        .post(format!("http://{addr}/certify"))
        .json(&req)
        .send()
        .await
        .unwrap();
    assert!(response.status().is_success());

    // Try to certify with an invalid proof
    let mut invalid_req = req;
    invalid_req.metadata.num_units = 8;
    let response = client
        .post(format!("http://{addr}/certify"))
        .json(&invalid_req)
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
}
