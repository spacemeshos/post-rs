use std::{future::IntoFuture, net::SocketAddr, str::FromStr, sync::atomic::AtomicBool};

use certifier::{
    certifier::{Certificate, CertifyRequest},
    configuration::RandomXMode,
};
use ed25519_dalek::SigningKey;
use parity_scale_codec::Decode;
use post::{
    config::{Cores, InitConfig, ProofConfig, ScryptParams},
    initialize::{CpuInitializer, Initialize},
    metadata::ProofMetadata,
    pow::randomx::RandomXFlag,
    prove::{self, generate_proof, Proof},
};
use reqwest::StatusCode;
use tokio::net::TcpListener;

fn gen_proof(
    cfg: ProofConfig,
    init_cfg: InitConfig,
    id: [u8; 32],
) -> (Proof<'static>, ProofMetadata) {
    // Initialize some data
    let challenge = b"hello world, challenge me!!!!!!!";
    let datadir = tempfile::tempdir().unwrap();

    let metadata = CpuInitializer::new(init_cfg.scrypt)
        .initialize(
            datadir.path(),
            &id,
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
    let proof = generate_proof(
        datadir.path(),
        challenge,
        cfg,
        32,
        Cores::Any(1),
        pow_flags,
        stop,
        prove::NoopProgressReporter {},
    )
    .unwrap();
    let metadata = ProofMetadata::new(metadata, *challenge);

    (proof, metadata)
}

#[tokio::test]
async fn test_certificate_post_proof() {
    let cfg = ProofConfig {
        k1: 20,
        k2: 10,
        pow_difficulty: [0xFF; 32],
    };
    let init_cfg = InitConfig {
        min_num_units: 1,
        max_num_units: 1000,
        labels_per_unit: 200,
        scrypt: ScryptParams::new(2, 1, 1),
    };
    // Spawn the certifier service
    let signer = SigningKey::generate(&mut rand::rngs::OsRng);
    let app = certifier::certifier::new(cfg, init_cfg, signer.clone(), RandomXMode::Light, None);
    let listener = TcpListener::bind(SocketAddr::from_str("127.0.0.1:0").unwrap())
        .await
        .unwrap();
    let addr = listener.local_addr().unwrap();
    let server = axum::serve(listener, app.into_make_service());
    tokio::spawn(server.into_future());

    let client = reqwest::Client::new();

    let node_id = [
        1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11,
        12, 13, 14, 15, 16,
    ];
    let (proof, metadata) = gen_proof(cfg, init_cfg, node_id);

    // Certify with a valid proof
    let req = CertifyRequest { proof, metadata };

    // save as json to file
    let json = serde_json::to_string(&req).unwrap();
    std::fs::write("certify_request.json", json).unwrap();

    let response = client
        .post(format!("http://{addr}/certify"))
        .json(&req)
        .send()
        .await
        .unwrap();
    assert!(response.status().is_success());

    // verify the certificate
    let data = response.bytes().await.unwrap();
    let cert_resp = serde_json::from_slice::<certifier::certifier::CertifyResponse>(&data).unwrap();
    let cert = Certificate::decode(&mut cert_resp.certificate.as_slice()).unwrap();
    assert!(cert.expiration.is_none());
    let signature = ed25519_dalek::Signature::from_slice(&cert_resp.signature).unwrap();
    assert!(signer.verify(&cert_resp.certificate, &signature).is_ok());

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

#[tokio::test]
async fn test_certificate_post_proof_with_expiration() {
    let cfg = ProofConfig {
        k1: 20,
        k2: 10,
        pow_difficulty: [0xFF; 32],
    };
    let init_cfg = InitConfig {
        min_num_units: 1,
        max_num_units: 1000,
        labels_per_unit: 200,
        scrypt: ScryptParams::new(2, 1, 1),
    };
    // Spawn the certifier service
    let signer = SigningKey::generate(&mut rand::rngs::OsRng);
    let expiry = chrono::Duration::try_days(1).unwrap();
    let app = certifier::certifier::new(
        cfg,
        init_cfg,
        signer.clone(),
        RandomXMode::Light,
        Some(expiry),
    );
    let listener = TcpListener::bind(SocketAddr::from_str("127.0.0.1:0").unwrap())
        .await
        .unwrap();
    let addr = listener.local_addr().unwrap();
    let server = axum::serve(listener, app.into_make_service());
    tokio::spawn(server.into_future());

    let client = reqwest::Client::new();

    let node_id = [0u8; 32];
    let (proof, metadata) = gen_proof(cfg, init_cfg, node_id);

    // Certify with a valid proof
    let req_time = chrono::Utc::now();
    let req = CertifyRequest { proof, metadata };
    let response = client
        .post(format!("http://{addr}/certify"))
        .json(&req)
        .send()
        .await
        .unwrap();
    assert!(response.status().is_success());

    // verify the certificate
    let data = response.bytes().await.unwrap();
    let cert_resp = serde_json::from_slice::<certifier::certifier::CertifyResponse>(&data).unwrap();
    let cert = Certificate::decode(&mut cert_resp.certificate.as_slice()).unwrap();
    assert!(cert.expiration.unwrap().0 >= (req_time + expiry).timestamp() as u64);
    assert!(cert.expiration.unwrap().0 <= (chrono::Utc::now() + expiry).timestamp() as u64);

    let signature = ed25519_dalek::Signature::from_slice(&cert_resp.signature).unwrap();
    assert!(signer.verify(&cert_resp.certificate, &signature).is_ok());
}
