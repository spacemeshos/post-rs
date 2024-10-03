mod server;

use std::{borrow::Cow, sync::Arc};

use rstest::rstest;
use tempfile::tempdir;
use tokio::sync::oneshot;

use post::{
    initialize::{CpuInitializer, Initialize},
    metadata::PostMetadata,
    prove::Proof,
};
use post_service::{
    client::{
        spacemesh_v1::{
            self, service_response, GenProofResponse, GenProofStatus, Metadata, MetadataResponse,
            NodeRequest,
        },
        MockPostService,
    },
    service::ProofGenState,
};
use server::{TestNodeRequest, TestServer, TlsConfig};
use tonic::transport::{Certificate, Identity};

#[tokio::test]
async fn test_registers() {
    let mut test_server = TestServer::new(None).await;
    let client = test_server.create_client(Arc::new(MockPostService::new()));
    let client_handle = tokio::spawn(client.run(None, std::time::Duration::from_secs(1)));

    // Check if client registered
    test_server.connected.recv().await.unwrap();
    client_handle.abort();
    let _ = client_handle.await;
}

#[tokio::test]
async fn test_registers_tls() {
    let ca = rcgen::generate_simple_self_signed(vec![]).unwrap();
    let client = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
    let server = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();

    let tls_config = TlsConfig {
        client_ca_cert: Certificate::from_pem(ca.serialize_pem().unwrap()),
        server_ca_cert: Certificate::from_pem(ca.serialize_pem().unwrap()),
        server: Identity::from_pem(
            server.serialize_pem_with_signer(&ca).unwrap(),
            server.serialize_private_key_pem(),
        ),
        client: Identity::from_pem(
            client.serialize_pem_with_signer(&ca).unwrap(),
            client.serialize_private_key_pem(),
        ),
    };
    let mut test_server = TestServer::new(Some(tls_config)).await;
    let client = test_server.create_client(Arc::new(MockPostService::new()));
    let client_handle = tokio::spawn(client.run(None, std::time::Duration::from_secs(1)));

    // Check if client registered
    test_server.connected.recv().await.unwrap();
    client_handle.abort();
    let _ = client_handle.await;
}

#[tokio::test]
async fn test_gen_proof_in_progress() {
    let mut test_server = TestServer::new(None).await;

    let mut service = MockPostService::new();
    service
        .expect_gen_proof()
        .returning(|_| Ok(ProofGenState::InProgress));
    let service = Arc::new(service);
    let client = test_server.create_client(service.clone());
    let client_handle = tokio::spawn(client.run(None, std::time::Duration::from_secs(1)));

    let connected = test_server.connected.recv().await.unwrap();
    let response = TestServer::generate_proof(&connected, vec![0xCA; 32]).await;

    assert_eq!(
        response.kind,
        Some(service_response::Kind::GenProof(GenProofResponse {
            status: GenProofStatus::Ok as i32,
            proof: None,
            metadata: None
        }))
    );

    client_handle.abort();
    let _ = client_handle.await;
}

#[tokio::test]
async fn test_gen_proof_failed() {
    let mut test_server = TestServer::new(None).await;

    let mut service = MockPostService::new();
    service
        .expect_gen_proof()
        .returning(|_| Err(eyre::eyre!("failed to generate proof")));

    let service = Arc::new(service);
    let client = test_server.create_client(service.clone());
    let client_handle = tokio::spawn(client.run(None, std::time::Duration::from_secs(1)));

    let connected = test_server.connected.recv().await.unwrap();
    let response = TestServer::generate_proof(&connected, vec![0xCA; 32]).await;

    assert_eq!(
        response.kind,
        Some(service_response::Kind::GenProof(GenProofResponse {
            status: GenProofStatus::Error as _,
            proof: None,
            metadata: None
        }))
    );

    client_handle.abort();
    let _ = client_handle.await;
}

#[tokio::test]
async fn test_gen_proof_finished() {
    let mut test_server = TestServer::new(None).await;

    let challenge = &[0xCA; 32];
    let indices = &[0xAA; 32];
    let node_id = &[0xBB; 32];
    let commitment_atx_id = &[0xCC; 32];

    let mut service = MockPostService::new();
    service.expect_gen_proof().returning(move |c| {
        assert_eq!(c, challenge);
        Ok(ProofGenState::Finished {
            proof: Proof {
                nonce: 1,
                indices: Cow::Owned(indices.to_vec()),
                pow: 7,
            },
        })
    });

    let post_metadata = PostMetadata {
        node_id: *node_id,
        commitment_atx_id: *commitment_atx_id,
        num_units: 4,
        labels_per_unit: 256,
        nonce: Some(12),
        ..Default::default()
    };
    service.expect_get_metadata().return_const(post_metadata);
    // First try passes
    service
        .expect_verify_proof()
        .once()
        .returning(|_, _| Ok(()));
    // Second try fails
    service
        .expect_verify_proof()
        .once()
        .returning(|_, _| Err(eyre::eyre!("invalid proof")));

    let service = Arc::new(service);
    let client = test_server.create_client(service.clone());
    let client_handle = tokio::spawn(client.run(None, std::time::Duration::from_secs(1)));

    let connected = test_server.connected.recv().await.unwrap();

    let response = TestServer::generate_proof(&connected, challenge.to_vec()).await;

    assert_eq!(
        response.kind,
        Some(service_response::Kind::GenProof(GenProofResponse {
            status: GenProofStatus::Ok as _,
            proof: Some(spacemesh_v1::Proof {
                nonce: 1,
                indices: indices.to_vec(),
                pow: 7,
            }),
            metadata: Some(spacemesh_v1::ProofMetadata {
                challenge: challenge.to_vec(),
                meta: Some(Metadata {
                    node_id: post_metadata.node_id.to_vec(),
                    commitment_atx_id: post_metadata.commitment_atx_id.to_vec(),
                    nonce: post_metadata.nonce,
                    num_units: post_metadata.num_units,
                    labels_per_unit: post_metadata.labels_per_unit,
                }),
            }),
        }))
    );

    // Second try should fail at verification
    let response = TestServer::generate_proof(&connected, challenge.to_vec()).await;
    assert_eq!(
        response.kind,
        Some(service_response::Kind::GenProof(GenProofResponse {
            status: GenProofStatus::Error as _,
            proof: None,
            metadata: None
        }))
    );

    client_handle.abort();
    let _ = client_handle.await;
}

#[tokio::test]
async fn test_broken_request_no_kind() {
    let mut test_server = TestServer::new(None).await;

    let mut service = MockPostService::new();
    service
        .expect_gen_proof()
        .returning(|_| Err(eyre::eyre!("failed to generate proof")));

    let service = Arc::new(service);
    let client = test_server.create_client(service.clone());
    let client_handle = tokio::spawn(client.run(None, std::time::Duration::from_secs(1)));

    let connected = test_server.connected.recv().await.unwrap();

    let (response, resp_rx) = oneshot::channel();
    connected
        .send(TestNodeRequest {
            request: NodeRequest { kind: None },
            response,
        })
        .await
        .unwrap();

    let response = resp_rx.await.unwrap();
    assert_eq!(
        response.kind,
        Some(service_response::Kind::GenProof(GenProofResponse {
            status: GenProofStatus::Error as _,
            proof: None,
            metadata: None,
        }))
    );

    client_handle.abort();
    let _ = client_handle.await;
}

#[rstest]
#[case(None)]
#[case(Some([0xFF; 32]))]
#[tokio::test]
async fn test_get_metadata(#[case] vrf_difficulty: Option<[u8; 32]>) {
    let datadir = tempdir().unwrap();
    let cfg = post::config::ProofConfig {
        k1: 23,
        k2: 32,
        pow_difficulty: [0xFF; 32],
    };

    let scrypt = post::config::ScryptParams::new(2, 1, 1);

    let metadata = CpuInitializer::new(scrypt)
        .initialize(
            datadir.path(),
            &[77; 32],
            &[0u8; 32],
            256 * 16,
            31,
            256 * 16,
            vrf_difficulty,
        )
        .unwrap();

    let mut test_server = TestServer::new(None).await;

    let service = post_service::service::PostService::new(
        datadir.path().into(),
        cfg,
        scrypt,
        16,
        post::config::Cores::Any(1),
        post::pow::randomx::RandomXFlag::get_recommended_flags(),
        None,
    )
    .unwrap();

    let client = test_server.create_client(Arc::new(service));
    let client_handle = tokio::spawn(client.run(None, std::time::Duration::from_secs(1)));
    let connected = test_server.connected.recv().await.unwrap();

    let response = TestServer::request_metadata(&connected).await;
    assert_eq!(
        response.kind,
        Some(service_response::Kind::Metadata(MetadataResponse {
            meta: Some(Metadata {
                node_id: metadata.node_id.to_vec(),
                commitment_atx_id: metadata.commitment_atx_id.to_vec(),
                num_units: metadata.num_units,
                labels_per_unit: metadata.labels_per_unit,
                nonce: metadata.nonce,
            }),
        }))
    );

    client_handle.abort();
    let _ = client_handle.await;
}
