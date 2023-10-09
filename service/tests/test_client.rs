use std::{borrow::Cow, sync::Arc};

use tokio::{
    net::TcpListener,
    sync::{broadcast, mpsc, oneshot},
};
use tokio_stream::wrappers::TcpListenerStream;
use tonic::transport::{Error, Server};

use post::{metadata::ProofMetadata, prove::Proof};
use post_service::{
    client::{MockPostService, PostService, ServiceClient},
    service::ProofGenState,
    test_server::{
        spacemesh_v1::{
            node_request, post_service_server::PostServiceServer, service_response,
            GenProofRequest, GenProofResponse, GenProofStatus, NodeRequest, ServiceResponse,
        },
        TestNodeRequest, TestPostService,
    },
};

struct TestServer {
    connected: broadcast::Receiver<mpsc::Sender<TestNodeRequest>>,
    handle: tokio::task::JoinHandle<Result<(), Error>>,
    addr: std::net::SocketAddr,
}

impl Drop for TestServer {
    fn drop(&mut self) {
        self.handle.abort();
    }
}

impl TestServer {
    async fn new() -> Self {
        let mut test_node = TestPostService::new();
        let reg = test_node.register_for_connections();

        let listener = TcpListener::bind("[::1]:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        let server = tokio::spawn(
            Server::builder()
                .add_service(PostServiceServer::new(test_node))
                .serve_with_incoming(TcpListenerStream::new(listener)),
        );

        TestServer {
            connected: reg,
            handle: server,
            addr,
        }
    }

    fn create_client<S>(&self, service: S) -> ServiceClient<S>
    where
        S: PostService,
    {
        ServiceClient::new(
            format!("http://{}", self.addr),
            std::time::Duration::from_secs(1),
            None,
            service,
        )
        .unwrap()
    }

    async fn generate_proof(
        connected: &mpsc::Sender<TestNodeRequest>,
        challenge: Vec<u8>,
    ) -> ServiceResponse {
        let (response, resp_rx) = oneshot::channel();
        connected
            .send(TestNodeRequest {
                request: NodeRequest {
                    kind: Some(node_request::Kind::GenProof(GenProofRequest { challenge })),
                },
                response,
            })
            .await
            .unwrap();
        resp_rx.await.unwrap()
    }
}

#[tokio::test]
async fn test_registers() {
    let mut test_server = TestServer::new().await;
    let client = test_server.create_client(Arc::new(MockPostService::new()));
    let client_handle = tokio::spawn(client.run());

    // Check if client registered
    test_server.connected.recv().await.unwrap();
    client_handle.abort();
    let _ = client_handle.await;
}

#[tokio::test]
async fn test_gen_proof_in_progress() {
    let mut test_server = TestServer::new().await;

    let mut service = MockPostService::new();
    service
        .expect_gen_proof()
        .returning(|_| Ok(ProofGenState::InProgress));
    let service = Arc::new(service);
    let client = test_server.create_client(service.clone());
    let client_handle = tokio::spawn(client.run());

    let connected = test_server.connected.recv().await.unwrap();
    let response = TestServer::generate_proof(&connected, vec![0xCA; 32]).await;

    let _exp_status = GenProofStatus::Ok as i32;
    assert!(matches!(
        response.kind.unwrap(),
        service_response::Kind::GenProof(GenProofResponse {
            status: _exp_status,
            proof: None,
            metadata: None
        })
    ));

    client_handle.abort();
    let _ = client_handle.await;
}

#[tokio::test]
async fn test_gen_proof_failed() {
    let mut test_server = TestServer::new().await;

    let mut service = MockPostService::new();
    service
        .expect_gen_proof()
        .returning(|_| Err(eyre::eyre!("failed to generate proof")));

    let service = Arc::new(service);
    let client = test_server.create_client(service.clone());
    let client_handle = tokio::spawn(client.run());

    let connected = test_server.connected.recv().await.unwrap();
    let response = TestServer::generate_proof(&connected, vec![0xCA; 32]).await;

    let _exp_status = GenProofStatus::Error as i32;
    assert!(matches!(
        response.kind.unwrap(),
        service_response::Kind::GenProof(GenProofResponse {
            status: _exp_status,
            proof: None,
            metadata: None
        })
    ));

    client_handle.abort();
    let _ = client_handle.await;
}

#[tokio::test]
async fn test_gen_proof_finished() {
    let mut test_server = TestServer::new().await;

    let challenge = &[0xCA; 32];
    let indices = &[0xAA; 32];
    let node_id = &[0xBB; 32];
    let commitment_atx_id = &[0xCC; 32];

    let mut service = MockPostService::new();
    service.expect_gen_proof().returning(move |c| {
        assert_eq!(c.as_slice(), challenge);
        Ok(ProofGenState::Finished {
            proof: Proof {
                nonce: 1,
                indices: Cow::Owned(indices.to_vec()),
                pow: 7,
            },
            metadata: ProofMetadata {
                node_id: *node_id,
                commitment_atx_id: *commitment_atx_id,
                challenge: *challenge,
                num_units: 4,
                labels_per_unit: 256,
            },
        })
    });
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
    let client_handle = tokio::spawn(client.run());

    let connected = test_server.connected.recv().await.unwrap();

    let response = TestServer::generate_proof(&connected, challenge.to_vec()).await;
    let _exp_status = GenProofStatus::Ok as i32;
    let _exp_proof = post_service::test_server::spacemesh_v1::Proof {
        nonce: 1,
        indices: indices.to_vec(),
        pow: 7,
    };
    let _exp_metadata = post_service::test_server::spacemesh_v1::ProofMetadata {
        challenge: challenge.to_vec(),
        node_id: Some(post_service::test_server::spacemesh_v1::SmesherId {
            id: node_id.to_vec(),
        }),
        commitment_atx_id: Some(post_service::test_server::spacemesh_v1::ActivationId {
            id: commitment_atx_id.to_vec(),
        }),
        num_units: 7,
        labels_per_unit: 256,
    };

    assert!(matches!(
        response.kind.unwrap(),
        service_response::Kind::GenProof(GenProofResponse {
            status: _exp_status,
            proof: Some(_exp_proof),
            metadata: Some(_exp_metadata),
        })
    ));

    // Second try should fail at verification
    let response = TestServer::generate_proof(&connected, challenge.to_vec()).await;
    let _exp_status = GenProofStatus::Error as i32;
    assert!(matches!(
        response.kind.unwrap(),
        service_response::Kind::GenProof(GenProofResponse {
            status: _exp_status,
            proof: None,
            metadata: None
        })
    ));

    client_handle.abort();
    let _ = client_handle.await;
}

#[tokio::test]
async fn test_broken_request_no_kind() {
    let mut test_server = TestServer::new().await;

    let mut service = MockPostService::new();
    service
        .expect_gen_proof()
        .returning(|_| Err(eyre::eyre!("failed to generate proof")));

    let service = Arc::new(service);
    let client = test_server.create_client(service.clone());
    let client_handle = tokio::spawn(client.run());

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
    let _exp_status = GenProofStatus::Error as i32;
    assert!(matches!(
        response.kind.unwrap(),
        service_response::Kind::GenProof(GenProofResponse {
            status: _exp_status,
            proof: None,
            metadata: None
        })
    ));

    client_handle.abort();
    let _ = client_handle.await;
}
