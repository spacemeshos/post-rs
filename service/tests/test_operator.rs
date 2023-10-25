use core::panic;
use std::{sync::Arc, time::Duration};

use tokio::{net::TcpListener, time::sleep};

use post::{
    initialize::{CpuInitializer, Initialize},
    pow::randomx::RandomXFlag,
    ScryptParams,
};
use post_service::{
    client::spacemesh_v1::{service_response, GenProofStatus},
    operator::{
        spacemesh_v1::{
            post_service_operator_client::PostServiceOperatorClient,
            post_service_status_response::Status, PostServiceStatusRequest,
        },
        OperatorServer,
    },
};

#[allow(dead_code)]
mod server;
use server::TestServer;

#[tokio::test]
async fn test_gen_proof_in_progress() {
    // Initialize some data
    let datadir = tempfile::tempdir().unwrap();

    let cfg = post::config::Config {
        k1: 8,
        k2: 4,
        k3: 4,
        pow_difficulty: [0xFF; 32],
        scrypt: ScryptParams::new(0, 0, 0),
    };

    CpuInitializer::new(cfg.scrypt)
        .initialize(datadir.path(), &[0xBE; 32], &[0xCE; 32], 256, 4, 256, None)
        .unwrap();

    let pow_flags = RandomXFlag::get_recommended_flags();

    let service = Arc::new(
        post_service::service::PostService::new(datadir.into_path(), cfg, 16, 1, pow_flags)
            .unwrap(),
    );

    let mut test_server = TestServer::new().await;
    let client = test_server.create_client(service.clone());
    tokio::spawn(client.run());

    // Create operator server and client
    let listener = TcpListener::bind("localhost:0").await.unwrap();
    let operator_addr = format!("http://{}", listener.local_addr().unwrap());
    tokio::spawn(OperatorServer::run(listener, service));
    let mut client = PostServiceOperatorClient::connect(operator_addr)
        .await
        .unwrap();

    // It starts in idle state
    let response = client.status(PostServiceStatusRequest {}).await.unwrap();
    assert_eq!(response.into_inner().status(), Status::Idle);

    // It transforms to Proving when a proof generation starts
    let connected = test_server.connected.recv().await.unwrap();
    TestServer::generate_proof(&connected, vec![0xCA; 32]).await;
    let response = client.status(PostServiceStatusRequest {}).await.unwrap();
    assert_eq!(response.into_inner().status(), Status::Proving);

    loop {
        let response = TestServer::generate_proof(&connected, vec![0xCA; 32]).await;
        if let Some(service_response::Kind::GenProof(resp)) = response.kind {
            match resp.status() {
                GenProofStatus::Ok => {
                    if resp.proof.is_some() {
                        break;
                    }
                }
                _ => {
                    panic!("Got error response from GenProof");
                }
            }
        } else {
            unreachable!();
        }
        sleep(Duration::from_millis(10)).await;
    }

    // It transforms back to Idle when the proof generation finishes
    let response = client.status(PostServiceStatusRequest {}).await.unwrap();
    assert_eq!(response.into_inner().status(), Status::Idle);
}
