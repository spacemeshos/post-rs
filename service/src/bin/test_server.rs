use std::fs::read_to_string;
use std::time::Duration;

use clap::Parser;
use eyre::Context;
use tokio::sync::oneshot;
use tokio::time::sleep;
use tonic::transport::Server;
use tonic::transport::{Certificate, Identity, ServerTlsConfig};

use post_service::test_server::spacemesh_v1::post_service_server::PostServiceServer;
use post_service::test_server::spacemesh_v1::{
    node_request, service_response, GenProofRequest, GenProofStatus, NodeRequest,
};
use post_service::test_server::{TestNodeRequest, TestPostService};

/// Post Service test server
#[derive(Parser, Debug)]
#[command(version, about)]
struct Cli {
    #[command(flatten, next_help_heading = "TLS configuration")]
    tls: Option<post_service::tls_config::Tls>,
}

#[tokio::main]
async fn main() -> eyre::Result<()> {
    let args = Cli::parse();

    let env = env_logger::Env::default().filter_or("RUST_LOG", "info");
    env_logger::init_from_env(env);

    let server = Server::builder();
    let mut server = if let Some(tls) = args.tls {
        log::info!(
            "configuring TLS: CA cert: {}, cert: {}, key: {}",
            tls.ca_cert.display(),
            tls.cert.display(),
            tls.key.display(),
        );
        let ca_cert = read_to_string(tls.ca_cert)?;
        let cert = read_to_string(tls.cert)?;
        let key = read_to_string(tls.key)?;

        let tls = ServerTlsConfig::new()
            .identity(Identity::from_pem(cert, key))
            .client_ca_root(Certificate::from_pem(ca_cert));

        server.tls_config(tls).wrap_err("setting up mTLS")?
    } else {
        log::info!("not configuring TLS");
        server
    };

    let mut test_node = TestPostService::new();
    let mut reg = test_node.register_for_connections();

    let router = server.add_service(PostServiceServer::new(test_node));

    let _handle = tokio::spawn(router.serve("[::1]:50051".parse()?));

    loop {
        // wait for the connection to be established
        let tx = reg.recv().await?;

        loop {
            let (resp_tx, resp_rx) = oneshot::channel();
            if let Err(e) = tx
                .send(TestNodeRequest {
                    request: NodeRequest {
                        kind: Some(node_request::Kind::GenProof(GenProofRequest {
                            challenge: vec![0xCA; 32],
                        })),
                    },
                    response: resp_tx,
                })
                .await
            {
                log::error!("post service disconnected: {e:?}");
                break;
            }

            let resp = resp_rx.await?;
            match resp.kind {
                Some(service_response::Kind::GenProof(resp)) => {
                    log::debug!("Got GenProof response: {resp:?}");
                    match resp.status() {
                        GenProofStatus::Ok => {
                            if let Some(proof) = resp.proof {
                                log::info!("POST proof generation finished, proof: {:?}", proof);
                                // break;
                            }
                            log::info!("POST proof generation in progress");
                        }
                        GenProofStatus::Unspecified => {
                            log::error!("unspecified status");
                        }
                        GenProofStatus::Error => {
                            log::error!("POST proof generation error");
                            break;
                        }
                    }
                }
                _ => {
                    log::error!("Got unexpected response: {:?}", resp);
                }
            }
            sleep(Duration::from_secs(5)).await;
        }
    }
}
