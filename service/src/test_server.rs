mod tls_config;

use std::fs::read_to_string;
use std::pin::Pin;
use std::sync::Mutex;
use std::time::Duration;

use clap::Parser;
use eyre::Context;
use tokio::sync::{broadcast, mpsc, oneshot};
use tokio::time::sleep;
use tokio_stream::{Stream, StreamExt};
use tonic::transport::{Certificate, Identity, ServerTlsConfig};
use tonic::{transport::Server, Request, Response, Status};

use spacemesh_v1::post_service_server::{PostService, PostServiceServer};
use spacemesh_v1::{NodeRequest, ServiceResponse};

use spacemesh_v1::node_request;
use spacemesh_v1::GenProofRequest;
pub mod spacemesh_v1 {
    tonic::include_proto!("spacemesh.v1");
}

struct TestNodeRequest {
    request: NodeRequest,
    response: oneshot::Sender<ServiceResponse>,
}

#[derive(Debug)]
pub struct TestPostService {
    registered: Mutex<broadcast::Sender<mpsc::Sender<TestNodeRequest>>>,
}

impl TestPostService {
    fn new() -> Self {
        Self {
            registered: Mutex::new(broadcast::channel(1).0),
        }
    }
    fn wait_for_connection(&mut self) -> broadcast::Receiver<mpsc::Sender<TestNodeRequest>> {
        self.registered.lock().unwrap().subscribe()
    }
}

#[tonic::async_trait]
impl PostService for TestPostService {
    type RegisterStream = Pin<Box<dyn Stream<Item = Result<NodeRequest, Status>> + Send + 'static>>;

    async fn register(
        &self,
        request: Request<tonic::Streaming<ServiceResponse>>,
    ) -> Result<Response<Self::RegisterStream>, Status> {
        log::info!("Post Service connected: {:?}", request);
        let mut stream = request.into_inner();

        let (tx, mut rx) = tokio::sync::mpsc::channel(1);
        self.registered
            .lock()
            .unwrap()
            .send(tx)
            .expect("nobody is interested in post service registered");

        let output = async_stream::try_stream! {
            while let Some(req) = rx.recv().await {
                yield req.request;
                if let Some(Ok(response)) = stream.next().await {
                    _ = req.response.send(response);
                } else {
                    log::info!("stream closed");
                    return;
                }
            }
        };

        Ok(Response::new(Box::pin(output) as Self::RegisterStream))
    }
}

/// Post Service test server
#[derive(Parser, Debug)]
#[command(version, about)]
struct Cli {
    #[command(flatten, next_help_heading = "TLS configuration")]
    tls: Option<tls_config::Tls>,
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
    let mut reg = test_node.wait_for_connection();

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
                Some(spacemesh_v1::service_response::Kind::GenProof(resp)) => {
                    log::debug!("Got GenProof response: {resp:?}");
                    match resp.status() {
                        spacemesh_v1::GenProofStatus::Ok => {
                            if let Some(proof) = resp.proof {
                                log::info!("POST proof generation finished, proof: {:?}", proof);
                                break;
                            }
                            log::info!("POST proof generation in progress");
                        }
                        spacemesh_v1::GenProofStatus::Unspecified => {
                            log::error!("unspecified status");
                        }
                        spacemesh_v1::GenProofStatus::Error => {
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

    // _ = handle.await?;
    // Ok(())
}
