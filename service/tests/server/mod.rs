//! Simple server implementation for tests
//!
//! Accepts connections from the service clients and
//! allows the tests to interact with it via a channel
//! or the provided methods.

use std::pin::Pin;

use post_service::client::{PostService, ServiceClient};
use tokio::net::TcpListener;
use tokio::sync::{broadcast, mpsc, oneshot};
use tokio_stream::wrappers::TcpListenerStream;
use tokio_stream::{Stream, StreamExt};
use tonic::transport::Server;
use tonic::{Request, Response, Status};

use post_service::client::spacemesh_v1::{
    node_request, post_service_server, GenProofRequest, MetadataRequest, NodeRequest,
    ServiceResponse,
};

#[derive(Debug)]
pub struct TestNodeRequest {
    pub request: NodeRequest,
    pub response: oneshot::Sender<ServiceResponse>,
}

#[derive(Debug)]
pub struct TestPostService {
    registered: broadcast::Sender<mpsc::Sender<TestNodeRequest>>,
}

impl TestPostService {
    pub fn new() -> Self {
        Self {
            registered: broadcast::channel(1).0,
        }
    }
    pub fn register_for_connections(
        &mut self,
    ) -> broadcast::Receiver<mpsc::Sender<TestNodeRequest>> {
        self.registered.subscribe()
    }
}

impl Default for TestPostService {
    fn default() -> Self {
        Self::new()
    }
}

#[tonic::async_trait]
impl post_service_server::PostService for TestPostService {
    type RegisterStream = Pin<Box<dyn Stream<Item = Result<NodeRequest, Status>> + Send + 'static>>;

    async fn register(
        &self,
        request: Request<tonic::Streaming<ServiceResponse>>,
    ) -> Result<Response<Self::RegisterStream>, Status> {
        log::info!("post service connected: {:?}", request);
        let mut stream = request.into_inner();

        let (tx, mut rx) = tokio::sync::mpsc::channel(1);
        self.registered
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

pub struct TestServer {
    pub connected: broadcast::Receiver<mpsc::Sender<TestNodeRequest>>,
    handle: tokio::task::JoinHandle<Result<(), tonic::transport::Error>>,
    addr: std::net::SocketAddr,
}

impl Drop for TestServer {
    fn drop(&mut self) {
        self.handle.abort();
    }
}

impl TestServer {
    pub async fn new() -> Self {
        let mut test_node = TestPostService::new();
        let reg = test_node.register_for_connections();

        let listener = TcpListener::bind("[::1]:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        let handle = tokio::spawn(
            Server::builder()
                .add_service(post_service_server::PostServiceServer::new(test_node))
                .serve_with_incoming(TcpListenerStream::new(listener)),
        );

        TestServer {
            connected: reg,
            handle,
            addr,
        }
    }

    pub fn create_client<S>(&self, service: S) -> ServiceClient<S>
    where
        S: PostService,
    {
        ServiceClient::new(format!("http://{}", self.addr), None, service).unwrap()
    }

    pub async fn generate_proof(
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

    pub async fn request_metadata(connected: &mpsc::Sender<TestNodeRequest>) -> ServiceResponse {
        let (response, resp_rx) = oneshot::channel();
        connected
            .send(TestNodeRequest {
                request: NodeRequest {
                    kind: Some(node_request::Kind::Metadata(MetadataRequest {})),
                },
                response,
            })
            .await
            .unwrap();
        resp_rx.await.unwrap()
    }
}
