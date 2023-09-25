use std::pin::Pin;

use tokio::sync::{broadcast, mpsc, oneshot};
use tokio_stream::{Stream, StreamExt};
use tonic::{Request, Response, Status};

use spacemesh_v1::post_service_server::PostService;
use spacemesh_v1::{NodeRequest, ServiceResponse};
pub mod spacemesh_v1 {
    tonic::include_proto!("spacemesh.v1");
}

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
