//! Operator service for controlling the post service.
//!
//! It exposes a GRPC API defined in `spacemesh.v1.post.proto`.
//! Allows to query the status of the post service.

use std::sync::Arc;

use tokio::net::TcpListener;
use tokio_stream::wrappers::TcpListenerStream;
use tonic::{transport::Server, Request, Response, Status};

use post_v1::operator_service_server::OperatorServiceServer;
use post_v1::{OperatorStatusRequest, OperatorStatusResponse};

pub mod post_v1 {
    tonic::include_proto!("post.v1");
    pub(crate) const FILE_DESCRIPTOR_SET: &[u8] =
        tonic::include_file_descriptor_set!("service_descriptor");
}

pub enum ServiceState {
    Idle,
    Proving,
}

#[mockall::automock]
/// The Service trait provides funcionality required by the OperatorService.
pub trait Service {
    /// Returns the current state of the service.
    fn status(&self) -> ServiceState;
}

#[derive(Debug, Default)]
pub struct OperatorService<S: Service> {
    service: Arc<S>,
}

#[tonic::async_trait]
impl<S: Service + Sync + Send + 'static> post_v1::operator_service_server::OperatorService
    for OperatorService<S>
{
    async fn status(
        &self,
        request: Request<OperatorStatusRequest>,
    ) -> Result<Response<OperatorStatusResponse>, Status> {
        log::debug!("got a request from {:?}", request.remote_addr());

        let status = match self.service.status() {
            ServiceState::Idle => post_v1::operator_status_response::Status::Idle,
            ServiceState::Proving => post_v1::operator_status_response::Status::Proving,
        };

        Ok(Response::new(OperatorStatusResponse {
            status: status as _,
        }))
    }
}

#[derive(Debug, Default)]
pub struct OperatorServer {}

impl OperatorServer {
    pub async fn run<S>(listener: TcpListener, service: Arc<S>) -> eyre::Result<()>
    where
        S: Service + Sync + Send + 'static,
    {
        log::info!("running operator service on {}", listener.local_addr()?);

        let reflection_service = tonic_reflection::server::Builder::configure()
            .register_encoded_file_descriptor_set(post_v1::FILE_DESCRIPTOR_SET)
            .build()?;

        let operator_service = OperatorServiceServer::new(OperatorService { service });

        Server::builder()
            .add_service(reflection_service)
            .add_service(operator_service)
            .serve_with_incoming(TcpListenerStream::new(listener))
            .await
            .map_err(|e| eyre::eyre!("failed to serve: {e}"))
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use tokio::net::TcpListener;

    use super::post_v1::operator_service_client::OperatorServiceClient;
    use super::post_v1::operator_status_response::Status;
    use super::post_v1::OperatorStatusRequest;

    #[tokio::test]
    async fn test_status() {
        let mut svc = super::MockService::new();
        svc.expect_status()
            .once()
            .returning(|| super::ServiceState::Idle);
        svc.expect_status()
            .once()
            .returning(|| super::ServiceState::Proving);

        let listener = TcpListener::bind("localhost:0").await.unwrap();
        let addr: std::net::SocketAddr = listener.local_addr().unwrap();

        tokio::spawn(super::OperatorServer::run(listener, Arc::new(svc)));

        let mut client = OperatorServiceClient::connect(format!("http://{addr}"))
            .await
            .unwrap();

        let response = client.status(OperatorStatusRequest {}).await.unwrap();
        assert_eq!(response.into_inner().status(), Status::Idle);

        let response = client.status(OperatorStatusRequest {}).await.unwrap();
        assert_eq!(response.into_inner().status(), Status::Proving);
    }
}
