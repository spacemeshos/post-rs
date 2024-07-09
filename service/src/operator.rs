//! Operator service for controlling the post service.
//!
//! It exposes an HTTP API.
//! Allows to query the status of the post service.

use std::{ops::Range, sync::Arc};

use axum::{extract::State, routing::get, Json, Router};
use serde::{Deserialize, Serialize};
use tokio::net::TcpListener;

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
/// The Post-service state
pub enum ServiceState {
    /// The service is idle.
    Idle,
    /// The service is currently proving.
    Proving {
        /// The range of nonces being proven in the current data pass.
        nonces: Range<u32>,
        /// The position (in bytes) in the POST data that is already checked.
        position: u64,
    },
    /// Finished proving, but the proof has not been fetched yet.
    DoneProving,
}

#[mockall::automock]
/// The Service trait provides funcionality required by the OperatorService.
pub trait Service {
    /// Returns the current state of the service.
    fn status(&self) -> ServiceState;
}

pub async fn run<S>(listener: TcpListener, service: Arc<S>) -> eyre::Result<()>
where
    S: Service + Sync + Send + 'static,
{
    log::info!("running operator service on {}", listener.local_addr()?);

    let app = Router::new()
        .route("/status", get(status))
        .with_state(service);

    axum::serve(listener, app)
        .await
        .map_err(|e| eyre::eyre!("failed to serve: {e}"))
}

async fn status<S>(State(service): State<Arc<S>>) -> Json<ServiceState>
where
    S: Service + Sync + Send + 'static,
{
    Json(service.status())
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use tokio::net::TcpListener;

    #[tokio::test]
    async fn test_status() {
        let mut svc = super::MockService::new();
        svc.expect_status()
            .once()
            .returning(|| super::ServiceState::Idle);
        let proving_status = super::ServiceState::Proving {
            nonces: 0..64,
            position: 1000,
        };
        svc.expect_status()
            .once()
            .return_const(proving_status.clone());

        let listener = TcpListener::bind("localhost:0").await.unwrap();
        let addr: std::net::SocketAddr = listener.local_addr().unwrap();
        let url = format!("http://{addr}/status");

        tokio::spawn(super::run(listener, Arc::new(svc)));

        let resp = reqwest::get(&url).await.unwrap();
        assert_eq!(super::ServiceState::Idle, resp.json().await.unwrap());

        let resp = reqwest::get(&url).await.unwrap();
        assert_eq!(proving_status, resp.json().await.unwrap());
    }
}
