//! Operator service for controlling the post service.
//!
//! It exposes an HTTP API.
//! Allows to query the status of the post service.

use std::sync::Arc;

use axum::{extract::State, routing::get, Json, Router};
use serde::{Deserialize, Serialize};
use tokio::net::TcpListener;

#[derive(Debug, Serialize, Deserialize)]
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
        svc.expect_status()
            .once()
            .returning(|| super::ServiceState::Proving);

        let listener = TcpListener::bind("localhost:0").await.unwrap();
        let addr: std::net::SocketAddr = listener.local_addr().unwrap();

        tokio::spawn(super::run(listener, Arc::new(svc)));

        let url = format!("http://{addr}/status");
        let resp = reqwest::get(&url).await.unwrap();
        let status: super::ServiceState = resp.json().await.unwrap();
        assert!(matches!(status, super::ServiceState::Idle));

        let resp = reqwest::get(&url)
            .await
            .unwrap()
            .error_for_status()
            .unwrap();
        let status: super::ServiceState = resp.json().await.unwrap();
        assert!(matches!(status, super::ServiceState::Proving));
    }
}
