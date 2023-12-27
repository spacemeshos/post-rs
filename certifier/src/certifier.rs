use std::sync::Arc;

use axum::http::StatusCode;
use axum::{extract::State, Json};
use axum::{routing::post, Router};
use ed25519_dalek::{Signer, SigningKey};
use post::config::{InitConfig, ProofConfig};
use post::pow::randomx::PoW;
use post::verification::{Mode, Verifier};
use serde::{Deserialize, Serialize};
use serde_with::{base64::Base64, serde_as};
use tracing::instrument;

use crate::configuration::RandomXMode;

#[derive(Debug, Deserialize, Serialize)]
pub struct CertifyRequest {
    pub proof: post::prove::Proof<'static>,
    pub metadata: post::metadata::ProofMetadata,
}

#[serde_as]
#[derive(Debug, Serialize)]
struct CertifyResponse {
    #[serde_as(as = "Base64")]
    signature: Vec<u8>,
    #[serde_as(as = "Base64")]
    pub_key: Vec<u8>,
}

#[instrument(skip(state))]
async fn certify(
    State(state): State<Arc<AppState>>,
    Json(req): Json<CertifyRequest>,
) -> Result<Json<CertifyResponse>, (StatusCode, String)> {
    tracing::debug!("certifying");

    let pub_key = req.metadata.node_id;
    let my_id = state.signer.verifying_key().to_bytes();
    let s = state.clone();

    let result = tokio::task::spawn_blocking(move || {
        s.verifier.verify(
            &req.proof,
            &req.metadata,
            &s.cfg,
            &s.init_cfg,
            &my_id,
            Mode::All,
        )
    })
    .await
    .map_err(|e| {
        tracing::error!("internal error verifying proof: {e:?}");
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            "error verifying proof".into(),
        )
    })?;

    result.map_err(|e| (StatusCode::FORBIDDEN, format!("invalid proof: {e:?}")))?;

    // Sign the nodeID
    let response = CertifyResponse {
        signature: state.signer.sign(&pub_key).to_vec(),
        pub_key: my_id.to_vec(),
    };
    Ok(Json(response))
}

struct AppState {
    verifier: Verifier,
    cfg: ProofConfig,
    init_cfg: InitConfig,
    signer: SigningKey,
}

pub fn new(
    cfg: ProofConfig,
    init_cfg: InitConfig,
    signer: SigningKey,
    randomx_mode: RandomXMode,
) -> Router {
    let state = AppState {
        verifier: Verifier::new(Box::new(
            PoW::new(randomx_mode.into()).expect("creating RandomX PoW verifier"),
        )),
        cfg,
        init_cfg,
        signer,
    };

    Router::new()
        .route("/certify", post(certify))
        .with_state(Arc::new(state))
}
