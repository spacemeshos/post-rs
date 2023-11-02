use std::sync::Arc;

use axum::{extract::State, Json};
use axum::{routing::post, Router};
use ed25519_dalek::{Signer, SigningKey};
use post::pow::randomx::{PoW, RandomXFlag};
use post::verification::{Verifier, VerifyingParams};
use serde::{Deserialize, Serialize};
use serde_with::{base64::Base64, serde_as};
use tracing::instrument;

#[derive(Debug, Deserialize)]
struct CertifyRequest {
    proof: post::prove::Proof<'static>,
    metadata: post::metadata::ProofMetadata,
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
    Json(request): Json<CertifyRequest>,
) -> Result<Json<CertifyResponse>, String> {
    tracing::debug!("certifying");

    let pub_key = request.metadata.node_id;
    let s = state.clone();
    let result = tokio::task::spawn_blocking(move || {
        s.verifier.verify(
            &request.proof,
            &request.metadata,
            VerifyingParams::new(&request.metadata, &s.cfg).unwrap(),
        )
    })
    .await;
    match result {
        Err(e) => return Err(format!("internal error verifying proof: {e:?}")),
        Ok(Err(e)) => return Err(format!("invalid proof: {e:?}")),
        _ => {}
    }

    // Sign the nodeID
    let response = CertifyResponse {
        signature: state.signer.sign(&pub_key).to_vec(),
        pub_key: state.signer.verifying_key().to_bytes().to_vec(),
    };
    Ok(Json(response))
}

struct AppState {
    verifier: Verifier,
    cfg: post::config::Config,
    signer: SigningKey,
}

pub fn new(cfg: post::config::Config, signer: SigningKey) -> Router {
    let state = AppState {
        verifier: Verifier::new(Box::new(
            PoW::new(RandomXFlag::get_recommended_flags()).expect("creating RandomX PoW verifier"),
        )),
        cfg,
        signer,
    };

    Router::new()
        .route("/certify", post(certify))
        .with_state(Arc::new(state))
}
