use std::sync::Arc;

use axum::http::StatusCode;
use axum::{extract::State, Json};
use axum::{routing::post, Router};
use chrono::Utc;
use ed25519_dalek::{Signature, Signer, SigningKey};
use parity_scale_codec::{Compact, Decode, Encode};
use post::config::{InitConfig, ProofConfig};
use post::pow::randomx::PoW;
use post::verification::Mode;
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
#[derive(Debug, Serialize, Deserialize)]
pub struct CertifyResponse {
    /// The certificate as scale-encoded `Certificate` struct
    #[serde_as(as = "Base64")]
    pub certificate: Vec<u8>,
    /// Signature of the certificate
    #[serde_as(as = "Base64")]
    pub signature: Vec<u8>,
    /// The public key of the certifier that signed the certificate
    #[serde_as(as = "Base64")]
    pub pub_key: Vec<u8>,
}

#[derive(Debug, Decode, Encode)]
pub struct Certificate {
    // ID of the node being certified
    pub pub_key: Vec<u8>,
    /// Unix timestamp
    pub expiration: Option<Compact<u64>>,
}

#[instrument(skip(state))]
async fn certify(
    State(state): State<Arc<Certifier>>,
    Json(req): Json<CertifyRequest>,
) -> Result<Json<CertifyResponse>, (StatusCode, String)> {
    tracing::debug!("certifying");

    let s = state.clone();
    let result = tokio::task::spawn_blocking(move || s.certify(&req.proof, &req.metadata))
        .await
        .map_err(|e| {
            tracing::error!("internal error verifying proof: {e:?}");
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                "error verifying proof".into(),
            )
        })?;

    match result {
        Ok(result) => {
            let response = CertifyResponse {
                certificate: result.0.to_vec(),
                signature: result.1.to_vec(),
                pub_key: state.signer.verifying_key().to_bytes().to_vec(),
            };
            Ok(Json(response))
        }
        Err(e) => {
            return Err((StatusCode::FORBIDDEN, format!("invalid proof: {e:?}")));
        }
    }
}

#[mockall::automock]
trait Verifier {
    fn verify(
        &self,
        proof: &post::prove::Proof<'static>,
        metadata: &post::metadata::ProofMetadata,
    ) -> Result<(), String>;
}

struct PostVerifier {
    verifier: post::verification::Verifier,
    cfg: ProofConfig,
    init_cfg: InitConfig,
}

impl Verifier for PostVerifier {
    fn verify(
        &self,
        proof: &post::prove::Proof<'_>,
        metadata: &post::metadata::ProofMetadata,
    ) -> Result<(), String> {
        self.verifier
            .verify(proof, metadata, &self.cfg, &self.init_cfg, Mode::All)
            .map_err(|e| format!("{e:?}"))
    }
}

struct Certifier {
    verifier: Arc<dyn Verifier + Send + Sync>,
    signer: SigningKey,
    expiry: Option<chrono::Duration>,
}

impl Certifier {
    pub fn certify(
        &self,
        proof: &post::prove::Proof<'static>,
        metadata: &post::metadata::ProofMetadata,
    ) -> Result<(Vec<u8>, Signature), String> {
        self.verifier.verify(proof, metadata)?;

        let cert = self.create_certificate(&metadata.node_id);
        let cert_encoded = cert.encode();
        let signature = self.signer.sign(&cert_encoded);

        Ok((cert_encoded.to_vec(), signature))
    }

    fn create_certificate(&self, id: &[u8; 32]) -> Certificate {
        let expiration = self.expiry.map(|exp| (Utc::now() + exp).timestamp() as u64);
        Certificate {
            pub_key: id.to_vec(),
            expiration: expiration.map(Compact),
        }
    }
}

pub fn new(
    cfg: ProofConfig,
    init_cfg: InitConfig,
    signer: SigningKey,
    randomx_mode: RandomXMode,
    expiry: Option<chrono::Duration>,
) -> Router {
    let verifier = Arc::new(PostVerifier {
        verifier: post::verification::Verifier::new(Box::new(
            PoW::new(randomx_mode.into()).expect("creating RandomX PoW verifier"),
        )),
        cfg,
        init_cfg,
    });
    let certifier = Certifier {
        verifier,
        signer,
        expiry,
    };

    Router::new()
        .route("/certify", post(certify))
        .with_state(Arc::new(certifier))
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use super::{Certificate, Certifier, MockVerifier};
    use chrono::{DateTime, Duration, Utc};
    use ed25519_dalek::SigningKey;
    use parity_scale_codec::{Compact, Decode, Encode};
    use post::{metadata::ProofMetadata, prove::Proof};
    #[test]
    fn serialize() {
        let cert = Certificate {
            pub_key: vec![
                1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 1, 2, 3, 4, 5, 6, 7, 8, 9,
                10, 11, 12, 13, 14, 15, 16,
            ],
            expiration: Some(Compact(
                DateTime::parse_from_rfc3339("1996-12-19T16:39:57-08:00")
                    .unwrap()
                    .to_utc()
                    .timestamp() as u64,
            )),
        };
        let b = &cert.encode();
        println!("{}", base64::encode(b));

        let val: u64 = 0x123456789abcdef0;

        let compact = Compact(val);
        let encoded = compact.encode();
        println!("{}", base64::encode(&encoded));
    }

    #[test]
    fn certify_invalid_post() {
        let mut verifier = MockVerifier::new();
        verifier
            .expect_verify()
            .returning(|_, _| Err("invalid".to_string()));

        let certifier = Certifier {
            verifier: Arc::new(verifier),
            signer: SigningKey::generate(&mut rand::rngs::OsRng),
            expiry: None,
        };

        let proof = Proof {
            nonce: 0,
            indices: std::borrow::Cow::Owned(vec![1, 2, 3]),
            pow: 0,
        };

        let metadata = ProofMetadata {
            node_id: [7; 32],
            commitment_atx_id: [0u8; 32],
            challenge: [0; 32],
            num_units: 1,
        };

        certifier
            .certify(&proof, &metadata)
            .expect_err("certification should fail");
    }

    #[test]
    fn ceritify_valid_post() {
        let mut verifier = MockVerifier::new();
        verifier.expect_verify().returning(|_, _| Ok(()));
        let certifier = Certifier {
            verifier: Arc::new(verifier),
            signer: SigningKey::generate(&mut rand::rngs::OsRng),
            expiry: None,
        };

        let proof = Proof {
            nonce: 0,
            indices: std::borrow::Cow::Owned(vec![1, 2, 3]),
            pow: 0,
        };

        let metadata = ProofMetadata {
            node_id: [7; 32],
            commitment_atx_id: [0u8; 32],
            challenge: [0; 32],
            num_units: 1,
        };

        let (encoded, signature) = certifier
            .certify(&proof, &metadata)
            .expect("certification should succeed");

        certifier
            .signer
            .verify(&encoded, &signature)
            .expect("signature should be valid");

        let cert = Certificate::decode(&mut encoded.as_slice())
            .expect("decoding certificate should succeed");
        assert!(cert.expiration.is_none());
    }

    #[test]
    fn create_cert_with_expiry() {
        let expiry = Duration::try_days(1).unwrap();
        let certifier = Certifier {
            verifier: Arc::new(MockVerifier::new()),
            signer: SigningKey::generate(&mut rand::rngs::OsRng),
            expiry: Some(expiry),
        };

        let started = Utc::now();
        let cert = certifier.create_certificate(&[7u8; 32]);

        let expiration = cert.expiration.unwrap().0;
        assert!(expiration >= (started + expiry).timestamp() as u64);
        assert!(expiration <= (chrono::Utc::now() + expiry).timestamp() as u64);
    }
}
