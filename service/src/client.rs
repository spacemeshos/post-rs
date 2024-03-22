//! Post Service GRPC client
//!
//! This module implements a GRPC client for the Post Service.
//! It connects to the node and registers itself as a Post Service.
//! It then waits for requests from the node and forwards them to the Post Service.

use std::time::Duration;

use post::metadata::PostMetadata;
pub(crate) use spacemesh_v1::post_service_client::PostServiceClient;
use spacemesh_v1::{node_request, service_response};
use spacemesh_v1::{
    GenProofRequest, GenProofResponse, GenProofStatus, Proof, ProofMetadata, ServiceResponse,
};
use tokio::sync::mpsc;
use tokio::time::sleep;
use tokio_stream::wrappers::ReceiverStream;
use tonic::transport::Certificate;
use tonic::transport::Channel;
use tonic::transport::ClientTlsConfig;
use tonic::transport::Endpoint;
use tonic::transport::Identity;
use tonic::Request;

use crate::client::spacemesh_v1::MetadataResponse;
use crate::service::ProofGenState;

pub mod spacemesh_v1 {
    tonic::include_proto!("spacemesh.v1");
}

pub struct ServiceClient<S: PostService> {
    endpoint: Endpoint,
    service: S,
}

#[mockall::automock]
#[allow(clippy::needless_lifetimes)]
pub trait PostService {
    fn get_metadata(&self) -> &PostMetadata;

    fn gen_proof(&self, challenge: &[u8]) -> eyre::Result<ProofGenState>;

    fn verify_proof<'a>(
        &self,
        proof: &post::prove::Proof<'a>,
        challenge: &[u8],
    ) -> eyre::Result<()>;
}

impl<T: PostService + ?Sized> PostService for std::sync::Arc<T> {
    fn gen_proof(&self, challenge: &[u8]) -> eyre::Result<ProofGenState> {
        self.as_ref().gen_proof(challenge)
    }

    fn verify_proof(&self, proof: &post::prove::Proof, challenge: &[u8]) -> eyre::Result<()> {
        self.as_ref().verify_proof(proof, challenge)
    }

    fn get_metadata(&self) -> &PostMetadata {
        self.as_ref().get_metadata()
    }
}

impl<S: PostService> ServiceClient<S> {
    pub fn new(
        address: String,
        tls: Option<(Option<String>, Certificate, Identity)>,
        service: S,
    ) -> eyre::Result<Self> {
        let endpoint = Channel::builder(address.parse()?)
            .keep_alive_timeout(Duration::from_secs(20))
            .http2_keep_alive_interval(Duration::from_secs(60));
        let endpoint = match tls {
            Some((domain, cert, identity)) => {
                let domain = match domain {
                    Some(domain) => domain,
                    None => endpoint
                        .uri()
                        .authority()
                        .ok_or_else(|| eyre::eyre!("no domain name in the endpoint"))?
                        .host()
                        .to_string(),
                };

                endpoint.tls_config(
                    ClientTlsConfig::new()
                        .domain_name(domain)
                        .ca_certificate(cert)
                        .identity(identity),
                )?
            }
            None => endpoint,
        };

        Ok(Self { endpoint, service })
    }

    pub async fn run(
        mut self,
        max_retries: Option<usize>,
        reconnect_interval: Duration,
    ) -> eyre::Result<()> {
        loop {
            let mut attempt = 1;
            let client = loop {
                log::debug!(
                    "connecting to the node on {} (attempt {})",
                    self.endpoint.uri(),
                    attempt
                );
                match PostServiceClient::connect(self.endpoint.clone()).await {
                    Ok(client) => break client,
                    Err(e) => {
                        log::info!("could not connect to the node: {e}");
                        if let Some(max) = max_retries {
                            eyre::ensure!(attempt <= max, "max retries ({max}) reached");
                        }
                        sleep(reconnect_interval).await;
                    }
                }
                attempt += 1;
            };
            let res = self.register_and_serve(client).await;
            log::info!("disconnected: {res:?}");
            sleep(reconnect_interval).await;
        }
    }

    async fn register_and_serve(
        &mut self,
        mut client: PostServiceClient<Channel>,
    ) -> eyre::Result<()> {
        let (tx, rx) = mpsc::channel::<ServiceResponse>(1);
        let response = client
            .register(Request::new(ReceiverStream::from(rx)))
            .await?;
        let mut inbound = response.into_inner();

        while let Some(request) = inbound.message().await? {
            log::debug!("Got request from node: {request:?}");
            match request.kind {
                Some(node_request::Kind::Metadata(_)) => {
                    let resp = self.get_metadata();
                    tx.send(resp).await?;
                }
                Some(node_request::Kind::GenProof(req)) => {
                    let resp = self.generate_and_verify_proof(req);
                    tx.send(resp).await?;
                }
                None => {
                    log::warn!("Got a request with no kind");
                    tx.send(ServiceResponse {
                        kind: Some(service_response::Kind::GenProof(GenProofResponse {
                            status: GenProofStatus::Error as i32,
                            ..Default::default()
                        })),
                    })
                    .await?
                }
            }
        }

        Ok(())
    }

    fn generate_and_verify_proof(&self, request: GenProofRequest) -> ServiceResponse {
        let result = self.service.gen_proof(&request.challenge);

        match result {
            Ok(ProofGenState::Finished { proof }) => {
                log::info!("proof generation finished");
                log::info!("verifying proof");
                let post_metadata = self.service.get_metadata();
                let started = std::time::Instant::now();
                if let Err(err) = self.service.verify_proof(&proof, &request.challenge) {
                    log::error!(
                        "failed proof verification: {err:?} (verification took: {}s)",
                        started.elapsed().as_secs_f64()
                    );
                    return ServiceResponse {
                        kind: Some(service_response::Kind::GenProof(GenProofResponse {
                            status: GenProofStatus::Error as i32,
                            ..Default::default()
                        })),
                    };
                }
                log::info!(
                    "proof is valid (verification took: {}s)",
                    started.elapsed().as_secs_f64()
                );

                ServiceResponse {
                    kind: Some(service_response::Kind::GenProof(GenProofResponse {
                        proof: Some(Proof {
                            nonce: proof.nonce,
                            indices: proof.indices.into_owned(),
                            pow: proof.pow,
                        }),
                        metadata: Some(ProofMetadata {
                            challenge: request.challenge,
                            meta: Some(convert_metadata(*post_metadata)),
                        }),
                        status: GenProofStatus::Ok as i32,
                    })),
                }
            }
            Ok(ProofGenState::InProgress) => {
                log::info!("proof generation in progress");
                ServiceResponse {
                    kind: Some(service_response::Kind::GenProof(GenProofResponse {
                        status: GenProofStatus::Ok as i32,
                        ..Default::default()
                    })),
                }
            }
            Err(e) => {
                log::error!("failed to generate proof: {e:?}");
                ServiceResponse {
                    kind: Some(service_response::Kind::GenProof(GenProofResponse {
                        status: GenProofStatus::Error as i32,
                        ..Default::default()
                    })),
                }
            }
        }
    }

    fn get_metadata(&self) -> ServiceResponse {
        let meta = self.service.get_metadata();
        log::info!("obtained metadata: {meta:?}");
        ServiceResponse {
            kind: Some(service_response::Kind::Metadata(MetadataResponse {
                meta: Some(convert_metadata(*meta)),
            })),
        }
    }
}

fn convert_metadata(meta: PostMetadata) -> spacemesh_v1::Metadata {
    spacemesh_v1::Metadata {
        node_id: meta.node_id.to_vec(),
        commitment_atx_id: meta.commitment_atx_id.to_vec(),
        nonce: meta.nonce,
        num_units: meta.num_units,
        labels_per_unit: meta.labels_per_unit,
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use tonic::transport::{Certificate, Identity};

    #[test]
    fn derives_domain_from_address() {
        let crt = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
        let client_crt = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
        super::ServiceClient::new(
            "https://localhost:1234".to_string(),
            Some((
                None,
                Certificate::from_pem(crt.serialize_pem().unwrap()),
                Identity::from_pem(
                    client_crt.serialize_pem().unwrap(),
                    client_crt.serialize_private_key_pem(),
                ),
            )),
            super::MockPostService::new(),
        )
        .unwrap();
    }

    #[tokio::test]
    async fn gives_up_after_max_retries() {
        let client = super::ServiceClient::new(
            "http://localhost:1234".to_string(),
            None,
            super::MockPostService::new(),
        )
        .unwrap();

        let res = client.run(Some(2), Duration::from_millis(1)).await;
        assert_eq!(res.unwrap_err().to_string(), "max retries (2) reached");
    }
}
