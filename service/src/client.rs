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
    reconnect_interval: Duration,
    service: S,
}

#[mockall::automock]
#[allow(clippy::needless_lifetimes)]
pub trait PostService {
    fn get_metadata(&self) -> eyre::Result<PostMetadata>;

    fn gen_proof(&self, challenge: Vec<u8>) -> eyre::Result<ProofGenState>;

    fn verify_proof<'a>(
        &self,
        proof: &post::prove::Proof<'a>,
        metadata: &post::metadata::ProofMetadata,
    ) -> eyre::Result<()>;
}

impl<T: PostService + ?Sized> PostService for std::sync::Arc<T> {
    fn gen_proof(&self, challenge: Vec<u8>) -> eyre::Result<ProofGenState> {
        self.as_ref().gen_proof(challenge)
    }

    fn verify_proof(
        &self,
        proof: &post::prove::Proof,
        metadata: &post::metadata::ProofMetadata,
    ) -> eyre::Result<()> {
        self.as_ref().verify_proof(proof, metadata)
    }

    fn get_metadata(&self) -> eyre::Result<PostMetadata> {
        self.as_ref().get_metadata()
    }
}

impl<S: PostService> ServiceClient<S> {
    pub fn new(
        address: String,
        reconnect_interval: Duration,
        tls: Option<(String, Certificate, Identity)>,
        service: S,
    ) -> eyre::Result<Self> {
        let endpoint = Channel::builder(address.parse()?);
        let endpoint = match tls {
            Some((domain, cert, identity)) => endpoint.tls_config(
                ClientTlsConfig::new()
                    .domain_name(domain)
                    .ca_certificate(cert)
                    .identity(identity),
            )?,
            None => endpoint,
        };

        Ok(Self {
            endpoint,
            reconnect_interval,
            service,
        })
    }

    pub async fn run(mut self) -> eyre::Result<()> {
        loop {
            let client = loop {
                log::debug!("connecting to the node on {}", self.endpoint.uri());
                match PostServiceClient::connect(self.endpoint.clone()).await {
                    Ok(client) => break client,
                    Err(e) => {
                        log::info!("could not connect to the node: {e}");
                        sleep(self.reconnect_interval).await;
                    }
                }
            };
            let res = self.register_and_serve(client).await;
            log::info!("disconnected: {res:?}");
            sleep(self.reconnect_interval).await;
        }
    }

    async fn register_and_serve(
        &mut self,
        mut client: PostServiceClient<Channel>,
    ) -> eyre::Result<()> {
        let (tx, mut rx) = mpsc::channel::<ServiceResponse>(1);
        let outbound = async_stream::stream! {
            while let Some(msg) = rx.recv().await {
                yield msg;
            }
        };

        let response = client.register(Request::new(outbound)).await?;
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
        let result = self.service.gen_proof(request.challenge.clone());

        match result {
            Ok(ProofGenState::Finished { proof }) => {
                log::info!("proof generation finished");
                let post_metadata = match self.service.get_metadata() {
                    Ok(m) => m,
                    Err(err) => {
                        log::error!("failed to get metadata: {err:?}");
                        return ServiceResponse {
                            kind: Some(service_response::Kind::GenProof(GenProofResponse {
                                status: GenProofStatus::Error as i32,
                                ..Default::default()
                            })),
                        };
                    }
                };

                if let Err(err) = self.service.verify_proof(
                    &proof,
                    &post::metadata::ProofMetadata::new(
                        post_metadata,
                        request.challenge.as_slice().try_into().unwrap(),
                    ),
                ) {
                    log::error!("generated proof is not valid: {err:?}");
                    return ServiceResponse {
                        kind: Some(service_response::Kind::GenProof(GenProofResponse {
                            status: GenProofStatus::Error as i32,
                            ..Default::default()
                        })),
                    };
                }

                ServiceResponse {
                    kind: Some(service_response::Kind::GenProof(GenProofResponse {
                        proof: Some(Proof {
                            nonce: proof.nonce,
                            indices: proof.indices.into_owned(),
                            pow: proof.pow,
                        }),
                        metadata: Some(ProofMetadata {
                            challenge: request.challenge,
                            meta: Some(convert_metadata(post_metadata)),
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
        match self.service.get_metadata() {
            Ok(meta) => {
                log::info!("obtained metadata: {meta:?}");
                ServiceResponse {
                    kind: Some(service_response::Kind::Metadata(MetadataResponse {
                        meta: Some(convert_metadata(meta)),
                    })),
                }
            }
            Err(e) => {
                log::error!("failed to get metadata: {e:?}");
                ServiceResponse {
                    kind: Some(service_response::Kind::Metadata(MetadataResponse {
                        meta: None,
                    })),
                }
            }
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
