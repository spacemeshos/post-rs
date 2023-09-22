use std::sync::Arc;
use std::sync::Mutex;
use std::time::Duration;

pub(crate) use spacemesh_v1::post_service_client::PostServiceClient;
use spacemesh_v1::{node_request, service_response};
use spacemesh_v1::{GenProofResponse, GenProofStatus, Proof, ProofMetadata, ServiceResponse};
use tokio::sync::mpsc;
use tokio::time::sleep;
use tonic::transport::Channel;
use tonic::Request;

use crate::service::ProofGenState;

pub mod spacemesh_v1 {
    tonic::include_proto!("spacemesh.v1");
}

pub(crate) struct ServiceClient {
    address: String,
    reconnect_interval: Duration,
    service: Arc<Mutex<crate::service::PostService>>,
}

impl ServiceClient {
    pub(crate) fn new(
        address: String,
        reconnect_interval: Duration,
        service: Arc<Mutex<crate::service::PostService>>,
    ) -> Self {
        Self {
            address,
            reconnect_interval,
            service,
        }
    }

    pub(crate) async fn run(self) -> eyre::Result<()> {
        loop {
            let client = loop {
                match PostServiceClient::connect(self.address.clone()).await {
                    Ok(client) => break client,
                    Err(e) => {
                        log::info!("could not connect to the node: {e:?}");
                        sleep(self.reconnect_interval).await;
                    }
                }
            };
            let res = run(client, self.service.clone()).await;
            log::info!("client exited: {res:?}");
        }
    }
}

async fn run(
    mut client: PostServiceClient<Channel>,
    service: Arc<Mutex<crate::service::PostService>>,
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
            Some(node_request::Kind::GenProof(req)) => {
                let result = service.lock().unwrap().gen_proof(req.challenge);

                let resp = match result {
                    Ok(ProofGenState::Finished { proof, metadata }) => {
                        log::info!("proof generation finished");
                        ServiceResponse {
                            kind: Some(service_response::Kind::GenProof(GenProofResponse {
                                proof: Some(Proof {
                                    nonce: proof.nonce,
                                    indices: proof.indices.into_owned(),
                                    pow: proof.pow,
                                }),
                                metadata: Some(ProofMetadata {
                                    challenge: metadata.challenge.to_vec(),
                                    node_id: Some(spacemesh_v1::SmesherId {
                                        id: metadata.node_id.to_vec(),
                                    }),
                                    commitment_atx_id: Some(spacemesh_v1::ActivationId {
                                        id: metadata.commitment_atx_id.to_vec(),
                                    }),
                                    num_units: metadata.num_units,
                                    labels_per_unit: metadata.labels_per_unit,
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
                };

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
