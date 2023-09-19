pub(crate) use spacemesh_v1::post_service_client::PostServiceClient;
use spacemesh_v1::service_response;
use spacemesh_v1::ServiceResponse;
use spacemesh_v1::{GenProofResponse, GenProofStatus, Proof, ProofMetadata};
use tokio::sync::{mpsc, oneshot};
use tonic::transport::Channel;
use tonic::Request;

use crate::service::Command;
use spacemesh_v1::node_request;

pub mod spacemesh_v1 {
    tonic::include_proto!("spacemesh.v1");
}

pub(crate) async fn run(
    mut client: PostServiceClient<Channel>,
    cmds: mpsc::Sender<Command>,
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
                let (cmd_response, rx) = oneshot::channel();
                let Ok(challenge) = req.challenge.try_into() else {
                    log::error!("invalid challenge");
                    tx.send(ServiceResponse {
                        kind: Some(service_response::Kind::GenProof(GenProofResponse {
                            status: GenProofStatus::Error as i32,
                            ..Default::default()
                        })),
                    })
                    .await?;
                    continue;
                };

                // Forward the request to the service
                cmds.send(Command::GenProof {
                    challenge,
                    response: cmd_response,
                })
                .await?;

                // Process the response from the service
                let resp = match rx.await? {
                    Ok(Some(resp)) => {
                        log::info!("proof generation finished");
                        ServiceResponse {
                            kind: Some(service_response::Kind::GenProof(GenProofResponse {
                                proof: Some(Proof {
                                    nonce: resp.0.nonce,
                                    indices: resp.0.indices.into_owned(),
                                    pow: resp.0.pow,
                                }),
                                metadata: Some(ProofMetadata {
                                    challenge: resp.1.challenge.to_vec(),
                                    node_id: Some(spacemesh_v1::SmesherId {
                                        id: resp.1.node_id.to_vec(),
                                    }),
                                    commitment_atx_id: Some(spacemesh_v1::ActivationId {
                                        id: resp.1.commitment_atx_id.to_vec(),
                                    }),
                                    num_units: resp.1.num_units,
                                    labels_per_unit: resp.1.labels_per_unit,
                                }),
                                status: GenProofStatus::Ok as i32,
                            })),
                        }
                    }
                    Ok(None) => {
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
