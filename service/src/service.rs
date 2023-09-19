use std::path::PathBuf;

use eyre::Context;
use post::{metadata::ProofMetadata, pow::randomx::RandomXFlag, prove::Proof};
use tokio::sync::{mpsc, oneshot};

#[derive(Debug)]
pub(crate) enum Command {
    GenProof {
        challenge: [u8; 32],
        response: oneshot::Sender<eyre::Result<Option<(Proof<'static>, ProofMetadata)>>>,
    },
}

#[derive(Debug)]
pub(crate) struct PostService {
    id: [u8; 32],
    datadir: PathBuf,
    cfg: post::config::Config,
    nonces: usize,
    threads: usize,
    pow_flags: RandomXFlag,
    rx: mpsc::Receiver<Command>,
    proof_generation: Option<tokio::task::JoinHandle<eyre::Result<Proof<'static>>>>,
}

impl PostService {
    pub(crate) fn new(
        rx: mpsc::Receiver<Command>,
        datadir: PathBuf,
        cfg: post::config::Config,
        nonces: usize,
        threads: usize,
        pow_flags: RandomXFlag,
    ) -> eyre::Result<Self> {
        let metadata =
            post::metadata::load(&datadir).wrap_err("loading metadata. Is POST initialized?")?;
        let id = metadata.node_id;

        Ok(Self {
            id,
            rx,
            proof_generation: None,
            datadir,
            cfg,
            nonces,
            threads,
            pow_flags,
        })
    }

    pub(crate) async fn run(mut self) -> eyre::Result<()> {
        log::info!("starting PostService");
        while let Some(cmd) = self.rx.recv().await {
            log::info!("got {cmd:?}");
            match cmd {
                Command::GenProof {
                    challenge,
                    response,
                } => {
                    log::info!("got GenProof command");
                    match &mut self.proof_generation {
                        Some(handle) => {
                            if handle.is_finished() {
                                log::info!("proof generation is finished");
                                let result = handle.await?;
                                self.proof_generation = None;
                                match result {
                                    Ok(proof) => {
                                        let metadata = post::metadata::load(&self.datadir).unwrap();

                                        _ = response.send(Ok(Some((
                                            proof,
                                            ProofMetadata {
                                                challenge,
                                                node_id: metadata.node_id,
                                                commitment_atx_id: metadata.commitment_atx_id,
                                                num_units: metadata.num_units,
                                                labels_per_unit: metadata.labels_per_unit,
                                            },
                                        ))));
                                    }
                                    Err(e) => {
                                        _ = response.send(Err(e));
                                    }
                                }
                            } else {
                                log::info!("proof generation in progress");
                                _ = response.send(Ok(None));
                            }
                        }
                        None => {
                            log::info!("starting proof generation");
                            let pow_flags = self.pow_flags;
                            let cfg = self.cfg;
                            let datadir = self.datadir.clone();
                            let node_id = self.id;
                            let nonces = self.nonces;
                            let threads = self.threads;
                            self.proof_generation = Some(tokio::task::spawn_blocking(move || {
                                post::prove::generate_proof(
                                    &datadir,
                                    &challenge,
                                    cfg,
                                    nonces,
                                    threads,
                                    pow_flags,
                                    Some(node_id),
                                )
                            }));
                            // in progress
                            _ = response.send(Ok(None));
                        }
                    }
                }
            }
        }
        Ok(())
    }
}
