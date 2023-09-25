//! Post Service

use std::path::PathBuf;

use eyre::Context;
use post::{metadata::ProofMetadata, pow::randomx::RandomXFlag, prove::Proof};

pub(crate) enum ProofGenState {
    InProgress,
    Finished {
        proof: Proof<'static>,
        metadata: ProofMetadata,
    },
}

#[derive(Debug)]
struct ProofGenProcess {
    handle: std::thread::JoinHandle<eyre::Result<Proof<'static>>>,
    challenge: Vec<u8>,
}

#[derive(Debug)]
pub(crate) struct PostService {
    id: [u8; 32],
    datadir: PathBuf,
    cfg: post::config::Config,
    nonces: usize,
    threads: usize,
    pow_flags: RandomXFlag,
    proof_generation: Option<ProofGenProcess>,
}

impl PostService {
    pub(crate) fn new(
        datadir: PathBuf,
        cfg: post::config::Config,
        nonces: usize,
        threads: usize,
        pow_flags: RandomXFlag,
    ) -> eyre::Result<Self> {
        let metadata =
            post::metadata::load(&datadir).wrap_err("loading metadata. Is POST initialized?")?;

        Ok(Self {
            id: metadata.node_id,
            proof_generation: None,
            datadir,
            cfg,
            nonces,
            threads,
            pow_flags,
        })
    }

    pub(crate) fn gen_proof(&mut self, challenge: Vec<u8>) -> eyre::Result<ProofGenState> {
        if let Some(process) = &mut self.proof_generation {
            eyre::ensure!(
                process.challenge == challenge,
                 "proof generation is in progress for a different challenge (current: {:X?}, requested: {:X?})", process.challenge, challenge,
                );

            if process.handle.is_finished() {
                log::info!("proof generation is finished");
                let result = match self.proof_generation.take().unwrap().handle.join() {
                    Ok(result) => result,
                    Err(err) => {
                        std::panic::resume_unwind(err);
                    }
                };

                match result {
                    Ok(proof) => {
                        let metadata = post::metadata::load(&self.datadir)
                            .wrap_err("loading POST metadata")?;

                        return Ok(ProofGenState::Finished {
                            proof,
                            metadata: ProofMetadata {
                                challenge: challenge
                                    .try_into()
                                    .map_err(|_| eyre::eyre!("invalid challenge format"))?,
                                node_id: metadata.node_id,
                                commitment_atx_id: metadata.commitment_atx_id,
                                num_units: metadata.num_units,
                                labels_per_unit: metadata.labels_per_unit,
                            },
                        });
                    }
                    Err(e) => {
                        return Err(e);
                    }
                }
            } else {
                log::info!("proof generation in progress");
                return Ok(ProofGenState::InProgress);
            }
        }

        let ch: [u8; 32] = challenge
            .as_slice()
            .try_into()
            .map_err(|_| eyre::eyre!("invalid challenge format"))?;
        log::info!("starting proof generation for challenge {ch:X?}");
        let pow_flags = self.pow_flags;
        let cfg = self.cfg;
        let datadir = self.datadir.clone();
        let miner_id = Some(self.id);
        let nonces = self.nonces;
        let threads = self.threads;
        self.proof_generation = Some(ProofGenProcess {
            challenge,
            handle: std::thread::spawn(move || {
                post::prove::generate_proof(
                    &datadir, &ch, cfg, nonces, threads, pow_flags, miner_id,
                )
            }),
        });

        Ok(ProofGenState::InProgress)
    }
}
