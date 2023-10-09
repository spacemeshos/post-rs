//! Post Service

use std::{
    path::PathBuf,
    sync::{atomic::AtomicBool, Arc, Mutex},
};

use eyre::Context;
use post::{
    metadata::ProofMetadata,
    pow::randomx::{PoW, RandomXFlag},
    prove::Proof,
    verification::{Verifier, VerifyingParams},
};

#[derive(Debug)]
pub enum ProofGenState {
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

pub struct PostService {
    datadir: PathBuf,
    cfg: post::config::Config,
    nonces: usize,
    threads: usize,
    pow_flags: RandomXFlag,
    proof_generation: Mutex<Option<ProofGenProcess>>,

    verifier: Verifier,
    stop: Arc<AtomicBool>,
}

impl PostService {
    pub fn new(
        datadir: PathBuf,
        cfg: post::config::Config,
        nonces: usize,
        threads: usize,
        pow_flags: RandomXFlag,
    ) -> eyre::Result<Self> {
        Ok(Self {
            proof_generation: Mutex::new(None),
            datadir,
            cfg,
            nonces,
            threads,
            pow_flags,
            verifier: Verifier::new(Box::new(PoW::new(RandomXFlag::get_recommended_flags())?)),
            stop: Arc::new(AtomicBool::new(false)),
        })
    }
}

impl crate::client::PostService for PostService {
    fn gen_proof(&self, challenge: Vec<u8>) -> eyre::Result<ProofGenState> {
        let mut proof_gen = self.proof_generation.lock().unwrap();
        if let Some(process) = proof_gen.as_mut() {
            eyre::ensure!(
                process.challenge == challenge,
                 "proof generation is in progress for a different challenge (current: {:X?}, requested: {:X?})", process.challenge, challenge,
                );

            if process.handle.is_finished() {
                log::info!("proof generation is finished");
                let result = match proof_gen.take().unwrap().handle.join() {
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
        let nonces = self.nonces;
        let threads = self.threads;
        let stop = self.stop.clone();
        *proof_gen = Some(ProofGenProcess {
            challenge,
            handle: std::thread::spawn(move || {
                post::prove::generate_proof(&datadir, &ch, cfg, nonces, threads, pow_flags, stop)
            }),
        });

        Ok(ProofGenState::InProgress)
    }

    fn verify_proof(&self, proof: &Proof, metadata: &ProofMetadata) -> eyre::Result<()> {
        self.verifier
            .verify(proof, metadata, VerifyingParams::new(metadata, &self.cfg)?)
            .wrap_err("verifying proof")
    }
}

impl Drop for PostService {
    fn drop(&mut self) {
        log::info!("shutting down post service");
        if let Some(process) = self.proof_generation.lock().unwrap().take() {
            log::debug!("killing proof generation process");
            self.stop.store(true, std::sync::atomic::Ordering::Relaxed);
            let _ = process.handle.join().unwrap();
            log::debug!("proof generation process exited");
        }
    }
}
