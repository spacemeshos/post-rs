//! Post Service

use std::{
    ops::{Range, RangeInclusive},
    path::PathBuf,
    sync::{atomic::AtomicBool, Arc, Mutex},
};

use eyre::Context;
use post::{
    metadata::{PostMetadata, ProofMetadata},
    pow::randomx::{PoW, RandomXFlag},
    prove::{self, Proof},
    verification::{Mode, Verifier},
};

use crate::operator::ServiceState;

#[derive(Debug)]
pub enum ProofGenState {
    InProgress,
    Finished { proof: Proof<'static> },
}

#[derive(Debug)]
enum ProofGenProcess {
    Idle,
    Running {
        handle: Option<std::thread::JoinHandle<eyre::Result<Proof<'static>>>>,
        challenge: [u8; 32],
        progress: ProvingProgress,
    },
    Done {
        proof: eyre::Result<Proof<'static>>,
    },
}

impl ProofGenProcess {
    fn check_finished(&mut self) {
        if let ProofGenProcess::Running { handle, .. } = self {
            if handle.as_ref().unwrap().is_finished() {
                let proof = match handle.take().unwrap().join() {
                    Ok(result) => result,
                    Err(err) => {
                        std::panic::resume_unwind(err);
                    }
                };
                *self = ProofGenProcess::Done { proof };
            }
        }
    }
}

#[derive(Clone, Debug, Default)]
struct ProvingProgress {
    inner: Arc<Mutex<ProvingProgressInner>>,
}

#[derive(Clone, Debug)]
struct ProvingProgressInner {
    // currently processed nonces
    nonces: std::ops::Range<u32>,
    // already finished chunks of data
    // the chunks are automatically merged when possible
    chunks: range_set::RangeSet<[RangeInclusive<u64>; 20]>,
}

impl Default for ProvingProgressInner {
    fn default() -> Self {
        Self {
            nonces: 0..0,
            chunks: range_set::RangeSet::new(),
        }
    }
}

impl prove::ProgressReporter for ProvingProgress {
    fn finished_chunk(&self, pos: u64, len: usize) {
        if len == 0 {
            return;
        }

        let range = pos..=(pos + len as u64 - 1);
        self.inner.lock().unwrap().chunks.insert_range(range);
    }

    fn new_nonce_group(&self, nonces: std::ops::Range<u32>) {
        let mut progress = self.inner.lock().unwrap();
        progress.nonces = nonces;
        progress.chunks.clear();
    }
}

impl ProvingProgress {
    fn get(&self) -> (Range<u32>, u64) {
        let progress = self.inner.lock().unwrap();
        (
            progress.nonces.clone(),
            progress.chunks.as_ref().first().map_or(0, |r| *r.end() + 1),
        )
    }
}

pub struct PostService {
    datadir: PathBuf,
    metadata: post::metadata::PostMetadata,
    cfg: post::config::ProofConfig,
    scrypt: post::config::ScryptParams,
    nonces: usize,
    threads: post::config::Cores,
    pow_flags: RandomXFlag,
    proof_generation: Mutex<ProofGenProcess>,

    stop: Arc<AtomicBool>,
}

impl PostService {
    pub fn new(
        datadir: PathBuf,
        cfg: post::config::ProofConfig,
        scrypt: post::config::ScryptParams,
        nonces: usize,
        threads: post::config::Cores,
        pow_flags: RandomXFlag,
    ) -> eyre::Result<Self> {
        Ok(Self {
            metadata: post::metadata::load(&datadir).wrap_err("loading POST metadata")?,
            datadir,
            cfg,
            scrypt,
            nonces,
            threads,
            pow_flags,
            proof_generation: Mutex::new(ProofGenProcess::Idle),
            stop: Arc::new(AtomicBool::new(false)),
        })
    }
}

impl crate::client::PostService for PostService {
    fn gen_proof(&self, ch: &[u8]) -> eyre::Result<ProofGenState> {
        let mut proof_gen = self.proof_generation.lock().unwrap();
        proof_gen.check_finished();
        match &*proof_gen {
            ProofGenProcess::Running { challenge, .. } => {
                eyre::ensure!(
                challenge.as_slice() == ch,
                 "proof generation is in progress for a different challenge (current: {}, requested: {})",
                  hex::encode_upper(challenge),
                  hex::encode_upper(ch),
                );
                return Ok(ProofGenState::InProgress);
            }
            ProofGenProcess::Idle => {
                let challenge: [u8; 32] = ch
                    .try_into()
                    .map_err(|_| eyre::eyre!("invalid challenge format"))?;
                log::info!(
                    "starting proof generation for challenge {}",
                    hex::encode_upper(challenge)
                );
                let pow_flags = self.pow_flags;
                let cfg = self.cfg;
                let datadir = self.datadir.clone();
                let nonces = self.nonces;
                let threads = self.threads.clone();
                let stop = self.stop.clone();
                let progress = ProvingProgress::default();
                let reporter = progress.clone();
                *proof_gen = ProofGenProcess::Running {
                    challenge,
                    handle: Some(std::thread::spawn(move || {
                        post::prove::generate_proof(
                            &datadir, &challenge, cfg, nonces, threads, pow_flags, stop, reporter,
                        )
                    })),
                    progress,
                };
            }
            ProofGenProcess::Done { proof } => {
                log::info!("proof generation is finished");
                return match proof {
                    Ok(proof) => Ok(ProofGenState::Finished {
                        proof: proof.clone(),
                    }),
                    Err(e) => Err(eyre::eyre!("proof generation failed: {}", e)),
                };
            }
        }

        Ok(ProofGenState::InProgress)
    }

    fn verify_proof(&self, proof: &Proof, challenge: &[u8]) -> eyre::Result<()> {
        let pow_verifier =
            PoW::new(RandomXFlag::get_recommended_flags()).context("creating PoW verifier")?;
        let verifier = Verifier::new(Box::new(pow_verifier));
        let metadata = &ProofMetadata::new(self.metadata, challenge.try_into()?);
        let init_cfg = post::config::InitConfig {
            // we assume our POST is correctly initialized.
            min_num_units: self.metadata.num_units,
            max_num_units: self.metadata.num_units,
            labels_per_unit: self.metadata.labels_per_unit,
            scrypt: self.scrypt,
        };
        let result = verifier
            .verify(proof, metadata, &self.cfg, &init_cfg, Mode::All)
            .context("verifying proof");
        *self.proof_generation.lock().unwrap() = ProofGenProcess::Idle;
        result
    }

    fn get_metadata(&self) -> &PostMetadata {
        &self.metadata
    }
}

impl crate::operator::Service for PostService {
    fn status(&self) -> ServiceState {
        let mut proof_gen = self.proof_generation.lock().unwrap();
        proof_gen.check_finished();
        match &*proof_gen {
            ProofGenProcess::Running { progress, .. } => {
                let (nonces, offset) = progress.get();
                ServiceState::Proving {
                    nonces,
                    position: offset,
                }
            }
            ProofGenProcess::Idle => ServiceState::Idle,
            ProofGenProcess::Done { .. } => ServiceState::DoneProving,
        }
    }
}

impl Drop for PostService {
    fn drop(&mut self) {
        log::info!("shutting down post service");
        if let ProofGenProcess::Running { handle, .. } = &mut *self.proof_generation.lock().unwrap()
        {
            log::debug!("stopping proof generation process");
            self.stop.store(true, std::sync::atomic::Ordering::Relaxed);
            let _ = handle.take().unwrap().join().unwrap();
            log::debug!("proof generation process exited");
        }
    }
}
