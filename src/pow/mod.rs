//! Proof of Work algorithm
//!
//! The PoW is required to prevent grinding on nonces
//! when looking for a proof. Without it a malicious actor
//! with a powerful enough computer could try many nonces
//! at the same time. In effect a proof could be found
//! without actually holding the whole POST data.

pub mod randomx;
use mockall::*;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum Error {
    #[error("proof of work not found")]
    PoWNotFound,
    #[error("proof of work is invalid")]
    InvalidPoW,
    #[error(transparent)]
    Internal(Box<dyn std::error::Error + Send + Sync>),
}

#[automock]
pub trait Prover {
    fn prove<'a>(
        &self,
        nonce_group: u8,
        challenge: &[u8; 8],
        difficulty: &[u8; 32],
        miner_id: Option<&'a [u8; 32]>,
    ) -> Result<u64, Error>;
}

#[automock]
pub trait PowVerifier {
    fn verify<'a>(
        &self,
        pow: u64,
        nonce_group: u8,
        challenge: &[u8; 8],
        difficulty: &[u8; 32],
        miner_id: Option<&'a [u8; 32]>,
    ) -> Result<(), Error>;
}
