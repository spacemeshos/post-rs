//! Proof of Work algorithm
//!
//! The PoW is required to prevent grinding on nonces
//! when looking for a proof. Without it a malicious actor
//! with a powerful enough computer could try many nonces
//! at the same time. In effect a proof could be found
//! without actually holding the whole POST data.

pub mod randomx;
pub mod service;
use mockall::*;
use std::ops::Range;
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
    fn prove(
        &self,
        nonce_group: u8,
        challenge: &[u8; 8],
        difficulty: &[u8; 32],
        miner_id: &[u8; 32],
    ) -> Result<u64, Error>;

    fn prove_many(
        &self,
        nonce_group: Range<u32>,
        challenge: &[u8; 8],
        difficulty: &[u8; 32],
        miner_id: &[u8; 32],
    ) -> Result<Vec<(u32, u64)>, Error>;

    fn par(&self) -> bool;
}

#[automock]
pub trait PowVerifier {
    fn verify(
        &self,
        pow: u64,
        nonce_group: u8,
        challenge: &[u8; 8],
        difficulty: &[u8; 32],
        miner_id: &[u8; 32],
    ) -> Result<(), Error>;
}
