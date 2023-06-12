//! Proof of Work algorithm
//!
//! The PoW is required to prevent grinding on nonces
//! when looking for a proof. Without it a malicious actor
//! with a powerful enough computer could try many nonces
//! at the same time. In effect a proof could be found
//! without actually holding the whole POST data.

pub mod randomx;
pub(crate) mod scrypt;

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
