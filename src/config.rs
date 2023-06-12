#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct Config {
    /// K1 specifies the difficulty for a label to be a candidate for a proof.
    pub k1: u32,
    /// K2 is the number of labels below the required difficulty required for a proof.
    pub k2: u32,
    /// K3 is the size of the subset of proof indices that is validated.
    pub k3: u32,
    /// Difficulty for K2 proof of work. Lower values increase difficulty of finding
    /// `k2_pow` for [Proof][crate::prove::Proof].
    /// deprecated since "0.2.0", scrypt-based K2 pow is deprecated, use RandomX instead
    pub k2_pow_dificulty: u64,
    /// Scrypt parameters for the Proofs of Work
    /// deprecated since "0.2.0", scrypt-based K2 pow is deprecated, use RandomX instead
    pub pow_scrypt: scrypt_jane::scrypt::ScryptParams,
    /// Difficulty for the nonce proof of work. Lower values increase difficulty of finding
    /// `pow` for [Proof][crate::prove::Proof].
    pub pow_difficulty: [u8; 32],
    /// Scrypt paramters for initilizing labels
    pub scrypt: scrypt_jane::scrypt::ScryptParams,
}
