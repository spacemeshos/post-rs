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
    pub k2_pow_difficulty: u64,
    /// Scrypt parameters for the Proofs of Work
    pub pow_scrypt: scrypt_jane::scrypt::ScryptParams,
    /// Scrypt paramters for initilizing labels
    pub scrypt: scrypt_jane::scrypt::ScryptParams,
}
