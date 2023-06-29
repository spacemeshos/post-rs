#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct Config {
    /// Difficulty for the nonce proof of work. Lower values increase difficulty of finding
    /// `pow` for [Proof][crate::prove::Proof].
    pub pow_difficulty: [u8; 32],
    /// K1 specifies the difficulty for a label to be a candidate for a proof.
    pub k1: u32,
    /// K2 is the number of labels below the required difficulty required for a proof.
    pub k2: u32,
    /// K3 is the size of the subset of proof indices that is validated.
    pub k3: u32,
    /// Scrypt paramters for initilizing labels
    pub scrypt: scrypt_jane::scrypt::ScryptParams,
}
