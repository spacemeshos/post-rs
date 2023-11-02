#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct Config {
    /// K1 specifies the difficulty for a label to be a candidate for a proof.
    pub k1: u32,
    /// K2 is the number of labels below the required difficulty required for a proof.
    pub k2: u32,
    /// K3 is the size of the subset of proof indices that is validated.
    pub k3: u32,
    /// Difficulty for the nonce proof of work. Lower values increase difficulty of finding
    /// `pow` for [Proof][crate::prove::Proof].
    pub pow_difficulty: [u8; 32],
    /// Scrypt paramters for initilizing labels
    pub scrypt: ScryptParams,
}

#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct ScryptParams {
    pub n: usize,
    pub r: usize,
    pub p: usize,
}

impl ScryptParams {
    pub fn new(n: usize, r: usize, p: usize) -> Self {
        assert!(n >= 2);
        assert!(n.is_power_of_two());
        assert!(r.is_power_of_two());
        assert!(p.is_power_of_two());
        Self { n, r, p }
    }
}

impl From<ScryptParams> for scrypt_jane::scrypt::ScryptParams {
    fn from(params: ScryptParams) -> Self {
        Self::new(
            params.n.ilog2() as u8 - 1,
            params.r.ilog2() as u8,
            params.p.ilog2() as u8,
        )
    }
}
