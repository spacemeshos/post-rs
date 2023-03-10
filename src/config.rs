#[repr(C)]
#[derive(Debug)]
pub struct Config {
    pub labels_per_unit: u64,
    /// K1 specifies the difficulty for a label to be a candidate for a proof.
    pub k1: u32,
    /// K2 is the number of labels below the required difficulty required for a proof.
    pub k2: u32,
    /// TODO: document
    pub k2_pow_difficulty: u64,
    /// TODO: document
    pub k3_pow_difficulty: u64,
    /// B is the number of labels used per AES invocation when generating a proof.
    /// Lower values speed up verification, higher values proof generation.
    pub b: u32,
    /// n is the number of nonces to try at the same time.
    pub n: u32,
}
