use std::{
    borrow::Cow,
    error::Error,
    ffi::{c_char, c_uchar, CStr},
    mem::ManuallyDrop,
    path::Path,
    sync::atomic::AtomicBool,
};

use post::{
    config::{InitConfig, ProofConfig},
    metadata::ProofMetadata,
    pow::randomx::{PoW, RandomXFlag},
    prove,
    verification::{Mode, Verifier},
};

use crate::ArrayU8;

#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct Proof {
    nonce: u32,
    indices: ArrayU8,
    pow: u64,
}

impl From<prove::Proof<'_>> for Proof {
    fn from(proof: prove::Proof) -> Self {
        let mut indices = ManuallyDrop::new(proof.indices.into_owned());
        let (ptr, len, cap) = (indices.as_mut_ptr(), indices.len(), indices.capacity());

        Self {
            nonce: proof.nonce,
            indices: ArrayU8 { ptr, len, cap },
            pow: proof.pow,
        }
    }
}

impl From<Proof> for prove::Proof<'_> {
    fn from(val: Proof) -> Self {
        post::prove::Proof {
            nonce: val.nonce,
            indices: Cow::Borrowed(unsafe { val.indices.as_slice() }),
            pow: val.pow,
        }
    }
}

/// Deallocate a proof obtained with generate_proof().
/// # Safety
/// `proof` must be a pointer to a Proof struct obtained with generate_proof().
#[no_mangle]
pub unsafe extern "C" fn free_proof(proof: *mut Proof) {
    let proof = Box::from_raw(proof);
    if !proof.indices.ptr.is_null() {
        Vec::from_raw_parts(proof.indices.ptr, proof.indices.len, proof.indices.cap);
    }
    // proof and vec will be deallocated on return
}

/// Generates a proof of space for the given challenge using the provided parameters.
/// Returns a pointer to a Proof struct which should be freed with free_proof() after use.
/// If an error occurs, prints it on stderr and returns null.
/// # Safety
/// `challenge` must be a 32-byte array.
#[no_mangle]
pub extern "C" fn generate_proof(
    datadir: *const c_char,
    challenge: *const c_uchar,
    cfg: ProofConfig,
    nonces: usize,
    threads: usize,
    pow_flags: RandomXFlag,
) -> *mut Proof {
    match _generate_proof(datadir, challenge, cfg, nonces, threads, pow_flags) {
        Ok(proof) => Box::into_raw(proof),
        Err(e) => {
            //TODO(poszu) communicate errors better
            log::error!("{e:?}");
            std::ptr::null_mut()
        }
    }
}

fn _generate_proof(
    datadir: *const c_char,
    challenge: *const c_uchar,
    cfg: ProofConfig,
    nonces: usize,
    threads: usize,
    pow_flags: RandomXFlag,
) -> Result<Box<Proof>, Box<dyn Error>> {
    let datadir = unsafe { CStr::from_ptr(datadir) };
    let datadir = Path::new(
        datadir
            .to_str()
            .map_err(|e| format!("reading datadir: {e:?}"))?,
    );

    let challenge = unsafe { std::slice::from_raw_parts(challenge, 32) };
    let challenge = challenge.try_into()?;

    let stop = AtomicBool::new(false);
    let proof = prove::generate_proof(datadir, challenge, cfg, nonces, threads, pow_flags, stop)?;
    Ok(Box::new(Proof::from(proof)))
}

#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VerifyResult {
    /// Proof is valid
    Ok,
    /// Invalid for other reasons
    Invalid,
    /// Found invalid label
    /// The index (in Proof.indices) of the index of invalid label is returned.
    /// Say the proof has 3 indices [100, 200, 500] (these index labels in POS data),
    /// if the label at index 200 is found invalid, the index 1 is returned.
    InvalidIndex { index_id: usize },
    /// Can't verify proof because invalid argument was passed
    InvalidArgument,
}

impl From<post::verification::Error> for VerifyResult {
    fn from(err: post::verification::Error) -> Self {
        match err {
            post::verification::Error::InvalidMsb { index_id, .. } => {
                VerifyResult::InvalidIndex { index_id }
            }
            post::verification::Error::InvalidLsb { index_id, .. } => {
                VerifyResult::InvalidIndex { index_id }
            }
            _ => VerifyResult::Invalid,
        }
    }
}

#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NewVerifierResult {
    Ok,
    InvalidArgument,
    Failed,
}

/// Get the recommended RandomX flags
///
/// Does not include:
/// * FLAG_LARGE_PAGES
/// * FLAG_FULL_MEM
/// * FLAG_SECURE
///
/// The above flags need to be set manually, if required.
#[no_mangle]
pub extern "C" fn recommended_pow_flags() -> RandomXFlag {
    RandomXFlag::get_recommended_flags()
}

#[no_mangle]
pub extern "C" fn new_verifier(flags: RandomXFlag, out: *mut *mut Verifier) -> NewVerifierResult {
    if out.is_null() {
        return NewVerifierResult::InvalidArgument;
    }
    match PoW::new(flags) {
        Ok(verifier) => {
            unsafe { *out = Box::into_raw(Box::new(Verifier::new(Box::new(verifier)))) };
            NewVerifierResult::Ok
        }

        Err(e) => {
            log::error!("{e:?}");
            NewVerifierResult::Failed
        }
    }
}

#[no_mangle]
pub extern "C" fn free_verifier(verifier: *mut Verifier) {
    if verifier.is_null() {
        return;
    }
    unsafe { drop(Box::from_raw(verifier)) };
}

/// Verify the proof
///
/// # Safety
/// - `verifier` must be initialized and properly aligned.
/// - `metadata` must be initialized and properly aligned.
#[no_mangle]
pub unsafe extern "C" fn verify_proof(
    verifier: *const Verifier,
    proof: Proof,
    metadata: *const ProofMetadata,
    cfg: ProofConfig,
    init_cfg: InitConfig,
) -> VerifyResult {
    _verify_proof(verifier, proof, metadata, cfg, init_cfg, Mode::All)
}

/// Verify a single index in the proof
///
/// # Safety
/// - `verifier` must be initialized and properly aligned.
/// - `metadata` must be initialized and properly aligned.
#[no_mangle]
pub unsafe extern "C" fn verify_proof_index(
    verifier: *const Verifier,
    proof: Proof,
    metadata: *const ProofMetadata,
    cfg: ProofConfig,
    init_cfg: InitConfig,
    index: usize,
) -> VerifyResult {
    _verify_proof(
        verifier,
        proof,
        metadata,
        cfg,
        init_cfg,
        Mode::One { index },
    )
}

/// Verify a subset of indexes in the proof
///
/// # Safety
/// - `verifier` must be initialized and properly aligned.
/// - `metadata` must be initialized and properly aligned.
/// - the caller must uphold the safety contract for `from_raw_parts`.
#[no_mangle]
pub unsafe extern "C" fn verify_proof_subset(
    verifier: *const Verifier,
    proof: Proof,
    metadata: *const ProofMetadata,
    cfg: ProofConfig,
    init_cfg: InitConfig,
    k3: usize,
    seed_ptr: *const u8,
    seed_len: usize,
) -> VerifyResult {
    _verify_proof(
        verifier,
        proof,
        metadata,
        cfg,
        init_cfg,
        Mode::Subset {
            k3,
            seed: std::slice::from_raw_parts(seed_ptr, seed_len),
        },
    )
}

unsafe fn _verify_proof(
    verifier: *const Verifier,
    proof: Proof,
    metadata: *const ProofMetadata,
    cfg: ProofConfig,
    init_cfg: InitConfig,
    mode: Mode,
) -> VerifyResult {
    let verifier = match verifier.as_ref() {
        Some(verifier) => verifier,
        None => {
            log::error!("Verifier is null");
            return VerifyResult::InvalidArgument;
        }
    };

    let metadata = match unsafe { metadata.as_ref() } {
        Some(metadata) => metadata,
        None => return VerifyResult::InvalidArgument,
    };

    match verifier.verify(&proof.into(), metadata, &cfg, &init_cfg, mode) {
        Ok(_) => VerifyResult::Ok,
        Err(err) => {
            log::error!("Proof is invalid: {err}");
            err.into()
        }
    }
}

#[cfg(test)]
mod tests {
    use std::ptr::null;

    use post::{
        config::ScryptParams, initialize::Initialize, metadata::ProofMetadata,
        pow::randomx::RandomXFlag,
    };

    use crate::post_impl::{free_verifier, verify_proof, verify_proof_index, verify_proof_subset};

    #[test]
    fn datadir_must_be_utf8() {
        let datadir = std::ffi::CString::new([159, 146, 150]).unwrap();
        let cfg = super::ProofConfig {
            k1: 10,
            k2: 20,
            pow_difficulty: [0xFF; 32],
        };
        let result = super::_generate_proof(
            datadir.as_ptr(),
            [0u8; 32].as_ptr(),
            cfg,
            1,
            0,
            Default::default(),
        );
        assert!(result.unwrap_err().to_string().contains("Utf8Error"));
    }

    #[test]
    fn create_and_free_verifier() {
        let mut verifier = std::ptr::null_mut();
        let result = super::new_verifier(RandomXFlag::default(), &mut verifier);
        assert_eq!(result, super::NewVerifierResult::Ok);
        assert!(!verifier.is_null());
        super::free_verifier(verifier);
    }

    #[test]
    fn create_verifier_with_null_out() {
        let result = super::new_verifier(RandomXFlag::default(), std::ptr::null_mut());
        assert_eq!(result, super::NewVerifierResult::InvalidArgument);
    }

    #[test]
    fn verify_proof_detects_null_params() {
        let proof = super::Proof {
            nonce: 0,
            indices: crate::ArrayU8::default(),
            pow: 0,
        };
        let cfg = super::ProofConfig {
            k1: 1,
            k2: 2,
            pow_difficulty: [0xFF; 32],
        };
        let init_cfg = super::InitConfig {
            min_num_units: 1,
            max_num_units: 1,
            labels_per_unit: 1,
            scrypt: ScryptParams::new(2, 1, 1),
        };
        // null verifier
        let result = unsafe { verify_proof(null(), proof, null(), cfg, init_cfg) };
        assert_eq!(result, super::VerifyResult::InvalidArgument);

        let mut verifier = std::ptr::null_mut();
        let result = super::new_verifier(RandomXFlag::default(), &mut verifier);
        assert_eq!(result, super::NewVerifierResult::Ok);
        assert!(!verifier.is_null());

        // null metadata
        let result = unsafe { verify_proof(verifier, proof, null(), cfg, init_cfg) };
        free_verifier(verifier);
        assert_eq!(result, super::VerifyResult::InvalidArgument);
    }

    #[test]
    fn test_end_to_end() {
        // Initialize some data first
        let datadir = tempfile::tempdir().unwrap();

        let cfg = post::config::ProofConfig {
            k1: 10,
            k2: 10,
            pow_difficulty: [
                0x0f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                0xff, 0xff, 0xff, 0xff,
            ],
        };

        let init_cfg = post::config::InitConfig {
            min_num_units: 1,
            max_num_units: 2,
            labels_per_unit: 200,
            scrypt: ScryptParams::new(2, 1, 1),
        };

        let meta = post::initialize::CpuInitializer::new(init_cfg.scrypt)
            .initialize(
                datadir.path(),
                &[77; 32],
                &[0u8; 32],
                init_cfg.labels_per_unit,
                2,
                100,
                None,
            )
            .unwrap();

        let pow_flags = RandomXFlag::get_recommended_flags();

        // Create verifier
        let mut verifier = std::ptr::null_mut();
        let result = super::new_verifier(pow_flags, &mut verifier);
        assert_eq!(result, super::NewVerifierResult::Ok);
        assert!(!verifier.is_null());

        let challenge = b"hello world, challenge me!!!!!!!";

        // Create proof
        let data_dir_cstr = std::ffi::CString::new(datadir.path().to_str().unwrap()).unwrap();
        let proof_ptr = crate::post_impl::generate_proof(
            data_dir_cstr.as_ptr(),
            challenge.as_ptr(),
            cfg,
            16,
            1,
            pow_flags,
        );
        let proof = unsafe { *proof_ptr };

        let metadata = ProofMetadata::new(meta, *challenge);
        let result = unsafe { verify_proof(verifier, proof, &metadata, cfg, init_cfg) };
        assert_eq!(result, super::VerifyResult::Ok);

        // Modify the proof to have different k2pow
        let proof = crate::post_impl::Proof {
            pow: (proof).pow - 1,
            ..proof
        };

        let result = unsafe { verify_proof(verifier, proof, &metadata, cfg, init_cfg) };
        assert_eq!(result, super::VerifyResult::Invalid);

        let result = unsafe { verify_proof_index(verifier, proof, &metadata, cfg, init_cfg, 0) };
        assert_eq!(result, super::VerifyResult::Invalid);

        let seed = &[];
        let result = unsafe {
            verify_proof_subset(
                verifier,
                proof,
                &metadata,
                cfg,
                init_cfg,
                0,
                seed.as_ptr(),
                seed.len(),
            )
        };
        assert_eq!(result, super::VerifyResult::Invalid);

        unsafe { super::free_proof(proof_ptr) };
        super::free_verifier(verifier);
    }
}
