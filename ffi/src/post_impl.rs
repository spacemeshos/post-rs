use core::slice;
use std::{
    borrow::Cow,
    error::Error,
    ffi::{c_char, c_uchar, CStr},
    mem::ManuallyDrop,
    path::Path,
    sync::atomic::AtomicBool,
};

use post::{
    config::Config,
    metadata::ProofMetadata,
    pow::randomx::{PoW, RandomXFlag},
    prove,
    verification::{Verifier, VerifyingParams},
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
        let indices = unsafe { slice::from_raw_parts(val.indices.ptr, val.indices.len) };

        post::prove::Proof {
            nonce: val.nonce,
            indices: Cow::from(indices),
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
    cfg: Config,
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
    cfg: Config,
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
    Ok,
    Invalid,
    InvalidArgument,
    FailedToCreateVerifier,
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
pub extern "C" fn new_verifier(flags: RandomXFlag, out: *mut *mut Verifier) -> VerifyResult {
    if out.is_null() {
        return VerifyResult::InvalidArgument;
    }
    match PoW::new(flags) {
        Ok(verifier) => {
            unsafe { *out = Box::into_raw(Box::new(Verifier::new(Box::new(verifier)))) };
            VerifyResult::Ok
        }

        Err(e) => {
            log::error!("{e:?}");
            VerifyResult::FailedToCreateVerifier
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

/// Verify a proof
///
/// # Safety
/// `metadata` must be initialized and properly aligned.
#[no_mangle]
pub unsafe extern "C" fn verify_proof(
    verifier: *const Verifier,
    proof: Proof,
    metadata: *const ProofMetadata,
    cfg: Config,
) -> VerifyResult {
    let verifier = match verifier.as_ref() {
        Some(verifier) => verifier,
        None => {
            log::error!("Verifier is null");
            return VerifyResult::InvalidArgument;
        }
    };

    let proof = match proof.try_into() {
        Ok(proof) => proof,
        Err(err) => {
            log::error!("Invalid proof: {err}");
            return VerifyResult::InvalidArgument;
        }
    };

    let metadata = match unsafe { metadata.as_ref() } {
        Some(metadata) => metadata,
        None => return VerifyResult::InvalidArgument,
    };

    let params = match VerifyingParams::new(metadata, &cfg) {
        Ok(params) => params,
        Err(_) => return VerifyResult::InvalidArgument,
    };

    match verifier.verify(&proof, metadata, params) {
        Ok(_) => VerifyResult::Ok,
        Err(err) => {
            log::error!("Proof is invalid: {err}");
            VerifyResult::Invalid
        }
    }
}

#[cfg(test)]
mod tests {
    use post::{
        config::ScryptParams, initialize::Initialize, metadata::ProofMetadata,
        pow::randomx::RandomXFlag,
    };

    #[test]
    fn datadir_must_be_utf8() {
        let datadir = std::ffi::CString::new([159, 146, 150]).unwrap();
        let cfg = super::Config {
            k1: 10,
            k2: 20,
            k3: 20,
            pow_difficulty: [0xFF; 32],
            scrypt: ScryptParams::new(2, 1, 1),
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
        assert_eq!(result, super::VerifyResult::Ok);
        assert!(!verifier.is_null());
        super::free_verifier(verifier);
    }

    #[test]
    fn detects_null_verifier() {
        let result = unsafe {
            super::verify_proof(
                std::ptr::null(),
                super::Proof {
                    nonce: 0,
                    indices: crate::ArrayU8::default(),
                    pow: 0,
                },
                std::ptr::null(),
                super::Config {
                    k1: 1,
                    k2: 2,
                    k3: 2,
                    pow_difficulty: [0xFF; 32],
                    scrypt: ScryptParams::new(2, 1, 1),
                },
            )
        };
        assert_eq!(result, super::VerifyResult::InvalidArgument);
    }

    #[test]
    fn test_end_to_end() {
        // Initialize some data first
        let labels_per_unit = 200;
        let datadir = tempfile::tempdir().unwrap();

        let cfg = post::config::Config {
            k1: 10,
            k2: 10,
            k3: 10,
            pow_difficulty: [
                0x0f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                0xff, 0xff, 0xff, 0xff,
            ],
            scrypt: ScryptParams::new(2, 1, 1),
        };

        let meta = post::initialize::CpuInitializer::new(cfg.scrypt)
            .initialize(
                datadir.path(),
                &[77; 32],
                &[0u8; 32],
                labels_per_unit,
                2,
                labels_per_unit,
                None,
            )
            .unwrap();

        let pow_flags = RandomXFlag::get_recommended_flags();

        // Create verifier
        let mut verifier = std::ptr::null_mut();
        let result: crate::post_impl::VerifyResult = super::new_verifier(pow_flags, &mut verifier);
        assert_eq!(result, super::VerifyResult::Ok);
        assert!(!verifier.is_null());

        let challenge = b"hello world, challenge me!!!!!!!";

        // Create proof without miner ID
        let data_dir_cstr = std::ffi::CString::new(datadir.path().to_str().unwrap()).unwrap();
        let cproof = crate::post_impl::generate_proof(
            data_dir_cstr.as_ptr(),
            challenge.as_ptr(),
            cfg,
            16,
            1,
            pow_flags,
        );

        let proof_metadata = ProofMetadata {
            node_id: meta.node_id,
            commitment_atx_id: meta.commitment_atx_id,
            challenge: *challenge,
            num_units: meta.num_units,
            labels_per_unit: meta.labels_per_unit,
        };

        let result =
            unsafe { crate::post_impl::verify_proof(verifier, *cproof, &proof_metadata as _, cfg) };

        assert_eq!(result, super::VerifyResult::Ok);

        // Modify the proof to have different k2pow
        let invalid_proof = unsafe {
            crate::post_impl::Proof {
                pow: (*cproof).pow - 1,
                ..*cproof
            }
        };

        let result = unsafe {
            crate::post_impl::verify_proof(verifier, invalid_proof, &proof_metadata as _, cfg)
        };
        assert_eq!(result, super::VerifyResult::Invalid);

        unsafe { super::free_proof(cproof) };
        super::free_verifier(verifier);
    }
}
