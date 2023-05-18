use std::{
    error::Error,
    ffi::{c_char, c_uchar, CStr},
    mem::{self, ManuallyDrop},
    path::Path,
};

pub use post::config::Config;
pub use post::metadata::ProofMetadata;
pub use post::ScryptParams;
use post::{
    prove,
    verification::{verify, VerifyingParams},
};

use crate::ArrayU8;

#[repr(C)]
#[derive(Debug)]
pub struct Proof {
    nonce: u32,
    indices: ArrayU8,
    k2_pow: u64,
}

/// Deallocate a proof obtained with generate_proof().
/// # Safety
/// `proof` must be a pointer to a Proof struct obtained with generate_proof().
#[no_mangle]
pub unsafe extern "C" fn free_proof(proof: *mut Proof) {
    let proof = Box::from_raw(proof);
    Vec::from_raw_parts(proof.indices.ptr, proof.indices.len, proof.indices.cap);
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
) -> *mut Proof {
    match _generate_proof(datadir, challenge, cfg, nonces, threads) {
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
) -> Result<Box<Proof>, Box<dyn Error>> {
    let datadir = unsafe { CStr::from_ptr(datadir) };
    let datadir = Path::new(
        datadir
            .to_str()
            .map_err(|e| format!("reading datadir: {e:?}"))?,
    );

    let challenge = unsafe { std::slice::from_raw_parts(challenge, 32) };
    let challenge = challenge.try_into()?;

    let proof = prove::generate_proof(datadir, challenge, cfg, nonces, threads)?;

    let mut indices = ManuallyDrop::new(proof.indices);
    let (ptr, len, cap) = (indices.as_mut_ptr(), indices.len(), indices.capacity());
    let proof = Box::new(Proof {
        nonce: proof.nonce,
        indices: ArrayU8 { ptr, len, cap },
        k2_pow: proof.k2_pow,
    });

    Ok(proof)
}

#[repr(C)]
pub enum VerifyResult {
    Ok,
    Invalid,
    InvalidArgument,
}

/// Verify a proof
///
/// # Safety
/// `metadata` must be initialized and properly aligned.
#[no_mangle]
pub unsafe extern "C" fn verify_proof(
    proof: Proof,
    metadata: *const ProofMetadata,
    cfg: Config,
) -> VerifyResult {
    let proof = {
        let indices =
            unsafe { Vec::from_raw_parts(proof.indices.ptr, proof.indices.len, proof.indices.cap) };
        post::prove::Proof {
            nonce: proof.nonce,
            indices,
            k2_pow: proof.k2_pow,
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

    let result = match verify(&proof, metadata, params) {
        Ok(_) => VerifyResult::Ok,
        Err(err) => {
            log::error!("Proof is invalid: {err}");
            VerifyResult::Invalid
        }
    };
    // avoid deallocating proof.indices as this memory is owned by the other side.
    mem::forget(proof.indices);
    result
}

#[cfg(test)]
mod tests {
    #[test]
    fn datadir_must_be_utf8() {
        let datadir = std::ffi::CString::new([159, 146, 150]).unwrap();
        let cfg = super::Config {
            k1: 10,
            k2: 20,
            k3: 20,
            k2_pow_difficulty: u64::MAX,
            pow_scrypt: super::ScryptParams::new(1, 1, 1),
            scrypt: super::ScryptParams::new(1, 1, 1),
        };
        let result = super::_generate_proof(datadir.as_ptr(), [0u8; 32].as_ptr(), cfg, 1, 0);
        assert!(result.unwrap_err().to_string().contains("Utf8Error"));
    }
}
