#![feature(vec_into_raw_parts)]

use std::{
    ffi::{c_char, c_uchar, CStr},
    mem,
    path::Path,
};

use eyre::Context;
pub use post::config::Config;
pub use post::metadata::ProofMetadata;
pub use post::ScryptParams;
use post::{
    prove,
    verification::{verify, VerifyingParams},
};

#[repr(C)]
pub struct ArrayU8 {
    ptr: *mut u8,
    len: usize,
    cap: usize,
}

#[repr(C)]
pub struct Proof {
    nonce: u32,
    indices: ArrayU8,
    k2_pow: u64,
    k3_pow: u64,
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
        Ok(proof) => proof,
        Err(e) => {
            //TODO(poszu) communicate errors better
            eprintln!("{e:?}");
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
) -> eyre::Result<*mut Proof> {
    let datadir = unsafe { CStr::from_ptr(datadir) };
    let datadir = Path::new(datadir.to_str().context("parsing datadir as UTF-8")?);

    let challenge = unsafe { std::slice::from_raw_parts(challenge, 32) };
    let challenge = challenge.try_into()?;

    let proof = prove::generate_proof(datadir, challenge, cfg, nonces, threads)?;

    let (ptr, len, cap) = proof.indices.into_raw_parts();
    let proof = Box::new(Proof {
        nonce: proof.nonce,
        indices: ArrayU8 { ptr, len, cap },
        k2_pow: proof.k2_pow,
        k3_pow: proof.k3_pow,
    });

    Ok(Box::into_raw(proof))
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
    threads: usize,
) -> VerifyResult {
    let proof = {
        let indices =
            unsafe { Vec::from_raw_parts(proof.indices.ptr, proof.indices.len, proof.indices.cap) };
        post::prove::Proof {
            nonce: proof.nonce,
            indices,
            k2_pow: proof.k2_pow,
            k3_pow: proof.k3_pow,
        }
    };

    let metadata = match unsafe { metadata.as_ref() } {
        Some(metadata) => metadata,
        None => return VerifyResult::InvalidArgument,
    };

    let num_labels = metadata.num_units as u64 * metadata.labels_per_unit;
    let params = match VerifyingParams::new(num_labels, cfg) {
        Ok(params) => params,
        Err(_) => return VerifyResult::InvalidArgument,
    };

    let result = match verify(&proof, metadata, params, threads) {
        Ok(_) => VerifyResult::Ok,
        Err(err) => {
            eprintln!("Proof is invalid: {err}");
            VerifyResult::Invalid
        }
    };
    // avoid deallocating proof.indices as this memory is owned by the other side.
    mem::forget(proof.indices);
    result
}
