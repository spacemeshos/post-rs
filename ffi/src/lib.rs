#![feature(vec_into_raw_parts)]

use std::{
    ffi::{c_char, c_uchar, CStr},
    path::Path,
};

pub use post::config::Config;
use post::prove;

#[repr(C)]
pub struct ArrayU64 {
    ptr: *mut u64,
    len: usize,
    cap: usize,
}

#[repr(C)]
pub struct Proof {
    nonce: u32,
    indicies: ArrayU64,
    k2_pow: u64,
    k3_pow: u64,
}

/// # Safety
/// proof must not be a null pointer.
#[no_mangle]
pub unsafe extern "C" fn free_proof(proof: *mut Proof) {
    let proof = Box::from_raw(proof);
    Vec::from_raw_parts(proof.indicies.ptr, proof.indicies.len, proof.indicies.cap);
    // proof and vec will be deallocated on return
}

/// Generate a proof
#[no_mangle]
pub extern "C" fn generate_proof(
    datadir: *const c_char,
    challenge: *const c_uchar,
    challenge_len: usize,
    cfg: Config,
) -> *mut Proof {
    match _generate_proof(datadir, challenge, challenge_len, cfg) {
        Ok(proof) => proof,
        Err(e) => {
            //TODO(brozansk) communicate errors better
            eprintln!("{e:?}");
            std::ptr::null_mut()
        }
    }
}

fn _generate_proof(
    datadir: *const c_char,
    challenge: *const c_uchar,
    challenge_len: usize,
    cfg: Config,
) -> eyre::Result<*mut Proof> {
    let datadir = unsafe { CStr::from_ptr(datadir) };
    let datadir = datadir.to_str().expect("Invalid UTF-8 string");
    let datadir = Path::new(datadir);

    let challenge = unsafe { std::slice::from_raw_parts(challenge, challenge_len) };
    let challenge = challenge.try_into()?;

    let proof = prove::generate_proof(datadir, challenge, cfg)?;

    let (ptr, len, cap) = proof.indicies.into_raw_parts();
    let proof = Box::new(Proof {
        nonce: proof.nonce,
        indicies: ArrayU64 { ptr, len, cap },
        k2_pow: proof.k2_pow,
        k3_pow: proof.k3_pow,
    });

    Ok(Box::into_raw(proof))
}
