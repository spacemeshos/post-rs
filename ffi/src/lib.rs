#![feature(vec_into_raw_parts)]

use std::{
    ffi::{c_char, c_uchar, CStr},
    path::Path,
};

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

    //FIXME Figure out how to reuse the Config type instead of duplicating it.
    let cfg = post::config::Config {
        labels_per_unit: cfg.labels_per_unit,
        k1: cfg.k1,
        k2: cfg.k2,
        k2_pow_difficulty: cfg.k2_pow_difficulty,
        k3_pow_difficulty: cfg.k3_pow_difficulty,
        b: cfg.b,
        n: cfg.n,
    };
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
