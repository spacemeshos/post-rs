use std::fmt::Debug;

use scrypt_ocl::{ocl::Platform, Scrypter};

pub enum Initializer {}

#[repr(u32)]
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum ScryptResult {
    Ok = 0,
    ErrorInvalidLabelsRange = 1,
    OclError = 2,
    InvalidArgument = 3,
}

impl From<scrypt_ocl::ocl::Error> for ScryptResult {
    fn from(_: scrypt_ocl::ocl::Error) -> Self {
        ScryptResult::OclError
    }
}

#[repr(C)]
#[derive(Clone, PartialEq, Eq, Default)]
pub struct Provider {
    name: [u8; 32],
}

impl Debug for Provider {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Provider")
            .field(
                "name",
                &std::ffi::CStr::from_bytes_until_nul(&self.name).unwrap(),
            )
            .finish()
    }
}

/// Returns the number of providers available.
#[no_mangle]
pub extern "C" fn get_providers_count(out: *mut usize) -> ScryptResult {
    if out.is_null() {
        return ScryptResult::InvalidArgument;
    }
    unsafe { *out = scrypt_ocl::get_providers_count() };
    ScryptResult::Ok
}

/// Returns all available providers.
#[no_mangle]
pub extern "C" fn get_providers(out: *mut Provider, out_len: usize) -> ScryptResult {
    if out.is_null() {
        return ScryptResult::InvalidArgument;
    }

    let list_core = if let Ok(ids) = scrypt_ocl::ocl::core::get_platform_ids() {
        ids
    } else {
        return ScryptResult::OclError;
    };
    let platforms = Platform::list_from_core(list_core);

    let out = unsafe { std::slice::from_raw_parts_mut(out, out_len) };

    for (out, platform) in out.iter_mut().zip(platforms.iter()) {
        let name = match platform.name() {
            Ok(name) => name,
            Err(e) => e.into(),
        };
        // Copy over the first out.name.len() - 1 bytes, and then add a null terminator.
        let name = name
            .bytes()
            .take(out.name.len() - 1)
            .chain(std::iter::once(0))
            .collect::<Vec<_>>();
        out.name[..name.len()].copy_from_slice(&name);
    }

    ScryptResult::Ok
}

#[no_mangle]
pub extern "C" fn initialize(
    initializer: *mut Initializer,
    start: u64,
    end: u64,
    out_buffer: *mut u8,
    out_nonce: *mut u64,
) -> ScryptResult {
    let _ = unsafe { Box::from_raw(initializer) };

    let scrypter = unsafe { &mut *(initializer as *mut Scrypter) };
    let len = if let Ok(len) = usize::try_from(end - start) {
        len * 16
    } else {
        return ScryptResult::ErrorInvalidLabelsRange;
    };

    let labels = unsafe { std::slice::from_raw_parts_mut(out_buffer, len) };
    let vrf_nonce = scrypter.scrypt(start..end, labels).unwrap();

    if !out_nonce.is_null() {
        if let Some(nonce) = vrf_nonce {
            unsafe { *out_nonce = nonce };
        } else {
            unsafe { *out_nonce = u64::MAX };
        }
    }
    ScryptResult::Ok
}

#[no_mangle]
pub extern "C" fn new_initializer(
    provider_id: usize,
    n: usize,
    commitment: *const u8,
    vrf_difficulty: *const u8,
) -> *mut Initializer {
    match _new_initializer(provider_id, n, commitment, vrf_difficulty) {
        Ok(initializer) => initializer,
        Err(e) => {
            eprintln!("Error creating initializer: {e:?}");
            std::ptr::null_mut()
        }
    }
}

fn _new_initializer(
    provider_id: usize,
    n: usize,
    commitment: *const u8,
    vrf_difficulty: *const u8,
) -> eyre::Result<*mut Initializer> {
    let commitment = unsafe { std::slice::from_raw_parts(commitment, 32) };
    let commitment = commitment.try_into()?;

    let vrf_difficulty = if vrf_difficulty.is_null() {
        None
    } else {
        let vrf_difficulty = unsafe { std::slice::from_raw_parts(vrf_difficulty, 32) };
        Some(vrf_difficulty.try_into()?)
    };

    let scrypter = Box::new(scrypt_ocl::Scrypter::new(
        Some(provider_id),
        n,
        commitment,
        vrf_difficulty,
    )?);

    Ok(Box::into_raw(scrypter) as *mut Initializer)
}

#[no_mangle]
pub extern "C" fn free_initializer(initializer: *mut Initializer) {
    unsafe { Box::from_raw(initializer) };
}

#[cfg(test)]
mod tests {
    use std::{mem::forget, ptr::null_mut};

    use post::ScryptParams;

    use crate::scrypt_ocl::ScryptResult;

    #[test]
    fn initialization() {
        let indices = 0..70;

        let initializer = super::new_initializer(0, 32, [0u8; 32].as_ptr(), std::ptr::null());

        let mut labels = vec![0u8; 70 * 16];
        let result = super::initialize(
            initializer,
            indices.start,
            indices.end,
            labels.as_mut_ptr(),
            null_mut(),
        );
        assert_eq!(ScryptResult::Ok, result);

        let mut expected =
            Vec::<u8>::with_capacity(usize::try_from(indices.end - indices.start).unwrap());

        post::initialize::initialize_to(
            &mut expected,
            &[0u8; 32],
            indices,
            ScryptParams::new(4, 0, 0),
        )
        .unwrap();

        assert_eq!(expected, labels);

        forget(labels); // Will be deallocated in free_initialization_result()
        super::free_initializer(initializer);
    }

    #[test]
    fn get_providers_count() {
        assert_eq!(
            ScryptResult::InvalidArgument,
            super::get_providers_count(null_mut())
        );

        let mut count = 0usize;
        let result = super::get_providers_count(&mut count as *mut usize);
        assert_eq!(ScryptResult::Ok, result);
        assert!(dbg!(count) > 0);
    }

    #[test]
    fn get_providers() {
        let mut count = 0usize;
        let result = super::get_providers_count(&mut count as *mut usize);
        assert_eq!(ScryptResult::Ok, result);

        let mut providers = vec![super::Provider::default(); count];

        assert_eq!(
            ScryptResult::Ok,
            super::get_providers(providers.as_mut_ptr(), count)
        );
        println!("{providers:?}");
    }
}
