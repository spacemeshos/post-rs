use std::fmt::Debug;

use scrypt_ocl::{ocl::DeviceType, ProviderId, Scrypter};

pub enum Initializer {}

#[repr(C)]
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
#[allow(clippy::enum_variant_names)]
pub enum InitializeResult {
    InitializeOk = 0,
    InitializeInvalidLabelsRange = 1,
    InitializeOclError = 2,
    InitializeInvalidArgument = 3,
    InitializeFailedToGetProviders = 4,
}

impl From<scrypt_ocl::ocl::Error> for InitializeResult {
    fn from(_: scrypt_ocl::ocl::Error) -> Self {
        InitializeResult::InitializeOclError
    }
}

#[repr(C)]
#[derive(Clone, PartialEq, Eq)]
pub struct Provider {
    name: [u8; 64],
    id: u32,
    class: DeviceClass,
}

#[repr(C)]
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum DeviceClass {
    CPU,
    GPU,
    UNKNOWN,
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
pub extern "C" fn get_providers_count() -> usize {
    scrypt_ocl::get_providers_count()
}

/// Returns all available providers.
#[no_mangle]
pub extern "C" fn get_providers(out: *mut Provider, out_len: usize) -> InitializeResult {
    if out.is_null() {
        return InitializeResult::InitializeInvalidArgument;
    }

    let providers = if let Ok(p) = scrypt_ocl::get_providers() {
        p
    } else {
        return InitializeResult::InitializeFailedToGetProviders;
    };

    let out = unsafe { std::slice::from_raw_parts_mut(out, out_len) };

    for (id, (out, provider)) in out.iter_mut().zip(providers.iter()).enumerate() {
        // Copy over the first out.name.len() - 1 bytes, and then add a null terminator.
        let name = format!("{provider}")
            .bytes()
            .take(out.name.len() - 1)
            .chain(std::iter::once(0))
            .collect::<Vec<_>>();
        out.name[..name.len()].copy_from_slice(&name);
        out.id = id as u32;
        out.class = match provider.class {
            class if class.intersects(DeviceType::GPU) => DeviceClass::GPU,
            class if class.intersects(DeviceType::CPU) => DeviceClass::CPU,
            _ => DeviceClass::UNKNOWN,
        }
    }

    InitializeResult::InitializeOk
}

/// Initializes labels for the given range.
///
/// start and end are inclusive.
#[no_mangle]
pub extern "C" fn initialize(
    initializer: *mut Initializer,
    start: u64,
    end: u64,
    out_buffer: *mut u8,
    out_nonce: *mut u64,
) -> InitializeResult {
    // Convert end to exclusive
    if end == u64::MAX {
        return InitializeResult::InitializeInvalidLabelsRange;
    }
    let end = end + 1;
    let _ = unsafe { Box::from_raw(initializer) };

    let scrypter = unsafe { &mut *(initializer as *mut Scrypter) };
    let len = if let Ok(len) = usize::try_from(end - start) {
        len * 16
    } else {
        return InitializeResult::InitializeInvalidLabelsRange;
    };

    let labels = unsafe { std::slice::from_raw_parts_mut(out_buffer, len) };
    let vrf_nonce = scrypter.scrypt(start..end, labels).unwrap();

    if !out_nonce.is_null() {
        if let Some(nonce) = vrf_nonce {
            unsafe { *out_nonce = nonce.index };
        } else {
            unsafe { *out_nonce = u64::MAX };
        }
    }
    InitializeResult::InitializeOk
}

#[no_mangle]
pub extern "C" fn new_initializer(
    provider_id: u32,
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
    provider_id: u32,
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
        Some(ProviderId(provider_id)),
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

    use crate::scrypt_ocl::InitializeResult;

    #[test]
    fn cant_initialize_more_than_2_64_labels() {
        let initializer = super::new_initializer(0, 32, [0u8; 32].as_ptr(), std::ptr::null());

        let mut labels = Vec::new();
        let result = super::initialize(initializer, 0, u64::MAX, labels.as_mut_ptr(), null_mut());
        assert_eq!(InitializeResult::InitializeInvalidLabelsRange, result);
    }

    #[test]
    fn initialization() {
        let indices = 0..=70;

        let initializer = super::new_initializer(0, 32, [0u8; 32].as_ptr(), std::ptr::null());

        let mut labels = vec![0u8; 71 * 16];
        let result = super::initialize(
            initializer,
            *indices.start(),
            *indices.end(),
            labels.as_mut_ptr(),
            null_mut(),
        );
        assert_eq!(InitializeResult::InitializeOk, result);

        let mut expected = Vec::<u8>::with_capacity(indices.clone().count());

        post::initialize::initialize_to(
            &mut expected,
            &[0u8; 32],
            *indices.start()..*indices.end() + 1,
            ScryptParams::new(4, 0, 0),
        )
        .unwrap();

        assert_eq!(expected, labels);

        forget(labels); // Will be deallocated in free_initialization_result()
        super::free_initializer(initializer);
    }

    #[test]
    fn get_providers_count() {
        let count = super::get_providers_count();
        assert!(dbg!(count) > 0);
    }

    #[test]
    fn get_providers() {
        let count = super::get_providers_count();
        let mut providers = vec![
            super::Provider {
                name: [0u8; 64],
                id: 0,
                class: super::DeviceClass::CPU
            };
            count
        ];

        assert_eq!(
            InitializeResult::InitializeOk,
            super::get_providers(providers.as_mut_ptr(), count)
        );
        println!("{providers:?}");
    }
}
