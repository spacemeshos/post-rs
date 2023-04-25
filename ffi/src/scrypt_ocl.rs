use scrypt_ocl::Scrypter;

use crate::ArrayU8;

pub enum Initializer {}

#[repr(C)]
pub struct InitializationResult {
    labels: ArrayU8,
    vrf_nonce: u64,
}

#[no_mangle]
pub extern "C" fn initialize(
    initializer: *mut Initializer,
    start: u64,
    end: u64,
) -> *mut InitializationResult {
    let _ = unsafe { Box::from_raw(initializer) };

    let scrypter = unsafe { &mut *(initializer as *mut Scrypter) };
    let (labels, vrf_nonce) = scrypter.scrypt(start..end).unwrap();

    let mut indices = std::mem::ManuallyDrop::new(labels);
    let (ptr, len, cap) = (indices.as_mut_ptr(), indices.len(), indices.capacity());
    let result = Box::new(InitializationResult {
        labels: ArrayU8 { ptr, len, cap },
        vrf_nonce: 0,
    });
    Box::into_raw(result)
}

#[no_mangle]
pub extern "C" fn new_initializer(
    n: usize,
    commitment: *const u8,
    vrf_difficulty: *const u8,
) -> *mut Initializer {
    match _new_initializer(n, commitment, vrf_difficulty) {
        Ok(initializer) => initializer,
        Err(e) => {
            eprintln!("Error creating initializer: {e:?}");
            std::ptr::null_mut()
        }
    }
}

fn _new_initializer(
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

    let scrypter = Box::new(scrypt_ocl::Scrypter::new(n, commitment, vrf_difficulty)?);

    Ok(Box::into_raw(scrypter) as *mut Initializer)
}

#[no_mangle]
pub extern "C" fn free_initializer(initializer: *mut Initializer) {
    let _ = unsafe { Box::from_raw(initializer) };
}

#[no_mangle]
pub extern "C" fn free_initialization_result(result: *mut InitializationResult) {
    let result = unsafe { Box::from_raw(result) };
    unsafe { Vec::from_raw_parts(result.labels.ptr, result.labels.len, result.labels.cap) };
}

#[cfg(test)]
mod tests {
    use std::mem::forget;

    use post::ScryptParams;

    #[test]
    fn initialization() {
        let indices = 0..70;

        let initializer = super::new_initializer(32, [0u8; 32].as_ptr(), std::ptr::null());

        let result = super::initialize(initializer, indices.start, indices.end);
        let labels = unsafe {
            Vec::from_raw_parts(
                (*result).labels.ptr,
                (*result).labels.len,
                (*result).labels.cap,
            )
        };

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
        super::free_initialization_result(result);
    }
}
