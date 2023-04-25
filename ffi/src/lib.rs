mod post_impl;
mod scrypt_ocl;

#[repr(C)]
pub struct ArrayU8 {
    ptr: *mut u8,
    len: usize,
    cap: usize,
}
