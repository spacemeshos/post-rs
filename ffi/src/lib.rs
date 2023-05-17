mod initialization;
mod log;
mod post_impl;

#[repr(C)]
pub struct ArrayU8 {
    ptr: *mut u8,
    len: usize,
    cap: usize,
}
