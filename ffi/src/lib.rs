mod initialization;
mod log;
mod post_impl;
mod version;

#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct ArrayU8 {
    ptr: *mut u8,
    len: usize,
    cap: usize,
}

impl Default for ArrayU8 {
    fn default() -> Self {
        Self {
            ptr: std::ptr::null_mut(),
            len: 0,
            cap: 0,
        }
    }
}
