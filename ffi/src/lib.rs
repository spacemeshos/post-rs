mod initialization;
mod log;
mod post_impl;

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

impl<T> From<T> for ArrayU8
where
    T: AsRef<[u8]>,
{
    fn from(t: T) -> Self {
        let slice = t.as_ref();

        Self {
            ptr: slice.as_ptr() as *mut u8,
            len: slice.len(),
            cap: slice.len(),
        }
    }
}

impl ArrayU8 {
    // SAFETY: the caller must uphold the safety contract for `std::slice::from_raw_parts`.
    pub(crate) unsafe fn as_slice(self) -> &'static [u8] {
        std::slice::from_raw_parts(self.ptr, self.len)
    }
}
