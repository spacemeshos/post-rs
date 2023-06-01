mod initialization;
mod log;
mod post_impl;

#[repr(C)]
#[derive(Debug)]
pub struct ArrayU8 {
    ptr: *mut u8,
    len: usize,
    cap: usize,
}

impl<T> From<T> for ArrayU8
where
    T: AsRef<[u8]>,
{
    fn from(value: T) -> Self {
        let s = value.as_ref();
        Self {
            ptr: s.as_ptr() as _,
            len: s.len(),
            cap: s.len(),
        }
    }
}
