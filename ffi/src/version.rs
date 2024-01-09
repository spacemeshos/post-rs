use std::ffi::{c_char, CStr};

const VERSION: &str = concat!(env!("CARGO_PKG_VERSION"), "\0");

#[no_mangle]
pub extern "C" fn version() -> *const c_char {
    unsafe { CStr::from_bytes_with_nul_unchecked(VERSION.as_bytes()) }.as_ptr()
}

#[cfg(test)]
mod tests {
    #[test]
    fn test_version() {
        let version = unsafe { std::ffi::CStr::from_ptr(super::version()) };
        assert_eq!(version.to_str().unwrap(), env!("CARGO_PKG_VERSION"));
    }
}
