use std::{
    fmt::{Debug, Formatter},
    mem::ManuallyDrop,
    sync::Once,
};

pub use log::LevelFilter;
use log::{Level, Log, Metadata, Record};
use simple_logger::SimpleLogger;

/// Configure logging for the library.
#[no_mangle]
pub extern "C" fn set_log_level(level: LevelFilter) -> i32 {
    match SimpleLogger::new().with_level(level).init() {
        Ok(_) => 0,
        Err(e) => {
            eprintln!("Failed to initialize logging: {e:?}");
            -1
        }
    }
}

/// FFI-safe borrowed Rust &str. Can represent `Option<&str>` by setting ptr to null.
#[repr(C)]
pub struct CStr {
    pub ptr: *const u8,
    pub len: usize,
}

impl CStr {
    pub unsafe fn to_str<'a>(&self) -> &'a str {
        let bytes = std::slice::from_raw_parts(self.ptr, self.len);
        std::str::from_utf8_unchecked(bytes)
    }
}

impl<'a> From<&'a str> for CStr {
    fn from(s: &'a str) -> Self {
        Self {
            ptr: s.as_ptr(),
            len: s.len(),
        }
    }
}

impl From<Option<&str>> for CStr {
    fn from(other: Option<&str>) -> Self {
        if let Some(s) = other {
            Self::from(s)
        } else {
            Self {
                ptr: std::ptr::null(),
                len: 0,
            }
        }
    }
}

/// FFI-safe owned Rust String.
#[repr(C)]
pub struct CString {
    pub ptr: *mut u8,
    pub cap: usize,
    pub len: usize,
}

impl CString {
    unsafe fn to_str<'a>(&self) -> &'a str {
        CStr {
            ptr: self.ptr,
            len: self.len,
        }
        .to_str()
    }
}

impl From<String> for CString {
    fn from(s: String) -> Self {
        let mut me = ManuallyDrop::new(s);
        let (ptr, len, cap) = (me.as_mut_ptr(), me.len(), me.capacity());
        Self { ptr, len, cap }
    }
}

impl Drop for CString {
    fn drop(&mut self) {
        unsafe {
            String::from_raw_parts(self.ptr, self.len, self.cap);
        }
    }
}

impl Debug for CString {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        unsafe { self.to_str() }.fmt(f)
    }
}

impl Debug for CStr {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        unsafe { self.to_str() }.fmt(f)
    }
}

#[repr(C)]
#[derive(Debug)]
pub struct ExternCRecord {
    pub level: Level,
    pub message: CString,  // Preformatted message
    pub module_path: CStr, // None points to null
    pub file: CStr,        // None points to null
    pub line: i64,         // None maps to -1, everything else should fit in u32.
}

impl<'a> From<&Record<'a>> for ExternCRecord {
    fn from(record: &Record<'a>) -> Self {
        Self {
            level: record.level(),
            message: CString::from(record.args().to_string()),
            module_path: CStr::from(record.module_path()),
            file: CStr::from(record.file()),
            line: record.line().map(|u| u as i64).unwrap_or(-1_i64),
        }
    }
}

static mut LOGGER: Option<ExternCLog> = None;
static SET_LOGGER: Once = Once::new();

struct ExternCLog {
    callback: extern "C" fn(&ExternCRecord),
}

impl ExternCLog {
    fn new(callback: extern "C" fn(&ExternCRecord)) -> Self {
        Self { callback }
    }
}

impl Log for ExternCLog {
    fn enabled(&self, _metadata: &Metadata) -> bool {
        true
    }

    fn log(&self, record: &Record) {
        (self.callback)(&ExternCRecord::from(record));
    }

    fn flush(&self) {}
}

/// Set the logging callback function that accepts a *const c_char.
/// The function is idempotent, calling it more then once will have no effect.
#[no_mangle]
pub extern "C" fn set_logging_callback(callback: extern "C" fn(&ExternCRecord)) {
    SET_LOGGER.call_once(|| {
        unsafe {
            LOGGER = Some(ExternCLog::new(callback));
            _ = log::set_logger(LOGGER.as_ref().unwrap());
        }
        log::set_max_level(log::LevelFilter::Trace);
    });
}

#[cfg(test)]
mod tests {
    use crate::log::ExternCRecord;

    #[test]
    fn configuring_logging() {
        let result = super::set_log_level(log::LevelFilter::Info);
        assert_eq!(0, result);

        log::info!("Hello, world!");
    }

    #[test]
    fn logging_callback() {
        extern "C" fn log_cb(record: &ExternCRecord) {
            assert_eq!("Hello, logger", unsafe { record.message.to_str() });
            assert_eq!(log::Level::Info, record.level);
        }

        super::set_logging_callback(log_cb);
        log::info!("Hello, logger");
    }
}
