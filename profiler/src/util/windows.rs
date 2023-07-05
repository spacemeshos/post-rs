use std::{error::Error, ffi::CString, fs::File, path::Path};

use windows::{
    core::PCSTR,
    Win32::{
        Foundation::{CloseHandle, FALSE, GENERIC_READ, HANDLE},
        Storage::FileSystem::{
            CreateFileA, FILE_FLAG_NO_BUFFERING, FILE_SHARE_READ, OPEN_EXISTING,
        },
    },
};

pub(crate) fn open_without_cache(path: &Path) -> Result<File, Box<dyn Error>> {
    let p = CString::new(path.to_str().ok_or("invalid path")?)?;
    let handle = unsafe {
        CreateFileA(
            PCSTR(p.as_ptr() as _),
            GENERIC_READ.0,
            FILE_SHARE_READ,
            None,
            OPEN_EXISTING,
            FILE_FLAG_NO_BUFFERING, // <- drops cache
            HANDLE(0),
        )
    }?;

    if unsafe { CloseHandle(handle) } == FALSE {
        return Err("failed to close file handle".into());
    }

    let f = File::open(path)?;
    Ok(f)
}
