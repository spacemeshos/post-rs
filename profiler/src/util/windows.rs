use std::{ffi::CString, fs::File, path::Path};

use eyre::Context;

use windows::{
    core::PCSTR,
    Win32::{
        Foundation::{CloseHandle, GENERIC_READ, HANDLE},
        Storage::FileSystem::{
            CreateFileA, FILE_FLAG_NO_BUFFERING, FILE_SHARE_READ, OPEN_EXISTING,
        },
    },
};

pub(crate) fn open_without_cache(path: &Path) -> eyre::Result<File> {
    let p = CString::new(path.to_str().ok_or(eyre::eyre!("invalid path"))?)?;
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
    }
    .wrap_err("opening file to drop cache")?;

    unsafe { CloseHandle(handle) }.wrap_err("closing handle")?;

    File::open(path).wrap_err("opening file")
}
