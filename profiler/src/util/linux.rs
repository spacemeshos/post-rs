use std::{error::Error, fs::File, fs::OpenOptions, os::fd::AsRawFd, path::Path};

pub(crate) fn open_without_cache(path: &Path) -> Result<File, Box<dyn Error>> {
    let file = File::open(path)?;

    let ret = unsafe {
        libc::posix_fadvise(
            file.as_raw_fd(),
            0 as libc::off_t,
            0 as libc::off_t,
            libc::POSIX_FADV_DONTNEED,
        )
    };
    if ret != 0 {
        return Err(format!("posix_fadvise failed: {ret}").into());
    }

    Ok(file)
}
