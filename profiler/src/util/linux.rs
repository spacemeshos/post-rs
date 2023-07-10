use std::{fs::File, os::fd::AsRawFd, path::Path};

pub(crate) fn open_without_cache(path: &Path) -> eyre::Result<File> {
    let file = File::open(path)?;

    let ret = unsafe {
        libc::posix_fadvise(
            file.as_raw_fd(),
            0 as libc::off_t,
            0 as libc::off_t,
            libc::POSIX_FADV_DONTNEED,
        )
    };
    eyre::ensure!(ret == 0, format!("posix_fadvise failed: {ret}"));

    Ok(file)
}
