use std::{fs::File, os::fd::AsRawFd, path::Path};

pub(crate) fn open_without_cache(path: &Path) -> eyre::Result<File> {
    let file = File::open(path)?;

    let ret = unsafe { libc::fcntl(file.as_raw_fd(), libc::F_NOCACHE, 1 as libc::c_int) };
    eyre::ensure!(ret == 0, format!("fcntl(F_NOCACHE) failed: {ret}"));

    Ok(file)
}
