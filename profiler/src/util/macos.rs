use std::{error::Error, fs::File, path::Path};

pub(crate) fn open_without_cache(path: &Path) -> Result<File, Box<dyn Error>> {
    let file = File::open(path)?;
    Ok(file)
}
