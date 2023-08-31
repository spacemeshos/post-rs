use std::{
    fs::{DirEntry, File},
    io::Read,
    path::Path,
};

use eyre::Context;
use itertools::Itertools;
use regex::Regex;

#[derive(Debug, PartialEq, Eq)]
pub struct Batch {
    pub data: Vec<u8>,
    pub pos: u64,
}

pub(crate) struct BatchingReader<T>
where
    T: Read,
{
    reader: T,
    starting_pos: u64,
    pos: u64,
    batch_size: usize,
    total_size: u64,
}

impl<T: Read> BatchingReader<T> {
    pub fn new(reader: T, pos: u64, batch_size: usize, total_size: u64) -> BatchingReader<T> {
        BatchingReader::<T> {
            reader,
            starting_pos: pos,
            pos,
            batch_size,
            total_size,
        }
    }
}

impl<T: Read> Iterator for BatchingReader<T> {
    type Item = Batch;

    fn next(&mut self) -> Option<Self::Item> {
        // FIXME(poszu) avoid reallocating the vector
        let pos_in_file = self.pos - self.starting_pos;
        if pos_in_file >= self.total_size {
            return None;
        }
        let remaining = self.total_size - pos_in_file;
        let batch_size = self.batch_size.min(remaining as usize);
        let mut data = Vec::with_capacity(batch_size);
        match self
            .reader
            .by_ref()
            .take(batch_size as u64)
            .read_to_end(&mut data)
        {
            Ok(0) => None,
            Ok(n) => {
                let batch = Batch {
                    data,
                    pos: self.pos,
                };
                self.pos += n as u64;
                Some(batch)
            }
            Err(_) => None,
        }
    }
}

pub(crate) fn pos_files(datadir: &Path) -> eyre::Result<impl Iterator<Item = DirEntry>> {
    let file_re = Regex::new(r"^postdata_(\d+)\.bin$").unwrap();
    let files = datadir
        .read_dir()
        .wrap_err_with(|| format!("reading {} directory", datadir.display()))?
        .filter_map(|entry| match entry {
            Ok(entry) => file_re
                .captures(entry.file_name().to_string_lossy().as_ref())
                .and_then(|c| c.get(1).unwrap().as_str().parse::<u64>().ok())
                .map(|id| (id, entry)),
            Err(err) => {
                log::warn!("error reading directory entry: {err}");
                None
            }
        })
        .sorted_by_key(|(id, _)| *id)
        .map(|(_, entry)| entry);

    Ok(files)
}

pub(crate) fn read_data(
    datadir: &Path,
    batch_size: usize,
    file_size: u64,
) -> eyre::Result<impl Iterator<Item = Batch>> {
    let mut readers = Vec::<BatchingReader<File>>::new();
    let mut files = pos_files(datadir)?.enumerate().peekable();

    while let Some((id, entry)) = files.next() {
        let pos = id as u64 * file_size;
        let path = entry.path();
        let file = File::open(&path)?;
        let pos_file_size = file.metadata().unwrap().len();

        // If there are more files, check if the size of the file is correct
        if files.peek().is_some() && pos_file_size != file_size {
            log::warn!(
                "invalid POS file {}, expected size: {file_size} vs actual size: {pos_file_size}",
                path.display(),
            );
        }
        readers.push(BatchingReader::new(file, pos, batch_size, file_size));
    }

    Ok(readers.into_iter().flatten())
}

pub fn read_from<R: Read>(
    reader: R,
    batch_size: usize,
    max_size: u64,
) -> impl Iterator<Item = Batch> {
    BatchingReader::new(reader, 0, batch_size, max_size)
}

#[cfg(test)]
mod tests {
    use std::io::Write;
    use std::{fs::File, io::Cursor};

    use tempfile::tempdir;

    use super::{pos_files, read_data, Batch, BatchingReader};

    #[test]
    fn batching_reader() {
        let data = (0..40).collect::<Vec<u8>>();
        let file = Cursor::new(data);
        let mut reader = BatchingReader::new(file, 0, 16, 40);
        assert_eq!(
            Some(Batch {
                data: (0..16).collect(),
                pos: 0,
            }),
            reader.next()
        );
        assert_eq!(
            Some(Batch {
                data: (16..32).collect(),
                pos: 16,
            }),
            reader.next()
        );
        assert_eq!(
            Some(Batch {
                data: (32..40).collect(),
                pos: 32,
            }),
            reader.next()
        );
        assert_eq!(None, reader.next());
    }

    #[test]
    fn reading_pos_data() {
        let tmp_dir = tempdir().unwrap();
        let data = ["2", "Hello World!", "1", "Welcome Back", ""];
        for (i, part) in data.iter().enumerate() {
            let file_path = tmp_dir.path().join(format!("postdata_{i}.bin"));
            let mut tmp_file = File::create(file_path).unwrap();
            write!(tmp_file, "{part}").unwrap();
        }

        let mut result = Vec::new();
        let mut next_expected_index = 0;
        let file_size = 4u64;
        for batch in read_data(tmp_dir.path(), file_size as usize, file_size).unwrap() {
            assert_eq!(next_expected_index, batch.pos);
            result.extend(batch.data);
            next_expected_index += file_size;
        }

        assert_eq!(b"2Hell1Welc", result.as_slice());
    }

    #[rstest::rstest]
    #[case("other.bin")]
    #[case("_postadata_0.bin")]
    #[case("postadata_0.bin_")]
    #[case("postadata_0_.bin")]
    fn skip_non_pos_files(#[case] filename: &'static str) {
        let tmp_dir = tempdir().unwrap();
        let file_path = tmp_dir.path().join(filename);
        let mut tmp_file = File::create(file_path).unwrap();
        write!(tmp_file, "some data").unwrap();

        assert!(read_data(tmp_dir.path(), 4, 4).unwrap().next().is_none());
    }

    #[test]
    fn pos_files_are_sorted() {
        let tmp_dir = tempdir().unwrap();
        let total_files = 100;
        for i in 0..total_files {
            File::create(tmp_dir.path().join(format!("postdata_{i}.bin"))).unwrap();
        }

        assert_eq!(total_files, pos_files(tmp_dir.path()).unwrap().count());

        for (i, file) in pos_files(tmp_dir.path()).unwrap().enumerate() {
            assert_eq!(
                format!("postdata_{i}.bin"),
                file.file_name().to_string_lossy()
            );
        }
    }
}
