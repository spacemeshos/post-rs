use std::{
    fs::{DirEntry, File},
    io::Read,
    path::Path,
};

use itertools::Itertools;
use regex::Regex;

#[derive(Debug, PartialEq, Eq)]
pub(crate) struct Batch {
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

fn pos_files(datadir: &Path) -> impl Iterator<Item = DirEntry> {
    let file_re = Regex::new(r"postdata_\d+\.bin").unwrap();
    datadir
        .read_dir()
        .expect("read_dir call failed")
        .filter_map(|entry| match entry {
            Ok(entry) => Some(entry),
            Err(_) => None,
        })
        .filter(|entry| file_re.is_match(entry.path().to_str().unwrap()))
        .sorted_by_key(|entry| entry.path())
}

pub(crate) fn read_data(
    datadir: &Path,
    batch_size: usize,
    file_size: u64,
) -> impl Iterator<Item = Batch> {
    let mut readers = Vec::<BatchingReader<File>>::new();
    for (id, entry) in pos_files(datadir).enumerate() {
        let pos = id as u64 * file_size;
        let file = File::open(entry.path()).unwrap();
        let pos_file_size = file.metadata().unwrap().len();
        if pos_file_size != file_size {
            eprintln!(
                "corrupted POS file, expected size: {}, actual size: {}",
                file_size, pos_file_size
            );
        }
        readers.push(BatchingReader::new(file, pos, batch_size, file_size));
    }

    readers.into_iter().flatten()
}

#[cfg(test)]
mod tests {
    use std::io::Write;
    use std::{fs::File, io::Cursor};

    use tempfile::tempdir;

    use crate::reader::{Batch, BatchingReader};

    use super::read_data;

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
        for batch in read_data(tmp_dir.path(), file_size as usize, file_size) {
            assert_eq!(next_expected_index, batch.pos);
            result.extend(batch.data);
            next_expected_index += file_size;
        }

        assert_eq!(b"2Hell1Welc", result.as_slice());
    }

    #[test]
    fn skip_non_pos_files() {
        let tmp_dir = tempdir().unwrap();
        let file_path = tmp_dir.path().join("other.bin");
        let mut tmp_file = File::create(file_path).unwrap();
        write!(tmp_file, "some data").unwrap();

        assert!(read_data(tmp_dir.path(), 4, 4).next().is_none());
    }
}