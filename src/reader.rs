use std::{
    fs::{DirEntry, File},
    io::Read,
    path::Path,
};

use itertools::Itertools;
use lazy_static::lazy_static;
use regex::Regex;
use streaming_iterator::{IntoStreamingIterator, StreamingIterator, StreamingIteratorMut};

#[derive(Debug, PartialEq, Eq)]
pub struct Batch {
    pub data: Vec<u8>,
    pub index: u64,
}

pub struct BatchingReader<T>
where
    T: Read,
{
    reader: T,
    index: u64,
    batch_size: usize,
    batch: Batch,
}

impl<T: Read> BatchingReader<T> {
    pub fn new(reader: T, index: u64, batch_size: usize) -> BatchingReader<T> {
        BatchingReader::<T> {
            reader,
            index,
            batch_size,
            batch: Batch {
                data: vec![0; batch_size],
                index: 0,
            },
        }
    }
}

impl<T: Read> Iterator for BatchingReader<T> {
    type Item = Batch;

    fn next(&mut self) -> Option<Self::Item> {
        let mut batch = Batch {
            data: vec![0; self.batch_size],
            index: self.index,
        };

        match self.reader.read(&mut batch.data) {
            Ok(0) => None,
            Ok(n) => {
                batch.data.resize(n, 0);
                self.index += n as u64;
                Some(batch)
            }
            Err(_) => None,
        }
    }
}

impl<T: Read> StreamingIterator for BatchingReader<T> {
    type Item = Batch;

    fn advance(&mut self) {
        self.batch.data.resize(self.batch_size, 0);
        match self.reader.read(&mut self.batch.data) {
            Ok(n) => {
                self.batch.data.resize(n, 0);
                self.index += n as u64;
                self.batch.index = self.index
            }
            Err(_) => self.batch.data.clear(),
        }
    }

    fn get(&self) -> Option<&Self::Item> {
        if self.batch.data.is_empty() {
            None
        } else {
            Some(&self.batch)
        }
    }
}

fn pos_files(datadir: &Path) -> impl Iterator<Item = DirEntry> {
    datadir
        .read_dir()
        .expect("read_dir call failed")
        .filter_map(|entry| match entry {
            Ok(entry) => Some(entry),
            Err(_) => None,
        })
        .filter(|entry| {
            lazy_static! {
                static ref RE: Regex = Regex::new(r"postdata_\d+\.bin").unwrap();
            }
            RE.is_match(entry.path().to_str().unwrap())
        })
        .sorted_by_key(|entry| entry.path())
}

pub fn read_data(datadir: &Path, batch_size: usize) -> impl Iterator<Item = Batch> {
    let mut pos = 0;
    let mut readers = Vec::<BatchingReader<File>>::new();
    for entry in pos_files(datadir) {
        let file = File::open(entry.path()).unwrap();
        let len = file.metadata().unwrap().len();
        readers.push(BatchingReader::new(file, pos, batch_size));
        pos += len
    }

    readers.into_iter().flat_map(|r| r.into_iter())
}

pub fn stream_data(datadir: &Path, batch_size: usize) -> impl StreamingIterator<Item = Batch> {
    let mut pos = 0;
    let mut readers = Vec::<BatchingReader<File>>::new();
    for entry in pos_files(datadir) {
        let file = File::open(entry.path()).unwrap();
        let len = file.metadata().unwrap().len();
        readers.push(BatchingReader::new(file, pos, batch_size));
        pos += len
    }

    readers.into_streaming_iter().flatten()
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
        let reader = BatchingReader::new(file, 0, 16);
        let mut iter = reader.into_iter();
        assert_eq!(
            Some(Batch {
                data: (0..16).collect(),
                index: 0,
            }),
            iter.next()
        );
        assert_eq!(
            Some(Batch {
                data: (16..32).collect(),
                index: 16,
            }),
            iter.next()
        );
        assert_eq!(
            Some(Batch {
                data: (32..40).collect(),
                index: 32,
            }),
            iter.next()
        );
    }

    #[test]
    fn reading_pos_data() {
        let tmp_dir = tempdir().unwrap();
        let data = ["2", "Hello World!", "1", "Welcome Back", ""];
        for (i, part) in data.iter().enumerate() {
            let file_path = tmp_dir.path().join(format!("postdata_{}.bin", i));
            let mut tmp_file = File::create(file_path).unwrap();
            write!(tmp_file, "{}", part).unwrap();
        }
        let expected = data.into_iter().collect::<String>();

        let mut result = String::new();
        let mut next_expected_index = 0;
        for batch in read_data(tmp_dir.path(), 4) {
            assert_eq!(next_expected_index, batch.index);
            result.extend(std::str::from_utf8(&batch.data));
            next_expected_index += batch.data.len() as u64;
        }

        assert_eq!(expected, result);
    }

    #[test]
    fn skip_non_pos_files() {
        let tmp_dir = tempdir().unwrap();
        let file_path = tmp_dir.path().join("other.bin");
        let mut tmp_file = File::create(file_path).unwrap();
        write!(tmp_file, "some data").unwrap();

        assert!(read_data(tmp_dir.path(), 4).next().is_none());
    }
}
