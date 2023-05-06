use std::{
    error::Error,
    fs::{create_dir_all, File},
    io::Write,
    ops::Range,
    path::Path,
};

use rayon::prelude::{IntoParallelIterator, ParallelIterator};
use scrypt_jane::scrypt::{scrypt, ScryptParams};

use crate::metadata::PostMetadata;

pub const LABEL_SIZE: usize = 16;
pub const ENTIRE_LABEL_SIZE: usize = 32;

pub fn calc_commitment(node_id: &[u8; 32], commitment_atx_id: &[u8; 32]) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(node_id);
    hasher.update(commitment_atx_id);
    hasher.finalize().into()
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VrfNonce {
    pub index: u64,
    pub label: [u8; 32],
}

pub trait Initialize {
    #[allow(clippy::too_many_arguments)]
    fn initialize(
        &mut self,
        datadir: &Path,
        node_id: &[u8; 32],
        commitment_atx_id: &[u8; 32],
        labels_per_unit: u64,
        num_units: u32,
        labels_per_file: u64,
        mut vrf_difficulty: Option<[u8; 32]>,
    ) -> Result<PostMetadata, Box<dyn Error>> {
        // Ensure that datadir exists
        create_dir_all(datadir)?;

        let commitment = calc_commitment(node_id, commitment_atx_id);

        let total_labels = labels_per_unit * num_units as u64;

        let mut files_number = total_labels / labels_per_file;
        if total_labels % labels_per_file != 0 {
            files_number += 1;
        }
        let mut nonce = None;
        for file_id in 0..files_number {
            let mut post_data = File::create(datadir.join(format!("postdata_{}.bin", file_id)))?;
            let index = file_id * labels_per_file;
            let labels = index..total_labels.min(index + labels_per_file);
            let new_nonce =
                self.initialize_to(&mut post_data, &commitment, labels, vrf_difficulty)?;
            if let Some(n) = new_nonce {
                vrf_difficulty = Some(n.label);
                nonce = Some(n);
            }
        }

        let metadata = PostMetadata {
            node_id: *node_id,
            commitment_atx_id: *commitment_atx_id,
            labels_per_unit,
            num_units,
            max_file_size: labels_per_file * 16,
            nonce: nonce.map(|n| n.index),
            last_position: None,
        };
        let metadata_file = File::create(datadir.join("postdata_metadata.json"))?;
        serde_json::to_writer_pretty(metadata_file, &metadata)?;

        Ok(metadata)
    }

    fn initialize_to(
        &mut self,
        writer: &mut dyn Write,
        commitment: &[u8; 32],
        labels: Range<u64>,
        vrf_difficulty: Option<[u8; 32]>,
    ) -> Result<Option<VrfNonce>, Box<dyn Error>>;
}

pub struct CpuInitializer {
    scrypt_params: ScryptParams,
}

impl CpuInitializer {
    pub fn new(scrypt_params: ScryptParams) -> Self {
        Self { scrypt_params }
    }
}

impl Initialize for CpuInitializer {
    fn initialize_to(
        &mut self,
        writer: &mut dyn Write,
        commitment: &[u8; 32],
        labels: Range<u64>,
        mut vrf_difficulty: Option<[u8; 32]>,
    ) -> Result<Option<VrfNonce>, Box<dyn Error>> {
        log::trace!("Initializing labels {:?}...", labels);
        let data = labels
            .clone()
            .into_par_iter()
            .map(|index| {
                let mut label = [0u8; 32];
                let mut scrypt_data = [0u8; 72];
                scrypt_data[0..32].copy_from_slice(commitment);
                scrypt_data[32..40].copy_from_slice(&index.to_le_bytes());
                scrypt(&scrypt_data, &[], self.scrypt_params, &mut label);
                label
            })
            .collect::<Vec<_>>();

        let mut best_nonce = None;
        for (id, label) in data.into_iter().enumerate() {
            if let Some(difficulty) = vrf_difficulty {
                if label < difficulty {
                    best_nonce = Some(VrfNonce {
                        index: labels.start + id as u64,
                        label,
                    });
                    vrf_difficulty = Some(label);
                    log::trace!("Found new smallest nonce: {best_nonce:?}");
                }
            }
            writer.write_all(&label[..16])?;
        }

        Ok(best_nonce)
    }
}

#[inline]
pub(crate) fn generate_label(commitment: &[u8; 32], params: ScryptParams, index: u64) -> [u8; 16] {
    let mut label = [0u8; 16];
    CpuInitializer::new(params)
        .initialize_to(
            &mut label.as_mut_slice(),
            commitment,
            index..index + 1,
            None,
        )
        .expect("initializing a label");
    label
}

#[cfg(test)]
mod tests {
    use std::io::Read;

    use crate::{metadata, reader};

    use super::*;

    #[test]
    fn test_initialize_to_file() {
        let labels = 7..27;
        let expected_size = (labels.end - labels.start) * 16;

        let mut pos_file = tempfile::tempfile().unwrap();
        let commitment = [0u8; 32];
        let scrypt_params = ScryptParams::new(1, 0, 0);
        CpuInitializer::new(scrypt_params)
            .initialize_to(&mut pos_file, &commitment, labels, None)
            .unwrap();

        assert_eq!(expected_size, pos_file.metadata().unwrap().len());
    }

    #[test]
    fn test_initialize_fits_in_single_file() {
        let scrypt_params = ScryptParams::new(1, 0, 0);
        let data_dir = tempfile::tempdir().unwrap();
        let data_path = data_dir.path();
        CpuInitializer::new(scrypt_params)
            .initialize(data_path, &[0u8; 32], &[0u8; 32], 100, 10, 2000, None)
            .unwrap();

        assert!(data_path.join("postdata_metadata.json").exists());
        assert!(data_path.join("postdata_0.bin").exists());

        for entry in std::fs::read_dir(data_path).unwrap() {
            let path = entry.unwrap().path();
            if path.extension().unwrap() == "bin" {
                assert_eq!(Some("postdata_0.bin".as_ref()), path.file_name());
                assert_eq!(16000, path.metadata().unwrap().len());
            } else {
                assert_eq!(Some("postdata_metadata.json".as_ref()), path.file_name());
            }
        }
    }

    #[test]
    fn test_initialize_returns_metadata() {
        let scrypt_params = ScryptParams::new(1, 0, 0);
        let data_dir = tempfile::tempdir().unwrap();
        let node_id = rand::random::<[u8; 32]>();
        let commitment_atx_id = rand::random::<[u8; 32]>();
        let metadata = CpuInitializer::new(scrypt_params)
            .initialize(
                data_dir.path(),
                &node_id,
                &commitment_atx_id,
                10,
                2,
                15,
                None,
            )
            .unwrap();

        assert_eq!(node_id, metadata.node_id);
        assert_eq!(commitment_atx_id, metadata.commitment_atx_id);
        assert_eq!(10, metadata.labels_per_unit);
        assert_eq!(2, metadata.num_units);
        assert_eq!(16 * 15, metadata.max_file_size);
        assert_eq!(None, metadata.nonce);
        assert_eq!(None, metadata.last_position);
    }

    #[test]
    fn test_initialize_split_many_files() {
        let scrypt_params = ScryptParams::new(1, 0, 0);
        let data_dir = tempfile::tempdir().unwrap();
        let data_path = data_dir.path();
        CpuInitializer::new(scrypt_params)
            .initialize(data_path, &[0u8; 32], &[0u8; 32], 100, 10, 15, None)
            .unwrap();

        assert!(data_path.join("postdata_metadata.json").exists());
        for id in 0..67 {
            assert!(data_path.join(format!("postdata_{}.bin", id)).exists());
        }
        assert!(!data_path.join("postdata_67.bin").exists());

        let mut total_size = 0;
        for entry in std::fs::read_dir(data_path).unwrap() {
            let path = entry.unwrap().path();
            let size = path.metadata().unwrap().len();
            match path.file_name().unwrap().to_str().unwrap() {
                "postdata_metadata.json" => {}
                "postdata_66.bin" => {
                    assert_eq!(16 * 10, size); // Last one is smaller
                    total_size += size;
                }
                _ => {
                    assert_eq!(16 * 15, size);
                    total_size += size;
                }
            }
        }
        assert_eq!(16000, total_size);
    }

    #[test]
    fn initialization_to_many_files_gives_same_result_as_single_file() {
        let scrypt_params = ScryptParams::new(1, 0, 0);
        let data_dir = tempfile::tempdir().unwrap();
        let data_path = data_dir.path();

        CpuInitializer::new(scrypt_params)
            .initialize(
                &data_path.join("many"),
                &[0u8; 32],
                &[0u8; 32],
                1000,
                10,
                100,
                Some([0xFFu8; 32]),
            )
            .unwrap();

        CpuInitializer::new(scrypt_params)
            .initialize(
                &data_path.join("single"),
                &[0u8; 32],
                &[0u8; 32],
                1000,
                10,
                10000,
                Some([0xFFu8; 32]),
            )
            .unwrap();

        let read_files = |path: &Path| -> Vec<u8> {
            let mut data = Vec::new();
            for entry in reader::pos_files(path) {
                let mut file = std::fs::File::open(entry.path()).unwrap();
                file.read_to_end(&mut data).unwrap();
            }
            data
        };
        // Read all files into memory from the many files version
        let many_files_data = read_files(&data_path.join("many"));
        // Read all files into memory from the single file version
        let single_files_data = read_files(&data_path.join("single"));
        assert_eq!(many_files_data, single_files_data);

        // Verify if nonces in metadata files are the same
        let metadata_many = metadata::load(&data_path.join("many")).unwrap();
        let metadata_single = metadata::load(&data_path.join("single")).unwrap();
        assert_eq!(metadata_many.nonce, metadata_single.nonce);
    }
}
