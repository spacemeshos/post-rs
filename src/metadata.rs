use std::{fs::File, io::BufReader, path::Path};

use serde::{Deserialize, Serialize};
use serde_with::base64::Base64;
use serde_with::serde_as;

const METADATA_FILE_NAME: &str = "postdata_metadata.json";

#[serde_as]
#[derive(Debug, Deserialize, Serialize, Clone, Copy, Default)]
#[serde(rename_all = "PascalCase")]
pub struct PostMetadata {
    #[serde_as(as = "Base64")]
    pub node_id: [u8; 32],
    #[serde_as(as = "Base64")]
    pub commitment_atx_id: [u8; 32],
    pub labels_per_unit: u64,
    pub num_units: u32,
    pub max_file_size: u64,
    pub nonce: Option<u64>,
    pub last_position: Option<u64>,
}

impl PostMetadata {
    pub fn total_labels(&self) -> u64 {
        self.num_units as u64 * self.labels_per_unit
    }

    pub fn total_size(&self) -> u64 {
        self.total_labels() * 16
    }

    pub fn num_files(&self) -> usize {
        (self.total_size() as f64 / self.max_file_size as f64).ceil() as usize
    }

    pub fn labels_in_file(&self, idx: usize) -> usize {
        assert_eq!(0, self.max_file_size % 16);
        let labels_in_files = self.max_file_size as usize / 16;
        match idx {
            idx if idx == self.num_files() - 1 => {
                let remainder = self.total_labels() as usize % labels_in_files;
                if remainder > 0 {
                    remainder
                } else {
                    labels_in_files
                }
            }
            idx if idx < self.num_files() - 1 => labels_in_files,
            _ => 0,
        }
    }
}

pub fn load(datadir: &Path) -> eyre::Result<PostMetadata> {
    let metatada_path = datadir.join(METADATA_FILE_NAME);
    let metadata_file = File::open(metatada_path)?;
    let reader = BufReader::new(metadata_file);
    let m = serde_json::from_reader(reader)?;
    Ok(m)
}

#[repr(C)]
#[serde_as]
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ProofMetadata {
    #[serde_as(as = "Base64")]
    pub node_id: [u8; 32],
    #[serde_as(as = "Base64")]
    pub commitment_atx_id: [u8; 32],
    #[serde_as(as = "Base64")]
    pub challenge: [u8; 32],
    pub num_units: u32,
    pub labels_per_unit: u64,
}

impl ProofMetadata {
    pub fn new(post_metadata: PostMetadata, challenge: [u8; 32]) -> Self {
        Self {
            challenge,
            node_id: post_metadata.node_id,
            commitment_atx_id: post_metadata.commitment_atx_id,
            num_units: post_metadata.num_units,
            labels_per_unit: post_metadata.labels_per_unit,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::PostMetadata;

    #[test]
    fn test_num_files() {
        let m = PostMetadata {
            labels_per_unit: 1,
            num_units: 1,
            max_file_size: 16,
            ..Default::default()
        };
        assert_eq!(m.num_files(), 1);

        let m = PostMetadata {
            labels_per_unit: 100,
            num_units: 77,
            max_file_size: 1024,
            ..Default::default()
        };
        assert_eq!(m.num_files(), 121);
    }

    #[test]
    fn test_labels_in_file() {
        let m = PostMetadata {
            labels_per_unit: 1,
            num_units: 1,
            max_file_size: 16,
            ..Default::default()
        };
        assert_eq!(1, m.labels_in_file(0));
        assert_eq!(0, m.labels_in_file(1));
    }
}
