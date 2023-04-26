use std::{fs::File, io::BufReader, path::Path};

use serde::{Deserialize, Serialize};
use serde_with::base64::Base64;
use serde_with::serde_as;

const METADATA_FILE_NAME: &str = "postdata_metadata.json";

#[serde_as]
#[derive(Debug, Deserialize, Serialize, Clone, Default)]
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

pub fn load(datadir: &Path) -> eyre::Result<PostMetadata> {
    let metatada_path = datadir.join(METADATA_FILE_NAME);
    let metadata_file = File::open(metatada_path)?;
    let reader = BufReader::new(metadata_file);
    let m = serde_json::from_reader(reader)?;
    Ok(m)
}

#[repr(C)]
#[derive(Debug, Clone)]
pub struct ProofMetadata {
    pub node_id: [u8; 32],
    pub commitment_atx_id: [u8; 32],
    pub challenge: [u8; 32],
    pub num_units: u32,
    pub labels_per_unit: u64,
}
