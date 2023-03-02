use std::{fs::File, io::BufReader, path::Path};

use serde::Deserialize;
use serde_with::base64::Base64;
use serde_with::serde_as;

const METADATA_FILE_NAME: &str = "postdata_metadata.json";

#[serde_as]
#[derive(Debug, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct PostMetadata {
    #[serde_as(as = "Base64")]
    pub node_id: Vec<u8>,
    #[serde_as(as = "Base64")]
    pub commitment_atx_id: Vec<u8>,
    pub bits_per_label: u8,
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
