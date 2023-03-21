use std::{error::Error, fs::File, io::Write, path::Path};

use scrypt_jane::scrypt::{scrypt, ScryptParams};

use crate::metadata::PostMetadata;

pub(crate) fn calc_commitment(node_id: &[u8; 32], commitment_atx_id: &[u8; 32]) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(node_id);
    hasher.update(commitment_atx_id);
    hasher.finalize().into()
}

pub fn initialize(
    datadir: &Path,
    node_id: &[u8; 32],
    commitment_atx_id: &[u8; 32],
    labels_per_unit: u64,
    num_units: u32,
    scrypt_params: ScryptParams,
) -> Result<PostMetadata, Box<dyn Error>> {
    let num_labels = usize::try_from(num_units as u64 * labels_per_unit)?;

    let commitment = calc_commitment(node_id, commitment_atx_id);

    let mut scrypt_data = [0u8; 72];
    scrypt_data[0..32].copy_from_slice(&commitment);

    let mut labels = vec![0u8; num_labels * 16];
    for (index, label) in labels.chunks_exact_mut(16).enumerate() {
        scrypt_data[32..40].copy_from_slice(&index.to_le_bytes());
        scrypt(&scrypt_data, &[], scrypt_params, label);
    }

    let file_path = datadir.join("postdata_0.bin");
    let mut post_data = File::create(file_path)?;
    post_data.write_all(&labels)?;

    let metadata = PostMetadata {
        node_id: *node_id,
        commitment_atx_id: *commitment_atx_id,
        labels_per_unit,
        num_units,
        max_file_size: num_labels as u64,
        nonce: None,
        last_position: None,
    };
    let metadata_file = File::create(datadir.join("postdata_metadata.json"))?;
    serde_json::to_writer_pretty(metadata_file, &metadata)?;

    Ok(metadata)
}
