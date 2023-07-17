//! Proof of Space data verification

use std::{io::Read, io::Seek, path::Path};

use rand::seq::IteratorRandom;
use rayon::prelude::{ParallelBridge, ParallelIterator};
use scrypt_jane::scrypt::ScryptParams;

use crate::{
    initialize::{calc_commitment, CpuInitializer, Initialize},
    metadata,
};

#[derive(Debug, thiserror::Error)]
pub enum VerificationError {
    #[error("invalid label in file {idx} at offset {offset}")]
    InvalidLabel { idx: usize, offset: u64 },
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
    #[error("unknown error: {0}")]
    Unknown(#[from] eyre::Error),
}

pub fn verify_files(
    datadir: &Path,           // path to POS data directory
    fraction: f64,            // total % of labels to verify
    from_file: Option<usize>, // inclusive
    to_file: Option<usize>,   // inclusive
    scrypt: ScryptParams,
) -> Result<(), VerificationError> {
    let metadata = metadata::load(datadir)?;

    let from_file = from_file.unwrap_or(0);
    let to_file = to_file.unwrap_or(metadata.num_files() - 1);

    for idx in from_file..=to_file {
        let file_path = datadir.join(format!("postdata_{}.bin", idx));
        log::info!("verifying file {}", file_path.display());

        let file = std::fs::File::open(file_path)?;
        let reader = std::io::BufReader::new(file);
        let labels_count = metadata.labels_in_file(idx);

        verify(reader, labels_count, idx, fraction, &metadata, scrypt)?;
    }

    Ok(())
}

fn verify<R: Read + Seek + Send>(
    mut labels: R,
    labels_count: usize,
    file_idx: usize,
    fraction: f64,
    metadata: &metadata::PostMetadata,
    scrypt_params: ScryptParams,
) -> Result<(), VerificationError> {
    let commitment = calc_commitment(&metadata.node_id, &metadata.commitment_atx_id);

    let labels_offset = file_idx as u64 * metadata.max_file_size / 16;
    let labels_to_verify = (labels_count as f64 * (fraction / 100.0)) as usize;

    let mut rng = rand::thread_rng();
    (0..labels_count as u64)
        .choose_multiple(&mut rng, labels_to_verify)
        .into_iter()
        .map(|index| -> Result<_, VerificationError> {
            let mut label = [0u8; 16];
            labels.seek(std::io::SeekFrom::Start(index * 16))?;
            labels.read_exact(&mut label)?;
            Ok((index, label))
        })
        .par_bridge()
        .map(|index_and_label| -> Result<(), VerificationError> {
            let (index, label) = index_and_label?;

            let mut expected_label = [0u8; 16];
            let label_index = index + labels_offset;
            CpuInitializer::new(scrypt_params)
                .initialize_to(
                    &mut expected_label.as_mut_slice(),
                    &commitment,
                    label_index..label_index + 1,
                    None,
                )
                .expect("initializing label");

            if label != expected_label {
                return Err(VerificationError::InvalidLabel {
                    idx: file_idx,
                    offset: index * 16,
                });
            }
            Ok(())
        })
        .collect::<Result<Vec<_>, _>>()?;

    Ok(())
}
