use std::{error::Error, path::Path};

use base64::{engine::general_purpose, Engine};
use post::ScryptParams;

fn main() -> Result<(), Box<dyn Error>> {
    let label_count = 50000;

    let node_id = general_purpose::STANDARD
        .decode("hBGTHs44tav7YR87sRVafuzZwObCZnK1Z/exYpxwqSQ=")
        .unwrap();
    let commitment_atx_id = general_purpose::STANDARD
        .decode("ZuxocVjIYWfv7A/K1Lmm8+mNsHzAZaWVpbl5+KINx+I=")
        .unwrap();

    let now = std::time::Instant::now();
    post::initialize::initialize(
        Path::new("./"),
        &node_id.try_into().unwrap(),
        &commitment_atx_id.try_into().unwrap(),
        label_count,
        1,
        label_count,
        ScryptParams::new(12, 0, 0),
    )?;

    let elapsed = now.elapsed();

    println!(
        "Scrypting {} labels took {} seconds. Speed: {:.0} labels/sec ({:.2} MB/sec)",
        label_count,
        elapsed.as_secs(),
        label_count as f64 / elapsed.as_secs_f64(),
        label_count as f64 * 16.0 / elapsed.as_secs_f64() / 1024.0 / 1024.0
    );
    Ok(())
}
