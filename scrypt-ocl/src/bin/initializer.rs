use std::{io::Write, time};

use base64::{engine::general_purpose, Engine};
use ocl::{core::ClVersions, Platform};
use scrypt_ocl::Scrypter;

fn main() {
    for platform in Platform::list() {
        println!(
            "Platform: {:?}, device versions: {:?}",
            platform.name(),
            platform.device_versions()
        );
    }

    let label_count = 50000;

    let node_id = general_purpose::STANDARD
        .decode("hBGTHs44tav7YR87sRVafuzZwObCZnK1Z/exYpxwqSQ=")
        .unwrap();
    let commitment_atx_id = general_purpose::STANDARD
        .decode("ZuxocVjIYWfv7A/K1Lmm8+mNsHzAZaWVpbl5+KINx+I=")
        .unwrap();
    let commitment = post::initialize::calc_commitment(
        &node_id.try_into().unwrap(),
        &commitment_atx_id.try_into().unwrap(),
    );

    let mut scrypter = Scrypter::new(None, 8192, &commitment, Some([0xFFu8; 32])).unwrap();
    let mut labels = vec![0u8; label_count * 16];

    let now = time::Instant::now();
    let vrf_nonce = scrypter.scrypt(0..label_count as u64, &mut labels).unwrap();
    let elapsed = now.elapsed();
    println!(
        "Scrypting {} labels took {} seconds. Speed: {:.0} labels/sec ({:.2} MB/sec, vrf_nonce: {vrf_nonce:?})",
        label_count,
        elapsed.as_secs(),
        label_count as f64 / elapsed.as_secs_f64(),
        label_count as f64 * 16.0 / elapsed.as_secs_f64() / 1024.0 / 1024.0
    );

    let mut file = std::fs::File::create("labels.bin").unwrap();
    file.write_all(&labels).unwrap();
}
