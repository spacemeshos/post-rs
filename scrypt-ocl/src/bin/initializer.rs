use std::{io::Write, time};

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

    let label_count = 256 * 1024;

    let mut scrypter = Scrypter::new(8192, &[0u8; 32], Some(&[0xFFu8; 32])).unwrap();

    let now = time::Instant::now();
    let (labels, vrf_nonce) = scrypter.scrypt(0..label_count).unwrap();
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
