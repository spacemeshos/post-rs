use std::io::Write;

use post::{
    config::ScryptParams,
    initialize::{CpuInitializer, Initialize},
    pos_verification::verify_files,
};

use tempfile::tempdir;

#[test]
fn test_generate_and_verify() {
    // Initialize some data
    let datadir = tempdir().unwrap();
    let scrypt = ScryptParams::new(2, 1, 1);

    CpuInitializer::new(scrypt)
        .initialize(datadir.path(), &[0u8; 32], &[0u8; 32], 256, 31, 700, None)
        .unwrap();

    // Verify the data
    verify_files(datadir.path(), 100.0, None, None, scrypt).unwrap();
    verify_files(datadir.path(), 1.0, None, None, scrypt).unwrap();
    verify_files(datadir.path(), 1.0, Some(0), Some(1), scrypt).unwrap();

    // Try verification with wrong scrypt params
    let wrong_scrypt = ScryptParams::new(4, 1, 1);
    assert!(verify_files(datadir.path(), 100.0, None, None, wrong_scrypt).is_err());
    assert!(verify_files(datadir.path(), 1.0, None, None, wrong_scrypt).is_err());
    assert!(verify_files(datadir.path(), 100.0, Some(0), Some(0), wrong_scrypt).is_err());

    // Modify some data
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .open(datadir.path().join("postdata_1.bin"))
        .unwrap();

    file.write_all(&[0u8; 16]).unwrap();

    assert!(verify_files(datadir.path(), 100.0, None, None, scrypt).is_err());
    assert!(verify_files(datadir.path(), 100.0, Some(1), Some(1), scrypt).is_err());
    assert!(verify_files(datadir.path(), 100.0, None, Some(1), scrypt).is_err());
    assert!(verify_files(datadir.path(), 100.0, Some(1), None, scrypt).is_err());

    // skip corrupted files - pass
    verify_files(datadir.path(), 100.0, None, Some(0), scrypt).unwrap();
    verify_files(datadir.path(), 100.0, Some(2), None, scrypt).unwrap();
}
