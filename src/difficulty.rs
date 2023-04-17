/// Calculate proving difficulty.
/// The lower the value of K1 - the more difficult it will be to find a good label.
pub fn proving_difficulty(num_labels: u64, k1: u32) -> eyre::Result<u64> {
    eyre::ensure!(num_labels > 0, "number of label blocks must be > 0");
    eyre::ensure!(
        num_labels >= k1 as u64,
        format!("k1 ({k1}) cannot be bigger than the number of labels ({num_labels})")
    );

    let x = u64::MAX / num_labels;
    let y = u64::MAX % num_labels;
    Ok(x * k1 as u64 + y * k1 as u64 / num_labels)
}

#[test]
fn zero_blocks() {
    assert!(proving_difficulty(0, 1).is_err());
}
