use eyre::Context;

/// Calculate proving difficulty.
///
/// K1 defines how many good labels are expected to be within all the labels.
/// The lower the value of K1 - the more difficult it will be to find a good label.
///
/// The difficulty is calculated as:
/// difficulty = 2^64 * K1 / num_labels
pub(crate) fn proving_difficulty(k1: u32, num_labels: u64) -> eyre::Result<u64> {
    eyre::ensure!(num_labels > 0, "number of label blocks must be > 0");
    eyre::ensure!(
        num_labels > k1 as u64,
        format!("number of labels ({num_labels}) must be bigger than k1 ({k1})")
    );
    let difficulty = (1u128 << 64) * k1 as u128 / num_labels as u128;
    u64::try_from(difficulty).wrap_err("difficulty doesn't fit in u64")
}

#[test]
fn zero_labels() {
    assert!(proving_difficulty(1, 0).is_err());
}

#[test]
fn too_big_k1() {
    assert!(proving_difficulty(2, 1).is_err());
    assert!(proving_difficulty(1, 1).is_err());
}

#[test]
fn difficulty_calculation() {
    assert_eq!(proving_difficulty(1, 2).unwrap(), 1u64 << 63);
    assert_eq!(proving_difficulty(1, 4).unwrap(), 1u64 << (64 - 2));
    assert_eq!(proving_difficulty(1, 128).unwrap(), 1u64 << (64 - 7));
}
