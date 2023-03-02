/// Calculate proving difficulty.
/// Assumes D=8 (64 bit values).
pub fn proving_difficulty(num_labels: u64, b: u32, k1: u32) -> eyre::Result<u64> {
    let num_blocks = num_labels / b as u64;
    eyre::ensure!(num_blocks > 0, "number of label blocks must be > 0");
    eyre::ensure!(
        num_blocks >= k1 as u64,
        format!("k1 ({k1}) cannot be bigger than the number of label blocks ({num_blocks})")
    );

    let x = u64::MAX / num_blocks;
    let y = u64::MAX % num_blocks;
    Ok(x * k1 as u64 + y * k1 as u64 / num_blocks)
}

#[cfg(test)]
mod tests {
    use crate::difficulty::proving_difficulty;

    #[test]
    fn zero_blocks() {
        assert!(proving_difficulty(0, 1, 1).is_err());
    }
}
