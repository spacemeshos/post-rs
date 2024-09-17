use primitive_types::U256;

/// Calculate proving difficulty.
///
/// K1 defines how many good labels are expected to be within all the labels.
/// The lower the value of K1 - the more difficult it will be to find a good label.
///
/// The difficulty is calculated as:
/// difficulty = 2^64 * K1 / num_labels
pub(crate) fn proving_difficulty(k1: u32, num_labels: u64) -> Result<u64, String> {
    if num_labels == 0 {
        return Err("number of label blocks must be > 0".to_string());
    }
    if num_labels <= k1 as u64 {
        return Err(format!(
            "number of labels ({num_labels}) must be bigger than k1 ({k1})"
        ));
    }
    let difficulty = (1u128 << 64) * k1 as u128 / num_labels as u128;
    u64::try_from(difficulty).or(Err("difficulty doesn't fit in u64".to_string()))
}

/// Scale PoW difficulty by the number of units.
///
/// The more units of data, the more difficult the PoW should be (linearly).
/// Because the PoW looks for values < difficulty, we need to scale the difficulty down.
/// The difficulty threshold is calculated as:
/// difficulty = difficulty / num_units
pub(crate) fn scale_pow_difficulty(difficulty: &[u8; 32], num_units: u32) -> [u8; 32] {
    let difficulty_scaled = U256::from_big_endian(difficulty) / num_units;
    difficulty_scaled.to_big_endian()
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

/// Test that PoW threshold is scaled with num_units.
#[test]
fn scaling_pow_thresholds() {
    {
        // don't scale when num_units is 1
        let difficulty = scale_pow_difficulty(&[0xFF; 32], 1);
        assert_eq!(difficulty, [0xFF; 32]);
    }
    {
        // scale with num_units
        let difficulty = scale_pow_difficulty(&[0xFF; 32], 2);
        assert!(difficulty < [0xFF; 32]);
        assert_eq!(
            difficulty.as_slice(),
            [&[0x7F], [0xFF; 31].as_slice()].concat()
        );
    }
    {
        // scale with num_units
        let difficulty = scale_pow_difficulty(&[0xFF; 32], 2_u32.pow(5));
        assert!(difficulty < [0xFF; 32]);
        assert_eq!(
            difficulty.as_slice(),
            [&[0xFF >> 5], [0xFF; 31].as_slice()].concat()
        );
    }
}
