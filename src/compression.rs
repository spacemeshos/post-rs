use bitvec::prelude::*;
use bitvec::{slice::BitSlice, view::BitView};

/// Compress indexes into a byte slice.
/// The number of bits used to store each index is `keep_bits`.
pub(crate) fn compress_indices(indexes: &[u64], keep_bits: usize) -> Vec<u8> {
    let mut bv = bitvec![u8, Lsb0;];
    for index in indexes {
        bv.extend_from_bitslice(&index.to_le_bytes().view_bits::<Lsb0>()[..keep_bits]);
    }
    bv.as_raw_slice().to_owned()
}

/// Decompress indexes from a byte slice, previously compressed with `compress_indices`.
/// Might return more indexes than the original, if the last byte contains unused bits.
pub(crate) fn decompress_indexes(indexes: &[u8], bits: usize) -> impl Iterator<Item = u64> + '_ {
    BitSlice::<_, Lsb0>::from_slice(indexes)
        .chunks_exact(bits)
        .map(|chunk| chunk.load_le::<u64>())
}

/// Calculate the number of bits required to store the value.
pub(crate) fn required_bits(value: u64) -> usize {
    if value == 0 {
        return 0;
    }
    (value.ilog2() + 1) as usize
}

#[cfg(test)]
#[allow(clippy::unusual_byte_groupings)]
mod tests {
    use super::*;
    use itertools::max;
    use proptest::prelude::*;
    #[test]
    fn test_compress() {
        let indexes = vec![0, 0b1111_1111_1111_0101, 0, 0b1111_1111_0000_1111];
        let compressed = compress_indices(&indexes, 3);
        assert_eq!(vec![0b00_101_000, 0b0000_1110], compressed);

        let compressed = compress_indices(&indexes, 16);
        assert_eq!(
            vec![
                0,
                0,
                0b1111_0101,
                0b1111_1111,
                0,
                0,
                0b0000_1111,
                0b1111_1111,
            ],
            compressed
        );
    }

    proptest! {
        #[test]
        fn compress_decompress_prop(indexes: [u64; 64]) {
            let max_value = max(indexes).unwrap();
            let bits = required_bits(max_value);
            let compressed = compress_indices(&indexes, bits);
            let decompressed: Vec<_> = decompress_indexes(&compressed, bits).take(indexes.len()).collect();
            assert_eq!(indexes.as_slice(), &decompressed);
        }
    }

    #[test]
    fn test_required_bits() {
        assert_eq!(0, required_bits(0));
        assert_eq!(1, required_bits(1));
        assert_eq!(20, required_bits(1 << 19));
        assert_eq!(63, required_bits((1 << 63) - 1));
        assert_eq!(64, required_bits(u64::MAX));
    }
}
