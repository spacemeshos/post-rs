use bitvec::prelude::*;
use bitvec::{slice::BitSlice, view::BitView};

pub(crate) fn compress_indexes(indexes: &[u64], keep_bits: usize) -> Vec<u8> {
    let mut bv = bitvec![u8, Lsb0;];
    for index in indexes {
        bv.extend_from_bitslice(&index.to_le_bytes().view_bits::<Lsb0>()[..keep_bits]);
    }
    bv.as_raw_slice().to_owned()
}

#[allow(dead_code)]
pub(crate) fn decompress_indexes(indexes: &[u8], bits: usize) -> Vec<u64> {
    BitSlice::<_, Lsb0>::from_slice(indexes)
        .chunks_exact(bits)
        .map(|chunk| chunk.load_le::<u64>())
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use itertools::max;
    use proptest::prelude::*;
    #[test]
    fn test_compress() {
        let indexes = vec![0, 0b1111_1111_1111_0101, 0, 0b1111_1111_0000_1111];
        let compressed = compress_indexes(&indexes, 3);
        assert_eq!(vec![0b00_101_000, 0b0000_1110], compressed);

        let compressed = compress_indexes(&indexes, 16);
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
            let bits = (max_value as f64).log2() as usize + 1;
            let compressed = compress_indexes(&indexes, bits);
            let decompressed = decompress_indexes(&compressed, bits);
            assert_eq!(indexes.as_slice(), &decompressed);
        }
    }
}
