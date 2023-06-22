#[derive(Debug, Clone)]
struct Blake3Rng(blake3::OutputReader);

impl Blake3Rng {
    fn from_seed(seed: &[&[u8]]) -> Self {
        let mut hasher = blake3::Hasher::new();
        for &part in seed {
            hasher.update(part);
        }
        Blake3Rng(hasher.finalize_xof())
    }

    fn next_u16(&mut self) -> u16 {
        let mut buf = [0u8; 2];
        self.0.fill(&mut buf);
        u16::from_le_bytes(buf)
    }
}

/// Picks random items from the provided Vec.
pub(crate) struct RandomValuesIterator<T> {
    // data shuffled in-place
    data: Vec<T>,
    rng: Blake3Rng,
    idx: usize,
}

impl<T> RandomValuesIterator<T> {
    pub(crate) fn new(data: Vec<T>, seed: &[&[u8]]) -> Self {
        Self {
            idx: 0,
            data,
            rng: Blake3Rng::from_seed(seed),
        }
    }
}

impl<T: Copy> Iterator for RandomValuesIterator<T> {
    type Item = T;

    fn next(&mut self) -> Option<Self::Item> {
        let remaining = self.data.len() - self.idx;
        if remaining == 0 {
            return None;
        }
        let max_allowed = u16::MAX - u16::MAX % remaining as u16;
        loop {
            let rand_num = self.rng.next_u16();
            if rand_num < max_allowed {
                self.data
                    .swap(self.idx, (rand_num as usize % remaining) + self.idx);
                let value = self.data[self.idx];
                self.idx += 1;
                return Some(value);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::RandomValuesIterator;
    use itertools::Itertools;
    use rayon::prelude::{IntoParallelIterator, ParallelIterator};
    use std::collections::HashSet;
    use std::sync::atomic::{AtomicUsize, Ordering};

    /// Check if returns unique items from its data set.
    #[test]
    fn gives_each_value_once() {
        let k2 = 1000;
        let iter = RandomValuesIterator::new((0..k2).collect(), &[]);
        let mut occurences = HashSet::new();
        for item in iter {
            assert!(occurences.insert(item));
        }
        assert_eq!(k2, occurences.len());
    }

    #[test]
    fn test_vec() {
        let expected = [
            39, 13, 95, 77, 36, 41, 74, 17, 59, 87, 91, 63, 40, 20, 94, 78, 48, 60, 18, 32, 67, 43,
            23, 69, 71, 1, 51, 79, 19, 53, 86, 80, 14, 84, 97, 92, 83, 26, 2, 81, 42, 55, 50, 88,
            75, 82, 44, 34, 58, 72, 35, 25, 10, 68, 12, 11, 70, 27, 98, 57, 96, 16, 45, 73, 0, 15,
            62, 46, 30, 89, 33, 54, 9, 29, 7, 90, 38, 5, 49, 61, 93, 99, 22, 6, 64, 24, 76, 85, 37,
            65, 31, 4, 52, 3, 56, 21, 8, 28, 66, 47,
        ];
        let input = (0..expected.len()).collect();

        let iter = RandomValuesIterator::new(input, &[]);
        assert_eq!(&expected, iter.collect_vec().as_slice());
    }

    #[test]
    fn distribution_is_uniform() {
        let data_set = (0..200).collect_vec();
        let occurences = (0..data_set.len())
            .map(|_| AtomicUsize::new(0))
            .collect_vec();

        // Take random n values many times and count each occurence
        let n = 50;
        let iterations = 2_000_000;
        (0u64..iterations).into_par_iter().for_each(|seed| {
            for value in RandomValuesIterator::new(data_set.clone(), &[&seed.to_le_bytes()]).take(n)
            {
                occurences[value].fetch_add(1, Ordering::Release);
            }
        });

        // Verify distribution
        let expected_count = (iterations * n as u64 / data_set.len() as u64) as f64;
        let max_deviation = 0.005;
        for (value, count) in occurences.into_iter().enumerate() {
            let count = count.load(Ordering::Acquire);
            let deviation = (count as f64 - expected_count) / expected_count;
            assert!(deviation.abs() < max_deviation, "{value} occured {count} times (expected {expected_count}). deviation {deviation} > {max_deviation}");
        }
    }
}
