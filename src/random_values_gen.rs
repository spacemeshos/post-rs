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
pub struct RandomValuesIterator<T> {
    values: Vec<T>,
    rng: Blake3Rng,
    j: usize,
}

impl<T> RandomValuesIterator<T> {
    pub(crate) fn new(values: Vec<T>, seed: &[&[u8]]) -> Self {
        Self {
            j: 0,
            values,
            rng: Blake3Rng::from_seed(seed),
        }
    }
}

impl<T: Copy> Iterator for RandomValuesIterator<T> {
    type Item = T;

    fn next(&mut self) -> Option<Self::Item> {
        let data_len = self.values.len();
        if self.j >= data_len {
            return None;
        }
        let max_allowed = u16::MAX - (u16::MAX % (data_len - self.j) as u16);
        loop {
            let rand_num = self.rng.next_u16();
            if rand_num < max_allowed {
                let index = rand_num as usize % (data_len - self.j);
                let result = self.values[index];
                self.values.swap(index, data_len - self.j - 1);
                self.j += 1;
                return Some(result);
            }
        }
    }
}

pub(crate) struct FisherYatesShuffle<T> {
    data: Vec<T>,
    rng: Blake3Rng,
    index: usize,
}

impl<T> FisherYatesShuffle<T> {
    pub(crate) fn new(data: Vec<T>, seed: &[&[u8]]) -> Self {
        Self {
            index: 0,
            data,
            rng: Blake3Rng::from_seed(seed),
        }
    }
}

impl<T: Copy> Iterator for FisherYatesShuffle<T> {
    type Item = T;

    fn next(&mut self) -> Option<Self::Item> {
        let remaining = self.data.len() - self.index;
        if remaining == 0 {
            return None;
        }
        loop {
            let rand_num = self.rng.next_u16();
            let sample_max = u16::MAX - u16::MAX % remaining as u16;

            if rand_num < sample_max {
                let replacement_position = (rand_num as usize % remaining) + self.index;
                self.data.swap(self.index, replacement_position);
                let value = self.data[self.index];
                self.index += 1;
                return Some(value);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use itertools::Itertools;
    use rayon::prelude::{IntoParallelIterator, ParallelIterator};
    use std::collections::HashSet;
    use std::sync::atomic::{AtomicUsize, Ordering};

    use crate::random_values_gen::FisherYatesShuffle;

    use super::RandomValuesIterator;

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
    fn fisher_yates_shuffling_iter() {
        let k2 = 1000;
        let mut occurences = HashSet::new();
        for item in FisherYatesShuffle::new((0..k2).collect(), &[]) {
            assert!(occurences.insert(item));
        }
        assert_eq!(k2, occurences.len());
    }

    #[test]
    fn distribution_is_uniform() {
        let data_set = (0..200).collect_vec();
        let occurences = (0..data_set.len())
            .map(|_| AtomicUsize::new(0))
            .collect_vec();

        // Take random n values many times and count each occurence
        let n = 50;
        let iterations = 10_000_000;
        (0u64..iterations).into_par_iter().for_each(|seed| {
            for value in RandomValuesIterator::new(data_set.clone(), &[&seed.to_le_bytes()]).take(n)
            {
                occurences[value].fetch_add(1, Ordering::Relaxed);
            }
        });

        // Verify distribution
        let expected_count = (iterations * n as u64 / data_set.len() as u64) as f64;
        let max_deviation = 0.002;

        for (value, count) in occurences.into_iter().enumerate() {
            let count = count.load(Ordering::Relaxed);
            let deviation = (count as f64 - expected_count) / expected_count;
            assert!(deviation.abs() < max_deviation, "{value} occured {count} times (expected {expected_count}). deviation {deviation} > {max_deviation}");
        }
    }

    #[test]
    fn distribution_is_uniform_fisher_iter() {
        let data_set = (0..200).collect_vec();
        let occurences = (0..data_set.len())
            .map(|_| AtomicUsize::new(0))
            .collect_vec();

        // Take random n values many times and count each occurence
        let n = 50;
        let iterations = 10_000_000;
        (0u64..iterations).into_par_iter().for_each(|seed| {
            for value in FisherYatesShuffle::new(data_set.clone(), &[&seed.to_le_bytes()]).take(n) {
                occurences[value].fetch_add(1, Ordering::Relaxed);
            }
        });

        // Verify distribution
        let expected_count = (iterations * n as u64 / data_set.len() as u64) as f64;
        let max_deviation = 0.002;

        for (value, count) in occurences.into_iter().enumerate() {
            let count = count.load(Ordering::Relaxed);
            let deviation = (count as f64 - expected_count) / expected_count;
            assert!(deviation.abs() < max_deviation, "{value} occured {count} times (expected {expected_count}). deviation {deviation} > {max_deviation}");
        }
    }
}
