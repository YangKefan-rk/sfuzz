#![allow(dead_code)]

use std::num::NonZeroUsize;

/// Layout of an RFuzz raw input stream.
///
/// `cycle_bits` is the concatenated width of the DUT top-level input pins for
/// one fuzzed cycle.  RFuzz stores the stream as whole bytes, so every mutation
/// is normalized to a multiple of `cycle_bytes`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct RfuzzInputLayout {
    cycle_bits: usize,
    cycle_bytes: NonZeroUsize,
    max_cycles: Option<usize>,
}

impl RfuzzInputLayout {
    pub(crate) fn new(cycle_bits: usize, max_cycles: Option<usize>) -> Self {
        let cycle_bytes = ((cycle_bits.max(1) + 7) / 8).max(1);
        Self {
            cycle_bits,
            cycle_bytes: NonZeroUsize::new(cycle_bytes).expect("cycle_bytes is non-zero"),
            max_cycles,
        }
    }

    pub(crate) fn cycle_bits(&self) -> usize {
        self.cycle_bits
    }

    pub(crate) fn cycle_bytes(&self) -> usize {
        self.cycle_bytes.get()
    }

    pub(crate) fn max_len(&self) -> Option<usize> {
        self.max_cycles
            .and_then(|cycles| cycles.checked_mul(self.cycle_bytes()))
    }

    pub(crate) fn normalize(&self, mut input: Vec<u8>) -> Vec<u8> {
        if let Some(max_len) = self.max_len() {
            input.truncate(max_len);
        }

        let cycle_bytes = self.cycle_bytes();
        if input.is_empty() {
            input.resize(cycle_bytes, 0);
            return input;
        }

        let rem = input.len() % cycle_bytes;
        if rem != 0 {
            input.resize(input.len() + cycle_bytes - rem, 0);
        }
        input
    }

    pub(crate) fn cycle_count_for_len(&self, len: usize) -> usize {
        len.div_ceil(self.cycle_bytes())
    }
}

#[cfg(test)]
mod tests {
    use super::RfuzzInputLayout;

    #[test]
    fn computes_cycle_bytes_from_bits() {
        assert_eq!(RfuzzInputLayout::new(1, None).cycle_bytes(), 1);
        assert_eq!(RfuzzInputLayout::new(8, None).cycle_bytes(), 1);
        assert_eq!(RfuzzInputLayout::new(9, None).cycle_bytes(), 2);
        assert_eq!(RfuzzInputLayout::new(35, None).cycle_bytes(), 5);
    }

    #[test]
    fn normalizes_to_cycle_granularity() {
        let layout = RfuzzInputLayout::new(17, None);
        assert_eq!(layout.normalize(vec![1, 2]), vec![1, 2, 0]);
        assert_eq!(layout.normalize(vec![1, 2, 3]), vec![1, 2, 3]);
        assert_eq!(layout.normalize(Vec::new()), vec![0, 0, 0]);
    }

    #[test]
    fn truncates_before_padding() {
        let layout = RfuzzInputLayout::new(16, Some(2));
        assert_eq!(layout.normalize(vec![1, 2, 3, 4, 5]), vec![1, 2, 3, 4]);
    }
}
