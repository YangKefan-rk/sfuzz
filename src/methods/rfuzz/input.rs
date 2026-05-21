#![allow(dead_code)]

use std::num::NonZeroUsize;

/// Layout of an RFuzz raw input stream.
///
/// `cycle_bits` is the concatenated width of the DUT top-level input pins for
/// one fuzzed cycle.  The RFuzz artifact transports one cycle as bytes padded
/// to a machine-word boundary, so every mutation is normalized to a multiple of
/// `cycle_bytes`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct RfuzzInputLayout {
    cycle_bits: usize,
    cycle_bytes: NonZeroUsize,
    cycle_byte_align: NonZeroUsize,
    max_cycles: Option<usize>,
}

impl RfuzzInputLayout {
    pub(crate) fn new(cycle_bits: usize, max_cycles: Option<usize>) -> Self {
        Self::with_cycle_byte_align(cycle_bits, max_cycles, 8)
    }

    pub(crate) fn with_cycle_byte_align(
        cycle_bits: usize,
        max_cycles: Option<usize>,
        cycle_byte_align: usize,
    ) -> Self {
        let cycle_byte_align =
            NonZeroUsize::new(cycle_byte_align.max(1)).expect("cycle_byte_align is non-zero");
        let raw_cycle_bytes = cycle_bits.max(1).div_ceil(8).max(1);
        let align = cycle_byte_align.get();
        let cycle_bytes = raw_cycle_bytes.div_ceil(align) * align;
        Self {
            cycle_bits,
            cycle_bytes: NonZeroUsize::new(cycle_bytes).expect("cycle_bytes is non-zero"),
            cycle_byte_align,
            max_cycles,
        }
    }

    pub(crate) fn cycle_bits(&self) -> usize {
        self.cycle_bits
    }

    pub(crate) fn cycle_bytes(&self) -> usize {
        self.cycle_bytes.get()
    }

    pub(crate) fn cycle_byte_align(&self) -> usize {
        self.cycle_byte_align.get()
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
            if self.max_len() != Some(0) {
                input.resize(cycle_bytes, 0);
            }
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
    fn computes_artifact_aligned_cycle_bytes_from_bits() {
        assert_eq!(RfuzzInputLayout::new(1, None).cycle_bytes(), 8);
        assert_eq!(RfuzzInputLayout::new(8, None).cycle_bytes(), 8);
        assert_eq!(RfuzzInputLayout::new(9, None).cycle_bytes(), 8);
        assert_eq!(RfuzzInputLayout::new(35, None).cycle_bytes(), 8);
        assert_eq!(RfuzzInputLayout::new(65, None).cycle_bytes(), 16);
        assert_eq!(RfuzzInputLayout::new(65, None).cycle_byte_align(), 8);
    }

    #[test]
    fn can_model_byte_tight_layout_when_needed() {
        assert_eq!(
            RfuzzInputLayout::with_cycle_byte_align(17, None, 1).cycle_bytes(),
            3
        );
    }

    #[test]
    fn normalizes_to_cycle_granularity() {
        let layout = RfuzzInputLayout::new(17, None);
        assert_eq!(layout.normalize(vec![1, 2]), vec![1, 2, 0, 0, 0, 0, 0, 0]);
        assert_eq!(layout.normalize(Vec::new()), vec![0; 8]);
    }

    #[test]
    fn cycle_count_and_padding_use_aligned_cycle_bytes() {
        let layout = RfuzzInputLayout::new(9, Some(3));
        assert_eq!(layout.cycle_bytes(), 8);
        assert_eq!(layout.cycle_count_for_len(0), 0);
        assert_eq!(layout.cycle_count_for_len(1), 1);
        assert_eq!(layout.cycle_count_for_len(8), 1);
        assert_eq!(layout.cycle_count_for_len(9), 2);
        assert_eq!(
            layout.normalize((1u8..=25).collect()),
            (1u8..=24).collect::<Vec<_>>()
        );
    }

    #[test]
    fn truncates_before_padding() {
        let layout = RfuzzInputLayout::new(16, Some(2));
        assert_eq!(
            layout.normalize((1u8..=17).collect()),
            (1u8..=16).collect::<Vec<_>>()
        );
    }

    #[test]
    fn zero_max_cycles_remains_empty() {
        let layout = RfuzzInputLayout::new(9, Some(0));
        assert_eq!(layout.max_len(), Some(0));
        assert_eq!(layout.normalize(Vec::new()), Vec::<u8>::new());
        assert_eq!(layout.normalize(vec![1, 2, 3]), Vec::<u8>::new());
    }
}
