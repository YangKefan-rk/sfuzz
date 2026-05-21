#![allow(dead_code)]

/// Tracks per-testcase mux-select toggles from sampled coverage words.
///
/// This mirrors the driver-side RFuzz idea in `surgefuzz`: remember the first
/// sampled mux-select state for one testcase, then OR `initial ^ current` into
/// the local toggle map for every later cycle. The tracker is intentionally
/// local: call `reset` before starting the next testcase.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct ToggleTracker {
    initial: Option<Vec<u32>>,
    local: Vec<u32>,
}

impl ToggleTracker {
    pub(crate) fn new(chunk_count: usize) -> Self {
        Self {
            initial: None,
            local: vec![0; chunk_count],
        }
    }

    pub(crate) fn reset(&mut self) {
        self.initial = None;
        self.local.fill(0);
    }

    pub(crate) fn update(&mut self, sample: &[u32]) {
        assert_eq!(
            sample.len(),
            self.local.len(),
            "coverage sample width must match tracker width"
        );

        let initial = self.initial.get_or_insert_with(|| sample.to_vec());
        for (idx, value) in sample.iter().enumerate() {
            self.local[idx] |= initial[idx] ^ value;
        }
    }

    pub(crate) fn local(&self) -> &[u32] {
        &self.local
    }

    pub(crate) fn is_empty(&self) -> bool {
        self.local.iter().all(|word| *word == 0)
    }

    pub(crate) fn local_bytes(&self) -> Vec<u8> {
        words_to_little_endian_bytes(&self.local)
    }
}

/// RFuzz fuzzer-side coverage state.
///
/// `current_local` is the local toggle map from exactly one testcase. It should
/// be cleared or replaced before every run. `total_global` accumulates coverage
/// from all accepted total-corpus inputs, including invalid inputs when the
/// caller uses JQF-style separate coverage. `valid_global` is a separate
/// accumulated map for valid-input-only feedback.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct RfuzzCoverageMap {
    current_local: Vec<u8>,
    total_global: Vec<u8>,
    valid_global: Vec<u8>,
    max_coverage: usize,
}

impl RfuzzCoverageMap {
    pub(crate) fn new(byte_len: usize, max_coverage: usize) -> Self {
        Self {
            current_local: vec![0; byte_len],
            total_global: vec![0; byte_len],
            valid_global: vec![0; byte_len],
            max_coverage,
        }
    }

    pub(crate) fn len(&self) -> usize {
        self.current_local.len()
    }

    pub(crate) fn reset_current(&mut self) {
        self.clear_current_local();
    }

    pub(crate) fn clear_current_local(&mut self) {
        self.current_local.fill(0);
    }

    pub(crate) fn set_current_from_bytes(&mut self, local: &[u8]) {
        assert_eq!(
            local.len(),
            self.current_local.len(),
            "local coverage width must match coverage map width"
        );
        self.current_local.copy_from_slice(local);
    }

    pub(crate) fn set_current_from_words(&mut self, local_words: &[u32]) {
        self.set_current_from_bytes(&words_to_little_endian_bytes(local_words));
    }

    pub(crate) fn set_current_from_tracker(&mut self, tracker: &ToggleTracker) {
        self.set_current_from_words(tracker.local());
    }

    pub(crate) fn current_local(&self) -> &[u8] {
        &self.current_local
    }

    pub(crate) fn current(&self) -> &[u8] {
        self.current_local()
    }

    pub(crate) fn current_mut(&mut self) -> &mut [u8] {
        &mut self.current_local
    }

    pub(crate) fn current_ptr(&mut self) -> *mut u8 {
        self.current_local.as_mut_ptr()
    }

    pub(crate) fn total_global(&self) -> &[u8] {
        &self.total_global
    }

    pub(crate) fn valid_global(&self) -> &[u8] {
        &self.valid_global
    }

    pub(crate) fn has_new_total(&self) -> bool {
        has_new_bits(&self.total_global, &self.current_local)
    }

    pub(crate) fn has_new_valid(&self) -> bool {
        has_new_bits(&self.valid_global, &self.current_local)
    }

    pub(crate) fn apply_total(&mut self) {
        apply_bits(&mut self.total_global, &self.current_local);
    }

    pub(crate) fn apply_valid(&mut self) {
        apply_bits(&mut self.valid_global, &self.current_local);
    }

    pub(crate) fn total_covered_bits(&self) -> usize {
        count_bits(&self.total_global)
    }

    pub(crate) fn valid_covered_bits(&self) -> usize {
        count_bits(&self.valid_global)
    }

    pub(crate) fn coverage_rate(&self) -> f64 {
        if self.max_coverage == 0 {
            return 0.0;
        }
        100.0 * self.total_covered_bits() as f64 / self.max_coverage as f64
    }
}

pub(crate) fn has_new_bits(global: &[u8], local: &[u8]) -> bool {
    assert_eq!(global.len(), local.len());
    global
        .iter()
        .zip(local.iter())
        .any(|(g, l)| (*l & !*g) != 0)
}

pub(crate) fn apply_bits(global: &mut [u8], local: &[u8]) {
    assert_eq!(global.len(), local.len());
    for (g, l) in global.iter_mut().zip(local.iter()) {
        *g |= *l;
    }
}

pub(crate) fn count_bits(bytes: &[u8]) -> usize {
    bytes.iter().map(|b| b.count_ones() as usize).sum()
}

pub(crate) fn words_to_little_endian_bytes(words: &[u32]) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(words.len() * 4);
    for word in words {
        bytes.extend_from_slice(&word.to_le_bytes());
    }
    bytes
}

#[cfg(test)]
mod tests {
    use super::{RfuzzCoverageMap, ToggleTracker};

    #[test]
    fn tracks_mux_toggle_against_first_sample() {
        let mut tracker = ToggleTracker::new(2);
        assert!(tracker.is_empty());
        tracker.update(&[0b0001, 0b0100]);
        assert_eq!(tracker.local(), &[0, 0]);
        assert!(tracker.is_empty());

        tracker.update(&[0b0011, 0b0100]);
        assert_eq!(tracker.local(), &[0b0010, 0]);
        assert!(!tracker.is_empty());

        tracker.update(&[0b0001, 0b1100]);
        assert_eq!(tracker.local(), &[0b0010, 0b1000]);

        tracker.update(&[0b1011, 0b0101]);
        assert_eq!(tracker.local(), &[0b1010, 0b1001]);
    }

    #[test]
    fn resets_tracker_between_testcases() {
        let mut tracker = ToggleTracker::new(1);
        tracker.update(&[0]);
        tracker.update(&[0xff]);
        assert_eq!(tracker.local(), &[0xff]);
        tracker.reset();
        assert!(tracker.is_empty());
        tracker.update(&[0xff]);
        assert_eq!(tracker.local(), &[0]);
    }

    #[test]
    fn separates_current_total_and_valid_coverage() {
        let mut map = RfuzzCoverageMap::new(2, 16);
        map.set_current_from_bytes(&[0b0000_0011, 0]);
        assert_eq!(map.current_local(), &[0b0000_0011, 0]);
        assert_eq!(map.total_global(), &[0, 0]);
        assert_eq!(map.valid_global(), &[0, 0]);
        assert!(map.has_new_total());
        assert!(map.has_new_valid());

        map.apply_total();
        assert_eq!(map.total_global(), &[0b0000_0011, 0]);
        assert_eq!(map.valid_global(), &[0, 0]);
        assert_eq!(map.total_covered_bits(), 2);
        assert_eq!(map.valid_covered_bits(), 0);
        assert!(!map.has_new_total());
        assert!(map.has_new_valid());

        map.apply_valid();
        assert_eq!(map.valid_covered_bits(), 2);
        assert_eq!(map.coverage_rate(), 12.5);

        map.reset_current();
        assert_eq!(map.current_local(), &[0, 0]);
        map.set_current_from_bytes(&[0b0000_0010, 0]);
        assert!(!map.has_new_total());
        assert!(!map.has_new_valid());
    }

    #[test]
    fn loads_current_toggle_map_from_tracker_without_touching_globals() {
        let mut tracker = ToggleTracker::new(1);
        tracker.update(&[0xaaaa_5555]);
        tracker.update(&[0xaaaa_55f0]);

        let mut map = RfuzzCoverageMap::new(4, 32);
        map.set_current_from_tracker(&tracker);

        assert_eq!(map.current_local(), &[0xa5, 0x00, 0x00, 0x00]);
        assert_eq!(map.total_global(), &[0, 0, 0, 0]);
        assert_eq!(map.valid_global(), &[0, 0, 0, 0]);
        assert!(map.has_new_total());

        map.apply_total();
        map.clear_current_local();
        assert_eq!(map.current_local(), &[0, 0, 0, 0]);
        assert_eq!(map.total_global(), &[0xa5, 0, 0, 0]);
    }
}
