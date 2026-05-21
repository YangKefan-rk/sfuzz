#![allow(dead_code)]

use super::score::SurgeAnnotation;

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct SurgeCoverageMap {
    current: Vec<u8>,
    global: Vec<u8>,
    max_coverage: usize,
}

impl SurgeCoverageMap {
    pub(crate) fn new(byte_len: usize, max_coverage: usize) -> Self {
        Self {
            current: vec![0; byte_len],
            global: vec![0; byte_len],
            max_coverage,
        }
    }

    pub(crate) fn reset_current(&mut self) {
        self.current.fill(0);
    }

    pub(crate) fn current(&self) -> &[u8] {
        &self.current
    }

    pub(crate) fn mark(&mut self, idx: usize) {
        if idx < self.current.len() {
            self.current[idx] = 1;
        }
    }

    pub(crate) fn has_new_coverage(&self) -> bool {
        self.current
            .iter()
            .zip(self.global.iter())
            .any(|(local, global)| *local != 0 && *global == 0)
    }

    pub(crate) fn apply(&mut self) {
        for (global, local) in self.global.iter_mut().zip(self.current.iter()) {
            if *global == 0 && *local != 0 {
                *global = *local;
            }
        }
    }

    pub(crate) fn covered_points(&self) -> usize {
        self.global.iter().filter(|value| **value != 0).count()
    }

    pub(crate) fn coverage_rate(&self) -> f64 {
        if self.max_coverage == 0 {
            0.0
        } else {
            100.0 * self.covered_points() as f64 / self.max_coverage as f64
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct SurgeCoverageIndex {
    annotation: SurgeAnnotation,
}

impl SurgeCoverageIndex {
    pub(crate) fn new(annotation: SurgeAnnotation) -> Self {
        Self { annotation }
    }

    pub(crate) fn index(&self, ancestor_state: u32, surge_score: u32) -> usize {
        match self.annotation {
            SurgeAnnotation::Freq { .. } | SurgeAnnotation::Consec { .. } => {
                ((ancestor_state as usize) << 4) | ((surge_score as usize) & 0xf)
            }
            SurgeAnnotation::Count { .. } => ancestor_state as usize,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{SurgeCoverageIndex, SurgeCoverageMap};
    use crate::methods::surgefuzz::score::{CountDirection, SurgeAnnotation};

    #[test]
    fn freq_and_consec_mix_ancestor_state_with_low_score_bits() {
        let indexer = SurgeCoverageIndex::new(SurgeAnnotation::Freq {
            active: true,
            window: 256,
        });
        assert_eq!(indexer.index(0b101, 0x23), 0b101_0011);
    }

    #[test]
    fn count_coverage_uses_ancestor_state_directly() {
        let indexer = SurgeCoverageIndex::new(SurgeAnnotation::Count {
            direction: CountDirection::Max,
        });
        assert_eq!(indexer.index(13, 99), 13);
    }

    #[test]
    fn map_tracks_current_and_global_byte_coverage() {
        let mut map = SurgeCoverageMap::new(8, 8);
        map.mark(3);
        assert!(map.has_new_coverage());
        assert_eq!(map.coverage_rate(), 0.0);
        map.apply();
        assert_eq!(map.covered_points(), 1);
        assert_eq!(map.coverage_rate(), 12.5);
        assert!(!map.has_new_coverage());
        map.reset_current();
        map.mark(9);
        assert_eq!(map.current(), &[0; 8]);
    }
}
