#![allow(dead_code)]

use super::metadata::DirectFuzzMetadata;

#[derive(Clone, Debug, PartialEq)]
pub(crate) struct DirectFuzzPowerSchedule {
    pub min_energy: f64,
    pub max_energy: f64,
    pub default_energy: f64,
}

impl Default for DirectFuzzPowerSchedule {
    fn default() -> Self {
        Self {
            min_energy: 0.0,
            max_energy: 25.0,
            default_energy: 1.0,
        }
    }
}

impl DirectFuzzPowerSchedule {
    pub(crate) fn energy_for_distance(&self, distance: Option<f64>, max_distance: usize) -> f64 {
        let Some(distance) = distance else {
            return self.min_energy;
        };
        if max_distance == 0 {
            return self.max_energy;
        }
        let span = self.max_energy - self.min_energy;
        let normalized = (distance / max_distance as f64).clamp(0.0, 1.0);
        self.max_energy - span * normalized
    }

    pub(crate) fn feedback(
        &self,
        metadata: &DirectFuzzMetadata,
        coverage: &[Vec<u8>],
        new_coverage: bool,
        target_progress: bool,
    ) -> DirectFuzzFeedback {
        let distance = metadata.input_distance(coverage);
        let energy = self.energy_for_distance(distance, metadata.max_distance());
        DirectFuzzFeedback {
            new_coverage,
            target_covered_bits: metadata.target_covered_bits(coverage),
            target_progress,
            distance,
            energy,
        }
    }
}

#[derive(Clone, Copy, Debug, Default, PartialEq)]
pub(crate) struct DirectFuzzFeedback {
    pub new_coverage: bool,
    pub target_covered_bits: usize,
    pub target_progress: bool,
    pub distance: Option<f64>,
    pub energy: f64,
}

impl DirectFuzzFeedback {
    pub(crate) fn covered_target(&self) -> bool {
        self.target_covered_bits > 0
    }
}

#[cfg(test)]
mod tests {
    use super::DirectFuzzPowerSchedule;
    use crate::methods::directfuzz::metadata::{CoverageInstance, DirectFuzzMetadata};

    #[test]
    fn maps_zero_distance_to_max_energy() {
        let schedule = DirectFuzzPowerSchedule::default();
        assert_eq!(schedule.energy_for_distance(Some(0.0), 10), 25.0);
    }

    #[test]
    fn maps_max_distance_to_min_energy() {
        let schedule = DirectFuzzPowerSchedule::default();
        assert_eq!(schedule.energy_for_distance(Some(10.0), 10), 0.0);
    }

    #[test]
    fn computes_intermediate_energy_linearly() {
        let schedule = DirectFuzzPowerSchedule::default();
        assert_eq!(schedule.energy_for_distance(Some(4.0), 8), 12.5);
    }

    #[test]
    fn feedback_combines_distance_target_and_energy() {
        let metadata = DirectFuzzMetadata::new(vec![
            CoverageInstance::new("a", "cov_a", 8, Some(2)),
            CoverageInstance::new("target", "cov_t", 8, Some(0)),
        ])
        .unwrap();
        let coverage = vec![vec![0b0000_0011], vec![0b0000_0001]];
        let feedback =
            DirectFuzzPowerSchedule::default().feedback(&metadata, &coverage, true, true);
        assert_eq!(feedback.target_covered_bits, 1);
        assert_eq!(feedback.distance, Some(4.0 / 3.0));
        assert!(feedback.energy > 0.0 && feedback.energy < 25.0);
        assert!(feedback.covered_target());
    }
}
