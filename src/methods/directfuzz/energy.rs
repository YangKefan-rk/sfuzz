#![allow(dead_code)]

use super::metadata::{DirectFuzzMetadata, DirectFuzzMetadataError};

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
        self.try_feedback(metadata, coverage, new_coverage, target_progress)
            .expect("coverage shape must match DirectFuzz metadata")
    }

    pub(crate) fn try_feedback(
        &self,
        metadata: &DirectFuzzMetadata,
        input_coverage: &[Vec<u8>],
        new_coverage: bool,
        target_progress: bool,
    ) -> Result<DirectFuzzFeedback, DirectFuzzMetadataError> {
        let stats = metadata.coverage_stats(input_coverage)?;
        let distance = stats.input_distance;
        let energy = self.energy_for_distance(distance, metadata.max_distance());
        Ok(DirectFuzzFeedback {
            new_coverage,
            target_covered_bits: stats.target_covered_bits,
            target_progress,
            distance,
            energy,
        })
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
    fn maps_no_reachable_coverage_to_min_energy() {
        let schedule = DirectFuzzPowerSchedule::default();
        assert_eq!(schedule.energy_for_distance(None, 8), 0.0);
    }

    #[test]
    fn clamps_distance_above_max_to_min_energy() {
        let schedule = DirectFuzzPowerSchedule::default();
        assert_eq!(schedule.energy_for_distance(Some(12.0), 8), 0.0);
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

    #[test]
    fn feedback_uses_local_input_coverage_not_accumulated_bitmap() {
        let metadata = DirectFuzzMetadata::new(vec![
            CoverageInstance::new("near", "cov_near", 8, Some(1)),
            CoverageInstance::new("target", "cov_t", 8, Some(0)),
        ])
        .unwrap();
        let schedule = DirectFuzzPowerSchedule::default();
        let previous_input = vec![vec![0], vec![0b0000_1111]];
        let current_input = vec![vec![0b0000_0011], vec![0]];
        let accumulated_bitmap = vec![vec![0b0000_0011], vec![0b0000_1111]];

        let previous = schedule.feedback(&metadata, &previous_input, true, true);
        assert!(previous.covered_target());
        assert_eq!(previous.energy, 25.0);

        let current = schedule.feedback(&metadata, &current_input, true, false);
        assert!(!current.covered_target());
        assert_eq!(current.distance, Some(1.0));
        assert_eq!(current.energy, 0.0);

        let accumulated = schedule.feedback(&metadata, &accumulated_bitmap, true, false);
        assert!(accumulated.covered_target());
        assert!(accumulated.energy > current.energy);
    }

    #[test]
    fn feedback_ignores_unreachable_coverage_for_distance() {
        let metadata = DirectFuzzMetadata::new(vec![
            CoverageInstance::new("dead", "cov_dead", 8, None),
            CoverageInstance::new("target", "cov_t", 8, Some(0)),
        ])
        .unwrap();
        let coverage = vec![vec![0xff], vec![0]];
        let feedback =
            DirectFuzzPowerSchedule::default().feedback(&metadata, &coverage, true, false);
        assert_eq!(feedback.distance, None);
        assert_eq!(feedback.energy, 0.0);
        assert!(!feedback.covered_target());
    }

    #[test]
    fn feedback_reports_coverage_shape_errors() {
        let metadata = DirectFuzzMetadata::new(vec![
            CoverageInstance::new("near", "cov_near", 9, Some(1)),
            CoverageInstance::new("target", "cov_t", 8, Some(0)),
        ])
        .unwrap();
        let err = DirectFuzzPowerSchedule::default()
            .try_feedback(&metadata, &[vec![0], vec![0]], true, false)
            .unwrap_err();
        assert!(matches!(
            err,
            crate::methods::directfuzz::metadata::DirectFuzzMetadataError::CoverageByteLengthMismatch {
                instance_index: 0,
                expected_bytes: 2,
                actual_bytes: 1,
                ..
            }
        ));
    }
}
