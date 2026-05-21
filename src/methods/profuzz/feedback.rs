#![allow(dead_code)]

#[derive(Clone, Debug, PartialEq)]
pub(crate) struct ProfuzzCampaign {
    target_count: usize,
    current_coverage: f64,
    threshold: f64,
    min_relative_improvement: f64,
}

#[derive(Clone, Copy, Debug, PartialEq)]
pub(crate) struct ProfuzzFeedback {
    pub coverage: f64,
    pub interesting: bool,
    pub reached_threshold: bool,
}

impl ProfuzzCampaign {
    pub(crate) fn new(
        target_count: usize,
        initial_coverage: f64,
        threshold: f64,
        min_relative_improvement: f64,
    ) -> Self {
        Self {
            target_count,
            current_coverage: initial_coverage,
            threshold,
            min_relative_improvement,
        }
    }

    pub(crate) fn coverage_from_covered(&self, covered_targets: usize) -> f64 {
        if self.target_count == 0 {
            0.0
        } else {
            100.0 * covered_targets as f64 / self.target_count as f64
        }
    }

    pub(crate) fn evaluate_percent(&mut self, coverage: f64) -> ProfuzzFeedback {
        let reached_threshold = coverage >= self.threshold;
        let interesting = reached_threshold
            || coverage > self.current_coverage * (1.0 + self.min_relative_improvement);
        if interesting && coverage > self.current_coverage {
            self.current_coverage = coverage;
        }
        ProfuzzFeedback {
            coverage,
            interesting,
            reached_threshold,
        }
    }

    pub(crate) fn current_coverage(&self) -> f64 {
        self.current_coverage
    }
}

impl Default for ProfuzzCampaign {
    fn default() -> Self {
        Self::new(0, 0.0, 90.0, 0.025)
    }
}

#[cfg(test)]
mod tests {
    use super::ProfuzzCampaign;

    #[test]
    fn computes_target_site_coverage_percent() {
        let campaign = ProfuzzCampaign::new(200, 0.0, 90.0, 0.025);
        assert_eq!(campaign.coverage_from_covered(50), 25.0);
    }

    #[test]
    fn keeps_only_threshold_or_relative_improvement() {
        let mut campaign = ProfuzzCampaign::new(100, 40.0, 90.0, 0.025);
        let small = campaign.evaluate_percent(40.5);
        assert!(!small.interesting);
        assert_eq!(campaign.current_coverage(), 40.0);

        let improved = campaign.evaluate_percent(42.0);
        assert!(improved.interesting);
        assert_eq!(campaign.current_coverage(), 42.0);

        let threshold = campaign.evaluate_percent(91.0);
        assert!(threshold.reached_threshold);
        assert!(threshold.interesting);
    }
}
