#![allow(dead_code)]

use super::coverage::RfuzzCoverageMap;

/// Result of one RFuzz testcase execution from the fuzzer's point of view.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub(crate) struct RfuzzOutcome {
    pub valid: bool,
    pub crashed: bool,
    pub timeout: bool,
    pub new_total_coverage: bool,
    pub new_valid_coverage: bool,
}

impl RfuzzOutcome {
    pub(crate) fn from_coverage(
        coverage: &RfuzzCoverageMap,
        valid: bool,
        crashed: bool,
        timeout: bool,
    ) -> Self {
        Self {
            valid,
            crashed,
            timeout,
            new_total_coverage: coverage.has_new_total(),
            new_valid_coverage: coverage.has_new_valid(),
        }
    }

    pub(crate) fn interesting(self, constrained: bool) -> bool {
        self.new_total_coverage
            || (constrained && self.valid && self.new_valid_coverage)
            || self.crashed
    }

    pub(crate) fn should_apply_valid(self, constrained: bool) -> bool {
        !constrained || self.valid
    }
}

#[cfg(test)]
mod tests {
    use crate::methods::rfuzz::coverage::RfuzzCoverageMap;

    use super::RfuzzOutcome;

    #[test]
    fn total_coverage_is_always_interesting() {
        let outcome = RfuzzOutcome {
            new_total_coverage: true,
            valid: false,
            ..RfuzzOutcome::default()
        };
        assert!(outcome.interesting(false));
        assert!(outcome.interesting(true));
    }

    #[test]
    fn valid_coverage_requires_constrained_valid_input() {
        let valid = RfuzzOutcome {
            valid: true,
            new_valid_coverage: true,
            ..RfuzzOutcome::default()
        };
        let invalid = RfuzzOutcome {
            valid: false,
            new_valid_coverage: true,
            ..RfuzzOutcome::default()
        };
        assert!(!valid.interesting(false));
        assert!(valid.interesting(true));
        assert!(!invalid.interesting(true));
        assert!(!invalid.should_apply_valid(true));
        assert!(invalid.should_apply_valid(false));
        assert!(valid.should_apply_valid(true));
    }

    #[test]
    fn crashes_are_objectives_even_without_new_coverage() {
        let outcome = RfuzzOutcome {
            crashed: true,
            ..RfuzzOutcome::default()
        };
        assert!(outcome.interesting(false));
    }

    #[test]
    fn derives_new_total_and_valid_flags_from_separate_maps() {
        let mut coverage = RfuzzCoverageMap::new(1, 8);
        coverage.set_current_from_bytes(&[0b0000_0011]);
        coverage.apply_total();
        coverage.set_current_from_bytes(&[0b0000_0010]);

        let invalid = RfuzzOutcome::from_coverage(&coverage, false, false, false);
        assert_eq!(
            invalid,
            RfuzzOutcome {
                valid: false,
                crashed: false,
                timeout: false,
                new_total_coverage: false,
                new_valid_coverage: true,
            }
        );
        assert!(!invalid.interesting(true));

        let valid = RfuzzOutcome::from_coverage(&coverage, true, false, false);
        assert!(valid.interesting(true));
    }

    #[test]
    fn invalid_constrained_input_can_still_be_total_interesting() {
        let mut coverage = RfuzzCoverageMap::new(1, 8);
        coverage.set_current_from_bytes(&[0b1000_0000]);

        let outcome = RfuzzOutcome::from_coverage(&coverage, false, false, false);
        assert!(outcome.new_total_coverage);
        assert!(outcome.new_valid_coverage);
        assert!(outcome.interesting(true));
        assert!(!outcome.should_apply_valid(true));
    }
}
