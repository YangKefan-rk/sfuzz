#![allow(dead_code)]

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
    use super::RfuzzOutcome;

    #[test]
    fn total_coverage_is_always_interesting() {
        let outcome = RfuzzOutcome {
            new_total_coverage: true,
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
    }

    #[test]
    fn crashes_are_objectives_even_without_new_coverage() {
        let outcome = RfuzzOutcome {
            crashed: true,
            ..RfuzzOutcome::default()
        };
        assert!(outcome.interesting(false));
    }
}
