use std::fmt;

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum CoverageStrategy {
    Named(String),
    Union { left: String, right: String },
}

impl CoverageStrategy {
    pub(crate) fn parse(spec: &str) -> Result<Self, String> {
        let trimmed = spec.trim();
        if trimmed.is_empty() {
            return Err("coverage strategy cannot be empty".to_string());
        }

        if trimmed
            .get(..6)
            .is_some_and(|prefix| prefix.eq_ignore_ascii_case("union:"))
        {
            let body = &trimmed[6..];
            let mut parts = body.split('+');
            let left = parts.next().unwrap_or_default();
            let right = parts.next().ok_or_else(|| {
                "union coverage must use the form union:<left>+<right>".to_string()
            })?;
            if parts.next().is_some() {
                return Err(
                    "union coverage currently supports exactly two coverage names".to_string(),
                );
            }

            let left = Self::parse_named(left)?;
            let right = Self::parse_named(right)?;
            if left.eq_ignore_ascii_case(&right) {
                return Err("union coverage requires two distinct coverage names".to_string());
            }
            if left
                .get(..7)
                .is_some_and(|prefix| prefix.eq_ignore_ascii_case("FIRRTL."))
                || right
                    .get(..7)
                    .is_some_and(|prefix| prefix.eq_ignore_ascii_case("FIRRTL."))
            {
                return Err(
                    "union coverage currently cannot target FIRRTL subtypes; use a top-level simulator coverage name"
                        .to_string(),
                );
            }

            return Ok(Self::Union { left, right });
        }

        Ok(Self::Named(Self::parse_named(trimmed)?))
    }

    fn parse_named(name: &str) -> Result<String, String> {
        let trimmed = name.trim();
        if trimmed.is_empty() {
            return Err("coverage name cannot be empty".to_string());
        }
        if trimmed.chars().any(char::is_whitespace) {
            return Err("coverage names cannot contain whitespace".to_string());
        }
        if trimmed.eq_ignore_ascii_case("FIRRTL") {
            return Err(
                "FIRRTL feedback must use a concrete subtype such as FIRRTL.<group>".to_string(),
            );
        }
        if trimmed
            .get(..6)
            .is_some_and(|prefix| prefix.eq_ignore_ascii_case("union:"))
        {
            return Err("nested union coverage is not supported".to_string());
        }

        Ok(trimmed.to_string())
    }
}

impl fmt::Display for CoverageStrategy {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Named(name) => f.write_str(name),
            Self::Union { left, right } => write!(f, "union:{left}+{right}"),
        }
    }
}

pub(crate) fn normalize_coverage_strategy(spec: &str) -> Result<String, String> {
    CoverageStrategy::parse(spec).map(|strategy| strategy.to_string())
}

#[cfg(test)]
mod tests {
    use super::{CoverageStrategy, normalize_coverage_strategy};

    #[test]
    fn parses_named_strategy() {
        assert_eq!(
            CoverageStrategy::parse("llvm.branch").unwrap(),
            CoverageStrategy::Named("llvm.branch".to_string())
        );
    }

    #[test]
    fn accepts_multicore_signal_strategy() {
        assert_eq!(
            normalize_coverage_strategy("multicore.signal").unwrap(),
            "multicore.signal"
        );
    }

    #[test]
    fn canonicalizes_union_strategy() {
        assert_eq!(
            normalize_coverage_strategy("Union: llvm.branch + Instruction").unwrap(),
            "union:llvm.branch+Instruction"
        );
    }

    #[test]
    fn rejects_empty_strategy() {
        assert!(CoverageStrategy::parse("   ").is_err());
    }

    #[test]
    fn rejects_bare_firrtl_strategy() {
        assert!(CoverageStrategy::parse("FIRRTL").is_err());
    }

    #[test]
    fn rejects_malformed_union_strategy() {
        assert!(CoverageStrategy::parse("union:llvm.branch+").is_err());
        assert!(CoverageStrategy::parse("union:llvm.branch+Instruction+Instr-Imm").is_err());
    }

    #[test]
    fn rejects_nested_union_strategy() {
        assert!(CoverageStrategy::parse("union:llvm.branch+union:Instruction+Instr-Imm").is_err());
    }

    #[test]
    fn rejects_union_with_firrtl_subtype() {
        assert!(CoverageStrategy::parse("union:FIRRTL.MSHR+llvm.branch").is_err());
    }
}
