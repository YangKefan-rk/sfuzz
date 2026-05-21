#![allow(dead_code)]

use std::fmt::{Display, Formatter};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum PatternBit {
    Zero,
    One,
    X,
}

impl TryFrom<char> for PatternBit {
    type Error = PatternError;

    fn try_from(value: char) -> Result<Self, Self::Error> {
        match value {
            '0' => Ok(Self::Zero),
            '1' => Ok(Self::One),
            'X' | 'x' => Ok(Self::X),
            _ => Err(PatternError::InvalidBit(value)),
        }
    }
}

impl From<PatternBit> for char {
    fn from(value: PatternBit) -> Self {
        match value {
            PatternBit::Zero => '0',
            PatternBit::One => '1',
            PatternBit::X => 'X',
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum PatternError {
    Empty,
    InvalidBit(char),
    Conflict,
    LengthMismatch { left: usize, right: usize },
    MissingPair { net: String },
}

impl Display for PatternError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Empty => write!(f, "PROFUZZ pattern list must not be empty"),
            Self::InvalidBit(bit) => write!(f, "invalid PROFUZZ pattern bit '{bit}'"),
            Self::Conflict => write!(f, "conflicting concrete PROFUZZ pattern bits"),
            Self::LengthMismatch { left, right } => {
                write!(f, "PROFUZZ pattern length mismatch: {left} vs {right}")
            }
            Self::MissingPair { net } => write!(
                f,
                "PROFUZZ ATPG pattern for net '{net}' must provide both 0 and 1 activation patterns"
            ),
        }
    }
}

impl std::error::Error for PatternError {}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct Pattern {
    bits: Vec<PatternBit>,
}

impl Pattern {
    pub(crate) fn parse(value: &str) -> Result<Self, PatternError> {
        let bits: Result<Vec<_>, _> = value.trim().chars().map(PatternBit::try_from).collect();
        let bits = bits?;
        if bits.is_empty() {
            return Err(PatternError::Empty);
        }
        Ok(Self { bits })
    }

    pub(crate) fn len(&self) -> usize {
        self.bits.len()
    }

    pub(crate) fn x_count(&self) -> usize {
        self.bits
            .iter()
            .filter(|bit| **bit == PatternBit::X)
            .count()
    }

    pub(crate) fn can_merge(&self, rhs: &Self) -> bool {
        self.try_merge(rhs).is_ok()
    }

    pub(crate) fn try_merge(&self, rhs: &Self) -> Result<Self, PatternError> {
        if self.len() != rhs.len() {
            return Err(PatternError::LengthMismatch {
                left: self.len(),
                right: rhs.len(),
            });
        }

        let mut bits = Vec::with_capacity(self.len());
        for (left, right) in self.bits.iter().zip(rhs.bits.iter()) {
            bits.push(match (*left, *right) {
                (PatternBit::X, value) | (value, PatternBit::X) => value,
                (PatternBit::Zero, PatternBit::Zero) => PatternBit::Zero,
                (PatternBit::One, PatternBit::One) => PatternBit::One,
                (PatternBit::Zero, PatternBit::One) | (PatternBit::One, PatternBit::Zero) => {
                    return Err(PatternError::Conflict);
                }
            });
        }
        Ok(Self { bits })
    }

    pub(crate) fn to_binary_string_with_x_as(&self, x_value: PatternBit) -> String {
        assert_ne!(x_value, PatternBit::X);
        self.bits
            .iter()
            .map(|bit| match bit {
                PatternBit::X => char::from(x_value),
                value => char::from(*value),
            })
            .collect()
    }
}

impl Display for Pattern {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        for bit in &self.bits {
            write!(f, "{}", char::from(*bit))?;
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct AtpgPatternPair {
    pub net: String,
    pub force_one: Pattern,
    pub force_zero: Pattern,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct PatternMergeResult {
    pub merged: Pattern,
    pub activated_high: Vec<String>,
    pub activated_low: Vec<String>,
    pub conflicts: Vec<String>,
}

pub(crate) fn merge_atpg_patterns(
    pairs: &[AtpgPatternPair],
) -> Result<PatternMergeResult, PatternError> {
    let Some(first) = pairs.first() else {
        return Err(PatternError::Empty);
    };

    let (first_pattern, first_high) = choose_more_mutable(&first.force_one, &first.force_zero)?;
    let mut merged = first_pattern.clone();
    let mut activated_high = Vec::new();
    let mut activated_low = Vec::new();
    if first_high {
        activated_high.push(first.net.clone());
    } else {
        activated_low.push(first.net.clone());
    }
    let mut conflicts = Vec::new();

    for pair in pairs.iter().skip(1) {
        let high = merged.try_merge(&pair.force_one).ok();
        let low = merged.try_merge(&pair.force_zero).ok();
        match (high, low) {
            (Some(high), Some(low)) => {
                let (chosen, is_high) = choose_more_mutable(&high, &low)?;
                merged = chosen.clone();
                if is_high {
                    activated_high.push(pair.net.clone());
                } else {
                    activated_low.push(pair.net.clone());
                }
            }
            (Some(high), None) => {
                merged = high;
                activated_high.push(pair.net.clone());
            }
            (None, Some(low)) => {
                merged = low;
                activated_low.push(pair.net.clone());
            }
            (None, None) => conflicts.push(pair.net.clone()),
        }
    }

    Ok(PatternMergeResult {
        merged,
        activated_high,
        activated_low,
        conflicts,
    })
}

fn choose_more_mutable<'a>(
    high: &'a Pattern,
    low: &'a Pattern,
) -> Result<(&'a Pattern, bool), PatternError> {
    if high.len() != low.len() {
        return Err(PatternError::LengthMismatch {
            left: high.len(),
            right: low.len(),
        });
    }
    if high.x_count() >= low.x_count() {
        Ok((high, true))
    } else {
        Ok((low, false))
    }
}

#[cfg(test)]
mod tests {
    use super::{AtpgPatternPair, Pattern, PatternBit, merge_atpg_patterns};

    #[test]
    fn merges_x_bits_without_conflict() {
        let left = Pattern::parse("10XX").unwrap();
        let right = Pattern::parse("1X01").unwrap();
        assert_eq!(left.try_merge(&right).unwrap().to_string(), "1001");
    }

    #[test]
    fn detects_conflicting_concrete_bits() {
        let left = Pattern::parse("10XX").unwrap();
        let right = Pattern::parse("11XX").unwrap();
        assert!(!left.can_merge(&right));
    }

    #[test]
    fn merges_pairs_and_keeps_more_x_values() {
        let pairs = vec![
            AtpgPatternPair {
                net: "n0".to_string(),
                force_one: Pattern::parse("1XXX").unwrap(),
                force_zero: Pattern::parse("0X11").unwrap(),
            },
            AtpgPatternPair {
                net: "n1".to_string(),
                force_one: Pattern::parse("XX10").unwrap(),
                force_zero: Pattern::parse("1XX1").unwrap(),
            },
            AtpgPatternPair {
                net: "n2".to_string(),
                force_one: Pattern::parse("0XXX").unwrap(),
                force_zero: Pattern::parse("0X00").unwrap(),
            },
        ];
        let result = merge_atpg_patterns(&pairs).unwrap();
        assert_eq!(result.merged.to_string(), "1XX1");
        assert_eq!(result.activated_high, vec!["n0"]);
        assert_eq!(result.activated_low, vec!["n1"]);
        assert_eq!(result.conflicts, vec!["n2"]);
    }

    #[test]
    fn converts_x_to_concrete_seed_bits() {
        let pattern = Pattern::parse("10X1").unwrap();
        assert_eq!(pattern.to_binary_string_with_x_as(PatternBit::Zero), "1001");
    }
}
