#![allow(dead_code)]

use std::fmt::{Display, Formatter};

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct CoverageInstance {
    pub instance: String,
    pub signal: String,
    pub width: usize,
    pub distance: Option<usize>,
}

impl CoverageInstance {
    pub(crate) fn new(
        instance: impl Into<String>,
        signal: impl Into<String>,
        width: usize,
        distance: Option<usize>,
    ) -> Self {
        Self {
            instance: instance.into(),
            signal: signal.into(),
            width,
            distance,
        }
    }

    pub(crate) fn is_target(&self) -> bool {
        self.distance == Some(0)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct DirectFuzzMetadata {
    instances: Vec<CoverageInstance>,
    max_distance: usize,
    total_width: usize,
    target_width: usize,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum DirectFuzzMetadataError {
    Empty,
    MissingTarget,
    CsvHeader {
        header: String,
    },
    CsvFieldCount {
        line: usize,
        expected: usize,
        actual: usize,
    },
    CsvWidth {
        line: usize,
        value: String,
    },
    CsvDistance {
        line: usize,
        value: String,
    },
    WidthMismatch {
        expected_instances: usize,
        actual_instances: usize,
    },
}

impl Display for DirectFuzzMetadataError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Empty => write!(f, "DirectFuzz metadata must contain at least one instance"),
            Self::MissingTarget => write!(
                f,
                "DirectFuzz metadata must contain at least one target instance at distance 0"
            ),
            Self::CsvHeader { header } => write!(
                f,
                "invalid DirectFuzz metadata CSV header '{header}', expected instance_name,coverage_signal_name,width,distance"
            ),
            Self::CsvFieldCount {
                line,
                expected,
                actual,
            } => write!(
                f,
                "invalid DirectFuzz metadata CSV at line {line}: expected {expected} fields, got {actual}"
            ),
            Self::CsvWidth { line, value } => write!(
                f,
                "invalid DirectFuzz metadata width at line {line}: '{value}'"
            ),
            Self::CsvDistance { line, value } => write!(
                f,
                "invalid DirectFuzz metadata distance at line {line}: '{value}'"
            ),
            Self::WidthMismatch {
                expected_instances,
                actual_instances,
            } => write!(
                f,
                "coverage instance count mismatch: expected {expected_instances}, got {actual_instances}"
            ),
        }
    }
}

impl std::error::Error for DirectFuzzMetadataError {}

impl DirectFuzzMetadata {
    const CSV_HEADER: &'static str = "instance_name,coverage_signal_name,width,distance";
    const SURGEFUZZ_UNREACHABLE_DISTANCE: usize = 256;

    pub(crate) fn new(instances: Vec<CoverageInstance>) -> Result<Self, DirectFuzzMetadataError> {
        if instances.is_empty() {
            return Err(DirectFuzzMetadataError::Empty);
        }

        let target_width = instances
            .iter()
            .filter(|instance| instance.is_target())
            .map(|instance| instance.width)
            .sum();
        if target_width == 0 {
            return Err(DirectFuzzMetadataError::MissingTarget);
        }

        let max_distance = instances
            .iter()
            .filter_map(|instance| instance.distance)
            .max()
            .unwrap_or(0);
        let total_width = instances.iter().map(|instance| instance.width).sum();
        Ok(Self {
            instances,
            max_distance,
            total_width,
            target_width,
        })
    }

    pub(crate) fn from_csv_str(csv: &str) -> Result<Self, DirectFuzzMetadataError> {
        let mut lines = csv.lines().enumerate();
        let Some((_, header)) = lines.find(|(_, line)| !line.trim().is_empty()) else {
            return Err(DirectFuzzMetadataError::Empty);
        };

        let header = header.trim();
        if header != Self::CSV_HEADER {
            return Err(DirectFuzzMetadataError::CsvHeader {
                header: header.to_string(),
            });
        }

        let mut instances = Vec::new();
        for (idx, line) in lines {
            let line_no = idx + 1;
            let line = line.trim();
            if line.is_empty() {
                continue;
            }

            let fields: Vec<_> = line.split(',').map(str::trim).collect();
            if fields.len() != 4 {
                return Err(DirectFuzzMetadataError::CsvFieldCount {
                    line: line_no,
                    expected: 4,
                    actual: fields.len(),
                });
            }

            let width =
                fields[2]
                    .parse::<usize>()
                    .map_err(|_| DirectFuzzMetadataError::CsvWidth {
                        line: line_no,
                        value: fields[2].to_string(),
                    })?;
            let distance =
                parse_distance(fields[3]).map_err(|_| DirectFuzzMetadataError::CsvDistance {
                    line: line_no,
                    value: fields[3].to_string(),
                })?;

            instances.push(CoverageInstance::new(fields[0], fields[1], width, distance));
        }

        Self::new(instances)
    }

    pub(crate) fn instances(&self) -> &[CoverageInstance] {
        &self.instances
    }

    pub(crate) fn max_distance(&self) -> usize {
        self.max_distance
    }

    pub(crate) fn total_width(&self) -> usize {
        self.total_width
    }

    pub(crate) fn target_width(&self) -> usize {
        self.target_width
    }

    pub(crate) fn target_covered_bits(&self, coverage: &[Vec<u8>]) -> usize {
        self.validate_coverage(coverage)
            .expect("coverage shape must match DirectFuzz metadata");
        coverage
            .iter()
            .zip(self.instances.iter())
            .filter(|(_, instance)| instance.is_target())
            .map(|(bytes, instance)| count_bits_with_width(bytes, instance.width))
            .sum()
    }

    pub(crate) fn input_distance(&self, coverage: &[Vec<u8>]) -> Option<f64> {
        self.validate_coverage(coverage)
            .expect("coverage shape must match DirectFuzz metadata");

        let mut weighted_distance = 0usize;
        let mut covered = 0usize;
        for (bytes, instance) in coverage.iter().zip(self.instances.iter()) {
            let Some(distance) = instance.distance else {
                continue;
            };
            let bits = count_bits_with_width(bytes, instance.width);
            covered += bits;
            weighted_distance += bits * distance;
        }

        if covered == 0 {
            None
        } else {
            Some(weighted_distance as f64 / covered as f64)
        }
    }

    fn validate_coverage(&self, coverage: &[Vec<u8>]) -> Result<(), DirectFuzzMetadataError> {
        if coverage.len() != self.instances.len() {
            return Err(DirectFuzzMetadataError::WidthMismatch {
                expected_instances: self.instances.len(),
                actual_instances: coverage.len(),
            });
        }
        Ok(())
    }
}

fn parse_distance(value: &str) -> Result<Option<usize>, ()> {
    if value.eq_ignore_ascii_case("undefined")
        || value.eq_ignore_ascii_case("unreachable")
        || value.eq_ignore_ascii_case("none")
    {
        return Ok(None);
    }

    let distance = value.parse::<usize>().map_err(|_| ())?;
    if distance == DirectFuzzMetadata::SURGEFUZZ_UNREACHABLE_DISTANCE {
        Ok(None)
    } else {
        Ok(Some(distance))
    }
}

fn count_bits_with_width(bytes: &[u8], width: usize) -> usize {
    let full_bytes = width / 8;
    let tail_bits = width % 8;
    let full_count: usize = bytes
        .iter()
        .take(full_bytes)
        .map(|byte| byte.count_ones() as usize)
        .sum();

    if tail_bits == 0 {
        full_count
    } else {
        let Some(tail) = bytes.get(full_bytes) else {
            return full_count;
        };
        let mask = (1u8 << tail_bits) - 1;
        full_count + (tail & mask).count_ones() as usize
    }
}

#[cfg(test)]
mod tests {
    use super::{CoverageInstance, DirectFuzzMetadata, DirectFuzzMetadataError};

    fn metadata() -> DirectFuzzMetadata {
        DirectFuzzMetadata::new(vec![
            CoverageInstance::new("root", "\\coverage_root", 8, Some(2)),
            CoverageInstance::new("near", "\\coverage_near", 8, Some(1)),
            CoverageInstance::new("target", "\\coverage_target", 8, Some(0)),
            CoverageInstance::new("unreachable", "\\coverage_dead", 8, None),
        ])
        .unwrap()
    }

    #[test]
    fn rejects_missing_target() {
        let err = DirectFuzzMetadata::new(vec![CoverageInstance::new("a", "cov", 1, Some(3))])
            .unwrap_err();
        assert_eq!(err, DirectFuzzMetadataError::MissingTarget);
    }

    #[test]
    fn computes_average_distance_over_covered_instances() {
        let metadata = metadata();
        let coverage = vec![vec![0b0000_0011], vec![0b0000_0001], vec![0], vec![0xff]];
        assert_eq!(metadata.input_distance(&coverage), Some(5.0 / 3.0));
    }

    #[test]
    fn ignores_unreachable_instances_for_distance() {
        let metadata = metadata();
        let coverage = vec![vec![0], vec![0], vec![0], vec![0xff]];
        assert_eq!(metadata.input_distance(&coverage), None);
    }

    #[test]
    fn counts_target_coverage() {
        let metadata = metadata();
        let coverage = vec![vec![0xff], vec![0xff], vec![0b1010_0001], vec![0xff]];
        assert_eq!(metadata.target_covered_bits(&coverage), 3);
    }

    #[test]
    fn ignores_padding_bits_beyond_instance_width() {
        let metadata = DirectFuzzMetadata::new(vec![
            CoverageInstance::new("near", "\\coverage_near", 3, Some(1)),
            CoverageInstance::new("target", "\\coverage_target", 3, Some(0)),
        ])
        .unwrap();
        let coverage = vec![vec![0xff], vec![0xff]];
        assert_eq!(metadata.input_distance(&coverage), Some(0.5));
        assert_eq!(metadata.target_covered_bits(&coverage), 3);
    }

    #[test]
    fn parses_surgefuzz_directfuzz_csv() {
        let metadata = DirectFuzzMetadata::from_csv_str(
            "\
instance_name,coverage_signal_name,width,distance
root,\\coverage_root,8,2
near,\\coverage_near,4,1
target,\\coverage_target,3,0
dead,\\coverage_dead,1,256
",
        )
        .unwrap();

        assert_eq!(metadata.instances().len(), 4);
        assert_eq!(metadata.total_width(), 16);
        assert_eq!(metadata.target_width(), 3);
        assert_eq!(metadata.max_distance(), 2);
        assert_eq!(metadata.instances()[3].distance, None);
    }

    #[test]
    fn rejects_bad_csv_shape() {
        let err = DirectFuzzMetadata::from_csv_str(
            "\
instance_name,coverage_signal_name,width,distance
root,\\coverage_root,8
",
        )
        .unwrap_err();
        assert_eq!(
            err,
            DirectFuzzMetadataError::CsvFieldCount {
                line: 2,
                expected: 4,
                actual: 3,
            }
        );
    }
}
