#![allow(dead_code)]

use std::fmt::{Display, Formatter};

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct AncestorSignal {
    pub name: String,
    pub width: usize,
    pub source: String,
    pub depth: usize,
    pub register_depth: usize,
    pub is_control: bool,
    pub cell_name: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct SurgeMetadata {
    signals: Vec<AncestorSignal>,
    coverage_bits: usize,
    ancestor_count: usize,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum SurgeMetadataError {
    CsvHeader {
        header: String,
    },
    CsvFieldCount {
        line: usize,
        expected: usize,
        actual: usize,
    },
    CsvNumber {
        line: usize,
        field: String,
        value: String,
    },
    Empty,
}

impl Display for SurgeMetadataError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::CsvHeader { header } => write!(
                f,
                "invalid SurgeFuzz metadata CSV header '{header}', expected name,width,src,depth,reg_depth,is_ctrl,cell_name"
            ),
            Self::CsvFieldCount {
                line,
                expected,
                actual,
            } => write!(
                f,
                "invalid SurgeFuzz metadata CSV at line {line}: expected {expected} fields, got {actual}"
            ),
            Self::CsvNumber { line, field, value } => write!(
                f,
                "invalid SurgeFuzz metadata number at line {line}, field {field}: '{value}'"
            ),
            Self::Empty => write!(f, "SurgeFuzz metadata must contain at least one signal"),
        }
    }
}

impl std::error::Error for SurgeMetadataError {}

impl SurgeMetadata {
    const CSV_HEADER: &'static str = "name,width,src,depth,reg_depth,is_ctrl,cell_name";

    pub(crate) fn new(signals: Vec<AncestorSignal>) -> Result<Self, SurgeMetadataError> {
        if signals.is_empty() {
            return Err(SurgeMetadataError::Empty);
        }
        let coverage_bits = signals
            .iter()
            .filter(|signal| signal.name.starts_with("dependent_"))
            .map(|signal| signal.width)
            .sum();
        let ancestor_count = signals
            .iter()
            .filter(|signal| signal.name.starts_with("dependent_"))
            .count();
        Ok(Self {
            signals,
            coverage_bits,
            ancestor_count,
        })
    }

    pub(crate) fn from_csv_str(csv: &str) -> Result<Self, SurgeMetadataError> {
        let mut lines = csv.lines().enumerate();
        let Some((_, header)) = lines.find(|(_, line)| !line.trim().is_empty()) else {
            return Err(SurgeMetadataError::Empty);
        };
        let header = header.trim();
        if header != Self::CSV_HEADER {
            return Err(SurgeMetadataError::CsvHeader {
                header: header.to_string(),
            });
        }

        let mut signals = Vec::new();
        for (idx, line) in lines {
            let line_no = idx + 1;
            let line = line.trim();
            if line.is_empty() {
                continue;
            }

            let fields: Vec<_> = line.split(',').map(str::trim).collect();
            if fields.len() != 7 {
                return Err(SurgeMetadataError::CsvFieldCount {
                    line: line_no,
                    expected: 7,
                    actual: fields.len(),
                });
            }

            signals.push(AncestorSignal {
                name: fields[0].to_string(),
                width: parse_usize(line_no, "width", fields[1])?,
                source: fields[2].to_string(),
                depth: parse_usize(line_no, "depth", fields[3])?,
                register_depth: parse_usize(line_no, "reg_depth", fields[4])?,
                is_control: parse_boolish(fields[5]),
                cell_name: fields[6].to_string(),
            });
        }
        Self::new(signals)
    }

    pub(crate) fn signals(&self) -> &[AncestorSignal] {
        &self.signals
    }

    pub(crate) fn coverage_bits(&self) -> usize {
        self.coverage_bits
    }

    pub(crate) fn ancestor_count(&self) -> usize {
        self.ancestor_count
    }

    pub(crate) fn bitmap_byte_size(&self) -> Option<usize> {
        if self.coverage_bits >= usize::BITS as usize {
            None
        } else {
            Some(1usize << self.coverage_bits)
        }
    }
}

fn parse_usize(line: usize, field: &str, value: &str) -> Result<usize, SurgeMetadataError> {
    value
        .parse::<usize>()
        .map_err(|_| SurgeMetadataError::CsvNumber {
            line,
            field: field.to_string(),
            value: value.to_string(),
        })
}

fn parse_boolish(value: &str) -> bool {
    matches!(value.trim(), "1" | "true" | "TRUE")
}

#[cfg(test)]
mod tests {
    use super::{SurgeMetadata, SurgeMetadataError};

    #[test]
    fn parses_surgefuzz_instrument_csv() {
        let metadata = SurgeMetadata::from_csv_str(
            "\
name,width,src,depth,reg_depth,is_ctrl,cell_name
coverage,1,1'0,0,0,0,
coverage_target,1,\\target,0,0,0,
dependent_0,1,\\foo,1,0,1,$mux
dependent_1,3,\\bar [2:0],3,1,0,$dff
",
        )
        .unwrap();
        assert_eq!(metadata.signals().len(), 4);
        assert_eq!(metadata.ancestor_count(), 2);
        assert_eq!(metadata.coverage_bits(), 4);
        assert_eq!(metadata.bitmap_byte_size(), Some(16));
        assert!(metadata.signals()[2].is_control);
    }

    #[test]
    fn rejects_bad_field_count() {
        let err = SurgeMetadata::from_csv_str(
            "\
name,width,src,depth,reg_depth,is_ctrl,cell_name
dependent_0,1,\\foo
",
        )
        .unwrap_err();
        assert_eq!(
            err,
            SurgeMetadataError::CsvFieldCount {
                line: 2,
                expected: 7,
                actual: 3,
            }
        );
    }
}
