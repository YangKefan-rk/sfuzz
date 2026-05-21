#![allow(dead_code)]

use std::collections::VecDeque;
use std::fmt::{Display, Formatter};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum SurgeAnnotation {
    Freq { active: bool, window: usize },
    Consec { active: bool },
    Count { direction: CountDirection },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum CountDirection {
    Max,
    Min,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum SurgeAnnotationError {
    Unknown(String),
    InvalidValue { kind: String, value: String },
}

impl Display for SurgeAnnotationError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Unknown(value) => write!(f, "unknown SurgeFuzz annotation '{value}'"),
            Self::InvalidValue { kind, value } => {
                write!(f, "invalid SurgeFuzz {kind} annotation value '{value}'")
            }
        }
    }
}

impl std::error::Error for SurgeAnnotationError {}

impl SurgeAnnotation {
    pub(crate) const DEFAULT_FREQ_WINDOW: usize = 256;

    pub(crate) fn parse(value: &str) -> Result<Self, SurgeAnnotationError> {
        let value = value.trim();
        let Some((kind, raw_setting)) = value.split_once('=') else {
            return Err(SurgeAnnotationError::Unknown(value.to_string()));
        };
        let kind = normalize_key(kind);
        let setting = raw_setting.trim().trim_matches('"');

        match kind.as_str() {
            "SURGEFREQ" | "FREQ" => Ok(Self::Freq {
                active: parse_bool_setting("FREQ", setting)?,
                window: Self::DEFAULT_FREQ_WINDOW,
            }),
            "SURGECONSEC" | "CONSEC" => Ok(Self::Consec {
                active: parse_bool_setting("CONSEC", setting)?,
            }),
            "SURGECOUNT" | "COUNT" => Ok(Self::Count {
                direction: parse_count_direction(setting)?,
            }),
            _ => Err(SurgeAnnotationError::Unknown(value.to_string())),
        }
    }
}

fn normalize_key(key: &str) -> String {
    key.chars()
        .filter(|ch| *ch != '_' && !ch.is_whitespace())
        .flat_map(char::to_uppercase)
        .collect()
}

fn parse_bool_setting(kind: &str, value: &str) -> Result<bool, SurgeAnnotationError> {
    match value {
        "1" | "true" | "TRUE" => Ok(true),
        "0" | "false" | "FALSE" => Ok(false),
        _ => Err(SurgeAnnotationError::InvalidValue {
            kind: kind.to_string(),
            value: value.to_string(),
        }),
    }
}

fn parse_count_direction(value: &str) -> Result<CountDirection, SurgeAnnotationError> {
    match value {
        "MAX" | "max" | "1" => Ok(CountDirection::Max),
        "MIN" | "min" | "0" => Ok(CountDirection::Min),
        _ => Err(SurgeAnnotationError::InvalidValue {
            kind: "COUNT".to_string(),
            value: value.to_string(),
        }),
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct SurgeRecorder {
    annotation: SurgeAnnotation,
    history: VecDeque<bool>,
    current_consecutive: usize,
    best_score: u32,
    score_bitmap: [bool; 256],
}

impl SurgeRecorder {
    pub(crate) fn new(annotation: SurgeAnnotation) -> Self {
        Self {
            annotation,
            history: VecDeque::new(),
            current_consecutive: 0,
            best_score: 0,
            score_bitmap: [false; 256],
        }
    }

    pub(crate) fn reset(&mut self) {
        self.history.clear();
        self.current_consecutive = 0;
        self.best_score = 0;
        self.score_bitmap.fill(false);
    }

    pub(crate) fn update(&mut self, annotated_value: u32) -> u32 {
        let score = match self.annotation {
            SurgeAnnotation::Freq { active, window } => {
                let hit = annotated_value != 0;
                self.update_freq(hit == active, window)
            }
            SurgeAnnotation::Consec { active } => {
                let hit = annotated_value != 0;
                self.update_consec(hit == active)
            }
            SurgeAnnotation::Count {
                direction: CountDirection::Max,
            } => annotated_value,
            SurgeAnnotation::Count {
                direction: CountDirection::Min,
            } => u32::MAX - annotated_value,
        };
        self.best_score = self.best_score.max(score);
        self.score_bitmap[(score & 0xff) as usize] = true;
        score
    }

    pub(crate) fn best_score(&self) -> u32 {
        self.best_score
    }

    pub(crate) fn score_bitmap(&self) -> &[bool; 256] {
        &self.score_bitmap
    }

    fn update_freq(&mut self, hit: bool, window: usize) -> u32 {
        let window = window.max(1);
        self.history.push_back(hit);
        if self.history.len() > window {
            self.history.pop_front();
        }
        self.history.iter().filter(|hit| **hit).count() as u32
    }

    fn update_consec(&mut self, hit: bool) -> u32 {
        if hit {
            self.current_consecutive += 1;
        } else {
            self.current_consecutive = 0;
        }
        self.current_consecutive as u32
    }
}

#[derive(Clone, Copy, Debug, PartialEq)]
pub(crate) struct SurgePowerSchedule {
    pub exponent: u32,
}

impl Default for SurgePowerSchedule {
    fn default() -> Self {
        Self { exponent: 2 }
    }
}

impl SurgePowerSchedule {
    pub(crate) fn energy(&self, score: u32) -> f64 {
        (score as f64).powi(self.exponent as i32)
    }
}

#[cfg(test)]
mod tests {
    use super::{CountDirection, SurgeAnnotation, SurgePowerSchedule, SurgeRecorder};

    #[test]
    fn parses_annotation_spellings() {
        assert_eq!(
            SurgeAnnotation::parse("SURGE_FREQ=1").unwrap(),
            SurgeAnnotation::Freq {
                active: true,
                window: SurgeAnnotation::DEFAULT_FREQ_WINDOW,
            }
        );
        assert_eq!(
            SurgeAnnotation::parse("SURGE_CONSEC=0").unwrap(),
            SurgeAnnotation::Consec { active: false }
        );
        assert_eq!(
            SurgeAnnotation::parse("SURGECOUNT=\"MAX\"").unwrap(),
            SurgeAnnotation::Count {
                direction: CountDirection::Max,
            }
        );
    }

    #[test]
    fn freq_score_is_sliding_window_count() {
        let mut recorder = SurgeRecorder::new(SurgeAnnotation::Freq {
            active: true,
            window: 4,
        });
        let scores: Vec<_> = [1, 0, 1, 1, 0, 1]
            .into_iter()
            .map(|value| recorder.update(value))
            .collect();
        assert_eq!(scores, vec![1, 1, 2, 3, 2, 3]);
        assert_eq!(recorder.best_score(), 3);
        assert!(recorder.score_bitmap()[3]);
    }

    #[test]
    fn freq_default_window_is_256_cycles() {
        let mut recorder = SurgeRecorder::new(SurgeAnnotation::Freq {
            active: true,
            window: SurgeAnnotation::DEFAULT_FREQ_WINDOW,
        });
        for _ in 0..SurgeAnnotation::DEFAULT_FREQ_WINDOW {
            assert!(recorder.update(1) <= 256);
        }
        assert_eq!(recorder.best_score(), 256);
        assert_eq!(recorder.update(0), 255);
        assert_eq!(recorder.update(1), 255);
        assert!(recorder.score_bitmap()[0]);
        assert!(recorder.score_bitmap()[255]);
    }

    #[test]
    fn freq_zero_annotation_counts_zero_values() {
        let mut recorder = SurgeRecorder::new(SurgeAnnotation::Freq {
            active: false,
            window: 4,
        });
        let scores: Vec<_> = [0, 1, 0, 0, 1, 0]
            .into_iter()
            .map(|value| recorder.update(value))
            .collect();
        assert_eq!(scores, vec![1, 1, 2, 3, 2, 3]);
    }

    #[test]
    fn consec_score_tracks_current_run() {
        let mut recorder = SurgeRecorder::new(SurgeAnnotation::Consec { active: true });
        let scores: Vec<_> = [1, 1, 0, 1, 1, 1]
            .into_iter()
            .map(|value| recorder.update(value))
            .collect();
        assert_eq!(scores, vec![1, 2, 0, 1, 2, 3]);
    }

    #[test]
    fn consec_resets_and_can_target_zero() {
        let mut recorder = SurgeRecorder::new(SurgeAnnotation::Consec { active: false });
        let scores: Vec<_> = [0, 0, 1, 0, 0, 0, 1]
            .into_iter()
            .map(|value| recorder.update(value))
            .collect();
        assert_eq!(scores, vec![1, 2, 0, 1, 2, 3, 0]);
        assert_eq!(recorder.best_score(), 3);
        recorder.reset();
        assert_eq!(recorder.best_score(), 0);
        assert_eq!(recorder.update(0), 1);
    }

    #[test]
    fn freq_and_consec_treat_nonzero_values_as_active() {
        let mut freq = SurgeRecorder::new(SurgeAnnotation::Freq {
            active: true,
            window: 4,
        });
        assert_eq!(freq.update(2), 1);

        let mut consec = SurgeRecorder::new(SurgeAnnotation::Consec { active: true });
        assert_eq!(consec.update(3), 1);
        assert_eq!(consec.update(0), 0);
    }

    #[test]
    fn count_score_keeps_raw_value_for_max() {
        let mut recorder = SurgeRecorder::new(SurgeAnnotation::Count {
            direction: CountDirection::Max,
        });
        assert_eq!(recorder.update(7), 7);
        assert_eq!(recorder.update(3), 3);
        assert_eq!(recorder.best_score(), 7);
    }

    #[test]
    fn count_min_inverts_raw_value_for_score_ordering() {
        let mut recorder = SurgeRecorder::new(SurgeAnnotation::Count {
            direction: CountDirection::Min,
        });
        assert_eq!(recorder.update(7), u32::MAX - 7);
        assert_eq!(recorder.update(3), u32::MAX - 3);
        assert_eq!(recorder.best_score(), u32::MAX - 3);
    }

    #[test]
    fn score_bitmap_uses_low_8_score_bits() {
        let mut recorder = SurgeRecorder::new(SurgeAnnotation::Count {
            direction: CountDirection::Max,
        });
        recorder.update(0x123);
        assert!(recorder.score_bitmap()[0x23]);
        assert!(!recorder.score_bitmap()[0x22]);
    }

    #[test]
    fn quadratic_power_schedule_matches_paper() {
        assert_eq!(SurgePowerSchedule::default().energy(9), 81.0);
        assert_eq!(SurgePowerSchedule::default().energy(0), 0.0);
    }
}
