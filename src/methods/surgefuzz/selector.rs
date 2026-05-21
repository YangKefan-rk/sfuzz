#![allow(dead_code)]

use std::collections::{HashMap, HashSet};

use super::metadata::AncestorSignal;

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct RegisterSample {
    pub name: String,
    pub values: Vec<u64>,
}

pub(crate) fn select_by_distance(signals: &[AncestorSignal], max_bits: usize) -> Vec<String> {
    let mut candidates: Vec<_> = signals
        .iter()
        .filter(|signal| signal.name.starts_with("dependent_"))
        .collect();
    candidates.sort_by_key(|signal| {
        (
            signal.register_depth,
            signal.depth,
            !signal.is_control,
            signal.name.clone(),
        )
    });

    let mut selected = Vec::new();
    let mut bits = 0usize;
    for signal in candidates {
        if bits >= max_bits {
            break;
        }
        selected.push(signal.name.clone());
        bits += signal.width;
    }
    selected
}

pub(crate) fn select_by_distance_and_nmi(
    signals: &[AncestorSignal],
    samples: &[RegisterSample],
    max_bits: usize,
    nmi_threshold: f64,
) -> Vec<String> {
    let sample_map: HashMap<_, _> = samples
        .iter()
        .map(|sample| (sample.name.as_str(), sample.values.as_slice()))
        .collect();
    let mut candidates: Vec<_> = signals
        .iter()
        .filter(|signal| signal.name.starts_with("dependent_"))
        .collect();
    candidates.sort_by_key(|signal| {
        (
            signal.register_depth,
            signal.depth,
            !signal.is_control,
            signal.name.clone(),
        )
    });

    let mut selected = Vec::new();
    let mut bits = 0usize;
    for candidate in candidates {
        if bits >= max_bits {
            break;
        }
        let Some(candidate_samples) = sample_map.get(candidate.name.as_str()) else {
            continue;
        };

        let redundant = selected.iter().any(|selected_name: &String| {
            let Some(selected_samples) = sample_map.get(selected_name.as_str()) else {
                return false;
            };
            normalized_mutual_information(candidate_samples, selected_samples) >= nmi_threshold
        });
        if redundant {
            continue;
        }

        selected.push(candidate.name.clone());
        bits += candidate.width;
    }
    selected
}

pub(crate) fn normalized_mutual_information(x: &[u64], y: &[u64]) -> f64 {
    assert_eq!(x.len(), y.len(), "sample vectors must have the same length");
    if x.is_empty() {
        return 0.0;
    }

    let hx = entropy(x);
    let hy = entropy(y);
    if hx == 0.0 && hy == 0.0 {
        return if x == y { 1.0 } else { 0.0 };
    }

    let mi = mutual_information(x, y);
    2.0 * mi / (hx + hy)
}

fn entropy(values: &[u64]) -> f64 {
    let mut counts = HashMap::new();
    for value in values {
        *counts.entry(*value).or_insert(0usize) += 1;
    }
    let total = values.len() as f64;
    counts
        .values()
        .map(|count| {
            let p = *count as f64 / total;
            -p * p.log2()
        })
        .sum()
}

fn mutual_information(x: &[u64], y: &[u64]) -> f64 {
    let total = x.len() as f64;
    let mut x_counts = HashMap::new();
    let mut y_counts = HashMap::new();
    let mut xy_counts = HashMap::new();

    for (xv, yv) in x.iter().zip(y.iter()) {
        *x_counts.entry(*xv).or_insert(0usize) += 1;
        *y_counts.entry(*yv).or_insert(0usize) += 1;
        *xy_counts.entry((*xv, *yv)).or_insert(0usize) += 1;
    }

    xy_counts
        .into_iter()
        .map(|((xv, yv), xy_count)| {
            let pxy = xy_count as f64 / total;
            let px = *x_counts.get(&xv).unwrap() as f64 / total;
            let py = *y_counts.get(&yv).unwrap() as f64 / total;
            pxy * (pxy / (px * py)).log2()
        })
        .sum()
}

pub(crate) fn parse_dependents_csv(csv: &str) -> Vec<RegisterSample> {
    let mut lines = csv.lines();
    let Some(header) = lines.find(|line| !line.trim().is_empty()) else {
        return Vec::new();
    };
    let names: Vec<_> = header.split(',').map(str::trim).collect();
    let dependent_names: Vec<_> = names
        .iter()
        .copied()
        .filter(|name| name.starts_with("dependent_"))
        .collect();
    let mut values: HashMap<String, Vec<u64>> = dependent_names
        .iter()
        .map(|name| ((*name).to_string(), Vec::new()))
        .collect();
    let dependent_set: HashSet<_> = dependent_names.into_iter().collect();

    for line in lines {
        let fields: Vec<_> = line.split(',').map(str::trim).collect();
        for (idx, name) in names.iter().enumerate() {
            if !dependent_set.contains(name) {
                continue;
            }
            let parsed = fields
                .get(idx)
                .and_then(|field| field.parse::<u64>().ok())
                .unwrap_or(0);
            values.get_mut(*name).unwrap().push(parsed);
        }
    }

    let mut samples: Vec<_> = values
        .into_iter()
        .map(|(name, values)| RegisterSample { name, values })
        .collect();
    samples.sort_by(|left, right| left.name.cmp(&right.name));
    samples
}

#[cfg(test)]
mod tests {
    use super::{
        RegisterSample, normalized_mutual_information, parse_dependents_csv, select_by_distance,
        select_by_distance_and_nmi,
    };
    use crate::methods::surgefuzz::metadata::AncestorSignal;

    fn signal(name: &str, width: usize, depth: usize, reg_depth: usize) -> AncestorSignal {
        AncestorSignal {
            name: name.to_string(),
            width,
            source: name.to_string(),
            depth,
            register_depth: reg_depth,
            is_control: false,
            cell_name: "$dff".to_string(),
        }
    }

    #[test]
    fn selects_closest_dependents_until_bit_budget() {
        let signals = vec![
            signal("dependent_2", 2, 3, 1),
            signal("dependent_0", 1, 1, 0),
            signal("dependent_1", 4, 2, 0),
        ];
        assert_eq!(
            select_by_distance(&signals, 2),
            vec!["dependent_0".to_string(), "dependent_1".to_string()]
        );
    }

    #[test]
    fn normalized_mutual_information_detects_identical_registers() {
        assert_eq!(
            normalized_mutual_information(&[0, 1, 0, 1], &[0, 1, 0, 1]),
            1.0
        );
        assert!(normalized_mutual_information(&[0, 0, 1, 1], &[0, 1, 0, 1]) < 0.01);
    }

    #[test]
    fn nmi_selection_prunes_redundant_dependents() {
        let signals = vec![
            signal("dependent_0", 1, 1, 0),
            signal("dependent_1", 1, 2, 0),
            signal("dependent_2", 1, 3, 0),
        ];
        let samples = vec![
            RegisterSample {
                name: "dependent_0".to_string(),
                values: vec![0, 1, 0, 1],
            },
            RegisterSample {
                name: "dependent_1".to_string(),
                values: vec![0, 1, 0, 1],
            },
            RegisterSample {
                name: "dependent_2".to_string(),
                values: vec![0, 0, 1, 1],
            },
        ];
        assert_eq!(
            select_by_distance_and_nmi(&signals, &samples, 3, 0.7),
            vec!["dependent_0".to_string(), "dependent_2".to_string()]
        );
    }

    #[test]
    fn parses_dependents_csv_samples() {
        let samples = parse_dependents_csv(
            "\
cycle,dependent_0,dependent_1,coverage_target
0,3,7,0
1,4,7,1
",
        );
        assert_eq!(
            samples,
            vec![
                RegisterSample {
                    name: "dependent_0".to_string(),
                    values: vec![3, 4],
                },
                RegisterSample {
                    name: "dependent_1".to_string(),
                    values: vec![7, 7],
                },
            ]
        );
    }
}
