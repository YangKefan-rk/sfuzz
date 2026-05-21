#![allow(dead_code)]

use std::cmp::Ordering;

#[derive(Clone, Debug, PartialEq)]
pub(crate) struct TargetSignal {
    pub name: String,
    pub fanin: usize,
    pub fanout: usize,
    pub entropy: f64,
    pub controllability: Option<f64>,
    pub observability: Option<f64>,
    pub depth: Option<usize>,
}

impl TargetSignal {
    pub(crate) fn new(name: impl Into<String>, fanin: usize, fanout: usize, entropy: f64) -> Self {
        Self {
            name: name.into(),
            fanin,
            fanout,
            entropy,
            controllability: None,
            observability: None,
            depth: None,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq)]
pub(crate) struct CostWeights {
    pub fanin: f64,
    pub fanout: f64,
    pub entropy: f64,
    pub controllability: f64,
    pub observability: f64,
    pub depth: f64,
}

impl Default for CostWeights {
    fn default() -> Self {
        Self {
            fanin: 1.0,
            fanout: 1.0,
            entropy: 1.0,
            controllability: 0.0,
            observability: 0.0,
            depth: 0.0,
        }
    }
}

#[derive(Clone, Debug, PartialEq)]
pub(crate) struct ScoredTarget {
    pub signal: TargetSignal,
    pub cost: f64,
}

pub(crate) fn score_targets(signals: &[TargetSignal], weights: CostWeights) -> Vec<ScoredTarget> {
    let max_fanin = signals.iter().map(|signal| signal.fanin).max().unwrap_or(1);
    let max_fanout = signals
        .iter()
        .map(|signal| signal.fanout)
        .max()
        .unwrap_or(1);
    let max_entropy = signals
        .iter()
        .map(|signal| signal.entropy)
        .fold(0.0, f64::max)
        .max(1.0);
    let max_depth = signals
        .iter()
        .filter_map(|signal| signal.depth)
        .max()
        .unwrap_or(1);

    signals
        .iter()
        .cloned()
        .map(|signal| {
            let cost = weights.fanin * signal.fanin as f64 / max_fanin as f64
                + weights.fanout * signal.fanout as f64 / max_fanout as f64
                + weights.entropy * signal.entropy / max_entropy
                + weights.controllability * signal.controllability.unwrap_or(0.0)
                + weights.observability * signal.observability.unwrap_or(0.0)
                + weights.depth * signal.depth.unwrap_or(0) as f64 / max_depth as f64;
            ScoredTarget { signal, cost }
        })
        .collect()
}

pub(crate) fn select_top_percent(
    signals: &[TargetSignal],
    weights: CostWeights,
    percent: f64,
) -> Vec<ScoredTarget> {
    if signals.is_empty() || percent <= 0.0 {
        return Vec::new();
    }
    let mut scored = score_targets(signals, weights);
    scored.sort_by(|left, right| {
        right
            .cost
            .partial_cmp(&left.cost)
            .unwrap_or(Ordering::Equal)
            .then_with(|| left.signal.name.cmp(&right.signal.name))
    });
    let count = ((signals.len() as f64) * percent / 100.0).ceil() as usize;
    scored.truncate(count.max(1).min(scored.len()));
    scored
}

pub(crate) fn select_above_threshold(
    signals: &[TargetSignal],
    weights: CostWeights,
    threshold: f64,
) -> Vec<ScoredTarget> {
    let mut scored: Vec<_> = score_targets(signals, weights)
        .into_iter()
        .filter(|target| target.cost >= threshold)
        .collect();
    scored.sort_by(|left, right| {
        right
            .cost
            .partial_cmp(&left.cost)
            .unwrap_or(Ordering::Equal)
            .then_with(|| left.signal.name.cmp(&right.signal.name))
    });
    scored
}

#[cfg(test)]
mod tests {
    use super::{
        CostWeights, TargetSignal, score_targets, select_above_threshold, select_top_percent,
    };

    fn targets() -> Vec<TargetSignal> {
        vec![
            TargetSignal::new("a", 1, 2, 0.2),
            TargetSignal::new("b", 8, 1, 0.9),
            TargetSignal::new("c", 4, 10, 0.4),
            TargetSignal::new("d", 2, 3, 0.1),
        ]
    }

    #[test]
    fn scores_targets_from_structural_and_entropy_features() {
        let scored = score_targets(&targets(), CostWeights::default());
        let b = scored
            .iter()
            .find(|target| target.signal.name == "b")
            .unwrap();
        assert!(b.cost > 1.9);
    }

    #[test]
    fn selects_top_percent_by_cost() {
        let selected = select_top_percent(&targets(), CostWeights::default(), 50.0);
        assert_eq!(selected.len(), 2);
        assert_eq!(selected[0].signal.name, "b");
        assert_eq!(selected[1].signal.name, "c");
    }

    #[test]
    fn selects_threshold_targets() {
        let selected = select_above_threshold(&targets(), CostWeights::default(), 1.8);
        assert_eq!(
            selected
                .iter()
                .map(|target| target.signal.name.as_str())
                .collect::<Vec<_>>(),
            vec!["b", "c"]
        );
    }
}
