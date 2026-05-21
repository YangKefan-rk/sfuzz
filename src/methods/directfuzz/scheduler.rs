#![allow(dead_code)]

use std::collections::VecDeque;

use super::energy::DirectFuzzFeedback;

#[derive(Clone, Debug, PartialEq)]
pub(crate) struct DirectFuzzSeedMeta {
    pub id: usize,
    pub feedback: DirectFuzzFeedback,
    pub use_default_energy: bool,
}

/// DirectFuzz's two-queue seed prioritization.
///
/// Seeds that cover at least one target-instance mux-select signal are served
/// from a priority FIFO before regular RFuzz seeds.  If target coverage has not
/// improved for `escape_interval` scheduled seeds, `next` can deliberately
/// escape to the currently lowest-energy regular seed with default energy.
#[derive(Clone, Debug)]
pub(crate) struct DirectFuzzQueue {
    target: VecDeque<DirectFuzzSeedMeta>,
    regular: VecDeque<DirectFuzzSeedMeta>,
    no_target_progress: usize,
    escape_interval: usize,
}

impl Default for DirectFuzzQueue {
    fn default() -> Self {
        Self::new(10)
    }
}

impl DirectFuzzQueue {
    pub(crate) fn new(escape_interval: usize) -> Self {
        Self {
            target: VecDeque::new(),
            regular: VecDeque::new(),
            no_target_progress: 0,
            escape_interval,
        }
    }

    pub(crate) fn push(&mut self, id: usize, feedback: DirectFuzzFeedback) {
        let meta = DirectFuzzSeedMeta {
            id,
            feedback,
            use_default_energy: false,
        };
        if feedback.covered_target() {
            self.target.push_back(meta);
        } else {
            self.regular.push_back(meta);
        }
        if feedback.target_progress {
            self.no_target_progress = 0;
        }
    }

    pub(crate) fn next(&mut self) -> Option<DirectFuzzSeedMeta> {
        let selected = if self.should_escape_local_minimum() {
            let mut selected = self.pop_low_energy_regular();
            if let Some(seed) = selected.as_mut() {
                seed.use_default_energy = true;
            }
            selected
                .or_else(|| self.pop_target_fifo())
                .or_else(|| self.pop_regular_fifo())
        } else {
            self.pop_target_fifo().or_else(|| self.pop_regular_fifo())
        }?;

        if selected.feedback.target_progress {
            self.no_target_progress = 0;
        } else {
            self.no_target_progress += 1;
        }
        Some(selected)
    }

    pub(crate) fn len(&self) -> usize {
        self.target.len() + self.regular.len()
    }

    pub(crate) fn target_len(&self) -> usize {
        self.target.len()
    }

    pub(crate) fn regular_len(&self) -> usize {
        self.regular.len()
    }

    fn should_escape_local_minimum(&self) -> bool {
        self.escape_interval != 0 && self.no_target_progress >= self.escape_interval
    }

    fn pop_target_fifo(&mut self) -> Option<DirectFuzzSeedMeta> {
        self.target.pop_front()
    }

    fn pop_regular_fifo(&mut self) -> Option<DirectFuzzSeedMeta> {
        self.regular.pop_front()
    }

    fn pop_low_energy_regular(&mut self) -> Option<DirectFuzzSeedMeta> {
        let idx = self
            .regular
            .iter()
            .enumerate()
            .min_by(|(_, left), (_, right)| {
                left.feedback
                    .energy
                    .partial_cmp(&right.feedback.energy)
                    .unwrap_or(std::cmp::Ordering::Equal)
            })
            .map(|(idx, _)| idx)?;
        self.regular.remove(idx)
    }
}

#[cfg(test)]
mod tests {
    use super::DirectFuzzQueue;
    use crate::methods::directfuzz::energy::DirectFuzzFeedback;

    fn feedback(target_bits: usize, target_progress: bool, energy: f64) -> DirectFuzzFeedback {
        DirectFuzzFeedback {
            target_covered_bits: target_bits,
            target_progress,
            energy,
            ..DirectFuzzFeedback::default()
        }
    }

    #[test]
    fn target_queue_has_priority_over_regular_queue() {
        let mut queue = DirectFuzzQueue::default();
        queue.push(1, feedback(0, false, 2.0));
        queue.push(2, feedback(1, false, 20.0));
        queue.push(3, feedback(0, false, 1.0));
        assert_eq!(queue.next().unwrap().id, 2);
        assert_eq!(queue.next().unwrap().id, 1);
        assert_eq!(queue.next().unwrap().id, 3);
    }

    #[test]
    fn preserves_fifo_inside_target_priority_queue() {
        let mut queue = DirectFuzzQueue::default();
        queue.push(10, feedback(1, false, 2.0));
        queue.push(11, feedback(3, false, 1.0));
        assert_eq!(queue.next().unwrap().id, 10);
        assert_eq!(queue.next().unwrap().id, 11);
    }

    #[test]
    fn preserves_fifo_inside_regular_queue() {
        let mut queue = DirectFuzzQueue::default();
        queue.push(10, feedback(0, false, 2.0));
        queue.push(11, feedback(0, false, 1.0));
        assert_eq!(queue.next().unwrap().id, 10);
        assert_eq!(queue.next().unwrap().id, 11);
    }

    #[test]
    fn routes_seeds_by_target_coverage() {
        let mut queue = DirectFuzzQueue::default();
        queue.push(1, feedback(0, false, 2.0));
        queue.push(2, feedback(4, false, 20.0));
        assert_eq!(queue.len(), 2);
        assert_eq!(queue.target_len(), 1);
        assert_eq!(queue.regular_len(), 1);
    }

    #[test]
    fn deterministically_escapes_to_low_energy_regular_seed_after_stall() {
        let mut queue = DirectFuzzQueue::new(2);
        queue.push(1, feedback(1, false, 20.0));
        queue.push(2, feedback(1, false, 21.0));
        queue.push(3, feedback(0, false, 7.0));
        queue.push(4, feedback(0, false, 1.0));
        assert_eq!(queue.next().unwrap().id, 1);
        assert_eq!(queue.next().unwrap().id, 2);
        let escaped = queue.next().unwrap();
        assert_eq!(escaped.id, 4);
        assert!(escaped.use_default_energy);
    }

    #[test]
    fn escape_falls_back_to_target_fifo_without_regular_seed() {
        let mut queue = DirectFuzzQueue::new(1);
        queue.push(1, feedback(1, false, 20.0));
        queue.push(2, feedback(1, false, 21.0));
        assert_eq!(queue.next().unwrap().id, 1);

        let selected = queue.next().unwrap();
        assert_eq!(selected.id, 2);
        assert!(!selected.use_default_energy);
    }

    #[test]
    fn disabling_escape_interval_preserves_priority_order() {
        let mut queue = DirectFuzzQueue::new(0);
        queue.push(1, feedback(1, false, 20.0));
        queue.push(2, feedback(1, false, 21.0));
        queue.push(3, feedback(0, false, 1.0));
        assert_eq!(queue.next().unwrap().id, 1);
        assert_eq!(queue.next().unwrap().id, 2);
        assert_eq!(queue.next().unwrap().id, 3);
    }

    #[test]
    fn target_progress_resets_stall_counter() {
        let mut queue = DirectFuzzQueue::new(1);
        queue.push(1, feedback(1, false, 20.0));
        queue.push(2, feedback(1, true, 21.0));
        queue.push(3, feedback(0, false, 1.0));
        assert_eq!(queue.next().unwrap().id, 1);
        assert_eq!(queue.next().unwrap().id, 3);
        assert_eq!(queue.next().unwrap().id, 2);
    }
}
