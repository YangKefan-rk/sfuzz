/**
 * DirectFuzz: Directed Coverage-Guided Fuzzing for RTL Designs
 *
 * Implements directed graybox fuzzing (DAC '21 DirectFuzz) on top of sfuzz/LibAFL.
 * Key ideas:
 *   1. Map SanCov guards to RTL module instance paths via Verilator function names
 *   2. Compute module hierarchy distance from each guard to a target module
 *   3. Prioritize seeds that cover guards closer to the target module
 *   4. Bias scheduling toward closer seeds
 */
use std::collections::HashMap;
use std::ffi::CString;

use libafl::corpus::{Corpus, CorpusId};
use libafl::prelude::*;
use libafl::schedulers::Scheduler;
use libafl::state::HasCorpus;
use libc::c_char;

use crate::coverage::{cover_as_mut_ptr, cover_len};

unsafe extern "C" {
    pub fn compute_directed_distances(
        target_path: *const c_char,
        out_distances: *mut u16,
        max_count: u32,
    ) -> u32;
    pub fn dump_sancov_info(filename: *const c_char);
}

/// Per-guard distance to target module (u16, lower = closer)
pub struct GuardDistances {
    distances: Vec<u16>,
}

impl GuardDistances {
    pub fn new(target_module: &str) -> Self {
        let n = cover_len();
        let mut distances = vec![u16::MAX; n];
        let target_cstr = CString::new(target_module).expect("invalid target module path");
        let computed = unsafe {
            compute_directed_distances(target_cstr.as_ptr(), distances.as_mut_ptr(), n as u32)
        };
        println!(
            "DirectFuzz: initialized {} guard distances for target '{}'",
            computed, target_module
        );
        // Print distance distribution
        let mut near = 0u32;
        let mut mid = 0u32;
        let mut far = 0u32;
        let mut unmapped = 0u32;
        for &d in &distances {
            if d == u16::MAX {
                unmapped += 1;
            } else if d == 0 {
                near += 1;
            } else if d <= 4 {
                mid += 1;
            } else {
                far += 1;
            }
        }
        println!(
            "DirectFuzz: distance distribution: exact={}, near(1-4)={}, far(>4)={}, unmapped={}",
            near, mid, far, unmapped
        );
        Self { distances }
    }

    /// Compute seed distance: minimum guard distance among covered guards
    pub fn seed_distance(&self, bitmap: &[u8]) -> f64 {
        let mut min_dist = u16::MAX;
        for (i, &covered) in bitmap.iter().enumerate() {
            if covered != 0 && i < self.distances.len() {
                min_dist = min_dist.min(self.distances[i]);
            }
        }
        min_dist as f64
    }
}

/// DirectedScheduler: prioritizes seeds that cover RTL modules closer to the target.
/// Implements the DirectFuzz (DAC '21) seed selection strategy.
pub struct DirectedScheduler {
    guard_distances: GuardDistances,
    seed_distances: HashMap<CorpusId, f64>,
    sorted_seeds: Vec<CorpusId>,
    current_index: usize,
}

impl DirectedScheduler {
    pub fn new(target_module: &str) -> Self {
        let guard_distances = GuardDistances::new(target_module);
        Self {
            guard_distances,
            seed_distances: HashMap::new(),
            sorted_seeds: Vec::new(),
            current_index: 0,
        }
    }

    fn resort(&mut self) {
        self.sorted_seeds.sort_by(|a, b| {
            let da = self.seed_distances.get(a).copied().unwrap_or(f64::MAX);
            let db = self.seed_distances.get(b).copied().unwrap_or(f64::MAX);
            da.partial_cmp(&db).unwrap_or(std::cmp::Ordering::Equal)
        });
        self.current_index = 0;
    }
}

impl<I, S> Scheduler<I, S> for DirectedScheduler
where
    S: HasCorpus<I>,
{
    fn on_add(&mut self, state: &mut S, id: CorpusId) -> Result<(), Error> {
        // Set parent id (same as QueueScheduler)
        let current_id = *state.corpus().current();
        state
            .corpus()
            .get(id)?
            .borrow_mut()
            .set_parent_id_optional(current_id);

        // Compute seed distance from the cumulative coverage bitmap
        let n = cover_len();
        let bitmap_ptr = cover_as_mut_ptr();
        let bitmap = unsafe { std::slice::from_raw_parts(bitmap_ptr, n) };
        let distance = self.guard_distances.seed_distance(bitmap);

        self.seed_distances.insert(id, distance);
        self.sorted_seeds.push(id);
        self.resort();

        println!(
            "DirectFuzz: seed {:?} added, distance={:.1}, corpus_size={}",
            id,
            distance,
            self.sorted_seeds.len()
        );

        Ok(())
    }

    /// Select next seed: DirectFuzz prioritizes closer seeds.
    /// Uses a weighted round-robin: top 1/3 of seeds (closest) get 3x more scheduling.
    fn next(&mut self, state: &mut S) -> Result<CorpusId, Error> {
        if self.sorted_seeds.is_empty() {
            return Err(Error::empty(
                "No entries in corpus. This often implies the target is not properly instrumented."
                    .to_owned(),
            ));
        }

        let n = self.sorted_seeds.len();
        // Weighted selection: top third gets 3x more turns
        let top_third = (n / 3).max(1);
        let effective_len = top_third * 3 + (n - top_third);

        let idx = self.current_index % effective_len;
        let selected_idx = if idx < top_third * 3 {
            // Within the top-third zone: cycle through top-third seeds
            idx % top_third
        } else {
            // Beyond top-third zone: cycle through remaining seeds
            top_third + (idx - top_third * 3)
        };

        let id = self.sorted_seeds[selected_idx.min(n - 1)];

        self.current_index += 1;
        if self.current_index >= effective_len {
            self.current_index = 0;
        }

        <Self as Scheduler<I, S>>::set_current_scheduled(self, state, Some(id))?;
        Ok(id)
    }

    fn set_current_scheduled(
        &mut self,
        state: &mut S,
        next_id: Option<CorpusId>,
    ) -> Result<(), Error> {
        *state.corpus_mut().current_mut() = next_id;
        Ok(())
    }
}

/// Dump SanCov guard info for offline analysis
pub fn dump_sancov_info_to_file(filename: &str) {
    let cstr = CString::new(filename).expect("invalid filename");
    unsafe { dump_sancov_info(cstr.as_ptr()) };
}
