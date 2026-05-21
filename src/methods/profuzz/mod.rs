//! PROFUZZ reproduction building blocks.
//!
//! PROFUZZ combines target-site selection, ATPG-guided seed generation, and
//! coverage-threshold feedback over hardware-native simulator coverage.

pub(crate) mod feedback;
pub(crate) mod mutation;
pub(crate) mod pattern;
pub(crate) mod target;
