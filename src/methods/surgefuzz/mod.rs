//! SurgeFuzz reproduction building blocks.
//!
//! This module keeps annotation scoring, ancestor-register metadata, and
//! surge-aware coverage separate from the simulator-specific driver glue.

pub(crate) mod coverage;
pub(crate) mod metadata;
pub(crate) mod score;
pub(crate) mod selector;
