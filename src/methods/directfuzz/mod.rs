//! DirectFuzz reproduction building blocks.
//!
//! This module contains the target-instance metadata, energy assignment, and
//! seed scheduling pieces of the DirectFuzz paper algorithm.  It deliberately
//! does not share runner code with other methods.

pub(crate) mod energy;
pub(crate) mod metadata;
pub(crate) mod scheduler;
