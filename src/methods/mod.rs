//! Fuzzing-method reproductions that are independent from the simulator ABI.
//!
//! Each child module is a separate method reproduction. Keeping them below this
//! common namespace avoids mixing method-specific logic into the generic LibAFL
//! runner, while each method remains unit-testable without a Verilated LinkNan
//! model.

pub(crate) mod directfuzz;
pub(crate) mod profuzz;
pub(crate) mod rfuzz;
pub(crate) mod surgefuzz;
