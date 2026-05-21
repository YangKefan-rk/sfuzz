//! Fuzzing-method reproductions that are independent from the simulator ABI.
//!
//! `rfuzz` and `directfuzz` are separate method reproductions.  Keeping them
//! below this common namespace avoids mixing method-specific logic into the
//! generic LibAFL runner, while each method remains unit-testable without a
//! Verilated LinkNan model.

pub(crate) mod directfuzz;
pub(crate) mod rfuzz;
