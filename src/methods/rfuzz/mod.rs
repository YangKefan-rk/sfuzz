//! RFuzz reproduction building blocks.
//!
//! RFuzz treats an RTL test as bytes over top-level input pins across time and
//! uses mux-select toggle coverage as feedback.  This module captures the
//! method-level pieces that can be shared by the current SFuzz harness and by
//! future raw-pin-stream harnesses.

pub(crate) mod coverage;
pub(crate) mod feedback;
pub(crate) mod input;
pub(crate) mod mutators;
