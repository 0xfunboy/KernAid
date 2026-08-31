#![forbid(unsafe_code)]
//! Deterministic Windows diagnostic-pack primitives.
//!
//! Phase 0 code in this crate consumes bounded, normalized observations. It
//! cannot execute commands, open host paths, or mutate Windows state.

pub mod diagnostics;
pub mod resident;
