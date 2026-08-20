#![forbid(unsafe_code)]
//! Linux read-only diagnostics and opt-in disposable fixture repair primitives.

pub mod diagnostics;
pub mod snapshot;

#[cfg(feature = "fixture-repair-lab")]
pub mod action_contract;

#[cfg(feature = "fixture-repair-lab")]
mod fixture_repair;

#[cfg(feature = "fixture-repair-lab")]
pub use fixture_repair::*;
