#![forbid(unsafe_code)]
//! Linux read-only diagnostics and opt-in disposable fixture repair primitives.

pub mod diagnostics;
pub mod hardware;
pub mod snapshot;

#[cfg(feature = "rescue-fstab-production-candidate")]
pub mod production_candidate_contract;

#[cfg(feature = "rescue-fstab-production-candidate")]
pub mod rescue_fstab_candidate;

#[cfg(feature = "fixture-repair-lab")]
pub mod action_contract;

#[cfg(feature = "fixture-repair-lab")]
mod fixture_repair;

#[cfg(feature = "fixture-repair-lab")]
pub use fixture_repair::*;
