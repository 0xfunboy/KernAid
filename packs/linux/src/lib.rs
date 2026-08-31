#![forbid(unsafe_code)]
//! Linux read-only diagnostics and opt-in disposable fixture repair primitives.

pub mod boot_critical_path;
pub mod diagnostics;
pub mod filesystem_health;
pub mod hardware;
pub mod snapshot;
pub mod storage_health;

#[cfg(feature = "rescue-fstab-production-candidate")]
pub mod production_candidate_contract;

#[cfg(feature = "rescue-fstab-production-candidate")]
pub mod rescue_fstab_candidate;

#[cfg(feature = "rescue-fstab-production-candidate")]
pub mod rescue_fstab_transaction_candidate;

#[cfg(feature = "rescue-crypttab-production-candidate")]
pub mod crypttab_candidate_contract;

#[cfg(feature = "rescue-crypttab-production-candidate")]
pub mod rescue_crypttab_candidate;

#[cfg(feature = "fixture-repair-lab")]
pub mod action_contract;

#[cfg(feature = "fixture-repair-lab")]
mod fixture_repair;

#[cfg(feature = "fixture-repair-lab")]
pub use fixture_repair::*;
