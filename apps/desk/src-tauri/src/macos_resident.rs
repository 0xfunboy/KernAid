//! Shared fixed macOS Resident collectors.
//!
//! The command catalog and projection normalizers live in the macOS pack so
//! Desk and the off-default Fleet Resident cannot drift into different native
//! collection surfaces.

pub use kernaid_macos_pack::resident::*;
