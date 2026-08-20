#![forbid(unsafe_code)]

//! Closed authentication-only bridge for the pinned Codex CLI in Rescue.
//!
//! The bridge deliberately exposes only device login, presence-only status,
//! and logout. It never accepts a prompt, model, command, path, environment,
//! API key, or broker operation, and it never opens or serializes `auth.json`.

#[cfg(target_os = "linux")]
mod linux;

#[cfg(target_os = "linux")]
pub use linux::{BridgeError, run_client, run_socket_activated_once};
