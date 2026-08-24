#![forbid(unsafe_code)]

//! Experimental, non-shipping Rescue Codex execution boundary.
//!
//! The default feature set deliberately exposes no executable surface. The
//! implementation exists only behind `experimental-codex-exec` and the
//! matching systemd source units are not part of the live image tree.

#[cfg(all(target_os = "linux", feature = "experimental-codex-exec"))]
mod jsonl;
#[cfg(all(target_os = "linux", feature = "experimental-codex-exec"))]
mod linux;
#[cfg(all(target_os = "linux", feature = "experimental-codex-exec"))]
mod wire;

#[cfg(all(target_os = "linux", feature = "experimental-codex-exec"))]
pub use linux::{BridgeError, run_socket_activated_once};
