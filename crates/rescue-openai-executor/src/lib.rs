#![forbid(unsafe_code)]

//! One-request, credential-free Rescue OpenAI executor scaffold.
//!
//! The shipping binary can report presence-only OpenAI status through the
//! authenticated Rescue vault. Provider execution and credential borrowing are
//! intentionally absent.

#[cfg(target_os = "linux")]
mod linux;

#[cfg(target_os = "linux")]
pub use linux::{ExecutorError, run_socket_activated_once};
