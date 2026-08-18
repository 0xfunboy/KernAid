#![forbid(unsafe_code)]

//! One-request Rescue OpenAI executor.
//!
//! The shipping binary reports presence-only status or performs one fixed,
//! leased OpenAI Responses diagnosis over its dedicated local TLS egress
//! boundary. It exposes no configurable destination, model, tool, command, or
//! environment surface.

#[cfg(target_os = "linux")]
mod linux;

#[cfg(target_os = "linux")]
pub use linux::{ExecutorError, run_socket_activated_once};
