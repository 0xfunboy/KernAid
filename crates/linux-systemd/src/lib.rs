#![deny(unsafe_op_in_unsafe_fn)]
//! Minimal safe ownership boundary for one systemd socket-activation FD.
//!
//! Normal KernAid crates forbid unsafe Rust. This leaf owns the sole raw-FD
//! conversion required by systemd's fixed `SD_LISTEN_FDS_START == 3` ABI.

#[cfg(target_os = "linux")]
use std::{
    env,
    os::fd::{FromRawFd, OwnedFd},
    sync::atomic::{AtomicBool, Ordering},
};

#[cfg(target_os = "linux")]
const SD_LISTEN_FDS_START: i32 = 3;

#[cfg(target_os = "linux")]
static ACTIVATION_FD_TAKEN: AtomicBool = AtomicBool::new(false);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ActivationError {
    InvalidEnvironment,
    AlreadyTaken,
    InvalidDescriptor,
}

/// Takes exactly one named activation descriptor from FD 3.
///
/// The process/environment checks implement the ownership preconditions of
/// `sd_listen_fds(3)`. A process can call this successfully at most once.
#[cfg(target_os = "linux")]
pub fn take_single_named_socket(expected_name: &str) -> Result<OwnedFd, ActivationError> {
    let listen_pid_matches = env::var("LISTEN_PID")
        .ok()
        .and_then(|value| value.parse::<u32>().ok())
        == Some(std::process::id());
    if expected_name.is_empty()
        || expected_name.len() > 64
        || !expected_name
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b':' | b'-'))
        || !listen_pid_matches
        || env::var("LISTEN_FDS").ok().as_deref() != Some("1")
        || env::var("LISTEN_FDNAMES").ok().as_deref() != Some(expected_name)
    {
        return Err(ActivationError::InvalidEnvironment);
    }
    ACTIVATION_FD_TAKEN
        .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
        .map_err(|_| ActivationError::AlreadyTaken)?;

    // SAFETY: systemd's validated LISTEN_PID/LISTEN_FDS contract transfers
    // ownership of the sole activation descriptor at fixed FD 3. The atomic
    // guard prevents a second safe owner from being constructed in-process.
    let socket = unsafe { OwnedFd::from_raw_fd(SD_LISTEN_FDS_START) };
    rustix::io::fcntl_setfd(&socket, rustix::io::FdFlags::CLOEXEC)
        .map_err(|_| ActivationError::InvalidDescriptor)?;
    Ok(socket)
}

#[cfg(not(target_os = "linux"))]
pub fn take_single_named_socket(_expected_name: &str) -> Result<(), ActivationError> {
    Err(ActivationError::InvalidEnvironment)
}
