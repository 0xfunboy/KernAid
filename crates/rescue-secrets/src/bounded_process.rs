use rustix::{
    fs::{self as rfs, OFlags},
    process::{Pid, Signal},
};
use std::{
    io::{self, Read},
    os::unix::process::CommandExt,
    process::{Child, Command, ExitStatus},
    thread,
    time::{Duration, Instant},
};

const POLL_INTERVAL: Duration = Duration::from_millis(10);
const TERMINATION_GRACE: Duration = Duration::from_millis(250);
const KILL_GRACE: Duration = Duration::from_secs(1);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum BoundedProcessError {
    Unavailable,
    StartFailed,
    WaitFailed,
    TimedOut,
    UnexpectedDescendant,
    CleanupFailed,
}

pub(crate) struct CapturedOutput {
    pub(crate) bytes: Vec<u8>,
    pub(crate) status: ExitStatus,
    pub(crate) exceeded_limit: bool,
}

pub(crate) fn capture(
    command: &mut Command,
    timeout: Duration,
    maximum_bytes: usize,
) -> Result<CapturedOutput, BoundedProcessError> {
    let capture_limit = maximum_bytes
        .checked_add(1)
        .ok_or(BoundedProcessError::StartFailed)?;
    let (mut child, process_group) = spawn_isolated(command)?;
    let Some(mut stdout) = child.stdout.take() else {
        return Err(cleanup_or(
            &mut child,
            process_group,
            BoundedProcessError::WaitFailed,
        ));
    };
    let descriptor_flags = match rfs::fcntl_getfl(&stdout) {
        Ok(flags) => flags,
        Err(_) => {
            return Err(cleanup_or(
                &mut child,
                process_group,
                BoundedProcessError::WaitFailed,
            ));
        }
    };
    if rfs::fcntl_setfl(&stdout, descriptor_flags | OFlags::NONBLOCK).is_err() {
        return Err(cleanup_or(
            &mut child,
            process_group,
            BoundedProcessError::WaitFailed,
        ));
    }

    let deadline = Instant::now() + timeout;
    let mut captured = Vec::with_capacity(capture_limit);
    let mut status = None;
    let mut stdout_closed = false;
    let mut buffer = [0_u8; 1024];
    loop {
        loop {
            match stdout.read(&mut buffer) {
                Ok(0) => {
                    stdout_closed = true;
                    break;
                }
                Ok(read) => {
                    if captured.len() < capture_limit {
                        let remaining = capture_limit - captured.len();
                        captured.extend_from_slice(&buffer[..read.min(remaining)]);
                    }
                }
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => break,
                Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
                Err(_) => {
                    return Err(cleanup_or(
                        &mut child,
                        process_group,
                        BoundedProcessError::WaitFailed,
                    ));
                }
            }
        }

        if status.is_none() {
            match child.try_wait() {
                Ok(observed) => status = observed,
                Err(_) => {
                    return Err(cleanup_or(
                        &mut child,
                        process_group,
                        BoundedProcessError::WaitFailed,
                    ));
                }
            }
        }
        if let Some(status) = status.filter(|_| stdout_closed) {
            if process_group_exists(process_group) != Ok(false) {
                return Err(cleanup_or(
                    &mut child,
                    process_group,
                    BoundedProcessError::UnexpectedDescendant,
                ));
            }
            return Ok(CapturedOutput {
                exceeded_limit: captured.len() > maximum_bytes,
                bytes: captured,
                status,
            });
        }
        if Instant::now() >= deadline {
            return Err(cleanup_or(
                &mut child,
                process_group,
                BoundedProcessError::TimedOut,
            ));
        }
        thread::sleep(POLL_INTERVAL);
    }
}

#[cfg_attr(not(feature = "experimental-vault-manager"), allow(dead_code))]
pub(crate) fn wait(
    command: &mut Command,
    timeout: Duration,
) -> Result<ExitStatus, BoundedProcessError> {
    let (mut child, process_group) = spawn_isolated(command)?;
    let deadline = Instant::now() + timeout;
    loop {
        match child.try_wait() {
            Ok(Some(status)) => {
                if process_group_exists(process_group) == Ok(false) {
                    return Ok(status);
                }
                return Err(cleanup_or(
                    &mut child,
                    process_group,
                    BoundedProcessError::UnexpectedDescendant,
                ));
            }
            Ok(None) => {}
            Err(_) => {
                return Err(cleanup_or(
                    &mut child,
                    process_group,
                    BoundedProcessError::WaitFailed,
                ));
            }
        }
        if Instant::now() >= deadline {
            return Err(cleanup_or(
                &mut child,
                process_group,
                BoundedProcessError::TimedOut,
            ));
        }
        thread::sleep(POLL_INTERVAL);
    }
}

fn spawn_isolated(command: &mut Command) -> Result<(Child, Pid), BoundedProcessError> {
    command.process_group(0);
    let child = command.spawn().map_err(|error| {
        if matches!(
            error.kind(),
            io::ErrorKind::NotFound | io::ErrorKind::PermissionDenied
        ) {
            BoundedProcessError::Unavailable
        } else {
            BoundedProcessError::StartFailed
        }
    })?;
    let process_group = Pid::from_child(&child);
    Ok((child, process_group))
}

fn process_group_exists(process_group: Pid) -> Result<bool, ()> {
    match rustix::process::test_kill_process_group(process_group) {
        Ok(()) => Ok(true),
        Err(error) if error == rustix::io::Errno::SRCH => Ok(false),
        Err(_) => Err(()),
    }
}

fn cleanup_or(
    child: &mut Child,
    process_group: Pid,
    error: BoundedProcessError,
) -> BoundedProcessError {
    if terminate_process_group(child, process_group) {
        error
    } else {
        BoundedProcessError::CleanupFailed
    }
}

fn terminate_process_group(child: &mut Child, process_group: Pid) -> bool {
    let _ = rustix::process::kill_process_group(process_group, Signal::TERM);
    let term_deadline = Instant::now() + TERMINATION_GRACE;
    while Instant::now() < term_deadline && process_group_exists(process_group) == Ok(true) {
        let _ = child.try_wait();
        thread::sleep(POLL_INTERVAL);
    }
    if process_group_exists(process_group) != Ok(false) {
        let _ = rustix::process::kill_process_group(process_group, Signal::KILL);
        let kill_deadline = Instant::now() + KILL_GRACE;
        while Instant::now() < kill_deadline && process_group_exists(process_group) == Ok(true) {
            let _ = child.try_wait();
            thread::sleep(POLL_INTERVAL);
        }
    }
    let _ = child.wait();
    process_group_exists(process_group) == Ok(false)
}
