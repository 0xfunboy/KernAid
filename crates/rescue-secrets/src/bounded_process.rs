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
const MAX_STDOUT_READS_PER_POLL: usize = 64;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum BoundedProcessError {
    Unavailable,
    StartFailed,
    WaitFailed,
    OutputLimitExceeded,
    TimedOut,
    UnexpectedDescendant,
    CleanupFailed,
}

pub(crate) struct CapturedOutput {
    pub(crate) bytes: Vec<u8>,
    pub(crate) status: ExitStatus,
}

pub(crate) fn capture(
    command: &mut Command,
    timeout: Duration,
    maximum_bytes: usize,
) -> Result<CapturedOutput, BoundedProcessError> {
    let capture_limit = maximum_bytes
        .checked_add(1)
        .ok_or(BoundedProcessError::OutputLimitExceeded)?;
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
        for _ in 0..MAX_STDOUT_READS_PER_POLL {
            if Instant::now() >= deadline {
                return Err(cleanup_or(
                    &mut child,
                    process_group,
                    BoundedProcessError::TimedOut,
                ));
            }
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
                    if captured.len() == capture_limit {
                        return Err(cleanup_or(
                            &mut child,
                            process_group,
                            BoundedProcessError::OutputLimitExceeded,
                        ));
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
    cleanup_outcome(terminate_process_group(child, process_group), error)
}

fn cleanup_outcome(cleaned: bool, error: BoundedProcessError) -> BoundedProcessError {
    if cleaned {
        error
    } else {
        BoundedProcessError::CleanupFailed
    }
}

fn terminate_process_group(child: &mut Child, process_group: Pid) -> bool {
    let _ = rustix::process::kill_process_group(process_group, Signal::TERM);
    let term_deadline = Instant::now() + TERMINATION_GRACE;
    if poll_cleanup_until(child, process_group, term_deadline) {
        return true;
    }

    let _ = rustix::process::kill_process_group(process_group, Signal::KILL);
    // A trusted fixed child should remain in its process group, but kill the
    // direct child as well so a group change cannot make ownership ambiguous.
    let _ = child.kill();
    let kill_deadline = Instant::now() + KILL_GRACE;
    poll_cleanup_until(child, process_group, kill_deadline)
}

fn poll_cleanup_until(child: &mut Child, process_group: Pid, deadline: Instant) -> bool {
    loop {
        let child_reaped = match child.try_wait() {
            Ok(Some(_)) => true,
            Ok(None) => false,
            Err(_) => return false,
        };
        let group_absent = match process_group_exists(process_group) {
            Ok(exists) => !exists,
            Err(()) => return false,
        };
        if child_reaped && group_absent {
            return true;
        }
        let Some(remaining) = deadline.checked_duration_since(Instant::now()) else {
            return false;
        };
        if remaining.is_zero() {
            return false;
        }
        thread::sleep(POLL_INTERVAL.min(remaining));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cleanup_ambiguity_is_terminal_and_never_uses_blocking_wait() {
        assert_eq!(
            cleanup_outcome(false, BoundedProcessError::TimedOut),
            BoundedProcessError::CleanupFailed
        );
        let blocking_wait = ["child", ".wait()"].concat();
        assert!(
            !include_str!("bounded_process.rs").contains(&blocking_wait),
            "cleanup must use only deadline-bounded try_wait polling"
        );
    }
}
