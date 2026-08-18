use rustix::{
    fd::{AsFd, AsRawFd, OwnedFd},
    fs::{self as rfs, OFlags},
    process::{Pid, Signal},
};
use std::{
    fs::File,
    io::{self, Read},
    os::{fd::RawFd, unix::process::CommandExt},
    path::{Path, PathBuf},
    process::{Child, Command, ExitStatus, Stdio},
    sync::Mutex,
    thread,
    time::{Duration, Instant},
};

const POLL_INTERVAL: Duration = Duration::from_millis(10);
const TERMINATION_GRACE: Duration = Duration::from_millis(250);
const KILL_GRACE: Duration = Duration::from_secs(1);
const MAX_STDOUT_READS_PER_POLL: usize = 64;
const CHILD_DESCRIPTOR_MINIMUM: RawFd = 3;
pub(crate) const CHILD_STDIN_PATH: &str = "/proc/self/fd/0";
static SPAWN_LOCK: Mutex<()> = Mutex::new(());

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

/// One descriptor capability made visible only to the next bounded child.
///
/// The parent-side duplicate remains CLOEXEC until `spawn_isolated` holds the
/// bounded-spawn lock. It is then cleared immediately before `spawn` and
/// closed in the parent immediately afterwards. The production worker is
/// single-threaded, and all of its external tools use this bounded spawn path.
/// The child addresses only its own inherited descriptor, so a non-dumpable
/// parent is never reopened via `/proc/<parent>/fd`.
pub(crate) struct InheritedChildDescriptor {
    descriptor: OwnedFd,
    path: PathBuf,
}

impl InheritedChildDescriptor {
    pub(crate) fn duplicate(source: impl AsFd) -> Result<Self, BoundedProcessError> {
        let descriptor = duplicate_cloexec(source)?;
        let number = descriptor.as_raw_fd();
        Ok(Self {
            descriptor,
            path: PathBuf::from(format!("/proc/self/fd/{number}")),
        })
    }

    pub(crate) fn path(&self) -> &Path {
        &self.path
    }
}

pub(crate) fn duplicate_child_stdin(source: impl AsFd) -> Result<Stdio, BoundedProcessError> {
    duplicate_cloexec(source).map(|descriptor| Stdio::from(File::from(descriptor)))
}

fn duplicate_cloexec(source: impl AsFd) -> Result<OwnedFd, BoundedProcessError> {
    let source = source.as_fd();
    let source_flags =
        rustix::io::fcntl_getfd(source).map_err(|_| BoundedProcessError::StartFailed)?;
    if !source_flags.contains(rustix::io::FdFlags::CLOEXEC) {
        return Err(BoundedProcessError::StartFailed);
    }
    let descriptor = rustix::io::fcntl_dupfd_cloexec(source, CHILD_DESCRIPTOR_MINIMUM)
        .map_err(|_| BoundedProcessError::StartFailed)?;
    let number = descriptor.as_raw_fd();
    let duplicate_flags =
        rustix::io::fcntl_getfd(&descriptor).map_err(|_| BoundedProcessError::StartFailed)?;
    if number < CHILD_DESCRIPTOR_MINIMUM || !duplicate_flags.contains(rustix::io::FdFlags::CLOEXEC)
    {
        return Err(BoundedProcessError::StartFailed);
    }
    Ok(descriptor)
}

pub(crate) fn capture(
    command: &mut Command,
    timeout: Duration,
    maximum_bytes: usize,
) -> Result<CapturedOutput, BoundedProcessError> {
    let capture_limit = maximum_bytes
        .checked_add(1)
        .ok_or(BoundedProcessError::OutputLimitExceeded)?;
    let (mut child, process_group) = spawn_isolated(command, None)?;
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
    wait_optional_descriptor(command, timeout, None)
}

pub(crate) fn wait_with_descriptor(
    command: &mut Command,
    timeout: Duration,
    descriptor: InheritedChildDescriptor,
) -> Result<ExitStatus, BoundedProcessError> {
    wait_optional_descriptor(command, timeout, Some(descriptor))
}

fn wait_optional_descriptor(
    command: &mut Command,
    timeout: Duration,
    descriptor: Option<InheritedChildDescriptor>,
) -> Result<ExitStatus, BoundedProcessError> {
    let (mut child, process_group) = spawn_isolated(command, descriptor)?;
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

fn spawn_isolated(
    command: &mut Command,
    descriptor: Option<InheritedChildDescriptor>,
) -> Result<(Child, Pid), BoundedProcessError> {
    let _spawn_guard = SPAWN_LOCK
        .lock()
        .map_err(|_| BoundedProcessError::StartFailed)?;
    if let Some(inherited) = descriptor.as_ref() {
        let flags = rustix::io::fcntl_getfd(&inherited.descriptor)
            .map_err(|_| BoundedProcessError::StartFailed)?;
        if !flags.contains(rustix::io::FdFlags::CLOEXEC) {
            return Err(BoundedProcessError::StartFailed);
        }
        rustix::io::fcntl_setfd(&inherited.descriptor, flags - rustix::io::FdFlags::CLOEXEC)
            .map_err(|_| BoundedProcessError::StartFailed)?;
    }
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
    });
    drop(descriptor);
    let child = child?;
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
    use rustix::process::{DumpableBehavior, set_dumpable_behavior};
    use std::{fs::File, os::unix::fs::MetadataExt, process::Stdio};

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

    #[test]
    fn nondumpable_parent_passes_only_a_child_self_descriptor() {
        const CHILD_FLAG: &str = "KERNAID_BOUNDED_DESCRIPTOR_CHILD";
        const GRANDCHILD_FLAG: &str = "KERNAID_BOUNDED_DESCRIPTOR_GRANDCHILD";
        const FIXED_BYTES: &[u8] = b"descriptor-capability-v1\n";
        if let Some(path) = std::env::var_os(GRANDCHILD_FLAG) {
            let path = PathBuf::from(path);
            assert!(path.to_string_lossy().starts_with("/proc/self/fd/"));
            let expected = std::fs::metadata(&path).expect("stat inherited descriptor");
            let aliases = std::fs::read_dir("/proc/self/fd")
                .expect("scan child descriptors")
                .filter_map(Result::ok)
                .filter_map(|entry| std::fs::metadata(entry.path()).ok())
                .filter(|metadata| {
                    metadata.dev() == expected.dev() && metadata.ino() == expected.ino()
                })
                .count();
            assert_eq!(
                aliases, 1,
                "only the intended child descriptor is inherited"
            );
            let bytes = std::fs::read(path).expect("read inherited descriptor");
            assert_eq!(bytes, FIXED_BYTES);
            return;
        }
        if let Some(path) = std::env::var_os(CHILD_FLAG) {
            set_dumpable_behavior(DumpableBehavior::NotDumpable).expect("set non-dumpable");
            let source = File::open(path).expect("open descriptor fixture");
            let source_flags = rustix::io::fcntl_getfd(&source).expect("source flags");
            rustix::io::fcntl_setfd(&source, source_flags | rustix::io::FdFlags::CLOEXEC)
                .expect("source CLOEXEC");
            let inherited = InheritedChildDescriptor::duplicate(&source).expect("child duplicate");
            assert!(
                inherited
                    .path()
                    .to_string_lossy()
                    .starts_with("/proc/self/fd/")
            );
            let mut command = Command::new(std::env::current_exe().expect("test executable"));
            command
                .arg("--exact")
                .arg(
                    "bounded_process::tests::nondumpable_parent_passes_only_a_child_self_descriptor",
                )
                .arg("--nocapture")
                .env_clear()
                .env(GRANDCHILD_FLAG, inherited.path())
                .stdin(Stdio::null())
                .stdout(Stdio::null())
                .stderr(Stdio::null());
            let status = wait_with_descriptor(&mut command, Duration::from_secs(1), inherited)
                .expect("wait for inherited descriptor child");
            assert!(status.success());
            assert!(
                rustix::io::fcntl_getfd(&source)
                    .expect("source flags after child")
                    .contains(rustix::io::FdFlags::CLOEXEC)
            );

            let child_stdin = duplicate_child_stdin(&source).expect("child stdin duplicate");
            let mut stdin_command = Command::new(std::env::current_exe().expect("test executable"));
            stdin_command
                .arg("--exact")
                .arg(
                    "bounded_process::tests::nondumpable_parent_passes_only_a_child_self_descriptor",
                )
                .arg("--nocapture")
                .env_clear()
                .env(GRANDCHILD_FLAG, CHILD_STDIN_PATH)
                .stdin(child_stdin)
                .stdout(Stdio::null())
                .stderr(Stdio::null());
            let status = wait(&mut stdin_command, Duration::from_secs(1))
                .expect("wait for child stdin descriptor");
            assert!(status.success());
            return;
        }

        let non_cloexec = tempfile::tempfile().expect("non-CLOEXEC fixture");
        let flags = rustix::io::fcntl_getfd(&non_cloexec).expect("non-CLOEXEC flags");
        rustix::io::fcntl_setfd(&non_cloexec, flags - rustix::io::FdFlags::CLOEXEC)
            .expect("clear source CLOEXEC");
        assert_eq!(
            InheritedChildDescriptor::duplicate(&non_cloexec).err(),
            Some(BoundedProcessError::StartFailed),
            "a source that could leak independently is rejected"
        );
        assert!(duplicate_child_stdin(&non_cloexec).is_err());

        let fixture = tempfile::NamedTempFile::new().expect("descriptor fixture");
        std::fs::write(fixture.path(), FIXED_BYTES).expect("write descriptor fixture");
        let status = Command::new(std::env::current_exe().expect("test executable"))
            .arg("--exact")
            .arg("bounded_process::tests::nondumpable_parent_passes_only_a_child_self_descriptor")
            .arg("--nocapture")
            .env(CHILD_FLAG, fixture.path())
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .expect("spawn non-dumpable regression child");
        assert!(status.success());
    }
}
