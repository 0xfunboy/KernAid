//! Descriptor-bound daemon runtime, fault marker, cgroup, and worker process.

use super::{RescueVaultDaemonError, internal_wire};
use rustix::{
    event::{PollFd, PollFlags, Timespec, poll},
    fd::OwnedFd,
    fs::{
        self as rfs, AtFlags, CWD, FileType, FlockOperation, Mode, OFlags, ResolveFlags, SeekFrom,
    },
    net::{AddressFamily, SocketFlags, SocketType, socketpair},
    pipe::{PipeFlags, pipe_with},
    process::{Pid, PidfdFlags, Signal, pidfd_open, pidfd_send_signal},
    thread::{
        CapabilitySet, CapabilitySets, capabilities, capability_is_in_ambient_set,
        capability_is_in_bounding_set, clear_ambient_capability_set,
        remove_capability_from_bounding_set, set_capabilities,
    },
};
use std::{
    ffi::{OsStr, OsString},
    fs as stdfs,
    os::{
        fd::{AsFd, BorrowedFd},
        unix::ffi::{OsStrExt, OsStringExt},
    },
    path::{Path, PathBuf},
    process::{Child, Command, Stdio},
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
    },
    time::{Duration, Instant},
};

const RUNTIME_ROOT_NAME: &str = "kernaid-rescue-vault";
const DAEMON_LOCK_NAME: &str = "kernaid-rescue-vaultd.lock";
const FAULT_MARKER_NAME: &str = "lifecycle-active-v1";
const FAULT_MARKER_BYTES: &[u8] = b"KERNAID_RESCUE_VAULT_LIFECYCLE_ARMED_V1\n";
const SUPERVISOR_CGROUP_NAME: &[u8] = b"supervisor";
const WORKER_CGROUP_NAME: &str = "worker";
const PIDS_CONTROLLER_NAME: &[u8] = b"pids";
const CGROUP2_SUPER_MAGIC: u64 = 0x6367_7270;
const PROC_SUPER_MAGIC: u64 = 0x0000_9fa0;
const TMPFS_MAGIC: u64 = 0x0102_1994;
const PIPEFS_MAGIC: u64 = 0x5049_5045;
const SECURE_DIRECTORY_MODE: u32 = 0o700;
const SECURE_FILE_MODE: u32 = 0o600;
const MAX_CGROUP_FILE_BYTES: usize = 4096;
const MAX_CGROUP_COMPONENTS: usize = 64;
const MAX_CGROUP_COMPONENT_BYTES: usize = 128;
const MAX_CGROUP_PROCESSES: usize = 256;
const WORKER_EXIT_GRACE: Duration = Duration::from_secs(2);
const WORKER_BOOTSTRAP_TIMEOUT: Duration = Duration::from_secs(10);
const MAX_PROVIDER_OUTPUT_BYTES: usize =
    kernaid_protocol::rescue_vault::MAX_OPENAI_KEY_BYTES as usize;
const _: () = assert!(MAX_PROVIDER_OUTPUT_BYTES <= rustix::pipe::PIPE_BUF);
const SUPERVISOR_STARTUP_CAPABILITIES: CapabilitySet = CapabilitySet::SYS_ADMIN
    .union(CapabilitySet::KILL)
    .union(CapabilitySet::SETPCAP);
const SUPERVISOR_RUNTIME_CAPABILITIES: CapabilitySet =
    CapabilitySet::SYS_ADMIN.union(CapabilitySet::KILL);
const WORKER_RUNTIME_CAPABILITIES: CapabilitySet = CapabilitySet::SYS_ADMIN;

pub(super) fn narrow_worker_capabilities() -> Result<(), RescueVaultDaemonError> {
    narrow_capabilities(
        SUPERVISOR_STARTUP_CAPABILITIES,
        WORKER_RUNTIME_CAPABILITIES,
        &[CapabilitySet::KILL, CapabilitySet::SETPCAP],
    )
}

pub(super) fn narrow_supervisor_capabilities() -> Result<(), RescueVaultDaemonError> {
    narrow_capabilities(
        SUPERVISOR_STARTUP_CAPABILITIES,
        SUPERVISOR_RUNTIME_CAPABILITIES,
        &[CapabilitySet::SETPCAP],
    )
}

pub(super) fn verify_current_supervisor_capabilities() -> Result<(), RescueVaultDaemonError> {
    verify_exact_capabilities(SUPERVISOR_RUNTIME_CAPABILITIES)
}

pub(super) fn verify_all_supervisor_threads_capabilities() -> Result<(), RescueVaultDaemonError> {
    let expected = format!("{:016x}", SUPERVISOR_RUNTIME_CAPABILITIES.bits());
    let mut observed = 0_usize;
    let tasks = stdfs::read_dir("/proc/self/task")
        .map_err(|_| RescueVaultDaemonError::RuntimeUnavailable)?;
    for task in tasks {
        let task = task.map_err(|_| RescueVaultDaemonError::RuntimeUnavailable)?;
        let name = task.file_name();
        if name.is_empty() || !name.as_encoded_bytes().iter().all(u8::is_ascii_digit) {
            return Err(RescueVaultDaemonError::RuntimeUnavailable);
        }
        let status = stdfs::read(task.path().join("status"))
            .map_err(|_| RescueVaultDaemonError::RuntimeUnavailable)?;
        if !thread_status_capabilities_are_exact(&status, &expected) {
            return Err(RescueVaultDaemonError::RuntimeUnavailable);
        }
        observed = observed
            .checked_add(1)
            .ok_or(RescueVaultDaemonError::RuntimeUnavailable)?;
    }
    if observed < 2 {
        return Err(RescueVaultDaemonError::RuntimeUnavailable);
    }
    Ok(())
}

fn verify_worker_thread_capabilities(pid: Pid) -> Result<(), RescueVaultDaemonError> {
    let expected = format!("{:016x}", WORKER_RUNTIME_CAPABILITIES.bits());
    let task_root = format!("/proc/{}/task", pid.as_raw_pid());
    let mut observed = 0_usize;
    let tasks =
        stdfs::read_dir(task_root).map_err(|_| RescueVaultDaemonError::WorkerUnavailable)?;
    for task in tasks {
        let task = task.map_err(|_| RescueVaultDaemonError::WorkerUnavailable)?;
        let name = task.file_name();
        if name.is_empty() || !name.as_encoded_bytes().iter().all(u8::is_ascii_digit) {
            return Err(RescueVaultDaemonError::WorkerUnavailable);
        }
        let status = stdfs::read(task.path().join("status"))
            .map_err(|_| RescueVaultDaemonError::WorkerUnavailable)?;
        if !thread_status_capabilities_are_exact(&status, &expected) {
            return Err(RescueVaultDaemonError::WorkerUnavailable);
        }
        observed = observed
            .checked_add(1)
            .ok_or(RescueVaultDaemonError::WorkerUnavailable)?;
    }
    if observed != 1 {
        return Err(RescueVaultDaemonError::WorkerUnavailable);
    }
    Ok(())
}

fn thread_status_capabilities_are_exact(status: &[u8], expected: &str) -> bool {
    let mut inheritable = None;
    let mut permitted = None;
    let mut effective = None;
    let mut bounding = None;
    let mut ambient = None;
    for line in status.split(|byte| *byte == b'\n') {
        let mut fields = line
            .split(|byte| byte.is_ascii_whitespace())
            .filter(|field| !field.is_empty());
        let Some(name) = fields.next() else {
            continue;
        };
        let Some(value) = fields.next() else {
            continue;
        };
        if fields.next().is_some() {
            continue;
        }
        let value = std::str::from_utf8(value).ok();
        match name {
            b"CapInh:" => inheritable = value,
            b"CapPrm:" => permitted = value,
            b"CapEff:" => effective = value,
            b"CapBnd:" => bounding = value,
            b"CapAmb:" => ambient = value,
            _ => {}
        }
    }
    inheritable == Some("0000000000000000")
        && permitted == Some(expected)
        && effective == Some(expected)
        && bounding == Some(expected)
        && ambient == Some("0000000000000000")
}

fn narrow_capabilities(
    expected_initial: CapabilitySet,
    expected_final: CapabilitySet,
    bounding_drops: &[CapabilitySet],
) -> Result<(), RescueVaultDaemonError> {
    verify_exact_capabilities(expected_initial)?;
    clear_ambient_capability_set().map_err(|_| RescueVaultDaemonError::RuntimeUnavailable)?;
    for capability in bounding_drops {
        remove_capability_from_bounding_set(*capability)
            .map_err(|_| RescueVaultDaemonError::RuntimeUnavailable)?;
    }
    set_capabilities(
        None,
        CapabilitySets {
            effective: expected_final,
            permitted: expected_final,
            inheritable: CapabilitySet::empty(),
        },
    )
    .map_err(|_| RescueVaultDaemonError::RuntimeUnavailable)?;
    verify_exact_capabilities(expected_final)
}

fn verify_exact_capabilities(expected: CapabilitySet) -> Result<(), RescueVaultDaemonError> {
    let observed = capabilities(None).map_err(|_| RescueVaultDaemonError::RuntimeUnavailable)?;
    if observed.effective != expected
        || observed.permitted != expected
        || !observed.inheritable.is_empty()
    {
        return Err(RescueVaultDaemonError::RuntimeUnavailable);
    }
    for bit in 0..u64::BITS {
        let capability = CapabilitySet::from_bits_retain(1_u64 << bit);
        let should_be_present = expected.intersects(capability);
        match capability_is_in_bounding_set(capability) {
            Ok(present) if present == should_be_present => {}
            Err(error) if error == rustix::io::Errno::INVAL && !should_be_present => {}
            _ => return Err(RescueVaultDaemonError::RuntimeUnavailable),
        }
        match capability_is_in_ambient_set(capability) {
            Ok(false) => {}
            Err(error) if error == rustix::io::Errno::INVAL => {}
            _ => return Err(RescueVaultDaemonError::RuntimeUnavailable),
        }
    }
    Ok(())
}

/// Runtime marker disposition at daemon startup.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum RuntimeDisposition {
    Ready,
    PersistentFault,
}

/// Holds the singleton lock and the systemd-owned runtime directory. Drop
/// deliberately never disarms an active lifecycle marker.
pub(super) struct DaemonRuntime {
    _lock: OwnedFd,
    root: OwnedFd,
    marker_armed: bool,
}

impl DaemonRuntime {
    pub(super) fn open() -> Result<(Self, RuntimeDisposition), RescueVaultDaemonError> {
        if !rustix::process::geteuid().is_root() {
            return Err(RescueVaultDaemonError::PrivilegeRequired);
        }
        let run = open_root_directory(Path::new("/run"), false)?;
        let root = open_runtime_root(&run)?;
        // The singleton lives inside the root-owned 0700 RuntimeDirectory.
        // A public sticky /run/lock still permits UID-1000 precreation DoS.
        let lock = acquire_daemon_lock(&root)?;
        match marker_disposition(&root)? {
            // Any named entry is persistent fault evidence. In particular, a
            // short or malformed marker is a plausible crash after CREATE or
            // write but before file/directory fsync. Startup must remain
            // status-only and must never clear or "repair" that evidence.
            RuntimeDisposition::PersistentFault => Ok((
                Self {
                    _lock: lock,
                    root,
                    marker_armed: true,
                },
                RuntimeDisposition::PersistentFault,
            )),
            RuntimeDisposition::Ready => Ok((
                Self {
                    _lock: lock,
                    root,
                    marker_armed: false,
                },
                RuntimeDisposition::Ready,
            )),
        }
    }

    /// Durably arm the lifecycle boundary immediately before the first
    /// mutating worker command, before a provider lease can materialize a
    /// credential, or when worker isolation becomes ambiguous.
    pub(super) fn arm_lifecycle(&mut self) -> Result<(), RescueVaultDaemonError> {
        match rfs::statat(&self.root, FAULT_MARKER_NAME, AtFlags::SYMLINK_NOFOLLOW) {
            Err(error) if error == rustix::io::Errno::NOENT => {
                create_fault_marker(&self.root)?;
            }
            Ok(_) => {
                verify_and_sync_fault_marker(&self.root)?;
            }
            Err(_) => return Err(RescueVaultDaemonError::RuntimeUnavailable),
        }
        self.marker_armed = true;
        Ok(())
    }

    /// Disarm only after the caller has proved an exact locked/non-mutated
    /// worker state, or a reaped worker and empty delegated cgroup.
    pub(super) fn disarm_after_verified_locked(&mut self) -> Result<(), RescueVaultDaemonError> {
        if !self.marker_armed {
            return match rfs::statat(&self.root, FAULT_MARKER_NAME, AtFlags::SYMLINK_NOFOLLOW) {
                Err(error) if error == rustix::io::Errno::NOENT => Ok(()),
                _ => Err(RescueVaultDaemonError::PersistentFault),
            };
        }
        remove_fault_marker_with_hook(&self.root, 0, 0, |_| Ok(()))?;
        self.marker_armed = false;
        Ok(())
    }

    /// Prove and durably checkpoint that no lifecycle marker exists. This is
    /// used only when no mutating worker command has been dispatched and the
    /// worker/cgroup have been cleanly reaped.
    pub(super) fn sync_and_verify_disarmed(&mut self) -> Result<(), RescueVaultDaemonError> {
        if self.marker_armed {
            return Err(RescueVaultDaemonError::PersistentFault);
        }
        rfs::fsync(&self.root).map_err(|_| RescueVaultDaemonError::RuntimeUnavailable)?;
        match rfs::statat(&self.root, FAULT_MARKER_NAME, AtFlags::SYMLINK_NOFOLLOW) {
            Err(error) if error == rustix::io::Errno::NOENT => Ok(()),
            _ => Err(RescueVaultDaemonError::PersistentFault),
        }
    }
}

fn marker_disposition(root: &OwnedFd) -> Result<RuntimeDisposition, RescueVaultDaemonError> {
    match rfs::statat(root, FAULT_MARKER_NAME, AtFlags::SYMLINK_NOFOLLOW) {
        Ok(_) => Ok(RuntimeDisposition::PersistentFault),
        Err(error) if error == rustix::io::Errno::NOENT => Ok(RuntimeDisposition::Ready),
        Err(_) => Err(RescueVaultDaemonError::RuntimeUnavailable),
    }
}

fn open_root_directory(path: &Path, exact_mode: bool) -> Result<OwnedFd, RescueVaultDaemonError> {
    let descriptor = rfs::openat2(
        CWD,
        path,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
        ResolveFlags::NO_SYMLINKS | ResolveFlags::NO_MAGICLINKS,
    )
    .map_err(|_| RescueVaultDaemonError::RuntimeUnavailable)?;
    validate_root_directory(&descriptor, exact_mode)?;
    Ok(descriptor)
}

fn open_runtime_root(run: &OwnedFd) -> Result<OwnedFd, RescueVaultDaemonError> {
    // RuntimeDirectory is exposed as a dedicated bind mount inside systemd's
    // service mount namespace. Cross exactly that known mount boundary from
    // the already validated /run descriptor, then bind the opened descriptor
    // back to its named entry and to /run's tmpfs. Every lookup below this
    // directory restores beneath_flags(), including NO_XDEV.
    let descriptor = rfs::openat2(
        run,
        RUNTIME_ROOT_NAME,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
        ResolveFlags::BENEATH | ResolveFlags::NO_SYMLINKS | ResolveFlags::NO_MAGICLINKS,
    )
    .map_err(|_| RescueVaultDaemonError::RuntimeUnavailable)?;
    validate_root_directory(&descriptor, true)?;

    let opened = rfs::fstat(&descriptor).map_err(|_| RescueVaultDaemonError::RuntimeUnavailable)?;
    let named = rfs::statat(run, RUNTIME_ROOT_NAME, AtFlags::SYMLINK_NOFOLLOW)
        .map_err(|_| RescueVaultDaemonError::RuntimeUnavailable)?;
    let run_stat = rfs::fstat(run).map_err(|_| RescueVaultDaemonError::RuntimeUnavailable)?;
    let opened_fs =
        rfs::fstatfs(&descriptor).map_err(|_| RescueVaultDaemonError::RuntimeUnavailable)?;
    let run_fs = rfs::fstatfs(run).map_err(|_| RescueVaultDaemonError::RuntimeUnavailable)?;
    if !runtime_root_mount_is_exact(
        opened.st_dev,
        opened.st_ino,
        named.st_dev,
        named.st_ino,
        run_stat.st_dev,
        u64::try_from(opened_fs.f_type).ok(),
        u64::try_from(run_fs.f_type).ok(),
    ) {
        return Err(RescueVaultDaemonError::RuntimeUnavailable);
    }
    Ok(descriptor)
}

fn runtime_root_mount_is_exact(
    opened_device: u64,
    opened_inode: u64,
    named_device: u64,
    named_inode: u64,
    run_device: u64,
    opened_filesystem: Option<u64>,
    run_filesystem: Option<u64>,
) -> bool {
    opened_device == named_device
        && opened_inode == named_inode
        && opened_device == run_device
        && opened_filesystem == Some(TMPFS_MAGIC)
        && run_filesystem == Some(TMPFS_MAGIC)
}

fn acquire_daemon_lock(lock_root: &OwnedFd) -> Result<OwnedFd, RescueVaultDaemonError> {
    let create = OFlags::RDWR | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW | OFlags::CLOEXEC;
    let (descriptor, created) = match rfs::openat2(
        lock_root,
        DAEMON_LOCK_NAME,
        create,
        Mode::RUSR | Mode::WUSR,
        beneath_flags(),
    ) {
        Ok(descriptor) => (descriptor, true),
        Err(error) if error == rustix::io::Errno::EXIST => (
            open_child_file(
                lock_root,
                DAEMON_LOCK_NAME,
                OFlags::RDWR | OFlags::CLOEXEC | OFlags::NOFOLLOW,
            )?,
            false,
        ),
        Err(_) => return Err(RescueVaultDaemonError::RuntimeUnavailable),
    };
    if created {
        rfs::fchmod(&descriptor, Mode::RUSR | Mode::WUSR)
            .map_err(|_| RescueVaultDaemonError::RuntimeUnavailable)?;
    }
    validate_secure_file(&descriptor, lock_root)?;
    rfs::flock(&descriptor, FlockOperation::NonBlockingLockExclusive).map_err(|error| {
        if error == rustix::io::Errno::AGAIN || error == rustix::io::Errno::WOULDBLOCK {
            RescueVaultDaemonError::AlreadyRunning
        } else {
            RescueVaultDaemonError::RuntimeUnavailable
        }
    })?;
    Ok(descriptor)
}

fn create_fault_marker(root: &OwnedFd) -> Result<(), RescueVaultDaemonError> {
    create_fault_marker_with_hook(root, 0, 0, |_| Ok(()))
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum MarkerMutationStep {
    Created,
    Written,
    FileSynced,
    Unlinked,
    DirectorySynced,
}

fn create_fault_marker_with_hook(
    root: &OwnedFd,
    expected_uid: u32,
    expected_gid: u32,
    mut hook: impl FnMut(MarkerMutationStep) -> Result<(), RescueVaultDaemonError>,
) -> Result<(), RescueVaultDaemonError> {
    let marker = rfs::openat2(
        root,
        FAULT_MARKER_NAME,
        OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::RUSR | Mode::WUSR,
        beneath_flags(),
    )
    .map_err(|_| RescueVaultDaemonError::RuntimeUnavailable)?;
    hook(MarkerMutationStep::Created)?;
    rfs::fchmod(&marker, Mode::RUSR | Mode::WUSR)
        .map_err(|_| RescueVaultDaemonError::RuntimeUnavailable)?;
    write_one(&marker, FAULT_MARKER_BYTES)
        .map_err(|_| RescueVaultDaemonError::RuntimeUnavailable)?;
    hook(MarkerMutationStep::Written)?;
    rfs::fsync(&marker).map_err(|_| RescueVaultDaemonError::RuntimeUnavailable)?;
    hook(MarkerMutationStep::FileSynced)?;
    validate_secure_file_owned(&marker, root, expected_uid, expected_gid)?;
    rfs::fsync(root).map_err(|_| RescueVaultDaemonError::RuntimeUnavailable)?;
    hook(MarkerMutationStep::DirectorySynced)
}

fn remove_fault_marker_with_hook(
    root: &OwnedFd,
    expected_uid: u32,
    expected_gid: u32,
    mut hook: impl FnMut(MarkerMutationStep) -> Result<(), RescueVaultDaemonError>,
) -> Result<(), RescueVaultDaemonError> {
    let marker = open_child_file(
        root,
        FAULT_MARKER_NAME,
        OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NOFOLLOW,
    )?;
    validate_secure_file_owned(&marker, root, expected_uid, expected_gid)?;
    let bytes = read_bounded(marker.as_fd(), FAULT_MARKER_BYTES.len() + 1)
        .map_err(|_| RescueVaultDaemonError::ShutdownFailed)?;
    if bytes.as_slice() != FAULT_MARKER_BYTES {
        return Err(RescueVaultDaemonError::ShutdownFailed);
    }
    let opened = rfs::fstat(&marker).map_err(|_| RescueVaultDaemonError::ShutdownFailed)?;
    let named = rfs::statat(root, FAULT_MARKER_NAME, AtFlags::SYMLINK_NOFOLLOW)
        .map_err(|_| RescueVaultDaemonError::ShutdownFailed)?;
    if opened.st_dev != named.st_dev || opened.st_ino != named.st_ino {
        return Err(RescueVaultDaemonError::ShutdownFailed);
    }
    rfs::unlinkat(root, FAULT_MARKER_NAME, AtFlags::empty())
        .map_err(|_| RescueVaultDaemonError::ShutdownFailed)?;
    hook(MarkerMutationStep::Unlinked)?;
    rfs::fsync(root).map_err(|_| RescueVaultDaemonError::ShutdownFailed)?;
    hook(MarkerMutationStep::DirectorySynced)
}

fn verify_and_sync_fault_marker(root: &OwnedFd) -> Result<(), RescueVaultDaemonError> {
    let marker = open_child_file(
        root,
        FAULT_MARKER_NAME,
        OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NOFOLLOW,
    )?;
    validate_secure_file(&marker, root)?;
    let bytes = read_bounded(marker.as_fd(), FAULT_MARKER_BYTES.len() + 1)
        .map_err(|_| RescueVaultDaemonError::PersistentFault)?;
    let opened = rfs::fstat(&marker).map_err(|_| RescueVaultDaemonError::PersistentFault)?;
    let named = rfs::statat(root, FAULT_MARKER_NAME, AtFlags::SYMLINK_NOFOLLOW)
        .map_err(|_| RescueVaultDaemonError::PersistentFault)?;
    if bytes.as_slice() != FAULT_MARKER_BYTES
        || opened.st_dev != named.st_dev
        || opened.st_ino != named.st_ino
    {
        return Err(RescueVaultDaemonError::PersistentFault);
    }
    rfs::fsync(&marker).map_err(|_| RescueVaultDaemonError::RuntimeUnavailable)?;
    rfs::fsync(root).map_err(|_| RescueVaultDaemonError::RuntimeUnavailable)
}

fn open_child_file(
    parent: &OwnedFd,
    name: &str,
    flags: OFlags,
) -> Result<OwnedFd, RescueVaultDaemonError> {
    rfs::openat2(parent, name, flags, Mode::empty(), beneath_flags())
        .map_err(|_| RescueVaultDaemonError::RuntimeUnavailable)
}

fn validate_root_directory(
    descriptor: &OwnedFd,
    exact_mode: bool,
) -> Result<(), RescueVaultDaemonError> {
    let stat = rfs::fstat(descriptor).map_err(|_| RescueVaultDaemonError::RuntimeUnavailable)?;
    let descriptor_flags = rustix::io::fcntl_getfd(descriptor)
        .map_err(|_| RescueVaultDaemonError::RuntimeUnavailable)?;
    if !FileType::from_raw_mode(stat.st_mode).is_dir()
        || stat.st_uid != 0
        || stat.st_gid != 0
        || (exact_mode && stat.st_mode & 0o7777 != SECURE_DIRECTORY_MODE)
        || (!exact_mode && stat.st_mode & 0o022 != 0)
        || !descriptor_flags.contains(rustix::io::FdFlags::CLOEXEC)
    {
        return Err(RescueVaultDaemonError::RuntimeUnavailable);
    }
    Ok(())
}

fn validate_secure_file(
    descriptor: &OwnedFd,
    parent: &OwnedFd,
) -> Result<(), RescueVaultDaemonError> {
    validate_secure_file_owned(descriptor, parent, 0, 0)
}

fn validate_secure_file_owned(
    descriptor: &OwnedFd,
    parent: &OwnedFd,
    expected_uid: u32,
    expected_gid: u32,
) -> Result<(), RescueVaultDaemonError> {
    let stat = rfs::fstat(descriptor).map_err(|_| RescueVaultDaemonError::RuntimeUnavailable)?;
    let parent_stat = rfs::fstat(parent).map_err(|_| RescueVaultDaemonError::RuntimeUnavailable)?;
    let descriptor_flags = rustix::io::fcntl_getfd(descriptor)
        .map_err(|_| RescueVaultDaemonError::RuntimeUnavailable)?;
    if !FileType::from_raw_mode(stat.st_mode).is_file()
        || stat.st_uid != expected_uid
        || stat.st_gid != expected_gid
        || stat.st_nlink != 1
        || stat.st_mode & 0o7777 != SECURE_FILE_MODE
        || stat.st_dev != parent_stat.st_dev
        || !descriptor_flags.contains(rustix::io::FdFlags::CLOEXEC)
    {
        return Err(RescueVaultDaemonError::RuntimeUnavailable);
    }
    Ok(())
}

fn beneath_flags() -> ResolveFlags {
    ResolveFlags::BENEATH
        | ResolveFlags::NO_SYMLINKS
        | ResolveFlags::NO_MAGICLINKS
        | ResolveFlags::NO_XDEV
}

/// A path-free handle to the exact delegated sibling cgroup reserved for the
/// worker.
pub(super) struct WorkerCgroup {
    parent: OwnedFd,
    supervisor: OwnedFd,
    worker: OwnedFd,
    supervisor_device: u64,
    supervisor_inode: u64,
    worker_device: u64,
    worker_inode: u64,
    supervisor_pid: i32,
}

impl WorkerCgroup {
    pub(super) fn prepare() -> Result<Self, RescueVaultDaemonError> {
        let membership = read_self_cgroup()?;
        let components = parse_delegated_membership(&membership)?;
        let root = open_cgroup_root()?;
        let delegated = open_component_path(&root, &components)?;
        validate_cgroup_directory(&delegated, Some(&root))?;
        let supervisor = open_cgroup_child(&delegated, OsStr::from_bytes(SUPERVISOR_CGROUP_NAME))?;
        validate_cgroup_directory(&supervisor, Some(&delegated))?;
        let self_pid = rustix::process::getpid().as_raw_pid();
        ensure_cgroup_domain(&delegated)?;
        ensure_cgroup_domain(&supervisor)?;
        if !read_cgroup_procs(&delegated)?.is_empty()
            || read_cgroup_procs(&supervisor)? != [self_pid]
        {
            return Err(RescueVaultDaemonError::CgroupUnavailable);
        }
        // Delegate=pids makes the controller available to the service, but
        // systemd does not enable it for children of the delegated root. Use
        // the retained parent descriptor to enable and read back the exact
        // controller before creating the sibling worker cgroup. Otherwise a
        // superficially valid worker directory has no pids.current and the
        // recursive population proof cannot be made.
        enable_pids_controller(&delegated)?;
        if !cgroup_tree_is_exact(&delegated, &supervisor, None)? {
            return Err(RescueVaultDaemonError::CgroupUnavailable);
        }

        match rfs::mkdirat(
            &delegated,
            WORKER_CGROUP_NAME,
            Mode::RUSR | Mode::WUSR | Mode::XUSR,
        ) {
            Ok(()) => {}
            Err(error) if error == rustix::io::Errno::EXIST => {
                return Err(RescueVaultDaemonError::CgroupUnavailable);
            }
            Err(_) => return Err(RescueVaultDaemonError::CgroupUnavailable),
        }
        let worker = open_cgroup_child(&delegated, OsStr::new(WORKER_CGROUP_NAME))?;
        validate_cgroup_directory(&worker, Some(&delegated))?;
        ensure_cgroup_domain(&worker)?;
        ensure_cgroup_control_files(&worker)?;
        if !worker_population_is_empty(
            &read_cgroup_procs(&worker)?,
            cgroup_pids_current(&worker)?,
            cgroup_descendant_count(&worker)?,
            cgroup_populated(&worker)?,
        ) || !cgroup_tree_is_exact(&delegated, &supervisor, Some(&worker))?
        {
            return Err(RescueVaultDaemonError::CgroupUnavailable);
        }
        let stat = rfs::fstat(&worker).map_err(|_| RescueVaultDaemonError::CgroupUnavailable)?;
        let supervisor_stat =
            rfs::fstat(&supervisor).map_err(|_| RescueVaultDaemonError::CgroupUnavailable)?;
        Ok(Self {
            parent: delegated,
            supervisor,
            worker,
            supervisor_device: supervisor_stat.st_dev,
            supervisor_inode: supervisor_stat.st_ino,
            worker_device: stat.st_dev,
            worker_inode: stat.st_ino,
            supervisor_pid: self_pid,
        })
    }

    pub(super) fn move_worker(&self, pid: Pid) -> Result<(), RescueVaultDaemonError> {
        self.validate_named_worker()?;
        self.validate_supervisor_topology(Some(pid.as_raw_pid()))?;
        if !worker_population_is_empty(
            &read_cgroup_procs(&self.worker)?,
            cgroup_pids_current(&self.worker)?,
            cgroup_descendant_count(&self.worker)?,
            cgroup_populated(&self.worker)?,
        ) {
            return Err(RescueVaultDaemonError::CgroupUnavailable);
        }
        let procs = open_cgroup_file(&self.worker, "cgroup.procs", OFlags::WRONLY)?;
        let pid_bytes = pid.as_raw_pid().to_string();
        write_one(&procs, pid_bytes.as_bytes())
            .map_err(|_| RescueVaultDaemonError::CgroupUnavailable)?;
        self.verify_exact_worker(pid)
    }

    pub(super) fn verify_exact_worker(&self, pid: Pid) -> Result<(), RescueVaultDaemonError> {
        self.validate_named_worker()?;
        self.validate_supervisor_topology(None)?;
        if !worker_population_is_exact(
            &read_cgroup_procs(&self.worker)?,
            cgroup_pids_current(&self.worker)?,
            cgroup_descendant_count(&self.worker)?,
            cgroup_populated(&self.worker)?,
            pid.as_raw_pid(),
        ) {
            return Err(RescueVaultDaemonError::CgroupUnavailable);
        }
        Ok(())
    }

    pub(super) fn kill_all(&self) -> Result<(), RescueVaultDaemonError> {
        self.validate_named_worker()?;
        let kill = open_cgroup_file(&self.worker, "cgroup.kill", OFlags::WRONLY)?;
        write_one(&kill, b"1").map_err(|_| RescueVaultDaemonError::CgroupUnavailable)
    }

    pub(super) fn wait_empty(&self, deadline: Instant) -> Result<(), RescueVaultDaemonError> {
        loop {
            self.validate_named_worker()?;
            if worker_population_is_empty(
                &read_cgroup_procs(&self.worker)?,
                cgroup_pids_current(&self.worker)?,
                cgroup_descendant_count(&self.worker)?,
                cgroup_populated(&self.worker)?,
            ) {
                return Ok(());
            }
            if Instant::now() >= deadline {
                return Err(RescueVaultDaemonError::ShutdownFailed);
            }
            std::thread::sleep(Duration::from_millis(10));
        }
    }

    pub(super) fn remove_empty(&self, deadline: Instant) -> Result<(), RescueVaultDaemonError> {
        self.wait_empty(deadline)?;
        self.validate_supervisor_topology(None)?;
        self.validate_named_worker()?;
        rfs::unlinkat(&self.parent, WORKER_CGROUP_NAME, AtFlags::REMOVEDIR)
            .map_err(|_| RescueVaultDaemonError::ShutdownFailed)?;
        match rfs::statat(&self.parent, WORKER_CGROUP_NAME, AtFlags::SYMLINK_NOFOLLOW) {
            Err(error) if error == rustix::io::Errno::NOENT => Ok(()),
            _ => Err(RescueVaultDaemonError::ShutdownFailed),
        }
    }

    fn validate_named_worker(&self) -> Result<(), RescueVaultDaemonError> {
        let retained =
            rfs::fstat(&self.worker).map_err(|_| RescueVaultDaemonError::CgroupUnavailable)?;
        let named = rfs::statat(&self.parent, WORKER_CGROUP_NAME, AtFlags::SYMLINK_NOFOLLOW)
            .map_err(|_| RescueVaultDaemonError::CgroupUnavailable)?;
        if retained.st_dev != self.worker_device
            || retained.st_ino != self.worker_inode
            || named.st_dev != self.worker_device
            || named.st_ino != self.worker_inode
        {
            return Err(RescueVaultDaemonError::CgroupUnavailable);
        }
        validate_cgroup_directory(&self.worker, Some(&self.parent))
    }

    fn validate_supervisor_topology(
        &self,
        pending_worker: Option<i32>,
    ) -> Result<(), RescueVaultDaemonError> {
        let retained =
            rfs::fstat(&self.supervisor).map_err(|_| RescueVaultDaemonError::CgroupUnavailable)?;
        let named = rfs::statat(
            &self.parent,
            OsStr::from_bytes(SUPERVISOR_CGROUP_NAME),
            AtFlags::SYMLINK_NOFOLLOW,
        )
        .map_err(|_| RescueVaultDaemonError::CgroupUnavailable)?;
        if retained.st_dev != self.supervisor_device
            || retained.st_ino != self.supervisor_inode
            || named.st_dev != self.supervisor_device
            || named.st_ino != self.supervisor_inode
            || !read_cgroup_procs(&self.parent)?.is_empty()
            || !cgroup_tree_is_exact(&self.parent, &self.supervisor, Some(&self.worker))?
        {
            return Err(RescueVaultDaemonError::CgroupUnavailable);
        }
        let mut expected = vec![self.supervisor_pid];
        if let Some(pid) = pending_worker {
            expected.push(pid);
            expected.sort_unstable();
        }
        if read_cgroup_procs(&self.supervisor)? != expected {
            return Err(RescueVaultDaemonError::CgroupUnavailable);
        }
        ensure_cgroup_domain(&self.parent)?;
        ensure_cgroup_domain(&self.supervisor)
    }
}

fn worker_population_is_empty(
    direct_processes: &[i32],
    current_processes: u64,
    descendants: u64,
    populated: bool,
) -> bool {
    direct_processes.is_empty() && current_processes == 0 && descendants == 0 && !populated
}

fn worker_population_is_exact(
    direct_processes: &[i32],
    current_processes: u64,
    descendants: u64,
    populated: bool,
    worker_pid: i32,
) -> bool {
    direct_processes == [worker_pid] && current_processes == 1 && descendants == 0 && populated
}

fn cgroup_tree_is_exact(
    parent: &OwnedFd,
    supervisor: &OwnedFd,
    worker: Option<&OwnedFd>,
) -> Result<bool, RescueVaultDaemonError> {
    let worker_descendants = worker.map(cgroup_descendant_count).transpose()?;
    Ok(cgroup_tree_metrics_are_exact(
        cgroup_descendant_count(parent)?,
        cgroup_descendant_count(supervisor)?,
        worker_descendants,
        cgroup_pids_current(supervisor)?,
    ))
}

fn cgroup_tree_metrics_are_exact(
    parent_descendants: u64,
    supervisor_descendants: u64,
    worker_descendants: Option<u64>,
    supervisor_tasks: u64,
) -> bool {
    let expected_descendants = if worker_descendants.is_some() { 2 } else { 1 };
    parent_descendants == expected_descendants
        && supervisor_descendants == 0
        && worker_descendants.is_none_or(|count| count == 0)
        && supervisor_tasks > 0
}

fn read_self_cgroup() -> Result<Vec<u8>, RescueVaultDaemonError> {
    let proc = rfs::openat2(
        CWD,
        "/proc",
        OFlags::PATH | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
        ResolveFlags::NO_SYMLINKS | ResolveFlags::NO_MAGICLINKS,
    )
    .map_err(|_| RescueVaultDaemonError::CgroupUnavailable)?;
    let filesystem = rfs::fstatfs(&proc).map_err(|_| RescueVaultDaemonError::CgroupUnavailable)?;
    if u64::try_from(filesystem.f_type).ok() != Some(PROC_SUPER_MAGIC) {
        return Err(RescueVaultDaemonError::CgroupUnavailable);
    }
    let relative = format!("{}/cgroup", rustix::process::getpid().as_raw_pid());
    let cgroup = rfs::openat2(
        &proc,
        relative,
        OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
        beneath_flags(),
    )
    .map_err(|_| RescueVaultDaemonError::CgroupUnavailable)?;
    read_bounded(cgroup.as_fd(), MAX_CGROUP_FILE_BYTES)
        .map_err(|_| RescueVaultDaemonError::CgroupUnavailable)
}

fn parse_delegated_membership(bytes: &[u8]) -> Result<Vec<OsString>, RescueVaultDaemonError> {
    if bytes.is_empty() || bytes.len() > MAX_CGROUP_FILE_BYTES || !bytes.ends_with(b"\n") {
        return Err(RescueVaultDaemonError::CgroupUnavailable);
    }
    let lines = bytes[..bytes.len() - 1].split(|byte| *byte == b'\n');
    let mut only = None;
    for line in lines {
        if line.is_empty() || only.is_some() || !line.starts_with(b"0::/") {
            return Err(RescueVaultDaemonError::CgroupUnavailable);
        }
        only = Some(&line[4..]);
    }
    let path = only.ok_or(RescueVaultDaemonError::CgroupUnavailable)?;
    let raw = path.split(|byte| *byte == b'/').collect::<Vec<_>>();
    if raw.len() < 2
        || raw.len() > MAX_CGROUP_COMPONENTS
        || raw.last().copied() != Some(SUPERVISOR_CGROUP_NAME)
    {
        return Err(RescueVaultDaemonError::CgroupUnavailable);
    }
    let mut components = Vec::with_capacity(raw.len() - 1);
    for component in &raw[..raw.len() - 1] {
        if component.is_empty()
            || component.len() > MAX_CGROUP_COMPONENT_BYTES
            || *component == b"."
            || *component == b".."
            || component.iter().any(|byte| *byte == 0 || *byte == b'/')
        {
            return Err(RescueVaultDaemonError::CgroupUnavailable);
        }
        components.push(OsString::from_vec(component.to_vec()));
    }
    Ok(components)
}

/// Worker-side half of the placement handshake. The parent verifies the exact
/// PID set through its retained cgroup descriptor; the worker independently
/// proves that its unified membership ends in the fixed sibling `worker`
/// before it receives any command.
pub(super) fn verify_current_worker_cgroup() -> Result<(), RescueVaultDaemonError> {
    let bytes = read_self_cgroup()?;
    parse_worker_membership(&bytes)
}

fn parse_worker_membership(bytes: &[u8]) -> Result<(), RescueVaultDaemonError> {
    if bytes.is_empty() || bytes.len() > MAX_CGROUP_FILE_BYTES || !bytes.ends_with(b"\n") {
        return Err(RescueVaultDaemonError::CgroupUnavailable);
    }
    let mut lines = bytes
        .split(|byte| *byte == b'\n')
        .filter(|line| !line.is_empty());
    let line = lines
        .next()
        .ok_or(RescueVaultDaemonError::CgroupUnavailable)?;
    if lines.next().is_some() || !line.starts_with(b"0::/") {
        return Err(RescueVaultDaemonError::CgroupUnavailable);
    }
    let components: Vec<&[u8]> = line[4..].split(|byte| *byte == b'/').collect();
    if components.is_empty()
        || components.len() > MAX_CGROUP_COMPONENTS
        || components.last().copied() != Some(WORKER_CGROUP_NAME.as_bytes())
        || components.iter().any(|component| {
            component.is_empty()
                || component.len() > MAX_CGROUP_COMPONENT_BYTES
                || *component == b"."
                || *component == b".."
                || component.contains(&0)
        })
    {
        return Err(RescueVaultDaemonError::CgroupUnavailable);
    }
    Ok(())
}

fn open_cgroup_root() -> Result<OwnedFd, RescueVaultDaemonError> {
    let descriptor = rfs::openat2(
        CWD,
        "/sys/fs/cgroup",
        OFlags::PATH | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
        ResolveFlags::NO_SYMLINKS | ResolveFlags::NO_MAGICLINKS,
    )
    .map_err(|_| RescueVaultDaemonError::CgroupUnavailable)?;
    let filesystem =
        rfs::fstatfs(&descriptor).map_err(|_| RescueVaultDaemonError::CgroupUnavailable)?;
    if u64::try_from(filesystem.f_type).ok() != Some(CGROUP2_SUPER_MAGIC) {
        return Err(RescueVaultDaemonError::CgroupUnavailable);
    }
    validate_cgroup_directory(&descriptor, None)?;
    Ok(descriptor)
}

fn open_component_path(
    root: &OwnedFd,
    components: &[OsString],
) -> Result<OwnedFd, RescueVaultDaemonError> {
    let mut path = PathBuf::new();
    for component in components {
        path.push(component);
    }
    rfs::openat2(
        root,
        path,
        OFlags::PATH | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
        beneath_flags(),
    )
    .map_err(|_| RescueVaultDaemonError::CgroupUnavailable)
}

fn open_cgroup_child(parent: &OwnedFd, name: &OsStr) -> Result<OwnedFd, RescueVaultDaemonError> {
    rfs::openat2(
        parent,
        name,
        OFlags::PATH | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
        beneath_flags(),
    )
    .map_err(|_| RescueVaultDaemonError::CgroupUnavailable)
}

fn validate_cgroup_directory(
    descriptor: &OwnedFd,
    parent: Option<&OwnedFd>,
) -> Result<(), RescueVaultDaemonError> {
    let stat = rfs::fstat(descriptor).map_err(|_| RescueVaultDaemonError::CgroupUnavailable)?;
    let filesystem =
        rfs::fstatfs(descriptor).map_err(|_| RescueVaultDaemonError::CgroupUnavailable)?;
    let descriptor_flags = rustix::io::fcntl_getfd(descriptor)
        .map_err(|_| RescueVaultDaemonError::CgroupUnavailable)?;
    if !FileType::from_raw_mode(stat.st_mode).is_dir()
        || stat.st_uid != 0
        || stat.st_gid != 0
        || u64::try_from(filesystem.f_type).ok() != Some(CGROUP2_SUPER_MAGIC)
        || !descriptor_flags.contains(rustix::io::FdFlags::CLOEXEC)
        || parent.is_some_and(|parent| {
            rfs::fstat(parent)
                .map(|parent| parent.st_dev != stat.st_dev)
                .unwrap_or(true)
        })
    {
        return Err(RescueVaultDaemonError::CgroupUnavailable);
    }
    Ok(())
}

fn ensure_cgroup_control_files(worker: &OwnedFd) -> Result<(), RescueVaultDaemonError> {
    let _events = open_cgroup_file(worker, "cgroup.events", OFlags::RDONLY)?;
    let _procs = open_cgroup_file(worker, "cgroup.procs", OFlags::RDONLY)?;
    let _kill = open_cgroup_file(worker, "cgroup.kill", OFlags::WRONLY)?;
    let _pids = open_cgroup_file(worker, "pids.current", OFlags::RDONLY)?;
    let _stat = open_cgroup_file(worker, "cgroup.stat", OFlags::RDONLY)?;
    Ok(())
}

fn ensure_cgroup_domain(directory: &OwnedFd) -> Result<(), RescueVaultDaemonError> {
    let descriptor = open_cgroup_file(directory, "cgroup.type", OFlags::RDONLY)?;
    let bytes = read_bounded(descriptor.as_fd(), 32)
        .map_err(|_| RescueVaultDaemonError::CgroupUnavailable)?;
    if bytes != b"domain\n" {
        return Err(RescueVaultDaemonError::CgroupUnavailable);
    }
    Ok(())
}

fn enable_pids_controller(directory: &OwnedFd) -> Result<(), RescueVaultDaemonError> {
    let available = open_cgroup_file(directory, "cgroup.controllers", OFlags::RDONLY)?;
    let available = read_bounded(available.as_fd(), MAX_CGROUP_FILE_BYTES)
        .map_err(|_| RescueVaultDaemonError::CgroupUnavailable)?;
    let subtree = open_cgroup_file(directory, "cgroup.subtree_control", OFlags::RDWR)?;
    let enabled = read_bounded(subtree.as_fd(), MAX_CGROUP_FILE_BYTES)
        .map_err(|_| RescueVaultDaemonError::CgroupUnavailable)?;
    if pids_controller_activation_required(&available, &enabled)? {
        rfs::seek(&subtree, SeekFrom::Start(0))
            .map_err(|_| RescueVaultDaemonError::CgroupUnavailable)?;
        write_one(&subtree, b"+pids\n").map_err(|_| RescueVaultDaemonError::CgroupUnavailable)?;
    }
    rfs::seek(&subtree, SeekFrom::Start(0))
        .map_err(|_| RescueVaultDaemonError::CgroupUnavailable)?;
    let verified = read_bounded(subtree.as_fd(), MAX_CGROUP_FILE_BYTES)
        .map_err(|_| RescueVaultDaemonError::CgroupUnavailable)?;
    if !pids_controller_is_listed(&verified)? {
        return Err(RescueVaultDaemonError::CgroupUnavailable);
    }
    Ok(())
}

fn pids_controller_activation_required(
    available: &[u8],
    enabled: &[u8],
) -> Result<bool, RescueVaultDaemonError> {
    if !pids_controller_is_listed(available)? {
        return Err(RescueVaultDaemonError::CgroupUnavailable);
    }
    Ok(!pids_controller_is_listed(enabled)?)
}

fn pids_controller_is_listed(bytes: &[u8]) -> Result<bool, RescueVaultDaemonError> {
    if bytes.len() > MAX_CGROUP_FILE_BYTES {
        return Err(RescueVaultDaemonError::CgroupUnavailable);
    }
    if bytes.is_empty() {
        return Ok(false);
    }
    if !bytes.ends_with(b"\n") || bytes[..bytes.len() - 1].contains(&b'\n') {
        return Err(RescueVaultDaemonError::CgroupUnavailable);
    }
    let mut controllers: Vec<&[u8]> = Vec::new();
    for controller in bytes[..bytes.len() - 1].split(|byte| *byte == b' ') {
        if controller.is_empty()
            || controller.len() > 64
            || !controller
                .iter()
                .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || *byte == b'_')
            || controllers.contains(&controller)
        {
            return Err(RescueVaultDaemonError::CgroupUnavailable);
        }
        controllers.push(controller);
    }
    Ok(controllers.contains(&PIDS_CONTROLLER_NAME))
}

fn open_cgroup_file(
    directory: &OwnedFd,
    name: &str,
    access: OFlags,
) -> Result<OwnedFd, RescueVaultDaemonError> {
    let descriptor = rfs::openat2(
        directory,
        name,
        access | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
        beneath_flags(),
    )
    .map_err(|_| RescueVaultDaemonError::CgroupUnavailable)?;
    let stat = rfs::fstat(&descriptor).map_err(|_| RescueVaultDaemonError::CgroupUnavailable)?;
    let parent = rfs::fstat(directory).map_err(|_| RescueVaultDaemonError::CgroupUnavailable)?;
    if !FileType::from_raw_mode(stat.st_mode).is_file()
        || stat.st_uid != 0
        || stat.st_gid != 0
        || stat.st_dev != parent.st_dev
    {
        return Err(RescueVaultDaemonError::CgroupUnavailable);
    }
    Ok(descriptor)
}

fn read_cgroup_procs(directory: &OwnedFd) -> Result<Vec<i32>, RescueVaultDaemonError> {
    let descriptor = open_cgroup_file(directory, "cgroup.procs", OFlags::RDONLY)?;
    let bytes = read_bounded(descriptor.as_fd(), MAX_CGROUP_FILE_BYTES)
        .map_err(|_| RescueVaultDaemonError::CgroupUnavailable)?;
    if bytes.is_empty() {
        return Ok(Vec::new());
    }
    if !bytes.ends_with(b"\n") {
        return Err(RescueVaultDaemonError::CgroupUnavailable);
    }
    let mut pids = Vec::new();
    for line in bytes[..bytes.len() - 1].split(|byte| *byte == b'\n') {
        if line.is_empty()
            || line.len() > 10
            || !line.iter().all(u8::is_ascii_digit)
            || (line.len() > 1 && line[0] == b'0')
        {
            return Err(RescueVaultDaemonError::CgroupUnavailable);
        }
        let value = std::str::from_utf8(line)
            .ok()
            .and_then(|value| value.parse::<i32>().ok())
            .filter(|value| *value > 0)
            .ok_or(RescueVaultDaemonError::CgroupUnavailable)?;
        if pids.contains(&value) || pids.len() >= MAX_CGROUP_PROCESSES {
            return Err(RescueVaultDaemonError::CgroupUnavailable);
        }
        pids.push(value);
    }
    pids.sort_unstable();
    Ok(pids)
}

fn cgroup_populated(directory: &OwnedFd) -> Result<bool, RescueVaultDaemonError> {
    let descriptor = open_cgroup_file(directory, "cgroup.events", OFlags::RDONLY)?;
    let bytes = read_bounded(descriptor.as_fd(), MAX_CGROUP_FILE_BYTES)
        .map_err(|_| RescueVaultDaemonError::CgroupUnavailable)?;
    let mut populated = None;
    for line in bytes
        .split(|byte| *byte == b'\n')
        .filter(|line| !line.is_empty())
    {
        let mut fields = line.split(|byte| *byte == b' ');
        let key = fields.next().unwrap_or_default();
        let value = fields.next().unwrap_or_default();
        if fields.next().is_some() || value.len() != 1 {
            return Err(RescueVaultDaemonError::CgroupUnavailable);
        }
        if key == b"populated" {
            if populated.is_some() || !matches!(value, b"0" | b"1") {
                return Err(RescueVaultDaemonError::CgroupUnavailable);
            }
            populated = Some(value == b"1");
        }
    }
    populated.ok_or(RescueVaultDaemonError::CgroupUnavailable)
}

fn cgroup_pids_current(directory: &OwnedFd) -> Result<u64, RescueVaultDaemonError> {
    let descriptor = open_cgroup_file(directory, "pids.current", OFlags::RDONLY)?;
    let bytes = read_bounded(descriptor.as_fd(), 32)
        .map_err(|_| RescueVaultDaemonError::CgroupUnavailable)?;
    parse_single_cgroup_number(&bytes)
}

fn cgroup_descendant_count(directory: &OwnedFd) -> Result<u64, RescueVaultDaemonError> {
    let descriptor = open_cgroup_file(directory, "cgroup.stat", OFlags::RDONLY)?;
    let bytes = read_bounded(descriptor.as_fd(), MAX_CGROUP_FILE_BYTES)
        .map_err(|_| RescueVaultDaemonError::CgroupUnavailable)?;
    if bytes.is_empty() || !bytes.ends_with(b"\n") {
        return Err(RescueVaultDaemonError::CgroupUnavailable);
    }
    let mut descendants = None;
    let mut keys: Vec<&[u8]> = Vec::new();
    for line in bytes[..bytes.len() - 1].split(|byte| *byte == b'\n') {
        let mut fields = line.split(|byte| *byte == b' ');
        let key = fields.next().unwrap_or_default();
        let value = fields.next().unwrap_or_default();
        if key.is_empty()
            || key.len() > 64
            || !key
                .iter()
                .all(|byte| byte.is_ascii_lowercase() || *byte == b'_')
            || fields.next().is_some()
            || keys.contains(&key)
        {
            return Err(RescueVaultDaemonError::CgroupUnavailable);
        }
        keys.push(key);
        let number = parse_decimal(value)?;
        if key == b"nr_descendants" {
            descendants = Some(number);
        }
    }
    descendants.ok_or(RescueVaultDaemonError::CgroupUnavailable)
}

fn parse_single_cgroup_number(bytes: &[u8]) -> Result<u64, RescueVaultDaemonError> {
    if bytes.is_empty() || !bytes.ends_with(b"\n") || bytes[..bytes.len() - 1].contains(&b'\n') {
        return Err(RescueVaultDaemonError::CgroupUnavailable);
    }
    parse_decimal(&bytes[..bytes.len() - 1])
}

fn parse_decimal(bytes: &[u8]) -> Result<u64, RescueVaultDaemonError> {
    if bytes.is_empty()
        || bytes.len() > 20
        || !bytes.iter().all(u8::is_ascii_digit)
        || (bytes.len() > 1 && bytes[0] == b'0')
    {
        return Err(RescueVaultDaemonError::CgroupUnavailable);
    }
    std::str::from_utf8(bytes)
        .ok()
        .and_then(|value| value.parse::<u64>().ok())
        .ok_or(RescueVaultDaemonError::CgroupUnavailable)
}

/// Long-lived child and its race-free kernel/cgroup ownership handles.
pub(super) struct WorkerHandle {
    channel: Mutex<WorkerChannel>,
    child: Mutex<Option<Child>>,
    pidfd: OwnedFd,
    pid: Pid,
    cgroup: WorkerCgroup,
    terminal: AtomicBool,
}

pub(super) enum WorkerSpawnResult {
    Ready(Arc<WorkerHandle>),
    CancelledClean,
}

struct WorkerChannel {
    socket: OwnedFd,
    next_request_id: u64,
}

impl WorkerHandle {
    pub(super) fn spawn(
        cgroup: WorkerCgroup,
        startup_deadline: Instant,
        cancellation: &AtomicBool,
    ) -> Result<WorkerSpawnResult, RescueVaultDaemonError> {
        let (parent_socket, child_socket) = socketpair(
            AddressFamily::UNIX,
            SocketType::SEQPACKET,
            SocketFlags::CLOEXEC,
            None,
        )
        .map_err(|_| RescueVaultDaemonError::WorkerUnavailable)?;
        let mut command = Command::new("/proc/self/exe");
        command
            .arg("--internal-worker")
            .env_clear()
            .current_dir("/")
            .stdin(Stdio::from(child_socket))
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        let mut child = command
            .spawn()
            .map_err(|_| RescueVaultDaemonError::WorkerUnavailable)?;
        let pid = Pid::from_child(&child);
        let pidfd = match pidfd_open(pid, PidfdFlags::NONBLOCK) {
            Ok(pidfd) => pidfd,
            Err(_) => {
                let _ = child.kill();
                let _ = bounded_child_reap(&mut child, cleanup_deadline(startup_deadline));
                return Err(RescueVaultDaemonError::WorkerUnavailable);
            }
        };
        let descriptor_flags = match rustix::io::fcntl_getfd(&pidfd) {
            Ok(flags) => flags,
            Err(_) => {
                cleanup_spawn_failure(&mut child, &pidfd, &cgroup, startup_deadline);
                return Err(RescueVaultDaemonError::WorkerUnavailable);
            }
        };
        if !descriptor_flags.contains(rustix::io::FdFlags::CLOEXEC) {
            cleanup_spawn_failure(&mut child, &pidfd, &cgroup, startup_deadline);
            return Err(RescueVaultDaemonError::WorkerUnavailable);
        }
        if cgroup.move_worker(pid).is_err() {
            cleanup_spawn_failure(&mut child, &pidfd, &cgroup, startup_deadline);
            return Err(RescueVaultDaemonError::CgroupUnavailable);
        }
        if internal_wire::validate_control_socket(parent_socket.as_fd()).is_err() {
            cleanup_spawn_failure(&mut child, &pidfd, &cgroup, startup_deadline);
            return Err(RescueVaultDaemonError::WorkerUnavailable);
        }
        let bootstrap_deadline = Instant::now()
            .checked_add(WORKER_BOOTSTRAP_TIMEOUT)
            .unwrap_or(startup_deadline)
            .min(startup_deadline);
        if cancellation.load(Ordering::Acquire) {
            return cancelled_spawn_result(&mut child, &pidfd, &cgroup, startup_deadline);
        }
        if internal_wire::send_command(
            parent_socket.as_fd(),
            internal_wire::WorkerCommand::bootstrap(1),
            None,
            bootstrap_deadline,
        )
        .is_err()
        {
            cleanup_spawn_failure(&mut child, &pidfd, &cgroup, startup_deadline);
            return Err(RescueVaultDaemonError::WorkerUnavailable);
        }
        let bootstrap = loop {
            if cancellation.load(Ordering::Acquire) {
                return cancelled_spawn_result(&mut child, &pidfd, &cgroup, startup_deadline);
            }
            let slice = Instant::now()
                .checked_add(Duration::from_millis(200))
                .unwrap_or(bootstrap_deadline)
                .min(bootstrap_deadline);
            match internal_wire::receive_response(parent_socket.as_fd(), 1, slice) {
                Ok(response) => break response,
                Err(internal_wire::InternalWireError::TimedOut) if slice < bootstrap_deadline => {}
                Err(_) => {
                    cleanup_spawn_failure(&mut child, &pidfd, &cgroup, startup_deadline);
                    return Err(RescueVaultDaemonError::WorkerUnavailable);
                }
            }
        };
        if bootstrap.code != internal_wire::WorkerResultCode::BootstrapReady
            || bootstrap.device_id.is_some()
            || bootstrap.output_size.is_some()
            || cgroup.verify_exact_worker(pid).is_err()
            || verify_worker_thread_capabilities(pid).is_err()
            || pidfd_ready(pidfd.as_fd()).unwrap_or(true)
        {
            cleanup_spawn_failure(&mut child, &pidfd, &cgroup, startup_deadline);
            return Err(RescueVaultDaemonError::WorkerUnavailable);
        }
        if cancellation.load(Ordering::Acquire) {
            return cancelled_spawn_result(&mut child, &pidfd, &cgroup, startup_deadline);
        }
        Ok(WorkerSpawnResult::Ready(Arc::new(Self {
            channel: Mutex::new(WorkerChannel {
                socket: parent_socket,
                next_request_id: 2,
            }),
            child: Mutex::new(Some(child)),
            pidfd,
            pid,
            cgroup,
            terminal: AtomicBool::new(false),
        })))
    }

    pub(super) fn transact(
        &self,
        kind: internal_wire::WorkerCommandKind,
        secret_size: Option<u16>,
        descriptor: Option<OwnedFd>,
        deadline: Instant,
    ) -> Result<(internal_wire::WorkerResponse, Option<OwnedFd>), RescueVaultDaemonError> {
        self.transact_cancellable(kind, secret_size, descriptor, deadline, None)
    }

    pub(super) fn transact_cancellable(
        &self,
        kind: internal_wire::WorkerCommandKind,
        secret_size: Option<u16>,
        descriptor: Option<OwnedFd>,
        deadline: Instant,
        cancellation: Option<&AtomicBool>,
    ) -> Result<(internal_wire::WorkerResponse, Option<OwnedFd>), RescueVaultDaemonError> {
        if kind == internal_wire::WorkerCommandKind::ProviderOpenAiBorrow {
            return Err(RescueVaultDaemonError::ProtocolFailure);
        }
        self.transact_inner(kind, secret_size, descriptor, deadline, cancellation, None)
    }

    /// Creates the one-shot worker-to-Agent credential pipe for one registered
    /// supervisor lease. This transaction is intentionally non-cancellable.
    pub(super) fn borrow_openai(
        &self,
        deadline: Instant,
    ) -> Result<(internal_wire::WorkerResponse, Option<OwnedFd>), RescueVaultDaemonError> {
        let (read, write) = create_provider_output_pipe()?;
        self.transact_inner(
            internal_wire::WorkerCommandKind::ProviderOpenAiBorrow,
            None,
            Some(write),
            deadline,
            None,
            Some(read),
        )
    }

    fn transact_inner(
        &self,
        kind: internal_wire::WorkerCommandKind,
        secret_size: Option<u16>,
        descriptor: Option<OwnedFd>,
        deadline: Instant,
        cancellation: Option<&AtomicBool>,
        provider_output: Option<OwnedFd>,
    ) -> Result<(internal_wire::WorkerResponse, Option<OwnedFd>), RescueVaultDaemonError> {
        let borrowing = kind == internal_wire::WorkerCommandKind::ProviderOpenAiBorrow;
        if borrowing != provider_output.is_some() || (borrowing && cancellation.is_some()) {
            return Err(RescueVaultDaemonError::ProtocolFailure);
        }
        if self.terminal.load(Ordering::Acquire) {
            return Err(RescueVaultDaemonError::WorkerUnavailable);
        }
        let mut channel = self
            .channel
            .lock()
            .map_err(|_| RescueVaultDaemonError::WorkerUnavailable)?;
        if self.terminal.load(Ordering::Acquire) {
            return Err(RescueVaultDaemonError::WorkerUnavailable);
        }
        self.cgroup.verify_exact_worker(self.pid)?;
        verify_worker_thread_capabilities(self.pid)?;
        if pidfd_ready(self.pidfd.as_fd())? {
            return Err(RescueVaultDaemonError::WorkerUnavailable);
        }
        let request_id = channel.next_request_id;
        channel.next_request_id = request_id
            .checked_add(1)
            .filter(|next| *next != 0)
            .ok_or(RescueVaultDaemonError::WorkerUnavailable)?;
        let (command, outgoing) = match (kind, secret_size, descriptor) {
            (internal_wire::WorkerCommandKind::Bootstrap, _, _) => {
                return Err(RescueVaultDaemonError::ProtocolFailure);
            }
            (internal_wire::WorkerCommandKind::Probe, None, None) => {
                (internal_wire::WorkerCommand::probe(request_id), None)
            }
            (internal_wire::WorkerCommandKind::Unlock, Some(size), Some(descriptor)) => (
                internal_wire::WorkerCommand::unlock(request_id, size),
                Some(descriptor),
            ),
            (internal_wire::WorkerCommandKind::Lock, None, None) => {
                (internal_wire::WorkerCommand::lock(request_id), None)
            }
            (internal_wire::WorkerCommandKind::ProviderStatus, None, None) => (
                internal_wire::WorkerCommand::provider_status(request_id),
                None,
            ),
            (
                internal_wire::WorkerCommandKind::ProviderOpenAiConfigure,
                Some(size),
                Some(descriptor),
            ) => (
                internal_wire::WorkerCommand::provider_openai_configure(request_id, size),
                Some(descriptor),
            ),
            (internal_wire::WorkerCommandKind::ProviderOpenAiLogout, None, None) => (
                internal_wire::WorkerCommand::provider_openai_logout(request_id),
                None,
            ),
            (internal_wire::WorkerCommandKind::ProviderOpenAiBorrow, None, Some(descriptor)) => (
                internal_wire::WorkerCommand::provider_openai_borrow(request_id),
                Some(descriptor),
            ),
            (internal_wire::WorkerCommandKind::AttestQuiescent, None, None) => (
                internal_wire::WorkerCommand::attest_quiescent(request_id),
                None,
            ),
            (internal_wire::WorkerCommandKind::Shutdown, None, None) => {
                (internal_wire::WorkerCommand::shutdown(request_id), None)
            }
            _ => return Err(RescueVaultDaemonError::ProtocolFailure),
        };
        let sent = internal_wire::send_command(
            channel.socket.as_fd(),
            command,
            outgoing.as_ref().map(AsFd::as_fd),
            deadline,
        );
        // SCM_RIGHTS has taken its own reference after a successful sendmsg.
        // Neither input secrets nor the supervisor's output writer remain
        // open while the worker processes the command.
        drop(outgoing);
        sent.map_err(|_| RescueVaultDaemonError::WorkerUnavailable)?;
        let response = loop {
            if cancellation.is_some_and(|cancelled| cancelled.load(Ordering::Acquire)) {
                return Err(RescueVaultDaemonError::WorkerUnavailable);
            }
            let now = Instant::now();
            let slice = now
                .checked_add(Duration::from_millis(200))
                .unwrap_or(deadline)
                .min(deadline);
            match internal_wire::receive_response(channel.socket.as_fd(), request_id, slice) {
                Ok(response) => break response,
                Err(internal_wire::InternalWireError::TimedOut) if slice < deadline => continue,
                Err(_) => return Err(RescueVaultDaemonError::WorkerUnavailable),
            }
        };
        if !response_matches(kind, &response) {
            return Err(RescueVaultDaemonError::ProtocolFailure);
        }
        self.cgroup.verify_exact_worker(self.pid)?;
        verify_worker_thread_capabilities(self.pid)?;
        if pidfd_ready(self.pidfd.as_fd())? {
            return Err(RescueVaultDaemonError::WorkerUnavailable);
        }
        let output = match provider_output {
            Some(output) => finalize_provider_output(output, &response, deadline)?,
            None => None,
        };
        Ok((response, output))
    }

    pub(super) fn exited(&self) -> Result<bool, RescueVaultDaemonError> {
        pidfd_ready(self.pidfd.as_fd())
    }

    pub(super) fn verify_healthy(&self) -> Result<(), RescueVaultDaemonError> {
        if self.terminal.load(Ordering::Acquire) {
            return Err(RescueVaultDaemonError::WorkerUnavailable);
        }
        self.cgroup.verify_exact_worker(self.pid)?;
        verify_worker_thread_capabilities(self.pid)?;
        if pidfd_ready(self.pidfd.as_fd())? {
            return Err(RescueVaultDaemonError::WorkerUnavailable);
        }
        Ok(())
    }

    pub(super) fn fault_and_terminate(
        &self,
        absolute_deadline: Instant,
    ) -> Result<(), RescueVaultDaemonError> {
        self.terminal.store(true, Ordering::Release);
        let cleanup = cleanup_deadline(absolute_deadline);
        if self
            .child
            .lock()
            .map_err(|_| RescueVaultDaemonError::ShutdownFailed)?
            .is_none()
        {
            return self.cgroup.wait_empty(cleanup);
        }
        let kill_cgroup = self.cgroup.kill_all();
        let kill_worker = pidfd_send_signal(&self.pidfd, Signal::KILL);
        if kill_cgroup.is_err() && kill_worker.is_err() {
            return Err(RescueVaultDaemonError::ShutdownFailed);
        }
        self.wait_reaped_and_empty(cleanup, false)
    }

    pub(super) fn cancel_clean(&self, deadline: Instant) -> Result<(), RescueVaultDaemonError> {
        self.terminal.store(true, Ordering::Release);
        let cleanup = cleanup_deadline(deadline);
        let kill_cgroup = self.cgroup.kill_all();
        let kill_worker = pidfd_send_signal(&self.pidfd, Signal::KILL);
        if kill_cgroup.is_err() && kill_worker.is_err() {
            return Err(RescueVaultDaemonError::ShutdownFailed);
        }
        self.wait_reaped_and_empty(cleanup, false)?;
        self.cgroup.remove_empty(cleanup)
    }

    pub(super) fn shutdown_clean(&self, deadline: Instant) -> Result<(), RescueVaultDaemonError> {
        let mut channel = self
            .channel
            .lock()
            .map_err(|_| RescueVaultDaemonError::ShutdownFailed)?;
        if self.terminal.load(Ordering::Acquire) {
            return Err(RescueVaultDaemonError::ShutdownFailed);
        }
        self.cgroup.verify_exact_worker(self.pid)?;
        if pidfd_ready(self.pidfd.as_fd())? {
            return Err(RescueVaultDaemonError::ShutdownFailed);
        }
        let request_id = channel.next_request_id;
        channel.next_request_id = request_id
            .checked_add(1)
            .filter(|next| *next != 0)
            .ok_or(RescueVaultDaemonError::ShutdownFailed)?;
        internal_wire::send_command(
            channel.socket.as_fd(),
            internal_wire::WorkerCommand::shutdown(request_id),
            None,
            deadline,
        )
        .map_err(|_| RescueVaultDaemonError::ShutdownFailed)?;
        let response =
            internal_wire::receive_response(channel.socket.as_fd(), request_id, deadline)
                .map_err(|_| RescueVaultDaemonError::ShutdownFailed)?;
        if response.code != internal_wire::WorkerResultCode::ShutdownSucceeded {
            return Err(RescueVaultDaemonError::ShutdownFailed);
        }
        self.terminal.store(true, Ordering::Release);
        drop(channel);
        self.wait_reaped_and_empty(deadline, true)?;
        self.cgroup.remove_empty(deadline)
    }

    fn wait_reaped_and_empty(
        &self,
        deadline: Instant,
        require_success: bool,
    ) -> Result<(), RescueVaultDaemonError> {
        wait_pidfd(self.pidfd.as_fd(), deadline)?;
        let mut child_guard = self
            .child
            .lock()
            .map_err(|_| RescueVaultDaemonError::ShutdownFailed)?;
        let Some(child) = child_guard.as_mut() else {
            return self.cgroup.wait_empty(deadline);
        };
        let status = child
            .try_wait()
            .map_err(|_| RescueVaultDaemonError::ShutdownFailed)?
            .ok_or(RescueVaultDaemonError::ShutdownFailed)?;
        if require_success && !status.success() {
            return Err(RescueVaultDaemonError::ShutdownFailed);
        }
        *child_guard = None;
        self.cgroup.wait_empty(deadline)
    }
}

fn cleanup_spawn_failure(
    child: &mut Child,
    pidfd: &OwnedFd,
    cgroup: &WorkerCgroup,
    absolute_deadline: Instant,
) -> bool {
    let _ = cgroup.kill_all();
    let _ = pidfd_send_signal(pidfd, Signal::KILL);
    let deadline = cleanup_deadline(absolute_deadline);
    if bounded_child_reap(child, deadline).is_err() || cgroup.wait_empty(deadline).is_err() {
        return false;
    }
    cgroup.remove_empty(deadline).is_ok()
}

fn cancelled_spawn_result(
    child: &mut Child,
    pidfd: &OwnedFd,
    cgroup: &WorkerCgroup,
    absolute_deadline: Instant,
) -> Result<WorkerSpawnResult, RescueVaultDaemonError> {
    if cleanup_spawn_failure(child, pidfd, cgroup, absolute_deadline) {
        Ok(WorkerSpawnResult::CancelledClean)
    } else {
        Err(RescueVaultDaemonError::ShutdownFailed)
    }
}

fn cleanup_deadline(absolute_deadline: Instant) -> Instant {
    Instant::now()
        .checked_add(WORKER_EXIT_GRACE)
        .unwrap_or(absolute_deadline)
        .min(absolute_deadline)
}

fn create_provider_output_pipe() -> Result<(OwnedFd, OwnedFd), RescueVaultDaemonError> {
    let (read, write) = pipe_with(PipeFlags::CLOEXEC | PipeFlags::NONBLOCK)
        .map_err(|_| RescueVaultDaemonError::WorkerUnavailable)?;
    validate_provider_output_endpoint(read.as_fd(), OFlags::RDONLY)?;
    validate_provider_output_endpoint(write.as_fd(), OFlags::WRONLY)?;
    let read_stat = rfs::fstat(&read).map_err(|_| RescueVaultDaemonError::WorkerUnavailable)?;
    let write_stat = rfs::fstat(&write).map_err(|_| RescueVaultDaemonError::WorkerUnavailable)?;
    if read_stat.st_dev != write_stat.st_dev || read_stat.st_ino != write_stat.st_ino {
        return Err(RescueVaultDaemonError::WorkerUnavailable);
    }
    Ok((read, write))
}

fn validate_provider_output_endpoint(
    descriptor: BorrowedFd<'_>,
    access: OFlags,
) -> Result<(), RescueVaultDaemonError> {
    let stat = rfs::fstat(descriptor).map_err(|_| RescueVaultDaemonError::WorkerUnavailable)?;
    let filesystem =
        rfs::fstatfs(descriptor).map_err(|_| RescueVaultDaemonError::WorkerUnavailable)?;
    let filesystem_type =
        u64::try_from(filesystem.f_type).map_err(|_| RescueVaultDaemonError::WorkerUnavailable)?;
    let status =
        rfs::fcntl_getfl(descriptor).map_err(|_| RescueVaultDaemonError::WorkerUnavailable)?;
    let descriptor_flags = rustix::io::fcntl_getfd(descriptor)
        .map_err(|_| RescueVaultDaemonError::WorkerUnavailable)?;
    let capacity = rustix::pipe::fcntl_getpipe_size(descriptor)
        .map_err(|_| RescueVaultDaemonError::WorkerUnavailable)?;
    if !FileType::from_raw_mode(stat.st_mode).is_fifo()
        || filesystem_type != PIPEFS_MAGIC
        || status != (access | OFlags::NONBLOCK)
        || descriptor_flags != rustix::io::FdFlags::CLOEXEC
        || stat.st_size != 0
        || capacity < MAX_PROVIDER_OUTPUT_BYTES
    {
        return Err(RescueVaultDaemonError::WorkerUnavailable);
    }
    Ok(())
}

fn finalize_provider_output(
    output: OwnedFd,
    response: &internal_wire::WorkerResponse,
    deadline: Instant,
) -> Result<Option<OwnedFd>, RescueVaultDaemonError> {
    validate_provider_output_endpoint(output.as_fd(), OFlags::RDONLY)?;
    let expected = match (response.code, response.output_size) {
        (internal_wire::WorkerResultCode::ProviderBorrowReady, Some(size))
            if (1..=MAX_PROVIDER_OUTPUT_BYTES).contains(&usize::from(size)) =>
        {
            u64::from(size)
        }
        (internal_wire::WorkerResultCode::ProviderBorrowReady, _) | (_, Some(_)) => {
            return Err(RescueVaultDaemonError::ProtocolFailure);
        }
        (_, None) => 0,
    };
    wait_provider_output_hup(output.as_fd(), deadline)?;
    let available = rustix::io::ioctl_fionread(output.as_fd())
        .map_err(|_| RescueVaultDaemonError::ProtocolFailure)?;
    if available != expected {
        return Err(RescueVaultDaemonError::ProtocolFailure);
    }
    if response.code == internal_wire::WorkerResultCode::ProviderBorrowReady {
        Ok(Some(output))
    } else {
        Ok(None)
    }
}

fn wait_provider_output_hup(
    output: BorrowedFd<'_>,
    deadline: Instant,
) -> Result<(), RescueVaultDaemonError> {
    loop {
        let remaining = deadline
            .checked_duration_since(Instant::now())
            .filter(|remaining| !remaining.is_zero())
            .ok_or(RescueVaultDaemonError::ProtocolFailure)?;
        let mut descriptors = [PollFd::from_borrowed_fd(output, PollFlags::HUP)];
        match poll(&mut descriptors, Some(&duration_to_timespec(remaining))) {
            Ok(0) => return Err(RescueVaultDaemonError::ProtocolFailure),
            Ok(_) => {
                let events = descriptors[0].revents();
                if events.intersects(PollFlags::NVAL | PollFlags::ERR) {
                    return Err(RescueVaultDaemonError::ProtocolFailure);
                }
                if events.contains(PollFlags::HUP) {
                    return Ok(());
                }
            }
            Err(error) if error == rustix::io::Errno::INTR => {}
            Err(_) => return Err(RescueVaultDaemonError::ProtocolFailure),
        }
    }
}

fn duration_to_timespec(duration: Duration) -> Timespec {
    let seconds = i64::try_from(duration.as_secs()).unwrap_or(i64::MAX);
    Timespec {
        tv_sec: seconds,
        tv_nsec: if seconds == i64::MAX {
            999_999_999
        } else {
            i64::from(duration.subsec_nanos())
        },
    }
}

fn response_matches(
    kind: internal_wire::WorkerCommandKind,
    response: &internal_wire::WorkerResponse,
) -> bool {
    use internal_wire::{WorkerCommandKind as Command, WorkerResultCode as Result};
    match kind {
        Command::Bootstrap => response.code == Result::BootstrapReady,
        Command::Probe => matches!(
            response.code,
            Result::ProbeAbsent
                | Result::ProbeUnprovisioned
                | Result::ProbeLocked
                | Result::ProbeProfileMismatch
                | Result::ProbeClassifierUnavailable
                | Result::ProbeIoFailed
                | Result::TimedOut
                | Result::CleanupFailed
        ),
        Command::Unlock => matches!(
            response.code,
            Result::UnlockSucceeded
                | Result::Absent
                | Result::Unprovisioned
                | Result::ProfileMismatch
                | Result::BadPassphrase
                | Result::MediaChanged
                | Result::IoFailed
                | Result::CleanupFailed
                | Result::TimedOut
                | Result::Busy
        ),
        Command::Lock => matches!(
            response.code,
            Result::LockSucceeded
                | Result::IoFailed
                | Result::CleanupFailed
                | Result::TimedOut
                | Result::Busy
        ),
        Command::ProviderStatus => matches!(
            response.code,
            Result::ProviderStatusUnconfigured
                | Result::ProviderStatusConfigured
                | Result::ProviderStateAmbiguous
                | Result::CleanupFailed
        ),
        Command::ProviderOpenAiConfigure => matches!(
            response.code,
            Result::ProviderConfigureSucceeded
                | Result::ProviderMutationAborted
                | Result::ProviderStateAmbiguous
                | Result::InvalidRequest
                | Result::CleanupFailed
        ),
        Command::ProviderOpenAiLogout => matches!(
            response.code,
            Result::ProviderLogoutSucceeded
                | Result::ProviderMutationAborted
                | Result::ProviderStateAmbiguous
                | Result::CleanupFailed
        ),
        Command::ProviderOpenAiBorrow => matches!(
            response.code,
            Result::ProviderBorrowReady
                | Result::ProviderBorrowUnconfigured
                | Result::ProviderStateAmbiguous
                | Result::IoFailed
                | Result::CleanupFailed
        ),
        Command::AttestQuiescent => matches!(
            response.code,
            Result::AttestAbsent
                | Result::AttestUnprovisioned
                | Result::AttestLocked
                | Result::AttestProfileMismatch
                | Result::TimedOut
                | Result::CleanupFailed
                | Result::IoFailed
        ),
        Command::Shutdown => matches!(
            response.code,
            Result::ShutdownSucceeded | Result::CleanupFailed | Result::TimedOut
        ),
    }
}

fn pidfd_ready(pidfd: BorrowedFd<'_>) -> Result<bool, RescueVaultDaemonError> {
    let mut descriptor = [PollFd::from_borrowed_fd(pidfd, PollFlags::IN)];
    let zero = Timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    match poll(&mut descriptor, Some(&zero)) {
        Ok(0) => Ok(false),
        Ok(_) if descriptor[0].revents().contains(PollFlags::NVAL) => {
            Err(RescueVaultDaemonError::WorkerUnavailable)
        }
        Ok(_) => Ok(descriptor[0]
            .revents()
            .intersects(PollFlags::IN | PollFlags::ERR | PollFlags::HUP)),
        Err(error) if error == rustix::io::Errno::INTR => Ok(false),
        Err(_) => Err(RescueVaultDaemonError::WorkerUnavailable),
    }
}

fn wait_pidfd(pidfd: BorrowedFd<'_>, deadline: Instant) -> Result<(), RescueVaultDaemonError> {
    loop {
        if pidfd_ready(pidfd)? {
            return Ok(());
        }
        let remaining = deadline
            .checked_duration_since(Instant::now())
            .filter(|remaining| !remaining.is_zero())
            .ok_or(RescueVaultDaemonError::ShutdownFailed)?;
        let seconds = i64::try_from(remaining.as_secs()).unwrap_or(i64::MAX);
        let timeout = Timespec {
            tv_sec: seconds,
            tv_nsec: if seconds == i64::MAX {
                999_999_999
            } else {
                i64::from(remaining.subsec_nanos())
            },
        };
        let mut descriptor = [PollFd::from_borrowed_fd(pidfd, PollFlags::IN)];
        match poll(&mut descriptor, Some(&timeout)) {
            Ok(0) => return Err(RescueVaultDaemonError::ShutdownFailed),
            Ok(_) => {}
            Err(error) if error == rustix::io::Errno::INTR => {}
            Err(_) => return Err(RescueVaultDaemonError::ShutdownFailed),
        }
    }
}

fn bounded_child_reap(child: &mut Child, deadline: Instant) -> Result<(), RescueVaultDaemonError> {
    loop {
        match child.try_wait() {
            Ok(Some(_)) => return Ok(()),
            Ok(None) if Instant::now() < deadline => {
                std::thread::sleep(Duration::from_millis(10));
            }
            Ok(None) | Err(_) => return Err(RescueVaultDaemonError::ShutdownFailed),
        }
    }
}

fn write_one(descriptor: &OwnedFd, bytes: &[u8]) -> Result<(), ()> {
    match rustix::io::write(descriptor, bytes) {
        Ok(written) if written == bytes.len() => Ok(()),
        _ => Err(()),
    }
}

fn read_bounded(descriptor: BorrowedFd<'_>, maximum: usize) -> Result<Vec<u8>, ()> {
    let mut output = Vec::new();
    let mut buffer = [0_u8; 512];
    loop {
        match rustix::io::read(descriptor, &mut buffer) {
            Ok(0) => return Ok(output),
            Ok(count) if output.len().saturating_add(count) <= maximum => {
                output.extend_from_slice(&buffer[..count]);
            }
            Ok(_) | Err(_) => return Err(()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{ffi::OsString, os::fd::AsRawFd, os::unix::fs::symlink};

    fn temporary_root() -> (tempfile::TempDir, OwnedFd) {
        let directory = tempfile::tempdir().expect("temporary runtime");
        let root = rfs::open(
            directory.path(),
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .expect("runtime descriptor");
        (directory, root)
    }

    #[test]
    fn delegated_path_parser_requires_exact_supervisor_sibling_shape() {
        assert_eq!(
            parse_delegated_membership(
                b"0::/system.slice/kernaid-rescue-vaultd.service/supervisor\n"
            )
            .expect("valid path"),
            vec![
                OsString::from("system.slice"),
                OsString::from("kernaid-rescue-vaultd.service")
            ]
        );
        for invalid in [
            &b"0::/supervisor\n"[..],
            &b"0::/a/../supervisor\n"[..],
            &b"0::/a/worker\n"[..],
            &b"2:cpu:/a/supervisor\n"[..],
            &b"0::/a/supervisor\n0::/b/supervisor\n"[..],
            &b"0::/a//supervisor\n"[..],
            &b"0::/a/supervisor"[..],
        ] {
            assert_eq!(
                parse_delegated_membership(invalid).err(),
                Some(RescueVaultDaemonError::CgroupUnavailable)
            );
        }
    }

    #[test]
    fn runtime_root_mount_crossing_requires_named_same_tmpfs_identity() {
        assert!(runtime_root_mount_is_exact(
            11,
            22,
            11,
            22,
            11,
            Some(TMPFS_MAGIC),
            Some(TMPFS_MAGIC),
        ));
        for candidate in [
            (12, 22, 11, 22, 11, Some(TMPFS_MAGIC), Some(TMPFS_MAGIC)),
            (11, 23, 11, 22, 11, Some(TMPFS_MAGIC), Some(TMPFS_MAGIC)),
            (11, 22, 11, 22, 12, Some(TMPFS_MAGIC), Some(TMPFS_MAGIC)),
            (
                11,
                22,
                11,
                22,
                11,
                Some(PROC_SUPER_MAGIC),
                Some(TMPFS_MAGIC),
            ),
            (11, 22, 11, 22, 11, Some(TMPFS_MAGIC), None),
        ] {
            assert!(!runtime_root_mount_is_exact(
                candidate.0,
                candidate.1,
                candidate.2,
                candidate.3,
                candidate.4,
                candidate.5,
                candidate.6,
            ));
        }
    }

    #[test]
    fn pids_controller_activation_is_exact_and_fail_closed() {
        assert_eq!(
            pids_controller_activation_required(b"cpu io memory pids\n", b""),
            Ok(true)
        );
        assert_eq!(
            pids_controller_activation_required(b"memory pids\n", b"pids\n"),
            Ok(false)
        );
        assert_eq!(pids_controller_is_listed(b"pids\n"), Ok(true));
        assert_eq!(pids_controller_is_listed(b"pid\n"), Ok(false));
        assert_eq!(pids_controller_is_listed(b""), Ok(false));
        assert_eq!(
            pids_controller_activation_required(b"cpu memory\n", b""),
            Err(RescueVaultDaemonError::CgroupUnavailable)
        );

        for invalid in [
            &b"pids"[..],
            &b"pids\nextra\n"[..],
            &b" pids\n"[..],
            &b"pids \n"[..],
            &b"cpu  pids\n"[..],
            &b"cpu\tpids\n"[..],
            &b"pids pids\n"[..],
            &b"PIDS\n"[..],
            &b"pids\0\n"[..],
        ] {
            assert_eq!(
                pids_controller_is_listed(invalid),
                Err(RescueVaultDaemonError::CgroupUnavailable)
            );
        }
    }

    #[test]
    fn recursive_cgroup_metrics_allow_only_supervisor_and_worker_siblings() {
        assert!(cgroup_tree_metrics_are_exact(1, 0, None, 2));
        assert!(cgroup_tree_metrics_are_exact(2, 0, Some(0), 2));
        for (parent, supervisor, worker, supervisor_tasks) in [
            (0, 0, None, 2),
            (2, 0, None, 2),
            (3, 0, Some(0), 2),
            (2, 1, Some(0), 2),
            (2, 0, Some(1), 2),
            (2, 0, Some(0), 0),
        ] {
            assert!(!cgroup_tree_metrics_are_exact(
                parent,
                supervisor,
                worker,
                supervisor_tasks,
            ));
        }
    }

    #[test]
    fn worker_membership_and_population_reject_nested_or_residual_processes() {
        assert_eq!(
            parse_worker_membership(b"0::/system.slice/example.service/worker\n"),
            Ok(())
        );
        for invalid in [
            &b"0::/system.slice/example.service/worker/child\n"[..],
            &b"0::/system.slice/example.service/supervisor\n"[..],
            &b"0::/system.slice/../worker\n"[..],
            &b"0::/system.slice/example.service/worker\n0::/other/worker\n"[..],
            &b"2:cpu:/system.slice/example.service/worker\n"[..],
        ] {
            assert_eq!(
                parse_worker_membership(invalid),
                Err(RescueVaultDaemonError::CgroupUnavailable)
            );
        }

        assert!(worker_population_is_exact(&[4242], 1, 0, true, 4242));
        assert!(!worker_population_is_exact(&[4242], 2, 0, true, 4242));
        assert!(!worker_population_is_exact(&[4242], 1, 1, true, 4242));
        assert!(!worker_population_is_exact(&[4242], 1, 0, false, 4242));
        assert!(!worker_population_is_exact(&[4242, 4243], 2, 0, true, 4242));

        assert!(worker_population_is_empty(&[], 0, 0, false));
        assert!(!worker_population_is_empty(&[], 1, 0, true));
        assert!(!worker_population_is_empty(&[], 1, 1, true));
        assert!(!worker_population_is_empty(&[4242], 1, 0, true));

        assert_eq!(parse_single_cgroup_number(b"0\n"), Ok(0));
        assert_eq!(parse_single_cgroup_number(b"1\n"), Ok(1));
        for invalid in [
            &b"01\n"[..],
            &b"1\n2\n"[..],
            &b"-1\n"[..],
            &b"1"[..],
            &b"\n"[..],
        ] {
            assert_eq!(
                parse_single_cgroup_number(invalid),
                Err(RescueVaultDaemonError::CgroupUnavailable)
            );
        }
    }

    #[test]
    fn worker_response_semantics_are_operation_specific() {
        let probe =
            internal_wire::WorkerResponse::new(1, internal_wire::WorkerResultCode::ProbeLocked);
        assert!(response_matches(
            internal_wire::WorkerCommandKind::Probe,
            &probe
        ));
        assert!(!response_matches(
            internal_wire::WorkerCommandKind::Unlock,
            &probe
        ));
        let unlock =
            internal_wire::WorkerResponse::unlocked(2, "KA-0123456789abcdef01234567".to_owned());
        assert!(response_matches(
            internal_wire::WorkerCommandKind::Unlock,
            &unlock
        ));

        let ready = internal_wire::WorkerResponse::provider_borrow_ready(3, 32);
        assert!(response_matches(
            internal_wire::WorkerCommandKind::ProviderOpenAiBorrow,
            &ready
        ));
        for divergent in [
            internal_wire::WorkerResultCode::Busy,
            internal_wire::WorkerResultCode::InvalidRequest,
        ] {
            assert!(!response_matches(
                internal_wire::WorkerCommandKind::ProviderOpenAiBorrow,
                &internal_wire::WorkerResponse::new(3, divergent)
            ));
        }
    }

    #[test]
    fn provider_output_completion_requires_exact_hup_and_byte_count_without_reading() {
        let (read, write) = create_provider_output_pipe().expect("provider output pipe");
        let synthetic = [b'X'; 32];
        assert_eq!(rustix::io::write(&write, &synthetic), Ok(32));
        drop(write);
        let ready = internal_wire::WorkerResponse::provider_borrow_ready(4, 32);
        let read = finalize_provider_output(read, &ready, Instant::now() + Duration::from_secs(1))
            .expect("valid ready completion")
            .expect("ready descriptor");
        assert_eq!(rustix::io::ioctl_fionread(read.as_fd()), Ok(32));

        let (empty, empty_writer) = create_provider_output_pipe().expect("empty output pipe");
        drop(empty_writer);
        let unconfigured = internal_wire::WorkerResponse::new(
            5,
            internal_wire::WorkerResultCode::ProviderBorrowUnconfigured,
        );
        assert!(
            finalize_provider_output(
                empty,
                &unconfigured,
                Instant::now() + Duration::from_secs(1)
            )
            .expect("valid unconfigured completion")
            .is_none()
        );
    }

    #[test]
    fn provider_output_completion_rejects_open_writer_timeout_and_protocol_mismatch() {
        let (open, open_writer) = create_provider_output_pipe().expect("open output pipe");
        let unconfigured = internal_wire::WorkerResponse::new(
            6,
            internal_wire::WorkerResultCode::ProviderBorrowUnconfigured,
        );
        assert!(matches!(
            finalize_provider_output(
                open,
                &unconfigured,
                Instant::now() + Duration::from_millis(20)
            ),
            Err(RescueVaultDaemonError::ProtocolFailure)
        ));
        let zero = Timespec {
            tv_sec: 0,
            tv_nsec: 0,
        };
        let mut descriptors = [PollFd::from_borrowed_fd(
            open_writer.as_fd(),
            PollFlags::OUT,
        )];
        assert_eq!(poll(&mut descriptors, Some(&zero)), Ok(1));
        assert!(descriptors[0].revents().contains(PollFlags::ERR));
        drop(open_writer);

        let (mismatch, mismatch_writer) =
            create_provider_output_pipe().expect("mismatch output pipe");
        let target = descriptor_target(mismatch.as_fd());
        let synthetic = [b'X'; 31];
        assert_eq!(rustix::io::write(&mismatch_writer, &synthetic), Ok(31));
        drop(mismatch_writer);
        assert_eq!(descriptor_target_count(&target), 1);
        let ready = internal_wire::WorkerResponse::provider_borrow_ready(7, 32);
        assert!(matches!(
            finalize_provider_output(mismatch, &ready, Instant::now() + Duration::from_secs(1)),
            Err(RescueVaultDaemonError::ProtocolFailure)
        ));
        assert_eq!(descriptor_target_count(&target), 0);

        let (unexpected, unexpected_writer) =
            create_provider_output_pipe().expect("unexpected output pipe");
        assert_eq!(rustix::io::write(&unexpected_writer, b"X"), Ok(1));
        drop(unexpected_writer);
        assert!(matches!(
            finalize_provider_output(
                unexpected,
                &unconfigured,
                Instant::now() + Duration::from_secs(1)
            ),
            Err(RescueVaultDaemonError::ProtocolFailure)
        ));
    }

    fn descriptor_target(descriptor: BorrowedFd<'_>) -> OsString {
        std::fs::read_link(format!("/proc/self/fd/{}", descriptor.as_raw_fd()))
            .expect("descriptor target")
            .into_os_string()
    }

    fn descriptor_target_count(target: &OsString) -> usize {
        std::fs::read_dir("/proc/self/fd")
            .expect("proc fd")
            .filter_map(Result::ok)
            .filter_map(|entry| std::fs::read_link(entry.path()).ok())
            .filter(|observed| observed.as_os_str() == target.as_os_str())
            .count()
    }

    #[test]
    fn any_named_or_partial_marker_forces_persistent_fault() {
        let (directory, root) = temporary_root();
        assert_eq!(
            marker_disposition(&root).expect("missing marker"),
            RuntimeDisposition::Ready
        );

        std::fs::write(directory.path().join(FAULT_MARKER_NAME), b"short").expect("partial marker");
        assert_eq!(
            marker_disposition(&root).expect("partial marker"),
            RuntimeDisposition::PersistentFault
        );
        std::fs::remove_file(directory.path().join(FAULT_MARKER_NAME)).expect("remove partial");
        symlink("missing-target", directory.path().join(FAULT_MARKER_NAME))
            .expect("marker symlink");
        assert_eq!(
            marker_disposition(&root).expect("named marker"),
            RuntimeDisposition::PersistentFault
        );
    }

    #[test]
    fn marker_create_write_and_sync_faults_remain_restart_evidence() {
        let uid = rustix::process::geteuid().as_raw();
        let gid = rustix::process::getegid().as_raw();
        for fault in [
            MarkerMutationStep::Created,
            MarkerMutationStep::Written,
            MarkerMutationStep::FileSynced,
            MarkerMutationStep::DirectorySynced,
        ] {
            let (_directory, root) = temporary_root();
            let result = create_fault_marker_with_hook(&root, uid, gid, |step| {
                if step == fault {
                    Err(RescueVaultDaemonError::RuntimeUnavailable)
                } else {
                    Ok(())
                }
            });
            assert!(result.is_err(), "fault point {fault:?}");
            assert_eq!(
                marker_disposition(&root).expect("restart disposition"),
                RuntimeDisposition::PersistentFault,
                "fault point {fault:?} must never restart a worker"
            );
        }
    }

    #[test]
    fn failed_marker_unlink_or_directory_sync_is_immediately_rearmed() {
        let uid = rustix::process::geteuid().as_raw();
        let gid = rustix::process::getegid().as_raw();
        for fault in [
            MarkerMutationStep::Unlinked,
            MarkerMutationStep::DirectorySynced,
        ] {
            let (_directory, root) = temporary_root();
            create_fault_marker_with_hook(&root, uid, gid, |_| Ok(())).expect("initial marker");
            let result = remove_fault_marker_with_hook(&root, uid, gid, |step| {
                if step == fault {
                    Err(RescueVaultDaemonError::ShutdownFailed)
                } else {
                    Ok(())
                }
            });
            assert!(result.is_err(), "fault point {fault:?}");
            // A failed disarm is never accepted as clean. The same action
            // mark_fault performs must recreate and durably sync the marker.
            match marker_disposition(&root).expect("post-fault disposition") {
                RuntimeDisposition::PersistentFault => {}
                RuntimeDisposition::Ready => {
                    create_fault_marker_with_hook(&root, uid, gid, |_| Ok(()))
                        .expect("immediate re-arm");
                }
            }
            assert_eq!(
                marker_disposition(&root).expect("restart disposition"),
                RuntimeDisposition::PersistentFault
            );
        }
    }

    #[test]
    fn cleanup_deadline_only_consumes_remaining_absolute_budget() {
        let now = Instant::now();
        let expired = now
            .checked_sub(Duration::from_secs(1))
            .expect("expired deadline");
        assert_eq!(cleanup_deadline(expired), expired);

        let short = Instant::now()
            .checked_add(Duration::from_millis(50))
            .expect("short deadline");
        assert_eq!(cleanup_deadline(short), short);

        let long = Instant::now()
            .checked_add(Duration::from_secs(30))
            .expect("long deadline");
        let bounded = cleanup_deadline(long);
        assert!(bounded <= long);
        assert!(bounded <= Instant::now() + WORKER_EXIT_GRACE);
    }
}
