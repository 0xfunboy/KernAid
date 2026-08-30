//! Descriptor-bound daemon runtime, fault marker, cgroup, and worker process.

use super::{RescueVaultDaemonError, internal_wire};
#[cfg(feature = "experimental-repair-store")]
use kernaid_protocol::rescue_repair_vault::{
    MAX_REPAIR_BACKUP_BYTES, RepairBackupBinding, RepairBackupDraft, RepairBackupStatusPayload,
    RepairFileMetadataV1, RepairReservationId, RepairRollbackBindingV1, RepairRollbackId,
    RepairRollbackResolution, RepairRollbackStatusSelector, RepairRollbackTransactionStatusPayload,
    RepairTransactionResolution, RepairTransactionStatusPayload, RepairTransactionStatusSelector,
};
use kernaid_protocol::rescue_vault::{
    MAX_SIGNED_REPORT_ENVELOPE_BYTES, ReportId, ReportSummary, Sha256, ValidatedRequest,
};
use rustix::{
    event::{PollFd, PollFlags, Timespec, poll},
    fd::OwnedFd,
    fs::{
        self as rfs, AtFlags, CWD, FileType, FlockOperation, Mode, OFlags, RawDir, ResolveFlags,
        SeekFrom,
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
use sha2::Digest;
use std::{
    ffi::{OsStr, OsString},
    fs as stdfs,
    mem::MaybeUninit,
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
use zeroize::Zeroizing;

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
const MAX_PROC_MOUNTINFO_BYTES: usize = 256 * 1024;
const PROVIDER_AGENT_CGROUP_NAME: &[u8] = b"agent";
const PROVIDER_CONTROL_CGROUP_NAME: &[u8] = b".control";
const SYSTEM_SLICE_CGROUP_NAME: &[u8] = b"system.slice";
const OPENAI_EXECUTOR_UNIT_PREFIX: &[u8] = b"kernaid-rescue-openai-executor@";
#[cfg(feature = "experimental-codex-home-lease")]
const CODEX_EXECUTOR_UNIT_PREFIX: &[u8] = b"kernaid-rescue-codex@";
const LEASE_PROBE_UNIT_PREFIX: &[u8] = b"kernaid-provider-lease-probe@";
const SERVICE_UNIT_SUFFIX: &[u8] = b".service";
const PROVIDER_UNIT_ROOT_AGENT_CONTROLS: [(&str, u32); 3] = [
    ("cgroup.procs", 0o644),
    ("cgroup.subtree_control", 0o644),
    ("cgroup.threads", 0o644),
];
const PROVIDER_SUBGROUP_AGENT_CONTROLS: [(&str, u32); 4] = [
    ("cgroup.procs", 0o644),
    ("cgroup.events", 0o444),
    ("cgroup.kill", 0o200),
    ("cgroup.stat", 0o444),
];
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
#[cfg(feature = "experimental-codex-home-lease")]
const CODEX_MOUNTER_BOOTSTRAP_CAPABILITIES: CapabilitySet = CapabilitySet::SYS_ADMIN
    .union(CapabilitySet::SYS_CHROOT)
    .union(CapabilitySet::SETPCAP);

pub(super) type WorkerReportGetResult =
    Result<(internal_wire::WorkerResponse, Option<Zeroizing<Vec<u8>>>), RescueVaultDaemonError>;
#[cfg(feature = "experimental-repair-store")]
pub(super) type WorkerRepairGetResult =
    Result<(internal_wire::WorkerResponse, Option<Zeroizing<Vec<u8>>>), RescueVaultDaemonError>;

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

#[cfg(feature = "experimental-codex-home-lease")]
pub(super) fn normalize_codex_mounter_capabilities() -> Result<(), RescueVaultDaemonError> {
    normalize_bootstrap_capabilities(CODEX_MOUNTER_BOOTSTRAP_CAPABILITIES)
}

#[cfg(feature = "experimental-codex-home-lease")]
pub(super) fn drop_codex_mounter_chroot_capability() -> Result<(), RescueVaultDaemonError> {
    narrow_capabilities(
        CODEX_MOUNTER_BOOTSTRAP_CAPABILITIES,
        CapabilitySet::SYS_ADMIN,
        &[CapabilitySet::SYS_CHROOT, CapabilitySet::SETPCAP],
    )
}

#[cfg(feature = "experimental-codex-home-lease")]
pub(super) fn verify_codex_mounter_mount_capability() -> Result<(), RescueVaultDaemonError> {
    verify_exact_capabilities(CapabilitySet::SYS_ADMIN)
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
    normalize_bootstrap_capabilities(expected_initial)?;
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

fn normalize_bootstrap_capabilities(expected: CapabilitySet) -> Result<(), RescueVaultDaemonError> {
    // systemd 257 may retain a subset of the service's authorized bootstrap
    // capabilities in CapInh while keeping CapEff/CapPrm/CapBnd exact. Clear
    // that non-effective set before any capability is dropped, then require
    // the same strict zero-inheritable shape used for the running processes.
    let observed = capabilities(None).map_err(|_| RescueVaultDaemonError::RuntimeUnavailable)?;
    if !bootstrap_capability_sets_are_allowed(&observed, expected) {
        return Err(RescueVaultDaemonError::RuntimeUnavailable);
    }
    verify_bounding_and_ambient_capabilities(expected)?;
    set_capabilities(
        None,
        CapabilitySets {
            effective: expected,
            permitted: expected,
            inheritable: CapabilitySet::empty(),
        },
    )
    .map_err(|_| RescueVaultDaemonError::RuntimeUnavailable)?;
    verify_exact_capabilities(expected)
}

fn bootstrap_capability_sets_are_allowed(
    observed: &CapabilitySets,
    expected: CapabilitySet,
) -> bool {
    observed.effective == expected
        && observed.permitted == expected
        && expected.contains(observed.inheritable)
}

fn verify_exact_capabilities(expected: CapabilitySet) -> Result<(), RescueVaultDaemonError> {
    let observed = capabilities(None).map_err(|_| RescueVaultDaemonError::RuntimeUnavailable)?;
    if observed.effective != expected
        || observed.permitted != expected
        || !observed.inheritable.is_empty()
    {
        return Err(RescueVaultDaemonError::RuntimeUnavailable);
    }
    verify_bounding_and_ambient_capabilities(expected)
}

fn verify_bounding_and_ambient_capabilities(
    expected: CapabilitySet,
) -> Result<(), RescueVaultDaemonError> {
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

/// The process boundary attached to a credential lease. DirectPeer is kept
/// for provider adapters whose execution model cannot create descendants;
/// shipping OpenAI borrows require the complete delegated service tree.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum ProcessScope {
    DirectPeer,
    CgroupTree,
}

/// Descriptor-bound process ownership retained for the entire provider lease.
pub(super) struct ProviderProcessBoundary {
    scope: ProcessScope,
    tree: Option<ProviderCgroupTree>,
}

impl ProviderProcessBoundary {
    pub(super) fn direct_peer() -> Self {
        Self {
            scope: ProcessScope::DirectPeer,
            tree: None,
        }
    }

    pub(super) fn capture(
        scope: ProcessScope,
        peer_pid: i32,
        peer_uid: u32,
        peer_gid: u32,
    ) -> Result<Self, RescueVaultDaemonError> {
        if peer_pid <= 1 || peer_uid == 0 || peer_gid == 0 {
            return Err(RescueVaultDaemonError::CgroupUnavailable);
        }
        let tree = match scope {
            ProcessScope::DirectPeer => return Ok(Self::direct_peer()),
            ProcessScope::CgroupTree => {
                Some(ProviderCgroupTree::capture(peer_pid, peer_uid, peer_gid)?)
            }
        };
        Ok(Self { scope, tree })
    }

    pub(super) fn try_clone(&self) -> Result<Self, RescueVaultDaemonError> {
        Ok(Self {
            scope: self.scope,
            tree: self
                .tree
                .as_ref()
                .map(ProviderCgroupTree::try_clone)
                .transpose()?,
        })
    }

    pub(super) fn verify_initial_peer(&self, peer_pid: i32) -> Result<(), RescueVaultDaemonError> {
        match &self.tree {
            Some(tree) => tree.verify_initial_peer(peer_pid),
            None => Ok(()),
        }
    }

    pub(super) fn events(&self) -> Option<BorrowedFd<'_>> {
        self.tree.as_ref().map(|tree| tree.events.as_fd())
    }

    pub(super) fn is_quiescent(
        &self,
        direct_peer_exited: bool,
    ) -> Result<bool, RescueVaultDaemonError> {
        match &self.tree {
            Some(tree) => tree.is_quiescent(),
            None => Ok(direct_peer_exited),
        }
    }

    pub(super) fn kill_all(&self) -> Result<(), RescueVaultDaemonError> {
        match &self.tree {
            Some(tree) => tree.kill_all(),
            None => Ok(()),
        }
    }

    #[cfg(test)]
    pub(super) fn scope(&self) -> ProcessScope {
        self.scope
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ProviderUnitKind {
    OpenAiExecutor,
    #[cfg(feature = "experimental-codex-home-lease")]
    CodexExecutor,
    LeaseProbe,
}

struct ProviderMembership {
    unit: OsString,
    kind: ProviderUnitKind,
}

struct ProviderCgroupTree {
    parent: OwnedFd,
    root: OwnedFd,
    agent: OwnedFd,
    events: OwnedFd,
    kill: OwnedFd,
    unit: OsString,
    kind: ProviderUnitKind,
    peer_uid: u32,
    peer_gid: u32,
    root_device: u64,
    root_inode: u64,
    agent_device: u64,
    agent_inode: u64,
    events_device: u64,
    events_inode: u64,
    kill_device: u64,
    kill_inode: u64,
}

impl ProviderCgroupTree {
    fn capture(
        peer_pid: i32,
        peer_uid: u32,
        peer_gid: u32,
    ) -> Result<Self, RescueVaultDaemonError> {
        let proc = open_proc_root()?;
        let membership_bytes =
            read_proc_pid_file(&proc, peer_pid, "cgroup", MAX_CGROUP_FILE_BYTES)?;
        let membership = parse_provider_membership(&membership_bytes)?;
        let peer_mountinfo =
            read_proc_pid_file(&proc, peer_pid, "mountinfo", MAX_PROC_MOUNTINFO_BYTES)?;
        let self_mountinfo = read_proc_pid_file(
            &proc,
            rustix::process::getpid().as_raw_pid(),
            "mountinfo",
            MAX_PROC_MOUNTINFO_BYTES,
        )?;

        let cgroup_root = open_cgroup_root()?;
        let root_stat =
            rfs::fstat(&cgroup_root).map_err(|_| RescueVaultDaemonError::CgroupUnavailable)?;
        if !mountinfo_has_exact_cgroup2_access(&peer_mountinfo, root_stat.st_dev, false)?
            || !mountinfo_has_exact_cgroup2_access(&self_mountinfo, root_stat.st_dev, true)?
        {
            return Err(RescueVaultDaemonError::CgroupUnavailable);
        }
        let parent = open_cgroup_child(&cgroup_root, OsStr::from_bytes(SYSTEM_SLICE_CGROUP_NAME))?;
        validate_cgroup_directory(&parent, Some(&cgroup_root))?;
        let root = open_cgroup_child(&parent, &membership.unit)?;
        validate_provider_delegated_directory(&root, &parent, peer_uid, peer_gid)?;
        validate_provider_unit_root_control_files(&root, peer_uid, peer_gid)?;
        let agent = open_cgroup_child(&root, OsStr::from_bytes(PROVIDER_AGENT_CGROUP_NAME))?;
        validate_provider_delegated_directory(&agent, &root, peer_uid, peer_gid)?;
        let events = open_cgroup_file(&root, "cgroup.events", OFlags::RDONLY)?;
        let kill = open_cgroup_file(&root, "cgroup.kill", OFlags::WRONLY)?;
        validate_provider_root_control_file(&events, &root, 0o444)?;
        validate_provider_root_control_file(&kill, &root, 0o200)?;
        validate_provider_subgroup_control_files(&agent, peer_uid, peer_gid)?;

        let root_stat = rfs::fstat(&root).map_err(|_| RescueVaultDaemonError::CgroupUnavailable)?;
        let agent_stat =
            rfs::fstat(&agent).map_err(|_| RescueVaultDaemonError::CgroupUnavailable)?;
        let events_stat =
            rfs::fstat(&events).map_err(|_| RescueVaultDaemonError::CgroupUnavailable)?;
        let kill_stat = rfs::fstat(&kill).map_err(|_| RescueVaultDaemonError::CgroupUnavailable)?;
        let tree = Self {
            parent,
            root,
            agent,
            events,
            kill,
            unit: membership.unit,
            kind: membership.kind,
            peer_uid,
            peer_gid,
            root_device: root_stat.st_dev,
            root_inode: root_stat.st_ino,
            agent_device: agent_stat.st_dev,
            agent_inode: agent_stat.st_ino,
            events_device: events_stat.st_dev,
            events_inode: events_stat.st_ino,
            kill_device: kill_stat.st_dev,
            kill_inode: kill_stat.st_ino,
        };
        tree.verify_initial_peer(peer_pid)?;
        Ok(tree)
    }

    fn try_clone(&self) -> Result<Self, RescueVaultDaemonError> {
        let duplicate = |descriptor: &OwnedFd| {
            rustix::io::fcntl_dupfd_cloexec(descriptor, 3)
                .map_err(|_| RescueVaultDaemonError::CgroupUnavailable)
        };
        // Open independent control-file descriptions. dup(2) would share the
        // cgroup.events offset across concurrent monitor/revoker snapshots.
        // If systemd has already collected the exact prevalidated unit, only
        // dead retained descriptions remain; their qualified ENODEV behavior
        // is first proven and they are safe to duplicate because no offset can
        // advance.
        let controls = (|| {
            let events = open_cgroup_file(&self.root, "cgroup.events", OFlags::RDONLY)?;
            let kill = open_cgroup_file(&self.root, "cgroup.kill", OFlags::WRONLY)?;
            validate_retained_identity(&events, self.events_device, self.events_inode, false)?;
            validate_retained_identity(&kill, self.kill_device, self.kill_inode, false)?;
            Ok::<_, RescueVaultDaemonError>((events, kill))
        })();
        let (events, kill) = match controls {
            Ok(controls) => controls,
            Err(_) if self.verify_garbage_collected()? => {
                (duplicate(&self.events)?, duplicate(&self.kill)?)
            }
            Err(_) => return Err(RescueVaultDaemonError::CgroupUnavailable),
        };
        Ok(Self {
            parent: duplicate(&self.parent)?,
            root: duplicate(&self.root)?,
            agent: duplicate(&self.agent)?,
            events,
            kill,
            unit: self.unit.clone(),
            kind: self.kind,
            peer_uid: self.peer_uid,
            peer_gid: self.peer_gid,
            root_device: self.root_device,
            root_inode: self.root_inode,
            agent_device: self.agent_device,
            agent_inode: self.agent_inode,
            events_device: self.events_device,
            events_inode: self.events_inode,
            kill_device: self.kill_device,
            kill_inode: self.kill_inode,
        })
    }

    fn verify_initial_peer(&self, peer_pid: i32) -> Result<(), RescueVaultDaemonError> {
        self.validate_named_root()?;
        self.validate_retained_descriptors()?;
        let named_agent = rfs::statat(
            &self.root,
            OsStr::from_bytes(PROVIDER_AGENT_CGROUP_NAME),
            AtFlags::SYMLINK_NOFOLLOW,
        )
        .map_err(|_| RescueVaultDaemonError::CgroupUnavailable)?;
        if named_agent.st_dev != self.agent_device || named_agent.st_ino != self.agent_inode {
            return Err(RescueVaultDaemonError::CgroupUnavailable);
        }
        let expected_children: &[&[u8]] = match self.kind {
            ProviderUnitKind::OpenAiExecutor => &[PROVIDER_AGENT_CGROUP_NAME],
            #[cfg(feature = "experimental-codex-home-lease")]
            ProviderUnitKind::CodexExecutor => &[PROVIDER_AGENT_CGROUP_NAME],
            ProviderUnitKind::LeaseProbe => {
                &[PROVIDER_CONTROL_CGROUP_NAME, PROVIDER_AGENT_CGROUP_NAME]
            }
        };
        if !provider_child_directories_are_exact(self.kind, &cgroup_child_directories(&self.root)?)
            || !read_provider_cgroup_procs(&self.root)?.is_empty()
            || read_provider_cgroup_procs(&self.agent)? != [peer_pid]
            || cgroup_descendant_count(&self.root)? != expected_children.len() as u64
            || provider_cgroup_descendant_count(&self.agent)? != 0
            || !cgroup_populated(&self.root)?
            || !provider_cgroup_populated(&self.agent)?
        {
            return Err(RescueVaultDaemonError::CgroupUnavailable);
        }
        if self.kind == ProviderUnitKind::LeaseProbe {
            let control =
                open_cgroup_child(&self.root, OsStr::from_bytes(PROVIDER_CONTROL_CGROUP_NAME))?;
            validate_provider_delegated_directory(
                &control,
                &self.root,
                self.peer_uid,
                self.peer_gid,
            )?;
            validate_provider_subgroup_control_files(&control, self.peer_uid, self.peer_gid)?;
            if !provider_control_is_empty(
                &read_provider_cgroup_procs(&control)?,
                provider_cgroup_descendant_count(&control)?,
                provider_cgroup_populated(&control)?,
            ) {
                return Err(RescueVaultDaemonError::CgroupUnavailable);
            }
        }
        Ok(())
    }

    fn is_quiescent(&self) -> Result<bool, RescueVaultDaemonError> {
        self.validate_retained_descriptors()?;
        match self.named_root_state()? {
            NamedCgroupState::Present => match read_cgroup_events_fd(self.events.as_fd()) {
                Ok(false) => Ok(true),
                Ok(true) => {
                    if self.validate_populated_topology().is_ok() {
                        return Ok(false);
                    }
                    // Population may drop while systemd recursively trims
                    // .control, agent, and finally the unit root between the
                    // fresh populated=1 read and the topology walk. Re-read
                    // the retained events file: an exact populated=0 is the
                    // same terminal evidence accepted above. A still-live or
                    // ENODEV descriptor remains closed unless the complete
                    // named-path-absence plus retained ENODEV proof succeeds.
                    let population = match read_cgroup_events_fd(self.events.as_fd()) {
                        Ok(false) => RetainedPopulationState::Empty,
                        Ok(true) => RetainedPopulationState::Populated,
                        Err(error) if error == rustix::io::Errno::NODEV => {
                            RetainedPopulationState::Gone
                        }
                        Err(_) => return Err(RescueVaultDaemonError::CgroupUnavailable),
                    };
                    let garbage_collected = match population {
                        RetainedPopulationState::Empty => false,
                        RetainedPopulationState::Populated | RetainedPopulationState::Gone => {
                            self.verify_garbage_collected()?
                        }
                    };
                    classify_topology_race(population, garbage_collected)
                }
                Err(error) if error == rustix::io::Errno::NODEV => self.verify_garbage_collected(),
                Err(_) => Err(RescueVaultDaemonError::CgroupUnavailable),
            },
            NamedCgroupState::Absent => self.verify_garbage_collected(),
        }
    }

    fn kill_all(&self) -> Result<(), RescueVaultDaemonError> {
        self.validate_retained_descriptors()?;
        match self.named_root_state()? {
            NamedCgroupState::Absent => {
                if self.verify_garbage_collected()? {
                    Ok(())
                } else {
                    Err(RescueVaultDaemonError::CgroupUnavailable)
                }
            }
            NamedCgroupState::Present => match rustix::io::write(&self.kill, b"1") {
                Ok(1) => Ok(()),
                Err(error) if error == rustix::io::Errno::NODEV => {
                    if self.verify_garbage_collected()? {
                        Ok(())
                    } else {
                        Err(RescueVaultDaemonError::CgroupUnavailable)
                    }
                }
                _ => Err(RescueVaultDaemonError::CgroupUnavailable),
            },
        }
    }

    fn validate_named_root(&self) -> Result<(), RescueVaultDaemonError> {
        match self.named_root_state()? {
            NamedCgroupState::Present => Ok(()),
            NamedCgroupState::Absent => Err(RescueVaultDaemonError::CgroupUnavailable),
        }
    }

    fn named_root_state(&self) -> Result<NamedCgroupState, RescueVaultDaemonError> {
        match rfs::statat(&self.parent, &self.unit, AtFlags::SYMLINK_NOFOLLOW) {
            Ok(named)
                if named.st_dev == self.root_device
                    && named.st_ino == self.root_inode
                    && FileType::from_raw_mode(named.st_mode).is_dir() =>
            {
                Ok(NamedCgroupState::Present)
            }
            Ok(_) => Err(RescueVaultDaemonError::CgroupUnavailable),
            Err(error) if error == rustix::io::Errno::NOENT => Ok(NamedCgroupState::Absent),
            Err(_) => Err(RescueVaultDaemonError::CgroupUnavailable),
        }
    }

    fn validate_retained_descriptors(&self) -> Result<(), RescueVaultDaemonError> {
        validate_retained_identity(&self.root, self.root_device, self.root_inode, true)?;
        validate_retained_identity(&self.agent, self.agent_device, self.agent_inode, true)?;
        validate_retained_identity(&self.events, self.events_device, self.events_inode, false)?;
        validate_retained_identity(&self.kill, self.kill_device, self.kill_inode, false)
    }

    fn validate_populated_topology(&self) -> Result<(), RescueVaultDaemonError> {
        self.validate_named_root()?;
        if !read_provider_cgroup_procs(&self.root)?.is_empty()
            || provider_cgroup_descendant_count(&self.agent)? != 0
        {
            return Err(RescueVaultDaemonError::CgroupUnavailable);
        }
        let expected_children: &[&[u8]] = match self.kind {
            ProviderUnitKind::OpenAiExecutor => &[PROVIDER_AGENT_CGROUP_NAME],
            #[cfg(feature = "experimental-codex-home-lease")]
            ProviderUnitKind::CodexExecutor => &[PROVIDER_AGENT_CGROUP_NAME],
            ProviderUnitKind::LeaseProbe => {
                &[PROVIDER_CONTROL_CGROUP_NAME, PROVIDER_AGENT_CGROUP_NAME]
            }
        };
        if !provider_child_directories_are_exact(self.kind, &cgroup_child_directories(&self.root)?)
            || cgroup_descendant_count(&self.root)? != expected_children.len() as u64
        {
            return Err(RescueVaultDaemonError::CgroupUnavailable);
        }
        if self.kind == ProviderUnitKind::LeaseProbe {
            let control =
                open_cgroup_child(&self.root, OsStr::from_bytes(PROVIDER_CONTROL_CGROUP_NAME))?;
            validate_provider_delegated_directory(
                &control,
                &self.root,
                self.peer_uid,
                self.peer_gid,
            )?;
            validate_provider_subgroup_control_files(&control, self.peer_uid, self.peer_gid)?;
            if !provider_control_is_empty(
                &read_provider_cgroup_procs(&control)?,
                provider_cgroup_descendant_count(&control)?,
                provider_cgroup_populated(&control)?,
            ) {
                return Err(RescueVaultDaemonError::CgroupUnavailable);
            }
        }
        Ok(())
    }

    fn verify_garbage_collected(&self) -> Result<bool, RescueVaultDaemonError> {
        if self.named_root_state()? != NamedCgroupState::Absent {
            return Ok(false);
        }
        let events_nodev = match read_cgroup_events_fd(self.events.as_fd()) {
            Err(error) if error == rustix::io::Errno::NODEV => true,
            Ok(_) => false,
            Err(_) => return Err(RescueVaultDaemonError::CgroupUnavailable),
        };
        let kill_nodev = match rustix::io::write(&self.kill, b"1") {
            Err(error) if error == rustix::io::Errno::NODEV => true,
            Ok(_) => false,
            Err(_) => return Err(RescueVaultDaemonError::CgroupUnavailable),
        };
        let named_path_still_absent = self.named_root_state()? == NamedCgroupState::Absent;
        Ok(garbage_collection_evidence_is_terminal(
            named_path_still_absent,
            events_nodev,
            kill_nodev,
        ))
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum NamedCgroupState {
    Present,
    Absent,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum RetainedPopulationState {
    Populated,
    Empty,
    Gone,
}

fn classify_topology_race(
    population: RetainedPopulationState,
    garbage_collected: bool,
) -> Result<bool, RescueVaultDaemonError> {
    match population {
        RetainedPopulationState::Empty => Ok(true),
        RetainedPopulationState::Populated | RetainedPopulationState::Gone if garbage_collected => {
            Ok(true)
        }
        RetainedPopulationState::Populated | RetainedPopulationState::Gone => {
            Err(RescueVaultDaemonError::CgroupUnavailable)
        }
    }
}

fn garbage_collection_evidence_is_terminal(
    named_path_absent: bool,
    retained_events_nodev: bool,
    retained_kill_nodev: bool,
) -> bool {
    named_path_absent && retained_events_nodev && retained_kill_nodev
}

fn provider_child_directories_are_exact(kind: ProviderUnitKind, children: &[&[u8]]) -> bool {
    match kind {
        ProviderUnitKind::OpenAiExecutor => children == [PROVIDER_AGENT_CGROUP_NAME],
        #[cfg(feature = "experimental-codex-home-lease")]
        ProviderUnitKind::CodexExecutor => children == [PROVIDER_AGENT_CGROUP_NAME],
        ProviderUnitKind::LeaseProbe => {
            children == [PROVIDER_CONTROL_CGROUP_NAME, PROVIDER_AGENT_CGROUP_NAME]
        }
    }
}

fn provider_control_is_empty(processes: &[i32], descendants: u64, populated: bool) -> bool {
    processes.is_empty() && descendants == 0 && !populated
}

fn validate_retained_identity(
    descriptor: &OwnedFd,
    expected_device: u64,
    expected_inode: u64,
    directory: bool,
) -> Result<(), RescueVaultDaemonError> {
    let stat = rfs::fstat(descriptor).map_err(|_| RescueVaultDaemonError::CgroupUnavailable)?;
    let file_type = FileType::from_raw_mode(stat.st_mode);
    let descriptor_flags = rustix::io::fcntl_getfd(descriptor)
        .map_err(|_| RescueVaultDaemonError::CgroupUnavailable)?;
    if stat.st_dev != expected_device
        || stat.st_ino != expected_inode
        || directory != file_type.is_dir()
        || (!directory && !file_type.is_file())
        || !descriptor_flags.contains(rustix::io::FdFlags::CLOEXEC)
    {
        return Err(RescueVaultDaemonError::CgroupUnavailable);
    }
    Ok(())
}

fn parse_provider_membership(bytes: &[u8]) -> Result<ProviderMembership, RescueVaultDaemonError> {
    if bytes.is_empty()
        || bytes.len() > MAX_CGROUP_FILE_BYTES
        || !bytes.ends_with(b"\n")
        || bytes[..bytes.len() - 1].contains(&b'\n')
        || !bytes.starts_with(b"0::/system.slice/")
    {
        return Err(RescueVaultDaemonError::CgroupUnavailable);
    }
    let path = &bytes[b"0::/system.slice/".len()..bytes.len() - 1];
    let Some(unit) = path.strip_suffix(b"/agent") else {
        return Err(RescueVaultDaemonError::CgroupUnavailable);
    };
    if unit.is_empty() || unit.contains(&b'/') {
        return Err(RescueVaultDaemonError::CgroupUnavailable);
    }
    let kind = if valid_instantiated_service(unit, OPENAI_EXECUTOR_UNIT_PREFIX) {
        ProviderUnitKind::OpenAiExecutor
    } else if valid_instantiated_service(unit, LEASE_PROBE_UNIT_PREFIX) {
        ProviderUnitKind::LeaseProbe
    } else {
        #[cfg(feature = "experimental-codex-home-lease")]
        if valid_instantiated_service(unit, CODEX_EXECUTOR_UNIT_PREFIX) {
            ProviderUnitKind::CodexExecutor
        } else {
            return Err(RescueVaultDaemonError::CgroupUnavailable);
        }
        #[cfg(not(feature = "experimental-codex-home-lease"))]
        return Err(RescueVaultDaemonError::CgroupUnavailable);
    };
    Ok(ProviderMembership {
        unit: OsString::from_vec(unit.to_vec()),
        kind,
    })
}

fn valid_instantiated_service(unit: &[u8], prefix: &[u8]) -> bool {
    let Some(instance_with_suffix) = unit.strip_prefix(prefix) else {
        return false;
    };
    let Some(instance) = instance_with_suffix.strip_suffix(SERVICE_UNIT_SUFFIX) else {
        return false;
    };
    if instance.is_empty() || instance.len() > MAX_CGROUP_COMPONENT_BYTES {
        return false;
    }
    let mut index = 0;
    while index < instance.len() {
        let byte = instance[index];
        if byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-' | b'.' | b':') {
            index += 1;
            continue;
        }
        if byte == b'\\'
            && instance.get(index + 1) == Some(&b'x')
            && instance
                .get(index + 2..index + 4)
                .is_some_and(|hex| hex.iter().all(u8::is_ascii_hexdigit))
        {
            index += 4;
            continue;
        }
        return false;
    }
    true
}

fn open_proc_root() -> Result<OwnedFd, RescueVaultDaemonError> {
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
    Ok(proc)
}

fn read_proc_pid_file(
    proc: &OwnedFd,
    pid: i32,
    name: &str,
    maximum: usize,
) -> Result<Vec<u8>, RescueVaultDaemonError> {
    if pid <= 0 || !pid.to_string().bytes().all(|byte| byte.is_ascii_digit()) {
        return Err(RescueVaultDaemonError::CgroupUnavailable);
    }
    let process = rfs::openat2(
        proc,
        pid.to_string(),
        OFlags::PATH | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
        beneath_flags(),
    )
    .map_err(|_| RescueVaultDaemonError::CgroupUnavailable)?;
    let descriptor = rfs::openat2(
        &process,
        name,
        OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
        beneath_flags(),
    )
    .map_err(|_| RescueVaultDaemonError::CgroupUnavailable)?;
    let stat = rfs::fstat(&descriptor).map_err(|_| RescueVaultDaemonError::CgroupUnavailable)?;
    let filesystem =
        rfs::fstatfs(&descriptor).map_err(|_| RescueVaultDaemonError::CgroupUnavailable)?;
    if !FileType::from_raw_mode(stat.st_mode).is_file()
        || u64::try_from(filesystem.f_type).ok() != Some(PROC_SUPER_MAGIC)
    {
        return Err(RescueVaultDaemonError::CgroupUnavailable);
    }
    read_bounded(descriptor.as_fd(), maximum).map_err(|_| RescueVaultDaemonError::CgroupUnavailable)
}

fn mountinfo_has_exact_cgroup2_access(
    bytes: &[u8],
    expected_device: u64,
    writable: bool,
) -> Result<bool, RescueVaultDaemonError> {
    if bytes.is_empty() || bytes.len() > MAX_PROC_MOUNTINFO_BYTES || !bytes.ends_with(b"\n") {
        return Err(RescueVaultDaemonError::CgroupUnavailable);
    }
    let mut found = false;
    for line in bytes[..bytes.len() - 1].split(|byte| *byte == b'\n') {
        if line.is_empty() || line.contains(&0) {
            return Err(RescueVaultDaemonError::CgroupUnavailable);
        }
        let fields: Vec<&[u8]> = line.split(|byte| *byte == b' ').collect();
        let Some(separator) = fields.iter().position(|field| *field == b"-") else {
            return Err(RescueVaultDaemonError::CgroupUnavailable);
        };
        if separator < 6 || fields.len().saturating_sub(separator) < 4 {
            return Err(RescueVaultDaemonError::CgroupUnavailable);
        }
        if fields[separator + 1] != b"cgroup2" {
            continue;
        }
        if found
            || fields[3] != b"/"
            || fields[4] != b"/sys/fs/cgroup"
            || fields[separator + 2] != b"cgroup2"
            || fields[2].contains(&b'\\')
            || fields[3].contains(&b'\\')
            || fields[4].contains(&b'\\')
        {
            return Ok(false);
        }
        let (major, minor) = parse_mountinfo_device(fields[2])?;
        if major != rfs::major(expected_device) || minor != rfs::minor(expected_device) {
            return Ok(false);
        }
        let (has_ro, has_rw) = parse_mount_access_options(fields[5])?;
        let (super_has_ro, super_has_rw) = parse_mount_access_options(fields[separator + 3])?;
        if has_ro == has_rw || writable != has_rw {
            return Ok(false);
        }
        if super_has_ro || !super_has_rw {
            return Ok(false);
        }
        found = true;
    }
    Ok(found)
}

fn parse_mount_access_options(bytes: &[u8]) -> Result<(bool, bool), RescueVaultDaemonError> {
    if bytes.is_empty() || bytes.len() > 4096 {
        return Err(RescueVaultDaemonError::CgroupUnavailable);
    }
    let mut options: Vec<&[u8]> = Vec::new();
    for option in bytes.split(|byte| *byte == b',') {
        if option.is_empty()
            || option.len() > 128
            || option.iter().any(|byte| {
                !byte.is_ascii_alphanumeric() && !matches!(byte, b'_' | b'-' | b'.' | b'=')
            })
            || options.contains(&option)
        {
            return Err(RescueVaultDaemonError::CgroupUnavailable);
        }
        options.push(option);
    }
    Ok((
        options.contains(&b"ro".as_slice()),
        options.contains(&b"rw".as_slice()),
    ))
}

fn parse_mountinfo_device(bytes: &[u8]) -> Result<(u32, u32), RescueVaultDaemonError> {
    let mut fields = bytes.split(|byte| *byte == b':');
    let major = fields.next().unwrap_or_default();
    let minor = fields.next().unwrap_or_default();
    if fields.next().is_some() {
        return Err(RescueVaultDaemonError::CgroupUnavailable);
    }
    let parse = |value: &[u8]| {
        if value.is_empty()
            || value.len() > 10
            || !value.iter().all(u8::is_ascii_digit)
            || (value.len() > 1 && value[0] == b'0')
        {
            return None;
        }
        std::str::from_utf8(value).ok()?.parse::<u32>().ok()
    };
    Ok((
        parse(major).ok_or(RescueVaultDaemonError::CgroupUnavailable)?,
        parse(minor).ok_or(RescueVaultDaemonError::CgroupUnavailable)?,
    ))
}

fn validate_provider_delegated_directory(
    descriptor: &OwnedFd,
    parent: &OwnedFd,
    peer_uid: u32,
    peer_gid: u32,
) -> Result<(), RescueVaultDaemonError> {
    let stat = rfs::fstat(descriptor).map_err(|_| RescueVaultDaemonError::CgroupUnavailable)?;
    let parent = rfs::fstat(parent).map_err(|_| RescueVaultDaemonError::CgroupUnavailable)?;
    let filesystem =
        rfs::fstatfs(descriptor).map_err(|_| RescueVaultDaemonError::CgroupUnavailable)?;
    let descriptor_flags = rustix::io::fcntl_getfd(descriptor)
        .map_err(|_| RescueVaultDaemonError::CgroupUnavailable)?;
    if !provider_delegated_directory_metadata_is_exact(
        FileType::from_raw_mode(stat.st_mode),
        (stat.st_uid, stat.st_gid),
        (peer_uid, peer_gid),
        (stat.st_dev, parent.st_dev),
        stat.st_mode,
        u64::try_from(filesystem.f_type).ok(),
        descriptor_flags.contains(rustix::io::FdFlags::CLOEXEC),
    ) {
        return Err(RescueVaultDaemonError::CgroupUnavailable);
    }
    Ok(())
}

fn provider_delegated_directory_metadata_is_exact(
    file_type: FileType,
    ownership: (u32, u32),
    expected_ownership: (u32, u32),
    device: (u64, u64),
    mode: u32,
    filesystem_type: Option<u64>,
    cloexec: bool,
) -> bool {
    file_type.is_dir()
        && ownership == expected_ownership
        && ownership.0 != 0
        && ownership.1 != 0
        && device.0 == device.1
        && mode & 0o7777 == 0o755
        && filesystem_type == Some(CGROUP2_SUPER_MAGIC)
        && cloexec
}

fn validate_provider_root_control_file(
    descriptor: &OwnedFd,
    root: &OwnedFd,
    expected_mode: u32,
) -> Result<(), RescueVaultDaemonError> {
    let stat = rfs::fstat(descriptor).map_err(|_| RescueVaultDaemonError::CgroupUnavailable)?;
    let root = rfs::fstat(root).map_err(|_| RescueVaultDaemonError::CgroupUnavailable)?;
    if !provider_root_control_metadata_is_exact(
        FileType::from_raw_mode(stat.st_mode),
        stat.st_uid,
        stat.st_gid,
        stat.st_dev,
        root.st_dev,
        stat.st_mode,
        expected_mode,
    ) {
        return Err(RescueVaultDaemonError::CgroupUnavailable);
    }
    Ok(())
}

fn provider_root_control_metadata_is_exact(
    file_type: FileType,
    uid: u32,
    gid: u32,
    device: u64,
    parent_device: u64,
    mode: u32,
    expected_mode: u32,
) -> bool {
    file_type.is_file()
        && uid == 0
        && gid == 0
        && device == parent_device
        && mode & 0o7777 == expected_mode
}

fn provider_delegated_control_metadata_is_exact(
    file_type: FileType,
    ownership: (u32, u32),
    expected_ownership: (u32, u32),
    device: (u64, u64),
    mode: u32,
    expected_mode: u32,
) -> bool {
    file_type.is_file()
        && ownership == expected_ownership
        && ownership.0 != 0
        && ownership.1 != 0
        && device.0 == device.1
        && mode & 0o7777 == expected_mode
}

fn validate_provider_unit_root_control_files(
    root: &OwnedFd,
    peer_uid: u32,
    peer_gid: u32,
) -> Result<(), RescueVaultDaemonError> {
    // systemd v257's fatal unified cg_set_access() allowlist delegates these
    // three writable unit-root controls while leaving events and kill root-owned.
    for (name, expected_mode) in PROVIDER_UNIT_ROOT_AGENT_CONTROLS {
        let stat = rfs::statat(root, name, AtFlags::SYMLINK_NOFOLLOW)
            .map_err(|_| RescueVaultDaemonError::CgroupUnavailable)?;
        let parent = rfs::fstat(root).map_err(|_| RescueVaultDaemonError::CgroupUnavailable)?;
        if !provider_delegated_control_metadata_is_exact(
            FileType::from_raw_mode(stat.st_mode),
            (stat.st_uid, stat.st_gid),
            (peer_uid, peer_gid),
            (stat.st_dev, parent.st_dev),
            stat.st_mode,
            expected_mode,
        ) {
            return Err(RescueVaultDaemonError::CgroupUnavailable);
        }
    }
    Ok(())
}

fn validate_provider_subgroup_control_files(
    subgroup: &OwnedFd,
    peer_uid: u32,
    peer_gid: u32,
) -> Result<(), RescueVaultDaemonError> {
    // v257 recursively chowns the selected DelegateSubgroup, including the
    // `.control` subgroup selected for ExecCondition. Inspect Agent-owned
    // write-only controls as metadata only; vaultd mutates the root kill file.
    for (name, expected_mode) in PROVIDER_SUBGROUP_AGENT_CONTROLS {
        let stat = rfs::statat(subgroup, name, AtFlags::SYMLINK_NOFOLLOW)
            .map_err(|_| RescueVaultDaemonError::CgroupUnavailable)?;
        let parent = rfs::fstat(subgroup).map_err(|_| RescueVaultDaemonError::CgroupUnavailable)?;
        if !provider_delegated_control_metadata_is_exact(
            FileType::from_raw_mode(stat.st_mode),
            (stat.st_uid, stat.st_gid),
            (peer_uid, peer_gid),
            (stat.st_dev, parent.st_dev),
            stat.st_mode,
            expected_mode,
        ) {
            return Err(RescueVaultDaemonError::CgroupUnavailable);
        }
    }
    Ok(())
}

fn cgroup_child_directories(
    directory: &OwnedFd,
) -> Result<Vec<&'static [u8]>, RescueVaultDaemonError> {
    let scan = rfs::openat2(
        directory,
        ".",
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
        beneath_flags(),
    )
    .map_err(|_| RescueVaultDaemonError::CgroupUnavailable)?;
    let mut buffer = [MaybeUninit::<u8>::uninit(); 8192];
    let mut entries = RawDir::new(&scan, &mut buffer);
    let mut children = Vec::new();
    let mut count = 0_usize;
    while let Some(entry) = entries.next() {
        let entry = entry.map_err(|_| RescueVaultDaemonError::CgroupUnavailable)?;
        let name = entry.file_name().to_bytes();
        if matches!(name, b"." | b"..") {
            continue;
        }
        count = count
            .checked_add(1)
            .ok_or(RescueVaultDaemonError::CgroupUnavailable)?;
        if count > 256 || name.len() > MAX_CGROUP_COMPONENT_BYTES {
            return Err(RescueVaultDaemonError::CgroupUnavailable);
        }
        let is_directory = if entry.file_type() == FileType::Unknown {
            rfs::statat(
                directory,
                OsStr::from_bytes(name),
                AtFlags::SYMLINK_NOFOLLOW,
            )
            .map(|stat| FileType::from_raw_mode(stat.st_mode).is_dir())
            .map_err(|_| RescueVaultDaemonError::CgroupUnavailable)?
        } else {
            entry.file_type().is_dir()
        };
        if !is_directory {
            continue;
        }
        let known = match name {
            PROVIDER_AGENT_CGROUP_NAME => PROVIDER_AGENT_CGROUP_NAME,
            PROVIDER_CONTROL_CGROUP_NAME => PROVIDER_CONTROL_CGROUP_NAME,
            _ => return Err(RescueVaultDaemonError::CgroupUnavailable),
        };
        if children.contains(&known) {
            return Err(RescueVaultDaemonError::CgroupUnavailable);
        }
        children.push(known);
    }
    children.sort_unstable();
    Ok(children)
}

fn read_cgroup_events_fd(descriptor: BorrowedFd<'_>) -> Result<bool, rustix::io::Errno> {
    rfs::seek(descriptor, SeekFrom::Start(0))?;
    let bytes = read_bounded_errno(descriptor, MAX_CGROUP_FILE_BYTES)?;
    parse_cgroup_events_populated(&bytes).map_err(|_| rustix::io::Errno::INVAL)
}

fn read_bounded_errno(
    descriptor: BorrowedFd<'_>,
    maximum: usize,
) -> Result<Vec<u8>, rustix::io::Errno> {
    let mut output = Vec::new();
    let mut buffer = [0_u8; 512];
    loop {
        match rustix::io::read(descriptor, &mut buffer) {
            Ok(0) => return Ok(output),
            Ok(count) if output.len().saturating_add(count) <= maximum => {
                output.extend_from_slice(&buffer[..count]);
            }
            Ok(_) => return Err(rustix::io::Errno::FBIG),
            Err(error) => return Err(error),
        }
    }
}

fn parse_cgroup_events_populated(bytes: &[u8]) -> Result<bool, RescueVaultDaemonError> {
    let mut populated = None;
    if bytes.is_empty() || bytes.len() > MAX_CGROUP_FILE_BYTES || !bytes.ends_with(b"\n") {
        return Err(RescueVaultDaemonError::CgroupUnavailable);
    }
    for line in bytes[..bytes.len() - 1].split(|byte| *byte == b'\n') {
        let mut fields = line.split(|byte| *byte == b' ');
        let key = fields.next().unwrap_or_default();
        let value = fields.next().unwrap_or_default();
        if key.is_empty() || fields.next().is_some() || value.len() != 1 {
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

fn open_provider_cgroup_file(
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
    if !FileType::from_raw_mode(stat.st_mode).is_file() || stat.st_dev != parent.st_dev {
        return Err(RescueVaultDaemonError::CgroupUnavailable);
    }
    Ok(descriptor)
}

fn read_cgroup_procs(directory: &OwnedFd) -> Result<Vec<i32>, RescueVaultDaemonError> {
    let descriptor = open_cgroup_file(directory, "cgroup.procs", OFlags::RDONLY)?;
    let bytes = read_bounded(descriptor.as_fd(), MAX_CGROUP_FILE_BYTES)
        .map_err(|_| RescueVaultDaemonError::CgroupUnavailable)?;
    parse_cgroup_procs(&bytes)
}

fn read_provider_cgroup_procs(directory: &OwnedFd) -> Result<Vec<i32>, RescueVaultDaemonError> {
    let descriptor = open_provider_cgroup_file(directory, "cgroup.procs", OFlags::RDONLY)?;
    let bytes = read_bounded(descriptor.as_fd(), MAX_CGROUP_FILE_BYTES)
        .map_err(|_| RescueVaultDaemonError::CgroupUnavailable)?;
    parse_cgroup_procs(&bytes)
}

fn parse_cgroup_procs(bytes: &[u8]) -> Result<Vec<i32>, RescueVaultDaemonError> {
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
    parse_cgroup_events_populated(&bytes)
}

fn provider_cgroup_populated(directory: &OwnedFd) -> Result<bool, RescueVaultDaemonError> {
    let descriptor = open_provider_cgroup_file(directory, "cgroup.events", OFlags::RDONLY)?;
    let bytes = read_bounded(descriptor.as_fd(), MAX_CGROUP_FILE_BYTES)
        .map_err(|_| RescueVaultDaemonError::CgroupUnavailable)?;
    parse_cgroup_events_populated(&bytes)
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
    parse_cgroup_descendant_count(&bytes)
}

fn provider_cgroup_descendant_count(directory: &OwnedFd) -> Result<u64, RescueVaultDaemonError> {
    let descriptor = open_provider_cgroup_file(directory, "cgroup.stat", OFlags::RDONLY)?;
    let bytes = read_bounded(descriptor.as_fd(), MAX_CGROUP_FILE_BYTES)
        .map_err(|_| RescueVaultDaemonError::CgroupUnavailable)?;
    parse_cgroup_descendant_count(&bytes)
}

fn parse_cgroup_descendant_count(bytes: &[u8]) -> Result<u64, RescueVaultDaemonError> {
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

#[derive(Default)]
struct WorkerTransactionContext<'a> {
    cancellation: Option<&'a AtomicBool>,
    provider_output: Option<OwnedFd>,
    application: Option<internal_wire::WorkerApplicationCommand>,
    #[cfg(feature = "experimental-repair-store")]
    repair: Option<internal_wire::WorkerRepairCommand>,
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
        #[cfg(feature = "experimental-codex-home-lease")]
        let codex_home_lease = kind == internal_wire::WorkerCommandKind::ProviderCodexHomeLease;
        #[cfg(not(feature = "experimental-codex-home-lease"))]
        let codex_home_lease = false;
        if kind == internal_wire::WorkerCommandKind::ProviderOpenAiBorrow || codex_home_lease {
            return Err(RescueVaultDaemonError::ProtocolFailure);
        }
        self.transact_inner(
            kind,
            secret_size,
            descriptor,
            deadline,
            WorkerTransactionContext {
                cancellation,
                ..WorkerTransactionContext::default()
            },
        )
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
            WorkerTransactionContext {
                provider_output: Some(read),
                ..WorkerTransactionContext::default()
            },
        )
    }

    /// Requests the descriptor-bound Codex home only after the supervisor has
    /// registered the complete Agent process tree as a revocable lease.
    #[cfg(feature = "experimental-codex-home-lease")]
    pub(super) fn lease_codex_home(
        &self,
        deadline: Instant,
    ) -> Result<(internal_wire::WorkerResponse, Option<OwnedFd>), RescueVaultDaemonError> {
        self.transact_inner(
            internal_wire::WorkerCommandKind::ProviderCodexHomeLease,
            None,
            None,
            deadline,
            WorkerTransactionContext::default(),
        )
    }

    pub(super) fn audit_append(
        &self,
        request: &ValidatedRequest,
        deadline: Instant,
    ) -> Result<internal_wire::WorkerResponse, RescueVaultDaemonError> {
        let kernaid_protocol::rescue_vault::RequestPayload::AuditAppend {
            sequence,
            event,
            outcome,
            error,
        } = request.payload()
        else {
            return Err(RescueVaultDaemonError::ProtocolFailure);
        };
        let application = internal_wire::WorkerApplicationCommand::AuditAppend {
            request_id: request.request_id().clone(),
            peer_uid: request.peer_uid(),
            peer_pid: request.peer_pid(),
            sequence: *sequence,
            event: *event,
            outcome: *outcome,
            error: *error,
        };
        self.transact_inner(
            internal_wire::WorkerCommandKind::AuditAppend,
            None,
            None,
            deadline,
            WorkerTransactionContext {
                application: Some(application),
                ..WorkerTransactionContext::default()
            },
        )
        .and_then(|(response, output)| {
            if output.is_none() {
                Ok(response)
            } else {
                Err(RescueVaultDaemonError::ProtocolFailure)
            }
        })
    }

    pub(super) fn report_persist(
        &self,
        report_id: &ReportId,
        payload_sha256: &Sha256,
        input_size: u64,
        input: OwnedFd,
        deadline: Instant,
    ) -> Result<internal_wire::WorkerResponse, RescueVaultDaemonError> {
        let application = internal_wire::WorkerApplicationCommand::ReportPersist {
            report_id: report_id.clone(),
            payload_sha256: internal_wire::decode_sha256(payload_sha256)
                .map_err(|_| RescueVaultDaemonError::ProtocolFailure)?,
            input_size,
        };
        self.transact_inner(
            internal_wire::WorkerCommandKind::ReportPersist,
            None,
            Some(input),
            deadline,
            WorkerTransactionContext {
                application: Some(application),
                ..WorkerTransactionContext::default()
            },
        )
        .and_then(|(response, output)| {
            if output.is_none() {
                Ok(response)
            } else {
                Err(RescueVaultDaemonError::ProtocolFailure)
            }
        })
    }

    pub(super) fn report_list(
        &self,
        deadline: Instant,
    ) -> Result<(internal_wire::WorkerResponse, Vec<ReportSummary>), RescueVaultDaemonError> {
        let (response, bytes) = self.transact_application_output(
            internal_wire::WorkerApplicationCommand::ReportList,
            internal_wire::MAX_APPLICATION_REPORT_LIST_BYTES,
            deadline,
        )?;
        if response.code != internal_wire::WorkerResultCode::ApplicationReportListReady {
            if bytes.is_empty() {
                return Ok((response, Vec::new()));
            }
            return Err(RescueVaultDaemonError::ProtocolFailure);
        }
        let count = response
            .application_record_count
            .ok_or(RescueVaultDaemonError::ProtocolFailure)?;
        if response.application_output_size != u64::try_from(bytes.len()).ok() {
            return Err(RescueVaultDaemonError::ProtocolFailure);
        }
        let reports = internal_wire::decode_report_records(&bytes, count)
            .map_err(|_| RescueVaultDaemonError::ProtocolFailure)?;
        Ok((response, reports))
    }

    pub(super) fn report_get(
        &self,
        report_id: &ReportId,
        deadline: Instant,
    ) -> WorkerReportGetResult {
        let (response, bytes) = self.transact_application_output(
            internal_wire::WorkerApplicationCommand::ReportGet {
                report_id: report_id.clone(),
            },
            MAX_SIGNED_REPORT_ENVELOPE_BYTES as usize,
            deadline,
        )?;
        match response.code {
            internal_wire::WorkerResultCode::ApplicationReportReady => {
                let report = response
                    .report
                    .as_ref()
                    .ok_or(RescueVaultDaemonError::ProtocolFailure)?;
                let expected = usize::try_from(report.envelope_size)
                    .map_err(|_| RescueVaultDaemonError::ProtocolFailure)?;
                if bytes.len() != expected
                    || response.application_output_size != Some(report.envelope_size)
                    || sha2::Sha256::digest(bytes.as_slice()).as_slice() != report.envelope_sha256
                {
                    return Err(RescueVaultDaemonError::ProtocolFailure);
                }
                Ok((response, Some(bytes)))
            }
            internal_wire::WorkerResultCode::ApplicationReportNotFound if bytes.is_empty() => {
                Ok((response, None))
            }
            _ if bytes.is_empty() => Ok((response, None)),
            _ => Err(RescueVaultDaemonError::ProtocolFailure),
        }
    }

    #[cfg(feature = "experimental-repair-store")]
    pub(super) fn repair_backup_reserve(
        &self,
        draft: &RepairBackupDraft,
        deadline: Instant,
    ) -> Result<internal_wire::WorkerResponse, RescueVaultDaemonError> {
        self.transact_repair_without_descriptor(
            internal_wire::WorkerRepairCommand::Reserve {
                draft: internal_wire::WorkerRepairDraft::from_protocol(draft),
            },
            deadline,
        )
    }

    #[cfg(feature = "experimental-repair-store")]
    pub(super) fn repair_backup_persist(
        &self,
        expected: &RepairBackupStatusPayload,
        binding: &RepairBackupBinding,
        metadata: &RepairFileMetadataV1,
        input_size: u64,
        input: OwnedFd,
        deadline: Instant,
    ) -> Result<internal_wire::WorkerResponse, RescueVaultDaemonError> {
        let expected = internal_wire::WorkerRepairStatus::from_protocol(expected)
            .map_err(|_| RescueVaultDaemonError::ProtocolFailure)?;
        let metadata = internal_wire::WorkerRepairFileMetadata::from_protocol(metadata);
        if !metadata.is_supported_root_file()
            || expected.metadata_sha256
                != metadata
                    .to_protocol()
                    .map_err(|_| RescueVaultDaemonError::ProtocolFailure)?
                    .canonical_sha256()
                    .bytes()
            || expected.backup_size != input_size
        {
            return Err(RescueVaultDaemonError::ProtocolFailure);
        }
        let bytes = read_exact_repair_input_pipe(
            input,
            input_size,
            expected.expected_backup_sha256,
            deadline,
        )?;
        let repair = internal_wire::WorkerRepairCommand::Persist {
            expected: Box::new(expected),
            binding: Box::new(internal_wire::WorkerRepairBinding::from_protocol(binding)),
            metadata,
            input_size,
        };
        self.transact_repair_input(repair, bytes.as_slice(), deadline)
    }

    #[cfg(feature = "experimental-repair-store")]
    pub(super) fn repair_backup_status(
        &self,
        expected: &RepairBackupStatusPayload,
        deadline: Instant,
    ) -> Result<internal_wire::WorkerResponse, RescueVaultDaemonError> {
        self.transact_repair_without_descriptor(
            internal_wire::WorkerRepairCommand::Status {
                expected: Box::new(
                    internal_wire::WorkerRepairStatus::from_protocol(expected)
                        .map_err(|_| RescueVaultDaemonError::ProtocolFailure)?,
                ),
            },
            deadline,
        )
    }

    #[cfg(feature = "experimental-repair-store")]
    pub(super) fn repair_backup_get(
        &self,
        expected: &RepairBackupStatusPayload,
        deadline: Instant,
    ) -> WorkerRepairGetResult {
        let expected_wire = internal_wire::WorkerRepairStatus::from_protocol(expected)
            .map_err(|_| RescueVaultDaemonError::ProtocolFailure)?;
        let (response, bytes) = self.transact_repair_output(
            internal_wire::WorkerRepairCommand::Get {
                expected: Box::new(expected_wire.clone()),
            },
            MAX_REPAIR_BACKUP_BYTES as usize,
            deadline,
        )?;
        match response.code {
            internal_wire::WorkerResultCode::RepairBackupReady => {
                let status = response
                    .repair_status
                    .as_deref()
                    .ok_or(RescueVaultDaemonError::ProtocolFailure)?;
                if !status.immutable_fields_match(&expected_wire)
                    || status.state != internal_wire::WorkerRepairState::Durable
                    || status.binding != expected_wire.binding
                    || usize::try_from(status.backup_size).ok() != Some(bytes.len())
                    || sha2::Sha256::digest(bytes.as_slice()).as_slice()
                        != status.expected_backup_sha256
                {
                    return Err(RescueVaultDaemonError::ProtocolFailure);
                }
                Ok((response, Some(bytes)))
            }
            _ if bytes.is_empty() => Ok((response, None)),
            _ => Err(RescueVaultDaemonError::ProtocolFailure),
        }
    }

    #[cfg(feature = "experimental-repair-store")]
    pub(super) fn repair_backup_cancel(
        &self,
        reservation_id: &RepairReservationId,
        draft_binding_sha256: &Sha256,
        deadline: Instant,
    ) -> Result<internal_wire::WorkerResponse, RescueVaultDaemonError> {
        self.transact_repair_without_descriptor(
            internal_wire::WorkerRepairCommand::Cancel {
                reservation_id: reservation_id.as_str().to_owned(),
                draft_binding_sha256: draft_binding_sha256.bytes(),
            },
            deadline,
        )
    }

    #[cfg(feature = "experimental-repair-store")]
    pub(super) fn repair_backup_retire(
        &self,
        expected: &RepairBackupStatusPayload,
        deadline: Instant,
    ) -> Result<internal_wire::WorkerResponse, RescueVaultDaemonError> {
        self.transact_repair_without_descriptor(
            internal_wire::WorkerRepairCommand::Retire {
                expected: Box::new(
                    internal_wire::WorkerRepairStatus::from_protocol(expected)
                        .map_err(|_| RescueVaultDaemonError::ProtocolFailure)?,
                ),
            },
            deadline,
        )
    }

    #[cfg(feature = "experimental-repair-store")]
    pub(super) fn repair_transaction_status(
        &self,
        selector: &RepairTransactionStatusSelector,
        deadline: Instant,
    ) -> Result<internal_wire::WorkerResponse, RescueVaultDaemonError> {
        self.transact_repair_without_descriptor(
            internal_wire::WorkerRepairCommand::TransactionStatus {
                selector: selector.clone(),
            },
            deadline,
        )
    }

    #[cfg(feature = "experimental-repair-store")]
    pub(super) fn repair_vault_live_identity(
        &self,
        deadline: Instant,
    ) -> Result<internal_wire::WorkerResponse, RescueVaultDaemonError> {
        self.transact_repair_without_descriptor(
            internal_wire::WorkerRepairCommand::VaultLiveParent,
            deadline,
        )
    }

    #[cfg(feature = "experimental-repair-store")]
    pub(super) fn repair_write_lease_consume(
        &self,
        selector: &RepairTransactionStatusSelector,
        deadline: Instant,
    ) -> Result<internal_wire::WorkerResponse, RescueVaultDaemonError> {
        self.transact_repair_without_descriptor(
            internal_wire::WorkerRepairCommand::WriteLeaseConsume {
                selector: selector.clone(),
            },
            deadline,
        )
    }

    #[cfg(feature = "experimental-repair-store")]
    pub(super) fn repair_transaction_resolve(
        &self,
        expected: &RepairTransactionStatusPayload,
        resolution: &RepairTransactionResolution,
        deadline: Instant,
    ) -> Result<internal_wire::WorkerResponse, RescueVaultDaemonError> {
        self.transact_repair_without_descriptor(
            internal_wire::WorkerRepairCommand::TransactionResolve {
                expected: Box::new(expected.clone()),
                resolution: resolution.clone(),
            },
            deadline,
        )
    }

    #[cfg(feature = "experimental-repair-store")]
    pub(super) fn repair_rollback_begin(
        &self,
        source: &RepairTransactionStatusPayload,
        rollback_id: &RepairRollbackId,
        binding: &RepairRollbackBindingV1,
        deadline: Instant,
    ) -> Result<internal_wire::WorkerResponse, RescueVaultDaemonError> {
        self.transact_repair_without_descriptor(
            internal_wire::WorkerRepairCommand::RollbackBegin {
                source: Box::new(source.clone()),
                rollback_id: rollback_id.clone(),
                binding: binding.clone(),
            },
            deadline,
        )
    }

    #[cfg(feature = "experimental-repair-store")]
    pub(super) fn repair_rollback_status(
        &self,
        selector: &RepairRollbackStatusSelector,
        deadline: Instant,
    ) -> Result<internal_wire::WorkerResponse, RescueVaultDaemonError> {
        self.transact_repair_without_descriptor(
            internal_wire::WorkerRepairCommand::RollbackStatus {
                selector: selector.clone(),
            },
            deadline,
        )
    }

    #[cfg(feature = "experimental-repair-store")]
    pub(super) fn repair_rollback_write_lease_consume(
        &self,
        selector: &RepairRollbackStatusSelector,
        deadline: Instant,
    ) -> Result<internal_wire::WorkerResponse, RescueVaultDaemonError> {
        self.transact_repair_without_descriptor(
            internal_wire::WorkerRepairCommand::RollbackWriteLeaseConsume {
                selector: selector.clone(),
            },
            deadline,
        )
    }

    #[cfg(feature = "experimental-repair-store")]
    pub(super) fn repair_rollback_resolve(
        &self,
        expected: &RepairRollbackTransactionStatusPayload,
        resolution: &RepairRollbackResolution,
        deadline: Instant,
    ) -> Result<internal_wire::WorkerResponse, RescueVaultDaemonError> {
        self.transact_repair_without_descriptor(
            internal_wire::WorkerRepairCommand::RollbackResolve {
                expected: Box::new(expected.clone()),
                resolution: resolution.clone(),
            },
            deadline,
        )
    }

    #[cfg(feature = "experimental-repair-store")]
    fn transact_repair_without_descriptor(
        &self,
        repair: internal_wire::WorkerRepairCommand,
        deadline: Instant,
    ) -> Result<internal_wire::WorkerResponse, RescueVaultDaemonError> {
        self.transact_inner(
            repair.kind(),
            None,
            None,
            deadline,
            WorkerTransactionContext {
                repair: Some(repair),
                ..WorkerTransactionContext::default()
            },
        )
        .and_then(|(response, output)| {
            if output.is_none() {
                Ok(response)
            } else {
                Err(RescueVaultDaemonError::ProtocolFailure)
            }
        })
    }

    #[cfg(feature = "experimental-repair-store")]
    fn transact_repair_input(
        &self,
        repair: internal_wire::WorkerRepairCommand,
        bytes: &[u8],
        deadline: Instant,
    ) -> Result<internal_wire::WorkerResponse, RescueVaultDaemonError> {
        if bytes.is_empty() || bytes.len() > MAX_REPAIR_BACKUP_BYTES as usize {
            return Err(RescueVaultDaemonError::ProtocolFailure);
        }
        let kind = repair.kind();
        let (read, write) =
            pipe_with(PipeFlags::CLOEXEC).map_err(|_| RescueVaultDaemonError::WorkerUnavailable)?;
        validate_runtime_repair_pipe_pair(read.as_fd(), write.as_fd())?;
        std::thread::scope(|scope| {
            let transaction = scope.spawn(move || {
                self.transact_inner(
                    kind,
                    None,
                    Some(read),
                    deadline,
                    WorkerTransactionContext {
                        repair: Some(repair),
                        ..WorkerTransactionContext::default()
                    },
                )
            });
            let write_result = write_exact_repair_source_pipe(write, bytes, deadline);
            let transaction = transaction
                .join()
                .map_err(|_| RescueVaultDaemonError::WorkerUnavailable)?;
            let (response, descriptor) = transaction?;
            if descriptor.is_some()
                || (write_result.is_err()
                    && response.code == internal_wire::WorkerResultCode::RepairBackupDurable)
            {
                return Err(RescueVaultDaemonError::ProtocolFailure);
            }
            Ok(response)
        })
    }

    #[cfg(feature = "experimental-repair-store")]
    fn transact_repair_output(
        &self,
        repair: internal_wire::WorkerRepairCommand,
        maximum: usize,
        deadline: Instant,
    ) -> Result<(internal_wire::WorkerResponse, Zeroizing<Vec<u8>>), RescueVaultDaemonError> {
        let kind = repair.kind();
        let (read, write) =
            pipe_with(PipeFlags::CLOEXEC).map_err(|_| RescueVaultDaemonError::WorkerUnavailable)?;
        std::thread::scope(|scope| {
            let transaction = scope.spawn(move || {
                self.transact_inner(
                    kind,
                    None,
                    Some(write),
                    deadline,
                    WorkerTransactionContext {
                        repair: Some(repair),
                        ..WorkerTransactionContext::default()
                    },
                )
            });
            let output = read_bounded_application_pipe(read, maximum, deadline);
            let transaction = transaction
                .join()
                .map_err(|_| RescueVaultDaemonError::WorkerUnavailable)?;
            let (response, descriptor) = transaction?;
            if descriptor.is_some() {
                return Err(RescueVaultDaemonError::ProtocolFailure);
            }
            Ok((response, output?))
        })
    }

    fn transact_application_output(
        &self,
        application: internal_wire::WorkerApplicationCommand,
        maximum: usize,
        deadline: Instant,
    ) -> Result<(internal_wire::WorkerResponse, Zeroizing<Vec<u8>>), RescueVaultDaemonError> {
        let kind = application.kind();
        let (read, write) =
            pipe_with(PipeFlags::CLOEXEC).map_err(|_| RescueVaultDaemonError::WorkerUnavailable)?;
        std::thread::scope(|scope| {
            let transaction = scope.spawn(move || {
                self.transact_inner(
                    kind,
                    None,
                    Some(write),
                    deadline,
                    WorkerTransactionContext {
                        application: Some(application),
                        ..WorkerTransactionContext::default()
                    },
                )
            });
            let output = read_bounded_application_pipe(read, maximum, deadline);
            let transaction = transaction
                .join()
                .map_err(|_| RescueVaultDaemonError::WorkerUnavailable)?;
            let (response, descriptor) = transaction?;
            if descriptor.is_some() {
                return Err(RescueVaultDaemonError::ProtocolFailure);
            }
            Ok((response, output?))
        })
    }

    fn transact_inner(
        &self,
        kind: internal_wire::WorkerCommandKind,
        secret_size: Option<u16>,
        descriptor: Option<OwnedFd>,
        deadline: Instant,
        context: WorkerTransactionContext<'_>,
    ) -> Result<(internal_wire::WorkerResponse, Option<OwnedFd>), RescueVaultDaemonError> {
        let WorkerTransactionContext {
            cancellation,
            provider_output,
            application,
            #[cfg(feature = "experimental-repair-store")]
            repair,
        } = context;
        let borrowing = kind == internal_wire::WorkerCommandKind::ProviderOpenAiBorrow;
        #[cfg(feature = "experimental-codex-home-lease")]
        let leasing_codex = kind == internal_wire::WorkerCommandKind::ProviderCodexHomeLease;
        #[cfg(not(feature = "experimental-codex-home-lease"))]
        let leasing_codex = false;
        if borrowing != provider_output.is_some()
            || ((borrowing || leasing_codex) && cancellation.is_some())
            || application
                .as_ref()
                .is_some_and(|application| application.kind() != kind)
        {
            return Err(RescueVaultDaemonError::ProtocolFailure);
        }
        #[cfg(feature = "experimental-repair-store")]
        if repair.as_ref().is_some_and(|repair| repair.kind() != kind) {
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
        #[cfg(feature = "experimental-repair-store")]
        if application.is_some() && repair.is_some() {
            return Err(RescueVaultDaemonError::ProtocolFailure);
        }
        #[cfg(feature = "experimental-repair-store")]
        let repair_payload = repair;
        #[cfg(not(feature = "experimental-repair-store"))]
        let repair_payload: Option<()> = None;
        let (command, outgoing) = match (kind, secret_size, descriptor, application, repair_payload)
        {
            #[cfg(feature = "experimental-repair-store")]
            (kind, None, descriptor, None, Some(repair)) if kind == repair.kind() => (
                internal_wire::WorkerCommand::repair(request_id, repair),
                descriptor,
            ),
            (kind, None, descriptor, Some(application), None) if kind == application.kind() => (
                internal_wire::WorkerCommand::application(request_id, application),
                descriptor,
            ),
            (internal_wire::WorkerCommandKind::Bootstrap, _, _, _, _) => {
                return Err(RescueVaultDaemonError::ProtocolFailure);
            }
            (internal_wire::WorkerCommandKind::Probe, None, None, None, None) => {
                (internal_wire::WorkerCommand::probe(request_id), None)
            }
            (
                internal_wire::WorkerCommandKind::Unlock,
                Some(size),
                Some(descriptor),
                None,
                None,
            ) => (
                internal_wire::WorkerCommand::unlock(request_id, size),
                Some(descriptor),
            ),
            (internal_wire::WorkerCommandKind::Lock, None, None, None, None) => {
                (internal_wire::WorkerCommand::lock(request_id), None)
            }
            (internal_wire::WorkerCommandKind::ProviderStatus, None, None, None, None) => (
                internal_wire::WorkerCommand::provider_status(request_id),
                None,
            ),
            (
                internal_wire::WorkerCommandKind::ProviderOpenAiConfigure,
                Some(size),
                Some(descriptor),
                None,
                None,
            ) => (
                internal_wire::WorkerCommand::provider_openai_configure(request_id, size),
                Some(descriptor),
            ),
            (internal_wire::WorkerCommandKind::ProviderOpenAiLogout, None, None, None, None) => (
                internal_wire::WorkerCommand::provider_openai_logout(request_id),
                None,
            ),
            (
                internal_wire::WorkerCommandKind::ProviderOpenAiBorrow,
                None,
                Some(descriptor),
                None,
                None,
            ) => (
                internal_wire::WorkerCommand::provider_openai_borrow(request_id),
                Some(descriptor),
            ),
            #[cfg(feature = "experimental-codex-home-lease")]
            (internal_wire::WorkerCommandKind::ProviderCodexHomeLease, None, None, None, None) => (
                internal_wire::WorkerCommand::provider_codex_home_lease(request_id),
                None,
            ),
            (internal_wire::WorkerCommandKind::AttestQuiescent, None, None, None, None) => (
                internal_wire::WorkerCommand::attest_quiescent(request_id),
                None,
            ),
            (internal_wire::WorkerCommandKind::Shutdown, None, None, None, None) => {
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
        let (response, received_output) = loop {
            if cancellation.is_some_and(|cancelled| cancelled.load(Ordering::Acquire)) {
                return Err(RescueVaultDaemonError::WorkerUnavailable);
            }
            let now = Instant::now();
            let slice = now
                .checked_add(Duration::from_millis(200))
                .unwrap_or(deadline)
                .min(deadline);
            #[cfg(feature = "experimental-codex-home-lease")]
            let received = if leasing_codex {
                internal_wire::receive_codex_home_response(
                    channel.socket.as_fd(),
                    request_id,
                    slice,
                )
            } else {
                internal_wire::receive_response(channel.socket.as_fd(), request_id, slice)
                    .map(|response| (response, None))
            };
            #[cfg(not(feature = "experimental-codex-home-lease"))]
            let received =
                internal_wire::receive_response(channel.socket.as_fd(), request_id, slice)
                    .map(|response| (response, None));
            match received {
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
            None => received_output,
        };
        #[cfg(feature = "experimental-codex-home-lease")]
        if leasing_codex
            && ((response.code == internal_wire::WorkerResultCode::ProviderCodexHomeReady)
                != output.is_some())
        {
            return Err(RescueVaultDaemonError::ProtocolFailure);
        }
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

fn read_bounded_application_pipe(
    descriptor: OwnedFd,
    maximum: usize,
    deadline: Instant,
) -> Result<Zeroizing<Vec<u8>>, RescueVaultDaemonError> {
    let stat = rfs::fstat(&descriptor).map_err(|_| RescueVaultDaemonError::WorkerUnavailable)?;
    let filesystem =
        rfs::fstatfs(&descriptor).map_err(|_| RescueVaultDaemonError::WorkerUnavailable)?;
    let filesystem_type =
        u64::try_from(filesystem.f_type).map_err(|_| RescueVaultDaemonError::WorkerUnavailable)?;
    let flags = rustix::io::fcntl_getfd(&descriptor)
        .map_err(|_| RescueVaultDaemonError::WorkerUnavailable)?;
    let status =
        rfs::fcntl_getfl(&descriptor).map_err(|_| RescueVaultDaemonError::WorkerUnavailable)?;
    #[cfg(feature = "experimental-repair-store")]
    let maximum_allowed =
        (MAX_REPAIR_BACKUP_BYTES as usize).max(MAX_SIGNED_REPORT_ENVELOPE_BYTES as usize);
    #[cfg(not(feature = "experimental-repair-store"))]
    let maximum_allowed = MAX_SIGNED_REPORT_ENVELOPE_BYTES as usize;
    if maximum > maximum_allowed
        || !FileType::from_raw_mode(stat.st_mode).is_fifo()
        || filesystem_type != PIPEFS_MAGIC
        || status != OFlags::RDONLY
        || flags != rustix::io::FdFlags::CLOEXEC
        || stat.st_size != 0
    {
        return Err(RescueVaultDaemonError::ProtocolFailure);
    }
    rfs::fcntl_setfl(&descriptor, OFlags::RDONLY | OFlags::NONBLOCK)
        .map_err(|_| RescueVaultDaemonError::WorkerUnavailable)?;
    let mut output = Zeroizing::new(Vec::new());
    loop {
        if Instant::now() >= deadline {
            return Err(RescueVaultDaemonError::WorkerUnavailable);
        }
        let mut chunk = Zeroizing::new([0_u8; 8192]);
        match rustix::io::read(&descriptor, &mut chunk[..]) {
            Ok(0) => return Ok(output),
            Ok(read) => {
                if output.len().saturating_add(read) > maximum {
                    return Err(RescueVaultDaemonError::ProtocolFailure);
                }
                output.extend_from_slice(&chunk[..read]);
            }
            Err(error) if error == rustix::io::Errno::INTR => {}
            Err(error) if error == rustix::io::Errno::AGAIN => {
                let remaining = deadline
                    .checked_duration_since(Instant::now())
                    .ok_or(RescueVaultDaemonError::WorkerUnavailable)?;
                let mut descriptors = [PollFd::from_borrowed_fd(
                    descriptor.as_fd(),
                    PollFlags::IN | PollFlags::HUP,
                )];
                match poll(&mut descriptors, Some(&duration_to_timespec(remaining))) {
                    Ok(0) => return Err(RescueVaultDaemonError::WorkerUnavailable),
                    Ok(_) if descriptors[0].revents().contains(PollFlags::NVAL) => {
                        return Err(RescueVaultDaemonError::ProtocolFailure);
                    }
                    Ok(_) => {}
                    Err(error) if error == rustix::io::Errno::INTR => {}
                    Err(_) => return Err(RescueVaultDaemonError::WorkerUnavailable),
                }
            }
            Err(_) => return Err(RescueVaultDaemonError::WorkerUnavailable),
        }
    }
}

#[cfg(feature = "experimental-repair-store")]
fn read_exact_repair_input_pipe(
    descriptor: OwnedFd,
    expected_size: u64,
    expected_sha256: [u8; 32],
    deadline: Instant,
) -> Result<Zeroizing<Vec<u8>>, RescueVaultDaemonError> {
    let expected = usize::try_from(expected_size)
        .ok()
        .filter(|size| (1..=MAX_REPAIR_BACKUP_BYTES as usize).contains(size))
        .ok_or(RescueVaultDaemonError::ProtocolFailure)?;
    let stat = rfs::fstat(&descriptor).map_err(|_| RescueVaultDaemonError::ProtocolFailure)?;
    let filesystem =
        rfs::fstatfs(&descriptor).map_err(|_| RescueVaultDaemonError::ProtocolFailure)?;
    let status =
        rfs::fcntl_getfl(&descriptor).map_err(|_| RescueVaultDaemonError::ProtocolFailure)?;
    let flags = rustix::io::fcntl_getfd(&descriptor)
        .map_err(|_| RescueVaultDaemonError::ProtocolFailure)?;
    if !FileType::from_raw_mode(stat.st_mode).is_fifo()
        || u64::try_from(filesystem.f_type).ok() != Some(PIPEFS_MAGIC)
        || status & OFlags::ACCMODE != OFlags::RDONLY
        || flags != rustix::io::FdFlags::CLOEXEC
        || stat.st_size != 0
    {
        return Err(RescueVaultDaemonError::ProtocolFailure);
    }
    rfs::fcntl_setfl(&descriptor, OFlags::RDONLY | OFlags::NONBLOCK)
        .map_err(|_| RescueVaultDaemonError::WorkerUnavailable)?;
    let mut output = Zeroizing::new(Vec::with_capacity(expected));
    while output.len() < expected {
        if Instant::now() >= deadline {
            return Err(RescueVaultDaemonError::WorkerUnavailable);
        }
        let mut chunk = Zeroizing::new([0_u8; 8192]);
        let wanted = (expected - output.len()).min(chunk.len());
        match rustix::io::read(&descriptor, &mut chunk[..wanted]) {
            Ok(0) => return Err(RescueVaultDaemonError::ProtocolFailure),
            Ok(read) => output.extend_from_slice(&chunk[..read]),
            Err(error) if error == rustix::io::Errno::INTR => {}
            Err(error) if error == rustix::io::Errno::AGAIN => {
                wait_runtime_pipe(descriptor.as_fd(), PollFlags::IN, deadline)?;
            }
            Err(_) => return Err(RescueVaultDaemonError::ProtocolFailure),
        }
    }
    loop {
        if Instant::now() >= deadline {
            return Err(RescueVaultDaemonError::WorkerUnavailable);
        }
        let mut extra = Zeroizing::new([0_u8; 1]);
        match rustix::io::read(&descriptor, &mut extra[..]) {
            Ok(0) => break,
            Ok(_) => return Err(RescueVaultDaemonError::ProtocolFailure),
            Err(error) if error == rustix::io::Errno::INTR => {}
            Err(error) if error == rustix::io::Errno::AGAIN => {
                wait_runtime_pipe(descriptor.as_fd(), PollFlags::IN | PollFlags::HUP, deadline)?;
            }
            Err(_) => return Err(RescueVaultDaemonError::ProtocolFailure),
        }
    }
    if sha2::Sha256::digest(output.as_slice()).as_slice() != expected_sha256 {
        return Err(RescueVaultDaemonError::ProtocolFailure);
    }
    Ok(output)
}

#[cfg(feature = "experimental-repair-store")]
fn wait_runtime_pipe(
    descriptor: BorrowedFd<'_>,
    interest: PollFlags,
    deadline: Instant,
) -> Result<(), RescueVaultDaemonError> {
    let remaining = deadline
        .checked_duration_since(Instant::now())
        .filter(|remaining| !remaining.is_zero())
        .ok_or(RescueVaultDaemonError::WorkerUnavailable)?;
    let mut descriptors = [PollFd::from_borrowed_fd(descriptor, interest)];
    match poll(&mut descriptors, Some(&duration_to_timespec(remaining))) {
        Ok(0) => Err(RescueVaultDaemonError::WorkerUnavailable),
        Ok(_)
            if descriptors[0]
                .revents()
                .intersects(PollFlags::NVAL | PollFlags::ERR) =>
        {
            Err(RescueVaultDaemonError::ProtocolFailure)
        }
        Ok(_) => Ok(()),
        Err(error) if error == rustix::io::Errno::INTR => Ok(()),
        Err(_) => Err(RescueVaultDaemonError::WorkerUnavailable),
    }
}

#[cfg(feature = "experimental-repair-store")]
fn validate_runtime_repair_pipe_pair(
    read: BorrowedFd<'_>,
    write: BorrowedFd<'_>,
) -> Result<(), RescueVaultDaemonError> {
    let read_stat = rfs::fstat(read).map_err(|_| RescueVaultDaemonError::WorkerUnavailable)?;
    let write_stat = rfs::fstat(write).map_err(|_| RescueVaultDaemonError::WorkerUnavailable)?;
    let filesystem = rfs::fstatfs(read).map_err(|_| RescueVaultDaemonError::WorkerUnavailable)?;
    let read_status =
        rfs::fcntl_getfl(read).map_err(|_| RescueVaultDaemonError::WorkerUnavailable)?;
    let write_status =
        rfs::fcntl_getfl(write).map_err(|_| RescueVaultDaemonError::WorkerUnavailable)?;
    let read_flags =
        rustix::io::fcntl_getfd(read).map_err(|_| RescueVaultDaemonError::WorkerUnavailable)?;
    let write_flags =
        rustix::io::fcntl_getfd(write).map_err(|_| RescueVaultDaemonError::WorkerUnavailable)?;
    if !FileType::from_raw_mode(read_stat.st_mode).is_fifo()
        || !FileType::from_raw_mode(write_stat.st_mode).is_fifo()
        || read_stat.st_dev != write_stat.st_dev
        || read_stat.st_ino != write_stat.st_ino
        || read_stat.st_size != 0
        || write_stat.st_size != 0
        || u64::try_from(filesystem.f_type).ok() != Some(PIPEFS_MAGIC)
        || read_status & OFlags::ACCMODE != OFlags::RDONLY
        || write_status & OFlags::ACCMODE != OFlags::WRONLY
        || read_flags != rustix::io::FdFlags::CLOEXEC
        || write_flags != rustix::io::FdFlags::CLOEXEC
    {
        return Err(RescueVaultDaemonError::ProtocolFailure);
    }
    Ok(())
}

#[cfg(feature = "experimental-repair-store")]
fn write_exact_repair_source_pipe(
    descriptor: OwnedFd,
    bytes: &[u8],
    deadline: Instant,
) -> Result<(), RescueVaultDaemonError> {
    let status =
        rfs::fcntl_getfl(&descriptor).map_err(|_| RescueVaultDaemonError::WorkerUnavailable)?;
    if status & OFlags::ACCMODE != OFlags::WRONLY {
        return Err(RescueVaultDaemonError::ProtocolFailure);
    }
    rfs::fcntl_setfl(&descriptor, status | OFlags::NONBLOCK)
        .map_err(|_| RescueVaultDaemonError::WorkerUnavailable)?;
    let mut written = 0_usize;
    while written < bytes.len() {
        if Instant::now() >= deadline {
            return Err(RescueVaultDaemonError::WorkerUnavailable);
        }
        match rustix::io::write(&descriptor, &bytes[written..]) {
            Ok(0) => return Err(RescueVaultDaemonError::ProtocolFailure),
            Ok(count) => {
                written = written
                    .checked_add(count)
                    .ok_or(RescueVaultDaemonError::ProtocolFailure)?
            }
            Err(error) if error == rustix::io::Errno::INTR => {}
            Err(error) if error == rustix::io::Errno::AGAIN => {
                wait_runtime_pipe(descriptor.as_fd(), PollFlags::OUT, deadline)?;
            }
            Err(error) if error == rustix::io::Errno::PIPE => {
                return Err(RescueVaultDaemonError::ProtocolFailure);
            }
            Err(_) => return Err(RescueVaultDaemonError::WorkerUnavailable),
        }
    }
    Ok(())
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
        Command::AuditAppend => matches!(
            response.code,
            Result::ApplicationAuditAppended
                | Result::ApplicationInvalidRequest
                | Result::ApplicationStaleSequence
                | Result::ApplicationMutationAborted
                | Result::ApplicationStateAmbiguous
                | Result::CleanupFailed
                | Result::Busy
        ),
        Command::ReportPersist => matches!(
            response.code,
            Result::ApplicationReportPersisted
                | Result::ApplicationInvalidRequest
                | Result::ApplicationReportTooLarge
                | Result::ApplicationMutationAborted
                | Result::ApplicationStateAmbiguous
                | Result::CleanupFailed
                | Result::Busy
        ),
        Command::ReportList => matches!(
            response.code,
            Result::ApplicationReportListReady
                | Result::ApplicationStateAmbiguous
                | Result::IoFailed
                | Result::CleanupFailed
                | Result::Busy
        ),
        Command::ReportGet => matches!(
            response.code,
            Result::ApplicationReportReady
                | Result::ApplicationReportNotFound
                | Result::ApplicationStateAmbiguous
                | Result::IoFailed
                | Result::CleanupFailed
                | Result::Busy
        ),
        #[cfg(feature = "experimental-repair-store")]
        Command::RepairBackupReserve => matches!(
            response.code,
            Result::RepairBackupReserved
                | Result::RepairInvalidRequest
                | Result::RepairConflict
                | Result::RepairReconciliationRequired
                | Result::RepairStorageUnavailable
                | Result::CleanupFailed
                | Result::Busy
        ),
        #[cfg(feature = "experimental-repair-store")]
        Command::RepairBackupPersist => matches!(
            response.code,
            Result::RepairBackupDurable
                | Result::RepairInvalidRequest
                | Result::RepairConflict
                | Result::RepairReconciliationRequired
                | Result::RepairStorageUnavailable
                | Result::CleanupFailed
                | Result::Busy
        ),
        #[cfg(feature = "experimental-repair-store")]
        Command::RepairBackupStatus => matches!(
            response.code,
            Result::RepairBackupStatusReady
                | Result::RepairBackupNotFound
                | Result::RepairInvalidRequest
                | Result::RepairConflict
                | Result::RepairReconciliationRequired
                | Result::RepairStorageUnavailable
                | Result::CleanupFailed
                | Result::Busy
        ),
        #[cfg(feature = "experimental-repair-store")]
        Command::RepairBackupGet => matches!(
            response.code,
            Result::RepairBackupReady
                | Result::RepairBackupNotFound
                | Result::RepairInvalidRequest
                | Result::RepairConflict
                | Result::RepairReconciliationRequired
                | Result::RepairStorageUnavailable
                | Result::IoFailed
                | Result::CleanupFailed
                | Result::Busy
        ),
        #[cfg(feature = "experimental-repair-store")]
        Command::RepairBackupCancel => matches!(
            response.code,
            Result::RepairBackupCancelled
                | Result::RepairBackupNotFound
                | Result::RepairInvalidRequest
                | Result::RepairConflict
                | Result::RepairReconciliationRequired
                | Result::RepairStorageUnavailable
                | Result::CleanupFailed
                | Result::Busy
        ),
        #[cfg(feature = "experimental-repair-store")]
        Command::RepairBackupRetire => matches!(
            response.code,
            Result::RepairBackupRetired
                | Result::RepairBackupNotFound
                | Result::RepairInvalidRequest
                | Result::RepairConflict
                | Result::RepairReconciliationRequired
                | Result::RepairStorageUnavailable
                | Result::CleanupFailed
                | Result::Busy
        ),
        #[cfg(feature = "experimental-repair-store")]
        Command::RepairTransactionStatus => matches!(
            response.code,
            Result::RepairTransactionStatusReady
                | Result::RepairBackupNotFound
                | Result::RepairInvalidRequest
                | Result::RepairConflict
                | Result::RepairReconciliationRequired
                | Result::RepairStorageUnavailable
                | Result::CleanupFailed
                | Result::Busy
        ),
        #[cfg(feature = "experimental-repair-store")]
        Command::RepairVaultLiveParent => matches!(
            response.code,
            Result::RepairVaultLiveIdentityReady
                | Result::RepairInvalidRequest
                | Result::RepairReconciliationRequired
                | Result::RepairStorageUnavailable
                | Result::CleanupFailed
                | Result::Busy
        ),
        #[cfg(feature = "experimental-repair-store")]
        Command::RepairTransactionWriteLeaseConsume => matches!(
            response.code,
            Result::RepairWriteLeaseConsumed
                | Result::RepairBackupNotFound
                | Result::RepairInvalidRequest
                | Result::RepairConflict
                | Result::RepairReconciliationRequired
                | Result::RepairStorageUnavailable
                | Result::CleanupFailed
                | Result::Busy
        ),
        #[cfg(feature = "experimental-repair-store")]
        Command::RepairTransactionResolve => matches!(
            response.code,
            Result::RepairTransactionResolved
                | Result::RepairBackupNotFound
                | Result::RepairInvalidRequest
                | Result::RepairConflict
                | Result::RepairReconciliationRequired
                | Result::RepairStorageUnavailable
                | Result::CleanupFailed
                | Result::Busy
        ),
        #[cfg(feature = "experimental-repair-store")]
        Command::RepairRollbackBegin => matches!(
            response.code,
            Result::RepairRollbackBegun
                | Result::RepairBackupNotFound
                | Result::RepairInvalidRequest
                | Result::RepairConflict
                | Result::RepairReconciliationRequired
                | Result::RepairStorageUnavailable
                | Result::CleanupFailed
                | Result::Busy
        ),
        #[cfg(feature = "experimental-repair-store")]
        Command::RepairRollbackStatus => matches!(
            response.code,
            Result::RepairRollbackStatusReady
                | Result::RepairBackupNotFound
                | Result::RepairInvalidRequest
                | Result::RepairConflict
                | Result::RepairReconciliationRequired
                | Result::RepairStorageUnavailable
                | Result::CleanupFailed
                | Result::Busy
        ),
        #[cfg(feature = "experimental-repair-store")]
        Command::RepairRollbackWriteLeaseConsume => matches!(
            response.code,
            Result::RepairRollbackWriteLeaseConsumed
                | Result::RepairBackupNotFound
                | Result::RepairInvalidRequest
                | Result::RepairConflict
                | Result::RepairReconciliationRequired
                | Result::RepairStorageUnavailable
                | Result::CleanupFailed
                | Result::Busy
        ),
        #[cfg(feature = "experimental-repair-store")]
        Command::RepairRollbackResolve => matches!(
            response.code,
            Result::RepairRollbackResolved
                | Result::RepairBackupNotFound
                | Result::RepairInvalidRequest
                | Result::RepairConflict
                | Result::RepairReconciliationRequired
                | Result::RepairStorageUnavailable
                | Result::CleanupFailed
                | Result::Busy
        ),
        #[cfg(feature = "experimental-codex-home-lease")]
        Command::ProviderCodexHomeLease => matches!(
            response.code,
            Result::ProviderCodexHomeReady
                | Result::ProviderCodexHomeUnconfigured
                | Result::ProviderStateAmbiguous
                | Result::InvalidRequest
                | Result::CleanupFailed
                | Result::Busy
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
    fn provider_membership_is_terminal_agent_in_one_exact_service_unit() {
        let production = parse_provider_membership(
            b"0::/system.slice/kernaid-rescue-openai-executor@4-123.service/agent\n",
        )
        .expect("production membership");
        assert_eq!(production.kind, ProviderUnitKind::OpenAiExecutor);
        assert_eq!(
            production.unit,
            OsString::from("kernaid-rescue-openai-executor@4-123.service")
        );
        let probe = parse_provider_membership(
            b"0::/system.slice/kernaid-provider-lease-probe@1-foo\\x2dbar.service/agent\n",
        )
        .expect("probe membership");
        assert_eq!(probe.kind, ProviderUnitKind::LeaseProbe);
        #[cfg(feature = "experimental-codex-home-lease")]
        {
            let codex = parse_provider_membership(
                b"0::/system.slice/kernaid-rescue-codex@7-auth.service/agent\n",
            )
            .expect("Codex membership");
            assert_eq!(codex.kind, ProviderUnitKind::CodexExecutor);
            assert_eq!(
                codex.unit,
                OsString::from("kernaid-rescue-codex@7-auth.service")
            );
        }

        for invalid in [
            b"0::/system.slice/kernaid-rescue-openai-executor@4.service\n".as_slice(),
            b"0::/system.slice/kernaid-rescue-openai-executor@4.service/agent/nested\n",
            b"0::/system.slice/kernaid-rescue-openai-executor@.service/agent\n",
            b"0::/system.slice/system-kernaid\\x2drescue\\x2dopenai\\x2dexecutor.slice/kernaid-rescue-openai-executor@4.service/agent\n",
            b"0::/user.slice/kernaid-rescue-openai-executor@4.service/agent\n",
            b"0::/system.slice/unrelated@4.service/agent\n",
            b"0::/system.slice/kernaid-rescue-openai-executor@4.service/agent\n0::/other\n",
            b"1:name=/system.slice/kernaid-rescue-openai-executor@4.service/agent\n",
        ] {
            assert_eq!(
                parse_provider_membership(invalid).err(),
                Some(RescueVaultDaemonError::CgroupUnavailable)
            );
        }
    }

    #[cfg(not(feature = "experimental-codex-home-lease"))]
    #[test]
    fn feature_off_rejects_codex_cgroup_membership() {
        assert_eq!(
            parse_provider_membership(
                b"0::/system.slice/kernaid-rescue-codex@7-auth.service/agent\n"
            )
            .err(),
            Some(RescueVaultDaemonError::CgroupUnavailable)
        );
    }

    #[test]
    fn provider_mount_access_requires_one_same_device_cgroup2_mount() {
        let device = rfs::makedev(0, 28);
        let peer =
            b"36 25 0:28 / /sys/fs/cgroup ro,nosuid,nodev,noexec,relatime - cgroup2 cgroup2 rw\n";
        let daemon =
            b"36 25 0:28 / /sys/fs/cgroup rw,nosuid,nodev,noexec,relatime - cgroup2 cgroup2 rw\n";
        assert_eq!(
            mountinfo_has_exact_cgroup2_access(peer, device, false),
            Ok(true)
        );
        assert_eq!(
            mountinfo_has_exact_cgroup2_access(daemon, device, true),
            Ok(true)
        );
        assert_eq!(
            mountinfo_has_exact_cgroup2_access(peer, device, true),
            Ok(false)
        );
        assert_eq!(
            mountinfo_has_exact_cgroup2_access(daemon, device, false),
            Ok(false)
        );
        for invalid in [
            b"36 25 0:29 / /sys/fs/cgroup ro - cgroup2 cgroup2 rw\n".as_slice(),
            b"36 25 0:28 / /other ro - cgroup2 cgroup2 rw\n",
            b"36 25 0:28 / /sys/fs/cgroup ro,rw - cgroup2 cgroup2 rw\n",
            b"36 25 0:28 / /sys/fs/cgroup ro - cgroup2 cgroup2 rw\n37 25 0:28 / /other ro - cgroup2 cgroup2 rw\n",
            b"36 25 0:28 / /sys/fs/cgroup ro - cgroup2 cgroup2 rw\n37 36 0:28 /system.slice/kernaid-rescue-openai-executor@1.service/memory.pressure /sys/fs/cgroup/system.slice/kernaid-rescue-openai-executor@1.service/memory.pressure rw,nosuid,nodev,noexec - cgroup2 cgroup2 rw\n",
        ] {
            assert_eq!(
                mountinfo_has_exact_cgroup2_access(invalid, device, false),
                Ok(false)
            );
        }
        assert_eq!(
            mountinfo_has_exact_cgroup2_access(
                b"36 25 0:28 / /sys/fs/cgroup ro,ro - cgroup2 cgroup2 rw\n",
                device,
                false,
            ),
            Err(RescueVaultDaemonError::CgroupUnavailable)
        );
    }

    #[test]
    fn provider_tree_terminal_states_are_closed_four_factor_evidence() {
        assert_eq!(
            parse_cgroup_events_populated(b"populated 0\nfrozen 0\n"),
            Ok(false)
        );
        assert_eq!(parse_cgroup_events_populated(b"populated 1\n"), Ok(true));
        for invalid in [
            b"".as_slice(),
            b"populated 0",
            b"populated 2\n",
            b"populated 0\npopulated 1\n",
            b"other 0\n",
        ] {
            assert_eq!(
                parse_cgroup_events_populated(invalid),
                Err(RescueVaultDaemonError::CgroupUnavailable)
            );
        }

        assert!(garbage_collection_evidence_is_terminal(true, true, true));
        for incomplete in [
            (false, true, true),
            (true, false, true),
            (true, true, false),
            (false, false, false),
        ] {
            assert!(!garbage_collection_evidence_is_terminal(
                incomplete.0,
                incomplete.1,
                incomplete.2
            ));
        }

        assert_eq!(
            classify_topology_race(RetainedPopulationState::Empty, false),
            Ok(true),
            "a second populated=0 read closes the systemd trim race"
        );
        for population in [
            RetainedPopulationState::Populated,
            RetainedPopulationState::Gone,
        ] {
            assert_eq!(
                classify_topology_race(population, true),
                Ok(true),
                "a live/ENODEV descriptor requires the full GC proof"
            );
            assert_eq!(
                classify_topology_race(population, false),
                Err(RescueVaultDaemonError::CgroupUnavailable),
                "partial topology without terminal proof stays fail-closed"
            );
        }
    }

    #[test]
    fn provider_unit_topology_and_root_kill_ownership_are_exact() {
        assert!(provider_child_directories_are_exact(
            ProviderUnitKind::OpenAiExecutor,
            &[PROVIDER_AGENT_CGROUP_NAME]
        ));
        #[cfg(feature = "experimental-codex-home-lease")]
        assert!(provider_child_directories_are_exact(
            ProviderUnitKind::CodexExecutor,
            &[PROVIDER_AGENT_CGROUP_NAME]
        ));
        assert!(provider_child_directories_are_exact(
            ProviderUnitKind::LeaseProbe,
            &[PROVIDER_CONTROL_CGROUP_NAME, PROVIDER_AGENT_CGROUP_NAME]
        ));
        assert!(!provider_child_directories_are_exact(
            ProviderUnitKind::OpenAiExecutor,
            &[PROVIDER_CONTROL_CGROUP_NAME, PROVIDER_AGENT_CGROUP_NAME]
        ));
        assert!(!provider_child_directories_are_exact(
            ProviderUnitKind::LeaseProbe,
            &[PROVIDER_AGENT_CGROUP_NAME]
        ));
        assert!(provider_control_is_empty(&[], 0, false));
        assert!(!provider_control_is_empty(&[41], 0, true));
        assert!(!provider_control_is_empty(&[], 1, false));
        assert_eq!(
            PROVIDER_UNIT_ROOT_AGENT_CONTROLS,
            [
                ("cgroup.procs", 0o644),
                ("cgroup.subtree_control", 0o644),
                ("cgroup.threads", 0o644),
            ]
        );
        assert_eq!(
            PROVIDER_SUBGROUP_AGENT_CONTROLS,
            [
                ("cgroup.procs", 0o644),
                ("cgroup.events", 0o444),
                ("cgroup.kill", 0o200),
                ("cgroup.stat", 0o444),
            ]
        );

        let device = rfs::makedev(0, 28);
        let peer = (1000, 1000);
        assert!(provider_delegated_directory_metadata_is_exact(
            FileType::from_raw_mode(0o040_755),
            peer,
            peer,
            (device, device),
            0o040_755,
            Some(CGROUP2_SUPER_MAGIC),
            true,
        ));
        for invalid_owner in [(0, 0), (0, 1000), (1000, 0), (1001, 1000)] {
            assert!(!provider_delegated_directory_metadata_is_exact(
                FileType::from_raw_mode(0o040_755),
                invalid_owner,
                peer,
                (device, device),
                0o040_755,
                Some(CGROUP2_SUPER_MAGIC),
                true,
            ));
        }
        assert!(!provider_delegated_directory_metadata_is_exact(
            FileType::from_raw_mode(0o040_755),
            peer,
            peer,
            (device, device),
            0o040_775,
            Some(CGROUP2_SUPER_MAGIC),
            true,
        ));
        for (file_type, devices, filesystem, cloexec) in [
            (
                FileType::RegularFile,
                (device, device),
                Some(CGROUP2_SUPER_MAGIC),
                true,
            ),
            (
                FileType::from_raw_mode(0o040_755),
                (rfs::makedev(0, 29), device),
                Some(CGROUP2_SUPER_MAGIC),
                true,
            ),
            (
                FileType::from_raw_mode(0o040_755),
                (device, device),
                Some(PROC_SUPER_MAGIC),
                true,
            ),
            (
                FileType::from_raw_mode(0o040_755),
                (device, device),
                Some(CGROUP2_SUPER_MAGIC),
                false,
            ),
        ] {
            assert!(!provider_delegated_directory_metadata_is_exact(
                file_type, peer, peer, devices, 0o040_755, filesystem, cloexec,
            ));
        }

        assert!(provider_delegated_control_metadata_is_exact(
            FileType::RegularFile,
            peer,
            peer,
            (device, device),
            0o100_644,
            0o644,
        ));
        for invalid_owner in [(0, 0), (0, 1000), (1000, 0), (1001, 1000)] {
            assert!(!provider_delegated_control_metadata_is_exact(
                FileType::RegularFile,
                invalid_owner,
                peer,
                (device, device),
                0o100_644,
                0o644,
            ));
        }
        assert!(!provider_delegated_control_metadata_is_exact(
            FileType::RegularFile,
            peer,
            peer,
            (device, device),
            0o100_600,
            0o644,
        ));
        assert!(!provider_delegated_control_metadata_is_exact(
            FileType::RegularFile,
            peer,
            peer,
            (rfs::makedev(0, 29), device),
            0o100_644,
            0o644,
        ));

        assert!(provider_root_control_metadata_is_exact(
            FileType::RegularFile,
            0,
            0,
            device,
            device,
            0o100_200,
            0o200,
        ));
        assert!(provider_root_control_metadata_is_exact(
            FileType::RegularFile,
            0,
            0,
            device,
            device,
            0o100_444,
            0o444,
        ));
        assert!(!provider_root_control_metadata_is_exact(
            FileType::RegularFile,
            0,
            0,
            device,
            device,
            0o100_400,
            0o444,
        ));
        for invalid in [
            (1000, 0, device, device, 0o100_200),
            (0, 1000, device, device, 0o100_200),
            (0, 0, rfs::makedev(0, 29), device, 0o100_200),
            (0, 0, device, device, 0o100_000),
            (0, 0, device, device, 0o100_220),
        ] {
            assert!(!provider_root_control_metadata_is_exact(
                FileType::RegularFile,
                invalid.0,
                invalid.1,
                invalid.2,
                invalid.3,
                invalid.4,
                0o200,
            ));
        }
    }

    #[test]
    fn systemd_257_bootstrap_inheritable_subset_is_normalizable() {
        let expected = CapabilitySet::SYS_ADMIN
            .union(CapabilitySet::KILL)
            .union(CapabilitySet::SETPCAP);
        let systemd_257 = CapabilitySets {
            effective: expected,
            permitted: expected,
            inheritable: CapabilitySet::SYS_ADMIN.union(CapabilitySet::SETPCAP),
        };
        assert!(bootstrap_capability_sets_are_allowed(
            &systemd_257,
            expected
        ));

        for invalid in [
            CapabilitySets {
                effective: expected.difference(CapabilitySet::KILL),
                permitted: expected,
                inheritable: CapabilitySet::empty(),
            },
            CapabilitySets {
                effective: expected,
                permitted: expected.difference(CapabilitySet::KILL),
                inheritable: CapabilitySet::empty(),
            },
            CapabilitySets {
                effective: expected,
                permitted: expected,
                inheritable: CapabilitySet::NET_ADMIN,
            },
        ] {
            assert!(!bootstrap_capability_sets_are_allowed(&invalid, expected));
        }
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

        let audit = internal_wire::WorkerResponse::audit_appended(4, 1);
        assert!(response_matches(
            internal_wire::WorkerCommandKind::AuditAppend,
            &audit
        ));
        assert!(!response_matches(
            internal_wire::WorkerCommandKind::ReportPersist,
            &audit
        ));
        let list = internal_wire::WorkerResponse::report_list_ready(5, 0, 0);
        assert!(response_matches(
            internal_wire::WorkerCommandKind::ReportList,
            &list
        ));
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

    #[test]
    fn application_output_reader_drains_more_than_pipe_capacity_with_an_exact_bound() {
        let body = vec![0x5a_u8; 256 * 1024];
        let (read, write) = pipe_with(PipeFlags::CLOEXEC).expect("application pipe");
        let observed = std::thread::scope(|scope| {
            let writer = scope.spawn(|| {
                let mut offset = 0_usize;
                while offset < body.len() {
                    match rustix::io::write(&write, &body[offset..]) {
                        Ok(written) => offset += written,
                        Err(error) if error == rustix::io::Errno::INTR => {}
                        Err(error) => return Err(error),
                    }
                }
                drop(write);
                Ok(())
            });
            let observed = read_bounded_application_pipe(
                read,
                body.len(),
                Instant::now() + Duration::from_secs(2),
            )
            .expect("bounded application output");
            writer
                .join()
                .expect("application writer thread")
                .expect("application pipe write");
            observed
        });
        assert_eq!(observed.as_slice(), body.as_slice());

        let (read, write) = pipe_with(PipeFlags::CLOEXEC).expect("overflow pipe");
        rustix::io::write(&write, b"abc").expect("overflow bytes");
        drop(write);
        assert!(matches!(
            read_bounded_application_pipe(read, 2, Instant::now() + Duration::from_secs(1)),
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
