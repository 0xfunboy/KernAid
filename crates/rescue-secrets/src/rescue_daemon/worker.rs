use super::{
    RescueVaultDaemonError, enforce_process_privacy, internal_wire, runtime,
    validate_no_active_swap,
};
use crate::{
    BootVaultLocation, BootVaultLocatorError, LocatedVaultClassification,
    LocatedVaultClassificationError, MapperName, MountedRescueVault, RescueVaultMountManager,
    VaultMountManagerError, VaultUnlockRequest, locate_boot_vault,
};
use nix::sys::signal::{SigSet, Signal as NixSignal};
use rand_core::{OsRng, RngCore};
use rustix::{
    fd::{AsFd, BorrowedFd, OwnedFd},
    fs::{self as rfs, FileType, OFlags},
    process::{Signal, getppid, set_parent_process_death_signal},
};
use std::{
    io,
    time::{Duration, Instant},
};

const CONTROL_WAIT_SLICE: Duration = Duration::from_secs(30);
const CONTROL_REPLY_TIMEOUT: Duration = Duration::from_secs(5);
const BOOTSTRAP_TIMEOUT: Duration = Duration::from_secs(10);
const CLASSIFICATION_TIMEOUT: Duration = Duration::from_secs(9 * 60);
const PIPEFS_MAGIC: u64 = 0x5049_5045;

enum WorkerVaultState {
    Locked,
    Unlocked(Box<MountedRescueVault>),
}

pub(super) fn run() -> Result<(), RescueVaultDaemonError> {
    enforce_process_privacy().map_err(|()| RescueVaultDaemonError::WorkerUnavailable)?;
    let control = take_control_socket()?;
    establish_parent_lifetime(control.as_fd())?;
    internal_wire::validate_control_socket(control.as_fd())
        .map_err(|_| RescueVaultDaemonError::WorkerUnavailable)?;
    bootstrap_after_parent_placement(control.as_fd())?;

    let mut state = WorkerVaultState::Locked;
    loop {
        let deadline = Instant::now() + CONTROL_WAIT_SLICE;
        let (command, descriptor) = match internal_wire::receive_command(control.as_fd(), deadline)
        {
            Ok(command) => command,
            Err(internal_wire::InternalWireError::TimedOut) => continue,
            Err(_) => return Err(RescueVaultDaemonError::ProtocolFailure),
        };
        let request_id = command.request_id;
        let (response, exit) = handle_command(command, descriptor, &mut state);
        internal_wire::send_response(
            control.as_fd(),
            &response,
            Instant::now() + CONTROL_REPLY_TIMEOUT,
        )
        .map_err(|_| RescueVaultDaemonError::ProtocolFailure)?;
        if exit {
            return if response.code == internal_wire::WorkerResultCode::ShutdownSucceeded {
                Ok(())
            } else {
                Err(RescueVaultDaemonError::ShutdownFailed)
            };
        }
        if response.request_id != request_id {
            return Err(RescueVaultDaemonError::ProtocolFailure);
        }
    }
}

fn bootstrap_after_parent_placement(control: BorrowedFd<'_>) -> Result<(), RescueVaultDaemonError> {
    let deadline = Instant::now() + BOOTSTRAP_TIMEOUT;
    let (command, descriptor) = internal_wire::receive_command(control, deadline)
        .map_err(|_| RescueVaultDaemonError::WorkerUnavailable)?;
    if command != internal_wire::WorkerCommand::bootstrap(1) || descriptor.is_some() {
        return Err(RescueVaultDaemonError::ProtocolFailure);
    }
    runtime::verify_current_worker_cgroup()?;
    internal_wire::send_response(
        control,
        &internal_wire::WorkerResponse::new(
            command.request_id,
            internal_wire::WorkerResultCode::BootstrapReady,
        ),
        deadline,
    )
    .map_err(|_| RescueVaultDaemonError::WorkerUnavailable)?;
    runtime::verify_current_worker_cgroup()
}

fn take_control_socket() -> Result<OwnedFd, RescueVaultDaemonError> {
    let stdin = io::stdin();
    rustix::io::fcntl_setfd(stdin.as_fd(), rustix::io::FdFlags::CLOEXEC)
        .map_err(|_| RescueVaultDaemonError::WorkerUnavailable)?;
    let descriptor = rustix::io::fcntl_dupfd_cloexec(stdin.as_fd(), 3)
        .map_err(|_| RescueVaultDaemonError::WorkerUnavailable)?;
    Ok(descriptor)
}

fn establish_parent_lifetime(control: BorrowedFd<'_>) -> Result<(), RescueVaultDaemonError> {
    let credentials = rustix::net::sockopt::socket_peercred(control)
        .map_err(|_| RescueVaultDaemonError::WorkerUnavailable)?;
    if credentials.uid.as_raw() != 0 || credentials.gid.as_raw() != 0 {
        return Err(RescueVaultDaemonError::WorkerUnavailable);
    }
    let expected_parent = credentials.pid;
    set_parent_process_death_signal(Some(Signal::KILL))
        .map_err(|_| RescueVaultDaemonError::WorkerUnavailable)?;
    if getppid() != Some(expected_parent) {
        return Err(RescueVaultDaemonError::WorkerUnavailable);
    }
    let mut inherited = SigSet::empty();
    inherited.add(NixSignal::SIGINT);
    inherited.add(NixSignal::SIGTERM);
    inherited
        .thread_unblock()
        .map_err(|_| RescueVaultDaemonError::WorkerUnavailable)?;
    Ok(())
}

fn handle_command(
    command: internal_wire::WorkerCommand,
    descriptor: Option<OwnedFd>,
    state: &mut WorkerVaultState,
) -> (internal_wire::WorkerResponse, bool) {
    use internal_wire::{WorkerCommandKind as Command, WorkerResultCode as Result};
    let request_id = command.request_id;
    match command.kind {
        Command::Bootstrap => (
            internal_wire::WorkerResponse::new(request_id, Result::InvalidRequest),
            true,
        ),
        Command::Probe => {
            if descriptor.is_some() {
                return (
                    internal_wire::WorkerResponse::new(request_id, Result::InvalidRequest),
                    false,
                );
            }
            let code = match state {
                WorkerVaultState::Unlocked(_) => Result::Busy,
                WorkerVaultState::Locked => probe_result(),
            };
            (internal_wire::WorkerResponse::new(request_id, code), false)
        }
        Command::Unlock => {
            let Some(passphrase) = descriptor else {
                return (
                    internal_wire::WorkerResponse::new(request_id, Result::InvalidRequest),
                    false,
                );
            };
            if !matches!(state, WorkerVaultState::Locked) {
                return (
                    internal_wire::WorkerResponse::new(request_id, Result::Busy),
                    false,
                );
            }
            if validate_internal_passphrase_pipe(passphrase.as_fd()).is_err() {
                return (
                    internal_wire::WorkerResponse::new(request_id, Result::InvalidRequest),
                    false,
                );
            }
            if validate_no_active_swap().is_err() {
                return (
                    internal_wire::WorkerResponse::new(request_id, Result::CleanupFailed),
                    false,
                );
            }
            match unlock(passphrase, command.passphrase_size) {
                Ok((mounted, device_id)) => {
                    *state = WorkerVaultState::Unlocked(Box::new(mounted));
                    (
                        internal_wire::WorkerResponse::unlocked(request_id, device_id),
                        false,
                    )
                }
                Err(code) => (internal_wire::WorkerResponse::new(request_id, code), false),
            }
        }
        Command::Lock => {
            if descriptor.is_some() {
                return (
                    internal_wire::WorkerResponse::new(request_id, Result::InvalidRequest),
                    false,
                );
            }
            let current = std::mem::replace(state, WorkerVaultState::Locked);
            let code = match current {
                WorkerVaultState::Locked => Result::Busy,
                WorkerVaultState::Unlocked(mounted) => match (*mounted).shutdown() {
                    Ok(()) => Result::LockSucceeded,
                    Err(VaultMountManagerError::CleanupFailed) => Result::CleanupFailed,
                    Err(VaultMountManagerError::OperationTimedOut) => Result::TimedOut,
                    Err(_) => Result::IoFailed,
                },
            };
            (internal_wire::WorkerResponse::new(request_id, code), false)
        }
        Command::AttestQuiescent => {
            if descriptor.is_some() || !matches!(state, WorkerVaultState::Locked) {
                return (
                    internal_wire::WorkerResponse::new(request_id, Result::InvalidRequest),
                    false,
                );
            }
            (
                internal_wire::WorkerResponse::new(request_id, attest_quiescent()),
                false,
            )
        }
        Command::Shutdown => {
            if descriptor.is_some() {
                return (
                    internal_wire::WorkerResponse::new(request_id, Result::InvalidRequest),
                    true,
                );
            }
            let current = std::mem::replace(state, WorkerVaultState::Locked);
            let was_unlocked = matches!(&current, WorkerVaultState::Unlocked(_));
            let code = match current {
                WorkerVaultState::Locked => Result::ShutdownSucceeded,
                WorkerVaultState::Unlocked(mounted) => match (*mounted).shutdown() {
                    Ok(()) => Result::ShutdownSucceeded,
                    Err(VaultMountManagerError::OperationTimedOut) => Result::TimedOut,
                    Err(_) => Result::CleanupFailed,
                },
            };
            let code = if was_unlocked && code == Result::ShutdownSucceeded {
                match attest_quiescent() {
                    Result::AttestLocked => Result::ShutdownSucceeded,
                    Result::TimedOut => Result::TimedOut,
                    Result::CleanupFailed => Result::CleanupFailed,
                    _ => Result::CleanupFailed,
                }
            } else {
                code
            };
            (internal_wire::WorkerResponse::new(request_id, code), true)
        }
    }
}

fn attest_quiescent() -> internal_wire::WorkerResultCode {
    use internal_wire::WorkerResultCode as Result;
    match locate_and_classify_quiescent() {
        Ok((_, LocatedVaultClassification::Unprovisioned)) => Result::AttestUnprovisioned,
        Ok((_, LocatedVaultClassification::Locked)) => Result::AttestLocked,
        Err(ProbeError::Absent) => Result::AttestAbsent,
        Err(ProbeError::ProfileMismatch) => Result::AttestProfileMismatch,
        Err(ProbeError::TimedOut) => Result::TimedOut,
        Err(ProbeError::CleanupFailed) => Result::CleanupFailed,
        Err(
            ProbeError::ClassifierUnavailable | ProbeError::MediaChanged | ProbeError::IoFailed,
        ) => Result::IoFailed,
    }
}

fn probe_result() -> internal_wire::WorkerResultCode {
    use internal_wire::WorkerResultCode as Result;
    match locate_and_classify_quiescent() {
        Ok((_, LocatedVaultClassification::Unprovisioned)) => Result::ProbeUnprovisioned,
        Ok((_, LocatedVaultClassification::Locked)) => Result::ProbeLocked,
        Err(ProbeError::Absent) => Result::ProbeAbsent,
        Err(ProbeError::ProfileMismatch) => Result::ProbeProfileMismatch,
        Err(ProbeError::ClassifierUnavailable) => Result::ProbeClassifierUnavailable,
        Err(ProbeError::TimedOut) => Result::TimedOut,
        Err(ProbeError::CleanupFailed) => Result::CleanupFailed,
        Err(ProbeError::MediaChanged | ProbeError::IoFailed) => Result::ProbeIoFailed,
    }
}

fn unlock(
    passphrase: OwnedFd,
    expected_size: u16,
) -> Result<(MountedRescueVault, String), internal_wire::WorkerResultCode> {
    use internal_wire::WorkerResultCode as Code;
    if expected_size == 0 {
        return Err(Code::InvalidRequest);
    }
    let (partition, classification) = locate_and_classify().map_err(map_probe_unlock_error)?;
    match classification {
        LocatedVaultClassification::Unprovisioned => return Err(Code::Unprovisioned),
        LocatedVaultClassification::Locked => {}
    }
    let mapper = fresh_mapper_name().map_err(|_| Code::IoFailed)?;
    let manager = RescueVaultMountManager::acquire().map_err(map_manager_error)?;
    let request = VaultUnlockRequest::from_located(partition, mapper);
    let mounted = manager
        .unlock_from_fd(request, passphrase)
        .map_err(map_manager_error)?;
    let device_id = match mounted
        .secrets()
        .open_application_store()
        .map(|store| store.device_id().to_owned())
    {
        Ok(device_id) => device_id,
        Err(_) => {
            return match mounted.shutdown() {
                Ok(()) => Err(Code::IoFailed),
                Err(_) => Err(Code::CleanupFailed),
            };
        }
    };
    if kernaid_device_identity::validate_device_id(&device_id).is_err() {
        return match mounted.shutdown() {
            Ok(()) => Err(Code::IoFailed),
            Err(_) => Err(Code::CleanupFailed),
        };
    }
    Ok((mounted, device_id))
}

fn fresh_mapper_name() -> Result<MapperName, ()> {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut random = [0_u8; 8];
    OsRng.try_fill_bytes(&mut random).map_err(|_| ())?;
    let mut bytes = *b"kernaid-vault-0000000000000000";
    for (index, byte) in random.iter().enumerate() {
        bytes[14 + index * 2] = HEX[usize::from(byte >> 4)];
        bytes[15 + index * 2] = HEX[usize::from(byte & 0x0f)];
    }
    let value = std::str::from_utf8(&bytes).map_err(|_| ())?;
    MapperName::parse(value).map_err(|_| ())
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ProbeError {
    Absent,
    ProfileMismatch,
    ClassifierUnavailable,
    MediaChanged,
    TimedOut,
    CleanupFailed,
    IoFailed,
}

fn locate_and_classify()
-> Result<(crate::LocatedVaultPartition, LocatedVaultClassification), ProbeError> {
    locate_and_classify_with(false)
}

fn locate_and_classify_quiescent()
-> Result<(crate::LocatedVaultPartition, LocatedVaultClassification), ProbeError> {
    locate_and_classify_with(true)
}

fn locate_and_classify_with(
    require_quiescence: bool,
) -> Result<(crate::LocatedVaultPartition, LocatedVaultClassification), ProbeError> {
    let partition = match locate_boot_vault().map_err(map_locator_error)? {
        BootVaultLocation::OpticalBootAbsent => return Err(ProbeError::Absent),
        BootVaultLocation::Vault(partition) => partition,
    };
    let classification = if require_quiescence {
        partition.classify_quiescent_read_only(CLASSIFICATION_TIMEOUT)
    } else {
        partition.classify_read_only(CLASSIFICATION_TIMEOUT)
    }
    .map_err(map_classifier_error)?;
    Ok((partition, classification))
}

fn map_locator_error(error: BootVaultLocatorError) -> ProbeError {
    match error {
        BootVaultLocatorError::BootMediumAbsent | BootVaultLocatorError::VaultPartitionAbsent => {
            ProbeError::Absent
        }
        BootVaultLocatorError::MediaChanged => ProbeError::MediaChanged,
        BootVaultLocatorError::OperationTimedOut => ProbeError::TimedOut,
        BootVaultLocatorError::CleanupFailed => ProbeError::CleanupFailed,
        BootVaultLocatorError::AmbiguousBootMedium
        | BootVaultLocatorError::UnsupportedBootMedium
        | BootVaultLocatorError::AmbiguousVaultPartition
        | BootVaultLocatorError::InvalidKernelIdentity
        | BootVaultLocatorError::InvalidVaultGeometry
        | BootVaultLocatorError::BlockDeviceUnavailable
        | BootVaultLocatorError::BlockIdentityUnavailable
        | BootVaultLocatorError::ToolUnavailable => ProbeError::IoFailed,
    }
}

fn map_classifier_error(error: LocatedVaultClassificationError) -> ProbeError {
    match error {
        LocatedVaultClassificationError::ProfileMismatch => ProbeError::ProfileMismatch,
        LocatedVaultClassificationError::ClassifierUnavailable => ProbeError::ClassifierUnavailable,
        LocatedVaultClassificationError::MediaChanged => ProbeError::MediaChanged,
        LocatedVaultClassificationError::OperationTimedOut => ProbeError::TimedOut,
        LocatedVaultClassificationError::CleanupFailed => ProbeError::CleanupFailed,
        LocatedVaultClassificationError::InvalidDeadline
        | LocatedVaultClassificationError::BlockIdentityUnavailable
        | LocatedVaultClassificationError::ToolUnavailable => ProbeError::IoFailed,
    }
}

fn map_probe_unlock_error(error: ProbeError) -> internal_wire::WorkerResultCode {
    use internal_wire::WorkerResultCode as Result;
    match error {
        ProbeError::Absent => Result::Absent,
        ProbeError::ProfileMismatch => Result::ProfileMismatch,
        ProbeError::ClassifierUnavailable | ProbeError::IoFailed => Result::IoFailed,
        ProbeError::MediaChanged => Result::MediaChanged,
        ProbeError::TimedOut => Result::TimedOut,
        ProbeError::CleanupFailed => Result::CleanupFailed,
    }
}

fn map_manager_error(error: VaultMountManagerError) -> internal_wire::WorkerResultCode {
    use internal_wire::WorkerResultCode as Result;
    match error {
        VaultMountManagerError::Unprovisioned => Result::Unprovisioned,
        VaultMountManagerError::ProfileMismatch => Result::ProfileMismatch,
        VaultMountManagerError::UnlockFailed => Result::BadPassphrase,
        VaultMountManagerError::ManagerLocked | VaultMountManagerError::MapperConflict => {
            Result::Busy
        }
        VaultMountManagerError::CleanupFailed => Result::CleanupFailed,
        VaultMountManagerError::OperationTimedOut => Result::TimedOut,
        VaultMountManagerError::InvalidBlockDevice
        | VaultMountManagerError::InvalidLuks2Header
        | VaultMountManagerError::WrongVaultLabel
        | VaultMountManagerError::MappingVerificationFailed => Result::MediaChanged,
        VaultMountManagerError::UnsupportedPlatform
        | VaultMountManagerError::PrivilegeRequired
        | VaultMountManagerError::InvalidMapperName
        | VaultMountManagerError::ClassifierUnavailable
        | VaultMountManagerError::PassphraseUnavailable
        | VaultMountManagerError::UnsupportedFilesystem
        | VaultMountManagerError::UnsafeMountRoot
        | VaultMountManagerError::MountFailed
        | VaultMountManagerError::MountVerificationFailed
        | VaultMountManagerError::SecureStateUnavailable
        | VaultMountManagerError::ToolUnavailable => Result::IoFailed,
    }
}

fn validate_internal_passphrase_pipe(descriptor: BorrowedFd<'_>) -> Result<(), ()> {
    let stat = rfs::fstat(descriptor).map_err(|_| ())?;
    let filesystem = rfs::fstatfs(descriptor).map_err(|_| ())?;
    let filesystem_type = u64::try_from(filesystem.f_type).map_err(|_| ())?;
    let status = rfs::fcntl_getfl(descriptor).map_err(|_| ())?;
    let descriptor_flags = rustix::io::fcntl_getfd(descriptor).map_err(|_| ())?;
    if !FileType::from_raw_mode(stat.st_mode).is_fifo()
        || filesystem_type != PIPEFS_MAGIC
        || status & OFlags::ACCMODE != OFlags::RDONLY
        || !descriptor_flags.contains(rustix::io::FdFlags::CLOEXEC)
        || stat.st_size != 0
    {
        return Err(());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use rustix::pipe::{PipeFlags, pipe_with};

    #[test]
    fn internal_passphrase_descriptor_requires_read_only_pipefs_cloexec() {
        let (read, write) = pipe_with(PipeFlags::CLOEXEC).expect("pipe");
        assert_eq!(validate_internal_passphrase_pipe(read.as_fd()), Ok(()));
        assert_eq!(validate_internal_passphrase_pipe(write.as_fd()), Err(()));

        let (plain_read, _plain_write) = pipe_with(PipeFlags::empty()).expect("plain pipe");
        assert_eq!(
            validate_internal_passphrase_pipe(plain_read.as_fd()),
            Err(())
        );
    }

    #[test]
    fn classification_and_manager_errors_preserve_fault_categories() {
        assert_eq!(
            map_classifier_error(LocatedVaultClassificationError::ProfileMismatch),
            ProbeError::ProfileMismatch
        );
        assert_eq!(
            map_classifier_error(LocatedVaultClassificationError::ClassifierUnavailable),
            ProbeError::ClassifierUnavailable
        );
        assert_eq!(
            map_manager_error(VaultMountManagerError::CleanupFailed),
            internal_wire::WorkerResultCode::CleanupFailed
        );
        assert_eq!(
            map_manager_error(VaultMountManagerError::OperationTimedOut),
            internal_wire::WorkerResultCode::TimedOut
        );
    }

    #[test]
    fn mapper_names_are_fresh_and_match_the_closed_lower_hex_grammar() {
        let first = fresh_mapper_name().expect("first mapper");
        let second = fresh_mapper_name().expect("second mapper");
        assert_ne!(first, second);
        assert!(format!("{first:?}").contains("validated"));
    }
}
