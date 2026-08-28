use super::{
    RescueVaultDaemonError, enforce_process_privacy, internal_wire, runtime,
    validate_no_active_swap,
};
use crate::{
    BootVaultLocation, BootVaultLocatorError, LocatedVaultClassification,
    LocatedVaultClassificationError, MapperName, MountedRescueVault, ProviderCredentialStatus,
    RescueApplicationStoreError, RescueVaultMountManager, VaultMountManagerError,
    VaultUnlockRequest, locate_boot_vault,
};
#[cfg(feature = "experimental-repair-store")]
use crate::{
    RepairBackupDraft as StoreRepairBackupDraft, RepairBackupStatus as StoreRepairBackupStatus,
    RepairBackupSummary as StoreRepairBackupSummary, RepairBinding as StoreRepairBinding,
    RepairVaultStoreError, ReservationId as StoreReservationId,
    VerifiedBackupMetadata as StoreVerifiedBackupMetadata,
};
use kernaid_protocol::rescue_vault::{
    AuditEventType, AuditOutcome, ErrorToken, MAX_OPENAI_KEY_BYTES, MAX_SESSION_REPORT_JSON_BYTES,
    MAX_SIGNED_REPORT_ENVELOPE_BYTES, ReportId, RequestId, validate_openai_api_key_bytes,
};
use nix::sys::signal::{SigSet, Signal as NixSignal};
use rand_core::{OsRng, RngCore};
use rustix::{
    event::{PollFd, PollFlags, Timespec, poll},
    fd::{AsFd, BorrowedFd, OwnedFd},
    fs::{self as rfs, FileType, OFlags},
    process::{Signal, getppid, set_parent_process_death_signal},
};
use sha2::{Digest, Sha256};
#[cfg(feature = "experimental-repair-store")]
use std::io::Read;
use std::{
    io,
    time::{Duration, Instant},
};
use zeroize::Zeroizing;

const CONTROL_WAIT_SLICE: Duration = Duration::from_secs(30);
const CONTROL_REPLY_TIMEOUT: Duration = Duration::from_secs(5);
const BOOTSTRAP_TIMEOUT: Duration = Duration::from_secs(10);
const CLASSIFICATION_TIMEOUT: Duration = Duration::from_secs(9 * 60);
const PROVIDER_PIPE_TIMEOUT: Duration = Duration::from_secs(15);
const APPLICATION_PIPE_TIMEOUT: Duration = Duration::from_secs(30);
const PIPEFS_MAGIC: u64 = 0x5049_5045;
const MAX_PROVIDER_OUTPUT_BYTES: usize = MAX_OPENAI_KEY_BYTES as usize;
const MAX_REPORT_INPUT_BYTES: usize = MAX_SESSION_REPORT_JSON_BYTES as usize;
const MAX_REPORT_OUTPUT_BYTES: usize = MAX_SIGNED_REPORT_ENVELOPE_BYTES as usize;
#[cfg(feature = "experimental-repair-store")]
const MAX_REPAIR_BYTES: usize =
    kernaid_protocol::rescue_repair_vault::MAX_REPAIR_BACKUP_BYTES as usize;
const _: () = assert!(MAX_PROVIDER_OUTPUT_BYTES <= rustix::pipe::PIPE_BUF);

enum WorkerVaultState {
    Locked,
    Unlocked(Box<MountedRescueVault>),
}

pub(super) fn run() -> Result<(), RescueVaultDaemonError> {
    runtime::narrow_worker_capabilities()?;
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
        let mut response_descriptor = None;
        let (response, exit) =
            handle_command(command, descriptor, &mut state, &mut response_descriptor);
        let response_deadline = Instant::now() + CONTROL_REPLY_TIMEOUT;
        #[cfg(feature = "experimental-codex-home-lease")]
        let sent = if let Some(descriptor) = response_descriptor.as_ref() {
            internal_wire::send_codex_home_response(
                control.as_fd(),
                &response,
                Some(descriptor.as_fd()),
                response_deadline,
            )
        } else {
            internal_wire::send_response(control.as_fd(), &response, response_deadline)
        };
        #[cfg(not(feature = "experimental-codex-home-lease"))]
        let sent = {
            debug_assert!(response_descriptor.is_none());
            internal_wire::send_response(control.as_fd(), &response, response_deadline)
        };
        drop(response_descriptor);
        sent.map_err(|_| RescueVaultDaemonError::ProtocolFailure)?;
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
    response_descriptor: &mut Option<OwnedFd>,
) -> (internal_wire::WorkerResponse, bool) {
    #[cfg(not(feature = "experimental-codex-home-lease"))]
    let _ = &response_descriptor;
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
            if validate_internal_secret_pipe(passphrase.as_fd()).is_err() {
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
            match unlock(passphrase, command.secret_size) {
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
        Command::ProviderStatus => {
            if descriptor.is_some() {
                return (
                    internal_wire::WorkerResponse::new(request_id, Result::InvalidRequest),
                    false,
                );
            }
            let code = match state {
                WorkerVaultState::Locked => Result::Busy,
                WorkerVaultState::Unlocked(_) if validate_no_active_swap().is_err() => {
                    Result::CleanupFailed
                }
                WorkerVaultState::Unlocked(mounted) => provider_status(mounted),
            };
            (internal_wire::WorkerResponse::new(request_id, code), false)
        }
        Command::ProviderOpenAiConfigure => {
            let Some(api_key) = descriptor else {
                return (
                    internal_wire::WorkerResponse::new(request_id, Result::InvalidRequest),
                    false,
                );
            };
            if validate_internal_secret_pipe(api_key.as_fd()).is_err() {
                return (
                    internal_wire::WorkerResponse::new(request_id, Result::InvalidRequest),
                    false,
                );
            }
            let code = match state {
                WorkerVaultState::Locked => Result::Busy,
                WorkerVaultState::Unlocked(_) if validate_no_active_swap().is_err() => {
                    Result::CleanupFailed
                }
                WorkerVaultState::Unlocked(mounted) => {
                    configure_openai(mounted, api_key, command.secret_size)
                }
            };
            (internal_wire::WorkerResponse::new(request_id, code), false)
        }
        Command::ProviderOpenAiBorrow => {
            let Some(output) = descriptor else {
                return (
                    internal_wire::WorkerResponse::new(request_id, Result::InvalidRequest),
                    false,
                );
            };
            if validate_internal_output_pipe(output.as_fd()).is_err() {
                return (
                    internal_wire::WorkerResponse::new(request_id, Result::InvalidRequest),
                    false,
                );
            }
            let borrowed = match state {
                WorkerVaultState::Locked => Err(Result::Busy),
                WorkerVaultState::Unlocked(_) if validate_no_active_swap().is_err() => {
                    Err(Result::CleanupFailed)
                }
                WorkerVaultState::Unlocked(mounted) => borrow_openai(mounted, output),
            };
            let response = match borrowed {
                Ok(Some(size)) => {
                    internal_wire::WorkerResponse::provider_borrow_ready(request_id, size)
                }
                Ok(None) => internal_wire::WorkerResponse::new(
                    request_id,
                    Result::ProviderBorrowUnconfigured,
                ),
                Err(code) => internal_wire::WorkerResponse::new(request_id, code),
            };
            (response, false)
        }
        Command::ProviderOpenAiLogout => {
            if descriptor.is_some() {
                return (
                    internal_wire::WorkerResponse::new(request_id, Result::InvalidRequest),
                    false,
                );
            }
            let code = match state {
                WorkerVaultState::Locked => Result::Busy,
                WorkerVaultState::Unlocked(_) if validate_no_active_swap().is_err() => {
                    Result::CleanupFailed
                }
                WorkerVaultState::Unlocked(mounted) => logout_openai(mounted),
            };
            (internal_wire::WorkerResponse::new(request_id, code), false)
        }
        Command::AuditAppend => {
            if descriptor.is_some() {
                return (
                    internal_wire::WorkerResponse::new(request_id, Result::InvalidRequest),
                    false,
                );
            }
            let Some(internal_wire::WorkerApplicationCommand::AuditAppend {
                request_id: agent_request_id,
                peer_uid,
                peer_pid,
                sequence,
                event,
                outcome,
                error,
            }) = command.application.as_ref()
            else {
                return (
                    internal_wire::WorkerResponse::new(request_id, Result::InvalidRequest),
                    false,
                );
            };
            let appended = match state {
                WorkerVaultState::Locked => Err(Result::Busy),
                WorkerVaultState::Unlocked(_) if validate_no_active_swap().is_err() => {
                    Err(Result::CleanupFailed)
                }
                WorkerVaultState::Unlocked(mounted) => append_agent_audit(
                    mounted,
                    agent_request_id,
                    *peer_uid,
                    *peer_pid,
                    *sequence,
                    *event,
                    *outcome,
                    *error,
                ),
            };
            let response = match appended {
                Ok(sequence) => internal_wire::WorkerResponse::audit_appended(request_id, sequence),
                Err(code) => internal_wire::WorkerResponse::new(request_id, code),
            };
            (response, false)
        }
        Command::ReportPersist => {
            let Some(input) = descriptor else {
                return (
                    internal_wire::WorkerResponse::new(request_id, Result::InvalidRequest),
                    false,
                );
            };
            if validate_internal_secret_pipe(input.as_fd()).is_err() {
                return (
                    internal_wire::WorkerResponse::new(request_id, Result::InvalidRequest),
                    false,
                );
            }
            let Some(internal_wire::WorkerApplicationCommand::ReportPersist {
                report_id,
                payload_sha256,
                input_size,
            }) = command.application.as_ref()
            else {
                return (
                    internal_wire::WorkerResponse::new(request_id, Result::InvalidRequest),
                    false,
                );
            };
            let persisted = match state {
                WorkerVaultState::Locked => Err(Result::Busy),
                WorkerVaultState::Unlocked(_) if validate_no_active_swap().is_err() => {
                    Err(Result::CleanupFailed)
                }
                WorkerVaultState::Unlocked(mounted) => {
                    persist_report(mounted, report_id, payload_sha256, *input_size, input)
                }
            };
            let response = match persisted {
                Ok(report) => internal_wire::WorkerResponse::report_persisted(request_id, report),
                Err(code) => internal_wire::WorkerResponse::new(request_id, code),
            };
            (response, false)
        }
        Command::ReportList => {
            let Some(output) = descriptor else {
                return (
                    internal_wire::WorkerResponse::new(request_id, Result::InvalidRequest),
                    false,
                );
            };
            if !matches!(
                command.application.as_ref(),
                Some(internal_wire::WorkerApplicationCommand::ReportList)
            ) || validate_internal_application_output_pipe(output.as_fd()).is_err()
            {
                return (
                    internal_wire::WorkerResponse::new(request_id, Result::InvalidRequest),
                    false,
                );
            }
            let listed = match state {
                WorkerVaultState::Locked => Err(Result::Busy),
                WorkerVaultState::Unlocked(_) if validate_no_active_swap().is_err() => {
                    Err(Result::CleanupFailed)
                }
                WorkerVaultState::Unlocked(mounted) => list_reports(mounted, output),
            };
            let response = match listed {
                Ok((size, count)) => {
                    internal_wire::WorkerResponse::report_list_ready(request_id, size, count)
                }
                Err(code) => internal_wire::WorkerResponse::new(request_id, code),
            };
            (response, false)
        }
        Command::ReportGet => {
            let Some(output) = descriptor else {
                return (
                    internal_wire::WorkerResponse::new(request_id, Result::InvalidRequest),
                    false,
                );
            };
            if validate_internal_application_output_pipe(output.as_fd()).is_err() {
                return (
                    internal_wire::WorkerResponse::new(request_id, Result::InvalidRequest),
                    false,
                );
            }
            let Some(internal_wire::WorkerApplicationCommand::ReportGet { report_id }) =
                command.application.as_ref()
            else {
                return (
                    internal_wire::WorkerResponse::new(request_id, Result::InvalidRequest),
                    false,
                );
            };
            let fetched = match state {
                WorkerVaultState::Locked => Err(Result::Busy),
                WorkerVaultState::Unlocked(_) if validate_no_active_swap().is_err() => {
                    Err(Result::CleanupFailed)
                }
                WorkerVaultState::Unlocked(mounted) => get_report(mounted, report_id, output),
            };
            let response = match fetched {
                Ok(Some(report)) => internal_wire::WorkerResponse::report_ready(request_id, report),
                Ok(None) => internal_wire::WorkerResponse::new(
                    request_id,
                    Result::ApplicationReportNotFound,
                ),
                Err(code) => internal_wire::WorkerResponse::new(request_id, code),
            };
            (response, false)
        }
        #[cfg(feature = "experimental-repair-store")]
        Command::RepairBackupReserve => {
            if descriptor.is_some() {
                return (
                    internal_wire::WorkerResponse::new(request_id, Result::RepairInvalidRequest),
                    false,
                );
            }
            let Some(internal_wire::WorkerRepairCommand::Reserve { draft }) =
                command.repair.as_ref()
            else {
                return (
                    internal_wire::WorkerResponse::new(request_id, Result::RepairInvalidRequest),
                    false,
                );
            };
            let reserved = match state {
                WorkerVaultState::Locked => Err(Result::Busy),
                WorkerVaultState::Unlocked(_) if validate_no_active_swap().is_err() => {
                    Err(Result::CleanupFailed)
                }
                WorkerVaultState::Unlocked(mounted) => reserve_repair_backup(mounted, draft),
            };
            let response = match reserved {
                Ok(status) => internal_wire::WorkerResponse::repair(
                    request_id,
                    Result::RepairBackupReserved,
                    status,
                ),
                Err(code) => internal_wire::WorkerResponse::new(request_id, code),
            };
            (response, false)
        }
        #[cfg(feature = "experimental-repair-store")]
        Command::RepairBackupPersist => {
            let Some(source) = descriptor else {
                return (
                    internal_wire::WorkerResponse::new(request_id, Result::RepairInvalidRequest),
                    false,
                );
            };
            let Some(internal_wire::WorkerRepairCommand::Persist {
                expected,
                binding,
                metadata,
                input_size,
            }) = command.repair.as_ref()
            else {
                return (
                    internal_wire::WorkerResponse::new(request_id, Result::RepairInvalidRequest),
                    false,
                );
            };
            if validate_internal_repair_source_pipe(source.as_fd(), *input_size).is_err()
                || !metadata.is_supported_root_file()
                || expected.metadata_sha256
                    != metadata
                        .to_protocol()
                        .map(|value| value.canonical_sha256().bytes())
                        .unwrap_or([0; 32])
            {
                return (
                    internal_wire::WorkerResponse::new(request_id, Result::RepairInvalidRequest),
                    false,
                );
            }
            let persisted = match state {
                WorkerVaultState::Locked => Err(Result::Busy),
                WorkerVaultState::Unlocked(_) if validate_no_active_swap().is_err() => {
                    Err(Result::CleanupFailed)
                }
                WorkerVaultState::Unlocked(mounted) => {
                    persist_repair_backup(mounted, expected, binding, *input_size, source)
                }
            };
            let response = match persisted {
                Ok(status) => internal_wire::WorkerResponse::repair(
                    request_id,
                    Result::RepairBackupDurable,
                    status,
                ),
                Err(code) => internal_wire::WorkerResponse::new(request_id, code),
            };
            (response, false)
        }
        #[cfg(feature = "experimental-repair-store")]
        Command::RepairBackupStatus => {
            if descriptor.is_some() {
                return (
                    internal_wire::WorkerResponse::new(request_id, Result::RepairInvalidRequest),
                    false,
                );
            }
            let Some(internal_wire::WorkerRepairCommand::Status { expected }) =
                command.repair.as_ref()
            else {
                return (
                    internal_wire::WorkerResponse::new(request_id, Result::RepairInvalidRequest),
                    false,
                );
            };
            let status = match state {
                WorkerVaultState::Locked => Err(Result::Busy),
                WorkerVaultState::Unlocked(_) if validate_no_active_swap().is_err() => {
                    Err(Result::CleanupFailed)
                }
                WorkerVaultState::Unlocked(mounted) => repair_backup_status(mounted, expected),
            };
            let response = match status {
                Ok(status) => internal_wire::WorkerResponse::repair(
                    request_id,
                    Result::RepairBackupStatusReady,
                    status,
                ),
                Err(code) => internal_wire::WorkerResponse::new(request_id, code),
            };
            (response, false)
        }
        #[cfg(feature = "experimental-repair-store")]
        Command::RepairBackupGet => {
            let Some(output) = descriptor else {
                return (
                    internal_wire::WorkerResponse::new(request_id, Result::RepairInvalidRequest),
                    false,
                );
            };
            if validate_internal_application_output_pipe(output.as_fd()).is_err() {
                return (
                    internal_wire::WorkerResponse::new(request_id, Result::RepairInvalidRequest),
                    false,
                );
            }
            let Some(internal_wire::WorkerRepairCommand::Get { expected }) =
                command.repair.as_ref()
            else {
                return (
                    internal_wire::WorkerResponse::new(request_id, Result::RepairInvalidRequest),
                    false,
                );
            };
            let backup = match state {
                WorkerVaultState::Locked => Err(Result::Busy),
                WorkerVaultState::Unlocked(_) if validate_no_active_swap().is_err() => {
                    Err(Result::CleanupFailed)
                }
                WorkerVaultState::Unlocked(mounted) => get_repair_backup(mounted, expected, output),
            };
            let response = match backup {
                Ok(status) => internal_wire::WorkerResponse::repair(
                    request_id,
                    Result::RepairBackupReady,
                    status,
                ),
                Err(code) => internal_wire::WorkerResponse::new(request_id, code),
            };
            (response, false)
        }
        #[cfg(feature = "experimental-codex-home-lease")]
        Command::ProviderCodexHomeLease => {
            if descriptor.is_some() || response_descriptor.is_some() {
                return (
                    internal_wire::WorkerResponse::new(request_id, Result::InvalidRequest),
                    false,
                );
            }
            let code = match state {
                WorkerVaultState::Locked => Result::Busy,
                WorkerVaultState::Unlocked(_) if validate_no_active_swap().is_err() => {
                    Result::CleanupFailed
                }
                WorkerVaultState::Unlocked(mounted) => {
                    match mounted.secrets().open_codex_home_lease() {
                        Ok(Some(home)) => {
                            *response_descriptor = Some(home);
                            Result::ProviderCodexHomeReady
                        }
                        Ok(None) => Result::ProviderCodexHomeUnconfigured,
                        Err(_) => Result::ProviderStateAmbiguous,
                    }
                }
            };
            (
                if code == Result::ProviderCodexHomeReady {
                    internal_wire::WorkerResponse::provider_codex_home_ready(request_id)
                } else {
                    internal_wire::WorkerResponse::new(request_id, code)
                },
                false,
            )
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

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ProviderMutationDisposition {
    Applied,
    Aborted,
    Ambiguous,
}

fn provider_status(mounted: &MountedRescueVault) -> internal_wire::WorkerResultCode {
    use internal_wire::WorkerResultCode as Result;
    let store = match mounted.secrets().open_application_store() {
        Ok(store) => store,
        Err(_) => return Result::ProviderStateAmbiguous,
    };
    match store.provider_status() {
        Ok(ProviderCredentialStatus::Absent) => Result::ProviderStatusUnconfigured,
        Ok(ProviderCredentialStatus::Configured) => Result::ProviderStatusConfigured,
        Err(_) => Result::ProviderStateAmbiguous,
    }
}

fn borrow_openai(
    mounted: &MountedRescueVault,
    output: OwnedFd,
) -> Result<Option<u16>, internal_wire::WorkerResultCode> {
    use internal_wire::WorkerResultCode as Result;
    let store = mounted
        .secrets()
        .open_application_store()
        .map_err(|_| Result::ProviderStateAmbiguous)?;
    let borrowed = store
        .with_openai_api_key(|value| write_openai_key_once(output.as_fd(), value))
        .map_err(|_| Result::ProviderStateAmbiguous);
    // The worker must close its only output writer before the control response
    // is sent. The supervisor can then prove EOF/HUP without reading a byte.
    drop(output);
    match borrowed {
        Ok(Some(Ok(size))) => Ok(Some(size)),
        Ok(None) => Ok(None),
        Ok(Some(Err(()))) => Err(Result::IoFailed),
        Err(code) => Err(code),
    }
}

fn write_openai_key_once(output: BorrowedFd<'_>, value: &[u8]) -> Result<u16, ()> {
    validate_openai_api_key_bytes(value).map_err(|_| ())?;
    let size = u16::try_from(value.len()).map_err(|_| ())?;
    if value.len() > MAX_PROVIDER_OUTPUT_BYTES {
        return Err(());
    }
    loop {
        match rustix::io::write(output, value) {
            Ok(written) if written == value.len() => return Ok(size),
            Err(error) if error == rustix::io::Errno::INTR => {}
            Ok(_) | Err(_) => return Err(()),
        }
    }
}

fn configure_openai(
    mounted: &MountedRescueVault,
    api_key_pipe: OwnedFd,
    declared_size: u16,
) -> internal_wire::WorkerResultCode {
    use internal_wire::WorkerResultCode as Result;
    let api_key = match read_exact_openai_api_key(
        api_key_pipe,
        declared_size,
        Instant::now() + PROVIDER_PIPE_TIMEOUT,
    ) {
        Ok(value) => value,
        Err(()) => return Result::InvalidRequest,
    };
    let desired: [u8; 32] = Sha256::digest(api_key.as_slice()).into();
    let mut store = match mounted.secrets().open_application_store() {
        Ok(store) => store,
        Err(_) => return Result::ProviderStateAmbiguous,
    };
    let prior = match provider_digest(&store) {
        Ok(observed) => observed,
        Err(()) => return Result::ProviderStateAmbiguous,
    };
    let operation_succeeded = store.configure_openai_api_key(api_key).is_ok();
    drop(store);
    let observed = match reopen_provider_digest(mounted) {
        Ok(observed) => observed,
        Err(()) => return Result::ProviderStateAmbiguous,
    };
    match classify_provider_mutation(prior, Some(desired), observed, operation_succeeded) {
        ProviderMutationDisposition::Applied => Result::ProviderConfigureSucceeded,
        ProviderMutationDisposition::Aborted => Result::ProviderMutationAborted,
        ProviderMutationDisposition::Ambiguous => Result::ProviderStateAmbiguous,
    }
}

fn logout_openai(mounted: &MountedRescueVault) -> internal_wire::WorkerResultCode {
    use internal_wire::WorkerResultCode as Result;
    let mut store = match mounted.secrets().open_application_store() {
        Ok(store) => store,
        Err(_) => return Result::ProviderStateAmbiguous,
    };
    let prior = match provider_digest(&store) {
        Ok(observed) => observed,
        Err(()) => return Result::ProviderStateAmbiguous,
    };
    let operation_succeeded = store.logout_openai().is_ok();
    drop(store);
    let observed = match reopen_provider_digest(mounted) {
        Ok(observed) => observed,
        Err(()) => return Result::ProviderStateAmbiguous,
    };
    match classify_provider_mutation(prior, None, observed, operation_succeeded) {
        ProviderMutationDisposition::Applied => Result::ProviderLogoutSucceeded,
        ProviderMutationDisposition::Aborted => Result::ProviderMutationAborted,
        ProviderMutationDisposition::Ambiguous => Result::ProviderStateAmbiguous,
    }
}

fn reopen_provider_digest(mounted: &MountedRescueVault) -> Result<Option<[u8; 32]>, ()> {
    let store = mounted.secrets().open_application_store().map_err(|_| ())?;
    provider_digest(&store)
}

fn provider_digest(store: &crate::RescueVaultApplicationStore<'_>) -> Result<Option<[u8; 32]>, ()> {
    store
        .with_openai_api_key(|value| Sha256::digest(value).into())
        .map_err(|_| ())
}

fn classify_provider_mutation(
    prior: Option<[u8; 32]>,
    desired: Option<[u8; 32]>,
    observed: Option<[u8; 32]>,
    operation_succeeded: bool,
) -> ProviderMutationDisposition {
    if observed == desired {
        ProviderMutationDisposition::Applied
    } else if !operation_succeeded && observed == prior {
        ProviderMutationDisposition::Aborted
    } else {
        ProviderMutationDisposition::Ambiguous
    }
}

#[allow(clippy::too_many_arguments)]
fn append_agent_audit(
    mounted: &MountedRescueVault,
    request_id: &RequestId,
    peer_uid: u32,
    peer_pid: u32,
    sequence: u64,
    event: AuditEventType,
    outcome: AuditOutcome,
    error: Option<ErrorToken>,
) -> Result<u64, internal_wire::WorkerResultCode> {
    use internal_wire::WorkerResultCode as Result;
    let mut store = mounted
        .secrets()
        .open_application_store()
        .map_err(|_| Result::ApplicationStateAmbiguous)?;
    match store.contains_agent_audit_request(request_id) {
        Ok(true) => return Err(Result::ApplicationStaleSequence),
        Ok(false) => {}
        Err(_) => return Err(Result::ApplicationStateAmbiguous),
    }
    let operation = store.append_agent_audit_fields(
        request_id, peer_uid, peer_pid, sequence, event, outcome, error,
    );
    drop(store);
    let observed = mounted
        .secrets()
        .open_application_store()
        .and_then(|store| store.contains_agent_audit_request(request_id));
    match (operation, observed) {
        (_, Ok(true)) => Ok(sequence),
        (Err(RescueApplicationStoreError::StaleAgentSequence), Ok(false)) => {
            Err(Result::ApplicationStaleSequence)
        }
        (Err(RescueApplicationStoreError::InvalidAgentAudit), Ok(false)) => {
            Err(Result::ApplicationInvalidRequest)
        }
        (Err(_), Ok(false)) => Err(Result::ApplicationMutationAborted),
        (Ok(_), Ok(false)) | (_, Err(_)) => Err(Result::ApplicationStateAmbiguous),
    }
}

fn persist_report(
    mounted: &MountedRescueVault,
    report_id: &ReportId,
    payload_sha256: &[u8; 32],
    input_size: u64,
    input: OwnedFd,
) -> Result<internal_wire::WorkerReportSummary, internal_wire::WorkerResultCode> {
    use internal_wire::WorkerResultCode as Result;
    let input_size = usize::try_from(input_size)
        .ok()
        .filter(|size| (2..=MAX_REPORT_INPUT_BYTES).contains(size))
        .ok_or(Result::ApplicationReportTooLarge)?;
    let raw_report =
        read_exact_application_pipe(input, input_size, Instant::now() + APPLICATION_PIPE_TIMEOUT)
            .map_err(|_| Result::ApplicationInvalidRequest)?;
    let mut store = mounted
        .secrets()
        .open_application_store()
        .map_err(|_| Result::ApplicationStateAmbiguous)?;
    let prior = store
        .list_reports()
        .map_err(|_| Result::ApplicationStateAmbiguous)?;
    if prior
        .iter()
        .any(|report| report.report_id() == report_id.as_str())
    {
        return Err(Result::ApplicationInvalidRequest);
    }
    let operation = store.persist_report(report_id.as_str(), payload_sha256, raw_report);
    drop(store);
    let observed = reopen_report_summary(mounted, report_id);
    match (operation, observed) {
        (_, Ok(Some(summary))) => Ok(summary),
        (
            Err(
                RescueApplicationStoreError::InvalidReportIdentifier
                | RescueApplicationStoreError::InvalidReport
                | RescueApplicationStoreError::ReportHashMismatch
                | RescueApplicationStoreError::ReportAlreadyExists,
            ),
            Ok(None),
        ) => Err(Result::ApplicationInvalidRequest),
        (Err(RescueApplicationStoreError::ReportLimitReached), Ok(None)) => {
            Err(Result::ApplicationReportTooLarge)
        }
        (Err(_), Ok(None)) => Err(Result::ApplicationMutationAborted),
        (Ok(_), Ok(None)) | (_, Err(_)) => Err(Result::ApplicationStateAmbiguous),
    }
}

fn reopen_report_summary(
    mounted: &MountedRescueVault,
    report_id: &ReportId,
) -> Result<Option<internal_wire::WorkerReportSummary>, RescueApplicationStoreError> {
    let store = mounted.secrets().open_application_store()?;
    store
        .list_reports()?
        .iter()
        .find(|report| report.report_id() == report_id.as_str())
        .map(internal_wire::WorkerReportSummary::from_store)
        .transpose()
        .map_err(|_| RescueApplicationStoreError::CorruptApplicationState)
}

fn list_reports(
    mounted: &MountedRescueVault,
    output: OwnedFd,
) -> Result<(u64, u16), internal_wire::WorkerResultCode> {
    use internal_wire::WorkerResultCode as Result;
    let store = mounted
        .secrets()
        .open_application_store()
        .map_err(|_| Result::ApplicationStateAmbiguous)?;
    let reports = store
        .list_reports()
        .map_err(|_| Result::ApplicationStateAmbiguous)?
        .iter()
        .map(internal_wire::WorkerReportSummary::from_store)
        .collect::<std::result::Result<Vec<_>, _>>()
        .map_err(|_| Result::ApplicationStateAmbiguous)?;
    let encoded = internal_wire::encode_report_records(&reports)
        .map_err(|_| Result::ApplicationStateAmbiguous)?;
    let count = u16::try_from(reports.len()).map_err(|_| Result::ApplicationStateAmbiguous)?;
    let size = u64::try_from(encoded.len()).map_err(|_| Result::ApplicationStateAmbiguous)?;
    write_application_output(output, &encoded, Instant::now() + APPLICATION_PIPE_TIMEOUT)
        .map_err(|_| Result::IoFailed)?;
    Ok((size, count))
}

fn get_report(
    mounted: &MountedRescueVault,
    report_id: &ReportId,
    output: OwnedFd,
) -> Result<Option<internal_wire::WorkerReportSummary>, internal_wire::WorkerResultCode> {
    use internal_wire::WorkerResultCode as Result;
    let store = mounted
        .secrets()
        .open_application_store()
        .map_err(|_| Result::ApplicationStateAmbiguous)?;
    let summary = store
        .list_reports()
        .map_err(|_| Result::ApplicationStateAmbiguous)?
        .iter()
        .find(|report| report.report_id() == report_id.as_str())
        .map(internal_wire::WorkerReportSummary::from_store)
        .transpose()
        .map_err(|_| Result::ApplicationStateAmbiguous)?;
    let Some(summary) = summary else {
        drop(output);
        return Ok(None);
    };
    let write_result = store
        .with_report_envelope(report_id.as_str(), |envelope| {
            if envelope.len() != summary.envelope_size as usize
                || envelope.len() > MAX_REPORT_OUTPUT_BYTES
                || Sha256::digest(envelope).as_slice() != summary.envelope_sha256
            {
                return Err(());
            }
            write_application_output(output, envelope, Instant::now() + APPLICATION_PIPE_TIMEOUT)
        })
        .map_err(|_| Result::ApplicationStateAmbiguous)?;
    match write_result {
        Some(Ok(())) => Ok(Some(summary)),
        Some(Err(())) => Err(Result::IoFailed),
        None => Err(Result::ApplicationStateAmbiguous),
    }
}

#[cfg(feature = "experimental-repair-store")]
fn reserve_repair_backup(
    mounted: &MountedRescueVault,
    draft: &internal_wire::WorkerRepairDraft,
) -> Result<internal_wire::WorkerRepairStatus, internal_wire::WorkerResultCode> {
    let draft = StoreRepairBackupDraft::new(
        draft.session_id.clone(),
        draft.target_id.clone(),
        draft.target_fingerprint,
        draft.expected_backup_sha256,
        draft.metadata_sha256,
        draft.backup_size,
        draft.required_capacity_bytes,
    )
    .map_err(map_repair_store_error)?;
    let mut store = mounted
        .secrets()
        .open_repair_store()
        .map_err(map_repair_store_error)?;
    let reserved = store
        .reserve_backup(draft)
        .map_err(map_repair_store_error)?;
    repair_reserved_status(reserved.summary())
}

#[cfg(feature = "experimental-repair-store")]
fn persist_repair_backup(
    mounted: &MountedRescueVault,
    expected: &internal_wire::WorkerRepairStatus,
    binding: &internal_wire::WorkerRepairBinding,
    input_size: u64,
    source: OwnedFd,
) -> Result<internal_wire::WorkerRepairStatus, internal_wire::WorkerResultCode> {
    use internal_wire::{WorkerRepairState, WorkerResultCode as Result};
    if expected.state != WorkerRepairState::Reserved
        || expected.backup_size != input_size
        || binding.resource_sha256 != expected.expected_backup_sha256
    {
        return Err(Result::RepairInvalidRequest);
    }
    let reservation_id = StoreReservationId::parse(expected.reservation_id.clone())
        .map_err(map_repair_store_error)?;
    let mut store = mounted
        .secrets()
        .open_repair_store()
        .map_err(map_repair_store_error)?;
    let reserved = store
        .resume_reserved(
            &reservation_id,
            &encode_worker_sha256(expected.draft_binding_sha256),
        )
        .map_err(map_repair_store_error)?;
    let observed = repair_reserved_status(reserved.summary())?;
    if &observed != expected {
        return Err(Result::RepairConflict);
    }
    let expected_binding = binding.clone();
    let binding = StoreRepairBinding::new(
        binding.plan_id.clone(),
        binding.plan_sha256,
        binding.approval_id.clone(),
        binding.approval_sha256,
        binding.resource_id.clone(),
        binding.resource_sha256,
    )
    .map_err(map_repair_store_error)?;
    let source_deadline = Instant::now()
        .checked_add(APPLICATION_PIPE_TIMEOUT)
        .ok_or(Result::RepairStorageUnavailable)?;
    let durable = store
        .persist_backup_until(reserved, binding, source, source_deadline)
        .map_err(map_repair_store_error)?;
    let status = repair_durable_status(durable.metadata())?;
    if !status.immutable_fields_match(expected)
        || status.state != WorkerRepairState::Durable
        || status.binding.as_ref() != Some(&expected_binding)
    {
        return Err(Result::RepairConflict);
    }
    Ok(status)
}

#[cfg(feature = "experimental-repair-store")]
fn repair_backup_status(
    mounted: &MountedRescueVault,
    expected: &internal_wire::WorkerRepairStatus,
) -> Result<internal_wire::WorkerRepairStatus, internal_wire::WorkerResultCode> {
    use internal_wire::{WorkerRepairState, WorkerResultCode as Result};
    let reservation_id = StoreReservationId::parse(expected.reservation_id.clone())
        .map_err(map_repair_store_error)?;
    let store = mounted
        .secrets()
        .open_repair_store()
        .map_err(map_repair_store_error)?;
    let draft_binding = encode_worker_sha256(expected.draft_binding_sha256);
    let observed = match store
        .backup_status(&reservation_id, &draft_binding)
        .map_err(map_repair_store_error)?
    {
        StoreRepairBackupStatus::Absent => return Err(Result::RepairBackupNotFound),
        StoreRepairBackupStatus::Reserved(summary) => repair_reserved_status(&summary)?,
        StoreRepairBackupStatus::Durable(metadata) => repair_durable_status(&metadata)?,
        StoreRepairBackupStatus::ReconciliationRequired => {
            return Err(Result::RepairReconciliationRequired);
        }
    };
    if !observed.immutable_fields_match(expected)
        || expected.state == WorkerRepairState::Durable && &observed != expected
        || expected.state == WorkerRepairState::Durable
            && observed.state != WorkerRepairState::Durable
    {
        return Err(Result::RepairConflict);
    }
    Ok(observed)
}

#[cfg(feature = "experimental-repair-store")]
fn get_repair_backup(
    mounted: &MountedRescueVault,
    expected: &internal_wire::WorkerRepairStatus,
    output: OwnedFd,
) -> Result<internal_wire::WorkerRepairStatus, internal_wire::WorkerResultCode> {
    use internal_wire::{WorkerRepairState, WorkerResultCode as Result};
    if expected.state != WorkerRepairState::Durable {
        return Err(Result::RepairInvalidRequest);
    }
    let reservation_id = StoreReservationId::parse(expected.reservation_id.clone())
        .map_err(map_repair_store_error)?;
    let store = mounted
        .secrets()
        .open_repair_store()
        .map_err(map_repair_store_error)?;
    let draft_binding = encode_worker_sha256(expected.draft_binding_sha256);
    let status = match store
        .backup_status(&reservation_id, &draft_binding)
        .map_err(map_repair_store_error)?
    {
        StoreRepairBackupStatus::Absent => return Err(Result::RepairBackupNotFound),
        StoreRepairBackupStatus::Durable(metadata) => repair_durable_status(&metadata)?,
        StoreRepairBackupStatus::Reserved(_) => return Err(Result::RepairConflict),
        StoreRepairBackupStatus::ReconciliationRequired => {
            return Err(Result::RepairReconciliationRequired);
        }
    };
    if &status != expected {
        return Err(Result::RepairConflict);
    }
    let expected_size = expected.backup_size;
    let expected_hash = expected.expected_backup_sha256;
    let callback = store
        .with_verified_backup(&reservation_id, &draft_binding, |reader| {
            write_repair_output(
                output,
                reader,
                expected_size,
                expected_hash,
                Instant::now() + APPLICATION_PIPE_TIMEOUT,
            )
            .map_err(|_| RepairVaultStoreError::StorageUnavailable)
        })
        .map_err(map_repair_store_error)?;
    let final_status = repair_durable_status(&callback)?;
    if final_status != status {
        return Err(Result::RepairConflict);
    }
    Ok(status)
}

#[cfg(feature = "experimental-repair-store")]
fn repair_reserved_status(
    summary: &StoreRepairBackupSummary,
) -> Result<internal_wire::WorkerRepairStatus, internal_wire::WorkerResultCode> {
    Ok(internal_wire::WorkerRepairStatus {
        state: internal_wire::WorkerRepairState::Reserved,
        reservation_id: summary.reservation_id().as_str().to_owned(),
        draft_binding_sha256: parse_store_sha256(summary.reservation_binding_sha256())?,
        locator: summary.backup_locator().to_owned(),
        vault_id: summary.vault_id().to_owned(),
        vault_identity_fingerprint: parse_store_sha256(summary.vault_identity_fingerprint())?,
        physical_parent_fingerprint: parse_store_sha256(summary.physical_parent_fingerprint())?,
        reserved_bytes: summary.reserved_capacity_bytes(),
        backup_size: summary.backup_size_bytes(),
        expected_backup_sha256: parse_store_sha256(summary.expected_backup_sha256())?,
        metadata_sha256: parse_store_sha256(summary.metadata_sha256())?,
        binding: None,
    })
}

#[cfg(feature = "experimental-repair-store")]
fn repair_durable_status(
    metadata: &StoreVerifiedBackupMetadata,
) -> Result<internal_wire::WorkerRepairStatus, internal_wire::WorkerResultCode> {
    Ok(internal_wire::WorkerRepairStatus {
        state: internal_wire::WorkerRepairState::Durable,
        reservation_id: metadata.reservation_id().as_str().to_owned(),
        draft_binding_sha256: parse_store_sha256(metadata.reservation_binding_sha256())?,
        locator: metadata.backup_locator().to_owned(),
        vault_id: metadata.vault_id().to_owned(),
        vault_identity_fingerprint: parse_store_sha256(metadata.vault_identity_fingerprint())?,
        physical_parent_fingerprint: parse_store_sha256(metadata.physical_parent_fingerprint())?,
        reserved_bytes: metadata.reserved_capacity_bytes(),
        backup_size: metadata.backup_size_bytes(),
        expected_backup_sha256: parse_store_sha256(metadata.backup_sha256())?,
        metadata_sha256: parse_store_sha256(metadata.metadata_sha256())?,
        binding: Some(internal_wire::WorkerRepairBinding {
            plan_id: metadata.plan_id().to_owned(),
            plan_sha256: parse_store_sha256(metadata.plan_sha256())?,
            approval_id: metadata.approval_id().to_owned(),
            approval_sha256: parse_store_sha256(metadata.approval_sha256())?,
            resource_id: metadata.resource_id().to_owned(),
            resource_sha256: parse_store_sha256(metadata.resource_sha256())?,
        }),
    })
}

#[cfg(feature = "experimental-repair-store")]
fn parse_store_sha256(value: &str) -> Result<[u8; 32], internal_wire::WorkerResultCode> {
    let value = kernaid_protocol::rescue_vault::Sha256::parse(value)
        .map_err(|_| internal_wire::WorkerResultCode::RepairStorageUnavailable)?;
    internal_wire::decode_sha256(&value)
        .map_err(|_| internal_wire::WorkerResultCode::RepairStorageUnavailable)
}

#[cfg(feature = "experimental-repair-store")]
fn encode_worker_sha256(value: [u8; 32]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(64);
    for byte in value {
        output.push(char::from(HEX[usize::from(byte >> 4)]));
        output.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    output
}

#[cfg(feature = "experimental-repair-store")]
fn map_repair_store_error(error: RepairVaultStoreError) -> internal_wire::WorkerResultCode {
    use internal_wire::WorkerResultCode as Result;
    match error {
        RepairVaultStoreError::InvalidDraft
        | RepairVaultStoreError::InvalidBinding
        | RepairVaultStoreError::InvalidReservationId
        | RepairVaultStoreError::UnsafeSource
        | RepairVaultStoreError::SourceHashMismatch => Result::RepairInvalidRequest,
        RepairVaultStoreError::ReservationNotFound => Result::RepairBackupNotFound,
        RepairVaultStoreError::ReservationConflict
        | RepairVaultStoreError::ReservationNotReady
        | RepairVaultStoreError::ConcurrentWrite => Result::RepairConflict,
        RepairVaultStoreError::ReconciliationRequired => Result::RepairReconciliationRequired,
        RepairVaultStoreError::InsufficientCapacity
        | RepairVaultStoreError::PhysicalParentUnavailable
        | RepairVaultStoreError::CorruptJournal
        | RepairVaultStoreError::CorruptStore
        | RepairVaultStoreError::WriteVerificationFailed
        | RepairVaultStoreError::StorageUnavailable => Result::RepairStorageUnavailable,
    }
}

#[cfg(feature = "experimental-repair-store")]
fn write_repair_output(
    output: OwnedFd,
    reader: &mut dyn Read,
    expected_size: u64,
    expected_sha256: [u8; 32],
    deadline: Instant,
) -> Result<(), ()> {
    let expected = usize::try_from(expected_size)
        .ok()
        .filter(|size| (1..=MAX_REPAIR_BYTES).contains(size))
        .ok_or(())?;
    let status = rfs::fcntl_getfl(&output).map_err(|_| ())?;
    rfs::fcntl_setfl(&output, status | OFlags::NONBLOCK).map_err(|_| ())?;
    let mut written = 0_usize;
    let mut hasher = Sha256::new();
    let mut buffer = Zeroizing::new([0_u8; 8192]);
    while written < expected {
        let wanted = (expected - written).min(buffer.len());
        let read = reader.read(&mut buffer[..wanted]).map_err(|_| ())?;
        if read == 0 {
            return Err(());
        }
        hasher.update(&buffer[..read]);
        let mut offset = 0_usize;
        while offset < read {
            ensure_pipe_deadline(deadline)?;
            match rustix::io::write(&output, &buffer[offset..read]) {
                Ok(0) => return Err(()),
                Ok(size) => offset += size,
                Err(error) if error == rustix::io::Errno::INTR => {}
                Err(error) if error == rustix::io::Errno::AGAIN => {
                    wait_pipe_ready(output.as_fd(), PollFlags::OUT, deadline)?;
                }
                Err(_) => return Err(()),
            }
        }
        written += read;
    }
    let mut extra = [0_u8; 1];
    if reader.read(&mut extra).map_err(|_| ())? != 0
        || hasher.finalize().as_slice() != expected_sha256
    {
        return Err(());
    }
    drop(output);
    Ok(())
}

#[cfg(feature = "experimental-repair-store")]
fn validate_internal_repair_source_pipe(
    descriptor: BorrowedFd<'_>,
    expected_size: u64,
) -> Result<(), ()> {
    let stat = rfs::fstat(descriptor).map_err(|_| ())?;
    let filesystem = rfs::fstatfs(descriptor).map_err(|_| ())?;
    let status = rfs::fcntl_getfl(descriptor).map_err(|_| ())?;
    let flags = rustix::io::fcntl_getfd(descriptor).map_err(|_| ())?;
    if !(1..=MAX_REPAIR_BYTES as u64).contains(&expected_size)
        || !FileType::from_raw_mode(stat.st_mode).is_fifo()
        || u64::try_from(filesystem.f_type).ok() != Some(PIPEFS_MAGIC)
        || stat.st_size != 0
        || status & OFlags::ACCMODE != OFlags::RDONLY
        || flags != rustix::io::FdFlags::CLOEXEC
    {
        return Err(());
    }
    Ok(())
}

fn read_exact_application_pipe(
    descriptor: OwnedFd,
    expected: usize,
    deadline: Instant,
) -> Result<Zeroizing<Vec<u8>>, ()> {
    if !(2..=MAX_REPORT_INPUT_BYTES).contains(&expected) {
        return Err(());
    }
    let status = rfs::fcntl_getfl(&descriptor).map_err(|_| ())?;
    rfs::fcntl_setfl(&descriptor, status | OFlags::NONBLOCK).map_err(|_| ())?;
    let mut value = Zeroizing::new(Vec::with_capacity(expected));
    while value.len() < expected {
        ensure_pipe_deadline(deadline)?;
        let mut chunk = [0_u8; 8192];
        let remaining = expected - value.len();
        let chunk_size = remaining.min(chunk.len());
        match rustix::io::read(&descriptor, &mut chunk[..chunk_size]) {
            Ok(0) => return Err(()),
            Ok(read) => value.extend_from_slice(&chunk[..read]),
            Err(error) if error == rustix::io::Errno::INTR => {}
            Err(error) if error == rustix::io::Errno::AGAIN => {
                wait_pipe_ready(descriptor.as_fd(), PollFlags::IN, deadline)?;
            }
            Err(_) => return Err(()),
        }
    }
    require_pipe_eof(descriptor.as_fd(), deadline)?;
    Ok(value)
}

fn write_application_output(output: OwnedFd, value: &[u8], deadline: Instant) -> Result<(), ()> {
    if value.len() > MAX_REPORT_OUTPUT_BYTES {
        return Err(());
    }
    let status = rfs::fcntl_getfl(&output).map_err(|_| ())?;
    rfs::fcntl_setfl(&output, status | OFlags::NONBLOCK).map_err(|_| ())?;
    let mut written = 0_usize;
    while written < value.len() {
        ensure_pipe_deadline(deadline)?;
        match rustix::io::write(&output, &value[written..]) {
            Ok(0) => return Err(()),
            Ok(size) => written += size,
            Err(error) if error == rustix::io::Errno::INTR => {}
            Err(error) if error == rustix::io::Errno::AGAIN => {
                wait_pipe_ready(output.as_fd(), PollFlags::OUT, deadline)?;
            }
            Err(_) => return Err(()),
        }
    }
    drop(output);
    Ok(())
}

fn read_exact_openai_api_key(
    descriptor: OwnedFd,
    declared_size: u16,
    deadline: Instant,
) -> Result<Zeroizing<Vec<u8>>, ()> {
    let expected = usize::from(declared_size);
    if expected == 0
        || u64::from(declared_size) > kernaid_protocol::rescue_vault::MAX_OPENAI_KEY_BYTES
    {
        return Err(());
    }
    let status = rfs::fcntl_getfl(&descriptor).map_err(|_| ())?;
    rfs::fcntl_setfl(&descriptor, status | OFlags::NONBLOCK).map_err(|_| ())?;
    let mut value = Zeroizing::new(Vec::with_capacity(expected));
    while value.len() < expected {
        ensure_pipe_deadline(deadline)?;
        let mut buffer = Zeroizing::new([0_u8; 256]);
        let remaining = expected - value.len();
        let chunk = remaining.min(buffer.len());
        match rustix::io::read(&descriptor, &mut buffer[..chunk]) {
            Ok(0) => return Err(()),
            Ok(read) => value.extend_from_slice(&buffer[..read]),
            Err(error) if error == rustix::io::Errno::INTR => {}
            Err(error) if error == rustix::io::Errno::AGAIN => {
                wait_provider_pipe(descriptor.as_fd(), deadline)?;
            }
            Err(_) => return Err(()),
        }
    }
    loop {
        ensure_pipe_deadline(deadline)?;
        let mut extra = Zeroizing::new([0_u8; 1]);
        match rustix::io::read(&descriptor, &mut extra[..]) {
            Ok(0) => break,
            Ok(_) => return Err(()),
            Err(error) if error == rustix::io::Errno::INTR => {}
            Err(error) if error == rustix::io::Errno::AGAIN => {
                wait_provider_pipe(descriptor.as_fd(), deadline)?;
            }
            Err(_) => return Err(()),
        }
    }
    validate_openai_api_key_bytes(&value).map_err(|_| ())?;
    Ok(value)
}

fn ensure_pipe_deadline(deadline: Instant) -> Result<(), ()> {
    deadline
        .checked_duration_since(Instant::now())
        .filter(|remaining| !remaining.is_zero())
        .map(|_| ())
        .ok_or(())
}

fn require_pipe_eof(descriptor: BorrowedFd<'_>, deadline: Instant) -> Result<(), ()> {
    loop {
        ensure_pipe_deadline(deadline)?;
        let mut extra = [0_u8; 1];
        match rustix::io::read(descriptor, &mut extra) {
            Ok(0) => return Ok(()),
            Ok(_) => return Err(()),
            Err(error) if error == rustix::io::Errno::INTR => {}
            Err(error) if error == rustix::io::Errno::AGAIN => {
                wait_pipe_ready(descriptor, PollFlags::IN, deadline)?;
            }
            Err(_) => return Err(()),
        }
    }
}

fn wait_pipe_ready(
    descriptor: BorrowedFd<'_>,
    interest: PollFlags,
    deadline: Instant,
) -> Result<(), ()> {
    let remaining = deadline.checked_duration_since(Instant::now()).ok_or(())?;
    let mut descriptors = [PollFd::from_borrowed_fd(descriptor, interest)];
    let seconds = i64::try_from(remaining.as_secs()).unwrap_or(i64::MAX);
    let timeout = Timespec {
        tv_sec: seconds,
        tv_nsec: if seconds == i64::MAX {
            999_999_999
        } else {
            i64::from(remaining.subsec_nanos())
        },
    };
    match poll(&mut descriptors, Some(&timeout)) {
        Ok(0) => Err(()),
        Ok(_) if descriptors[0].revents().contains(PollFlags::NVAL) => Err(()),
        Ok(_) => Ok(()),
        Err(error) if error == rustix::io::Errno::INTR => Ok(()),
        Err(_) => Err(()),
    }
}

fn wait_provider_pipe(descriptor: BorrowedFd<'_>, deadline: Instant) -> Result<(), ()> {
    wait_pipe_ready(descriptor, PollFlags::IN, deadline)
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
    let mapper = fresh_mapper_name().map_err(|_| Code::UnlockIoMapperName)?;
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
                Ok(()) => Err(Code::UnlockIoApplicationStore),
                Err(_) => Err(Code::CleanupFailed),
            };
        }
    };
    if kernaid_device_identity::validate_device_id(&device_id).is_err() {
        return match mounted.shutdown() {
            Ok(()) => Err(Code::UnlockIoDeviceId),
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
        ProbeError::ClassifierUnavailable => Result::UnlockIoProbeClassifier,
        ProbeError::IoFailed => Result::UnlockIoProbe,
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
        VaultMountManagerError::UnsupportedPlatform => Result::UnlockIoUnsupportedPlatform,
        VaultMountManagerError::PrivilegeRequired => Result::UnlockIoPrivilegeRequired,
        VaultMountManagerError::InvalidMapperName => Result::UnlockIoInvalidMapperName,
        VaultMountManagerError::ClassifierUnavailable => Result::UnlockIoClassifierUnavailable,
        VaultMountManagerError::PassphraseUnavailable => Result::UnlockIoPassphraseUnavailable,
        VaultMountManagerError::ProvisioningFormatFailed
        | VaultMountManagerError::ProvisioningInitializationFailed => {
            Result::UnlockIoSecureStateUnavailable
        }
        VaultMountManagerError::UnsupportedFilesystem => Result::UnlockIoUnsupportedFilesystem,
        VaultMountManagerError::UnsafeMountRoot => Result::UnlockIoUnsafeMountRoot,
        VaultMountManagerError::MountFailed => Result::UnlockIoMountFailed,
        VaultMountManagerError::MountVerificationFailed => Result::UnlockIoMountVerificationFailed,
        VaultMountManagerError::SecureStateUnavailable => Result::UnlockIoSecureStateUnavailable,
        VaultMountManagerError::ToolUnavailable => Result::UnlockIoToolUnavailable,
    }
}

fn validate_internal_secret_pipe(descriptor: BorrowedFd<'_>) -> Result<(), ()> {
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

fn validate_internal_output_pipe(descriptor: BorrowedFd<'_>) -> Result<(), ()> {
    let stat = rfs::fstat(descriptor).map_err(|_| ())?;
    let filesystem = rfs::fstatfs(descriptor).map_err(|_| ())?;
    let filesystem_type = u64::try_from(filesystem.f_type).map_err(|_| ())?;
    let status = rfs::fcntl_getfl(descriptor).map_err(|_| ())?;
    let descriptor_flags = rustix::io::fcntl_getfd(descriptor).map_err(|_| ())?;
    let capacity = rustix::pipe::fcntl_getpipe_size(descriptor).map_err(|_| ())?;
    if !FileType::from_raw_mode(stat.st_mode).is_fifo()
        || filesystem_type != PIPEFS_MAGIC
        || status != (OFlags::WRONLY | OFlags::NONBLOCK)
        || descriptor_flags != rustix::io::FdFlags::CLOEXEC
        || stat.st_size != 0
        || capacity < MAX_PROVIDER_OUTPUT_BYTES
    {
        return Err(());
    }
    Ok(())
}

fn validate_internal_application_output_pipe(descriptor: BorrowedFd<'_>) -> Result<(), ()> {
    let stat = rfs::fstat(descriptor).map_err(|_| ())?;
    let filesystem = rfs::fstatfs(descriptor).map_err(|_| ())?;
    let filesystem_type = u64::try_from(filesystem.f_type).map_err(|_| ())?;
    let status = rfs::fcntl_getfl(descriptor).map_err(|_| ())?;
    let descriptor_flags = rustix::io::fcntl_getfd(descriptor).map_err(|_| ())?;
    if !FileType::from_raw_mode(stat.st_mode).is_fifo()
        || filesystem_type != PIPEFS_MAGIC
        || status != OFlags::WRONLY
        || descriptor_flags != rustix::io::FdFlags::CLOEXEC
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
    fn internal_secret_descriptor_requires_read_only_pipefs_cloexec() {
        let (read, write) = pipe_with(PipeFlags::CLOEXEC).expect("pipe");
        assert_eq!(validate_internal_secret_pipe(read.as_fd()), Ok(()));
        assert_eq!(validate_internal_secret_pipe(write.as_fd()), Err(()));

        let (plain_read, _plain_write) = pipe_with(PipeFlags::empty()).expect("plain pipe");
        assert_eq!(validate_internal_secret_pipe(plain_read.as_fd()), Err(()));
    }

    #[test]
    fn internal_provider_output_requires_nonblocking_write_only_pipefs_cloexec() {
        let (read, write) =
            pipe_with(PipeFlags::CLOEXEC | PipeFlags::NONBLOCK).expect("output pipe");
        assert_eq!(validate_internal_output_pipe(write.as_fd()), Ok(()));
        assert_eq!(validate_internal_output_pipe(read.as_fd()), Err(()));

        let (_blocking_read, blocking_write) =
            pipe_with(PipeFlags::CLOEXEC).expect("blocking pipe");
        assert_eq!(
            validate_internal_output_pipe(blocking_write.as_fd()),
            Err(())
        );

        let (_plain_read, plain_write) = pipe_with(PipeFlags::NONBLOCK).expect("non-cloexec pipe");
        assert_eq!(validate_internal_output_pipe(plain_write.as_fd()), Err(()));

        let directory = tempfile::tempdir().expect("endpoint matrix directory");
        let fifo_path = directory.path().join("named-fifo");
        rfs::mkfifoat(
            rustix::fs::CWD,
            &fifo_path,
            rustix::fs::Mode::from_raw_mode(0o600),
        )
        .expect("named fifo");
        let _fifo_reader = rfs::open(
            &fifo_path,
            OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NONBLOCK,
            rustix::fs::Mode::empty(),
        )
        .expect("named fifo reader");
        let fifo_writer = rfs::open(
            &fifo_path,
            OFlags::WRONLY | OFlags::CLOEXEC | OFlags::NONBLOCK,
            rustix::fs::Mode::empty(),
        )
        .expect("named fifo writer");
        assert_eq!(validate_internal_output_pipe(fifo_writer.as_fd()), Err(()));

        let regular_path = directory.path().join("regular");
        let regular = rfs::open(
            &regular_path,
            OFlags::CREATE | OFlags::EXCL | OFlags::WRONLY | OFlags::CLOEXEC | OFlags::NONBLOCK,
            rustix::fs::Mode::from_raw_mode(0o600),
        )
        .expect("regular file");
        assert_eq!(validate_internal_output_pipe(regular.as_fd()), Err(()));

        let (socket, _peer) = rustix::net::socketpair(
            rustix::net::AddressFamily::UNIX,
            rustix::net::SocketType::STREAM,
            rustix::net::SocketFlags::CLOEXEC | rustix::net::SocketFlags::NONBLOCK,
            None,
        )
        .expect("socket pair");
        assert_eq!(validate_internal_output_pipe(socket.as_fd()), Err(()));
    }

    #[test]
    fn internal_application_output_requires_blocking_write_only_anonymous_pipe() {
        let (read, write) = pipe_with(PipeFlags::CLOEXEC).expect("application output pipe");
        assert_eq!(
            validate_internal_application_output_pipe(write.as_fd()),
            Ok(())
        );
        assert_eq!(
            validate_internal_application_output_pipe(read.as_fd()),
            Err(())
        );

        let (_read, nonblocking) =
            pipe_with(PipeFlags::CLOEXEC | PipeFlags::NONBLOCK).expect("nonblocking pipe");
        assert_eq!(
            validate_internal_application_output_pipe(nonblocking.as_fd()),
            Err(())
        );
    }

    #[test]
    fn application_pipe_input_is_exact_and_output_closes_at_eof() {
        let body = br#"{"report":"TEST_ONLY"}"#;
        let (read, write) = pipe_with(PipeFlags::CLOEXEC).expect("report input");
        rustix::io::write(&write, body).expect("write report input");
        drop(write);
        let observed =
            read_exact_application_pipe(read, body.len(), Instant::now() + Duration::from_secs(1))
                .expect("exact report input");
        assert_eq!(observed.as_slice(), body);

        let (extra_read, extra_write) = pipe_with(PipeFlags::CLOEXEC).expect("extra input");
        rustix::io::write(&extra_write, b"{}x").expect("write extra input");
        drop(extra_write);
        assert!(
            read_exact_application_pipe(extra_read, 2, Instant::now() + Duration::from_secs(1))
                .is_err()
        );

        let (output_read, output_write) = pipe_with(PipeFlags::CLOEXEC).expect("report output");
        write_application_output(output_write, body, Instant::now() + Duration::from_secs(1))
            .expect("write report output");
        assert_eq!(
            rustix::io::ioctl_fionread(output_read.as_fd()),
            Ok(body.len() as u64)
        );
        let mut bytes = vec![0_u8; body.len()];
        assert_eq!(
            rustix::io::read(output_read.as_fd(), &mut bytes),
            Ok(body.len())
        );
        assert_eq!(bytes, body);
        assert_eq!(rustix::io::read(output_read.as_fd(), &mut [0_u8; 1]), Ok(0));
    }

    #[test]
    fn provider_output_is_one_bounded_write_without_supervisor_readback() {
        let (read, write) =
            pipe_with(PipeFlags::CLOEXEC | PipeFlags::NONBLOCK).expect("output pipe");
        assert!(write_openai_key_once(write.as_fd(), &[]).is_err());
        assert!(write_openai_key_once(write.as_fd(), &[b' '; 1]).is_err());
        let synthetic = [b'X'; 32];
        assert_eq!(write_openai_key_once(write.as_fd(), &synthetic), Ok(32));
        assert_eq!(rustix::io::ioctl_fionread(read.as_fd()), Ok(32));
        drop(write);
        let zero = Timespec {
            tv_sec: 0,
            tv_nsec: 0,
        };
        let mut descriptors = [PollFd::from_borrowed_fd(read.as_fd(), PollFlags::HUP)];
        assert_eq!(poll(&mut descriptors, Some(&zero)), Ok(1));
        assert!(descriptors[0].revents().contains(PollFlags::HUP));
        let mut observed = [0_u8; 32];
        assert_eq!(rustix::io::read(read.as_fd(), &mut observed), Ok(32));
        assert!(
            observed == synthetic,
            "synthetic provider output changed during the bounded write"
        );
        let mut eof = [0_u8; 1];
        assert_eq!(rustix::io::read(read.as_fd(), &mut eof), Ok(0));
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
        assert_eq!(
            map_probe_unlock_error(ProbeError::ClassifierUnavailable),
            internal_wire::WorkerResultCode::UnlockIoProbeClassifier
        );
        assert_eq!(
            map_probe_unlock_error(ProbeError::IoFailed),
            internal_wire::WorkerResultCode::UnlockIoProbe
        );
        for (error, code) in [
            (
                VaultMountManagerError::UnsupportedPlatform,
                internal_wire::WorkerResultCode::UnlockIoUnsupportedPlatform,
            ),
            (
                VaultMountManagerError::PrivilegeRequired,
                internal_wire::WorkerResultCode::UnlockIoPrivilegeRequired,
            ),
            (
                VaultMountManagerError::InvalidMapperName,
                internal_wire::WorkerResultCode::UnlockIoInvalidMapperName,
            ),
            (
                VaultMountManagerError::ClassifierUnavailable,
                internal_wire::WorkerResultCode::UnlockIoClassifierUnavailable,
            ),
            (
                VaultMountManagerError::PassphraseUnavailable,
                internal_wire::WorkerResultCode::UnlockIoPassphraseUnavailable,
            ),
            (
                VaultMountManagerError::UnsupportedFilesystem,
                internal_wire::WorkerResultCode::UnlockIoUnsupportedFilesystem,
            ),
            (
                VaultMountManagerError::UnsafeMountRoot,
                internal_wire::WorkerResultCode::UnlockIoUnsafeMountRoot,
            ),
            (
                VaultMountManagerError::MountFailed,
                internal_wire::WorkerResultCode::UnlockIoMountFailed,
            ),
            (
                VaultMountManagerError::MountVerificationFailed,
                internal_wire::WorkerResultCode::UnlockIoMountVerificationFailed,
            ),
            (
                VaultMountManagerError::SecureStateUnavailable,
                internal_wire::WorkerResultCode::UnlockIoSecureStateUnavailable,
            ),
            (
                VaultMountManagerError::ToolUnavailable,
                internal_wire::WorkerResultCode::UnlockIoToolUnavailable,
            ),
        ] {
            assert_eq!(
                map_manager_error(error),
                code,
                "wrong mapping for {error:?}"
            );
        }
    }

    #[test]
    fn mapper_names_are_fresh_and_match_the_closed_lower_hex_grammar() {
        let first = fresh_mapper_name().expect("first mapper");
        let second = fresh_mapper_name().expect("second mapper");
        assert_ne!(first, second);
        assert!(format!("{first:?}").contains("validated"));
    }

    #[test]
    fn provider_key_pipe_is_exact_eof_bounded_and_visible_ascii_only() {
        fn pipe_bytes(bytes: &[u8], keep_writer: bool) -> (OwnedFd, Option<OwnedFd>) {
            let (read, write) = pipe_with(PipeFlags::CLOEXEC).expect("pipe");
            rustix::io::write(&write, bytes).expect("write synthetic bytes");
            if keep_writer {
                (read, Some(write))
            } else {
                drop(write);
                (read, None)
            }
        }

        let bytes = b"VISIBLE_TEST_ONLY";
        let (valid, _) = pipe_bytes(bytes, false);
        let value = read_exact_openai_api_key(
            valid,
            u16::try_from(bytes.len()).expect("bounded length"),
            Instant::now() + Duration::from_secs(1),
        )
        .expect("valid key bytes");
        assert_eq!(value.len(), bytes.len());
        assert!(value.iter().all(u8::is_ascii_graphic));

        let (short, _) = pipe_bytes(b"SHORT", false);
        assert!(
            read_exact_openai_api_key(short, 6, Instant::now() + Duration::from_millis(100))
                .is_err()
        );
        let (extra, _) = pipe_bytes(b"EXTRA", false);
        assert!(
            read_exact_openai_api_key(extra, 4, Instant::now() + Duration::from_millis(100))
                .is_err()
        );
        let (control, _) = pipe_bytes(b"BAD KEY", false);
        assert!(
            read_exact_openai_api_key(control, 7, Instant::now() + Duration::from_millis(100))
                .is_err()
        );
        let (open, writer) = pipe_bytes(b"OPEN", true);
        assert!(
            read_exact_openai_api_key(open, 4, Instant::now() + Duration::from_millis(20)).is_err()
        );
        drop(writer);
    }

    #[test]
    fn provider_mutation_reconciliation_distinguishes_desired_prior_and_third_state() {
        let prior = Some([1_u8; 32]);
        let desired = Some([2_u8; 32]);
        assert_eq!(
            classify_provider_mutation(prior, desired, desired, false),
            ProviderMutationDisposition::Applied
        );
        assert_eq!(
            classify_provider_mutation(prior, desired, prior, false),
            ProviderMutationDisposition::Aborted
        );
        assert_eq!(
            classify_provider_mutation(prior, desired, Some([3_u8; 32]), false),
            ProviderMutationDisposition::Ambiguous
        );
        assert_eq!(
            classify_provider_mutation(prior, desired, prior, true),
            ProviderMutationDisposition::Ambiguous
        );
        assert_eq!(
            classify_provider_mutation(prior, None, None, false),
            ProviderMutationDisposition::Applied
        );
    }
}
