use super::{
    RescueVaultDaemonError, enforce_process_privacy, group_has_exact_openai_boundaries,
    internal_wire, passwd_has_exact_companion, passwd_openai_agent_uid,
    runtime::{
        self, DaemonRuntime, ProcessScope, ProviderProcessBoundary, RuntimeDisposition,
        WorkerCgroup, WorkerHandle, WorkerSpawnResult,
    },
    validate_no_active_swap,
};
#[cfg(feature = "experimental-codex-home-lease")]
use super::{group_has_exact_codex_boundaries, passwd_has_exact_codex_agent};
use kernaid_protocol::rescue_vault::{
    AgentRole, DescriptorDeclaration, DescriptorType, ErrorToken, MAX_INITIAL_STATE_VERSION,
    MAX_SAFE_JSON_INTEGER, Operation, PeerAllowlist, Provider, ProviderState,
    ProviderStatusPayload, RequestDecodeError, RequestPayload, ServerReceiveError, SuccessPayload,
    ValidatedRequest, VaultState, VaultStatusPayload, authenticate_seqpacket_peer,
    gate_operation_for_vault_state, validate_passphrase_read,
};
use nix::sys::signal::{SigSet, Signal};
use nix::sys::socket::{getsockopt, sockopt};
use rand_core::{OsRng, RngCore};
use rustix::{
    event::{PollFd, PollFlags, Timespec, poll},
    fd::{AsFd, BorrowedFd, OwnedFd},
    fs::{self as rfs, FileType, OFlags},
    net::{
        AddressFamily, RecvFlags, SendFlags, SocketAddrUnix, SocketFlags, SocketType, accept_with,
        recv, sendto, socket_with, socketpair,
    },
    pipe::{PipeFlags, pipe_with},
    process::{Signal as ProcessSignal, pidfd_send_signal},
};
use std::{
    env,
    ffi::OsStr,
    io,
    os::unix::ffi::OsStrExt,
    path::Path,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
    },
    thread::{self, JoinHandle},
    time::{Duration, Instant},
};
use zeroize::Zeroizing;

const CONNECTION_LIMIT: usize = 16;
const CONNECTION_TIMEOUT: Duration = Duration::from_secs(3);
const ACCEPT_POLL_SLICE: Duration = Duration::from_millis(200);
const CLIENT_PIPE_TIMEOUT: Duration = Duration::from_secs(15);
const WORKER_OPERATION_TIMEOUT: Duration = Duration::from_secs(10 * 60);
const WORKER_STARTUP_TIMEOUT: Duration = Duration::from_secs(10);
const PROVIDER_BORROW_TIMEOUT: Duration = Duration::from_secs(20);
const PROVIDER_LEASE_TIMEOUT: Duration = Duration::from_secs(120);
const LEASE_REVOCATION_TIMEOUT: Duration = Duration::from_secs(10);
const SHUTDOWN_TIMEOUT: Duration = Duration::from_secs(110);
const READINESS_NOTIFICATION_TIMEOUT: Duration = Duration::from_secs(3);
const UNLOCK_RATE_LIMIT: Duration = Duration::from_secs(2);
const CONTROL_SOCKET_PATH: &str = "/run/kernaid-rescue-vault.sock";
const NOTIFY_SOCKET_ENV: &str = "NOTIFY_SOCKET";
const READY_NOTIFICATION: &[u8] = b"READY=1";
const MAX_NOTIFY_SOCKET_BYTES: usize = 108;
const PASSWD_FILE_PATH: &str = "/etc/passwd";
const GROUP_FILE_PATH: &str = "/etc/group";
const LISTENER_GROUP_NAME: &[u8] = b"kernaid-vault";
const GROUP_FILE_LIMIT: usize = 1024 * 1024;

#[derive(Clone, Debug, PartialEq, Eq)]
enum Availability {
    Available {
        state: VaultState,
        device_id: Option<String>,
    },
    Unavailable(ErrorToken),
}

#[derive(Debug)]
struct ServiceState {
    version: u64,
    availability: Availability,
    transition_origin: Option<Availability>,
    provider_operation_active: bool,
    last_unlock_attempt: Option<Instant>,
    faulted: bool,
    fault_marker_required: bool,
    marker_persistence_failed: bool,
    clean_fault_shutdown: bool,
}

#[derive(Clone, Debug)]
struct Snapshot {
    version: u64,
    availability: Availability,
}

struct Supervisor {
    state: Mutex<ServiceState>,
    lifecycle: Mutex<()>,
    runtime: Mutex<Box<dyn RuntimeBoundary>>,
    worker: Option<Arc<dyn WorkerBoundary>>,
    privacy: Arc<dyn PrivacyBoundary>,
    leases: Mutex<LeaseRegistry>,
    faulted: AtomicBool,
    stopping: Arc<AtomicBool>,
    stop_deadline: Arc<Mutex<Option<Instant>>>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum LeaseState {
    Pending,
    PotentiallyIssued,
    Established,
    Revoking,
}

struct ProviderLease {
    id: u64,
    socket: OwnedFd,
    pidfd: OwnedFd,
    peer_pid: i32,
    process: ProviderProcessBoundary,
    state: LeaseState,
    handoff_deadline: Instant,
    lease_deadline: Option<Instant>,
    output_obligation: Arc<LeaseOutputState>,
}

struct LeaseRegistry {
    next_id: u64,
    active: Option<ProviderLease>,
}

impl Default for LeaseRegistry {
    fn default() -> Self {
        Self {
            next_id: 1,
            active: None,
        }
    }
}

struct LeaseCandidate {
    socket: OwnedFd,
    pidfd: OwnedFd,
    peer_pid: i32,
    process: ProviderProcessBoundary,
}

struct LeaseSnapshot {
    id: u64,
    socket: OwnedFd,
    pidfd: OwnedFd,
    process: ProviderProcessBoundary,
    deadline: Instant,
    output_obligation: Arc<LeaseOutputState>,
}

struct LeaseOutputState {
    finalized: AtomicBool,
}

struct LeaseOutputGuard {
    descriptor: Option<OwnedFd>,
    state: Arc<LeaseOutputState>,
}

impl LeaseOutputGuard {
    fn new(state: Arc<LeaseOutputState>) -> Self {
        Self {
            descriptor: None,
            state,
        }
    }

    fn adopt(&mut self, descriptor: OwnedFd) -> Result<(), OwnedFd> {
        if self.descriptor.is_some() {
            return Err(descriptor);
        }
        self.descriptor = Some(descriptor);
        Ok(())
    }

    fn descriptor(&self) -> Option<BorrowedFd<'_>> {
        self.descriptor.as_ref().map(AsFd::as_fd)
    }
}

impl Drop for LeaseOutputGuard {
    fn drop(&mut self) {
        // Close every supervisor-owned credential descriptor before publishing
        // finalization. Revocation may remove the lease only after observing
        // this release-store in addition to peer HUP, pidfd exit, and whole
        // process-scope quiescence.
        drop(self.descriptor.take());
        self.state.finalized.store(true, Ordering::Release);
    }
}

trait PrivacyBoundary: Send + Sync {
    fn validate_no_active_swap(&self) -> Result<(), ()>;
}

struct ProcPrivacyBoundary;

impl PrivacyBoundary for ProcPrivacyBoundary {
    fn validate_no_active_swap(&self) -> Result<(), ()> {
        validate_no_active_swap()
    }
}

trait RuntimeBoundary: Send {
    fn arm_lifecycle(&mut self) -> Result<(), RescueVaultDaemonError>;
    fn disarm_after_verified_locked(&mut self) -> Result<(), RescueVaultDaemonError>;
    fn sync_and_verify_disarmed(&mut self) -> Result<(), RescueVaultDaemonError>;
}

impl RuntimeBoundary for DaemonRuntime {
    fn arm_lifecycle(&mut self) -> Result<(), RescueVaultDaemonError> {
        DaemonRuntime::arm_lifecycle(self)
    }

    fn disarm_after_verified_locked(&mut self) -> Result<(), RescueVaultDaemonError> {
        DaemonRuntime::disarm_after_verified_locked(self)
    }

    fn sync_and_verify_disarmed(&mut self) -> Result<(), RescueVaultDaemonError> {
        DaemonRuntime::sync_and_verify_disarmed(self)
    }
}

trait WorkerBoundary: Send + Sync {
    fn transact(
        &self,
        kind: internal_wire::WorkerCommandKind,
        passphrase_size: Option<u16>,
        descriptor: Option<OwnedFd>,
        deadline: Instant,
    ) -> Result<(internal_wire::WorkerResponse, Option<OwnedFd>), RescueVaultDaemonError>;
    fn borrow_openai(
        &self,
        deadline: Instant,
    ) -> Result<(internal_wire::WorkerResponse, Option<OwnedFd>), RescueVaultDaemonError>;
    #[cfg(feature = "experimental-codex-home-lease")]
    fn lease_codex_home(
        &self,
        deadline: Instant,
    ) -> Result<(internal_wire::WorkerResponse, Option<OwnedFd>), RescueVaultDaemonError>;
    fn verify_healthy(&self) -> Result<(), RescueVaultDaemonError>;
    fn exited(&self) -> Result<bool, RescueVaultDaemonError>;
    fn fault_and_terminate(&self, deadline: Instant) -> Result<(), RescueVaultDaemonError>;
    fn cancel_clean(&self, deadline: Instant) -> Result<(), RescueVaultDaemonError>;
    fn shutdown_clean(&self, deadline: Instant) -> Result<(), RescueVaultDaemonError>;
}

impl WorkerBoundary for WorkerHandle {
    fn transact(
        &self,
        kind: internal_wire::WorkerCommandKind,
        passphrase_size: Option<u16>,
        descriptor: Option<OwnedFd>,
        deadline: Instant,
    ) -> Result<(internal_wire::WorkerResponse, Option<OwnedFd>), RescueVaultDaemonError> {
        WorkerHandle::transact(self, kind, passphrase_size, descriptor, deadline)
    }

    fn borrow_openai(
        &self,
        deadline: Instant,
    ) -> Result<(internal_wire::WorkerResponse, Option<OwnedFd>), RescueVaultDaemonError> {
        WorkerHandle::borrow_openai(self, deadline)
    }

    #[cfg(feature = "experimental-codex-home-lease")]
    fn lease_codex_home(
        &self,
        deadline: Instant,
    ) -> Result<(internal_wire::WorkerResponse, Option<OwnedFd>), RescueVaultDaemonError> {
        WorkerHandle::lease_codex_home(self, deadline)
    }

    fn verify_healthy(&self) -> Result<(), RescueVaultDaemonError> {
        WorkerHandle::verify_healthy(self)
    }

    fn exited(&self) -> Result<bool, RescueVaultDaemonError> {
        WorkerHandle::exited(self)
    }

    fn fault_and_terminate(&self, deadline: Instant) -> Result<(), RescueVaultDaemonError> {
        WorkerHandle::fault_and_terminate(self, deadline)
    }

    fn cancel_clean(&self, deadline: Instant) -> Result<(), RescueVaultDaemonError> {
        WorkerHandle::cancel_clean(self, deadline)
    }

    fn shutdown_clean(&self, deadline: Instant) -> Result<(), RescueVaultDaemonError> {
        WorkerHandle::shutdown_clean(self, deadline)
    }
}

#[derive(Clone)]
struct StopControl {
    requested: Arc<AtomicBool>,
    first_requested_at: Arc<Mutex<Option<Instant>>>,
    deadline: Arc<Mutex<Option<Instant>>>,
}

enum WorkerStartup {
    Ready {
        worker: Arc<WorkerHandle>,
        availability: Availability,
    },
    Faulted {
        worker: Option<Arc<WorkerHandle>>,
        untracked_worker_may_remain: bool,
    },
    Unavailable(RescueVaultDaemonError),
    CancelledClean,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum StartupReadiness {
    Ready,
    Stopping,
    Failed,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct FaultContainment {
    marker_durable: bool,
    worker_quiesced: bool,
}

impl FaultContainment {
    fn permits_status_service(self) -> bool {
        self.marker_durable && self.worker_quiesced
    }
}

enum SystemdNotifier {
    Disabled,
    Enabled(SocketAddrUnix),
}

impl SystemdNotifier {
    fn from_environment() -> Result<Self, RescueVaultDaemonError> {
        Self::from_value(env::var_os(NOTIFY_SOCKET_ENV).as_deref())
    }

    fn from_value(value: Option<&OsStr>) -> Result<Self, RescueVaultDaemonError> {
        let Some(value) = value else {
            return Ok(Self::Disabled);
        };
        let bytes = value.as_bytes();
        if bytes.is_empty() || bytes.len() > MAX_NOTIFY_SOCKET_BYTES || bytes.contains(&0) {
            return Err(RescueVaultDaemonError::InvalidConfiguration);
        }
        let address = match bytes[0] {
            b'/' => SocketAddrUnix::new(Path::new(value)),
            b'@' if bytes.len() > 1 => SocketAddrUnix::new_abstract_name(&bytes[1..]),
            _ => return Err(RescueVaultDaemonError::InvalidConfiguration),
        }
        .map_err(|_| RescueVaultDaemonError::InvalidConfiguration)?;
        Ok(Self::Enabled(address))
    }

    fn notify_ready_by(&self, deadline: Instant) -> Result<(), RescueVaultDaemonError> {
        let Self::Enabled(address) = self else {
            return Ok(());
        };
        send_readiness_notification(address, deadline)
    }
}

impl StopControl {
    fn new() -> Self {
        Self {
            requested: Arc::new(AtomicBool::new(false)),
            first_requested_at: Arc::new(Mutex::new(None)),
            deadline: Arc::new(Mutex::new(None)),
        }
    }

    fn request(&self) {
        let requested_at = Instant::now();
        self.request_at(requested_at);
    }

    fn request_at(&self, requested_at: Instant) {
        let Ok(mut first_requested_at) = self.first_requested_at.lock() else {
            return;
        };
        let first = first_requested_at.map_or(requested_at, |first| first.min(requested_at));
        *first_requested_at = Some(first);
        let Ok(mut deadline) = self.deadline.lock() else {
            return;
        };
        let requested_deadline = first.checked_add(SHUTDOWN_TIMEOUT).unwrap_or(first);
        *deadline = Some(deadline.map_or(requested_deadline, |current| {
            current.min(requested_deadline)
        }));
        self.requested.store(true, Ordering::Release);
    }

    fn deadline_or(&self, fallback: Instant) -> Instant {
        self.deadline
            .lock()
            .ok()
            .and_then(|deadline| *deadline)
            .unwrap_or(fallback)
    }
}

pub(super) fn run(companion_uid: u32) -> Result<(), RescueVaultDaemonError> {
    enforce_process_privacy().map_err(|()| RescueVaultDaemonError::RuntimeUnavailable)?;
    let notifier = SystemdNotifier::from_environment()?;
    let signal_set = block_termination_signals()?;
    let stop = StopControl::new();
    spawn_signal_waiter(signal_set, stop.clone())?;
    let allowlist = validated_peer_allowlist(companion_uid)?;
    let listener = take_listener()?;
    let (mut daemon_runtime, disposition) = DaemonRuntime::open()?;
    let seed = state_version_seed()?;
    let mut parent_capabilities_narrowed = false;
    let mut parent_capability_failure = false;

    let (worker, availability, startup_fault, untracked_worker_may_remain) = match disposition {
        RuntimeDisposition::PersistentFault => (None, faulted_availability(), true, false),
        RuntimeDisposition::Ready => match start_worker(
            &stop,
            &mut parent_capabilities_narrowed,
            &mut parent_capability_failure,
        ) {
            WorkerStartup::Ready {
                worker,
                availability,
            } => (Some(worker), availability, false, false),
            WorkerStartup::Faulted {
                worker,
                untracked_worker_may_remain,
            } => (
                worker,
                faulted_availability(),
                true,
                untracked_worker_may_remain,
            ),
            WorkerStartup::Unavailable(error) => return Err(error),
            WorkerStartup::CancelledClean => return Ok(()),
        },
    };
    let capabilities_ready = !parent_capability_failure
        && (parent_capabilities_narrowed || runtime::narrow_supervisor_capabilities().is_ok())
        && runtime::verify_all_supervisor_threads_capabilities().is_ok()
        && peer_pidfd_capability_probe().is_ok();
    if !capabilities_ready {
        let deadline = stop.deadline_or(Instant::now() + SHUTDOWN_TIMEOUT);
        let worker_quiesced = !untracked_worker_may_remain
            && worker
                .as_ref()
                .is_none_or(|worker| worker.fault_and_terminate(deadline).is_ok());
        let marker_durable = daemon_runtime.arm_lifecycle().is_ok();
        return Err(if worker_quiesced && marker_durable {
            RescueVaultDaemonError::RuntimeUnavailable
        } else {
            RescueVaultDaemonError::ShutdownFailed
        });
    }
    let supervisor = Arc::new(Supervisor {
        state: Mutex::new(ServiceState {
            version: seed,
            availability,
            transition_origin: None,
            provider_operation_active: false,
            last_unlock_attempt: None,
            faulted: startup_fault,
            fault_marker_required: startup_fault,
            marker_persistence_failed: false,
            clean_fault_shutdown: false,
        }),
        lifecycle: Mutex::new(()),
        runtime: Mutex::new(Box::new(daemon_runtime)),
        worker: worker.map(|worker| -> Arc<dyn WorkerBoundary> { worker }),
        privacy: Arc::new(ProcPrivacyBoundary),
        leases: Mutex::new(LeaseRegistry::default()),
        faulted: AtomicBool::new(startup_fault),
        stopping: Arc::clone(&stop.requested),
        stop_deadline: Arc::clone(&stop.deadline),
    });
    let fault_containment = if startup_fault && disposition == RuntimeDisposition::Ready {
        let mut containment = supervisor.mark_fault();
        if untracked_worker_may_remain {
            containment.worker_quiesced = false;
        }
        containment
    } else {
        FaultContainment {
            marker_durable: true,
            worker_quiesced: true,
        }
    };
    let readiness = supervisor.startup_readiness(fault_containment, disposition);
    let readiness_result = publish_readiness(&notifier, readiness, &stop);
    match readiness {
        StartupReadiness::Ready => match readiness_result {
            Ok(true) => {}
            Ok(false) => {
                let deadline = stop.deadline_or(
                    Instant::now()
                        .checked_add(SHUTDOWN_TIMEOUT)
                        .unwrap_or_else(Instant::now),
                );
                return supervisor.shutdown(deadline);
            }
            Err(readiness_error) => {
                return shutdown_after_readiness_failure(&supervisor, &stop, readiness_error);
            }
        },
        StartupReadiness::Stopping => {
            let deadline = stop.deadline_or(
                Instant::now()
                    .checked_add(SHUTDOWN_TIMEOUT)
                    .unwrap_or_else(Instant::now),
            );
            return supervisor.shutdown(deadline);
        }
        StartupReadiness::Failed => {
            stop.request();
            let deadline = stop.deadline_or(
                Instant::now()
                    .checked_add(SHUTDOWN_TIMEOUT)
                    .unwrap_or_else(Instant::now),
            );
            return match supervisor.shutdown(deadline) {
                Ok(()) => Err(RescueVaultDaemonError::RuntimeUnavailable),
                Err(error) => Err(error),
            };
        }
    }

    let serve_result = serve_connections(listener, allowlist, Arc::clone(&supervisor), &stop);
    stop.requested.store(true, Ordering::Release);
    match serve_result {
        Ok(deadline) => supervisor.shutdown(deadline),
        Err(error) => {
            if !supervisor.faulted.load(Ordering::Acquire) {
                supervisor.mark_fault();
            }
            Err(error)
        }
    }
}

fn start_worker(
    stop: &StopControl,
    parent_capabilities_narrowed: &mut bool,
    parent_capability_failure: &mut bool,
) -> WorkerStartup {
    if stop.requested.load(Ordering::Acquire) {
        return WorkerStartup::CancelledClean;
    }
    let cgroup = match WorkerCgroup::prepare() {
        Ok(cgroup) => cgroup,
        Err(error) => return WorkerStartup::Unavailable(error),
    };
    if stop.requested.load(Ordering::Acquire) {
        let deadline = stop.deadline_or(Instant::now() + SHUTDOWN_TIMEOUT);
        return if cgroup.remove_empty(deadline).is_ok() {
            WorkerStartup::CancelledClean
        } else {
            WorkerStartup::Faulted {
                worker: None,
                untracked_worker_may_remain: false,
            }
        };
    }
    let bootstrap_deadline = Instant::now() + WORKER_STARTUP_TIMEOUT;
    let worker = match WorkerHandle::spawn(cgroup, bootstrap_deadline, &stop.requested) {
        Ok(WorkerSpawnResult::Ready(worker)) => worker,
        Ok(WorkerSpawnResult::CancelledClean) => return WorkerStartup::CancelledClean,
        Err(_) => {
            return WorkerStartup::Faulted {
                worker: None,
                // WorkerHandle::spawn performs bounded cleanup, but its
                // error does not prove that reap/cgroup cleanup completed.
                untracked_worker_may_remain: true,
            };
        }
    };
    if runtime::narrow_supervisor_capabilities().is_err()
        || runtime::verify_all_supervisor_threads_capabilities().is_err()
    {
        *parent_capability_failure = true;
        return WorkerStartup::Faulted {
            worker: Some(worker),
            untracked_worker_may_remain: false,
        };
    }
    *parent_capabilities_narrowed = true;
    if stop.requested.load(Ordering::Acquire) {
        return cancel_startup_worker(worker, stop);
    }
    let probe_deadline = Instant::now()
        .checked_add(WORKER_OPERATION_TIMEOUT)
        .unwrap_or_else(Instant::now);
    let response = worker.transact_cancellable(
        internal_wire::WorkerCommandKind::Probe,
        None,
        None,
        probe_deadline,
        Some(&stop.requested),
    );
    if stop.requested.load(Ordering::Acquire) {
        return cancel_startup_worker(worker, stop);
    }
    match response {
        Ok((response, None)) => match probe_availability(response.code) {
            Ok(availability) => WorkerStartup::Ready {
                worker,
                availability,
            },
            Err(()) => {
                let _ = worker.fault_and_terminate(probe_deadline);
                WorkerStartup::Faulted {
                    worker: Some(worker),
                    untracked_worker_may_remain: false,
                }
            }
        },
        Ok((_, Some(_))) | Err(_) => {
            let _ = worker.fault_and_terminate(probe_deadline);
            WorkerStartup::Faulted {
                worker: Some(worker),
                untracked_worker_may_remain: false,
            }
        }
    }
}

fn cancel_startup_worker(worker: Arc<WorkerHandle>, stop: &StopControl) -> WorkerStartup {
    let deadline = stop.deadline_or(Instant::now() + SHUTDOWN_TIMEOUT);
    if worker.cancel_clean(deadline).is_ok() {
        WorkerStartup::CancelledClean
    } else {
        WorkerStartup::Faulted {
            worker: Some(worker),
            untracked_worker_may_remain: false,
        }
    }
}

fn probe_availability(code: internal_wire::WorkerResultCode) -> Result<Availability, ()> {
    use internal_wire::WorkerResultCode as Result;
    match code {
        Result::ProbeAbsent => Ok(available(VaultState::Absent, None)),
        Result::ProbeUnprovisioned => Ok(available(VaultState::Unprovisioned, None)),
        Result::ProbeLocked => Ok(available(VaultState::Locked, None)),
        Result::ProbeProfileMismatch => Ok(Availability::Unavailable(ErrorToken::ProfileMismatch)),
        Result::ProbeClassifierUnavailable | Result::ProbeIoFailed => {
            Ok(Availability::Unavailable(ErrorToken::IoFailed))
        }
        Result::TimedOut | Result::CleanupFailed => Err(()),
        _ => Err(()),
    }
}

fn faulted_availability() -> Availability {
    available(VaultState::FaultedRebootRequired, None)
}

fn available(state: VaultState, device_id: Option<String>) -> Availability {
    Availability::Available { state, device_id }
}

fn take_listener() -> Result<OwnedFd, RescueVaultDaemonError> {
    let listener_gid = lookup_listener_group()?;
    let stdin = io::stdin();
    rustix::io::fcntl_setfd(stdin.as_fd(), rustix::io::FdFlags::CLOEXEC)
        .map_err(|_| RescueVaultDaemonError::InvalidListener)?;
    let listener = rustix::io::fcntl_dupfd_cloexec(stdin.as_fd(), 3)
        .map_err(|_| RescueVaultDaemonError::InvalidListener)?;
    let status =
        rfs::fcntl_getfl(&listener).map_err(|_| RescueVaultDaemonError::InvalidListener)?;
    rfs::fcntl_setfl(&listener, status | OFlags::NONBLOCK)
        .map_err(|_| RescueVaultDaemonError::InvalidListener)?;
    validate_listener(listener.as_fd(), listener_gid)?;
    Ok(listener)
}

fn validate_listener(
    listener: BorrowedFd<'_>,
    listener_gid: u32,
) -> Result<(), RescueVaultDaemonError> {
    let descriptor_flags =
        rustix::io::fcntl_getfd(listener).map_err(|_| RescueVaultDaemonError::InvalidListener)?;
    let status_flags =
        rfs::fcntl_getfl(listener).map_err(|_| RescueVaultDaemonError::InvalidListener)?;
    let stat = rfs::fstat(listener).map_err(|_| RescueVaultDaemonError::InvalidListener)?;
    let run = rfs::statat(rfs::CWD, "/run", rfs::AtFlags::SYMLINK_NOFOLLOW)
        .map_err(|_| RescueVaultDaemonError::InvalidListener)?;
    let named = rfs::statat(
        rfs::CWD,
        CONTROL_SOCKET_PATH,
        rfs::AtFlags::SYMLINK_NOFOLLOW,
    )
    .map_err(|_| RescueVaultDaemonError::InvalidListener)?;
    let address: SocketAddrUnix = rustix::net::getsockname(listener)
        .map_err(|_| RescueVaultDaemonError::InvalidListener)?
        .try_into()
        .map_err(|_| RescueVaultDaemonError::InvalidListener)?;
    let unconnected = matches!(
        rustix::net::getpeername(listener),
        Err(error) if error == rustix::io::Errno::NOTCONN
    );
    if rustix::net::sockopt::socket_domain(listener)
        .map_err(|_| RescueVaultDaemonError::InvalidListener)?
        != AddressFamily::UNIX
        || rustix::net::sockopt::socket_type(listener)
            .map_err(|_| RescueVaultDaemonError::InvalidListener)?
            != SocketType::SEQPACKET
        || !rustix::net::sockopt::socket_acceptconn(listener)
            .map_err(|_| RescueVaultDaemonError::InvalidListener)?
        || !descriptor_flags.contains(rustix::io::FdFlags::CLOEXEC)
        || !status_flags.contains(OFlags::NONBLOCK)
        || !FileType::from_raw_mode(stat.st_mode).is_socket()
        // This is the independent sockfs creator identity. The filesystem
        // pathname has its own root:kernaid-vault metadata below; its GID is
        // intentionally not compared with the sockfs inode GID.
        || stat.st_uid != 0
        || !FileType::from_raw_mode(run.st_mode).is_dir()
        || run.st_uid != 0
        || run.st_gid != 0
        || run.st_mode & 0o022 != 0
        || !FileType::from_raw_mode(named.st_mode).is_socket()
        || named.st_uid != 0
        || named.st_gid != listener_gid
        || named.st_nlink != 1
        || named.st_mode & 0o7777 != 0o660
        || named.st_dev != run.st_dev
        || address.path_bytes() != Some(CONTROL_SOCKET_PATH.as_bytes())
        || !unconnected
        || rustix::net::sockopt::socket_passcred(listener)
            .map_err(|_| RescueVaultDaemonError::InvalidListener)?
    {
        return Err(RescueVaultDaemonError::InvalidListener);
    }
    Ok(())
}

fn validated_peer_allowlist(companion_uid: u32) -> Result<PeerAllowlist, RescueVaultDaemonError> {
    let descriptor = rfs::openat2(
        rfs::CWD,
        PASSWD_FILE_PATH,
        OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NOFOLLOW,
        rfs::Mode::empty(),
        rfs::ResolveFlags::NO_SYMLINKS | rfs::ResolveFlags::NO_MAGICLINKS,
    )
    .map_err(|_| RescueVaultDaemonError::InvalidConfiguration)?;
    let stat = rfs::fstat(&descriptor).map_err(|_| RescueVaultDaemonError::InvalidConfiguration)?;
    if !FileType::from_raw_mode(stat.st_mode).is_file()
        || stat.st_uid != 0
        || stat.st_gid != 0
        || stat.st_nlink != 1
        || stat.st_mode & 0o022 != 0
    {
        return Err(RescueVaultDaemonError::InvalidConfiguration);
    }
    let bytes = read_file_bounded(descriptor.as_fd(), GROUP_FILE_LIMIT)?;
    if !passwd_has_exact_companion(&bytes, companion_uid) {
        return Err(RescueVaultDaemonError::InvalidConfiguration);
    }
    #[cfg(feature = "experimental-codex-home-lease")]
    if !passwd_has_exact_codex_agent(&bytes, companion_uid) {
        return Err(RescueVaultDaemonError::InvalidConfiguration);
    }
    let agent_uid = passwd_openai_agent_uid(&bytes, companion_uid)
        .ok_or(RescueVaultDaemonError::InvalidConfiguration)?;
    validate_openai_agent_groups(agent_uid)?;
    #[cfg(feature = "experimental-codex-home-lease")]
    validate_codex_agent_groups()?;
    let builder = PeerAllowlist::builder(companion_uid)
        .agent(AgentRole::OpenAi, agent_uid)
        .map_err(|_| RescueVaultDaemonError::InvalidConfiguration)?;
    #[cfg(feature = "experimental-codex-home-lease")]
    let builder = builder
        .agent(AgentRole::Codex, crate::CODEX_AGENT_UID)
        .map_err(|_| RescueVaultDaemonError::InvalidConfiguration)?;
    builder
        .build()
        .map_err(|_| RescueVaultDaemonError::InvalidConfiguration)
}

#[cfg(feature = "experimental-codex-home-lease")]
fn validate_codex_agent_groups() -> Result<(), RescueVaultDaemonError> {
    let descriptor = rfs::openat2(
        rfs::CWD,
        GROUP_FILE_PATH,
        OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NOFOLLOW,
        rfs::Mode::empty(),
        rfs::ResolveFlags::NO_SYMLINKS | rfs::ResolveFlags::NO_MAGICLINKS,
    )
    .map_err(|_| RescueVaultDaemonError::InvalidConfiguration)?;
    let stat = rfs::fstat(&descriptor).map_err(|_| RescueVaultDaemonError::InvalidConfiguration)?;
    if !FileType::from_raw_mode(stat.st_mode).is_file()
        || stat.st_uid != 0
        || stat.st_gid != 0
        || stat.st_nlink != 1
        || stat.st_mode & 0o022 != 0
    {
        return Err(RescueVaultDaemonError::InvalidConfiguration);
    }
    let bytes = read_file_bounded(descriptor.as_fd(), GROUP_FILE_LIMIT)?;
    if !group_has_exact_codex_boundaries(&bytes) {
        return Err(RescueVaultDaemonError::InvalidConfiguration);
    }
    Ok(())
}

fn validate_openai_agent_groups(agent_uid: u32) -> Result<(), RescueVaultDaemonError> {
    let descriptor = rfs::openat2(
        rfs::CWD,
        GROUP_FILE_PATH,
        OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NOFOLLOW,
        rfs::Mode::empty(),
        rfs::ResolveFlags::NO_SYMLINKS | rfs::ResolveFlags::NO_MAGICLINKS,
    )
    .map_err(|_| RescueVaultDaemonError::InvalidConfiguration)?;
    let stat = rfs::fstat(&descriptor).map_err(|_| RescueVaultDaemonError::InvalidConfiguration)?;
    if !FileType::from_raw_mode(stat.st_mode).is_file()
        || stat.st_uid != 0
        || stat.st_gid != 0
        || stat.st_nlink != 1
        || stat.st_mode & 0o022 != 0
    {
        return Err(RescueVaultDaemonError::InvalidConfiguration);
    }
    let bytes = read_file_bounded(descriptor.as_fd(), GROUP_FILE_LIMIT)?;
    if !group_has_exact_openai_boundaries(&bytes, agent_uid) {
        return Err(RescueVaultDaemonError::InvalidConfiguration);
    }
    Ok(())
}

fn lookup_listener_group() -> Result<u32, RescueVaultDaemonError> {
    let descriptor = rfs::openat2(
        rfs::CWD,
        GROUP_FILE_PATH,
        OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NOFOLLOW,
        rfs::Mode::empty(),
        rfs::ResolveFlags::NO_SYMLINKS | rfs::ResolveFlags::NO_MAGICLINKS,
    )
    .map_err(|_| RescueVaultDaemonError::InvalidConfiguration)?;
    let stat = rfs::fstat(&descriptor).map_err(|_| RescueVaultDaemonError::InvalidConfiguration)?;
    if !FileType::from_raw_mode(stat.st_mode).is_file()
        || stat.st_uid != 0
        || stat.st_gid != 0
        || stat.st_nlink != 1
        || stat.st_mode & 0o022 != 0
    {
        return Err(RescueVaultDaemonError::InvalidConfiguration);
    }
    let bytes = read_file_bounded(descriptor.as_fd(), GROUP_FILE_LIMIT)?;
    let mut entries: Vec<(&[u8], u32)> = Vec::new();
    for line in bytes
        .split(|byte| *byte == b'\n')
        .filter(|line| !line.is_empty())
    {
        if line.len() > 4096 || line.contains(&0) {
            return Err(RescueVaultDaemonError::InvalidConfiguration);
        }
        let fields: Vec<&[u8]> = line.split(|byte| *byte == b':').collect();
        if fields.len() != 4 {
            return Err(RescueVaultDaemonError::InvalidConfiguration);
        }
        if fields[0].is_empty()
            || fields[2].is_empty()
            || !fields[2].iter().all(u8::is_ascii_digit)
            || (fields[2].len() > 1 && fields[2][0] == b'0')
        {
            return Err(RescueVaultDaemonError::InvalidConfiguration);
        }
        let gid = std::str::from_utf8(fields[2])
            .ok()
            .and_then(|value| value.parse::<u32>().ok())
            .ok_or(RescueVaultDaemonError::InvalidConfiguration)?;
        entries.push((fields[0], gid));
    }
    let mut named = entries
        .iter()
        .filter(|(name, _)| *name == LISTENER_GROUP_NAME);
    let gid = named
        .next()
        .map(|(_, gid)| *gid)
        .ok_or(RescueVaultDaemonError::InvalidConfiguration)?;
    if gid == 0
        || named.next().is_some()
        || entries
            .iter()
            .filter(|(_, candidate)| *candidate == gid)
            .count()
            != 1
    {
        return Err(RescueVaultDaemonError::InvalidConfiguration);
    }
    Ok(gid)
}

fn read_file_bounded(
    descriptor: BorrowedFd<'_>,
    maximum: usize,
) -> Result<Vec<u8>, RescueVaultDaemonError> {
    let mut bytes = Vec::new();
    let mut buffer = [0_u8; 4096];
    loop {
        match rustix::io::read(descriptor, &mut buffer) {
            Ok(0) => return Ok(bytes),
            Ok(read) if bytes.len().saturating_add(read) <= maximum => {
                bytes.extend_from_slice(&buffer[..read]);
            }
            Ok(_) => return Err(RescueVaultDaemonError::InvalidConfiguration),
            Err(error) if error == rustix::io::Errno::INTR => {}
            Err(_) => return Err(RescueVaultDaemonError::InvalidConfiguration),
        }
    }
}

fn block_termination_signals() -> Result<SigSet, RescueVaultDaemonError> {
    let mut signals = SigSet::empty();
    signals.add(Signal::SIGINT);
    signals.add(Signal::SIGTERM);
    signals
        .thread_block()
        .map_err(|_| RescueVaultDaemonError::RuntimeUnavailable)?;
    Ok(signals)
}

fn spawn_signal_waiter(signals: SigSet, stop: StopControl) -> Result<(), RescueVaultDaemonError> {
    let (ready_tx, ready_rx) = std::sync::mpsc::sync_channel(0);
    thread::spawn(move || {
        let ready = runtime::narrow_supervisor_capabilities().is_ok()
            && runtime::verify_current_supervisor_capabilities().is_ok();
        if ready_tx.send(ready).is_err() || !ready {
            return;
        }
        run_signal_waiter(signals, stop, || true);
    });
    match ready_rx.recv_timeout(CONNECTION_TIMEOUT) {
        Ok(true) => Ok(()),
        Ok(false) | Err(_) => Err(RescueVaultDaemonError::RuntimeUnavailable),
    }
}

fn run_signal_waiter(signals: SigSet, stop: StopControl, keep_running: impl Fn() -> bool) {
    while keep_running() {
        match signals.wait() {
            Ok(_) => stop.request(),
            Err(_) => {
                // Keep this already-narrowed task alive after a sigwait
                // failure. Main will observe the stop request and exit;
                // allowing the task to disappear could make the exact
                // all-thread capability attestation race a clean stop.
                stop.request();
                while keep_running() {
                    thread::park_timeout(ACCEPT_POLL_SLICE);
                }
            }
        }
    }
}

fn state_version_seed() -> Result<u64, RescueVaultDaemonError> {
    for _ in 0..8 {
        let mut bytes = [0_u8; 8];
        OsRng
            .try_fill_bytes(&mut bytes)
            .map_err(|_| RescueVaultDaemonError::RuntimeUnavailable)?;
        let seed = u64::from_le_bytes(bytes) & MAX_INITIAL_STATE_VERSION;
        if seed != 0 {
            return Ok(seed);
        }
    }
    Err(RescueVaultDaemonError::RuntimeUnavailable)
}

fn publish_readiness(
    notifier: &SystemdNotifier,
    readiness: StartupReadiness,
    stop: &StopControl,
) -> Result<bool, RescueVaultDaemonError> {
    if readiness != StartupReadiness::Ready {
        return Ok(false);
    }
    let deadline = Instant::now()
        .checked_add(READINESS_NOTIFICATION_TIMEOUT)
        .ok_or(RescueVaultDaemonError::RuntimeUnavailable)?;
    publish_readiness_by(notifier, readiness, stop, deadline)
}

fn publish_readiness_by(
    notifier: &SystemdNotifier,
    readiness: StartupReadiness,
    stop: &StopControl,
    deadline: Instant,
) -> Result<bool, RescueVaultDaemonError> {
    publish_readiness_with(readiness, stop, || notifier.notify_ready_by(deadline))
}

fn publish_readiness_with(
    readiness: StartupReadiness,
    stop: &StopControl,
    publish: impl FnOnce() -> Result<(), RescueVaultDaemonError>,
) -> Result<bool, RescueVaultDaemonError> {
    if readiness != StartupReadiness::Ready {
        return Ok(false);
    }
    let _linearization = stop
        .deadline
        .lock()
        .map_err(|_| RescueVaultDaemonError::RuntimeUnavailable)?;
    if stop.requested.load(Ordering::Acquire) {
        return Ok(false);
    }
    publish()?;
    Ok(true)
}

fn shutdown_after_readiness_failure(
    supervisor: &Supervisor,
    stop: &StopControl,
    readiness_error: RescueVaultDaemonError,
) -> Result<(), RescueVaultDaemonError> {
    stop.request();
    let deadline = stop.deadline_or(
        Instant::now()
            .checked_add(SHUTDOWN_TIMEOUT)
            .unwrap_or_else(Instant::now),
    );
    match supervisor.shutdown(deadline) {
        Ok(()) => Err(readiness_error),
        Err(shutdown_error) => Err(shutdown_error),
    }
}

fn send_readiness_notification(
    address: &SocketAddrUnix,
    deadline: Instant,
) -> Result<(), RescueVaultDaemonError> {
    ensure_before(deadline).map_err(|()| RescueVaultDaemonError::RuntimeUnavailable)?;
    let socket = open_notification_socket()?;
    loop {
        ensure_before(deadline).map_err(|()| RescueVaultDaemonError::RuntimeUnavailable)?;
        match sendto(
            &socket,
            READY_NOTIFICATION,
            SendFlags::DONTWAIT | SendFlags::NOSIGNAL,
            address,
        ) {
            Ok(sent) if sent == READY_NOTIFICATION.len() => return Ok(()),
            Ok(_) => return Err(RescueVaultDaemonError::RuntimeUnavailable),
            Err(error) if error == rustix::io::Errno::INTR => {}
            Err(error) if error == rustix::io::Errno::AGAIN => {
                wait_notification_writable(socket.as_fd(), deadline)?;
            }
            Err(_) => return Err(RescueVaultDaemonError::RuntimeUnavailable),
        }
    }
}

fn open_notification_socket() -> Result<OwnedFd, RescueVaultDaemonError> {
    let socket = socket_with(
        AddressFamily::UNIX,
        SocketType::DGRAM,
        SocketFlags::CLOEXEC | SocketFlags::NONBLOCK,
        None,
    )
    .map_err(|_| RescueVaultDaemonError::RuntimeUnavailable)?;
    let descriptor_flags =
        rustix::io::fcntl_getfd(&socket).map_err(|_| RescueVaultDaemonError::RuntimeUnavailable)?;
    let status_flags =
        rfs::fcntl_getfl(&socket).map_err(|_| RescueVaultDaemonError::RuntimeUnavailable)?;
    if !descriptor_flags.contains(rustix::io::FdFlags::CLOEXEC)
        || !status_flags.contains(OFlags::NONBLOCK)
        || rustix::net::sockopt::socket_domain(&socket)
            .map_err(|_| RescueVaultDaemonError::RuntimeUnavailable)?
            != AddressFamily::UNIX
        || rustix::net::sockopt::socket_type(&socket)
            .map_err(|_| RescueVaultDaemonError::RuntimeUnavailable)?
            != SocketType::DGRAM
        || rustix::net::sockopt::socket_acceptconn(&socket)
            .map_err(|_| RescueVaultDaemonError::RuntimeUnavailable)?
    {
        return Err(RescueVaultDaemonError::RuntimeUnavailable);
    }
    Ok(socket)
}

fn wait_notification_writable(
    socket: BorrowedFd<'_>,
    deadline: Instant,
) -> Result<(), RescueVaultDaemonError> {
    loop {
        let remaining = deadline
            .checked_duration_since(Instant::now())
            .filter(|remaining| !remaining.is_zero())
            .ok_or(RescueVaultDaemonError::RuntimeUnavailable)?;
        let mut descriptor = [PollFd::from_borrowed_fd(socket, PollFlags::OUT)];
        match poll(&mut descriptor, Some(&duration_to_timespec(remaining))) {
            Ok(0) => return Err(RescueVaultDaemonError::RuntimeUnavailable),
            Ok(_) => {
                let events = descriptor[0].revents();
                if events.intersects(PollFlags::ERR | PollFlags::HUP | PollFlags::NVAL) {
                    return Err(RescueVaultDaemonError::RuntimeUnavailable);
                }
                if events.contains(PollFlags::OUT) {
                    return Ok(());
                }
            }
            Err(error) if error == rustix::io::Errno::INTR => {}
            Err(_) => return Err(RescueVaultDaemonError::RuntimeUnavailable),
        }
    }
}

fn serve_connections(
    listener: OwnedFd,
    allowlist: PeerAllowlist,
    supervisor: Arc<Supervisor>,
    stop: &StopControl,
) -> Result<Instant, RescueVaultDaemonError> {
    let mut handlers: Vec<JoinHandle<()>> = Vec::new();
    let mut terminal_error = None;
    'serving: while !stop.requested.load(Ordering::Acquire) {
        reap_handlers(&mut handlers, &supervisor);
        if supervisor.sweep_expired_lease().is_err() {
            terminal_error = Some(RescueVaultDaemonError::ShutdownFailed);
            break;
        }
        if let Some(worker) = supervisor.worker.as_ref()
            && !supervisor.faulted.load(Ordering::Acquire)
        {
            match worker.exited() {
                Ok(true) => {
                    terminal_error = Some(RescueVaultDaemonError::WorkerUnavailable);
                    break;
                }
                Ok(false) => {}
                Err(error) => {
                    terminal_error = Some(error);
                    break;
                }
            }
        }
        if let Err(error) = wait_listener(listener.as_fd()) {
            terminal_error = Some(error);
            break;
        }
        loop {
            if stop.requested.load(Ordering::Acquire) {
                break;
            }
            match accept_with(&listener, SocketFlags::CLOEXEC | SocketFlags::NONBLOCK) {
                Ok(connection) if handlers.len() < CONNECTION_LIMIT => {
                    let supervisor = Arc::clone(&supervisor);
                    handlers.push(thread::spawn(move || {
                        handle_connection(connection, allowlist, supervisor);
                    }));
                }
                Ok(_) => {}
                Err(error) if error == rustix::io::Errno::AGAIN => break,
                Err(error) if error == rustix::io::Errno::INTR => continue,
                Err(_) => {
                    terminal_error = Some(RescueVaultDaemonError::InvalidListener);
                    break 'serving;
                }
            }
        }
    }
    stop.request();
    drop(listener);
    let deadline = stop.deadline_or(Instant::now() + SHUTDOWN_TIMEOUT);
    let revoke_deadline = Instant::now()
        .checked_add(LEASE_REVOCATION_TIMEOUT)
        .unwrap_or(deadline)
        .min(deadline);
    let revoke_failed = supervisor.revoke_active_lease(revoke_deadline).is_err();
    if revoke_failed {
        terminal_error = Some(RescueVaultDaemonError::ShutdownFailed);
    }
    let fault_reserved = terminal_error.is_some();
    if fault_reserved {
        let containment = supervisor.mark_fault_by(deadline);
        if !containment.permits_status_service() {
            terminal_error = Some(RescueVaultDaemonError::ShutdownFailed);
        }
    }
    while !handlers.is_empty() {
        reap_handlers(&mut handlers, &supervisor);
        if !handlers.is_empty() && Instant::now() >= deadline {
            terminal_error = Some(RescueVaultDaemonError::ShutdownFailed);
            break;
        }
        if !handlers.is_empty() {
            thread::sleep(Duration::from_millis(10));
        }
    }
    if let Some(error) = terminal_error {
        Err(error)
    } else {
        Ok(deadline)
    }
}

fn reap_handlers(handlers: &mut Vec<JoinHandle<()>>, supervisor: &Supervisor) {
    let mut index = 0;
    while index < handlers.len() {
        if handlers[index].is_finished() {
            let handler = handlers.swap_remove(index);
            if handler.join().is_err() {
                supervisor.mark_fault();
            }
        } else {
            index += 1;
        }
    }
}

fn wait_listener(listener: BorrowedFd<'_>) -> Result<(), RescueVaultDaemonError> {
    let mut descriptor = [PollFd::from_borrowed_fd(listener, PollFlags::IN)];
    let timeout = duration_to_timespec(ACCEPT_POLL_SLICE);
    match poll(&mut descriptor, Some(&timeout)) {
        Ok(_) if descriptor[0].revents().contains(PollFlags::NVAL) => {
            Err(RescueVaultDaemonError::InvalidListener)
        }
        Ok(_) => Ok(()),
        Err(error) if error == rustix::io::Errno::INTR => Ok(()),
        Err(_) => Err(RescueVaultDaemonError::InvalidListener),
    }
}

fn handle_connection(connection: OwnedFd, allowlist: PeerAllowlist, supervisor: Arc<Supervisor>) {
    handle_connection_by(connection, allowlist, supervisor, true);
}

fn handle_connection_by(
    connection: OwnedFd,
    allowlist: PeerAllowlist,
    supervisor: Arc<Supervisor>,
    validate_production_socket: bool,
) {
    if supervisor.stopping.load(Ordering::Acquire) {
        return;
    }
    if validate_production_socket && validate_accepted_connection(connection.as_fd()).is_err() {
        return;
    }
    let peer = match authenticate_seqpacket_peer(connection.as_fd(), allowlist) {
        Ok(peer) => peer,
        Err(_) => return,
    };
    let receive_deadline = Instant::now() + CONNECTION_TIMEOUT;
    let request = match peer.receive_request(receive_deadline) {
        Ok(request) => request,
        Err(ServerReceiveError::Decode(RequestDecodeError::Reject(rejected))) => {
            let version = supervisor.snapshot().version;
            let _ = peer.send_rejection(&rejected, version, Instant::now() + CONNECTION_TIMEOUT);
            return;
        }
        Err(_) => return,
    };
    let mutation = matches!(
        request.operation(),
        Operation::VaultUnlock
            | Operation::VaultLock
            | Operation::ProviderOpenAiConfigure
            | Operation::ProviderLogout
    );
    let started = Instant::now();
    let (version, result) = supervisor.handle_connected_request(
        request,
        started,
        ClientConnection::Socket(connection.as_fd()),
    );
    let send_deadline = if mutation {
        let operation_deadline = started
            .checked_add(WORKER_OPERATION_TIMEOUT)
            .unwrap_or(started);
        Instant::now()
            .checked_add(CONNECTION_TIMEOUT)
            .unwrap_or(operation_deadline)
            .min(operation_deadline)
    } else {
        Instant::now()
            .checked_add(CONNECTION_TIMEOUT)
            .unwrap_or_else(Instant::now)
    };
    match result {
        HandlerResult::Success(request, payload) => {
            let _ = peer.send_success(&request, version, &payload, &[], send_deadline);
        }
        HandlerResult::Descriptor {
            request,
            payload,
            output,
            lease_id,
            handoff_deadline,
        } => {
            let descriptor_send_deadline = send_deadline.min(handoff_deadline);
            let sent = match output.descriptor() {
                Some(descriptor) => supervisor.send_provider_descriptor(lease_id, || {
                    peer.send_success(
                        &request,
                        version,
                        &payload,
                        &[descriptor],
                        descriptor_send_deadline,
                    )
                    .is_ok()
                }),
                None => Err(RescueVaultDaemonError::PersistentFault),
            };
            // Publish the output-finalized latch only after the supervisor's
            // credential read descriptor is closed. Revocation and lock wait
            // for this latch in addition to Agent HUP, pidfd exit, and whole
            // process-scope quiescence.
            drop(output);
            match sent {
                Ok(DescriptorSend::Established) => {
                    if supervisor.monitor_provider_lease(lease_id).is_err() {
                        supervisor.mark_fault();
                    }
                }
                Ok(DescriptorSend::RevocationRequired(snapshot)) => {
                    if supervisor.finish_provider_revocation(snapshot).is_err() {
                        supervisor.mark_fault();
                    }
                }
                Ok(DescriptorSend::RevocationInProgress) => {}
                Err(_) => {
                    supervisor.mark_fault();
                }
            }
        }
        HandlerResult::Error(request, error) => {
            let _ = peer.send_error(&request, version, error, send_deadline);
        }
        HandlerResult::Drop => {}
    }
}

fn validate_accepted_connection(connection: BorrowedFd<'_>) -> Result<(), RescueVaultDaemonError> {
    let descriptor =
        rustix::io::fcntl_getfd(connection).map_err(|_| RescueVaultDaemonError::ProtocolFailure)?;
    let status =
        rfs::fcntl_getfl(connection).map_err(|_| RescueVaultDaemonError::ProtocolFailure)?;
    let address: SocketAddrUnix = rustix::net::getsockname(connection)
        .map_err(|_| RescueVaultDaemonError::ProtocolFailure)?
        .try_into()
        .map_err(|_| RescueVaultDaemonError::ProtocolFailure)?;
    if !descriptor.contains(rustix::io::FdFlags::CLOEXEC)
        || !status.contains(OFlags::NONBLOCK)
        || rustix::net::sockopt::socket_domain(connection)
            .map_err(|_| RescueVaultDaemonError::ProtocolFailure)?
            != AddressFamily::UNIX
        || rustix::net::sockopt::socket_type(connection)
            .map_err(|_| RescueVaultDaemonError::ProtocolFailure)?
            != SocketType::SEQPACKET
        || rustix::net::sockopt::socket_acceptconn(connection)
            .map_err(|_| RescueVaultDaemonError::ProtocolFailure)?
        || rustix::net::getpeername(connection).is_err()
        || address.path_bytes() != Some(CONTROL_SOCKET_PATH.as_bytes())
        || rustix::net::sockopt::socket_passcred(connection)
            .map_err(|_| RescueVaultDaemonError::ProtocolFailure)?
    {
        return Err(RescueVaultDaemonError::ProtocolFailure);
    }
    Ok(())
}

fn socket_client_is_live(connection: BorrowedFd<'_>) -> bool {
    let mut byte = [0_u8; 1];
    matches!(
        recv(connection, &mut byte, RecvFlags::PEEK | RecvFlags::DONTWAIT),
        Err(error) if error == rustix::io::Errno::AGAIN
    )
}

enum HandlerResult {
    Success(ValidatedRequest, SuccessPayload),
    Descriptor {
        request: ValidatedRequest,
        payload: SuccessPayload,
        output: LeaseOutputGuard,
        lease_id: u64,
        handoff_deadline: Instant,
    },
    Error(ValidatedRequest, ErrorToken),
    Drop,
}

enum DispatchArm {
    Armed,
    StoppedBeforeArm,
    StoppedAfterArm,
    ClientGoneBeforeArm,
    ClientGoneAfterArm,
}

enum ProviderDispatchArm {
    Armed,
    RevocationInProgress,
    StoppedBeforeArm,
    ClientGoneBeforeArm,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum LeaseWait {
    Released,
    Deadline,
}

enum PotentialIssue {
    Armed(LeaseOutputGuard),
    CancelledBeforeSecret,
    RevocationInProgress,
}

enum PendingCancel {
    CancelledHere(u64),
    RevocationInProgress,
}

enum DescriptorSend {
    Established,
    RevocationRequired(LeaseSnapshot),
    RevocationInProgress,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ProviderLeaseKind {
    OpenAi,
    #[cfg(feature = "experimental-codex-home-lease")]
    CodexHome,
}

enum ClientConnection<'socket> {
    Socket(BorrowedFd<'socket>),
    #[cfg(test)]
    LeaseTestSocket(BorrowedFd<'socket>),
    #[cfg(test)]
    AssumedLive,
    #[cfg(test)]
    BlockingLive(Arc<BlockingClientLiveness>),
}

impl ClientConnection<'_> {
    fn is_live(&self) -> bool {
        match self {
            Self::Socket(socket) => socket_client_is_live(*socket),
            #[cfg(test)]
            Self::LeaseTestSocket(socket) => socket_client_is_live(*socket),
            #[cfg(test)]
            Self::AssumedLive => true,
            #[cfg(test)]
            Self::BlockingLive(liveness) => liveness.is_live(),
        }
    }

    fn lease_candidate(
        &self,
        requested_scope: ProcessScope,
    ) -> Result<LeaseCandidate, RescueVaultDaemonError> {
        let (socket, production_validation, process_scope) = match self {
            Self::Socket(socket) => (socket, true, requested_scope),
            #[cfg(test)]
            Self::LeaseTestSocket(socket) => (socket, false, ProcessScope::DirectPeer),
            #[cfg(test)]
            Self::AssumedLive | Self::BlockingLive(_) => {
                return Err(RescueVaultDaemonError::ProtocolFailure);
            }
        };
        let credentials = getsockopt(socket, sockopt::PeerCredentials)
            .map_err(|_| RescueVaultDaemonError::ProtocolFailure)?;
        if credentials.pid() <= 1 || credentials.uid() == 0 || credentials.gid() == 0 {
            return Err(RescueVaultDaemonError::ProtocolFailure);
        }
        let pidfd = getsockopt(socket, sockopt::PeerPidfd)
            .map_err(|_| RescueVaultDaemonError::ProtocolFailure)?;
        let pidfd_flags =
            rustix::io::fcntl_getfd(&pidfd).map_err(|_| RescueVaultDaemonError::ProtocolFailure)?;
        if pidfd_flags != rustix::io::FdFlags::CLOEXEC || lease_pid_exited(pidfd.as_fd())? {
            return Err(RescueVaultDaemonError::ProtocolFailure);
        }
        let observer = rustix::io::fcntl_dupfd_cloexec(*socket, 3)
            .map_err(|_| RescueVaultDaemonError::ProtocolFailure)?;
        if production_validation {
            validate_accepted_connection(observer.as_fd())?;
        }
        let source = rfs::fstat(*socket).map_err(|_| RescueVaultDaemonError::ProtocolFailure)?;
        let duplicate =
            rfs::fstat(&observer).map_err(|_| RescueVaultDaemonError::ProtocolFailure)?;
        if source.st_dev != duplicate.st_dev || source.st_ino != duplicate.st_ino {
            return Err(RescueVaultDaemonError::ProtocolFailure);
        }
        let process = ProviderProcessBoundary::capture(
            process_scope,
            credentials.pid(),
            credentials.uid(),
            credentials.gid(),
        )
        .map_err(|_| RescueVaultDaemonError::ProtocolFailure)?;
        if getsockopt(&observer, sockopt::PeerCredentials)
            .map(|observed| observed != credentials)
            .unwrap_or(true)
            || lease_pid_exited(pidfd.as_fd())?
        {
            return Err(RescueVaultDaemonError::ProtocolFailure);
        }
        process.verify_initial_peer(credentials.pid())?;
        Ok(LeaseCandidate {
            socket: observer,
            pidfd,
            peer_pid: credentials.pid(),
            process,
        })
    }
}

fn lease_pid_exited(pidfd: BorrowedFd<'_>) -> Result<bool, RescueVaultDaemonError> {
    let zero = Timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    loop {
        let mut descriptor = [PollFd::from_borrowed_fd(pidfd, PollFlags::IN)];
        match poll(&mut descriptor, Some(&zero)) {
            Ok(0) => return Ok(false),
            Ok(_) => {
                let events = descriptor[0].revents();
                if events.intersects(PollFlags::ERR | PollFlags::NVAL) {
                    return Err(RescueVaultDaemonError::ProtocolFailure);
                }
                return Ok(events.contains(PollFlags::IN));
            }
            Err(error) if error == rustix::io::Errno::INTR => {}
            Err(_) => return Err(RescueVaultDaemonError::ProtocolFailure),
        }
    }
}

fn peer_pidfd_capability_probe() -> Result<(), RescueVaultDaemonError> {
    let (first, second) = socketpair(
        AddressFamily::UNIX,
        SocketType::SEQPACKET,
        SocketFlags::CLOEXEC | SocketFlags::NONBLOCK,
        None,
    )
    .map_err(|_| RescueVaultDaemonError::RuntimeUnavailable)?;
    let first_pidfd = getsockopt(&first, sockopt::PeerPidfd)
        .map_err(|_| RescueVaultDaemonError::RuntimeUnavailable)?;
    let second_pidfd = getsockopt(&second, sockopt::PeerPidfd)
        .map_err(|_| RescueVaultDaemonError::RuntimeUnavailable)?;
    for pidfd in [&first_pidfd, &second_pidfd] {
        if rustix::io::fcntl_getfd(pidfd).map_err(|_| RescueVaultDaemonError::RuntimeUnavailable)?
            != rustix::io::FdFlags::CLOEXEC
            || lease_pid_exited(pidfd.as_fd())?
        {
            return Err(RescueVaultDaemonError::RuntimeUnavailable);
        }
    }
    Ok(())
}

fn snapshot_provider_lease(lease: &ProviderLease) -> Result<LeaseSnapshot, RescueVaultDaemonError> {
    let socket = rustix::io::fcntl_dupfd_cloexec(&lease.socket, 3)
        .map_err(|_| RescueVaultDaemonError::RuntimeUnavailable)?;
    let pidfd = rustix::io::fcntl_dupfd_cloexec(&lease.pidfd, 3)
        .map_err(|_| RescueVaultDaemonError::RuntimeUnavailable)?;
    if rustix::io::fcntl_getfd(&socket).map_err(|_| RescueVaultDaemonError::RuntimeUnavailable)?
        != rustix::io::FdFlags::CLOEXEC
        || rustix::io::fcntl_getfd(&pidfd)
            .map_err(|_| RescueVaultDaemonError::RuntimeUnavailable)?
            != rustix::io::FdFlags::CLOEXEC
    {
        return Err(RescueVaultDaemonError::RuntimeUnavailable);
    }
    Ok(LeaseSnapshot {
        id: lease.id,
        socket,
        pidfd,
        process: lease.process.try_clone()?,
        deadline: lease.lease_deadline.unwrap_or(lease.handoff_deadline),
        output_obligation: Arc::clone(&lease.output_obligation),
    })
}

fn wait_for_lease_evidence(
    lease: &LeaseSnapshot,
    deadline: Instant,
) -> Result<LeaseWait, RescueVaultDaemonError> {
    let mut socket_closed = false;
    let mut process_exited = false;
    loop {
        let output_finalized = lease.output_obligation.finalized.load(Ordering::Acquire);
        let process_scope_quiescent = lease.process.is_quiescent(process_exited)?;
        if lease_release_evidence_is_complete(
            socket_closed,
            process_exited,
            output_finalized,
            process_scope_quiescent,
        ) {
            return Ok(LeaseWait::Released);
        }
        let now = Instant::now();
        if now >= deadline {
            return Ok(LeaseWait::Deadline);
        }
        let remaining = deadline.saturating_duration_since(now);
        let slice = remaining.min(ACCEPT_POLL_SLICE);
        let mut descriptors = vec![
            PollFd::from_borrowed_fd(lease.socket.as_fd(), PollFlags::HUP | PollFlags::RDHUP),
            PollFd::from_borrowed_fd(lease.pidfd.as_fd(), PollFlags::IN),
        ];
        if !process_scope_quiescent && let Some(events) = lease.process.events() {
            // cgroup.events reports population changes with POLLPRI. On
            // systemd 257 a collected cgroup reports POLLERR, never POLLHUP;
            // the error is accepted only through the qualified ENODEV proof.
            descriptors.push(PollFd::from_borrowed_fd(
                events,
                PollFlags::PRI | PollFlags::ERR,
            ));
        }
        match poll(&mut descriptors, Some(&duration_to_timespec(slice))) {
            Ok(_) => {
                let socket_events = descriptors[0].revents();
                let process_events = descriptors[1].revents();
                let process_scope_events = descriptors.get(2).map(PollFd::revents);
                if socket_events.intersects(PollFlags::ERR | PollFlags::NVAL)
                    || process_events.intersects(PollFlags::ERR | PollFlags::NVAL)
                {
                    return Err(RescueVaultDaemonError::ProtocolFailure);
                }
                if process_scope_events
                    .is_some_and(|events| events.intersects(PollFlags::HUP | PollFlags::NVAL))
                {
                    return Err(RescueVaultDaemonError::ProtocolFailure);
                }
                // RDHUP is only a peer write-half close. A transferred client
                // descriptor can still be open, so only full HUP is release
                // evidence.
                socket_closed |= socket_events.contains(PollFlags::HUP);
                process_exited |= process_events.contains(PollFlags::IN);
                if process_scope_events.is_some_and(|events| events.contains(PollFlags::ERR))
                    && !lease.process.is_quiescent(process_exited)?
                {
                    // POLLERR is the qualified systemd-GC signal only when
                    // the retained ENODEV and named-path proof agrees. Do not
                    // spin on an unexplained permanently-ready error bit.
                    return Err(RescueVaultDaemonError::ProtocolFailure);
                }
            }
            Err(error) if error == rustix::io::Errno::INTR => {}
            Err(_) => return Err(RescueVaultDaemonError::ProtocolFailure),
        }
    }
}

fn lease_release_evidence_is_complete(
    socket_closed: bool,
    process_exited: bool,
    output_finalized: bool,
    process_scope_quiescent: bool,
) -> bool {
    socket_closed && process_exited && output_finalized && process_scope_quiescent
}

#[cfg(test)]
struct BlockingClientLiveness {
    entered: std::sync::mpsc::SyncSender<()>,
    release: Mutex<std::sync::mpsc::Receiver<()>>,
    blocked: AtomicBool,
    live: AtomicBool,
}

#[cfg(test)]
impl BlockingClientLiveness {
    fn is_live(&self) -> bool {
        if !self.blocked.swap(true, Ordering::AcqRel) {
            if self.entered.send(()).is_err() {
                return false;
            }
            let Ok(release) = self.release.lock() else {
                return false;
            };
            if release.recv().is_err() {
                return false;
            }
        }
        self.live.load(Ordering::Acquire)
    }
}

impl Supervisor {
    fn snapshot(&self) -> Snapshot {
        let Ok(_decision) = self.lifecycle.lock() else {
            return Snapshot {
                version: MAX_SAFE_JSON_INTEGER,
                availability: faulted_availability(),
            };
        };
        match self.state.lock() {
            Ok(state) => Snapshot {
                version: state.version,
                availability: state.availability.clone(),
            },
            Err(_) => Snapshot {
                version: MAX_SAFE_JSON_INTEGER,
                availability: faulted_availability(),
            },
        }
    }

    fn handle_connected_request(
        self: &Arc<Self>,
        request: ValidatedRequest,
        started: Instant,
        connection: ClientConnection<'_>,
    ) -> (u64, HandlerResult) {
        let operation = request.operation();
        if !external_request_is_enabled(&request) {
            let version = self.snapshot().version;
            return (
                version,
                HandlerResult::Error(request, ErrorToken::NotAuthorized),
            );
        }
        match operation {
            Operation::VaultStatus => self.handle_status(request),
            Operation::VaultUnlock => self.handle_unlock(request, started, &connection),
            Operation::VaultLock => self.handle_lock(request, started, &connection),
            Operation::ProviderStatus => self.handle_provider_status(request, started, &connection),
            Operation::ProviderOpenAiConfigure => {
                self.handle_provider_configure(request, started, &connection)
            }
            Operation::ProviderOpenAiBorrow => {
                self.handle_provider_borrow(request, started, &connection)
            }
            #[cfg(feature = "experimental-codex-home-lease")]
            Operation::ProviderCodexHomeLease => {
                self.handle_provider_borrow(request, started, &connection)
            }
            Operation::ProviderLogout => self.handle_provider_logout(request, started, &connection),
            _ => unreachable!("external operation allowlist is closed"),
        }
    }

    #[cfg(test)]
    fn handle_request(
        self: &Arc<Self>,
        request: ValidatedRequest,
        started: Instant,
    ) -> (u64, HandlerResult) {
        self.handle_connected_request(request, started, ClientConnection::AssumedLive)
    }

    fn handle_status(&self, request: ValidatedRequest) -> (u64, HandlerResult) {
        let snapshot = self.snapshot();
        if !status_version_is_accepted(request.expected_state_version(), snapshot.version) {
            return (
                snapshot.version,
                HandlerResult::Error(request, ErrorToken::StaleState),
            );
        }
        match snapshot.availability {
            Availability::Unavailable(error) => {
                (snapshot.version, HandlerResult::Error(request, error))
            }
            Availability::Available { state, device_id } => {
                match VaultStatusPayload::new(state, device_id.as_deref()) {
                    Ok(status) => (
                        snapshot.version,
                        HandlerResult::Success(request, SuccessPayload::VaultStatus(status)),
                    ),
                    Err(_) => {
                        self.mark_fault();
                        let version = self.snapshot().version;
                        (
                            version,
                            HandlerResult::Error(request, ErrorToken::RebootRequired),
                        )
                    }
                }
            }
        }
    }

    fn handle_provider_status(
        self: &Arc<Self>,
        request: ValidatedRequest,
        started: Instant,
        connection: &ClientConnection<'_>,
    ) -> (u64, HandlerResult) {
        let operation_deadline = started
            .checked_add(WORKER_OPERATION_TIMEOUT)
            .unwrap_or(started);
        if !matches!(request.payload(), RequestPayload::Empty) {
            let version = self.snapshot().version;
            return (version, HandlerResult::Error(request, ErrorToken::IoFailed));
        }
        if let Err((version, error)) =
            self.begin_provider_operation(request.expected_state_version(), false, connection)
        {
            if error == ErrorToken::RebootRequired {
                self.mark_fault_by(operation_deadline);
                return (
                    self.snapshot().version,
                    HandlerResult::Error(request, ErrorToken::RebootRequired),
                );
            }
            return (version, HandlerResult::Error(request, error));
        }
        match self.provider_dispatch_ready(false, connection) {
            Ok(DispatchArm::Armed) => {}
            Ok(DispatchArm::StoppedBeforeArm | DispatchArm::StoppedAfterArm) => {
                return match self.release_provider_status() {
                    Ok(version) => (version, HandlerResult::Error(request, ErrorToken::Busy)),
                    Err(()) => {
                        self.mark_fault_by(operation_deadline);
                        (
                            self.snapshot().version,
                            HandlerResult::Error(request, ErrorToken::RebootRequired),
                        )
                    }
                };
            }
            Ok(DispatchArm::ClientGoneBeforeArm | DispatchArm::ClientGoneAfterArm) => {
                return match self.release_provider_status() {
                    Ok(version) => (version, HandlerResult::Error(request, ErrorToken::IoFailed)),
                    Err(()) => {
                        self.mark_fault_by(operation_deadline);
                        (
                            self.snapshot().version,
                            HandlerResult::Error(request, ErrorToken::RebootRequired),
                        )
                    }
                };
            }
            Err(_) => {
                self.mark_fault_by(operation_deadline);
                return (
                    self.snapshot().version,
                    HandlerResult::Error(request, ErrorToken::RebootRequired),
                );
            }
        }
        let Some(worker) = self.worker.as_ref() else {
            self.mark_fault_by(operation_deadline);
            return (
                self.snapshot().version,
                HandlerResult::Error(request, ErrorToken::RebootRequired),
            );
        };
        match worker.transact(
            internal_wire::WorkerCommandKind::ProviderStatus,
            None,
            None,
            operation_deadline,
        ) {
            Ok((response, None)) => {
                use internal_wire::WorkerResultCode as Result;
                let openai = match response.code {
                    Result::ProviderStatusUnconfigured => ProviderState::Unconfigured,
                    Result::ProviderStatusConfigured => ProviderState::Configured,
                    Result::ProviderStateAmbiguous => {
                        self.mark_fault_by(operation_deadline);
                        return (
                            self.snapshot().version,
                            HandlerResult::Error(request, ErrorToken::RebootRequired),
                        );
                    }
                    _ => {
                        self.mark_fault_by(operation_deadline);
                        return (
                            self.snapshot().version,
                            HandlerResult::Error(request, ErrorToken::RebootRequired),
                        );
                    }
                };
                let version = match self.release_provider_status() {
                    Ok(version) => version,
                    Err(()) => {
                        self.mark_fault_by(operation_deadline);
                        return (
                            self.snapshot().version,
                            HandlerResult::Error(request, ErrorToken::RebootRequired),
                        );
                    }
                };
                (
                    version,
                    HandlerResult::Success(
                        request,
                        SuccessPayload::ProviderStatus(ProviderStatusPayload {
                            openai,
                            codex: ProviderState::Unconfigured,
                        }),
                    ),
                )
            }
            Ok((_, Some(_))) | Err(_) => {
                self.mark_fault_by(operation_deadline);
                (
                    self.snapshot().version,
                    HandlerResult::Error(request, ErrorToken::RebootRequired),
                )
            }
        }
    }

    fn handle_provider_borrow(
        self: &Arc<Self>,
        request: ValidatedRequest,
        started: Instant,
        connection: &ClientConnection<'_>,
    ) -> (u64, HandlerResult) {
        let lease_kind = match request.operation() {
            Operation::ProviderOpenAiBorrow => ProviderLeaseKind::OpenAi,
            #[cfg(feature = "experimental-codex-home-lease")]
            Operation::ProviderCodexHomeLease => ProviderLeaseKind::CodexHome,
            _ => unreachable!("provider lease operation allowlist is closed"),
        };
        let handoff_deadline = started
            .checked_add(PROVIDER_BORROW_TIMEOUT)
            .unwrap_or(started);
        if !matches!(request.payload(), RequestPayload::Empty) {
            let version = self.snapshot().version;
            return (version, HandlerResult::Error(request, ErrorToken::IoFailed));
        }
        let candidate = match connection.lease_candidate(provider_process_scope(request.role())) {
            Ok(candidate) => candidate,
            Err(_) => {
                return (
                    self.snapshot().version,
                    HandlerResult::Error(request, ErrorToken::IoFailed),
                );
            }
        };
        let (_version, lease_id) = match self.begin_provider_borrow(
            request.expected_state_version(),
            connection,
            candidate,
            handoff_deadline,
        ) {
            Ok(result) => result,
            Err((version, error)) => {
                if error == ErrorToken::RebootRequired {
                    self.mark_fault_by(handoff_deadline);
                    return (
                        self.snapshot().version,
                        HandlerResult::Error(request, ErrorToken::RebootRequired),
                    );
                }
                return (version, HandlerResult::Error(request, error));
            }
        };
        match self.provider_borrow_dispatch_ready(lease_id, connection) {
            Ok(ProviderDispatchArm::Armed) => {}
            Ok(ProviderDispatchArm::RevocationInProgress) => {
                return (self.snapshot().version, HandlerResult::Drop);
            }
            Ok(ProviderDispatchArm::StoppedBeforeArm) => {
                return match self.cancel_pending_lease(lease_id) {
                    Ok(PendingCancel::CancelledHere(version)) => {
                        (version, HandlerResult::Error(request, ErrorToken::Busy))
                    }
                    Ok(PendingCancel::RevocationInProgress) => {
                        (self.snapshot().version, HandlerResult::Drop)
                    }
                    Err(_) => {
                        self.mark_fault_by(handoff_deadline);
                        (self.snapshot().version, HandlerResult::Drop)
                    }
                };
            }
            Ok(ProviderDispatchArm::ClientGoneBeforeArm) => {
                return match self.cancel_pending_lease(lease_id) {
                    Ok(PendingCancel::CancelledHere(version)) => {
                        (version, HandlerResult::Error(request, ErrorToken::IoFailed))
                    }
                    Ok(PendingCancel::RevocationInProgress) => {
                        (self.snapshot().version, HandlerResult::Drop)
                    }
                    Err(_) => {
                        self.mark_fault_by(handoff_deadline);
                        (self.snapshot().version, HandlerResult::Drop)
                    }
                };
            }
            Err(_) => {
                let _ =
                    self.revoke_provider_lease(lease_id, Instant::now() + LEASE_REVOCATION_TIMEOUT);
                self.mark_fault_by(handoff_deadline);
                return (self.snapshot().version, HandlerResult::Drop);
            }
        }
        let mut output = match self.mark_lease_potentially_issued(lease_id) {
            Ok(PotentialIssue::Armed(output)) => output,
            Ok(PotentialIssue::CancelledBeforeSecret) => {
                return (self.snapshot().version, HandlerResult::Drop);
            }
            Ok(PotentialIssue::RevocationInProgress) => {
                return (self.snapshot().version, HandlerResult::Drop);
            }
            Err(_) => {
                let _ = self.cancel_pending_lease(lease_id);
                self.mark_fault_by(handoff_deadline);
                return (self.snapshot().version, HandlerResult::Drop);
            }
        };
        let Some(worker) = self.worker.as_ref() else {
            drop(output);
            let _ = self.revoke_provider_lease(lease_id, Instant::now() + LEASE_REVOCATION_TIMEOUT);
            self.mark_fault_by(handoff_deadline);
            return (self.snapshot().version, HandlerResult::Drop);
        };
        let borrowed = match lease_kind {
            ProviderLeaseKind::OpenAi => worker.borrow_openai(handoff_deadline),
            #[cfg(feature = "experimental-codex-home-lease")]
            ProviderLeaseKind::CodexHome => worker.lease_codex_home(handoff_deadline),
        };
        match borrowed {
            Ok((response, descriptor)) => {
                #[cfg(feature = "experimental-codex-home-lease")]
                if lease_kind == ProviderLeaseKind::CodexHome
                    && descriptor
                        .as_ref()
                        .is_some_and(|descriptor| validate_codex_home_handoff(descriptor).is_err())
                {
                    drop(descriptor);
                    return self.fail_ambiguous_borrow(lease_id, handoff_deadline, output);
                }
                if let Some(descriptor) = descriptor
                    && let Err(descriptor) = output.adopt(descriptor)
                {
                    drop(descriptor);
                    return self.fail_ambiguous_borrow(lease_id, handoff_deadline, output);
                }
                let ready = match lease_kind {
                    ProviderLeaseKind::OpenAi => {
                        response.code == internal_wire::WorkerResultCode::ProviderBorrowReady
                    }
                    #[cfg(feature = "experimental-codex-home-lease")]
                    ProviderLeaseKind::CodexHome => {
                        response.code == internal_wire::WorkerResultCode::ProviderCodexHomeReady
                    }
                };
                if ready && output.descriptor().is_some() {
                    let declaration = match lease_kind {
                        ProviderLeaseKind::OpenAi => {
                            let Some(size) = response.output_size else {
                                return self.fail_ambiguous_borrow(
                                    lease_id,
                                    handoff_deadline,
                                    output,
                                );
                            };
                            DescriptorDeclaration {
                                kind: DescriptorType::OpenAiApiKeyPipe,
                                size: u64::from(size),
                            }
                        }
                        #[cfg(feature = "experimental-codex-home-lease")]
                        ProviderLeaseKind::CodexHome if response.output_size.is_none() => {
                            DescriptorDeclaration {
                                kind: DescriptorType::CodexHomeOPath,
                                size: 0,
                            }
                        }
                        #[cfg(feature = "experimental-codex-home-lease")]
                        ProviderLeaseKind::CodexHome => {
                            return self.fail_ambiguous_borrow(lease_id, handoff_deadline, output);
                        }
                    };
                    let version = match self.finish_provider_borrow_ready(lease_id) {
                        Ok(Some(version)) => version,
                        Ok(None) => {
                            drop(output);
                            return (self.snapshot().version, HandlerResult::Drop);
                        }
                        Err(_) => {
                            return self.fail_ambiguous_borrow(lease_id, handoff_deadline, output);
                        }
                    };
                    return (
                        version,
                        HandlerResult::Descriptor {
                            request,
                            payload: SuccessPayload::Descriptor(declaration),
                            output,
                            lease_id,
                            handoff_deadline,
                        },
                    );
                }
                let unconfigured = match lease_kind {
                    ProviderLeaseKind::OpenAi => {
                        response.code == internal_wire::WorkerResultCode::ProviderBorrowUnconfigured
                    }
                    #[cfg(feature = "experimental-codex-home-lease")]
                    ProviderLeaseKind::CodexHome => {
                        response.code
                            == internal_wire::WorkerResultCode::ProviderCodexHomeUnconfigured
                    }
                };
                if unconfigured && response.output_size.is_none() && output.descriptor().is_none() {
                    drop(output);
                    return match self.finish_provider_borrow_unconfigured(lease_id) {
                        Ok(Some(version)) => (
                            version,
                            HandlerResult::Error(request, ErrorToken::ProviderUnconfigured),
                        ),
                        Ok(None) => (self.snapshot().version, HandlerResult::Drop),
                        Err(_) => {
                            self.mark_fault_by(handoff_deadline);
                            (self.snapshot().version, HandlerResult::Drop)
                        }
                    };
                }
                self.fail_ambiguous_borrow(lease_id, handoff_deadline, output)
            }
            Err(_) => self.fail_ambiguous_borrow(lease_id, handoff_deadline, output),
        }
    }

    fn fail_ambiguous_borrow(
        &self,
        lease_id: u64,
        handoff_deadline: Instant,
        output: LeaseOutputGuard,
    ) -> (u64, HandlerResult) {
        drop(output);
        let revoke_deadline = Instant::now()
            .checked_add(LEASE_REVOCATION_TIMEOUT)
            .unwrap_or_else(Instant::now);
        let _ = self.revoke_provider_lease(lease_id, revoke_deadline);
        self.mark_fault_by(handoff_deadline.max(revoke_deadline));
        (self.snapshot().version, HandlerResult::Drop)
    }

    fn handle_provider_configure(
        self: &Arc<Self>,
        mut request: ValidatedRequest,
        started: Instant,
        connection: &ClientConnection<'_>,
    ) -> (u64, HandlerResult) {
        let operation_deadline = started
            .checked_add(WORKER_OPERATION_TIMEOUT)
            .unwrap_or(started);
        let input_size = match request.payload() {
            RequestPayload::ProviderOpenAiConfigure { input } => input.size,
            _ => {
                let version = self.snapshot().version;
                return (version, HandlerResult::Error(request, ErrorToken::IoFailed));
            }
        };
        if let Err((version, error)) =
            self.begin_provider_operation(request.expected_state_version(), true, connection)
        {
            if error == ErrorToken::RebootRequired {
                self.mark_fault_by(operation_deadline);
                return (
                    self.snapshot().version,
                    HandlerResult::Error(request, ErrorToken::RebootRequired),
                );
            }
            return (version, HandlerResult::Error(request, error));
        }
        let descriptor = match request.take_descriptor() {
            Some(descriptor) => descriptor,
            None => {
                return self.finish_provider_mutation_without_dispatch(
                    request,
                    ErrorToken::FdRequired,
                    operation_deadline,
                );
            }
        };
        match self.provider_dispatch_ready(true, connection) {
            Ok(DispatchArm::Armed) => {}
            Ok(DispatchArm::StoppedBeforeArm) => {
                return self.finish_provider_mutation_without_dispatch(
                    request,
                    ErrorToken::Busy,
                    operation_deadline,
                );
            }
            Ok(DispatchArm::ClientGoneBeforeArm) => {
                return self.finish_provider_mutation_without_dispatch(
                    request,
                    ErrorToken::IoFailed,
                    operation_deadline,
                );
            }
            Ok(DispatchArm::StoppedAfterArm | DispatchArm::ClientGoneAfterArm) => {
                self.mark_fault_by(operation_deadline);
                return (
                    self.snapshot().version,
                    HandlerResult::Error(request, ErrorToken::RebootRequired),
                );
            }
            Err(_) => {
                self.mark_fault_by(operation_deadline);
                return (
                    self.snapshot().version,
                    HandlerResult::Error(request, ErrorToken::RebootRequired),
                );
            }
        }
        let Some(worker) = self.worker.as_ref() else {
            self.mark_fault_by(operation_deadline);
            return (
                self.snapshot().version,
                HandlerResult::Error(request, ErrorToken::RebootRequired),
            );
        };
        let response = worker.transact(
            internal_wire::WorkerCommandKind::ProviderOpenAiConfigure,
            u16::try_from(input_size).ok(),
            Some(descriptor),
            operation_deadline,
        );
        match response {
            Ok((response, None)) => self.finish_provider_mutation(
                request,
                response,
                ProviderState::Configured,
                internal_wire::WorkerResultCode::ProviderConfigureSucceeded,
                operation_deadline,
            ),
            Ok((_, Some(_))) | Err(_) => {
                self.mark_fault_by(operation_deadline);
                (
                    self.snapshot().version,
                    HandlerResult::Error(request, ErrorToken::RebootRequired),
                )
            }
        }
    }

    fn handle_provider_logout(
        self: &Arc<Self>,
        request: ValidatedRequest,
        started: Instant,
        connection: &ClientConnection<'_>,
    ) -> (u64, HandlerResult) {
        let operation_deadline = started
            .checked_add(WORKER_OPERATION_TIMEOUT)
            .unwrap_or(started);
        match request.payload() {
            RequestPayload::ProviderLogout {
                provider: Provider::OpenAi,
            } => {}
            RequestPayload::ProviderLogout {
                provider: Provider::Codex,
            } => {
                let version = self.snapshot().version;
                return (
                    version,
                    HandlerResult::Error(request, ErrorToken::NotAuthorized),
                );
            }
            _ => {
                let version = self.snapshot().version;
                return (version, HandlerResult::Error(request, ErrorToken::IoFailed));
            }
        }
        if let Err((version, error)) =
            self.begin_provider_operation(request.expected_state_version(), true, connection)
        {
            if error == ErrorToken::RebootRequired {
                self.mark_fault_by(operation_deadline);
                return (
                    self.snapshot().version,
                    HandlerResult::Error(request, ErrorToken::RebootRequired),
                );
            }
            return (version, HandlerResult::Error(request, error));
        }
        match self.provider_dispatch_ready(true, connection) {
            Ok(DispatchArm::Armed) => {}
            Ok(DispatchArm::StoppedBeforeArm) => {
                return self.finish_provider_mutation_without_dispatch(
                    request,
                    ErrorToken::Busy,
                    operation_deadline,
                );
            }
            Ok(DispatchArm::ClientGoneBeforeArm) => {
                return self.finish_provider_mutation_without_dispatch(
                    request,
                    ErrorToken::IoFailed,
                    operation_deadline,
                );
            }
            Ok(DispatchArm::StoppedAfterArm | DispatchArm::ClientGoneAfterArm) => {
                self.mark_fault_by(operation_deadline);
                return (
                    self.snapshot().version,
                    HandlerResult::Error(request, ErrorToken::RebootRequired),
                );
            }
            Err(_) => {
                self.mark_fault_by(operation_deadline);
                return (
                    self.snapshot().version,
                    HandlerResult::Error(request, ErrorToken::RebootRequired),
                );
            }
        }
        let Some(worker) = self.worker.as_ref() else {
            self.mark_fault_by(operation_deadline);
            return (
                self.snapshot().version,
                HandlerResult::Error(request, ErrorToken::RebootRequired),
            );
        };
        match worker.transact(
            internal_wire::WorkerCommandKind::ProviderOpenAiLogout,
            None,
            None,
            operation_deadline,
        ) {
            Ok((response, None)) => self.finish_provider_mutation(
                request,
                response,
                ProviderState::Unconfigured,
                internal_wire::WorkerResultCode::ProviderLogoutSucceeded,
                operation_deadline,
            ),
            Ok((_, Some(_))) | Err(_) => {
                self.mark_fault_by(operation_deadline);
                (
                    self.snapshot().version,
                    HandlerResult::Error(request, ErrorToken::RebootRequired),
                )
            }
        }
    }

    fn handle_unlock(
        self: &Arc<Self>,
        mut request: ValidatedRequest,
        started: Instant,
        connection: &ClientConnection<'_>,
    ) -> (u64, HandlerResult) {
        let operation_deadline = started
            .checked_add(WORKER_OPERATION_TIMEOUT)
            .unwrap_or(started);
        let input_size = match request.payload() {
            RequestPayload::VaultUnlock { input } => input.size,
            _ => {
                let version = self.snapshot().version;
                return (version, HandlerResult::Error(request, ErrorToken::IoFailed));
            }
        };
        match self.begin_unlock(request.expected_state_version(), started, connection) {
            Ok(_) => {}
            Err((version, error)) => {
                if error == ErrorToken::RebootRequired {
                    self.mark_fault_by(operation_deadline);
                    return (
                        self.snapshot().version,
                        HandlerResult::Error(request, ErrorToken::RebootRequired),
                    );
                }
                return (version, HandlerResult::Error(request, error));
            }
        };
        // This gate is deliberately after all stale/policy decisions but
        // before descriptor ownership is taken or a single secret byte is
        // read. No lifecycle marker is needed when the idle worker can be
        // cleanly reaped without dispatching Unlock.
        if self.privacy.validate_no_active_swap().is_err() {
            self.mark_pre_mutation_fault_by(operation_deadline);
            return (
                self.snapshot().version,
                HandlerResult::Error(request, ErrorToken::RebootRequired),
            );
        }
        let descriptor = match request.take_descriptor() {
            Some(descriptor) => descriptor,
            None => {
                return self.finish_nonmutating_unlock_error(
                    request,
                    ErrorToken::FdRequired,
                    operation_deadline,
                );
            }
        };
        let pipe_deadline = started + CLIENT_PIPE_TIMEOUT;
        let secret = match read_exact_passphrase(descriptor, input_size, pipe_deadline) {
            Ok(secret) => secret,
            Err(()) => {
                return self.finish_nonmutating_unlock_error(
                    request,
                    ErrorToken::IoFailed,
                    operation_deadline,
                );
            }
        };
        let internal_pipe = match repipe_passphrase(&secret) {
            Ok(pipe) => pipe,
            Err(()) => {
                return self.finish_nonmutating_unlock_error(
                    request,
                    ErrorToken::IoFailed,
                    operation_deadline,
                );
            }
        };
        drop(secret);
        match self.arm_for_dispatch(VaultState::Unlocking, connection) {
            Ok(DispatchArm::Armed) => {}
            Ok(DispatchArm::StoppedBeforeArm) => {
                let version = match self.rollback_transition_for_stop(VaultState::Unlocking) {
                    Ok(version) => version,
                    Err(()) => {
                        self.mark_fault_by(operation_deadline);
                        return (
                            self.snapshot().version,
                            HandlerResult::Error(request, ErrorToken::RebootRequired),
                        );
                    }
                };
                return (version, HandlerResult::Error(request, ErrorToken::Busy));
            }
            Ok(DispatchArm::ClientGoneBeforeArm) => {
                let version = match self.rollback_transition_for_stop(VaultState::Unlocking) {
                    Ok(version) => version,
                    Err(()) => {
                        self.mark_fault_by(operation_deadline);
                        return (
                            self.snapshot().version,
                            HandlerResult::Error(request, ErrorToken::RebootRequired),
                        );
                    }
                };
                return (version, HandlerResult::Error(request, ErrorToken::IoFailed));
            }
            Ok(DispatchArm::StoppedAfterArm | DispatchArm::ClientGoneAfterArm) | Err(_) => {
                self.mark_fault_by(operation_deadline);
                return (
                    self.snapshot().version,
                    HandlerResult::Error(request, ErrorToken::RebootRequired),
                );
            }
        }
        let Some(worker) = self.worker.as_ref() else {
            self.mark_fault_by(operation_deadline);
            let version = self.snapshot().version;
            return (
                version,
                HandlerResult::Error(request, ErrorToken::RebootRequired),
            );
        };
        let response = worker.transact(
            internal_wire::WorkerCommandKind::Unlock,
            u16::try_from(input_size).ok(),
            Some(internal_pipe),
            operation_deadline,
        );
        match response {
            Ok((response, None)) => self.finish_unlock(request, response, operation_deadline),
            Ok((_, Some(_))) | Err(_) => {
                self.mark_fault_by(operation_deadline);
                let version = self.snapshot().version;
                (
                    version,
                    HandlerResult::Error(request, ErrorToken::RebootRequired),
                )
            }
        }
    }

    fn begin_unlock(
        &self,
        expected: u64,
        now: Instant,
        connection: &ClientConnection<'_>,
    ) -> Result<u64, (u64, ErrorToken)> {
        let _decision = self
            .lifecycle
            .lock()
            .map_err(|_| (0, ErrorToken::RebootRequired))?;
        let mut state = self
            .state
            .lock()
            .map_err(|_| (0, ErrorToken::RebootRequired))?;
        if !connection.is_live() {
            return Err((state.version, ErrorToken::IoFailed));
        }
        begin_unlock_state(
            &mut state,
            expected,
            now,
            self.stopping.load(Ordering::Acquire),
        )
    }

    fn finish_unlock(
        &self,
        request: ValidatedRequest,
        response: internal_wire::WorkerResponse,
        deadline: Instant,
    ) -> (u64, HandlerResult) {
        use internal_wire::WorkerResultCode as Result;
        match response.code {
            Result::UnlockSucceeded => {
                let Some(device_id) = response.device_id else {
                    self.mark_fault_by(deadline);
                    let version = self.snapshot().version;
                    return (
                        version,
                        HandlerResult::Error(request, ErrorToken::RebootRequired),
                    );
                };
                let version = match self.complete_transition(
                    VaultState::Unlocking,
                    available(VaultState::Unlocked, Some(device_id.clone())),
                ) {
                    Ok(version) => version,
                    Err(()) => {
                        self.mark_fault_by(deadline);
                        return (
                            self.snapshot().version,
                            HandlerResult::Error(request, ErrorToken::RebootRequired),
                        );
                    }
                };
                match VaultStatusPayload::new(VaultState::Unlocked, Some(&device_id)) {
                    Ok(status) => (
                        version,
                        HandlerResult::Success(request, SuccessPayload::VaultStatus(status)),
                    ),
                    Err(_) => {
                        self.mark_fault_by(deadline);
                        let version = self.snapshot().version;
                        (
                            version,
                            HandlerResult::Error(request, ErrorToken::RebootRequired),
                        )
                    }
                }
            }
            Result::TimedOut | Result::CleanupFailed => {
                self.mark_fault_by(deadline);
                let version = self.snapshot().version;
                (
                    version,
                    HandlerResult::Error(request, ErrorToken::RebootRequired),
                )
            }
            Result::Absent | Result::Unprovisioned | Result::ProfileMismatch => {
                self.mark_fault_by(deadline);
                (
                    self.snapshot().version,
                    HandlerResult::Error(request, ErrorToken::RebootRequired),
                )
            }
            Result::BadPassphrase | Result::MediaChanged | Result::IoFailed | Result::Busy => {
                let (availability, error) = match response.code {
                    Result::BadPassphrase => (
                        available(VaultState::Locked, None),
                        ErrorToken::BadPassphrase,
                    ),
                    Result::MediaChanged => (
                        Availability::Unavailable(ErrorToken::MediaChanged),
                        ErrorToken::MediaChanged,
                    ),
                    Result::IoFailed => (
                        Availability::Unavailable(ErrorToken::IoFailed),
                        ErrorToken::IoFailed,
                    ),
                    Result::Busy => (available(VaultState::Locked, None), ErrorToken::Busy),
                    _ => unreachable!(),
                };
                let version = match self.complete_after_locked_attestation(
                    VaultState::Unlocking,
                    availability,
                    deadline,
                ) {
                    Ok(version) => version,
                    Err(()) => {
                        self.mark_fault_by(deadline);
                        return (
                            self.snapshot().version,
                            HandlerResult::Error(request, ErrorToken::RebootRequired),
                        );
                    }
                };
                (version, HandlerResult::Error(request, error))
            }
            _ => {
                self.mark_fault_by(deadline);
                let version = self.snapshot().version;
                (
                    version,
                    HandlerResult::Error(request, ErrorToken::RebootRequired),
                )
            }
        }
    }

    fn finish_nonmutating_unlock_error(
        &self,
        request: ValidatedRequest,
        error: ErrorToken,
        deadline: Instant,
    ) -> (u64, HandlerResult) {
        match self.complete_locked_after_nonmutation() {
            Ok(version) => (version, HandlerResult::Error(request, error)),
            Err(()) => {
                self.mark_fault_by(deadline);
                (
                    self.snapshot().version,
                    HandlerResult::Error(request, ErrorToken::RebootRequired),
                )
            }
        }
    }

    fn handle_lock(
        self: &Arc<Self>,
        request: ValidatedRequest,
        started: Instant,
        connection: &ClientConnection<'_>,
    ) -> (u64, HandlerResult) {
        let operation_deadline = started
            .checked_add(WORKER_OPERATION_TIMEOUT)
            .unwrap_or(started);
        if !matches!(request.payload(), RequestPayload::Empty) {
            let version = self.snapshot().version;
            return (version, HandlerResult::Error(request, ErrorToken::IoFailed));
        }
        let (_transition_version, lease_id) =
            match self.begin_lock(request.expected_state_version(), connection) {
                Ok(result) => result,
                Err((version, error)) => {
                    if error == ErrorToken::RebootRequired {
                        self.mark_fault_by(operation_deadline);
                        return (
                            self.snapshot().version,
                            HandlerResult::Error(request, ErrorToken::RebootRequired),
                        );
                    }
                    return (version, HandlerResult::Error(request, error));
                }
            };
        if let Some(lease_id) = lease_id {
            let revoke_deadline = Instant::now()
                .checked_add(LEASE_REVOCATION_TIMEOUT)
                .unwrap_or(operation_deadline)
                .min(operation_deadline);
            if self
                .revoke_provider_lease(lease_id, revoke_deadline)
                .is_err()
            {
                self.mark_fault_by(operation_deadline);
                return (
                    self.snapshot().version,
                    HandlerResult::Error(request, ErrorToken::RebootRequired),
                );
            }
        }
        match self.arm_for_dispatch(VaultState::Locking, connection) {
            Ok(DispatchArm::Armed) => {}
            Ok(DispatchArm::StoppedBeforeArm) => {
                let version = match self.rollback_transition_for_stop(VaultState::Locking) {
                    Ok(version) => version,
                    Err(()) => {
                        self.mark_fault_by(operation_deadline);
                        return (
                            self.snapshot().version,
                            HandlerResult::Error(request, ErrorToken::RebootRequired),
                        );
                    }
                };
                return (version, HandlerResult::Error(request, ErrorToken::Busy));
            }
            Ok(DispatchArm::ClientGoneBeforeArm) => {
                let version = match self.rollback_transition_for_stop(VaultState::Locking) {
                    Ok(version) => version,
                    Err(()) => {
                        self.mark_fault_by(operation_deadline);
                        return (
                            self.snapshot().version,
                            HandlerResult::Error(request, ErrorToken::RebootRequired),
                        );
                    }
                };
                return (version, HandlerResult::Error(request, ErrorToken::IoFailed));
            }
            Ok(DispatchArm::StoppedAfterArm | DispatchArm::ClientGoneAfterArm) | Err(_) => {
                self.mark_fault_by(operation_deadline);
                return (
                    self.snapshot().version,
                    HandlerResult::Error(request, ErrorToken::RebootRequired),
                );
            }
        }
        let Some(worker) = self.worker.as_ref() else {
            self.mark_fault_by(operation_deadline);
            let version = self.snapshot().version;
            return (
                version,
                HandlerResult::Error(request, ErrorToken::RebootRequired),
            );
        };
        let response = worker.transact(
            internal_wire::WorkerCommandKind::Lock,
            None,
            None,
            operation_deadline,
        );
        match response {
            Ok((response, None))
                if response.code == internal_wire::WorkerResultCode::LockSucceeded =>
            {
                let version = match self.complete_after_locked_attestation(
                    VaultState::Locking,
                    available(VaultState::Locked, None),
                    operation_deadline,
                ) {
                    Ok(version) => version,
                    Err(()) => {
                        self.mark_fault_by(operation_deadline);
                        return (
                            self.snapshot().version,
                            HandlerResult::Error(request, ErrorToken::RebootRequired),
                        );
                    }
                };
                let status = match VaultStatusPayload::new(VaultState::Locked, None) {
                    Ok(status) => status,
                    Err(_) => {
                        self.mark_fault_by(operation_deadline);
                        let version = self.snapshot().version;
                        return (
                            version,
                            HandlerResult::Error(request, ErrorToken::RebootRequired),
                        );
                    }
                };
                (
                    version,
                    HandlerResult::Success(request, SuccessPayload::VaultStatus(status)),
                )
            }
            Ok(_) | Err(_) => {
                self.mark_fault_by(operation_deadline);
                let version = self.snapshot().version;
                (
                    version,
                    HandlerResult::Error(request, ErrorToken::RebootRequired),
                )
            }
        }
    }

    fn begin_lock(
        &self,
        expected: u64,
        connection: &ClientConnection<'_>,
    ) -> Result<(u64, Option<u64>), (u64, ErrorToken)> {
        let _decision = self
            .lifecycle
            .lock()
            .map_err(|_| (0, ErrorToken::RebootRequired))?;
        let mut state = self
            .state
            .lock()
            .map_err(|_| (0, ErrorToken::RebootRequired))?;
        if !connection.is_live() {
            return Err((state.version, ErrorToken::IoFailed));
        }
        let mut leases = self
            .leases
            .lock()
            .map_err(|_| (state.version, ErrorToken::RebootRequired))?;
        let version =
            begin_lock_state(&mut state, expected, self.stopping.load(Ordering::Acquire))?;
        let lease_id = leases.active.as_mut().map(|lease| {
            lease.state = LeaseState::Revoking;
            lease.id
        });
        Ok((version, lease_id))
    }

    fn begin_provider_operation(
        &self,
        expected: u64,
        mutation: bool,
        connection: &ClientConnection<'_>,
    ) -> Result<u64, (u64, ErrorToken)> {
        let _decision = self
            .lifecycle
            .lock()
            .map_err(|_| (0, ErrorToken::RebootRequired))?;
        let mut state = self
            .state
            .lock()
            .map_err(|_| (0, ErrorToken::RebootRequired))?;
        if !connection.is_live() {
            return Err((state.version, ErrorToken::IoFailed));
        }
        if self
            .leases
            .lock()
            .map_err(|_| (state.version, ErrorToken::RebootRequired))?
            .active
            .is_some()
        {
            return Err((state.version, ErrorToken::Busy));
        }
        begin_provider_operation_state(
            &mut state,
            expected,
            mutation,
            self.stopping.load(Ordering::Acquire),
        )
    }

    fn begin_provider_borrow(
        &self,
        expected: u64,
        connection: &ClientConnection<'_>,
        candidate: LeaseCandidate,
        handoff_deadline: Instant,
    ) -> Result<(u64, u64), (u64, ErrorToken)> {
        let _decision = self
            .lifecycle
            .lock()
            .map_err(|_| (0, ErrorToken::RebootRequired))?;
        let mut state = self
            .state
            .lock()
            .map_err(|_| (0, ErrorToken::RebootRequired))?;
        {
            let leases = self
                .leases
                .lock()
                .map_err(|_| (state.version, ErrorToken::RebootRequired))?;
            if leases.active.is_some() {
                return Err((state.version, ErrorToken::Busy));
            }
        }
        let version = begin_provider_operation_state(
            &mut state,
            expected,
            false,
            self.stopping.load(Ordering::Acquire),
        )?;
        // The registry, rather than the generic provider-operation bit, owns
        // the borrow lifetime. This keeps vault.lock able to revoke a lease.
        state.provider_operation_active = false;
        if !connection.is_live()
            || !socket_client_is_live(candidate.socket.as_fd())
            || lease_pid_exited(candidate.pidfd.as_fd())
                .map_err(|_| (version, ErrorToken::RebootRequired))?
            || candidate
                .process
                .verify_initial_peer(candidate.peer_pid)
                .is_err()
        {
            return Err((version, ErrorToken::IoFailed));
        }
        self.runtime
            .lock()
            .map_err(|_| (version, ErrorToken::RebootRequired))?
            .arm_lifecycle()
            .map_err(|_| (version, ErrorToken::RebootRequired))?;
        // The marker fsync is intentionally outside the lease mutex. Recheck
        // every externally mutable gate before installing Pending so a stop
        // or peer exit during the arm cannot materialize a credential lease.
        if self.stopping.load(Ordering::Acquire) {
            return Err((version, ErrorToken::Busy));
        }
        if !connection.is_live()
            || !socket_client_is_live(candidate.socket.as_fd())
            || lease_pid_exited(candidate.pidfd.as_fd())
                .map_err(|_| (version, ErrorToken::RebootRequired))?
            || candidate
                .process
                .verify_initial_peer(candidate.peer_pid)
                .is_err()
        {
            return Err((version, ErrorToken::IoFailed));
        }
        let mut leases = self
            .leases
            .lock()
            .map_err(|_| (version, ErrorToken::RebootRequired))?;
        if leases.active.is_some() {
            return Err((version, ErrorToken::RebootRequired));
        }
        let lease_id = leases.next_id;
        leases.next_id = lease_id
            .checked_add(1)
            .filter(|next| *next != 0)
            .ok_or((version, ErrorToken::RebootRequired))?;
        leases.active = Some(ProviderLease {
            id: lease_id,
            socket: candidate.socket,
            pidfd: candidate.pidfd,
            peer_pid: candidate.peer_pid,
            process: candidate.process,
            state: LeaseState::Pending,
            handoff_deadline,
            lease_deadline: None,
            output_obligation: Arc::new(LeaseOutputState {
                finalized: AtomicBool::new(true),
            }),
        });
        Ok((version, lease_id))
    }

    fn provider_borrow_dispatch_ready(
        &self,
        lease_id: u64,
        connection: &ClientConnection<'_>,
    ) -> Result<ProviderDispatchArm, RescueVaultDaemonError> {
        let _decision = self
            .lifecycle
            .lock()
            .map_err(|_| RescueVaultDaemonError::RuntimeUnavailable)?;
        let state = self
            .state
            .lock()
            .map_err(|_| RescueVaultDaemonError::RuntimeUnavailable)?;
        let leases = self
            .leases
            .lock()
            .map_err(|_| RescueVaultDaemonError::RuntimeUnavailable)?;
        match leases.active.as_ref() {
            None => return Ok(ProviderDispatchArm::RevocationInProgress),
            Some(lease) if lease.id != lease_id => {
                return Ok(ProviderDispatchArm::RevocationInProgress);
            }
            Some(lease) if lease.state == LeaseState::Revoking => {
                return Ok(ProviderDispatchArm::RevocationInProgress);
            }
            Some(lease) if lease.state == LeaseState::Pending => {}
            Some(_) => return Err(RescueVaultDaemonError::PersistentFault),
        }
        if state.faulted
            || state.provider_operation_active
            || state.transition_origin.is_some()
            || !matches!(
                state.availability,
                Availability::Available {
                    state: VaultState::Unlocked,
                    device_id: Some(_),
                }
            )
        {
            return Err(RescueVaultDaemonError::PersistentFault);
        }
        if !connection.is_live() {
            return Ok(ProviderDispatchArm::ClientGoneBeforeArm);
        }
        if self.stopping.load(Ordering::Acquire) {
            return Ok(ProviderDispatchArm::StoppedBeforeArm);
        }
        self.privacy
            .validate_no_active_swap()
            .map_err(|()| RescueVaultDaemonError::RuntimeUnavailable)?;
        if self.stopping.load(Ordering::Acquire) {
            Ok(ProviderDispatchArm::StoppedBeforeArm)
        } else if !connection.is_live() {
            Ok(ProviderDispatchArm::ClientGoneBeforeArm)
        } else {
            Ok(ProviderDispatchArm::Armed)
        }
    }

    fn mark_lease_potentially_issued(
        &self,
        lease_id: u64,
    ) -> Result<PotentialIssue, RescueVaultDaemonError> {
        let _decision = self
            .lifecycle
            .lock()
            .map_err(|_| RescueVaultDaemonError::RuntimeUnavailable)?;
        let state = self
            .state
            .lock()
            .map_err(|_| RescueVaultDaemonError::RuntimeUnavailable)?;
        let mut leases = self
            .leases
            .lock()
            .map_err(|_| RescueVaultDaemonError::RuntimeUnavailable)?;
        let Some(lease) = leases.active.as_ref() else {
            return Ok(PotentialIssue::RevocationInProgress);
        };
        if lease.id != lease_id {
            return Ok(PotentialIssue::RevocationInProgress);
        }
        match lease.state {
            LeaseState::Pending => {}
            LeaseState::Revoking => return Ok(PotentialIssue::RevocationInProgress),
            LeaseState::PotentiallyIssued | LeaseState::Established => {
                return Err(RescueVaultDaemonError::PersistentFault);
            }
        }
        if state.faulted {
            return Ok(PotentialIssue::RevocationInProgress);
        }
        let pid_exited = lease_pid_exited(lease.pidfd.as_fd())?;
        let cancel_without_secret = state.provider_operation_active
            || state.transition_origin.is_some()
            || self.stopping.load(Ordering::Acquire)
            || Instant::now() >= lease.handoff_deadline
            || !socket_client_is_live(lease.socket.as_fd())
            || pid_exited;
        if cancel_without_secret {
            // Pending has never requested a credential descriptor. This is a
            // definite-no-secret cancellation, not release of an issued
            // process-scope lease.
            leases.active.take();
            return Ok(PotentialIssue::CancelledBeforeSecret);
        }
        lease.process.verify_initial_peer(lease.peer_pid)?;
        let output_obligation = Arc::new(LeaseOutputState {
            finalized: AtomicBool::new(false),
        });
        let lease = leases
            .active
            .as_mut()
            .ok_or(RescueVaultDaemonError::PersistentFault)?;
        lease.state = LeaseState::PotentiallyIssued;
        lease.output_obligation = Arc::clone(&output_obligation);
        Ok(PotentialIssue::Armed(LeaseOutputGuard::new(
            output_obligation,
        )))
    }

    fn cancel_pending_lease(&self, lease_id: u64) -> Result<PendingCancel, RescueVaultDaemonError> {
        let _decision = self
            .lifecycle
            .lock()
            .map_err(|_| RescueVaultDaemonError::RuntimeUnavailable)?;
        let state = self
            .state
            .lock()
            .map_err(|_| RescueVaultDaemonError::RuntimeUnavailable)?;
        let mut leases = self
            .leases
            .lock()
            .map_err(|_| RescueVaultDaemonError::RuntimeUnavailable)?;
        if state.faulted {
            return Ok(PendingCancel::RevocationInProgress);
        }
        match leases.active.as_ref() {
            Some(lease) if lease.id == lease_id && lease.state == LeaseState::Pending => {
                // Pending is removable without process termination because no
                // provider descriptor has been requested or transferred.
                leases.active.take();
                Ok(PendingCancel::CancelledHere(state.version))
            }
            Some(lease) if lease.id == lease_id && lease.state == LeaseState::Revoking => {
                Ok(PendingCancel::RevocationInProgress)
            }
            None => Ok(PendingCancel::RevocationInProgress),
            Some(lease) if lease.id != lease_id => Ok(PendingCancel::RevocationInProgress),
            Some(_) => Err(RescueVaultDaemonError::PersistentFault),
        }
    }

    fn finish_provider_borrow_ready(
        &self,
        lease_id: u64,
    ) -> Result<Option<u64>, RescueVaultDaemonError> {
        let _decision = self
            .lifecycle
            .lock()
            .map_err(|_| RescueVaultDaemonError::RuntimeUnavailable)?;
        let state = self
            .state
            .lock()
            .map_err(|_| RescueVaultDaemonError::RuntimeUnavailable)?;
        let leases = self
            .leases
            .lock()
            .map_err(|_| RescueVaultDaemonError::RuntimeUnavailable)?;
        let Some(lease) = leases.active.as_ref().filter(|lease| lease.id == lease_id) else {
            return Ok(None);
        };
        if lease.state == LeaseState::Revoking
            || self.stopping.load(Ordering::Acquire)
            || state.faulted
        {
            return Ok(None);
        }
        if lease.state != LeaseState::PotentiallyIssued
            || lease.output_obligation.finalized.load(Ordering::Acquire)
            || state.provider_operation_active
            || state.transition_origin.is_some()
            || !matches!(
                state.availability,
                Availability::Available {
                    state: VaultState::Unlocked,
                    device_id: Some(_),
                }
            )
        {
            return Err(RescueVaultDaemonError::PersistentFault);
        }
        Ok(Some(state.version))
    }

    fn finish_provider_borrow_unconfigured(
        &self,
        lease_id: u64,
    ) -> Result<Option<u64>, RescueVaultDaemonError> {
        let _decision = self
            .lifecycle
            .lock()
            .map_err(|_| RescueVaultDaemonError::RuntimeUnavailable)?;
        let state = self
            .state
            .lock()
            .map_err(|_| RescueVaultDaemonError::RuntimeUnavailable)?;
        let mut leases = self
            .leases
            .lock()
            .map_err(|_| RescueVaultDaemonError::RuntimeUnavailable)?;
        let Some(lease) = leases.active.as_ref().filter(|lease| lease.id == lease_id) else {
            return Ok(None);
        };
        if lease.state == LeaseState::Revoking
            || self.stopping.load(Ordering::Acquire)
            || state.faulted
        {
            return Ok(None);
        }
        if lease.state != LeaseState::PotentiallyIssued
            || !lease.output_obligation.finalized.load(Ordering::Acquire)
            || state.provider_operation_active
            || state.transition_origin.is_some()
            || !matches!(
                state.availability,
                Availability::Available {
                    state: VaultState::Unlocked,
                    device_id: Some(_),
                }
            )
        {
            return Err(RescueVaultDaemonError::PersistentFault);
        }
        // The worker returned an authenticated Unconfigured response with no
        // descriptor and the false-issued output obligation is finalized.
        leases.active.take();
        Ok(Some(state.version))
    }

    fn send_provider_descriptor(
        &self,
        lease_id: u64,
        send: impl FnOnce() -> bool,
    ) -> Result<DescriptorSend, RescueVaultDaemonError> {
        let decision = self
            .lifecycle
            .lock()
            .map_err(|_| RescueVaultDaemonError::RuntimeUnavailable)?;
        let state = self
            .state
            .lock()
            .map_err(|_| RescueVaultDaemonError::RuntimeUnavailable)?;
        let mut leases = self
            .leases
            .lock()
            .map_err(|_| RescueVaultDaemonError::RuntimeUnavailable)?;
        let Some(lease) = leases.active.as_mut().filter(|lease| lease.id == lease_id) else {
            return Ok(DescriptorSend::RevocationInProgress);
        };
        if lease.state == LeaseState::Revoking {
            return Ok(DescriptorSend::RevocationInProgress);
        }
        if lease.state != LeaseState::PotentiallyIssued
            || lease.lease_deadline.is_some()
            || lease.output_obligation.finalized.load(Ordering::Acquire)
            || state.provider_operation_active
            || state.transition_origin.is_some()
            || !matches!(
                state.availability,
                Availability::Available {
                    state: VaultState::Unlocked,
                    device_id: Some(_),
                }
            )
        {
            return Err(RescueVaultDaemonError::PersistentFault);
        }
        let must_revoke = self.stopping.load(Ordering::Acquire)
            || state.faulted
            || !socket_client_is_live(lease.socket.as_fd())
            || lease_pid_exited(lease.pidfd.as_fd())?;
        if must_revoke {
            lease.state = LeaseState::Revoking;
            let mut snapshot = snapshot_provider_lease(lease)?;
            snapshot.deadline = Instant::now()
                .checked_add(LEASE_REVOCATION_TIMEOUT)
                .unwrap_or_else(Instant::now);
            drop(leases);
            drop(state);
            drop(decision);
            return Ok(DescriptorSend::RevocationRequired(snapshot));
        }
        lease.process.verify_initial_peer(lease.peer_pid)?;
        lease.lease_deadline = Some(
            Instant::now()
                .checked_add(PROVIDER_LEASE_TIMEOUT)
                .unwrap_or_else(Instant::now),
        );
        drop(leases);
        drop(state);

        // The lifecycle guard is intentionally retained across SCM_RIGHTS.
        // Lock/revoke therefore either wins before this point or waits until
        // the send has completed or become ambiguous.
        if send() {
            let state = self
                .state
                .lock()
                .map_err(|_| RescueVaultDaemonError::RuntimeUnavailable)?;
            let mut leases = self
                .leases
                .lock()
                .map_err(|_| RescueVaultDaemonError::RuntimeUnavailable)?;
            let lease = leases
                .active
                .as_mut()
                .filter(|lease| lease.id == lease_id)
                .ok_or(RescueVaultDaemonError::PersistentFault)?;
            if lease.state != LeaseState::PotentiallyIssued
                || lease.lease_deadline.is_none()
                || state.faulted
            {
                return Err(RescueVaultDaemonError::PersistentFault);
            }
            lease.state = LeaseState::Established;
            drop(leases);
            drop(state);
            drop(decision);
            return Ok(DescriptorSend::Established);
        }

        let state = self
            .state
            .lock()
            .map_err(|_| RescueVaultDaemonError::RuntimeUnavailable)?;
        let mut leases = self
            .leases
            .lock()
            .map_err(|_| RescueVaultDaemonError::RuntimeUnavailable)?;
        let snapshot = match leases.active.as_mut().filter(|lease| lease.id == lease_id) {
            Some(lease) if lease.state == LeaseState::PotentiallyIssued => {
                lease.state = LeaseState::Revoking;
                let mut snapshot = snapshot_provider_lease(lease)?;
                snapshot.deadline = Instant::now()
                    .checked_add(LEASE_REVOCATION_TIMEOUT)
                    .unwrap_or_else(Instant::now);
                Some(snapshot)
            }
            Some(lease) if lease.state == LeaseState::Revoking => None,
            None => None,
            Some(_) => return Err(RescueVaultDaemonError::PersistentFault),
        };
        drop(leases);
        drop(state);
        drop(decision);
        if let Some(snapshot) = snapshot {
            Ok(DescriptorSend::RevocationRequired(snapshot))
        } else {
            Ok(DescriptorSend::RevocationInProgress)
        }
    }

    fn monitor_provider_lease(&self, lease_id: u64) -> Result<(), RescueVaultDaemonError> {
        let snapshot = {
            let _decision = self
                .lifecycle
                .lock()
                .map_err(|_| RescueVaultDaemonError::RuntimeUnavailable)?;
            let state = self
                .state
                .lock()
                .map_err(|_| RescueVaultDaemonError::RuntimeUnavailable)?;
            let leases = self
                .leases
                .lock()
                .map_err(|_| RescueVaultDaemonError::RuntimeUnavailable)?;
            let Some(lease) = leases.active.as_ref().filter(|lease| lease.id == lease_id) else {
                return Ok(());
            };
            if lease.state == LeaseState::Revoking || state.faulted {
                return Ok(());
            }
            if lease.state != LeaseState::Established {
                return Err(RescueVaultDaemonError::PersistentFault);
            }
            snapshot_provider_lease(lease)?
        };
        match wait_for_lease_evidence(&snapshot, snapshot.deadline)? {
            LeaseWait::Released => self.complete_normal_lease(lease_id),
            LeaseWait::Deadline => self.revoke_provider_lease(
                lease_id,
                Instant::now()
                    .checked_add(LEASE_REVOCATION_TIMEOUT)
                    .unwrap_or_else(Instant::now),
            ),
        }
    }

    fn complete_normal_lease(&self, lease_id: u64) -> Result<(), RescueVaultDaemonError> {
        let _decision = self
            .lifecycle
            .lock()
            .map_err(|_| RescueVaultDaemonError::RuntimeUnavailable)?;
        let _state = self
            .state
            .lock()
            .map_err(|_| RescueVaultDaemonError::RuntimeUnavailable)?;
        let mut leases = self
            .leases
            .lock()
            .map_err(|_| RescueVaultDaemonError::RuntimeUnavailable)?;
        match leases.active.as_ref().filter(|lease| lease.id == lease_id) {
            Some(lease)
                if lease.state == LeaseState::Established
                    && lease.output_obligation.finalized.load(Ordering::Acquire) =>
            {
                leases.active.take();
                Ok(())
            }
            Some(lease) if lease.state == LeaseState::Revoking => Ok(()),
            None => Ok(()),
            Some(_) => Err(RescueVaultDaemonError::PersistentFault),
        }
    }

    fn revoke_provider_lease(
        &self,
        lease_id: u64,
        deadline: Instant,
    ) -> Result<(), RescueVaultDaemonError> {
        let snapshot = {
            let _decision = self
                .lifecycle
                .lock()
                .map_err(|_| RescueVaultDaemonError::RuntimeUnavailable)?;
            let _state = self
                .state
                .lock()
                .map_err(|_| RescueVaultDaemonError::RuntimeUnavailable)?;
            let mut leases = self
                .leases
                .lock()
                .map_err(|_| RescueVaultDaemonError::RuntimeUnavailable)?;
            let Some(lease) = leases.active.as_mut().filter(|lease| lease.id == lease_id) else {
                return Ok(());
            };
            lease.state = LeaseState::Revoking;
            let mut snapshot = snapshot_provider_lease(lease)?;
            snapshot.deadline = deadline;
            snapshot
        };
        self.finish_provider_revocation(snapshot)
    }

    fn revoke_active_lease(&self, deadline: Instant) -> Result<(), RescueVaultDaemonError> {
        let lease_id = {
            let _decision = self
                .lifecycle
                .lock()
                .map_err(|_| RescueVaultDaemonError::RuntimeUnavailable)?;
            let _state = self
                .state
                .lock()
                .map_err(|_| RescueVaultDaemonError::RuntimeUnavailable)?;
            self.leases
                .lock()
                .map_err(|_| RescueVaultDaemonError::RuntimeUnavailable)?
                .active
                .as_ref()
                .map(|lease| lease.id)
        };
        match lease_id {
            Some(lease_id) => self.revoke_provider_lease(lease_id, deadline),
            None => Ok(()),
        }
    }

    fn finish_provider_revocation(
        &self,
        snapshot: LeaseSnapshot,
    ) -> Result<(), RescueVaultDaemonError> {
        // Kill the complete delegated unit tree first. The pidfd signal stays
        // as an independent defense for the authenticated peer itself.
        let tree_kill_ok = snapshot.process.kill_all().is_ok();
        let already_exited = lease_pid_exited(snapshot.pidfd.as_fd())?;
        let signal_result = if already_exited {
            Ok(())
        } else {
            pidfd_send_signal(&snapshot.pidfd, ProcessSignal::KILL)
        };
        // ESRCH is only provisionally acceptable here. The wait below must
        // still prove pidfd POLLIN, full peer-socket HUP, output finalization,
        // and whole-tree quiescence.
        let signal_ok = signal_result.is_ok()
            || signal_result
                .as_ref()
                .is_err_and(|error| *error == rustix::io::Errno::SRCH);
        let evidence = wait_for_lease_evidence(&snapshot, snapshot.deadline)?;
        if evidence != LeaseWait::Released {
            return Err(RescueVaultDaemonError::ShutdownFailed);
        }
        let _decision = self
            .lifecycle
            .lock()
            .map_err(|_| RescueVaultDaemonError::ShutdownFailed)?;
        let _state = self
            .state
            .lock()
            .map_err(|_| RescueVaultDaemonError::ShutdownFailed)?;
        let mut leases = self
            .leases
            .lock()
            .map_err(|_| RescueVaultDaemonError::ShutdownFailed)?;
        match leases
            .active
            .as_ref()
            .filter(|lease| lease.id == snapshot.id)
        {
            Some(lease) if lease.state == LeaseState::Revoking => {
                leases.active.take();
            }
            Some(_) => return Err(RescueVaultDaemonError::ShutdownFailed),
            None => {}
        }
        if tree_kill_ok && signal_ok {
            Ok(())
        } else {
            Err(RescueVaultDaemonError::ShutdownFailed)
        }
    }

    fn sweep_expired_lease(&self) -> Result<(), RescueVaultDaemonError> {
        let expired = {
            let _decision = self
                .lifecycle
                .lock()
                .map_err(|_| RescueVaultDaemonError::RuntimeUnavailable)?;
            let _state = self
                .state
                .lock()
                .map_err(|_| RescueVaultDaemonError::RuntimeUnavailable)?;
            self.leases
                .lock()
                .map_err(|_| RescueVaultDaemonError::RuntimeUnavailable)?
                .active
                .as_ref()
                .filter(|lease| lease.state != LeaseState::Revoking)
                .and_then(|lease| {
                    let deadline = lease.lease_deadline.unwrap_or(lease.handoff_deadline);
                    (Instant::now() >= deadline).then_some(lease.id)
                })
        };
        if let Some(lease_id) = expired {
            self.revoke_provider_lease(
                lease_id,
                Instant::now()
                    .checked_add(LEASE_REVOCATION_TIMEOUT)
                    .unwrap_or_else(Instant::now),
            )?;
        }
        Ok(())
    }

    fn provider_dispatch_ready(
        &self,
        mutation: bool,
        connection: &ClientConnection<'_>,
    ) -> Result<DispatchArm, RescueVaultDaemonError> {
        let _decision = self
            .lifecycle
            .lock()
            .map_err(|_| RescueVaultDaemonError::RuntimeUnavailable)?;
        let state = self
            .state
            .lock()
            .map_err(|_| RescueVaultDaemonError::RuntimeUnavailable)?;
        if state.faulted
            || !state.provider_operation_active
            || mutation != state.transition_origin.is_some()
            || !matches!(
                state.availability,
                Availability::Available {
                    state: VaultState::Unlocked,
                    device_id: Some(_),
                }
            )
        {
            return Err(RescueVaultDaemonError::PersistentFault);
        }
        if !connection.is_live() {
            return Ok(DispatchArm::ClientGoneBeforeArm);
        }
        if self.stopping.load(Ordering::Acquire) {
            return Ok(DispatchArm::StoppedBeforeArm);
        }
        self.privacy
            .validate_no_active_swap()
            .map_err(|()| RescueVaultDaemonError::RuntimeUnavailable)?;
        if self.stopping.load(Ordering::Acquire) {
            return Ok(DispatchArm::StoppedBeforeArm);
        }
        if !connection.is_live() {
            return Ok(DispatchArm::ClientGoneBeforeArm);
        }
        if mutation {
            self.runtime
                .lock()
                .map_err(|_| RescueVaultDaemonError::RuntimeUnavailable)?
                .arm_lifecycle()?;
        }
        if self.stopping.load(Ordering::Acquire) {
            Ok(DispatchArm::StoppedAfterArm)
        } else if !connection.is_live() {
            Ok(DispatchArm::ClientGoneAfterArm)
        } else {
            Ok(DispatchArm::Armed)
        }
    }

    fn release_provider_status(&self) -> Result<u64, ()> {
        let _decision = self.lifecycle.lock().map_err(|_| ())?;
        let mut state = self.state.lock().map_err(|_| ())?;
        if state.faulted
            || !state.provider_operation_active
            || state.transition_origin.is_some()
            || !matches!(
                state.availability,
                Availability::Available {
                    state: VaultState::Unlocked,
                    device_id: Some(_),
                }
            )
        {
            return Err(());
        }
        state.provider_operation_active = false;
        Ok(state.version)
    }

    fn complete_provider_mutation(&self) -> Result<u64, ()> {
        let _decision = self.lifecycle.lock().map_err(|_| ())?;
        let mut state = self.state.lock().map_err(|_| ())?;
        let origin = state.transition_origin.as_ref().ok_or(())?;
        if state.faulted
            || !state.provider_operation_active
            || origin != &state.availability
            || !matches!(
                state.availability,
                Availability::Available {
                    state: VaultState::Unlocked,
                    device_id: Some(_),
                }
            )
            || state.version >= MAX_SAFE_JSON_INTEGER
        {
            return Err(());
        }
        state.version += 1;
        state.transition_origin = None;
        state.provider_operation_active = false;
        Ok(state.version)
    }

    fn finish_provider_mutation_without_dispatch(
        &self,
        request: ValidatedRequest,
        error: ErrorToken,
        deadline: Instant,
    ) -> (u64, HandlerResult) {
        match self.complete_provider_mutation() {
            Ok(version) => (version, HandlerResult::Error(request, error)),
            Err(()) => {
                self.mark_fault_by(deadline);
                (
                    self.snapshot().version,
                    HandlerResult::Error(request, ErrorToken::RebootRequired),
                )
            }
        }
    }

    fn finish_provider_mutation(
        &self,
        request: ValidatedRequest,
        response: internal_wire::WorkerResponse,
        desired: ProviderState,
        expected_success: internal_wire::WorkerResultCode,
        deadline: Instant,
    ) -> (u64, HandlerResult) {
        use internal_wire::WorkerResultCode as Result;
        if response.code == expected_success {
            return match self.complete_provider_mutation() {
                Ok(version) => (
                    version,
                    HandlerResult::Success(
                        request,
                        SuccessPayload::ProviderStatus(ProviderStatusPayload {
                            openai: desired,
                            codex: ProviderState::Unconfigured,
                        }),
                    ),
                ),
                Err(()) => {
                    self.mark_fault_by(deadline);
                    (
                        self.snapshot().version,
                        HandlerResult::Error(request, ErrorToken::RebootRequired),
                    )
                }
            };
        }
        match response.code {
            Result::ProviderMutationAborted | Result::InvalidRequest => {
                match self.complete_provider_mutation() {
                    Ok(version) => (version, HandlerResult::Error(request, ErrorToken::IoFailed)),
                    Err(()) => {
                        self.mark_fault_by(deadline);
                        (
                            self.snapshot().version,
                            HandlerResult::Error(request, ErrorToken::RebootRequired),
                        )
                    }
                }
            }
            _ => {
                self.mark_fault_by(deadline);
                (
                    self.snapshot().version,
                    HandlerResult::Error(request, ErrorToken::RebootRequired),
                )
            }
        }
    }

    fn complete_transition(
        &self,
        expected: VaultState,
        availability: Availability,
    ) -> Result<u64, ()> {
        let _decision = self.lifecycle.lock().map_err(|_| ())?;
        let mut state = self.state.lock().map_err(|_| ())?;
        validate_completion(&state, expected)?;
        if matches!(
            &availability,
            Availability::Available {
                state: VaultState::Unlocked,
                ..
            }
        ) {
            self.runtime
                .lock()
                .map_err(|_| ())?
                .arm_lifecycle()
                .map_err(|_| ())?;
        }
        Ok(apply_completion(&mut state, availability))
    }

    fn complete_after_locked_attestation(
        &self,
        expected: VaultState,
        availability: Availability,
        deadline: Instant,
    ) -> Result<u64, ()> {
        let worker = self.worker.as_ref().ok_or(())?;
        let response = worker
            .transact(
                internal_wire::WorkerCommandKind::AttestQuiescent,
                None,
                None,
                deadline,
            )
            .map_err(|_| ())?;
        let (response, output) = response;
        if response.code != internal_wire::WorkerResultCode::AttestLocked
            || response.device_id.is_some()
            || output.is_some()
        {
            return Err(());
        }
        let _decision = self.lifecycle.lock().map_err(|_| ())?;
        let mut state = self.state.lock().map_err(|_| ())?;
        validate_completion(&state, expected)?;
        worker.verify_healthy().map_err(|_| ())?;
        self.runtime
            .lock()
            .map_err(|_| ())?
            .disarm_after_verified_locked()
            .map_err(|_| ())?;
        Ok(apply_completion(&mut state, availability))
    }

    fn complete_locked_after_nonmutation(&self) -> Result<u64, ()> {
        self.complete_transition(VaultState::Unlocking, available(VaultState::Locked, None))
    }

    fn arm_for_dispatch(
        &self,
        expected: VaultState,
        connection: &ClientConnection<'_>,
    ) -> Result<DispatchArm, RescueVaultDaemonError> {
        let _decision = self
            .lifecycle
            .lock()
            .map_err(|_| RescueVaultDaemonError::RuntimeUnavailable)?;
        let state = self
            .state
            .lock()
            .map_err(|_| RescueVaultDaemonError::RuntimeUnavailable)?;
        if state.faulted
            || !matches!(
                state.availability,
                Availability::Available { state: current, .. } if current == expected
            )
        {
            return Err(RescueVaultDaemonError::PersistentFault);
        }
        if !connection.is_live() {
            return Ok(DispatchArm::ClientGoneBeforeArm);
        }
        if self.stopping.load(Ordering::Acquire) {
            return Ok(DispatchArm::StoppedBeforeArm);
        }
        self.privacy
            .validate_no_active_swap()
            .map_err(|()| RescueVaultDaemonError::RuntimeUnavailable)?;
        if self.stopping.load(Ordering::Acquire) {
            return Ok(DispatchArm::StoppedBeforeArm);
        }
        if !connection.is_live() {
            return Ok(DispatchArm::ClientGoneBeforeArm);
        }
        self.runtime
            .lock()
            .map_err(|_| RescueVaultDaemonError::RuntimeUnavailable)?
            .arm_lifecycle()?;
        if self.stopping.load(Ordering::Acquire) {
            Ok(DispatchArm::StoppedAfterArm)
        } else if !connection.is_live() {
            Ok(DispatchArm::ClientGoneAfterArm)
        } else {
            Ok(DispatchArm::Armed)
        }
    }

    fn rollback_transition_for_stop(&self, expected: VaultState) -> Result<u64, ()> {
        let _decision = self.lifecycle.lock().map_err(|_| ())?;
        let mut state = self.state.lock().map_err(|_| ())?;
        validate_completion(&state, expected)?;
        let origin = state.transition_origin.take().ok_or(())?;
        Ok(apply_completion(&mut state, origin))
    }

    fn startup_readiness(
        &self,
        mut containment: FaultContainment,
        disposition: RuntimeDisposition,
    ) -> StartupReadiness {
        if !self.faulted.load(Ordering::Acquire) {
            let worker_is_healthy = self
                .worker
                .as_ref()
                .is_some_and(|worker| worker.verify_healthy().is_ok());
            if !worker_is_healthy {
                containment = self.mark_fault();
            }
        }
        let state = match self.state.lock() {
            Ok(state) => state,
            Err(_) => return StartupReadiness::Failed,
        };
        let leases_empty = self
            .leases
            .lock()
            .map(|leases| leases.active.is_none())
            .unwrap_or(false);
        let faulted = self.faulted.load(Ordering::Acquire);
        let coherent = faulted == state.faulted
            && state.transition_origin.is_none()
            && !state.provider_operation_active
            && leases_empty
            && !state.marker_persistence_failed
            && if faulted {
                disposition == RuntimeDisposition::PersistentFault
                    && state.fault_marker_required
                    && containment.permits_status_service()
                    && matches!(
                        state.availability,
                        Availability::Available {
                            state: VaultState::FaultedRebootRequired,
                            device_id: None,
                        }
                    )
            } else {
                !state.fault_marker_required && self.worker.is_some()
            };
        if !coherent {
            StartupReadiness::Failed
        } else if self.stopping.load(Ordering::Acquire) {
            StartupReadiness::Stopping
        } else {
            StartupReadiness::Ready
        }
    }

    fn mark_fault(&self) -> FaultContainment {
        self.mark_fault_by(
            Instant::now()
                .checked_add(SHUTDOWN_TIMEOUT)
                .unwrap_or_else(Instant::now),
        )
    }

    fn mark_fault_by(&self, requested_deadline: Instant) -> FaultContainment {
        let deadline = self
            .stop_deadline
            .lock()
            .ok()
            .and_then(|deadline| *deadline)
            .map_or(requested_deadline, |stop| stop.min(requested_deadline));
        let first_marker_attempt = {
            let _decision = self
                .lifecycle
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            self.faulted.store(true, Ordering::Release);
            {
                let mut state = self
                    .state
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner);
                transition_state_to_fault(&mut state, true);
            }
            let mut runtime = self
                .runtime
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            runtime.arm_lifecycle()
        };
        let revoke_deadline = Instant::now()
            .checked_add(LEASE_REVOCATION_TIMEOUT)
            .unwrap_or(deadline)
            .min(deadline);
        let lease_quiesced = self.revoke_active_lease(revoke_deadline).is_ok();
        let worker_terminated = self
            .worker
            .as_ref()
            .is_none_or(|worker| worker.fault_and_terminate(deadline).is_ok());
        let worker_quiesced = lease_quiesced && worker_terminated;
        let marker_result = if first_marker_attempt.is_ok() {
            first_marker_attempt
        } else {
            let _decision = self
                .lifecycle
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            self.runtime
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .arm_lifecycle()
        };
        let _decision = self
            .lifecycle
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        state.marker_persistence_failed = marker_result.is_err();
        if state.marker_persistence_failed || !lease_quiesced || !worker_terminated {
            self.stopping.store(true, Ordering::Release);
        }
        FaultContainment {
            marker_durable: marker_result.is_ok(),
            worker_quiesced,
        }
    }

    fn mark_pre_mutation_fault_by(&self, requested_deadline: Instant) {
        let local_deadline = Instant::now()
            .checked_add(SHUTDOWN_TIMEOUT)
            .unwrap_or(requested_deadline);
        let deadline = requested_deadline.min(local_deadline);
        let prepared = (|| {
            let _decision = self.lifecycle.lock().map_err(|_| ())?;
            let mut state = self.state.lock().map_err(|_| ())?;
            if state.fault_marker_required {
                return Err(());
            }
            self.runtime
                .lock()
                .map_err(|_| ())?
                .sync_and_verify_disarmed()
                .map_err(|_| ())?;
            self.faulted.store(true, Ordering::Release);
            transition_state_to_fault(&mut state, false);
            state.marker_persistence_failed = false;
            state.clean_fault_shutdown = false;
            self.stopping.store(true, Ordering::Release);
            Ok(())
        })();
        if prepared.is_err() {
            self.mark_fault_by(deadline);
            return;
        }
        let worker_clean = self
            .worker
            .as_ref()
            .is_none_or(|worker| worker.cancel_clean(deadline).is_ok());
        let finalized = if worker_clean {
            (|| {
                let _decision = self.lifecycle.lock().map_err(|_| ())?;
                let mut state = self.state.lock().map_err(|_| ())?;
                if state.fault_marker_required {
                    return Err(());
                }
                self.runtime
                    .lock()
                    .map_err(|_| ())?
                    .sync_and_verify_disarmed()
                    .map_err(|_| ())?;
                state.clean_fault_shutdown = true;
                Ok(())
            })()
            .is_ok()
        } else {
            false
        };
        if !finalized {
            self.mark_fault_by(deadline);
        }
    }

    fn shutdown(&self, deadline: Instant) -> Result<(), RescueVaultDaemonError> {
        let result = (|| {
            let _decision = self
                .lifecycle
                .lock()
                .map_err(|_| RescueVaultDaemonError::ShutdownFailed)?;
            let state = self
                .state
                .lock()
                .map_err(|_| RescueVaultDaemonError::ShutdownFailed)?;
            let leases = self
                .leases
                .lock()
                .map_err(|_| RescueVaultDaemonError::ShutdownFailed)?;
            if leases.active.is_some() {
                return Err(RescueVaultDaemonError::ShutdownFailed);
            }
            drop(leases);
            if state.faulted {
                if !state.fault_marker_required
                    && !state.marker_persistence_failed
                    && state.clean_fault_shutdown
                {
                    drop(state);
                    self.runtime
                        .lock()
                        .map_err(|_| RescueVaultDaemonError::ShutdownFailed)?
                        .sync_and_verify_disarmed()
                        .map_err(|_| RescueVaultDaemonError::ShutdownFailed)
                } else {
                    Err(RescueVaultDaemonError::ShutdownFailed)
                }
            } else {
                drop(state);
                if let Some(worker) = self.worker.as_ref() {
                    worker.shutdown_clean(deadline)?;
                }
                self.runtime
                    .lock()
                    .map_err(|_| RescueVaultDaemonError::ShutdownFailed)?
                    .disarm_after_verified_locked()
            }
        })();
        if result.is_err() {
            self.mark_fault_by(deadline);
        }
        result
    }
}

fn external_operation_is_enabled(
    operation: Operation,
    role: kernaid_protocol::rescue_vault::PeerRole,
) -> bool {
    match role {
        kernaid_protocol::rescue_vault::PeerRole::Companion => matches!(
            operation,
            Operation::VaultStatus
                | Operation::VaultUnlock
                | Operation::VaultLock
                | Operation::ProviderOpenAiConfigure
                | Operation::ProviderStatus
                | Operation::ProviderLogout
        ),
        kernaid_protocol::rescue_vault::PeerRole::Agent(AgentRole::OpenAi) => matches!(
            operation,
            Operation::VaultStatus | Operation::ProviderStatus | Operation::ProviderOpenAiBorrow
        ),
        kernaid_protocol::rescue_vault::PeerRole::Agent(AgentRole::Codex) => {
            cfg!(feature = "experimental-codex-home-lease")
                && matches!(
                    operation,
                    Operation::VaultStatus
                        | Operation::ProviderStatus
                        | Operation::ProviderCodexHomeLease
                )
        }
        kernaid_protocol::rescue_vault::PeerRole::Agent(AgentRole::Application) => false,
    }
}

#[cfg(feature = "experimental-codex-home-lease")]
fn validate_codex_home_handoff(descriptor: &OwnedFd) -> Result<(), RescueVaultDaemonError> {
    const EXT4_SUPER_MAGIC: u64 = 0xef53;
    let stat = rfs::fstat(descriptor).map_err(|_| RescueVaultDaemonError::ProtocolFailure)?;
    let filesystem =
        rfs::fstatfs(descriptor).map_err(|_| RescueVaultDaemonError::ProtocolFailure)?;
    let status =
        rfs::fcntl_getfl(descriptor).map_err(|_| RescueVaultDaemonError::ProtocolFailure)?;
    let flags =
        rustix::io::fcntl_getfd(descriptor).map_err(|_| RescueVaultDaemonError::ProtocolFailure)?;
    if !FileType::from_raw_mode(stat.st_mode).is_dir()
        || stat.st_nlink < 2
        || stat.st_uid != crate::CODEX_AGENT_UID
        || stat.st_gid != crate::CODEX_AGENT_GID
        || stat.st_mode & 0o7777 != 0o700
        || u64::try_from(filesystem.f_type).ok() != Some(EXT4_SUPER_MAGIC)
        || !crate::codex_home_status_flags_are_exact(status)
        || flags != rustix::io::FdFlags::CLOEXEC
    {
        return Err(RescueVaultDaemonError::ProtocolFailure);
    }
    Ok(())
}

fn provider_process_scope(role: kernaid_protocol::rescue_vault::PeerRole) -> ProcessScope {
    match role {
        kernaid_protocol::rescue_vault::PeerRole::Agent(AgentRole::OpenAi) => {
            ProcessScope::CgroupTree
        }
        #[cfg(feature = "experimental-codex-home-lease")]
        kernaid_protocol::rescue_vault::PeerRole::Agent(AgentRole::Codex) => {
            ProcessScope::CgroupTree
        }
        #[cfg(not(feature = "experimental-codex-home-lease"))]
        kernaid_protocol::rescue_vault::PeerRole::Agent(AgentRole::Codex) => {
            ProcessScope::DirectPeer
        }
        kernaid_protocol::rescue_vault::PeerRole::Companion
        | kernaid_protocol::rescue_vault::PeerRole::Agent(AgentRole::Application) => {
            ProcessScope::DirectPeer
        }
    }
}

fn external_request_is_enabled(request: &ValidatedRequest) -> bool {
    external_operation_is_enabled(request.operation(), request.role())
        && !matches!(
            request.payload(),
            RequestPayload::ProviderLogout {
                provider: Provider::Codex
            }
        )
}

fn status_version_is_accepted(expected: u64, current: u64) -> bool {
    expected == 0 || expected == current
}

fn begin_unlock_state(
    state: &mut ServiceState,
    expected: u64,
    now: Instant,
    stopping: bool,
) -> Result<u64, (u64, ErrorToken)> {
    if state.faulted {
        return Err((state.version, ErrorToken::RebootRequired));
    }
    if stopping {
        return Err((state.version, ErrorToken::Busy));
    }
    if expected != state.version {
        return Err((state.version, ErrorToken::StaleState));
    }
    if state.provider_operation_active {
        return Err((state.version, ErrorToken::Busy));
    }
    match &state.availability {
        Availability::Unavailable(error) => return Err((state.version, *error)),
        Availability::Available { state: vault, .. } => {
            if let Err(error) = gate_operation_for_vault_state(*vault, Operation::VaultUnlock) {
                return Err((state.version, error));
            }
            match vault {
                VaultState::Absent => return Err((state.version, ErrorToken::Absent)),
                VaultState::Unprovisioned => {
                    return Err((state.version, ErrorToken::Unprovisioned));
                }
                VaultState::Locked => {}
                VaultState::Unlocked
                | VaultState::Unlocking
                | VaultState::Locking
                | VaultState::FaultedRebootRequired => {
                    return Err((state.version, ErrorToken::Busy));
                }
            }
        }
    }
    if state
        .last_unlock_attempt
        .is_some_and(|last| now.saturating_duration_since(last) < UNLOCK_RATE_LIMIT)
    {
        return Err((state.version, ErrorToken::RateLimited));
    }
    ensure_transition_headroom(state.version, 2).map_err(|error| (state.version, error))?;
    if state.transition_origin.is_some() {
        return Err((state.version, ErrorToken::RebootRequired));
    }
    state.transition_origin = Some(state.availability.clone());
    state.version += 1;
    state.availability = available(VaultState::Unlocking, None);
    state.last_unlock_attempt = Some(now);
    Ok(state.version)
}

fn begin_lock_state(
    state: &mut ServiceState,
    expected: u64,
    stopping: bool,
) -> Result<u64, (u64, ErrorToken)> {
    if state.faulted {
        return Err((state.version, ErrorToken::RebootRequired));
    }
    if stopping {
        return Err((state.version, ErrorToken::Busy));
    }
    if expected != state.version {
        return Err((state.version, ErrorToken::StaleState));
    }
    if state.provider_operation_active {
        return Err((state.version, ErrorToken::Busy));
    }
    match &state.availability {
        Availability::Unavailable(error) => return Err((state.version, *error)),
        Availability::Available { state: vault, .. } => {
            if let Err(error) = gate_operation_for_vault_state(*vault, Operation::VaultLock) {
                return Err((state.version, error));
            }
            match vault {
                VaultState::Unlocked => {}
                VaultState::Locked => return Err((state.version, ErrorToken::Locked)),
                VaultState::Absent => return Err((state.version, ErrorToken::Absent)),
                VaultState::Unprovisioned => {
                    return Err((state.version, ErrorToken::Unprovisioned));
                }
                VaultState::Unlocking | VaultState::Locking => {
                    return Err((state.version, ErrorToken::Busy));
                }
                VaultState::FaultedRebootRequired => {
                    return Err((state.version, ErrorToken::RebootRequired));
                }
            }
        }
    }
    ensure_transition_headroom(state.version, 2).map_err(|error| (state.version, error))?;
    if state.transition_origin.is_some() {
        return Err((state.version, ErrorToken::RebootRequired));
    }
    state.transition_origin = Some(state.availability.clone());
    state.version += 1;
    state.availability = available(VaultState::Locking, None);
    Ok(state.version)
}

fn begin_provider_operation_state(
    state: &mut ServiceState,
    expected: u64,
    mutation: bool,
    stopping: bool,
) -> Result<u64, (u64, ErrorToken)> {
    if state.faulted {
        return Err((state.version, ErrorToken::RebootRequired));
    }
    if stopping {
        return Err((state.version, ErrorToken::Busy));
    }
    if expected != state.version {
        return Err((state.version, ErrorToken::StaleState));
    }
    if state.provider_operation_active || state.transition_origin.is_some() {
        return Err((state.version, ErrorToken::Busy));
    }
    match &state.availability {
        Availability::Unavailable(error) => return Err((state.version, *error)),
        Availability::Available { state: vault, .. } => match vault {
            VaultState::Unlocked => {}
            VaultState::Absent => return Err((state.version, ErrorToken::Absent)),
            VaultState::Unprovisioned => {
                return Err((state.version, ErrorToken::Unprovisioned));
            }
            VaultState::Locked => return Err((state.version, ErrorToken::Locked)),
            VaultState::Unlocking | VaultState::Locking => {
                return Err((state.version, ErrorToken::Busy));
            }
            VaultState::FaultedRebootRequired => {
                return Err((state.version, ErrorToken::RebootRequired));
            }
        },
    }
    if mutation {
        ensure_transition_headroom(state.version, 2).map_err(|error| (state.version, error))?;
        state.transition_origin = Some(state.availability.clone());
        state.version += 1;
    }
    state.provider_operation_active = true;
    Ok(state.version)
}

fn validate_completion(state: &ServiceState, expected: VaultState) -> Result<(), ()> {
    if state.faulted
        || state.provider_operation_active
        || state.transition_origin.is_none()
        || !matches!(
            state.availability,
            Availability::Available { state: current, .. } if current == expected
        )
        || state.version >= MAX_SAFE_JSON_INTEGER
    {
        Err(())
    } else {
        Ok(())
    }
}

fn apply_completion(state: &mut ServiceState, availability: Availability) -> u64 {
    debug_assert!(!state.faulted && state.version < MAX_SAFE_JSON_INTEGER);
    state.version += 1;
    state.availability = availability;
    state.transition_origin = None;
    state.provider_operation_active = false;
    state.version
}

fn transition_state_to_fault(state: &mut ServiceState, marker_required: bool) {
    if !state.faulted {
        state.faulted = true;
        if state.version < MAX_SAFE_JSON_INTEGER {
            state.version += 1;
        }
    }
    state.fault_marker_required |= marker_required;
    if state.fault_marker_required {
        state.clean_fault_shutdown = false;
    }
    state.availability = faulted_availability();
    state.transition_origin = None;
    state.provider_operation_active = false;
}

fn ensure_transition_headroom(version: u64, transitions: u64) -> Result<(), ErrorToken> {
    version
        .checked_add(transitions)
        .filter(|value| *value <= MAX_SAFE_JSON_INTEGER)
        .map(|_| ())
        .ok_or(ErrorToken::RebootRequired)
}

fn read_exact_passphrase(
    descriptor: OwnedFd,
    declared_size: u64,
    deadline: Instant,
) -> Result<Zeroizing<Vec<u8>>, ()> {
    let expected = usize::try_from(declared_size).map_err(|_| ())?;
    let status = rfs::fcntl_getfl(&descriptor).map_err(|_| ())?;
    rfs::fcntl_setfl(&descriptor, status | OFlags::NONBLOCK).map_err(|_| ())?;
    let mut value = Zeroizing::new(Vec::with_capacity(expected));
    while value.len() < expected {
        ensure_before(deadline)?;
        let mut buffer = Zeroizing::new([0_u8; 256]);
        let remaining = expected - value.len();
        let chunk = remaining.min(buffer.len());
        match rustix::io::read(&descriptor, &mut buffer[..chunk]) {
            Ok(0) => return Err(()),
            Ok(read) => value.extend_from_slice(&buffer[..read]),
            Err(error) if error == rustix::io::Errno::INTR => {}
            Err(error) if error == rustix::io::Errno::AGAIN => {
                wait_pipe(descriptor.as_fd(), deadline)?;
            }
            Err(_) => return Err(()),
        }
    }
    let reached_eof = loop {
        ensure_before(deadline)?;
        let mut extra = Zeroizing::new([0_u8; 1]);
        match rustix::io::read(&descriptor, &mut extra[..]) {
            Ok(0) => break true,
            Ok(_) => break false,
            Err(error) if error == rustix::io::Errno::INTR => {}
            Err(error) if error == rustix::io::Errno::AGAIN => {
                wait_pipe(descriptor.as_fd(), deadline)?;
            }
            Err(_) => return Err(()),
        }
    };
    validate_passphrase_read(&value, declared_size, reached_eof).map_err(|_| ())?;
    Ok(value)
}

fn repipe_passphrase(secret: &[u8]) -> Result<OwnedFd, ()> {
    let (read, write) = pipe_with(PipeFlags::CLOEXEC).map_err(|_| ())?;
    let mut written = 0;
    while written < secret.len() {
        match rustix::io::write(&write, &secret[written..]) {
            Ok(0) => return Err(()),
            Ok(count) => written += count,
            Err(error) if error == rustix::io::Errno::INTR => {}
            Err(_) => return Err(()),
        }
    }
    drop(write);
    Ok(read)
}

fn wait_pipe(descriptor: BorrowedFd<'_>, deadline: Instant) -> Result<(), ()> {
    let remaining = deadline.checked_duration_since(Instant::now()).ok_or(())?;
    let mut descriptors = [PollFd::from_borrowed_fd(descriptor, PollFlags::IN)];
    match poll(&mut descriptors, Some(&duration_to_timespec(remaining))) {
        Ok(0) => Err(()),
        Ok(_) if descriptors[0].revents().contains(PollFlags::NVAL) => Err(()),
        Ok(_) => Ok(()),
        Err(error) if error == rustix::io::Errno::INTR => Ok(()),
        Err(_) => Err(()),
    }
}

fn ensure_before(deadline: Instant) -> Result<(), ()> {
    deadline
        .checked_duration_since(Instant::now())
        .filter(|remaining| !remaining.is_zero())
        .map(|_| ())
        .ok_or(())
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

#[cfg(test)]
mod tests {
    use super::*;
    use kernaid_protocol::rescue_vault::{API_VERSION, PeerRole, authenticate_seqpacket_peer};
    use rustix::{
        net::{
            AddressFamily, SendAncillaryBuffer, SendAncillaryMessage, SendFlags, Shutdown,
            SocketFlags, SocketType, bind, recv, send, sendmsg, shutdown, socket_with, socketpair,
        },
        pipe::{PipeFlags, pipe_with},
        process::{Pid, PidfdFlags, pidfd_open},
    };
    use std::{
        collections::VecDeque,
        ffi::OsString,
        io::IoSlice,
        mem::MaybeUninit,
        os::unix::ffi::OsStringExt,
        os::unix::thread::JoinHandleExt,
        process::Command,
        sync::{
            atomic::{AtomicU64, AtomicUsize},
            mpsc,
        },
    };

    #[derive(Default)]
    struct FakeRuntimeState {
        arms: usize,
        disarms: usize,
        disarmed_checks: usize,
        marker: bool,
        fail_arms: usize,
        fail_arm_on: Option<usize>,
        fail_disarms: usize,
        fail_disarmed_checks: usize,
    }

    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    enum TraceEvent {
        RuntimeArm,
        RuntimeArmFailed,
        RuntimeDisarm,
        RuntimeDisarmFailed,
        RuntimeDisarmedCheck,
        RuntimeDisarmedCheckFailed,
        WorkerUnlock,
        WorkerLock,
        WorkerAttest,
        WorkerVerify,
        WorkerVerifyFailed,
        WorkerCancel,
        WorkerFault,
        WorkerShutdown,
        WorkerOther,
        CallerObservedPublication,
    }

    struct FakeRuntime {
        state: Arc<Mutex<FakeRuntimeState>>,
        trace: Arc<Mutex<Vec<TraceEvent>>>,
    }

    impl RuntimeBoundary for FakeRuntime {
        fn arm_lifecycle(&mut self) -> Result<(), RescueVaultDaemonError> {
            let mut state = self.state.lock().expect("fake runtime");
            state.arms += 1;
            let fail_countdown = state.fail_arms > 0;
            let fail_nth = state.fail_arm_on == Some(state.arms);
            if fail_countdown || fail_nth {
                state.fail_arms = state.fail_arms.saturating_sub(1);
                if fail_nth {
                    state.fail_arm_on = None;
                }
                drop(state);
                self.trace
                    .lock()
                    .expect("effect trace")
                    .push(TraceEvent::RuntimeArmFailed);
                return Err(RescueVaultDaemonError::RuntimeUnavailable);
            }
            state.marker = true;
            drop(state);
            self.trace
                .lock()
                .expect("effect trace")
                .push(TraceEvent::RuntimeArm);
            Ok(())
        }

        fn disarm_after_verified_locked(&mut self) -> Result<(), RescueVaultDaemonError> {
            let mut state = self.state.lock().expect("fake runtime");
            state.disarms += 1;
            if state.fail_disarms > 0 {
                state.fail_disarms -= 1;
                drop(state);
                self.trace
                    .lock()
                    .expect("effect trace")
                    .push(TraceEvent::RuntimeDisarmFailed);
                return Err(RescueVaultDaemonError::RuntimeUnavailable);
            }
            if !state.marker {
                return Err(RescueVaultDaemonError::PersistentFault);
            }
            state.marker = false;
            drop(state);
            self.trace
                .lock()
                .expect("effect trace")
                .push(TraceEvent::RuntimeDisarm);
            Ok(())
        }

        fn sync_and_verify_disarmed(&mut self) -> Result<(), RescueVaultDaemonError> {
            let mut state = self.state.lock().expect("fake runtime");
            state.disarmed_checks += 1;
            if state.fail_disarmed_checks > 0 {
                state.fail_disarmed_checks -= 1;
                drop(state);
                self.trace
                    .lock()
                    .expect("effect trace")
                    .push(TraceEvent::RuntimeDisarmedCheckFailed);
                return Err(RescueVaultDaemonError::RuntimeUnavailable);
            }
            let marker = state.marker;
            drop(state);
            self.trace
                .lock()
                .expect("effect trace")
                .push(TraceEvent::RuntimeDisarmedCheck);
            if marker {
                Err(RescueVaultDaemonError::PersistentFault)
            } else {
                Ok(())
            }
        }
    }

    #[derive(Default)]
    struct FakeWorkerState {
        calls: Vec<internal_wire::WorkerCommandKind>,
        responses: VecDeque<Result<internal_wire::WorkerResponse, RescueVaultDaemonError>>,
        outputs: VecDeque<Option<OwnedFd>>,
        passphrase_bytes: usize,
        verifies: usize,
        cancellations: usize,
        faults: usize,
        fault_deadlines: Vec<Instant>,
        shutdowns: usize,
        fail_verify: bool,
        fail_fault: bool,
        block_unlock: Option<(mpsc::SyncSender<()>, mpsc::Receiver<()>)>,
    }

    struct FakeWorker {
        state: Arc<Mutex<FakeWorkerState>>,
        trace: Arc<Mutex<Vec<TraceEvent>>>,
    }

    impl WorkerBoundary for FakeWorker {
        fn transact(
            &self,
            kind: internal_wire::WorkerCommandKind,
            _passphrase_size: Option<u16>,
            passphrase: Option<OwnedFd>,
            _deadline: Instant,
        ) -> Result<(internal_wire::WorkerResponse, Option<OwnedFd>), RescueVaultDaemonError>
        {
            let event = match kind {
                internal_wire::WorkerCommandKind::Unlock => TraceEvent::WorkerUnlock,
                internal_wire::WorkerCommandKind::Lock => TraceEvent::WorkerLock,
                internal_wire::WorkerCommandKind::AttestQuiescent => TraceEvent::WorkerAttest,
                _ => TraceEvent::WorkerOther,
            };
            self.trace.lock().expect("effect trace").push(event);
            let mut secret_bytes = 0;
            if let Some(passphrase) = passphrase {
                let mut buffer = Zeroizing::new([0_u8; 256]);
                loop {
                    match rustix::io::read(&passphrase, &mut buffer[..]) {
                        Ok(0) => break,
                        Ok(read) => secret_bytes += read,
                        Err(error) if error == rustix::io::Errno::INTR => {}
                        Err(_) => return Err(RescueVaultDaemonError::WorkerUnavailable),
                    }
                }
            }
            let mut state = self.state.lock().expect("fake worker");
            state.calls.push(kind);
            state.passphrase_bytes += secret_bytes;
            let block = if kind == internal_wire::WorkerCommandKind::Unlock {
                state.block_unlock.take()
            } else {
                None
            };
            let response = state
                .responses
                .pop_front()
                .unwrap_or(Err(RescueVaultDaemonError::ProtocolFailure));
            let output = state.outputs.pop_front().unwrap_or(None);
            drop(state);
            if let Some((entered, release)) = block {
                entered
                    .send(())
                    .map_err(|_| RescueVaultDaemonError::WorkerUnavailable)?;
                release
                    .recv()
                    .map_err(|_| RescueVaultDaemonError::WorkerUnavailable)?;
            }
            response.map(|response| (response, output))
        }

        fn borrow_openai(
            &self,
            deadline: Instant,
        ) -> Result<(internal_wire::WorkerResponse, Option<OwnedFd>), RescueVaultDaemonError>
        {
            self.transact(
                internal_wire::WorkerCommandKind::ProviderOpenAiBorrow,
                None,
                None,
                deadline,
            )
        }

        #[cfg(feature = "experimental-codex-home-lease")]
        fn lease_codex_home(
            &self,
            deadline: Instant,
        ) -> Result<(internal_wire::WorkerResponse, Option<OwnedFd>), RescueVaultDaemonError>
        {
            self.transact(
                internal_wire::WorkerCommandKind::ProviderCodexHomeLease,
                None,
                None,
                deadline,
            )
        }

        fn verify_healthy(&self) -> Result<(), RescueVaultDaemonError> {
            let mut state = self.state.lock().expect("fake worker");
            state.verifies += 1;
            let fail = state.fail_verify;
            drop(state);
            self.trace.lock().expect("effect trace").push(if fail {
                TraceEvent::WorkerVerifyFailed
            } else {
                TraceEvent::WorkerVerify
            });
            if fail {
                return Err(RescueVaultDaemonError::WorkerUnavailable);
            }
            Ok(())
        }

        fn exited(&self) -> Result<bool, RescueVaultDaemonError> {
            Ok(false)
        }

        fn fault_and_terminate(&self, deadline: Instant) -> Result<(), RescueVaultDaemonError> {
            self.trace
                .lock()
                .expect("effect trace")
                .push(TraceEvent::WorkerFault);
            let mut state = self.state.lock().expect("fake worker");
            state.faults += 1;
            state.fault_deadlines.push(deadline);
            if state.fail_fault {
                Err(RescueVaultDaemonError::ShutdownFailed)
            } else {
                Ok(())
            }
        }

        fn cancel_clean(&self, _deadline: Instant) -> Result<(), RescueVaultDaemonError> {
            self.trace
                .lock()
                .expect("effect trace")
                .push(TraceEvent::WorkerCancel);
            self.state.lock().expect("fake worker").cancellations += 1;
            Ok(())
        }

        fn shutdown_clean(&self, _deadline: Instant) -> Result<(), RescueVaultDaemonError> {
            self.trace
                .lock()
                .expect("effect trace")
                .push(TraceEvent::WorkerShutdown);
            self.state.lock().expect("fake worker").shutdowns += 1;
            Ok(())
        }
    }

    struct FakePrivacy {
        allowed: AtomicBool,
        checks: AtomicUsize,
    }

    struct BlockingRuntime {
        entered: mpsc::SyncSender<()>,
        release: mpsc::Receiver<()>,
    }

    struct StopDuringFirstArmRuntime {
        state: Arc<Mutex<FakeRuntimeState>>,
        trace: Arc<Mutex<Vec<TraceEvent>>>,
        entered: mpsc::SyncSender<()>,
        release: Option<mpsc::Receiver<()>>,
    }

    impl RuntimeBoundary for StopDuringFirstArmRuntime {
        fn arm_lifecycle(&mut self) -> Result<(), RescueVaultDaemonError> {
            let mut state = self.state.lock().expect("runtime state");
            state.arms += 1;
            state.marker = true;
            drop(state);
            self.trace
                .lock()
                .expect("effect trace")
                .push(TraceEvent::RuntimeArm);
            if let Some(release) = self.release.take() {
                self.entered
                    .send(())
                    .map_err(|_| RescueVaultDaemonError::RuntimeUnavailable)?;
                release
                    .recv()
                    .map_err(|_| RescueVaultDaemonError::RuntimeUnavailable)?;
            }
            Ok(())
        }

        fn disarm_after_verified_locked(&mut self) -> Result<(), RescueVaultDaemonError> {
            Err(RescueVaultDaemonError::RuntimeUnavailable)
        }

        fn sync_and_verify_disarmed(&mut self) -> Result<(), RescueVaultDaemonError> {
            Err(RescueVaultDaemonError::RuntimeUnavailable)
        }
    }

    struct BlockingPrivacy {
        calls: AtomicUsize,
        block_on: usize,
        entered: mpsc::SyncSender<()>,
        release: Mutex<mpsc::Receiver<()>>,
    }

    impl PrivacyBoundary for BlockingPrivacy {
        fn validate_no_active_swap(&self) -> Result<(), ()> {
            let call = self.calls.fetch_add(1, Ordering::SeqCst) + 1;
            if call == self.block_on {
                self.entered.send(()).map_err(|_| ())?;
                self.release
                    .lock()
                    .map_err(|_| ())?
                    .recv()
                    .map_err(|_| ())?;
            }
            Ok(())
        }
    }

    impl RuntimeBoundary for BlockingRuntime {
        fn arm_lifecycle(&mut self) -> Result<(), RescueVaultDaemonError> {
            self.entered
                .send(())
                .map_err(|_| RescueVaultDaemonError::RuntimeUnavailable)?;
            self.release
                .recv()
                .map_err(|_| RescueVaultDaemonError::RuntimeUnavailable)
        }

        fn disarm_after_verified_locked(&mut self) -> Result<(), RescueVaultDaemonError> {
            Err(RescueVaultDaemonError::RuntimeUnavailable)
        }

        fn sync_and_verify_disarmed(&mut self) -> Result<(), RescueVaultDaemonError> {
            Err(RescueVaultDaemonError::RuntimeUnavailable)
        }
    }

    impl PrivacyBoundary for FakePrivacy {
        fn validate_no_active_swap(&self) -> Result<(), ()> {
            self.checks.fetch_add(1, Ordering::Relaxed);
            if self.allowed.load(Ordering::Acquire) {
                Ok(())
            } else {
                Err(())
            }
        }
    }

    type FakeSupervisorHarness = (
        Arc<Supervisor>,
        Arc<Mutex<FakeRuntimeState>>,
        Arc<Mutex<FakeWorkerState>>,
        Arc<FakePrivacy>,
        Arc<Mutex<Vec<TraceEvent>>>,
    );

    fn fake_supervisor(
        state: ServiceState,
        responses: impl IntoIterator<
            Item = Result<internal_wire::WorkerResponse, RescueVaultDaemonError>,
        >,
        privacy_allowed: bool,
    ) -> FakeSupervisorHarness {
        let runtime = Arc::new(Mutex::new(FakeRuntimeState::default()));
        let trace = Arc::new(Mutex::new(Vec::new()));
        let worker = Arc::new(Mutex::new(FakeWorkerState {
            responses: responses.into_iter().collect(),
            ..FakeWorkerState::default()
        }));
        let privacy = Arc::new(FakePrivacy {
            allowed: AtomicBool::new(privacy_allowed),
            checks: AtomicUsize::new(0),
        });
        let supervisor = Arc::new(Supervisor {
            state: Mutex::new(state),
            lifecycle: Mutex::new(()),
            runtime: Mutex::new(Box::new(FakeRuntime {
                state: Arc::clone(&runtime),
                trace: Arc::clone(&trace),
            })),
            worker: Some(Arc::new(FakeWorker {
                state: Arc::clone(&worker),
                trace: Arc::clone(&trace),
            })),
            privacy: Arc::clone(&privacy) as Arc<dyn PrivacyBoundary>,
            leases: Mutex::new(LeaseRegistry::default()),
            faulted: AtomicBool::new(false),
            stopping: Arc::new(AtomicBool::new(false)),
            stop_deadline: Arc::new(Mutex::new(None)),
        });
        (supervisor, runtime, worker, privacy, trace)
    }

    enum OutputBarrierPhase {
        PreWorker,
        WorkerReturnedPreAdopt,
        ReadyPreScm,
        PostScmPreLocalDrop,
    }

    fn direct_peer_boundary() -> ProviderProcessBoundary {
        ProviderProcessBoundary::direct_peer()
    }

    fn install_output_obligated_lease(
        supervisor: &Supervisor,
    ) -> (LeaseOutputGuard, OwnedFd, std::process::Child) {
        let (observer, client) = socketpair(
            AddressFamily::UNIX,
            SocketType::SEQPACKET,
            SocketFlags::CLOEXEC | SocketFlags::NONBLOCK,
            None,
        )
        .expect("lease Agent socketpair");
        rustix::io::fcntl_setfd(&client, rustix::io::FdFlags::empty())
            .expect("make Agent socket inheritable");
        let child = Command::new("/bin/sleep")
            .arg("30")
            .spawn()
            .expect("lease Agent child");
        rustix::io::fcntl_setfd(&client, rustix::io::FdFlags::CLOEXEC)
            .expect("restore Agent socket CLOEXEC");
        drop(client);
        let pid = Pid::from_raw(i32::try_from(child.id()).expect("child pid range"))
            .expect("nonzero child pid");
        let pidfd = pidfd_open(pid, PidfdFlags::NONBLOCK).expect("lease Agent pidfd");
        let output_state = Arc::new(LeaseOutputState {
            finalized: AtomicBool::new(false),
        });
        supervisor.leases.lock().expect("lease registry").active = Some(ProviderLease {
            id: 1,
            socket: observer,
            pidfd,
            peer_pid: pid.as_raw_pid(),
            process: direct_peer_boundary(),
            state: LeaseState::PotentiallyIssued,
            handoff_deadline: Instant::now() + PROVIDER_BORROW_TIMEOUT,
            lease_deadline: None,
            output_obligation: Arc::clone(&output_state),
        });
        let (read, write) = pipe_with(PipeFlags::CLOEXEC).expect("credential output pipe");
        rustix::io::write(&write, b"TEST_ONLY_PROVIDER_KEY").expect("credential bytes");
        drop(write);
        (LeaseOutputGuard::new(output_state), read, child)
    }

    fn assert_lock_waits_for_output_finalization(phase: OutputBarrierPhase) {
        let mut unlocked = service_state(30, VaultState::Unlocked);
        unlocked.availability = available(
            VaultState::Unlocked,
            Some("KA-0123456789abcdef01234567".to_owned()),
        );
        let (supervisor, runtime, worker, _, _) = fake_supervisor(
            unlocked,
            [
                Ok(internal_wire::WorkerResponse::new(
                    1,
                    internal_wire::WorkerResultCode::LockSucceeded,
                )),
                Ok(internal_wire::WorkerResponse::new(
                    2,
                    internal_wire::WorkerResultCode::AttestLocked,
                )),
            ],
            true,
        );
        let (mut output, raw_output, mut child) = install_output_obligated_lease(&supervisor);
        let mut raw_output = Some(raw_output);
        match phase {
            OutputBarrierPhase::PreWorker => {
                drop(raw_output.take());
            }
            OutputBarrierPhase::WorkerReturnedPreAdopt => {}
            OutputBarrierPhase::ReadyPreScm => {
                output
                    .adopt(raw_output.take().expect("worker output"))
                    .expect("single output adoption");
                assert_eq!(supervisor.finish_provider_borrow_ready(1), Ok(Some(30)));
            }
            OutputBarrierPhase::PostScmPreLocalDrop => {
                output
                    .adopt(raw_output.take().expect("worker output"))
                    .expect("single output adoption");
                assert_eq!(supervisor.finish_provider_borrow_ready(1), Ok(Some(30)));
                assert!(matches!(
                    supervisor.send_provider_descriptor(1, || true),
                    Ok(DescriptorSend::Established)
                ));
            }
        }

        let request = validated_request("vault.lock", serde_json::json!({}), 30, None);
        let running = Arc::clone(&supervisor);
        let (result_tx, result_rx) = mpsc::channel();
        let handler = thread::spawn(move || {
            result_tx
                .send(running.handle_request(request, Instant::now()))
                .expect("lock result");
        });
        let child_deadline = Instant::now() + Duration::from_secs(2);
        while child.try_wait().expect("Agent status").is_none() {
            assert!(
                Instant::now() < child_deadline,
                "lock did not terminate the registered Agent"
            );
            thread::sleep(Duration::from_millis(10));
        }
        assert!(matches!(
            result_rx.recv_timeout(Duration::from_millis(100)),
            Err(mpsc::RecvTimeoutError::Timeout)
        ));
        assert!(worker.lock().expect("worker trace").calls.is_empty());
        assert_eq!(runtime.lock().expect("runtime trace").disarms, 0);
        assert!(matches!(
            supervisor
                .leases
                .lock()
                .expect("lease registry")
                .active
                .as_ref(),
            Some(lease) if lease.state == LeaseState::Revoking
        ));

        // A worker-returned descriptor not yet adopted is still a supervisor
        // credential FD and must be closed before the guard publishes.
        drop(raw_output.take());
        drop(output);
        let (version, result) = result_rx
            .recv_timeout(Duration::from_secs(2))
            .expect("lock completion after output finalization");
        handler.join().expect("lock handler");
        assert_eq!(version, 32);
        assert_handler_status(result, VaultState::Locked, None);
        assert_eq!(
            worker.lock().expect("worker trace").calls,
            [
                internal_wire::WorkerCommandKind::Lock,
                internal_wire::WorkerCommandKind::AttestQuiescent,
            ]
        );
        let runtime = runtime.lock().expect("runtime trace");
        assert_eq!((runtime.disarms, runtime.marker), (1, false));
        assert!(
            supervisor
                .leases
                .lock()
                .expect("lease registry")
                .active
                .is_none()
        );
    }

    fn validated_request_for_role(
        operation: &str,
        payload: serde_json::Value,
        expected_version: u64,
        descriptor: Option<BorrowedFd<'_>>,
        role: PeerRole,
    ) -> ValidatedRequest {
        validated_request_with_connection_for_role(
            operation,
            payload,
            expected_version,
            descriptor,
            role,
        )
        .0
    }

    fn validated_request_with_connection_for_role(
        operation: &str,
        payload: serde_json::Value,
        expected_version: u64,
        descriptor: Option<BorrowedFd<'_>>,
        role: PeerRole,
    ) -> (ValidatedRequest, OwnedFd, OwnedFd) {
        static REQUEST: AtomicU64 = AtomicU64::new(1);
        let (client, server) = socketpair(
            AddressFamily::UNIX,
            SocketType::SEQPACKET,
            SocketFlags::CLOEXEC,
            None,
        )
        .expect("request socketpair");
        let uid = rustix::net::sockopt::socket_peercred(&client)
            .expect("peer credentials")
            .uid
            .as_raw();
        assert_ne!(uid, 0, "handler tests require an unprivileged peer");
        let other_uid = if uid == 1 { 2 } else { 1 };
        let (companion_uid, agent_role, agent_uid) = match role {
            PeerRole::Companion => (uid, AgentRole::OpenAi, other_uid),
            PeerRole::Agent(agent_role) => (other_uid, agent_role, uid),
        };
        let allowlist = PeerAllowlist::builder(companion_uid)
            .agent(agent_role, agent_uid)
            .expect("test Agent role mapping")
            .build()
            .expect("test allowlist");
        let peer = authenticate_seqpacket_peer(server.as_fd(), allowlist)
            .expect("authenticated test peer");
        let request_id = format!(
            "R-00000000-0000-0000-0000-{:012x}",
            REQUEST.fetch_add(1, Ordering::Relaxed)
        );
        let datagram = serde_json::to_vec(&serde_json::json!({
            "apiVersion": API_VERSION,
            "requestId": request_id,
            "expectedStateVersion": expected_version,
            "operation": operation,
            "payload": payload,
        }))
        .expect("request json");
        if let Some(descriptor) = descriptor {
            let io = [IoSlice::new(&datagram)];
            let rights = [descriptor];
            let mut space = [MaybeUninit::uninit(); rustix::cmsg_space!(ScmRights(1))];
            let mut ancillary = SendAncillaryBuffer::new(&mut space);
            assert!(ancillary.push(SendAncillaryMessage::ScmRights(&rights)));
            assert_eq!(
                sendmsg(&client, &io, &mut ancillary, SendFlags::NOSIGNAL)
                    .expect("request with descriptor"),
                datagram.len()
            );
        } else {
            assert_eq!(
                send(&client, &datagram, SendFlags::NOSIGNAL).expect("request"),
                datagram.len()
            );
        }
        let request = peer
            .receive_request(Instant::now() + Duration::from_secs(2))
            .expect("validated request");
        drop(peer);
        (request, client, server)
    }

    fn validated_request(
        operation: &str,
        payload: serde_json::Value,
        expected_version: u64,
        descriptor: Option<BorrowedFd<'_>>,
    ) -> ValidatedRequest {
        validated_request_for_role(
            operation,
            payload,
            expected_version,
            descriptor,
            PeerRole::Companion,
        )
    }

    fn descriptor_request(
        operation: &str,
        payload: serde_json::Value,
        expected_version: u64,
        role: PeerRole,
        bytes: &[u8],
    ) -> (ValidatedRequest, OwnedFd) {
        let (read, write) = pipe_with(PipeFlags::CLOEXEC).expect("request pipe");
        rustix::io::write(&write, bytes).expect("request pipe bytes");
        let request = validated_request_for_role(
            operation,
            payload,
            expected_version,
            Some(read.as_fd()),
            role,
        );
        drop(read);
        (request, write)
    }

    fn assert_pipe_has_no_reader(writer: BorrowedFd<'_>) {
        let mut descriptor = [PollFd::from_borrowed_fd(
            writer,
            PollFlags::OUT | PollFlags::ERR,
        )];
        let timeout = Timespec {
            tv_sec: 1,
            tv_nsec: 0,
        };
        assert_eq!(poll(&mut descriptor, Some(&timeout)).expect("pipe poll"), 1);
        assert!(descriptor[0].revents().contains(PollFlags::ERR));
    }

    fn unlock_request(
        version: u64,
        bytes: &[u8],
        keep_writer: bool,
    ) -> (ValidatedRequest, Option<OwnedFd>) {
        let (read, write) = pipe_with(PipeFlags::CLOEXEC).expect("passphrase pipe");
        rustix::io::write(&write, bytes).expect("passphrase fixture");
        let request = validated_request(
            "vault.unlock",
            serde_json::json!({
                "input": {"type": "passphrase-pipe", "size": 12}
            }),
            version,
            Some(read.as_fd()),
        );
        drop(read);
        if keep_writer {
            (request, Some(write))
        } else {
            drop(write);
            (request, None)
        }
    }

    fn connected_unlock_request(version: u64) -> (ValidatedRequest, OwnedFd, OwnedFd) {
        let (read, write) = pipe_with(PipeFlags::CLOEXEC).expect("passphrase pipe");
        rustix::io::write(&write, b"TEST_ONLY_12").expect("passphrase fixture");
        drop(write);
        let (request, client, server) = validated_request_with_connection_for_role(
            "vault.unlock",
            serde_json::json!({
                "input": {"type": "passphrase-pipe", "size": 12}
            }),
            version,
            Some(read.as_fd()),
            PeerRole::Companion,
        );
        drop(read);
        (request, client, server)
    }

    fn assert_handler_error(result: HandlerResult, expected: ErrorToken) {
        assert!(matches!(
            result,
            HandlerResult::Error(_request, error) if error == expected
        ));
    }

    fn assert_handler_status(
        result: HandlerResult,
        expected_state: VaultState,
        expected_device: Option<&str>,
    ) {
        assert!(matches!(
            result,
            HandlerResult::Success(_, SuccessPayload::VaultStatus(status))
                if status.vault_state() == expected_state
                    && status.device_id() == expected_device
        ));
    }

    fn assert_handler_provider_status(result: HandlerResult, expected: ProviderState) {
        assert!(matches!(
            result,
            HandlerResult::Success(
                _request,
                SuccessPayload::ProviderStatus(ProviderStatusPayload {
                    openai,
                    codex: ProviderState::Unconfigured,
                }),
            ) if openai == expected
        ));
    }

    fn service_state(version: u64, vault: VaultState) -> ServiceState {
        ServiceState {
            version,
            availability: available(vault, None),
            transition_origin: None,
            provider_operation_active: false,
            last_unlock_attempt: None,
            faulted: false,
            fault_marker_required: false,
            marker_persistence_failed: false,
            clean_fault_shutdown: false,
        }
    }

    fn unlocked_service_state(version: u64) -> ServiceState {
        let mut state = service_state(version, VaultState::Unlocked);
        state.availability = available(
            VaultState::Unlocked,
            Some("KA-0123456789abcdef01234567".to_owned()),
        );
        state
    }

    fn notification_receiver(address: &SocketAddrUnix) -> OwnedFd {
        let receiver = socket_with(
            AddressFamily::UNIX,
            SocketType::DGRAM,
            SocketFlags::CLOEXEC | SocketFlags::NONBLOCK,
            None,
        )
        .expect("notification receiver");
        bind(&receiver, address).expect("bind notification receiver");
        receiver
    }

    fn receive_notification(receiver: &OwnedFd) -> Result<Vec<u8>, rustix::io::Errno> {
        let mut buffer = [0_u8; 64];
        recv(receiver, &mut buffer, RecvFlags::DONTWAIT)
            .map(|(received, _)| buffer[..received].to_vec())
    }

    fn assert_no_notification(receiver: &OwnedFd) {
        assert!(matches!(
            receive_notification(receiver),
            Err(error) if error == rustix::io::Errno::AGAIN
        ));
    }

    fn verified_fault_containment() -> FaultContainment {
        FaultContainment {
            marker_durable: true,
            worker_quiesced: true,
        }
    }

    #[test]
    fn readiness_filesystem_seam_is_exact_and_never_premature() {
        let directory = tempfile::tempdir().expect("temporary notify directory");
        let path = directory.path().join("notify.sock");
        let address = SocketAddrUnix::new(&path).expect("filesystem notification address");
        let receiver = notification_receiver(&address);
        let notifier = SystemdNotifier::from_value(Some(path.as_os_str())).expect("notifier");
        let stop = StopControl::new();

        assert_eq!(
            publish_readiness_by(&notifier, StartupReadiness::Stopping, &stop, Instant::now(),),
            Ok(false)
        );
        assert_eq!(
            publish_readiness_by(&notifier, StartupReadiness::Failed, &stop, Instant::now(),),
            Ok(false)
        );
        assert_no_notification(&receiver);

        assert_eq!(
            publish_readiness_by(
                &notifier,
                StartupReadiness::Ready,
                &stop,
                Instant::now() + Duration::from_secs(1),
            ),
            Ok(true)
        );
        assert_eq!(
            receive_notification(&receiver).expect("readiness datagram"),
            READY_NOTIFICATION
        );
        assert_no_notification(&receiver);
    }

    #[test]
    fn readiness_abstract_socket_seam_sends_exact_datagram() {
        static NEXT_ABSTRACT_SOCKET: AtomicU64 = AtomicU64::new(1);

        let name = format!(
            "kernaid-ready-{}-{}",
            std::process::id(),
            NEXT_ABSTRACT_SOCKET.fetch_add(1, Ordering::Relaxed)
        )
        .into_bytes();
        let address = SocketAddrUnix::new_abstract_name(&name).expect("abstract address");
        let receiver = notification_receiver(&address);
        let mut activation = Vec::with_capacity(name.len() + 1);
        activation.push(b'@');
        activation.extend_from_slice(&name);
        let activation = OsString::from_vec(activation);
        let notifier =
            SystemdNotifier::from_value(Some(activation.as_os_str())).expect("abstract notifier");
        let stop = StopControl::new();

        assert_eq!(
            publish_readiness_by(
                &notifier,
                StartupReadiness::Ready,
                &stop,
                Instant::now() + Duration::from_secs(1),
            ),
            Ok(true)
        );
        assert_eq!(
            receive_notification(&receiver).expect("abstract readiness datagram"),
            READY_NOTIFICATION
        );
        assert_no_notification(&receiver);
    }

    #[test]
    fn readiness_and_stop_are_linearized_without_moving_the_stop_deadline() {
        let stop = StopControl::new();
        let publisher_stop = stop.clone();
        let (publish_entered_tx, publish_entered_rx) = mpsc::sync_channel(0);
        let (publish_release_tx, publish_release_rx) = mpsc::sync_channel(0);
        let publisher = thread::spawn(move || {
            publish_readiness_with(StartupReadiness::Ready, &publisher_stop, || {
                publish_entered_tx.send(()).expect("publish entered");
                publish_release_rx.recv().expect("publish release");
                Ok(())
            })
        });
        publish_entered_rx
            .recv_timeout(Duration::from_secs(1))
            .expect("publisher holds readiness gate");

        let requested_at = Instant::now();
        let requester_stop = stop.clone();
        let (request_entered_tx, request_entered_rx) = mpsc::sync_channel(0);
        let (request_done_tx, request_done_rx) = mpsc::sync_channel(0);
        let requester = thread::spawn(move || {
            request_entered_tx.send(()).expect("request entered");
            requester_stop.request_at(requested_at);
            request_done_tx.send(()).expect("request completed");
        });
        request_entered_rx
            .recv_timeout(Duration::from_secs(1))
            .expect("stop request attempted");
        assert_eq!(
            request_done_rx.recv_timeout(Duration::from_millis(50)),
            Err(mpsc::RecvTimeoutError::Timeout),
            "stop-first publication ordering escaped the shared gate"
        );
        publish_release_tx.send(()).expect("release publication");
        assert_eq!(publisher.join().expect("publisher thread"), Ok(true));
        request_done_rx
            .recv_timeout(Duration::from_secs(1))
            .expect("stop request completed after publication");
        requester.join().expect("requester thread");
        assert!(stop.requested.load(Ordering::Acquire));
        assert_eq!(
            *stop.deadline.lock().expect("stop deadline"),
            requested_at.checked_add(SHUTDOWN_TIMEOUT),
            "waiting behind READY must not move the first signal's budget"
        );

        let stop_first = StopControl::new();
        stop_first.request();
        let called = Arc::new(AtomicBool::new(false));
        let called_by_publish = Arc::clone(&called);
        assert_eq!(
            publish_readiness_with(StartupReadiness::Ready, &stop_first, || {
                called_by_publish.store(true, Ordering::Release);
                Ok(())
            }),
            Ok(false)
        );
        assert!(!called.load(Ordering::Acquire));
    }

    #[test]
    fn readiness_socket_and_activation_input_are_bounded_and_sanitized() {
        let socket = open_notification_socket().expect("notification socket");
        assert!(
            rustix::io::fcntl_getfd(&socket)
                .expect("descriptor flags")
                .contains(rustix::io::FdFlags::CLOEXEC)
        );
        assert!(
            rfs::fcntl_getfl(&socket)
                .expect("status flags")
                .contains(OFlags::NONBLOCK)
        );
        assert_eq!(
            rustix::net::sockopt::socket_domain(&socket).expect("socket domain"),
            AddressFamily::UNIX
        );
        assert_eq!(
            rustix::net::sockopt::socket_type(&socket).expect("socket type"),
            SocketType::DGRAM
        );
        assert!(!rustix::net::sockopt::socket_acceptconn(&socket).expect("accept state"));

        for invalid in [
            OsString::new(),
            OsString::from("relative.sock"),
            OsString::from("@"),
            OsString::from_vec(vec![b'@', 0, b'x']),
            OsString::from_vec(vec![b'@'; MAX_NOTIFY_SOCKET_BYTES + 1]),
        ] {
            let error = SystemdNotifier::from_value(Some(invalid.as_os_str()))
                .err()
                .expect("invalid activation input rejected");
            assert_eq!(error, RescueVaultDaemonError::InvalidConfiguration);
            assert_eq!(
                error.to_string(),
                "invalid Rescue vault daemon configuration"
            );
        }

        let maximum_abstract = OsString::from_vec({
            let mut value = vec![b'a'; MAX_NOTIFY_SOCKET_BYTES];
            value[0] = b'@';
            value
        });
        assert!(
            SystemdNotifier::from_value(Some(maximum_abstract.as_os_str())).is_ok(),
            "the largest representable abstract activation address must be accepted"
        );
    }

    #[test]
    fn readiness_deadline_and_send_failure_are_fail_closed_with_clean_shutdown() {
        let directory = tempfile::tempdir().expect("temporary notify directory");
        let path = directory.path().join("not-listening.sock");
        let notifier = SystemdNotifier::from_value(Some(path.as_os_str())).expect("notifier");
        let send_stop = StopControl::new();
        assert_eq!(
            publish_readiness_by(
                &notifier,
                StartupReadiness::Ready,
                &send_stop,
                Instant::now(),
            ),
            Err(RescueVaultDaemonError::RuntimeUnavailable)
        );

        let (supervisor, runtime, worker, _, _) =
            fake_supervisor(service_state(9, VaultState::Locked), [], true);
        runtime.lock().expect("runtime state").marker = true;
        let stop = StopControl {
            requested: Arc::clone(&supervisor.stopping),
            first_requested_at: Arc::new(Mutex::new(None)),
            deadline: Arc::clone(&supervisor.stop_deadline),
        };
        let readiness_error = publish_readiness_by(
            &notifier,
            StartupReadiness::Ready,
            &stop,
            Instant::now() + Duration::from_secs(1),
        )
        .expect_err("missing receiver must reject readiness");
        let started = Instant::now();
        assert_eq!(
            shutdown_after_readiness_failure(&supervisor, &stop, readiness_error),
            Err(RescueVaultDaemonError::RuntimeUnavailable)
        );
        let finished = Instant::now();
        assert!(stop.requested.load(Ordering::Acquire));
        let deadline = stop
            .deadline
            .lock()
            .expect("stop deadline")
            .expect("bounded stop deadline");
        assert!(deadline >= started && deadline <= finished + SHUTDOWN_TIMEOUT);
        assert_eq!(worker.lock().expect("worker state").shutdowns, 1);
        assert_eq!(runtime.lock().expect("runtime state").disarms, 1);
        assert!(!runtime.lock().expect("runtime state").marker);
    }

    #[test]
    fn readiness_rechecks_worker_and_allows_only_preexisting_fault_status() {
        let (contained, _, contained_worker, _, _) =
            fake_supervisor(service_state(20, VaultState::Locked), [], true);
        contained_worker.lock().expect("worker state").fail_verify = true;
        assert_eq!(
            contained.startup_readiness(verified_fault_containment(), RuntimeDisposition::Ready,),
            StartupReadiness::Failed,
            "a fresh startup fault must never be published as healthy readiness"
        );
        let state = contained.state.lock().expect("service state");
        assert!(state.faulted);
        assert!(matches!(
            state.availability,
            Availability::Available {
                state: VaultState::FaultedRebootRequired,
                device_id: None,
            }
        ));
        drop(state);
        let worker = contained_worker.lock().expect("worker state");
        assert_eq!(worker.verifies, 1);
        assert_eq!(worker.faults, 1);
        drop(worker);

        let mut persistent_state = service_state(25, VaultState::FaultedRebootRequired);
        persistent_state.faulted = true;
        persistent_state.fault_marker_required = true;
        let (persistent, _, persistent_worker, _, _) = fake_supervisor(persistent_state, [], true);
        persistent.faulted.store(true, Ordering::Release);
        assert_eq!(
            persistent.startup_readiness(
                verified_fault_containment(),
                RuntimeDisposition::PersistentFault,
            ),
            StartupReadiness::Ready,
            "only a marker observed before startup may become status-only ready"
        );
        assert_eq!(
            persistent_worker.lock().expect("worker state").verifies,
            0,
            "persistent-fault readiness must not run a worker health check"
        );

        let (uncontained, _, uncontained_worker, _, _) =
            fake_supervisor(service_state(30, VaultState::Locked), [], true);
        {
            let mut worker = uncontained_worker.lock().expect("worker state");
            worker.fail_verify = true;
            worker.fail_fault = true;
        }
        assert_eq!(
            uncontained.startup_readiness(verified_fault_containment(), RuntimeDisposition::Ready,),
            StartupReadiness::Failed
        );
        assert!(uncontained.state.lock().expect("service state").faulted);
    }

    #[test]
    fn state_seed_is_nonzero_and_within_initial_epoch() {
        for _ in 0..32 {
            let seed = state_version_seed().expect("seed");
            assert!((1..=MAX_INITIAL_STATE_VERSION).contains(&seed));
        }
    }

    #[test]
    fn supervisor_executes_wrong_key_success_and_lock_with_exact_effects() {
        let locked = service_state(10, VaultState::Locked);
        let (wrong, wrong_runtime, wrong_worker, _, wrong_trace) = fake_supervisor(
            locked,
            [
                Ok(internal_wire::WorkerResponse::new(
                    1,
                    internal_wire::WorkerResultCode::BadPassphrase,
                )),
                Ok(internal_wire::WorkerResponse::new(
                    2,
                    internal_wire::WorkerResultCode::AttestLocked,
                )),
            ],
            true,
        );
        let (request, _) = unlock_request(10, b"TEST_ONLY_12", false);
        let (version, result) = wrong.handle_request(request, Instant::now());
        assert_eq!(version, 12);
        assert_handler_error(result, ErrorToken::BadPassphrase);
        wrong_trace
            .lock()
            .expect("effect trace")
            .push(TraceEvent::CallerObservedPublication);
        let runtime = wrong_runtime.lock().expect("runtime trace");
        assert_eq!(
            (runtime.arms, runtime.disarms, runtime.marker),
            (1, 1, false)
        );
        drop(runtime);
        let worker = wrong_worker.lock().expect("worker trace");
        assert_eq!(
            worker.calls,
            [
                internal_wire::WorkerCommandKind::Unlock,
                internal_wire::WorkerCommandKind::AttestQuiescent,
            ]
        );
        assert_eq!(worker.passphrase_bytes, 12);
        drop(worker);
        assert_eq!(
            *wrong_trace.lock().expect("effect trace"),
            [
                TraceEvent::RuntimeArm,
                TraceEvent::WorkerUnlock,
                TraceEvent::WorkerAttest,
                TraceEvent::WorkerVerify,
                TraceEvent::RuntimeDisarm,
                TraceEvent::CallerObservedPublication,
            ]
        );

        let success_state = service_state(20, VaultState::Locked);
        let (success, success_runtime, success_worker, _, success_trace) = fake_supervisor(
            success_state,
            [Ok(internal_wire::WorkerResponse::unlocked(
                1,
                "KA-0123456789abcdef01234567".to_owned(),
            ))],
            true,
        );
        let (request, _) = unlock_request(20, b"TEST_ONLY_12", false);
        let (version, result) = success.handle_request(request, Instant::now());
        assert_eq!(version, 22);
        assert_handler_status(
            result,
            VaultState::Unlocked,
            Some("KA-0123456789abcdef01234567"),
        );
        success_trace
            .lock()
            .expect("effect trace")
            .push(TraceEvent::CallerObservedPublication);
        let runtime = success_runtime.lock().expect("runtime trace");
        assert_eq!(
            (runtime.arms, runtime.disarms, runtime.marker),
            (2, 0, true)
        );
        drop(runtime);
        assert_eq!(
            success_worker.lock().expect("worker trace").calls,
            [internal_wire::WorkerCommandKind::Unlock]
        );
        assert_eq!(
            *success_trace.lock().expect("effect trace"),
            [
                TraceEvent::RuntimeArm,
                TraceEvent::WorkerUnlock,
                TraceEvent::RuntimeArm,
                TraceEvent::CallerObservedPublication,
            ]
        );

        let mut unlocked = service_state(30, VaultState::Unlocked);
        unlocked.availability = available(
            VaultState::Unlocked,
            Some("KA-0123456789abcdef01234567".to_owned()),
        );
        let (lock, lock_runtime, lock_worker, _, lock_trace) = fake_supervisor(
            unlocked,
            [
                Ok(internal_wire::WorkerResponse::new(
                    1,
                    internal_wire::WorkerResultCode::LockSucceeded,
                )),
                Ok(internal_wire::WorkerResponse::new(
                    2,
                    internal_wire::WorkerResultCode::AttestLocked,
                )),
            ],
            true,
        );
        let request = validated_request("vault.lock", serde_json::json!({}), 30, None);
        let (version, result) = lock.handle_request(request, Instant::now());
        assert_eq!(version, 32);
        assert_handler_status(result, VaultState::Locked, None);
        lock_trace
            .lock()
            .expect("effect trace")
            .push(TraceEvent::CallerObservedPublication);
        let runtime = lock_runtime.lock().expect("runtime trace");
        assert_eq!(
            (runtime.arms, runtime.disarms, runtime.marker),
            (1, 1, false)
        );
        assert_eq!(
            lock_worker.lock().expect("worker trace").calls,
            [
                internal_wire::WorkerCommandKind::Lock,
                internal_wire::WorkerCommandKind::AttestQuiescent,
            ]
        );
        assert_eq!(
            *lock_trace.lock().expect("effect trace"),
            [
                TraceEvent::RuntimeArm,
                TraceEvent::WorkerLock,
                TraceEvent::WorkerAttest,
                TraceEvent::WorkerVerify,
                TraceEvent::RuntimeDisarm,
                TraceEvent::CallerObservedPublication,
            ]
        );
    }

    #[test]
    fn supervisor_malformed_slow_and_swap_blocked_inputs_never_dispatch() {
        for (bytes, keep_writer, started) in [
            (&b"short"[..], false, Instant::now()),
            (
                &b"TEST_ONLY_12"[..],
                true,
                Instant::now() - CLIENT_PIPE_TIMEOUT - Duration::from_secs(1),
            ),
        ] {
            let (supervisor, runtime, worker, _, _) =
                fake_supervisor(service_state(40, VaultState::Locked), [], true);
            let (request, writer) = unlock_request(40, bytes, keep_writer);
            let (version, result) = supervisor.handle_request(request, started);
            assert_eq!(version, 42);
            assert_handler_error(result, ErrorToken::IoFailed);
            assert!(worker.lock().expect("worker trace").calls.is_empty());
            let runtime = runtime.lock().expect("runtime trace");
            assert_eq!(
                (runtime.arms, runtime.disarms, runtime.marker),
                (0, 0, false)
            );
            drop(writer);
        }

        let (supervisor, runtime, worker, privacy, _) =
            fake_supervisor(service_state(50, VaultState::Locked), [], false);
        let (request, _) = unlock_request(50, b"TEST_ONLY_12", false);
        let (version, result) = supervisor.handle_request(request, Instant::now());
        assert_eq!(version, 52);
        assert_handler_error(result, ErrorToken::RebootRequired);
        let worker = worker.lock().expect("worker trace");
        assert!(worker.calls.is_empty());
        assert_eq!(worker.cancellations, 1);
        drop(worker);
        let runtime = runtime.lock().expect("runtime trace");
        assert_eq!((runtime.arms, runtime.marker), (0, false));
        assert!(runtime.disarmed_checks >= 2);
        assert_eq!(privacy.checks.load(Ordering::Relaxed), 1);
    }

    #[test]
    fn supervisor_faults_on_every_post_begin_effect_failure_and_preserves_marker_dominance() {
        let (arm, arm_runtime, arm_worker, _, arm_trace) =
            fake_supervisor(service_state(70, VaultState::Locked), [], true);
        arm_runtime.lock().expect("runtime fixture").fail_arms = 1;
        let (request, _) = unlock_request(70, b"TEST_ONLY_12", false);
        let (version, result) = arm.handle_request(request, Instant::now());
        assert_eq!(version, 72);
        assert_handler_error(result, ErrorToken::RebootRequired);
        assert_eq!(arm.snapshot().availability, faulted_availability());
        assert_eq!(arm_worker.lock().expect("worker trace").faults, 1);
        assert_eq!(
            *arm_trace.lock().expect("effect trace"),
            [
                TraceEvent::RuntimeArmFailed,
                TraceEvent::RuntimeArm,
                TraceEvent::WorkerFault,
            ]
        );
        assert!(arm_runtime.lock().expect("runtime trace").marker);

        let device_id = "KA-0123456789abcdef01234567".to_owned();
        let (publish, publish_runtime, publish_worker, _, publish_trace) = fake_supervisor(
            service_state(75, VaultState::Locked),
            [Ok(internal_wire::WorkerResponse::unlocked(1, device_id))],
            true,
        );
        publish_runtime.lock().expect("runtime fixture").fail_arm_on = Some(2);
        let (request, _) = unlock_request(75, b"TEST_ONLY_12", false);
        let (version, result) = publish.handle_request(request, Instant::now());
        assert_eq!(version, 77);
        assert_handler_error(result, ErrorToken::RebootRequired);
        assert_eq!(publish.snapshot().availability, faulted_availability());
        let worker = publish_worker.lock().expect("worker trace");
        assert_eq!(worker.calls, [internal_wire::WorkerCommandKind::Unlock]);
        assert_eq!(worker.faults, 1);
        drop(worker);
        assert!(publish_runtime.lock().expect("runtime trace").marker);
        assert_eq!(
            *publish_trace.lock().expect("effect trace"),
            [
                TraceEvent::RuntimeArm,
                TraceEvent::WorkerUnlock,
                TraceEvent::RuntimeArmFailed,
                TraceEvent::RuntimeArm,
                TraceEvent::WorkerFault,
            ]
        );

        let (transact, transact_runtime, transact_worker, _, transact_trace) = fake_supervisor(
            service_state(80, VaultState::Locked),
            [Err(RescueVaultDaemonError::WorkerUnavailable)],
            true,
        );
        let (request, _) = unlock_request(80, b"TEST_ONLY_12", false);
        let (version, result) = transact.handle_request(request, Instant::now());
        assert_eq!(version, 82);
        assert_handler_error(result, ErrorToken::RebootRequired);
        assert_eq!(transact_worker.lock().expect("worker trace").faults, 1);
        assert_eq!(
            *transact_trace.lock().expect("effect trace"),
            [
                TraceEvent::RuntimeArm,
                TraceEvent::WorkerUnlock,
                TraceEvent::RuntimeArm,
                TraceEvent::WorkerFault,
            ]
        );
        assert!(transact_runtime.lock().expect("runtime trace").marker);

        for failure in ["verify", "disarm"] {
            let (supervisor, runtime, worker, _, trace) = fake_supervisor(
                service_state(90, VaultState::Locked),
                [
                    Ok(internal_wire::WorkerResponse::new(
                        1,
                        internal_wire::WorkerResultCode::BadPassphrase,
                    )),
                    Ok(internal_wire::WorkerResponse::new(
                        2,
                        internal_wire::WorkerResultCode::AttestLocked,
                    )),
                ],
                true,
            );
            if failure == "verify" {
                worker.lock().expect("worker fixture").fail_verify = true;
            } else {
                runtime.lock().expect("runtime fixture").fail_disarms = 1;
            }
            let (request, _) = unlock_request(90, b"TEST_ONLY_12", false);
            let (version, result) = supervisor.handle_request(request, Instant::now());
            assert_eq!(version, 92);
            assert_handler_error(result, ErrorToken::RebootRequired);
            assert_eq!(supervisor.snapshot().availability, faulted_availability());
            assert_eq!(worker.lock().expect("worker trace").faults, 1);
            assert!(runtime.lock().expect("runtime trace").marker);
            let trace = trace.lock().expect("effect trace");
            assert_eq!(trace[0], TraceEvent::RuntimeArm);
            assert_eq!(trace[1], TraceEvent::WorkerUnlock);
            assert_eq!(trace[2], TraceEvent::WorkerAttest);
            assert!(trace.contains(&TraceEvent::WorkerFault));
            assert!(trace.contains(&TraceEvent::RuntimeArm));
            if failure == "verify" {
                assert!(trace.contains(&TraceEvent::WorkerVerifyFailed));
                assert!(!trace.contains(&TraceEvent::RuntimeDisarm));
            } else {
                assert!(trace.contains(&TraceEvent::WorkerVerify));
                assert!(trace.contains(&TraceEvent::RuntimeDisarmFailed));
            }
        }

        let (persistent, runtime, worker, _, trace) =
            fake_supervisor(service_state(100, VaultState::Locked), [], true);
        runtime.lock().expect("runtime fixture").fail_arms = 3;
        let (request, _) = unlock_request(100, b"TEST_ONLY_12", false);
        let (version, result) = persistent.handle_request(request, Instant::now());
        assert_eq!(version, 102);
        assert_handler_error(result, ErrorToken::RebootRequired);
        let state = persistent.state.lock().expect("service state");
        assert!(state.faulted);
        assert!(state.marker_persistence_failed);
        assert!(persistent.stopping.load(Ordering::Acquire));
        drop(state);
        assert_eq!(worker.lock().expect("worker trace").faults, 1);
        assert_eq!(
            trace
                .lock()
                .expect("effect trace")
                .iter()
                .filter(|event| **event == TraceEvent::RuntimeArmFailed)
                .count(),
            3
        );
    }

    #[test]
    fn fault_cleanup_never_extends_the_operation_or_stop_deadline() {
        let (operation, _, worker, _, _) = fake_supervisor(
            service_state(610, VaultState::Locked),
            [Err(RescueVaultDaemonError::WorkerUnavailable)],
            true,
        );
        let started = Instant::now();
        let operation_deadline = started
            .checked_add(WORKER_OPERATION_TIMEOUT)
            .expect("operation deadline");
        let (request, _) = unlock_request(610, b"TEST_ONLY_12", false);
        let (version, result) = operation.handle_request(request, started);
        assert_eq!(version, 612);
        assert_handler_error(result, ErrorToken::RebootRequired);
        assert_eq!(
            worker.lock().expect("worker trace").fault_deadlines,
            [operation_deadline],
            "fault cleanup must consume the original operation budget"
        );

        let (stopping, _, worker, _, _) =
            fake_supervisor(service_state(620, VaultState::Locked), [], true);
        let stop_deadline = Instant::now()
            .checked_add(Duration::from_secs(10))
            .expect("stop deadline");
        *stopping.stop_deadline.lock().expect("stop deadline state") = Some(stop_deadline);
        stopping.mark_fault_by(
            stop_deadline
                .checked_add(WORKER_OPERATION_TIMEOUT)
                .expect("later operation deadline"),
        );
        assert_eq!(
            worker.lock().expect("worker trace").fault_deadlines,
            [stop_deadline],
            "the first signal's absolute stop deadline must dominate"
        );
    }

    #[test]
    fn supervisor_rejects_all_deferred_requests_in_every_state_without_effects() {
        for vault in [
            VaultState::Absent,
            VaultState::Unprovisioned,
            VaultState::Locked,
            VaultState::Unlocking,
            VaultState::Unlocked,
            VaultState::Locking,
            VaultState::FaultedRebootRequired,
        ] {
            let mut initial = service_state(60, vault);
            if vault == VaultState::FaultedRebootRequired {
                initial.faulted = true;
                initial.fault_marker_required = true;
            }
            let expected_availability = initial.availability.clone();
            let expected_faulted = initial.faulted;
            let expected_fault_marker_required = initial.fault_marker_required;
            let (supervisor, runtime, worker, privacy, _) = fake_supervisor(initial, [], true);
            let (persist, persist_writer) = descriptor_request(
                "report.persist",
                serde_json::json!({
                    "reportId": "RP-00000000-0000-0000-0000-000000000001",
                    "payloadSha256": "0".repeat(64),
                    "input": {"type": "session-report-json-pipe", "size": 2}
                }),
                60,
                PeerRole::Agent(AgentRole::Application),
                b"{}",
            );
            let requests = [
                #[cfg(not(feature = "experimental-codex-home-lease"))]
                (
                    validated_request_for_role(
                        "provider.codex.home_lease",
                        serde_json::json!({}),
                        60,
                        None,
                        PeerRole::Agent(AgentRole::Codex),
                    ),
                    None,
                ),
                #[cfg(not(feature = "experimental-codex-home-lease"))]
                (
                    validated_request_for_role(
                        "provider.status",
                        serde_json::json!({}),
                        60,
                        None,
                        PeerRole::Agent(AgentRole::Codex),
                    ),
                    None,
                ),
                #[cfg(not(feature = "experimental-codex-home-lease"))]
                (
                    validated_request_for_role(
                        "vault.status",
                        serde_json::json!({}),
                        60,
                        None,
                        PeerRole::Agent(AgentRole::Codex),
                    ),
                    None,
                ),
                (
                    validated_request_for_role(
                        "provider.logout",
                        serde_json::json!({"provider": "codex"}),
                        60,
                        None,
                        PeerRole::Agent(AgentRole::Codex),
                    ),
                    None,
                ),
                (
                    validated_request_for_role(
                        "provider.logout",
                        serde_json::json!({"provider": "codex"}),
                        60,
                        None,
                        PeerRole::Companion,
                    ),
                    None,
                ),
                (
                    validated_request_for_role(
                        "audit.append",
                        serde_json::json!({
                            "sequence": 1,
                            "event": "agent-session-start",
                            "outcome": "succeeded"
                        }),
                        60,
                        None,
                        PeerRole::Agent(AgentRole::Application),
                    ),
                    None,
                ),
                (
                    validated_request_for_role(
                        "vault.status",
                        serde_json::json!({}),
                        60,
                        None,
                        PeerRole::Agent(AgentRole::Application),
                    ),
                    None,
                ),
                (
                    validated_request_for_role(
                        "provider.status",
                        serde_json::json!({}),
                        60,
                        None,
                        PeerRole::Agent(AgentRole::Application),
                    ),
                    None,
                ),
                (persist, Some(persist_writer)),
                (
                    validated_request_for_role(
                        "report.list",
                        serde_json::json!({}),
                        60,
                        None,
                        PeerRole::Agent(AgentRole::Application),
                    ),
                    None,
                ),
                (
                    validated_request_for_role(
                        "report.get",
                        serde_json::json!({
                            "reportId": "RP-00000000-0000-0000-0000-000000000001"
                        }),
                        60,
                        None,
                        PeerRole::Agent(AgentRole::Application),
                    ),
                    None,
                ),
            ];
            for (request, writer) in requests {
                let (version, result) = supervisor.handle_request(request, Instant::now());
                assert_eq!(version, 60);
                assert_handler_error(result, ErrorToken::NotAuthorized);
                if let Some(writer) = writer {
                    assert_pipe_has_no_reader(writer.as_fd());
                }
            }
            let state = supervisor.state.lock().expect("service state");
            assert_eq!(state.version, 60);
            assert_eq!(state.availability, expected_availability);
            assert!(state.transition_origin.is_none());
            assert!(!state.provider_operation_active);
            assert!(state.last_unlock_attempt.is_none());
            assert_eq!(state.faulted, expected_faulted);
            assert_eq!(state.fault_marker_required, expected_fault_marker_required);
            assert!(!state.marker_persistence_failed);
            assert!(!state.clean_fault_shutdown);
            drop(state);
            assert!(
                supervisor
                    .leases
                    .lock()
                    .expect("lease registry")
                    .active
                    .is_none()
            );
            assert!(worker.lock().expect("worker trace").calls.is_empty());
            assert_eq!(privacy.checks.load(Ordering::Acquire), 0);
            let runtime = runtime.lock().expect("runtime trace");
            assert_eq!(
                (runtime.arms, runtime.disarms, runtime.marker),
                (0, 0, false)
            );
        }
    }

    #[test]
    fn passphrase_reader_rejects_short_extra_nul_and_non_eof() {
        fn pipe_bytes(bytes: &[u8], keep_open: bool) -> (OwnedFd, Option<OwnedFd>) {
            let (read, write) = pipe_with(PipeFlags::CLOEXEC).expect("pipe");
            rustix::io::write(&write, bytes).expect("write");
            if keep_open {
                (read, Some(write))
            } else {
                drop(write);
                (read, None)
            }
        }
        let deadline = || Instant::now() + Duration::from_millis(100);
        let (short, _) = pipe_bytes(b"short", false);
        assert!(read_exact_passphrase(short, 12, deadline()).is_err());
        let (extra, _) = pipe_bytes(b"abcdefghijklmn", false);
        assert!(read_exact_passphrase(extra, 12, deadline()).is_err());
        let (nul, _) = pipe_bytes(b"abcde\0ghijkl", false);
        assert!(read_exact_passphrase(nul, 12, deadline()).is_err());
        let (not_eof, writer) = pipe_bytes(b"abcdefghijkl", true);
        assert!(read_exact_passphrase(not_eof, 12, deadline()).is_err());
        drop(writer);
    }

    #[test]
    fn transition_headroom_never_wraps_json_integer() {
        assert_eq!(
            ensure_transition_headroom(MAX_SAFE_JSON_INTEGER - 2, 2),
            Ok(())
        );
        assert_eq!(
            ensure_transition_headroom(MAX_SAFE_JSON_INTEGER - 1, 2),
            Err(ErrorToken::RebootRequired)
        );
    }

    #[test]
    fn status_bootstrap_exact_and_stale_rules_are_closed() {
        assert!(status_version_is_accepted(0, 41));
        assert!(status_version_is_accepted(41, 41));
        assert!(!status_version_is_accepted(40, 41));
        assert!(!status_version_is_accepted(42, 41));

        let (supervisor, runtime, worker, _, _) =
            fake_supervisor(service_state(41, VaultState::Locked), [], true);
        for expected in [0, 41] {
            let request = validated_request("vault.status", serde_json::json!({}), expected, None);
            let (version, result) = supervisor.handle_request(request, Instant::now());
            assert_eq!(version, 41);
            assert_handler_status(result, VaultState::Locked, None);
        }
        for expected in [40, 42] {
            let request = validated_request("vault.status", serde_json::json!({}), expected, None);
            let (version, result) = supervisor.handle_request(request, Instant::now());
            assert_eq!(version, 41);
            assert_handler_error(result, ErrorToken::StaleState);
        }
        assert!(worker.lock().expect("worker trace").calls.is_empty());
        let runtime = runtime.lock().expect("runtime trace");
        assert_eq!((runtime.arms, runtime.disarms), (0, 0));
    }

    #[test]
    fn shipping_peer_roles_have_a_closed_operation_surface() {
        let operations = [
            Operation::VaultStatus,
            Operation::VaultUnlock,
            Operation::VaultLock,
            Operation::ProviderOpenAiConfigure,
            Operation::ProviderStatus,
            Operation::ProviderLogout,
            Operation::ProviderOpenAiBorrow,
            Operation::ProviderCodexHomeLease,
            Operation::AuditAppend,
            Operation::ReportPersist,
            Operation::ReportList,
            Operation::ReportGet,
        ];
        for operation in operations {
            assert_eq!(
                external_operation_is_enabled(operation, PeerRole::Companion),
                matches!(
                    operation,
                    Operation::VaultStatus
                        | Operation::VaultUnlock
                        | Operation::VaultLock
                        | Operation::ProviderOpenAiConfigure
                        | Operation::ProviderStatus
                        | Operation::ProviderLogout
                ),
                "unexpected Companion shipping permission for {operation:?}"
            );
            assert_eq!(
                external_operation_is_enabled(operation, PeerRole::Agent(AgentRole::OpenAi)),
                matches!(
                    operation,
                    Operation::VaultStatus
                        | Operation::ProviderStatus
                        | Operation::ProviderOpenAiBorrow
                ),
                "unexpected OpenAI shipping permission for {operation:?}"
            );
            assert!(
                !external_operation_is_enabled(operation, PeerRole::Agent(AgentRole::Application)),
                "disabled Application role reached {operation:?}"
            );
            assert_eq!(
                external_operation_is_enabled(operation, PeerRole::Agent(AgentRole::Codex)),
                cfg!(feature = "experimental-codex-home-lease")
                    && matches!(
                        operation,
                        Operation::VaultStatus
                            | Operation::ProviderStatus
                            | Operation::ProviderCodexHomeLease
                    ),
                "unexpected Codex permission for {operation:?}"
            );
        }
        assert_eq!(
            provider_process_scope(PeerRole::Agent(AgentRole::OpenAi)),
            ProcessScope::CgroupTree
        );
        #[cfg(feature = "experimental-codex-home-lease")]
        assert_eq!(
            provider_process_scope(PeerRole::Agent(AgentRole::Codex)),
            ProcessScope::CgroupTree
        );
        #[cfg(not(feature = "experimental-codex-home-lease"))]
        assert_eq!(
            provider_process_scope(PeerRole::Agent(AgentRole::Codex)),
            ProcessScope::DirectPeer
        );
        for role in [PeerRole::Companion, PeerRole::Agent(AgentRole::Application)] {
            assert_eq!(provider_process_scope(role), ProcessScope::DirectPeer);
        }
    }

    #[test]
    fn provider_borrow_requires_a_live_authenticated_socket_identity() {
        let (supervisor, runtime, worker, privacy, _) = fake_supervisor(
            unlocked_service_state(710),
            [Ok(internal_wire::WorkerResponse::provider_borrow_ready(
                1, 32,
            ))],
            true,
        );
        let request = validated_request_for_role(
            "provider.openai.borrow",
            serde_json::json!({}),
            710,
            None,
            PeerRole::Agent(AgentRole::OpenAi),
        );
        let (version, result) = supervisor.handle_request(request, Instant::now());
        assert_eq!(version, 710);
        assert_handler_error(result, ErrorToken::IoFailed);
        assert_eq!(supervisor.snapshot().version, 710);
        let worker = worker.lock().expect("worker trace");
        assert!(worker.calls.is_empty());
        assert_eq!(worker.responses.len(), 1);
        drop(worker);
        assert_eq!(privacy.checks.load(Ordering::Relaxed), 0);
        let runtime = runtime.lock().expect("runtime trace");
        assert_eq!((runtime.arms, runtime.disarms), (0, 0));
        assert!(!runtime.marker);
    }

    #[test]
    fn companion_provider_borrow_is_rejected_before_pidfd_lease_or_any_effect() {
        let (supervisor, runtime, worker, privacy, _) = fake_supervisor(
            unlocked_service_state(710),
            [Ok(internal_wire::WorkerResponse::provider_borrow_ready(
                1, 32,
            ))],
            true,
        );
        let uid = rustix::process::getuid().as_raw();
        assert_ne!(uid, 0, "role test requires an unprivileged peer");
        let agent_uid = if uid == 1 { 2 } else { 1 };
        let allowlist = PeerAllowlist::builder(uid)
            .agent(AgentRole::OpenAi, agent_uid)
            .expect("test OpenAI role mapping")
            .build()
            .expect("test allowlist");
        for with_descriptor in [false, true] {
            let (client, server) = socketpair(
                AddressFamily::UNIX,
                SocketType::SEQPACKET,
                SocketFlags::CLOEXEC,
                None,
            )
            .expect("Companion request socketpair");
            let request_id = if with_descriptor {
                "R-00000000-0000-0000-0000-000000000712"
            } else {
                "R-00000000-0000-0000-0000-000000000711"
            };
            let datagram = serde_json::to_vec(&serde_json::json!({
                "apiVersion": API_VERSION,
                "requestId": request_id,
                "expectedStateVersion": 710,
                "operation": "provider.openai.borrow",
                "payload": {},
            }))
            .expect("Companion request");
            let mut descriptor_writer = None;
            if with_descriptor {
                let (read, write) = pipe_with(PipeFlags::CLOEXEC).expect("forbidden descriptor");
                let io = [IoSlice::new(&datagram)];
                let rights = [read.as_fd()];
                let mut space = [MaybeUninit::uninit(); rustix::cmsg_space!(ScmRights(1))];
                let mut ancillary = SendAncillaryBuffer::new(&mut space);
                assert!(ancillary.push(SendAncillaryMessage::ScmRights(&rights)));
                assert_eq!(
                    sendmsg(&client, &io, &mut ancillary, SendFlags::NOSIGNAL)
                        .expect("Companion descriptor request"),
                    datagram.len()
                );
                drop(read);
                descriptor_writer = Some(write);
            } else {
                assert_eq!(
                    send(&client, &datagram, SendFlags::NOSIGNAL)
                        .expect("Companion borrow request"),
                    datagram.len()
                );
            }
            handle_connection_by(server, allowlist, Arc::clone(&supervisor), false);
            let mut response = [0_u8; 2048];
            let (initialized, read) =
                recv(&client, &mut response, RecvFlags::empty()).expect("authorization response");
            assert_eq!(initialized, read);
            assert!(
                response[..read]
                    .windows(b"NOT_AUTHORIZED".len())
                    .any(|window| window == b"NOT_AUTHORIZED"),
                "Companion borrow was not rejected as unauthorized"
            );
            if let Some(writer) = descriptor_writer {
                assert_pipe_has_no_reader(writer.as_fd());
            }
        }
        assert_eq!(supervisor.snapshot().version, 710);
        assert!(
            supervisor
                .leases
                .lock()
                .expect("lease registry")
                .active
                .is_none()
        );
        let worker = worker.lock().expect("worker trace");
        assert!(worker.calls.is_empty());
        assert_eq!(worker.responses.len(), 1);
        drop(worker);
        assert_eq!(privacy.checks.load(Ordering::Acquire), 0);
        let runtime = runtime.lock().expect("runtime trace");
        assert_eq!((runtime.arms, runtime.disarms), (0, 0));
        assert!(!runtime.marker);
    }

    #[test]
    fn provider_borrow_unconfigured_is_definite_no_secret_and_preserves_version() {
        let (supervisor, runtime, worker, privacy, _) = fake_supervisor(
            unlocked_service_state(711),
            [Ok(internal_wire::WorkerResponse::new(
                1,
                internal_wire::WorkerResultCode::ProviderBorrowUnconfigured,
            ))],
            true,
        );
        let (request, client, server) = validated_request_with_connection_for_role(
            "provider.openai.borrow",
            serde_json::json!({}),
            711,
            None,
            PeerRole::Agent(AgentRole::OpenAi),
        );
        let (version, result) = supervisor.handle_connected_request(
            request,
            Instant::now(),
            ClientConnection::LeaseTestSocket(server.as_fd()),
        );
        assert_eq!(version, 711);
        assert_handler_error(result, ErrorToken::ProviderUnconfigured);
        assert_eq!(supervisor.snapshot().version, 711);
        assert!(
            supervisor
                .leases
                .lock()
                .expect("lease registry")
                .active
                .is_none()
        );
        assert_eq!(
            worker.lock().expect("worker trace").calls,
            [internal_wire::WorkerCommandKind::ProviderOpenAiBorrow]
        );
        assert_eq!(privacy.checks.load(Ordering::Relaxed), 1);
        let runtime = runtime.lock().expect("runtime trace");
        assert_eq!((runtime.arms, runtime.disarms), (1, 0));
        assert!(runtime.marker);
        drop(client);
    }

    #[cfg(feature = "experimental-codex-home-lease")]
    #[test]
    fn codex_home_unconfigured_is_definite_no_descriptor_and_preserves_version() {
        let (supervisor, runtime, worker, privacy, _) = fake_supervisor(
            unlocked_service_state(714),
            [Ok(internal_wire::WorkerResponse::new(
                1,
                internal_wire::WorkerResultCode::ProviderCodexHomeUnconfigured,
            ))],
            true,
        );
        let (request, client, server) = validated_request_with_connection_for_role(
            "provider.codex.home_lease",
            serde_json::json!({}),
            714,
            None,
            PeerRole::Agent(AgentRole::Codex),
        );
        let (version, result) = supervisor.handle_connected_request(
            request,
            Instant::now(),
            ClientConnection::LeaseTestSocket(server.as_fd()),
        );
        assert_eq!(version, 714);
        assert_handler_error(result, ErrorToken::ProviderUnconfigured);
        assert_eq!(supervisor.snapshot().version, 714);
        assert!(
            supervisor
                .leases
                .lock()
                .expect("lease registry")
                .active
                .is_none()
        );
        assert_eq!(
            worker.lock().expect("worker trace").calls,
            [internal_wire::WorkerCommandKind::ProviderCodexHomeLease]
        );
        assert_eq!(privacy.checks.load(Ordering::Relaxed), 1);
        let runtime = runtime.lock().expect("runtime trace");
        assert_eq!((runtime.arms, runtime.disarms), (1, 0));
        assert!(runtime.marker);
        drop(client);
    }

    #[cfg(feature = "experimental-codex-home-lease")]
    #[test]
    fn codex_home_fault_and_stop_fail_before_worker_dispatch() {
        for (mut state, stopping, expected) in [
            (unlocked_service_state(715), true, ErrorToken::Busy),
            (
                {
                    let mut state = unlocked_service_state(716);
                    state.faulted = true;
                    state.fault_marker_required = true;
                    state.availability = faulted_availability();
                    state
                },
                false,
                ErrorToken::RebootRequired,
            ),
        ] {
            state.provider_operation_active = false;
            let (supervisor, _, worker, privacy, _) = fake_supervisor(state, [], true);
            supervisor.stopping.store(stopping, Ordering::Release);
            let expected_version = supervisor.snapshot().version;
            let (request, client, server) = validated_request_with_connection_for_role(
                "provider.codex.home_lease",
                serde_json::json!({}),
                expected_version,
                None,
                PeerRole::Agent(AgentRole::Codex),
            );
            let (version, result) = supervisor.handle_connected_request(
                request,
                Instant::now(),
                ClientConnection::LeaseTestSocket(server.as_fd()),
            );
            assert!(version >= expected_version);
            assert_handler_error(result, expected);
            assert!(worker.lock().expect("worker trace").calls.is_empty());
            assert_eq!(privacy.checks.load(Ordering::Acquire), 0);
            drop(client);
        }
    }

    #[cfg(feature = "experimental-codex-home-lease")]
    #[test]
    fn openai_and_codex_share_one_global_lease_registry() {
        let (supervisor, _, worker, privacy, _) =
            fake_supervisor(unlocked_service_state(717), [], true);
        let (first_peer, first_server) = socketpair(
            AddressFamily::UNIX,
            SocketType::SEQPACKET,
            SocketFlags::CLOEXEC | SocketFlags::NONBLOCK,
            None,
        )
        .expect("OpenAI lease socket");
        let first_connection = ClientConnection::LeaseTestSocket(first_server.as_fd());
        let first_candidate = first_connection
            .lease_candidate(ProcessScope::CgroupTree)
            .expect("OpenAI candidate");
        let (_, lease_id) = supervisor
            .begin_provider_borrow(
                717,
                &first_connection,
                first_candidate,
                Instant::now() + PROVIDER_BORROW_TIMEOUT,
            )
            .expect("OpenAI pending lease");

        let (second_peer, second_server) = socketpair(
            AddressFamily::UNIX,
            SocketType::SEQPACKET,
            SocketFlags::CLOEXEC | SocketFlags::NONBLOCK,
            None,
        )
        .expect("Codex lease socket");
        let second_connection = ClientConnection::LeaseTestSocket(second_server.as_fd());
        let second_candidate = second_connection
            .lease_candidate(ProcessScope::CgroupTree)
            .expect("Codex candidate");
        assert_eq!(
            supervisor.begin_provider_borrow(
                717,
                &second_connection,
                second_candidate,
                Instant::now() + PROVIDER_BORROW_TIMEOUT,
            ),
            Err((717, ErrorToken::Busy))
        );
        assert!(matches!(
            supervisor
                .leases
                .lock()
                .expect("lease registry")
                .active
                .as_ref(),
            Some(lease) if lease.id == lease_id && lease.state == LeaseState::Pending
        ));
        supervisor
            .cancel_pending_lease(lease_id)
            .expect("cancel pending lease");
        assert!(worker.lock().expect("worker trace").calls.is_empty());
        assert_eq!(privacy.checks.load(Ordering::Acquire), 0);
        drop((first_peer, first_server, second_peer, second_server));
    }

    #[test]
    fn fault_reservation_wins_before_unconfigured_borrow_completion() {
        let (supervisor, _, worker, privacy, _) =
            fake_supervisor(unlocked_service_state(712), [], true);
        let (output, raw_output, mut child) = install_output_obligated_lease(&supervisor);
        drop(raw_output);
        drop(output);
        {
            let _decision = supervisor.lifecycle.lock().expect("lifecycle boundary");
            supervisor.faulted.store(true, Ordering::Release);
            let mut state = supervisor.state.lock().expect("service state");
            transition_state_to_fault(&mut state, true);
        }

        assert_eq!(supervisor.finish_provider_borrow_unconfigured(1), Ok(None));
        assert!(matches!(
            supervisor
                .leases
                .lock()
                .expect("lease registry")
                .active
                .as_ref(),
            Some(lease) if lease.state == LeaseState::PotentiallyIssued
        ));
        assert!(worker.lock().expect("worker trace").calls.is_empty());
        assert_eq!(privacy.checks.load(Ordering::Acquire), 0);

        supervisor
            .revoke_active_lease(Instant::now() + Duration::from_secs(1))
            .expect("fault owner revokes the retained lease");
        let _ = child.wait();
    }

    #[test]
    fn fault_reservation_wins_before_pending_borrow_cancellation() {
        let (supervisor, _, worker, privacy, _) =
            fake_supervisor(unlocked_service_state(713), [], true);
        let (output, raw_output, mut child) = install_output_obligated_lease(&supervisor);
        drop(raw_output);
        drop(output);
        supervisor
            .leases
            .lock()
            .expect("lease registry")
            .active
            .as_mut()
            .expect("active lease")
            .state = LeaseState::Pending;
        {
            let _decision = supervisor.lifecycle.lock().expect("lifecycle boundary");
            supervisor.faulted.store(true, Ordering::Release);
            let mut state = supervisor.state.lock().expect("service state");
            transition_state_to_fault(&mut state, true);
        }

        assert!(matches!(
            supervisor.mark_lease_potentially_issued(1),
            Ok(PotentialIssue::RevocationInProgress)
        ));
        assert!(matches!(
            supervisor.cancel_pending_lease(1),
            Ok(PendingCancel::RevocationInProgress)
        ));
        assert!(matches!(
            supervisor
                .leases
                .lock()
                .expect("lease registry")
                .active
                .as_ref(),
            Some(lease) if lease.state == LeaseState::Pending
        ));
        assert!(worker.lock().expect("worker trace").calls.is_empty());
        assert_eq!(privacy.checks.load(Ordering::Acquire), 0);

        supervisor
            .revoke_active_lease(Instant::now() + Duration::from_secs(1))
            .expect("fault owner revokes the retained Pending lease");
        let _ = child.wait();
    }

    #[test]
    fn provider_status_configure_and_logout_use_real_requests_and_exact_versions() {
        let (status, runtime, worker, privacy, _) = fake_supervisor(
            unlocked_service_state(60),
            [Ok(internal_wire::WorkerResponse::new(
                1,
                internal_wire::WorkerResultCode::ProviderStatusConfigured,
            ))],
            true,
        );
        let request = validated_request_for_role(
            "provider.status",
            serde_json::json!({}),
            60,
            None,
            PeerRole::Agent(AgentRole::OpenAi),
        );
        let (version, result) = status.handle_request(request, Instant::now());
        assert_eq!(version, 60);
        assert_handler_provider_status(result, ProviderState::Configured);
        assert_eq!(privacy.checks.load(Ordering::Relaxed), 1);
        assert_eq!(
            worker.lock().expect("worker trace").calls,
            [internal_wire::WorkerCommandKind::ProviderStatus]
        );
        assert_eq!(runtime.lock().expect("runtime trace").arms, 0);

        let (configure, runtime, worker, privacy, _) = fake_supervisor(
            unlocked_service_state(70),
            [Ok(internal_wire::WorkerResponse::new(
                2,
                internal_wire::WorkerResultCode::ProviderConfigureSucceeded,
            ))],
            true,
        );
        let (request, writer) = descriptor_request(
            "provider.openai.configure",
            serde_json::json!({
                "input": {"type": "openai-api-key-pipe", "size": 1}
            }),
            70,
            PeerRole::Companion,
            b"K",
        );
        drop(writer);
        let (version, result) = configure.handle_request(request, Instant::now());
        assert_eq!(version, 72);
        assert_handler_provider_status(result, ProviderState::Configured);
        assert_eq!(privacy.checks.load(Ordering::Relaxed), 1);
        let worker = worker.lock().expect("worker trace");
        assert_eq!(
            worker.calls,
            [internal_wire::WorkerCommandKind::ProviderOpenAiConfigure]
        );
        assert_eq!(worker.passphrase_bytes, 1);
        drop(worker);
        let runtime = runtime.lock().expect("runtime trace");
        assert_eq!(runtime.arms, 1);
        assert!(runtime.marker);

        let (logout, runtime, worker, privacy, _) = fake_supervisor(
            unlocked_service_state(80),
            [Ok(internal_wire::WorkerResponse::new(
                3,
                internal_wire::WorkerResultCode::ProviderLogoutSucceeded,
            ))],
            true,
        );
        let request = validated_request(
            "provider.logout",
            serde_json::json!({"provider": "openai"}),
            80,
            None,
        );
        let (version, result) = logout.handle_request(request, Instant::now());
        assert_eq!(version, 82);
        assert_handler_provider_status(result, ProviderState::Unconfigured);
        assert_eq!(privacy.checks.load(Ordering::Relaxed), 1);
        assert_eq!(
            worker.lock().expect("worker trace").calls,
            [internal_wire::WorkerCommandKind::ProviderOpenAiLogout]
        );
        assert_eq!(runtime.lock().expect("runtime trace").arms, 1);
    }

    #[test]
    fn provider_gates_reject_stale_locked_busy_dead_client_and_codex_without_dispatch() {
        for (mut state, expected, error) in [
            (unlocked_service_state(90), 89, ErrorToken::StaleState),
            (
                service_state(90, VaultState::Locked),
                90,
                ErrorToken::Locked,
            ),
        ] {
            state.provider_operation_active = false;
            let (supervisor, _, worker, privacy, _) = fake_supervisor(state, [], true);
            let request =
                validated_request("provider.status", serde_json::json!({}), expected, None);
            let (version, result) = supervisor.handle_request(request, Instant::now());
            assert_eq!(version, 90);
            assert_handler_error(result, error);
            assert!(worker.lock().expect("worker trace").calls.is_empty());
            assert_eq!(privacy.checks.load(Ordering::Relaxed), 0);
        }

        let mut active = unlocked_service_state(100);
        active.provider_operation_active = true;
        let (supervisor, _, worker, _, _) = fake_supervisor(active, [], true);
        let request = validated_request("provider.status", serde_json::json!({}), 100, None);
        let (version, result) = supervisor.handle_request(request, Instant::now());
        assert_eq!(version, 100);
        assert_handler_error(result, ErrorToken::Busy);
        assert!(worker.lock().expect("worker trace").calls.is_empty());

        let (supervisor, _, worker, _, _) = fake_supervisor(unlocked_service_state(110), [], true);
        let (request, client, server) = validated_request_with_connection_for_role(
            "provider.status",
            serde_json::json!({}),
            110,
            None,
            PeerRole::Companion,
        );
        drop(client);
        let (version, result) = supervisor.handle_connected_request(
            request,
            Instant::now(),
            ClientConnection::Socket(server.as_fd()),
        );
        assert_eq!(version, 110);
        assert_handler_error(result, ErrorToken::IoFailed);
        assert!(worker.lock().expect("worker trace").calls.is_empty());

        let (supervisor, _, worker, _, _) = fake_supervisor(unlocked_service_state(120), [], true);
        let request = validated_request(
            "provider.logout",
            serde_json::json!({"provider": "codex"}),
            120,
            None,
        );
        let (version, result) = supervisor.handle_request(request, Instant::now());
        assert_eq!(version, 120);
        assert_handler_error(result, ErrorToken::NotAuthorized);
        assert!(worker.lock().expect("worker trace").calls.is_empty());

        let mut faulted = unlocked_service_state(125);
        faulted.faulted = true;
        faulted.fault_marker_required = true;
        faulted.availability = faulted_availability();
        let (supervisor, _, worker, _, _) = fake_supervisor(faulted, [], true);
        supervisor.faulted.store(true, Ordering::Release);
        let request = validated_request("provider.status", serde_json::json!({}), 125, None);
        let (version, result) = supervisor.handle_request(request, Instant::now());
        assert_eq!(version, 125);
        assert_handler_error(result, ErrorToken::RebootRequired);
        assert!(worker.lock().expect("worker trace").calls.is_empty());

        let mut provider_mutation = unlocked_service_state(126);
        assert_eq!(
            begin_provider_operation_state(&mut provider_mutation, 126, true, false),
            Ok(127)
        );
        assert_eq!(
            begin_lock_state(&mut provider_mutation, 127, false),
            Err((127, ErrorToken::Busy))
        );
        assert_eq!(
            begin_provider_operation_state(&mut provider_mutation, 127, false, false),
            Err((127, ErrorToken::Busy))
        );

        let mut vault_mutation = unlocked_service_state(128);
        assert_eq!(begin_lock_state(&mut vault_mutation, 128, false), Ok(129));
        assert_eq!(
            begin_provider_operation_state(&mut vault_mutation, 129, false, false),
            Err((129, ErrorToken::Busy))
        );
    }

    #[test]
    fn provider_aborted_is_consistent_but_ambiguous_or_privacy_failure_faults() {
        let (aborted, _, worker, _, _) = fake_supervisor(
            unlocked_service_state(130),
            [Ok(internal_wire::WorkerResponse::new(
                4,
                internal_wire::WorkerResultCode::ProviderMutationAborted,
            ))],
            true,
        );
        let request = validated_request(
            "provider.logout",
            serde_json::json!({"provider": "openai"}),
            130,
            None,
        );
        let (version, result) = aborted.handle_request(request, Instant::now());
        assert_eq!(version, 132);
        assert_handler_error(result, ErrorToken::IoFailed);
        assert!(!aborted.faulted.load(Ordering::Acquire));
        assert_eq!(worker.lock().expect("worker trace").faults, 0);

        let (ambiguous, _, worker, _, _) = fake_supervisor(
            unlocked_service_state(140),
            [Ok(internal_wire::WorkerResponse::new(
                5,
                internal_wire::WorkerResultCode::ProviderStateAmbiguous,
            ))],
            true,
        );
        let request = validated_request("provider.status", serde_json::json!({}), 140, None);
        let (version, result) = ambiguous.handle_request(request, Instant::now());
        assert_eq!(version, 141);
        assert_handler_error(result, ErrorToken::RebootRequired);
        assert!(ambiguous.faulted.load(Ordering::Acquire));
        assert_eq!(worker.lock().expect("worker trace").faults, 1);

        let (privacy_failed, _, worker, privacy, _) =
            fake_supervisor(unlocked_service_state(150), [], false);
        let request = validated_request("provider.status", serde_json::json!({}), 150, None);
        let (version, result) = privacy_failed.handle_request(request, Instant::now());
        assert_eq!(version, 151);
        assert_handler_error(result, ErrorToken::RebootRequired);
        assert_eq!(privacy.checks.load(Ordering::Relaxed), 1);
        let worker = worker.lock().expect("worker trace");
        assert!(worker.calls.is_empty());
        assert_eq!(worker.faults, 1);
    }

    #[test]
    fn provider_stop_before_arm_rolls_back_but_stop_after_marker_faults() {
        let (before, runtime, worker, _, _) =
            fake_supervisor(unlocked_service_state(160), [], true);
        before.stopping.store(true, Ordering::Release);
        let request = validated_request(
            "provider.logout",
            serde_json::json!({"provider": "openai"}),
            160,
            None,
        );
        let (version, result) = before.handle_request(request, Instant::now());
        assert_eq!(version, 160);
        assert_handler_error(result, ErrorToken::Busy);
        assert_eq!(runtime.lock().expect("runtime trace").arms, 0);
        assert!(worker.lock().expect("worker trace").calls.is_empty());

        let (after, runtime, worker, _, trace) =
            fake_supervisor(unlocked_service_state(170), [], true);
        let (entered_tx, entered_rx) = mpsc::sync_channel(0);
        let (release_tx, release_rx) = mpsc::sync_channel(0);
        *after.runtime.lock().expect("runtime boundary") = Box::new(StopDuringFirstArmRuntime {
            state: Arc::clone(&runtime),
            trace: Arc::clone(&trace),
            entered: entered_tx,
            release: Some(release_rx),
        });
        let request = validated_request(
            "provider.logout",
            serde_json::json!({"provider": "openai"}),
            170,
            None,
        );
        let running = Arc::clone(&after);
        let handler = thread::spawn(move || running.handle_request(request, Instant::now()));
        entered_rx.recv().expect("provider marker arm reached");
        after.stopping.store(true, Ordering::Release);
        release_tx.send(()).expect("release provider marker arm");
        let (version, result) = handler.join().expect("provider handler");
        assert_eq!(version, 172);
        assert_handler_error(result, ErrorToken::RebootRequired);
        assert!(after.faulted.load(Ordering::Acquire));
        let worker = worker.lock().expect("worker trace");
        assert!(worker.calls.is_empty());
        assert_eq!(worker.faults, 1);
        assert!(runtime.lock().expect("runtime trace").marker);
    }

    #[test]
    fn unlock_wrong_key_success_and_lock_each_use_two_versions() {
        let now = Instant::now();

        let mut wrong = service_state(100, VaultState::Locked);
        assert_eq!(
            begin_unlock_state(&mut wrong, 99, now, false),
            Err((100, ErrorToken::StaleState))
        );
        assert_eq!(wrong.version, 100);
        assert_eq!(begin_unlock_state(&mut wrong, 100, now, false), Ok(101));
        assert_eq!(wrong.availability, available(VaultState::Unlocking, None));
        validate_completion(&wrong, VaultState::Unlocking)
            .expect("wrong-key attestation completion");
        assert_eq!(
            apply_completion(&mut wrong, available(VaultState::Locked, None)),
            102
        );
        assert_eq!(
            begin_unlock_state(&mut wrong, 102, now, false),
            Err((102, ErrorToken::RateLimited))
        );

        let mut success = service_state(200, VaultState::Locked);
        assert_eq!(begin_unlock_state(&mut success, 200, now, false), Ok(201));
        validate_completion(&success, VaultState::Unlocking).expect("unlock completion");
        assert_eq!(
            apply_completion(
                &mut success,
                available(
                    VaultState::Unlocked,
                    Some("KA-0123456789abcdef01234567".to_owned()),
                ),
            ),
            202
        );
        assert_eq!(begin_lock_state(&mut success, 202, false), Ok(203));
        validate_completion(&success, VaultState::Locking).expect("lock completion");
        assert_eq!(
            apply_completion(&mut success, available(VaultState::Locked, None)),
            204
        );
    }

    #[test]
    fn malformed_or_slow_input_exposes_unlocking_then_returns_locked() {
        let now = Instant::now();
        let mut state = service_state(300, VaultState::Locked);
        assert_eq!(begin_unlock_state(&mut state, 300, now, false), Ok(301));
        assert_eq!(state.availability, available(VaultState::Unlocking, None));
        validate_completion(&state, VaultState::Unlocking).expect("nonmutation completion");
        assert_eq!(
            apply_completion(&mut state, available(VaultState::Locked, None)),
            302
        );
        assert!(!state.faulted);
        assert!(!state.fault_marker_required);
    }

    #[test]
    fn fault_wins_over_status_begin_and_completion_once() {
        let now = Instant::now();
        let mut state = service_state(400, VaultState::Locked);
        assert_eq!(begin_unlock_state(&mut state, 400, now, false), Ok(401));
        transition_state_to_fault(&mut state, true);
        assert_eq!(state.version, 402);
        assert_eq!(state.availability, faulted_availability());
        transition_state_to_fault(&mut state, true);
        assert_eq!(state.version, 402, "fault transition is idempotent");
        assert_eq!(
            begin_unlock_state(&mut state, 402, now + UNLOCK_RATE_LIMIT, false),
            Err((402, ErrorToken::RebootRequired))
        );
        assert!(validate_completion(&state, VaultState::Unlocking).is_err());
        assert!(status_version_is_accepted(0, state.version));
        assert!(state.fault_marker_required);
    }

    #[test]
    fn lifecycle_boundary_serializes_fault_against_status_begin_and_completion() {
        let (supervisor, _, worker, _, _) =
            fake_supervisor(service_state(500, VaultState::Locked), [], true);
        let (entered_tx, entered_rx) = mpsc::sync_channel(0);
        let (release_tx, release_rx) = mpsc::sync_channel(0);
        *supervisor.runtime.lock().expect("runtime boundary") = Box::new(BlockingRuntime {
            entered: entered_tx,
            release: release_rx,
        });

        let status_request = validated_request("vault.status", serde_json::json!({}), 0, None);
        let (secret_read, secret_write) = pipe_with(PipeFlags::CLOEXEC).expect("secret pipe");
        rustix::io::write(&secret_write, b"TEST_ONLY_12").expect("secret bytes");
        let retained_read =
            rustix::io::fcntl_dupfd_cloexec(&secret_read, 3).expect("retained unread proof");
        let unlock_request = validated_request(
            "vault.unlock",
            serde_json::json!({
                "input": {"type": "passphrase-pipe", "size": 12}
            }),
            500,
            Some(secret_read.as_fd()),
        );
        drop(secret_read);
        drop(secret_write);

        let faulting = Arc::clone(&supervisor);
        let fault_thread = thread::spawn(move || faulting.mark_fault());
        entered_rx
            .recv_timeout(Duration::from_secs(1))
            .expect("fault reached marker barrier");

        let (status_tx, status_rx) = mpsc::channel();
        let status_supervisor = Arc::clone(&supervisor);
        let status_thread = thread::spawn(move || {
            let (version, result) =
                status_supervisor.handle_request(status_request, Instant::now());
            let state = match result {
                HandlerResult::Success(_, SuccessPayload::VaultStatus(status)) => {
                    Some(status.vault_state())
                }
                _ => None,
            };
            status_tx.send((version, state)).expect("status result");
        });

        let (unlock_tx, unlock_rx) = mpsc::channel();
        let unlock_supervisor = Arc::clone(&supervisor);
        let unlock_thread = thread::spawn(move || {
            let (version, result) =
                unlock_supervisor.handle_request(unlock_request, Instant::now());
            let error = match result {
                HandlerResult::Error(_, error) => Some(error),
                _ => None,
            };
            unlock_tx.send((version, error)).expect("unlock result");
        });

        let (completion_tx, completion_rx) = mpsc::channel();
        let completion_supervisor = Arc::clone(&supervisor);
        let completion_thread = thread::spawn(move || {
            completion_tx
                .send(completion_supervisor.complete_transition(
                    VaultState::Unlocking,
                    available(VaultState::Locked, None),
                ))
                .expect("completion result");
        });

        assert_eq!(
            status_rx.recv_timeout(Duration::from_millis(50)),
            Err(mpsc::RecvTimeoutError::Timeout),
            "status escaped the fault boundary"
        );
        assert_eq!(
            unlock_rx.recv_timeout(Duration::from_millis(50)),
            Err(mpsc::RecvTimeoutError::Timeout),
            "unlock escaped the fault boundary"
        );
        assert_eq!(
            completion_rx.recv_timeout(Duration::from_millis(50)),
            Err(mpsc::RecvTimeoutError::Timeout)
        );

        release_tx.send(()).expect("release marker barrier");
        fault_thread.join().expect("fault thread");
        // The rejected unlock invokes idempotent mark_fault() to re-verify the
        // durable marker. Let that second marker proof complete too; it must
        // not increment the public state version again.
        entered_rx
            .recv_timeout(Duration::from_secs(1))
            .expect("rejected unlock reached marker recheck");
        release_tx.send(()).expect("release marker recheck");
        assert_eq!(
            status_rx.recv_timeout(Duration::from_secs(1)),
            Ok((501, Some(VaultState::FaultedRebootRequired)))
        );
        assert_eq!(
            unlock_rx.recv_timeout(Duration::from_secs(1)),
            Ok((501, Some(ErrorToken::RebootRequired)))
        );
        assert!(
            completion_rx
                .recv_timeout(Duration::from_secs(1))
                .expect("completion after fault")
                .is_err()
        );
        status_thread.join().expect("status thread");
        unlock_thread.join().expect("unlock thread");
        completion_thread.join().expect("completion thread");

        let mut unread = Zeroizing::new([0_u8; 12]);
        assert_eq!(
            rustix::io::read(&retained_read, &mut unread[..]).expect("unread secret proof"),
            unread.len()
        );
        assert_eq!(&unread[..], b"TEST_ONLY_12");
        assert_eq!(supervisor.snapshot().version, 501);
        assert_eq!(worker.lock().expect("worker trace").faults, 2);
    }

    #[test]
    fn stop_before_arm_rolls_back_without_marker_or_worker_for_unlock_and_lock() {
        let (mut unlock, unlock_runtime, unlock_worker, _, _) =
            fake_supervisor(service_state(600, VaultState::Locked), [], true);
        let (entered_tx, entered_rx) = mpsc::sync_channel(0);
        let (release_tx, release_rx) = mpsc::sync_channel(0);
        Arc::get_mut(&mut unlock)
            .expect("exclusive supervisor")
            .privacy = Arc::new(BlockingPrivacy {
            calls: AtomicUsize::new(0),
            block_on: 2,
            entered: entered_tx,
            release: Mutex::new(release_rx),
        });
        let (request, _) = unlock_request(600, b"TEST_ONLY_12", false);
        let running = Arc::clone(&unlock);
        let (result_tx, result_rx) = mpsc::channel();
        let handler = thread::spawn(move || {
            let (version, result) = running.handle_request(request, Instant::now());
            result_tx
                .send((
                    version,
                    matches!(result, HandlerResult::Error(_, ErrorToken::Busy)),
                ))
                .expect("unlock stop result");
        });
        entered_rx
            .recv_timeout(Duration::from_secs(1))
            .expect("unlock reached pre-arm privacy barrier");
        unlock.stopping.store(true, Ordering::Release);
        release_tx.send(()).expect("release unlock pre-arm");
        assert_eq!(
            result_rx.recv_timeout(Duration::from_secs(1)),
            Ok((602, true))
        );
        handler.join().expect("unlock handler");
        assert_eq!(
            unlock.snapshot().availability,
            available(VaultState::Locked, None)
        );
        assert!(unlock_worker.lock().expect("worker trace").calls.is_empty());
        let runtime = unlock_runtime.lock().expect("runtime trace");
        assert_eq!((runtime.arms, runtime.marker), (0, false));
        drop(runtime);

        let mut initial = service_state(610, VaultState::Unlocked);
        initial.availability = available(
            VaultState::Unlocked,
            Some("KA-0123456789abcdef01234567".to_owned()),
        );
        let (mut lock, lock_runtime, lock_worker, _, _) = fake_supervisor(initial, [], true);
        lock_runtime.lock().expect("runtime fixture").marker = true;
        let (entered_tx, entered_rx) = mpsc::sync_channel(0);
        let (release_tx, release_rx) = mpsc::sync_channel(0);
        Arc::get_mut(&mut lock)
            .expect("exclusive supervisor")
            .privacy = Arc::new(BlockingPrivacy {
            calls: AtomicUsize::new(0),
            block_on: 1,
            entered: entered_tx,
            release: Mutex::new(release_rx),
        });
        let request = validated_request("vault.lock", serde_json::json!({}), 610, None);
        let running = Arc::clone(&lock);
        let (result_tx, result_rx) = mpsc::channel();
        let handler = thread::spawn(move || {
            let (version, result) = running.handle_request(request, Instant::now());
            result_tx
                .send((
                    version,
                    matches!(result, HandlerResult::Error(_, ErrorToken::Busy)),
                ))
                .expect("lock stop result");
        });
        entered_rx
            .recv_timeout(Duration::from_secs(1))
            .expect("lock reached pre-arm privacy barrier");
        lock.stopping.store(true, Ordering::Release);
        release_tx.send(()).expect("release lock pre-arm");
        assert_eq!(
            result_rx.recv_timeout(Duration::from_secs(1)),
            Ok((612, true))
        );
        handler.join().expect("lock handler");
        assert_eq!(
            lock.snapshot().availability,
            available(
                VaultState::Unlocked,
                Some("KA-0123456789abcdef01234567".to_owned())
            )
        );
        assert!(lock_worker.lock().expect("worker trace").calls.is_empty());
        let runtime = lock_runtime.lock().expect("runtime trace");
        assert_eq!((runtime.arms, runtime.marker), (0, true));
    }

    #[test]
    fn stop_after_arm_or_dispatch_faults_and_retains_marker() {
        let (armed, runtime, worker, _, trace) =
            fake_supervisor(service_state(620, VaultState::Locked), [], true);
        let (entered_tx, entered_rx) = mpsc::sync_channel(0);
        let (release_tx, release_rx) = mpsc::sync_channel(0);
        *armed.runtime.lock().expect("runtime boundary") = Box::new(StopDuringFirstArmRuntime {
            state: Arc::clone(&runtime),
            trace: Arc::clone(&trace),
            entered: entered_tx,
            release: Some(release_rx),
        });
        let (request, _) = unlock_request(620, b"TEST_ONLY_12", false);
        let running = Arc::clone(&armed);
        let (result_tx, result_rx) = mpsc::channel();
        let handler = thread::spawn(move || {
            let (version, result) = running.handle_request(request, Instant::now());
            result_tx
                .send((
                    version,
                    matches!(result, HandlerResult::Error(_, ErrorToken::RebootRequired)),
                ))
                .expect("post-arm result");
        });
        entered_rx
            .recv_timeout(Duration::from_secs(1))
            .expect("marker arm barrier");
        armed.stopping.store(true, Ordering::Release);
        release_tx.send(()).expect("release marker arm");
        assert_eq!(
            result_rx.recv_timeout(Duration::from_secs(1)),
            Ok((622, true))
        );
        handler.join().expect("post-arm handler");
        assert!(worker.lock().expect("worker trace").calls.is_empty());
        assert!(runtime.lock().expect("runtime trace").marker);
        assert_eq!(armed.snapshot().availability, faulted_availability());

        let (dispatched, runtime, worker, _, trace) = fake_supervisor(
            service_state(630, VaultState::Locked),
            [Err(RescueVaultDaemonError::WorkerUnavailable)],
            true,
        );
        let (entered_tx, entered_rx) = mpsc::sync_channel(0);
        let (release_tx, release_rx) = mpsc::sync_channel(0);
        worker.lock().expect("worker fixture").block_unlock = Some((entered_tx, release_rx));
        let (request, _) = unlock_request(630, b"TEST_ONLY_12", false);
        let running = Arc::clone(&dispatched);
        let (result_tx, result_rx) = mpsc::channel();
        let handler = thread::spawn(move || {
            let (version, result) = running.handle_request(request, Instant::now());
            result_tx
                .send((
                    version,
                    matches!(result, HandlerResult::Error(_, ErrorToken::RebootRequired)),
                ))
                .expect("post-dispatch result");
        });
        entered_rx
            .recv_timeout(Duration::from_secs(1))
            .expect("worker dispatch barrier");
        dispatched.stopping.store(true, Ordering::Release);
        release_tx.send(()).expect("release worker dispatch");
        assert_eq!(
            result_rx.recv_timeout(Duration::from_secs(1)),
            Ok((632, true))
        );
        handler.join().expect("post-dispatch handler");
        assert_eq!(
            worker.lock().expect("worker trace").calls,
            [internal_wire::WorkerCommandKind::Unlock]
        );
        assert!(runtime.lock().expect("runtime trace").marker);
        let trace = trace.lock().expect("effect trace");
        assert!(trace.contains(&TraceEvent::WorkerUnlock));
        assert!(trace.contains(&TraceEvent::WorkerFault));
    }

    #[test]
    fn peer_liveness_probe_rejects_eof_and_unexpected_records() {
        let (client, server) = socketpair(
            AddressFamily::UNIX,
            SocketType::SEQPACKET,
            SocketFlags::CLOEXEC,
            None,
        )
        .expect("liveness socketpair");
        assert!(socket_client_is_live(server.as_fd()));
        assert_eq!(
            send(&client, b"unexpected", SendFlags::NOSIGNAL).expect("extra record"),
            10
        );
        assert!(!socket_client_is_live(server.as_fd()));
        let mut drain = [0_u8; 10];
        assert_eq!(
            recv(&server, &mut drain, RecvFlags::empty())
                .expect("drain record")
                .0,
            drain.len()
        );
        assert!(socket_client_is_live(server.as_fd()));
        drop(client);
        assert!(!socket_client_is_live(server.as_fd()));
    }

    #[test]
    fn closed_peer_before_begin_never_changes_state_or_dispatches() {
        let (unlock, unlock_runtime, unlock_worker, _, _) =
            fake_supervisor(service_state(640, VaultState::Locked), [], true);
        let (unlock_request, unlock_client, unlock_server) = connected_unlock_request(640);
        drop(unlock_client);
        let (version, result) = unlock.handle_connected_request(
            unlock_request,
            Instant::now(),
            ClientConnection::Socket(unlock_server.as_fd()),
        );
        assert_eq!(version, 640);
        assert_handler_error(result, ErrorToken::IoFailed);
        assert_eq!(
            unlock.snapshot().availability,
            available(VaultState::Locked, None)
        );
        assert_eq!(
            (
                unlock_runtime.lock().expect("runtime trace").arms,
                unlock_worker.lock().expect("worker trace").calls.len()
            ),
            (0, 0)
        );

        let mut initial = service_state(650, VaultState::Unlocked);
        initial.availability = available(
            VaultState::Unlocked,
            Some("KA-0123456789abcdef01234567".to_owned()),
        );
        let (lock, lock_runtime, lock_worker, _, _) = fake_supervisor(initial, [], true);
        lock_runtime.lock().expect("runtime fixture").marker = true;
        let (request, client, server) = validated_request_with_connection_for_role(
            "vault.lock",
            serde_json::json!({}),
            650,
            None,
            PeerRole::Companion,
        );
        drop(client);
        let (version, result) = lock.handle_connected_request(
            request,
            Instant::now(),
            ClientConnection::Socket(server.as_fd()),
        );
        assert_eq!(version, 650);
        assert_handler_error(result, ErrorToken::IoFailed);
        assert_eq!(
            lock.snapshot().availability,
            available(
                VaultState::Unlocked,
                Some("KA-0123456789abcdef01234567".to_owned())
            )
        );
        assert!(lock_worker.lock().expect("worker trace").calls.is_empty());
        assert_eq!(lock_runtime.lock().expect("runtime trace").arms, 0);
    }

    #[test]
    fn status_winning_after_peer_close_cannot_be_followed_by_late_dispatch() {
        let (supervisor, runtime, worker, _, _) =
            fake_supervisor(service_state(655, VaultState::Locked), [], true);
        let (unlock_request, unlock_client, unlock_server) = connected_unlock_request(655);
        drop(unlock_client);
        let (status_request, status_client, status_server) =
            validated_request_with_connection_for_role(
                "vault.status",
                serde_json::json!({}),
                655,
                None,
                PeerRole::Companion,
            );
        let (release_mutation_tx, release_mutation_rx) = mpsc::sync_channel(0);
        let running = Arc::clone(&supervisor);
        let mutation = thread::spawn(move || {
            release_mutation_rx.recv().expect("release mutation");
            running.handle_connected_request(
                unlock_request,
                Instant::now(),
                ClientConnection::Socket(unlock_server.as_fd()),
            )
        });
        let running = Arc::clone(&supervisor);
        let (status_tx, status_rx) = mpsc::channel();
        let status = thread::spawn(move || {
            let result = running.handle_connected_request(
                status_request,
                Instant::now(),
                ClientConnection::Socket(status_server.as_fd()),
            );
            status_tx.send(result).expect("status result");
            drop(status_client);
        });
        let (version, result) = status_rx
            .recv_timeout(Duration::from_secs(1))
            .expect("source status wins");
        assert_eq!(version, 655);
        assert_handler_status(result, VaultState::Locked, None);
        release_mutation_tx.send(()).expect("release old request");
        let (version, result) = mutation.join().expect("closed-peer mutation");
        status.join().expect("source status");
        assert_eq!(version, 655);
        assert_handler_error(result, ErrorToken::IoFailed);
        assert!(worker.lock().expect("worker trace").calls.is_empty());
        assert_eq!(runtime.lock().expect("runtime trace").arms, 0);
        assert_eq!(
            supervisor.snapshot().availability,
            available(VaultState::Locked, None)
        );

        let device_id = "KA-0123456789abcdef01234567".to_owned();
        let (mutation_wins, _, worker, _, _) = fake_supervisor(
            service_state(680, VaultState::Locked),
            [Ok(internal_wire::WorkerResponse::unlocked(
                1,
                device_id.clone(),
            ))],
            true,
        );
        let (entered_tx, entered_rx) = mpsc::sync_channel(0);
        let (release_tx, release_rx) = mpsc::sync_channel(0);
        worker.lock().expect("worker fixture").block_unlock = Some((entered_tx, release_rx));
        let (request, mutation_client, mutation_server) = connected_unlock_request(680);
        let running = Arc::clone(&mutation_wins);
        let mutation = thread::spawn(move || {
            let result = running.handle_connected_request(
                request,
                Instant::now(),
                ClientConnection::Socket(mutation_server.as_fd()),
            );
            drop(mutation_client);
            result
        });
        entered_rx
            .recv_timeout(Duration::from_secs(1))
            .expect("mutation reached worker");
        let (request, status_client, status_server) = validated_request_with_connection_for_role(
            "vault.status",
            serde_json::json!({}),
            681,
            None,
            PeerRole::Companion,
        );
        let (version, result) = mutation_wins.handle_connected_request(
            request,
            Instant::now(),
            ClientConnection::Socket(status_server.as_fd()),
        );
        drop(status_client);
        assert_eq!(version, 681);
        assert_handler_status(result, VaultState::Unlocking, None);
        release_tx.send(()).expect("release worker");
        let (version, result) = mutation.join().expect("winning mutation");
        assert_eq!(version, 682);
        assert_handler_status(result, VaultState::Unlocked, Some(&device_id));
        assert_eq!(
            worker.lock().expect("worker trace").calls,
            [internal_wire::WorkerCommandKind::Unlock]
        );
    }

    #[test]
    fn blocking_liveness_probe_linearizes_begin_before_status_snapshot() {
        let device_id = "KA-0123456789abcdef01234567".to_owned();
        let (supervisor, _, worker, _, _) = fake_supervisor(
            service_state(690, VaultState::Locked),
            [Ok(internal_wire::WorkerResponse::unlocked(
                1,
                device_id.clone(),
            ))],
            true,
        );
        let (worker_entered_tx, worker_entered_rx) = mpsc::sync_channel(0);
        let (worker_release_tx, worker_release_rx) = mpsc::sync_channel(0);
        worker.lock().expect("worker fixture").block_unlock =
            Some((worker_entered_tx, worker_release_rx));
        let (liveness_entered_tx, liveness_entered_rx) = mpsc::sync_channel(0);
        let (liveness_release_tx, liveness_release_rx) = mpsc::sync_channel(0);
        let liveness = Arc::new(BlockingClientLiveness {
            entered: liveness_entered_tx,
            release: Mutex::new(liveness_release_rx),
            blocked: AtomicBool::new(false),
            live: AtomicBool::new(true),
        });
        let (request, _) = unlock_request(690, b"TEST_ONLY_12", false);
        let running = Arc::clone(&supervisor);
        let mutation = thread::spawn(move || {
            running.handle_connected_request(
                request,
                Instant::now(),
                ClientConnection::BlockingLive(liveness),
            )
        });
        liveness_entered_rx
            .recv_timeout(Duration::from_secs(1))
            .expect("begin liveness barrier");

        let status_request = validated_request("vault.status", serde_json::json!({}), 0, None);
        let running = Arc::clone(&supervisor);
        let (status_tx, status_rx) = mpsc::channel();
        let status = thread::spawn(move || {
            status_tx
                .send(running.handle_request(status_request, Instant::now()))
                .expect("status result");
        });
        assert!(
            matches!(
                status_rx.recv_timeout(Duration::from_millis(50)),
                Err(mpsc::RecvTimeoutError::Timeout)
            ),
            "status must not observe Locked while begin owns lifecycle"
        );
        liveness_release_tx.send(()).expect("release liveness");
        worker_entered_rx
            .recv_timeout(Duration::from_secs(1))
            .expect("mutation dispatched");
        let (version, result) = status_rx
            .recv_timeout(Duration::from_secs(1))
            .expect("post-linearization status");
        assert_eq!(version, 691);
        assert_handler_status(result, VaultState::Unlocking, None);
        worker_release_tx.send(()).expect("release worker");
        let (version, result) = mutation.join().expect("mutation");
        status.join().expect("status");
        assert_eq!(version, 692);
        assert_handler_status(result, VaultState::Unlocked, Some(&device_id));
    }

    #[test]
    fn peer_close_pre_arm_rolls_back_but_post_arm_faults() {
        let (mut pre_arm, pre_runtime, pre_worker, _, _) =
            fake_supervisor(service_state(660, VaultState::Locked), [], true);
        let (entered_tx, entered_rx) = mpsc::sync_channel(0);
        let (release_tx, release_rx) = mpsc::sync_channel(0);
        Arc::get_mut(&mut pre_arm)
            .expect("exclusive supervisor")
            .privacy = Arc::new(BlockingPrivacy {
            calls: AtomicUsize::new(0),
            block_on: 2,
            entered: entered_tx,
            release: Mutex::new(release_rx),
        });
        let (request, client, server) = connected_unlock_request(660);
        let running = Arc::clone(&pre_arm);
        let (result_tx, result_rx) = mpsc::channel();
        let handler = thread::spawn(move || {
            let (version, result) = running.handle_connected_request(
                request,
                Instant::now(),
                ClientConnection::Socket(server.as_fd()),
            );
            result_tx
                .send((
                    version,
                    matches!(result, HandlerResult::Error(_, ErrorToken::IoFailed)),
                ))
                .expect("pre-arm result");
        });
        entered_rx
            .recv_timeout(Duration::from_secs(1))
            .expect("pre-arm privacy barrier");
        drop(client);
        release_tx.send(()).expect("release pre-arm privacy");
        assert_eq!(
            result_rx.recv_timeout(Duration::from_secs(1)),
            Ok((662, true))
        );
        handler.join().expect("pre-arm handler");
        assert!(pre_worker.lock().expect("worker trace").calls.is_empty());
        assert_eq!(
            (
                pre_runtime.lock().expect("runtime trace").arms,
                pre_arm.snapshot().availability
            ),
            (0, available(VaultState::Locked, None))
        );

        let (post_arm, runtime, worker, _, trace) =
            fake_supervisor(service_state(670, VaultState::Locked), [], true);
        let (entered_tx, entered_rx) = mpsc::sync_channel(0);
        let (release_tx, release_rx) = mpsc::sync_channel(0);
        *post_arm.runtime.lock().expect("runtime boundary") = Box::new(StopDuringFirstArmRuntime {
            state: Arc::clone(&runtime),
            trace: Arc::clone(&trace),
            entered: entered_tx,
            release: Some(release_rx),
        });
        let (request, client, server) = connected_unlock_request(670);
        let running = Arc::clone(&post_arm);
        let (result_tx, result_rx) = mpsc::channel();
        let handler = thread::spawn(move || {
            let (version, result) = running.handle_connected_request(
                request,
                Instant::now(),
                ClientConnection::Socket(server.as_fd()),
            );
            result_tx
                .send((
                    version,
                    matches!(result, HandlerResult::Error(_, ErrorToken::RebootRequired)),
                ))
                .expect("post-arm result");
        });
        entered_rx
            .recv_timeout(Duration::from_secs(1))
            .expect("marker arm barrier");
        drop(client);
        release_tx.send(()).expect("release marker arm");
        assert_eq!(
            result_rx.recv_timeout(Duration::from_secs(1)),
            Ok((672, true))
        );
        handler.join().expect("post-arm handler");
        assert!(worker.lock().expect("worker trace").calls.is_empty());
        assert!(runtime.lock().expect("runtime trace").marker);
        assert_eq!(post_arm.snapshot().availability, faulted_availability());
    }

    #[test]
    fn peer_pidfd_startup_probe_matches_shipping_seqpacket_mechanism() {
        peer_pidfd_capability_probe().expect("SO_PEERPIDFD seqpacket probe");
    }

    #[test]
    fn narrowed_signal_waiter_survives_first_stop_through_startup_attestation() {
        let mut signals = SigSet::empty();
        signals.add(Signal::SIGUSR1);
        signals.thread_block().expect("block test signal");
        let stop = StopControl::new();
        let keep_running = Arc::new(AtomicBool::new(true));
        let keep = Arc::clone(&keep_running);
        let waiter_stop = stop.clone();
        let waiter = thread::spawn(move || {
            run_signal_waiter(signals, waiter_stop, || keep.load(Ordering::Acquire));
        });
        nix::sys::pthread::pthread_kill(waiter.as_pthread_t(), Signal::SIGUSR1)
            .expect("first test signal");
        let deadline = Instant::now() + Duration::from_secs(1);
        while !stop.requested.load(Ordering::Acquire) {
            assert!(
                Instant::now() < deadline,
                "signal waiter did not request stop"
            );
            thread::sleep(Duration::from_millis(10));
        }
        assert!(
            !waiter.is_finished(),
            "the narrowed task must remain attestable after the first stop signal"
        );
        keep_running.store(false, Ordering::Release);
        nix::sys::pthread::pthread_kill(waiter.as_pthread_t(), Signal::SIGUSR1)
            .expect("wake test waiter for cleanup");
        waiter.join().expect("test signal waiter");
        signals.thread_unblock().expect("unblock test signal");
    }

    #[test]
    fn lock_waits_for_output_finalization_before_worker_return() {
        assert_lock_waits_for_output_finalization(OutputBarrierPhase::PreWorker);
    }

    #[test]
    fn lock_waits_for_worker_returned_output_before_adoption_and_finish() {
        assert_lock_waits_for_output_finalization(OutputBarrierPhase::WorkerReturnedPreAdopt);
    }

    #[test]
    fn lock_waits_for_ready_output_before_scm_rights_handoff() {
        assert_lock_waits_for_output_finalization(OutputBarrierPhase::ReadyPreScm);
    }

    #[test]
    fn lock_waits_for_local_output_drop_after_successful_scm_rights_handoff() {
        assert_lock_waits_for_output_finalization(OutputBarrierPhase::PostScmPreLocalDrop);
    }

    #[test]
    fn output_finalization_timeout_faults_and_kills_worker_without_disarm() {
        let mut unlocked = service_state(40, VaultState::Unlocked);
        unlocked.availability = available(
            VaultState::Unlocked,
            Some("KA-0123456789abcdef01234567".to_owned()),
        );
        let (supervisor, runtime, worker, _, trace) = fake_supervisor(unlocked, [], true);
        let (mut output, raw_output, mut child) = install_output_obligated_lease(&supervisor);
        output.adopt(raw_output).expect("worker output adoption");
        assert_eq!(
            supervisor.revoke_provider_lease(1, Instant::now() + Duration::from_millis(100)),
            Err(RescueVaultDaemonError::ShutdownFailed)
        );
        let containment = supervisor.mark_fault_by(Instant::now() + Duration::from_millis(100));
        assert!(containment.marker_durable);
        assert!(!containment.worker_quiesced);
        assert!(supervisor.stopping.load(Ordering::Acquire));
        assert_eq!(worker.lock().expect("worker trace").faults, 1);
        assert_eq!(runtime.lock().expect("runtime trace").disarms, 0);
        assert!(
            !trace
                .lock()
                .expect("effect trace")
                .contains(&TraceEvent::WorkerLock)
        );
        assert!(matches!(
            supervisor
                .leases
                .lock()
                .expect("lease registry")
                .active
                .as_ref(),
            Some(lease) if lease.state == LeaseState::Revoking
        ));

        drop(output);
        supervisor
            .revoke_active_lease(Instant::now() + Duration::from_secs(1))
            .expect("cleanup finalized lease");
        let _ = child.wait();
        assert!(
            supervisor
                .leases
                .lock()
                .expect("lease registry")
                .active
                .is_none()
        );
    }

    #[test]
    fn stop_revoker_winning_pending_borrow_remains_a_clean_no_secret_shutdown() {
        let mut unlocked = service_state(45, VaultState::Unlocked);
        unlocked.availability = available(
            VaultState::Unlocked,
            Some("KA-0123456789abcdef01234567".to_owned()),
        );
        let (supervisor, runtime, worker, privacy, _) = fake_supervisor(unlocked, [], true);
        let (output, raw_output, mut child) = install_output_obligated_lease(&supervisor);
        drop(raw_output);
        drop(output);
        supervisor
            .leases
            .lock()
            .expect("lease registry")
            .active
            .as_mut()
            .expect("active lease")
            .state = LeaseState::Pending;
        supervisor.stopping.store(true, Ordering::Release);
        supervisor
            .revoke_active_lease(Instant::now() + Duration::from_secs(1))
            .expect("stop wins Pending revocation");
        let _ = child.wait();

        assert!(matches!(
            supervisor.provider_borrow_dispatch_ready(1, &ClientConnection::AssumedLive),
            Ok(ProviderDispatchArm::RevocationInProgress)
        ));
        assert!(matches!(
            supervisor.mark_lease_potentially_issued(1),
            Ok(PotentialIssue::RevocationInProgress)
        ));
        assert!(worker.lock().expect("worker trace").calls.is_empty());
        assert_eq!(privacy.checks.load(Ordering::Acquire), 0);
        assert!(!supervisor.faulted.load(Ordering::Acquire));
        {
            let mut runtime = runtime.lock().expect("runtime trace");
            runtime.marker = true;
        }
        supervisor
            .shutdown(Instant::now() + Duration::from_secs(1))
            .expect("clean shutdown after Pending revoke");
        let runtime = runtime.lock().expect("runtime trace");
        assert_eq!((runtime.disarms, runtime.marker), (1, false));
        let worker = worker.lock().expect("worker trace");
        assert_eq!((worker.shutdowns, worker.faults), (1, 0));
    }

    #[test]
    fn every_lease_has_a_latch_and_false_issued_or_revoking_latches_block_removal() {
        let mut unlocked = service_state(50, VaultState::Unlocked);
        unlocked.availability = available(
            VaultState::Unlocked,
            Some("KA-0123456789abcdef01234567".to_owned()),
        );
        let (supervisor, _, _, _, _) = fake_supervisor(unlocked, [], true);
        let (pending_peer, pending_server) = socketpair(
            AddressFamily::UNIX,
            SocketType::SEQPACKET,
            SocketFlags::CLOEXEC | SocketFlags::NONBLOCK,
            None,
        )
        .expect("pending lease socketpair");
        let pending_connection = ClientConnection::LeaseTestSocket(pending_server.as_fd());
        let pending_candidate = pending_connection
            .lease_candidate(ProcessScope::CgroupTree)
            .expect("pending lease candidate");
        assert_eq!(pending_candidate.process.scope(), ProcessScope::DirectPeer);
        let (_, pending_id) = supervisor
            .begin_provider_borrow(
                50,
                &pending_connection,
                pending_candidate,
                Instant::now() + PROVIDER_BORROW_TIMEOUT,
            )
            .expect("pending lease");
        assert!(matches!(
            supervisor
                .leases
                .lock()
                .expect("lease registry")
                .active
                .as_ref(),
            Some(lease)
                if lease.state == LeaseState::Pending
                    && lease.output_obligation.finalized.load(Ordering::Acquire)
        ));
        supervisor
            .cancel_pending_lease(pending_id)
            .expect("cancel definite-no-secret pending lease");
        drop(pending_peer);
        drop(pending_server);
        let (socket, _peer) = socketpair(
            AddressFamily::UNIX,
            SocketType::SEQPACKET,
            SocketFlags::CLOEXEC | SocketFlags::NONBLOCK,
            None,
        )
        .expect("lease socketpair");
        let (pidfd, _writer) = pipe_with(PipeFlags::CLOEXEC).expect("placeholder pidfd");
        let output_obligation = Arc::new(LeaseOutputState {
            finalized: AtomicBool::new(false),
        });
        supervisor.leases.lock().expect("lease registry").active = Some(ProviderLease {
            id: 1,
            socket,
            pidfd,
            peer_pid: rustix::process::getpid().as_raw_pid(),
            process: direct_peer_boundary(),
            state: LeaseState::Established,
            handoff_deadline: Instant::now() + PROVIDER_BORROW_TIMEOUT,
            lease_deadline: Some(Instant::now() + PROVIDER_LEASE_TIMEOUT),
            output_obligation,
        });
        assert_eq!(
            supervisor.complete_normal_lease(1),
            Err(RescueVaultDaemonError::PersistentFault)
        );
        assert!(
            supervisor
                .leases
                .lock()
                .expect("lease registry")
                .active
                .is_some()
        );
        supervisor
            .leases
            .lock()
            .expect("lease registry")
            .active
            .as_mut()
            .expect("active lease")
            .state = LeaseState::Revoking;
        assert_eq!(supervisor.complete_normal_lease(1), Ok(()));
        assert!(
            supervisor
                .leases
                .lock()
                .expect("lease registry")
                .active
                .is_some(),
            "a Revoking lease is removed only by four-factor revocation"
        );
    }

    #[test]
    fn lease_release_requires_full_hup_not_only_peer_write_half_close() {
        let (observer, client) = socketpair(
            AddressFamily::UNIX,
            SocketType::SEQPACKET,
            SocketFlags::CLOEXEC | SocketFlags::NONBLOCK,
            None,
        )
        .expect("lease socketpair");
        let mut child = Command::new("/bin/sh")
            .args(["-c", "sleep 0.05"])
            .spawn()
            .expect("short child");
        let pid = Pid::from_raw(i32::try_from(child.id()).expect("child pid range"))
            .expect("nonzero child pid");
        let pidfd = pidfd_open(pid, PidfdFlags::NONBLOCK).expect("test pidfd");
        shutdown(&client, Shutdown::Write).expect("peer write-half close");
        child.wait().expect("child exit");
        let first_deadline = Instant::now() + Duration::from_millis(100);
        let snapshot = LeaseSnapshot {
            id: 1,
            socket: observer,
            pidfd,
            process: direct_peer_boundary(),
            deadline: first_deadline,
            output_obligation: Arc::new(LeaseOutputState {
                finalized: AtomicBool::new(true),
            }),
        };
        assert_eq!(
            wait_for_lease_evidence(&snapshot, first_deadline),
            Ok(LeaseWait::Deadline),
            "RDHUP plus pidfd exit must not release a still-open peer descriptor"
        );
        drop(client);
        let final_deadline = Instant::now() + Duration::from_secs(1);
        assert_eq!(
            wait_for_lease_evidence(&snapshot, final_deadline),
            Ok(LeaseWait::Released)
        );
    }

    #[test]
    fn lease_release_requires_socket_pid_output_and_whole_tree_quiescence() {
        assert!(lease_release_evidence_is_complete(true, true, true, true));
        for incomplete in [
            (false, true, true, true),
            (true, false, true, true),
            (true, true, false, true),
            // The authenticated peer may have exited while an inherited-key
            // descendant still populates the delegated service tree.
            (true, true, true, false),
        ] {
            assert!(!lease_release_evidence_is_complete(
                incomplete.0,
                incomplete.1,
                incomplete.2,
                incomplete.3
            ));
        }
    }
}
