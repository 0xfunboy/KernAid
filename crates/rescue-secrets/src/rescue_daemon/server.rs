use super::{
    RescueVaultDaemonError, enforce_process_privacy, internal_wire, passwd_has_exact_companion,
    runtime::{DaemonRuntime, RuntimeDisposition, WorkerCgroup, WorkerHandle, WorkerSpawnResult},
    validate_no_active_swap,
};
use kernaid_protocol::rescue_vault::{
    ErrorToken, MAX_INITIAL_STATE_VERSION, MAX_SAFE_JSON_INTEGER, Operation, PeerAllowlist,
    RequestDecodeError, RequestPayload, ServerReceiveError, SuccessPayload, ValidatedRequest,
    VaultState, VaultStatusPayload, authenticate_seqpacket_peer, gate_operation_for_vault_state,
    validate_passphrase_read,
};
use nix::sys::signal::{SigSet, Signal};
use rand_core::{OsRng, RngCore};
use rustix::{
    event::{PollFd, PollFlags, Timespec, poll},
    fd::{AsFd, BorrowedFd, OwnedFd},
    fs::{self as rfs, FileType, OFlags},
    net::{
        AddressFamily, RecvFlags, SendFlags, SocketAddrUnix, SocketFlags, SocketType, accept_with,
        recv, sendto, socket_with,
    },
    pipe::{PipeFlags, pipe_with},
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
    faulted: AtomicBool,
    stopping: Arc<AtomicBool>,
    stop_deadline: Arc<Mutex<Option<Instant>>>,
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
        passphrase: Option<BorrowedFd<'_>>,
        deadline: Instant,
    ) -> Result<internal_wire::WorkerResponse, RescueVaultDaemonError>;
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
        passphrase: Option<BorrowedFd<'_>>,
        deadline: Instant,
    ) -> Result<internal_wire::WorkerResponse, RescueVaultDaemonError> {
        WorkerHandle::transact(self, kind, passphrase_size, passphrase, deadline)
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
    spawn_signal_waiter(signal_set, stop.clone());
    validate_companion_identity(companion_uid)?;
    let allowlist = PeerAllowlist::companion_only(companion_uid)
        .map_err(|_| RescueVaultDaemonError::InvalidConfiguration)?;
    let listener = take_listener()?;
    let (runtime, disposition) = DaemonRuntime::open()?;
    let seed = state_version_seed()?;

    let (worker, availability, startup_fault, untracked_worker_may_remain) = match disposition {
        RuntimeDisposition::PersistentFault => (None, faulted_availability(), true, false),
        RuntimeDisposition::Ready => match start_worker(&stop) {
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
    let supervisor = Arc::new(Supervisor {
        state: Mutex::new(ServiceState {
            version: seed,
            availability,
            transition_origin: None,
            last_unlock_attempt: None,
            faulted: startup_fault,
            fault_marker_required: startup_fault,
            marker_persistence_failed: false,
            clean_fault_shutdown: false,
        }),
        lifecycle: Mutex::new(()),
        runtime: Mutex::new(Box::new(runtime)),
        worker: worker.map(|worker| -> Arc<dyn WorkerBoundary> { worker }),
        privacy: Arc::new(ProcPrivacyBoundary),
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

fn start_worker(stop: &StopControl) -> WorkerStartup {
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
    let startup_deadline = Instant::now() + WORKER_OPERATION_TIMEOUT;
    let worker = match WorkerHandle::spawn(cgroup, startup_deadline, &stop.requested) {
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
    if stop.requested.load(Ordering::Acquire) {
        return cancel_startup_worker(worker, stop);
    }
    let response = worker.transact_cancellable(
        internal_wire::WorkerCommandKind::Probe,
        None,
        None,
        startup_deadline,
        Some(&stop.requested),
    );
    if stop.requested.load(Ordering::Acquire) {
        return cancel_startup_worker(worker, stop);
    }
    match response {
        Ok(response) => match probe_availability(response.code) {
            Ok(availability) => WorkerStartup::Ready {
                worker,
                availability,
            },
            Err(()) => {
                let _ = worker.fault_and_terminate(startup_deadline);
                WorkerStartup::Faulted {
                    worker: Some(worker),
                    untracked_worker_may_remain: false,
                }
            }
        },
        Err(_) => {
            let _ = worker.fault_and_terminate(startup_deadline);
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

fn validate_companion_identity(expected_uid: u32) -> Result<(), RescueVaultDaemonError> {
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
        || stat.st_nlink != 1
        || stat.st_mode & 0o022 != 0
    {
        return Err(RescueVaultDaemonError::InvalidConfiguration);
    }
    let bytes = read_file_bounded(descriptor.as_fd(), GROUP_FILE_LIMIT)?;
    if !passwd_has_exact_companion(&bytes, expected_uid) {
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

fn spawn_signal_waiter(signals: SigSet, stop: StopControl) {
    thread::spawn(move || {
        if signals.wait().is_ok() {
            stop.request();
        }
    });
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
    while !stop.requested.load(Ordering::Acquire) {
        reap_handlers(&mut handlers, &supervisor);
        if let Some(worker) = supervisor.worker.as_ref()
            && !supervisor.faulted.load(Ordering::Acquire)
            && worker.exited()?
        {
            supervisor.mark_fault();
        }
        wait_listener(listener.as_fd())?;
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
                    supervisor.mark_fault();
                    return Err(RescueVaultDaemonError::InvalidListener);
                }
            }
        }
    }
    let deadline = stop.deadline_or(Instant::now() + SHUTDOWN_TIMEOUT);
    while !handlers.is_empty() {
        reap_handlers(&mut handlers, &supervisor);
        if !handlers.is_empty() && Instant::now() >= deadline {
            supervisor.mark_fault();
            return Err(RescueVaultDaemonError::ShutdownFailed);
        }
        if !handlers.is_empty() {
            thread::sleep(Duration::from_millis(10));
        }
    }
    Ok(deadline)
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
    if supervisor.stopping.load(Ordering::Acquire) {
        return;
    }
    if validate_accepted_connection(connection.as_fd()).is_err() {
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
        Operation::VaultUnlock | Operation::VaultLock
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
        HandlerResult::Error(request, error) => {
            let _ = peer.send_error(&request, version, error, send_deadline);
        }
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
    Error(ValidatedRequest, ErrorToken),
}

enum DispatchArm {
    Armed,
    StoppedBeforeArm,
    StoppedAfterArm,
    ClientGoneBeforeArm,
    ClientGoneAfterArm,
}

enum ClientConnection<'socket> {
    Socket(BorrowedFd<'socket>),
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
            Self::AssumedLive => true,
            #[cfg(test)]
            Self::BlockingLive(liveness) => liveness.is_live(),
        }
    }
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
        if !external_operation_is_enabled(operation) {
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
            Some(internal_pipe.as_fd()),
            operation_deadline,
        );
        drop(internal_pipe);
        match response {
            Ok(response) => self.finish_unlock(request, response, operation_deadline),
            Err(_) => {
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
        if let Err((version, error)) = self.begin_lock(request.expected_state_version(), connection)
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
            Ok(response) if response.code == internal_wire::WorkerResultCode::LockSucceeded => {
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
        begin_lock_state(&mut state, expected, self.stopping.load(Ordering::Acquire))
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
        if response.code != internal_wire::WorkerResultCode::AttestLocked
            || response.device_id.is_some()
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
        let faulted = self.faulted.load(Ordering::Acquire);
        let coherent = faulted == state.faulted
            && state.transition_origin.is_none()
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
        let worker_quiesced = self
            .worker
            .as_ref()
            .is_none_or(|worker| worker.fault_and_terminate(deadline).is_ok());
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
        if state.marker_persistence_failed {
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

fn external_operation_is_enabled(operation: Operation) -> bool {
    matches!(
        operation,
        Operation::VaultStatus | Operation::VaultUnlock | Operation::VaultLock
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

fn validate_completion(state: &ServiceState, expected: VaultState) -> Result<(), ()> {
    if state.faulted
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
            AddressFamily, SendAncillaryBuffer, SendAncillaryMessage, SendFlags, SocketFlags,
            SocketType, bind, send, sendmsg, socket_with, socketpair,
        },
        pipe::{PipeFlags, pipe_with},
    };
    use std::{
        collections::VecDeque,
        ffi::OsString,
        io::IoSlice,
        mem::MaybeUninit,
        os::unix::ffi::OsStringExt,
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
            passphrase: Option<BorrowedFd<'_>>,
            _deadline: Instant,
        ) -> Result<internal_wire::WorkerResponse, RescueVaultDaemonError> {
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
                    match rustix::io::read(passphrase, &mut buffer[..]) {
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
            drop(state);
            if let Some((entered, release)) = block {
                entered
                    .send(())
                    .map_err(|_| RescueVaultDaemonError::WorkerUnavailable)?;
                release
                    .recv()
                    .map_err(|_| RescueVaultDaemonError::WorkerUnavailable)?;
            }
            response
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
            faulted: AtomicBool::new(false),
            stopping: Arc::new(AtomicBool::new(false)),
            stop_deadline: Arc::new(Mutex::new(None)),
        });
        (supervisor, runtime, worker, privacy, trace)
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
        let (companion_uid, agent_uid) = match role {
            PeerRole::Companion => (uid, other_uid),
            PeerRole::Agent => (other_uid, uid),
        };
        let peer = authenticate_seqpacket_peer(
            server.as_fd(),
            PeerAllowlist::new(companion_uid, agent_uid).expect("test allowlist"),
        )
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

    fn service_state(version: u64, vault: VaultState) -> ServiceState {
        ServiceState {
            version,
            availability: available(vault, None),
            transition_origin: None,
            last_unlock_attempt: None,
            faulted: false,
            fault_marker_required: false,
            marker_persistence_failed: false,
            clean_fault_shutdown: false,
        }
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
    fn supervisor_rejects_all_non_lifecycle_requests_in_every_state_without_effects() {
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
            let (supervisor, runtime, worker, _, _) = fake_supervisor(initial, [], true);
            let (configure, configure_writer) = descriptor_request(
                "provider.openai.configure",
                serde_json::json!({
                    "input": {"type": "openai-api-key-pipe", "size": 1}
                }),
                60,
                PeerRole::Companion,
                b"K",
            );
            let (persist, persist_writer) = descriptor_request(
                "report.persist",
                serde_json::json!({
                    "reportId": "RP-00000000-0000-0000-0000-000000000001",
                    "payloadSha256": "0".repeat(64),
                    "input": {"type": "session-report-json-pipe", "size": 2}
                }),
                60,
                PeerRole::Agent,
                b"{}",
            );
            let requests = [
                (configure, Some(configure_writer)),
                (
                    validated_request("provider.status", serde_json::json!({}), 60, None),
                    None,
                ),
                (
                    validated_request(
                        "provider.logout",
                        serde_json::json!({"provider": "openai"}),
                        60,
                        None,
                    ),
                    None,
                ),
                (
                    validated_request_for_role(
                        "provider.openai.borrow",
                        serde_json::json!({}),
                        60,
                        None,
                        PeerRole::Agent,
                    ),
                    None,
                ),
                (
                    validated_request_for_role(
                        "provider.codex.home_lease",
                        serde_json::json!({}),
                        60,
                        None,
                        PeerRole::Agent,
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
                        PeerRole::Agent,
                    ),
                    None,
                ),
                (persist, Some(persist_writer)),
                (
                    validated_request("report.list", serde_json::json!({}), 60, None),
                    None,
                ),
                (
                    validated_request(
                        "report.get",
                        serde_json::json!({
                            "reportId": "RP-00000000-0000-0000-0000-000000000001"
                        }),
                        60,
                        None,
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
            assert_eq!(supervisor.snapshot().version, 60);
            assert!(worker.lock().expect("worker trace").calls.is_empty());
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
    fn only_three_external_operations_are_enabled_in_every_state() {
        let forbidden = [
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
        for vault in [
            VaultState::Absent,
            VaultState::Unprovisioned,
            VaultState::Locked,
            VaultState::Unlocking,
            VaultState::Unlocked,
            VaultState::Locking,
            VaultState::FaultedRebootRequired,
        ] {
            let state = service_state(700, vault);
            for operation in forbidden {
                assert!(!external_operation_is_enabled(operation));
                assert_eq!(state.version, 700);
            }
        }
        for operation in [
            Operation::VaultStatus,
            Operation::VaultUnlock,
            Operation::VaultLock,
        ] {
            assert!(external_operation_is_enabled(operation));
        }
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
                HandlerResult::Success(_, _) => None,
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
}
