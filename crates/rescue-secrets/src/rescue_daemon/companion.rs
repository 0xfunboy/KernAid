use super::{
    COMPANION_UID, RescueVaultCompanionError, enforce_process_privacy, passwd_has_exact_companion,
    remote_error_name, validate_no_active_swap,
};
use kernaid_protocol::{
    rescue_vault::{
        MAX_PASSPHRASE_BYTES, MIN_PASSPHRASE_BYTES, RequestId, SuccessPayload, VaultState,
    },
    rescue_vault_transport::{
        ClientExchangeError, ClientRequest, ClientRequestPayload, ClientResponse,
        ClientResponseOutcome, SeqpacketTransportError, authenticate_root_seqpacket_server,
    },
};
use nix::sys::signal::{SigSet, Signal};
use rand_core::{OsRng, RngCore};
use rustix::{
    event::{PollFd, PollFlags, Timespec, poll},
    fd::{AsFd, BorrowedFd, OwnedFd},
    fs::{self as rfs, FileType, Mode, OFlags, ResolveFlags},
    net::{AddressFamily, SocketAddrUnix, SocketFlags, SocketType, connect, socket_with},
    pipe::{PipeFlags, pipe_with},
    termios::{
        LocalModes, OptionalActions, QueueSelector, Termios, tcflush, tcgetattr, tcgetpgrp,
        tcsetattr,
    },
};
use std::{
    ffi::OsString,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    thread,
    time::{Duration, Instant},
};
use zeroize::Zeroizing;

const CONTROL_SOCKET: &str = "/run/kernaid-rescue-vault.sock";
const PASSWD_PATH: &str = "/etc/passwd";
const TTY_PATH: &str = "/dev/tty";
const CONNECT_TIMEOUT: Duration = Duration::from_secs(3);
const STATUS_TIMEOUT: Duration = Duration::from_secs(5);
const MUTATION_TIMEOUT: Duration = Duration::from_secs(610);
const TTY_POLL_SLICE: Duration = Duration::from_millis(100);
const RESPONSE_POLL_SLICE: Duration = Duration::from_millis(100);
const RECONCILIATION_RESERVE: Duration = Duration::from_secs(5);
const MAX_PASSWD_BYTES: usize = 1024 * 1024;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Command {
    Status,
    Unlock,
    Lock,
}

pub(super) fn run<I>(arguments: I) -> Result<(), RescueVaultCompanionError>
where
    I: IntoIterator<Item = OsString>,
{
    enforce_process_privacy().map_err(|()| RescueVaultCompanionError::TransportUnavailable)?;
    validate_shipping_identity(COMPANION_UID)?;
    let command = parse_command(arguments)?;
    let tty = open_tty()?;
    let interrupted = install_signal_waiter()?;
    let result = execute(command, tty.as_fd(), &interrupted);
    if let Err(error) = result {
        let _ = write_tty_error(tty.as_fd(), error);
        return Err(error);
    }
    Ok(())
}

fn parse_command<I>(arguments: I) -> Result<Command, RescueVaultCompanionError>
where
    I: IntoIterator<Item = OsString>,
{
    let mut arguments = arguments.into_iter();
    let command = match arguments.next().as_deref() {
        Some(value) if value == "status" => Command::Status,
        Some(value) if value == "unlock" => Command::Unlock,
        Some(value) if value == "lock" => Command::Lock,
        _ => return Err(RescueVaultCompanionError::InvalidCommand),
    };
    if arguments.next().is_some() {
        return Err(RescueVaultCompanionError::InvalidCommand);
    }
    Ok(command)
}

fn validate_shipping_identity(expected_uid: u32) -> Result<(), RescueVaultCompanionError> {
    if rustix::process::geteuid().as_raw() != expected_uid {
        return Err(RescueVaultCompanionError::TransportUnavailable);
    }
    let passwd = rfs::openat2(
        rfs::CWD,
        PASSWD_PATH,
        OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NOFOLLOW,
        Mode::empty(),
        ResolveFlags::NO_SYMLINKS | ResolveFlags::NO_MAGICLINKS,
    )
    .map_err(|_| RescueVaultCompanionError::TransportUnavailable)?;
    let stat = rfs::fstat(&passwd).map_err(|_| RescueVaultCompanionError::TransportUnavailable)?;
    if !FileType::from_raw_mode(stat.st_mode).is_file()
        || stat.st_uid != 0
        || stat.st_nlink != 1
        || stat.st_mode & 0o022 != 0
    {
        return Err(RescueVaultCompanionError::TransportUnavailable);
    }
    let bytes = read_bounded(passwd.as_fd(), MAX_PASSWD_BYTES)
        .map_err(|_| RescueVaultCompanionError::TransportUnavailable)?;
    if !passwd_has_exact_companion(&bytes, expected_uid) {
        return Err(RescueVaultCompanionError::TransportUnavailable);
    }
    Ok(())
}

fn open_tty() -> Result<OwnedFd, RescueVaultCompanionError> {
    let tty = rfs::openat2(
        rfs::CWD,
        TTY_PATH,
        OFlags::RDWR | OFlags::CLOEXEC | OFlags::NOFOLLOW | OFlags::NONBLOCK,
        Mode::empty(),
        ResolveFlags::NO_SYMLINKS | ResolveFlags::NO_MAGICLINKS,
    )
    .map_err(|_| RescueVaultCompanionError::TtyUnavailable)?;
    let stat = rfs::fstat(&tty).map_err(|_| RescueVaultCompanionError::TtyUnavailable)?;
    let flags =
        rustix::io::fcntl_getfd(&tty).map_err(|_| RescueVaultCompanionError::TtyUnavailable)?;
    if !FileType::from_raw_mode(stat.st_mode).is_char_device()
        || !flags.contains(rustix::io::FdFlags::CLOEXEC)
        || tcgetattr(&tty).is_err()
    {
        return Err(RescueVaultCompanionError::TtyUnavailable);
    }
    Ok(tty)
}

fn install_signal_waiter() -> Result<Arc<AtomicBool>, RescueVaultCompanionError> {
    let signals = companion_signal_set();
    signals
        .thread_block()
        .map_err(|_| RescueVaultCompanionError::Interrupted)?;
    let interrupted = Arc::new(AtomicBool::new(false));
    let observed = Arc::clone(&interrupted);
    thread::spawn(move || {
        if signals.wait().is_ok() {
            observed.store(true, Ordering::Release);
        }
    });
    Ok(interrupted)
}

fn companion_signal_set() -> SigSet {
    let mut signals = SigSet::empty();
    signals.add(Signal::SIGINT);
    signals.add(Signal::SIGTERM);
    signals.add(Signal::SIGHUP);
    signals.add(Signal::SIGQUIT);
    signals.add(Signal::SIGTSTP);
    signals.add(Signal::SIGTTIN);
    signals.add(Signal::SIGTTOU);
    signals
}

fn execute(
    command: Command,
    tty: BorrowedFd<'_>,
    interrupted: &AtomicBool,
) -> Result<(), RescueVaultCompanionError> {
    let status = exchange(
        ClientRequestPayload::VaultStatus,
        0,
        &[],
        STATUS_TIMEOUT,
        None,
        None,
    )?;
    if interrupted.load(Ordering::Acquire) {
        return Err(RescueVaultCompanionError::Interrupted);
    }
    if command == Command::Status {
        return display_response(tty, &status);
    }
    let state_version = status.state_version();
    let status_payload = match status.outcome() {
        ClientResponseOutcome::Success(SuccessPayload::VaultStatus(status)) => status,
        ClientResponseOutcome::Error(_) => return display_response(tty, &status),
        _ => return Err(RescueVaultCompanionError::ProtocolFailure),
    };
    if let Some(error) = mutation_source_error(command, status_payload.vault_state()) {
        display_response(tty, &status)?;
        return Err(RescueVaultCompanionError::Remote(error));
    }
    let response = match command {
        Command::Unlock => {
            let secret = read_secret_from_tty(tty, interrupted)?;
            let (read, write) = pipe_with(PipeFlags::CLOEXEC)
                .map_err(|_| RescueVaultCompanionError::TransportUnavailable)?;
            write_pipe_secret(write.as_fd(), &secret)
                .map_err(|_| RescueVaultCompanionError::TransportUnavailable)?;
            drop(write);
            let size = u64::try_from(secret.len())
                .map_err(|_| RescueVaultCompanionError::SecretInvalid)?;
            drop(secret);
            if interrupted.load(Ordering::Acquire) {
                return Err(RescueVaultCompanionError::Interrupted);
            }
            exchange(
                ClientRequestPayload::VaultUnlock {
                    passphrase_size: size,
                },
                state_version,
                &[read.as_fd()],
                MUTATION_TIMEOUT,
                Some(interrupted),
                Some((tty, VaultState::Unlocked, state_version)),
            )?
        }
        Command::Lock => exchange(
            ClientRequestPayload::VaultLock,
            state_version,
            &[],
            MUTATION_TIMEOUT,
            Some(interrupted),
            Some((tty, VaultState::Locked, state_version)),
        )?,
        Command::Status => return Err(RescueVaultCompanionError::InvalidCommand),
    };
    display_response(tty, &response)
}

fn mutation_source_error(
    command: Command,
    state: VaultState,
) -> Option<kernaid_protocol::rescue_vault::ErrorToken> {
    use kernaid_protocol::rescue_vault::ErrorToken;
    match (command, state) {
        (Command::Unlock, VaultState::Locked) | (Command::Lock, VaultState::Unlocked) => None,
        (_, VaultState::Absent) => Some(ErrorToken::Absent),
        (_, VaultState::Unprovisioned) => Some(ErrorToken::Unprovisioned),
        (Command::Lock, VaultState::Locked) => Some(ErrorToken::Locked),
        (Command::Unlock, VaultState::Unlocked)
        | (_, VaultState::Unlocking | VaultState::Locking) => Some(ErrorToken::Busy),
        (_, VaultState::FaultedRebootRequired) => Some(ErrorToken::RebootRequired),
        (Command::Status, _) => Some(ErrorToken::NotAuthorized),
    }
}

fn exchange(
    payload: ClientRequestPayload,
    state_version: u64,
    descriptors: &[BorrowedFd<'_>],
    timeout: Duration,
    before_send: Option<&AtomicBool>,
    reconciliation: Option<(BorrowedFd<'_>, VaultState, u64)>,
) -> Result<ClientResponse, RescueVaultCompanionError> {
    let aggregate_deadline = Instant::now()
        .checked_add(timeout)
        .ok_or(RescueVaultCompanionError::TransportUnavailable)?;
    let connect_deadline = Instant::now()
        .checked_add(CONNECT_TIMEOUT)
        .unwrap_or(aggregate_deadline)
        .min(aggregate_deadline);
    let socket = connect_control(connect_deadline)?;
    let disposition = {
        let server = authenticate_root_seqpacket_server(socket.as_fd())
            .map_err(|_| RescueVaultCompanionError::TransportUnavailable)?;
        let request = ClientRequest::new(fresh_request_id()?, state_version, payload)
            .map_err(|_| RescueVaultCompanionError::ProtocolFailure)?;
        let response_deadline = if reconciliation.is_some() {
            aggregate_deadline
                .checked_sub(RECONCILIATION_RESERVE)
                .filter(|deadline| *deadline > Instant::now())
                .unwrap_or(aggregate_deadline)
        } else {
            aggregate_deadline
        };
        if before_send.is_some_and(|interrupted| interrupted.load(Ordering::Acquire)) {
            return Err(RescueVaultCompanionError::Interrupted);
        }
        server
            .send_request(&request, descriptors, response_deadline)
            .map_err(map_client_exchange_error)?;
        receive_correlated_or_reconcile(
            response_deadline,
            before_send,
            reconciliation.is_some(),
            |slice| server.receive_response(&request, slice),
            |response| {
                if let Some((_, target, prior_version)) = reconciliation
                    && matches!(response.outcome(), ClientResponseOutcome::Success(_))
                    && !direct_mutation_success_is_exact(response, target, prior_version)
                {
                    return Err(RescueVaultCompanionError::ProtocolFailure);
                }
                Ok(())
            },
        )?
    };
    // The authenticated server capability borrows `socket`; close the owning
    // descriptor before a fresh status connection is opened after a genuine
    // unknown-outcome transport failure.
    drop(socket);
    match disposition {
        ReceiveDisposition::Response(response) => Ok(response),
        ReceiveDisposition::Reconcile(fallback) => {
            reconcile_unknown_mutation(reconciliation, fallback, aggregate_deadline)
        }
    }
}

enum ReceiveDisposition<T> {
    Response(T),
    Reconcile(RescueVaultCompanionError),
}

fn receive_correlated_or_reconcile<T>(
    response_deadline: Instant,
    interrupted: Option<&AtomicBool>,
    reconciliation_enabled: bool,
    mut receive: impl FnMut(Instant) -> Result<T, ClientExchangeError>,
    mut validate: impl FnMut(&T) -> Result<(), RescueVaultCompanionError>,
) -> Result<ReceiveDisposition<T>, RescueVaultCompanionError> {
    loop {
        let slice = Instant::now()
            .checked_add(RESPONSE_POLL_SLICE)
            .unwrap_or(response_deadline)
            .min(response_deadline);
        match receive(slice) {
            Ok(response) => {
                validate(&response)?;
                return Ok(ReceiveDisposition::Response(response));
            }
            Err(ClientExchangeError::Transport(SeqpacketTransportError::TimedOut))
                if slice < response_deadline =>
            {
                // A response already received above is authoritative. If a
                // signal wins this polling boundary, close this exact
                // connection and reconcile through fresh status requests;
                // server begin/pre-arm liveness gates prevent late dispatch.
                if interrupted.is_some_and(|flag| flag.load(Ordering::Acquire)) {
                    return Ok(ReceiveDisposition::Reconcile(
                        RescueVaultCompanionError::Interrupted,
                    ));
                }
            }
            Err(error)
                if reconciliation_enabled
                    && interrupted_receive_error_has_unknown_outcome(&error) =>
            {
                let fallback = if interrupted.is_some_and(|flag| flag.load(Ordering::Acquire)) {
                    RescueVaultCompanionError::Interrupted
                } else {
                    RescueVaultCompanionError::TransportUnavailable
                };
                return Ok(ReceiveDisposition::Reconcile(fallback));
            }
            Err(error) => return Err(map_client_exchange_error(error)),
        }
    }
}

fn interrupted_receive_error_has_unknown_outcome(error: &ClientExchangeError) -> bool {
    matches!(
        error,
        ClientExchangeError::Transport(
            SeqpacketTransportError::TimedOut
                | SeqpacketTransportError::IoFailed
                | SeqpacketTransportError::AmbiguousZeroByte
        )
    )
}

fn map_client_exchange_error(error: ClientExchangeError) -> RescueVaultCompanionError {
    match error {
        ClientExchangeError::Transport(
            SeqpacketTransportError::TimedOut | SeqpacketTransportError::IoFailed,
        ) => RescueVaultCompanionError::TransportUnavailable,
        ClientExchangeError::Transport(_) => RescueVaultCompanionError::ProtocolFailure,
        ClientExchangeError::Request(_) | ClientExchangeError::Response(_) => {
            RescueVaultCompanionError::ProtocolFailure
        }
    }
}

fn reconcile_unknown_mutation(
    reconciliation: Option<(BorrowedFd<'_>, VaultState, u64)>,
    fallback: RescueVaultCompanionError,
    deadline: Instant,
) -> Result<ClientResponse, RescueVaultCompanionError> {
    let Some((tty, target, prior_version)) = reconciliation else {
        return Err(RescueVaultCompanionError::ProtocolFailure);
    };
    let outcome = poll_reconciliation_until(
        deadline,
        |attempt| {
            exchange(
                ClientRequestPayload::VaultStatus,
                0,
                &[],
                attempt,
                None,
                None,
            )
        },
        |status| {
            if reconciled_mutation_target_is_authoritative(status, target, prior_version) {
                ReconciliationClass::Target
            } else if response_is_transitional(status) {
                ReconciliationClass::Transitional
            } else {
                ReconciliationClass::Terminal
            }
        },
        Instant::now,
        thread::sleep,
    )?;
    match outcome {
        ReconciliationPoll::Target(status) => return Ok(status),
        ReconciliationPoll::Terminal(status) => display_response(tty, &status)?,
        ReconciliationPoll::Expired(Some(status)) => display_response(tty, &status)?,
        ReconciliationPoll::Expired(None) => {}
    }
    Err(fallback)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ReconciliationClass {
    Target,
    Transitional,
    Terminal,
}

enum ReconciliationPoll<T> {
    Target(T),
    Terminal(T),
    Expired(Option<T>),
}

fn poll_reconciliation_until<T>(
    deadline: Instant,
    mut query: impl FnMut(Duration) -> Result<T, RescueVaultCompanionError>,
    mut classify: impl FnMut(&T) -> ReconciliationClass,
    mut now: impl FnMut() -> Instant,
    mut wait: impl FnMut(Duration),
) -> Result<ReconciliationPoll<T>, RescueVaultCompanionError> {
    let mut last_transitional = None;
    loop {
        let Some(remaining) = deadline.checked_duration_since(now()) else {
            return Ok(ReconciliationPoll::Expired(last_transitional));
        };
        if remaining.is_zero() {
            return Ok(ReconciliationPoll::Expired(last_transitional));
        }
        match query(remaining.min(STATUS_TIMEOUT)) {
            Ok(status) => match classify(&status) {
                ReconciliationClass::Target => return Ok(ReconciliationPoll::Target(status)),
                ReconciliationClass::Terminal => return Ok(ReconciliationPoll::Terminal(status)),
                ReconciliationClass::Transitional => last_transitional = Some(status),
            },
            Err(RescueVaultCompanionError::TransportUnavailable) => {}
            Err(error) => return Err(error),
        }
        let Some(remaining) = deadline.checked_duration_since(now()) else {
            return Ok(ReconciliationPoll::Expired(last_transitional));
        };
        if remaining.is_zero() {
            return Ok(ReconciliationPoll::Expired(last_transitional));
        }
        wait(RESPONSE_POLL_SLICE.min(remaining));
    }
}

fn response_is_transitional(response: &ClientResponse) -> bool {
    matches!(
        response.outcome(),
        ClientResponseOutcome::Success(SuccessPayload::VaultStatus(status))
            if matches!(status.vault_state(), VaultState::Unlocking | VaultState::Locking)
    )
}

fn direct_mutation_success_is_exact(
    response: &ClientResponse,
    target: VaultState,
    prior_version: u64,
) -> bool {
    direct_mutation_version_is_exact(response.state_version(), prior_version)
        && response_is_exact_mutation_target(response, target)
}

fn direct_mutation_version_is_exact(response_version: u64, prior_version: u64) -> bool {
    prior_version
        .checked_add(2)
        .is_some_and(|expected| response_version == expected)
}

fn reconciled_mutation_target_is_authoritative(
    response: &ClientResponse,
    target: VaultState,
    prior_version: u64,
) -> bool {
    reconciled_mutation_version_is_authoritative(response.state_version(), prior_version)
        && response_is_exact_mutation_target(response, target)
}

fn reconciled_mutation_version_is_authoritative(response_version: u64, prior_version: u64) -> bool {
    prior_version
        .checked_add(2)
        .is_some_and(|minimum| response_version >= minimum)
}

fn response_is_exact_mutation_target(response: &ClientResponse, target: VaultState) -> bool {
    let ClientResponseOutcome::Success(SuccessPayload::VaultStatus(status)) = response.outcome()
    else {
        return false;
    };
    if status.vault_state() != target {
        return false;
    }
    match target {
        VaultState::Unlocked => status.device_id().is_some(),
        VaultState::Locked => status.device_id().is_none(),
        _ => false,
    }
}

fn connect_control(deadline: Instant) -> Result<OwnedFd, RescueVaultCompanionError> {
    let socket = socket_with(
        AddressFamily::UNIX,
        SocketType::SEQPACKET,
        SocketFlags::CLOEXEC | SocketFlags::NONBLOCK,
        None,
    )
    .map_err(|_| RescueVaultCompanionError::TransportUnavailable)?;
    let address = SocketAddrUnix::new(CONTROL_SOCKET)
        .map_err(|_| RescueVaultCompanionError::TransportUnavailable)?;
    match connect(&socket, &address) {
        Ok(()) => {}
        Err(error) if error == rustix::io::Errno::INPROGRESS => {
            wait_socket(socket.as_fd(), PollFlags::OUT, deadline)?;
            rustix::net::sockopt::socket_error(&socket)
                .map_err(|_| RescueVaultCompanionError::TransportUnavailable)?
                .map_err(|_| RescueVaultCompanionError::TransportUnavailable)?;
        }
        Err(_) => return Err(RescueVaultCompanionError::TransportUnavailable),
    }
    Ok(socket)
}

fn fresh_request_id() -> Result<RequestId, RescueVaultCompanionError> {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut random = [0_u8; 16];
    OsRng
        .try_fill_bytes(&mut random)
        .map_err(|_| RescueVaultCompanionError::TransportUnavailable)?;
    let mut uuid = [b'0'; 38];
    uuid[..2].copy_from_slice(b"R-");
    let mut target = 2;
    for byte in &random {
        if matches!(target, 10 | 15 | 20 | 25) {
            uuid[target] = b'-';
            target += 1;
        }
        uuid[target] = HEX[usize::from(byte >> 4)];
        uuid[target + 1] = HEX[usize::from(byte & 0x0f)];
        target += 2;
    }
    let value =
        std::str::from_utf8(&uuid).map_err(|_| RescueVaultCompanionError::ProtocolFailure)?;
    RequestId::parse(value).map_err(|_| RescueVaultCompanionError::ProtocolFailure)
}

fn display_response(
    tty: BorrowedFd<'_>,
    response: &ClientResponse,
) -> Result<(), RescueVaultCompanionError> {
    let version = format!("stateVersion: {}\n", response.state_version());
    write_tty(tty, version.as_bytes())?;
    match response.outcome() {
        ClientResponseOutcome::Error(error) => Err(RescueVaultCompanionError::Remote(*error)),
        ClientResponseOutcome::Success(SuccessPayload::VaultStatus(status)) => {
            let state = match status.vault_state() {
                VaultState::Absent => "absent",
                VaultState::Unprovisioned => "unprovisioned",
                VaultState::Locked => "locked",
                VaultState::Unlocking => "unlocking",
                VaultState::Unlocked => "unlocked",
                VaultState::Locking => "locking",
                VaultState::FaultedRebootRequired => "faulted-reboot-required",
            };
            let line = format!("vaultState: {state}\n");
            write_tty(tty, line.as_bytes())?;
            if let Some(device_id) = status.device_id() {
                write_tty(tty, b"deviceId: ")?;
                write_tty(tty, device_id.as_bytes())?;
                write_tty(tty, b"\n")?;
            }
            Ok(())
        }
        _ => Err(RescueVaultCompanionError::ProtocolFailure),
    }
}

fn write_tty_error(
    tty: BorrowedFd<'_>,
    error: RescueVaultCompanionError,
) -> Result<(), RescueVaultCompanionError> {
    let token = match error {
        RescueVaultCompanionError::Remote(error) => remote_error_name(error),
        RescueVaultCompanionError::Interrupted => "INTERRUPTED",
        RescueVaultCompanionError::InvalidCommand => "INVALID_COMMAND",
        RescueVaultCompanionError::TtyUnavailable => "TTY_UNAVAILABLE",
        RescueVaultCompanionError::EchoControlFailed => "ECHO_CONTROL_FAILED",
        RescueVaultCompanionError::SecretInvalid => "SECRET_INVALID",
        RescueVaultCompanionError::TransportUnavailable => "TRANSPORT_UNAVAILABLE",
        RescueVaultCompanionError::ProtocolFailure => "PROTOCOL_FAILURE",
    };
    write_tty(tty, b"error: ")?;
    write_tty(tty, token.as_bytes())?;
    write_tty(tty, b"\n")
}

struct EchoGuard<'tty> {
    tty: BorrowedFd<'tty>,
    original: Termios,
    restored: bool,
}

impl<'tty> EchoGuard<'tty> {
    fn hide_with_foreground_check(
        tty: BorrowedFd<'tty>,
        mut foreground_check: impl FnMut(BorrowedFd<'_>) -> Result<(), RescueVaultCompanionError>,
    ) -> Result<Self, RescueVaultCompanionError> {
        foreground_check(tty)?;
        let original = tcgetattr(tty).map_err(|_| RescueVaultCompanionError::EchoControlFailed)?;
        let mut guard = Self {
            tty,
            original,
            restored: false,
        };
        let mut hidden = guard.original.clone();
        hidden
            .local_modes
            .remove(LocalModes::ECHO | LocalModes::ECHONL);
        if tcsetattr(tty, OptionalActions::Now, &hidden).is_err() {
            return Err(guard.abort_after_hide(RescueVaultCompanionError::EchoControlFailed));
        }
        let observed = match tcgetattr(tty) {
            Ok(observed) => observed,
            Err(_) => {
                return Err(guard.abort_after_hide(RescueVaultCompanionError::EchoControlFailed));
            }
        };
        if observed
            .local_modes
            .intersects(LocalModes::ECHO | LocalModes::ECHONL)
        {
            return Err(guard.abort_after_hide(RescueVaultCompanionError::EchoControlFailed));
        }
        if let Err(error) = foreground_check(tty) {
            return Err(guard.abort_after_hide(error));
        }
        if tcflush(tty, QueueSelector::IFlush).is_err() {
            return Err(guard.abort_after_hide(RescueVaultCompanionError::EchoControlFailed));
        }
        Ok(guard)
    }

    fn abort_after_hide(
        &mut self,
        primary: RescueVaultCompanionError,
    ) -> RescueVaultCompanionError {
        if self.cleanup_after_hide().is_ok() {
            primary
        } else {
            RescueVaultCompanionError::EchoControlFailed
        }
    }

    fn cleanup_after_hide(&mut self) -> Result<(), RescueVaultCompanionError> {
        self.cleanup_after_hide_with_hook(|| {})
    }

    fn cleanup_after_hide_with_hook(
        &mut self,
        between_first_flush_and_restore: impl FnOnce(),
    ) -> Result<(), RescueVaultCompanionError> {
        // Input may arrive after the first flush but before echo restoration.
        // Attempt all three steps and let any cleanup ambiguity dominate.
        let first_flush = tcflush(self.tty, QueueSelector::IFlush).is_ok();
        between_first_flush_and_restore();
        let restored = self.restore().is_ok();
        let second_flush = tcflush(self.tty, QueueSelector::IFlush).is_ok();
        if first_flush && restored && second_flush {
            Ok(())
        } else {
            Err(RescueVaultCompanionError::EchoControlFailed)
        }
    }

    fn restore(&mut self) -> Result<(), RescueVaultCompanionError> {
        if self.restored {
            return Ok(());
        }
        tcsetattr(self.tty, OptionalActions::Now, &self.original)
            .map_err(|_| RescueVaultCompanionError::EchoControlFailed)?;
        let observed =
            tcgetattr(self.tty).map_err(|_| RescueVaultCompanionError::EchoControlFailed)?;
        let echo = LocalModes::ECHO | LocalModes::ECHONL;
        if observed.local_modes & echo != self.original.local_modes & echo {
            return Err(RescueVaultCompanionError::EchoControlFailed);
        }
        self.restored = true;
        Ok(())
    }
}

impl Drop for EchoGuard<'_> {
    fn drop(&mut self) {
        if !self.restored {
            let _ = tcsetattr(self.tty, OptionalActions::Now, &self.original);
        }
    }
}

fn read_secret_from_tty(
    tty: BorrowedFd<'_>,
    interrupted: &AtomicBool,
) -> Result<Zeroizing<Vec<u8>>, RescueVaultCompanionError> {
    validate_no_active_swap().map_err(|()| RescueVaultCompanionError::TransportUnavailable)?;
    read_secret_from_tty_after_privacy_check(tty, interrupted)
}

fn read_secret_from_tty_after_privacy_check(
    tty: BorrowedFd<'_>,
    interrupted: &AtomicBool,
) -> Result<Zeroizing<Vec<u8>>, RescueVaultCompanionError> {
    read_secret_after_privacy_with_foreground_check(tty, interrupted, ensure_foreground_tty)
}

fn read_secret_after_privacy_with_foreground_check(
    tty: BorrowedFd<'_>,
    interrupted: &AtomicBool,
    foreground_check: fn(BorrowedFd<'_>) -> Result<(), RescueVaultCompanionError>,
) -> Result<Zeroizing<Vec<u8>>, RescueVaultCompanionError> {
    // Allocate before echo is disabled so allocator failure cannot strand the
    // controlling terminal in the hidden state.
    let value = preallocated_secret_buffer();
    let mut guard = EchoGuard::hide_with_foreground_check(tty, foreground_check)?;
    let prompt_deadline = Instant::now() + Duration::from_secs(2);
    if let Err(error) = write_tty_all(
        tty,
        b"READY\nVault passphrase: ",
        prompt_deadline,
        Some(interrupted),
    ) {
        return Err(guard.abort_after_hide(error));
    }
    let result = read_secret_line(tty, interrupted, value);
    guard.cleanup_after_hide()?;
    write_tty(tty, b"\n")?;
    result
}

fn preallocated_secret_buffer() -> Zeroizing<Vec<u8>> {
    Zeroizing::new(Vec::with_capacity(MAX_PASSPHRASE_BYTES as usize))
}

fn read_secret_line(
    tty: BorrowedFd<'_>,
    interrupted: &AtomicBool,
    mut value: Zeroizing<Vec<u8>>,
) -> Result<Zeroizing<Vec<u8>>, RescueVaultCompanionError> {
    if value.capacity() < MAX_PASSPHRASE_BYTES as usize || !value.is_empty() {
        return Err(RescueVaultCompanionError::SecretInvalid);
    }
    loop {
        if interrupted.load(Ordering::Acquire) {
            return Err(RescueVaultCompanionError::Interrupted);
        }
        let mut buffer = Zeroizing::new([0_u8; 256]);
        match rustix::io::read(tty, &mut buffer[..]) {
            Ok(0) => return Err(RescueVaultCompanionError::SecretInvalid),
            Ok(read) => {
                let chunk = &buffer[..read];
                if let Some(newline) = chunk.iter().position(|byte| *byte == b'\n') {
                    if newline > (MAX_PASSPHRASE_BYTES as usize).saturating_sub(value.len()) {
                        return Err(RescueVaultCompanionError::SecretInvalid);
                    }
                    value.extend_from_slice(&chunk[..newline]);
                    if newline + 1 != chunk.len() {
                        return Err(RescueVaultCompanionError::SecretInvalid);
                    }
                    if value.last() == Some(&b'\r') {
                        value.pop();
                    }
                    break;
                }
                if chunk.len() > (MAX_PASSPHRASE_BYTES as usize).saturating_sub(value.len()) {
                    return Err(RescueVaultCompanionError::SecretInvalid);
                }
                value.extend_from_slice(chunk);
            }
            Err(error) if error == rustix::io::Errno::INTR => {}
            Err(error) if error == rustix::io::Errno::AGAIN => {
                wait_tty(tty, interrupted)?;
            }
            Err(_) => return Err(RescueVaultCompanionError::TtyUnavailable),
        }
    }
    if !(MIN_PASSPHRASE_BYTES as usize..=MAX_PASSPHRASE_BYTES as usize).contains(&value.len())
        || value.contains(&0)
    {
        return Err(RescueVaultCompanionError::SecretInvalid);
    }
    reject_buffered_tty_input(tty, interrupted)?;
    Ok(value)
}

fn reject_buffered_tty_input(
    tty: BorrowedFd<'_>,
    interrupted: &AtomicBool,
) -> Result<(), RescueVaultCompanionError> {
    loop {
        if interrupted.load(Ordering::Acquire) {
            return Err(RescueVaultCompanionError::Interrupted);
        }
        let mut extra = Zeroizing::new([0_u8; 1]);
        match rustix::io::read(tty, &mut extra[..]) {
            Err(error) if error == rustix::io::Errno::AGAIN => return Ok(()),
            Err(error) if error == rustix::io::Errno::INTR => {}
            Ok(_) => return Err(RescueVaultCompanionError::SecretInvalid),
            Err(_) => return Err(RescueVaultCompanionError::TtyUnavailable),
        }
    }
}

fn ensure_foreground_tty(tty: BorrowedFd<'_>) -> Result<(), RescueVaultCompanionError> {
    let foreground = tcgetpgrp(tty).map_err(|_| RescueVaultCompanionError::TtyUnavailable)?;
    if !process_group_is_foreground(foreground, rustix::process::getpgrp()) {
        return Err(RescueVaultCompanionError::TtyUnavailable);
    }
    Ok(())
}

fn process_group_is_foreground(
    terminal_group: rustix::process::Pid,
    process_group: rustix::process::Pid,
) -> bool {
    terminal_group == process_group
}

fn wait_tty(
    tty: BorrowedFd<'_>,
    interrupted: &AtomicBool,
) -> Result<(), RescueVaultCompanionError> {
    let mut descriptor = [PollFd::from_borrowed_fd(tty, PollFlags::IN)];
    match poll(&mut descriptor, Some(&duration_to_timespec(TTY_POLL_SLICE))) {
        Ok(_) if interrupted.load(Ordering::Acquire) => Err(RescueVaultCompanionError::Interrupted),
        Ok(_) if descriptor[0].revents().contains(PollFlags::NVAL) => {
            Err(RescueVaultCompanionError::TtyUnavailable)
        }
        Ok(_) => Ok(()),
        Err(error) if error == rustix::io::Errno::INTR => Ok(()),
        Err(_) => Err(RescueVaultCompanionError::TtyUnavailable),
    }
}

fn wait_socket(
    socket: BorrowedFd<'_>,
    interest: PollFlags,
    deadline: Instant,
) -> Result<(), RescueVaultCompanionError> {
    let remaining = deadline
        .checked_duration_since(Instant::now())
        .ok_or(RescueVaultCompanionError::TransportUnavailable)?;
    let mut descriptor = [PollFd::from_borrowed_fd(socket, interest)];
    match poll(&mut descriptor, Some(&duration_to_timespec(remaining))) {
        Ok(0) => Err(RescueVaultCompanionError::TransportUnavailable),
        Ok(_) if descriptor[0].revents().contains(PollFlags::NVAL) => {
            Err(RescueVaultCompanionError::TransportUnavailable)
        }
        Ok(_) => Ok(()),
        Err(_) => Err(RescueVaultCompanionError::TransportUnavailable),
    }
}

fn write_tty(descriptor: BorrowedFd<'_>, bytes: &[u8]) -> Result<(), RescueVaultCompanionError> {
    write_tty_all(
        descriptor,
        bytes,
        Instant::now() + Duration::from_secs(2),
        None,
    )
}

fn write_tty_all(
    descriptor: BorrowedFd<'_>,
    bytes: &[u8],
    deadline: Instant,
    interrupted: Option<&AtomicBool>,
) -> Result<(), RescueVaultCompanionError> {
    let mut written = 0;
    while written < bytes.len() {
        if interrupted.is_some_and(|interrupted| interrupted.load(Ordering::Acquire)) {
            return Err(RescueVaultCompanionError::Interrupted);
        }
        if Instant::now() >= deadline {
            return Err(RescueVaultCompanionError::TtyUnavailable);
        }
        match rustix::io::write(descriptor, &bytes[written..]) {
            Ok(0) => return Err(RescueVaultCompanionError::TtyUnavailable),
            Ok(count) => written += count,
            Err(error) if error == rustix::io::Errno::INTR => {}
            Err(error) if error == rustix::io::Errno::AGAIN => {
                wait_tty_write(descriptor, deadline, interrupted)?;
            }
            Err(_) => return Err(RescueVaultCompanionError::TtyUnavailable),
        }
    }
    Ok(())
}

fn wait_tty_write(
    descriptor: BorrowedFd<'_>,
    deadline: Instant,
    interrupted: Option<&AtomicBool>,
) -> Result<(), RescueVaultCompanionError> {
    if interrupted.is_some_and(|interrupted| interrupted.load(Ordering::Acquire)) {
        return Err(RescueVaultCompanionError::Interrupted);
    }
    let now = Instant::now();
    if now >= deadline {
        return Err(RescueVaultCompanionError::TtyUnavailable);
    }
    let slice = now
        .checked_add(TTY_POLL_SLICE)
        .unwrap_or(deadline)
        .min(deadline);
    let remaining = slice
        .checked_duration_since(now)
        .ok_or(RescueVaultCompanionError::TtyUnavailable)?;
    let mut pollfd = [PollFd::from_borrowed_fd(descriptor, PollFlags::OUT)];
    match poll(&mut pollfd, Some(&duration_to_timespec(remaining))) {
        Ok(_) if interrupted.is_some_and(|interrupted| interrupted.load(Ordering::Acquire)) => {
            Err(RescueVaultCompanionError::Interrupted)
        }
        Ok(_) if pollfd[0].revents().contains(PollFlags::NVAL) => {
            Err(RescueVaultCompanionError::TtyUnavailable)
        }
        Ok(_) => Ok(()),
        Err(error) if error == rustix::io::Errno::INTR => Ok(()),
        Err(_) => Err(RescueVaultCompanionError::TtyUnavailable),
    }
}

fn write_pipe_secret(descriptor: BorrowedFd<'_>, bytes: &[u8]) -> Result<(), ()> {
    loop {
        match rustix::io::write(descriptor, bytes) {
            Ok(written) if written == bytes.len() => return Ok(()),
            Ok(_) => return Err(()),
            Err(error) if error == rustix::io::Errno::INTR => {}
            Err(_) => return Err(()),
        }
    }
}

fn read_bounded(descriptor: BorrowedFd<'_>, maximum: usize) -> Result<Vec<u8>, ()> {
    let mut bytes = Vec::new();
    let mut buffer = [0_u8; 4096];
    loop {
        match rustix::io::read(descriptor, &mut buffer) {
            Ok(0) => return Ok(bytes),
            Ok(read) if bytes.len().saturating_add(read) <= maximum => {
                bytes.extend_from_slice(&buffer[..read]);
            }
            Ok(_) => return Err(()),
            Err(error) if error == rustix::io::Errno::INTR => {}
            Err(_) => return Err(()),
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

#[cfg(test)]
mod tests {
    use super::*;
    use kernaid_protocol::{
        rescue_vault::ProtocolViolation, rescue_vault_transport::ClientResponseDecodeError,
    };
    use nix::pty::openpty;
    use rustix::net::{RecvFlags, SendFlags, recv, send, socketpair};
    use std::{cell::Cell, collections::VecDeque, sync::atomic::AtomicUsize};

    fn assume_foreground(_tty: BorrowedFd<'_>) -> Result<(), RescueVaultCompanionError> {
        Ok(())
    }

    fn nonblocking_pty() -> nix::pty::OpenptyResult {
        let pty = openpty(None, None).expect("pty");
        let flags = rfs::fcntl_getfl(&pty.slave).expect("pty flags");
        rfs::fcntl_setfl(&pty.slave, flags | OFlags::NONBLOCK).expect("nonblocking slave");
        pty
    }

    fn delayed_master_write(master: OwnedFd, bytes: Vec<u8>) -> thread::JoinHandle<()> {
        thread::spawn(move || {
            thread::sleep(Duration::from_millis(30));
            let mut written = 0;
            while written < bytes.len() {
                match rustix::io::write(&master, &bytes[written..]) {
                    Ok(0) => return,
                    Ok(count) => written += count,
                    Err(error) if error == rustix::io::Errno::INTR => {}
                    Err(_) => return,
                }
            }
        })
    }

    #[test]
    fn command_surface_is_exact_and_path_free() {
        assert_eq!(
            parse_command([OsString::from("status")]),
            Ok(Command::Status)
        );
        assert_eq!(
            parse_command([OsString::from("unlock")]),
            Ok(Command::Unlock)
        );
        assert!(parse_command([OsString::from("unlock"), OsString::from("/dev/sda")]).is_err());
        assert!(parse_command([OsString::from("--socket=/tmp/x")]).is_err());
    }

    #[test]
    fn passwd_binding_requires_one_exact_kernaid_uid() {
        let valid =
            b"root:x:0:0:root:/root:/bin/sh\nkernaid:x:1000:1000::/nonexistent:/usr/sbin/nologin\n";
        assert!(passwd_has_exact_companion(valid, 1000));
        assert!(!passwd_has_exact_companion(valid, 1001));
        assert!(!passwd_has_exact_companion(
            b"kernaid:x:1000:1000::/:/bin/false\nkernaid:x:1000:1000::/:/bin/false\n",
            1000
        ));
    }

    #[test]
    fn interrupted_tty_read_restores_echo_on_a_real_pty() {
        let pty = openpty(None, None).expect("pty");
        let master_flags = rfs::fcntl_getfl(&pty.master).expect("master flags");
        rfs::fcntl_setfl(&pty.master, master_flags | OFlags::NONBLOCK).expect("nonblocking master");
        let before = tcgetattr(&pty.slave).expect("before");
        let interrupted = AtomicBool::new(true);
        assert_eq!(
            read_secret_after_privacy_with_foreground_check(
                pty.slave.as_fd(),
                &interrupted,
                assume_foreground,
            ),
            Err(RescueVaultCompanionError::Interrupted)
        );
        let after = tcgetattr(&pty.slave).expect("after");
        assert_eq!(before.local_modes, after.local_modes);
        let mut output = [0_u8; 1];
        assert_eq!(
            rustix::io::read(&pty.master, &mut output).err(),
            Some(rustix::io::Errno::AGAIN),
            "an interrupt before the prompt must not emit READY"
        );
    }

    #[test]
    fn real_pty_flushes_prequeued_input_rejects_multiline_and_never_reallocates_secret() {
        let pty = nonblocking_pty();
        let before = tcgetattr(&pty.slave).expect("before");
        rustix::io::write(&pty.master, b"PREQUEUED_VALUE\n").expect("prequeue");
        let interrupted = Arc::new(AtomicBool::new(false));
        let trigger = Arc::clone(&interrupted);
        let trigger = thread::spawn(move || {
            thread::sleep(Duration::from_millis(150));
            trigger.store(true, Ordering::Release);
        });
        assert_eq!(
            read_secret_after_privacy_with_foreground_check(
                pty.slave.as_fd(),
                &interrupted,
                assume_foreground,
            ),
            Err(RescueVaultCompanionError::Interrupted),
            "prequeued bytes must have been flushed before READY"
        );
        trigger.join().expect("interrupt trigger");
        assert_eq!(
            before.local_modes,
            tcgetattr(&pty.slave).expect("restored").local_modes
        );

        let pty = nonblocking_pty();
        let master_keepalive =
            rustix::io::fcntl_dupfd_cloexec(&pty.master, 3).expect("multiline master keepalive");
        let writer = delayed_master_write(pty.master, b"TEST_ONLY_12\nsecond-line\n".to_vec());
        assert_eq!(
            read_secret_after_privacy_with_foreground_check(
                pty.slave.as_fd(),
                &AtomicBool::new(false),
                assume_foreground,
            ),
            Err(RescueVaultCompanionError::SecretInvalid)
        );
        writer.join().expect("multiline writer");
        drop(master_keepalive);

        let pty = nonblocking_pty();
        let master_keepalive =
            rustix::io::fcntl_dupfd_cloexec(&pty.master, 3).expect("valid master keepalive");
        let writer = delayed_master_write(pty.master, b"TEST_ONLY_12\n".to_vec());
        let secret = read_secret_after_privacy_with_foreground_check(
            pty.slave.as_fd(),
            &AtomicBool::new(false),
            assume_foreground,
        )
        .expect("valid secret");
        writer.join().expect("valid writer");
        assert_eq!(&secret[..], b"TEST_ONLY_12");
        assert!(secret.capacity() >= MAX_PASSPHRASE_BYTES as usize);
        drop(master_keepalive);

        let pty = nonblocking_pty();
        let master_keepalive =
            rustix::io::fcntl_dupfd_cloexec(&pty.master, 3).expect("maximum master keepalive");
        let mut maximum = vec![b'A'; MAX_PASSPHRASE_BYTES as usize];
        maximum.push(b'\n');
        let writer = delayed_master_write(pty.master, maximum);
        let initial = preallocated_secret_buffer();
        let initial_pointer = initial.as_ptr();
        let initial_capacity = initial.capacity();
        let secret = read_secret_line(pty.slave.as_fd(), &AtomicBool::new(false), initial)
            .expect("maximum-size secret");
        writer.join().expect("maximum writer");
        assert_eq!(secret.len(), MAX_PASSPHRASE_BYTES as usize);
        assert_eq!(secret.capacity(), initial_capacity);
        assert_eq!(secret.as_ptr(), initial_pointer);
        drop(master_keepalive);

        let pty = nonblocking_pty();
        let master_keepalive =
            rustix::io::fcntl_dupfd_cloexec(&pty.master, 3).expect("overflow master keepalive");
        let mut overflow = vec![b'A'; MAX_PASSPHRASE_BYTES as usize + 1];
        overflow.push(b'\n');
        let writer = delayed_master_write(pty.master, overflow);
        assert_eq!(
            read_secret_after_privacy_with_foreground_check(
                pty.slave.as_fd(),
                &AtomicBool::new(false),
                assume_foreground,
            ),
            Err(RescueVaultCompanionError::SecretInvalid)
        );
        writer.join().expect("overflow writer");
        drop(master_keepalive);
    }

    #[test]
    fn second_foreground_check_restores_echo_and_cleanup_failure_dominates() {
        static CHECKS: AtomicUsize = AtomicUsize::new(0);
        fn fail_second_check(_tty: BorrowedFd<'_>) -> Result<(), RescueVaultCompanionError> {
            if CHECKS.fetch_add(1, Ordering::SeqCst) == 0 {
                Ok(())
            } else {
                Err(RescueVaultCompanionError::TtyUnavailable)
            }
        }

        CHECKS.store(0, Ordering::SeqCst);
        let pty = nonblocking_pty();
        let before = tcgetattr(&pty.slave).expect("before");
        rustix::io::write(&pty.master, b"PREQUEUED_VALUE\n").expect("prequeued input");
        assert!(matches!(
            EchoGuard::hide_with_foreground_check(pty.slave.as_fd(), fail_second_check),
            Err(RescueVaultCompanionError::TtyUnavailable)
        ));
        assert_eq!(
            before.local_modes,
            tcgetattr(&pty.slave).expect("restored").local_modes
        );
        let mut queued = Zeroizing::new([0_u8; 1]);
        assert_eq!(
            rustix::io::read(&pty.slave, &mut queued[..]).err(),
            Some(rustix::io::Errno::AGAIN),
            "every post-hide abort must flush pending terminal input"
        );

        let pty = nonblocking_pty();
        let mut master = Some(pty.master);
        let mut checks = 0_usize;
        let result = EchoGuard::hide_with_foreground_check(pty.slave.as_fd(), |_| {
            checks += 1;
            if checks == 2 {
                drop(master.take());
                Err(RescueVaultCompanionError::TtyUnavailable)
            } else {
                Ok(())
            }
        });
        assert!(matches!(
            result,
            Err(RescueVaultCompanionError::EchoControlFailed)
        ));
    }

    #[test]
    fn cleanup_flushes_input_arriving_between_first_flush_and_restore() {
        let pty = nonblocking_pty();
        let before = tcgetattr(&pty.slave).expect("before");
        let mut guard = EchoGuard::hide_with_foreground_check(pty.slave.as_fd(), assume_foreground)
            .expect("hide echo");
        guard
            .cleanup_after_hide_with_hook(|| {
                assert_eq!(
                    rustix::io::write(&pty.master, b"WINDOW_SENTINEL\n")
                        .expect("inject cleanup-window input"),
                    16
                );
            })
            .expect("double-flush cleanup");
        assert_eq!(
            before.local_modes,
            tcgetattr(&pty.slave).expect("restored").local_modes
        );
        let mut queued = Zeroizing::new([0_u8; 1]);
        assert_eq!(
            rustix::io::read(&pty.slave, &mut queued[..]).err(),
            Some(rustix::io::Errno::AGAIN),
            "the post-restore flush must remove input from the cleanup window"
        );
    }

    #[test]
    fn tty_output_backpressure_observes_interrupt_without_resetting_deadline() {
        let (read, write) = pipe_with(PipeFlags::CLOEXEC | PipeFlags::NONBLOCK).expect("pipe");
        let fill = [0_u8; 4096];
        let filled = loop {
            match rustix::io::write(&write, &fill) {
                Ok(_) => {}
                Err(error) if error == rustix::io::Errno::AGAIN => break true,
                Err(_) => break false,
            }
        };
        assert!(filled);
        let interrupted = Arc::new(AtomicBool::new(false));
        let trigger = Arc::clone(&interrupted);
        let trigger = thread::spawn(move || {
            thread::sleep(Duration::from_millis(50));
            trigger.store(true, Ordering::Release);
        });
        let started = Instant::now();
        assert_eq!(
            write_tty_all(
                write.as_fd(),
                b"x",
                started + Duration::from_secs(2),
                Some(&interrupted),
            ),
            Err(RescueVaultCompanionError::Interrupted)
        );
        assert!(started.elapsed() < Duration::from_millis(500));
        trigger.join().expect("interrupt trigger");
        drop(read);
    }

    #[test]
    fn only_transport_failures_have_unknown_post_send_outcome() {
        assert!(interrupted_receive_error_has_unknown_outcome(
            &ClientExchangeError::Transport(SeqpacketTransportError::IoFailed)
        ));
        assert!(interrupted_receive_error_has_unknown_outcome(
            &ClientExchangeError::Transport(SeqpacketTransportError::TimedOut)
        ));
        assert!(interrupted_receive_error_has_unknown_outcome(
            &ClientExchangeError::Transport(SeqpacketTransportError::AmbiguousZeroByte)
        ));
        for error in [
            SeqpacketTransportError::InvalidTransport,
            SeqpacketTransportError::ServerNotRoot,
            SeqpacketTransportError::EmptyDatagram,
            SeqpacketTransportError::DatagramTooLarge,
            SeqpacketTransportError::AncillaryTruncated,
            SeqpacketTransportError::UnexpectedAncillary,
            SeqpacketTransportError::TooManyDescriptors,
            SeqpacketTransportError::IncompleteSend,
        ] {
            let error = ClientExchangeError::Transport(error);
            assert!(!interrupted_receive_error_has_unknown_outcome(&error));
            assert_eq!(
                map_client_exchange_error(error),
                RescueVaultCompanionError::ProtocolFailure
            );
        }
        assert!(!interrupted_receive_error_has_unknown_outcome(
            &ClientExchangeError::Response(ClientResponseDecodeError::InvalidCorrelation)
        ));
        assert!(!interrupted_receive_error_has_unknown_outcome(
            &ClientExchangeError::Request(ProtocolViolation::InvalidPayload)
        ));
        assert_eq!(
            map_client_exchange_error(ClientExchangeError::Transport(
                SeqpacketTransportError::IoFailed,
            )),
            RescueVaultCompanionError::TransportUnavailable
        );
        assert_eq!(
            map_client_exchange_error(ClientExchangeError::Response(
                ClientResponseDecodeError::InvalidCorrelation,
            )),
            RescueVaultCompanionError::ProtocolFailure
        );
        assert!(direct_mutation_version_is_exact(12, 10));
        assert!(!direct_mutation_version_is_exact(11, 10));
        assert!(!direct_mutation_version_is_exact(13, 10));
        assert!(reconciled_mutation_version_is_authoritative(12, 10));
        assert!(reconciled_mutation_version_is_authoritative(15, 10));
        assert!(!reconciled_mutation_version_is_authoritative(11, 10));
    }

    #[test]
    fn correlated_response_wins_signal_but_silent_socket_reconciles_and_closes() {
        let (daemon, companion) = socketpair(
            AddressFamily::UNIX,
            SocketType::SEQPACKET,
            SocketFlags::CLOEXEC | SocketFlags::NONBLOCK,
            None,
        )
        .expect("fast response socketpair");
        assert_eq!(
            send(&daemon, &[42], SendFlags::NOSIGNAL).expect("fast response"),
            1
        );
        let interrupted = AtomicBool::new(true);
        let mut byte = [0_u8; 1];
        let outcome = receive_correlated_or_reconcile(
            Instant::now() + Duration::from_secs(1),
            Some(&interrupted),
            true,
            |_| match recv(&companion, &mut byte, RecvFlags::DONTWAIT) {
                Ok((1, _)) => Ok(byte[0]),
                Ok(_) => Err(ClientExchangeError::Transport(
                    SeqpacketTransportError::IoFailed,
                )),
                Err(error) if error == rustix::io::Errno::AGAIN => Err(
                    ClientExchangeError::Transport(SeqpacketTransportError::TimedOut),
                ),
                Err(_) => Err(ClientExchangeError::Transport(
                    SeqpacketTransportError::IoFailed,
                )),
            },
            |_| Ok(()),
        )
        .expect("authoritative response");
        assert!(matches!(outcome, ReceiveDisposition::Response(42)));

        let (daemon, companion) = socketpair(
            AddressFamily::UNIX,
            SocketType::SEQPACKET,
            SocketFlags::CLOEXEC | SocketFlags::NONBLOCK,
            None,
        )
        .expect("silent response socketpair");
        let mut byte = [0_u8; 1];
        let outcome = receive_correlated_or_reconcile(
            Instant::now() + Duration::from_secs(1),
            Some(&interrupted),
            true,
            |_| match recv(&companion, &mut byte, RecvFlags::DONTWAIT) {
                Err(error) if error == rustix::io::Errno::AGAIN => Err(
                    ClientExchangeError::Transport(SeqpacketTransportError::TimedOut),
                ),
                _ => Err(ClientExchangeError::Transport(
                    SeqpacketTransportError::IoFailed,
                )),
            },
            |_: &u8| Ok(()),
        )
        .expect("signal reconciliation");
        assert!(matches!(
            outcome,
            ReceiveDisposition::Reconcile(RescueVaultCompanionError::Interrupted)
        ));
        drop(companion);
        assert_eq!(
            recv(&daemon, &mut byte, RecvFlags::DONTWAIT)
                .expect("peer EOF after cancellation")
                .0,
            0
        );
    }

    #[test]
    fn malformed_correlated_response_never_reconciles_even_after_signal() {
        let interrupted = AtomicBool::new(true);
        let result = receive_correlated_or_reconcile(
            Instant::now() + Duration::from_secs(1),
            Some(&interrupted),
            true,
            |_| {
                Err::<u8, _>(ClientExchangeError::Response(
                    ClientResponseDecodeError::InvalidCorrelation,
                ))
            },
            |_| Ok(()),
        );
        assert!(matches!(
            result,
            Err(RescueVaultCompanionError::ProtocolFailure)
        ));

        for transport in [
            SeqpacketTransportError::InvalidTransport,
            SeqpacketTransportError::ServerNotRoot,
            SeqpacketTransportError::EmptyDatagram,
            SeqpacketTransportError::DatagramTooLarge,
            SeqpacketTransportError::AncillaryTruncated,
            SeqpacketTransportError::UnexpectedAncillary,
            SeqpacketTransportError::TooManyDescriptors,
            SeqpacketTransportError::IncompleteSend,
        ] {
            let receive_calls = Cell::new(0_usize);
            let result = receive_correlated_or_reconcile(
                Instant::now() + Duration::from_secs(1),
                Some(&interrupted),
                true,
                |_| {
                    receive_calls.set(receive_calls.get() + 1);
                    Err::<u8, _>(ClientExchangeError::Transport(transport))
                },
                |_| Ok(()),
            );
            assert!(matches!(
                result,
                Err(RescueVaultCompanionError::ProtocolFailure)
            ));
            assert_eq!(receive_calls.get(), 1, "strict framing error retried");
        }

        let no_signal = AtomicBool::new(false);
        let result = receive_correlated_or_reconcile(
            Instant::now() + Duration::from_secs(1),
            Some(&no_signal),
            true,
            |_| {
                Err::<u8, _>(ClientExchangeError::Transport(
                    SeqpacketTransportError::IoFailed,
                ))
            },
            |_| Ok(()),
        )
        .expect("transport reconciliation");
        assert!(matches!(
            result,
            ReceiveDisposition::Reconcile(RescueVaultCompanionError::TransportUnavailable)
        ));
    }

    #[test]
    fn reconciliation_polls_transitions_and_preserves_terminal_evidence() {
        let base = Instant::now();
        let elapsed = Cell::new(Duration::ZERO);
        let mut script = VecDeque::from([
            Ok(1_u8),
            Err(RescueVaultCompanionError::TransportUnavailable),
            Ok(2_u8),
        ]);
        let outcome = poll_reconciliation_until(
            base + Duration::from_secs(1),
            |_| {
                script
                    .pop_front()
                    .unwrap_or(Err(RescueVaultCompanionError::TransportUnavailable))
            },
            |sample| match sample {
                1 => ReconciliationClass::Transitional,
                2 => ReconciliationClass::Target,
                _ => ReconciliationClass::Terminal,
            },
            || base + elapsed.get(),
            |duration| elapsed.set(elapsed.get() + duration),
        )
        .expect("poll target");
        assert!(matches!(outcome, ReconciliationPoll::Target(2)));
        assert_eq!(elapsed.get(), RESPONSE_POLL_SLICE * 2);

        let terminal = poll_reconciliation_until(
            base + Duration::from_secs(1),
            |_| Ok(3_u8),
            |_| ReconciliationClass::Terminal,
            || base,
            |_| {},
        )
        .expect("terminal evidence");
        assert!(matches!(terminal, ReconciliationPoll::Terminal(3)));
    }

    #[test]
    fn reconciliation_deadline_returns_the_last_transitional_evidence() {
        let base = Instant::now();
        let elapsed = Cell::new(Duration::ZERO);
        let outcome = poll_reconciliation_until(
            base + Duration::from_millis(250),
            |_| Ok(7_u8),
            |_| ReconciliationClass::Transitional,
            || base + elapsed.get(),
            |duration| elapsed.set(elapsed.get() + duration),
        )
        .expect("poll expiry");
        assert!(matches!(outcome, ReconciliationPoll::Expired(Some(7))));
        assert_eq!(elapsed.get(), Duration::from_millis(250));

        let protocol_error = poll_reconciliation_until(
            base + Duration::from_secs(1),
            |_| Err::<u8, _>(RescueVaultCompanionError::ProtocolFailure),
            |_| ReconciliationClass::Target,
            || base,
            |_| {},
        );
        assert!(matches!(
            protocol_error,
            Err(RescueVaultCompanionError::ProtocolFailure)
        ));
    }

    #[test]
    fn job_control_signals_are_synchronously_intercepted() {
        let signals = companion_signal_set();
        for signal in [
            Signal::SIGINT,
            Signal::SIGTERM,
            Signal::SIGHUP,
            Signal::SIGQUIT,
            Signal::SIGTSTP,
            Signal::SIGTTIN,
            Signal::SIGTTOU,
        ] {
            assert!(signals.contains(signal));
        }
        let group = rustix::process::getpgrp();
        assert!(process_group_is_foreground(group, group));
        let secret = preallocated_secret_buffer();
        assert!(secret.is_empty());
        assert!(secret.capacity() >= MAX_PASSPHRASE_BYTES as usize);
    }

    #[test]
    fn request_ids_are_canonical_and_fresh() {
        let first = fresh_request_id().expect("first");
        let second = fresh_request_id().expect("second");
        assert_ne!(first, second);
        assert_eq!(first.as_str().len(), 38);
    }

    #[test]
    fn remote_error_output_uses_only_closed_tokens() {
        for token in [
            kernaid_protocol::rescue_vault::ErrorToken::ProfileMismatch,
            kernaid_protocol::rescue_vault::ErrorToken::NotAuthorized,
            kernaid_protocol::rescue_vault::ErrorToken::RebootRequired,
        ] {
            assert!(
                remote_error_name(token)
                    .bytes()
                    .all(|byte| byte.is_ascii_uppercase() || byte == b'_')
            );
        }
    }

    #[test]
    fn mutation_commands_require_the_exact_source_state() {
        use kernaid_protocol::rescue_vault::ErrorToken;
        let cases = [
            (VaultState::Absent, ErrorToken::Absent, ErrorToken::Absent),
            (
                VaultState::Unprovisioned,
                ErrorToken::Unprovisioned,
                ErrorToken::Unprovisioned,
            ),
            (
                VaultState::Locked,
                ErrorToken::NotAuthorized,
                ErrorToken::Locked,
            ),
            (VaultState::Unlocking, ErrorToken::Busy, ErrorToken::Busy),
            (
                VaultState::Unlocked,
                ErrorToken::Busy,
                ErrorToken::NotAuthorized,
            ),
            (VaultState::Locking, ErrorToken::Busy, ErrorToken::Busy),
            (
                VaultState::FaultedRebootRequired,
                ErrorToken::RebootRequired,
                ErrorToken::RebootRequired,
            ),
        ];
        for (state, unlock_error, lock_error) in cases {
            let unlock = mutation_source_error(Command::Unlock, state);
            let lock = mutation_source_error(Command::Lock, state);
            if state == VaultState::Locked {
                assert_eq!(unlock, None);
            } else {
                assert_eq!(unlock, Some(unlock_error));
            }
            if state == VaultState::Unlocked {
                assert_eq!(lock, None);
            } else {
                assert_eq!(lock, Some(lock_error));
            }
        }
    }
}
