use crate::{
    jsonl::{MAX_JSONL_BYTES, parse_jsonl, prepare_execution},
    wire::{
        BridgeCode, ControlRequest, DiagnosisRequest, MAX_CONTROL_FRAME_BYTES, WireError,
        encode_error, encode_success, parse_control_frame, parse_diagnosis_input,
    },
};
use kernaid_protocol::{
    rescue_vault::{ErrorToken, RequestId, SuccessPayload, VaultState},
    rescue_vault_transport::{
        ClientRequest, ClientRequestPayload, ClientResponseOutcome,
        authenticate_root_seqpacket_server,
    },
};
use kernaid_rescue_openai_provider::DiagnosisProposal;
use rustix::{
    event::{PollFd, PollFlags, Timespec, poll},
    fd::{AsFd, BorrowedFd, OwnedFd},
    fs::{self as rfs, FileType, MemfdFlags, Mode, OFlags, SealFlags},
    net::{
        AddressFamily, RecvAncillaryBuffer, RecvAncillaryMessage, RecvFlags, ReturnFlags,
        SendFlags, SocketAddrUnix, SocketFlags, SocketType, connect, recvmsg, send, socket_with,
    },
};
use std::{
    env, fmt, fs,
    io::IoSliceMut,
    mem::MaybeUninit,
    os::{fd::AsRawFd, unix::process::ExitStatusExt},
    path::{Path, PathBuf},
    process::{Child, Command, Stdio},
    time::{Duration, Instant},
};

const CODEX_SOCKET_PATH: &[u8] = b"/run/kernaid-rescue-codex.sock";
const VAULT_SOCKET_PATH: &str = "/run/kernaid-rescue-vault.sock";
const CODEX_BINARY: &str = "/usr/lib/kernaid/codex";
#[cfg(test)]
const CODEX_CLI_VERSION: &str = "0.147.0";
const CODEX_AGENT_UID: u32 = 1003;
const CODEX_AGENT_GID: u32 = 1003;
const RUNTIME_PREFIX: &str = "/run/kernaid-rescue-codex-";
const PIPEFS_MAGIC: u64 = 0x5049_5045;
const TMPFS_MAGIC: u64 = 0x0102_1994;
const EXT4_SUPER_MAGIC: u64 = 0xef53;
const CONTROL_TIMEOUT: Duration = Duration::from_secs(3);
const VAULT_TIMEOUT: Duration = Duration::from_secs(20);
const CODEX_TIMEOUT: Duration = Duration::from_secs(110);
const CHILD_CLEANUP_TIMEOUT: Duration = Duration::from_secs(2);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BridgeError {
    InvalidIdentity,
    InvalidSocket,
    NoData,
    RequestTooLarge,
    UnexpectedAncillary,
    InvalidRequest,
    TimedOut,
    IoFailed,
    IncompleteSend,
    RuntimeUnavailable,
}

impl fmt::Display for BridgeError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::InvalidIdentity => "Codex bridge identity is invalid",
            Self::InvalidSocket => "Codex bridge socket is invalid",
            Self::NoData => "Codex bridge received no data",
            Self::RequestTooLarge => "Codex bridge request is too large",
            Self::UnexpectedAncillary => "Codex bridge ancillary data is invalid",
            Self::InvalidRequest => "Codex bridge request is invalid",
            Self::TimedOut => "Codex bridge operation timed out",
            Self::IoFailed => "Codex bridge I/O failed",
            Self::IncompleteSend => "Codex bridge response was incomplete",
            Self::RuntimeUnavailable => "Codex bridge runtime is unavailable",
        })
    }
}

impl std::error::Error for BridgeError {}

trait HomeLease {
    fn home(&self) -> BorrowedFd<'_>;
}

trait VaultBoundary {
    fn lease(&self, request_id: &str) -> Result<Box<dyn HomeLease>, BridgeCode>;
}

trait CodexBoundary {
    fn execute(
        &self,
        home: BorrowedFd<'_>,
        request: &DiagnosisRequest,
        runtime: &RuntimePaths,
    ) -> Result<DiagnosisProposal, BridgeCode>;
}

struct SystemBoundaries;

struct SystemHomeLease {
    // Keeping the authenticated socket open retains the exact vault lease
    // through child exit, parser finalization, and local response delivery.
    _control_socket: OwnedFd,
    home: OwnedFd,
}

impl HomeLease for SystemHomeLease {
    fn home(&self) -> BorrowedFd<'_> {
        self.home.as_fd()
    }
}

impl VaultBoundary for SystemBoundaries {
    fn lease(&self, request_id: &str) -> Result<Box<dyn HomeLease>, BridgeCode> {
        let request_id = vault_request_id(request_id)?;
        let status_request =
            ClientRequest::new(request_id.clone(), 0, ClientRequestPayload::VaultStatus)
                .map_err(|_| BridgeCode::Transport)?;
        let status = exchange_vault(&status_request, deadline_after(CONTROL_TIMEOUT)?)?;
        match status.outcome() {
            ClientResponseOutcome::Success(SuccessPayload::VaultStatus(vault))
                if vault.vault_state() == VaultState::Unlocked => {}
            ClientResponseOutcome::Success(SuccessPayload::VaultStatus(_))
            | ClientResponseOutcome::Error(ErrorToken::Absent)
            | ClientResponseOutcome::Error(ErrorToken::Unprovisioned)
            | ClientResponseOutcome::Error(ErrorToken::Locked)
            | ClientResponseOutcome::Error(ErrorToken::ProviderUnconfigured) => {
                return Err(BridgeCode::CredentialUnavailable);
            }
            ClientResponseOutcome::Error(
                ErrorToken::Busy | ErrorToken::RateLimited | ErrorToken::StaleState,
            ) => {
                return Err(BridgeCode::Busy);
            }
            ClientResponseOutcome::Error(_) | ClientResponseOutcome::Success(_) => {
                return Err(BridgeCode::Transport);
            }
        }

        let lease_request = ClientRequest::new(
            request_id,
            status.state_version(),
            ClientRequestPayload::ProviderCodexHomeLease,
        )
        .map_err(|_| BridgeCode::Transport)?;
        let socket = connect_vault(deadline_after(CONTROL_TIMEOUT)?)?;
        let authenticated = authenticate_root_seqpacket_server(socket.as_fd())
            .map_err(|_| BridgeCode::Transport)?;
        let deadline = deadline_after(VAULT_TIMEOUT)?;
        authenticated
            .send_request(&lease_request, &[], deadline)
            .map_err(|_| BridgeCode::Transport)?;
        let mut response = authenticated
            .receive_response(&lease_request, deadline)
            .map_err(|_| BridgeCode::Transport)?;
        if response.state_version() != status.state_version() {
            return Err(BridgeCode::Transport);
        }
        match response.outcome() {
            ClientResponseOutcome::Success(SuccessPayload::Descriptor(declaration))
                if declaration.size == 0 => {}
            ClientResponseOutcome::Error(
                ErrorToken::Absent
                | ErrorToken::Locked
                | ErrorToken::ProviderUnconfigured
                | ErrorToken::Unprovisioned,
            ) => {
                return Err(BridgeCode::CredentialUnavailable);
            }
            ClientResponseOutcome::Error(
                ErrorToken::Busy | ErrorToken::RateLimited | ErrorToken::StaleState,
            ) => {
                return Err(BridgeCode::Busy);
            }
            ClientResponseOutcome::Error(_) | ClientResponseOutcome::Success(_) => {
                return Err(BridgeCode::Transport);
            }
        }
        let home = response.take_descriptor().ok_or(BridgeCode::Transport)?;
        validate_home(home.as_fd())?;
        Ok(Box::new(SystemHomeLease {
            _control_socket: socket,
            home,
        }))
    }
}

impl CodexBoundary for SystemBoundaries {
    fn execute(
        &self,
        home: BorrowedFd<'_>,
        request: &DiagnosisRequest,
        runtime: &RuntimePaths,
    ) -> Result<DiagnosisProposal, BridgeCode> {
        let prepared = prepare_execution(request).map_err(|error| match error {
            crate::jsonl::JsonlError::TooLarge => BridgeCode::RequestTooLarge,
            _ => BridgeCode::InvalidRequest,
        })?;
        let schema = runtime.write_schema(&prepared.schema)?;
        let inherited = [
            home,
            schema.as_fd(),
            runtime.log.as_fd(),
            runtime.sqlite.as_fd(),
        ];
        set_inheritance(&inherited, false)?;
        let mut command = build_codex_command(home, schema.as_fd(), runtime);
        let spawned = command.spawn();
        let restore = set_inheritance(&inherited, true);
        if restore.is_err() {
            if let Ok(mut child) = spawned {
                terminate_child(&mut child);
            }
            return Err(BridgeCode::ExecutionUnavailable);
        }
        let mut child = spawned.map_err(|_| BridgeCode::ExecutionUnavailable)?;
        let execution_deadline = deadline_after(CODEX_TIMEOUT)?;
        if let Err(error) = write_child_input(&mut child, &prepared.prompt, execution_deadline) {
            terminate_child(&mut child);
            return Err(error);
        }
        let output = read_child_output(&mut child, execution_deadline)?;
        parse_jsonl(&output, request).map_err(|error| match error {
            crate::jsonl::JsonlError::TooLarge => BridgeCode::ResponseTooLarge,
            crate::jsonl::JsonlError::ForbiddenEvent
            | crate::jsonl::JsonlError::InvalidEvent
            | crate::jsonl::JsonlError::InvalidFinal
            | crate::jsonl::JsonlError::InvalidStream => BridgeCode::InvalidResponse,
        })
    }
}

/// Serves one systemd-accepted request. The binary is feature-gated and its
/// source units are deliberately outside the live-image include tree.
pub fn run_socket_activated_once() -> Result<(), BridgeError> {
    use rustix::process::{DumpableBehavior, dumpable_behavior, set_dumpable_behavior};
    if rustix::process::getuid().as_raw() != CODEX_AGENT_UID
        || rustix::process::getgid().as_raw() != CODEX_AGENT_GID
    {
        return Err(BridgeError::InvalidIdentity);
    }
    set_dumpable_behavior(DumpableBehavior::NotDumpable)
        .map_err(|_| BridgeError::InvalidIdentity)?;
    if dumpable_behavior().map_err(|_| BridgeError::InvalidIdentity)?
        != DumpableBehavior::NotDumpable
    {
        return Err(BridgeError::InvalidIdentity);
    }
    let input = std::io::stdin();
    prepare_client_socket(input.as_fd(), Some(CODEX_SOCKET_PATH))?;
    let (frame, mut descriptors) = receive_control_packet(
        input.as_fd(),
        deadline_after(CONTROL_TIMEOUT).map_err(map_code)?,
    )?;
    let control = parse_control_frame(&frame).map_err(map_wire)?;
    let descriptor = descriptors.pop().ok_or(BridgeError::UnexpectedAncillary)?;
    if !descriptors.is_empty() {
        return Err(BridgeError::UnexpectedAncillary);
    }
    let diagnosis_frame = match read_declared_pipe(
        descriptor.as_fd(),
        control.input_size(),
        deadline_after(CONTROL_TIMEOUT).map_err(map_code)?,
    ) {
        Ok(frame) => frame,
        Err(error) => {
            let _ = send_closed_error(input.as_fd(), &control, BridgeCode::InvalidRequest);
            return Err(error);
        }
    };
    // The request is now an owned snapshot. Close both the received endpoint
    // and the private endpoint used by `read_declared_pipe` before parsing or
    // starting Codex so later peer-side pipe activity has no consumer here.
    drop(descriptor);
    let request = match parse_diagnosis_input(&control, &diagnosis_frame) {
        Ok(request) => request,
        Err(_) => {
            let _ = send_closed_error(input.as_fd(), &control, BridgeCode::InvalidRequest);
            return Err(BridgeError::InvalidRequest);
        }
    };
    let runtime = match RuntimePaths::prepare_from_env() {
        Ok(runtime) => runtime,
        Err(code) => {
            send_closed_error(input.as_fd(), &control, code)?;
            return Ok(());
        }
    };
    serve_valid_request(
        input.as_fd(),
        &control,
        &request,
        &runtime,
        &SystemBoundaries,
        &SystemBoundaries,
    )
}

fn serve_valid_request(
    socket: BorrowedFd<'_>,
    control: &ControlRequest,
    request: &DiagnosisRequest,
    runtime: &RuntimePaths,
    vault: &dyn VaultBoundary,
    codex: &dyn CodexBoundary,
) -> Result<(), BridgeError> {
    let lease = match vault.lease(request.request_id()) {
        Ok(lease) => lease,
        Err(code) => {
            send_closed_error(socket, control, code)?;
            return Ok(());
        }
    };
    let encoded = match codex.execute(lease.home(), request, runtime) {
        Ok(proposal) => match encode_success(request, &proposal) {
            Ok(encoded) => encoded,
            Err(_) => encode_error(control, BridgeCode::ResponseTooLarge).map_err(map_wire)?,
        },
        Err(code) => encode_error(control, code).map_err(map_wire)?,
    };
    let sent = send_frame(
        socket,
        &encoded,
        deadline_after(CONTROL_TIMEOUT).map_err(map_code)?,
    );
    // Closing the lease socket is deliberately after the complete response
    // send. Process exit then supplies the independent pidfd factor; the vault
    // itself still waits for whole-cgroup quiescence.
    drop(lease);
    sent
}

fn send_closed_error(
    socket: BorrowedFd<'_>,
    request: &ControlRequest,
    code: BridgeCode,
) -> Result<(), BridgeError> {
    let encoded = encode_error(request, code).map_err(map_wire)?;
    send_frame(
        socket,
        &encoded,
        deadline_after(CONTROL_TIMEOUT).map_err(map_code)?,
    )
}

fn vault_request_id(request_id: &str) -> Result<RequestId, BridgeCode> {
    let suffix = request_id.strip_prefix("O-").ok_or(BridgeCode::Transport)?;
    RequestId::parse(&format!("R-{suffix}")).map_err(|_| BridgeCode::Transport)
}

fn exchange_vault(
    request: &ClientRequest,
    deadline: Instant,
) -> Result<kernaid_protocol::rescue_vault_transport::ClientResponse, BridgeCode> {
    let socket = connect_vault(deadline)?;
    let authenticated =
        authenticate_root_seqpacket_server(socket.as_fd()).map_err(|_| BridgeCode::Transport)?;
    authenticated
        .send_request(request, &[], deadline)
        .map_err(|_| BridgeCode::Transport)?;
    authenticated
        .receive_response(request, deadline)
        .map_err(|_| BridgeCode::Transport)
}

fn connect_vault(deadline: Instant) -> Result<OwnedFd, BridgeCode> {
    let socket = socket_with(
        AddressFamily::UNIX,
        SocketType::SEQPACKET,
        SocketFlags::CLOEXEC | SocketFlags::NONBLOCK,
        None,
    )
    .map_err(|_| BridgeCode::Transport)?;
    let address = SocketAddrUnix::new(VAULT_SOCKET_PATH).map_err(|_| BridgeCode::Transport)?;
    match connect(&socket, &address) {
        Ok(()) => {}
        Err(error) if error == rustix::io::Errno::INPROGRESS => {
            wait_ready(socket.as_fd(), PollFlags::OUT, deadline)
                .map_err(|_| BridgeCode::Transport)?;
            rustix::net::sockopt::socket_error(&socket)
                .map_err(|_| BridgeCode::Transport)?
                .map_err(|_| BridgeCode::Transport)?;
        }
        Err(_) => return Err(BridgeCode::Transport),
    }
    Ok(socket)
}

fn validate_home(home: BorrowedFd<'_>) -> Result<(), BridgeCode> {
    let stat = rfs::fstat(home).map_err(|_| BridgeCode::Transport)?;
    let filesystem = rfs::fstatfs(home).map_err(|_| BridgeCode::Transport)?;
    let filesystem_type = u64::try_from(filesystem.f_type).map_err(|_| BridgeCode::Transport)?;
    let flags = rfs::fcntl_getfl(home).map_err(|_| BridgeCode::Transport)?;
    let descriptor_flags = rustix::io::fcntl_getfd(home).map_err(|_| BridgeCode::Transport)?;
    if !FileType::from_raw_mode(stat.st_mode).is_dir()
        || stat.st_uid != CODEX_AGENT_UID
        || stat.st_gid != CODEX_AGENT_GID
        || stat.st_mode & 0o7777 != 0o700
        || stat.st_nlink < 2
        || filesystem_type != EXT4_SUPER_MAGIC
        || flags != (OFlags::PATH | OFlags::DIRECTORY | OFlags::NOFOLLOW)
        || descriptor_flags != rustix::io::FdFlags::CLOEXEC
    {
        return Err(BridgeCode::Transport);
    }
    Ok(())
}

fn prepare_client_socket(
    socket: BorrowedFd<'_>,
    expected_local_path: Option<&[u8]>,
) -> Result<(), BridgeError> {
    let mut descriptor_flags =
        rustix::io::fcntl_getfd(socket).map_err(|_| BridgeError::InvalidSocket)?;
    descriptor_flags.insert(rustix::io::FdFlags::CLOEXEC);
    rustix::io::fcntl_setfd(socket, descriptor_flags).map_err(|_| BridgeError::InvalidSocket)?;
    let status = rfs::fcntl_getfl(socket).map_err(|_| BridgeError::InvalidSocket)?;
    rfs::fcntl_setfl(socket, status | OFlags::NONBLOCK).map_err(|_| BridgeError::InvalidSocket)?;
    let local: SocketAddrUnix = rustix::net::getsockname(socket)
        .map_err(|_| BridgeError::InvalidSocket)?
        .try_into()
        .map_err(|_| BridgeError::InvalidSocket)?;
    let peer =
        rustix::net::sockopt::socket_peercred(socket).map_err(|_| BridgeError::InvalidSocket)?;
    if rustix::net::sockopt::socket_domain(socket).map_err(|_| BridgeError::InvalidSocket)?
        != AddressFamily::UNIX
        || rustix::net::sockopt::socket_type(socket).map_err(|_| BridgeError::InvalidSocket)?
            != SocketType::SEQPACKET
        || rustix::net::sockopt::socket_acceptconn(socket)
            .map_err(|_| BridgeError::InvalidSocket)?
        || rustix::net::getpeername(socket).is_err()
        || peer.pid.as_raw_nonzero().get() <= 1
        || peer.uid.as_raw() == 0
        || peer.gid.as_raw() == 0
        || rustix::net::sockopt::socket_passcred(socket).map_err(|_| BridgeError::InvalidSocket)?
        || expected_local_path.is_some_and(|expected| local.path_bytes() != Some(expected))
    {
        return Err(BridgeError::InvalidSocket);
    }
    Ok(())
}

fn receive_control_packet(
    socket: BorrowedFd<'_>,
    deadline: Instant,
) -> Result<(Vec<u8>, Vec<OwnedFd>), BridgeError> {
    let mut bytes = vec![0_u8; MAX_CONTROL_FRAME_BYTES + 1];
    let mut io = [IoSliceMut::new(&mut bytes)];
    let mut control_space =
        [MaybeUninit::uninit(); rustix::cmsg_space!(ScmRights(2), ScmCredentials(1))];
    let mut control = RecvAncillaryBuffer::new(&mut control_space);
    let message = loop {
        ensure_before(deadline)?;
        match recvmsg(
            socket,
            &mut io,
            &mut control,
            RecvFlags::CMSG_CLOEXEC | RecvFlags::TRUNC | RecvFlags::DONTWAIT,
        ) {
            Ok(message) => break message,
            Err(error) if error == rustix::io::Errno::INTR => {}
            Err(error) if error == rustix::io::Errno::AGAIN => {
                wait_ready(socket, PollFlags::IN, deadline)?;
            }
            Err(_) => return Err(BridgeError::IoFailed),
        }
    };
    if message.flags.contains(ReturnFlags::TRUNC) || message.bytes > MAX_CONTROL_FRAME_BYTES {
        return Err(BridgeError::RequestTooLarge);
    }
    if message.flags.contains(ReturnFlags::CTRUNC) {
        return Err(BridgeError::UnexpectedAncillary);
    }
    if message.bytes == 0 {
        return Err(BridgeError::NoData);
    }
    let mut descriptors = Vec::new();
    let mut unexpected = false;
    for ancillary in control.drain() {
        match ancillary {
            RecvAncillaryMessage::ScmRights(rights) => descriptors.extend(rights),
            _ => unexpected = true,
        }
    }
    drop(control);
    if unexpected || descriptors.len() != 1 {
        return Err(BridgeError::UnexpectedAncillary);
    }
    bytes.truncate(message.bytes);
    Ok((bytes, descriptors))
}

fn read_declared_pipe(
    descriptor: BorrowedFd<'_>,
    expected: usize,
    deadline: Instant,
) -> Result<Vec<u8>, BridgeError> {
    let reader = reopen_input_pipe(descriptor)?;
    // HUP closes the declared frame at the instant it is observed. A hostile
    // peer may retain the read endpoint and reopen a writer through procfs, so
    // all subsequent reads use our independent O_NONBLOCK file description
    // and only this owned byte snapshot is used after the endpoint is closed.
    wait_pipe_hup(reader.as_fd(), deadline)?;
    let available =
        rustix::io::ioctl_fionread(reader.as_fd()).map_err(|_| BridgeError::IoFailed)?;
    if usize::try_from(available).ok() != Some(expected) {
        return Err(BridgeError::InvalidRequest);
    }
    let mut value = vec![0_u8; expected];
    let mut offset = 0_usize;
    while offset < expected {
        ensure_before(deadline)?;
        match rustix::io::read(reader.as_fd(), &mut value[offset..]) {
            Ok(0) => return Err(BridgeError::InvalidRequest),
            Ok(read) => offset = offset.saturating_add(read),
            Err(error) if error == rustix::io::Errno::INTR => {}
            Err(error) if error == rustix::io::Errno::AGAIN => {
                wait_ready(reader.as_fd(), PollFlags::IN, deadline)?;
            }
            Err(_) => return Err(BridgeError::IoFailed),
        }
    }
    let mut extra = [0_u8; 1];
    match rustix::io::read(reader.as_fd(), &mut extra) {
        Ok(0) => Ok(value),
        Ok(_) => Err(BridgeError::InvalidRequest),
        Err(error) if error == rustix::io::Errno::INTR => {
            read_declared_pipe_tail(reader.as_fd(), value, deadline)
        }
        Err(error) if error == rustix::io::Errno::AGAIN => {
            wait_ready(reader.as_fd(), PollFlags::IN, deadline)?;
            read_declared_pipe_tail(reader.as_fd(), value, deadline)
        }
        Err(_) => Err(BridgeError::IoFailed),
    }
}

fn reopen_input_pipe(descriptor: BorrowedFd<'_>) -> Result<OwnedFd, BridgeError> {
    validate_input_pipe(descriptor)?;
    let source = rfs::fstat(descriptor).map_err(|_| BridgeError::InvalidRequest)?;
    let reader = rfs::open(
        procfd(descriptor),
        OFlags::RDONLY | OFlags::NONBLOCK | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(|_| BridgeError::InvalidRequest)?;
    validate_input_pipe_status(
        reader.as_fd(),
        OFlags::RDONLY | OFlags::NONBLOCK | OFlags::LARGEFILE,
    )?;
    let reopened = rfs::fstat(&reader).map_err(|_| BridgeError::InvalidRequest)?;
    if source.st_dev != reopened.st_dev || source.st_ino != reopened.st_ino {
        return Err(BridgeError::InvalidRequest);
    }
    Ok(reader)
}

fn read_declared_pipe_tail(
    descriptor: BorrowedFd<'_>,
    value: Vec<u8>,
    deadline: Instant,
) -> Result<Vec<u8>, BridgeError> {
    loop {
        ensure_before(deadline)?;
        let mut extra = [0_u8; 1];
        match rustix::io::read(descriptor, &mut extra) {
            Ok(0) => return Ok(value),
            Ok(_) => return Err(BridgeError::InvalidRequest),
            Err(error) if error == rustix::io::Errno::INTR => {}
            Err(error) if error == rustix::io::Errno::AGAIN => {
                wait_ready(descriptor, PollFlags::IN, deadline)?;
            }
            Err(_) => return Err(BridgeError::IoFailed),
        }
    }
}

fn validate_input_pipe(descriptor: BorrowedFd<'_>) -> Result<(), BridgeError> {
    validate_input_pipe_status(descriptor, OFlags::RDONLY | OFlags::NONBLOCK)
}

fn validate_input_pipe_status(
    descriptor: BorrowedFd<'_>,
    expected_status: OFlags,
) -> Result<(), BridgeError> {
    let stat = rfs::fstat(descriptor).map_err(|_| BridgeError::InvalidRequest)?;
    let filesystem = rfs::fstatfs(descriptor).map_err(|_| BridgeError::InvalidRequest)?;
    let filesystem_type =
        u64::try_from(filesystem.f_type).map_err(|_| BridgeError::InvalidRequest)?;
    let status = rfs::fcntl_getfl(descriptor).map_err(|_| BridgeError::InvalidRequest)?;
    let descriptor_flags =
        rustix::io::fcntl_getfd(descriptor).map_err(|_| BridgeError::InvalidRequest)?;
    if !FileType::from_raw_mode(stat.st_mode).is_fifo()
        || filesystem_type != PIPEFS_MAGIC
        || status != expected_status
        || descriptor_flags != rustix::io::FdFlags::CLOEXEC
        || stat.st_size != 0
    {
        return Err(BridgeError::InvalidRequest);
    }
    Ok(())
}

fn wait_pipe_hup(descriptor: BorrowedFd<'_>, deadline: Instant) -> Result<(), BridgeError> {
    loop {
        ensure_before(deadline)?;
        let mut descriptors = [PollFd::from_borrowed_fd(descriptor, PollFlags::HUP)];
        match poll(
            &mut descriptors,
            Some(&duration_to_timespec(
                deadline.saturating_duration_since(Instant::now()),
            )),
        ) {
            Ok(0) => return Err(BridgeError::TimedOut),
            Ok(_) => {
                let events = descriptors[0].revents();
                if events.intersects(PollFlags::ERR | PollFlags::NVAL) {
                    return Err(BridgeError::InvalidRequest);
                }
                if events.contains(PollFlags::HUP) {
                    return Ok(());
                }
            }
            Err(error) if error == rustix::io::Errno::INTR => {}
            Err(_) => return Err(BridgeError::IoFailed),
        }
    }
}

fn send_frame(socket: BorrowedFd<'_>, frame: &[u8], deadline: Instant) -> Result<(), BridgeError> {
    let sent = loop {
        ensure_before(deadline)?;
        match send(socket, frame, SendFlags::DONTWAIT | SendFlags::NOSIGNAL) {
            Ok(sent) => break sent,
            Err(error) if error == rustix::io::Errno::INTR => {}
            Err(error) if error == rustix::io::Errno::AGAIN => {
                wait_ready(socket, PollFlags::OUT, deadline)?;
            }
            Err(_) => return Err(BridgeError::IoFailed),
        }
    };
    if sent == frame.len() {
        Ok(())
    } else {
        Err(BridgeError::IncompleteSend)
    }
}

struct RuntimePaths {
    _root: OwnedFd,
    work: OwnedFd,
    log: OwnedFd,
    sqlite: OwnedFd,
    expected_uid: u32,
    expected_gid: u32,
}

impl RuntimePaths {
    fn prepare_from_env() -> Result<Self, BridgeCode> {
        let raw = env::var_os("RUNTIME_DIRECTORY").ok_or(BridgeCode::ExecutionUnavailable)?;
        let path = PathBuf::from(raw);
        let text = path.to_str().ok_or(BridgeCode::ExecutionUnavailable)?;
        if !text.starts_with(RUNTIME_PREFIX)
            || text.len() <= RUNTIME_PREFIX.len()
            || text[RUNTIME_PREFIX.len()..].bytes().any(|byte| {
                !(byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b':'))
            })
        {
            return Err(BridgeCode::ExecutionUnavailable);
        }
        Self::prepare_at(&path, CODEX_AGENT_UID, CODEX_AGENT_GID)
    }

    fn prepare_at(path: &Path, expected_uid: u32, expected_gid: u32) -> Result<Self, BridgeCode> {
        let root = open_runtime_directory(path, expected_uid, expected_gid)?;
        if fs::read_dir(path)
            .map_err(|_| BridgeCode::ExecutionUnavailable)?
            .next()
            .is_some()
        {
            return Err(BridgeCode::ExecutionUnavailable);
        }
        for name in ["work", "log", "sqlite"] {
            rfs::mkdirat(&root, name, Mode::from_raw_mode(0o700))
                .map_err(|_| BridgeCode::ExecutionUnavailable)?;
        }
        let work = open_runtime_child(&root, "work", expected_uid, expected_gid)?;
        let log = open_runtime_child(&root, "log", expected_uid, expected_gid)?;
        let sqlite = open_runtime_child(&root, "sqlite", expected_uid, expected_gid)?;
        Ok(Self {
            _root: root,
            work,
            log,
            sqlite,
            expected_uid,
            expected_gid,
        })
    }

    fn write_schema(&self, schema: &[u8]) -> Result<OwnedFd, BridgeCode> {
        if schema.is_empty() || schema.len() > 64 * 1024 {
            return Err(BridgeCode::ExecutionUnavailable);
        }
        let schema_fd = rfs::memfd_create(
            "kernaid-codex-output-schema",
            MemfdFlags::CLOEXEC | MemfdFlags::ALLOW_SEALING,
        )
        .map_err(|_| BridgeCode::ExecutionUnavailable)?;
        rfs::fchmod(&schema_fd, Mode::from_raw_mode(0o600))
            .map_err(|_| BridgeCode::ExecutionUnavailable)?;
        let mut offset = 0_usize;
        while offset < schema.len() {
            match rustix::io::write(&schema_fd, &schema[offset..]) {
                Ok(0) => return Err(BridgeCode::ExecutionUnavailable),
                Ok(written) => offset = offset.saturating_add(written),
                Err(error) if error == rustix::io::Errno::INTR => {}
                Err(_) => return Err(BridgeCode::ExecutionUnavailable),
            }
        }
        let required_seals =
            SealFlags::SEAL | SealFlags::SHRINK | SealFlags::GROW | SealFlags::WRITE;
        rfs::fcntl_add_seals(&schema_fd, required_seals)
            .map_err(|_| BridgeCode::ExecutionUnavailable)?;
        let stat = rfs::fstat(&schema_fd).map_err(|_| BridgeCode::ExecutionUnavailable)?;
        let filesystem = rfs::fstatfs(&schema_fd).map_err(|_| BridgeCode::ExecutionUnavailable)?;
        if !FileType::from_raw_mode(stat.st_mode).is_file()
            || stat.st_uid != self.expected_uid
            || stat.st_gid != self.expected_gid
            || stat.st_mode & 0o7777 != 0o600
            || usize::try_from(stat.st_size).ok() != Some(schema.len())
            || u64::try_from(filesystem.f_type).ok() != Some(TMPFS_MAGIC)
            || rfs::fcntl_get_seals(&schema_fd).map_err(|_| BridgeCode::ExecutionUnavailable)?
                != required_seals
            || rustix::io::fcntl_getfd(&schema_fd).map_err(|_| BridgeCode::ExecutionUnavailable)?
                != rustix::io::FdFlags::CLOEXEC
        {
            return Err(BridgeCode::ExecutionUnavailable);
        }
        Ok(schema_fd)
    }
}

fn open_runtime_directory(
    path: &Path,
    expected_uid: u32,
    expected_gid: u32,
) -> Result<OwnedFd, BridgeCode> {
    let descriptor = rfs::open(
        path,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(|_| BridgeCode::ExecutionUnavailable)?;
    validate_runtime_directory(descriptor.as_fd(), expected_uid, expected_gid)?;
    Ok(descriptor)
}

fn open_runtime_child(
    root: &OwnedFd,
    name: &str,
    expected_uid: u32,
    expected_gid: u32,
) -> Result<OwnedFd, BridgeCode> {
    let descriptor = rfs::openat(
        root,
        name,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(|_| BridgeCode::ExecutionUnavailable)?;
    validate_runtime_directory(descriptor.as_fd(), expected_uid, expected_gid)?;
    Ok(descriptor)
}

fn validate_runtime_directory(
    descriptor: BorrowedFd<'_>,
    expected_uid: u32,
    expected_gid: u32,
) -> Result<(), BridgeCode> {
    let stat = rfs::fstat(descriptor).map_err(|_| BridgeCode::ExecutionUnavailable)?;
    let filesystem = rfs::fstatfs(descriptor).map_err(|_| BridgeCode::ExecutionUnavailable)?;
    let filesystem_type =
        u64::try_from(filesystem.f_type).map_err(|_| BridgeCode::ExecutionUnavailable)?;
    if !FileType::from_raw_mode(stat.st_mode).is_dir()
        || stat.st_uid != expected_uid
        || stat.st_gid != expected_gid
        || stat.st_mode & 0o7777 != 0o700
        || stat.st_nlink < 2
        || filesystem_type != TMPFS_MAGIC
        || rustix::io::fcntl_getfd(descriptor).map_err(|_| BridgeCode::ExecutionUnavailable)?
            != rustix::io::FdFlags::CLOEXEC
    {
        return Err(BridgeCode::ExecutionUnavailable);
    }
    Ok(())
}

fn set_inheritance(descriptors: &[BorrowedFd<'_>], cloexec: bool) -> Result<(), BridgeCode> {
    let flags = if cloexec {
        rustix::io::FdFlags::CLOEXEC
    } else {
        rustix::io::FdFlags::empty()
    };
    for (index, descriptor) in descriptors.iter().enumerate() {
        if rustix::io::fcntl_setfd(*descriptor, flags).is_err() {
            let rollback = if cloexec {
                rustix::io::FdFlags::empty()
            } else {
                rustix::io::FdFlags::CLOEXEC
            };
            for changed in &descriptors[..index] {
                let _ = rustix::io::fcntl_setfd(*changed, rollback);
            }
            return Err(BridgeCode::ExecutionUnavailable);
        }
    }
    Ok(())
}

fn procfd(descriptor: BorrowedFd<'_>) -> String {
    format!("/proc/self/fd/{}", descriptor.as_raw_fd())
}

fn build_codex_command(
    home: BorrowedFd<'_>,
    schema: BorrowedFd<'_>,
    runtime: &RuntimePaths,
) -> Command {
    let home_path = procfd(home);
    let schema_path = procfd(schema);
    let log_path = procfd(runtime.log.as_fd());
    let sqlite_path = procfd(runtime.sqlite.as_fd());
    let work_path = procfd(runtime.work.as_fd());
    let mut command = Command::new(CODEX_BINARY);
    command
        .env_clear()
        .env("PATH", "/usr/bin:/bin")
        .env("HOME", "/nonexistent")
        .env("CODEX_HOME", &home_path)
        .env("CODEX_SQLITE_HOME", &sqlite_path)
        .env("LANG", "C.UTF-8")
        .env("LC_ALL", "C.UTF-8")
        .env("RUST_LOG", "error")
        .current_dir(work_path)
        .arg("exec")
        .arg("--ephemeral")
        .arg("--ignore-user-config")
        .arg("--ignore-rules")
        .arg("--sandbox")
        .arg("read-only")
        .arg("--json")
        .arg("--output-schema")
        .arg(schema_path)
        .arg("--skip-git-repo-check")
        .arg("-c")
        .arg("cli_auth_credentials_store=\"file\"")
        .arg("-c")
        .arg(format!("log_dir=\"{log_path}\""))
        .arg("-")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null());
    command
}

fn write_child_input(
    child: &mut Child,
    prompt: &[u8],
    deadline: Instant,
) -> Result<(), BridgeCode> {
    let input = child.stdin.take().ok_or(BridgeCode::ExecutionUnavailable)?;
    let status = rfs::fcntl_getfl(input.as_fd()).map_err(|_| BridgeCode::ExecutionUnavailable)?;
    rfs::fcntl_setfl(input.as_fd(), status | OFlags::NONBLOCK)
        .map_err(|_| BridgeCode::ExecutionUnavailable)?;
    let mut offset = 0_usize;
    while offset < prompt.len() {
        if Instant::now() >= deadline {
            return Err(BridgeCode::Timeout);
        }
        match rustix::io::write(input.as_fd(), &prompt[offset..]) {
            Ok(0) => return Err(BridgeCode::ExecutionUnavailable),
            Ok(written) => offset = offset.saturating_add(written),
            Err(error) if error == rustix::io::Errno::INTR => {}
            Err(error) if error == rustix::io::Errno::AGAIN => {
                wait_ready(input.as_fd(), PollFlags::OUT, deadline).map_err(|error| {
                    if error == BridgeError::TimedOut {
                        BridgeCode::Timeout
                    } else {
                        BridgeCode::ExecutionUnavailable
                    }
                })?;
            }
            Err(_) => return Err(BridgeCode::ExecutionUnavailable),
        }
    }
    // Dropping the only parent-side writer is the prompt frame terminator.
    drop(input);
    Ok(())
}

fn read_child_output(child: &mut Child, deadline: Instant) -> Result<Vec<u8>, BridgeCode> {
    let output = child
        .stdout
        .take()
        .ok_or(BridgeCode::ExecutionUnavailable)?;
    let status = rfs::fcntl_getfl(output.as_fd()).map_err(|_| BridgeCode::ExecutionUnavailable)?;
    rfs::fcntl_setfl(output.as_fd(), status | OFlags::NONBLOCK)
        .map_err(|_| BridgeCode::ExecutionUnavailable)?;
    let mut bytes = Vec::new();
    let mut eof = false;
    while !eof {
        if Instant::now() >= deadline {
            terminate_child(child);
            return Err(BridgeCode::Timeout);
        }
        let mut buffer = [0_u8; 8192];
        match rustix::io::read(output.as_fd(), &mut buffer) {
            Ok(0) => eof = true,
            Ok(read) => {
                if bytes.len().saturating_add(read) > MAX_JSONL_BYTES {
                    terminate_child(child);
                    return Err(BridgeCode::ResponseTooLarge);
                }
                bytes.extend_from_slice(&buffer[..read]);
            }
            Err(error) if error == rustix::io::Errno::INTR => {}
            Err(error) if error == rustix::io::Errno::AGAIN => {
                let slice = deadline
                    .saturating_duration_since(Instant::now())
                    .min(Duration::from_millis(250));
                let mut descriptors = [PollFd::from_borrowed_fd(
                    output.as_fd(),
                    PollFlags::IN | PollFlags::HUP,
                )];
                match poll(&mut descriptors, Some(&duration_to_timespec(slice))) {
                    Ok(_) => {
                        if descriptors[0]
                            .revents()
                            .intersects(PollFlags::ERR | PollFlags::NVAL)
                        {
                            terminate_child(child);
                            return Err(BridgeCode::ExecutionUnavailable);
                        }
                    }
                    Err(error) if error == rustix::io::Errno::INTR => {}
                    Err(_) => {
                        terminate_child(child);
                        return Err(BridgeCode::ExecutionUnavailable);
                    }
                }
            }
            Err(_) => {
                terminate_child(child);
                return Err(BridgeCode::ExecutionUnavailable);
            }
        }
    }
    let status = wait_child(child, deadline)?;
    if !status.success() || status.signal().is_some() {
        return Err(BridgeCode::ExecutionUnavailable);
    }
    Ok(bytes)
}

fn wait_child(
    child: &mut Child,
    deadline: Instant,
) -> Result<std::process::ExitStatus, BridgeCode> {
    loop {
        match child
            .try_wait()
            .map_err(|_| BridgeCode::ExecutionUnavailable)?
        {
            Some(status) => return Ok(status),
            None => {
                let Some(remaining) = deadline.checked_duration_since(Instant::now()) else {
                    terminate_child(child);
                    return Err(BridgeCode::Timeout);
                };
                if remaining.is_zero() {
                    terminate_child(child);
                    return Err(BridgeCode::Timeout);
                }
                std::thread::sleep(remaining.min(Duration::from_millis(10)));
            }
        }
    }
}

fn terminate_child(child: &mut Child) {
    let _ = child.kill();
    let deadline = Instant::now().checked_add(CHILD_CLEANUP_TIMEOUT);
    loop {
        match child.try_wait() {
            Ok(Some(_)) | Err(_) => return,
            Ok(None) => {}
        }
        let Some(remaining) =
            deadline.and_then(|value| value.checked_duration_since(Instant::now()))
        else {
            return;
        };
        if remaining.is_zero() {
            return;
        }
        std::thread::sleep(remaining.min(Duration::from_millis(10)));
    }
}

fn deadline_after(duration: Duration) -> Result<Instant, BridgeCode> {
    Instant::now()
        .checked_add(duration)
        .ok_or(BridgeCode::Timeout)
}

fn ensure_before(deadline: Instant) -> Result<(), BridgeError> {
    deadline
        .checked_duration_since(Instant::now())
        .filter(|remaining| !remaining.is_zero())
        .map(|_| ())
        .ok_or(BridgeError::TimedOut)
}

fn wait_ready(
    descriptor: BorrowedFd<'_>,
    interest: PollFlags,
    deadline: Instant,
) -> Result<(), BridgeError> {
    loop {
        ensure_before(deadline)?;
        let remaining = deadline.saturating_duration_since(Instant::now());
        let mut descriptors = [PollFd::from_borrowed_fd(descriptor, interest)];
        match poll(&mut descriptors, Some(&duration_to_timespec(remaining))) {
            Ok(0) => return Err(BridgeError::TimedOut),
            Ok(_) => {
                let ready = descriptors[0].revents();
                if ready.contains(PollFlags::NVAL) {
                    return Err(BridgeError::IoFailed);
                }
                if ready.intersects(interest | PollFlags::ERR | PollFlags::HUP) {
                    return Ok(());
                }
            }
            Err(error) if error == rustix::io::Errno::INTR => {}
            Err(_) => return Err(BridgeError::IoFailed),
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

fn map_wire(error: WireError) -> BridgeError {
    match error {
        WireError::InvalidSize | WireError::InvalidFrame | WireError::InvalidRequest => {
            BridgeError::InvalidRequest
        }
        WireError::ResponseTooLarge => BridgeError::RequestTooLarge,
    }
}

fn map_code(code: BridgeCode) -> BridgeError {
    match code {
        BridgeCode::Timeout => BridgeError::TimedOut,
        BridgeCode::InvalidRequest => BridgeError::InvalidRequest,
        BridgeCode::RequestTooLarge => BridgeError::RequestTooLarge,
        BridgeCode::Busy
        | BridgeCode::CredentialUnavailable
        | BridgeCode::ExecutionUnavailable
        | BridgeCode::InvalidResponse
        | BridgeCode::ResponseTooLarge
        | BridgeCode::Transport => BridgeError::IoFailed,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::wire::{API_VERSION, INPUT_DESCRIPTOR_KIND, OPERATION};
    use rustix::{
        net::{
            AddressFamily, SendAncillaryBuffer, SendAncillaryMessage, SocketFlags, SocketType,
            sendmsg, socketpair,
        },
        pipe::{PipeFlags, pipe_with},
    };
    use std::{
        io::IoSlice,
        os::unix::fs::PermissionsExt,
        sync::{
            Arc,
            atomic::{AtomicBool, Ordering},
        },
    };

    const REQUEST_ID: &str = "O-33333333-3333-3333-3333-333333333333";
    const INPUT: &[u8] = include_bytes!(
        "../../../packages/schemas/fixtures/rescue-openai/valid/linux-generic-canary.request.raw"
    );

    struct FakeLease {
        home: OwnedFd,
        dropped: Arc<AtomicBool>,
    }

    impl HomeLease for FakeLease {
        fn home(&self) -> BorrowedFd<'_> {
            self.home.as_fd()
        }
    }

    impl Drop for FakeLease {
        fn drop(&mut self) {
            self.dropped.store(true, Ordering::Release);
        }
    }

    struct FakeVault {
        home: fs::File,
        dropped: Arc<AtomicBool>,
    }

    impl VaultBoundary for FakeVault {
        fn lease(&self, _: &str) -> Result<Box<dyn HomeLease>, BridgeCode> {
            let home = rustix::io::fcntl_dupfd_cloexec(&self.home, 3)
                .map_err(|_| BridgeCode::Transport)?;
            Ok(Box::new(FakeLease {
                home,
                dropped: Arc::clone(&self.dropped),
            }))
        }
    }

    struct FakeCodex {
        dropped: Arc<AtomicBool>,
    }

    impl CodexBoundary for FakeCodex {
        fn execute(
            &self,
            _: BorrowedFd<'_>,
            request: &DiagnosisRequest,
            _: &RuntimePaths,
        ) -> Result<DiagnosisProposal, BridgeCode> {
            assert!(!self.dropped.load(Ordering::Acquire));
            Ok(request.context().deterministic_proposal().clone())
        }
    }

    fn control_frame() -> Vec<u8> {
        let mut value = serde_json::to_vec(&serde_json::json!({
            "apiVersion": API_VERSION,
            "requestId": REQUEST_ID,
            "operation": OPERATION,
            "payload": {
                "input": {
                    "kind": INPUT_DESCRIPTOR_KIND,
                    "size": INPUT.len()
                }
            }
        }))
        .expect("control JSON");
        value.push(b'\n');
        value
    }

    fn runtime() -> (tempfile::TempDir, RuntimePaths) {
        let directory = tempfile::Builder::new()
            .prefix("kernaid-codex-runtime-")
            .tempdir_in("/dev/shm")
            .expect("tmpfs runtime");
        fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700))
            .expect("runtime permissions");
        let runtime = RuntimePaths::prepare_at(
            directory.path(),
            rustix::process::getuid().as_raw(),
            rustix::process::getgid().as_raw(),
        )
        .expect("runtime paths");
        (directory, runtime)
    }

    #[test]
    fn command_is_pinned_scrubbed_and_descriptor_bound() {
        let home = tempfile::tempdir_in("/dev/shm").expect("home");
        let home_fd = rfs::open(
            home.path(),
            OFlags::PATH | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .expect("home fd");
        let (_directory, runtime) = runtime();
        let schema = runtime.write_schema(b"{}").expect("schema");
        assert_eq!(
            rfs::fcntl_get_seals(&schema).expect("schema seals"),
            SealFlags::SEAL | SealFlags::SHRINK | SealFlags::GROW | SealFlags::WRITE
        );
        assert_eq!(
            rustix::io::write(&schema, b"x").err(),
            Some(rustix::io::Errno::PERM)
        );
        let command = build_codex_command(home_fd.as_fd(), schema.as_fd(), &runtime);
        assert_eq!(command.get_program(), CODEX_BINARY);
        let args = command
            .get_args()
            .map(|arg| arg.to_string_lossy().into_owned())
            .collect::<Vec<_>>();
        let expected_args = vec![
            "exec".to_owned(),
            "--ephemeral".to_owned(),
            "--ignore-user-config".to_owned(),
            "--ignore-rules".to_owned(),
            "--sandbox".to_owned(),
            "read-only".to_owned(),
            "--json".to_owned(),
            "--output-schema".to_owned(),
            procfd(schema.as_fd()),
            "--skip-git-repo-check".to_owned(),
            "-c".to_owned(),
            "cli_auth_credentials_store=\"file\"".to_owned(),
            "-c".to_owned(),
            format!("log_dir=\"{}\"", procfd(runtime.log.as_fd())),
            "-".to_owned(),
        ];
        assert_eq!(args, expected_args);
        let variables = command
            .get_envs()
            .map(|(name, value)| {
                (
                    name.to_string_lossy().into_owned(),
                    value.map(|value| value.to_string_lossy().into_owned()),
                )
            })
            .collect::<Vec<_>>();
        assert_eq!(variables.len(), 7);
        let expected_home = procfd(home_fd.as_fd());
        assert!(variables.iter().any(|(name, value)| {
            name == "CODEX_HOME" && value.as_deref() == Some(expected_home.as_str())
        }));
        assert!(!variables.iter().any(|(name, _)| {
            matches!(
                name.as_str(),
                "OPENAI_API_KEY" | "CODEX_API_KEY" | "CODEX_ACCESS_TOKEN"
            )
        }));
        assert_eq!(CODEX_CLI_VERSION, "0.147.0");
    }

    #[test]
    fn successful_response_is_sent_before_lease_drop() {
        if rustix::process::getuid().as_raw() == 0 {
            return;
        }
        let (server, client) = socketpair(
            AddressFamily::UNIX,
            SocketType::SEQPACKET,
            SocketFlags::CLOEXEC,
            None,
        )
        .expect("socketpair");
        prepare_client_socket(server.as_fd(), None).expect("server socket");

        let (reader, writer) = pipe_with(PipeFlags::CLOEXEC | PipeFlags::NONBLOCK).expect("pipe");
        assert_eq!(
            rustix::io::write(&writer, INPUT).expect("write input"),
            INPUT.len()
        );
        drop(writer);
        let frame = control_frame();
        let io = [IoSlice::new(&frame)];
        let rights = [reader.as_fd()];
        let mut ancillary_space = [MaybeUninit::uninit(); rustix::cmsg_space!(ScmRights(1))];
        let mut ancillary = SendAncillaryBuffer::new(&mut ancillary_space);
        assert!(ancillary.push(SendAncillaryMessage::ScmRights(&rights)));
        assert_eq!(
            sendmsg(&client, &io, &mut ancillary, SendFlags::NOSIGNAL).expect("send request"),
            frame.len()
        );

        let (received, mut descriptors) = receive_control_packet(
            server.as_fd(),
            deadline_after(CONTROL_TIMEOUT).expect("deadline"),
        )
        .expect("receive control");
        let control = parse_control_frame(&received).expect("parse control");
        let descriptor = descriptors.pop().expect("input fd");
        let input = read_declared_pipe(
            descriptor.as_fd(),
            control.input_size(),
            deadline_after(CONTROL_TIMEOUT).expect("deadline"),
        )
        .expect("read input");
        let request = parse_diagnosis_input(&control, &input).expect("diagnosis");
        let home = tempfile::tempdir_in("/dev/shm").expect("home");
        let home_file = fs::File::open(home.path()).expect("home file");
        let dropped = Arc::new(AtomicBool::new(false));
        let vault = FakeVault {
            home: home_file,
            dropped: Arc::clone(&dropped),
        };
        let codex = FakeCodex {
            dropped: Arc::clone(&dropped),
        };
        let (_directory, runtime) = runtime();
        serve_valid_request(server.as_fd(), &control, &request, &runtime, &vault, &codex)
            .expect("serve");
        assert!(dropped.load(Ordering::Acquire));

        let mut response = [0_u8; 64 * 1024];
        let read = rustix::io::read(&client, &mut response).expect("read response");
        let value: serde_json::Value =
            serde_json::from_slice(&response[..read - 1]).expect("response JSON");
        assert_eq!(value.get("ok"), Some(&serde_json::Value::Bool(true)));
        assert_eq!(
            value.pointer("/payload/proposal/evidenceIds/0"),
            Some(&serde_json::Value::String("E-RESCUE-CORPUS".to_owned()))
        );
    }

    #[test]
    fn control_packet_requires_exactly_one_descriptor() {
        if rustix::process::getuid().as_raw() == 0 {
            return;
        }
        for descriptor_count in [0_usize, 2] {
            let (server, client) = socketpair(
                AddressFamily::UNIX,
                SocketType::SEQPACKET,
                SocketFlags::CLOEXEC,
                None,
            )
            .expect("socketpair");
            prepare_client_socket(server.as_fd(), None).expect("server socket");
            let frame = control_frame();
            let io = [IoSlice::new(&frame)];
            let (first, first_writer) =
                pipe_with(PipeFlags::CLOEXEC | PipeFlags::NONBLOCK).expect("first pipe");
            let (second, second_writer) =
                pipe_with(PipeFlags::CLOEXEC | PipeFlags::NONBLOCK).expect("second pipe");
            let rights = [first.as_fd(), second.as_fd()];
            let mut ancillary_space = [MaybeUninit::uninit(); rustix::cmsg_space!(ScmRights(2))];
            let mut ancillary = SendAncillaryBuffer::new(&mut ancillary_space);
            if descriptor_count != 0 {
                assert!(
                    ancillary.push(SendAncillaryMessage::ScmRights(&rights[..descriptor_count]))
                );
            }
            assert_eq!(
                sendmsg(&client, &io, &mut ancillary, SendFlags::NOSIGNAL).expect("send request"),
                frame.len()
            );
            drop((first_writer, second_writer));
            assert_eq!(
                receive_control_packet(
                    server.as_fd(),
                    deadline_after(CONTROL_TIMEOUT).expect("deadline")
                )
                .err(),
                Some(BridgeError::UnexpectedAncillary),
                "descriptor count {descriptor_count}"
            );
        }
    }

    #[test]
    fn input_pipe_requires_closed_writer_and_exact_declared_bytes() {
        let (reader, writer) = pipe_with(PipeFlags::CLOEXEC | PipeFlags::NONBLOCK).expect("pipe");
        assert_eq!(rustix::io::write(&writer, b"abc").expect("write"), 3);
        let deadline = Instant::now()
            .checked_add(Duration::from_millis(20))
            .expect("deadline");
        assert_eq!(
            read_declared_pipe(reader.as_fd(), 3, deadline),
            Err(BridgeError::TimedOut)
        );
        drop(writer);
        assert_eq!(
            read_declared_pipe(
                reader.as_fd(),
                2,
                deadline_after(CONTROL_TIMEOUT).expect("deadline")
            ),
            Err(BridgeError::InvalidRequest)
        );
    }

    #[test]
    fn input_pipe_snapshot_has_independent_nonblocking_status() {
        let (reader, writer) = pipe_with(PipeFlags::CLOEXEC | PipeFlags::NONBLOCK).expect("pipe");
        let private_reader = reopen_input_pipe(reader.as_fd()).expect("private reader");
        let mut peer_status = rfs::fcntl_getfl(&reader).expect("peer status");
        peer_status.remove(OFlags::NONBLOCK);
        rfs::fcntl_setfl(&reader, peer_status).expect("clear peer nonblocking status");
        assert_eq!(
            rfs::fcntl_getfl(&private_reader).expect("private status"),
            OFlags::RDONLY | OFlags::NONBLOCK | OFlags::LARGEFILE
        );
        drop(writer);
    }

    #[test]
    fn prompt_pipe_write_is_deadline_bounded() {
        let mut child = Command::new("/bin/sh")
            .args(["-c", "exec /bin/sleep 1"])
            .stdin(Stdio::piped())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("spawn non-reader");
        let prompt = vec![b'x'; 4 * 1024 * 1024];
        let deadline = Instant::now()
            .checked_add(Duration::from_millis(20))
            .expect("deadline");
        assert_eq!(
            write_child_input(&mut child, &prompt, deadline),
            Err(BridgeCode::Timeout)
        );
        terminate_child(&mut child);
    }

    #[test]
    fn lock_matches_pinned_binary_and_nonshipping_path() {
        let lock: serde_json::Value =
            serde_json::from_str(include_str!("../../../rescue/codex/codex-cli.lock.json"))
                .expect("Codex lock");
        assert_eq!(
            lock.pointer("/upstream/version")
                .and_then(serde_json::Value::as_str),
            Some(CODEX_CLI_VERSION)
        );
        assert_eq!(
            lock.pointer("/artifact/binary/installPath")
                .and_then(serde_json::Value::as_str),
            Some(CODEX_BINARY)
        );
        assert_eq!(
            lock.pointer("/artifact/binary/versionOutput")
                .and_then(serde_json::Value::as_str),
            Some("codex-cli 0.147.0\n")
        );
    }
}
