use kernaid_protocol::{
    rescue_vault::{DescriptorType, ErrorToken, RequestId, SuccessPayload, VaultState},
    rescue_vault_transport::{
        ClientRequest, ClientRequestPayload, ClientResponseOutcome,
        authenticate_root_seqpacket_server,
    },
};
use rand_core::{OsRng, RngCore};
use rustix::{
    event::{PollFd, PollFlags, Timespec, poll},
    fd::{AsFd, BorrowedFd, OwnedFd},
    fs::{self as rfs, AtFlags, FileType, Mode, OFlags, ResolveFlags},
    net::{
        AddressFamily, RecvAncillaryBuffer, RecvAncillaryMessage, RecvFlags, ReturnFlags,
        SendFlags, SocketAddrUnix, SocketFlags, SocketType, connect, recvmsg, send, socket_with,
    },
    process::{DumpableBehavior, Pid, Signal, dumpable_behavior, set_dumpable_behavior},
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    ffi::{OsStr, OsString},
    fs::File,
    io::{self, IoSliceMut, Read, Write},
    mem::MaybeUninit,
    os::{fd::AsRawFd, unix::process::CommandExt},
    path::PathBuf,
    process::{Child, Command, ExitStatus, Stdio},
    sync::{Mutex, mpsc},
    thread,
    time::{Duration, Instant},
};
use zeroize::{Zeroize, Zeroizing};

const API_VERSION: &str = "kernaid.dev/rescue-codex-auth/v1alpha1";
const BRIDGE_SOCKET_PATH: &str = "/run/kernaid-rescue-codex.sock";
const VAULT_SOCKET_PATH: &str = "/run/kernaid-rescue-vault.sock";
const SHIPPING_CODEX_PATH: &str = "/usr/lib/kernaid/codex";
const SHIPPING_CODEX_SIZE: u64 = 258_278_208;
const SHIPPING_CODEX_SHA256: &str =
    "cb0a15567e9a60a5820d54b0f6ae86d504dc3805c1eab21a47f70e3eb7b73a40";
const CODEX_UID: u32 = 973;
const CODEX_GID: u32 = 973;
const LIVE_USER_UID: u32 = 1000;
const EXT4_SUPER_MAGIC: u64 = 0xef53;
const HOME_CONFIG: &[u8] = b"cli_auth_credentials_store = \"file\"\n";
const DEVICE_VERIFICATION_URL: &str = "https://auth.openai.com/codex/device";
const MAX_REQUEST_BYTES: usize = 1024;
const MAX_RESPONSE_BYTES: usize = 2048;
const MAX_CLI_OUTPUT_BYTES: usize = 32 * 1024;
const MAX_AUTH_FILE_BYTES: u64 = 128 * 1024;
const MAX_LOGIN_LOG_BYTES: u64 = 1024 * 1024;
const REQUEST_TIMEOUT: Duration = Duration::from_secs(5);
const VAULT_TIMEOUT: Duration = Duration::from_secs(20);
const STATUS_TIMEOUT: Duration = Duration::from_secs(15);
const LOGOUT_TIMEOUT: Duration = Duration::from_secs(45);
const DEVICE_LOGIN_TIMEOUT: Duration = Duration::from_secs(16 * 60);
const PROCESS_POLL_INTERVAL: Duration = Duration::from_millis(25);
const PROCESS_STOP_GRACE: Duration = Duration::from_secs(2);
const CHILD_DESCRIPTOR_MINIMUM: i32 = 8;
static SPAWN_LOCK: Mutex<()> = Mutex::new(());

#[derive(Clone, Copy, Debug, Deserialize, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
enum Operation {
    DeviceLogin,
    Status,
    Logout,
}

impl Operation {
    fn cli_arguments(self) -> &'static [&'static str] {
        match self {
            Self::DeviceLogin => &["login", "--device-auth"],
            Self::Status => &["login", "status"],
            Self::Logout => &["logout"],
        }
    }

    fn timeout(self) -> Duration {
        match self {
            Self::DeviceLogin => DEVICE_LOGIN_TIMEOUT,
            Self::Status => STATUS_TIMEOUT,
            Self::Logout => LOGOUT_TIMEOUT,
        }
    }
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Request {
    api_version: String,
    request_id: String,
    operation: Operation,
}

#[derive(Clone, Copy, Debug, Deserialize, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
enum AuthStatus {
    AuthenticatedChatgpt,
    AuthenticatedApiKey,
    AuthenticatedAccessToken,
    SignedOut,
    AlreadySignedOut,
}

#[derive(Clone, Copy, Debug, Deserialize, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
enum SafeError {
    VaultLocked,
    VaultUnconfigured,
    Busy,
    RebootRequired,
    Transport,
    CliUnavailable,
    CliFailed,
    TimedOut,
    UnsafeHome,
    UnsafeExecutable,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct Response<'request> {
    api_version: &'static str,
    request_id: &'request str,
    operation: Operation,
    #[serde(flatten)]
    payload: ResponsePayload<'request>,
}

#[derive(Debug, Serialize)]
#[serde(tag = "stage", rename_all = "kebab-case")]
enum ResponsePayload<'value> {
    DeviceCode {
        #[serde(rename = "verificationUrl")]
        verification_url: &'value str,
        #[serde(rename = "userCode")]
        user_code: &'value str,
    },
    Complete {
        status: AuthStatus,
    },
    Error {
        code: SafeError,
    },
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ReceivedResponse {
    api_version: String,
    request_id: String,
    operation: Operation,
    stage: String,
    #[serde(default)]
    verification_url: Option<String>,
    #[serde(default)]
    user_code: Option<String>,
    #[serde(default)]
    status: Option<AuthStatus>,
    #[serde(default)]
    code: Option<SafeError>,
}

impl ReceivedResponse {
    fn validate(&self, request: &Request) -> Result<(), ()> {
        if self.api_version != API_VERSION
            || self.request_id != request.request_id
            || self.operation != request.operation
        {
            return Err(());
        }
        match self.stage.as_str() {
            "device-code" => {
                if request.operation != Operation::DeviceLogin
                    || self.verification_url.as_deref() != Some(DEVICE_VERIFICATION_URL)
                    || !self.user_code.as_deref().is_some_and(valid_device_code)
                    || self.status.is_some()
                    || self.code.is_some()
                {
                    return Err(());
                }
            }
            "complete" => {
                if self.verification_url.is_some()
                    || self.user_code.is_some()
                    || self.status.is_none()
                    || self.code.is_some()
                    || !matches!(
                        (request.operation, self.status),
                        (
                            Operation::DeviceLogin,
                            Some(AuthStatus::AuthenticatedChatgpt)
                        ) | (
                            Operation::Status,
                            Some(
                                AuthStatus::AuthenticatedChatgpt
                                    | AuthStatus::AuthenticatedApiKey
                                    | AuthStatus::AuthenticatedAccessToken
                                    | AuthStatus::SignedOut
                            )
                        ) | (
                            Operation::Logout,
                            Some(AuthStatus::SignedOut | AuthStatus::AlreadySignedOut)
                        )
                    )
                {
                    return Err(());
                }
            }
            "error" => {
                if self.verification_url.is_some()
                    || self.user_code.is_some()
                    || self.status.is_some()
                    || self.code.is_none()
                {
                    return Err(());
                }
            }
            _ => return Err(()),
        }
        Ok(())
    }

    fn terminal(&self) -> bool {
        self.stage != "device-code"
    }
}

#[derive(Clone)]
struct CliPolicy {
    path: PathBuf,
    size: u64,
    sha256: String,
    uid: u32,
    gid: u32,
    mode: u32,
}

impl CliPolicy {
    fn shipping() -> Self {
        Self {
            path: PathBuf::from(SHIPPING_CODEX_PATH),
            size: SHIPPING_CODEX_SIZE,
            sha256: SHIPPING_CODEX_SHA256.to_owned(),
            uid: 0,
            gid: 0,
            mode: 0o755,
        }
    }
}

#[derive(Clone, Copy)]
struct HomePolicy {
    uid: u32,
    gid: u32,
    require_ext4: bool,
}

impl HomePolicy {
    fn shipping() -> Self {
        Self {
            uid: CODEX_UID,
            gid: CODEX_GID,
            require_ext4: true,
        }
    }
}

struct HomeLease {
    _control: OwnedFd,
    home: OwnedFd,
}

/// Deliberately opaque public failure: callers receive no CLI or credential material.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BridgeError;

trait Responder {
    fn send(&mut self, payload: &ResponsePayload<'_>) -> Result<(), ()>;
}

struct SocketResponder<'socket> {
    socket: BorrowedFd<'socket>,
    request: &'socket Request,
}

impl Responder for SocketResponder<'_> {
    fn send(&mut self, payload: &ResponsePayload<'_>) -> Result<(), ()> {
        let response = Response {
            api_version: API_VERSION,
            request_id: &self.request.request_id,
            operation: self.request.operation,
            payload: match payload {
                ResponsePayload::DeviceCode {
                    verification_url,
                    user_code,
                } => ResponsePayload::DeviceCode {
                    verification_url,
                    user_code,
                },
                ResponsePayload::Complete { status } => {
                    ResponsePayload::Complete { status: *status }
                }
                ResponsePayload::Error { code } => ResponsePayload::Error { code: *code },
            },
        };
        let mut frame = serde_json::to_vec(&response).map_err(|_| ())?;
        frame.push(b'\n');
        if frame.len() > MAX_RESPONSE_BYTES
            || send(
                self.socket,
                &frame,
                SendFlags::NOSIGNAL | SendFlags::DONTWAIT,
            )
            .map_err(|_| ())?
                != frame.len()
        {
            return Err(());
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ExecutionError {
    CliUnavailable,
    CliFailed,
    TimedOut,
    UnsafeHome,
    UnsafeExecutable,
    ClientGone,
}

impl ExecutionError {
    fn safe(self) -> SafeError {
        match self {
            Self::CliUnavailable => SafeError::CliUnavailable,
            Self::CliFailed => SafeError::CliFailed,
            Self::TimedOut => SafeError::TimedOut,
            Self::UnsafeHome => SafeError::UnsafeHome,
            Self::UnsafeExecutable => SafeError::UnsafeExecutable,
            Self::ClientGone => SafeError::Transport,
        }
    }
}

/// Run one socket-activated authentication operation.
pub fn run_socket_activated_once() -> Result<(), BridgeError> {
    run_socket_activated_once_inner().map_err(|()| BridgeError)
}

fn run_socket_activated_once_inner() -> Result<(), ()> {
    if rustix::process::geteuid().as_raw() != CODEX_UID
        || rustix::process::getegid().as_raw() != CODEX_GID
        || set_dumpable_behavior(DumpableBehavior::NotDumpable).is_err()
        || dumpable_behavior().ok() != Some(DumpableBehavior::NotDumpable)
    {
        return Err(());
    }
    let stdin = std::io::stdin();
    let socket = rustix::io::fcntl_dupfd_cloexec(stdin.as_fd(), 3).map_err(|_| ())?;
    validate_server_socket(socket.as_fd())?;
    let request = receive_request(socket.as_fd())?;
    let mut responder = SocketResponder {
        socket: socket.as_fd(),
        request: &request,
    };
    let deadline = Instant::now().checked_add(VAULT_TIMEOUT).ok_or(())?;
    let lease = match lease_home(&request.request_id, deadline) {
        Ok(lease) => lease,
        Err(code) => {
            responder.send(&ResponsePayload::Error { code })?;
            return Ok(());
        }
    };
    let outcome = execute_with_home(
        request.operation,
        &lease.home,
        &CliPolicy::shipping(),
        HomePolicy::shipping(),
        &mut responder,
    );
    drop(lease);
    if let Err(error) = outcome {
        if error != ExecutionError::ClientGone {
            responder.send(&ResponsePayload::Error { code: error.safe() })?;
        }
    }
    Ok(())
}

fn validate_server_socket(socket: BorrowedFd<'_>) -> Result<(), ()> {
    let socket_type = rustix::net::sockopt::socket_type(socket).map_err(|_| ())?;
    let peer = rustix::net::sockopt::socket_peercred(socket).map_err(|_| ())?;
    let flags = rustix::io::fcntl_getfd(socket).map_err(|_| ())?;
    if socket_type != SocketType::SEQPACKET
        || peer.uid.as_raw() != LIVE_USER_UID
        || !flags.contains(rustix::io::FdFlags::CLOEXEC)
    {
        return Err(());
    }
    Ok(())
}

fn receive_request(socket: BorrowedFd<'_>) -> Result<Request, ()> {
    let deadline = Instant::now().checked_add(REQUEST_TIMEOUT).ok_or(())?;
    wait_ready(socket, PollFlags::IN, deadline)?;
    let mut bytes = [0_u8; MAX_REQUEST_BYTES + 1];
    let mut io = [IoSliceMut::new(&mut bytes)];
    let mut ancillary_space =
        [MaybeUninit::uninit(); rustix::cmsg_space!(ScmRights(2), ScmCredentials(1))];
    let mut ancillary = RecvAncillaryBuffer::new(&mut ancillary_space);
    let message = recvmsg(
        socket,
        &mut io,
        &mut ancillary,
        RecvFlags::CMSG_CLOEXEC | RecvFlags::TRUNC | RecvFlags::DONTWAIT,
    )
    .map_err(|_| ())?;
    let unexpected = ancillary.drain().any(|item| {
        matches!(
            item,
            RecvAncillaryMessage::ScmRights(_) | RecvAncillaryMessage::ScmCredentials(_)
        )
    });
    drop(ancillary);
    if unexpected
        || message.bytes == 0
        || message.bytes > MAX_REQUEST_BYTES
        || message
            .flags
            .intersects(ReturnFlags::TRUNC | ReturnFlags::CTRUNC)
    {
        return Err(());
    }
    let request: Request = serde_json::from_slice(&bytes[..message.bytes]).map_err(|_| ())?;
    if request.api_version != API_VERSION || !valid_request_id(&request.request_id) {
        return Err(());
    }
    Ok(request)
}

fn lease_home(request_id: &str, deadline: Instant) -> Result<HomeLease, SafeError> {
    let suffix = request_id.strip_prefix("C-").ok_or(SafeError::Transport)?;
    let vault_id = RequestId::parse(&format!("R-{suffix}")).map_err(|_| SafeError::Transport)?;
    let status_request = ClientRequest::new(vault_id.clone(), 0, ClientRequestPayload::VaultStatus)
        .map_err(|_| SafeError::Transport)?;
    let status_socket = connect_vault(deadline)?;
    let authenticated = authenticate_root_seqpacket_server(status_socket.as_fd())
        .map_err(|_| SafeError::Transport)?;
    authenticated
        .send_request(&status_request, &[], deadline)
        .map_err(|_| SafeError::Transport)?;
    let status_response = authenticated
        .receive_response(&status_request, deadline)
        .map_err(|_| SafeError::Transport)?;
    let state_version = status_response.state_version();
    match status_response.outcome() {
        ClientResponseOutcome::Success(SuccessPayload::VaultStatus(status))
            if status.vault_state() == VaultState::Unlocked => {}
        ClientResponseOutcome::Success(SuccessPayload::VaultStatus(_)) => {
            return Err(SafeError::VaultLocked);
        }
        ClientResponseOutcome::Error(error) => return Err(map_vault_error(*error)),
        _ => return Err(SafeError::Transport),
    }
    drop(status_socket);

    let request = ClientRequest::new(
        vault_id,
        state_version,
        ClientRequestPayload::ProviderCodexHomeLease,
    )
    .map_err(|_| SafeError::Transport)?;
    let socket = connect_vault(deadline)?;
    let authenticated =
        authenticate_root_seqpacket_server(socket.as_fd()).map_err(|_| SafeError::Transport)?;
    authenticated
        .send_request(&request, &[], deadline)
        .map_err(|_| SafeError::Transport)?;
    let mut response = authenticated
        .receive_response(&request, deadline)
        .map_err(|_| SafeError::Transport)?;
    if response.state_version() != state_version {
        return Err(SafeError::Transport);
    }
    match response.outcome() {
        ClientResponseOutcome::Success(SuccessPayload::Descriptor(declaration))
            if declaration.kind == DescriptorType::CodexHomeOPath && declaration.size == 0 => {}
        ClientResponseOutcome::Error(error) => return Err(map_vault_error(*error)),
        _ => return Err(SafeError::Transport),
    }
    let home = response.take_descriptor().ok_or(SafeError::Transport)?;
    Ok(HomeLease {
        _control: socket,
        home,
    })
}

fn map_vault_error(error: ErrorToken) -> SafeError {
    match error {
        ErrorToken::Busy | ErrorToken::StaleState | ErrorToken::RateLimited => SafeError::Busy,
        ErrorToken::ProviderUnconfigured => SafeError::VaultUnconfigured,
        ErrorToken::RebootRequired => SafeError::RebootRequired,
        ErrorToken::Absent
        | ErrorToken::Unprovisioned
        | ErrorToken::Locked
        | ErrorToken::BadPassphrase => SafeError::VaultLocked,
        ErrorToken::MediaChanged
        | ErrorToken::ProfileMismatch
        | ErrorToken::FdRequired
        | ErrorToken::FdForbidden
        | ErrorToken::NotAuthorized
        | ErrorToken::ReportTooLarge
        | ErrorToken::IoFailed => SafeError::Transport,
    }
}

fn connect_vault(deadline: Instant) -> Result<OwnedFd, SafeError> {
    let socket = socket_with(
        AddressFamily::UNIX,
        SocketType::SEQPACKET,
        SocketFlags::CLOEXEC | SocketFlags::NONBLOCK,
        None,
    )
    .map_err(|_| SafeError::Transport)?;
    let address = SocketAddrUnix::new(VAULT_SOCKET_PATH).map_err(|_| SafeError::Transport)?;
    match connect(&socket, &address) {
        Ok(()) => {}
        Err(error) if error == rustix::io::Errno::INPROGRESS => {
            wait_ready(socket.as_fd(), PollFlags::OUT, deadline)
                .map_err(|_| SafeError::Transport)?;
            rustix::net::sockopt::socket_error(&socket)
                .map_err(|_| SafeError::Transport)?
                .map_err(|_| SafeError::Transport)?;
        }
        Err(_) => return Err(SafeError::Transport),
    }
    Ok(socket)
}

fn execute_with_home(
    operation: Operation,
    home: &OwnedFd,
    cli: &CliPolicy,
    home_policy: HomePolicy,
    responder: &mut dyn Responder,
) -> Result<(), ExecutionError> {
    validate_home(home, home_policy)?;
    let mut child = spawn_cli(operation, home, cli)?;
    let deadline = Instant::now()
        .checked_add(operation.timeout())
        .ok_or(ExecutionError::TimedOut)?;
    let outcome = collect_cli(operation, &mut child, deadline, responder);
    if outcome.is_err() {
        terminate_child_group(&mut child);
    } else {
        // A successful direct child is already reaped, but a helper that
        // closed both pipes must not outlive the authentication operation.
        let _ = rustix::process::kill_process_group(Pid::from_child(&child), Signal::KILL);
    }
    // Re-attest persistent state even when the CLI timed out, exceeded an
    // output bound, or lost its client. An interrupted official command may
    // have changed its credential store before the operational error.
    validate_home(home, home_policy)?;
    let (status, mut stdout, mut stderr) = outcome?;
    let result = classify_cli_result(operation, status, &stdout, &stderr);
    stdout.zeroize();
    stderr.zeroize();
    let status = result?;
    responder
        .send(&ResponsePayload::Complete { status })
        .map_err(|_| ExecutionError::ClientGone)
}

fn spawn_cli(
    operation: Operation,
    home: &OwnedFd,
    policy: &CliPolicy,
) -> Result<Child, ExecutionError> {
    let executable = open_verified_executable(policy)?;
    let inherited_home = rustix::io::fcntl_dupfd_cloexec(home, CHILD_DESCRIPTOR_MINIMUM)
        .map_err(|_| ExecutionError::UnsafeHome)?;
    let inherited_executable =
        rustix::io::fcntl_dupfd_cloexec(&executable, CHILD_DESCRIPTOR_MINIMUM)
            .map_err(|_| ExecutionError::UnsafeExecutable)?;
    let home_path = format!("/proc/self/fd/{}", inherited_home.as_raw_fd());
    let executable_path = format!("/proc/self/fd/{}", inherited_executable.as_raw_fd());
    let mut command = Command::new(executable_path);
    command
        .args(operation.cli_arguments())
        .env_clear()
        .env("CODEX_HOME", &home_path)
        .env("HOME", "/nonexistent")
        .env("LANG", "C")
        .env("LC_ALL", "C")
        .env("RUST_LOG", "off")
        .env("TERM", "dumb")
        // The pinned CLI explicitly refuses to create its tool aliases when
        // CODEX_HOME is beneath the process temp root. Every absolute home is
        // beneath `/`; this keeps auth-only runs from adding executable
        // symlinks under the credential directory. ProtectSystem=strict makes
        // `/` unusable for unrelated temporary writes as well.
        .env("TMPDIR", "/")
        .current_dir(&home_path)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .process_group(0);

    let _guard = SPAWN_LOCK
        .lock()
        .map_err(|_| ExecutionError::CliUnavailable)?;
    for descriptor in [&inherited_home, &inherited_executable] {
        rustix::io::fcntl_setfd(descriptor, rustix::io::FdFlags::empty())
            .map_err(|_| ExecutionError::CliUnavailable)?;
    }
    let spawned = command.spawn();
    for descriptor in [&inherited_home, &inherited_executable] {
        let _ = rustix::io::fcntl_setfd(descriptor, rustix::io::FdFlags::CLOEXEC);
    }
    drop(inherited_home);
    drop(inherited_executable);
    spawned.map_err(|_| ExecutionError::CliUnavailable)
}

fn open_verified_executable(policy: &CliPolicy) -> Result<File, ExecutionError> {
    let descriptor = rfs::openat2(
        rfs::CWD,
        &policy.path,
        OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
        ResolveFlags::NO_SYMLINKS | ResolveFlags::NO_MAGICLINKS,
    )
    .map_err(|_| ExecutionError::CliUnavailable)?;
    let before = rfs::fstat(&descriptor).map_err(|_| ExecutionError::UnsafeExecutable)?;
    if !FileType::from_raw_mode(before.st_mode).is_file()
        || before.st_uid != policy.uid
        || before.st_gid != policy.gid
        || before.st_nlink != 1
        || before.st_mode & 0o7777 != policy.mode
        || u64::try_from(before.st_size).ok() != Some(policy.size)
    {
        return Err(ExecutionError::UnsafeExecutable);
    }
    let mut file = File::from(descriptor);
    let mut digest = Sha256::new();
    let mut buffer = [0_u8; 64 * 1024];
    let mut total = 0_u64;
    loop {
        let count = file
            .read(&mut buffer)
            .map_err(|_| ExecutionError::UnsafeExecutable)?;
        if count == 0 {
            break;
        }
        total = total
            .checked_add(u64::try_from(count).map_err(|_| ExecutionError::UnsafeExecutable)?)
            .ok_or(ExecutionError::UnsafeExecutable)?;
        if total > policy.size {
            return Err(ExecutionError::UnsafeExecutable);
        }
        digest.update(&buffer[..count]);
    }
    buffer.zeroize();
    let after = rfs::fstat(&file).map_err(|_| ExecutionError::UnsafeExecutable)?;
    if total != policy.size
        || (
            before.st_dev,
            before.st_ino,
            before.st_size,
            before.st_mtime,
            before.st_mtime_nsec,
        ) != (
            after.st_dev,
            after.st_ino,
            after.st_size,
            after.st_mtime,
            after.st_mtime_nsec,
        )
        || format!("{:x}", digest.finalize()) != policy.sha256
    {
        return Err(ExecutionError::UnsafeExecutable);
    }
    Ok(file)
}

fn validate_home(home: &OwnedFd, policy: HomePolicy) -> Result<(), ExecutionError> {
    let stat = rfs::fstat(home).map_err(|_| ExecutionError::UnsafeHome)?;
    let filesystem = rfs::fstatfs(home).map_err(|_| ExecutionError::UnsafeHome)?;
    let status = rfs::fcntl_getfl(home).map_err(|_| ExecutionError::UnsafeHome)?;
    let descriptor_flags = rustix::io::fcntl_getfd(home).map_err(|_| ExecutionError::UnsafeHome)?;
    if !FileType::from_raw_mode(stat.st_mode).is_dir()
        || stat.st_uid != policy.uid
        || stat.st_gid != policy.gid
        || stat.st_nlink < 2
        || stat.st_mode & 0o7777 != 0o700
        || status != (OFlags::PATH | OFlags::DIRECTORY | OFlags::NOFOLLOW)
        || descriptor_flags != rustix::io::FdFlags::CLOEXEC
        || (policy.require_ext4 && u64::try_from(filesystem.f_type).ok() != Some(EXT4_SUPER_MAGIC))
    {
        return Err(ExecutionError::UnsafeHome);
    }
    let readable = rfs::openat2(
        home,
        ".",
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
        ResolveFlags::BENEATH
            | ResolveFlags::NO_SYMLINKS
            | ResolveFlags::NO_MAGICLINKS
            | ResolveFlags::NO_XDEV,
    )
    .map_err(|_| ExecutionError::UnsafeHome)?;
    let entries_path = format!("/proc/self/fd/{}", readable.as_raw_fd());
    let mut names = Vec::new();
    for entry in std::fs::read_dir(entries_path).map_err(|_| ExecutionError::UnsafeHome)? {
        let entry = entry.map_err(|_| ExecutionError::UnsafeHome)?;
        let name = entry.file_name();
        let Some(name) = name.to_str() else {
            return Err(ExecutionError::UnsafeHome);
        };
        if !matches!(name, "auth.json" | "config.toml" | "log") {
            return Err(ExecutionError::UnsafeHome);
        }
        names.push(name.to_owned());
    }
    names.sort_unstable();
    if !names.iter().any(|name| name == "config.toml") {
        return Err(ExecutionError::UnsafeHome);
    }
    validate_config(&readable, policy)?;
    if names.iter().any(|name| name == "auth.json") {
        validate_metadata_only_file(&readable, "auth.json", policy, 1, MAX_AUTH_FILE_BYTES)?;
    }
    if names.iter().any(|name| name == "log") {
        validate_log_directory(&readable, policy)?;
    }
    let final_stat = rfs::fstat(home).map_err(|_| ExecutionError::UnsafeHome)?;
    if (
        stat.st_dev,
        stat.st_ino,
        stat.st_mode,
        stat.st_uid,
        stat.st_gid,
        stat.st_nlink,
        stat.st_mtime,
        stat.st_mtime_nsec,
        stat.st_ctime,
        stat.st_ctime_nsec,
    ) != (
        final_stat.st_dev,
        final_stat.st_ino,
        final_stat.st_mode,
        final_stat.st_uid,
        final_stat.st_gid,
        final_stat.st_nlink,
        final_stat.st_mtime,
        final_stat.st_mtime_nsec,
        final_stat.st_ctime,
        final_stat.st_ctime_nsec,
    ) {
        return Err(ExecutionError::UnsafeHome);
    }
    Ok(())
}

fn validate_config(directory: &OwnedFd, policy: HomePolicy) -> Result<(), ExecutionError> {
    let descriptor = rfs::openat2(
        directory,
        "config.toml",
        OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
        ResolveFlags::BENEATH
            | ResolveFlags::NO_SYMLINKS
            | ResolveFlags::NO_MAGICLINKS
            | ResolveFlags::NO_XDEV,
    )
    .map_err(|_| ExecutionError::UnsafeHome)?;
    let before = rfs::fstat(&descriptor).map_err(|_| ExecutionError::UnsafeHome)?;
    if !valid_regular_metadata(
        &before,
        policy,
        HOME_CONFIG.len() as u64,
        HOME_CONFIG.len() as u64,
    ) {
        return Err(ExecutionError::UnsafeHome);
    }
    let mut file = File::from(descriptor);
    let mut bytes = Zeroizing::new(Vec::with_capacity(HOME_CONFIG.len() + 1));
    (&mut file)
        .take((HOME_CONFIG.len() + 1) as u64)
        .read_to_end(&mut bytes)
        .map_err(|_| ExecutionError::UnsafeHome)?;
    let after = rfs::fstat(&file).map_err(|_| ExecutionError::UnsafeHome)?;
    if bytes.as_slice() != HOME_CONFIG
        || (
            before.st_dev,
            before.st_ino,
            before.st_size,
            before.st_mtime,
            before.st_mtime_nsec,
        ) != (
            after.st_dev,
            after.st_ino,
            after.st_size,
            after.st_mtime,
            after.st_mtime_nsec,
        )
    {
        return Err(ExecutionError::UnsafeHome);
    }
    Ok(())
}

fn validate_metadata_only_file(
    directory: &OwnedFd,
    name: &str,
    policy: HomePolicy,
    minimum: u64,
    maximum: u64,
) -> Result<(), ExecutionError> {
    let stat = rfs::statat(directory, name, AtFlags::SYMLINK_NOFOLLOW)
        .map_err(|_| ExecutionError::UnsafeHome)?;
    if !valid_regular_metadata(&stat, policy, minimum, maximum) {
        return Err(ExecutionError::UnsafeHome);
    }
    Ok(())
}

fn valid_regular_metadata(
    stat: &rustix::fs::Stat,
    policy: HomePolicy,
    minimum: u64,
    maximum: u64,
) -> bool {
    let size = u64::try_from(stat.st_size).ok();
    FileType::from_raw_mode(stat.st_mode).is_file()
        && stat.st_uid == policy.uid
        && stat.st_gid == policy.gid
        && stat.st_nlink == 1
        && stat.st_mode & 0o7777 == 0o600
        && size.is_some_and(|size| (minimum..=maximum).contains(&size))
}

fn validate_log_directory(directory: &OwnedFd, policy: HomePolicy) -> Result<(), ExecutionError> {
    let descriptor = rfs::openat2(
        directory,
        "log",
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
        ResolveFlags::BENEATH
            | ResolveFlags::NO_SYMLINKS
            | ResolveFlags::NO_MAGICLINKS
            | ResolveFlags::NO_XDEV,
    )
    .map_err(|_| ExecutionError::UnsafeHome)?;
    let stat = rfs::fstat(&descriptor).map_err(|_| ExecutionError::UnsafeHome)?;
    if !FileType::from_raw_mode(stat.st_mode).is_dir()
        || stat.st_uid != policy.uid
        || stat.st_gid != policy.gid
        || stat.st_nlink < 2
        || stat.st_mode & 0o7777 != 0o700
    {
        return Err(ExecutionError::UnsafeHome);
    }
    let entries_path = format!("/proc/self/fd/{}", descriptor.as_raw_fd());
    let names = std::fs::read_dir(entries_path)
        .map_err(|_| ExecutionError::UnsafeHome)?
        .map(|entry| entry.map(|entry| entry.file_name()))
        .collect::<Result<Vec<_>, _>>()
        .map_err(|_| ExecutionError::UnsafeHome)?;
    if names.len() > 1
        || names
            .first()
            .is_some_and(|name| name != OsStr::new("codex-login.log"))
    {
        return Err(ExecutionError::UnsafeHome);
    }
    if !names.is_empty() {
        validate_metadata_only_file(
            &descriptor,
            "codex-login.log",
            policy,
            0,
            MAX_LOGIN_LOG_BYTES,
        )?;
    }
    let final_stat = rfs::fstat(&descriptor).map_err(|_| ExecutionError::UnsafeHome)?;
    if (
        stat.st_dev,
        stat.st_ino,
        stat.st_mode,
        stat.st_uid,
        stat.st_gid,
        stat.st_nlink,
        stat.st_mtime,
        stat.st_mtime_nsec,
        stat.st_ctime,
        stat.st_ctime_nsec,
    ) != (
        final_stat.st_dev,
        final_stat.st_ino,
        final_stat.st_mode,
        final_stat.st_uid,
        final_stat.st_gid,
        final_stat.st_nlink,
        final_stat.st_mtime,
        final_stat.st_mtime_nsec,
        final_stat.st_ctime,
        final_stat.st_ctime_nsec,
    ) {
        return Err(ExecutionError::UnsafeHome);
    }
    Ok(())
}

#[derive(Clone, Copy)]
enum StreamKind {
    Stdout,
    Stderr,
}

enum ReaderEvent {
    Chunk(StreamKind, Zeroizing<Vec<u8>>),
    Closed,
    Failed,
}

type CollectedCli = (ExitStatus, Zeroizing<Vec<u8>>, Zeroizing<Vec<u8>>);

fn collect_cli(
    operation: Operation,
    child: &mut Child,
    deadline: Instant,
    responder: &mut dyn Responder,
) -> Result<CollectedCli, ExecutionError> {
    let stdout = child.stdout.take().ok_or(ExecutionError::CliUnavailable)?;
    let stderr = child.stderr.take().ok_or(ExecutionError::CliUnavailable)?;
    let (sender, receiver) = mpsc::channel();
    let stdout_reader = spawn_reader(stdout, StreamKind::Stdout, sender.clone());
    let stderr_reader = spawn_reader(stderr, StreamKind::Stderr, sender);
    let mut stdout = Zeroizing::new(Vec::new());
    let mut stderr = Zeroizing::new(Vec::new());
    let mut readers_closed = 0_usize;
    let mut status = None;
    let mut device_code_sent = false;
    loop {
        if Instant::now() >= deadline {
            return Err(ExecutionError::TimedOut);
        }
        match receiver.recv_timeout(PROCESS_POLL_INTERVAL) {
            Ok(ReaderEvent::Chunk(kind, mut bytes)) => {
                let target = match kind {
                    StreamKind::Stdout => &mut stdout,
                    StreamKind::Stderr => &mut stderr,
                };
                if target.len().saturating_add(bytes.len()) > MAX_CLI_OUTPUT_BYTES {
                    bytes.zeroize();
                    return Err(ExecutionError::CliFailed);
                }
                target.extend_from_slice(&bytes);
                bytes.zeroize();
                if operation == Operation::DeviceLogin
                    && !device_code_sent
                    && let Some(code) = parse_device_code(&stdout)
                {
                    responder
                        .send(&ResponsePayload::DeviceCode {
                            verification_url: DEVICE_VERIFICATION_URL,
                            user_code: &code,
                        })
                        .map_err(|_| ExecutionError::ClientGone)?;
                    device_code_sent = true;
                }
            }
            Ok(ReaderEvent::Closed) => readers_closed += 1,
            Ok(ReaderEvent::Failed) => return Err(ExecutionError::CliFailed),
            Err(mpsc::RecvTimeoutError::Timeout) => {}
            Err(mpsc::RecvTimeoutError::Disconnected) if readers_closed == 2 => {}
            Err(mpsc::RecvTimeoutError::Disconnected) => return Err(ExecutionError::CliFailed),
        }
        if status.is_none() {
            status = child.try_wait().map_err(|_| ExecutionError::CliFailed)?;
        }
        if status.is_some() && readers_closed == 2 {
            break;
        }
    }
    stdout_reader
        .join()
        .map_err(|_| ExecutionError::CliFailed)?;
    stderr_reader
        .join()
        .map_err(|_| ExecutionError::CliFailed)?;
    if operation == Operation::DeviceLogin && !device_code_sent {
        return Err(ExecutionError::CliFailed);
    }
    Ok((status.ok_or(ExecutionError::CliFailed)?, stdout, stderr))
}

fn spawn_reader<R: Read + Send + 'static>(
    mut reader: R,
    kind: StreamKind,
    sender: mpsc::Sender<ReaderEvent>,
) -> thread::JoinHandle<()> {
    thread::spawn(move || {
        let mut buffer = [0_u8; 1024];
        loop {
            match reader.read(&mut buffer) {
                Ok(0) => {
                    let _ = sender.send(ReaderEvent::Closed);
                    break;
                }
                Ok(count) => {
                    let chunk = Zeroizing::new(buffer[..count].to_vec());
                    buffer[..count].zeroize();
                    if sender.send(ReaderEvent::Chunk(kind, chunk)).is_err() {
                        break;
                    }
                }
                Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
                Err(_) => {
                    let _ = sender.send(ReaderEvent::Failed);
                    break;
                }
            }
        }
        buffer.zeroize();
    })
}

fn classify_cli_result(
    operation: Operation,
    status: ExitStatus,
    stdout: &[u8],
    stderr: &[u8],
) -> Result<AuthStatus, ExecutionError> {
    match operation {
        Operation::DeviceLogin => {
            if status.success()
                && parse_device_code(stdout).is_some()
                && has_exact_line(stderr, b"Successfully logged in")
            {
                Ok(AuthStatus::AuthenticatedChatgpt)
            } else {
                Err(ExecutionError::CliFailed)
            }
        }
        Operation::Status => {
            if !stdout.is_empty() {
                return Err(ExecutionError::CliFailed);
            }
            if status.success() && has_exact_line(stderr, b"Logged in using ChatGPT") {
                Ok(AuthStatus::AuthenticatedChatgpt)
            } else if status.success()
                && stderr
                    .split(|byte| *byte == b'\n')
                    .any(|line| line.starts_with(b"Logged in using an API key - "))
            {
                Ok(AuthStatus::AuthenticatedApiKey)
            } else if status.success()
                && (has_exact_line(stderr, b"Logged in using access token")
                    || has_exact_line(stderr, b"Logged in using personal access token"))
            {
                Ok(AuthStatus::AuthenticatedAccessToken)
            } else if status.code() == Some(1) && has_exact_line(stderr, b"Not logged in") {
                Ok(AuthStatus::SignedOut)
            } else {
                Err(ExecutionError::CliFailed)
            }
        }
        Operation::Logout => {
            if !stdout.is_empty() {
                return Err(ExecutionError::CliFailed);
            }
            if status.success() && has_exact_line(stderr, b"Successfully logged out") {
                Ok(AuthStatus::SignedOut)
            } else if status.success() && has_exact_line(stderr, b"Not logged in") {
                Ok(AuthStatus::AlreadySignedOut)
            } else {
                Err(ExecutionError::CliFailed)
            }
        }
    }
}

fn has_exact_line(bytes: &[u8], expected: &[u8]) -> bool {
    bytes
        .split(|byte| *byte == b'\n')
        .map(|line| line.strip_suffix(b"\r").unwrap_or(line))
        .any(|line| line == expected)
}

fn parse_device_code(bytes: &[u8]) -> Option<String> {
    if count_subslice(bytes, DEVICE_VERIFICATION_URL.as_bytes()) != 1 {
        return None;
    }
    let mut found = None;
    for (position, window) in bytes.windows(9).enumerate() {
        if window[4] != b'-'
            || !window[..4]
                .iter()
                .chain(&window[5..])
                .all(|byte| byte.is_ascii_uppercase() || byte.is_ascii_digit())
        {
            continue;
        }
        let before_ok = position == 0
            || !(bytes[position - 1].is_ascii_uppercase() || bytes[position - 1].is_ascii_digit());
        let after = position + window.len();
        let after_ok = after == bytes.len()
            || !(bytes[after].is_ascii_uppercase() || bytes[after].is_ascii_digit());
        if !before_ok || !after_ok {
            continue;
        }
        let code = std::str::from_utf8(window).ok()?.to_owned();
        if found.replace(code).is_some() {
            return None;
        }
    }
    found
}

fn count_subslice(haystack: &[u8], needle: &[u8]) -> usize {
    haystack
        .windows(needle.len())
        .filter(|candidate| *candidate == needle)
        .count()
}

fn valid_device_code(value: &str) -> bool {
    let bytes = value.as_bytes();
    bytes.len() == 9
        && bytes[4] == b'-'
        && bytes[..4]
            .iter()
            .chain(&bytes[5..])
            .all(|byte| byte.is_ascii_uppercase() || byte.is_ascii_digit())
}

fn terminate_child_group(child: &mut Child) {
    let group = Pid::from_child(child);
    let _ = rustix::process::kill_process_group(group, Signal::TERM);
    let deadline = Instant::now() + PROCESS_STOP_GRACE;
    while Instant::now() < deadline {
        if child.try_wait().ok().flatten().is_some() {
            let _ = rustix::process::kill_process_group(group, Signal::KILL);
            return;
        }
        thread::sleep(PROCESS_POLL_INTERVAL);
    }
    let _ = rustix::process::kill_process_group(group, Signal::KILL);
    let _ = child.kill();
    let _ = child.wait();
}

/// Run the live-user client for one closed operation.
pub fn run_client(arguments: impl Iterator<Item = OsString>) -> Result<(), BridgeError> {
    run_client_inner(arguments).map_err(|()| BridgeError)
}

fn run_client_inner(arguments: impl Iterator<Item = OsString>) -> Result<(), ()> {
    let mut arguments = arguments;
    let operation = match arguments.next().as_deref() {
        Some(value) if value == OsStr::new("device-login") => Operation::DeviceLogin,
        Some(value) if value == OsStr::new("status") => Operation::Status,
        Some(value) if value == OsStr::new("logout") => Operation::Logout,
        _ => {
            eprintln!("Uso: kernaid-codex-auth <device-login|status|logout>");
            return Err(());
        }
    };
    if arguments.next().is_some() {
        eprintln!("Uso: kernaid-codex-auth <device-login|status|logout>");
        return Err(());
    }
    let request = Request {
        api_version: API_VERSION.to_owned(),
        request_id: random_request_id(),
        operation,
    };
    let mut frame = serde_json::to_vec(&request).map_err(|_| ())?;
    if frame.len() > MAX_REQUEST_BYTES {
        return Err(());
    }
    let deadline = Instant::now()
        .checked_add(operation.timeout() + VAULT_TIMEOUT + Duration::from_secs(10))
        .ok_or(())?;
    let socket = connect_bridge(deadline)?;
    if send(&socket, &frame, SendFlags::NOSIGNAL).map_err(|_| ())? != frame.len() {
        frame.zeroize();
        return Err(());
    }
    frame.zeroize();
    let mut device_code_seen = false;
    loop {
        let response = receive_client_response(socket.as_fd(), deadline)?;
        response.validate(&request)?;
        if response.stage == "device-code" {
            if device_code_seen {
                return Err(());
            }
            device_code_seen = true;
            let code = response.user_code.as_deref().ok_or(())?;
            println!("Apri {DEVICE_VERIFICATION_URL} e inserisci il codice monouso {code}.");
            io::stdout().flush().map_err(|_| ())?;
        } else if response.stage == "complete" {
            if operation == Operation::DeviceLogin && !device_code_seen {
                return Err(());
            }
            let message = match response.status.ok_or(())? {
                AuthStatus::AuthenticatedChatgpt => "autenticato con ChatGPT",
                AuthStatus::AuthenticatedApiKey => "autenticato con API key",
                AuthStatus::AuthenticatedAccessToken => "autenticato con access token",
                AuthStatus::SignedOut => "disconnesso",
                AuthStatus::AlreadySignedOut => "già disconnesso",
            };
            println!("KernAid Codex: {message}");
        } else {
            let message = match response.code.ok_or(())? {
                SafeError::VaultLocked => "vault bloccato",
                SafeError::VaultUnconfigured => "home Codex non configurata",
                SafeError::Busy => "operazione già in corso",
                SafeError::RebootRequired => "riavvio Rescue richiesto",
                SafeError::TimedOut => "operazione scaduta",
                SafeError::CliUnavailable => "CLI Codex non disponibile",
                SafeError::UnsafeHome | SafeError::UnsafeExecutable => "stato Codex non sicuro",
                SafeError::Transport | SafeError::CliFailed => "operazione non riuscita",
            };
            eprintln!("KernAid Codex: {message}.");
        }
        if response.terminal() {
            return if response.stage == "complete" {
                Ok(())
            } else {
                Err(())
            };
        }
    }
}

fn connect_bridge(deadline: Instant) -> Result<OwnedFd, ()> {
    let socket = socket_with(
        AddressFamily::UNIX,
        SocketType::SEQPACKET,
        SocketFlags::CLOEXEC | SocketFlags::NONBLOCK,
        None,
    )
    .map_err(|_| ())?;
    let address = SocketAddrUnix::new(BRIDGE_SOCKET_PATH).map_err(|_| ())?;
    match connect(&socket, &address) {
        Ok(()) => {}
        Err(error) if error == rustix::io::Errno::INPROGRESS => {
            wait_ready(socket.as_fd(), PollFlags::OUT, deadline)?;
            rustix::net::sockopt::socket_error(&socket)
                .map_err(|_| ())?
                .map_err(|_| ())?;
        }
        Err(_) => return Err(()),
    }
    let credentials = rustix::net::sockopt::socket_peercred(&socket).map_err(|_| ())?;
    let socket_type = rustix::net::sockopt::socket_type(&socket).map_err(|_| ())?;
    if credentials.uid.as_raw() != 0 || socket_type != SocketType::SEQPACKET {
        return Err(());
    }
    Ok(socket)
}

fn receive_client_response(
    socket: BorrowedFd<'_>,
    deadline: Instant,
) -> Result<ReceivedResponse, ()> {
    wait_ready(socket, PollFlags::IN, deadline)?;
    let mut bytes = [0_u8; MAX_RESPONSE_BYTES + 1];
    let mut io = [IoSliceMut::new(&mut bytes)];
    let mut ancillary_space =
        [MaybeUninit::uninit(); rustix::cmsg_space!(ScmRights(2), ScmCredentials(1))];
    let mut ancillary = RecvAncillaryBuffer::new(&mut ancillary_space);
    let message = recvmsg(
        socket,
        &mut io,
        &mut ancillary,
        RecvFlags::CMSG_CLOEXEC | RecvFlags::TRUNC | RecvFlags::DONTWAIT,
    )
    .map_err(|_| ())?;
    if ancillary.drain().next().is_some()
        || message.bytes == 0
        || message.bytes > MAX_RESPONSE_BYTES
        || message
            .flags
            .intersects(ReturnFlags::TRUNC | ReturnFlags::CTRUNC)
        || bytes[..message.bytes].last() != Some(&b'\n')
    {
        return Err(());
    }
    serde_json::from_slice(&bytes[..message.bytes - 1]).map_err(|_| ())
}

fn random_request_id() -> String {
    let mut value = [0_u8; 16];
    OsRng.fill_bytes(&mut value);
    value[6] = (value[6] & 0x0f) | 0x40;
    value[8] = (value[8] & 0x3f) | 0x80;
    format!(
        "C-{:02x}{:02x}{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
        value[0],
        value[1],
        value[2],
        value[3],
        value[4],
        value[5],
        value[6],
        value[7],
        value[8],
        value[9],
        value[10],
        value[11],
        value[12],
        value[13],
        value[14],
        value[15]
    )
}

fn valid_request_id(value: &str) -> bool {
    if value.len() != 38 || !value.starts_with("C-") {
        return false;
    }
    value[2..].bytes().enumerate().all(|(index, byte)| {
        if matches!(index, 8 | 13 | 18 | 23) {
            byte == b'-'
        } else {
            byte.is_ascii_digit() || matches!(byte, b'a'..=b'f')
        }
    })
}

fn wait_ready(socket: BorrowedFd<'_>, interest: PollFlags, deadline: Instant) -> Result<(), ()> {
    loop {
        let remaining = deadline.checked_duration_since(Instant::now()).ok_or(())?;
        let seconds = i64::try_from(remaining.as_secs()).unwrap_or(i64::MAX);
        let timeout = Timespec {
            tv_sec: seconds,
            tv_nsec: if seconds == i64::MAX {
                999_999_999
            } else {
                i64::from(remaining.subsec_nanos())
            },
        };
        let mut descriptors = [PollFd::from_borrowed_fd(socket, interest)];
        match poll(&mut descriptors, Some(&timeout)) {
            Ok(0) => return Err(()),
            Ok(_) => {
                let ready = descriptors[0].revents();
                if ready.contains(PollFlags::NVAL) {
                    return Err(());
                }
                if ready.intersects(interest | PollFlags::ERR | PollFlags::HUP | PollFlags::RDHUP) {
                    return Ok(());
                }
            }
            Err(error) if error == rustix::io::Errno::INTR => {}
            Err(_) => return Err(()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{fs, os::unix::fs::PermissionsExt};
    use tempfile::TempDir;

    #[derive(Default)]
    struct CapturingResponder {
        frames: Vec<String>,
    }

    impl Responder for CapturingResponder {
        fn send(&mut self, payload: &ResponsePayload<'_>) -> Result<(), ()> {
            self.frames
                .push(serde_json::to_string(payload).map_err(|_| ())?);
            Ok(())
        }
    }

    struct Fixture {
        _root: TempDir,
        home_path: PathBuf,
        home: OwnedFd,
        cli: CliPolicy,
        home_policy: HomePolicy,
        trace_path: PathBuf,
    }

    impl Fixture {
        fn new() -> Self {
            let root = tempfile::tempdir().expect("fixture root");
            let home_path = root.path().join("home");
            fs::create_dir(&home_path).expect("home");
            fs::set_permissions(&home_path, fs::Permissions::from_mode(0o700)).expect("home mode");
            fs::write(home_path.join("config.toml"), HOME_CONFIG).expect("config");
            fs::set_permissions(
                home_path.join("config.toml"),
                fs::Permissions::from_mode(0o600),
            )
            .expect("config mode");
            let trace_path = root.path().join("trace");
            let script_path = root.path().join("codex-fake");
            let script = format!(
                "#!/bin/sh\nset -eu\n[ \"$TMPDIR\" = / ] || exit 98\nprintf '%s\\n' \"$*\" >>'{}'\ncase \"$*\" in\n  'login --device-auth')\n    printf 'raw-secret-canary\\nhttps://auth.openai.com/codex/device\\nABCD-1234\\n'\n    printf '{{\"token\":\"raw-secret-canary\"}}\\n' >\"$CODEX_HOME/auth.json\"\n    chmod 600 \"$CODEX_HOME/auth.json\"\n    printf 'Successfully logged in\\n' >&2\n    ;;\n  'login status')\n    if [ -f \"$CODEX_HOME/auth.json\" ]; then printf 'Logged in using ChatGPT\\n' >&2; exit 0; fi\n    printf 'Not logged in\\n' >&2; exit 1\n    ;;\n  'logout')\n    if [ -f \"$CODEX_HOME/auth.json\" ]; then rm -- \"$CODEX_HOME/auth.json\"; printf 'Successfully logged out\\n' >&2; else printf 'Not logged in\\n' >&2; fi\n    ;;\n  *) exit 97 ;;\nesac\n",
                trace_path.display()
            );
            fs::write(&script_path, script).expect("fake CLI");
            fs::set_permissions(&script_path, fs::Permissions::from_mode(0o755))
                .expect("fake CLI mode");
            let bytes = fs::read(&script_path).expect("fake CLI bytes");
            let metadata = fs::metadata(&script_path).expect("fake CLI metadata");
            let owner = rfs::statat(rfs::CWD, &script_path, AtFlags::SYMLINK_NOFOLLOW)
                .expect("fake CLI stat");
            let home_owner =
                rfs::statat(rfs::CWD, &home_path, AtFlags::SYMLINK_NOFOLLOW).expect("home stat");
            let home = rfs::openat2(
                rfs::CWD,
                &home_path,
                OFlags::PATH | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
                Mode::empty(),
                ResolveFlags::NO_SYMLINKS | ResolveFlags::NO_MAGICLINKS,
            )
            .expect("home descriptor");
            Self {
                _root: root,
                home_path,
                home,
                cli: CliPolicy {
                    path: script_path,
                    size: metadata.len(),
                    sha256: format!("{:x}", Sha256::digest(bytes)),
                    uid: owner.st_uid,
                    gid: owner.st_gid,
                    mode: 0o755,
                },
                home_policy: HomePolicy {
                    uid: home_owner.st_uid,
                    gid: home_owner.st_gid,
                    require_ext4: false,
                },
                trace_path,
            }
        }

        fn run(&self, operation: Operation) -> CapturingResponder {
            let mut responder = CapturingResponder::default();
            execute_with_home(
                operation,
                &self.home,
                &self.cli,
                self.home_policy,
                &mut responder,
            )
            .expect("bridge operation");
            responder
        }
    }

    #[test]
    fn fake_cli_persists_across_bridge_restart_and_logout_is_bounded() {
        let fixture = Fixture::new();
        let login = fixture.run(Operation::DeviceLogin);
        assert_eq!(login.frames.len(), 2);
        assert!(login.frames[0].contains("device-code"));
        assert!(login.frames[0].contains(DEVICE_VERIFICATION_URL));
        assert!(login.frames[0].contains("ABCD-1234"));
        assert!(login.frames[1].contains("authenticated-chatgpt"));
        assert!(!login.frames.join("\n").contains("raw-secret-canary"));

        // A fresh bridge instance sees only the persistent CLI-managed state.
        let status = fixture.run(Operation::Status);
        assert_eq!(status.frames.len(), 1);
        assert!(status.frames[0].contains("authenticated-chatgpt"));

        let logout = fixture.run(Operation::Logout);
        assert_eq!(logout.frames.len(), 1);
        assert!(logout.frames[0].contains("signed-out"));
        assert!(!fixture.home_path.join("auth.json").exists());
        let signed_out = fixture.run(Operation::Status);
        assert!(signed_out.frames[0].contains("signed-out"));

        let trace = fs::read_to_string(&fixture.trace_path).expect("fake trace");
        assert_eq!(
            trace.lines().collect::<Vec<_>>(),
            [
                "login --device-auth",
                "login status",
                "logout",
                "login status"
            ]
        );
    }

    #[test]
    fn auth_json_is_metadata_only_and_symlink_tamper_fails_before_cli() {
        let fixture = Fixture::new();
        fixture.run(Operation::DeviceLogin);
        let trace_before = fs::read(&fixture.trace_path).expect("trace before");
        fs::remove_file(fixture.home_path.join("auth.json")).expect("remove auth");
        std::os::unix::fs::symlink("config.toml", fixture.home_path.join("auth.json"))
            .expect("tampered auth symlink");
        let mut responder = CapturingResponder::default();
        assert_eq!(
            execute_with_home(
                Operation::Status,
                &fixture.home,
                &fixture.cli,
                fixture.home_policy,
                &mut responder,
            ),
            Err(ExecutionError::UnsafeHome)
        );
        assert_eq!(
            fs::read(&fixture.trace_path).expect("trace after"),
            trace_before
        );
        assert!(responder.frames.is_empty());
    }

    #[test]
    fn executable_hash_tamper_fails_before_spawn() {
        let fixture = Fixture::new();
        fs::write(&fixture.cli.path, b"#!/bin/sh\nexit 0\n").expect("tamper fake CLI");
        fs::set_permissions(&fixture.cli.path, fs::Permissions::from_mode(0o755))
            .expect("tampered mode");
        let mut responder = CapturingResponder::default();
        assert_eq!(
            execute_with_home(
                Operation::Status,
                &fixture.home,
                &fixture.cli,
                fixture.home_policy,
                &mut responder,
            ),
            Err(ExecutionError::UnsafeExecutable)
        );
        assert!(!fixture.trace_path.exists());
    }

    #[test]
    fn failed_cli_side_effect_is_re_attested_and_fails_closed() {
        let mut fixture = Fixture::new();
        let script = b"#!/bin/sh\nset -eu\nprintf x >\"$CODEX_HOME/unexpected\"\nexit 1\n";
        fs::write(&fixture.cli.path, script).expect("replace fake CLI");
        fs::set_permissions(&fixture.cli.path, fs::Permissions::from_mode(0o755))
            .expect("replacement mode");
        fixture.cli.size = script.len() as u64;
        fixture.cli.sha256 = format!("{:x}", Sha256::digest(script));
        let mut responder = CapturingResponder::default();
        assert_eq!(
            execute_with_home(
                Operation::Status,
                &fixture.home,
                &fixture.cli,
                fixture.home_policy,
                &mut responder,
            ),
            Err(ExecutionError::UnsafeHome)
        );
        assert!(responder.frames.is_empty());
    }

    #[test]
    fn request_and_device_code_grammars_are_closed() {
        assert!(valid_request_id("C-01234567-89ab-4def-8123-456789abcdef"));
        assert!(!valid_request_id("C-01234567-89AB-4def-8123-456789abcdef"));
        assert!(valid_device_code("ABCD-1234"));
        assert!(!valid_device_code("abcd-1234"));
        assert_eq!(
            parse_device_code(b"noise https://auth.openai.com/codex/device more ABCD-1234 end"),
            Some("ABCD-1234".to_owned())
        );
    }

    #[test]
    fn client_binds_terminal_status_to_the_requested_operation() {
        let request = Request {
            api_version: API_VERSION.to_owned(),
            request_id: "C-01234567-89ab-4def-8123-456789abcdef".to_owned(),
            operation: Operation::DeviceLogin,
        };
        let valid = ReceivedResponse {
            api_version: API_VERSION.to_owned(),
            request_id: request.request_id.clone(),
            operation: request.operation,
            stage: "complete".to_owned(),
            verification_url: None,
            user_code: None,
            status: Some(AuthStatus::AuthenticatedChatgpt),
            code: None,
        };
        assert_eq!(valid.validate(&request), Ok(()));
        let invalid = ReceivedResponse {
            status: Some(AuthStatus::SignedOut),
            ..valid
        };
        assert_eq!(invalid.validate(&request), Err(()));
    }

    #[test]
    fn shipping_lock_constants_are_exact() {
        let lock: serde_json::Value =
            serde_json::from_slice(include_bytes!("../../../rescue/codex/codex-cli.lock.json"))
                .expect("Codex lock");
        assert_eq!(
            lock.pointer("/artifact/binary/installPath")
                .and_then(serde_json::Value::as_str),
            Some(SHIPPING_CODEX_PATH)
        );
        assert_eq!(
            lock.pointer("/artifact/binary/sizeBytes")
                .and_then(serde_json::Value::as_u64),
            Some(SHIPPING_CODEX_SIZE)
        );
        assert_eq!(
            lock.pointer("/artifact/binary/sha256")
                .and_then(serde_json::Value::as_str),
            Some(SHIPPING_CODEX_SHA256)
        );
    }
}
