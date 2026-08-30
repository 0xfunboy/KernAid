use kernaid_protocol::{
    rescue_vault::{
        ErrorToken, ProviderState as VaultProviderState, RequestId, SuccessPayload,
        VaultState as ProtocolVaultState, validate_openai_api_key_bytes,
    },
    rescue_vault_transport::{
        ClientRequest, ClientRequestPayload, ClientResponse, ClientResponseOutcome,
        authenticate_root_seqpacket_server,
    },
};
use kernaid_rescue_openai_provider::{
    CredentialState, MAX_OPENAI_RESPONSE_BODY_BYTES, MAX_REQUEST_FRAME_BYTES, OpenAiWireError,
    PreparedOpenAiExchange, ProviderErrorCode, ProviderOperation, ProviderRequest,
    ProviderResponse, ProviderStatus, VaultState, decode_openai_response, encode_response_frame,
    parse_request_frame, prepare_openai_exchange,
};
use rustix::{
    event::{PollFd, PollFlags, Timespec, poll},
    fd::{AsFd, BorrowedFd, OwnedFd},
    fs::{self as rfs, FileType, OFlags},
    net::{
        AddressFamily, RecvAncillaryBuffer, RecvFlags, ReturnFlags, SendFlags, SocketAddrUnix,
        SocketFlags, SocketType, connect, recvmsg, send, socket_with,
    },
};
use rustls::{ClientConfig, ClientConnection, RootCertStore, StreamOwned, pki_types::ServerName};
use std::{
    io::{self, IoSliceMut, Read, Write, stdin},
    mem::MaybeUninit,
    os::unix::net::UnixStream,
    sync::Arc,
    time::{Duration, Instant},
};
use zeroize::Zeroizing;

const PROVIDER_SOCKET_PATH: &[u8] = b"/run/kernaid-rescue-openai.sock";
const VAULT_SOCKET_PATH: &str = "/run/kernaid-rescue-vault.sock";
const EGRESS_SOCKET_PATH: &str = "/run/kernaid-rescue-openai-egress.sock";
const OPENAI_HOST: &str = "api.openai.com";
const REQUEST_TIMEOUT: Duration = Duration::from_secs(3);
const BORROW_TIMEOUT: Duration = Duration::from_secs(20);
const HTTPS_TIMEOUT: Duration = Duration::from_secs(110);
const EGRESS_CONNECT_TIMEOUT: Duration = Duration::from_secs(3);
const TLS_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(15);
const HTTP_WRITE_TIMEOUT: Duration = Duration::from_secs(10);
const MAX_HTTP_HEADER_BYTES: usize = 16 * 1024;
const MAX_HTTP_WIRE_BYTES: usize =
    MAX_HTTP_HEADER_BYTES + MAX_OPENAI_RESPONSE_BODY_BYTES + 16 * 1024;
const MAX_HTTP_HEADERS: usize = 64;
const PIPEFS_MAGIC: u64 = 0x5049_5045;

/// Sanitized one-shot executor failures. No variant carries peer input, a
/// pathname, an operating-system error, or provider data.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ExecutorError {
    InvalidSocket,
    NoData,
    RequestTooLarge,
    UnexpectedAncillary,
    InvalidRequest,
    TimedOut,
    IoFailed,
    IncompleteSend,
}

trait VaultBoundary {
    fn observe(
        &self,
        provider_request_id: &str,
        deadline: Instant,
    ) -> Result<ProviderStatus, ProviderErrorCode>;

    fn borrow_openai(
        &self,
        provider_request_id: &str,
        deadline: Instant,
    ) -> Result<BorrowedCredential, ProviderErrorCode>;
}

struct BorrowedCredential {
    // Retain the exact authenticated lease socket until the provider response
    // has been sent and this one-shot process is ready to exit.
    _control_socket: OwnedFd,
    key_pipe: OwnedFd,
    declared_size: u64,
}

trait OpenAiBoundary {
    fn exchange(
        &self,
        prepared: &PreparedOpenAiExchange,
        api_key: &[u8],
        deadline: Instant,
    ) -> Result<ProviderResponse, ProviderErrorCode>;
}

struct SystemBoundaries;

impl VaultBoundary for SystemBoundaries {
    fn observe(
        &self,
        provider_request_id: &str,
        deadline: Instant,
    ) -> Result<ProviderStatus, ProviderErrorCode> {
        let request_id = vault_request_id(provider_request_id)?;
        let vault_request =
            ClientRequest::new(request_id.clone(), 0, ClientRequestPayload::VaultStatus)
                .map_err(|_| ProviderErrorCode::Transport)?;
        let vault_response = exchange_vault(&vault_request, deadline)?;
        let vault_status = match vault_response.outcome() {
            ClientResponseOutcome::Success(SuccessPayload::VaultStatus(status)) => status,
            ClientResponseOutcome::Error(error) => return map_vault_error(*error),
            _ => return Err(ProviderErrorCode::Transport),
        };
        let local_vault = map_vault_state(vault_status.vault_state());
        if local_vault != VaultState::Unlocked {
            return ProviderStatus::new(local_vault, CredentialState::Unavailable)
                .map_err(|_| ProviderErrorCode::Transport);
        }

        let provider_request = ClientRequest::new(
            request_id,
            vault_response.state_version(),
            ClientRequestPayload::ProviderStatus,
        )
        .map_err(|_| ProviderErrorCode::Transport)?;
        let provider_response = exchange_vault(&provider_request, deadline)?;
        require_correlated_state_version(
            vault_response.state_version(),
            provider_response.state_version(),
            version_outcome(provider_response.outcome()),
        )?;
        match provider_response.outcome() {
            ClientResponseOutcome::Success(SuccessPayload::ProviderStatus(status)) => {
                let credential = match status.openai {
                    VaultProviderState::Unconfigured => CredentialState::Absent,
                    VaultProviderState::Configured => CredentialState::Configured,
                };
                ProviderStatus::new(VaultState::Unlocked, credential)
                    .map_err(|_| ProviderErrorCode::Transport)
            }
            ClientResponseOutcome::Error(error) => map_vault_error(*error),
            _ => Err(ProviderErrorCode::Transport),
        }
    }

    fn borrow_openai(
        &self,
        provider_request_id: &str,
        deadline: Instant,
    ) -> Result<BorrowedCredential, ProviderErrorCode> {
        let request_id = vault_request_id(provider_request_id)?;
        let status_request =
            ClientRequest::new(request_id.clone(), 0, ClientRequestPayload::VaultStatus)
                .map_err(|_| ProviderErrorCode::Transport)?;
        let status_response = exchange_vault(&status_request, deadline)?;
        match status_response.outcome() {
            ClientResponseOutcome::Success(SuccessPayload::VaultStatus(status))
                if status.vault_state() == ProtocolVaultState::Unlocked => {}
            ClientResponseOutcome::Success(SuccessPayload::VaultStatus(_)) => {
                return Err(ProviderErrorCode::CredentialUnavailable);
            }
            ClientResponseOutcome::Error(ErrorToken::Busy | ErrorToken::StaleState) => {
                return Err(ProviderErrorCode::Busy);
            }
            ClientResponseOutcome::Error(ErrorToken::ProviderUnconfigured) => {
                return Err(ProviderErrorCode::CredentialUnavailable);
            }
            ClientResponseOutcome::Error(_) | ClientResponseOutcome::Success(_) => {
                return Err(ProviderErrorCode::Transport);
            }
        }

        let request = ClientRequest::new(
            request_id,
            status_response.state_version(),
            ClientRequestPayload::ProviderOpenAiBorrow,
        )
        .map_err(|_| ProviderErrorCode::Transport)?;
        let socket = connect_vault(deadline)?;
        let authenticated = authenticate_root_seqpacket_server(socket.as_fd())
            .map_err(|_| ProviderErrorCode::Transport)?;
        authenticated
            .send_request(&request, &[], deadline)
            .map_err(|_| ProviderErrorCode::Transport)?;
        let mut response = authenticated
            .receive_response(&request, deadline)
            .map_err(|_| ProviderErrorCode::Transport)?;
        require_correlated_state_version(
            status_response.state_version(),
            response.state_version(),
            version_outcome(response.outcome()),
        )?;
        let declared_size = match response.outcome() {
            ClientResponseOutcome::Success(SuccessPayload::Descriptor(declaration)) => {
                declaration.size
            }
            ClientResponseOutcome::Error(ErrorToken::ProviderUnconfigured) => {
                return Err(ProviderErrorCode::CredentialUnavailable);
            }
            ClientResponseOutcome::Error(ErrorToken::Busy | ErrorToken::StaleState) => {
                return Err(ProviderErrorCode::Busy);
            }
            ClientResponseOutcome::Error(ErrorToken::RebootRequired) => {
                return Err(ProviderErrorCode::CredentialUnavailable);
            }
            ClientResponseOutcome::Error(_) | ClientResponseOutcome::Success(_) => {
                return Err(ProviderErrorCode::Transport);
            }
        };
        let key_pipe = response
            .take_descriptor()
            .ok_or(ProviderErrorCode::Transport)?;
        Ok(BorrowedCredential {
            _control_socket: socket,
            key_pipe,
            declared_size,
        })
    }
}

#[derive(Clone, Copy)]
enum VersionOutcome {
    Exact,
    StrictlyNewer,
    Monotonic,
}

fn version_outcome(outcome: &ClientResponseOutcome) -> VersionOutcome {
    match outcome {
        ClientResponseOutcome::Error(ErrorToken::StaleState) => VersionOutcome::StrictlyNewer,
        ClientResponseOutcome::Error(ErrorToken::Busy | ErrorToken::RebootRequired) => {
            VersionOutcome::Monotonic
        }
        ClientResponseOutcome::Success(_) | ClientResponseOutcome::Error(_) => {
            VersionOutcome::Exact
        }
    }
}

fn require_correlated_state_version(
    expected: u64,
    observed: u64,
    outcome: VersionOutcome,
) -> Result<(), ProviderErrorCode> {
    let valid = match outcome {
        VersionOutcome::Exact => observed == expected,
        VersionOutcome::StrictlyNewer => observed > expected,
        VersionOutcome::Monotonic => observed >= expected,
    };
    if valid {
        Ok(())
    } else {
        Err(ProviderErrorCode::Transport)
    }
}

impl OpenAiBoundary for SystemBoundaries {
    fn exchange(
        &self,
        prepared: &PreparedOpenAiExchange,
        api_key: &[u8],
        deadline: Instant,
    ) -> Result<ProviderResponse, ProviderErrorCode> {
        fixed_openai_exchange(prepared, api_key, deadline, production_tls_config()?)
    }
}

fn map_vault_state(state: ProtocolVaultState) -> VaultState {
    match state {
        ProtocolVaultState::Absent => VaultState::Absent,
        ProtocolVaultState::Unprovisioned => VaultState::Unprovisioned,
        ProtocolVaultState::Locked => VaultState::Locked,
        ProtocolVaultState::Unlocking => VaultState::Unlocking,
        ProtocolVaultState::Unlocked => VaultState::Unlocked,
        ProtocolVaultState::Locking => VaultState::Locking,
        ProtocolVaultState::FaultedRebootRequired => VaultState::FaultedRebootRequired,
    }
}

fn map_vault_error(error: ErrorToken) -> Result<ProviderStatus, ProviderErrorCode> {
    let state = match error {
        ErrorToken::Absent => VaultState::Absent,
        ErrorToken::Unprovisioned => VaultState::Unprovisioned,
        ErrorToken::Locked => VaultState::Locked,
        ErrorToken::RebootRequired => VaultState::FaultedRebootRequired,
        ErrorToken::Busy | ErrorToken::StaleState => return Err(ProviderErrorCode::Busy),
        ErrorToken::NotAuthorized | ErrorToken::ProviderUnconfigured => {
            return Err(ProviderErrorCode::Transport);
        }
        ErrorToken::BadPassphrase
        | ErrorToken::MediaChanged
        | ErrorToken::ProfileMismatch
        | ErrorToken::FdRequired
        | ErrorToken::FdForbidden
        | ErrorToken::RateLimited
        | ErrorToken::ReportTooLarge
        | ErrorToken::IoFailed => return Err(ProviderErrorCode::Transport),
    };
    ProviderStatus::new(state, CredentialState::Unavailable)
        .map_err(|_| ProviderErrorCode::Transport)
}

fn vault_request_id(provider_request_id: &str) -> Result<RequestId, ProviderErrorCode> {
    let suffix = provider_request_id
        .strip_prefix("O-")
        .ok_or(ProviderErrorCode::Transport)?;
    RequestId::parse(&format!("R-{suffix}")).map_err(|_| ProviderErrorCode::Transport)
}

fn exchange_vault(
    request: &ClientRequest,
    deadline: Instant,
) -> Result<ClientResponse, ProviderErrorCode> {
    let socket = connect_vault(deadline)?;
    let authenticated = authenticate_root_seqpacket_server(socket.as_fd())
        .map_err(|_| ProviderErrorCode::Transport)?;
    authenticated
        .send_request(request, &[], deadline)
        .map_err(|_| ProviderErrorCode::Transport)?;
    authenticated
        .receive_response(request, deadline)
        .map_err(|_| ProviderErrorCode::Transport)
}

fn connect_vault(deadline: Instant) -> Result<OwnedFd, ProviderErrorCode> {
    let socket = socket_with(
        AddressFamily::UNIX,
        SocketType::SEQPACKET,
        SocketFlags::CLOEXEC | SocketFlags::NONBLOCK,
        None,
    )
    .map_err(|_| ProviderErrorCode::Transport)?;
    let address =
        SocketAddrUnix::new(VAULT_SOCKET_PATH).map_err(|_| ProviderErrorCode::Transport)?;
    match connect(&socket, &address) {
        Ok(()) => {}
        Err(error) if error == rustix::io::Errno::INPROGRESS => {
            wait_ready(socket.as_fd(), PollFlags::OUT, deadline)
                .map_err(|_| ProviderErrorCode::Transport)?;
            rustix::net::sockopt::socket_error(&socket)
                .map_err(|_| ProviderErrorCode::Transport)?
                .map_err(|_| ProviderErrorCode::Transport)?;
        }
        Err(_) => return Err(ProviderErrorCode::Transport),
    }
    Ok(socket)
}

fn read_openai_key(
    descriptor: BorrowedFd<'_>,
    declared_size: u64,
    deadline: Instant,
) -> Result<Zeroizing<Vec<u8>>, ProviderErrorCode> {
    let expected = usize::try_from(declared_size).map_err(|_| ProviderErrorCode::Transport)?;
    if expected == 0 || declared_size > kernaid_protocol::rescue_vault::MAX_OPENAI_KEY_BYTES {
        return Err(ProviderErrorCode::Transport);
    }
    let stat = rfs::fstat(descriptor).map_err(|_| ProviderErrorCode::Transport)?;
    let filesystem = rfs::fstatfs(descriptor).map_err(|_| ProviderErrorCode::Transport)?;
    let filesystem_type =
        u64::try_from(filesystem.f_type).map_err(|_| ProviderErrorCode::Transport)?;
    let status = rfs::fcntl_getfl(descriptor).map_err(|_| ProviderErrorCode::Transport)?;
    let descriptor_flags =
        rustix::io::fcntl_getfd(descriptor).map_err(|_| ProviderErrorCode::Transport)?;
    if !FileType::from_raw_mode(stat.st_mode).is_fifo()
        || filesystem_type != PIPEFS_MAGIC
        || status != (OFlags::RDONLY | OFlags::NONBLOCK)
        || descriptor_flags != rustix::io::FdFlags::CLOEXEC
        || stat.st_size != 0
    {
        return Err(ProviderErrorCode::Transport);
    }
    wait_key_pipe_hup(descriptor, deadline)?;
    let available =
        rustix::io::ioctl_fionread(descriptor).map_err(|_| ProviderErrorCode::Transport)?;
    if available != declared_size {
        return Err(ProviderErrorCode::Transport);
    }
    let mut value = Zeroizing::new(vec![0_u8; expected]);
    let mut offset = 0_usize;
    while offset < expected {
        ensure_provider_before(deadline)?;
        match rustix::io::read(descriptor, &mut value[offset..]) {
            Ok(0) => return Err(ProviderErrorCode::Transport),
            Ok(read) => offset = offset.saturating_add(read),
            Err(error) if error == rustix::io::Errno::INTR => {}
            Err(error) if error == rustix::io::Errno::AGAIN => {
                wait_ready(descriptor, PollFlags::IN, deadline).map_err(map_executor_io)?;
            }
            Err(_) => return Err(ProviderErrorCode::Transport),
        }
    }
    let reached_eof = loop {
        ensure_provider_before(deadline)?;
        let mut extra = Zeroizing::new([0_u8; 1]);
        match rustix::io::read(descriptor, &mut extra[..]) {
            Ok(0) => break true,
            Ok(_) => break false,
            Err(error) if error == rustix::io::Errno::INTR => {}
            Err(error) if error == rustix::io::Errno::AGAIN => {
                wait_ready(descriptor, PollFlags::IN, deadline).map_err(map_executor_io)?;
            }
            Err(_) => return Err(ProviderErrorCode::Transport),
        }
    };
    if !reached_eof || validate_openai_api_key_bytes(&value).is_err() {
        return Err(ProviderErrorCode::Transport);
    }
    Ok(value)
}

fn wait_key_pipe_hup(
    descriptor: BorrowedFd<'_>,
    deadline: Instant,
) -> Result<(), ProviderErrorCode> {
    loop {
        let remaining = deadline
            .checked_duration_since(Instant::now())
            .filter(|remaining| !remaining.is_zero())
            .ok_or(ProviderErrorCode::Timeout)?;
        let seconds = i64::try_from(remaining.as_secs()).unwrap_or(i64::MAX);
        let timeout = Timespec {
            tv_sec: seconds,
            tv_nsec: if seconds == i64::MAX {
                999_999_999
            } else {
                i64::from(remaining.subsec_nanos())
            },
        };
        let mut descriptors = [PollFd::from_borrowed_fd(descriptor, PollFlags::HUP)];
        match poll(&mut descriptors, Some(&timeout)) {
            Ok(0) => return Err(ProviderErrorCode::Timeout),
            Ok(_) => {
                let events = descriptors[0].revents();
                if events.intersects(PollFlags::ERR | PollFlags::NVAL) {
                    return Err(ProviderErrorCode::Transport);
                }
                if events.contains(PollFlags::HUP) {
                    return Ok(());
                }
            }
            Err(error) if error == rustix::io::Errno::INTR => {}
            Err(_) => return Err(ProviderErrorCode::Transport),
        }
    }
}

fn map_prepare_error(error: OpenAiWireError) -> ProviderErrorCode {
    match error {
        OpenAiWireError::RequestTooLarge => ProviderErrorCode::RequestTooLarge,
        OpenAiWireError::UnsupportedOperation | OpenAiWireError::RequestEncoding => {
            ProviderErrorCode::InvalidRequest
        }
        _ => ProviderErrorCode::InvalidRequest,
    }
}

fn map_decode_error(error: OpenAiWireError) -> ProviderErrorCode {
    match error {
        OpenAiWireError::ResponseTooLarge => ProviderErrorCode::ResponseTooLarge,
        OpenAiWireError::UnexpectedHttpStatus
        | OpenAiWireError::RefusedResponse
        | OpenAiWireError::UpstreamFailure => ProviderErrorCode::Upstream,
        OpenAiWireError::InvalidContentType
        | OpenAiWireError::UnsupportedContentEncoding
        | OpenAiWireError::InvalidResponse
        | OpenAiWireError::IncompleteResponse
        | OpenAiWireError::UnexpectedOutput
        | OpenAiWireError::InvalidUsage => ProviderErrorCode::InvalidResponse,
        OpenAiWireError::UnsupportedOperation
        | OpenAiWireError::RequestEncoding
        | OpenAiWireError::RequestTooLarge => ProviderErrorCode::InvalidRequest,
    }
}

fn ensure_provider_before(deadline: Instant) -> Result<(), ProviderErrorCode> {
    deadline
        .checked_duration_since(Instant::now())
        .filter(|remaining| !remaining.is_zero())
        .map(|_| ())
        .ok_or(ProviderErrorCode::Timeout)
}

fn map_executor_io(error: ExecutorError) -> ProviderErrorCode {
    match error {
        ExecutorError::TimedOut => ProviderErrorCode::Timeout,
        _ => ProviderErrorCode::Transport,
    }
}

fn production_tls_config() -> Result<Arc<ClientConfig>, ProviderErrorCode> {
    let roots = RootCertStore::from_iter(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    tls_config_with_roots(roots)
}

#[cfg(test)]
fn test_tls_config(roots: RootCertStore) -> Result<Arc<ClientConfig>, ProviderErrorCode> {
    tls_config_with_roots(roots)
}

fn tls_config_with_roots(roots: RootCertStore) -> Result<Arc<ClientConfig>, ProviderErrorCode> {
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let mut config = ClientConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13, &rustls::version::TLS12])
        .map_err(|_| ProviderErrorCode::Transport)?
        .with_root_certificates(roots)
        .with_no_client_auth();
    config.alpn_protocols = vec![b"http/1.1".to_vec()];
    Ok(Arc::new(config))
}

struct DeadlineUnixStream {
    stream: UnixStream,
    deadline: Instant,
}

impl DeadlineUnixStream {
    fn new(stream: UnixStream, deadline: Instant) -> Self {
        Self { stream, deadline }
    }

    fn set_deadline(&mut self, deadline: Instant) {
        self.deadline = deadline;
    }

    fn remaining(&self) -> io::Result<Duration> {
        self.deadline
            .checked_duration_since(Instant::now())
            .filter(|remaining| !remaining.is_zero())
            .ok_or_else(|| io::Error::new(io::ErrorKind::TimedOut, "deadline exceeded"))
    }
}

impl Read for DeadlineUnixStream {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        self.stream.set_read_timeout(Some(self.remaining()?))?;
        self.stream.read(buffer)
    }
}

impl Write for DeadlineUnixStream {
    fn write(&mut self, buffer: &[u8]) -> io::Result<usize> {
        self.stream.set_write_timeout(Some(self.remaining()?))?;
        self.stream.write(buffer)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.stream.set_write_timeout(Some(self.remaining()?))?;
        self.stream.flush()
    }
}

fn stage_deadline(total: Instant, allowance: Duration) -> Result<Instant, ProviderErrorCode> {
    ensure_provider_before(total)?;
    Ok(Instant::now()
        .checked_add(allowance)
        .unwrap_or(total)
        .min(total))
}

fn connect_egress(deadline: Instant) -> Result<UnixStream, ProviderErrorCode> {
    let socket = socket_with(
        AddressFamily::UNIX,
        SocketType::STREAM,
        SocketFlags::CLOEXEC | SocketFlags::NONBLOCK,
        None,
    )
    .map_err(|_| ProviderErrorCode::Transport)?;
    let address =
        SocketAddrUnix::new(EGRESS_SOCKET_PATH).map_err(|_| ProviderErrorCode::Transport)?;
    match connect(&socket, &address) {
        Ok(()) => {}
        Err(error) if error == rustix::io::Errno::INPROGRESS => {
            wait_ready(socket.as_fd(), PollFlags::OUT, deadline).map_err(map_executor_io)?;
            rustix::net::sockopt::socket_error(&socket)
                .map_err(|_| ProviderErrorCode::Transport)?
                .map_err(|_| ProviderErrorCode::Transport)?;
        }
        Err(_) => return Err(ProviderErrorCode::Transport),
    }
    let peer: SocketAddrUnix = rustix::net::getpeername(&socket)
        .map_err(|_| ProviderErrorCode::Transport)?
        .ok_or(ProviderErrorCode::Transport)?
        .try_into()
        .map_err(|_| ProviderErrorCode::Transport)?;
    if rustix::net::sockopt::socket_domain(&socket).map_err(|_| ProviderErrorCode::Transport)?
        != AddressFamily::UNIX
        || rustix::net::sockopt::socket_type(&socket).map_err(|_| ProviderErrorCode::Transport)?
            != SocketType::STREAM
        || rustix::net::sockopt::socket_acceptconn(&socket)
            .map_err(|_| ProviderErrorCode::Transport)?
        || peer.path_bytes() != Some(EGRESS_SOCKET_PATH.as_bytes())
    {
        return Err(ProviderErrorCode::Transport);
    }
    let status = rfs::fcntl_getfl(&socket).map_err(|_| ProviderErrorCode::Transport)?;
    rfs::fcntl_setfl(&socket, status & !OFlags::NONBLOCK)
        .map_err(|_| ProviderErrorCode::Transport)?;
    Ok(UnixStream::from(socket))
}

fn fixed_openai_exchange(
    prepared: &PreparedOpenAiExchange,
    api_key: &[u8],
    deadline: Instant,
    tls_config: Arc<ClientConfig>,
) -> Result<ProviderResponse, ProviderErrorCode> {
    ensure_provider_before(deadline)?;
    let connect_deadline = stage_deadline(deadline, EGRESS_CONNECT_TIMEOUT)?;
    let stream = connect_egress(connect_deadline)?;
    fixed_openai_exchange_over_stream(prepared, api_key, deadline, tls_config, stream)
}

fn fixed_openai_exchange_over_stream(
    prepared: &PreparedOpenAiExchange,
    api_key: &[u8],
    deadline: Instant,
    tls_config: Arc<ClientConfig>,
    stream: UnixStream,
) -> Result<ProviderResponse, ProviderErrorCode> {
    ensure_provider_before(deadline)?;
    if prepared.method() != "POST"
        || prepared.path() != "/v1/responses"
        || prepared.content_type() != "application/json"
        || prepared.body().is_empty()
    {
        return Err(ProviderErrorCode::InvalidRequest);
    }
    validate_openai_api_key_bytes(api_key).map_err(|_| ProviderErrorCode::Transport)?;
    let server_name = ServerName::try_from(OPENAI_HOST)
        .map_err(|_| ProviderErrorCode::Transport)?
        .to_owned();
    let connection =
        ClientConnection::new(tls_config, server_name).map_err(|_| ProviderErrorCode::Transport)?;
    let handshake_deadline = stage_deadline(deadline, TLS_HANDSHAKE_TIMEOUT)?;
    let mut tls = StreamOwned::new(
        connection,
        DeadlineUnixStream::new(stream, handshake_deadline),
    );
    while tls.conn.is_handshaking() {
        ensure_provider_before(handshake_deadline)?;
        tls.conn.complete_io(&mut tls.sock).map_err(map_std_io)?;
    }
    if tls.conn.alpn_protocol() != Some(b"http/1.1".as_slice()) {
        return Err(ProviderErrorCode::Transport);
    }

    const FIXED_PREFIX: &[u8] =
        b"POST /v1/responses HTTP/1.1\r\nHost: api.openai.com\r\nAuthorization: Bearer ";
    let fixed_suffix = format!(
        "\r\nContent-Type: application/json\r\nAccept: application/json\r\nAccept-Encoding: identity\r\nConnection: close\r\nContent-Length: {}\r\n\r\n",
        prepared.body().len()
    );
    let write_deadline = stage_deadline(deadline, HTTP_WRITE_TIMEOUT)?;
    tls.sock.set_deadline(write_deadline);
    // Keep the credential in its original zeroizing allocation. Segment the
    // fixed HTTP write so no second application-owned buffer ever combines
    // the key with headers or diagnosis evidence.
    tls.write_all(FIXED_PREFIX).map_err(map_std_io)?;
    tls.write_all(api_key).map_err(map_std_io)?;
    tls.write_all(fixed_suffix.as_bytes()).map_err(map_std_io)?;
    tls.write_all(prepared.body()).map_err(map_std_io)?;
    tls.flush().map_err(map_std_io)?;

    tls.sock.set_deadline(deadline);
    let response = read_http_response(&mut tls, deadline)?;
    let decoded = decode_openai_response(
        prepared,
        response.status,
        &response.content_type,
        response.content_encoding.as_deref(),
        &response.body,
    )
    .map_err(map_decode_error)?;
    Ok(decoded.into_parts().0)
}

fn map_std_io(error: io::Error) -> ProviderErrorCode {
    match error.kind() {
        io::ErrorKind::TimedOut | io::ErrorKind::WouldBlock => ProviderErrorCode::Timeout,
        _ => ProviderErrorCode::Transport,
    }
}

struct HttpResponseParts {
    status: u16,
    content_type: Vec<u8>,
    content_encoding: Option<Vec<u8>>,
    body: Vec<u8>,
}

fn read_http_response(
    tls: &mut StreamOwned<ClientConnection, DeadlineUnixStream>,
    deadline: Instant,
) -> Result<HttpResponseParts, ProviderErrorCode> {
    let mut wire = Vec::with_capacity(8192);
    loop {
        ensure_provider_before(deadline)?;
        if let Some(response) = try_parse_http_response(&wire, false)? {
            return Ok(response);
        }
        if wire.len() >= MAX_HTTP_WIRE_BYTES {
            return Err(ProviderErrorCode::ResponseTooLarge);
        }
        let mut buffer = [0_u8; 4096];
        let read = tls.read(&mut buffer).map_err(map_std_io)?;
        if read == 0 {
            return try_parse_http_response(&wire, true)?.ok_or(ProviderErrorCode::InvalidResponse);
        }
        if wire.len().saturating_add(read) > MAX_HTTP_WIRE_BYTES {
            return Err(ProviderErrorCode::ResponseTooLarge);
        }
        wire.extend_from_slice(&buffer[..read]);
    }
}

fn try_parse_http_response(
    wire: &[u8],
    eof: bool,
) -> Result<Option<HttpResponseParts>, ProviderErrorCode> {
    let mut headers = [httparse::EMPTY_HEADER; MAX_HTTP_HEADERS];
    let mut response = httparse::Response::new(&mut headers);
    let header_bytes = match response
        .parse(wire)
        .map_err(|_| ProviderErrorCode::InvalidResponse)?
    {
        httparse::Status::Complete(bytes) => bytes,
        httparse::Status::Partial if !eof && wire.len() <= MAX_HTTP_HEADER_BYTES => {
            return Ok(None);
        }
        httparse::Status::Partial => return Err(ProviderErrorCode::InvalidResponse),
    };
    if header_bytes > MAX_HTTP_HEADER_BYTES || response.version != Some(1) {
        return Err(ProviderErrorCode::InvalidResponse);
    }
    let status = response.code.ok_or(ProviderErrorCode::InvalidResponse)?;
    for singleton in [
        "content-length",
        "transfer-encoding",
        "content-type",
        "content-encoding",
        "connection",
    ] {
        if response
            .headers
            .iter()
            .filter(|header| header.name.eq_ignore_ascii_case(singleton))
            .count()
            > 1
        {
            return Err(ProviderErrorCode::InvalidResponse);
        }
    }
    let header = |name: &str| {
        response
            .headers
            .iter()
            .find(|header| header.name.eq_ignore_ascii_case(name))
            .map(|header| header.value)
    };
    let content_type = header("content-type")
        .ok_or(ProviderErrorCode::InvalidResponse)?
        .to_vec();
    let content_encoding = header("content-encoding").map(<[u8]>::to_vec);
    let transfer_encoding = header("transfer-encoding");
    let content_length = header("content-length");
    if transfer_encoding.is_some() && content_length.is_some() {
        return Err(ProviderErrorCode::InvalidResponse);
    }
    let body_wire = &wire[header_bytes..];
    let body = if let Some(value) = content_length {
        if value.is_empty() || !value.iter().all(u8::is_ascii_digit) {
            return Err(ProviderErrorCode::InvalidResponse);
        }
        let length = std::str::from_utf8(value)
            .ok()
            .and_then(|value| value.parse::<usize>().ok())
            .ok_or(ProviderErrorCode::InvalidResponse)?;
        if length > MAX_OPENAI_RESPONSE_BODY_BYTES {
            return Err(ProviderErrorCode::ResponseTooLarge);
        }
        if body_wire.len() < length && !eof {
            return Ok(None);
        }
        if body_wire.len() != length {
            return Err(ProviderErrorCode::InvalidResponse);
        }
        body_wire.to_vec()
    } else if let Some(value) = transfer_encoding {
        if !value.eq_ignore_ascii_case(b"chunked") {
            return Err(ProviderErrorCode::InvalidResponse);
        }
        match decode_chunked_body(body_wire)? {
            ChunkedBody::Partial if !eof => return Ok(None),
            ChunkedBody::Partial => return Err(ProviderErrorCode::InvalidResponse),
            ChunkedBody::Complete { body, consumed } if consumed == body_wire.len() => body,
            ChunkedBody::Complete { .. } => return Err(ProviderErrorCode::InvalidResponse),
        }
    } else {
        if !eof {
            return Ok(None);
        }
        if body_wire.len() > MAX_OPENAI_RESPONSE_BODY_BYTES {
            return Err(ProviderErrorCode::ResponseTooLarge);
        }
        body_wire.to_vec()
    };
    Ok(Some(HttpResponseParts {
        status,
        content_type,
        content_encoding,
        body,
    }))
}

enum ChunkedBody {
    Partial,
    Complete { body: Vec<u8>, consumed: usize },
}

fn decode_chunked_body(wire: &[u8]) -> Result<ChunkedBody, ProviderErrorCode> {
    let mut cursor = 0_usize;
    let mut body = Vec::new();
    loop {
        let Some(line_end) = wire[cursor..]
            .windows(2)
            .position(|window| window == b"\r\n")
            .map(|offset| cursor + offset)
        else {
            return if wire.len().saturating_sub(cursor) <= 32 {
                Ok(ChunkedBody::Partial)
            } else {
                Err(ProviderErrorCode::InvalidResponse)
            };
        };
        let size_bytes = &wire[cursor..line_end];
        if size_bytes.is_empty()
            || size_bytes.len() > 16
            || !size_bytes.iter().all(u8::is_ascii_hexdigit)
        {
            return Err(ProviderErrorCode::InvalidResponse);
        }
        let size = std::str::from_utf8(size_bytes)
            .ok()
            .and_then(|value| usize::from_str_radix(value, 16).ok())
            .ok_or(ProviderErrorCode::InvalidResponse)?;
        cursor = line_end + 2;
        if size == 0 {
            if wire.len() < cursor + 2 {
                return Ok(ChunkedBody::Partial);
            }
            if &wire[cursor..cursor + 2] != b"\r\n" {
                return Err(ProviderErrorCode::InvalidResponse);
            }
            cursor += 2;
            return Ok(ChunkedBody::Complete {
                body,
                consumed: cursor,
            });
        }
        if body.len().saturating_add(size) > MAX_OPENAI_RESPONSE_BODY_BYTES {
            return Err(ProviderErrorCode::ResponseTooLarge);
        }
        let data_end = cursor
            .checked_add(size)
            .ok_or(ProviderErrorCode::ResponseTooLarge)?;
        let frame_end = data_end
            .checked_add(2)
            .ok_or(ProviderErrorCode::ResponseTooLarge)?;
        if wire.len() < frame_end {
            return Ok(ChunkedBody::Partial);
        }
        if &wire[data_end..frame_end] != b"\r\n" {
            return Err(ProviderErrorCode::InvalidResponse);
        }
        body.extend_from_slice(&wire[cursor..data_end]);
        cursor = frame_end;
    }
}

/// Serves exactly one packet from the connected socket inherited on standard
/// input. The function intentionally does not inspect argv or environment and
/// writes no diagnostic stream.
pub fn run_socket_activated_once() -> Result<(), ExecutorError> {
    use rustix::process::{DumpableBehavior, dumpable_behavior, set_dumpable_behavior};
    set_dumpable_behavior(DumpableBehavior::NotDumpable)
        .map_err(|_| ExecutorError::InvalidSocket)?;
    if dumpable_behavior().map_err(|_| ExecutorError::InvalidSocket)?
        != DumpableBehavior::NotDumpable
    {
        return Err(ExecutorError::InvalidSocket);
    }
    let input = stdin();
    serve_one(
        input.as_fd(),
        Some(PROVIDER_SOCKET_PATH),
        &SystemBoundaries,
        &SystemBoundaries,
    )
}

fn serve_one(
    socket: BorrowedFd<'_>,
    expected_local_path: Option<&[u8]>,
    vault: &dyn VaultBoundary,
    openai: &dyn OpenAiBoundary,
) -> Result<(), ExecutorError> {
    prepare_client_socket(socket, expected_local_path)?;
    let receive_deadline = Instant::now()
        .checked_add(REQUEST_TIMEOUT)
        .ok_or(ExecutorError::TimedOut)?;
    let frame = receive_frame(socket, receive_deadline)?;
    let request = parse_request_frame(&frame).map_err(|_| ExecutorError::InvalidRequest)?;
    let mut lease = None;
    let response = match &request {
        ProviderRequest::Status { request_id } => match vault.observe(request_id, receive_deadline)
        {
            Ok(status) => ProviderResponse::status(request_id, status),
            Err(error) => ProviderResponse::error(request_id, ProviderOperation::Status, error),
        },
        ProviderRequest::ContextPreview {
            request_id,
            preview,
        } => ProviderResponse::context_preview(request_id, preview.clone()),
        ProviderRequest::DiagnoseBindingMismatch { request_id } => ProviderResponse::error(
            request_id,
            ProviderOperation::Diagnose,
            ProviderErrorCode::InvalidRequest,
        ),
        ProviderRequest::Diagnose { request_id, .. } => {
            let prepared = match prepare_openai_exchange(&request) {
                Ok(prepared) => prepared,
                Err(error) => {
                    let error = map_prepare_error(error);
                    return send_provider_error(socket, request_id, error);
                }
            };
            let borrow_deadline = Instant::now()
                .checked_add(BORROW_TIMEOUT)
                .ok_or(ExecutorError::TimedOut)?;
            match vault.borrow_openai(request_id, borrow_deadline) {
                Ok(borrowed) => {
                    lease = Some(borrowed);
                    let borrowed = lease.as_ref().ok_or(ExecutorError::IoFailed)?;
                    match read_openai_key(
                        borrowed.key_pipe.as_fd(),
                        borrowed.declared_size,
                        borrow_deadline,
                    ) {
                        Ok(api_key) => {
                            let exchange_deadline = Instant::now()
                                .checked_add(HTTPS_TIMEOUT)
                                .ok_or(ExecutorError::TimedOut)?;
                            match openai.exchange(&prepared, &api_key, exchange_deadline) {
                                Ok(response) => Ok(response),
                                Err(error) => ProviderResponse::error(
                                    request_id,
                                    ProviderOperation::Diagnose,
                                    error,
                                ),
                            }
                        }
                        Err(error) => {
                            ProviderResponse::error(request_id, ProviderOperation::Diagnose, error)
                        }
                    }
                }
                Err(error) => {
                    ProviderResponse::error(request_id, ProviderOperation::Diagnose, error)
                }
            }
        }
    }
    .map_err(|_| ExecutorError::InvalidRequest)?;
    let encoded = encode_response_frame(&response).map_err(|_| ExecutorError::IoFailed)?;
    let send_deadline = Instant::now()
        .checked_add(REQUEST_TIMEOUT)
        .ok_or(ExecutorError::TimedOut)?;
    let result = send_frame(socket, &encoded, send_deadline);
    // Keep the authenticated vault control socket (and therefore the exact
    // lease identity) alive through both HTTPS completion and local response
    // delivery. Process exit supplies the independent pidfd factor.
    drop(lease);
    result
}

fn send_provider_error(
    socket: BorrowedFd<'_>,
    request_id: &str,
    error: ProviderErrorCode,
) -> Result<(), ExecutorError> {
    let response = ProviderResponse::error(request_id, ProviderOperation::Diagnose, error)
        .map_err(|_| ExecutorError::InvalidRequest)?;
    let encoded = encode_response_frame(&response).map_err(|_| ExecutorError::IoFailed)?;
    let deadline = Instant::now()
        .checked_add(REQUEST_TIMEOUT)
        .ok_or(ExecutorError::TimedOut)?;
    send_frame(socket, &encoded, deadline)
}

fn prepare_client_socket(
    socket: BorrowedFd<'_>,
    expected_local_path: Option<&[u8]>,
) -> Result<(), ExecutorError> {
    let mut descriptor_flags =
        rustix::io::fcntl_getfd(socket).map_err(|_| ExecutorError::InvalidSocket)?;
    descriptor_flags.insert(rustix::io::FdFlags::CLOEXEC);
    rustix::io::fcntl_setfd(socket, descriptor_flags).map_err(|_| ExecutorError::InvalidSocket)?;
    let status = rfs::fcntl_getfl(socket).map_err(|_| ExecutorError::InvalidSocket)?;
    rfs::fcntl_setfl(socket, status | OFlags::NONBLOCK)
        .map_err(|_| ExecutorError::InvalidSocket)?;
    let local: SocketAddrUnix = rustix::net::getsockname(socket)
        .map_err(|_| ExecutorError::InvalidSocket)?
        .try_into()
        .map_err(|_| ExecutorError::InvalidSocket)?;
    let peer =
        rustix::net::sockopt::socket_peercred(socket).map_err(|_| ExecutorError::InvalidSocket)?;
    if rustix::net::sockopt::socket_domain(socket).map_err(|_| ExecutorError::InvalidSocket)?
        != AddressFamily::UNIX
        || rustix::net::sockopt::socket_type(socket).map_err(|_| ExecutorError::InvalidSocket)?
            != SocketType::SEQPACKET
        || rustix::net::sockopt::socket_acceptconn(socket)
            .map_err(|_| ExecutorError::InvalidSocket)?
        || rustix::net::getpeername(socket).is_err()
        || peer.uid.as_raw() == 0
        || rustix::net::sockopt::socket_passcred(socket)
            .map_err(|_| ExecutorError::InvalidSocket)?
        || expected_local_path.is_some_and(|expected| local.path_bytes() != Some(expected))
    {
        return Err(ExecutorError::InvalidSocket);
    }
    Ok(())
}

fn receive_frame(socket: BorrowedFd<'_>, deadline: Instant) -> Result<Vec<u8>, ExecutorError> {
    let mut bytes = vec![0_u8; MAX_REQUEST_FRAME_BYTES + 1];
    let mut io = [IoSliceMut::new(&mut bytes)];
    // Deliberately provide zero ancillary capacity. Linux reports every cmsg
    // kind, including kinds not modeled by rustix, through MSG_CTRUNC and
    // closes any excess SCM_RIGHTS descriptors in the kernel.
    let mut control_space: [MaybeUninit<u8>; 0] = [];
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
            Err(_) => return Err(ExecutorError::IoFailed),
        }
    };
    if message.flags.contains(ReturnFlags::TRUNC) || message.bytes > MAX_REQUEST_FRAME_BYTES {
        return Err(ExecutorError::RequestTooLarge);
    }
    if message.flags.contains(ReturnFlags::CTRUNC) {
        return Err(ExecutorError::UnexpectedAncillary);
    }
    if message.bytes == 0 {
        return Err(ExecutorError::NoData);
    }
    bytes.truncate(message.bytes);
    Ok(bytes)
}

fn send_frame(
    socket: BorrowedFd<'_>,
    frame: &[u8],
    deadline: Instant,
) -> Result<(), ExecutorError> {
    let sent = loop {
        ensure_before(deadline)?;
        match send(socket, frame, SendFlags::DONTWAIT | SendFlags::NOSIGNAL) {
            Ok(sent) => break sent,
            Err(error) if error == rustix::io::Errno::INTR => {}
            Err(error) if error == rustix::io::Errno::AGAIN => {
                wait_ready(socket, PollFlags::OUT, deadline)?;
            }
            Err(_) => return Err(ExecutorError::IoFailed),
        }
    };
    if sent == frame.len() {
        Ok(())
    } else {
        Err(ExecutorError::IncompleteSend)
    }
}

fn ensure_before(deadline: Instant) -> Result<(), ExecutorError> {
    deadline
        .checked_duration_since(Instant::now())
        .filter(|remaining| !remaining.is_zero())
        .map(|_| ())
        .ok_or(ExecutorError::TimedOut)
}

fn wait_ready(
    socket: BorrowedFd<'_>,
    interest: PollFlags,
    deadline: Instant,
) -> Result<(), ExecutorError> {
    loop {
        let remaining = deadline
            .checked_duration_since(Instant::now())
            .filter(|remaining| !remaining.is_zero())
            .ok_or(ExecutorError::TimedOut)?;
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
            Ok(0) => return Err(ExecutorError::TimedOut),
            Ok(_) => {
                let ready = descriptors[0].revents();
                if ready.contains(PollFlags::NVAL) {
                    return Err(ExecutorError::InvalidSocket);
                }
                if ready.intersects(interest | PollFlags::ERR | PollFlags::HUP | PollFlags::RDHUP) {
                    return Ok(());
                }
            }
            Err(error) if error == rustix::io::Errno::INTR => {}
            Err(_) => return Err(ExecutorError::IoFailed),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rcgen::generate_simple_self_signed;
    use rustix::{
        io::Errno,
        net::{SendAncillaryBuffer, SendAncillaryMessage, SocketFlags, recv, sendmsg, socketpair},
        pipe::{PipeFlags, pipe_with},
    };
    use rustls::{ServerConfig, ServerConnection, pki_types::PrivateKeyDer};
    use std::{
        cell::{Cell, RefCell},
        io::IoSlice,
        thread,
    };

    const STATUS_REQUEST: &[u8] =
        include_bytes!("../../../packages/schemas/fixtures/rescue-openai/valid/status.request.raw");
    const DIAGNOSE_REQUEST: &[u8] = include_bytes!(
        "../../../packages/schemas/fixtures/rescue-openai/valid/linux-generic-canary.request.raw"
    );
    const CONTEXT_PREVIEW_REQUEST: &[u8] = include_bytes!(
        "../../../packages/schemas/fixtures/rescue-openai/valid/windows-generic-context-preview.request.raw"
    );
    const OPENAI_RESPONSE: &[u8] = include_bytes!(
        "../../rescue-openai-provider/testdata/openai-responses-v1/linux-generic-canary.response.json"
    );

    struct FakeVault {
        calls: Cell<usize>,
        borrow_calls: Cell<usize>,
        result: RefCell<Result<ProviderStatus, ProviderErrorCode>>,
        borrow_result: RefCell<Result<Vec<u8>, ProviderErrorCode>>,
        control_peer: RefCell<Option<OwnedFd>>,
    }

    impl FakeVault {
        fn configured() -> Self {
            Self {
                calls: Cell::new(0),
                borrow_calls: Cell::new(0),
                result: RefCell::new(Ok(ProviderStatus::new(
                    VaultState::Unlocked,
                    CredentialState::Configured,
                )
                .expect("valid configured status"))),
                borrow_result: RefCell::new(Ok(b"TEST_ONLY_TOKEN_BYTES".to_vec())),
                control_peer: RefCell::new(None),
            }
        }
    }

    impl VaultBoundary for FakeVault {
        fn observe(
            &self,
            _provider_request_id: &str,
            _deadline: Instant,
        ) -> Result<ProviderStatus, ProviderErrorCode> {
            self.calls.set(self.calls.get() + 1);
            self.result.borrow().clone()
        }

        fn borrow_openai(
            &self,
            _provider_request_id: &str,
            _deadline: Instant,
        ) -> Result<BorrowedCredential, ProviderErrorCode> {
            self.borrow_calls.set(self.borrow_calls.get() + 1);
            let value = self.borrow_result.borrow().clone()?;
            let (read, write) = pipe_with(PipeFlags::CLOEXEC | PipeFlags::NONBLOCK)
                .map_err(|_| ProviderErrorCode::Transport)?;
            if rustix::io::write(&write, &value).ok() != Some(value.len()) {
                return Err(ProviderErrorCode::Transport);
            }
            drop(write);
            let (control, peer) = seqpacket_pair();
            *self.control_peer.borrow_mut() = Some(peer);
            Ok(BorrowedCredential {
                _control_socket: control,
                key_pipe: read,
                declared_size: u64::try_from(value.len())
                    .map_err(|_| ProviderErrorCode::Transport)?,
            })
        }
    }

    struct FakeOpenAi<'vault> {
        calls: Cell<usize>,
        result: ProviderErrorCode,
        vault: Option<&'vault FakeVault>,
        lease_was_live: Cell<bool>,
    }

    impl Default for FakeOpenAi<'_> {
        fn default() -> Self {
            Self {
                calls: Cell::new(0),
                result: ProviderErrorCode::Upstream,
                vault: None,
                lease_was_live: Cell::new(false),
            }
        }
    }

    impl OpenAiBoundary for FakeOpenAi<'_> {
        fn exchange(
            &self,
            _prepared: &PreparedOpenAiExchange,
            api_key: &[u8],
            _deadline: Instant,
        ) -> Result<ProviderResponse, ProviderErrorCode> {
            assert!(
                api_key == b"TEST_ONLY_TOKEN_BYTES",
                "fake boundary received unexpected credential bytes"
            );
            if let Some(vault) = self.vault {
                let peer = vault.control_peer.borrow();
                let peer = peer.as_ref().expect("lease control observer");
                let mut byte = [0_u8; 1];
                let live = matches!(
                    recv(peer, &mut byte, RecvFlags::PEEK | RecvFlags::DONTWAIT),
                    Err(error) if error == Errno::AGAIN
                );
                assert!(live, "lease control socket closed before HTTPS exchange");
                self.lease_was_live.set(true);
            }
            self.calls.set(self.calls.get() + 1);
            Err(self.result)
        }
    }

    fn seqpacket_pair() -> (OwnedFd, OwnedFd) {
        socketpair(
            AddressFamily::UNIX,
            SocketType::SEQPACKET,
            SocketFlags::CLOEXEC,
            None,
        )
        .expect("seqpacket pair")
    }

    fn generated_tls_server(
        subject_name: &str,
        alpn_protocols: Vec<Vec<u8>>,
    ) -> (RootCertStore, Arc<ServerConfig>) {
        let certified = generate_simple_self_signed(vec![subject_name.to_owned()])
            .expect("local TLS certificate");
        let mut roots = RootCertStore::empty();
        roots
            .add(certified.cert.der().clone())
            .expect("local test root");
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let key = PrivateKeyDer::Pkcs8(certified.signing_key.serialize_der().into());
        let mut server = ServerConfig::builder_with_provider(provider)
            .with_protocol_versions(&[&rustls::version::TLS13, &rustls::version::TLS12])
            .expect("TLS versions")
            .with_no_client_auth()
            .with_single_cert(vec![certified.cert.der().clone()], key)
            .expect("server certificate");
        server.alpn_protocols = alpn_protocols;
        (roots, Arc::new(server))
    }

    fn local_tls_configs() -> (Arc<ClientConfig>, Arc<ServerConfig>) {
        let (roots, server) = generated_tls_server(OPENAI_HOST, vec![b"http/1.1".to_vec()]);
        let client = test_tls_config(roots).expect("test-only root seam");
        (client, server)
    }

    fn find_header_end(bytes: &[u8]) -> Option<usize> {
        bytes
            .windows(4)
            .position(|window| window == b"\r\n\r\n")
            .map(|offset| offset + 4)
    }

    fn read_test_http_request(stream: &mut StreamOwned<ServerConnection, UnixStream>) -> Vec<u8> {
        stream
            .sock
            .set_read_timeout(Some(Duration::from_secs(2)))
            .expect("server read timeout");
        let mut request = Vec::new();
        let expected = loop {
            if let Some(header_end) = find_header_end(&request) {
                let header = &request[..header_end];
                let marker = b"\r\nContent-Length: ";
                let start = header
                    .windows(marker.len())
                    .position(|window| window == marker)
                    .map(|offset| offset + marker.len())
                    .expect("fixed content length header");
                let end = header[start..]
                    .windows(2)
                    .position(|window| window == b"\r\n")
                    .map(|offset| start + offset)
                    .expect("content length terminator");
                let length = std::str::from_utf8(&header[start..end])
                    .expect("content length text")
                    .parse::<usize>()
                    .expect("content length number");
                break header_end + length;
            }
            let mut buffer = [0_u8; 4096];
            let read = stream.read(&mut buffer).expect("TLS request header");
            assert!(read > 0, "TLS request closed before headers");
            request.extend_from_slice(&buffer[..read]);
        };
        while request.len() < expected {
            let mut buffer = [0_u8; 4096];
            let read = stream.read(&mut buffer).expect("TLS request body");
            assert!(read > 0, "TLS request closed before body");
            request.extend_from_slice(&buffer[..read]);
        }
        assert!(
            request.len() == expected,
            "unexpected trailing request bytes"
        );
        request
    }

    fn complete_test_server_handshake(config: Arc<ServerConfig>, mut stream: UnixStream) {
        let Ok(mut connection) = ServerConnection::new(config) else {
            return;
        };
        stream
            .set_read_timeout(Some(Duration::from_secs(2)))
            .expect("handshake read timeout");
        stream
            .set_write_timeout(Some(Duration::from_secs(2)))
            .expect("handshake write timeout");
        while connection.is_handshaking() {
            if connection.complete_io(&mut stream).is_err() {
                return;
            }
        }
    }

    fn execute(
        frame: &[u8],
        vault: &FakeVault,
        openai: &FakeOpenAi<'_>,
    ) -> (ProviderRequest, ProviderResponse) {
        let (client, server) = seqpacket_pair();
        assert_eq!(
            send(&client, frame, SendFlags::NOSIGNAL).expect("request send"),
            frame.len()
        );
        serve_one(server.as_fd(), None, vault, openai).expect("serve request");
        let mut response = vec![0_u8; 64 * 1024];
        let (initialized, read) =
            recv(&client, &mut response, RecvFlags::empty()).expect("response receive");
        assert_eq!(initialized, read);
        response.truncate(read);
        let request = parse_request_frame(frame).expect("request fixture");
        let parsed = kernaid_rescue_openai_provider::parse_response_frame(&request, &response)
            .expect("executor response");
        (request, parsed)
    }

    #[test]
    fn status_maps_presence_only_and_contacts_the_vault_once() {
        let openai = FakeOpenAi::default();
        for (vault_state, credential) in [
            (VaultState::Unlocked, CredentialState::Configured),
            (VaultState::Unlocked, CredentialState::Absent),
            (VaultState::Locked, CredentialState::Unavailable),
            (VaultState::Unlocking, CredentialState::Unavailable),
            (VaultState::Locking, CredentialState::Unavailable),
            (
                VaultState::FaultedRebootRequired,
                CredentialState::Unavailable,
            ),
        ] {
            let vault = FakeVault {
                calls: Cell::new(0),
                borrow_calls: Cell::new(0),
                result: RefCell::new(Ok(
                    ProviderStatus::new(vault_state, credential).expect("valid status fixture")
                )),
                borrow_result: RefCell::new(Ok(b"TEST_ONLY_TOKEN_BYTES".to_vec())),
                control_peer: RefCell::new(None),
            };
            let (_, response) = execute(STATUS_REQUEST, &vault, &openai);
            let status = response.status_payload().expect("status payload");
            assert_eq!(status.vault(), vault_state);
            assert_eq!(status.credential(), credential);
            assert_eq!(vault.calls.get(), 1);
            assert_eq!(vault.borrow_calls.get(), 0);
        }
        assert_eq!(openai.calls.get(), 0);
    }

    #[test]
    fn diagnose_borrows_once_and_maps_the_fixed_exchange_error() {
        let vault = FakeVault::configured();
        let openai = FakeOpenAi::default();
        let (_, response) = execute(DIAGNOSE_REQUEST, &vault, &openai);
        assert_eq!(response.operation(), ProviderOperation::Diagnose);
        assert_eq!(response.error_code(), Some(ProviderErrorCode::Upstream));
        assert_eq!(vault.calls.get(), 0);
        assert_eq!(vault.borrow_calls.get(), 1);
        assert_eq!(openai.calls.get(), 1);
    }

    #[test]
    fn context_preview_borrows_no_credential_and_performs_no_egress() {
        let vault = FakeVault::configured();
        let openai = FakeOpenAi::default();
        let (_, response) = execute(CONTEXT_PREVIEW_REQUEST, &vault, &openai);
        assert_eq!(response.operation(), ProviderOperation::ContextPreview);
        assert!(response.context_preview_payload().is_some());
        assert_eq!(vault.calls.get(), 0);
        assert_eq!(vault.borrow_calls.get(), 0);
        assert_eq!(openai.calls.get(), 0);
    }

    #[test]
    fn context_digest_mismatch_fails_before_credential_or_egress() {
        let vault = FakeVault::configured();
        let openai = FakeOpenAi::default();
        let valid = String::from_utf8(DIAGNOSE_REQUEST.to_vec()).expect("UTF-8 fixture");
        let invalid = valid.replace(
            "sha256:f2812750246df0fa9872fc8d5af373636edf5ae79121fdec380bc7dfc22a5b78",
            "sha256:02812750246df0fa9872fc8d5af373636edf5ae79121fdec380bc7dfc22a5b78",
        );
        assert_ne!(valid, invalid);
        let (_, response) = execute(invalid.as_bytes(), &vault, &openai);
        assert_eq!(response.operation(), ProviderOperation::Diagnose);
        assert_eq!(
            response.error_code(),
            Some(ProviderErrorCode::InvalidRequest)
        );
        assert_eq!(vault.calls.get(), 0);
        assert_eq!(vault.borrow_calls.get(), 0);
        assert_eq!(openai.calls.get(), 0);
    }

    #[test]
    fn lease_control_socket_stays_live_through_exchange_then_closes_after_local_send() {
        let vault = FakeVault::configured();
        let openai = FakeOpenAi {
            calls: Cell::new(0),
            result: ProviderErrorCode::Upstream,
            vault: Some(&vault),
            lease_was_live: Cell::new(false),
        };
        let (_, response) = execute(DIAGNOSE_REQUEST, &vault, &openai);
        assert_eq!(response.error_code(), Some(ProviderErrorCode::Upstream));
        assert!(
            openai.lease_was_live.get(),
            "lease socket was not live during exchange"
        );
        let peer = vault.control_peer.borrow();
        let peer = peer.as_ref().expect("lease control observer");
        let mut byte = [0_u8; 1];
        assert!(
            matches!(
                recv(peer, &mut byte, RecvFlags::DONTWAIT),
                Ok((initialized, read)) if initialized == read && read == 0
            ),
            "lease socket remained open or was not observable"
        );
    }

    #[test]
    fn vault_failures_remain_closed_error_tokens() {
        let openai = FakeOpenAi::default();
        for (source, expected) in [
            (ProviderErrorCode::Busy, ProviderErrorCode::Busy),
            (ProviderErrorCode::Transport, ProviderErrorCode::Transport),
            (
                ProviderErrorCode::CredentialUnavailable,
                ProviderErrorCode::CredentialUnavailable,
            ),
        ] {
            let vault = FakeVault {
                calls: Cell::new(0),
                borrow_calls: Cell::new(0),
                result: RefCell::new(Err(source)),
                borrow_result: RefCell::new(Err(source)),
                control_peer: RefCell::new(None),
            };
            let (_, response) = execute(STATUS_REQUEST, &vault, &openai);
            assert_eq!(response.error_code(), Some(expected));
            assert_eq!(vault.calls.get(), 1);
        }
    }

    #[test]
    fn one_process_consumes_exactly_one_packet() {
        let vault = FakeVault::configured();
        let openai = FakeOpenAi::default();
        let (client, server) = seqpacket_pair();
        assert_eq!(
            send(&client, STATUS_REQUEST, SendFlags::NOSIGNAL).expect("first request"),
            STATUS_REQUEST.len()
        );
        serve_one(server.as_fd(), None, &vault, &openai).expect("serve one request");
        let mut response = vec![0_u8; 64 * 1024];
        let (initialized, read) =
            recv(&client, &mut response, RecvFlags::empty()).expect("first response");
        assert_eq!(initialized, read);
        assert!(read > 0);
        assert_eq!(
            send(&client, STATUS_REQUEST, SendFlags::NOSIGNAL).expect("second request"),
            STATUS_REQUEST.len()
        );
        drop(server);
        match recv(&client, &mut response, RecvFlags::empty()) {
            Ok((initialized, read)) => {
                assert_eq!(initialized, read);
                assert_eq!(read, 0);
            }
            Err(error) => assert_eq!(error, Errno::CONNRESET),
        }
        assert_eq!(vault.calls.get(), 1);
    }

    #[test]
    fn empty_and_invalid_packets_produce_no_data_response() {
        for frame in [&[][..], b"{}\n".as_slice()] {
            let vault = FakeVault::configured();
            let openai = FakeOpenAi::default();
            let (client, server) = seqpacket_pair();
            assert_eq!(
                send(&client, frame, SendFlags::NOSIGNAL).expect("invalid request"),
                frame.len()
            );
            let result = serve_one(server.as_fd(), None, &vault, &openai);
            assert!(matches!(
                result,
                Err(ExecutorError::NoData | ExecutorError::InvalidRequest)
            ));
            drop(server);
            let mut response = [0_u8; 1];
            let (initialized, read) =
                recv(&client, &mut response, RecvFlags::empty()).expect("closed response");
            assert_eq!(initialized, read);
            assert_eq!(read, 0);
            assert_eq!(vault.calls.get(), 0);
        }
    }

    #[test]
    fn descriptor_bearing_requests_are_rejected_before_dispatch() {
        let vault = FakeVault::configured();
        let openai = FakeOpenAi::default();
        let (client, server) = seqpacket_pair();
        let (read_end, write_end) = pipe_with(PipeFlags::CLOEXEC).expect("test pipe");
        let io = [IoSlice::new(STATUS_REQUEST)];
        let rights = [read_end.as_fd()];
        let mut space = [MaybeUninit::uninit(); rustix::cmsg_space!(ScmRights(1))];
        let mut ancillary = SendAncillaryBuffer::new(&mut space);
        assert!(ancillary.push(SendAncillaryMessage::ScmRights(&rights)));
        assert_eq!(
            sendmsg(&client, &io, &mut ancillary, SendFlags::NOSIGNAL).expect("descriptor request"),
            STATUS_REQUEST.len()
        );
        drop(read_end);
        assert_eq!(
            serve_one(server.as_fd(), None, &vault, &openai),
            Err(ExecutorError::UnexpectedAncillary)
        );
        drop(server);
        assert_eq!(rustix::io::write(&write_end, b"x").err(), Some(Errno::PIPE));
        assert_eq!(vault.calls.get(), 0);
    }

    #[test]
    fn test_only_root_seam_runs_one_fixed_tls_http_exchange() {
        let request = parse_request_frame(DIAGNOSE_REQUEST).expect("diagnose fixture");
        let prepared = prepare_openai_exchange(&request).expect("prepared fixed exchange");
        let expected_body = prepared.body().to_vec();
        let (client_config, server_config) = local_tls_configs();
        let (client_stream, server_stream) = UnixStream::pair().expect("local Unix stream");
        let server = thread::spawn(move || {
            let connection =
                ServerConnection::new(server_config).expect("local TLS server connection");
            let mut tls = StreamOwned::new(connection, server_stream);
            let request = read_test_http_request(&mut tls);
            let header_end = find_header_end(&request).expect("request headers");
            let headers = &request[..header_end];
            const AUTH_PREFIX: &[u8] =
                b"POST /v1/responses HTTP/1.1\r\nHost: api.openai.com\r\nAuthorization: Bearer ";
            assert!(
                headers.starts_with(AUTH_PREFIX),
                "fixed method/path/Host/auth header surface changed"
            );
            let token_end = headers[AUTH_PREFIX.len()..]
                .windows(2)
                .position(|window| window == b"\r\n")
                .map(|offset| AUTH_PREFIX.len() + offset)
                .expect("auth header terminator");
            assert!(
                headers[AUTH_PREFIX.len()..token_end] == *b"TEST_ONLY_TOKEN_BYTES",
                "segmented auth token bytes changed"
            );
            assert!(
                headers
                    .windows(b"\r\nAccept-Encoding: identity\r\n".len())
                    .any(|window| window == b"\r\nAccept-Encoding: identity\r\n"),
                "fixed identity encoding header missing"
            );
            assert!(
                request[header_end..] == expected_body,
                "opaque prepared request body changed in transport"
            );
            let response_head = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Encoding: identity\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                OPENAI_RESPONSE.len()
            );
            tls.write_all(response_head.as_bytes())
                .expect("TLS response headers");
            tls.write_all(OPENAI_RESPONSE).expect("TLS response body");
            tls.flush().expect("TLS response flush");
        });
        let response = fixed_openai_exchange_over_stream(
            &prepared,
            b"TEST_ONLY_TOKEN_BYTES",
            Instant::now() + Duration::from_secs(5),
            client_config,
            client_stream,
        )
        .expect("fixed local TLS exchange");
        assert_eq!(response.operation(), ProviderOperation::Diagnose);
        assert!(response.error_code().is_none());
        server.join().expect("local TLS server");
    }

    #[test]
    fn fixed_tls_rejects_untrusted_root_wrong_name_and_missing_http1_alpn() {
        let request = parse_request_frame(DIAGNOSE_REQUEST).expect("diagnose fixture");
        let prepared = prepare_openai_exchange(&request).expect("prepared fixed exchange");

        let (_roots, server_config) = generated_tls_server(OPENAI_HOST, vec![b"http/1.1".to_vec()]);
        let (client_stream, server_stream) = UnixStream::pair().expect("untrusted Unix stream");
        let server = thread::spawn(move || {
            complete_test_server_handshake(server_config, server_stream);
        });
        assert!(matches!(
            fixed_openai_exchange_over_stream(
                &prepared,
                b"TEST_ONLY_TOKEN_BYTES",
                Instant::now() + Duration::from_secs(3),
                production_tls_config().expect("production roots"),
                client_stream,
            ),
            Err(ProviderErrorCode::Transport)
        ));
        server.join().expect("untrusted TLS server");

        let (roots, server_config) =
            generated_tls_server("not-api.invalid", vec![b"http/1.1".to_vec()]);
        let client_config = test_tls_config(roots).expect("wrong-name test roots");
        let (client_stream, server_stream) = UnixStream::pair().expect("wrong-name Unix stream");
        let server = thread::spawn(move || {
            complete_test_server_handshake(server_config, server_stream);
        });
        assert!(matches!(
            fixed_openai_exchange_over_stream(
                &prepared,
                b"TEST_ONLY_TOKEN_BYTES",
                Instant::now() + Duration::from_secs(3),
                client_config,
                client_stream,
            ),
            Err(ProviderErrorCode::Transport)
        ));
        server.join().expect("wrong-name TLS server");

        let (roots, server_config) = generated_tls_server(OPENAI_HOST, vec![b"h2".to_vec()]);
        let client_config = test_tls_config(roots).expect("ALPN test roots");
        let (client_stream, server_stream) = UnixStream::pair().expect("ALPN Unix stream");
        let server = thread::spawn(move || {
            complete_test_server_handshake(server_config, server_stream);
        });
        assert!(matches!(
            fixed_openai_exchange_over_stream(
                &prepared,
                b"TEST_ONLY_TOKEN_BYTES",
                Instant::now() + Duration::from_secs(3),
                client_config,
                client_stream,
            ),
            Err(ProviderErrorCode::Transport)
        ));
        server.join().expect("ALPN TLS server");
    }

    #[test]
    fn strict_http_framing_accepts_cl_chunked_eof_and_repeated_ignored_headers() {
        let content_length = b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 2\r\nSet-Cookie: a=1\r\nSet-Cookie: b=2\r\n\r\n{}";
        let parsed = try_parse_http_response(content_length, false)
            .expect("content-length framing")
            .expect("complete content-length response");
        assert!(parsed.body == b"{}", "content-length body mismatch");

        let chunked = b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nTransfer-Encoding: chunked\r\n\r\n1\r\n{\r\n1\r\n}\r\n0\r\n\r\n";
        let parsed = try_parse_http_response(chunked, false)
            .expect("chunked framing")
            .expect("complete chunked response");
        assert!(parsed.body == b"{}", "chunked body mismatch");

        let eof = b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n{}";
        assert!(
            try_parse_http_response(eof, false)
                .expect("incomplete EOF framing")
                .is_none()
        );
        let parsed = try_parse_http_response(eof, true)
            .expect("EOF framing")
            .expect("complete EOF response");
        assert!(parsed.body == b"{}", "EOF body mismatch");
    }

    #[test]
    fn strict_http_framing_rejects_ambiguity_trailing_malformed_and_oversize() {
        for invalid in [
            &b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Type: application/json\r\nContent-Length: 2\r\n\r\n{}"[..],
            &b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 2\r\nTransfer-Encoding: chunked\r\n\r\n{}"[..],
            &b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 2\r\n\r\n{}x"[..],
            &b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nTransfer-Encoding: chunked\r\n\r\n2;x=1\r\n{}\r\n0\r\n\r\n"[..],
            &b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nTransfer-Encoding: chunked\r\n\r\n2\r\n{}xx\r\n0\r\n\r\n"[..],
        ] {
            assert!(
                try_parse_http_response(invalid, true).is_err(),
                "ambiguous or malformed framing was accepted"
            );
        }
        let oversized = format!(
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n",
            MAX_OPENAI_RESPONSE_BODY_BYTES + 1
        );
        assert!(matches!(
            try_parse_http_response(oversized.as_bytes(), false),
            Err(ProviderErrorCode::ResponseTooLarge)
        ));
        assert_eq!(
            ensure_provider_before(Instant::now() - Duration::from_millis(1)),
            Err(ProviderErrorCode::Timeout)
        );
    }

    #[test]
    fn key_pipe_use_boundary_requires_exact_private_pipe_hup_size_and_eof() {
        let value = b"TEST_ONLY_TOKEN_BYTES";
        let (read, write) =
            pipe_with(PipeFlags::CLOEXEC | PipeFlags::NONBLOCK).expect("exact key pipe");
        assert!(
            rustix::io::write(&write, value).ok() == Some(value.len()),
            "test key pipe write failed"
        );
        drop(write);
        let key = read_openai_key(
            read.as_fd(),
            u64::try_from(value.len()).expect("test size"),
            Instant::now() + Duration::from_secs(1),
        )
        .expect("exact key pipe read");
        assert!(key.as_slice() == value, "exact key pipe bytes changed");

        let (read, write) =
            pipe_with(PipeFlags::CLOEXEC | PipeFlags::NONBLOCK).expect("mismatch key pipe");
        assert!(
            rustix::io::write(&write, value).ok() == Some(value.len()),
            "test mismatch pipe write failed"
        );
        drop(write);
        assert!(
            matches!(
                read_openai_key(
                    read.as_fd(),
                    u64::try_from(value.len() - 1).expect("test mismatch size"),
                    Instant::now() + Duration::from_secs(1),
                ),
                Err(ProviderErrorCode::Transport)
            ),
            "declared-size mismatch was accepted"
        );

        let (read, write) =
            pipe_with(PipeFlags::CLOEXEC | PipeFlags::NONBLOCK).expect("open writer key pipe");
        assert!(
            rustix::io::write(&write, value).ok() == Some(value.len()),
            "test open-writer pipe write failed"
        );
        assert!(
            matches!(
                read_openai_key(
                    read.as_fd(),
                    u64::try_from(value.len()).expect("test size"),
                    Instant::now() + Duration::from_millis(20),
                ),
                Err(ProviderErrorCode::Timeout)
            ),
            "open writer did not time out"
        );
        drop(write);

        let (read, write) =
            pipe_with(PipeFlags::CLOEXEC | PipeFlags::NONBLOCK).expect("control-byte key pipe");
        assert!(
            rustix::io::write(&write, b"\n").ok() == Some(1),
            "test control-byte pipe write failed"
        );
        drop(write);
        assert!(
            matches!(
                read_openai_key(read.as_fd(), 1, Instant::now() + Duration::from_secs(1)),
                Err(ProviderErrorCode::Transport)
            ),
            "control-byte key was accepted"
        );
    }

    #[test]
    fn key_pipe_use_boundary_rejects_wrong_type_access_flags_and_cloexec() {
        let (socket, _peer) = seqpacket_pair();
        assert!(
            matches!(
                read_openai_key(socket.as_fd(), 1, Instant::now() + Duration::from_secs(1)),
                Err(ProviderErrorCode::Transport)
            ),
            "non-pipe descriptor was accepted"
        );

        let (read, write) =
            pipe_with(PipeFlags::CLOEXEC | PipeFlags::NONBLOCK).expect("access key pipe");
        assert!(
            matches!(
                read_openai_key(write.as_fd(), 1, Instant::now() + Duration::from_secs(1)),
                Err(ProviderErrorCode::Transport)
            ),
            "write-only pipe was accepted"
        );
        drop(read);
        drop(write);

        let (read, write) = pipe_with(PipeFlags::CLOEXEC).expect("blocking key pipe");
        drop(write);
        assert!(
            matches!(
                read_openai_key(read.as_fd(), 1, Instant::now() + Duration::from_secs(1)),
                Err(ProviderErrorCode::Transport)
            ),
            "blocking pipe was accepted"
        );

        let (read, write) =
            pipe_with(PipeFlags::CLOEXEC | PipeFlags::NONBLOCK).expect("CLOEXEC key pipe");
        rustix::io::fcntl_setfd(&read, rustix::io::FdFlags::empty()).expect("clear test CLOEXEC");
        drop(write);
        assert!(
            matches!(
                read_openai_key(read.as_fd(), 1, Instant::now() + Duration::from_secs(1)),
                Err(ProviderErrorCode::Transport)
            ),
            "non-CLOEXEC pipe was accepted"
        );
    }

    #[test]
    fn operation_and_request_id_surface_is_fixed() {
        assert_eq!(
            vault_request_id("O-12345678-1234-1234-1234-123456789abc")
                .expect("mapped request id")
                .as_str(),
            "R-12345678-1234-1234-1234-123456789abc"
        );
        assert!(vault_request_id("R-12345678-1234-1234-1234-123456789abc").is_err());
        assert_eq!(
            map_vault_state(ProtocolVaultState::Absent),
            VaultState::Absent
        );
        assert_eq!(
            map_vault_error(ErrorToken::Busy),
            Err(ProviderErrorCode::Busy)
        );
        assert_eq!(
            map_vault_error(ErrorToken::NotAuthorized),
            Err(ProviderErrorCode::Transport)
        );
        assert_eq!(
            map_vault_error(ErrorToken::ProviderUnconfigured),
            Err(ProviderErrorCode::Transport)
        );
        for (expected, observed, outcome, accepted) in [
            (41, 41, VersionOutcome::Exact, true),
            (41, 42, VersionOutcome::Exact, false),
            (41, 40, VersionOutcome::Exact, false),
            (41, 42, VersionOutcome::StrictlyNewer, true),
            (41, 41, VersionOutcome::StrictlyNewer, false),
            (41, 40, VersionOutcome::StrictlyNewer, false),
            (41, 41, VersionOutcome::Monotonic, true),
            (41, 42, VersionOutcome::Monotonic, true),
            (41, 40, VersionOutcome::Monotonic, false),
            (
                kernaid_protocol::rescue_vault::MAX_SAFE_JSON_INTEGER,
                kernaid_protocol::rescue_vault::MAX_SAFE_JSON_INTEGER,
                VersionOutcome::Monotonic,
                true,
            ),
        ] {
            assert!(
                require_correlated_state_version(expected, observed, outcome).is_ok() == accepted,
                "response version matrix changed"
            );
        }
    }
}
