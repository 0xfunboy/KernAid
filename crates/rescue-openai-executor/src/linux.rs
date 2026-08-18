use kernaid_protocol::{
    rescue_vault::{
        ErrorToken, ProviderState as VaultProviderState, RequestId, SuccessPayload,
        VaultState as ProtocolVaultState,
    },
    rescue_vault_transport::{
        ClientRequest, ClientRequestPayload, ClientResponse, ClientResponseOutcome,
        authenticate_root_seqpacket_server,
    },
};
use kernaid_rescue_openai_provider::{
    CredentialState, MAX_REQUEST_FRAME_BYTES, ProviderErrorCode, ProviderOperation,
    ProviderRequest, ProviderResponse, ProviderStatus, VaultState, encode_response_frame,
    parse_request_frame,
};
use rustix::{
    event::{PollFd, PollFlags, Timespec, poll},
    fd::{AsFd, BorrowedFd, OwnedFd},
    fs::{self as rfs, OFlags},
    net::{
        AddressFamily, RecvAncillaryBuffer, RecvFlags, ReturnFlags, SendFlags, SocketAddrUnix,
        SocketFlags, SocketType, connect, recvmsg, send, socket_with,
    },
};
use std::{
    io::{IoSliceMut, stdin},
    mem::MaybeUninit,
    time::{Duration, Instant},
};

const PROVIDER_SOCKET_PATH: &[u8] = b"/run/kernaid-rescue-openai.sock";
const VAULT_SOCKET_PATH: &str = "/run/kernaid-rescue-vault.sock";
const REQUEST_TIMEOUT: Duration = Duration::from_secs(3);

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

trait VaultObserver {
    fn observe(
        &self,
        provider_request_id: &str,
        deadline: Instant,
    ) -> Result<ProviderStatus, ProviderErrorCode>;
}

struct SystemVaultObserver;

impl VaultObserver for SystemVaultObserver {
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
        &SystemVaultObserver,
    )
}

fn serve_one(
    socket: BorrowedFd<'_>,
    expected_local_path: Option<&[u8]>,
    vault: &dyn VaultObserver,
) -> Result<(), ExecutorError> {
    prepare_client_socket(socket, expected_local_path)?;
    let deadline = Instant::now()
        .checked_add(REQUEST_TIMEOUT)
        .ok_or(ExecutorError::TimedOut)?;
    let frame = receive_frame(socket, deadline)?;
    let request = parse_request_frame(&frame).map_err(|_| ExecutorError::InvalidRequest)?;
    let response = match &request {
        ProviderRequest::Status { request_id } => match vault.observe(request_id, deadline) {
            Ok(status) => ProviderResponse::status(request_id, status),
            Err(error) => ProviderResponse::error(request_id, ProviderOperation::Status, error),
        },
        ProviderRequest::Diagnose { request_id, .. } => ProviderResponse::error(
            request_id,
            ProviderOperation::Diagnose,
            ProviderErrorCode::CredentialUnavailable,
        ),
    }
    .map_err(|_| ExecutorError::InvalidRequest)?;
    let encoded = encode_response_frame(&response).map_err(|_| ExecutorError::IoFailed)?;
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
    use rustix::{
        io::Errno,
        net::{SendAncillaryBuffer, SendAncillaryMessage, SocketFlags, recv, sendmsg, socketpair},
        pipe::{PipeFlags, pipe_with},
    };
    use std::{
        cell::{Cell, RefCell},
        io::IoSlice,
    };

    const STATUS_REQUEST: &[u8] =
        include_bytes!("../../../packages/schemas/fixtures/rescue-openai/valid/status.request.raw");
    const DIAGNOSE_REQUEST: &[u8] = include_bytes!(
        "../../../packages/schemas/fixtures/rescue-openai/valid/linux-generic-canary.request.raw"
    );

    struct FakeVault {
        calls: Cell<usize>,
        result: RefCell<Result<ProviderStatus, ProviderErrorCode>>,
    }

    impl FakeVault {
        fn configured() -> Self {
            Self {
                calls: Cell::new(0),
                result: RefCell::new(Ok(ProviderStatus::new(
                    VaultState::Unlocked,
                    CredentialState::Configured,
                )
                .expect("valid configured status"))),
            }
        }
    }

    impl VaultObserver for FakeVault {
        fn observe(
            &self,
            _provider_request_id: &str,
            _deadline: Instant,
        ) -> Result<ProviderStatus, ProviderErrorCode> {
            self.calls.set(self.calls.get() + 1);
            self.result.borrow().clone()
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

    fn execute(frame: &[u8], vault: &FakeVault) -> (ProviderRequest, ProviderResponse) {
        let (client, server) = seqpacket_pair();
        assert_eq!(
            send(&client, frame, SendFlags::NOSIGNAL).expect("request send"),
            frame.len()
        );
        serve_one(server.as_fd(), None, vault).expect("serve request");
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
                result: RefCell::new(Ok(
                    ProviderStatus::new(vault_state, credential).expect("valid status fixture")
                )),
            };
            let (_, response) = execute(STATUS_REQUEST, &vault);
            let status = response.status_payload().expect("status payload");
            assert_eq!(status.vault(), vault_state);
            assert_eq!(status.credential(), credential);
            assert_eq!(vault.calls.get(), 1);
        }
    }

    #[test]
    fn diagnose_is_closed_without_contacting_the_vault() {
        let vault = FakeVault::configured();
        let (_, response) = execute(DIAGNOSE_REQUEST, &vault);
        assert_eq!(response.operation(), ProviderOperation::Diagnose);
        assert_eq!(
            response.error_code(),
            Some(ProviderErrorCode::CredentialUnavailable)
        );
        assert_eq!(vault.calls.get(), 0);
    }

    #[test]
    fn vault_failures_remain_closed_error_tokens() {
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
                result: RefCell::new(Err(source)),
            };
            let (_, response) = execute(STATUS_REQUEST, &vault);
            assert_eq!(response.error_code(), Some(expected));
            assert_eq!(vault.calls.get(), 1);
        }
    }

    #[test]
    fn one_process_consumes_exactly_one_packet() {
        let vault = FakeVault::configured();
        let (client, server) = seqpacket_pair();
        assert_eq!(
            send(&client, STATUS_REQUEST, SendFlags::NOSIGNAL).expect("first request"),
            STATUS_REQUEST.len()
        );
        serve_one(server.as_fd(), None, &vault).expect("serve one request");
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
            let (client, server) = seqpacket_pair();
            assert_eq!(
                send(&client, frame, SendFlags::NOSIGNAL).expect("invalid request"),
                frame.len()
            );
            let result = serve_one(server.as_fd(), None, &vault);
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
            serve_one(server.as_fd(), None, &vault),
            Err(ExecutorError::UnexpectedAncillary)
        );
        drop(server);
        assert_eq!(rustix::io::write(&write_end, b"x").err(), Some(Errno::PIPE));
        assert_eq!(vault.calls.get(), 0);
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
    }
}
