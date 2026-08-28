//! Strict Linux transport and client codec for the Rescue vault protocol.
//!
//! The transport owns every descriptor received with `SCM_RIGHTS` and closes
//! it on every rejection path. Client requests and responses remain the exact
//! JSON wire format declared in the sibling [`crate::rescue_vault`] module;
//! this module adds no command, path, or free-form error surface.
//!
//! Every receiving endpoint must keep options that synthesize unmodelled
//! ancillary records disabled. In particular, `SO_PASSPIDFD`, `SO_PASSSEC`,
//! and socket timestamping must stay off. The daemon inherits that policy from
//! its root-owned listener; the client creates its endpoint with those options
//! disabled. `rustix` 1.1 models `SCM_RIGHTS` and `SCM_CREDENTIALS` here, but
//! filters other control-message kinds before this crate can reject or close
//! them.

#[cfg(feature = "experimental-repair-store")]
use crate::rescue_repair_vault::{
    MAX_REPAIR_BACKUP_BYTES, RepairBackupBinding, RepairBackupDraft, RepairBackupReleasePayload,
    RepairBackupState, RepairBackupStatusPayload, RepairExecutionIntentV1, RepairFileMetadataV1,
    RepairReservationId, RepairTransactionResolution, RepairTransactionStatusPayload,
    RepairTransactionStatusResultPayload, RepairTransactionStatusSelector,
    RepairVaultLiveIdentityPayload, RepairWriteLeasePayload,
};
use crate::rescue_vault::{
    API_VERSION, AuditEventType, AuditOutcome, DescriptorDeclaration, DescriptorType, ErrorToken,
    MAX_AUDIT_SEQUENCE, MAX_DATAGRAM_BYTES, MAX_OPENAI_KEY_BYTES, MAX_PASSPHRASE_BYTES,
    MAX_REPORTS_PER_RESPONSE, MAX_SAFE_JSON_INTEGER, MAX_SESSION_REPORT_JSON_BYTES,
    MAX_SIGNED_REPORT_ENVELOPE_BYTES, MIN_PASSPHRASE_BYTES, Operation, ProtocolViolation, Provider,
    ProviderState, ProviderStatusPayload, ReportId, ReportSummary, RequestId, Sha256,
    SuccessPayload, VaultState, VaultStatusPayload, valid_report_list, validate_borrowed_pipe,
    validate_mount_namespace_descriptor, validate_mount_root_descriptor, validate_o_path_directory,
};
use rustix::event::{PollFd, PollFlags, Timespec, poll};
use rustix::net::{
    AddressFamily, RecvAncillaryBuffer, RecvAncillaryMessage, RecvFlags, ReturnFlags,
    SendAncillaryBuffer, SendAncillaryMessage, SendFlags, SocketType, recvmsg, sendmsg,
};
use serde::{Deserialize, Serialize};
use serde_json::value::RawValue;
use std::{
    fmt,
    io::{IoSlice, IoSliceMut},
    mem::MaybeUninit,
    os::fd::{AsFd, BorrowedFd, OwnedFd},
    time::{Duration, Instant},
};

/// A complete seqpacket and the descriptors received with that one record.
pub(crate) struct ReceivedSeqpacket {
    bytes: Vec<u8>,
    descriptors: Vec<OwnedFd>,
    socket_identity: SeqpacketSocketIdentity,
}

impl ReceivedSeqpacket {
    /// Returns the exact packet bytes.
    #[cfg(test)]
    pub(crate) fn bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// Returns the number of owned descriptors attached to this packet.
    #[cfg(test)]
    pub(crate) fn descriptor_count(&self) -> usize {
        self.descriptors.len()
    }

    /// Returns the kernel identity of the socket that produced this record.
    pub(crate) fn socket_identity(&self) -> SeqpacketSocketIdentity {
        self.socket_identity
    }

    /// Transfers ownership of the packet bytes and descriptors.
    pub(crate) fn into_parts(self) -> (Vec<u8>, Vec<OwnedFd>) {
        (self.bytes, self.descriptors)
    }
}

impl fmt::Debug for ReceivedSeqpacket {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ReceivedSeqpacket")
            .field("byte_count", &self.bytes.len())
            .field("descriptor_count", &self.descriptors.len())
            .finish()
    }
}

/// Sanitized transport failures. No variant contains packet bytes, a path,
/// peer-controlled text, or an operating-system error string.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SeqpacketTransportError {
    InvalidTransport,
    ServerNotRoot,
    EmptyDatagram,
    AmbiguousZeroByte,
    DatagramTooLarge,
    AncillaryTruncated,
    UnexpectedAncillary,
    TooManyDescriptors,
    TimedOut,
    IoFailed,
    IncompleteSend,
}

impl fmt::Display for SeqpacketTransportError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::InvalidTransport => "invalid Rescue vault seqpacket transport",
            Self::ServerNotRoot => "Rescue vault server peer is not root",
            Self::EmptyDatagram => "empty Rescue vault seqpacket",
            Self::AmbiguousZeroByte => "ambiguous zero-byte Rescue vault receive",
            Self::DatagramTooLarge => "Rescue vault seqpacket exceeds its bound",
            Self::AncillaryTruncated => "truncated Rescue vault ancillary data",
            Self::UnexpectedAncillary => "unexpected Rescue vault ancillary data",
            Self::TooManyDescriptors => "too many Rescue vault descriptors",
            Self::TimedOut => "Rescue vault seqpacket deadline expired",
            Self::IoFailed => "Rescue vault seqpacket I/O failed",
            Self::IncompleteSend => "incomplete Rescue vault seqpacket send",
        })
    }
}

impl std::error::Error for SeqpacketTransportError {}

/// An authenticated client-side connection to the root vault server.
///
/// The borrowed socket is retained so requests and responses cannot be moved
/// onto a different, unauthenticated connection. This capability is
/// deliberately neither `Clone` nor `Copy`.
pub struct AuthenticatedVaultServer<'socket> {
    socket: BorrowedFd<'socket>,
    socket_identity: SeqpacketSocketIdentity,
    pid: u32,
}

impl fmt::Debug for AuthenticatedVaultServer<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AuthenticatedVaultServer")
            .field("pid", &self.pid)
            .finish_non_exhaustive()
    }
}

impl AuthenticatedVaultServer<'_> {
    /// Returns the PID observed through `SO_PEERCRED`.
    pub fn pid(&self) -> u32 {
        self.pid
    }
}

/// Verifies that a connected client socket is AF_UNIX `SOCK_SEQPACKET` and
/// that its peer has effective UID 0 according to `SO_PEERCRED`.
pub fn authenticate_root_seqpacket_server(
    socket: BorrowedFd<'_>,
) -> Result<AuthenticatedVaultServer<'_>, SeqpacketTransportError> {
    let socket_identity = validate_seqpacket_socket(socket)?;
    let credentials = rustix::net::sockopt::socket_peercred(socket)
        .map_err(|_| SeqpacketTransportError::InvalidTransport)?;
    let pid = credentials.pid.as_raw_nonzero().get() as u32;
    validate_root_server_identity(credentials.uid.as_raw())?;
    Ok(AuthenticatedVaultServer {
        socket,
        socket_identity,
        pid,
    })
}

fn validate_root_server_identity(uid: u32) -> Result<(), SeqpacketTransportError> {
    if uid != 0 {
        return Err(SeqpacketTransportError::ServerNotRoot);
    }
    Ok(())
}

/// Receives exactly one bounded AF_UNIX `SOCK_SEQPACKET` record.
///
/// The data buffer is one byte larger than the wire maximum. Ancillary space
/// can hold at least two descriptors plus credentials, so an extra descriptor
/// or `SCM_CREDENTIALS` record is observable and rejected. `MSG_CMSG_CLOEXEC`
/// is mandatory; all descriptors are owned and closed on every error path.
pub(crate) fn recv_seqpacket<Fd: AsFd>(
    socket: Fd,
    deadline: Instant,
) -> Result<ReceivedSeqpacket, SeqpacketTransportError> {
    let socket = socket.as_fd();
    ensure_deadline(deadline)?;
    let socket_identity = validate_seqpacket_socket(socket)?;
    ensure_deadline(deadline)?;

    let mut bytes = vec![0_u8; MAX_DATAGRAM_BYTES + 1];
    let mut io = [IoSliceMut::new(&mut bytes)];
    let mut control_space =
        [MaybeUninit::uninit(); rustix::cmsg_space!(ScmRights(2), ScmCredentials(1))];
    let mut control = RecvAncillaryBuffer::new(&mut control_space);
    let message = loop {
        ensure_deadline(deadline)?;
        match recvmsg(
            socket,
            &mut io,
            &mut control,
            RecvFlags::CMSG_CLOEXEC | RecvFlags::TRUNC | RecvFlags::DONTWAIT,
        ) {
            Ok(message) => break message,
            Err(error) if error == rustix::io::Errno::INTR => continue,
            Err(error) if error == rustix::io::Errno::AGAIN => {
                wait_until_ready(socket, PollFlags::IN, deadline)?;
            }
            Err(_) => return Err(SeqpacketTransportError::IoFailed),
        }
    };

    if message.flags.contains(ReturnFlags::CTRUNC) {
        return Err(SeqpacketTransportError::AncillaryTruncated);
    }
    if message.flags.contains(ReturnFlags::TRUNC) || message.bytes > MAX_DATAGRAM_BYTES {
        return Err(SeqpacketTransportError::DatagramTooLarge);
    }
    let mut descriptors = Vec::new();
    let mut unexpected_ancillary = false;
    for ancillary in control.drain() {
        match ancillary {
            RecvAncillaryMessage::ScmRights(rights) => descriptors.extend(rights),
            RecvAncillaryMessage::ScmCredentials(_) => unexpected_ancillary = true,
            _ => unexpected_ancillary = true,
        }
    }
    drop(control);

    if message.bytes == 0 {
        // Linux reports both an orderly SOCK_SEQPACKET peer shutdown and a
        // real zero-length record as the same zero-byte recvmsg result. A
        // zero-length record immediately followed by shutdown is therefore
        // indistinguishable from EOF. Ancillary data proves this was a real
        // record. Otherwise classify only what the kernel still exposes: a
        // live peer is a definite framing violation, while hangup is an
        // explicit ambiguity that callers may reconcile only after mutation.
        return Err(if !descriptors.is_empty() || unexpected_ancillary {
            SeqpacketTransportError::EmptyDatagram
        } else {
            classify_zero_length_receive(socket, deadline)
        });
    }

    if unexpected_ancillary {
        return Err(SeqpacketTransportError::UnexpectedAncillary);
    }
    if descriptors.len() > 2 {
        return Err(SeqpacketTransportError::TooManyDescriptors);
    }
    if descriptors.iter().any(|descriptor| {
        rustix::io::fcntl_getfd(descriptor)
            .map(|flags| !flags.contains(rustix::io::FdFlags::CLOEXEC))
            .unwrap_or(true)
    }) {
        return Err(SeqpacketTransportError::UnexpectedAncillary);
    }

    bytes.truncate(message.bytes);
    Ok(ReceivedSeqpacket {
        bytes,
        descriptors,
        socket_identity,
    })
}

fn classify_zero_length_receive(
    socket: BorrowedFd<'_>,
    deadline: Instant,
) -> SeqpacketTransportError {
    loop {
        if ensure_deadline(deadline).is_err() {
            // The caller has already consumed a zero-byte result. Never turn
            // that consumed event into a retryable timeout merely
            // because its nonblocking classification crossed the deadline.
            // The peer state is now unresolved, so require the same fresh
            // post-mutation reconciliation as zero-byte plus hangup.
            return SeqpacketTransportError::AmbiguousZeroByte;
        }
        let mut byte = [0_u8; 1];
        let mut io = [IoSliceMut::new(&mut byte)];
        let mut control_space =
            [MaybeUninit::uninit(); rustix::cmsg_space!(ScmRights(2), ScmCredentials(1))];
        let mut control = RecvAncillaryBuffer::new(&mut control_space);
        let message = match recvmsg(
            socket,
            &mut io,
            &mut control,
            RecvFlags::CMSG_CLOEXEC | RecvFlags::TRUNC | RecvFlags::DONTWAIT | RecvFlags::PEEK,
        ) {
            Ok(message) => message,
            Err(error) if error == rustix::io::Errno::INTR => continue,
            Err(error) if error == rustix::io::Errno::AGAIN => {
                return SeqpacketTransportError::EmptyDatagram;
            }
            Err(_) => return SeqpacketTransportError::IoFailed,
        };

        let mut ancillary_present = false;
        for ancillary in control.drain() {
            ancillary_present = true;
            if let RecvAncillaryMessage::ScmRights(rights) = ancillary {
                // MSG_PEEK duplicates SCM_RIGHTS descriptors into this
                // process. Consume their owning iterator so every duplicate
                // is closed while the original queued record remains intact.
                for descriptor in rights {
                    drop(descriptor);
                }
            }
        }
        drop(control);

        if message.bytes > 0
            || ancillary_present
            || message
                .flags
                .intersects(ReturnFlags::TRUNC | ReturnFlags::CTRUNC)
        {
            return SeqpacketTransportError::EmptyDatagram;
        }

        let mut descriptor = [PollFd::from_borrowed_fd(
            socket,
            PollFlags::IN | PollFlags::RDHUP,
        )];
        let immediate = Timespec {
            tv_sec: 0,
            tv_nsec: 0,
        };
        loop {
            if ensure_deadline(deadline).is_err() {
                return SeqpacketTransportError::AmbiguousZeroByte;
            }
            match poll(&mut descriptor, Some(&immediate)) {
                Ok(_) => {
                    let events = descriptor[0].revents();
                    if events.intersects(PollFlags::ERR | PollFlags::NVAL) {
                        return SeqpacketTransportError::IoFailed;
                    }
                    return if events.intersects(PollFlags::HUP | PollFlags::RDHUP) {
                        SeqpacketTransportError::AmbiguousZeroByte
                    } else {
                        SeqpacketTransportError::EmptyDatagram
                    };
                }
                Err(error) if error == rustix::io::Errno::INTR => continue,
                Err(_) => return SeqpacketTransportError::IoFailed,
            }
        }
    }
}

/// Sends exactly one bounded AF_UNIX `SOCK_SEQPACKET` record.
///
/// At most two descriptors are accepted. `MSG_NOSIGNAL` prevents a closed peer
/// from terminating the process, and any non-full send is an error.
pub(crate) fn send_seqpacket<Fd: AsFd>(
    socket: Fd,
    bytes: &[u8],
    descriptors: &[BorrowedFd<'_>],
    deadline: Instant,
) -> Result<(), SeqpacketTransportError> {
    let socket = socket.as_fd();
    ensure_deadline(deadline)?;
    validate_seqpacket_socket(socket)?;
    if bytes.is_empty() {
        return Err(SeqpacketTransportError::EmptyDatagram);
    }
    if bytes.len() > MAX_DATAGRAM_BYTES {
        return Err(SeqpacketTransportError::DatagramTooLarge);
    }
    if descriptors.len() > 2 {
        return Err(SeqpacketTransportError::TooManyDescriptors);
    }
    ensure_deadline(deadline)?;

    let io = [IoSlice::new(bytes)];
    let mut control_space = [MaybeUninit::uninit(); rustix::cmsg_space!(ScmRights(2))];
    let mut control = SendAncillaryBuffer::new(&mut control_space);
    if !descriptors.is_empty() && !control.push(SendAncillaryMessage::ScmRights(descriptors)) {
        return Err(SeqpacketTransportError::IoFailed);
    }
    let sent = loop {
        ensure_deadline(deadline)?;
        match sendmsg(
            socket,
            &io,
            &mut control,
            SendFlags::NOSIGNAL | SendFlags::DONTWAIT,
        ) {
            Ok(sent) => break sent,
            Err(error) if error == rustix::io::Errno::INTR => continue,
            Err(error) if error == rustix::io::Errno::AGAIN => {
                wait_until_ready(socket, PollFlags::OUT, deadline)?;
            }
            Err(_) => return Err(SeqpacketTransportError::IoFailed),
        }
    };
    if sent != bytes.len() {
        return Err(SeqpacketTransportError::IncompleteSend);
    }
    Ok(())
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) struct SeqpacketSocketIdentity {
    pub(crate) device: u64,
    pub(crate) inode: u64,
}

pub(crate) fn validate_seqpacket_socket(
    socket: BorrowedFd<'_>,
) -> Result<SeqpacketSocketIdentity, SeqpacketTransportError> {
    let descriptor_flags =
        rustix::io::fcntl_getfd(socket).map_err(|_| SeqpacketTransportError::InvalidTransport)?;
    if rustix::net::sockopt::socket_domain(socket)
        .map_err(|_| SeqpacketTransportError::InvalidTransport)?
        != AddressFamily::UNIX
        || rustix::net::sockopt::socket_type(socket)
            .map_err(|_| SeqpacketTransportError::InvalidTransport)?
            != SocketType::SEQPACKET
        || rustix::net::sockopt::socket_acceptconn(socket)
            .map_err(|_| SeqpacketTransportError::InvalidTransport)?
        || !descriptor_flags.contains(rustix::io::FdFlags::CLOEXEC)
    {
        return Err(SeqpacketTransportError::InvalidTransport);
    }
    rustix::net::getpeername(socket).map_err(|_| SeqpacketTransportError::InvalidTransport)?;
    let stat = rustix::fs::fstat(socket).map_err(|_| SeqpacketTransportError::InvalidTransport)?;
    Ok(SeqpacketSocketIdentity {
        device: stat.st_dev,
        inode: stat.st_ino,
    })
}

pub(crate) fn validate_bound_seqpacket_socket(
    socket: BorrowedFd<'_>,
    expected: SeqpacketSocketIdentity,
) -> Result<(), SeqpacketTransportError> {
    if validate_seqpacket_socket(socket)? != expected {
        return Err(SeqpacketTransportError::InvalidTransport);
    }
    Ok(())
}

fn wait_until_ready(
    socket: BorrowedFd<'_>,
    interest: PollFlags,
    deadline: Instant,
) -> Result<(), SeqpacketTransportError> {
    loop {
        let remaining = deadline
            .checked_duration_since(Instant::now())
            .filter(|remaining| !remaining.is_zero())
            .ok_or(SeqpacketTransportError::TimedOut)?;
        let timeout = duration_to_timespec(remaining);
        let mut descriptors = [PollFd::from_borrowed_fd(socket, interest)];
        match poll(&mut descriptors, Some(&timeout)) {
            Ok(0) => return Err(SeqpacketTransportError::TimedOut),
            Ok(_) => {
                let ready = descriptors[0].revents();
                if ready.contains(PollFlags::NVAL) {
                    return Err(SeqpacketTransportError::InvalidTransport);
                }
                if ready.intersects(interest | PollFlags::ERR | PollFlags::HUP | PollFlags::RDHUP) {
                    return Ok(());
                }
            }
            Err(error) if error == rustix::io::Errno::INTR => {}
            Err(_) => return Err(SeqpacketTransportError::IoFailed),
        }
    }
}

pub(crate) fn ensure_deadline(deadline: Instant) -> Result<(), SeqpacketTransportError> {
    deadline
        .checked_duration_since(Instant::now())
        .filter(|remaining| !remaining.is_zero())
        .map(|_| ())
        .ok_or(SeqpacketTransportError::TimedOut)
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

/// Typed client request body. No variant carries a command, path, mapper name,
/// passphrase, API key, or report bytes.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ClientRequestPayload {
    VaultStatus,
    VaultUnlock {
        passphrase_size: u64,
    },
    VaultLock,
    ProviderOpenAiConfigure {
        api_key_size: u64,
    },
    ProviderStatus,
    ProviderLogout {
        provider: Provider,
    },
    ProviderOpenAiBorrow,
    ProviderCodexHomeLease,
    AuditAppend {
        sequence: u64,
        event: AuditEventType,
        outcome: AuditOutcome,
        error: Option<ErrorToken>,
    },
    ReportPersist {
        report_id: ReportId,
        payload_sha256: Sha256,
        input_size: u64,
    },
    ReportList,
    ReportGet {
        report_id: ReportId,
    },
    #[cfg(feature = "experimental-repair-store")]
    RepairBackupReserve {
        draft: RepairBackupDraft,
    },
    #[cfg(feature = "experimental-repair-store")]
    RepairBackupPersist {
        expected: Box<RepairBackupStatusPayload>,
        binding: RepairBackupBinding,
        metadata: RepairFileMetadataV1,
        input_size: u64,
    },
    #[cfg(feature = "experimental-repair-store")]
    RepairBackupStatus {
        expected: Box<RepairBackupStatusPayload>,
    },
    #[cfg(feature = "experimental-repair-store")]
    RepairBackupGet {
        expected: Box<RepairBackupStatusPayload>,
    },
    #[cfg(feature = "experimental-repair-store")]
    RepairBackupCancel {
        reservation_id: RepairReservationId,
        draft_binding_sha256: Sha256,
    },
    #[cfg(feature = "experimental-repair-store")]
    RepairBackupRetire {
        expected: Box<RepairBackupStatusPayload>,
    },
    #[cfg(feature = "experimental-repair-store")]
    RepairTransactionStatus {
        selector: RepairTransactionStatusSelector,
    },
    #[cfg(feature = "experimental-repair-store")]
    RepairTransactionResolve {
        expected: Box<RepairTransactionStatusPayload>,
        resolution: RepairTransactionResolution,
    },
    #[cfg(feature = "experimental-repair-store")]
    RepairTransactionWriteLeaseConsume {
        selector: RepairTransactionStatusSelector,
    },
    #[cfg(feature = "experimental-repair-store")]
    RepairVaultLiveParent,
}

impl ClientRequestPayload {
    /// Returns the exact closed wire operation for this typed payload.
    pub fn operation(&self) -> Operation {
        match self {
            Self::VaultStatus => Operation::VaultStatus,
            Self::VaultUnlock { .. } => Operation::VaultUnlock,
            Self::VaultLock => Operation::VaultLock,
            Self::ProviderOpenAiConfigure { .. } => Operation::ProviderOpenAiConfigure,
            Self::ProviderStatus => Operation::ProviderStatus,
            Self::ProviderLogout { .. } => Operation::ProviderLogout,
            Self::ProviderOpenAiBorrow => Operation::ProviderOpenAiBorrow,
            Self::ProviderCodexHomeLease => Operation::ProviderCodexHomeLease,
            Self::AuditAppend { .. } => Operation::AuditAppend,
            Self::ReportPersist { .. } => Operation::ReportPersist,
            Self::ReportList => Operation::ReportList,
            Self::ReportGet { .. } => Operation::ReportGet,
            #[cfg(feature = "experimental-repair-store")]
            Self::RepairBackupReserve { .. } => Operation::RepairBackupReserve,
            #[cfg(feature = "experimental-repair-store")]
            Self::RepairBackupPersist { .. } => Operation::RepairBackupPersist,
            #[cfg(feature = "experimental-repair-store")]
            Self::RepairBackupStatus { .. } => Operation::RepairBackupStatus,
            #[cfg(feature = "experimental-repair-store")]
            Self::RepairBackupGet { .. } => Operation::RepairBackupGet,
            #[cfg(feature = "experimental-repair-store")]
            Self::RepairBackupCancel { .. } => Operation::RepairBackupCancel,
            #[cfg(feature = "experimental-repair-store")]
            Self::RepairBackupRetire { .. } => Operation::RepairBackupRetire,
            #[cfg(feature = "experimental-repair-store")]
            Self::RepairTransactionStatus { .. } => Operation::RepairTransactionStatus,
            #[cfg(feature = "experimental-repair-store")]
            Self::RepairTransactionResolve { .. } => Operation::RepairTransactionResolve,
            #[cfg(feature = "experimental-repair-store")]
            Self::RepairVaultLiveParent => Operation::RepairVaultLiveParent,
            #[cfg(feature = "experimental-repair-store")]
            Self::RepairTransactionWriteLeaseConsume { .. } => {
                Operation::RepairTransactionWriteLeaseConsume
            }
        }
    }

    fn input_declaration(&self) -> Option<DescriptorDeclaration> {
        match self {
            Self::VaultUnlock { passphrase_size } => Some(DescriptorDeclaration {
                kind: DescriptorType::PassphrasePipe,
                size: *passphrase_size,
            }),
            Self::ProviderOpenAiConfigure { api_key_size } => Some(DescriptorDeclaration {
                kind: DescriptorType::OpenAiApiKeyPipe,
                size: *api_key_size,
            }),
            Self::ReportPersist { input_size, .. } => Some(DescriptorDeclaration {
                kind: DescriptorType::SessionReportJsonPipe,
                size: *input_size,
            }),
            #[cfg(feature = "experimental-repair-store")]
            Self::RepairBackupPersist { input_size, .. } => Some(DescriptorDeclaration {
                kind: DescriptorType::RepairBackupInputPipe,
                size: *input_size,
            }),
            Self::VaultStatus
            | Self::VaultLock
            | Self::ProviderStatus
            | Self::ProviderLogout { .. }
            | Self::ProviderOpenAiBorrow
            | Self::ProviderCodexHomeLease
            | Self::AuditAppend { .. }
            | Self::ReportList
            | Self::ReportGet { .. } => None,
            #[cfg(feature = "experimental-repair-store")]
            Self::RepairBackupReserve { .. }
            | Self::RepairBackupStatus { .. }
            | Self::RepairBackupGet { .. }
            | Self::RepairBackupCancel { .. }
            | Self::RepairBackupRetire { .. }
            | Self::RepairTransactionStatus { .. }
            | Self::RepairTransactionResolve { .. }
            | Self::RepairVaultLiveParent
            | Self::RepairTransactionWriteLeaseConsume { .. } => None,
        }
    }
}

/// A schema-valid client request before transport.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ClientRequest {
    request_id: RequestId,
    expected_state_version: u64,
    payload: ClientRequestPayload,
}

impl ClientRequest {
    /// Constructs and validates a typed request.
    pub fn new(
        request_id: RequestId,
        expected_state_version: u64,
        payload: ClientRequestPayload,
    ) -> Result<Self, ProtocolViolation> {
        if expected_state_version > MAX_SAFE_JSON_INTEGER || !valid_client_payload(&payload) {
            return Err(ProtocolViolation::InvalidPayload);
        }
        Ok(Self {
            request_id,
            expected_state_version,
            payload,
        })
    }

    pub fn request_id(&self) -> &RequestId {
        &self.request_id
    }

    pub fn expected_state_version(&self) -> u64 {
        self.expected_state_version
    }

    pub fn operation(&self) -> Operation {
        self.payload.operation()
    }

    pub fn payload(&self) -> &ClientRequestPayload {
        &self.payload
    }
}

fn valid_client_payload(payload: &ClientRequestPayload) -> bool {
    match payload {
        ClientRequestPayload::VaultUnlock { passphrase_size } => {
            (MIN_PASSPHRASE_BYTES..=MAX_PASSPHRASE_BYTES).contains(passphrase_size)
        }
        ClientRequestPayload::ProviderOpenAiConfigure { api_key_size } => {
            (1..=MAX_OPENAI_KEY_BYTES).contains(api_key_size)
        }
        ClientRequestPayload::AuditAppend {
            sequence,
            outcome,
            error,
            ..
        } => {
            (1..=MAX_AUDIT_SEQUENCE).contains(sequence)
                && ((*outcome == AuditOutcome::Succeeded && error.is_none())
                    || (*outcome != AuditOutcome::Succeeded && error.is_some()))
        }
        ClientRequestPayload::ReportPersist { input_size, .. } => {
            (2..=MAX_SESSION_REPORT_JSON_BYTES).contains(input_size)
        }
        #[cfg(feature = "experimental-repair-store")]
        ClientRequestPayload::RepairBackupPersist {
            expected,
            binding,
            metadata,
            input_size,
        } => {
            expected.validate().is_ok()
                && expected.state() == RepairBackupState::Reserved
                && expected.backup_size() == *input_size
                && metadata.validate().is_ok()
                && metadata.canonical_sha256() == *expected.metadata_sha256()
                && binding.execution_intent().before_sha256() == expected.expected_backup_sha256()
                && binding.execution_intent().before_metadata() == metadata
                && binding
                    .execution_intent()
                    .target_physical_parent_fingerprint()
                    != expected.physical_parent_fingerprint()
                && (1..=MAX_REPAIR_BACKUP_BYTES).contains(input_size)
        }
        ClientRequestPayload::VaultStatus
        | ClientRequestPayload::VaultLock
        | ClientRequestPayload::ProviderStatus
        | ClientRequestPayload::ProviderLogout { .. }
        | ClientRequestPayload::ProviderOpenAiBorrow
        | ClientRequestPayload::ProviderCodexHomeLease
        | ClientRequestPayload::ReportList
        | ClientRequestPayload::ReportGet { .. } => true,
        #[cfg(feature = "experimental-repair-store")]
        ClientRequestPayload::RepairBackupReserve { .. } => true,
        #[cfg(feature = "experimental-repair-store")]
        ClientRequestPayload::RepairBackupStatus { expected } => expected.validate().is_ok(),
        #[cfg(feature = "experimental-repair-store")]
        ClientRequestPayload::RepairBackupGet { expected } => {
            expected.validate().is_ok() && expected.state() == RepairBackupState::Durable
        }
        #[cfg(feature = "experimental-repair-store")]
        ClientRequestPayload::RepairBackupCancel { .. } => true,
        #[cfg(feature = "experimental-repair-store")]
        ClientRequestPayload::RepairBackupRetire { expected } => {
            expected.validate().is_ok() && expected.state() == RepairBackupState::Durable
        }
        #[cfg(feature = "experimental-repair-store")]
        ClientRequestPayload::RepairTransactionStatus { selector } => selector.validate().is_ok(),
        #[cfg(feature = "experimental-repair-store")]
        ClientRequestPayload::RepairTransactionResolve {
            expected,
            resolution,
        } => {
            expected.validate().is_ok()
                && expected.is_unresolved()
                && expected
                    .backup()
                    .execution_intent()
                    .is_some_and(|intent| resolution.validate_against(intent).is_ok())
        }
        #[cfg(feature = "experimental-repair-store")]
        ClientRequestPayload::RepairVaultLiveParent => true,
        #[cfg(feature = "experimental-repair-store")]
        ClientRequestPayload::RepairTransactionWriteLeaseConsume { selector } => {
            matches!(selector, RepairTransactionStatusSelector::Exact { .. })
                && selector.validate().is_ok()
        }
    }
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct ClientRequestWire<'a, T: Serialize> {
    api_version: &'static str,
    request_id: &'a str,
    expected_state_version: u64,
    operation: Operation,
    payload: T,
}

#[derive(Serialize)]
struct EmptyRequestPayload {}

#[derive(Serialize)]
struct InputRequestPayload<'a> {
    input: &'a DescriptorDeclaration,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct CodexHomeLeaseRequestPayload {
    mount_namespace: DescriptorDeclaration,
    mount_root: DescriptorDeclaration,
}

#[derive(Serialize)]
struct LogoutRequestPayload {
    provider: Provider,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct AuditRequestPayload {
    sequence: u64,
    event: AuditEventType,
    outcome: AuditOutcome,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<ErrorToken>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct PersistRequestPayload<'a> {
    report_id: &'a ReportId,
    payload_sha256: &'a Sha256,
    input: &'a DescriptorDeclaration,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct GetRequestPayload<'a> {
    report_id: &'a ReportId,
}

#[cfg(feature = "experimental-repair-store")]
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct RepairBackupReserveRequestPayload<'a> {
    session_id: &'a str,
    target_id: &'a str,
    target_fingerprint: &'a Sha256,
    target_recovery_fingerprint: &'a str,
    expected_backup_sha256: &'a Sha256,
    metadata_sha256: &'a Sha256,
    backup_size: u64,
    required_capacity_bytes: u64,
}

#[cfg(feature = "experimental-repair-store")]
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct RepairBackupPersistRequestPayload<'a> {
    expected: &'a RepairBackupStatusPayload,
    metadata: &'a RepairFileMetadataV1,
    plan_id: &'a str,
    plan_sha256: &'a Sha256,
    approval_id: &'a str,
    approval_sha256: &'a Sha256,
    resource_id: &'a str,
    resource_sha256: &'a Sha256,
    execution_intent: &'a RepairExecutionIntentV1,
    input: &'a DescriptorDeclaration,
}

#[cfg(feature = "experimental-repair-store")]
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct RepairBackupReferenceRequestPayload<'a> {
    expected: &'a RepairBackupStatusPayload,
}

#[cfg(feature = "experimental-repair-store")]
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct RepairBackupCancelRequestPayload<'a> {
    reservation_id: &'a RepairReservationId,
    draft_binding_sha256: &'a Sha256,
}

#[cfg(feature = "experimental-repair-store")]
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct RepairTransactionStatusRequestPayload<'a> {
    selector: &'a RepairTransactionStatusSelector,
}

#[cfg(feature = "experimental-repair-store")]
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct RepairTransactionResolveRequestPayload<'a> {
    expected: &'a RepairTransactionStatusPayload,
    resolution: &'a RepairTransactionResolution,
}

/// Encodes a typed client request and validates the exact outgoing descriptor
/// arity and descriptor identity together.
pub fn encode_client_request(
    request: &ClientRequest,
    descriptors: &[BorrowedFd<'_>],
) -> Result<Vec<u8>, ProtocolViolation> {
    validate_client_request_descriptors(request, descriptors)?;
    let declaration = request.payload.input_declaration();
    let bytes = match &request.payload {
        ClientRequestPayload::VaultStatus
        | ClientRequestPayload::VaultLock
        | ClientRequestPayload::ProviderStatus
        | ClientRequestPayload::ProviderOpenAiBorrow
        | ClientRequestPayload::ReportList => {
            encode_client_request_payload(request, EmptyRequestPayload {})
        }
        #[cfg(feature = "experimental-repair-store")]
        ClientRequestPayload::RepairVaultLiveParent => {
            encode_client_request_payload(request, EmptyRequestPayload {})
        }
        ClientRequestPayload::VaultUnlock { .. }
        | ClientRequestPayload::ProviderOpenAiConfigure { .. } => encode_client_request_payload(
            request,
            InputRequestPayload {
                input: declaration
                    .as_ref()
                    .ok_or(ProtocolViolation::InvalidPayload)?,
            },
        ),
        ClientRequestPayload::ProviderCodexHomeLease => encode_client_request_payload(
            request,
            CodexHomeLeaseRequestPayload {
                mount_namespace: DescriptorDeclaration {
                    kind: DescriptorType::CodexMountNamespace,
                    size: 0,
                },
                mount_root: DescriptorDeclaration {
                    kind: DescriptorType::CodexMountRoot,
                    size: 0,
                },
            },
        ),
        ClientRequestPayload::ProviderLogout { provider } => encode_client_request_payload(
            request,
            LogoutRequestPayload {
                provider: *provider,
            },
        ),
        ClientRequestPayload::AuditAppend {
            sequence,
            event,
            outcome,
            error,
        } => encode_client_request_payload(
            request,
            AuditRequestPayload {
                sequence: *sequence,
                event: *event,
                outcome: *outcome,
                error: *error,
            },
        ),
        ClientRequestPayload::ReportPersist {
            report_id,
            payload_sha256,
            ..
        } => encode_client_request_payload(
            request,
            PersistRequestPayload {
                report_id,
                payload_sha256,
                input: declaration
                    .as_ref()
                    .ok_or(ProtocolViolation::InvalidPayload)?,
            },
        ),
        ClientRequestPayload::ReportGet { report_id } => {
            encode_client_request_payload(request, GetRequestPayload { report_id })
        }
        #[cfg(feature = "experimental-repair-store")]
        ClientRequestPayload::RepairBackupReserve { draft } => encode_client_request_payload(
            request,
            RepairBackupReserveRequestPayload {
                session_id: draft.session_id(),
                target_id: draft.target_id(),
                target_fingerprint: draft.target_fingerprint(),
                target_recovery_fingerprint: draft.target_recovery_fingerprint(),
                expected_backup_sha256: draft.expected_backup_sha256(),
                metadata_sha256: draft.metadata_sha256(),
                backup_size: draft.backup_size(),
                required_capacity_bytes: draft.required_capacity_bytes(),
            },
        ),
        #[cfg(feature = "experimental-repair-store")]
        ClientRequestPayload::RepairBackupPersist {
            expected,
            binding,
            metadata,
            ..
        } => encode_client_request_payload(
            request,
            RepairBackupPersistRequestPayload {
                expected,
                metadata,
                plan_id: binding.plan_id(),
                plan_sha256: binding.plan_sha256(),
                approval_id: binding.approval_id(),
                approval_sha256: binding.approval_sha256(),
                resource_id: binding.resource_id(),
                resource_sha256: binding.resource_sha256(),
                execution_intent: binding.execution_intent(),
                input: declaration
                    .as_ref()
                    .ok_or(ProtocolViolation::InvalidPayload)?,
            },
        ),
        #[cfg(feature = "experimental-repair-store")]
        ClientRequestPayload::RepairBackupStatus { expected }
        | ClientRequestPayload::RepairBackupGet { expected }
        | ClientRequestPayload::RepairBackupRetire { expected } => {
            encode_client_request_payload(request, RepairBackupReferenceRequestPayload { expected })
        }
        #[cfg(feature = "experimental-repair-store")]
        ClientRequestPayload::RepairBackupCancel {
            reservation_id,
            draft_binding_sha256,
        } => encode_client_request_payload(
            request,
            RepairBackupCancelRequestPayload {
                reservation_id,
                draft_binding_sha256,
            },
        ),
        #[cfg(feature = "experimental-repair-store")]
        ClientRequestPayload::RepairTransactionStatus { selector } => {
            encode_client_request_payload(
                request,
                RepairTransactionStatusRequestPayload { selector },
            )
        }
        #[cfg(feature = "experimental-repair-store")]
        ClientRequestPayload::RepairTransactionWriteLeaseConsume { selector } => {
            encode_client_request_payload(
                request,
                RepairTransactionStatusRequestPayload { selector },
            )
        }
        #[cfg(feature = "experimental-repair-store")]
        ClientRequestPayload::RepairTransactionResolve {
            expected,
            resolution,
        } => encode_client_request_payload(
            request,
            RepairTransactionResolveRequestPayload {
                expected,
                resolution,
            },
        ),
    }?;
    if bytes.len() > MAX_DATAGRAM_BYTES {
        return Err(ProtocolViolation::DatagramTooLarge);
    }
    Ok(bytes)
}

fn encode_client_request_payload<T: Serialize>(
    request: &ClientRequest,
    payload: T,
) -> Result<Vec<u8>, ProtocolViolation> {
    serde_json::to_vec(&ClientRequestWire {
        api_version: API_VERSION,
        request_id: request.request_id.as_str(),
        expected_state_version: request.expected_state_version,
        operation: request.operation(),
        payload,
    })
    .map_err(|_| ProtocolViolation::InvalidPayload)
}

fn validate_client_request_descriptors(
    request: &ClientRequest,
    descriptors: &[BorrowedFd<'_>],
) -> Result<(), ProtocolViolation> {
    if matches!(
        request.payload(),
        ClientRequestPayload::ProviderCodexHomeLease
    ) {
        return match descriptors {
            [] | [_] => Err(ProtocolViolation::FdRequired),
            [namespace, root] => {
                validate_mount_namespace_descriptor(*namespace)?;
                validate_mount_root_descriptor(*root)
            }
            [_, _, ..] => Err(ProtocolViolation::FdForbidden),
        };
    }
    match (request.payload.input_declaration(), descriptors) {
        (None, []) => Ok(()),
        (None, [_, ..]) | (Some(_), [_, _, ..]) => Err(ProtocolViolation::FdForbidden),
        (Some(_), []) => Err(ProtocolViolation::FdRequired),
        (Some(declaration), [descriptor]) => match declaration.kind {
            DescriptorType::CodexMountNamespace => validate_mount_namespace_descriptor(*descriptor),
            DescriptorType::PassphrasePipe
            | DescriptorType::OpenAiApiKeyPipe
            | DescriptorType::SessionReportJsonPipe => validate_borrowed_pipe(*descriptor),
            #[cfg(feature = "experimental-repair-store")]
            DescriptorType::RepairBackupInputPipe => validate_borrowed_pipe(*descriptor),
            DescriptorType::CodexHomeOPath
            | DescriptorType::CodexMountRoot
            | DescriptorType::SignedReportEnvelopePipe => Err(ProtocolViolation::InvalidPayload),
            #[cfg(feature = "experimental-repair-store")]
            DescriptorType::RepairBackupOutputPipe => Err(ProtocolViolation::InvalidPayload),
        },
    }
}

/// Strict client-side outcome for one correlated response.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ClientResponseOutcome {
    Success(SuccessPayload),
    Error(ErrorToken),
}

/// A response validated against its originating typed request.
pub struct ClientResponse {
    state_version: u64,
    operation: Operation,
    outcome: ClientResponseOutcome,
    descriptors: Vec<OwnedFd>,
}

impl ClientResponse {
    pub fn state_version(&self) -> u64 {
        self.state_version
    }

    pub fn operation(&self) -> Operation {
        self.operation
    }

    pub fn outcome(&self) -> &ClientResponseOutcome {
        &self.outcome
    }

    pub fn descriptor_count(&self) -> usize {
        self.descriptors.len()
    }

    /// Transfers the sole validated response descriptor, when present.
    pub fn take_descriptor(&mut self) -> Option<OwnedFd> {
        self.descriptors.pop()
    }
}

impl fmt::Debug for ClientResponse {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ClientResponse")
            .field("state_version", &self.state_version)
            .field("operation", &self.operation)
            .field("outcome", &self.outcome)
            .field("descriptor_count", &self.descriptors.len())
            .finish()
    }
}

/// Sanitized strict response-decoding failures.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ClientResponseDecodeError {
    EmptyDatagram,
    DatagramTooLarge,
    InvalidJson,
    UnsupportedVersion,
    InvalidCorrelation,
    InvalidStateVersion,
    InvalidPayload,
    FdRequired,
    FdForbidden,
    InvalidDescriptor,
}

impl fmt::Display for ClientResponseDecodeError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::EmptyDatagram => "empty Rescue vault response",
            Self::DatagramTooLarge => "Rescue vault response exceeds its bound",
            Self::InvalidJson => "invalid Rescue vault response envelope",
            Self::UnsupportedVersion => "unsupported Rescue vault response version",
            Self::InvalidCorrelation => "uncorrelated Rescue vault response",
            Self::InvalidStateVersion => "invalid Rescue vault response state version",
            Self::InvalidPayload => "invalid Rescue vault response payload",
            Self::FdRequired => "Rescue vault response requires one descriptor",
            Self::FdForbidden => "Rescue vault response forbids descriptors",
            Self::InvalidDescriptor => "invalid Rescue vault response descriptor",
        })
    }
}

impl std::error::Error for ClientResponseDecodeError {}

/// Sanitized client exchange failure. The only public send/receive surface is
/// on [`AuthenticatedVaultServer`], so response decoding cannot be used to
/// bypass the root `SO_PEERCRED` check.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ClientExchangeError {
    Request(ProtocolViolation),
    Transport(SeqpacketTransportError),
    Response(ClientResponseDecodeError),
}

impl fmt::Display for ClientExchangeError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Request(error) => error.fmt(formatter),
            Self::Transport(error) => error.fmt(formatter),
            Self::Response(error) => error.fmt(formatter),
        }
    }
}

impl std::error::Error for ClientExchangeError {}

impl AuthenticatedVaultServer<'_> {
    /// Encodes and sends one typed request on this authenticated connection.
    pub fn send_request(
        &self,
        request: &ClientRequest,
        descriptors: &[BorrowedFd<'_>],
        deadline: Instant,
    ) -> Result<(), ClientExchangeError> {
        ensure_deadline(deadline).map_err(ClientExchangeError::Transport)?;
        validate_bound_seqpacket_socket(self.socket, self.socket_identity)
            .map_err(ClientExchangeError::Transport)?;
        let datagram =
            encode_client_request(request, descriptors).map_err(ClientExchangeError::Request)?;
        send_seqpacket(self.socket, &datagram, descriptors, deadline)
            .map_err(ClientExchangeError::Transport)
    }

    /// Receives and strictly decodes the response for `request` on this same
    /// authenticated connection.
    pub fn receive_response(
        &self,
        request: &ClientRequest,
        deadline: Instant,
    ) -> Result<ClientResponse, ClientExchangeError> {
        ensure_deadline(deadline).map_err(ClientExchangeError::Transport)?;
        validate_bound_seqpacket_socket(self.socket, self.socket_identity)
            .map_err(ClientExchangeError::Transport)?;
        let packet =
            recv_seqpacket(self.socket, deadline).map_err(ClientExchangeError::Transport)?;
        if packet.socket_identity() != self.socket_identity {
            return Err(ClientExchangeError::Transport(
                SeqpacketTransportError::InvalidTransport,
            ));
        }
        let (datagram, descriptors) = packet.into_parts();
        decode_client_response(&datagram, descriptors, request)
            .map_err(ClientExchangeError::Response)
    }
}

#[derive(Deserialize)]
struct ResponseOutcomeProbe {
    outcome: ResponseOutcome,
}

#[derive(Deserialize)]
enum ResponseOutcome {
    #[serde(rename = "ok")]
    Ok,
    #[serde(rename = "error")]
    Error,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct SuccessResponseWire<'a> {
    api_version: &'a str,
    request_id: &'a str,
    state_version: u64,
    operation: Operation,
    #[serde(rename = "outcome")]
    _outcome: OkOutcome,
    #[serde(borrow)]
    payload: &'a RawValue,
}

#[derive(Deserialize)]
enum OkOutcome {
    #[serde(rename = "ok")]
    Ok,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ErrorResponseWire<'a> {
    api_version: &'a str,
    request_id: &'a str,
    state_version: u64,
    operation: Operation,
    #[serde(rename = "outcome")]
    _outcome: ErrorOutcome,
    error: ErrorToken,
}

#[derive(Deserialize)]
enum ErrorOutcome {
    #[serde(rename = "error")]
    Error,
}

/// Decodes one response and binds it to the exact request ID, operation,
/// payload semantics, and descriptor arity of `request`.
///
/// `received_descriptors` is consumed and therefore closed on every error.
fn decode_client_response(
    datagram: &[u8],
    received_descriptors: Vec<OwnedFd>,
    request: &ClientRequest,
) -> Result<ClientResponse, ClientResponseDecodeError> {
    if datagram.is_empty() {
        return Err(ClientResponseDecodeError::EmptyDatagram);
    }
    if datagram.len() > MAX_DATAGRAM_BYTES {
        return Err(ClientResponseDecodeError::DatagramTooLarge);
    }
    let outcome: ResponseOutcomeProbe =
        serde_json::from_slice(datagram).map_err(|_| ClientResponseDecodeError::InvalidJson)?;
    match outcome.outcome {
        ResponseOutcome::Ok => {
            let response: SuccessResponseWire<'_> = serde_json::from_slice(datagram)
                .map_err(|_| ClientResponseDecodeError::InvalidJson)?;
            validate_response_correlation(
                response.api_version,
                response.request_id,
                response.state_version,
                response.operation,
                request,
            )?;
            validate_success_state_version(response.state_version, request)?;
            let payload = decode_success_payload(response.payload, &received_descriptors, request)?;
            Ok(ClientResponse {
                state_version: response.state_version,
                operation: response.operation,
                outcome: ClientResponseOutcome::Success(payload),
                descriptors: received_descriptors,
            })
        }
        ResponseOutcome::Error => {
            let response: ErrorResponseWire<'_> = serde_json::from_slice(datagram)
                .map_err(|_| ClientResponseDecodeError::InvalidJson)?;
            validate_response_correlation(
                response.api_version,
                response.request_id,
                response.state_version,
                response.operation,
                request,
            )?;
            if !received_descriptors.is_empty() {
                return Err(ClientResponseDecodeError::FdForbidden);
            }
            Ok(ClientResponse {
                state_version: response.state_version,
                operation: response.operation,
                outcome: ClientResponseOutcome::Error(response.error),
                descriptors: received_descriptors,
            })
        }
    }
}

fn validate_response_correlation(
    api_version: &str,
    request_id: &str,
    state_version: u64,
    operation: Operation,
    request: &ClientRequest,
) -> Result<(), ClientResponseDecodeError> {
    if api_version != API_VERSION {
        return Err(ClientResponseDecodeError::UnsupportedVersion);
    }
    if RequestId::parse(request_id).is_err()
        || request_id != request.request_id.as_str()
        || operation != request.operation()
    {
        return Err(ClientResponseDecodeError::InvalidCorrelation);
    }
    if state_version > MAX_SAFE_JSON_INTEGER {
        return Err(ClientResponseDecodeError::InvalidStateVersion);
    }
    Ok(())
}

fn validate_success_state_version(
    state_version: u64,
    request: &ClientRequest,
) -> Result<(), ClientResponseDecodeError> {
    let base_mutation = matches!(
        request.payload(),
        ClientRequestPayload::VaultUnlock { .. }
            | ClientRequestPayload::VaultLock
            | ClientRequestPayload::ProviderOpenAiConfigure { .. }
            | ClientRequestPayload::ProviderLogout { .. }
    );
    #[cfg(feature = "experimental-repair-store")]
    let repair_mutation = matches!(
        request.payload(),
        ClientRequestPayload::RepairBackupReserve { .. }
            | ClientRequestPayload::RepairBackupPersist { .. }
            | ClientRequestPayload::RepairBackupCancel { .. }
            | ClientRequestPayload::RepairBackupRetire { .. }
            | ClientRequestPayload::RepairTransactionResolve { .. }
            | ClientRequestPayload::RepairTransactionWriteLeaseConsume { .. }
    );
    #[cfg(not(feature = "experimental-repair-store"))]
    let repair_mutation = false;
    if (base_mutation || repair_mutation)
        && request
            .expected_state_version()
            .checked_add(2)
            .filter(|version| *version <= MAX_SAFE_JSON_INTEGER)
            != Some(state_version)
    {
        return Err(ClientResponseDecodeError::InvalidStateVersion);
    }
    Ok(())
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct DescriptorResponseWire {
    output: DescriptorDeclaration,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct AuditResponseWire {
    sequence: u64,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ReportSummaryWire {
    report_id: String,
    envelope_size: u64,
    envelope_sha256: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ReportListResponseWire {
    reports: Vec<ReportSummaryWire>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ReportResponseWire {
    report: ReportSummaryWire,
    output: DescriptorDeclaration,
}

#[cfg(feature = "experimental-repair-store")]
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct RepairBackupResponseWire {
    backup: RepairBackupStatusPayload,
    output: DescriptorDeclaration,
}

fn decode_success_payload(
    raw: &RawValue,
    descriptors: &[OwnedFd],
    request: &ClientRequest,
) -> Result<SuccessPayload, ClientResponseDecodeError> {
    match &request.payload {
        ClientRequestPayload::VaultStatus
        | ClientRequestPayload::VaultUnlock { .. }
        | ClientRequestPayload::VaultLock => {
            require_no_descriptors(descriptors)?;
            let status = decode_vault_status(raw)?;
            if !status.is_exact()
                || (matches!(&request.payload, ClientRequestPayload::VaultUnlock { .. })
                    && status.vault_state() != VaultState::Unlocked)
                || (matches!(&request.payload, ClientRequestPayload::VaultLock)
                    && status.vault_state() != VaultState::Locked)
            {
                return Err(ClientResponseDecodeError::InvalidPayload);
            }
            Ok(SuccessPayload::VaultStatus(status))
        }
        ClientRequestPayload::ProviderOpenAiConfigure { .. }
        | ClientRequestPayload::ProviderStatus
        | ClientRequestPayload::ProviderLogout { .. } => {
            require_no_descriptors(descriptors)?;
            let status: ProviderStatusPayload = decode_payload(raw)?;
            let exact = match &request.payload {
                ClientRequestPayload::ProviderOpenAiConfigure { .. } => {
                    status.openai == ProviderState::Configured
                }
                ClientRequestPayload::ProviderLogout {
                    provider: Provider::OpenAi,
                } => status.openai == ProviderState::Unconfigured,
                ClientRequestPayload::ProviderLogout {
                    provider: Provider::Codex,
                } => status.codex == ProviderState::Unconfigured,
                ClientRequestPayload::ProviderStatus => true,
                _ => false,
            };
            if !exact {
                return Err(ClientResponseDecodeError::InvalidPayload);
            }
            Ok(SuccessPayload::ProviderStatus(status))
        }
        ClientRequestPayload::ProviderOpenAiBorrow => {
            let descriptor: DescriptorResponseWire = decode_payload(raw)?;
            if descriptor.output.kind != DescriptorType::OpenAiApiKeyPipe
                || !(1..=MAX_OPENAI_KEY_BYTES).contains(&descriptor.output.size)
            {
                return Err(ClientResponseDecodeError::InvalidPayload);
            }
            validate_one_descriptor(descriptors, DescriptorType::OpenAiApiKeyPipe)?;
            Ok(SuccessPayload::Descriptor(descriptor.output))
        }
        ClientRequestPayload::ProviderCodexHomeLease => {
            let descriptor: DescriptorResponseWire = decode_payload(raw)?;
            if descriptor.output.kind != DescriptorType::CodexHomeOPath
                || descriptor.output.size != 0
            {
                return Err(ClientResponseDecodeError::InvalidPayload);
            }
            validate_one_descriptor(descriptors, DescriptorType::CodexHomeOPath)?;
            Ok(SuccessPayload::Descriptor(descriptor.output))
        }
        ClientRequestPayload::AuditAppend { sequence, .. } => {
            require_no_descriptors(descriptors)?;
            let response: AuditResponseWire = decode_payload(raw)?;
            if response.sequence != *sequence
                || !(1..=MAX_AUDIT_SEQUENCE).contains(&response.sequence)
            {
                return Err(ClientResponseDecodeError::InvalidPayload);
            }
            Ok(SuccessPayload::AuditAppended {
                sequence: response.sequence,
            })
        }
        ClientRequestPayload::ReportPersist { report_id, .. } => {
            require_no_descriptors(descriptors)?;
            let report = parse_report_summary(decode_payload(raw)?)?;
            if report.report_id() != report_id {
                return Err(ClientResponseDecodeError::InvalidPayload);
            }
            Ok(SuccessPayload::ReportStored(report))
        }
        ClientRequestPayload::ReportList => {
            require_no_descriptors(descriptors)?;
            let response: ReportListResponseWire = decode_payload(raw)?;
            if response.reports.len() > MAX_REPORTS_PER_RESPONSE {
                return Err(ClientResponseDecodeError::InvalidPayload);
            }
            let reports = response
                .reports
                .into_iter()
                .map(parse_report_summary)
                .collect::<Result<Vec<_>, _>>()?;
            if !valid_report_list(&reports) {
                return Err(ClientResponseDecodeError::InvalidPayload);
            }
            Ok(SuccessPayload::ReportList { reports })
        }
        ClientRequestPayload::ReportGet { report_id } => {
            let response: ReportResponseWire = decode_payload(raw)?;
            let report = parse_report_summary(response.report)?;
            if report.report_id() != report_id
                || response.output.kind != DescriptorType::SignedReportEnvelopePipe
                || response.output.size != report.envelope_size()
                || response.output.size > MAX_SIGNED_REPORT_ENVELOPE_BYTES
            {
                return Err(ClientResponseDecodeError::InvalidPayload);
            }
            validate_one_descriptor(descriptors, DescriptorType::SignedReportEnvelopePipe)?;
            Ok(SuccessPayload::Report(report, response.output))
        }
        #[cfg(feature = "experimental-repair-store")]
        ClientRequestPayload::RepairBackupReserve { draft } => {
            require_no_descriptors(descriptors)?;
            let status: RepairBackupStatusPayload = decode_payload(raw)?;
            if status.validate().is_err()
                || status.state() != RepairBackupState::Reserved
                || status.draft_binding_sha256() != &draft.draft_binding_sha256()
                || status.backup_size() != draft.backup_size()
                || status.expected_backup_sha256() != draft.expected_backup_sha256()
                || status.metadata_sha256() != draft.metadata_sha256()
                || status.reserved_bytes() < draft.required_capacity_bytes()
            {
                return Err(ClientResponseDecodeError::InvalidPayload);
            }
            Ok(SuccessPayload::RepairBackupStatus(Box::new(status)))
        }
        #[cfg(feature = "experimental-repair-store")]
        ClientRequestPayload::RepairBackupPersist {
            expected,
            binding,
            input_size,
            ..
        } => {
            require_no_descriptors(descriptors)?;
            let status: RepairBackupStatusPayload = decode_payload(raw)?;
            if status.validate().is_err()
                || status.state() != RepairBackupState::Durable
                || !status.immutable_fields_match(expected)
                || status.backup_size() != *input_size
                || status.plan_id() != Some(binding.plan_id())
                || status.plan_sha256() != Some(binding.plan_sha256())
                || status.approval_id() != Some(binding.approval_id())
                || status.approval_sha256() != Some(binding.approval_sha256())
                || status.resource_id() != Some(binding.resource_id())
                || status.resource_sha256() != Some(binding.resource_sha256())
                || status.execution_intent() != Some(binding.execution_intent())
            {
                return Err(ClientResponseDecodeError::InvalidPayload);
            }
            Ok(SuccessPayload::RepairBackupStatus(Box::new(status)))
        }
        #[cfg(feature = "experimental-repair-store")]
        ClientRequestPayload::RepairBackupStatus { expected } => {
            require_no_descriptors(descriptors)?;
            let status: RepairBackupStatusPayload = decode_payload(raw)?;
            if status.validate().is_err() || !status.immutable_fields_match(expected) {
                return Err(ClientResponseDecodeError::InvalidPayload);
            }
            Ok(SuccessPayload::RepairBackupStatus(Box::new(status)))
        }
        #[cfg(feature = "experimental-repair-store")]
        ClientRequestPayload::RepairBackupGet { expected } => {
            let response: RepairBackupResponseWire = decode_payload(raw)?;
            if response.backup.validate().is_err()
                || response.backup.state() != RepairBackupState::Durable
                || !response.backup.immutable_fields_match(expected)
                || response.output.kind != DescriptorType::RepairBackupOutputPipe
                || response.output.size != response.backup.backup_size()
            {
                return Err(ClientResponseDecodeError::InvalidPayload);
            }
            validate_one_descriptor(descriptors, DescriptorType::RepairBackupOutputPipe)?;
            Ok(SuccessPayload::RepairBackup(
                Box::new(response.backup),
                response.output,
            ))
        }
        #[cfg(feature = "experimental-repair-store")]
        ClientRequestPayload::RepairBackupCancel {
            reservation_id,
            draft_binding_sha256,
        } => {
            require_no_descriptors(descriptors)?;
            let released: RepairBackupReleasePayload = decode_payload(raw)?;
            if released.validate().is_err()
                || released.reservation_id() != reservation_id
                || released.draft_binding_sha256() != draft_binding_sha256
            {
                return Err(ClientResponseDecodeError::InvalidPayload);
            }
            Ok(SuccessPayload::RepairBackupReleased(released))
        }
        #[cfg(feature = "experimental-repair-store")]
        ClientRequestPayload::RepairBackupRetire { expected } => {
            require_no_descriptors(descriptors)?;
            let released: RepairBackupReleasePayload = decode_payload(raw)?;
            if released.validate().is_err()
                || released.reservation_id() != expected.reservation_id()
                || released.draft_binding_sha256() != expected.draft_binding_sha256()
                || released.released_bytes() != expected.reserved_bytes()
            {
                return Err(ClientResponseDecodeError::InvalidPayload);
            }
            Ok(SuccessPayload::RepairBackupReleased(released))
        }
        #[cfg(feature = "experimental-repair-store")]
        ClientRequestPayload::RepairTransactionStatus { selector } => {
            require_no_descriptors(descriptors)?;
            let result: RepairTransactionStatusResultPayload = decode_payload(raw)?;
            if !selector.matches_result(&result) {
                return Err(ClientResponseDecodeError::InvalidPayload);
            }
            Ok(SuccessPayload::RepairTransactionStatus(Box::new(result)))
        }
        #[cfg(feature = "experimental-repair-store")]
        ClientRequestPayload::RepairTransactionResolve {
            expected,
            resolution,
        } => {
            require_no_descriptors(descriptors)?;
            let status: RepairTransactionStatusPayload = decode_payload(raw)?;
            if status.validate().is_err()
                || !status.same_transaction(expected)
                || !status.resolves_with(resolution)
            {
                return Err(ClientResponseDecodeError::InvalidPayload);
            }
            Ok(SuccessPayload::RepairTransactionResolved(Box::new(status)))
        }
        #[cfg(feature = "experimental-repair-store")]
        ClientRequestPayload::RepairVaultLiveParent => {
            require_no_descriptors(descriptors)?;
            let identity: RepairVaultLiveIdentityPayload = decode_payload(raw)?;
            if identity.validate().is_err() {
                return Err(ClientResponseDecodeError::InvalidPayload);
            }
            Ok(SuccessPayload::RepairVaultLiveIdentity(identity))
        }
        #[cfg(feature = "experimental-repair-store")]
        ClientRequestPayload::RepairTransactionWriteLeaseConsume { selector } => {
            require_no_descriptors(descriptors)?;
            let lease: RepairWriteLeasePayload = decode_payload(raw)?;
            if lease.validate().is_err()
                || !matches!(
                    selector,
                    RepairTransactionStatusSelector::Exact {
                        reservation_id,
                        transaction_binding_sha256,
                    } if lease.transaction().backup().reservation_id() == reservation_id
                        && lease.transaction().transaction_binding_sha256()
                            == transaction_binding_sha256
                )
            {
                return Err(ClientResponseDecodeError::InvalidPayload);
            }
            Ok(SuccessPayload::RepairWriteLeaseConsumed(Box::new(lease)))
        }
    }
}

fn decode_payload<T: for<'de> Deserialize<'de>>(
    raw: &RawValue,
) -> Result<T, ClientResponseDecodeError> {
    serde_json::from_str(raw.get()).map_err(|_| ClientResponseDecodeError::InvalidPayload)
}

#[derive(Deserialize)]
#[serde(untagged)]
enum VaultStatusResponseWire {
    Unlocked(UnlockedVaultStatusResponseWire),
    Other(OtherVaultStatusResponseWire),
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct UnlockedVaultStatusResponseWire {
    #[serde(rename = "vaultState")]
    _vault_state: UnlockedVaultState,
    device_id: String,
}

#[derive(Deserialize)]
enum UnlockedVaultState {
    #[serde(rename = "unlocked")]
    Unlocked,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct OtherVaultStatusResponseWire {
    vault_state: VaultState,
}

fn decode_vault_status(raw: &RawValue) -> Result<VaultStatusPayload, ClientResponseDecodeError> {
    let status: VaultStatusResponseWire = decode_payload(raw)?;
    match status {
        VaultStatusResponseWire::Unlocked(status) => {
            VaultStatusPayload::new(VaultState::Unlocked, Some(&status.device_id))
        }
        VaultStatusResponseWire::Other(status) if status.vault_state != VaultState::Unlocked => {
            VaultStatusPayload::new(status.vault_state, None)
        }
        VaultStatusResponseWire::Other(_) => Err(ProtocolViolation::InvalidPayload),
    }
    .map_err(|_| ClientResponseDecodeError::InvalidPayload)
}

fn parse_report_summary(
    report: ReportSummaryWire,
) -> Result<ReportSummary, ClientResponseDecodeError> {
    let report_id = ReportId::parse(&report.report_id)
        .map_err(|_| ClientResponseDecodeError::InvalidPayload)?;
    let sha256 = Sha256::parse(&report.envelope_sha256)
        .map_err(|_| ClientResponseDecodeError::InvalidPayload)?;
    ReportSummary::new(report_id, report.envelope_size, sha256)
        .map_err(|_| ClientResponseDecodeError::InvalidPayload)
}

fn require_no_descriptors(descriptors: &[OwnedFd]) -> Result<(), ClientResponseDecodeError> {
    if descriptors.is_empty() {
        Ok(())
    } else {
        Err(ClientResponseDecodeError::FdForbidden)
    }
}

fn validate_one_descriptor(
    descriptors: &[OwnedFd],
    kind: DescriptorType,
) -> Result<(), ClientResponseDecodeError> {
    let descriptor = match descriptors {
        [] => return Err(ClientResponseDecodeError::FdRequired),
        [descriptor] => descriptor.as_fd(),
        [_, _, ..] => return Err(ClientResponseDecodeError::FdForbidden),
    };
    let result = match kind {
        DescriptorType::OpenAiApiKeyPipe | DescriptorType::SignedReportEnvelopePipe => {
            validate_borrowed_pipe(descriptor)
        }
        #[cfg(feature = "experimental-repair-store")]
        DescriptorType::RepairBackupOutputPipe => validate_borrowed_pipe(descriptor),
        DescriptorType::CodexHomeOPath => validate_o_path_directory(descriptor),
        DescriptorType::PassphrasePipe
        | DescriptorType::CodexMountNamespace
        | DescriptorType::CodexMountRoot
        | DescriptorType::SessionReportJsonPipe => Err(ProtocolViolation::InvalidDescriptor),
        #[cfg(feature = "experimental-repair-store")]
        DescriptorType::RepairBackupInputPipe => Err(ProtocolViolation::InvalidDescriptor),
    };
    result.map_err(|_| ClientResponseDecodeError::InvalidDescriptor)
}

#[cfg(test)]
mod tests {
    use super::*;
    use rustix::{
        fs::{CWD, Mode, OFlags},
        net::{AddressFamily, SocketFlags, SocketType, socketpair},
        pipe::{PipeFlags, pipe_with},
    };

    const REQUEST_ID: &str = "R-12345678-1234-1234-1234-123456789abc";
    const OTHER_REQUEST_ID: &str = "R-aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee";
    const DEVICE_ID: &str = "KA-0123456789abcdef01234567";

    fn request(payload: ClientRequestPayload) -> ClientRequest {
        ClientRequest::new(
            RequestId::parse(REQUEST_ID).expect("request ID"),
            7,
            payload,
        )
        .expect("client request")
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

    fn read_pipe() -> OwnedFd {
        let (read, _write) = pipe_with(PipeFlags::CLOEXEC).expect("pipe");
        read
    }

    fn mount_namespace() -> OwnedFd {
        rustix::fs::open(
            "/proc/self/ns/mnt",
            OFlags::RDONLY | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .expect("mount namespace")
    }

    fn mount_root() -> OwnedFd {
        rustix::fs::open(
            "/",
            OFlags::PATH | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .expect("mount root")
    }

    fn test_deadline() -> Instant {
        Instant::now() + Duration::from_secs(2)
    }

    fn authenticated_test_server(socket: BorrowedFd<'_>) -> AuthenticatedVaultServer<'_> {
        validate_root_server_identity(0).expect("synthetic root identity");
        AuthenticatedVaultServer {
            socket,
            socket_identity: validate_seqpacket_socket(socket).expect("valid client socket"),
            pid: 123,
        }
    }

    fn status_response(request_id: &str, operation: &str, payload: &str) -> Vec<u8> {
        success_response(request_id, 8, operation, payload)
    }

    fn success_response(
        request_id: &str,
        state_version: u64,
        operation: &str,
        payload: &str,
    ) -> Vec<u8> {
        format!(
            "{{\"apiVersion\":\"{API_VERSION}\",\"requestId\":\"{request_id}\",\"stateVersion\":{state_version},\"operation\":\"{operation}\",\"outcome\":\"ok\",\"payload\":{payload}}}"
        )
        .into_bytes()
    }

    #[test]
    fn transport_round_trips_one_record_and_sets_cloexec_on_received_fd() {
        let (sender, receiver) = seqpacket_pair();
        let pipe = read_pipe();
        send_seqpacket(sender.as_fd(), b"request", &[pipe.as_fd()], test_deadline())
            .expect("send packet");
        let packet = recv_seqpacket(receiver.as_fd(), test_deadline()).expect("receive packet");
        assert_eq!(packet.bytes(), b"request");
        assert_eq!(packet.descriptor_count(), 1);
        let (_, descriptors) = packet.into_parts();
        let flags = rustix::io::fcntl_getfd(&descriptors[0]).expect("received descriptor flags");
        assert!(flags.contains(rustix::io::FdFlags::CLOEXEC));
    }

    #[test]
    fn transport_rejects_stream_empty_and_oversized_records() {
        let (stream, _peer) = socketpair(
            AddressFamily::UNIX,
            SocketType::STREAM,
            SocketFlags::CLOEXEC,
            None,
        )
        .expect("stream pair");
        assert_eq!(
            send_seqpacket(stream.as_fd(), b"x", &[], test_deadline()),
            Err(SeqpacketTransportError::InvalidTransport)
        );

        let (sender, receiver) = seqpacket_pair();
        rustix::net::send(sender.as_fd(), b"", SendFlags::NOSIGNAL).expect("empty record");
        assert_eq!(
            recv_seqpacket(receiver.as_fd(), test_deadline()).err(),
            Some(SeqpacketTransportError::EmptyDatagram)
        );

        let (sender, receiver) = seqpacket_pair();
        let oversized = vec![b'x'; MAX_DATAGRAM_BYTES + 1];
        rustix::net::send(sender.as_fd(), &oversized, SendFlags::NOSIGNAL)
            .expect("oversized record");
        assert_eq!(
            recv_seqpacket(receiver.as_fd(), test_deadline()).err(),
            Some(SeqpacketTransportError::DatagramTooLarge)
        );
        assert_eq!(
            send_seqpacket(sender.as_fd(), &oversized, &[], test_deadline()),
            Err(SeqpacketTransportError::DatagramTooLarge)
        );
    }

    #[test]
    fn transport_separates_live_empty_records_from_ambiguous_hangup() {
        let (sender, receiver) = seqpacket_pair();
        rustix::net::send(sender.as_fd(), b"", SendFlags::NOSIGNAL).expect("empty record");
        assert_eq!(
            recv_seqpacket(receiver.as_fd(), test_deadline()).err(),
            Some(SeqpacketTransportError::EmptyDatagram)
        );
        drop(sender);
        assert_eq!(
            recv_seqpacket(receiver.as_fd(), test_deadline()).err(),
            Some(SeqpacketTransportError::AmbiguousZeroByte)
        );

        let (sender, receiver) = seqpacket_pair();
        drop(sender);
        assert_eq!(
            recv_seqpacket(receiver.as_fd(), test_deadline()).err(),
            Some(SeqpacketTransportError::AmbiguousZeroByte)
        );

        let (sender, receiver) = seqpacket_pair();
        rustix::net::send(sender.as_fd(), b"", SendFlags::NOSIGNAL).expect("empty record");
        drop(sender);
        assert_eq!(
            recv_seqpacket(receiver.as_fd(), test_deadline()).err(),
            Some(SeqpacketTransportError::AmbiguousZeroByte)
        );

        let (sender, receiver) = seqpacket_pair();
        drop(sender);
        let expired = Instant::now()
            .checked_sub(Duration::from_millis(1))
            .expect("expired instant");
        assert_eq!(
            classify_zero_length_receive(receiver.as_fd(), expired),
            SeqpacketTransportError::AmbiguousZeroByte
        );
    }

    #[test]
    fn rejecting_an_empty_record_preserves_the_following_record_and_descriptor() {
        let (sender, receiver) = seqpacket_pair();
        let pipe = read_pipe();
        let pipe_stat = rustix::fs::fstat(&pipe).expect("pipe identity");
        rustix::net::send(sender.as_fd(), b"", SendFlags::NOSIGNAL).expect("empty record");
        send_seqpacket(sender.as_fd(), b"next", &[pipe.as_fd()], test_deadline())
            .expect("following record");
        drop(sender);

        assert_eq!(
            recv_seqpacket(receiver.as_fd(), test_deadline()).err(),
            Some(SeqpacketTransportError::EmptyDatagram)
        );
        assert_eq!(count_open_pipe_inode(pipe_stat.st_ino), 1);
        let packet = recv_seqpacket(receiver.as_fd(), test_deadline()).expect("following record");
        assert_eq!(packet.bytes(), b"next");
        let (_, descriptors) = packet.into_parts();
        assert_eq!(descriptors.len(), 1);
        let received_stat = rustix::fs::fstat(&descriptors[0]).expect("received pipe identity");
        assert_eq!(received_stat.st_ino, pipe_stat.st_ino);
        assert!(
            rustix::io::fcntl_getfd(&descriptors[0])
                .expect("received pipe flags")
                .contains(rustix::io::FdFlags::CLOEXEC)
        );

        let (sender, receiver) = seqpacket_pair();
        send_seqpacket(sender.as_fd(), b"authoritative", &[], test_deadline())
            .expect("valid record");
        drop(sender);
        assert_eq!(
            recv_seqpacket(receiver.as_fd(), test_deadline())
                .expect("queued response wins close")
                .bytes(),
            b"authoritative"
        );
    }

    #[test]
    fn transport_deadlines_bound_idle_receive_backpressure_and_expired_records() {
        let (sender, receiver) = seqpacket_pair();
        let timeout = Instant::now() + Duration::from_millis(25);
        assert_eq!(
            recv_seqpacket(receiver.as_fd(), timeout).err(),
            Some(SeqpacketTransportError::TimedOut)
        );

        rustix::net::send(sender.as_fd(), b"queued", SendFlags::NOSIGNAL).expect("queue record");
        let expired = Instant::now()
            .checked_sub(Duration::from_millis(1))
            .expect("expired instant");
        assert_eq!(
            recv_seqpacket(receiver.as_fd(), expired).err(),
            Some(SeqpacketTransportError::TimedOut)
        );
        assert_eq!(
            recv_seqpacket(receiver.as_fd(), test_deadline())
                .expect("queued record remains")
                .bytes(),
            b"queued"
        );

        assert_eq!(
            send_seqpacket(sender.as_fd(), b"expired-send", &[], expired),
            Err(SeqpacketTransportError::TimedOut)
        );
        assert_eq!(
            recv_seqpacket(receiver.as_fd(), Instant::now() + Duration::from_millis(25),).err(),
            Some(SeqpacketTransportError::TimedOut)
        );

        rustix::net::sockopt::set_socket_send_buffer_size(sender.as_fd(), 4096)
            .expect("small send buffer");
        let fill = vec![b'x'; 1024];
        let mut filled = false;
        let mut fill_error = None;
        for _ in 0..10_000 {
            match rustix::net::send(
                sender.as_fd(),
                &fill,
                SendFlags::NOSIGNAL | SendFlags::DONTWAIT,
            ) {
                Ok(_) => {}
                Err(error) if error == rustix::io::Errno::AGAIN => {
                    filled = true;
                    break;
                }
                Err(error) => {
                    fill_error = Some(error);
                    break;
                }
            }
        }
        assert!(
            fill_error.is_none(),
            "unexpected send-fill error: {fill_error:?}"
        );
        assert!(filled, "seqpacket send queue did not fill");
        assert_eq!(
            send_seqpacket(
                sender.as_fd(),
                b"blocked",
                &[],
                Instant::now() + Duration::from_millis(25),
            ),
            Err(SeqpacketTransportError::TimedOut)
        );
    }

    #[test]
    fn listener_is_rejected_by_record_and_peer_authentication_apis() {
        let (_directory, listener) = seqpacket_listener();
        assert_eq!(
            send_seqpacket(listener.as_fd(), b"x", &[], test_deadline()),
            Err(SeqpacketTransportError::InvalidTransport)
        );
        assert_eq!(
            recv_seqpacket(listener.as_fd(), test_deadline()).err(),
            Some(SeqpacketTransportError::InvalidTransport)
        );
        assert_eq!(
            authenticate_root_seqpacket_server(listener.as_fd()).err(),
            Some(SeqpacketTransportError::InvalidTransport)
        );
        assert_eq!(
            crate::rescue_vault::authenticate_seqpacket_peer(
                listener.as_fd(),
                crate::rescue_vault::PeerAllowlist::companion_only(1000).expect("test allowlist"),
            )
            .err(),
            Some(ProtocolViolation::InvalidTransport)
        );
    }

    #[test]
    fn transport_rejects_credentials_and_extra_descriptors_without_leaking_them() {
        let (sender, receiver) = seqpacket_pair();
        rustix::net::sockopt::set_socket_passcred(receiver.as_fd(), true)
            .expect("enable credentials");
        rustix::net::send(sender.as_fd(), b"credentials", SendFlags::NOSIGNAL)
            .expect("send credential-bearing record");
        assert_eq!(
            recv_seqpacket(receiver.as_fd(), test_deadline()).err(),
            Some(SeqpacketTransportError::UnexpectedAncillary)
        );

        let (sender, receiver) = seqpacket_pair();
        let (first_read, first_write) = pipe_with(PipeFlags::CLOEXEC).expect("first pipe");
        let (second_read, second_write) = pipe_with(PipeFlags::CLOEXEC).expect("second pipe");
        let (third_read, third_write) = pipe_with(PipeFlags::CLOEXEC).expect("third pipe");
        let first_inode = rustix::fs::fstat(&first_read).expect("first stat").st_ino;
        let second_inode = rustix::fs::fstat(&second_read).expect("second stat").st_ino;
        let third_inode = rustix::fs::fstat(&third_read).expect("third stat").st_ino;
        raw_send_descriptors(
            sender.as_fd(),
            b"three",
            &[first_read.as_fd(), second_read.as_fd(), third_read.as_fd()],
        );
        drop(first_read);
        drop(second_read);
        drop(third_read);
        assert_eq!(
            recv_seqpacket(receiver.as_fd(), test_deadline()).err(),
            Some(SeqpacketTransportError::TooManyDescriptors)
        );
        assert_eq!(count_open_pipe_inode(first_inode), 1);
        assert_eq!(count_open_pipe_inode(second_inode), 1);
        assert_eq!(count_open_pipe_inode(third_inode), 1);
        drop(first_write);
        drop(second_write);
        drop(third_write);
    }

    #[test]
    fn transport_rejects_control_truncation_and_closes_received_descriptors() {
        let (sender, receiver) = seqpacket_pair();
        let mut reads = Vec::new();
        let mut writes = Vec::new();
        for _ in 0..16 {
            let (read, write) = pipe_with(PipeFlags::CLOEXEC).expect("pipe");
            reads.push(read);
            writes.push(write);
        }
        let inode = rustix::fs::fstat(&reads[0]).expect("pipe stat").st_ino;
        let borrowed = reads.iter().map(AsFd::as_fd).collect::<Vec<_>>();
        raw_send_descriptors(sender.as_fd(), b"many", &borrowed);
        drop(reads);
        assert_eq!(
            recv_seqpacket(receiver.as_fd(), test_deadline()).err(),
            Some(SeqpacketTransportError::AncillaryTruncated)
        );
        assert_eq!(count_open_pipe_inode(inode), 1);
        drop(writes);
    }

    #[test]
    fn client_authenticates_only_a_root_seqpacket_server() {
        assert_eq!(validate_root_server_identity(0), Ok(()));
        assert_eq!(
            validate_root_server_identity(1000),
            Err(SeqpacketTransportError::ServerNotRoot)
        );
        let (stream, _peer) = socketpair(
            AddressFamily::UNIX,
            SocketType::STREAM,
            SocketFlags::CLOEXEC,
            None,
        )
        .expect("stream pair");
        assert_eq!(
            authenticate_root_seqpacket_server(stream.as_fd()).err(),
            Some(SeqpacketTransportError::InvalidTransport)
        );

        let (client, _server) = seqpacket_pair();
        assert_eq!(
            authenticate_root_seqpacket_server(client.as_fd()).err(),
            Some(SeqpacketTransportError::ServerNotRoot)
        );
    }

    #[test]
    fn authenticated_client_capability_is_the_only_exchange_surface() {
        let (client, daemon) = seqpacket_pair();
        let connection = authenticated_test_server(client.as_fd());
        let request = request(ClientRequestPayload::VaultStatus);
        connection
            .send_request(&request, &[], test_deadline())
            .expect("authenticated send");
        let received = recv_seqpacket(daemon.as_fd(), test_deadline()).expect("daemon receive");
        assert!(received.bytes().starts_with(b"{"));

        let response = status_response(REQUEST_ID, "vault.status", "{\"vaultState\":\"locked\"}");
        send_seqpacket(daemon.as_fd(), &response, &[], test_deadline()).expect("daemon response");
        let decoded = connection
            .receive_response(&request, test_deadline())
            .expect("authenticated receive and decode");
        assert_eq!(decoded.operation(), Operation::VaultStatus);

        send_seqpacket(daemon.as_fd(), &response, &[], test_deadline())
            .expect("queue second daemon response");
        let expired = Instant::now()
            .checked_sub(Duration::from_millis(1))
            .expect("expired instant");
        assert_eq!(
            connection.receive_response(&request, expired).err(),
            Some(ClientExchangeError::Transport(
                SeqpacketTransportError::TimedOut
            ))
        );
        assert!(
            connection
                .receive_response(&request, test_deadline())
                .is_ok()
        );
        assert_eq!(
            connection.send_request(&request, &[], expired).err(),
            Some(ClientExchangeError::Transport(
                SeqpacketTransportError::TimedOut
            ))
        );
        assert_eq!(
            recv_seqpacket(daemon.as_fd(), Instant::now() + Duration::from_millis(20),).err(),
            Some(SeqpacketTransportError::TimedOut)
        );
    }

    #[test]
    fn authenticated_client_receives_only_an_exact_codex_home_o_path() {
        let (client, daemon) = seqpacket_pair();
        let connection = authenticated_test_server(client.as_fd());
        let request = request(ClientRequestPayload::ProviderCodexHomeLease);
        let response = status_response(
            REQUEST_ID,
            "provider.codex.home_lease",
            "{\"output\":{\"type\":\"codex-home-o-path\",\"size\":0}}",
        );
        let home = rustix::fs::open(
            "/",
            OFlags::PATH | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .expect("exact Codex home shape");
        send_seqpacket(daemon.as_fd(), &response, &[home.as_fd()], test_deadline())
            .expect("send exact Codex home response");

        let mut decoded = connection
            .receive_response(&request, test_deadline())
            .expect("receive exact Codex home response");
        assert_eq!(decoded.operation(), Operation::ProviderCodexHomeLease);
        assert_eq!(decoded.descriptor_count(), 1);
        let received = decoded.take_descriptor().expect("Codex home descriptor");
        assert_eq!(
            rustix::fs::fcntl_getfl(&received).expect("received status flags"),
            OFlags::PATH | OFlags::DIRECTORY | OFlags::NOFOLLOW
        );
        assert_eq!(
            rustix::io::fcntl_getfd(&received).expect("received descriptor flags"),
            rustix::io::FdFlags::CLOEXEC
        );
    }

    #[test]
    fn authenticated_client_requires_exact_two_step_mutation_versions() {
        for (payload, operation, response_payload) in [
            (
                ClientRequestPayload::VaultUnlock {
                    passphrase_size: 12,
                },
                "vault.unlock",
                format!("{{\"vaultState\":\"unlocked\",\"deviceId\":\"{DEVICE_ID}\"}}"),
            ),
            (
                ClientRequestPayload::VaultLock,
                "vault.lock",
                "{\"vaultState\":\"locked\"}".to_owned(),
            ),
            (
                ClientRequestPayload::ProviderOpenAiConfigure { api_key_size: 12 },
                "provider.openai.configure",
                "{\"openai\":\"configured\",\"codex\":\"unconfigured\"}".to_owned(),
            ),
            (
                ClientRequestPayload::ProviderLogout {
                    provider: Provider::OpenAi,
                },
                "provider.logout",
                "{\"openai\":\"unconfigured\",\"codex\":\"unconfigured\"}".to_owned(),
            ),
        ] {
            let request = request(payload);
            for version in [7_u64, 8, 9, 10] {
                let (client, daemon) = seqpacket_pair();
                let connection = authenticated_test_server(client.as_fd());
                let response = success_response(REQUEST_ID, version, operation, &response_payload);
                send_seqpacket(daemon.as_fd(), &response, &[], test_deadline())
                    .expect("daemon response");
                let result = connection.receive_response(&request, test_deadline());
                if version == 9 {
                    assert!(result.is_ok(), "exact +2 response rejected");
                } else {
                    assert_eq!(
                        result.err(),
                        Some(ClientExchangeError::Response(
                            ClientResponseDecodeError::InvalidStateVersion
                        ))
                    );
                }
            }
        }

        let status = request(ClientRequestPayload::VaultStatus);
        let (client, daemon) = seqpacket_pair();
        let connection = authenticated_test_server(client.as_fd());
        let response = status_response(REQUEST_ID, "vault.status", "{\"vaultState\":\"locked\"}");
        send_seqpacket(daemon.as_fd(), &response, &[], test_deadline()).expect("status response");
        assert!(
            connection
                .receive_response(&status, test_deadline())
                .is_ok()
        );

        let unlock = request(ClientRequestPayload::VaultUnlock {
            passphrase_size: 12,
        });
        let (client, daemon) = seqpacket_pair();
        let connection = authenticated_test_server(client.as_fd());
        let response = format!(
            "{{\"apiVersion\":\"{API_VERSION}\",\"requestId\":\"{REQUEST_ID}\",\"stateVersion\":7,\"operation\":\"vault.unlock\",\"outcome\":\"error\",\"error\":\"BAD_PASSPHRASE\"}}"
        );
        send_seqpacket(daemon.as_fd(), response.as_bytes(), &[], test_deadline())
            .expect("error response");
        assert!(
            connection
                .receive_response(&unlock, test_deadline())
                .is_ok()
        );

        let exhausted = ClientRequest::new(
            RequestId::parse(REQUEST_ID).expect("request ID"),
            MAX_SAFE_JSON_INTEGER - 1,
            ClientRequestPayload::VaultLock,
        )
        .expect("headroom-exhausted request");
        let (client, daemon) = seqpacket_pair();
        let connection = authenticated_test_server(client.as_fd());
        let response = success_response(
            REQUEST_ID,
            MAX_SAFE_JSON_INTEGER,
            "vault.lock",
            "{\"vaultState\":\"locked\"}",
        );
        send_seqpacket(daemon.as_fd(), &response, &[], test_deadline()).expect("bounded response");
        assert_eq!(
            connection
                .receive_response(&exhausted, test_deadline())
                .err(),
            Some(ClientExchangeError::Response(
                ClientResponseDecodeError::InvalidStateVersion
            ))
        );
    }

    #[test]
    fn authenticated_client_cannot_receive_from_another_connection() {
        let (client_a, _daemon_a) = seqpacket_pair();
        let (client_b, daemon_b) = seqpacket_pair();
        let connection_a = authenticated_test_server(client_a.as_fd());
        let connection_b = authenticated_test_server(client_b.as_fd());
        let request = request(ClientRequestPayload::VaultStatus);
        let response = status_response(REQUEST_ID, "vault.status", "{\"vaultState\":\"locked\"}");
        send_seqpacket(daemon_b.as_fd(), &response, &[], test_deadline())
            .expect("queue response on second connection");

        assert_eq!(
            connection_a
                .receive_response(&request, Instant::now() + Duration::from_millis(20),)
                .err(),
            Some(ClientExchangeError::Transport(
                SeqpacketTransportError::TimedOut
            ))
        );
        assert!(
            connection_b
                .receive_response(&request, test_deadline())
                .is_ok()
        );
    }

    #[test]
    fn every_socket_boundary_requires_cloexec() {
        let (socket, peer) = seqpacket_pair();
        rustix::io::fcntl_setfd(socket.as_fd(), rustix::io::FdFlags::empty())
            .expect("clear socket CLOEXEC");
        assert_eq!(
            send_seqpacket(socket.as_fd(), b"request", &[], test_deadline()),
            Err(SeqpacketTransportError::InvalidTransport)
        );
        assert_eq!(
            recv_seqpacket(socket.as_fd(), test_deadline()).err(),
            Some(SeqpacketTransportError::InvalidTransport)
        );
        assert_eq!(
            authenticate_root_seqpacket_server(socket.as_fd()).err(),
            Some(SeqpacketTransportError::InvalidTransport)
        );
        assert_eq!(
            crate::rescue_vault::authenticate_seqpacket_peer(
                socket.as_fd(),
                crate::rescue_vault::PeerAllowlist::companion_only(1000).expect("allowlist"),
            )
            .err(),
            Some(ProtocolViolation::InvalidTransport)
        );

        rustix::io::fcntl_setfd(socket.as_fd(), rustix::io::FdFlags::CLOEXEC)
            .expect("restore socket CLOEXEC");
        let connection = authenticated_test_server(socket.as_fd());
        rustix::io::fcntl_setfd(socket.as_fd(), rustix::io::FdFlags::empty())
            .expect("clear authenticated socket CLOEXEC");
        let request = request(ClientRequestPayload::VaultStatus);
        assert_eq!(
            connection
                .send_request(&request, &[], test_deadline())
                .err(),
            Some(ClientExchangeError::Transport(
                SeqpacketTransportError::InvalidTransport
            ))
        );
        let response = status_response(REQUEST_ID, "vault.status", "{\"vaultState\":\"locked\"}");
        send_seqpacket(peer.as_fd(), &response, &[], test_deadline()).expect("queue response");
        assert_eq!(
            connection.receive_response(&request, test_deadline()).err(),
            Some(ClientExchangeError::Transport(
                SeqpacketTransportError::InvalidTransport
            ))
        );
    }

    #[test]
    fn typed_request_encoder_matches_server_decoder_and_fd_arity() {
        let status = request(ClientRequestPayload::VaultStatus);
        let status_bytes = encode_client_request(&status, &[]).expect("status encode");
        assert_eq!(
            String::from_utf8(status_bytes).expect("UTF-8"),
            format!(
                "{{\"apiVersion\":\"{API_VERSION}\",\"requestId\":\"{REQUEST_ID}\",\"expectedStateVersion\":7,\"operation\":\"vault.status\",\"payload\":{{}}}}"
            )
        );
        assert_eq!(
            encode_client_request(&status, &[read_pipe().as_fd()]),
            Err(ProtocolViolation::FdForbidden)
        );

        let unlock = request(ClientRequestPayload::VaultUnlock {
            passphrase_size: 12,
        });
        assert_eq!(
            encode_client_request(&unlock, &[]),
            Err(ProtocolViolation::FdRequired)
        );
        let pipe = read_pipe();
        let bytes = encode_client_request(&unlock, &[pipe.as_fd()]).expect("unlock encode");
        assert!(
            String::from_utf8(bytes)
                .expect("UTF-8")
                .contains("passphrase-pipe")
        );
        let codex = request(ClientRequestPayload::ProviderCodexHomeLease);
        assert_eq!(
            encode_client_request(&codex, &[]),
            Err(ProtocolViolation::FdRequired)
        );
        assert_eq!(
            encode_client_request(&codex, &[read_pipe().as_fd()]),
            Err(ProtocolViolation::FdRequired)
        );
        let namespace = mount_namespace();
        let root = mount_root();
        let bytes = encode_client_request(&codex, &[namespace.as_fd(), root.as_fd()])
            .expect("Codex namespace request");
        let encoded = String::from_utf8(bytes).expect("UTF-8");
        assert!(encoded.contains("codex-mount-namespace"));
        assert!(encoded.contains("codex-mount-root"));
        assert!(encoded.contains("\"size\":0"));
        assert_eq!(
            ClientRequest::new(
                RequestId::parse(REQUEST_ID).expect("request ID"),
                MAX_SAFE_JSON_INTEGER + 1,
                ClientRequestPayload::VaultStatus,
            ),
            Err(ProtocolViolation::InvalidPayload)
        );
    }

    #[cfg(feature = "experimental-repair-store")]
    #[test]
    fn repair_backup_client_codec_binds_mutations_and_descriptor_direction() {
        use crate::rescue_repair_vault::{
            RepairBackupBinding, RepairBackupDraft, RepairBackupStatusPayload,
            RepairExecutionIntentV1, RepairFileMetadataV1, RepairReservationId,
            RepairTransactionResolution, RepairTransactionResolutionOutcome,
            RepairTransactionStatusPayload, RepairTransactionStatusResultPayload,
            RepairTransactionStatusSelector, RepairVaultLiveIdentityPayload,
        };

        let hash = |byte: char| Sha256::parse(&byte.to_string().repeat(64)).expect("test SHA-256");
        let metadata = RepairFileMetadataV1::new(0o644, 0, 0).expect("file metadata");
        let draft = RepairBackupDraft::new(
            "S-session-1",
            "target-1",
            hash('1'),
            format!("recovery:{}", "4".repeat(64)),
            hash('2'),
            metadata.canonical_sha256(),
            4096,
            8192,
        )
        .expect("repair draft");
        let reserve = request(ClientRequestPayload::RepairBackupReserve {
            draft: draft.clone(),
        });
        let encoded = encode_client_request(&reserve, &[]).expect("reserve request");
        let encoded = String::from_utf8(encoded).expect("UTF-8 request");
        assert!(encoded.contains("repair.backup.reserve"));
        assert!(!encoded.contains("/dev/"));
        assert_eq!(
            encode_client_request(&reserve, &[read_pipe().as_fd()]),
            Err(ProtocolViolation::FdForbidden)
        );

        let reservation =
            RepairReservationId::parse("B-0123456789abcdef0123456789abcdef").expect("reservation");
        let draft_binding = draft.draft_binding_sha256();
        let reserved = RepairBackupStatusPayload::reserved(
            reservation.clone(),
            draft_binding.clone(),
            reservation.locator(),
            "V-0123456789abcdef0123456789abcdef",
            hash('5'),
            hash('6'),
            8192,
            4096,
            hash('2'),
            metadata.canonical_sha256(),
        )
        .expect("reserved status");
        let response = success_response(
            REQUEST_ID,
            9,
            "repair.backup.reserve",
            &serde_json::to_string(&reserved).expect("reserved JSON"),
        );
        assert!(decode_client_response(&response, Vec::new(), &reserve).is_ok());
        let mut wrong_binding = serde_json::to_value(&reserved).expect("reserved JSON value");
        wrong_binding["draftBindingSha256"] = serde_json::Value::String("0".repeat(64));
        let wrong_binding = success_response(
            REQUEST_ID,
            9,
            "repair.backup.reserve",
            &serde_json::to_string(&wrong_binding).expect("wrong binding JSON"),
        );
        assert_eq!(
            decode_client_response(&wrong_binding, Vec::new(), &reserve).err(),
            Some(ClientResponseDecodeError::InvalidPayload)
        );
        let stale = success_response(
            REQUEST_ID,
            8,
            "repair.backup.reserve",
            &serde_json::to_string(&reserved).expect("reserved JSON"),
        );
        assert_eq!(
            decode_client_response(&stale, Vec::new(), &reserve).err(),
            Some(ClientResponseDecodeError::InvalidStateVersion)
        );

        let execution_intent = RepairExecutionIntentV1::new(
            "S-session-1",
            7,
            "target-1",
            format!("scan:{}", "a".repeat(64)),
            hash('1'),
            hash('4'),
            format!("recovery:{}", "5".repeat(64)),
            format!("lock:{}", "b".repeat(64)),
            hash('2'),
            hash('c'),
            hash('d'),
            hash('e'),
            metadata.clone(),
        )
        .expect("execution intent");
        let binding = RepairBackupBinding::new(
            "P-plan-1",
            hash('7'),
            "A-approval-1",
            hash('8'),
            "rescue:selected-linux-root:etc/fstab",
            hash('2'),
            execution_intent.clone(),
        )
        .expect("repair binding");
        let persist = request(ClientRequestPayload::RepairBackupPersist {
            expected: Box::new(reserved.clone()),
            binding: binding.clone(),
            metadata: metadata.clone(),
            input_size: 4096,
        });
        assert_eq!(
            encode_client_request(&persist, &[]),
            Err(ProtocolViolation::FdRequired)
        );
        let input = read_pipe();
        let persist_json = encode_client_request(&persist, &[input.as_fd()])
            .expect("persist request with input pipe");
        assert!(
            String::from_utf8(persist_json)
                .expect("UTF-8 persist")
                .contains("repair-backup-input-pipe")
        );

        let durable = RepairBackupStatusPayload::durable(
            reservation.clone(),
            draft_binding,
            reservation.locator(),
            "V-0123456789abcdef0123456789abcdef",
            hash('5'),
            hash('6'),
            8192,
            4096,
            hash('2'),
            metadata.canonical_sha256(),
            binding,
        )
        .expect("durable status");
        let persist_response = success_response(
            REQUEST_ID,
            9,
            "repair.backup.persist",
            &serde_json::to_string(&durable).expect("durable JSON"),
        );
        assert!(decode_client_response(&persist_response, Vec::new(), &persist).is_ok());
        let mut vault_drift = serde_json::to_value(&durable).expect("durable JSON value");
        vault_drift["vaultId"] =
            serde_json::Value::String("V-ffffffffffffffffffffffffffffffff".into());
        let vault_drift = success_response(
            REQUEST_ID,
            9,
            "repair.backup.persist",
            &serde_json::to_string(&vault_drift).expect("drift JSON"),
        );
        assert_eq!(
            decode_client_response(&vault_drift, Vec::new(), &persist).err(),
            Some(ClientResponseDecodeError::InvalidPayload)
        );

        let get = request(ClientRequestPayload::RepairBackupGet {
            expected: Box::new(durable.clone()),
        });
        let get_payload = format!(
            "{{\"backup\":{},\"output\":{{\"type\":\"repair-backup-output-pipe\",\"size\":4096}}}}",
            serde_json::to_string(&durable).expect("durable JSON")
        );
        let get_response = success_response(REQUEST_ID, 9, "repair.backup.get", &get_payload);
        assert_eq!(
            decode_client_response(&get_response, Vec::new(), &get).err(),
            Some(ClientResponseDecodeError::FdRequired)
        );
        let output = read_pipe();
        let decoded = decode_client_response(&get_response, vec![output], &get)
            .expect("get response with output pipe");
        assert_eq!(decoded.descriptor_count(), 1);

        let release_json = format!(
            "{{\"reservationId\":\"{}\",\"draftBindingSha256\":\"{}\",\"releasedBytes\":8192}}",
            reservation.as_str(),
            durable.draft_binding_sha256().as_str()
        );
        let cancel = request(ClientRequestPayload::RepairBackupCancel {
            reservation_id: reservation.clone(),
            draft_binding_sha256: durable.draft_binding_sha256().clone(),
        });
        let cancel_json = encode_client_request(&cancel, &[]).expect("cancel request");
        assert!(
            String::from_utf8(cancel_json)
                .expect("UTF-8 cancel")
                .contains("repair.backup.cancel")
        );
        let cancel_response =
            success_response(REQUEST_ID, 9, "repair.backup.cancel", &release_json);
        assert!(decode_client_response(&cancel_response, Vec::new(), &cancel).is_ok());
        let zero_release = release_json.replace("\"releasedBytes\":8192", "\"releasedBytes\":0");
        let zero_response = success_response(REQUEST_ID, 9, "repair.backup.cancel", &zero_release);
        assert!(decode_client_response(&zero_response, Vec::new(), &cancel).is_err());

        let retire = request(ClientRequestPayload::RepairBackupRetire {
            expected: Box::new(durable.clone()),
        });
        let retire_response =
            success_response(REQUEST_ID, 9, "repair.backup.retire", &release_json);
        assert!(decode_client_response(&retire_response, Vec::new(), &retire).is_ok());

        let pending =
            RepairTransactionStatusPayload::pending(durable.clone()).expect("pending transaction");
        let transaction_status = request(ClientRequestPayload::RepairTransactionStatus {
            selector: RepairTransactionStatusSelector::pending_singleton(),
        });
        let status_json =
            encode_client_request(&transaction_status, &[]).expect("transaction status request");
        assert!(
            String::from_utf8(status_json)
                .expect("UTF-8 transaction status")
                .contains("repair.transaction.status")
        );
        let status_result = RepairTransactionStatusResultPayload::found(pending.clone());
        let status_response = success_response(
            REQUEST_ID,
            9,
            "repair.transaction.status",
            &serde_json::to_string(&status_result).expect("transaction result JSON"),
        );
        assert!(decode_client_response(&status_response, Vec::new(), &transaction_status).is_ok());

        let resolution = RepairTransactionResolution::new(
            RepairTransactionResolutionOutcome::CommittedAfter,
            execution_intent.after_sha256().clone(),
            metadata.canonical_sha256(),
            true,
            &execution_intent,
        )
        .expect("committed resolution");
        let resolve = request(ClientRequestPayload::RepairTransactionResolve {
            expected: Box::new(pending),
            resolution: resolution.clone(),
        });
        let resolve_json = encode_client_request(&resolve, &[]).expect("resolve request");
        assert!(
            String::from_utf8(resolve_json)
                .expect("UTF-8 resolve")
                .contains("repair.transaction.resolve")
        );
        let resolved = RepairTransactionStatusPayload::resolved(durable, resolution)
            .expect("resolved transaction");
        let resolved_response = success_response(
            REQUEST_ID,
            9,
            "repair.transaction.resolve",
            &serde_json::to_string(&resolved).expect("resolved JSON"),
        );
        assert!(decode_client_response(&resolved_response, Vec::new(), &resolve).is_ok());

        let live = request(ClientRequestPayload::RepairVaultLiveParent);
        let live_json = encode_client_request(&live, &[]).expect("live Vault parent request");
        assert!(
            String::from_utf8(live_json)
                .expect("UTF-8 live identity")
                .contains("repair.vault.live-parent")
        );
        let live_identity = RepairVaultLiveIdentityPayload::new(
            "V-0123456789abcdef0123456789abcdef",
            hash('c'),
            hash('d'),
        )
        .expect("live Vault identity");
        let live_response = success_response(
            REQUEST_ID,
            9,
            "repair.vault.live-parent",
            &serde_json::to_string(&live_identity).expect("live identity JSON"),
        );
        assert!(decode_client_response(&live_response, Vec::new(), &live).is_ok());
    }

    #[test]
    fn response_decoder_is_strict_correlated_and_descriptor_exact() {
        let status = request(ClientRequestPayload::VaultStatus);
        let valid = status_response(
            REQUEST_ID,
            "vault.status",
            &format!("{{\"vaultState\":\"unlocked\",\"deviceId\":\"{DEVICE_ID}\"}}"),
        );
        let decoded = decode_client_response(&valid, Vec::new(), &status).expect("valid status");
        assert_eq!(decoded.state_version(), 8);
        assert!(matches!(
            decoded.outcome(),
            ClientResponseOutcome::Success(SuccessPayload::VaultStatus(_))
        ));

        let wrong_id = status_response(
            OTHER_REQUEST_ID,
            "vault.status",
            "{\"vaultState\":\"locked\"}",
        );
        assert_eq!(
            decode_client_response(&wrong_id, Vec::new(), &status).err(),
            Some(ClientResponseDecodeError::InvalidCorrelation)
        );
        let wrong_operation =
            status_response(REQUEST_ID, "vault.lock", "{\"vaultState\":\"locked\"}");
        assert_eq!(
            decode_client_response(&wrong_operation, Vec::new(), &status).err(),
            Some(ClientResponseDecodeError::InvalidCorrelation)
        );

        let unknown_payload = status_response(
            REQUEST_ID,
            "vault.status",
            "{\"vaultState\":\"locked\",\"path\":\"/secret\"}",
        );
        assert_eq!(
            decode_client_response(&unknown_payload, Vec::new(), &status).err(),
            Some(ClientResponseDecodeError::InvalidPayload)
        );

        let error_with_payload = format!(
            "{{\"apiVersion\":\"{API_VERSION}\",\"requestId\":\"{REQUEST_ID}\",\"stateVersion\":8,\"operation\":\"vault.status\",\"outcome\":\"error\",\"error\":\"IO_FAILED\",\"payload\":{{}}}}"
        );
        assert_eq!(
            decode_client_response(error_with_payload.as_bytes(), Vec::new(), &status).err(),
            Some(ClientResponseDecodeError::InvalidJson)
        );

        let borrow = request(ClientRequestPayload::ProviderOpenAiBorrow);
        let borrow_response = status_response(
            REQUEST_ID,
            "provider.openai.borrow",
            "{\"output\":{\"type\":\"openai-api-key-pipe\",\"size\":12}}",
        );
        assert_eq!(
            decode_client_response(&borrow_response, Vec::new(), &borrow).err(),
            Some(ClientResponseDecodeError::FdRequired)
        );
        let pipe = read_pipe();
        let decoded =
            decode_client_response(&borrow_response, vec![pipe], &borrow).expect("borrow response");
        assert_eq!(decoded.descriptor_count(), 1);
    }

    #[test]
    fn response_decoder_rejects_duplicate_trailing_and_unsafe_state_numbers() {
        let status = request(ClientRequestPayload::VaultStatus);
        let duplicate = format!(
            "{{\"apiVersion\":\"{API_VERSION}\",\"requestId\":\"{REQUEST_ID}\",\"stateVersion\":8,\"stateVersion\":9,\"operation\":\"vault.status\",\"outcome\":\"ok\",\"payload\":{{\"vaultState\":\"locked\"}}}}"
        );
        assert_eq!(
            decode_client_response(duplicate.as_bytes(), Vec::new(), &status).err(),
            Some(ClientResponseDecodeError::InvalidJson)
        );
        let trailing = [
            status_response(REQUEST_ID, "vault.status", "{\"vaultState\":\"locked\"}"),
            b"[]".to_vec(),
        ]
        .concat();
        assert_eq!(
            decode_client_response(&trailing, Vec::new(), &status).err(),
            Some(ClientResponseDecodeError::InvalidJson)
        );
        let unsafe_state = format!(
            "{{\"apiVersion\":\"{API_VERSION}\",\"requestId\":\"{REQUEST_ID}\",\"stateVersion\":{},\"operation\":\"vault.status\",\"outcome\":\"ok\",\"payload\":{{\"vaultState\":\"locked\"}}}}",
            MAX_SAFE_JSON_INTEGER + 1
        );
        assert_eq!(
            decode_client_response(unsafe_state.as_bytes(), Vec::new(), &status).err(),
            Some(ClientResponseDecodeError::InvalidStateVersion)
        );
    }

    fn raw_send_descriptors(socket: BorrowedFd<'_>, bytes: &[u8], fds: &[BorrowedFd<'_>]) {
        let io = [IoSlice::new(bytes)];
        let mut space = vec![MaybeUninit::uninit(); rustix::cmsg_space!(ScmRights(fds.len()))];
        let mut control = SendAncillaryBuffer::new(&mut space);
        assert!(control.push(SendAncillaryMessage::ScmRights(fds)));
        assert_eq!(
            sendmsg(socket, &io, &mut control, SendFlags::NOSIGNAL).expect("raw sendmsg"),
            bytes.len()
        );
    }

    fn seqpacket_listener() -> (tempfile::TempDir, OwnedFd) {
        let directory = tempfile::tempdir().expect("listener temp dir");
        let path = directory.path().join("vault.sock");
        let listener = rustix::net::socket_with(
            AddressFamily::UNIX,
            SocketType::SEQPACKET,
            SocketFlags::CLOEXEC,
            None,
        )
        .expect("listener socket");
        let address = rustix::net::SocketAddrUnix::new(&path).expect("listener address");
        rustix::net::bind(listener.as_fd(), &address).expect("bind listener");
        rustix::net::listen(listener.as_fd(), 1).expect("listen");
        (directory, listener)
    }

    fn count_open_pipe_inode(inode: u64) -> usize {
        std::fs::read_dir("/proc/self/fd")
            .expect("read proc fd")
            .filter_map(Result::ok)
            .filter_map(|entry| {
                let metadata = std::fs::metadata(entry.path()).ok()?;
                use std::os::unix::fs::MetadataExt;
                (metadata.ino() == inode).then_some(())
            })
            .count()
    }

    #[test]
    fn response_descriptor_rejects_named_fifo_and_wrong_access_mode() {
        let borrow = request(ClientRequestPayload::ProviderOpenAiBorrow);
        let response = status_response(
            REQUEST_ID,
            "provider.openai.borrow",
            "{\"output\":{\"type\":\"openai-api-key-pipe\",\"size\":12}}",
        );
        let directory = tempfile::tempdir().expect("temp dir");
        let path = directory.path().join("fifo");
        rustix::fs::mkfifoat(CWD, &path, Mode::RUSR | Mode::WUSR).expect("mkfifo");
        let fifo = rustix::fs::open(
            &path,
            OFlags::RDONLY | OFlags::NONBLOCK | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .expect("open fifo");
        assert_eq!(
            decode_client_response(&response, vec![fifo], &borrow).err(),
            Some(ClientResponseDecodeError::InvalidDescriptor)
        );

        let (_read, write) = pipe_with(PipeFlags::CLOEXEC).expect("pipe");
        assert_eq!(
            decode_client_response(&response, vec![write], &borrow).err(),
            Some(ClientResponseDecodeError::InvalidDescriptor)
        );
    }

    #[test]
    fn debug_output_never_formats_packet_bytes_or_descriptor_numbers() {
        let (sender, receiver) = seqpacket_pair();
        send_seqpacket(sender.as_fd(), b"do-not-log-this", &[], test_deadline()).expect("send");
        let packet = recv_seqpacket(receiver.as_fd(), test_deadline()).expect("receive");
        let debug = format!("{packet:?}");
        assert!(!debug.contains("do-not-log-this"));

        let connection = authenticated_test_server(sender.as_fd());
        let debug = format!("{connection:?}");
        assert!(!debug.contains("socket"));
        assert!(!debug.contains("identity"));
        assert!(!debug.contains("token"));
    }
}
