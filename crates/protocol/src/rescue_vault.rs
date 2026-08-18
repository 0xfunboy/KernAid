//! Closed local IPC contract for the Rescue vault service.
//!
//! The transport is AF_UNIX `SOCK_SEQPACKET`. One packet contains exactly one
//! UTF-8 JSON document and at most one `SCM_RIGHTS` descriptor. Peer identity
//! is always taken from `SO_PEERCRED`; a PID or UID in JSON would be attacker
//! input and is therefore not part of the wire format.

use crate::rescue_vault_transport::{
    SeqpacketSocketIdentity, SeqpacketTransportError, ensure_deadline, recv_seqpacket,
    send_seqpacket, validate_bound_seqpacket_socket, validate_seqpacket_socket,
};
use serde::{Deserialize, Serialize};
use serde_json::value::RawValue;
use std::{
    fmt,
    os::fd::{BorrowedFd, OwnedFd},
    sync::Arc,
    time::Instant,
};

/// Exact version accepted on the Rescue vault socket.
pub const API_VERSION: &str = "kernaid.dev/rescue-vault/v1alpha1";
/// Maximum size of one complete seqpacket datagram.
pub const MAX_DATAGRAM_BYTES: usize = 64 * 1024;
/// Highest integer that every JSON/TypeScript implementation represents
/// exactly (`Number.MAX_SAFE_INTEGER`).
pub const MAX_SAFE_JSON_INTEGER: u64 = 9_007_199_254_740_991;
/// Largest CSPRNG seed value allowed for a fresh state-version epoch. Checked
/// increments may subsequently advance up to [`MAX_SAFE_JSON_INTEGER`].
pub const MAX_INITIAL_STATE_VERSION: u64 = (1_u64 << 52) - 1;
/// Highest Agent audit sequence accepted by the journal contract.
pub const MAX_AUDIT_SEQUENCE: u64 = 1_000_000;
/// Shortest passphrase accepted by the shipping vault writer v2 profile.
pub const MIN_PASSPHRASE_BYTES: u64 = 12;
/// Largest passphrase accepted through the one-shot pipe.
pub const MAX_PASSPHRASE_BYTES: u64 = 1024;
/// Largest OpenAI API key accepted through the one-shot pipe.
pub const MAX_OPENAI_KEY_BYTES: u64 = 512;
/// Largest schema-valid SessionReport JSON accepted for signing. This is
/// sourced from the signing implementation so the IPC boundary cannot
/// silently diverge.
pub const MAX_SESSION_REPORT_JSON_BYTES: u64 =
    kernaid_device_identity::MAX_SIGNED_REPORT_PAYLOAD_BYTES as u64;
/// Largest serialized authenticated `SignedReportEnvelope` returned or
/// indexed by the daemon. The 1.5 MiB ceiling includes base64url expansion and
/// the bounded envelope metadata around a maximum-size raw payload.
pub const MAX_SIGNED_REPORT_ENVELOPE_BYTES: u64 = 1536 * 1024;
/// Largest report index returned in one response.
pub const MAX_REPORTS_PER_RESPONSE: usize = 256;
/// Fixed authenticated media type for every persisted SessionReport payload.
pub const SESSION_REPORT_MEDIA_TYPE: &str = "application/json";
const PIPEFS_MAGIC: u64 = 0x5049_5045;

/// The unprivileged identities allowed to connect to the service.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PeerAllowlist {
    companion_uid: u32,
    agent_uid: Option<u32>,
}

impl PeerAllowlist {
    /// Constructs an allowlist. The roles must remain distinct and neither
    /// role may silently become root.
    pub fn new(companion_uid: u32, agent_uid: u32) -> Result<Self, ProtocolViolation> {
        if companion_uid == 0 || agent_uid == 0 || companion_uid == agent_uid {
            return Err(ProtocolViolation::InvalidAllowlist);
        }
        Ok(Self {
            companion_uid,
            agent_uid: Some(agent_uid),
        })
    }

    /// Constructs the lifecycle-only allowlist used before an Agent service
    /// exists. No UID can be authenticated as [`PeerRole::Agent`].
    pub fn companion_only(companion_uid: u32) -> Result<Self, ProtocolViolation> {
        if companion_uid == 0 {
            return Err(ProtocolViolation::InvalidAllowlist);
        }
        Ok(Self {
            companion_uid,
            agent_uid: None,
        })
    }

    fn role_for(self, peer_uid: u32) -> Result<PeerRole, ProtocolViolation> {
        if peer_uid == self.companion_uid {
            Ok(PeerRole::Companion)
        } else if self.agent_uid == Some(peer_uid) {
            Ok(PeerRole::Agent)
        } else {
            Err(ProtocolViolation::NotAuthorized)
        }
    }
}

/// Role derived exclusively from a kernel-authenticated peer UID.
///
/// The protocol retains future Agent audit/report shapes, while the shipping
/// Rescue daemon further restricts its OpenAI Agent UID to status operations.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PeerRole {
    Companion,
    Agent,
}

/// An authenticated server-side connection to one allowlisted peer.
///
/// The socket borrow and kernel socket identity bind all received requests and
/// emitted responses to this exact connection. The capability is deliberately
/// neither `Clone` nor `Copy`.
pub struct AuthenticatedPeer<'socket> {
    socket: BorrowedFd<'socket>,
    socket_identity: SeqpacketSocketIdentity,
    connection_token: Arc<()>,
    pid: u32,
    uid: u32,
    role: PeerRole,
}

impl fmt::Debug for AuthenticatedPeer<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AuthenticatedPeer")
            .field("pid", &self.pid)
            .field("uid", &self.uid)
            .field("role", &self.role)
            .finish_non_exhaustive()
    }
}

impl AuthenticatedPeer<'_> {
    pub fn pid(&self) -> u32 {
        self.pid
    }

    pub fn uid(&self) -> u32 {
        self.uid
    }

    pub fn role(&self) -> PeerRole {
        self.role
    }

    /// Receives, decodes, and authorizes one request from this exact peer.
    pub fn receive_request(
        &self,
        deadline: Instant,
    ) -> Result<ValidatedRequest, ServerReceiveError> {
        ensure_deadline(deadline).map_err(ServerReceiveError::Transport)?;
        validate_bound_seqpacket_socket(self.socket, self.socket_identity)
            .map_err(ServerReceiveError::Transport)?;
        let packet =
            recv_seqpacket(self.socket, deadline).map_err(ServerReceiveError::Transport)?;
        if packet.socket_identity() != self.socket_identity {
            return Err(ServerReceiveError::Transport(
                SeqpacketTransportError::InvalidTransport,
            ));
        }
        let (datagram, descriptors) = packet.into_parts();
        decode_request(
            &datagram,
            PeerIdentity {
                pid: self.pid,
                uid: self.uid,
                role: self.role,
                connection_identity: self.socket_identity,
                connection_token: Arc::clone(&self.connection_token),
            },
            descriptors,
        )
        .map_err(ServerReceiveError::Decode)
    }

    /// Encodes and sends a success response on the connection that produced
    /// `request`.
    pub fn send_success(
        &self,
        request: &ValidatedRequest,
        state_version: u64,
        payload: &SuccessPayload,
        output_descriptors: &[BorrowedFd<'_>],
        deadline: Instant,
    ) -> Result<(), ServerSendError> {
        ensure_deadline(deadline).map_err(ServerSendError::Transport)?;
        self.validate_response_binding(request.connection_identity, &request.connection_token)?;
        let datagram = encode_success(request, state_version, payload, output_descriptors)
            .map_err(ServerSendError::Protocol)?;
        send_seqpacket(self.socket, &datagram, output_descriptors, deadline)
            .map_err(ServerSendError::Transport)
    }

    /// Encodes and sends a closed-token error response on the connection that
    /// produced `request`.
    pub fn send_error(
        &self,
        request: &ValidatedRequest,
        state_version: u64,
        error: ErrorToken,
        deadline: Instant,
    ) -> Result<(), ServerSendError> {
        ensure_deadline(deadline).map_err(ServerSendError::Transport)?;
        self.validate_response_binding(request.connection_identity, &request.connection_token)?;
        let datagram =
            encode_error(request, state_version, error, &[]).map_err(ServerSendError::Protocol)?;
        send_seqpacket(self.socket, &datagram, &[], deadline).map_err(ServerSendError::Transport)
    }

    /// Sends the sole correlated response allowed for an authenticated decode
    /// rejection, on the same connection that produced it.
    pub fn send_rejection(
        &self,
        rejected: &RejectedRequestContext,
        state_version: u64,
        deadline: Instant,
    ) -> Result<(), ServerSendError> {
        ensure_deadline(deadline).map_err(ServerSendError::Transport)?;
        self.validate_response_binding(rejected.connection_identity, &rejected.connection_token)?;
        let datagram =
            encode_rejection(rejected, state_version).map_err(ServerSendError::Protocol)?;
        send_seqpacket(self.socket, &datagram, &[], deadline).map_err(ServerSendError::Transport)
    }

    fn validate_response_binding(
        &self,
        connection_identity: SeqpacketSocketIdentity,
        connection_token: &Arc<()>,
    ) -> Result<(), ServerSendError> {
        validate_bound_seqpacket_socket(self.socket, self.socket_identity)
            .map_err(ServerSendError::Transport)?;
        if connection_identity != self.socket_identity
            || !Arc::ptr_eq(connection_token, &self.connection_token)
        {
            return Err(ServerSendError::Transport(
                SeqpacketTransportError::InvalidTransport,
            ));
        }
        Ok(())
    }
}

/// Authenticates a connected AF_UNIX `SOCK_SEQPACKET` peer with
/// `SO_PEERCRED`, then applies the configured UID allowlist.
pub fn authenticate_seqpacket_peer(
    socket: BorrowedFd<'_>,
    allowlist: PeerAllowlist,
) -> Result<AuthenticatedPeer<'_>, ProtocolViolation> {
    let socket_identity =
        validate_seqpacket_socket(socket).map_err(|_| ProtocolViolation::InvalidTransport)?;
    let credentials = rustix::net::sockopt::socket_peercred(socket)
        .map_err(|_| ProtocolViolation::InvalidTransport)?;
    let pid = credentials.pid.as_raw_nonzero().get() as u32;
    let uid = credentials.uid.as_raw();
    Ok(AuthenticatedPeer {
        socket,
        socket_identity,
        connection_token: Arc::new(()),
        pid,
        uid,
        role: allowlist.role_for(uid)?,
    })
}

struct PeerIdentity {
    pid: u32,
    uid: u32,
    role: PeerRole,
    connection_identity: SeqpacketSocketIdentity,
    connection_token: Arc<()>,
}

/// Closed request operation set. There is no command, path, or generic tool
/// operation.
#[derive(Clone, Copy, Debug, Deserialize, PartialEq, Eq, Serialize)]
pub enum Operation {
    #[serde(rename = "vault.status")]
    VaultStatus,
    #[serde(rename = "vault.unlock")]
    VaultUnlock,
    #[serde(rename = "vault.lock")]
    VaultLock,
    #[serde(rename = "provider.openai.configure")]
    ProviderOpenAiConfigure,
    #[serde(rename = "provider.status")]
    ProviderStatus,
    #[serde(rename = "provider.logout")]
    ProviderLogout,
    #[serde(rename = "provider.openai.borrow")]
    ProviderOpenAiBorrow,
    #[serde(rename = "provider.codex.home_lease")]
    ProviderCodexHomeLease,
    #[serde(rename = "audit.append")]
    AuditAppend,
    #[serde(rename = "report.persist")]
    ReportPersist,
    #[serde(rename = "report.list")]
    ReportList,
    #[serde(rename = "report.get")]
    ReportGet,
}

impl Operation {
    fn permits(self, role: PeerRole) -> bool {
        match self {
            Self::VaultUnlock
            | Self::VaultLock
            | Self::ProviderOpenAiConfigure
            | Self::ProviderLogout => role == PeerRole::Companion,
            Self::ProviderOpenAiBorrow
            | Self::ProviderCodexHomeLease
            | Self::AuditAppend
            | Self::ReportPersist => role == PeerRole::Agent,
            Self::VaultStatus | Self::ProviderStatus | Self::ReportList | Self::ReportGet => true,
        }
    }
}

/// Opaque, validated correlation identifier.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RequestId(String);

impl RequestId {
    /// Reconstructs a request identifier with the exact wire grammar.
    pub fn parse(value: &str) -> Result<Self, ProtocolViolation> {
        parse_request_id(value)
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// Opaque, validated persisted-report identifier.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(transparent)]
pub struct ReportId(String);

impl ReportId {
    /// Reconstruct a persisted report identifier with the exact wire grammar.
    pub fn parse(value: &str) -> Result<Self, ProtocolViolation> {
        if value.len() != 39 || !value.starts_with("RP-") || !canonical_uuid(&value.as_bytes()[3..])
        {
            return Err(ProtocolViolation::InvalidPayload);
        }
        Ok(Self(value.to_owned()))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// Opaque lowercase SHA-256 value.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(transparent)]
pub struct Sha256(String);

impl Sha256 {
    /// Reconstruct a persisted lowercase SHA-256 value with the exact wire
    /// grammar.
    pub fn parse(value: &str) -> Result<Self, ProtocolViolation> {
        if value.len() != 64
            || !value
                .as_bytes()
                .iter()
                .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
        {
            return Err(ProtocolViolation::InvalidPayload);
        }
        Ok(Self(value.to_owned()))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// Exact descriptor purpose carried in an operation payload.
#[derive(Clone, Copy, Debug, Deserialize, PartialEq, Eq, Serialize)]
pub enum DescriptorType {
    #[serde(rename = "passphrase-pipe")]
    PassphrasePipe,
    #[serde(rename = "openai-api-key-pipe")]
    OpenAiApiKeyPipe,
    #[serde(rename = "codex-home-o-path")]
    CodexHomeOPath,
    #[serde(rename = "session-report-json-pipe")]
    SessionReportJsonPipe,
    #[serde(rename = "signed-report-envelope-pipe")]
    SignedReportEnvelopePipe,
}

/// Declared one-shot descriptor body. `size` is the exact number of bytes the
/// eventual consumer must read before EOF; it is never secret material.
#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DescriptorDeclaration {
    #[serde(rename = "type")]
    pub kind: DescriptorType,
    pub size: u64,
}

/// Provider selected for the generic logout operation.
#[derive(Clone, Copy, Debug, Deserialize, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Provider {
    OpenAi,
    Codex,
}

/// Fixed Agent-asserted session categories. Privileged vault/provider/report
/// events are generated internally by the daemon and cannot be submitted by
/// the Agent. Observed text and filesystem paths cannot be smuggled through
/// this channel.
#[derive(Clone, Copy, Debug, Deserialize, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum AuditEventType {
    AgentSessionStart,
    AgentDiagnosisComplete,
    AgentSessionEnd,
}

#[derive(Clone, Copy, Debug, Deserialize, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum AuditOutcome {
    Succeeded,
    Rejected,
    Failed,
}

/// Closed error vocabulary safe to show outside the privileged process.
#[derive(Clone, Copy, Debug, Deserialize, PartialEq, Eq, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ErrorToken {
    Absent,
    Unprovisioned,
    Locked,
    BadPassphrase,
    MediaChanged,
    ProfileMismatch,
    StaleState,
    FdRequired,
    FdForbidden,
    NotAuthorized,
    RateLimited,
    Busy,
    ProviderUnconfigured,
    ReportTooLarge,
    IoFailed,
    RebootRequired,
}

/// Operation-specific validated request body.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RequestPayload {
    Empty,
    VaultUnlock {
        input: DescriptorDeclaration,
    },
    ProviderOpenAiConfigure {
        input: DescriptorDeclaration,
    },
    ProviderLogout {
        provider: Provider,
    },
    AuditAppend {
        sequence: u64,
        event: AuditEventType,
        outcome: AuditOutcome,
        error: Option<ErrorToken>,
    },
    ReportPersist {
        report_id: ReportId,
        payload_sha256: Sha256,
        input: DescriptorDeclaration,
    },
    ReportGet {
        report_id: ReportId,
    },
}

/// A request accepted after schema, role, descriptor-count, descriptor-type,
/// and declared-size validation.
pub struct ValidatedRequest {
    request_id: RequestId,
    expected_state_version: u64,
    operation: Operation,
    peer_pid: u32,
    peer_uid: u32,
    role: PeerRole,
    payload: RequestPayload,
    descriptors: Vec<OwnedFd>,
    connection_identity: SeqpacketSocketIdentity,
    connection_token: Arc<()>,
}

impl fmt::Debug for ValidatedRequest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ValidatedRequest")
            .field("request_id", &self.request_id)
            .field("expected_state_version", &self.expected_state_version)
            .field("operation", &self.operation)
            .field("peer_pid", &self.peer_pid)
            .field("peer_uid", &self.peer_uid)
            .field("role", &self.role)
            .field("payload", &self.payload)
            .field("descriptor_count", &self.descriptors.len())
            .finish()
    }
}

impl ValidatedRequest {
    pub fn request_id(&self) -> &RequestId {
        &self.request_id
    }

    pub fn expected_state_version(&self) -> u64 {
        self.expected_state_version
    }

    pub fn operation(&self) -> Operation {
        self.operation
    }

    pub fn role(&self) -> PeerRole {
        self.role
    }

    pub fn peer_pid(&self) -> u32 {
        self.peer_pid
    }

    pub fn peer_uid(&self) -> u32 {
        self.peer_uid
    }

    pub fn payload(&self) -> &RequestPayload {
        &self.payload
    }

    /// Transfers the sole already-validated input descriptor to the handler.
    /// Operations without an input descriptor return `None`.
    pub fn take_descriptor(&mut self) -> Option<OwnedFd> {
        self.descriptors.pop()
    }
}

/// Local decoder failures. Their display text is fixed and carries no JSON,
/// path, descriptor, provider secret, or OS error.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ProtocolViolation {
    EmptyDatagram,
    DatagramTooLarge,
    InvalidJson,
    UnsupportedVersion,
    InvalidRequestId,
    InvalidPayload,
    InvalidAllowlist,
    InvalidTransport,
    NotAuthorized,
    FdRequired,
    FdForbidden,
    InvalidDescriptor,
}

impl ProtocolViolation {
    /// Returns a wire-safe error only for failures that are safe to
    /// acknowledge. Syntax/version errors should close the connection.
    pub fn error_token(self) -> Option<ErrorToken> {
        match self {
            Self::NotAuthorized => Some(ErrorToken::NotAuthorized),
            Self::FdRequired | Self::InvalidDescriptor => Some(ErrorToken::FdRequired),
            Self::FdForbidden => Some(ErrorToken::FdForbidden),
            Self::EmptyDatagram
            | Self::DatagramTooLarge
            | Self::InvalidJson
            | Self::UnsupportedVersion
            | Self::InvalidRequestId
            | Self::InvalidPayload
            | Self::InvalidAllowlist
            | Self::InvalidTransport => None,
        }
    }
}

impl fmt::Display for ProtocolViolation {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::EmptyDatagram => "empty Rescue vault datagram",
            Self::DatagramTooLarge => "Rescue vault datagram exceeds its bound",
            Self::InvalidJson => "invalid Rescue vault JSON envelope",
            Self::UnsupportedVersion => "unsupported Rescue vault protocol version",
            Self::InvalidRequestId => "invalid Rescue vault request identifier",
            Self::InvalidPayload => "invalid Rescue vault operation payload",
            Self::InvalidAllowlist => "invalid Rescue vault peer allowlist",
            Self::InvalidTransport => "invalid Rescue vault socket transport",
            Self::NotAuthorized => "Rescue vault peer is not authorized",
            Self::FdRequired => "Rescue vault operation requires one descriptor",
            Self::FdForbidden => "Rescue vault operation forbids received descriptors",
            Self::InvalidDescriptor => "invalid Rescue vault descriptor",
        })
    }
}

impl std::error::Error for ProtocolViolation {}

/// Sanitized decode failure. `Close` has no trustworthy request context and
/// requires closing the connection without a response. `Reject` is minted only
/// after version, request ID, state version and operation have been validated,
/// so the daemon can emit one correlated closed-token response.
#[derive(Debug)]
pub enum RequestDecodeError {
    Close(ProtocolViolation),
    Reject(RejectedRequestContext),
}

impl RequestDecodeError {
    pub fn violation(&self) -> ProtocolViolation {
        match self {
            Self::Close(violation) => *violation,
            Self::Reject(context) => context.violation,
        }
    }
}

impl PartialEq<ProtocolViolation> for RequestDecodeError {
    fn eq(&self, other: &ProtocolViolation) -> bool {
        self.violation() == *other
    }
}

impl fmt::Display for RequestDecodeError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.violation().fmt(formatter)
    }
}

impl std::error::Error for RequestDecodeError {}

/// Failure while receiving a request through an authenticated peer
/// capability.
#[derive(Debug)]
pub enum ServerReceiveError {
    Transport(SeqpacketTransportError),
    Decode(RequestDecodeError),
}

impl fmt::Display for ServerReceiveError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Transport(error) => error.fmt(formatter),
            Self::Decode(error) => error.fmt(formatter),
        }
    }
}

impl std::error::Error for ServerReceiveError {}

/// Failure while encoding or sending a response through an authenticated peer
/// capability.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ServerSendError {
    Protocol(ProtocolViolation),
    Transport(SeqpacketTransportError),
}

impl fmt::Display for ServerSendError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Protocol(error) => error.fmt(formatter),
            Self::Transport(error) => error.fmt(formatter),
        }
    }
}

impl std::error::Error for ServerSendError {}

/// Correlation data retained for an authenticated protocol rejection. It has
/// no payload, peer-supplied text or descriptor metadata.
pub struct RejectedRequestContext {
    request_id: RequestId,
    operation: Operation,
    violation: ProtocolViolation,
    error: ErrorToken,
    connection_identity: SeqpacketSocketIdentity,
    connection_token: Arc<()>,
}

impl fmt::Debug for RejectedRequestContext {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RejectedRequestContext")
            .field("request_id", &self.request_id)
            .field("operation", &self.operation)
            .field("violation", &self.violation)
            .field("error", &self.error)
            .finish()
    }
}

impl RejectedRequestContext {
    pub fn request_id(&self) -> &RequestId {
        &self.request_id
    }

    pub fn operation(&self) -> Operation {
        self.operation
    }

    pub fn violation(&self) -> ProtocolViolation {
        self.violation
    }

    pub fn error(&self) -> ErrorToken {
        self.error
    }
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct WireRequest<'a> {
    api_version: &'a str,
    request_id: &'a str,
    expected_state_version: u64,
    operation: Operation,
    #[serde(borrow)]
    payload: &'a RawValue,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct EmptyPayload {}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct DescriptorPayload {
    input: DescriptorDeclaration,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct LogoutPayload {
    provider: Provider,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct AuditPayload {
    sequence: u64,
    event: AuditEventType,
    outcome: AuditOutcome,
    error: Option<ErrorToken>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct PersistPayload {
    report_id: String,
    payload_sha256: String,
    input: DescriptorDeclaration,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct GetPayload {
    report_id: String,
}

/// Decodes and authorizes one complete request packet for an already-bound
/// peer identity. The public entry point is [`AuthenticatedPeer::receive_request`].
///
/// `received_descriptors` must be the exact set from this one seqpacket. The
/// function consumes and closes them on every error.
fn decode_request(
    datagram: &[u8],
    peer: PeerIdentity,
    received_descriptors: Vec<OwnedFd>,
) -> Result<ValidatedRequest, RequestDecodeError> {
    if datagram.is_empty() {
        return Err(RequestDecodeError::Close(ProtocolViolation::EmptyDatagram));
    }
    if datagram.len() > MAX_DATAGRAM_BYTES {
        return Err(RequestDecodeError::Close(
            ProtocolViolation::DatagramTooLarge,
        ));
    }
    let wire: WireRequest<'_> = serde_json::from_slice(datagram)
        .map_err(|_| RequestDecodeError::Close(ProtocolViolation::InvalidJson))?;
    if wire.api_version != API_VERSION {
        return Err(RequestDecodeError::Close(
            ProtocolViolation::UnsupportedVersion,
        ));
    }
    if wire.expected_state_version > MAX_SAFE_JSON_INTEGER {
        return Err(RequestDecodeError::Close(ProtocolViolation::InvalidPayload));
    }
    let request_id = parse_request_id(wire.request_id).map_err(RequestDecodeError::Close)?;
    if !wire.operation.permits(peer.role) {
        return Err(rejected_request(
            request_id,
            wire.operation,
            ProtocolViolation::NotAuthorized,
            ErrorToken::NotAuthorized,
            peer.connection_identity,
            Arc::clone(&peer.connection_token),
        ));
    }

    let payload = parse_payload(wire.operation, wire.payload).map_err(RequestDecodeError::Close)?;
    if let Err(violation) = validate_received_descriptors(&payload, &received_descriptors) {
        let Some(error) = violation.error_token() else {
            return Err(RequestDecodeError::Close(violation));
        };
        return Err(rejected_request(
            request_id,
            wire.operation,
            violation,
            error,
            peer.connection_identity,
            Arc::clone(&peer.connection_token),
        ));
    }
    Ok(ValidatedRequest {
        request_id,
        expected_state_version: wire.expected_state_version,
        operation: wire.operation,
        peer_pid: peer.pid,
        peer_uid: peer.uid,
        role: peer.role,
        payload,
        descriptors: received_descriptors,
        connection_identity: peer.connection_identity,
        connection_token: peer.connection_token,
    })
}

fn rejected_request(
    request_id: RequestId,
    operation: Operation,
    violation: ProtocolViolation,
    error: ErrorToken,
    connection_identity: SeqpacketSocketIdentity,
    connection_token: Arc<()>,
) -> RequestDecodeError {
    RequestDecodeError::Reject(RejectedRequestContext {
        request_id,
        operation,
        violation,
        error,
        connection_identity,
        connection_token,
    })
}

fn parse_payload(
    operation: Operation,
    raw: &RawValue,
) -> Result<RequestPayload, ProtocolViolation> {
    match operation {
        Operation::VaultStatus
        | Operation::VaultLock
        | Operation::ProviderStatus
        | Operation::ProviderOpenAiBorrow
        | Operation::ProviderCodexHomeLease
        | Operation::ReportList => {
            serde_json::from_str::<EmptyPayload>(raw.get())
                .map_err(|_| ProtocolViolation::InvalidPayload)?;
            Ok(RequestPayload::Empty)
        }
        Operation::VaultUnlock => {
            let payload = serde_json::from_str::<DescriptorPayload>(raw.get())
                .map_err(|_| ProtocolViolation::InvalidPayload)?;
            validate_declaration(
                &payload.input,
                DescriptorType::PassphrasePipe,
                MIN_PASSPHRASE_BYTES,
                MAX_PASSPHRASE_BYTES,
            )?;
            Ok(RequestPayload::VaultUnlock {
                input: payload.input,
            })
        }
        Operation::ProviderOpenAiConfigure => {
            let payload = serde_json::from_str::<DescriptorPayload>(raw.get())
                .map_err(|_| ProtocolViolation::InvalidPayload)?;
            validate_declaration(
                &payload.input,
                DescriptorType::OpenAiApiKeyPipe,
                1,
                MAX_OPENAI_KEY_BYTES,
            )?;
            Ok(RequestPayload::ProviderOpenAiConfigure {
                input: payload.input,
            })
        }
        Operation::ProviderLogout => {
            let payload = serde_json::from_str::<LogoutPayload>(raw.get())
                .map_err(|_| ProtocolViolation::InvalidPayload)?;
            Ok(RequestPayload::ProviderLogout {
                provider: payload.provider,
            })
        }
        Operation::AuditAppend => {
            let payload = serde_json::from_str::<AuditPayload>(raw.get())
                .map_err(|_| ProtocolViolation::InvalidPayload)?;
            if !(1..=MAX_AUDIT_SEQUENCE).contains(&payload.sequence)
                || (payload.outcome == AuditOutcome::Succeeded && payload.error.is_some())
                || (payload.outcome != AuditOutcome::Succeeded && payload.error.is_none())
            {
                return Err(ProtocolViolation::InvalidPayload);
            }
            Ok(RequestPayload::AuditAppend {
                sequence: payload.sequence,
                event: payload.event,
                outcome: payload.outcome,
                error: payload.error,
            })
        }
        Operation::ReportPersist => {
            let payload = serde_json::from_str::<PersistPayload>(raw.get())
                .map_err(|_| ProtocolViolation::InvalidPayload)?;
            validate_declaration(
                &payload.input,
                DescriptorType::SessionReportJsonPipe,
                2,
                MAX_SESSION_REPORT_JSON_BYTES,
            )?;
            Ok(RequestPayload::ReportPersist {
                report_id: ReportId::parse(&payload.report_id)?,
                payload_sha256: Sha256::parse(&payload.payload_sha256)?,
                input: payload.input,
            })
        }
        Operation::ReportGet => {
            let payload = serde_json::from_str::<GetPayload>(raw.get())
                .map_err(|_| ProtocolViolation::InvalidPayload)?;
            Ok(RequestPayload::ReportGet {
                report_id: ReportId::parse(&payload.report_id)?,
            })
        }
    }
}

fn validate_declaration(
    declaration: &DescriptorDeclaration,
    expected_kind: DescriptorType,
    minimum_size: u64,
    maximum_size: u64,
) -> Result<(), ProtocolViolation> {
    if declaration.kind != expected_kind
        || declaration.size < minimum_size
        || declaration.size > maximum_size
    {
        return Err(ProtocolViolation::InvalidPayload);
    }
    Ok(())
}

/// Applies the same provider-key byte policy as the shipping native secure
/// store after a handler has read exactly the declared pipe size and EOF.
/// The value is never formatted or retained by this function.
pub fn validate_openai_api_key_bytes(value: &[u8]) -> Result<(), ProtocolViolation> {
    if value.is_empty()
        || u64::try_from(value.len())
            .ok()
            .is_none_or(|length| length > MAX_OPENAI_KEY_BYTES)
        || !value.iter().all(|byte| matches!(byte, 0x21..=0x7e))
    {
        return Err(ProtocolViolation::InvalidPayload);
    }
    Ok(())
}

/// Applies the vault writer v2 passphrase policy after a handler has read the
/// declared bytes and attempted one further read to prove EOF.
///
/// Callers should retain the bytes in zeroizing storage; this validator never
/// formats, logs or copies the value.
pub fn validate_passphrase_read(
    value: &[u8],
    declared_size: u64,
    reached_eof: bool,
) -> Result<(), ProtocolViolation> {
    if !(MIN_PASSPHRASE_BYTES..=MAX_PASSPHRASE_BYTES).contains(&declared_size)
        || u64::try_from(value.len()) != Ok(declared_size)
        || !reached_eof
        || value.contains(&0)
    {
        return Err(ProtocolViolation::InvalidPayload);
    }
    Ok(())
}

fn payload_descriptor(payload: &RequestPayload) -> Option<&DescriptorDeclaration> {
    match payload {
        RequestPayload::VaultUnlock { input }
        | RequestPayload::ProviderOpenAiConfigure { input }
        | RequestPayload::ReportPersist { input, .. } => Some(input),
        RequestPayload::Empty
        | RequestPayload::ProviderLogout { .. }
        | RequestPayload::AuditAppend { .. }
        | RequestPayload::ReportGet { .. } => None,
    }
}

fn validate_received_descriptors(
    payload: &RequestPayload,
    descriptors: &[OwnedFd],
) -> Result<(), ProtocolViolation> {
    match (payload_descriptor(payload), descriptors) {
        (Some(_), []) => return Err(ProtocolViolation::FdRequired),
        (Some(_), [descriptor]) => validate_pipe_descriptor(descriptor)?,
        (Some(_), [_, ..]) | (None, [_, ..]) => return Err(ProtocolViolation::FdForbidden),
        (None, []) => {}
    }
    Ok(())
}

fn validate_pipe_descriptor(descriptor: &OwnedFd) -> Result<(), ProtocolViolation> {
    use rustix::fs::{self as rfs, FileType, OFlags};

    let stat = rfs::fstat(descriptor).map_err(|_| ProtocolViolation::InvalidDescriptor)?;
    let filesystem = rfs::fstatfs(descriptor).map_err(|_| ProtocolViolation::InvalidDescriptor)?;
    let filesystem_type =
        u64::try_from(filesystem.f_type).map_err(|_| ProtocolViolation::InvalidDescriptor)?;
    let status = rfs::fcntl_getfl(descriptor).map_err(|_| ProtocolViolation::InvalidDescriptor)?;
    let fd_flags =
        rustix::io::fcntl_getfd(descriptor).map_err(|_| ProtocolViolation::InvalidDescriptor)?;
    if !FileType::from_raw_mode(stat.st_mode).is_fifo()
        || filesystem_type != PIPEFS_MAGIC
        || status & OFlags::ACCMODE != OFlags::RDONLY
        || !fd_flags.contains(rustix::io::FdFlags::CLOEXEC)
        || stat.st_size != 0
    {
        return Err(ProtocolViolation::InvalidDescriptor);
    }
    Ok(())
}

fn parse_request_id(value: &str) -> Result<RequestId, ProtocolViolation> {
    if value.len() != 38 || !value.starts_with("R-") || !canonical_uuid(&value.as_bytes()[2..]) {
        return Err(ProtocolViolation::InvalidRequestId);
    }
    Ok(RequestId(value.to_owned()))
}

fn canonical_uuid(value: &[u8]) -> bool {
    value.len() == 36
        && value.iter().enumerate().all(|(index, byte)| match index {
            8 | 13 | 18 | 23 => *byte == b'-',
            _ => byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'),
        })
}

/// State of persistent Rescue vault media, safe for UI display.
#[derive(Clone, Copy, Debug, Deserialize, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum VaultState {
    Absent,
    Unprovisioned,
    Locked,
    Unlocking,
    Unlocked,
    Locking,
    FaultedRebootRequired,
}

/// Apply the closed vault-state gate after request authentication. A faulted
/// service exposes status only until reboot; transitional states expose status
/// while rejecting competing work as busy.
pub fn gate_operation_for_vault_state(
    vault_state: VaultState,
    operation: Operation,
) -> Result<(), ErrorToken> {
    match (vault_state, operation) {
        (VaultState::FaultedRebootRequired, Operation::VaultStatus) => Ok(()),
        (VaultState::FaultedRebootRequired, _) => Err(ErrorToken::RebootRequired),
        (VaultState::Unlocking | VaultState::Locking, Operation::VaultStatus) => Ok(()),
        (VaultState::Unlocking | VaultState::Locking, _) => Err(ErrorToken::Busy),
        _ => Ok(()),
    }
}

#[derive(Clone, Copy, Debug, Deserialize, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum ProviderState {
    Unconfigured,
    Configured,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct VaultStatusPayload {
    vault_state: VaultState,
    #[serde(skip_serializing_if = "Option::is_none")]
    device_id: Option<String>,
}

impl VaultStatusPayload {
    /// Create an exact status payload. A public device identity is required
    /// only while the vault is unlocked and forbidden in every other state.
    pub fn new(
        vault_state: VaultState,
        device_id: Option<&str>,
    ) -> Result<Self, ProtocolViolation> {
        let valid = match (vault_state, device_id) {
            (VaultState::Unlocked, Some(device_id)) => {
                kernaid_device_identity::validate_device_id(device_id).is_ok()
            }
            (
                VaultState::Absent
                | VaultState::Unprovisioned
                | VaultState::Locked
                | VaultState::Unlocking
                | VaultState::Locking
                | VaultState::FaultedRebootRequired,
                None,
            ) => true,
            _ => false,
        };
        if !valid {
            return Err(ProtocolViolation::InvalidPayload);
        }
        Ok(Self {
            vault_state,
            device_id: device_id.map(str::to_owned),
        })
    }

    pub fn vault_state(&self) -> VaultState {
        self.vault_state
    }

    pub fn device_id(&self) -> Option<&str> {
        self.device_id.as_deref()
    }

    pub(crate) fn is_exact(&self) -> bool {
        match (self.vault_state, self.device_id.as_deref()) {
            (VaultState::Unlocked, Some(device_id)) => {
                kernaid_device_identity::validate_device_id(device_id).is_ok()
            }
            (
                VaultState::Absent
                | VaultState::Unprovisioned
                | VaultState::Locked
                | VaultState::Unlocking
                | VaultState::Locking
                | VaultState::FaultedRebootRequired,
                None,
            ) => true,
            _ => false,
        }
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ProviderStatusPayload {
    pub openai: ProviderState,
    pub codex: ProviderState,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ReportSummary {
    report_id: ReportId,
    envelope_size: u64,
    envelope_sha256: Sha256,
}

impl ReportSummary {
    /// Describe the serialized, signature-verified envelope stored by the
    /// daemon. These are deliberately not the raw payload size/hash declared
    /// by `report.persist`.
    pub fn new(
        report_id: ReportId,
        envelope_size: u64,
        envelope_sha256: Sha256,
    ) -> Result<Self, ProtocolViolation> {
        if !(2..=MAX_SIGNED_REPORT_ENVELOPE_BYTES).contains(&envelope_size) {
            return Err(ProtocolViolation::InvalidPayload);
        }
        Ok(Self {
            report_id,
            envelope_size,
            envelope_sha256,
        })
    }

    pub fn report_id(&self) -> &ReportId {
        &self.report_id
    }

    pub fn envelope_size(&self) -> u64 {
        self.envelope_size
    }

    pub fn envelope_sha256(&self) -> &Sha256 {
        &self.envelope_sha256
    }
}

/// Closed success payload set. No variant contains a filesystem path, secret,
/// OS error string, or free-form diagnostic text.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SuccessPayload {
    VaultStatus(VaultStatusPayload),
    ProviderStatus(ProviderStatusPayload),
    Descriptor(DescriptorDeclaration),
    AuditAppended { sequence: u64 },
    ReportStored(ReportSummary),
    ReportList { reports: Vec<ReportSummary> },
    Report(ReportSummary, DescriptorDeclaration),
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct SuccessWire<'a, T: Serialize> {
    api_version: &'static str,
    request_id: &'a str,
    state_version: u64,
    operation: Operation,
    outcome: &'static str,
    payload: T,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct ErrorWire<'a> {
    api_version: &'static str,
    request_id: &'a str,
    state_version: u64,
    operation: Operation,
    outcome: &'static str,
    error: ErrorToken,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct DescriptorResponse<'a> {
    output: &'a DescriptorDeclaration,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct AuditResponse {
    sequence: u64,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ReportListResponse<'a> {
    reports: &'a [ReportSummary],
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ReportResponse<'a> {
    report: &'a ReportSummary,
    output: &'a DescriptorDeclaration,
}

/// Encodes one success packet only when its payload and ancillary descriptors
/// exactly match the request operation.
fn encode_success(
    request: &ValidatedRequest,
    state_version: u64,
    payload: &SuccessPayload,
    output_descriptors: &[BorrowedFd<'_>],
) -> Result<Vec<u8>, ProtocolViolation> {
    if state_version > MAX_SAFE_JSON_INTEGER {
        return Err(ProtocolViolation::InvalidPayload);
    }
    validate_success(request, payload, output_descriptors)?;
    let request_id = request.request_id.as_str();
    let operation = request.operation;
    let bytes = match payload {
        SuccessPayload::VaultStatus(value) => serde_json::to_vec(&SuccessWire {
            api_version: API_VERSION,
            request_id,
            state_version,
            operation,
            outcome: "ok",
            payload: value,
        }),
        SuccessPayload::ProviderStatus(value) => serde_json::to_vec(&SuccessWire {
            api_version: API_VERSION,
            request_id,
            state_version,
            operation,
            outcome: "ok",
            payload: value,
        }),
        SuccessPayload::Descriptor(output) => serde_json::to_vec(&SuccessWire {
            api_version: API_VERSION,
            request_id,
            state_version,
            operation,
            outcome: "ok",
            payload: DescriptorResponse { output },
        }),
        SuccessPayload::AuditAppended { sequence } => serde_json::to_vec(&SuccessWire {
            api_version: API_VERSION,
            request_id,
            state_version,
            operation,
            outcome: "ok",
            payload: AuditResponse {
                sequence: *sequence,
            },
        }),
        SuccessPayload::ReportStored(report) => serde_json::to_vec(&SuccessWire {
            api_version: API_VERSION,
            request_id,
            state_version,
            operation,
            outcome: "ok",
            payload: report,
        }),
        SuccessPayload::ReportList { reports } => serde_json::to_vec(&SuccessWire {
            api_version: API_VERSION,
            request_id,
            state_version,
            operation,
            outcome: "ok",
            payload: ReportListResponse { reports },
        }),
        SuccessPayload::Report(report, output) => serde_json::to_vec(&SuccessWire {
            api_version: API_VERSION,
            request_id,
            state_version,
            operation,
            outcome: "ok",
            payload: ReportResponse { report, output },
        }),
    }
    .map_err(|_| ProtocolViolation::InvalidPayload)?;
    if bytes.len() > MAX_DATAGRAM_BYTES {
        return Err(ProtocolViolation::DatagramTooLarge);
    }
    Ok(bytes)
}

/// Encodes an error packet. Errors can never carry a descriptor or a message.
fn encode_error(
    request: &ValidatedRequest,
    state_version: u64,
    error: ErrorToken,
    output_descriptors: &[BorrowedFd<'_>],
) -> Result<Vec<u8>, ProtocolViolation> {
    if state_version > MAX_SAFE_JSON_INTEGER {
        return Err(ProtocolViolation::InvalidPayload);
    }
    if !output_descriptors.is_empty() {
        return Err(ProtocolViolation::FdForbidden);
    }
    let bytes = serde_json::to_vec(&ErrorWire {
        api_version: API_VERSION,
        request_id: request.request_id.as_str(),
        state_version,
        operation: request.operation,
        outcome: "error",
        error,
    })
    .map_err(|_| ProtocolViolation::InvalidPayload)?;
    if bytes.len() > MAX_DATAGRAM_BYTES {
        return Err(ProtocolViolation::DatagramTooLarge);
    }
    Ok(bytes)
}

/// Encodes the only response allowed for a decode-time rejection. Close-only
/// failures intentionally have no such API because their correlation fields
/// were not all trustworthy.
fn encode_rejection(
    rejected: &RejectedRequestContext,
    state_version: u64,
) -> Result<Vec<u8>, ProtocolViolation> {
    if state_version > MAX_SAFE_JSON_INTEGER {
        return Err(ProtocolViolation::InvalidPayload);
    }
    let bytes = serde_json::to_vec(&ErrorWire {
        api_version: API_VERSION,
        request_id: rejected.request_id.as_str(),
        state_version,
        operation: rejected.operation,
        outcome: "error",
        error: rejected.error,
    })
    .map_err(|_| ProtocolViolation::InvalidPayload)?;
    if bytes.len() > MAX_DATAGRAM_BYTES {
        return Err(ProtocolViolation::DatagramTooLarge);
    }
    Ok(bytes)
}

fn validate_success(
    request: &ValidatedRequest,
    payload: &SuccessPayload,
    descriptors: &[BorrowedFd<'_>],
) -> Result<(), ProtocolViolation> {
    let descriptor_declaration = match (request.operation, &request.payload, payload) {
        (Operation::VaultStatus, RequestPayload::Empty, SuccessPayload::VaultStatus(status))
            if status.is_exact() =>
        {
            None
        }
        (
            Operation::VaultUnlock,
            RequestPayload::VaultUnlock { .. },
            SuccessPayload::VaultStatus(status),
        ) if status.is_exact() && status.vault_state() == VaultState::Unlocked => None,
        (Operation::VaultLock, RequestPayload::Empty, SuccessPayload::VaultStatus(status))
            if status.is_exact() && status.vault_state() == VaultState::Locked =>
        {
            None
        }
        (
            Operation::ProviderOpenAiConfigure,
            RequestPayload::ProviderOpenAiConfigure { .. },
            SuccessPayload::ProviderStatus(ProviderStatusPayload {
                openai: ProviderState::Configured,
                ..
            }),
        )
        | (Operation::ProviderStatus, RequestPayload::Empty, SuccessPayload::ProviderStatus(_)) => {
            None
        }
        (
            Operation::ProviderLogout,
            RequestPayload::ProviderLogout {
                provider: Provider::OpenAi,
            },
            SuccessPayload::ProviderStatus(ProviderStatusPayload {
                openai: ProviderState::Unconfigured,
                ..
            }),
        )
        | (
            Operation::ProviderLogout,
            RequestPayload::ProviderLogout {
                provider: Provider::Codex,
            },
            SuccessPayload::ProviderStatus(ProviderStatusPayload {
                codex: ProviderState::Unconfigured,
                ..
            }),
        ) => None,
        (
            Operation::AuditAppend,
            RequestPayload::AuditAppend {
                sequence: requested,
                ..
            },
            SuccessPayload::AuditAppended { sequence },
        ) if (1..=MAX_AUDIT_SEQUENCE).contains(sequence) && sequence == requested => None,
        (
            Operation::ReportPersist,
            RequestPayload::ReportPersist {
                report_id,
                payload_sha256: _,
                input: _,
            },
            SuccessPayload::ReportStored(report),
        ) if report.report_id() == report_id => None,
        (
            Operation::ProviderOpenAiBorrow,
            RequestPayload::Empty,
            SuccessPayload::Descriptor(declaration),
        ) if declaration.kind == DescriptorType::OpenAiApiKeyPipe
            && (1..=MAX_OPENAI_KEY_BYTES).contains(&declaration.size) =>
        {
            Some(declaration)
        }
        (
            Operation::ProviderCodexHomeLease,
            RequestPayload::Empty,
            SuccessPayload::Descriptor(declaration),
        ) if declaration.kind == DescriptorType::CodexHomeOPath && declaration.size == 0 => {
            Some(declaration)
        }
        (Operation::ReportList, RequestPayload::Empty, SuccessPayload::ReportList { reports })
            if valid_report_list(reports) =>
        {
            None
        }
        (
            Operation::ReportGet,
            RequestPayload::ReportGet { report_id },
            SuccessPayload::Report(report, declaration),
        ) if declaration.kind == DescriptorType::SignedReportEnvelopePipe
            && declaration.size == report.envelope_size()
            && declaration.size <= MAX_SIGNED_REPORT_ENVELOPE_BYTES
            && report.report_id() == report_id =>
        {
            Some(declaration)
        }
        _ => return Err(ProtocolViolation::InvalidPayload),
    };

    match (descriptor_declaration, descriptors) {
        (None, []) => Ok(()),
        (None, [_, ..]) | (Some(_), [_, _, ..]) => Err(ProtocolViolation::FdForbidden),
        (Some(_), []) => Err(ProtocolViolation::FdRequired),
        (Some(declaration), [descriptor]) => match declaration.kind {
            DescriptorType::OpenAiApiKeyPipe | DescriptorType::SignedReportEnvelopePipe => {
                validate_borrowed_pipe(*descriptor)
            }
            DescriptorType::CodexHomeOPath => validate_o_path_directory(*descriptor),
            DescriptorType::PassphrasePipe | DescriptorType::SessionReportJsonPipe => {
                Err(ProtocolViolation::InvalidPayload)
            }
        },
    }
}

pub(crate) fn valid_report_list(reports: &[ReportSummary]) -> bool {
    reports.len() <= MAX_REPORTS_PER_RESPONSE
        && reports.iter().enumerate().all(|(index, report)| {
            reports[..index]
                .iter()
                .all(|other| other.report_id() != report.report_id())
        })
}

pub(crate) fn validate_borrowed_pipe(descriptor: BorrowedFd<'_>) -> Result<(), ProtocolViolation> {
    use rustix::fs::{self as rfs, FileType, OFlags};

    let stat = rfs::fstat(descriptor).map_err(|_| ProtocolViolation::InvalidDescriptor)?;
    let filesystem = rfs::fstatfs(descriptor).map_err(|_| ProtocolViolation::InvalidDescriptor)?;
    let filesystem_type =
        u64::try_from(filesystem.f_type).map_err(|_| ProtocolViolation::InvalidDescriptor)?;
    let status = rfs::fcntl_getfl(descriptor).map_err(|_| ProtocolViolation::InvalidDescriptor)?;
    let fd_flags =
        rustix::io::fcntl_getfd(descriptor).map_err(|_| ProtocolViolation::InvalidDescriptor)?;
    if !FileType::from_raw_mode(stat.st_mode).is_fifo()
        || filesystem_type != PIPEFS_MAGIC
        || status & OFlags::ACCMODE != OFlags::RDONLY
        || !fd_flags.contains(rustix::io::FdFlags::CLOEXEC)
        || stat.st_size != 0
    {
        return Err(ProtocolViolation::InvalidDescriptor);
    }
    Ok(())
}

pub(crate) fn validate_o_path_directory(
    descriptor: BorrowedFd<'_>,
) -> Result<(), ProtocolViolation> {
    use rustix::fs::{self as rfs, FileType, OFlags};

    let stat = rfs::fstat(descriptor).map_err(|_| ProtocolViolation::InvalidDescriptor)?;
    let status = rfs::fcntl_getfl(descriptor).map_err(|_| ProtocolViolation::InvalidDescriptor)?;
    let fd_flags =
        rustix::io::fcntl_getfd(descriptor).map_err(|_| ProtocolViolation::InvalidDescriptor)?;
    if !FileType::from_raw_mode(stat.st_mode).is_dir()
        || !status.contains(OFlags::PATH)
        || !fd_flags.contains(rustix::io::FdFlags::CLOEXEC)
    {
        return Err(ProtocolViolation::InvalidDescriptor);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rescue_vault_transport::{
        ClientRequest, ClientRequestPayload, encode_client_request,
    };
    use rustix::{
        fs::{CWD, Mode, OFlags},
        pipe::{PipeFlags, pipe_with},
    };
    use std::{
        os::fd::AsFd,
        time::{Duration, Instant},
    };

    const REQUEST_ID: &str = "R-12345678-1234-1234-1234-123456789abc";
    const DEVICE_ID: &str = "KA-0123456789abcdef01234567";

    fn allowlist() -> PeerAllowlist {
        PeerAllowlist::new(1000, 1001).expect("valid test allowlist")
    }

    fn peer(uid: u32) -> PeerIdentity {
        PeerIdentity {
            pid: 4242,
            uid,
            role: allowlist().role_for(uid).expect("allowed test UID"),
            connection_identity: SeqpacketSocketIdentity {
                device: 7,
                inode: 11,
            },
            connection_token: Arc::new(()),
        }
    }

    fn decode_request(
        datagram: &[u8],
        peer: PeerIdentity,
        descriptors: Vec<OwnedFd>,
    ) -> Result<ValidatedRequest, ProtocolViolation> {
        super::decode_request(datagram, peer, descriptors).map_err(|error| error.violation())
    }

    fn request(operation: &str, payload: &str) -> Vec<u8> {
        format!(
            "{{\"apiVersion\":\"{API_VERSION}\",\"requestId\":\"{REQUEST_ID}\",\"expectedStateVersion\":7,\"operation\":\"{operation}\",\"payload\":{payload}}}"
        )
        .into_bytes()
    }

    fn read_pipe() -> OwnedFd {
        let (read, _write) = pipe_with(PipeFlags::CLOEXEC).expect("pipe");
        read
    }

    fn named_fifo() -> (tempfile::TempDir, OwnedFd) {
        let directory = tempfile::tempdir().expect("temporary FIFO directory");
        let path = directory.path().join("named-fifo");
        rustix::fs::mkfifoat(CWD, &path, Mode::RUSR | Mode::WUSR).expect("create named FIFO");
        let descriptor = rustix::fs::open(
            &path,
            OFlags::RDONLY | OFlags::NONBLOCK | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .expect("open named FIFO");
        (directory, descriptor)
    }

    fn vault_status(state: VaultState) -> VaultStatusPayload {
        let device_id = (state == VaultState::Unlocked).then_some(DEVICE_ID);
        VaultStatusPayload::new(state, device_id).expect("valid test vault status")
    }

    #[test]
    fn peer_role_is_minted_from_seqpacket_so_peercred() {
        use rustix::net::{AddressFamily, SocketFlags, SocketType, socketpair};

        let (first, second) = socketpair(
            AddressFamily::UNIX,
            SocketType::SEQPACKET,
            SocketFlags::CLOEXEC,
            None,
        )
        .expect("seqpacket pair");
        let credentials = rustix::net::sockopt::socket_peercred(&first).expect("peer credentials");
        let pid = credentials.pid.as_raw_nonzero().get() as u32;
        let uid = credentials.uid.as_raw();
        if uid == 0 {
            // The production allowlist intentionally cannot authorize root as
            // either unprivileged role.
            assert_eq!(
                PeerAllowlist::new(uid, 1).err(),
                Some(ProtocolViolation::InvalidAllowlist)
            );
            return;
        }
        let other = if uid == 1 { 2 } else { 1 };
        let authenticated = authenticate_seqpacket_peer(
            second.as_fd(),
            PeerAllowlist::new(uid, other).expect("allowlist"),
        )
        .expect("authenticated peer");
        assert_eq!(authenticated.pid(), pid);
        assert_eq!(authenticated.uid(), uid);
        assert_eq!(authenticated.role(), PeerRole::Companion);
        let debug = format!("{authenticated:?}");
        assert!(!debug.contains("socket"));
        assert!(!debug.contains("identity"));
        assert!(!debug.contains("token"));

        let (stream, _peer) = socketpair(
            AddressFamily::UNIX,
            SocketType::STREAM,
            SocketFlags::CLOEXEC,
            None,
        )
        .expect("stream pair");
        assert_eq!(
            authenticate_seqpacket_peer(
                stream.as_fd(),
                PeerAllowlist::new(uid, other).expect("allowlist"),
            )
            .err(),
            Some(ProtocolViolation::InvalidTransport)
        );
    }

    #[test]
    fn authenticated_peer_binds_records_and_responses_to_one_capability() {
        use rustix::net::{AddressFamily, SocketFlags, SocketType, socketpair};

        let (client_a, server_a) = socketpair(
            AddressFamily::UNIX,
            SocketType::SEQPACKET,
            SocketFlags::CLOEXEC,
            None,
        )
        .expect("first seqpacket pair");
        let (client_b, server_b) = socketpair(
            AddressFamily::UNIX,
            SocketType::SEQPACKET,
            SocketFlags::CLOEXEC,
            None,
        )
        .expect("second seqpacket pair");
        let uid = rustix::net::sockopt::socket_peercred(&server_a)
            .expect("peer credentials")
            .uid
            .as_raw();
        if uid == 0 {
            return;
        }
        let other = if uid == 1 { 2 } else { 1 };
        let allowlist = PeerAllowlist::new(uid, other).expect("allowlist");
        let peer_a = authenticate_seqpacket_peer(server_a.as_fd(), allowlist)
            .expect("authenticate first peer");
        let peer_a_reauthenticated = authenticate_seqpacket_peer(server_a.as_fd(), allowlist)
            .expect("reauthenticate first peer");
        let peer_b = authenticate_seqpacket_peer(server_b.as_fd(), allowlist)
            .expect("authenticate second peer");

        let request_bytes = request("vault.status", "{}");
        crate::rescue_vault_transport::send_seqpacket(
            client_a.as_fd(),
            &request_bytes,
            &[],
            Instant::now() + Duration::from_secs(2),
        )
        .expect("send first request");
        let request_a = peer_a
            .receive_request(Instant::now() + Duration::from_secs(2))
            .expect("receive first request");
        let response = SuccessPayload::VaultStatus(vault_status(VaultState::Locked));

        assert_eq!(
            peer_b
                .send_success(
                    &request_a,
                    8,
                    &response,
                    &[],
                    Instant::now() + Duration::from_secs(2),
                )
                .err(),
            Some(ServerSendError::Transport(
                SeqpacketTransportError::InvalidTransport
            ))
        );
        assert_eq!(
            peer_a_reauthenticated
                .send_success(
                    &request_a,
                    8,
                    &response,
                    &[],
                    Instant::now() + Duration::from_secs(2),
                )
                .err(),
            Some(ServerSendError::Transport(
                SeqpacketTransportError::InvalidTransport
            ))
        );

        peer_a
            .send_success(
                &request_a,
                8,
                &response,
                &[],
                Instant::now() + Duration::from_secs(2),
            )
            .expect("send response on originating capability");
        let response_a = crate::rescue_vault_transport::recv_seqpacket(
            client_a.as_fd(),
            Instant::now() + Duration::from_secs(2),
        )
        .expect("receive first response");
        assert!(response_a.bytes().starts_with(b"{"));

        crate::rescue_vault_transport::send_seqpacket(
            client_b.as_fd(),
            &request_bytes,
            &[],
            Instant::now() + Duration::from_secs(2),
        )
        .expect("send second request");
        assert!(matches!(
            peer_a.receive_request(Instant::now() + Duration::from_millis(20)),
            Err(ServerReceiveError::Transport(
                SeqpacketTransportError::TimedOut
            ))
        ));
        assert!(
            peer_b
                .receive_request(Instant::now() + Duration::from_secs(2))
                .is_ok()
        );
    }

    #[test]
    fn authenticated_peer_revalidates_socket_cloexec_before_receive() {
        use rustix::net::{AddressFamily, SocketFlags, SocketType, socketpair};

        let (client, server) = socketpair(
            AddressFamily::UNIX,
            SocketType::SEQPACKET,
            SocketFlags::CLOEXEC,
            None,
        )
        .expect("seqpacket pair");
        let uid = rustix::net::sockopt::socket_peercred(&server)
            .expect("peer credentials")
            .uid
            .as_raw();
        if uid == 0 {
            return;
        }
        let other = if uid == 1 { 2 } else { 1 };
        let peer = authenticate_seqpacket_peer(
            server.as_fd(),
            PeerAllowlist::new(uid, other).expect("allowlist"),
        )
        .expect("authenticate peer");
        crate::rescue_vault_transport::send_seqpacket(
            client.as_fd(),
            &request("vault.status", "{}"),
            &[],
            Instant::now() + Duration::from_secs(2),
        )
        .expect("queue request");

        rustix::io::fcntl_setfd(server.as_fd(), rustix::io::FdFlags::empty())
            .expect("clear socket CLOEXEC");
        let expired = Instant::now()
            .checked_sub(Duration::from_millis(1))
            .expect("expired instant");
        assert!(matches!(
            peer.receive_request(expired),
            Err(ServerReceiveError::Transport(
                SeqpacketTransportError::TimedOut
            ))
        ));
        assert!(matches!(
            peer.receive_request(Instant::now() + Duration::from_secs(2)),
            Err(ServerReceiveError::Transport(
                SeqpacketTransportError::InvalidTransport
            ))
        ));
        rustix::io::fcntl_setfd(server.as_fd(), rustix::io::FdFlags::CLOEXEC)
            .expect("restore socket CLOEXEC");
        let request = peer
            .receive_request(Instant::now() + Duration::from_secs(2))
            .expect("receive after restoring CLOEXEC");
        rustix::io::fcntl_setfd(server.as_fd(), rustix::io::FdFlags::empty())
            .expect("clear socket CLOEXEC before response");
        assert_eq!(
            peer.send_error(&request, 8, ErrorToken::IoFailed, expired)
                .err(),
            Some(ServerSendError::Transport(
                SeqpacketTransportError::TimedOut
            ))
        );
        assert_eq!(
            peer.send_error(
                &request,
                8,
                ErrorToken::IoFailed,
                Instant::now() + Duration::from_secs(2),
            )
            .err(),
            Some(ServerSendError::Transport(
                SeqpacketTransportError::InvalidTransport
            ))
        );
    }

    #[test]
    fn companion_only_allowlist_never_mints_an_agent() {
        let allowlist = PeerAllowlist::companion_only(1000).expect("companion-only allowlist");
        assert_eq!(allowlist.role_for(1000), Ok(PeerRole::Companion));
        assert_eq!(
            allowlist.role_for(1001),
            Err(ProtocolViolation::NotAuthorized)
        );
        assert_eq!(
            PeerAllowlist::companion_only(0),
            Err(ProtocolViolation::InvalidAllowlist)
        );
    }

    #[test]
    fn typed_client_requests_round_trip_through_the_server_decoder() {
        let status = ClientRequest::new(
            RequestId::parse(REQUEST_ID).expect("request ID"),
            7,
            ClientRequestPayload::VaultStatus,
        )
        .expect("status request");
        let status_bytes = encode_client_request(&status, &[]).expect("encode status");
        let decoded = decode_request(&status_bytes, peer(1000), Vec::new())
            .expect("server decodes typed status");
        assert_eq!(decoded.operation(), Operation::VaultStatus);

        let unlock = ClientRequest::new(
            RequestId::parse(REQUEST_ID).expect("request ID"),
            7,
            ClientRequestPayload::VaultUnlock {
                passphrase_size: MIN_PASSPHRASE_BYTES,
            },
        )
        .expect("unlock request");
        let pipe = read_pipe();
        let unlock_bytes = encode_client_request(&unlock, &[pipe.as_fd()]).expect("encode unlock");
        let mut decoded = decode_request(&unlock_bytes, peer(1000), vec![pipe])
            .expect("server decodes typed unlock");
        assert_eq!(decoded.operation(), Operation::VaultUnlock);
        assert!(decoded.take_descriptor().is_some());
    }

    #[test]
    fn status_is_exact_and_descriptor_free() {
        let decoded = decode_request(&request("vault.status", "{}"), peer(1000), Vec::new())
            .expect("status request");
        assert_eq!(decoded.operation(), Operation::VaultStatus);
        assert_eq!(decoded.role(), PeerRole::Companion);
        assert_eq!(decoded.peer_pid(), 4242);
        assert_eq!(decoded.peer_uid(), 1000);
        assert_eq!(decoded.expected_state_version(), 7);

        assert_eq!(
            decode_request(
                &request("vault.status", "{\"device\":\"/dev/sda3\"}"),
                peer(1000),
                Vec::new(),
            )
            .err(),
            Some(ProtocolViolation::InvalidPayload)
        );
        assert_eq!(
            decode_request(
                &request("vault.status", "{}"),
                peer(1000),
                vec![read_pipe()],
            )
            .err(),
            Some(ProtocolViolation::FdForbidden)
        );
    }

    #[test]
    fn vault_status_exposes_device_identity_only_while_unlocked() {
        let request = decode_request(&request("vault.status", "{}"), peer(1000), Vec::new())
            .expect("status request");
        for state in [
            VaultState::Absent,
            VaultState::Unprovisioned,
            VaultState::Locked,
            VaultState::Unlocking,
            VaultState::Locking,
            VaultState::FaultedRebootRequired,
        ] {
            let status = VaultStatusPayload::new(state, None).expect("path-free status");
            let encoded = encode_success(&request, 8, &SuccessPayload::VaultStatus(status), &[])
                .expect("status response");
            assert!(
                !String::from_utf8(encoded)
                    .expect("UTF-8")
                    .contains("deviceId")
            );
        }

        let unlocked = VaultStatusPayload::new(VaultState::Unlocked, Some(DEVICE_ID))
            .expect("unlocked identity");
        assert_eq!(unlocked.device_id(), Some(DEVICE_ID));
        let encoded = encode_success(&request, 8, &SuccessPayload::VaultStatus(unlocked), &[])
            .expect("unlocked response");
        assert!(
            String::from_utf8(encoded)
                .expect("UTF-8")
                .contains(DEVICE_ID)
        );

        assert_eq!(
            VaultStatusPayload::new(VaultState::Unlocked, None).err(),
            Some(ProtocolViolation::InvalidPayload)
        );
        assert_eq!(
            VaultStatusPayload::new(VaultState::Locked, Some(DEVICE_ID)).err(),
            Some(ProtocolViolation::InvalidPayload)
        );
        assert_eq!(
            VaultStatusPayload::new(VaultState::Unlocked, Some("KA-invalid")).err(),
            Some(ProtocolViolation::InvalidPayload)
        );

        assert_eq!(
            gate_operation_for_vault_state(
                VaultState::FaultedRebootRequired,
                Operation::VaultStatus,
            ),
            Ok(())
        );
        assert_eq!(
            gate_operation_for_vault_state(
                VaultState::FaultedRebootRequired,
                Operation::VaultUnlock,
            ),
            Err(ErrorToken::RebootRequired)
        );
        assert_eq!(
            gate_operation_for_vault_state(VaultState::Unlocking, Operation::ReportGet),
            Err(ErrorToken::Busy)
        );
    }

    #[test]
    fn decode_rejections_retain_only_validated_correlation_context() {
        let malformed =
            super::decode_request(b"{}", peer(1000), Vec::new()).expect_err("close-only");
        assert!(matches!(malformed, RequestDecodeError::Close(_)));

        let unauthorized = super::decode_request(
            &request(
                "vault.unlock",
                "{\"input\":{\"type\":\"passphrase-pipe\",\"size\":12}}",
            ),
            peer(1001),
            vec![read_pipe()],
        )
        .expect_err("role rejection");
        let context = match unauthorized {
            RequestDecodeError::Reject(context) => Some(context),
            RequestDecodeError::Close(_) => None,
        }
        .expect("authorization rejection context");
        assert_eq!(context.request_id().as_str(), REQUEST_ID);
        assert_eq!(context.operation(), Operation::VaultUnlock);
        assert_eq!(context.violation(), ProtocolViolation::NotAuthorized);
        assert_eq!(context.error(), ErrorToken::NotAuthorized);
        let debug = format!("{context:?}");
        assert!(!debug.contains("identity"));
        assert!(!debug.contains("token"));
        let response = encode_rejection(&context, 8).expect("correlated rejection");
        let response = String::from_utf8(response).expect("UTF-8 rejection");
        assert!(response.contains(REQUEST_ID));
        assert!(response.contains("NOT_AUTHORIZED"));

        let missing_fd = super::decode_request(
            &request(
                "vault.unlock",
                "{\"input\":{\"type\":\"passphrase-pipe\",\"size\":12}}",
            ),
            peer(1000),
            Vec::new(),
        )
        .expect_err("descriptor rejection");
        let context = match missing_fd {
            RequestDecodeError::Reject(context) => Some(context),
            RequestDecodeError::Close(_) => None,
        }
        .expect("descriptor rejection context");
        assert_eq!(context.error(), ErrorToken::FdRequired);
        assert!(encode_rejection(&context, 8).is_ok());

        let forbidden_fd = super::decode_request(
            &request("vault.status", "{}"),
            peer(1000),
            vec![read_pipe()],
        )
        .expect_err("forbidden descriptor rejection");
        let context = match forbidden_fd {
            RequestDecodeError::Reject(context) => Some(context),
            RequestDecodeError::Close(_) => None,
        }
        .expect("forbidden descriptor context");
        assert_eq!(context.error(), ErrorToken::FdForbidden);
        let response = encode_rejection(&context, 8).expect("FD_FORBIDDEN rejection");
        assert!(
            String::from_utf8(response)
                .expect("UTF-8 rejection")
                .contains("FD_FORBIDDEN")
        );
    }

    #[test]
    fn duplicate_unknown_and_secret_json_fields_are_rejected() {
        let duplicate = format!(
            "{{\"apiVersion\":\"{API_VERSION}\",\"requestId\":\"{REQUEST_ID}\",\"expectedStateVersion\":1,\"expectedStateVersion\":2,\"operation\":\"vault.status\",\"payload\":{{}}}}"
        );
        assert_eq!(
            decode_request(duplicate.as_bytes(), peer(1000), Vec::new()).err(),
            Some(ProtocolViolation::InvalidJson)
        );
        let secret = request(
            "vault.unlock",
            "{\"input\":{\"type\":\"passphrase-pipe\",\"size\":12},\"passphrase\":\"forbidden\"}",
        );
        assert_eq!(
            decode_request(&secret, peer(1000), vec![read_pipe()]).err(),
            Some(ProtocolViolation::InvalidPayload)
        );

        let duplicate_payload = request(
            "vault.unlock",
            "{\"input\":{\"type\":\"passphrase-pipe\",\"size\":12,\"size\":13}}",
        );
        assert_eq!(
            decode_request(&duplicate_payload, peer(1000), vec![read_pipe()]).err(),
            Some(ProtocolViolation::InvalidPayload)
        );

        let mut maximum = request("vault.status", "{}");
        maximum.resize(MAX_DATAGRAM_BYTES, b' ');
        assert!(decode_request(&maximum, peer(1000), Vec::new()).is_ok());
        maximum.push(b' ');
        assert_eq!(
            decode_request(&maximum, peer(1000), Vec::new()).err(),
            Some(ProtocolViolation::DatagramTooLarge)
        );

        let mut trailing_json = request("vault.status", "{}");
        trailing_json.extend_from_slice(b"{}");
        assert_eq!(
            decode_request(&trailing_json, peer(1000), Vec::new()).err(),
            Some(ProtocolViolation::InvalidJson)
        );
    }

    #[test]
    fn roles_and_input_pipe_contracts_are_closed() {
        let unlock = request(
            "vault.unlock",
            "{\"input\":{\"type\":\"passphrase-pipe\",\"size\":12}}",
        );
        assert!(decode_request(&unlock, peer(1000), vec![read_pipe()]).is_ok());
        assert_eq!(
            decode_request(&unlock, peer(1001), vec![read_pipe()]).err(),
            Some(ProtocolViolation::NotAuthorized)
        );
        assert_eq!(
            decode_request(&unlock, peer(1000), Vec::new()).err(),
            Some(ProtocolViolation::FdRequired)
        );
        let too_short = request(
            "vault.unlock",
            "{\"input\":{\"type\":\"passphrase-pipe\",\"size\":11}}",
        );
        assert_eq!(
            decode_request(&too_short, peer(1000), vec![read_pipe()]).err(),
            Some(ProtocolViolation::InvalidPayload)
        );
        assert_eq!(
            allowlist().role_for(9999).err(),
            Some(ProtocolViolation::NotAuthorized)
        );

        let ordinary =
            rustix::fs::open("/dev/null", OFlags::RDONLY | OFlags::CLOEXEC, Mode::empty())
                .expect("open /dev/null");
        assert_eq!(
            decode_request(&unlock, peer(1000), vec![ordinary]).err(),
            Some(ProtocolViolation::InvalidDescriptor)
        );

        let (_read, write) = pipe_with(PipeFlags::CLOEXEC).expect("pipe");
        assert_eq!(
            decode_request(&unlock, peer(1000), vec![write]).err(),
            Some(ProtocolViolation::InvalidDescriptor)
        );

        let without_cloexec = read_pipe();
        let mut flags = rustix::io::fcntl_getfd(&without_cloexec).expect("descriptor flags");
        flags.remove(rustix::io::FdFlags::CLOEXEC);
        rustix::io::fcntl_setfd(&without_cloexec, flags).expect("clear CLOEXEC");
        assert_eq!(
            decode_request(&unlock, peer(1000), vec![without_cloexec]).err(),
            Some(ProtocolViolation::InvalidDescriptor)
        );
    }

    #[test]
    fn named_fifos_are_rejected_for_every_secret_and_report_input() {
        let report_payload = format!(
            "{{\"reportId\":\"RP-12345678-1234-1234-1234-123456789abc\",\"payloadSha256\":\"{}\",\"input\":{{\"type\":\"session-report-json-pipe\",\"size\":512}}}}",
            "a".repeat(64)
        );
        let cases = [
            (
                "vault.unlock",
                "{\"input\":{\"type\":\"passphrase-pipe\",\"size\":12}}".to_owned(),
                1000,
            ),
            (
                "provider.openai.configure",
                "{\"input\":{\"type\":\"openai-api-key-pipe\",\"size\":64}}".to_owned(),
                1000,
            ),
            ("report.persist", report_payload, 1001),
        ];
        for (operation, payload, uid) in cases {
            let (_directory, fifo) = named_fifo();
            assert_eq!(
                decode_request(&request(operation, &payload), peer(uid), vec![fifo]).err(),
                Some(ProtocolViolation::InvalidDescriptor),
                "named FIFO accepted for {operation}"
            );
        }
    }

    #[test]
    fn every_operation_has_a_strict_role_and_payload() {
        let cases = [
            ("vault.lock", "{}", 1000),
            ("provider.status", "{}", 1001),
            ("provider.logout", "{\"provider\":\"openai\"}", 1000),
            ("provider.openai.borrow", "{}", 1001),
            ("provider.codex.home_lease", "{}", 1001),
            (
                "audit.append",
                "{\"sequence\":1,\"event\":\"agent-session-start\",\"outcome\":\"failed\",\"error\":\"IO_FAILED\"}",
                1001,
            ),
            ("report.list", "{}", 1000),
            (
                "report.get",
                "{\"reportId\":\"RP-12345678-1234-1234-1234-123456789abc\"}",
                1001,
            ),
        ];
        for (operation, payload, uid) in cases {
            let decoded = decode_request(&request(operation, payload), peer(uid), Vec::new());
            assert!(decoded.is_ok(), "operation contract failed: {operation}");
        }
        assert_eq!(
            decode_request(
                &request("provider.codex.home_lease", "{}"),
                peer(1000),
                Vec::new(),
            )
            .err(),
            Some(ProtocolViolation::NotAuthorized)
        );

        let configure = request(
            "provider.openai.configure",
            "{\"input\":{\"type\":\"openai-api-key-pipe\",\"size\":64}}",
        );
        assert!(decode_request(&configure, peer(1000), vec![read_pipe()]).is_ok());
        let oversized_key = request(
            "provider.openai.configure",
            "{\"input\":{\"type\":\"openai-api-key-pipe\",\"size\":513}}",
        );
        assert_eq!(
            decode_request(&oversized_key, peer(1000), vec![read_pipe()]).err(),
            Some(ProtocolViolation::InvalidPayload)
        );
        let persist = request(
            "report.persist",
            &format!(
                "{{\"reportId\":\"RP-12345678-1234-1234-1234-123456789abc\",\"payloadSha256\":\"{}\",\"input\":{{\"type\":\"session-report-json-pipe\",\"size\":512}}}}",
                "a".repeat(64)
            ),
        );
        assert!(decode_request(&persist, peer(1001), vec![read_pipe()]).is_ok());

        let oversized_persist = request(
            "report.persist",
            &format!(
                "{{\"reportId\":\"RP-12345678-1234-1234-1234-123456789abc\",\"payloadSha256\":\"{}\",\"input\":{{\"type\":\"session-report-json-pipe\",\"size\":{}}}}}",
                "a".repeat(64),
                MAX_SESSION_REPORT_JSON_BYTES + 1
            ),
        );
        assert_eq!(
            decode_request(&oversized_persist, peer(1001), vec![read_pipe()]).err(),
            Some(ProtocolViolation::InvalidPayload)
        );
    }

    #[test]
    fn every_operation_enforces_the_complete_peer_role_matrix() {
        let report_hash = "a".repeat(64);
        let report_persist = format!(
            "{{\"reportId\":\"RP-12345678-1234-1234-1234-123456789abc\",\"payloadSha256\":\"{report_hash}\",\"input\":{{\"type\":\"session-report-json-pipe\",\"size\":512}}}}"
        );
        let cases = [
            ("vault.status", "{}", false, true, true),
            (
                "vault.unlock",
                "{\"input\":{\"type\":\"passphrase-pipe\",\"size\":12}}",
                true,
                true,
                false,
            ),
            ("vault.lock", "{}", false, true, false),
            (
                "provider.openai.configure",
                "{\"input\":{\"type\":\"openai-api-key-pipe\",\"size\":64}}",
                true,
                true,
                false,
            ),
            ("provider.status", "{}", false, true, true),
            (
                "provider.logout",
                "{\"provider\":\"openai\"}",
                false,
                true,
                false,
            ),
            ("provider.openai.borrow", "{}", false, false, true),
            ("provider.codex.home_lease", "{}", false, false, true),
            (
                "audit.append",
                "{\"sequence\":1,\"event\":\"agent-session-start\",\"outcome\":\"succeeded\"}",
                false,
                false,
                true,
            ),
            ("report.persist", report_persist.as_str(), true, false, true),
            ("report.list", "{}", false, true, true),
            (
                "report.get",
                "{\"reportId\":\"RP-12345678-1234-1234-1234-123456789abc\"}",
                false,
                true,
                true,
            ),
        ];
        for (operation, payload, needs_descriptor, companion, agent) in cases {
            for (uid, allowed) in [(1000, companion), (1001, agent)] {
                let descriptors = needs_descriptor.then(read_pipe).into_iter().collect();
                let result = decode_request(&request(operation, payload), peer(uid), descriptors);
                if allowed {
                    assert!(result.is_ok(), "{operation} rejected UID {uid}");
                } else {
                    assert_eq!(
                        result.err(),
                        Some(ProtocolViolation::NotAuthorized),
                        "{operation} authorized UID {uid}"
                    );
                }
            }
        }
    }

    #[test]
    fn agent_cannot_forge_privileged_audit_events() {
        for privileged_event in [
            "vault-unlock",
            "vault-lock",
            "provider-configure",
            "provider-logout",
            "report-persist",
        ] {
            let payload = format!(
                "{{\"sequence\":1,\"event\":\"{privileged_event}\",\"outcome\":\"succeeded\"}}"
            );
            assert_eq!(
                decode_request(&request("audit.append", &payload), peer(1001), Vec::new(),).err(),
                Some(ProtocolViolation::InvalidPayload)
            );
        }
    }

    #[test]
    fn json_integer_and_journal_sequence_bounds_are_exact() {
        assert_eq!(MAX_AUDIT_SEQUENCE, kernaid_storage::MAX_JOURNAL_ENTRIES);
        assert!(std::hint::black_box(MAX_INITIAL_STATE_VERSION) < MAX_SAFE_JSON_INTEGER);

        let oversized_state = format!(
            "{{\"apiVersion\":\"{API_VERSION}\",\"requestId\":\"{REQUEST_ID}\",\"expectedStateVersion\":{},\"operation\":\"vault.status\",\"payload\":{{}}}}",
            MAX_SAFE_JSON_INTEGER + 1
        );
        assert_eq!(
            decode_request(oversized_state.as_bytes(), peer(1000), Vec::new()).err(),
            Some(ProtocolViolation::InvalidPayload)
        );

        let maximum_audit = format!(
            "{{\"sequence\":{MAX_AUDIT_SEQUENCE},\"event\":\"agent-session-end\",\"outcome\":\"succeeded\"}}"
        );
        assert!(
            decode_request(
                &request("audit.append", &maximum_audit),
                peer(1001),
                Vec::new(),
            )
            .is_ok()
        );
        let oversized_audit = format!(
            "{{\"sequence\":{},\"event\":\"agent-session-end\",\"outcome\":\"succeeded\"}}",
            MAX_AUDIT_SEQUENCE + 1
        );
        assert_eq!(
            decode_request(
                &request("audit.append", &oversized_audit),
                peer(1001),
                Vec::new(),
            )
            .err(),
            Some(ProtocolViolation::InvalidPayload)
        );

        let status_request = decode_request(&request("vault.status", "{}"), peer(1000), Vec::new())
            .expect("status request");
        assert_eq!(
            encode_success(
                &status_request,
                MAX_SAFE_JSON_INTEGER + 1,
                &SuccessPayload::VaultStatus(vault_status(VaultState::Locked)),
                &[],
            )
            .err(),
            Some(ProtocolViolation::InvalidPayload)
        );
        assert_eq!(
            encode_error(
                &status_request,
                MAX_SAFE_JSON_INTEGER + 1,
                ErrorToken::Busy,
                &[],
            )
            .err(),
            Some(ProtocolViolation::InvalidPayload)
        );
    }

    #[test]
    fn openai_key_bytes_match_shipping_visible_ascii_policy() {
        assert_eq!(validate_openai_api_key_bytes(b"x"), Ok(()));
        assert_eq!(
            validate_openai_api_key_bytes(&vec![b'x'; MAX_OPENAI_KEY_BYTES as usize]),
            Ok(())
        );
        for invalid in [b"".as_slice(), b"contains space", b"line\nfeed", b"\x7f"] {
            assert_eq!(
                validate_openai_api_key_bytes(invalid),
                Err(ProtocolViolation::InvalidPayload)
            );
        }
        assert_eq!(
            validate_openai_api_key_bytes(&vec![b'x'; MAX_OPENAI_KEY_BYTES as usize + 1]),
            Err(ProtocolViolation::InvalidPayload)
        );
    }

    #[test]
    fn passphrase_post_read_requires_exact_size_eof_and_no_nul() {
        let exact = b"abcdefghijkl";
        assert_eq!(
            validate_passphrase_read(exact, MIN_PASSPHRASE_BYTES, true),
            Ok(())
        );
        assert_eq!(
            validate_passphrase_read(b"abcdefghijk", 11, true),
            Err(ProtocolViolation::InvalidPayload)
        );
        assert_eq!(
            validate_passphrase_read(b"abcde\0ghijkl", MIN_PASSPHRASE_BYTES, true),
            Err(ProtocolViolation::InvalidPayload)
        );
        assert_eq!(
            validate_passphrase_read(b"abcdefghijklm", MIN_PASSPHRASE_BYTES, true),
            Err(ProtocolViolation::InvalidPayload)
        );
        assert_eq!(
            validate_passphrase_read(exact, MIN_PASSPHRASE_BYTES, false),
            Err(ProtocolViolation::InvalidPayload)
        );
    }

    #[test]
    fn success_encoder_checks_operation_and_output_descriptor_shape() {
        let request = decode_request(
            &request("provider.openai.borrow", "{}"),
            peer(1001),
            Vec::new(),
        )
        .expect("borrow request");
        let pipe = read_pipe();
        let payload = SuccessPayload::Descriptor(DescriptorDeclaration {
            kind: DescriptorType::OpenAiApiKeyPipe,
            size: 64,
        });
        let encoded =
            encode_success(&request, 8, &payload, &[pipe.as_fd()]).expect("valid borrow response");
        let text = String::from_utf8(encoded).expect("JSON is UTF-8");
        assert!(!text.contains("/dev/") && !text.contains("secret"));
        let wrong_payload = SuccessPayload::VaultStatus(vault_status(VaultState::Locked));
        assert_eq!(
            encode_success(&request, 8, &wrong_payload, &[]).err(),
            Some(ProtocolViolation::InvalidPayload)
        );
        assert_eq!(
            encode_error(&request, 8, ErrorToken::Locked, &[pipe.as_fd()]).err(),
            Some(ProtocolViolation::FdForbidden)
        );
        assert!(encode_error(&request, 8, ErrorToken::ProviderUnconfigured, &[],).is_ok());
        let (_directory, fifo) = named_fifo();
        assert_eq!(
            encode_success(&request, 8, &payload, &[fifo.as_fd()]).err(),
            Some(ProtocolViolation::InvalidDescriptor)
        );
        let (_read, write) = pipe_with(PipeFlags::CLOEXEC).expect("pipe");
        assert_eq!(
            encode_success(&request, 8, &payload, &[write.as_fd()]).err(),
            Some(ProtocolViolation::InvalidDescriptor)
        );
    }

    #[test]
    fn report_payload_and_signed_envelope_contracts_are_directional() {
        assert_eq!(
            MAX_SESSION_REPORT_JSON_BYTES,
            kernaid_device_identity::MAX_SIGNED_REPORT_PAYLOAD_BYTES as u64
        );
        let identity = kernaid_device_identity::DeviceIdentity::from_seed(&[7_u8; 32])
            .expect("fixed test identity");
        let maximum_payload = vec![b'x'; MAX_SESSION_REPORT_JSON_BYTES as usize];
        let envelope = identity
            .sign_report_envelope(&maximum_payload, SESSION_REPORT_MEDIA_TYPE, 1, &[9_u8; 32])
            .expect("maximum payload envelope");
        let serialized = serde_json::to_vec(&envelope).expect("serialize signed envelope");
        assert!(serialized.len() as u64 > MAX_SESSION_REPORT_JSON_BYTES);
        assert!(serialized.len() as u64 <= MAX_SIGNED_REPORT_ENVELOPE_BYTES);

        let payload_hash = "a".repeat(64);
        let persist_body = format!(
            "{{\"reportId\":\"RP-12345678-1234-1234-1234-123456789abc\",\"payloadSha256\":\"{payload_hash}\",\"input\":{{\"type\":\"session-report-json-pipe\",\"size\":{MAX_SESSION_REPORT_JSON_BYTES}}}}}"
        );
        let mut persist = decode_request(
            &request("report.persist", &persist_body),
            peer(1001),
            vec![read_pipe()],
        )
        .expect("raw report payload request");
        drop(persist.take_descriptor());

        let wrong_input =
            persist_body.replace("session-report-json-pipe", "signed-report-envelope-pipe");
        assert_eq!(
            decode_request(
                &request("report.persist", &wrong_input),
                peer(1001),
                vec![read_pipe()],
            )
            .err(),
            Some(ProtocolViolation::InvalidPayload)
        );

        let report_id =
            ReportId::parse("RP-12345678-1234-1234-1234-123456789abc").expect("report ID");
        let envelope_hash = Sha256::parse(&"b".repeat(64)).expect("envelope hash");
        let summary = ReportSummary::new(
            report_id.clone(),
            serialized.len() as u64,
            envelope_hash.clone(),
        )
        .expect("envelope summary");
        let stored = encode_success(
            &persist,
            8,
            &SuccessPayload::ReportStored(summary.clone()),
            &[],
        )
        .expect("persisted signed envelope metadata");
        let stored = String::from_utf8(stored).expect("response UTF-8");
        assert!(stored.contains("envelopeSize") && stored.contains("envelopeSha256"));
        assert!(!stored.contains("payloadSha256"));

        let get = decode_request(
            &request(
                "report.get",
                "{\"reportId\":\"RP-12345678-1234-1234-1234-123456789abc\"}",
            ),
            peer(1001),
            Vec::new(),
        )
        .expect("report get request");
        let output = DescriptorDeclaration {
            kind: DescriptorType::SignedReportEnvelopePipe,
            size: summary.envelope_size(),
        };
        let pipe = read_pipe();
        assert!(
            encode_success(
                &get,
                8,
                &SuccessPayload::Report(summary.clone(), output),
                &[pipe.as_fd()],
            )
            .is_ok()
        );
        let (_directory, fifo) = named_fifo();
        let named_fifo_output = DescriptorDeclaration {
            kind: DescriptorType::SignedReportEnvelopePipe,
            size: summary.envelope_size(),
        };
        assert_eq!(
            encode_success(
                &get,
                8,
                &SuccessPayload::Report(summary.clone(), named_fifo_output),
                &[fifo.as_fd()],
            )
            .err(),
            Some(ProtocolViolation::InvalidDescriptor)
        );
        let wrong_output = DescriptorDeclaration {
            kind: DescriptorType::SessionReportJsonPipe,
            size: summary.envelope_size(),
        };
        assert_eq!(
            encode_success(
                &get,
                8,
                &SuccessPayload::Report(summary, wrong_output),
                &[pipe.as_fd()],
            )
            .err(),
            Some(ProtocolViolation::InvalidPayload)
        );
        assert_eq!(
            ReportSummary::new(
                report_id,
                MAX_SIGNED_REPORT_ENVELOPE_BYTES + 1,
                envelope_hash,
            )
            .err(),
            Some(ProtocolViolation::InvalidPayload)
        );
    }

    #[test]
    fn persisted_report_summary_components_reconstruct_fail_closed() {
        let report_id = "RP-12345678-1234-1234-1234-123456789abc";
        let hash = "b".repeat(64);
        let reconstructed_id = ReportId::parse(report_id).expect("persisted report ID");
        let reconstructed_hash = Sha256::parse(&hash).expect("persisted envelope hash");
        let summary = ReportSummary::new(reconstructed_id, 512, reconstructed_hash)
            .expect("reconstructed report summary");
        assert_eq!(summary.report_id().as_str(), report_id);
        assert_eq!(summary.envelope_sha256().as_str(), hash);

        for invalid in [
            "R-12345678-1234-1234-1234-123456789abc",
            "RP-12345678-1234-1234-1234-123456789abC",
            "RP-12345678-1234-1234-1234-123456789abc0",
        ] {
            assert_eq!(
                ReportId::parse(invalid).err(),
                Some(ProtocolViolation::InvalidPayload)
            );
        }
        for invalid in ["b".repeat(63), "B".repeat(64), "g".repeat(64)] {
            assert_eq!(
                Sha256::parse(&invalid).err(),
                Some(ProtocolViolation::InvalidPayload)
            );
        }
    }

    #[test]
    fn state_changing_success_must_match_the_requested_transition() {
        let mut unlock = decode_request(
            &request(
                "vault.unlock",
                "{\"input\":{\"type\":\"passphrase-pipe\",\"size\":12}}",
            ),
            peer(1000),
            vec![read_pipe()],
        )
        .expect("unlock request");
        drop(unlock.take_descriptor());
        let unlocked = SuccessPayload::VaultStatus(vault_status(VaultState::Unlocked));
        assert!(encode_success(&unlock, 8, &unlocked, &[]).is_ok());
        let locked = SuccessPayload::VaultStatus(vault_status(VaultState::Locked));
        assert_eq!(
            encode_success(&unlock, 8, &locked, &[]).err(),
            Some(ProtocolViolation::InvalidPayload)
        );

        let mut configure = decode_request(
            &request(
                "provider.openai.configure",
                "{\"input\":{\"type\":\"openai-api-key-pipe\",\"size\":64}}",
            ),
            peer(1000),
            vec![read_pipe()],
        )
        .expect("configure request");
        drop(configure.take_descriptor());
        let configured = SuccessPayload::ProviderStatus(ProviderStatusPayload {
            openai: ProviderState::Configured,
            codex: ProviderState::Unconfigured,
        });
        assert!(encode_success(&configure, 8, &configured, &[]).is_ok());
        let unconfigured = SuccessPayload::ProviderStatus(ProviderStatusPayload {
            openai: ProviderState::Unconfigured,
            codex: ProviderState::Unconfigured,
        });
        assert_eq!(
            encode_success(&configure, 8, &unconfigured, &[]).err(),
            Some(ProtocolViolation::InvalidPayload)
        );
    }

    #[test]
    fn codex_home_response_requires_an_o_path_directory() {
        let request = decode_request(
            &request("provider.codex.home_lease", "{}"),
            peer(1001),
            Vec::new(),
        )
        .expect("home lease request");
        let payload = SuccessPayload::Descriptor(DescriptorDeclaration {
            kind: DescriptorType::CodexHomeOPath,
            size: 0,
        });
        let lease = rustix::fs::open(
            "/",
            OFlags::PATH | OFlags::DIRECTORY | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .expect("O_PATH directory");
        assert!(encode_success(&request, 8, &payload, &[lease.as_fd()]).is_ok());

        let ordinary = rustix::fs::open(
            "/",
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .expect("ordinary directory");
        assert_eq!(
            encode_success(&request, 8, &payload, &[ordinary.as_fd()]).err(),
            Some(ProtocolViolation::InvalidDescriptor)
        );
    }
}
