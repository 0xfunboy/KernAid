//! Closed local IPC contract for the Rescue vault service.
//!
//! The transport is AF_UNIX `SOCK_SEQPACKET`. One packet contains exactly one
//! UTF-8 JSON document and at most two `SCM_RIGHTS` descriptors. Peer identity
//! is always taken from `SO_PEERCRED`; a PID or UID in JSON would be attacker
//! input and is therefore not part of the wire format.

#[cfg(feature = "experimental-repair-store")]
use crate::rescue_repair_vault::{
    MAX_REPAIR_BACKUP_BYTES, RepairBackupBinding, RepairBackupDraft, RepairBackupReleasePayload,
    RepairBackupState, RepairBackupStatusPayload, RepairExecutionIntentV1, RepairFileMetadataV1,
    RepairReservationId, RepairTransactionResolution, RepairTransactionStatusPayload,
    RepairTransactionStatusResultPayload, RepairTransactionStatusSelector,
    RepairVaultLiveIdentityPayload,
};
use crate::rescue_vault_transport::{
    SeqpacketSocketIdentity, SeqpacketTransportError, ensure_deadline, recv_seqpacket,
    send_seqpacket, validate_bound_seqpacket_socket, validate_seqpacket_socket,
};
use serde::{Deserialize, Serialize};
use serde_json::value::RawValue;
use std::{
    fmt,
    os::fd::{AsFd, AsRawFd, BorrowedFd, OwnedFd},
    path::PathBuf,
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
const NSFS_MAGIC: u64 = 0x6e73_6673;

/// The unprivileged identities allowed to connect to the service.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct PeerAllowlist {
    companion_uid: u32,
    application_uid: Option<u32>,
    openai_uid: Option<u32>,
    codex_uid: Option<u32>,
    #[cfg(feature = "experimental-repair-store")]
    repair_broker_uid: Option<u32>,
}

impl fmt::Debug for PeerAllowlist {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut debug = formatter.debug_struct("PeerAllowlist");
        debug
            .field("companion_configured", &(self.companion_uid != 0))
            .field("application_configured", &self.application_uid.is_some())
            .field("openai_configured", &self.openai_uid.is_some())
            .field("codex_configured", &self.codex_uid.is_some());
        #[cfg(feature = "experimental-repair-store")]
        debug.field(
            "repair_broker_configured",
            &self.repair_broker_uid.is_some(),
        );
        debug.finish()
    }
}

impl PeerAllowlist {
    /// Starts a fail-closed allowlist builder. No peer can be authenticated
    /// until [`PeerAllowlistBuilder::build`] validates the complete mapping.
    #[must_use]
    pub fn builder(companion_uid: u32) -> PeerAllowlistBuilder {
        PeerAllowlistBuilder {
            companion_uid,
            application_uid: None,
            openai_uid: None,
            codex_uid: None,
            #[cfg(feature = "experimental-repair-store")]
            repair_broker_uid: None,
        }
    }

    /// Constructs the lifecycle-only allowlist used before any Agent service
    /// exists. No UID can be authenticated as [`PeerRole::Agent`].
    pub fn companion_only(companion_uid: u32) -> Result<Self, ProtocolViolation> {
        Self::builder(companion_uid).build()
    }

    fn role_for(self, peer_uid: u32) -> Result<PeerRole, ProtocolViolation> {
        if peer_uid == self.companion_uid {
            Ok(PeerRole::Companion)
        } else if self.application_uid == Some(peer_uid) {
            Ok(PeerRole::Agent(AgentRole::Application))
        } else if self.openai_uid == Some(peer_uid) {
            Ok(PeerRole::Agent(AgentRole::OpenAi))
        } else if self.codex_uid == Some(peer_uid) {
            Ok(PeerRole::Agent(AgentRole::Codex))
        } else if cfg!(feature = "experimental-repair-store")
            && self.repair_broker_uid() == Some(peer_uid)
        {
            #[cfg(feature = "experimental-repair-store")]
            {
                Ok(PeerRole::RepairBroker)
            }
            #[cfg(not(feature = "experimental-repair-store"))]
            unreachable!()
        } else {
            Err(ProtocolViolation::NotAuthorized)
        }
    }
}

/// Builder for the kernel-UID-to-role mapping.
///
/// Agent identities are optional, but every configured UID is non-root and
/// distinct, and each UID and Agent role can occur at most once.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct PeerAllowlistBuilder {
    companion_uid: u32,
    application_uid: Option<u32>,
    openai_uid: Option<u32>,
    codex_uid: Option<u32>,
    #[cfg(feature = "experimental-repair-store")]
    repair_broker_uid: Option<u32>,
}

impl fmt::Debug for PeerAllowlistBuilder {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut debug = formatter.debug_struct("PeerAllowlistBuilder");
        debug
            .field("companion_configured", &(self.companion_uid != 0))
            .field("application_configured", &self.application_uid.is_some())
            .field("openai_configured", &self.openai_uid.is_some())
            .field("codex_configured", &self.codex_uid.is_some());
        #[cfg(feature = "experimental-repair-store")]
        debug.field(
            "repair_broker_configured",
            &self.repair_broker_uid.is_some(),
        );
        debug.finish()
    }
}

impl PeerAllowlistBuilder {
    /// Adds exactly one UID mapping for `role`.
    pub fn agent(mut self, role: AgentRole, uid: u32) -> Result<Self, ProtocolViolation> {
        if uid == 0
            || uid == self.companion_uid
            || self.application_uid == Some(uid)
            || self.openai_uid == Some(uid)
            || self.codex_uid == Some(uid)
            || self.repair_broker_uid() == Some(uid)
            || self.uid_for(role).is_some()
        {
            return Err(ProtocolViolation::InvalidAllowlist);
        }
        *self.uid_for_mut(role) = Some(uid);
        Ok(self)
    }

    /// Adds the sole UID permitted to call the experimental repair store.
    /// Root is rejected: a privileged process must cross into the dedicated
    /// `kernaid-repair` identity before using this shared Vault socket.
    #[cfg(feature = "experimental-repair-store")]
    pub fn repair_broker(mut self, uid: u32) -> Result<Self, ProtocolViolation> {
        if uid == 0
            || uid == self.companion_uid
            || self.application_uid == Some(uid)
            || self.openai_uid == Some(uid)
            || self.codex_uid == Some(uid)
            || self.repair_broker_uid.is_some()
        {
            return Err(ProtocolViolation::InvalidAllowlist);
        }
        self.repair_broker_uid = Some(uid);
        Ok(self)
    }

    /// Validates and seals the complete mapping.
    pub fn build(self) -> Result<PeerAllowlist, ProtocolViolation> {
        let configured = [
            self.application_uid,
            self.openai_uid,
            self.codex_uid,
            self.repair_broker_uid(),
        ];
        if self.companion_uid == 0
            || configured
                .iter()
                .flatten()
                .any(|uid| *uid == 0 || *uid == self.companion_uid)
            || configured.iter().flatten().enumerate().any(|(index, uid)| {
                configured
                    .iter()
                    .flatten()
                    .skip(index + 1)
                    .any(|other| other == uid)
            })
        {
            return Err(ProtocolViolation::InvalidAllowlist);
        }
        Ok(PeerAllowlist {
            companion_uid: self.companion_uid,
            application_uid: self.application_uid,
            openai_uid: self.openai_uid,
            codex_uid: self.codex_uid,
            #[cfg(feature = "experimental-repair-store")]
            repair_broker_uid: self.repair_broker_uid,
        })
    }

    fn uid_for(self, role: AgentRole) -> Option<u32> {
        match role {
            AgentRole::Application => self.application_uid,
            AgentRole::OpenAi => self.openai_uid,
            AgentRole::Codex => self.codex_uid,
        }
    }

    fn uid_for_mut(&mut self, role: AgentRole) -> &mut Option<u32> {
        match role {
            AgentRole::Application => &mut self.application_uid,
            AgentRole::OpenAi => &mut self.openai_uid,
            AgentRole::Codex => &mut self.codex_uid,
        }
    }

    fn repair_broker_uid(&self) -> Option<u32> {
        #[cfg(feature = "experimental-repair-store")]
        {
            self.repair_broker_uid
        }
        #[cfg(not(feature = "experimental-repair-store"))]
        {
            None
        }
    }
}

impl PeerAllowlist {
    fn repair_broker_uid(&self) -> Option<u32> {
        #[cfg(feature = "experimental-repair-store")]
        {
            self.repair_broker_uid
        }
        #[cfg(not(feature = "experimental-repair-store"))]
        {
            None
        }
    }
}

/// Purpose-specific Agent identity derived exclusively from its allowlisted
/// kernel UID.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AgentRole {
    Application,
    OpenAi,
    Codex,
}

/// Role derived exclusively from a kernel-authenticated peer UID.
///
/// Agent purpose is part of this server-side capability rather than the wire
/// envelope. The shipping Rescue daemon constructs only an OpenAI Agent role
/// and further restricts it to status plus one leased OpenAI credential borrow
/// operation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PeerRole {
    Companion,
    Agent(AgentRole),
    #[cfg(feature = "experimental-repair-store")]
    RepairBroker,
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
    #[cfg(feature = "experimental-repair-store")]
    #[serde(rename = "repair.backup.reserve")]
    RepairBackupReserve,
    #[cfg(feature = "experimental-repair-store")]
    #[serde(rename = "repair.backup.persist")]
    RepairBackupPersist,
    #[cfg(feature = "experimental-repair-store")]
    #[serde(rename = "repair.backup.status")]
    RepairBackupStatus,
    #[cfg(feature = "experimental-repair-store")]
    #[serde(rename = "repair.backup.get")]
    RepairBackupGet,
    #[cfg(feature = "experimental-repair-store")]
    #[serde(rename = "repair.backup.cancel")]
    RepairBackupCancel,
    #[cfg(feature = "experimental-repair-store")]
    #[serde(rename = "repair.backup.retire")]
    RepairBackupRetire,
    #[cfg(feature = "experimental-repair-store")]
    #[serde(rename = "repair.transaction.status")]
    RepairTransactionStatus,
    #[cfg(feature = "experimental-repair-store")]
    #[serde(rename = "repair.transaction.resolve")]
    RepairTransactionResolve,
    #[cfg(feature = "experimental-repair-store")]
    #[serde(rename = "repair.vault.live-parent")]
    RepairVaultLiveParent,
}

impl Operation {
    fn permits(self, role: PeerRole) -> bool {
        match role {
            PeerRole::Companion => matches!(
                self,
                Self::VaultStatus
                    | Self::VaultUnlock
                    | Self::VaultLock
                    | Self::ProviderOpenAiConfigure
                    | Self::ProviderStatus
                    | Self::ProviderLogout
                    | Self::ReportList
                    | Self::ReportGet
            ),
            PeerRole::Agent(AgentRole::Application) => matches!(
                self,
                Self::VaultStatus
                    | Self::ProviderStatus
                    | Self::AuditAppend
                    | Self::ReportPersist
                    | Self::ReportList
                    | Self::ReportGet
            ),
            PeerRole::Agent(AgentRole::OpenAi) => matches!(
                self,
                Self::VaultStatus | Self::ProviderStatus | Self::ProviderOpenAiBorrow
            ),
            PeerRole::Agent(AgentRole::Codex) => {
                matches!(self, Self::VaultStatus | Self::ProviderCodexHomeLease)
            }
            #[cfg(feature = "experimental-repair-store")]
            PeerRole::RepairBroker => matches!(
                self,
                Self::RepairBackupReserve
                    | Self::RepairBackupPersist
                    | Self::RepairBackupStatus
                    | Self::RepairBackupGet
                    | Self::RepairBackupCancel
                    | Self::RepairBackupRetire
                    | Self::RepairTransactionStatus
                    | Self::RepairTransactionResolve
                    | Self::RepairVaultLiveParent
            ),
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

impl<'de> Deserialize<'de> for Sha256 {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        Self::parse(&value).map_err(serde::de::Error::custom)
    }
}

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

    /// Returns the canonical 32 digest bytes represented by this value.
    pub fn bytes(&self) -> [u8; 32] {
        let mut bytes = [0_u8; 32];
        for (index, pair) in self.0.as_bytes().chunks_exact(2).enumerate() {
            bytes[index] = (hex_nibble(pair[0]) << 4) | hex_nibble(pair[1]);
        }
        bytes
    }
}

fn hex_nibble(byte: u8) -> u8 {
    match byte {
        b'0'..=b'9' => byte - b'0',
        b'a'..=b'f' => byte - b'a' + 10,
        _ => unreachable!("Sha256 validates lowercase hexadecimal input"),
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
    #[serde(rename = "codex-mount-namespace")]
    CodexMountNamespace,
    #[serde(rename = "codex-mount-root")]
    CodexMountRoot,
    #[serde(rename = "session-report-json-pipe")]
    SessionReportJsonPipe,
    #[serde(rename = "signed-report-envelope-pipe")]
    SignedReportEnvelopePipe,
    #[cfg(feature = "experimental-repair-store")]
    #[serde(rename = "repair-backup-input-pipe")]
    RepairBackupInputPipe,
    #[cfg(feature = "experimental-repair-store")]
    #[serde(rename = "repair-backup-output-pipe")]
    RepairBackupOutputPipe,
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
    ProviderCodexHomeLease {
        mount_namespace: DescriptorDeclaration,
        mount_root: DescriptorDeclaration,
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
    #[cfg(feature = "experimental-repair-store")]
    RepairBackupReserve {
        draft: RepairBackupDraft,
    },
    #[cfg(feature = "experimental-repair-store")]
    RepairBackupPersist {
        expected: Box<RepairBackupStatusPayload>,
        binding: RepairBackupBinding,
        metadata: RepairFileMetadataV1,
        input: DescriptorDeclaration,
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
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct CodexHomeLeasePayload {
    mount_namespace: DescriptorDeclaration,
    mount_root: DescriptorDeclaration,
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

#[cfg(feature = "experimental-repair-store")]
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct RepairBackupReservePayload {
    session_id: String,
    target_id: String,
    target_fingerprint: String,
    target_recovery_fingerprint: String,
    expected_backup_sha256: String,
    metadata_sha256: String,
    backup_size: u64,
    required_capacity_bytes: u64,
}

#[cfg(feature = "experimental-repair-store")]
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct RepairBackupPersistPayload {
    expected: RepairBackupStatusPayload,
    metadata: RepairFileMetadataV1,
    plan_id: String,
    plan_sha256: String,
    approval_id: String,
    approval_sha256: String,
    resource_id: String,
    resource_sha256: String,
    execution_intent: RepairExecutionIntentV1,
    input: DescriptorDeclaration,
}

#[cfg(feature = "experimental-repair-store")]
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct RepairBackupReferencePayload {
    expected: RepairBackupStatusPayload,
}

#[cfg(feature = "experimental-repair-store")]
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct RepairBackupCancelPayload {
    reservation_id: String,
    draft_binding_sha256: String,
}

#[cfg(feature = "experimental-repair-store")]
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct RepairTransactionStatusRequestPayload {
    selector: RepairTransactionStatusSelector,
}

#[cfg(feature = "experimental-repair-store")]
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct RepairTransactionResolveRequestPayload {
    expected: RepairTransactionStatusPayload,
    resolution: RepairTransactionResolution,
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
    if !request_payload_is_authorized(peer.role, &payload) {
        return Err(rejected_request(
            request_id,
            wire.operation,
            ProtocolViolation::NotAuthorized,
            ErrorToken::NotAuthorized,
            peer.connection_identity,
            Arc::clone(&peer.connection_token),
        ));
    }
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

fn request_payload_is_authorized(role: PeerRole, payload: &RequestPayload) -> bool {
    match (role, payload) {
        (PeerRole::Agent(AgentRole::Codex), RequestPayload::ProviderLogout { provider }) => {
            *provider == Provider::Codex
        }
        (PeerRole::Companion, RequestPayload::ProviderLogout { .. }) => true,
        (_, RequestPayload::ProviderLogout { .. }) => false,
        _ => true,
    }
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
        | Operation::ReportList => {
            serde_json::from_str::<EmptyPayload>(raw.get())
                .map_err(|_| ProtocolViolation::InvalidPayload)?;
            Ok(RequestPayload::Empty)
        }
        #[cfg(feature = "experimental-repair-store")]
        Operation::RepairVaultLiveParent => {
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
        Operation::ProviderCodexHomeLease => {
            let payload = serde_json::from_str::<CodexHomeLeasePayload>(raw.get())
                .map_err(|_| ProtocolViolation::InvalidPayload)?;
            validate_declaration(
                &payload.mount_namespace,
                DescriptorType::CodexMountNamespace,
                0,
                0,
            )?;
            validate_declaration(&payload.mount_root, DescriptorType::CodexMountRoot, 0, 0)?;
            Ok(RequestPayload::ProviderCodexHomeLease {
                mount_namespace: payload.mount_namespace,
                mount_root: payload.mount_root,
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
        #[cfg(feature = "experimental-repair-store")]
        Operation::RepairBackupReserve => {
            let payload = serde_json::from_str::<RepairBackupReservePayload>(raw.get())
                .map_err(|_| ProtocolViolation::InvalidPayload)?;
            Ok(RequestPayload::RepairBackupReserve {
                draft: RepairBackupDraft::new(
                    payload.session_id,
                    payload.target_id,
                    Sha256::parse(&payload.target_fingerprint)?,
                    payload.target_recovery_fingerprint,
                    Sha256::parse(&payload.expected_backup_sha256)?,
                    Sha256::parse(&payload.metadata_sha256)?,
                    payload.backup_size,
                    payload.required_capacity_bytes,
                )?,
            })
        }
        #[cfg(feature = "experimental-repair-store")]
        Operation::RepairBackupPersist => {
            let payload = serde_json::from_str::<RepairBackupPersistPayload>(raw.get())
                .map_err(|_| ProtocolViolation::InvalidPayload)?;
            payload.expected.validate()?;
            payload.metadata.validate()?;
            payload.execution_intent.validate()?;
            if payload.expected.state() != RepairBackupState::Reserved
                || payload.metadata.canonical_sha256() != *payload.expected.metadata_sha256()
                || payload.execution_intent.before_sha256()
                    != payload.expected.expected_backup_sha256()
                || payload.execution_intent.before_metadata() != &payload.metadata
                || payload
                    .execution_intent
                    .target_physical_parent_fingerprint()
                    == payload.expected.physical_parent_fingerprint()
            {
                return Err(ProtocolViolation::InvalidPayload);
            }
            validate_declaration(
                &payload.input,
                DescriptorType::RepairBackupInputPipe,
                1,
                MAX_REPAIR_BACKUP_BYTES,
            )?;
            Ok(RequestPayload::RepairBackupPersist {
                expected: Box::new(payload.expected),
                binding: RepairBackupBinding::new(
                    payload.plan_id,
                    Sha256::parse(&payload.plan_sha256)?,
                    payload.approval_id,
                    Sha256::parse(&payload.approval_sha256)?,
                    payload.resource_id,
                    Sha256::parse(&payload.resource_sha256)?,
                    payload.execution_intent,
                )?,
                metadata: payload.metadata,
                input: payload.input,
            })
        }
        #[cfg(feature = "experimental-repair-store")]
        Operation::RepairBackupStatus
        | Operation::RepairBackupGet
        | Operation::RepairBackupRetire => {
            let payload = serde_json::from_str::<RepairBackupReferencePayload>(raw.get())
                .map_err(|_| ProtocolViolation::InvalidPayload)?;
            payload.expected.validate()?;
            if matches!(
                operation,
                Operation::RepairBackupGet | Operation::RepairBackupRetire
            ) && payload.expected.state() != RepairBackupState::Durable
            {
                return Err(ProtocolViolation::InvalidPayload);
            }
            if operation == Operation::RepairBackupStatus {
                Ok(RequestPayload::RepairBackupStatus {
                    expected: Box::new(payload.expected),
                })
            } else if operation == Operation::RepairBackupGet {
                Ok(RequestPayload::RepairBackupGet {
                    expected: Box::new(payload.expected),
                })
            } else {
                Ok(RequestPayload::RepairBackupRetire {
                    expected: Box::new(payload.expected),
                })
            }
        }
        #[cfg(feature = "experimental-repair-store")]
        Operation::RepairBackupCancel => {
            let payload = serde_json::from_str::<RepairBackupCancelPayload>(raw.get())
                .map_err(|_| ProtocolViolation::InvalidPayload)?;
            Ok(RequestPayload::RepairBackupCancel {
                reservation_id: RepairReservationId::parse(&payload.reservation_id)?,
                draft_binding_sha256: Sha256::parse(&payload.draft_binding_sha256)?,
            })
        }
        #[cfg(feature = "experimental-repair-store")]
        Operation::RepairTransactionStatus => {
            let payload = serde_json::from_str::<RepairTransactionStatusRequestPayload>(raw.get())
                .map_err(|_| ProtocolViolation::InvalidPayload)?;
            payload.selector.validate()?;
            Ok(RequestPayload::RepairTransactionStatus {
                selector: payload.selector,
            })
        }
        #[cfg(feature = "experimental-repair-store")]
        Operation::RepairTransactionResolve => {
            let payload = serde_json::from_str::<RepairTransactionResolveRequestPayload>(raw.get())
                .map_err(|_| ProtocolViolation::InvalidPayload)?;
            payload.expected.validate()?;
            let Some(intent) = payload.expected.backup().execution_intent() else {
                return Err(ProtocolViolation::InvalidPayload);
            };
            payload.resolution.validate_against(intent)?;
            if !payload.expected.is_unresolved() {
                return Err(ProtocolViolation::InvalidPayload);
            }
            Ok(RequestPayload::RepairTransactionResolve {
                expected: Box::new(payload.expected),
                resolution: payload.resolution,
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
        #[cfg(feature = "experimental-repair-store")]
        RequestPayload::RepairBackupPersist { input, .. } => Some(input),
        RequestPayload::ProviderCodexHomeLease { .. } => None,
        RequestPayload::Empty
        | RequestPayload::ProviderLogout { .. }
        | RequestPayload::AuditAppend { .. }
        | RequestPayload::ReportGet { .. } => None,
        #[cfg(feature = "experimental-repair-store")]
        RequestPayload::RepairBackupReserve { .. }
        | RequestPayload::RepairBackupStatus { .. }
        | RequestPayload::RepairBackupGet { .. }
        | RequestPayload::RepairBackupCancel { .. }
        | RequestPayload::RepairBackupRetire { .. }
        | RequestPayload::RepairTransactionStatus { .. }
        | RequestPayload::RepairTransactionResolve { .. } => None,
    }
}

fn validate_received_descriptors(
    payload: &RequestPayload,
    descriptors: &[OwnedFd],
) -> Result<(), ProtocolViolation> {
    if let RequestPayload::ProviderCodexHomeLease {
        mount_namespace,
        mount_root,
    } = payload
    {
        validate_declaration(mount_namespace, DescriptorType::CodexMountNamespace, 0, 0)?;
        validate_declaration(mount_root, DescriptorType::CodexMountRoot, 0, 0)?;
        return match descriptors {
            [] | [_] => Err(ProtocolViolation::FdRequired),
            [namespace, root] => {
                validate_mount_namespace_descriptor(namespace.as_fd())?;
                validate_mount_root_descriptor(root.as_fd())
            }
            [_, _, ..] => Err(ProtocolViolation::FdForbidden),
        };
    }
    match (payload_descriptor(payload), descriptors) {
        (Some(_), []) => return Err(ProtocolViolation::FdRequired),
        (Some(declaration), [descriptor]) => match declaration.kind {
            DescriptorType::CodexMountNamespace => {
                validate_mount_namespace_descriptor(descriptor.as_fd())?
            }
            DescriptorType::PassphrasePipe
            | DescriptorType::OpenAiApiKeyPipe
            | DescriptorType::SessionReportJsonPipe => validate_pipe_descriptor(descriptor)?,
            #[cfg(feature = "experimental-repair-store")]
            DescriptorType::RepairBackupInputPipe => validate_pipe_descriptor(descriptor)?,
            DescriptorType::CodexHomeOPath
            | DescriptorType::CodexMountRoot
            | DescriptorType::SignedReportEnvelopePipe => {
                return Err(ProtocolViolation::InvalidPayload);
            }
            #[cfg(feature = "experimental-repair-store")]
            DescriptorType::RepairBackupOutputPipe => {
                return Err(ProtocolViolation::InvalidPayload);
            }
        },
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

/// Validates the descriptor-only mount namespace capability used by the
/// Codex home lease. The nsfs identity plus the kernel's fixed `mnt:[N]`
/// procfs rendering distinguishes it from every other namespace kind without
/// accepting a caller-provided path or identifier.
pub fn validate_mount_namespace_descriptor(
    descriptor: BorrowedFd<'_>,
) -> Result<(), ProtocolViolation> {
    use rustix::fs::{self as rfs, OFlags};

    let filesystem = rfs::fstatfs(descriptor).map_err(|_| ProtocolViolation::InvalidDescriptor)?;
    let status = rfs::fcntl_getfl(descriptor).map_err(|_| ProtocolViolation::InvalidDescriptor)?;
    let flags =
        rustix::io::fcntl_getfd(descriptor).map_err(|_| ProtocolViolation::InvalidDescriptor)?;
    if u64::try_from(filesystem.f_type).ok() != Some(NSFS_MAGIC)
        || status & OFlags::ACCMODE != OFlags::RDONLY
        || flags != rustix::io::FdFlags::CLOEXEC
    {
        return Err(ProtocolViolation::InvalidDescriptor);
    }
    let target = std::fs::read_link(PathBuf::from(format!(
        "/proc/self/fd/{}",
        descriptor.as_raw_fd()
    )))
    .map_err(|_| ProtocolViolation::InvalidDescriptor)?;
    let bytes = target.as_os_str().as_encoded_bytes();
    let Some(identifier) = bytes
        .strip_prefix(b"mnt:[")
        .and_then(|value| value.strip_suffix(b"]"))
    else {
        return Err(ProtocolViolation::InvalidDescriptor);
    };
    if identifier.is_empty() || !identifier.iter().all(u8::is_ascii_digit) {
        return Err(ProtocolViolation::InvalidDescriptor);
    }
    Ok(())
}

/// Validates the bridge root capability paired with its mount namespace.
pub fn validate_mount_root_descriptor(descriptor: BorrowedFd<'_>) -> Result<(), ProtocolViolation> {
    use rustix::fs::{self as rfs, FileType, OFlags};

    let stat = rfs::fstat(descriptor).map_err(|_| ProtocolViolation::InvalidDescriptor)?;
    let status = rfs::fcntl_getfl(descriptor).map_err(|_| ProtocolViolation::InvalidDescriptor)?;
    let flags =
        rustix::io::fcntl_getfd(descriptor).map_err(|_| ProtocolViolation::InvalidDescriptor)?;
    if !FileType::from_raw_mode(stat.st_mode).is_dir()
        || stat.st_uid != 0
        || stat.st_gid != 0
        || status != OFlags::PATH | OFlags::DIRECTORY | OFlags::NOFOLLOW
        || flags != rustix::io::FdFlags::CLOEXEC
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
    AuditAppended {
        sequence: u64,
    },
    ReportStored(ReportSummary),
    ReportList {
        reports: Vec<ReportSummary>,
    },
    Report(ReportSummary, DescriptorDeclaration),
    #[cfg(feature = "experimental-repair-store")]
    RepairBackupStatus(Box<RepairBackupStatusPayload>),
    #[cfg(feature = "experimental-repair-store")]
    RepairBackup(Box<RepairBackupStatusPayload>, DescriptorDeclaration),
    #[cfg(feature = "experimental-repair-store")]
    RepairBackupReleased(RepairBackupReleasePayload),
    #[cfg(feature = "experimental-repair-store")]
    RepairTransactionStatus(Box<RepairTransactionStatusResultPayload>),
    #[cfg(feature = "experimental-repair-store")]
    RepairTransactionResolved(Box<RepairTransactionStatusPayload>),
    #[cfg(feature = "experimental-repair-store")]
    RepairVaultLiveIdentity(RepairVaultLiveIdentityPayload),
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

#[cfg(feature = "experimental-repair-store")]
#[derive(Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct RepairBackupResponse<'a> {
    backup: &'a RepairBackupStatusPayload,
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
        #[cfg(feature = "experimental-repair-store")]
        SuccessPayload::RepairBackupStatus(status) => serde_json::to_vec(&SuccessWire {
            api_version: API_VERSION,
            request_id,
            state_version,
            operation,
            outcome: "ok",
            payload: status,
        }),
        #[cfg(feature = "experimental-repair-store")]
        SuccessPayload::RepairBackup(status, output) => serde_json::to_vec(&SuccessWire {
            api_version: API_VERSION,
            request_id,
            state_version,
            operation,
            outcome: "ok",
            payload: RepairBackupResponse {
                backup: status,
                output,
            },
        }),
        #[cfg(feature = "experimental-repair-store")]
        SuccessPayload::RepairBackupReleased(released) => serde_json::to_vec(&SuccessWire {
            api_version: API_VERSION,
            request_id,
            state_version,
            operation,
            outcome: "ok",
            payload: released,
        }),
        #[cfg(feature = "experimental-repair-store")]
        SuccessPayload::RepairTransactionStatus(status) => serde_json::to_vec(&SuccessWire {
            api_version: API_VERSION,
            request_id,
            state_version,
            operation,
            outcome: "ok",
            payload: status,
        }),
        #[cfg(feature = "experimental-repair-store")]
        SuccessPayload::RepairTransactionResolved(status) => serde_json::to_vec(&SuccessWire {
            api_version: API_VERSION,
            request_id,
            state_version,
            operation,
            outcome: "ok",
            payload: status,
        }),
        #[cfg(feature = "experimental-repair-store")]
        SuccessPayload::RepairVaultLiveIdentity(identity) => serde_json::to_vec(&SuccessWire {
            api_version: API_VERSION,
            request_id,
            state_version,
            operation,
            outcome: "ok",
            payload: identity,
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
            RequestPayload::ProviderCodexHomeLease { .. },
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
        #[cfg(feature = "experimental-repair-store")]
        (
            Operation::RepairBackupReserve,
            RequestPayload::RepairBackupReserve { draft },
            SuccessPayload::RepairBackupStatus(status),
        ) if status.validate().is_ok()
            && status.state() == RepairBackupState::Reserved
            && status.draft_binding_sha256() == &draft.draft_binding_sha256()
            && status.backup_size() == draft.backup_size()
            && status.expected_backup_sha256() == draft.expected_backup_sha256()
            && status.metadata_sha256() == draft.metadata_sha256()
            && status.reserved_bytes() >= draft.required_capacity_bytes() =>
        {
            None
        }
        #[cfg(feature = "experimental-repair-store")]
        (
            Operation::RepairBackupPersist,
            RequestPayload::RepairBackupPersist {
                expected,
                binding,
                metadata,
                input,
            },
            SuccessPayload::RepairBackupStatus(status),
        ) if status.validate().is_ok()
            && status.state() == RepairBackupState::Durable
            && status.immutable_fields_match(expected)
            && metadata.canonical_sha256() == *expected.metadata_sha256()
            && status.backup_size() == input.size
            && status.plan_id() == Some(binding.plan_id())
            && status.plan_sha256() == Some(binding.plan_sha256())
            && status.approval_id() == Some(binding.approval_id())
            && status.approval_sha256() == Some(binding.approval_sha256())
            && status.resource_id() == Some(binding.resource_id())
            && status.resource_sha256() == Some(binding.resource_sha256())
            && status.execution_intent() == Some(binding.execution_intent()) =>
        {
            None
        }
        #[cfg(feature = "experimental-repair-store")]
        (
            Operation::RepairBackupStatus,
            RequestPayload::RepairBackupStatus { expected },
            SuccessPayload::RepairBackupStatus(status),
        ) if status.validate().is_ok()
            && status.immutable_fields_match(expected)
            && status.state() == expected.state() =>
        {
            None
        }
        #[cfg(feature = "experimental-repair-store")]
        (
            Operation::RepairBackupGet,
            RequestPayload::RepairBackupGet { expected },
            SuccessPayload::RepairBackup(status, declaration),
        ) if status.validate().is_ok()
            && status.state() == RepairBackupState::Durable
            && status.as_ref() == expected.as_ref()
            && declaration.kind == DescriptorType::RepairBackupOutputPipe
            && declaration.size == status.backup_size() =>
        {
            Some(declaration)
        }
        #[cfg(feature = "experimental-repair-store")]
        (
            Operation::RepairBackupCancel,
            RequestPayload::RepairBackupCancel {
                reservation_id,
                draft_binding_sha256,
            },
            SuccessPayload::RepairBackupReleased(released),
        ) if released.validate().is_ok()
            && released.reservation_id() == reservation_id
            && released.draft_binding_sha256() == draft_binding_sha256 =>
        {
            None
        }
        #[cfg(feature = "experimental-repair-store")]
        (
            Operation::RepairBackupRetire,
            RequestPayload::RepairBackupRetire { expected },
            SuccessPayload::RepairBackupReleased(released),
        ) if expected.state() == RepairBackupState::Durable
            && released.validate().is_ok()
            && released.reservation_id() == expected.reservation_id()
            && released.draft_binding_sha256() == expected.draft_binding_sha256()
            && released.released_bytes() == expected.reserved_bytes() =>
        {
            None
        }
        #[cfg(feature = "experimental-repair-store")]
        (
            Operation::RepairTransactionStatus,
            RequestPayload::RepairTransactionStatus { selector },
            SuccessPayload::RepairTransactionStatus(result),
        ) if selector.matches_result(result) => None,
        #[cfg(feature = "experimental-repair-store")]
        (
            Operation::RepairTransactionResolve,
            RequestPayload::RepairTransactionResolve {
                expected,
                resolution,
            },
            SuccessPayload::RepairTransactionResolved(status),
        ) if status.validate().is_ok()
            && status.same_transaction(expected)
            && status.resolves_with(resolution) =>
        {
            None
        }
        #[cfg(feature = "experimental-repair-store")]
        (
            Operation::RepairVaultLiveParent,
            RequestPayload::Empty,
            SuccessPayload::RepairVaultLiveIdentity(identity),
        ) if identity.validate().is_ok() => None,
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
            #[cfg(feature = "experimental-repair-store")]
            DescriptorType::RepairBackupOutputPipe => validate_borrowed_pipe(*descriptor),
            DescriptorType::CodexHomeOPath => validate_o_path_directory(*descriptor),
            DescriptorType::PassphrasePipe
            | DescriptorType::CodexMountNamespace
            | DescriptorType::CodexMountRoot
            | DescriptorType::SessionReportJsonPipe => Err(ProtocolViolation::InvalidPayload),
            #[cfg(feature = "experimental-repair-store")]
            DescriptorType::RepairBackupInputPipe => Err(ProtocolViolation::InvalidPayload),
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
        || status != (OFlags::PATH | OFlags::DIRECTORY | OFlags::NOFOLLOW)
        || fd_flags != rustix::io::FdFlags::CLOEXEC
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
    const COMPANION_UID: u32 = 1000;
    const APPLICATION_UID: u32 = 1001;
    const OPENAI_UID: u32 = 1002;
    const CODEX_UID: u32 = 1003;
    #[cfg(feature = "experimental-repair-store")]
    const REPAIR_UID: u32 = 1004;

    fn allowlist() -> PeerAllowlist {
        PeerAllowlist::builder(COMPANION_UID)
            .agent(AgentRole::Application, APPLICATION_UID)
            .and_then(|builder| builder.agent(AgentRole::OpenAi, OPENAI_UID))
            .and_then(|builder| builder.agent(AgentRole::Codex, CODEX_UID))
            .and_then(PeerAllowlistBuilder::build)
            .expect("valid test allowlist")
    }

    fn one_agent_allowlist(
        companion_uid: u32,
        role: AgentRole,
        agent_uid: u32,
    ) -> Result<PeerAllowlist, ProtocolViolation> {
        PeerAllowlist::builder(companion_uid)
            .agent(role, agent_uid)?
            .build()
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

    #[cfg(feature = "experimental-repair-store")]
    fn repair_peer() -> PeerIdentity {
        let allowlist = PeerAllowlist::builder(COMPANION_UID)
            .agent(AgentRole::Application, APPLICATION_UID)
            .and_then(|builder| builder.agent(AgentRole::OpenAi, OPENAI_UID))
            .and_then(|builder| builder.agent(AgentRole::Codex, CODEX_UID))
            .and_then(|builder| builder.repair_broker(REPAIR_UID))
            .and_then(PeerAllowlistBuilder::build)
            .expect("repair test allowlist");
        PeerIdentity {
            pid: 4243,
            uid: REPAIR_UID,
            role: allowlist.role_for(REPAIR_UID).expect("repair broker UID"),
            connection_identity: SeqpacketSocketIdentity {
                device: 7,
                inode: 12,
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
                one_agent_allowlist(uid, AgentRole::OpenAi, 1).err(),
                Some(ProtocolViolation::InvalidAllowlist)
            );
            return;
        }
        let other = if uid == 1 { 2 } else { 1 };
        let authenticated = authenticate_seqpacket_peer(
            second.as_fd(),
            one_agent_allowlist(uid, AgentRole::OpenAi, other).expect("allowlist"),
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
                one_agent_allowlist(uid, AgentRole::OpenAi, other).expect("allowlist"),
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
        let allowlist = one_agent_allowlist(uid, AgentRole::OpenAi, other).expect("allowlist");
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
            one_agent_allowlist(uid, AgentRole::OpenAi, other).expect("allowlist"),
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
    fn allowlist_builder_rejects_root_aliases_and_duplicate_assignments() {
        assert_eq!(
            PeerAllowlist::builder(0).build(),
            Err(ProtocolViolation::InvalidAllowlist)
        );
        assert_eq!(
            PeerAllowlist::builder(1000)
                .agent(AgentRole::OpenAi, 0)
                .err(),
            Some(ProtocolViolation::InvalidAllowlist)
        );
        assert_eq!(
            PeerAllowlist::builder(1000)
                .agent(AgentRole::OpenAi, 1000)
                .err(),
            Some(ProtocolViolation::InvalidAllowlist)
        );
        let openai = PeerAllowlist::builder(1000)
            .agent(AgentRole::OpenAi, 1001)
            .expect("first role assignment");
        assert_eq!(
            openai.agent(AgentRole::OpenAi, 1002).err(),
            Some(ProtocolViolation::InvalidAllowlist)
        );
        assert_eq!(
            openai.agent(AgentRole::Codex, 1001).err(),
            Some(ProtocolViolation::InvalidAllowlist)
        );
        let builder_debug = format!("{openai:?}");
        assert!(!builder_debug.contains("1000"));
        assert!(!builder_debug.contains("1001"));

        let allowlist = allowlist();
        assert_eq!(
            allowlist.role_for(APPLICATION_UID),
            Ok(PeerRole::Agent(AgentRole::Application))
        );
        assert_eq!(
            allowlist.role_for(OPENAI_UID),
            Ok(PeerRole::Agent(AgentRole::OpenAi))
        );
        assert_eq!(
            allowlist.role_for(CODEX_UID),
            Ok(PeerRole::Agent(AgentRole::Codex))
        );
        let debug = format!("{allowlist:?}");
        for uid in [COMPANION_UID, APPLICATION_UID, OPENAI_UID, CODEX_UID] {
            assert!(!debug.contains(&uid.to_string()));
        }
    }

    #[cfg(feature = "experimental-repair-store")]
    #[test]
    fn repair_broker_role_and_eight_operations_are_closed_and_path_free() {
        use crate::rescue_repair_vault::{
            RepairBackupBinding, RepairBackupReleasePayload, RepairBackupStatusPayload,
            RepairExecutionIntentV1, RepairFileMetadataV1, RepairReservationId,
            RepairTransactionResolution, RepairTransactionResolutionOutcome,
            RepairTransactionStatusPayload, RepairTransactionStatusResultPayload,
            repair_backup_output,
        };

        let repair_allowlist = PeerAllowlist::builder(COMPANION_UID)
            .repair_broker(REPAIR_UID)
            .and_then(PeerAllowlistBuilder::build)
            .expect("repair allowlist");
        assert_eq!(
            repair_allowlist.role_for(REPAIR_UID),
            Ok(PeerRole::RepairBroker)
        );
        assert!(
            PeerAllowlist::builder(COMPANION_UID)
                .repair_broker(0)
                .is_err()
        );
        assert!(
            PeerAllowlist::builder(COMPANION_UID)
                .agent(AgentRole::Application, REPAIR_UID)
                .and_then(|builder| builder.repair_broker(REPAIR_UID))
                .is_err()
        );

        let hash = |byte: char| byte.to_string().repeat(64);
        let metadata = RepairFileMetadataV1::new(0o644, 0, 0).expect("metadata");
        let metadata_sha256 = metadata.canonical_sha256();
        let reserve = request(
            "repair.backup.reserve",
            &format!(
                "{{\"sessionId\":\"S-session-1\",\"targetId\":\"target-1\",\"targetFingerprint\":\"{}\",\"targetRecoveryFingerprint\":\"recovery:{}\",\"expectedBackupSha256\":\"{}\",\"metadataSha256\":\"{}\",\"backupSize\":4096,\"requiredCapacityBytes\":8192}}",
                hash('1'),
                hash('4'),
                hash('2'),
                metadata_sha256.as_str()
            ),
        );
        let reserve_request =
            decode_request(&reserve, repair_peer(), Vec::new()).expect("repair broker reserve");
        assert_eq!(reserve_request.role(), PeerRole::RepairBroker);
        assert!(matches!(
            reserve_request.payload(),
            RequestPayload::RepairBackupReserve { .. }
        ));
        assert_eq!(
            decode_request(&reserve, peer(COMPANION_UID), Vec::new()).err(),
            Some(ProtocolViolation::NotAuthorized)
        );

        let reservation =
            RepairReservationId::parse("B-0123456789abcdef0123456789abcdef").expect("reservation");
        let draft = match reserve_request.payload() {
            RequestPayload::RepairBackupReserve { draft } => draft,
            _ => unreachable!("decoded reserve payload"),
        };
        let reserved = RepairBackupStatusPayload::reserved(
            reservation.clone(),
            draft.draft_binding_sha256(),
            reservation.locator(),
            "V-0123456789abcdef0123456789abcdef",
            Sha256::parse(&hash('8')).expect("hash"),
            Sha256::parse(&hash('9')).expect("hash"),
            8192,
            4096,
            Sha256::parse(&hash('2')).expect("hash"),
            metadata_sha256.clone(),
        )
        .expect("reserved backup");
        assert!(
            encode_success(
                &reserve_request,
                9,
                &SuccessPayload::RepairBackupStatus(Box::new(reserved.clone())),
                &[],
            )
            .is_ok()
        );
        let wrong_binding = RepairBackupStatusPayload::reserved(
            reservation.clone(),
            Sha256::parse(&hash('0')).expect("hash"),
            reservation.locator(),
            "V-0123456789abcdef0123456789abcdef",
            Sha256::parse(&hash('8')).expect("hash"),
            Sha256::parse(&hash('9')).expect("hash"),
            8192,
            4096,
            Sha256::parse(&hash('2')).expect("hash"),
            metadata_sha256.clone(),
        )
        .expect("shape-valid wrong binding");
        assert_eq!(
            encode_success(
                &reserve_request,
                9,
                &SuccessPayload::RepairBackupStatus(Box::new(wrong_binding)),
                &[],
            ),
            Err(ProtocolViolation::InvalidPayload)
        );
        let execution_intent = RepairExecutionIntentV1::new(
            "S-session-1",
            7,
            "target-1",
            format!("scan:{}", hash('a')),
            Sha256::parse(&hash('1')).expect("hash"),
            Sha256::parse(&hash('7')).expect("hash"),
            format!("recovery:{}", hash('8')),
            format!("lock:{}", hash('b')),
            Sha256::parse(&hash('2')).expect("hash"),
            Sha256::parse(&hash('c')).expect("hash"),
            Sha256::parse(&hash('d')).expect("hash"),
            Sha256::parse(&hash('e')).expect("hash"),
            metadata.clone(),
        )
        .expect("execution intent");
        let binding = RepairBackupBinding::new(
            "P-plan-1",
            Sha256::parse(&hash('4')).expect("hash"),
            "A-approval-1",
            Sha256::parse(&hash('5')).expect("hash"),
            "rescue:selected-linux-root:etc/fstab",
            Sha256::parse(&hash('2')).expect("hash"),
            execution_intent.clone(),
        )
        .expect("binding");
        let durable = RepairBackupStatusPayload::durable(
            reservation.clone(),
            draft.draft_binding_sha256(),
            reservation.locator(),
            "V-0123456789abcdef0123456789abcdef",
            Sha256::parse(&hash('8')).expect("hash"),
            Sha256::parse(&hash('9')).expect("hash"),
            8192,
            4096,
            Sha256::parse(&hash('2')).expect("hash"),
            metadata_sha256,
            binding,
        )
        .expect("durable backup");

        let persist = request(
            "repair.backup.persist",
            &format!(
                "{{\"expected\":{},\"metadata\":{},\"planId\":\"P-plan-1\",\"planSha256\":\"{}\",\"approvalId\":\"A-approval-1\",\"approvalSha256\":\"{}\",\"resourceId\":\"rescue:selected-linux-root:etc/fstab\",\"resourceSha256\":\"{}\",\"executionIntent\":{},\"input\":{{\"type\":\"repair-backup-input-pipe\",\"size\":4096}}}}",
                serde_json::to_string(&reserved).expect("reserved JSON"),
                serde_json::to_string(&metadata).expect("metadata JSON"),
                hash('4'),
                hash('5'),
                hash('2'),
                serde_json::to_string(&execution_intent).expect("intent JSON")
            ),
        );
        let input = read_pipe();
        let mut persist_request =
            decode_request(&persist, repair_peer(), vec![input]).expect("repair backup persist");
        assert!(persist_request.take_descriptor().is_some());
        let encoded = encode_success(
            &persist_request,
            9,
            &SuccessPayload::RepairBackupStatus(Box::new(durable.clone())),
            &[],
        )
        .expect("durable persist response");
        let encoded = String::from_utf8(encoded).expect("UTF-8 response");
        assert!(encoded.contains("vault://repair/B-"));
        assert!(!encoded.contains("/dev/"));
        assert!(!encoded.contains("/mnt/"));

        for operation in ["repair.backup.status", "repair.backup.get"] {
            let reference = request(
                operation,
                &format!(
                    "{{\"expected\":{}}}",
                    serde_json::to_string(&durable).expect("durable JSON")
                ),
            );
            let request = decode_request(&reference, repair_peer(), Vec::new())
                .expect("repair backup reference");
            if operation.ends_with("status") {
                assert!(
                    encode_success(
                        &request,
                        9,
                        &SuccessPayload::RepairBackupStatus(Box::new(durable.clone())),
                        &[],
                    )
                    .is_ok()
                );
            } else {
                let output = read_pipe();
                assert!(
                    encode_success(
                        &request,
                        9,
                        &SuccessPayload::RepairBackup(
                            Box::new(durable.clone()),
                            repair_backup_output(4096).expect("output declaration"),
                        ),
                        &[output.as_fd()],
                    )
                    .is_ok()
                );
            }
        }

        let cancel = request(
            "repair.backup.cancel",
            &format!(
                "{{\"reservationId\":\"{}\",\"draftBindingSha256\":\"{}\"}}",
                reservation.as_str(),
                draft.draft_binding_sha256().as_str()
            ),
        );
        let cancel = decode_request(&cancel, repair_peer(), Vec::new()).expect("stable cancel");
        let released = RepairBackupReleasePayload::new(
            reservation.clone(),
            draft.draft_binding_sha256(),
            8192,
        )
        .expect("release acknowledgement");
        assert!(
            encode_success(
                &cancel,
                11,
                &SuccessPayload::RepairBackupReleased(released.clone()),
                &[],
            )
            .is_ok()
        );

        let retire = request(
            "repair.backup.retire",
            &format!(
                "{{\"expected\":{}}}",
                serde_json::to_string(&durable).expect("durable JSON")
            ),
        );
        let retire = decode_request(&retire, repair_peer(), Vec::new()).expect("durable retire");
        assert!(
            encode_success(
                &retire,
                13,
                &SuccessPayload::RepairBackupReleased(released),
                &[],
            )
            .is_ok()
        );

        let pending =
            RepairTransactionStatusPayload::pending(durable.clone()).expect("pending transaction");
        let transaction_status_bytes = request(
            "repair.transaction.status",
            "{\"selector\":{\"kind\":\"pending-singleton\"}}",
        );
        assert_eq!(
            decode_request(&transaction_status_bytes, peer(COMPANION_UID), Vec::new(),).err(),
            Some(ProtocolViolation::NotAuthorized)
        );
        let transaction_status =
            decode_request(&transaction_status_bytes, repair_peer(), Vec::new())
                .expect("pending transaction lookup");
        assert!(
            encode_success(
                &transaction_status,
                13,
                &SuccessPayload::RepairTransactionStatus(Box::new(
                    RepairTransactionStatusResultPayload::found(pending.clone()),
                )),
                &[],
            )
            .is_ok()
        );

        let resolution = RepairTransactionResolution::new(
            RepairTransactionResolutionOutcome::CommittedAfter,
            execution_intent.after_sha256().clone(),
            metadata.canonical_sha256(),
            true,
            &execution_intent,
        )
        .expect("committed resolution");
        let resolve = request(
            "repair.transaction.resolve",
            &serde_json::json!({
                "expected": pending,
                "resolution": resolution,
            })
            .to_string(),
        );
        let resolve = decode_request(&resolve, repair_peer(), Vec::new())
            .expect("transaction resolution request");
        let resolved = RepairTransactionStatusPayload::resolved(durable, resolution)
            .expect("resolved transaction");
        assert!(
            encode_success(
                &resolve,
                15,
                &SuccessPayload::RepairTransactionResolved(Box::new(resolved)),
                &[],
            )
            .is_ok()
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
            peer(APPLICATION_UID),
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
            decode_request(&unlock, peer(APPLICATION_UID), vec![read_pipe()]).err(),
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
            ("report.persist", report_payload, APPLICATION_UID),
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
            ("vault.lock", "{}", COMPANION_UID),
            ("provider.status", "{}", OPENAI_UID),
            (
                "provider.logout",
                "{\"provider\":\"openai\"}",
                COMPANION_UID,
            ),
            ("provider.openai.borrow", "{}", OPENAI_UID),
            (
                "audit.append",
                "{\"sequence\":1,\"event\":\"agent-session-start\",\"outcome\":\"failed\",\"error\":\"IO_FAILED\"}",
                APPLICATION_UID,
            ),
            ("report.list", "{}", COMPANION_UID),
            (
                "report.get",
                "{\"reportId\":\"RP-12345678-1234-1234-1234-123456789abc\"}",
                APPLICATION_UID,
            ),
        ];
        for (operation, payload, uid) in cases {
            let decoded = decode_request(&request(operation, payload), peer(uid), Vec::new());
            assert!(decoded.is_ok(), "operation contract failed: {operation}");
        }
        let codex = request(
            "provider.codex.home_lease",
            "{\"mountNamespace\":{\"type\":\"codex-mount-namespace\",\"size\":0},\"mountRoot\":{\"type\":\"codex-mount-root\",\"size\":0}}",
        );
        assert!(
            decode_request(
                &codex,
                peer(CODEX_UID),
                vec![mount_namespace(), mount_root()]
            )
            .is_ok()
        );
        assert_eq!(
            decode_request(
                &codex,
                peer(COMPANION_UID),
                vec![mount_namespace(), mount_root()],
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
        assert!(decode_request(&persist, peer(APPLICATION_UID), vec![read_pipe()]).is_ok());

        let oversized_persist = request(
            "report.persist",
            &format!(
                "{{\"reportId\":\"RP-12345678-1234-1234-1234-123456789abc\",\"payloadSha256\":\"{}\",\"input\":{{\"type\":\"session-report-json-pipe\",\"size\":{}}}}}",
                "a".repeat(64),
                MAX_SESSION_REPORT_JSON_BYTES + 1
            ),
        );
        assert_eq!(
            decode_request(&oversized_persist, peer(APPLICATION_UID), vec![read_pipe()],).err(),
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
            ("vault.status", "{}", false, [true, true, true, true]),
            (
                "vault.unlock",
                "{\"input\":{\"type\":\"passphrase-pipe\",\"size\":12}}",
                true,
                [true, false, false, false],
            ),
            ("vault.lock", "{}", false, [true, false, false, false]),
            (
                "provider.openai.configure",
                "{\"input\":{\"type\":\"openai-api-key-pipe\",\"size\":64}}",
                true,
                [true, false, false, false],
            ),
            ("provider.status", "{}", false, [true, true, true, false]),
            (
                "provider.logout",
                "{\"provider\":\"openai\"}",
                false,
                [true, false, false, false],
            ),
            (
                "provider.logout",
                "{\"provider\":\"codex\"}",
                false,
                [true, false, false, false],
            ),
            (
                "provider.openai.borrow",
                "{}",
                false,
                [false, false, true, false],
            ),
            (
                "provider.codex.home_lease",
                "{\"mountNamespace\":{\"type\":\"codex-mount-namespace\",\"size\":0},\"mountRoot\":{\"type\":\"codex-mount-root\",\"size\":0}}",
                true,
                [false, false, false, true],
            ),
            (
                "audit.append",
                "{\"sequence\":1,\"event\":\"agent-session-start\",\"outcome\":\"succeeded\"}",
                false,
                [false, true, false, false],
            ),
            (
                "report.persist",
                report_persist.as_str(),
                true,
                [false, true, false, false],
            ),
            ("report.list", "{}", false, [true, true, false, false]),
            (
                "report.get",
                "{\"reportId\":\"RP-12345678-1234-1234-1234-123456789abc\"}",
                false,
                [true, true, false, false],
            ),
        ];
        for (operation, payload, needs_descriptor, permissions) in cases {
            for (uid, allowed) in [
                (COMPANION_UID, permissions[0]),
                (APPLICATION_UID, permissions[1]),
                (OPENAI_UID, permissions[2]),
                (CODEX_UID, permissions[3]),
            ] {
                let descriptors = if operation == "provider.codex.home_lease" {
                    vec![mount_namespace(), mount_root()]
                } else {
                    needs_descriptor.then(read_pipe).into_iter().collect()
                };
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
                decode_request(
                    &request("audit.append", &payload),
                    peer(APPLICATION_UID),
                    Vec::new(),
                )
                .err(),
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
                peer(APPLICATION_UID),
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
                peer(APPLICATION_UID),
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
            peer(OPENAI_UID),
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
            peer(APPLICATION_UID),
            vec![read_pipe()],
        )
        .expect("raw report payload request");
        drop(persist.take_descriptor());

        let wrong_input =
            persist_body.replace("session-report-json-pipe", "signed-report-envelope-pipe");
        assert_eq!(
            decode_request(
                &request("report.persist", &wrong_input),
                peer(APPLICATION_UID),
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
            peer(APPLICATION_UID),
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
            &request(
                "provider.codex.home_lease",
                "{\"mountNamespace\":{\"type\":\"codex-mount-namespace\",\"size\":0},\"mountRoot\":{\"type\":\"codex-mount-root\",\"size\":0}}",
            ),
            peer(CODEX_UID),
            vec![mount_namespace(), mount_root()],
        )
        .expect("home lease request");
        let payload = SuccessPayload::Descriptor(DescriptorDeclaration {
            kind: DescriptorType::CodexHomeOPath,
            size: 0,
        });
        let lease = rustix::fs::open(
            "/",
            OFlags::PATH | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .expect("O_PATH directory");
        assert!(encode_success(&request, 8, &payload, &[lease.as_fd()]).is_ok());

        let missing_directory = rustix::fs::open(
            "/",
            OFlags::PATH | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .expect("O_PATH without O_DIRECTORY");
        assert_eq!(
            encode_success(&request, 8, &payload, &[missing_directory.as_fd()]).err(),
            Some(ProtocolViolation::InvalidDescriptor)
        );

        let missing_nofollow = rustix::fs::open(
            "/",
            OFlags::PATH | OFlags::DIRECTORY | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .expect("O_PATH without O_NOFOLLOW");
        assert_eq!(
            encode_success(&request, 8, &payload, &[missing_nofollow.as_fd()]).err(),
            Some(ProtocolViolation::InvalidDescriptor)
        );

        let missing_cloexec = rustix::fs::open(
            "/",
            OFlags::PATH | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .expect("O_PATH before clearing CLOEXEC");
        rustix::io::fcntl_setfd(&missing_cloexec, rustix::io::FdFlags::empty())
            .expect("clear CLOEXEC");
        assert_eq!(
            encode_success(&request, 8, &payload, &[missing_cloexec.as_fd()]).err(),
            Some(ProtocolViolation::InvalidDescriptor)
        );

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
