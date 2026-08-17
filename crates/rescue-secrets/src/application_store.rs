//! Closed application-level persistence for the mounted Rescue vault.
//!
//! This layer is deliberately narrower than the encrypted journal and device
//! identity primitives beneath it. Production callers can store one OpenAI
//! credential, append only typed Agent lifecycle records, and persist signed
//! `SessionReport` documents. They cannot append arbitrary journal bytes,
//! create an identity, export a key, or use the identity as a generic signing
//! oracle.

use crate::linux::{
    DEVICE_IDENTITY_NAME, JOURNAL_ANCHOR_NAME, JOURNAL_DATABASE_NAME, JOURNAL_KEY_NAME,
    JOURNAL_SHM_NAME, JOURNAL_WAL_NAME, RescueDeviceIdentityStore, RescueJournalSecretStore,
    VaultInner,
};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use kernaid_device_identity::{DeviceIdentity, SignedReportEnvelope};
use kernaid_protocol::rescue_vault::{
    AuditEventType, AuditOutcome, ErrorToken, MAX_AUDIT_SEQUENCE, Operation, PeerRole,
    RequestPayload, ValidatedRequest,
};
use kernaid_report_schema::{MAX_SESSION_REPORT_BYTES, validate_session_report_json};
use kernaid_storage::{
    JournalAnchor, JournalEntryRef, JournalReplayError, JournalReplayLimits, SecureJournal,
};
use rand_core::{OsRng, RngCore};
use rustix::{
    fd::{AsFd, OwnedFd},
    fs::{
        self as rfs, AtFlags, FileType, Mode, OFlags, RawDir, RenameFlags, ResolveFlags, Stat,
        StatxFlags,
    },
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeMap, BTreeSet},
    error::Error,
    fmt,
    fs::File,
    io::{Read, Write},
    mem::MaybeUninit,
    path::Path,
    sync::MutexGuard,
};
use zeroize::{Zeroize, Zeroizing};

const PROVIDER_FILE_NAME: &str = "provider-openai-api-key-v1";
const REPORT_FILE_PREFIX: &str = "report-v1-";
const REPORT_FILE_SUFFIX: &str = ".json";
const STAGE_FILE_PREFIX: &str = ".kernaid-app-stage-v1-";
const PROVIDER_ENVELOPE_PREFIX: &[u8] = b"kernaid-rescue-provider-v1:openai-api-key-v1:";
const MAX_PROVIDER_KEY_BYTES: usize = 512;
const MAX_PROVIDER_ENVELOPE_BYTES: usize = 1024;
const MAX_SIGNED_REPORT_ENVELOPE_BYTES: usize = 1536 * 1024;
const MAX_REPORTS: usize = 256;
const MAX_APPLICATION_EVENT_BYTES: usize = 2048;
const MAX_APPLICATION_REPLAY_BYTES: u64 = MAX_APPLICATION_EVENT_BYTES as u64 * MAX_AUDIT_SEQUENCE;
const SCAN_BUFFER_BYTES: usize = 8192;
const MAX_LAYOUT_ENTRIES: usize = 270;
const MAX_LAYOUT_NAME_BYTES: usize = 128;
const FILE_MODE: u32 = 0o600;
const REPORT_MEDIA_TYPE: &str = "application/json";

/// Sanitized application-store failures. Variants contain no path, OS error,
/// transaction identifier, provider bytes, report body, or envelope bytes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RescueApplicationStoreError {
    MissingDeviceIdentity,
    InvalidProviderCredential,
    ProviderUnconfigured,
    InvalidReportIdentifier,
    InvalidReport,
    ReportHashMismatch,
    ReportAlreadyExists,
    ReportNotFound,
    ReportLimitReached,
    InvalidAgentAudit,
    StaleAgentSequence,
    CorruptJournal,
    CorruptApplicationState,
    ConcurrentWrite,
    WriteVerificationFailed,
    StorageUnavailable,
    ReopenRequired,
}

impl fmt::Display for RescueApplicationStoreError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::MissingDeviceIdentity => "the Rescue device identity is not provisioned",
            Self::InvalidProviderCredential => "invalid OpenAI credential",
            Self::ProviderUnconfigured => "the OpenAI credential is not configured",
            Self::InvalidReportIdentifier => "invalid Rescue report identifier",
            Self::InvalidReport => "invalid SessionReport document",
            Self::ReportHashMismatch => "the SessionReport hash does not match",
            Self::ReportAlreadyExists => "the Rescue report identifier already exists",
            Self::ReportNotFound => "the Rescue report does not exist",
            Self::ReportLimitReached => "the Rescue report limit has been reached",
            Self::InvalidAgentAudit => "invalid Agent lifecycle audit record",
            Self::StaleAgentSequence => "the Agent audit sequence is not the next value",
            Self::CorruptJournal => "the Rescue application journal is invalid",
            Self::CorruptApplicationState => "the Rescue application state is invalid",
            Self::ConcurrentWrite => "the Rescue application state changed concurrently",
            Self::WriteVerificationFailed => "Rescue application persistence verification failed",
            Self::StorageUnavailable => "Rescue application storage is unavailable",
            Self::ReopenRequired => "the Rescue application store must be reopened",
        })
    }
}

impl Error for RescueApplicationStoreError {}

/// Presence-only OpenAI credential state.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ProviderCredentialStatus {
    Absent,
    Configured,
}

/// Public metadata for one authenticated persisted report. The body and
/// serialized signed envelope remain callback-only.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RescueReportSummary {
    report_id: String,
    envelope_size: u64,
    envelope_sha256: [u8; 32],
}

impl RescueReportSummary {
    #[must_use]
    pub fn report_id(&self) -> &str {
        &self.report_id
    }

    #[must_use]
    pub const fn envelope_size(&self) -> u64 {
        self.envelope_size
    }

    #[must_use]
    pub const fn envelope_sha256(&self) -> &[u8; 32] {
        &self.envelope_sha256
    }
}

/// Descriptor-oriented application storage bound to one verified vault,
/// device identity and authenticated journal grammar.
pub struct RescueVaultApplicationStore<'vault> {
    inner: &'vault VaultInner,
    journal: SecureJournal<RescueJournalSecretStore<'vault>>,
    identity: DeviceIdentity,
    device_id: String,
    state: RecoveredState,
    head: JournalAnchor,
    healthy: bool,
    _application_guard: MutexGuard<'vault, ()>,
    #[cfg(test)]
    fault: Option<ApplicationFaultPoint>,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(tag = "type", deny_unknown_fields)]
enum ApplicationEvent {
    #[serde(rename = "vault.identity.bound")]
    IdentityBound {
        #[serde(rename = "deviceId")]
        device_id: String,
        #[serde(rename = "publicKeySha256")]
        public_key_sha256: String,
    },
    #[serde(rename = "provider.openai.configure.intent")]
    ProviderConfigureIntent {
        #[serde(rename = "transactionId")]
        transaction_id: String,
        #[serde(rename = "oldSha256")]
        old_sha256: Option<String>,
        #[serde(rename = "newSha256")]
        new_sha256: String,
    },
    #[serde(rename = "provider.openai.configure.complete")]
    ProviderConfigureComplete {
        #[serde(rename = "transactionId")]
        transaction_id: String,
        outcome: CompletionOutcome,
    },
    #[serde(rename = "provider.openai.logout.intent")]
    ProviderLogoutIntent {
        #[serde(rename = "transactionId")]
        transaction_id: String,
        #[serde(rename = "oldSha256")]
        old_sha256: Option<String>,
    },
    #[serde(rename = "provider.openai.logout.complete")]
    ProviderLogoutComplete {
        #[serde(rename = "transactionId")]
        transaction_id: String,
        outcome: CompletionOutcome,
    },
    #[serde(rename = "report.persist.intent")]
    ReportPersistIntent {
        #[serde(rename = "transactionId")]
        transaction_id: String,
        #[serde(rename = "reportId")]
        report_id: String,
        #[serde(rename = "payloadSha256")]
        payload_sha256: String,
    },
    #[serde(rename = "report.persist.complete")]
    ReportPersistComplete {
        #[serde(rename = "transactionId")]
        transaction_id: String,
        outcome: CompletionOutcome,
        #[serde(rename = "envelopeSize")]
        envelope_size: Option<u64>,
        #[serde(rename = "envelopeSha256")]
        envelope_sha256: Option<String>,
    },
    #[serde(rename = "agent.audit.append")]
    AgentAuditAppend {
        #[serde(rename = "requestId")]
        request_id: String,
        sequence: u64,
        #[serde(rename = "peerUid")]
        peer_uid: u32,
        #[serde(rename = "peerPid")]
        peer_pid: u32,
        event: AuditEventType,
        outcome: AuditOutcome,
        error: Option<ErrorToken>,
    },
}

#[derive(Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
enum CompletionOutcome {
    Applied,
    Aborted,
}

struct RecoveredState {
    identity: Option<IdentityBinding>,
    provider_sha256: Option<[u8; 32]>,
    reports: BTreeMap<String, ReportRecord>,
    pending: Option<PendingIntent>,
    active_agent: Option<ActiveAgentAudit>,
    agent_request_ids: BTreeSet<[u8; 16]>,
    tail: Option<TailEvent>,
}

impl RecoveredState {
    fn empty() -> Self {
        Self {
            identity: None,
            provider_sha256: None,
            reports: BTreeMap::new(),
            pending: None,
            active_agent: None,
            agent_request_ids: BTreeSet::new(),
            tail: None,
        }
    }

    // Application mutations other than Agent audit never inspect or change
    // the replay set. Keeping it out of their pre-append candidate avoids an
    // O(n) copy of as many as one million authenticated request identifiers.
    fn validation_candidate_without_agent_ids(&self) -> Self {
        Self {
            identity: self.identity.clone(),
            provider_sha256: self.provider_sha256,
            reports: self.reports.clone(),
            pending: self.pending.clone(),
            active_agent: self.active_agent,
            agent_request_ids: BTreeSet::new(),
            tail: self.tail.clone(),
        }
    }
}

#[derive(Clone)]
struct IdentityBinding {
    device_id: String,
    public_key_sha256: [u8; 32],
}

#[derive(Clone, Copy)]
struct ActiveAgentAudit {
    peer_uid: u32,
    peer_pid: u32,
    last_sequence: u64,
}

#[derive(Clone)]
struct ReportRecord {
    report_id: String,
    payload_sha256: [u8; 32],
    intent_sequence: u64,
    intent_entry_hash: [u8; 32],
    envelope_size: u64,
    envelope_sha256: [u8; 32],
}

#[derive(Clone)]
enum PendingIntent {
    ProviderConfigure {
        transaction_id: String,
        old_sha256: Option<[u8; 32]>,
        new_sha256: [u8; 32],
    },
    ProviderLogout {
        transaction_id: String,
        old_sha256: Option<[u8; 32]>,
    },
    ReportPersist {
        transaction_id: String,
        report_id: String,
        payload_sha256: [u8; 32],
        position: IntentPosition,
    },
}

#[derive(Clone, Copy)]
struct IntentPosition {
    sequence: u64,
    entry_hash: [u8; 32],
}

#[derive(Clone)]
enum TailEvent {
    Other,
    ConfigureApplied {
        transaction_id: String,
        old_sha256: [u8; 32],
        new_sha256: [u8; 32],
    },
    LogoutApplied {
        transaction_id: String,
        old_sha256: Option<[u8; 32]>,
    },
}

#[derive(Clone, Copy, PartialEq, Eq)]
struct AppFileState {
    device: u64,
    inode: u64,
    size: i64,
    mode: u32,
    uid: u32,
    gid: u32,
    links: u64,
    modified_seconds: i64,
    modified_nanos: u64,
    changed_seconds: i64,
    changed_nanos: u64,
}

impl AppFileState {
    fn from_stat(stat: &Stat) -> Self {
        Self {
            device: stat.st_dev,
            inode: stat.st_ino,
            size: stat.st_size,
            mode: stat.st_mode,
            uid: stat.st_uid,
            gid: stat.st_gid,
            links: stat.st_nlink,
            modified_seconds: stat.st_mtime,
            modified_nanos: stat.st_mtime_nsec,
            changed_seconds: stat.st_ctime,
            changed_nanos: stat.st_ctime_nsec,
        }
    }

    fn same_object(self, other: Self) -> bool {
        self.device == other.device && self.inode == other.inode
    }
}

#[derive(Default)]
struct ApplicationLayout {
    provider_present: bool,
    reports: BTreeMap<String, String>,
    stages: Vec<String>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ApplicationFaultPoint {
    IntentDurable,
    StageFileDurable,
    StageDirectoryDurable,
    FinalRenamed,
    FinalDirectoryDurable,
    CompleteDurable,
    StageRemovedBeforeDirectorySync,
    RecoveryDirectoryDurable,
    RecoveryCompleteDurable,
    RecoveryCleanupDirectoryDurable,
}

impl<'vault> RescueVaultApplicationStore<'vault> {
    pub(crate) fn open(inner: &'vault VaultInner) -> Result<Self, RescueApplicationStoreError> {
        Self::open_internal(inner, None)
    }

    fn open_internal(
        inner: &'vault VaultInner,
        recovery_fault: Option<ApplicationFaultPoint>,
    ) -> Result<Self, RescueApplicationStoreError> {
        let application_guard = inner
            .application_guard()
            .map_err(|_| RescueApplicationStoreError::StorageUnavailable)?;
        inner
            .ensure_integrity()
            .map_err(|_| RescueApplicationStoreError::CorruptApplicationState)?;

        // Identity is deliberately load-only here. Provisioning is a separate
        // privileged-probe operation and is unavailable through this surface.
        let identity = RescueDeviceIdentityStore { inner }
            .load_device_identity()
            .map_err(|_| RescueApplicationStoreError::CorruptApplicationState)?
            .ok_or(RescueApplicationStoreError::MissingDeviceIdentity)?;
        let device_id = identity.device_id();
        let public_key_sha256: [u8; 32] = Sha256::digest(identity.public_key()).into();

        let mut journal = inner
            .open_application_journal()
            .map_err(|_| RescueApplicationStoreError::CorruptJournal)?;
        let limits = JournalReplayLimits::new(MAX_AUDIT_SEQUENCE, MAX_APPLICATION_REPLAY_BYTES)
            .map_err(|_| RescueApplicationStoreError::CorruptJournal)?;
        let (state, summary) = journal
            .fold(limits, RecoveredState::empty(), |state, entry| {
                replay_application_event(state, entry)
            })
            .map_err(map_replay_error)?;

        let mut store = Self {
            inner,
            journal,
            identity,
            device_id,
            state,
            head: summary.head,
            healthy: true,
            _application_guard: application_guard,
            #[cfg(test)]
            fault: recovery_fault,
        };
        #[cfg(not(test))]
        let _ = recovery_fault;

        let layout = store.scan_layout()?;
        if store.head.sequence == 0 {
            if store.state.identity.is_some()
                || store.state.pending.is_some()
                || layout.provider_present
                || !layout.reports.is_empty()
                || !layout.stages.is_empty()
            {
                return Err(RescueApplicationStoreError::CorruptApplicationState);
            }
            store.append_event(ApplicationEvent::IdentityBound {
                device_id: store.device_id.clone(),
                public_key_sha256: encode_hex(&public_key_sha256),
            })?;
        }

        let binding = store
            .state
            .identity
            .as_ref()
            .ok_or(RescueApplicationStoreError::CorruptJournal)?;
        if binding.device_id != store.device_id || binding.public_key_sha256 != public_key_sha256 {
            return Err(RescueApplicationStoreError::CorruptJournal);
        }

        // Authenticated replay above is side-effect free. Only after it has
        // accepted the complete chain may a single tail intent be reconciled.
        store.recover_pending()?;
        store.cleanup_completed_logout_stage()?;
        store.validate_materialized_state_full()?;
        store.healthy = true;
        Ok(store)
    }

    /// Public device fingerprint bound by journal entry one.
    #[must_use]
    pub fn device_id(&self) -> &str {
        &self.device_id
    }

    pub fn provider_status(&self) -> Result<ProviderCredentialStatus, RescueApplicationStoreError> {
        self.ensure_ready()?;
        self.validate_provider_materialization()?;
        Ok(if self.state.provider_sha256.is_some() {
            ProviderCredentialStatus::Configured
        } else {
            ProviderCredentialStatus::Absent
        })
    }

    /// Configure or replace the one Rescue OpenAI key. The supplied
    /// allocation is erased on every return path.
    pub fn configure_openai_api_key(
        &mut self,
        api_key: Zeroizing<Vec<u8>>,
    ) -> Result<(), RescueApplicationStoreError> {
        self.ensure_ready()?;
        validate_openai_key(&api_key)?;
        self.validate_materialized_state()?;
        let old_sha256 = self.state.provider_sha256;
        let new_sha256: [u8; 32] = Sha256::digest(api_key.as_slice()).into();
        let transaction_id = generate_transaction_id();
        self.healthy = false;
        self.append_event(ApplicationEvent::ProviderConfigureIntent {
            transaction_id: transaction_id.clone(),
            old_sha256: old_sha256.as_ref().map(|hash| encode_hex(hash)),
            new_sha256: encode_hex(&new_sha256),
        })?;
        self.trip_fault(ApplicationFaultPoint::IntentDurable)?;

        let envelope = encode_provider_envelope(&api_key)?;
        self.create_stage(&transaction_id, &envelope)?;
        self.install_provider_stage(&transaction_id, old_sha256, new_sha256)?;
        self.append_event(ApplicationEvent::ProviderConfigureComplete {
            transaction_id: transaction_id.clone(),
            outcome: CompletionOutcome::Applied,
        })?;
        self.trip_fault(ApplicationFaultPoint::CompleteDurable)?;
        if old_sha256.is_some() {
            self.remove_stage(&transaction_id)?;
        }
        self.validate_provider_materialization()?;
        self.healthy = true;
        Ok(())
    }

    /// Borrow the key only for the duration of `use_secret`. There is no raw
    /// getter and the decoded allocation is zeroized immediately afterwards.
    pub fn with_openai_api_key<T>(
        &self,
        use_secret: impl FnOnce(&[u8]) -> T,
    ) -> Result<Option<T>, RescueApplicationStoreError> {
        self.ensure_ready()?;
        let Some(expected_hash) = self.state.provider_sha256 else {
            if self
                .read_optional(PROVIDER_FILE_NAME, MAX_PROVIDER_ENVELOPE_BYTES)?
                .is_some()
            {
                return Err(RescueApplicationStoreError::CorruptApplicationState);
            }
            return Ok(None);
        };
        let envelope = self
            .read_optional(PROVIDER_FILE_NAME, MAX_PROVIDER_ENVELOPE_BYTES)?
            .ok_or(RescueApplicationStoreError::CorruptApplicationState)?;
        let api_key = decode_provider_envelope(&envelope)?;
        if <[u8; 32]>::from(Sha256::digest(api_key.as_slice())) != expected_hash {
            return Err(RescueApplicationStoreError::CorruptApplicationState);
        }
        Ok(Some(use_secret(&api_key)))
    }

    /// Idempotently remove the OpenAI credential through a journaled
    /// tombstone transition. A crash never makes an uncommitted deletion look
    /// like a completed one.
    pub fn logout_openai(&mut self) -> Result<(), RescueApplicationStoreError> {
        self.ensure_ready()?;
        self.validate_materialized_state()?;
        let old_sha256 = self.state.provider_sha256;
        let transaction_id = generate_transaction_id();
        self.healthy = false;
        self.append_event(ApplicationEvent::ProviderLogoutIntent {
            transaction_id: transaction_id.clone(),
            old_sha256: old_sha256.as_ref().map(|hash| encode_hex(hash)),
        })?;
        self.trip_fault(ApplicationFaultPoint::IntentDurable)?;

        if let Some(expected_hash) = old_sha256 {
            self.move_provider_to_tombstone(&transaction_id, expected_hash)?;
        }
        self.append_event(ApplicationEvent::ProviderLogoutComplete {
            transaction_id: transaction_id.clone(),
            outcome: CompletionOutcome::Applied,
        })?;
        self.trip_fault(ApplicationFaultPoint::CompleteDurable)?;
        if old_sha256.is_some() {
            self.remove_stage(&transaction_id)?;
        }
        self.validate_provider_materialization()?;
        self.healthy = true;
        Ok(())
    }

    /// Append one already-authorized, closed Agent lifecycle claim. Agent
    /// sequence is distinct from journal sequence and must advance exactly by
    /// one within the fixed protocol ceiling.
    pub fn append_agent_audit(
        &mut self,
        request: &ValidatedRequest,
    ) -> Result<u64, RescueApplicationStoreError> {
        self.ensure_ready()?;
        if request.operation() != Operation::AuditAppend || request.role() != PeerRole::Agent {
            return Err(RescueApplicationStoreError::InvalidAgentAudit);
        }
        let RequestPayload::AuditAppend {
            sequence,
            event,
            outcome,
            error,
        } = request.payload()
        else {
            return Err(RescueApplicationStoreError::InvalidAgentAudit);
        };
        let peer_uid = request.peer_uid();
        let peer_pid = request.peer_pid();
        let request_id = decode_request_id(request.request_id().as_str())
            .map_err(|_| RescueApplicationStoreError::InvalidAgentAudit)?;
        if self.state.agent_request_ids.contains(&request_id) {
            return Err(RescueApplicationStoreError::StaleAgentSequence);
        }
        let next = self.expected_agent_audit_sequence(peer_uid, peer_pid, *event)?;
        if *sequence != next {
            return Err(RescueApplicationStoreError::StaleAgentSequence);
        }
        if (*outcome == AuditOutcome::Succeeded && error.is_some())
            || (*outcome != AuditOutcome::Succeeded && error.is_none())
        {
            return Err(RescueApplicationStoreError::InvalidAgentAudit);
        }
        self.validate_materialized_state()?;
        self.healthy = false;
        self.append_event(ApplicationEvent::AgentAuditAppend {
            request_id: request.request_id().as_str().to_owned(),
            sequence: *sequence,
            peer_uid,
            peer_pid,
            event: *event,
            outcome: *outcome,
            error: *error,
        })?;
        self.validate_materialized_state()?;
        self.healthy = true;
        Ok(*sequence)
    }

    fn expected_agent_audit_sequence(
        &self,
        peer_uid: u32,
        peer_pid: u32,
        event: AuditEventType,
    ) -> Result<u64, RescueApplicationStoreError> {
        self.ensure_ready()?;
        if peer_uid == 0 || peer_pid == 0 {
            return Err(RescueApplicationStoreError::InvalidAgentAudit);
        }
        if event == AuditEventType::AgentSessionStart {
            return Ok(1);
        }
        let active = self
            .state
            .active_agent
            .filter(|active| active.peer_uid == peer_uid && active.peer_pid == peer_pid)
            .ok_or(RescueApplicationStoreError::StaleAgentSequence)?;
        let next = active
            .last_sequence
            .checked_add(1)
            .ok_or(RescueApplicationStoreError::StaleAgentSequence)?;
        if next > MAX_AUDIT_SEQUENCE {
            return Err(RescueApplicationStoreError::StaleAgentSequence);
        }
        Ok(next)
    }

    /// Validate, hash, journal-bind, sign and durably persist one exact raw
    /// `SessionReport` document.
    pub fn persist_report(
        &mut self,
        report_id: &str,
        expected_payload_sha256: &[u8; 32],
        raw_report: Zeroizing<Vec<u8>>,
    ) -> Result<RescueReportSummary, RescueApplicationStoreError> {
        self.ensure_ready()?;
        validate_report_id(report_id)?;
        if raw_report.len() > MAX_SESSION_REPORT_BYTES
            || validate_session_report_json(&raw_report).is_err()
        {
            return Err(RescueApplicationStoreError::InvalidReport);
        }
        let payload_sha256: [u8; 32] = Sha256::digest(raw_report.as_slice()).into();
        if &payload_sha256 != expected_payload_sha256 {
            return Err(RescueApplicationStoreError::ReportHashMismatch);
        }
        self.validate_materialized_state()?;
        if self.state.reports.contains_key(report_id) {
            return Err(RescueApplicationStoreError::ReportAlreadyExists);
        }
        if self.state.reports.len() >= MAX_REPORTS {
            return Err(RescueApplicationStoreError::ReportLimitReached);
        }
        let final_name = report_filename(report_id)?;
        if self
            .read_optional(&final_name, MAX_SIGNED_REPORT_ENVELOPE_BYTES)?
            .is_some()
        {
            return Err(RescueApplicationStoreError::CorruptApplicationState);
        }

        let transaction_id = generate_transaction_id();
        self.healthy = false;
        self.append_event(ApplicationEvent::ReportPersistIntent {
            transaction_id: transaction_id.clone(),
            report_id: report_id.to_owned(),
            payload_sha256: encode_hex(&payload_sha256),
        })?;
        let position = match self.state.pending.as_ref() {
            Some(PendingIntent::ReportPersist { position, .. }) => *position,
            _ => return Err(RescueApplicationStoreError::CorruptJournal),
        };
        self.trip_fault(ApplicationFaultPoint::IntentDurable)?;

        let signed = ZeroizingSignedEnvelope(
            self.identity
                .sign_report_envelope(
                    &raw_report,
                    REPORT_MEDIA_TYPE,
                    position.sequence,
                    &position.entry_hash,
                )
                .map_err(|_| RescueApplicationStoreError::InvalidReport)?,
        );
        let envelope = Zeroizing::new(
            serde_json::to_vec(&signed.0)
                .map_err(|_| RescueApplicationStoreError::StorageUnavailable)?,
        );
        if !(2..=MAX_SIGNED_REPORT_ENVELOPE_BYTES).contains(&envelope.len()) {
            return Err(RescueApplicationStoreError::InvalidReport);
        }
        let envelope_sha256: [u8; 32] = Sha256::digest(envelope.as_slice()).into();
        self.create_stage(&transaction_id, &envelope)?;
        self.install_report_stage(&transaction_id, &final_name)?;
        let final_envelope = self
            .read_optional(&final_name, MAX_SIGNED_REPORT_ENVELOPE_BYTES)?
            .ok_or(RescueApplicationStoreError::WriteVerificationFailed)?;
        if final_envelope.as_slice() != envelope.as_slice() {
            return Err(RescueApplicationStoreError::WriteVerificationFailed);
        }
        verify_report_envelope(&final_envelope, &self.identity, &payload_sha256, position)?;
        self.append_event(ApplicationEvent::ReportPersistComplete {
            transaction_id,
            outcome: CompletionOutcome::Applied,
            envelope_size: Some(envelope.len() as u64),
            envelope_sha256: Some(encode_hex(&envelope_sha256)),
        })?;
        self.trip_fault(ApplicationFaultPoint::CompleteDurable)?;
        self.validate_materialized_state()?;
        self.healthy = true;
        self.state
            .reports
            .get(report_id)
            .map(report_summary)
            .ok_or(RescueApplicationStoreError::CorruptJournal)
    }

    /// Return the bounded authenticated report index after checking the
    /// filename/size bijection. Open verifies every envelope once; a later
    /// [`Self::with_report_envelope`] call re-verifies the requested file.
    pub fn list_reports(&self) -> Result<Vec<RescueReportSummary>, RescueApplicationStoreError> {
        self.ensure_ready()?;
        self.validate_materialized_state()?;
        Ok(self.state.reports.values().map(report_summary).collect())
    }

    /// Borrow one verified serialized signed envelope for a scoped response
    /// writer. The allocation is erased when the callback returns.
    pub fn with_report_envelope<T>(
        &self,
        report_id: &str,
        use_envelope: impl FnOnce(&[u8]) -> T,
    ) -> Result<Option<T>, RescueApplicationStoreError> {
        self.ensure_ready()?;
        validate_report_id(report_id)?;
        let Some(record) = self.state.reports.get(report_id) else {
            return Ok(None);
        };
        let envelope = self.read_and_verify_report(record)?;
        Ok(Some(use_envelope(&envelope)))
    }

    fn ensure_ready(&self) -> Result<(), RescueApplicationStoreError> {
        if self.healthy && self.state.pending.is_none() {
            Ok(())
        } else {
            Err(RescueApplicationStoreError::ReopenRequired)
        }
    }

    fn append_event(
        &mut self,
        event: ApplicationEvent,
    ) -> Result<IntentPosition, RescueApplicationStoreError> {
        let encoded = serialize_event(&event)?;
        let next_sequence = self
            .head
            .sequence
            .checked_add(1)
            .ok_or(RescueApplicationStoreError::CorruptJournal)?;
        if let ApplicationEvent::AgentAuditAppend {
            request_id,
            sequence,
            peer_uid,
            peer_pid,
            event,
            outcome,
            error,
        } = &event
        {
            validate_agent_audit_transition(
                &self.state,
                request_id,
                *sequence,
                *peer_uid,
                *peer_pid,
                *event,
                *outcome,
                *error,
            )?;
        } else {
            let mut candidate = self.state.validation_candidate_without_agent_ids();
            transition_state(
                &mut candidate,
                event.clone(),
                IntentPosition {
                    sequence: next_sequence,
                    entry_hash: [0; 32],
                },
            )?;
        }
        self.inner
            .ensure_integrity()
            .map_err(|_| RescueApplicationStoreError::CorruptApplicationState)?;
        self.inner
            .preflight_journal_layout()
            .map_err(|_| RescueApplicationStoreError::CorruptApplicationState)?;
        let entry = self
            .journal
            .append_expected(self.head, &encoded)
            .map_err(|_| RescueApplicationStoreError::CorruptJournal)?;
        let position = IntentPosition {
            sequence: entry.sequence,
            entry_hash: entry.entry_hash,
        };
        transition_state(&mut self.state, event, position).map_err(|_| {
            self.healthy = false;
            RescueApplicationStoreError::CorruptJournal
        })?;
        self.head = JournalAnchor {
            journal_id: self.head.journal_id,
            sequence: entry.sequence,
            entry_hash: entry.entry_hash,
        };
        self.inner
            .ensure_integrity()
            .map_err(|_| RescueApplicationStoreError::CorruptApplicationState)?;
        self.inner
            .preflight_journal_layout()
            .map_err(|_| RescueApplicationStoreError::CorruptApplicationState)?;
        Ok(position)
    }

    #[cfg(test)]
    fn trip_fault(
        &mut self,
        point: ApplicationFaultPoint,
    ) -> Result<(), RescueApplicationStoreError> {
        if self.fault == Some(point) {
            self.fault = None;
            return Err(RescueApplicationStoreError::StorageUnavailable);
        }
        Ok(())
    }

    #[cfg(not(test))]
    fn trip_fault(
        &mut self,
        _point: ApplicationFaultPoint,
    ) -> Result<(), RescueApplicationStoreError> {
        Ok(())
    }
}

fn replay_application_event(
    state: &mut RecoveredState,
    entry: JournalEntryRef<'_>,
) -> Result<(), RescueApplicationStoreError> {
    if entry.event.is_empty() || entry.event.len() > MAX_APPLICATION_EVENT_BYTES {
        return Err(RescueApplicationStoreError::CorruptJournal);
    }
    let event: ApplicationEvent = serde_json::from_slice(entry.event)
        .map_err(|_| RescueApplicationStoreError::CorruptJournal)?;
    let canonical =
        serde_json::to_vec(&event).map_err(|_| RescueApplicationStoreError::CorruptJournal)?;
    if canonical.as_slice() != entry.event {
        return Err(RescueApplicationStoreError::CorruptJournal);
    }
    transition_state(
        state,
        event,
        IntentPosition {
            sequence: entry.sequence,
            entry_hash: entry.entry_hash,
        },
    )
}

fn serialize_event(
    event: &ApplicationEvent,
) -> Result<Zeroizing<Vec<u8>>, RescueApplicationStoreError> {
    let encoded = Zeroizing::new(
        serde_json::to_vec(event).map_err(|_| RescueApplicationStoreError::StorageUnavailable)?,
    );
    if encoded.is_empty() || encoded.len() > MAX_APPLICATION_EVENT_BYTES {
        return Err(RescueApplicationStoreError::CorruptJournal);
    }
    Ok(encoded)
}

fn transition_state(
    state: &mut RecoveredState,
    event: ApplicationEvent,
    position: IntentPosition,
) -> Result<(), RescueApplicationStoreError> {
    if position.sequence == 1 {
        let ApplicationEvent::IdentityBound {
            device_id,
            public_key_sha256,
        } = event
        else {
            return Err(RescueApplicationStoreError::CorruptJournal);
        };
        if state.identity.is_some()
            || state.pending.is_some()
            || !state.reports.is_empty()
            || state.provider_sha256.is_some()
            || state.active_agent.is_some()
            || !state.agent_request_ids.is_empty()
            || kernaid_device_identity::validate_device_id(&device_id).is_err()
        {
            return Err(RescueApplicationStoreError::CorruptJournal);
        }
        state.identity = Some(IdentityBinding {
            device_id,
            public_key_sha256: decode_hash(&public_key_sha256)?,
        });
        state.tail = Some(TailEvent::Other);
        return Ok(());
    }
    if position.sequence == 0 || state.identity.is_none() {
        return Err(RescueApplicationStoreError::CorruptJournal);
    }

    match event {
        ApplicationEvent::IdentityBound { .. } => {
            return Err(RescueApplicationStoreError::CorruptJournal);
        }
        ApplicationEvent::ProviderConfigureIntent {
            transaction_id,
            old_sha256,
            new_sha256,
        } => {
            require_no_pending(state)?;
            validate_transaction_id(&transaction_id)?;
            let old_sha256 = decode_optional_hash(old_sha256.as_deref())?;
            let new_sha256 = decode_hash(&new_sha256)?;
            if old_sha256 != state.provider_sha256 {
                return Err(RescueApplicationStoreError::CorruptJournal);
            }
            state.pending = Some(PendingIntent::ProviderConfigure {
                transaction_id,
                old_sha256,
                new_sha256,
            });
            state.tail = Some(TailEvent::Other);
        }
        ApplicationEvent::ProviderConfigureComplete {
            transaction_id,
            outcome,
        } => {
            validate_transaction_id(&transaction_id)?;
            let Some(PendingIntent::ProviderConfigure {
                transaction_id: expected_transaction,
                old_sha256,
                new_sha256,
                ..
            }) = state.pending.take()
            else {
                return Err(RescueApplicationStoreError::CorruptJournal);
            };
            if transaction_id != expected_transaction {
                return Err(RescueApplicationStoreError::CorruptJournal);
            }
            state.provider_sha256 = match outcome {
                CompletionOutcome::Applied => Some(new_sha256),
                CompletionOutcome::Aborted => old_sha256,
            };
            state.tail = match (outcome, old_sha256) {
                (CompletionOutcome::Applied, Some(old_sha256)) => {
                    Some(TailEvent::ConfigureApplied {
                        transaction_id,
                        old_sha256,
                        new_sha256,
                    })
                }
                _ => Some(TailEvent::Other),
            };
        }
        ApplicationEvent::ProviderLogoutIntent {
            transaction_id,
            old_sha256,
        } => {
            require_no_pending(state)?;
            validate_transaction_id(&transaction_id)?;
            let old_sha256 = decode_optional_hash(old_sha256.as_deref())?;
            if old_sha256 != state.provider_sha256 {
                return Err(RescueApplicationStoreError::CorruptJournal);
            }
            state.pending = Some(PendingIntent::ProviderLogout {
                transaction_id,
                old_sha256,
            });
            state.tail = Some(TailEvent::Other);
        }
        ApplicationEvent::ProviderLogoutComplete {
            transaction_id,
            outcome,
        } => {
            validate_transaction_id(&transaction_id)?;
            let Some(PendingIntent::ProviderLogout {
                transaction_id: expected_transaction,
                old_sha256,
                ..
            }) = state.pending.take()
            else {
                return Err(RescueApplicationStoreError::CorruptJournal);
            };
            if transaction_id != expected_transaction {
                return Err(RescueApplicationStoreError::CorruptJournal);
            }
            state.provider_sha256 = match outcome {
                CompletionOutcome::Applied => None,
                CompletionOutcome::Aborted => old_sha256,
            };
            state.tail = match outcome {
                CompletionOutcome::Applied => Some(TailEvent::LogoutApplied {
                    transaction_id,
                    old_sha256,
                }),
                CompletionOutcome::Aborted => Some(TailEvent::Other),
            };
        }
        ApplicationEvent::ReportPersistIntent {
            transaction_id,
            report_id,
            payload_sha256,
        } => {
            require_no_pending(state)?;
            validate_transaction_id(&transaction_id)?;
            validate_report_id(&report_id)?;
            if state.reports.contains_key(&report_id) || state.reports.len() >= MAX_REPORTS {
                return Err(RescueApplicationStoreError::CorruptJournal);
            }
            state.pending = Some(PendingIntent::ReportPersist {
                transaction_id,
                report_id,
                payload_sha256: decode_hash(&payload_sha256)?,
                position,
            });
            state.tail = Some(TailEvent::Other);
        }
        ApplicationEvent::ReportPersistComplete {
            transaction_id,
            outcome,
            envelope_size,
            envelope_sha256,
        } => {
            validate_transaction_id(&transaction_id)?;
            let Some(PendingIntent::ReportPersist {
                transaction_id: expected_transaction,
                report_id,
                payload_sha256,
                position: intent_position,
            }) = state.pending.take()
            else {
                return Err(RescueApplicationStoreError::CorruptJournal);
            };
            if transaction_id != expected_transaction {
                return Err(RescueApplicationStoreError::CorruptJournal);
            }
            match outcome {
                CompletionOutcome::Applied => {
                    let size = envelope_size
                        .filter(|size| (2..=MAX_SIGNED_REPORT_ENVELOPE_BYTES as u64).contains(size))
                        .ok_or(RescueApplicationStoreError::CorruptJournal)?;
                    let hash = decode_hash(
                        envelope_sha256
                            .as_deref()
                            .ok_or(RescueApplicationStoreError::CorruptJournal)?,
                    )?;
                    if state.reports.len() >= MAX_REPORTS || state.reports.contains_key(&report_id)
                    {
                        return Err(RescueApplicationStoreError::CorruptJournal);
                    }
                    state.reports.insert(
                        report_id.clone(),
                        ReportRecord {
                            report_id,
                            payload_sha256,
                            intent_sequence: intent_position.sequence,
                            intent_entry_hash: intent_position.entry_hash,
                            envelope_size: size,
                            envelope_sha256: hash,
                        },
                    );
                }
                CompletionOutcome::Aborted => {
                    if envelope_size.is_some() || envelope_sha256.is_some() {
                        return Err(RescueApplicationStoreError::CorruptJournal);
                    }
                }
            }
            state.tail = Some(TailEvent::Other);
        }
        ApplicationEvent::AgentAuditAppend {
            request_id,
            sequence,
            peer_uid,
            peer_pid,
            event,
            outcome,
            error,
        } => {
            let request_id = validate_agent_audit_transition(
                state,
                &request_id,
                sequence,
                peer_uid,
                peer_pid,
                event,
                outcome,
                error,
            )?;
            if event == AuditEventType::AgentSessionStart {
                if outcome == AuditOutcome::Succeeded {
                    state.active_agent = Some(ActiveAgentAudit {
                        peer_uid,
                        peer_pid,
                        last_sequence: sequence,
                    });
                }
            } else {
                let active = state
                    .active_agent
                    .as_mut()
                    .filter(|active| active.peer_uid == peer_uid && active.peer_pid == peer_pid)
                    .ok_or(RescueApplicationStoreError::CorruptJournal)?;
                let expected = active
                    .last_sequence
                    .checked_add(1)
                    .ok_or(RescueApplicationStoreError::CorruptJournal)?;
                if sequence != expected || sequence > MAX_AUDIT_SEQUENCE {
                    return Err(RescueApplicationStoreError::CorruptJournal);
                }
                active.last_sequence = sequence;
                if event == AuditEventType::AgentSessionEnd {
                    state.active_agent = None;
                }
            }
            if !state.agent_request_ids.insert(request_id) {
                return Err(RescueApplicationStoreError::CorruptJournal);
            }
            state.tail = Some(TailEvent::Other);
        }
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn validate_agent_audit_transition(
    state: &RecoveredState,
    request_id: &str,
    sequence: u64,
    peer_uid: u32,
    peer_pid: u32,
    event: AuditEventType,
    outcome: AuditOutcome,
    error: Option<ErrorToken>,
) -> Result<[u8; 16], RescueApplicationStoreError> {
    require_no_pending(state)?;
    let request_id = decode_request_id(request_id)?;
    if state.agent_request_ids.contains(&request_id)
        || state.agent_request_ids.len() >= MAX_AUDIT_SEQUENCE as usize
        || peer_uid == 0
        || peer_pid == 0
        || (outcome == AuditOutcome::Succeeded && error.is_some())
        || (outcome != AuditOutcome::Succeeded && error.is_none())
    {
        return Err(RescueApplicationStoreError::CorruptJournal);
    }
    if event == AuditEventType::AgentSessionStart {
        if sequence != 1 {
            return Err(RescueApplicationStoreError::CorruptJournal);
        }
    } else {
        let active = state
            .active_agent
            .filter(|active| active.peer_uid == peer_uid && active.peer_pid == peer_pid)
            .ok_or(RescueApplicationStoreError::CorruptJournal)?;
        let expected = active
            .last_sequence
            .checked_add(1)
            .ok_or(RescueApplicationStoreError::CorruptJournal)?;
        if sequence != expected || sequence > MAX_AUDIT_SEQUENCE {
            return Err(RescueApplicationStoreError::CorruptJournal);
        }
    }
    Ok(request_id)
}

fn require_no_pending(state: &RecoveredState) -> Result<(), RescueApplicationStoreError> {
    if state.pending.is_some() {
        Err(RescueApplicationStoreError::CorruptJournal)
    } else {
        Ok(())
    }
}

fn map_replay_error(
    error: JournalReplayError<RescueApplicationStoreError>,
) -> RescueApplicationStoreError {
    match error {
        JournalReplayError::Journal(_) => RescueApplicationStoreError::CorruptJournal,
        JournalReplayError::Callback(_) => RescueApplicationStoreError::CorruptJournal,
    }
}

impl RescueVaultApplicationStore<'_> {
    fn recover_pending(&mut self) -> Result<(), RescueApplicationStoreError> {
        let Some(pending) = self.state.pending.clone() else {
            return Ok(());
        };
        self.healthy = false;
        match pending {
            PendingIntent::ProviderConfigure {
                transaction_id,
                old_sha256,
                new_sha256,
            } => self.recover_provider_configure(&transaction_id, old_sha256, new_sha256),
            PendingIntent::ProviderLogout {
                transaction_id,
                old_sha256,
            } => self.recover_provider_logout(&transaction_id, old_sha256),
            PendingIntent::ReportPersist {
                transaction_id,
                report_id,
                payload_sha256,
                position,
            } => self.recover_report(&transaction_id, &report_id, payload_sha256, position),
        }
    }

    fn recover_provider_configure(
        &mut self,
        transaction_id: &str,
        old_sha256: Option<[u8; 32]>,
        new_sha256: [u8; 32],
    ) -> Result<(), RescueApplicationStoreError> {
        let layout = self.scan_layout()?;
        require_only_expected_stage(&layout, transaction_id)?;
        let stage_name = stage_filename(transaction_id)?;
        let final_state = self.observe_provider_file(PROVIDER_FILE_NAME)?;
        let stage_state = self.observe_provider_file(&stage_name)?;
        let (outcome, applied_stage_sha256) = match old_sha256 {
            None => match (final_state, stage_state) {
                (ObservedProvider::Valid(final_hash), ObservedProvider::Missing)
                    if final_hash == new_sha256 =>
                {
                    (CompletionOutcome::Applied, None)
                }
                (ObservedProvider::Missing, ObservedProvider::Valid(stage_hash))
                    if stage_hash == new_sha256 =>
                {
                    self.install_provider_stage(transaction_id, None, new_sha256)?;
                    (CompletionOutcome::Applied, None)
                }
                (ObservedProvider::Missing, ObservedProvider::Missing) => {
                    (CompletionOutcome::Aborted, None)
                }
                (ObservedProvider::Missing, ObservedProvider::Invalid) => {
                    self.remove_stage(transaction_id)?;
                    (CompletionOutcome::Aborted, None)
                }
                _ => return Err(RescueApplicationStoreError::CorruptApplicationState),
            },
            Some(old_hash) => match (final_state, stage_state) {
                (ObservedProvider::Valid(final_hash), ObservedProvider::Valid(stage_hash))
                    if final_hash == old_hash && stage_hash == new_sha256 =>
                {
                    self.install_provider_stage(transaction_id, Some(old_hash), new_sha256)?;
                    (CompletionOutcome::Applied, Some(old_hash))
                }
                (ObservedProvider::Valid(final_hash), ObservedProvider::Valid(stage_hash))
                    if final_hash == new_sha256 && stage_hash == old_hash =>
                {
                    (CompletionOutcome::Applied, Some(old_hash))
                }
                (ObservedProvider::Valid(final_hash), ObservedProvider::Missing)
                    if final_hash == old_hash =>
                {
                    (CompletionOutcome::Aborted, None)
                }
                (ObservedProvider::Valid(final_hash), ObservedProvider::Missing)
                    if final_hash == new_sha256 =>
                {
                    (CompletionOutcome::Applied, None)
                }
                (ObservedProvider::Missing, ObservedProvider::Valid(stage_hash))
                    if stage_hash == old_hash =>
                {
                    self.rename_noreplace(&stage_name, PROVIDER_FILE_NAME)?;
                    self.sync_state_directory()?;
                    if self.read_provider_hash(PROVIDER_FILE_NAME)? != Some(old_hash) {
                        return Err(RescueApplicationStoreError::WriteVerificationFailed);
                    }
                    (CompletionOutcome::Aborted, None)
                }
                (ObservedProvider::Missing, ObservedProvider::Valid(stage_hash))
                    if stage_hash == new_sha256 =>
                {
                    self.rename_noreplace(&stage_name, PROVIDER_FILE_NAME)?;
                    self.sync_state_directory()?;
                    if self.read_provider_hash(PROVIDER_FILE_NAME)? != Some(new_sha256) {
                        return Err(RescueApplicationStoreError::WriteVerificationFailed);
                    }
                    (CompletionOutcome::Applied, None)
                }
                (ObservedProvider::Valid(final_hash), ObservedProvider::Invalid)
                    if final_hash == old_hash =>
                {
                    self.remove_stage(transaction_id)?;
                    (CompletionOutcome::Aborted, None)
                }
                (ObservedProvider::Invalid, ObservedProvider::Valid(stage_hash))
                    if stage_hash == old_hash =>
                {
                    self.exchange_named(PROVIDER_FILE_NAME, &stage_name)?;
                    self.sync_state_directory()?;
                    if self.read_provider_hash(PROVIDER_FILE_NAME)? != Some(old_hash) {
                        return Err(RescueApplicationStoreError::WriteVerificationFailed);
                    }
                    self.remove_stage(transaction_id)?;
                    (CompletionOutcome::Aborted, None)
                }
                _ => return Err(RescueApplicationStoreError::CorruptApplicationState),
            },
        };
        // A process may have crashed after a rename, exchange, or invalid
        // stage removal became visible but before its directory entry was
        // durable. Persist and re-read the complete expected namespace before
        // either Applied or Aborted can become journal-durable.
        let expected_final_sha256 = match outcome {
            CompletionOutcome::Applied => Some(new_sha256),
            CompletionOutcome::Aborted => old_sha256,
        };
        self.sync_state_directory()?;
        if self.read_provider_hash(PROVIDER_FILE_NAME)? != expected_final_sha256
            || self.read_provider_hash(&stage_name)? != applied_stage_sha256
        {
            return Err(RescueApplicationStoreError::WriteVerificationFailed);
        }
        self.trip_fault(ApplicationFaultPoint::RecoveryDirectoryDurable)?;
        self.append_event(ApplicationEvent::ProviderConfigureComplete {
            transaction_id: transaction_id.to_owned(),
            outcome,
        })?;
        self.trip_fault(ApplicationFaultPoint::RecoveryCompleteDurable)?;
        if outcome == CompletionOutcome::Applied
            && old_sha256.is_some()
            && self.stat_optional(&stage_name)?.is_some()
        {
            self.remove_stage(transaction_id)?;
        }
        self.healthy = true;
        Ok(())
    }

    fn recover_provider_logout(
        &mut self,
        transaction_id: &str,
        old_sha256: Option<[u8; 32]>,
    ) -> Result<(), RescueApplicationStoreError> {
        let layout = self.scan_layout()?;
        require_only_expected_stage(&layout, transaction_id)?;
        let final_hash = self.read_provider_hash(PROVIDER_FILE_NAME)?;
        let stage_hash = self.read_provider_hash(&stage_filename(transaction_id)?)?;
        match old_sha256 {
            None if final_hash.is_none() && stage_hash.is_none() => {}
            Some(expected) if final_hash == Some(expected) && stage_hash.is_none() => {
                self.move_provider_to_tombstone(transaction_id, expected)?;
            }
            Some(expected) if final_hash.is_none() && stage_hash == Some(expected) => {}
            _ => return Err(RescueApplicationStoreError::CorruptApplicationState),
        }
        // The tombstone rename can be visible after a process crash without
        // yet surviving power loss. Make the observed deletion/tombstone pair
        // durable and verify it again before committing the journal outcome.
        self.sync_state_directory()?;
        if self.read_provider_hash(PROVIDER_FILE_NAME)?.is_some()
            || self.read_provider_hash(&stage_filename(transaction_id)?)? != old_sha256
        {
            return Err(RescueApplicationStoreError::WriteVerificationFailed);
        }
        self.trip_fault(ApplicationFaultPoint::RecoveryDirectoryDurable)?;
        self.append_event(ApplicationEvent::ProviderLogoutComplete {
            transaction_id: transaction_id.to_owned(),
            outcome: CompletionOutcome::Applied,
        })?;
        self.trip_fault(ApplicationFaultPoint::RecoveryCompleteDurable)?;
        if old_sha256.is_some() {
            self.remove_stage(transaction_id)?;
        }
        self.healthy = true;
        Ok(())
    }

    fn recover_report(
        &mut self,
        transaction_id: &str,
        report_id: &str,
        payload_sha256: [u8; 32],
        position: IntentPosition,
    ) -> Result<(), RescueApplicationStoreError> {
        let layout = self.scan_layout()?;
        require_only_expected_stage(&layout, transaction_id)?;
        let final_name = report_filename(report_id)?;
        let final_bytes = self.read_optional(&final_name, MAX_SIGNED_REPORT_ENVELOPE_BYTES)?;
        let stage_name = stage_filename(transaction_id)?;
        let stage_bytes = self.read_optional(&stage_name, MAX_SIGNED_REPORT_ENVELOPE_BYTES)?;
        if final_bytes.is_some() && stage_bytes.is_some() {
            return Err(RescueApplicationStoreError::CorruptApplicationState);
        }

        let materialized = if let Some(bytes) = final_bytes {
            Some(report_materialization(
                &bytes,
                &self.identity,
                &payload_sha256,
                position,
            )?)
        } else if let Some(bytes) = stage_bytes {
            match report_materialization(&bytes, &self.identity, &payload_sha256, position) {
                Ok(materialization) => {
                    self.install_report_stage(transaction_id, &final_name)?;
                    let persisted = self
                        .read_optional(&final_name, MAX_SIGNED_REPORT_ENVELOPE_BYTES)?
                        .ok_or(RescueApplicationStoreError::WriteVerificationFailed)?;
                    let verified = report_materialization(
                        &persisted,
                        &self.identity,
                        &payload_sha256,
                        position,
                    )?;
                    if verified != materialization {
                        return Err(RescueApplicationStoreError::WriteVerificationFailed);
                    }
                    Some(verified)
                }
                Err(_) => {
                    self.remove_stage(transaction_id)?;
                    None
                }
            }
        } else {
            None
        };

        // Both a final rename and an invalid-stage unlink can be visible
        // without being durable. Persist the reconciled namespace and verify
        // its exact final/stage state before either completion outcome.
        self.sync_state_directory()?;
        let durable_stage = self.read_optional(&stage_name, MAX_SIGNED_REPORT_ENVELOPE_BYTES)?;
        let durable_final = self.read_optional(&final_name, MAX_SIGNED_REPORT_ENVELOPE_BYTES)?;
        let materialized = match materialized {
            Some(expected) => {
                if durable_stage.is_some() {
                    return Err(RescueApplicationStoreError::CorruptApplicationState);
                }
                let persisted =
                    durable_final.ok_or(RescueApplicationStoreError::WriteVerificationFailed)?;
                let verified =
                    report_materialization(&persisted, &self.identity, &payload_sha256, position)?;
                if verified != expected {
                    return Err(RescueApplicationStoreError::WriteVerificationFailed);
                }
                Some(verified)
            }
            None => {
                if durable_final.is_some() || durable_stage.is_some() {
                    return Err(RescueApplicationStoreError::WriteVerificationFailed);
                }
                None
            }
        };
        self.trip_fault(ApplicationFaultPoint::RecoveryDirectoryDurable)?;

        let (outcome, envelope_size, envelope_sha256) = match materialized {
            Some(materialization) => (
                CompletionOutcome::Applied,
                Some(materialization.size),
                Some(encode_hex(&materialization.sha256)),
            ),
            None => (CompletionOutcome::Aborted, None, None),
        };
        self.append_event(ApplicationEvent::ReportPersistComplete {
            transaction_id: transaction_id.to_owned(),
            outcome,
            envelope_size,
            envelope_sha256,
        })?;
        self.trip_fault(ApplicationFaultPoint::RecoveryCompleteDurable)?;
        self.healthy = true;
        Ok(())
    }

    fn cleanup_completed_logout_stage(&mut self) -> Result<(), RescueApplicationStoreError> {
        let layout = self.scan_layout()?;
        if layout.stages.is_empty() {
            // Absence may be the visible result of a prior unlink that died
            // before directory fsync. Make it durable before this store can
            // become healthy and append an unrelated future tail event.
            self.sync_state_directory()?;
            if !self.scan_layout()?.stages.is_empty() {
                return Err(RescueApplicationStoreError::ConcurrentWrite);
            }
            self.trip_fault(ApplicationFaultPoint::RecoveryCleanupDirectoryDurable)?;
            return Ok(());
        }
        let (transaction_id, expected_stage_hash, expected_final_hash) =
            match self.state.tail.clone() {
                Some(TailEvent::ConfigureApplied {
                    transaction_id,
                    old_sha256,
                    new_sha256,
                }) => (transaction_id, old_sha256, Some(new_sha256)),
                Some(TailEvent::LogoutApplied {
                    transaction_id,
                    old_sha256: Some(old_sha256),
                }) => (transaction_id, old_sha256, None),
                _ => return Err(RescueApplicationStoreError::CorruptApplicationState),
            };
        if self.read_provider_hash(PROVIDER_FILE_NAME)? != expected_final_hash
            || self.read_provider_hash(&stage_filename(&transaction_id)?)?
                != Some(expected_stage_hash)
        {
            return Err(RescueApplicationStoreError::CorruptApplicationState);
        }
        require_only_expected_stage(&layout, &transaction_id)?;
        self.remove_stage(&transaction_id)?;
        if !self.scan_layout()?.stages.is_empty() {
            return Err(RescueApplicationStoreError::ConcurrentWrite);
        }
        self.trip_fault(ApplicationFaultPoint::RecoveryCleanupDirectoryDurable)
    }
}

fn open_child(
    directory: &OwnedFd,
    path: &Path,
    flags: OFlags,
    mode: Mode,
) -> Result<OwnedFd, rustix::io::Errno> {
    rfs::openat2(
        directory,
        path,
        flags,
        mode,
        ResolveFlags::BENEATH
            | ResolveFlags::NO_SYMLINKS
            | ResolveFlags::NO_MAGICLINKS
            | ResolveFlags::NO_XDEV,
    )
}

fn descriptor_mount_id(descriptor: impl AsFd) -> Result<u64, RescueApplicationStoreError> {
    let stat = rfs::statx(
        descriptor,
        "",
        AtFlags::EMPTY_PATH | AtFlags::NO_AUTOMOUNT | AtFlags::SYMLINK_NOFOLLOW,
        StatxFlags::MNT_ID,
    )
    .map_err(|_| RescueApplicationStoreError::StorageUnavailable)?;
    if !StatxFlags::from_bits_retain(stat.stx_mask).contains(StatxFlags::MNT_ID)
        || stat.stx_mnt_id == 0
    {
        return Err(RescueApplicationStoreError::StorageUnavailable);
    }
    Ok(stat.stx_mnt_id)
}

fn is_core_state_name(name: &str) -> bool {
    matches!(
        name,
        JOURNAL_KEY_NAME
            | JOURNAL_ANCHOR_NAME
            | DEVICE_IDENTITY_NAME
            | JOURNAL_DATABASE_NAME
            | JOURNAL_WAL_NAME
            | JOURNAL_SHM_NAME
    )
}

fn validate_literal_name(name: &str) -> Result<(), RescueApplicationStoreError> {
    if name.is_empty()
        || name.len() > MAX_LAYOUT_NAME_BYTES
        || !name.is_ascii()
        || name == "."
        || name == ".."
        || name.as_bytes().contains(&b'/')
        || name.as_bytes().contains(&0)
    {
        return Err(RescueApplicationStoreError::CorruptApplicationState);
    }
    Ok(())
}

fn validate_transaction_id(value: &str) -> Result<(), RescueApplicationStoreError> {
    if value.len() != 32
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
    {
        return Err(RescueApplicationStoreError::CorruptJournal);
    }
    Ok(())
}

fn generate_transaction_id() -> String {
    let mut bytes = [0_u8; 16];
    OsRng.fill_bytes(&mut bytes);
    encode_hex(&bytes)
}

fn stage_filename(transaction_id: &str) -> Result<String, RescueApplicationStoreError> {
    validate_transaction_id(transaction_id)?;
    Ok(format!("{STAGE_FILE_PREFIX}{transaction_id}"))
}

fn require_only_expected_stage(
    layout: &ApplicationLayout,
    transaction_id: &str,
) -> Result<(), RescueApplicationStoreError> {
    let expected = stage_filename(transaction_id)?;
    if layout.stages.is_empty() || (layout.stages.len() == 1 && layout.stages[0] == expected) {
        Ok(())
    } else {
        Err(RescueApplicationStoreError::CorruptApplicationState)
    }
}

fn validate_report_id(value: &str) -> Result<(), RescueApplicationStoreError> {
    let Some(uuid) = value.strip_prefix("RP-") else {
        return Err(RescueApplicationStoreError::InvalidReportIdentifier);
    };
    if uuid.len() != 36
        || !uuid.bytes().enumerate().all(|(index, byte)| match index {
            8 | 13 | 18 | 23 => byte == b'-',
            _ => byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'),
        })
    {
        return Err(RescueApplicationStoreError::InvalidReportIdentifier);
    }
    Ok(())
}

fn decode_request_id(value: &str) -> Result<[u8; 16], RescueApplicationStoreError> {
    let Some(uuid) = value.strip_prefix("R-") else {
        return Err(RescueApplicationStoreError::CorruptJournal);
    };
    if uuid.len() != 36
        || !uuid.bytes().enumerate().all(|(index, byte)| match index {
            8 | 13 | 18 | 23 => byte == b'-',
            _ => byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'),
        })
    {
        return Err(RescueApplicationStoreError::CorruptJournal);
    }

    let mut decoded = [0_u8; 16];
    let mut nibble_index = 0_usize;
    for byte in uuid.bytes().filter(|byte| *byte != b'-') {
        let nibble = decode_hex_nibble(byte)?;
        let destination = nibble_index / 2;
        if nibble_index % 2 == 0 {
            decoded[destination] = nibble << 4;
        } else {
            decoded[destination] |= nibble;
        }
        nibble_index += 1;
    }
    if nibble_index != 32 {
        return Err(RescueApplicationStoreError::CorruptJournal);
    }
    Ok(decoded)
}

fn report_filename(report_id: &str) -> Result<String, RescueApplicationStoreError> {
    validate_report_id(report_id)?;
    Ok(format!(
        "{REPORT_FILE_PREFIX}{report_id}{REPORT_FILE_SUFFIX}"
    ))
}

fn report_id_from_filename(name: &str) -> Option<&str> {
    let report_id = name
        .strip_prefix(REPORT_FILE_PREFIX)?
        .strip_suffix(REPORT_FILE_SUFFIX)?;
    validate_report_id(report_id).ok()?;
    (report_filename(report_id).ok()?.as_str() == name).then_some(report_id)
}

fn validate_openai_key(api_key: &[u8]) -> Result<(), RescueApplicationStoreError> {
    if !(1..=MAX_PROVIDER_KEY_BYTES).contains(&api_key.len())
        || !api_key.iter().all(|byte| (0x21..=0x7e).contains(byte))
    {
        return Err(RescueApplicationStoreError::InvalidProviderCredential);
    }
    Ok(())
}

fn encode_provider_envelope(
    api_key: &[u8],
) -> Result<Zeroizing<Vec<u8>>, RescueApplicationStoreError> {
    validate_openai_key(api_key)?;
    let encoded_len = base64::encoded_len(api_key.len(), false)
        .ok_or(RescueApplicationStoreError::InvalidProviderCredential)?;
    let mut encoded = Zeroizing::new(vec![0_u8; encoded_len]);
    let written = URL_SAFE_NO_PAD
        .encode_slice(api_key, encoded.as_mut_slice())
        .map_err(|_| RescueApplicationStoreError::InvalidProviderCredential)?;
    encoded.truncate(written);
    let mut envelope = Zeroizing::new(Vec::with_capacity(
        PROVIDER_ENVELOPE_PREFIX.len() + encoded.len() + 1,
    ));
    envelope.extend_from_slice(PROVIDER_ENVELOPE_PREFIX);
    envelope.extend_from_slice(&encoded);
    envelope.push(b'\n');
    if envelope.len() > MAX_PROVIDER_ENVELOPE_BYTES {
        return Err(RescueApplicationStoreError::InvalidProviderCredential);
    }
    Ok(envelope)
}

fn decode_provider_envelope(
    envelope: &[u8],
) -> Result<Zeroizing<Vec<u8>>, RescueApplicationStoreError> {
    if envelope.len() > MAX_PROVIDER_ENVELOPE_BYTES
        || !envelope.starts_with(PROVIDER_ENVELOPE_PREFIX)
        || !envelope.ends_with(b"\n")
    {
        return Err(RescueApplicationStoreError::InvalidProviderCredential);
    }
    let encoded = &envelope[PROVIDER_ENVELOPE_PREFIX.len()..envelope.len() - 1];
    if encoded.is_empty() || encoded.contains(&b'=') {
        return Err(RescueApplicationStoreError::InvalidProviderCredential);
    }
    let mut decoded = Zeroizing::new(vec![0_u8; base64::decoded_len_estimate(encoded.len())]);
    let written = URL_SAFE_NO_PAD
        .decode_slice(encoded, decoded.as_mut_slice())
        .map_err(|_| RescueApplicationStoreError::InvalidProviderCredential)?;
    decoded.truncate(written);
    validate_openai_key(&decoded)?;
    let canonical = encode_provider_envelope(&decoded)?;
    if canonical.as_slice() != envelope {
        return Err(RescueApplicationStoreError::InvalidProviderCredential);
    }
    Ok(decoded)
}

fn encode_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut encoded = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        encoded.push(char::from(HEX[usize::from(byte >> 4)]));
        encoded.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    encoded
}

fn decode_hash(value: &str) -> Result<[u8; 32], RescueApplicationStoreError> {
    if value.len() != 64 {
        return Err(RescueApplicationStoreError::CorruptJournal);
    }
    let mut decoded = [0_u8; 32];
    for (destination, pair) in decoded.iter_mut().zip(value.as_bytes().chunks_exact(2)) {
        *destination = decode_hex_nibble(pair[0])?
            .checked_mul(16)
            .and_then(|high| high.checked_add(decode_hex_nibble(pair[1]).ok()?))
            .ok_or(RescueApplicationStoreError::CorruptJournal)?;
    }
    Ok(decoded)
}

fn decode_hex_nibble(byte: u8) -> Result<u8, RescueApplicationStoreError> {
    match byte {
        b'0'..=b'9' => Ok(byte - b'0'),
        b'a'..=b'f' => Ok(byte - b'a' + 10),
        _ => Err(RescueApplicationStoreError::CorruptJournal),
    }
}

fn decode_optional_hash(
    value: Option<&str>,
) -> Result<Option<[u8; 32]>, RescueApplicationStoreError> {
    value.map(decode_hash).transpose()
}

fn report_summary(record: &ReportRecord) -> RescueReportSummary {
    RescueReportSummary {
        report_id: record.report_id.clone(),
        envelope_size: record.envelope_size,
        envelope_sha256: record.envelope_sha256,
    }
}

fn verify_report_envelope(
    envelope_bytes: &[u8],
    identity: &DeviceIdentity,
    expected_payload_sha256: &[u8; 32],
    position: IntentPosition,
) -> Result<(), RescueApplicationStoreError> {
    report_materialization(envelope_bytes, identity, expected_payload_sha256, position).map(|_| ())
}

fn report_materialization(
    envelope_bytes: &[u8],
    identity: &DeviceIdentity,
    expected_payload_sha256: &[u8; 32],
    position: IntentPosition,
) -> Result<ReportMaterialization, RescueApplicationStoreError> {
    if !(2..=MAX_SIGNED_REPORT_ENVELOPE_BYTES).contains(&envelope_bytes.len()) {
        return Err(RescueApplicationStoreError::InvalidReport);
    }
    let envelope = ZeroizingSignedEnvelope(
        serde_json::from_slice::<SignedReportEnvelope>(envelope_bytes)
            .map_err(|_| RescueApplicationStoreError::InvalidReport)?,
    );
    let canonical = Zeroizing::new(
        serde_json::to_vec(&envelope.0).map_err(|_| RescueApplicationStoreError::InvalidReport)?,
    );
    if canonical.as_slice() != envelope_bytes
        || envelope.0.payload_media_type != REPORT_MEDIA_TYPE
        || envelope.0.journal_sequence != position.sequence
        || envelope.0.journal_entry_hash != URL_SAFE_NO_PAD.encode(position.entry_hash)
    {
        return Err(RescueApplicationStoreError::InvalidReport);
    }
    let payload = envelope
        .0
        .verify_zeroizing(&identity.public_key())
        .map_err(|_| RescueApplicationStoreError::InvalidReport)?;
    if <[u8; 32]>::from(Sha256::digest(payload.as_slice())) != *expected_payload_sha256
        || validate_session_report_json(payload.as_slice()).is_err()
    {
        return Err(RescueApplicationStoreError::InvalidReport);
    }
    Ok(ReportMaterialization {
        size: envelope_bytes.len() as u64,
        sha256: Sha256::digest(envelope_bytes).into(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{VAULT_MARKER_NAME, VAULT_MARKER_V1, VaultOwner};
    use std::{
        fs::{self, OpenOptions},
        os::unix::fs::{OpenOptionsExt, PermissionsExt, symlink},
        path::{Path, PathBuf},
    };
    use tempfile::TempDir;

    const REPORT_ID: &str = "RP-12345678-1234-1234-1234-123456789abc";
    const VALID_REPORT: &[u8] =
        include_bytes!("../../../packages/schemas/testdata/session-report/valid/baseline.raw");

    struct Fixture {
        _temporary: TempDir,
        root: PathBuf,
        owner: VaultOwner,
    }

    impl Fixture {
        fn new() -> Self {
            let temporary = tempfile::tempdir().expect("temporary directory");
            let root = temporary.path().join("vault");
            fs::create_dir(&root).expect("create vault root");
            fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).expect("vault mode");
            write_secure(&root.join(VAULT_MARKER_NAME), VAULT_MARKER_V1);
            let state = root.join(".kernaid-secure-state-v1");
            fs::create_dir(&state).expect("create state directory");
            fs::set_permissions(&state, fs::Permissions::from_mode(0o700)).expect("state mode");
            write_secure(&root.join(".kernaid-rescue-secrets.lock"), b"");
            Self {
                _temporary: temporary,
                root,
                owner: VaultOwner::effective(),
            }
        }

        fn open_vault(&self) -> crate::linux::RescueVaultSecrets {
            crate::linux::RescueVaultSecrets::open_for_test(&self.root, self.owner)
                .expect("open fixture vault")
        }

        fn provision_identity(&self) -> String {
            let vault = self.open_vault();
            vault
                .device_identity_store()
                .create_device_identity()
                .expect("provision identity")
                .device_id()
        }

        fn state_path(&self, name: &str) -> PathBuf {
            self.root.join(".kernaid-secure-state-v1").join(name)
        }
    }

    fn write_secure(path: &Path, bytes: &[u8]) {
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(FILE_MODE)
            .open(path)
            .expect("create secure fixture file");
        file.write_all(bytes).expect("write secure fixture file");
        file.sync_all().expect("sync secure fixture file");
    }

    fn only_stage_path(fixture: &Fixture) -> PathBuf {
        let state_directory = fixture.state_path(".");
        let mut stages = fs::read_dir(&state_directory)
            .expect("read state directory")
            .filter_map(Result::ok)
            .map(|entry| entry.path())
            .filter(|path| {
                path.file_name()
                    .and_then(|name| name.to_str())
                    .is_some_and(|name| name.starts_with(STAGE_FILE_PREFIX))
            });
        let stage = stages.next().expect("one application stage");
        assert!(stages.next().is_none(), "only one application stage");
        stage
    }

    fn report_hash() -> [u8; 32] {
        Sha256::digest(VALID_REPORT).into()
    }

    fn audit_request(
        sequence: u64,
        event: AuditEventType,
        outcome: AuditOutcome,
        error: Option<ErrorToken>,
    ) -> ValidatedRequest {
        use kernaid_protocol::rescue_vault::{
            API_VERSION, PeerAllowlist, authenticate_seqpacket_peer,
        };
        use rustix::net::{AddressFamily, SendFlags, SocketFlags, SocketType, socketpair};
        use std::sync::atomic::{AtomicU64, Ordering};
        use std::time::{Duration, Instant};

        static NEXT_REQUEST: AtomicU64 = AtomicU64::new(1);

        let (peer_socket, server_socket) = socketpair(
            AddressFamily::UNIX,
            SocketType::SEQPACKET,
            SocketFlags::CLOEXEC,
            None,
        )
        .expect("create authenticated seqpacket pair");
        let credentials = rustix::net::sockopt::socket_peercred(&peer_socket)
            .expect("read test peer credentials");
        let uid = credentials.uid.as_raw();
        assert_ne!(uid, 0, "test Agent must be unprivileged");
        let companion_uid = if uid == 1 { 2 } else { 1 };
        let peer = authenticate_seqpacket_peer(
            server_socket.as_fd(),
            PeerAllowlist::new(companion_uid, uid).expect("valid Agent allowlist"),
        )
        .expect("authenticate Agent peer");
        let payload = serde_json::json!({
            "sequence": sequence,
            "event": event,
            "outcome": outcome,
            "error": error,
        });
        let request_id = format!(
            "R-00000000-0000-0000-0000-{:012x}",
            NEXT_REQUEST.fetch_add(1, Ordering::Relaxed)
        );
        let datagram = serde_json::to_vec(&serde_json::json!({
            "apiVersion": API_VERSION,
            "requestId": request_id,
            "expectedStateVersion": 0,
            "operation": "audit.append",
            "payload": payload,
        }))
        .expect("serialize audit request");
        assert_eq!(
            rustix::net::send(
                peer_socket.as_fd(),
                &datagram,
                SendFlags::NOSIGNAL | SendFlags::DONTWAIT,
            )
            .expect("send authenticated audit request"),
            datagram.len()
        );
        peer.receive_request(Instant::now() + Duration::from_secs(2))
            .expect("receive authenticated audit request")
    }

    fn application_journal_len(fixture: &Fixture) -> usize {
        let vault = fixture.open_vault();
        vault
            .open_journal()
            .expect("open raw test journal")
            .entries()
            .expect("read raw test journal")
            .len()
    }

    fn fail_recovery_at(
        fixture: &Fixture,
        point: ApplicationFaultPoint,
    ) -> RescueApplicationStoreError {
        let vault = fixture.open_vault();
        RescueVaultApplicationStore::open_internal(&vault.inner, Some(point))
            .err()
            .expect("recovery fault must interrupt open")
    }

    #[test]
    fn identity_is_load_only_and_binds_the_first_journal_entry() {
        let fixture = Fixture::new();
        {
            let vault = fixture.open_vault();
            assert!(matches!(
                vault.open_application_store(),
                Err(RescueApplicationStoreError::MissingDeviceIdentity)
            ));
        }
        assert!(!fixture.state_path(JOURNAL_DATABASE_NAME).exists());

        let expected_device_id = fixture.provision_identity();
        {
            let vault = fixture.open_vault();
            let store = vault
                .open_application_store()
                .expect("open initialized application store");
            assert_eq!(store.device_id(), expected_device_id);
        }
        let vault = fixture.open_vault();
        let mut journal = vault.open_journal().expect("open raw test journal");
        let entries = journal.entries().expect("read application journal");
        assert_eq!(entries.len(), 1);
        assert!(
            entries[0]
                .event
                .starts_with(b"{\"type\":\"vault.identity.bound\"")
        );
    }

    #[test]
    fn provider_roundtrip_is_callback_only_and_logout_is_idempotent() {
        let fixture = Fixture::new();
        fixture.provision_identity();
        {
            let vault = fixture.open_vault();
            let mut store = vault
                .open_application_store()
                .expect("open application store");
            assert_eq!(
                store.provider_status().expect("provider status"),
                ProviderCredentialStatus::Absent
            );
            assert_eq!(
                store
                    .with_openai_api_key(|_| ())
                    .expect("borrow absent key"),
                None
            );
            store
                .configure_openai_api_key(Zeroizing::new(
                    b"TEST_ONLY_PROVIDER_VALUE_BASIC".to_vec(),
                ))
                .expect("configure key");
            assert_eq!(
                store
                    .with_openai_api_key(|key| key == b"TEST_ONLY_PROVIDER_VALUE_BASIC")
                    .expect("borrow configured key"),
                Some(true)
            );
            store.logout_openai().expect("logout key");
            store.logout_openai().expect("idempotent logout");
        }
        let vault = fixture.open_vault();
        let store = vault
            .open_application_store()
            .expect("reopen application store");
        assert_eq!(
            store.provider_status().expect("provider status"),
            ProviderCredentialStatus::Absent
        );
    }

    #[test]
    fn report_roundtrip_verifies_the_named_final_envelope() {
        let fixture = Fixture::new();
        fixture.provision_identity();
        {
            let vault = fixture.open_vault();
            let mut store = vault
                .open_application_store()
                .expect("open application store");
            let summary = store
                .persist_report(
                    REPORT_ID,
                    &report_hash(),
                    Zeroizing::new(VALID_REPORT.to_vec()),
                )
                .expect("persist report");
            assert_eq!(summary.report_id(), REPORT_ID);
            assert_eq!(store.list_reports().expect("list reports"), vec![summary]);
            assert_eq!(
                store
                    .with_report_envelope(REPORT_ID, |bytes| {
                        serde_json::from_slice::<SignedReportEnvelope>(bytes).is_ok()
                    })
                    .expect("borrow envelope"),
                Some(true)
            );
            assert_eq!(
                store
                    .with_report_envelope("RP-aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa", |_| ())
                    .expect("missing envelope"),
                None
            );
        }
        let vault = fixture.open_vault();
        let store = vault.open_application_store().expect("reopen report store");
        assert_eq!(store.list_reports().expect("list reports").len(), 1);
    }

    #[test]
    fn agent_lifecycle_sequence_survives_reopen_and_new_start_is_explicit() {
        let fixture = Fixture::new();
        fixture.provision_identity();
        {
            let vault = fixture.open_vault();
            let mut store = vault
                .open_application_store()
                .expect("open application store");
            store
                .append_agent_audit(&audit_request(
                    1,
                    AuditEventType::AgentSessionStart,
                    AuditOutcome::Succeeded,
                    None,
                ))
                .expect("start lifecycle");
            store
                .append_agent_audit(&audit_request(
                    2,
                    AuditEventType::AgentDiagnosisComplete,
                    AuditOutcome::Failed,
                    Some(ErrorToken::IoFailed),
                ))
                .expect("diagnosis lifecycle");
        }
        {
            let vault = fixture.open_vault();
            let mut store = vault
                .open_application_store()
                .expect("reopen application store");
            assert!(matches!(
                store.append_agent_audit(&audit_request(
                    4,
                    AuditEventType::AgentSessionEnd,
                    AuditOutcome::Succeeded,
                    None,
                )),
                Err(RescueApplicationStoreError::StaleAgentSequence)
            ));
            store
                .append_agent_audit(&audit_request(
                    3,
                    AuditEventType::AgentSessionEnd,
                    AuditOutcome::Succeeded,
                    None,
                ))
                .expect("end lifecycle");
            assert_eq!(
                store
                    .append_agent_audit(&audit_request(
                        1,
                        AuditEventType::AgentSessionStart,
                        AuditOutcome::Succeeded,
                        None,
                    ))
                    .expect("new lifecycle"),
                1
            );
        }
    }

    #[test]
    fn replayed_request_is_rejected_and_failed_start_preserves_active_lifecycle() {
        let fixture = Fixture::new();
        fixture.provision_identity();
        {
            let vault = fixture.open_vault();
            let mut store = vault
                .open_application_store()
                .expect("open application store");
            let start = audit_request(
                1,
                AuditEventType::AgentSessionStart,
                AuditOutcome::Succeeded,
                None,
            );
            store.append_agent_audit(&start).expect("start lifecycle");
            let head_before_replay = store.head;
            assert!(matches!(
                store.append_agent_audit(&start),
                Err(RescueApplicationStoreError::StaleAgentSequence)
            ));
            assert_eq!(store.head.sequence, head_before_replay.sequence);
            assert_eq!(store.head.entry_hash, head_before_replay.entry_hash);
            let failed_start = audit_request(
                1,
                AuditEventType::AgentSessionStart,
                AuditOutcome::Failed,
                Some(ErrorToken::Busy),
            );
            store
                .append_agent_audit(&failed_start)
                .expect("record failed restart without replacing active lifecycle");
            store
                .append_agent_audit(&audit_request(
                    2,
                    AuditEventType::AgentDiagnosisComplete,
                    AuditOutcome::Succeeded,
                    None,
                ))
                .expect("failed restart preserves the original next sequence");
            store
                .append_agent_audit(&audit_request(
                    1,
                    AuditEventType::AgentSessionStart,
                    AuditOutcome::Succeeded,
                    None,
                ))
                .expect("successful same-peer restart explicitly resets lifecycle");
        }
        {
            let vault = fixture.open_vault();
            let mut store = vault
                .open_application_store()
                .expect("reopen healthy lifecycle");
            store
                .append_agent_audit(&audit_request(
                    2,
                    AuditEventType::AgentDiagnosisComplete,
                    AuditOutcome::Succeeded,
                    None,
                ))
                .expect("continue explicitly reset lifecycle");
        }
        let vault = fixture.open_vault();
        let mut journal = vault.open_journal().expect("open raw test journal");
        assert_eq!(journal.entries().expect("journal entries").len(), 6);
    }

    #[test]
    fn historical_agent_request_replays_never_cross_lifecycle_boundaries() {
        let fixture = Fixture::new();
        fixture.provision_identity();
        {
            let vault = fixture.open_vault();
            let mut store = vault
                .open_application_store()
                .expect("open application store");
            let start = audit_request(
                1,
                AuditEventType::AgentSessionStart,
                AuditOutcome::Succeeded,
                None,
            );
            let diagnosis = audit_request(
                2,
                AuditEventType::AgentDiagnosisComplete,
                AuditOutcome::Succeeded,
                None,
            );
            let end = audit_request(
                3,
                AuditEventType::AgentSessionEnd,
                AuditOutcome::Succeeded,
                None,
            );
            store.append_agent_audit(&start).expect("append A");
            store.append_agent_audit(&diagnosis).expect("append B");
            store.append_agent_audit(&end).expect("append C");

            let head_after_first_lifecycle = store.head;
            assert!(matches!(
                store.append_agent_audit(&start),
                Err(RescueApplicationStoreError::StaleAgentSequence)
            ));
            assert_eq!(store.head.sequence, head_after_first_lifecycle.sequence);
            assert_eq!(store.head.entry_hash, head_after_first_lifecycle.entry_hash);

            store
                .append_agent_audit(&audit_request(
                    1,
                    AuditEventType::AgentSessionStart,
                    AuditOutcome::Succeeded,
                    None,
                ))
                .expect("append D");
            let head_after_new_start = store.head;
            assert!(matches!(
                store.append_agent_audit(&diagnosis),
                Err(RescueApplicationStoreError::StaleAgentSequence)
            ));
            assert_eq!(store.head.sequence, head_after_new_start.sequence);
            assert_eq!(store.head.entry_hash, head_after_new_start.entry_hash);
            store
                .append_agent_audit(&audit_request(
                    2,
                    AuditEventType::AgentDiagnosisComplete,
                    AuditOutcome::Succeeded,
                    None,
                ))
                .expect("append E");
        }
        {
            let vault = fixture.open_vault();
            vault
                .open_application_store()
                .expect("reopen after rejected historical replays");
        }
        let vault = fixture.open_vault();
        let mut journal = vault.open_journal().expect("open raw test journal");
        assert_eq!(journal.entries().expect("journal entries").len(), 6);
    }

    #[test]
    fn noncanonical_or_unbound_journal_events_fail_closed() {
        for event in [
            b"arbitrary legacy event".as_slice(),
            b"{ \"type\":\"vault.identity.bound\",\"deviceId\":\"KA-000000000000000000000000\",\"publicKeySha256\":\"0000000000000000000000000000000000000000000000000000000000000000\"}".as_slice(),
        ] {
            let fixture = Fixture::new();
            fixture.provision_identity();
            {
                let vault = fixture.open_vault();
                vault
                    .open_journal()
                    .expect("open raw test journal")
                    .append(event)
                    .expect("append invalid application event");
            }
            let vault = fixture.open_vault();
            assert!(matches!(
                vault.open_application_store(),
                Err(RescueApplicationStoreError::CorruptJournal)
            ));
        }
    }

    #[test]
    fn unsafe_provider_and_stray_report_paths_fail_closed() {
        let fixture = Fixture::new();
        fixture.provision_identity();
        {
            let vault = fixture.open_vault();
            let mut store = vault
                .open_application_store()
                .expect("open application store");
            store
                .configure_openai_api_key(Zeroizing::new(
                    b"TEST_ONLY_PROVIDER_VALUE_HARDLINK".to_vec(),
                ))
                .expect("configure key");
        }
        fs::hard_link(
            fixture.state_path(PROVIDER_FILE_NAME),
            fixture.state_path("provider-hardlink"),
        )
        .expect("hardlink provider");
        let vault = fixture.open_vault();
        assert!(vault.open_application_store().is_err());
        drop(vault);

        fs::remove_file(fixture.state_path("provider-hardlink")).expect("remove hardlink");
        let stray = fixture.state_path("report-v1-RP-aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa.json");
        symlink(fixture.state_path(PROVIDER_FILE_NAME), stray)
            .expect("create stray report symlink");
        let vault = fixture.open_vault();
        assert!(vault.open_application_store().is_err());
    }

    #[test]
    fn a_second_application_store_fails_immediately_then_reopens_after_drop() {
        let fixture = Fixture::new();
        fixture.provision_identity();
        let vault = fixture.open_vault();
        let first = vault
            .open_application_store()
            .expect("open first application store");
        let started = std::time::Instant::now();
        assert!(matches!(
            vault.open_application_store(),
            Err(RescueApplicationStoreError::StorageUnavailable)
        ));
        assert!(started.elapsed() < std::time::Duration::from_secs(1));
        drop(first);
        vault
            .open_application_store()
            .expect("open after first store is dropped");
    }

    #[test]
    fn configure_crash_boundaries_recover_or_abort_deterministically() {
        let cases = [
            (ApplicationFaultPoint::IntentDurable, false),
            (ApplicationFaultPoint::StageFileDurable, true),
            (ApplicationFaultPoint::StageDirectoryDurable, true),
            (ApplicationFaultPoint::FinalRenamed, true),
            (ApplicationFaultPoint::FinalDirectoryDurable, true),
            (ApplicationFaultPoint::CompleteDurable, true),
        ];
        for (fault, should_apply) in cases {
            let fixture = Fixture::new();
            fixture.provision_identity();
            {
                let vault = fixture.open_vault();
                let mut store = vault
                    .open_application_store()
                    .expect("open application store");
                store.fault = Some(fault);
                assert!(matches!(
                    store.configure_openai_api_key(Zeroizing::new(
                        b"TEST_ONLY_PROVIDER_VALUE_CRASH_NEW".to_vec()
                    )),
                    Err(RescueApplicationStoreError::StorageUnavailable)
                ));
                assert!(matches!(
                    store.provider_status(),
                    Err(RescueApplicationStoreError::ReopenRequired)
                ));
            }
            let vault = fixture.open_vault();
            let store = vault
                .open_application_store()
                .expect("recover configured provider");
            assert_eq!(
                store.provider_status().expect("provider status"),
                if should_apply {
                    ProviderCredentialStatus::Configured
                } else {
                    ProviderCredentialStatus::Absent
                },
                "fault boundary {fault:?}"
            );
        }

        for (fault, should_apply) in [
            (ApplicationFaultPoint::IntentDurable, false),
            (ApplicationFaultPoint::StageFileDurable, true),
            (ApplicationFaultPoint::StageDirectoryDurable, true),
            (ApplicationFaultPoint::FinalRenamed, true),
            (ApplicationFaultPoint::FinalDirectoryDurable, true),
            (ApplicationFaultPoint::CompleteDurable, true),
        ] {
            let fixture = Fixture::new();
            fixture.provision_identity();
            {
                let vault = fixture.open_vault();
                let mut store = vault
                    .open_application_store()
                    .expect("open application store");
                store
                    .configure_openai_api_key(Zeroizing::new(
                        b"TEST_ONLY_PROVIDER_VALUE_CRASH_OLD".to_vec(),
                    ))
                    .expect("configure old key");
                store.fault = Some(fault);
                assert!(
                    store
                        .configure_openai_api_key(Zeroizing::new(
                            b"TEST_ONLY_PROVIDER_VALUE_CRASH_REPLACEMENT".to_vec(),
                        ))
                        .is_err()
                );
            }
            let vault = fixture.open_vault();
            let store = vault.open_application_store().expect("recover replacement");
            assert_eq!(
                store
                    .with_openai_api_key(|key| {
                        key == if should_apply {
                            b"TEST_ONLY_PROVIDER_VALUE_CRASH_REPLACEMENT".as_slice()
                        } else {
                            b"TEST_ONLY_PROVIDER_VALUE_CRASH_OLD".as_slice()
                        }
                    })
                    .expect("borrow recovered key"),
                Some(true),
                "replacement boundary {fault:?}"
            );
        }
    }

    #[test]
    fn corrupted_new_value_after_exchange_rolls_back_the_retained_old_value() {
        let fixture = Fixture::new();
        fixture.provision_identity();
        {
            let vault = fixture.open_vault();
            let mut store = vault
                .open_application_store()
                .expect("open application store");
            store
                .configure_openai_api_key(Zeroizing::new(
                    b"TEST_ONLY_PROVIDER_VALUE_ROLLBACK_OLD".to_vec(),
                ))
                .expect("configure old value");
            store.fault = Some(ApplicationFaultPoint::FinalRenamed);
            assert!(
                store
                    .configure_openai_api_key(Zeroizing::new(
                        b"TEST_ONLY_PROVIDER_VALUE_ROLLBACK_NEW".to_vec(),
                    ))
                    .is_err()
            );
        }
        fs::write(
            fixture.state_path(PROVIDER_FILE_NAME),
            b"corrupt-exchanged-new-value",
        )
        .expect("corrupt exchanged new value");
        fs::set_permissions(
            fixture.state_path(PROVIDER_FILE_NAME),
            fs::Permissions::from_mode(FILE_MODE),
        )
        .expect("restore provider mode");

        let vault = fixture.open_vault();
        let store = vault
            .open_application_store()
            .expect("roll back to retained old value");
        assert_eq!(
            store
                .with_openai_api_key(|key| { key == b"TEST_ONLY_PROVIDER_VALUE_ROLLBACK_OLD" })
                .expect("borrow rolled-back provider value"),
            Some(true)
        );
    }

    #[test]
    fn missing_provider_final_recovers_from_the_hash_bound_exchange_stage() {
        for (fault, expected) in [
            (
                ApplicationFaultPoint::FinalRenamed,
                b"TEST_ONLY_PROVIDER_VALUE_MISSING_FINAL_OLD".as_slice(),
            ),
            (
                ApplicationFaultPoint::StageDirectoryDurable,
                b"TEST_ONLY_PROVIDER_VALUE_MISSING_FINAL_NEW".as_slice(),
            ),
        ] {
            let fixture = Fixture::new();
            fixture.provision_identity();
            {
                let vault = fixture.open_vault();
                let mut store = vault
                    .open_application_store()
                    .expect("open application store");
                store
                    .configure_openai_api_key(Zeroizing::new(
                        b"TEST_ONLY_PROVIDER_VALUE_MISSING_FINAL_OLD".to_vec(),
                    ))
                    .expect("configure old value");
                store.fault = Some(fault);
                assert!(
                    store
                        .configure_openai_api_key(Zeroizing::new(
                            b"TEST_ONLY_PROVIDER_VALUE_MISSING_FINAL_NEW".to_vec(),
                        ))
                        .is_err()
                );
            }
            assert!(only_stage_path(&fixture).is_file());
            fs::remove_file(fixture.state_path(PROVIDER_FILE_NAME))
                .expect("simulate missing provider final");

            let vault = fixture.open_vault();
            let store = vault
                .open_application_store()
                .expect("recover the authenticated stage");
            assert_eq!(
                store
                    .with_openai_api_key(|key| key == expected)
                    .expect("borrow recovered provider"),
                Some(true),
                "fault boundary {fault:?}"
            );
        }
    }

    #[test]
    fn installed_new_provider_remains_applied_if_old_exchange_stage_is_missing() {
        let fixture = Fixture::new();
        fixture.provision_identity();
        {
            let vault = fixture.open_vault();
            let mut store = vault
                .open_application_store()
                .expect("open application store");
            store
                .configure_openai_api_key(Zeroizing::new(
                    b"TEST_ONLY_PROVIDER_VALUE_STAGE_LOST_OLD".to_vec(),
                ))
                .expect("configure old value");
            store.fault = Some(ApplicationFaultPoint::FinalRenamed);
            assert!(
                store
                    .configure_openai_api_key(Zeroizing::new(
                        b"TEST_ONLY_PROVIDER_VALUE_STAGE_LOST_NEW".to_vec(),
                    ))
                    .is_err()
            );
        }
        fs::remove_file(only_stage_path(&fixture)).expect("simulate missing old exchange stage");

        let vault = fixture.open_vault();
        let store = vault
            .open_application_store()
            .expect("complete authenticated installed replacement");
        assert_eq!(
            store
                .with_openai_api_key(|key| key == b"TEST_ONLY_PROVIDER_VALUE_STAGE_LOST_NEW")
                .expect("borrow installed replacement"),
            Some(true)
        );
    }

    #[test]
    fn logout_crash_boundaries_always_converge_to_absent() {
        for fault in [
            ApplicationFaultPoint::IntentDurable,
            ApplicationFaultPoint::FinalRenamed,
            ApplicationFaultPoint::FinalDirectoryDurable,
            ApplicationFaultPoint::CompleteDurable,
        ] {
            let fixture = Fixture::new();
            fixture.provision_identity();
            {
                let vault = fixture.open_vault();
                let mut store = vault
                    .open_application_store()
                    .expect("open application store");
                store
                    .configure_openai_api_key(Zeroizing::new(
                        b"TEST_ONLY_PROVIDER_VALUE_LOGOUT_CRASH".to_vec(),
                    ))
                    .expect("configure key");
                store.fault = Some(fault);
                assert!(store.logout_openai().is_err());
            }
            let vault = fixture.open_vault();
            let store = vault.open_application_store().expect("recover logout");
            assert_eq!(
                store.provider_status().expect("provider status"),
                ProviderCredentialStatus::Absent,
                "logout boundary {fault:?}"
            );
        }
    }

    #[test]
    fn report_crash_boundaries_recover_only_a_durable_envelope() {
        let cases = [
            (ApplicationFaultPoint::IntentDurable, false),
            (ApplicationFaultPoint::StageFileDurable, true),
            (ApplicationFaultPoint::StageDirectoryDurable, true),
            (ApplicationFaultPoint::FinalRenamed, true),
            (ApplicationFaultPoint::FinalDirectoryDurable, true),
            (ApplicationFaultPoint::CompleteDurable, true),
        ];
        for (fault, should_apply) in cases {
            let fixture = Fixture::new();
            fixture.provision_identity();
            {
                let vault = fixture.open_vault();
                let mut store = vault
                    .open_application_store()
                    .expect("open application store");
                store.fault = Some(fault);
                assert!(
                    store
                        .persist_report(
                            REPORT_ID,
                            &report_hash(),
                            Zeroizing::new(VALID_REPORT.to_vec()),
                        )
                        .is_err()
                );
            }
            let vault = fixture.open_vault();
            let store = vault.open_application_store().expect("recover report");
            assert_eq!(
                store.list_reports().expect("list recovered reports").len(),
                usize::from(should_apply),
                "report boundary {fault:?}"
            );
        }
    }

    #[test]
    fn recovery_fsyncs_visible_namespace_before_any_applied_complete() {
        {
            let fixture = Fixture::new();
            fixture.provision_identity();
            {
                let vault = fixture.open_vault();
                let mut store = vault
                    .open_application_store()
                    .expect("open configure fixture");
                store.fault = Some(ApplicationFaultPoint::FinalRenamed);
                assert!(
                    store
                        .configure_openai_api_key(Zeroizing::new(
                            b"TEST_ONLY_PROVIDER_VALUE_RECOVERY_ORDER".to_vec(),
                        ))
                        .is_err()
                );
            }
            let pending_entries = application_journal_len(&fixture);
            assert_eq!(
                fail_recovery_at(&fixture, ApplicationFaultPoint::RecoveryDirectoryDurable),
                RescueApplicationStoreError::StorageUnavailable
            );
            assert_eq!(application_journal_len(&fixture), pending_entries);
            assert_eq!(
                fail_recovery_at(&fixture, ApplicationFaultPoint::RecoveryCompleteDurable),
                RescueApplicationStoreError::StorageUnavailable
            );
            assert_eq!(application_journal_len(&fixture), pending_entries + 1);
            let vault = fixture.open_vault();
            let store = vault
                .open_application_store()
                .expect("reopen configure after complete crash");
            assert_eq!(
                store
                    .with_openai_api_key(|key| {
                        key == b"TEST_ONLY_PROVIDER_VALUE_RECOVERY_ORDER"
                    })
                    .expect("borrow recovery-ordered key"),
                Some(true)
            );
        }

        {
            let fixture = Fixture::new();
            fixture.provision_identity();
            {
                let vault = fixture.open_vault();
                let mut store = vault.open_application_store().expect("open logout fixture");
                store
                    .configure_openai_api_key(Zeroizing::new(
                        b"TEST_ONLY_PROVIDER_VALUE_LOGOUT_ORDER".to_vec(),
                    ))
                    .expect("configure logout fixture");
                store.fault = Some(ApplicationFaultPoint::FinalRenamed);
                assert!(store.logout_openai().is_err());
            }
            let pending_entries = application_journal_len(&fixture);
            assert_eq!(
                fail_recovery_at(&fixture, ApplicationFaultPoint::RecoveryDirectoryDurable),
                RescueApplicationStoreError::StorageUnavailable
            );
            assert_eq!(application_journal_len(&fixture), pending_entries);
            assert_eq!(
                fail_recovery_at(&fixture, ApplicationFaultPoint::RecoveryCompleteDurable),
                RescueApplicationStoreError::StorageUnavailable
            );
            assert_eq!(application_journal_len(&fixture), pending_entries + 1);
            assert_eq!(
                fail_recovery_at(
                    &fixture,
                    ApplicationFaultPoint::StageRemovedBeforeDirectorySync,
                ),
                RescueApplicationStoreError::StorageUnavailable
            );
            assert_eq!(application_journal_len(&fixture), pending_entries + 1);
            assert_eq!(
                fail_recovery_at(
                    &fixture,
                    ApplicationFaultPoint::RecoveryCleanupDirectoryDurable,
                ),
                RescueApplicationStoreError::StorageUnavailable
            );
            assert_eq!(application_journal_len(&fixture), pending_entries + 1);
            let vault = fixture.open_vault();
            let store = vault
                .open_application_store()
                .expect("reopen logout after complete crash");
            assert_eq!(
                store.provider_status().expect("logout provider status"),
                ProviderCredentialStatus::Absent
            );
        }

        {
            let fixture = Fixture::new();
            fixture.provision_identity();
            {
                let vault = fixture.open_vault();
                let mut store = vault.open_application_store().expect("open report fixture");
                store.fault = Some(ApplicationFaultPoint::FinalRenamed);
                assert!(
                    store
                        .persist_report(
                            REPORT_ID,
                            &report_hash(),
                            Zeroizing::new(VALID_REPORT.to_vec()),
                        )
                        .is_err()
                );
            }
            let pending_entries = application_journal_len(&fixture);
            assert_eq!(
                fail_recovery_at(&fixture, ApplicationFaultPoint::RecoveryDirectoryDurable),
                RescueApplicationStoreError::StorageUnavailable
            );
            assert_eq!(application_journal_len(&fixture), pending_entries);
            assert_eq!(
                fail_recovery_at(&fixture, ApplicationFaultPoint::RecoveryCompleteDurable),
                RescueApplicationStoreError::StorageUnavailable
            );
            assert_eq!(application_journal_len(&fixture), pending_entries + 1);
            let vault = fixture.open_vault();
            let store = vault
                .open_application_store()
                .expect("reopen report after complete crash");
            assert_eq!(
                store.list_reports().expect("list recovered report").len(),
                1
            );
            assert_eq!(
                store
                    .with_report_envelope(REPORT_ID, |_| true)
                    .expect("verify recovered report"),
                Some(true)
            );
        }
    }

    #[test]
    fn recovery_fsyncs_stage_removal_before_any_aborted_complete() {
        {
            let fixture = Fixture::new();
            fixture.provision_identity();
            {
                let vault = fixture.open_vault();
                let mut store = vault
                    .open_application_store()
                    .expect("open aborted configure fixture");
                store.fault = Some(ApplicationFaultPoint::StageDirectoryDurable);
                assert!(
                    store
                        .configure_openai_api_key(Zeroizing::new(
                            b"TEST_ONLY_PROVIDER_VALUE_ABORT_ORDER".to_vec(),
                        ))
                        .is_err()
                );
            }
            let stage = only_stage_path(&fixture);
            fs::write(&stage, b"invalid-provider-stage").expect("corrupt provider stage");
            let pending_entries = application_journal_len(&fixture);
            assert_eq!(
                fail_recovery_at(
                    &fixture,
                    ApplicationFaultPoint::StageRemovedBeforeDirectorySync,
                ),
                RescueApplicationStoreError::StorageUnavailable
            );
            assert_eq!(application_journal_len(&fixture), pending_entries);
            assert!(!stage.exists(), "invalid provider stage unlink is visible");
            assert_eq!(
                fail_recovery_at(&fixture, ApplicationFaultPoint::RecoveryDirectoryDurable),
                RescueApplicationStoreError::StorageUnavailable
            );
            assert_eq!(application_journal_len(&fixture), pending_entries);
            assert_eq!(
                fail_recovery_at(&fixture, ApplicationFaultPoint::RecoveryCompleteDurable),
                RescueApplicationStoreError::StorageUnavailable
            );
            assert_eq!(application_journal_len(&fixture), pending_entries + 1);
            let vault = fixture.open_vault();
            let store = vault
                .open_application_store()
                .expect("reopen aborted configure after complete crash");
            assert_eq!(
                store.provider_status().expect("provider status"),
                ProviderCredentialStatus::Absent
            );
        }

        {
            let fixture = Fixture::new();
            fixture.provision_identity();
            {
                let vault = fixture.open_vault();
                let mut store = vault
                    .open_application_store()
                    .expect("open aborted report fixture");
                store.fault = Some(ApplicationFaultPoint::StageDirectoryDurable);
                assert!(
                    store
                        .persist_report(
                            REPORT_ID,
                            &report_hash(),
                            Zeroizing::new(VALID_REPORT.to_vec()),
                        )
                        .is_err()
                );
            }
            let stage = only_stage_path(&fixture);
            fs::write(&stage, b"{}").expect("corrupt report stage");
            let pending_entries = application_journal_len(&fixture);
            assert_eq!(
                fail_recovery_at(
                    &fixture,
                    ApplicationFaultPoint::StageRemovedBeforeDirectorySync,
                ),
                RescueApplicationStoreError::StorageUnavailable
            );
            assert_eq!(application_journal_len(&fixture), pending_entries);
            assert!(!stage.exists(), "invalid report stage unlink is visible");
            assert_eq!(
                fail_recovery_at(&fixture, ApplicationFaultPoint::RecoveryDirectoryDurable),
                RescueApplicationStoreError::StorageUnavailable
            );
            assert_eq!(application_journal_len(&fixture), pending_entries);
            assert_eq!(
                fail_recovery_at(&fixture, ApplicationFaultPoint::RecoveryCompleteDurable),
                RescueApplicationStoreError::StorageUnavailable
            );
            assert_eq!(application_journal_len(&fixture), pending_entries + 1);
            let vault = fixture.open_vault();
            let store = vault
                .open_application_store()
                .expect("reopen aborted report after complete crash");
            assert!(
                store
                    .list_reports()
                    .expect("list aborted reports")
                    .is_empty()
            );
        }
    }

    #[test]
    fn report_content_tamper_and_unexpected_stage_fail_closed() {
        let fixture = Fixture::new();
        fixture.provision_identity();
        {
            let vault = fixture.open_vault();
            let mut store = vault
                .open_application_store()
                .expect("open application store");
            store
                .persist_report(
                    REPORT_ID,
                    &report_hash(),
                    Zeroizing::new(VALID_REPORT.to_vec()),
                )
                .expect("persist report");
        }
        let report_path = fixture.state_path(&report_filename(REPORT_ID).expect("report name"));
        let mut bytes = fs::read(&report_path).expect("read persisted report");
        let last = bytes.last_mut().expect("nonempty report envelope");
        *last ^= 1;
        fs::write(&report_path, bytes).expect("tamper report");
        fs::set_permissions(&report_path, fs::Permissions::from_mode(FILE_MODE))
            .expect("restore report mode");
        let vault = fixture.open_vault();
        assert!(matches!(
            vault.open_application_store(),
            Err(RescueApplicationStoreError::CorruptApplicationState)
                | Err(RescueApplicationStoreError::InvalidReport)
        ));
        drop(vault);

        fs::remove_file(&report_path).expect("remove tampered report");
        write_secure(
            &fixture.state_path(".kernaid-app-stage-v1-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"),
            b"unexpected-stage",
        );
        let vault = fixture.open_vault();
        assert!(vault.open_application_store().is_err());
    }

    #[test]
    fn report_state_machine_rejects_the_257th_report_before_an_intent() {
        let mut state = RecoveredState::empty();
        transition_state(
            &mut state,
            ApplicationEvent::IdentityBound {
                device_id: "KA-000000000000000000000000".to_owned(),
                public_key_sha256: "00".repeat(32),
            },
            IntentPosition {
                sequence: 1,
                entry_hash: [1; 32],
            },
        )
        .expect("identity binding");
        let mut sequence = 2_u64;
        for index in 0..MAX_REPORTS {
            let transaction_id = format!("{index:032x}");
            let report_id = format!("RP-00000000-0000-0000-0000-{index:012x}");
            transition_state(
                &mut state,
                ApplicationEvent::ReportPersistIntent {
                    transaction_id: transaction_id.clone(),
                    report_id,
                    payload_sha256: "11".repeat(32),
                },
                IntentPosition {
                    sequence,
                    entry_hash: [2; 32],
                },
            )
            .expect("report intent");
            sequence += 1;
            transition_state(
                &mut state,
                ApplicationEvent::ReportPersistComplete {
                    transaction_id,
                    outcome: CompletionOutcome::Applied,
                    envelope_size: Some(2),
                    envelope_sha256: Some("22".repeat(32)),
                },
                IntentPosition {
                    sequence,
                    entry_hash: [3; 32],
                },
            )
            .expect("report complete");
            sequence += 1;
        }
        assert_eq!(state.reports.len(), MAX_REPORTS);
        assert!(matches!(
            transition_state(
                &mut state,
                ApplicationEvent::ReportPersistIntent {
                    transaction_id: "ff".repeat(16),
                    report_id: "RP-ffffffff-ffff-ffff-ffff-ffffffffffff".to_owned(),
                    payload_sha256: "33".repeat(32),
                },
                IntentPosition {
                    sequence,
                    entry_hash: [4; 32],
                },
            ),
            Err(RescueApplicationStoreError::CorruptJournal)
        ));
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
struct ReportMaterialization {
    size: u64,
    sha256: [u8; 32],
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum ObservedProvider {
    Missing,
    Valid([u8; 32]),
    Invalid,
}

struct ZeroizingSignedEnvelope(SignedReportEnvelope);

impl Drop for ZeroizingSignedEnvelope {
    fn drop(&mut self) {
        self.0.payload.zeroize();
    }
}

impl RescueVaultApplicationStore<'_> {
    fn scan_layout(&self) -> Result<ApplicationLayout, RescueApplicationStoreError> {
        let _guard = self
            .inner
            .operation_guard()
            .map_err(|_| RescueApplicationStoreError::StorageUnavailable)?;
        self.inner
            .ensure_integrity()
            .map_err(|_| RescueApplicationStoreError::CorruptApplicationState)?;
        let scan_fd = open_child(
            self.inner.state_directory_fd(),
            Path::new("."),
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .map_err(|_| RescueApplicationStoreError::CorruptApplicationState)?;
        if descriptor_mount_id(&scan_fd)? != self.inner.root_mount_id() {
            return Err(RescueApplicationStoreError::CorruptApplicationState);
        }

        let mut layout = ApplicationLayout::default();
        let mut count = 0_usize;
        let mut buffer = [MaybeUninit::<u8>::uninit(); SCAN_BUFFER_BYTES];
        let mut entries = RawDir::new(&scan_fd, &mut buffer);
        while let Some(entry) = entries.next() {
            let entry = entry.map_err(|_| RescueApplicationStoreError::StorageUnavailable)?;
            let name = entry.file_name().to_bytes();
            if name == b"." || name == b".." {
                continue;
            }
            count = count
                .checked_add(1)
                .ok_or(RescueApplicationStoreError::CorruptApplicationState)?;
            if count > MAX_LAYOUT_ENTRIES
                || name.is_empty()
                || name.len() > MAX_LAYOUT_NAME_BYTES
                || !name.is_ascii()
            {
                return Err(RescueApplicationStoreError::CorruptApplicationState);
            }
            let name = std::str::from_utf8(name)
                .map_err(|_| RescueApplicationStoreError::CorruptApplicationState)?;
            if is_core_state_name(name) {
                continue;
            }
            if name == PROVIDER_FILE_NAME {
                if layout.provider_present {
                    return Err(RescueApplicationStoreError::CorruptApplicationState);
                }
                layout.provider_present = true;
                continue;
            }
            if let Some(report_id) = report_id_from_filename(name) {
                if layout.reports.len() >= MAX_REPORTS
                    || layout
                        .reports
                        .insert(report_id.to_owned(), name.to_owned())
                        .is_some()
                {
                    return Err(RescueApplicationStoreError::CorruptApplicationState);
                }
                continue;
            }
            if let Some(transaction_id) = name.strip_prefix(STAGE_FILE_PREFIX) {
                validate_transaction_id(transaction_id)?;
                if !layout.stages.is_empty() {
                    return Err(RescueApplicationStoreError::CorruptApplicationState);
                }
                layout.stages.push(name.to_owned());
                continue;
            }
            return Err(RescueApplicationStoreError::CorruptApplicationState);
        }
        self.inner
            .ensure_integrity()
            .map_err(|_| RescueApplicationStoreError::CorruptApplicationState)?;
        Ok(layout)
    }

    fn validate_materialized_state(&self) -> Result<(), RescueApplicationStoreError> {
        let layout = self.scan_layout()?;
        if !layout.stages.is_empty()
            || layout.provider_present != self.state.provider_sha256.is_some()
            || layout.reports.len() != self.state.reports.len()
            || !layout
                .reports
                .keys()
                .all(|report_id| self.state.reports.contains_key(report_id))
        {
            return Err(RescueApplicationStoreError::CorruptApplicationState);
        }
        if self.read_provider_hash(PROVIDER_FILE_NAME)? != self.state.provider_sha256 {
            return Err(RescueApplicationStoreError::CorruptApplicationState);
        }
        for record in self.state.reports.values() {
            let name = report_filename(&record.report_id)?;
            let state = self
                .stat_optional(&name)?
                .ok_or(RescueApplicationStoreError::CorruptApplicationState)?;
            if state.size != record.envelope_size as i64 {
                return Err(RescueApplicationStoreError::CorruptApplicationState);
            }
        }
        Ok(())
    }

    fn validate_materialized_state_full(&self) -> Result<(), RescueApplicationStoreError> {
        self.validate_materialized_state()?;
        for record in self.state.reports.values() {
            self.read_and_verify_report(record)?;
        }
        Ok(())
    }

    fn validate_provider_materialization(&self) -> Result<(), RescueApplicationStoreError> {
        let observed = self.read_provider_hash(PROVIDER_FILE_NAME)?;
        if observed != self.state.provider_sha256 {
            return Err(RescueApplicationStoreError::CorruptApplicationState);
        }
        Ok(())
    }

    fn read_provider_hash(
        &self,
        name: &str,
    ) -> Result<Option<[u8; 32]>, RescueApplicationStoreError> {
        let Some(envelope) = self.read_optional(name, MAX_PROVIDER_ENVELOPE_BYTES)? else {
            return Ok(None);
        };
        let key = decode_provider_envelope(&envelope)
            .map_err(|_| RescueApplicationStoreError::CorruptApplicationState)?;
        Ok(Some(Sha256::digest(key.as_slice()).into()))
    }

    fn observe_provider_file(
        &self,
        name: &str,
    ) -> Result<ObservedProvider, RescueApplicationStoreError> {
        let Some(envelope) = self.read_optional(name, MAX_PROVIDER_ENVELOPE_BYTES)? else {
            return Ok(ObservedProvider::Missing);
        };
        Ok(match decode_provider_envelope(&envelope) {
            Ok(key) => ObservedProvider::Valid(Sha256::digest(key.as_slice()).into()),
            Err(_) => ObservedProvider::Invalid,
        })
    }

    fn read_and_verify_report(
        &self,
        record: &ReportRecord,
    ) -> Result<Zeroizing<Vec<u8>>, RescueApplicationStoreError> {
        let name = report_filename(&record.report_id)?;
        let envelope = self
            .read_optional(&name, MAX_SIGNED_REPORT_ENVELOPE_BYTES)?
            .ok_or(RescueApplicationStoreError::CorruptApplicationState)?;
        if envelope.len() as u64 != record.envelope_size
            || <[u8; 32]>::from(Sha256::digest(envelope.as_slice())) != record.envelope_sha256
        {
            return Err(RescueApplicationStoreError::CorruptApplicationState);
        }
        verify_report_envelope(
            &envelope,
            &self.identity,
            &record.payload_sha256,
            IntentPosition {
                sequence: record.intent_sequence,
                entry_hash: record.intent_entry_hash,
            },
        )?;
        Ok(envelope)
    }

    fn read_optional(
        &self,
        name: &str,
        maximum: usize,
    ) -> Result<Option<Zeroizing<Vec<u8>>>, RescueApplicationStoreError> {
        validate_literal_name(name)?;
        let _guard = self
            .inner
            .operation_guard()
            .map_err(|_| RescueApplicationStoreError::StorageUnavailable)?;
        self.inner
            .ensure_integrity()
            .map_err(|_| RescueApplicationStoreError::CorruptApplicationState)?;
        let descriptor = match open_child(
            self.inner.state_directory_fd(),
            Path::new(name),
            OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC,
            Mode::empty(),
        ) {
            Ok(descriptor) => descriptor,
            Err(error) if error == rustix::io::Errno::NOENT => return Ok(None),
            Err(_) => return Err(RescueApplicationStoreError::CorruptApplicationState),
        };
        let before = self.validate_file_descriptor(&descriptor)?;
        let size = usize::try_from(before.size)
            .map_err(|_| RescueApplicationStoreError::CorruptApplicationState)?;
        if size > maximum {
            return Err(RescueApplicationStoreError::CorruptApplicationState);
        }
        let mut file = File::from(descriptor);
        let mut bytes = Zeroizing::new(Vec::with_capacity(size));
        Read::by_ref(&mut file)
            .take((maximum + 1) as u64)
            .read_to_end(bytes.as_mut())
            .map_err(|_| RescueApplicationStoreError::StorageUnavailable)?;
        if bytes.len() != size || bytes.len() > maximum {
            return Err(RescueApplicationStoreError::ConcurrentWrite);
        }
        let after = self.validate_file_descriptor(&file)?;
        let named = self
            .stat_optional_unlocked(name)?
            .ok_or(RescueApplicationStoreError::ConcurrentWrite)?;
        if before != after || after != named {
            return Err(RescueApplicationStoreError::ConcurrentWrite);
        }
        self.inner
            .ensure_integrity()
            .map_err(|_| RescueApplicationStoreError::CorruptApplicationState)?;
        Ok(Some(bytes))
    }

    fn stat_optional(
        &self,
        name: &str,
    ) -> Result<Option<AppFileState>, RescueApplicationStoreError> {
        validate_literal_name(name)?;
        let _guard = self
            .inner
            .operation_guard()
            .map_err(|_| RescueApplicationStoreError::StorageUnavailable)?;
        self.inner
            .ensure_integrity()
            .map_err(|_| RescueApplicationStoreError::CorruptApplicationState)?;
        let state = self.stat_optional_unlocked(name)?;
        self.inner
            .ensure_integrity()
            .map_err(|_| RescueApplicationStoreError::CorruptApplicationState)?;
        Ok(state)
    }

    fn stat_optional_unlocked(
        &self,
        name: &str,
    ) -> Result<Option<AppFileState>, RescueApplicationStoreError> {
        let descriptor = match open_child(
            self.inner.state_directory_fd(),
            Path::new(name),
            OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC,
            Mode::empty(),
        ) {
            Ok(descriptor) => descriptor,
            Err(error) if error == rustix::io::Errno::NOENT => return Ok(None),
            Err(_) => return Err(RescueApplicationStoreError::CorruptApplicationState),
        };
        let descriptor_state = self.validate_file_descriptor(&descriptor)?;
        let named_stat = rfs::statat(
            self.inner.state_directory_fd(),
            name,
            AtFlags::SYMLINK_NOFOLLOW,
        )
        .map_err(|_| RescueApplicationStoreError::ConcurrentWrite)?;
        let named_state = self.validate_file_stat(&named_stat)?;
        if descriptor_state != named_state {
            return Err(RescueApplicationStoreError::ConcurrentWrite);
        }
        Ok(Some(descriptor_state))
    }

    fn validate_file_descriptor(
        &self,
        descriptor: impl AsFd,
    ) -> Result<AppFileState, RescueApplicationStoreError> {
        let stat =
            rfs::fstat(&descriptor).map_err(|_| RescueApplicationStoreError::StorageUnavailable)?;
        let state = self.validate_file_stat(&stat)?;
        if descriptor_mount_id(descriptor)? != self.inner.root_mount_id() {
            return Err(RescueApplicationStoreError::CorruptApplicationState);
        }
        Ok(state)
    }

    fn validate_file_stat(&self, stat: &Stat) -> Result<AppFileState, RescueApplicationStoreError> {
        let owner = self.inner.owner();
        if !FileType::from_raw_mode(stat.st_mode).is_file()
            || stat.st_nlink != 1
            || stat.st_size < 0
            || stat.st_uid != owner.uid
            || stat.st_gid != owner.gid
            || stat.st_mode & 0o7777 != FILE_MODE
            || stat.st_dev != self.inner.state_device()
        {
            return Err(RescueApplicationStoreError::CorruptApplicationState);
        }
        Ok(AppFileState::from_stat(stat))
    }

    fn create_stage(
        &mut self,
        transaction_id: &str,
        bytes: &[u8],
    ) -> Result<(), RescueApplicationStoreError> {
        let name = stage_filename(transaction_id)?;
        if bytes.is_empty() || bytes.len() > MAX_SIGNED_REPORT_ENVELOPE_BYTES {
            return Err(RescueApplicationStoreError::CorruptApplicationState);
        }
        {
            let _guard = self
                .inner
                .operation_guard()
                .map_err(|_| RescueApplicationStoreError::StorageUnavailable)?;
            self.inner
                .ensure_integrity()
                .map_err(|_| RescueApplicationStoreError::CorruptApplicationState)?;
            if self.stat_optional_unlocked(&name)?.is_some() {
                return Err(RescueApplicationStoreError::ConcurrentWrite);
            }
            let descriptor = open_child(
                self.inner.state_directory_fd(),
                Path::new(&name),
                OFlags::RDWR | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW | OFlags::CLOEXEC,
                Mode::RUSR | Mode::WUSR,
            )
            .map_err(|error| {
                if error == rustix::io::Errno::EXIST {
                    RescueApplicationStoreError::ConcurrentWrite
                } else {
                    RescueApplicationStoreError::StorageUnavailable
                }
            })?;
            rfs::fchmod(&descriptor, Mode::RUSR | Mode::WUSR)
                .map_err(|_| RescueApplicationStoreError::StorageUnavailable)?;
            self.validate_file_descriptor(&descriptor)?;
            let mut file = File::from(descriptor);
            file.write_all(bytes)
                .map_err(|_| RescueApplicationStoreError::StorageUnavailable)?;
            file.flush()
                .map_err(|_| RescueApplicationStoreError::StorageUnavailable)?;
            file.sync_all()
                .map_err(|_| RescueApplicationStoreError::StorageUnavailable)?;
            let after = self.validate_file_descriptor(&file)?;
            if after.size != bytes.len() as i64 {
                return Err(RescueApplicationStoreError::WriteVerificationFailed);
            }
        }
        self.trip_fault(ApplicationFaultPoint::StageFileDurable)?;
        self.sync_state_directory()?;
        self.trip_fault(ApplicationFaultPoint::StageDirectoryDurable)?;
        let persisted = self
            .read_optional(&name, MAX_SIGNED_REPORT_ENVELOPE_BYTES)?
            .ok_or(RescueApplicationStoreError::WriteVerificationFailed)?;
        if persisted.as_slice() != bytes {
            return Err(RescueApplicationStoreError::WriteVerificationFailed);
        }
        Ok(())
    }

    fn install_provider_stage(
        &mut self,
        transaction_id: &str,
        old_sha256: Option<[u8; 32]>,
        new_sha256: [u8; 32],
    ) -> Result<(), RescueApplicationStoreError> {
        let stage_name = stage_filename(transaction_id)?;
        if self.read_provider_hash(&stage_name)? != Some(new_sha256) {
            return Err(RescueApplicationStoreError::CorruptApplicationState);
        }
        let current = self.read_provider_hash(PROVIDER_FILE_NAME)?;
        match (current, old_sha256) {
            (Some(current), Some(expected)) if current == expected => {
                self.exchange_named(&stage_name, PROVIDER_FILE_NAME)?;
            }
            (None, None) => self.rename_noreplace(&stage_name, PROVIDER_FILE_NAME)?,
            _ => return Err(RescueApplicationStoreError::CorruptApplicationState),
        }
        self.trip_fault(ApplicationFaultPoint::FinalRenamed)?;
        self.sync_state_directory()?;
        self.trip_fault(ApplicationFaultPoint::FinalDirectoryDurable)?;
        let expected_stage = old_sha256;
        if self.read_provider_hash(PROVIDER_FILE_NAME)? != Some(new_sha256)
            || self.read_provider_hash(&stage_name)? != expected_stage
        {
            return Err(RescueApplicationStoreError::WriteVerificationFailed);
        }
        Ok(())
    }

    fn move_provider_to_tombstone(
        &mut self,
        transaction_id: &str,
        expected_hash: [u8; 32],
    ) -> Result<(), RescueApplicationStoreError> {
        let stage_name = stage_filename(transaction_id)?;
        if self.read_provider_hash(PROVIDER_FILE_NAME)? != Some(expected_hash)
            || self
                .read_optional(&stage_name, MAX_PROVIDER_ENVELOPE_BYTES)?
                .is_some()
        {
            return Err(RescueApplicationStoreError::CorruptApplicationState);
        }
        self.rename_noreplace(PROVIDER_FILE_NAME, &stage_name)?;
        self.trip_fault(ApplicationFaultPoint::FinalRenamed)?;
        self.sync_state_directory()?;
        self.trip_fault(ApplicationFaultPoint::FinalDirectoryDurable)?;
        if self.read_provider_hash(PROVIDER_FILE_NAME)?.is_some()
            || self.read_provider_hash(&stage_name)? != Some(expected_hash)
        {
            return Err(RescueApplicationStoreError::WriteVerificationFailed);
        }
        Ok(())
    }

    fn install_report_stage(
        &mut self,
        transaction_id: &str,
        final_name: &str,
    ) -> Result<(), RescueApplicationStoreError> {
        let stage_name = stage_filename(transaction_id)?;
        if self.stat_optional(&stage_name)?.is_none() || self.stat_optional(final_name)?.is_some() {
            return Err(RescueApplicationStoreError::CorruptApplicationState);
        }
        self.rename_noreplace(&stage_name, final_name)?;
        self.trip_fault(ApplicationFaultPoint::FinalRenamed)?;
        self.sync_state_directory()?;
        self.trip_fault(ApplicationFaultPoint::FinalDirectoryDurable)?;
        if self.stat_optional(&stage_name)?.is_some() || self.stat_optional(final_name)?.is_none() {
            return Err(RescueApplicationStoreError::WriteVerificationFailed);
        }
        Ok(())
    }

    fn remove_stage(&mut self, transaction_id: &str) -> Result<(), RescueApplicationStoreError> {
        let name = stage_filename(transaction_id)?;
        self.unlink_named(&name)?;
        self.trip_fault(ApplicationFaultPoint::StageRemovedBeforeDirectorySync)?;
        self.sync_state_directory()
    }

    fn unlink_named(&self, name: &str) -> Result<(), RescueApplicationStoreError> {
        validate_literal_name(name)?;
        let _guard = self
            .inner
            .operation_guard()
            .map_err(|_| RescueApplicationStoreError::StorageUnavailable)?;
        self.inner
            .ensure_integrity()
            .map_err(|_| RescueApplicationStoreError::CorruptApplicationState)?;
        let before = self
            .stat_optional_unlocked(name)?
            .ok_or(RescueApplicationStoreError::ConcurrentWrite)?;
        let named = rfs::statat(
            self.inner.state_directory_fd(),
            name,
            AtFlags::SYMLINK_NOFOLLOW,
        )
        .map_err(|_| RescueApplicationStoreError::ConcurrentWrite)?;
        if !before.same_object(self.validate_file_stat(&named)?) {
            return Err(RescueApplicationStoreError::ConcurrentWrite);
        }
        rfs::unlinkat(self.inner.state_directory_fd(), name, AtFlags::empty())
            .map_err(|_| RescueApplicationStoreError::StorageUnavailable)?;
        if self.stat_optional_unlocked(name)?.is_some() {
            return Err(RescueApplicationStoreError::ConcurrentWrite);
        }
        self.inner
            .ensure_integrity()
            .map_err(|_| RescueApplicationStoreError::CorruptApplicationState)
    }

    fn rename_noreplace(
        &self,
        source: &str,
        destination: &str,
    ) -> Result<(), RescueApplicationStoreError> {
        validate_literal_name(source)?;
        validate_literal_name(destination)?;
        let _guard = self
            .inner
            .operation_guard()
            .map_err(|_| RescueApplicationStoreError::StorageUnavailable)?;
        self.inner
            .ensure_integrity()
            .map_err(|_| RescueApplicationStoreError::CorruptApplicationState)?;
        let source_state = self
            .stat_optional_unlocked(source)?
            .ok_or(RescueApplicationStoreError::ConcurrentWrite)?;
        if self.stat_optional_unlocked(destination)?.is_some() {
            return Err(RescueApplicationStoreError::ConcurrentWrite);
        }
        rfs::renameat_with(
            self.inner.state_directory_fd(),
            source,
            self.inner.state_directory_fd(),
            destination,
            RenameFlags::NOREPLACE,
        )
        .map_err(|error| {
            if error == rustix::io::Errno::EXIST || error == rustix::io::Errno::NOENT {
                RescueApplicationStoreError::ConcurrentWrite
            } else {
                RescueApplicationStoreError::StorageUnavailable
            }
        })?;
        let destination_state = self
            .stat_optional_unlocked(destination)?
            .ok_or(RescueApplicationStoreError::ConcurrentWrite)?;
        if self.stat_optional_unlocked(source)?.is_some()
            || !destination_state.same_object(source_state)
            || destination_state.size != source_state.size
        {
            return Err(RescueApplicationStoreError::ConcurrentWrite);
        }
        self.inner
            .ensure_integrity()
            .map_err(|_| RescueApplicationStoreError::CorruptApplicationState)
    }

    fn exchange_named(&self, first: &str, second: &str) -> Result<(), RescueApplicationStoreError> {
        validate_literal_name(first)?;
        validate_literal_name(second)?;
        let _guard = self
            .inner
            .operation_guard()
            .map_err(|_| RescueApplicationStoreError::StorageUnavailable)?;
        self.inner
            .ensure_integrity()
            .map_err(|_| RescueApplicationStoreError::CorruptApplicationState)?;
        let first_before = self
            .stat_optional_unlocked(first)?
            .ok_or(RescueApplicationStoreError::ConcurrentWrite)?;
        let second_before = self
            .stat_optional_unlocked(second)?
            .ok_or(RescueApplicationStoreError::ConcurrentWrite)?;
        rfs::renameat_with(
            self.inner.state_directory_fd(),
            first,
            self.inner.state_directory_fd(),
            second,
            RenameFlags::EXCHANGE,
        )
        .map_err(|_| RescueApplicationStoreError::StorageUnavailable)?;
        let first_after = self
            .stat_optional_unlocked(first)?
            .ok_or(RescueApplicationStoreError::ConcurrentWrite)?;
        let second_after = self
            .stat_optional_unlocked(second)?
            .ok_or(RescueApplicationStoreError::ConcurrentWrite)?;
        if !first_after.same_object(second_before)
            || first_after.size != second_before.size
            || !second_after.same_object(first_before)
            || second_after.size != first_before.size
        {
            return Err(RescueApplicationStoreError::ConcurrentWrite);
        }
        self.inner
            .ensure_integrity()
            .map_err(|_| RescueApplicationStoreError::CorruptApplicationState)
    }

    fn sync_state_directory(&self) -> Result<(), RescueApplicationStoreError> {
        let _guard = self
            .inner
            .operation_guard()
            .map_err(|_| RescueApplicationStoreError::StorageUnavailable)?;
        self.inner
            .ensure_integrity()
            .map_err(|_| RescueApplicationStoreError::CorruptApplicationState)?;
        rfs::fsync(self.inner.state_directory_fd())
            .map_err(|_| RescueApplicationStoreError::StorageUnavailable)?;
        self.inner
            .ensure_integrity()
            .map_err(|_| RescueApplicationStoreError::CorruptApplicationState)
    }
}
