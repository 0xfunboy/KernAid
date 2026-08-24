//! Dormant fixture-lab repair broker.
//!
//! This module is Linux-only and deliberately has no IPC, Core, desktop, or
//! production-target integration. It can dispatch exactly one compile-time
//! pinned action against an explicitly marked disposable fixture. Paths are
//! accepted only through [`FixtureRepairConfig`], which is local-only and is
//! neither serializable nor exposed by receipts or errors.

use kernaid_core::validate_fixture_repair_lab_plan;
use kernaid_device_identity::{DeviceIdentity, SignedReportEnvelope};
use kernaid_linux_pack::{
    PreservedMetadata, RepairReceipt,
    action_contract::{FIXTURE_ACTION_ID, FIXTURE_RESOURCE_ID, FIXTURE_ROLLBACK_ID},
    execute_missing_fstab_device_repair, preview_missing_fstab_device,
    preview_missing_fstab_device_rollback, rollback_missing_fstab_device_repair,
};
use kernaid_protocol::{ActionStep, Risk, ValidatedPlan};
use kernaid_storage::{
    JournalAnchor, JournalEntry, JournalEntryRef, JournalReplayError, JournalReplayLimits,
    JournalSecretStore, SecureJournal,
};
use serde::{Deserialize, Serialize, Serializer};
use sha2::{Digest, Sha256};
use std::{
    collections::{HashMap, HashSet},
    error::Error,
    fmt, fs,
    path::{Path, PathBuf},
};

const RECEIPT_API_VERSION: &str = "kernaid.dev/fixture-repair-receipt/v2";
const RECEIPT_KIND: &str = "FixtureRepairReceipt";
const RECEIPT_MEDIA_TYPE: &str = "application/vnd.kernaid.fixture-repair-receipt+json";
const REPORT_API_VERSION: &str = "kernaid.dev/fixture-repair-report/v1";
const REPORT_KIND: &str = "FixtureRepairReport";
const REPORT_MEDIA_TYPE: &str = "application/vnd.kernaid.fixture-repair-report+json";
pub const FIXTURE_REPAIR_REPORT_SCHEMA_JSON: &str =
    include_str!("../schemas/fixture-repair-report-v1.json");
const PLAN_HASH_DOMAIN: &[u8] = b"KERNAID-FIXTURE-REPAIR-PLAN-V2\0";
const ROLLBACK_PLAN_HASH_DOMAIN: &[u8] = b"KERNAID-FIXTURE-ROLLBACK-PLAN-V1\0";
const DIFF_HASH_DOMAIN: &[u8] = b"KERNAID-FIXTURE-REPAIR-DIFF-V1\0";
const FINDING_ID: &str = "KA-LNX-P0-003";
const FINDING_VERSION: u32 = 2;
const BACKUP_LOCATOR_PREFIX: &str = "fixture-lab-backup://linux-fstab/";
pub const DEVICE_BINDING_EVENT_KIND: &str = "fixture.repair.device-bound.v1";
pub const INTENT_EVENT_KIND: &str = "fixture.repair.intent.v1";
pub const COMPLETED_EVENT_KIND: &str = "fixture.repair.completed.v1";
pub const ROLLBACK_INTENT_EVENT_KIND: &str = "fixture.rollback.intent.v1";
pub const ROLLED_BACK_EVENT_KIND: &str = "fixture.rollback.completed.v1";
pub const RECOVERY_EVENT_KIND: &str = "fixture.repair.recovery.v1";
const RECOVERY_DISPOSITION: &str = "manual-inspection-required";
const RISK: &str = "R2";
const BACKUP_DECLARATION: &str = "required-separate-byte-verified-copy";
const BACKUP_RESULT: &str = "created-and-byte-verified";
const VALIDATION_DECLARATION: &str =
    "fstab is syntactically parsed and the unique missing UUID entry is disabled";
const ROLLBACK_DECLARATION: &str =
    "atomically restore the byte-verified backup and original mode/uid/gid";
const ROLLBACK_VALIDATION_DECLARATION: &str =
    "restored fstab bytes and original mode/uid/gid match the verified backup";
const MAX_ID_BYTES: usize = 128;
const MAX_EVIDENCE_IDS: usize = 32;
const MAX_APPROVALS: usize = 1024;
const MAX_BROKER_EVENT_BYTES: usize = 16 * 1024;
const MAX_BROKER_EVENTS: u64 = 1 + (MAX_APPROVALS as u64 * 2);
const MAX_REPLAY_BYTES: u64 = MAX_BROKER_EVENTS * MAX_BROKER_EVENT_BYTES as u64;

/// Trusted local-only fixture paths. This type intentionally implements no
/// serialization, and its debug form never reveals either path.
pub struct FixtureRepairConfig {
    fixture_root: PathBuf,
    backup_dir: PathBuf,
}

impl FixtureRepairConfig {
    /// Pin existing, non-symlink directories for this broker instance.
    pub fn new(
        fixture_root: impl AsRef<Path>,
        backup_dir: impl AsRef<Path>,
    ) -> Result<Self, FixtureRepairError> {
        let fixture_root = canonical_directory(fixture_root.as_ref())?;
        let backup_dir = canonical_directory(backup_dir.as_ref())?;
        if backup_dir.starts_with(&fixture_root) || fixture_root.starts_with(&backup_dir) {
            return Err(FixtureRepairError::InvalidLocalConfig);
        }
        Ok(Self {
            fixture_root,
            backup_dir,
        })
    }
}

impl fmt::Debug for FixtureRepairConfig {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("FixtureRepairConfig")
            .field("fixture_root", &"[local path redacted]")
            .field("backup_dir", &"[local path redacted]")
            .finish()
    }
}

/// Evidence identity and digest supplied by the read-only diagnosis pipeline.
/// Construction validates the closed ID/hash forms before a plan can exist.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct FixtureEvidenceBinding {
    id: String,
    sha256: String,
}

impl FixtureEvidenceBinding {
    pub fn new(
        id: impl Into<String>,
        sha256: impl Into<String>,
    ) -> Result<Self, FixtureRepairError> {
        let binding = Self {
            id: id.into(),
            sha256: sha256.into(),
        };
        validate_evidence_binding(&binding).map_err(|_| FixtureRepairError::InvalidStage)?;
        Ok(binding)
    }

    pub fn id(&self) -> &str {
        &self.id
    }

    pub fn sha256(&self) -> &str {
        &self.sha256
    }
}

/// Unserialized, typed request used to stage the single fixture action. It
/// deliberately accepts no path, command, replacement bytes, or raw JSON.
pub struct StageFixtureRepairRequest<'request> {
    pub session_id: &'request str,
    pub plan_id: &'request str,
    pub action_id: &'request str,
    pub diagnosis_sha256: &'request str,
    pub finding_id: &'request str,
    pub finding_version: u32,
    pub evidence: &'request [FixtureEvidenceBinding],
}

impl fmt::Debug for StageFixtureRepairRequest<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("StageFixtureRepairRequest")
            .field("session_id_bytes", &self.session_id.len())
            .field("plan_id_bytes", &self.plan_id.len())
            .field("action_id_bytes", &self.action_id.len())
            .field("diagnosis_sha256_bytes", &self.diagnosis_sha256.len())
            .field("finding_id_bytes", &self.finding_id.len())
            .field("finding_version", &self.finding_version)
            .field("evidence_count", &self.evidence.len())
            .finish()
    }
}

/// The only risk supported by the fixture repair broker.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FixtureRepairRisk {
    R2,
}

/// A staged fixture plan containing only typed identifiers, opaque hashes and
/// fixed backup/validation declarations. It contains no target bytes or path.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StagedFixtureRepair {
    session_id: String,
    plan_id: String,
    action_id: &'static str,
    resource_id: &'static str,
    diagnosis_sha256: String,
    finding_id: &'static str,
    finding_version: u32,
    evidence: Vec<FixtureEvidenceBinding>,
    target_snapshot: String,
    expected_before_sha256: String,
    expected_after_sha256: String,
    diff_sha256: String,
    backup_locator: String,
    plan_hash: String,
}

impl StagedFixtureRepair {
    pub fn session_id(&self) -> &str {
        &self.session_id
    }

    pub fn plan_id(&self) -> &str {
        &self.plan_id
    }

    pub const fn action_id(&self) -> &'static str {
        self.action_id
    }

    pub const fn resource_id(&self) -> &'static str {
        self.resource_id
    }

    pub fn diagnosis_sha256(&self) -> &str {
        &self.diagnosis_sha256
    }

    pub const fn finding_id(&self) -> &'static str {
        self.finding_id
    }

    pub const fn finding_version(&self) -> u32 {
        self.finding_version
    }

    pub fn evidence(&self) -> &[FixtureEvidenceBinding] {
        &self.evidence
    }

    pub fn target_snapshot(&self) -> &str {
        &self.target_snapshot
    }

    pub fn expected_before_sha256(&self) -> &str {
        &self.expected_before_sha256
    }

    pub fn expected_after_sha256(&self) -> &str {
        &self.expected_after_sha256
    }

    pub fn diff_sha256(&self) -> &str {
        &self.diff_sha256
    }

    pub fn backup_locator(&self) -> &str {
        &self.backup_locator
    }

    pub fn plan_hash(&self) -> &str {
        &self.plan_hash
    }

    pub const fn risk(&self) -> FixtureRepairRisk {
        FixtureRepairRisk::R2
    }

    pub const fn backup_declaration(&self) -> &'static str {
        BACKUP_DECLARATION
    }

    pub const fn validation_declaration(&self) -> &'static str {
        VALIDATION_DECLARATION
    }

    pub const fn rollback_declaration(&self) -> &'static str {
        ROLLBACK_DECLARATION
    }
}

/// Explicit local approval. All fields are checked against the staged plan;
/// the sequence must be exactly the next durable approval sequence.
pub struct FixtureRepairApproval<'approval> {
    pub approval_id: &'approval str,
    pub approval_sequence: u64,
    pub session_id: &'approval str,
    pub plan_id: &'approval str,
    pub plan_hash: &'approval str,
    pub target_snapshot: &'approval str,
}

impl fmt::Debug for FixtureRepairApproval<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("FixtureRepairApproval")
            .field("approval_id_bytes", &self.approval_id.len())
            .field("approval_sequence", &self.approval_sequence)
            .field("session_id_bytes", &self.session_id.len())
            .field("plan_id_bytes", &self.plan_id.len())
            .field("plan_hash_bytes", &self.plan_hash.len())
            .field("target_snapshot_bytes", &self.target_snapshot.len())
            .finish()
    }
}

/// Typed request for the second, explicitly approved transaction. The repair
/// receipt is resolved from the authenticated journal, never supplied by the
/// caller.
pub struct StageFixtureRollbackRequest<'request> {
    pub session_id: &'request str,
    pub plan_id: &'request str,
    pub repair_approval_id: &'request str,
}

impl fmt::Debug for StageFixtureRollbackRequest<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("StageFixtureRollbackRequest")
            .field("session_id_bytes", &self.session_id.len())
            .field("plan_id_bytes", &self.plan_id.len())
            .field("repair_approval_id_bytes", &self.repair_approval_id.len())
            .finish()
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StagedFixtureRollback {
    session_id: String,
    plan_id: String,
    repair_approval_id: String,
    repair_plan_hash: String,
    resource_id: &'static str,
    target_snapshot: String,
    installed_sha256: String,
    restored_sha256: String,
    backup_locator: String,
    backup_sha256: String,
    plan_hash: String,
}

impl StagedFixtureRollback {
    pub fn session_id(&self) -> &str {
        &self.session_id
    }

    pub fn plan_id(&self) -> &str {
        &self.plan_id
    }

    pub fn repair_approval_id(&self) -> &str {
        &self.repair_approval_id
    }

    pub const fn action_id(&self) -> &'static str {
        FIXTURE_ROLLBACK_ID
    }

    pub const fn resource_id(&self) -> &'static str {
        self.resource_id
    }

    pub fn target_snapshot(&self) -> &str {
        &self.target_snapshot
    }

    pub fn installed_sha256(&self) -> &str {
        &self.installed_sha256
    }

    pub fn restored_sha256(&self) -> &str {
        &self.restored_sha256
    }

    pub fn backup_locator(&self) -> &str {
        &self.backup_locator
    }

    pub fn plan_hash(&self) -> &str {
        &self.plan_hash
    }

    pub const fn risk(&self) -> FixtureRepairRisk {
        FixtureRepairRisk::R2
    }

    pub const fn validation_declaration(&self) -> &'static str {
        ROLLBACK_VALIDATION_DECLARATION
    }
}

pub struct FixtureRollbackApproval<'approval> {
    pub approval_id: &'approval str,
    pub approval_sequence: u64,
    pub session_id: &'approval str,
    pub plan_id: &'approval str,
    pub plan_hash: &'approval str,
    pub target_snapshot: &'approval str,
}

impl fmt::Debug for FixtureRollbackApproval<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("FixtureRollbackApproval")
            .field("approval_id_bytes", &self.approval_id.len())
            .field("approval_sequence", &self.approval_sequence)
            .field("session_id_bytes", &self.session_id.len())
            .field("plan_id_bytes", &self.plan_id.len())
            .field("plan_hash_bytes", &self.plan_hash.len())
            .field("target_snapshot_bytes", &self.target_snapshot.len())
            .finish()
    }
}

/// Closed, signed receipt payload. Every field is covered by the device
/// signature and the exact completed-event journal head.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct FixtureRepairReceiptPayload {
    api_version: String,
    kind: String,
    device_id: String,
    journal_id: String,
    journal_sequence: u64,
    intent_journal_sequence: u64,
    approval_id: String,
    approval_sequence: u64,
    approval_decision: String,
    risk: String,
    session_id: String,
    plan_id: String,
    plan_hash: String,
    action_id: String,
    resource_id: String,
    diagnosis_sha256: String,
    finding_id: String,
    finding_version: u32,
    evidence: Vec<FixtureEvidenceBinding>,
    target_snapshot: String,
    before_sha256: String,
    after_sha256: String,
    after_target_precondition: String,
    diff_sha256: String,
    backup_locator: String,
    backup_sha256: String,
    backup: String,
    validation: String,
    rollback: String,
    validation_passed: bool,
    metadata_preserved: bool,
    before_mode: u32,
    before_uid: u32,
    before_gid: u32,
}

impl FixtureRepairReceiptPayload {
    pub fn device_id(&self) -> &str {
        &self.device_id
    }

    pub fn journal_id(&self) -> &str {
        &self.journal_id
    }

    pub const fn journal_sequence(&self) -> u64 {
        self.journal_sequence
    }

    pub fn approval_id(&self) -> &str {
        &self.approval_id
    }

    pub const fn approval_sequence(&self) -> u64 {
        self.approval_sequence
    }

    pub fn plan_hash(&self) -> &str {
        &self.plan_hash
    }

    pub fn diagnosis_sha256(&self) -> &str {
        &self.diagnosis_sha256
    }

    pub fn finding_id(&self) -> &str {
        &self.finding_id
    }

    pub const fn finding_version(&self) -> u32 {
        self.finding_version
    }

    pub fn evidence(&self) -> &[FixtureEvidenceBinding] {
        &self.evidence
    }

    pub fn before_sha256(&self) -> &str {
        &self.before_sha256
    }

    pub fn after_sha256(&self) -> &str {
        &self.after_sha256
    }

    pub fn diff_sha256(&self) -> &str {
        &self.diff_sha256
    }

    pub fn backup_locator(&self) -> &str {
        &self.backup_locator
    }

    pub fn backup_sha256(&self) -> &str {
        &self.backup_sha256
    }

    pub const fn validation_passed(&self) -> bool {
        self.validation_passed
    }

    pub const fn metadata_preserved(&self) -> bool {
        self.metadata_preserved
    }
}

/// Signed receipt carried by the existing closed report envelope. Debug output
/// is inherited from the redacting envelope implementation.
#[derive(Clone, PartialEq, Eq)]
pub struct SignedFixtureRepairReceipt {
    envelope: SignedReportEnvelope,
}

impl SignedFixtureRepairReceipt {
    pub fn envelope(&self) -> &SignedReportEnvelope {
        &self.envelope
    }

    /// Verify the device signature and strict receipt payload against a
    /// caller-pinned public key.
    pub fn verify(
        &self,
        expected_public_key: &[u8; 32],
    ) -> Result<FixtureRepairReceiptPayload, FixtureRepairError> {
        if self.envelope.payload_media_type != RECEIPT_MEDIA_TYPE {
            return Err(FixtureRepairError::InvalidReceipt);
        }
        let verified = self
            .envelope
            .verify(expected_public_key)
            .map_err(|_| FixtureRepairError::InvalidReceipt)?;
        let payload: FixtureRepairReceiptPayload =
            strict_json(verified.as_bytes()).map_err(|_| FixtureRepairError::InvalidReceipt)?;
        validate_receipt_payload(&payload).map_err(|_| FixtureRepairError::InvalidReceipt)?;
        if payload.device_id != self.envelope.device_id
            || payload.journal_sequence != self.envelope.journal_sequence
        {
            return Err(FixtureRepairError::InvalidReceipt);
        }
        Ok(payload)
    }
}

impl fmt::Debug for SignedFixtureRepairReceipt {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_tuple("SignedFixtureRepairReceipt")
            .field(&self.envelope)
            .finish()
    }
}

impl Serialize for SignedFixtureRepairReceipt {
    fn serialize<SerializerType>(
        &self,
        serializer: SerializerType,
    ) -> Result<SerializerType::Ok, SerializerType::Error>
    where
        SerializerType: Serializer,
    {
        self.envelope.serialize(serializer)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct FixtureRollbackReportPayload {
    journal_sequence: u64,
    intent_journal_sequence: u64,
    approval_id: String,
    approval_sequence: u64,
    approval_decision: String,
    risk: String,
    plan_id: String,
    plan_hash: String,
    action_id: String,
    resource_id: String,
    target_snapshot: String,
    replaced_sha256: String,
    restored_sha256: String,
    backup_locator: String,
    backup_sha256: String,
    validation: String,
    validation_passed: bool,
    metadata_preserved: bool,
}

/// Final strict, signed and replay-verifiable report for the entire fixture
/// cycle. The nested repair receipt binds evidence through backup creation;
/// the rollback section binds the second approval and exact restoration.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct FixtureRepairReportPayload {
    api_version: String,
    kind: String,
    device_id: String,
    journal_id: String,
    journal_sequence: u64,
    repair: FixtureRepairReceiptPayload,
    rollback: FixtureRollbackReportPayload,
    final_state: String,
}

impl FixtureRepairReportPayload {
    pub fn device_id(&self) -> &str {
        &self.device_id
    }

    pub fn repair(&self) -> &FixtureRepairReceiptPayload {
        &self.repair
    }

    pub fn rollback_plan_hash(&self) -> &str {
        &self.rollback.plan_hash
    }

    pub fn rollback_approval_id(&self) -> &str {
        &self.rollback.approval_id
    }

    pub fn restored_sha256(&self) -> &str {
        &self.rollback.restored_sha256
    }

    pub const fn journal_sequence(&self) -> u64 {
        self.journal_sequence
    }

    pub fn final_state(&self) -> &str {
        &self.final_state
    }
}

#[derive(Clone, PartialEq, Eq)]
pub struct SignedFixtureRepairReport {
    envelope: SignedReportEnvelope,
}

impl SignedFixtureRepairReport {
    pub fn envelope(&self) -> &SignedReportEnvelope {
        &self.envelope
    }

    pub fn verify(
        &self,
        expected_public_key: &[u8; 32],
    ) -> Result<FixtureRepairReportPayload, FixtureRepairError> {
        if self.envelope.payload_media_type != REPORT_MEDIA_TYPE {
            return Err(FixtureRepairError::InvalidReceipt);
        }
        let verified = self
            .envelope
            .verify(expected_public_key)
            .map_err(|_| FixtureRepairError::InvalidReceipt)?;
        let payload: FixtureRepairReportPayload =
            strict_json(verified.as_bytes()).map_err(|_| FixtureRepairError::InvalidReceipt)?;
        validate_report_payload(&payload).map_err(|_| FixtureRepairError::InvalidReceipt)?;
        if payload.device_id != self.envelope.device_id
            || payload.journal_sequence != self.envelope.journal_sequence
        {
            return Err(FixtureRepairError::InvalidReceipt);
        }
        Ok(payload)
    }
}

impl fmt::Debug for SignedFixtureRepairReport {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_tuple("SignedFixtureRepairReport")
            .field(&self.envelope)
            .finish()
    }
}

impl Serialize for SignedFixtureRepairReport {
    fn serialize<SerializerType>(
        &self,
        serializer: SerializerType,
    ) -> Result<SerializerType::Ok, SerializerType::Error>
    where
        SerializerType: Serializer,
    {
        self.envelope.serialize(serializer)
    }
}

/// Sanitized fixture-broker failures. No variant stores an OS path, target
/// content, pack error, journal plaintext, or provider-controlled string.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FixtureRepairError {
    InvalidLocalConfig,
    InvalidJournal,
    JournalUnavailable,
    DeviceBindingMismatch,
    MutationBlocked,
    InvalidStage,
    UnsupportedAction,
    ContractMismatch,
    FixtureRejected,
    InvalidApproval,
    ApprovalMismatch,
    ApprovalReused,
    NonMonotonicApproval,
    StaleTarget,
    ExecutionOutcomeUnknown,
    ReceiptUnavailable,
    InvalidReceipt,
    CapacityExceeded,
}

impl fmt::Display for FixtureRepairError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::InvalidLocalConfig => "fixture repair local configuration is invalid",
            Self::InvalidJournal => "fixture repair journal is invalid",
            Self::JournalUnavailable => "fixture repair journal is unavailable",
            Self::DeviceBindingMismatch => "fixture repair journal device binding does not match",
            Self::MutationBlocked => "fixture repair mutation is blocked pending manual inspection",
            Self::InvalidStage => "fixture repair stage request is invalid",
            Self::UnsupportedAction => "fixture repair action is not allowed",
            Self::ContractMismatch => "fixture repair contract does not match the preview",
            Self::FixtureRejected => "fixture repair preview was rejected",
            Self::InvalidApproval => "fixture repair approval is invalid",
            Self::ApprovalMismatch => "fixture repair approval does not match the staged plan",
            Self::ApprovalReused => "fixture repair approval was already consumed",
            Self::NonMonotonicApproval => "fixture repair approval sequence is not next",
            Self::StaleTarget => "fixture repair target changed after staging",
            Self::ExecutionOutcomeUnknown => "fixture repair outcome requires manual inspection",
            Self::ReceiptUnavailable => "fixture repair completed but its receipt is unavailable",
            Self::InvalidReceipt => "fixture repair receipt is invalid",
            Self::CapacityExceeded => "fixture repair journal capacity is exhausted",
        })
    }
}

impl Error for FixtureRepairError {}

/// Borrowed broker attached to a dedicated authenticated journal and an
/// already-existing device identity. Attachment never generates an identity.
pub struct FixtureRepairBroker<'attached, Store: JournalSecretStore> {
    config: FixtureRepairConfig,
    journal: &'attached mut SecureJournal<Store>,
    identity: &'attached DeviceIdentity,
    head: JournalAnchor,
    used_approval_ids: HashSet<String>,
    completed_receipts: HashMap<String, RecoverableReceipt>,
    completed_reports: HashMap<String, RecoverableReport>,
    last_approval_sequence: u64,
    mutation_blocked: bool,
}

impl<Store: JournalSecretStore> fmt::Debug for FixtureRepairBroker<'_, Store> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("FixtureRepairBroker")
            .field("config", &self.config)
            .field("journal_sequence", &self.head.sequence)
            .field("used_approval_count", &self.used_approval_ids.len())
            .field("completed_receipt_count", &self.completed_receipts.len())
            .field("completed_report_count", &self.completed_reports.len())
            .field("last_approval_sequence", &self.last_approval_sequence)
            .field("mutation_blocked", &self.mutation_blocked)
            .finish_non_exhaustive()
    }
}

impl<'attached, Store: JournalSecretStore> FixtureRepairBroker<'attached, Store> {
    /// Attach to a dedicated journal, authenticate its complete bounded event
    /// history, and bind a new empty journal to the supplied identity. A
    /// dangling intent is converted to a durable manual-recovery record and
    /// permanently blocks this journal from further mutation.
    pub fn attach(
        config: FixtureRepairConfig,
        journal: &'attached mut SecureJournal<Store>,
        identity: &'attached DeviceIdentity,
    ) -> Result<Self, FixtureRepairError> {
        let device_id = identity.device_id();
        let public_key_sha256 = sha256_bytes(&identity.public_key());
        let limits = JournalReplayLimits::new(MAX_BROKER_EVENTS, MAX_REPLAY_BYTES)
            .map_err(|_| FixtureRepairError::InvalidJournal)?;
        let initial = ReplayState::new(device_id.clone(), public_key_sha256.clone());
        let (mut replay, summary) = journal
            .fold(limits, initial, |state, entry| state.apply(entry))
            .map_err(map_replay_error)?;
        let journal_id = hex_bytes(&summary.head.journal_id);

        if summary.entries == 0 {
            let binding = JournalEvent::DeviceBound(DeviceBoundEvent {
                device_id,
                public_key_sha256,
                journal_id: journal_id.clone(),
            });
            let bytes = encode_event(&binding)?;
            let entry = journal
                .append_expected(summary.head, &bytes)
                .map_err(|_| FixtureRepairError::JournalUnavailable)?;
            replay.bound = true;
            replay.bound_journal_id = Some(journal_id);
            return Ok(Self {
                config,
                journal,
                identity,
                head: anchor_from_entry(summary.head.journal_id, &entry),
                used_approval_ids: replay.used_approval_ids,
                completed_receipts: replay.completed_receipts,
                completed_reports: replay.completed_reports,
                last_approval_sequence: replay.last_approval_sequence,
                mutation_blocked: false,
            });
        }

        if !replay.bound || replay.bound_journal_id.as_deref() != Some(journal_id.as_str()) {
            return Err(FixtureRepairError::DeviceBindingMismatch);
        }

        let mut broker = Self {
            config,
            journal,
            identity,
            head: summary.head,
            used_approval_ids: replay.used_approval_ids,
            completed_receipts: replay.completed_receipts,
            completed_reports: replay.completed_reports,
            last_approval_sequence: replay.last_approval_sequence,
            mutation_blocked: replay.mutation_blocked,
        };

        if let Some(pending) = replay.pending.take() {
            broker.mutation_blocked = true;
            broker
                .append_pending_recovery(&pending)
                .map_err(|_| FixtureRepairError::JournalUnavailable)?;
        }
        Ok(broker)
    }

    #[must_use]
    pub const fn is_mutation_blocked(&self) -> bool {
        self.mutation_blocked
    }

    pub fn next_approval_sequence(&self) -> Result<u64, FixtureRepairError> {
        if self.used_approval_ids.len() >= MAX_APPROVALS {
            return Err(FixtureRepairError::CapacityExceeded);
        }
        self.last_approval_sequence
            .checked_add(1)
            .ok_or(FixtureRepairError::CapacityExceeded)
    }

    /// Reissue the deterministic device signature for a completed receipt
    /// reconstructed from the authenticated journal. This is the recovery path
    /// when power is lost after the completed event but before the original
    /// caller persists the returned envelope.
    pub fn reissue_completed_receipt(
        &mut self,
        approval_id: &str,
    ) -> Result<SignedFixtureRepairReceipt, FixtureRepairError> {
        validate_approval_id(approval_id).map_err(|_| FixtureRepairError::InvalidApproval)?;
        let current = self
            .journal
            .head()
            .map_err(|_| FixtureRepairError::JournalUnavailable)?;
        if current != self.head {
            return Err(FixtureRepairError::JournalUnavailable);
        }
        let completed = self
            .completed_receipts
            .get(approval_id)
            .ok_or(FixtureRepairError::InvalidReceipt)?;
        validate_receipt_payload(&completed.payload)
            .map_err(|_| FixtureRepairError::InvalidReceipt)?;
        let payload_bytes = serde_json::to_vec(&completed.payload)
            .map_err(|_| FixtureRepairError::ReceiptUnavailable)?;
        let envelope = self
            .identity
            .sign_report_envelope(
                &payload_bytes,
                RECEIPT_MEDIA_TYPE,
                completed.journal_sequence,
                &completed.journal_entry_hash,
            )
            .map_err(|_| FixtureRepairError::ReceiptUnavailable)?;
        Ok(SignedFixtureRepairReceipt { envelope })
    }

    /// Reissue the final cycle report from the authenticated rolled-back
    /// completion. The lookup key is the original repair approval ID.
    pub fn reissue_completed_report(
        &mut self,
        repair_approval_id: &str,
    ) -> Result<SignedFixtureRepairReport, FixtureRepairError> {
        validate_approval_id(repair_approval_id)
            .map_err(|_| FixtureRepairError::InvalidApproval)?;
        let current = self
            .journal
            .head()
            .map_err(|_| FixtureRepairError::JournalUnavailable)?;
        if current != self.head {
            return Err(FixtureRepairError::JournalUnavailable);
        }
        let completed = self
            .completed_reports
            .get(repair_approval_id)
            .ok_or(FixtureRepairError::InvalidReceipt)?;
        validate_report_payload(&completed.payload)
            .map_err(|_| FixtureRepairError::InvalidReceipt)?;
        let payload_bytes = serde_json::to_vec(&completed.payload)
            .map_err(|_| FixtureRepairError::ReceiptUnavailable)?;
        let envelope = self
            .identity
            .sign_report_envelope(
                &payload_bytes,
                REPORT_MEDIA_TYPE,
                completed.journal_sequence,
                &completed.journal_entry_hash,
            )
            .map_err(|_| FixtureRepairError::ReceiptUnavailable)?;
        Ok(SignedFixtureRepairReport { envelope })
    }

    /// Read-only staging for the rollback transaction. The trusted repair
    /// receipt and backup path are reconstructed only from the journal and
    /// local configuration.
    pub fn stage_rollback(
        &self,
        request: StageFixtureRollbackRequest<'_>,
    ) -> Result<StagedFixtureRollback, FixtureRepairError> {
        if self.mutation_blocked {
            return Err(FixtureRepairError::MutationBlocked);
        }
        validate_session_id(request.session_id).map_err(|_| FixtureRepairError::InvalidStage)?;
        validate_plan_id(request.plan_id).map_err(|_| FixtureRepairError::InvalidStage)?;
        validate_approval_id(request.repair_approval_id)
            .map_err(|_| FixtureRepairError::InvalidStage)?;
        if self
            .completed_reports
            .contains_key(request.repair_approval_id)
        {
            return Err(FixtureRepairError::InvalidStage);
        }
        let completed = self
            .completed_receipts
            .get(request.repair_approval_id)
            .ok_or(FixtureRepairError::InvalidStage)?;
        let repair_payload = &completed.payload;
        if repair_payload.session_id != request.session_id
            || repair_payload.plan_id == request.plan_id
        {
            return Err(FixtureRepairError::InvalidStage);
        }
        let repair = pack_repair_receipt(&self.config, repair_payload)
            .map_err(|_| FixtureRepairError::InvalidReceipt)?;
        let preview = preview_missing_fstab_device_rollback(&self.config.fixture_root, &repair)
            .map_err(|_| FixtureRepairError::StaleTarget)?;
        if preview.target_fingerprint != repair_payload.after_target_precondition
            || preview.installed_sha256 != repair_payload.after_sha256
            || preview.restored_sha256 != repair_payload.before_sha256
            || preview.backup_sha256 != repair_payload.backup_sha256
            || preview.validation != ROLLBACK_VALIDATION_DECLARATION
        {
            return Err(FixtureRepairError::InvalidReceipt);
        }
        let mut staged = StagedFixtureRollback {
            session_id: request.session_id.to_owned(),
            plan_id: request.plan_id.to_owned(),
            repair_approval_id: request.repair_approval_id.to_owned(),
            repair_plan_hash: repair_payload.plan_hash.clone(),
            resource_id: FIXTURE_RESOURCE_ID,
            target_snapshot: preview.target_fingerprint,
            installed_sha256: preview.installed_sha256,
            restored_sha256: preview.restored_sha256,
            backup_locator: repair_payload.backup_locator.clone(),
            backup_sha256: preview.backup_sha256,
            plan_hash: String::new(),
        };
        staged.plan_hash = compute_rollback_plan_hash(&staged);
        Ok(staged)
    }

    /// Preview and bind the pinned fixture transaction without writing either
    /// the journal or target.
    pub fn stage(
        &self,
        request: StageFixtureRepairRequest<'_>,
    ) -> Result<StagedFixtureRepair, FixtureRepairError> {
        if self.mutation_blocked {
            return Err(FixtureRepairError::MutationBlocked);
        }
        if request.action_id != FIXTURE_ACTION_ID {
            return Err(FixtureRepairError::UnsupportedAction);
        }
        validate_session_id(request.session_id).map_err(|_| FixtureRepairError::InvalidStage)?;
        validate_plan_id(request.plan_id).map_err(|_| FixtureRepairError::InvalidStage)?;
        validate_sha256(request.diagnosis_sha256).map_err(|_| FixtureRepairError::InvalidStage)?;
        if request.finding_id != FINDING_ID || request.finding_version != FINDING_VERSION {
            return Err(FixtureRepairError::InvalidStage);
        }
        let evidence = canonical_evidence_bindings(request.evidence)
            .map_err(|_| FixtureRepairError::InvalidStage)?;
        let evidence_ids = evidence
            .iter()
            .map(|binding| binding.id.clone())
            .collect::<Vec<_>>();
        let preview = preview_missing_fstab_device(&self.config.fixture_root, &evidence_ids)
            .map_err(|_| FixtureRepairError::FixtureRejected)?;
        let actual_before = preview.target_content_fingerprint;
        let actual_after = sha256_bytes(preview.after.as_bytes());
        if !preview.backup_required
            || preview.validation != VALIDATION_DECLARATION
            || preview.rollback != ROLLBACK_DECLARATION
        {
            return Err(FixtureRepairError::ContractMismatch);
        }
        validate_sha256(&preview.target_fingerprint)
            .map_err(|_| FixtureRepairError::FixtureRejected)?;
        let backup_locator =
            backup_locator_for(&actual_before).map_err(|_| FixtureRepairError::FixtureRejected)?;
        let backup_path = backup_path_for(&self.config.backup_dir, &actual_before)
            .map_err(|_| FixtureRepairError::FixtureRejected)?;
        match fs::symlink_metadata(backup_path) {
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            _ => return Err(FixtureRepairError::FixtureRejected),
        }

        let mut staged = StagedFixtureRepair {
            session_id: request.session_id.to_owned(),
            plan_id: request.plan_id.to_owned(),
            action_id: FIXTURE_ACTION_ID,
            resource_id: FIXTURE_RESOURCE_ID,
            diagnosis_sha256: request.diagnosis_sha256.to_owned(),
            finding_id: FINDING_ID,
            finding_version: FINDING_VERSION,
            evidence,
            target_snapshot: preview.target_fingerprint,
            expected_before_sha256: actual_before,
            expected_after_sha256: actual_after,
            diff_sha256: diff_sha256(preview.before.as_bytes(), preview.after.as_bytes()),
            backup_locator,
            plan_hash: String::new(),
        };
        staged.plan_hash = compute_plan_hash(&staged);
        let core_plan = ValidatedPlan {
            plan_id: staged.plan_id.clone(),
            target_fingerprint: staged.target_snapshot.clone(),
            steps: vec![ActionStep {
                action: staged.action_id.to_owned(),
                risk: Risk::R2,
                target_fingerprint: staged.target_snapshot.clone(),
                evidence_ids: staged
                    .evidence
                    .iter()
                    .map(|binding| binding.id.clone())
                    .collect(),
                preconditions: vec!["linux.fstab.preflight".to_owned()],
                backup: Some("required".to_owned()),
                validation: "linux.boot.validate-fstab".to_owned(),
                rollback: Some(FIXTURE_ROLLBACK_ID.to_owned()),
            }],
        };
        validate_fixture_repair_lab_plan(&core_plan, &staged.target_snapshot)
            .map_err(|_| FixtureRepairError::ContractMismatch)?;
        Ok(staged)
    }

    /// Durably record intent, run the real fixture transaction, append a
    /// completion record, and return a device-signed receipt. Any failure after
    /// durable intent records manual recovery and blocks all later mutation.
    pub fn execute(
        &mut self,
        staged: &StagedFixtureRepair,
        approval: FixtureRepairApproval<'_>,
    ) -> Result<SignedFixtureRepairReceipt, FixtureRepairError> {
        self.validate_approval(staged, &approval)?;
        self.fresh_preview_matches(staged)?;

        let pending = match self.append_intent(staged, &approval) {
            Ok(pending) => pending,
            Err(error) => {
                self.mutation_blocked = true;
                return Err(error);
            }
        };

        let internal_approval = format!(
            "fixture-broker-v1:{}:{}",
            approval.approval_sequence,
            staged.plan_hash.strip_prefix("sha256:").unwrap_or_default()
        );
        let evidence_ids = staged
            .evidence
            .iter()
            .map(|binding| binding.id.clone())
            .collect::<Vec<_>>();
        let repair = match execute_missing_fstab_device_repair(
            &self.config.fixture_root,
            &self.config.backup_dir,
            &staged.target_snapshot,
            &evidence_ids,
            &internal_approval,
        ) {
            Ok(repair) => repair,
            Err(_) => {
                self.block_with_recovery(&pending);
                return Err(FixtureRepairError::ExecutionOutcomeUnknown);
            }
        };

        if repair.before_fingerprint != staged.expected_before_sha256
            || repair.after_fingerprint != staged.expected_after_sha256
            || repair.backup_fingerprint != staged.expected_before_sha256
            || repair.backup_path
                != match backup_path_for(&self.config.backup_dir, &staged.expected_before_sha256) {
                    Ok(path) => path,
                    Err(_) => {
                        self.block_with_recovery(&pending);
                        return Err(FixtureRepairError::ExecutionOutcomeUnknown);
                    }
                }
            || !repair.validation_passed
            || !repair.metadata_preserved
        {
            self.block_with_recovery(&pending);
            return Err(FixtureRepairError::ExecutionOutcomeUnknown);
        }

        let completion_sequence = match self.head.sequence.checked_add(1) {
            Some(sequence) => sequence,
            None => {
                self.block_with_recovery(&pending);
                return Err(FixtureRepairError::ExecutionOutcomeUnknown);
            }
        };
        let payload = FixtureRepairReceiptPayload {
            api_version: RECEIPT_API_VERSION.to_owned(),
            kind: RECEIPT_KIND.to_owned(),
            device_id: self.identity.device_id(),
            journal_id: hex_bytes(&self.head.journal_id),
            journal_sequence: completion_sequence,
            intent_journal_sequence: pending.journal_sequence,
            approval_id: pending.approval_id.clone(),
            approval_sequence: pending.approval_sequence,
            approval_decision: "approved".to_owned(),
            risk: RISK.to_owned(),
            session_id: pending.session_id.clone(),
            plan_id: pending.plan_id.clone(),
            plan_hash: pending.plan_hash.clone(),
            action_id: pending.action_id.clone(),
            resource_id: pending.resource_id.clone(),
            diagnosis_sha256: pending.diagnosis_sha256.clone(),
            finding_id: pending.finding_id.clone(),
            finding_version: pending.finding_version,
            evidence: pending.evidence.clone(),
            target_snapshot: pending.target_snapshot.clone(),
            before_sha256: repair.before_fingerprint,
            after_sha256: repair.after_fingerprint,
            after_target_precondition: repair.after_target_precondition,
            diff_sha256: pending.diff_sha256.clone(),
            backup_locator: pending.backup_locator.clone(),
            backup_sha256: repair.backup_fingerprint,
            backup: BACKUP_RESULT.to_owned(),
            validation: VALIDATION_DECLARATION.to_owned(),
            rollback: ROLLBACK_DECLARATION.to_owned(),
            validation_passed: repair.validation_passed,
            metadata_preserved: repair.metadata_preserved,
            before_mode: repair.before_metadata.mode,
            before_uid: repair.before_metadata.uid,
            before_gid: repair.before_metadata.gid,
        };
        let payload_bytes = match serde_json::to_vec(&payload) {
            Ok(bytes) if bytes.len() <= MAX_BROKER_EVENT_BYTES => bytes,
            _ => {
                self.block_with_recovery(&pending);
                return Err(FixtureRepairError::ExecutionOutcomeUnknown);
            }
        };
        let completed = CompletedEvent {
            receipt: payload,
            receipt_payload_sha256: sha256_bytes(&payload_bytes),
        };
        let completed_entry =
            match self.append_event(&JournalEvent::Completed(Box::new(completed.clone()))) {
                Ok(entry) => entry,
                Err(_) => {
                    self.block_with_recovery(&pending);
                    return Err(FixtureRepairError::ExecutionOutcomeUnknown);
                }
            };
        if completed_entry.sequence != completion_sequence {
            self.mutation_blocked = true;
            return Err(FixtureRepairError::ReceiptUnavailable);
        }

        self.completed_receipts.insert(
            pending.approval_id.clone(),
            RecoverableReceipt {
                payload: completed.receipt,
                journal_sequence: completed_entry.sequence,
                journal_entry_hash: completed_entry.entry_hash,
            },
        );
        self.reissue_completed_receipt(&pending.approval_id)
    }

    /// Execute the separately staged and approved rollback, then sign the
    /// strict end-to-end cycle report against the rolled-back journal head.
    pub fn execute_rollback(
        &mut self,
        staged: &StagedFixtureRollback,
        approval: FixtureRollbackApproval<'_>,
    ) -> Result<SignedFixtureRepairReport, FixtureRepairError> {
        self.validate_rollback_approval(staged, &approval)?;
        let repair_payload = self
            .completed_receipts
            .get(&staged.repair_approval_id)
            .ok_or(FixtureRepairError::InvalidReceipt)?
            .payload
            .clone();
        self.fresh_rollback_preview_matches(staged, &repair_payload)?;

        let pending = match self.append_rollback_intent(staged, &approval, &repair_payload) {
            Ok(pending) => pending,
            Err(error) => {
                self.mutation_blocked = true;
                return Err(error);
            }
        };
        let repair = match pack_repair_receipt(&self.config, &repair_payload) {
            Ok(repair) => repair,
            Err(_) => {
                self.block_with_rollback_recovery(&pending);
                return Err(FixtureRepairError::ExecutionOutcomeUnknown);
            }
        };
        let internal_approval = format!(
            "fixture-broker-rollback-v1:{}:{}",
            approval.approval_sequence,
            staged.plan_hash.strip_prefix("sha256:").unwrap_or_default()
        );
        let rollback = match rollback_missing_fstab_device_repair(
            &self.config.fixture_root,
            &repair,
            &internal_approval,
        ) {
            Ok(rollback) => rollback,
            Err(_) => {
                self.block_with_rollback_recovery(&pending);
                return Err(FixtureRepairError::ExecutionOutcomeUnknown);
            }
        };
        if rollback.replaced_fingerprint != staged.installed_sha256
            || rollback.restored_fingerprint != staged.restored_sha256
            || rollback.backup_fingerprint != staged.backup_sha256
            || rollback.backup_path
                != match backup_path_for(&self.config.backup_dir, &staged.restored_sha256) {
                    Ok(path) => path,
                    Err(_) => {
                        self.block_with_rollback_recovery(&pending);
                        return Err(FixtureRepairError::ExecutionOutcomeUnknown);
                    }
                }
            || rollback.automatic
            || !rollback.validation_passed
            || !rollback.metadata_preserved
        {
            self.block_with_rollback_recovery(&pending);
            return Err(FixtureRepairError::ExecutionOutcomeUnknown);
        }

        let completion_sequence = match self.head.sequence.checked_add(1) {
            Some(sequence) => sequence,
            None => {
                self.block_with_rollback_recovery(&pending);
                return Err(FixtureRepairError::ExecutionOutcomeUnknown);
            }
        };
        let report = FixtureRepairReportPayload {
            api_version: REPORT_API_VERSION.to_owned(),
            kind: REPORT_KIND.to_owned(),
            device_id: self.identity.device_id(),
            journal_id: hex_bytes(&self.head.journal_id),
            journal_sequence: completion_sequence,
            repair: repair_payload,
            rollback: FixtureRollbackReportPayload {
                journal_sequence: completion_sequence,
                intent_journal_sequence: pending.journal_sequence,
                approval_id: pending.approval_id.clone(),
                approval_sequence: pending.approval_sequence,
                approval_decision: "approved".to_owned(),
                risk: RISK.to_owned(),
                plan_id: pending.plan_id.clone(),
                plan_hash: pending.plan_hash.clone(),
                action_id: pending.action_id.clone(),
                resource_id: pending.resource_id.clone(),
                target_snapshot: pending.target_snapshot.clone(),
                replaced_sha256: rollback.replaced_fingerprint,
                restored_sha256: rollback.restored_fingerprint,
                backup_locator: pending.backup_locator.clone(),
                backup_sha256: rollback.backup_fingerprint,
                validation: ROLLBACK_VALIDATION_DECLARATION.to_owned(),
                validation_passed: rollback.validation_passed,
                metadata_preserved: rollback.metadata_preserved,
            },
            final_state: "rolled-back".to_owned(),
        };
        let payload_bytes = match serde_json::to_vec(&report) {
            Ok(bytes) if bytes.len() <= MAX_BROKER_EVENT_BYTES => bytes,
            _ => {
                self.block_with_rollback_recovery(&pending);
                return Err(FixtureRepairError::ExecutionOutcomeUnknown);
            }
        };
        let completed = RolledBackEvent {
            report,
            report_payload_sha256: sha256_bytes(&payload_bytes),
        };
        let completed_entry =
            match self.append_event(&JournalEvent::RolledBack(Box::new(completed.clone()))) {
                Ok(entry) => entry,
                Err(_) => {
                    self.block_with_rollback_recovery(&pending);
                    return Err(FixtureRepairError::ExecutionOutcomeUnknown);
                }
            };
        if completed_entry.sequence != completion_sequence {
            self.mutation_blocked = true;
            return Err(FixtureRepairError::ReceiptUnavailable);
        }
        self.completed_reports.insert(
            staged.repair_approval_id.clone(),
            RecoverableReport {
                payload: completed.report,
                journal_sequence: completed_entry.sequence,
                journal_entry_hash: completed_entry.entry_hash,
            },
        );
        self.reissue_completed_report(&staged.repair_approval_id)
    }

    fn validate_rollback_approval(
        &self,
        staged: &StagedFixtureRollback,
        approval: &FixtureRollbackApproval<'_>,
    ) -> Result<(), FixtureRepairError> {
        if self.mutation_blocked {
            return Err(FixtureRepairError::MutationBlocked);
        }
        validate_approval_id(approval.approval_id)
            .map_err(|_| FixtureRepairError::InvalidApproval)?;
        if self.used_approval_ids.contains(approval.approval_id) {
            return Err(FixtureRepairError::ApprovalReused);
        }
        if self.used_approval_ids.len() >= MAX_APPROVALS {
            return Err(FixtureRepairError::CapacityExceeded);
        }
        if approval.approval_sequence != self.next_approval_sequence()? {
            return Err(FixtureRepairError::NonMonotonicApproval);
        }
        if self
            .completed_reports
            .contains_key(&staged.repair_approval_id)
            || approval.session_id != staged.session_id
            || approval.plan_id != staged.plan_id
            || approval.plan_hash != staged.plan_hash
            || approval.target_snapshot != staged.target_snapshot
            || staged.resource_id != FIXTURE_RESOURCE_ID
            || compute_rollback_plan_hash(staged) != staged.plan_hash
        {
            return Err(FixtureRepairError::ApprovalMismatch);
        }
        Ok(())
    }

    fn fresh_rollback_preview_matches(
        &self,
        staged: &StagedFixtureRollback,
        repair_payload: &FixtureRepairReceiptPayload,
    ) -> Result<(), FixtureRepairError> {
        let repair = pack_repair_receipt(&self.config, repair_payload)
            .map_err(|_| FixtureRepairError::InvalidReceipt)?;
        let preview = preview_missing_fstab_device_rollback(&self.config.fixture_root, &repair)
            .map_err(|_| FixtureRepairError::StaleTarget)?;
        if preview.target_fingerprint != staged.target_snapshot
            || preview.installed_sha256 != staged.installed_sha256
            || preview.restored_sha256 != staged.restored_sha256
            || preview.backup_sha256 != staged.backup_sha256
            || preview.validation != ROLLBACK_VALIDATION_DECLARATION
            || staged.backup_locator != repair_payload.backup_locator
        {
            return Err(FixtureRepairError::StaleTarget);
        }
        Ok(())
    }

    fn append_rollback_intent(
        &mut self,
        staged: &StagedFixtureRollback,
        approval: &FixtureRollbackApproval<'_>,
        repair: &FixtureRepairReceiptPayload,
    ) -> Result<RollbackIntentEvent, FixtureRepairError> {
        let journal_sequence = self
            .head
            .sequence
            .checked_add(1)
            .ok_or(FixtureRepairError::CapacityExceeded)?;
        let intent = RollbackIntentEvent {
            journal_sequence,
            approval_id: approval.approval_id.to_owned(),
            approval_sequence: approval.approval_sequence,
            session_id: staged.session_id.clone(),
            plan_id: staged.plan_id.clone(),
            plan_hash: staged.plan_hash.clone(),
            repair_approval_id: staged.repair_approval_id.clone(),
            repair_plan_hash: staged.repair_plan_hash.clone(),
            repair_journal_sequence: repair.journal_sequence,
            action_id: FIXTURE_ROLLBACK_ID.to_owned(),
            resource_id: FIXTURE_RESOURCE_ID.to_owned(),
            target_snapshot: staged.target_snapshot.clone(),
            installed_sha256: staged.installed_sha256.clone(),
            restored_sha256: staged.restored_sha256.clone(),
            backup_locator: staged.backup_locator.clone(),
            backup_sha256: staged.backup_sha256.clone(),
        };
        self.append_event(&JournalEvent::RollbackIntent(intent.clone()))?;
        self.used_approval_ids.insert(intent.approval_id.clone());
        self.last_approval_sequence = intent.approval_sequence;
        Ok(intent)
    }

    fn validate_approval(
        &self,
        staged: &StagedFixtureRepair,
        approval: &FixtureRepairApproval<'_>,
    ) -> Result<(), FixtureRepairError> {
        if self.mutation_blocked {
            return Err(FixtureRepairError::MutationBlocked);
        }
        validate_approval_id(approval.approval_id)
            .map_err(|_| FixtureRepairError::InvalidApproval)?;
        if self.used_approval_ids.contains(approval.approval_id) {
            return Err(FixtureRepairError::ApprovalReused);
        }
        if self.used_approval_ids.len() >= MAX_APPROVALS {
            return Err(FixtureRepairError::CapacityExceeded);
        }
        if approval.approval_sequence != self.next_approval_sequence()? {
            return Err(FixtureRepairError::NonMonotonicApproval);
        }
        if approval.session_id != staged.session_id
            || approval.plan_id != staged.plan_id
            || approval.plan_hash != staged.plan_hash
            || approval.target_snapshot != staged.target_snapshot
            || staged.action_id != FIXTURE_ACTION_ID
            || staged.resource_id != FIXTURE_RESOURCE_ID
            || compute_plan_hash(staged) != staged.plan_hash
        {
            return Err(FixtureRepairError::ApprovalMismatch);
        }
        Ok(())
    }

    fn fresh_preview_matches(
        &self,
        staged: &StagedFixtureRepair,
    ) -> Result<(), FixtureRepairError> {
        let evidence_ids = staged
            .evidence
            .iter()
            .map(|binding| binding.id.clone())
            .collect::<Vec<_>>();
        let preview = preview_missing_fstab_device(&self.config.fixture_root, &evidence_ids)
            .map_err(|_| FixtureRepairError::StaleTarget)?;
        if preview.target_fingerprint != staged.target_snapshot
            || preview.target_content_fingerprint != staged.expected_before_sha256
            || sha256_bytes(preview.after.as_bytes()) != staged.expected_after_sha256
            || diff_sha256(preview.before.as_bytes(), preview.after.as_bytes())
                != staged.diff_sha256
            || backup_locator_for(&staged.expected_before_sha256).as_deref()
                != Ok(staged.backup_locator.as_str())
            || !preview.backup_required
            || preview.validation != VALIDATION_DECLARATION
            || preview.rollback != ROLLBACK_DECLARATION
        {
            return Err(FixtureRepairError::StaleTarget);
        }
        Ok(())
    }

    fn append_intent(
        &mut self,
        staged: &StagedFixtureRepair,
        approval: &FixtureRepairApproval<'_>,
    ) -> Result<IntentEvent, FixtureRepairError> {
        let journal_sequence = self
            .head
            .sequence
            .checked_add(1)
            .ok_or(FixtureRepairError::CapacityExceeded)?;
        let intent = IntentEvent {
            journal_sequence,
            approval_id: approval.approval_id.to_owned(),
            approval_sequence: approval.approval_sequence,
            session_id: staged.session_id.clone(),
            plan_id: staged.plan_id.clone(),
            plan_hash: staged.plan_hash.clone(),
            action_id: FIXTURE_ACTION_ID.to_owned(),
            resource_id: FIXTURE_RESOURCE_ID.to_owned(),
            diagnosis_sha256: staged.diagnosis_sha256.clone(),
            finding_id: staged.finding_id.to_owned(),
            finding_version: staged.finding_version,
            evidence: staged.evidence.clone(),
            target_snapshot: staged.target_snapshot.clone(),
            expected_before_sha256: staged.expected_before_sha256.clone(),
            expected_after_sha256: staged.expected_after_sha256.clone(),
            diff_sha256: staged.diff_sha256.clone(),
            backup_locator: staged.backup_locator.clone(),
        };
        self.append_event(&JournalEvent::Intent(intent.clone()))?;
        self.used_approval_ids.insert(intent.approval_id.clone());
        self.last_approval_sequence = intent.approval_sequence;
        Ok(intent)
    }

    fn append_event(&mut self, event: &JournalEvent) -> Result<JournalEntry, FixtureRepairError> {
        let current = self
            .journal
            .head()
            .map_err(|_| FixtureRepairError::JournalUnavailable)?;
        if current != self.head {
            return Err(FixtureRepairError::JournalUnavailable);
        }
        let bytes = encode_event(event)?;
        let entry = self
            .journal
            .append_expected(self.head, &bytes)
            .map_err(|_| FixtureRepairError::JournalUnavailable)?;
        self.head = anchor_from_entry(self.head.journal_id, &entry);
        Ok(entry)
    }

    fn append_recovery(&mut self, pending: &IntentEvent) -> Result<(), FixtureRepairError> {
        self.append_pending_recovery(&PendingIntent::Repair(pending.clone()))
    }

    fn append_pending_recovery(
        &mut self,
        pending: &PendingIntent,
    ) -> Result<(), FixtureRepairError> {
        let recovery = JournalEvent::Recovery(RecoveryEvent {
            approval_id: pending.approval_id().to_owned(),
            approval_sequence: pending.approval_sequence(),
            session_id: pending.session_id().to_owned(),
            plan_id: pending.plan_id().to_owned(),
            plan_hash: pending.plan_hash().to_owned(),
            intent_journal_sequence: pending.journal_sequence(),
            disposition: RECOVERY_DISPOSITION.to_owned(),
        });
        self.append_event(&recovery)?;
        self.mutation_blocked = true;
        Ok(())
    }

    fn block_with_recovery(&mut self, pending: &IntentEvent) {
        self.mutation_blocked = true;
        let _ = self.append_recovery(pending);
    }

    fn block_with_rollback_recovery(&mut self, pending: &RollbackIntentEvent) {
        self.mutation_blocked = true;
        let _ = self.append_pending_recovery(&PendingIntent::Rollback(pending.clone()));
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct DeviceBoundEvent {
    device_id: String,
    public_key_sha256: String,
    journal_id: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct IntentEvent {
    journal_sequence: u64,
    approval_id: String,
    approval_sequence: u64,
    session_id: String,
    plan_id: String,
    plan_hash: String,
    action_id: String,
    resource_id: String,
    diagnosis_sha256: String,
    finding_id: String,
    finding_version: u32,
    evidence: Vec<FixtureEvidenceBinding>,
    target_snapshot: String,
    expected_before_sha256: String,
    expected_after_sha256: String,
    diff_sha256: String,
    backup_locator: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct CompletedEvent {
    receipt: FixtureRepairReceiptPayload,
    receipt_payload_sha256: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct RollbackIntentEvent {
    journal_sequence: u64,
    approval_id: String,
    approval_sequence: u64,
    session_id: String,
    plan_id: String,
    plan_hash: String,
    repair_approval_id: String,
    repair_plan_hash: String,
    repair_journal_sequence: u64,
    action_id: String,
    resource_id: String,
    target_snapshot: String,
    installed_sha256: String,
    restored_sha256: String,
    backup_locator: String,
    backup_sha256: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct RolledBackEvent {
    report: FixtureRepairReportPayload,
    report_payload_sha256: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct RecoveryEvent {
    approval_id: String,
    approval_sequence: u64,
    session_id: String,
    plan_id: String,
    plan_hash: String,
    intent_journal_sequence: u64,
    disposition: String,
}

#[derive(Clone)]
struct RecoverableReceipt {
    payload: FixtureRepairReceiptPayload,
    journal_sequence: u64,
    journal_entry_hash: [u8; 32],
}

#[derive(Clone)]
struct RecoverableReport {
    payload: FixtureRepairReportPayload,
    journal_sequence: u64,
    journal_entry_hash: [u8; 32],
}

#[derive(Clone)]
enum PendingIntent {
    Repair(IntentEvent),
    Rollback(RollbackIntentEvent),
}

impl PendingIntent {
    fn approval_id(&self) -> &str {
        match self {
            Self::Repair(intent) => &intent.approval_id,
            Self::Rollback(intent) => &intent.approval_id,
        }
    }

    fn approval_sequence(&self) -> u64 {
        match self {
            Self::Repair(intent) => intent.approval_sequence,
            Self::Rollback(intent) => intent.approval_sequence,
        }
    }

    fn session_id(&self) -> &str {
        match self {
            Self::Repair(intent) => &intent.session_id,
            Self::Rollback(intent) => &intent.session_id,
        }
    }

    fn plan_id(&self) -> &str {
        match self {
            Self::Repair(intent) => &intent.plan_id,
            Self::Rollback(intent) => &intent.plan_id,
        }
    }

    fn plan_hash(&self) -> &str {
        match self {
            Self::Repair(intent) => &intent.plan_hash,
            Self::Rollback(intent) => &intent.plan_hash,
        }
    }

    fn journal_sequence(&self) -> u64 {
        match self {
            Self::Repair(intent) => intent.journal_sequence,
            Self::Rollback(intent) => intent.journal_sequence,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", content = "event", deny_unknown_fields)]
enum JournalEvent {
    #[serde(rename = "fixture.repair.device-bound.v1")]
    DeviceBound(DeviceBoundEvent),
    #[serde(rename = "fixture.repair.intent.v1")]
    Intent(IntentEvent),
    #[serde(rename = "fixture.repair.completed.v1")]
    Completed(Box<CompletedEvent>),
    #[serde(rename = "fixture.rollback.intent.v1")]
    RollbackIntent(RollbackIntentEvent),
    #[serde(rename = "fixture.rollback.completed.v1")]
    RolledBack(Box<RolledBackEvent>),
    #[serde(rename = "fixture.repair.recovery.v1")]
    Recovery(RecoveryEvent),
}

struct ReplayState {
    expected_device_id: String,
    expected_public_key_sha256: String,
    bound: bool,
    bound_journal_id: Option<String>,
    used_approval_ids: HashSet<String>,
    completed_receipts: HashMap<String, RecoverableReceipt>,
    completed_reports: HashMap<String, RecoverableReport>,
    last_approval_sequence: u64,
    pending: Option<PendingIntent>,
    mutation_blocked: bool,
}

impl ReplayState {
    fn new(expected_device_id: String, expected_public_key_sha256: String) -> Self {
        Self {
            expected_device_id,
            expected_public_key_sha256,
            bound: false,
            bound_journal_id: None,
            used_approval_ids: HashSet::new(),
            completed_receipts: HashMap::new(),
            completed_reports: HashMap::new(),
            last_approval_sequence: 0,
            pending: None,
            mutation_blocked: false,
        }
    }

    fn apply(&mut self, entry: JournalEntryRef<'_>) -> Result<(), ReplayFailure> {
        if entry.event.is_empty() || entry.event.len() > MAX_BROKER_EVENT_BYTES {
            return Err(ReplayFailure);
        }
        let event: JournalEvent = strict_json(entry.event).map_err(|_| ReplayFailure)?;
        match event {
            JournalEvent::DeviceBound(binding) => {
                if entry.sequence != 1
                    || self.bound
                    || self.pending.is_some()
                    || self.last_approval_sequence != 0
                    || binding.device_id != self.expected_device_id
                    || binding.public_key_sha256 != self.expected_public_key_sha256
                    || !valid_journal_id(&binding.journal_id)
                {
                    return Err(ReplayFailure);
                }
                self.bound_journal_id = Some(binding.journal_id);
                self.bound = true;
            }
            JournalEvent::Intent(intent) => {
                if !self.bound
                    || self.mutation_blocked
                    || self.pending.is_some()
                    || self.used_approval_ids.len() >= MAX_APPROVALS
                    || intent.journal_sequence != entry.sequence
                    || intent.approval_sequence
                        != self
                            .last_approval_sequence
                            .checked_add(1)
                            .ok_or(ReplayFailure)?
                    || self.used_approval_ids.contains(&intent.approval_id)
                    || validate_intent(&intent).is_err()
                {
                    return Err(ReplayFailure);
                }
                self.used_approval_ids.insert(intent.approval_id.clone());
                self.last_approval_sequence = intent.approval_sequence;
                self.pending = Some(PendingIntent::Repair(intent));
            }
            JournalEvent::Completed(completed) => {
                let Some(PendingIntent::Repair(pending)) = self.pending.as_ref() else {
                    return Err(ReplayFailure);
                };
                let journal_id = self.bound_journal_id.as_deref().ok_or(ReplayFailure)?;
                validate_completed(
                    &completed,
                    pending,
                    &self.expected_device_id,
                    journal_id,
                    entry.sequence,
                )?;
                if self
                    .completed_receipts
                    .insert(
                        pending.approval_id.clone(),
                        RecoverableReceipt {
                            payload: completed.receipt,
                            journal_sequence: entry.sequence,
                            journal_entry_hash: entry.entry_hash,
                        },
                    )
                    .is_some()
                {
                    return Err(ReplayFailure);
                }
                self.pending = None;
            }
            JournalEvent::RollbackIntent(intent) => {
                let repair = self
                    .completed_receipts
                    .get(&intent.repair_approval_id)
                    .ok_or(ReplayFailure)?;
                if !self.bound
                    || self.mutation_blocked
                    || self.pending.is_some()
                    || self.used_approval_ids.len() >= MAX_APPROVALS
                    || self
                        .completed_reports
                        .contains_key(&intent.repair_approval_id)
                    || intent.journal_sequence != entry.sequence
                    || intent.approval_sequence
                        != self
                            .last_approval_sequence
                            .checked_add(1)
                            .ok_or(ReplayFailure)?
                    || self.used_approval_ids.contains(&intent.approval_id)
                    || validate_rollback_intent(&intent, &repair.payload).is_err()
                {
                    return Err(ReplayFailure);
                }
                self.used_approval_ids.insert(intent.approval_id.clone());
                self.last_approval_sequence = intent.approval_sequence;
                self.pending = Some(PendingIntent::Rollback(intent));
            }
            JournalEvent::RolledBack(rolled_back) => {
                let Some(PendingIntent::Rollback(pending)) = self.pending.as_ref() else {
                    return Err(ReplayFailure);
                };
                let journal_id = self.bound_journal_id.as_deref().ok_or(ReplayFailure)?;
                validate_rolled_back(
                    &rolled_back,
                    pending,
                    &self.expected_device_id,
                    journal_id,
                    entry.sequence,
                )?;
                if self
                    .completed_reports
                    .insert(
                        pending.repair_approval_id.clone(),
                        RecoverableReport {
                            payload: rolled_back.report,
                            journal_sequence: entry.sequence,
                            journal_entry_hash: entry.entry_hash,
                        },
                    )
                    .is_some()
                {
                    return Err(ReplayFailure);
                }
                self.pending = None;
            }
            JournalEvent::Recovery(recovery) => {
                let pending = self.pending.as_ref().ok_or(ReplayFailure)?;
                if recovery.approval_id != pending.approval_id()
                    || recovery.approval_sequence != pending.approval_sequence()
                    || recovery.session_id != pending.session_id()
                    || recovery.plan_id != pending.plan_id()
                    || recovery.plan_hash != pending.plan_hash()
                    || recovery.intent_journal_sequence != pending.journal_sequence()
                    || recovery.disposition != RECOVERY_DISPOSITION
                {
                    return Err(ReplayFailure);
                }
                self.pending = None;
                self.mutation_blocked = true;
            }
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct ReplayFailure;

fn map_replay_error(error: JournalReplayError<ReplayFailure>) -> FixtureRepairError {
    match error {
        JournalReplayError::Journal(_) | JournalReplayError::Callback(_) => {
            FixtureRepairError::InvalidJournal
        }
    }
}

fn validate_intent(intent: &IntentEvent) -> Result<(), ReplayFailure> {
    validate_approval_id(&intent.approval_id)?;
    validate_session_id(&intent.session_id)?;
    validate_plan_id(&intent.plan_id)?;
    validate_sha256(&intent.plan_hash)?;
    validate_sha256(&intent.diagnosis_sha256)?;
    validate_sha256(&intent.target_snapshot)?;
    validate_sha256(&intent.expected_before_sha256)?;
    validate_sha256(&intent.expected_after_sha256)?;
    validate_sha256(&intent.diff_sha256)?;
    if intent.expected_before_sha256 == intent.expected_after_sha256
        || intent.action_id != FIXTURE_ACTION_ID
        || intent.resource_id != FIXTURE_RESOURCE_ID
        || intent.finding_id != FINDING_ID
        || intent.finding_version != FINDING_VERSION
        || !canonical_evidence_binding_slice(&intent.evidence)
        || backup_locator_for(&intent.expected_before_sha256).as_deref()
            != Ok(intent.backup_locator.as_str())
    {
        return Err(ReplayFailure);
    }
    let staged = StagedFixtureRepair {
        session_id: intent.session_id.clone(),
        plan_id: intent.plan_id.clone(),
        action_id: FIXTURE_ACTION_ID,
        resource_id: FIXTURE_RESOURCE_ID,
        diagnosis_sha256: intent.diagnosis_sha256.clone(),
        finding_id: FINDING_ID,
        finding_version: FINDING_VERSION,
        evidence: intent.evidence.clone(),
        target_snapshot: intent.target_snapshot.clone(),
        expected_before_sha256: intent.expected_before_sha256.clone(),
        expected_after_sha256: intent.expected_after_sha256.clone(),
        diff_sha256: intent.diff_sha256.clone(),
        backup_locator: intent.backup_locator.clone(),
        plan_hash: String::new(),
    };
    if compute_plan_hash(&staged) != intent.plan_hash {
        return Err(ReplayFailure);
    }
    Ok(())
}

fn validate_completed(
    completed: &CompletedEvent,
    pending: &IntentEvent,
    expected_device_id: &str,
    journal_id: &str,
    journal_sequence: u64,
) -> Result<(), ReplayFailure> {
    let payload = &completed.receipt;
    validate_receipt_payload(payload)?;
    let bytes = serde_json::to_vec(payload).map_err(|_| ReplayFailure)?;
    if completed.receipt_payload_sha256 != sha256_bytes(&bytes)
        || payload.device_id != expected_device_id
        || payload.journal_id != journal_id
        || payload.journal_sequence != journal_sequence
        || payload.intent_journal_sequence != pending.journal_sequence
        || payload.approval_id != pending.approval_id
        || payload.approval_sequence != pending.approval_sequence
        || payload.session_id != pending.session_id
        || payload.plan_id != pending.plan_id
        || payload.plan_hash != pending.plan_hash
        || payload.action_id != pending.action_id
        || payload.resource_id != pending.resource_id
        || payload.diagnosis_sha256 != pending.diagnosis_sha256
        || payload.finding_id != pending.finding_id
        || payload.finding_version != pending.finding_version
        || payload.evidence != pending.evidence
        || payload.target_snapshot != pending.target_snapshot
        || payload.before_sha256 != pending.expected_before_sha256
        || payload.after_sha256 != pending.expected_after_sha256
        || payload.diff_sha256 != pending.diff_sha256
        || payload.backup_locator != pending.backup_locator
        || payload.backup_sha256 != pending.expected_before_sha256
    {
        return Err(ReplayFailure);
    }
    Ok(())
}

fn validate_rollback_intent(
    intent: &RollbackIntentEvent,
    repair: &FixtureRepairReceiptPayload,
) -> Result<(), ReplayFailure> {
    validate_approval_id(&intent.approval_id)?;
    validate_session_id(&intent.session_id)?;
    validate_plan_id(&intent.plan_id)?;
    validate_sha256(&intent.plan_hash)?;
    validate_sha256(&intent.repair_plan_hash)?;
    validate_sha256(&intent.target_snapshot)?;
    validate_sha256(&intent.installed_sha256)?;
    validate_sha256(&intent.restored_sha256)?;
    validate_sha256(&intent.backup_sha256)?;
    if intent.action_id != FIXTURE_ROLLBACK_ID
        || intent.resource_id != FIXTURE_RESOURCE_ID
        || intent.session_id != repair.session_id
        || intent.repair_approval_id != repair.approval_id
        || intent.repair_plan_hash != repair.plan_hash
        || intent.repair_journal_sequence != repair.journal_sequence
        || intent.target_snapshot != repair.after_target_precondition
        || intent.installed_sha256 != repair.after_sha256
        || intent.restored_sha256 != repair.before_sha256
        || intent.backup_locator != repair.backup_locator
        || intent.backup_sha256 != repair.backup_sha256
    {
        return Err(ReplayFailure);
    }
    let staged = StagedFixtureRollback {
        session_id: intent.session_id.clone(),
        plan_id: intent.plan_id.clone(),
        repair_approval_id: intent.repair_approval_id.clone(),
        repair_plan_hash: intent.repair_plan_hash.clone(),
        resource_id: FIXTURE_RESOURCE_ID,
        target_snapshot: intent.target_snapshot.clone(),
        installed_sha256: intent.installed_sha256.clone(),
        restored_sha256: intent.restored_sha256.clone(),
        backup_locator: intent.backup_locator.clone(),
        backup_sha256: intent.backup_sha256.clone(),
        plan_hash: String::new(),
    };
    if compute_rollback_plan_hash(&staged) != intent.plan_hash {
        return Err(ReplayFailure);
    }
    Ok(())
}

fn validate_rolled_back(
    completed: &RolledBackEvent,
    pending: &RollbackIntentEvent,
    expected_device_id: &str,
    journal_id: &str,
    journal_sequence: u64,
) -> Result<(), ReplayFailure> {
    validate_report_payload(&completed.report)?;
    let bytes = serde_json::to_vec(&completed.report).map_err(|_| ReplayFailure)?;
    let rollback = &completed.report.rollback;
    if completed.report_payload_sha256 != sha256_bytes(&bytes)
        || completed.report.device_id != expected_device_id
        || completed.report.journal_id != journal_id
        || completed.report.journal_sequence != journal_sequence
        || rollback.journal_sequence != journal_sequence
        || rollback.intent_journal_sequence != pending.journal_sequence
        || rollback.approval_id != pending.approval_id
        || rollback.approval_sequence != pending.approval_sequence
        || rollback.plan_id != pending.plan_id
        || rollback.plan_hash != pending.plan_hash
        || rollback.action_id != pending.action_id
        || rollback.resource_id != pending.resource_id
        || rollback.target_snapshot != pending.target_snapshot
        || rollback.replaced_sha256 != pending.installed_sha256
        || rollback.restored_sha256 != pending.restored_sha256
        || rollback.backup_locator != pending.backup_locator
        || rollback.backup_sha256 != pending.backup_sha256
        || completed.report.repair.approval_id != pending.repair_approval_id
        || completed.report.repair.plan_hash != pending.repair_plan_hash
        || completed.report.repair.journal_sequence != pending.repair_journal_sequence
    {
        return Err(ReplayFailure);
    }
    Ok(())
}

fn validate_report_payload(payload: &FixtureRepairReportPayload) -> Result<(), ReplayFailure> {
    validate_receipt_payload(&payload.repair)?;
    let rollback = &payload.rollback;
    let expected_intent_sequence = rollback
        .approval_sequence
        .checked_mul(2)
        .ok_or(ReplayFailure)?;
    let expected_completion_sequence = expected_intent_sequence
        .checked_add(1)
        .ok_or(ReplayFailure)?;
    if payload.api_version != REPORT_API_VERSION
        || payload.kind != REPORT_KIND
        || payload.final_state != "rolled-back"
        || payload.device_id != payload.repair.device_id
        || payload.journal_id != payload.repair.journal_id
        || payload.journal_sequence != rollback.journal_sequence
        || rollback.journal_sequence != expected_completion_sequence
        || rollback.intent_journal_sequence != expected_intent_sequence
        || rollback.approval_sequence
            != payload
                .repair
                .approval_sequence
                .checked_add(1)
                .ok_or(ReplayFailure)?
        || rollback.action_id != FIXTURE_ROLLBACK_ID
        || rollback.resource_id != FIXTURE_RESOURCE_ID
        || rollback.approval_decision != "approved"
        || rollback.risk != RISK
        || rollback.target_snapshot != payload.repair.after_target_precondition
        || rollback.replaced_sha256 != payload.repair.after_sha256
        || rollback.restored_sha256 != payload.repair.before_sha256
        || rollback.backup_locator != payload.repair.backup_locator
        || rollback.backup_sha256 != payload.repair.backup_sha256
        || rollback.validation != ROLLBACK_VALIDATION_DECLARATION
        || !rollback.validation_passed
        || !rollback.metadata_preserved
    {
        return Err(ReplayFailure);
    }
    kernaid_device_identity::validate_device_id(&payload.device_id).map_err(|_| ReplayFailure)?;
    if !valid_journal_id(&payload.journal_id) {
        return Err(ReplayFailure);
    }
    validate_approval_id(&rollback.approval_id)?;
    validate_plan_id(&rollback.plan_id)?;
    validate_sha256(&rollback.plan_hash)?;
    validate_sha256(&rollback.target_snapshot)?;
    validate_sha256(&rollback.replaced_sha256)?;
    validate_sha256(&rollback.restored_sha256)?;
    validate_sha256(&rollback.backup_sha256)?;
    let staged = StagedFixtureRollback {
        session_id: payload.repair.session_id.clone(),
        plan_id: rollback.plan_id.clone(),
        repair_approval_id: payload.repair.approval_id.clone(),
        repair_plan_hash: payload.repair.plan_hash.clone(),
        resource_id: FIXTURE_RESOURCE_ID,
        target_snapshot: rollback.target_snapshot.clone(),
        installed_sha256: rollback.replaced_sha256.clone(),
        restored_sha256: rollback.restored_sha256.clone(),
        backup_locator: rollback.backup_locator.clone(),
        backup_sha256: rollback.backup_sha256.clone(),
        plan_hash: String::new(),
    };
    if compute_rollback_plan_hash(&staged) != rollback.plan_hash {
        return Err(ReplayFailure);
    }
    Ok(())
}

fn validate_receipt_payload(payload: &FixtureRepairReceiptPayload) -> Result<(), ReplayFailure> {
    let expected_intent_sequence = payload
        .approval_sequence
        .checked_mul(2)
        .ok_or(ReplayFailure)?;
    let expected_completion_sequence = expected_intent_sequence
        .checked_add(1)
        .ok_or(ReplayFailure)?;
    if payload.api_version != RECEIPT_API_VERSION
        || payload.kind != RECEIPT_KIND
        || payload.action_id != FIXTURE_ACTION_ID
        || payload.resource_id != FIXTURE_RESOURCE_ID
        || payload.approval_decision != "approved"
        || payload.risk != RISK
        || payload.finding_id != FINDING_ID
        || payload.finding_version != FINDING_VERSION
        || payload.backup != BACKUP_RESULT
        || payload.validation != VALIDATION_DECLARATION
        || payload.rollback != ROLLBACK_DECLARATION
        || !payload.validation_passed
        || !payload.metadata_preserved
        || payload.approval_sequence == 0
        || payload.approval_sequence > MAX_APPROVALS as u64
        || payload.intent_journal_sequence != expected_intent_sequence
        || payload.journal_sequence != expected_completion_sequence
        || !valid_journal_id(&payload.journal_id)
        || payload.before_sha256 == payload.after_sha256
        || payload.backup_sha256 != payload.before_sha256
        || backup_locator_for(&payload.before_sha256).as_deref()
            != Ok(payload.backup_locator.as_str())
        || payload.before_mode & !0o7777 != 0
    {
        return Err(ReplayFailure);
    }
    kernaid_device_identity::validate_device_id(&payload.device_id).map_err(|_| ReplayFailure)?;
    validate_approval_id(&payload.approval_id)?;
    validate_session_id(&payload.session_id)?;
    validate_plan_id(&payload.plan_id)?;
    validate_sha256(&payload.plan_hash)?;
    validate_sha256(&payload.diagnosis_sha256)?;
    validate_sha256(&payload.target_snapshot)?;
    validate_sha256(&payload.before_sha256)?;
    validate_sha256(&payload.after_sha256)?;
    validate_sha256(&payload.after_target_precondition)?;
    validate_sha256(&payload.diff_sha256)?;
    validate_sha256(&payload.backup_sha256)?;
    if !canonical_evidence_binding_slice(&payload.evidence) {
        return Err(ReplayFailure);
    }
    let staged = StagedFixtureRepair {
        session_id: payload.session_id.clone(),
        plan_id: payload.plan_id.clone(),
        action_id: FIXTURE_ACTION_ID,
        resource_id: FIXTURE_RESOURCE_ID,
        diagnosis_sha256: payload.diagnosis_sha256.clone(),
        finding_id: FINDING_ID,
        finding_version: FINDING_VERSION,
        evidence: payload.evidence.clone(),
        target_snapshot: payload.target_snapshot.clone(),
        expected_before_sha256: payload.before_sha256.clone(),
        expected_after_sha256: payload.after_sha256.clone(),
        diff_sha256: payload.diff_sha256.clone(),
        backup_locator: payload.backup_locator.clone(),
        plan_hash: String::new(),
    };
    if compute_plan_hash(&staged) != payload.plan_hash {
        return Err(ReplayFailure);
    }
    Ok(())
}

fn pack_repair_receipt(
    config: &FixtureRepairConfig,
    payload: &FixtureRepairReceiptPayload,
) -> Result<RepairReceipt, ReplayFailure> {
    validate_receipt_payload(payload)?;
    let backup_path = backup_path_for(&config.backup_dir, &payload.before_sha256)?;
    if backup_locator_for(&payload.before_sha256)? != payload.backup_locator {
        return Err(ReplayFailure);
    }
    Ok(RepairReceipt {
        before_fingerprint: payload.before_sha256.clone(),
        after_fingerprint: payload.after_sha256.clone(),
        after_target_precondition: payload.after_target_precondition.clone(),
        backup_path,
        backup_fingerprint: payload.backup_sha256.clone(),
        before_metadata: PreservedMetadata {
            mode: payload.before_mode,
            uid: payload.before_uid,
            gid: payload.before_gid,
        },
        validation_passed: payload.validation_passed,
        metadata_preserved: payload.metadata_preserved,
    })
}

fn canonical_directory(path: &Path) -> Result<PathBuf, FixtureRepairError> {
    let metadata =
        fs::symlink_metadata(path).map_err(|_| FixtureRepairError::InvalidLocalConfig)?;
    if !metadata.is_dir() || metadata.file_type().is_symlink() {
        return Err(FixtureRepairError::InvalidLocalConfig);
    }
    fs::canonicalize(path).map_err(|_| FixtureRepairError::InvalidLocalConfig)
}

fn validate_typed_id(value: &str, prefix: &str) -> Result<(), ReplayFailure> {
    let suffix = value.strip_prefix(prefix).ok_or(ReplayFailure)?;
    if suffix.is_empty()
        || value.len() > MAX_ID_BYTES
        || !suffix
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
    {
        return Err(ReplayFailure);
    }
    Ok(())
}

fn validate_session_id(value: &str) -> Result<(), ReplayFailure> {
    validate_typed_id(value, "S-")
}

fn validate_plan_id(value: &str) -> Result<(), ReplayFailure> {
    validate_typed_id(value, "P-")
}

fn validate_evidence_id(value: &str) -> Result<(), ReplayFailure> {
    validate_typed_id(value, "E-")
}

fn validate_approval_id(value: &str) -> Result<(), ReplayFailure> {
    validate_typed_id(value, "A-")
}

fn validate_evidence_binding(binding: &FixtureEvidenceBinding) -> Result<(), ReplayFailure> {
    validate_evidence_id(&binding.id)?;
    validate_sha256(&binding.sha256)
}

fn canonical_evidence_bindings(
    values: &[FixtureEvidenceBinding],
) -> Result<Vec<FixtureEvidenceBinding>, ReplayFailure> {
    if values.is_empty() || values.len() > MAX_EVIDENCE_IDS {
        return Err(ReplayFailure);
    }
    for value in values {
        validate_evidence_binding(value)?;
    }
    let mut canonical = values.to_vec();
    canonical.sort_by(|left, right| left.id.cmp(&right.id));
    if canonical.windows(2).any(|pair| pair[0].id == pair[1].id) {
        return Err(ReplayFailure);
    }
    Ok(canonical)
}

fn canonical_evidence_binding_slice(values: &[FixtureEvidenceBinding]) -> bool {
    !values.is_empty()
        && values.len() <= MAX_EVIDENCE_IDS
        && values
            .iter()
            .all(|value| validate_evidence_binding(value).is_ok())
        && values.windows(2).all(|pair| pair[0].id < pair[1].id)
}

fn validate_sha256(value: &str) -> Result<(), ReplayFailure> {
    let Some(digest) = value.strip_prefix("sha256:") else {
        return Err(ReplayFailure);
    };
    if digest.len() != 64
        || !digest
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
    {
        return Err(ReplayFailure);
    }
    Ok(())
}

fn valid_journal_id(value: &str) -> bool {
    value.len() == 32
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
}

fn backup_name_for(before_sha256: &str) -> Result<String, ReplayFailure> {
    validate_sha256(before_sha256)?;
    let digest = before_sha256.strip_prefix("sha256:").ok_or(ReplayFailure)?;
    Ok(format!("fstab-{}.bak", &digest[..16]))
}

fn backup_locator_for(before_sha256: &str) -> Result<String, ReplayFailure> {
    Ok(format!(
        "{BACKUP_LOCATOR_PREFIX}{}",
        backup_name_for(before_sha256)?
    ))
}

fn backup_path_for(backup_dir: &Path, before_sha256: &str) -> Result<PathBuf, ReplayFailure> {
    Ok(backup_dir.join(backup_name_for(before_sha256)?))
}

fn diff_sha256(before: &[u8], after: &[u8]) -> String {
    let mut digest = Sha256::new();
    digest.update(DIFF_HASH_DOMAIN);
    hash_part(&mut digest, b"before");
    hash_part(&mut digest, before);
    hash_part(&mut digest, b"after");
    hash_part(&mut digest, after);
    format!("sha256:{:x}", digest.finalize())
}

fn compute_plan_hash(staged: &StagedFixtureRepair) -> String {
    let mut digest = Sha256::new();
    digest.update(PLAN_HASH_DOMAIN);
    hash_part(&mut digest, b"sessionId");
    hash_part(&mut digest, staged.session_id.as_bytes());
    hash_part(&mut digest, b"planId");
    hash_part(&mut digest, staged.plan_id.as_bytes());
    hash_part(&mut digest, b"actionId");
    hash_part(&mut digest, staged.action_id.as_bytes());
    hash_part(&mut digest, b"resourceId");
    hash_part(&mut digest, staged.resource_id.as_bytes());
    hash_part(&mut digest, b"diagnosisSha256");
    hash_part(&mut digest, staged.diagnosis_sha256.as_bytes());
    hash_part(&mut digest, b"findingId");
    hash_part(&mut digest, staged.finding_id.as_bytes());
    hash_part(&mut digest, b"findingVersion");
    digest.update(u64::from(staged.finding_version).to_be_bytes());
    hash_part(&mut digest, b"evidence");
    digest.update((staged.evidence.len() as u64).to_be_bytes());
    for binding in &staged.evidence {
        hash_part(&mut digest, binding.id.as_bytes());
        hash_part(&mut digest, binding.sha256.as_bytes());
    }
    hash_part(&mut digest, b"targetSnapshot");
    hash_part(&mut digest, staged.target_snapshot.as_bytes());
    hash_part(&mut digest, b"expectedBeforeSha256");
    hash_part(&mut digest, staged.expected_before_sha256.as_bytes());
    hash_part(&mut digest, b"expectedAfterSha256");
    hash_part(&mut digest, staged.expected_after_sha256.as_bytes());
    hash_part(&mut digest, b"diffSha256");
    hash_part(&mut digest, staged.diff_sha256.as_bytes());
    hash_part(&mut digest, b"backupLocator");
    hash_part(&mut digest, staged.backup_locator.as_bytes());
    hash_part(&mut digest, b"risk");
    hash_part(&mut digest, RISK.as_bytes());
    hash_part(&mut digest, b"backup");
    hash_part(&mut digest, BACKUP_DECLARATION.as_bytes());
    hash_part(&mut digest, b"validation");
    hash_part(&mut digest, VALIDATION_DECLARATION.as_bytes());
    hash_part(&mut digest, b"rollback");
    hash_part(&mut digest, ROLLBACK_DECLARATION.as_bytes());
    format!("sha256:{:x}", digest.finalize())
}

fn compute_rollback_plan_hash(staged: &StagedFixtureRollback) -> String {
    let mut digest = Sha256::new();
    digest.update(ROLLBACK_PLAN_HASH_DOMAIN);
    for (label, value) in [
        (b"sessionId".as_slice(), staged.session_id.as_bytes()),
        (b"planId".as_slice(), staged.plan_id.as_bytes()),
        (
            b"repairApprovalId".as_slice(),
            staged.repair_approval_id.as_bytes(),
        ),
        (
            b"repairPlanHash".as_slice(),
            staged.repair_plan_hash.as_bytes(),
        ),
        (b"actionId".as_slice(), FIXTURE_ROLLBACK_ID.as_bytes()),
        (b"resourceId".as_slice(), staged.resource_id.as_bytes()),
        (
            b"targetSnapshot".as_slice(),
            staged.target_snapshot.as_bytes(),
        ),
        (
            b"installedSha256".as_slice(),
            staged.installed_sha256.as_bytes(),
        ),
        (
            b"restoredSha256".as_slice(),
            staged.restored_sha256.as_bytes(),
        ),
        (
            b"backupLocator".as_slice(),
            staged.backup_locator.as_bytes(),
        ),
        (b"backupSha256".as_slice(), staged.backup_sha256.as_bytes()),
        (b"risk".as_slice(), RISK.as_bytes()),
        (
            b"validation".as_slice(),
            ROLLBACK_VALIDATION_DECLARATION.as_bytes(),
        ),
    ] {
        hash_part(&mut digest, label);
        hash_part(&mut digest, value);
    }
    format!("sha256:{:x}", digest.finalize())
}

fn hash_part(digest: &mut Sha256, value: &[u8]) {
    digest.update((value.len() as u64).to_be_bytes());
    digest.update(value);
}

fn sha256_bytes(value: &[u8]) -> String {
    format!("sha256:{:x}", Sha256::digest(value))
}

fn hex_bytes(value: &[u8]) -> String {
    value.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn strict_json<'de, Value>(input: &'de [u8]) -> Result<Value, serde_json::Error>
where
    Value: Deserialize<'de>,
{
    let mut deserializer = serde_json::Deserializer::from_slice(input);
    let value = Value::deserialize(&mut deserializer)?;
    deserializer.end()?;
    Ok(value)
}

fn encode_event(event: &JournalEvent) -> Result<Vec<u8>, FixtureRepairError> {
    let bytes = serde_json::to_vec(event).map_err(|_| FixtureRepairError::JournalUnavailable)?;
    if bytes.is_empty() || bytes.len() > MAX_BROKER_EVENT_BYTES {
        return Err(FixtureRepairError::CapacityExceeded);
    }
    Ok(bytes)
}

fn anchor_from_entry(journal_id: [u8; 16], entry: &JournalEntry) -> JournalAnchor {
    JournalAnchor {
        journal_id,
        sequence: entry.sequence,
        entry_hash: entry.entry_hash,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use kernaid_linux_pack::diagnostics::{
        DiagnosticReport, EvidenceInput, LinuxP0Inputs, diagnose_linux_p0,
    };
    use kernaid_storage::{JOURNAL_KEY_BYTES, JournalKey, SecretStoreError};
    use std::{
        collections::BTreeSet,
        env,
        os::unix::fs::{MetadataExt, PermissionsExt},
        process,
        sync::{
            Arc, Mutex,
            atomic::{AtomicU64, Ordering},
        },
    };
    use zeroize::Zeroizing;

    static NEXT: AtomicU64 = AtomicU64::new(1);
    const BROKEN_FSTAB: &[u8] = include_bytes!(
        "../../../packs/linux/fixtures/repair/fstab-missing-device-v1/root/etc/fstab"
    );
    const DISPOSABLE_MARKER: &[u8] = include_bytes!(
        "../../../packs/linux/fixtures/repair/fstab-missing-device-v1/root/.kernaid-disposable-fixture"
    );
    const HEALTHY_LSBLK: &[u8] =
        include_bytes!("../../../packs/linux/fixtures/diagnostics/healthy/lsblk.json");
    const HEALTHY_READ_ONLY_MOUNTS: &[u8] =
        include_bytes!("../../../packs/linux/fixtures/diagnostics/healthy/findmnt-read-only.json");
    const HEALTHY_FAILED: &[u8] =
        include_bytes!("../../../packs/linux/fixtures/diagnostics/healthy/systemctl-failed.txt");
    const HEALTHY_UNIT_STATE: &[u8] = include_bytes!(
        "../../../packs/linux/fixtures/diagnostics/healthy/systemctl-unit-state.txt"
    );
    const HEALTHY_DF: &[u8] =
        include_bytes!("../../../packs/linux/fixtures/diagnostics/healthy/df.txt");
    const HEALTHY_LINK: &[u8] =
        include_bytes!("../../../packs/linux/fixtures/diagnostics/healthy/ip-link.json");
    const HEALTHY_ROUTE: &[u8] =
        include_bytes!("../../../packs/linux/fixtures/diagnostics/healthy/ip-route.json");
    const HEALTHY_DPKG: &[u8] =
        include_bytes!("../../../packs/linux/fixtures/diagnostics/healthy/dpkg-audit.txt");

    #[derive(Default)]
    struct MemorySecretState {
        key: Option<[u8; JOURNAL_KEY_BYTES]>,
        anchor: Option<JournalAnchor>,
    }

    #[derive(Clone, Default)]
    struct MemorySecretStore {
        state: Arc<Mutex<MemorySecretState>>,
    }

    impl JournalSecretStore for MemorySecretStore {
        fn load_key(&mut self) -> Result<Option<JournalKey>, SecretStoreError> {
            let state = self
                .state
                .lock()
                .map_err(|_| SecretStoreError::new("memory store unavailable"))?;
            Ok(state
                .key
                .map(|key| JournalKey::from_zeroizing(Zeroizing::new(key))))
        }

        fn store_key(&mut self, key: &JournalKey) -> Result<(), SecretStoreError> {
            let mut state = self
                .state
                .lock()
                .map_err(|_| SecretStoreError::new("memory store unavailable"))?;
            state.key = Some(*key.expose_secret());
            Ok(())
        }

        fn load_anchor(&mut self) -> Result<Option<JournalAnchor>, SecretStoreError> {
            let state = self
                .state
                .lock()
                .map_err(|_| SecretStoreError::new("memory store unavailable"))?;
            Ok(state.anchor)
        }

        fn store_anchor(&mut self, anchor: &JournalAnchor) -> Result<(), SecretStoreError> {
            let mut state = self
                .state
                .lock()
                .map_err(|_| SecretStoreError::new("memory store unavailable"))?;
            state.anchor = Some(*anchor);
            Ok(())
        }
    }

    struct TestTree {
        root: PathBuf,
    }

    impl TestTree {
        fn new(name: &str) -> Self {
            let root = env::temp_dir().join(format!(
                "kernaid-broker-{name}-{}-{}",
                process::id(),
                NEXT.fetch_add(1, Ordering::Relaxed)
            ));
            fs::create_dir_all(root.join("target/etc")).expect("create target fixture");
            fs::create_dir_all(root.join("backup")).expect("create backup fixture");
            fs::write(
                root.join("target/.kernaid-disposable-fixture"),
                DISPOSABLE_MARKER,
            )
            .expect("write fixture marker");
            fs::write(root.join("target/etc/fstab"), BROKEN_FSTAB).expect("write fixture fstab");
            Self { root }
        }

        fn target(&self) -> PathBuf {
            self.root.join("target")
        }

        fn backup(&self) -> PathBuf {
            self.root.join("backup")
        }

        fn fstab(&self) -> PathBuf {
            self.target().join("etc/fstab")
        }

        fn journal(&self) -> PathBuf {
            self.root.join("fixture-repair.db")
        }

        fn config(&self) -> FixtureRepairConfig {
            FixtureRepairConfig::new(self.target(), self.backup()).expect("fixture config")
        }
    }

    impl Drop for TestTree {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.root);
        }
    }

    fn evidence_bindings() -> Vec<FixtureEvidenceBinding> {
        vec![
            FixtureEvidenceBinding::new("E-001", sha256_bytes(b"fstab evidence"))
                .expect("valid evidence binding"),
            FixtureEvidenceBinding::new("E-002", sha256_bytes(b"block evidence"))
                .expect("valid evidence binding"),
        ]
    }

    fn diagnostic_report(fstab: &[u8]) -> DiagnosticReport {
        let evidence = |id, body| EvidenceInput { id, body };
        diagnose_linux_p0(LinuxP0Inputs {
            lsblk_json: evidence("E-LINUX-LSBLK", HEALTHY_LSBLK),
            read_only_mounts_json: evidence("E-LINUX-MOUNTS-READ-ONLY", HEALTHY_READ_ONLY_MOUNTS),
            systemctl_failed: evidence("E-LINUX-SYSTEMD-FAILED", HEALTHY_FAILED),
            systemctl_unit_state: evidence("E-LINUX-SYSTEMD-STATE", HEALTHY_UNIT_STATE),
            fstab: evidence("E-LINUX-FSTAB", fstab),
            df: evidence("E-LINUX-DF", HEALTHY_DF),
            ip_link_json: evidence("E-LINUX-IP-LINK", HEALTHY_LINK),
            ip_route_json: evidence("E-LINUX-IP-ROUTE", HEALTHY_ROUTE),
            dpkg_audit: evidence("E-LINUX-DPKG", HEALTHY_DPKG),
        })
        .expect("diagnose coherent fixture")
    }

    fn contains_fixture_finding(report: &DiagnosticReport) -> bool {
        report
            .findings
            .iter()
            .any(|finding| finding.rule_id == FINDING_ID && finding.rule_version == 2)
    }

    fn diagnostic_bindings() -> Vec<FixtureEvidenceBinding> {
        vec![
            FixtureEvidenceBinding::new("E-LINUX-FSTAB", sha256_bytes(BROKEN_FSTAB))
                .expect("fstab evidence binding"),
            FixtureEvidenceBinding::new("E-LINUX-LSBLK", sha256_bytes(HEALTHY_LSBLK))
                .expect("lsblk evidence binding"),
        ]
    }

    fn assert_required_key_parity(value: &serde_json::Value, required: &serde_json::Value) {
        let actual = value
            .as_object()
            .expect("strict payload object")
            .keys()
            .map(String::as_str)
            .collect::<BTreeSet<_>>();
        let declared = required
            .as_array()
            .expect("schema required array")
            .iter()
            .map(|key| key.as_str().expect("schema key"))
            .collect::<BTreeSet<_>>();
        assert_eq!(actual, declared);
    }

    fn file_metadata(path: &Path) -> (u32, u32, u32) {
        let metadata = fs::metadata(path).expect("read fixture metadata");
        (metadata.mode() & 0o7777, metadata.uid(), metadata.gid())
    }

    fn assert_signed_report_value_rejected(
        identity: &DeviceIdentity,
        public_key: &[u8; 32],
        journal_sequence: u64,
        value: &serde_json::Value,
    ) {
        let bytes = serde_json::to_vec(value).expect("serialize invalid report value");
        let envelope = identity
            .sign_report_envelope(&bytes, REPORT_MEDIA_TYPE, journal_sequence, &[0x62; 32])
            .expect("sign invalid report value");
        assert_eq!(
            SignedFixtureRepairReport { envelope }.verify(public_key),
            Err(FixtureRepairError::InvalidReceipt)
        );
    }

    fn stage<'a, Store: JournalSecretStore>(
        broker: &FixtureRepairBroker<'a, Store>,
        _tree: &TestTree,
    ) -> StagedFixtureRepair {
        let evidence = evidence_bindings();
        broker
            .stage(StageFixtureRepairRequest {
                session_id: "S-fixture",
                plan_id: "P-fixture",
                action_id: FIXTURE_ACTION_ID,
                diagnosis_sha256: &sha256_bytes(b"diagnosis with KA-LNX-P0-003"),
                finding_id: FINDING_ID,
                finding_version: FINDING_VERSION,
                evidence: &evidence,
            })
            .expect("stage fixture repair")
    }

    fn approval<'a>(
        staged: &'a StagedFixtureRepair,
        approval_id: &'a str,
        approval_sequence: u64,
    ) -> FixtureRepairApproval<'a> {
        FixtureRepairApproval {
            approval_id,
            approval_sequence,
            session_id: staged.session_id(),
            plan_id: staged.plan_id(),
            plan_hash: staged.plan_hash(),
            target_snapshot: staged.target_snapshot(),
        }
    }

    fn rollback_approval<'a>(
        staged: &'a StagedFixtureRollback,
        approval_id: &'a str,
        approval_sequence: u64,
    ) -> FixtureRollbackApproval<'a> {
        FixtureRollbackApproval {
            approval_id,
            approval_sequence,
            session_id: staged.session_id(),
            plan_id: staged.plan_id(),
            plan_hash: staged.plan_hash(),
            target_snapshot: staged.target_snapshot(),
        }
    }

    fn decode_events(journal: &mut SecureJournal<MemorySecretStore>) -> Vec<JournalEvent> {
        journal
            .entries()
            .expect("read journal")
            .iter()
            .map(|entry| strict_json(&entry.event).expect("decode broker event"))
            .collect()
    }

    #[test]
    fn happy_path_orders_intent_before_real_pack_and_signs_completed_head() {
        let tree = TestTree::new("happy");
        let store = MemorySecretStore::default();
        let identity = DeviceIdentity::from_seed(&[0x41; 32]).expect("test identity");
        let public_key = identity.public_key();
        let mut journal = SecureJournal::open(&tree.journal(), store).expect("open journal");
        let mut broker = FixtureRepairBroker::attach(tree.config(), &mut journal, &identity)
            .expect("attach broker");
        let staged = stage(&broker, &tree);
        let receipt = broker
            .execute(&staged, approval(&staged, "A-001", 1))
            .expect("execute fixture repair");
        let verified = receipt.verify(&public_key).expect("verify signed receipt");
        assert_eq!(verified.before_sha256(), staged.expected_before_sha256());
        assert_eq!(verified.after_sha256(), staged.expected_after_sha256());
        assert_eq!(verified.backup_sha256(), staged.expected_before_sha256());
        assert_eq!(verified.plan_hash(), staged.plan_hash());
        assert!(verified.validation_passed());
        assert!(verified.metadata_preserved());
        assert_ne!(
            fs::read(tree.fstab()).expect("read repaired fstab"),
            BROKEN_FSTAB
        );

        drop(broker);
        let entries = journal.entries().expect("read completed journal");
        assert_eq!(entries.len(), 3);
        assert!(matches!(
            strict_json::<JournalEvent>(&entries[0].event),
            Ok(JournalEvent::DeviceBound(_))
        ));
        assert!(matches!(
            strict_json::<JournalEvent>(&entries[1].event),
            Ok(JournalEvent::Intent(_))
        ));
        let intent = match strict_json::<JournalEvent>(&entries[1].event).expect("intent event") {
            JournalEvent::Intent(intent) => Some(intent),
            _ => None,
        }
        .expect("second event must be intent");
        let completed =
            match strict_json::<JournalEvent>(&entries[2].event).expect("completed event") {
                JournalEvent::Completed(completed) => Some(completed),
                _ => None,
            }
            .expect("third event must be completion");
        let payload_bytes = serde_json::to_vec(&completed.receipt).expect("serialize payload");
        assert_eq!(
            completed.receipt_payload_sha256,
            sha256_bytes(&payload_bytes)
        );
        assert_eq!(receipt.envelope().journal_sequence, entries[2].sequence);
        assert_eq!(
            receipt.envelope().journal_entry_hash,
            base64_url(&entries[2].entry_hash)
        );
        assert!(
            validate_completed(
                &completed,
                &intent,
                "KA-000000000000000000000000",
                &completed.receipt.journal_id,
                entries[2].sequence,
            )
            .is_err(),
            "a syntactically valid but different device ID must fail replay"
        );
    }

    #[test]
    fn coherent_fixture_runs_diagnosis_repair_verify_rollback_and_signed_report() {
        let tree = TestTree::new("diagnosis-repair-rollback");
        fs::set_permissions(tree.fstab(), fs::Permissions::from_mode(0o640))
            .expect("set checked fixture mode");
        let expected_metadata = file_metadata(&tree.fstab());
        assert_eq!(expected_metadata.0, 0o640);
        let original = fs::read(tree.fstab()).expect("read checked fixture copy");
        assert_eq!(original, BROKEN_FSTAB);
        let diagnosis_before = diagnostic_report(&original);
        assert!(contains_fixture_finding(&diagnosis_before));
        let finding = diagnosis_before
            .findings
            .iter()
            .find(|finding| finding.rule_id == FINDING_ID)
            .expect("fixture finding");
        assert_eq!(finding.evidence_ids, vec!["E-LINUX-FSTAB", "E-LINUX-LSBLK"]);

        let diagnosis_sha256 = sha256_bytes(
            &serde_json::to_vec(&diagnosis_before).expect("serialize deterministic diagnosis"),
        );
        let evidence = diagnostic_bindings();
        let store = MemorySecretStore::default();
        let identity = DeviceIdentity::from_seed(&[0x61; 32]).expect("test identity");
        let public_key = identity.public_key();
        let mut journal =
            SecureJournal::open(&tree.journal(), store.clone()).expect("open journal");
        let final_envelope;
        {
            let mut broker = FixtureRepairBroker::attach(tree.config(), &mut journal, &identity)
                .expect("attach broker");
            let staged = broker
                .stage(StageFixtureRepairRequest {
                    session_id: "S-e2e",
                    plan_id: "P-repair",
                    action_id: FIXTURE_ACTION_ID,
                    diagnosis_sha256: &diagnosis_sha256,
                    finding_id: FINDING_ID,
                    finding_version: 2,
                    evidence: &evidence,
                })
                .expect("stage diagnosis-bound repair");
            assert_eq!(staged.diagnosis_sha256(), diagnosis_sha256);
            assert_eq!(staged.finding_id(), FINDING_ID);
            assert_eq!(staged.finding_version(), 2);
            assert_eq!(staged.evidence(), evidence);
            assert_eq!(staged.risk(), FixtureRepairRisk::R2);
            assert!(staged.backup_locator().starts_with(BACKUP_LOCATOR_PREFIX));
            assert_ne!(staged.diff_sha256(), staged.expected_before_sha256());

            let repair_receipt = broker
                .execute(&staged, approval(&staged, "A-repair", 1))
                .expect("execute approved repair");
            let verified_repair = repair_receipt
                .verify(&public_key)
                .expect("verify repair receipt");
            assert_eq!(verified_repair.diagnosis_sha256(), diagnosis_sha256);
            assert_eq!(verified_repair.evidence(), evidence);
            assert_eq!(verified_repair.diff_sha256(), staged.diff_sha256());
            assert_eq!(verified_repair.backup_locator(), staged.backup_locator());
            assert_eq!(
                (
                    verified_repair.before_mode,
                    verified_repair.before_uid,
                    verified_repair.before_gid,
                ),
                expected_metadata
            );

            let repaired = fs::read(tree.fstab()).expect("read repaired fixture");
            assert!(!contains_fixture_finding(&diagnostic_report(&repaired)));
            assert_eq!(file_metadata(&tree.fstab()), expected_metadata);

            let rollback = broker
                .stage_rollback(StageFixtureRollbackRequest {
                    session_id: "S-e2e",
                    plan_id: "P-rollback",
                    repair_approval_id: "A-repair",
                })
                .expect("stage journal-bound rollback");
            assert_eq!(rollback.action_id(), FIXTURE_ROLLBACK_ID);
            assert_eq!(rollback.risk(), FixtureRepairRisk::R2);
            assert_eq!(rollback.installed_sha256(), staged.expected_after_sha256());
            assert_eq!(rollback.restored_sha256(), staged.expected_before_sha256());
            assert_eq!(rollback.backup_locator(), staged.backup_locator());

            let report = broker
                .execute_rollback(&rollback, rollback_approval(&rollback, "A-rollback", 2))
                .expect("execute approved rollback");
            let verified = report.verify(&public_key).expect("verify final report");
            assert_eq!(verified.final_state(), "rolled-back");
            assert_eq!(verified.journal_sequence(), 5);
            assert_eq!(verified.repair().plan_hash(), staged.plan_hash());
            assert_eq!(verified.rollback_plan_hash(), rollback.plan_hash());
            assert_eq!(verified.rollback_approval_id(), "A-rollback");
            assert_eq!(verified.restored_sha256(), staged.expected_before_sha256());
            let report_value = serde_json::to_value(&verified).expect("serialize report value");
            let report_schema: serde_json::Value =
                serde_json::from_str(FIXTURE_REPAIR_REPORT_SCHEMA_JSON)
                    .expect("parse report schema");
            assert_required_key_parity(&report_value, &report_schema["required"]);
            assert_required_key_parity(
                &report_value["repair"],
                &report_schema["$defs"]["repair"]["required"],
            );
            assert_required_key_parity(
                &report_value["rollback"],
                &report_schema["$defs"]["rollback"]["required"],
            );
            let mut impossible = report_value.clone();
            impossible
                .as_object_mut()
                .expect("report object")
                .insert("unknownField".to_owned(), serde_json::Value::Bool(true));
            assert_signed_report_value_rejected(
                &identity,
                &public_key,
                verified.journal_sequence(),
                &impossible,
            );

            for field in ["validation", "rollback"] {
                let mut wrong_declaration = report_value.clone();
                wrong_declaration["repair"][field] =
                    serde_json::Value::String("not-the-pinned-declaration".to_owned());
                assert_signed_report_value_rejected(
                    &identity,
                    &public_key,
                    verified.journal_sequence(),
                    &wrong_declaration,
                );
            }
            for field in ["beforeUid", "beforeGid"] {
                let mut out_of_range_identity = report_value.clone();
                out_of_range_identity["repair"][field] =
                    serde_json::Value::from(u64::from(u32::MAX) + 1);
                assert_signed_report_value_rejected(
                    &identity,
                    &public_key,
                    verified.journal_sequence(),
                    &out_of_range_identity,
                );
            }
            let mut duplicate_binding = report_value.clone();
            let duplicate = duplicate_binding["repair"]["evidence"][0].clone();
            duplicate_binding["repair"]["evidence"]
                .as_array_mut()
                .expect("evidence array")
                .insert(1, duplicate);
            assert_signed_report_value_rejected(
                &identity,
                &public_key,
                verified.journal_sequence(),
                &duplicate_binding,
            );

            let mut duplicate_semantic_id = report_value.clone();
            let mut same_id_different_hash = duplicate_semantic_id["repair"]["evidence"][0].clone();
            same_id_different_hash["sha256"] = serde_json::Value::String(sha256_bytes(
                b"different bytes under the same semantic evidence id",
            ));
            duplicate_semantic_id["repair"]["evidence"]
                .as_array_mut()
                .expect("evidence array")
                .insert(1, same_id_different_hash);
            assert_signed_report_value_rejected(
                &identity,
                &public_key,
                verified.journal_sequence(),
                &duplicate_semantic_id,
            );
            final_envelope = report.envelope().clone();
        }

        let restored = fs::read(tree.fstab()).expect("read restored fixture");
        assert_eq!(
            restored, original,
            "rollback must restore exact fixture bytes"
        );
        assert_eq!(file_metadata(&tree.fstab()), expected_metadata);
        assert!(contains_fixture_finding(&diagnostic_report(&restored)));
        let events = decode_events(&mut journal);
        assert!(matches!(
            events.as_slice(),
            [
                JournalEvent::DeviceBound(_),
                JournalEvent::Intent(_),
                JournalEvent::Completed(_),
                JournalEvent::RollbackIntent(_),
                JournalEvent::RolledBack(_),
            ]
        ));
        drop(journal);

        let mut reopened = SecureJournal::open(&tree.journal(), store).expect("reopen journal");
        let mut broker = FixtureRepairBroker::attach(tree.config(), &mut reopened, &identity)
            .expect("replay complete cycle");
        assert_eq!(broker.next_approval_sequence(), Ok(3));
        let reissued = broker
            .reissue_completed_report("A-repair")
            .expect("reissue final report");
        assert_eq!(reissued.envelope(), &final_envelope);
        reissued
            .verify(&public_key)
            .expect("verify replayed report");
    }

    #[test]
    fn rollback_tamper_and_invalid_approval_fail_before_intent() {
        let tree = TestTree::new("rollback-pre-intent-rejections");
        let store = MemorySecretStore::default();
        let identity = DeviceIdentity::from_seed(&[0x63; 32]).expect("test identity");
        let mut journal = SecureJournal::open(&tree.journal(), store).expect("open journal");
        let mut broker = FixtureRepairBroker::attach(tree.config(), &mut journal, &identity)
            .expect("attach broker");
        let repair_plan = stage(&broker, &tree);
        broker
            .execute(&repair_plan, approval(&repair_plan, "A-repair", 1))
            .expect("execute repair");
        let rollback = broker
            .stage_rollback(StageFixtureRollbackRequest {
                session_id: "S-fixture",
                plan_id: "P-rollback",
                repair_approval_id: "A-repair",
            })
            .expect("stage rollback");
        let completed_head = broker.head;

        assert_eq!(
            broker.execute_rollback(
                &rollback,
                rollback_approval(&rollback, "A-wrong-sequence", 3),
            ),
            Err(FixtureRepairError::NonMonotonicApproval)
        );
        let wrong_hash = FixtureRollbackApproval {
            plan_hash: "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            ..rollback_approval(&rollback, "A-wrong-hash", 2)
        };
        assert_eq!(
            broker.execute_rollback(&rollback, wrong_hash),
            Err(FixtureRepairError::ApprovalMismatch)
        );
        assert_eq!(broker.head, completed_head);

        let external = b"# external edit after repair\nUUID=other / ext4 defaults 0 1\n";
        fs::write(tree.fstab(), external).expect("make rollback target stale");
        assert_eq!(
            broker.execute_rollback(
                &rollback,
                rollback_approval(&rollback, "A-stale-rollback", 2),
            ),
            Err(FixtureRepairError::StaleTarget)
        );
        assert_eq!(broker.head, completed_head);
        assert_eq!(
            fs::read(tree.fstab()).expect("read external state"),
            external
        );
    }

    #[test]
    fn tampered_backup_blocks_rollback_staging_without_journal_write() {
        let tree = TestTree::new("rollback-backup-tamper");
        let store = MemorySecretStore::default();
        let identity = DeviceIdentity::from_seed(&[0x64; 32]).expect("test identity");
        let mut journal = SecureJournal::open(&tree.journal(), store).expect("open journal");
        let mut broker = FixtureRepairBroker::attach(tree.config(), &mut journal, &identity)
            .expect("attach broker");
        let repair_plan = stage(&broker, &tree);
        broker
            .execute(&repair_plan, approval(&repair_plan, "A-repair", 1))
            .expect("execute repair");
        let completed_head = broker.head;
        let repaired = fs::read(tree.fstab()).expect("read repaired target");
        let backup_path = backup_path_for(&tree.backup(), repair_plan.expected_before_sha256())
            .expect("derive trusted backup path");
        fs::write(backup_path, b"tampered backup").expect("tamper backup fixture");
        assert_eq!(
            broker.stage_rollback(StageFixtureRollbackRequest {
                session_id: "S-fixture",
                plan_id: "P-rollback",
                repair_approval_id: "A-repair",
            }),
            Err(FixtureRepairError::StaleTarget)
        );
        assert_eq!(broker.head, completed_head);
        assert_eq!(
            fs::read(tree.fstab()).expect("read unchanged repair"),
            repaired
        );
    }

    #[test]
    fn dangling_rollback_intent_gets_durable_recovery_and_blocks_reopen() {
        let tree = TestTree::new("dangling-rollback");
        let store = MemorySecretStore::default();
        let identity = DeviceIdentity::from_seed(&[0x65; 32]).expect("test identity");
        let mut journal =
            SecureJournal::open(&tree.journal(), store.clone()).expect("open journal");
        let repaired;
        {
            let mut broker = FixtureRepairBroker::attach(tree.config(), &mut journal, &identity)
                .expect("attach broker");
            let repair_plan = stage(&broker, &tree);
            broker
                .execute(&repair_plan, approval(&repair_plan, "A-repair", 1))
                .expect("execute repair");
            let rollback = broker
                .stage_rollback(StageFixtureRollbackRequest {
                    session_id: "S-fixture",
                    plan_id: "P-rollback",
                    repair_approval_id: "A-repair",
                })
                .expect("stage rollback");
            let repair_payload = broker
                .completed_receipts
                .get("A-repair")
                .expect("completed repair")
                .payload
                .clone();
            broker
                .append_rollback_intent(
                    &rollback,
                    &rollback_approval(&rollback, "A-rollback", 2),
                    &repair_payload,
                )
                .expect("append rollback intent without mutation");
            repaired = fs::read(tree.fstab()).expect("read repaired target");
        }
        drop(journal);

        let mut reopened =
            SecureJournal::open(&tree.journal(), store.clone()).expect("reopen journal");
        let broker = FixtureRepairBroker::attach(tree.config(), &mut reopened, &identity)
            .expect("attach records rollback recovery");
        assert!(broker.is_mutation_blocked());
        assert_eq!(fs::read(tree.fstab()).expect("read target"), repaired);
        drop(broker);
        let events = decode_events(&mut reopened);
        assert!(matches!(
            events.as_slice(),
            [
                JournalEvent::DeviceBound(_),
                JournalEvent::Intent(_),
                JournalEvent::Completed(_),
                JournalEvent::RollbackIntent(_),
                JournalEvent::Recovery(_),
            ]
        ));
        drop(reopened);

        let mut again =
            SecureJournal::open(&tree.journal(), store).expect("reopen blocked journal");
        let broker = FixtureRepairBroker::attach(tree.config(), &mut again, &identity)
            .expect("reattach blocked broker");
        assert!(broker.is_mutation_blocked());
    }

    #[test]
    fn signed_receipt_rejects_broker_impossible_approval_sequence() {
        let tree = TestTree::new("impossible-receipt-sequence");
        let store = MemorySecretStore::default();
        let identity = DeviceIdentity::from_seed(&[0x51; 32]).expect("test identity");
        let public_key = identity.public_key();
        let mut journal = SecureJournal::open(&tree.journal(), store).expect("open journal");
        let mut broker = FixtureRepairBroker::attach(tree.config(), &mut journal, &identity)
            .expect("attach broker");
        let staged = stage(&broker, &tree);
        let receipt = broker
            .execute(&staged, approval(&staged, "A-impossible", 1))
            .expect("execute fixture repair");
        let valid_payload = receipt.verify(&public_key).expect("verify valid receipt");

        for approval_sequence in [0, 2, MAX_APPROVALS as u64 + 1] {
            let mut impossible_payload = valid_payload.clone();
            impossible_payload.approval_sequence = approval_sequence;
            let payload_bytes =
                serde_json::to_vec(&impossible_payload).expect("serialize impossible payload");
            let envelope = identity
                .sign_report_envelope(
                    &payload_bytes,
                    RECEIPT_MEDIA_TYPE,
                    impossible_payload.journal_sequence,
                    &[0x52; 32],
                )
                .expect("sign impossible payload");
            let impossible_receipt = SignedFixtureRepairReceipt { envelope };
            assert_eq!(
                impossible_receipt.verify(&public_key),
                Err(FixtureRepairError::InvalidReceipt),
                "approval sequence {approval_sequence} must not describe a broker receipt"
            );
        }
    }

    #[test]
    fn malformed_stage_and_invalid_approvals_write_nothing() {
        let tree = TestTree::new("reject-before-intent");
        let store = MemorySecretStore::default();
        let identity = DeviceIdentity::from_seed(&[0x42; 32]).expect("test identity");
        let mut journal = SecureJournal::open(&tree.journal(), store).expect("open journal");
        let mut broker = FixtureRepairBroker::attach(tree.config(), &mut journal, &identity)
            .expect("attach broker");
        let binding_head = broker.head;
        let before = fs::read(tree.fstab()).expect("read fixture before");
        let evidence = evidence_bindings();
        assert_eq!(
            broker.stage(StageFixtureRepairRequest {
                session_id: "S-fixture",
                plan_id: "P-fixture",
                action_id: FIXTURE_ACTION_ID,
                diagnosis_sha256: "not-a-digest",
                finding_id: FINDING_ID,
                finding_version: FINDING_VERSION,
                evidence: &evidence,
            }),
            Err(FixtureRepairError::InvalidStage)
        );
        let diagnosis = sha256_bytes(b"diagnosis with KA-LNX-P0-003");
        let wrong_evidence = vec![FixtureEvidenceBinding {
            id: "A-cross-domain".to_owned(),
            sha256: sha256_bytes(b"wrong evidence"),
        }];
        for (session_id, plan_id, evidence) in [
            ("A-cross-domain", "P-fixture", evidence.as_slice()),
            ("S-fixture", "E-cross-domain", evidence.as_slice()),
            ("S-fixture", "P-fixture", wrong_evidence.as_slice()),
        ] {
            assert_eq!(
                broker.stage(StageFixtureRepairRequest {
                    session_id,
                    plan_id,
                    action_id: FIXTURE_ACTION_ID,
                    diagnosis_sha256: &diagnosis,
                    finding_id: FINDING_ID,
                    finding_version: FINDING_VERSION,
                    evidence,
                }),
                Err(FixtureRepairError::InvalidStage)
            );
        }
        let oversized_evidence = vec![FixtureEvidenceBinding {
            id: format!("E-{}", "a".repeat(MAX_ID_BYTES)),
            sha256: sha256_bytes(b"oversized evidence id"),
        }];
        assert_eq!(
            broker.stage(StageFixtureRepairRequest {
                session_id: "S-fixture",
                plan_id: "P-fixture",
                action_id: FIXTURE_ACTION_ID,
                diagnosis_sha256: &diagnosis,
                finding_id: FINDING_ID,
                finding_version: FINDING_VERSION,
                evidence: &oversized_evidence,
            }),
            Err(FixtureRepairError::InvalidStage)
        );
        let staged = stage(&broker, &tree);

        let wrong_sequence = approval(&staged, "A-wrong-sequence", 2);
        assert_eq!(
            broker.execute(&staged, wrong_sequence),
            Err(FixtureRepairError::NonMonotonicApproval)
        );
        let wrong_hash = FixtureRepairApproval {
            plan_hash: "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            ..approval(&staged, "A-wrong-hash", 1)
        };
        assert_eq!(
            broker.execute(&staged, wrong_hash),
            Err(FixtureRepairError::ApprovalMismatch)
        );
        let malformed = FixtureRepairApproval {
            approval_id: " contains-space",
            ..approval(&staged, "unused", 1)
        };
        assert_eq!(
            broker.execute(&staged, malformed),
            Err(FixtureRepairError::InvalidApproval)
        );
        assert_eq!(
            broker.execute(&staged, approval(&staged, "P-cross-domain", 1)),
            Err(FixtureRepairError::InvalidApproval)
        );
        assert_eq!(broker.head, binding_head);
        assert_eq!(
            fs::read(tree.fstab()).expect("read unchanged fixture"),
            before
        );
    }

    #[test]
    fn plan_hash_binds_diagnosis_evidence_diff_and_backup_locator() {
        let tree = TestTree::new("plan-bindings");
        let store = MemorySecretStore::default();
        let identity = DeviceIdentity::from_seed(&[0x66; 32]).expect("test identity");
        let mut journal = SecureJournal::open(&tree.journal(), store).expect("open journal");
        let broker = FixtureRepairBroker::attach(tree.config(), &mut journal, &identity)
            .expect("attach broker");
        let staged = stage(&broker, &tree);

        let mut diagnosis_tamper = staged.clone();
        diagnosis_tamper.diagnosis_sha256 = sha256_bytes(b"different diagnosis");
        assert_ne!(compute_plan_hash(&diagnosis_tamper), staged.plan_hash());

        let mut evidence_tamper = staged.clone();
        evidence_tamper.evidence[0].sha256 = sha256_bytes(b"different evidence");
        assert_ne!(compute_plan_hash(&evidence_tamper), staged.plan_hash());

        let mut diff_tamper = staged.clone();
        diff_tamper.diff_sha256 = sha256_bytes(b"different diff");
        assert_ne!(compute_plan_hash(&diff_tamper), staged.plan_hash());

        let mut locator_tamper = staged.clone();
        locator_tamper.backup_locator =
            "fixture-lab-backup://linux-fstab/fstab-aaaaaaaaaaaaaaaa.bak".to_owned();
        assert_ne!(compute_plan_hash(&locator_tamper), staged.plan_hash());
    }

    #[test]
    fn checked_report_schema_is_closed_and_matches_pinned_contract() {
        let schema: serde_json::Value = serde_json::from_str(FIXTURE_REPAIR_REPORT_SCHEMA_JSON)
            .expect("parse checked report schema");
        assert_eq!(schema["additionalProperties"], false);
        assert_eq!(
            schema["properties"]["apiVersion"]["const"],
            REPORT_API_VERSION
        );
        assert_eq!(schema["properties"]["kind"]["const"], REPORT_KIND);
        assert_eq!(schema["$defs"]["repair"]["additionalProperties"], false);
        let repair_properties = &schema["$defs"]["repair"]["properties"];
        assert_eq!(repair_properties["findingId"]["const"], FINDING_ID);
        assert_eq!(
            repair_properties["findingVersion"]["const"],
            FINDING_VERSION
        );
        assert_eq!(
            repair_properties["validation"]["const"],
            VALIDATION_DECLARATION
        );
        assert_eq!(repair_properties["rollback"]["const"], ROLLBACK_DECLARATION);
        assert_eq!(repair_properties["beforeUid"]["maximum"], u32::MAX);
        assert_eq!(repair_properties["beforeGid"]["maximum"], u32::MAX);
        assert_eq!(repair_properties["evidence"]["uniqueItems"], true);
        assert!(
            repair_properties["evidence"]["description"]
                .as_str()
                .is_some_and(|description| description.contains("semantically unique"))
        );
        assert_eq!(schema["$defs"]["rollback"]["additionalProperties"], false);
        assert_eq!(
            schema["$defs"]["rollback"]["properties"]["actionId"]["const"],
            FIXTURE_ROLLBACK_ID
        );
    }

    #[test]
    fn stale_target_fails_before_intent_and_preserves_external_state() {
        let tree = TestTree::new("stale");
        let store = MemorySecretStore::default();
        let identity = DeviceIdentity::from_seed(&[0x43; 32]).expect("test identity");
        let mut journal = SecureJournal::open(&tree.journal(), store).expect("open journal");
        let mut broker = FixtureRepairBroker::attach(tree.config(), &mut journal, &identity)
            .expect("attach broker");
        let staged = stage(&broker, &tree);
        let binding_head = broker.head;
        let external = b"# externally changed\nUUID=other / ext4 defaults 0 1\n";
        fs::write(tree.fstab(), external).expect("make staged target stale");
        assert_eq!(
            broker.execute(&staged, approval(&staged, "A-stale", 1)),
            Err(FixtureRepairError::StaleTarget)
        );
        assert_eq!(broker.head, binding_head);
        assert_eq!(
            fs::read(tree.fstab()).expect("read external state"),
            external
        );
    }

    #[test]
    fn restart_replays_completion_sequence_and_used_approval_ids() {
        let tree = TestTree::new("restart");
        let store = MemorySecretStore::default();
        let identity = DeviceIdentity::from_seed(&[0x44; 32]).expect("test identity");
        let mut journal =
            SecureJournal::open(&tree.journal(), store.clone()).expect("open journal");
        let original_envelope;
        {
            let mut broker = FixtureRepairBroker::attach(tree.config(), &mut journal, &identity)
                .expect("attach broker");
            let staged = stage(&broker, &tree);
            let receipt = broker
                .execute(&staged, approval(&staged, "A-restart", 1))
                .expect("execute repair");
            original_envelope = receipt.envelope().clone();
        }
        drop(journal);

        let mut reopened = SecureJournal::open(&tree.journal(), store).expect("reopen journal");
        let mut broker = FixtureRepairBroker::attach(tree.config(), &mut reopened, &identity)
            .expect("reattach broker");
        assert_eq!(broker.next_approval_sequence(), Ok(2));
        let reissued = broker
            .reissue_completed_receipt("A-restart")
            .expect("reissue receipt from authenticated completion");
        assert_eq!(reissued.envelope(), &original_envelope);
        reissued
            .verify(&identity.public_key())
            .expect("verify reissued receipt");
        let staged = StagedFixtureRepair {
            session_id: "S-next".to_owned(),
            plan_id: "P-next".to_owned(),
            action_id: FIXTURE_ACTION_ID,
            resource_id: FIXTURE_RESOURCE_ID,
            diagnosis_sha256:
                "sha256:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd".to_owned(),
            finding_id: FINDING_ID,
            finding_version: FINDING_VERSION,
            evidence: vec![FixtureEvidenceBinding {
                id: "E-003".to_owned(),
                sha256: "sha256:eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee"
                    .to_owned(),
            }],
            target_snapshot:
                "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".to_owned(),
            expected_before_sha256:
                "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb".to_owned(),
            expected_after_sha256:
                "sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc".to_owned(),
            diff_sha256: "sha256:ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
                .to_owned(),
            backup_locator: "fixture-lab-backup://linux-fstab/fstab-bbbbbbbbbbbbbbbb.bak"
                .to_owned(),
            plan_hash: String::new(),
        };
        let mut staged = staged;
        staged.plan_hash = compute_plan_hash(&staged);
        let head = broker.head;
        assert_eq!(
            broker.execute(&staged, approval(&staged, "A-restart", 2)),
            Err(FixtureRepairError::ApprovalReused)
        );
        assert_eq!(broker.head, head);
    }

    #[test]
    fn dangling_intent_gets_durable_recovery_and_blocks_reopen() {
        let tree = TestTree::new("dangling");
        let store = MemorySecretStore::default();
        let identity = DeviceIdentity::from_seed(&[0x45; 32]).expect("test identity");
        let mut journal =
            SecureJournal::open(&tree.journal(), store.clone()).expect("open journal");
        {
            let mut broker = FixtureRepairBroker::attach(tree.config(), &mut journal, &identity)
                .expect("attach broker");
            let staged = stage(&broker, &tree);
            let pending = broker
                .append_intent(&staged, &approval(&staged, "A-dangling", 1))
                .expect("append intent without mutation");
            assert_eq!(pending.approval_id, "A-dangling");
        }
        drop(journal);
        assert_eq!(
            fs::read(tree.fstab()).expect("read untouched fixture"),
            BROKEN_FSTAB
        );

        let mut reopened =
            SecureJournal::open(&tree.journal(), store.clone()).expect("reopen journal");
        let broker = FixtureRepairBroker::attach(tree.config(), &mut reopened, &identity)
            .expect("attach performs recovery");
        assert!(broker.is_mutation_blocked());
        drop(broker);
        let events = decode_events(&mut reopened);
        assert_eq!(events.len(), 3);
        assert!(matches!(events[1], JournalEvent::Intent(_)));
        assert!(matches!(events[2], JournalEvent::Recovery(_)));
        drop(reopened);

        let mut again =
            SecureJournal::open(&tree.journal(), store).expect("reopen recovered journal");
        let broker = FixtureRepairBroker::attach(tree.config(), &mut again, &identity)
            .expect("reattach blocked broker");
        assert!(broker.is_mutation_blocked());
    }

    #[test]
    fn pack_execute_failure_records_recovery_and_blocks_later_mutation() {
        let tree = TestTree::new("execute-failure");
        let store = MemorySecretStore::default();
        let identity = DeviceIdentity::from_seed(&[0x46; 32]).expect("test identity");
        let mut journal = SecureJournal::open(&tree.journal(), store).expect("open journal");
        let mut broker = FixtureRepairBroker::attach(tree.config(), &mut journal, &identity)
            .expect("attach broker");
        let staged = stage(&broker, &tree);
        let digest = staged
            .expected_before_sha256()
            .strip_prefix("sha256:")
            .expect("hash prefix");
        fs::write(
            tree.backup().join(format!("fstab-{}.bak", &digest[..16])),
            b"preexisting collision",
        )
        .expect("create backup collision");
        assert_eq!(
            broker.execute(&staged, approval(&staged, "A-failure", 1)),
            Err(FixtureRepairError::ExecutionOutcomeUnknown)
        );
        assert!(broker.is_mutation_blocked());
        assert_eq!(
            fs::read(tree.fstab()).expect("read unchanged fixture"),
            BROKEN_FSTAB
        );
        assert_eq!(
            broker.execute(&staged, approval(&staged, "A-later", 2)),
            Err(FixtureRepairError::MutationBlocked)
        );
        drop(broker);
        let events = decode_events(&mut journal);
        assert!(matches!(
            events.as_slice(),
            [
                JournalEvent::DeviceBound(_),
                JournalEvent::Intent(_),
                JournalEvent::Recovery(_)
            ]
        ));
    }

    #[test]
    fn dedicated_journal_is_device_bound_and_rejects_non_broker_events() {
        let tree = TestTree::new("device-binding");
        let store = MemorySecretStore::default();
        let identity = DeviceIdentity::from_seed(&[0x47; 32]).expect("test identity");
        let mut journal =
            SecureJournal::open(&tree.journal(), store.clone()).expect("open journal");
        drop(
            FixtureRepairBroker::attach(tree.config(), &mut journal, &identity)
                .expect("attach broker"),
        );
        drop(journal);

        let other = DeviceIdentity::from_seed(&[0x48; 32]).expect("other identity");
        let mut reopened = SecureJournal::open(&tree.journal(), store).expect("reopen journal");
        assert_eq!(
            FixtureRepairBroker::attach(tree.config(), &mut reopened, &other).map(|_| ()),
            Err(FixtureRepairError::InvalidJournal)
        );

        let foreign = TestTree::new("foreign-journal");
        let foreign_store = MemorySecretStore::default();
        let mut foreign_journal =
            SecureJournal::open(&foreign.journal(), foreign_store).expect("open foreign journal");
        foreign_journal
            .append(br#"{"kind":"unrelated.event.v1","event":{}} trailing"#)
            .expect("append authenticated foreign event");
        assert_eq!(
            FixtureRepairBroker::attach(foreign.config(), &mut foreign_journal, &identity)
                .map(|_| ()),
            Err(FixtureRepairError::InvalidJournal)
        );
    }

    #[test]
    fn strict_event_parser_rejects_unknown_duplicate_and_trailing_fields() {
        let identity = DeviceIdentity::from_seed(&[0x49; 32]).expect("test identity");
        for (name, event) in [
            (
                "unknown",
                br#"{"kind":"fixture.repair.device-bound.v1","event":{"deviceId":"KA-000000000000000000000000","publicKeySha256":"sha256:0000000000000000000000000000000000000000000000000000000000000000","journalId":"00000000000000000000000000000000","extra":true}}"#.as_slice(),
            ),
            (
                "duplicate",
                br#"{"kind":"fixture.repair.device-bound.v1","kind":"fixture.repair.device-bound.v1","event":{}}"#.as_slice(),
            ),
            ("trailing", br#"{} {}"#.as_slice()),
        ] {
            let tree = TestTree::new(name);
            let store = MemorySecretStore::default();
            let mut journal = SecureJournal::open(&tree.journal(), store).expect("open journal");
            journal.append(event).expect("append malformed authenticated event");
            assert_eq!(
                FixtureRepairBroker::attach(tree.config(), &mut journal, &identity).map(|_| ()),
                Err(FixtureRepairError::InvalidJournal),
                "{name} event must fail closed"
            );
        }
    }

    #[test]
    fn public_debug_errors_and_serialized_receipt_never_expose_local_paths_or_content() {
        const CALLER_CANARY: &str = "/private/caller-secret/raw-command";
        let tree = TestTree::new("redaction");
        let target_text = tree.target().to_string_lossy().into_owned();
        let backup_text = tree.backup().to_string_lossy().into_owned();
        let store = MemorySecretStore::default();
        let identity = DeviceIdentity::from_seed(&[0x4a; 32]).expect("test identity");
        let public_key = identity.public_key();
        let mut journal = SecureJournal::open(&tree.journal(), store).expect("open journal");
        let mut broker = FixtureRepairBroker::attach(tree.config(), &mut journal, &identity)
            .expect("attach broker");
        let staged = stage(&broker, &tree);
        let receipt = broker
            .execute(&staged, approval(&staged, "A-redaction", 1))
            .expect("execute repair");
        let serialized = serde_json::to_string(&receipt).expect("serialize receipt");
        let debug = format!("{broker:?} {staged:?} {receipt:?}");
        let error = format!(
            "{:?} {}",
            FixtureRepairError::ExecutionOutcomeUnknown,
            FixtureRepairError::ExecutionOutcomeUnknown
        );
        let untrusted_evidence = vec![FixtureEvidenceBinding {
            id: CALLER_CANARY.to_owned(),
            sha256: CALLER_CANARY.to_owned(),
        }];
        let caller_debug = format!(
            "{:?} {:?}",
            StageFixtureRepairRequest {
                session_id: CALLER_CANARY,
                plan_id: CALLER_CANARY,
                action_id: CALLER_CANARY,
                diagnosis_sha256: CALLER_CANARY,
                finding_id: CALLER_CANARY,
                finding_version: 1,
                evidence: &untrusted_evidence,
            },
            FixtureRepairApproval {
                approval_id: CALLER_CANARY,
                approval_sequence: 1,
                session_id: CALLER_CANARY,
                plan_id: CALLER_CANARY,
                plan_hash: CALLER_CANARY,
                target_snapshot: CALLER_CANARY,
            }
        );
        for output in [&serialized, &debug, &error, &caller_debug] {
            assert!(!output.contains(&target_text));
            assert!(!output.contains(&backup_text));
            assert!(!output.contains("UUID=missing-data"));
            assert!(!output.contains("backupPath"));
            assert!(!output.contains(CALLER_CANARY));
        }
        let payload = receipt.verify(&public_key).expect("verify receipt");
        let payload_value = serde_json::to_value(payload).expect("serialize payload value");
        let object = payload_value.as_object().expect("receipt object");
        for forbidden in ["path", "raw", "replacement", "command", "backupPath"] {
            assert!(!object.contains_key(forbidden));
        }
    }

    #[test]
    fn local_config_rejects_either_target_backup_ancestor_relationship() {
        let tree = TestTree::new("config-boundary");
        fs::create_dir_all(tree.target().join("inside-backup"))
            .expect("create nested backup directory");
        assert!(matches!(
            FixtureRepairConfig::new(tree.target(), tree.target().join("inside-backup")),
            Err(FixtureRepairError::InvalidLocalConfig)
        ));
        assert!(matches!(
            FixtureRepairConfig::new(tree.target(), &tree.root),
            Err(FixtureRepairError::InvalidLocalConfig)
        ));
    }

    fn base64_url(bytes: &[u8]) -> String {
        const TABLE: &[u8; 64] =
            b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
        let mut output = String::new();
        for chunk in bytes.chunks(3) {
            let first = u32::from(chunk[0]);
            let second = u32::from(*chunk.get(1).unwrap_or(&0));
            let third = u32::from(*chunk.get(2).unwrap_or(&0));
            let bits = (first << 16) | (second << 8) | third;
            output.push(TABLE[((bits >> 18) & 0x3f) as usize] as char);
            output.push(TABLE[((bits >> 12) & 0x3f) as usize] as char);
            if chunk.len() > 1 {
                output.push(TABLE[((bits >> 6) & 0x3f) as usize] as char);
            }
            if chunk.len() > 2 {
                output.push(TABLE[(bits & 0x3f) as usize] as char);
            }
        }
        output
    }
}
