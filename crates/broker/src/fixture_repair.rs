//! Dormant fixture-lab repair broker.
//!
//! This module is Linux-only and deliberately has no IPC, Core, desktop, or
//! production-target integration. It can dispatch exactly one compile-time
//! pinned action against an explicitly marked disposable fixture. Paths are
//! accepted only through [`FixtureRepairConfig`], which is local-only and is
//! neither serializable nor exposed by receipts or errors.

use kernaid_device_identity::{DeviceIdentity, SignedReportEnvelope};
use kernaid_linux_pack::{
    action_contract::{FIXTURE_ACTION_ID, FIXTURE_RESOURCE_ID, parse_fixture_fstab_repair_input},
    execute_missing_fstab_device_repair, preview_missing_fstab_device,
};
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

const RECEIPT_API_VERSION: &str = "kernaid.dev/fixture-repair-receipt/v1";
const RECEIPT_KIND: &str = "FixtureRepairReceipt";
const RECEIPT_MEDIA_TYPE: &str = "application/vnd.kernaid.fixture-repair-receipt+json";
const PLAN_HASH_DOMAIN: &[u8] = b"KERNAID-FIXTURE-REPAIR-PLAN-V1\0";
pub const DEVICE_BINDING_EVENT_KIND: &str = "fixture.repair.device-bound.v1";
pub const INTENT_EVENT_KIND: &str = "fixture.repair.intent.v1";
pub const COMPLETED_EVENT_KIND: &str = "fixture.repair.completed.v1";
pub const RECOVERY_EVENT_KIND: &str = "fixture.repair.recovery.v1";
const RECOVERY_DISPOSITION: &str = "manual-inspection-required";
const RISK: &str = "R2";
const BACKUP_DECLARATION: &str = "required-separate-byte-verified-copy";
const BACKUP_RESULT: &str = "created-and-byte-verified";
const VALIDATION_DECLARATION: &str =
    "fstab is syntactically parsed and the unique missing UUID entry is disabled";
const ROLLBACK_DECLARATION: &str =
    "atomically restore the byte-verified backup and original mode/uid/gid";
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

/// Unserialized request used to stage the single fixture action.
pub struct StageFixtureRepairRequest<'request> {
    pub session_id: &'request str,
    pub plan_id: &'request str,
    pub action_id: &'request str,
    pub contract_input: &'request [u8],
    pub evidence_ids: &'request [String],
}

impl fmt::Debug for StageFixtureRepairRequest<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("StageFixtureRepairRequest")
            .field("session_id_bytes", &self.session_id.len())
            .field("plan_id_bytes", &self.plan_id.len())
            .field("action_id_bytes", &self.action_id.len())
            .field("contract_input_bytes", &self.contract_input.len())
            .field("evidence_id_count", &self.evidence_ids.len())
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
    evidence_ids: Vec<String>,
    target_snapshot: String,
    expected_before_sha256: String,
    expected_after_sha256: String,
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

    pub fn evidence_ids(&self) -> &[String] {
        &self.evidence_ids
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
    session_id: String,
    plan_id: String,
    plan_hash: String,
    action_id: String,
    resource_id: String,
    evidence_ids: Vec<String>,
    target_snapshot: String,
    before_sha256: String,
    after_sha256: String,
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

    pub fn before_sha256(&self) -> &str {
        &self.before_sha256
    }

    pub fn after_sha256(&self) -> &str {
        &self.after_sha256
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
            last_approval_sequence: replay.last_approval_sequence,
            mutation_blocked: replay.mutation_blocked,
        };

        if let Some(pending) = replay.pending.take() {
            broker.mutation_blocked = true;
            broker
                .append_recovery(&pending)
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
        let evidence_ids = canonical_evidence_ids(request.evidence_ids)
            .map_err(|_| FixtureRepairError::InvalidStage)?;
        let parsed = parse_fixture_fstab_repair_input(request.action_id, request.contract_input)
            .map_err(|_| FixtureRepairError::InvalidStage)?;
        let preview = preview_missing_fstab_device(&self.config.fixture_root, &evidence_ids)
            .map_err(|_| FixtureRepairError::FixtureRejected)?;
        let actual_before = preview.target_content_fingerprint;
        let actual_after = sha256_bytes(preview.after.as_bytes());
        if parsed.expected_before_sha256().as_str() != actual_before
            || parsed.expected_after_sha256().as_str() != actual_after
            || parsed.resource_id() != FIXTURE_RESOURCE_ID
            || !preview.backup_required
            || preview.validation != VALIDATION_DECLARATION
            || preview.rollback != ROLLBACK_DECLARATION
        {
            return Err(FixtureRepairError::ContractMismatch);
        }
        validate_sha256(&preview.target_fingerprint)
            .map_err(|_| FixtureRepairError::FixtureRejected)?;

        let mut staged = StagedFixtureRepair {
            session_id: request.session_id.to_owned(),
            plan_id: request.plan_id.to_owned(),
            action_id: FIXTURE_ACTION_ID,
            resource_id: FIXTURE_RESOURCE_ID,
            evidence_ids,
            target_snapshot: preview.target_fingerprint,
            expected_before_sha256: actual_before,
            expected_after_sha256: actual_after,
            plan_hash: String::new(),
        };
        staged.plan_hash = compute_plan_hash(&staged);
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
        let repair = match execute_missing_fstab_device_repair(
            &self.config.fixture_root,
            &self.config.backup_dir,
            &staged.target_snapshot,
            &staged.evidence_ids,
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
            session_id: pending.session_id.clone(),
            plan_id: pending.plan_id.clone(),
            plan_hash: pending.plan_hash.clone(),
            action_id: pending.action_id.clone(),
            resource_id: pending.resource_id.clone(),
            evidence_ids: pending.evidence_ids.clone(),
            target_snapshot: pending.target_snapshot.clone(),
            before_sha256: repair.before_fingerprint,
            after_sha256: repair.after_fingerprint,
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
        let preview = preview_missing_fstab_device(&self.config.fixture_root, &staged.evidence_ids)
            .map_err(|_| FixtureRepairError::StaleTarget)?;
        if preview.target_fingerprint != staged.target_snapshot
            || preview.target_content_fingerprint != staged.expected_before_sha256
            || sha256_bytes(preview.after.as_bytes()) != staged.expected_after_sha256
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
            evidence_ids: staged.evidence_ids.clone(),
            target_snapshot: staged.target_snapshot.clone(),
            expected_before_sha256: staged.expected_before_sha256.clone(),
            expected_after_sha256: staged.expected_after_sha256.clone(),
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
        let recovery = JournalEvent::Recovery(RecoveryEvent {
            approval_id: pending.approval_id.clone(),
            approval_sequence: pending.approval_sequence,
            session_id: pending.session_id.clone(),
            plan_id: pending.plan_id.clone(),
            plan_hash: pending.plan_hash.clone(),
            intent_journal_sequence: pending.journal_sequence,
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
    evidence_ids: Vec<String>,
    target_snapshot: String,
    expected_before_sha256: String,
    expected_after_sha256: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct CompletedEvent {
    receipt: FixtureRepairReceiptPayload,
    receipt_payload_sha256: String,
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

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", content = "event", deny_unknown_fields)]
enum JournalEvent {
    #[serde(rename = "fixture.repair.device-bound.v1")]
    DeviceBound(DeviceBoundEvent),
    #[serde(rename = "fixture.repair.intent.v1")]
    Intent(IntentEvent),
    #[serde(rename = "fixture.repair.completed.v1")]
    Completed(Box<CompletedEvent>),
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
    last_approval_sequence: u64,
    pending: Option<IntentEvent>,
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
                self.pending = Some(intent);
            }
            JournalEvent::Completed(completed) => {
                let pending = self.pending.as_ref().ok_or(ReplayFailure)?;
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
            JournalEvent::Recovery(recovery) => {
                let pending = self.pending.as_ref().ok_or(ReplayFailure)?;
                if recovery.approval_id != pending.approval_id
                    || recovery.approval_sequence != pending.approval_sequence
                    || recovery.session_id != pending.session_id
                    || recovery.plan_id != pending.plan_id
                    || recovery.plan_hash != pending.plan_hash
                    || recovery.intent_journal_sequence != pending.journal_sequence
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
    validate_sha256(&intent.target_snapshot)?;
    validate_sha256(&intent.expected_before_sha256)?;
    validate_sha256(&intent.expected_after_sha256)?;
    if intent.expected_before_sha256 == intent.expected_after_sha256
        || intent.action_id != FIXTURE_ACTION_ID
        || intent.resource_id != FIXTURE_RESOURCE_ID
        || !canonical_evidence_slice(&intent.evidence_ids)
    {
        return Err(ReplayFailure);
    }
    let staged = StagedFixtureRepair {
        session_id: intent.session_id.clone(),
        plan_id: intent.plan_id.clone(),
        action_id: FIXTURE_ACTION_ID,
        resource_id: FIXTURE_RESOURCE_ID,
        evidence_ids: intent.evidence_ids.clone(),
        target_snapshot: intent.target_snapshot.clone(),
        expected_before_sha256: intent.expected_before_sha256.clone(),
        expected_after_sha256: intent.expected_after_sha256.clone(),
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
        || payload.evidence_ids != pending.evidence_ids
        || payload.target_snapshot != pending.target_snapshot
        || payload.before_sha256 != pending.expected_before_sha256
        || payload.after_sha256 != pending.expected_after_sha256
        || payload.backup_sha256 != pending.expected_before_sha256
    {
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
        || payload.before_mode & !0o7777 != 0
    {
        return Err(ReplayFailure);
    }
    kernaid_device_identity::validate_device_id(&payload.device_id).map_err(|_| ReplayFailure)?;
    validate_approval_id(&payload.approval_id)?;
    validate_session_id(&payload.session_id)?;
    validate_plan_id(&payload.plan_id)?;
    validate_sha256(&payload.plan_hash)?;
    validate_sha256(&payload.target_snapshot)?;
    validate_sha256(&payload.before_sha256)?;
    validate_sha256(&payload.after_sha256)?;
    validate_sha256(&payload.backup_sha256)?;
    if !canonical_evidence_slice(&payload.evidence_ids) {
        return Err(ReplayFailure);
    }
    let staged = StagedFixtureRepair {
        session_id: payload.session_id.clone(),
        plan_id: payload.plan_id.clone(),
        action_id: FIXTURE_ACTION_ID,
        resource_id: FIXTURE_RESOURCE_ID,
        evidence_ids: payload.evidence_ids.clone(),
        target_snapshot: payload.target_snapshot.clone(),
        expected_before_sha256: payload.before_sha256.clone(),
        expected_after_sha256: payload.after_sha256.clone(),
        plan_hash: String::new(),
    };
    if compute_plan_hash(&staged) != payload.plan_hash {
        return Err(ReplayFailure);
    }
    Ok(())
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

fn canonical_evidence_ids(values: &[String]) -> Result<Vec<String>, ReplayFailure> {
    if values.is_empty() || values.len() > MAX_EVIDENCE_IDS {
        return Err(ReplayFailure);
    }
    for value in values {
        validate_evidence_id(value)?;
    }
    let mut canonical = values.to_vec();
    canonical.sort();
    if canonical.windows(2).any(|pair| pair[0] == pair[1]) {
        return Err(ReplayFailure);
    }
    Ok(canonical)
}

fn canonical_evidence_slice(values: &[String]) -> bool {
    !values.is_empty()
        && values.len() <= MAX_EVIDENCE_IDS
        && values
            .iter()
            .all(|value| validate_evidence_id(value).is_ok())
        && values.windows(2).all(|pair| pair[0] < pair[1])
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
    hash_part(&mut digest, b"evidenceIds");
    digest.update((staged.evidence_ids.len() as u64).to_be_bytes());
    for evidence_id in &staged.evidence_ids {
        hash_part(&mut digest, evidence_id.as_bytes());
    }
    hash_part(&mut digest, b"targetSnapshot");
    hash_part(&mut digest, staged.target_snapshot.as_bytes());
    hash_part(&mut digest, b"expectedBeforeSha256");
    hash_part(&mut digest, staged.expected_before_sha256.as_bytes());
    hash_part(&mut digest, b"expectedAfterSha256");
    hash_part(&mut digest, staged.expected_after_sha256.as_bytes());
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
    use kernaid_storage::{JOURNAL_KEY_BYTES, JournalKey, SecretStoreError};
    use serde_json::json;
    use std::{
        env, process,
        sync::{
            Arc, Mutex,
            atomic::{AtomicU64, Ordering},
        },
    };
    use zeroize::Zeroizing;

    static NEXT: AtomicU64 = AtomicU64::new(1);
    const BROKEN_FSTAB: &[u8] = b"# test\nUUID=missing-data /mnt/data ext4 defaults 0 2\n";

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
                b"KERNAID_DISPOSABLE_FIXTURE_V1\n",
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

    fn action_input(tree: &TestTree, evidence: &[String]) -> Vec<u8> {
        let preview = preview_missing_fstab_device(&tree.target(), evidence)
            .expect("preview fixture for action input");
        serde_json::to_vec(&json!({
            "resourceId": FIXTURE_RESOURCE_ID,
            "expectedBeforeSha256": preview.target_content_fingerprint,
            "expectedAfterSha256": sha256_bytes(preview.after.as_bytes()),
        }))
        .expect("serialize action input")
    }

    fn stage<'a, Store: JournalSecretStore>(
        broker: &FixtureRepairBroker<'a, Store>,
        tree: &TestTree,
    ) -> StagedFixtureRepair {
        let evidence = vec!["E-001".to_owned(), "E-002".to_owned()];
        let input = action_input(tree, &evidence);
        broker
            .stage(StageFixtureRepairRequest {
                session_id: "S-fixture",
                plan_id: "P-fixture",
                action_id: FIXTURE_ACTION_ID,
                contract_input: &input,
                evidence_ids: &evidence,
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
        let evidence = vec!["E-001".to_owned()];
        assert_eq!(
            broker.stage(StageFixtureRepairRequest {
                session_id: "S-fixture",
                plan_id: "P-fixture",
                action_id: FIXTURE_ACTION_ID,
                contract_input: br#"{"resourceId":"fixture:linux-fstab-v1","command":"id"}"#,
                evidence_ids: &evidence,
            }),
            Err(FixtureRepairError::InvalidStage)
        );
        let valid_input = action_input(&tree, &evidence);
        let wrong_evidence = vec!["A-cross-domain".to_owned()];
        for (session_id, plan_id, evidence_ids) in [
            ("A-cross-domain", "P-fixture", evidence.as_slice()),
            ("S-fixture", "E-cross-domain", evidence.as_slice()),
            ("S-fixture", "P-fixture", wrong_evidence.as_slice()),
        ] {
            assert_eq!(
                broker.stage(StageFixtureRepairRequest {
                    session_id,
                    plan_id,
                    action_id: FIXTURE_ACTION_ID,
                    contract_input: &valid_input,
                    evidence_ids,
                }),
                Err(FixtureRepairError::InvalidStage)
            );
        }
        let oversized_evidence = vec![format!("E-{}", "a".repeat(MAX_ID_BYTES))];
        assert_eq!(
            broker.stage(StageFixtureRepairRequest {
                session_id: "S-fixture",
                plan_id: "P-fixture",
                action_id: FIXTURE_ACTION_ID,
                contract_input: &valid_input,
                evidence_ids: &oversized_evidence,
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
            evidence_ids: vec!["E-003".to_owned()],
            target_snapshot:
                "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".to_owned(),
            expected_before_sha256:
                "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb".to_owned(),
            expected_after_sha256:
                "sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc".to_owned(),
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
        let untrusted_evidence = vec![CALLER_CANARY.to_owned()];
        let caller_debug = format!(
            "{:?} {:?}",
            StageFixtureRepairRequest {
                session_id: CALLER_CANARY,
                plan_id: CALLER_CANARY,
                action_id: CALLER_CANARY,
                contract_input: CALLER_CANARY.as_bytes(),
                evidence_ids: &untrusted_evidence,
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
