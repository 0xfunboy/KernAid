//! Closed parent/worker transport for the privileged vault lifecycle.
//!
//! The wire is fixed-size binary data. It contains no pathname, secret,
//! command string, diagnostic text, or JSON. The sole permitted descriptor is
//! one anonymous pipe on commands with an exact input or output body. Frames
//! carry only closed enums, numeric bounds, UUID bytes and SHA-256 bytes; JSON,
//! paths, report bodies and credentials travel only through those pipes. With
//! the separate experimental Codex-home feature, one successful response may
//! instead carry the already validated `O_PATH` home-directory descriptor.

#[cfg(feature = "experimental-repair-store")]
use kernaid_protocol::rescue_repair_vault::{
    MAX_REPAIR_BACKUP_BYTES, RepairBackupBinding, RepairBackupDraft, RepairBackupState,
    RepairBackupStatusPayload, RepairExecutionIntentV1, RepairFileMetadataV1, RepairReservationId,
    RepairTransactionPhase, RepairTransactionResolution, RepairTransactionResolutionOutcome,
    RepairTransactionStatusPayload, RepairTransactionStatusSelector, RepairTransactionTargetState,
    RepairVaultLiveIdentityPayload,
};
use kernaid_protocol::rescue_vault::{
    AuditEventType, AuditOutcome, ErrorToken, MAX_AUDIT_SEQUENCE, MAX_OPENAI_KEY_BYTES,
    MAX_PASSPHRASE_BYTES, MAX_REPORTS_PER_RESPONSE, MAX_SESSION_REPORT_JSON_BYTES,
    MAX_SIGNED_REPORT_ENVELOPE_BYTES, MIN_PASSPHRASE_BYTES, ReportId, ReportSummary, RequestId,
    Sha256,
};
use rustix::{
    event::{PollFd, PollFlags, Timespec, poll},
    net::{
        AddressFamily, RecvAncillaryBuffer, RecvAncillaryMessage, RecvFlags, ReturnFlags,
        SendAncillaryBuffer, SendAncillaryMessage, SendFlags, SocketType, recvmsg, sendmsg,
    },
};
use std::{
    fmt,
    io::{IoSlice, IoSliceMut},
    mem::MaybeUninit,
    os::fd::{BorrowedFd, OwnedFd},
    time::{Duration, Instant},
};

#[cfg(feature = "experimental-codex-home-lease")]
use std::os::fd::AsFd;

#[cfg(feature = "experimental-repair-store")]
const COMMAND_MAGIC: &[u8; 8] = b"KRVWC006";
#[cfg(not(feature = "experimental-repair-store"))]
const COMMAND_MAGIC: &[u8; 8] = b"KRVWC003";
#[cfg(feature = "experimental-repair-store")]
const RESPONSE_MAGIC: &[u8; 8] = b"KRVWR006";
#[cfg(not(feature = "experimental-repair-store"))]
const RESPONSE_MAGIC: &[u8; 8] = b"KRVWR003";
// Repair capabilities intentionally remain one canonical fixed-size binary
// record. 2048 bytes covers the closed set of bounded (<=128 byte) opaque IDs
// and hashes without introducing JSON, paths, or a second framing language.
#[cfg(feature = "experimental-repair-store")]
const COMMAND_BYTES: usize = 2048;
#[cfg(not(feature = "experimental-repair-store"))]
const COMMAND_BYTES: usize = 128;
#[cfg(feature = "experimental-repair-store")]
const RESPONSE_BYTES: usize = 2048;
#[cfg(not(feature = "experimental-repair-store"))]
const RESPONSE_BYTES: usize = 128;
const MAX_RECORD_BYTES: usize = if COMMAND_BYTES > RESPONSE_BYTES {
    COMMAND_BYTES
} else {
    RESPONSE_BYTES
};
const COMMAND_VALUE_OFFSET: usize = 20;
const COMMAND_PEER_UID_OFFSET: usize = 28;
const COMMAND_PEER_PID_OFFSET: usize = 32;
const COMMAND_IDENTIFIER_OFFSET: usize = 36;
const COMMAND_SHA256_OFFSET: usize = 52;
const RESPONSE_VALUE_OFFSET: usize = 20;
const RESPONSE_COUNT_OFFSET: usize = 28;
const RESPONSE_IDENTIFIER_OFFSET: usize = 32;
const RESPONSE_SHA256_OFFSET: usize = 48;
const DEVICE_ID_OFFSET: usize = 80;
const MAX_DEVICE_ID_BYTES: usize = 32;
pub(super) const APPLICATION_REPORT_RECORD_BYTES: usize = 64;
pub(super) const MAX_APPLICATION_REPORT_LIST_BYTES: usize =
    MAX_REPORTS_PER_RESPONSE * APPLICATION_REPORT_RECORD_BYTES;
#[cfg(feature = "experimental-repair-store")]
const REPAIR_PAYLOAD_OFFSET: usize = 20;
#[cfg(feature = "experimental-repair-store")]
const MAX_REPAIR_ID_BYTES: usize = 128;

#[cfg(feature = "experimental-repair-store")]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum WorkerRepairState {
    Reserved,
    Durable,
}

#[cfg(feature = "experimental-repair-store")]
#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct WorkerRepairDraft {
    pub(super) session_id: String,
    pub(super) target_id: String,
    pub(super) target_fingerprint: [u8; 32],
    pub(super) target_recovery_fingerprint: String,
    pub(super) expected_backup_sha256: [u8; 32],
    pub(super) metadata_sha256: [u8; 32],
    pub(super) backup_size: u64,
    pub(super) required_capacity_bytes: u64,
}

#[cfg(feature = "experimental-repair-store")]
impl WorkerRepairDraft {
    pub(super) fn from_protocol(value: &RepairBackupDraft) -> Self {
        Self {
            session_id: value.session_id().to_owned(),
            target_id: value.target_id().to_owned(),
            target_fingerprint: value.target_fingerprint().bytes(),
            target_recovery_fingerprint: value.target_recovery_fingerprint().to_owned(),
            expected_backup_sha256: value.expected_backup_sha256().bytes(),
            metadata_sha256: value.metadata_sha256().bytes(),
            backup_size: value.backup_size(),
            required_capacity_bytes: value.required_capacity_bytes(),
        }
    }

    fn validate(&self) -> Result<(), InternalWireError> {
        RepairBackupDraft::new(
            self.session_id.clone(),
            self.target_id.clone(),
            protocol_sha256(self.target_fingerprint)?,
            self.target_recovery_fingerprint.clone(),
            protocol_sha256(self.expected_backup_sha256)?,
            protocol_sha256(self.metadata_sha256)?,
            self.backup_size,
            self.required_capacity_bytes,
        )
        .map(|_| ())
        .map_err(|_| InternalWireError::InvalidFrame)
    }
}

#[cfg(feature = "experimental-repair-store")]
#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct WorkerRepairVaultLiveIdentity {
    pub(super) vault_id: String,
    pub(super) vault_identity_fingerprint: [u8; 32],
    pub(super) physical_parent_fingerprint: [u8; 32],
}

#[cfg(feature = "experimental-repair-store")]
impl WorkerRepairVaultLiveIdentity {
    pub(super) fn to_protocol(&self) -> Result<RepairVaultLiveIdentityPayload, InternalWireError> {
        RepairVaultLiveIdentityPayload::new(
            self.vault_id.clone(),
            protocol_sha256(self.vault_identity_fingerprint)?,
            protocol_sha256(self.physical_parent_fingerprint)?,
        )
        .map_err(|_| InternalWireError::InvalidFrame)
    }

    fn validate(&self) -> Result<(), InternalWireError> {
        self.to_protocol().map(|_| ())
    }
}

#[cfg(feature = "experimental-repair-store")]
#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct WorkerRepairBinding {
    pub(super) plan_id: String,
    pub(super) plan_sha256: [u8; 32],
    pub(super) approval_id: String,
    pub(super) approval_sha256: [u8; 32],
    pub(super) resource_id: String,
    pub(super) resource_sha256: [u8; 32],
    pub(super) execution_intent: RepairExecutionIntentV1,
}

#[cfg(feature = "experimental-repair-store")]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct WorkerRepairFileMetadata {
    pub(super) mode: u32,
    pub(super) uid: u32,
    pub(super) gid: u32,
}

#[cfg(feature = "experimental-repair-store")]
impl WorkerRepairFileMetadata {
    pub(super) fn from_protocol(value: &RepairFileMetadataV1) -> Self {
        Self {
            mode: value.mode(),
            uid: value.uid(),
            gid: value.gid(),
        }
    }

    pub(super) fn to_protocol(self) -> Result<RepairFileMetadataV1, InternalWireError> {
        RepairFileMetadataV1::new(self.mode, self.uid, self.gid)
            .map_err(|_| InternalWireError::InvalidFrame)
    }

    pub(super) fn is_supported_root_file(self) -> bool {
        self.mode == 0o644 && self.uid == 0 && self.gid == 0
    }
}

#[cfg(feature = "experimental-repair-store")]
impl WorkerRepairBinding {
    pub(super) fn from_protocol(value: &RepairBackupBinding) -> Self {
        Self {
            plan_id: value.plan_id().to_owned(),
            plan_sha256: value.plan_sha256().bytes(),
            approval_id: value.approval_id().to_owned(),
            approval_sha256: value.approval_sha256().bytes(),
            resource_id: value.resource_id().to_owned(),
            resource_sha256: value.resource_sha256().bytes(),
            execution_intent: value.execution_intent().clone(),
        }
    }

    fn to_protocol(&self) -> Result<RepairBackupBinding, InternalWireError> {
        RepairBackupBinding::new(
            self.plan_id.clone(),
            protocol_sha256(self.plan_sha256)?,
            self.approval_id.clone(),
            protocol_sha256(self.approval_sha256)?,
            self.resource_id.clone(),
            protocol_sha256(self.resource_sha256)?,
            self.execution_intent.clone(),
        )
        .map_err(|_| InternalWireError::InvalidFrame)
    }
}

#[cfg(feature = "experimental-repair-store")]
#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct WorkerRepairStatus {
    pub(super) state: WorkerRepairState,
    pub(super) reservation_id: String,
    pub(super) draft_binding_sha256: [u8; 32],
    pub(super) locator: String,
    pub(super) vault_id: String,
    pub(super) vault_identity_fingerprint: [u8; 32],
    pub(super) physical_parent_fingerprint: [u8; 32],
    pub(super) reserved_bytes: u64,
    pub(super) backup_size: u64,
    pub(super) expected_backup_sha256: [u8; 32],
    pub(super) metadata_sha256: [u8; 32],
    pub(super) binding: Option<WorkerRepairBinding>,
}

#[cfg(feature = "experimental-repair-store")]
impl WorkerRepairStatus {
    pub(super) fn from_protocol(
        value: &RepairBackupStatusPayload,
    ) -> Result<Self, InternalWireError> {
        let binding = match value.state() {
            RepairBackupState::Reserved => None,
            RepairBackupState::Durable => Some(WorkerRepairBinding {
                plan_id: value
                    .plan_id()
                    .ok_or(InternalWireError::InvalidFrame)?
                    .to_owned(),
                plan_sha256: value
                    .plan_sha256()
                    .ok_or(InternalWireError::InvalidFrame)?
                    .bytes(),
                approval_id: value
                    .approval_id()
                    .ok_or(InternalWireError::InvalidFrame)?
                    .to_owned(),
                approval_sha256: value
                    .approval_sha256()
                    .ok_or(InternalWireError::InvalidFrame)?
                    .bytes(),
                resource_id: value
                    .resource_id()
                    .ok_or(InternalWireError::InvalidFrame)?
                    .to_owned(),
                resource_sha256: value
                    .resource_sha256()
                    .ok_or(InternalWireError::InvalidFrame)?
                    .bytes(),
                execution_intent: value
                    .execution_intent()
                    .ok_or(InternalWireError::InvalidFrame)?
                    .clone(),
            }),
        };
        let status = Self {
            state: match value.state() {
                RepairBackupState::Reserved => WorkerRepairState::Reserved,
                RepairBackupState::Durable => WorkerRepairState::Durable,
            },
            reservation_id: value.reservation_id().as_str().to_owned(),
            draft_binding_sha256: value.draft_binding_sha256().bytes(),
            locator: value.locator().to_owned(),
            vault_id: value.vault_id().to_owned(),
            vault_identity_fingerprint: value.vault_identity_fingerprint().bytes(),
            physical_parent_fingerprint: value.physical_parent_fingerprint().bytes(),
            reserved_bytes: value.reserved_bytes(),
            backup_size: value.backup_size(),
            expected_backup_sha256: value.expected_backup_sha256().bytes(),
            metadata_sha256: value.metadata_sha256().bytes(),
            binding,
        };
        status.validate()?;
        Ok(status)
    }

    pub(super) fn to_protocol(&self) -> Result<RepairBackupStatusPayload, InternalWireError> {
        let reservation_id = RepairReservationId::parse(&self.reservation_id)
            .map_err(|_| InternalWireError::InvalidFrame)?;
        let common = (
            reservation_id,
            protocol_sha256(self.draft_binding_sha256)?,
            self.locator.clone(),
            self.vault_id.clone(),
            protocol_sha256(self.vault_identity_fingerprint)?,
            protocol_sha256(self.physical_parent_fingerprint)?,
            self.reserved_bytes,
            self.backup_size,
            protocol_sha256(self.expected_backup_sha256)?,
            protocol_sha256(self.metadata_sha256)?,
        );
        match (self.state, self.binding.as_ref()) {
            (WorkerRepairState::Reserved, None) => RepairBackupStatusPayload::reserved(
                common.0, common.1, common.2, common.3, common.4, common.5, common.6, common.7,
                common.8, common.9,
            ),
            (WorkerRepairState::Durable, Some(binding)) => RepairBackupStatusPayload::durable(
                common.0,
                common.1,
                common.2,
                common.3,
                common.4,
                common.5,
                common.6,
                common.7,
                common.8,
                common.9,
                binding.to_protocol()?,
            ),
            _ => return Err(InternalWireError::InvalidFrame),
        }
        .map_err(|_| InternalWireError::InvalidFrame)
    }

    fn validate(&self) -> Result<(), InternalWireError> {
        self.to_protocol().map(|_| ())
    }

    pub(super) fn immutable_fields_match(&self, other: &Self) -> bool {
        self.reservation_id == other.reservation_id
            && self.draft_binding_sha256 == other.draft_binding_sha256
            && self.locator == other.locator
            && self.vault_id == other.vault_id
            && self.vault_identity_fingerprint == other.vault_identity_fingerprint
            && self.physical_parent_fingerprint == other.physical_parent_fingerprint
            && self.reserved_bytes == other.reserved_bytes
            && self.backup_size == other.backup_size
            && self.expected_backup_sha256 == other.expected_backup_sha256
            && self.metadata_sha256 == other.metadata_sha256
    }
}

#[cfg(feature = "experimental-repair-store")]
#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) enum WorkerRepairCommand {
    Reserve {
        draft: WorkerRepairDraft,
    },
    Persist {
        expected: Box<WorkerRepairStatus>,
        binding: Box<WorkerRepairBinding>,
        metadata: WorkerRepairFileMetadata,
        input_size: u64,
    },
    Status {
        expected: Box<WorkerRepairStatus>,
    },
    Get {
        expected: Box<WorkerRepairStatus>,
    },
    Cancel {
        reservation_id: String,
        draft_binding_sha256: [u8; 32],
    },
    Retire {
        expected: Box<WorkerRepairStatus>,
    },
    TransactionStatus {
        selector: RepairTransactionStatusSelector,
    },
    TransactionResolve {
        expected: Box<RepairTransactionStatusPayload>,
        resolution: RepairTransactionResolution,
    },
    VaultLiveParent,
}

#[cfg(feature = "experimental-repair-store")]
impl WorkerRepairCommand {
    pub(super) const fn kind(&self) -> WorkerCommandKind {
        match self {
            Self::Reserve { .. } => WorkerCommandKind::RepairBackupReserve,
            Self::Persist { .. } => WorkerCommandKind::RepairBackupPersist,
            Self::Status { .. } => WorkerCommandKind::RepairBackupStatus,
            Self::Get { .. } => WorkerCommandKind::RepairBackupGet,
            Self::Cancel { .. } => WorkerCommandKind::RepairBackupCancel,
            Self::Retire { .. } => WorkerCommandKind::RepairBackupRetire,
            Self::TransactionStatus { .. } => WorkerCommandKind::RepairTransactionStatus,
            Self::TransactionResolve { .. } => WorkerCommandKind::RepairTransactionResolve,
            Self::VaultLiveParent => WorkerCommandKind::RepairVaultLiveParent,
        }
    }

    fn validate(&self) -> Result<(), InternalWireError> {
        match self {
            Self::Reserve { draft } => draft.validate(),
            Self::Persist {
                expected,
                binding,
                metadata,
                input_size,
            } => {
                expected.validate()?;
                binding.to_protocol()?;
                let metadata_hash = metadata.to_protocol()?.canonical_sha256().bytes();
                if expected.state != WorkerRepairState::Reserved
                    || expected.backup_size != *input_size
                    || expected.metadata_sha256 != metadata_hash
                    || binding.resource_sha256 != expected.expected_backup_sha256
                    || !metadata.is_supported_root_file()
                    || !(1..=MAX_REPAIR_BACKUP_BYTES).contains(input_size)
                {
                    return Err(InternalWireError::InvalidFrame);
                }
                Ok(())
            }
            Self::Status { expected } => expected.validate(),
            Self::Get { expected } => {
                expected.validate()?;
                if expected.state != WorkerRepairState::Durable {
                    return Err(InternalWireError::InvalidFrame);
                }
                Ok(())
            }
            Self::Cancel {
                reservation_id,
                draft_binding_sha256,
            } => {
                RepairReservationId::parse(reservation_id)
                    .map_err(|_| InternalWireError::InvalidFrame)?;
                protocol_sha256(*draft_binding_sha256).map(|_| ())
            }
            Self::Retire { expected } => {
                expected.validate()?;
                if expected.state != WorkerRepairState::Durable {
                    return Err(InternalWireError::InvalidFrame);
                }
                Ok(())
            }
            Self::TransactionStatus { selector } => validate_repair_transaction_selector(selector),
            Self::TransactionResolve {
                expected,
                resolution,
            } => {
                validate_repair_transaction_status(expected)?;
                validate_repair_transaction_resolution(
                    resolution,
                    expected
                        .backup()
                        .execution_intent()
                        .ok_or(InternalWireError::InvalidFrame)?,
                )
            }
            Self::VaultLiveParent => Ok(()),
        }
    }
}

#[cfg(feature = "experimental-repair-store")]
fn protocol_sha256(value: [u8; 32]) -> Result<Sha256, InternalWireError> {
    Sha256::parse(&encode_sha256(&value)).map_err(|_| InternalWireError::InvalidFrame)
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) enum WorkerApplicationCommand {
    AuditAppend {
        request_id: RequestId,
        peer_uid: u32,
        peer_pid: u32,
        sequence: u64,
        event: AuditEventType,
        outcome: AuditOutcome,
        error: Option<ErrorToken>,
    },
    ReportPersist {
        report_id: ReportId,
        payload_sha256: [u8; 32],
        input_size: u64,
    },
    ReportList,
    ReportGet {
        report_id: ReportId,
    },
}

impl WorkerApplicationCommand {
    pub(super) const fn kind(&self) -> WorkerCommandKind {
        match self {
            Self::AuditAppend { .. } => WorkerCommandKind::AuditAppend,
            Self::ReportPersist { .. } => WorkerCommandKind::ReportPersist,
            Self::ReportList => WorkerCommandKind::ReportList,
            Self::ReportGet { .. } => WorkerCommandKind::ReportGet,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum WorkerCommandKind {
    Bootstrap,
    Probe,
    Unlock,
    Lock,
    ProviderStatus,
    ProviderOpenAiConfigure,
    ProviderOpenAiLogout,
    ProviderOpenAiBorrow,
    #[cfg(feature = "experimental-codex-home-lease")]
    ProviderCodexHomeLease,
    AuditAppend,
    ReportPersist,
    ReportList,
    ReportGet,
    #[cfg(feature = "experimental-repair-store")]
    RepairBackupReserve,
    #[cfg(feature = "experimental-repair-store")]
    RepairBackupPersist,
    #[cfg(feature = "experimental-repair-store")]
    RepairBackupStatus,
    #[cfg(feature = "experimental-repair-store")]
    RepairBackupGet,
    #[cfg(feature = "experimental-repair-store")]
    RepairBackupCancel,
    #[cfg(feature = "experimental-repair-store")]
    RepairBackupRetire,
    #[cfg(feature = "experimental-repair-store")]
    RepairTransactionStatus,
    #[cfg(feature = "experimental-repair-store")]
    RepairTransactionResolve,
    #[cfg(feature = "experimental-repair-store")]
    RepairVaultLiveParent,
    AttestQuiescent,
    Shutdown,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct WorkerCommand {
    pub(super) request_id: u64,
    pub(super) kind: WorkerCommandKind,
    pub(super) secret_size: u16,
    pub(super) application: Option<WorkerApplicationCommand>,
    #[cfg(feature = "experimental-repair-store")]
    pub(super) repair: Option<WorkerRepairCommand>,
}

impl WorkerCommand {
    pub(super) fn bootstrap(request_id: u64) -> Self {
        Self {
            request_id,
            kind: WorkerCommandKind::Bootstrap,
            secret_size: 0,
            application: None,
            #[cfg(feature = "experimental-repair-store")]
            repair: None,
        }
    }

    pub(super) fn probe(request_id: u64) -> Self {
        Self {
            request_id,
            kind: WorkerCommandKind::Probe,
            secret_size: 0,
            application: None,
            #[cfg(feature = "experimental-repair-store")]
            repair: None,
        }
    }

    pub(super) fn unlock(request_id: u64, passphrase_size: u16) -> Self {
        Self {
            request_id,
            kind: WorkerCommandKind::Unlock,
            secret_size: passphrase_size,
            application: None,
            #[cfg(feature = "experimental-repair-store")]
            repair: None,
        }
    }

    pub(super) fn lock(request_id: u64) -> Self {
        Self {
            request_id,
            kind: WorkerCommandKind::Lock,
            secret_size: 0,
            application: None,
            #[cfg(feature = "experimental-repair-store")]
            repair: None,
        }
    }

    pub(super) fn provider_status(request_id: u64) -> Self {
        Self {
            request_id,
            kind: WorkerCommandKind::ProviderStatus,
            secret_size: 0,
            application: None,
            #[cfg(feature = "experimental-repair-store")]
            repair: None,
        }
    }

    pub(super) fn provider_openai_configure(request_id: u64, api_key_size: u16) -> Self {
        Self {
            request_id,
            kind: WorkerCommandKind::ProviderOpenAiConfigure,
            secret_size: api_key_size,
            application: None,
            #[cfg(feature = "experimental-repair-store")]
            repair: None,
        }
    }

    pub(super) fn provider_openai_logout(request_id: u64) -> Self {
        Self {
            request_id,
            kind: WorkerCommandKind::ProviderOpenAiLogout,
            secret_size: 0,
            application: None,
            #[cfg(feature = "experimental-repair-store")]
            repair: None,
        }
    }

    pub(super) fn provider_openai_borrow(request_id: u64) -> Self {
        Self {
            request_id,
            kind: WorkerCommandKind::ProviderOpenAiBorrow,
            secret_size: 0,
            application: None,
            #[cfg(feature = "experimental-repair-store")]
            repair: None,
        }
    }

    #[cfg(feature = "experimental-codex-home-lease")]
    pub(super) fn provider_codex_home_lease(request_id: u64) -> Self {
        Self {
            request_id,
            kind: WorkerCommandKind::ProviderCodexHomeLease,
            secret_size: 0,
            application: None,
            #[cfg(feature = "experimental-repair-store")]
            repair: None,
        }
    }

    pub(super) fn application(request_id: u64, application: WorkerApplicationCommand) -> Self {
        Self {
            request_id,
            kind: application.kind(),
            secret_size: 0,
            application: Some(application),
            #[cfg(feature = "experimental-repair-store")]
            repair: None,
        }
    }

    #[cfg(feature = "experimental-repair-store")]
    pub(super) fn repair(request_id: u64, repair: WorkerRepairCommand) -> Self {
        Self {
            request_id,
            kind: repair.kind(),
            secret_size: 0,
            application: None,
            repair: Some(repair),
        }
    }

    pub(super) fn shutdown(request_id: u64) -> Self {
        Self {
            request_id,
            kind: WorkerCommandKind::Shutdown,
            secret_size: 0,
            application: None,
            #[cfg(feature = "experimental-repair-store")]
            repair: None,
        }
    }

    pub(super) fn attest_quiescent(request_id: u64) -> Self {
        Self {
            request_id,
            kind: WorkerCommandKind::AttestQuiescent,
            secret_size: 0,
            application: None,
            #[cfg(feature = "experimental-repair-store")]
            repair: None,
        }
    }

    fn encode(&self) -> Result<[u8; COMMAND_BYTES], InternalWireError> {
        let application_kind = self
            .application
            .as_ref()
            .map(WorkerApplicationCommand::kind);
        #[cfg(feature = "experimental-repair-store")]
        let repair_kind = self.repair.as_ref().map(WorkerRepairCommand::kind);
        #[cfg(feature = "experimental-repair-store")]
        if repair_kind.is_some_and(|kind| kind != self.kind)
            || (repair_kind.is_some() && (application_kind.is_some() || self.secret_size != 0))
            || (repair_kind.is_none()
                && matches!(
                    self.kind,
                    WorkerCommandKind::RepairBackupReserve
                        | WorkerCommandKind::RepairBackupPersist
                        | WorkerCommandKind::RepairBackupStatus
                        | WorkerCommandKind::RepairBackupGet
                        | WorkerCommandKind::RepairBackupCancel
                        | WorkerCommandKind::RepairBackupRetire
                        | WorkerCommandKind::RepairTransactionStatus
                        | WorkerCommandKind::RepairTransactionResolve
                        | WorkerCommandKind::RepairVaultLiveParent
                ))
        {
            return Err(InternalWireError::InvalidFrame);
        }
        if self.request_id == 0
            || application_kind.is_some_and(|kind| kind != self.kind)
            || (application_kind.is_some() && self.secret_size != 0)
            || (application_kind.is_none()
                && ((self.kind == WorkerCommandKind::Unlock
                    && !valid_passphrase_size(self.secret_size))
                    || (self.kind == WorkerCommandKind::ProviderOpenAiConfigure
                        && !valid_openai_key_size(self.secret_size))
                    || (!matches!(
                        self.kind,
                        WorkerCommandKind::Unlock | WorkerCommandKind::ProviderOpenAiConfigure
                    ) && self.secret_size != 0)
                    || matches!(
                        self.kind,
                        WorkerCommandKind::AuditAppend
                            | WorkerCommandKind::ReportPersist
                            | WorkerCommandKind::ReportList
                            | WorkerCommandKind::ReportGet
                    )))
        {
            return Err(InternalWireError::InvalidFrame);
        }
        let mut bytes = [0_u8; COMMAND_BYTES];
        bytes[..8].copy_from_slice(COMMAND_MAGIC);
        bytes[8] = match self.kind {
            WorkerCommandKind::Bootstrap => 1,
            WorkerCommandKind::Probe => 2,
            WorkerCommandKind::Unlock => 3,
            WorkerCommandKind::Lock => 4,
            WorkerCommandKind::Shutdown => 5,
            WorkerCommandKind::AttestQuiescent => 6,
            WorkerCommandKind::ProviderStatus => 7,
            WorkerCommandKind::ProviderOpenAiConfigure => 8,
            WorkerCommandKind::ProviderOpenAiLogout => 9,
            WorkerCommandKind::ProviderOpenAiBorrow => 10,
            #[cfg(feature = "experimental-codex-home-lease")]
            WorkerCommandKind::ProviderCodexHomeLease => 11,
            WorkerCommandKind::AuditAppend => 12,
            WorkerCommandKind::ReportPersist => 13,
            WorkerCommandKind::ReportList => 14,
            WorkerCommandKind::ReportGet => 15,
            #[cfg(feature = "experimental-repair-store")]
            WorkerCommandKind::RepairBackupReserve => 16,
            #[cfg(feature = "experimental-repair-store")]
            WorkerCommandKind::RepairBackupPersist => 17,
            #[cfg(feature = "experimental-repair-store")]
            WorkerCommandKind::RepairBackupStatus => 18,
            #[cfg(feature = "experimental-repair-store")]
            WorkerCommandKind::RepairBackupGet => 19,
            #[cfg(feature = "experimental-repair-store")]
            WorkerCommandKind::RepairBackupCancel => 20,
            #[cfg(feature = "experimental-repair-store")]
            WorkerCommandKind::RepairBackupRetire => 21,
            #[cfg(feature = "experimental-repair-store")]
            WorkerCommandKind::RepairTransactionStatus => 22,
            #[cfg(feature = "experimental-repair-store")]
            WorkerCommandKind::RepairTransactionResolve => 23,
            #[cfg(feature = "experimental-repair-store")]
            WorkerCommandKind::RepairVaultLiveParent => 24,
        };
        bytes[12..20].copy_from_slice(&self.request_id.to_be_bytes());
        if let Some(application) = &self.application {
            match application {
                WorkerApplicationCommand::AuditAppend {
                    request_id,
                    peer_uid,
                    peer_pid,
                    sequence,
                    event,
                    outcome,
                    error,
                } => {
                    if *peer_uid == 0
                        || *peer_pid == 0
                        || !(1..=MAX_AUDIT_SEQUENCE).contains(sequence)
                        || ((*outcome == AuditOutcome::Succeeded && error.is_some())
                            || (*outcome != AuditOutcome::Succeeded && error.is_none()))
                    {
                        return Err(InternalWireError::InvalidFrame);
                    }
                    bytes[9] = encode_audit_event(*event);
                    bytes[10] = encode_audit_outcome(*outcome);
                    bytes[11] = error.map(encode_error_token).unwrap_or(0);
                    bytes[COMMAND_VALUE_OFFSET..COMMAND_VALUE_OFFSET + 8]
                        .copy_from_slice(&sequence.to_be_bytes());
                    bytes[COMMAND_PEER_UID_OFFSET..COMMAND_PEER_UID_OFFSET + 4]
                        .copy_from_slice(&peer_uid.to_be_bytes());
                    bytes[COMMAND_PEER_PID_OFFSET..COMMAND_PEER_PID_OFFSET + 4]
                        .copy_from_slice(&peer_pid.to_be_bytes());
                    bytes[COMMAND_IDENTIFIER_OFFSET..COMMAND_IDENTIFIER_OFFSET + 16]
                        .copy_from_slice(&encode_identifier(request_id.as_str(), b"R-")?);
                }
                WorkerApplicationCommand::ReportPersist {
                    report_id,
                    payload_sha256,
                    input_size,
                } => {
                    if !(2..=MAX_SESSION_REPORT_JSON_BYTES).contains(input_size) {
                        return Err(InternalWireError::InvalidFrame);
                    }
                    bytes[COMMAND_VALUE_OFFSET..COMMAND_VALUE_OFFSET + 8]
                        .copy_from_slice(&input_size.to_be_bytes());
                    bytes[COMMAND_IDENTIFIER_OFFSET..COMMAND_IDENTIFIER_OFFSET + 16]
                        .copy_from_slice(&encode_identifier(report_id.as_str(), b"RP-")?);
                    bytes[COMMAND_SHA256_OFFSET..COMMAND_SHA256_OFFSET + 32]
                        .copy_from_slice(payload_sha256);
                }
                WorkerApplicationCommand::ReportList => {}
                WorkerApplicationCommand::ReportGet { report_id } => {
                    bytes[COMMAND_IDENTIFIER_OFFSET..COMMAND_IDENTIFIER_OFFSET + 16]
                        .copy_from_slice(&encode_identifier(report_id.as_str(), b"RP-")?);
                }
            }
        }
        #[cfg(feature = "experimental-repair-store")]
        if let Some(repair) = &self.repair {
            repair.validate()?;
            encode_repair_command(&mut bytes, repair)?;
        } else if self.application.is_none() {
            bytes[COMMAND_VALUE_OFFSET..COMMAND_VALUE_OFFSET + 2]
                .copy_from_slice(&self.secret_size.to_be_bytes());
        }
        #[cfg(not(feature = "experimental-repair-store"))]
        if self.application.is_none() {
            bytes[COMMAND_VALUE_OFFSET..COMMAND_VALUE_OFFSET + 2]
                .copy_from_slice(&self.secret_size.to_be_bytes());
        }
        Ok(bytes)
    }

    fn decode(bytes: &[u8]) -> Result<Self, InternalWireError> {
        if bytes.len() != COMMAND_BYTES || &bytes[..8] != COMMAND_MAGIC {
            return Err(InternalWireError::InvalidFrame);
        }
        let request_id = u64::from_be_bytes(
            bytes[12..20]
                .try_into()
                .map_err(|_| InternalWireError::InvalidFrame)?,
        );
        let secret_size = u16::from_be_bytes(
            bytes[COMMAND_VALUE_OFFSET..COMMAND_VALUE_OFFSET + 2]
                .try_into()
                .map_err(|_| InternalWireError::InvalidFrame)?,
        );
        let kind = match bytes[8] {
            1 => WorkerCommandKind::Bootstrap,
            2 => WorkerCommandKind::Probe,
            3 => WorkerCommandKind::Unlock,
            4 => WorkerCommandKind::Lock,
            5 => WorkerCommandKind::Shutdown,
            6 => WorkerCommandKind::AttestQuiescent,
            7 => WorkerCommandKind::ProviderStatus,
            8 => WorkerCommandKind::ProviderOpenAiConfigure,
            9 => WorkerCommandKind::ProviderOpenAiLogout,
            10 => WorkerCommandKind::ProviderOpenAiBorrow,
            #[cfg(feature = "experimental-codex-home-lease")]
            11 => WorkerCommandKind::ProviderCodexHomeLease,
            12 => WorkerCommandKind::AuditAppend,
            13 => WorkerCommandKind::ReportPersist,
            14 => WorkerCommandKind::ReportList,
            15 => WorkerCommandKind::ReportGet,
            #[cfg(feature = "experimental-repair-store")]
            16 => WorkerCommandKind::RepairBackupReserve,
            #[cfg(feature = "experimental-repair-store")]
            17 => WorkerCommandKind::RepairBackupPersist,
            #[cfg(feature = "experimental-repair-store")]
            18 => WorkerCommandKind::RepairBackupStatus,
            #[cfg(feature = "experimental-repair-store")]
            19 => WorkerCommandKind::RepairBackupGet,
            #[cfg(feature = "experimental-repair-store")]
            20 => WorkerCommandKind::RepairBackupCancel,
            #[cfg(feature = "experimental-repair-store")]
            21 => WorkerCommandKind::RepairBackupRetire,
            #[cfg(feature = "experimental-repair-store")]
            22 => WorkerCommandKind::RepairTransactionStatus,
            #[cfg(feature = "experimental-repair-store")]
            23 => WorkerCommandKind::RepairTransactionResolve,
            #[cfg(feature = "experimental-repair-store")]
            24 => WorkerCommandKind::RepairVaultLiveParent,
            _ => return Err(InternalWireError::InvalidFrame),
        };
        let application = match kind {
            WorkerCommandKind::AuditAppend => Some(WorkerApplicationCommand::AuditAppend {
                request_id: RequestId::parse(&decode_identifier(
                    b"R-",
                    &bytes[COMMAND_IDENTIFIER_OFFSET..COMMAND_IDENTIFIER_OFFSET + 16],
                ))
                .map_err(|_| InternalWireError::InvalidFrame)?,
                peer_uid: u32::from_be_bytes(
                    bytes[COMMAND_PEER_UID_OFFSET..COMMAND_PEER_UID_OFFSET + 4]
                        .try_into()
                        .map_err(|_| InternalWireError::InvalidFrame)?,
                ),
                peer_pid: u32::from_be_bytes(
                    bytes[COMMAND_PEER_PID_OFFSET..COMMAND_PEER_PID_OFFSET + 4]
                        .try_into()
                        .map_err(|_| InternalWireError::InvalidFrame)?,
                ),
                sequence: u64::from_be_bytes(
                    bytes[COMMAND_VALUE_OFFSET..COMMAND_VALUE_OFFSET + 8]
                        .try_into()
                        .map_err(|_| InternalWireError::InvalidFrame)?,
                ),
                event: decode_audit_event(bytes[9])?,
                outcome: decode_audit_outcome(bytes[10])?,
                error: (bytes[11] != 0)
                    .then(|| decode_error_token(bytes[11]))
                    .transpose()?,
            }),
            WorkerCommandKind::ReportPersist => Some(WorkerApplicationCommand::ReportPersist {
                report_id: ReportId::parse(&decode_identifier(
                    b"RP-",
                    &bytes[COMMAND_IDENTIFIER_OFFSET..COMMAND_IDENTIFIER_OFFSET + 16],
                ))
                .map_err(|_| InternalWireError::InvalidFrame)?,
                payload_sha256: bytes[COMMAND_SHA256_OFFSET..COMMAND_SHA256_OFFSET + 32]
                    .try_into()
                    .map_err(|_| InternalWireError::InvalidFrame)?,
                input_size: u64::from_be_bytes(
                    bytes[COMMAND_VALUE_OFFSET..COMMAND_VALUE_OFFSET + 8]
                        .try_into()
                        .map_err(|_| InternalWireError::InvalidFrame)?,
                ),
            }),
            WorkerCommandKind::ReportList => Some(WorkerApplicationCommand::ReportList),
            WorkerCommandKind::ReportGet => Some(WorkerApplicationCommand::ReportGet {
                report_id: ReportId::parse(&decode_identifier(
                    b"RP-",
                    &bytes[COMMAND_IDENTIFIER_OFFSET..COMMAND_IDENTIFIER_OFFSET + 16],
                ))
                .map_err(|_| InternalWireError::InvalidFrame)?,
            }),
            _ => None,
        };
        #[cfg(feature = "experimental-repair-store")]
        let repair = match kind {
            WorkerCommandKind::RepairBackupReserve
            | WorkerCommandKind::RepairBackupPersist
            | WorkerCommandKind::RepairBackupStatus
            | WorkerCommandKind::RepairBackupGet
            | WorkerCommandKind::RepairBackupCancel
            | WorkerCommandKind::RepairBackupRetire
            | WorkerCommandKind::RepairTransactionStatus
            | WorkerCommandKind::RepairTransactionResolve
            | WorkerCommandKind::RepairVaultLiveParent => Some(decode_repair_command(bytes, kind)?),
            _ => None,
        };
        #[cfg(feature = "experimental-repair-store")]
        let payload_command = application.is_some() || repair.is_some();
        #[cfg(not(feature = "experimental-repair-store"))]
        let payload_command = application.is_some();
        let command = Self {
            request_id,
            kind,
            secret_size: if payload_command { 0 } else { secret_size },
            application,
            #[cfg(feature = "experimental-repair-store")]
            repair,
        };
        if command.encode()?.as_slice() != bytes {
            return Err(InternalWireError::InvalidFrame);
        }
        Ok(command)
    }
}

#[cfg(feature = "experimental-repair-store")]
fn encode_repair_command(
    bytes: &mut [u8; COMMAND_BYTES],
    command: &WorkerRepairCommand,
) -> Result<(), InternalWireError> {
    let mut writer = ClosedFrameWriter::new(&mut bytes[REPAIR_PAYLOAD_OFFSET..]);
    match command {
        WorkerRepairCommand::Reserve { draft } => encode_repair_draft(&mut writer, draft)?,
        WorkerRepairCommand::Persist {
            expected,
            binding,
            metadata,
            input_size,
        } => {
            encode_repair_status(&mut writer, expected)?;
            encode_repair_binding(&mut writer, binding)?;
            writer.u32(metadata.mode)?;
            writer.u32(metadata.uid)?;
            writer.u32(metadata.gid)?;
            writer.u64(*input_size)?;
        }
        WorkerRepairCommand::Status { expected }
        | WorkerRepairCommand::Get { expected }
        | WorkerRepairCommand::Retire { expected } => {
            encode_repair_status(&mut writer, expected)?;
        }
        WorkerRepairCommand::Cancel {
            reservation_id,
            draft_binding_sha256,
        } => {
            writer.string(reservation_id, MAX_REPAIR_ID_BYTES)?;
            writer.hash(*draft_binding_sha256)?;
        }
        WorkerRepairCommand::TransactionStatus { selector } => {
            encode_repair_transaction_selector(&mut writer, selector)?;
        }
        WorkerRepairCommand::TransactionResolve {
            expected,
            resolution,
        } => {
            encode_repair_transaction_status(&mut writer, expected)?;
            encode_repair_transaction_resolution(
                &mut writer,
                resolution,
                expected
                    .backup()
                    .execution_intent()
                    .ok_or(InternalWireError::InvalidFrame)?,
            )?;
        }
        WorkerRepairCommand::VaultLiveParent => {}
    }
    Ok(())
}

#[cfg(feature = "experimental-repair-store")]
fn decode_repair_command(
    bytes: &[u8],
    kind: WorkerCommandKind,
) -> Result<WorkerRepairCommand, InternalWireError> {
    let mut reader = ClosedFrameReader::new(
        bytes
            .get(REPAIR_PAYLOAD_OFFSET..)
            .ok_or(InternalWireError::InvalidFrame)?,
    );
    let command = match kind {
        WorkerCommandKind::RepairBackupReserve => WorkerRepairCommand::Reserve {
            draft: decode_repair_draft(&mut reader)?,
        },
        WorkerCommandKind::RepairBackupPersist => WorkerRepairCommand::Persist {
            expected: Box::new(decode_repair_status(&mut reader)?),
            binding: Box::new(decode_repair_binding(&mut reader)?),
            metadata: WorkerRepairFileMetadata {
                mode: reader.u32()?,
                uid: reader.u32()?,
                gid: reader.u32()?,
            },
            input_size: reader.u64()?,
        },
        WorkerCommandKind::RepairBackupStatus => WorkerRepairCommand::Status {
            expected: Box::new(decode_repair_status(&mut reader)?),
        },
        WorkerCommandKind::RepairBackupGet => WorkerRepairCommand::Get {
            expected: Box::new(decode_repair_status(&mut reader)?),
        },
        WorkerCommandKind::RepairBackupCancel => WorkerRepairCommand::Cancel {
            reservation_id: reader.string(MAX_REPAIR_ID_BYTES)?,
            draft_binding_sha256: reader.hash()?,
        },
        WorkerCommandKind::RepairBackupRetire => WorkerRepairCommand::Retire {
            expected: Box::new(decode_repair_status(&mut reader)?),
        },
        WorkerCommandKind::RepairTransactionStatus => WorkerRepairCommand::TransactionStatus {
            selector: decode_repair_transaction_selector(&mut reader)?,
        },
        WorkerCommandKind::RepairTransactionResolve => {
            let expected = decode_repair_transaction_status(&mut reader)?;
            let resolution = decode_repair_transaction_resolution(
                &mut reader,
                expected
                    .backup()
                    .execution_intent()
                    .ok_or(InternalWireError::InvalidFrame)?,
            )?;
            WorkerRepairCommand::TransactionResolve {
                expected: Box::new(expected),
                resolution,
            }
        }
        WorkerCommandKind::RepairVaultLiveParent => WorkerRepairCommand::VaultLiveParent,
        _ => return Err(InternalWireError::InvalidFrame),
    };
    if !reader.remaining_is_zero() {
        return Err(InternalWireError::InvalidFrame);
    }
    command.validate()?;
    Ok(command)
}

#[cfg(feature = "experimental-repair-store")]
fn encode_repair_draft(
    writer: &mut ClosedFrameWriter<'_>,
    draft: &WorkerRepairDraft,
) -> Result<(), InternalWireError> {
    draft.validate()?;
    writer.string(&draft.session_id, MAX_REPAIR_ID_BYTES)?;
    writer.string(&draft.target_id, MAX_REPAIR_ID_BYTES)?;
    writer.hash(draft.target_fingerprint)?;
    writer.string(&draft.target_recovery_fingerprint, MAX_REPAIR_ID_BYTES)?;
    writer.hash(draft.expected_backup_sha256)?;
    writer.hash(draft.metadata_sha256)?;
    writer.u64(draft.backup_size)?;
    writer.u64(draft.required_capacity_bytes)
}

#[cfg(feature = "experimental-repair-store")]
fn decode_repair_draft(
    reader: &mut ClosedFrameReader<'_>,
) -> Result<WorkerRepairDraft, InternalWireError> {
    let draft = WorkerRepairDraft {
        session_id: reader.string(MAX_REPAIR_ID_BYTES)?,
        target_id: reader.string(MAX_REPAIR_ID_BYTES)?,
        target_fingerprint: reader.hash()?,
        target_recovery_fingerprint: reader.string(MAX_REPAIR_ID_BYTES)?,
        expected_backup_sha256: reader.hash()?,
        metadata_sha256: reader.hash()?,
        backup_size: reader.u64()?,
        required_capacity_bytes: reader.u64()?,
    };
    draft.validate()?;
    Ok(draft)
}

#[cfg(feature = "experimental-repair-store")]
fn encode_repair_binding(
    writer: &mut ClosedFrameWriter<'_>,
    binding: &WorkerRepairBinding,
) -> Result<(), InternalWireError> {
    binding.to_protocol()?;
    writer.string(&binding.plan_id, MAX_REPAIR_ID_BYTES)?;
    writer.hash(binding.plan_sha256)?;
    writer.string(&binding.approval_id, MAX_REPAIR_ID_BYTES)?;
    writer.hash(binding.approval_sha256)?;
    writer.string(&binding.resource_id, MAX_REPAIR_ID_BYTES)?;
    writer.hash(binding.resource_sha256)?;
    encode_repair_execution_intent(writer, &binding.execution_intent)
}

#[cfg(feature = "experimental-repair-store")]
fn decode_repair_binding(
    reader: &mut ClosedFrameReader<'_>,
) -> Result<WorkerRepairBinding, InternalWireError> {
    let binding = WorkerRepairBinding {
        plan_id: reader.string(MAX_REPAIR_ID_BYTES)?,
        plan_sha256: reader.hash()?,
        approval_id: reader.string(MAX_REPAIR_ID_BYTES)?,
        approval_sha256: reader.hash()?,
        resource_id: reader.string(MAX_REPAIR_ID_BYTES)?,
        resource_sha256: reader.hash()?,
        execution_intent: decode_repair_execution_intent(reader)?,
    };
    binding.to_protocol()?;
    Ok(binding)
}

#[cfg(feature = "experimental-repair-store")]
fn encode_repair_execution_intent(
    writer: &mut ClosedFrameWriter<'_>,
    intent: &RepairExecutionIntentV1,
) -> Result<(), InternalWireError> {
    writer.string(intent.action_id(), MAX_REPAIR_ID_BYTES)?;
    writer.string(intent.session_id(), MAX_REPAIR_ID_BYTES)?;
    writer.u64(intent.approval_sequence())?;
    writer.string(intent.target_id(), MAX_REPAIR_ID_BYTES)?;
    writer.string(intent.scan_fingerprint(), MAX_REPAIR_ID_BYTES)?;
    writer.hash(intent.target_fingerprint().bytes())?;
    writer.hash(intent.target_physical_parent_fingerprint().bytes())?;
    writer.string(intent.target_recovery_fingerprint(), MAX_REPAIR_ID_BYTES)?;
    writer.string(intent.lock_identity(), MAX_REPAIR_ID_BYTES)?;
    writer.hash(intent.before_sha256().bytes())?;
    writer.hash(intent.after_sha256().bytes())?;
    writer.hash(intent.diff_sha256().bytes())?;
    writer.hash(intent.observed_uuid_set_sha256().bytes())?;
    encode_repair_file_metadata(writer, intent.before_metadata())
}

#[cfg(feature = "experimental-repair-store")]
fn decode_repair_execution_intent(
    reader: &mut ClosedFrameReader<'_>,
) -> Result<RepairExecutionIntentV1, InternalWireError> {
    let action_id = reader.string(MAX_REPAIR_ID_BYTES)?;
    let session_id = reader.string(MAX_REPAIR_ID_BYTES)?;
    let approval_sequence = reader.u64()?;
    let target_id = reader.string(MAX_REPAIR_ID_BYTES)?;
    let scan_fingerprint = reader.string(MAX_REPAIR_ID_BYTES)?;
    let target_fingerprint = protocol_sha256(reader.hash()?)?;
    let target_physical_parent_fingerprint = protocol_sha256(reader.hash()?)?;
    let target_recovery_fingerprint = reader.string(MAX_REPAIR_ID_BYTES)?;
    let lock_identity = reader.string(MAX_REPAIR_ID_BYTES)?;
    let before_sha256 = protocol_sha256(reader.hash()?)?;
    let after_sha256 = protocol_sha256(reader.hash()?)?;
    let diff_sha256 = protocol_sha256(reader.hash()?)?;
    let observed_uuid_set_sha256 = protocol_sha256(reader.hash()?)?;
    let before_metadata = decode_repair_file_metadata(reader)?;
    let intent = RepairExecutionIntentV1::new(
        session_id,
        approval_sequence,
        target_id,
        scan_fingerprint,
        target_fingerprint,
        target_physical_parent_fingerprint,
        target_recovery_fingerprint,
        lock_identity,
        before_sha256,
        after_sha256,
        diff_sha256,
        observed_uuid_set_sha256,
        before_metadata,
    )
    .map_err(|_| InternalWireError::InvalidFrame)?;
    if intent.action_id() != action_id {
        return Err(InternalWireError::InvalidFrame);
    }
    Ok(intent)
}

#[cfg(feature = "experimental-repair-store")]
fn encode_repair_file_metadata(
    writer: &mut ClosedFrameWriter<'_>,
    metadata: &RepairFileMetadataV1,
) -> Result<(), InternalWireError> {
    writer.u32(metadata.mode())?;
    writer.u32(metadata.uid())?;
    writer.u32(metadata.gid())
}

#[cfg(feature = "experimental-repair-store")]
fn decode_repair_file_metadata(
    reader: &mut ClosedFrameReader<'_>,
) -> Result<RepairFileMetadataV1, InternalWireError> {
    RepairFileMetadataV1::new(reader.u32()?, reader.u32()?, reader.u32()?)
        .map_err(|_| InternalWireError::InvalidFrame)
}

#[cfg(feature = "experimental-repair-store")]
fn encode_repair_status(
    writer: &mut ClosedFrameWriter<'_>,
    status: &WorkerRepairStatus,
) -> Result<(), InternalWireError> {
    status.validate()?;
    writer.u8(match status.state {
        WorkerRepairState::Reserved => 1,
        WorkerRepairState::Durable => 2,
    })?;
    writer.string(&status.reservation_id, MAX_REPAIR_ID_BYTES)?;
    writer.hash(status.draft_binding_sha256)?;
    writer.string(&status.locator, MAX_REPAIR_ID_BYTES)?;
    writer.string(&status.vault_id, MAX_REPAIR_ID_BYTES)?;
    writer.hash(status.vault_identity_fingerprint)?;
    writer.hash(status.physical_parent_fingerprint)?;
    writer.u64(status.reserved_bytes)?;
    writer.u64(status.backup_size)?;
    writer.hash(status.expected_backup_sha256)?;
    writer.hash(status.metadata_sha256)?;
    if let Some(binding) = status.binding.as_ref() {
        encode_repair_binding(writer, binding)?;
    }
    Ok(())
}

#[cfg(feature = "experimental-repair-store")]
fn decode_repair_status(
    reader: &mut ClosedFrameReader<'_>,
) -> Result<WorkerRepairStatus, InternalWireError> {
    let state = match reader.u8()? {
        1 => WorkerRepairState::Reserved,
        2 => WorkerRepairState::Durable,
        _ => return Err(InternalWireError::InvalidFrame),
    };
    let status = WorkerRepairStatus {
        state,
        reservation_id: reader.string(MAX_REPAIR_ID_BYTES)?,
        draft_binding_sha256: reader.hash()?,
        locator: reader.string(MAX_REPAIR_ID_BYTES)?,
        vault_id: reader.string(MAX_REPAIR_ID_BYTES)?,
        vault_identity_fingerprint: reader.hash()?,
        physical_parent_fingerprint: reader.hash()?,
        reserved_bytes: reader.u64()?,
        backup_size: reader.u64()?,
        expected_backup_sha256: reader.hash()?,
        metadata_sha256: reader.hash()?,
        binding: if state == WorkerRepairState::Durable {
            Some(decode_repair_binding(reader)?)
        } else {
            None
        },
    };
    status.validate()?;
    Ok(status)
}

#[cfg(feature = "experimental-repair-store")]
fn encode_repair_transaction_selector(
    writer: &mut ClosedFrameWriter<'_>,
    selector: &RepairTransactionStatusSelector,
) -> Result<(), InternalWireError> {
    validate_repair_transaction_selector(selector)?;
    match selector {
        RepairTransactionStatusSelector::PendingSingleton => writer.u8(1),
        RepairTransactionStatusSelector::Exact {
            reservation_id,
            transaction_binding_sha256,
        } => {
            writer.u8(2)?;
            writer.string(reservation_id.as_str(), MAX_REPAIR_ID_BYTES)?;
            writer.hash(transaction_binding_sha256.bytes())
        }
    }
}

#[cfg(feature = "experimental-repair-store")]
fn decode_repair_transaction_selector(
    reader: &mut ClosedFrameReader<'_>,
) -> Result<RepairTransactionStatusSelector, InternalWireError> {
    let selector = match reader.u8()? {
        1 => RepairTransactionStatusSelector::pending_singleton(),
        2 => RepairTransactionStatusSelector::exact(
            RepairReservationId::parse(&reader.string(MAX_REPAIR_ID_BYTES)?)
                .map_err(|_| InternalWireError::InvalidFrame)?,
            protocol_sha256(reader.hash()?)?,
        ),
        _ => return Err(InternalWireError::InvalidFrame),
    };
    validate_repair_transaction_selector(&selector)?;
    Ok(selector)
}

#[cfg(feature = "experimental-repair-store")]
fn validate_repair_transaction_selector(
    selector: &RepairTransactionStatusSelector,
) -> Result<(), InternalWireError> {
    match selector {
        RepairTransactionStatusSelector::PendingSingleton => Ok(()),
        RepairTransactionStatusSelector::Exact {
            reservation_id,
            transaction_binding_sha256,
        } => {
            RepairReservationId::parse(reservation_id.as_str())
                .map_err(|_| InternalWireError::InvalidFrame)?;
            protocol_sha256(transaction_binding_sha256.bytes()).map(|_| ())
        }
    }
}

#[cfg(feature = "experimental-repair-store")]
fn encode_repair_transaction_status(
    writer: &mut ClosedFrameWriter<'_>,
    status: &RepairTransactionStatusPayload,
) -> Result<(), InternalWireError> {
    validate_repair_transaction_status(status)?;
    writer.u8(match status.phase() {
        RepairTransactionPhase::Pending => 1,
        RepairTransactionPhase::Resolved => 2,
        RepairTransactionPhase::ManualReconciliationRequired => 3,
    })?;
    writer.hash(status.transaction_binding_sha256().bytes())?;
    encode_repair_status(writer, &WorkerRepairStatus::from_protocol(status.backup())?)?;
    match status.resolution() {
        None => writer.u8(0),
        Some(resolution) => {
            writer.u8(1)?;
            encode_repair_transaction_resolution(
                writer,
                resolution,
                status
                    .backup()
                    .execution_intent()
                    .ok_or(InternalWireError::InvalidFrame)?,
            )
        }
    }
}

#[cfg(feature = "experimental-repair-store")]
fn decode_repair_transaction_status(
    reader: &mut ClosedFrameReader<'_>,
) -> Result<RepairTransactionStatusPayload, InternalWireError> {
    let encoded_phase = match reader.u8()? {
        1 => RepairTransactionPhase::Pending,
        2 => RepairTransactionPhase::Resolved,
        3 => RepairTransactionPhase::ManualReconciliationRequired,
        _ => return Err(InternalWireError::InvalidFrame),
    };
    let encoded_binding = reader.hash()?;
    let backup = decode_repair_status(reader)?.to_protocol()?;
    let intent = backup
        .execution_intent()
        .ok_or(InternalWireError::InvalidFrame)?;
    let resolution = match reader.u8()? {
        0 => None,
        1 => Some(decode_repair_transaction_resolution(reader, intent)?),
        _ => return Err(InternalWireError::InvalidFrame),
    };
    let status = match resolution {
        None => RepairTransactionStatusPayload::pending(backup),
        Some(resolution) => RepairTransactionStatusPayload::resolved(backup, resolution),
    }
    .map_err(|_| InternalWireError::InvalidFrame)?;
    if status.phase() != encoded_phase
        || status.transaction_binding_sha256().bytes() != encoded_binding
    {
        return Err(InternalWireError::InvalidFrame);
    }
    validate_repair_transaction_status(&status)?;
    Ok(status)
}

#[cfg(feature = "experimental-repair-store")]
fn validate_repair_transaction_status(
    status: &RepairTransactionStatusPayload,
) -> Result<(), InternalWireError> {
    let canonical = match status.resolution() {
        None => RepairTransactionStatusPayload::pending(status.backup().clone()),
        Some(resolution) => {
            RepairTransactionStatusPayload::resolved(status.backup().clone(), resolution.clone())
        }
    }
    .map_err(|_| InternalWireError::InvalidFrame)?;
    if &canonical != status {
        return Err(InternalWireError::InvalidFrame);
    }
    Ok(())
}

#[cfg(feature = "experimental-repair-store")]
fn encode_repair_transaction_resolution(
    writer: &mut ClosedFrameWriter<'_>,
    resolution: &RepairTransactionResolution,
    intent: &RepairExecutionIntentV1,
) -> Result<(), InternalWireError> {
    validate_repair_transaction_resolution(resolution, intent)?;
    writer.u8(match resolution.outcome() {
        RepairTransactionResolutionOutcome::CommittedAfter => 1,
        RepairTransactionResolutionOutcome::ClosedBeforeUnchanged => 2,
        RepairTransactionResolutionOutcome::ClosedBeforeRestored => 3,
        RepairTransactionResolutionOutcome::ManualReconciliationRequired => 4,
    })?;
    writer.u8(match resolution.target_state() {
        RepairTransactionTargetState::Before => 1,
        RepairTransactionTargetState::After => 2,
        RepairTransactionTargetState::Third => 3,
    })?;
    writer.hash(resolution.observed_resource_sha256().bytes())?;
    writer.hash(resolution.observed_metadata_sha256().bytes())?;
    writer.u8(u8::from(resolution.mount_cleanup_verified()))
}

#[cfg(feature = "experimental-repair-store")]
fn decode_repair_transaction_resolution(
    reader: &mut ClosedFrameReader<'_>,
    intent: &RepairExecutionIntentV1,
) -> Result<RepairTransactionResolution, InternalWireError> {
    let outcome = match reader.u8()? {
        1 => RepairTransactionResolutionOutcome::CommittedAfter,
        2 => RepairTransactionResolutionOutcome::ClosedBeforeUnchanged,
        3 => RepairTransactionResolutionOutcome::ClosedBeforeRestored,
        4 => RepairTransactionResolutionOutcome::ManualReconciliationRequired,
        _ => return Err(InternalWireError::InvalidFrame),
    };
    let encoded_target_state = match reader.u8()? {
        1 => RepairTransactionTargetState::Before,
        2 => RepairTransactionTargetState::After,
        3 => RepairTransactionTargetState::Third,
        _ => return Err(InternalWireError::InvalidFrame),
    };
    let observed_resource_sha256 = protocol_sha256(reader.hash()?)?;
    let observed_metadata_sha256 = protocol_sha256(reader.hash()?)?;
    let mount_cleanup_verified = match reader.u8()? {
        0 => false,
        1 => true,
        _ => return Err(InternalWireError::InvalidFrame),
    };
    let resolution = RepairTransactionResolution::new(
        outcome,
        observed_resource_sha256,
        observed_metadata_sha256,
        mount_cleanup_verified,
        intent,
    )
    .map_err(|_| InternalWireError::InvalidFrame)?;
    if resolution.target_state() != encoded_target_state {
        return Err(InternalWireError::InvalidFrame);
    }
    Ok(resolution)
}

#[cfg(feature = "experimental-repair-store")]
fn validate_repair_transaction_resolution(
    resolution: &RepairTransactionResolution,
    intent: &RepairExecutionIntentV1,
) -> Result<(), InternalWireError> {
    let canonical = RepairTransactionResolution::new(
        resolution.outcome(),
        resolution.observed_resource_sha256().clone(),
        resolution.observed_metadata_sha256().clone(),
        resolution.mount_cleanup_verified(),
        intent,
    )
    .map_err(|_| InternalWireError::InvalidFrame)?;
    if &canonical != resolution {
        return Err(InternalWireError::InvalidFrame);
    }
    Ok(())
}

#[cfg(feature = "experimental-repair-store")]
struct ClosedFrameWriter<'a> {
    bytes: &'a mut [u8],
    offset: usize,
}

#[cfg(feature = "experimental-repair-store")]
impl<'a> ClosedFrameWriter<'a> {
    fn new(bytes: &'a mut [u8]) -> Self {
        Self { bytes, offset: 0 }
    }

    fn raw(&mut self, value: &[u8]) -> Result<(), InternalWireError> {
        let end = self
            .offset
            .checked_add(value.len())
            .filter(|end| *end <= self.bytes.len())
            .ok_or(InternalWireError::InvalidFrame)?;
        self.bytes[self.offset..end].copy_from_slice(value);
        self.offset = end;
        Ok(())
    }

    fn u8(&mut self, value: u8) -> Result<(), InternalWireError> {
        self.raw(&[value])
    }

    fn u64(&mut self, value: u64) -> Result<(), InternalWireError> {
        self.raw(&value.to_be_bytes())
    }

    fn u32(&mut self, value: u32) -> Result<(), InternalWireError> {
        self.raw(&value.to_be_bytes())
    }

    fn hash(&mut self, value: [u8; 32]) -> Result<(), InternalWireError> {
        self.raw(&value)
    }

    fn string(&mut self, value: &str, maximum: usize) -> Result<(), InternalWireError> {
        if value.is_empty() || value.len() > maximum {
            return Err(InternalWireError::InvalidFrame);
        }
        let length = u16::try_from(value.len()).map_err(|_| InternalWireError::InvalidFrame)?;
        self.raw(&length.to_be_bytes())?;
        self.raw(value.as_bytes())
    }
}

#[cfg(feature = "experimental-repair-store")]
struct ClosedFrameReader<'a> {
    bytes: &'a [u8],
    offset: usize,
}

#[cfg(feature = "experimental-repair-store")]
impl<'a> ClosedFrameReader<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, offset: 0 }
    }

    fn raw(&mut self, length: usize) -> Result<&'a [u8], InternalWireError> {
        let end = self
            .offset
            .checked_add(length)
            .filter(|end| *end <= self.bytes.len())
            .ok_or(InternalWireError::InvalidFrame)?;
        let value = &self.bytes[self.offset..end];
        self.offset = end;
        Ok(value)
    }

    fn u8(&mut self) -> Result<u8, InternalWireError> {
        self.raw(1)?
            .first()
            .copied()
            .ok_or(InternalWireError::InvalidFrame)
    }

    fn u64(&mut self) -> Result<u64, InternalWireError> {
        Ok(u64::from_be_bytes(
            self.raw(8)?
                .try_into()
                .map_err(|_| InternalWireError::InvalidFrame)?,
        ))
    }

    fn u32(&mut self) -> Result<u32, InternalWireError> {
        Ok(u32::from_be_bytes(
            self.raw(4)?
                .try_into()
                .map_err(|_| InternalWireError::InvalidFrame)?,
        ))
    }

    fn hash(&mut self) -> Result<[u8; 32], InternalWireError> {
        self.raw(32)?
            .try_into()
            .map_err(|_| InternalWireError::InvalidFrame)
    }

    fn string(&mut self, maximum: usize) -> Result<String, InternalWireError> {
        let length = usize::from(u16::from_be_bytes(
            self.raw(2)?
                .try_into()
                .map_err(|_| InternalWireError::InvalidFrame)?,
        ));
        if length == 0 || length > maximum {
            return Err(InternalWireError::InvalidFrame);
        }
        std::str::from_utf8(self.raw(length)?)
            .map(str::to_owned)
            .map_err(|_| InternalWireError::InvalidFrame)
    }

    fn remaining_is_zero(&self) -> bool {
        self.bytes[self.offset..].iter().all(|byte| *byte == 0)
    }
}

fn encode_identifier(value: &str, prefix: &[u8]) -> Result<[u8; 16], InternalWireError> {
    let bytes = value.as_bytes();
    if bytes.len() != prefix.len() + 36 || &bytes[..prefix.len()] != prefix {
        return Err(InternalWireError::InvalidFrame);
    }
    let mut output = [0_u8; 16];
    let mut nibble = 0_usize;
    for (index, byte) in bytes[prefix.len()..].iter().copied().enumerate() {
        if matches!(index, 8 | 13 | 18 | 23) {
            if byte != b'-' {
                return Err(InternalWireError::InvalidFrame);
            }
            continue;
        }
        let value = match byte {
            b'0'..=b'9' => byte - b'0',
            b'a'..=b'f' => byte - b'a' + 10,
            _ => return Err(InternalWireError::InvalidFrame),
        };
        if nibble & 1 == 0 {
            output[nibble / 2] = value << 4;
        } else {
            output[nibble / 2] |= value;
        }
        nibble += 1;
    }
    if nibble != 32 {
        return Err(InternalWireError::InvalidFrame);
    }
    Ok(output)
}

fn decode_identifier(prefix: &[u8], value: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    debug_assert_eq!(value.len(), 16);
    let mut bytes = vec![0_u8; prefix.len() + 36];
    bytes[..prefix.len()].copy_from_slice(prefix);
    let mut output = prefix.len();
    for (index, byte) in value.iter().copied().enumerate() {
        if matches!(index, 4 | 6 | 8 | 10) {
            bytes[output] = b'-';
            output += 1;
        }
        bytes[output] = HEX[usize::from(byte >> 4)];
        bytes[output + 1] = HEX[usize::from(byte & 0x0f)];
        output += 2;
    }
    String::from_utf8(bytes).expect("closed ASCII identifier")
}

fn encode_sha256(value: &[u8; 32]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut bytes = [0_u8; 64];
    for (index, byte) in value.iter().copied().enumerate() {
        bytes[index * 2] = HEX[usize::from(byte >> 4)];
        bytes[index * 2 + 1] = HEX[usize::from(byte & 0x0f)];
    }
    String::from_utf8(bytes.to_vec()).expect("closed lowercase SHA-256")
}

pub(super) fn decode_sha256(value: &Sha256) -> Result<[u8; 32], InternalWireError> {
    let bytes = value.as_str().as_bytes();
    if bytes.len() != 64 {
        return Err(InternalWireError::InvalidFrame);
    }
    let mut output = [0_u8; 32];
    for (index, pair) in bytes.chunks_exact(2).enumerate() {
        let decode = |byte| match byte {
            b'0'..=b'9' => Ok(byte - b'0'),
            b'a'..=b'f' => Ok(byte - b'a' + 10),
            _ => Err(InternalWireError::InvalidFrame),
        };
        output[index] = (decode(pair[0])? << 4) | decode(pair[1])?;
    }
    Ok(output)
}

pub(super) fn encode_report_records(
    reports: &[WorkerReportSummary],
) -> Result<Vec<u8>, InternalWireError> {
    if reports.len() > MAX_REPORTS_PER_RESPONSE {
        return Err(InternalWireError::InvalidFrame);
    }
    let mut output = vec![0_u8; reports.len() * APPLICATION_REPORT_RECORD_BYTES];
    let mut previous: Option<String> = None;
    for (index, report) in reports.iter().enumerate() {
        if !(2..=MAX_SIGNED_REPORT_ENVELOPE_BYTES).contains(&report.envelope_size)
            || previous
                .as_deref()
                .is_some_and(|value| value >= report.report_id.as_str())
        {
            return Err(InternalWireError::InvalidFrame);
        }
        previous = Some(report.report_id.as_str().to_owned());
        let offset = index * APPLICATION_REPORT_RECORD_BYTES;
        output[offset..offset + 16]
            .copy_from_slice(&encode_identifier(report.report_id.as_str(), b"RP-")?);
        output[offset + 16..offset + 24].copy_from_slice(&report.envelope_size.to_be_bytes());
        output[offset + 24..offset + 56].copy_from_slice(&report.envelope_sha256);
    }
    Ok(output)
}

pub(super) fn decode_report_records(
    bytes: &[u8],
    expected_count: u16,
) -> Result<Vec<ReportSummary>, InternalWireError> {
    if usize::from(expected_count) > MAX_REPORTS_PER_RESPONSE
        || bytes.len() != usize::from(expected_count) * APPLICATION_REPORT_RECORD_BYTES
    {
        return Err(InternalWireError::InvalidFrame);
    }
    let mut output = Vec::with_capacity(usize::from(expected_count));
    let mut previous: Option<String> = None;
    for record in bytes.chunks_exact(APPLICATION_REPORT_RECORD_BYTES) {
        if record[56..].iter().any(|byte| *byte != 0) {
            return Err(InternalWireError::InvalidFrame);
        }
        let report_id = ReportId::parse(&decode_identifier(b"RP-", &record[..16]))
            .map_err(|_| InternalWireError::InvalidFrame)?;
        if previous
            .as_deref()
            .is_some_and(|value| value >= report_id.as_str())
        {
            return Err(InternalWireError::InvalidFrame);
        }
        let envelope_size = u64::from_be_bytes(
            record[16..24]
                .try_into()
                .map_err(|_| InternalWireError::InvalidFrame)?,
        );
        let envelope_sha256: [u8; 32] = record[24..56]
            .try_into()
            .map_err(|_| InternalWireError::InvalidFrame)?;
        let summary = WorkerReportSummary {
            report_id,
            envelope_size,
            envelope_sha256,
        };
        previous = Some(summary.report_id.as_str().to_owned());
        output.push(summary.to_protocol()?);
    }
    Ok(output)
}

fn encode_audit_event(value: AuditEventType) -> u8 {
    match value {
        AuditEventType::AgentSessionStart => 1,
        AuditEventType::AgentDiagnosisComplete => 2,
        AuditEventType::AgentSessionEnd => 3,
    }
}

fn decode_audit_event(value: u8) -> Result<AuditEventType, InternalWireError> {
    match value {
        1 => Ok(AuditEventType::AgentSessionStart),
        2 => Ok(AuditEventType::AgentDiagnosisComplete),
        3 => Ok(AuditEventType::AgentSessionEnd),
        _ => Err(InternalWireError::InvalidFrame),
    }
}

fn encode_audit_outcome(value: AuditOutcome) -> u8 {
    match value {
        AuditOutcome::Succeeded => 1,
        AuditOutcome::Rejected => 2,
        AuditOutcome::Failed => 3,
    }
}

fn decode_audit_outcome(value: u8) -> Result<AuditOutcome, InternalWireError> {
    match value {
        1 => Ok(AuditOutcome::Succeeded),
        2 => Ok(AuditOutcome::Rejected),
        3 => Ok(AuditOutcome::Failed),
        _ => Err(InternalWireError::InvalidFrame),
    }
}

fn encode_error_token(value: ErrorToken) -> u8 {
    match value {
        ErrorToken::Absent => 1,
        ErrorToken::Unprovisioned => 2,
        ErrorToken::Locked => 3,
        ErrorToken::BadPassphrase => 4,
        ErrorToken::MediaChanged => 5,
        ErrorToken::ProfileMismatch => 6,
        ErrorToken::StaleState => 7,
        ErrorToken::FdRequired => 8,
        ErrorToken::FdForbidden => 9,
        ErrorToken::NotAuthorized => 10,
        ErrorToken::RateLimited => 11,
        ErrorToken::Busy => 12,
        ErrorToken::ProviderUnconfigured => 13,
        ErrorToken::ReportTooLarge => 14,
        ErrorToken::IoFailed => 15,
        ErrorToken::RebootRequired => 16,
    }
}

fn decode_error_token(value: u8) -> Result<ErrorToken, InternalWireError> {
    match value {
        1 => Ok(ErrorToken::Absent),
        2 => Ok(ErrorToken::Unprovisioned),
        3 => Ok(ErrorToken::Locked),
        4 => Ok(ErrorToken::BadPassphrase),
        5 => Ok(ErrorToken::MediaChanged),
        6 => Ok(ErrorToken::ProfileMismatch),
        7 => Ok(ErrorToken::StaleState),
        8 => Ok(ErrorToken::FdRequired),
        9 => Ok(ErrorToken::FdForbidden),
        10 => Ok(ErrorToken::NotAuthorized),
        11 => Ok(ErrorToken::RateLimited),
        12 => Ok(ErrorToken::Busy),
        13 => Ok(ErrorToken::ProviderUnconfigured),
        14 => Ok(ErrorToken::ReportTooLarge),
        15 => Ok(ErrorToken::IoFailed),
        16 => Ok(ErrorToken::RebootRequired),
        _ => Err(InternalWireError::InvalidFrame),
    }
}

fn valid_passphrase_size(size: u16) -> bool {
    let size = u64::from(size);
    (MIN_PASSPHRASE_BYTES..=MAX_PASSPHRASE_BYTES).contains(&size)
}

fn valid_openai_key_size(size: u16) -> bool {
    (1..=MAX_OPENAI_KEY_BYTES).contains(&u64::from(size))
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum WorkerResultCode {
    BootstrapReady,
    ProbeAbsent,
    ProbeUnprovisioned,
    ProbeLocked,
    ProbeProfileMismatch,
    ProbeClassifierUnavailable,
    ProbeIoFailed,
    UnlockSucceeded,
    LockSucceeded,
    ShutdownSucceeded,
    Absent,
    Unprovisioned,
    ProfileMismatch,
    BadPassphrase,
    MediaChanged,
    IoFailed,
    CleanupFailed,
    TimedOut,
    Busy,
    InvalidRequest,
    AttestAbsent,
    AttestUnprovisioned,
    AttestLocked,
    AttestProfileMismatch,
    ProviderStatusUnconfigured,
    ProviderStatusConfigured,
    ProviderConfigureSucceeded,
    ProviderLogoutSucceeded,
    ProviderMutationAborted,
    ProviderStateAmbiguous,
    ProviderBorrowReady,
    ProviderBorrowUnconfigured,
    #[cfg(feature = "experimental-codex-home-lease")]
    ProviderCodexHomeReady,
    #[cfg(feature = "experimental-codex-home-lease")]
    ProviderCodexHomeUnconfigured,
    UnlockIoProbe,
    UnlockIoProbeClassifier,
    UnlockIoMapperName,
    UnlockIoUnsupportedPlatform,
    UnlockIoPrivilegeRequired,
    UnlockIoInvalidMapperName,
    UnlockIoClassifierUnavailable,
    UnlockIoPassphraseUnavailable,
    UnlockIoUnsupportedFilesystem,
    UnlockIoUnsafeMountRoot,
    UnlockIoMountFailed,
    UnlockIoMountVerificationFailed,
    UnlockIoSecureStateUnavailable,
    UnlockIoToolUnavailable,
    UnlockIoApplicationStore,
    UnlockIoDeviceId,
    ApplicationAuditAppended,
    ApplicationReportPersisted,
    ApplicationReportListReady,
    ApplicationReportReady,
    ApplicationReportNotFound,
    ApplicationInvalidRequest,
    ApplicationStaleSequence,
    ApplicationReportTooLarge,
    ApplicationMutationAborted,
    ApplicationStateAmbiguous,
    #[cfg(feature = "experimental-repair-store")]
    RepairBackupReserved,
    #[cfg(feature = "experimental-repair-store")]
    RepairBackupDurable,
    #[cfg(feature = "experimental-repair-store")]
    RepairBackupStatusReady,
    #[cfg(feature = "experimental-repair-store")]
    RepairBackupReady,
    #[cfg(feature = "experimental-repair-store")]
    RepairBackupNotFound,
    #[cfg(feature = "experimental-repair-store")]
    RepairInvalidRequest,
    #[cfg(feature = "experimental-repair-store")]
    RepairConflict,
    #[cfg(feature = "experimental-repair-store")]
    RepairReconciliationRequired,
    #[cfg(feature = "experimental-repair-store")]
    RepairStorageUnavailable,
    #[cfg(feature = "experimental-repair-store")]
    RepairBackupCancelled,
    #[cfg(feature = "experimental-repair-store")]
    RepairBackupRetired,
    #[cfg(feature = "experimental-repair-store")]
    RepairTransactionStatusReady,
    #[cfg(feature = "experimental-repair-store")]
    RepairTransactionResolved,
    #[cfg(feature = "experimental-repair-store")]
    RepairVaultLiveIdentityReady,
}

impl WorkerResultCode {
    fn encode(self) -> u8 {
        match self {
            Self::BootstrapReady => 1,
            Self::ProbeAbsent => 2,
            Self::ProbeUnprovisioned => 3,
            Self::ProbeLocked => 4,
            Self::ProbeProfileMismatch => 5,
            Self::ProbeClassifierUnavailable => 6,
            Self::ProbeIoFailed => 7,
            Self::UnlockSucceeded => 8,
            Self::LockSucceeded => 9,
            Self::ShutdownSucceeded => 10,
            Self::Absent => 11,
            Self::Unprovisioned => 12,
            Self::ProfileMismatch => 13,
            Self::BadPassphrase => 14,
            Self::MediaChanged => 15,
            Self::IoFailed => 16,
            Self::CleanupFailed => 17,
            Self::TimedOut => 18,
            Self::Busy => 19,
            Self::InvalidRequest => 20,
            Self::AttestAbsent => 21,
            Self::AttestUnprovisioned => 22,
            Self::AttestLocked => 23,
            Self::AttestProfileMismatch => 24,
            Self::ProviderStatusUnconfigured => 25,
            Self::ProviderStatusConfigured => 26,
            Self::ProviderConfigureSucceeded => 27,
            Self::ProviderLogoutSucceeded => 28,
            Self::ProviderMutationAborted => 29,
            Self::ProviderStateAmbiguous => 30,
            Self::ProviderBorrowReady => 31,
            Self::ProviderBorrowUnconfigured => 32,
            #[cfg(feature = "experimental-codex-home-lease")]
            Self::ProviderCodexHomeReady => 33,
            #[cfg(feature = "experimental-codex-home-lease")]
            Self::ProviderCodexHomeUnconfigured => 34,
            Self::UnlockIoProbe => 35,
            Self::UnlockIoProbeClassifier => 36,
            Self::UnlockIoMapperName => 37,
            Self::UnlockIoUnsupportedPlatform => 38,
            Self::UnlockIoPrivilegeRequired => 39,
            Self::UnlockIoInvalidMapperName => 40,
            Self::UnlockIoClassifierUnavailable => 41,
            Self::UnlockIoPassphraseUnavailable => 42,
            Self::UnlockIoUnsupportedFilesystem => 43,
            Self::UnlockIoUnsafeMountRoot => 44,
            Self::UnlockIoMountFailed => 45,
            Self::UnlockIoMountVerificationFailed => 46,
            Self::UnlockIoSecureStateUnavailable => 47,
            Self::UnlockIoToolUnavailable => 48,
            Self::UnlockIoApplicationStore => 49,
            Self::UnlockIoDeviceId => 50,
            Self::ApplicationAuditAppended => 51,
            Self::ApplicationReportPersisted => 52,
            Self::ApplicationReportListReady => 53,
            Self::ApplicationReportReady => 54,
            Self::ApplicationReportNotFound => 55,
            Self::ApplicationInvalidRequest => 56,
            Self::ApplicationStaleSequence => 57,
            Self::ApplicationReportTooLarge => 58,
            Self::ApplicationMutationAborted => 59,
            Self::ApplicationStateAmbiguous => 60,
            #[cfg(feature = "experimental-repair-store")]
            Self::RepairBackupReserved => 61,
            #[cfg(feature = "experimental-repair-store")]
            Self::RepairBackupDurable => 62,
            #[cfg(feature = "experimental-repair-store")]
            Self::RepairBackupStatusReady => 63,
            #[cfg(feature = "experimental-repair-store")]
            Self::RepairBackupReady => 64,
            #[cfg(feature = "experimental-repair-store")]
            Self::RepairBackupNotFound => 65,
            #[cfg(feature = "experimental-repair-store")]
            Self::RepairInvalidRequest => 66,
            #[cfg(feature = "experimental-repair-store")]
            Self::RepairConflict => 67,
            #[cfg(feature = "experimental-repair-store")]
            Self::RepairReconciliationRequired => 68,
            #[cfg(feature = "experimental-repair-store")]
            Self::RepairStorageUnavailable => 69,
            #[cfg(feature = "experimental-repair-store")]
            Self::RepairBackupCancelled => 70,
            #[cfg(feature = "experimental-repair-store")]
            Self::RepairBackupRetired => 71,
            #[cfg(feature = "experimental-repair-store")]
            Self::RepairTransactionStatusReady => 72,
            #[cfg(feature = "experimental-repair-store")]
            Self::RepairTransactionResolved => 73,
            #[cfg(feature = "experimental-repair-store")]
            Self::RepairVaultLiveIdentityReady => 74,
        }
    }

    fn decode(value: u8) -> Result<Self, InternalWireError> {
        match value {
            1 => Ok(Self::BootstrapReady),
            2 => Ok(Self::ProbeAbsent),
            3 => Ok(Self::ProbeUnprovisioned),
            4 => Ok(Self::ProbeLocked),
            5 => Ok(Self::ProbeProfileMismatch),
            6 => Ok(Self::ProbeClassifierUnavailable),
            7 => Ok(Self::ProbeIoFailed),
            8 => Ok(Self::UnlockSucceeded),
            9 => Ok(Self::LockSucceeded),
            10 => Ok(Self::ShutdownSucceeded),
            11 => Ok(Self::Absent),
            12 => Ok(Self::Unprovisioned),
            13 => Ok(Self::ProfileMismatch),
            14 => Ok(Self::BadPassphrase),
            15 => Ok(Self::MediaChanged),
            16 => Ok(Self::IoFailed),
            17 => Ok(Self::CleanupFailed),
            18 => Ok(Self::TimedOut),
            19 => Ok(Self::Busy),
            20 => Ok(Self::InvalidRequest),
            21 => Ok(Self::AttestAbsent),
            22 => Ok(Self::AttestUnprovisioned),
            23 => Ok(Self::AttestLocked),
            24 => Ok(Self::AttestProfileMismatch),
            25 => Ok(Self::ProviderStatusUnconfigured),
            26 => Ok(Self::ProviderStatusConfigured),
            27 => Ok(Self::ProviderConfigureSucceeded),
            28 => Ok(Self::ProviderLogoutSucceeded),
            29 => Ok(Self::ProviderMutationAborted),
            30 => Ok(Self::ProviderStateAmbiguous),
            31 => Ok(Self::ProviderBorrowReady),
            32 => Ok(Self::ProviderBorrowUnconfigured),
            #[cfg(feature = "experimental-codex-home-lease")]
            33 => Ok(Self::ProviderCodexHomeReady),
            #[cfg(feature = "experimental-codex-home-lease")]
            34 => Ok(Self::ProviderCodexHomeUnconfigured),
            35 => Ok(Self::UnlockIoProbe),
            36 => Ok(Self::UnlockIoProbeClassifier),
            37 => Ok(Self::UnlockIoMapperName),
            38 => Ok(Self::UnlockIoUnsupportedPlatform),
            39 => Ok(Self::UnlockIoPrivilegeRequired),
            40 => Ok(Self::UnlockIoInvalidMapperName),
            41 => Ok(Self::UnlockIoClassifierUnavailable),
            42 => Ok(Self::UnlockIoPassphraseUnavailable),
            43 => Ok(Self::UnlockIoUnsupportedFilesystem),
            44 => Ok(Self::UnlockIoUnsafeMountRoot),
            45 => Ok(Self::UnlockIoMountFailed),
            46 => Ok(Self::UnlockIoMountVerificationFailed),
            47 => Ok(Self::UnlockIoSecureStateUnavailable),
            48 => Ok(Self::UnlockIoToolUnavailable),
            49 => Ok(Self::UnlockIoApplicationStore),
            50 => Ok(Self::UnlockIoDeviceId),
            51 => Ok(Self::ApplicationAuditAppended),
            52 => Ok(Self::ApplicationReportPersisted),
            53 => Ok(Self::ApplicationReportListReady),
            54 => Ok(Self::ApplicationReportReady),
            55 => Ok(Self::ApplicationReportNotFound),
            56 => Ok(Self::ApplicationInvalidRequest),
            57 => Ok(Self::ApplicationStaleSequence),
            58 => Ok(Self::ApplicationReportTooLarge),
            59 => Ok(Self::ApplicationMutationAborted),
            60 => Ok(Self::ApplicationStateAmbiguous),
            #[cfg(feature = "experimental-repair-store")]
            61 => Ok(Self::RepairBackupReserved),
            #[cfg(feature = "experimental-repair-store")]
            62 => Ok(Self::RepairBackupDurable),
            #[cfg(feature = "experimental-repair-store")]
            63 => Ok(Self::RepairBackupStatusReady),
            #[cfg(feature = "experimental-repair-store")]
            64 => Ok(Self::RepairBackupReady),
            #[cfg(feature = "experimental-repair-store")]
            65 => Ok(Self::RepairBackupNotFound),
            #[cfg(feature = "experimental-repair-store")]
            66 => Ok(Self::RepairInvalidRequest),
            #[cfg(feature = "experimental-repair-store")]
            67 => Ok(Self::RepairConflict),
            #[cfg(feature = "experimental-repair-store")]
            68 => Ok(Self::RepairReconciliationRequired),
            #[cfg(feature = "experimental-repair-store")]
            69 => Ok(Self::RepairStorageUnavailable),
            #[cfg(feature = "experimental-repair-store")]
            70 => Ok(Self::RepairBackupCancelled),
            #[cfg(feature = "experimental-repair-store")]
            71 => Ok(Self::RepairBackupRetired),
            #[cfg(feature = "experimental-repair-store")]
            72 => Ok(Self::RepairTransactionStatusReady),
            #[cfg(feature = "experimental-repair-store")]
            73 => Ok(Self::RepairTransactionResolved),
            #[cfg(feature = "experimental-repair-store")]
            74 => Ok(Self::RepairVaultLiveIdentityReady),
            _ => Err(InternalWireError::InvalidFrame),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct WorkerReportSummary {
    pub(super) report_id: ReportId,
    pub(super) envelope_size: u64,
    pub(super) envelope_sha256: [u8; 32],
}

impl WorkerReportSummary {
    pub(super) fn from_store(
        value: &crate::RescueReportSummary,
    ) -> Result<Self, InternalWireError> {
        let report_id =
            ReportId::parse(value.report_id()).map_err(|_| InternalWireError::InvalidFrame)?;
        if !(2..=MAX_SIGNED_REPORT_ENVELOPE_BYTES).contains(&value.envelope_size()) {
            return Err(InternalWireError::InvalidFrame);
        }
        Ok(Self {
            report_id,
            envelope_size: value.envelope_size(),
            envelope_sha256: *value.envelope_sha256(),
        })
    }

    pub(super) fn to_protocol(&self) -> Result<ReportSummary, InternalWireError> {
        ReportSummary::new(
            self.report_id.clone(),
            self.envelope_size,
            Sha256::parse(&encode_sha256(&self.envelope_sha256))
                .map_err(|_| InternalWireError::InvalidFrame)?,
        )
        .map_err(|_| InternalWireError::InvalidFrame)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct WorkerResponse {
    pub(super) request_id: u64,
    pub(super) code: WorkerResultCode,
    pub(super) device_id: Option<String>,
    pub(super) output_size: Option<u16>,
    pub(super) audit_sequence: Option<u64>,
    pub(super) report: Option<WorkerReportSummary>,
    pub(super) application_output_size: Option<u64>,
    pub(super) application_record_count: Option<u16>,
    #[cfg(feature = "experimental-repair-store")]
    pub(super) repair_status: Option<Box<WorkerRepairStatus>>,
    #[cfg(feature = "experimental-repair-store")]
    pub(super) repair_released_bytes: Option<u64>,
    #[cfg(feature = "experimental-repair-store")]
    pub(super) repair_transaction_status: Option<Box<RepairTransactionStatusPayload>>,
    #[cfg(feature = "experimental-repair-store")]
    pub(super) repair_vault_live_identity: Option<WorkerRepairVaultLiveIdentity>,
}

impl WorkerResponse {
    pub(super) fn new(request_id: u64, code: WorkerResultCode) -> Self {
        Self {
            request_id,
            code,
            device_id: None,
            output_size: None,
            audit_sequence: None,
            report: None,
            application_output_size: None,
            application_record_count: None,
            #[cfg(feature = "experimental-repair-store")]
            repair_status: None,
            #[cfg(feature = "experimental-repair-store")]
            repair_released_bytes: None,
            #[cfg(feature = "experimental-repair-store")]
            repair_transaction_status: None,
            #[cfg(feature = "experimental-repair-store")]
            repair_vault_live_identity: None,
        }
    }

    pub(super) fn unlocked(request_id: u64, device_id: String) -> Self {
        Self {
            request_id,
            code: WorkerResultCode::UnlockSucceeded,
            device_id: Some(device_id),
            output_size: None,
            audit_sequence: None,
            report: None,
            application_output_size: None,
            application_record_count: None,
            #[cfg(feature = "experimental-repair-store")]
            repair_status: None,
            #[cfg(feature = "experimental-repair-store")]
            repair_released_bytes: None,
            #[cfg(feature = "experimental-repair-store")]
            repair_transaction_status: None,
            #[cfg(feature = "experimental-repair-store")]
            repair_vault_live_identity: None,
        }
    }

    pub(super) fn provider_borrow_ready(request_id: u64, output_size: u16) -> Self {
        Self {
            request_id,
            code: WorkerResultCode::ProviderBorrowReady,
            device_id: None,
            output_size: Some(output_size),
            audit_sequence: None,
            report: None,
            application_output_size: None,
            application_record_count: None,
            #[cfg(feature = "experimental-repair-store")]
            repair_status: None,
            #[cfg(feature = "experimental-repair-store")]
            repair_released_bytes: None,
            #[cfg(feature = "experimental-repair-store")]
            repair_transaction_status: None,
            #[cfg(feature = "experimental-repair-store")]
            repair_vault_live_identity: None,
        }
    }

    pub(super) fn audit_appended(request_id: u64, sequence: u64) -> Self {
        let mut response = Self::new(request_id, WorkerResultCode::ApplicationAuditAppended);
        response.audit_sequence = Some(sequence);
        response
    }

    pub(super) fn report_persisted(request_id: u64, report: WorkerReportSummary) -> Self {
        let mut response = Self::new(request_id, WorkerResultCode::ApplicationReportPersisted);
        response.report = Some(report);
        response
    }

    pub(super) fn report_list_ready(request_id: u64, output_size: u64, count: u16) -> Self {
        let mut response = Self::new(request_id, WorkerResultCode::ApplicationReportListReady);
        response.application_output_size = Some(output_size);
        response.application_record_count = Some(count);
        response
    }

    pub(super) fn report_ready(request_id: u64, report: WorkerReportSummary) -> Self {
        let mut response = Self::new(request_id, WorkerResultCode::ApplicationReportReady);
        response.application_output_size = Some(report.envelope_size);
        response.report = Some(report);
        response
    }

    #[cfg(feature = "experimental-repair-store")]
    pub(super) fn repair(
        request_id: u64,
        code: WorkerResultCode,
        status: WorkerRepairStatus,
    ) -> Self {
        let mut response = Self::new(request_id, code);
        response.repair_status = Some(Box::new(status));
        response
    }

    #[cfg(feature = "experimental-repair-store")]
    pub(super) fn repair_released(
        request_id: u64,
        code: WorkerResultCode,
        released_bytes: u64,
    ) -> Self {
        let mut response = Self::new(request_id, code);
        response.repair_released_bytes = Some(released_bytes);
        response
    }

    #[cfg(feature = "experimental-repair-store")]
    pub(super) fn repair_transaction_status(
        request_id: u64,
        status: Option<RepairTransactionStatusPayload>,
    ) -> Self {
        let mut response = Self::new(request_id, WorkerResultCode::RepairTransactionStatusReady);
        response.repair_transaction_status = status.map(Box::new);
        response
    }

    #[cfg(feature = "experimental-repair-store")]
    pub(super) fn repair_transaction_resolved(
        request_id: u64,
        status: RepairTransactionStatusPayload,
    ) -> Self {
        let mut response = Self::new(request_id, WorkerResultCode::RepairTransactionResolved);
        response.repair_transaction_status = Some(Box::new(status));
        response
    }

    #[cfg(feature = "experimental-repair-store")]
    pub(super) fn repair_vault_live_identity(
        request_id: u64,
        identity: WorkerRepairVaultLiveIdentity,
    ) -> Self {
        let mut response = Self::new(request_id, WorkerResultCode::RepairVaultLiveIdentityReady);
        response.repair_vault_live_identity = Some(identity);
        response
    }

    #[cfg(feature = "experimental-codex-home-lease")]
    pub(super) fn provider_codex_home_ready(request_id: u64) -> Self {
        Self::new(request_id, WorkerResultCode::ProviderCodexHomeReady)
    }

    fn encode(&self) -> Result<[u8; RESPONSE_BYTES], InternalWireError> {
        let device_metadata = self.code == WorkerResultCode::UnlockSucceeded;
        let provider_metadata = self.code == WorkerResultCode::ProviderBorrowReady;
        let audit_metadata = self.code == WorkerResultCode::ApplicationAuditAppended;
        let persisted_metadata = self.code == WorkerResultCode::ApplicationReportPersisted;
        let list_metadata = self.code == WorkerResultCode::ApplicationReportListReady;
        let report_metadata = self.code == WorkerResultCode::ApplicationReportReady;
        #[cfg(feature = "experimental-repair-store")]
        let repair_metadata = matches!(
            self.code,
            WorkerResultCode::RepairBackupReserved
                | WorkerResultCode::RepairBackupDurable
                | WorkerResultCode::RepairBackupStatusReady
                | WorkerResultCode::RepairBackupReady
        );
        #[cfg(feature = "experimental-repair-store")]
        let repair_release_metadata = matches!(
            self.code,
            WorkerResultCode::RepairBackupCancelled | WorkerResultCode::RepairBackupRetired
        );
        #[cfg(feature = "experimental-repair-store")]
        let repair_transaction_metadata = matches!(
            self.code,
            WorkerResultCode::RepairTransactionStatusReady
                | WorkerResultCode::RepairTransactionResolved
        );
        #[cfg(feature = "experimental-repair-store")]
        let repair_vault_live_identity_metadata =
            self.code == WorkerResultCode::RepairVaultLiveIdentityReady;
        #[cfg(feature = "experimental-repair-store")]
        if repair_metadata != self.repair_status.is_some()
            || repair_release_metadata != self.repair_released_bytes.is_some()
            || (!repair_transaction_metadata && self.repair_transaction_status.is_some())
            || repair_vault_live_identity_metadata != self.repair_vault_live_identity.is_some()
            || (self.code == WorkerResultCode::RepairTransactionResolved
                && self.repair_transaction_status.is_none())
            || self
                .repair_released_bytes
                .is_some_and(|bytes| !(1..=MAX_REPAIR_BACKUP_BYTES).contains(&bytes))
            || self.repair_status.as_ref().is_some_and(|status| {
                status.validate().is_err()
                    || matches!(self.code, WorkerResultCode::RepairBackupReserved)
                        && status.state != WorkerRepairState::Reserved
                    || matches!(
                        self.code,
                        WorkerResultCode::RepairBackupDurable | WorkerResultCode::RepairBackupReady
                    ) && status.state != WorkerRepairState::Durable
            })
            || self
                .repair_transaction_status
                .as_deref()
                .is_some_and(|status| validate_repair_transaction_status(status).is_err())
            || self
                .repair_vault_live_identity
                .as_ref()
                .is_some_and(|identity| identity.validate().is_err())
        {
            return Err(InternalWireError::InvalidFrame);
        }
        if self.request_id == 0
            || device_metadata != self.device_id.is_some()
            || provider_metadata != self.output_size.is_some()
            || audit_metadata != self.audit_sequence.is_some()
            || (persisted_metadata || report_metadata) != self.report.is_some()
            || (list_metadata || report_metadata) != self.application_output_size.is_some()
            || list_metadata != self.application_record_count.is_some()
            || self
                .output_size
                .is_some_and(|size| !valid_openai_key_size(size))
            || self
                .audit_sequence
                .is_some_and(|sequence| !(1..=MAX_AUDIT_SEQUENCE).contains(&sequence))
            || self
                .application_record_count
                .is_some_and(|count| usize::from(count) > MAX_REPORTS_PER_RESPONSE)
            || self.application_output_size.is_some_and(|size| {
                if list_metadata {
                    size > MAX_APPLICATION_REPORT_LIST_BYTES as u64
                } else {
                    !(2..=MAX_SIGNED_REPORT_ENVELOPE_BYTES).contains(&size)
                }
            })
            || self.report.as_ref().is_some_and(|report| {
                !(2..=MAX_SIGNED_REPORT_ENVELOPE_BYTES).contains(&report.envelope_size)
                    || (report_metadata
                        && self.application_output_size != Some(report.envelope_size))
            })
            || (list_metadata
                && self.application_output_size
                    != self
                        .application_record_count
                        .map(|count| u64::from(count) * APPLICATION_REPORT_RECORD_BYTES as u64))
        {
            return Err(InternalWireError::InvalidFrame);
        }
        let device = self.device_id.as_deref().unwrap_or_default().as_bytes();
        if (!device.is_empty() && !valid_device_id(device)) || device.len() > MAX_DEVICE_ID_BYTES {
            return Err(InternalWireError::InvalidFrame);
        }
        let mut bytes = [0_u8; RESPONSE_BYTES];
        bytes[..8].copy_from_slice(RESPONSE_MAGIC);
        bytes[8] = self.code.encode();
        bytes[9] = u8::try_from(device.len()).map_err(|_| InternalWireError::InvalidFrame)?;
        bytes[10..12].copy_from_slice(&self.output_size.unwrap_or_default().to_be_bytes());
        bytes[12..20].copy_from_slice(&self.request_id.to_be_bytes());
        let value = self
            .audit_sequence
            .or(self.application_output_size)
            .or({
                #[cfg(feature = "experimental-repair-store")]
                {
                    self.repair_released_bytes
                }
                #[cfg(not(feature = "experimental-repair-store"))]
                {
                    None
                }
            })
            .or_else(|| self.report.as_ref().map(|report| report.envelope_size))
            .unwrap_or_default();
        bytes[RESPONSE_VALUE_OFFSET..RESPONSE_VALUE_OFFSET + 8]
            .copy_from_slice(&value.to_be_bytes());
        bytes[RESPONSE_COUNT_OFFSET..RESPONSE_COUNT_OFFSET + 2].copy_from_slice(
            &self
                .application_record_count
                .unwrap_or_default()
                .to_be_bytes(),
        );
        if let Some(report) = &self.report {
            bytes[RESPONSE_IDENTIFIER_OFFSET..RESPONSE_IDENTIFIER_OFFSET + 16]
                .copy_from_slice(&encode_identifier(report.report_id.as_str(), b"RP-")?);
            bytes[RESPONSE_SHA256_OFFSET..RESPONSE_SHA256_OFFSET + 32]
                .copy_from_slice(&report.envelope_sha256);
        }
        bytes[DEVICE_ID_OFFSET..DEVICE_ID_OFFSET + device.len()].copy_from_slice(device);
        #[cfg(feature = "experimental-repair-store")]
        if let Some(status) = self.repair_status.as_ref() {
            let mut writer = ClosedFrameWriter::new(&mut bytes[REPAIR_PAYLOAD_OFFSET..]);
            encode_repair_status(&mut writer, status)?;
        } else if repair_transaction_metadata {
            let mut writer = ClosedFrameWriter::new(&mut bytes[REPAIR_PAYLOAD_OFFSET..]);
            match self.repair_transaction_status.as_deref() {
                Some(status) => {
                    writer.u8(1)?;
                    encode_repair_transaction_status(&mut writer, status)?;
                }
                None => writer.u8(0)?,
            }
        } else if let Some(identity) = self.repair_vault_live_identity.as_ref() {
            let mut writer = ClosedFrameWriter::new(&mut bytes[REPAIR_PAYLOAD_OFFSET..]);
            writer.string(&identity.vault_id, MAX_REPAIR_ID_BYTES)?;
            writer.hash(identity.vault_identity_fingerprint)?;
            writer.hash(identity.physical_parent_fingerprint)?;
        }
        Ok(bytes)
    }

    fn decode(bytes: &[u8]) -> Result<Self, InternalWireError> {
        if bytes.len() != RESPONSE_BYTES || &bytes[..8] != RESPONSE_MAGIC {
            return Err(InternalWireError::InvalidFrame);
        }
        let code = WorkerResultCode::decode(bytes[8])?;
        #[cfg(feature = "experimental-repair-store")]
        let repair_metadata = matches!(
            code,
            WorkerResultCode::RepairBackupReserved
                | WorkerResultCode::RepairBackupDurable
                | WorkerResultCode::RepairBackupStatusReady
                | WorkerResultCode::RepairBackupReady
        );
        #[cfg(feature = "experimental-repair-store")]
        let repair_release_metadata = matches!(
            code,
            WorkerResultCode::RepairBackupCancelled | WorkerResultCode::RepairBackupRetired
        );
        #[cfg(feature = "experimental-repair-store")]
        let repair_transaction_metadata = matches!(
            code,
            WorkerResultCode::RepairTransactionStatusReady
                | WorkerResultCode::RepairTransactionResolved
        );
        #[cfg(feature = "experimental-repair-store")]
        let repair_vault_live_identity_metadata =
            code == WorkerResultCode::RepairVaultLiveIdentityReady;
        #[cfg(feature = "experimental-repair-store")]
        let repair_wire =
            repair_metadata || repair_transaction_metadata || repair_vault_live_identity_metadata;
        #[cfg(not(feature = "experimental-repair-store"))]
        let repair_wire = false;
        let device_len = usize::from(bytes[9]);
        let output_size = u16::from_be_bytes(
            bytes[10..12]
                .try_into()
                .map_err(|_| InternalWireError::InvalidFrame)?,
        );
        if device_len > MAX_DEVICE_ID_BYTES
            || (!repair_wire
                && bytes[DEVICE_ID_OFFSET + device_len..DEVICE_ID_OFFSET + MAX_DEVICE_ID_BYTES]
                    .iter()
                    .any(|byte| *byte != 0))
        {
            return Err(InternalWireError::InvalidFrame);
        }
        let request_id = u64::from_be_bytes(
            bytes[12..20]
                .try_into()
                .map_err(|_| InternalWireError::InvalidFrame)?,
        );
        let device_id = if device_len == 0 {
            None
        } else {
            let device = &bytes[DEVICE_ID_OFFSET..DEVICE_ID_OFFSET + device_len];
            if !valid_device_id(device) {
                return Err(InternalWireError::InvalidFrame);
            }
            Some(
                std::str::from_utf8(device)
                    .map_err(|_| InternalWireError::InvalidFrame)?
                    .to_owned(),
            )
        };
        let value = u64::from_be_bytes(
            bytes[RESPONSE_VALUE_OFFSET..RESPONSE_VALUE_OFFSET + 8]
                .try_into()
                .map_err(|_| InternalWireError::InvalidFrame)?,
        );
        let count = u16::from_be_bytes(
            bytes[RESPONSE_COUNT_OFFSET..RESPONSE_COUNT_OFFSET + 2]
                .try_into()
                .map_err(|_| InternalWireError::InvalidFrame)?,
        );
        let report = if matches!(
            code,
            WorkerResultCode::ApplicationReportPersisted | WorkerResultCode::ApplicationReportReady
        ) {
            Some(WorkerReportSummary {
                report_id: ReportId::parse(&decode_identifier(
                    b"RP-",
                    &bytes[RESPONSE_IDENTIFIER_OFFSET..RESPONSE_IDENTIFIER_OFFSET + 16],
                ))
                .map_err(|_| InternalWireError::InvalidFrame)?,
                envelope_size: value,
                envelope_sha256: bytes[RESPONSE_SHA256_OFFSET..RESPONSE_SHA256_OFFSET + 32]
                    .try_into()
                    .map_err(|_| InternalWireError::InvalidFrame)?,
            })
        } else {
            None
        };
        #[cfg(feature = "experimental-repair-store")]
        let repair_status = if repair_metadata {
            let mut reader = ClosedFrameReader::new(
                bytes
                    .get(REPAIR_PAYLOAD_OFFSET..)
                    .ok_or(InternalWireError::InvalidFrame)?,
            );
            let status = decode_repair_status(&mut reader)?;
            if !reader.remaining_is_zero() {
                return Err(InternalWireError::InvalidFrame);
            }
            Some(Box::new(status))
        } else {
            None
        };
        #[cfg(feature = "experimental-repair-store")]
        let repair_transaction_status = if repair_transaction_metadata {
            let mut reader = ClosedFrameReader::new(
                bytes
                    .get(REPAIR_PAYLOAD_OFFSET..)
                    .ok_or(InternalWireError::InvalidFrame)?,
            );
            let status = match reader.u8()? {
                0 => None,
                1 => Some(Box::new(decode_repair_transaction_status(&mut reader)?)),
                _ => return Err(InternalWireError::InvalidFrame),
            };
            if !reader.remaining_is_zero() {
                return Err(InternalWireError::InvalidFrame);
            }
            status
        } else {
            None
        };
        #[cfg(feature = "experimental-repair-store")]
        let repair_vault_live_identity = if repair_vault_live_identity_metadata {
            let mut reader = ClosedFrameReader::new(
                bytes
                    .get(REPAIR_PAYLOAD_OFFSET..)
                    .ok_or(InternalWireError::InvalidFrame)?,
            );
            let identity = WorkerRepairVaultLiveIdentity {
                vault_id: reader.string(MAX_REPAIR_ID_BYTES)?,
                vault_identity_fingerprint: reader.hash()?,
                physical_parent_fingerprint: reader.hash()?,
            };
            identity.validate()?;
            if !reader.remaining_is_zero() {
                return Err(InternalWireError::InvalidFrame);
            }
            Some(identity)
        } else {
            None
        };
        let response = Self {
            request_id,
            code,
            device_id,
            output_size: (output_size != 0).then_some(output_size),
            audit_sequence: (code == WorkerResultCode::ApplicationAuditAppended).then_some(value),
            report,
            application_output_size: matches!(
                code,
                WorkerResultCode::ApplicationReportListReady
                    | WorkerResultCode::ApplicationReportReady
            )
            .then_some(value),
            application_record_count: (code == WorkerResultCode::ApplicationReportListReady)
                .then_some(count),
            #[cfg(feature = "experimental-repair-store")]
            repair_status,
            #[cfg(feature = "experimental-repair-store")]
            repair_released_bytes: repair_release_metadata.then_some(value),
            #[cfg(feature = "experimental-repair-store")]
            repair_transaction_status,
            #[cfg(feature = "experimental-repair-store")]
            repair_vault_live_identity,
        };
        if response.encode()?.as_slice() != bytes {
            return Err(InternalWireError::InvalidFrame);
        }
        Ok(response)
    }
}

fn valid_device_id(value: &[u8]) -> bool {
    std::str::from_utf8(value)
        .ok()
        .is_some_and(|value| kernaid_device_identity::validate_device_id(value).is_ok())
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum InternalWireError {
    InvalidTransport,
    InvalidFrame,
    InvalidDescriptors,
    TimedOut,
    IoFailed,
}

impl fmt::Display for InternalWireError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::InvalidTransport => "invalid Rescue worker transport",
            Self::InvalidFrame => "invalid Rescue worker frame",
            Self::InvalidDescriptors => "invalid Rescue worker descriptors",
            Self::TimedOut => "Rescue worker transport timed out",
            Self::IoFailed => "Rescue worker transport failed",
        })
    }
}

impl std::error::Error for InternalWireError {}

pub(super) fn send_command(
    socket: BorrowedFd<'_>,
    command: WorkerCommand,
    descriptor: Option<BorrowedFd<'_>>,
    deadline: Instant,
) -> Result<(), InternalWireError> {
    let bytes = command.encode()?;
    match (command_requires_descriptor(command.kind), descriptor) {
        (true, Some(descriptor)) => send_record(socket, &bytes, &[descriptor], deadline),
        (true, None) | (false, Some(_)) => Err(InternalWireError::InvalidDescriptors),
        (false, None) => send_record(socket, &bytes, &[], deadline),
    }
}

pub(super) fn receive_command(
    socket: BorrowedFd<'_>,
    deadline: Instant,
) -> Result<(WorkerCommand, Option<OwnedFd>), InternalWireError> {
    let (bytes, mut descriptors) = receive_record(socket, deadline)?;
    let command = WorkerCommand::decode(&bytes)?;
    match (command_requires_descriptor(command.kind), descriptors.len()) {
        (true, 1) => Ok((command, descriptors.pop())),
        (true, _) | (false, 1..) => Err(InternalWireError::InvalidDescriptors),
        (false, 0) => Ok((command, None)),
    }
}

fn command_requires_descriptor(kind: WorkerCommandKind) -> bool {
    let base = matches!(
        kind,
        WorkerCommandKind::Unlock
            | WorkerCommandKind::ProviderOpenAiConfigure
            | WorkerCommandKind::ProviderOpenAiBorrow
            | WorkerCommandKind::ReportPersist
            | WorkerCommandKind::ReportList
            | WorkerCommandKind::ReportGet
    );
    #[cfg(feature = "experimental-repair-store")]
    let repair = matches!(
        kind,
        WorkerCommandKind::RepairBackupPersist | WorkerCommandKind::RepairBackupGet
    );
    #[cfg(not(feature = "experimental-repair-store"))]
    let repair = false;
    base || repair
}

pub(super) fn send_response(
    socket: BorrowedFd<'_>,
    response: &WorkerResponse,
    deadline: Instant,
) -> Result<(), InternalWireError> {
    send_record(socket, &response.encode()?, &[], deadline)
}

#[cfg(feature = "experimental-codex-home-lease")]
pub(super) fn send_codex_home_response(
    socket: BorrowedFd<'_>,
    response: &WorkerResponse,
    descriptor: Option<BorrowedFd<'_>>,
    deadline: Instant,
) -> Result<(), InternalWireError> {
    match (response.code, descriptor) {
        (WorkerResultCode::ProviderCodexHomeReady, Some(descriptor)) => {
            validate_codex_home_descriptor(descriptor)?;
            send_record(socket, &response.encode()?, &[descriptor], deadline)
        }
        (WorkerResultCode::ProviderCodexHomeUnconfigured, None) => {
            send_record(socket, &response.encode()?, &[], deadline)
        }
        _ => Err(InternalWireError::InvalidDescriptors),
    }
}

pub(super) fn receive_response(
    socket: BorrowedFd<'_>,
    expected_request_id: u64,
    deadline: Instant,
) -> Result<WorkerResponse, InternalWireError> {
    let (bytes, descriptors) = receive_record(socket, deadline)?;
    if !descriptors.is_empty() {
        return Err(InternalWireError::InvalidDescriptors);
    }
    let response = WorkerResponse::decode(&bytes)?;
    if response.request_id != expected_request_id {
        return Err(InternalWireError::InvalidFrame);
    }
    Ok(response)
}

#[cfg(feature = "experimental-codex-home-lease")]
pub(super) fn receive_codex_home_response(
    socket: BorrowedFd<'_>,
    expected_request_id: u64,
    deadline: Instant,
) -> Result<(WorkerResponse, Option<OwnedFd>), InternalWireError> {
    let (bytes, mut descriptors) = receive_record(socket, deadline)?;
    let response = WorkerResponse::decode(&bytes)?;
    if response.request_id != expected_request_id {
        return Err(InternalWireError::InvalidFrame);
    }
    match (response.code, descriptors.len()) {
        (WorkerResultCode::ProviderCodexHomeReady, 1) => {
            let descriptor = descriptors
                .pop()
                .ok_or(InternalWireError::InvalidDescriptors)?;
            validate_codex_home_descriptor(descriptor.as_fd())?;
            Ok((response, Some(descriptor)))
        }
        (
            WorkerResultCode::ProviderCodexHomeUnconfigured
            | WorkerResultCode::ProviderStateAmbiguous
            | WorkerResultCode::CleanupFailed
            | WorkerResultCode::Busy
            | WorkerResultCode::InvalidRequest,
            0,
        ) => Ok((response, None)),
        _ => Err(InternalWireError::InvalidDescriptors),
    }
}

#[cfg(feature = "experimental-codex-home-lease")]
fn validate_codex_home_descriptor(descriptor: BorrowedFd<'_>) -> Result<(), InternalWireError> {
    use rustix::fs::{self as rfs, FileType};

    let stat = rfs::fstat(descriptor).map_err(|_| InternalWireError::InvalidDescriptors)?;
    let status = rfs::fcntl_getfl(descriptor).map_err(|_| InternalWireError::InvalidDescriptors)?;
    let flags =
        rustix::io::fcntl_getfd(descriptor).map_err(|_| InternalWireError::InvalidDescriptors)?;
    if !FileType::from_raw_mode(stat.st_mode).is_dir()
        || stat.st_nlink < 2
        || stat.st_uid != crate::CODEX_AGENT_UID
        || stat.st_gid != crate::CODEX_AGENT_GID
        || stat.st_mode & 0o7777 != 0o700
        || !crate::codex_home_status_flags_are_exact(status)
        || flags != rustix::io::FdFlags::CLOEXEC
    {
        return Err(InternalWireError::InvalidDescriptors);
    }
    Ok(())
}

pub(super) fn validate_control_socket(socket: BorrowedFd<'_>) -> Result<(), InternalWireError> {
    let flags = rustix::io::fcntl_getfd(socket).map_err(|_| InternalWireError::InvalidTransport)?;
    if !flags.contains(rustix::io::FdFlags::CLOEXEC)
        || rustix::net::sockopt::socket_domain(socket)
            .map_err(|_| InternalWireError::InvalidTransport)?
            != AddressFamily::UNIX
        || rustix::net::sockopt::socket_type(socket)
            .map_err(|_| InternalWireError::InvalidTransport)?
            != SocketType::SEQPACKET
        || rustix::net::sockopt::socket_acceptconn(socket)
            .map_err(|_| InternalWireError::InvalidTransport)?
        || rustix::net::getpeername(socket).is_err()
        || rustix::net::sockopt::socket_passcred(socket)
            .map_err(|_| InternalWireError::InvalidTransport)?
    {
        return Err(InternalWireError::InvalidTransport);
    }
    Ok(())
}

pub(super) fn send_record(
    socket: BorrowedFd<'_>,
    bytes: &[u8],
    descriptors: &[BorrowedFd<'_>],
    deadline: Instant,
) -> Result<(), InternalWireError> {
    ensure_deadline(deadline)?;
    validate_control_socket(socket)?;
    if bytes.is_empty() || bytes.len() > MAX_RECORD_BYTES || descriptors.len() > 3 {
        return Err(InternalWireError::InvalidFrame);
    }
    let io = [IoSlice::new(bytes)];
    let mut space = [MaybeUninit::uninit(); rustix::cmsg_space!(ScmRights(3))];
    let mut ancillary = SendAncillaryBuffer::new(&mut space);
    if !descriptors.is_empty() && !ancillary.push(SendAncillaryMessage::ScmRights(descriptors)) {
        return Err(InternalWireError::IoFailed);
    }
    loop {
        ensure_deadline(deadline)?;
        match sendmsg(
            socket,
            &io,
            &mut ancillary,
            SendFlags::DONTWAIT | SendFlags::NOSIGNAL,
        ) {
            Ok(sent) if sent == bytes.len() => return Ok(()),
            Ok(_) => return Err(InternalWireError::IoFailed),
            Err(error) if error == rustix::io::Errno::INTR => {}
            Err(error) if error == rustix::io::Errno::AGAIN => {
                wait_ready(socket, PollFlags::OUT, deadline)?;
            }
            Err(_) => return Err(InternalWireError::IoFailed),
        }
    }
}

pub(super) fn receive_record(
    socket: BorrowedFd<'_>,
    deadline: Instant,
) -> Result<(Vec<u8>, Vec<OwnedFd>), InternalWireError> {
    ensure_deadline(deadline)?;
    validate_control_socket(socket)?;
    let mut bytes = [0_u8; MAX_RECORD_BYTES + 1];
    let mut io = [IoSliceMut::new(&mut bytes)];
    let mut space = [MaybeUninit::uninit(); rustix::cmsg_space!(ScmRights(3), ScmCredentials(1))];
    let mut ancillary = RecvAncillaryBuffer::new(&mut space);
    let message = loop {
        ensure_deadline(deadline)?;
        match recvmsg(
            socket,
            &mut io,
            &mut ancillary,
            RecvFlags::CMSG_CLOEXEC | RecvFlags::DONTWAIT | RecvFlags::TRUNC,
        ) {
            Ok(message) => break message,
            Err(error) if error == rustix::io::Errno::INTR => {}
            Err(error) if error == rustix::io::Errno::AGAIN => {
                wait_ready(socket, PollFlags::IN, deadline)?;
            }
            Err(_) => return Err(InternalWireError::IoFailed),
        }
    };
    if message
        .flags
        .intersects(ReturnFlags::TRUNC | ReturnFlags::CTRUNC)
        || message.bytes == 0
        || message.bytes > MAX_RECORD_BYTES
    {
        return Err(InternalWireError::InvalidFrame);
    }
    let mut descriptors = Vec::new();
    let mut unexpected = false;
    for message in ancillary.drain() {
        match message {
            RecvAncillaryMessage::ScmRights(rights) => descriptors.extend(rights),
            RecvAncillaryMessage::ScmCredentials(_) => unexpected = true,
            _ => unexpected = true,
        }
    }
    if unexpected
        || descriptors.len() > 3
        || descriptors.iter().any(|descriptor| {
            rustix::io::fcntl_getfd(descriptor)
                .map(|flags| !flags.contains(rustix::io::FdFlags::CLOEXEC))
                .unwrap_or(true)
        })
    {
        return Err(InternalWireError::InvalidDescriptors);
    }
    Ok((bytes[..message.bytes].to_vec(), descriptors))
}

fn ensure_deadline(deadline: Instant) -> Result<(), InternalWireError> {
    deadline
        .checked_duration_since(Instant::now())
        .filter(|remaining| !remaining.is_zero())
        .map(|_| ())
        .ok_or(InternalWireError::TimedOut)
}

fn wait_ready(
    socket: BorrowedFd<'_>,
    interest: PollFlags,
    deadline: Instant,
) -> Result<(), InternalWireError> {
    loop {
        let remaining = deadline
            .checked_duration_since(Instant::now())
            .filter(|remaining| !remaining.is_zero())
            .ok_or(InternalWireError::TimedOut)?;
        let mut descriptors = [PollFd::from_borrowed_fd(socket, interest)];
        match poll(&mut descriptors, Some(&duration_to_timespec(remaining))) {
            Ok(0) => return Err(InternalWireError::TimedOut),
            Ok(_) if descriptors[0].revents().contains(PollFlags::NVAL) => {
                return Err(InternalWireError::InvalidTransport);
            }
            Ok(_)
                if descriptors[0]
                    .revents()
                    .intersects(interest | PollFlags::ERR | PollFlags::HUP | PollFlags::RDHUP) =>
            {
                return Ok(());
            }
            Ok(_) => {}
            Err(error) if error == rustix::io::Errno::INTR => {}
            Err(_) => return Err(InternalWireError::IoFailed),
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

#[cfg(test)]
mod tests {
    use super::*;
    use rustix::{
        net::{
            AddressFamily, SendAncillaryBuffer, SendAncillaryMessage, SendFlags, SocketFlags,
            SocketType, send, sendmsg, socketpair,
        },
        pipe::{PipeFlags, pipe_with},
    };
    use std::{
        ffi::OsString,
        io::IoSlice,
        mem::MaybeUninit,
        os::fd::{AsFd, AsRawFd},
    };

    fn pair() -> (OwnedFd, OwnedFd) {
        socketpair(
            AddressFamily::UNIX,
            SocketType::SEQPACKET,
            SocketFlags::CLOEXEC,
            None,
        )
        .expect("socketpair")
    }

    #[cfg(not(feature = "experimental-repair-store"))]
    #[test]
    fn shipping_v003_frames_remain_byte_for_byte_stable() {
        let request_id = 0x0102_0304_0506_0708_u64;
        let mut expected_command = [0_u8; 128];
        expected_command[..8].copy_from_slice(b"KRVWC003");
        expected_command[8] = 2;
        expected_command[12..20].copy_from_slice(&request_id.to_be_bytes());
        assert_eq!(
            WorkerCommand::probe(request_id).encode(),
            Ok(expected_command)
        );

        let mut expected_response = [0_u8; 128];
        expected_response[..8].copy_from_slice(b"KRVWR003");
        expected_response[8] = 4;
        expected_response[12..20].copy_from_slice(&request_id.to_be_bytes());
        assert_eq!(
            WorkerResponse::new(request_id, WorkerResultCode::ProbeLocked).encode(),
            Ok(expected_response)
        );
    }

    #[cfg(feature = "experimental-repair-store")]
    #[test]
    fn repair_frames_round_trip_full_capability_metadata_and_closed_padding() {
        let metadata = RepairFileMetadataV1::new(0o644, 0, 0).expect("root file metadata");
        let expected_hash = [0x22; 32];
        let reserved = WorkerRepairStatus {
            state: WorkerRepairState::Reserved,
            reservation_id: format!("B-{}", "1".repeat(32)),
            draft_binding_sha256: [0x11; 32],
            locator: format!("vault://repair/B-{}", "1".repeat(32)),
            vault_id: format!("V-{}", "2".repeat(32)),
            vault_identity_fingerprint: [0x33; 32],
            physical_parent_fingerprint: [0x44; 32],
            reserved_bytes: 8192,
            backup_size: 4096,
            expected_backup_sha256: expected_hash,
            metadata_sha256: metadata.canonical_sha256().bytes(),
            binding: None,
        };
        let binding = WorkerRepairBinding {
            plan_id: "P-plan".to_owned(),
            plan_sha256: [0x55; 32],
            approval_id: "A-approval".to_owned(),
            approval_sha256: [0x66; 32],
            resource_id: "rescue:selected-linux-root:etc/fstab".to_owned(),
            resource_sha256: expected_hash,
            execution_intent: RepairExecutionIntentV1::new(
                "S-session",
                1,
                "target-root",
                format!("scan:{}", "7".repeat(64)),
                protocol_sha256([0x77; 32]).expect("target fingerprint"),
                protocol_sha256([0x88; 32]).expect("target physical parent"),
                format!("recovery:{}", "8".repeat(64)),
                format!("lock:{}", "9".repeat(64)),
                protocol_sha256(expected_hash).expect("before hash"),
                protocol_sha256([0xaa; 32]).expect("after hash"),
                protocol_sha256([0xbb; 32]).expect("diff hash"),
                protocol_sha256([0xcc; 32]).expect("UUID set hash"),
                metadata.clone(),
            )
            .expect("execution intent"),
        };
        let persist = WorkerCommand::repair(
            41,
            WorkerRepairCommand::Persist {
                expected: Box::new(reserved.clone()),
                binding: Box::new(binding.clone()),
                metadata: WorkerRepairFileMetadata::from_protocol(&metadata),
                input_size: 4096,
            },
        );
        let encoded = persist.encode().expect("repair persist frame");
        assert_eq!(encoded.len(), 2048);
        assert_eq!(&encoded[..8], b"KRVWC006");
        assert_eq!(WorkerCommand::decode(&encoded), Ok(persist));

        let mut noncanonical = encoded;
        noncanonical[COMMAND_BYTES - 1] = 1;
        assert_eq!(
            WorkerCommand::decode(&noncanonical),
            Err(InternalWireError::InvalidFrame)
        );

        let mut durable = reserved;
        durable.state = WorkerRepairState::Durable;
        durable.binding = Some(binding);
        let response =
            WorkerResponse::repair(41, WorkerResultCode::RepairBackupDurable, durable.clone());
        let encoded = response.encode().expect("repair response frame");
        assert_eq!(encoded.len(), 2048);
        assert_eq!(&encoded[..8], b"KRVWR006");
        assert_eq!(WorkerResponse::decode(&encoded), Ok(response));

        let durable_protocol = durable.to_protocol().expect("durable protocol status");
        let pending =
            RepairTransactionStatusPayload::pending(durable_protocol).expect("pending transaction");
        let status_command = WorkerCommand::repair(
            45,
            WorkerRepairCommand::TransactionStatus {
                selector: RepairTransactionStatusSelector::pending_singleton(),
            },
        );
        let encoded = status_command.encode().expect("transaction status frame");
        assert_eq!(WorkerCommand::decode(&encoded), Ok(status_command));

        let intent = pending
            .backup()
            .execution_intent()
            .expect("durable execution intent");
        let resolution = RepairTransactionResolution::new(
            RepairTransactionResolutionOutcome::CommittedAfter,
            intent.after_sha256().clone(),
            intent.before_metadata().canonical_sha256(),
            true,
            intent,
        )
        .expect("committed resolution");
        let resolve_command = WorkerCommand::repair(
            46,
            WorkerRepairCommand::TransactionResolve {
                expected: Box::new(pending.clone()),
                resolution: resolution.clone(),
            },
        );
        let encoded = resolve_command.encode().expect("transaction resolve frame");
        assert_eq!(WorkerCommand::decode(&encoded), Ok(resolve_command));

        let resolved =
            RepairTransactionStatusPayload::resolved(pending.backup().clone(), resolution)
                .expect("resolved transaction");
        let live_command = WorkerCommand::repair(50, WorkerRepairCommand::VaultLiveParent);
        let encoded = live_command.encode().expect("live Vault parent command");
        assert_eq!(WorkerCommand::decode(&encoded), Ok(live_command));
        let live_identity = WorkerRepairVaultLiveIdentity {
            vault_id: format!("V-{}", "d".repeat(32)),
            vault_identity_fingerprint: [0xdd; 32],
            physical_parent_fingerprint: [0xee; 32],
        };
        for response in [
            WorkerResponse::repair_transaction_status(47, None),
            WorkerResponse::repair_transaction_status(48, Some(pending)),
            WorkerResponse::repair_transaction_resolved(49, resolved),
            WorkerResponse::repair_vault_live_identity(50, live_identity),
        ] {
            let encoded = response.encode().expect("transaction response frame");
            assert_eq!(WorkerResponse::decode(&encoded), Ok(response));
        }

        for command in [
            WorkerCommand::repair(
                42,
                WorkerRepairCommand::Cancel {
                    reservation_id: durable.reservation_id.clone(),
                    draft_binding_sha256: durable.draft_binding_sha256,
                },
            ),
            WorkerCommand::repair(
                43,
                WorkerRepairCommand::Retire {
                    expected: Box::new(durable.clone()),
                },
            ),
        ] {
            let encoded = command.encode().expect("lifecycle command frame");
            assert_eq!(WorkerCommand::decode(&encoded), Ok(command));
        }
        let released =
            WorkerResponse::repair_released(44, WorkerResultCode::RepairBackupRetired, 8192);
        let encoded = released.encode().expect("release response frame");
        assert_eq!(WorkerResponse::decode(&encoded), Ok(released));
    }

    #[test]
    fn closed_command_and_response_round_trip() {
        let (parent, worker) = pair();
        let (read, _write) = pipe_with(PipeFlags::CLOEXEC).expect("pipe");
        let deadline = Instant::now() + Duration::from_secs(2);
        send_command(
            parent.as_fd(),
            WorkerCommand::unlock(7, 12),
            Some(read.as_fd()),
            deadline,
        )
        .expect("send unlock");
        let (command, descriptor) = receive_command(worker.as_fd(), deadline).expect("receive");
        assert_eq!(command, WorkerCommand::unlock(7, 12));
        assert!(descriptor.is_some());

        let (key_read, _key_write) = pipe_with(PipeFlags::CLOEXEC).expect("key pipe");
        send_command(
            parent.as_fd(),
            WorkerCommand::provider_openai_configure(8, 32),
            Some(key_read.as_fd()),
            deadline,
        )
        .expect("send provider configure");
        let (command, descriptor) = receive_command(worker.as_fd(), deadline).expect("receive");
        assert_eq!(command, WorkerCommand::provider_openai_configure(8, 32));
        assert!(descriptor.is_some());

        let (_borrow_read, borrow_write) =
            pipe_with(PipeFlags::CLOEXEC | PipeFlags::NONBLOCK).expect("borrow pipe");
        send_command(
            parent.as_fd(),
            WorkerCommand::provider_openai_borrow(9),
            Some(borrow_write.as_fd()),
            deadline,
        )
        .expect("send provider borrow");
        let (command, descriptor) = receive_command(worker.as_fd(), deadline).expect("receive");
        assert_eq!(command, WorkerCommand::provider_openai_borrow(9));
        assert!(descriptor.is_some());

        #[cfg(feature = "experimental-codex-home-lease")]
        {
            send_command(
                parent.as_fd(),
                WorkerCommand::provider_codex_home_lease(10),
                None,
                deadline,
            )
            .expect("send Codex home lease");
            let (command, descriptor) =
                receive_command(worker.as_fd(), deadline).expect("receive Codex home lease");
            assert_eq!(command, WorkerCommand::provider_codex_home_lease(10));
            assert!(descriptor.is_none());
        }

        let response = WorkerResponse::unlocked(7, "KA-0123456789abcdef01234567".to_owned());
        send_response(worker.as_fd(), &response, deadline).expect("send response");
        assert_eq!(
            receive_response(parent.as_fd(), 7, deadline).expect("receive response"),
            response
        );

        let response = WorkerResponse::provider_borrow_ready(9, 32);
        send_response(worker.as_fd(), &response, deadline).expect("send borrow response");
        assert_eq!(
            receive_response(parent.as_fd(), 9, deadline).expect("receive borrow response"),
            response
        );

        #[cfg(feature = "experimental-codex-home-lease")]
        {
            let response = WorkerResponse::new(10, WorkerResultCode::ProviderCodexHomeUnconfigured);
            send_response(worker.as_fd(), &response, deadline).expect("send unconfigured home");
            let (observed, descriptor) = receive_codex_home_response(parent.as_fd(), 10, deadline)
                .expect("receive unconfigured home");
            assert_eq!(observed, response);
            assert!(descriptor.is_none());
        }
    }

    #[test]
    fn application_commands_and_metadata_round_trip_without_text_frames() {
        let agent_request =
            RequestId::parse("R-00000000-0000-0000-0000-000000000011").expect("agent request id");
        let report_id =
            ReportId::parse("RP-00000000-0000-0000-0000-000000000021").expect("report id");
        let audit = WorkerCommand::application(
            11,
            WorkerApplicationCommand::AuditAppend {
                request_id: agent_request,
                peer_uid: 1001,
                peer_pid: 4242,
                sequence: 1,
                event: AuditEventType::AgentSessionStart,
                outcome: AuditOutcome::Succeeded,
                error: None,
            },
        );
        let encoded = audit.encode().expect("audit frame");
        assert_eq!(encoded.len(), COMMAND_BYTES);
        assert_eq!(encoded[8], 12);
        assert!(!encoded.windows(2).any(|window| window == b"R-"));
        assert_eq!(WorkerCommand::decode(&encoded), Ok(audit.clone()));

        let persist = WorkerCommand::application(
            12,
            WorkerApplicationCommand::ReportPersist {
                report_id: report_id.clone(),
                payload_sha256: [0x5a; 32],
                input_size: 4096,
            },
        );
        let encoded = persist.encode().expect("persist frame");
        assert_eq!(encoded[8], 13);
        assert!(!encoded.windows(3).any(|window| window == b"RP-"));
        assert_eq!(WorkerCommand::decode(&encoded), Ok(persist.clone()));

        let (parent, worker) = pair();
        let (input, _input_writer) = pipe_with(PipeFlags::CLOEXEC).expect("report input pipe");
        let deadline = Instant::now() + Duration::from_secs(1);
        send_command(
            parent.as_fd(),
            persist.clone(),
            Some(input.as_fd()),
            deadline,
        )
        .expect("send report persist");
        assert_eq!(
            receive_command(worker.as_fd(), deadline)
                .expect("receive report persist")
                .0,
            persist
        );
        assert_eq!(
            send_command(parent.as_fd(), audit.clone(), Some(input.as_fd()), deadline),
            Err(InternalWireError::InvalidDescriptors)
        );
        assert_eq!(
            send_command(parent.as_fd(), persist.clone(), None, deadline),
            Err(InternalWireError::InvalidDescriptors)
        );

        let list = WorkerCommand::application(13, WorkerApplicationCommand::ReportList);
        assert_eq!(
            WorkerCommand::decode(&list.encode().expect("list")),
            Ok(list)
        );
        let get = WorkerCommand::application(
            14,
            WorkerApplicationCommand::ReportGet {
                report_id: report_id.clone(),
            },
        );
        assert_eq!(WorkerCommand::decode(&get.encode().expect("get")), Ok(get));

        let summary = WorkerReportSummary {
            report_id,
            envelope_size: 8192,
            envelope_sha256: [0xa5; 32],
        };
        for response in [
            WorkerResponse::audit_appended(21, 1),
            WorkerResponse::report_persisted(22, summary.clone()),
            WorkerResponse::report_list_ready(23, APPLICATION_REPORT_RECORD_BYTES as u64, 1),
            WorkerResponse::report_ready(24, summary),
        ] {
            let encoded = response.encode().expect("application response");
            assert_eq!(encoded.len(), RESPONSE_BYTES);
            assert_eq!(WorkerResponse::decode(&encoded), Ok(response));
        }
    }

    #[test]
    fn report_record_pipe_format_is_fixed_sorted_and_bounded() {
        let reports = [
            WorkerReportSummary {
                report_id: ReportId::parse("RP-00000000-0000-0000-0000-000000000001")
                    .expect("first report"),
                envelope_size: 2,
                envelope_sha256: [1; 32],
            },
            WorkerReportSummary {
                report_id: ReportId::parse("RP-00000000-0000-0000-0000-000000000002")
                    .expect("second report"),
                envelope_size: 3,
                envelope_sha256: [2; 32],
            },
        ];
        let encoded = encode_report_records(&reports).expect("report records");
        assert_eq!(encoded.len(), 2 * APPLICATION_REPORT_RECORD_BYTES);
        assert!(encoded[56..64].iter().all(|byte| *byte == 0));
        let decoded = decode_report_records(&encoded, 2).expect("decode report records");
        assert_eq!(decoded.len(), 2);
        assert_eq!(decoded[0].report_id(), &reports[0].report_id);
        assert_eq!(decoded[1].envelope_size(), 3);

        let mut reversed = reports;
        reversed.reverse();
        assert_eq!(
            encode_report_records(&reversed),
            Err(InternalWireError::InvalidFrame)
        );
        let mut reserved = encoded;
        reserved[63] = 1;
        assert_eq!(
            decode_report_records(&reserved, 2),
            Err(InternalWireError::InvalidFrame)
        );
    }

    #[test]
    fn canonical_frames_reject_wrong_arity_reserved_bytes_and_correlation() {
        assert_eq!(
            WorkerCommand::unlock(1, 11).encode(),
            Err(InternalWireError::InvalidFrame)
        );
        assert_eq!(
            WorkerCommand::provider_openai_configure(1, 0).encode(),
            Err(InternalWireError::InvalidFrame)
        );
        assert_eq!(
            WorkerCommand::provider_openai_configure(1, 513).encode(),
            Err(InternalWireError::InvalidFrame)
        );
        let borrow = WorkerCommand::provider_openai_borrow(1)
            .encode()
            .expect("borrow frame");
        assert_eq!(borrow[8], 10);
        assert_eq!(&borrow[20..22], &[0, 0]);
        let mut noncanonical_borrow = borrow;
        noncanonical_borrow[21] = 1;
        assert_eq!(
            WorkerCommand::decode(&noncanonical_borrow),
            Err(InternalWireError::InvalidFrame)
        );
        #[cfg(feature = "experimental-codex-home-lease")]
        {
            let deadline = Instant::now() + Duration::from_secs(2);
            let home = WorkerCommand::provider_codex_home_lease(1)
                .encode()
                .expect("home frame");
            assert_eq!(home[8], 11);
            assert_eq!(&home[20..22], &[0, 0]);
            assert_eq!(
                send_command(
                    pair().0.as_fd(),
                    WorkerCommand::provider_codex_home_lease(1),
                    Some(read_pipe_for_test().as_fd()),
                    deadline,
                ),
                Err(InternalWireError::InvalidDescriptors)
            );
        }
        assert_eq!(
            WorkerResponse::new(1, WorkerResultCode::ProviderBorrowReady).encode(),
            Err(InternalWireError::InvalidFrame)
        );
        assert_eq!(
            WorkerResponse::provider_borrow_ready(1, 0).encode(),
            Err(InternalWireError::InvalidFrame)
        );
        assert_eq!(
            WorkerResponse::provider_borrow_ready(1, 513).encode(),
            Err(InternalWireError::InvalidFrame)
        );
        let encoded_ready = WorkerResponse::provider_borrow_ready(1, 32)
            .encode()
            .expect("canonical ready response");
        assert_eq!(encoded_ready[8], 31);
        assert_eq!(encoded_ready[9], 0);
        assert_eq!(&encoded_ready[10..12], &[0, 32]);
        let encoded_unconfigured =
            WorkerResponse::new(1, WorkerResultCode::ProviderBorrowUnconfigured)
                .encode()
                .expect("canonical unconfigured response");
        assert_eq!(encoded_unconfigured[8], 32);
        assert_eq!(&encoded_unconfigured[10..12], &[0, 0]);
        let mut frame = WorkerCommand::probe(1).encode().expect("frame");
        frame[84] = 1;
        assert_eq!(
            WorkerCommand::decode(&frame),
            Err(InternalWireError::InvalidFrame)
        );
        let mut legacy_command = WorkerCommand::probe(1).encode().expect("legacy command");
        legacy_command[..8].copy_from_slice(b"KRVWC001");
        assert_eq!(
            WorkerCommand::decode(&legacy_command),
            Err(InternalWireError::InvalidFrame)
        );
        let response = WorkerResponse::new(9, WorkerResultCode::ProbeLocked);
        let mut encoded = response.encode().expect("response");
        encoded[63] = 1;
        assert_eq!(
            WorkerResponse::decode(&encoded),
            Err(InternalWireError::InvalidFrame)
        );
        let mut legacy_response = response.encode().expect("legacy response");
        legacy_response[..8].copy_from_slice(b"KRVWR001");
        assert_eq!(
            WorkerResponse::decode(&legacy_response),
            Err(InternalWireError::InvalidFrame)
        );
        let mut encoded = WorkerResponse::new(9, WorkerResultCode::ProbeLocked)
            .encode()
            .expect("response");
        encoded[11] = 1;
        assert_eq!(
            WorkerResponse::decode(&encoded),
            Err(InternalWireError::InvalidFrame)
        );

        let mut encoded = WorkerResponse::provider_borrow_ready(9, 32)
            .encode()
            .expect("borrow response");
        encoded[11] = 0;
        assert_eq!(
            WorkerResponse::decode(&encoded),
            Err(InternalWireError::InvalidFrame)
        );

        let (parent, worker) = pair();
        let deadline = Instant::now() + Duration::from_secs(2);
        send_response(worker.as_fd(), &response, deadline).expect("send");
        assert_eq!(
            receive_response(parent.as_fd(), 10, deadline),
            Err(InternalWireError::InvalidFrame)
        );

        let (parent, _worker) = pair();
        assert_eq!(
            send_command(
                parent.as_fd(),
                WorkerCommand::provider_openai_borrow(11),
                None,
                deadline
            ),
            Err(InternalWireError::InvalidDescriptors)
        );
    }

    #[test]
    fn unlock_io_diagnostic_codes_keep_the_fixed_payload_free_frame() {
        use WorkerResultCode as Result;
        for (code, encoded_code) in [
            (Result::UnlockIoProbe, 35),
            (Result::UnlockIoProbeClassifier, 36),
            (Result::UnlockIoMapperName, 37),
            (Result::UnlockIoUnsupportedPlatform, 38),
            (Result::UnlockIoPrivilegeRequired, 39),
            (Result::UnlockIoInvalidMapperName, 40),
            (Result::UnlockIoClassifierUnavailable, 41),
            (Result::UnlockIoPassphraseUnavailable, 42),
            (Result::UnlockIoUnsupportedFilesystem, 43),
            (Result::UnlockIoUnsafeMountRoot, 44),
            (Result::UnlockIoMountFailed, 45),
            (Result::UnlockIoMountVerificationFailed, 46),
            (Result::UnlockIoSecureStateUnavailable, 47),
            (Result::UnlockIoToolUnavailable, 48),
            (Result::UnlockIoApplicationStore, 49),
            (Result::UnlockIoDeviceId, 50),
        ] {
            let frame = WorkerResponse::new(7, code)
                .encode()
                .expect("canonical diagnostic response");
            assert_eq!(frame.len(), RESPONSE_BYTES);
            assert_eq!(frame[8], encoded_code);
            assert_eq!(&frame[9..12], &[0, 0, 0]);
            assert_eq!(&frame[12..20], &7_u64.to_be_bytes());
            assert!(frame[20..].iter().all(|byte| *byte == 0));
            assert_eq!(
                WorkerResponse::decode(&frame).expect("diagnostic response round trip"),
                WorkerResponse::new(7, code)
            );
        }
        let mut reserved = WorkerResponse::new(7, Result::UnlockIoDeviceId)
            .encode()
            .expect("canonical diagnostic response");
        reserved[8] = 61;
        assert_eq!(
            WorkerResponse::decode(&reserved),
            Err(InternalWireError::InvalidFrame)
        );
    }

    #[cfg(feature = "experimental-codex-home-lease")]
    fn read_pipe_for_test() -> OwnedFd {
        pipe_with(PipeFlags::CLOEXEC).expect("pipe").0
    }

    #[cfg(feature = "experimental-codex-home-lease")]
    #[test]
    fn codex_home_response_rejects_missing_or_wrong_owner_descriptors() {
        let (sender, receiver) = pair();
        let response = WorkerResponse::provider_codex_home_ready(41);
        let deadline = Instant::now() + Duration::from_secs(2);
        assert_eq!(
            send_codex_home_response(sender.as_fd(), &response, None, deadline),
            Err(InternalWireError::InvalidDescriptors)
        );

        let directory = rustix::fs::open(
            "/tmp",
            rustix::fs::OFlags::PATH | rustix::fs::OFlags::DIRECTORY | rustix::fs::OFlags::CLOEXEC,
            rustix::fs::Mode::empty(),
        )
        .expect("temporary directory");
        assert_eq!(
            send_codex_home_response(sender.as_fd(), &response, Some(directory.as_fd()), deadline,),
            Err(InternalWireError::InvalidDescriptors)
        );
        drop(receiver);
    }

    #[test]
    fn debug_and_errors_never_contain_payload_or_descriptor_numbers() {
        let response = WorkerResponse::unlocked(7, "KA-0123456789abcdef01234567".to_owned());
        let debug = format!("{response:?}");
        assert!(debug.contains("KA-"));
        assert!(!InternalWireError::InvalidFrame.to_string().contains('7'));
    }

    #[test]
    fn short_extra_and_timed_out_records_fail_closed() {
        for bytes in [
            &[0_u8; COMMAND_BYTES - 1][..],
            &[0_u8; COMMAND_BYTES + 1][..],
        ] {
            let (sender, receiver) = pair();
            send(&sender, bytes, SendFlags::NOSIGNAL).expect("raw frame");
            assert!(matches!(
                receive_command(receiver.as_fd(), Instant::now() + Duration::from_secs(1)),
                Err(InternalWireError::InvalidFrame)
            ));
        }
        let (_sender, receiver) = pair();
        assert!(matches!(
            receive_command(receiver.as_fd(), Instant::now() + Duration::from_millis(10)),
            Err(InternalWireError::TimedOut)
        ));
    }

    #[test]
    fn duplicate_rights_are_rejected_and_closed() {
        fn descriptor_target(descriptor: BorrowedFd<'_>) -> OsString {
            std::fs::read_link(format!("/proc/self/fd/{}", descriptor.as_raw_fd()))
                .expect("descriptor target")
                .into_os_string()
        }

        fn target_count(target: &OsString) -> usize {
            std::fs::read_dir("/proc/self/fd")
                .expect("proc fd")
                .filter_map(Result::ok)
                .filter_map(|entry| std::fs::read_link(entry.path()).ok())
                .filter(|observed| observed.as_os_str() == target.as_os_str())
                .count()
        }

        let (sender, receiver) = pair();
        let (first, first_write) = pipe_with(PipeFlags::CLOEXEC).expect("first pipe");
        let (second, second_write) = pipe_with(PipeFlags::CLOEXEC).expect("second pipe");
        let first_target = descriptor_target(first.as_fd());
        let second_target = descriptor_target(second.as_fd());
        let first_baseline = target_count(&first_target);
        let second_baseline = target_count(&second_target);
        let frame = WorkerCommand::unlock(9, 12).encode().expect("frame");
        let io = [IoSlice::new(&frame)];
        let rights = [first.as_fd(), second.as_fd()];
        let mut space = [MaybeUninit::uninit(); rustix::cmsg_space!(ScmRights(2))];
        let mut ancillary = SendAncillaryBuffer::new(&mut space);
        assert!(ancillary.push(SendAncillaryMessage::ScmRights(&rights)));
        assert_eq!(
            sendmsg(&sender, &io, &mut ancillary, SendFlags::NOSIGNAL).expect("send rights"),
            COMMAND_BYTES
        );
        assert!(matches!(
            receive_command(receiver.as_fd(), Instant::now() + Duration::from_secs(1)),
            Err(InternalWireError::InvalidDescriptors)
        ));
        assert_eq!(target_count(&first_target), first_baseline);
        assert_eq!(target_count(&second_target), second_baseline);
        rustix::io::fcntl_getfd(&first_write).expect("first writer remains owned");
        rustix::io::fcntl_getfd(&second_write).expect("second writer remains owned");
    }

    #[test]
    fn generated_credentials_and_send_backpressure_are_bounded() {
        let (_sender, receiver) = pair();
        rustix::net::sockopt::set_socket_passcred(&receiver, true).expect("passcred");
        assert!(matches!(
            receive_command(receiver.as_fd(), Instant::now() + Duration::from_millis(10)),
            Err(InternalWireError::InvalidTransport)
        ));

        let (sender, _receiver) = pair();
        rustix::net::sockopt::set_socket_send_buffer_size(&sender, 1024)
            .expect("small send buffer");
        let frame = WorkerResponse::new(1, WorkerResultCode::ProbeLocked)
            .encode()
            .expect("response");
        let mut filled = false;
        let mut unexpected_error = false;
        for _ in 0..10_000 {
            match send(&sender, &frame, SendFlags::DONTWAIT | SendFlags::NOSIGNAL) {
                Ok(_) => {}
                Err(error) if error == rustix::io::Errno::AGAIN => {
                    filled = true;
                    break;
                }
                Err(_) => {
                    unexpected_error = true;
                    break;
                }
            }
        }
        assert!(!unexpected_error);
        assert!(filled);
        assert_eq!(
            send_response(
                sender.as_fd(),
                &WorkerResponse::new(2, WorkerResultCode::ProbeLocked),
                Instant::now() + Duration::from_millis(20)
            ),
            Err(InternalWireError::TimedOut)
        );
    }
}
