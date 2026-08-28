//! Dedicated, descriptor-oriented storage for reversible Rescue repairs.
//!
//! The repair namespace is independent from application credentials/reports.
//! Public values contain only opaque identifiers, hashes and byte counts. The
//! filesystem path and the backup descriptor never cross this module.

use crate::{
    VaultOwner,
    linux::{RescueDeviceIdentityStore, VaultInner},
};
use kernaid_protocol::rescue_repair_vault::RepairFileMetadataV1;
use kernaid_storage::{
    JOURNAL_KEY_BYTES, JournalAnchor, JournalEntryRef, JournalKey, JournalReplayLimits,
    JournalSecretStore, SecretStoreError, SecureJournal,
};
use rand_core::{OsRng, RngCore};
use rustix::{
    event::{PollFd, PollFlags, Timespec, poll},
    fd::{AsFd, OwnedFd},
    fs::{
        self as rfs, AtFlags, FallocateFlags, FileType, FlockOperation, Mode, OFlags, RawDir,
        RenameFlags, ResolveFlags, Stat, StatxFlags,
    },
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeMap, BTreeSet},
    error::Error,
    fmt,
    fs::File,
    io::{Read, Seek, SeekFrom, Write},
    mem::MaybeUninit,
    path::Path,
    sync::MutexGuard,
    time::{Duration, Instant},
};
use zeroize::Zeroizing;

const REPAIR_NAMESPACE: &str = ".kernaid-repair-store-v1";
const BACKUP_DIRECTORY: &str = "backups";
const LOCK_NAME: &str = "lock";
const JOURNAL_DATABASE_NAME: &str = "journal.sqlite3";
const JOURNAL_WAL_NAME: &str = "journal.sqlite3-wal";
const JOURNAL_SHM_NAME: &str = "journal.sqlite3-shm";
const JOURNAL_KEY_NAME: &str = "journal-key";
const JOURNAL_ANCHOR_NAME: &str = "journal-anchor";
const BACKUP_PREFIX: &str = "backup-";
const TEMP_PREFIX: &str = ".tmp-";
const DIRECTORY_MODE: u32 = 0o700;
const FILE_MODE: u32 = 0o600;
const MAX_BACKUP_BYTES: u64 = 16 * 1024 * 1024;
const MAX_RESERVATIONS: usize = 64;
// Bounded at 16 MiB of authenticated event payload. This permits repeated
// reserve/persist/retire lifecycles while journal compaction remains a
// separate promotion gate; it is intentionally finite.
const MAX_JOURNAL_EVENTS: u64 = 4096;
const MAX_EVENT_BYTES: u64 = 4096;
// Release acknowledgements are retained independently from active reservation
// slots so a lost response can be replayed exactly. Every tombstone requires
// at least an authenticated intent/complete pair, so the journal bound also
// gives this map a strict lifetime bound without inventing unbounded state.
const MAX_RELEASE_TOMBSTONES: usize = (MAX_JOURNAL_EVENTS / 2) as usize;
const PIPEFS_MAGIC: u64 = 0x5049_5045;
const DEFAULT_SOURCE_DEADLINE: Duration = Duration::from_secs(30);
const MAX_LAYOUT_ENTRIES: usize = 72;
const SCAN_BUFFER_BYTES: usize = 8192;
const SECRET_PREFIX: &[u8] = b"KERNAID-REPAIR-STORE-SECRET-V1\0";
const RESERVATION_BINDING_DOMAIN: &[u8] = b"KERNAID-REPAIR-RESERVATION-V1\0";
const VAULT_IDENTITY_DOMAIN: &[u8] = b"KERNAID-REPAIR-VAULT-IDENTITY-V1\0";
const STABLE_VAULT_ID_DOMAIN: &[u8] = b"KERNAID-REPAIR-STABLE-VAULT-ID-V1\0";
const PHYSICAL_PARENT_DOMAIN: &[u8] = b"KERNAID-REPAIR-PHYSICAL-PARENT-V1\0";
const FSTAB_RESOURCE_ID: &str = "rescue:selected-linux-root:etc/fstab";

/// Sanitized Repair Vault failures. No variant carries an OS path, raw backup
/// bytes or an operating-system error string.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RepairVaultStoreError {
    InvalidDraft,
    InvalidBinding,
    InvalidReservationId,
    ReservationNotFound,
    ReservationConflict,
    ReservationNotReady,
    ReconciliationRequired,
    UnsafeSource,
    SourceHashMismatch,
    InsufficientCapacity,
    PhysicalParentUnavailable,
    CorruptJournal,
    CorruptStore,
    ConcurrentWrite,
    WriteVerificationFailed,
    StorageUnavailable,
}

impl fmt::Display for RepairVaultStoreError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::InvalidDraft => "invalid repair backup draft",
            Self::InvalidBinding => "invalid repair plan binding",
            Self::InvalidReservationId => "invalid repair reservation identifier",
            Self::ReservationNotFound => "repair backup reservation was not found",
            Self::ReservationConflict => "repair backup reservation conflicts with durable state",
            Self::ReservationNotReady => "repair backup reservation is not ready",
            Self::ReconciliationRequired => "Repair Vault reconciliation is required",
            Self::UnsafeSource => "repair backup source descriptor is unsafe",
            Self::SourceHashMismatch => "repair backup source hash does not match",
            Self::InsufficientCapacity => "Repair Vault capacity reservation is insufficient",
            Self::PhysicalParentUnavailable => {
                "authenticated Repair Vault physical-parent identity is unavailable"
            }
            Self::CorruptJournal => "Repair Vault journal is invalid",
            Self::CorruptStore => "Repair Vault state is invalid",
            Self::ConcurrentWrite => "Repair Vault state changed concurrently",
            Self::WriteVerificationFailed => "Repair Vault write verification failed",
            Self::StorageUnavailable => "Repair Vault storage is unavailable",
        })
    }
}

impl Error for RepairVaultStoreError {}

/// Opaque durable reservation identifier. Parsing validates syntax only; all
/// authority comes from authenticated store state.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(transparent)]
pub struct ReservationId(String);

impl ReservationId {
    pub fn parse(value: impl Into<String>) -> Result<Self, RepairVaultStoreError> {
        let value = value.into();
        if !valid_reservation_id(&value) {
            return Err(RepairVaultStoreError::InvalidReservationId);
        }
        Ok(Self(value))
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    fn generate() -> Self {
        let mut random = [0_u8; 16];
        OsRng.fill_bytes(&mut random);
        Self(format!("B-{}", encode_hex(&random)))
    }
}

impl<'de> Deserialize<'de> for ReservationId {
    fn deserialize<Deserializer>(deserializer: Deserializer) -> Result<Self, Deserializer::Error>
    where
        Deserializer: serde::Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        Self::parse(value).map_err(|_| serde::de::Error::custom("invalid reservation ID"))
    }
}

/// Canonical, path-free material bound before the final repair plan exists.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RepairBackupDraft {
    session_id: String,
    target_id: String,
    target_fingerprint: [u8; 32],
    expected_backup_sha256: [u8; 32],
    metadata_sha256: [u8; 32],
    backup_size_bytes: u64,
    required_capacity_bytes: u64,
}

impl RepairBackupDraft {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        session_id: impl Into<String>,
        target_id: impl Into<String>,
        target_fingerprint: [u8; 32],
        expected_backup_sha256: [u8; 32],
        metadata_sha256: [u8; 32],
        backup_size_bytes: u64,
        required_capacity_bytes: u64,
    ) -> Result<Self, RepairVaultStoreError> {
        let value = Self {
            session_id: session_id.into(),
            target_id: target_id.into(),
            target_fingerprint,
            expected_backup_sha256,
            metadata_sha256,
            backup_size_bytes,
            required_capacity_bytes,
        };
        value.validate()?;
        Ok(value)
    }

    fn validate(&self) -> Result<(), RepairVaultStoreError> {
        if !valid_prefixed_id(&self.session_id, "S-")
            || !valid_opaque_id(&self.target_id)
            || self.target_fingerprint == [0; 32]
            || self.expected_backup_sha256 == [0; 32]
            || self.metadata_sha256 != canonical_fstab_metadata_sha256()
            || self.backup_size_bytes == 0
            || self.required_capacity_bytes < self.backup_size_bytes
            || self.required_capacity_bytes > MAX_BACKUP_BYTES
        {
            return Err(RepairVaultStoreError::InvalidDraft);
        }
        Ok(())
    }

    #[must_use]
    pub fn session_id(&self) -> &str {
        &self.session_id
    }

    #[must_use]
    pub fn target_id(&self) -> &str {
        &self.target_id
    }

    #[must_use]
    pub const fn target_fingerprint(&self) -> &[u8; 32] {
        &self.target_fingerprint
    }

    #[must_use]
    pub const fn expected_backup_sha256(&self) -> &[u8; 32] {
        &self.expected_backup_sha256
    }

    #[must_use]
    pub const fn metadata_sha256(&self) -> &[u8; 32] {
        &self.metadata_sha256
    }

    #[must_use]
    pub const fn backup_size_bytes(&self) -> u64 {
        self.backup_size_bytes
    }

    #[must_use]
    pub const fn required_capacity_bytes(&self) -> u64 {
        self.required_capacity_bytes
    }

    /// Canonical pre-plan binding used by the durable reservation protocol.
    #[must_use]
    pub fn reservation_binding_sha256(&self) -> String {
        reservation_binding(self)
    }
}

/// Digest of the only metadata contract supported in Repair Store v1:
/// `/etc/fstab`, root-owned mode 0644, without xattrs or an ACL.
#[must_use]
pub fn canonical_fstab_metadata_sha256() -> [u8; 32] {
    RepairFileMetadataV1::new(0o644, 0, 0)
        .expect("canonical fstab metadata is valid")
        .canonical_sha256()
        .bytes()
}

/// Post-approval binding persisted before backup bytes are installed.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RepairBinding {
    plan_id: String,
    plan_sha256: [u8; 32],
    approval_id: String,
    approval_sha256: [u8; 32],
    resource_id: String,
    resource_sha256: [u8; 32],
}

impl RepairBinding {
    pub fn new(
        plan_id: impl Into<String>,
        plan_sha256: [u8; 32],
        approval_id: impl Into<String>,
        approval_sha256: [u8; 32],
        resource_id: impl Into<String>,
        resource_sha256: [u8; 32],
    ) -> Result<Self, RepairVaultStoreError> {
        let value = Self {
            plan_id: plan_id.into(),
            plan_sha256,
            approval_id: approval_id.into(),
            approval_sha256,
            resource_id: resource_id.into(),
            resource_sha256,
        };
        value.validate()?;
        Ok(value)
    }

    fn validate(&self) -> Result<(), RepairVaultStoreError> {
        if !valid_prefixed_id(&self.plan_id, "P-")
            || !valid_prefixed_id(&self.approval_id, "A-")
            || self.plan_sha256 == [0; 32]
            || self.approval_sha256 == [0; 32]
            || self.resource_id != FSTAB_RESOURCE_ID
            || self.resource_sha256 == [0; 32]
        {
            return Err(RepairVaultStoreError::InvalidBinding);
        }
        Ok(())
    }

    #[must_use]
    pub fn plan_id(&self) -> &str {
        &self.plan_id
    }

    #[must_use]
    pub const fn plan_sha256(&self) -> &[u8; 32] {
        &self.plan_sha256
    }

    #[must_use]
    pub fn approval_id(&self) -> &str {
        &self.approval_id
    }

    #[must_use]
    pub const fn approval_sha256(&self) -> &[u8; 32] {
        &self.approval_sha256
    }

    #[must_use]
    pub fn resource_id(&self) -> &str {
        &self.resource_id
    }

    #[must_use]
    pub const fn resource_sha256(&self) -> &[u8; 32] {
        &self.resource_sha256
    }
}

/// Non-cloneable in-process handle for one physically allocated reservation.
pub struct ReservedRepairBackup {
    summary: RepairBackupSummary,
}

impl fmt::Debug for ReservedRepairBackup {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ReservedRepairBackup")
            .field("summary", &self.summary)
            .finish()
    }
}

impl ReservedRepairBackup {
    #[must_use]
    pub fn summary(&self) -> &RepairBackupSummary {
        &self.summary
    }

    #[must_use]
    pub fn reservation_id(&self) -> &ReservationId {
        self.summary.reservation_id()
    }

    #[must_use]
    pub fn backup_locator(&self) -> &str {
        self.summary.backup_locator()
    }

    #[must_use]
    pub fn reservation_binding_sha256(&self) -> &str {
        self.summary.reservation_binding_sha256()
    }

    #[must_use]
    pub fn vault_id(&self) -> &str {
        self.summary.vault_id()
    }

    #[must_use]
    pub fn vault_identity_fingerprint(&self) -> &str {
        self.summary.vault_identity_fingerprint()
    }

    #[must_use]
    pub fn physical_parent_fingerprint(&self) -> &str {
        self.summary.physical_parent_fingerprint()
    }

    #[must_use]
    pub const fn reserved_capacity_bytes(&self) -> u64 {
        self.summary.reserved_capacity_bytes
    }

    #[must_use]
    pub const fn backup_size_bytes(&self) -> u64 {
        self.summary.backup_size_bytes
    }

    #[must_use]
    pub fn expected_backup_sha256(&self) -> &str {
        &self.summary.expected_backup_sha256
    }

    #[must_use]
    pub fn metadata_sha256(&self) -> &str {
        &self.summary.metadata_sha256
    }
}

/// Authenticated path-free evidence for a physically allocated reservation.
/// This value is cloneable because it is status evidence, never execution
/// authority; persistence still requires [`ReservedRepairBackup`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RepairBackupSummary {
    reservation_id: ReservationId,
    backup_locator: String,
    reservation_binding_sha256: String,
    vault_id: String,
    vault_identity_fingerprint: String,
    physical_parent_fingerprint: String,
    reserved_capacity_bytes: u64,
    backup_size_bytes: u64,
    expected_backup_sha256: String,
    metadata_sha256: String,
}

impl RepairBackupSummary {
    #[must_use]
    pub fn reservation_id(&self) -> &ReservationId {
        &self.reservation_id
    }

    #[must_use]
    pub fn backup_locator(&self) -> &str {
        &self.backup_locator
    }

    #[must_use]
    pub fn reservation_binding_sha256(&self) -> &str {
        &self.reservation_binding_sha256
    }

    #[must_use]
    pub fn vault_id(&self) -> &str {
        &self.vault_id
    }

    #[must_use]
    pub fn vault_identity_fingerprint(&self) -> &str {
        &self.vault_identity_fingerprint
    }

    #[must_use]
    pub fn physical_parent_fingerprint(&self) -> &str {
        &self.physical_parent_fingerprint
    }

    #[must_use]
    pub const fn reserved_capacity_bytes(&self) -> u64 {
        self.reserved_capacity_bytes
    }

    #[must_use]
    pub const fn backup_size_bytes(&self) -> u64 {
        self.backup_size_bytes
    }

    #[must_use]
    pub fn expected_backup_sha256(&self) -> &str {
        &self.expected_backup_sha256
    }

    #[must_use]
    pub fn metadata_sha256(&self) -> &str {
        &self.metadata_sha256
    }
}

/// Evidence that the expected backup bytes and final plan binding are durable.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DurableRepairBackup {
    metadata: VerifiedBackupMetadata,
}

impl DurableRepairBackup {
    #[must_use]
    pub fn metadata(&self) -> &VerifiedBackupMetadata {
        &self.metadata
    }
}

/// Path-free metadata returned only after a complete descriptor-bound readback.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VerifiedBackupMetadata {
    reservation_id: ReservationId,
    backup_locator: String,
    reservation_binding_sha256: String,
    backup_sha256: String,
    metadata_sha256: String,
    backup_size_bytes: u64,
    reserved_capacity_bytes: u64,
    vault_id: String,
    vault_identity_fingerprint: String,
    physical_parent_fingerprint: String,
    plan_id: String,
    plan_sha256: String,
    approval_id: String,
    approval_sha256: String,
    resource_id: String,
    resource_sha256: String,
}

impl VerifiedBackupMetadata {
    #[must_use]
    pub fn reservation_id(&self) -> &ReservationId {
        &self.reservation_id
    }

    #[must_use]
    pub fn backup_locator(&self) -> &str {
        &self.backup_locator
    }

    #[must_use]
    pub fn reservation_binding_sha256(&self) -> &str {
        &self.reservation_binding_sha256
    }

    #[must_use]
    pub fn backup_sha256(&self) -> &str {
        &self.backup_sha256
    }

    #[must_use]
    pub fn metadata_sha256(&self) -> &str {
        &self.metadata_sha256
    }

    #[must_use]
    pub const fn backup_size_bytes(&self) -> u64 {
        self.backup_size_bytes
    }

    #[must_use]
    pub const fn reserved_capacity_bytes(&self) -> u64 {
        self.reserved_capacity_bytes
    }

    #[must_use]
    pub fn vault_id(&self) -> &str {
        &self.vault_id
    }

    #[must_use]
    pub fn vault_identity_fingerprint(&self) -> &str {
        &self.vault_identity_fingerprint
    }

    #[must_use]
    pub fn physical_parent_fingerprint(&self) -> &str {
        &self.physical_parent_fingerprint
    }

    #[must_use]
    pub fn plan_id(&self) -> &str {
        &self.plan_id
    }

    #[must_use]
    pub fn plan_sha256(&self) -> &str {
        &self.plan_sha256
    }

    #[must_use]
    pub fn approval_id(&self) -> &str {
        &self.approval_id
    }

    #[must_use]
    pub fn approval_sha256(&self) -> &str {
        &self.approval_sha256
    }

    #[must_use]
    pub fn resource_id(&self) -> &str {
        &self.resource_id
    }

    #[must_use]
    pub fn resource_sha256(&self) -> &str {
        &self.resource_sha256
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RepairBackupStatus {
    Absent,
    Reserved(RepairBackupSummary),
    Durable(VerifiedBackupMetadata),
    ReconciliationRequired,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(tag = "type", deny_unknown_fields)]
enum RepairEvent {
    #[serde(rename = "repair.backup.reserve.intent")]
    ReserveIntent {
        #[serde(rename = "reservationId")]
        reservation_id: ReservationId,
        draft: RepairBackupDraft,
        #[serde(rename = "reservationBindingSha256")]
        reservation_binding_sha256: String,
        #[serde(rename = "reservedCapacityBytes")]
        reserved_capacity_bytes: u64,
        #[serde(rename = "vaultId")]
        vault_id: String,
        #[serde(rename = "vaultIdentityFingerprint")]
        vault_identity_fingerprint: String,
        #[serde(rename = "physicalParentFingerprint")]
        physical_parent_fingerprint: String,
    },
    #[serde(rename = "repair.backup.reserve.complete")]
    ReserveComplete {
        #[serde(rename = "reservationId")]
        reservation_id: ReservationId,
    },
    #[serde(rename = "repair.backup.reserve.abort")]
    ReserveAbort {
        #[serde(rename = "reservationId")]
        reservation_id: ReservationId,
    },
    #[serde(rename = "repair.backup.persist.intent")]
    PersistIntent {
        #[serde(rename = "reservationId")]
        reservation_id: ReservationId,
        binding: RepairBinding,
    },
    #[serde(rename = "repair.backup.persist.complete")]
    PersistComplete {
        #[serde(rename = "reservationId")]
        reservation_id: ReservationId,
        #[serde(rename = "backupSha256")]
        backup_sha256: String,
        #[serde(rename = "backupSizeBytes")]
        backup_size_bytes: u64,
    },
    #[serde(rename = "repair.backup.persist.abort")]
    PersistAbort {
        #[serde(rename = "reservationId")]
        reservation_id: ReservationId,
    },
    #[serde(rename = "repair.backup.cancel.intent")]
    CancelIntent {
        #[serde(rename = "reservationId")]
        reservation_id: ReservationId,
    },
    #[serde(rename = "repair.backup.cancel.complete")]
    CancelComplete {
        #[serde(rename = "reservationId")]
        reservation_id: ReservationId,
    },
    #[serde(rename = "repair.backup.retire.intent")]
    RetireIntent {
        #[serde(rename = "reservationId")]
        reservation_id: ReservationId,
    },
    #[serde(rename = "repair.backup.retire.complete")]
    RetireComplete {
        #[serde(rename = "reservationId")]
        reservation_id: ReservationId,
    },
}

struct ReservationRecord {
    draft: RepairBackupDraft,
    reservation_binding_sha256: String,
    reserved_capacity_bytes: u64,
    vault_id: String,
    vault_identity_fingerprint: String,
    physical_parent_fingerprint: String,
    phase: ReservationPhase,
}

#[derive(Clone)]
enum ReservationPhase {
    ReservePending,
    Reserved,
    PersistPending(RepairBinding),
    CancelPending,
    RetirePending(RepairBinding),
    Durable(RepairBinding),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ReleaseOperation {
    Cancel,
    Retire,
}

struct ReleaseTombstone {
    operation: ReleaseOperation,
    record: ReservationRecord,
}

#[derive(Default)]
struct RecoveredState {
    reservations: BTreeMap<ReservationId, ReservationRecord>,
    released: BTreeMap<ReservationId, ReleaseTombstone>,
    seen_reservation_ids: BTreeSet<ReservationId>,
    pending: Option<ReservationId>,
}

struct FilesystemState {
    device: u64,
    inode: u64,
    size: i64,
    blocks: i64,
    mode: u32,
    uid: u32,
    gid: u32,
    links: u64,
}

impl FilesystemState {
    fn from_stat(stat: &Stat) -> Self {
        Self {
            device: stat.st_dev,
            inode: stat.st_ino,
            size: stat.st_size,
            blocks: stat.st_blocks,
            mode: stat.st_mode,
            uid: stat.st_uid,
            gid: stat.st_gid,
            links: stat.st_nlink,
        }
    }

    fn same_object(&self, other: &Self) -> bool {
        self.device == other.device && self.inode == other.inode
    }
}

/// Exclusive handle for the isolated Repair Vault namespace.
pub struct RepairVaultStore<'vault> {
    inner: &'vault VaultInner,
    namespace_fd: OwnedFd,
    namespace_state: FilesystemState,
    backups_fd: OwnedFd,
    backups_state: FilesystemState,
    _lock_fd: OwnedFd,
    journal: SecureJournal<RepairJournalSecretStore<'vault>>,
    state: RecoveredState,
    vault_id: String,
    vault_identity_fingerprint: String,
    physical_parent_fingerprint: String,
    event_count: u64,
    checked_out: BTreeSet<ReservationId>,
    healthy: bool,
    _repair_guard: MutexGuard<'vault, ()>,
}

impl<'vault> RepairVaultStore<'vault> {
    pub(crate) fn open(inner: &'vault VaultInner) -> Result<Self, RepairVaultStoreError> {
        let repair_guard = inner
            .repair_guard()
            .map_err(|_| RepairVaultStoreError::StorageUnavailable)?;
        inner
            .ensure_integrity()
            .map_err(|_| RepairVaultStoreError::CorruptStore)?;
        // Fail before creating any namespace object when the mount attestation
        // cannot prove the physical parent of the boot Vault.
        let (vault_id, vault_identity_fingerprint, physical_parent_fingerprint) =
            vault_fingerprints(inner)?;
        let (namespace_fd, namespace_state, backups_fd, backups_state, lock_fd) =
            initialize_namespace(inner)?;
        cleanup_repair_secret_orphan(
            inner,
            &namespace_fd,
            inner.owner(),
            inner.root_device(),
            inner.root_mount_id(),
        )?;
        let journal_descriptor = rustix::io::fcntl_dupfd_cloexec(&namespace_fd, 3)
            .map_err(|_| RepairVaultStoreError::StorageUnavailable)?;
        let journal_path = inner
            .root_path()
            .join(REPAIR_NAMESPACE)
            .join(JOURNAL_DATABASE_NAME);
        let mut journal = SecureJournal::open(
            &journal_path,
            RepairJournalSecretStore {
                inner,
                directory: journal_descriptor,
                directory_state: FilesystemState {
                    device: namespace_state.device,
                    inode: namespace_state.inode,
                    size: namespace_state.size,
                    blocks: namespace_state.blocks,
                    mode: namespace_state.mode,
                    uid: namespace_state.uid,
                    gid: namespace_state.gid,
                    links: namespace_state.links,
                },
            },
        )
        .map_err(|_| RepairVaultStoreError::CorruptJournal)?;
        let replay_limits =
            JournalReplayLimits::new(MAX_JOURNAL_EVENTS, MAX_JOURNAL_EVENTS * MAX_EVENT_BYTES)
                .map_err(|_| RepairVaultStoreError::CorruptJournal)?;
        let (state, replay) = journal
            .fold(
                replay_limits,
                RecoveredState::default(),
                replay_repair_event,
            )
            .map_err(|_| RepairVaultStoreError::CorruptJournal)?;
        let mut store = Self {
            inner,
            namespace_fd,
            namespace_state,
            backups_fd,
            backups_state,
            _lock_fd: lock_fd,
            journal,
            state,
            vault_id,
            vault_identity_fingerprint,
            physical_parent_fingerprint,
            event_count: replay.entries,
            checked_out: BTreeSet::new(),
            healthy: true,
            _repair_guard: repair_guard,
        };
        // Journal records are durable across remounts and reboots.  Authenticate
        // their stable Vault identity before recovery is allowed to mutate any
        // backing object or append a reconciliation event.  Live mount and
        // block-parent claims are checked separately at Reserved authority use.
        store.verify_recovered_vault_identity()?;
        store.reconcile_pending()?;
        store.validate_layout()?;
        Ok(store)
    }

    /// Allocate, synchronize and read back the requested capacity before
    /// returning an opaque reservation capability.
    pub fn reserve_backup(
        &mut self,
        draft: RepairBackupDraft,
    ) -> Result<ReservedRepairBackup, RepairVaultStoreError> {
        draft.validate()?;
        self.require_mutable()?;
        self.require_event_capacity(2)?;
        if self.state.reservations.len() >= MAX_RESERVATIONS {
            return Err(RepairVaultStoreError::InsufficientCapacity);
        }
        let reservation_id = self.generate_unused_reservation_id()?;
        let reservation_binding_sha256 = reservation_binding(&draft);
        let reserved_capacity_bytes = draft.required_capacity_bytes;
        self.append_event(RepairEvent::ReserveIntent {
            reservation_id: reservation_id.clone(),
            draft,
            reservation_binding_sha256: reservation_binding_sha256.clone(),
            reserved_capacity_bytes,
            vault_id: self.vault_id.clone(),
            vault_identity_fingerprint: self.vault_identity_fingerprint.clone(),
            physical_parent_fingerprint: self.physical_parent_fingerprint.clone(),
        })?;
        if let Err(error) = self.allocate_and_verify(&reservation_id, reserved_capacity_bytes) {
            self.healthy = false;
            return Err(error);
        }
        self.append_event(RepairEvent::ReserveComplete {
            reservation_id: reservation_id.clone(),
        })?;
        self.reserved_capability(&reservation_id)
    }

    /// Persist an exact read-only source descriptor into an existing physical
    /// reservation, fsync it, and byte-verify it before committing completion.
    pub fn persist_backup(
        &mut self,
        reservation: ReservedRepairBackup,
        binding: RepairBinding,
        source: OwnedFd,
    ) -> Result<DurableRepairBackup, RepairVaultStoreError> {
        self.persist_backup_until(
            reservation,
            binding,
            source,
            Instant::now() + DEFAULT_SOURCE_DEADLINE,
        )
    }

    /// Persist from an anonymous pipe, bounded by an absolute deadline.
    pub fn persist_backup_until(
        &mut self,
        reservation: ReservedRepairBackup,
        binding: RepairBinding,
        source: OwnedFd,
        deadline: Instant,
    ) -> Result<DurableRepairBackup, RepairVaultStoreError> {
        binding.validate()?;
        self.require_mutable()?;
        self.require_event_capacity(2)?;
        self.consume_checkout(reservation.reservation_id())?;
        let record = self
            .state
            .reservations
            .get(reservation.reservation_id())
            .ok_or(RepairVaultStoreError::ReservationNotFound)?;
        self.verify_record_live_parent(record)?;
        if binding.resource_sha256 != record.draft.expected_backup_sha256 {
            return Err(RepairVaultStoreError::InvalidBinding);
        }
        if !matches!(record.phase, ReservationPhase::Reserved)
            || reservation.reservation_binding_sha256() != record.reservation_binding_sha256
            || reservation.reserved_capacity_bytes() != record.reserved_capacity_bytes
            || reservation.vault_identity_fingerprint() != self.vault_identity_fingerprint
            || reservation.physical_parent_fingerprint() != self.physical_parent_fingerprint
        {
            return Err(RepairVaultStoreError::ReservationConflict);
        }
        let expected_size = record.draft.backup_size_bytes;
        let expected_sha256 = record.draft.expected_backup_sha256;
        let reserved_capacity_bytes = record.reserved_capacity_bytes;
        let bytes = read_source(source, expected_size, expected_sha256, deadline)?;
        self.append_event(RepairEvent::PersistIntent {
            reservation_id: reservation.reservation_id().clone(),
            binding,
        })?;
        if let Err(error) = self.install_and_verify(
            reservation.reservation_id(),
            bytes.as_slice(),
            expected_size,
            expected_sha256,
            reserved_capacity_bytes,
        ) {
            self.healthy = false;
            return Err(error);
        }
        self.append_event(RepairEvent::PersistComplete {
            reservation_id: reservation.reservation_id().clone(),
            backup_sha256: encode_hex(&expected_sha256),
            backup_size_bytes: expected_size,
        })?;
        Ok(DurableRepairBackup {
            metadata: self.verified_metadata(reservation.reservation_id())?,
        })
    }

    /// Cancel one checked-out, still-empty reservation capability.
    pub fn cancel_reservation(
        &mut self,
        reservation: ReservedRepairBackup,
    ) -> Result<(), RepairVaultStoreError> {
        self.consume_checkout(reservation.reservation_id())?;
        self.cancel_reserved(
            reservation.reservation_id(),
            reservation.reservation_binding_sha256(),
        )
        .map(|_| ())
    }

    /// Cancel a stable Reserved reservation using only its opaque identifier
    /// and exact draft binding. This lifecycle release deliberately does not
    /// re-mint live-parent write authority.
    pub fn cancel_reserved(
        &mut self,
        reservation_id: &ReservationId,
        reservation_binding_sha256: &str,
    ) -> Result<u64, RepairVaultStoreError> {
        self.require_mutable()?;
        if !valid_sha256(reservation_binding_sha256) {
            return Err(RepairVaultStoreError::ReservationConflict);
        }
        if let Some(released) = self.state.released.get(reservation_id) {
            self.verify_release_tombstone(released)?;
            if released.operation == ReleaseOperation::Cancel
                && released.record.reservation_binding_sha256 == reservation_binding_sha256
            {
                return Ok(released.record.reserved_capacity_bytes);
            }
            return Err(RepairVaultStoreError::ReservationConflict);
        }
        self.require_event_capacity(2)?;
        let record = self
            .state
            .reservations
            .get(reservation_id)
            .ok_or(RepairVaultStoreError::ReservationNotFound)?;
        self.verify_record_vault_identity(record)?;
        if !matches!(record.phase, ReservationPhase::Reserved)
            || reservation_binding_sha256 != record.reservation_binding_sha256
        {
            return Err(RepairVaultStoreError::ReservationConflict);
        }
        self.verify_reserved_file(reservation_id, record)?;
        let released_bytes = record.reserved_capacity_bytes;
        let reservation_id = reservation_id.clone();
        self.checked_out.remove(&reservation_id);
        self.append_event(RepairEvent::CancelIntent {
            reservation_id: reservation_id.clone(),
        })?;
        if let Some((_, existing)) =
            self.open_pending_backup_file(&reservation_id, OFlags::RDONLY)?
        {
            self.remove_pending_backup_file(&reservation_id, &existing)?;
        }
        self.append_event(RepairEvent::CancelComplete { reservation_id })?;
        Ok(released_bytes)
    }

    /// Crash-safely retire one exact Durable backup. The caller must present
    /// every immutable reservation field and the complete persisted
    /// plan/approval/resource binding as returned by the store.
    pub fn retire_backup(
        &mut self,
        expected: &VerifiedBackupMetadata,
    ) -> Result<u64, RepairVaultStoreError> {
        self.require_mutable()?;
        if let Some(released) = self.state.released.get(expected.reservation_id()) {
            self.verify_release_tombstone(released)?;
            if released.operation == ReleaseOperation::Retire
                && self.released_verified_metadata(expected.reservation_id(), released)?
                    == *expected
            {
                return Ok(released.record.reserved_capacity_bytes);
            }
            return Err(RepairVaultStoreError::ReservationConflict);
        }
        self.require_event_capacity(2)?;
        let record = self
            .state
            .reservations
            .get(expected.reservation_id())
            .ok_or(RepairVaultStoreError::ReservationNotFound)?;
        self.verify_record_vault_identity(record)?;
        if !matches!(record.phase, ReservationPhase::Durable(_))
            || self.verified_metadata(expected.reservation_id())? != *expected
        {
            return Err(RepairVaultStoreError::ReservationConflict);
        }
        self.verify_durable_file(expected.reservation_id(), record)?;
        let released_bytes = record.reserved_capacity_bytes;
        let reservation_id = expected.reservation_id().clone();
        self.append_event(RepairEvent::RetireIntent {
            reservation_id: reservation_id.clone(),
        })?;
        if let Some((_, existing)) =
            self.open_pending_backup_file(&reservation_id, OFlags::RDONLY)?
        {
            self.remove_pending_backup_file(&reservation_id, &existing)?;
        }
        self.append_event(RepairEvent::RetireComplete { reservation_id })?;
        Ok(released_bytes)
    }

    /// Rehydrate a reserved capability from authenticated journal state after
    /// a worker restart or a separate protocol connection. The caller must
    /// present the exact pre-plan draft binding returned by reservation.
    pub fn resume_reserved(
        &mut self,
        reservation_id: &ReservationId,
        reservation_binding_sha256: &str,
    ) -> Result<ReservedRepairBackup, RepairVaultStoreError> {
        if !self.healthy || self.state.pending.is_some() {
            return Err(RepairVaultStoreError::ReconciliationRequired);
        }
        if !valid_sha256(reservation_binding_sha256) {
            return Err(RepairVaultStoreError::ReservationConflict);
        }
        let record = self
            .state
            .reservations
            .get(reservation_id)
            .ok_or(RepairVaultStoreError::ReservationNotFound)?;
        self.verify_record_live_parent(record)?;
        if !matches!(record.phase, ReservationPhase::Reserved)
            || record.reservation_binding_sha256 != reservation_binding_sha256
        {
            return Err(RepairVaultStoreError::ReservationConflict);
        }
        self.verify_reserved_file(reservation_id, record)?;
        self.reserved_capability(reservation_id)
    }

    /// Return authenticated state without exposing a backing path.
    pub fn backup_status(
        &self,
        reservation_id: &ReservationId,
        reservation_binding_sha256: &str,
    ) -> Result<RepairBackupStatus, RepairVaultStoreError> {
        self.validate_store_boundary()?;
        if self.state.pending.is_some() {
            return Ok(RepairBackupStatus::ReconciliationRequired);
        }
        let Some(record) = self.state.reservations.get(reservation_id) else {
            if let Some(released) = self.state.released.get(reservation_id) {
                self.verify_release_tombstone(released)?;
                if released.record.reservation_binding_sha256 != reservation_binding_sha256 {
                    return Err(RepairVaultStoreError::ReservationConflict);
                }
            }
            return Ok(RepairBackupStatus::Absent);
        };
        self.verify_record_vault_identity(record)?;
        if record.reservation_binding_sha256 != reservation_binding_sha256 {
            return Err(RepairVaultStoreError::ReservationConflict);
        }
        match &record.phase {
            ReservationPhase::ReservePending
            | ReservationPhase::PersistPending(_)
            | ReservationPhase::CancelPending
            | ReservationPhase::RetirePending(_) => Ok(RepairBackupStatus::ReconciliationRequired),
            ReservationPhase::Reserved => {
                self.verify_reserved_file(reservation_id, record)?;
                Ok(RepairBackupStatus::Reserved(
                    self.reservation_summary(reservation_id)?,
                ))
            }
            ReservationPhase::Durable(_) => {
                self.verify_durable_file(reservation_id, record)?;
                Ok(RepairBackupStatus::Durable(
                    self.verified_metadata(reservation_id)?,
                ))
            }
        }
    }

    /// Verify the complete durable backup, lend a size-bounded reader to the
    /// callback, and verify the same descriptor and named object again.
    pub fn with_verified_backup<F>(
        &self,
        reservation_id: &ReservationId,
        reservation_binding_sha256: &str,
        callback: F,
    ) -> Result<VerifiedBackupMetadata, RepairVaultStoreError>
    where
        F: FnOnce(&mut dyn Read) -> Result<(), RepairVaultStoreError>,
    {
        if !self.healthy || self.state.pending.is_some() {
            return Err(RepairVaultStoreError::ReconciliationRequired);
        }
        let record = self
            .state
            .reservations
            .get(reservation_id)
            .ok_or(RepairVaultStoreError::ReservationNotFound)?;
        self.verify_record_vault_identity(record)?;
        if record.reservation_binding_sha256 != reservation_binding_sha256 {
            return Err(RepairVaultStoreError::ReservationConflict);
        }
        if !matches!(record.phase, ReservationPhase::Durable(_)) {
            return Err(RepairVaultStoreError::ReservationNotReady);
        }
        let (mut file, before) = self.open_backup_file(reservation_id, OFlags::RDONLY)?;
        verify_file_contents(&mut file, record, false)?;
        file.seek(SeekFrom::Start(0))
            .map_err(|_| RepairVaultStoreError::StorageUnavailable)?;
        let callback_result = {
            let mut limited = Read::by_ref(&mut file).take(record.draft.backup_size_bytes);
            let result = callback(&mut limited);
            if result.is_ok() && limited.limit() != 0 {
                Err(RepairVaultStoreError::WriteVerificationFailed)
            } else {
                result
            }
        };
        verify_file_contents(&mut file, record, false)?;
        let after = validate_regular_file(
            &file,
            self.inner.owner(),
            self.inner.root_device(),
            self.inner.root_mount_id(),
            Some(record.reserved_capacity_bytes),
        )?;
        let named = named_file_state(
            &self.backups_fd,
            &backup_filename(reservation_id),
            self.inner.owner(),
            self.inner.root_device(),
            Some(record.reserved_capacity_bytes),
        )?;
        if !before.same_object(&after) || !after.same_object(&named) {
            return Err(RepairVaultStoreError::ConcurrentWrite);
        }
        callback_result?;
        self.verified_metadata(reservation_id)
    }

    fn require_mutable(&self) -> Result<(), RepairVaultStoreError> {
        if !self.healthy || self.state.pending.is_some() {
            return Err(RepairVaultStoreError::ReconciliationRequired);
        }
        self.validate_store_boundary()
    }

    fn require_event_capacity(&self, required: u64) -> Result<(), RepairVaultStoreError> {
        if self.event_count.saturating_add(required) > MAX_JOURNAL_EVENTS {
            Err(RepairVaultStoreError::InsufficientCapacity)
        } else {
            Ok(())
        }
    }

    fn verify_recovered_vault_identity(&self) -> Result<(), RepairVaultStoreError> {
        for record in self.state.reservations.values() {
            self.verify_record_vault_identity(record)?;
        }
        for released in self.state.released.values() {
            self.verify_release_tombstone(released)?;
        }
        Ok(())
    }

    fn verify_record_vault_identity(
        &self,
        record: &ReservationRecord,
    ) -> Result<(), RepairVaultStoreError> {
        if record.vault_id != self.vault_id
            || record.vault_identity_fingerprint != self.vault_identity_fingerprint
        {
            Err(RepairVaultStoreError::ReservationConflict)
        } else {
            Ok(())
        }
    }

    fn verify_record_live_parent(
        &self,
        record: &ReservationRecord,
    ) -> Result<(), RepairVaultStoreError> {
        self.verify_record_vault_identity(record)?;
        if record.physical_parent_fingerprint != self.physical_parent_fingerprint {
            Err(RepairVaultStoreError::ReservationConflict)
        } else {
            Ok(())
        }
    }

    fn verify_release_tombstone(
        &self,
        released: &ReleaseTombstone,
    ) -> Result<(), RepairVaultStoreError> {
        self.verify_record_vault_identity(&released.record)?;
        match (&released.operation, &released.record.phase) {
            (ReleaseOperation::Cancel, ReservationPhase::CancelPending)
            | (ReleaseOperation::Retire, ReservationPhase::RetirePending(_)) => Ok(()),
            _ => Err(RepairVaultStoreError::CorruptJournal),
        }
    }

    fn consume_checkout(
        &mut self,
        reservation_id: &ReservationId,
    ) -> Result<(), RepairVaultStoreError> {
        if self.checked_out.remove(reservation_id) {
            Ok(())
        } else {
            Err(RepairVaultStoreError::ReservationConflict)
        }
    }

    fn append_event(&mut self, event: RepairEvent) -> Result<(), RepairVaultStoreError> {
        // Enforce the authenticated replay bound before persistence: an event
        // that could never be replayed must never become durable.
        if self.event_count >= MAX_JOURNAL_EVENTS {
            return Err(RepairVaultStoreError::InsufficientCapacity);
        }
        let encoded =
            serde_json::to_vec(&event).map_err(|_| RepairVaultStoreError::CorruptStore)?;
        if encoded.len() as u64 > MAX_EVENT_BYTES {
            return Err(RepairVaultStoreError::CorruptStore);
        }
        let entry = match self.journal.append(&encoded) {
            Ok(entry) => entry,
            Err(_) => {
                self.healthy = false;
                return Err(RepairVaultStoreError::CorruptJournal);
            }
        };
        let borrowed = JournalEntryRef {
            sequence: entry.sequence,
            event: &entry.event,
            previous_hash: entry.previous_hash,
            entry_hash: entry.entry_hash,
        };
        if apply_repair_event(&mut self.state, event, borrowed).is_err() {
            self.healthy = false;
            return Err(RepairVaultStoreError::CorruptJournal);
        }
        self.event_count = self
            .event_count
            .checked_add(1)
            .ok_or(RepairVaultStoreError::CorruptJournal)?;
        Ok(())
    }

    fn generate_unused_reservation_id(&self) -> Result<ReservationId, RepairVaultStoreError> {
        for _ in 0..16 {
            let candidate = ReservationId::generate();
            if !self.state.seen_reservation_ids.contains(&candidate)
                && named_optional_state(
                    &self.backups_fd,
                    &backup_filename(&candidate),
                    self.inner.owner(),
                    self.inner.root_device(),
                    None,
                )?
                .is_none()
            {
                return Ok(candidate);
            }
        }
        Err(RepairVaultStoreError::StorageUnavailable)
    }

    fn reserved_capability(
        &mut self,
        reservation_id: &ReservationId,
    ) -> Result<ReservedRepairBackup, RepairVaultStoreError> {
        let record = self
            .state
            .reservations
            .get(reservation_id)
            .ok_or(RepairVaultStoreError::ReservationNotFound)?;
        if !matches!(record.phase, ReservationPhase::Reserved) {
            return Err(RepairVaultStoreError::ReservationNotReady);
        }
        let summary = self.reservation_summary(reservation_id)?;
        if !self.checked_out.insert(reservation_id.clone()) {
            return Err(RepairVaultStoreError::ReservationConflict);
        }
        Ok(ReservedRepairBackup { summary })
    }

    fn reservation_summary(
        &self,
        reservation_id: &ReservationId,
    ) -> Result<RepairBackupSummary, RepairVaultStoreError> {
        let record = self
            .state
            .reservations
            .get(reservation_id)
            .ok_or(RepairVaultStoreError::ReservationNotFound)?;
        Ok(RepairBackupSummary {
            reservation_id: reservation_id.clone(),
            backup_locator: backup_locator(reservation_id),
            reservation_binding_sha256: record.reservation_binding_sha256.clone(),
            vault_id: record.vault_id.clone(),
            vault_identity_fingerprint: record.vault_identity_fingerprint.clone(),
            physical_parent_fingerprint: record.physical_parent_fingerprint.clone(),
            reserved_capacity_bytes: record.reserved_capacity_bytes,
            backup_size_bytes: record.draft.backup_size_bytes,
            expected_backup_sha256: encode_hex(&record.draft.expected_backup_sha256),
            metadata_sha256: encode_hex(&record.draft.metadata_sha256),
        })
    }

    fn verified_metadata(
        &self,
        reservation_id: &ReservationId,
    ) -> Result<VerifiedBackupMetadata, RepairVaultStoreError> {
        let record = self
            .state
            .reservations
            .get(reservation_id)
            .ok_or(RepairVaultStoreError::ReservationNotFound)?;
        let ReservationPhase::Durable(binding) = &record.phase else {
            return Err(RepairVaultStoreError::ReservationNotReady);
        };
        Ok(verified_metadata_from_record(
            reservation_id,
            record,
            binding,
        ))
    }

    fn released_verified_metadata(
        &self,
        reservation_id: &ReservationId,
        released: &ReleaseTombstone,
    ) -> Result<VerifiedBackupMetadata, RepairVaultStoreError> {
        self.verify_release_tombstone(released)?;
        let ReservationPhase::RetirePending(binding) = &released.record.phase else {
            return Err(RepairVaultStoreError::ReservationConflict);
        };
        Ok(verified_metadata_from_record(
            reservation_id,
            &released.record,
            binding,
        ))
    }

    fn allocate_and_verify(
        &self,
        reservation_id: &ReservationId,
        capacity: u64,
    ) -> Result<(), RepairVaultStoreError> {
        let _guard = self
            .inner
            .operation_guard()
            .map_err(|_| RepairVaultStoreError::StorageUnavailable)?;
        self.validate_store_boundary_unlocked()?;
        let name = backup_filename(reservation_id);
        let descriptor = open_child(
            &self.backups_fd,
            Path::new(&name),
            OFlags::RDWR | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::RUSR | Mode::WUSR,
        )
        .map_err(|error| {
            if error == rustix::io::Errno::EXIST {
                RepairVaultStoreError::ReservationConflict
            } else if error == rustix::io::Errno::NOSPC {
                RepairVaultStoreError::InsufficientCapacity
            } else {
                RepairVaultStoreError::StorageUnavailable
            }
        })?;
        rfs::fchmod(&descriptor, Mode::RUSR | Mode::WUSR)
            .map_err(|_| RepairVaultStoreError::StorageUnavailable)?;
        rfs::fallocate(&descriptor, FallocateFlags::empty(), 0, capacity).map_err(|error| {
            if error == rustix::io::Errno::NOSPC || error == rustix::io::Errno::FBIG {
                RepairVaultStoreError::InsufficientCapacity
            } else {
                RepairVaultStoreError::StorageUnavailable
            }
        })?;
        rfs::fsync(&descriptor).map_err(|_| RepairVaultStoreError::StorageUnavailable)?;
        let state = validate_regular_file(
            &descriptor,
            self.inner.owner(),
            self.inner.root_device(),
            self.inner.root_mount_id(),
            Some(capacity),
        )?;
        require_physical_allocation(&state, capacity)?;
        rfs::fsync(&self.backups_fd).map_err(|_| RepairVaultStoreError::StorageUnavailable)?;
        let named = named_file_state(
            &self.backups_fd,
            &name,
            self.inner.owner(),
            self.inner.root_device(),
            Some(capacity),
        )?;
        if !state.same_object(&named) {
            return Err(RepairVaultStoreError::ConcurrentWrite);
        }
        let mut file = File::from(descriptor);
        verify_zero_filled(&mut file, capacity)?;
        self.validate_store_boundary_unlocked()
    }

    fn install_and_verify(
        &self,
        reservation_id: &ReservationId,
        bytes: &[u8],
        expected_size: u64,
        expected_sha256: [u8; 32],
        capacity: u64,
    ) -> Result<(), RepairVaultStoreError> {
        let _guard = self
            .inner
            .operation_guard()
            .map_err(|_| RepairVaultStoreError::StorageUnavailable)?;
        self.validate_store_boundary_unlocked()?;
        let (mut file, before) = self.open_backup_file_unlocked(reservation_id, OFlags::RDWR)?;
        file.seek(SeekFrom::Start(0))
            .map_err(|_| RepairVaultStoreError::StorageUnavailable)?;
        file.write_all(bytes)
            .map_err(|_| RepairVaultStoreError::StorageUnavailable)?;
        file.flush()
            .map_err(|_| RepairVaultStoreError::StorageUnavailable)?;
        file.sync_all()
            .map_err(|_| RepairVaultStoreError::StorageUnavailable)?;
        rfs::fsync(&self.backups_fd).map_err(|_| RepairVaultStoreError::StorageUnavailable)?;
        let after = validate_regular_file(
            &file,
            self.inner.owner(),
            self.inner.root_device(),
            self.inner.root_mount_id(),
            Some(capacity),
        )?;
        let named = named_file_state(
            &self.backups_fd,
            &backup_filename(reservation_id),
            self.inner.owner(),
            self.inner.root_device(),
            Some(capacity),
        )?;
        if !before.same_object(&after) || !after.same_object(&named) {
            return Err(RepairVaultStoreError::ConcurrentWrite);
        }
        let temporary_record = ReservationRecord {
            draft: RepairBackupDraft {
                session_id: "S-verification".to_owned(),
                target_id: "verification".to_owned(),
                target_fingerprint: [1; 32],
                expected_backup_sha256: expected_sha256,
                metadata_sha256: [1; 32],
                backup_size_bytes: expected_size,
                required_capacity_bytes: capacity,
            },
            reservation_binding_sha256: String::new(),
            reserved_capacity_bytes: capacity,
            vault_id: "V-verification".to_owned(),
            vault_identity_fingerprint: "00".repeat(32),
            physical_parent_fingerprint: "00".repeat(32),
            phase: ReservationPhase::Reserved,
        };
        verify_file_contents(&mut file, &temporary_record, false)?;
        self.validate_store_boundary_unlocked()
    }

    fn verify_reserved_file(
        &self,
        reservation_id: &ReservationId,
        record: &ReservationRecord,
    ) -> Result<(), RepairVaultStoreError> {
        let (mut file, _) = self.open_backup_file(reservation_id, OFlags::RDONLY)?;
        verify_file_contents(&mut file, record, true)
    }

    fn verify_durable_file(
        &self,
        reservation_id: &ReservationId,
        record: &ReservationRecord,
    ) -> Result<(), RepairVaultStoreError> {
        let (mut file, _) = self.open_backup_file(reservation_id, OFlags::RDONLY)?;
        verify_file_contents(&mut file, record, false)
    }

    fn open_backup_file(
        &self,
        reservation_id: &ReservationId,
        flags: OFlags,
    ) -> Result<(File, FilesystemState), RepairVaultStoreError> {
        let _guard = self
            .inner
            .operation_guard()
            .map_err(|_| RepairVaultStoreError::StorageUnavailable)?;
        self.validate_store_boundary_unlocked()?;
        self.open_backup_file_unlocked(reservation_id, flags)
    }

    fn open_backup_file_unlocked(
        &self,
        reservation_id: &ReservationId,
        flags: OFlags,
    ) -> Result<(File, FilesystemState), RepairVaultStoreError> {
        let record = self
            .state
            .reservations
            .get(reservation_id)
            .ok_or(RepairVaultStoreError::ReservationNotFound)?;
        let name = backup_filename(reservation_id);
        let descriptor = open_child(
            &self.backups_fd,
            Path::new(&name),
            flags | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .map_err(|_| RepairVaultStoreError::CorruptStore)?;
        let state = validate_regular_file(
            &descriptor,
            self.inner.owner(),
            self.inner.root_device(),
            self.inner.root_mount_id(),
            Some(record.reserved_capacity_bytes),
        )?;
        require_physical_allocation(&state, record.reserved_capacity_bytes)?;
        let named = named_file_state(
            &self.backups_fd,
            &name,
            self.inner.owner(),
            self.inner.root_device(),
            Some(record.reserved_capacity_bytes),
        )?;
        if !state.same_object(&named) {
            return Err(RepairVaultStoreError::ConcurrentWrite);
        }
        Ok((File::from(descriptor), state))
    }

    fn reconcile_pending(&mut self) -> Result<(), RepairVaultStoreError> {
        let Some(reservation_id) = self.state.pending.clone() else {
            return Ok(());
        };
        let record = self
            .state
            .reservations
            .get(&reservation_id)
            .ok_or(RepairVaultStoreError::CorruptJournal)?;
        let phase = record.phase.clone();
        let capacity = record.reserved_capacity_bytes;
        let backup_size = record.draft.backup_size_bytes;
        let backup_sha256 = record.draft.expected_backup_sha256;
        match phase {
            ReservationPhase::ReservePending => {
                let observed = self.open_pending_backup_file(&reservation_id, OFlags::RDONLY)?;
                let complete = match observed {
                    Some((mut file, state)) => {
                        if exact_allocation(&state, capacity) {
                            match verify_zero_filled(&mut file, capacity) {
                                Ok(()) => true,
                                Err(RepairVaultStoreError::WriteVerificationFailed) => false,
                                Err(error) => return Err(error),
                            }
                        } else {
                            false
                        }
                    }
                    None => false,
                };
                if complete {
                    self.append_event(RepairEvent::ReserveComplete { reservation_id })
                } else {
                    if let Some((_, state)) =
                        self.open_pending_backup_file(&reservation_id, OFlags::RDONLY)?
                    {
                        self.remove_pending_backup_file(&reservation_id, &state)?;
                    }
                    self.append_event(RepairEvent::ReserveAbort { reservation_id })
                }
            }
            ReservationPhase::PersistPending(_) => {
                let observed = self.open_pending_backup_file(&reservation_id, OFlags::RDONLY)?;
                let durable = match observed {
                    Some((mut file, state)) => {
                        if exact_allocation(&state, capacity) {
                            match verify_file_contents(&mut file, record, false) {
                                Ok(()) => true,
                                Err(RepairVaultStoreError::WriteVerificationFailed) => false,
                                Err(error) => return Err(error),
                            }
                        } else {
                            false
                        }
                    }
                    None => false,
                };
                if durable {
                    self.append_event(RepairEvent::PersistComplete {
                        reservation_id,
                        backup_sha256: encode_hex(&backup_sha256),
                        backup_size_bytes: backup_size,
                    })
                } else {
                    let expected = self
                        .open_pending_backup_file(&reservation_id, OFlags::RDONLY)?
                        .map(|(_, state)| state);
                    self.reset_pending_backup_file(&reservation_id, expected.as_ref(), capacity)?;
                    self.append_event(RepairEvent::PersistAbort { reservation_id })
                }
            }
            ReservationPhase::CancelPending => {
                if let Some((_, state)) =
                    self.open_pending_backup_file(&reservation_id, OFlags::RDONLY)?
                {
                    self.remove_pending_backup_file(&reservation_id, &state)?;
                }
                self.append_event(RepairEvent::CancelComplete { reservation_id })
            }
            ReservationPhase::RetirePending(_) => {
                if let Some((_, state)) =
                    self.open_pending_backup_file(&reservation_id, OFlags::RDONLY)?
                {
                    self.remove_pending_backup_file(&reservation_id, &state)?;
                }
                self.append_event(RepairEvent::RetireComplete { reservation_id })
            }
            ReservationPhase::Reserved | ReservationPhase::Durable(_) => {
                Err(RepairVaultStoreError::CorruptJournal)
            }
        }
    }

    fn open_pending_backup_file(
        &self,
        reservation_id: &ReservationId,
        flags: OFlags,
    ) -> Result<Option<(File, FilesystemState)>, RepairVaultStoreError> {
        let _guard = self
            .inner
            .operation_guard()
            .map_err(|_| RepairVaultStoreError::StorageUnavailable)?;
        self.validate_store_boundary_unlocked()?;
        let name = backup_filename(reservation_id);
        let descriptor = match open_child(
            &self.backups_fd,
            Path::new(&name),
            flags | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        ) {
            Ok(descriptor) => descriptor,
            Err(error) if error == rustix::io::Errno::NOENT => return Ok(None),
            Err(_) => return Err(RepairVaultStoreError::CorruptStore),
        };
        let state = validate_regular_file(
            &descriptor,
            self.inner.owner(),
            self.inner.root_device(),
            self.inner.root_mount_id(),
            None,
        )?;
        let named = named_file_state(
            &self.backups_fd,
            &name,
            self.inner.owner(),
            self.inner.root_device(),
            None,
        )?;
        if !state.same_object(&named) || state.size != named.size {
            return Err(RepairVaultStoreError::ConcurrentWrite);
        }
        Ok(Some((File::from(descriptor), state)))
    }

    fn remove_pending_backup_file(
        &self,
        reservation_id: &ReservationId,
        expected: &FilesystemState,
    ) -> Result<(), RepairVaultStoreError> {
        let _guard = self
            .inner
            .operation_guard()
            .map_err(|_| RepairVaultStoreError::StorageUnavailable)?;
        self.validate_store_boundary_unlocked()?;
        let name = backup_filename(reservation_id);
        let named = named_file_state(
            &self.backups_fd,
            &name,
            self.inner.owner(),
            self.inner.root_device(),
            None,
        )?;
        if !named.same_object(expected) || named.size != expected.size {
            return Err(RepairVaultStoreError::ConcurrentWrite);
        }
        rfs::unlinkat(&self.backups_fd, &name, AtFlags::empty())
            .map_err(|_| RepairVaultStoreError::ConcurrentWrite)?;
        rfs::fsync(&self.backups_fd).map_err(|_| RepairVaultStoreError::StorageUnavailable)?;
        if named_optional_state(
            &self.backups_fd,
            &name,
            self.inner.owner(),
            self.inner.root_device(),
            None,
        )?
        .is_some()
        {
            return Err(RepairVaultStoreError::ConcurrentWrite);
        }
        self.validate_store_boundary_unlocked()
    }

    fn reset_pending_backup_file(
        &self,
        reservation_id: &ReservationId,
        expected: Option<&FilesystemState>,
        capacity: u64,
    ) -> Result<(), RepairVaultStoreError> {
        let _guard = self
            .inner
            .operation_guard()
            .map_err(|_| RepairVaultStoreError::StorageUnavailable)?;
        self.validate_store_boundary_unlocked()?;
        let name = backup_filename(reservation_id);
        let descriptor = match expected {
            Some(expected) => {
                let descriptor = open_child(
                    &self.backups_fd,
                    Path::new(&name),
                    OFlags::RDWR | OFlags::NOFOLLOW | OFlags::CLOEXEC,
                    Mode::empty(),
                )
                .map_err(|_| RepairVaultStoreError::ConcurrentWrite)?;
                let state = validate_regular_file(
                    &descriptor,
                    self.inner.owner(),
                    self.inner.root_device(),
                    self.inner.root_mount_id(),
                    None,
                )?;
                let named = named_file_state(
                    &self.backups_fd,
                    &name,
                    self.inner.owner(),
                    self.inner.root_device(),
                    None,
                )?;
                if !state.same_object(expected)
                    || state.size != expected.size
                    || !state.same_object(&named)
                {
                    return Err(RepairVaultStoreError::ConcurrentWrite);
                }
                descriptor
            }
            None => open_child(
                &self.backups_fd,
                Path::new(&name),
                OFlags::RDWR | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW | OFlags::CLOEXEC,
                Mode::RUSR | Mode::WUSR,
            )
            .map_err(|_| RepairVaultStoreError::ConcurrentWrite)?,
        };
        rfs::fchmod(&descriptor, Mode::RUSR | Mode::WUSR)
            .map_err(|_| RepairVaultStoreError::StorageUnavailable)?;
        rfs::ftruncate(&descriptor, 0).map_err(|_| RepairVaultStoreError::StorageUnavailable)?;
        rfs::fallocate(&descriptor, FallocateFlags::empty(), 0, capacity).map_err(|error| {
            if error == rustix::io::Errno::NOSPC || error == rustix::io::Errno::FBIG {
                RepairVaultStoreError::InsufficientCapacity
            } else {
                RepairVaultStoreError::StorageUnavailable
            }
        })?;
        rfs::fsync(&descriptor).map_err(|_| RepairVaultStoreError::StorageUnavailable)?;
        let state = validate_regular_file(
            &descriptor,
            self.inner.owner(),
            self.inner.root_device(),
            self.inner.root_mount_id(),
            Some(capacity),
        )?;
        require_physical_allocation(&state, capacity)?;
        let named = named_file_state(
            &self.backups_fd,
            &name,
            self.inner.owner(),
            self.inner.root_device(),
            Some(capacity),
        )?;
        if !state.same_object(&named) {
            return Err(RepairVaultStoreError::ConcurrentWrite);
        }
        rfs::fsync(&self.backups_fd).map_err(|_| RepairVaultStoreError::StorageUnavailable)?;
        let mut file = File::from(descriptor);
        verify_zero_filled(&mut file, capacity)?;
        self.validate_store_boundary_unlocked()
    }

    fn validate_layout(&self) -> Result<(), RepairVaultStoreError> {
        self.validate_store_boundary()?;
        scan_namespace(self)?;
        scan_backups(self)
    }

    fn validate_store_boundary(&self) -> Result<(), RepairVaultStoreError> {
        let _guard = self
            .inner
            .operation_guard()
            .map_err(|_| RepairVaultStoreError::StorageUnavailable)?;
        self.validate_store_boundary_unlocked()
    }

    fn validate_store_boundary_unlocked(&self) -> Result<(), RepairVaultStoreError> {
        self.inner
            .ensure_integrity()
            .map_err(|_| RepairVaultStoreError::CorruptStore)?;
        validate_named_directory(
            self.inner.root_directory_fd(),
            REPAIR_NAMESPACE,
            &self.namespace_fd,
            &self.namespace_state,
            self.inner.owner(),
            self.inner.root_device(),
            self.inner.root_mount_id(),
        )?;
        validate_named_directory(
            &self.namespace_fd,
            BACKUP_DIRECTORY,
            &self.backups_fd,
            &self.backups_state,
            self.inner.owner(),
            self.inner.root_device(),
            self.inner.root_mount_id(),
        )
    }
}

fn verified_metadata_from_record(
    reservation_id: &ReservationId,
    record: &ReservationRecord,
    binding: &RepairBinding,
) -> VerifiedBackupMetadata {
    VerifiedBackupMetadata {
        reservation_id: reservation_id.clone(),
        backup_locator: backup_locator(reservation_id),
        reservation_binding_sha256: record.reservation_binding_sha256.clone(),
        backup_sha256: encode_hex(&record.draft.expected_backup_sha256),
        metadata_sha256: encode_hex(&record.draft.metadata_sha256),
        backup_size_bytes: record.draft.backup_size_bytes,
        reserved_capacity_bytes: record.reserved_capacity_bytes,
        vault_id: record.vault_id.clone(),
        vault_identity_fingerprint: record.vault_identity_fingerprint.clone(),
        physical_parent_fingerprint: record.physical_parent_fingerprint.clone(),
        plan_id: binding.plan_id.clone(),
        plan_sha256: encode_hex(&binding.plan_sha256),
        approval_id: binding.approval_id.clone(),
        approval_sha256: encode_hex(&binding.approval_sha256),
        resource_id: binding.resource_id.clone(),
        resource_sha256: encode_hex(&binding.resource_sha256),
    }
}

fn replay_repair_event(
    state: &mut RecoveredState,
    entry: JournalEntryRef<'_>,
) -> Result<(), RepairVaultStoreError> {
    let event: RepairEvent =
        serde_json::from_slice(entry.event).map_err(|_| RepairVaultStoreError::CorruptJournal)?;
    let canonical =
        serde_json::to_vec(&event).map_err(|_| RepairVaultStoreError::CorruptJournal)?;
    if canonical.as_slice() != entry.event {
        return Err(RepairVaultStoreError::CorruptJournal);
    }
    apply_repair_event(state, event, entry)
}

fn apply_repair_event(
    state: &mut RecoveredState,
    event: RepairEvent,
    _entry: JournalEntryRef<'_>,
) -> Result<(), RepairVaultStoreError> {
    match event {
        RepairEvent::ReserveIntent {
            reservation_id,
            draft,
            reservation_binding_sha256,
            reserved_capacity_bytes,
            vault_id,
            vault_identity_fingerprint,
            physical_parent_fingerprint,
        } => {
            draft.validate()?;
            if !valid_sha256(&reservation_binding_sha256)
                || reservation_binding_sha256 != reservation_binding(&draft)
                || reserved_capacity_bytes != draft.required_capacity_bytes
                || state.pending.is_some()
                || state.reservations.len() >= MAX_RESERVATIONS
                || state.reservations.contains_key(&reservation_id)
                || state.released.contains_key(&reservation_id)
                || state.seen_reservation_ids.contains(&reservation_id)
                || !valid_vault_id(&vault_id)
                || !valid_sha256(&vault_identity_fingerprint)
                || !valid_sha256(&physical_parent_fingerprint)
            {
                return Err(RepairVaultStoreError::CorruptJournal);
            }
            state.seen_reservation_ids.insert(reservation_id.clone());
            state.pending = Some(reservation_id.clone());
            state.reservations.insert(
                reservation_id,
                ReservationRecord {
                    draft,
                    reservation_binding_sha256,
                    reserved_capacity_bytes,
                    vault_id,
                    vault_identity_fingerprint,
                    physical_parent_fingerprint,
                    phase: ReservationPhase::ReservePending,
                },
            );
        }
        RepairEvent::ReserveComplete { reservation_id } => {
            if state.pending.as_ref() != Some(&reservation_id) {
                return Err(RepairVaultStoreError::CorruptJournal);
            }
            let record = state
                .reservations
                .get_mut(&reservation_id)
                .ok_or(RepairVaultStoreError::CorruptJournal)?;
            if !matches!(record.phase, ReservationPhase::ReservePending) {
                return Err(RepairVaultStoreError::CorruptJournal);
            }
            record.phase = ReservationPhase::Reserved;
            state.pending = None;
        }
        RepairEvent::ReserveAbort { reservation_id } => {
            if state.pending.as_ref() != Some(&reservation_id)
                || !matches!(
                    state
                        .reservations
                        .get(&reservation_id)
                        .map(|record| &record.phase),
                    Some(ReservationPhase::ReservePending)
                )
            {
                return Err(RepairVaultStoreError::CorruptJournal);
            }
            state.reservations.remove(&reservation_id);
            state.pending = None;
        }
        RepairEvent::PersistIntent {
            reservation_id,
            binding,
        } => {
            binding.validate()?;
            if state.pending.is_some() {
                return Err(RepairVaultStoreError::CorruptJournal);
            }
            let record = state
                .reservations
                .get_mut(&reservation_id)
                .ok_or(RepairVaultStoreError::CorruptJournal)?;
            if !matches!(record.phase, ReservationPhase::Reserved)
                || binding.resource_sha256 != record.draft.expected_backup_sha256
            {
                return Err(RepairVaultStoreError::CorruptJournal);
            }
            record.phase = ReservationPhase::PersistPending(binding);
            state.pending = Some(reservation_id);
        }
        RepairEvent::PersistComplete {
            reservation_id,
            backup_sha256,
            backup_size_bytes,
        } => {
            if state.pending.as_ref() != Some(&reservation_id) {
                return Err(RepairVaultStoreError::CorruptJournal);
            }
            let record = state
                .reservations
                .get_mut(&reservation_id)
                .ok_or(RepairVaultStoreError::CorruptJournal)?;
            if backup_sha256 != encode_hex(&record.draft.expected_backup_sha256)
                || backup_size_bytes != record.draft.backup_size_bytes
            {
                return Err(RepairVaultStoreError::CorruptJournal);
            }
            let ReservationPhase::PersistPending(binding) = &record.phase else {
                return Err(RepairVaultStoreError::CorruptJournal);
            };
            record.phase = ReservationPhase::Durable(binding.clone());
            state.pending = None;
        }
        RepairEvent::PersistAbort { reservation_id } => {
            if state.pending.as_ref() != Some(&reservation_id) {
                return Err(RepairVaultStoreError::CorruptJournal);
            }
            let record = state
                .reservations
                .get_mut(&reservation_id)
                .ok_or(RepairVaultStoreError::CorruptJournal)?;
            if !matches!(record.phase, ReservationPhase::PersistPending(_)) {
                return Err(RepairVaultStoreError::CorruptJournal);
            }
            record.phase = ReservationPhase::Reserved;
            state.pending = None;
        }
        RepairEvent::CancelIntent { reservation_id } => {
            if state.pending.is_some()
                || !matches!(
                    state
                        .reservations
                        .get(&reservation_id)
                        .map(|record| &record.phase),
                    Some(ReservationPhase::Reserved)
                )
            {
                return Err(RepairVaultStoreError::CorruptJournal);
            }
            state.pending = Some(reservation_id.clone());
            state
                .reservations
                .get_mut(&reservation_id)
                .ok_or(RepairVaultStoreError::CorruptJournal)?
                .phase = ReservationPhase::CancelPending;
        }
        RepairEvent::CancelComplete { reservation_id } => {
            if state.pending.as_ref() != Some(&reservation_id)
                || state.released.len() >= MAX_RELEASE_TOMBSTONES
                || state.released.contains_key(&reservation_id)
                || !matches!(
                    state
                        .reservations
                        .get(&reservation_id)
                        .map(|record| &record.phase),
                    Some(ReservationPhase::CancelPending)
                )
            {
                return Err(RepairVaultStoreError::CorruptJournal);
            }
            let record = state
                .reservations
                .remove(&reservation_id)
                .ok_or(RepairVaultStoreError::CorruptJournal)?;
            state.released.insert(
                reservation_id,
                ReleaseTombstone {
                    operation: ReleaseOperation::Cancel,
                    record,
                },
            );
            state.pending = None;
        }
        RepairEvent::RetireIntent { reservation_id } => {
            if state.pending.is_some()
                || !matches!(
                    state
                        .reservations
                        .get(&reservation_id)
                        .map(|record| &record.phase),
                    Some(ReservationPhase::Durable(_))
                )
            {
                return Err(RepairVaultStoreError::CorruptJournal);
            }
            let record = state
                .reservations
                .get_mut(&reservation_id)
                .ok_or(RepairVaultStoreError::CorruptJournal)?;
            let ReservationPhase::Durable(binding) = &record.phase else {
                return Err(RepairVaultStoreError::CorruptJournal);
            };
            record.phase = ReservationPhase::RetirePending(binding.clone());
            state.pending = Some(reservation_id);
        }
        RepairEvent::RetireComplete { reservation_id } => {
            if state.pending.as_ref() != Some(&reservation_id)
                || state.released.len() >= MAX_RELEASE_TOMBSTONES
                || state.released.contains_key(&reservation_id)
                || !matches!(
                    state
                        .reservations
                        .get(&reservation_id)
                        .map(|record| &record.phase),
                    Some(ReservationPhase::RetirePending(_))
                )
            {
                return Err(RepairVaultStoreError::CorruptJournal);
            }
            let record = state
                .reservations
                .remove(&reservation_id)
                .ok_or(RepairVaultStoreError::CorruptJournal)?;
            state.released.insert(
                reservation_id,
                ReleaseTombstone {
                    operation: ReleaseOperation::Retire,
                    record,
                },
            );
            state.pending = None;
        }
    }
    Ok(())
}

fn initialize_namespace(
    inner: &VaultInner,
) -> Result<(OwnedFd, FilesystemState, OwnedFd, FilesystemState, OwnedFd), RepairVaultStoreError> {
    let _guard = inner
        .operation_guard()
        .map_err(|_| RepairVaultStoreError::StorageUnavailable)?;
    inner
        .ensure_integrity()
        .map_err(|_| RepairVaultStoreError::CorruptStore)?;
    let (namespace_fd, namespace_state, namespace_created) = open_or_create_directory(
        inner.root_directory_fd(),
        REPAIR_NAMESPACE,
        inner.owner(),
        inner.root_device(),
        inner.root_mount_id(),
    )?;
    let (backups_fd, backups_state, backups_created) = open_or_create_directory(
        &namespace_fd,
        BACKUP_DIRECTORY,
        inner.owner(),
        inner.root_device(),
        inner.root_mount_id(),
    )?;
    let (lock_fd, lock_created) = open_or_create_lock(
        &namespace_fd,
        inner.owner(),
        inner.root_device(),
        inner.root_mount_id(),
    )?;
    rfs::flock(&lock_fd, FlockOperation::NonBlockingLockExclusive).map_err(|error| {
        if error == rustix::io::Errno::WOULDBLOCK {
            RepairVaultStoreError::StorageUnavailable
        } else {
            RepairVaultStoreError::CorruptStore
        }
    })?;
    if namespace_created || backups_created || lock_created {
        rfs::fsync(&backups_fd).map_err(|_| RepairVaultStoreError::StorageUnavailable)?;
        rfs::fsync(&namespace_fd).map_err(|_| RepairVaultStoreError::StorageUnavailable)?;
        rfs::fsync(inner.root_directory_fd())
            .map_err(|_| RepairVaultStoreError::StorageUnavailable)?;
    }
    inner
        .ensure_integrity()
        .map_err(|_| RepairVaultStoreError::CorruptStore)?;
    Ok((
        namespace_fd,
        namespace_state,
        backups_fd,
        backups_state,
        lock_fd,
    ))
}

fn cleanup_repair_secret_orphan(
    inner: &VaultInner,
    directory: &OwnedFd,
    owner: VaultOwner,
    expected_device: u64,
    expected_mount_id: u64,
) -> Result<(), RepairVaultStoreError> {
    let _guard = inner
        .operation_guard()
        .map_err(|_| RepairVaultStoreError::StorageUnavailable)?;
    inner
        .ensure_integrity()
        .map_err(|_| RepairVaultStoreError::CorruptStore)?;
    let names = scan_directory_names(directory)?;
    let mut orphan = None;
    for name in names.keys().filter(|name| name.starts_with(TEMP_PREFIX)) {
        if name.len() != TEMP_PREFIX.len() + 32
            || !name[TEMP_PREFIX.len()..]
                .bytes()
                .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
            || orphan.replace(name.clone()).is_some()
        {
            return Err(RepairVaultStoreError::CorruptStore);
        }
    }
    let Some(orphan) = orphan else {
        return Ok(());
    };
    let maximum = SECRET_PREFIX.len() + 2 + JournalAnchor::ENCODED_BYTES.max(JOURNAL_KEY_BYTES);
    let envelope = read_optional_file(
        directory,
        &orphan,
        owner,
        expected_device,
        expected_mount_id,
        maximum,
    )?
    .ok_or(RepairVaultStoreError::CorruptStore)?;
    let key = decode_secret(RepairSecretKind::Key, envelope.as_slice()).is_ok();
    let anchor = decode_secret(RepairSecretKind::Anchor, envelope.as_slice()).is_ok();
    let kind = match (key, anchor) {
        (true, false) => RepairSecretKind::Key,
        (false, true) => RepairSecretKind::Anchor,
        _ => return Err(RepairVaultStoreError::CorruptStore),
    };
    if let Some(final_envelope) = read_optional_file(
        directory,
        kind.name(),
        owner,
        expected_device,
        expected_mount_id,
        SECRET_PREFIX.len() + 2 + kind.size(),
    )? {
        decode_secret(kind, final_envelope.as_slice())?;
    }
    let expected = named_file_state(directory, &orphan, owner, expected_device, None)?;
    let rechecked = named_file_state(directory, &orphan, owner, expected_device, None)?;
    if !expected.same_object(&rechecked) || expected.size != rechecked.size {
        return Err(RepairVaultStoreError::ConcurrentWrite);
    }
    rfs::unlinkat(directory, &orphan, AtFlags::empty())
        .map_err(|_| RepairVaultStoreError::ConcurrentWrite)?;
    rfs::fsync(directory).map_err(|_| RepairVaultStoreError::StorageUnavailable)?;
    if named_optional_state(directory, &orphan, owner, expected_device, None)?.is_some() {
        return Err(RepairVaultStoreError::ConcurrentWrite);
    }
    inner
        .ensure_integrity()
        .map_err(|_| RepairVaultStoreError::CorruptStore)
}

fn open_or_create_directory(
    parent: &OwnedFd,
    name: &str,
    owner: VaultOwner,
    expected_device: u64,
    expected_mount_id: u64,
) -> Result<(OwnedFd, FilesystemState, bool), RepairVaultStoreError> {
    let created = match rfs::mkdirat(parent, name, Mode::RUSR | Mode::WUSR | Mode::XUSR) {
        Ok(()) => true,
        Err(error) if error == rustix::io::Errno::EXIST => false,
        Err(_) => return Err(RepairVaultStoreError::StorageUnavailable),
    };
    let descriptor = open_child(
        parent,
        Path::new(name),
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(|_| RepairVaultStoreError::CorruptStore)?;
    if created {
        rfs::fchmod(&descriptor, Mode::RUSR | Mode::WUSR | Mode::XUSR)
            .map_err(|_| RepairVaultStoreError::StorageUnavailable)?;
        rfs::fsync(&descriptor).map_err(|_| RepairVaultStoreError::StorageUnavailable)?;
        rfs::fsync(parent).map_err(|_| RepairVaultStoreError::StorageUnavailable)?;
    }
    let state = validate_directory(&descriptor, owner, expected_device, expected_mount_id)?;
    let named = named_directory_state(parent, name, owner, expected_device)?;
    if !state.same_object(&named) {
        return Err(RepairVaultStoreError::ConcurrentWrite);
    }
    Ok((descriptor, state, created))
}

fn open_or_create_lock(
    parent: &OwnedFd,
    owner: VaultOwner,
    expected_device: u64,
    expected_mount_id: u64,
) -> Result<(OwnedFd, bool), RepairVaultStoreError> {
    let (descriptor, created) = match open_child(
        parent,
        Path::new(LOCK_NAME),
        OFlags::RDWR | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::RUSR | Mode::WUSR,
    ) {
        Ok(descriptor) => (descriptor, true),
        Err(error) if error == rustix::io::Errno::EXIST => (
            open_child(
                parent,
                Path::new(LOCK_NAME),
                OFlags::RDWR | OFlags::NOFOLLOW | OFlags::CLOEXEC,
                Mode::empty(),
            )
            .map_err(|_| RepairVaultStoreError::CorruptStore)?,
            false,
        ),
        Err(_) => return Err(RepairVaultStoreError::StorageUnavailable),
    };
    if created {
        rfs::fchmod(&descriptor, Mode::RUSR | Mode::WUSR)
            .map_err(|_| RepairVaultStoreError::StorageUnavailable)?;
        rfs::fsync(&descriptor).map_err(|_| RepairVaultStoreError::StorageUnavailable)?;
    }
    let state = validate_regular_file(
        &descriptor,
        owner,
        expected_device,
        expected_mount_id,
        Some(0),
    )?;
    let named = named_file_state(parent, LOCK_NAME, owner, expected_device, Some(0))?;
    if !state.same_object(&named) {
        return Err(RepairVaultStoreError::ConcurrentWrite);
    }
    Ok((descriptor, created))
}

struct RepairJournalSecretStore<'vault> {
    inner: &'vault VaultInner,
    directory: OwnedFd,
    directory_state: FilesystemState,
}

#[derive(Clone, Copy)]
enum RepairSecretKind {
    Key,
    Anchor,
}

impl RepairSecretKind {
    const fn name(self) -> &'static str {
        match self {
            Self::Key => JOURNAL_KEY_NAME,
            Self::Anchor => JOURNAL_ANCHOR_NAME,
        }
    }

    const fn tag(self) -> u8 {
        match self {
            Self::Key => b'K',
            Self::Anchor => b'A',
        }
    }

    const fn size(self) -> usize {
        match self {
            Self::Key => JOURNAL_KEY_BYTES,
            Self::Anchor => JournalAnchor::ENCODED_BYTES,
        }
    }
}

impl JournalSecretStore for RepairJournalSecretStore<'_> {
    fn load_key(&mut self) -> Result<Option<JournalKey>, SecretStoreError> {
        let Some(bytes) = self.load(RepairSecretKind::Key).map_err(secret_error)? else {
            return Ok(None);
        };
        let mut key = Zeroizing::new([0_u8; JOURNAL_KEY_BYTES]);
        key.copy_from_slice(&bytes);
        Ok(Some(JournalKey::from_zeroizing(key)))
    }

    fn store_key(&mut self, key: &JournalKey) -> Result<(), SecretStoreError> {
        self.store(RepairSecretKind::Key, key.expose_secret())
            .map_err(secret_error)
    }

    fn load_anchor(&mut self) -> Result<Option<JournalAnchor>, SecretStoreError> {
        self.load(RepairSecretKind::Anchor)
            .map_err(secret_error)?
            .map(|bytes| {
                JournalAnchor::from_bytes(&bytes)
                    .map_err(|_| SecretStoreError::new("invalid Repair Vault anchor"))
            })
            .transpose()
    }

    fn store_anchor(&mut self, anchor: &JournalAnchor) -> Result<(), SecretStoreError> {
        self.store(RepairSecretKind::Anchor, &anchor.to_bytes())
            .map_err(secret_error)
    }
}

impl RepairJournalSecretStore<'_> {
    fn validate(&self) -> Result<(), RepairVaultStoreError> {
        self.inner
            .ensure_integrity()
            .map_err(|_| RepairVaultStoreError::CorruptStore)?;
        validate_named_directory(
            self.inner.root_directory_fd(),
            REPAIR_NAMESPACE,
            &self.directory,
            &self.directory_state,
            self.inner.owner(),
            self.inner.root_device(),
            self.inner.root_mount_id(),
        )
    }

    fn load(
        &self,
        kind: RepairSecretKind,
    ) -> Result<Option<Zeroizing<Vec<u8>>>, RepairVaultStoreError> {
        let _guard = self
            .inner
            .operation_guard()
            .map_err(|_| RepairVaultStoreError::StorageUnavailable)?;
        self.validate()?;
        let Some(envelope) = read_optional_file(
            &self.directory,
            kind.name(),
            self.inner.owner(),
            self.inner.root_device(),
            self.inner.root_mount_id(),
            SECRET_PREFIX.len() + 2 + kind.size(),
        )?
        else {
            return Ok(None);
        };
        decode_secret(kind, envelope.as_slice()).map(Some)
    }

    fn store(&self, kind: RepairSecretKind, bytes: &[u8]) -> Result<(), RepairVaultStoreError> {
        if bytes.len() != kind.size() {
            return Err(RepairVaultStoreError::CorruptStore);
        }
        let envelope = encode_secret(kind, bytes);
        let _guard = self
            .inner
            .operation_guard()
            .map_err(|_| RepairVaultStoreError::StorageUnavailable)?;
        self.validate()?;
        atomic_store_secret(
            &self.directory,
            kind.name(),
            envelope.as_slice(),
            self.inner.owner(),
            self.inner.root_device(),
            self.inner.root_mount_id(),
        )
    }
}

fn secret_error(error: RepairVaultStoreError) -> SecretStoreError {
    SecretStoreError::new(error.to_string())
}

fn encode_secret(kind: RepairSecretKind, bytes: &[u8]) -> Zeroizing<Vec<u8>> {
    let mut envelope = Zeroizing::new(Vec::with_capacity(SECRET_PREFIX.len() + 2 + bytes.len()));
    envelope.extend_from_slice(SECRET_PREFIX);
    envelope.push(kind.tag());
    envelope.push(0);
    envelope.extend_from_slice(bytes);
    envelope
}

fn decode_secret(
    kind: RepairSecretKind,
    envelope: &[u8],
) -> Result<Zeroizing<Vec<u8>>, RepairVaultStoreError> {
    let prefix_len = SECRET_PREFIX.len();
    if envelope.len() != prefix_len + 2 + kind.size()
        || &envelope[..prefix_len] != SECRET_PREFIX
        || envelope[prefix_len] != kind.tag()
        || envelope[prefix_len + 1] != 0
    {
        return Err(RepairVaultStoreError::CorruptStore);
    }
    Ok(Zeroizing::new(envelope[prefix_len + 2..].to_vec()))
}

fn atomic_store_secret(
    directory: &OwnedFd,
    final_name: &str,
    envelope: &[u8],
    owner: VaultOwner,
    expected_device: u64,
    expected_mount_id: u64,
) -> Result<(), RepairVaultStoreError> {
    let existing = named_optional_state(directory, final_name, owner, expected_device, None)?;
    let (mut temporary, mut temporary_guard) =
        create_temporary_file(directory, owner, expected_device, expected_mount_id)?;
    temporary
        .write_all(envelope)
        .map_err(|_| RepairVaultStoreError::StorageUnavailable)?;
    temporary
        .flush()
        .map_err(|_| RepairVaultStoreError::StorageUnavailable)?;
    temporary
        .sync_all()
        .map_err(|_| RepairVaultStoreError::StorageUnavailable)?;
    let readback = read_optional_file(
        directory,
        temporary_guard.name(),
        owner,
        expected_device,
        expected_mount_id,
        envelope.len(),
    )?
    .ok_or(RepairVaultStoreError::WriteVerificationFailed)?;
    if readback.as_slice() != envelope {
        return Err(RepairVaultStoreError::WriteVerificationFailed);
    }
    rfs::fsync(directory).map_err(|_| RepairVaultStoreError::StorageUnavailable)?;
    let current = named_optional_state(directory, final_name, owner, expected_device, None)?;
    if !same_optional_object(&existing, &current) {
        return Err(RepairVaultStoreError::ConcurrentWrite);
    }
    let result = if existing.is_some() {
        rfs::renameat(directory, temporary_guard.name(), directory, final_name)
    } else {
        rfs::renameat_with(
            directory,
            temporary_guard.name(),
            directory,
            final_name,
            RenameFlags::NOREPLACE,
        )
    };
    if result.is_err() {
        return Err(RepairVaultStoreError::ConcurrentWrite);
    }
    temporary_guard.disarm();
    rfs::fsync(directory).map_err(|_| RepairVaultStoreError::StorageUnavailable)?;
    let final_state = named_file_state(directory, final_name, owner, expected_device, None)?;
    if !final_state.same_object(temporary_guard.state()) {
        return Err(RepairVaultStoreError::ConcurrentWrite);
    }
    let persisted = read_optional_file(
        directory,
        final_name,
        owner,
        expected_device,
        expected_mount_id,
        envelope.len(),
    )?
    .ok_or(RepairVaultStoreError::WriteVerificationFailed)?;
    if persisted.as_slice() != envelope {
        return Err(RepairVaultStoreError::WriteVerificationFailed);
    }
    Ok(())
}

fn create_temporary_file(
    directory: &OwnedFd,
    owner: VaultOwner,
    expected_device: u64,
    expected_mount_id: u64,
) -> Result<(File, TemporaryFileGuard), RepairVaultStoreError> {
    for _ in 0..16 {
        let name = format!(
            "{TEMP_PREFIX}{:016x}{:016x}",
            OsRng.next_u64(),
            OsRng.next_u64()
        );
        let descriptor = match open_child(
            directory,
            Path::new(&name),
            OFlags::RDWR | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::RUSR | Mode::WUSR,
        ) {
            Ok(descriptor) => descriptor,
            Err(error) if error == rustix::io::Errno::EXIST => continue,
            Err(_) => return Err(RepairVaultStoreError::StorageUnavailable),
        };
        rfs::fchmod(&descriptor, Mode::RUSR | Mode::WUSR)
            .map_err(|_| RepairVaultStoreError::StorageUnavailable)?;
        let state = validate_regular_file(
            &descriptor,
            owner,
            expected_device,
            expected_mount_id,
            Some(0),
        )?;
        let named = named_file_state(directory, &name, owner, expected_device, Some(0))?;
        if !state.same_object(&named) {
            return Err(RepairVaultStoreError::ConcurrentWrite);
        }
        let guard = TemporaryFileGuard {
            directory: rustix::io::fcntl_dupfd_cloexec(directory, 3)
                .map_err(|_| RepairVaultStoreError::StorageUnavailable)?,
            name,
            state,
            armed: true,
        };
        return Ok((File::from(descriptor), guard));
    }
    Err(RepairVaultStoreError::StorageUnavailable)
}

struct TemporaryFileGuard {
    directory: OwnedFd,
    name: String,
    state: FilesystemState,
    armed: bool,
}

impl TemporaryFileGuard {
    fn name(&self) -> &str {
        &self.name
    }

    fn state(&self) -> &FilesystemState {
        &self.state
    }

    fn disarm(&mut self) {
        self.armed = false;
    }
}

impl Drop for TemporaryFileGuard {
    fn drop(&mut self) {
        if self.armed {
            cleanup_temporary(&self.directory, &self.name, &self.state);
        }
    }
}

fn cleanup_temporary(directory: &OwnedFd, name: &str, expected: &FilesystemState) {
    if let Ok(stat) = rfs::statat(directory, name, AtFlags::SYMLINK_NOFOLLOW)
        && expected.same_object(&FilesystemState::from_stat(&stat))
    {
        let _ = rfs::unlinkat(directory, name, AtFlags::empty());
        let _ = rfs::fsync(directory);
    }
}

fn same_optional_object(left: &Option<FilesystemState>, right: &Option<FilesystemState>) -> bool {
    match (left, right) {
        (None, None) => true,
        (Some(left), Some(right)) => left.same_object(right),
        _ => false,
    }
}

fn read_source(
    source: OwnedFd,
    expected_size: u64,
    expected_sha256: [u8; 32],
    deadline: Instant,
) -> Result<Zeroizing<Vec<u8>>, RepairVaultStoreError> {
    let status = rfs::fcntl_getfl(&source).map_err(|_| RepairVaultStoreError::UnsafeSource)?;
    let descriptor_flags =
        rustix::io::fcntl_getfd(&source).map_err(|_| RepairVaultStoreError::UnsafeSource)?;
    let stat = rfs::fstat(&source).map_err(|_| RepairVaultStoreError::UnsafeSource)?;
    let filesystem = rfs::fstatfs(&source).map_err(|_| RepairVaultStoreError::UnsafeSource)?;
    let filesystem_type =
        u64::try_from(filesystem.f_type).map_err(|_| RepairVaultStoreError::UnsafeSource)?;
    if status & OFlags::ACCMODE != OFlags::RDONLY
        || !descriptor_flags.contains(rustix::io::FdFlags::CLOEXEC)
        || !FileType::from_raw_mode(stat.st_mode).is_fifo()
        || filesystem_type != PIPEFS_MAGIC
        || stat.st_size != 0
    {
        return Err(RepairVaultStoreError::UnsafeSource);
    }
    let capacity =
        usize::try_from(expected_size).map_err(|_| RepairVaultStoreError::UnsafeSource)?;
    rfs::fcntl_setfl(&source, status | OFlags::NONBLOCK)
        .map_err(|_| RepairVaultStoreError::UnsafeSource)?;
    let mut bytes = Zeroizing::new(Vec::with_capacity(capacity));
    let maximum = capacity.saturating_add(1);
    loop {
        if Instant::now() >= deadline {
            return Err(RepairVaultStoreError::UnsafeSource);
        }
        let mut chunk = [0_u8; 8192];
        let remaining = maximum.saturating_sub(bytes.len());
        if remaining == 0 {
            return Err(RepairVaultStoreError::UnsafeSource);
        }
        let read_limit = remaining.min(chunk.len());
        match rustix::io::read(&source, &mut chunk[..read_limit]) {
            Ok(0) => break,
            Ok(read) => bytes.extend_from_slice(&chunk[..read]),
            Err(error) if error == rustix::io::Errno::INTR => {}
            Err(error) if error == rustix::io::Errno::AGAIN => {
                let remaining = deadline
                    .checked_duration_since(Instant::now())
                    .filter(|remaining| !remaining.is_zero())
                    .ok_or(RepairVaultStoreError::UnsafeSource)?;
                let timeout = Timespec {
                    tv_sec: i64::try_from(remaining.as_secs()).unwrap_or(i64::MAX),
                    tv_nsec: i64::from(remaining.subsec_nanos()),
                };
                let mut descriptors = [PollFd::from_borrowed_fd(
                    source.as_fd(),
                    PollFlags::IN | PollFlags::HUP,
                )];
                match poll(&mut descriptors, Some(&timeout)) {
                    Ok(0) => return Err(RepairVaultStoreError::UnsafeSource),
                    Ok(_)
                        if descriptors[0]
                            .revents()
                            .intersects(PollFlags::NVAL | PollFlags::ERR) =>
                    {
                        return Err(RepairVaultStoreError::UnsafeSource);
                    }
                    Ok(_) => {}
                    Err(error) if error == rustix::io::Errno::INTR => {}
                    Err(_) => return Err(RepairVaultStoreError::UnsafeSource),
                }
            }
            Err(_) => return Err(RepairVaultStoreError::UnsafeSource),
        }
    }
    if bytes.len() != capacity {
        return Err(RepairVaultStoreError::UnsafeSource);
    }
    let observed: [u8; 32] = Sha256::digest(bytes.as_slice()).into();
    if observed != expected_sha256 {
        return Err(RepairVaultStoreError::SourceHashMismatch);
    }
    Ok(bytes)
}

fn verify_file_contents(
    file: &mut File,
    record: &ReservationRecord,
    expect_zero: bool,
) -> Result<(), RepairVaultStoreError> {
    file.seek(SeekFrom::Start(0))
        .map_err(|_| RepairVaultStoreError::StorageUnavailable)?;
    let mut hasher = Sha256::new();
    let mut remaining_content = record.draft.backup_size_bytes;
    let mut remaining_total = record.reserved_capacity_bytes;
    let mut buffer = [0_u8; 8192];
    while remaining_total > 0 {
        let wanted = usize::try_from(remaining_total.min(buffer.len() as u64))
            .map_err(|_| RepairVaultStoreError::CorruptStore)?;
        file.read_exact(&mut buffer[..wanted])
            .map_err(|_| RepairVaultStoreError::WriteVerificationFailed)?;
        if expect_zero {
            if buffer[..wanted].iter().any(|byte| *byte != 0) {
                return Err(RepairVaultStoreError::WriteVerificationFailed);
            }
        } else {
            let content = usize::try_from(remaining_content.min(wanted as u64))
                .map_err(|_| RepairVaultStoreError::CorruptStore)?;
            hasher.update(&buffer[..content]);
            if buffer[content..wanted].iter().any(|byte| *byte != 0) {
                return Err(RepairVaultStoreError::WriteVerificationFailed);
            }
            remaining_content -= content as u64;
        }
        remaining_total -= wanted as u64;
    }
    let mut extra = [0_u8; 1];
    if file
        .read(&mut extra)
        .map_err(|_| RepairVaultStoreError::StorageUnavailable)?
        != 0
    {
        return Err(RepairVaultStoreError::ConcurrentWrite);
    }
    if !expect_zero {
        let observed: [u8; 32] = hasher.finalize().into();
        if remaining_content != 0 || observed != record.draft.expected_backup_sha256 {
            return Err(RepairVaultStoreError::WriteVerificationFailed);
        }
    }
    Ok(())
}

fn verify_zero_filled(file: &mut File, capacity: u64) -> Result<(), RepairVaultStoreError> {
    let record = ReservationRecord {
        draft: RepairBackupDraft {
            session_id: "S-verification".to_owned(),
            target_id: "verification".to_owned(),
            target_fingerprint: [1; 32],
            expected_backup_sha256: [1; 32],
            metadata_sha256: [1; 32],
            backup_size_bytes: 1,
            required_capacity_bytes: capacity,
        },
        reservation_binding_sha256: String::new(),
        reserved_capacity_bytes: capacity,
        vault_id: "V-verification".to_owned(),
        vault_identity_fingerprint: "00".repeat(32),
        physical_parent_fingerprint: "00".repeat(32),
        phase: ReservationPhase::ReservePending,
    };
    verify_file_contents(file, &record, true)
}

fn require_physical_allocation(
    state: &FilesystemState,
    required: u64,
) -> Result<(), RepairVaultStoreError> {
    let blocks = u64::try_from(state.blocks).map_err(|_| RepairVaultStoreError::CorruptStore)?;
    let allocated = blocks
        .checked_mul(512)
        .ok_or(RepairVaultStoreError::CorruptStore)?;
    if allocated < required {
        return Err(RepairVaultStoreError::InsufficientCapacity);
    }
    Ok(())
}

fn exact_allocation(state: &FilesystemState, required: u64) -> bool {
    state.size >= 0
        && state.size as u64 == required
        && u64::try_from(state.blocks)
            .ok()
            .and_then(|blocks| blocks.checked_mul(512))
            .is_some_and(|allocated| allocated >= required)
}

fn scan_namespace(store: &RepairVaultStore<'_>) -> Result<(), RepairVaultStoreError> {
    let _guard = store
        .inner
        .operation_guard()
        .map_err(|_| RepairVaultStoreError::StorageUnavailable)?;
    store.validate_store_boundary_unlocked()?;
    let names = scan_directory_names(&store.namespace_fd)?;
    let required = [
        BACKUP_DIRECTORY,
        LOCK_NAME,
        JOURNAL_DATABASE_NAME,
        JOURNAL_KEY_NAME,
        JOURNAL_ANCHOR_NAME,
    ];
    if required
        .iter()
        .any(|required| !names.contains_key(*required))
    {
        return Err(RepairVaultStoreError::CorruptStore);
    }
    for name in names.keys() {
        if !required.contains(&name.as_str())
            && name != JOURNAL_WAL_NAME
            && name != JOURNAL_SHM_NAME
        {
            return Err(RepairVaultStoreError::CorruptStore);
        }
    }
    for name in [
        LOCK_NAME,
        JOURNAL_DATABASE_NAME,
        JOURNAL_KEY_NAME,
        JOURNAL_ANCHOR_NAME,
        JOURNAL_WAL_NAME,
        JOURNAL_SHM_NAME,
    ] {
        if names.contains_key(name) {
            let _ = named_file_state(
                &store.namespace_fd,
                name,
                store.inner.owner(),
                store.inner.root_device(),
                None,
            )?;
        }
    }
    Ok(())
}

fn scan_backups(store: &RepairVaultStore<'_>) -> Result<(), RepairVaultStoreError> {
    let _guard = store
        .inner
        .operation_guard()
        .map_err(|_| RepairVaultStoreError::StorageUnavailable)?;
    store.validate_store_boundary_unlocked()?;
    let names = scan_directory_names(&store.backups_fd)?;
    if names.len() > MAX_RESERVATIONS {
        return Err(RepairVaultStoreError::CorruptStore);
    }
    for (reservation_id, record) in &store.state.reservations {
        let name = backup_filename(reservation_id);
        let present = names.contains_key(&name);
        if !present
            && !matches!(
                record.phase,
                ReservationPhase::ReservePending | ReservationPhase::CancelPending
            )
        {
            return Err(RepairVaultStoreError::CorruptStore);
        }
        if present {
            let state = named_file_state(
                &store.backups_fd,
                &name,
                store.inner.owner(),
                store.inner.root_device(),
                Some(record.reserved_capacity_bytes),
            )?;
            require_physical_allocation(&state, record.reserved_capacity_bytes)?;
        }
    }
    for name in names.keys() {
        let Some(id) = name.strip_prefix(BACKUP_PREFIX) else {
            return Err(RepairVaultStoreError::CorruptStore);
        };
        let reservation_id = ReservationId::parse(id.to_owned())?;
        if !store.state.reservations.contains_key(&reservation_id) {
            return Err(RepairVaultStoreError::CorruptStore);
        }
    }
    Ok(())
}

fn scan_directory_names(
    directory: &OwnedFd,
) -> Result<BTreeMap<String, ()>, RepairVaultStoreError> {
    let scan_fd = open_child(
        directory,
        Path::new("."),
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(|_| RepairVaultStoreError::CorruptStore)?;
    let mut names = BTreeMap::new();
    let mut buffer = [MaybeUninit::<u8>::uninit(); SCAN_BUFFER_BYTES];
    let mut entries = RawDir::new(&scan_fd, &mut buffer);
    while let Some(entry) = entries.next() {
        let entry = entry.map_err(|_| RepairVaultStoreError::StorageUnavailable)?;
        let name = entry.file_name().to_bytes();
        if name == b"." || name == b".." {
            continue;
        }
        if names.len() >= MAX_LAYOUT_ENTRIES || name.is_empty() || !name.is_ascii() {
            return Err(RepairVaultStoreError::CorruptStore);
        }
        let name = std::str::from_utf8(name)
            .map_err(|_| RepairVaultStoreError::CorruptStore)?
            .to_owned();
        if names.insert(name, ()).is_some() {
            return Err(RepairVaultStoreError::CorruptStore);
        }
    }
    Ok(names)
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

fn descriptor_mount_id(descriptor: impl AsFd) -> Result<u64, RepairVaultStoreError> {
    let stat = rfs::statx(
        descriptor,
        "",
        AtFlags::EMPTY_PATH | AtFlags::NO_AUTOMOUNT | AtFlags::SYMLINK_NOFOLLOW,
        StatxFlags::MNT_ID,
    )
    .map_err(|_| RepairVaultStoreError::StorageUnavailable)?;
    if !StatxFlags::from_bits_retain(stat.stx_mask).contains(StatxFlags::MNT_ID)
        || stat.stx_mnt_id == 0
    {
        return Err(RepairVaultStoreError::StorageUnavailable);
    }
    Ok(stat.stx_mnt_id)
}

fn validate_directory(
    descriptor: &OwnedFd,
    owner: VaultOwner,
    expected_device: u64,
    expected_mount_id: u64,
) -> Result<FilesystemState, RepairVaultStoreError> {
    let stat = rfs::fstat(descriptor).map_err(|_| RepairVaultStoreError::StorageUnavailable)?;
    if !FileType::from_raw_mode(stat.st_mode).is_dir()
        || stat.st_nlink < 2
        || stat.st_uid != owner.uid
        || stat.st_gid != owner.gid
        || stat.st_mode & 0o7777 != DIRECTORY_MODE
        || stat.st_dev != expected_device
        || descriptor_mount_id(descriptor)? != expected_mount_id
    {
        return Err(RepairVaultStoreError::CorruptStore);
    }
    Ok(FilesystemState::from_stat(&stat))
}

fn validate_regular_file(
    descriptor: impl AsFd,
    owner: VaultOwner,
    expected_device: u64,
    expected_mount_id: u64,
    expected_size: Option<u64>,
) -> Result<FilesystemState, RepairVaultStoreError> {
    let stat = rfs::fstat(&descriptor).map_err(|_| RepairVaultStoreError::StorageUnavailable)?;
    if !FileType::from_raw_mode(stat.st_mode).is_file()
        || stat.st_nlink != 1
        || stat.st_size < 0
        || stat.st_uid != owner.uid
        || stat.st_gid != owner.gid
        || stat.st_mode & 0o7777 != FILE_MODE
        || stat.st_dev != expected_device
        || descriptor_mount_id(&descriptor)? != expected_mount_id
        || expected_size.is_some_and(|size| stat.st_size as u64 != size)
    {
        return Err(RepairVaultStoreError::CorruptStore);
    }
    Ok(FilesystemState::from_stat(&stat))
}

fn named_directory_state(
    parent: &OwnedFd,
    name: &str,
    owner: VaultOwner,
    expected_device: u64,
) -> Result<FilesystemState, RepairVaultStoreError> {
    let stat = rfs::statat(parent, name, AtFlags::SYMLINK_NOFOLLOW)
        .map_err(|_| RepairVaultStoreError::CorruptStore)?;
    if !FileType::from_raw_mode(stat.st_mode).is_dir()
        || stat.st_nlink < 2
        || stat.st_uid != owner.uid
        || stat.st_gid != owner.gid
        || stat.st_mode & 0o7777 != DIRECTORY_MODE
        || stat.st_dev != expected_device
    {
        return Err(RepairVaultStoreError::CorruptStore);
    }
    Ok(FilesystemState::from_stat(&stat))
}

fn named_file_state(
    parent: &OwnedFd,
    name: &str,
    owner: VaultOwner,
    expected_device: u64,
    expected_size: Option<u64>,
) -> Result<FilesystemState, RepairVaultStoreError> {
    named_optional_state(parent, name, owner, expected_device, expected_size)?
        .ok_or(RepairVaultStoreError::CorruptStore)
}

fn named_optional_state(
    parent: &OwnedFd,
    name: &str,
    owner: VaultOwner,
    expected_device: u64,
    expected_size: Option<u64>,
) -> Result<Option<FilesystemState>, RepairVaultStoreError> {
    let stat = match rfs::statat(parent, name, AtFlags::SYMLINK_NOFOLLOW) {
        Ok(stat) => stat,
        Err(error) if error == rustix::io::Errno::NOENT => return Ok(None),
        Err(_) => return Err(RepairVaultStoreError::CorruptStore),
    };
    if !FileType::from_raw_mode(stat.st_mode).is_file()
        || stat.st_nlink != 1
        || stat.st_size < 0
        || stat.st_uid != owner.uid
        || stat.st_gid != owner.gid
        || stat.st_mode & 0o7777 != FILE_MODE
        || stat.st_dev != expected_device
        || expected_size.is_some_and(|size| stat.st_size as u64 != size)
    {
        return Err(RepairVaultStoreError::CorruptStore);
    }
    Ok(Some(FilesystemState::from_stat(&stat)))
}

#[allow(clippy::too_many_arguments)]
fn validate_named_directory(
    parent: &OwnedFd,
    name: &str,
    descriptor: &OwnedFd,
    expected_state: &FilesystemState,
    owner: VaultOwner,
    expected_device: u64,
    expected_mount_id: u64,
) -> Result<(), RepairVaultStoreError> {
    let descriptor_state =
        validate_directory(descriptor, owner, expected_device, expected_mount_id)?;
    let named = named_directory_state(parent, name, owner, expected_device)?;
    if !descriptor_state.same_object(expected_state)
        || !named.same_object(expected_state)
        || !descriptor_state.same_object(&named)
    {
        return Err(RepairVaultStoreError::ConcurrentWrite);
    }
    Ok(())
}

fn read_optional_file(
    parent: &OwnedFd,
    name: &str,
    owner: VaultOwner,
    expected_device: u64,
    expected_mount_id: u64,
    maximum: usize,
) -> Result<Option<Zeroizing<Vec<u8>>>, RepairVaultStoreError> {
    let descriptor = match open_child(
        parent,
        Path::new(name),
        OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC,
        Mode::empty(),
    ) {
        Ok(descriptor) => descriptor,
        Err(error) if error == rustix::io::Errno::NOENT => return Ok(None),
        Err(_) => return Err(RepairVaultStoreError::CorruptStore),
    };
    let before =
        validate_regular_file(&descriptor, owner, expected_device, expected_mount_id, None)?;
    let size = usize::try_from(before.size).map_err(|_| RepairVaultStoreError::CorruptStore)?;
    if size > maximum {
        return Err(RepairVaultStoreError::CorruptStore);
    }
    let mut file = File::from(descriptor);
    let mut bytes = Zeroizing::new(Vec::with_capacity(size));
    Read::by_ref(&mut file)
        .take((maximum + 1) as u64)
        .read_to_end(bytes.as_mut())
        .map_err(|_| RepairVaultStoreError::StorageUnavailable)?;
    if bytes.len() != size {
        return Err(RepairVaultStoreError::ConcurrentWrite);
    }
    let after = validate_regular_file(&file, owner, expected_device, expected_mount_id, None)?;
    let named = named_file_state(parent, name, owner, expected_device, None)?;
    if !before.same_object(&after) || !after.same_object(&named) || after.size != before.size {
        return Err(RepairVaultStoreError::ConcurrentWrite);
    }
    Ok(Some(bytes))
}

fn reservation_binding(draft: &RepairBackupDraft) -> String {
    let mut hasher = Sha256::new();
    hasher.update(RESERVATION_BINDING_DOMAIN);
    hash_field(&mut hasher, draft.session_id.as_bytes());
    hash_field(&mut hasher, draft.target_id.as_bytes());
    hash_field(&mut hasher, &draft.target_fingerprint);
    hash_field(&mut hasher, &draft.expected_backup_sha256);
    hash_field(&mut hasher, &draft.metadata_sha256);
    hash_field(&mut hasher, &draft.backup_size_bytes.to_be_bytes());
    hash_field(&mut hasher, &draft.required_capacity_bytes.to_be_bytes());
    encode_hex(&hasher.finalize())
}

fn vault_fingerprints(
    inner: &VaultInner,
) -> Result<(String, String, String), RepairVaultStoreError> {
    let mut identity_store = RescueDeviceIdentityStore { inner };
    let identity_public_key = identity_store
        .load_device_identity()
        .map_err(|_| RepairVaultStoreError::CorruptStore)?
        .map(|identity| identity.public_key());
    #[cfg(test)]
    let identity_public_key = identity_public_key.or(Some([0x49; 32]));
    let identity_public_key = identity_public_key.ok_or(RepairVaultStoreError::CorruptStore)?;
    let attestation = inner.mount_attestation_claims();
    #[cfg(test)]
    let luks_uuid = attestation
        .map(|claims| claims.luks_uuid)
        .unwrap_or(*b"00000000-0000-0000-0000-000000000000");
    #[cfg(not(test))]
    let luks_uuid = attestation
        .ok_or(RepairVaultStoreError::PhysicalParentUnavailable)?
        .luks_uuid;
    let (vault_id, vault_identity) = stable_vault_identity(&luks_uuid, &identity_public_key);
    let parent_claims = inner.repair_physical_parent_claims();
    #[cfg(test)]
    let parent_claims = parent_claims.or(Some(crate::RepairPhysicalParentClaims {
        parent_major: 8,
        parent_minor: 0,
        disk_sequence: 1,
        media_sector_count: 2_097_152,
        logical_sector_bytes: 512,
    }));
    let parent_claims = parent_claims.ok_or(RepairVaultStoreError::PhysicalParentUnavailable)?;
    let mut parent = Sha256::new();
    parent.update(PHYSICAL_PARENT_DOMAIN);
    parent.update(parent_claims.parent_major.to_be_bytes());
    parent.update(parent_claims.parent_minor.to_be_bytes());
    parent.update(parent_claims.disk_sequence.to_be_bytes());
    parent.update(parent_claims.media_sector_count.to_be_bytes());
    parent.update(parent_claims.logical_sector_bytes.to_be_bytes());
    let physical_parent = encode_hex(&parent.finalize());
    Ok((vault_id, vault_identity, physical_parent))
}

/// Durable Vault identity deliberately excludes mount IDs, device-mapper
/// numbers and other boot-local kernel allocation.  Those values remain part
/// of the live mount attestation, while journal recovery and rollback bind to
/// the provisioned device identity and authenticated LUKS UUID.
fn stable_vault_identity(luks_uuid: &[u8; 36], identity_public_key: &[u8; 32]) -> (String, String) {
    let mut stable_id = Sha256::new();
    stable_id.update(STABLE_VAULT_ID_DOMAIN);
    hash_field(&mut stable_id, luks_uuid);
    hash_field(&mut stable_id, identity_public_key);
    let stable_id_digest = encode_hex(&stable_id.finalize());
    let vault_id = format!("V-{}", &stable_id_digest[..32]);

    let mut stable_fingerprint = Sha256::new();
    stable_fingerprint.update(VAULT_IDENTITY_DOMAIN);
    hash_field(&mut stable_fingerprint, luks_uuid);
    hash_field(&mut stable_fingerprint, identity_public_key);
    let vault_identity = encode_hex(&stable_fingerprint.finalize());
    (vault_id, vault_identity)
}

fn hash_field(hasher: &mut Sha256, field: &[u8]) {
    hasher.update((field.len() as u64).to_be_bytes());
    hasher.update(field);
}

fn backup_filename(reservation_id: &ReservationId) -> String {
    format!("{BACKUP_PREFIX}{}", reservation_id.as_str())
}

fn backup_locator(reservation_id: &ReservationId) -> String {
    format!("vault://repair/{}", reservation_id.as_str())
}

fn valid_reservation_id(value: &str) -> bool {
    value.len() == 34
        && value.strip_prefix("B-").is_some_and(|suffix| {
            suffix
                .bytes()
                .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
        })
}

fn valid_vault_id(value: &str) -> bool {
    value.len() == 34
        && value.strip_prefix("V-").is_some_and(|suffix| {
            suffix
                .bytes()
                .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
        })
}

fn valid_prefixed_id(value: &str, prefix: &str) -> bool {
    (3..=128).contains(&value.len())
        && value.strip_prefix(prefix).is_some_and(|suffix| {
            !suffix.is_empty()
                && suffix
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
        })
}

fn valid_opaque_id(value: &str) -> bool {
    (1..=128).contains(&value.len())
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b':' | b'.'))
        && !value.contains("..")
}

fn valid_sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
}

fn encode_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut encoded = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        encoded.push(HEX[(byte >> 4) as usize] as char);
        encoded.push(HEX[(byte & 0x0f) as usize] as char);
    }
    encoded
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{RescueVaultSecrets, VAULT_MARKER_NAME, VAULT_MARKER_V1, VaultOwner};
    use rustix::pipe::{PipeFlags, pipe_with};
    use std::{
        fs::{self, OpenOptions},
        os::unix::fs::OpenOptionsExt,
        path::PathBuf,
    };
    use tempfile::TempDir;

    struct Fixture {
        _temporary: TempDir,
        root: PathBuf,
        vault: RescueVaultSecrets,
    }

    impl Fixture {
        fn new() -> Self {
            let temporary = tempfile::tempdir().expect("temporary vault");
            let root = temporary.path().join("vault");
            fs::create_dir(&root).expect("create vault root");
            fs::set_permissions(&root, std::os::unix::fs::PermissionsExt::from_mode(0o700))
                .expect("set root mode");
            write_fixture_file(&root.join(VAULT_MARKER_NAME), VAULT_MARKER_V1);
            write_fixture_file(&root.join(".kernaid-rescue-secrets.lock"), b"");
            fs::create_dir(root.join(".kernaid-secure-state-v1")).expect("create state");
            fs::set_permissions(
                root.join(".kernaid-secure-state-v1"),
                std::os::unix::fs::PermissionsExt::from_mode(0o700),
            )
            .expect("set state mode");
            let owner = VaultOwner::effective();
            let vault = RescueVaultSecrets::open_for_test(&root, owner).expect("open test vault");
            Self {
                _temporary: temporary,
                root,
                vault,
            }
        }

        fn read_only_source(&self, bytes: &[u8]) -> OwnedFd {
            let (read_end, write_end) = pipe_with(PipeFlags::CLOEXEC).expect("create source pipe");
            let mut writer = File::from(write_end);
            writer.write_all(bytes).expect("write source pipe");
            drop(writer);
            read_end
        }
    }

    fn write_fixture_file(path: &Path, bytes: &[u8]) {
        let mut file = OpenOptions::new()
            .create_new(true)
            .write(true)
            .mode(0o600)
            .open(path)
            .expect("create fixture file");
        file.write_all(bytes).expect("write fixture file");
        file.sync_all().expect("sync fixture file");
    }

    fn draft(bytes: &[u8], capacity: u64) -> RepairBackupDraft {
        RepairBackupDraft::new(
            "S-repair-test",
            "target-test",
            [7; 32],
            Sha256::digest(bytes).into(),
            canonical_fstab_metadata_sha256(),
            bytes.len() as u64,
            capacity,
        )
        .expect("valid draft")
    }

    fn binding(bytes: &[u8]) -> RepairBinding {
        RepairBinding::new(
            "P-repair-test",
            [9; 32],
            "A-repair-test",
            [10; 32],
            "rescue:selected-linux-root:etc/fstab",
            Sha256::digest(bytes).into(),
        )
        .expect("valid binding")
    }

    fn reservation_id(hex_digit: char) -> ReservationId {
        ReservationId::parse(format!("B-{}", hex_digit.to_string().repeat(32)))
            .expect("valid fixed reservation id")
    }

    fn backup_path(fixture: &Fixture, reservation_id: &ReservationId) -> PathBuf {
        fixture
            .root
            .join(REPAIR_NAMESPACE)
            .join(BACKUP_DIRECTORY)
            .join(backup_filename(reservation_id))
    }

    fn identity_fields(store: &RepairVaultStore<'_>) -> (String, String, String) {
        (
            store.vault_id.clone(),
            store.vault_identity_fingerprint.clone(),
            store.physical_parent_fingerprint.clone(),
        )
    }

    #[test]
    fn stable_vault_identity_is_full_key_and_luks_bound() {
        let luks_uuid = *b"11111111-2222-3333-4444-555555555555";
        let (vault_id, fingerprint) = stable_vault_identity(&luks_uuid, &[0x41; 32]);
        assert_eq!(vault_id.len(), 34);
        assert_eq!(fingerprint.len(), 64);
        assert_ne!(
            (vault_id.clone(), fingerprint.clone()),
            stable_vault_identity(&luks_uuid, &[0x42; 32])
        );
        assert_ne!(
            (vault_id, fingerprint),
            stable_vault_identity(b"aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee", &[0x41; 32])
        );
    }

    #[test]
    fn reserve_persist_reopen_and_callback_round_trip() {
        let fixture = Fixture::new();
        let bytes = b"UUID=missing /mnt/data ext4 defaults 0 2\n";
        let (reservation_id, locator, binding_hash) = {
            let mut store = fixture
                .vault
                .open_repair_store()
                .expect("open repair store");
            let reserved = store
                .reserve_backup(draft(bytes, 8192))
                .expect("reserve backup");
            let status = store
                .backup_status(
                    reserved.reservation_id(),
                    reserved.reservation_binding_sha256(),
                )
                .expect("reserved status");
            assert!(matches!(status, RepairBackupStatus::Reserved(_)));
            assert_eq!(
                reserved.backup_locator(),
                format!("vault://repair/{}", reserved.reservation_id().as_str())
            );
            (
                reserved.reservation_id().clone(),
                reserved.backup_locator().to_owned(),
                reserved.reservation_binding_sha256().to_owned(),
            )
        };
        {
            let mut store = fixture
                .vault
                .open_repair_store()
                .expect("reopen reserved repair store");
            let reserved = store
                .resume_reserved(&reservation_id, &binding_hash)
                .expect("resume authenticated reservation");
            let durable = store
                .persist_backup(reserved, binding(bytes), fixture.read_only_source(bytes))
                .expect("persist backup");
            assert_eq!(durable.metadata().backup_size_bytes(), bytes.len() as u64);
        }
        let store = fixture
            .vault
            .open_repair_store()
            .expect("reopen repair store");
        let status = store
            .backup_status(&reservation_id, &binding_hash)
            .expect("durable status");
        assert!(matches!(status, RepairBackupStatus::Durable(_)));
        assert_eq!(
            store.with_verified_backup(&reservation_id, &binding_hash, |reader| {
                let mut one = [0_u8; 1];
                reader
                    .read_exact(&mut one)
                    .map_err(|_| RepairVaultStoreError::StorageUnavailable)
            }),
            Err(RepairVaultStoreError::WriteVerificationFailed)
        );
        let mut observed = Vec::new();
        let metadata = store
            .with_verified_backup(&reservation_id, &binding_hash, |reader| {
                reader
                    .read_to_end(&mut observed)
                    .map_err(|_| RepairVaultStoreError::StorageUnavailable)?;
                Ok(())
            })
            .expect("verified callback");
        assert_eq!(observed, bytes);
        assert_eq!(metadata.backup_locator(), locator);
        assert_eq!(metadata.reservation_binding_sha256(), binding_hash);
        assert_eq!(metadata.backup_sha256(), encode_hex(&Sha256::digest(bytes)));
    }

    #[test]
    fn source_hash_mismatch_does_not_consume_reservation() {
        let fixture = Fixture::new();
        let expected = b"expected\n";
        let other = b"differen\n";
        let mut store = fixture
            .vault
            .open_repair_store()
            .expect("open repair store");
        let reserved = store
            .reserve_backup(draft(expected, 4096))
            .expect("reserve backup");
        let reservation_id = reserved.reservation_id().clone();
        let reservation_binding_sha256 = reserved.reservation_binding_sha256().to_owned();
        assert_eq!(
            store.persist_backup(reserved, binding(expected), fixture.read_only_source(other),),
            Err(RepairVaultStoreError::SourceHashMismatch)
        );
        let status = store
            .backup_status(&reservation_id, &reservation_binding_sha256)
            .expect("reservation remains valid");
        assert!(matches!(status, RepairBackupStatus::Reserved(_)));
    }

    #[test]
    fn persist_accepts_exact_closed_pipe_and_consumes_capability() {
        let fixture = Fixture::new();
        let bytes = b"pipe backup\n";
        let mut store = fixture
            .vault
            .open_repair_store()
            .expect("open repair store");
        let reserved = store
            .reserve_backup(draft(bytes, 4096))
            .expect("reserve backup");
        let (read_end, write_end) = pipe_with(PipeFlags::CLOEXEC).expect("create pipe");
        let mut writer = File::from(write_end);
        writer.write_all(bytes).expect("write exact pipe payload");
        drop(writer);

        store
            .persist_backup(reserved, binding(bytes), read_end)
            .expect("persist exact pipe payload");
    }

    #[test]
    fn binding_hash_mismatch_is_rejected_and_reservation_can_be_cancelled() {
        let fixture = Fixture::new();
        let bytes = b"binding backup\n";
        let mut store = fixture
            .vault
            .open_repair_store()
            .expect("open repair store");
        let reserved = store
            .reserve_backup(draft(bytes, 4096))
            .expect("reserve backup");
        let reservation_id = reserved.reservation_id().clone();
        assert_eq!(
            store.persist_backup(
                reserved,
                binding(b"different bytes\n"),
                fixture.read_only_source(bytes),
            ),
            Err(RepairVaultStoreError::InvalidBinding)
        );
        let resumed = store
            .resume_reserved(&reservation_id, &reservation_binding(&draft(bytes, 4096)))
            .expect("resume rejected reservation");
        store
            .cancel_reservation(resumed)
            .expect("cancel reservation");
        assert_eq!(
            store.backup_status(&reservation_id, &reservation_binding(&draft(bytes, 4096))),
            Ok(RepairBackupStatus::Absent)
        );
    }

    #[test]
    fn reopen_completes_fully_allocated_zero_reservation_intent() {
        let fixture = Fixture::new();
        let bytes = b"pending reservation\n";
        let reservation_id = reservation_id('1');
        let backup_draft = draft(bytes, 4096);
        {
            let mut store = fixture
                .vault
                .open_repair_store()
                .expect("open repair store");
            let (vault_id, vault_identity_fingerprint, physical_parent_fingerprint) =
                identity_fields(&store);
            store
                .append_event(RepairEvent::ReserveIntent {
                    reservation_id: reservation_id.clone(),
                    reservation_binding_sha256: reservation_binding(&backup_draft),
                    reserved_capacity_bytes: 4096,
                    draft: backup_draft,
                    vault_id,
                    vault_identity_fingerprint,
                    physical_parent_fingerprint,
                })
                .expect("append reserve intent");
            store
                .allocate_and_verify(&reservation_id, 4096)
                .expect("allocate reservation without completing journal event");
        }

        let store = fixture
            .vault
            .open_repair_store()
            .expect("reconcile reservation intent");
        assert!(matches!(
            store.backup_status(&reservation_id, &reservation_binding(&draft(bytes, 4096)),),
            Ok(RepairBackupStatus::Reserved(_))
        ));
    }

    #[test]
    fn reopen_removes_partial_reservation_and_aborts_intent() {
        let fixture = Fixture::new();
        let bytes = b"partial reservation\n";
        let reservation_id = reservation_id('2');
        let backup_draft = draft(bytes, 4096);
        {
            let mut store = fixture
                .vault
                .open_repair_store()
                .expect("open repair store");
            let (vault_id, vault_identity_fingerprint, physical_parent_fingerprint) =
                identity_fields(&store);
            store
                .append_event(RepairEvent::ReserveIntent {
                    reservation_id: reservation_id.clone(),
                    reservation_binding_sha256: reservation_binding(&backup_draft),
                    reserved_capacity_bytes: 4096,
                    draft: backup_draft,
                    vault_id,
                    vault_identity_fingerprint,
                    physical_parent_fingerprint,
                })
                .expect("append reserve intent");
        }
        let path = backup_path(&fixture, &reservation_id);
        write_fixture_file(&path, b"partial");

        let store = fixture
            .vault
            .open_repair_store()
            .expect("reconcile partial reservation");
        assert_eq!(
            store.backup_status(&reservation_id, &"0".repeat(64)),
            Ok(RepairBackupStatus::Absent)
        );
        assert!(!path.exists());
    }

    #[test]
    fn reopen_aborts_missing_reservation_intent() {
        let fixture = Fixture::new();
        let bytes = b"missing reservation\n";
        let reservation_id = reservation_id('3');
        let backup_draft = draft(bytes, 4096);
        {
            let mut store = fixture
                .vault
                .open_repair_store()
                .expect("open repair store");
            let (vault_id, vault_identity_fingerprint, physical_parent_fingerprint) =
                identity_fields(&store);
            store
                .append_event(RepairEvent::ReserveIntent {
                    reservation_id: reservation_id.clone(),
                    reservation_binding_sha256: reservation_binding(&backup_draft),
                    reserved_capacity_bytes: 4096,
                    draft: backup_draft,
                    vault_id,
                    vault_identity_fingerprint,
                    physical_parent_fingerprint,
                })
                .expect("append reserve intent without creating a file");
        }

        let store = fixture
            .vault
            .open_repair_store()
            .expect("abort missing reservation intent");
        assert_eq!(
            store.backup_status(&reservation_id, &"0".repeat(64)),
            Ok(RepairBackupStatus::Absent)
        );
    }

    #[test]
    fn reopen_completes_exact_persist_intent() {
        let fixture = Fixture::new();
        let exact_bytes = b"durable before completion\n";
        let exact_id = {
            let mut store = fixture
                .vault
                .open_repair_store()
                .expect("open repair store");
            let exact = store
                .reserve_backup(draft(exact_bytes, 4096))
                .expect("reserve exact backup");
            let exact_id = exact.reservation_id().clone();

            store
                .append_event(RepairEvent::PersistIntent {
                    reservation_id: exact_id.clone(),
                    binding: binding(exact_bytes),
                })
                .expect("append exact persist intent");
            store
                .install_and_verify(
                    &exact_id,
                    exact_bytes,
                    exact_bytes.len() as u64,
                    Sha256::digest(exact_bytes).into(),
                    4096,
                )
                .expect("install exact backup without completion event");
            exact_id
        };

        let store = fixture
            .vault
            .open_repair_store()
            .expect("complete exact persist intent");
        assert!(matches!(
            store.backup_status(&exact_id, &reservation_binding(&draft(exact_bytes, 4096)),),
            Ok(RepairBackupStatus::Durable(_))
        ));
    }

    #[test]
    fn reopen_reconciles_durable_bytes_after_live_parent_drift() {
        let fixture = Fixture::new();
        let bytes = b"durable across reboot\n";
        let reservation_id = reservation_id('8');
        let backup_draft = draft(bytes, 4096);
        let draft_binding = reservation_binding(&backup_draft);
        let stale_parent = "f".repeat(64);
        {
            let mut store = fixture
                .vault
                .open_repair_store()
                .expect("open repair store");
            assert_ne!(store.physical_parent_fingerprint, stale_parent);
            store
                .append_event(RepairEvent::ReserveIntent {
                    reservation_id: reservation_id.clone(),
                    reservation_binding_sha256: draft_binding.clone(),
                    reserved_capacity_bytes: 4096,
                    draft: backup_draft,
                    vault_id: store.vault_id.clone(),
                    vault_identity_fingerprint: store.vault_identity_fingerprint.clone(),
                    physical_parent_fingerprint: stale_parent,
                })
                .expect("append historical reserve intent");
            store
                .allocate_and_verify(&reservation_id, 4096)
                .expect("allocate historical reservation");
            store
                .append_event(RepairEvent::ReserveComplete {
                    reservation_id: reservation_id.clone(),
                })
                .expect("complete historical reservation");
            assert_eq!(
                store.resume_reserved(&reservation_id, &draft_binding).err(),
                Some(RepairVaultStoreError::ReservationConflict)
            );
            store
                .append_event(RepairEvent::PersistIntent {
                    reservation_id: reservation_id.clone(),
                    binding: binding(bytes),
                })
                .expect("append persist intent before simulated power loss");
            store
                .install_and_verify(
                    &reservation_id,
                    bytes,
                    bytes.len() as u64,
                    Sha256::digest(bytes).into(),
                    4096,
                )
                .expect("install durable bytes before simulated power loss");
        }

        let store = fixture
            .vault
            .open_repair_store()
            .expect("reconcile persist intent after reboot-local parent drift");
        assert!(matches!(
            store.backup_status(&reservation_id, &draft_binding),
            Ok(RepairBackupStatus::Durable(_))
        ));
        let mut observed = Vec::new();
        store
            .with_verified_backup(&reservation_id, &draft_binding, |reader| {
                reader
                    .read_to_end(&mut observed)
                    .map_err(|_| RepairVaultStoreError::StorageUnavailable)?;
                Ok(())
            })
            .expect("read durable backup after parent drift");
        assert_eq!(observed, bytes);
    }

    #[test]
    fn stable_identity_drift_blocks_before_pending_reconciliation() {
        let fixture = Fixture::new();
        let bytes = b"do not reconcile on a different vault\n";
        let reservation_id = reservation_id('9');
        let backup_draft = draft(bytes, 4096);
        {
            let mut store = fixture
                .vault
                .open_repair_store()
                .expect("open repair store");
            let conflicting_identity = if store.vault_identity_fingerprint == "e".repeat(64) {
                "d".repeat(64)
            } else {
                "e".repeat(64)
            };
            store
                .append_event(RepairEvent::ReserveIntent {
                    reservation_id,
                    reservation_binding_sha256: reservation_binding(&backup_draft),
                    reserved_capacity_bytes: 4096,
                    draft: backup_draft,
                    vault_id: store.vault_id.clone(),
                    vault_identity_fingerprint: conflicting_identity,
                    physical_parent_fingerprint: store.physical_parent_fingerprint.clone(),
                })
                .expect("append conflicting pending identity");
        }

        assert_eq!(
            fixture.vault.open_repair_store().err(),
            Some(RepairVaultStoreError::ReservationConflict)
        );
        assert_eq!(
            fixture.vault.open_repair_store().err(),
            Some(RepairVaultStoreError::ReservationConflict)
        );
    }

    #[test]
    fn reopen_resets_partial_persist_intent_to_reserved() {
        let fixture = Fixture::new();
        let partial_bytes = b"must be reset\n";
        let partial_id = {
            let mut store = fixture
                .vault
                .open_repair_store()
                .expect("open repair store");
            let partial = store
                .reserve_backup(draft(partial_bytes, 4096))
                .expect("reserve partial backup");
            let partial_id = partial.reservation_id().clone();
            store
                .append_event(RepairEvent::PersistIntent {
                    reservation_id: partial_id.clone(),
                    binding: binding(partial_bytes),
                })
                .expect("append partial persist intent");
            partial_id
        };

        let partial_path = backup_path(&fixture, &partial_id);
        let partial = OpenOptions::new()
            .write(true)
            .truncate(true)
            .open(&partial_path)
            .expect("open partial backup");
        partial.set_len(7).expect("truncate partial backup");
        partial.sync_all().expect("sync partial backup");
        drop(partial);

        let store = fixture
            .vault
            .open_repair_store()
            .expect("reconcile partial persist intent");
        assert!(matches!(
            store.backup_status(
                &partial_id,
                &reservation_binding(&draft(partial_bytes, 4096)),
            ),
            Ok(RepairBackupStatus::Reserved(_))
        ));
        assert_eq!(
            fs::metadata(partial_path).expect("reset metadata").len(),
            4096
        );
    }

    #[test]
    fn reopen_removes_valid_orphan_secret_temporary_file() {
        let fixture = Fixture::new();
        {
            let _store = fixture.vault.open_repair_store().expect("initialize store");
        }
        let temporary = fixture
            .root
            .join(REPAIR_NAMESPACE)
            .join(format!("{TEMP_PREFIX}{}", "a".repeat(32)));
        let envelope = encode_secret(RepairSecretKind::Key, &[0x42; JOURNAL_KEY_BYTES]);
        write_fixture_file(&temporary, &envelope);

        let _store = fixture
            .vault
            .open_repair_store()
            .expect("remove valid orphan temporary file");
        assert!(!temporary.exists());
    }

    #[test]
    fn tampered_backup_fails_closed_without_path_disclosure() {
        let fixture = Fixture::new();
        let bytes = b"original\n";
        let reservation_id = {
            let mut store = fixture
                .vault
                .open_repair_store()
                .expect("open repair store");
            let reserved = store
                .reserve_backup(draft(bytes, 4096))
                .expect("reserve backup");
            let reservation_id = reserved.reservation_id().clone();
            store
                .persist_backup(reserved, binding(bytes), fixture.read_only_source(bytes))
                .expect("persist backup");
            reservation_id
        };
        let name = backup_filename(&reservation_id);
        let path = fixture
            .root
            .join(REPAIR_NAMESPACE)
            .join(BACKUP_DIRECTORY)
            .join(name);
        let mut tamper = OpenOptions::new()
            .write(true)
            .open(&path)
            .expect("open backup for tamper");
        tamper.write_all(b"X").expect("tamper backup");
        tamper.sync_all().expect("sync tamper");
        drop(tamper);
        let store = fixture
            .vault
            .open_repair_store()
            .expect("reopen repair store");
        let error = store
            .backup_status(&reservation_id, &reservation_binding(&draft(bytes, 4096)))
            .expect_err("tamper must fail closed");
        assert_eq!(error, RepairVaultStoreError::WriteVerificationFailed);
        assert!(!error.to_string().contains(path.to_string_lossy().as_ref()));
    }

    #[test]
    fn reservation_identifier_rejects_path_syntax() {
        assert_eq!(
            ReservationId::parse("B-../../outside"),
            Err(RepairVaultStoreError::InvalidReservationId)
        );
        assert_eq!(
            RepairBackupDraft::new("S-ok", "/dev/sda", [1; 32], [2; 32], [3; 32], 1, 1),
            Err(RepairVaultStoreError::InvalidDraft)
        );
        assert!(
            RepairBinding::new(
                "P-real-resource",
                [1; 32],
                "A-real-resource",
                [2; 32],
                "rescue:selected-linux-root:etc/fstab",
                [3; 32],
            )
            .is_ok()
        );
        assert_eq!(
            RepairBinding::new(
                "P-bad-resource",
                [1; 32],
                "A-bad-resource",
                [2; 32],
                "/etc/fstab",
                [3; 32],
            ),
            Err(RepairVaultStoreError::InvalidBinding)
        );
    }

    #[test]
    fn stable_cancel_releases_reserved_capacity_without_live_parent_authority() {
        let fixture = Fixture::new();
        let bytes = b"cancel without parent remint\n";
        let reservation_id = reservation_id('a');
        let backup_draft = draft(bytes, 4096);
        let draft_binding = reservation_binding(&backup_draft);
        let mut store = fixture
            .vault
            .open_repair_store()
            .expect("open repair store");
        let stale_parent = if store.physical_parent_fingerprint == "f".repeat(64) {
            "e".repeat(64)
        } else {
            "f".repeat(64)
        };
        store
            .append_event(RepairEvent::ReserveIntent {
                reservation_id: reservation_id.clone(),
                draft: backup_draft,
                reservation_binding_sha256: draft_binding.clone(),
                reserved_capacity_bytes: 4096,
                vault_id: store.vault_id.clone(),
                vault_identity_fingerprint: store.vault_identity_fingerprint.clone(),
                physical_parent_fingerprint: stale_parent,
            })
            .expect("append historical reserve intent");
        store
            .allocate_and_verify(&reservation_id, 4096)
            .expect("allocate reservation");
        store
            .append_event(RepairEvent::ReserveComplete {
                reservation_id: reservation_id.clone(),
            })
            .expect("complete reservation");
        assert_eq!(
            store.resume_reserved(&reservation_id, &draft_binding).err(),
            Some(RepairVaultStoreError::ReservationConflict)
        );
        assert_eq!(
            store.cancel_reserved(&reservation_id, &draft_binding),
            Ok(4096)
        );
        // A lost success response must be retryable without another journal
        // mutation or live-parent authority.
        assert_eq!(
            store.cancel_reserved(&reservation_id, &draft_binding),
            Ok(4096)
        );
        assert_eq!(
            store.cancel_reserved(&reservation_id, &"f".repeat(64)),
            Err(RepairVaultStoreError::ReservationConflict)
        );
        drop(store);

        let mut store = fixture
            .vault
            .open_repair_store()
            .expect("rebuild cancel tombstone after restart");
        assert_eq!(
            store.cancel_reserved(&reservation_id, &draft_binding),
            Ok(4096)
        );
        assert_eq!(
            store.backup_status(&reservation_id, &draft_binding),
            Ok(RepairBackupStatus::Absent)
        );
        assert_eq!(
            store.backup_status(&reservation_id, &"f".repeat(64)),
            Err(RepairVaultStoreError::ReservationConflict)
        );
    }

    #[test]
    fn durable_retire_requires_exact_status_and_recovers_after_unlink() {
        let fixture = Fixture::new();
        let bytes = b"durable retirement\n";
        let (reservation_id, draft_binding, metadata) = {
            let mut store = fixture
                .vault
                .open_repair_store()
                .expect("open repair store");
            let reserved = store
                .reserve_backup(draft(bytes, 4096))
                .expect("reserve backup");
            let reservation_id = reserved.reservation_id().clone();
            let draft_binding = reserved.reservation_binding_sha256().to_owned();
            let durable = store
                .persist_backup(reserved, binding(bytes), fixture.read_only_source(bytes))
                .expect("persist backup");
            (reservation_id, draft_binding, durable.metadata().clone())
        };
        {
            let mut store = fixture
                .vault
                .open_repair_store()
                .expect("reopen repair store");
            let mut wrong = metadata.clone();
            wrong.approval_sha256 = "f".repeat(64);
            assert_eq!(
                store.retire_backup(&wrong),
                Err(RepairVaultStoreError::ReservationConflict)
            );
            store
                .append_event(RepairEvent::RetireIntent {
                    reservation_id: reservation_id.clone(),
                })
                .expect("append retire intent");
            let (_, state) = store
                .open_pending_backup_file(&reservation_id, OFlags::RDONLY)
                .expect("open pending backup")
                .expect("durable file exists");
            store
                .remove_pending_backup_file(&reservation_id, &state)
                .expect("unlink before simulated crash");
        }
        let mut store = fixture
            .vault
            .open_repair_store()
            .expect("complete retire after restart");
        assert_eq!(
            store.backup_status(&reservation_id, &draft_binding),
            Ok(RepairBackupStatus::Absent)
        );
        assert!(!backup_path(&fixture, &reservation_id).exists());
        assert_eq!(store.retire_backup(&metadata), Ok(4096));
        let mut wrong = metadata.clone();
        wrong.approval_sha256 = "f".repeat(64);
        assert_eq!(
            store.retire_backup(&wrong),
            Err(RepairVaultStoreError::ReservationConflict)
        );
        assert_eq!(
            store.cancel_reserved(&reservation_id, &draft_binding),
            Err(RepairVaultStoreError::ReservationConflict)
        );
        assert!(store.reserve_backup(draft(b"slot reused\n", 4096)).is_ok());
        drop(store);

        let mut store = fixture
            .vault
            .open_repair_store()
            .expect("rebuild retire tombstone after second restart");
        assert_eq!(store.retire_backup(&metadata), Ok(4096));
    }
}
