//! Closed, path-free values for the experimental Rescue repair backup store.
//!
//! The server derives storage paths exclusively from a validated reservation
//! identifier. These values intentionally contain no path, command, raw
//! backup bytes, device name or executable operation.

use crate::rescue_vault::{DescriptorDeclaration, DescriptorType, ProtocolViolation, Sha256};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256 as Sha256Hasher};

/// Maximum supported backup body for the first bounded configuration repair.
pub const MAX_REPAIR_BACKUP_BYTES: u64 = 16 * 1024 * 1024;
/// Maximum capacity one request may reserve in the repair store.
pub const MAX_REPAIR_RESERVED_BYTES: u64 = 16 * 1024 * 1024;
/// Stable logical namespace; it is not a host filesystem path.
pub const REPAIR_BACKUP_LOCATOR_PREFIX: &str = "vault://repair/";
/// The only mutation this first transaction protocol can describe.
pub const REPAIR_EXECUTION_ACTION_ID: &str = "linux.fstab.disable-missing-uuid.v1";
/// The only resource this first transaction protocol can mutate.
pub const REPAIR_EXECUTION_RESOURCE_ID: &str = "rescue:selected-linux-root:etc/fstab";
/// The sole root-helper capability that a consumed V1 lease can authorize.
pub const REPAIR_WRITE_LEASE_CAPABILITY: &str = "fstab-direct-leaf-rw-v1";
/// The sole post-commit rollback action represented by this protocol.
pub const REPAIR_ROLLBACK_ACTION_ID: &str = "linux.fstab.restore";
/// The sole root-helper capability represented by a consumed rollback lease.
pub const REPAIR_ROLLBACK_WRITE_LEASE_CAPABILITY: &str = "fstab-rollback-direct-leaf-rw-v1";
/// Closed crypttab mutation supported by the shared repair transaction engine.
pub const CRYPTTAB_REPAIR_EXECUTION_ACTION_ID: &str = "linux.crypttab.disable-missing-uuid.v1";
/// Logical crypttab resource; never interpreted as a caller-controlled path.
pub const CRYPTTAB_REPAIR_EXECUTION_RESOURCE_ID: &str = "rescue:selected-linux-root:etc/crypttab";
/// Root-helper capability for one consumed crypttab write lease.
pub const CRYPTTAB_REPAIR_WRITE_LEASE_CAPABILITY: &str = "crypttab-direct-leaf-rw-v1";
/// Closed post-commit rollback action for crypttab.
pub const CRYPTTAB_REPAIR_ROLLBACK_ACTION_ID: &str = "linux.crypttab.disable-missing-source.v1";
/// Root-helper capability for one consumed crypttab rollback lease.
pub const CRYPTTAB_REPAIR_ROLLBACK_WRITE_LEASE_CAPABILITY: &str =
    "crypttab-rollback-direct-leaf-rw-v1";
/// Closed, candidate-only ext4 repair. The durable Vault object is the
/// normalized preflight evidence; the e2fsck undo stream remains a same-boot
/// capability and is never represented as a durable full-filesystem backup.
pub const EXT4_REPAIR_EXECUTION_ACTION_ID: &str = "linux.ext4.fsck-preen-with-undo.v1";
pub const EXT4_REPAIR_EXECUTION_RESOURCE_ID: &str = "rescue:selected-linux-filesystem:ext4";
pub const EXT4_REPAIR_WRITE_LEASE_CAPABILITY: &str = "ext4-block-rw-v1";
pub const EXT4_REPAIR_ROLLBACK_ACTION_ID: &str = "linux.ext4.fsck-undo.same-boot.v1";
pub const EXT4_REPAIR_ROLLBACK_WRITE_LEASE_CAPABILITY: &str = "ext4-block-rollback-rw-v1";
/// Closed resolver-link repair. Public clients select this logical resource,
/// never a filesystem path or link target.
pub const RESOLVER_LINK_REPAIR_EXECUTION_ACTION_ID: &str = "linux.network.restore-resolver-link.v1";
pub const RESOLVER_LINK_REPAIR_EXECUTION_RESOURCE_ID: &str =
    "rescue:selected-linux-root:etc/resolver-link";
pub const RESOLVER_LINK_REPAIR_WRITE_LEASE_CAPABILITY: &str = "resolver-link-direct-leaf-rw-v1";
pub const RESOLVER_LINK_REPAIR_ROLLBACK_ACTION_ID: &str =
    "linux.network.restore-resolver-link-state.v1";
pub const RESOLVER_LINK_REPAIR_ROLLBACK_WRITE_LEASE_CAPABILITY: &str =
    "resolver-link-rollback-direct-leaf-rw-v1";

const MAX_OPAQUE_ID_BYTES: usize = 128;
const RESERVATION_BINDING_DOMAIN: &[u8] = b"KERNAID-REPAIR-RESERVATION-V1\0";
const FILE_METADATA_DOMAIN: &[u8] = b"KERNAID-REPAIR-FILE-METADATA-V1\0";
const EXECUTION_INTENT_BINDING_DOMAIN: &[u8] = b"KERNAID-REPAIR-EXECUTION-INTENT-V1\0";
const TRANSACTION_BINDING_DOMAIN: &[u8] = b"KERNAID-REPAIR-TRANSACTION-V1\0";
const WRITE_LEASE_BINDING_DOMAIN: &[u8] = b"KERNAID-REPAIR-WRITE-LEASE-V1\0";
const ROLLBACK_TRANSACTION_BINDING_DOMAIN: &[u8] = b"KERNAID-REPAIR-ROLLBACK-TRANSACTION-V1\0";
const ROLLBACK_WRITE_LEASE_BINDING_DOMAIN: &[u8] = b"KERNAID-REPAIR-ROLLBACK-WRITE-LEASE-V1\0";
const LOCK_ID_DOMAIN: &[u8] = b"kernaid:rescue-fstab:target-lock:v2\0";
const CRYPTTAB_LOCK_ID_DOMAIN: &[u8] = b"kernaid:rescue-crypttab:target-lock:v1\0";
const EXT4_LOCK_ID_DOMAIN: &[u8] = b"kernaid:rescue-ext4-fsck:target-lock:v1\0";
const RESOLVER_LINK_LOCK_ID_DOMAIN: &[u8] = b"kernaid:rescue-resolver-link:target-lock:v1\0";
const MAX_PERMISSION_MODE: u32 = 0o7777;
const MAX_SAFE_JSON_INTEGER: u64 = 9_007_199_254_740_991;

/// Complete set of regular files the Rescue transaction engine may mutate.
/// No API in this module accepts a raw path, command or arbitrary action.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RepairResourceV1 {
    Fstab,
    Crypttab,
    Ext4Filesystem,
    ResolverLink,
}

impl RepairResourceV1 {
    pub const fn action_id(self) -> &'static str {
        match self {
            Self::Fstab => REPAIR_EXECUTION_ACTION_ID,
            Self::Crypttab => CRYPTTAB_REPAIR_EXECUTION_ACTION_ID,
            Self::Ext4Filesystem => EXT4_REPAIR_EXECUTION_ACTION_ID,
            Self::ResolverLink => RESOLVER_LINK_REPAIR_EXECUTION_ACTION_ID,
        }
    }

    pub const fn resource_id(self) -> &'static str {
        match self {
            Self::Fstab => REPAIR_EXECUTION_RESOURCE_ID,
            Self::Crypttab => CRYPTTAB_REPAIR_EXECUTION_RESOURCE_ID,
            Self::Ext4Filesystem => EXT4_REPAIR_EXECUTION_RESOURCE_ID,
            Self::ResolverLink => RESOLVER_LINK_REPAIR_EXECUTION_RESOURCE_ID,
        }
    }

    pub const fn write_lease_capability(self) -> &'static str {
        match self {
            Self::Fstab => REPAIR_WRITE_LEASE_CAPABILITY,
            Self::Crypttab => CRYPTTAB_REPAIR_WRITE_LEASE_CAPABILITY,
            Self::Ext4Filesystem => EXT4_REPAIR_WRITE_LEASE_CAPABILITY,
            Self::ResolverLink => RESOLVER_LINK_REPAIR_WRITE_LEASE_CAPABILITY,
        }
    }

    pub const fn rollback_action_id(self) -> &'static str {
        match self {
            Self::Fstab => REPAIR_ROLLBACK_ACTION_ID,
            Self::Crypttab => CRYPTTAB_REPAIR_ROLLBACK_ACTION_ID,
            Self::Ext4Filesystem => EXT4_REPAIR_ROLLBACK_ACTION_ID,
            Self::ResolverLink => RESOLVER_LINK_REPAIR_ROLLBACK_ACTION_ID,
        }
    }

    pub const fn rollback_write_lease_capability(self) -> &'static str {
        match self {
            Self::Fstab => REPAIR_ROLLBACK_WRITE_LEASE_CAPABILITY,
            Self::Crypttab => CRYPTTAB_REPAIR_ROLLBACK_WRITE_LEASE_CAPABILITY,
            Self::Ext4Filesystem => EXT4_REPAIR_ROLLBACK_WRITE_LEASE_CAPABILITY,
            Self::ResolverLink => RESOLVER_LINK_REPAIR_ROLLBACK_WRITE_LEASE_CAPABILITY,
        }
    }

    pub fn from_resource_id(value: &str) -> Result<Self, ProtocolViolation> {
        match value {
            REPAIR_EXECUTION_RESOURCE_ID => Ok(Self::Fstab),
            CRYPTTAB_REPAIR_EXECUTION_RESOURCE_ID => Ok(Self::Crypttab),
            EXT4_REPAIR_EXECUTION_RESOURCE_ID => Ok(Self::Ext4Filesystem),
            RESOLVER_LINK_REPAIR_EXECUTION_RESOURCE_ID => Ok(Self::ResolverLink),
            _ => Err(ProtocolViolation::InvalidPayload),
        }
    }

    pub fn from_execution(action_id: &str, resource_id: &str) -> Result<Self, ProtocolViolation> {
        let resource = Self::from_resource_id(resource_id)?;
        if action_id != resource.action_id() {
            return Err(ProtocolViolation::InvalidPayload);
        }
        Ok(resource)
    }

    fn supports_metadata(self, metadata: &RepairFileMetadataV1) -> bool {
        match self {
            Self::Fstab => metadata.mode == 0o644,
            Self::Crypttab => matches!(metadata.mode, 0o600 | 0o644),
            // This metadata binds the small normalized evidence object stored
            // in the Repair Vault, not target filesystem metadata.
            Self::Ext4Filesystem => metadata.mode == 0o600,
            // Metadata describes the canonical backup-state envelope stored
            // in the Vault. The target object itself is always a symlink or
            // exact absence and has no caller-controlled metadata.
            Self::ResolverLink => metadata.mode == 0o600,
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum RepairMetadataAbsence {
    None,
}

/// Closed, path-free metadata for the first regular-file repair resource.
#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RepairFileMetadataV1 {
    mode: u32,
    uid: u32,
    gid: u32,
    xattrs: RepairMetadataAbsence,
    posix_acl: RepairMetadataAbsence,
}

impl RepairFileMetadataV1 {
    pub fn new(mode: u32, uid: u32, gid: u32) -> Result<Self, ProtocolViolation> {
        if mode > MAX_PERMISSION_MODE {
            return Err(ProtocolViolation::InvalidPayload);
        }
        Ok(Self {
            mode,
            uid,
            gid,
            xattrs: RepairMetadataAbsence::None,
            posix_acl: RepairMetadataAbsence::None,
        })
    }
    pub const fn mode(&self) -> u32 {
        self.mode
    }
    pub const fn uid(&self) -> u32 {
        self.uid
    }
    pub const fn gid(&self) -> u32 {
        self.gid
    }
    pub fn canonical_sha256(&self) -> Sha256 {
        canonical_repair_file_metadata_sha256(self)
    }
    pub(crate) fn validate(&self) -> Result<(), ProtocolViolation> {
        if self.mode > MAX_PERMISSION_MODE {
            return Err(ProtocolViolation::InvalidPayload);
        }
        Ok(())
    }
}

pub fn canonical_repair_file_metadata_sha256(metadata: &RepairFileMetadataV1) -> Sha256 {
    let mut hasher = Sha256Hasher::new();
    hasher.update(FILE_METADATA_DOMAIN);
    hash_field(&mut hasher, &metadata.mode.to_be_bytes());
    hash_field(&mut hasher, &metadata.uid.to_be_bytes());
    hash_field(&mut hasher, &metadata.gid.to_be_bytes());
    hash_field(&mut hasher, &[0]);
    hash_field(&mut hasher, &[0]);
    Sha256::parse(&encode_hex(&hasher.finalize())).expect("SHA-256 digest is canonical")
}

/// Opaque backup reservation identifier (`B-` plus 32 lowercase hex digits).
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(transparent)]
pub struct RepairReservationId(String);

impl<'de> Deserialize<'de> for RepairReservationId {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        Self::parse(&value).map_err(serde::de::Error::custom)
    }
}

impl RepairReservationId {
    pub fn parse(value: &str) -> Result<Self, ProtocolViolation> {
        let Some(suffix) = value.strip_prefix("B-") else {
            return Err(ProtocolViolation::InvalidPayload);
        };
        if suffix.len() != 32 || !suffix.bytes().all(is_lower_hex) {
            return Err(ProtocolViolation::InvalidPayload);
        }
        Ok(Self(value.to_owned()))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub fn locator(&self) -> String {
        format!("{REPAIR_BACKUP_LOCATOR_PREFIX}{}", self.0)
    }
}

/// Immutable material from which the Vault mints a durable reservation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RepairBackupDraft {
    session_id: String,
    target_id: String,
    target_fingerprint: Sha256,
    target_recovery_fingerprint: String,
    expected_backup_sha256: Sha256,
    metadata_sha256: Sha256,
    backup_size: u64,
    required_capacity_bytes: u64,
}

impl RepairBackupDraft {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        session_id: impl Into<String>,
        target_id: impl Into<String>,
        target_fingerprint: Sha256,
        target_recovery_fingerprint: impl Into<String>,
        expected_backup_sha256: Sha256,
        metadata_sha256: Sha256,
        backup_size: u64,
        required_capacity_bytes: u64,
    ) -> Result<Self, ProtocolViolation> {
        let value = Self {
            session_id: session_id.into(),
            target_id: target_id.into(),
            target_fingerprint,
            target_recovery_fingerprint: target_recovery_fingerprint.into(),
            expected_backup_sha256,
            metadata_sha256,
            backup_size,
            required_capacity_bytes,
        };
        if !valid_prefixed_id(&value.session_id, "S-")
            || !valid_opaque_id(&value.target_id)
            || !valid_digest_id(&value.target_recovery_fingerprint, "recovery:")
            || !(1..=MAX_REPAIR_BACKUP_BYTES).contains(&value.backup_size)
            || !(value.backup_size..=MAX_REPAIR_RESERVED_BYTES)
                .contains(&value.required_capacity_bytes)
        {
            return Err(ProtocolViolation::InvalidPayload);
        }
        Ok(value)
    }

    pub fn session_id(&self) -> &str {
        &self.session_id
    }
    pub fn target_id(&self) -> &str {
        &self.target_id
    }
    pub fn target_fingerprint(&self) -> &Sha256 {
        &self.target_fingerprint
    }
    pub fn target_recovery_fingerprint(&self) -> &str {
        &self.target_recovery_fingerprint
    }
    pub fn expected_backup_sha256(&self) -> &Sha256 {
        &self.expected_backup_sha256
    }
    pub fn metadata_sha256(&self) -> &Sha256 {
        &self.metadata_sha256
    }
    pub const fn backup_size(&self) -> u64 {
        self.backup_size
    }
    pub const fn required_capacity_bytes(&self) -> u64 {
        self.required_capacity_bytes
    }

    /// Computes the exact store-side pre-plan binding. Every field is framed
    /// by an unsigned 64-bit big-endian length before its bytes.
    pub fn draft_binding_sha256(&self) -> Sha256 {
        canonical_repair_draft_binding_sha256(self)
    }
}

/// Computes the canonical store-compatible binding for a validated draft.
pub fn canonical_repair_draft_binding_sha256(draft: &RepairBackupDraft) -> Sha256 {
    let mut hasher = Sha256Hasher::new();
    hasher.update(RESERVATION_BINDING_DOMAIN);
    hash_field(&mut hasher, draft.session_id.as_bytes());
    hash_field(&mut hasher, draft.target_id.as_bytes());
    hash_field(&mut hasher, &draft.target_fingerprint.bytes());
    hash_field(&mut hasher, draft.target_recovery_fingerprint.as_bytes());
    hash_field(&mut hasher, &draft.expected_backup_sha256.bytes());
    hash_field(&mut hasher, &draft.metadata_sha256.bytes());
    hash_field(&mut hasher, &draft.backup_size.to_be_bytes());
    hash_field(&mut hasher, &draft.required_capacity_bytes.to_be_bytes());
    Sha256::parse(&encode_hex(&hasher.finalize())).expect("SHA-256 digest is canonical")
}

/// Durable, path-free description of the one approved mutation that recovery
/// is allowed to reconcile after a reboot.
///
/// This value is audit data, not execution authority. In particular it
/// contains no path, descriptor, replacement bytes, command, or generic
/// action argument.
#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RepairExecutionIntentV1 {
    action_id: String,
    session_id: String,
    approval_sequence: u64,
    target_id: String,
    scan_fingerprint: String,
    target_fingerprint: Sha256,
    target_physical_parent_fingerprint: Sha256,
    target_recovery_fingerprint: String,
    lock_identity: String,
    before_sha256: Sha256,
    after_sha256: Sha256,
    diff_sha256: Sha256,
    observed_uuid_set_sha256: Sha256,
    before_metadata: RepairFileMetadataV1,
}

impl RepairExecutionIntentV1 {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        session_id: impl Into<String>,
        approval_sequence: u64,
        target_id: impl Into<String>,
        scan_fingerprint: impl Into<String>,
        target_fingerprint: Sha256,
        target_physical_parent_fingerprint: Sha256,
        target_recovery_fingerprint: impl Into<String>,
        lock_identity: impl Into<String>,
        before_sha256: Sha256,
        after_sha256: Sha256,
        diff_sha256: Sha256,
        observed_uuid_set_sha256: Sha256,
        before_metadata: RepairFileMetadataV1,
    ) -> Result<Self, ProtocolViolation> {
        Self::new_for_resource(
            RepairResourceV1::Fstab,
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
    }

    #[allow(clippy::too_many_arguments)]
    pub fn new_for_resource(
        resource: RepairResourceV1,
        session_id: impl Into<String>,
        approval_sequence: u64,
        target_id: impl Into<String>,
        scan_fingerprint: impl Into<String>,
        target_fingerprint: Sha256,
        target_physical_parent_fingerprint: Sha256,
        target_recovery_fingerprint: impl Into<String>,
        lock_identity: impl Into<String>,
        before_sha256: Sha256,
        after_sha256: Sha256,
        diff_sha256: Sha256,
        observed_uuid_set_sha256: Sha256,
        before_metadata: RepairFileMetadataV1,
    ) -> Result<Self, ProtocolViolation> {
        let value = Self {
            action_id: resource.action_id().to_owned(),
            session_id: session_id.into(),
            approval_sequence,
            target_id: target_id.into(),
            scan_fingerprint: scan_fingerprint.into(),
            target_fingerprint,
            target_physical_parent_fingerprint,
            target_recovery_fingerprint: target_recovery_fingerprint.into(),
            lock_identity: lock_identity.into(),
            before_sha256,
            after_sha256,
            diff_sha256,
            observed_uuid_set_sha256,
            before_metadata,
        };
        value.validate()?;
        Ok(value)
    }

    pub fn action_id(&self) -> &str {
        &self.action_id
    }
    pub fn session_id(&self) -> &str {
        &self.session_id
    }
    pub const fn approval_sequence(&self) -> u64 {
        self.approval_sequence
    }
    pub fn target_id(&self) -> &str {
        &self.target_id
    }
    pub fn scan_fingerprint(&self) -> &str {
        &self.scan_fingerprint
    }
    pub fn target_fingerprint(&self) -> &Sha256 {
        &self.target_fingerprint
    }
    pub fn target_physical_parent_fingerprint(&self) -> &Sha256 {
        &self.target_physical_parent_fingerprint
    }
    pub fn target_recovery_fingerprint(&self) -> &str {
        &self.target_recovery_fingerprint
    }
    pub fn lock_identity(&self) -> &str {
        &self.lock_identity
    }
    pub fn before_sha256(&self) -> &Sha256 {
        &self.before_sha256
    }
    pub fn after_sha256(&self) -> &Sha256 {
        &self.after_sha256
    }
    pub fn diff_sha256(&self) -> &Sha256 {
        &self.diff_sha256
    }
    pub fn observed_uuid_set_sha256(&self) -> &Sha256 {
        &self.observed_uuid_set_sha256
    }
    pub fn before_metadata(&self) -> &RepairFileMetadataV1 {
        &self.before_metadata
    }

    /// Domain-separated canonical binding persisted with the durable backup.
    pub fn canonical_binding_sha256(&self) -> Sha256 {
        canonical_repair_execution_intent_sha256(self)
    }

    pub(crate) fn validate(&self) -> Result<(), ProtocolViolation> {
        let resource = match self.action_id.as_str() {
            REPAIR_EXECUTION_ACTION_ID => RepairResourceV1::Fstab,
            CRYPTTAB_REPAIR_EXECUTION_ACTION_ID => RepairResourceV1::Crypttab,
            EXT4_REPAIR_EXECUTION_ACTION_ID => RepairResourceV1::Ext4Filesystem,
            RESOLVER_LINK_REPAIR_EXECUTION_ACTION_ID => RepairResourceV1::ResolverLink,
            _ => return Err(ProtocolViolation::InvalidPayload),
        };
        if !valid_prefixed_id(&self.session_id, "S-")
            || !(1..=MAX_SAFE_JSON_INTEGER).contains(&self.approval_sequence)
            || !valid_opaque_id(&self.target_id)
            || !valid_digest_id(&self.scan_fingerprint, "scan:")
            || !valid_digest_id(&self.target_recovery_fingerprint, "recovery:")
            || !valid_digest_id(&self.lock_identity, "lock:")
            || self.before_sha256 == self.after_sha256
            || self.before_metadata.validate().is_err()
            || !resource.supports_metadata(&self.before_metadata)
        {
            return Err(ProtocolViolation::InvalidPayload);
        }
        Ok(())
    }
}

/// Computes the exact V1 execution-intent binding using length-framed fields.
pub fn canonical_repair_execution_intent_sha256(intent: &RepairExecutionIntentV1) -> Sha256 {
    let mut hasher = Sha256Hasher::new();
    hasher.update(EXECUTION_INTENT_BINDING_DOMAIN);
    hash_field(&mut hasher, intent.action_id.as_bytes());
    hash_field(&mut hasher, intent.session_id.as_bytes());
    hash_field(&mut hasher, &intent.approval_sequence.to_be_bytes());
    hash_field(&mut hasher, intent.target_id.as_bytes());
    hash_field(&mut hasher, intent.scan_fingerprint.as_bytes());
    hash_field(&mut hasher, &intent.target_fingerprint.bytes());
    hash_field(
        &mut hasher,
        &intent.target_physical_parent_fingerprint.bytes(),
    );
    hash_field(&mut hasher, intent.target_recovery_fingerprint.as_bytes());
    hash_field(&mut hasher, intent.lock_identity.as_bytes());
    hash_field(&mut hasher, &intent.before_sha256.bytes());
    hash_field(&mut hasher, &intent.after_sha256.bytes());
    hash_field(&mut hasher, &intent.diff_sha256.bytes());
    hash_field(&mut hasher, &intent.observed_uuid_set_sha256.bytes());
    hash_field(
        &mut hasher,
        &intent.before_metadata.canonical_sha256().bytes(),
    );
    Sha256::parse(&encode_hex(&hasher.finalize())).expect("SHA-256 digest is canonical")
}

/// Derives the only canonical lock identity accepted for the V1 fstab
/// resource. Keeping this derivation beside the durable intent lets the Vault
/// independently reject a syntactically valid but target-unbound lock.
pub fn canonical_repair_lock_identity(target_recovery_fingerprint: &str) -> String {
    canonical_repair_lock_identity_for_resource(
        target_recovery_fingerprint,
        RepairResourceV1::Fstab,
    )
}

pub fn canonical_repair_lock_identity_for_resource(
    target_recovery_fingerprint: &str,
    resource: RepairResourceV1,
) -> String {
    let mut hasher = Sha256Hasher::new();
    hasher.update(match resource {
        RepairResourceV1::Fstab => LOCK_ID_DOMAIN,
        RepairResourceV1::Crypttab => CRYPTTAB_LOCK_ID_DOMAIN,
        RepairResourceV1::Ext4Filesystem => EXT4_LOCK_ID_DOMAIN,
        RepairResourceV1::ResolverLink => RESOLVER_LINK_LOCK_ID_DOMAIN,
    });
    for value in [target_recovery_fingerprint, resource.resource_id()] {
        hash_field(&mut hasher, value.as_bytes());
    }
    format!("lock:{}", encode_hex(&hasher.finalize()))
}

/// Final authorization binding supplied only when backup bytes are persisted.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RepairBackupBinding {
    plan_id: String,
    plan_sha256: Sha256,
    approval_id: String,
    approval_sha256: Sha256,
    resource_id: String,
    resource_sha256: Sha256,
    execution_intent: Box<RepairExecutionIntentV1>,
}

impl RepairBackupBinding {
    pub fn new(
        plan_id: impl Into<String>,
        plan_sha256: Sha256,
        approval_id: impl Into<String>,
        approval_sha256: Sha256,
        resource_id: impl Into<String>,
        resource_sha256: Sha256,
        execution_intent: RepairExecutionIntentV1,
    ) -> Result<Self, ProtocolViolation> {
        let value = Self {
            plan_id: plan_id.into(),
            plan_sha256,
            approval_id: approval_id.into(),
            approval_sha256,
            resource_id: resource_id.into(),
            resource_sha256,
            execution_intent: Box::new(execution_intent),
        };
        if !valid_prefixed_id(&value.plan_id, "P-")
            || !valid_prefixed_id(&value.approval_id, "A-")
            || !valid_resource_id(&value.resource_id)
            || value.execution_intent.validate().is_err()
            || RepairResourceV1::from_execution(
                value.execution_intent.action_id(),
                &value.resource_id,
            )
            .is_err()
            || value.resource_sha256 != *value.execution_intent.before_sha256()
        {
            return Err(ProtocolViolation::InvalidPayload);
        }
        Ok(value)
    }

    pub fn plan_id(&self) -> &str {
        &self.plan_id
    }
    pub fn plan_sha256(&self) -> &Sha256 {
        &self.plan_sha256
    }
    pub fn approval_id(&self) -> &str {
        &self.approval_id
    }
    pub fn approval_sha256(&self) -> &Sha256 {
        &self.approval_sha256
    }
    pub fn resource_id(&self) -> &str {
        &self.resource_id
    }
    pub fn resource_sha256(&self) -> &Sha256 {
        &self.resource_sha256
    }
    pub fn execution_intent(&self) -> &RepairExecutionIntentV1 {
        &self.execution_intent
    }
}

#[derive(Clone, Copy, Debug, Deserialize, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum RepairBackupState {
    Reserved,
    Durable,
}

/// Transient, path-free identity of the Vault mounted in the current boot.
///
/// Unlike [`RepairBackupStatusPayload`], this value is deliberately excluded
/// from durable transaction bindings. Recovery uses it to compare the fresh
/// current-boot physical parent with a freshly reacquired target capability.
#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RepairVaultLiveIdentityPayload {
    vault_id: String,
    vault_identity_fingerprint: Sha256,
    physical_parent_fingerprint: Sha256,
}

impl RepairVaultLiveIdentityPayload {
    pub fn new(
        vault_id: impl Into<String>,
        vault_identity_fingerprint: Sha256,
        physical_parent_fingerprint: Sha256,
    ) -> Result<Self, ProtocolViolation> {
        let value = Self {
            vault_id: vault_id.into(),
            vault_identity_fingerprint,
            physical_parent_fingerprint,
        };
        value.validate()?;
        Ok(value)
    }

    pub fn vault_id(&self) -> &str {
        &self.vault_id
    }

    pub fn vault_identity_fingerprint(&self) -> &Sha256 {
        &self.vault_identity_fingerprint
    }

    pub fn physical_parent_fingerprint(&self) -> &Sha256 {
        &self.physical_parent_fingerprint
    }

    pub(crate) fn validate(&self) -> Result<(), ProtocolViolation> {
        if !valid_vault_id(&self.vault_id)
            || self.vault_identity_fingerprint.bytes() == [0; 32]
            || self.physical_parent_fingerprint.bytes() == [0; 32]
        {
            return Err(ProtocolViolation::InvalidPayload);
        }
        Ok(())
    }
}

/// Closed status returned by reserve, persist, status and get.
///
/// Durable-only fields are present as one complete set. A reserved response
/// cannot smuggle a partial authorization binding.
#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RepairBackupStatusPayload {
    state: RepairBackupState,
    reservation_id: RepairReservationId,
    draft_binding_sha256: Sha256,
    locator: String,
    vault_id: String,
    vault_identity_fingerprint: Sha256,
    physical_parent_fingerprint: Sha256,
    reserved_bytes: u64,
    backup_size: u64,
    expected_backup_sha256: Sha256,
    metadata_sha256: Sha256,
    #[serde(skip_serializing_if = "Option::is_none")]
    plan_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    plan_sha256: Option<Sha256>,
    #[serde(skip_serializing_if = "Option::is_none")]
    approval_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    approval_sha256: Option<Sha256>,
    #[serde(skip_serializing_if = "Option::is_none")]
    resource_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    resource_sha256: Option<Sha256>,
    #[serde(skip_serializing_if = "Option::is_none")]
    execution_intent: Option<RepairExecutionIntentV1>,
}

/// Path-free acknowledgement that one exact reservation and its physically
/// allocated capacity were released. This is deliberately not a generic
/// delete result: its identity fields are bound to the lifecycle request.
#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RepairBackupReleasePayload {
    reservation_id: RepairReservationId,
    draft_binding_sha256: Sha256,
    released_bytes: u64,
}

impl RepairBackupReleasePayload {
    pub fn new(
        reservation_id: RepairReservationId,
        draft_binding_sha256: Sha256,
        released_bytes: u64,
    ) -> Result<Self, ProtocolViolation> {
        if !(1..=MAX_REPAIR_RESERVED_BYTES).contains(&released_bytes) {
            return Err(ProtocolViolation::InvalidPayload);
        }
        Ok(Self {
            reservation_id,
            draft_binding_sha256,
            released_bytes,
        })
    }

    pub fn reservation_id(&self) -> &RepairReservationId {
        &self.reservation_id
    }

    pub fn draft_binding_sha256(&self) -> &Sha256 {
        &self.draft_binding_sha256
    }

    pub const fn released_bytes(&self) -> u64 {
        self.released_bytes
    }

    pub(crate) fn validate(&self) -> Result<(), ProtocolViolation> {
        if !(1..=MAX_REPAIR_RESERVED_BYTES).contains(&self.released_bytes) {
            return Err(ProtocolViolation::InvalidPayload);
        }
        Ok(())
    }
}

impl RepairBackupStatusPayload {
    #[allow(clippy::too_many_arguments)]
    pub fn reserved(
        reservation_id: RepairReservationId,
        draft_binding_sha256: Sha256,
        locator: impl Into<String>,
        vault_id: impl Into<String>,
        vault_identity_fingerprint: Sha256,
        physical_parent_fingerprint: Sha256,
        reserved_bytes: u64,
        backup_size: u64,
        expected_backup_sha256: Sha256,
        metadata_sha256: Sha256,
    ) -> Result<Self, ProtocolViolation> {
        Self::new(
            RepairBackupState::Reserved,
            reservation_id,
            draft_binding_sha256,
            locator,
            vault_id,
            vault_identity_fingerprint,
            physical_parent_fingerprint,
            reserved_bytes,
            backup_size,
            expected_backup_sha256,
            metadata_sha256,
            None,
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub fn durable(
        reservation_id: RepairReservationId,
        draft_binding_sha256: Sha256,
        locator: impl Into<String>,
        vault_id: impl Into<String>,
        vault_identity_fingerprint: Sha256,
        physical_parent_fingerprint: Sha256,
        reserved_bytes: u64,
        backup_size: u64,
        expected_backup_sha256: Sha256,
        metadata_sha256: Sha256,
        binding: RepairBackupBinding,
    ) -> Result<Self, ProtocolViolation> {
        Self::new(
            RepairBackupState::Durable,
            reservation_id,
            draft_binding_sha256,
            locator,
            vault_id,
            vault_identity_fingerprint,
            physical_parent_fingerprint,
            reserved_bytes,
            backup_size,
            expected_backup_sha256,
            metadata_sha256,
            Some(binding),
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn new(
        state: RepairBackupState,
        reservation_id: RepairReservationId,
        draft_binding_sha256: Sha256,
        locator: impl Into<String>,
        vault_id: impl Into<String>,
        vault_identity_fingerprint: Sha256,
        physical_parent_fingerprint: Sha256,
        reserved_bytes: u64,
        backup_size: u64,
        expected_backup_sha256: Sha256,
        metadata_sha256: Sha256,
        binding: Option<RepairBackupBinding>,
    ) -> Result<Self, ProtocolViolation> {
        let locator = locator.into();
        let vault_id = vault_id.into();
        if locator != reservation_id.locator()
            || !valid_vault_id(&vault_id)
            || !(1..=MAX_REPAIR_BACKUP_BYTES).contains(&backup_size)
            || !(backup_size..=MAX_REPAIR_RESERVED_BYTES).contains(&reserved_bytes)
            || matches!(state, RepairBackupState::Reserved) != binding.is_none()
        {
            return Err(ProtocolViolation::InvalidPayload);
        }
        let (
            plan_id,
            plan_sha256,
            approval_id,
            approval_sha256,
            resource_id,
            resource_sha256,
            execution_intent,
        ) = binding.map_or((None, None, None, None, None, None, None), |value| {
            (
                Some(value.plan_id),
                Some(value.plan_sha256),
                Some(value.approval_id),
                Some(value.approval_sha256),
                Some(value.resource_id),
                Some(value.resource_sha256),
                Some(*value.execution_intent),
            )
        });
        Ok(Self {
            state,
            reservation_id,
            draft_binding_sha256,
            locator,
            vault_id,
            vault_identity_fingerprint,
            physical_parent_fingerprint,
            reserved_bytes,
            backup_size,
            expected_backup_sha256,
            metadata_sha256,
            plan_id,
            plan_sha256,
            approval_id,
            approval_sha256,
            resource_id,
            resource_sha256,
            execution_intent,
        })
    }

    pub(crate) fn validate(&self) -> Result<(), ProtocolViolation> {
        let valid_binding = match self.state {
            RepairBackupState::Reserved => self.binding_fields_are_none(),
            RepairBackupState::Durable => self.binding_fields_are_valid(),
        };
        if self.locator != self.reservation_id.locator()
            || !valid_vault_id(&self.vault_id)
            || !(1..=MAX_REPAIR_BACKUP_BYTES).contains(&self.backup_size)
            || !(self.backup_size..=MAX_REPAIR_RESERVED_BYTES).contains(&self.reserved_bytes)
            || !valid_binding
        {
            return Err(ProtocolViolation::InvalidPayload);
        }
        Ok(())
    }

    fn binding_fields_are_none(&self) -> bool {
        self.plan_id.is_none()
            && self.plan_sha256.is_none()
            && self.approval_id.is_none()
            && self.approval_sha256.is_none()
            && self.resource_id.is_none()
            && self.resource_sha256.is_none()
            && self.execution_intent.is_none()
    }

    fn binding_fields_are_valid(&self) -> bool {
        self.plan_id
            .as_deref()
            .is_some_and(|value| valid_prefixed_id(value, "P-"))
            && self.plan_sha256.is_some()
            && self
                .approval_id
                .as_deref()
                .is_some_and(|value| valid_prefixed_id(value, "A-"))
            && self.approval_sha256.is_some()
            && self.resource_id.as_deref().is_some_and(valid_resource_id)
            && self
                .resource_sha256
                .as_ref()
                .is_some_and(|resource_sha256| {
                    self.execution_intent.as_ref().is_some_and(|intent| {
                        intent.validate().is_ok()
                            && resource_sha256 == intent.before_sha256()
                            && &self.expected_backup_sha256 == intent.before_sha256()
                            && self.metadata_sha256 == intent.before_metadata().canonical_sha256()
                            && &self.physical_parent_fingerprint
                                != intent.target_physical_parent_fingerprint()
                    })
                })
    }

    pub const fn state(&self) -> RepairBackupState {
        self.state
    }
    pub fn reservation_id(&self) -> &RepairReservationId {
        &self.reservation_id
    }
    pub fn draft_binding_sha256(&self) -> &Sha256 {
        &self.draft_binding_sha256
    }
    pub fn locator(&self) -> &str {
        &self.locator
    }
    pub fn vault_id(&self) -> &str {
        &self.vault_id
    }
    pub fn vault_identity_fingerprint(&self) -> &Sha256 {
        &self.vault_identity_fingerprint
    }
    pub fn physical_parent_fingerprint(&self) -> &Sha256 {
        &self.physical_parent_fingerprint
    }
    pub const fn reserved_bytes(&self) -> u64 {
        self.reserved_bytes
    }
    pub const fn backup_size(&self) -> u64 {
        self.backup_size
    }
    pub fn expected_backup_sha256(&self) -> &Sha256 {
        &self.expected_backup_sha256
    }
    pub fn metadata_sha256(&self) -> &Sha256 {
        &self.metadata_sha256
    }
    pub fn plan_id(&self) -> Option<&str> {
        self.plan_id.as_deref()
    }
    pub fn plan_sha256(&self) -> Option<&Sha256> {
        self.plan_sha256.as_ref()
    }
    pub fn approval_id(&self) -> Option<&str> {
        self.approval_id.as_deref()
    }
    pub fn approval_sha256(&self) -> Option<&Sha256> {
        self.approval_sha256.as_ref()
    }
    pub fn resource_id(&self) -> Option<&str> {
        self.resource_id.as_deref()
    }
    pub fn resource_sha256(&self) -> Option<&Sha256> {
        self.resource_sha256.as_ref()
    }
    pub fn execution_intent(&self) -> Option<&RepairExecutionIntentV1> {
        self.execution_intent.as_ref()
    }

    /// Compares every reservation field that remains immutable across the
    /// reserved-to-durable transition.
    pub(crate) fn immutable_fields_match(&self, other: &Self) -> bool {
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

/// Durable lifecycle phase for one repair transaction.
#[derive(Clone, Copy, Debug, Deserialize, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum RepairTransactionPhase {
    /// Backup and intent are durable, but no final outcome has been recorded.
    Pending,
    /// The target is verified in an approved closed state.
    Resolved,
    /// A known but unsafe/ambiguous state blocks later mutations.
    ManualReconciliationRequired,
}

/// Classification of the currently observed resource bytes.
#[derive(Clone, Copy, Debug, Deserialize, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum RepairTransactionTargetState {
    Before,
    After,
    Third,
}

/// Closed result vocabulary for transaction reconciliation.
#[derive(Clone, Copy, Debug, Deserialize, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum RepairTransactionResolutionOutcome {
    CommittedAfter,
    ClosedBeforeUnchanged,
    ClosedBeforeRestored,
    ManualReconciliationRequired,
}

/// Exact observation used to resolve, or deliberately keep blocking, a
/// transaction. Unknown text and host paths cannot be attached to it.
#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RepairTransactionResolution {
    outcome: RepairTransactionResolutionOutcome,
    target_state: RepairTransactionTargetState,
    observed_resource_sha256: Sha256,
    observed_metadata_sha256: Sha256,
    mount_cleanup_verified: bool,
}

impl RepairTransactionResolution {
    pub fn new(
        outcome: RepairTransactionResolutionOutcome,
        observed_resource_sha256: Sha256,
        observed_metadata_sha256: Sha256,
        mount_cleanup_verified: bool,
        intent: &RepairExecutionIntentV1,
    ) -> Result<Self, ProtocolViolation> {
        let target_state = classify_target_state(&observed_resource_sha256, intent);
        let value = Self {
            outcome,
            target_state,
            observed_resource_sha256,
            observed_metadata_sha256,
            mount_cleanup_verified,
        };
        value.validate_against(intent)?;
        Ok(value)
    }

    pub const fn outcome(&self) -> RepairTransactionResolutionOutcome {
        self.outcome
    }
    pub const fn target_state(&self) -> RepairTransactionTargetState {
        self.target_state
    }
    pub fn observed_resource_sha256(&self) -> &Sha256 {
        &self.observed_resource_sha256
    }
    pub fn observed_metadata_sha256(&self) -> &Sha256 {
        &self.observed_metadata_sha256
    }
    pub const fn mount_cleanup_verified(&self) -> bool {
        self.mount_cleanup_verified
    }

    pub(crate) fn validate_against(
        &self,
        intent: &RepairExecutionIntentV1,
    ) -> Result<(), ProtocolViolation> {
        intent.validate()?;
        if self.target_state != classify_target_state(&self.observed_resource_sha256, intent) {
            return Err(ProtocolViolation::InvalidPayload);
        }
        let metadata_matches =
            self.observed_metadata_sha256 == intent.before_metadata().canonical_sha256();
        let exact_closed_state = match self.outcome {
            RepairTransactionResolutionOutcome::CommittedAfter => {
                self.target_state == RepairTransactionTargetState::After
                    && metadata_matches
                    && self.mount_cleanup_verified
            }
            RepairTransactionResolutionOutcome::ClosedBeforeUnchanged
            | RepairTransactionResolutionOutcome::ClosedBeforeRestored => {
                self.target_state == RepairTransactionTargetState::Before
                    && metadata_matches
                    && self.mount_cleanup_verified
            }
            RepairTransactionResolutionOutcome::ManualReconciliationRequired => true,
        };
        if !exact_closed_state {
            return Err(ProtocolViolation::InvalidPayload);
        }
        Ok(())
    }

    const fn phase(&self) -> RepairTransactionPhase {
        match self.outcome {
            RepairTransactionResolutionOutcome::ManualReconciliationRequired => {
                RepairTransactionPhase::ManualReconciliationRequired
            }
            RepairTransactionResolutionOutcome::CommittedAfter
            | RepairTransactionResolutionOutcome::ClosedBeforeUnchanged
            | RepairTransactionResolutionOutcome::ClosedBeforeRestored => {
                RepairTransactionPhase::Resolved
            }
        }
    }
}

fn classify_target_state(
    observed_resource_sha256: &Sha256,
    intent: &RepairExecutionIntentV1,
) -> RepairTransactionTargetState {
    if observed_resource_sha256 == intent.before_sha256() {
        RepairTransactionTargetState::Before
    } else if observed_resource_sha256 == intent.after_sha256() {
        RepairTransactionTargetState::After
    } else {
        RepairTransactionTargetState::Third
    }
}

/// Authenticated transaction record reconstructed from the durable backup
/// record after a process restart or machine reboot.
#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RepairTransactionStatusPayload {
    phase: RepairTransactionPhase,
    transaction_binding_sha256: Sha256,
    backup: Box<RepairBackupStatusPayload>,
    #[serde(skip_serializing_if = "Option::is_none")]
    resolution: Option<RepairTransactionResolution>,
}

impl RepairTransactionStatusPayload {
    pub fn pending(backup: RepairBackupStatusPayload) -> Result<Self, ProtocolViolation> {
        Self::new(RepairTransactionPhase::Pending, backup, None)
    }

    pub fn resolved(
        backup: RepairBackupStatusPayload,
        resolution: RepairTransactionResolution,
    ) -> Result<Self, ProtocolViolation> {
        let phase = resolution.phase();
        Self::new(phase, backup, Some(resolution))
    }

    fn new(
        phase: RepairTransactionPhase,
        backup: RepairBackupStatusPayload,
        resolution: Option<RepairTransactionResolution>,
    ) -> Result<Self, ProtocolViolation> {
        let transaction_binding_sha256 = canonical_repair_transaction_binding_sha256(&backup)?;
        let value = Self {
            phase,
            transaction_binding_sha256,
            backup: Box::new(backup),
            resolution,
        };
        value.validate()?;
        Ok(value)
    }

    pub const fn phase(&self) -> RepairTransactionPhase {
        self.phase
    }
    pub fn transaction_binding_sha256(&self) -> &Sha256 {
        &self.transaction_binding_sha256
    }
    pub fn backup(&self) -> &RepairBackupStatusPayload {
        &self.backup
    }
    pub fn resolution(&self) -> Option<&RepairTransactionResolution> {
        self.resolution.as_ref()
    }
    pub const fn is_unresolved(&self) -> bool {
        matches!(
            self.phase,
            RepairTransactionPhase::Pending | RepairTransactionPhase::ManualReconciliationRequired
        )
    }

    pub(crate) fn validate(&self) -> Result<(), ProtocolViolation> {
        self.backup.validate()?;
        if self.backup.state() != RepairBackupState::Durable
            || self.transaction_binding_sha256
                != canonical_repair_transaction_binding_sha256(&self.backup)?
        {
            return Err(ProtocolViolation::InvalidPayload);
        }
        let Some(intent) = self.backup.execution_intent() else {
            return Err(ProtocolViolation::InvalidPayload);
        };
        match (&self.phase, &self.resolution) {
            (RepairTransactionPhase::Pending, None) => Ok(()),
            (RepairTransactionPhase::Resolved, Some(resolution))
                if resolution.phase() == RepairTransactionPhase::Resolved =>
            {
                resolution.validate_against(intent)
            }
            (RepairTransactionPhase::ManualReconciliationRequired, Some(resolution))
                if resolution.phase() == RepairTransactionPhase::ManualReconciliationRequired =>
            {
                resolution.validate_against(intent)
            }
            _ => Err(ProtocolViolation::InvalidPayload),
        }
    }

    pub(crate) fn same_transaction(&self, other: &Self) -> bool {
        self.backup.reservation_id() == other.backup.reservation_id()
            && self.transaction_binding_sha256 == other.transaction_binding_sha256
            && self.backup == other.backup
    }

    pub(crate) fn resolves_with(&self, resolution: &RepairTransactionResolution) -> bool {
        self.resolution.as_ref() == Some(resolution) && self.phase == resolution.phase()
    }
}

/// Computes the immutable transaction identity from the complete durable
/// backup record and its execution intent.
pub fn canonical_repair_transaction_binding_sha256(
    backup: &RepairBackupStatusPayload,
) -> Result<Sha256, ProtocolViolation> {
    backup.validate()?;
    if backup.state() != RepairBackupState::Durable {
        return Err(ProtocolViolation::InvalidPayload);
    }
    let Some(plan_id) = backup.plan_id() else {
        return Err(ProtocolViolation::InvalidPayload);
    };
    let Some(plan_sha256) = backup.plan_sha256() else {
        return Err(ProtocolViolation::InvalidPayload);
    };
    let Some(approval_id) = backup.approval_id() else {
        return Err(ProtocolViolation::InvalidPayload);
    };
    let Some(approval_sha256) = backup.approval_sha256() else {
        return Err(ProtocolViolation::InvalidPayload);
    };
    let Some(resource_id) = backup.resource_id() else {
        return Err(ProtocolViolation::InvalidPayload);
    };
    let Some(resource_sha256) = backup.resource_sha256() else {
        return Err(ProtocolViolation::InvalidPayload);
    };
    let Some(execution_intent) = backup.execution_intent() else {
        return Err(ProtocolViolation::InvalidPayload);
    };

    let mut hasher = Sha256Hasher::new();
    hasher.update(TRANSACTION_BINDING_DOMAIN);
    hash_field(&mut hasher, backup.reservation_id().as_str().as_bytes());
    hash_field(&mut hasher, &backup.draft_binding_sha256().bytes());
    hash_field(&mut hasher, backup.locator().as_bytes());
    hash_field(&mut hasher, backup.vault_id().as_bytes());
    hash_field(&mut hasher, &backup.vault_identity_fingerprint().bytes());
    hash_field(&mut hasher, &backup.physical_parent_fingerprint().bytes());
    hash_field(&mut hasher, &backup.reserved_bytes().to_be_bytes());
    hash_field(&mut hasher, &backup.backup_size().to_be_bytes());
    hash_field(&mut hasher, &backup.expected_backup_sha256().bytes());
    hash_field(&mut hasher, &backup.metadata_sha256().bytes());
    hash_field(&mut hasher, plan_id.as_bytes());
    hash_field(&mut hasher, &plan_sha256.bytes());
    hash_field(&mut hasher, approval_id.as_bytes());
    hash_field(&mut hasher, &approval_sha256.bytes());
    hash_field(&mut hasher, resource_id.as_bytes());
    hash_field(&mut hasher, &resource_sha256.bytes());
    hash_field(
        &mut hasher,
        &execution_intent.canonical_binding_sha256().bytes(),
    );
    Ok(Sha256::parse(&encode_hex(&hasher.finalize())).expect("SHA-256 digest is canonical"))
}

/// Closed transaction lookup. `PendingSingleton` is the reboot bootstrap:
/// V1 permits at most one unresolved transaction in the store.
#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
#[serde(tag = "kind", rename_all = "kebab-case", deny_unknown_fields)]
pub enum RepairTransactionStatusSelector {
    PendingSingleton,
    Exact {
        #[serde(rename = "reservationId")]
        reservation_id: RepairReservationId,
        #[serde(rename = "transactionBindingSha256")]
        transaction_binding_sha256: Sha256,
    },
}

impl RepairTransactionStatusSelector {
    pub const fn pending_singleton() -> Self {
        Self::PendingSingleton
    }

    pub fn exact(reservation_id: RepairReservationId, transaction_binding_sha256: Sha256) -> Self {
        Self::Exact {
            reservation_id,
            transaction_binding_sha256,
        }
    }

    pub fn for_status(status: &RepairTransactionStatusPayload) -> Self {
        Self::exact(
            status.backup.reservation_id().clone(),
            status.transaction_binding_sha256.clone(),
        )
    }

    pub(crate) fn validate(&self) -> Result<(), ProtocolViolation> {
        match self {
            Self::PendingSingleton | Self::Exact { .. } => Ok(()),
        }
    }

    pub(crate) fn matches_result(&self, result: &RepairTransactionStatusResultPayload) -> bool {
        if result.validate().is_err() {
            return false;
        }
        match (self, result.transaction()) {
            (Self::PendingSingleton, None) => true,
            (Self::PendingSingleton, Some(status)) => status.is_unresolved(),
            (
                Self::Exact {
                    reservation_id,
                    transaction_binding_sha256,
                },
                Some(status),
            ) => {
                status.backup.reservation_id() == reservation_id
                    && status.transaction_binding_sha256() == transaction_binding_sha256
            }
            (Self::Exact { .. }, None) => false,
        }
    }
}

/// Bounded result for either the singleton reboot lookup or an exact lookup.
#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RepairTransactionStatusResultPayload {
    transaction: Option<Box<RepairTransactionStatusPayload>>,
}

impl RepairTransactionStatusResultPayload {
    pub const fn absent() -> Self {
        Self { transaction: None }
    }

    pub fn found(transaction: RepairTransactionStatusPayload) -> Self {
        Self {
            transaction: Some(Box::new(transaction)),
        }
    }

    pub fn transaction(&self) -> Option<&RepairTransactionStatusPayload> {
        self.transaction.as_deref()
    }

    pub(crate) fn validate(&self) -> Result<(), ProtocolViolation> {
        if let Some(transaction) = &self.transaction {
            transaction.validate()?;
        }
        Ok(())
    }
}

/// Receipt for one write-mount lease that the Vault has already consumed.
///
/// This is closed audit evidence returned only to the root target helper; it
/// is not a transferable bearer token. The helper must derive its target from
/// the embedded Pending transaction and may hand off at most one descriptor.
#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RepairWriteLeasePayload {
    capability: String,
    boot_epoch_sha256: Sha256,
    lease_binding_sha256: Sha256,
    transaction: Box<RepairTransactionStatusPayload>,
}

impl RepairWriteLeasePayload {
    pub fn consumed(
        transaction: RepairTransactionStatusPayload,
        boot_epoch_sha256: Sha256,
    ) -> Result<Self, ProtocolViolation> {
        let resource = repair_resource_from_transaction(&transaction)?;
        let lease_binding_sha256 =
            canonical_repair_write_lease_sha256(&transaction, &boot_epoch_sha256)?;
        let value = Self {
            capability: resource.write_lease_capability().to_owned(),
            boot_epoch_sha256,
            lease_binding_sha256,
            transaction: Box::new(transaction),
        };
        value.validate()?;
        Ok(value)
    }

    pub fn capability(&self) -> &str {
        &self.capability
    }

    pub fn boot_epoch_sha256(&self) -> &Sha256 {
        &self.boot_epoch_sha256
    }

    pub fn lease_binding_sha256(&self) -> &Sha256 {
        &self.lease_binding_sha256
    }

    pub fn transaction(&self) -> &RepairTransactionStatusPayload {
        &self.transaction
    }

    pub fn validate(&self) -> Result<(), ProtocolViolation> {
        self.transaction.validate()?;
        let Some(intent) = self.transaction.backup().execution_intent() else {
            return Err(ProtocolViolation::InvalidPayload);
        };
        let resource = repair_resource_from_transaction(&self.transaction)?;
        if self.capability != resource.write_lease_capability()
            || self.transaction.phase() != RepairTransactionPhase::Pending
            || self.transaction.backup().state() != RepairBackupState::Durable
            || self.boot_epoch_sha256.bytes().iter().all(|byte| *byte == 0)
            || intent.lock_identity()
                != canonical_repair_lock_identity_for_resource(
                    intent.target_recovery_fingerprint(),
                    resource,
                )
            || self.lease_binding_sha256
                != canonical_repair_write_lease_sha256(&self.transaction, &self.boot_epoch_sha256)?
        {
            return Err(ProtocolViolation::InvalidPayload);
        }
        Ok(())
    }
}

/// Binds a consumed lease to one exact Pending transaction and boot epoch.
pub fn canonical_repair_write_lease_sha256(
    transaction: &RepairTransactionStatusPayload,
    boot_epoch_sha256: &Sha256,
) -> Result<Sha256, ProtocolViolation> {
    transaction.validate()?;
    if transaction.phase() != RepairTransactionPhase::Pending
        || boot_epoch_sha256.bytes().iter().all(|byte| *byte == 0)
    {
        return Err(ProtocolViolation::InvalidPayload);
    }
    let Some(intent) = transaction.backup().execution_intent() else {
        return Err(ProtocolViolation::InvalidPayload);
    };
    let resource = repair_resource_from_transaction(transaction)?;
    if intent.lock_identity()
        != canonical_repair_lock_identity_for_resource(
            intent.target_recovery_fingerprint(),
            resource,
        )
    {
        return Err(ProtocolViolation::InvalidPayload);
    }
    let mut hasher = Sha256Hasher::new();
    hasher.update(WRITE_LEASE_BINDING_DOMAIN);
    hash_field(&mut hasher, resource.write_lease_capability().as_bytes());
    hash_field(
        &mut hasher,
        &transaction.transaction_binding_sha256().bytes(),
    );
    hash_field(&mut hasher, &boot_epoch_sha256.bytes());
    hash_field(&mut hasher, intent.target_recovery_fingerprint().as_bytes());
    hash_field(&mut hasher, intent.lock_identity().as_bytes());
    Ok(Sha256::parse(&encode_hex(&hasher.finalize())).expect("SHA-256 digest is canonical"))
}

/// Opaque identity of one child rollback transaction. It carries no storage
/// locator and is never accepted without the complete source and binding.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(transparent)]
pub struct RepairRollbackId(String);

impl<'de> Deserialize<'de> for RepairRollbackId {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        Self::parse(&value).map_err(serde::de::Error::custom)
    }
}

impl RepairRollbackId {
    pub fn parse(value: &str) -> Result<Self, ProtocolViolation> {
        let Some(suffix) = value.strip_prefix("RB-") else {
            return Err(ProtocolViolation::InvalidPayload);
        };
        if suffix.len() != 32 || !suffix.bytes().all(is_lower_hex) {
            return Err(ProtocolViolation::InvalidPayload);
        }
        Ok(Self(value.to_owned()))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// Fresh plan and approval material for a child rollback transaction.
///
/// The immutable target, resource, backup and installed/restored hashes are
/// inherited only through the exact source transaction. The approval must be
/// the strict next sequence and must differ from the source repair approval.
#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RepairRollbackBindingV1 {
    action_id: String,
    plan_id: String,
    plan_sha256: Sha256,
    approval_id: String,
    approval_sha256: Sha256,
    approval_sequence: u64,
}

impl RepairRollbackBindingV1 {
    pub fn new(
        source: &RepairTransactionStatusPayload,
        plan_id: impl Into<String>,
        plan_sha256: Sha256,
        approval_id: impl Into<String>,
        approval_sha256: Sha256,
        approval_sequence: u64,
    ) -> Result<Self, ProtocolViolation> {
        let resource = repair_resource_from_transaction(source)?;
        let value = Self {
            action_id: resource.rollback_action_id().to_owned(),
            plan_id: plan_id.into(),
            plan_sha256,
            approval_id: approval_id.into(),
            approval_sha256,
            approval_sequence,
        };
        value.validate_against(source)?;
        Ok(value)
    }

    pub fn action_id(&self) -> &str {
        &self.action_id
    }

    pub fn plan_id(&self) -> &str {
        &self.plan_id
    }

    pub fn plan_sha256(&self) -> &Sha256 {
        &self.plan_sha256
    }

    pub fn approval_id(&self) -> &str {
        &self.approval_id
    }

    pub fn approval_sha256(&self) -> &Sha256 {
        &self.approval_sha256
    }

    pub const fn approval_sequence(&self) -> u64 {
        self.approval_sequence
    }

    pub fn validate_against(
        &self,
        source: &RepairTransactionStatusPayload,
    ) -> Result<(), ProtocolViolation> {
        validate_committed_rollback_source(source)?;
        let source_plan_id = source
            .backup()
            .plan_id()
            .ok_or(ProtocolViolation::InvalidPayload)?;
        let source_plan_sha256 = source
            .backup()
            .plan_sha256()
            .ok_or(ProtocolViolation::InvalidPayload)?;
        let source_approval_id = source
            .backup()
            .approval_id()
            .ok_or(ProtocolViolation::InvalidPayload)?;
        let source_approval_sha256 = source
            .backup()
            .approval_sha256()
            .ok_or(ProtocolViolation::InvalidPayload)?;
        let source_intent = source
            .backup()
            .execution_intent()
            .ok_or(ProtocolViolation::InvalidPayload)?;
        let resource = repair_resource_from_transaction(source)?;
        // ext4 e2undo is a same-boot failure guard executed inside the root
        // helper, not a durable post-commit rollback authority.
        if resource == RepairResourceV1::Ext4Filesystem {
            return Err(ProtocolViolation::InvalidPayload);
        }
        let next_sequence = source_intent
            .approval_sequence()
            .checked_add(1)
            .filter(|value| *value <= MAX_SAFE_JSON_INTEGER)
            .ok_or(ProtocolViolation::InvalidPayload)?;
        if self.action_id != resource.rollback_action_id()
            || !valid_prefixed_id(&self.plan_id, "P-")
            || !valid_prefixed_id(&self.approval_id, "A-")
            || self.plan_sha256.bytes() == [0; 32]
            || self.approval_sha256.bytes() == [0; 32]
            || self.plan_id == source_plan_id
            || &self.plan_sha256 == source_plan_sha256
            || self.approval_id == source_approval_id
            || &self.approval_sha256 == source_approval_sha256
            || self.approval_sequence != next_sequence
        {
            return Err(ProtocolViolation::InvalidPayload);
        }
        Ok(())
    }
}

/// Closed result vocabulary for a user-approved post-commit rollback.
#[derive(Clone, Copy, Debug, Deserialize, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum RepairRollbackResolutionOutcome {
    RolledBackBefore,
    ManualReconciliationRequired,
}

/// Exact observation used to resolve a child rollback transaction.
#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RepairRollbackResolution {
    outcome: RepairRollbackResolutionOutcome,
    target_state: RepairTransactionTargetState,
    observed_resource_sha256: Sha256,
    observed_metadata_sha256: Sha256,
    mount_cleanup_verified: bool,
}

impl RepairRollbackResolution {
    pub fn new(
        outcome: RepairRollbackResolutionOutcome,
        observed_resource_sha256: Sha256,
        observed_metadata_sha256: Sha256,
        mount_cleanup_verified: bool,
        source: &RepairTransactionStatusPayload,
    ) -> Result<Self, ProtocolViolation> {
        validate_committed_rollback_source(source)?;
        let intent = source
            .backup()
            .execution_intent()
            .ok_or(ProtocolViolation::InvalidPayload)?;
        let value = Self {
            outcome,
            target_state: classify_target_state(&observed_resource_sha256, intent),
            observed_resource_sha256,
            observed_metadata_sha256,
            mount_cleanup_verified,
        };
        value.validate_against(source)?;
        Ok(value)
    }

    pub const fn outcome(&self) -> RepairRollbackResolutionOutcome {
        self.outcome
    }

    pub const fn target_state(&self) -> RepairTransactionTargetState {
        self.target_state
    }

    pub fn observed_resource_sha256(&self) -> &Sha256 {
        &self.observed_resource_sha256
    }

    pub fn observed_metadata_sha256(&self) -> &Sha256 {
        &self.observed_metadata_sha256
    }

    pub const fn mount_cleanup_verified(&self) -> bool {
        self.mount_cleanup_verified
    }

    pub fn validate_against(
        &self,
        source: &RepairTransactionStatusPayload,
    ) -> Result<(), ProtocolViolation> {
        validate_committed_rollback_source(source)?;
        let intent = source
            .backup()
            .execution_intent()
            .ok_or(ProtocolViolation::InvalidPayload)?;
        if self.target_state != classify_target_state(&self.observed_resource_sha256, intent) {
            return Err(ProtocolViolation::InvalidPayload);
        }
        let metadata_matches =
            self.observed_metadata_sha256 == intent.before_metadata().canonical_sha256();
        let exact_closed_state = match self.outcome {
            RepairRollbackResolutionOutcome::RolledBackBefore => {
                self.target_state == RepairTransactionTargetState::Before
                    && metadata_matches
                    && self.mount_cleanup_verified
            }
            RepairRollbackResolutionOutcome::ManualReconciliationRequired => true,
        };
        if !exact_closed_state {
            return Err(ProtocolViolation::InvalidPayload);
        }
        Ok(())
    }

    const fn phase(&self) -> RepairTransactionPhase {
        match self.outcome {
            RepairRollbackResolutionOutcome::RolledBackBefore => RepairTransactionPhase::Resolved,
            RepairRollbackResolutionOutcome::ManualReconciliationRequired => {
                RepairTransactionPhase::ManualReconciliationRequired
            }
        }
    }
}

/// Durable, path-free status of one rollback child linked to an immutable
/// committed source transaction.
#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RepairRollbackTransactionStatusPayload {
    phase: RepairTransactionPhase,
    rollback_id: RepairRollbackId,
    rollback_transaction_binding_sha256: Sha256,
    source: Box<RepairTransactionStatusPayload>,
    binding: RepairRollbackBindingV1,
    #[serde(skip_serializing_if = "Option::is_none")]
    resolution: Option<RepairRollbackResolution>,
}

impl RepairRollbackTransactionStatusPayload {
    pub fn pending(
        rollback_id: RepairRollbackId,
        source: RepairTransactionStatusPayload,
        binding: RepairRollbackBindingV1,
    ) -> Result<Self, ProtocolViolation> {
        Self::new(
            RepairTransactionPhase::Pending,
            rollback_id,
            source,
            binding,
            None,
        )
    }

    pub fn resolved(
        rollback_id: RepairRollbackId,
        source: RepairTransactionStatusPayload,
        binding: RepairRollbackBindingV1,
        resolution: RepairRollbackResolution,
    ) -> Result<Self, ProtocolViolation> {
        Self::new(
            resolution.phase(),
            rollback_id,
            source,
            binding,
            Some(resolution),
        )
    }

    fn new(
        phase: RepairTransactionPhase,
        rollback_id: RepairRollbackId,
        source: RepairTransactionStatusPayload,
        binding: RepairRollbackBindingV1,
        resolution: Option<RepairRollbackResolution>,
    ) -> Result<Self, ProtocolViolation> {
        binding.validate_against(&source)?;
        let rollback_transaction_binding_sha256 =
            canonical_repair_rollback_transaction_binding_sha256(&rollback_id, &source, &binding)?;
        let value = Self {
            phase,
            rollback_id,
            rollback_transaction_binding_sha256,
            source: Box::new(source),
            binding,
            resolution,
        };
        value.validate()?;
        Ok(value)
    }

    pub const fn phase(&self) -> RepairTransactionPhase {
        self.phase
    }

    pub fn rollback_id(&self) -> &RepairRollbackId {
        &self.rollback_id
    }

    pub fn rollback_transaction_binding_sha256(&self) -> &Sha256 {
        &self.rollback_transaction_binding_sha256
    }

    pub fn source(&self) -> &RepairTransactionStatusPayload {
        &self.source
    }

    pub fn binding(&self) -> &RepairRollbackBindingV1 {
        &self.binding
    }

    pub fn resolution(&self) -> Option<&RepairRollbackResolution> {
        self.resolution.as_ref()
    }

    pub const fn is_unresolved(&self) -> bool {
        matches!(
            self.phase,
            RepairTransactionPhase::Pending | RepairTransactionPhase::ManualReconciliationRequired
        )
    }

    pub fn validate(&self) -> Result<(), ProtocolViolation> {
        self.binding.validate_against(&self.source)?;
        if self.rollback_transaction_binding_sha256
            != canonical_repair_rollback_transaction_binding_sha256(
                &self.rollback_id,
                &self.source,
                &self.binding,
            )?
        {
            return Err(ProtocolViolation::InvalidPayload);
        }
        match (&self.phase, &self.resolution) {
            (RepairTransactionPhase::Pending, None) => Ok(()),
            (RepairTransactionPhase::Resolved, Some(resolution))
                if resolution.phase() == RepairTransactionPhase::Resolved =>
            {
                resolution.validate_against(&self.source)
            }
            (RepairTransactionPhase::ManualReconciliationRequired, Some(resolution))
                if resolution.phase() == RepairTransactionPhase::ManualReconciliationRequired =>
            {
                resolution.validate_against(&self.source)
            }
            _ => Err(ProtocolViolation::InvalidPayload),
        }
    }

    pub fn same_transaction(&self, other: &Self) -> bool {
        self.rollback_id == other.rollback_id
            && self.rollback_transaction_binding_sha256 == other.rollback_transaction_binding_sha256
            && self.source == other.source
            && self.binding == other.binding
    }

    pub fn resolves_with(&self, resolution: &RepairRollbackResolution) -> bool {
        self.resolution.as_ref() == Some(resolution) && self.phase == resolution.phase()
    }
}

/// Computes the child identity from the exact source plus fresh rollback
/// plan/approval. The source receipt alone can never mint this binding.
pub fn canonical_repair_rollback_transaction_binding_sha256(
    rollback_id: &RepairRollbackId,
    source: &RepairTransactionStatusPayload,
    binding: &RepairRollbackBindingV1,
) -> Result<Sha256, ProtocolViolation> {
    binding.validate_against(source)?;
    let mut hasher = Sha256Hasher::new();
    hasher.update(ROLLBACK_TRANSACTION_BINDING_DOMAIN);
    hash_field(&mut hasher, rollback_id.as_str().as_bytes());
    hash_field(
        &mut hasher,
        source.backup().reservation_id().as_str().as_bytes(),
    );
    hash_field(&mut hasher, &source.transaction_binding_sha256().bytes());
    hash_field(&mut hasher, binding.action_id().as_bytes());
    hash_field(&mut hasher, binding.plan_id().as_bytes());
    hash_field(&mut hasher, &binding.plan_sha256().bytes());
    hash_field(&mut hasher, binding.approval_id().as_bytes());
    hash_field(&mut hasher, &binding.approval_sha256().bytes());
    hash_field(&mut hasher, &binding.approval_sequence().to_be_bytes());
    Ok(Sha256::parse(&encode_hex(&hasher.finalize())).expect("SHA-256 digest is canonical"))
}

/// Closed lookup for rollback children. The singleton is the reboot recovery
/// bootstrap and never enumerates resolved history.
#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
#[serde(tag = "kind", rename_all = "kebab-case", deny_unknown_fields)]
pub enum RepairRollbackStatusSelector {
    PendingSingleton,
    Exact {
        #[serde(rename = "rollbackId")]
        rollback_id: RepairRollbackId,
        #[serde(rename = "rollbackTransactionBindingSha256")]
        rollback_transaction_binding_sha256: Sha256,
    },
}

impl RepairRollbackStatusSelector {
    pub const fn pending_singleton() -> Self {
        Self::PendingSingleton
    }

    pub fn exact(
        rollback_id: RepairRollbackId,
        rollback_transaction_binding_sha256: Sha256,
    ) -> Self {
        Self::Exact {
            rollback_id,
            rollback_transaction_binding_sha256,
        }
    }

    pub fn for_status(status: &RepairRollbackTransactionStatusPayload) -> Self {
        Self::exact(
            status.rollback_id.clone(),
            status.rollback_transaction_binding_sha256.clone(),
        )
    }

    pub fn validate(&self) -> Result<(), ProtocolViolation> {
        match self {
            Self::PendingSingleton | Self::Exact { .. } => Ok(()),
        }
    }

    pub fn matches_result(&self, result: &RepairRollbackStatusResultPayload) -> bool {
        if result.validate().is_err() {
            return false;
        }
        match (self, result.transaction()) {
            (Self::PendingSingleton, None) => true,
            (Self::PendingSingleton, Some(status)) => status.is_unresolved(),
            (
                Self::Exact {
                    rollback_id,
                    rollback_transaction_binding_sha256,
                },
                Some(status),
            ) => {
                status.rollback_id() == rollback_id
                    && status.rollback_transaction_binding_sha256()
                        == rollback_transaction_binding_sha256
            }
            (Self::Exact { .. }, None) => false,
        }
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RepairRollbackStatusResultPayload {
    transaction: Option<Box<RepairRollbackTransactionStatusPayload>>,
}

impl RepairRollbackStatusResultPayload {
    pub const fn absent() -> Self {
        Self { transaction: None }
    }

    pub fn found(transaction: RepairRollbackTransactionStatusPayload) -> Self {
        Self {
            transaction: Some(Box::new(transaction)),
        }
    }

    pub fn transaction(&self) -> Option<&RepairRollbackTransactionStatusPayload> {
        self.transaction.as_deref()
    }

    pub fn validate(&self) -> Result<(), ProtocolViolation> {
        if let Some(transaction) = &self.transaction {
            transaction.validate()?;
        }
        Ok(())
    }
}

/// Receipt for a consumed rollback write lease. It is audit evidence for the
/// root helper, not a transferable bearer capability.
#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RepairRollbackWriteLeasePayload {
    capability: String,
    boot_epoch_sha256: Sha256,
    lease_binding_sha256: Sha256,
    transaction: Box<RepairRollbackTransactionStatusPayload>,
}

impl RepairRollbackWriteLeasePayload {
    pub fn consumed(
        transaction: RepairRollbackTransactionStatusPayload,
        boot_epoch_sha256: Sha256,
    ) -> Result<Self, ProtocolViolation> {
        let resource = repair_resource_from_transaction(transaction.source())?;
        let lease_binding_sha256 =
            canonical_repair_rollback_write_lease_sha256(&transaction, &boot_epoch_sha256)?;
        let value = Self {
            capability: resource.rollback_write_lease_capability().to_owned(),
            boot_epoch_sha256,
            lease_binding_sha256,
            transaction: Box::new(transaction),
        };
        value.validate()?;
        Ok(value)
    }

    pub fn capability(&self) -> &str {
        &self.capability
    }

    pub fn boot_epoch_sha256(&self) -> &Sha256 {
        &self.boot_epoch_sha256
    }

    pub fn lease_binding_sha256(&self) -> &Sha256 {
        &self.lease_binding_sha256
    }

    pub fn transaction(&self) -> &RepairRollbackTransactionStatusPayload {
        &self.transaction
    }

    pub fn validate(&self) -> Result<(), ProtocolViolation> {
        self.transaction.validate()?;
        let source_intent = self
            .transaction
            .source()
            .backup()
            .execution_intent()
            .ok_or(ProtocolViolation::InvalidPayload)?;
        let resource = repair_resource_from_transaction(self.transaction.source())?;
        if self.capability != resource.rollback_write_lease_capability()
            || self.transaction.phase() != RepairTransactionPhase::Pending
            || self.transaction.binding().action_id() != resource.rollback_action_id()
            || self.boot_epoch_sha256.bytes() == [0; 32]
            || source_intent.lock_identity()
                != canonical_repair_lock_identity_for_resource(
                    source_intent.target_recovery_fingerprint(),
                    resource,
                )
            || self.lease_binding_sha256
                != canonical_repair_rollback_write_lease_sha256(
                    &self.transaction,
                    &self.boot_epoch_sha256,
                )?
        {
            return Err(ProtocolViolation::InvalidPayload);
        }
        Ok(())
    }
}

pub fn canonical_repair_rollback_write_lease_sha256(
    transaction: &RepairRollbackTransactionStatusPayload,
    boot_epoch_sha256: &Sha256,
) -> Result<Sha256, ProtocolViolation> {
    transaction.validate()?;
    if transaction.phase() != RepairTransactionPhase::Pending
        || boot_epoch_sha256.bytes() == [0; 32]
    {
        return Err(ProtocolViolation::InvalidPayload);
    }
    let intent = transaction
        .source()
        .backup()
        .execution_intent()
        .ok_or(ProtocolViolation::InvalidPayload)?;
    let resource = repair_resource_from_transaction(transaction.source())?;
    if intent.lock_identity()
        != canonical_repair_lock_identity_for_resource(
            intent.target_recovery_fingerprint(),
            resource,
        )
    {
        return Err(ProtocolViolation::InvalidPayload);
    }
    let mut hasher = Sha256Hasher::new();
    hasher.update(ROLLBACK_WRITE_LEASE_BINDING_DOMAIN);
    hash_field(
        &mut hasher,
        resource.rollback_write_lease_capability().as_bytes(),
    );
    hash_field(
        &mut hasher,
        &transaction.rollback_transaction_binding_sha256().bytes(),
    );
    hash_field(&mut hasher, &boot_epoch_sha256.bytes());
    hash_field(&mut hasher, intent.target_recovery_fingerprint().as_bytes());
    hash_field(&mut hasher, intent.lock_identity().as_bytes());
    Ok(Sha256::parse(&encode_hex(&hasher.finalize())).expect("SHA-256 digest is canonical"))
}

fn validate_committed_rollback_source(
    source: &RepairTransactionStatusPayload,
) -> Result<(), ProtocolViolation> {
    source.validate()?;
    if source.phase() != RepairTransactionPhase::Resolved
        || source
            .resolution()
            .map(RepairTransactionResolution::outcome)
            != Some(RepairTransactionResolutionOutcome::CommittedAfter)
    {
        return Err(ProtocolViolation::InvalidPayload);
    }
    Ok(())
}

pub fn repair_resource_from_transaction(
    transaction: &RepairTransactionStatusPayload,
) -> Result<RepairResourceV1, ProtocolViolation> {
    let intent = transaction
        .backup()
        .execution_intent()
        .ok_or(ProtocolViolation::InvalidPayload)?;
    let resource_id = transaction
        .backup()
        .resource_id()
        .ok_or(ProtocolViolation::InvalidPayload)?;
    RepairResourceV1::from_execution(intent.action_id(), resource_id)
}

pub fn repair_backup_input(size: u64) -> Result<DescriptorDeclaration, ProtocolViolation> {
    if !(1..=MAX_REPAIR_BACKUP_BYTES).contains(&size) {
        return Err(ProtocolViolation::InvalidPayload);
    }
    Ok(DescriptorDeclaration {
        kind: DescriptorType::RepairBackupInputPipe,
        size,
    })
}

pub fn repair_backup_output(size: u64) -> Result<DescriptorDeclaration, ProtocolViolation> {
    if !(1..=MAX_REPAIR_BACKUP_BYTES).contains(&size) {
        return Err(ProtocolViolation::InvalidPayload);
    }
    Ok(DescriptorDeclaration {
        kind: DescriptorType::RepairBackupOutputPipe,
        size,
    })
}

fn valid_prefixed_id(value: &str, prefix: &str) -> bool {
    value.len() <= MAX_OPAQUE_ID_BYTES
        && value.strip_prefix(prefix).is_some_and(|suffix| {
            !suffix.is_empty()
                && suffix
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
        })
}

fn valid_opaque_id(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= MAX_OPAQUE_ID_BYTES
        && !value.contains("..")
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b':' | b'.'))
}

fn valid_digest_id(value: &str, prefix: &str) -> bool {
    value
        .strip_prefix(prefix)
        .is_some_and(|suffix| suffix.len() == 64 && suffix.bytes().all(is_lower_hex))
}

fn valid_resource_id(value: &str) -> bool {
    RepairResourceV1::from_resource_id(value).is_ok()
}

fn is_lower_hex(byte: u8) -> bool {
    byte.is_ascii_digit() || matches!(byte, b'a'..=b'f')
}

fn valid_vault_id(value: &str) -> bool {
    value
        .strip_prefix("V-")
        .is_some_and(|suffix| suffix.len() == 32 && suffix.bytes().all(is_lower_hex))
}

fn hash_field(hasher: &mut Sha256Hasher, field: &[u8]) {
    hasher.update((field.len() as u64).to_be_bytes());
    hasher.update(field);
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

#[cfg(test)]
mod tests {
    use super::*;

    fn hash(byte: char) -> Sha256 {
        Sha256::parse(&byte.to_string().repeat(64)).expect("test SHA-256")
    }

    fn reservation() -> RepairReservationId {
        RepairReservationId::parse("B-0123456789abcdef0123456789abcdef").expect("reservation ID")
    }

    fn metadata() -> RepairFileMetadataV1 {
        RepairFileMetadataV1::new(0o644, 0, 0).expect("metadata")
    }

    #[test]
    fn live_vault_identity_is_closed_and_rejects_zero_hashes() {
        let identity = RepairVaultLiveIdentityPayload::new(
            "V-0123456789abcdef0123456789abcdef",
            hash('1'),
            hash('2'),
        )
        .expect("live Vault identity");
        assert_eq!(identity.vault_identity_fingerprint(), &hash('1'));
        assert_eq!(identity.physical_parent_fingerprint(), &hash('2'));
        assert!(
            RepairVaultLiveIdentityPayload::new(
                "V-0123456789abcdef0123456789abcdef",
                hash('0'),
                hash('2'),
            )
            .is_err()
        );
    }

    fn execution_intent(
        before_sha256: Sha256,
        before_metadata: RepairFileMetadataV1,
    ) -> RepairExecutionIntentV1 {
        let recovery_fingerprint = format!("recovery:{}", "8".repeat(64));
        RepairExecutionIntentV1::new(
            "S-session-1",
            7,
            "target-1",
            format!("scan:{}", "1".repeat(64)),
            hash('2'),
            hash('9'),
            recovery_fingerprint.clone(),
            canonical_repair_lock_identity(&recovery_fingerprint),
            before_sha256,
            hash('b'),
            hash('c'),
            hash('d'),
            before_metadata,
        )
        .expect("execution intent")
    }

    fn durable_status() -> RepairBackupStatusPayload {
        let metadata = metadata();
        let before_sha256 = hash('4');
        let binding = RepairBackupBinding::new(
            "P-plan-1",
            hash('6'),
            "A-approval-1",
            hash('7'),
            "rescue:selected-linux-root:etc/fstab",
            before_sha256.clone(),
            execution_intent(before_sha256.clone(), metadata.clone()),
        )
        .expect("binding");
        RepairBackupStatusPayload::durable(
            reservation(),
            hash('1'),
            reservation().locator(),
            "V-0123456789abcdef0123456789abcdef",
            hash('2'),
            hash('3'),
            8192,
            4096,
            before_sha256,
            metadata.canonical_sha256(),
            binding,
        )
        .expect("durable status")
    }

    fn committed_status() -> RepairTransactionStatusPayload {
        let durable = durable_status();
        let intent = durable.execution_intent().expect("execution intent");
        let resolution = RepairTransactionResolution::new(
            RepairTransactionResolutionOutcome::CommittedAfter,
            intent.after_sha256().clone(),
            intent.before_metadata().canonical_sha256(),
            true,
            intent,
        )
        .expect("committed resolution");
        RepairTransactionStatusPayload::resolved(durable, resolution)
            .expect("committed source transaction")
    }

    fn rollback_binding(source: &RepairTransactionStatusPayload) -> RepairRollbackBindingV1 {
        RepairRollbackBindingV1::new(
            source,
            "P-rollback-1",
            hash('8'),
            "A-rollback-1",
            hash('9'),
            8,
        )
        .expect("rollback binding")
    }

    #[test]
    fn reservation_and_status_are_exact_and_path_free() {
        let reserved = RepairBackupStatusPayload::reserved(
            reservation(),
            hash('1'),
            "vault://repair/B-0123456789abcdef0123456789abcdef",
            "V-0123456789abcdef0123456789abcdef",
            hash('2'),
            hash('3'),
            8192,
            4096,
            hash('4'),
            hash('5'),
        )
        .expect("reserved status");
        assert_eq!(reserved.state(), RepairBackupState::Reserved);
        assert!(reserved.validate().is_ok());
        let encoded = serde_json::to_string(&reserved).expect("status JSON");
        assert!(!encoded.contains("/dev/"));
        assert!(!encoded.contains("/mnt/"));
        assert!(!encoded.contains("planId"));

        let mut drifted: serde_json::Value = serde_json::from_str(&encoded).expect("JSON value");
        drifted["locator"] = serde_json::Value::String("vault://repair/B-other".into());
        let drifted: RepairBackupStatusPayload =
            serde_json::from_value(drifted).expect("wire shape remains parseable");
        assert_eq!(drifted.validate(), Err(ProtocolViolation::InvalidPayload));
        assert!(
            RepairBackupStatusPayload::reserved(
                reservation(),
                hash('1'),
                reservation().locator(),
                "V-0123456789abcdef0123456789abcdef",
                hash('2'),
                hash('3'),
                2048,
                4096,
                hash('4'),
                hash('5'),
            )
            .is_err()
        );
    }

    #[test]
    fn durable_status_requires_complete_plan_approval_and_resource_binding() {
        let durable = durable_status();
        assert_eq!(durable.state(), RepairBackupState::Durable);
        assert_eq!(durable.plan_id(), Some("P-plan-1"));
        assert_eq!(
            durable.execution_intent().map(|intent| intent.action_id()),
            Some(REPAIR_EXECUTION_ACTION_ID)
        );
        assert!(durable.validate().is_ok());

        let mut partial = serde_json::to_value(&durable).expect("status JSON");
        partial
            .as_object_mut()
            .expect("object")
            .remove("approvalSha256");
        let partial: RepairBackupStatusPayload =
            serde_json::from_value(partial).expect("wire shape remains parseable");
        assert_eq!(partial.validate(), Err(ProtocolViolation::InvalidPayload));

        let metadata = metadata();
        let before = hash('4');
        assert!(
            RepairBackupBinding::new(
                "P-plan-1",
                hash('6'),
                "A-approval-1",
                hash('7'),
                "rescue:selected-linux-root:etc/shadow",
                before.clone(),
                execution_intent(before, metadata),
            )
            .is_err()
        );
    }

    #[test]
    fn crypttab_intent_lease_and_metadata_are_resource_distinct() {
        let recovery = format!("recovery:{}", "8".repeat(64));
        let private_metadata = RepairFileMetadataV1::new(0o600, 0, 0).expect("private metadata");
        assert!(
            RepairExecutionIntentV1::new(
                "S-session-1",
                1,
                "target-1",
                format!("scan:{}", "1".repeat(64)),
                hash('2'),
                hash('9'),
                recovery.clone(),
                canonical_repair_lock_identity(&recovery),
                hash('4'),
                hash('b'),
                hash('c'),
                hash('d'),
                private_metadata.clone(),
            )
            .is_err()
        );
        let intent = RepairExecutionIntentV1::new_for_resource(
            RepairResourceV1::Crypttab,
            "S-session-1",
            1,
            "target-1",
            format!("scan:{}", "1".repeat(64)),
            hash('2'),
            hash('9'),
            recovery.clone(),
            canonical_repair_lock_identity_for_resource(&recovery, RepairResourceV1::Crypttab),
            hash('4'),
            hash('b'),
            hash('c'),
            hash('d'),
            private_metadata.clone(),
        )
        .expect("crypttab execution intent");
        assert_eq!(intent.action_id(), CRYPTTAB_REPAIR_EXECUTION_ACTION_ID);
        assert_ne!(
            intent.lock_identity(),
            canonical_repair_lock_identity(&recovery)
        );
        assert!(
            RepairBackupBinding::new(
                "P-plan-1",
                hash('6'),
                "A-approval-1",
                hash('7'),
                REPAIR_EXECUTION_RESOURCE_ID,
                hash('4'),
                intent.clone(),
            )
            .is_err()
        );
        let binding = RepairBackupBinding::new(
            "P-plan-1",
            hash('6'),
            "A-approval-1",
            hash('7'),
            CRYPTTAB_REPAIR_EXECUTION_RESOURCE_ID,
            hash('4'),
            intent,
        )
        .expect("crypttab binding");
        let durable = RepairBackupStatusPayload::durable(
            reservation(),
            hash('1'),
            reservation().locator(),
            "V-0123456789abcdef0123456789abcdef",
            hash('2'),
            hash('3'),
            8192,
            4096,
            hash('4'),
            private_metadata.canonical_sha256(),
            binding,
        )
        .expect("crypttab durable status");
        let pending = RepairTransactionStatusPayload::pending(durable.clone())
            .expect("pending crypttab transaction");
        let lease =
            RepairWriteLeasePayload::consumed(pending, hash('e')).expect("crypttab write lease");
        assert_eq!(lease.capability(), CRYPTTAB_REPAIR_WRITE_LEASE_CAPABILITY);

        let intent = durable.execution_intent().expect("crypttab intent");
        let resolution = RepairTransactionResolution::new(
            RepairTransactionResolutionOutcome::CommittedAfter,
            intent.after_sha256().clone(),
            intent.before_metadata().canonical_sha256(),
            true,
            intent,
        )
        .expect("crypttab committed resolution");
        let source = RepairTransactionStatusPayload::resolved(durable, resolution)
            .expect("committed crypttab source");
        let rollback_binding = RepairRollbackBindingV1::new(
            &source,
            "P-crypttab-rollback",
            hash('8'),
            "A-crypttab-rollback",
            hash('9'),
            2,
        )
        .expect("crypttab rollback binding");
        assert_eq!(
            rollback_binding.action_id(),
            CRYPTTAB_REPAIR_ROLLBACK_ACTION_ID
        );
        let rollback = RepairRollbackTransactionStatusPayload::pending(
            RepairRollbackId::parse("RB-fedcba9876543210fedcba9876543210").expect("rollback ID"),
            source,
            rollback_binding,
        )
        .expect("crypttab rollback transaction");
        let rollback_lease = RepairRollbackWriteLeasePayload::consumed(rollback, hash('f'))
            .expect("crypttab rollback lease");
        assert_eq!(
            rollback_lease.capability(),
            CRYPTTAB_REPAIR_ROLLBACK_WRITE_LEASE_CAPABILITY
        );
    }

    #[test]
    fn resolver_link_intent_is_resource_and_lock_domain_distinct() {
        let recovery = format!("recovery:{}", "8".repeat(64));
        let metadata = RepairFileMetadataV1::new(0o600, 0, 0).expect("closed state metadata");
        let intent = RepairExecutionIntentV1::new_for_resource(
            RepairResourceV1::ResolverLink,
            "S-session-1",
            1,
            "target-1",
            format!("scan:{}", "1".repeat(64)),
            hash('2'),
            hash('9'),
            recovery.clone(),
            canonical_repair_lock_identity_for_resource(&recovery, RepairResourceV1::ResolverLink),
            hash('4'),
            hash('b'),
            hash('c'),
            hash('d'),
            metadata,
        )
        .expect("resolver-link intent");
        assert_eq!(intent.action_id(), RESOLVER_LINK_REPAIR_EXECUTION_ACTION_ID);
        assert_eq!(
            RepairResourceV1::from_execution(
                intent.action_id(),
                RESOLVER_LINK_REPAIR_EXECUTION_RESOURCE_ID,
            ),
            Ok(RepairResourceV1::ResolverLink),
        );
        assert_ne!(
            intent.lock_identity(),
            canonical_repair_lock_identity(&recovery),
        );
        assert_ne!(
            RepairResourceV1::ResolverLink.write_lease_capability(),
            RepairResourceV1::Crypttab.write_lease_capability(),
        );
    }

    #[test]
    fn execution_intent_and_transaction_binding_are_canonical_and_path_free() {
        let durable = durable_status();
        let pending =
            RepairTransactionStatusPayload::pending(durable.clone()).expect("pending transaction");
        let same = RepairTransactionStatusPayload::pending(durable).expect("same transaction");
        assert_eq!(
            pending.transaction_binding_sha256(),
            same.transaction_binding_sha256()
        );
        assert!(pending.is_unresolved());
        let encoded = serde_json::to_string(&pending).expect("transaction JSON");
        assert!(encoded.contains("\"targetRecoveryFingerprint\":\"recovery:"));
        assert!(!encoded.contains("/dev/"));
        assert!(!encoded.contains("/mnt/"));
        assert!(!encoded.contains("command"));

        let mut unknown: serde_json::Value = serde_json::from_str(&encoded).expect("JSON value");
        unknown["hostPath"] = serde_json::Value::String("/etc/fstab".to_owned());
        assert!(serde_json::from_value::<RepairTransactionStatusPayload>(unknown).is_err());

        let durable = durable_status();
        let mut invalid_intent =
            serde_json::to_value(durable.execution_intent().expect("intent")).expect("intent JSON");
        invalid_intent["targetRecoveryFingerprint"] =
            serde_json::Value::String("recovery:UPPERCASE".to_owned());
        let invalid_intent: RepairExecutionIntentV1 =
            serde_json::from_value(invalid_intent).expect("closed wire shape");
        assert_eq!(
            invalid_intent.validate(),
            Err(ProtocolViolation::InvalidPayload)
        );
    }

    #[test]
    fn write_lease_is_exact_pending_boot_scoped_and_tamper_evident() {
        let pending =
            RepairTransactionStatusPayload::pending(durable_status()).expect("pending transaction");
        let lease = RepairWriteLeasePayload::consumed(pending.clone(), hash('e'))
            .expect("consumed write lease receipt");
        assert_eq!(lease.capability(), REPAIR_WRITE_LEASE_CAPABILITY);
        assert_eq!(lease.transaction(), &pending);
        assert_eq!(lease.boot_epoch_sha256(), &hash('e'));
        assert!(lease.validate().is_ok());

        let mut tampered = serde_json::to_value(&lease).expect("lease JSON");
        tampered["bootEpochSha256"] = serde_json::Value::String("f".repeat(64));
        let tampered: RepairWriteLeasePayload =
            serde_json::from_value(tampered).expect("closed wire shape");
        assert_eq!(tampered.validate(), Err(ProtocolViolation::InvalidPayload));

        let resolved_intent = pending.backup().execution_intent().expect("durable intent");
        let resolution = RepairTransactionResolution::new(
            RepairTransactionResolutionOutcome::CommittedAfter,
            resolved_intent.after_sha256().clone(),
            resolved_intent.before_metadata().canonical_sha256(),
            true,
            resolved_intent,
        )
        .expect("resolution");
        let resolved = RepairTransactionStatusPayload::resolved(durable_status(), resolution)
            .expect("resolved transaction");
        assert!(RepairWriteLeasePayload::consumed(resolved, hash('e')).is_err());
    }

    #[test]
    fn rollback_child_requires_committed_source_and_fresh_plan_and_next_approval() {
        let source = committed_status();
        let binding = rollback_binding(&source);
        let pending = RepairRollbackTransactionStatusPayload::pending(
            RepairRollbackId::parse("RB-0123456789abcdef0123456789abcdef").expect("rollback ID"),
            source.clone(),
            binding,
        )
        .expect("pending rollback child");
        assert_eq!(pending.phase(), RepairTransactionPhase::Pending);
        assert_ne!(
            pending.rollback_transaction_binding_sha256(),
            source.transaction_binding_sha256()
        );
        let encoded = serde_json::to_string(&pending).expect("rollback JSON");
        assert!(!encoded.contains("/dev/"));
        assert!(!encoded.contains("/mnt/"));
        assert!(!encoded.contains("command"));

        assert!(
            RepairRollbackBindingV1::new(
                &source,
                source.backup().plan_id().expect("source plan"),
                hash('8'),
                "A-rollback-1",
                hash('9'),
                8,
            )
            .is_err()
        );
        assert!(
            RepairRollbackBindingV1::new(
                &source,
                "P-rollback-1",
                source
                    .backup()
                    .plan_sha256()
                    .expect("source plan hash")
                    .clone(),
                "A-rollback-1",
                hash('9'),
                8,
            )
            .is_err()
        );
        assert!(
            RepairRollbackBindingV1::new(
                &source,
                "P-rollback-1",
                hash('8'),
                source.backup().approval_id().expect("source approval"),
                hash('9'),
                8,
            )
            .is_err()
        );
        assert!(
            RepairRollbackBindingV1::new(
                &source,
                "P-rollback-1",
                hash('8'),
                "A-rollback-1",
                hash('9'),
                7,
            )
            .is_err()
        );
        let unresolved =
            RepairTransactionStatusPayload::pending(durable_status()).expect("pending source");
        assert!(
            RepairRollbackBindingV1::new(
                &unresolved,
                "P-rollback-1",
                hash('8'),
                "A-rollback-1",
                hash('9'),
                8,
            )
            .is_err()
        );
    }

    #[test]
    fn rollback_lease_is_domain_separated_pending_and_boot_scoped() {
        let source = committed_status();
        let pending = RepairRollbackTransactionStatusPayload::pending(
            RepairRollbackId::parse("RB-fedcba9876543210fedcba9876543210").expect("rollback ID"),
            source.clone(),
            rollback_binding(&source),
        )
        .expect("pending rollback");
        let lease = RepairRollbackWriteLeasePayload::consumed(pending.clone(), hash('e'))
            .expect("rollback lease");
        assert_eq!(lease.capability(), REPAIR_ROLLBACK_WRITE_LEASE_CAPABILITY);
        assert_eq!(lease.transaction(), &pending);
        assert!(lease.validate().is_ok());

        let resolution = RepairRollbackResolution::new(
            RepairRollbackResolutionOutcome::RolledBackBefore,
            source
                .backup()
                .execution_intent()
                .expect("intent")
                .before_sha256()
                .clone(),
            source
                .backup()
                .execution_intent()
                .expect("intent")
                .before_metadata()
                .canonical_sha256(),
            true,
            &source,
        )
        .expect("rollback resolution");
        let resolved = RepairRollbackTransactionStatusPayload::resolved(
            pending.rollback_id().clone(),
            source.clone(),
            rollback_binding(&source),
            resolution,
        )
        .expect("resolved rollback");
        assert!(RepairRollbackWriteLeasePayload::consumed(resolved, hash('e')).is_err());
    }

    #[test]
    fn transaction_resolution_distinguishes_before_after_and_third() {
        let durable = durable_status();
        let intent = durable.execution_intent().expect("execution intent");
        let committed = RepairTransactionResolution::new(
            RepairTransactionResolutionOutcome::CommittedAfter,
            intent.after_sha256().clone(),
            intent.before_metadata().canonical_sha256(),
            true,
            intent,
        )
        .expect("committed resolution");
        assert_eq!(
            committed.target_state(),
            RepairTransactionTargetState::After
        );
        let resolved = RepairTransactionStatusPayload::resolved(durable.clone(), committed)
            .expect("resolved transaction");
        assert_eq!(resolved.phase(), RepairTransactionPhase::Resolved);
        assert!(!resolved.is_unresolved());

        let manual = RepairTransactionResolution::new(
            RepairTransactionResolutionOutcome::ManualReconciliationRequired,
            hash('e'),
            hash('f'),
            false,
            intent,
        )
        .expect("manual resolution");
        assert_eq!(manual.target_state(), RepairTransactionTargetState::Third);
        let manual =
            RepairTransactionStatusPayload::resolved(durable, manual).expect("manual transaction");
        assert!(manual.is_unresolved());
        assert!(
            RepairTransactionStatusSelector::pending_singleton()
                .matches_result(&RepairTransactionStatusResultPayload::found(manual))
        );
    }

    #[test]
    fn draft_and_descriptor_bounds_fail_closed() {
        assert!(RepairReservationId::parse("B-ABC").is_err());
        assert!(
            RepairBackupDraft::new(
                "S-session",
                "target-1",
                hash('1'),
                format!("recovery:{}", "4".repeat(64)),
                hash('2'),
                hash('3'),
                4096,
                8192,
            )
            .is_ok()
        );
        assert!(
            RepairBackupDraft::new(
                "S-session",
                "/dev/sda2",
                hash('1'),
                format!("recovery:{}", "4".repeat(64)),
                hash('2'),
                hash('3'),
                4096,
                8192,
            )
            .is_err()
        );
        assert!(repair_backup_input(0).is_err());
        assert!(repair_backup_output(MAX_REPAIR_BACKUP_BYTES + 1).is_err());
    }

    #[test]
    fn draft_binding_matches_the_store_domain_and_length_framing() {
        let draft = RepairBackupDraft::new(
            "S-session-1",
            "target-1",
            hash('1'),
            format!("recovery:{}", "4".repeat(64)),
            hash('2'),
            hash('3'),
            4096,
            8192,
        )
        .expect("canonical draft");
        assert_eq!(
            canonical_repair_draft_binding_sha256(&draft).as_str(),
            "a17c24df89d841805937201849843e7562bfcb11be03b81d1cdc06d5e8954179"
        );
        assert!(
            RepairBackupDraft::new(
                "S-session-1",
                "target-1",
                hash('1'),
                format!("recovery:{}", "4".repeat(64)),
                hash('2'),
                hash('3'),
                8192,
                4096,
            )
            .is_err()
        );
    }

    #[test]
    fn file_metadata_v1_is_closed_bounded_and_hash_bound() {
        let metadata = RepairFileMetadataV1::new(0o640, 1000, 1001).expect("metadata");
        assert_eq!(metadata.mode(), 0o640);
        assert_eq!(metadata.uid(), 1000);
        assert_eq!(metadata.gid(), 1001);
        assert_eq!(
            metadata.canonical_sha256(),
            canonical_repair_file_metadata_sha256(&metadata)
        );
        assert!(RepairFileMetadataV1::new(0o10000, 0, 0).is_err());
        let json = serde_json::to_string(&metadata).expect("metadata JSON");
        assert_eq!(
            json,
            r#"{"mode":416,"uid":1000,"gid":1001,"xattrs":"none","posixAcl":"none"}"#
        );
        assert!(!json.contains('/'));
    }
}
