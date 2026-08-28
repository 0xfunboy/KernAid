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

const MAX_OPAQUE_ID_BYTES: usize = 128;
const RESERVATION_BINDING_DOMAIN: &[u8] = b"KERNAID-REPAIR-RESERVATION-V1\0";

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
        expected_backup_sha256: Sha256,
        metadata_sha256: Sha256,
        backup_size: u64,
        required_capacity_bytes: u64,
    ) -> Result<Self, ProtocolViolation> {
        let value = Self {
            session_id: session_id.into(),
            target_id: target_id.into(),
            target_fingerprint,
            expected_backup_sha256,
            metadata_sha256,
            backup_size,
            required_capacity_bytes,
        };
        if !valid_prefixed_id(&value.session_id, "S-")
            || !valid_opaque_id(&value.target_id)
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
    hash_field(&mut hasher, &draft.expected_backup_sha256.bytes());
    hash_field(&mut hasher, &draft.metadata_sha256.bytes());
    hash_field(&mut hasher, &draft.backup_size.to_be_bytes());
    hash_field(&mut hasher, &draft.required_capacity_bytes.to_be_bytes());
    Sha256::parse(&encode_hex(&hasher.finalize())).expect("SHA-256 digest is canonical")
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
}

impl RepairBackupBinding {
    pub fn new(
        plan_id: impl Into<String>,
        plan_sha256: Sha256,
        approval_id: impl Into<String>,
        approval_sha256: Sha256,
        resource_id: impl Into<String>,
        resource_sha256: Sha256,
    ) -> Result<Self, ProtocolViolation> {
        let value = Self {
            plan_id: plan_id.into(),
            plan_sha256,
            approval_id: approval_id.into(),
            approval_sha256,
            resource_id: resource_id.into(),
            resource_sha256,
        };
        if !valid_prefixed_id(&value.plan_id, "P-")
            || !valid_prefixed_id(&value.approval_id, "A-")
            || !valid_resource_id(&value.resource_id)
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
}

#[derive(Clone, Copy, Debug, Deserialize, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum RepairBackupState {
    Reserved,
    Durable,
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
        let (plan_id, plan_sha256, approval_id, approval_sha256, resource_id, resource_sha256) =
            binding.map_or((None, None, None, None, None, None), |value| {
                (
                    Some(value.plan_id),
                    Some(value.plan_sha256),
                    Some(value.approval_id),
                    Some(value.approval_sha256),
                    Some(value.resource_id),
                    Some(value.resource_sha256),
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
            && self.resource_sha256.is_some()
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

fn valid_resource_id(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= MAX_OPAQUE_ID_BYTES
        && !value.starts_with('/')
        && !value.contains("..")
        && !value.contains('\\')
        && value.bytes().all(|byte| {
            byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b':' | b'/' | b'.')
        })
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
        let binding = RepairBackupBinding::new(
            "P-plan-1",
            hash('6'),
            "A-approval-1",
            hash('7'),
            "rescue:selected-linux-root:etc/fstab",
            hash('8'),
        )
        .expect("binding");
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
            hash('5'),
            binding,
        )
        .expect("durable status");
        assert_eq!(durable.state(), RepairBackupState::Durable);
        assert_eq!(durable.plan_id(), Some("P-plan-1"));
        assert!(durable.validate().is_ok());

        let mut partial = serde_json::to_value(&durable).expect("status JSON");
        partial
            .as_object_mut()
            .expect("object")
            .remove("approvalSha256");
        let partial: RepairBackupStatusPayload =
            serde_json::from_value(partial).expect("wire shape remains parseable");
        assert_eq!(partial.validate(), Err(ProtocolViolation::InvalidPayload));
    }

    #[test]
    fn draft_and_descriptor_bounds_fail_closed() {
        assert!(RepairReservationId::parse("B-ABC").is_err());
        assert!(
            RepairBackupDraft::new(
                "S-session",
                "target-1",
                hash('1'),
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
            hash('2'),
            hash('3'),
            4096,
            8192,
        )
        .expect("canonical draft");
        assert_eq!(
            canonical_repair_draft_binding_sha256(&draft).as_str(),
            "d542b029fcb511754445d421195ad99f720a24c5db572e8bbd198b2a0e150bdc"
        );
        assert!(
            RepairBackupDraft::new(
                "S-session-1",
                "target-1",
                hash('1'),
                hash('2'),
                hash('3'),
                8192,
                4096,
            )
            .is_err()
        );
    }
}
