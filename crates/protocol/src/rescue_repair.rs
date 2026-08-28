//! Closed, path-free protocol objects for the disabled Rescue `fstab` preflight.
//!
//! These values carry only opaque identifiers and deterministic fingerprints.
//! They contain no path, device name, command, observed bytes, replacement
//! bytes, file descriptor or I/O capability. Constructing a value performs all
//! validation; the module deliberately provides no execution operation.

use std::fmt;

pub const RESCUE_FSTAB_RESOURCE_ID: &str = "rescue:selected-linux-root:etc/fstab";
pub const RESCUE_FSTAB_EVIDENCE_IDS: [&str; 2] = ["E-LINUX-FSTAB", "E-LINUX-LSBLK"];
pub const RESCUE_FSTAB_READY_OUTCOME: &str = "ready-read-only";

const MAX_PREFIXED_ID_BYTES: usize = 128;
const MAX_OPAQUE_ID_BYTES: usize = 96;
const VAULT_LOCATOR_PREFIX: &str = "vault://repair/";

/// Sanitized fail-closed failures. No variant carries caller-controlled text.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RescueRepairProtocolError {
    InvalidRequestId,
    InvalidSessionId,
    InvalidPlanId,
    InvalidHash,
    InvalidResourceId,
    InvalidTargetId,
    InvalidScanFingerprint,
    InvalidEvidenceId,
    InvalidEvidenceOrder,
    InvalidVaultId,
    InvalidReservationId,
    InvalidReservationBinding,
    InvalidVaultLocator,
    InvalidVaultIdentity,
    InvalidPhysicalParent,
    PhysicalParentsNotDistinct,
    InvalidCapacity,
    InsufficientCapacity,
    InvalidLockIdentity,
    InvalidOutcome,
}

impl fmt::Display for RescueRepairProtocolError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::InvalidRequestId => "invalid Rescue repair request identifier",
            Self::InvalidSessionId => "invalid Rescue repair session identifier",
            Self::InvalidPlanId => "invalid Rescue repair plan identifier",
            Self::InvalidHash => "invalid Rescue repair hash",
            Self::InvalidResourceId => "invalid Rescue repair resource identifier",
            Self::InvalidTargetId => "invalid Rescue repair target identifier",
            Self::InvalidScanFingerprint => "invalid Rescue repair scan fingerprint",
            Self::InvalidEvidenceId => "invalid Rescue repair evidence identifier",
            Self::InvalidEvidenceOrder => "invalid Rescue repair evidence order",
            Self::InvalidVaultId => "invalid Rescue repair vault identifier",
            Self::InvalidReservationId => "invalid Rescue repair reservation identifier",
            Self::InvalidReservationBinding => "invalid Rescue repair reservation binding",
            Self::InvalidVaultLocator => "invalid Rescue repair vault locator",
            Self::InvalidVaultIdentity => "invalid Rescue repair vault identity",
            Self::InvalidPhysicalParent => "invalid Rescue repair physical parent",
            Self::PhysicalParentsNotDistinct => {
                "Rescue repair target and vault physical parents are not distinct"
            }
            Self::InvalidCapacity => "invalid Rescue repair vault capacity",
            Self::InsufficientCapacity => "insufficient Rescue repair vault capacity",
            Self::InvalidLockIdentity => "invalid Rescue repair lock identity",
            Self::InvalidOutcome => "invalid Rescue repair preflight outcome",
        })
    }
}

/// Closed client request for the sole production-candidate preparation flow.
///
/// These are the only values the untrusted UI may select.  In particular the
/// request contains no action, resource, path, bytes, snapshot hash, evidence
/// identifier or evidence hash: the broker derives all of those while holding
/// the root-issued read-only target capability.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RescueFstabPrepareRequest {
    request_id: String,
    session_id: String,
    plan_id: String,
    scan_fingerprint: String,
    target_id: String,
    target_fingerprint: String,
}

impl RescueFstabPrepareRequest {
    pub fn new(
        request_id: impl Into<String>,
        session_id: impl Into<String>,
        plan_id: impl Into<String>,
        scan_fingerprint: impl Into<String>,
        target_id: impl Into<String>,
        target_fingerprint: impl Into<String>,
    ) -> Result<Self, RescueRepairProtocolError> {
        let request = Self {
            request_id: request_id.into(),
            session_id: session_id.into(),
            plan_id: plan_id.into(),
            scan_fingerprint: scan_fingerprint.into(),
            target_id: target_id.into(),
            target_fingerprint: target_fingerprint.into(),
        };
        request.validate()?;
        Ok(request)
    }

    fn validate(&self) -> Result<(), RescueRepairProtocolError> {
        if !valid_request_id(&self.request_id) {
            return Err(RescueRepairProtocolError::InvalidRequestId);
        }
        if !valid_prefixed_id(&self.session_id, "S-") {
            return Err(RescueRepairProtocolError::InvalidSessionId);
        }
        if !valid_prefixed_id(&self.plan_id, "P-") {
            return Err(RescueRepairProtocolError::InvalidPlanId);
        }
        if !valid_scan_fingerprint(&self.scan_fingerprint) {
            return Err(RescueRepairProtocolError::InvalidScanFingerprint);
        }
        if !valid_target_id(&self.target_id) {
            return Err(RescueRepairProtocolError::InvalidTargetId);
        }
        if !valid_sha256(&self.target_fingerprint) {
            return Err(RescueRepairProtocolError::InvalidHash);
        }
        Ok(())
    }

    pub fn request_id(&self) -> &str {
        &self.request_id
    }
    pub fn session_id(&self) -> &str {
        &self.session_id
    }
    pub fn plan_id(&self) -> &str {
        &self.plan_id
    }
    pub fn scan_fingerprint(&self) -> &str {
        &self.scan_fingerprint
    }
    pub fn target_id(&self) -> &str {
        &self.target_id
    }
    pub fn target_fingerprint(&self) -> &str {
        &self.target_fingerprint
    }
}

impl std::error::Error for RescueRepairProtocolError {}

/// One canonical evidence digest. Only the two candidate evidence identifiers
/// are accepted; the containing request enforces their exact order.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RescueFstabEvidenceBinding {
    evidence_id: String,
    sha256: String,
}

/// Closed request for the read-only discovery/reservation phase.
///
/// This intentionally precedes a final plan hash and local R2 approval.  The
/// broker must first bind the selected target, exact resource snapshot and a
/// real Vault reservation; Core can then stage and approve the resulting
/// immutable plan.  Keeping approval fields out of this value prevents an
/// approval from being collected for a plan whose backup location is not yet
/// known.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RescueFstabPreflightIntent {
    session_id: String,
    plan_id: String,
    target_fingerprint: String,
    target_snapshot: String,
    resource_id: String,
    target_id: String,
    scan_fingerprint: String,
    evidence: [RescueFstabEvidenceBinding; 2],
}

impl RescueFstabPreflightIntent {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        session_id: impl Into<String>,
        plan_id: impl Into<String>,
        target_fingerprint: impl Into<String>,
        target_snapshot: impl Into<String>,
        resource_id: impl Into<String>,
        target_id: impl Into<String>,
        scan_fingerprint: impl Into<String>,
        evidence: [RescueFstabEvidenceBinding; 2],
    ) -> Result<Self, RescueRepairProtocolError> {
        let intent = Self {
            session_id: session_id.into(),
            plan_id: plan_id.into(),
            target_fingerprint: target_fingerprint.into(),
            target_snapshot: target_snapshot.into(),
            resource_id: resource_id.into(),
            target_id: target_id.into(),
            scan_fingerprint: scan_fingerprint.into(),
            evidence,
        };
        intent.validate()?;
        Ok(intent)
    }

    fn validate(&self) -> Result<(), RescueRepairProtocolError> {
        if !valid_prefixed_id(&self.session_id, "S-") {
            return Err(RescueRepairProtocolError::InvalidSessionId);
        }
        if !valid_prefixed_id(&self.plan_id, "P-") {
            return Err(RescueRepairProtocolError::InvalidPlanId);
        }
        if !valid_sha256(&self.target_fingerprint) || !valid_sha256(&self.target_snapshot) {
            return Err(RescueRepairProtocolError::InvalidHash);
        }
        if self.resource_id != RESCUE_FSTAB_RESOURCE_ID {
            return Err(RescueRepairProtocolError::InvalidResourceId);
        }
        if !valid_opaque_id(&self.target_id) {
            return Err(RescueRepairProtocolError::InvalidTargetId);
        }
        if !valid_scan_fingerprint(&self.scan_fingerprint) {
            return Err(RescueRepairProtocolError::InvalidScanFingerprint);
        }
        for (binding, expected_id) in self.evidence.iter().zip(RESCUE_FSTAB_EVIDENCE_IDS) {
            if binding.evidence_id != expected_id {
                return Err(RescueRepairProtocolError::InvalidEvidenceOrder);
            }
            if !valid_sha256(&binding.sha256) {
                return Err(RescueRepairProtocolError::InvalidHash);
            }
        }
        Ok(())
    }

    pub fn session_id(&self) -> &str {
        &self.session_id
    }
    pub fn plan_id(&self) -> &str {
        &self.plan_id
    }
    pub fn target_fingerprint(&self) -> &str {
        &self.target_fingerprint
    }
    pub fn target_snapshot(&self) -> &str {
        &self.target_snapshot
    }
    pub fn resource_id(&self) -> &str {
        &self.resource_id
    }
    pub fn target_id(&self) -> &str {
        &self.target_id
    }
    pub fn scan_fingerprint(&self) -> &str {
        &self.scan_fingerprint
    }
    pub fn evidence(&self) -> &[RescueFstabEvidenceBinding; 2] {
        &self.evidence
    }
}

impl RescueFstabEvidenceBinding {
    pub fn new(
        evidence_id: impl Into<String>,
        sha256: impl Into<String>,
    ) -> Result<Self, RescueRepairProtocolError> {
        let binding = Self {
            evidence_id: evidence_id.into(),
            sha256: sha256.into(),
        };
        if !RESCUE_FSTAB_EVIDENCE_IDS.contains(&binding.evidence_id.as_str()) {
            return Err(RescueRepairProtocolError::InvalidEvidenceId);
        }
        if !valid_sha256(&binding.sha256) {
            return Err(RescueRepairProtocolError::InvalidHash);
        }
        Ok(binding)
    }

    pub fn evidence_id(&self) -> &str {
        &self.evidence_id
    }

    pub fn sha256(&self) -> &str {
        &self.sha256
    }
}

/// Audit-only result of read-only discovery and a real Vault reservation.
///
/// The receipt is safe to clone and render, but grants no authority.  Core
/// must stage `plan_hash` and collect a later local approval; only the
/// broker-owned prepared value retaining its descriptors and reservation can
/// subsequently accept that approval.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RescueFstabPreparedPlanReceipt {
    intent: RescueFstabPreflightIntent,
    plan_hash: String,
    after_sha256: String,
    diff_sha256: String,
    vault_id: String,
    reservation_id: String,
    reservation_binding_sha256: String,
    backup_locator: String,
    vault_identity_fingerprint: String,
    target_recovery_fingerprint: String,
    target_physical_parent_fingerprint: String,
    vault_physical_parent_fingerprint: String,
    required_capacity_bytes: u64,
    reserved_capacity_bytes: u64,
    lock_identity: String,
    outcome: String,
}

impl RescueFstabPreparedPlanReceipt {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        intent: RescueFstabPreflightIntent,
        plan_hash: impl Into<String>,
        after_sha256: impl Into<String>,
        diff_sha256: impl Into<String>,
        vault_id: impl Into<String>,
        reservation_id: impl Into<String>,
        reservation_binding_sha256: impl Into<String>,
        backup_locator: impl Into<String>,
        vault_identity_fingerprint: impl Into<String>,
        target_recovery_fingerprint: impl Into<String>,
        target_physical_parent_fingerprint: impl Into<String>,
        vault_physical_parent_fingerprint: impl Into<String>,
        required_capacity_bytes: u64,
        reserved_capacity_bytes: u64,
        lock_identity: impl Into<String>,
        outcome: impl Into<String>,
    ) -> Result<Self, RescueRepairProtocolError> {
        intent.validate()?;
        let receipt = Self {
            intent,
            plan_hash: plan_hash.into(),
            after_sha256: after_sha256.into(),
            diff_sha256: diff_sha256.into(),
            vault_id: vault_id.into(),
            reservation_id: reservation_id.into(),
            reservation_binding_sha256: reservation_binding_sha256.into(),
            backup_locator: backup_locator.into(),
            vault_identity_fingerprint: vault_identity_fingerprint.into(),
            target_recovery_fingerprint: target_recovery_fingerprint.into(),
            target_physical_parent_fingerprint: target_physical_parent_fingerprint.into(),
            vault_physical_parent_fingerprint: vault_physical_parent_fingerprint.into(),
            required_capacity_bytes,
            reserved_capacity_bytes,
            lock_identity: lock_identity.into(),
            outcome: outcome.into(),
        };
        receipt.validate()?;
        Ok(receipt)
    }

    fn validate(&self) -> Result<(), RescueRepairProtocolError> {
        self.intent.validate()?;
        if !valid_sha256(&self.plan_hash)
            || !valid_sha256(&self.after_sha256)
            || !valid_sha256(&self.diff_sha256)
            || self.after_sha256 == self.intent.target_snapshot
        {
            return Err(RescueRepairProtocolError::InvalidHash);
        }
        if !valid_opaque_id(&self.vault_id) {
            return Err(RescueRepairProtocolError::InvalidVaultId);
        }
        if !valid_prefixed_id(&self.reservation_id, "B-") {
            return Err(RescueRepairProtocolError::InvalidReservationId);
        }
        if !valid_sha256(&self.reservation_binding_sha256) {
            return Err(RescueRepairProtocolError::InvalidReservationBinding);
        }
        if !valid_vault_locator(&self.backup_locator)
            || self.backup_locator.strip_prefix(VAULT_LOCATOR_PREFIX)
                != Some(self.reservation_id.as_str())
        {
            return Err(RescueRepairProtocolError::InvalidVaultLocator);
        }
        if !valid_sha256(&self.vault_identity_fingerprint) {
            return Err(RescueRepairProtocolError::InvalidVaultIdentity);
        }
        if !valid_recovery_fingerprint(&self.target_recovery_fingerprint) {
            return Err(RescueRepairProtocolError::InvalidTargetId);
        }
        if !valid_sha256(&self.target_physical_parent_fingerprint)
            || !valid_sha256(&self.vault_physical_parent_fingerprint)
        {
            return Err(RescueRepairProtocolError::InvalidPhysicalParent);
        }
        if self.target_physical_parent_fingerprint == self.vault_physical_parent_fingerprint {
            return Err(RescueRepairProtocolError::PhysicalParentsNotDistinct);
        }
        if self.required_capacity_bytes == 0 || self.reserved_capacity_bytes == 0 {
            return Err(RescueRepairProtocolError::InvalidCapacity);
        }
        if self.reserved_capacity_bytes < self.required_capacity_bytes {
            return Err(RescueRepairProtocolError::InsufficientCapacity);
        }
        if !valid_opaque_id(&self.lock_identity) {
            return Err(RescueRepairProtocolError::InvalidLockIdentity);
        }
        if self.outcome != RESCUE_FSTAB_READY_OUTCOME {
            return Err(RescueRepairProtocolError::InvalidOutcome);
        }
        Ok(())
    }

    pub fn intent(&self) -> &RescueFstabPreflightIntent {
        &self.intent
    }
    pub fn plan_hash(&self) -> &str {
        &self.plan_hash
    }
    pub fn before_sha256(&self) -> &str {
        self.intent.target_snapshot()
    }
    pub fn after_sha256(&self) -> &str {
        &self.after_sha256
    }
    pub fn diff_sha256(&self) -> &str {
        &self.diff_sha256
    }
    pub fn vault_id(&self) -> &str {
        &self.vault_id
    }
    pub fn reservation_id(&self) -> &str {
        &self.reservation_id
    }
    pub fn reservation_binding_sha256(&self) -> &str {
        &self.reservation_binding_sha256
    }
    pub fn backup_locator(&self) -> &str {
        &self.backup_locator
    }
    pub fn vault_identity_fingerprint(&self) -> &str {
        &self.vault_identity_fingerprint
    }
    pub fn target_recovery_fingerprint(&self) -> &str {
        &self.target_recovery_fingerprint
    }
    pub fn target_physical_parent_fingerprint(&self) -> &str {
        &self.target_physical_parent_fingerprint
    }
    pub fn vault_physical_parent_fingerprint(&self) -> &str {
        &self.vault_physical_parent_fingerprint
    }
    pub const fn required_capacity_bytes(&self) -> u64 {
        self.required_capacity_bytes
    }
    pub const fn reserved_capacity_bytes(&self) -> u64 {
        self.reserved_capacity_bytes
    }
    pub fn lock_identity(&self) -> &str {
        &self.lock_identity
    }
    pub fn outcome(&self) -> &str {
        &self.outcome
    }
}

fn valid_sha256(value: &str) -> bool {
    value
        .strip_prefix("sha256:")
        .is_some_and(valid_lower_hex_64)
}

fn valid_scan_fingerprint(value: &str) -> bool {
    value.strip_prefix("scan:").is_some_and(valid_lower_hex_64)
}

fn valid_target_id(value: &str) -> bool {
    value
        .strip_prefix("target:")
        .is_some_and(valid_lower_hex_64)
}

fn valid_request_id(value: &str) -> bool {
    let Some(uuid) = value.strip_prefix("R-") else {
        return false;
    };
    uuid.len() == 36
        && uuid.bytes().enumerate().all(|(index, byte)| match index {
            8 | 13 | 18 | 23 => byte == b'-',
            _ => byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte),
        })
}

fn valid_recovery_fingerprint(value: &str) -> bool {
    value
        .strip_prefix("recovery:")
        .is_some_and(valid_lower_hex_64)
}

fn valid_lower_hex_64(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn valid_prefixed_id(value: &str, prefix: &str) -> bool {
    value.len() <= MAX_PREFIXED_ID_BYTES
        && value.strip_prefix(prefix).is_some_and(|suffix| {
            !suffix.is_empty()
                && suffix
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
        })
}

fn valid_opaque_id(value: &str) -> bool {
    (1..=MAX_OPAQUE_ID_BYTES).contains(&value.len())
        && !value.contains("..")
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b':' | b'.'))
}

fn valid_vault_locator(value: &str) -> bool {
    value.len() <= VAULT_LOCATOR_PREFIX.len() + MAX_OPAQUE_ID_BYTES
        && value
            .strip_prefix(VAULT_LOCATOR_PREFIX)
            .is_some_and(valid_opaque_id)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hash(character: char) -> String {
        format!("sha256:{}", character.to_string().repeat(64))
    }

    fn scan(character: char) -> String {
        format!("scan:{}", character.to_string().repeat(64))
    }

    fn target(character: char) -> String {
        format!("target:{}", character.to_string().repeat(64))
    }

    #[test]
    fn prepare_request_contains_only_closed_selection_claims() {
        let request = RescueFstabPrepareRequest::new(
            "R-01234567-89ab-cdef-0123-456789abcdef",
            "S-rescue",
            "P-fstab",
            scan('6'),
            target('7'),
            hash('2'),
        )
        .expect("closed prepare request");
        assert_eq!(request.session_id(), "S-rescue");
        assert_eq!(request.plan_id(), "P-fstab");
        assert_eq!(request.scan_fingerprint(), scan('6'));
        assert_eq!(request.target_id(), target('7'));
        assert_eq!(request.target_fingerprint(), hash('2'));

        assert_eq!(
            RescueFstabPrepareRequest::new(
                "R-NOT-A-UUID",
                "S-rescue",
                "P-fstab",
                scan('6'),
                target('7'),
                hash('2'),
            ),
            Err(RescueRepairProtocolError::InvalidRequestId)
        );
        assert_eq!(
            RescueFstabPrepareRequest::new(
                "R-01234567-89ab-cdef-0123-456789abcdef",
                "S-rescue",
                "P-fstab",
                scan('6'),
                "/dev/sda2",
                hash('2'),
            ),
            Err(RescueRepairProtocolError::InvalidTargetId)
        );
    }

    fn evidence() -> [RescueFstabEvidenceBinding; 2] {
        [
            RescueFstabEvidenceBinding::new(RESCUE_FSTAB_EVIDENCE_IDS[0], hash('4'))
                .expect("fstab evidence"),
            RescueFstabEvidenceBinding::new(RESCUE_FSTAB_EVIDENCE_IDS[1], hash('5'))
                .expect("lsblk evidence"),
        ]
    }

    fn intent() -> RescueFstabPreflightIntent {
        RescueFstabPreflightIntent::new(
            "S-rescue",
            "P-fstab",
            hash('2'),
            hash('3'),
            RESCUE_FSTAB_RESOURCE_ID,
            "target-01",
            scan('6'),
            evidence(),
        )
        .expect("preflight intent")
    }

    #[test]
    fn prepared_plan_is_reserved_before_approval() {
        let intent = intent();
        let receipt = RescueFstabPreparedPlanReceipt::new(
            intent.clone(),
            hash('1'),
            hash('a'),
            hash('b'),
            "vault-01",
            "B-backup-01",
            hash('6'),
            "vault://repair/B-backup-01",
            hash('7'),
            format!("recovery:{}", "a".repeat(64)),
            hash('8'),
            hash('9'),
            4096,
            8192,
            "lock:f589",
            RESCUE_FSTAB_READY_OUTCOME,
        )
        .expect("prepared plan receipt");

        assert_eq!(receipt.intent(), &intent);
        assert_eq!(receipt.plan_hash(), hash('1'));
        assert_eq!(receipt.before_sha256(), hash('3'));
        assert_eq!(receipt.after_sha256(), hash('a'));
        assert_eq!(receipt.diff_sha256(), hash('b'));
        assert_eq!(receipt.reservation_id(), "B-backup-01");
        assert_eq!(receipt.backup_locator(), "vault://repair/B-backup-01");
        assert_eq!(
            receipt.target_recovery_fingerprint(),
            format!("recovery:{}", "a".repeat(64))
        );
        assert_eq!(receipt.outcome(), RESCUE_FSTAB_READY_OUTCOME);

        assert_eq!(
            RescueFstabPreparedPlanReceipt::new(
                intent,
                hash('1'),
                hash('3'),
                hash('b'),
                "vault-01",
                "B-backup-01",
                hash('6'),
                "vault://repair/B-backup-01",
                hash('7'),
                format!("recovery:{}", "a".repeat(64)),
                hash('8'),
                hash('9'),
                4096,
                8192,
                "lock:f589",
                RESCUE_FSTAB_READY_OUTCOME,
            ),
            Err(RescueRepairProtocolError::InvalidHash)
        );
    }

    #[test]
    fn evidence_is_exact_ordered_and_hash_bound() {
        assert_eq!(
            RescueFstabEvidenceBinding::new("E-LINUX-RAW", hash('a')),
            Err(RescueRepairProtocolError::InvalidEvidenceId)
        );
        assert_eq!(
            RescueFstabEvidenceBinding::new("E-LINUX-FSTAB", "sha256:ABC"),
            Err(RescueRepairProtocolError::InvalidHash)
        );
        let canonical = evidence();
        let reversed = [canonical[1].clone(), canonical[0].clone()];
        assert_eq!(
            RescueFstabPreflightIntent::new(
                "S-rescue",
                "P-fstab",
                hash('2'),
                hash('3'),
                RESCUE_FSTAB_RESOURCE_ID,
                "target-01",
                scan('6'),
                reversed,
            ),
            Err(RescueRepairProtocolError::InvalidEvidenceOrder)
        );
    }

    #[test]
    fn intent_rejects_path_command_and_identity_drift() {
        for forbidden_target in ["/dev/sda2", "../../target", "target;mount", "rm -rf"] {
            assert_eq!(
                RescueFstabPreflightIntent::new(
                    "S-rescue",
                    "P-fstab",
                    hash('2'),
                    hash('3'),
                    RESCUE_FSTAB_RESOURCE_ID,
                    forbidden_target,
                    scan('6'),
                    evidence(),
                ),
                Err(RescueRepairProtocolError::InvalidTargetId)
            );
        }
        assert_eq!(
            RescueFstabPreflightIntent::new(
                "S-rescue",
                "P-fstab",
                hash('2'),
                hash('3'),
                "rescue:selected-linux-root:etc/shadow",
                "target-01",
                scan('6'),
                evidence(),
            ),
            Err(RescueRepairProtocolError::InvalidResourceId)
        );
    }
}
