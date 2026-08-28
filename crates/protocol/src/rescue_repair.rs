//! Closed, path-free protocol objects for the disabled Rescue `fstab` preflight.
//!
//! These values carry only opaque identifiers and deterministic fingerprints.
//! They contain no path, device name, command, observed bytes, replacement
//! bytes, file descriptor or I/O capability. Constructing a value performs all
//! validation; the module deliberately provides no execution operation.

use std::fmt;

pub const RESCUE_FSTAB_RESOURCE_ID: &str = "rescue:selected-linux-root:etc/fstab";
pub const RESCUE_FSTAB_TYPED_CONFIRMATION: &str = "DISABILITA VOCE FSTAB";
pub const RESCUE_FSTAB_EVIDENCE_IDS: [&str; 2] = ["E-LINUX-FSTAB", "E-LINUX-LSBLK"];
pub const RESCUE_FSTAB_READY_OUTCOME: &str = "ready-read-only";

const MAX_PREFIXED_ID_BYTES: usize = 128;
const MAX_OPAQUE_ID_BYTES: usize = 96;
const VAULT_LOCATOR_PREFIX: &str = "vault://repair/";

/// Sanitized fail-closed failures. No variant carries caller-controlled text.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RescueRepairProtocolError {
    InvalidSessionId,
    InvalidPlanId,
    InvalidHash,
    InvalidResourceId,
    InvalidTargetId,
    InvalidScanFingerprint,
    InvalidApprovalId,
    InvalidApprovalSequence,
    InvalidTypedConfirmation,
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
    RequestBindingDrift,
}

impl fmt::Display for RescueRepairProtocolError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::InvalidSessionId => "invalid Rescue repair session identifier",
            Self::InvalidPlanId => "invalid Rescue repair plan identifier",
            Self::InvalidHash => "invalid Rescue repair hash",
            Self::InvalidResourceId => "invalid Rescue repair resource identifier",
            Self::InvalidTargetId => "invalid Rescue repair target identifier",
            Self::InvalidScanFingerprint => "invalid Rescue repair scan fingerprint",
            Self::InvalidApprovalId => "invalid Rescue repair approval identifier",
            Self::InvalidApprovalSequence => "invalid Rescue repair approval sequence",
            Self::InvalidTypedConfirmation => "invalid Rescue repair typed confirmation",
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
            Self::RequestBindingDrift => "Rescue repair request binding drift",
        })
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

/// Complete request admitted at the root-broker preflight boundary.
///
/// Private fields make the shape closed: callers cannot append a path,
/// command, raw observation or replacement payload to an admitted request.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RescueFstabPreflightRequest {
    session_id: String,
    plan_id: String,
    plan_hash: String,
    target_fingerprint: String,
    target_snapshot: String,
    resource_id: String,
    target_id: String,
    scan_fingerprint: String,
    approval_id: String,
    approval_sequence: u64,
    typed_confirmation: String,
    evidence: [RescueFstabEvidenceBinding; 2],
}

impl RescueFstabPreflightRequest {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        session_id: impl Into<String>,
        plan_id: impl Into<String>,
        plan_hash: impl Into<String>,
        target_fingerprint: impl Into<String>,
        target_snapshot: impl Into<String>,
        resource_id: impl Into<String>,
        target_id: impl Into<String>,
        scan_fingerprint: impl Into<String>,
        approval_id: impl Into<String>,
        approval_sequence: u64,
        typed_confirmation: impl Into<String>,
        evidence: [RescueFstabEvidenceBinding; 2],
    ) -> Result<Self, RescueRepairProtocolError> {
        let request = Self {
            session_id: session_id.into(),
            plan_id: plan_id.into(),
            plan_hash: plan_hash.into(),
            target_fingerprint: target_fingerprint.into(),
            target_snapshot: target_snapshot.into(),
            resource_id: resource_id.into(),
            target_id: target_id.into(),
            scan_fingerprint: scan_fingerprint.into(),
            approval_id: approval_id.into(),
            approval_sequence,
            typed_confirmation: typed_confirmation.into(),
            evidence,
        };
        request.validate()?;
        Ok(request)
    }

    fn validate(&self) -> Result<(), RescueRepairProtocolError> {
        if !valid_prefixed_id(&self.session_id, "S-") {
            return Err(RescueRepairProtocolError::InvalidSessionId);
        }
        if !valid_prefixed_id(&self.plan_id, "P-") {
            return Err(RescueRepairProtocolError::InvalidPlanId);
        }
        if !valid_sha256(&self.plan_hash)
            || !valid_sha256(&self.target_fingerprint)
            || !valid_sha256(&self.target_snapshot)
        {
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
        if !valid_prefixed_id(&self.approval_id, "A-") {
            return Err(RescueRepairProtocolError::InvalidApprovalId);
        }
        if self.approval_sequence == 0 {
            return Err(RescueRepairProtocolError::InvalidApprovalSequence);
        }
        if self.typed_confirmation != RESCUE_FSTAB_TYPED_CONFIRMATION {
            return Err(RescueRepairProtocolError::InvalidTypedConfirmation);
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
    pub fn plan_hash(&self) -> &str {
        &self.plan_hash
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
    pub fn approval_id(&self) -> &str {
        &self.approval_id
    }
    pub const fn approval_sequence(&self) -> u64 {
        self.approval_sequence
    }
    pub fn typed_confirmation(&self) -> &str {
        &self.typed_confirmation
    }
    pub fn evidence(&self) -> &[RescueFstabEvidenceBinding; 2] {
        &self.evidence
    }
}

/// Successful read-only preflight audit evidence.
///
/// This value is cloneable and publicly reconstructible for transport, so it
/// deliberately grants no execution authority. Only the broker-owned,
/// non-cloneable prepared object that retains the Core admission, target lock
/// and Vault reservation may authorize a later executor. The receipt owns the
/// exact validated request for correlation, and the reservation binding is
/// minted from a pre-plan draft rather than the final plan hash to avoid a
/// circular Vault capability definition.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RescueFstabPreflightReceipt {
    request: RescueFstabPreflightRequest,
    vault_id: String,
    reservation_id: String,
    reservation_binding_sha256: String,
    backup_locator: String,
    vault_identity_fingerprint: String,
    target_physical_parent_fingerprint: String,
    vault_physical_parent_fingerprint: String,
    required_capacity_bytes: u64,
    reserved_capacity_bytes: u64,
    lock_identity: String,
    outcome: String,
}

impl RescueFstabPreflightReceipt {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        request: RescueFstabPreflightRequest,
        vault_id: impl Into<String>,
        reservation_id: impl Into<String>,
        reservation_binding_sha256: impl Into<String>,
        backup_locator: impl Into<String>,
        vault_identity_fingerprint: impl Into<String>,
        target_physical_parent_fingerprint: impl Into<String>,
        vault_physical_parent_fingerprint: impl Into<String>,
        required_capacity_bytes: u64,
        reserved_capacity_bytes: u64,
        lock_identity: impl Into<String>,
        outcome: impl Into<String>,
    ) -> Result<Self, RescueRepairProtocolError> {
        request.validate()?;
        let receipt = Self {
            request,
            vault_id: vault_id.into(),
            reservation_id: reservation_id.into(),
            reservation_binding_sha256: reservation_binding_sha256.into(),
            backup_locator: backup_locator.into(),
            vault_identity_fingerprint: vault_identity_fingerprint.into(),
            target_physical_parent_fingerprint: target_physical_parent_fingerprint.into(),
            vault_physical_parent_fingerprint: vault_physical_parent_fingerprint.into(),
            required_capacity_bytes,
            reserved_capacity_bytes,
            lock_identity: lock_identity.into(),
            outcome: outcome.into(),
        };
        if !valid_opaque_id(&receipt.vault_id) {
            return Err(RescueRepairProtocolError::InvalidVaultId);
        }
        if !valid_prefixed_id(&receipt.reservation_id, "B-") {
            return Err(RescueRepairProtocolError::InvalidReservationId);
        }
        if !valid_sha256(&receipt.reservation_binding_sha256) {
            return Err(RescueRepairProtocolError::InvalidReservationBinding);
        }
        if !valid_vault_locator(&receipt.backup_locator)
            || receipt.backup_locator.strip_prefix(VAULT_LOCATOR_PREFIX)
                != Some(receipt.reservation_id.as_str())
        {
            return Err(RescueRepairProtocolError::InvalidVaultLocator);
        }
        if !valid_sha256(&receipt.vault_identity_fingerprint) {
            return Err(RescueRepairProtocolError::InvalidVaultIdentity);
        }
        if !valid_sha256(&receipt.target_physical_parent_fingerprint)
            || !valid_sha256(&receipt.vault_physical_parent_fingerprint)
        {
            return Err(RescueRepairProtocolError::InvalidPhysicalParent);
        }
        if receipt.target_physical_parent_fingerprint == receipt.vault_physical_parent_fingerprint {
            return Err(RescueRepairProtocolError::PhysicalParentsNotDistinct);
        }
        if receipt.required_capacity_bytes == 0 || receipt.reserved_capacity_bytes == 0 {
            return Err(RescueRepairProtocolError::InvalidCapacity);
        }
        if receipt.reserved_capacity_bytes < receipt.required_capacity_bytes {
            return Err(RescueRepairProtocolError::InsufficientCapacity);
        }
        if !valid_opaque_id(&receipt.lock_identity) {
            return Err(RescueRepairProtocolError::InvalidLockIdentity);
        }
        if receipt.outcome != RESCUE_FSTAB_READY_OUTCOME {
            return Err(RescueRepairProtocolError::InvalidOutcome);
        }
        Ok(receipt)
    }

    /// Correlates audit evidence with the exact admitted request. A successful
    /// comparison does not grant execution authority.
    pub fn validate_request_binding(
        &self,
        request: &RescueFstabPreflightRequest,
    ) -> Result<(), RescueRepairProtocolError> {
        if &self.request != request {
            return Err(RescueRepairProtocolError::RequestBindingDrift);
        }
        request.validate()
    }

    pub fn request(&self) -> &RescueFstabPreflightRequest {
        &self.request
    }
    pub fn session_id(&self) -> &str {
        self.request.session_id()
    }
    pub fn plan_id(&self) -> &str {
        self.request.plan_id()
    }
    pub fn plan_hash(&self) -> &str {
        self.request.plan_hash()
    }
    pub fn target_fingerprint(&self) -> &str {
        self.request.target_fingerprint()
    }
    pub fn target_snapshot(&self) -> &str {
        self.request.target_snapshot()
    }
    pub fn resource_id(&self) -> &str {
        self.request.resource_id()
    }
    pub fn target_id(&self) -> &str {
        self.request.target_id()
    }
    pub fn scan_fingerprint(&self) -> &str {
        self.request.scan_fingerprint()
    }
    pub fn approval_id(&self) -> &str {
        self.request.approval_id()
    }
    pub const fn approval_sequence(&self) -> u64 {
        self.request.approval_sequence()
    }
    pub fn typed_confirmation(&self) -> &str {
        self.request.typed_confirmation()
    }
    pub fn evidence(&self) -> &[RescueFstabEvidenceBinding; 2] {
        self.request.evidence()
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

    fn evidence() -> [RescueFstabEvidenceBinding; 2] {
        [
            RescueFstabEvidenceBinding::new(RESCUE_FSTAB_EVIDENCE_IDS[0], hash('4'))
                .expect("fstab evidence"),
            RescueFstabEvidenceBinding::new(RESCUE_FSTAB_EVIDENCE_IDS[1], hash('5'))
                .expect("lsblk evidence"),
        ]
    }

    fn request_with(
        resource_id: &str,
        target_id: &str,
        approval_sequence: u64,
        confirmation: &str,
        evidence: [RescueFstabEvidenceBinding; 2],
    ) -> Result<RescueFstabPreflightRequest, RescueRepairProtocolError> {
        RescueFstabPreflightRequest::new(
            "S-rescue",
            "P-fstab",
            hash('1'),
            hash('2'),
            hash('3'),
            resource_id,
            target_id,
            scan('6'),
            "A-local",
            approval_sequence,
            confirmation,
            evidence,
        )
    }

    fn request() -> RescueFstabPreflightRequest {
        request_with(
            RESCUE_FSTAB_RESOURCE_ID,
            "target-01",
            7,
            RESCUE_FSTAB_TYPED_CONFIRMATION,
            evidence(),
        )
        .expect("request")
    }

    #[test]
    fn canonical_request_and_read_only_receipt_bind_every_claim() {
        let request = request();
        let receipt = RescueFstabPreflightReceipt::new(
            request.clone(),
            "vault-01",
            "B-backup-01",
            hash('6'),
            "vault://repair/B-backup-01",
            hash('7'),
            hash('8'),
            hash('9'),
            4096,
            8192,
            "lock:f589",
            RESCUE_FSTAB_READY_OUTCOME,
        )
        .expect("receipt");

        assert_eq!(receipt.session_id(), "S-rescue");
        assert_eq!(receipt.plan_id(), "P-fstab");
        assert_eq!(receipt.plan_hash(), hash('1'));
        assert_eq!(receipt.target_fingerprint(), hash('2'));
        assert_eq!(receipt.target_snapshot(), hash('3'));
        assert_eq!(receipt.resource_id(), RESCUE_FSTAB_RESOURCE_ID);
        assert_eq!(receipt.target_id(), "target-01");
        assert_eq!(receipt.scan_fingerprint(), scan('6'));
        assert_eq!(receipt.approval_id(), "A-local");
        assert_eq!(receipt.approval_sequence(), 7);
        assert_eq!(
            receipt.typed_confirmation(),
            RESCUE_FSTAB_TYPED_CONFIRMATION
        );
        assert_eq!(receipt.evidence()[0].evidence_id(), "E-LINUX-FSTAB");
        assert_eq!(receipt.evidence()[1].evidence_id(), "E-LINUX-LSBLK");
        assert_eq!(receipt.vault_id(), "vault-01");
        assert_eq!(receipt.reservation_id(), "B-backup-01");
        assert_eq!(receipt.reservation_binding_sha256(), hash('6'));
        assert_eq!(receipt.backup_locator(), "vault://repair/B-backup-01");
        assert_eq!(receipt.vault_identity_fingerprint(), hash('7'));
        assert_eq!(receipt.target_physical_parent_fingerprint(), hash('8'));
        assert_eq!(receipt.vault_physical_parent_fingerprint(), hash('9'));
        assert_eq!(receipt.required_capacity_bytes(), 4096);
        assert_eq!(receipt.reserved_capacity_bytes(), 8192);
        assert_eq!(receipt.lock_identity(), "lock:f589");
        assert_eq!(receipt.outcome(), "ready-read-only");
        assert_eq!(receipt.validate_request_binding(&request), Ok(()));
    }

    #[test]
    fn request_rejects_identity_hash_approval_and_contract_drift() {
        assert_eq!(
            RescueFstabPreflightRequest::new(
                "session",
                "P-fstab",
                hash('1'),
                hash('2'),
                hash('3'),
                RESCUE_FSTAB_RESOURCE_ID,
                "target-01",
                scan('6'),
                "A-local",
                7,
                RESCUE_FSTAB_TYPED_CONFIRMATION,
                evidence(),
            ),
            Err(RescueRepairProtocolError::InvalidSessionId)
        );
        assert_eq!(
            RescueFstabPreflightRequest::new(
                "S-rescue",
                "P-fstab",
                "sha256:bad",
                hash('2'),
                hash('3'),
                RESCUE_FSTAB_RESOURCE_ID,
                "target-01",
                scan('6'),
                "A-local",
                7,
                RESCUE_FSTAB_TYPED_CONFIRMATION,
                evidence(),
            ),
            Err(RescueRepairProtocolError::InvalidHash)
        );
        assert_eq!(
            request_with(
                "rescue:selected-linux-root:etc/shadow",
                "target-01",
                7,
                RESCUE_FSTAB_TYPED_CONFIRMATION,
                evidence(),
            ),
            Err(RescueRepairProtocolError::InvalidResourceId)
        );
        assert_eq!(
            request_with(
                RESCUE_FSTAB_RESOURCE_ID,
                "target-01",
                0,
                RESCUE_FSTAB_TYPED_CONFIRMATION,
                evidence(),
            ),
            Err(RescueRepairProtocolError::InvalidApprovalSequence)
        );
        assert_eq!(
            request_with(
                RESCUE_FSTAB_RESOURCE_ID,
                "target-01",
                7,
                "disabilita voce fstab",
                evidence(),
            ),
            Err(RescueRepairProtocolError::InvalidTypedConfirmation)
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
            request_with(
                RESCUE_FSTAB_RESOURCE_ID,
                "target-01",
                7,
                RESCUE_FSTAB_TYPED_CONFIRMATION,
                reversed,
            ),
            Err(RescueRepairProtocolError::InvalidEvidenceOrder)
        );
    }

    #[test]
    fn path_command_and_non_read_only_receipt_forms_fail_closed() {
        for forbidden_target in ["/dev/sda2", "../../target", "target;mount", "rm -rf"] {
            assert_eq!(
                request_with(
                    RESCUE_FSTAB_RESOURCE_ID,
                    forbidden_target,
                    7,
                    RESCUE_FSTAB_TYPED_CONFIRMATION,
                    evidence(),
                ),
                Err(RescueRepairProtocolError::InvalidTargetId)
            );
        }

        let reservation = |reservation_id: &str, binding: String| {
            RescueFstabPreflightReceipt::new(
                request(),
                "vault-01",
                reservation_id,
                binding,
                "vault://repair/B-backup",
                hash('7'),
                hash('8'),
                hash('9'),
                1,
                2,
                "lock:1",
                RESCUE_FSTAB_READY_OUTCOME,
            )
        };
        assert_eq!(
            reservation("reservation-without-type", hash('6')),
            Err(RescueRepairProtocolError::InvalidReservationId)
        );
        assert_eq!(
            reservation("B-backup", "sha256:bad".into()),
            Err(RescueRepairProtocolError::InvalidReservationBinding)
        );

        let make = |locator: &str,
                    target_parent: String,
                    vault_parent: String,
                    required,
                    reserved,
                    lock: &str,
                    outcome: &str| {
            RescueFstabPreflightReceipt::new(
                request(),
                "vault-01",
                "B-backup",
                hash('6'),
                locator,
                hash('7'),
                target_parent,
                vault_parent,
                required,
                reserved,
                lock,
                outcome,
            )
        };
        assert_eq!(
            make(
                "/boot/vault/backup",
                hash('8'),
                hash('9'),
                1,
                2,
                "lock:1",
                RESCUE_FSTAB_READY_OUTCOME
            ),
            Err(RescueRepairProtocolError::InvalidVaultLocator)
        );
        assert_eq!(
            make(
                "vault://repair/../../fstab",
                hash('8'),
                hash('9'),
                1,
                2,
                "lock:1",
                RESCUE_FSTAB_READY_OUTCOME
            ),
            Err(RescueRepairProtocolError::InvalidVaultLocator)
        );
        assert_eq!(
            make(
                "vault://repair/B-backup",
                hash('8'),
                hash('8'),
                1,
                2,
                "lock:1",
                RESCUE_FSTAB_READY_OUTCOME
            ),
            Err(RescueRepairProtocolError::PhysicalParentsNotDistinct)
        );
        assert_eq!(
            make(
                "vault://repair/B-backup",
                hash('8'),
                hash('9'),
                3,
                2,
                "lock:1",
                RESCUE_FSTAB_READY_OUTCOME
            ),
            Err(RescueRepairProtocolError::InsufficientCapacity)
        );
        assert_eq!(
            make(
                "vault://repair/B-backup",
                hash('8'),
                hash('9'),
                1,
                2,
                "/run/lock",
                RESCUE_FSTAB_READY_OUTCOME
            ),
            Err(RescueRepairProtocolError::InvalidLockIdentity)
        );
        assert_eq!(
            make(
                "vault://repair/B-backup",
                hash('8'),
                hash('9'),
                1,
                2,
                "lock:1",
                "ready-read-write"
            ),
            Err(RescueRepairProtocolError::InvalidOutcome)
        );
    }

    #[test]
    fn receipt_detects_any_request_binding_drift() {
        let original = request();
        let receipt = RescueFstabPreflightReceipt::new(
            original.clone(),
            "vault-01",
            "B-backup-01",
            hash('6'),
            "vault://repair/B-backup-01",
            hash('7'),
            hash('8'),
            hash('9'),
            1,
            2,
            "lock:1",
            RESCUE_FSTAB_READY_OUTCOME,
        )
        .expect("receipt");
        let drifted = RescueFstabPreflightRequest::new(
            "S-rescue",
            "P-other",
            hash('1'),
            hash('2'),
            hash('3'),
            RESCUE_FSTAB_RESOURCE_ID,
            "target-01",
            scan('6'),
            "A-local",
            7,
            RESCUE_FSTAB_TYPED_CONFIRMATION,
            evidence(),
        )
        .expect("drifted request");
        assert_eq!(
            receipt.validate_request_binding(&drifted),
            Err(RescueRepairProtocolError::RequestBindingDrift)
        );
    }
}
