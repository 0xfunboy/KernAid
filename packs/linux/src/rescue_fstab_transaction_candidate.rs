//! Immutable admission bindings for the disabled Rescue `fstab` candidate.
//!
//! This is deliberately not an executor or broker handler. It binds a future
//! Core R2 plan to broker-resolved opaque capabilities and deterministic
//! evidence. No path, command, file descriptor, replacement bytes or I/O cross
//! this contract.

use crate::{
    production_candidate_contract::{
        ACTION_ID, BACKUP_PHYSICAL_PARENT_POLICY, BACKUP_POLICY_ID, CANCELLATION_POLICY_ID,
        FINDING_ID, FINDING_VERSION, IDEMPOTENCY_POLICY_ID, PREFLIGHT_ID, REDACTION_POLICY_ID,
        RESOURCE_ID, ROLLBACK_ID, SUPPORTED_FILESYSTEM, TRANSACTION_TIMEOUT_MILLISECONDS,
        VALIDATE_ID,
    },
    rescue_fstab_candidate::DisableMissingUuidPreview,
};
use sha2::{Digest, Sha256};

const PLAN_HASH_DOMAIN: &[u8] =
    b"kernaid:linux.fstab.disable-missing-uuid.v1:transaction-plan:v2\0";
const MAX_ID_BYTES: usize = 128;
const MAX_OPAQUE_BYTES: usize = 96;

pub const RISK_ID: &str = "R2";
pub const FSTAB_EVIDENCE_ID: &str = "E-LINUX-FSTAB";
pub const LSBLK_EVIDENCE_ID: &str = "E-LINUX-LSBLK";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CandidateTransactionError {
    InvalidCapability,
    InvalidSessionId,
    InvalidPlanId,
    InvalidScanFingerprint,
    InvalidFingerprint,
    PlanContractMismatch,
    InvalidEvidenceBinding,
    EvidenceSetMismatch,
    InvalidVaultLocator,
    VaultNotAuthenticated,
    InvalidVaultCapacity,
    VaultCapacityInsufficient,
    PhysicalDeviceNotDistinct,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SelectedTargetCapability {
    target_id: String,
    scan_fingerprint: String,
    physical_parent_fingerprint: String,
}

impl SelectedTargetCapability {
    pub fn new(
        target_id: impl Into<String>,
        scan_fingerprint: impl Into<String>,
        physical_parent_fingerprint: impl Into<String>,
    ) -> Result<Self, CandidateTransactionError> {
        let value = Self {
            target_id: target_id.into(),
            scan_fingerprint: scan_fingerprint.into(),
            physical_parent_fingerprint: physical_parent_fingerprint.into(),
        };
        if !valid_opaque_id(&value.target_id) {
            return Err(CandidateTransactionError::InvalidCapability);
        }
        if !valid_scan_fingerprint(&value.scan_fingerprint) {
            return Err(CandidateTransactionError::InvalidScanFingerprint);
        }
        if !valid_sha256(&value.physical_parent_fingerprint) {
            return Err(CandidateTransactionError::InvalidFingerprint);
        }
        Ok(value)
    }

    pub fn target_id(&self) -> &str {
        &self.target_id
    }
    pub fn scan_fingerprint(&self) -> &str {
        &self.scan_fingerprint
    }
    pub fn physical_parent_fingerprint(&self) -> &str {
        &self.physical_parent_fingerprint
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BootVaultBackupCapability {
    vault_id: String,
    backup_locator: String,
    vault_identity_fingerprint: String,
    physical_parent_fingerprint: String,
    authenticated_and_unlocked: bool,
    required_capacity_bytes: u64,
    available_capacity_bytes: u64,
}

impl BootVaultBackupCapability {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        vault_id: impl Into<String>,
        backup_locator: impl Into<String>,
        vault_identity_fingerprint: impl Into<String>,
        physical_parent_fingerprint: impl Into<String>,
        authenticated_and_unlocked: bool,
        required_capacity_bytes: u64,
        available_capacity_bytes: u64,
    ) -> Result<Self, CandidateTransactionError> {
        let value = Self {
            vault_id: vault_id.into(),
            backup_locator: backup_locator.into(),
            vault_identity_fingerprint: vault_identity_fingerprint.into(),
            physical_parent_fingerprint: physical_parent_fingerprint.into(),
            authenticated_and_unlocked,
            required_capacity_bytes,
            available_capacity_bytes,
        };
        if !valid_opaque_id(&value.vault_id) {
            return Err(CandidateTransactionError::InvalidCapability);
        }
        if !valid_vault_locator(&value.backup_locator) {
            return Err(CandidateTransactionError::InvalidVaultLocator);
        }
        if !valid_sha256(&value.vault_identity_fingerprint)
            || !valid_sha256(&value.physical_parent_fingerprint)
        {
            return Err(CandidateTransactionError::InvalidFingerprint);
        }
        if !value.authenticated_and_unlocked {
            return Err(CandidateTransactionError::VaultNotAuthenticated);
        }
        if value.required_capacity_bytes == 0 || value.available_capacity_bytes == 0 {
            return Err(CandidateTransactionError::InvalidVaultCapacity);
        }
        if value.available_capacity_bytes < value.required_capacity_bytes {
            return Err(CandidateTransactionError::VaultCapacityInsufficient);
        }
        Ok(value)
    }

    pub fn vault_id(&self) -> &str {
        &self.vault_id
    }
    pub fn backup_locator(&self) -> &str {
        &self.backup_locator
    }
    pub fn vault_identity_fingerprint(&self) -> &str {
        &self.vault_identity_fingerprint
    }
    pub fn physical_parent_fingerprint(&self) -> &str {
        &self.physical_parent_fingerprint
    }
    pub const fn authenticated_and_unlocked(&self) -> bool {
        self.authenticated_and_unlocked
    }
    pub const fn required_capacity_bytes(&self) -> u64 {
        self.required_capacity_bytes
    }
    pub const fn available_capacity_bytes(&self) -> u64 {
        self.available_capacity_bytes
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CandidateEvidenceBinding {
    evidence_id: String,
    sha256: String,
}

impl CandidateEvidenceBinding {
    pub fn new(
        evidence_id: impl Into<String>,
        sha256: impl Into<String>,
    ) -> Result<Self, CandidateTransactionError> {
        let value = Self {
            evidence_id: evidence_id.into(),
            sha256: sha256.into(),
        };
        if !valid_evidence_id(&value.evidence_id) {
            return Err(CandidateTransactionError::InvalidEvidenceBinding);
        }
        if !valid_sha256(&value.sha256) {
            return Err(CandidateTransactionError::InvalidFingerprint);
        }
        Ok(value)
    }

    pub fn evidence_id(&self) -> &str {
        &self.evidence_id
    }
    pub fn sha256(&self) -> &str {
        &self.sha256
    }
}

/// Claims arriving at the admission boundary. All fields must match the sole
/// candidate contract exactly; only session and plan identifiers vary.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CandidatePlanClaimsInput<'a> {
    pub session_id: &'a str,
    pub plan_id: &'a str,
    pub action_id: &'a str,
    pub resource_id: &'a str,
    pub finding_id: &'a str,
    pub finding_version: u16,
    pub risk: &'a str,
    pub supported_filesystem: &'a str,
    pub preflight_id: &'a str,
    pub backup_policy_id: &'a str,
    pub backup_physical_parent_policy: &'a str,
    pub validation_id: &'a str,
    pub rollback_id: &'a str,
    pub timeout_milliseconds: u64,
    pub cancellation_policy_id: &'a str,
    pub idempotency_policy_id: &'a str,
    pub redaction_policy_id: &'a str,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CandidatePlanClaims {
    session_id: String,
    plan_id: String,
    action_id: String,
    resource_id: String,
    finding_id: String,
    finding_version: u16,
    risk: String,
    supported_filesystem: String,
    preflight_id: String,
    backup_policy_id: String,
    backup_physical_parent_policy: String,
    validation_id: String,
    rollback_id: String,
    timeout_milliseconds: u64,
    cancellation_policy_id: String,
    idempotency_policy_id: String,
    redaction_policy_id: String,
}

impl CandidatePlanClaims {
    pub fn admit(input: CandidatePlanClaimsInput<'_>) -> Result<Self, CandidateTransactionError> {
        if !valid_prefixed_id(input.session_id, "S-") {
            return Err(CandidateTransactionError::InvalidSessionId);
        }
        if !valid_prefixed_id(input.plan_id, "P-") {
            return Err(CandidateTransactionError::InvalidPlanId);
        }
        if input.action_id != ACTION_ID
            || input.resource_id != RESOURCE_ID
            || input.finding_id != FINDING_ID
            || input.finding_version != FINDING_VERSION
            || input.risk != RISK_ID
            || input.supported_filesystem != SUPPORTED_FILESYSTEM
            || input.preflight_id != PREFLIGHT_ID
            || input.backup_policy_id != BACKUP_POLICY_ID
            || input.backup_physical_parent_policy != BACKUP_PHYSICAL_PARENT_POLICY
            || input.validation_id != VALIDATE_ID
            || input.rollback_id != ROLLBACK_ID
            || input.timeout_milliseconds != TRANSACTION_TIMEOUT_MILLISECONDS
            || input.cancellation_policy_id != CANCELLATION_POLICY_ID
            || input.idempotency_policy_id != IDEMPOTENCY_POLICY_ID
            || input.redaction_policy_id != REDACTION_POLICY_ID
        {
            return Err(CandidateTransactionError::PlanContractMismatch);
        }
        Ok(Self {
            session_id: input.session_id.into(),
            plan_id: input.plan_id.into(),
            action_id: input.action_id.into(),
            resource_id: input.resource_id.into(),
            finding_id: input.finding_id.into(),
            finding_version: input.finding_version,
            risk: input.risk.into(),
            supported_filesystem: input.supported_filesystem.into(),
            preflight_id: input.preflight_id.into(),
            backup_policy_id: input.backup_policy_id.into(),
            backup_physical_parent_policy: input.backup_physical_parent_policy.into(),
            validation_id: input.validation_id.into(),
            rollback_id: input.rollback_id.into(),
            timeout_milliseconds: input.timeout_milliseconds,
            cancellation_policy_id: input.cancellation_policy_id.into(),
            idempotency_policy_id: input.idempotency_policy_id.into(),
            redaction_policy_id: input.redaction_policy_id.into(),
        })
    }

    pub fn session_id(&self) -> &str {
        &self.session_id
    }
    pub fn plan_id(&self) -> &str {
        &self.plan_id
    }
    pub fn action_id(&self) -> &str {
        &self.action_id
    }
    pub fn resource_id(&self) -> &str {
        &self.resource_id
    }
    pub fn finding_id(&self) -> &str {
        &self.finding_id
    }
    pub const fn finding_version(&self) -> u16 {
        self.finding_version
    }
    pub fn risk(&self) -> &str {
        &self.risk
    }
    pub fn supported_filesystem(&self) -> &str {
        &self.supported_filesystem
    }
    pub fn preflight_id(&self) -> &str {
        &self.preflight_id
    }
    pub fn backup_policy_id(&self) -> &str {
        &self.backup_policy_id
    }
    pub fn backup_physical_parent_policy(&self) -> &str {
        &self.backup_physical_parent_policy
    }
    pub fn validation_id(&self) -> &str {
        &self.validation_id
    }
    pub fn rollback_id(&self) -> &str {
        &self.rollback_id
    }
    pub const fn timeout_milliseconds(&self) -> u64 {
        self.timeout_milliseconds
    }
    pub fn cancellation_policy_id(&self) -> &str {
        &self.cancellation_policy_id
    }
    pub fn idempotency_policy_id(&self) -> &str {
        &self.idempotency_policy_id
    }
    pub fn redaction_policy_id(&self) -> &str {
        &self.redaction_policy_id
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FstabCandidateTransactionPlan {
    plan_sha256: String,
    claims: CandidatePlanClaims,
    target: SelectedTargetCapability,
    vault: BootVaultBackupCapability,
    evidence: [CandidateEvidenceBinding; 2],
    before_sha256: String,
    observed_uuid_set_sha256: String,
    after_sha256: String,
    diff_sha256: String,
}

impl FstabCandidateTransactionPlan {
    pub fn stage(
        preview: &DisableMissingUuidPreview,
        claims: CandidatePlanClaims,
        target: SelectedTargetCapability,
        vault: BootVaultBackupCapability,
        evidence: Vec<CandidateEvidenceBinding>,
    ) -> Result<Self, CandidateTransactionError> {
        if target.physical_parent_fingerprint == vault.physical_parent_fingerprint {
            return Err(CandidateTransactionError::PhysicalDeviceNotDistinct);
        }
        let minimum_capacity = u64::try_from(preview.proposed_fstab().len())
            .map_err(|_| CandidateTransactionError::InvalidVaultCapacity)?;
        if vault.required_capacity_bytes < minimum_capacity {
            return Err(CandidateTransactionError::InvalidVaultCapacity);
        }
        let evidence: [CandidateEvidenceBinding; 2] = evidence
            .try_into()
            .map_err(|_| CandidateTransactionError::EvidenceSetMismatch)?;
        if evidence[0].evidence_id != FSTAB_EVIDENCE_ID
            || evidence[1].evidence_id != LSBLK_EVIDENCE_ID
        {
            return Err(CandidateTransactionError::EvidenceSetMismatch);
        }

        let mut plan = Self {
            plan_sha256: String::new(),
            claims,
            target,
            vault,
            evidence,
            before_sha256: preview.before_sha256().into(),
            observed_uuid_set_sha256: preview.observed_uuid_set_sha256().into(),
            after_sha256: preview.after_sha256().into(),
            diff_sha256: preview.diff_sha256().into(),
        };
        plan.plan_sha256 = plan.compute_hash();
        Ok(plan)
    }

    fn compute_hash(&self) -> String {
        let mut digest = Sha256::new();
        digest.update(PLAN_HASH_DOMAIN);
        for value in [
            self.claims.session_id.as_str(),
            self.claims.plan_id.as_str(),
            self.claims.action_id.as_str(),
            self.claims.resource_id.as_str(),
            self.claims.finding_id.as_str(),
        ] {
            hash_string(&mut digest, value);
        }
        digest.update(self.claims.finding_version.to_be_bytes());
        for value in [
            self.claims.risk.as_str(),
            self.claims.supported_filesystem.as_str(),
            self.claims.preflight_id.as_str(),
            self.claims.backup_policy_id.as_str(),
            self.claims.backup_physical_parent_policy.as_str(),
            self.claims.validation_id.as_str(),
            self.claims.rollback_id.as_str(),
        ] {
            hash_string(&mut digest, value);
        }
        digest.update(self.claims.timeout_milliseconds.to_be_bytes());
        hash_string(&mut digest, &self.claims.cancellation_policy_id);
        hash_string(&mut digest, &self.claims.idempotency_policy_id);
        hash_string(&mut digest, &self.claims.redaction_policy_id);
        for value in [
            self.target.target_id.as_str(),
            self.target.scan_fingerprint.as_str(),
            self.target.physical_parent_fingerprint.as_str(),
            self.vault.vault_id.as_str(),
            self.vault.backup_locator.as_str(),
            self.vault.vault_identity_fingerprint.as_str(),
            self.vault.physical_parent_fingerprint.as_str(),
        ] {
            hash_string(&mut digest, value);
        }
        digest.update([u8::from(self.vault.authenticated_and_unlocked)]);
        digest.update(self.vault.required_capacity_bytes.to_be_bytes());
        digest.update(self.vault.available_capacity_bytes.to_be_bytes());
        for binding in &self.evidence {
            hash_string(&mut digest, &binding.evidence_id);
            hash_string(&mut digest, &binding.sha256);
        }
        for value in [
            self.before_sha256.as_str(),
            self.observed_uuid_set_sha256.as_str(),
            self.after_sha256.as_str(),
            self.diff_sha256.as_str(),
        ] {
            hash_string(&mut digest, value);
        }
        format!("sha256:{:x}", digest.finalize())
    }

    pub fn plan_sha256(&self) -> &str {
        &self.plan_sha256
    }
    pub fn claims(&self) -> &CandidatePlanClaims {
        &self.claims
    }
    pub fn target(&self) -> &SelectedTargetCapability {
        &self.target
    }
    pub fn vault(&self) -> &BootVaultBackupCapability {
        &self.vault
    }
    pub fn evidence(&self) -> &[CandidateEvidenceBinding; 2] {
        &self.evidence
    }
    pub fn before_sha256(&self) -> &str {
        &self.before_sha256
    }
    pub fn observed_uuid_set_sha256(&self) -> &str {
        &self.observed_uuid_set_sha256
    }
    pub fn after_sha256(&self) -> &str {
        &self.after_sha256
    }
    pub fn diff_sha256(&self) -> &str {
        &self.diff_sha256
    }
}

fn hash_string(digest: &mut Sha256, value: &str) {
    digest.update((value.len() as u64).to_be_bytes());
    digest.update(value.as_bytes());
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
    value.len() <= MAX_ID_BYTES
        && value.strip_prefix(prefix).is_some_and(|suffix| {
            !suffix.is_empty()
                && suffix
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
        })
}

fn valid_opaque_id(value: &str) -> bool {
    (1..=MAX_OPAQUE_BYTES).contains(&value.len())
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b':' | b'.'))
        && !value.contains("..")
}

fn valid_evidence_id(value: &str) -> bool {
    value.len() <= MAX_OPAQUE_BYTES
        && value.strip_prefix("E-").is_some_and(|suffix| {
            !suffix.is_empty()
                && suffix
                    .bytes()
                    .all(|byte| byte.is_ascii_uppercase() || byte.is_ascii_digit() || byte == b'-')
        })
}

fn valid_vault_locator(value: &str) -> bool {
    value.len() <= 128
        && value.strip_prefix("vault://repair/").is_some_and(|suffix| {
            !suffix.is_empty()
                && suffix.len() <= 64
                && suffix
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
        })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rescue_fstab_candidate::preview_disable_missing_uuid;
    use std::collections::BTreeSet;

    fn hash(c: char) -> String {
        format!("sha256:{}", c.to_string().repeat(64))
    }
    fn scan(c: char) -> String {
        format!("scan:{}", c.to_string().repeat(64))
    }
    fn preview() -> DisableMissingUuidPreview {
        preview_disable_missing_uuid(
            b"UUID=AAAA-BBBB / ext4 defaults 0 1\nUUID=DEAD-BEEF /srv/archive ext4 defaults 0 2\n",
            &BTreeSet::from(["aaaa-bbbb".into()]),
        )
        .expect("preview")
    }
    fn input<'a>() -> CandidatePlanClaimsInput<'a> {
        CandidatePlanClaimsInput {
            session_id: "S-rescue",
            plan_id: "P-fstab",
            action_id: ACTION_ID,
            resource_id: RESOURCE_ID,
            finding_id: FINDING_ID,
            finding_version: FINDING_VERSION,
            risk: RISK_ID,
            supported_filesystem: SUPPORTED_FILESYSTEM,
            preflight_id: PREFLIGHT_ID,
            backup_policy_id: BACKUP_POLICY_ID,
            backup_physical_parent_policy: BACKUP_PHYSICAL_PARENT_POLICY,
            validation_id: VALIDATE_ID,
            rollback_id: ROLLBACK_ID,
            timeout_milliseconds: TRANSACTION_TIMEOUT_MILLISECONDS,
            cancellation_policy_id: CANCELLATION_POLICY_ID,
            idempotency_policy_id: IDEMPOTENCY_POLICY_ID,
            redaction_policy_id: REDACTION_POLICY_ID,
        }
    }
    fn claims() -> CandidatePlanClaims {
        CandidatePlanClaims::admit(input()).expect("claims")
    }
    fn target(scan_hash: char, parent: char) -> SelectedTargetCapability {
        SelectedTargetCapability::new("target-01", scan(scan_hash), hash(parent)).expect("target")
    }
    fn vault(
        locator: &str,
        identity: char,
        parent: char,
        required: u64,
        available: u64,
    ) -> BootVaultBackupCapability {
        BootVaultBackupCapability::new(
            "vault-01",
            locator,
            hash(identity),
            hash(parent),
            true,
            required,
            available,
        )
        .expect("vault")
    }
    fn evidence(a: char, b: char) -> Vec<CandidateEvidenceBinding> {
        vec![
            CandidateEvidenceBinding::new(FSTAB_EVIDENCE_ID, hash(a)).expect("fstab"),
            CandidateEvidenceBinding::new(LSBLK_EVIDENCE_ID, hash(b)).expect("lsblk"),
        ]
    }
    fn stage() -> FstabCandidateTransactionPlan {
        FstabCandidateTransactionPlan::stage(
            &preview(),
            claims(),
            target('1', 'a'),
            vault("vault://repair/B-before", '2', 'b', 4096, 8192),
            evidence('3', '4'),
        )
        .expect("stage")
    }

    #[test]
    fn canonical_plan_is_deterministic_and_all_bindings_are_visible() {
        let plan = stage();
        assert_eq!(plan, stage());
        assert!(valid_sha256(plan.plan_sha256()));
        assert_eq!(plan.claims().session_id(), "S-rescue");
        assert_eq!(plan.claims().plan_id(), "P-fstab");
        assert_eq!(plan.claims().action_id(), ACTION_ID);
        assert_eq!(plan.claims().resource_id(), RESOURCE_ID);
        assert_eq!(plan.claims().finding_id(), FINDING_ID);
        assert_eq!(plan.claims().finding_version(), FINDING_VERSION);
        assert_eq!(plan.claims().risk(), RISK_ID);
        assert_eq!(plan.claims().supported_filesystem(), SUPPORTED_FILESYSTEM);
        assert_eq!(plan.claims().preflight_id(), PREFLIGHT_ID);
        assert_eq!(plan.claims().backup_policy_id(), BACKUP_POLICY_ID);
        assert_eq!(
            plan.claims().backup_physical_parent_policy(),
            BACKUP_PHYSICAL_PARENT_POLICY
        );
        assert_eq!(plan.claims().validation_id(), VALIDATE_ID);
        assert_eq!(plan.claims().rollback_id(), ROLLBACK_ID);
        assert_eq!(
            plan.claims().timeout_milliseconds(),
            TRANSACTION_TIMEOUT_MILLISECONDS
        );
        assert_eq!(
            plan.claims().cancellation_policy_id(),
            CANCELLATION_POLICY_ID
        );
        assert_eq!(plan.claims().idempotency_policy_id(), IDEMPOTENCY_POLICY_ID);
        assert_eq!(plan.claims().redaction_policy_id(), REDACTION_POLICY_ID);
        assert_eq!(plan.target().target_id(), "target-01");
        assert_eq!(plan.target().scan_fingerprint(), scan('1'));
        assert_eq!(plan.target().physical_parent_fingerprint(), hash('a'));
        assert_eq!(plan.vault().vault_id(), "vault-01");
        assert_eq!(plan.vault().backup_locator(), "vault://repair/B-before");
        assert_eq!(plan.vault().vault_identity_fingerprint(), hash('2'));
        assert_eq!(plan.vault().physical_parent_fingerprint(), hash('b'));
        assert!(plan.vault().authenticated_and_unlocked());
        assert_eq!(plan.vault().required_capacity_bytes(), 4096);
        assert_eq!(plan.vault().available_capacity_bytes(), 8192);
        assert_eq!(plan.evidence()[0].evidence_id(), FSTAB_EVIDENCE_ID);
        assert_eq!(plan.evidence()[0].sha256(), hash('3'));
        assert_eq!(plan.evidence()[1].evidence_id(), LSBLK_EVIDENCE_ID);
        assert_eq!(plan.evidence()[1].sha256(), hash('4'));
        assert_eq!(plan.before_sha256(), preview().before_sha256());
        assert_eq!(
            plan.observed_uuid_set_sha256(),
            preview().observed_uuid_set_sha256()
        );
        assert_eq!(plan.after_sha256(), preview().after_sha256());
        assert_eq!(plan.diff_sha256(), preview().diff_sha256());
    }

    #[test]
    fn ids_and_real_scan_fingerprint_are_strict() {
        for bad in ["", "S-", "session", "S-under_score", "S-path/x"] {
            let mut value = input();
            value.session_id = bad;
            assert_eq!(
                CandidatePlanClaims::admit(value),
                Err(CandidateTransactionError::InvalidSessionId)
            );
        }
        for bad in ["", "P-", "plan", "P-under_score", "P-path/x"] {
            let mut value = input();
            value.plan_id = bad;
            assert_eq!(
                CandidatePlanClaims::admit(value),
                Err(CandidateTransactionError::InvalidPlanId)
            );
        }
        for bad in [hash('1'), "scan:abcd".into(), scan('A'), scan('g')] {
            assert_eq!(
                SelectedTargetCapability::new("target", bad, hash('a')),
                Err(CandidateTransactionError::InvalidScanFingerprint)
            );
        }
        assert_eq!(
            SelectedTargetCapability::new("/dev/sda2", scan('1'), hash('a')),
            Err(CandidateTransactionError::InvalidCapability)
        );
    }

    #[test]
    fn every_contract_drift_is_rejected_and_hash_bound() {
        macro_rules! reject {
            ($field:ident, $value:expr) => {{
                let mut value = input();
                value.$field = $value;
                assert_eq!(
                    CandidatePlanClaims::admit(value),
                    Err(CandidateTransactionError::PlanContractMismatch),
                    "{}",
                    stringify!($field)
                );
            }};
        }
        reject!(action_id, "other.action");
        reject!(resource_id, "other-resource");
        reject!(finding_id, "KA-LNX-P0-004");
        reject!(finding_version, FINDING_VERSION + 1);
        reject!(risk, "R1");
        reject!(supported_filesystem, "xfs");
        reject!(preflight_id, "other.preflight");
        reject!(backup_policy_id, "other.backup");
        reject!(backup_physical_parent_policy, "same-device");
        reject!(validation_id, "other.validation");
        reject!(rollback_id, "other.rollback");
        reject!(timeout_milliseconds, TRANSACTION_TIMEOUT_MILLISECONDS - 1);
        reject!(cancellation_policy_id, "other.cancellation");
        reject!(idempotency_policy_id, "other.idempotency");
        reject!(redaction_policy_id, "other.redaction");

        let plan = stage();
        let original = plan.compute_hash();
        macro_rules! bound {
            ($field:ident, $value:expr) => {{
                let mut changed = plan.clone();
                changed.claims.$field = $value;
                assert_ne!(original, changed.compute_hash(), "{}", stringify!($field));
            }};
        }
        bound!(session_id, "S-other".into());
        bound!(plan_id, "P-other".into());
        bound!(action_id, "other.action".into());
        bound!(resource_id, "other-resource".into());
        bound!(finding_id, "KA-LNX-P0-004".into());
        bound!(finding_version, FINDING_VERSION + 1);
        bound!(risk, "R3".into());
        bound!(supported_filesystem, "xfs".into());
        bound!(preflight_id, "other.preflight".into());
        bound!(backup_policy_id, "other.backup".into());
        bound!(backup_physical_parent_policy, "same-device".into());
        bound!(validation_id, "other.validation".into());
        bound!(rollback_id, "other.rollback".into());
        bound!(timeout_milliseconds, TRANSACTION_TIMEOUT_MILLISECONDS + 1);
        bound!(cancellation_policy_id, "other.cancel".into());
        bound!(idempotency_policy_id, "other.idempotency".into());
        bound!(redaction_policy_id, "other.redaction".into());
    }

    #[test]
    fn evidence_list_is_exact_canonical_and_hash_bound() {
        let base = stage();
        let changed = FstabCandidateTransactionPlan::stage(
            &preview(),
            claims(),
            target('1', 'a'),
            vault("vault://repair/B-before", '2', 'b', 4096, 8192),
            evidence('5', '4'),
        )
        .expect("changed evidence");
        assert_ne!(base.plan_sha256(), changed.plan_sha256());

        let mut reversed = evidence('3', '4');
        reversed.reverse();
        for bad in [reversed, evidence('3', '4')[..1].to_vec()] {
            assert_eq!(
                FstabCandidateTransactionPlan::stage(
                    &preview(),
                    claims(),
                    target('1', 'a'),
                    vault("vault://repair/B-before", '2', 'b', 4096, 8192),
                    bad,
                ),
                Err(CandidateTransactionError::EvidenceSetMismatch)
            );
        }
        let wrong = vec![
            CandidateEvidenceBinding::new("E-LINUX-OTHER", hash('3')).expect("other"),
            CandidateEvidenceBinding::new(LSBLK_EVIDENCE_ID, hash('4')).expect("lsblk"),
        ];
        assert_eq!(
            FstabCandidateTransactionPlan::stage(
                &preview(),
                claims(),
                target('1', 'a'),
                vault("vault://repair/B-before", '2', 'b', 4096, 8192),
                wrong,
            ),
            Err(CandidateTransactionError::EvidenceSetMismatch)
        );
        assert_eq!(
            CandidateEvidenceBinding::new("E-linux-fstab", hash('3')),
            Err(CandidateTransactionError::InvalidEvidenceBinding)
        );
        assert_eq!(
            CandidateEvidenceBinding::new(FSTAB_EVIDENCE_ID, "sha256:bad"),
            Err(CandidateTransactionError::InvalidFingerprint)
        );
    }

    #[test]
    fn vault_is_opaque_sized_authenticated_and_on_a_distinct_parent() {
        let make = |locator, unlocked, required, available| {
            BootVaultBackupCapability::new(
                "vault",
                locator,
                hash('2'),
                hash('b'),
                unlocked,
                required,
                available,
            )
        };
        assert_eq!(
            make("/boot/vault/file", true, 4096, 8192),
            Err(CandidateTransactionError::InvalidVaultLocator)
        );
        assert_eq!(
            make("vault://repair/../../file", true, 4096, 8192),
            Err(CandidateTransactionError::InvalidVaultLocator)
        );
        assert_eq!(
            make("vault://repair/B-before", false, 4096, 8192),
            Err(CandidateTransactionError::VaultNotAuthenticated)
        );
        assert_eq!(
            make("vault://repair/B-before", true, 0, 8192),
            Err(CandidateTransactionError::InvalidVaultCapacity)
        );
        assert_eq!(
            make("vault://repair/B-before", true, 8192, 4096),
            Err(CandidateTransactionError::VaultCapacityInsufficient)
        );
        assert_eq!(
            FstabCandidateTransactionPlan::stage(
                &preview(),
                claims(),
                target('1', 'a'),
                vault("vault://repair/B-before", '2', 'a', 4096, 8192),
                evidence('3', '4'),
            ),
            Err(CandidateTransactionError::PhysicalDeviceNotDistinct)
        );
        assert_eq!(
            FstabCandidateTransactionPlan::stage(
                &preview(),
                claims(),
                target('1', 'a'),
                vault("vault://repair/B-before", '2', 'b', 1, 8192),
                evidence('3', '4'),
            ),
            Err(CandidateTransactionError::InvalidVaultCapacity)
        );
    }

    #[test]
    fn target_vault_capacity_evidence_and_preview_drift_change_hash() {
        let base = stage();
        let variants = [
            (
                target('5', 'a'),
                vault("vault://repair/B-before", '2', 'b', 4096, 8192),
                evidence('3', '4'),
            ),
            (
                target('1', 'c'),
                vault("vault://repair/B-before", '2', 'b', 4096, 8192),
                evidence('3', '4'),
            ),
            (
                target('1', 'a'),
                vault("vault://repair/B-other", '2', 'b', 4096, 8192),
                evidence('3', '4'),
            ),
            (
                target('1', 'a'),
                vault("vault://repair/B-before", '5', 'b', 4096, 8192),
                evidence('3', '4'),
            ),
            (
                target('1', 'a'),
                vault("vault://repair/B-before", '2', 'c', 4096, 8192),
                evidence('3', '4'),
            ),
            (
                target('1', 'a'),
                vault("vault://repair/B-before", '2', 'b', 4097, 8192),
                evidence('3', '4'),
            ),
            (
                target('1', 'a'),
                vault("vault://repair/B-before", '2', 'b', 4096, 8193),
                evidence('3', '4'),
            ),
            (
                target('1', 'a'),
                vault("vault://repair/B-before", '2', 'b', 4096, 8192),
                evidence('5', '4'),
            ),
        ];
        for (target, vault, evidence) in variants {
            let changed =
                FstabCandidateTransactionPlan::stage(&preview(), claims(), target, vault, evidence)
                    .expect("drift plan");
            assert_ne!(base.plan_sha256(), changed.plan_sha256());
        }

        let changed_preview = preview_disable_missing_uuid(
            b"# changed\nUUID=AAAA-BBBB / ext4 defaults 0 1\nUUID=DEAD-BEEF /srv/archive ext4 defaults 0 2\n",
            &BTreeSet::from(["aaaa-bbbb".into()]),
        )
        .expect("changed preview");
        let changed = FstabCandidateTransactionPlan::stage(
            &changed_preview,
            claims(),
            target('1', 'a'),
            vault("vault://repair/B-before", '2', 'b', 4096, 8192),
            evidence('3', '4'),
        )
        .expect("changed preview plan");
        assert_ne!(base.plan_sha256(), changed.plan_sha256());
    }
}
