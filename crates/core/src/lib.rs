#![forbid(unsafe_code)]
use kernaid_evidence::{
    Evidence,
    linux_snapshot::{
        COLLECTOR as LINUX_SNAPSHOT_COLLECTOR, CONTENT_TYPE as LINUX_SNAPSHOT_CONTENT_TYPE,
        LinuxNormalizedSnapshotEnvelope, SnapshotError,
    },
};
#[cfg(feature = "fixture-repair-lab")]
use kernaid_policy::validate_fixture_repair_lab_plan as validate_fixture_repair_lab_policy;
use kernaid_policy::{PolicyError, validate_phase_zero};
#[cfg(feature = "rescue-crypttab-production-candidate")]
use kernaid_policy::{
    RESCUE_CRYPTTAB_ACTION_ID, RESCUE_CRYPTTAB_RESOURCE_ID,
    validate_rescue_crypttab_production_candidate_plan as validate_rescue_crypttab_candidate_policy,
};
#[cfg(feature = "rescue-fstab-production-candidate")]
use kernaid_policy::{
    RESCUE_FSTAB_ACTION_ID, RESCUE_FSTAB_EVIDENCE_IDS, RESCUE_FSTAB_FINDING_ID,
    RESCUE_FSTAB_FINDING_VERSION, RESCUE_FSTAB_RESOURCE_ID, RESCUE_FSTAB_ROLLBACK_BACKUP,
    RESCUE_FSTAB_ROLLBACK_EVIDENCE_ID, RESCUE_FSTAB_ROLLBACK_ID,
    RESCUE_FSTAB_ROLLBACK_PREFLIGHT_ID, RESCUE_FSTAB_VALIDATION_ID,
    validate_rescue_fstab_production_candidate_plan as validate_rescue_fstab_candidate_policy,
    validate_rescue_fstab_rollback_plan as validate_rescue_fstab_rollback_policy,
};
use kernaid_protocol::ValidatedPlan;
use sha2::{Digest, Sha256};
use std::{collections::HashSet, error::Error, fmt};

/// Apply Core's closed admission boundary to the one disposable-fixture plan.
/// The broker calls this same entry point before returning a staged R2 plan.
#[cfg(feature = "fixture-repair-lab")]
pub fn validate_fixture_repair_lab_plan(
    plan: &ValidatedPlan,
    target_fingerprint: &str,
) -> Result<(), PolicyError> {
    validate_fixture_repair_lab_policy(plan, target_fingerprint)
}

/// Apply Core's admission-only boundary to the disabled Rescue `fstab`
/// production candidate. This validates metadata and cannot dispatch a broker
/// action or touch a filesystem.
#[cfg(feature = "rescue-fstab-production-candidate")]
pub fn validate_rescue_fstab_production_candidate_plan(
    plan: &ValidatedPlan,
    target_fingerprint: &str,
) -> Result<(), PolicyError> {
    validate_rescue_fstab_candidate_policy(plan, target_fingerprint)
}

/// Apply Core's admission boundary to the separately approved post-commit
/// rollback. This validates bindings only and grants no write authority.
#[cfg(feature = "rescue-fstab-production-candidate")]
pub fn validate_rescue_fstab_rollback_plan(
    plan: &ValidatedPlan,
    target_fingerprint: &str,
) -> Result<(), PolicyError> {
    validate_rescue_fstab_rollback_policy(plan, target_fingerprint)
}

#[cfg(feature = "rescue-crypttab-production-candidate")]
pub const RESCUE_CRYPTTAB_TYPED_CONFIRMATION: &str = "DISABILITA VOCE CRYPTTAB";

/// Apply Core's admission-only boundary to the off-default crypttab plan.
#[cfg(feature = "rescue-crypttab-production-candidate")]
pub fn validate_rescue_crypttab_production_candidate_plan(
    plan: &ValidatedPlan,
    target_fingerprint: &str,
) -> Result<(), PolicyError> {
    validate_rescue_crypttab_candidate_policy(plan, target_fingerprint)
}

/// Immutable broker-derived identity for one exact crypttab preview. Action
/// and resource are compile-time pinned and cannot be supplied by a caller.
#[cfg(feature = "rescue-crypttab-production-candidate")]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RescueCrypttabCandidateBinding {
    session_id: String,
    plan_id: String,
    plan_sha256: String,
    target_fingerprint: String,
    target_snapshot: String,
}

#[cfg(feature = "rescue-crypttab-production-candidate")]
impl RescueCrypttabCandidateBinding {
    pub fn new(
        session_id: impl Into<String>,
        plan_id: impl Into<String>,
        plan_sha256: impl Into<String>,
        target_fingerprint: impl Into<String>,
        target_snapshot: impl Into<String>,
    ) -> Result<Self, RescueCrypttabAdmissionError> {
        let value = Self {
            session_id: session_id.into(),
            plan_id: plan_id.into(),
            plan_sha256: plan_sha256.into(),
            target_fingerprint: target_fingerprint.into(),
            target_snapshot: target_snapshot.into(),
        };
        if !valid_crypttab_id(&value.session_id, "S-")
            || !valid_crypttab_id(&value.plan_id, "P-")
            || !valid_crypttab_hash(&value.plan_sha256)
            || !valid_crypttab_hash(&value.target_fingerprint)
            || !valid_crypttab_hash(&value.target_snapshot)
        {
            return Err(RescueCrypttabAdmissionError::InvalidBinding);
        }
        Ok(value)
    }
    pub fn session_id(&self) -> &str {
        &self.session_id
    }
    pub fn plan_id(&self) -> &str {
        &self.plan_id
    }
    pub fn plan_sha256(&self) -> &str {
        &self.plan_sha256
    }
    pub fn target_fingerprint(&self) -> &str {
        &self.target_fingerprint
    }
    pub fn target_snapshot(&self) -> &str {
        &self.target_snapshot
    }
    pub const fn action_id(&self) -> &'static str {
        RESCUE_CRYPTTAB_ACTION_ID
    }
    pub const fn resource_id(&self) -> &'static str {
        RESCUE_CRYPTTAB_RESOURCE_ID
    }
}

#[cfg(feature = "rescue-crypttab-production-candidate")]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RescueCrypttabCandidateApproval {
    approval_id: String,
    sequence: u64,
    binding: RescueCrypttabCandidateBinding,
    typed_confirmation: String,
}

#[cfg(feature = "rescue-crypttab-production-candidate")]
impl RescueCrypttabCandidateApproval {
    pub fn new(
        approval_id: impl Into<String>,
        sequence: u64,
        binding: RescueCrypttabCandidateBinding,
        typed_confirmation: impl Into<String>,
    ) -> Result<Self, RescueCrypttabAdmissionError> {
        let value = Self {
            approval_id: approval_id.into(),
            sequence,
            binding,
            typed_confirmation: typed_confirmation.into(),
        };
        if !valid_crypttab_id(&value.approval_id, "A-") || value.sequence == 0 {
            return Err(RescueCrypttabAdmissionError::InvalidApproval);
        }
        Ok(value)
    }
}

#[cfg(feature = "rescue-crypttab-production-candidate")]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RescueCrypttabAdmissionState {
    Staged,
    Approved,
}

#[cfg(feature = "rescue-crypttab-production-candidate")]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RescueCrypttabCandidateAdmission {
    binding: RescueCrypttabCandidateBinding,
    state: RescueCrypttabAdmissionState,
    approval_id: Option<String>,
}

#[cfg(feature = "rescue-crypttab-production-candidate")]
impl RescueCrypttabCandidateAdmission {
    pub fn stage(
        plan: &ValidatedPlan,
        binding: RescueCrypttabCandidateBinding,
    ) -> Result<Self, RescueCrypttabAdmissionError> {
        validate_rescue_crypttab_candidate_policy(plan, binding.target_fingerprint())
            .map_err(|_| RescueCrypttabAdmissionError::PolicyRejected)?;
        if plan.plan_id != binding.plan_id || plan.target_fingerprint != binding.target_fingerprint
        {
            return Err(RescueCrypttabAdmissionError::BindingMismatch);
        }
        Ok(Self {
            binding,
            state: RescueCrypttabAdmissionState::Staged,
            approval_id: None,
        })
    }

    pub fn approve(
        &mut self,
        approval: RescueCrypttabCandidateApproval,
    ) -> Result<(), RescueCrypttabAdmissionError> {
        if self.state != RescueCrypttabAdmissionState::Staged || self.approval_id.is_some() {
            return Err(RescueCrypttabAdmissionError::ApprovalReplay);
        }
        if approval.binding != self.binding || approval.sequence != 1 {
            return Err(RescueCrypttabAdmissionError::BindingMismatch);
        }
        if approval.typed_confirmation != RESCUE_CRYPTTAB_TYPED_CONFIRMATION {
            return Err(RescueCrypttabAdmissionError::WrongConfirmation);
        }
        self.approval_id = Some(approval.approval_id);
        self.state = RescueCrypttabAdmissionState::Approved;
        Ok(())
    }

    pub const fn state(&self) -> RescueCrypttabAdmissionState {
        self.state
    }
    pub fn binding(&self) -> &RescueCrypttabCandidateBinding {
        &self.binding
    }
    pub fn approval_id(&self) -> Option<&str> {
        self.approval_id.as_deref()
    }
}

#[cfg(feature = "rescue-crypttab-production-candidate")]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RescueCrypttabAdmissionError {
    InvalidBinding,
    InvalidApproval,
    PolicyRejected,
    BindingMismatch,
    WrongConfirmation,
    ApprovalReplay,
}

#[cfg(feature = "rescue-crypttab-production-candidate")]
fn valid_crypttab_id(value: &str, prefix: &str) -> bool {
    value.strip_prefix(prefix).is_some_and(|suffix| {
        !suffix.is_empty()
            && value.len() <= 128
            && suffix
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
    })
}

#[cfg(feature = "rescue-crypttab-production-candidate")]
fn valid_crypttab_hash(value: &str) -> bool {
    value.strip_prefix("sha256:").is_some_and(|digest| {
        digest.len() == 64
            && digest
                .bytes()
                .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
    })
}

/// Immutable broker-derived bindings for one fixture-only R2 mutation.
///
/// This type is deliberately available only in the disposable fixture build.
/// Callers cannot change any binding after staging, and every later transition
/// must present the same values again.
#[cfg(feature = "fixture-repair-lab")]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FixtureMutationBinding {
    plan_id: String,
    plan_hash: String,
    target_snapshot: String,
    resource_id: String,
    resource_precondition: String,
}

#[cfg(feature = "fixture-repair-lab")]
impl FixtureMutationBinding {
    pub fn new(
        plan_id: impl Into<String>,
        plan_hash: impl Into<String>,
        target_snapshot: impl Into<String>,
        resource_id: impl Into<String>,
        resource_precondition: impl Into<String>,
    ) -> Result<Self, FixtureTransactionError> {
        let binding = Self {
            plan_id: plan_id.into(),
            plan_hash: plan_hash.into(),
            target_snapshot: target_snapshot.into(),
            resource_id: resource_id.into(),
            resource_precondition: resource_precondition.into(),
        };
        if !valid_fixture_identifier(&binding.plan_id)
            || !valid_fixture_sha256(&binding.plan_hash)
            || !valid_fixture_sha256(&binding.target_snapshot)
            || !valid_fixture_identifier(&binding.resource_id)
            || !valid_fixture_sha256(&binding.resource_precondition)
        {
            return Err(FixtureTransactionError::InvalidBinding);
        }
        Ok(binding)
    }

    pub fn plan_id(&self) -> &str {
        &self.plan_id
    }

    pub fn plan_hash(&self) -> &str {
        &self.plan_hash
    }

    pub fn target_snapshot(&self) -> &str {
        &self.target_snapshot
    }

    pub fn resource_id(&self) -> &str {
        &self.resource_id
    }

    pub fn resource_precondition(&self) -> &str {
        &self.resource_precondition
    }
}

/// Complete immutable proof presented for approval and every later mutation
/// transition. The approval identifier and sequence become immutable on the
/// first successful `approve` call.
#[cfg(feature = "fixture-repair-lab")]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FixtureTransitionProof {
    mutation: FixtureMutationBinding,
    approval_id: String,
    approval_sequence: u64,
}

#[cfg(feature = "fixture-repair-lab")]
impl FixtureTransitionProof {
    pub fn new(
        mutation: FixtureMutationBinding,
        approval_id: impl Into<String>,
        approval_sequence: u64,
    ) -> Result<Self, FixtureTransactionError> {
        let proof = Self {
            mutation,
            approval_id: approval_id.into(),
            approval_sequence,
        };
        if !valid_fixture_identifier(&proof.approval_id) || proof.approval_sequence == 0 {
            return Err(FixtureTransactionError::InvalidApproval);
        }
        Ok(proof)
    }

    pub fn mutation(&self) -> &FixtureMutationBinding {
        &self.mutation
    }

    pub fn approval_id(&self) -> &str {
        &self.approval_id
    }

    pub const fn approval_sequence(&self) -> u64 {
        self.approval_sequence
    }
}

#[cfg(feature = "fixture-repair-lab")]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FixtureVerificationOutcome {
    Succeeded,
    Failed,
}

#[cfg(feature = "fixture-repair-lab")]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FixtureRepairTransactionState {
    Staged,
    Approved,
    Repairing,
    Verified(FixtureVerificationOutcome),
    Complete(FixtureVerificationOutcome),
}

#[cfg(feature = "fixture-repair-lab")]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FixtureRollbackTransactionState {
    Staged,
    Approved,
    RollingBack,
    Verified(FixtureVerificationOutcome),
    Complete(FixtureVerificationOutcome),
}

#[cfg(feature = "fixture-repair-lab")]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FixtureTransactionError {
    InvalidBinding,
    InvalidApproval,
    InvalidTransition,
    BindingMismatch,
    ApprovalMismatch,
    RollbackApprovalNotDistinct,
}

#[cfg(feature = "fixture-repair-lab")]
impl fmt::Display for FixtureTransactionError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::InvalidBinding => "fixture transaction binding is invalid",
            Self::InvalidApproval => "fixture transaction approval is invalid",
            Self::InvalidTransition => "fixture transaction transition is invalid",
            Self::BindingMismatch => "fixture transaction binding changed after staging",
            Self::ApprovalMismatch => "fixture transaction approval changed after approval",
            Self::RollbackApprovalNotDistinct => "fixture rollback requires a distinct approval",
        })
    }
}

#[cfg(feature = "fixture-repair-lab")]
impl Error for FixtureTransactionError {}

#[cfg(feature = "fixture-repair-lab")]
#[derive(Clone, Debug, PartialEq, Eq)]
struct BoundFixtureTransaction {
    mutation: FixtureMutationBinding,
    approval_id: Option<String>,
    approval_sequence: Option<u64>,
}

#[cfg(feature = "fixture-repair-lab")]
impl BoundFixtureTransaction {
    fn staged(mutation: FixtureMutationBinding) -> Self {
        Self {
            mutation,
            approval_id: None,
            approval_sequence: None,
        }
    }

    fn approve(&mut self, proof: &FixtureTransitionProof) -> Result<(), FixtureTransactionError> {
        self.validate_mutation(proof)?;
        if self.approval_id.is_some() || self.approval_sequence.is_some() {
            return Err(FixtureTransactionError::InvalidTransition);
        }
        self.approval_id = Some(proof.approval_id.clone());
        self.approval_sequence = Some(proof.approval_sequence);
        Ok(())
    }

    fn validate_proof(
        &self,
        proof: &FixtureTransitionProof,
    ) -> Result<(), FixtureTransactionError> {
        self.validate_mutation(proof)?;
        if self.approval_id.as_deref() != Some(proof.approval_id.as_str())
            || self.approval_sequence != Some(proof.approval_sequence)
        {
            return Err(FixtureTransactionError::ApprovalMismatch);
        }
        Ok(())
    }

    fn validate_mutation(
        &self,
        proof: &FixtureTransitionProof,
    ) -> Result<(), FixtureTransactionError> {
        if self.mutation != proof.mutation {
            return Err(FixtureTransactionError::BindingMismatch);
        }
        Ok(())
    }
}

/// Feature-gated Core state machine for the disposable fixture repair.
#[cfg(feature = "fixture-repair-lab")]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FixtureRepairTransaction {
    bound: BoundFixtureTransaction,
    state: FixtureRepairTransactionState,
}

#[cfg(feature = "fixture-repair-lab")]
impl FixtureRepairTransaction {
    pub fn stage(mutation: FixtureMutationBinding) -> Self {
        Self {
            bound: BoundFixtureTransaction::staged(mutation),
            state: FixtureRepairTransactionState::Staged,
        }
    }

    pub const fn state(&self) -> FixtureRepairTransactionState {
        self.state
    }

    pub fn binding(&self) -> &FixtureMutationBinding {
        &self.bound.mutation
    }

    pub fn approval_id(&self) -> Option<&str> {
        self.bound.approval_id.as_deref()
    }

    pub const fn approval_sequence(&self) -> Option<u64> {
        self.bound.approval_sequence
    }

    pub fn approve(
        &mut self,
        proof: &FixtureTransitionProof,
    ) -> Result<(), FixtureTransactionError> {
        if self.state != FixtureRepairTransactionState::Staged {
            return Err(FixtureTransactionError::InvalidTransition);
        }
        self.bound.approve(proof)?;
        self.state = FixtureRepairTransactionState::Approved;
        Ok(())
    }

    pub fn begin_repair(
        &mut self,
        proof: &FixtureTransitionProof,
    ) -> Result<(), FixtureTransactionError> {
        if self.state != FixtureRepairTransactionState::Approved {
            return Err(FixtureTransactionError::InvalidTransition);
        }
        self.bound.validate_proof(proof)?;
        self.state = FixtureRepairTransactionState::Repairing;
        Ok(())
    }

    pub fn record_verification(
        &mut self,
        proof: &FixtureTransitionProof,
        outcome: FixtureVerificationOutcome,
    ) -> Result<(), FixtureTransactionError> {
        if self.state != FixtureRepairTransactionState::Repairing {
            return Err(FixtureTransactionError::InvalidTransition);
        }
        self.bound.validate_proof(proof)?;
        self.state = FixtureRepairTransactionState::Verified(outcome);
        Ok(())
    }

    pub fn complete(
        &mut self,
        proof: &FixtureTransitionProof,
    ) -> Result<(), FixtureTransactionError> {
        let FixtureRepairTransactionState::Verified(outcome) = self.state else {
            return Err(FixtureTransactionError::InvalidTransition);
        };
        self.bound.validate_proof(proof)?;
        self.state = FixtureRepairTransactionState::Complete(outcome);
        Ok(())
    }
}

/// Feature-gated Core state machine for the separately approved rollback.
#[cfg(feature = "fixture-repair-lab")]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FixtureRollbackTransaction {
    bound: BoundFixtureTransaction,
    repair_approval_id: String,
    repair_plan_hash: String,
    state: FixtureRollbackTransactionState,
}

#[cfg(feature = "fixture-repair-lab")]
impl FixtureRollbackTransaction {
    pub fn stage(
        mutation: FixtureMutationBinding,
        repair_approval_id: impl Into<String>,
        repair_plan_hash: impl Into<String>,
    ) -> Result<Self, FixtureTransactionError> {
        let repair_approval_id = repair_approval_id.into();
        let repair_plan_hash = repair_plan_hash.into();
        if !valid_fixture_identifier(&repair_approval_id)
            || !valid_fixture_sha256(&repair_plan_hash)
        {
            return Err(FixtureTransactionError::InvalidBinding);
        }
        Ok(Self {
            bound: BoundFixtureTransaction::staged(mutation),
            repair_approval_id,
            repair_plan_hash,
            state: FixtureRollbackTransactionState::Staged,
        })
    }

    pub const fn state(&self) -> FixtureRollbackTransactionState {
        self.state
    }

    pub fn binding(&self) -> &FixtureMutationBinding {
        &self.bound.mutation
    }

    pub fn repair_approval_id(&self) -> &str {
        &self.repair_approval_id
    }

    pub fn repair_plan_hash(&self) -> &str {
        &self.repair_plan_hash
    }

    pub fn approve(
        &mut self,
        proof: &FixtureTransitionProof,
    ) -> Result<(), FixtureTransactionError> {
        if self.state != FixtureRollbackTransactionState::Staged {
            return Err(FixtureTransactionError::InvalidTransition);
        }
        if proof.approval_id == self.repair_approval_id {
            return Err(FixtureTransactionError::RollbackApprovalNotDistinct);
        }
        self.bound.approve(proof)?;
        self.state = FixtureRollbackTransactionState::Approved;
        Ok(())
    }

    pub fn begin_rollback(
        &mut self,
        proof: &FixtureTransitionProof,
    ) -> Result<(), FixtureTransactionError> {
        if self.state != FixtureRollbackTransactionState::Approved {
            return Err(FixtureTransactionError::InvalidTransition);
        }
        self.bound.validate_proof(proof)?;
        self.state = FixtureRollbackTransactionState::RollingBack;
        Ok(())
    }

    pub fn record_verification(
        &mut self,
        proof: &FixtureTransitionProof,
        outcome: FixtureVerificationOutcome,
    ) -> Result<(), FixtureTransactionError> {
        if self.state != FixtureRollbackTransactionState::RollingBack {
            return Err(FixtureTransactionError::InvalidTransition);
        }
        self.bound.validate_proof(proof)?;
        self.state = FixtureRollbackTransactionState::Verified(outcome);
        Ok(())
    }

    pub fn complete(
        &mut self,
        proof: &FixtureTransitionProof,
    ) -> Result<(), FixtureTransactionError> {
        let FixtureRollbackTransactionState::Verified(outcome) = self.state else {
            return Err(FixtureTransactionError::InvalidTransition);
        };
        self.bound.validate_proof(proof)?;
        self.state = FixtureRollbackTransactionState::Complete(outcome);
        Ok(())
    }
}

#[cfg(feature = "fixture-repair-lab")]
fn valid_fixture_sha256(value: &str) -> bool {
    value.strip_prefix("sha256:").is_some_and(|digest| {
        digest.len() == 64
            && digest
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    })
}

#[cfg(feature = "fixture-repair-lab")]
fn valid_fixture_identifier(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b':' | b'-'))
}

/// Exact local confirmation required by the disabled R2 candidate.
#[cfg(feature = "rescue-fstab-production-candidate")]
pub const RESCUE_FSTAB_TYPED_CONFIRMATION: &str = "DISABILITA VOCE FSTAB";

/// Exact confirmation for the separate post-commit rollback approval.
#[cfg(feature = "rescue-fstab-production-candidate")]
pub const RESCUE_FSTAB_ROLLBACK_TYPED_CONFIRMATION: &str = "RIPRISTINA FSTAB ORIGINALE";

#[cfg(feature = "rescue-fstab-production-candidate")]
const RESCUE_FSTAB_APPROVAL_HASH_DOMAIN: &[u8] =
    b"kernaid:linux.fstab.disable-missing-uuid.v1:approval:v1\0";

#[cfg(feature = "rescue-fstab-production-candidate")]
const RESCUE_FSTAB_ROLLBACK_APPROVAL_HASH_DOMAIN: &[u8] =
    b"kernaid:linux.fstab.restore:approval:v1\0";

#[cfg(feature = "rescue-fstab-production-candidate")]
const RESCUE_FSTAB_ROLLBACK_PLAN_HASH_DOMAIN: &[u8] = b"kernaid:linux.fstab.restore:plan:v1\0";

/// Reconstruct the sole rollback policy plan and its deterministic hash from
/// broker-owned IDs plus the authenticated source receipt selector. The hash
/// binds every plan field, the rollback child ID, and the exact source receipt.
#[cfg(feature = "rescue-fstab-production-candidate")]
pub fn canonical_rescue_fstab_rollback_plan(
    plan_id: &str,
    rollback_id: &str,
    target_fingerprint: &str,
    reservation_id: &str,
    transaction_binding_sha256: &str,
) -> Result<(ValidatedPlan, String), RescueFstabRollbackAdmissionError> {
    if !valid_rescue_candidate_id(plan_id, "P-")
        || !valid_rescue_candidate_id(rollback_id, "RB-")
        || !valid_rescue_candidate_sha256(target_fingerprint)
        || !valid_rescue_candidate_id(reservation_id, "B-")
        || !valid_rescue_candidate_sha256(transaction_binding_sha256)
    {
        return Err(RescueFstabRollbackAdmissionError::InvalidBinding);
    }
    let plan = ValidatedPlan {
        plan_id: plan_id.to_owned(),
        target_fingerprint: target_fingerprint.to_owned(),
        steps: vec![kernaid_protocol::ActionStep {
            action: RESCUE_FSTAB_ROLLBACK_ID.to_owned(),
            risk: kernaid_protocol::Risk::R2,
            target_fingerprint: target_fingerprint.to_owned(),
            evidence_ids: vec![RESCUE_FSTAB_ROLLBACK_EVIDENCE_ID.to_owned()],
            preconditions: vec![RESCUE_FSTAB_ROLLBACK_PREFLIGHT_ID.to_owned()],
            backup: Some(RESCUE_FSTAB_ROLLBACK_BACKUP.to_owned()),
            validation: RESCUE_FSTAB_VALIDATION_ID.to_owned(),
            rollback: None,
        }],
    };
    validate_rescue_fstab_rollback_policy(&plan, target_fingerprint)
        .map_err(RescueFstabRollbackAdmissionError::PolicyRejected)?;

    let mut digest = Sha256::new();
    digest.update(RESCUE_FSTAB_ROLLBACK_PLAN_HASH_DOMAIN);
    for value in [
        plan.plan_id.as_str(),
        plan.target_fingerprint.as_str(),
        RESCUE_FSTAB_ROLLBACK_ID,
        "R2",
        target_fingerprint,
        RESCUE_FSTAB_ROLLBACK_EVIDENCE_ID,
        RESCUE_FSTAB_ROLLBACK_PREFLIGHT_ID,
        RESCUE_FSTAB_ROLLBACK_BACKUP,
        RESCUE_FSTAB_VALIDATION_ID,
        "rollback:none",
        rollback_id,
        reservation_id,
        transaction_binding_sha256,
    ] {
        digest.update((value.len() as u64).to_be_bytes());
        digest.update(value.as_bytes());
    }
    Ok((plan, format!("sha256:{:x}", digest.finalize())))
}

/// Exact observation and contract binding produced by the candidate broker.
///
/// This is the feature-gated alternative to fabricating a general
/// `LinuxNormalizedSnapshot` for the narrowly scoped offline candidate.  Its
/// constructor admits only the one action/finding/resource/evidence set, and
/// the later `Session` transition still validates the canonical policy plan,
/// session target and complete plan binding before entering `Plan`.
#[cfg(feature = "rescue-fstab-production-candidate")]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RescueFstabBrokerDerivedEvidence {
    session_id: String,
    plan_id: String,
    plan_hash: String,
    target_fingerprint: String,
    target_snapshot: String,
    action_id: String,
    finding_id: String,
    finding_version: u16,
    resource_id: String,
    evidence: [(String, String); 2],
}

#[cfg(feature = "rescue-fstab-production-candidate")]
impl RescueFstabBrokerDerivedEvidence {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        session_id: impl Into<String>,
        plan_id: impl Into<String>,
        plan_hash: impl Into<String>,
        target_fingerprint: impl Into<String>,
        target_snapshot: impl Into<String>,
        action_id: impl Into<String>,
        finding_id: impl Into<String>,
        finding_version: u16,
        resource_id: impl Into<String>,
        evidence: [(String, String); 2],
    ) -> Result<Self, RescueFstabCandidateAdmissionError> {
        let binding = Self {
            session_id: session_id.into(),
            plan_id: plan_id.into(),
            plan_hash: plan_hash.into(),
            target_fingerprint: target_fingerprint.into(),
            target_snapshot: target_snapshot.into(),
            action_id: action_id.into(),
            finding_id: finding_id.into(),
            finding_version,
            resource_id: resource_id.into(),
            evidence,
        };
        if !valid_rescue_candidate_id(&binding.session_id, "S-")
            || !valid_rescue_candidate_id(&binding.plan_id, "P-")
            || !valid_rescue_candidate_sha256(&binding.plan_hash)
            || !valid_rescue_candidate_sha256(&binding.target_fingerprint)
            || !valid_rescue_candidate_sha256(&binding.target_snapshot)
            || binding.action_id != RESCUE_FSTAB_ACTION_ID
            || binding.finding_id != RESCUE_FSTAB_FINDING_ID
            || binding.finding_version != RESCUE_FSTAB_FINDING_VERSION
            || binding.resource_id != RESCUE_FSTAB_RESOURCE_ID
            || binding.evidence[0].0 != RESCUE_FSTAB_EVIDENCE_IDS[0]
            || binding.evidence[1].0 != RESCUE_FSTAB_EVIDENCE_IDS[1]
            || binding
                .evidence
                .iter()
                .any(|(_, hash)| !valid_rescue_candidate_sha256(hash))
        {
            return Err(RescueFstabCandidateAdmissionError::InvalidBrokerEvidence);
        }
        Ok(binding)
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
    pub fn action_id(&self) -> &str {
        &self.action_id
    }
    pub fn finding_id(&self) -> &str {
        &self.finding_id
    }
    pub const fn finding_version(&self) -> u16 {
        self.finding_version
    }
    pub fn resource_id(&self) -> &str {
        &self.resource_id
    }
    pub fn evidence(&self) -> &[(String, String); 2] {
        &self.evidence
    }
}

/// Immutable material admitted for the candidate approval transition.
#[cfg(feature = "rescue-fstab-production-candidate")]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RescueFstabCandidateBinding {
    session_id: String,
    plan_id: String,
    plan_hash: String,
    target_fingerprint: String,
    resource_precondition: String,
}

#[cfg(feature = "rescue-fstab-production-candidate")]
impl RescueFstabCandidateBinding {
    pub fn new(
        session_id: impl Into<String>,
        plan_id: impl Into<String>,
        plan_hash: impl Into<String>,
        target_fingerprint: impl Into<String>,
        resource_precondition: impl Into<String>,
    ) -> Result<Self, RescueFstabCandidateAdmissionError> {
        let binding = Self {
            session_id: session_id.into(),
            plan_id: plan_id.into(),
            plan_hash: plan_hash.into(),
            target_fingerprint: target_fingerprint.into(),
            resource_precondition: resource_precondition.into(),
        };
        if !valid_rescue_candidate_id(&binding.session_id, "S-")
            || !valid_rescue_candidate_id(&binding.plan_id, "P-")
            || !valid_rescue_candidate_sha256(&binding.plan_hash)
            || !valid_rescue_candidate_sha256(&binding.target_fingerprint)
            || !valid_rescue_candidate_sha256(&binding.resource_precondition)
        {
            return Err(RescueFstabCandidateAdmissionError::InvalidBinding);
        }
        Ok(binding)
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

    pub const fn resource_id(&self) -> &'static str {
        RESCUE_FSTAB_RESOURCE_ID
    }

    /// SHA-256 of the exact selected-root `fstab` snapshot that must still
    /// match before any later execution layer could write the resource.
    pub fn resource_precondition(&self) -> &str {
        &self.resource_precondition
    }

    /// Schema-aligned alias for [`Self::resource_precondition`].
    pub fn target_snapshot(&self) -> &str {
        self.resource_precondition()
    }
}

/// Caller-presented approval proof. Every mutable field is compared with the
/// immutable staged binding before the approval state can advance.
#[cfg(feature = "rescue-fstab-production-candidate")]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RescueFstabCandidateApproval {
    binding: RescueFstabCandidateBinding,
    approval_id: String,
    approval_sequence: u64,
    typed_confirmation: String,
}

#[cfg(feature = "rescue-fstab-production-candidate")]
impl RescueFstabCandidateApproval {
    pub fn new(
        binding: RescueFstabCandidateBinding,
        approval_id: impl Into<String>,
        approval_sequence: u64,
        typed_confirmation: impl Into<String>,
    ) -> Result<Self, RescueFstabCandidateAdmissionError> {
        let approval = Self {
            binding,
            approval_id: approval_id.into(),
            approval_sequence,
            typed_confirmation: typed_confirmation.into(),
        };
        if !valid_rescue_candidate_id(&approval.approval_id, "A-")
            || approval.approval_sequence == 0
        {
            return Err(RescueFstabCandidateAdmissionError::InvalidApproval);
        }
        Ok(approval)
    }

    pub fn binding(&self) -> &RescueFstabCandidateBinding {
        &self.binding
    }

    pub fn session_id(&self) -> &str {
        self.binding.session_id()
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
}

#[cfg(feature = "rescue-fstab-production-candidate")]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RescueFstabCandidateAdmissionState {
    Staged,
    Approved,
}

/// Admission and approval state only. There is intentionally no execute,
/// repair, verify, rollback, broker, or filesystem transition on this type.
#[cfg(feature = "rescue-fstab-production-candidate")]
#[derive(Debug, PartialEq, Eq)]
pub struct RescueFstabCandidateAdmission {
    binding: RescueFstabCandidateBinding,
    state: RescueFstabCandidateAdmissionState,
    next_approval_sequence: u64,
    approval_id: Option<String>,
    approval_sequence: Option<u64>,
    approval_sha256: Option<String>,
}

#[cfg(feature = "rescue-fstab-production-candidate")]
impl RescueFstabCandidateAdmission {
    fn stage(
        binding: RescueFstabCandidateBinding,
        last_approval_sequence: u64,
    ) -> Result<Self, RescueFstabCandidateAdmissionError> {
        let next_approval_sequence = last_approval_sequence
            .checked_add(1)
            .ok_or(RescueFstabCandidateAdmissionError::SequenceExhausted)?;
        Ok(Self {
            binding,
            state: RescueFstabCandidateAdmissionState::Staged,
            next_approval_sequence,
            approval_id: None,
            approval_sequence: None,
            approval_sha256: None,
        })
    }

    pub const fn state(&self) -> RescueFstabCandidateAdmissionState {
        self.state
    }

    pub fn binding(&self) -> &RescueFstabCandidateBinding {
        &self.binding
    }

    pub const fn next_approval_sequence(&self) -> u64 {
        self.next_approval_sequence
    }

    pub fn approval_id(&self) -> Option<&str> {
        self.approval_id.as_deref()
    }

    pub const fn approval_sequence(&self) -> Option<u64> {
        self.approval_sequence
    }

    /// Canonical, domain-separated binding of the exact accepted approval.
    /// It exists only after the single-use transition to `Approved` and is
    /// suitable for the durable Repair Vault binding.
    pub fn approval_sha256(&self) -> Option<&str> {
        self.approval_sha256.as_deref()
    }

    pub fn approve(
        &mut self,
        approval: &RescueFstabCandidateApproval,
    ) -> Result<(), RescueFstabCandidateAdmissionError> {
        if self.state != RescueFstabCandidateAdmissionState::Staged {
            return Err(RescueFstabCandidateAdmissionError::ApprovalReplay);
        }
        if approval.binding != self.binding {
            return Err(RescueFstabCandidateAdmissionError::BindingMismatch);
        }
        if approval.approval_sequence != self.next_approval_sequence {
            return Err(RescueFstabCandidateAdmissionError::NonMonotonicApproval);
        }
        if approval.typed_confirmation != RESCUE_FSTAB_TYPED_CONFIRMATION {
            return Err(RescueFstabCandidateAdmissionError::TypedConfirmationMismatch);
        }

        let approval_sha256 = rescue_fstab_approval_sha256(approval);
        self.approval_id = Some(approval.approval_id.clone());
        self.approval_sequence = Some(approval.approval_sequence);
        self.approval_sha256 = Some(approval_sha256);
        self.state = RescueFstabCandidateAdmissionState::Approved;
        Ok(())
    }
}

#[cfg(feature = "rescue-fstab-production-candidate")]
fn rescue_fstab_approval_sha256(approval: &RescueFstabCandidateApproval) -> String {
    let mut digest = Sha256::new();
    digest.update(RESCUE_FSTAB_APPROVAL_HASH_DOMAIN);
    for value in [
        approval.binding.session_id.as_str(),
        approval.binding.plan_id.as_str(),
        approval.binding.plan_hash.as_str(),
        approval.binding.target_fingerprint.as_str(),
        approval.binding.resource_precondition.as_str(),
        RESCUE_FSTAB_RESOURCE_ID,
        approval.approval_id.as_str(),
    ] {
        digest.update((value.len() as u64).to_be_bytes());
        digest.update(value.as_bytes());
    }
    digest.update(approval.approval_sequence.to_be_bytes());
    digest.update((approval.typed_confirmation.len() as u64).to_be_bytes());
    digest.update(approval.typed_confirmation.as_bytes());
    format!("sha256:{:x}", digest.finalize())
}

/// Authenticated committed repair receipt retained as the source of one
/// rollback plan. It contains identifiers and hashes only, never a path,
/// descriptor, byte buffer, mount handle, or write capability.
#[cfg(feature = "rescue-fstab-production-candidate")]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RescueFstabRollbackSourceBinding {
    source_plan_id: String,
    source_plan_hash: String,
    source_approval_id: String,
    source_approval_sequence: u64,
    reservation_id: String,
    transaction_binding_sha256: String,
    backup_locator: String,
}

#[cfg(feature = "rescue-fstab-production-candidate")]
impl RescueFstabRollbackSourceBinding {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        source_plan_id: impl Into<String>,
        source_plan_hash: impl Into<String>,
        source_approval_id: impl Into<String>,
        source_approval_sequence: u64,
        reservation_id: impl Into<String>,
        transaction_binding_sha256: impl Into<String>,
        backup_locator: impl Into<String>,
    ) -> Result<Self, RescueFstabRollbackAdmissionError> {
        let value = Self {
            source_plan_id: source_plan_id.into(),
            source_plan_hash: source_plan_hash.into(),
            source_approval_id: source_approval_id.into(),
            source_approval_sequence,
            reservation_id: reservation_id.into(),
            transaction_binding_sha256: transaction_binding_sha256.into(),
            backup_locator: backup_locator.into(),
        };
        if !valid_rescue_candidate_id(&value.source_plan_id, "P-")
            || !valid_rescue_candidate_sha256(&value.source_plan_hash)
            || !valid_rescue_candidate_id(&value.source_approval_id, "A-")
            || value.source_approval_sequence == 0
            || !valid_rescue_candidate_id(&value.reservation_id, "B-")
            || !valid_rescue_candidate_sha256(&value.transaction_binding_sha256)
            || value.backup_locator.strip_prefix("vault://repair/")
                != Some(value.reservation_id.as_str())
        {
            return Err(RescueFstabRollbackAdmissionError::InvalidSourceReceipt);
        }
        Ok(value)
    }

    pub fn source_plan_id(&self) -> &str {
        &self.source_plan_id
    }
    pub fn source_plan_hash(&self) -> &str {
        &self.source_plan_hash
    }
    pub fn source_approval_id(&self) -> &str {
        &self.source_approval_id
    }
    pub const fn source_approval_sequence(&self) -> u64 {
        self.source_approval_sequence
    }
    pub fn reservation_id(&self) -> &str {
        &self.reservation_id
    }
    pub fn transaction_binding_sha256(&self) -> &str {
        &self.transaction_binding_sha256
    }
    pub fn backup_locator(&self) -> &str {
        &self.backup_locator
    }
}

/// Immutable binding of one rollback plan to one committed source receipt.
#[cfg(feature = "rescue-fstab-production-candidate")]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RescueFstabRollbackBinding {
    session_id: String,
    rollback_id: String,
    plan_id: String,
    plan_hash: String,
    target_fingerprint: String,
    source: RescueFstabRollbackSourceBinding,
}

#[cfg(feature = "rescue-fstab-production-candidate")]
impl RescueFstabRollbackBinding {
    pub fn new(
        session_id: impl Into<String>,
        rollback_id: impl Into<String>,
        plan_id: impl Into<String>,
        plan_hash: impl Into<String>,
        target_fingerprint: impl Into<String>,
        source: RescueFstabRollbackSourceBinding,
    ) -> Result<Self, RescueFstabRollbackAdmissionError> {
        let value = Self {
            session_id: session_id.into(),
            rollback_id: rollback_id.into(),
            plan_id: plan_id.into(),
            plan_hash: plan_hash.into(),
            target_fingerprint: target_fingerprint.into(),
            source,
        };
        if !valid_rescue_candidate_id(&value.session_id, "S-")
            || !valid_rescue_candidate_id(&value.rollback_id, "RB-")
            || !valid_rescue_candidate_id(&value.plan_id, "P-")
            || !valid_rescue_candidate_sha256(&value.plan_hash)
            || !valid_rescue_candidate_sha256(&value.target_fingerprint)
            || value.plan_id == value.source.source_plan_id
            || value.plan_hash == value.source.source_plan_hash
        {
            return Err(RescueFstabRollbackAdmissionError::InvalidBinding);
        }
        Ok(value)
    }

    pub fn session_id(&self) -> &str {
        &self.session_id
    }
    pub fn rollback_id(&self) -> &str {
        &self.rollback_id
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
    pub const fn resource_id(&self) -> &'static str {
        RESCUE_FSTAB_RESOURCE_ID
    }
    pub const fn source(&self) -> &RescueFstabRollbackSourceBinding {
        &self.source
    }
}

/// Fresh approval proof for one exact rollback binding.
#[cfg(feature = "rescue-fstab-production-candidate")]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RescueFstabRollbackApproval {
    binding: RescueFstabRollbackBinding,
    approval_id: String,
    approval_sequence: u64,
    typed_confirmation: String,
}

#[cfg(feature = "rescue-fstab-production-candidate")]
impl RescueFstabRollbackApproval {
    pub fn new(
        binding: RescueFstabRollbackBinding,
        approval_id: impl Into<String>,
        approval_sequence: u64,
        typed_confirmation: impl Into<String>,
    ) -> Result<Self, RescueFstabRollbackAdmissionError> {
        let value = Self {
            binding,
            approval_id: approval_id.into(),
            approval_sequence,
            typed_confirmation: typed_confirmation.into(),
        };
        if !valid_rescue_candidate_id(&value.approval_id, "A-") || value.approval_sequence == 0 {
            return Err(RescueFstabRollbackAdmissionError::InvalidApproval);
        }
        Ok(value)
    }

    pub const fn binding(&self) -> &RescueFstabRollbackBinding {
        &self.binding
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
}

#[cfg(feature = "rescue-fstab-production-candidate")]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RescueFstabRollbackAdmissionState {
    Staged,
    Approved,
}

/// Approval-only Core state for post-commit rollback. Execution remains in a
/// broker backend and cannot be reached from this type.
#[cfg(feature = "rescue-fstab-production-candidate")]
#[derive(Debug, PartialEq, Eq)]
pub struct RescueFstabRollbackAdmission {
    binding: RescueFstabRollbackBinding,
    state: RescueFstabRollbackAdmissionState,
    next_approval_sequence: u64,
    approval_id: Option<String>,
    approval_sha256: Option<String>,
}

#[cfg(feature = "rescue-fstab-production-candidate")]
impl RescueFstabRollbackAdmission {
    fn stage(
        binding: RescueFstabRollbackBinding,
    ) -> Result<Self, RescueFstabRollbackAdmissionError> {
        let next_approval_sequence = binding
            .source
            .source_approval_sequence
            .checked_add(1)
            .ok_or(RescueFstabRollbackAdmissionError::SequenceExhausted)?;
        Ok(Self {
            binding,
            state: RescueFstabRollbackAdmissionState::Staged,
            next_approval_sequence,
            approval_id: None,
            approval_sha256: None,
        })
    }

    pub const fn binding(&self) -> &RescueFstabRollbackBinding {
        &self.binding
    }
    pub const fn state(&self) -> RescueFstabRollbackAdmissionState {
        self.state
    }
    pub const fn next_approval_sequence(&self) -> u64 {
        self.next_approval_sequence
    }
    pub fn approval_id(&self) -> Option<&str> {
        self.approval_id.as_deref()
    }
    pub fn approval_sha256(&self) -> Option<&str> {
        self.approval_sha256.as_deref()
    }

    pub fn approve(
        &mut self,
        approval: &RescueFstabRollbackApproval,
    ) -> Result<(), RescueFstabRollbackAdmissionError> {
        if self.state != RescueFstabRollbackAdmissionState::Staged {
            return Err(RescueFstabRollbackAdmissionError::ApprovalReplay);
        }
        if approval.binding != self.binding {
            return Err(RescueFstabRollbackAdmissionError::BindingMismatch);
        }
        if approval.approval_id == self.binding.source.source_approval_id {
            return Err(RescueFstabRollbackAdmissionError::ApprovalNotFresh);
        }
        if approval.approval_sequence != self.next_approval_sequence {
            return Err(RescueFstabRollbackAdmissionError::NonMonotonicApproval);
        }
        if approval.typed_confirmation != RESCUE_FSTAB_ROLLBACK_TYPED_CONFIRMATION {
            return Err(RescueFstabRollbackAdmissionError::TypedConfirmationMismatch);
        }
        self.approval_sha256 = Some(rescue_fstab_rollback_approval_sha256(approval));
        self.approval_id = Some(approval.approval_id.clone());
        self.state = RescueFstabRollbackAdmissionState::Approved;
        Ok(())
    }
}

#[cfg(feature = "rescue-fstab-production-candidate")]
fn rescue_fstab_rollback_approval_sha256(approval: &RescueFstabRollbackApproval) -> String {
    let mut digest = Sha256::new();
    digest.update(RESCUE_FSTAB_ROLLBACK_APPROVAL_HASH_DOMAIN);
    for value in [
        approval.binding.session_id.as_str(),
        approval.binding.rollback_id.as_str(),
        approval.binding.plan_id.as_str(),
        approval.binding.plan_hash.as_str(),
        approval.binding.target_fingerprint.as_str(),
        RESCUE_FSTAB_RESOURCE_ID,
        approval.binding.source.source_plan_id.as_str(),
        approval.binding.source.source_plan_hash.as_str(),
        approval.binding.source.source_approval_id.as_str(),
        approval.binding.source.reservation_id.as_str(),
        approval.binding.source.transaction_binding_sha256.as_str(),
        approval.binding.source.backup_locator.as_str(),
        approval.approval_id.as_str(),
    ] {
        digest.update((value.len() as u64).to_be_bytes());
        digest.update(value.as_bytes());
    }
    digest.update(
        approval
            .binding
            .source
            .source_approval_sequence
            .to_be_bytes(),
    );
    digest.update(approval.approval_sequence.to_be_bytes());
    digest.update((approval.typed_confirmation.len() as u64).to_be_bytes());
    digest.update(approval.typed_confirmation.as_bytes());
    format!("sha256:{:x}", digest.finalize())
}

#[cfg(feature = "rescue-fstab-production-candidate")]
#[derive(Debug, PartialEq, Eq)]
pub enum RescueFstabRollbackAdmissionError {
    InvalidSessionState,
    WrongSessionMode,
    PolicyRejected(PolicyError),
    InvalidSourceReceipt,
    InvalidBinding,
    InvalidApproval,
    BindingMismatch,
    ApprovalNotFresh,
    NonMonotonicApproval,
    TypedConfirmationMismatch,
    ApprovalReplay,
    SequenceExhausted,
}

#[cfg(feature = "rescue-fstab-production-candidate")]
impl fmt::Display for RescueFstabRollbackAdmissionError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::InvalidSessionState => "Rescue fstab rollback is outside a fresh session",
            Self::WrongSessionMode => "Rescue fstab rollback requires LinuxRescue mode",
            Self::PolicyRejected(_) => "Rescue fstab rollback policy rejected the plan",
            Self::InvalidSourceReceipt => "Rescue fstab rollback source receipt is invalid",
            Self::InvalidBinding => "Rescue fstab rollback binding is invalid",
            Self::InvalidApproval => "Rescue fstab rollback approval is invalid",
            Self::BindingMismatch => "Rescue fstab rollback approval binding does not match",
            Self::ApprovalNotFresh => "Rescue fstab rollback requires a fresh approval",
            Self::NonMonotonicApproval => "Rescue fstab rollback approval sequence is not next",
            Self::TypedConfirmationMismatch => {
                "Rescue fstab rollback requires the exact typed confirmation"
            }
            Self::ApprovalReplay => "Rescue fstab rollback approval was already consumed",
            Self::SequenceExhausted => "Rescue fstab rollback approval sequence is exhausted",
        })
    }
}

#[cfg(feature = "rescue-fstab-production-candidate")]
impl Error for RescueFstabRollbackAdmissionError {}

#[cfg(feature = "rescue-fstab-production-candidate")]
#[derive(Debug, PartialEq, Eq)]
pub enum RescueFstabCandidateAdmissionError {
    InvalidSessionState,
    WrongSessionMode,
    PolicyRejected(PolicyError),
    InvalidBinding,
    InvalidApproval,
    InvalidBrokerEvidence,
    BindingMismatch,
    NonMonotonicApproval,
    TypedConfirmationMismatch,
    ApprovalReplay,
    SequenceExhausted,
}

#[cfg(feature = "rescue-fstab-production-candidate")]
impl fmt::Display for RescueFstabCandidateAdmissionError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::InvalidSessionState => "Rescue fstab candidate admission is outside Diagnose",
            Self::WrongSessionMode => "Rescue fstab candidate requires LinuxRescue mode",
            Self::PolicyRejected(_) => "Rescue fstab candidate policy rejected the plan",
            Self::InvalidBinding => "Rescue fstab candidate binding is invalid",
            Self::InvalidApproval => "Rescue fstab candidate approval is invalid",
            Self::InvalidBrokerEvidence => "Rescue fstab candidate broker evidence is invalid",
            Self::BindingMismatch => "Rescue fstab candidate approval binding does not match",
            Self::NonMonotonicApproval => "Rescue fstab approval sequence is not next",
            Self::TypedConfirmationMismatch => {
                "Rescue fstab candidate requires the exact typed confirmation"
            }
            Self::ApprovalReplay => "Rescue fstab candidate approval was already consumed",
            Self::SequenceExhausted => "Rescue fstab approval sequence is exhausted",
        })
    }
}

#[cfg(feature = "rescue-fstab-production-candidate")]
impl Error for RescueFstabCandidateAdmissionError {}

#[cfg(feature = "rescue-fstab-production-candidate")]
fn valid_rescue_candidate_sha256(value: &str) -> bool {
    value.strip_prefix("sha256:").is_some_and(|digest| {
        digest.len() == 64
            && digest
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    })
}

#[cfg(feature = "rescue-fstab-production-candidate")]
fn valid_rescue_candidate_id(value: &str, prefix: &str) -> bool {
    let Some(suffix) = value.strip_prefix(prefix) else {
        return false;
    };
    !suffix.is_empty()
        && value.len() <= 128
        && suffix
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum State {
    Observe,
    Diagnose,
    Plan,
    Repair,
    Verify,
    Complete,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SessionMode {
    NonLinux,
    LinuxResident,
    LinuxRescue,
}

pub struct Session {
    state: State,
    fingerprint: String,
    mode: SessionMode,
    linux_snapshot: Option<LinuxSnapshotBinding>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LinuxSnapshotBinding {
    pub evidence_id: String,
    pub evidence_sha256: String,
    pub snapshot_sha256: String,
    pub target: String,
    pub target_fingerprint: String,
    pub capture_mode: &'static str,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LinuxSnapshotAdmissionError {
    InvalidSessionState,
    InvalidEvidenceBinding,
    InvalidEnvelope(SnapshotError),
    DuplicateSnapshot,
    ModeMismatch,
    IncompleteLinuxCorpus,
    ExplicitLinuxAdmissionRequired,
    UnsupportedLinuxTopology,
}

impl fmt::Display for LinuxSnapshotAdmissionError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::InvalidSessionState => "Linux snapshot admission is outside Observe",
            Self::InvalidEvidenceBinding => "Linux snapshot evidence binding is invalid",
            Self::InvalidEnvelope(_) => "Linux snapshot envelope is invalid",
            Self::DuplicateSnapshot => "Linux snapshot was already admitted",
            Self::ModeMismatch => {
                "Linux snapshot capture does not match the immutable session mode"
            }
            Self::IncompleteLinuxCorpus => "Linux evidence corpus is incomplete",
            Self::ExplicitLinuxAdmissionRequired => {
                "Linux sessions require the explicit snapshot admission transition"
            }
            Self::UnsupportedLinuxTopology => {
                "Linux snapshot declares a multi-filesystem topology unsupported by v1"
            }
        })
    }
}

impl Error for LinuxSnapshotAdmissionError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::InvalidEnvelope(error) => Some(error),
            _ => None,
        }
    }
}
impl Session {
    pub fn new(fingerprint: impl Into<String>, mode: SessionMode) -> Self {
        Self {
            state: State::Observe,
            fingerprint: fingerprint.into(),
            mode,
            linux_snapshot: None,
        }
    }
    pub fn state(&self) -> &State {
        &self.state
    }
    pub const fn mode(&self) -> SessionMode {
        self.mode
    }

    /// Compatibility transition for explicitly non-Linux sessions only.
    pub fn evidence_complete(&mut self) -> Result<(), LinuxSnapshotAdmissionError> {
        if self.state != State::Observe {
            return Err(LinuxSnapshotAdmissionError::InvalidSessionState);
        }
        if self.mode != SessionMode::NonLinux {
            return Err(LinuxSnapshotAdmissionError::ExplicitLinuxAdmissionRequired);
        }
        self.state = State::Diagnose;
        Ok(())
    }

    pub fn admit_linux_snapshot(
        &mut self,
        evidence: &Evidence,
        envelope_bytes: &[u8],
    ) -> Result<&LinuxSnapshotBinding, LinuxSnapshotAdmissionError> {
        if self.state != State::Observe {
            return Err(LinuxSnapshotAdmissionError::InvalidSessionState);
        }
        if self.linux_snapshot.is_some() {
            return Err(LinuxSnapshotAdmissionError::DuplicateSnapshot);
        }
        let envelope = LinuxNormalizedSnapshotEnvelope::parse(envelope_bytes)
            .map_err(LinuxSnapshotAdmissionError::InvalidEnvelope)?;
        if !envelope.snapshot.topology.supported {
            return Err(LinuxSnapshotAdmissionError::UnsupportedLinuxTopology);
        }
        let evidence_hash = format!("{:x}", Sha256::digest(envelope_bytes));
        let (capture_mode, target_valid) = match self.mode {
            SessionMode::LinuxResident if envelope.capture.is_resident() => {
                ("resident", evidence.target == "local-machine")
            }
            SessionMode::LinuxRescue if envelope.capture.is_rescue() => {
                ("rescue", evidence.target == "selected-installed-target")
            }
            SessionMode::NonLinux | SessionMode::LinuxResident | SessionMode::LinuxRescue => {
                return Err(LinuxSnapshotAdmissionError::ModeMismatch);
            }
        };
        if evidence.id.is_empty()
            || evidence.collector != LINUX_SNAPSHOT_COLLECTOR
            || evidence.content_type != LINUX_SNAPSHOT_CONTENT_TYPE
            || !evidence.is_untrusted()
            || !target_valid
            || evidence.sha256 != evidence_hash
            || evidence.blob_ref != format!("sha256:{evidence_hash}")
        {
            return Err(LinuxSnapshotAdmissionError::InvalidEvidenceBinding);
        }
        self.linux_snapshot = Some(LinuxSnapshotBinding {
            evidence_id: evidence.id.clone(),
            evidence_sha256: evidence_hash,
            snapshot_sha256: envelope.snapshot_sha256,
            target: evidence.target.clone(),
            target_fingerprint: self.fingerprint.clone(),
            capture_mode,
        });
        Ok(self
            .linux_snapshot
            .as_ref()
            .expect("snapshot binding was inserted"))
    }

    pub fn linux_snapshot_binding(&self) -> Option<&LinuxSnapshotBinding> {
        self.linux_snapshot.as_ref()
    }

    pub fn linux_evidence_complete(
        &mut self,
        evidence: &[Evidence],
    ) -> Result<(), LinuxSnapshotAdmissionError> {
        if self.state != State::Observe {
            return Err(LinuxSnapshotAdmissionError::InvalidSessionState);
        }
        let binding = self
            .linux_snapshot
            .as_ref()
            .ok_or(LinuxSnapshotAdmissionError::InvalidEvidenceBinding)?;
        let snapshot_collector_count = evidence
            .iter()
            .filter(|item| item.collector == LINUX_SNAPSHOT_COLLECTOR)
            .count();
        let bound_snapshot_count = evidence
            .iter()
            .filter(|item| {
                item.id == binding.evidence_id
                    && item.collector == LINUX_SNAPSHOT_COLLECTOR
                    && item.sha256 == binding.evidence_sha256
                    && item.target == binding.target
            })
            .count();
        let evidence_ids = evidence
            .iter()
            .map(|item| item.id.as_str())
            .collect::<HashSet<_>>();
        if snapshot_collector_count != 1
            || bound_snapshot_count != 1
            || evidence_ids.len() != evidence.len()
            || evidence
                .iter()
                .any(|item| item.target != binding.target || !item.is_untrusted())
        {
            return Err(LinuxSnapshotAdmissionError::IncompleteLinuxCorpus);
        }
        match self.mode {
            SessionMode::LinuxResident => {
                if evidence.len() != LINUX_RESIDENT_REQUIRED_COLLECTORS.len() + 1
                    || evidence.iter().any(|item| {
                        item.collector != LINUX_SNAPSHOT_COLLECTOR
                            && !LINUX_RESIDENT_REQUIRED_COLLECTORS
                                .contains(&item.collector.as_str())
                    })
                    || LINUX_RESIDENT_REQUIRED_COLLECTORS.iter().any(|collector| {
                        evidence
                            .iter()
                            .filter(|item| item.collector == *collector)
                            .count()
                            != 1
                    })
                {
                    return Err(LinuxSnapshotAdmissionError::IncompleteLinuxCorpus);
                }
            }
            SessionMode::LinuxRescue => {
                if evidence.len() != 1 {
                    return Err(LinuxSnapshotAdmissionError::IncompleteLinuxCorpus);
                }
            }
            SessionMode::NonLinux => {
                return Err(LinuxSnapshotAdmissionError::ModeMismatch);
            }
        }
        self.state = State::Diagnose;
        Ok(())
    }
    pub fn stage(&mut self, plan: &ValidatedPlan) -> Result<(), PolicyError> {
        if self.state != State::Diagnose {
            return Err(PolicyError::MutationDisabled);
        }
        for step in &plan.steps {
            validate_phase_zero(step)?;
        }
        if plan.target_fingerprint != self.fingerprint {
            return Err(PolicyError::MutationDisabled);
        }
        self.state = State::Plan;
        Ok(())
    }

    /// Stage the one disposable-fixture R2 action when the lab feature is
    /// explicitly compiled. This is a separate entry point so the normal
    /// Phase 0 path cannot accidentally inherit mutation admission.
    #[cfg(feature = "fixture-repair-lab")]
    pub fn stage_fixture_repair_lab(&mut self, plan: &ValidatedPlan) -> Result<(), PolicyError> {
        if self.state != State::Diagnose {
            return Err(PolicyError::MutationDisabled);
        }
        validate_fixture_repair_lab_plan(plan, &self.fingerprint)?;
        self.state = State::Plan;
        Ok(())
    }

    /// Stage admission metadata for the disabled Rescue `fstab` candidate.
    ///
    /// A successful call advances only to `Plan` and returns an approval-only
    /// state object. It cannot execute or dispatch the action.
    #[cfg(feature = "rescue-fstab-production-candidate")]
    pub fn stage_rescue_fstab_production_candidate(
        &mut self,
        plan: &ValidatedPlan,
        session_id: impl Into<String>,
        plan_hash: impl Into<String>,
        resource_precondition: impl Into<String>,
        last_approval_sequence: u64,
    ) -> Result<RescueFstabCandidateAdmission, RescueFstabCandidateAdmissionError> {
        if self.state != State::Diagnose {
            return Err(RescueFstabCandidateAdmissionError::InvalidSessionState);
        }
        if self.mode != SessionMode::LinuxRescue {
            return Err(RescueFstabCandidateAdmissionError::WrongSessionMode);
        }
        validate_rescue_fstab_production_candidate_plan(plan, &self.fingerprint)
            .map_err(RescueFstabCandidateAdmissionError::PolicyRejected)?;
        let binding = RescueFstabCandidateBinding::new(
            session_id,
            plan.plan_id.clone(),
            plan_hash,
            plan.target_fingerprint.clone(),
            resource_precondition,
        )?;
        let admission = RescueFstabCandidateAdmission::stage(binding, last_approval_sequence)?;
        self.state = State::Plan;
        Ok(admission)
    }

    /// Admit the sole Rescue candidate directly from exact broker-derived
    /// evidence, without manufacturing a general Linux snapshot envelope.
    ///
    /// This transition exists only for the production-candidate feature and
    /// only from a fresh `LinuxRescue` session.  It is not a generic
    /// evidence-complete shortcut: all action, finding, resource, evidence,
    /// target and plan bindings are closed and checked before `Plan`.
    #[cfg(feature = "rescue-fstab-production-candidate")]
    pub fn stage_rescue_fstab_broker_candidate(
        &mut self,
        plan: &ValidatedPlan,
        evidence: &RescueFstabBrokerDerivedEvidence,
        last_approval_sequence: u64,
    ) -> Result<RescueFstabCandidateAdmission, RescueFstabCandidateAdmissionError> {
        if self.state != State::Observe || self.linux_snapshot.is_some() {
            return Err(RescueFstabCandidateAdmissionError::InvalidSessionState);
        }
        if self.mode != SessionMode::LinuxRescue {
            return Err(RescueFstabCandidateAdmissionError::WrongSessionMode);
        }
        validate_rescue_fstab_production_candidate_plan(plan, &self.fingerprint)
            .map_err(RescueFstabCandidateAdmissionError::PolicyRejected)?;
        let [step] = plan.steps.as_slice() else {
            return Err(RescueFstabCandidateAdmissionError::InvalidBrokerEvidence);
        };
        if evidence.plan_id != plan.plan_id
            || evidence.target_fingerprint != self.fingerprint
            || evidence.target_fingerprint != plan.target_fingerprint
            || evidence.action_id != step.action
            || evidence.resource_id != RESCUE_FSTAB_RESOURCE_ID
            || evidence.finding_id != RESCUE_FSTAB_FINDING_ID
            || evidence.finding_version != RESCUE_FSTAB_FINDING_VERSION
            || evidence.evidence[0].0 != step.evidence_ids[0]
            || evidence.evidence[1].0 != step.evidence_ids[1]
        {
            return Err(RescueFstabCandidateAdmissionError::InvalidBrokerEvidence);
        }
        let binding = RescueFstabCandidateBinding::new(
            evidence.session_id.clone(),
            evidence.plan_id.clone(),
            evidence.plan_hash.clone(),
            evidence.target_fingerprint.clone(),
            evidence.target_snapshot.clone(),
        )?;
        let admission = RescueFstabCandidateAdmission::stage(binding, last_approval_sequence)?;
        self.state = State::Plan;
        Ok(admission)
    }

    /// Stage a separate post-commit rollback against one authenticated source
    /// receipt. The returned state can accept an approval but cannot execute.
    #[cfg(feature = "rescue-fstab-production-candidate")]
    pub fn stage_rescue_fstab_rollback(
        &mut self,
        plan: &ValidatedPlan,
        binding: RescueFstabRollbackBinding,
    ) -> Result<RescueFstabRollbackAdmission, RescueFstabRollbackAdmissionError> {
        if self.state != State::Observe || self.linux_snapshot.is_some() {
            return Err(RescueFstabRollbackAdmissionError::InvalidSessionState);
        }
        if self.mode != SessionMode::LinuxRescue {
            return Err(RescueFstabRollbackAdmissionError::WrongSessionMode);
        }
        validate_rescue_fstab_rollback_policy(plan, &self.fingerprint)
            .map_err(RescueFstabRollbackAdmissionError::PolicyRejected)?;
        if binding.plan_id != plan.plan_id
            || binding.target_fingerprint != plan.target_fingerprint
            || binding.target_fingerprint != self.fingerprint
        {
            return Err(RescueFstabRollbackAdmissionError::BindingMismatch);
        }
        let admission = RescueFstabRollbackAdmission::stage(binding)?;
        self.state = State::Plan;
        Ok(admission)
    }
}

pub const LINUX_RESIDENT_P0_COLLECTORS: [&str; 9] = [
    "linux.block.inventory",
    "linux.mounts.read-only",
    "linux.systemd.failed",
    "linux.systemd.state",
    "linux.fstab",
    "linux.df",
    "linux.network.links",
    "linux.network.routes",
    "linux.dpkg.audit",
];

pub const LINUX_RESIDENT_REQUIRED_COLLECTORS: [&str; 11] = [
    "system.hostname",
    "linux.hardware.inventory",
    "linux.block.inventory",
    "linux.mounts.read-only",
    "linux.systemd.failed",
    "linux.systemd.state",
    "linux.fstab",
    "linux.df",
    "linux.network.links",
    "linux.network.routes",
    "linux.dpkg.audit",
];

#[cfg(test)]
mod tests {
    use super::*;
    use kernaid_evidence::linux_snapshot::{
        COLLECTION_SCOPE, LinuxBoot, LinuxConfiguration, LinuxFilesystemTopology,
        LinuxFstabSummary, LinuxNormalizedSnapshot, LinuxNormalizedSnapshotEnvelope,
        LinuxPackageDatabases, LinuxRelease, LinuxSnapshotCapture, SNAPSHOT_SCOPE,
    };
    use kernaid_protocol::{ActionStep, Risk};

    fn envelope(capture: LinuxSnapshotCapture) -> Vec<u8> {
        envelope_with_topology(capture, true)
    }

    fn envelope_with_topology(capture: LinuxSnapshotCapture, supported: bool) -> Vec<u8> {
        LinuxNormalizedSnapshotEnvelope::new(
            capture,
            LinuxNormalizedSnapshot {
                family: "linux".to_owned(),
                scope: SNAPSHOT_SCOPE.to_owned(),
                installation_confirmed: true,
                topology: LinuxFilesystemTopology {
                    collection_scope: COLLECTION_SCOPE.to_owned(),
                    separate_etc_mount_present: !supported,
                    separate_boot_mount_present: false,
                    separate_usr_mount_present: false,
                    separate_var_mount_present: false,
                    relevant_separate_mount_present: !supported,
                    supported,
                },
                release: LinuxRelease {
                    id: Some("fixture".to_owned()),
                    name: None,
                    pretty_name: None,
                    version_id: None,
                    source: "etc-os-release".to_owned(),
                },
                boot: LinuxBoot {
                    directory_present: false,
                    kernel_artifact_count: 0,
                    initramfs_artifact_count: 0,
                    bootloader_directory_count: 0,
                    symlink_artifact_count: 0,
                },
                configuration: LinuxConfiguration {
                    fstab: LinuxFstabSummary {
                        present: false,
                        entry_count: 0,
                        root_entry_present: false,
                        efi_entry_present: false,
                        swap_entry_count: 0,
                        network_entry_count: 0,
                        malformed_line_count: 0,
                    },
                    machine_id_present: false,
                },
                package_databases: LinuxPackageDatabases {
                    dpkg_status_present: false,
                    rpm_database_present: false,
                    pacman_database_present: false,
                },
            },
        )
        .expect("snapshot")
        .canonical_json()
        .expect("canonical envelope")
    }

    fn evidence(target: &str, bytes: &[u8]) -> Evidence {
        let hash = format!("{:x}", Sha256::digest(bytes));
        Evidence {
            id: "E-SNAPSHOT".to_owned(),
            collector: LINUX_SNAPSHOT_COLLECTOR.to_owned(),
            target: target.to_owned(),
            captured_at: "2026-08-20T00:00:00Z".to_owned(),
            content_type: LINUX_SNAPSHOT_CONTENT_TYPE.to_owned(),
            sha256: hash.clone(),
            sensitivity: "system".to_owned(),
            trust: "observed-untrusted".to_owned(),
            summary: "fixture".to_owned(),
            blob_ref: format!("sha256:{hash}"),
        }
    }

    fn resident_corpus(snapshot: Evidence) -> Vec<Evidence> {
        let mut evidence = vec![snapshot];
        evidence.extend(LINUX_RESIDENT_REQUIRED_COLLECTORS.iter().enumerate().map(
            |(index, collector)| Evidence {
                id: format!("E-P0-{index}"),
                collector: (*collector).to_owned(),
                target: "local-machine".to_owned(),
                captured_at: "2026-08-20T00:00:00Z".to_owned(),
                content_type: "text/plain".to_owned(),
                sha256: "1".repeat(64),
                sensitivity: "system".to_owned(),
                trust: "observed-untrusted".to_owned(),
                summary: "fixture".to_owned(),
                blob_ref: format!("sha256:{}", "1".repeat(64)),
            },
        ));
        evidence
    }

    fn r0_plan() -> ValidatedPlan {
        ValidatedPlan {
            plan_id: "P-fixture".to_owned(),
            target_fingerprint: "sha256:fixture".to_owned(),
            steps: vec![ActionStep {
                action: "system.observe.noop".to_owned(),
                risk: Risk::R0,
                target_fingerprint: "sha256:fixture".to_owned(),
                evidence_ids: vec!["E-SNAPSHOT".to_owned()],
                preconditions: vec![],
                backup: None,
                validation: "evidence.exists".to_owned(),
                rollback: None,
            }],
        }
    }

    #[cfg(feature = "rescue-fstab-production-candidate")]
    const RESCUE_CANDIDATE_TARGET: &str =
        "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

    #[cfg(feature = "rescue-fstab-production-candidate")]
    const RESCUE_CANDIDATE_PLAN_HASH: &str =
        "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";

    #[cfg(feature = "rescue-fstab-production-candidate")]
    const RESCUE_CANDIDATE_TARGET_SNAPSHOT: &str =
        "sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc";

    #[cfg(feature = "rescue-fstab-production-candidate")]
    fn rescue_candidate_plan() -> ValidatedPlan {
        use kernaid_policy::{
            RESCUE_FSTAB_ACTION_ID, RESCUE_FSTAB_BACKUP, RESCUE_FSTAB_EVIDENCE_IDS,
            RESCUE_FSTAB_PREFLIGHT_ID, RESCUE_FSTAB_ROLLBACK_ID, RESCUE_FSTAB_VALIDATION_ID,
        };

        ValidatedPlan {
            plan_id: "P-rescue-fstab-candidate".to_owned(),
            target_fingerprint: RESCUE_CANDIDATE_TARGET.to_owned(),
            steps: vec![ActionStep {
                action: RESCUE_FSTAB_ACTION_ID.to_owned(),
                risk: Risk::R2,
                target_fingerprint: RESCUE_CANDIDATE_TARGET.to_owned(),
                evidence_ids: RESCUE_FSTAB_EVIDENCE_IDS
                    .iter()
                    .map(|value| (*value).to_owned())
                    .collect(),
                preconditions: vec![RESCUE_FSTAB_PREFLIGHT_ID.to_owned()],
                backup: Some(RESCUE_FSTAB_BACKUP.to_owned()),
                validation: RESCUE_FSTAB_VALIDATION_ID.to_owned(),
                rollback: Some(RESCUE_FSTAB_ROLLBACK_ID.to_owned()),
            }],
        }
    }

    #[cfg(feature = "rescue-fstab-production-candidate")]
    fn rescue_rollback_plan() -> ValidatedPlan {
        use kernaid_policy::{
            RESCUE_FSTAB_ROLLBACK_BACKUP, RESCUE_FSTAB_ROLLBACK_EVIDENCE_ID,
            RESCUE_FSTAB_ROLLBACK_ID, RESCUE_FSTAB_ROLLBACK_PREFLIGHT_ID,
            RESCUE_FSTAB_VALIDATION_ID,
        };

        ValidatedPlan {
            plan_id: "P-rescue-fstab-rollback".to_owned(),
            target_fingerprint: RESCUE_CANDIDATE_TARGET.to_owned(),
            steps: vec![ActionStep {
                action: RESCUE_FSTAB_ROLLBACK_ID.to_owned(),
                risk: Risk::R2,
                target_fingerprint: RESCUE_CANDIDATE_TARGET.to_owned(),
                evidence_ids: vec![RESCUE_FSTAB_ROLLBACK_EVIDENCE_ID.to_owned()],
                preconditions: vec![RESCUE_FSTAB_ROLLBACK_PREFLIGHT_ID.to_owned()],
                backup: Some(RESCUE_FSTAB_ROLLBACK_BACKUP.to_owned()),
                validation: RESCUE_FSTAB_VALIDATION_ID.to_owned(),
                rollback: None,
            }],
        }
    }

    #[cfg(feature = "rescue-fstab-production-candidate")]
    fn rescue_candidate_broker_evidence(plan_id: &str) -> RescueFstabBrokerDerivedEvidence {
        RescueFstabBrokerDerivedEvidence::new(
            "S-rescue-1",
            plan_id,
            RESCUE_CANDIDATE_PLAN_HASH,
            RESCUE_CANDIDATE_TARGET,
            RESCUE_CANDIDATE_TARGET_SNAPSHOT,
            RESCUE_FSTAB_ACTION_ID,
            RESCUE_FSTAB_FINDING_ID,
            RESCUE_FSTAB_FINDING_VERSION,
            RESCUE_FSTAB_RESOURCE_ID,
            [
                (
                    RESCUE_FSTAB_EVIDENCE_IDS[0].to_owned(),
                    "sha256:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd"
                        .to_owned(),
                ),
                (
                    RESCUE_FSTAB_EVIDENCE_IDS[1].to_owned(),
                    "sha256:eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee"
                        .to_owned(),
                ),
            ],
        )
        .expect("closed broker evidence")
    }

    #[cfg(feature = "rescue-fstab-production-candidate")]
    fn diagnosed_rescue_candidate_session() -> Session {
        let bytes = envelope(LinuxSnapshotCapture::rescue());
        let snapshot = evidence("selected-installed-target", &bytes);
        let mut session = Session::new(RESCUE_CANDIDATE_TARGET, SessionMode::LinuxRescue);
        session
            .admit_linux_snapshot(&snapshot, &bytes)
            .expect("admit Rescue snapshot");
        session
            .linux_evidence_complete(std::slice::from_ref(&snapshot))
            .expect("complete Rescue evidence");
        session
    }

    #[cfg(feature = "fixture-repair-lab")]
    const FIXTURE_TARGET: &str =
        "sha256:1111111111111111111111111111111111111111111111111111111111111111";

    #[cfg(feature = "fixture-repair-lab")]
    fn fixture_r2_plan() -> ValidatedPlan {
        use kernaid_policy::{
            FIXTURE_FSTAB_ACTION_ID, FIXTURE_FSTAB_BACKUP, FIXTURE_FSTAB_PREFLIGHT_ID,
            FIXTURE_FSTAB_ROLLBACK_ID, FIXTURE_FSTAB_VALIDATION_ID,
        };

        ValidatedPlan {
            plan_id: "P-fixture-repair".to_owned(),
            target_fingerprint: FIXTURE_TARGET.to_owned(),
            steps: vec![ActionStep {
                action: FIXTURE_FSTAB_ACTION_ID.to_owned(),
                risk: Risk::R2,
                target_fingerprint: FIXTURE_TARGET.to_owned(),
                evidence_ids: vec!["E-SNAPSHOT".to_owned(), "E-P0-2".to_owned()],
                preconditions: vec![FIXTURE_FSTAB_PREFLIGHT_ID.to_owned()],
                backup: Some(FIXTURE_FSTAB_BACKUP.to_owned()),
                validation: FIXTURE_FSTAB_VALIDATION_ID.to_owned(),
                rollback: Some(FIXTURE_FSTAB_ROLLBACK_ID.to_owned()),
            }],
        }
    }

    #[cfg(feature = "fixture-repair-lab")]
    fn fixture_mutation(plan_id: &str, marker: char) -> FixtureMutationBinding {
        FixtureMutationBinding::new(
            plan_id,
            format!("sha256:{}", marker.to_string().repeat(64)),
            FIXTURE_TARGET,
            "linux.fstab",
            format!("sha256:{}", "b".repeat(64)),
        )
        .expect("valid fixture mutation binding")
    }

    #[cfg(feature = "fixture-repair-lab")]
    fn fixture_proof(
        mutation: &FixtureMutationBinding,
        approval_id: &str,
        sequence: u64,
    ) -> FixtureTransitionProof {
        FixtureTransitionProof::new(mutation.clone(), approval_id, sequence)
            .expect("valid fixture transition proof")
    }

    #[cfg(feature = "fixture-repair-lab")]
    fn diagnosed_fixture_session() -> Session {
        let bytes = envelope(LinuxSnapshotCapture::resident());
        let snapshot = evidence("local-machine", &bytes);
        let corpus = resident_corpus(snapshot.clone());
        let mut session = Session::new(FIXTURE_TARGET, SessionMode::LinuxResident);
        session
            .admit_linux_snapshot(&snapshot, &bytes)
            .expect("admit fixture snapshot");
        session
            .linux_evidence_complete(&corpus)
            .expect("complete fixture evidence");
        session
    }

    #[test]
    fn linux_transition_requires_a_hash_and_capture_bound_snapshot() {
        let bytes = envelope(LinuxSnapshotCapture::resident());
        let snapshot_evidence = evidence("local-machine", &bytes);
        let mut session = Session::new("sha256:fixture", SessionMode::LinuxResident);
        assert_eq!(
            session.linux_evidence_complete(&[]),
            Err(LinuxSnapshotAdmissionError::InvalidEvidenceBinding)
        );
        let binding = session
            .admit_linux_snapshot(&snapshot_evidence, &bytes)
            .expect("admitted snapshot");
        assert_eq!(binding.capture_mode, "resident");
        assert_eq!(
            session.linux_evidence_complete(std::slice::from_ref(&snapshot_evidence)),
            Err(LinuxSnapshotAdmissionError::IncompleteLinuxCorpus)
        );
        let production_corpus = resident_corpus(snapshot_evidence);
        assert_eq!(production_corpus.len(), 12);
        session
            .linux_evidence_complete(&production_corpus)
            .expect("Linux evidence complete");
        assert_eq!(session.state(), &State::Diagnose);
    }

    #[test]
    fn linux_transition_rejects_foreign_duplicate_and_extra_evidence() {
        let bytes = envelope(LinuxSnapshotCapture::resident());
        let snapshot_evidence = evidence("local-machine", &bytes);

        let mut foreign = resident_corpus(snapshot_evidence.clone());
        foreign[2].target = "foreign-machine".to_owned();
        let mut foreign_session = Session::new("sha256:fixture", SessionMode::LinuxResident);
        foreign_session
            .admit_linux_snapshot(&snapshot_evidence, &bytes)
            .expect("admitted snapshot");
        assert_eq!(
            foreign_session.linux_evidence_complete(&foreign),
            Err(LinuxSnapshotAdmissionError::IncompleteLinuxCorpus)
        );

        let mut duplicate_id = resident_corpus(snapshot_evidence.clone());
        duplicate_id[2].id = duplicate_id[0].id.clone();
        let mut duplicate_session = Session::new("sha256:fixture", SessionMode::LinuxResident);
        duplicate_session
            .admit_linux_snapshot(&snapshot_evidence, &bytes)
            .expect("admitted snapshot");
        assert_eq!(
            duplicate_session.linux_evidence_complete(&duplicate_id),
            Err(LinuxSnapshotAdmissionError::IncompleteLinuxCorpus)
        );

        let mut duplicate_collector = resident_corpus(snapshot_evidence.clone());
        duplicate_collector
            .last_mut()
            .expect("last P0 item")
            .collector = LINUX_RESIDENT_P0_COLLECTORS[0].to_owned();
        let mut duplicate_collector_session =
            Session::new("sha256:fixture", SessionMode::LinuxResident);
        duplicate_collector_session
            .admit_linux_snapshot(&snapshot_evidence, &bytes)
            .expect("admitted snapshot");
        assert_eq!(
            duplicate_collector_session.linux_evidence_complete(&duplicate_collector),
            Err(LinuxSnapshotAdmissionError::IncompleteLinuxCorpus)
        );

        let mut extra = resident_corpus(snapshot_evidence.clone());
        let mut extra_item = extra[2].clone();
        extra_item.id = "E-EXTRA".to_owned();
        extra_item.collector = "linux.raw.uncontracted".to_owned();
        extra.push(extra_item);
        let mut extra_session = Session::new("sha256:fixture", SessionMode::LinuxResident);
        extra_session
            .admit_linux_snapshot(&snapshot_evidence, &bytes)
            .expect("admitted snapshot");
        assert_eq!(
            extra_session.linux_evidence_complete(&extra),
            Err(LinuxSnapshotAdmissionError::IncompleteLinuxCorpus)
        );

        let rescue_bytes = envelope(LinuxSnapshotCapture::rescue());
        let rescue_snapshot = evidence("selected-installed-target", &rescue_bytes);
        let mut rescue_extra = vec![rescue_snapshot.clone()];
        let mut extra_item = rescue_snapshot.clone();
        extra_item.id = "E-EXTRA".to_owned();
        extra_item.collector = "linux.raw.uncontracted".to_owned();
        rescue_extra.push(extra_item);
        let mut rescue_session = Session::new("sha256:fixture", SessionMode::LinuxRescue);
        rescue_session
            .admit_linux_snapshot(&rescue_snapshot, &rescue_bytes)
            .expect("admitted snapshot");
        assert_eq!(
            rescue_session.linux_evidence_complete(&rescue_extra),
            Err(LinuxSnapshotAdmissionError::IncompleteLinuxCorpus)
        );
    }

    #[test]
    fn rescue_attestation_cannot_bind_to_a_resident_target() {
        let bytes = envelope(LinuxSnapshotCapture::rescue());
        let mut session = Session::new("sha256:fixture", SessionMode::LinuxResident);
        assert_eq!(
            session.admit_linux_snapshot(&evidence("selected-installed-target", &bytes), &bytes),
            Err(LinuxSnapshotAdmissionError::ModeMismatch)
        );
    }

    #[test]
    fn resident_attestation_cannot_bind_to_a_rescue_session() {
        let bytes = envelope(LinuxSnapshotCapture::resident());
        let mut session = Session::new("sha256:fixture", SessionMode::LinuxRescue);
        assert_eq!(
            session.admit_linux_snapshot(&evidence("local-machine", &bytes), &bytes),
            Err(LinuxSnapshotAdmissionError::ModeMismatch)
        );
    }

    #[test]
    fn unsupported_topology_is_rejected_in_both_linux_modes() {
        for (mode, capture, target) in [
            (
                SessionMode::LinuxResident,
                LinuxSnapshotCapture::resident(),
                "local-machine",
            ),
            (
                SessionMode::LinuxRescue,
                LinuxSnapshotCapture::rescue(),
                "selected-installed-target",
            ),
        ] {
            let bytes = envelope_with_topology(capture, false);
            let mut session = Session::new("sha256:fixture", mode);
            assert_eq!(
                session.admit_linux_snapshot(&evidence(target, &bytes), &bytes),
                Err(LinuxSnapshotAdmissionError::UnsupportedLinuxTopology)
            );
            assert_eq!(session.state(), &State::Observe);
        }
    }

    #[test]
    fn legacy_transition_is_explicitly_non_linux_only() {
        let mut linux = Session::new("sha256:fixture", SessionMode::LinuxResident);
        assert_eq!(
            linux.evidence_complete(),
            Err(LinuxSnapshotAdmissionError::ExplicitLinuxAdmissionRequired)
        );
        assert_eq!(linux.state(), &State::Observe);

        let mut non_linux = Session::new("sha256:fixture", SessionMode::NonLinux);
        non_linux
            .evidence_complete()
            .expect("non-Linux compatibility");
        assert_eq!(non_linux.state(), &State::Diagnose);
    }

    #[test]
    fn fresh_linux_sessions_cannot_bypass_snapshot_admission_by_staging() {
        for mode in [SessionMode::LinuxResident, SessionMode::LinuxRescue] {
            let mut session = Session::new("sha256:fixture", mode);
            assert_eq!(
                session.stage(&r0_plan()),
                Err(PolicyError::MutationDisabled)
            );
            assert_eq!(session.state(), &State::Observe);
        }
    }

    #[cfg(feature = "rescue-fstab-production-candidate")]
    #[test]
    fn rescue_candidate_has_a_separate_rescue_diagnose_only_entrypoint() {
        let plan = rescue_candidate_plan();
        let mut normal_phase_zero = diagnosed_rescue_candidate_session();
        assert_eq!(
            normal_phase_zero.stage(&plan),
            Err(PolicyError::MutationDisabled)
        );
        assert_eq!(normal_phase_zero.state(), &State::Diagnose);

        let mut observe = Session::new(RESCUE_CANDIDATE_TARGET, SessionMode::LinuxRescue);
        assert_eq!(
            observe.stage_rescue_fstab_production_candidate(
                &plan,
                "S-rescue-1",
                RESCUE_CANDIDATE_PLAN_HASH,
                RESCUE_CANDIDATE_TARGET_SNAPSHOT,
                6,
            ),
            Err(RescueFstabCandidateAdmissionError::InvalidSessionState)
        );

        let mut non_rescue = Session::new(RESCUE_CANDIDATE_TARGET, SessionMode::NonLinux);
        non_rescue.evidence_complete().expect("enter Diagnose");
        assert_eq!(
            non_rescue.stage_rescue_fstab_production_candidate(
                &plan,
                "S-rescue-1",
                RESCUE_CANDIDATE_PLAN_HASH,
                RESCUE_CANDIDATE_TARGET_SNAPSHOT,
                6,
            ),
            Err(RescueFstabCandidateAdmissionError::WrongSessionMode)
        );

        let mut rescue = diagnosed_rescue_candidate_session();
        let admission = rescue
            .stage_rescue_fstab_production_candidate(
                &plan,
                "S-rescue-1",
                RESCUE_CANDIDATE_PLAN_HASH,
                RESCUE_CANDIDATE_TARGET_SNAPSHOT,
                6,
            )
            .expect("stage admission metadata only");
        assert_eq!(rescue.state(), &State::Plan);
        assert_eq!(
            admission.state(),
            RescueFstabCandidateAdmissionState::Staged
        );
        assert_eq!(admission.next_approval_sequence(), 7);
        assert_eq!(admission.binding().session_id(), "S-rescue-1");
        assert_eq!(admission.binding().plan_id(), plan.plan_id);
        assert_eq!(admission.binding().plan_hash(), RESCUE_CANDIDATE_PLAN_HASH);
        assert_eq!(
            admission.binding().target_fingerprint(),
            RESCUE_CANDIDATE_TARGET
        );
        assert_eq!(
            admission.binding().target_snapshot(),
            RESCUE_CANDIDATE_TARGET_SNAPSHOT
        );
        assert_eq!(admission.binding().resource_id(), RESCUE_FSTAB_RESOURCE_ID);
    }

    #[cfg(feature = "rescue-fstab-production-candidate")]
    #[test]
    fn broker_evidence_is_the_only_direct_rescue_observe_to_plan_path() {
        let plan = rescue_candidate_plan();
        let evidence = rescue_candidate_broker_evidence(&plan.plan_id);
        let mut rescue = Session::new(RESCUE_CANDIDATE_TARGET, SessionMode::LinuxRescue);
        let admission = rescue
            .stage_rescue_fstab_broker_candidate(&plan, &evidence, 6)
            .expect("closed broker admission");
        assert_eq!(rescue.state(), &State::Plan);
        assert_eq!(admission.binding().session_id(), "S-rescue-1");
        assert_eq!(admission.binding().plan_hash(), RESCUE_CANDIDATE_PLAN_HASH);
        assert_eq!(
            admission.binding().target_snapshot(),
            RESCUE_CANDIDATE_TARGET_SNAPSHOT
        );

        let mut non_rescue = Session::new(RESCUE_CANDIDATE_TARGET, SessionMode::NonLinux);
        assert_eq!(
            non_rescue.stage_rescue_fstab_broker_candidate(&plan, &evidence, 6),
            Err(RescueFstabCandidateAdmissionError::WrongSessionMode)
        );
        assert_eq!(non_rescue.state(), &State::Observe);
    }

    #[cfg(feature = "rescue-fstab-production-candidate")]
    #[test]
    fn broker_evidence_rejects_open_contracts_and_cross_plan_binding() {
        assert_eq!(
            RescueFstabBrokerDerivedEvidence::new(
                "S-rescue-1",
                "P-rescue-fstab-candidate",
                RESCUE_CANDIDATE_PLAN_HASH,
                RESCUE_CANDIDATE_TARGET,
                RESCUE_CANDIDATE_TARGET_SNAPSHOT,
                "linux.anything.execute",
                RESCUE_FSTAB_FINDING_ID,
                RESCUE_FSTAB_FINDING_VERSION,
                RESCUE_FSTAB_RESOURCE_ID,
                [
                    (
                        RESCUE_FSTAB_EVIDENCE_IDS[0].to_owned(),
                        RESCUE_CANDIDATE_PLAN_HASH.to_owned()
                    ),
                    (
                        RESCUE_FSTAB_EVIDENCE_IDS[1].to_owned(),
                        RESCUE_CANDIDATE_TARGET_SNAPSHOT.to_owned()
                    ),
                ],
            ),
            Err(RescueFstabCandidateAdmissionError::InvalidBrokerEvidence)
        );

        let plan = rescue_candidate_plan();
        let evidence = rescue_candidate_broker_evidence("P-other-plan");
        let mut session = Session::new(RESCUE_CANDIDATE_TARGET, SessionMode::LinuxRescue);
        assert_eq!(
            session.stage_rescue_fstab_broker_candidate(&plan, &evidence, 6),
            Err(RescueFstabCandidateAdmissionError::InvalidBrokerEvidence)
        );
        assert_eq!(session.state(), &State::Observe);
    }

    #[cfg(feature = "rescue-fstab-production-candidate")]
    #[test]
    fn rescue_candidate_rejects_invalid_binding_and_policy_without_staging() {
        let plan = rescue_candidate_plan();
        let mut session = diagnosed_rescue_candidate_session();
        assert_eq!(
            session.stage_rescue_fstab_production_candidate(
                &plan,
                "session-without-type",
                RESCUE_CANDIDATE_PLAN_HASH,
                RESCUE_CANDIDATE_TARGET_SNAPSHOT,
                6,
            ),
            Err(RescueFstabCandidateAdmissionError::InvalidBinding)
        );
        assert_eq!(session.state(), &State::Diagnose);

        assert_eq!(
            session.stage_rescue_fstab_production_candidate(
                &plan,
                "S-rescue-1",
                "sha256:not-a-hash",
                RESCUE_CANDIDATE_TARGET_SNAPSHOT,
                6,
            ),
            Err(RescueFstabCandidateAdmissionError::InvalidBinding)
        );
        assert_eq!(session.state(), &State::Diagnose);

        assert_eq!(
            session.stage_rescue_fstab_production_candidate(
                &plan,
                "S-rescue-1",
                RESCUE_CANDIDATE_PLAN_HASH,
                RESCUE_CANDIDATE_TARGET_SNAPSHOT,
                u64::MAX,
            ),
            Err(RescueFstabCandidateAdmissionError::SequenceExhausted)
        );
        assert_eq!(session.state(), &State::Diagnose);

        let mut drifted = plan;
        drifted.steps[0].evidence_ids.reverse();
        assert_eq!(
            session.stage_rescue_fstab_production_candidate(
                &drifted,
                "S-rescue-1",
                RESCUE_CANDIDATE_PLAN_HASH,
                RESCUE_CANDIDATE_TARGET_SNAPSHOT,
                6,
            ),
            Err(RescueFstabCandidateAdmissionError::PolicyRejected(
                PolicyError::InvalidRescueFstabEvidence
            ))
        );
        assert_eq!(session.state(), &State::Diagnose);
    }

    #[cfg(feature = "rescue-fstab-production-candidate")]
    #[test]
    fn rescue_candidate_approval_is_exact_bound_fresh_and_single_use() {
        let mut session = diagnosed_rescue_candidate_session();
        let mut admission = session
            .stage_rescue_fstab_production_candidate(
                &rescue_candidate_plan(),
                "S-rescue-1",
                RESCUE_CANDIDATE_PLAN_HASH,
                RESCUE_CANDIDATE_TARGET_SNAPSHOT,
                6,
            )
            .expect("stage candidate");
        let binding = admission.binding().clone();
        assert_eq!(admission.approval_sha256(), None);

        assert_eq!(
            RescueFstabCandidateApproval::new(
                binding.clone(),
                "A-rescue-1",
                0,
                RESCUE_FSTAB_TYPED_CONFIRMATION,
            ),
            Err(RescueFstabCandidateAdmissionError::InvalidApproval)
        );

        for sequence in [6, 8] {
            let approval = RescueFstabCandidateApproval::new(
                binding.clone(),
                "A-rescue-1",
                sequence,
                RESCUE_FSTAB_TYPED_CONFIRMATION,
            )
            .expect("well-formed but non-next approval");
            assert_eq!(
                admission.approve(&approval),
                Err(RescueFstabCandidateAdmissionError::NonMonotonicApproval)
            );
        }

        for confirmation in ["disabilita voce fstab", "DISABILITA VOCE FSTAB "] {
            let approval =
                RescueFstabCandidateApproval::new(binding.clone(), "A-rescue-1", 7, confirmation)
                    .expect("well-formed approval");
            assert_eq!(
                admission.approve(&approval),
                Err(RescueFstabCandidateAdmissionError::TypedConfirmationMismatch)
            );
        }

        for foreign_binding in [
            RescueFstabCandidateBinding::new(
                "S-foreign",
                binding.plan_id(),
                binding.plan_hash(),
                binding.target_fingerprint(),
                binding.target_snapshot(),
            ),
            RescueFstabCandidateBinding::new(
                binding.session_id(),
                binding.plan_id(),
                format!("sha256:{}", "d".repeat(64)),
                binding.target_fingerprint(),
                binding.target_snapshot(),
            ),
            RescueFstabCandidateBinding::new(
                binding.session_id(),
                binding.plan_id(),
                binding.plan_hash(),
                format!("sha256:{}", "e".repeat(64)),
                binding.target_snapshot(),
            ),
            RescueFstabCandidateBinding::new(
                binding.session_id(),
                binding.plan_id(),
                binding.plan_hash(),
                binding.target_fingerprint(),
                format!("sha256:{}", "f".repeat(64)),
            ),
        ] {
            let approval = RescueFstabCandidateApproval::new(
                foreign_binding.expect("valid foreign binding"),
                "A-rescue-1",
                7,
                RESCUE_FSTAB_TYPED_CONFIRMATION,
            )
            .expect("well-formed foreign approval");
            assert_eq!(
                admission.approve(&approval),
                Err(RescueFstabCandidateAdmissionError::BindingMismatch)
            );
        }

        let approval = RescueFstabCandidateApproval::new(
            binding,
            "A-rescue-1",
            7,
            RESCUE_FSTAB_TYPED_CONFIRMATION,
        )
        .expect("exact approval");
        assert_eq!(approval.session_id(), "S-rescue-1");
        admission.approve(&approval).expect("approve once");
        assert_eq!(
            admission.state(),
            RescueFstabCandidateAdmissionState::Approved
        );
        assert_eq!(admission.approval_id(), Some("A-rescue-1"));
        assert_eq!(admission.approval_sequence(), Some(7));
        let approval_sha256 = admission.approval_sha256().expect("accepted approval hash");
        assert!(valid_rescue_candidate_sha256(approval_sha256));
        assert_eq!(approval_sha256, rescue_fstab_approval_sha256(&approval));
        assert_eq!(
            admission.approve(&approval),
            Err(RescueFstabCandidateAdmissionError::ApprovalReplay)
        );
    }

    #[cfg(feature = "rescue-fstab-production-candidate")]
    #[test]
    fn rollback_plan_hash_is_canonical_and_binds_the_source_and_child_id() {
        let transaction = format!("sha256:{}", "d".repeat(64));
        let (plan, first) = canonical_rescue_fstab_rollback_plan(
            "P-rescue-fstab-rollback",
            "RB-rescue-rollback",
            RESCUE_CANDIDATE_TARGET,
            "B-source-backup",
            &transaction,
        )
        .expect("canonical rollback plan");
        let (_, repeated) = canonical_rescue_fstab_rollback_plan(
            "P-rescue-fstab-rollback",
            "RB-rescue-rollback",
            RESCUE_CANDIDATE_TARGET,
            "B-source-backup",
            &transaction,
        )
        .expect("same canonical rollback plan");
        let (_, different_child) = canonical_rescue_fstab_rollback_plan(
            "P-rescue-fstab-rollback",
            "RB-other-rollback",
            RESCUE_CANDIDATE_TARGET,
            "B-source-backup",
            &transaction,
        )
        .expect("different child rollback plan");
        assert_eq!(plan, rescue_rollback_plan());
        assert_eq!(first, repeated);
        assert_ne!(first, different_child);
        assert!(valid_rescue_candidate_sha256(&first));
    }

    #[cfg(feature = "rescue-fstab-production-candidate")]
    #[test]
    fn rescue_rollback_has_a_distinct_source_bound_fresh_approval() {
        let plan = rescue_rollback_plan();
        let source = RescueFstabRollbackSourceBinding::new(
            "P-rescue-fstab-candidate",
            RESCUE_CANDIDATE_PLAN_HASH,
            "A-source-repair",
            7,
            "B-source-backup",
            format!("sha256:{}", "d".repeat(64)),
            "vault://repair/B-source-backup",
        )
        .expect("committed source receipt");
        let binding = RescueFstabRollbackBinding::new(
            "S-rescue-rollback",
            "RB-rescue-rollback",
            plan.plan_id.clone(),
            format!("sha256:{}", "e".repeat(64)),
            RESCUE_CANDIDATE_TARGET,
            source,
        )
        .expect("rollback binding");
        let mut session = Session::new(RESCUE_CANDIDATE_TARGET, SessionMode::LinuxRescue);
        let mut admission = session
            .stage_rescue_fstab_rollback(&plan, binding.clone())
            .expect("stage rollback");
        assert_eq!(admission.next_approval_sequence(), 8);

        let reused = RescueFstabRollbackApproval::new(
            binding.clone(),
            "A-source-repair",
            8,
            RESCUE_FSTAB_ROLLBACK_TYPED_CONFIRMATION,
        )
        .expect("syntactically valid reused proof");
        assert_eq!(
            admission.approve(&reused),
            Err(RescueFstabRollbackAdmissionError::ApprovalNotFresh)
        );

        let wrong_phrase = RescueFstabRollbackApproval::new(
            binding.clone(),
            "A-fresh-rollback",
            8,
            RESCUE_FSTAB_TYPED_CONFIRMATION,
        )
        .expect("syntactically valid wrong phrase");
        assert_eq!(
            admission.approve(&wrong_phrase),
            Err(RescueFstabRollbackAdmissionError::TypedConfirmationMismatch)
        );

        let fresh = RescueFstabRollbackApproval::new(
            binding,
            "A-fresh-rollback",
            8,
            RESCUE_FSTAB_ROLLBACK_TYPED_CONFIRMATION,
        )
        .expect("fresh rollback proof");
        admission.approve(&fresh).expect("approve rollback");
        assert_eq!(
            admission.state(),
            RescueFstabRollbackAdmissionState::Approved
        );
        assert!(
            admission
                .approval_sha256()
                .is_some_and(valid_rescue_candidate_sha256)
        );
    }

    #[cfg(feature = "fixture-repair-lab")]
    #[test]
    fn exact_fixture_r2_plan_uses_only_the_lab_admission() {
        let plan = fixture_r2_plan();
        let mut phase_zero = diagnosed_fixture_session();
        assert_eq!(phase_zero.stage(&plan), Err(PolicyError::MutationDisabled));
        assert_eq!(phase_zero.state(), &State::Diagnose);

        phase_zero
            .stage_fixture_repair_lab(&plan)
            .expect("stage the exact fixture-only plan");
        assert_eq!(phase_zero.state(), &State::Plan);
    }

    #[cfg(feature = "fixture-repair-lab")]
    #[test]
    fn lab_admission_rejects_contract_drift_without_advancing_state() {
        let mut wrong_action = fixture_r2_plan();
        wrong_action.steps[0].action = "linux.fstab.repair-entry".to_owned();
        let mut session = diagnosed_fixture_session();
        assert_eq!(
            session.stage_fixture_repair_lab(&wrong_action),
            Err(PolicyError::MutationDisabled)
        );
        assert_eq!(session.state(), &State::Diagnose);

        let mut wrong_precondition = fixture_r2_plan();
        wrong_precondition.steps[0].preconditions = vec!["target.still_matches".to_owned()];
        assert_eq!(
            session.stage_fixture_repair_lab(&wrong_precondition),
            Err(PolicyError::InvalidFixturePrecondition)
        );
        assert_eq!(session.state(), &State::Diagnose);

        let mut wrong_target = fixture_r2_plan();
        wrong_target.steps[0].target_fingerprint = format!("sha256:{}", "2".repeat(64));
        assert_eq!(
            session.stage_fixture_repair_lab(&wrong_target),
            Err(PolicyError::IncoherentTargetFingerprint)
        );
        assert_eq!(session.state(), &State::Diagnose);
    }

    #[cfg(feature = "fixture-repair-lab")]
    #[test]
    fn lab_admission_still_requires_the_diagnose_state() {
        let mut session = Session::new(FIXTURE_TARGET, SessionMode::LinuxResident);
        assert_eq!(
            session.stage_fixture_repair_lab(&fixture_r2_plan()),
            Err(PolicyError::MutationDisabled)
        );
        assert_eq!(session.state(), &State::Observe);
    }

    #[cfg(feature = "fixture-repair-lab")]
    #[test]
    fn fixture_repair_transaction_requires_bound_approval_and_ordered_transitions() {
        let mutation = fixture_mutation("P-fixture-repair", 'a');
        let proof = fixture_proof(&mutation, "A-fixture-repair", 7);
        let mut transaction = FixtureRepairTransaction::stage(mutation.clone());

        assert_eq!(
            transaction.begin_repair(&proof),
            Err(FixtureTransactionError::InvalidTransition)
        );
        transaction.approve(&proof).expect("approve repair");
        assert_eq!(transaction.state(), FixtureRepairTransactionState::Approved);

        let changed_binding = fixture_mutation("P-foreign-repair", 'a');
        let changed_proof = fixture_proof(&changed_binding, "A-fixture-repair", 7);
        assert_eq!(
            transaction.begin_repair(&changed_proof),
            Err(FixtureTransactionError::BindingMismatch)
        );
        let changed_approval = fixture_proof(&mutation, "A-foreign-repair", 7);
        assert_eq!(
            transaction.begin_repair(&changed_approval),
            Err(FixtureTransactionError::ApprovalMismatch)
        );

        transaction.begin_repair(&proof).expect("begin repair");
        transaction
            .record_verification(&proof, FixtureVerificationOutcome::Succeeded)
            .expect("record successful verification");
        transaction.complete(&proof).expect("complete repair");
        assert_eq!(
            transaction.state(),
            FixtureRepairTransactionState::Complete(FixtureVerificationOutcome::Succeeded)
        );
        assert_eq!(transaction.binding(), &mutation);
        assert_eq!(
            transaction.complete(&proof),
            Err(FixtureTransactionError::InvalidTransition)
        );
    }

    #[cfg(feature = "fixture-repair-lab")]
    #[test]
    fn fixture_repair_failure_is_an_explicit_completed_outcome() {
        let mutation = fixture_mutation("P-fixture-failed", 'c');
        let proof = fixture_proof(&mutation, "A-fixture-failed", 8);
        let mut transaction = FixtureRepairTransaction::stage(mutation);
        transaction.approve(&proof).expect("approve repair");
        transaction.begin_repair(&proof).expect("begin repair");
        transaction
            .record_verification(&proof, FixtureVerificationOutcome::Failed)
            .expect("record failed verification");
        transaction.complete(&proof).expect("complete failure");
        assert_eq!(
            transaction.state(),
            FixtureRepairTransactionState::Complete(FixtureVerificationOutcome::Failed)
        );
    }

    #[cfg(feature = "fixture-repair-lab")]
    #[test]
    fn fixture_rollback_is_bound_to_repair_but_requires_a_new_approval() {
        let mutation = fixture_mutation("P-fixture-rollback", 'd');
        let repair_plan_hash = format!("sha256:{}", "a".repeat(64));
        let mut transaction = FixtureRollbackTransaction::stage(
            mutation.clone(),
            "A-fixture-repair",
            &repair_plan_hash,
        )
        .expect("stage rollback");
        assert_eq!(transaction.repair_approval_id(), "A-fixture-repair");
        assert_eq!(transaction.repair_plan_hash(), repair_plan_hash);

        let reused_approval = fixture_proof(&mutation, "A-fixture-repair", 9);
        assert_eq!(
            transaction.approve(&reused_approval),
            Err(FixtureTransactionError::RollbackApprovalNotDistinct)
        );
        assert_eq!(transaction.state(), FixtureRollbackTransactionState::Staged);

        let rollback_approval = fixture_proof(&mutation, "A-fixture-rollback", 9);
        transaction
            .approve(&rollback_approval)
            .expect("approve rollback separately");
        transaction
            .begin_rollback(&rollback_approval)
            .expect("begin rollback");
        transaction
            .record_verification(&rollback_approval, FixtureVerificationOutcome::Succeeded)
            .expect("verify rollback");
        transaction
            .complete(&rollback_approval)
            .expect("complete rollback");
        assert_eq!(
            transaction.state(),
            FixtureRollbackTransactionState::Complete(FixtureVerificationOutcome::Succeeded)
        );
    }

    #[test]
    fn wrapper_hash_tampering_fails_before_admission() {
        let bytes = envelope(LinuxSnapshotCapture::resident());
        let mut bound = evidence("local-machine", &bytes);
        bound.sha256 = "0".repeat(64);
        bound.blob_ref = format!("sha256:{}", bound.sha256);
        let mut session = Session::new("sha256:fixture", SessionMode::LinuxResident);
        assert_eq!(
            session.admit_linux_snapshot(&bound, &bytes),
            Err(LinuxSnapshotAdmissionError::InvalidEvidenceBinding)
        );
    }
}
