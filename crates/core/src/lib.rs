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
