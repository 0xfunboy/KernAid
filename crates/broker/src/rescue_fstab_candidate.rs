//! Two-phase, read-only preparation for the disabled Rescue `fstab` candidate.
//!
//! Discovery starts from an intent that contains neither a final plan hash nor
//! approval. The broker retains the selected target guard, observes the exact
//! resource, creates a preview, and only then obtains a real Vault reservation.
//! That reservation becomes part of the immutable plan and audit-only receipt.
//! A later Core approval must consume the prepared authority before an approved
//! transaction can exist. This module contains no mutation implementation.

use kernaid_core::{
    RescueFstabBrokerDerivedEvidence, RescueFstabCandidateAdmission,
    RescueFstabCandidateAdmissionError, RescueFstabCandidateAdmissionState, Session,
    validate_rescue_fstab_production_candidate_plan,
};
use kernaid_linux_pack::{
    production_candidate_contract::{
        ACTION_ID, BACKUP_PHYSICAL_PARENT_POLICY, BACKUP_POLICY_ID, BACKUP_RESERVATION_POLICY_ID,
        CANCELLATION_POLICY_ID, FINDING_ID, FINDING_VERSION, IDEMPOTENCY_POLICY_ID, PREFLIGHT_ID,
        REDACTION_POLICY_ID, RESOURCE_ID, ROLLBACK_ID, SUPPORTED_FILESYSTEM,
        TRANSACTION_TIMEOUT_MILLISECONDS, VALIDATE_ID,
    },
    rescue_fstab_candidate::{
        DisableMissingUuidPreview, PreviewError, preview_disable_missing_uuid,
    },
    rescue_fstab_transaction_candidate::{
        BootVaultBackupCapability, CandidateEvidenceBinding, CandidatePlanClaims,
        CandidatePlanClaimsInput, CandidateTransactionError, FstabCandidateTransactionPlan,
        SelectedTargetCapability,
    },
};
use kernaid_protocol::{
    ActionStep, Risk, ValidatedPlan,
    rescue_repair::{
        RESCUE_FSTAB_EVIDENCE_IDS, RESCUE_FSTAB_READY_OUTCOME, RescueFstabEvidenceBinding,
        RescueFstabPreflightIntent, RescueFstabPrepareRequest, RescueFstabPreparedPlanReceipt,
    },
    rescue_repair_vault::RepairFileMetadataV1,
};
use sha2::{Digest, Sha256};
use std::{collections::BTreeSet, fmt, time::Instant};
use zeroize::Zeroizing;

use crate::target_physical_parent::RescueTargetPhysicalParentGuard;

impl RescueTargetPhysicalParentGuard {
    /// Rebuilds the path-free transaction claim from the retained leaf and
    /// physical-parent descriptors. No caller supplies physical ancestry.
    pub fn selected_target_claims(
        &self,
    ) -> Result<SelectedTargetCapability, CandidateTransactionError> {
        self.revalidate()
            .map_err(|_| CandidateTransactionError::InvalidCapability)?;
        SelectedTargetCapability::new(
            self.target_claims().target_id(),
            self.target_claims().scan_fingerprint(),
            self.target_claims().recovery_fingerprint(),
            self.physical_parent_fingerprint(),
        )
    }
}

/// Sanitized failures at the target/Vault resolver boundary.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RescueFstabCapabilityResolutionError {
    Unavailable,
    IdentityChanged,
    LockUnavailable,
    TimedOut,
}

/// Exact observations collected while the target guard is retained.
///
/// This value is neither serializable nor cloneable. `Debug` redacts bytes,
/// UUIDs, and capability identities.
pub struct TrustedRescueFstabObservation {
    resolved_target_fingerprint: String,
    fstab_bytes: Zeroizing<Vec<u8>>,
    metadata: RepairFileMetadataV1,
    observed_uuids: BTreeSet<String>,
    target: SelectedTargetCapability,
    evidence: [CandidateEvidenceBinding; 2],
}

impl TrustedRescueFstabObservation {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        resolved_target_fingerprint: impl Into<String>,
        fstab_bytes: Vec<u8>,
        metadata: RepairFileMetadataV1,
        observed_uuids: BTreeSet<String>,
        target: SelectedTargetCapability,
        evidence: [CandidateEvidenceBinding; 2],
    ) -> Self {
        Self {
            resolved_target_fingerprint: resolved_target_fingerprint.into(),
            fstab_bytes: Zeroizing::new(fstab_bytes),
            metadata,
            observed_uuids,
            target,
            evidence,
        }
    }

    pub fn fstab_bytes(&self) -> &[u8] {
        &self.fstab_bytes
    }

    pub const fn metadata(&self) -> &RepairFileMetadataV1 {
        &self.metadata
    }

    pub(crate) fn target_recovery_fingerprint(&self) -> &str {
        self.target.recovery_fingerprint()
    }
}

impl fmt::Debug for TrustedRescueFstabObservation {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("TrustedRescueFstabObservation")
            .field("resolved_target_fingerprint", &"[opaque fingerprint]")
            .field("fstab_bytes", &"[redacted]")
            .field("metadata", &self.metadata)
            .field("observed_uuid_count", &self.observed_uuids.len())
            .field("target", &"[opaque capability]")
            .field("evidence", &"[opaque hashes]")
            .finish()
    }
}

/// A live reservation must be able to prove its binding and cancel itself.
///
/// Cancellation consumes the guard and receives the caller's one absolute
/// deadline. Implementations must never treat dropping a local descriptor as
/// equivalent to a successful persistent Vault cancellation.
pub trait RescueFstabVaultReservation {
    fn reservation_id(&self) -> &str;
    fn reservation_binding_sha256(&self) -> &str;
    fn cancel(self, deadline: Instant) -> Result<(), RescueFstabCapabilityResolutionError>;
}

/// Trusted two-phase resolver boundary: target observation first, Vault
/// reservation second. Every method that may perform I/O receives the same
/// caller-supplied absolute deadline.
pub trait RescueFstabPreflightCapabilityResolver {
    /// Opaque, non-cloneable guard retaining the selected target read-only.
    type TargetGuard;
    /// Opaque, non-cloneable live Vault reservation.
    type VaultReservation: RescueFstabVaultReservation;

    fn acquire_target_guard(
        &mut self,
        request: &RescueFstabPrepareRequest,
        deadline: Instant,
    ) -> Result<Self::TargetGuard, RescueFstabCapabilityResolutionError>;

    fn observe_under_target_guard(
        &mut self,
        request: &RescueFstabPrepareRequest,
        target_guard: &Self::TargetGuard,
        deadline: Instant,
    ) -> Result<TrustedRescueFstabObservation, RescueFstabCapabilityResolutionError>;

    /// Creates a real reservation only after identity, evidence, snapshot and
    /// preview validation. An error return must not leave a live reservation.
    fn reserve_vault(
        &mut self,
        intent: &RescueFstabPreflightIntent,
        target_guard: &Self::TargetGuard,
        observation: &TrustedRescueFstabObservation,
        preview: &DisableMissingUuidPreview,
        deadline: Instant,
    ) -> Result<
        (Self::VaultReservation, BootVaultBackupCapability),
        RescueFstabCapabilityResolutionError,
    >;

    /// Stable opaque identity of the already-held target guard. This accessor
    /// must perform no I/O.
    fn target_guard_identity<'guard>(&self, target_guard: &'guard Self::TargetGuard)
    -> &'guard str;
}

/// Broker-owned authority after observation, preview and Vault reservation,
/// but before Core approval. The receipt alone grants no authority.
#[must_use = "authorize this prepared plan or cancel its Vault reservation explicitly"]
pub struct PreparedRescueFstabPlan<TargetGuard, Reservation> {
    request_id: String,
    receipt: RescueFstabPreparedPlanReceipt,
    plan: FstabCandidateTransactionPlan,
    preview: DisableMissingUuidPreview,
    backup_bytes: Zeroizing<Vec<u8>>,
    metadata: RepairFileMetadataV1,
    target_guard: TargetGuard,
    reservation: Reservation,
}

impl<TargetGuard, Reservation> PreparedRescueFstabPlan<TargetGuard, Reservation>
where
    Reservation: RescueFstabVaultReservation,
{
    /// Audit evidence only. It is cloneable but cannot authorize execution.
    pub fn receipt(&self) -> &RescueFstabPreparedPlanReceipt {
        &self.receipt
    }

    pub fn request_id(&self) -> &str {
        &self.request_id
    }

    pub fn plan(&self) -> &FstabCandidateTransactionPlan {
        &self.plan
    }

    pub fn before_sha256(&self) -> &str {
        self.preview.before_sha256()
    }

    pub fn after_sha256(&self) -> &str {
        self.preview.after_sha256()
    }

    pub fn diff_sha256(&self) -> &str {
        self.preview.diff_sha256()
    }

    /// Canonical Core policy view of this exact broker transaction plan.
    pub fn validated_plan(&self) -> Result<ValidatedPlan, CandidateTransactionError> {
        validated_plan_from_rescue_fstab_transaction_plan(
            &self.plan,
            self.receipt.intent().target_fingerprint(),
        )
    }

    /// Advance a fresh Rescue Core session directly from the observation
    /// retained by this prepared authority. No UI evidence or snapshot is
    /// accepted by this adapter.
    pub fn stage_core_admission(
        &self,
        session: &mut Session,
        last_approval_sequence: u64,
    ) -> Result<RescueFstabCandidateAdmission, RescueFstabCandidateAdmissionError> {
        let plan = self
            .validated_plan()
            .map_err(|_| RescueFstabCandidateAdmissionError::InvalidBrokerEvidence)?;
        let evidence =
            broker_derived_core_evidence(&self.plan, self.receipt.intent().target_fingerprint())
                .map_err(|_| RescueFstabCandidateAdmissionError::InvalidBrokerEvidence)?;
        session.stage_rescue_fstab_broker_candidate(&plan, &evidence, last_approval_sequence)
    }

    /// Consumes this prepared authority and its approved Core admission.
    /// Rejection explicitly cancels the persistent reservation; therefore an
    /// absolute deadline is required even though the successful path is pure.
    pub fn authorize(
        self,
        approved: RescueFstabCandidateAdmission,
        cancellation_deadline: Instant,
    ) -> Result<ApprovedRescueFstabTransaction<TargetGuard, Reservation>, RescueFstabPreflightError>
    {
        if let Err(error) = validate_approved_admission(&approved, &self.receipt, &self.plan) {
            let Self { reservation, .. } = self;
            return fail_after_reservation(reservation, cancellation_deadline, error);
        }
        let Self {
            request_id: _,
            receipt,
            plan,
            preview,
            backup_bytes,
            metadata,
            target_guard,
            reservation,
        } = self;
        Ok(ApprovedRescueFstabTransaction {
            receipt,
            plan,
            preview,
            backup_bytes,
            metadata,
            admission: approved,
            target_guard,
            reservation,
        })
    }

    /// Explicitly releases a prepared plan that will not be approved.
    pub fn cancel(self, deadline: Instant) -> Result<(), RescueFstabPreflightError> {
        let Self { reservation, .. } = self;
        reservation
            .cancel(deadline)
            .map_err(|_| RescueFstabPreflightError::CancellationFailed)
    }
}

impl<TargetGuard, Reservation> fmt::Debug for PreparedRescueFstabPlan<TargetGuard, Reservation> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PreparedRescueFstabPlan")
            .field("request_id", &"[opaque]")
            .field("receipt", &self.receipt)
            .field("plan_hash", &self.plan.plan_sha256())
            .field("before_sha256", &self.preview.before_sha256())
            .field("after_sha256", &self.preview.after_sha256())
            .field("backup_bytes", &"[redacted]")
            .field("metadata", &self.metadata)
            .field("target_guard", &"[opaque guard]")
            .field("reservation", &"[opaque guard]")
            .finish()
    }
}

/// Fully bound, non-cloneable authority after the exact Core approval.
/// No executor or mutation method is exposed in this phase.
#[must_use]
pub struct ApprovedRescueFstabTransaction<TargetGuard, Reservation> {
    receipt: RescueFstabPreparedPlanReceipt,
    plan: FstabCandidateTransactionPlan,
    preview: DisableMissingUuidPreview,
    backup_bytes: Zeroizing<Vec<u8>>,
    metadata: RepairFileMetadataV1,
    admission: RescueFstabCandidateAdmission,
    target_guard: TargetGuard,
    reservation: Reservation,
}

/// Crate-private one-shot material consumed by the closed production
/// executor. Keeping this transfer private prevents callers from separating
/// approval, target authority, backup bytes, and the live Vault reservation.
pub(crate) struct ApprovedRescueFstabExecutionParts<TargetGuard, Reservation> {
    pub(crate) plan: FstabCandidateTransactionPlan,
    pub(crate) preview: DisableMissingUuidPreview,
    pub(crate) backup_bytes: Zeroizing<Vec<u8>>,
    pub(crate) metadata: RepairFileMetadataV1,
    pub(crate) admission: RescueFstabCandidateAdmission,
    pub(crate) target_guard: TargetGuard,
    pub(crate) reservation: Reservation,
}

impl<TargetGuard, Reservation> ApprovedRescueFstabTransaction<TargetGuard, Reservation> {
    pub fn receipt(&self) -> &RescueFstabPreparedPlanReceipt {
        &self.receipt
    }

    pub fn plan(&self) -> &FstabCandidateTransactionPlan {
        &self.plan
    }

    pub fn backup_bytes(&self) -> &[u8] {
        &self.backup_bytes
    }

    pub const fn metadata(&self) -> &RepairFileMetadataV1 {
        &self.metadata
    }

    pub fn proposed_fstab(&self) -> &[u8] {
        self.preview.proposed_fstab()
    }

    pub fn approval_id(&self) -> &str {
        self.admission
            .approval_id()
            .expect("Approved admission always has an approval ID")
    }

    pub fn approval_sequence(&self) -> u64 {
        self.admission
            .approval_sequence()
            .expect("Approved admission always has an approval sequence")
    }

    pub fn approval_sha256(&self) -> &str {
        self.admission
            .approval_sha256()
            .expect("Approved admission always has an approval hash")
    }

    pub const fn target_guard(&self) -> &TargetGuard {
        &self.target_guard
    }

    pub const fn reservation(&self) -> &Reservation {
        &self.reservation
    }

    pub(crate) fn into_execution_parts(
        self,
    ) -> ApprovedRescueFstabExecutionParts<TargetGuard, Reservation> {
        let Self {
            receipt: _,
            plan,
            preview,
            backup_bytes,
            metadata,
            admission,
            target_guard,
            reservation,
        } = self;
        ApprovedRescueFstabExecutionParts {
            plan,
            preview,
            backup_bytes,
            metadata,
            admission,
            target_guard,
            reservation,
        }
    }
}

impl<TargetGuard, Reservation> ApprovedRescueFstabTransaction<TargetGuard, Reservation>
where
    Reservation: RescueFstabVaultReservation,
{
    /// Explicitly aborts an approved transaction before any executor consumes
    /// it. The retained target guard and all byte material are dropped only
    /// after the persistent Vault reservation has been asked to cancel.
    pub fn cancel(self, deadline: Instant) -> Result<(), RescueFstabPreflightError> {
        let Self { reservation, .. } = self;
        reservation
            .cancel(deadline)
            .map_err(|_| RescueFstabPreflightError::CancellationFailed)
    }
}

impl<TargetGuard, Reservation> fmt::Debug
    for ApprovedRescueFstabTransaction<TargetGuard, Reservation>
{
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ApprovedRescueFstabTransaction")
            .field("receipt", &self.receipt)
            .field("plan_hash", &self.plan.plan_sha256())
            .field("backup_bytes", &"[redacted]")
            .field("proposed_fstab_bytes", &"[redacted]")
            .field("metadata", &self.metadata)
            .field("approval", &"[bound Core admission]")
            .field("target_guard", &"[opaque guard]")
            .field("reservation", &"[opaque guard]")
            .finish()
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RescueFstabPreflightError {
    ApprovalRequired,
    AdmissionBindingMismatch,
    ApprovalBindingMismatch,
    TargetIdentityMismatch,
    EvidenceBindingMismatch,
    TargetSnapshotMismatch,
    Resolver(RescueFstabCapabilityResolutionError),
    PreviewRejected(PreviewError),
    TransactionRejected(CandidateTransactionError),
    ReservationBindingMismatch,
    ReceiptRejected,
    CancellationFailed,
}

/// Broker-owned preparation for the sole production candidate.
///
/// `request` contains only correlation/session/plan identifiers and the three
/// boot-local target selection claims. The broker acquires the root-issued
/// capability, observes exact bytes and the UUID inventory, derives every
/// evidence and snapshot binding, reserves the Vault, and only then returns a
/// non-cloneable prepared authority. All resolver I/O shares `deadline`.
pub fn prepare_rescue_fstab_candidate<Resolver>(
    request: RescueFstabPrepareRequest,
    resolver: &mut Resolver,
    deadline: Instant,
) -> Result<
    PreparedRescueFstabPlan<Resolver::TargetGuard, Resolver::VaultReservation>,
    RescueFstabPreflightError,
>
where
    Resolver: RescueFstabPreflightCapabilityResolver,
{
    let target_guard = resolver
        .acquire_target_guard(&request, deadline)
        .map_err(RescueFstabPreflightError::Resolver)?;
    let observation = resolver
        .observe_under_target_guard(&request, &target_guard, deadline)
        .map_err(RescueFstabPreflightError::Resolver)?;

    validate_observation(&request, &observation)?;
    let preview =
        preview_disable_missing_uuid(&observation.fstab_bytes, &observation.observed_uuids)
            .map_err(RescueFstabPreflightError::PreviewRejected)?;
    let intent = broker_owned_intent(&request, &observation, &preview)?;

    let claims =
        canonical_claims(&intent).map_err(RescueFstabPreflightError::TransactionRejected)?;
    let (reservation, vault) = resolver
        .reserve_vault(&intent, &target_guard, &observation, &preview, deadline)
        .map_err(RescueFstabPreflightError::Resolver)?;

    if reservation.reservation_id() != vault.reservation_id()
        || reservation.reservation_binding_sha256() != vault.reservation_binding_sha256()
    {
        return fail_after_reservation(
            reservation,
            deadline,
            RescueFstabPreflightError::ReservationBindingMismatch,
        );
    }

    let TrustedRescueFstabObservation {
        fstab_bytes,
        metadata,
        target,
        evidence,
        ..
    } = observation;
    let plan = match FstabCandidateTransactionPlan::stage(
        &preview,
        claims,
        target,
        vault,
        evidence.into(),
    ) {
        Ok(plan) => plan,
        Err(error) => {
            return fail_after_reservation(
                reservation,
                deadline,
                RescueFstabPreflightError::TransactionRejected(error),
            );
        }
    };

    let receipt = match RescueFstabPreparedPlanReceipt::new(
        intent,
        plan.plan_sha256(),
        plan.after_sha256(),
        plan.diff_sha256(),
        plan.vault().vault_id(),
        plan.vault().reservation_id(),
        plan.vault().reservation_binding_sha256(),
        plan.vault().backup_locator(),
        plan.vault().vault_identity_fingerprint(),
        plan.target().recovery_fingerprint(),
        plan.target().physical_parent_fingerprint(),
        plan.vault().physical_parent_fingerprint(),
        plan.vault().required_capacity_bytes(),
        plan.vault().reserved_capacity_bytes(),
        resolver.target_guard_identity(&target_guard),
        RESCUE_FSTAB_READY_OUTCOME,
    ) {
        Ok(receipt) => receipt,
        Err(_) => {
            return fail_after_reservation(
                reservation,
                deadline,
                RescueFstabPreflightError::ReceiptRejected,
            );
        }
    };

    Ok(PreparedRescueFstabPlan {
        request_id: request.request_id().to_owned(),
        receipt,
        plan,
        preview,
        backup_bytes: fstab_bytes,
        metadata,
        target_guard,
        reservation,
    })
}

fn broker_owned_intent(
    request: &RescueFstabPrepareRequest,
    observation: &TrustedRescueFstabObservation,
    preview: &DisableMissingUuidPreview,
) -> Result<RescueFstabPreflightIntent, RescueFstabPreflightError> {
    if preview.before_sha256() != prefixed_digest(observation.fstab_bytes()) {
        return Err(RescueFstabPreflightError::TargetSnapshotMismatch);
    }
    let evidence = observation.evidence.each_ref().map(|binding| {
        RescueFstabEvidenceBinding::new(binding.evidence_id(), binding.sha256())
            .map_err(|_| RescueFstabPreflightError::EvidenceBindingMismatch)
    });
    let [first, second] = evidence;
    RescueFstabPreflightIntent::new(
        request.session_id(),
        request.plan_id(),
        request.target_fingerprint(),
        preview.before_sha256(),
        RESOURCE_ID,
        request.target_id(),
        request.scan_fingerprint(),
        [first?, second?],
    )
    .map_err(|_| RescueFstabPreflightError::AdmissionBindingMismatch)
}

fn validate_observation(
    request: &RescueFstabPrepareRequest,
    observation: &TrustedRescueFstabObservation,
) -> Result<(), RescueFstabPreflightError> {
    if observation.resolved_target_fingerprint != request.target_fingerprint()
        || observation.target.target_id() != request.target_id()
        || observation.target.scan_fingerprint() != request.scan_fingerprint()
    {
        return Err(RescueFstabPreflightError::TargetIdentityMismatch);
    }
    for (observed, expected_id) in observation.evidence.iter().zip(RESCUE_FSTAB_EVIDENCE_IDS) {
        if observed.evidence_id() != expected_id {
            return Err(RescueFstabPreflightError::EvidenceBindingMismatch);
        }
    }
    Ok(())
}

fn prefixed_digest(bytes: &[u8]) -> String {
    format!("sha256:{:x}", Sha256::digest(bytes))
}

fn validate_approved_admission(
    admission: &RescueFstabCandidateAdmission,
    receipt: &RescueFstabPreparedPlanReceipt,
    plan: &FstabCandidateTransactionPlan,
) -> Result<(), RescueFstabPreflightError> {
    if admission.state() != RescueFstabCandidateAdmissionState::Approved {
        return Err(RescueFstabPreflightError::ApprovalRequired);
    }
    let intent = receipt.intent();
    let binding = admission.binding();
    if binding.session_id() != intent.session_id()
        || binding.plan_id() != intent.plan_id()
        || binding.plan_hash() != receipt.plan_hash()
        || binding.plan_hash() != plan.plan_sha256()
        || binding.target_fingerprint() != intent.target_fingerprint()
        || binding.target_snapshot() != intent.target_snapshot()
        || binding.target_snapshot() != receipt.before_sha256()
        || binding.resource_id() != intent.resource_id()
        || plan.claims().session_id() != intent.session_id()
        || plan.claims().plan_id() != intent.plan_id()
        || plan.claims().resource_id() != intent.resource_id()
        || plan.before_sha256() != intent.target_snapshot()
        || plan.after_sha256() != receipt.after_sha256()
        || plan.diff_sha256() != receipt.diff_sha256()
        || plan.target().target_id() != intent.target_id()
        || plan.target().scan_fingerprint() != intent.scan_fingerprint()
        || receipt.target_recovery_fingerprint() != plan.target().recovery_fingerprint()
    {
        return Err(RescueFstabPreflightError::AdmissionBindingMismatch);
    }
    if admission.approval_id().is_none()
        || admission.approval_sequence().is_none()
        || admission.approval_sequence() != Some(admission.next_approval_sequence())
    {
        return Err(RescueFstabPreflightError::ApprovalBindingMismatch);
    }
    Ok(())
}

fn fail_after_reservation<T, Reservation>(
    reservation: Reservation,
    deadline: Instant,
    error: RescueFstabPreflightError,
) -> Result<T, RescueFstabPreflightError>
where
    Reservation: RescueFstabVaultReservation,
{
    reservation
        .cancel(deadline)
        .map_err(|_| RescueFstabPreflightError::CancellationFailed)?;
    Err(error)
}

fn canonical_claims(
    intent: &RescueFstabPreflightIntent,
) -> Result<CandidatePlanClaims, CandidateTransactionError> {
    canonical_claims_for(intent.session_id(), intent.plan_id())
}

fn canonical_claims_for(
    session_id: &str,
    plan_id: &str,
) -> Result<CandidatePlanClaims, CandidateTransactionError> {
    CandidatePlanClaims::admit(CandidatePlanClaimsInput {
        session_id,
        plan_id,
        action_id: ACTION_ID,
        resource_id: RESOURCE_ID,
        finding_id: FINDING_ID,
        finding_version: FINDING_VERSION,
        risk: "R2",
        supported_filesystem: SUPPORTED_FILESYSTEM,
        preflight_id: PREFLIGHT_ID,
        backup_policy_id: BACKUP_POLICY_ID,
        backup_reservation_policy_id: BACKUP_RESERVATION_POLICY_ID,
        backup_physical_parent_policy: BACKUP_PHYSICAL_PARENT_POLICY,
        validation_id: VALIDATE_ID,
        rollback_id: ROLLBACK_ID,
        timeout_milliseconds: TRANSACTION_TIMEOUT_MILLISECONDS,
        cancellation_policy_id: CANCELLATION_POLICY_ID,
        idempotency_policy_id: IDEMPOTENCY_POLICY_ID,
        redaction_policy_id: REDACTION_POLICY_ID,
    })
}

/// Build the canonical Core policy plan for an already staged candidate
/// transaction. The variable target fingerprint is supplied from the same
/// broker-owned prepared receipt; every other plan field is reconstructed
/// from, and checked against, the immutable transaction claims.
pub fn validated_plan_from_rescue_fstab_transaction_plan(
    transaction: &FstabCandidateTransactionPlan,
    target_fingerprint: &str,
) -> Result<ValidatedPlan, CandidateTransactionError> {
    let expected = canonical_claims_for(
        transaction.claims().session_id(),
        transaction.claims().plan_id(),
    )?;
    if transaction.claims() != &expected {
        return Err(CandidateTransactionError::PlanContractMismatch);
    }
    let plan = ValidatedPlan {
        plan_id: transaction.claims().plan_id().to_owned(),
        target_fingerprint: target_fingerprint.to_owned(),
        steps: vec![ActionStep {
            action: transaction.claims().action_id().to_owned(),
            risk: Risk::R2,
            target_fingerprint: target_fingerprint.to_owned(),
            evidence_ids: transaction
                .evidence()
                .iter()
                .map(|binding| binding.evidence_id().to_owned())
                .collect(),
            preconditions: vec![transaction.claims().preflight_id().to_owned()],
            backup: Some("required".to_owned()),
            validation: transaction.claims().validation_id().to_owned(),
            rollback: Some(transaction.claims().rollback_id().to_owned()),
        }],
    };
    validate_rescue_fstab_production_candidate_plan(&plan, target_fingerprint)
        .map_err(|_| CandidateTransactionError::PlanContractMismatch)?;
    Ok(plan)
}

fn broker_derived_core_evidence(
    transaction: &FstabCandidateTransactionPlan,
    target_fingerprint: &str,
) -> Result<RescueFstabBrokerDerivedEvidence, CandidateTransactionError> {
    let _ = validated_plan_from_rescue_fstab_transaction_plan(transaction, target_fingerprint)?;
    let evidence = transaction.evidence().each_ref().map(|binding| {
        (
            binding.evidence_id().to_owned(),
            binding.sha256().to_owned(),
        )
    });
    RescueFstabBrokerDerivedEvidence::new(
        transaction.claims().session_id(),
        transaction.claims().plan_id(),
        transaction.plan_sha256(),
        target_fingerprint,
        transaction.before_sha256(),
        transaction.claims().action_id(),
        transaction.claims().finding_id(),
        transaction.claims().finding_version(),
        transaction.claims().resource_id(),
        evidence,
    )
    .map_err(|_| CandidateTransactionError::PlanContractMismatch)
}

#[cfg(test)]
mod tests {
    use super::*;
    use kernaid_core::{
        RESCUE_FSTAB_TYPED_CONFIRMATION, RescueFstabCandidateAdmissionError,
        RescueFstabCandidateApproval, Session, SessionMode,
    };
    use kernaid_evidence::{
        Evidence,
        linux_snapshot::{
            COLLECTION_SCOPE, COLLECTOR as LINUX_SNAPSHOT_COLLECTOR,
            CONTENT_TYPE as LINUX_SNAPSHOT_CONTENT_TYPE, LinuxBoot, LinuxConfiguration,
            LinuxFilesystemTopology, LinuxFstabSummary, LinuxNormalizedSnapshot,
            LinuxNormalizedSnapshotEnvelope, LinuxPackageDatabases, LinuxRelease,
            LinuxSnapshotCapture, SNAPSHOT_SCOPE,
        },
    };
    use kernaid_protocol::{ActionStep, Risk, ValidatedPlan};
    use sha2::{Digest, Sha256};
    use std::sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
    };
    use std::time::Duration;

    const SESSION_ID: &str = "S-rescue-preflight";
    const PLAN_ID: &str = "P-rescue-fstab";
    const APPROVAL_ID: &str = "A-rescue-fstab";
    const APPROVAL_SEQUENCE: u64 = 7;
    const REQUEST_ID: &str = "R-01234567-89ab-cdef-0123-456789abcdef";
    const FSTAB: &[u8] =
        b"UUID=AAAA-BBBB / ext4 defaults 0 1\nUUID=DEAD-BEEF /srv/archive ext4 defaults 0 2\n";

    fn hash(character: char) -> String {
        format!("sha256:{}", character.to_string().repeat(64))
    }

    fn scan(character: char) -> String {
        format!("scan:{}", character.to_string().repeat(64))
    }

    fn recovery(character: char) -> String {
        format!("recovery:{}", character.to_string().repeat(64))
    }

    fn target_id() -> String {
        format!("target:{}", "2".repeat(64))
    }

    fn observed() -> BTreeSet<String> {
        BTreeSet::from(["aaaa-bbbb".to_owned()])
    }

    fn target(parent: char) -> SelectedTargetCapability {
        SelectedTargetCapability::new(target_id(), scan('1'), recovery('7'), hash(parent))
            .expect("target capability")
    }

    fn vault(parent: char) -> BootVaultBackupCapability {
        BootVaultBackupCapability::new(
            "vault-01",
            "B-preflight",
            hash('b'),
            "vault://repair/B-preflight",
            hash('c'),
            hash(parent),
            true,
            4096,
            8192,
        )
        .expect("Vault capability")
    }

    fn transaction_evidence(first: char, second: char) -> [CandidateEvidenceBinding; 2] {
        [
            CandidateEvidenceBinding::new(RESCUE_FSTAB_EVIDENCE_IDS[0], hash(first))
                .expect("fstab evidence"),
            CandidateEvidenceBinding::new(RESCUE_FSTAB_EVIDENCE_IDS[1], hash(second))
                .expect("lsblk evidence"),
        ]
    }

    fn exact_request() -> RescueFstabPrepareRequest {
        RescueFstabPrepareRequest::new(
            REQUEST_ID,
            SESSION_ID,
            PLAN_ID,
            scan('1'),
            target_id(),
            hash('f'),
        )
        .expect("closed request")
    }

    fn exact_observation() -> TrustedRescueFstabObservation {
        TrustedRescueFstabObservation::new(
            hash('f'),
            FSTAB.to_vec(),
            RepairFileMetadataV1::new(0o644, 0, 0).expect("metadata"),
            observed(),
            target('a'),
            transaction_evidence('d', 'e'),
        )
    }

    struct TestTargetGuard {
        identity: String,
        dropped: Arc<AtomicBool>,
    }

    impl Drop for TestTargetGuard {
        fn drop(&mut self) {
            self.dropped.store(true, Ordering::SeqCst);
        }
    }

    struct TestReservation {
        reservation_id: String,
        binding: String,
        calls: Arc<Mutex<Vec<&'static str>>>,
        dropped: Arc<AtomicBool>,
        cancel_fails: bool,
        expected_deadline: Instant,
    }

    impl Drop for TestReservation {
        fn drop(&mut self) {
            self.dropped.store(true, Ordering::SeqCst);
        }
    }

    impl RescueFstabVaultReservation for TestReservation {
        fn reservation_id(&self) -> &str {
            &self.reservation_id
        }

        fn reservation_binding_sha256(&self) -> &str {
            &self.binding
        }

        fn cancel(self, deadline: Instant) -> Result<(), RescueFstabCapabilityResolutionError> {
            assert_eq!(deadline, self.expected_deadline);
            self.calls.lock().expect("calls lock").push("cancel");
            if self.cancel_fails {
                Err(RescueFstabCapabilityResolutionError::Unavailable)
            } else {
                Ok(())
            }
        }
    }

    struct TestResolver {
        observation: Option<TrustedRescueFstabObservation>,
        vault: BootVaultBackupCapability,
        lock_identity: String,
        calls: Arc<Mutex<Vec<&'static str>>>,
        target_dropped: Arc<AtomicBool>,
        reservation_dropped: Arc<AtomicBool>,
        cancel_fails: bool,
        expected_deadline: Instant,
    }

    impl TestResolver {
        fn new(observation: TrustedRescueFstabObservation, deadline: Instant) -> Self {
            Self {
                observation: Some(observation),
                vault: vault('b'),
                lock_identity: format!("lock:{}", "9".repeat(64)),
                calls: Arc::new(Mutex::new(Vec::new())),
                target_dropped: Arc::new(AtomicBool::new(false)),
                reservation_dropped: Arc::new(AtomicBool::new(false)),
                cancel_fails: false,
                expected_deadline: deadline,
            }
        }

        fn record(&self, operation: &'static str, deadline: Instant) {
            assert_eq!(deadline, self.expected_deadline);
            self.calls.lock().expect("calls lock").push(operation);
        }

        fn calls(&self) -> Vec<&'static str> {
            self.calls.lock().expect("calls lock").clone()
        }
    }

    impl RescueFstabPreflightCapabilityResolver for TestResolver {
        type TargetGuard = TestTargetGuard;
        type VaultReservation = TestReservation;

        fn acquire_target_guard(
            &mut self,
            _request: &RescueFstabPrepareRequest,
            deadline: Instant,
        ) -> Result<Self::TargetGuard, RescueFstabCapabilityResolutionError> {
            self.record("acquire", deadline);
            Ok(TestTargetGuard {
                identity: self.lock_identity.clone(),
                dropped: Arc::clone(&self.target_dropped),
            })
        }

        fn observe_under_target_guard(
            &mut self,
            _request: &RescueFstabPrepareRequest,
            _target_guard: &Self::TargetGuard,
            deadline: Instant,
        ) -> Result<TrustedRescueFstabObservation, RescueFstabCapabilityResolutionError> {
            self.record("observe", deadline);
            self.observation
                .take()
                .ok_or(RescueFstabCapabilityResolutionError::Unavailable)
        }

        fn reserve_vault(
            &mut self,
            _intent: &RescueFstabPreflightIntent,
            _target_guard: &Self::TargetGuard,
            _observation: &TrustedRescueFstabObservation,
            _preview: &DisableMissingUuidPreview,
            deadline: Instant,
        ) -> Result<
            (Self::VaultReservation, BootVaultBackupCapability),
            RescueFstabCapabilityResolutionError,
        > {
            self.record("reserve", deadline);
            Ok((
                TestReservation {
                    reservation_id: self.vault.reservation_id().to_owned(),
                    binding: self.vault.reservation_binding_sha256().to_owned(),
                    calls: Arc::clone(&self.calls),
                    dropped: Arc::clone(&self.reservation_dropped),
                    cancel_fails: self.cancel_fails,
                    expected_deadline: self.expected_deadline,
                },
                self.vault.clone(),
            ))
        }

        fn target_guard_identity<'guard>(
            &self,
            target_guard: &'guard Self::TargetGuard,
        ) -> &'guard str {
            &target_guard.identity
        }
    }

    fn candidate_core_plan() -> ValidatedPlan {
        ValidatedPlan {
            plan_id: PLAN_ID.to_owned(),
            target_fingerprint: hash('f'),
            steps: vec![ActionStep {
                action: ACTION_ID.to_owned(),
                risk: Risk::R2,
                target_fingerprint: hash('f'),
                evidence_ids: RESCUE_FSTAB_EVIDENCE_IDS
                    .iter()
                    .map(|value| (*value).to_owned())
                    .collect(),
                preconditions: vec![PREFLIGHT_ID.to_owned()],
                backup: Some("required".to_owned()),
                validation: VALIDATE_ID.to_owned(),
                rollback: Some(ROLLBACK_ID.to_owned()),
            }],
        }
    }

    fn rescue_snapshot() -> (Evidence, Vec<u8>) {
        let bytes = LinuxNormalizedSnapshotEnvelope::new(
            LinuxSnapshotCapture::rescue(),
            LinuxNormalizedSnapshot {
                family: "linux".to_owned(),
                scope: SNAPSHOT_SCOPE.to_owned(),
                installation_confirmed: true,
                topology: LinuxFilesystemTopology {
                    collection_scope: COLLECTION_SCOPE.to_owned(),
                    separate_etc_mount_present: false,
                    separate_boot_mount_present: false,
                    separate_usr_mount_present: false,
                    separate_var_mount_present: false,
                    relevant_separate_mount_present: false,
                    supported: true,
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
                        present: true,
                        entry_count: 2,
                        root_entry_present: true,
                        efi_entry_present: false,
                        swap_entry_count: 0,
                        network_entry_count: 0,
                        malformed_line_count: 0,
                    },
                    machine_id_present: true,
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
        .expect("canonical snapshot");
        let digest = format!("{:x}", Sha256::digest(&bytes));
        let evidence = Evidence {
            id: "E-SNAPSHOT".to_owned(),
            collector: LINUX_SNAPSHOT_COLLECTOR.to_owned(),
            target: "selected-installed-target".to_owned(),
            captured_at: "2026-08-28T00:00:00Z".to_owned(),
            content_type: LINUX_SNAPSHOT_CONTENT_TYPE.to_owned(),
            sha256: digest.clone(),
            sensitivity: "system".to_owned(),
            trust: "observed-untrusted".to_owned(),
            summary: "fixture".to_owned(),
            blob_ref: format!("sha256:{digest}"),
        };
        (evidence, bytes)
    }

    fn staged_admission(
        session_id: &str,
        plan_hash: &str,
        target_snapshot: &str,
    ) -> RescueFstabCandidateAdmission {
        let (snapshot, bytes) = rescue_snapshot();
        let mut session = Session::new(hash('f'), SessionMode::LinuxRescue);
        session
            .admit_linux_snapshot(&snapshot, &bytes)
            .expect("admit snapshot");
        session
            .linux_evidence_complete(std::slice::from_ref(&snapshot))
            .expect("diagnosis boundary");
        session
            .stage_rescue_fstab_production_candidate(
                &candidate_core_plan(),
                session_id,
                plan_hash,
                target_snapshot,
                APPROVAL_SEQUENCE - 1,
            )
            .expect("stage admission")
    }

    fn approve(admission: &mut RescueFstabCandidateAdmission) -> RescueFstabCandidateApproval {
        let approval = RescueFstabCandidateApproval::new(
            admission.binding().clone(),
            APPROVAL_ID,
            APPROVAL_SEQUENCE,
            RESCUE_FSTAB_TYPED_CONFIRMATION,
        )
        .expect("approval");
        admission.approve(&approval).expect("approve admission");
        approval
    }

    fn deadline() -> Instant {
        Instant::now() + Duration::from_secs(2)
    }

    #[test]
    fn observation_precedes_reservation_and_approval_consumes_prepared_authority() {
        let deadline = deadline();
        let mut resolver = TestResolver::new(exact_observation(), deadline);
        let target_dropped = Arc::clone(&resolver.target_dropped);
        let reservation_dropped = Arc::clone(&resolver.reservation_dropped);
        let prepared = prepare_rescue_fstab_candidate(exact_request(), &mut resolver, deadline)
            .expect("prepare before approval");

        assert_eq!(resolver.calls(), ["acquire", "observe", "reserve"]);
        assert_eq!(
            prepared.receipt().plan_hash(),
            prepared.plan().plan_sha256()
        );
        assert_eq!(prepared.receipt().before_sha256(), prepared.before_sha256());
        assert_eq!(prepared.receipt().after_sha256(), prepared.after_sha256());
        assert_eq!(prepared.receipt().diff_sha256(), prepared.diff_sha256());
        assert_eq!(
            prepared.receipt().backup_locator(),
            "vault://repair/B-preflight"
        );
        assert!(!target_dropped.load(Ordering::SeqCst));
        assert!(!reservation_dropped.load(Ordering::SeqCst));
        let debug = format!("{prepared:?}");
        assert!(!debug.contains("DEAD-BEEF"));
        assert!(!debug.contains("/srv/archive"));

        let mut admission = staged_admission(
            prepared.receipt().intent().session_id(),
            prepared.receipt().plan_hash(),
            prepared.receipt().before_sha256(),
        );
        approve(&mut admission);
        let approved = prepared
            .authorize(admission, deadline)
            .expect("exact later approval");
        assert_eq!(approved.approval_id(), APPROVAL_ID);
        assert_eq!(approved.approval_sequence(), APPROVAL_SEQUENCE);
        assert!(approved.approval_sha256().starts_with("sha256:"));
        assert_eq!(approved.backup_bytes(), FSTAB);
        assert_eq!(approved.metadata().mode(), 0o644);
        assert_ne!(approved.proposed_fstab(), FSTAB);
        assert_eq!(resolver.calls(), ["acquire", "observe", "reserve"]);
        drop(approved);
        assert!(target_dropped.load(Ordering::SeqCst));
        assert!(reservation_dropped.load(Ordering::SeqCst));
    }

    #[test]
    fn approval_replay_is_rejected_and_binding_drift_cancels() {
        let deadline = deadline();
        let mut resolver = TestResolver::new(exact_observation(), deadline);
        let prepared = prepare_rescue_fstab_candidate(exact_request(), &mut resolver, deadline)
            .expect("prepared plan");
        let mut admission = staged_admission(
            SESSION_ID,
            prepared.receipt().plan_hash(),
            prepared.receipt().before_sha256(),
        );
        let approval = approve(&mut admission);
        assert_eq!(
            admission.approve(&approval),
            Err(RescueFstabCandidateAdmissionError::ApprovalReplay)
        );
        let approved = prepared
            .authorize(admission, deadline)
            .expect("first exact approval remains valid");
        approved.cancel(deadline).expect("approved abort cleanup");
        assert_eq!(
            resolver.calls(),
            ["acquire", "observe", "reserve", "cancel"]
        );

        let mut resolver = TestResolver::new(exact_observation(), deadline);
        let calls = Arc::clone(&resolver.calls);
        let prepared = prepare_rescue_fstab_candidate(exact_request(), &mut resolver, deadline)
            .expect("prepared plan");
        let mut drifted = staged_admission(SESSION_ID, &hash('7'), prepared.before_sha256());
        approve(&mut drifted);
        assert_eq!(
            prepared
                .authorize(drifted, deadline)
                .expect_err("plan drift"),
            RescueFstabPreflightError::AdmissionBindingMismatch
        );
        assert_eq!(
            *calls.lock().expect("calls lock"),
            ["acquire", "observe", "reserve", "cancel"]
        );
    }

    #[test]
    fn staged_approval_and_observation_drift_fail_closed() {
        let deadline = deadline();
        let mut resolver = TestResolver::new(exact_observation(), deadline);
        let prepared = prepare_rescue_fstab_candidate(exact_request(), &mut resolver, deadline)
            .expect("prepared plan");
        let staged = staged_admission(
            SESSION_ID,
            prepared.receipt().plan_hash(),
            prepared.before_sha256(),
        );
        assert_eq!(
            prepared
                .authorize(staged, deadline)
                .expect_err("not approved"),
            RescueFstabPreflightError::ApprovalRequired
        );
        assert_eq!(
            resolver.calls(),
            ["acquire", "observe", "reserve", "cancel"]
        );

        let mut identity_drift = exact_observation();
        identity_drift.resolved_target_fingerprint = hash('8');
        let mut resolver = TestResolver::new(identity_drift, deadline);
        assert_eq!(
            prepare_rescue_fstab_candidate(exact_request(), &mut resolver, deadline)
                .expect_err("target drift"),
            RescueFstabPreflightError::TargetIdentityMismatch
        );
        assert_eq!(resolver.calls(), ["acquire", "observe"]);

        let mut evidence_drift = exact_observation();
        evidence_drift.evidence[0] = CandidateEvidenceBinding::new("E-OTHER", hash('8'))
            .expect("syntactically valid non-candidate evidence");
        let mut resolver = TestResolver::new(evidence_drift, deadline);
        assert_eq!(
            prepare_rescue_fstab_candidate(exact_request(), &mut resolver, deadline)
                .expect_err("evidence drift"),
            RescueFstabPreflightError::EvidenceBindingMismatch
        );
        assert_eq!(resolver.calls(), ["acquire", "observe"]);
    }

    #[test]
    fn prepared_authority_stages_core_from_broker_evidence_without_snapshot_fixture() {
        let deadline = deadline();
        let mut resolver = TestResolver::new(exact_observation(), deadline);
        let prepared = prepare_rescue_fstab_candidate(exact_request(), &mut resolver, deadline)
            .expect("prepared plan");
        let canonical = prepared.validated_plan().expect("canonical Core plan");
        assert_eq!(canonical.plan_id, PLAN_ID);
        assert_eq!(canonical.target_fingerprint, hash('f'));
        assert_eq!(canonical.steps.len(), 1);

        let mut session = Session::new(hash('f'), SessionMode::LinuxRescue);
        let admission = prepared
            .stage_core_admission(&mut session, APPROVAL_SEQUENCE - 1)
            .expect("broker-derived direct Core admission");
        assert_eq!(session.state(), &kernaid_core::State::Plan);
        assert_eq!(admission.binding().plan_id(), PLAN_ID);
        assert_eq!(
            admission.binding().plan_hash(),
            prepared.plan().plan_sha256()
        );
        assert_eq!(
            admission.binding().target_snapshot(),
            prepared.before_sha256()
        );
        prepared.cancel(deadline).expect("release reservation");
    }

    #[test]
    fn plan_and_receipt_failures_cancel_and_cancel_failure_dominates() {
        let deadline = deadline();
        let mut resolver = TestResolver::new(exact_observation(), deadline);
        resolver.vault = vault('a');
        assert_eq!(
            prepare_rescue_fstab_candidate(exact_request(), &mut resolver, deadline)
                .expect_err("same physical parent"),
            RescueFstabPreflightError::TransactionRejected(
                CandidateTransactionError::PhysicalDeviceNotDistinct
            )
        );
        assert_eq!(
            resolver.calls(),
            ["acquire", "observe", "reserve", "cancel"]
        );

        let mut resolver = TestResolver::new(exact_observation(), deadline);
        resolver.lock_identity = "../../path-like-lock".to_owned();
        assert_eq!(
            prepare_rescue_fstab_candidate(exact_request(), &mut resolver, deadline)
                .expect_err("receipt rejection"),
            RescueFstabPreflightError::ReceiptRejected
        );
        assert_eq!(
            resolver.calls(),
            ["acquire", "observe", "reserve", "cancel"]
        );

        let mut resolver = TestResolver::new(exact_observation(), deadline);
        resolver.vault = vault('a');
        resolver.cancel_fails = true;
        assert_eq!(
            prepare_rescue_fstab_candidate(exact_request(), &mut resolver, deadline)
                .expect_err("cancellation failure"),
            RescueFstabPreflightError::CancellationFailed
        );
        assert_eq!(
            resolver.calls(),
            ["acquire", "observe", "reserve", "cancel"]
        );
    }
}
