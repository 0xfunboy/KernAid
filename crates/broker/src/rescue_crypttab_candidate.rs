//! Broker-owned preflight and Core admission for the Rescue crypttab action.
//!
//! The deterministic preview has no public observation constructor or write
//! method. Production preparation creates it from the retained descriptor-only
//! target bundle, couples it to a distinct authenticated Vault reservation,
//! and transfers that inseparable authority into the shared repair transaction
//! engine only after exact typed approval.

use kernaid_core::{
    RescueCrypttabAdmissionError, RescueCrypttabCandidateAdmission,
    RescueCrypttabCandidateApproval, RescueCrypttabCandidateBinding,
};
use kernaid_linux_pack::{
    crypttab_candidate_contract::{ACTION_ID, PREFLIGHT_ID, RESOURCE_ID, ROLLBACK_ID, VALIDATE_ID},
    rescue_crypttab_candidate::{
        CrypttabPreviewError, DisableMissingCrypttabUuidPreview,
        preview_disable_missing_crypttab_uuid,
    },
};
use kernaid_protocol::{
    ActionStep, Risk, ValidatedPlan,
    rescue_crypttab_repair::{
        EVIDENCE_IDS, RescueCrypttabEvidenceBinding, RescueCrypttabPrepareRequest,
        RescueCrypttabPreparedDescriptor,
    },
    rescue_repair_vault::RepairFileMetadataV1,
};
use sha2::{Digest, Sha256};
use std::time::Instant;
use std::{collections::BTreeSet, fmt};
use zeroize::Zeroizing;

use crate::{
    rescue_fstab_candidate::RescueFstabVaultReservation,
    rescue_fstab_preflight_resolver::{
        ProductionRescueFstabTargetGuard, ProductionRescueFstabVaultReservation,
        acquire_crypttab_target_guard, reserve_crypttab_backup,
    },
};

const PLAN_HASH_DOMAIN: &[u8] = b"kernaid:linux.crypttab.disable-missing-uuid.v1:plan:v1\0";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RescueCrypttabPreflightError {
    TargetIdentityMismatch,
    UnsupportedTarget,
    Observation,
    PreviewRejected(CrypttabPreviewError),
    InvalidBinding,
    PolicyRejected,
    ApprovalRejected,
    TargetUnavailable,
    VaultUnavailable,
    CancellationFailed,
}

/// Production read-only entry point. The caller must retain `target` across
/// any later Vault reservation; this function only derives and admits the
/// immutable preview while the descriptor bundle is still revalidated.
pub fn prepare_rescue_crypttab_candidate_from_target(
    request: &RescueCrypttabPrepareRequest,
    target: &crate::target_physical_parent::RescueTargetPhysicalParentGuard,
) -> Result<PreparedRescueCrypttabCandidate, RescueCrypttabPreflightError> {
    let observation = crate::rescue_crypttab_observer::observe_rescue_crypttab(target)
        .map_err(|_| RescueCrypttabPreflightError::Observation)?;
    prepare_rescue_crypttab_candidate(request, observation)
}

/// Read-only material produced by a broker resolver while it retains the
/// selected target capability. Construction remains crate-private.
pub struct BrokerOwnedCrypttabObservation {
    scan_fingerprint: String,
    target_id: String,
    target_fingerprint: String,
    direct_leaf_ext4: bool,
    crypttab_bytes: Zeroizing<Vec<u8>>,
    fstab_bytes: Zeroizing<Vec<u8>>,
    observed_uuids: BTreeSet<String>,
    metadata: RepairFileMetadataV1,
}

impl BrokerOwnedCrypttabObservation {
    #[cfg(test)]
    fn new_for_test(
        request: &RescueCrypttabPrepareRequest,
        crypttab: &[u8],
        fstab: &[u8],
        observed_uuids: BTreeSet<String>,
    ) -> Self {
        Self {
            scan_fingerprint: request.scan_fingerprint().to_owned(),
            target_id: request.target_id().to_owned(),
            target_fingerprint: request.target_fingerprint().to_owned(),
            direct_leaf_ext4: true,
            crypttab_bytes: Zeroizing::new(crypttab.to_vec()),
            fstab_bytes: Zeroizing::new(fstab.to_vec()),
            observed_uuids,
            metadata: RepairFileMetadataV1::new(0o644, 0, 0).expect("test metadata"),
        }
    }

    /// Only another broker module holding the real root-issued target guard
    /// may construct this value. No caller-controlled path or action exists.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn from_retained_target_capability(
        scan_fingerprint: String,
        target_id: String,
        target_fingerprint: String,
        direct_leaf_ext4: bool,
        crypttab_bytes: Zeroizing<Vec<u8>>,
        fstab_bytes: Zeroizing<Vec<u8>>,
        observed_uuids: BTreeSet<String>,
        metadata: RepairFileMetadataV1,
    ) -> Self {
        Self {
            scan_fingerprint,
            target_id,
            target_fingerprint,
            direct_leaf_ext4,
            crypttab_bytes,
            fstab_bytes,
            observed_uuids,
            metadata,
        }
    }
}

impl fmt::Debug for BrokerOwnedCrypttabObservation {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("BrokerOwnedCrypttabObservation")
            .field("scan_fingerprint", &"[opaque]")
            .field("target_id", &"[opaque]")
            .field("target_fingerprint", &"[opaque]")
            .field("direct_leaf_ext4", &self.direct_leaf_ext4)
            .field("crypttab_bytes", &"[redacted]")
            .field("fstab_bytes", &"[redacted]")
            .field("observed_uuids", &"[redacted]")
            .finish()
    }
}

/// Non-cloneable admitted preview. It retains exact before/after bytes in
/// memory but grants no write. Approval consumes this value once.
#[must_use]
pub struct PreparedRescueCrypttabCandidate {
    descriptor: RescueCrypttabPreparedDescriptor,
    plan: ValidatedPlan,
    binding: RescueCrypttabCandidateBinding,
    admission: RescueCrypttabCandidateAdmission,
    backup_bytes: Zeroizing<Vec<u8>>,
    proposed_bytes: Zeroizing<Vec<u8>>,
    metadata: RepairFileMetadataV1,
}

impl PreparedRescueCrypttabCandidate {
    pub fn descriptor(&self) -> &RescueCrypttabPreparedDescriptor {
        &self.descriptor
    }
    pub fn plan(&self) -> &ValidatedPlan {
        &self.plan
    }
    pub const fn metadata(&self) -> &RepairFileMetadataV1 {
        &self.metadata
    }

    pub fn approve(
        mut self,
        approval_id: impl Into<String>,
        typed_confirmation: impl Into<String>,
    ) -> Result<ApprovedRescueCrypttabCandidate, RescueCrypttabPreflightError> {
        let approval = RescueCrypttabCandidateApproval::new(
            approval_id,
            1,
            self.binding.clone(),
            typed_confirmation,
        )
        .map_err(|_| RescueCrypttabPreflightError::ApprovalRejected)?;
        self.admission
            .approve(approval)
            .map_err(|_| RescueCrypttabPreflightError::ApprovalRejected)?;
        Ok(ApprovedRescueCrypttabCandidate {
            descriptor: self.descriptor,
            plan: self.plan,
            admission: self.admission,
            backup_bytes: self.backup_bytes,
            proposed_bytes: self.proposed_bytes,
            metadata: self.metadata,
        })
    }
}

/// Production prepared authority. Target and authenticated Vault reservation
/// remain inseparable from the immutable preview until approval or cancel.
#[must_use]
pub struct PreparedRescueCrypttabTransaction {
    candidate: PreparedRescueCrypttabCandidate,
    target_guard: ProductionRescueFstabTargetGuard,
    reservation: ProductionRescueFstabVaultReservation,
}

impl PreparedRescueCrypttabTransaction {
    pub fn descriptor(&self) -> &RescueCrypttabPreparedDescriptor {
        self.candidate.descriptor()
    }

    pub fn backup_locator(&self) -> &str {
        self.reservation.status().locator()
    }

    pub fn approve(
        self,
        approval_id: impl Into<String>,
        typed_confirmation: impl Into<String>,
        cancellation_deadline: Instant,
    ) -> Result<ApprovedRescueCrypttabTransaction, RescueCrypttabPreflightError> {
        let Self {
            candidate,
            target_guard,
            reservation,
        } = self;
        let candidate = match candidate.approve(approval_id, typed_confirmation) {
            Ok(candidate) => candidate,
            Err(error) => {
                reservation
                    .cancel(cancellation_deadline)
                    .map_err(|_| RescueCrypttabPreflightError::CancellationFailed)?;
                return Err(error);
            }
        };
        Ok(ApprovedRescueCrypttabTransaction {
            candidate,
            target_guard,
            reservation,
        })
    }

    pub fn cancel(self, deadline: Instant) -> Result<(), RescueCrypttabPreflightError> {
        self.reservation
            .cancel(deadline)
            .map_err(|_| RescueCrypttabPreflightError::CancellationFailed)
    }
}

#[must_use]
pub struct ApprovedRescueCrypttabTransaction {
    candidate: ApprovedRescueCrypttabCandidate,
    target_guard: ProductionRescueFstabTargetGuard,
    reservation: ProductionRescueFstabVaultReservation,
}

pub(crate) struct ApprovedRescueCrypttabExecutionParts {
    pub(crate) descriptor: RescueCrypttabPreparedDescriptor,
    pub(crate) plan: ValidatedPlan,
    pub(crate) admission: RescueCrypttabCandidateAdmission,
    pub(crate) backup_bytes: Zeroizing<Vec<u8>>,
    pub(crate) proposed_bytes: Zeroizing<Vec<u8>>,
    pub(crate) metadata: RepairFileMetadataV1,
    pub(crate) target_guard: ProductionRescueFstabTargetGuard,
    pub(crate) reservation: ProductionRescueFstabVaultReservation,
}

impl ApprovedRescueCrypttabTransaction {
    pub fn descriptor(&self) -> &RescueCrypttabPreparedDescriptor {
        self.candidate.descriptor()
    }

    pub fn cancel(self, deadline: Instant) -> Result<(), RescueCrypttabPreflightError> {
        self.reservation
            .cancel(deadline)
            .map_err(|_| RescueCrypttabPreflightError::CancellationFailed)
    }

    pub(crate) fn into_execution_parts(self) -> ApprovedRescueCrypttabExecutionParts {
        let ApprovedRescueCrypttabCandidate {
            descriptor,
            plan,
            admission,
            backup_bytes,
            proposed_bytes,
            metadata,
        } = self.candidate;
        ApprovedRescueCrypttabExecutionParts {
            descriptor,
            plan,
            admission,
            backup_bytes,
            proposed_bytes,
            metadata,
            target_guard: self.target_guard,
            reservation: self.reservation,
        }
    }
}

/// Full production prepare path: acquire target, observe both files, admit
/// the fail-closed preview, then reserve a distinct authenticated backup.
pub fn prepare_rescue_crypttab_transaction(
    request: RescueCrypttabPrepareRequest,
    deadline: Instant,
) -> Result<PreparedRescueCrypttabTransaction, RescueCrypttabPreflightError> {
    let target_guard = acquire_crypttab_target_guard(&request, deadline)
        .map_err(|_| RescueCrypttabPreflightError::TargetUnavailable)?;
    let observation =
        crate::rescue_crypttab_observer::observe_rescue_crypttab(target_guard.inner())
            .map_err(|_| RescueCrypttabPreflightError::Observation)?;
    let candidate = prepare_rescue_crypttab_candidate(&request, observation)?;
    let reservation = reserve_crypttab_backup(
        &request,
        &target_guard,
        &candidate.backup_bytes,
        candidate.metadata(),
        deadline,
    )
    .map_err(|_| RescueCrypttabPreflightError::VaultUnavailable)?;
    Ok(PreparedRescueCrypttabTransaction {
        candidate,
        target_guard,
        reservation,
    })
}

impl fmt::Debug for PreparedRescueCrypttabCandidate {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PreparedRescueCrypttabCandidate")
            .field("descriptor", &self.descriptor)
            .field("backup_bytes", &"[redacted]")
            .field("proposed_bytes", &"[redacted]")
            .finish_non_exhaustive()
    }
}

/// Core-approved preview material. It is not write authority on its own; the
/// production wrapper keeps it inseparable from the retained target and Vault
/// reservation before the shared executor can consume it.
#[must_use]
pub struct ApprovedRescueCrypttabCandidate {
    descriptor: RescueCrypttabPreparedDescriptor,
    plan: ValidatedPlan,
    admission: RescueCrypttabCandidateAdmission,
    // Retained as opaque, zeroizing material for the shared Vault-backed
    // executor. This approved value alone is not write authority.
    #[allow(dead_code)]
    backup_bytes: Zeroizing<Vec<u8>>,
    #[allow(dead_code)]
    proposed_bytes: Zeroizing<Vec<u8>>,
    metadata: RepairFileMetadataV1,
}

impl ApprovedRescueCrypttabCandidate {
    pub fn descriptor(&self) -> &RescueCrypttabPreparedDescriptor {
        &self.descriptor
    }
    pub fn plan(&self) -> &ValidatedPlan {
        &self.plan
    }
    pub fn approval_id(&self) -> &str {
        self.admission
            .approval_id()
            .expect("approved admission has an approval ID")
    }
    pub const fn metadata(&self) -> &RepairFileMetadataV1 {
        &self.metadata
    }
    #[cfg(test)]
    pub(crate) fn backup_bytes(&self) -> &[u8] {
        &self.backup_bytes
    }
    #[cfg(test)]
    pub(crate) fn proposed_bytes(&self) -> &[u8] {
        &self.proposed_bytes
    }
}

impl fmt::Debug for ApprovedRescueCrypttabCandidate {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ApprovedRescueCrypttabCandidate")
            .field("descriptor", &self.descriptor)
            .field("approval", &"[bound Core approval]")
            .field("backup_bytes", &"[redacted]")
            .field("proposed_bytes", &"[redacted]")
            .finish_non_exhaustive()
    }
}

pub fn prepare_rescue_crypttab_candidate(
    request: &RescueCrypttabPrepareRequest,
    observation: BrokerOwnedCrypttabObservation,
) -> Result<PreparedRescueCrypttabCandidate, RescueCrypttabPreflightError> {
    if observation.scan_fingerprint != request.scan_fingerprint()
        || observation.target_id != request.target_id()
        || observation.target_fingerprint != request.target_fingerprint()
    {
        return Err(RescueCrypttabPreflightError::TargetIdentityMismatch);
    }
    if !observation.direct_leaf_ext4 {
        return Err(RescueCrypttabPreflightError::UnsupportedTarget);
    }
    let preview = preview_disable_missing_crypttab_uuid(
        &observation.crypttab_bytes,
        &observation.fstab_bytes,
        &observation.observed_uuids,
    )
    .map_err(RescueCrypttabPreflightError::PreviewRejected)?;
    let evidence = evidence_bindings(&observation, &preview)?;
    let plan = canonical_plan(request);
    let plan_sha256 = canonical_plan_sha256(request, &preview, &evidence);
    let binding = RescueCrypttabCandidateBinding::new(
        request.session_id(),
        request.plan_id(),
        &plan_sha256,
        request.target_fingerprint(),
        preview.before_sha256(),
    )
    .map_err(|_| RescueCrypttabPreflightError::InvalidBinding)?;
    let admission = RescueCrypttabCandidateAdmission::stage(&plan, binding.clone())
        .map_err(map_admission_error)?;
    let descriptor = RescueCrypttabPreparedDescriptor::new(
        request,
        plan_sha256,
        preview.before_sha256(),
        preview.after_sha256(),
        preview.diff_sha256(),
        preview.observed_uuid_set_sha256(),
        preview.fstab_consumer_set_sha256(),
        evidence,
    )
    .map_err(|_| RescueCrypttabPreflightError::InvalidBinding)?;
    Ok(PreparedRescueCrypttabCandidate {
        descriptor,
        plan,
        binding,
        admission,
        backup_bytes: observation.crypttab_bytes,
        proposed_bytes: Zeroizing::new(preview.proposed_crypttab().to_vec()),
        metadata: observation.metadata,
    })
}

fn evidence_bindings(
    observation: &BrokerOwnedCrypttabObservation,
    preview: &DisableMissingCrypttabUuidPreview,
) -> Result<[RescueCrypttabEvidenceBinding; 3], RescueCrypttabPreflightError> {
    [
        sha256(&observation.crypttab_bytes),
        sha256(&observation.fstab_bytes),
        preview.observed_uuid_set_sha256().to_owned(),
    ]
    .into_iter()
    .zip(EVIDENCE_IDS)
    .map(|(hash, id)| {
        RescueCrypttabEvidenceBinding::new(id, hash)
            .map_err(|_| RescueCrypttabPreflightError::InvalidBinding)
    })
    .collect::<Result<Vec<_>, _>>()?
    .try_into()
    .map_err(|_| RescueCrypttabPreflightError::InvalidBinding)
}

fn canonical_plan(request: &RescueCrypttabPrepareRequest) -> ValidatedPlan {
    ValidatedPlan {
        plan_id: request.plan_id().to_owned(),
        target_fingerprint: request.target_fingerprint().to_owned(),
        steps: vec![ActionStep {
            action: ACTION_ID.to_owned(),
            risk: Risk::R2,
            target_fingerprint: request.target_fingerprint().to_owned(),
            evidence_ids: EVIDENCE_IDS
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

fn canonical_plan_sha256(
    request: &RescueCrypttabPrepareRequest,
    preview: &DisableMissingCrypttabUuidPreview,
    evidence: &[RescueCrypttabEvidenceBinding; 3],
) -> String {
    let mut digest = Sha256::new();
    digest.update(PLAN_HASH_DOMAIN);
    for value in [
        request.session_id(),
        request.plan_id(),
        request.scan_fingerprint(),
        request.target_id(),
        request.target_fingerprint(),
        ACTION_ID,
        RESOURCE_ID,
        PREFLIGHT_ID,
        VALIDATE_ID,
        ROLLBACK_ID,
        preview.before_sha256(),
        preview.after_sha256(),
        preview.diff_sha256(),
        preview.observed_uuid_set_sha256(),
        preview.fstab_consumer_set_sha256(),
    ] {
        hash_framed(&mut digest, value.as_bytes());
    }
    for item in evidence {
        hash_framed(&mut digest, item.evidence_id().as_bytes());
        hash_framed(&mut digest, item.sha256().as_bytes());
    }
    format!("sha256:{:x}", digest.finalize())
}

fn hash_framed(digest: &mut Sha256, value: &[u8]) {
    digest.update((value.len() as u64).to_be_bytes());
    digest.update(value);
}

fn sha256(bytes: &[u8]) -> String {
    format!("sha256:{:x}", Sha256::digest(bytes))
}

fn map_admission_error(error: RescueCrypttabAdmissionError) -> RescueCrypttabPreflightError {
    match error {
        RescueCrypttabAdmissionError::PolicyRejected => {
            RescueCrypttabPreflightError::PolicyRejected
        }
        _ => RescueCrypttabPreflightError::InvalidBinding,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use kernaid_core::{RESCUE_CRYPTTAB_TYPED_CONFIRMATION, RescueCrypttabAdmissionState};

    fn request() -> RescueCrypttabPrepareRequest {
        RescueCrypttabPrepareRequest::new(
            "R-01234567-89ab-cdef-0123-456789abcdef",
            "S-crypttab",
            "P-crypttab",
            format!("scan:{}", "1".repeat(64)),
            format!("target:{}", "2".repeat(64)),
            format!("sha256:{}", "3".repeat(64)),
        )
        .expect("request")
    }

    fn observation(request: &RescueCrypttabPrepareRequest) -> BrokerOwnedCrypttabObservation {
        BrokerOwnedCrypttabObservation::new_for_test(
            request,
            b"system UUID=AAAA-BBBB none luks\narchive UUID=DEAD-BEEF none luks\n",
            b"UUID=ROOT / ext4 defaults 0 1\n",
            ["aaaa-bbbb".to_owned()].into_iter().collect(),
        )
    }

    #[test]
    fn prepares_and_approves_only_the_closed_plan() {
        let request = request();
        let prepared =
            prepare_rescue_crypttab_candidate(&request, observation(&request)).expect("prepared");
        assert_eq!(prepared.descriptor().action_id(), ACTION_ID);
        assert_eq!(prepared.descriptor().resource_id(), RESOURCE_ID);
        assert_eq!(prepared.plan().steps.len(), 1);
        let debug = format!("{prepared:?}");
        assert!(!debug.contains("DEAD-BEEF"));
        assert!(!debug.contains("archive"));
        let approved = prepared
            .approve("A-local-approval", RESCUE_CRYPTTAB_TYPED_CONFIRMATION)
            .expect("approval");
        assert_eq!(approved.approval_id(), "A-local-approval");
        assert_eq!(
            approved.admission.state(),
            RescueCrypttabAdmissionState::Approved
        );
        assert!(!approved.backup_bytes().is_empty());
        assert_ne!(approved.backup_bytes(), approved.proposed_bytes());
    }

    #[test]
    fn mandatory_fstab_consumer_and_wrong_confirmation_fail_closed() {
        let request = request();
        let mut observed = observation(&request);
        observed.fstab_bytes =
            Zeroizing::new(b"/dev/mapper/archive /srv/archive ext4 defaults 0 2\n".to_vec());
        assert_eq!(
            prepare_rescue_crypttab_candidate(&request, observed).err(),
            Some(RescueCrypttabPreflightError::PreviewRejected(
                CrypttabPreviewError::MandatoryFstabConsumer
            ))
        );
        let prepared =
            prepare_rescue_crypttab_candidate(&request, observation(&request)).expect("prepared");
        assert_eq!(
            prepared.approve("A-local-approval", "SI").err(),
            Some(RescueCrypttabPreflightError::ApprovalRejected)
        );
    }

    #[test]
    fn target_identity_and_topology_are_rechecked() {
        let request = request();
        let mut stale = observation(&request);
        stale.target_fingerprint = format!("sha256:{}", "4".repeat(64));
        assert_eq!(
            prepare_rescue_crypttab_candidate(&request, stale).err(),
            Some(RescueCrypttabPreflightError::TargetIdentityMismatch)
        );
        let mut complex = observation(&request);
        complex.direct_leaf_ext4 = false;
        assert_eq!(
            prepare_rescue_crypttab_candidate(&request, complex).err(),
            Some(RescueCrypttabPreflightError::UnsupportedTarget)
        );
    }
}
