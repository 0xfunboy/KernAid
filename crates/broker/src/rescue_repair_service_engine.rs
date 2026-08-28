//! Production engine behind the closed Rescue repair service state machine.
//!
//! Every preparation input is converted to the broker-owned request that
//! derives snapshot and evidence under the retained target capability. Core
//! admission is staged before the authority can be exposed as Prepared.

use crate::{
    rescue_fstab_candidate::{
        ApprovedRescueFstabTransaction, PreparedRescueFstabPlan,
        RescueFstabCapabilityResolutionError, RescueFstabPreflightError,
        prepare_rescue_fstab_candidate,
    },
    rescue_fstab_executor::{
        RescueFstabExecutionOutcome, RescueFstabExecutionReceipt, execute_approved_rescue_fstab,
        recover_pending_rescue_fstab,
    },
    rescue_fstab_preflight_resolver::{
        ProductionRescueFstabPreflightResolver, ProductionRescueFstabTargetGuard,
        ProductionRescueFstabVaultReservation,
    },
    rescue_repair_service::{
        BoundRepairApproval, BrokerOwnedPrepareCommand, PreparedRepairDescriptor,
        RepairEngineFailure, RepairPreparationEngine, RepairPrepareFailureStage,
        RepairTerminalOutcome, RepairTerminalReceipt,
    },
};
use kernaid_core::{
    RescueFstabCandidateAdmission, RescueFstabCandidateApproval, Session, SessionMode,
};
use kernaid_protocol::rescue_repair::RescueFstabPrepareRequest;
use std::time::Instant;

type ProductionPreparedPlan = PreparedRescueFstabPlan<
    ProductionRescueFstabTargetGuard,
    ProductionRescueFstabVaultReservation,
>;

type ProductionApprovedTransaction = ApprovedRescueFstabTransaction<
    ProductionRescueFstabTargetGuard,
    ProductionRescueFstabVaultReservation,
>;

/// Non-cloneable retained prepare authority plus its exact staged Core state.
pub struct ProductionPreparedRepair {
    plan: ProductionPreparedPlan,
    admission: RescueFstabCandidateAdmission,
}

/// The approved type remains the broker's inseparable target/backup/Core
/// authority and can only be consumed by the closed executor.
pub struct ProductionApprovedRepair(ProductionApprovedTransaction);

#[derive(Default)]
pub struct ProductionRepairEngine;

impl ProductionRepairEngine {
    pub const fn new() -> Self {
        Self
    }
}

impl RepairPreparationEngine for ProductionRepairEngine {
    type Prepared = ProductionPreparedRepair;
    type Approved = ProductionApprovedRepair;

    fn recover_pending(
        &mut self,
        deadline: Instant,
    ) -> Result<Option<RepairTerminalReceipt>, RepairEngineFailure> {
        recover_pending_rescue_fstab(deadline)
            .map_err(|_| RepairEngineFailure::RecoveryUnavailable)?
            .map(terminal_receipt)
            .transpose()
    }

    fn prepare(
        &mut self,
        command: &BrokerOwnedPrepareCommand,
        deadline: Instant,
    ) -> Result<(Self::Prepared, PreparedRepairDescriptor), RepairEngineFailure> {
        let request = RescueFstabPrepareRequest::new(
            command.request_id(),
            command.session_id(),
            command.plan_id(),
            command.target().scan_fingerprint(),
            command.target().target_id(),
            command.target().target_fingerprint(),
        )
        .map_err(|_| {
            RepairEngineFailure::PrepareFailed(RepairPrepareFailureStage::AdmissionInternal)
        })?;
        let mut resolver = ProductionRescueFstabPreflightResolver::new();
        let prepared = prepare_rescue_fstab_candidate(request, &mut resolver, deadline)
            .map_err(map_preflight_failure)?;
        if prepared.request_id() != command.request_id() {
            return cancel_failed_prepare(
                prepared,
                deadline,
                RepairPrepareFailureStage::AdmissionInternal,
            );
        }

        let target_fingerprint = prepared.receipt().intent().target_fingerprint().to_owned();
        let mut session = Session::new(&target_fingerprint, SessionMode::LinuxRescue);
        let admission = match prepared.stage_core_admission(&mut session, 0) {
            Ok(admission) => admission,
            Err(_) => {
                return cancel_failed_prepare(
                    prepared,
                    deadline,
                    RepairPrepareFailureStage::AdmissionInternal,
                );
            }
        };
        let descriptor = match PreparedRepairDescriptor::new(
            prepared.receipt().intent().session_id(),
            prepared.receipt().intent().plan_id(),
            prepared.receipt().plan_hash(),
            &target_fingerprint,
            prepared.before_sha256(),
            prepared.after_sha256(),
            prepared.diff_sha256(),
            admission.next_approval_sequence(),
            true,
            prepared.receipt().target_physical_parent_fingerprint()
                != prepared.receipt().vault_physical_parent_fingerprint(),
        ) {
            Ok(descriptor) => descriptor,
            Err(_) => {
                return cancel_failed_prepare(
                    prepared,
                    deadline,
                    RepairPrepareFailureStage::AdmissionInternal,
                );
            }
        };
        Ok((
            ProductionPreparedRepair {
                plan: prepared,
                admission,
            },
            descriptor,
        ))
    }

    fn approve(
        &mut self,
        prepared: Self::Prepared,
        approval: &BoundRepairApproval,
        deadline: Instant,
    ) -> Result<Self::Approved, RepairEngineFailure> {
        let ProductionPreparedRepair {
            plan,
            mut admission,
        } = prepared;
        let proof = match RescueFstabCandidateApproval::new(
            admission.binding().clone(),
            approval.approval_id(),
            approval.approval_sequence(),
            approval.typed_confirmation(),
        ) {
            Ok(proof) => proof,
            Err(_) => {
                plan.cancel(deadline)
                    .map_err(|_| RepairEngineFailure::CancelFailed)?;
                return Err(RepairEngineFailure::ApprovalRejected);
            }
        };
        if proof.session_id() != approval.session_id()
            || proof.binding().plan_id() != approval.plan_id()
            || proof.binding().plan_hash() != approval.plan_hash()
        {
            plan.cancel(deadline)
                .map_err(|_| RepairEngineFailure::CancelFailed)?;
            return Err(RepairEngineFailure::ApprovalRejected);
        }
        if admission.approve(&proof).is_err() {
            plan.cancel(deadline)
                .map_err(|_| RepairEngineFailure::CancelFailed)?;
            return Err(RepairEngineFailure::ApprovalRejected);
        }
        plan.authorize(admission, deadline)
            .map(ProductionApprovedRepair)
            .map_err(|_| RepairEngineFailure::ApprovalRejected)
    }

    fn execute(
        &mut self,
        approved: Self::Approved,
        deadline: Instant,
    ) -> Result<RepairTerminalReceipt, RepairEngineFailure> {
        match execute_approved_rescue_fstab(approved.0, deadline) {
            Ok(receipt) => terminal_receipt(receipt),
            Err(_) => match recover_pending_rescue_fstab(deadline) {
                Ok(Some(receipt)) => terminal_receipt(receipt),
                Ok(None) => Err(RepairEngineFailure::ExecutionFailed),
                Err(_) => RepairTerminalReceipt::new(
                    RepairTerminalOutcome::ManualReconciliationRequired,
                    None,
                    None,
                ),
            },
        }
    }

    fn cancel_prepared(
        prepared: Self::Prepared,
        deadline: Instant,
    ) -> Result<(), RepairEngineFailure> {
        prepared
            .plan
            .cancel(deadline)
            .map_err(|_| RepairEngineFailure::CancelFailed)
    }
}

fn cancel_failed_prepare<T>(
    prepared: ProductionPreparedPlan,
    deadline: Instant,
    stage: RepairPrepareFailureStage,
) -> Result<T, RepairEngineFailure> {
    prepared
        .cancel(deadline)
        .map_err(|_| RepairEngineFailure::CancelFailed)?;
    Err(RepairEngineFailure::PrepareFailed(stage))
}

fn map_preflight_failure(error: RescueFstabPreflightError) -> RepairEngineFailure {
    let stage = match error {
        RescueFstabPreflightError::TargetCapability(
            RescueFstabCapabilityResolutionError::TimedOut,
        ) => RepairPrepareFailureStage::TargetCapabilityTimedOut,
        RescueFstabPreflightError::TargetCapability(
            RescueFstabCapabilityResolutionError::IdentityChanged,
        ) => RepairPrepareFailureStage::TargetCapabilityIdentityChanged,
        RescueFstabPreflightError::TargetCapability(
            RescueFstabCapabilityResolutionError::Unavailable
            | RescueFstabCapabilityResolutionError::LockUnavailable,
        ) => RepairPrepareFailureStage::TargetCapabilityUnavailable,
        RescueFstabPreflightError::Observation(_)
        | RescueFstabPreflightError::TargetIdentityMismatch
        | RescueFstabPreflightError::EvidenceBindingMismatch
        | RescueFstabPreflightError::TargetSnapshotMismatch
        | RescueFstabPreflightError::PreviewRejected(_) => {
            RepairPrepareFailureStage::ObservationPreview
        }
        RescueFstabPreflightError::VaultReserve(_)
        | RescueFstabPreflightError::ReservationBindingMismatch => {
            RepairPrepareFailureStage::VaultReserve
        }
        RescueFstabPreflightError::ApprovalRequired
        | RescueFstabPreflightError::AdmissionBindingMismatch
        | RescueFstabPreflightError::ApprovalBindingMismatch
        | RescueFstabPreflightError::TransactionRejected(_)
        | RescueFstabPreflightError::ReceiptRejected
        | RescueFstabPreflightError::CancellationFailed => {
            RepairPrepareFailureStage::AdmissionInternal
        }
    };
    RepairEngineFailure::PrepareFailed(stage)
}

fn terminal_receipt(
    receipt: RescueFstabExecutionReceipt,
) -> Result<RepairTerminalReceipt, RepairEngineFailure> {
    let outcome = match receipt.outcome() {
        RescueFstabExecutionOutcome::Committed => RepairTerminalOutcome::Committed,
        RescueFstabExecutionOutcome::ClosedBeforeUnchanged => {
            RepairTerminalOutcome::ClosedBeforeUnchanged
        }
        RescueFstabExecutionOutcome::ClosedBeforeRestored => {
            RepairTerminalOutcome::ClosedBeforeRestored
        }
        RescueFstabExecutionOutcome::ManualReconciliationRequired => {
            RepairTerminalOutcome::ManualReconciliationRequired
        }
    };
    RepairTerminalReceipt::new(
        outcome,
        Some(receipt.reservation_id().to_owned()),
        Some(receipt.transaction_binding_sha256().to_owned()),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rescue_fstab_candidate::RescueFstabCapabilityResolutionError;

    #[test]
    fn preflight_failures_map_to_closed_public_stages() {
        for (error, expected) in [
            (
                RescueFstabPreflightError::TargetCapability(
                    RescueFstabCapabilityResolutionError::Unavailable,
                ),
                RepairPrepareFailureStage::TargetCapabilityUnavailable,
            ),
            (
                RescueFstabPreflightError::TargetCapability(
                    RescueFstabCapabilityResolutionError::TimedOut,
                ),
                RepairPrepareFailureStage::TargetCapabilityTimedOut,
            ),
            (
                RescueFstabPreflightError::TargetCapability(
                    RescueFstabCapabilityResolutionError::IdentityChanged,
                ),
                RepairPrepareFailureStage::TargetCapabilityIdentityChanged,
            ),
            (
                RescueFstabPreflightError::Observation(
                    RescueFstabCapabilityResolutionError::TimedOut,
                ),
                RepairPrepareFailureStage::ObservationPreview,
            ),
            (
                RescueFstabPreflightError::VaultReserve(
                    RescueFstabCapabilityResolutionError::IdentityChanged,
                ),
                RepairPrepareFailureStage::VaultReserve,
            ),
            (
                RescueFstabPreflightError::ReceiptRejected,
                RepairPrepareFailureStage::AdmissionInternal,
            ),
        ] {
            assert_eq!(
                map_preflight_failure(error),
                RepairEngineFailure::PrepareFailed(expected)
            );
        }
    }
}
