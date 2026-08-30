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
        ApprovedRescueFstabRollback, PreparedRescueFstabRollback, RescueFstabExecutionError,
        RescueFstabExecutionOutcome, RescueFstabExecutionReceipt, RescueFstabQualificationFault,
        RescueFstabRollbackExecutionOutcome, RescueFstabRollbackExecutionReceipt,
        authorize_prepared_rescue_fstab_rollback, execute_approved_rescue_fstab,
        execute_approved_rescue_fstab_rollback,
        execute_approved_rescue_fstab_with_qualification_fault, prepare_rescue_fstab_rollback,
        recover_pending_rescue_fstab, recover_pending_rescue_fstab_rollback,
    },
    rescue_fstab_preflight_resolver::{
        ProductionRescueFstabPreflightResolver, ProductionRescueFstabTargetGuard,
        ProductionRescueFstabVaultReservation,
    },
    rescue_repair_service::{
        BoundRepairApproval, BoundRollbackApproval, BrokerOwnedPrepareCommand,
        BrokerOwnedRollbackPrepareCommand, PreparedRepairDescriptor, PreparedRollbackDescriptor,
        RepairEngineFailure, RepairExecutionFailureStage, RepairPreparationEngine,
        RepairPrepareFailureStage, RepairTerminalOutcome, RepairTerminalReceipt,
    },
};
use kernaid_core::{
    RescueFstabCandidateAdmission, RescueFstabCandidateApproval, RescueFstabRollbackAdmission,
    RescueFstabRollbackApproval, RescueFstabRollbackBinding, RescueFstabRollbackSourceBinding,
    Session, SessionMode, canonical_rescue_fstab_rollback_plan,
};
use kernaid_protocol::{
    rescue_repair::RescueFstabPrepareRequest, rescue_repair_vault::RepairRollbackBindingV1,
    rescue_vault::Sha256,
};
use rustix::fs::{self as rfs, Mode, OFlags};
use std::{fs::File, io::Read, os::unix::fs::MetadataExt, path::Path, time::Instant};

const QUALIFICATION_CREDENTIAL_NAME: &str = "kernaid-repair-fault";
const QUALIFICATION_CREDENTIAL_DIRECTORY: &str = "/run/credentials/kernaid-rescue-repaird.service";
const NO_QUALIFICATION_FAULT_TOKEN: &[u8] = b"none-v1";
const TERMINATE_AFTER_PENDING_TOKEN: &[u8] = b"terminate-after-pending-v1";
const FAIL_AFTER_INSTALLED_TOKEN: &[u8] = b"fail-after-installed-v1";
const MAX_QUALIFICATION_CREDENTIAL_BYTES: u64 = 64;

fn qualification_credential_mode_is_read_only(mode: u32) -> bool {
    // systemd keeps service credentials owner-read-only. For a non-root
    // service it may add a read ACL for the service UID; the ACL mask is
    // represented by the group-read bit even though no group can modify the
    // credential. Accept only those two read-only representations.
    matches!(mode & 0o777, 0o400 | 0o440)
}

/// Closed seam for the post-commit rollback public layer. Implementations must
/// retain all Vault/root authority in the associated types; commands and
/// descriptors are path-free audit material only. The production Vault/root
/// implementation is intentionally not part of this layer.
pub trait RescueFstabRollbackBackend: Send + 'static {
    type PreparedRollback: Send + 'static;
    type ApprovedRollback: Send + 'static;

    fn prepare_rollback(
        &mut self,
        command: &BrokerOwnedRollbackPrepareCommand,
        deadline: Instant,
    ) -> Result<(Self::PreparedRollback, PreparedRollbackDescriptor), RepairEngineFailure>;

    fn approve_rollback(
        &mut self,
        prepared: Self::PreparedRollback,
        approval: &BoundRollbackApproval,
        deadline: Instant,
    ) -> Result<Self::ApprovedRollback, RepairEngineFailure>;

    fn execute_rollback(
        &mut self,
        approved: Self::ApprovedRollback,
        deadline: Instant,
    ) -> Result<RepairTerminalReceipt, RepairEngineFailure>;

    fn cancel_prepared_rollback(
        prepared: Self::PreparedRollback,
        deadline: Instant,
    ) -> Result<(), RepairEngineFailure>;
}

/// Non-cloneable read-only target/Vault authority plus its staged rollback
/// admission. No child transaction or writable mount exists at this point.
pub struct ProductionPreparedRollback {
    authority: PreparedRescueFstabRollback,
    admission: RescueFstabRollbackAdmission,
}

/// Core-approved and durably persisted child authority consumed by execution.
pub struct ProductionApprovedRollback(ApprovedRescueFstabRollback);

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

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RepairQualificationConfigurationError {
    InvalidCredential,
}

impl std::fmt::Display for RepairQualificationConfigurationError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("invalid closed repair qualification credential")
    }
}

impl std::error::Error for RepairQualificationConfigurationError {}

#[derive(Default)]
pub struct ProductionRepairEngine {
    qualification_fault: RescueFstabQualificationFault,
}

impl ProductionRepairEngine {
    pub const fn new() -> Self {
        Self {
            qualification_fault: RescueFstabQualificationFault::None,
        }
    }

    /// Loads the sole optional QEMU qualification credential propagated by
    /// systemd. The directory and filename are fixed, the file must be the
    /// read-only regular credential created for this exact unit, and only two
    /// compiled tokens are accepted. An absent credential is the normal
    /// production-candidate configuration.
    pub fn from_systemd_qualification_credential()
    -> Result<Self, RepairQualificationConfigurationError> {
        let Some(directory) = std::env::var_os("CREDENTIALS_DIRECTORY") else {
            return Ok(Self::new());
        };
        if Path::new(&directory) != Path::new(QUALIFICATION_CREDENTIAL_DIRECTORY) {
            return Err(RepairQualificationConfigurationError::InvalidCredential);
        }
        let path = Path::new(&directory).join(QUALIFICATION_CREDENTIAL_NAME);
        let descriptor = match rfs::open(
            &path,
            OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NOFOLLOW,
            Mode::empty(),
        ) {
            Ok(descriptor) => descriptor,
            Err(error) if error == rustix::io::Errno::NOENT => return Ok(Self::new()),
            Err(_) => return Err(RepairQualificationConfigurationError::InvalidCredential),
        };
        let mut credential = File::from(descriptor);
        let before = credential
            .metadata()
            .map_err(|_| RepairQualificationConfigurationError::InvalidCredential)?;
        if !before.file_type().is_file()
            || before.len() == 0
            || before.len() > MAX_QUALIFICATION_CREDENTIAL_BYTES
            || !qualification_credential_mode_is_read_only(before.mode())
            || before.nlink() != 1
        {
            return Err(RepairQualificationConfigurationError::InvalidCredential);
        }
        let mut bytes = Vec::with_capacity(MAX_QUALIFICATION_CREDENTIAL_BYTES as usize);
        (&mut credential)
            .take(MAX_QUALIFICATION_CREDENTIAL_BYTES + 1)
            .read_to_end(&mut bytes)
            .map_err(|_| RepairQualificationConfigurationError::InvalidCredential)?;
        let after = credential
            .metadata()
            .map_err(|_| RepairQualificationConfigurationError::InvalidCredential)?;
        if bytes.len() as u64 != before.len()
            || after.dev() != before.dev()
            || after.ino() != before.ino()
            || after.len() != before.len()
            || after.mode() != before.mode()
            || after.nlink() != before.nlink()
            || after.mtime() != before.mtime()
            || after.mtime_nsec() != before.mtime_nsec()
            || after.ctime() != before.ctime()
            || after.ctime_nsec() != before.ctime_nsec()
        {
            return Err(RepairQualificationConfigurationError::InvalidCredential);
        }

        let qualification_fault = parse_qualification_fault(&bytes)?;
        Ok(Self {
            qualification_fault,
        })
    }
}

fn parse_qualification_fault(
    bytes: &[u8],
) -> Result<RescueFstabQualificationFault, RepairQualificationConfigurationError> {
    match bytes {
        NO_QUALIFICATION_FAULT_TOKEN => Ok(RescueFstabQualificationFault::None),
        TERMINATE_AFTER_PENDING_TOKEN => Ok(RescueFstabQualificationFault::TerminateAfterPending),
        FAIL_AFTER_INSTALLED_TOKEN => Ok(RescueFstabQualificationFault::FailAfterInstalled),
        _ => Err(RepairQualificationConfigurationError::InvalidCredential),
    }
}

impl RepairPreparationEngine for ProductionRepairEngine {
    type Prepared = ProductionPreparedRepair;
    type Approved = ProductionApprovedRepair;

    fn recover_pending(
        &mut self,
        deadline: Instant,
    ) -> Result<Option<RepairTerminalReceipt>, RepairEngineFailure> {
        if let Some(receipt) = recover_pending_rescue_fstab_rollback(deadline)
            .map_err(|_| RepairEngineFailure::RecoveryUnavailable)?
        {
            return rollback_terminal_receipt(receipt).map(Some);
        }
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
            prepared.receipt().intent().resource_id(),
            prepared.receipt().backup_locator(),
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
                return Err(RepairEngineFailure::ApprovalRejected(
                    RepairExecutionFailureStage::ApprovalProof,
                ));
            }
        };
        if proof.session_id() != approval.session_id()
            || proof.binding().plan_id() != approval.plan_id()
            || proof.binding().plan_hash() != approval.plan_hash()
        {
            plan.cancel(deadline)
                .map_err(|_| RepairEngineFailure::CancelFailed)?;
            return Err(RepairEngineFailure::ApprovalRejected(
                RepairExecutionFailureStage::ApprovalBinding,
            ));
        }
        if admission.approve(&proof).is_err() {
            plan.cancel(deadline)
                .map_err(|_| RepairEngineFailure::CancelFailed)?;
            return Err(RepairEngineFailure::ApprovalRejected(
                RepairExecutionFailureStage::ApprovalAdmission,
            ));
        }
        plan.authorize(admission, deadline)
            .map(ProductionApprovedRepair)
            .map_err(map_approval_authorize_failure)
    }

    fn execute(
        &mut self,
        approved: Self::Approved,
        deadline: Instant,
    ) -> Result<RepairTerminalReceipt, RepairEngineFailure> {
        let result = if self.qualification_fault == RescueFstabQualificationFault::None {
            execute_approved_rescue_fstab(approved.0, deadline)
        } else {
            execute_approved_rescue_fstab_with_qualification_fault(
                approved.0,
                deadline,
                self.qualification_fault,
            )
        };
        match result {
            Ok(receipt) => terminal_receipt(receipt),
            Err(error) => match recover_pending_rescue_fstab(deadline) {
                Ok(Some(receipt)) => terminal_receipt(receipt.with_initial_failure(error)),
                Ok(None) => Err(RepairEngineFailure::ExecutionFailed(map_execution_failure(
                    error,
                ))),
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

impl RescueFstabRollbackBackend for ProductionRepairEngine {
    type PreparedRollback = ProductionPreparedRollback;
    type ApprovedRollback = ProductionApprovedRollback;

    fn prepare_rollback(
        &mut self,
        command: &BrokerOwnedRollbackPrepareCommand,
        deadline: Instant,
    ) -> Result<(Self::PreparedRollback, PreparedRollbackDescriptor), RepairEngineFailure> {
        let authority = prepare_rescue_fstab_rollback(
            command.source().reservation_id(),
            command.source().transaction_binding_sha256(),
            deadline,
        )
        .map_err(|_| RepairEngineFailure::RollbackUnavailable)?;
        let source = authority.source();
        let backup = source.backup();
        let intent = backup
            .execution_intent()
            .ok_or(RepairEngineFailure::RollbackUnavailable)?;
        let source_plan_id = backup
            .plan_id()
            .ok_or(RepairEngineFailure::RollbackUnavailable)?;
        let source_plan_hash = prefixed_sha256(
            backup
                .plan_sha256()
                .ok_or(RepairEngineFailure::RollbackUnavailable)?,
        );
        let source_approval_id = backup
            .approval_id()
            .ok_or(RepairEngineFailure::RollbackUnavailable)?;
        let source_binding = RescueFstabRollbackSourceBinding::new(
            source_plan_id,
            &source_plan_hash,
            source_approval_id,
            intent.approval_sequence(),
            backup.reservation_id().as_str(),
            prefixed_sha256(source.transaction_binding_sha256()),
            backup.locator(),
        )
        .map_err(|_| RepairEngineFailure::RollbackUnavailable)?;
        let (plan, plan_hash) = canonical_rescue_fstab_rollback_plan(
            command.plan_id(),
            command.rollback_id(),
            authority.target_fingerprint(),
            command.source().reservation_id(),
            command.source().transaction_binding_sha256(),
        )
        .map_err(|_| RepairEngineFailure::RollbackUnavailable)?;
        let binding = RescueFstabRollbackBinding::new(
            command.session_id(),
            command.rollback_id(),
            command.plan_id(),
            &plan_hash,
            authority.target_fingerprint(),
            source_binding,
        )
        .map_err(|_| RepairEngineFailure::RollbackUnavailable)?;
        let mut session = Session::new(authority.target_fingerprint(), SessionMode::LinuxRescue);
        let admission = session
            .stage_rescue_fstab_rollback(&plan, binding)
            .map_err(|_| RepairEngineFailure::RollbackUnavailable)?;
        let descriptor = PreparedRollbackDescriptor::new(
            command.session_id(),
            command.rollback_id(),
            command.plan_id(),
            &plan_hash,
            authority.target_fingerprint(),
            command.source().clone(),
            source_approval_id,
            backup
                .resource_id()
                .ok_or(RepairEngineFailure::RollbackUnavailable)?,
            backup.locator(),
            admission.next_approval_sequence(),
        )?;
        Ok((
            ProductionPreparedRollback {
                authority,
                admission,
            },
            descriptor,
        ))
    }

    fn approve_rollback(
        &mut self,
        prepared: Self::PreparedRollback,
        approval: &BoundRollbackApproval,
        deadline: Instant,
    ) -> Result<Self::ApprovedRollback, RepairEngineFailure> {
        let ProductionPreparedRollback {
            authority,
            mut admission,
        } = prepared;
        let proof = RescueFstabRollbackApproval::new(
            admission.binding().clone(),
            approval.approval_id(),
            approval.approval_sequence(),
            approval.typed_confirmation(),
        )
        .map_err(|_| {
            RepairEngineFailure::ApprovalRejected(RepairExecutionFailureStage::ApprovalProof)
        })?;
        if proof.binding().session_id() != approval.session_id()
            || proof.binding().rollback_id() != approval.rollback_id()
            || proof.binding().plan_id() != approval.plan_id()
            || proof.binding().plan_hash() != approval.plan_hash()
            || proof.binding().source().reservation_id() != approval.source().reservation_id()
            || proof.binding().source().transaction_binding_sha256()
                != approval.source().transaction_binding_sha256()
        {
            return Err(RepairEngineFailure::ApprovalRejected(
                RepairExecutionFailureStage::ApprovalBinding,
            ));
        }
        admission.approve(&proof).map_err(|_| {
            RepairEngineFailure::ApprovalRejected(RepairExecutionFailureStage::ApprovalAdmission)
        })?;
        let binding = RepairRollbackBindingV1::new(
            authority.source(),
            admission.binding().plan_id(),
            parse_prefixed_sha256(admission.binding().plan_hash())?,
            admission
                .approval_id()
                .ok_or(RepairEngineFailure::Internal)?,
            parse_prefixed_sha256(
                admission
                    .approval_sha256()
                    .ok_or(RepairEngineFailure::Internal)?,
            )?,
            admission.next_approval_sequence(),
        )
        .map_err(|_| {
            RepairEngineFailure::ApprovalRejected(RepairExecutionFailureStage::ApprovalAuthorize)
        })?;
        match authorize_prepared_rescue_fstab_rollback(
            authority,
            approval.rollback_id(),
            binding,
            deadline,
        ) {
            Ok(approved) => Ok(ProductionApprovedRollback(approved)),
            Err(RescueFstabExecutionError::AuthorizationNotPersisted) => {
                Err(RepairEngineFailure::ApprovalRejected(
                    RepairExecutionFailureStage::ApprovalAuthorize,
                ))
            }
            Err(error) => Err(RepairEngineFailure::ExecutionFailed(map_execution_failure(
                error,
            ))),
        }
    }

    fn execute_rollback(
        &mut self,
        approved: Self::ApprovedRollback,
        deadline: Instant,
    ) -> Result<RepairTerminalReceipt, RepairEngineFailure> {
        match execute_approved_rescue_fstab_rollback(approved.0, deadline) {
            Ok(receipt) => rollback_terminal_receipt(receipt),
            Err(error) => match recover_pending_rescue_fstab_rollback(deadline) {
                Ok(Some(receipt)) => rollback_terminal_receipt(receipt),
                Ok(None) | Err(_) => Err(RepairEngineFailure::ExecutionFailed(
                    map_execution_failure(error),
                )),
            },
        }
    }

    fn cancel_prepared_rollback(
        prepared: Self::PreparedRollback,
        _deadline: Instant,
    ) -> Result<(), RepairEngineFailure> {
        drop(prepared);
        Ok(())
    }
}

fn map_execution_failure(error: RescueFstabExecutionError) -> RepairExecutionFailureStage {
    match error {
        RescueFstabExecutionError::InvalidAuthority => RepairExecutionFailureStage::Authority,
        RescueFstabExecutionError::AuthorizationNotPersisted => {
            RepairExecutionFailureStage::ApprovalAuthorize
        }
        RescueFstabExecutionError::TargetChanged | RescueFstabExecutionError::UnsafeTarget => {
            RepairExecutionFailureStage::Target
        }
        RescueFstabExecutionError::LockUnavailable => RepairExecutionFailureStage::Lock,
        RescueFstabExecutionError::TimedOut => RepairExecutionFailureStage::Timeout,
        RescueFstabExecutionError::VaultUnavailable
        | RescueFstabExecutionError::VaultReconciliationRequired => {
            RepairExecutionFailureStage::Vault
        }
        RescueFstabExecutionError::DetachedMountUnavailable
        | RescueFstabExecutionError::RecoveryRequired => RepairExecutionFailureStage::Write,
        RescueFstabExecutionError::MutationFailed => RepairExecutionFailureStage::Mutation,
        RescueFstabExecutionError::RecoveryUnavailable => RepairExecutionFailureStage::Recovery,
    }
}

fn map_approval_authorize_failure(error: RescueFstabPreflightError) -> RepairEngineFailure {
    if error == RescueFstabPreflightError::CancellationFailed {
        RepairEngineFailure::CancelFailed
    } else {
        RepairEngineFailure::ApprovalRejected(RepairExecutionFailureStage::ApprovalAuthorize)
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
    let execution_failure_stage = receipt.initial_failure().map(map_execution_failure);
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
    terminal_receipt_from_executor_parts(
        outcome,
        receipt.reservation_id(),
        receipt.transaction_binding_sha256(),
    )?
    .with_execution_failure_stage(execution_failure_stage)
}

fn rollback_terminal_receipt(
    receipt: RescueFstabRollbackExecutionReceipt,
) -> Result<RepairTerminalReceipt, RepairEngineFailure> {
    let outcome = match receipt.outcome() {
        RescueFstabRollbackExecutionOutcome::RolledBackOriginal => {
            RepairTerminalOutcome::RolledBackOriginal
        }
        RescueFstabRollbackExecutionOutcome::ManualReconciliationRequired => {
            RepairTerminalOutcome::ManualReconciliationRequired
        }
    };
    terminal_receipt_from_executor_parts(
        outcome,
        receipt.source_reservation_id(),
        receipt.source_transaction_binding_sha256(),
    )
}

fn prefixed_sha256(value: &Sha256) -> String {
    format!("sha256:{}", value.as_str())
}

fn parse_prefixed_sha256(value: &str) -> Result<Sha256, RepairEngineFailure> {
    value
        .strip_prefix("sha256:")
        .ok_or(RepairEngineFailure::Internal)
        .and_then(|digest| Sha256::parse(digest).map_err(|_| RepairEngineFailure::Internal))
}

fn terminal_receipt_from_executor_parts(
    outcome: RepairTerminalOutcome,
    reservation_id: &str,
    transaction_binding_sha256: &str,
) -> Result<RepairTerminalReceipt, RepairEngineFailure> {
    RepairTerminalReceipt::new(
        outcome,
        Some(reservation_id.to_owned()),
        Some(format!("sha256:{transaction_binding_sha256}")),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rescue_fstab_candidate::RescueFstabCapabilityResolutionError;

    #[test]
    fn executor_digest_is_rendered_in_public_sha256_grammar() {
        assert!(
            terminal_receipt_from_executor_parts(
                RepairTerminalOutcome::Committed,
                "B-0123456789abcdef0123456789abcdef",
                &"5".repeat(64),
            )
            .is_ok()
        );
    }

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

    #[test]
    fn execution_failures_map_to_closed_internal_stages() {
        for (error, expected) in [
            (
                RescueFstabExecutionError::InvalidAuthority,
                RepairExecutionFailureStage::Authority,
            ),
            (
                RescueFstabExecutionError::TargetChanged,
                RepairExecutionFailureStage::Target,
            ),
            (
                RescueFstabExecutionError::UnsafeTarget,
                RepairExecutionFailureStage::Target,
            ),
            (
                RescueFstabExecutionError::LockUnavailable,
                RepairExecutionFailureStage::Lock,
            ),
            (
                RescueFstabExecutionError::TimedOut,
                RepairExecutionFailureStage::Timeout,
            ),
            (
                RescueFstabExecutionError::VaultUnavailable,
                RepairExecutionFailureStage::Vault,
            ),
            (
                RescueFstabExecutionError::VaultReconciliationRequired,
                RepairExecutionFailureStage::Vault,
            ),
            (
                RescueFstabExecutionError::DetachedMountUnavailable,
                RepairExecutionFailureStage::Write,
            ),
            (
                RescueFstabExecutionError::RecoveryRequired,
                RepairExecutionFailureStage::Write,
            ),
            (
                RescueFstabExecutionError::MutationFailed,
                RepairExecutionFailureStage::Mutation,
            ),
            (
                RescueFstabExecutionError::RecoveryUnavailable,
                RepairExecutionFailureStage::Recovery,
            ),
        ] {
            assert_eq!(map_execution_failure(error), expected);
        }
    }

    #[test]
    fn authorize_distinguishes_rejection_from_cancellation_failure() {
        assert_eq!(
            map_approval_authorize_failure(RescueFstabPreflightError::ApprovalBindingMismatch),
            RepairEngineFailure::ApprovalRejected(RepairExecutionFailureStage::ApprovalAuthorize)
        );
        assert_eq!(
            map_approval_authorize_failure(RescueFstabPreflightError::CancellationFailed),
            RepairEngineFailure::CancelFailed
        );
    }

    #[test]
    fn qualification_fault_parser_accepts_only_default_or_two_fixed_faults() {
        assert_eq!(
            parse_qualification_fault(NO_QUALIFICATION_FAULT_TOKEN),
            Ok(RescueFstabQualificationFault::None)
        );
        assert_eq!(
            parse_qualification_fault(TERMINATE_AFTER_PENDING_TOKEN),
            Ok(RescueFstabQualificationFault::TerminateAfterPending)
        );
        assert_eq!(
            parse_qualification_fault(FAIL_AFTER_INSTALLED_TOKEN),
            Ok(RescueFstabQualificationFault::FailAfterInstalled)
        );
        for rejected in [
            b"".as_slice(),
            b"terminate-after-pending-v1\n".as_slice(),
            b"fail-after-installed-v2".as_slice(),
            b"shell.exec".as_slice(),
        ] {
            assert_eq!(
                parse_qualification_fault(rejected),
                Err(RepairQualificationConfigurationError::InvalidCredential)
            );
        }
    }

    #[test]
    fn qualification_credential_mode_accepts_only_systemd_read_acl_forms() {
        for accepted in [0o100400, 0o100440] {
            assert!(qualification_credential_mode_is_read_only(accepted));
        }
        for rejected in [
            0o100000, 0o100040, 0o100404, 0o100444, 0o100600, 0o100640, 0o100660,
        ] {
            assert!(!qualification_credential_mode_is_read_only(rejected));
        }
    }

    #[test]
    fn ordinary_candidate_engine_has_no_qualification_fault() {
        assert_eq!(
            ProductionRepairEngine::new().qualification_fault,
            RescueFstabQualificationFault::None
        );
    }
}
