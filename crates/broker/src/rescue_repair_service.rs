//! Closed local control plane for the off-default Rescue `fstab` candidate.
//!
//! This module deliberately separates the socket/state-machine boundary from
//! the production preparation adapter.  A client can select only one already
//! discovered boot-local target and can never submit a pathname, device name,
//! action identifier, command, observed bytes, or replacement bytes.

use kernaid_core::RESCUE_FSTAB_TYPED_CONFIRMATION;
use kernaid_linux_pack::production_candidate_contract::ACTION_ID;
use kernaid_protocol::rescue_vault::RequestId;
use rustix::rand::{GetRandomFlags, getrandom};
use serde::{Deserialize, Serialize};
use std::{
    fmt,
    sync::mpsc::{self, Receiver, SyncSender, TrySendError},
    thread,
    time::{Duration, Instant},
};

pub const REPAIR_SERVICE_API_VERSION: &str = "kernaid.dev/rescue-repair-service/v1alpha1";
pub const REPAIR_SERVICE_MAX_FRAME_BYTES: usize = 4096;

// Preparation includes the repeated root-owned target observation plus the
// first durable Vault reservation. Slow USB media and the TCG qualification
// must retain useful time for both while the operation remains bounded.
const PREPARE_TIMEOUT: Duration = Duration::from_secs(120);
const EXECUTE_TIMEOUT: Duration = Duration::from_secs(150);
const CANCEL_TIMEOUT: Duration = Duration::from_secs(15);
const RISK_ID: &str = "R2";

/// Boot-local, path-free selector accepted by `repair.fstab.prepare`.
#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RepairTargetSelector {
    scan_fingerprint: String,
    target_fingerprint: String,
    target_id: String,
}

impl RepairTargetSelector {
    pub fn scan_fingerprint(&self) -> &str {
        &self.scan_fingerprint
    }

    pub fn target_fingerprint(&self) -> &str {
        &self.target_fingerprint
    }

    pub fn target_id(&self) -> &str {
        &self.target_id
    }

    fn validate(&self) -> Result<(), RepairServiceErrorToken> {
        if !valid_prefixed_hash(&self.scan_fingerprint, "scan:")
            || !valid_prefixed_hash(&self.target_fingerprint, "sha256:")
            || !valid_prefixed_hash(&self.target_id, "target:")
        {
            return Err(RepairServiceErrorToken::InvalidRequest);
        }
        Ok(())
    }
}

/// Strict request union. Serde rejects unknown and duplicate fields.
#[derive(Debug, Deserialize, PartialEq, Eq)]
#[serde(tag = "operation", deny_unknown_fields)]
pub enum RepairServiceRequest {
    #[serde(rename = "repair.status")]
    Status {
        #[serde(rename = "apiVersion")]
        api_version: String,
        #[serde(rename = "requestId")]
        request_id: String,
    },
    #[serde(rename = "repair.fstab.prepare")]
    Prepare {
        #[serde(rename = "apiVersion")]
        api_version: String,
        #[serde(rename = "requestId")]
        request_id: String,
        target: RepairTargetSelector,
    },
    #[serde(rename = "repair.fstab.approve")]
    Approve {
        #[serde(rename = "apiVersion")]
        api_version: String,
        #[serde(rename = "requestId")]
        request_id: String,
        #[serde(rename = "preparedId")]
        prepared_id: String,
        #[serde(rename = "sessionId")]
        session_id: String,
        #[serde(rename = "planId")]
        plan_id: String,
        #[serde(rename = "planHash")]
        plan_hash: String,
        #[serde(rename = "approvalId")]
        approval_id: String,
        #[serde(rename = "approvalSequence")]
        approval_sequence: u64,
        #[serde(rename = "typedConfirmation")]
        typed_confirmation: String,
    },
    #[serde(rename = "repair.fstab.cancel")]
    Cancel {
        #[serde(rename = "apiVersion")]
        api_version: String,
        #[serde(rename = "requestId")]
        request_id: String,
        #[serde(rename = "preparedId")]
        prepared_id: String,
        #[serde(rename = "planHash")]
        plan_hash: String,
    },
}

impl RepairServiceRequest {
    fn operation(&self) -> &'static str {
        match self {
            Self::Status { .. } => "repair.status",
            Self::Prepare { .. } => "repair.fstab.prepare",
            Self::Approve { .. } => "repair.fstab.approve",
            Self::Cancel { .. } => "repair.fstab.cancel",
        }
    }

    fn api_version(&self) -> &str {
        match self {
            Self::Status { api_version, .. }
            | Self::Prepare { api_version, .. }
            | Self::Approve { api_version, .. }
            | Self::Cancel { api_version, .. } => api_version,
        }
    }

    fn request_id(&self) -> &str {
        match self {
            Self::Status { request_id, .. }
            | Self::Prepare { request_id, .. }
            | Self::Approve { request_id, .. }
            | Self::Cancel { request_id, .. } => request_id,
        }
    }

    fn validate_envelope(&self) -> Result<(), RepairServiceErrorToken> {
        if self.api_version() != REPAIR_SERVICE_API_VERSION
            || RequestId::parse(self.request_id()).is_err()
        {
            return Err(RepairServiceErrorToken::InvalidRequest);
        }
        match self {
            Self::Status { .. } => Ok(()),
            Self::Prepare { target, .. } => target.validate(),
            Self::Approve {
                prepared_id,
                session_id,
                plan_id,
                plan_hash,
                approval_id,
                approval_sequence,
                typed_confirmation,
                ..
            } => {
                if !valid_fixed_id(prepared_id, "Q-")
                    || !valid_fixed_id(session_id, "S-")
                    || !valid_fixed_id(plan_id, "P-")
                    || !valid_prefixed_hash(plan_hash, "sha256:")
                    || !valid_fixed_id(approval_id, "A-")
                    || *approval_sequence == 0
                    || typed_confirmation != RESCUE_FSTAB_TYPED_CONFIRMATION
                {
                    return Err(RepairServiceErrorToken::InvalidRequest);
                }
                Ok(())
            }
            Self::Cancel {
                prepared_id,
                plan_hash,
                ..
            } => {
                if !valid_fixed_id(prepared_id, "Q-") || !valid_prefixed_hash(plan_hash, "sha256:")
                {
                    return Err(RepairServiceErrorToken::InvalidRequest);
                }
                Ok(())
            }
        }
    }
}

/// Only input passed from this service into the broker-owned prepare adapter.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BrokerOwnedPrepareCommand {
    request_id: String,
    session_id: String,
    plan_id: String,
    target: RepairTargetSelector,
}

impl BrokerOwnedPrepareCommand {
    pub fn request_id(&self) -> &str {
        &self.request_id
    }

    pub fn session_id(&self) -> &str {
        &self.session_id
    }

    pub fn plan_id(&self) -> &str {
        &self.plan_id
    }

    pub const fn target(&self) -> &RepairTargetSelector {
        &self.target
    }
}

/// Exact approval material echoed from a prepared response. Implementations
/// still have to submit it to Core; matching here is not an admission bypass.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BoundRepairApproval {
    request_id: String,
    prepared_id: String,
    session_id: String,
    plan_id: String,
    plan_hash: String,
    approval_id: String,
    approval_sequence: u64,
    typed_confirmation: String,
}

impl BoundRepairApproval {
    pub fn request_id(&self) -> &str {
        &self.request_id
    }

    pub fn prepared_id(&self) -> &str {
        &self.prepared_id
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

/// Sanitized engine failure classes. No implementation error text crosses the
/// local API boundary.
#[derive(Clone, Copy, Debug, Serialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum RepairPrepareFailureStage {
    TargetCapability,
    ObservationPreview,
    VaultReserve,
    AdmissionInternal,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RepairEngineFailure {
    PrepareFailed(RepairPrepareFailureStage),
    ApprovalRejected,
    CancelFailed,
    ExecutionFailed,
    RecoveryUnavailable,
    Internal,
}

/// Path-free terminal result produced by execution or startup recovery.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RepairTerminalReceipt {
    outcome: RepairTerminalOutcome,
    reservation_id: Option<String>,
    transaction_binding_sha256: Option<String>,
    prepare_failure_stage: Option<RepairPrepareFailureStage>,
}

impl RepairTerminalReceipt {
    pub fn new(
        outcome: RepairTerminalOutcome,
        reservation_id: Option<String>,
        transaction_binding_sha256: Option<String>,
    ) -> Result<Self, RepairEngineFailure> {
        let has_transaction = reservation_id.is_some() || transaction_binding_sha256.is_some();
        if has_transaction
            && (!reservation_id.as_deref().is_some_and(valid_reservation_id)
                || !transaction_binding_sha256
                    .as_deref()
                    .is_some_and(|value| valid_prefixed_hash(value, "sha256:")))
        {
            return Err(RepairEngineFailure::Internal);
        }
        if matches!(
            outcome,
            RepairTerminalOutcome::Cancelled | RepairTerminalOutcome::Failed
        ) && has_transaction
        {
            return Err(RepairEngineFailure::Internal);
        }
        if matches!(
            outcome,
            RepairTerminalOutcome::Committed
                | RepairTerminalOutcome::ClosedBeforeUnchanged
                | RepairTerminalOutcome::ClosedBeforeRestored
        ) && !has_transaction
        {
            return Err(RepairEngineFailure::Internal);
        }
        Ok(Self {
            outcome,
            reservation_id,
            transaction_binding_sha256,
            prepare_failure_stage: None,
        })
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RepairTerminalOutcome {
    Committed,
    ClosedBeforeUnchanged,
    ClosedBeforeRestored,
    Cancelled,
    ManualReconciliationRequired,
    Failed,
}

/// Audit-only summary returned by the production prepare adapter beside its
/// non-cloneable authority.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PreparedRepairDescriptor {
    session_id: String,
    plan_id: String,
    plan_hash: String,
    target_fingerprint: String,
    before_sha256: String,
    after_sha256: String,
    diff_sha256: String,
    next_approval_sequence: u64,
    backup_reserved: bool,
    vault_distinct: bool,
}

impl PreparedRepairDescriptor {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        session_id: impl Into<String>,
        plan_id: impl Into<String>,
        plan_hash: impl Into<String>,
        target_fingerprint: impl Into<String>,
        before_sha256: impl Into<String>,
        after_sha256: impl Into<String>,
        diff_sha256: impl Into<String>,
        next_approval_sequence: u64,
        backup_reserved: bool,
        vault_distinct: bool,
    ) -> Result<Self, RepairEngineFailure> {
        let value = Self {
            session_id: session_id.into(),
            plan_id: plan_id.into(),
            plan_hash: plan_hash.into(),
            target_fingerprint: target_fingerprint.into(),
            before_sha256: before_sha256.into(),
            after_sha256: after_sha256.into(),
            diff_sha256: diff_sha256.into(),
            next_approval_sequence,
            backup_reserved,
            vault_distinct,
        };
        if !valid_fixed_id(&value.session_id, "S-")
            || !valid_fixed_id(&value.plan_id, "P-")
            || !valid_prefixed_hash(&value.plan_hash, "sha256:")
            || !valid_prefixed_hash(&value.target_fingerprint, "sha256:")
            || !valid_prefixed_hash(&value.before_sha256, "sha256:")
            || !valid_prefixed_hash(&value.after_sha256, "sha256:")
            || !valid_prefixed_hash(&value.diff_sha256, "sha256:")
            || value.next_approval_sequence == 0
            || !value.backup_reserved
            || !value.vault_distinct
        {
            return Err(RepairEngineFailure::Internal);
        }
        Ok(value)
    }
}

/// Seam implemented by the broker-owned preparation/Core/executor adapter.
/// `Prepared` and `Approved` are deliberately non-Clone associated types.
pub trait RepairPreparationEngine: Send + 'static {
    type Prepared: Send + 'static;
    type Approved: Send + 'static;

    fn recover_pending(
        &mut self,
        deadline: Instant,
    ) -> Result<Option<RepairTerminalReceipt>, RepairEngineFailure>;

    fn prepare(
        &mut self,
        command: &BrokerOwnedPrepareCommand,
        deadline: Instant,
    ) -> Result<(Self::Prepared, PreparedRepairDescriptor), RepairEngineFailure>;

    fn approve(
        &mut self,
        prepared: Self::Prepared,
        approval: &BoundRepairApproval,
        deadline: Instant,
    ) -> Result<Self::Approved, RepairEngineFailure>;

    fn execute(
        &mut self,
        approved: Self::Approved,
        deadline: Instant,
    ) -> Result<RepairTerminalReceipt, RepairEngineFailure>;

    /// Must durably cancel the reservation retained by `prepared`.
    fn cancel_prepared(
        prepared: Self::Prepared,
        deadline: Instant,
    ) -> Result<(), RepairEngineFailure>;
}

#[derive(Clone, Copy, Debug, Serialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum RepairServiceErrorToken {
    InvalidRequest,
    Unauthorized,
    Busy,
    StateConflict,
    BindingMismatch,
    ApprovalRejected,
    PrepareFailed,
    CancelFailed,
    ExecutionFailed,
    RecoveryUnavailable,
    Internal,
}

#[derive(Clone, Copy, Debug, Serialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum RepairPublicState {
    Idle,
    Preparing,
    Prepared,
    Executing,
    Succeeded,
    Restored,
    Cancelled,
    ManualReconciliationRequired,
    Failed,
}

#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct PreparedRepairDetail {
    kind: &'static str,
    prepared_id: String,
    session_id: String,
    plan_id: String,
    plan_hash: String,
    target_fingerprint: String,
    before_sha256: String,
    after_sha256: String,
    diff_sha256: String,
    action_id: &'static str,
    risk: &'static str,
    backup: PreparedBackupDetail,
    next_approval_sequence: u64,
    confirmation_required: &'static str,
}

#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
struct PreparedBackupDetail {
    state: &'static str,
    vault_distinct: bool,
}

#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct TerminalRepairDetail {
    kind: &'static str,
    terminal_outcome: &'static str,
    reservation_id: Option<String>,
    transaction_binding_sha256: Option<String>,
    reboot_required: bool,
    prepare_failure_stage: Option<RepairPrepareFailureStage>,
}

#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
#[serde(untagged)]
pub enum RepairResponseDetail {
    Prepared(PreparedRepairDetail),
    Terminal(TerminalRepairDetail),
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct SuccessResponse<'a> {
    api_version: &'static str,
    request_id: &'a str,
    operation: &'a str,
    outcome: &'static str,
    state_version: u64,
    state: RepairPublicState,
    detail: Option<RepairResponseDetail>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct ErrorResponse<'a> {
    api_version: &'static str,
    request_id: &'a str,
    operation: &'a str,
    outcome: &'static str,
    state_version: u64,
    state: RepairPublicState,
    detail: Option<RepairResponseDetail>,
    error: RepairServiceErrorToken,
}

#[derive(Clone, Debug)]
struct PreparedSummary {
    prepare_request_id: String,
    prepared_id: String,
    descriptor: PreparedRepairDescriptor,
}

impl PreparedSummary {
    fn detail(&self) -> PreparedRepairDetail {
        PreparedRepairDetail {
            kind: "fstab-prepared",
            prepared_id: self.prepared_id.clone(),
            session_id: self.descriptor.session_id.clone(),
            plan_id: self.descriptor.plan_id.clone(),
            plan_hash: self.descriptor.plan_hash.clone(),
            target_fingerprint: self.descriptor.target_fingerprint.clone(),
            before_sha256: self.descriptor.before_sha256.clone(),
            after_sha256: self.descriptor.after_sha256.clone(),
            diff_sha256: self.descriptor.diff_sha256.clone(),
            action_id: ACTION_ID,
            risk: RISK_ID,
            backup: PreparedBackupDetail {
                state: "reserved",
                vault_distinct: true,
            },
            next_approval_sequence: self.descriptor.next_approval_sequence,
            confirmation_required: RESCUE_FSTAB_TYPED_CONFIRMATION,
        }
    }
}

enum InternalState<Prepared> {
    Idle,
    Preparing {
        operation_id: u64,
        command: BrokerOwnedPrepareCommand,
        prepared_id: String,
    },
    Prepared {
        authority: Prepared,
        summary: PreparedSummary,
    },
    Executing {
        operation_id: u64,
    },
    Terminal(RepairTerminalReceipt),
}

struct ServiceState<Prepared> {
    version: u64,
    next_operation_id: u64,
    phase: InternalState<Prepared>,
}

enum WorkerJob<Prepared> {
    Prepare {
        operation_id: u64,
        command: BrokerOwnedPrepareCommand,
        deadline: Instant,
    },
    ApproveAndExecute {
        operation_id: u64,
        prepared: Prepared,
        approval: BoundRepairApproval,
        deadline: Instant,
    },
    Cancel {
        operation_id: u64,
        prepared: Prepared,
        deadline: Instant,
    },
}

enum WorkerResult<Prepared> {
    Prepared {
        operation_id: u64,
        result: Result<(Prepared, PreparedRepairDescriptor), RepairEngineFailure>,
    },
    Executed {
        operation_id: u64,
        result: Result<RepairTerminalReceipt, RepairEngineFailure>,
    },
    Cancelled {
        operation_id: u64,
        result: Result<(), RepairEngineFailure>,
    },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RepairServiceStartError {
    RecoveryUnavailable,
    WorkerUnavailable,
}

impl fmt::Display for RepairServiceStartError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::RecoveryUnavailable => "repair recovery barrier unavailable",
            Self::WorkerUnavailable => "repair worker unavailable",
        })
    }
}

impl std::error::Error for RepairServiceStartError {}

/// Single non-cloneable service state machine. Startup performs the durable
/// PendingSingleton recovery barrier before the worker is created or any
/// readiness notification can be emitted by the caller.
pub struct RescueRepairService<Engine: RepairPreparationEngine> {
    state: ServiceState<Engine::Prepared>,
    jobs: SyncSender<WorkerJob<Engine::Prepared>>,
    results: Receiver<WorkerResult<Engine::Prepared>>,
}

impl<Engine: RepairPreparationEngine> RescueRepairService<Engine> {
    pub fn start(
        mut engine: Engine,
        recovery_deadline: Instant,
    ) -> Result<Self, RepairServiceStartError> {
        let recovered = engine
            .recover_pending(recovery_deadline)
            .map_err(|_| RepairServiceStartError::RecoveryUnavailable)?;
        let initial_phase = recovered.map_or(InternalState::Idle, InternalState::Terminal);
        let (job_tx, job_rx) = mpsc::sync_channel(1);
        let (result_tx, result_rx) = mpsc::sync_channel(1);
        thread::Builder::new()
            .name("kernaid-repair-worker".to_owned())
            .spawn(move || run_worker(engine, job_rx, result_tx))
            .map_err(|_| RepairServiceStartError::WorkerUnavailable)?;
        Ok(Self {
            state: ServiceState {
                version: 1,
                next_operation_id: 1,
                phase: initial_phase,
            },
            jobs: job_tx,
            results: result_rx,
        })
    }

    /// Parses one complete bounded seqpacket and returns one complete bounded
    /// response. Peer authentication is performed by the transport before
    /// this method is called.
    pub fn handle_frame(&mut self, frame: &[u8]) -> Vec<u8> {
        self.drain_results();
        let correlation = correlation_probe(frame);
        if frame.is_empty() || frame.len() > REPAIR_SERVICE_MAX_FRAME_BYTES {
            return self.encode_error(
                correlation.request_id(),
                correlation.operation(),
                RepairServiceErrorToken::InvalidRequest,
            );
        }
        let request: RepairServiceRequest = match serde_json::from_slice(frame) {
            Ok(request) => request,
            Err(_) => {
                return self.encode_error(
                    correlation.request_id(),
                    correlation.operation(),
                    RepairServiceErrorToken::InvalidRequest,
                );
            }
        };
        if let Err(error) = request.validate_envelope() {
            return self.encode_error(request.request_id(), request.operation(), error);
        }
        let request_id = request.request_id().to_owned();
        let operation = request.operation();
        let outcome = self.dispatch(request);
        self.drain_results();
        match outcome {
            Ok(()) => self.encode_success(&request_id, operation),
            Err(error) => self.encode_error(&request_id, operation, error),
        }
    }

    pub fn public_state(&mut self) -> RepairPublicState {
        self.drain_results();
        self.snapshot().0
    }

    pub fn state_version(&mut self) -> u64 {
        self.drain_results();
        self.state.version
    }

    fn dispatch(&mut self, request: RepairServiceRequest) -> Result<(), RepairServiceErrorToken> {
        match request {
            RepairServiceRequest::Status { .. } => Ok(()),
            RepairServiceRequest::Prepare {
                request_id, target, ..
            } => self.begin_prepare(request_id, target),
            RepairServiceRequest::Approve {
                request_id,
                prepared_id,
                session_id,
                plan_id,
                plan_hash,
                approval_id,
                approval_sequence,
                typed_confirmation,
                ..
            } => self.begin_approval(BoundRepairApproval {
                request_id,
                prepared_id,
                session_id,
                plan_id,
                plan_hash,
                approval_id,
                approval_sequence,
                typed_confirmation,
            }),
            RepairServiceRequest::Cancel {
                request_id,
                prepared_id,
                plan_hash,
                ..
            } => self.begin_cancel(&request_id, &prepared_id, &plan_hash),
        }
    }

    fn begin_prepare(
        &mut self,
        request_id: String,
        target: RepairTargetSelector,
    ) -> Result<(), RepairServiceErrorToken> {
        match self.state.phase {
            InternalState::Idle => {}
            InternalState::Preparing { .. } | InternalState::Executing { .. } => {
                return Err(RepairServiceErrorToken::Busy);
            }
            InternalState::Prepared { .. } | InternalState::Terminal(_) => {
                return Err(RepairServiceErrorToken::StateConflict);
            }
        }
        let session_id = session_id_from_request(&request_id)?;
        let plan_id = fresh_fixed_id("P-")?;
        let prepared_id = fresh_fixed_id("Q-")?;
        let operation_id = self.take_operation_id()?;
        let command = BrokerOwnedPrepareCommand {
            request_id,
            session_id,
            plan_id,
            target,
        };
        let deadline = absolute_deadline(PREPARE_TIMEOUT)?;
        let job = WorkerJob::Prepare {
            operation_id,
            command: command.clone(),
            deadline,
        };
        self.jobs
            .try_send(job)
            .map_err(|_| RepairServiceErrorToken::Internal)?;
        self.state.phase = InternalState::Preparing {
            operation_id,
            command,
            prepared_id,
        };
        self.bump_version()?;
        Ok(())
    }

    fn begin_approval(
        &mut self,
        approval: BoundRepairApproval,
    ) -> Result<(), RepairServiceErrorToken> {
        match &self.state.phase {
            InternalState::Preparing { .. } | InternalState::Executing { .. } => {
                return Err(RepairServiceErrorToken::Busy);
            }
            InternalState::Idle | InternalState::Terminal(_) => {
                return Err(RepairServiceErrorToken::StateConflict);
            }
            InternalState::Prepared { summary, .. } => {
                if approval.request_id == summary.prepare_request_id
                    || approval.prepared_id != summary.prepared_id
                    || approval.session_id != summary.descriptor.session_id
                    || approval.plan_id != summary.descriptor.plan_id
                    || approval.plan_hash != summary.descriptor.plan_hash
                    || approval.approval_sequence != summary.descriptor.next_approval_sequence
                {
                    return Err(RepairServiceErrorToken::BindingMismatch);
                }
            }
        }
        let operation_id = self.take_operation_id()?;
        let deadline = absolute_deadline(EXECUTE_TIMEOUT)?;
        let previous = std::mem::replace(
            &mut self.state.phase,
            InternalState::Executing { operation_id },
        );
        let InternalState::Prepared {
            authority: prepared,
            ..
        } = previous
        else {
            return Err(RepairServiceErrorToken::Internal);
        };
        let job = WorkerJob::ApproveAndExecute {
            operation_id,
            prepared,
            approval,
            deadline,
        };
        if let Err(error) = self.jobs.try_send(job) {
            let rejected = match error {
                TrySendError::Full(job) | TrySendError::Disconnected(job) => job,
            };
            let recovered = match rejected {
                WorkerJob::ApproveAndExecute { prepared, .. } => prepared,
                WorkerJob::Prepare { .. } | WorkerJob::Cancel { .. } => {
                    return Err(RepairServiceErrorToken::Internal);
                }
            };
            let _ = Engine::cancel_prepared(recovered, Instant::now() + CANCEL_TIMEOUT);
            self.state.phase = InternalState::Terminal(failed_receipt());
            self.bump_version()?;
            return Err(RepairServiceErrorToken::Internal);
        }
        self.bump_version()?;
        Ok(())
    }

    fn begin_cancel(
        &mut self,
        request_id: &str,
        prepared_id: &str,
        plan_hash: &str,
    ) -> Result<(), RepairServiceErrorToken> {
        match &self.state.phase {
            InternalState::Preparing { .. } | InternalState::Executing { .. } => {
                return Err(RepairServiceErrorToken::Busy);
            }
            InternalState::Idle | InternalState::Terminal(_) => {
                return Err(RepairServiceErrorToken::StateConflict);
            }
            InternalState::Prepared { summary, .. } => {
                if request_id == summary.prepare_request_id
                    || prepared_id != summary.prepared_id
                    || plan_hash != summary.descriptor.plan_hash
                {
                    return Err(RepairServiceErrorToken::BindingMismatch);
                }
            }
        }
        let operation_id = self.take_operation_id()?;
        let deadline = absolute_deadline(CANCEL_TIMEOUT)?;
        let previous = std::mem::replace(
            &mut self.state.phase,
            InternalState::Executing { operation_id },
        );
        let InternalState::Prepared {
            authority: prepared,
            ..
        } = previous
        else {
            return Err(RepairServiceErrorToken::Internal);
        };
        let job = WorkerJob::Cancel {
            operation_id,
            prepared,
            deadline,
        };
        if let Err(error) = self.jobs.try_send(job) {
            let rejected = match error {
                TrySendError::Full(job) | TrySendError::Disconnected(job) => job,
            };
            let recovered = match rejected {
                WorkerJob::Cancel { prepared, .. } => prepared,
                WorkerJob::Prepare { .. } | WorkerJob::ApproveAndExecute { .. } => {
                    return Err(RepairServiceErrorToken::Internal);
                }
            };
            let _ = Engine::cancel_prepared(recovered, Instant::now() + CANCEL_TIMEOUT);
            self.state.phase = InternalState::Terminal(failed_receipt());
            self.bump_version()?;
            return Err(RepairServiceErrorToken::Internal);
        }
        self.bump_version()?;
        Ok(())
    }

    fn drain_results(&mut self) {
        while let Ok(result) = self.results.try_recv() {
            self.apply_worker_result(result);
        }
    }

    fn apply_worker_result(&mut self, result: WorkerResult<Engine::Prepared>) {
        match result {
            WorkerResult::Prepared {
                operation_id,
                result,
            } => {
                let InternalState::Preparing {
                    operation_id: expected,
                    command,
                    prepared_id,
                } = &self.state.phase
                else {
                    if let Ok((prepared, _)) = result {
                        let _ = Engine::cancel_prepared(prepared, Instant::now() + CANCEL_TIMEOUT);
                    }
                    return;
                };
                if operation_id != *expected {
                    if let Ok((prepared, _)) = result {
                        let _ = Engine::cancel_prepared(prepared, Instant::now() + CANCEL_TIMEOUT);
                    }
                    return;
                }
                match result {
                    Ok((authority, descriptor)) if descriptor_matches(command, &descriptor) => {
                        let summary = PreparedSummary {
                            prepare_request_id: command.request_id.clone(),
                            prepared_id: prepared_id.clone(),
                            descriptor,
                        };
                        self.state.phase = InternalState::Prepared { authority, summary };
                    }
                    Ok((authority, _)) => {
                        let _ = Engine::cancel_prepared(authority, Instant::now() + CANCEL_TIMEOUT);
                        self.state.phase = InternalState::Terminal(prepare_failed_receipt(
                            RepairPrepareFailureStage::AdmissionInternal,
                        ));
                    }
                    Err(error) => {
                        self.state.phase = InternalState::Terminal(prepare_failed_receipt(
                            prepare_failure_stage(error),
                        ));
                    }
                }
                let _ = self.bump_version();
            }
            WorkerResult::Executed {
                operation_id,
                result,
            } => {
                if !matches!(
                    self.state.phase,
                    InternalState::Executing {
                        operation_id: expected
                    } if expected == operation_id
                ) {
                    return;
                }
                self.state.phase =
                    InternalState::Terminal(result.unwrap_or_else(|_| failed_receipt()));
                let _ = self.bump_version();
            }
            WorkerResult::Cancelled {
                operation_id,
                result,
            } => {
                if !matches!(
                    self.state.phase,
                    InternalState::Executing {
                        operation_id: expected
                    } if expected == operation_id
                ) {
                    return;
                }
                self.state.phase = InternalState::Terminal(if result.is_ok() {
                    cancelled_receipt()
                } else {
                    failed_receipt()
                });
                let _ = self.bump_version();
            }
        }
    }

    fn snapshot(&self) -> (RepairPublicState, Option<RepairResponseDetail>) {
        match &self.state.phase {
            InternalState::Idle => (RepairPublicState::Idle, None),
            InternalState::Preparing { .. } => (RepairPublicState::Preparing, None),
            InternalState::Prepared { summary, .. } => (
                RepairPublicState::Prepared,
                Some(RepairResponseDetail::Prepared(summary.detail())),
            ),
            InternalState::Executing { .. } => (RepairPublicState::Executing, None),
            InternalState::Terminal(receipt) => (
                public_terminal_state(receipt.outcome),
                Some(RepairResponseDetail::Terminal(terminal_detail(receipt))),
            ),
        }
    }

    fn encode_success(&self, request_id: &str, operation: &str) -> Vec<u8> {
        let (state, detail) = self.snapshot();
        encode_bounded(&SuccessResponse {
            api_version: REPAIR_SERVICE_API_VERSION,
            request_id,
            operation,
            outcome: "ok",
            state_version: self.state.version,
            state,
            detail,
        })
    }

    fn encode_error(
        &self,
        request_id: &str,
        operation: &str,
        error: RepairServiceErrorToken,
    ) -> Vec<u8> {
        let (state, detail) = self.snapshot();
        encode_bounded(&ErrorResponse {
            api_version: REPAIR_SERVICE_API_VERSION,
            request_id,
            operation,
            outcome: "error",
            state_version: self.state.version,
            state,
            detail,
            error,
        })
    }

    fn take_operation_id(&mut self) -> Result<u64, RepairServiceErrorToken> {
        let value = self.state.next_operation_id;
        self.state.next_operation_id = value
            .checked_add(1)
            .ok_or(RepairServiceErrorToken::Internal)?;
        Ok(value)
    }

    fn bump_version(&mut self) -> Result<(), RepairServiceErrorToken> {
        self.state.version = self
            .state
            .version
            .checked_add(1)
            .ok_or(RepairServiceErrorToken::Internal)?;
        Ok(())
    }
}

fn run_worker<Engine: RepairPreparationEngine>(
    mut engine: Engine,
    jobs: Receiver<WorkerJob<Engine::Prepared>>,
    results: SyncSender<WorkerResult<Engine::Prepared>>,
) {
    while let Ok(job) = jobs.recv() {
        let result = match job {
            WorkerJob::Prepare {
                operation_id,
                command,
                deadline,
            } => WorkerResult::Prepared {
                operation_id,
                result: engine.prepare(&command, deadline),
            },
            WorkerJob::ApproveAndExecute {
                operation_id,
                prepared,
                approval,
                deadline,
            } => {
                let result = engine
                    .approve(prepared, &approval, deadline)
                    .and_then(|approved| engine.execute(approved, deadline));
                WorkerResult::Executed {
                    operation_id,
                    result,
                }
            }
            WorkerJob::Cancel {
                operation_id,
                prepared,
                deadline,
            } => WorkerResult::Cancelled {
                operation_id,
                result: Engine::cancel_prepared(prepared, deadline),
            },
        };
        if let Err(error) = results.send(result) {
            if let WorkerResult::Prepared {
                result: Ok((prepared, _)),
                ..
            } = error.0
            {
                let _ = Engine::cancel_prepared(prepared, Instant::now() + CANCEL_TIMEOUT);
            }
            break;
        }
    }
}

fn descriptor_matches(
    command: &BrokerOwnedPrepareCommand,
    descriptor: &PreparedRepairDescriptor,
) -> bool {
    descriptor.session_id == command.session_id
        && descriptor.plan_id == command.plan_id
        && descriptor.target_fingerprint == command.target.target_fingerprint
        && descriptor.backup_reserved
        && descriptor.vault_distinct
}

fn public_terminal_state(outcome: RepairTerminalOutcome) -> RepairPublicState {
    match outcome {
        RepairTerminalOutcome::Committed => RepairPublicState::Succeeded,
        RepairTerminalOutcome::ClosedBeforeUnchanged
        | RepairTerminalOutcome::ClosedBeforeRestored => RepairPublicState::Restored,
        RepairTerminalOutcome::Cancelled => RepairPublicState::Cancelled,
        RepairTerminalOutcome::ManualReconciliationRequired => {
            RepairPublicState::ManualReconciliationRequired
        }
        RepairTerminalOutcome::Failed => RepairPublicState::Failed,
    }
}

fn terminal_detail(receipt: &RepairTerminalReceipt) -> TerminalRepairDetail {
    let terminal_outcome = match receipt.outcome {
        RepairTerminalOutcome::Committed => "committed",
        RepairTerminalOutcome::ClosedBeforeUnchanged => "closed-before-unchanged",
        RepairTerminalOutcome::ClosedBeforeRestored => "closed-before-restored",
        RepairTerminalOutcome::Cancelled => "cancelled",
        RepairTerminalOutcome::ManualReconciliationRequired => "manual-reconciliation-required",
        RepairTerminalOutcome::Failed => "failed",
    };
    TerminalRepairDetail {
        kind: "terminal",
        terminal_outcome,
        reservation_id: receipt.reservation_id.clone(),
        transaction_binding_sha256: receipt.transaction_binding_sha256.clone(),
        reboot_required: receipt.outcome == RepairTerminalOutcome::ManualReconciliationRequired,
        prepare_failure_stage: receipt.prepare_failure_stage,
    }
}

fn prepare_failure_stage(error: RepairEngineFailure) -> RepairPrepareFailureStage {
    match error {
        RepairEngineFailure::PrepareFailed(stage) => stage,
        RepairEngineFailure::ApprovalRejected
        | RepairEngineFailure::CancelFailed
        | RepairEngineFailure::ExecutionFailed
        | RepairEngineFailure::RecoveryUnavailable
        | RepairEngineFailure::Internal => RepairPrepareFailureStage::AdmissionInternal,
    }
}

fn cancelled_receipt() -> RepairTerminalReceipt {
    RepairTerminalReceipt {
        outcome: RepairTerminalOutcome::Cancelled,
        reservation_id: None,
        transaction_binding_sha256: None,
        prepare_failure_stage: None,
    }
}

fn failed_receipt() -> RepairTerminalReceipt {
    RepairTerminalReceipt {
        outcome: RepairTerminalOutcome::Failed,
        reservation_id: None,
        transaction_binding_sha256: None,
        prepare_failure_stage: None,
    }
}

fn prepare_failed_receipt(stage: RepairPrepareFailureStage) -> RepairTerminalReceipt {
    RepairTerminalReceipt {
        outcome: RepairTerminalOutcome::Failed,
        reservation_id: None,
        transaction_binding_sha256: None,
        prepare_failure_stage: Some(stage),
    }
}

fn absolute_deadline(budget: Duration) -> Result<Instant, RepairServiceErrorToken> {
    Instant::now()
        .checked_add(budget)
        .ok_or(RepairServiceErrorToken::Internal)
}

fn session_id_from_request(request_id: &str) -> Result<String, RepairServiceErrorToken> {
    RequestId::parse(request_id).map_err(|_| RepairServiceErrorToken::InvalidRequest)?;
    let compact: String = request_id[2..]
        .bytes()
        .filter(|byte| *byte != b'-')
        .map(char::from)
        .collect();
    if compact.len() != 32 || !lower_hex(compact.as_bytes()) {
        return Err(RepairServiceErrorToken::InvalidRequest);
    }
    Ok(format!("S-{compact}"))
}

fn fresh_fixed_id(prefix: &str) -> Result<String, RepairServiceErrorToken> {
    let mut bytes = [0_u8; 16];
    let mut offset = 0;
    while offset < bytes.len() {
        let count = getrandom(&mut bytes[offset..], GetRandomFlags::NONBLOCK)
            .map_err(|_| RepairServiceErrorToken::Internal)?;
        if count == 0 {
            return Err(RepairServiceErrorToken::Internal);
        }
        offset += count;
    }
    let mut value = String::with_capacity(prefix.len() + 32);
    value.push_str(prefix);
    for byte in bytes {
        use fmt::Write as _;
        write!(&mut value, "{byte:02x}").map_err(|_| RepairServiceErrorToken::Internal)?;
    }
    Ok(value)
}

fn valid_fixed_id(value: &str, prefix: &str) -> bool {
    value
        .strip_prefix(prefix)
        .is_some_and(|suffix| suffix.len() == 32 && lower_hex(suffix.as_bytes()))
}

fn valid_prefixed_hash(value: &str, prefix: &str) -> bool {
    value
        .strip_prefix(prefix)
        .is_some_and(|suffix| suffix.len() == 64 && lower_hex(suffix.as_bytes()))
}

fn valid_reservation_id(value: &str) -> bool {
    valid_fixed_id(value, "B-")
}

fn lower_hex(bytes: &[u8]) -> bool {
    bytes
        .iter()
        .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(byte))
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct CorrelationProbe {
    request_id: Option<String>,
    operation: Option<String>,
}

impl CorrelationProbe {
    fn request_id(&self) -> &str {
        self.request_id
            .as_deref()
            .filter(|value| RequestId::parse(value).is_ok())
            .unwrap_or("R-00000000-0000-0000-0000-000000000000")
    }

    fn operation(&self) -> &str {
        self.operation
            .as_deref()
            .filter(|value| {
                matches!(
                    *value,
                    "repair.status"
                        | "repair.fstab.prepare"
                        | "repair.fstab.approve"
                        | "repair.fstab.cancel"
                )
            })
            .unwrap_or("repair.status")
    }
}

fn correlation_probe(frame: &[u8]) -> CorrelationProbe {
    serde_json::from_slice(frame).unwrap_or(CorrelationProbe {
        request_id: None,
        operation: None,
    })
}

fn encode_bounded(value: &impl Serialize) -> Vec<u8> {
    let encoded = serde_json::to_vec(value).unwrap_or_else(|_| {
        br#"{"apiVersion":"kernaid.dev/rescue-repair-service/v1alpha1","requestId":"R-00000000-0000-0000-0000-000000000000","operation":"repair.status","outcome":"error","stateVersion":0,"state":"failed","detail":{"kind":"terminal","terminalOutcome":"failed","reservationId":null,"transactionBindingSha256":null,"rebootRequired":false,"prepareFailureStage":null},"error":"internal"}"#.to_vec()
    });
    debug_assert!(encoded.len() <= REPAIR_SERVICE_MAX_FRAME_BYTES);
    encoded
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::Value;
    use std::{
        sync::{Arc, Mutex},
        time::Duration,
    };

    const REQUEST: &str = "R-01234567-89ab-cdef-0123-456789abcdef";

    struct PreparedAuthority;
    struct ApprovedAuthority;

    #[derive(Default)]
    struct MockState {
        prepared: usize,
        approved: usize,
        executed: usize,
    }

    struct MockEngine {
        state: Arc<Mutex<MockState>>,
        recovery: Option<RepairTerminalReceipt>,
    }

    impl RepairPreparationEngine for MockEngine {
        type Prepared = PreparedAuthority;
        type Approved = ApprovedAuthority;

        fn recover_pending(
            &mut self,
            _deadline: Instant,
        ) -> Result<Option<RepairTerminalReceipt>, RepairEngineFailure> {
            Ok(self.recovery.take())
        }

        fn prepare(
            &mut self,
            command: &BrokerOwnedPrepareCommand,
            _deadline: Instant,
        ) -> Result<(Self::Prepared, PreparedRepairDescriptor), RepairEngineFailure> {
            self.state.lock().expect("mock state").prepared += 1;
            Ok((
                PreparedAuthority,
                PreparedRepairDescriptor::new(
                    command.session_id(),
                    command.plan_id(),
                    hash('1'),
                    command.target().target_fingerprint(),
                    hash('2'),
                    hash('3'),
                    hash('4'),
                    1,
                    true,
                    true,
                )?,
            ))
        }

        fn approve(
            &mut self,
            _prepared: Self::Prepared,
            _approval: &BoundRepairApproval,
            _deadline: Instant,
        ) -> Result<Self::Approved, RepairEngineFailure> {
            self.state.lock().expect("mock state").approved += 1;
            Ok(ApprovedAuthority)
        }

        fn execute(
            &mut self,
            _approved: Self::Approved,
            _deadline: Instant,
        ) -> Result<RepairTerminalReceipt, RepairEngineFailure> {
            self.state.lock().expect("mock state").executed += 1;
            RepairTerminalReceipt::new(
                RepairTerminalOutcome::Committed,
                Some("B-0123456789abcdef0123456789abcdef".to_owned()),
                Some(hash('5')),
            )
        }

        fn cancel_prepared(
            _prepared: Self::Prepared,
            _deadline: Instant,
        ) -> Result<(), RepairEngineFailure> {
            Ok(())
        }
    }

    fn service() -> (RescueRepairService<MockEngine>, Arc<Mutex<MockState>>) {
        let state = Arc::new(Mutex::new(MockState::default()));
        let engine = MockEngine {
            state: state.clone(),
            recovery: None,
        };
        (
            RescueRepairService::start(engine, Instant::now() + Duration::from_secs(1))
                .expect("service"),
            state,
        )
    }

    fn prepare_frame() -> Vec<u8> {
        format!(
            r#"{{"apiVersion":"{REPAIR_SERVICE_API_VERSION}","requestId":"{REQUEST}","operation":"repair.fstab.prepare","target":{{"scanFingerprint":"scan:{}","targetFingerprint":"sha256:{}","targetId":"target:{}"}}}}"#,
            "1".repeat(64),
            "2".repeat(64),
            "3".repeat(64)
        )
        .into_bytes()
    }

    fn json(bytes: &[u8]) -> Value {
        serde_json::from_slice(bytes).expect("response JSON")
    }

    fn wait_for_state(service: &mut RescueRepairService<MockEngine>, state: RepairPublicState) {
        for _ in 0..100 {
            if service.public_state() == state {
                return;
            }
            thread::sleep(Duration::from_millis(2));
        }
        assert_eq!(service.public_state(), state, "state transition timed out");
    }

    #[test]
    fn strict_wire_rejects_unknown_fields_and_never_reflects_unvalidated_correlation() {
        let (mut service, _) = service();
        let response = json(&service.handle_frame(
            br#"{"apiVersion":"wrong","requestId":"../../bad","operation":"shell.exec","path":"/etc/shadow"}"#,
        ));
        assert_eq!(response["outcome"], "error");
        assert_eq!(response["error"], "invalid-request");
        assert_eq!(
            response["requestId"],
            "R-00000000-0000-0000-0000-000000000000"
        );
        assert_eq!(response["operation"], "repair.status");
    }

    #[test]
    fn prepare_is_async_and_server_derives_all_plan_identifiers() {
        let (mut service, state) = service();
        let response = json(&service.handle_frame(&prepare_frame()));
        let immediate_state = response["state"].as_str();
        assert!(matches!(
            immediate_state,
            Some("preparing") | Some("prepared")
        ));
        if immediate_state == Some("preparing") {
            assert!(response["detail"].is_null());
        } else {
            assert_eq!(response["detail"]["kind"], "fstab-prepared");
        }
        wait_for_state(&mut service, RepairPublicState::Prepared);

        let status = json(&service.handle_frame(
            format!(
                r#"{{"apiVersion":"{REPAIR_SERVICE_API_VERSION}","requestId":"R-aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee","operation":"repair.status"}}"#
            )
            .as_bytes(),
        ));
        let detail = &status["detail"];
        assert_eq!(detail["kind"], "fstab-prepared");
        assert_eq!(detail["sessionId"], "S-0123456789abcdef0123456789abcdef");
        assert!(
            detail["planId"]
                .as_str()
                .is_some_and(|id| valid_fixed_id(id, "P-"))
        );
        assert!(
            detail["preparedId"]
                .as_str()
                .is_some_and(|id| valid_fixed_id(id, "Q-"))
        );
        assert_eq!(
            detail["confirmationRequired"],
            RESCUE_FSTAB_TYPED_CONFIRMATION
        );
        assert_eq!(state.lock().expect("mock state").prepared, 1);
    }

    #[test]
    fn approval_must_echo_every_prepared_binding_then_runs_once() {
        let (mut service, state) = service();
        let _ = service.handle_frame(&prepare_frame());
        wait_for_state(&mut service, RepairPublicState::Prepared);
        let status = json(&service.handle_frame(
            format!(
                r#"{{"apiVersion":"{REPAIR_SERVICE_API_VERSION}","requestId":"R-aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee","operation":"repair.status"}}"#
            )
            .as_bytes(),
        ));
        let detail = &status["detail"];
        let approval = format!(
            r#"{{"apiVersion":"{REPAIR_SERVICE_API_VERSION}","requestId":"R-fedcba98-7654-3210-fedc-ba9876543210","operation":"repair.fstab.approve","preparedId":"{}","sessionId":"{}","planId":"{}","planHash":"{}","approvalId":"A-11111111111111111111111111111111","approvalSequence":1,"typedConfirmation":"{RESCUE_FSTAB_TYPED_CONFIRMATION}"}}"#,
            detail["preparedId"].as_str().expect("prepared ID"),
            detail["sessionId"].as_str().expect("session ID"),
            detail["planId"].as_str().expect("plan ID"),
            detail["planHash"].as_str().expect("plan hash"),
        );
        let accepted = json(&service.handle_frame(approval.as_bytes()));
        assert_eq!(accepted["state"], "executing");
        wait_for_state(&mut service, RepairPublicState::Succeeded);
        let calls = state.lock().expect("mock state");
        assert_eq!((calls.approved, calls.executed), (1, 1));
    }

    #[test]
    fn startup_recovery_is_a_barrier_and_maps_manual_state() {
        let state = Arc::new(Mutex::new(MockState::default()));
        let recovery = RepairTerminalReceipt::new(
            RepairTerminalOutcome::ManualReconciliationRequired,
            Some("B-0123456789abcdef0123456789abcdef".to_owned()),
            Some(hash('9')),
        )
        .expect("manual receipt");
        let mut service = RescueRepairService::start(
            MockEngine {
                state,
                recovery: Some(recovery),
            },
            Instant::now() + Duration::from_secs(1),
        )
        .expect("service");
        assert_eq!(
            service.public_state(),
            RepairPublicState::ManualReconciliationRequired
        );
    }

    #[test]
    fn prepare_failure_detail_exposes_only_the_closed_stage_token() {
        for (stage, expected) in [
            (
                RepairPrepareFailureStage::TargetCapability,
                "target-capability",
            ),
            (
                RepairPrepareFailureStage::ObservationPreview,
                "observation-preview",
            ),
            (RepairPrepareFailureStage::VaultReserve, "vault-reserve"),
            (
                RepairPrepareFailureStage::AdmissionInternal,
                "admission-internal",
            ),
        ] {
            let detail = serde_json::to_value(terminal_detail(&prepare_failed_receipt(stage)))
                .expect("terminal detail");
            assert_eq!(detail["prepareFailureStage"], expected);
            assert_eq!(detail["terminalOutcome"], "failed");
            assert_eq!(detail["reservationId"], Value::Null);
            assert_eq!(detail["transactionBindingSha256"], Value::Null);
            assert!(!detail.to_string().contains('/'));
        }
    }

    fn hash(character: char) -> String {
        format!("sha256:{}", character.to_string().repeat(64))
    }
}
