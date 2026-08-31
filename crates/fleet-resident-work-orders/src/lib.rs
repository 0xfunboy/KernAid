#![forbid(unsafe_code)]
//! Durable, transport-neutral Resident counterpart for typed Fleet work orders.
//!
//! This crate never accepts a command string or invokes a shell. Network data
//! can select only the closed action/version catalog in `kernaid-fleet-client`.
//! A trusted local adapter prepares a digest-only execution binding; Resident
//! persists it before calling the adapter's idempotent execute/recover method.

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use chrono::DateTime;
use ed25519_dalek::{Signature, VerifyingKey};
use kernaid_device_identity::DeviceIdentity;
use kernaid_fleet_client::{
    FleetClientError, LeasedWorkOrder, SignedWorkOrderClaimRequest, SignedWorkOrderResult,
    WorkOrderActionId, WorkOrderClaimRequestInput, WorkOrderKind, WorkOrderRequiredFeature,
    WorkOrderResultInput, WorkOrderResultOutcome, WorkOrderRisk,
};
use kernaid_fleet_policy::{
    PolicyDecision, PolicyEvaluation, PolicyOperation, RiskLevel, TransportState,
    VerifiedPolicyBundle,
};
use kernaid_fleet_runtime::FleetCapabilities;
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::{
    error::Error,
    fmt, fs,
    io::{self, Write},
    path::{Path, PathBuf},
};
use zeroize::Zeroizing;

#[cfg(feature = "linux-service")]
pub mod linux;
#[cfg(all(feature = "windows-service", any(windows, test)))]
pub mod windows;

#[cfg(unix)]
use std::{
    fs::File,
    os::unix::fs::{OpenOptionsExt, PermissionsExt},
};

#[cfg(not(windows))]
use std::fs::OpenOptions;

pub const JOURNAL_SCHEMA: &str = "dev.kernaid.fleet.resident-work-order-journal.v1";
pub const SERVICE_RECEIPT_SCHEMA: &str = "dev.kernaid.fleet.service-receipt.v1";
pub const SERVICE_RECEIPT_SIGNATURE_DOMAIN: &[u8] = b"kernaid:fleet:service-receipt:v1\0";
pub const LOCAL_RESULT_DIGEST_DOMAIN: &[u8] = b"kernaid:fleet:local-work-order-result:v1\0";
pub const WORK_ORDER_RESULT_RESPONSE_SCHEMA: &str =
    "dev.kernaid.fleet.work-order-result-response.v1";

const JOURNAL_FILE: &str = "work-order-journal.cjson";
const JOURNAL_TEMP_FILE: &str = ".work-order-journal.pending";
const MAX_JOURNAL_BYTES: usize = 256 * 1024;
const MAX_RECEIPT_BYTES: usize = 8 * 1024;
const MAX_RESPONSE_BYTES: usize = 32 * 1024;
const MAX_IDENTIFIER_BYTES: usize = 160;
const MAX_TIMESTAMP_BYTES: usize = 64;
const MAX_SAFE_JSON_INTEGER: u64 = 9_007_199_254_740_991;
const SIGNATURE_BYTES: usize = 64;
const SHA256_BYTES: usize = 32;

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WorkOrderReceiptOperation {
    WorkOrderClaim,
    WorkOrderResult,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
enum ReceiptOutcome {
    Accepted,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct WorkOrderResultResponse {
    schema: String,
    tenant_id: String,
    device_id: String,
    work_order_id: String,
    status: WorkOrderResultOutcome,
    outcome: WorkOrderResultOutcome,
    result_sha256: String,
    accepted: bool,
    idempotent: bool,
}

#[derive(Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct SignedServiceReceipt {
    schema: String,
    tenant_id: String,
    device_id: String,
    operation: WorkOrderReceiptOperation,
    sequence: u64,
    request_sha256: String,
    response_sha256: String,
    accepted_at: String,
    outcome: ReceiptOutcome,
    signature: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct UnsignedServiceReceipt<'a> {
    schema: &'a str,
    tenant_id: &'a str,
    device_id: &'a str,
    operation: WorkOrderReceiptOperation,
    sequence: u64,
    request_sha256: &'a str,
    response_sha256: &'a str,
    accepted_at: &'a str,
    outcome: ReceiptOutcome,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ReceiptCheckpoint {
    sequence: u64,
    receipt_sha256: String,
}

struct VerifiedServiceReceipt {
    checkpoint: ReceiptCheckpoint,
}

impl SignedServiceReceipt {
    fn unsigned(&self) -> UnsignedServiceReceipt<'_> {
        UnsignedServiceReceipt {
            schema: &self.schema,
            tenant_id: &self.tenant_id,
            device_id: &self.device_id,
            operation: self.operation,
            sequence: self.sequence,
            request_sha256: &self.request_sha256,
            response_sha256: &self.response_sha256,
            accepted_at: &self.accepted_at,
            outcome: self.outcome,
        }
    }
}

fn verify_service_receipt(
    bytes: &[u8],
    anchor: &VerifyingKey,
    tenant_id: &str,
    device_id: &str,
    operation: WorkOrderReceiptOperation,
    request: &[u8],
    response: &[u8],
) -> Result<VerifiedServiceReceipt, ResidentWorkOrderError> {
    if bytes.is_empty() || bytes.len() > MAX_RECEIPT_BYTES {
        return Err(ResidentWorkOrderError::InvalidServiceReceipt);
    }
    let receipt: SignedServiceReceipt = import_canonical(bytes, MAX_RECEIPT_BYTES)?;
    if receipt.schema != SERVICE_RECEIPT_SCHEMA
        || receipt.tenant_id != tenant_id
        || receipt.device_id != device_id
        || receipt.operation != operation
        || receipt.sequence == 0
        || receipt.sequence > MAX_SAFE_JSON_INTEGER
        || receipt.request_sha256 != sha256_hex(request)
        || receipt.response_sha256 != sha256_hex(response)
        || receipt.outcome != ReceiptOutcome::Accepted
    {
        return Err(ResidentWorkOrderError::InvalidServiceReceipt);
    }
    validate_identifier(&receipt.tenant_id)?;
    validate_identifier(&receipt.device_id)?;
    validate_timestamp(&receipt.accepted_at)?;
    validate_sha256(&receipt.request_sha256)?;
    validate_sha256(&receipt.response_sha256)?;
    let signature = decode_signature(&receipt.signature)?;
    let unsigned = Zeroizing::new(canonical_json(&receipt.unsigned())?);
    let mut message = Zeroizing::new(Vec::with_capacity(
        SERVICE_RECEIPT_SIGNATURE_DOMAIN.len() + unsigned.len(),
    ));
    message.extend_from_slice(SERVICE_RECEIPT_SIGNATURE_DOMAIN);
    message.extend_from_slice(unsigned.as_slice());
    anchor
        .verify_strict(&message, &Signature::from_bytes(&signature))
        .map_err(|_| ResidentWorkOrderError::InvalidServiceReceipt)?;
    Ok(VerifiedServiceReceipt {
        checkpoint: ReceiptCheckpoint {
            sequence: receipt.sequence,
            receipt_sha256: sha256_hex(bytes),
        },
    })
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TransportErrorCode {
    InvalidEndpoint,
    Connect,
    Timeout,
    Tls,
    Protocol,
    ResponseTooLarge,
}

pub struct WorkOrderTransportResponse {
    pub status: u16,
    pub body: Vec<u8>,
    /// Exact decoded canonical service receipt bytes.
    pub receipt: Option<Vec<u8>>,
}

pub trait ResidentWorkOrderTransport {
    fn claim(
        &mut self,
        body: &[u8],
        maximum_response_bytes: usize,
    ) -> Result<WorkOrderTransportResponse, TransportErrorCode>;

    fn submit_result(
        &mut self,
        body: &[u8],
        maximum_response_bytes: usize,
    ) -> Result<WorkOrderTransportResponse, TransportErrorCode>;
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ResidentPlatform {
    Linux,
    Rescue,
    Windows,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct BoundLocalApproval {
    work_order_id: String,
    lease_id: String,
    action_id: WorkOrderActionId,
    action_version: u16,
    execution_id: String,
    plan_sha256: String,
    target_sha256: String,
    approval_sequence: u64,
    approved_at: String,
    proof_sha256: String,
}

impl BoundLocalApproval {
    #[allow(clippy::too_many_arguments)]
    #[must_use]
    pub fn new(
        work_order_id: impl Into<String>,
        lease_id: impl Into<String>,
        action_id: WorkOrderActionId,
        action_version: u16,
        execution_id: impl Into<String>,
        plan_sha256: impl Into<String>,
        target_sha256: impl Into<String>,
        approval_sequence: u64,
        approved_at: impl Into<String>,
        proof_sha256: impl Into<String>,
    ) -> Self {
        Self {
            work_order_id: work_order_id.into(),
            lease_id: lease_id.into(),
            action_id,
            action_version,
            execution_id: execution_id.into(),
            plan_sha256: plan_sha256.into(),
            target_sha256: target_sha256.into(),
            approval_sequence,
            approved_at: approved_at.into(),
            proof_sha256: proof_sha256.into(),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PreparedLocalExecution {
    execution_id: String,
    work_order_id: String,
    lease_id: String,
    action_id: WorkOrderActionId,
    action_version: u16,
    plan_sha256: String,
    target_sha256: String,
    local_approval: Option<BoundLocalApproval>,
}

impl PreparedLocalExecution {
    #[must_use]
    pub fn diagnostic(
        order: &LeasedWorkOrder,
        execution_id: impl Into<String>,
        plan_sha256: impl Into<String>,
        target_sha256: impl Into<String>,
    ) -> Self {
        Self {
            execution_id: execution_id.into(),
            work_order_id: order.work_order_id().to_owned(),
            lease_id: order.lease().lease_id().to_owned(),
            action_id: order.action_id(),
            action_version: order.action_version(),
            plan_sha256: plan_sha256.into(),
            target_sha256: target_sha256.into(),
            local_approval: None,
        }
    }

    #[must_use]
    pub fn approved_write(
        order: &LeasedWorkOrder,
        execution_id: impl Into<String>,
        plan_sha256: impl Into<String>,
        target_sha256: impl Into<String>,
        local_approval: BoundLocalApproval,
    ) -> Self {
        Self {
            execution_id: execution_id.into(),
            work_order_id: order.work_order_id().to_owned(),
            lease_id: order.lease().lease_id().to_owned(),
            action_id: order.action_id(),
            action_version: order.action_version(),
            plan_sha256: plan_sha256.into(),
            target_sha256: target_sha256.into(),
            local_approval: Some(local_approval),
        }
    }

    #[must_use]
    pub fn execution_id(&self) -> &str {
        &self.execution_id
    }

    #[must_use]
    pub const fn action_id(&self) -> WorkOrderActionId {
        self.action_id
    }

    #[must_use]
    pub const fn action_version(&self) -> u16 {
        self.action_version
    }

    #[must_use]
    pub fn plan_sha256(&self) -> &str {
        &self.plan_sha256
    }

    #[must_use]
    pub fn target_sha256(&self) -> &str {
        &self.target_sha256
    }

    #[must_use]
    pub fn local_approval(&self) -> Option<&BoundLocalApproval> {
        self.local_approval.as_ref()
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LocalHandoffErrorCode {
    ApprovalPending,
    Busy,
    StateMismatch,
    ExecutionFailed,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LocalExecutionResult {
    pub outcome: WorkOrderResultOutcome,
    pub result_sha256: String,
}

impl LocalExecutionResult {
    #[must_use]
    pub fn new(outcome: WorkOrderResultOutcome, result_sha256: impl Into<String>) -> Self {
        Self {
            outcome,
            result_sha256: result_sha256.into(),
        }
    }
}

/// Trusted local adapter. `prepare` must not mutate. `execute_or_recover` must
/// use `execution_id` as a durable idempotency key and may only dispatch the
/// typed action enum; its implementation must never concatenate a shell line.
pub trait LocalWorkOrderHandoff {
    fn prepare(
        &mut self,
        order: &LeasedWorkOrder,
        execution_id: &str,
    ) -> Result<PreparedLocalExecution, LocalHandoffErrorCode>;

    fn execute_or_recover(
        &mut self,
        prepared: &PreparedLocalExecution,
    ) -> Result<LocalExecutionResult, LocalHandoffErrorCode>;
}

pub struct WorkOrderAuthorization<'a> {
    pub platform: ResidentPlatform,
    pub capabilities: FleetCapabilities,
    pub policies: &'a [VerifiedPolicyBundle],
    pub local_max_risk: RiskLevel,
    pub local_approval_from: RiskLevel,
    pub now_unix: u64,
}

pub struct WorkOrderCycleInput {
    pub issued_at: String,
    pub now_unix: u64,
    pub nonce: Zeroizing<Vec<u8>>,
    pub lease_seconds: u16,
}

impl fmt::Debug for WorkOrderCycleInput {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("WorkOrderCycleInput")
            .field("issued_at", &self.issued_at)
            .field("now_unix", &self.now_unix)
            .field("lease_seconds", &self.lease_seconds)
            .finish_non_exhaustive()
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum WorkOrderCycleOutcome {
    NoWork,
    AwaitingLocalApproval {
        work_order_id: String,
        lease_id: String,
    },
    Completed {
        work_order_id: String,
        outcome: WorkOrderResultOutcome,
        result_sha256: String,
    },
}

#[derive(Debug)]
pub enum ResidentWorkOrderError {
    InvalidContext,
    InvalidServiceReceipt,
    ReceiptRollback,
    ReceiptConflict,
    HttpRejected,
    MissingReceipt,
    InvalidResponse,
    StateCorrupt,
    LeaseExpiredRecoveryRequired,
    LocalBindingInvalid,
    Transport(TransportErrorCode),
    Handoff(LocalHandoffErrorCode),
    Client(FleetClientError),
    Io(io::Error),
}

impl ResidentWorkOrderError {
    #[must_use]
    pub const fn code(&self) -> &'static str {
        match self {
            Self::InvalidContext => "work-order-context-invalid",
            Self::InvalidServiceReceipt => "work-order-receipt-invalid",
            Self::ReceiptRollback => "work-order-receipt-rollback",
            Self::ReceiptConflict => "work-order-receipt-conflict",
            Self::HttpRejected => "work-order-http-rejected",
            Self::MissingReceipt => "work-order-receipt-missing",
            Self::InvalidResponse => "work-order-response-invalid",
            Self::StateCorrupt => "work-order-state-corrupt",
            Self::LeaseExpiredRecoveryRequired => "work-order-recovery-required",
            Self::LocalBindingInvalid => "work-order-local-binding-invalid",
            Self::Transport(_) => "work-order-transport-failed",
            Self::Handoff(LocalHandoffErrorCode::ApprovalPending) => "work-order-approval-pending",
            Self::Handoff(_) => "work-order-handoff-failed",
            Self::Client(_) => "work-order-wire-invalid",
            Self::Io(_) => "work-order-state-io",
        }
    }
}

impl fmt::Display for ResidentWorkOrderError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.code())
    }
}

impl Error for ResidentWorkOrderError {}

impl From<FleetClientError> for ResidentWorkOrderError {
    fn from(value: FleetClientError) -> Self {
        Self::Client(value)
    }
}

impl From<io::Error> for ResidentWorkOrderError {
    fn from(value: io::Error) -> Self {
        Self::Io(value)
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ClaimExchange {
    request: String,
    response: String,
    receipt: String,
}

impl ClaimExchange {
    fn new(request: &[u8], response: &[u8], receipt: &[u8]) -> Self {
        Self {
            request: URL_SAFE_NO_PAD.encode(request),
            response: URL_SAFE_NO_PAD.encode(response),
            receipt: URL_SAFE_NO_PAD.encode(receipt),
        }
    }

    fn request(&self) -> Result<Vec<u8>, ResidentWorkOrderError> {
        decode_bounded(&self.request, MAX_RESPONSE_BYTES)
    }

    fn response(&self) -> Result<Vec<u8>, ResidentWorkOrderError> {
        decode_bounded(&self.response, MAX_RESPONSE_BYTES)
    }

    fn receipt(&self) -> Result<Vec<u8>, ResidentWorkOrderError> {
        decode_bounded(&self.receipt, MAX_RECEIPT_BYTES)
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct CompletedCheckpoint {
    work_order_id: String,
    lease_id: String,
    result_sha256: String,
    result_envelope_sha256: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "state", rename_all = "snake_case", deny_unknown_fields)]
enum JournalStage {
    Idle,
    ClaimPending {
        request: String,
    },
    LeaseReady {
        claim: ClaimExchange,
    },
    ExecutionPending {
        claim: ClaimExchange,
        preparation: PreparedLocalExecution,
    },
    ResultPending {
        claim: ClaimExchange,
        preparation: Option<PreparedLocalExecution>,
        result: String,
    },
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct JournalDocument {
    schema: String,
    tenant_id: String,
    device_id: String,
    receipt_checkpoint: Option<ReceiptCheckpoint>,
    last_completed: Option<CompletedCheckpoint>,
    stage: JournalStage,
}

struct WorkOrderJournal {
    directory: PathBuf,
    document: JournalDocument,
}

impl WorkOrderJournal {
    fn open(
        directory: &Path,
        tenant_id: &str,
        device_id: &str,
    ) -> Result<Self, ResidentWorkOrderError> {
        prepare_private_directory(directory)?;
        cleanup_temporary(&directory.join(JOURNAL_TEMP_FILE))?;
        let path = directory.join(JOURNAL_FILE);
        let document = match read_private_optional(&path, MAX_JOURNAL_BYTES)? {
            Some(bytes) => import_canonical(&bytes, MAX_JOURNAL_BYTES)?,
            None => JournalDocument {
                schema: JOURNAL_SCHEMA.to_owned(),
                tenant_id: tenant_id.to_owned(),
                device_id: device_id.to_owned(),
                receipt_checkpoint: None,
                last_completed: None,
                stage: JournalStage::Idle,
            },
        };
        validate_journal(&document, tenant_id, device_id)?;
        let mut journal = Self {
            directory: directory.to_path_buf(),
            document,
        };
        if !path.exists() {
            journal.persist()?;
        }
        Ok(journal)
    }

    fn replace_stage(
        &mut self,
        stage: JournalStage,
        receipt_checkpoint: Option<ReceiptCheckpoint>,
    ) -> Result<(), ResidentWorkOrderError> {
        self.document.stage = stage;
        if let Some(checkpoint) = receipt_checkpoint {
            self.document.receipt_checkpoint = Some(checkpoint);
        }
        self.persist()
    }

    fn complete(
        &mut self,
        checkpoint: ReceiptCheckpoint,
        completed: CompletedCheckpoint,
    ) -> Result<(), ResidentWorkOrderError> {
        self.document.receipt_checkpoint = Some(checkpoint);
        self.document.last_completed = Some(completed);
        self.document.stage = JournalStage::Idle;
        self.persist()
    }

    fn persist(&mut self) -> Result<(), ResidentWorkOrderError> {
        validate_journal(
            &self.document,
            &self.document.tenant_id,
            &self.document.device_id,
        )?;
        let bytes = canonical_json(&self.document)?;
        if bytes.is_empty() || bytes.len() > MAX_JOURNAL_BYTES {
            return Err(ResidentWorkOrderError::StateCorrupt);
        }
        write_atomic(&self.directory, JOURNAL_FILE, JOURNAL_TEMP_FILE, &bytes)
    }
}

pub struct ResidentWorkOrderEngine<T> {
    tenant_id: String,
    device_id: String,
    device_public_key: [u8; 32],
    service_receipt_anchor: VerifyingKey,
    transport: T,
    journal: WorkOrderJournal,
}

impl<T: ResidentWorkOrderTransport> ResidentWorkOrderEngine<T> {
    pub fn open(
        tenant_id: &str,
        identity: &DeviceIdentity,
        service_receipt_anchor: &[u8; 32],
        state_directory: &Path,
        transport: T,
    ) -> Result<Self, ResidentWorkOrderError> {
        validate_identifier(tenant_id)?;
        let device_id = identity.device_id();
        let service_receipt_anchor = VerifyingKey::from_bytes(service_receipt_anchor)
            .map_err(|_| ResidentWorkOrderError::InvalidContext)?;
        let journal = WorkOrderJournal::open(state_directory, tenant_id, &device_id)?;
        Ok(Self {
            tenant_id: tenant_id.to_owned(),
            device_id,
            device_public_key: identity.public_key(),
            service_receipt_anchor,
            transport,
            journal,
        })
    }

    pub fn run_once<H: LocalWorkOrderHandoff>(
        &mut self,
        identity: &DeviceIdentity,
        input: WorkOrderCycleInput,
        authorization: &WorkOrderAuthorization<'_>,
        handoff: &mut H,
    ) -> Result<WorkOrderCycleOutcome, ResidentWorkOrderError> {
        self.ensure_identity(identity)?;
        validate_cycle_input(&input, authorization)?;
        for _ in 0..6 {
            match self.journal.document.stage.clone() {
                JournalStage::Idle => {
                    let request = SignedWorkOrderClaimRequest::sign(
                        identity,
                        WorkOrderClaimRequestInput::new(
                            &self.tenant_id,
                            &input.issued_at,
                            input.nonce.to_vec(),
                            input.lease_seconds,
                        ),
                    )?
                    .export_offline()?;
                    self.journal.replace_stage(
                        JournalStage::ClaimPending {
                            request: URL_SAFE_NO_PAD.encode(request),
                        },
                        None,
                    )?;
                }
                JournalStage::ClaimPending { request } => {
                    let request = decode_bounded(&request, MAX_RESPONSE_BYTES)?;
                    let signed_request = SignedWorkOrderClaimRequest::import_offline(
                        &request,
                        &self.tenant_id,
                        &self.device_id,
                        &self.device_public_key,
                    )?;
                    let response = self
                        .transport
                        .claim(&request, MAX_RESPONSE_BYTES)
                        .map_err(ResidentWorkOrderError::Transport)?;
                    if response.status != 200 {
                        return Err(ResidentWorkOrderError::HttpRejected);
                    }
                    if response.body.len() > MAX_RESPONSE_BYTES {
                        return Err(ResidentWorkOrderError::InvalidResponse);
                    }
                    let receipt = response
                        .receipt
                        .as_deref()
                        .ok_or(ResidentWorkOrderError::MissingReceipt)?;
                    let verified = verify_service_receipt(
                        receipt,
                        &self.service_receipt_anchor,
                        &self.tenant_id,
                        &self.device_id,
                        WorkOrderReceiptOperation::WorkOrderClaim,
                        &request,
                        &response.body,
                    )?;
                    let checkpoint = admit_receipt(
                        self.journal.document.receipt_checkpoint.as_ref(),
                        &verified.checkpoint,
                    )?;
                    let parsed = signed_request.import_response(&response.body)?;
                    if parsed.work_order().is_none() {
                        self.journal
                            .replace_stage(JournalStage::Idle, Some(checkpoint))?;
                        return Ok(WorkOrderCycleOutcome::NoWork);
                    }
                    self.journal.replace_stage(
                        JournalStage::LeaseReady {
                            claim: ClaimExchange::new(&request, &response.body, receipt),
                        },
                        Some(checkpoint),
                    )?;
                }
                JournalStage::LeaseReady { claim } => {
                    let order = self.load_order(&claim)?;
                    if lease_expired(&order, input.now_unix)? {
                        self.journal.replace_stage(JournalStage::Idle, None)?;
                        return Ok(WorkOrderCycleOutcome::NoWork);
                    }
                    if let Err(denial) = authorize_work_order(&order, authorization) {
                        let result = self.signed_denial(identity, &order, &input, denial)?;
                        self.journal.replace_stage(
                            JournalStage::ResultPending {
                                claim,
                                preparation: None,
                                result: URL_SAFE_NO_PAD.encode(result.export_offline()?),
                            },
                            None,
                        )?;
                        continue;
                    }
                    let execution_id = execution_id(&self.tenant_id, &self.device_id, &order);
                    let preparation = match handoff.prepare(&order, &execution_id) {
                        Ok(preparation) => preparation,
                        Err(LocalHandoffErrorCode::ApprovalPending) => {
                            return Ok(WorkOrderCycleOutcome::AwaitingLocalApproval {
                                work_order_id: order.work_order_id().to_owned(),
                                lease_id: order.lease().lease_id().to_owned(),
                            });
                        }
                        Err(error) => return Err(ResidentWorkOrderError::Handoff(error)),
                    };
                    validate_preparation(&preparation, &order, &execution_id, input.now_unix)?;
                    self.journal.replace_stage(
                        JournalStage::ExecutionPending { claim, preparation },
                        None,
                    )?;
                }
                JournalStage::ExecutionPending { claim, preparation } => {
                    let order = self.load_order(&claim)?;
                    if lease_expired(&order, input.now_unix)? {
                        return Err(ResidentWorkOrderError::LeaseExpiredRecoveryRequired);
                    }
                    validate_preparation(
                        &preparation,
                        &order,
                        &execution_id(&self.tenant_id, &self.device_id, &order),
                        input.now_unix,
                    )?;
                    let local_result = handoff
                        .execute_or_recover(&preparation)
                        .map_err(ResidentWorkOrderError::Handoff)?;
                    validate_sha256(&local_result.result_sha256)?;
                    let result = SignedWorkOrderResult::sign(
                        identity,
                        WorkOrderResultInput::from_order(
                            &self.tenant_id,
                            &order,
                            local_result.outcome,
                            &input.issued_at,
                            local_result.result_sha256,
                        ),
                    )?;
                    self.journal.replace_stage(
                        JournalStage::ResultPending {
                            claim,
                            preparation: Some(preparation),
                            result: URL_SAFE_NO_PAD.encode(result.export_offline()?),
                        },
                        None,
                    )?;
                }
                JournalStage::ResultPending {
                    claim,
                    preparation,
                    result,
                } => {
                    let order = self.load_order(&claim)?;
                    if lease_expired(&order, input.now_unix)? {
                        return Err(ResidentWorkOrderError::LeaseExpiredRecoveryRequired);
                    }
                    if let Some(preparation) = &preparation {
                        validate_preparation(
                            preparation,
                            &order,
                            &execution_id(&self.tenant_id, &self.device_id, &order),
                            input.now_unix,
                        )?;
                    }
                    let result = decode_bounded(&result, MAX_RESPONSE_BYTES)?;
                    let signed_result = SignedWorkOrderResult::import_offline(
                        &result,
                        &self.tenant_id,
                        &self.device_id,
                        &self.device_public_key,
                    )?;
                    if signed_result.work_order_id() != order.work_order_id()
                        || signed_result.lease_id() != order.lease().lease_id()
                    {
                        return Err(ResidentWorkOrderError::StateCorrupt);
                    }
                    let response = self
                        .transport
                        .submit_result(&result, MAX_RESPONSE_BYTES)
                        .map_err(ResidentWorkOrderError::Transport)?;
                    if !matches!(response.status, 200 | 201) {
                        return Err(ResidentWorkOrderError::HttpRejected);
                    }
                    validate_result_response(&response.body, &signed_result)?;
                    let receipt = response
                        .receipt
                        .as_deref()
                        .ok_or(ResidentWorkOrderError::MissingReceipt)?;
                    let verified = verify_service_receipt(
                        receipt,
                        &self.service_receipt_anchor,
                        &self.tenant_id,
                        &self.device_id,
                        WorkOrderReceiptOperation::WorkOrderResult,
                        &result,
                        &response.body,
                    )?;
                    let checkpoint = admit_receipt(
                        self.journal.document.receipt_checkpoint.as_ref(),
                        &verified.checkpoint,
                    )?;
                    let completed = CompletedCheckpoint {
                        work_order_id: order.work_order_id().to_owned(),
                        lease_id: order.lease().lease_id().to_owned(),
                        result_sha256: local_result_sha256(&signed_result, &result),
                        result_envelope_sha256: sha256_hex(&result),
                    };
                    let outcome = signed_result.outcome();
                    let result_sha256 = completed.result_sha256.clone();
                    self.journal.complete(checkpoint, completed)?;
                    return Ok(WorkOrderCycleOutcome::Completed {
                        work_order_id: order.work_order_id().to_owned(),
                        outcome,
                        result_sha256,
                    });
                }
            }
        }
        Err(ResidentWorkOrderError::StateCorrupt)
    }

    fn ensure_identity(&self, identity: &DeviceIdentity) -> Result<(), ResidentWorkOrderError> {
        if identity.device_id() != self.device_id || identity.public_key() != self.device_public_key
        {
            return Err(ResidentWorkOrderError::InvalidContext);
        }
        Ok(())
    }

    fn load_order(&self, claim: &ClaimExchange) -> Result<LeasedWorkOrder, ResidentWorkOrderError> {
        let request = claim.request()?;
        let response = claim.response()?;
        let receipt = claim.receipt()?;
        let signed = SignedWorkOrderClaimRequest::import_offline(
            &request,
            &self.tenant_id,
            &self.device_id,
            &self.device_public_key,
        )?;
        let verified = verify_service_receipt(
            &receipt,
            &self.service_receipt_anchor,
            &self.tenant_id,
            &self.device_id,
            WorkOrderReceiptOperation::WorkOrderClaim,
            &request,
            &response,
        )?;
        ensure_retained_receipt(
            self.journal.document.receipt_checkpoint.as_ref(),
            &verified.checkpoint,
        )?;
        signed
            .import_response(&response)?
            .into_work_order()
            .ok_or(ResidentWorkOrderError::StateCorrupt)
    }

    fn signed_denial(
        &self,
        identity: &DeviceIdentity,
        order: &LeasedWorkOrder,
        input: &WorkOrderCycleInput,
        denial: AuthorizationDenial,
    ) -> Result<SignedWorkOrderResult, ResidentWorkOrderError> {
        SignedWorkOrderResult::sign(
            identity,
            WorkOrderResultInput::from_order(
                &self.tenant_id,
                order,
                WorkOrderResultOutcome::Rejected,
                &input.issued_at,
                rejection_digest(order, denial),
            ),
        )
        .map_err(Into::into)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum AuthorizationDenial {
    UnsupportedAction,
    Entitlement,
    PolicyMissing,
    PolicyDenied,
}

impl AuthorizationDenial {
    const fn code(self) -> &'static str {
        match self {
            Self::UnsupportedAction => "unsupported-action",
            Self::Entitlement => "entitlement-denied",
            Self::PolicyMissing => "policy-missing",
            Self::PolicyDenied => "policy-denied",
        }
    }
}

fn authorize_work_order(
    order: &LeasedWorkOrder,
    authorization: &WorkOrderAuthorization<'_>,
) -> Result<(), AuthorizationDenial> {
    if authorization.now_unix == 0
        || authorization.now_unix > MAX_SAFE_JSON_INTEGER
        || !action_supported(order.action_id(), authorization.platform)
    {
        return Err(AuthorizationDenial::UnsupportedAction);
    }
    match order.action_id().metadata().required_feature {
        WorkOrderRequiredFeature::Fleet if !authorization.capabilities.fleet_sync => {
            return Err(AuthorizationDenial::Entitlement);
        }
        WorkOrderRequiredFeature::EnterpriseRepair
            if !authorization.capabilities.enterprise_repair =>
        {
            return Err(AuthorizationDenial::Entitlement);
        }
        WorkOrderRequiredFeature::Fleet | WorkOrderRequiredFeature::EnterpriseRepair => {}
    }
    if order.kind() == WorkOrderKind::Repair && authorization.policies.is_empty() {
        return Err(AuthorizationDenial::PolicyMissing);
    }
    let action_risk = policy_risk(order.risk());
    let operation = match order.kind() {
        WorkOrderKind::Diagnosis => PolicyOperation::Diagnostic,
        WorkOrderKind::Repair => PolicyOperation::NewRepair,
    };
    for policy in authorization.policies {
        let decision = policy.evaluate(&PolicyEvaluation {
            device_id: order.target_device_id(),
            action_id: order.action_id().wire_name(),
            action_risk: Some(action_risk),
            local_max_risk: authorization.local_max_risk,
            local_approval_from: authorization.local_approval_from,
            locally_known: true,
            locally_allowed: true,
            operation,
            transport: TransportState::Online,
            now_unix: authorization.now_unix,
        });
        if !matches!(
            (order.kind(), decision),
            (WorkOrderKind::Diagnosis, PolicyDecision::DiagnosticsAllowed)
                | (
                    WorkOrderKind::Repair,
                    PolicyDecision::NewRepairAllowed { .. }
                )
        ) {
            return Err(AuthorizationDenial::PolicyDenied);
        }
    }
    Ok(())
}

const fn action_supported(action: WorkOrderActionId, platform: ResidentPlatform) -> bool {
    match action {
        WorkOrderActionId::LinuxFilesystemHealthV1
        | WorkOrderActionId::LinuxStorageHealthV1
        | WorkOrderActionId::LinuxBootCriticalPathV1 => {
            matches!(platform, ResidentPlatform::Linux | ResidentPlatform::Rescue)
        }
        WorkOrderActionId::LinuxFstabDisableMissingUuidV1 => {
            matches!(platform, ResidentPlatform::Rescue)
                && cfg!(any(test, feature = "rescue-fstab-handoff"))
        }
        WorkOrderActionId::WindowsP0DiagnoseV1 => matches!(platform, ResidentPlatform::Windows),
    }
}

const fn policy_risk(risk: WorkOrderRisk) -> RiskLevel {
    match risk {
        WorkOrderRisk::R0 => RiskLevel::R0,
        WorkOrderRisk::R1 => RiskLevel::R1,
        WorkOrderRisk::R2 => RiskLevel::R2,
        WorkOrderRisk::R3 => RiskLevel::R3,
    }
}

fn validate_cycle_input(
    input: &WorkOrderCycleInput,
    authorization: &WorkOrderAuthorization<'_>,
) -> Result<(), ResidentWorkOrderError> {
    validate_timestamp(&input.issued_at)?;
    if input.now_unix == 0
        || input.now_unix > MAX_SAFE_JSON_INTEGER
        || input.now_unix != authorization.now_unix
        || !(16..=64).contains(&input.nonce.len())
        || !(30..=900).contains(&input.lease_seconds)
    {
        return Err(ResidentWorkOrderError::InvalidContext);
    }
    Ok(())
}

fn validate_preparation(
    prepared: &PreparedLocalExecution,
    order: &LeasedWorkOrder,
    expected_execution_id: &str,
    now_unix: u64,
) -> Result<(), ResidentWorkOrderError> {
    if prepared.execution_id != expected_execution_id
        || prepared.work_order_id != order.work_order_id()
        || prepared.lease_id != order.lease().lease_id()
        || prepared.action_id != order.action_id()
        || prepared.action_version != order.action_version()
    {
        return Err(ResidentWorkOrderError::LocalBindingInvalid);
    }
    validate_identifier(&prepared.execution_id)?;
    validate_sha256(&prepared.plan_sha256)?;
    validate_sha256(&prepared.target_sha256)?;
    match (order.kind(), prepared.local_approval.as_ref()) {
        (WorkOrderKind::Diagnosis, None) => Ok(()),
        (WorkOrderKind::Repair, Some(approval)) => {
            if !order.local_approval_required()
                || order.approval().is_none()
                || approval.work_order_id != prepared.work_order_id
                || approval.lease_id != prepared.lease_id
                || approval.action_id != prepared.action_id
                || approval.action_version != prepared.action_version
                || approval.execution_id != prepared.execution_id
                || approval.plan_sha256 != prepared.plan_sha256
                || approval.target_sha256 != prepared.target_sha256
                || approval.approval_sequence == 0
                || approval.approval_sequence > MAX_SAFE_JSON_INTEGER
            {
                return Err(ResidentWorkOrderError::LocalBindingInvalid);
            }
            validate_sha256(&approval.proof_sha256)?;
            validate_timestamp(&approval.approved_at)?;
            let approved_at = timestamp_unix(&approval.approved_at)?;
            let leased_at = timestamp_unix(order.lease().leased_at())?;
            let lease_expires_at = timestamp_unix(order.lease().lease_expires_at())?;
            if approved_at < leased_at || approved_at > now_unix || approved_at >= lease_expires_at
            {
                return Err(ResidentWorkOrderError::LocalBindingInvalid);
            }
            Ok(())
        }
        _ => Err(ResidentWorkOrderError::LocalBindingInvalid),
    }
}

fn lease_expired(order: &LeasedWorkOrder, now_unix: u64) -> Result<bool, ResidentWorkOrderError> {
    Ok(now_unix >= timestamp_unix(order.lease().lease_expires_at())?)
}

fn timestamp_unix(value: &str) -> Result<u64, ResidentWorkOrderError> {
    let timestamp = DateTime::parse_from_rfc3339(value)
        .map_err(|_| ResidentWorkOrderError::InvalidContext)?
        .timestamp();
    u64::try_from(timestamp).map_err(|_| ResidentWorkOrderError::InvalidContext)
}

fn execution_id(tenant_id: &str, device_id: &str, order: &LeasedWorkOrder) -> String {
    let mut hasher = Sha256::new();
    hasher.update(b"kernaid:fleet:local-work-order-execution:v1\0");
    for value in [
        tenant_id,
        device_id,
        order.work_order_id(),
        order.lease().lease_id(),
        order.action_id().wire_name(),
    ] {
        hasher.update((value.len() as u64).to_be_bytes());
        hasher.update(value.as_bytes());
    }
    format!("exec_{}", &sha256_hex(&hasher.finalize())[..32])
}

fn rejection_digest(order: &LeasedWorkOrder, denial: AuthorizationDenial) -> String {
    let mut hasher = Sha256::new();
    hasher.update(LOCAL_RESULT_DIGEST_DOMAIN);
    for value in [
        "rejected",
        denial.code(),
        order.work_order_id(),
        order.lease().lease_id(),
        order.action_id().wire_name(),
    ] {
        hasher.update((value.len() as u64).to_be_bytes());
        hasher.update(value.as_bytes());
    }
    sha256_hex(&hasher.finalize())
}

fn local_result_sha256(result: &SignedWorkOrderResult, _bytes: &[u8]) -> String {
    result.result_sha256().to_owned()
}

fn validate_result_response(
    bytes: &[u8],
    result: &SignedWorkOrderResult,
) -> Result<(), ResidentWorkOrderError> {
    if bytes.is_empty() || bytes.len() > MAX_RESPONSE_BYTES {
        return Err(ResidentWorkOrderError::InvalidResponse);
    }
    let response: WorkOrderResultResponse =
        serde_json::from_slice(bytes).map_err(|_| ResidentWorkOrderError::InvalidResponse)?;
    if response.schema != WORK_ORDER_RESULT_RESPONSE_SCHEMA
        || response.tenant_id != result.tenant_id()
        || response.device_id != result.device_id()
        || response.work_order_id != result.work_order_id()
        || response.status != result.outcome()
        || response.outcome != result.outcome()
        || response.result_sha256 != result.result_sha256()
        || !response.accepted
    {
        return Err(ResidentWorkOrderError::InvalidResponse);
    }
    let _ = response.idempotent;
    Ok(())
}

fn admit_receipt(
    retained: Option<&ReceiptCheckpoint>,
    candidate: &ReceiptCheckpoint,
) -> Result<ReceiptCheckpoint, ResidentWorkOrderError> {
    validate_receipt_checkpoint(candidate)?;
    match retained {
        None => Ok(candidate.clone()),
        Some(current) if candidate.sequence > current.sequence => Ok(candidate.clone()),
        Some(current) if candidate == current => Ok(current.clone()),
        Some(current) if candidate.sequence < current.sequence => {
            Err(ResidentWorkOrderError::ReceiptRollback)
        }
        Some(_) => Err(ResidentWorkOrderError::ReceiptConflict),
    }
}

fn ensure_retained_receipt(
    retained: Option<&ReceiptCheckpoint>,
    candidate: &ReceiptCheckpoint,
) -> Result<(), ResidentWorkOrderError> {
    let retained = retained.ok_or(ResidentWorkOrderError::StateCorrupt)?;
    validate_receipt_checkpoint(retained)?;
    validate_receipt_checkpoint(candidate)?;
    if candidate.sequence > retained.sequence
        || (candidate.sequence == retained.sequence && candidate != retained)
    {
        return Err(ResidentWorkOrderError::StateCorrupt);
    }
    Ok(())
}

fn validate_receipt_checkpoint(
    checkpoint: &ReceiptCheckpoint,
) -> Result<(), ResidentWorkOrderError> {
    if checkpoint.sequence == 0 || checkpoint.sequence > MAX_SAFE_JSON_INTEGER {
        return Err(ResidentWorkOrderError::StateCorrupt);
    }
    validate_sha256(&checkpoint.receipt_sha256)
}

fn validate_journal(
    document: &JournalDocument,
    tenant_id: &str,
    device_id: &str,
) -> Result<(), ResidentWorkOrderError> {
    if document.schema != JOURNAL_SCHEMA
        || document.tenant_id != tenant_id
        || document.device_id != device_id
    {
        return Err(ResidentWorkOrderError::StateCorrupt);
    }
    validate_identifier(&document.tenant_id)?;
    validate_identifier(&document.device_id)?;
    if let Some(checkpoint) = &document.receipt_checkpoint {
        validate_receipt_checkpoint(checkpoint)?;
    }
    if let Some(completed) = &document.last_completed {
        validate_identifier(&completed.work_order_id)?;
        validate_identifier(&completed.lease_id)?;
        validate_sha256(&completed.result_sha256)?;
        validate_sha256(&completed.result_envelope_sha256)?;
    }
    match &document.stage {
        JournalStage::Idle => Ok(()),
        JournalStage::ClaimPending { request } => {
            decode_bounded(request, MAX_RESPONSE_BYTES).map(|_| ())
        }
        JournalStage::LeaseReady { claim } => validate_claim_exchange(claim),
        JournalStage::ExecutionPending { claim, preparation } => {
            validate_claim_exchange(claim)?;
            validate_identifier(&preparation.execution_id)?;
            validate_sha256(&preparation.plan_sha256)?;
            validate_sha256(&preparation.target_sha256)
        }
        JournalStage::ResultPending {
            claim,
            preparation,
            result,
        } => {
            validate_claim_exchange(claim)?;
            if let Some(preparation) = preparation {
                validate_identifier(&preparation.execution_id)?;
                validate_sha256(&preparation.plan_sha256)?;
                validate_sha256(&preparation.target_sha256)?;
            }
            decode_bounded(result, MAX_RESPONSE_BYTES).map(|_| ())
        }
    }
}

fn validate_claim_exchange(claim: &ClaimExchange) -> Result<(), ResidentWorkOrderError> {
    claim.request().map(|_| ())?;
    claim.response().map(|_| ())?;
    claim.receipt().map(|_| ())
}

fn decode_bounded(encoded: &str, maximum: usize) -> Result<Vec<u8>, ResidentWorkOrderError> {
    if encoded.is_empty() || encoded.contains('=') || encoded.len() > maximum.saturating_mul(2) {
        return Err(ResidentWorkOrderError::StateCorrupt);
    }
    let decoded = URL_SAFE_NO_PAD
        .decode(encoded)
        .map_err(|_| ResidentWorkOrderError::StateCorrupt)?;
    if decoded.is_empty() || decoded.len() > maximum || URL_SAFE_NO_PAD.encode(&decoded) != encoded
    {
        return Err(ResidentWorkOrderError::StateCorrupt);
    }
    Ok(decoded)
}

fn decode_signature(encoded: &str) -> Result<[u8; SIGNATURE_BYTES], ResidentWorkOrderError> {
    let decoded = decode_bounded(encoded, SIGNATURE_BYTES)?;
    decoded
        .try_into()
        .map_err(|_| ResidentWorkOrderError::InvalidServiceReceipt)
}

fn validate_identifier(value: &str) -> Result<(), ResidentWorkOrderError> {
    if value.is_empty()
        || value.len() > MAX_IDENTIFIER_BYTES
        || !value.bytes().all(|byte| {
            byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b':' | b'/')
        })
    {
        return Err(ResidentWorkOrderError::StateCorrupt);
    }
    Ok(())
}

fn validate_timestamp(value: &str) -> Result<(), ResidentWorkOrderError> {
    if value.is_empty()
        || value.len() > MAX_TIMESTAMP_BYTES
        || DateTime::parse_from_rfc3339(value).is_err()
        || value.chars().any(char::is_control)
    {
        return Err(ResidentWorkOrderError::InvalidContext);
    }
    Ok(())
}

fn validate_sha256(value: &str) -> Result<(), ResidentWorkOrderError> {
    if value.len() != SHA256_BYTES * 2
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(ResidentWorkOrderError::StateCorrupt);
    }
    Ok(())
}

fn sha256_hex(bytes: &[u8]) -> String {
    Sha256::digest(bytes)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

fn prepare_private_directory(path: &Path) -> Result<(), ResidentWorkOrderError> {
    if !path.is_absolute() || path == Path::new("/") {
        return Err(ResidentWorkOrderError::StateCorrupt);
    }
    match fs::symlink_metadata(path) {
        Ok(metadata) => inspect_private_directory(&metadata)?,
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            fs::create_dir(path)?;
            #[cfg(unix)]
            fs::set_permissions(path, fs::Permissions::from_mode(0o700))?;
            inspect_private_directory(&fs::symlink_metadata(path)?)?;
        }
        Err(error) => return Err(error.into()),
    }
    Ok(())
}

fn inspect_private_directory(metadata: &fs::Metadata) -> Result<(), ResidentWorkOrderError> {
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err(ResidentWorkOrderError::StateCorrupt);
    }
    #[cfg(unix)]
    if metadata.permissions().mode() & 0o077 != 0 {
        return Err(ResidentWorkOrderError::StateCorrupt);
    }
    Ok(())
}

fn inspect_private_file(metadata: &fs::Metadata) -> Result<(), ResidentWorkOrderError> {
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return Err(ResidentWorkOrderError::StateCorrupt);
    }
    #[cfg(unix)]
    if metadata.permissions().mode() & 0o077 != 0 {
        return Err(ResidentWorkOrderError::StateCorrupt);
    }
    Ok(())
}

fn read_private_optional(
    path: &Path,
    maximum: usize,
) -> Result<Option<Vec<u8>>, ResidentWorkOrderError> {
    match fs::symlink_metadata(path) {
        Ok(metadata) => {
            inspect_private_file(&metadata)?;
            if metadata.len() == 0 || metadata.len() > maximum as u64 {
                return Err(ResidentWorkOrderError::StateCorrupt);
            }
            let bytes = fs::read(path)?;
            if bytes.len() > maximum || bytes.len() as u64 != metadata.len() {
                return Err(ResidentWorkOrderError::StateCorrupt);
            }
            Ok(Some(bytes))
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(error.into()),
    }
}

fn cleanup_temporary(path: &Path) -> Result<(), ResidentWorkOrderError> {
    match fs::symlink_metadata(path) {
        Ok(metadata) => {
            inspect_private_file(&metadata)?;
            fs::remove_file(path)?;
            sync_directory(path.parent().ok_or(ResidentWorkOrderError::StateCorrupt)?)
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error.into()),
    }
}

#[cfg(not(windows))]
fn write_atomic(
    directory: &Path,
    name: &str,
    temporary_name: &str,
    bytes: &[u8],
) -> Result<(), ResidentWorkOrderError> {
    if bytes.is_empty() || bytes.len() > MAX_JOURNAL_BYTES {
        return Err(ResidentWorkOrderError::StateCorrupt);
    }
    let target = directory.join(name);
    let temporary = directory.join(temporary_name);
    if let Ok(metadata) = fs::symlink_metadata(&target) {
        inspect_private_file(&metadata)?;
    }
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    options.mode(0o600);
    let mut file = options.open(&temporary)?;
    let result = (|| -> Result<(), ResidentWorkOrderError> {
        file.write_all(bytes)?;
        file.flush()?;
        file.sync_all()?;
        fs::rename(&temporary, &target)?;
        sync_directory(directory)?;
        inspect_private_file(&fs::symlink_metadata(target)?)?;
        Ok(())
    })();
    if result.is_err() {
        let _ = fs::remove_file(temporary);
    }
    result
}

#[cfg(windows)]
fn write_atomic(
    directory: &Path,
    name: &str,
    _temporary_name: &str,
    bytes: &[u8],
) -> Result<(), ResidentWorkOrderError> {
    use atomic_write_file::AtomicWriteFile;

    if bytes.is_empty() || bytes.len() > MAX_JOURNAL_BYTES {
        return Err(ResidentWorkOrderError::StateCorrupt);
    }
    let target = directory.join(name);
    if let Ok(metadata) = fs::symlink_metadata(&target) {
        inspect_private_file(&metadata)?;
    }
    let mut file = AtomicWriteFile::open(&target)?;
    file.write_all(bytes)?;
    file.flush()?;
    file.commit()?;
    inspect_private_file(&fs::symlink_metadata(target)?)
}

#[cfg(unix)]
fn sync_directory(path: &Path) -> Result<(), ResidentWorkOrderError> {
    File::open(path)?.sync_all()?;
    Ok(())
}

#[cfg(not(unix))]
fn sync_directory(_path: &Path) -> Result<(), ResidentWorkOrderError> {
    Ok(())
}

fn import_canonical<T>(bytes: &[u8], maximum: usize) -> Result<T, ResidentWorkOrderError>
where
    T: DeserializeOwned + Serialize,
{
    if bytes.is_empty() || bytes.len() > maximum {
        return Err(ResidentWorkOrderError::StateCorrupt);
    }
    let parsed: T =
        serde_json::from_slice(bytes).map_err(|_| ResidentWorkOrderError::StateCorrupt)?;
    if canonical_json(&parsed)? != bytes {
        return Err(ResidentWorkOrderError::StateCorrupt);
    }
    Ok(parsed)
}

fn canonical_json<T: Serialize>(value: &T) -> Result<Vec<u8>, ResidentWorkOrderError> {
    let value = serde_json::to_value(value).map_err(|_| ResidentWorkOrderError::StateCorrupt)?;
    validate_json(&value)?;
    let mut output = Vec::new();
    write_canonical(&value, &mut output)?;
    Ok(output)
}

fn validate_json(value: &Value) -> Result<(), ResidentWorkOrderError> {
    match value {
        Value::Null | Value::Bool(_) | Value::String(_) => Ok(()),
        Value::Number(number) => {
            if number
                .as_u64()
                .is_some_and(|value| value <= MAX_SAFE_JSON_INTEGER)
                || number
                    .as_i64()
                    .is_some_and(|value| value.unsigned_abs() <= MAX_SAFE_JSON_INTEGER)
            {
                Ok(())
            } else {
                Err(ResidentWorkOrderError::StateCorrupt)
            }
        }
        Value::Array(values) => values.iter().try_for_each(validate_json),
        Value::Object(values) => values.values().try_for_each(validate_json),
    }
}

fn write_canonical(value: &Value, output: &mut Vec<u8>) -> Result<(), ResidentWorkOrderError> {
    match value {
        Value::Null => output.extend_from_slice(b"null"),
        Value::Bool(value) => output.extend_from_slice(if *value { b"true" } else { b"false" }),
        Value::Number(value) => output.extend_from_slice(value.to_string().as_bytes()),
        Value::String(value) => output.extend_from_slice(
            serde_json::to_string(value)
                .map_err(|_| ResidentWorkOrderError::StateCorrupt)?
                .as_bytes(),
        ),
        Value::Array(values) => {
            output.push(b'[');
            for (index, value) in values.iter().enumerate() {
                if index != 0 {
                    output.push(b',');
                }
                write_canonical(value, output)?;
            }
            output.push(b']');
        }
        Value::Object(values) => {
            output.push(b'{');
            let mut keys: Vec<&str> = values.keys().map(String::as_str).collect();
            keys.sort_unstable();
            for (index, key) in keys.into_iter().enumerate() {
                if index != 0 {
                    output.push(b',');
                }
                output.extend_from_slice(
                    serde_json::to_string(key)
                        .map_err(|_| ResidentWorkOrderError::StateCorrupt)?
                        .as_bytes(),
                );
                output.push(b':');
                write_canonical(
                    values
                        .get(key)
                        .ok_or(ResidentWorkOrderError::StateCorrupt)?,
                    output,
                )?;
            }
            output.push(b'}');
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer as _, SigningKey};
    use kernaid_fleet_runtime::FleetEntitlementState;
    use serde_json::json;
    use std::sync::{
        Arc, Mutex,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    };
    use tempfile::TempDir;

    const TENANT: &str = "tenant-europe-1";
    const NOW: &str = "2026-08-31T12:30:45Z";
    const NOW_UNIX: u64 = 1_788_179_445;

    #[derive(Clone, Copy)]
    enum MockOrderKind {
        Diagnosis,
        Repair,
    }

    #[derive(Clone)]
    struct MockTransport {
        identity_public_key: [u8; 32],
        device_id: String,
        service_key: SigningKey,
        kind: MockOrderKind,
        wrong_receipt_tenant: bool,
        fail_result_once: Arc<AtomicBool>,
        claims: Arc<AtomicUsize>,
        results: Arc<AtomicUsize>,
        result_bodies: Arc<Mutex<Vec<Vec<u8>>>>,
    }

    impl ResidentWorkOrderTransport for MockTransport {
        fn claim(
            &mut self,
            body: &[u8],
            _maximum_response_bytes: usize,
        ) -> Result<WorkOrderTransportResponse, TransportErrorCode> {
            self.claims.fetch_add(1, Ordering::SeqCst);
            let claim = SignedWorkOrderClaimRequest::import_offline(
                body,
                TENANT,
                &self.device_id,
                &self.identity_public_key,
            )
            .map_err(|_| TransportErrorCode::Protocol)?;
            let order = match self.kind {
                MockOrderKind::Diagnosis => json!({
                    "workOrderId": "wo_diag_01",
                    "targetDeviceId": claim.device_id(),
                    "actionId": "linux.filesystem.health.v1",
                    "actionVersion": 1,
                    "kind": "diagnosis",
                    "risk": "R0",
                    "localApprovalRequired": false,
                    "status": "leased",
                    "createdAt": "2026-08-31T12:00:00Z",
                    "expiresAt": "2026-08-31T13:00:00Z",
                    "approval": null,
                    "lease": {
                        "leaseId": "lease_diag_01",
                        "leasedAt": NOW,
                        "leaseExpiresAt": "2026-08-31T12:35:45Z"
                    }
                }),
                MockOrderKind::Repair => json!({
                    "workOrderId": "wo_repair_01",
                    "targetDeviceId": claim.device_id(),
                    "actionId": "linux.fstab.disable-missing-uuid.v1",
                    "actionVersion": 1,
                    "kind": "repair",
                    "risk": "R2",
                    "localApprovalRequired": true,
                    "status": "leased",
                    "createdAt": "2026-08-31T12:00:00Z",
                    "expiresAt": "2026-08-31T13:00:00Z",
                    "approval": {
                        "approvedByCredentialId": "cred_operator_01",
                        "approvedAt": "2026-08-31T12:29:00Z"
                    },
                    "lease": {
                        "leaseId": "lease_repair_01",
                        "leasedAt": NOW,
                        "leaseExpiresAt": "2026-08-31T12:35:45Z"
                    }
                }),
            };
            let response = serde_json::to_vec(&json!({
                "schema": kernaid_fleet_client::WORK_ORDER_CLAIM_RESPONSE_SCHEMA,
                "tenantId": TENANT,
                "deviceId": claim.device_id(),
                "workOrder": order,
                "idempotent": false
            }))
            .map_err(|_| TransportErrorCode::Protocol)?;
            let receipt_tenant = if self.wrong_receipt_tenant {
                "tenant-other"
            } else {
                TENANT
            };
            let receipt = signed_receipt(
                receipt_tenant,
                claim.device_id(),
                WorkOrderReceiptOperation::WorkOrderClaim,
                1,
                body,
                &response,
                &self.service_key,
            )
            .map_err(|_| TransportErrorCode::Protocol)?;
            Ok(WorkOrderTransportResponse {
                status: 200,
                body: response,
                receipt: Some(receipt),
            })
        }

        fn submit_result(
            &mut self,
            body: &[u8],
            _maximum_response_bytes: usize,
        ) -> Result<WorkOrderTransportResponse, TransportErrorCode> {
            self.results.fetch_add(1, Ordering::SeqCst);
            self.result_bodies
                .lock()
                .map_err(|_| TransportErrorCode::Protocol)?
                .push(body.to_vec());
            if self.fail_result_once.swap(false, Ordering::SeqCst) {
                return Err(TransportErrorCode::Timeout);
            }
            let result = SignedWorkOrderResult::import_offline(
                body,
                TENANT,
                &self.device_id,
                &self.identity_public_key,
            )
            .map_err(|_| TransportErrorCode::Protocol)?;
            let response = serde_json::to_vec(&json!({
                "schema": WORK_ORDER_RESULT_RESPONSE_SCHEMA,
                "tenantId": TENANT,
                "deviceId": self.device_id,
                "workOrderId": result.work_order_id(),
                "status": result.outcome(),
                "outcome": result.outcome(),
                "resultSha256": result.result_sha256(),
                "accepted": true,
                "idempotent": false
            }))
            .map_err(|_| TransportErrorCode::Protocol)?;
            let receipt = signed_receipt(
                TENANT,
                &self.device_id,
                WorkOrderReceiptOperation::WorkOrderResult,
                2,
                body,
                &response,
                &self.service_key,
            )
            .map_err(|_| TransportErrorCode::Protocol)?;
            Ok(WorkOrderTransportResponse {
                status: 201,
                body: response,
                receipt: Some(receipt),
            })
        }
    }

    struct MockHandoff {
        prepares: Arc<AtomicUsize>,
        executions: Arc<AtomicUsize>,
        execution_ids: Arc<Mutex<Vec<String>>>,
        fail_execution_once: Arc<AtomicBool>,
    }

    impl LocalWorkOrderHandoff for MockHandoff {
        fn prepare(
            &mut self,
            order: &LeasedWorkOrder,
            execution_id: &str,
        ) -> Result<PreparedLocalExecution, LocalHandoffErrorCode> {
            self.prepares.fetch_add(1, Ordering::SeqCst);
            Ok(PreparedLocalExecution::diagnostic(
                order,
                execution_id,
                "11".repeat(32),
                "22".repeat(32),
            ))
        }

        fn execute_or_recover(
            &mut self,
            prepared: &PreparedLocalExecution,
        ) -> Result<LocalExecutionResult, LocalHandoffErrorCode> {
            self.executions.fetch_add(1, Ordering::SeqCst);
            self.execution_ids
                .lock()
                .map_err(|_| LocalHandoffErrorCode::StateMismatch)?
                .push(prepared.execution_id().to_owned());
            if self.fail_execution_once.swap(false, Ordering::SeqCst) {
                return Err(LocalHandoffErrorCode::Busy);
            }
            Ok(LocalExecutionResult::new(
                WorkOrderResultOutcome::Succeeded,
                "33".repeat(32),
            ))
        }
    }

    fn identity() -> DeviceIdentity {
        DeviceIdentity::from_seed(&[0x42; 32]).expect("fixed identity")
    }

    fn service_key() -> SigningKey {
        SigningKey::from_bytes(&[0x73; 32])
    }

    fn capabilities(fleet_sync: bool, enterprise_repair: bool) -> FleetCapabilities {
        FleetCapabilities {
            entitlement_state: FleetEntitlementState::Absent,
            diagnostics: true,
            report_export: true,
            rollback: true,
            consumer_repair: false,
            enterprise_repair,
            fleet_sync,
            cached_policy: false,
            audit_upload: false,
            updates: false,
            enterprise_providers: false,
        }
    }

    fn input() -> WorkOrderCycleInput {
        WorkOrderCycleInput {
            issued_at: NOW.to_owned(),
            now_unix: NOW_UNIX,
            nonce: Zeroizing::new(vec![0xa5; 32]),
            lease_seconds: 300,
        }
    }

    fn authorization<'a>(
        platform: ResidentPlatform,
        capabilities: FleetCapabilities,
        policies: &'a [VerifiedPolicyBundle],
    ) -> WorkOrderAuthorization<'a> {
        WorkOrderAuthorization {
            platform,
            capabilities,
            policies,
            local_max_risk: RiskLevel::R2,
            local_approval_from: RiskLevel::R1,
            now_unix: NOW_UNIX,
        }
    }

    type MockParts = (
        MockTransport,
        MockHandoff,
        Arc<AtomicUsize>,
        Arc<AtomicUsize>,
        Arc<AtomicUsize>,
        Arc<Mutex<Vec<Vec<u8>>>>,
    );

    fn mocks(identity: &DeviceIdentity, kind: MockOrderKind) -> MockParts {
        let claims = Arc::new(AtomicUsize::new(0));
        let results = Arc::new(AtomicUsize::new(0));
        let executions = Arc::new(AtomicUsize::new(0));
        let result_bodies = Arc::new(Mutex::new(Vec::new()));
        (
            MockTransport {
                identity_public_key: identity.public_key(),
                device_id: identity.device_id(),
                service_key: service_key(),
                kind,
                wrong_receipt_tenant: false,
                fail_result_once: Arc::new(AtomicBool::new(false)),
                claims: Arc::clone(&claims),
                results: Arc::clone(&results),
                result_bodies: Arc::clone(&result_bodies),
            },
            MockHandoff {
                prepares: Arc::new(AtomicUsize::new(0)),
                executions: Arc::clone(&executions),
                execution_ids: Arc::new(Mutex::new(Vec::new())),
                fail_execution_once: Arc::new(AtomicBool::new(false)),
            },
            claims,
            results,
            executions,
            result_bodies,
        )
    }

    fn signed_receipt(
        tenant_id: &str,
        device_id: &str,
        operation: WorkOrderReceiptOperation,
        sequence: u64,
        request: &[u8],
        response: &[u8],
        key: &SigningKey,
    ) -> Result<Vec<u8>, ResidentWorkOrderError> {
        let mut receipt = SignedServiceReceipt {
            schema: SERVICE_RECEIPT_SCHEMA.to_owned(),
            tenant_id: tenant_id.to_owned(),
            device_id: device_id.to_owned(),
            operation,
            sequence,
            request_sha256: sha256_hex(request),
            response_sha256: sha256_hex(response),
            accepted_at: NOW.to_owned(),
            outcome: ReceiptOutcome::Accepted,
            signature: String::new(),
        };
        let unsigned = canonical_json(&receipt.unsigned())?;
        let mut message =
            Vec::with_capacity(SERVICE_RECEIPT_SIGNATURE_DOMAIN.len() + unsigned.len());
        message.extend_from_slice(SERVICE_RECEIPT_SIGNATURE_DOMAIN);
        message.extend_from_slice(&unsigned);
        receipt.signature = URL_SAFE_NO_PAD.encode(key.sign(&message).to_bytes());
        canonical_json(&receipt)
    }

    #[test]
    fn diagnosis_claim_handoff_and_signed_result_complete_end_to_end() {
        let directory = TempDir::new().expect("tempdir");
        let state = directory.path().join("work-order-state");
        let identity = identity();
        let (transport, mut handoff, claims, results, executions, _) =
            mocks(&identity, MockOrderKind::Diagnosis);
        let mut engine = ResidentWorkOrderEngine::open(
            TENANT,
            &identity,
            &service_key().verifying_key().to_bytes(),
            &state,
            transport,
        )
        .expect("open engine");
        let outcome = engine
            .run_once(
                &identity,
                input(),
                &authorization(ResidentPlatform::Linux, capabilities(true, false), &[]),
                &mut handoff,
            )
            .expect("complete order");
        assert!(matches!(
            outcome,
            WorkOrderCycleOutcome::Completed {
                outcome: WorkOrderResultOutcome::Succeeded,
                ..
            }
        ));
        assert_eq!(claims.load(Ordering::SeqCst), 1);
        assert_eq!(results.load(Ordering::SeqCst), 1);
        assert_eq!(executions.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn result_timeout_restarts_with_exact_bytes_without_reexecution() {
        let directory = TempDir::new().expect("tempdir");
        let state = directory.path().join("work-order-state");
        let identity = identity();
        let (transport, mut handoff, _, results, executions, result_bodies) =
            mocks(&identity, MockOrderKind::Diagnosis);
        transport.fail_result_once.store(true, Ordering::SeqCst);
        let shared_transport = transport.clone();
        let anchor = service_key().verifying_key().to_bytes();
        let mut engine =
            ResidentWorkOrderEngine::open(TENANT, &identity, &anchor, &state, transport)
                .expect("open engine");
        assert!(matches!(
            engine.run_once(
                &identity,
                input(),
                &authorization(ResidentPlatform::Linux, capabilities(true, false), &[]),
                &mut handoff,
            ),
            Err(ResidentWorkOrderError::Transport(
                TransportErrorCode::Timeout
            ))
        ));
        drop(engine);
        let mut reopened =
            ResidentWorkOrderEngine::open(TENANT, &identity, &anchor, &state, shared_transport)
                .expect("reopen engine");
        reopened
            .run_once(
                &identity,
                input(),
                &authorization(ResidentPlatform::Linux, capabilities(true, false), &[]),
                &mut handoff,
            )
            .expect("retry exact result");
        assert_eq!(executions.load(Ordering::SeqCst), 1);
        assert_eq!(results.load(Ordering::SeqCst), 2);
        let bodies = result_bodies.lock().expect("result bodies");
        assert_eq!(bodies.len(), 2);
        assert_eq!(bodies[0], bodies[1]);
    }

    #[test]
    fn execution_restart_uses_same_idempotency_key() {
        let directory = TempDir::new().expect("tempdir");
        let state = directory.path().join("work-order-state");
        let identity = identity();
        let (transport, mut handoff, _, _, executions, _) =
            mocks(&identity, MockOrderKind::Diagnosis);
        handoff.fail_execution_once.store(true, Ordering::SeqCst);
        let transport_again = transport.clone();
        let anchor = service_key().verifying_key().to_bytes();
        let mut engine =
            ResidentWorkOrderEngine::open(TENANT, &identity, &anchor, &state, transport)
                .expect("open engine");
        assert!(matches!(
            engine.run_once(
                &identity,
                input(),
                &authorization(ResidentPlatform::Linux, capabilities(true, false), &[]),
                &mut handoff,
            ),
            Err(ResidentWorkOrderError::Handoff(LocalHandoffErrorCode::Busy))
        ));
        drop(engine);
        let mut reopened =
            ResidentWorkOrderEngine::open(TENANT, &identity, &anchor, &state, transport_again)
                .expect("reopen engine");
        reopened
            .run_once(
                &identity,
                input(),
                &authorization(ResidentPlatform::Linux, capabilities(true, false), &[]),
                &mut handoff,
            )
            .expect("recover execution");
        assert_eq!(executions.load(Ordering::SeqCst), 2);
        let ids = handoff.execution_ids.lock().expect("execution IDs");
        assert_eq!(ids.len(), 2);
        assert_eq!(ids[0], ids[1]);
    }

    #[test]
    fn repair_without_policy_is_signed_rejection_and_never_handed_off() {
        let directory = TempDir::new().expect("tempdir");
        let state = directory.path().join("work-order-state");
        let identity = identity();
        let (transport, mut handoff, _, results, executions, _) =
            mocks(&identity, MockOrderKind::Repair);
        let mut engine = ResidentWorkOrderEngine::open(
            TENANT,
            &identity,
            &service_key().verifying_key().to_bytes(),
            &state,
            transport,
        )
        .expect("open engine");
        let outcome = engine
            .run_once(
                &identity,
                input(),
                &authorization(ResidentPlatform::Rescue, capabilities(true, true), &[]),
                &mut handoff,
            )
            .expect("submit rejection");
        assert!(matches!(
            outcome,
            WorkOrderCycleOutcome::Completed {
                outcome: WorkOrderResultOutcome::Rejected,
                ..
            }
        ));
        assert_eq!(executions.load(Ordering::SeqCst), 0);
        assert_eq!(results.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn cross_tenant_service_receipt_fails_before_local_handoff() {
        let directory = TempDir::new().expect("tempdir");
        let identity = identity();
        let (mut transport, mut handoff, _, _, executions, _) =
            mocks(&identity, MockOrderKind::Diagnosis);
        transport.wrong_receipt_tenant = true;
        let mut engine = ResidentWorkOrderEngine::open(
            TENANT,
            &identity,
            &service_key().verifying_key().to_bytes(),
            &directory.path().join("work-order-state"),
            transport,
        )
        .expect("open engine");
        assert!(matches!(
            engine.run_once(
                &identity,
                input(),
                &authorization(ResidentPlatform::Linux, capabilities(true, false), &[]),
                &mut handoff,
            ),
            Err(ResidentWorkOrderError::InvalidServiceReceipt)
        ));
        assert_eq!(executions.load(Ordering::SeqCst), 0);
    }
}
