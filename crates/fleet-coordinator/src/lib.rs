#![forbid(unsafe_code)]
//! Transport-neutral orchestration for the device-side Fleet runtime.
//!
//! This crate never opens a network socket and never owns a bearer credential
//! or signing seed. Callers transport the exact request bytes and return exact
//! response/receipt bytes through this boundary.

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use chrono::DateTime;
use ed25519_dalek::{Signature, VerifyingKey};
use kernaid_device_identity::DeviceIdentity;
use kernaid_entitlements::{EntitlementError, verify_entitlement, verify_revocations};
pub use kernaid_fleet_audit::{AuditKind, AuditOutcome, AuditRisk};
pub use kernaid_fleet_client::{
    EntitlementPullRequestInput, FleetClientError, InventoryAsset, PolicyPullRequestInput,
};
use kernaid_fleet_client::{SignedEntitlementPullRequest, SignedPolicyPullRequest};
use kernaid_fleet_policy::{FleetPolicyError, SignedPolicyBundle, TransportState};
use kernaid_fleet_runtime::{
    AuditAcknowledgement, FleetEntitlementState, FleetRuntime, FleetRuntimeError,
};
pub use kernaid_fleet_runtime::{AuditEnqueueResult, AuditEventDraft, FleetCapabilities};
use rusqlite::{
    Connection, OpenFlags, OptionalExtension, Transaction, TransactionBehavior, params,
};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::{
    error::Error,
    fmt,
    fs::{self, OpenOptions},
    io,
    path::{Path, PathBuf},
};

#[cfg(unix)]
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};

/// Canonical service receipt wire schema.
pub const SERVICE_RECEIPT_SCHEMA: &str = "dev.kernaid.fleet.service-receipt.v1";
/// Exact service receipt signature prefix.
pub const SERVICE_RECEIPT_SIGNATURE_DOMAIN: &[u8] = b"kernaid:fleet:service-receipt:v1\0";

const APPLICATION_ID: i64 = 0x4b41_4643; // "KAFC"
const SCHEMA_VERSION: i64 = 1;
const MAX_SAFE_JSON_INTEGER: u64 = 9_007_199_254_740_991;
const MAX_RECEIPT_BYTES: usize = 8 * 1024;
const MAX_PULL_RESPONSE_BYTES: usize = 4 * 1024 * 1024;
const MAX_POLICY_ITEMS: usize = 256;
const MAX_ENTITLEMENT_ITEMS: usize = 1;
const MAX_ID_BYTES: usize = 160;
const MAX_TIMESTAMP_BYTES: usize = 64;
const SHA256_BYTES: usize = 32;
const SIGNATURE_BYTES: usize = 64;

/// Fleet operation carried by an exact request/receipt pair.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum FleetOperation {
    Inventory,
    Audit,
    PolicyPull,
    EntitlementPull,
}

impl FleetOperation {
    #[must_use]
    pub const fn route(self) -> &'static str {
        match self {
            Self::Inventory => "/v1/inventories",
            Self::Audit => "/v1/audit-events",
            Self::PolicyPull => "/v1/policy-pulls",
            Self::EntitlementPull => "/v1/entitlement-pulls",
        }
    }

    const fn database_name(self) -> &'static str {
        match self {
            Self::PolicyPull => "policy_pull",
            Self::EntitlementPull => "entitlement_pull",
            Self::Inventory | Self::Audit => "invalid",
        }
    }

    fn from_database_name(value: &str) -> Result<Self, FleetCoordinatorError> {
        match value {
            "policy_pull" => Ok(Self::PolicyPull),
            "entitlement_pull" => Ok(Self::EntitlementPull),
            _ => Err(FleetCoordinatorError::StateCorrupt),
        }
    }

    const fn is_pull(self) -> bool {
        matches!(self, Self::PolicyPull | Self::EntitlementPull)
    }
}

#[derive(Clone)]
enum PreparedSource {
    Inventory {
        id: u64,
        payload_sha256: [u8; SHA256_BYTES],
    },
    Audit {
        id: u64,
        payload_sha256: [u8; SHA256_BYTES],
    },
    Pull,
}

/// Exact body plus opaque local acknowledgement binding. The body is safe to
/// pass to an HTTPS transport but is intentionally omitted from `Debug`.
#[derive(Clone)]
pub struct PreparedRequest {
    operation: FleetOperation,
    body: Vec<u8>,
    request_sha256: [u8; SHA256_BYTES],
    source: PreparedSource,
}

impl PreparedRequest {
    #[must_use]
    pub const fn operation(&self) -> FleetOperation {
        self.operation
    }

    #[must_use]
    pub const fn route(&self) -> &'static str {
        self.operation.route()
    }

    #[must_use]
    pub fn body(&self) -> &[u8] {
        &self.body
    }

    #[must_use]
    pub const fn request_sha256(&self) -> &[u8; SHA256_BYTES] {
        &self.request_sha256
    }
}

impl fmt::Debug for PreparedRequest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PreparedRequest")
            .field("operation", &self.operation)
            .field("body_len", &self.body.len())
            .finish_non_exhaustive()
    }
}

/// Whether a verified service receipt advanced durable state or was an exact
/// replay of the current checkpoint.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReceiptAdmission {
    Advanced,
    IdempotentReplay,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PullApplyResult {
    pub documents_applied: u16,
    pub receipt_admission: ReceiptAdmission,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PullStatus {
    Idle,
    Pending,
    RecoveryRequired,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LocalSyncState {
    Ready,
    WorkPending,
    RecoveryRequired,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PolicyCacheState {
    Verified,
    Applying,
    Corrupt,
}

/// Bounded policy view for Desk/Rescue. No rules or assignments are exposed.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LocalPolicySnapshot {
    pub state: PolicyCacheState,
    pub cached_count: u16,
    pub applicable_count: u16,
}

/// Privacy-minimized local view for presentation layers.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LocalFleetSnapshot {
    pub sync_state: LocalSyncState,
    pub pending_inventory: u64,
    pub pending_audit: u64,
    pub policy_pull: PullStatus,
    pub entitlement_pull: PullStatus,
    pub last_receipt_sequence: Option<u64>,
    pub capabilities: FleetCapabilities,
    pub policy: LocalPolicySnapshot,
}

/// Public-only configuration. Trust anchors are retained in memory and never
/// copied into either database.
pub struct FleetCoordinatorConfig<'a> {
    pub coordinator_state_path: &'a Path,
    pub runtime_state_path: &'a Path,
    pub tenant_id: &'a str,
    pub service_receipt_anchor: &'a [u8; 32],
    pub entitlement_anchor: &'a [u8; 32],
    pub policy_anchor: &'a [u8; 32],
}

/// Sanitized coordinator failures. Display output never contains request
/// bytes, paths, nonces, signatures, tokens or key material.
#[derive(Debug)]
pub enum FleetCoordinatorError {
    InvalidPath,
    SymlinkRejected,
    InsecurePermissions,
    UnsupportedFormat,
    IdentityMismatch,
    InvalidTrustAnchor,
    InvalidRequest,
    InvalidResponse,
    ResponseTooLarge,
    InvalidReceipt,
    ReceiptRollback,
    ReceiptConflict,
    PullInFlight,
    PullNotPending,
    RecoveryRequired,
    StateCorrupt,
    Client(FleetClientError),
    Runtime(FleetRuntimeError),
    Policy(FleetPolicyError),
    Entitlement(EntitlementError),
    Database(rusqlite::Error),
    Io(io::Error),
}

impl fmt::Display for FleetCoordinatorError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::InvalidPath => "invalid Fleet coordinator state path",
            Self::SymlinkRejected => "Fleet coordinator state links are not allowed",
            Self::InsecurePermissions => "Fleet coordinator state permissions are too broad",
            Self::UnsupportedFormat => "unsupported Fleet coordinator state format",
            Self::IdentityMismatch => "Fleet coordinator identity does not match",
            Self::InvalidTrustAnchor => "Fleet coordinator trust anchor is invalid",
            Self::InvalidRequest => "Fleet coordinator request is invalid",
            Self::InvalidResponse => "Fleet coordinator response is invalid",
            Self::ResponseTooLarge => "Fleet coordinator response is too large",
            Self::InvalidReceipt => "Fleet service receipt is invalid",
            Self::ReceiptRollback => "Fleet service receipt sequence rolled back",
            Self::ReceiptConflict => "Fleet service receipt replay conflicts with retained state",
            Self::PullInFlight => "a different Fleet pull is already pending",
            Self::PullNotPending => "Fleet pull is not pending",
            Self::RecoveryRequired => "Fleet pull recovery is required",
            Self::StateCorrupt => "Fleet coordinator state is corrupt",
            Self::Client(_) => "Fleet request signing failed",
            Self::Runtime(_) => "Fleet runtime operation failed",
            Self::Policy(_) => "Fleet policy response verification failed",
            Self::Entitlement(_) => "Fleet entitlement response verification failed",
            Self::Database(_) => "Fleet coordinator database operation failed",
            Self::Io(_) => "Fleet coordinator state operation failed",
        })
    }
}

impl Error for FleetCoordinatorError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Client(error) => Some(error),
            Self::Runtime(error) => Some(error),
            Self::Policy(error) => Some(error),
            Self::Entitlement(error) => Some(error),
            Self::Database(error) => Some(error),
            Self::Io(error) => Some(error),
            _ => None,
        }
    }
}

impl From<FleetClientError> for FleetCoordinatorError {
    fn from(value: FleetClientError) -> Self {
        Self::Client(value)
    }
}

impl From<FleetRuntimeError> for FleetCoordinatorError {
    fn from(value: FleetRuntimeError) -> Self {
        Self::Runtime(value)
    }
}

impl From<FleetPolicyError> for FleetCoordinatorError {
    fn from(value: FleetPolicyError) -> Self {
        Self::Policy(value)
    }
}

impl From<EntitlementError> for FleetCoordinatorError {
    fn from(value: EntitlementError) -> Self {
        Self::Entitlement(value)
    }
}

impl From<rusqlite::Error> for FleetCoordinatorError {
    fn from(value: rusqlite::Error) -> Self {
        Self::Database(value)
    }
}

impl From<io::Error> for FleetCoordinatorError {
    fn from(value: io::Error) -> Self {
        Self::Io(value)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
enum ReceiptOutcome {
    Accepted,
}

#[derive(Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct SignedServiceReceipt {
    schema: String,
    tenant_id: String,
    device_id: String,
    operation: FleetOperation,
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
    operation: FleetOperation,
    sequence: u64,
    request_sha256: &'a str,
    response_sha256: &'a str,
    accepted_at: &'a str,
    outcome: ReceiptOutcome,
}

struct VerifiedServiceReceipt {
    sequence: u64,
    digest: [u8; SHA256_BYTES],
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct PolicyPullResponse {
    schema: String,
    tenant_id: String,
    device_id: String,
    items: Vec<Value>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct EntitlementPullResponse {
    schema: String,
    tenant_id: String,
    device_id: String,
    entitlements: Vec<Value>,
    revocations: Option<Value>,
}

struct PendingPullRow {
    operation: FleetOperation,
    request: Vec<u8>,
    request_sha256: [u8; SHA256_BYTES],
    state: i64,
    response: Option<Vec<u8>>,
    receipt: Option<Vec<u8>>,
}

enum ParsedPullResponse {
    Policies(Vec<Vec<u8>>),
    Entitlements {
        entitlement: Option<Vec<u8>>,
        revocations: Option<Vec<u8>>,
    },
}

/// Durable, transport-neutral Fleet coordinator.
pub struct FleetCoordinator {
    runtime: FleetRuntime,
    state: Connection,
    state_path: PathBuf,
    tenant_id: String,
    device_id: String,
    device_public_key: [u8; 32],
    service_receipt_anchor: VerifyingKey,
    entitlement_anchor: [u8; 32],
    policy_anchor: VerifyingKey,
}

impl FleetCoordinator {
    /// Open both durable stores and recover any fully journaled pull response.
    pub fn open(
        config: FleetCoordinatorConfig<'_>,
        identity: &DeviceIdentity,
    ) -> Result<Self, FleetCoordinatorError> {
        let service_receipt_anchor = VerifyingKey::from_bytes(config.service_receipt_anchor)
            .map_err(|_| FleetCoordinatorError::InvalidTrustAnchor)?;
        let policy_anchor = VerifyingKey::from_bytes(config.policy_anchor)
            .map_err(|_| FleetCoordinatorError::InvalidTrustAnchor)?;
        VerifyingKey::from_bytes(config.entitlement_anchor)
            .map_err(|_| FleetCoordinatorError::InvalidTrustAnchor)?;
        let runtime = FleetRuntime::open_with_trust_anchors(
            config.runtime_state_path,
            config.tenant_id,
            identity,
            config.entitlement_anchor,
            config.policy_anchor,
        )?;
        prepare_state_path(config.coordinator_state_path)?;
        let state = Connection::open_with_flags(
            config.coordinator_state_path,
            OpenFlags::SQLITE_OPEN_READ_WRITE
                | OpenFlags::SQLITE_OPEN_NO_MUTEX
                | OpenFlags::SQLITE_OPEN_NOFOLLOW,
        )?;
        configure_state(&state)?;
        initialize_or_validate_state(&state, config.tenant_id, runtime.device_id())?;
        harden_state_files(config.coordinator_state_path)?;
        let mut coordinator = Self {
            tenant_id: config.tenant_id.to_owned(),
            device_id: runtime.device_id().to_owned(),
            device_public_key: identity.public_key(),
            runtime,
            state,
            state_path: config.coordinator_state_path.to_path_buf(),
            service_receipt_anchor,
            entitlement_anchor: *config.entitlement_anchor,
            policy_anchor,
        };
        coordinator.recover_staged_pulls()?;
        Ok(coordinator)
    }

    #[must_use]
    pub fn tenant_id(&self) -> &str {
        &self.tenant_id
    }

    #[must_use]
    pub fn device_id(&self) -> &str {
        &self.device_id
    }

    /// Sign and durably enqueue privacy-minimized inventory.
    pub fn queue_inventory(
        &mut self,
        identity: &DeviceIdentity,
        observed_at: &str,
        assets: Vec<InventoryAsset>,
    ) -> Result<Vec<u64>, FleetCoordinatorError> {
        self.ensure_identity(identity)?;
        Ok(self
            .runtime
            .queue_inventory(identity, observed_at, assets)?)
    }

    /// Sign and durably enqueue a privacy-bounded audit event.
    pub fn enqueue_audit(
        &mut self,
        identity: &DeviceIdentity,
        draft: AuditEventDraft,
    ) -> Result<AuditEnqueueResult, FleetCoordinatorError> {
        self.ensure_identity(identity)?;
        Ok(self.runtime.enqueue_audit(identity, draft)?)
    }

    /// Return exact inventory request bodies without mutating retry state.
    pub fn ready_inventory(
        &mut self,
        now_epoch_seconds: u64,
        limit: usize,
    ) -> Result<Vec<PreparedRequest>, FleetCoordinatorError> {
        Ok(self
            .runtime
            .ready_inventory(now_epoch_seconds, limit)?
            .into_iter()
            .map(|pending| {
                let body = pending.payload().to_vec();
                PreparedRequest {
                    operation: FleetOperation::Inventory,
                    request_sha256: sha256(&body),
                    body,
                    source: PreparedSource::Inventory {
                        id: pending.id(),
                        payload_sha256: *pending.payload_sha256(),
                    },
                }
            })
            .collect())
    }

    /// Return exact audit request bodies without acknowledging their journal.
    pub fn ready_audit(&self, limit: usize) -> Result<Vec<PreparedRequest>, FleetCoordinatorError> {
        Ok(self
            .runtime
            .pending_audit(limit)?
            .into_iter()
            .map(|pending| {
                let body = pending.payload().to_vec();
                PreparedRequest {
                    operation: FleetOperation::Audit,
                    request_sha256: sha256(&body),
                    body,
                    source: PreparedSource::Audit {
                        id: pending.id(),
                        payload_sha256: *pending.payload_sha256(),
                    },
                }
            })
            .collect())
    }

    /// Acknowledge an inventory/audit row only after an externally anchored
    /// receipt binds the exact request and exact response bytes.
    pub fn accept_upload_receipt(
        &mut self,
        prepared: &PreparedRequest,
        response: &[u8],
        receipt: &[u8],
    ) -> Result<ReceiptAdmission, FleetCoordinatorError> {
        let source = match (&prepared.operation, &prepared.source) {
            (FleetOperation::Inventory, PreparedSource::Inventory { .. })
            | (FleetOperation::Audit, PreparedSource::Audit { .. }) => &prepared.source,
            _ => return Err(FleetCoordinatorError::InvalidRequest),
        };
        if response.len() > MAX_RECEIPT_BYTES {
            return Err(FleetCoordinatorError::ResponseTooLarge);
        }
        let verified = self.verify_receipt(
            receipt,
            prepared.operation,
            &prepared.request_sha256,
            &sha256(response),
        )?;
        let transaction = self
            .state
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let admission = admit_receipt(&transaction, &verified)?;
        transaction.commit()?;
        match source {
            PreparedSource::Inventory { id, payload_sha256 } => {
                self.runtime.acknowledge(*id, payload_sha256)?;
            }
            PreparedSource::Audit { id, payload_sha256 } => {
                let _: AuditAcknowledgement =
                    self.runtime.acknowledge_audit(*id, payload_sha256)?;
            }
            PreparedSource::Pull => return Err(FleetCoordinatorError::InvalidRequest),
        }
        harden_state_files(&self.state_path)?;
        Ok(admission)
    }

    /// Record an inventory transport retry against the exact prepared row.
    pub fn record_inventory_retry(
        &mut self,
        prepared: &PreparedRequest,
        now_epoch_seconds: u64,
        retry_delay_seconds: u64,
    ) -> Result<(), FleetCoordinatorError> {
        let PreparedSource::Inventory { id, payload_sha256 } = &prepared.source else {
            return Err(FleetCoordinatorError::InvalidRequest);
        };
        self.runtime
            .record_retry(*id, payload_sha256, now_epoch_seconds, retry_delay_seconds)?;
        Ok(())
    }

    /// Create or exactly replay one durable policy pull request.
    pub fn prepare_policy_pull(
        &mut self,
        identity: &DeviceIdentity,
        input: PolicyPullRequestInput,
    ) -> Result<PreparedRequest, FleetCoordinatorError> {
        self.ensure_identity(identity)?;
        let request = SignedPolicyPullRequest::sign(identity, input)?;
        self.retain_pull(FleetOperation::PolicyPull, request.export_offline()?)
    }

    /// Create or exactly replay one durable entitlement pull request.
    pub fn prepare_entitlement_pull(
        &mut self,
        identity: &DeviceIdentity,
        input: EntitlementPullRequestInput,
    ) -> Result<PreparedRequest, FleetCoordinatorError> {
        self.ensure_identity(identity)?;
        let request = SignedEntitlementPullRequest::sign(identity, input)?;
        self.retain_pull(FleetOperation::EntitlementPull, request.export_offline()?)
    }

    /// Reload a pending request after process restart without minting a nonce.
    pub fn pending_pull(
        &self,
        operation: FleetOperation,
    ) -> Result<Option<PreparedRequest>, FleetCoordinatorError> {
        if !operation.is_pull() {
            return Err(FleetCoordinatorError::InvalidRequest);
        }
        let Some(row) = read_pending_pull(&self.state, operation)? else {
            return Ok(None);
        };
        validate_pending_pull(
            &row,
            &self.tenant_id,
            &self.device_id,
            &self.device_public_key,
        )?;
        Ok(Some(prepared_pull(row.operation, row.request)))
    }

    /// Explicitly discard an expired request only while no response is being
    /// applied. The exact digest prevents a stale caller discarding a newer
    /// nonce.
    pub fn abandon_pull(
        &mut self,
        operation: FleetOperation,
        request_sha256: &[u8; SHA256_BYTES],
    ) -> Result<(), FleetCoordinatorError> {
        if !operation.is_pull() {
            return Err(FleetCoordinatorError::InvalidRequest);
        }
        let changed = self.state.execute(
            "DELETE FROM fleet_coordinator_pulls
             WHERE operation = ?1 AND request_sha256 = ?2 AND state = 0",
            params![operation.database_name(), request_sha256.as_slice()],
        )?;
        if changed != 1 {
            return Err(FleetCoordinatorError::PullNotPending);
        }
        Ok(())
    }

    /// Verify, journal and apply a complete signed policy/entitlement response.
    pub fn apply_pull_response(
        &mut self,
        prepared: &PreparedRequest,
        response: &[u8],
        receipt: &[u8],
    ) -> Result<PullApplyResult, FleetCoordinatorError> {
        if !prepared.operation.is_pull() || !matches!(prepared.source, PreparedSource::Pull) {
            return Err(FleetCoordinatorError::InvalidRequest);
        }
        if response.len() > MAX_PULL_RESPONSE_BYTES {
            return Err(FleetCoordinatorError::ResponseTooLarge);
        }
        let response_sha256 = sha256(response);
        let verified_receipt = self.verify_receipt(
            receipt,
            prepared.operation,
            &prepared.request_sha256,
            &response_sha256,
        )?;
        let parsed = self.parse_pull_response(prepared.operation, response)?;
        let document_count = parsed.document_count()?;
        let transaction = self
            .state
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let row = read_pending_pull(&transaction, prepared.operation)?
            .ok_or(FleetCoordinatorError::PullNotPending)?;
        validate_pending_pull(
            &row,
            &self.tenant_id,
            &self.device_id,
            &self.device_public_key,
        )?;
        if row.request != prepared.body || row.request_sha256 != prepared.request_sha256 {
            return Err(FleetCoordinatorError::InvalidRequest);
        }
        let receipt_admission = admit_receipt(&transaction, &verified_receipt)?;
        match row.state {
            0 => {
                let changed = transaction.execute(
                    "UPDATE fleet_coordinator_pulls
                     SET state = 1, response = ?2, receipt = ?3
                     WHERE operation = ?1 AND state = 0",
                    params![prepared.operation.database_name(), response, receipt],
                )?;
                if changed != 1 {
                    return Err(FleetCoordinatorError::StateCorrupt);
                }
            }
            1 if row.response.as_deref() == Some(response)
                && row.receipt.as_deref() == Some(receipt) => {}
            1 => return Err(FleetCoordinatorError::RecoveryRequired),
            _ => return Err(FleetCoordinatorError::StateCorrupt),
        }
        transaction.commit()?;
        self.apply_staged_pull(prepared.operation)?;
        harden_state_files(&self.state_path)?;
        Ok(PullApplyResult {
            documents_applied: document_count,
            receipt_admission,
        })
    }

    /// Return the bounded Desk/Rescue view. Cache corruption and incomplete
    /// application remove paid capability flags but retain safety paths.
    pub fn local_snapshot(
        &self,
        now_unix: u64,
        transport: TransportState,
    ) -> Result<LocalFleetSnapshot, FleetCoordinatorError> {
        let policy_pull = self.pull_status(FleetOperation::PolicyPull)?;
        let entitlement_pull = self.pull_status(FleetOperation::EntitlementPull)?;
        let recovery_required = matches!(policy_pull, PullStatus::RecoveryRequired)
            || matches!(entitlement_pull, PullStatus::RecoveryRequired);
        let pending_inventory = self.runtime.pending_count()?;
        let pending_audit = self.runtime.pending_audit_count()?;
        let mut capabilities = self.runtime.capabilities(now_unix);

        let policy = if matches!(policy_pull, PullStatus::RecoveryRequired) {
            capabilities.cached_policy = false;
            LocalPolicySnapshot {
                state: PolicyCacheState::Applying,
                cached_count: 0,
                applicable_count: 0,
            }
        } else {
            match self.runtime.load_policies() {
                Ok(policies) => {
                    let cached_count = bounded_count(policies.len())?;
                    let applicable_count = bounded_count(
                        policies
                            .iter()
                            .filter(|policy| {
                                policy.is_applicable_to(&self.device_id, now_unix, transport)
                            })
                            .count(),
                    )?;
                    LocalPolicySnapshot {
                        state: PolicyCacheState::Verified,
                        cached_count,
                        applicable_count,
                    }
                }
                Err(_) => {
                    capabilities.cached_policy = false;
                    LocalPolicySnapshot {
                        state: PolicyCacheState::Corrupt,
                        cached_count: 0,
                        applicable_count: 0,
                    }
                }
            }
        };
        if recovery_required {
            capabilities = degraded_capabilities();
        }
        let work_pending = pending_inventory != 0
            || pending_audit != 0
            || matches!(policy_pull, PullStatus::Pending)
            || matches!(entitlement_pull, PullStatus::Pending);
        Ok(LocalFleetSnapshot {
            sync_state: if recovery_required {
                LocalSyncState::RecoveryRequired
            } else if work_pending {
                LocalSyncState::WorkPending
            } else {
                LocalSyncState::Ready
            },
            pending_inventory,
            pending_audit,
            policy_pull,
            entitlement_pull,
            last_receipt_sequence: read_receipt_checkpoint(&self.state)?.map(|value| value.0),
            capabilities,
            policy,
        })
    }

    fn ensure_identity(&self, identity: &DeviceIdentity) -> Result<(), FleetCoordinatorError> {
        if identity.device_id() != self.device_id || identity.public_key() != self.device_public_key
        {
            return Err(FleetCoordinatorError::IdentityMismatch);
        }
        Ok(())
    }

    fn retain_pull(
        &mut self,
        operation: FleetOperation,
        request: Vec<u8>,
    ) -> Result<PreparedRequest, FleetCoordinatorError> {
        let candidate = PendingPullRow {
            operation,
            request_sha256: sha256(&request),
            request,
            state: 0,
            response: None,
            receipt: None,
        };
        validate_pending_pull(
            &candidate,
            &self.tenant_id,
            &self.device_id,
            &self.device_public_key,
        )?;
        let transaction = self
            .state
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        if let Some(existing) = read_pending_pull(&transaction, operation)? {
            validate_pending_pull(
                &existing,
                &self.tenant_id,
                &self.device_id,
                &self.device_public_key,
            )?;
            if existing.state == 1 {
                return Err(FleetCoordinatorError::RecoveryRequired);
            }
            if existing.request != candidate.request
                || existing.request_sha256 != candidate.request_sha256
            {
                return Err(FleetCoordinatorError::PullInFlight);
            }
            transaction.commit()?;
            return Ok(prepared_pull(operation, candidate.request));
        }
        transaction.execute(
            "INSERT INTO fleet_coordinator_pulls
             (operation, request, request_sha256, state, response, receipt)
             VALUES (?1, ?2, ?3, 0, NULL, NULL)",
            params![
                operation.database_name(),
                candidate.request,
                candidate.request_sha256.as_slice()
            ],
        )?;
        transaction.commit()?;
        harden_state_files(&self.state_path)?;
        Ok(prepared_pull(operation, candidate.request))
    }

    fn verify_receipt(
        &self,
        bytes: &[u8],
        operation: FleetOperation,
        request_sha256: &[u8; SHA256_BYTES],
        response_sha256: &[u8; SHA256_BYTES],
    ) -> Result<VerifiedServiceReceipt, FleetCoordinatorError> {
        if bytes.is_empty() || bytes.len() > MAX_RECEIPT_BYTES {
            return Err(FleetCoordinatorError::InvalidReceipt);
        }
        let receipt: SignedServiceReceipt =
            serde_json::from_slice(bytes).map_err(|_| FleetCoordinatorError::InvalidReceipt)?;
        if canonical_json(&receipt)? != bytes {
            return Err(FleetCoordinatorError::InvalidReceipt);
        }
        receipt.validate()?;
        if receipt.tenant_id != self.tenant_id
            || receipt.device_id != self.device_id
            || receipt.operation != operation
            || receipt.request_sha256 != hex_sha256(request_sha256)
            || receipt.response_sha256 != hex_sha256(response_sha256)
        {
            return Err(FleetCoordinatorError::InvalidReceipt);
        }
        let signature = decode_signature(&receipt.signature)?;
        let unsigned = canonical_json(&receipt.unsigned())?;
        let mut message =
            Vec::with_capacity(SERVICE_RECEIPT_SIGNATURE_DOMAIN.len() + unsigned.len());
        message.extend_from_slice(SERVICE_RECEIPT_SIGNATURE_DOMAIN);
        message.extend_from_slice(&unsigned);
        self.service_receipt_anchor
            .verify_strict(&message, &Signature::from_bytes(&signature))
            .map_err(|_| FleetCoordinatorError::InvalidReceipt)?;
        Ok(VerifiedServiceReceipt {
            sequence: receipt.sequence,
            digest: sha256(bytes),
        })
    }

    fn parse_pull_response(
        &self,
        operation: FleetOperation,
        bytes: &[u8],
    ) -> Result<ParsedPullResponse, FleetCoordinatorError> {
        match operation {
            FleetOperation::PolicyPull => {
                let response: PolicyPullResponse = serde_json::from_slice(bytes)
                    .map_err(|_| FleetCoordinatorError::InvalidResponse)?;
                if response.schema != "dev.kernaid.fleet.policy-pull-response.v1"
                    || response.tenant_id != self.tenant_id
                    || response.device_id != self.device_id
                    || response.items.len() > MAX_POLICY_ITEMS
                {
                    return Err(FleetCoordinatorError::InvalidResponse);
                }
                let mut documents = Vec::with_capacity(response.items.len());
                let mut policy_ids = Vec::with_capacity(response.items.len());
                for item in response.items {
                    let document = canonical_value_bytes(&item)?;
                    let verified = SignedPolicyBundle::import_and_verify(
                        &document,
                        &self.policy_anchor,
                        &self.tenant_id,
                    )?;
                    if !verified.applies_to_device(&self.device_id) {
                        return Err(FleetCoordinatorError::InvalidResponse);
                    }
                    policy_ids.push(verified.policy_id().to_owned());
                    documents.push(document);
                }
                if !strictly_sorted(&policy_ids) {
                    return Err(FleetCoordinatorError::InvalidResponse);
                }
                Ok(ParsedPullResponse::Policies(documents))
            }
            FleetOperation::EntitlementPull => {
                let response: EntitlementPullResponse = serde_json::from_slice(bytes)
                    .map_err(|_| FleetCoordinatorError::InvalidResponse)?;
                if response.schema != "dev.kernaid.fleet.entitlement-pull-response.v1"
                    || response.tenant_id != self.tenant_id
                    || response.device_id != self.device_id
                    || response.entitlements.len() > MAX_ENTITLEMENT_ITEMS
                {
                    return Err(FleetCoordinatorError::InvalidResponse);
                }
                let entitlement = response
                    .entitlements
                    .first()
                    .map(|value| -> Result<Vec<u8>, FleetCoordinatorError> {
                        let document = canonical_value_bytes(value)?;
                        let verified =
                            verify_entitlement(&document, &self.entitlement_anchor, None)?;
                        if verified.envelope.claims.tenant_id != self.tenant_id
                            || verified
                                .envelope
                                .claims
                                .device_ids
                                .binary_search(&self.device_id)
                                .is_err()
                        {
                            return Err(FleetCoordinatorError::InvalidResponse);
                        }
                        Ok(document)
                    })
                    .transpose()?;
                let revocations = response
                    .revocations
                    .as_ref()
                    .map(|value| -> Result<Vec<u8>, FleetCoordinatorError> {
                        let document = canonical_value_bytes(value)?;
                        verify_revocations(&document, &self.entitlement_anchor, None)?;
                        Ok(document)
                    })
                    .transpose()?;
                Ok(ParsedPullResponse::Entitlements {
                    entitlement,
                    revocations,
                })
            }
            FleetOperation::Inventory | FleetOperation::Audit => {
                Err(FleetCoordinatorError::InvalidRequest)
            }
        }
    }

    fn apply_staged_pull(
        &mut self,
        operation: FleetOperation,
    ) -> Result<(), FleetCoordinatorError> {
        let row = read_pending_pull(&self.state, operation)?
            .ok_or(FleetCoordinatorError::PullNotPending)?;
        validate_pending_pull(
            &row,
            &self.tenant_id,
            &self.device_id,
            &self.device_public_key,
        )?;
        if row.state != 1 {
            return Err(FleetCoordinatorError::PullNotPending);
        }
        let response = row
            .response
            .as_deref()
            .ok_or(FleetCoordinatorError::StateCorrupt)?;
        let receipt = row
            .receipt
            .as_deref()
            .ok_or(FleetCoordinatorError::StateCorrupt)?;
        let verified =
            self.verify_receipt(receipt, operation, &row.request_sha256, &sha256(response))?;
        let checkpoint =
            read_receipt_checkpoint(&self.state)?.ok_or(FleetCoordinatorError::StateCorrupt)?;
        if checkpoint.0 < verified.sequence
            || (checkpoint.0 == verified.sequence && checkpoint.1 != verified.digest)
        {
            return Err(FleetCoordinatorError::StateCorrupt);
        }
        match self.parse_pull_response(operation, response)? {
            ParsedPullResponse::Policies(documents) => {
                for document in documents {
                    self.runtime.apply_policy(&document)?;
                }
            }
            ParsedPullResponse::Entitlements {
                entitlement,
                revocations,
            } => {
                if let Some(document) = entitlement {
                    self.runtime.apply_entitlement(&document)?;
                }
                if let Some(document) = revocations {
                    self.runtime.apply_revocations(&document)?;
                }
            }
        }
        let changed = self.state.execute(
            "DELETE FROM fleet_coordinator_pulls
             WHERE operation = ?1 AND state = 1 AND request_sha256 = ?2",
            params![operation.database_name(), row.request_sha256.as_slice()],
        )?;
        if changed != 1 {
            return Err(FleetCoordinatorError::StateCorrupt);
        }
        Ok(())
    }

    fn recover_staged_pulls(&mut self) -> Result<(), FleetCoordinatorError> {
        let operations = {
            let mut statement = self.state.prepare(
                "SELECT operation FROM fleet_coordinator_pulls
                 WHERE state = 1 ORDER BY operation",
            )?;
            let rows = statement.query_map([], |row| row.get::<_, String>(0))?;
            let mut operations = Vec::new();
            for row in rows {
                operations.push(FleetOperation::from_database_name(&row?)?);
            }
            operations
        };
        for operation in operations {
            self.apply_staged_pull(operation)?;
        }
        Ok(())
    }

    fn pull_status(&self, operation: FleetOperation) -> Result<PullStatus, FleetCoordinatorError> {
        Ok(match read_pending_pull(&self.state, operation)? {
            None => PullStatus::Idle,
            Some(row) if row.state == 0 => PullStatus::Pending,
            Some(row) if row.state == 1 => PullStatus::RecoveryRequired,
            Some(_) => return Err(FleetCoordinatorError::StateCorrupt),
        })
    }
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

    fn validate(&self) -> Result<(), FleetCoordinatorError> {
        if self.schema != SERVICE_RECEIPT_SCHEMA
            || !valid_identifier(&self.tenant_id)
            || !valid_identifier(&self.device_id)
            || self.sequence == 0
            || self.sequence > MAX_SAFE_JSON_INTEGER
            || !valid_sha256(&self.request_sha256)
            || !valid_sha256(&self.response_sha256)
            || self.accepted_at.is_empty()
            || self.accepted_at.len() > MAX_TIMESTAMP_BYTES
            || DateTime::parse_from_rfc3339(&self.accepted_at).is_err()
        {
            return Err(FleetCoordinatorError::InvalidReceipt);
        }
        decode_signature(&self.signature)?;
        Ok(())
    }
}

impl ParsedPullResponse {
    fn document_count(&self) -> Result<u16, FleetCoordinatorError> {
        let count = match self {
            Self::Policies(documents) => documents.len(),
            Self::Entitlements {
                entitlement,
                revocations,
            } => usize::from(entitlement.is_some()) + usize::from(revocations.is_some()),
        };
        bounded_count(count)
    }
}

fn prepared_pull(operation: FleetOperation, body: Vec<u8>) -> PreparedRequest {
    PreparedRequest {
        operation,
        request_sha256: sha256(&body),
        body,
        source: PreparedSource::Pull,
    }
}

fn validate_pending_pull(
    row: &PendingPullRow,
    tenant_id: &str,
    device_id: &str,
    public_key: &[u8; 32],
) -> Result<(), FleetCoordinatorError> {
    if !row.operation.is_pull()
        || row.request.is_empty()
        || row.request_sha256 != sha256(&row.request)
        || !matches!(row.state, 0 | 1)
        || (row.state == 0 && (row.response.is_some() || row.receipt.is_some()))
        || (row.state == 1 && (row.response.is_none() || row.receipt.is_none()))
    {
        return Err(FleetCoordinatorError::StateCorrupt);
    }
    match row.operation {
        FleetOperation::PolicyPull => {
            SignedPolicyPullRequest::import_offline(
                &row.request,
                tenant_id,
                device_id,
                public_key,
            )?;
        }
        FleetOperation::EntitlementPull => {
            SignedEntitlementPullRequest::import_offline(
                &row.request,
                tenant_id,
                device_id,
                public_key,
            )?;
        }
        FleetOperation::Inventory | FleetOperation::Audit => {
            return Err(FleetCoordinatorError::StateCorrupt);
        }
    }
    Ok(())
}

fn read_pending_pull(
    connection: &Connection,
    operation: FleetOperation,
) -> Result<Option<PendingPullRow>, FleetCoordinatorError> {
    let row = connection
        .query_row(
            "SELECT operation, request, request_sha256, state, response, receipt
             FROM fleet_coordinator_pulls WHERE operation = ?1",
            [operation.database_name()],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, Vec<u8>>(1)?,
                    row.get::<_, Vec<u8>>(2)?,
                    row.get::<_, i64>(3)?,
                    row.get::<_, Option<Vec<u8>>>(4)?,
                    row.get::<_, Option<Vec<u8>>>(5)?,
                ))
            },
        )
        .optional()?;
    row.map(|(operation, request, digest, state, response, receipt)| {
        let request_sha256 = digest
            .try_into()
            .map_err(|_| FleetCoordinatorError::StateCorrupt)?;
        Ok(PendingPullRow {
            operation: FleetOperation::from_database_name(&operation)?,
            request,
            request_sha256,
            state,
            response,
            receipt,
        })
    })
    .transpose()
}

fn admit_receipt(
    transaction: &Transaction<'_>,
    receipt: &VerifiedServiceReceipt,
) -> Result<ReceiptAdmission, FleetCoordinatorError> {
    match read_receipt_checkpoint(transaction)? {
        None => {
            transaction.execute(
                "INSERT INTO fleet_coordinator_receipt_checkpoint
                 (singleton, sequence, receipt_sha256) VALUES (1, ?1, ?2)",
                params![receipt.sequence, receipt.digest.as_slice()],
            )?;
            Ok(ReceiptAdmission::Advanced)
        }
        Some((sequence, _)) if receipt.sequence > sequence => {
            transaction.execute(
                "UPDATE fleet_coordinator_receipt_checkpoint
                 SET sequence = ?1, receipt_sha256 = ?2 WHERE singleton = 1",
                params![receipt.sequence, receipt.digest.as_slice()],
            )?;
            Ok(ReceiptAdmission::Advanced)
        }
        Some((sequence, digest)) if receipt.sequence == sequence && receipt.digest == digest => {
            Ok(ReceiptAdmission::IdempotentReplay)
        }
        Some((sequence, _)) if receipt.sequence < sequence => {
            Err(FleetCoordinatorError::ReceiptRollback)
        }
        Some(_) => Err(FleetCoordinatorError::ReceiptConflict),
    }
}

fn read_receipt_checkpoint(
    connection: &Connection,
) -> Result<Option<(u64, [u8; SHA256_BYTES])>, FleetCoordinatorError> {
    let row = connection
        .query_row(
            "SELECT sequence, receipt_sha256
             FROM fleet_coordinator_receipt_checkpoint WHERE singleton = 1",
            [],
            |row| Ok((row.get::<_, u64>(0)?, row.get::<_, Vec<u8>>(1)?)),
        )
        .optional()?;
    row.map(|(sequence, digest)| {
        if sequence == 0 || sequence > MAX_SAFE_JSON_INTEGER {
            return Err(FleetCoordinatorError::StateCorrupt);
        }
        Ok((
            sequence,
            digest
                .try_into()
                .map_err(|_| FleetCoordinatorError::StateCorrupt)?,
        ))
    })
    .transpose()
}

fn configure_state(connection: &Connection) -> Result<(), FleetCoordinatorError> {
    connection.busy_timeout(std::time::Duration::from_secs(5))?;
    connection.execute_batch(
        "PRAGMA foreign_keys = ON;
         PRAGMA trusted_schema = OFF;
         PRAGMA journal_mode = WAL;
         PRAGMA synchronous = FULL;",
    )?;
    Ok(())
}

fn initialize_or_validate_state(
    connection: &Connection,
    tenant_id: &str,
    device_id: &str,
) -> Result<(), FleetCoordinatorError> {
    let application_id: i64 =
        connection.query_row("PRAGMA application_id", [], |row| row.get(0))?;
    let user_version: i64 = connection.query_row("PRAGMA user_version", [], |row| row.get(0))?;
    if application_id == 0 && user_version == 0 {
        connection.execute_batch(
            "BEGIN IMMEDIATE;
             CREATE TABLE fleet_coordinator_identity (
               singleton INTEGER PRIMARY KEY CHECK(singleton = 1),
               tenant_id TEXT NOT NULL,
               device_id TEXT NOT NULL
             );
             CREATE TABLE fleet_coordinator_receipt_checkpoint (
               singleton INTEGER PRIMARY KEY CHECK(singleton = 1),
               sequence INTEGER NOT NULL CHECK(sequence > 0),
               receipt_sha256 BLOB NOT NULL CHECK(length(receipt_sha256) = 32)
             );
             CREATE TABLE fleet_coordinator_pulls (
               operation TEXT PRIMARY KEY
                 CHECK(operation IN ('policy_pull', 'entitlement_pull')),
               request BLOB NOT NULL,
               request_sha256 BLOB NOT NULL CHECK(length(request_sha256) = 32),
               state INTEGER NOT NULL CHECK(state IN (0, 1)),
               response BLOB,
               receipt BLOB,
               CHECK((state = 0 AND response IS NULL AND receipt IS NULL)
                  OR (state = 1 AND response IS NOT NULL AND receipt IS NOT NULL))
             );
             PRAGMA application_id = 1262569027;
             PRAGMA user_version = 1;",
        )?;
        connection.execute(
            "INSERT INTO fleet_coordinator_identity
             (singleton, tenant_id, device_id) VALUES (1, ?1, ?2)",
            params![tenant_id, device_id],
        )?;
        connection.execute_batch("COMMIT;")?;
    } else if application_id != APPLICATION_ID || user_version != SCHEMA_VERSION {
        return Err(FleetCoordinatorError::UnsupportedFormat);
    }
    let identity = connection
        .query_row(
            "SELECT tenant_id, device_id FROM fleet_coordinator_identity WHERE singleton = 1",
            [],
            |row| Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?)),
        )
        .optional()?;
    if identity.as_ref() != Some(&(tenant_id.to_owned(), device_id.to_owned())) {
        return Err(FleetCoordinatorError::IdentityMismatch);
    }
    let identity_rows: u64 = connection.query_row(
        "SELECT COUNT(*) FROM fleet_coordinator_identity",
        [],
        |row| row.get(0),
    )?;
    let checkpoint_rows: u64 = connection.query_row(
        "SELECT COUNT(*) FROM fleet_coordinator_receipt_checkpoint",
        [],
        |row| row.get(0),
    )?;
    let pull_rows: u64 =
        connection.query_row("SELECT COUNT(*) FROM fleet_coordinator_pulls", [], |row| {
            row.get(0)
        })?;
    if identity_rows != 1 || checkpoint_rows > 1 || pull_rows > 2 {
        return Err(FleetCoordinatorError::StateCorrupt);
    }
    Ok(())
}

fn prepare_state_path(path: &Path) -> Result<(), FleetCoordinatorError> {
    if path.as_os_str().is_empty() || path.file_name().is_none() {
        return Err(FleetCoordinatorError::InvalidPath);
    }
    let parent = path.parent().ok_or(FleetCoordinatorError::InvalidPath)?;
    if !parent.is_dir() {
        return Err(FleetCoordinatorError::InvalidPath);
    }
    let result = match fs::symlink_metadata(path) {
        Ok(metadata) => inspect_state_metadata(&metadata),
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            let mut options = OpenOptions::new();
            options.write(true).create_new(true);
            #[cfg(unix)]
            options.mode(0o600);
            options.open(path)?;
            inspect_state_metadata(&fs::symlink_metadata(path)?)
        }
        Err(error) => Err(error.into()),
    };
    result?;
    inspect_optional_sidecar(&sqlite_sidecar(path, "-wal"))?;
    inspect_optional_sidecar(&sqlite_sidecar(path, "-shm"))
}

fn inspect_state_metadata(metadata: &fs::Metadata) -> Result<(), FleetCoordinatorError> {
    if metadata.file_type().is_symlink() {
        return Err(FleetCoordinatorError::SymlinkRejected);
    }
    if !metadata.is_file() {
        return Err(FleetCoordinatorError::InvalidPath);
    }
    #[cfg(unix)]
    if metadata.permissions().mode() & 0o077 != 0 {
        return Err(FleetCoordinatorError::InsecurePermissions);
    }
    Ok(())
}

fn harden_state_files(path: &Path) -> Result<(), FleetCoordinatorError> {
    inspect_state_metadata(&fs::symlink_metadata(path)?)?;
    #[cfg(unix)]
    for candidate in [
        path.to_path_buf(),
        sqlite_sidecar(path, "-wal"),
        sqlite_sidecar(path, "-shm"),
    ] {
        match fs::symlink_metadata(&candidate) {
            Ok(metadata) => {
                if metadata.file_type().is_symlink() || !metadata.is_file() {
                    return Err(FleetCoordinatorError::SymlinkRejected);
                }
                fs::set_permissions(candidate, fs::Permissions::from_mode(0o600))?;
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(error) => return Err(error.into()),
        }
    }
    Ok(())
}

fn inspect_optional_sidecar(path: &Path) -> Result<(), FleetCoordinatorError> {
    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_symlink() || !metadata.is_file() => {
            Err(FleetCoordinatorError::SymlinkRejected)
        }
        Ok(_) => Ok(()),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error.into()),
    }
}

fn sqlite_sidecar(path: &Path, suffix: &str) -> PathBuf {
    let mut value = path.as_os_str().to_os_string();
    value.push(suffix);
    PathBuf::from(value)
}

fn degraded_capabilities() -> FleetCapabilities {
    FleetCapabilities {
        entitlement_state: FleetEntitlementState::Corrupt,
        diagnostics: true,
        report_export: true,
        rollback: true,
        consumer_repair: false,
        enterprise_repair: false,
        fleet_sync: false,
        cached_policy: false,
        audit_upload: false,
        updates: false,
        enterprise_providers: false,
    }
}

fn bounded_count(count: usize) -> Result<u16, FleetCoordinatorError> {
    u16::try_from(count).map_err(|_| FleetCoordinatorError::StateCorrupt)
}

fn valid_identifier(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= MAX_ID_BYTES
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b':' | b'-'))
}

fn valid_sha256(value: &str) -> bool {
    value.len() == SHA256_BYTES * 2
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
}

fn decode_signature(value: &str) -> Result<[u8; SIGNATURE_BYTES], FleetCoordinatorError> {
    let decoded = URL_SAFE_NO_PAD
        .decode(value)
        .map_err(|_| FleetCoordinatorError::InvalidReceipt)?;
    if URL_SAFE_NO_PAD.encode(&decoded) != value {
        return Err(FleetCoordinatorError::InvalidReceipt);
    }
    decoded
        .try_into()
        .map_err(|_| FleetCoordinatorError::InvalidReceipt)
}

fn canonical_json<T: Serialize>(value: &T) -> Result<Vec<u8>, FleetCoordinatorError> {
    let value = serde_json::to_value(value).map_err(|_| FleetCoordinatorError::InvalidResponse)?;
    validate_canonical_value(&value)?;
    serde_json::to_vec(&value).map_err(|_| FleetCoordinatorError::InvalidResponse)
}

fn canonical_value_bytes(value: &Value) -> Result<Vec<u8>, FleetCoordinatorError> {
    validate_canonical_value(value)?;
    serde_json::to_vec(value).map_err(|_| FleetCoordinatorError::InvalidResponse)
}

fn validate_canonical_value(value: &Value) -> Result<(), FleetCoordinatorError> {
    match value {
        Value::Null | Value::Bool(_) | Value::String(_) => Ok(()),
        Value::Number(number) => number
            .as_u64()
            .filter(|value| *value <= MAX_SAFE_JSON_INTEGER)
            .map(|_| ())
            .ok_or(FleetCoordinatorError::InvalidResponse),
        Value::Array(items) => items.iter().try_for_each(validate_canonical_value),
        Value::Object(fields) => fields.values().try_for_each(validate_canonical_value),
    }
}

fn sha256(bytes: &[u8]) -> [u8; SHA256_BYTES] {
    Sha256::digest(bytes).into()
}

fn hex_sha256(bytes: &[u8; SHA256_BYTES]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn strictly_sorted(values: &[String]) -> bool {
    values.windows(2).all(|pair| pair[0] < pair[1])
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};
    use kernaid_entitlements::{
        ENTITLEMENT_SCHEMA, EntitlementClaims, EntitlementLimits, Feature, Plan,
        REVOCATIONS_SCHEMA, RevocationClaims, sign_entitlement, sign_revocations,
    };
    use kernaid_fleet_client::{AssetArchitecture, AssetHealth, AssetPlatform, FindingCounts};
    use kernaid_fleet_policy::{
        Assignments, PolicyBundleContent, PolicyRules, ProviderMode, RiskLevel, UpdateRing,
    };
    use serde_json::json;
    use tempfile::TempDir;

    const TENANT: &str = "tenant-coordinator-1";
    const NOW: &str = "2026-08-31T12:30:45Z";

    struct Harness {
        _directory: TempDir,
        coordinator_path: PathBuf,
        runtime_path: PathBuf,
        identity: DeviceIdentity,
        service_key: SigningKey,
        entitlement_key: SigningKey,
        policy_key: SigningKey,
    }

    impl Harness {
        fn new() -> Self {
            let directory = tempfile::tempdir().expect("temporary coordinator directory");
            Self {
                coordinator_path: directory.path().join("coordinator.sqlite3"),
                runtime_path: directory.path().join("runtime.sqlite3"),
                _directory: directory,
                identity: DeviceIdentity::from_seed(&[0x42; 32]).expect("fixed identity"),
                service_key: SigningKey::from_bytes(&[0x31; 32]),
                entitlement_key: SigningKey::from_bytes(&[0x51; 32]),
                policy_key: SigningKey::from_bytes(&[0x61; 32]),
            }
        }

        fn open(&self) -> FleetCoordinator {
            FleetCoordinator::open(
                FleetCoordinatorConfig {
                    coordinator_state_path: &self.coordinator_path,
                    runtime_state_path: &self.runtime_path,
                    tenant_id: TENANT,
                    service_receipt_anchor: &self.service_key.verifying_key().to_bytes(),
                    entitlement_anchor: &self.entitlement_key.verifying_key().to_bytes(),
                    policy_anchor: &self.policy_key.verifying_key().to_bytes(),
                },
                &self.identity,
            )
            .expect("open coordinator")
        }
    }

    fn asset(id: &str) -> InventoryAsset {
        InventoryAsset::new(
            id,
            "ab".repeat(32),
            AssetPlatform::Linux,
            AssetArchitecture::X86_64,
            Some("Debian 13".to_owned()),
            AssetHealth::Healthy,
            FindingCounts::new(0, 0, 1),
            "cd".repeat(32),
        )
    }

    fn audit_draft(event_id: &str) -> AuditEventDraft {
        AuditEventDraft {
            session_id: "session-coordinator-1".to_owned(),
            event_id: event_id.to_owned(),
            occurred_at: NOW.to_owned(),
            kind: AuditKind::DiagnosticStarted,
            outcome: AuditOutcome::Started,
            risk: None,
            action_id: None,
            target_sha256: None,
            report_sha256: None,
            evidence_sha256: Vec::new(),
        }
    }

    fn policy_document(harness: &Harness, policy_id: &str, revision: u64) -> Vec<u8> {
        SignedPolicyBundle::sign(
            PolicyBundleContent {
                tenant_id: TENANT.to_owned(),
                policy_id: policy_id.to_owned(),
                revision,
                issued_at_unix: 1_000,
                not_before_unix: 1_100,
                offline_allowed_until_unix: 2_000,
                expires_at_unix: 3_000,
                assignments: Assignments::device_ids(vec![harness.identity.device_id()]),
                rules: PolicyRules {
                    max_risk: RiskLevel::R2,
                    local_approval_from: RiskLevel::R1,
                    allowed_action_ids: vec!["linux.fstab.disable-missing-uuid.v1".to_owned()],
                    denied_action_ids: Vec::new(),
                    allow_evidence_upload: false,
                    retention_days: 30,
                    provider_modes: vec![ProviderMode::Offline],
                    update_ring: UpdateRing::Stable,
                    emergency_rollback_always_allowed: true,
                },
            },
            &harness.policy_key,
        )
        .expect("sign policy")
        .export_canonical()
        .expect("export policy")
    }

    fn entitlement_document(harness: &Harness, sequence: u64) -> Vec<u8> {
        sign_entitlement(
            EntitlementClaims {
                schema: ENTITLEMENT_SCHEMA.to_owned(),
                entitlement_id: "ent_coordinator_001".to_owned(),
                tenant_id: TENANT.to_owned(),
                sequence,
                plan: Plan::Enterprise,
                features: vec![
                    Feature::Audit,
                    Feature::EnterpriseRepair,
                    Feature::Fleet,
                    Feature::Policy,
                    Feature::Updates,
                ],
                device_ids: vec![harness.identity.device_id()],
                limits: EntitlementLimits {
                    max_tool_devices: 4,
                    max_technicians: 8,
                    max_managed_assets: 1_000,
                },
                issued_at_unix: 1_000,
                not_before_unix: 1_000,
                offline_lease_until_unix: 2_000,
                expires_at_unix: 3_000,
                grace_until_unix: 4_000,
            },
            &harness.entitlement_key,
        )
        .expect("sign entitlement")
    }

    fn revocation_document(harness: &Harness, sequence: u64) -> Vec<u8> {
        sign_revocations(
            RevocationClaims {
                schema: REVOCATIONS_SCHEMA.to_owned(),
                sequence,
                issued_at_unix: 1_500,
                revoked_entitlement_ids: vec!["ent_coordinator_001".to_owned()],
            },
            &harness.entitlement_key,
        )
        .expect("sign revocations")
    }

    fn policy_response(harness: &Harness, document: &[u8]) -> Vec<u8> {
        serde_json::to_vec(&json!({
            "schema": "dev.kernaid.fleet.policy-pull-response.v1",
            "tenantId": TENANT,
            "deviceId": harness.identity.device_id(),
            "items": [serde_json::from_slice::<Value>(document).expect("policy value")]
        }))
        .expect("policy response")
    }

    fn entitlement_response(
        harness: &Harness,
        entitlement: &[u8],
        revocations: Option<&[u8]>,
    ) -> Vec<u8> {
        serde_json::to_vec(&json!({
            "schema": "dev.kernaid.fleet.entitlement-pull-response.v1",
            "tenantId": TENANT,
            "deviceId": harness.identity.device_id(),
            "entitlements": [serde_json::from_slice::<Value>(entitlement).expect("entitlement value")],
            "revocations": revocations.map(|document| serde_json::from_slice::<Value>(document).expect("revocation value"))
        }))
        .expect("entitlement response")
    }

    fn service_receipt(
        harness: &Harness,
        sequence: u64,
        prepared: &PreparedRequest,
        response: &[u8],
    ) -> Vec<u8> {
        service_receipt_for_tenant(harness, sequence, prepared, response, TENANT)
    }

    fn service_receipt_for_tenant(
        harness: &Harness,
        sequence: u64,
        prepared: &PreparedRequest,
        response: &[u8],
        tenant_id: &str,
    ) -> Vec<u8> {
        let mut receipt = SignedServiceReceipt {
            schema: SERVICE_RECEIPT_SCHEMA.to_owned(),
            tenant_id: tenant_id.to_owned(),
            device_id: harness.identity.device_id(),
            operation: prepared.operation,
            sequence,
            request_sha256: hex_sha256(&prepared.request_sha256),
            response_sha256: hex_sha256(&sha256(response)),
            accepted_at: NOW.to_owned(),
            outcome: ReceiptOutcome::Accepted,
            signature: String::new(),
        };
        let unsigned = canonical_json(&receipt.unsigned()).expect("canonical receipt content");
        let mut message = SERVICE_RECEIPT_SIGNATURE_DOMAIN.to_vec();
        message.extend_from_slice(&unsigned);
        receipt.signature = URL_SAFE_NO_PAD.encode(harness.service_key.sign(&message).to_bytes());
        canonical_json(&receipt).expect("canonical signed receipt")
    }

    fn prepare_policy(coordinator: &mut FleetCoordinator, harness: &Harness) -> PreparedRequest {
        coordinator
            .prepare_policy_pull(
                &harness.identity,
                PolicyPullRequestInput::new(TENANT, NOW, vec![0xa5; 32]),
            )
            .expect("prepare policy pull")
    }

    fn prepare_entitlement(
        coordinator: &mut FleetCoordinator,
        harness: &Harness,
    ) -> PreparedRequest {
        coordinator
            .prepare_entitlement_pull(
                &harness.identity,
                EntitlementPullRequestInput::new(TENANT, NOW, vec![0xb5; 32]),
            )
            .expect("prepare entitlement pull")
    }

    #[test]
    fn inventory_survives_restart_and_only_valid_receipt_acknowledges() {
        let harness = Harness::new();
        let mut coordinator = harness.open();
        coordinator
            .queue_inventory(&harness.identity, NOW, vec![asset("asset-01")])
            .expect("queue inventory");
        let first = coordinator
            .ready_inventory(0, 1)
            .expect("ready inventory")
            .remove(0);
        let first_body = first.body.clone();
        drop(coordinator);

        let mut coordinator = harness.open();
        let prepared = coordinator
            .ready_inventory(0, 1)
            .expect("ready after restart")
            .remove(0);
        assert_eq!(prepared.body(), first_body);
        let response = br#"{"accepted":true}"#;
        let receipt = service_receipt(&harness, 1, &prepared, response);
        assert!(matches!(
            coordinator.accept_upload_receipt(&prepared, br#"{"accepted":false}"#, &receipt),
            Err(FleetCoordinatorError::InvalidReceipt)
        ));
        assert_eq!(coordinator.runtime.pending_count().expect("pending"), 1);
        assert_eq!(
            coordinator
                .accept_upload_receipt(&prepared, response, &receipt)
                .expect("accept receipt"),
            ReceiptAdmission::Advanced
        );
        assert_eq!(coordinator.runtime.pending_count().expect("empty"), 0);
    }

    #[test]
    fn audit_outbox_is_acknowledged_only_after_bound_receipt() {
        let harness = Harness::new();
        let mut coordinator = harness.open();
        coordinator
            .enqueue_audit(&harness.identity, audit_draft("event-01"))
            .expect("enqueue audit");
        let prepared = coordinator.ready_audit(1).expect("ready audit").remove(0);
        let response = br#"{"accepted":true}"#;
        let mut receipt = service_receipt(&harness, 1, &prepared, response);
        let last = receipt.len() - 2;
        receipt[last] = if receipt[last] == b'A' { b'B' } else { b'A' };
        assert!(
            coordinator
                .accept_upload_receipt(&prepared, response, &receipt)
                .is_err()
        );
        assert_eq!(
            coordinator.runtime.pending_audit_count().expect("pending"),
            1
        );

        let receipt = service_receipt(&harness, 1, &prepared, response);
        assert_eq!(
            coordinator
                .accept_upload_receipt(&prepared, response, &receipt)
                .expect("valid audit receipt"),
            ReceiptAdmission::Advanced
        );
        assert_eq!(coordinator.runtime.pending_audit_count().expect("empty"), 0);
        assert_eq!(
            coordinator
                .accept_upload_receipt(&prepared, response, &receipt)
                .expect("exact receipt replay"),
            ReceiptAdmission::IdempotentReplay
        );
    }

    #[test]
    fn pending_pull_survives_restart_and_blocks_nonce_replacement() {
        let harness = Harness::new();
        let mut coordinator = harness.open();
        let first = prepare_policy(&mut coordinator, &harness);
        drop(coordinator);

        let mut coordinator = harness.open();
        let recovered = coordinator
            .pending_pull(FleetOperation::PolicyPull)
            .expect("read pending")
            .expect("pending pull");
        assert_eq!(recovered.body(), first.body());
        assert!(matches!(
            coordinator.prepare_policy_pull(
                &harness.identity,
                PolicyPullRequestInput::new(TENANT, NOW, vec![0xc5; 32]),
            ),
            Err(FleetCoordinatorError::PullInFlight)
        ));
        coordinator
            .abandon_pull(FleetOperation::PolicyPull, first.request_sha256())
            .expect("abandon exact request");
        let replacement = coordinator
            .prepare_policy_pull(
                &harness.identity,
                PolicyPullRequestInput::new(TENANT, NOW, vec![0xc5; 32]),
            )
            .expect("fresh request");
        assert_ne!(replacement.request_sha256(), first.request_sha256());
    }

    #[test]
    fn signed_policy_response_advances_cache_and_snapshot() {
        let harness = Harness::new();
        let mut coordinator = harness.open();
        let prepared = prepare_policy(&mut coordinator, &harness);
        let document = policy_document(&harness, "policy-alpha", 1);
        let response = policy_response(&harness, &document);
        let receipt = service_receipt(&harness, 1, &prepared, &response);
        let applied = coordinator
            .apply_pull_response(&prepared, &response, &receipt)
            .expect("apply policy response");
        assert_eq!(applied.documents_applied, 1);
        let snapshot = coordinator
            .local_snapshot(1_500, TransportState::Online)
            .expect("snapshot");
        assert_eq!(snapshot.policy.state, PolicyCacheState::Verified);
        assert_eq!(snapshot.policy.cached_count, 1);
        assert_eq!(snapshot.policy.applicable_count, 1);
        assert_eq!(snapshot.policy_pull, PullStatus::Idle);
        assert_eq!(snapshot.last_receipt_sequence, Some(1));
    }

    #[test]
    fn truncated_or_unknown_pull_response_never_mutates_cache() {
        let harness = Harness::new();
        let mut coordinator = harness.open();
        let prepared = prepare_policy(&mut coordinator, &harness);
        let partial = br#"{"deviceId":"cut"#;
        let receipt = service_receipt(&harness, 1, &prepared, partial);
        assert!(matches!(
            coordinator.apply_pull_response(&prepared, partial, &receipt),
            Err(FleetCoordinatorError::InvalidResponse)
        ));
        assert!(
            coordinator
                .runtime
                .load_policies()
                .expect("policies")
                .is_empty()
        );

        let unknown = serde_json::to_vec(&json!({
            "schema": "dev.kernaid.fleet.policy-pull-response.v1",
            "tenantId": TENANT,
            "deviceId": harness.identity.device_id(),
            "items": [],
            "rawDiagnostics": "forbidden"
        }))
        .expect("unknown response");
        let receipt = service_receipt(&harness, 1, &prepared, &unknown);
        assert!(matches!(
            coordinator.apply_pull_response(&prepared, &unknown, &receipt),
            Err(FleetCoordinatorError::InvalidResponse)
        ));
        assert_eq!(
            coordinator
                .pending_pull(FleetOperation::PolicyPull)
                .expect("pending")
                .expect("request remains")
                .body(),
            prepared.body()
        );
    }

    #[test]
    fn receipt_checkpoint_rejects_rollback_conflict_and_cross_tenant() {
        let harness = Harness::new();
        let mut coordinator = harness.open();
        coordinator
            .queue_inventory(
                &harness.identity,
                NOW,
                vec![asset("asset-01"), asset("asset-02")],
            )
            .expect("queue batch");
        let mut prepared = coordinator.ready_inventory(0, 2).expect("ready batch");
        let first = prepared.remove(0);
        let second = prepared.remove(0);
        let response = br#"{"accepted":true}"#;
        let receipt = service_receipt(&harness, 2, &first, response);
        coordinator
            .accept_upload_receipt(&first, response, &receipt)
            .expect("advance receipt checkpoint");

        let rollback = service_receipt(&harness, 1, &second, response);
        assert!(matches!(
            coordinator.accept_upload_receipt(&second, response, &rollback),
            Err(FleetCoordinatorError::ReceiptRollback)
        ));
        let conflict = service_receipt(&harness, 2, &second, response);
        assert!(matches!(
            coordinator.accept_upload_receipt(&second, response, &conflict),
            Err(FleetCoordinatorError::ReceiptConflict)
        ));
        let cross_tenant =
            service_receipt_for_tenant(&harness, 3, &second, response, "tenant-other");
        assert!(matches!(
            coordinator.accept_upload_receipt(&second, response, &cross_tenant),
            Err(FleetCoordinatorError::InvalidReceipt)
        ));
        assert_eq!(coordinator.runtime.pending_count().expect("one pending"), 1);
    }

    #[test]
    fn entitlement_and_revocation_response_fail_paid_features_closed() {
        let harness = Harness::new();
        let mut coordinator = harness.open();
        let prepared = prepare_entitlement(&mut coordinator, &harness);
        let entitlement = entitlement_document(&harness, 1);
        let revocations = revocation_document(&harness, 1);
        let response = entitlement_response(&harness, &entitlement, Some(&revocations));
        let receipt = service_receipt(&harness, 1, &prepared, &response);
        let applied = coordinator
            .apply_pull_response(&prepared, &response, &receipt)
            .expect("apply commercial documents");
        assert_eq!(applied.documents_applied, 2);
        let snapshot = coordinator
            .local_snapshot(1_500, TransportState::Online)
            .expect("snapshot");
        assert_eq!(
            snapshot.capabilities.entitlement_state,
            FleetEntitlementState::Licensed(kernaid_entitlements::EntitlementState::Revoked)
        );
        assert!(snapshot.capabilities.diagnostics);
        assert!(snapshot.capabilities.report_export);
        assert!(snapshot.capabilities.rollback);
        assert!(!snapshot.capabilities.enterprise_repair);
        assert!(!snapshot.capabilities.fleet_sync);
    }

    #[test]
    fn fully_journaled_response_recovers_on_open() {
        let harness = Harness::new();
        let mut coordinator = harness.open();
        let prepared = prepare_policy(&mut coordinator, &harness);
        let document = policy_document(&harness, "policy-recovery", 1);
        let response = policy_response(&harness, &document);
        let receipt = service_receipt(&harness, 1, &prepared, &response);
        let verified = coordinator
            .verify_receipt(
                &receipt,
                FleetOperation::PolicyPull,
                prepared.request_sha256(),
                &sha256(&response),
            )
            .expect("verify receipt");
        coordinator
            .parse_pull_response(FleetOperation::PolicyPull, &response)
            .expect("validate complete response");
        let transaction = coordinator
            .state
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .expect("stage transaction");
        admit_receipt(&transaction, &verified).expect("admit receipt");
        transaction
            .execute(
                "UPDATE fleet_coordinator_pulls
                 SET state = 1, response = ?2, receipt = ?3
                 WHERE operation = ?1",
                params![
                    FleetOperation::PolicyPull.database_name(),
                    response,
                    receipt
                ],
            )
            .expect("stage exact response");
        transaction.commit().expect("commit staged response");
        drop(coordinator);

        let coordinator = harness.open();
        assert!(
            coordinator
                .pending_pull(FleetOperation::PolicyPull)
                .expect("read pull")
                .is_none()
        );
        assert_eq!(
            coordinator
                .runtime
                .load_policies()
                .expect("recovered cache")
                .len(),
            1
        );
    }

    #[test]
    fn rollback_response_stays_recoverable_and_snapshot_degrades_safely() {
        let harness = Harness::new();
        let mut coordinator = harness.open();
        let newer = policy_document(&harness, "policy-rollback", 2);
        coordinator
            .runtime
            .apply_policy(&newer)
            .expect("seed newer policy");
        let prepared = prepare_policy(&mut coordinator, &harness);
        let older = policy_document(&harness, "policy-rollback", 1);
        let response = policy_response(&harness, &older);
        let receipt = service_receipt(&harness, 1, &prepared, &response);
        assert!(matches!(
            coordinator.apply_pull_response(&prepared, &response, &receipt),
            Err(FleetCoordinatorError::Runtime(_))
        ));
        let snapshot = coordinator
            .local_snapshot(1_500, TransportState::Online)
            .expect("degraded snapshot");
        assert_eq!(snapshot.sync_state, LocalSyncState::RecoveryRequired);
        assert!(snapshot.capabilities.diagnostics);
        assert!(snapshot.capabilities.report_export);
        assert!(snapshot.capabilities.rollback);
        assert!(!snapshot.capabilities.enterprise_repair);
        assert!(!snapshot.capabilities.cached_policy);
    }
}
