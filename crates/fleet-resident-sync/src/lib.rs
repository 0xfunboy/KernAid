#![forbid(unsafe_code)]
//! Off-default Linux Resident Fleet synchronization service.
//!
//! The core engine is transport-testable. The real HTTPS/keyring integration
//! is available only with the `linux-resident` feature.

use kernaid_device_identity::DeviceIdentity;
use kernaid_fleet_client::{
    EnrollmentPlatform, EnrollmentRequestInput, EntitlementPullRequestInput, InventoryAsset,
    PolicyPullRequestInput, SignedEnrollmentRequest,
};
use kernaid_fleet_coordinator::{
    FleetCoordinator, FleetCoordinatorError, FleetOperation, PreparedRequest,
};
use kernaid_fleet_policy::TransportState;
use serde::{Deserialize, Serialize};
use std::{
    error::Error,
    fmt,
    fs::{self, File, OpenOptions},
    io::{self, Write},
    path::{Path, PathBuf},
};

#[cfg(unix)]
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};

pub const CONFIG_SCHEMA: &str = "dev.kernaid.fleet.resident-sync-config.v1";
pub const ENROLLMENT_STATE_SCHEMA: &str = "dev.kernaid.fleet.resident-enrollment.v1";
pub const RESIDENT_IDENTITY_NAMESPACE: &str = "resident-v1";

const ENROLLMENT_ROUTE: &str = "/v1/enrollments";
const ENROLLMENT_STATE_FILE: &str = "enrollment-v1.json";
const ENROLLMENT_PENDING_FILE: &str = ".enrollment-v1.pending";
const MAX_CONFIG_BYTES: usize = 16 * 1024;
const MAX_ENROLLMENT_RESPONSE_BYTES: usize = 8 * 1024;
const MAX_UPLOAD_RESPONSE_BYTES: usize = 8 * 1024;
const MAX_PULL_RESPONSE_BYTES: usize = 4 * 1024 * 1024;
const MAX_REQUEST_BYTES: usize = 1024 * 1024;
const MIN_INTERVAL_SECONDS: u64 = 30;
const MAX_INTERVAL_SECONDS: u64 = 24 * 60 * 60;
const MIN_TIMEOUT_SECONDS: u64 = 1;
const MAX_CONNECT_TIMEOUT_SECONDS: u64 = 30;
const MAX_REQUEST_TIMEOUT_SECONDS: u64 = 120;
const MAX_BATCH_LIMIT: usize = 256;
const MAX_RETRY_DELAY_SECONDS: u64 = 24 * 60 * 60;

/// Strict public configuration. Enrollment token bytes live only in the
/// separate file named by `enrollment_token_file`.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ResidentSyncConfig {
    pub schema: String,
    pub endpoint: String,
    pub tenant_id: String,
    pub state_directory: PathBuf,
    pub service_receipt_anchor_file: PathBuf,
    pub entitlement_anchor_file: PathBuf,
    pub policy_anchor_file: PathBuf,
    pub enrollment_token_file: PathBuf,
    pub interval_seconds: u64,
    pub connect_timeout_seconds: u64,
    pub request_timeout_seconds: u64,
    pub batch_limit: usize,
    pub retry_delay_seconds: u64,
}

impl ResidentSyncConfig {
    pub fn parse(bytes: &[u8]) -> Result<Self, ResidentSyncError> {
        if bytes.is_empty() || bytes.len() > MAX_CONFIG_BYTES {
            return Err(ResidentSyncError::InvalidConfig);
        }
        let config: Self =
            serde_json::from_slice(bytes).map_err(|_| ResidentSyncError::InvalidConfig)?;
        config.validate()?;
        Ok(config)
    }

    fn validate(&self) -> Result<(), ResidentSyncError> {
        if self.schema != CONFIG_SCHEMA
            || !valid_https_origin(&self.endpoint)
            || !valid_identifier(&self.tenant_id)
            || !absolute_file_parent(&self.state_directory)
            || !absolute_file(&self.service_receipt_anchor_file)
            || !absolute_file(&self.entitlement_anchor_file)
            || !absolute_file(&self.policy_anchor_file)
            || !absolute_file(&self.enrollment_token_file)
            || !(MIN_INTERVAL_SECONDS..=MAX_INTERVAL_SECONDS).contains(&self.interval_seconds)
            || !(MIN_TIMEOUT_SECONDS..=MAX_CONNECT_TIMEOUT_SECONDS)
                .contains(&self.connect_timeout_seconds)
            || !(MIN_TIMEOUT_SECONDS..=MAX_REQUEST_TIMEOUT_SECONDS)
                .contains(&self.request_timeout_seconds)
            || self.connect_timeout_seconds > self.request_timeout_seconds
            || self.batch_limit == 0
            || self.batch_limit > MAX_BATCH_LIMIT
            || self.retry_delay_seconds == 0
            || self.retry_delay_seconds > MAX_RETRY_DELAY_SECONDS
        {
            return Err(ResidentSyncError::InvalidConfig);
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FleetRoute {
    Enrollment,
    Inventory,
    Audit,
    PolicyPull,
    EntitlementPull,
}

impl FleetRoute {
    #[must_use]
    pub const fn path(self) -> &'static str {
        match self {
            Self::Enrollment => ENROLLMENT_ROUTE,
            Self::Inventory => "/v1/inventories",
            Self::Audit => "/v1/audit-events",
            Self::PolicyPull => "/v1/policy-pulls",
            Self::EntitlementPull => "/v1/entitlement-pulls",
        }
    }

    const fn from_operation(operation: FleetOperation) -> Self {
        match operation {
            FleetOperation::Inventory => Self::Inventory,
            FleetOperation::Audit => Self::Audit,
            FleetOperation::PolicyPull => Self::PolicyPull,
            FleetOperation::EntitlementPull => Self::EntitlementPull,
        }
    }
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

/// Exact bounded HTTPS result. `receipt` contains decoded canonical receipt
/// bytes, never a bearer credential.
pub struct FleetTransportResponse {
    pub status: u16,
    pub body: Vec<u8>,
    pub receipt: Option<Vec<u8>>,
}

/// Closed Fleet-only transport surface. There is no arbitrary method or URL.
pub trait FleetTransport {
    fn origin(&self) -> &str;

    fn post(
        &mut self,
        route: FleetRoute,
        body: &[u8],
        max_response_bytes: usize,
    ) -> Result<FleetTransportResponse, TransportErrorCode>;
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ObservationTime {
    pub rfc3339: String,
    pub unix_seconds: u64,
}

/// Source of fresh clock, nonce and minimized local inventory observations.
pub trait ResidentObservationSource {
    fn now(&mut self) -> Result<ObservationTime, ResidentSyncError>;
    fn nonce(&mut self) -> Result<Vec<u8>, ResidentSyncError>;
    fn inventory(&mut self, identity: &DeviceIdentity)
    -> Result<InventoryAsset, ResidentSyncError>;
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EnrollmentOutcome {
    AlreadyEnrolled,
    NewlyEnrolled,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct CycleSummary {
    pub enrollment: Option<EnrollmentOutcome>,
    pub inventory_uploaded: u16,
    pub audit_uploaded: u16,
    pub policy_documents: u16,
    pub entitlement_documents: u16,
}

#[derive(Debug)]
pub enum ResidentSyncError {
    InvalidConfig,
    InvalidState,
    StateMismatch,
    IdentityUnavailable,
    EnrollmentRequired,
    EnrollmentRejected,
    HttpRejected,
    MissingReceipt,
    PayloadTooLarge,
    ClockUnavailable,
    NonceUnavailable,
    InventoryUnavailable,
    Transport(TransportErrorCode),
    Coordinator(FleetCoordinatorError),
    Client(kernaid_fleet_client::FleetClientError),
    Io(io::Error),
}

impl ResidentSyncError {
    #[must_use]
    pub const fn code(&self) -> &'static str {
        match self {
            Self::InvalidConfig => "config-invalid",
            Self::InvalidState => "state-invalid",
            Self::StateMismatch => "state-mismatch",
            Self::IdentityUnavailable => "identity-unavailable",
            Self::EnrollmentRequired => "enrollment-required",
            Self::EnrollmentRejected => "enrollment-rejected",
            Self::HttpRejected => "http-rejected",
            Self::MissingReceipt => "receipt-missing",
            Self::PayloadTooLarge => "payload-too-large",
            Self::ClockUnavailable => "clock-unavailable",
            Self::NonceUnavailable => "nonce-unavailable",
            Self::InventoryUnavailable => "inventory-unavailable",
            Self::Transport(code) => match code {
                TransportErrorCode::InvalidEndpoint => "transport-endpoint",
                TransportErrorCode::Connect => "transport-connect",
                TransportErrorCode::Timeout => "transport-timeout",
                TransportErrorCode::Tls => "transport-tls",
                TransportErrorCode::Protocol => "transport-protocol",
                TransportErrorCode::ResponseTooLarge => "transport-response-large",
            },
            Self::Coordinator(_) => "coordinator-failed",
            Self::Client(_) => "signing-failed",
            Self::Io(_) => "state-io",
        }
    }
}

impl fmt::Display for ResidentSyncError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.code())
    }
}

impl Error for ResidentSyncError {}

impl From<FleetCoordinatorError> for ResidentSyncError {
    fn from(value: FleetCoordinatorError) -> Self {
        Self::Coordinator(value)
    }
}

impl From<kernaid_fleet_client::FleetClientError> for ResidentSyncError {
    fn from(value: kernaid_fleet_client::FleetClientError) -> Self {
        Self::Client(value)
    }
}

impl From<io::Error> for ResidentSyncError {
    fn from(value: io::Error) -> Self {
        Self::Io(value)
    }
}

#[derive(Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct EnrollmentState {
    schema: String,
    endpoint: String,
    tenant_id: String,
    device_id: String,
    enrolled_at: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct EnrollmentResponse {
    schema: String,
    tenant_id: String,
    device_id: String,
    enrolled_at: String,
    accepted: bool,
}

struct EnrollmentJournal {
    directory: PathBuf,
    path: PathBuf,
}

impl EnrollmentJournal {
    fn new(directory: &Path) -> Self {
        Self {
            directory: directory.to_path_buf(),
            path: directory.join(ENROLLMENT_STATE_FILE),
        }
    }

    fn verify(
        &self,
        endpoint: &str,
        tenant_id: &str,
        device_id: &str,
    ) -> Result<bool, ResidentSyncError> {
        let bytes = match read_private_bounded(&self.path, MAX_ENROLLMENT_RESPONSE_BYTES) {
            Ok(bytes) => bytes,
            Err(ResidentSyncError::Io(error)) if error.kind() == io::ErrorKind::NotFound => {
                return Ok(false);
            }
            Err(error) => return Err(error),
        };
        let state: EnrollmentState =
            serde_json::from_slice(&bytes).map_err(|_| ResidentSyncError::InvalidState)?;
        let canonical = serde_json::to_vec(&state).map_err(|_| ResidentSyncError::InvalidState)?;
        if canonical != bytes
            || state.schema != ENROLLMENT_STATE_SCHEMA
            || state.endpoint != endpoint
            || state.tenant_id != tenant_id
            || state.device_id != device_id
            || chrono::DateTime::parse_from_rfc3339(&state.enrolled_at).is_err()
        {
            return Err(ResidentSyncError::StateMismatch);
        }
        Ok(true)
    }

    fn persist(&self, state: &EnrollmentState) -> Result<(), ResidentSyncError> {
        match fs::symlink_metadata(&self.path) {
            Ok(_) => return Err(ResidentSyncError::InvalidState),
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(error) => return Err(error.into()),
        }
        let bytes = serde_json::to_vec(state).map_err(|_| ResidentSyncError::InvalidState)?;
        let pending = self.directory.join(ENROLLMENT_PENDING_FILE);
        let mut options = OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        options.mode(0o600);
        let mut file = options.open(&pending)?;
        file.write_all(&bytes)?;
        file.sync_all()?;
        fs::rename(&pending, &self.path)?;
        File::open(&self.directory)?.sync_all()?;
        Ok(())
    }
}

/// One resident sync instance. The caller supplies an HTTPS implementation and
/// observation source; all durable protocol state remains in the coordinator.
pub struct ResidentSyncEngine<T, S> {
    coordinator: FleetCoordinator,
    identity: DeviceIdentity,
    transport: T,
    source: S,
    journal: EnrollmentJournal,
    tenant_id: String,
    batch_limit: usize,
    retry_delay_seconds: u64,
}

impl<T: FleetTransport, S: ResidentObservationSource> ResidentSyncEngine<T, S> {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        coordinator: FleetCoordinator,
        identity: DeviceIdentity,
        transport: T,
        source: S,
        state_directory: &Path,
        tenant_id: &str,
        batch_limit: usize,
        retry_delay_seconds: u64,
    ) -> Result<Self, ResidentSyncError> {
        if coordinator.tenant_id() != tenant_id
            || coordinator.device_id() != identity.device_id()
            || !valid_https_origin(transport.origin())
            || batch_limit == 0
            || batch_limit > MAX_BATCH_LIMIT
            || retry_delay_seconds == 0
            || retry_delay_seconds > MAX_RETRY_DELAY_SECONDS
        {
            return Err(ResidentSyncError::InvalidConfig);
        }
        Ok(Self {
            coordinator,
            identity,
            transport,
            source,
            journal: EnrollmentJournal::new(state_directory),
            tenant_id: tenant_id.to_owned(),
            batch_limit,
            retry_delay_seconds,
        })
    }

    pub fn ensure_enrolled(
        &mut self,
        enrollment_token: Option<&str>,
    ) -> Result<EnrollmentOutcome, ResidentSyncError> {
        if self.journal.verify(
            self.transport.origin(),
            &self.tenant_id,
            &self.identity.device_id(),
        )? {
            return Ok(EnrollmentOutcome::AlreadyEnrolled);
        }
        let token = enrollment_token.ok_or(ResidentSyncError::EnrollmentRequired)?;
        let now = self.source.now()?;
        let nonce = self.source.nonce()?;
        let request = SignedEnrollmentRequest::sign(
            &self.identity,
            EnrollmentRequestInput::new(
                token.to_owned(),
                self.tenant_id.clone(),
                EnrollmentPlatform::Linux,
                env!("CARGO_PKG_VERSION"),
                now.rfc3339,
                nonce,
            ),
        )?;
        let body = request.export_offline()?;
        let response = self.post(FleetRoute::Enrollment, &body, MAX_ENROLLMENT_RESPONSE_BYTES)?;
        if !matches!(response.status, 200 | 201) {
            return Err(ResidentSyncError::EnrollmentRejected);
        }
        let accepted: EnrollmentResponse = serde_json::from_slice(&response.body)
            .map_err(|_| ResidentSyncError::EnrollmentRejected)?;
        if accepted.schema != "dev.kernaid.fleet.enrollment-response.v1"
            || accepted.tenant_id != self.tenant_id
            || accepted.device_id != self.identity.device_id()
            || !accepted.accepted
            || chrono::DateTime::parse_from_rfc3339(&accepted.enrolled_at).is_err()
        {
            return Err(ResidentSyncError::EnrollmentRejected);
        }
        self.journal.persist(&EnrollmentState {
            schema: ENROLLMENT_STATE_SCHEMA.to_owned(),
            endpoint: self.transport.origin().to_owned(),
            tenant_id: self.tenant_id.clone(),
            device_id: self.identity.device_id(),
            enrolled_at: accepted.enrolled_at,
        })?;
        Ok(EnrollmentOutcome::NewlyEnrolled)
    }

    /// Run one bounded cycle. A missing receipt or failed channel leaves its
    /// durable work pending and stops the cycle without applying later data.
    pub fn run_cycle(
        &mut self,
        enrollment_token: Option<&str>,
    ) -> Result<CycleSummary, ResidentSyncError> {
        let enrollment = self.ensure_enrolled(enrollment_token)?;
        let now = self.source.now()?;
        let snapshot = self
            .coordinator
            .local_snapshot(now.unix_seconds, TransportState::Online)?;
        if snapshot.pending_inventory == 0 {
            let inventory = self.source.inventory(&self.identity)?;
            self.coordinator
                .queue_inventory(&self.identity, &now.rfc3339, vec![inventory])?;
        }
        let inventory_uploaded = self.upload_inventory(&now)?;
        let audit_uploaded = self.upload_audit()?;
        let policy_documents = self.pull_policy()?;
        let entitlement_documents = self.pull_entitlement()?;
        Ok(CycleSummary {
            enrollment: Some(enrollment),
            inventory_uploaded,
            audit_uploaded,
            policy_documents,
            entitlement_documents,
        })
    }

    #[must_use]
    pub fn coordinator(&self) -> &FleetCoordinator {
        &self.coordinator
    }

    fn upload_inventory(&mut self, now: &ObservationTime) -> Result<u16, ResidentSyncError> {
        let requests = self
            .coordinator
            .ready_inventory(now.unix_seconds, self.batch_limit)?;
        let mut uploaded = 0_u16;
        for request in requests {
            let response = match self.post_prepared(&request, MAX_UPLOAD_RESPONSE_BYTES) {
                Ok(response) if matches!(response.status, 200 | 201) => response,
                Ok(_) => {
                    self.coordinator.record_inventory_retry(
                        &request,
                        now.unix_seconds,
                        self.retry_delay_seconds,
                    )?;
                    return Err(ResidentSyncError::HttpRejected);
                }
                Err(error) => {
                    self.coordinator.record_inventory_retry(
                        &request,
                        now.unix_seconds,
                        self.retry_delay_seconds,
                    )?;
                    return Err(error);
                }
            };
            let receipt = response
                .receipt
                .as_deref()
                .ok_or(ResidentSyncError::MissingReceipt)?;
            self.coordinator
                .accept_upload_receipt(&request, &response.body, receipt)?;
            uploaded = uploaded
                .checked_add(1)
                .ok_or(ResidentSyncError::InvalidState)?;
        }
        Ok(uploaded)
    }

    fn upload_audit(&mut self) -> Result<u16, ResidentSyncError> {
        let requests = self.coordinator.ready_audit(self.batch_limit)?;
        let mut uploaded = 0_u16;
        for request in requests {
            let response = self.post_prepared(&request, MAX_UPLOAD_RESPONSE_BYTES)?;
            if !matches!(response.status, 200 | 201) {
                return Err(ResidentSyncError::HttpRejected);
            }
            let receipt = response
                .receipt
                .as_deref()
                .ok_or(ResidentSyncError::MissingReceipt)?;
            self.coordinator
                .accept_upload_receipt(&request, &response.body, receipt)?;
            uploaded = uploaded
                .checked_add(1)
                .ok_or(ResidentSyncError::InvalidState)?;
        }
        Ok(uploaded)
    }

    fn pull_policy(&mut self) -> Result<u16, ResidentSyncError> {
        let request = match self.coordinator.pending_pull(FleetOperation::PolicyPull)? {
            Some(request) => request,
            None => {
                let now = self.source.now()?;
                let nonce = self.source.nonce()?;
                self.coordinator.prepare_policy_pull(
                    &self.identity,
                    PolicyPullRequestInput::new(self.tenant_id.clone(), now.rfc3339, nonce),
                )?
            }
        };
        self.apply_pull(request)
    }

    fn pull_entitlement(&mut self) -> Result<u16, ResidentSyncError> {
        let request = match self
            .coordinator
            .pending_pull(FleetOperation::EntitlementPull)?
        {
            Some(request) => request,
            None => {
                let now = self.source.now()?;
                let nonce = self.source.nonce()?;
                self.coordinator.prepare_entitlement_pull(
                    &self.identity,
                    EntitlementPullRequestInput::new(self.tenant_id.clone(), now.rfc3339, nonce),
                )?
            }
        };
        self.apply_pull(request)
    }

    fn apply_pull(&mut self, request: PreparedRequest) -> Result<u16, ResidentSyncError> {
        let response = self.post_prepared(&request, MAX_PULL_RESPONSE_BYTES)?;
        if !matches!(response.status, 200 | 201) {
            if matches!(response.status, 401 | 409) {
                self.coordinator
                    .abandon_pull(request.operation(), request.request_sha256())?;
            }
            return Err(ResidentSyncError::HttpRejected);
        }
        let receipt = response
            .receipt
            .as_deref()
            .ok_or(ResidentSyncError::MissingReceipt)?;
        Ok(self
            .coordinator
            .apply_pull_response(&request, &response.body, receipt)?
            .documents_applied)
    }

    fn post_prepared(
        &mut self,
        request: &PreparedRequest,
        max_response_bytes: usize,
    ) -> Result<FleetTransportResponse, ResidentSyncError> {
        self.post(
            FleetRoute::from_operation(request.operation()),
            request.body(),
            max_response_bytes,
        )
    }

    fn post(
        &mut self,
        route: FleetRoute,
        body: &[u8],
        max_response_bytes: usize,
    ) -> Result<FleetTransportResponse, ResidentSyncError> {
        if body.is_empty() || body.len() > MAX_REQUEST_BYTES {
            return Err(ResidentSyncError::PayloadTooLarge);
        }
        let response = self
            .transport
            .post(route, body, max_response_bytes)
            .map_err(ResidentSyncError::Transport)?;
        if response.status < 100
            || response.status > 599
            || response.body.len() > max_response_bytes
            || response
                .receipt
                .as_ref()
                .is_some_and(|receipt| receipt.len() > MAX_UPLOAD_RESPONSE_BYTES)
        {
            return Err(ResidentSyncError::PayloadTooLarge);
        }
        Ok(response)
    }
}

fn read_private_bounded(path: &Path, limit: usize) -> Result<Vec<u8>, ResidentSyncError> {
    let metadata = fs::symlink_metadata(path)?;
    if !metadata.is_file() || metadata.file_type().is_symlink() {
        return Err(ResidentSyncError::InvalidState);
    }
    #[cfg(unix)]
    if metadata.permissions().mode() & 0o077 != 0 {
        return Err(ResidentSyncError::InvalidState);
    }
    let size = usize::try_from(metadata.len()).map_err(|_| ResidentSyncError::PayloadTooLarge)?;
    if size == 0 || size > limit {
        return Err(ResidentSyncError::PayloadTooLarge);
    }
    let bytes = fs::read(path)?;
    if bytes.len() != size {
        return Err(ResidentSyncError::InvalidState);
    }
    Ok(bytes)
}

fn valid_https_origin(value: &str) -> bool {
    let Some(authority) = value.strip_prefix("https://") else {
        return false;
    };
    let authority = authority.strip_suffix('/').unwrap_or(authority);
    !authority.is_empty()
        && authority.len() <= 255
        && !authority.contains(['/', '@', '?', '#', '\\'])
        && !authority.bytes().any(|byte| byte.is_ascii_whitespace())
}

fn valid_identifier(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b':' | b'-'))
}

fn absolute_file(path: &Path) -> bool {
    path.is_absolute() && path.file_name().is_some()
}

fn absolute_file_parent(path: &Path) -> bool {
    path.is_absolute() && path.file_name().is_some()
}

#[cfg(feature = "linux-resident")]
pub mod linux;

#[cfg(test)]
mod tests {
    use super::*;
    use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
    use ed25519_dalek::{Signer, SigningKey};
    use kernaid_fleet_client::{AssetArchitecture, AssetHealth, AssetPlatform, FindingCounts};
    use kernaid_fleet_coordinator::{
        AuditEventDraft, AuditKind, AuditOutcome, FleetCoordinatorConfig, PullStatus,
        SERVICE_RECEIPT_SCHEMA, SERVICE_RECEIPT_SIGNATURE_DOMAIN,
    };
    use serde_json::{Value, json};
    use sha2::{Digest, Sha256};
    use tempfile::TempDir;

    const TENANT: &str = "tenant-resident-1";
    const NOW: &str = "2026-08-31T12:30:45Z";
    const NOW_UNIX: u64 = 1_788_179_445;

    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    enum MockFault {
        None,
        MissingReceipt(FleetRoute),
        InvalidReceipt(FleetRoute),
        OversizedResponse(FleetRoute),
        Conflict(FleetRoute),
        InvalidEnrollment,
    }

    struct MockTransport {
        origin: String,
        tenant_id: String,
        device_id: String,
        signing_key: SigningKey,
        next_receipt_sequence: u64,
        fault: MockFault,
        routes: Vec<FleetRoute>,
    }

    impl MockTransport {
        fn new(origin: &str, device_id: &str, sequence: u64, fault: MockFault) -> Self {
            Self {
                origin: origin.to_owned(),
                tenant_id: TENANT.to_owned(),
                device_id: device_id.to_owned(),
                signing_key: SigningKey::from_bytes(&[0x31; 32]),
                next_receipt_sequence: sequence,
                fault,
                routes: Vec::new(),
            }
        }

        fn response_body(&self, route: FleetRoute) -> Vec<u8> {
            let value = match route {
                FleetRoute::Enrollment => json!({
                    "accepted": true,
                    "deviceId": self.device_id,
                    "enrolledAt": NOW,
                    "schema": "dev.kernaid.fleet.enrollment-response.v1",
                    "tenantId": self.tenant_id,
                }),
                FleetRoute::Inventory | FleetRoute::Audit => json!({"accepted": true}),
                FleetRoute::PolicyPull => json!({
                    "deviceId": self.device_id,
                    "items": [],
                    "schema": "dev.kernaid.fleet.policy-pull-response.v1",
                    "tenantId": self.tenant_id,
                }),
                FleetRoute::EntitlementPull => json!({
                    "deviceId": self.device_id,
                    "entitlements": [],
                    "revocations": null,
                    "schema": "dev.kernaid.fleet.entitlement-pull-response.v1",
                    "tenantId": self.tenant_id,
                }),
            };
            serde_json::to_vec(&value).expect("mock response serializes")
        }

        fn receipt(&mut self, route: FleetRoute, request: &[u8], response: &[u8]) -> Vec<u8> {
            let operation = match route {
                FleetRoute::Inventory => "inventory",
                FleetRoute::Audit => "audit",
                FleetRoute::PolicyPull => "policy_pull",
                FleetRoute::EntitlementPull => "entitlement_pull",
                FleetRoute::Enrollment => unreachable!("enrollment has no service receipt"),
            };
            let mut unsigned = json!({
                "acceptedAt": NOW,
                "deviceId": self.device_id,
                "operation": operation,
                "outcome": "accepted",
                "requestSha256": hex_sha256(request),
                "responseSha256": hex_sha256(response),
                "schema": SERVICE_RECEIPT_SCHEMA,
                "sequence": self.next_receipt_sequence,
                "tenantId": self.tenant_id,
            });
            self.next_receipt_sequence += 1;
            let canonical = serde_json::to_vec(&unsigned).expect("canonical receipt content");
            let mut message = SERVICE_RECEIPT_SIGNATURE_DOMAIN.to_vec();
            message.extend_from_slice(&canonical);
            let signature = URL_SAFE_NO_PAD.encode(self.signing_key.sign(&message).to_bytes());
            unsigned
                .as_object_mut()
                .expect("receipt object")
                .insert("signature".to_owned(), Value::String(signature));
            serde_json::to_vec(&unsigned).expect("canonical signed receipt")
        }
    }

    impl FleetTransport for MockTransport {
        fn origin(&self) -> &str {
            &self.origin
        }

        fn post(
            &mut self,
            route: FleetRoute,
            body: &[u8],
            max_response_bytes: usize,
        ) -> Result<FleetTransportResponse, TransportErrorCode> {
            self.routes.push(route);
            if self.fault == MockFault::OversizedResponse(route) {
                return Ok(FleetTransportResponse {
                    status: 200,
                    body: vec![b'x'; max_response_bytes + 1],
                    receipt: None,
                });
            }
            if self.fault == MockFault::Conflict(route) {
                return Ok(FleetTransportResponse {
                    status: 409,
                    body: b"{}".to_vec(),
                    receipt: None,
                });
            }
            let body_out =
                if route == FleetRoute::Enrollment && self.fault == MockFault::InvalidEnrollment {
                    serde_json::to_vec(&json!({
                        "accepted": true,
                        "deviceId": self.device_id,
                        "enrolledAt": NOW,
                        "schema": "dev.kernaid.fleet.enrollment-response.v1",
                        "tenantId": self.tenant_id,
                        "unexpected": "rejected"
                    }))
                    .expect("invalid mock response")
                } else {
                    self.response_body(route)
                };
            let receipt = if route == FleetRoute::Enrollment
                || self.fault == MockFault::MissingReceipt(route)
            {
                None
            } else {
                let mut receipt = self.receipt(route, body, &body_out);
                if self.fault == MockFault::InvalidReceipt(route) {
                    receipt[0] ^= 1;
                }
                Some(receipt)
            };
            Ok(FleetTransportResponse {
                status: if route == FleetRoute::Enrollment {
                    201
                } else {
                    200
                },
                body: body_out,
                receipt,
            })
        }
    }

    struct MockSource {
        nonce_byte: u8,
    }

    impl MockSource {
        const fn new() -> Self {
            Self { nonce_byte: 0xa1 }
        }
    }

    impl ResidentObservationSource for MockSource {
        fn now(&mut self) -> Result<ObservationTime, ResidentSyncError> {
            Ok(ObservationTime {
                rfc3339: NOW.to_owned(),
                unix_seconds: NOW_UNIX,
            })
        }

        fn nonce(&mut self) -> Result<Vec<u8>, ResidentSyncError> {
            let value = self.nonce_byte;
            self.nonce_byte = self.nonce_byte.wrapping_add(1);
            Ok(vec![value; 32])
        }

        fn inventory(
            &mut self,
            _identity: &DeviceIdentity,
        ) -> Result<InventoryAsset, ResidentSyncError> {
            Ok(InventoryAsset::new(
                "resident-self",
                "ab".repeat(32),
                AssetPlatform::Linux,
                AssetArchitecture::X86_64,
                Some("Debian 13".to_owned()),
                AssetHealth::Unknown,
                FindingCounts::new(0, 0, 0),
                "cd".repeat(32),
            ))
        }
    }

    struct Fixture {
        directory: TempDir,
        service_key: SigningKey,
        entitlement_key: SigningKey,
        policy_key: SigningKey,
    }

    impl Fixture {
        fn new() -> Self {
            Self {
                directory: tempfile::tempdir().expect("temporary state directory"),
                service_key: SigningKey::from_bytes(&[0x31; 32]),
                entitlement_key: SigningKey::from_bytes(&[0x51; 32]),
                policy_key: SigningKey::from_bytes(&[0x61; 32]),
            }
        }

        fn identity(&self) -> DeviceIdentity {
            DeviceIdentity::from_seed(&[0x42; 32]).expect("fixed identity")
        }

        fn open(&self, identity: &DeviceIdentity) -> FleetCoordinator {
            FleetCoordinator::open(
                FleetCoordinatorConfig {
                    coordinator_state_path: &self.directory.path().join("coordinator.sqlite3"),
                    runtime_state_path: &self.directory.path().join("runtime.sqlite3"),
                    tenant_id: TENANT,
                    service_receipt_anchor: &self.service_key.verifying_key().to_bytes(),
                    entitlement_anchor: &self.entitlement_key.verifying_key().to_bytes(),
                    policy_anchor: &self.policy_key.verifying_key().to_bytes(),
                },
                identity,
            )
            .expect("open coordinator")
        }

        fn engine(
            &self,
            origin: &str,
            receipt_sequence: u64,
            fault: MockFault,
        ) -> ResidentSyncEngine<MockTransport, MockSource> {
            let identity = self.identity();
            let device_id = identity.device_id();
            ResidentSyncEngine::new(
                self.open(&identity),
                identity,
                MockTransport::new(origin, &device_id, receipt_sequence, fault),
                MockSource::new(),
                self.directory.path(),
                TENANT,
                32,
                60,
            )
            .expect("create resident engine")
        }
    }

    fn audit_draft() -> AuditEventDraft {
        AuditEventDraft {
            session_id: "session-resident-1".to_owned(),
            event_id: "event-resident-1".to_owned(),
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

    fn hex_sha256(bytes: &[u8]) -> String {
        Sha256::digest(bytes)
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect()
    }

    #[test]
    fn complete_cycle_enrolls_uploads_and_survives_restart() {
        let fixture = Fixture::new();
        let identity = fixture.identity();
        let mut coordinator = fixture.open(&identity);
        coordinator
            .enqueue_audit(&identity, audit_draft())
            .expect("queue audit");
        let mut engine = ResidentSyncEngine::new(
            coordinator,
            identity,
            MockTransport::new(
                "https://fleet.example.test",
                &fixture.identity().device_id(),
                1,
                MockFault::None,
            ),
            MockSource::new(),
            fixture.directory.path(),
            TENANT,
            32,
            60,
        )
        .expect("create engine");

        let summary = engine
            .run_cycle(Some("enroll_test_secret_once"))
            .expect("complete first sync");
        assert_eq!(summary.enrollment, Some(EnrollmentOutcome::NewlyEnrolled));
        assert_eq!(summary.inventory_uploaded, 1);
        assert_eq!(summary.audit_uploaded, 1);
        assert_eq!(summary.policy_documents, 0);
        assert_eq!(summary.entitlement_documents, 0);
        assert_eq!(
            engine.transport.routes,
            vec![
                FleetRoute::Enrollment,
                FleetRoute::Inventory,
                FleetRoute::Audit,
                FleetRoute::PolicyPull,
                FleetRoute::EntitlementPull,
            ]
        );
        let snapshot = engine
            .coordinator()
            .local_snapshot(NOW_UNIX, TransportState::Online)
            .expect("snapshot");
        assert_eq!(snapshot.pending_inventory, 0);
        assert_eq!(snapshot.pending_audit, 0);
        assert_eq!(snapshot.last_receipt_sequence, Some(4));
        let enrollment = fs::read(fixture.directory.path().join(ENROLLMENT_STATE_FILE))
            .expect("enrollment journal");
        assert!(!String::from_utf8_lossy(&enrollment).contains("secret"));
        drop(engine);

        let mut restarted = fixture.engine("https://fleet.example.test", 5, MockFault::None);
        let second = restarted.run_cycle(None).expect("sync after restart");
        assert_eq!(second.enrollment, Some(EnrollmentOutcome::AlreadyEnrolled));
        assert_eq!(second.inventory_uploaded, 1);
        assert!(!restarted.transport.routes.contains(&FleetRoute::Enrollment));
    }

    #[test]
    fn missing_receipt_never_acknowledges_inventory() {
        let fixture = Fixture::new();
        let mut engine = fixture.engine(
            "https://fleet.example.test",
            1,
            MockFault::MissingReceipt(FleetRoute::Inventory),
        );
        let error = engine
            .run_cycle(Some("enroll_test_secret_once"))
            .expect_err("unsigned success must fail");
        assert!(matches!(error, ResidentSyncError::MissingReceipt));
        let snapshot = engine
            .coordinator()
            .local_snapshot(NOW_UNIX, TransportState::Online)
            .expect("snapshot");
        assert_eq!(snapshot.pending_inventory, 1);
    }

    #[test]
    fn invalid_receipt_keeps_pull_pending() {
        let fixture = Fixture::new();
        let mut engine = fixture.engine(
            "https://fleet.example.test",
            1,
            MockFault::InvalidReceipt(FleetRoute::PolicyPull),
        );
        let error = engine
            .run_cycle(Some("enroll_test_secret_once"))
            .expect_err("tampered receipt must fail");
        assert!(matches!(error, ResidentSyncError::Coordinator(_)));
        let snapshot = engine
            .coordinator()
            .local_snapshot(NOW_UNIX, TransportState::Online)
            .expect("snapshot");
        assert_eq!(snapshot.policy_pull, PullStatus::Pending);
    }

    #[test]
    fn rejected_pull_is_abandoned_without_applying_later_channels() {
        let fixture = Fixture::new();
        let mut engine = fixture.engine(
            "https://fleet.example.test",
            1,
            MockFault::Conflict(FleetRoute::PolicyPull),
        );
        let error = engine
            .run_cycle(Some("enroll_test_secret_once"))
            .expect_err("conflicted pull must fail");
        assert!(matches!(error, ResidentSyncError::HttpRejected));
        let snapshot = engine
            .coordinator()
            .local_snapshot(NOW_UNIX, TransportState::Online)
            .expect("snapshot");
        assert_eq!(snapshot.policy_pull, PullStatus::Idle);
        assert!(
            !engine
                .transport
                .routes
                .contains(&FleetRoute::EntitlementPull)
        );
    }

    #[test]
    fn enrollment_is_strict_bounded_and_never_journaled_on_failure() {
        for fault in [
            MockFault::InvalidEnrollment,
            MockFault::OversizedResponse(FleetRoute::Enrollment),
        ] {
            let fixture = Fixture::new();
            let mut engine = fixture.engine("https://fleet.example.test", 1, fault);
            assert!(
                engine
                    .ensure_enrolled(Some("enroll_test_secret_once"))
                    .is_err()
            );
            assert!(
                !fixture
                    .directory
                    .path()
                    .join(ENROLLMENT_STATE_FILE)
                    .exists()
            );
        }
    }

    #[test]
    fn enrollment_journal_binds_origin_tenant_and_identity() {
        let fixture = Fixture::new();
        let mut engine = fixture.engine("https://fleet.example.test", 1, MockFault::None);
        engine
            .ensure_enrolled(Some("enroll_test_secret_once"))
            .expect("enroll");
        drop(engine);

        let journal = EnrollmentJournal::new(fixture.directory.path());
        assert!(matches!(
            journal.verify(
                "https://fleet.example.test",
                "tenant-other",
                &fixture.identity().device_id()
            ),
            Err(ResidentSyncError::StateMismatch)
        ));
        assert!(matches!(
            journal.verify("https://fleet.example.test", TENANT, "KA-wrong-device"),
            Err(ResidentSyncError::StateMismatch)
        ));

        let mut changed_origin = fixture.engine("https://other.example.test", 1, MockFault::None);
        let error = changed_origin
            .ensure_enrolled(None)
            .expect_err("origin mismatch must fail");
        assert!(matches!(error, ResidentSyncError::StateMismatch));
    }

    #[test]
    fn config_rejects_http_unknown_fields_and_unbounded_values() {
        let valid = json!({
            "batchLimit": 32,
            "connectTimeoutSeconds": 10,
            "endpoint": "https://fleet.example.test",
            "enrollmentTokenFile": "/tmp/kernaid/enrollment-token",
            "entitlementAnchorFile": "/tmp/kernaid/entitlement.pub",
            "intervalSeconds": 300,
            "policyAnchorFile": "/tmp/kernaid/policy.pub",
            "requestTimeoutSeconds": 30,
            "retryDelaySeconds": 60,
            "schema": CONFIG_SCHEMA,
            "serviceReceiptAnchorFile": "/tmp/kernaid/service.pub",
            "stateDirectory": "/tmp/kernaid/state",
            "tenantId": TENANT,
        });
        assert!(
            ResidentSyncConfig::parse(&serde_json::to_vec(&valid).expect("valid config bytes"))
                .is_ok()
        );
        for invalid in [
            {
                let mut value = valid.clone();
                value["endpoint"] = json!("http://fleet.example.test");
                value
            },
            {
                let mut value = valid.clone();
                value["batchLimit"] = json!(MAX_BATCH_LIMIT + 1);
                value
            },
            {
                let mut value = valid.clone();
                value
                    .as_object_mut()
                    .expect("config object")
                    .insert("token".to_owned(), json!("must-not-be-here"));
                value
            },
        ] {
            assert!(
                ResidentSyncConfig::parse(
                    &serde_json::to_vec(&invalid).expect("invalid config bytes")
                )
                .is_err()
            );
        }
    }
}
