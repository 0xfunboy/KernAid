//! Installable, off-default Linux Resident service adapter.
//!
//! This module deliberately exposes only the three read-only Linux diagnostic
//! collectors. Rescue repair stays behind its existing Vault/Core/Broker
//! boundary and is never reachable through this systemd service.

use super::{
    LocalExecutionResult, LocalHandoffErrorCode, LocalWorkOrderHandoff, PreparedLocalExecution,
    ResidentPlatform, ResidentWorkOrderEngine, ResidentWorkOrderError, ResidentWorkOrderTransport,
    TransportErrorCode, WorkOrderAuthorization, WorkOrderCycleInput, WorkOrderCycleOutcome,
    WorkOrderTransportResponse,
};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use chrono::{SecondsFormat, Utc};
use fs2::FileExt as _;
use kernaid_device_identity::{DeviceIdentity, validate_device_id};
use kernaid_fleet_client::{LeasedWorkOrder, WorkOrderActionId, WorkOrderResultOutcome};
use kernaid_fleet_policy::{RiskLevel, TransportState};
use kernaid_fleet_runtime::{FleetRuntime, FleetRuntimeError};
use kernaid_linux_pack::{boot_critical_path, filesystem_health, storage_health};
use kernaid_native_secrets::NativeDeviceIdentityStore;
use rand_core::{OsRng, RngCore};
use reqwest::{
    Url,
    blocking::{Client, Response},
    header::{ACCEPT, CONTENT_LENGTH, CONTENT_TYPE, HeaderName},
    redirect::Policy,
};
use rustix::{
    fs::{self as rfs, AtFlags, CWD, FileType, Mode, OFlags},
    process,
};
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::{
    env,
    error::Error,
    ffi::OsStr,
    fmt,
    fs::{self, File, OpenOptions},
    io::{self, Read, Write},
    os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt},
    path::{Path, PathBuf},
    thread,
    time::Duration,
};
use zeroize::Zeroizing;

pub const SERVICE_CONFIG_SCHEMA: &str = "dev.kernaid.fleet.resident-work-order-service-config.v1";
pub const RESIDENT_IDENTITY_NAMESPACE: &str = "resident-v1";

const CLAIM_ROUTE: &str = "/v1/work-order-claims";
const RESULT_ROUTE: &str = "/v1/work-order-results";
const RECEIPT_HEADER: HeaderName = HeaderName::from_static("x-kernaid-fleet-receipt");
const SERVICE_LOCK_FILE: &str = ".resident-work-orders-v1.lock";
const WORK_ORDER_STATE_DIRECTORY: &str = "protocol";
const EXECUTION_STATE_DIRECTORY: &str = "diagnostics";
const EXECUTION_STATE_FILE: &str = "execution-v1.cjson";
const EXECUTION_PENDING_FILE: &str = ".execution-v1.pending";
const EXECUTION_STATE_SCHEMA: &str = "dev.kernaid.fleet.local-diagnostic-execution.v1";
const PLAN_DIGEST_DOMAIN: &[u8] = b"kernaid:fleet:local-diagnostic-plan:v1\0";
const TARGET_DIGEST_DOMAIN: &[u8] = b"kernaid:fleet:local-diagnostic-target:v1\0";
const MAX_CONFIG_BYTES: usize = 16 * 1024;
const MAX_ANCHOR_FILE_BYTES: usize = 128;
const MAX_REQUEST_BYTES: usize = 64 * 1024;
const MAX_RECEIPT_HEADER_BYTES: usize = 8 * 1024;
const MAX_EXECUTION_STATE_BYTES: usize = 8 * 1024;
const MAX_DIAGNOSTIC_BYTES: usize = 64 * 1024;
const MAX_ENDPOINT_BYTES: usize = 4 * 1024;
const MAX_IDENTIFIER_BYTES: usize = 160;
const MIN_INTERVAL_SECONDS: u64 = 30;
const MAX_INTERVAL_SECONDS: u64 = 24 * 60 * 60;
const MIN_BACKOFF_SECONDS: u64 = 1;
const MAX_BACKOFF_SECONDS: u64 = 60 * 60;
const MIN_TIMEOUT_SECONDS: u64 = 1;
const MAX_CONNECT_TIMEOUT_SECONDS: u64 = 30;
const MAX_REQUEST_TIMEOUT_SECONDS: u64 = 120;

/// Public, strict service configuration. It cannot contain a token, key,
/// command, executable path, action argument or writable target.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct LinuxWorkOrderServiceConfig {
    pub schema: String,
    pub endpoint: String,
    pub tenant_id: String,
    pub state_directory: PathBuf,
    pub runtime_state_file: PathBuf,
    pub service_receipt_anchor_file: PathBuf,
    pub entitlement_anchor_file: PathBuf,
    pub policy_anchor_file: PathBuf,
    pub interval_seconds: u64,
    pub minimum_backoff_seconds: u64,
    pub maximum_backoff_seconds: u64,
    pub connect_timeout_seconds: u64,
    pub request_timeout_seconds: u64,
    pub lease_seconds: u16,
}

impl LinuxWorkOrderServiceConfig {
    pub fn parse(bytes: &[u8]) -> Result<Self, LinuxWorkOrderServiceError> {
        if bytes.is_empty() || bytes.len() > MAX_CONFIG_BYTES {
            return Err(LinuxWorkOrderServiceError::InvalidConfig);
        }
        let config: Self =
            serde_json::from_slice(bytes).map_err(|_| LinuxWorkOrderServiceError::InvalidConfig)?;
        config.validate()?;
        Ok(config)
    }

    fn validate(&self) -> Result<(), LinuxWorkOrderServiceError> {
        if self.schema != SERVICE_CONFIG_SCHEMA
            || !valid_https_origin(&self.endpoint)
            || !valid_identifier(&self.tenant_id)
            || !absolute_directory(&self.state_directory)
            || !absolute_file(&self.runtime_state_file)
            || !absolute_file(&self.service_receipt_anchor_file)
            || !absolute_file(&self.entitlement_anchor_file)
            || !absolute_file(&self.policy_anchor_file)
            || !(MIN_INTERVAL_SECONDS..=MAX_INTERVAL_SECONDS).contains(&self.interval_seconds)
            || !(MIN_BACKOFF_SECONDS..=MAX_BACKOFF_SECONDS).contains(&self.minimum_backoff_seconds)
            || !(self.minimum_backoff_seconds..=MAX_BACKOFF_SECONDS)
                .contains(&self.maximum_backoff_seconds)
            || !(MIN_TIMEOUT_SECONDS..=MAX_CONNECT_TIMEOUT_SECONDS)
                .contains(&self.connect_timeout_seconds)
            || !(MIN_TIMEOUT_SECONDS..=MAX_REQUEST_TIMEOUT_SECONDS)
                .contains(&self.request_timeout_seconds)
            || self.connect_timeout_seconds > self.request_timeout_seconds
            || !(30..=900).contains(&self.lease_seconds)
        {
            return Err(LinuxWorkOrderServiceError::InvalidConfig);
        }
        let files = [
            &self.runtime_state_file,
            &self.service_receipt_anchor_file,
            &self.entitlement_anchor_file,
            &self.policy_anchor_file,
        ];
        for (index, file) in files.iter().enumerate() {
            if files[..index].contains(file) {
                return Err(LinuxWorkOrderServiceError::InvalidConfig);
            }
        }
        Ok(())
    }
}

#[derive(Debug)]
pub enum LinuxWorkOrderServiceError {
    InvalidConfig,
    InvalidState,
    IdentityUnavailable,
    ClockUnavailable,
    NonceUnavailable,
    Runtime(FleetRuntimeError),
    Resident(ResidentWorkOrderError),
    Io(io::Error),
}

impl LinuxWorkOrderServiceError {
    #[must_use]
    pub const fn code(&self) -> &'static str {
        match self {
            Self::InvalidConfig => "config-invalid",
            Self::InvalidState => "state-invalid",
            Self::IdentityUnavailable => "identity-unavailable",
            Self::ClockUnavailable => "clock-unavailable",
            Self::NonceUnavailable => "nonce-unavailable",
            Self::Runtime(_) => "runtime-unavailable",
            Self::Resident(error) => error.code(),
            Self::Io(_) => "io-failed",
        }
    }

    const fn transient(&self) -> bool {
        matches!(
            self,
            Self::Resident(ResidentWorkOrderError::Transport(
                TransportErrorCode::Connect
                    | TransportErrorCode::Timeout
                    | TransportErrorCode::Tls
                    | TransportErrorCode::Protocol
            )) | Self::Resident(ResidentWorkOrderError::HttpRejected)
        )
    }
}

impl fmt::Display for LinuxWorkOrderServiceError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.code())
    }
}

impl Error for LinuxWorkOrderServiceError {}

impl From<ResidentWorkOrderError> for LinuxWorkOrderServiceError {
    fn from(error: ResidentWorkOrderError) -> Self {
        Self::Resident(error)
    }
}

impl From<FleetRuntimeError> for LinuxWorkOrderServiceError {
    fn from(error: FleetRuntimeError) -> Self {
        Self::Runtime(error)
    }
}

impl From<io::Error> for LinuxWorkOrderServiceError {
    fn from(error: io::Error) -> Self {
        Self::Io(error)
    }
}

/// HTTPS-only implementation with two fixed POST routes. Redirects, proxies,
/// caller-selected paths and authorization headers are absent by construction.
pub struct HttpsWorkOrderTransport {
    client: Client,
    base: Url,
    origin: String,
}

impl HttpsWorkOrderTransport {
    pub fn new(
        endpoint: &str,
        connect_timeout_seconds: u64,
        request_timeout_seconds: u64,
    ) -> Result<Self, LinuxWorkOrderServiceError> {
        let base =
            strict_base_url(endpoint).map_err(|_| LinuxWorkOrderServiceError::InvalidConfig)?;
        let origin = base.origin().ascii_serialization();
        let _ = rustls::crypto::ring::default_provider().install_default();
        let client = Client::builder()
            .https_only(true)
            .no_proxy()
            .redirect(Policy::none())
            .connect_timeout(Duration::from_secs(connect_timeout_seconds))
            .timeout(Duration::from_secs(request_timeout_seconds))
            .user_agent(concat!(
                "KernAid-Fleet-Resident-Work-Orders/",
                env!("CARGO_PKG_VERSION")
            ))
            .build()
            .map_err(|_| LinuxWorkOrderServiceError::InvalidConfig)?;
        Ok(Self {
            client,
            base,
            origin,
        })
    }

    fn post(
        &self,
        route: &'static str,
        body: &[u8],
        maximum_response_bytes: usize,
    ) -> Result<WorkOrderTransportResponse, TransportErrorCode> {
        if body.is_empty()
            || body.len() > MAX_REQUEST_BYTES
            || maximum_response_bytes == 0
            || maximum_response_bytes > MAX_REQUEST_BYTES
        {
            return Err(TransportErrorCode::Protocol);
        }
        let url = self
            .base
            .join(route.trim_start_matches('/'))
            .map_err(|_| TransportErrorCode::InvalidEndpoint)?;
        if url.origin().ascii_serialization() != self.origin
            || url.path() != route
            || url.query().is_some()
            || url.fragment().is_some()
        {
            return Err(TransportErrorCode::InvalidEndpoint);
        }
        let response = self
            .client
            .post(url)
            .header(ACCEPT, "application/json")
            .header(CONTENT_TYPE, "application/json")
            .body(body.to_vec())
            .send()
            .map_err(map_reqwest_error)?;
        read_response(response, maximum_response_bytes)
    }
}

impl ResidentWorkOrderTransport for HttpsWorkOrderTransport {
    fn claim(
        &mut self,
        body: &[u8],
        maximum_response_bytes: usize,
    ) -> Result<WorkOrderTransportResponse, TransportErrorCode> {
        self.post(CLAIM_ROUTE, body, maximum_response_bytes)
    }

    fn submit_result(
        &mut self,
        body: &[u8],
        maximum_response_bytes: usize,
    ) -> Result<WorkOrderTransportResponse, TransportErrorCode> {
        self.post(RESULT_ROUTE, body, maximum_response_bytes)
    }
}

fn read_response(
    mut response: Response,
    maximum_response_bytes: usize,
) -> Result<WorkOrderTransportResponse, TransportErrorCode> {
    if response
        .headers()
        .get(CONTENT_LENGTH)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.parse::<u64>().ok())
        .is_some_and(|length| length > maximum_response_bytes as u64)
    {
        return Err(TransportErrorCode::ResponseTooLarge);
    }
    let receipt = response
        .headers()
        .get(&RECEIPT_HEADER)
        .map(decode_receipt_header)
        .transpose()?;
    let status = response.status().as_u16();
    let mut body = Vec::new();
    response
        .by_ref()
        .take((maximum_response_bytes as u64).saturating_add(1))
        .read_to_end(&mut body)
        .map_err(|_| TransportErrorCode::Protocol)?;
    if body.len() > maximum_response_bytes {
        return Err(TransportErrorCode::ResponseTooLarge);
    }
    Ok(WorkOrderTransportResponse {
        status,
        body,
        receipt,
    })
}

fn decode_receipt_header(
    value: &reqwest::header::HeaderValue,
) -> Result<Vec<u8>, TransportErrorCode> {
    let encoded = value.to_str().map_err(|_| TransportErrorCode::Protocol)?;
    if encoded.is_empty() || encoded.len() > MAX_RECEIPT_HEADER_BYTES * 2 {
        return Err(TransportErrorCode::Protocol);
    }
    let decoded = URL_SAFE_NO_PAD
        .decode(encoded)
        .map_err(|_| TransportErrorCode::Protocol)?;
    if decoded.is_empty()
        || decoded.len() > MAX_RECEIPT_HEADER_BYTES
        || URL_SAFE_NO_PAD.encode(&decoded) != encoded
    {
        return Err(TransportErrorCode::Protocol);
    }
    Ok(decoded)
}

fn map_reqwest_error(error: reqwest::Error) -> TransportErrorCode {
    if error.is_timeout() {
        TransportErrorCode::Timeout
    } else if error.is_connect() {
        TransportErrorCode::Connect
    } else if error.is_builder() {
        TransportErrorCode::InvalidEndpoint
    } else {
        TransportErrorCode::Protocol
    }
}

trait DiagnosticCollector {
    fn collect(&mut self, action: WorkOrderActionId) -> Result<Vec<u8>, LocalHandoffErrorCode>;
}

struct SystemDiagnosticCollector;

impl DiagnosticCollector for SystemDiagnosticCollector {
    fn collect(&mut self, action: WorkOrderActionId) -> Result<Vec<u8>, LocalHandoffErrorCode> {
        let bytes = match action {
            WorkOrderActionId::LinuxFilesystemHealthV1 => {
                filesystem_health::to_bounded_json(&filesystem_health::collect_current_root())
                    .map(String::into_bytes)
            }
            WorkOrderActionId::LinuxStorageHealthV1 => {
                storage_health::to_bounded_json(&storage_health::collect_current_machine())
                    .map(String::into_bytes)
            }
            WorkOrderActionId::LinuxBootCriticalPathV1 => {
                boot_critical_path::to_bounded_json(&boot_critical_path::collect_current_machine())
                    .map(String::into_bytes)
            }
            WorkOrderActionId::LinuxFstabDisableMissingUuidV1
            | WorkOrderActionId::LinuxCrypttabDisableMissingUuidV1
            | WorkOrderActionId::LinuxExt4FsckPreenWithUndoV1
            | WorkOrderActionId::LinuxNetworkRestoreResolverLinkV1 => {
                return Err(LocalHandoffErrorCode::StateMismatch);
            }
            WorkOrderActionId::WindowsP0DiagnoseV1 => {
                return Err(LocalHandoffErrorCode::StateMismatch);
            }
            WorkOrderActionId::MacosP0DiagnoseV1 => {
                return Err(LocalHandoffErrorCode::StateMismatch);
            }
        }
        .map_err(|_| LocalHandoffErrorCode::ExecutionFailed)?;
        if bytes.is_empty() || bytes.len() > MAX_DIAGNOSTIC_BYTES {
            return Err(LocalHandoffErrorCode::ExecutionFailed);
        }
        Ok(bytes)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "lowercase")]
enum ExecutionState {
    Pending,
    Completed,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct DiagnosticExecutionRecord {
    schema: String,
    execution_id: String,
    action_id: WorkOrderActionId,
    action_version: u16,
    plan_sha256: String,
    target_sha256: String,
    state: ExecutionState,
    result_sha256: Option<String>,
}

impl DiagnosticExecutionRecord {
    fn pending(prepared: &PreparedLocalExecution) -> Self {
        Self {
            schema: EXECUTION_STATE_SCHEMA.to_owned(),
            execution_id: prepared.execution_id().to_owned(),
            action_id: prepared.action_id(),
            action_version: prepared.action_version(),
            plan_sha256: prepared.plan_sha256().to_owned(),
            target_sha256: prepared.target_sha256().to_owned(),
            state: ExecutionState::Pending,
            result_sha256: None,
        }
    }

    fn validate(&self) -> Result<(), LocalHandoffErrorCode> {
        if self.schema != EXECUTION_STATE_SCHEMA
            || !valid_identifier(&self.execution_id)
            || !is_diagnostic(self.action_id)
            || self.action_version != self.action_id.metadata().version
            || !valid_sha256(&self.plan_sha256)
            || !valid_sha256(&self.target_sha256)
            || (self.state == ExecutionState::Pending && self.result_sha256.is_some())
            || (self.state == ExecutionState::Completed
                && self
                    .result_sha256
                    .as_deref()
                    .is_none_or(|value| !valid_sha256(value)))
        {
            return Err(LocalHandoffErrorCode::StateMismatch);
        }
        Ok(())
    }

    fn matches(&self, prepared: &PreparedLocalExecution) -> bool {
        self.execution_id == prepared.execution_id()
            && self.action_id == prepared.action_id()
            && self.action_version == prepared.action_version()
            && self.plan_sha256 == prepared.plan_sha256()
            && self.target_sha256 == prepared.target_sha256()
    }
}

/// Closed Linux handoff. Its durable cache stores only typed identifiers and
/// digests; diagnostic documents and tool output are never persisted here.
struct LinuxDiagnosticHandoff<C> {
    directory: PathBuf,
    device_id: String,
    collector: C,
}

impl LinuxDiagnosticHandoff<SystemDiagnosticCollector> {
    fn open(directory: &Path, device_id: &str) -> Result<Self, LinuxWorkOrderServiceError> {
        ensure_private_directory(directory)?;
        cleanup_temporary(&directory.join(EXECUTION_PENDING_FILE))?;
        validate_device_id(device_id).map_err(|_| LinuxWorkOrderServiceError::InvalidState)?;
        Ok(Self {
            directory: directory.to_path_buf(),
            device_id: device_id.to_owned(),
            collector: SystemDiagnosticCollector,
        })
    }
}

impl<C: DiagnosticCollector> LinuxDiagnosticHandoff<C> {
    #[cfg(test)]
    fn with_collector(directory: &Path, device_id: &str, collector: C) -> Self {
        Self {
            directory: directory.to_path_buf(),
            device_id: device_id.to_owned(),
            collector,
        }
    }

    fn read_record(&self) -> Result<Option<DiagnosticExecutionRecord>, LocalHandoffErrorCode> {
        let path = self.directory.join(EXECUTION_STATE_FILE);
        let bytes = match read_private_optional(&path, MAX_EXECUTION_STATE_BYTES)
            .map_err(|_| LocalHandoffErrorCode::StateMismatch)?
        {
            Some(bytes) => bytes,
            None => return Ok(None),
        };
        let record: DiagnosticExecutionRecord =
            import_canonical(&bytes).map_err(|_| LocalHandoffErrorCode::StateMismatch)?;
        record.validate()?;
        Ok(Some(record))
    }

    fn persist_record(
        &self,
        record: &DiagnosticExecutionRecord,
    ) -> Result<(), LocalHandoffErrorCode> {
        record.validate()?;
        let bytes = canonical_json(record).map_err(|_| LocalHandoffErrorCode::StateMismatch)?;
        if bytes.len() > MAX_EXECUTION_STATE_BYTES {
            return Err(LocalHandoffErrorCode::StateMismatch);
        }
        write_atomic(
            &self.directory,
            EXECUTION_STATE_FILE,
            EXECUTION_PENDING_FILE,
            &bytes,
        )
        .map_err(|_| LocalHandoffErrorCode::StateMismatch)
    }
}

impl<C: DiagnosticCollector> LocalWorkOrderHandoff for LinuxDiagnosticHandoff<C> {
    fn prepare(
        &mut self,
        order: &LeasedWorkOrder,
        execution_id: &str,
    ) -> Result<PreparedLocalExecution, LocalHandoffErrorCode> {
        if !is_diagnostic(order.action_id())
            || order.action_version() != order.action_id().metadata().version
            || order.local_approval_required()
            || order.approval().is_some()
        {
            return Err(LocalHandoffErrorCode::StateMismatch);
        }
        let version = order.action_version().to_string();
        let plan_sha256 = digest_fields(
            PLAN_DIGEST_DOMAIN,
            &[execution_id, order.action_id().wire_name(), &version],
        );
        let target_sha256 = digest_fields(
            TARGET_DIGEST_DOMAIN,
            &[&self.device_id, order.action_id().wire_name()],
        );
        Ok(PreparedLocalExecution::diagnostic(
            order,
            execution_id,
            plan_sha256,
            target_sha256,
        ))
    }

    fn execute_or_recover(
        &mut self,
        prepared: &PreparedLocalExecution,
    ) -> Result<LocalExecutionResult, LocalHandoffErrorCode> {
        if !is_diagnostic(prepared.action_id())
            || prepared.action_version() != prepared.action_id().metadata().version
            || prepared.local_approval().is_some()
        {
            return Err(LocalHandoffErrorCode::StateMismatch);
        }
        let version = prepared.action_version().to_string();
        if prepared.plan_sha256()
            != digest_fields(
                PLAN_DIGEST_DOMAIN,
                &[
                    prepared.execution_id(),
                    prepared.action_id().wire_name(),
                    &version,
                ],
            )
            || prepared.target_sha256()
                != digest_fields(
                    TARGET_DIGEST_DOMAIN,
                    &[&self.device_id, prepared.action_id().wire_name()],
                )
        {
            return Err(LocalHandoffErrorCode::StateMismatch);
        }
        let mut record = DiagnosticExecutionRecord::pending(prepared);
        if let Some(retained) = self.read_record()? {
            if retained.matches(prepared) && retained.state == ExecutionState::Completed {
                return Ok(LocalExecutionResult::new(
                    WorkOrderResultOutcome::Succeeded,
                    retained
                        .result_sha256
                        .ok_or(LocalHandoffErrorCode::StateMismatch)?,
                ));
            }
            if retained.state == ExecutionState::Pending && !retained.matches(prepared) {
                return Err(LocalHandoffErrorCode::StateMismatch);
            }
        }
        self.persist_record(&record)?;
        let document = self.collector.collect(prepared.action_id())?;
        record.state = ExecutionState::Completed;
        record.result_sha256 = Some(hex_sha256(&document));
        self.persist_record(&record)?;
        Ok(LocalExecutionResult::new(
            WorkOrderResultOutcome::Succeeded,
            record
                .result_sha256
                .ok_or(LocalHandoffErrorCode::StateMismatch)?,
        ))
    }
}

const fn is_diagnostic(action: WorkOrderActionId) -> bool {
    matches!(
        action,
        WorkOrderActionId::LinuxFilesystemHealthV1
            | WorkOrderActionId::LinuxStorageHealthV1
            | WorkOrderActionId::LinuxBootCriticalPathV1
    )
}

pub fn run_from_args() -> Result<(), LinuxWorkOrderServiceError> {
    let mut arguments = env::args_os().skip(1);
    if arguments.next().as_deref() != Some(OsStr::new("--config")) {
        return Err(LinuxWorkOrderServiceError::InvalidConfig);
    }
    let config_path = PathBuf::from(
        arguments
            .next()
            .ok_or(LinuxWorkOrderServiceError::InvalidConfig)?,
    );
    let once = match arguments.next() {
        None => false,
        Some(value) if value == "--once" => true,
        Some(_) => return Err(LinuxWorkOrderServiceError::InvalidConfig),
    };
    if arguments.next().is_some() {
        return Err(LinuxWorkOrderServiceError::InvalidConfig);
    }
    let config =
        LinuxWorkOrderServiceConfig::parse(&read_public_bounded(&config_path, MAX_CONFIG_BYTES)?)?;
    run_service(config, once)
}

pub fn run_service(
    config: LinuxWorkOrderServiceConfig,
    once: bool,
) -> Result<(), LinuxWorkOrderServiceError> {
    config.validate()?;
    ensure_private_directory(&config.state_directory)?;
    let _lock = open_service_lock(&config.state_directory.join(SERVICE_LOCK_FILE))?;
    let service_anchor = read_public_anchor(&config.service_receipt_anchor_file)?;
    let entitlement_anchor = read_public_anchor(&config.entitlement_anchor_file)?;
    let policy_anchor = read_public_anchor(&config.policy_anchor_file)?;
    let mut identity_store = NativeDeviceIdentityStore::open_named(RESIDENT_IDENTITY_NAMESPACE)
        .map_err(|_| LinuxWorkOrderServiceError::IdentityUnavailable)?;
    let identity = identity_store
        .load_device_identity()
        .map_err(|_| LinuxWorkOrderServiceError::IdentityUnavailable)?
        .ok_or(LinuxWorkOrderServiceError::IdentityUnavailable)?;
    let runtime = FleetRuntime::open_with_trust_anchors(
        &config.runtime_state_file,
        &config.tenant_id,
        &identity,
        &entitlement_anchor,
        &policy_anchor,
    )?;
    let transport = HttpsWorkOrderTransport::new(
        &config.endpoint,
        config.connect_timeout_seconds,
        config.request_timeout_seconds,
    )?;
    let mut engine = ResidentWorkOrderEngine::open(
        &config.tenant_id,
        &identity,
        &service_anchor,
        &config.state_directory.join(WORK_ORDER_STATE_DIRECTORY),
        transport,
    )?;
    let mut handoff = LinuxDiagnosticHandoff::open(
        &config.state_directory.join(EXECUTION_STATE_DIRECTORY),
        &identity.device_id(),
    )?;
    let mut backoff = config.minimum_backoff_seconds;

    loop {
        let cycle = run_cycle(&config, &runtime, &identity, &mut engine, &mut handoff);
        match cycle {
            Ok(outcome) => {
                print_outcome(&outcome);
                if once {
                    return Ok(());
                }
                backoff = config.minimum_backoff_seconds;
                thread::sleep(Duration::from_secs(config.interval_seconds));
            }
            Err(error) if error.transient() && !once => {
                eprintln!(
                    "KERNAID_FLEET_RESIDENT_WORK_ORDERS_V1 status=offline code={}",
                    error.code()
                );
                thread::sleep(Duration::from_secs(backoff));
                backoff = next_backoff(backoff, config.maximum_backoff_seconds);
            }
            Err(error) => return Err(error),
        }
    }
}

fn run_cycle<T: ResidentWorkOrderTransport, H: LocalWorkOrderHandoff>(
    config: &LinuxWorkOrderServiceConfig,
    runtime: &FleetRuntime,
    identity: &DeviceIdentity,
    engine: &mut ResidentWorkOrderEngine<T>,
    handoff: &mut H,
) -> Result<WorkOrderCycleOutcome, LinuxWorkOrderServiceError> {
    let now = Utc::now();
    let now_unix =
        u64::try_from(now.timestamp()).map_err(|_| LinuxWorkOrderServiceError::ClockUnavailable)?;
    let issued_at = now.to_rfc3339_opts(SecondsFormat::Secs, true);
    let mut nonce = Zeroizing::new(vec![0_u8; 32]);
    OsRng
        .try_fill_bytes(&mut nonce)
        .map_err(|_| LinuxWorkOrderServiceError::NonceUnavailable)?;
    let capabilities = runtime.capabilities(now_unix);
    let policies = runtime.applicable_policies(now_unix, TransportState::Online)?;
    let authorization = WorkOrderAuthorization {
        platform: ResidentPlatform::Linux,
        capabilities,
        policies: &policies,
        // This service intentionally cannot admit a repair even if a future
        // catalog entry is accidentally added to its local handoff.
        local_max_risk: RiskLevel::R0,
        local_approval_from: RiskLevel::R0,
        now_unix,
    };
    let outcome = engine
        .run_once(
            identity,
            WorkOrderCycleInput {
                issued_at,
                now_unix,
                nonce,
                lease_seconds: config.lease_seconds,
            },
            &authorization,
            handoff,
        )
        .map_err(LinuxWorkOrderServiceError::from)?;
    if matches!(outcome, WorkOrderCycleOutcome::AwaitingLocalApproval { .. }) {
        return Err(LinuxWorkOrderServiceError::InvalidState);
    }
    Ok(outcome)
}

fn print_outcome(outcome: &WorkOrderCycleOutcome) {
    match outcome {
        WorkOrderCycleOutcome::NoWork => println!(
            "KERNAID_FLEET_RESIDENT_WORK_ORDERS_V1 status=ok outcome=no-work writes=disabled"
        ),
        WorkOrderCycleOutcome::Completed { outcome, .. } => println!(
            "KERNAID_FLEET_RESIDENT_WORK_ORDERS_V1 status=ok outcome={outcome:?} writes=disabled"
        ),
        WorkOrderCycleOutcome::AwaitingLocalApproval { .. } => eprintln!(
            "KERNAID_FLEET_RESIDENT_WORK_ORDERS_V1 status=failed code=unexpected-write-order"
        ),
    }
}

fn next_backoff(current: u64, maximum: u64) -> u64 {
    current.saturating_mul(2).min(maximum)
}

fn strict_base_url(endpoint: &str) -> Result<Url, ()> {
    if endpoint.is_empty() || endpoint.len() > MAX_ENDPOINT_BYTES {
        return Err(());
    }
    let mut url = Url::parse(endpoint).map_err(|_| ())?;
    if url.scheme() != "https"
        || url.host_str().is_none()
        || !url.username().is_empty()
        || url.password().is_some()
        || url.query().is_some()
        || url.fragment().is_some()
        || !matches!(url.path(), "" | "/")
    {
        return Err(());
    }
    url.set_path("/");
    Ok(url)
}

fn valid_https_origin(endpoint: &str) -> bool {
    strict_base_url(endpoint).is_ok()
}

fn absolute_directory(path: &Path) -> bool {
    path.is_absolute() && path != Path::new("/") && path.file_name().is_some()
}

fn absolute_file(path: &Path) -> bool {
    path.is_absolute()
        && path.parent().is_some_and(absolute_directory)
        && path.file_name().is_some()
}

fn valid_identifier(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= MAX_IDENTIFIER_BYTES
        && value.bytes().all(|byte| {
            byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b':' | b'/')
        })
}

fn valid_sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn digest_fields(domain: &[u8], fields: &[&str]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(domain);
    for field in fields {
        hasher.update((field.len() as u64).to_be_bytes());
        hasher.update(field.as_bytes());
    }
    hex_bytes(&hasher.finalize())
}

fn hex_sha256(bytes: &[u8]) -> String {
    hex_bytes(&Sha256::digest(bytes))
}

fn hex_bytes(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn read_public_anchor(path: &Path) -> Result<[u8; 32], LinuxWorkOrderServiceError> {
    let bytes = read_public_bounded(path, MAX_ANCHOR_FILE_BYTES)?;
    let encoded = std::str::from_utf8(
        trim_ascii_line(&bytes).ok_or(LinuxWorkOrderServiceError::InvalidConfig)?,
    )
    .map_err(|_| LinuxWorkOrderServiceError::InvalidConfig)?;
    let decoded = URL_SAFE_NO_PAD
        .decode(encoded)
        .map_err(|_| LinuxWorkOrderServiceError::InvalidConfig)?;
    if URL_SAFE_NO_PAD.encode(&decoded) != encoded {
        return Err(LinuxWorkOrderServiceError::InvalidConfig);
    }
    decoded
        .try_into()
        .map_err(|_| LinuxWorkOrderServiceError::InvalidConfig)
}

fn read_public_bounded(path: &Path, maximum: usize) -> Result<Vec<u8>, LinuxWorkOrderServiceError> {
    let metadata = fs::symlink_metadata(path)?;
    if !metadata.is_file()
        || metadata.file_type().is_symlink()
        || metadata.mode() & 0o022 != 0
        || metadata.len() == 0
        || metadata.len() > maximum as u64
    {
        return Err(LinuxWorkOrderServiceError::InvalidConfig);
    }
    let bytes = fs::read(path)?;
    if bytes.len() > maximum || bytes.len() as u64 != metadata.len() {
        return Err(LinuxWorkOrderServiceError::InvalidConfig);
    }
    Ok(bytes)
}

fn ensure_private_directory(path: &Path) -> Result<(), LinuxWorkOrderServiceError> {
    if !absolute_directory(path) {
        return Err(LinuxWorkOrderServiceError::InvalidConfig);
    }
    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.is_dir() && !metadata.file_type().is_symlink() => {}
        Err(error) if error.kind() == io::ErrorKind::NotFound => fs::create_dir_all(path)?,
        _ => return Err(LinuxWorkOrderServiceError::InvalidState),
    }
    let metadata = fs::symlink_metadata(path)?;
    if !metadata.is_dir()
        || metadata.file_type().is_symlink()
        || metadata.uid() != process::getuid().as_raw()
    {
        return Err(LinuxWorkOrderServiceError::InvalidState);
    }
    fs::set_permissions(path, fs::Permissions::from_mode(0o700))?;
    if fs::symlink_metadata(path)?.mode() & 0o7777 != 0o700 {
        return Err(LinuxWorkOrderServiceError::InvalidState);
    }
    Ok(())
}

fn open_service_lock(path: &Path) -> Result<File, LinuxWorkOrderServiceError> {
    let descriptor = rfs::openat(
        CWD,
        path,
        OFlags::RDWR | OFlags::CREATE | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::RUSR | Mode::WUSR,
    )
    .map_err(|_| LinuxWorkOrderServiceError::InvalidState)?;
    let descriptor_state =
        rfs::fstat(&descriptor).map_err(|_| LinuxWorkOrderServiceError::InvalidState)?;
    let named_state = rfs::statat(CWD, path, AtFlags::SYMLINK_NOFOLLOW)
        .map_err(|_| LinuxWorkOrderServiceError::InvalidState)?;
    if !FileType::from_raw_mode(descriptor_state.st_mode).is_file()
        || !FileType::from_raw_mode(named_state.st_mode).is_file()
        || descriptor_state.st_dev != named_state.st_dev
        || descriptor_state.st_ino != named_state.st_ino
        || descriptor_state.st_nlink != 1
        || descriptor_state.st_uid != process::getuid().as_raw()
    {
        return Err(LinuxWorkOrderServiceError::InvalidState);
    }
    rfs::fchmod(&descriptor, Mode::RUSR | Mode::WUSR)
        .map_err(|_| LinuxWorkOrderServiceError::InvalidState)?;
    let file = File::from(descriptor);
    file.try_lock_exclusive()
        .map_err(|_| LinuxWorkOrderServiceError::InvalidState)?;
    Ok(file)
}

fn cleanup_temporary(path: &Path) -> Result<(), LinuxWorkOrderServiceError> {
    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.is_file() && !metadata.file_type().is_symlink() => {
            fs::remove_file(path)?;
            Ok(())
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        _ => Err(LinuxWorkOrderServiceError::InvalidState),
    }
}

fn read_private_optional(path: &Path, maximum: usize) -> io::Result<Option<Vec<u8>>> {
    let metadata = match fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error),
    };
    if !metadata.is_file()
        || metadata.file_type().is_symlink()
        || metadata.uid() != process::getuid().as_raw()
        || metadata.mode() & 0o7777 != 0o600
        || metadata.len() == 0
        || metadata.len() > maximum as u64
    {
        return Err(io::Error::other("private state rejected"));
    }
    let bytes = fs::read(path)?;
    if bytes.is_empty() || bytes.len() > maximum || bytes.len() as u64 != metadata.len() {
        return Err(io::Error::other("private state changed"));
    }
    Ok(Some(bytes))
}

fn write_atomic(directory: &Path, name: &str, pending_name: &str, bytes: &[u8]) -> io::Result<()> {
    let pending = directory.join(pending_name);
    let destination = directory.join(name);
    match fs::symlink_metadata(&pending) {
        Ok(_) => {
            return Err(io::Error::new(
                io::ErrorKind::AlreadyExists,
                "pending state exists",
            ));
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Err(error) => return Err(error),
    }
    let mut options = OpenOptions::new();
    options.write(true).create_new(true).mode(0o600);
    let mut file = options.open(&pending)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    fs::rename(&pending, &destination)?;
    File::open(directory)?.sync_all()
}

fn canonical_json<T: Serialize>(value: &T) -> Result<Vec<u8>, ()> {
    let mut value = serde_json::to_value(value).map_err(|_| ())?;
    validate_json(&value)?;
    sort_json(&mut value);
    serde_json::to_vec(&value).map_err(|_| ())
}

fn import_canonical<T: DeserializeOwned>(bytes: &[u8]) -> Result<T, ()> {
    if bytes.is_empty() || bytes.len() > MAX_EXECUTION_STATE_BYTES {
        return Err(());
    }
    let mut value: Value = serde_json::from_slice(bytes).map_err(|_| ())?;
    validate_json(&value)?;
    sort_json(&mut value);
    if serde_json::to_vec(&value).map_err(|_| ())? != bytes {
        return Err(());
    }
    serde_json::from_value(value).map_err(|_| ())
}

fn validate_json(value: &Value) -> Result<(), ()> {
    match value {
        Value::Null | Value::Bool(_) | Value::String(_) => Ok(()),
        Value::Number(number) if number.as_i64().is_some() || number.as_u64().is_some() => Ok(()),
        Value::Number(_) => Err(()),
        Value::Array(values) => values.iter().try_for_each(validate_json),
        Value::Object(values) => values.values().try_for_each(validate_json),
    }
}

fn sort_json(value: &mut Value) {
    match value {
        Value::Array(values) => values.iter_mut().for_each(sort_json),
        Value::Object(values) => {
            let mut sorted = serde_json::Map::new();
            let mut keys: Vec<_> = values.keys().cloned().collect();
            keys.sort_unstable();
            for key in keys {
                if let Some(mut child) = values.remove(&key) {
                    sort_json(&mut child);
                    sorted.insert(key, child);
                }
            }
            *values = sorted;
        }
        _ => {}
    }
}

fn trim_ascii_line(bytes: &[u8]) -> Option<&[u8]> {
    let bytes = bytes.strip_suffix(b"\n").unwrap_or(bytes);
    let bytes = bytes.strip_suffix(b"\r").unwrap_or(bytes);
    if bytes.is_empty() || bytes.contains(&b'\n') || bytes.contains(&b'\r') {
        None
    } else {
        Some(bytes)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    };
    use tempfile::TempDir;

    struct FixedCollector {
        calls: Arc<AtomicUsize>,
    }

    impl DiagnosticCollector for FixedCollector {
        fn collect(&mut self, action: WorkOrderActionId) -> Result<Vec<u8>, LocalHandoffErrorCode> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            match action {
                WorkOrderActionId::LinuxFilesystemHealthV1 => Ok(b"{\"health\":\"ok\"}".to_vec()),
                WorkOrderActionId::LinuxStorageHealthV1 => Ok(b"{\"storage\":\"ok\"}".to_vec()),
                WorkOrderActionId::LinuxBootCriticalPathV1 => Ok(b"{\"boot\":\"ok\"}".to_vec()),
                WorkOrderActionId::LinuxFstabDisableMissingUuidV1
                | WorkOrderActionId::LinuxCrypttabDisableMissingUuidV1
                | WorkOrderActionId::LinuxExt4FsckPreenWithUndoV1
                | WorkOrderActionId::LinuxNetworkRestoreResolverLinkV1 => {
                    Err(LocalHandoffErrorCode::StateMismatch)
                }
                WorkOrderActionId::WindowsP0DiagnoseV1 => Err(LocalHandoffErrorCode::StateMismatch),
                WorkOrderActionId::MacosP0DiagnoseV1 => Err(LocalHandoffErrorCode::StateMismatch),
            }
        }
    }

    fn valid_config(directory: &Path) -> LinuxWorkOrderServiceConfig {
        LinuxWorkOrderServiceConfig {
            schema: SERVICE_CONFIG_SCHEMA.to_owned(),
            endpoint: "https://fleet.example.invalid".to_owned(),
            tenant_id: "tenant-alpha".to_owned(),
            state_directory: directory.join("work-orders"),
            runtime_state_file: directory.join("fleet/runtime.sqlite3"),
            service_receipt_anchor_file: directory.join("config/service.pub"),
            entitlement_anchor_file: directory.join("config/entitlement.pub"),
            policy_anchor_file: directory.join("config/policy.pub"),
            interval_seconds: 60,
            minimum_backoff_seconds: 2,
            maximum_backoff_seconds: 120,
            connect_timeout_seconds: 5,
            request_timeout_seconds: 20,
            lease_seconds: 300,
        }
    }

    #[test]
    fn config_is_strict_https_and_has_no_secret_or_command_surface() {
        let directory = TempDir::new().expect("tempdir");
        let config = valid_config(directory.path());
        let bytes = serde_json::to_vec(&config).expect("config bytes");
        assert_eq!(
            LinuxWorkOrderServiceConfig::parse(&bytes).expect("valid"),
            config
        );
        let mut value: Value = serde_json::from_slice(&bytes).expect("JSON");
        value
            .as_object_mut()
            .expect("object")
            .insert("command".to_owned(), Value::String("sh -c id".to_owned()));
        assert!(
            LinuxWorkOrderServiceConfig::parse(&serde_json::to_vec(&value).expect("invalid bytes"))
                .is_err()
        );
        let mut invalid = config;
        invalid.endpoint = "https://user:secret@fleet.example.invalid".to_owned();
        assert!(invalid.validate().is_err());
    }

    #[test]
    fn diagnostic_cache_recovers_by_execution_id_without_recollecting() {
        let directory = TempDir::new().expect("tempdir");
        let state = directory.path().join("diagnostics");
        ensure_private_directory(&state).expect("private state");
        let identity = DeviceIdentity::from_seed(&[0x52; 32]).expect("identity");
        let calls = Arc::new(AtomicUsize::new(0));
        let mut handoff = LinuxDiagnosticHandoff::with_collector(
            &state,
            &identity.device_id(),
            FixedCollector {
                calls: Arc::clone(&calls),
            },
        );
        let prepared = PreparedLocalExecution {
            execution_id: "exec_0123456789abcdef0123456789abcdef".to_owned(),
            work_order_id: "wo_test".to_owned(),
            lease_id: "lease_test".to_owned(),
            action_id: WorkOrderActionId::LinuxFilesystemHealthV1,
            action_version: 1,
            plan_sha256: digest_fields(
                PLAN_DIGEST_DOMAIN,
                &[
                    "exec_0123456789abcdef0123456789abcdef",
                    "linux.filesystem.health.v1",
                    "1",
                ],
            ),
            target_sha256: digest_fields(
                TARGET_DIGEST_DOMAIN,
                &[&identity.device_id(), "linux.filesystem.health.v1"],
            ),
            local_approval: None,
        };
        let first = handoff
            .execute_or_recover(&prepared)
            .expect("first execute");
        let second = handoff.execute_or_recover(&prepared).expect("recover");
        assert_eq!(first, second);
        assert_eq!(calls.load(Ordering::SeqCst), 1);
        let state_bytes = fs::read(state.join(EXECUTION_STATE_FILE)).expect("state bytes");
        assert!(
            !state_bytes
                .windows(b"{\"health\":\"ok\"}".len())
                .any(|window| window == b"{\"health\":\"ok\"}")
        );
    }

    #[test]
    fn write_action_never_reaches_linux_collector() {
        let directory = TempDir::new().expect("tempdir");
        let state = directory.path().join("diagnostics");
        ensure_private_directory(&state).expect("private state");
        let identity = DeviceIdentity::from_seed(&[0x53; 32]).expect("identity");
        let calls = Arc::new(AtomicUsize::new(0));
        let mut handoff = LinuxDiagnosticHandoff::with_collector(
            &state,
            &identity.device_id(),
            FixedCollector {
                calls: Arc::clone(&calls),
            },
        );
        let prepared = PreparedLocalExecution {
            execution_id: "exec_1123456789abcdef0123456789abcdef".to_owned(),
            work_order_id: "wo_write".to_owned(),
            lease_id: "lease_write".to_owned(),
            action_id: WorkOrderActionId::LinuxFstabDisableMissingUuidV1,
            action_version: 1,
            plan_sha256: "11".repeat(32),
            target_sha256: "22".repeat(32),
            local_approval: None,
        };
        assert_eq!(
            handoff.execute_or_recover(&prepared),
            Err(LocalHandoffErrorCode::StateMismatch)
        );
        assert_eq!(calls.load(Ordering::SeqCst), 0);
        assert!(!state.join(EXECUTION_STATE_FILE).exists());
    }

    #[test]
    fn backoff_is_bounded() {
        assert_eq!(next_backoff(2, 120), 4);
        assert_eq!(next_backoff(64, 120), 120);
        assert_eq!(next_backoff(120, 120), 120);
    }
}
