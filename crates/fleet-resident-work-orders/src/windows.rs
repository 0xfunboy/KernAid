//! Installable, off-default Windows Resident for one closed Fleet R0 action.
//!
//! The service accepts only `windows.p0.diagnose.v1`. Remote work orders never
//! supply a command, argument, script, path, or collector selector. Native
//! collection reuses the fixed Windows P0 contract in `kernaid-windows-pack`.

use super::{
    LocalExecutionResult, LocalHandoffErrorCode, LocalWorkOrderHandoff, PreparedLocalExecution,
    ResidentWorkOrderError, ResidentWorkOrderTransport, TransportErrorCode,
    WorkOrderTransportResponse,
};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
#[cfg(windows)]
use chrono::{SecondsFormat, Utc};
#[cfg(windows)]
use fs2::FileExt as _;
use kernaid_device_identity::validate_device_id;
use kernaid_fleet_client::{LeasedWorkOrder, WorkOrderActionId, WorkOrderResultOutcome};
use kernaid_fleet_runtime::FleetRuntimeError;
#[cfg(windows)]
use kernaid_native_secrets::NativeDeviceIdentityStore;
use reqwest::{
    Url,
    blocking::{Client, Response},
    header::{ACCEPT, CONTENT_LENGTH, CONTENT_TYPE, HeaderName},
    redirect::Policy,
};
use rustls::crypto::ring;
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::{
    error::Error,
    fmt,
    fs::{self, OpenOptions},
    io::{self, Read, Write},
    path::{Component, Path, PathBuf},
    time::Duration,
};

#[cfg(windows)]
use super::{
    ResidentPlatform, ResidentWorkOrderEngine, WorkOrderAuthorization, WorkOrderCycleInput,
    WorkOrderCycleOutcome,
};

#[cfg(windows)]
use kernaid_device_identity::DeviceIdentity;

#[cfg(windows)]
use kernaid_fleet_policy::{RiskLevel, TransportState};

#[cfg(windows)]
use kernaid_fleet_runtime::FleetRuntime;

#[cfg(windows)]
use rand_core::{OsRng, RngCore};

#[cfg(windows)]
use std::{
    collections::BTreeMap,
    env,
    ffi::{OsStr, OsString},
    fs::File,
    process::{ChildStderr, ChildStdout, Command, ExitStatus, Stdio},
    sync::{
        OnceLock,
        mpsc::{self, Receiver, RecvTimeoutError},
    },
    thread,
    time::Instant,
};

#[cfg(windows)]
use zeroize::Zeroizing;

#[cfg(windows)]
use process_wrap::std::{ChildWrapper, CommandWrap, JobObject};

#[cfg(windows)]
use windows_service::{
    define_windows_service,
    service::{
        ServiceAccess, ServiceControl, ServiceControlAccept, ServiceErrorControl, ServiceExitCode,
        ServiceInfo, ServiceStartType, ServiceState, ServiceStatus, ServiceType,
    },
    service_control_handler::{self, ServiceControlHandlerResult},
    service_dispatcher,
    service_manager::{ServiceManager, ServiceManagerAccess},
};

pub const WINDOWS_SERVICE_CONFIG_SCHEMA: &str =
    "dev.kernaid.fleet.resident-windows-service-config.v1";
pub const WINDOWS_SERVICE_NAME: &str = "KernAidFleetResidentWindows";
pub const WINDOWS_SERVICE_DISPLAY_NAME: &str = "KernAid Fleet Resident (Windows R0)";
pub const RESIDENT_IDENTITY_NAMESPACE: &str = "resident-v1";

const CLAIM_ROUTE: &str = "/v1/work-order-claims";
const RESULT_ROUTE: &str = "/v1/work-order-results";
const RECEIPT_HEADER: HeaderName = HeaderName::from_static("x-kernaid-fleet-receipt");
#[cfg(windows)]
const SERVICE_LOCK_FILE: &str = ".resident-windows-v1.lock";
#[cfg(windows)]
const WORK_ORDER_STATE_DIRECTORY: &str = "protocol";
#[cfg(windows)]
const EXECUTION_STATE_DIRECTORY: &str = "diagnostics";
const EXECUTION_STATE_FILE: &str = "execution-v1.cjson";
const EXECUTION_PENDING_FILE: &str = ".execution-v1.pending";
const EXECUTION_STATE_SCHEMA: &str = "dev.kernaid.fleet.windows-diagnostic-execution.v1";
const PLAN_DIGEST_DOMAIN: &[u8] = b"kernaid:fleet:windows-p0-plan:v1\0";
const TARGET_DIGEST_DOMAIN: &[u8] = b"kernaid:fleet:windows-p0-target:v1\0";
const MAX_CONFIG_BYTES: usize = 16 * 1024;
#[cfg(windows)]
const MAX_ANCHOR_FILE_BYTES: usize = 128;
const MAX_REQUEST_BYTES: usize = 64 * 1024;
const MAX_RECEIPT_HEADER_BYTES: usize = 8 * 1024;
const MAX_EXECUTION_STATE_BYTES: usize = 8 * 1024;
const MAX_DIAGNOSTIC_BYTES: usize = 64 * 1024;
#[cfg(windows)]
const MAX_NATIVE_OUTPUT_BYTES: usize = 1024 * 1024;
const MAX_ENDPOINT_BYTES: usize = 4 * 1024;
const MIN_INTERVAL_SECONDS: u64 = 30;
const MAX_INTERVAL_SECONDS: u64 = 24 * 60 * 60;
const MAX_BACKOFF_SECONDS: u64 = 60 * 60;
const MAX_CONNECT_TIMEOUT_SECONDS: u64 = 30;
const MAX_REQUEST_TIMEOUT_SECONDS: u64 = 180;

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct WindowsWorkOrderServiceConfig {
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

impl WindowsWorkOrderServiceConfig {
    pub fn parse(bytes: &[u8]) -> Result<Self, WindowsWorkOrderServiceError> {
        if bytes.is_empty() || bytes.len() > MAX_CONFIG_BYTES {
            return Err(WindowsWorkOrderServiceError::InvalidConfig);
        }
        let config: Self = serde_json::from_slice(bytes)
            .map_err(|_| WindowsWorkOrderServiceError::InvalidConfig)?;
        config.validate()?;
        Ok(config)
    }

    fn validate(&self) -> Result<(), WindowsWorkOrderServiceError> {
        if self.schema != WINDOWS_SERVICE_CONFIG_SCHEMA
            || !valid_https_origin(&self.endpoint)
            || !valid_identifier(&self.tenant_id)
            || !safe_absolute_path(&self.state_directory)
            || !safe_absolute_path(&self.runtime_state_file)
            || !safe_absolute_path(&self.service_receipt_anchor_file)
            || !safe_absolute_path(&self.entitlement_anchor_file)
            || !safe_absolute_path(&self.policy_anchor_file)
            || !(MIN_INTERVAL_SECONDS..=MAX_INTERVAL_SECONDS).contains(&self.interval_seconds)
            || self.minimum_backoff_seconds == 0
            || self.minimum_backoff_seconds > self.maximum_backoff_seconds
            || self.maximum_backoff_seconds > MAX_BACKOFF_SECONDS
            || self.connect_timeout_seconds == 0
            || self.connect_timeout_seconds > MAX_CONNECT_TIMEOUT_SECONDS
            || self.request_timeout_seconds == 0
            || self.request_timeout_seconds > MAX_REQUEST_TIMEOUT_SECONDS
            || self.connect_timeout_seconds > self.request_timeout_seconds
            || !(30..=900).contains(&self.lease_seconds)
        {
            return Err(WindowsWorkOrderServiceError::InvalidConfig);
        }
        let paths = [
            &self.runtime_state_file,
            &self.service_receipt_anchor_file,
            &self.entitlement_anchor_file,
            &self.policy_anchor_file,
        ];
        for (index, path) in paths.iter().enumerate() {
            if paths[..index].contains(path) {
                return Err(WindowsWorkOrderServiceError::InvalidConfig);
            }
        }
        Ok(())
    }
}

#[derive(Debug)]
pub enum WindowsWorkOrderServiceError {
    InvalidArguments,
    InvalidConfig,
    InvalidState,
    IdentityUnavailable,
    ClockUnavailable,
    NonceUnavailable,
    ServiceControl,
    Runtime(FleetRuntimeError),
    Resident(ResidentWorkOrderError),
    Io(io::Error),
}

impl WindowsWorkOrderServiceError {
    #[must_use]
    pub const fn code(&self) -> &'static str {
        match self {
            Self::InvalidArguments => "arguments-invalid",
            Self::InvalidConfig => "config-invalid",
            Self::InvalidState => "state-invalid",
            Self::IdentityUnavailable => "identity-unavailable",
            Self::ClockUnavailable => "clock-unavailable",
            Self::NonceUnavailable => "nonce-unavailable",
            Self::ServiceControl => "windows-service-control-failed",
            Self::Runtime(_) => "runtime-unavailable",
            Self::Resident(error) => error.code(),
            Self::Io(_) => "io-failed",
        }
    }

    #[cfg(windows)]
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

impl fmt::Display for WindowsWorkOrderServiceError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.code())
    }
}

impl Error for WindowsWorkOrderServiceError {}

impl From<io::Error> for WindowsWorkOrderServiceError {
    fn from(value: io::Error) -> Self {
        Self::Io(value)
    }
}

impl From<ResidentWorkOrderError> for WindowsWorkOrderServiceError {
    fn from(value: ResidentWorkOrderError) -> Self {
        Self::Resident(value)
    }
}

impl From<FleetRuntimeError> for WindowsWorkOrderServiceError {
    fn from(value: FleetRuntimeError) -> Self {
        Self::Runtime(value)
    }
}

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
    ) -> Result<Self, WindowsWorkOrderServiceError> {
        let base =
            strict_base_url(endpoint).map_err(|()| WindowsWorkOrderServiceError::InvalidConfig)?;
        let origin = base.origin().ascii_serialization();
        let _ = ring::default_provider().install_default();
        let client = Client::builder()
            .https_only(true)
            .no_proxy()
            .redirect(Policy::none())
            .connect_timeout(Duration::from_secs(connect_timeout_seconds))
            .timeout(Duration::from_secs(request_timeout_seconds))
            .user_agent(concat!(
                "KernAid-Fleet-Resident-Windows/",
                env!("CARGO_PKG_VERSION")
            ))
            .build()
            .map_err(|_| WindowsWorkOrderServiceError::InvalidConfig)?;
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
            || self.action_id != WorkOrderActionId::WindowsP0DiagnoseV1
            || self.action_version != 1
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

struct WindowsDiagnosticHandoff<C> {
    directory: PathBuf,
    device_id: String,
    collector: C,
}

impl<C: DiagnosticCollector> WindowsDiagnosticHandoff<C> {
    fn with_collector(
        directory: &Path,
        device_id: &str,
        collector: C,
    ) -> Result<Self, WindowsWorkOrderServiceError> {
        ensure_private_directory(directory)?;
        cleanup_pending(&directory.join(EXECUTION_PENDING_FILE))?;
        validate_device_id(device_id).map_err(|_| WindowsWorkOrderServiceError::InvalidState)?;
        Ok(Self {
            directory: directory.to_path_buf(),
            device_id: device_id.to_owned(),
            collector,
        })
    }

    fn read_record(&self) -> Result<Option<DiagnosticExecutionRecord>, LocalHandoffErrorCode> {
        let Some(bytes) = read_bounded_optional(
            &self.directory.join(EXECUTION_STATE_FILE),
            MAX_EXECUTION_STATE_BYTES,
        )
        .map_err(|_| LocalHandoffErrorCode::StateMismatch)?
        else {
            return Ok(None);
        };
        let record: DiagnosticExecutionRecord =
            import_canonical(&bytes).map_err(|()| LocalHandoffErrorCode::StateMismatch)?;
        record.validate()?;
        Ok(Some(record))
    }

    fn persist_record(
        &self,
        record: &DiagnosticExecutionRecord,
    ) -> Result<(), LocalHandoffErrorCode> {
        record.validate()?;
        let bytes = canonical_json(record).map_err(|()| LocalHandoffErrorCode::StateMismatch)?;
        if bytes.len() > MAX_EXECUTION_STATE_BYTES {
            return Err(LocalHandoffErrorCode::StateMismatch);
        }
        write_state_atomic(
            &self.directory,
            EXECUTION_STATE_FILE,
            EXECUTION_PENDING_FILE,
            &bytes,
        )
        .map_err(|_| LocalHandoffErrorCode::StateMismatch)
    }
}

impl<C: DiagnosticCollector> LocalWorkOrderHandoff for WindowsDiagnosticHandoff<C> {
    fn prepare(
        &mut self,
        order: &LeasedWorkOrder,
        execution_id: &str,
    ) -> Result<PreparedLocalExecution, LocalHandoffErrorCode> {
        if order.action_id() != WorkOrderActionId::WindowsP0DiagnoseV1
            || order.action_version() != 1
            || order.local_approval_required()
            || order.approval().is_some()
        {
            return Err(LocalHandoffErrorCode::StateMismatch);
        }
        let plan_sha256 = digest_fields(
            PLAN_DIGEST_DOMAIN,
            &[
                execution_id,
                WorkOrderActionId::WindowsP0DiagnoseV1.wire_name(),
                "1",
            ],
        );
        let target_sha256 = digest_fields(
            TARGET_DIGEST_DOMAIN,
            &[
                &self.device_id,
                WorkOrderActionId::WindowsP0DiagnoseV1.wire_name(),
            ],
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
        if prepared.action_id() != WorkOrderActionId::WindowsP0DiagnoseV1
            || prepared.action_version() != 1
            || prepared.local_approval().is_some()
            || prepared.plan_sha256()
                != digest_fields(
                    PLAN_DIGEST_DOMAIN,
                    &[
                        prepared.execution_id(),
                        WorkOrderActionId::WindowsP0DiagnoseV1.wire_name(),
                        "1",
                    ],
                )
            || prepared.target_sha256()
                != digest_fields(
                    TARGET_DIGEST_DOMAIN,
                    &[
                        &self.device_id,
                        WorkOrderActionId::WindowsP0DiagnoseV1.wire_name(),
                    ],
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
            if !retained.matches(prepared) && retained.state == ExecutionState::Pending {
                return Err(LocalHandoffErrorCode::StateMismatch);
            }
        }
        self.persist_record(&record)?;
        let document = self
            .collector
            .collect(WorkOrderActionId::WindowsP0DiagnoseV1)?;
        if document.is_empty() || document.len() > MAX_DIAGNOSTIC_BYTES {
            return Err(LocalHandoffErrorCode::ExecutionFailed);
        }
        record.state = ExecutionState::Completed;
        record.result_sha256 = Some(sha256_hex(&document));
        self.persist_record(&record)?;
        Ok(LocalExecutionResult::new(
            WorkOrderResultOutcome::Succeeded,
            record
                .result_sha256
                .ok_or(LocalHandoffErrorCode::StateMismatch)?,
        ))
    }
}

#[cfg(windows)]
struct SystemWindowsP0Collector;

#[cfg(windows)]
impl DiagnosticCollector for SystemWindowsP0Collector {
    fn collect(&mut self, action: WorkOrderActionId) -> Result<Vec<u8>, LocalHandoffErrorCode> {
        use kernaid_windows_pack::diagnostics::{
            EvidenceInput, WindowsP0Inputs, diagnose_windows_p0, proposal_from_report,
        };

        if action != WorkOrderActionId::WindowsP0DiagnoseV1 {
            return Err(LocalHandoffErrorCode::StateMismatch);
        }
        let documents = collect_windows_p0_documents()?;
        let input = |collector: &str,
                     id: &'static str|
         -> Result<EvidenceInput<'_>, LocalHandoffErrorCode> {
            let body = documents
                .get(collector)
                .ok_or(LocalHandoffErrorCode::ExecutionFailed)?;
            Ok(EvidenceInput {
                id,
                body: body.as_bytes(),
            })
        };
        let report = diagnose_windows_p0(WindowsP0Inputs {
            event_log_json: input("windows.event-log.window", "E-WIN-FLEET-1")?,
            reliability_json: input("windows.reliability.records", "E-WIN-FLEET-2")?,
            component_store_json: input("windows.component-store.check-health", "E-WIN-FLEET-3")?,
            sfc_json: input("windows.sfc.verify-only", "E-WIN-FLEET-4")?,
            update_json: input("windows.update.state", "E-WIN-FLEET-5")?,
            services_json: input("windows.services.state", "E-WIN-FLEET-6")?,
            network_json: input("windows.network.state", "E-WIN-FLEET-7")?,
            drivers_json: input("windows.drivers.state", "E-WIN-FLEET-8")?,
            bitlocker_json: input("windows.bitlocker.state", "E-WIN-FLEET-9")?,
            boot_json: input("windows.boot.state", "E-WIN-FLEET-10")?,
            volumes_json: input("windows.volumes.state", "E-WIN-FLEET-11")?,
        })
        .map_err(|_| LocalHandoffErrorCode::ExecutionFailed)?;
        let encoded = serde_json::to_vec(&proposal_from_report(&report))
            .map_err(|_| LocalHandoffErrorCode::ExecutionFailed)?;
        if encoded.is_empty() || encoded.len() > MAX_DIAGNOSTIC_BYTES {
            return Err(LocalHandoffErrorCode::ExecutionFailed);
        }
        Ok(encoded)
    }
}

#[cfg(windows)]
fn collect_windows_p0_documents() -> Result<BTreeMap<&'static str, String>, LocalHandoffErrorCode> {
    use kernaid_windows_pack::resident::{COLLECTORS, P0_WALL_CLOCK_BUDGET};

    let started = Instant::now();
    let results = thread::scope(|scope| {
        let handles = COLLECTORS.map(|spec| scope.spawn(move || collect_spec(spec)));
        COLLECTORS
            .into_iter()
            .zip(handles)
            .map(|(spec, handle)| {
                handle
                    .join()
                    .map_err(|_| LocalHandoffErrorCode::ExecutionFailed)?
                    .map(|body| (spec.collector, body))
            })
            .collect::<Result<Vec<_>, _>>()
    })?;
    if started.elapsed() > P0_WALL_CLOCK_BUDGET {
        return Err(LocalHandoffErrorCode::ExecutionFailed);
    }
    if results.len() != 11 {
        return Err(LocalHandoffErrorCode::ExecutionFailed);
    }
    Ok(results.into_iter().collect())
}

#[cfg(windows)]
fn collect_spec(
    spec: kernaid_windows_pack::resident::CollectorSpec,
) -> Result<String, LocalHandoffErrorCode> {
    use kernaid_windows_pack::resident::{
        BCDEDIT, BOOT_MANAGER_ARGS, BOOT_TIMEOUT, CollectorKind, DEFAULT_LOADER_ARGS, DISM,
        DISM_ARGS, DISM_TIMEOUT, FIRMWARE_REG_ARGS, OS_LOADER_ARGS, POWERSHELL,
        POWERSHELL_PREFIX_ARGS, POWERSHELL_TIMEOUT, REG, normalize_boot, normalize_dism,
        sfc_not_run_projection, validate_projection,
    };

    let output = match spec.kind {
        CollectorKind::PowerShell(script) => {
            let args = [
                POWERSHELL_PREFIX_ARGS[0],
                POWERSHELL_PREFIX_ARGS[1],
                POWERSHELL_PREFIX_ARGS[2],
                POWERSHELL_PREFIX_ARGS[3],
                script,
            ];
            let result = run_fixed_command(
                POWERSHELL,
                &args,
                POWERSHELL_TIMEOUT,
                MAX_NATIVE_OUTPUT_BYTES,
            )?;
            if result.exit_code != 0 || !result.stderr.trim().is_empty() {
                return Err(LocalHandoffErrorCode::ExecutionFailed);
            }
            result.stdout
        }
        CollectorKind::Dism => {
            let result =
                run_fixed_command(DISM, &DISM_ARGS, DISM_TIMEOUT, MAX_NATIVE_OUTPUT_BYTES)?;
            normalize_dism(&result.stdout, &result.stderr, result.exit_code)
                .map_err(|_| LocalHandoffErrorCode::ExecutionFailed)?
        }
        CollectorKind::SfcNotRunUnqualified => {
            sfc_not_run_projection().map_err(|_| LocalHandoffErrorCode::ExecutionFailed)?
        }
        CollectorKind::Boot => {
            let (firmware, manager, loaders, default_loader) = thread::scope(|scope| {
                let firmware = scope.spawn(|| {
                    run_fixed_command(
                        REG,
                        &FIRMWARE_REG_ARGS,
                        BOOT_TIMEOUT,
                        MAX_NATIVE_OUTPUT_BYTES,
                    )
                });
                let manager = scope.spawn(|| {
                    run_fixed_command(
                        BCDEDIT,
                        &BOOT_MANAGER_ARGS,
                        BOOT_TIMEOUT,
                        MAX_NATIVE_OUTPUT_BYTES,
                    )
                });
                let loaders = scope.spawn(|| {
                    run_fixed_command(
                        BCDEDIT,
                        &OS_LOADER_ARGS,
                        BOOT_TIMEOUT,
                        MAX_NATIVE_OUTPUT_BYTES,
                    )
                });
                let default_loader = scope.spawn(|| {
                    run_fixed_command(
                        BCDEDIT,
                        &DEFAULT_LOADER_ARGS,
                        BOOT_TIMEOUT,
                        MAX_NATIVE_OUTPUT_BYTES,
                    )
                });
                (
                    firmware.join().ok().and_then(Result::ok),
                    manager.join().ok().and_then(Result::ok),
                    loaders.join().ok().and_then(Result::ok),
                    default_loader.join().ok().and_then(Result::ok),
                )
            });
            normalize_boot(
                native_output(&firmware),
                native_output(&manager),
                native_output(&loaders),
                native_output(&default_loader),
            )
            .map_err(|_| LocalHandoffErrorCode::ExecutionFailed)?
        }
    };
    validate_projection(spec.collector, &output)
        .map_err(|_| LocalHandoffErrorCode::ExecutionFailed)?;
    Ok(output)
}

#[cfg(windows)]
fn native_output(
    value: &Option<FixedCommandOutput>,
) -> kernaid_windows_pack::resident::NativeOutput<'_> {
    kernaid_windows_pack::resident::NativeOutput {
        stdout: value.as_ref().map_or("", |item| item.stdout.as_str()),
        exit_code: value.as_ref().map_or(-1, |item| item.exit_code),
    }
}

#[cfg(windows)]
struct WindowsJobChild(Box<dyn ChildWrapper>);

#[cfg(windows)]
impl WindowsJobChild {
    fn take_stdout(&mut self) -> Option<ChildStdout> {
        self.0.stdout().take()
    }

    fn take_stderr(&mut self) -> Option<ChildStderr> {
        self.0.stderr().take()
    }

    fn try_wait(&mut self) -> io::Result<Option<ExitStatus>> {
        self.0.try_wait()
    }

    fn terminate(&mut self) {
        let _ = self.0.kill();
    }
}

#[cfg(windows)]
struct FixedCommandOutput {
    stdout: String,
    stderr: String,
    exit_code: i32,
}

#[cfg(windows)]
fn run_fixed_command(
    program: &'static str,
    args: &[&'static str],
    timeout: Duration,
    maximum_output_bytes: usize,
) -> Result<FixedCommandOutput, LocalHandoffErrorCode> {
    use kernaid_windows_pack::resident::WINDOWS_ENVIRONMENT;

    let mut command = Command::new(program);
    command
        .args(args)
        .env_clear()
        .current_dir(r"C:\Windows\System32")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    for (name, value) in WINDOWS_ENVIRONMENT {
        command.env(name, value);
    }
    let mut wrapped = CommandWrap::from(command);
    wrapped.wrap(JobObject);
    let child = wrapped
        .spawn()
        .map_err(|_| LocalHandoffErrorCode::ExecutionFailed)?;
    let mut child = WindowsJobChild(child);
    let stdout = child
        .take_stdout()
        .ok_or(LocalHandoffErrorCode::ExecutionFailed)?;
    let stderr = child
        .take_stderr()
        .ok_or(LocalHandoffErrorCode::ExecutionFailed)?;
    let stdout = spawn_bounded_reader(stdout, maximum_output_bytes);
    let stderr = spawn_bounded_reader(stderr, maximum_output_bytes);
    let deadline = Instant::now() + timeout;
    let status = loop {
        match child.try_wait() {
            Ok(Some(status)) => break status,
            Ok(None) if Instant::now() < deadline => thread::sleep(Duration::from_millis(20)),
            Ok(None) | Err(_) => {
                child.terminate();
                return Err(LocalHandoffErrorCode::ExecutionFailed);
            }
        }
    };
    let stdout = stdout
        .join()
        .map_err(|_| LocalHandoffErrorCode::ExecutionFailed)??;
    let stderr = stderr
        .join()
        .map_err(|_| LocalHandoffErrorCode::ExecutionFailed)??;
    let stdout = String::from_utf8(stdout).map_err(|_| LocalHandoffErrorCode::ExecutionFailed)?;
    let stderr = String::from_utf8(stderr).map_err(|_| LocalHandoffErrorCode::ExecutionFailed)?;
    Ok(FixedCommandOutput {
        stdout,
        stderr,
        exit_code: status
            .code()
            .ok_or(LocalHandoffErrorCode::ExecutionFailed)?,
    })
}

#[cfg(windows)]
fn spawn_bounded_reader(
    mut reader: impl Read + Send + 'static,
    maximum: usize,
) -> thread::JoinHandle<Result<Vec<u8>, LocalHandoffErrorCode>> {
    thread::spawn(move || {
        let mut retained = Vec::with_capacity(maximum.min(64 * 1024));
        let mut buffer = [0_u8; 8192];
        loop {
            let read = reader
                .read(&mut buffer)
                .map_err(|_| LocalHandoffErrorCode::ExecutionFailed)?;
            if read == 0 {
                return Ok(retained);
            }
            if retained.len().saturating_add(read) > maximum {
                return Err(LocalHandoffErrorCode::ExecutionFailed);
            }
            retained.extend_from_slice(&buffer[..read]);
        }
    })
}

#[cfg(windows)]
impl WindowsDiagnosticHandoff<SystemWindowsP0Collector> {
    fn open(directory: &Path, device_id: &str) -> Result<Self, WindowsWorkOrderServiceError> {
        Self::with_collector(directory, device_id, SystemWindowsP0Collector)
    }
}

#[cfg(windows)]
fn run_cycle<T: ResidentWorkOrderTransport, H: LocalWorkOrderHandoff>(
    config: &WindowsWorkOrderServiceConfig,
    runtime: &FleetRuntime,
    identity: &DeviceIdentity,
    engine: &mut ResidentWorkOrderEngine<T>,
    handoff: &mut H,
) -> Result<WorkOrderCycleOutcome, WindowsWorkOrderServiceError> {
    let now = Utc::now();
    let now_unix = u64::try_from(now.timestamp())
        .map_err(|_| WindowsWorkOrderServiceError::ClockUnavailable)?;
    let mut nonce = Zeroizing::new(vec![0_u8; 32]);
    OsRng
        .try_fill_bytes(&mut nonce)
        .map_err(|_| WindowsWorkOrderServiceError::NonceUnavailable)?;
    let capabilities = runtime.capabilities(now_unix);
    let policies = runtime.applicable_policies(now_unix, TransportState::Online)?;
    let authorization = WorkOrderAuthorization {
        platform: ResidentPlatform::Windows,
        capabilities,
        policies: &policies,
        local_max_risk: RiskLevel::R0,
        local_approval_from: RiskLevel::R0,
        now_unix,
    };
    let outcome = engine.run_once(
        identity,
        WorkOrderCycleInput {
            issued_at: now.to_rfc3339_opts(SecondsFormat::Secs, true),
            now_unix,
            nonce,
            lease_seconds: config.lease_seconds,
        },
        &authorization,
        handoff,
    )?;
    if matches!(outcome, WorkOrderCycleOutcome::AwaitingLocalApproval { .. }) {
        return Err(WindowsWorkOrderServiceError::InvalidState);
    }
    Ok(outcome)
}

#[cfg(windows)]
fn run_worker(
    config: WindowsWorkOrderServiceConfig,
    once: bool,
    initialize_identity: bool,
    shutdown: &Receiver<()>,
) -> Result<(), WindowsWorkOrderServiceError> {
    config.validate()?;
    ensure_private_directory(&config.state_directory)?;
    let _lock = open_service_lock(&config.state_directory.join(SERVICE_LOCK_FILE))?;
    let service_anchor = read_public_anchor(&config.service_receipt_anchor_file)?;
    let entitlement_anchor = read_public_anchor(&config.entitlement_anchor_file)?;
    let policy_anchor = read_public_anchor(&config.policy_anchor_file)?;
    let mut identity_store = NativeDeviceIdentityStore::open_named(RESIDENT_IDENTITY_NAMESPACE)
        .map_err(|_| WindowsWorkOrderServiceError::IdentityUnavailable)?;
    let identity = match identity_store
        .load_device_identity()
        .map_err(|_| WindowsWorkOrderServiceError::IdentityUnavailable)?
    {
        Some(identity) => identity,
        None if initialize_identity => identity_store
            .create_device_identity()
            .map_err(|_| WindowsWorkOrderServiceError::IdentityUnavailable)?,
        None => return Err(WindowsWorkOrderServiceError::IdentityUnavailable),
    };
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
    let mut handoff = WindowsDiagnosticHandoff::open(
        &config.state_directory.join(EXECUTION_STATE_DIRECTORY),
        &identity.device_id(),
    )?;
    let mut backoff = config.minimum_backoff_seconds;
    loop {
        let result = run_cycle(&config, &runtime, &identity, &mut engine, &mut handoff);
        if once {
            return result.map(|_| ());
        }
        let wait_seconds = match result {
            Ok(_) => {
                backoff = config.minimum_backoff_seconds;
                config.interval_seconds
            }
            Err(error) if error.transient() => {
                let wait = backoff;
                backoff = backoff
                    .saturating_mul(2)
                    .min(config.maximum_backoff_seconds);
                wait
            }
            Err(error) => return Err(error),
        };
        match shutdown.recv_timeout(Duration::from_secs(wait_seconds)) {
            Ok(()) | Err(RecvTimeoutError::Disconnected) => return Ok(()),
            Err(RecvTimeoutError::Timeout) => {}
        }
    }
}

#[cfg(windows)]
static SERVICE_CONFIG_PATH: OnceLock<PathBuf> = OnceLock::new();

#[cfg(windows)]
define_windows_service!(ffi_service_main, service_main);

#[cfg(windows)]
fn service_main(arguments: Vec<OsString>) {
    let result = service_main_inner(arguments);
    let _ = result;
}

#[cfg(windows)]
fn service_main_inner(arguments: Vec<OsString>) -> Result<(), WindowsWorkOrderServiceError> {
    let initialize_identity = parse_service_start_arguments(&arguments)?;
    let config_path = SERVICE_CONFIG_PATH
        .get()
        .ok_or(WindowsWorkOrderServiceError::InvalidArguments)?;
    let config =
        WindowsWorkOrderServiceConfig::parse(&read_public_bounded(config_path, MAX_CONFIG_BYTES)?)?;
    let (shutdown_tx, shutdown_rx) = mpsc::channel();
    let handler = move |control| match control {
        ServiceControl::Interrogate => ServiceControlHandlerResult::NoError,
        ServiceControl::Stop => {
            let _ = shutdown_tx.send(());
            ServiceControlHandlerResult::NoError
        }
        _ => ServiceControlHandlerResult::NotImplemented,
    };
    let status = service_control_handler::register(WINDOWS_SERVICE_NAME, handler)
        .map_err(|_| WindowsWorkOrderServiceError::ServiceControl)?;
    status
        .set_service_status(service_status(ServiceState::Running, true, 0))
        .map_err(|_| WindowsWorkOrderServiceError::ServiceControl)?;
    let result = run_worker(config, false, initialize_identity, &shutdown_rx);
    let exit = if result.is_ok() { 0 } else { 1 };
    status
        .set_service_status(service_status(ServiceState::Stopped, false, exit))
        .map_err(|_| WindowsWorkOrderServiceError::ServiceControl)?;
    result
}

#[cfg(windows)]
fn service_status(state: ServiceState, accepts_stop: bool, exit: u32) -> ServiceStatus {
    ServiceStatus {
        service_type: ServiceType::OWN_PROCESS,
        current_state: state,
        controls_accepted: if accepts_stop {
            ServiceControlAccept::STOP
        } else {
            ServiceControlAccept::empty()
        },
        exit_code: ServiceExitCode::Win32(exit),
        checkpoint: 0,
        wait_hint: Duration::ZERO,
        process_id: None,
    }
}

#[cfg(windows)]
fn parse_service_start_arguments(
    arguments: &[OsString],
) -> Result<bool, WindowsWorkOrderServiceError> {
    let filtered: Vec<&OsStr> = arguments
        .iter()
        .map(OsString::as_os_str)
        .filter(|value| *value != OsStr::new(WINDOWS_SERVICE_NAME))
        .collect();
    match filtered.as_slice() {
        [] => Ok(false),
        [value] if *value == OsStr::new("--initialize-identity") => Ok(true),
        _ => Err(WindowsWorkOrderServiceError::InvalidArguments),
    }
}

#[cfg(windows)]
pub fn run_from_args() -> Result<(), WindowsWorkOrderServiceError> {
    let mut arguments = env::args_os().skip(1);
    let command = arguments
        .next()
        .ok_or(WindowsWorkOrderServiceError::InvalidArguments)?;
    match command.to_str() {
        Some("install") => {
            let config_path = exact_config_argument(&mut arguments)?;
            install_service(&config_path)
        }
        Some("start") => {
            let initialize = match arguments.next() {
                None => false,
                Some(value) if value == "--initialize-identity" => true,
                Some(_) => return Err(WindowsWorkOrderServiceError::InvalidArguments),
            };
            if arguments.next().is_some() {
                return Err(WindowsWorkOrderServiceError::InvalidArguments);
            }
            start_service(initialize)
        }
        Some("stop") if arguments.next().is_none() => stop_service(),
        Some("uninstall") if arguments.next().is_none() => uninstall_service(),
        Some("run-once") => {
            let config_path = exact_config_argument(&mut arguments)?;
            let config = WindowsWorkOrderServiceConfig::parse(&read_public_bounded(
                &config_path,
                MAX_CONFIG_BYTES,
            )?)?;
            let (_sender, receiver) = mpsc::channel();
            run_worker(config, true, false, &receiver)
        }
        Some("service") => {
            let config_path = exact_config_argument(&mut arguments)?;
            SERVICE_CONFIG_PATH
                .set(config_path)
                .map_err(|_| WindowsWorkOrderServiceError::InvalidArguments)?;
            service_dispatcher::start(WINDOWS_SERVICE_NAME, ffi_service_main)
                .map_err(|_| WindowsWorkOrderServiceError::ServiceControl)
        }
        _ => Err(WindowsWorkOrderServiceError::InvalidArguments),
    }
}

#[cfg(not(windows))]
pub fn run_from_args() -> Result<(), WindowsWorkOrderServiceError> {
    Err(WindowsWorkOrderServiceError::ServiceControl)
}

#[cfg(windows)]
fn exact_config_argument(
    arguments: &mut impl Iterator<Item = OsString>,
) -> Result<PathBuf, WindowsWorkOrderServiceError> {
    if arguments.next().as_deref() != Some(OsStr::new("--config")) {
        return Err(WindowsWorkOrderServiceError::InvalidArguments);
    }
    let path = PathBuf::from(
        arguments
            .next()
            .ok_or(WindowsWorkOrderServiceError::InvalidArguments)?,
    );
    if arguments.next().is_some() || !safe_absolute_path(&path) {
        return Err(WindowsWorkOrderServiceError::InvalidArguments);
    }
    Ok(path)
}

#[cfg(windows)]
fn install_service(config_path: &Path) -> Result<(), WindowsWorkOrderServiceError> {
    let _ =
        WindowsWorkOrderServiceConfig::parse(&read_public_bounded(config_path, MAX_CONFIG_BYTES)?)?;
    let executable = env::current_exe()?;
    if !safe_absolute_path(&executable) {
        return Err(WindowsWorkOrderServiceError::InvalidArguments);
    }
    let manager = ServiceManager::local_computer(
        None::<&str>,
        ServiceManagerAccess::CONNECT | ServiceManagerAccess::CREATE_SERVICE,
    )
    .map_err(|_| WindowsWorkOrderServiceError::ServiceControl)?;
    let info = ServiceInfo {
        name: OsString::from(WINDOWS_SERVICE_NAME),
        display_name: OsString::from(WINDOWS_SERVICE_DISPLAY_NAME),
        service_type: ServiceType::OWN_PROCESS,
        start_type: ServiceStartType::OnDemand,
        error_control: ServiceErrorControl::Normal,
        executable_path: executable,
        launch_arguments: vec![
            OsString::from("service"),
            OsString::from("--config"),
            config_path.as_os_str().to_owned(),
        ],
        dependencies: vec![],
        account_name: Some(OsString::from(r"NT AUTHORITY\LocalService")),
        account_password: None,
    };
    let service = manager
        .create_service(
            &info,
            ServiceAccess::CHANGE_CONFIG | ServiceAccess::QUERY_STATUS,
        )
        .map_err(|_| WindowsWorkOrderServiceError::ServiceControl)?;
    service
        .set_description(
            "Off-default KernAid Fleet R0 diagnostics; no remote command or repair surface.",
        )
        .map_err(|_| WindowsWorkOrderServiceError::ServiceControl)
}

#[cfg(windows)]
fn start_service(initialize_identity: bool) -> Result<(), WindowsWorkOrderServiceError> {
    let manager = ServiceManager::local_computer(None::<&str>, ServiceManagerAccess::CONNECT)
        .map_err(|_| WindowsWorkOrderServiceError::ServiceControl)?;
    let service = manager
        .open_service(
            WINDOWS_SERVICE_NAME,
            ServiceAccess::START | ServiceAccess::QUERY_STATUS,
        )
        .map_err(|_| WindowsWorkOrderServiceError::ServiceControl)?;
    if initialize_identity {
        service.start(&[OsStr::new("--initialize-identity")])
    } else {
        service.start::<&OsStr>(&[])
    }
    .map_err(|_| WindowsWorkOrderServiceError::ServiceControl)
}

#[cfg(windows)]
fn stop_service() -> Result<(), WindowsWorkOrderServiceError> {
    let manager = ServiceManager::local_computer(None::<&str>, ServiceManagerAccess::CONNECT)
        .map_err(|_| WindowsWorkOrderServiceError::ServiceControl)?;
    let service = manager
        .open_service(
            WINDOWS_SERVICE_NAME,
            ServiceAccess::STOP | ServiceAccess::QUERY_STATUS,
        )
        .map_err(|_| WindowsWorkOrderServiceError::ServiceControl)?;
    if service
        .query_status()
        .map_err(|_| WindowsWorkOrderServiceError::ServiceControl)?
        .current_state
        != ServiceState::Stopped
    {
        service
            .stop()
            .map_err(|_| WindowsWorkOrderServiceError::ServiceControl)?;
    }
    Ok(())
}

#[cfg(windows)]
fn uninstall_service() -> Result<(), WindowsWorkOrderServiceError> {
    let manager = ServiceManager::local_computer(None::<&str>, ServiceManagerAccess::CONNECT)
        .map_err(|_| WindowsWorkOrderServiceError::ServiceControl)?;
    let service = manager
        .open_service(
            WINDOWS_SERVICE_NAME,
            ServiceAccess::STOP | ServiceAccess::QUERY_STATUS | ServiceAccess::DELETE,
        )
        .map_err(|_| WindowsWorkOrderServiceError::ServiceControl)?;
    service
        .delete()
        .map_err(|_| WindowsWorkOrderServiceError::ServiceControl)?;
    if service
        .query_status()
        .map_err(|_| WindowsWorkOrderServiceError::ServiceControl)?
        .current_state
        != ServiceState::Stopped
    {
        service
            .stop()
            .map_err(|_| WindowsWorkOrderServiceError::ServiceControl)?;
    }
    Ok(())
}

fn strict_base_url(endpoint: &str) -> Result<Url, ()> {
    if endpoint.is_empty() || endpoint.len() > MAX_ENDPOINT_BYTES {
        return Err(());
    }
    let url = Url::parse(endpoint).map_err(|_| ())?;
    if url.scheme() != "https"
        || url.cannot_be_a_base()
        || url.username() != ""
        || url.password().is_some()
        || url.host_str().is_none()
        || url.query().is_some()
        || url.fragment().is_some()
        || !matches!(url.path(), "" | "/")
    {
        return Err(());
    }
    Ok(url)
}

fn valid_https_origin(endpoint: &str) -> bool {
    strict_base_url(endpoint).is_ok()
}

fn valid_identifier(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 160
        && value.bytes().enumerate().all(|(index, byte)| {
            byte.is_ascii_alphanumeric() || (index > 0 && matches!(byte, b'.' | b'_' | b':' | b'-'))
        })
}

fn valid_sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn safe_absolute_path(path: &Path) -> bool {
    path.is_absolute()
        && path
            .components()
            .all(|component| !matches!(component, Component::ParentDir | Component::CurDir))
}

fn ensure_private_directory(path: &Path) -> Result<(), WindowsWorkOrderServiceError> {
    if !safe_absolute_path(path) {
        return Err(WindowsWorkOrderServiceError::InvalidConfig);
    }
    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.is_dir() && !metadata.file_type().is_symlink() => {}
        Err(error) if error.kind() == io::ErrorKind::NotFound => fs::create_dir_all(path)?,
        _ => return Err(WindowsWorkOrderServiceError::InvalidState),
    }
    let metadata = fs::symlink_metadata(path)?;
    if !metadata.is_dir() || metadata.file_type().is_symlink() {
        return Err(WindowsWorkOrderServiceError::InvalidState);
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};
        if metadata.uid() != rustix::process::getuid().as_raw() {
            return Err(WindowsWorkOrderServiceError::InvalidState);
        }
        fs::set_permissions(path, fs::Permissions::from_mode(0o700))?;
    }
    Ok(())
}

#[cfg(windows)]
fn open_service_lock(path: &Path) -> Result<File, WindowsWorkOrderServiceError> {
    if let Ok(metadata) = fs::symlink_metadata(path) {
        if !metadata.is_file() || metadata.file_type().is_symlink() {
            return Err(WindowsWorkOrderServiceError::InvalidState);
        }
    }
    let mut options = OpenOptions::new();
    options.read(true).write(true).create(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let file = options.open(path)?;
    file.try_lock_exclusive()
        .map_err(|_| WindowsWorkOrderServiceError::InvalidState)?;
    Ok(file)
}

fn cleanup_pending(path: &Path) -> Result<(), WindowsWorkOrderServiceError> {
    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.is_file() && !metadata.file_type().is_symlink() => {
            fs::remove_file(path)?;
            Ok(())
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        _ => Err(WindowsWorkOrderServiceError::InvalidState),
    }
}

#[cfg(windows)]
fn read_public_bounded(path: &Path, maximum: usize) -> io::Result<Vec<u8>> {
    let metadata = fs::symlink_metadata(path)?;
    if !metadata.is_file()
        || metadata.file_type().is_symlink()
        || metadata.len() == 0
        || metadata.len() > maximum as u64
    {
        return Err(io::Error::other("bounded public file rejected"));
    }
    let bytes = fs::read(path)?;
    if bytes.is_empty() || bytes.len() > maximum || bytes.len() as u64 != metadata.len() {
        return Err(io::Error::other("bounded public file changed"));
    }
    Ok(bytes)
}

#[cfg(windows)]
fn read_public_anchor(path: &Path) -> Result<[u8; 32], WindowsWorkOrderServiceError> {
    let bytes = read_public_bounded(path, MAX_ANCHOR_FILE_BYTES)?;
    let line = bytes
        .strip_suffix(b"\r\n")
        .or_else(|| bytes.strip_suffix(b"\n"))
        .unwrap_or(&bytes);
    if line.is_empty() || line.contains(&b'\r') || line.contains(&b'\n') || line.contains(&b'=') {
        return Err(WindowsWorkOrderServiceError::InvalidConfig);
    }
    let decoded = URL_SAFE_NO_PAD
        .decode(line)
        .map_err(|_| WindowsWorkOrderServiceError::InvalidConfig)?;
    decoded
        .try_into()
        .map_err(|_| WindowsWorkOrderServiceError::InvalidConfig)
}

fn read_bounded_optional(path: &Path, maximum: usize) -> io::Result<Option<Vec<u8>>> {
    let metadata = match fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error),
    };
    if !metadata.is_file()
        || metadata.file_type().is_symlink()
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

#[cfg(windows)]
fn write_state_atomic(
    directory: &Path,
    name: &str,
    _pending_name: &str,
    bytes: &[u8],
) -> io::Result<()> {
    use atomic_write_file::AtomicWriteFile;

    let mut file = AtomicWriteFile::open(directory.join(name))?;
    file.write_all(bytes)?;
    file.flush()?;
    file.commit()
}

#[cfg(not(windows))]
fn write_state_atomic(
    directory: &Path,
    name: &str,
    pending_name: &str,
    bytes: &[u8],
) -> io::Result<()> {
    let pending = directory.join(pending_name);
    let destination = directory.join(name);
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options.open(&pending)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    fs::rename(pending, destination)
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

fn digest_fields(domain: &[u8], fields: &[&str]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(domain);
    for field in fields {
        hasher.update((field.len() as u64).to_be_bytes());
        hasher.update(field.as_bytes());
    }
    hex_sha256(&hasher.finalize())
}

fn sha256_hex(bytes: &[u8]) -> String {
    hex_sha256(&Sha256::digest(bytes))
}

fn hex_sha256(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
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
            if action != WorkOrderActionId::WindowsP0DiagnoseV1 {
                return Err(LocalHandoffErrorCode::StateMismatch);
            }
            self.calls.fetch_add(1, Ordering::SeqCst);
            Ok(br#"{"diagnosis":"bounded-fixture"}"#.to_vec())
        }
    }

    fn prepared(execution_id: &str) -> PreparedLocalExecution {
        PreparedLocalExecution {
            execution_id: execution_id.to_owned(),
            work_order_id: "wo_windows_fixture".to_owned(),
            lease_id: "lease_windows_fixture".to_owned(),
            action_id: WorkOrderActionId::WindowsP0DiagnoseV1,
            action_version: 1,
            plan_sha256: digest_fields(
                PLAN_DIGEST_DOMAIN,
                &[
                    execution_id,
                    WorkOrderActionId::WindowsP0DiagnoseV1.wire_name(),
                    "1",
                ],
            ),
            target_sha256: digest_fields(
                TARGET_DIGEST_DOMAIN,
                &[
                    "KA-0123456789abcdef01234567",
                    WorkOrderActionId::WindowsP0DiagnoseV1.wire_name(),
                ],
            ),
            local_approval: None,
        }
    }

    #[test]
    fn config_rejects_secret_and_command_fields() {
        let payload = br#"{"schema":"dev.kernaid.fleet.resident-windows-service-config.v1","endpoint":"https://fleet.example.invalid","tenantId":"tenant-a","stateDirectory":"/tmp/state","runtimeStateFile":"/tmp/runtime","serviceReceiptAnchorFile":"/tmp/service.pub","entitlementAnchorFile":"/tmp/entitlement.pub","policyAnchorFile":"/tmp/policy.pub","intervalSeconds":60,"minimumBackoffSeconds":2,"maximumBackoffSeconds":120,"connectTimeoutSeconds":5,"requestTimeoutSeconds":30,"leaseSeconds":300,"command":"cmd.exe","token":"secret"}"#;
        assert!(WindowsWorkOrderServiceConfig::parse(payload).is_err());
    }

    #[test]
    fn diagnostic_handoff_replays_completed_digest_without_recollecting()
    -> Result<(), Box<dyn Error>> {
        let root = TempDir::new()?;
        let calls = Arc::new(AtomicUsize::new(0));
        let mut first = WindowsDiagnosticHandoff::with_collector(
            root.path(),
            "KA-0123456789abcdef01234567",
            FixedCollector {
                calls: Arc::clone(&calls),
            },
        )?;
        let initial = first
            .execute_or_recover(&prepared("exec_windows_fixture"))
            .map_err(|_| io::Error::other("initial diagnostic failed"))?;
        drop(first);
        let mut reopened = WindowsDiagnosticHandoff::with_collector(
            root.path(),
            "KA-0123456789abcdef01234567",
            FixedCollector {
                calls: Arc::clone(&calls),
            },
        )?;
        let replay = reopened
            .execute_or_recover(&prepared("exec_windows_fixture"))
            .map_err(|_| io::Error::other("diagnostic replay failed"))?;
        assert_eq!(initial, replay);
        assert_eq!(calls.load(Ordering::SeqCst), 1);

        reopened
            .execute_or_recover(&prepared("exec_windows_fixture_2"))
            .map_err(|_| io::Error::other("next diagnostic failed"))?;
        assert_eq!(calls.load(Ordering::SeqCst), 2);
        Ok(())
    }

    #[test]
    fn handoff_rejects_non_windows_action_before_collection() -> Result<(), Box<dyn Error>> {
        let root = TempDir::new()?;
        let calls = Arc::new(AtomicUsize::new(0));
        let mut handoff = WindowsDiagnosticHandoff::with_collector(
            root.path(),
            "KA-0123456789abcdef01234567",
            FixedCollector {
                calls: Arc::clone(&calls),
            },
        )?;
        let mut invalid = prepared("exec_windows_fixture");
        invalid.action_id = WorkOrderActionId::LinuxFilesystemHealthV1;
        assert!(handoff.execute_or_recover(&invalid).is_err());
        assert_eq!(calls.load(Ordering::SeqCst), 0);
        Ok(())
    }
}
