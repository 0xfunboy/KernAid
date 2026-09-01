//! Installable, off-default macOS Fleet Resident for one closed R0 action.
//!
//! Only `macos.p0.diagnose.v1` is admitted. The work order and public
//! configuration cannot select a command, argument, path, collector, script,
//! or repair. Native collection uses the fixed bounded contract shared with
//! Desk through `kernaid_macos_pack::resident`.

use super::{
    LocalExecutionResult, LocalHandoffErrorCode, LocalWorkOrderHandoff, PreparedLocalExecution,
    ResidentWorkOrderError, ResidentWorkOrderTransport, TransportErrorCode,
    WorkOrderTransportResponse,
};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
#[cfg(target_os = "macos")]
use fs2::FileExt as _;
use kernaid_device_identity::validate_device_id;
use kernaid_fleet_client::{LeasedWorkOrder, WorkOrderActionId, WorkOrderResultOutcome};
use kernaid_fleet_runtime::FleetRuntimeError;
use reqwest::{
    Url,
    blocking::{Client, Response},
    header::{ACCEPT, CONTENT_LENGTH, CONTENT_TYPE, HeaderName},
    redirect::Policy,
};
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::{
    error::Error,
    fmt,
    fs::{self, File, OpenOptions},
    io::{self, Read, Write},
    os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt},
    path::{Component, Path, PathBuf},
    time::Duration,
};

#[cfg(target_os = "macos")]
use super::{
    ResidentPlatform, ResidentWorkOrderEngine, WorkOrderAuthorization, WorkOrderCycleInput,
    WorkOrderCycleOutcome,
};
#[cfg(target_os = "macos")]
use chrono::{SecondsFormat, Utc};
#[cfg(target_os = "macos")]
use kernaid_device_identity::DeviceIdentity;
#[cfg(target_os = "macos")]
use kernaid_fleet_policy::{RiskLevel, TransportState};
#[cfg(target_os = "macos")]
use kernaid_fleet_runtime::FleetRuntime;
#[cfg(target_os = "macos")]
use kernaid_native_secrets::NativeDeviceIdentityStore;
#[cfg(target_os = "macos")]
use rand_core::{OsRng, RngCore};
#[cfg(target_os = "macos")]
use std::{
    collections::BTreeMap,
    env,
    ffi::OsStr,
    os::unix::process::CommandExt as _,
    process::{Child, Command, Stdio},
    thread,
    time::{Instant, SystemTime, UNIX_EPOCH},
};
#[cfg(target_os = "macos")]
use zeroize::Zeroizing;

pub const MACOS_SERVICE_CONFIG_SCHEMA: &str = "dev.kernaid.fleet.resident-macos-service-config.v1";
pub const RESIDENT_IDENTITY_NAMESPACE: &str = "resident-v1";

const CLAIM_ROUTE: &str = "/v1/work-order-claims";
const RESULT_ROUTE: &str = "/v1/work-order-results";
const RECEIPT_HEADER: HeaderName = HeaderName::from_static("x-kernaid-fleet-receipt");
#[cfg(target_os = "macos")]
const SERVICE_LOCK_FILE: &str = ".resident-macos-v1.lock";
#[cfg(target_os = "macos")]
const WORK_ORDER_STATE_DIRECTORY: &str = "protocol";
#[cfg(target_os = "macos")]
const EXECUTION_STATE_DIRECTORY: &str = "diagnostics";
const EXECUTION_STATE_FILE: &str = "execution-v1.cjson";
const EXECUTION_PENDING_FILE: &str = ".execution-v1.pending";
const EXECUTION_STATE_SCHEMA: &str = "dev.kernaid.fleet.macos-diagnostic-execution.v1";
const PLAN_DIGEST_DOMAIN: &[u8] = b"kernaid:fleet:macos-p0-plan:v1\0";
const TARGET_DIGEST_DOMAIN: &[u8] = b"kernaid:fleet:macos-p0-target:v1\0";
const MAX_CONFIG_BYTES: usize = 16 * 1024;
#[cfg(target_os = "macos")]
const MAX_ANCHOR_FILE_BYTES: usize = 128;
const MAX_REQUEST_BYTES: usize = 64 * 1024;
const MAX_RECEIPT_HEADER_BYTES: usize = 8 * 1024;
const MAX_EXECUTION_STATE_BYTES: usize = 8 * 1024;
const MAX_DIAGNOSTIC_BYTES: usize = 64 * 1024;
#[cfg(target_os = "macos")]
const MAX_NATIVE_OUTPUT_BYTES: usize = 1024 * 1024;
const MAX_ENDPOINT_BYTES: usize = 4 * 1024;
const MAX_IDENTIFIER_BYTES: usize = 160;
const MIN_INTERVAL_SECONDS: u64 = 30;
const MAX_INTERVAL_SECONDS: u64 = 24 * 60 * 60;
const MAX_BACKOFF_SECONDS: u64 = 60 * 60;
const MAX_CONNECT_TIMEOUT_SECONDS: u64 = 30;
const MAX_REQUEST_TIMEOUT_SECONDS: u64 = 180;
#[cfg(target_os = "macos")]
const TERMINATION_GRACE: Duration = Duration::from_millis(250);

/// Strict public configuration. Unknown fields, secrets and caller-selected
/// executable or collector fields are rejected by construction.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct MacosWorkOrderServiceConfig {
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

impl MacosWorkOrderServiceConfig {
    pub fn parse(bytes: &[u8]) -> Result<Self, MacosWorkOrderServiceError> {
        if bytes.is_empty() || bytes.len() > MAX_CONFIG_BYTES {
            return Err(MacosWorkOrderServiceError::InvalidConfig);
        }
        let config: Self =
            serde_json::from_slice(bytes).map_err(|_| MacosWorkOrderServiceError::InvalidConfig)?;
        config.validate()?;
        Ok(config)
    }

    fn validate(&self) -> Result<(), MacosWorkOrderServiceError> {
        if self.schema != MACOS_SERVICE_CONFIG_SCHEMA
            || !valid_https_origin(&self.endpoint)
            || !valid_identifier(&self.tenant_id)
            || !safe_absolute_directory(&self.state_directory)
            || !safe_absolute_file(&self.runtime_state_file)
            || !safe_absolute_file(&self.service_receipt_anchor_file)
            || !safe_absolute_file(&self.entitlement_anchor_file)
            || !safe_absolute_file(&self.policy_anchor_file)
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
            return Err(MacosWorkOrderServiceError::InvalidConfig);
        }
        let files = [
            &self.runtime_state_file,
            &self.service_receipt_anchor_file,
            &self.entitlement_anchor_file,
            &self.policy_anchor_file,
        ];
        for (index, file) in files.iter().enumerate() {
            if files[..index].contains(file) {
                return Err(MacosWorkOrderServiceError::InvalidConfig);
            }
        }
        Ok(())
    }
}

#[derive(Debug)]
pub enum MacosWorkOrderServiceError {
    InvalidArguments,
    InvalidConfig,
    InvalidState,
    UnsupportedPlatform,
    IdentityUnavailable,
    ClockUnavailable,
    NonceUnavailable,
    Runtime(FleetRuntimeError),
    Resident(ResidentWorkOrderError),
    Io(io::Error),
}

impl MacosWorkOrderServiceError {
    #[must_use]
    pub const fn code(&self) -> &'static str {
        match self {
            Self::InvalidArguments => "arguments-invalid",
            Self::InvalidConfig => "config-invalid",
            Self::InvalidState => "state-invalid",
            Self::UnsupportedPlatform => "platform-unsupported",
            Self::IdentityUnavailable => "identity-unavailable",
            Self::ClockUnavailable => "clock-unavailable",
            Self::NonceUnavailable => "nonce-unavailable",
            Self::Runtime(_) => "runtime-unavailable",
            Self::Resident(error) => error.code(),
            Self::Io(_) => "io-failed",
        }
    }

    #[cfg(target_os = "macos")]
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

impl fmt::Display for MacosWorkOrderServiceError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.code())
    }
}

impl Error for MacosWorkOrderServiceError {}

impl From<io::Error> for MacosWorkOrderServiceError {
    fn from(value: io::Error) -> Self {
        Self::Io(value)
    }
}

impl From<ResidentWorkOrderError> for MacosWorkOrderServiceError {
    fn from(value: ResidentWorkOrderError) -> Self {
        Self::Resident(value)
    }
}

impl From<FleetRuntimeError> for MacosWorkOrderServiceError {
    fn from(value: FleetRuntimeError) -> Self {
        Self::Runtime(value)
    }
}

/// HTTPS-only transport with exactly two same-origin POST routes, no proxy,
/// no redirects, no bearer token and bounded responses.
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
    ) -> Result<Self, MacosWorkOrderServiceError> {
        let base =
            strict_base_url(endpoint).map_err(|()| MacosWorkOrderServiceError::InvalidConfig)?;
        let origin = base.origin().ascii_serialization();
        let _ = rustls::crypto::ring::default_provider().install_default();
        let client = Client::builder()
            .https_only(true)
            .no_proxy()
            .redirect(Policy::none())
            .connect_timeout(Duration::from_secs(connect_timeout_seconds))
            .timeout(Duration::from_secs(request_timeout_seconds))
            .user_agent(concat!(
                "KernAid-Fleet-Resident-macOS/",
                env!("CARGO_PKG_VERSION")
            ))
            .build()
            .map_err(|_| MacosWorkOrderServiceError::InvalidConfig)?;
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
            || self.action_id != WorkOrderActionId::MacosP0DiagnoseV1
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

/// Closed durable handoff. It retains only opaque bindings and the terminal
/// result digest, never native output or diagnostic content.
struct MacosDiagnosticHandoff<C> {
    directory: PathBuf,
    device_id: String,
    collector: C,
}

impl<C: DiagnosticCollector> MacosDiagnosticHandoff<C> {
    fn with_collector(
        directory: &Path,
        device_id: &str,
        collector: C,
    ) -> Result<Self, MacosWorkOrderServiceError> {
        ensure_private_directory(directory)?;
        cleanup_temporary(&directory.join(EXECUTION_PENDING_FILE))?;
        validate_device_id(device_id).map_err(|_| MacosWorkOrderServiceError::InvalidState)?;
        Ok(Self {
            directory: directory.to_path_buf(),
            device_id: device_id.to_owned(),
            collector,
        })
    }

    fn read_record(&self) -> Result<Option<DiagnosticExecutionRecord>, LocalHandoffErrorCode> {
        let Some(bytes) = read_private_optional(
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
        if bytes.is_empty() || bytes.len() > MAX_EXECUTION_STATE_BYTES {
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

impl<C: DiagnosticCollector> LocalWorkOrderHandoff for MacosDiagnosticHandoff<C> {
    fn prepare(
        &mut self,
        order: &LeasedWorkOrder,
        execution_id: &str,
    ) -> Result<PreparedLocalExecution, LocalHandoffErrorCode> {
        if order.action_id() != WorkOrderActionId::MacosP0DiagnoseV1
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
                WorkOrderActionId::MacosP0DiagnoseV1.wire_name(),
                "1",
            ],
        );
        let target_sha256 = digest_fields(
            TARGET_DIGEST_DOMAIN,
            &[
                &self.device_id,
                WorkOrderActionId::MacosP0DiagnoseV1.wire_name(),
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
        if prepared.action_id() != WorkOrderActionId::MacosP0DiagnoseV1
            || prepared.action_version() != 1
            || prepared.local_approval().is_some()
            || prepared.plan_sha256()
                != digest_fields(
                    PLAN_DIGEST_DOMAIN,
                    &[
                        prepared.execution_id(),
                        WorkOrderActionId::MacosP0DiagnoseV1.wire_name(),
                        "1",
                    ],
                )
            || prepared.target_sha256()
                != digest_fields(
                    TARGET_DIGEST_DOMAIN,
                    &[
                        &self.device_id,
                        WorkOrderActionId::MacosP0DiagnoseV1.wire_name(),
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
            if retained.state == ExecutionState::Pending && !retained.matches(prepared) {
                return Err(LocalHandoffErrorCode::StateMismatch);
            }
        }

        self.persist_record(&record)?;
        let document = self
            .collector
            .collect(WorkOrderActionId::MacosP0DiagnoseV1)?;
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

#[cfg(target_os = "macos")]
struct SystemMacosP0Collector;

#[cfg(target_os = "macos")]
impl DiagnosticCollector for SystemMacosP0Collector {
    fn collect(&mut self, action: WorkOrderActionId) -> Result<Vec<u8>, LocalHandoffErrorCode> {
        use kernaid_macos_pack::{
            EvidenceInput, MacosP0Inputs, diagnose_macos_p0, proposal_from_report,
        };

        if action != WorkOrderActionId::MacosP0DiagnoseV1 {
            return Err(LocalHandoffErrorCode::StateMismatch);
        }
        let documents = collect_macos_p0_documents()?;
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
        let report = diagnose_macos_p0(MacosP0Inputs {
            storage: input("macos.storage.inventory", "E-MACOS-FLEET-1")?,
            apfs: input("macos.apfs.capacity", "E-MACOS-FLEET-2")?,
            launchd: input("macos.launchd.state", "E-MACOS-FLEET-3")?,
            network: input("macos.network.state", "E-MACOS-FLEET-4")?,
            updates: input("macos.software-update.state", "E-MACOS-FLEET-5")?,
            events: input("macos.system-events.summary", "E-MACOS-FLEET-6")?,
            startup: input("macos.startup.state", "E-MACOS-FLEET-7")?,
            snapshots: input("macos.snapshots.inventory", "E-MACOS-FLEET-8")?,
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

#[cfg(target_os = "macos")]
impl MacosDiagnosticHandoff<SystemMacosP0Collector> {
    fn open(directory: &Path, device_id: &str) -> Result<Self, MacosWorkOrderServiceError> {
        Self::with_collector(directory, device_id, SystemMacosP0Collector)
    }
}

#[cfg(target_os = "macos")]
struct FixedCommandOutput {
    stdout: String,
    stderr: String,
    exit_code: i32,
}

#[cfg(target_os = "macos")]
fn collect_macos_p0_documents() -> Result<BTreeMap<&'static str, String>, LocalHandoffErrorCode> {
    use kernaid_macos_pack::resident;

    let started = Instant::now();
    let results = thread::scope(|scope| {
        let storage = scope.spawn(collect_storage);
        let apfs = scope.spawn(collect_apfs);
        let launchd = scope.spawn(collect_launchd);
        let network = scope.spawn(collect_network);
        let startup = scope.spawn(collect_startup);
        let snapshots = scope.spawn(collect_snapshots);
        [
            join_collector(storage),
            join_collector(apfs),
            join_collector(launchd),
            join_collector(network),
            join_collector(startup),
            join_collector(snapshots),
            projection(
                "macos.software-update.state",
                resident::updates_unqualified_projection(),
            ),
            projection(
                "macos.system-events.summary",
                resident::events_unqualified_projection(),
            ),
        ]
    });
    if started.elapsed() > kernaid_macos_pack::resident::P0_WALL_CLOCK_BUDGET {
        return Err(LocalHandoffErrorCode::ExecutionFailed);
    }
    let mut documents = BTreeMap::new();
    for result in results {
        let (collector, document) = result?;
        if documents.insert(collector, document).is_some() {
            return Err(LocalHandoffErrorCode::ExecutionFailed);
        }
    }
    if documents.len() != kernaid_macos_pack::resident::COLLECTORS.len()
        || kernaid_macos_pack::resident::COLLECTORS
            .iter()
            .any(|collector| !documents.contains_key(collector))
    {
        return Err(LocalHandoffErrorCode::ExecutionFailed);
    }
    Ok(documents)
}

#[cfg(target_os = "macos")]
fn join_collector(
    handle: thread::ScopedJoinHandle<'_, Result<(&'static str, String), LocalHandoffErrorCode>>,
) -> Result<(&'static str, String), LocalHandoffErrorCode> {
    handle
        .join()
        .map_err(|_| LocalHandoffErrorCode::ExecutionFailed)?
}

#[cfg(target_os = "macos")]
fn projection(
    collector: &'static str,
    document: Result<String, ()>,
) -> Result<(&'static str, String), LocalHandoffErrorCode> {
    let document = document.map_err(|()| LocalHandoffErrorCode::ExecutionFailed)?;
    if document.is_empty()
        || document.len() > MAX_NATIVE_OUTPUT_BYTES
        || kernaid_macos_pack::resident::validate_projection(collector, &document).is_err()
    {
        return Err(LocalHandoffErrorCode::ExecutionFailed);
    }
    Ok((collector, document))
}

#[cfg(target_os = "macos")]
fn collect_storage() -> Result<(&'static str, String), LocalHandoffErrorCode> {
    use kernaid_macos_pack::resident;
    let output = complete(run_fixed_command(
        resident::SYSTEM_PROFILER,
        &resident::SYSTEM_PROFILER_ARGS,
        resident::STORAGE_TIMEOUT,
    )?)?;
    projection(
        "macos.storage.inventory",
        resident::normalize_storage(&output.stdout),
    )
}

#[cfg(target_os = "macos")]
fn collect_apfs() -> Result<(&'static str, String), LocalHandoffErrorCode> {
    use kernaid_macos_pack::resident;
    let (list, root) = thread::scope(|scope| {
        let list = scope.spawn(|| {
            run_fixed_command(
                resident::DISKUTIL,
                &resident::APFS_LIST_ARGS,
                resident::STANDARD_TIMEOUT,
            )
            .and_then(complete)
        });
        let root = scope.spawn(|| {
            run_fixed_command(
                resident::DISKUTIL,
                &resident::ROOT_INFO_ARGS,
                resident::STANDARD_TIMEOUT,
            )
            .and_then(complete)
        });
        Ok::<_, LocalHandoffErrorCode>((
            list.join()
                .map_err(|_| LocalHandoffErrorCode::ExecutionFailed)?,
            root.join()
                .map_err(|_| LocalHandoffErrorCode::ExecutionFailed)?,
        ))
    })?;
    let list = list?;
    let root = root?;
    projection(
        "macos.apfs.capacity",
        resident::normalize_apfs(list.stdout.as_bytes(), root.stdout.as_bytes()),
    )
}

#[cfg(target_os = "macos")]
fn collect_launchd() -> Result<(&'static str, String), LocalHandoffErrorCode> {
    use kernaid_macos_pack::resident;
    let output = complete(run_fixed_command(
        resident::LAUNCHCTL,
        &resident::LAUNCHCTL_ARGS,
        resident::STANDARD_TIMEOUT,
    )?)?;
    projection(
        "macos.launchd.state",
        resident::normalize_launchd_user(&output.stdout),
    )
}

#[cfg(target_os = "macos")]
fn collect_network() -> Result<(&'static str, String), LocalHandoffErrorCode> {
    use kernaid_macos_pack::resident;
    let (nwi, route, dns) = thread::scope(|scope| {
        let nwi = scope.spawn(|| {
            run_fixed_command(
                resident::SCUTIL,
                &resident::NWI_ARGS,
                resident::STANDARD_TIMEOUT,
            )
            .and_then(complete)
        });
        let route = scope.spawn(|| {
            run_fixed_command(
                resident::ROUTE,
                &resident::ROUTE_ARGS,
                resident::STANDARD_TIMEOUT,
            )
            .and_then(complete_route)
        });
        let dns = scope.spawn(|| {
            run_fixed_command(
                resident::SCUTIL,
                &resident::DNS_ARGS,
                resident::STANDARD_TIMEOUT,
            )
            .and_then(complete)
        });
        Ok::<_, LocalHandoffErrorCode>((
            nwi.join()
                .map_err(|_| LocalHandoffErrorCode::ExecutionFailed)?,
            route
                .join()
                .map_err(|_| LocalHandoffErrorCode::ExecutionFailed)?,
            dns.join()
                .map_err(|_| LocalHandoffErrorCode::ExecutionFailed)?,
        ))
    })?;
    let nwi = nwi?;
    let route = route?;
    let dns = dns?;
    projection(
        "macos.network.state",
        resident::normalize_network(&nwi.stdout, route.exit_code, &dns.stdout),
    )
}

#[cfg(target_os = "macos")]
fn collect_startup() -> Result<(&'static str, String), LocalHandoffErrorCode> {
    use kernaid_macos_pack::resident;
    let output = complete(run_fixed_command(
        resident::SYSCTL,
        &resident::SAFE_BOOT_ARGS,
        resident::STANDARD_TIMEOUT,
    )?)?;
    projection(
        "macos.startup.state",
        resident::normalize_startup(&output.stdout),
    )
}

#[cfg(target_os = "macos")]
fn collect_snapshots() -> Result<(&'static str, String), LocalHandoffErrorCode> {
    use kernaid_macos_pack::resident;
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| LocalHandoffErrorCode::ExecutionFailed)?
        .as_secs();
    let output = complete(run_fixed_command(
        resident::TMUTIL,
        &resident::SNAPSHOT_ARGS,
        resident::STANDARD_TIMEOUT,
    )?)?;
    projection(
        "macos.snapshots.inventory",
        resident::normalize_snapshots(&output.stdout, now),
    )
}

#[cfg(target_os = "macos")]
fn complete(output: FixedCommandOutput) -> Result<FixedCommandOutput, LocalHandoffErrorCode> {
    if output.exit_code != 0 || !output.stderr.trim().is_empty() {
        return Err(LocalHandoffErrorCode::ExecutionFailed);
    }
    Ok(output)
}

#[cfg(target_os = "macos")]
fn complete_route(output: FixedCommandOutput) -> Result<FixedCommandOutput, LocalHandoffErrorCode> {
    if !matches!(output.exit_code, 0 | 1) {
        return Err(LocalHandoffErrorCode::ExecutionFailed);
    }
    Ok(output)
}

#[cfg(target_os = "macos")]
fn run_fixed_command(
    program: &'static str,
    args: &[&'static str],
    timeout: Duration,
) -> Result<FixedCommandOutput, LocalHandoffErrorCode> {
    let mut command = Command::new(program);
    command
        .args(args)
        .env_clear()
        .env("LC_ALL", "C")
        .env("LANG", "C")
        .env("PATH", "/usr/sbin:/usr/bin:/sbin:/bin")
        .current_dir("/")
        .process_group(0)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let mut child = command
        .spawn()
        .map_err(|_| LocalHandoffErrorCode::ExecutionFailed)?;
    let stdout = child
        .stdout
        .take()
        .ok_or(LocalHandoffErrorCode::ExecutionFailed)?;
    let stderr = child
        .stderr
        .take()
        .ok_or(LocalHandoffErrorCode::ExecutionFailed)?;
    let stdout = spawn_bounded_reader(stdout);
    let stderr = spawn_bounded_reader(stderr);
    let deadline = Instant::now() + timeout;
    let status = loop {
        match child.try_wait() {
            Ok(Some(status)) => break status,
            Ok(None) if Instant::now() < deadline => thread::sleep(Duration::from_millis(20)),
            Ok(None) | Err(_) => {
                terminate_process_group(&mut child);
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

#[cfg(target_os = "macos")]
fn spawn_bounded_reader(
    mut reader: impl Read + Send + 'static,
) -> thread::JoinHandle<Result<Vec<u8>, LocalHandoffErrorCode>> {
    thread::spawn(move || {
        let mut retained = Vec::with_capacity(64 * 1024);
        let mut exceeded = false;
        let mut buffer = [0_u8; 8192];
        loop {
            let read = reader
                .read(&mut buffer)
                .map_err(|_| LocalHandoffErrorCode::ExecutionFailed)?;
            if read == 0 {
                return if exceeded {
                    Err(LocalHandoffErrorCode::ExecutionFailed)
                } else {
                    Ok(retained)
                };
            }
            let remaining = MAX_NATIVE_OUTPUT_BYTES.saturating_sub(retained.len());
            retained.extend_from_slice(&buffer[..read.min(remaining)]);
            exceeded |= read > remaining;
        }
    })
}

#[cfg(target_os = "macos")]
fn terminate_process_group(child: &mut Child) {
    let group = rustix::process::Pid::from_child(&*child);
    let _ = rustix::process::kill_process_group(group, rustix::process::Signal::TERM);
    let deadline = Instant::now() + TERMINATION_GRACE;
    while Instant::now() < deadline {
        if matches!(child.try_wait(), Ok(Some(_))) {
            return;
        }
        thread::sleep(Duration::from_millis(10));
    }
    let _ = rustix::process::kill_process_group(group, rustix::process::Signal::KILL);
    let _ = child.wait();
}

#[cfg(target_os = "macos")]
pub fn run_from_args() -> Result<(), MacosWorkOrderServiceError> {
    let mut arguments = env::args_os().skip(1);
    if arguments.next().as_deref() != Some(OsStr::new("--config")) {
        return Err(MacosWorkOrderServiceError::InvalidArguments);
    }
    let config_path = PathBuf::from(
        arguments
            .next()
            .ok_or(MacosWorkOrderServiceError::InvalidArguments)?,
    );
    let once = match arguments.next() {
        None => false,
        Some(value) if value == "--once" => true,
        Some(_) => return Err(MacosWorkOrderServiceError::InvalidArguments),
    };
    if arguments.next().is_some() || !safe_absolute_file(&config_path) {
        return Err(MacosWorkOrderServiceError::InvalidArguments);
    }
    let config =
        MacosWorkOrderServiceConfig::parse(&read_public_bounded(&config_path, MAX_CONFIG_BYTES)?)?;
    run_service(config, once)
}

#[cfg(not(target_os = "macos"))]
pub fn run_from_args() -> Result<(), MacosWorkOrderServiceError> {
    Err(MacosWorkOrderServiceError::UnsupportedPlatform)
}

#[cfg(target_os = "macos")]
pub fn run_service(
    config: MacosWorkOrderServiceConfig,
    once: bool,
) -> Result<(), MacosWorkOrderServiceError> {
    config.validate()?;
    ensure_private_directory(&config.state_directory)?;
    let _lock = open_service_lock(&config.state_directory.join(SERVICE_LOCK_FILE))?;
    let service_anchor = read_public_anchor(&config.service_receipt_anchor_file)?;
    let entitlement_anchor = read_public_anchor(&config.entitlement_anchor_file)?;
    let policy_anchor = read_public_anchor(&config.policy_anchor_file)?;
    let mut identity_store = NativeDeviceIdentityStore::open_named(RESIDENT_IDENTITY_NAMESPACE)
        .map_err(|_| MacosWorkOrderServiceError::IdentityUnavailable)?;
    let identity = identity_store
        .load_device_identity()
        .map_err(|_| MacosWorkOrderServiceError::IdentityUnavailable)?
        .ok_or(MacosWorkOrderServiceError::IdentityUnavailable)?;
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
    let mut handoff = MacosDiagnosticHandoff::open(
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
                    "KERNAID_FLEET_RESIDENT_MACOS_V1 status=offline code={}",
                    error.code()
                );
                thread::sleep(Duration::from_secs(backoff));
                backoff = backoff
                    .saturating_mul(2)
                    .min(config.maximum_backoff_seconds);
            }
            Err(error) => return Err(error),
        }
    }
}

#[cfg(target_os = "macos")]
fn run_cycle<T: ResidentWorkOrderTransport, H: LocalWorkOrderHandoff>(
    config: &MacosWorkOrderServiceConfig,
    runtime: &FleetRuntime,
    identity: &DeviceIdentity,
    engine: &mut ResidentWorkOrderEngine<T>,
    handoff: &mut H,
) -> Result<WorkOrderCycleOutcome, MacosWorkOrderServiceError> {
    let now = Utc::now();
    let now_unix =
        u64::try_from(now.timestamp()).map_err(|_| MacosWorkOrderServiceError::ClockUnavailable)?;
    let mut nonce = Zeroizing::new(vec![0_u8; 32]);
    OsRng
        .try_fill_bytes(&mut nonce)
        .map_err(|_| MacosWorkOrderServiceError::NonceUnavailable)?;
    let capabilities = runtime.capabilities(now_unix);
    let policies = runtime.applicable_policies(now_unix, TransportState::Online)?;
    let authorization = WorkOrderAuthorization {
        platform: ResidentPlatform::Macos,
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
        return Err(MacosWorkOrderServiceError::InvalidState);
    }
    Ok(outcome)
}

#[cfg(target_os = "macos")]
fn print_outcome(outcome: &WorkOrderCycleOutcome) {
    match outcome {
        WorkOrderCycleOutcome::NoWork => {
            println!("KERNAID_FLEET_RESIDENT_MACOS_V1 status=ok outcome=no-work writes=disabled")
        }
        WorkOrderCycleOutcome::Completed { outcome, .. } => println!(
            "KERNAID_FLEET_RESIDENT_MACOS_V1 status=ok outcome={outcome:?} writes=disabled"
        ),
        WorkOrderCycleOutcome::AwaitingLocalApproval { .. } => {
            eprintln!("KERNAID_FLEET_RESIDENT_MACOS_V1 status=failed code=unexpected-write-order")
        }
    }
}

fn strict_base_url(endpoint: &str) -> Result<Url, ()> {
    if endpoint.is_empty() || endpoint.len() > MAX_ENDPOINT_BYTES {
        return Err(());
    }
    let mut url = Url::parse(endpoint).map_err(|_| ())?;
    if url.scheme() != "https"
        || url.cannot_be_a_base()
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

fn safe_path_components(path: &Path) -> bool {
    path.components()
        .all(|part| !matches!(part, Component::CurDir | Component::ParentDir))
}

fn safe_absolute_directory(path: &Path) -> bool {
    path.is_absolute()
        && path != Path::new("/")
        && path.file_name().is_some()
        && safe_path_components(path)
}

fn safe_absolute_file(path: &Path) -> bool {
    path.is_absolute()
        && path.parent().is_some_and(safe_absolute_directory)
        && path.file_name().is_some()
        && safe_path_components(path)
}

fn valid_identifier(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= MAX_IDENTIFIER_BYTES
        && value.bytes().enumerate().all(|(index, byte)| {
            byte.is_ascii_alphanumeric() || (index > 0 && matches!(byte, b'-' | b'_' | b'.' | b':'))
        })
}

fn valid_sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn ensure_private_directory(path: &Path) -> Result<(), MacosWorkOrderServiceError> {
    if !safe_absolute_directory(path) {
        return Err(MacosWorkOrderServiceError::InvalidConfig);
    }
    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.is_dir() && !metadata.file_type().is_symlink() => {}
        Err(error) if error.kind() == io::ErrorKind::NotFound => fs::create_dir_all(path)?,
        _ => return Err(MacosWorkOrderServiceError::InvalidState),
    }
    let metadata = fs::symlink_metadata(path)?;
    if !metadata.is_dir()
        || metadata.file_type().is_symlink()
        || metadata.uid() != rustix::process::getuid().as_raw()
    {
        return Err(MacosWorkOrderServiceError::InvalidState);
    }
    fs::set_permissions(path, fs::Permissions::from_mode(0o700))?;
    if fs::symlink_metadata(path)?.mode() & 0o7777 != 0o700 {
        return Err(MacosWorkOrderServiceError::InvalidState);
    }
    Ok(())
}

#[cfg(target_os = "macos")]
fn open_service_lock(path: &Path) -> Result<File, MacosWorkOrderServiceError> {
    use rustix::fs::{AtFlags, CWD, FileType, Mode, OFlags};

    let descriptor = rustix::fs::openat(
        CWD,
        path,
        OFlags::RDWR | OFlags::CREATE | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::RUSR | Mode::WUSR,
    )
    .map_err(|_| MacosWorkOrderServiceError::InvalidState)?;
    let descriptor_state =
        rustix::fs::fstat(&descriptor).map_err(|_| MacosWorkOrderServiceError::InvalidState)?;
    let named_state = rustix::fs::statat(CWD, path, AtFlags::SYMLINK_NOFOLLOW)
        .map_err(|_| MacosWorkOrderServiceError::InvalidState)?;
    if !FileType::from_raw_mode(descriptor_state.st_mode).is_file()
        || !FileType::from_raw_mode(named_state.st_mode).is_file()
        || descriptor_state.st_dev != named_state.st_dev
        || descriptor_state.st_ino != named_state.st_ino
        || descriptor_state.st_nlink != 1
        || descriptor_state.st_uid != rustix::process::getuid().as_raw()
    {
        return Err(MacosWorkOrderServiceError::InvalidState);
    }
    rustix::fs::fchmod(&descriptor, Mode::RUSR | Mode::WUSR)
        .map_err(|_| MacosWorkOrderServiceError::InvalidState)?;
    let file = File::from(descriptor);
    file.try_lock_exclusive()
        .map_err(|_| MacosWorkOrderServiceError::InvalidState)?;
    Ok(file)
}

fn cleanup_temporary(path: &Path) -> Result<(), MacosWorkOrderServiceError> {
    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.is_file() && !metadata.file_type().is_symlink() => {
            fs::remove_file(path)?;
            Ok(())
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        _ => Err(MacosWorkOrderServiceError::InvalidState),
    }
}

#[cfg(target_os = "macos")]
fn read_public_anchor(path: &Path) -> Result<[u8; 32], MacosWorkOrderServiceError> {
    let bytes = read_public_bounded(path, MAX_ANCHOR_FILE_BYTES)?;
    let encoded = std::str::from_utf8(
        trim_ascii_line(&bytes).ok_or(MacosWorkOrderServiceError::InvalidConfig)?,
    )
    .map_err(|_| MacosWorkOrderServiceError::InvalidConfig)?;
    let decoded = URL_SAFE_NO_PAD
        .decode(encoded)
        .map_err(|_| MacosWorkOrderServiceError::InvalidConfig)?;
    if URL_SAFE_NO_PAD.encode(&decoded) != encoded {
        return Err(MacosWorkOrderServiceError::InvalidConfig);
    }
    decoded
        .try_into()
        .map_err(|_| MacosWorkOrderServiceError::InvalidConfig)
}

#[cfg(target_os = "macos")]
fn read_public_bounded(path: &Path, maximum: usize) -> Result<Vec<u8>, MacosWorkOrderServiceError> {
    let metadata = fs::symlink_metadata(path)?;
    if !metadata.is_file()
        || metadata.file_type().is_symlink()
        || metadata.uid() != rustix::process::getuid().as_raw()
        || metadata.mode() & 0o022 != 0
        || metadata.len() == 0
        || metadata.len() > maximum as u64
    {
        return Err(MacosWorkOrderServiceError::InvalidConfig);
    }
    let bytes = fs::read(path)?;
    if bytes.is_empty() || bytes.len() > maximum || bytes.len() as u64 != metadata.len() {
        return Err(MacosWorkOrderServiceError::InvalidConfig);
    }
    Ok(bytes)
}

fn read_private_optional(path: &Path, maximum: usize) -> io::Result<Option<Vec<u8>>> {
    let metadata = match fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error),
    };
    if !metadata.is_file()
        || metadata.file_type().is_symlink()
        || metadata.uid() != rustix::process::getuid().as_raw()
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
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&pending)?;
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

#[cfg(target_os = "macos")]
fn trim_ascii_line(bytes: &[u8]) -> Option<&[u8]> {
    let bytes = bytes.strip_suffix(b"\n").unwrap_or(bytes);
    let bytes = bytes.strip_suffix(b"\r").unwrap_or(bytes);
    if bytes.is_empty() || bytes.contains(&b'\n') || bytes.contains(&b'\r') {
        None
    } else {
        Some(bytes)
    }
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

fn sha256_hex(bytes: &[u8]) -> String {
    hex_bytes(&Sha256::digest(bytes))
}

fn hex_bytes(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use kernaid_device_identity::DeviceIdentity;
    use std::sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    };
    use tempfile::TempDir;

    struct FixedCollector {
        calls: Arc<AtomicUsize>,
        document: &'static [u8],
    }

    impl DiagnosticCollector for FixedCollector {
        fn collect(&mut self, action: WorkOrderActionId) -> Result<Vec<u8>, LocalHandoffErrorCode> {
            if action != WorkOrderActionId::MacosP0DiagnoseV1 {
                return Err(LocalHandoffErrorCode::StateMismatch);
            }
            self.calls.fetch_add(1, Ordering::SeqCst);
            Ok(self.document.to_vec())
        }
    }

    fn prepared(device_id: &str, execution_id: &str) -> PreparedLocalExecution {
        PreparedLocalExecution {
            execution_id: execution_id.to_owned(),
            work_order_id: "wo_macos_fixture".to_owned(),
            lease_id: "lease_macos_fixture".to_owned(),
            action_id: WorkOrderActionId::MacosP0DiagnoseV1,
            action_version: 1,
            plan_sha256: digest_fields(
                PLAN_DIGEST_DOMAIN,
                &[
                    execution_id,
                    WorkOrderActionId::MacosP0DiagnoseV1.wire_name(),
                    "1",
                ],
            ),
            target_sha256: digest_fields(
                TARGET_DIGEST_DOMAIN,
                &[device_id, WorkOrderActionId::MacosP0DiagnoseV1.wire_name()],
            ),
            local_approval: None,
        }
    }

    fn valid_config(root: &Path) -> MacosWorkOrderServiceConfig {
        MacosWorkOrderServiceConfig {
            schema: MACOS_SERVICE_CONFIG_SCHEMA.to_owned(),
            endpoint: "https://fleet.example.invalid/".to_owned(),
            tenant_id: "tenant-macos".to_owned(),
            state_directory: root.join("state"),
            runtime_state_file: root.join("runtime/fleet.sqlite3"),
            service_receipt_anchor_file: root.join("trust/service.pub"),
            entitlement_anchor_file: root.join("trust/entitlement.pub"),
            policy_anchor_file: root.join("trust/policy.pub"),
            interval_seconds: 60,
            minimum_backoff_seconds: 2,
            maximum_backoff_seconds: 120,
            connect_timeout_seconds: 5,
            request_timeout_seconds: 30,
            lease_seconds: 300,
        }
    }

    #[test]
    fn config_is_https_only_and_rejects_command_or_secret_fields() {
        let root = TempDir::new().expect("tempdir");
        let config = valid_config(root.path());
        let bytes = serde_json::to_vec(&config).expect("config");
        assert_eq!(
            MacosWorkOrderServiceConfig::parse(&bytes).expect("valid config"),
            config
        );
        let mut value: Value = serde_json::from_slice(&bytes).expect("JSON");
        value
            .as_object_mut()
            .expect("object")
            .insert("command".to_owned(), Value::String("/bin/sh".to_owned()));
        assert!(
            MacosWorkOrderServiceConfig::parse(&serde_json::to_vec(&value).expect("bytes"))
                .is_err()
        );

        let mut invalid = config;
        invalid.endpoint = "https://user:secret@fleet.example.invalid/".to_owned();
        assert!(invalid.validate().is_err());
    }

    #[test]
    fn completed_execution_replays_digest_without_recollection_or_raw_state() {
        let root = TempDir::new().expect("tempdir");
        let state = root.path().join("diagnostics");
        let identity = DeviceIdentity::from_seed(&[0x64; 32]).expect("identity");
        let calls = Arc::new(AtomicUsize::new(0));
        let document = br#"{"diagnosis":"bounded-macos-native-fixture"}"#;
        let execution = prepared(
            &identity.device_id(),
            "exec_macos_0123456789abcdef0123456789abcdef",
        );

        let mut first = MacosDiagnosticHandoff::with_collector(
            &state,
            &identity.device_id(),
            FixedCollector {
                calls: Arc::clone(&calls),
                document,
            },
        )
        .expect("handoff");
        let initial = first
            .execute_or_recover(&execution)
            .expect("initial execution");
        drop(first);
        let mut reopened = MacosDiagnosticHandoff::with_collector(
            &state,
            &identity.device_id(),
            FixedCollector {
                calls: Arc::clone(&calls),
                document,
            },
        )
        .expect("reopen");
        assert_eq!(
            reopened.execute_or_recover(&execution).expect("replay"),
            initial
        );
        assert_eq!(calls.load(Ordering::SeqCst), 1);
        let retained = fs::read(state.join(EXECUTION_STATE_FILE)).expect("state");
        assert!(
            !retained
                .windows(document.len())
                .any(|window| window == document)
        );
    }

    #[test]
    fn non_macos_action_never_reaches_collector() {
        let root = TempDir::new().expect("tempdir");
        let state = root.path().join("diagnostics");
        let identity = DeviceIdentity::from_seed(&[0x65; 32]).expect("identity");
        let calls = Arc::new(AtomicUsize::new(0));
        let mut handoff = MacosDiagnosticHandoff::with_collector(
            &state,
            &identity.device_id(),
            FixedCollector {
                calls: Arc::clone(&calls),
                document: b"{}",
            },
        )
        .expect("handoff");
        let mut invalid = prepared(
            &identity.device_id(),
            "exec_macos_1123456789abcdef0123456789abcdef",
        );
        invalid.action_id = WorkOrderActionId::WindowsP0DiagnoseV1;
        assert_eq!(
            handoff.execute_or_recover(&invalid),
            Err(LocalHandoffErrorCode::StateMismatch)
        );
        assert_eq!(calls.load(Ordering::SeqCst), 0);
        assert!(!state.join(EXECUTION_STATE_FILE).exists());
    }
}
