//! Repair-image-only Fleet work-order service for Rescue.
//!
//! This process owns no device private key. It polls the fixed Fleet HTTPS
//! origin, asks the Rescue Vault for only the three purpose-specific signed
//! envelopes, and shares one verified repair adapter with the local Desk
//! approval socket. Stable diagnosis images do not compile or package it.

use crate::{
    LocalWorkOrderHandoff, ResidentPlatform, ResidentWorkOrderEngine, ResidentWorkOrderError,
    ResidentWorkOrderTransport, TransportErrorCode, WorkOrderAuthorization, WorkOrderCycleInput,
    WorkOrderCycleOutcome, WorkOrderTransportResponse,
    enrollment::{self, EnrollmentTransport, ResidentEnrollmentError},
    rescue::RescueAdapterError,
    rescue_local::{LOCAL_SOCKET_FD_NAME, open_system_local_service, run_activated_local_service},
    rescue_vault_signer::VaultFleetSigner,
};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use chrono::{SecondsFormat, Utc};
use fs2::FileExt as _;
use kernaid_fleet_client::{
    EnrollmentPlatform, EnrollmentRequestInput, FleetClientError, FleetRequestSigner,
};
use kernaid_fleet_policy::{RiskLevel, TransportState};
use kernaid_fleet_runtime::{FleetRuntime, FleetRuntimeError};
use rand_core::{OsRng, RngCore};
use reqwest::{
    Url,
    blocking::{Client, Response},
    header::{ACCEPT, CONTENT_LENGTH, CONTENT_TYPE, HeaderName},
    redirect::Policy,
};
use serde::{Deserialize, Serialize};
use std::{
    env,
    error::Error,
    ffi::OsStr,
    fmt,
    fs::{self, File, OpenOptions},
    io::{self, Read, Write},
    os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt},
    path::{Path, PathBuf},
    process::Command,
    sync::mpsc::{self, Receiver, RecvTimeoutError},
    thread,
    time::Duration,
};
use zeroize::Zeroizing;

pub const SERVICE_CONFIG_SCHEMA: &str = "dev.kernaid.fleet.rescue-repair-service-config.v1";
pub const BOOTSTRAP_BUNDLE_SCHEMA: &str = "dev.kernaid.fleet.rescue-repair-bootstrap-bundle.v1";
const SERVICE_LOCK_FILE: &str = ".fleet-rescue-repair.lock";
const WORK_ORDER_STATE_DIRECTORY: &str = "protocol";
const REPAIR_STATE_DIRECTORY: &str = "repair";
const CLAIM_ROUTE: &str = "/v1/work-order-claims";
const RESULT_ROUTE: &str = "/v1/work-order-results";
const RECEIPT_HEADER: HeaderName = HeaderName::from_static("x-kernaid-fleet-receipt");
const MAX_CONFIG_BYTES: usize = 16 * 1024;
const MAX_ANCHOR_FILE_BYTES: usize = 128;
const MAX_REQUEST_BYTES: usize = 64 * 1024;
const MAX_RECEIPT_HEADER_BYTES: usize = 8 * 1024;
const MAX_ENDPOINT_BYTES: usize = 4 * 1024;
const MAX_IDENTIFIER_BYTES: usize = 160;
const MIN_INTERVAL_SECONDS: u64 = 5;
const MAX_INTERVAL_SECONDS: u64 = 24 * 60 * 60;
const MIN_BACKOFF_SECONDS: u64 = 1;
const MAX_BACKOFF_SECONDS: u64 = 60 * 60;
const MIN_TIMEOUT_SECONDS: u64 = 1;
const MAX_CONNECT_TIMEOUT_SECONDS: u64 = 30;
const MAX_REQUEST_TIMEOUT_SECONDS: u64 = 120;
const SERVICE_CONFIG_PATH: &str = "/etc/kernaid/fleet-rescue-repair.json";
const SERVICE_RECEIPT_ANCHOR_PATH: &str = "/etc/kernaid/fleet-service-receipt.anchor";
const ENTITLEMENT_ANCHOR_PATH: &str = "/etc/kernaid/fleet-entitlement.anchor";
const POLICY_ANCHOR_PATH: &str = "/etc/kernaid/fleet-policy.anchor";
const SERVICE_STATE_DIRECTORY: &str = "/var/lib/kernaid-fleet-rescue";
const STAGED_CONFIG_FILE: &str = "fleet-rescue-repair.json";
const STAGED_SERVICE_ANCHOR_FILE: &str = "fleet-service-receipt.anchor";
const STAGED_ENTITLEMENT_ANCHOR_FILE: &str = "fleet-entitlement.anchor";
const STAGED_POLICY_ANCHOR_FILE: &str = "fleet-policy.anchor";
const STAGED_BUNDLE_FILE: &str = "bootstrap-bundle.json";
const STAGED_TOKEN_FILE: &str = "enrollment.token";

/// Tenant-specific public material accepted by the one-shot Rescue bootstrap.
/// The enrollment token remains a separate root-owned 0600 file and this
/// schema deliberately has no private-key or executable fields.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RescueFleetBootstrapBundle {
    pub schema: String,
    pub endpoint: String,
    pub tenant_id: String,
    pub service_receipt_anchor: String,
    pub entitlement_anchor: String,
    pub policy_anchor: String,
    pub interval_seconds: u64,
    pub minimum_backoff_seconds: u64,
    pub maximum_backoff_seconds: u64,
    pub connect_timeout_seconds: u64,
    pub request_timeout_seconds: u64,
    pub lease_seconds: u16,
}

impl RescueFleetBootstrapBundle {
    fn parse(bytes: &[u8]) -> Result<Self, RescueFleetServiceError> {
        if bytes.is_empty() || bytes.len() > MAX_CONFIG_BYTES {
            return Err(RescueFleetServiceError::InvalidConfig);
        }
        let bundle: Self =
            serde_json::from_slice(bytes).map_err(|_| RescueFleetServiceError::InvalidConfig)?;
        bundle.validate()?;
        Ok(bundle)
    }

    fn validate(&self) -> Result<(), RescueFleetServiceError> {
        if self.schema != BOOTSTRAP_BUNDLE_SCHEMA
            || !valid_https_origin(&self.endpoint)
            || !valid_identifier(&self.tenant_id)
            || decode_anchor(&self.service_receipt_anchor).is_err()
            || decode_anchor(&self.entitlement_anchor).is_err()
            || decode_anchor(&self.policy_anchor).is_err()
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
            return Err(RescueFleetServiceError::InvalidConfig);
        }
        Ok(())
    }

    fn service_config(
        &self,
        device_id: String,
        public_key: [u8; 32],
    ) -> Result<RescueFleetServiceConfig, RescueFleetServiceError> {
        let state_directory = PathBuf::from(SERVICE_STATE_DIRECTORY);
        let config = RescueFleetServiceConfig {
            schema: SERVICE_CONFIG_SCHEMA.to_owned(),
            endpoint: self.endpoint.clone(),
            tenant_id: self.tenant_id.clone(),
            device_id,
            device_public_key: URL_SAFE_NO_PAD.encode(public_key),
            runtime_state_file: state_directory.join("runtime.sqlite3"),
            state_directory,
            service_receipt_anchor_file: PathBuf::from(SERVICE_RECEIPT_ANCHOR_PATH),
            entitlement_anchor_file: PathBuf::from(ENTITLEMENT_ANCHOR_PATH),
            policy_anchor_file: PathBuf::from(POLICY_ANCHOR_PATH),
            interval_seconds: self.interval_seconds,
            minimum_backoff_seconds: self.minimum_backoff_seconds,
            maximum_backoff_seconds: self.maximum_backoff_seconds,
            connect_timeout_seconds: self.connect_timeout_seconds,
            request_timeout_seconds: self.request_timeout_seconds,
            lease_seconds: self.lease_seconds,
        };
        config.validate()?;
        Ok(config)
    }
}

/// Public-only configuration. In particular, this schema cannot contain an
/// enrollment token, private key, command, executable, repair operation, or
/// target path.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RescueFleetServiceConfig {
    pub schema: String,
    pub endpoint: String,
    pub tenant_id: String,
    pub device_id: String,
    pub device_public_key: String,
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

impl RescueFleetServiceConfig {
    pub fn parse(bytes: &[u8]) -> Result<Self, RescueFleetServiceError> {
        if bytes.is_empty() || bytes.len() > MAX_CONFIG_BYTES {
            return Err(RescueFleetServiceError::InvalidConfig);
        }
        let config: Self =
            serde_json::from_slice(bytes).map_err(|_| RescueFleetServiceError::InvalidConfig)?;
        config.validate()?;
        Ok(config)
    }

    fn validate(&self) -> Result<(), RescueFleetServiceError> {
        let public_key = self.public_key()?;
        if self.schema != SERVICE_CONFIG_SCHEMA
            || !valid_https_origin(&self.endpoint)
            || !valid_identifier(&self.tenant_id)
            || kernaid_device_identity::validate_device_id(&self.device_id).is_err()
            || kernaid_device_identity::device_id_for_public_key(&public_key) != self.device_id
            || !absolute_directory(&self.state_directory)
            || self.runtime_state_file != self.state_directory.join("runtime.sqlite3")
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
            return Err(RescueFleetServiceError::InvalidConfig);
        }
        let files = [
            &self.runtime_state_file,
            &self.service_receipt_anchor_file,
            &self.entitlement_anchor_file,
            &self.policy_anchor_file,
        ];
        if files
            .iter()
            .enumerate()
            .any(|(index, file)| files[..index].contains(file))
        {
            return Err(RescueFleetServiceError::InvalidConfig);
        }
        Ok(())
    }

    fn public_key(&self) -> Result<[u8; 32], RescueFleetServiceError> {
        let decoded = URL_SAFE_NO_PAD
            .decode(&self.device_public_key)
            .map_err(|_| RescueFleetServiceError::InvalidConfig)?;
        if URL_SAFE_NO_PAD.encode(&decoded) != self.device_public_key {
            return Err(RescueFleetServiceError::InvalidConfig);
        }
        decoded
            .try_into()
            .map_err(|_| RescueFleetServiceError::InvalidConfig)
    }
}

#[derive(Debug)]
pub enum RescueFleetServiceError {
    InvalidArguments,
    InvalidConfig,
    InvalidState,
    PrivilegeRequired,
    ProvisioningFailed,
    ClockUnavailable,
    NonceUnavailable,
    ActivationUnavailable,
    LocalServiceUnavailable,
    Runtime(FleetRuntimeError),
    Resident(ResidentWorkOrderError),
    Enrollment(ResidentEnrollmentError),
    Client(FleetClientError),
    Rescue(RescueAdapterError),
    Io(io::Error),
}

impl RescueFleetServiceError {
    #[must_use]
    pub const fn code(&self) -> &'static str {
        match self {
            Self::InvalidArguments => "arguments-invalid",
            Self::InvalidConfig => "config-invalid",
            Self::InvalidState => "state-invalid",
            Self::PrivilegeRequired => "root-privilege-required",
            Self::ProvisioningFailed => "provisioning-failed",
            Self::ClockUnavailable => "clock-unavailable",
            Self::NonceUnavailable => "nonce-unavailable",
            Self::ActivationUnavailable => "socket-activation-unavailable",
            Self::LocalServiceUnavailable => "local-service-unavailable",
            Self::Runtime(_) => "runtime-unavailable",
            Self::Resident(error) => error.code(),
            Self::Enrollment(error) => error.code(),
            Self::Client(_) => "vault-fleet-signer-unavailable",
            Self::Rescue(error) => match error {
                RescueAdapterError::BrokerUnavailable => "repair-broker-unavailable",
                _ => "repair-adapter-unavailable",
            },
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
                | Self::Resident(ResidentWorkOrderError::Client(
                    FleetClientError::SignerUnavailable
                ))
        )
    }
}

impl fmt::Display for RescueFleetServiceError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.code())
    }
}

impl Error for RescueFleetServiceError {}

impl From<io::Error> for RescueFleetServiceError {
    fn from(error: io::Error) -> Self {
        Self::Io(error)
    }
}

impl From<FleetRuntimeError> for RescueFleetServiceError {
    fn from(error: FleetRuntimeError) -> Self {
        Self::Runtime(error)
    }
}

impl From<ResidentWorkOrderError> for RescueFleetServiceError {
    fn from(error: ResidentWorkOrderError) -> Self {
        Self::Resident(error)
    }
}

impl From<ResidentEnrollmentError> for RescueFleetServiceError {
    fn from(error: ResidentEnrollmentError) -> Self {
        Self::Enrollment(error)
    }
}

impl From<FleetClientError> for RescueFleetServiceError {
    fn from(error: FleetClientError) -> Self {
        Self::Client(error)
    }
}

impl From<RescueAdapterError> for RescueFleetServiceError {
    fn from(error: RescueAdapterError) -> Self {
        Self::Rescue(error)
    }
}

struct RescueHttpsTransport {
    client: Client,
    base: Url,
    origin: String,
}

impl RescueHttpsTransport {
    fn new(config: &RescueFleetServiceConfig) -> Result<Self, RescueFleetServiceError> {
        let base = strict_base_url(&config.endpoint)
            .map_err(|()| RescueFleetServiceError::InvalidConfig)?;
        let origin = base.origin().ascii_serialization();
        let _ = rustls::crypto::ring::default_provider().install_default();
        let client = Client::builder()
            .https_only(true)
            .no_proxy()
            .redirect(Policy::none())
            .connect_timeout(Duration::from_secs(config.connect_timeout_seconds))
            .timeout(Duration::from_secs(config.request_timeout_seconds))
            .user_agent(concat!(
                "KernAid-Fleet-Rescue-Repair/",
                env!("CARGO_PKG_VERSION")
            ))
            .build()
            .map_err(|_| RescueFleetServiceError::InvalidConfig)?;
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

impl ResidentWorkOrderTransport for RescueHttpsTransport {
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

impl EnrollmentTransport for RescueHttpsTransport {
    fn origin(&self) -> &str {
        &self.origin
    }

    fn post_enrollment(
        &mut self,
        body: &[u8],
        maximum_response_bytes: usize,
    ) -> Result<WorkOrderTransportResponse, TransportErrorCode> {
        self.post(enrollment::ENROLLMENT_ROUTE, body, maximum_response_bytes)
    }
}

pub fn run_from_args() -> Result<(), RescueFleetServiceError> {
    let mut arguments = env::args_os().skip(1);
    let command = arguments
        .next()
        .ok_or(RescueFleetServiceError::InvalidArguments)?;
    match command.to_str() {
        Some("serve") => {
            let config_path = exact_config_argument(&mut arguments)?;
            run_service(load_config(&config_path)?, false)
        }
        Some("run-once") => {
            let config_path = exact_config_argument(&mut arguments)?;
            run_service(load_config(&config_path)?, true)
        }
        Some("enroll") => {
            if arguments.next().as_deref() != Some(OsStr::new("--config")) {
                return Err(RescueFleetServiceError::InvalidArguments);
            }
            let config_path = PathBuf::from(
                arguments
                    .next()
                    .ok_or(RescueFleetServiceError::InvalidArguments)?,
            );
            if arguments.next().as_deref() != Some(OsStr::new("--token-file")) {
                return Err(RescueFleetServiceError::InvalidArguments);
            }
            let token_path = PathBuf::from(
                arguments
                    .next()
                    .ok_or(RescueFleetServiceError::InvalidArguments)?,
            );
            if arguments.next().is_some() {
                return Err(RescueFleetServiceError::InvalidArguments);
            }
            bootstrap_enrollment(load_config(&config_path)?, &token_path)
        }
        Some("bootstrap") => {
            let (bundle_path, token_path) = exact_bootstrap_arguments(&mut arguments)?;
            provision_bootstrap(&bundle_path, &token_path)
        }
        Some("__stage-bootstrap") => {
            let (bundle_path, token_path, output_directory) =
                exact_stage_bootstrap_arguments(&mut arguments)?;
            stage_bootstrap(&bundle_path, &token_path, &output_directory)
        }
        _ => Err(RescueFleetServiceError::InvalidArguments),
    }
}

fn exact_bootstrap_arguments(
    arguments: &mut impl Iterator<Item = std::ffi::OsString>,
) -> Result<(PathBuf, PathBuf), RescueFleetServiceError> {
    if arguments.next().as_deref() != Some(OsStr::new("--bundle")) {
        return Err(RescueFleetServiceError::InvalidArguments);
    }
    let bundle = PathBuf::from(
        arguments
            .next()
            .ok_or(RescueFleetServiceError::InvalidArguments)?,
    );
    if arguments.next().as_deref() != Some(OsStr::new("--token-file")) {
        return Err(RescueFleetServiceError::InvalidArguments);
    }
    let token = PathBuf::from(
        arguments
            .next()
            .ok_or(RescueFleetServiceError::InvalidArguments)?,
    );
    if arguments.next().is_some() {
        return Err(RescueFleetServiceError::InvalidArguments);
    }
    Ok((bundle, token))
}

fn exact_stage_bootstrap_arguments(
    arguments: &mut impl Iterator<Item = std::ffi::OsString>,
) -> Result<(PathBuf, PathBuf, PathBuf), RescueFleetServiceError> {
    let (bundle, token) = exact_bootstrap_prefix(arguments)?;
    if arguments.next().as_deref() != Some(OsStr::new("--output-directory")) {
        return Err(RescueFleetServiceError::InvalidArguments);
    }
    let output = PathBuf::from(
        arguments
            .next()
            .ok_or(RescueFleetServiceError::InvalidArguments)?,
    );
    if arguments.next().is_some() {
        return Err(RescueFleetServiceError::InvalidArguments);
    }
    Ok((bundle, token, output))
}

fn exact_bootstrap_prefix(
    arguments: &mut impl Iterator<Item = std::ffi::OsString>,
) -> Result<(PathBuf, PathBuf), RescueFleetServiceError> {
    if arguments.next().as_deref() != Some(OsStr::new("--bundle")) {
        return Err(RescueFleetServiceError::InvalidArguments);
    }
    let bundle = PathBuf::from(
        arguments
            .next()
            .ok_or(RescueFleetServiceError::InvalidArguments)?,
    );
    if arguments.next().as_deref() != Some(OsStr::new("--token-file")) {
        return Err(RescueFleetServiceError::InvalidArguments);
    }
    let token = PathBuf::from(
        arguments
            .next()
            .ok_or(RescueFleetServiceError::InvalidArguments)?,
    );
    Ok((bundle, token))
}

fn provision_bootstrap(
    bundle_path: &Path,
    token_path: &Path,
) -> Result<(), RescueFleetServiceError> {
    if !rustix::process::geteuid().is_root() {
        return Err(RescueFleetServiceError::PrivilegeRequired);
    }
    let bundle_bytes = read_public_bounded(bundle_path, MAX_CONFIG_BYTES)?;
    let bundle = RescueFleetBootstrapBundle::parse(&bundle_bytes)?;
    let token = enrollment::read_optional_enrollment_token(token_path)?
        .ok_or(ResidentEnrollmentError::EnrollmentRequired)?;

    checked_command(Command::new("/usr/bin/install").args([
        OsStr::new("-d"),
        OsStr::new("-o"),
        OsStr::new("kernaid-fleet"),
        OsStr::new("-g"),
        OsStr::new("kernaid-repair-client"),
        OsStr::new("-m"),
        OsStr::new("0700"),
        OsStr::new(SERVICE_STATE_DIRECTORY),
    ]))?;

    let stage = new_bootstrap_stage_path()?;
    fs::create_dir(&stage)?;
    let _stage_guard = BootstrapStageGuard(stage.clone());
    fs::set_permissions(&stage, fs::Permissions::from_mode(0o700))?;
    let staged_bundle = stage.join(STAGED_BUNDLE_FILE);
    let staged_token = stage.join(STAGED_TOKEN_FILE);
    write_private_new(&staged_bundle, &bundle_bytes)?;
    write_private_new(&staged_token, token.as_bytes())?;
    checked_command(
        Command::new("/usr/bin/chown")
            .arg("kernaid-fleet:kernaid-repair-client")
            .arg(&stage)
            .arg(&staged_bundle)
            .arg(&staged_token),
    )?;

    (|| {
        let executable = env::current_exe()?;
        checked_command(
            Command::new("/usr/sbin/runuser")
                .arg("--user")
                .arg("kernaid-fleet")
                .arg("--group")
                .arg("kernaid-repair-client")
                .arg("--supp-group")
                .arg("kernaid-vault")
                .arg("--")
                .arg(executable)
                .arg("__stage-bootstrap")
                .arg("--bundle")
                .arg(&staged_bundle)
                .arg("--token-file")
                .arg(&staged_token)
                .arg("--output-directory")
                .arg(&stage),
        )?;

        let config_bytes = read_public_bounded(&stage.join(STAGED_CONFIG_FILE), MAX_CONFIG_BYTES)?;
        let config = RescueFleetServiceConfig::parse(&config_bytes)?;
        if !bundle_matches_config(&bundle, &config) {
            return Err(RescueFleetServiceError::InvalidState);
        }
        let staged_anchors = [
            (STAGED_SERVICE_ANCHOR_FILE, &bundle.service_receipt_anchor),
            (STAGED_ENTITLEMENT_ANCHOR_FILE, &bundle.entitlement_anchor),
            (STAGED_POLICY_ANCHOR_FILE, &bundle.policy_anchor),
        ];
        for (name, expected) in staged_anchors {
            if read_public_anchor(&stage.join(name))? != decode_anchor(expected)? {
                return Err(RescueFleetServiceError::InvalidState);
            }
        }

        ensure_root_config_directory()?;
        install_public_exact(
            &stage.join(STAGED_SERVICE_ANCHOR_FILE),
            Path::new(SERVICE_RECEIPT_ANCHOR_PATH),
            MAX_ANCHOR_FILE_BYTES,
        )?;
        install_public_exact(
            &stage.join(STAGED_ENTITLEMENT_ANCHOR_FILE),
            Path::new(ENTITLEMENT_ANCHOR_PATH),
            MAX_ANCHOR_FILE_BYTES,
        )?;
        install_public_exact(
            &stage.join(STAGED_POLICY_ANCHOR_FILE),
            Path::new(POLICY_ANCHOR_PATH),
            MAX_ANCHOR_FILE_BYTES,
        )?;
        // The service config is the activation gate and is installed last.
        install_public_exact(
            &stage.join(STAGED_CONFIG_FILE),
            Path::new(SERVICE_CONFIG_PATH),
            MAX_CONFIG_BYTES,
        )?;
        enrollment::remove_consumed_enrollment_token(token_path)?;
        checked_command(Command::new("/usr/bin/systemctl").arg("daemon-reload"))?;
        checked_command(
            Command::new("/usr/bin/systemctl")
                .arg("start")
                .arg("kernaid-fleet-rescue-repair.socket")
                .arg("kernaid-fleet-rescue-repair.service"),
        )?;
        println!(
            "KERNAID_FLEET_RESCUE_BOOTSTRAP_V1 status=provisioned device={} tenant={}",
            config.device_id, config.tenant_id
        );
        Ok(())
    })()
}

fn stage_bootstrap(
    bundle_path: &Path,
    token_path: &Path,
    output_directory: &Path,
) -> Result<(), RescueFleetServiceError> {
    if rustix::process::geteuid().is_root() {
        return Err(RescueFleetServiceError::InvalidState);
    }
    ensure_private_directory(output_directory)?;
    let bundle =
        RescueFleetBootstrapBundle::parse(&read_public_bounded(bundle_path, MAX_CONFIG_BYTES)?)?;
    let token = enrollment::read_optional_enrollment_token(token_path)?
        .ok_or(ResidentEnrollmentError::EnrollmentRequired)?;
    let now = Utc::now();
    let mut nonce = Zeroizing::new(vec![0_u8; 32]);
    OsRng
        .try_fill_bytes(&mut nonce)
        .map_err(|_| RescueFleetServiceError::NonceUnavailable)?;
    let discovery_input = EnrollmentRequestInput::new(
        token.as_str(),
        bundle.tenant_id.clone(),
        EnrollmentPlatform::Rescue,
        env!("CARGO_PKG_VERSION"),
        now.to_rfc3339_opts(SecondsFormat::Secs, true),
        nonce.to_vec(),
    );
    let signer = VaultFleetSigner::discover_from_enrollment(&discovery_input)?;
    let config = bundle.service_config(signer.device_id()?, signer.public_key()?)?;
    drop(token);
    bootstrap_enrollment(config.clone(), token_path)?;

    write_private_new(
        &output_directory.join(STAGED_SERVICE_ANCHOR_FILE),
        format!("{}\n", bundle.service_receipt_anchor).as_bytes(),
    )?;
    write_private_new(
        &output_directory.join(STAGED_ENTITLEMENT_ANCHOR_FILE),
        format!("{}\n", bundle.entitlement_anchor).as_bytes(),
    )?;
    write_private_new(
        &output_directory.join(STAGED_POLICY_ANCHOR_FILE),
        format!("{}\n", bundle.policy_anchor).as_bytes(),
    )?;
    let config_bytes =
        serde_json::to_vec(&config).map_err(|_| RescueFleetServiceError::InvalidConfig)?;
    write_private_new(&output_directory.join(STAGED_CONFIG_FILE), &config_bytes)
}

fn exact_config_argument(
    arguments: &mut impl Iterator<Item = std::ffi::OsString>,
) -> Result<PathBuf, RescueFleetServiceError> {
    if arguments.next().as_deref() != Some(OsStr::new("--config")) {
        return Err(RescueFleetServiceError::InvalidArguments);
    }
    let path = PathBuf::from(
        arguments
            .next()
            .ok_or(RescueFleetServiceError::InvalidArguments)?,
    );
    if arguments.next().is_some() {
        return Err(RescueFleetServiceError::InvalidArguments);
    }
    Ok(path)
}

fn load_config(path: &Path) -> Result<RescueFleetServiceConfig, RescueFleetServiceError> {
    RescueFleetServiceConfig::parse(&read_public_bounded(path, MAX_CONFIG_BYTES)?)
}

fn bootstrap_enrollment(
    config: RescueFleetServiceConfig,
    token_path: &Path,
) -> Result<(), RescueFleetServiceError> {
    config.validate()?;
    ensure_private_directory(&config.state_directory)?;
    let _lock = open_service_lock(&config.state_directory.join(SERVICE_LOCK_FILE))?;
    let signer = VaultFleetSigner::new(config.device_id.clone(), config.public_key()?)?;
    let token = enrollment::read_optional_enrollment_token(token_path)?
        .ok_or(ResidentEnrollmentError::EnrollmentRequired)?;
    let now = Utc::now();
    let now_unix =
        u64::try_from(now.timestamp()).map_err(|_| RescueFleetServiceError::ClockUnavailable)?;
    if now_unix == 0 {
        return Err(RescueFleetServiceError::ClockUnavailable);
    }
    let mut nonce = Zeroizing::new(vec![0_u8; 32]);
    OsRng
        .try_fill_bytes(&mut nonce)
        .map_err(|_| RescueFleetServiceError::NonceUnavailable)?;
    let mut transport = RescueHttpsTransport::new(&config)?;
    enrollment::bootstrap_enrollment(
        &signer,
        EnrollmentPlatform::Rescue,
        &config.state_directory,
        &config.tenant_id,
        Some(token.as_str()),
        now.to_rfc3339_opts(SecondsFormat::Secs, true),
        nonce,
        &mut transport,
    )?;
    enrollment::remove_consumed_enrollment_token(token_path)?;
    Ok(())
}

pub fn run_service(
    config: RescueFleetServiceConfig,
    once: bool,
) -> Result<(), RescueFleetServiceError> {
    config.validate()?;
    ensure_private_directory(&config.state_directory)?;
    let _lock = open_service_lock(&config.state_directory.join(SERVICE_LOCK_FILE))?;
    let public_key = config.public_key()?;
    let signer = VaultFleetSigner::new(config.device_id.clone(), public_key)?;
    let service_anchor = read_public_anchor(&config.service_receipt_anchor_file)?;
    let entitlement_anchor = read_public_anchor(&config.entitlement_anchor_file)?;
    let policy_anchor = read_public_anchor(&config.policy_anchor_file)?;
    let transport = RescueHttpsTransport::new(&config)?;
    enrollment::require_enrollment(
        &config.state_directory,
        &transport.origin,
        &config.tenant_id,
        &config.device_id,
    )?;
    let runtime = FleetRuntime::open_with_public_identity_and_trust_anchors(
        &config.runtime_state_file,
        &config.tenant_id,
        &config.device_id,
        &public_key,
        &entitlement_anchor,
        &policy_anchor,
    )?;
    let mut engine = ResidentWorkOrderEngine::open(
        &config.tenant_id,
        &signer,
        &service_anchor,
        &config.state_directory.join(WORK_ORDER_STATE_DIRECTORY),
        transport,
    )?;
    let local_service = open_system_local_service(
        &config.state_directory.join(REPAIR_STATE_DIRECTORY),
        &config.tenant_id,
        &config.device_id,
    )?;
    let handoff = local_service.shared_adapter();
    let listener = kernaid_linux_systemd::take_single_named_socket(LOCAL_SOCKET_FD_NAME)
        .map_err(|_| RescueFleetServiceError::ActivationUnavailable)?;
    let (local_exit_sender, local_exit_receiver) = mpsc::sync_channel(1);
    thread::spawn(move || {
        let _ = local_exit_sender.send(run_activated_local_service(listener, local_service));
    });

    let mut backoff = config.minimum_backoff_seconds;
    loop {
        ensure_local_service_running(&local_exit_receiver)?;
        let cycle = {
            let mut handoff = handoff
                .lock()
                .map_err(|_| RescueFleetServiceError::InvalidState)?;
            run_cycle(&config, &runtime, &signer, &mut engine, &mut *handoff)
        };
        if once {
            return cycle.map(|outcome| print_outcome(&outcome));
        }
        let wait_seconds = match cycle {
            Ok(outcome) => {
                let wait = successful_cycle_wait_seconds(&outcome, config.interval_seconds);
                print_outcome(&outcome);
                backoff = config.minimum_backoff_seconds;
                wait
            }
            Err(error) if error.transient() => {
                eprintln!(
                    "KERNAID_FLEET_RESCUE_REPAIR_V1 status=offline code={}",
                    error.code()
                );
                let wait = backoff;
                backoff = backoff
                    .saturating_mul(2)
                    .min(config.maximum_backoff_seconds);
                wait
            }
            Err(error) => return Err(error),
        };
        wait_with_local_service(&local_exit_receiver, Duration::from_secs(wait_seconds))?;
    }
}

fn successful_cycle_wait_seconds(outcome: &WorkOrderCycleOutcome, interval_seconds: u64) -> u64 {
    match outcome {
        // Desk writes the approval through the local socket. Poll Fleet again
        // promptly so an approved intent is not hidden behind the normal
        // fleet interval; the bound remains finite if a notification is lost.
        WorkOrderCycleOutcome::AwaitingLocalApproval { .. } => interval_seconds.min(2),
        WorkOrderCycleOutcome::NoWork | WorkOrderCycleOutcome::Completed { .. } => interval_seconds,
    }
}

fn run_cycle<T: ResidentWorkOrderTransport, H: LocalWorkOrderHandoff>(
    config: &RescueFleetServiceConfig,
    runtime: &FleetRuntime,
    signer: &VaultFleetSigner,
    engine: &mut ResidentWorkOrderEngine<T>,
    handoff: &mut H,
) -> Result<WorkOrderCycleOutcome, RescueFleetServiceError> {
    let now = Utc::now();
    let now_unix =
        u64::try_from(now.timestamp()).map_err(|_| RescueFleetServiceError::ClockUnavailable)?;
    if now_unix == 0 {
        return Err(RescueFleetServiceError::ClockUnavailable);
    }
    let mut nonce = Zeroizing::new(vec![0_u8; 32]);
    OsRng
        .try_fill_bytes(&mut nonce)
        .map_err(|_| RescueFleetServiceError::NonceUnavailable)?;
    let capabilities = runtime.capabilities(now_unix);
    let policies = runtime.applicable_policies(now_unix, TransportState::Online)?;
    let authorization = WorkOrderAuthorization {
        platform: ResidentPlatform::Rescue,
        capabilities,
        policies: &policies,
        local_max_risk: RiskLevel::R3,
        local_approval_from: RiskLevel::R2,
        now_unix,
    };
    engine
        .run_once(
            signer,
            WorkOrderCycleInput {
                issued_at: now.to_rfc3339_opts(SecondsFormat::Secs, true),
                now_unix,
                nonce,
                lease_seconds: config.lease_seconds,
            },
            &authorization,
            handoff,
        )
        .map_err(Into::into)
}

fn ensure_local_service_running(
    receiver: &Receiver<Result<(), RescueAdapterError>>,
) -> Result<(), RescueFleetServiceError> {
    match receiver.try_recv() {
        Ok(Ok(())) | Err(mpsc::TryRecvError::Disconnected) => {
            Err(RescueFleetServiceError::LocalServiceUnavailable)
        }
        Ok(Err(error)) => Err(error.into()),
        Err(mpsc::TryRecvError::Empty) => Ok(()),
    }
}

fn wait_with_local_service(
    receiver: &Receiver<Result<(), RescueAdapterError>>,
    duration: Duration,
) -> Result<(), RescueFleetServiceError> {
    match receiver.recv_timeout(duration) {
        Ok(Ok(())) | Err(RecvTimeoutError::Disconnected) => {
            Err(RescueFleetServiceError::LocalServiceUnavailable)
        }
        Ok(Err(error)) => Err(error.into()),
        Err(RecvTimeoutError::Timeout) => Ok(()),
    }
}

fn print_outcome(outcome: &WorkOrderCycleOutcome) {
    match outcome {
        WorkOrderCycleOutcome::NoWork => println!(
            "KERNAID_FLEET_RESCUE_REPAIR_V1 status=ok outcome=no-work writes=approval-gated"
        ),
        WorkOrderCycleOutcome::AwaitingLocalApproval { .. } => println!(
            "KERNAID_FLEET_RESCUE_REPAIR_V1 status=ok outcome=awaiting-local-approval writes=disabled"
        ),
        WorkOrderCycleOutcome::Completed { outcome, .. } => println!(
            "KERNAID_FLEET_RESCUE_REPAIR_V1 status=ok outcome={outcome:?} writes=approval-gated"
        ),
    }
}

fn read_response(
    mut response: Response,
    maximum_response_bytes: usize,
) -> Result<WorkOrderTransportResponse, TransportErrorCode> {
    let maximum =
        u64::try_from(maximum_response_bytes).map_err(|_| TransportErrorCode::ResponseTooLarge)?;
    if response
        .headers()
        .get(CONTENT_LENGTH)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.parse::<u64>().ok())
        .is_some_and(|length| length > maximum)
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
        .take(maximum.saturating_add(1))
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

fn valid_identifier(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= MAX_IDENTIFIER_BYTES
        && value.bytes().all(|byte| {
            byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b':' | b'/')
        })
}

fn absolute_directory(path: &Path) -> bool {
    path.is_absolute() && path != Path::new("/") && path.file_name().is_some()
}

fn absolute_file(path: &Path) -> bool {
    path.is_absolute()
        && path.parent().is_some_and(absolute_directory)
        && path.file_name().is_some()
}

fn read_public_anchor(path: &Path) -> Result<[u8; 32], RescueFleetServiceError> {
    let bytes = read_public_bounded(path, MAX_ANCHOR_FILE_BYTES)?;
    let encoded =
        std::str::from_utf8(trim_ascii_line(&bytes).ok_or(RescueFleetServiceError::InvalidConfig)?)
            .map_err(|_| RescueFleetServiceError::InvalidConfig)?;
    decode_anchor(encoded)
}

fn decode_anchor(encoded: &str) -> Result<[u8; 32], RescueFleetServiceError> {
    let decoded = URL_SAFE_NO_PAD
        .decode(encoded)
        .map_err(|_| RescueFleetServiceError::InvalidConfig)?;
    if URL_SAFE_NO_PAD.encode(&decoded) != encoded {
        return Err(RescueFleetServiceError::InvalidConfig);
    }
    decoded
        .try_into()
        .map_err(|_| RescueFleetServiceError::InvalidConfig)
}

fn bundle_matches_config(
    bundle: &RescueFleetBootstrapBundle,
    config: &RescueFleetServiceConfig,
) -> bool {
    config.endpoint == bundle.endpoint
        && config.tenant_id == bundle.tenant_id
        && config.state_directory == Path::new(SERVICE_STATE_DIRECTORY)
        && config.runtime_state_file == Path::new(SERVICE_STATE_DIRECTORY).join("runtime.sqlite3")
        && config.service_receipt_anchor_file == Path::new(SERVICE_RECEIPT_ANCHOR_PATH)
        && config.entitlement_anchor_file == Path::new(ENTITLEMENT_ANCHOR_PATH)
        && config.policy_anchor_file == Path::new(POLICY_ANCHOR_PATH)
        && config.interval_seconds == bundle.interval_seconds
        && config.minimum_backoff_seconds == bundle.minimum_backoff_seconds
        && config.maximum_backoff_seconds == bundle.maximum_backoff_seconds
        && config.connect_timeout_seconds == bundle.connect_timeout_seconds
        && config.request_timeout_seconds == bundle.request_timeout_seconds
        && config.lease_seconds == bundle.lease_seconds
}

fn checked_command(command: &mut Command) -> Result<(), RescueFleetServiceError> {
    let status = command.status()?;
    if status.success() {
        Ok(())
    } else {
        Err(RescueFleetServiceError::ProvisioningFailed)
    }
}

fn new_bootstrap_stage_path() -> Result<PathBuf, RescueFleetServiceError> {
    let mut random = [0_u8; 16];
    OsRng
        .try_fill_bytes(&mut random)
        .map_err(|_| RescueFleetServiceError::NonceUnavailable)?;
    let mut suffix = String::with_capacity(32);
    for byte in random {
        use fmt::Write as _;
        write!(&mut suffix, "{byte:02x}").map_err(|_| RescueFleetServiceError::NonceUnavailable)?;
    }
    Ok(PathBuf::from(format!(
        "/run/kernaid-fleet-rescue-bootstrap-{suffix}"
    )))
}

fn write_private_new(path: &Path, bytes: &[u8]) -> Result<(), RescueFleetServiceError> {
    if bytes.is_empty() || !absolute_file(path) {
        return Err(RescueFleetServiceError::InvalidState);
    }
    let mut options = OpenOptions::new();
    options.write(true).create_new(true).mode(0o600);
    let mut file = options.open(path)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    Ok(())
}

fn ensure_root_config_directory() -> Result<(), RescueFleetServiceError> {
    let path = Path::new("/etc/kernaid");
    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.is_dir() && !metadata.file_type().is_symlink() => {}
        Err(error) if error.kind() == io::ErrorKind::NotFound => fs::create_dir(path)?,
        _ => return Err(RescueFleetServiceError::InvalidState),
    }
    let metadata = fs::symlink_metadata(path)?;
    if metadata.uid() != 0 || metadata.mode() & 0o022 != 0 {
        return Err(RescueFleetServiceError::InvalidState);
    }
    Ok(())
}

fn install_public_exact(
    source: &Path,
    destination: &Path,
    maximum: usize,
) -> Result<(), RescueFleetServiceError> {
    let bytes = read_public_bounded(source, maximum)?;
    match fs::symlink_metadata(destination) {
        Ok(metadata) => {
            if !metadata.is_file()
                || metadata.file_type().is_symlink()
                || metadata.uid() != 0
                || metadata.mode() & 0o022 != 0
                || read_public_bounded(destination, maximum)? != bytes
            {
                return Err(RescueFleetServiceError::InvalidState);
            }
            return Ok(());
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Err(error) => return Err(error.into()),
    }
    let parent = destination
        .parent()
        .ok_or(RescueFleetServiceError::InvalidState)?;
    let name = destination
        .file_name()
        .and_then(OsStr::to_str)
        .ok_or(RescueFleetServiceError::InvalidState)?;
    let temporary = parent.join(format!(".{name}.bootstrap-pending"));
    let mut options = OpenOptions::new();
    options.write(true).create_new(true).mode(0o600);
    let mut file = options.open(&temporary)?;
    file.write_all(&bytes)?;
    file.sync_all()?;
    fs::set_permissions(&temporary, fs::Permissions::from_mode(0o644))?;
    fs::rename(&temporary, destination)?;
    File::open(parent)?.sync_all()?;
    Ok(())
}

fn cleanup_bootstrap_stage(stage: &Path) {
    for name in [
        STAGED_CONFIG_FILE,
        STAGED_SERVICE_ANCHOR_FILE,
        STAGED_ENTITLEMENT_ANCHOR_FILE,
        STAGED_POLICY_ANCHOR_FILE,
        STAGED_BUNDLE_FILE,
        STAGED_TOKEN_FILE,
    ] {
        match fs::remove_file(stage.join(name)) {
            Ok(()) => {}
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(_) => {}
        }
    }
    let _ = fs::remove_dir(stage);
}

struct BootstrapStageGuard(PathBuf);

impl Drop for BootstrapStageGuard {
    fn drop(&mut self) {
        cleanup_bootstrap_stage(&self.0);
    }
}

fn read_public_bounded(path: &Path, maximum: usize) -> Result<Vec<u8>, RescueFleetServiceError> {
    let metadata = fs::symlink_metadata(path)?;
    let maximum = u64::try_from(maximum).map_err(|_| RescueFleetServiceError::InvalidConfig)?;
    if !metadata.is_file()
        || metadata.file_type().is_symlink()
        || metadata.mode() & 0o022 != 0
        || metadata.len() == 0
        || metadata.len() > maximum
    {
        return Err(RescueFleetServiceError::InvalidConfig);
    }
    let bytes = fs::read(path)?;
    if u64::try_from(bytes.len()).ok() != Some(metadata.len()) {
        return Err(RescueFleetServiceError::InvalidConfig);
    }
    Ok(bytes)
}

fn ensure_private_directory(path: &Path) -> Result<(), RescueFleetServiceError> {
    if !absolute_directory(path) {
        return Err(RescueFleetServiceError::InvalidConfig);
    }
    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.is_dir() && !metadata.file_type().is_symlink() => {}
        Err(error) if error.kind() == io::ErrorKind::NotFound => fs::create_dir_all(path)?,
        _ => return Err(RescueFleetServiceError::InvalidState),
    }
    let metadata = fs::symlink_metadata(path)?;
    if !metadata.is_dir()
        || metadata.file_type().is_symlink()
        || metadata.uid() != rustix::process::getuid().as_raw()
    {
        return Err(RescueFleetServiceError::InvalidState);
    }
    fs::set_permissions(path, fs::Permissions::from_mode(0o700))?;
    if fs::symlink_metadata(path)?.mode() & 0o7777 != 0o700 {
        return Err(RescueFleetServiceError::InvalidState);
    }
    Ok(())
}

fn open_service_lock(path: &Path) -> Result<File, RescueFleetServiceError> {
    let mut options = OpenOptions::new();
    options.read(true).write(true).create(true).mode(0o600);
    let file = options.open(path)?;
    let metadata = file.metadata()?;
    let named = fs::symlink_metadata(path)?;
    if !metadata.is_file()
        || named.file_type().is_symlink()
        || !named.is_file()
        || metadata.dev() != named.dev()
        || metadata.ino() != named.ino()
        || metadata.nlink() != 1
        || metadata.uid() != rustix::process::getuid().as_raw()
    {
        return Err(RescueFleetServiceError::InvalidState);
    }
    fs::set_permissions(path, fs::Permissions::from_mode(0o600))?;
    file.try_lock_exclusive()
        .map_err(|_| RescueFleetServiceError::InvalidState)?;
    Ok(file)
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
    use kernaid_device_identity::DeviceIdentity;
    use tempfile::TempDir;

    fn valid_config(directory: &Path) -> RescueFleetServiceConfig {
        let identity = DeviceIdentity::from_seed(&[0x57; 32]).expect("identity");
        RescueFleetServiceConfig {
            schema: SERVICE_CONFIG_SCHEMA.to_owned(),
            endpoint: "https://fleet.example.invalid".to_owned(),
            tenant_id: "tenant-rescue".to_owned(),
            device_id: identity.device_id(),
            device_public_key: URL_SAFE_NO_PAD.encode(identity.public_key()),
            state_directory: directory.join("state"),
            runtime_state_file: directory.join("state/runtime.sqlite3"),
            service_receipt_anchor_file: directory.join("anchors/service.pub"),
            entitlement_anchor_file: directory.join("anchors/entitlement.pub"),
            policy_anchor_file: directory.join("anchors/policy.pub"),
            interval_seconds: 30,
            minimum_backoff_seconds: 2,
            maximum_backoff_seconds: 60,
            connect_timeout_seconds: 5,
            request_timeout_seconds: 20,
            lease_seconds: 300,
        }
    }

    fn valid_bundle() -> RescueFleetBootstrapBundle {
        RescueFleetBootstrapBundle {
            schema: BOOTSTRAP_BUNDLE_SCHEMA.to_owned(),
            endpoint: "https://fleet.example.invalid".to_owned(),
            tenant_id: "tenant-rescue".to_owned(),
            service_receipt_anchor: URL_SAFE_NO_PAD.encode([0x11; 32]),
            entitlement_anchor: URL_SAFE_NO_PAD.encode([0x22; 32]),
            policy_anchor: URL_SAFE_NO_PAD.encode([0x33; 32]),
            interval_seconds: 30,
            minimum_backoff_seconds: 2,
            maximum_backoff_seconds: 60,
            connect_timeout_seconds: 5,
            request_timeout_seconds: 20,
            lease_seconds: 300,
        }
    }

    #[test]
    fn config_is_public_only_and_pins_exact_identity() {
        let directory = TempDir::new().expect("tempdir");
        let config = valid_config(directory.path());
        let bytes = serde_json::to_vec(&config).expect("config");
        assert_eq!(
            RescueFleetServiceConfig::parse(&bytes).expect("valid"),
            config
        );

        let mut value: serde_json::Value = serde_json::from_slice(&bytes).expect("json");
        value
            .as_object_mut()
            .expect("object")
            .insert("privateKey".to_owned(), serde_json::json!("forbidden"));
        assert!(
            RescueFleetServiceConfig::parse(&serde_json::to_vec(&value).expect("json")).is_err()
        );

        let mut mismatched = config;
        mismatched.device_id = "KA-0123456789abcdef01234567".to_owned();
        assert!(mismatched.validate().is_err());
    }

    #[test]
    fn transport_origin_rejects_paths_credentials_and_plain_http() {
        for invalid in [
            "http://fleet.example.invalid",
            "https://user:secret@fleet.example.invalid",
            "https://fleet.example.invalid/api",
            "https://fleet.example.invalid/?tenant=other",
        ] {
            assert!(strict_base_url(invalid).is_err(), "{invalid}");
        }
        assert!(strict_base_url("https://fleet.example.invalid:8443").is_ok());
    }

    #[test]
    fn bootstrap_bundle_generates_fixed_public_paths_and_local_identity() {
        let bundle = valid_bundle();
        let identity = DeviceIdentity::from_seed(&[0x31; 32]).expect("identity");
        let config = bundle
            .service_config(identity.device_id(), identity.public_key())
            .expect("service config");
        assert!(bundle_matches_config(&bundle, &config));
        assert_eq!(config.state_directory, Path::new(SERVICE_STATE_DIRECTORY));
        assert_eq!(
            config.service_receipt_anchor_file,
            Path::new(SERVICE_RECEIPT_ANCHOR_PATH)
        );

        let mut value = serde_json::to_value(bundle).expect("bundle JSON");
        value
            .as_object_mut()
            .expect("object")
            .insert("enrollmentToken".to_owned(), serde_json::json!("forbidden"));
        assert!(
            RescueFleetBootstrapBundle::parse(&serde_json::to_vec(&value).expect("JSON")).is_err()
        );
    }

    #[test]
    fn local_approval_wait_is_bounded_to_two_seconds() {
        let awaiting = WorkOrderCycleOutcome::AwaitingLocalApproval {
            work_order_id: "wo-1".to_owned(),
            lease_id: "lease-1".to_owned(),
        };
        assert_eq!(successful_cycle_wait_seconds(&awaiting, 300), 2);
    }
}
