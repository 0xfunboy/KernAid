//! Shared, explicit Resident enrollment bootstrap for native service adapters.
//!
//! The bootstrap is deliberately separate from normal service startup. It
//! signs one bounded enrollment request with an identity that is already held
//! by the caller, persists only the public enrollment binding, and never owns
//! or serializes an identity seed.

use crate::{TransportErrorCode, WorkOrderTransportResponse};
#[cfg(test)]
use kernaid_device_identity::DeviceIdentity;
use kernaid_fleet_client::{EnrollmentPlatform, EnrollmentRequestInput, FleetRequestSigner};
use serde::{Deserialize, Serialize};
use std::{
    error::Error,
    fmt,
    fs::{self, OpenOptions},
    io::{self, Write},
    path::{Path, PathBuf},
};
use zeroize::Zeroizing;

#[cfg(unix)]
use std::{
    fs::File,
    os::unix::fs::{OpenOptionsExt, PermissionsExt},
};

#[cfg(all(
    unix,
    any(
        feature = "linux-service",
        feature = "macos-service",
        feature = "rescue-fleet-service"
    )
))]
use std::os::unix::fs::MetadataExt;

#[cfg(windows)]
use std::os::windows::fs::MetadataExt;

pub const ENROLLMENT_STATE_SCHEMA: &str = "dev.kernaid.fleet.resident-enrollment.v1";
pub const ENROLLMENT_ROUTE: &str = "/v1/enrollments";
pub const MAX_ENROLLMENT_TOKEN_BYTES: usize = 512;

const ENROLLMENT_STATE_FILE: &str = "enrollment-v1.json";
const ENROLLMENT_PENDING_FILE: &str = ".enrollment-v1.pending";
const MAX_ENROLLMENT_RESPONSE_BYTES: usize = 8 * 1024;

pub trait EnrollmentTransport {
    fn origin(&self) -> &str;

    fn post_enrollment(
        &mut self,
        body: &[u8],
        maximum_response_bytes: usize,
    ) -> Result<WorkOrderTransportResponse, TransportErrorCode>;
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EnrollmentOutcome {
    AlreadyEnrolled,
    NewlyEnrolled,
}

#[derive(Debug)]
pub enum ResidentEnrollmentError {
    InvalidInput,
    InvalidState,
    EnrollmentRequired,
    EnrollmentRejected,
    Transport(TransportErrorCode),
    Client(kernaid_fleet_client::FleetClientError),
    Io(io::Error),
}

impl ResidentEnrollmentError {
    #[must_use]
    pub const fn code(&self) -> &'static str {
        match self {
            Self::InvalidInput => "enrollment-input-invalid",
            Self::InvalidState => "enrollment-state-invalid",
            Self::EnrollmentRequired => "enrollment-required",
            Self::EnrollmentRejected => "enrollment-rejected",
            Self::Transport(_) => "enrollment-transport-failed",
            Self::Client(_) => "enrollment-signing-failed",
            Self::Io(_) => "enrollment-state-io",
        }
    }
}

impl fmt::Display for ResidentEnrollmentError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.code())
    }
}

impl Error for ResidentEnrollmentError {}

impl From<io::Error> for ResidentEnrollmentError {
    fn from(value: io::Error) -> Self {
        Self::Io(value)
    }
}

impl From<kernaid_fleet_client::FleetClientError> for ResidentEnrollmentError {
    fn from(value: kernaid_fleet_client::FleetClientError) -> Self {
        Self::Client(value)
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
    ) -> Result<bool, ResidentEnrollmentError> {
        let bytes = match read_private_bounded(&self.path, MAX_ENROLLMENT_RESPONSE_BYTES) {
            Ok(bytes) => bytes,
            Err(ResidentEnrollmentError::Io(error)) if error.kind() == io::ErrorKind::NotFound => {
                return Ok(false);
            }
            Err(error) => return Err(error),
        };
        let state: EnrollmentState =
            serde_json::from_slice(&bytes).map_err(|_| ResidentEnrollmentError::InvalidState)?;
        let canonical =
            serde_json::to_vec(&state).map_err(|_| ResidentEnrollmentError::InvalidState)?;
        if canonical != bytes
            || state.schema != ENROLLMENT_STATE_SCHEMA
            || state.endpoint != endpoint
            || state.tenant_id != tenant_id
            || state.device_id != device_id
            || chrono::DateTime::parse_from_rfc3339(&state.enrolled_at).is_err()
        {
            return Err(ResidentEnrollmentError::InvalidState);
        }
        Ok(true)
    }

    fn persist(&self, state: &EnrollmentState) -> Result<(), ResidentEnrollmentError> {
        match fs::symlink_metadata(&self.path) {
            Ok(_) => return Err(ResidentEnrollmentError::InvalidState),
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(error) => return Err(error.into()),
        }
        let bytes = serde_json::to_vec(state).map_err(|_| ResidentEnrollmentError::InvalidState)?;
        let pending = self.directory.join(ENROLLMENT_PENDING_FILE);
        let mut options = OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        options.mode(0o600);
        let mut file = options.open(&pending)?;
        file.write_all(&bytes)?;
        file.sync_all()?;
        fs::rename(&pending, &self.path)?;
        #[cfg(unix)]
        File::open(&self.directory)?.sync_all()?;
        Ok(())
    }
}

/// Verify that normal service startup is bound to a completed enrollment.
pub fn require_enrollment(
    state_directory: &Path,
    endpoint: &str,
    tenant_id: &str,
    device_id: &str,
) -> Result<(), ResidentEnrollmentError> {
    validate_binding_inputs(state_directory, endpoint, tenant_id, device_id)?;
    if EnrollmentJournal::new(state_directory).verify(endpoint, tenant_id, device_id)? {
        Ok(())
    } else {
        Err(ResidentEnrollmentError::EnrollmentRequired)
    }
}

/// Perform one explicit, bounded enrollment attempt.
///
/// A caller must hold both its service-instance lock and the canonical
/// identity-creation lock for the complete call. `None` is accepted only when
/// the exact enrollment journal already exists.
#[allow(clippy::too_many_arguments)]
pub fn bootstrap_enrollment<T: EnrollmentTransport, S: FleetRequestSigner + ?Sized>(
    identity: &S,
    platform: EnrollmentPlatform,
    state_directory: &Path,
    tenant_id: &str,
    token: Option<&str>,
    issued_at: String,
    nonce: Zeroizing<Vec<u8>>,
    transport: &mut T,
) -> Result<EnrollmentOutcome, ResidentEnrollmentError> {
    let endpoint = transport.origin().to_owned();
    let device_id = identity.device_id()?;
    validate_binding_inputs(state_directory, &endpoint, tenant_id, &device_id)?;
    let journal = EnrollmentJournal::new(state_directory);
    if journal.verify(&endpoint, tenant_id, &device_id)? {
        return Ok(EnrollmentOutcome::AlreadyEnrolled);
    }
    let token = token.ok_or(ResidentEnrollmentError::EnrollmentRequired)?;
    let request = identity.sign_enrollment(EnrollmentRequestInput::new(
        token.to_owned(),
        tenant_id.to_owned(),
        platform,
        env!("CARGO_PKG_VERSION"),
        issued_at,
        nonce.to_vec(),
    ))?;
    let body = request.export_offline()?;
    let response = transport
        .post_enrollment(&body, MAX_ENROLLMENT_RESPONSE_BYTES)
        .map_err(ResidentEnrollmentError::Transport)?;
    if !matches!(response.status, 200 | 201)
        || response.body.is_empty()
        || response.body.len() > MAX_ENROLLMENT_RESPONSE_BYTES
    {
        return Err(ResidentEnrollmentError::EnrollmentRejected);
    }
    let accepted: EnrollmentResponse = serde_json::from_slice(&response.body)
        .map_err(|_| ResidentEnrollmentError::EnrollmentRejected)?;
    if accepted.schema != "dev.kernaid.fleet.enrollment-response.v1"
        || accepted.tenant_id != tenant_id
        || accepted.device_id != device_id
        || !accepted.accepted
        || chrono::DateTime::parse_from_rfc3339(&accepted.enrolled_at).is_err()
    {
        return Err(ResidentEnrollmentError::EnrollmentRejected);
    }
    journal.persist(&EnrollmentState {
        schema: ENROLLMENT_STATE_SCHEMA.to_owned(),
        endpoint,
        tenant_id: tenant_id.to_owned(),
        device_id,
        enrolled_at: accepted.enrolled_at,
    })?;
    Ok(EnrollmentOutcome::NewlyEnrolled)
}

pub fn read_optional_enrollment_token(
    path: &Path,
) -> Result<Option<Zeroizing<String>>, ResidentEnrollmentError> {
    let bytes = match read_private_bounded(path, MAX_ENROLLMENT_TOKEN_BYTES) {
        Ok(bytes) => Zeroizing::new(bytes),
        Err(ResidentEnrollmentError::Io(error)) if error.kind() == io::ErrorKind::NotFound => {
            return Ok(None);
        }
        Err(error) => return Err(error),
    };
    let token = trim_ascii_line(&bytes).ok_or(ResidentEnrollmentError::InvalidInput)?;
    if token.is_empty()
        || token.len() > MAX_ENROLLMENT_TOKEN_BYTES
        || token
            .iter()
            .any(|byte| !byte.is_ascii_graphic() || byte.is_ascii_whitespace())
    {
        return Err(ResidentEnrollmentError::InvalidInput);
    }
    let token =
        String::from_utf8(token.to_vec()).map_err(|_| ResidentEnrollmentError::InvalidInput)?;
    Ok(Some(Zeroizing::new(token)))
}

pub fn remove_consumed_enrollment_token(path: &Path) -> Result<(), ResidentEnrollmentError> {
    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.is_file() && !metadata.file_type().is_symlink() => {
            fs::remove_file(path)?;
            Ok(())
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        _ => Err(ResidentEnrollmentError::InvalidState),
    }
}

fn validate_binding_inputs(
    state_directory: &Path,
    endpoint: &str,
    tenant_id: &str,
    device_id: &str,
) -> Result<(), ResidentEnrollmentError> {
    if !state_directory.is_absolute()
        || state_directory.file_name().is_none()
        || !valid_https_origin(endpoint)
        || !valid_identifier(tenant_id)
        || kernaid_device_identity::validate_device_id(device_id).is_err()
    {
        return Err(ResidentEnrollmentError::InvalidInput);
    }
    Ok(())
}

fn read_private_bounded(path: &Path, maximum: usize) -> Result<Vec<u8>, ResidentEnrollmentError> {
    let metadata = fs::symlink_metadata(path)?;
    if !metadata.is_file()
        || metadata.file_type().is_symlink()
        || metadata.len() == 0
        || metadata.len() > maximum as u64
    {
        return Err(ResidentEnrollmentError::InvalidState);
    }
    #[cfg(unix)]
    if metadata.permissions().mode() & 0o077 != 0 {
        return Err(ResidentEnrollmentError::InvalidState);
    }
    #[cfg(all(
        unix,
        any(
            feature = "linux-service",
            feature = "macos-service",
            feature = "rescue-fleet-service"
        )
    ))]
    if metadata.uid() != rustix::process::getuid().as_raw() {
        return Err(ResidentEnrollmentError::InvalidState);
    }
    #[cfg(windows)]
    if metadata.file_attributes() & 0x0000_0400 != 0 {
        return Err(ResidentEnrollmentError::InvalidState);
    }
    let bytes = fs::read(path)?;
    if bytes.is_empty() || bytes.len() > maximum || bytes.len() as u64 != metadata.len() {
        return Err(ResidentEnrollmentError::InvalidState);
    }
    Ok(bytes)
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

fn valid_https_origin(value: &str) -> bool {
    let Some(authority) = value.strip_prefix("https://") else {
        return false;
    };
    !authority.is_empty()
        && authority.len() <= 255
        && !authority.contains(['/', '@', '?', '#', '\\'])
        && !authority.bytes().any(|byte| byte.is_ascii_whitespace())
}

fn valid_identifier(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 160
        && value.bytes().enumerate().all(|(index, byte)| {
            byte.is_ascii_alphanumeric() || (index > 0 && matches!(byte, b'-' | b'_' | b'.' | b':'))
        })
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::{Value, json};
    use tempfile::TempDir;

    struct AcceptingTransport {
        origin: String,
        calls: usize,
    }

    impl EnrollmentTransport for AcceptingTransport {
        fn origin(&self) -> &str {
            &self.origin
        }

        fn post_enrollment(
            &mut self,
            body: &[u8],
            maximum_response_bytes: usize,
        ) -> Result<WorkOrderTransportResponse, TransportErrorCode> {
            assert_eq!(maximum_response_bytes, MAX_ENROLLMENT_RESPONSE_BYTES);
            let request: Value = serde_json::from_slice(body).expect("request JSON");
            self.calls += 1;
            Ok(WorkOrderTransportResponse {
                status: 201,
                body: serde_json::to_vec(&json!({
                    "accepted": true,
                    "deviceId": request["deviceId"],
                    "enrolledAt": "2026-09-01T02:30:00Z",
                    "schema": "dev.kernaid.fleet.enrollment-response.v1",
                    "tenantId": request["tenantId"],
                }))
                .expect("response"),
                receipt: None,
            })
        }
    }

    #[test]
    fn bootstrap_persists_only_binding_and_is_idempotent() {
        let root = TempDir::new().expect("tempdir");
        #[cfg(unix)]
        fs::set_permissions(root.path(), fs::Permissions::from_mode(0o700)).expect("private root");
        let identity = DeviceIdentity::from_seed(&[0x71; 32]).expect("identity");
        let mut transport = AcceptingTransport {
            origin: "https://fleet.example.test".to_owned(),
            calls: 0,
        };
        assert_eq!(
            bootstrap_enrollment(
                &identity,
                EnrollmentPlatform::Macos,
                root.path(),
                "tenant-native",
                Some("enroll_secret_once"),
                "2026-09-01T02:29:59Z".to_owned(),
                Zeroizing::new(vec![0x42; 32]),
                &mut transport,
            )
            .expect("bootstrap"),
            EnrollmentOutcome::NewlyEnrolled
        );
        assert_eq!(transport.calls, 1);
        let journal = fs::read(root.path().join(ENROLLMENT_STATE_FILE)).expect("journal");
        assert!(!journal.windows(6).any(|value| value == b"secret"));
        assert_eq!(
            bootstrap_enrollment(
                &identity,
                EnrollmentPlatform::Macos,
                root.path(),
                "tenant-native",
                None,
                "2026-09-01T02:31:00Z".to_owned(),
                Zeroizing::new(vec![0x43; 32]),
                &mut transport,
            )
            .expect("idempotent bootstrap"),
            EnrollmentOutcome::AlreadyEnrolled
        );
        assert_eq!(transport.calls, 1);
    }

    #[test]
    fn normal_start_requires_exact_enrollment_binding() {
        let root = TempDir::new().expect("tempdir");
        let identity = DeviceIdentity::from_seed(&[0x72; 32]).expect("identity");
        assert!(matches!(
            require_enrollment(
                root.path(),
                "https://fleet.example.test",
                "tenant-native",
                &identity.device_id(),
            ),
            Err(ResidentEnrollmentError::EnrollmentRequired)
        ));
    }
}
