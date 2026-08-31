#![forbid(unsafe_code)]
//! Off-default Resident delivery of vendor-signed Fleet updates.
//!
//! The core has a closed transport trait and never selects a filesystem path,
//! slot, proxy, credential, or boot action from network data. Platform code
//! supplies an already-open inactive target. A successful cycle leaves a
//! durable stager receipt plus a device-signed, privacy-minimized audit receipt;
//! it deliberately does not arm or activate a boot target.

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use chrono::DateTime;
use ed25519_dalek::{Signature, VerifyingKey};
use kernaid_device_identity::{DeviceIdentity, device_id_for_public_key, validate_device_id};
use kernaid_fleet_client::{
    FleetClientError, SignedUpdatePullRequest, UpdatePullRequestInput, UpdatePullResponseError,
};
use kernaid_update_client::{
    AdmittedUpdate, ArtifactDescriptor, ArtifactStager, Availability, CompletedArtifactEvidence,
    PreopenedInactiveTarget, Slot, StagingError, StagingReceipt, StagingRecovery,
    UpdateArchitecture, UpdateCheckpoint, UpdateContext, UpdateError, UpdatePlatform, UpdateRing,
    VerifiedUpdate, admit_update,
};
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::{
    error::Error,
    fmt,
    fs::{self, File, OpenOptions},
    io::{self, Cursor, Read, Write},
    path::{Path, PathBuf},
};
use url::Url;
use zeroize::Zeroizing;

#[cfg(unix)]
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};

pub mod activation;
#[cfg(feature = "linux-resident")]
pub mod linux;
#[cfg(feature = "linux-systemd-boot-activator")]
pub mod linux_activation;

pub const UPDATE_AUDIT_RECEIPT_SCHEMA: &str = "dev.kernaid.fleet.resident-update-audit-receipt.v1";
pub const UPDATE_AUDIT_RECEIPT_DOMAIN: &[u8] = b"kernaid:fleet:resident-update-audit-receipt:v1\0";
pub const CONFIG_SCHEMA: &str = "dev.kernaid.fleet.resident-update-config.v1";
pub const RESIDENT_IDENTITY_NAMESPACE: &str = "resident-v1";

const CHECKPOINT_FILE: &str = "manifest-checkpoint.cjson";
const CHECKPOINT_TEMP_FILE: &str = ".manifest-checkpoint.pending";
const AUDIT_RECEIPT_FILE: &str = "update-audit-receipt.cjson";
const AUDIT_RECEIPT_TEMP_FILE: &str = ".update-audit-receipt.pending";
const STAGING_DIRECTORY: &str = "staging";
const MAX_PULL_RESPONSE_BYTES: usize = 256 * 1024;
const MAX_CHECKPOINT_BYTES: usize = 4 * 1024;
const MAX_RECEIPT_BYTES: usize = 16 * 1024;
const MAX_CONFIG_BYTES: usize = 16 * 1024;
const MAX_IDENTIFIER_BYTES: usize = 160;
const MAX_ENDPOINT_BYTES: usize = 4 * 1024;
const MAX_SAFE_JSON_INTEGER: u64 = 9_007_199_254_740_991;
const SIGNATURE_BYTES: usize = 64;
const MIN_INTERVAL_SECONDS: u64 = 30;
const MAX_INTERVAL_SECONDS: u64 = 24 * 60 * 60;
const MIN_TIMEOUT_SECONDS: u64 = 1;
const MAX_CONNECT_TIMEOUT_SECONDS: u64 = 30;
const MAX_REQUEST_TIMEOUT_SECONDS: u64 = 60 * 60;

/// Strict public configuration. It intentionally has no bearer token, key,
/// proxy, arbitrary route, active-target path or boot activation field.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ResidentUpdateConfig {
    pub schema: String,
    pub endpoint: String,
    pub tenant_id: String,
    pub state_directory: PathBuf,
    pub runtime_state_file: PathBuf,
    pub update_anchor_file: PathBuf,
    pub entitlement_anchor_file: PathBuf,
    pub policy_anchor_file: PathBuf,
    /// Legacy engineering mode: one locally selected inactive file and an
    /// explicit current slot. Both fields must be present together.
    #[serde(default)]
    pub inactive_target_file: Option<PathBuf>,
    #[serde(default)]
    pub active_slot: Option<Slot>,
    /// Production A/B mode: both local targets are provisioned up front and
    /// the Linux adapter selects only the inactive one from `/proc/cmdline`.
    #[serde(default)]
    pub slot_a_target_file: Option<PathBuf>,
    #[serde(default)]
    pub slot_b_target_file: Option<PathBuf>,
    pub update_ring: UpdateRing,
    pub interval_seconds: u64,
    pub connect_timeout_seconds: u64,
    pub request_timeout_seconds: u64,
}

impl ResidentUpdateConfig {
    pub fn parse(bytes: &[u8]) -> Result<Self, ResidentUpdateError> {
        if bytes.is_empty() || bytes.len() > MAX_CONFIG_BYTES {
            return Err(ResidentUpdateError::InvalidConfig);
        }
        let config: Self =
            serde_json::from_slice(bytes).map_err(|_| ResidentUpdateError::InvalidConfig)?;
        config.validate()?;
        Ok(config)
    }

    fn validate(&self) -> Result<(), ResidentUpdateError> {
        if self.schema != CONFIG_SCHEMA
            || validate_https_origin(&self.endpoint).is_err()
            || validate_identifier(&self.tenant_id).is_err()
            || !absolute_directory(&self.state_directory)
            || !absolute_file(&self.runtime_state_file)
            || !absolute_file(&self.update_anchor_file)
            || !absolute_file(&self.entitlement_anchor_file)
            || !absolute_file(&self.policy_anchor_file)
            || !(MIN_INTERVAL_SECONDS..=MAX_INTERVAL_SECONDS).contains(&self.interval_seconds)
            || !(MIN_TIMEOUT_SECONDS..=MAX_CONNECT_TIMEOUT_SECONDS)
                .contains(&self.connect_timeout_seconds)
            || !(MIN_TIMEOUT_SECONDS..=MAX_REQUEST_TIMEOUT_SECONDS)
                .contains(&self.request_timeout_seconds)
            || self.connect_timeout_seconds > self.request_timeout_seconds
        {
            return Err(ResidentUpdateError::InvalidConfig);
        }
        let legacy = match (&self.inactive_target_file, self.active_slot) {
            (Some(path), Some(_)) if absolute_file(path) => true,
            (None, None) => false,
            _ => return Err(ResidentUpdateError::InvalidConfig),
        };
        let provisioned_ab = match (&self.slot_a_target_file, &self.slot_b_target_file) {
            (Some(slot_a), Some(slot_b)) if absolute_file(slot_a) && absolute_file(slot_b) => true,
            (None, None) => false,
            _ => return Err(ResidentUpdateError::InvalidConfig),
        };
        if legacy == provisioned_ab {
            return Err(ResidentUpdateError::InvalidConfig);
        }
        let mut distinct_files = vec![
            &self.runtime_state_file,
            &self.update_anchor_file,
            &self.entitlement_anchor_file,
            &self.policy_anchor_file,
        ];
        if let Some(path) = self.inactive_target_file.as_ref() {
            distinct_files.push(path);
        }
        if let Some(path) = self.slot_a_target_file.as_ref() {
            distinct_files.push(path);
        }
        if let Some(path) = self.slot_b_target_file.as_ref() {
            distinct_files.push(path);
        }
        for (index, path) in distinct_files.iter().enumerate() {
            if distinct_files[..index].contains(path) {
                return Err(ResidentUpdateError::InvalidConfig);
            }
        }
        Ok(())
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

pub struct UpdatePullTransportResponse {
    pub status: u16,
    pub body: Vec<u8>,
}

/// Closed transport capability. The implementation can POST only the fixed
/// update-pull operation and download only the vendor-signed descriptor passed
/// by the engine.
pub trait ResidentUpdateTransport {
    type ArtifactReader: Read;

    fn origin(&self) -> &str;

    fn pull_updates(
        &mut self,
        body: &[u8],
        maximum_response_bytes: usize,
    ) -> Result<UpdatePullTransportResponse, TransportErrorCode>;

    fn download_artifact(
        &mut self,
        artifact: &ArtifactDescriptor,
    ) -> Result<Self::ArtifactReader, TransportErrorCode>;
}

pub struct UpdateCycleInput {
    pub issued_at: String,
    pub now_unix: u64,
    pub nonce: Zeroizing<Vec<u8>>,
    pub platform: UpdatePlatform,
    pub architecture: UpdateArchitecture,
    pub update_ring: UpdateRing,
    pub updates_entitled: bool,
}

impl fmt::Debug for UpdateCycleInput {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("UpdateCycleInput")
            .field("issued_at", &self.issued_at)
            .field("now_unix", &self.now_unix)
            .field("platform", &self.platform)
            .field("architecture", &self.architecture)
            .field("update_ring", &self.update_ring)
            .field("updates_entitled", &self.updates_entitled)
            .finish_non_exhaustive()
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum AuditOutcome {
    Staged,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum BootActivation {
    NotArmed,
}

/// Device-signed local audit proof. It contains only IDs, digests, slots and a
/// timestamp; artifact URLs, headers, logs, tokens and key material are absent.
#[derive(Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SignedUpdateAuditReceipt {
    schema: String,
    tenant_id: String,
    device_id: String,
    release_id: String,
    sequence: u64,
    manifest_sha256: String,
    artifact_sha256: String,
    staging_receipt_sha256: String,
    staged_at: String,
    active_slot: Slot,
    target_slot: Slot,
    outcome: AuditOutcome,
    boot_activation: BootActivation,
    signature: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct UnsignedUpdateAuditReceipt<'a> {
    schema: &'a str,
    tenant_id: &'a str,
    device_id: &'a str,
    release_id: &'a str,
    sequence: u64,
    manifest_sha256: &'a str,
    artifact_sha256: &'a str,
    staging_receipt_sha256: &'a str,
    staged_at: &'a str,
    active_slot: Slot,
    target_slot: Slot,
    outcome: AuditOutcome,
    boot_activation: BootActivation,
}

impl SignedUpdateAuditReceipt {
    fn sign(
        identity: &DeviceIdentity,
        tenant_id: &str,
        update: &VerifiedUpdate,
        staging_receipt: &StagingReceipt,
        staged_at: &str,
    ) -> Result<Self, ResidentUpdateError> {
        let target_slot = staging_receipt.target_slot();
        let staging_bytes = staging_receipt.export_canonical()?;
        let mut receipt = Self {
            schema: UPDATE_AUDIT_RECEIPT_SCHEMA.to_owned(),
            tenant_id: tenant_id.to_owned(),
            device_id: identity.device_id(),
            release_id: update.release_id().to_owned(),
            sequence: update.sequence(),
            manifest_sha256: hex_sha256(update.manifest_sha256()),
            artifact_sha256: update.artifact().sha256.clone(),
            staging_receipt_sha256: hex_sha256(&Sha256::digest(staging_bytes)),
            staged_at: staged_at.to_owned(),
            active_slot: target_slot.inactive(),
            target_slot,
            outcome: AuditOutcome::Staged,
            boot_activation: BootActivation::NotArmed,
            signature: String::new(),
        };
        receipt.validate_unsigned()?;
        let unsigned = Zeroizing::new(receipt.unsigned_canonical()?);
        receipt.signature = URL_SAFE_NO_PAD.encode(
            identity
                .sign_domain_separated_payload(UPDATE_AUDIT_RECEIPT_DOMAIN, &unsigned)
                .map_err(|_| ResidentUpdateError::ReceiptInvalid)?,
        );
        receipt.validate()?;
        Ok(receipt)
    }

    pub fn import_and_verify(
        bytes: &[u8],
        expected_tenant_id: &str,
        expected_device_id: &str,
        public_key: &[u8; 32],
    ) -> Result<Self, ResidentUpdateError> {
        let receipt: Self = import_canonical(bytes, MAX_RECEIPT_BYTES)?;
        receipt.verify(expected_tenant_id, expected_device_id, public_key)?;
        Ok(receipt)
    }

    pub fn export_canonical(&self) -> Result<Vec<u8>, ResidentUpdateError> {
        self.validate()?;
        let bytes = canonical_json(self)?;
        validate_size(bytes.len(), MAX_RECEIPT_BYTES)?;
        Ok(bytes)
    }

    pub fn verify(
        &self,
        expected_tenant_id: &str,
        expected_device_id: &str,
        public_key: &[u8; 32],
    ) -> Result<(), ResidentUpdateError> {
        self.validate()?;
        validate_identifier(expected_tenant_id)?;
        validate_device_id(expected_device_id).map_err(|_| ResidentUpdateError::ReceiptInvalid)?;
        if self.tenant_id != expected_tenant_id
            || self.device_id != expected_device_id
            || device_id_for_public_key(public_key) != expected_device_id
        {
            return Err(ResidentUpdateError::ReceiptBindingMismatch);
        }
        let signature = decode_signature(&self.signature)?;
        let verifying_key = VerifyingKey::from_bytes(public_key)
            .map_err(|_| ResidentUpdateError::ReceiptInvalid)?;
        let unsigned = Zeroizing::new(self.unsigned_canonical()?);
        let mut message = Zeroizing::new(Vec::with_capacity(
            UPDATE_AUDIT_RECEIPT_DOMAIN.len() + unsigned.len(),
        ));
        message.extend_from_slice(UPDATE_AUDIT_RECEIPT_DOMAIN);
        message.extend_from_slice(&unsigned);
        verifying_key
            .verify_strict(&message, &Signature::from_bytes(&signature))
            .map_err(|_| ResidentUpdateError::ReceiptInvalid)
    }

    #[must_use]
    pub fn tenant_id(&self) -> &str {
        &self.tenant_id
    }

    #[must_use]
    pub fn device_id(&self) -> &str {
        &self.device_id
    }

    #[must_use]
    pub fn release_id(&self) -> &str {
        &self.release_id
    }

    #[must_use]
    pub const fn sequence(&self) -> u64 {
        self.sequence
    }

    #[must_use]
    pub const fn target_slot(&self) -> Slot {
        self.target_slot
    }

    #[must_use]
    pub fn staged_at(&self) -> &str {
        &self.staged_at
    }

    fn unsigned(&self) -> UnsignedUpdateAuditReceipt<'_> {
        UnsignedUpdateAuditReceipt {
            schema: &self.schema,
            tenant_id: &self.tenant_id,
            device_id: &self.device_id,
            release_id: &self.release_id,
            sequence: self.sequence,
            manifest_sha256: &self.manifest_sha256,
            artifact_sha256: &self.artifact_sha256,
            staging_receipt_sha256: &self.staging_receipt_sha256,
            staged_at: &self.staged_at,
            active_slot: self.active_slot,
            target_slot: self.target_slot,
            outcome: self.outcome,
            boot_activation: self.boot_activation,
        }
    }

    fn unsigned_canonical(&self) -> Result<Vec<u8>, ResidentUpdateError> {
        canonical_json(&self.unsigned())
    }

    fn validate(&self) -> Result<(), ResidentUpdateError> {
        self.validate_unsigned()?;
        decode_signature(&self.signature)?;
        Ok(())
    }

    fn validate_unsigned(&self) -> Result<(), ResidentUpdateError> {
        if self.schema != UPDATE_AUDIT_RECEIPT_SCHEMA
            || self.sequence == 0
            || self.sequence > MAX_SAFE_JSON_INTEGER
            || self.active_slot.inactive() != self.target_slot
            || self.outcome != AuditOutcome::Staged
            || self.boot_activation != BootActivation::NotArmed
        {
            return Err(ResidentUpdateError::ReceiptInvalid);
        }
        validate_identifier(&self.tenant_id)?;
        validate_device_id(&self.device_id).map_err(|_| ResidentUpdateError::ReceiptInvalid)?;
        validate_identifier(&self.release_id)?;
        validate_sha256(&self.manifest_sha256)?;
        validate_sha256(&self.artifact_sha256)?;
        validate_sha256(&self.staging_receipt_sha256)?;
        validate_timestamp(&self.staged_at)
    }
}

impl fmt::Debug for SignedUpdateAuditReceipt {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SignedUpdateAuditReceipt")
            .field("tenant_id", &self.tenant_id)
            .field("device_id", &self.device_id)
            .field("release_id", &self.release_id)
            .field("sequence", &self.sequence)
            .field("target_slot", &self.target_slot)
            .field("boot_activation", &self.boot_activation)
            .finish_non_exhaustive()
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum UpdateCycleOutcome {
    NoUpdate,
    Staged(SignedUpdateAuditReceipt),
    AlreadyStaged(SignedUpdateAuditReceipt),
}

#[derive(Debug)]
pub enum ResidentUpdateError {
    InvalidConfig,
    InvalidState,
    IdentityUnavailable,
    RuntimeUnavailable,
    ClockUnavailable,
    NonceUnavailable,
    InvalidEndpoint,
    InvalidContext,
    UpdatesNotEntitled,
    HttpRejected,
    PullResponseTooLarge,
    ResponseNotEligible(Availability),
    ResponseConflict,
    StateCorrupt,
    ReceiptInvalid,
    ReceiptBindingMismatch,
    Transport(TransportErrorCode),
    Client(FleetClientError),
    PullResponse(UpdatePullResponseError),
    Update(UpdateError),
    Staging(StagingError),
    Activation(activation::ActivationError),
    Io(io::Error),
}

impl ResidentUpdateError {
    #[must_use]
    pub const fn code(&self) -> &'static str {
        match self {
            Self::InvalidConfig => "config-invalid",
            Self::InvalidState => "state-invalid",
            Self::IdentityUnavailable => "identity-unavailable",
            Self::RuntimeUnavailable => "runtime-unavailable",
            Self::ClockUnavailable => "clock-unavailable",
            Self::NonceUnavailable => "nonce-unavailable",
            Self::InvalidEndpoint => "endpoint-invalid",
            Self::InvalidContext => "context-invalid",
            Self::UpdatesNotEntitled => "updates-not-entitled",
            Self::HttpRejected => "http-rejected",
            Self::PullResponseTooLarge => "pull-response-large",
            Self::ResponseNotEligible(_) => "manifest-not-eligible",
            Self::ResponseConflict => "manifest-response-conflict",
            Self::StateCorrupt => "update-state-corrupt",
            Self::ReceiptInvalid => "audit-receipt-invalid",
            Self::ReceiptBindingMismatch => "audit-receipt-binding",
            Self::Transport(code) => match code {
                TransportErrorCode::InvalidEndpoint => "transport-endpoint",
                TransportErrorCode::Connect => "transport-connect",
                TransportErrorCode::Timeout => "transport-timeout",
                TransportErrorCode::Tls => "transport-tls",
                TransportErrorCode::Protocol => "transport-protocol",
                TransportErrorCode::ResponseTooLarge => "transport-response-large",
            },
            Self::Client(_) => "request-signing-failed",
            Self::PullResponse(_) => "pull-response-invalid",
            Self::Update(error) => match error {
                UpdateError::SequenceRollback => "manifest-sequence-rollback",
                UpdateError::SequenceConflict => "manifest-sequence-conflict",
                _ => "manifest-invalid",
            },
            Self::Staging(_) => "artifact-staging-failed",
            Self::Activation(error) => error.code(),
            Self::Io(_) => "update-state-io",
        }
    }
}

impl fmt::Display for ResidentUpdateError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.code())
    }
}

impl Error for ResidentUpdateError {}

impl From<FleetClientError> for ResidentUpdateError {
    fn from(value: FleetClientError) -> Self {
        Self::Client(value)
    }
}

impl From<UpdatePullResponseError> for ResidentUpdateError {
    fn from(value: UpdatePullResponseError) -> Self {
        Self::PullResponse(value)
    }
}

impl From<UpdateError> for ResidentUpdateError {
    fn from(value: UpdateError) -> Self {
        Self::Update(value)
    }
}

impl From<StagingError> for ResidentUpdateError {
    fn from(value: StagingError) -> Self {
        Self::Staging(value)
    }
}

impl From<activation::ActivationError> for ResidentUpdateError {
    fn from(value: activation::ActivationError) -> Self {
        Self::Activation(value)
    }
}

impl From<io::Error> for ResidentUpdateError {
    fn from(value: io::Error) -> Self {
        Self::Io(value)
    }
}

struct UpdateJournal {
    directory: PathBuf,
}

impl UpdateJournal {
    fn open(directory: &Path) -> Result<Self, ResidentUpdateError> {
        prepare_private_directory(directory)?;
        let journal = Self {
            directory: directory.to_path_buf(),
        };
        journal.cleanup_temporary(CHECKPOINT_TEMP_FILE)?;
        journal.cleanup_temporary(AUDIT_RECEIPT_TEMP_FILE)?;
        let _ = journal.load_checkpoint()?;
        Ok(journal)
    }

    fn load_checkpoint(&self) -> Result<Option<UpdateCheckpoint>, ResidentUpdateError> {
        self.read_optional(CHECKPOINT_FILE, MAX_CHECKPOINT_BYTES)?
            .map(|bytes| UpdateCheckpoint::import_canonical(&bytes).map_err(Into::into))
            .transpose()
    }

    fn persist_checkpoint(
        &self,
        previous: Option<&UpdateCheckpoint>,
        next: &UpdateCheckpoint,
    ) -> Result<(), ResidentUpdateError> {
        let retained = self.load_checkpoint()?;
        if retained.as_ref() != previous {
            return Err(ResidentUpdateError::StateCorrupt);
        }
        let bytes = next.export_canonical()?;
        if retained.as_ref() == Some(next) {
            return Ok(());
        }
        self.write_atomic(
            CHECKPOINT_FILE,
            CHECKPOINT_TEMP_FILE,
            &bytes,
            retained.is_some(),
        )
    }

    fn load_audit_receipt(
        &self,
        tenant_id: &str,
        device_id: &str,
        public_key: &[u8; 32],
    ) -> Result<Option<SignedUpdateAuditReceipt>, ResidentUpdateError> {
        self.read_optional(AUDIT_RECEIPT_FILE, MAX_RECEIPT_BYTES)?
            .map(|bytes| {
                SignedUpdateAuditReceipt::import_and_verify(
                    &bytes, tenant_id, device_id, public_key,
                )
            })
            .transpose()
    }

    fn persist_audit_receipt(
        &self,
        receipt: &SignedUpdateAuditReceipt,
    ) -> Result<(), ResidentUpdateError> {
        let bytes = receipt.export_canonical()?;
        match self.read_optional(AUDIT_RECEIPT_FILE, MAX_RECEIPT_BYTES)? {
            Some(existing) if existing == bytes => Ok(()),
            Some(_) => Err(ResidentUpdateError::StateCorrupt),
            None => self.write_atomic(AUDIT_RECEIPT_FILE, AUDIT_RECEIPT_TEMP_FILE, &bytes, false),
        }
    }

    fn read_optional(
        &self,
        name: &str,
        maximum: usize,
    ) -> Result<Option<Vec<u8>>, ResidentUpdateError> {
        let path = self.directory.join(name);
        match fs::symlink_metadata(&path) {
            Ok(metadata) => {
                inspect_private_file(&metadata)?;
                if metadata.len() == 0 || metadata.len() > maximum as u64 {
                    return Err(ResidentUpdateError::StateCorrupt);
                }
                let bytes = fs::read(path)?;
                if bytes.len() > maximum || bytes.len() as u64 != metadata.len() {
                    return Err(ResidentUpdateError::StateCorrupt);
                }
                Ok(Some(bytes))
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(None),
            Err(error) => Err(error.into()),
        }
    }

    fn write_atomic(
        &self,
        name: &str,
        temporary_name: &str,
        bytes: &[u8],
        replace: bool,
    ) -> Result<(), ResidentUpdateError> {
        if bytes.is_empty() {
            return Err(ResidentUpdateError::StateCorrupt);
        }
        let target = self.directory.join(name);
        let temporary = self.directory.join(temporary_name);
        match fs::symlink_metadata(&target) {
            Ok(metadata) if replace => inspect_private_file(&metadata)?,
            Ok(_) => return Err(ResidentUpdateError::StateCorrupt),
            Err(error) if error.kind() == io::ErrorKind::NotFound && !replace => {}
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                return Err(ResidentUpdateError::StateCorrupt);
            }
            Err(error) => return Err(error.into()),
        }
        let mut options = OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        options.mode(0o600);
        let mut file = options.open(&temporary)?;
        let result = (|| -> Result<(), ResidentUpdateError> {
            file.write_all(bytes)?;
            file.flush()?;
            file.sync_all()?;
            fs::rename(&temporary, &target)?;
            sync_directory(&self.directory)?;
            inspect_private_file(&fs::symlink_metadata(&target)?)?;
            Ok(())
        })();
        if result.is_err() {
            let _ = fs::remove_file(&temporary);
        }
        result
    }

    fn cleanup_temporary(&self, name: &str) -> Result<(), ResidentUpdateError> {
        let path = self.directory.join(name);
        match fs::symlink_metadata(&path) {
            Ok(metadata) => {
                inspect_private_file(&metadata)?;
                fs::remove_file(path)?;
                sync_directory(&self.directory)
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
            Err(error) => Err(error.into()),
        }
    }
}

pub struct ResidentUpdateEngine<T> {
    endpoint: String,
    tenant_id: String,
    update_anchor: VerifyingKey,
    transport: T,
    journal: UpdateJournal,
    stager: ArtifactStager,
}

impl<T: ResidentUpdateTransport> ResidentUpdateEngine<T> {
    pub fn open(
        endpoint: &str,
        tenant_id: &str,
        state_directory: &Path,
        update_anchor: &[u8; 32],
        transport: T,
    ) -> Result<Self, ResidentUpdateError> {
        let endpoint = validate_https_origin(endpoint)?;
        if transport.origin() != endpoint {
            return Err(ResidentUpdateError::InvalidEndpoint);
        }
        validate_identifier(tenant_id)?;
        let update_anchor = VerifyingKey::from_bytes(update_anchor)
            .map_err(|_| ResidentUpdateError::InvalidContext)?;
        let journal = UpdateJournal::open(state_directory)?;
        let stager = ArtifactStager::open(&state_directory.join(STAGING_DIRECTORY))?;
        Ok(Self {
            endpoint,
            tenant_id: tenant_id.to_owned(),
            update_anchor,
            transport,
            journal,
            stager,
        })
    }

    #[must_use]
    pub fn endpoint(&self) -> &str {
        &self.endpoint
    }

    pub fn run_once(
        &mut self,
        identity: &DeviceIdentity,
        input: UpdateCycleInput,
        target: &mut PreopenedInactiveTarget,
    ) -> Result<UpdateCycleOutcome, ResidentUpdateError> {
        validate_cycle_input(&input)?;
        let device_id = identity.device_id();
        if let Some(receipt) =
            self.journal
                .load_audit_receipt(&self.tenant_id, &device_id, &identity.public_key())?
        {
            self.verify_completed_receipt(&receipt)?;
            return Ok(UpdateCycleOutcome::AlreadyStaged(receipt));
        }
        if !input.updates_entitled {
            return Err(ResidentUpdateError::UpdatesNotEntitled);
        }

        let request = SignedUpdatePullRequest::sign(
            identity,
            UpdatePullRequestInput::new(
                &self.tenant_id,
                input.platform,
                input.architecture,
                input.update_ring,
                &input.issued_at,
                input.nonce.to_vec(),
            ),
        )?;
        let request_bytes = request.export_offline()?;
        let response = self
            .transport
            .pull_updates(&request_bytes, MAX_PULL_RESPONSE_BYTES)
            .map_err(ResidentUpdateError::Transport)?;
        if response.status != 200 {
            return Err(ResidentUpdateError::HttpRejected);
        }
        if response.body.len() > MAX_PULL_RESPONSE_BYTES {
            return Err(ResidentUpdateError::PullResponseTooLarge);
        }
        let updates = request.import_verified_response(&response.body, &self.update_anchor)?;
        let context = UpdateContext {
            device_id: &device_id,
            platform: input.platform,
            architecture: input.architecture,
            update_ring: input.update_ring,
            now_unix: input.now_unix,
        };
        let Some(verified) = select_update(updates, &context)? else {
            return Ok(UpdateCycleOutcome::NoUpdate);
        };

        let previous = self.journal.load_checkpoint()?;
        let admission = admit_update(previous.as_ref(), verified)?;
        self.journal
            .persist_checkpoint(previous.as_ref(), &admission.next_checkpoint)?;

        let staging_receipt = match self.stager.recovery_status()? {
            StagingRecovery::Completed(_) => self.stager.stage(
                &admission.update,
                &context,
                input.updates_entitled,
                &mut Cursor::new(Vec::<u8>::new()),
                target,
            )?,
            StagingRecovery::Clean | StagingRecovery::Interrupted(_) => {
                let mut source = self
                    .transport
                    .download_artifact(admission.update.verified().artifact())
                    .map_err(ResidentUpdateError::Transport)?;
                self.stager.stage(
                    &admission.update,
                    &context,
                    input.updates_entitled,
                    &mut source,
                    target,
                )?
            }
        };
        let activation_candidate =
            activation::BootActivationCandidate::derive(&admission.update, &staging_receipt)?;
        activation::ActivationJournal::open(&self.journal.directory)?
            .persist_candidate(&activation_candidate)?;
        let receipt = SignedUpdateAuditReceipt::sign(
            identity,
            &self.tenant_id,
            admission.update.verified(),
            &staging_receipt,
            &input.issued_at,
        )?;
        self.journal.persist_audit_receipt(&receipt)?;
        Ok(UpdateCycleOutcome::Staged(receipt))
    }

    fn verify_completed_receipt(
        &self,
        receipt: &SignedUpdateAuditReceipt,
    ) -> Result<(), ResidentUpdateError> {
        let StagingRecovery::Completed(staging_receipt) = self.stager.recovery_status()? else {
            return Err(ResidentUpdateError::StateCorrupt);
        };
        let digest = hex_sha256(&Sha256::digest(staging_receipt.export_canonical()?));
        if staging_receipt.release_id() != receipt.release_id
            || staging_receipt.sequence() != receipt.sequence
            || staging_receipt.target_slot() != receipt.target_slot
            || digest != receipt.staging_receipt_sha256
        {
            return Err(ResidentUpdateError::StateCorrupt);
        }
        Ok(())
    }
}

fn select_update(
    mut updates: Vec<VerifiedUpdate>,
    context: &UpdateContext<'_>,
) -> Result<Option<VerifiedUpdate>, ResidentUpdateError> {
    for update in &updates {
        let availability = update.availability(context);
        if availability != Availability::Eligible {
            return Err(ResidentUpdateError::ResponseNotEligible(availability));
        }
    }
    updates.sort_by_key(VerifiedUpdate::sequence);
    if let [.., previous, last] = updates.as_slice()
        && previous.sequence() == last.sequence()
        && previous.manifest_sha256() != last.manifest_sha256()
    {
        return Err(ResidentUpdateError::ResponseConflict);
    }
    Ok(updates.pop())
}

fn validate_cycle_input(input: &UpdateCycleInput) -> Result<(), ResidentUpdateError> {
    validate_timestamp(&input.issued_at)?;
    if input.now_unix == 0
        || input.now_unix > MAX_SAFE_JSON_INTEGER
        || !(16..=64).contains(&input.nonce.len())
    {
        return Err(ResidentUpdateError::InvalidContext);
    }
    Ok(())
}

fn validate_https_origin(value: &str) -> Result<String, ResidentUpdateError> {
    if value.is_empty() || value.len() > MAX_ENDPOINT_BYTES {
        return Err(ResidentUpdateError::InvalidEndpoint);
    }
    let mut url = Url::parse(value).map_err(|_| ResidentUpdateError::InvalidEndpoint)?;
    if url.scheme() != "https"
        || url.host_str().is_none()
        || !url.username().is_empty()
        || url.password().is_some()
        || url.query().is_some()
        || url.fragment().is_some()
        || !matches!(url.path(), "" | "/")
    {
        return Err(ResidentUpdateError::InvalidEndpoint);
    }
    url.set_path("/");
    Ok(url.origin().ascii_serialization())
}

fn absolute_directory(path: &Path) -> bool {
    path.is_absolute() && path.parent().is_some() && path != Path::new("/")
}

fn absolute_file(path: &Path) -> bool {
    path.is_absolute()
        && path
            .file_name()
            .is_some_and(|name| !name.is_empty() && name != "." && name != "..")
}

fn prepare_private_directory(path: &Path) -> Result<(), ResidentUpdateError> {
    if !path.is_absolute() {
        return Err(ResidentUpdateError::StateCorrupt);
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

fn inspect_private_directory(metadata: &fs::Metadata) -> Result<(), ResidentUpdateError> {
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err(ResidentUpdateError::StateCorrupt);
    }
    #[cfg(unix)]
    if metadata.permissions().mode() & 0o077 != 0 {
        return Err(ResidentUpdateError::StateCorrupt);
    }
    Ok(())
}

fn inspect_private_file(metadata: &fs::Metadata) -> Result<(), ResidentUpdateError> {
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return Err(ResidentUpdateError::StateCorrupt);
    }
    #[cfg(unix)]
    if metadata.permissions().mode() & 0o077 != 0 {
        return Err(ResidentUpdateError::StateCorrupt);
    }
    Ok(())
}

#[cfg(unix)]
fn sync_directory(path: &Path) -> Result<(), ResidentUpdateError> {
    File::open(path)?.sync_all()?;
    Ok(())
}

#[cfg(not(unix))]
fn sync_directory(_path: &Path) -> Result<(), ResidentUpdateError> {
    Ok(())
}

fn decode_signature(encoded: &str) -> Result<[u8; SIGNATURE_BYTES], ResidentUpdateError> {
    if encoded.contains('=') || encoded.len() > 128 {
        return Err(ResidentUpdateError::ReceiptInvalid);
    }
    let decoded = URL_SAFE_NO_PAD
        .decode(encoded)
        .map_err(|_| ResidentUpdateError::ReceiptInvalid)?;
    if decoded.len() != SIGNATURE_BYTES || URL_SAFE_NO_PAD.encode(&decoded) != encoded {
        return Err(ResidentUpdateError::ReceiptInvalid);
    }
    decoded
        .try_into()
        .map_err(|_| ResidentUpdateError::ReceiptInvalid)
}

fn validate_identifier(value: &str) -> Result<(), ResidentUpdateError> {
    if value.is_empty()
        || value.len() > MAX_IDENTIFIER_BYTES
        || !value.bytes().all(|byte| {
            byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b':' | b'/')
        })
    {
        return Err(ResidentUpdateError::ReceiptInvalid);
    }
    Ok(())
}

fn validate_timestamp(value: &str) -> Result<(), ResidentUpdateError> {
    if value.is_empty()
        || value.len() > 64
        || DateTime::parse_from_rfc3339(value).is_err()
        || value.chars().any(char::is_control)
    {
        return Err(ResidentUpdateError::InvalidContext);
    }
    Ok(())
}

fn validate_sha256(value: &str) -> Result<(), ResidentUpdateError> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(ResidentUpdateError::ReceiptInvalid);
    }
    Ok(())
}

fn hex_sha256(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn validate_size(actual: usize, maximum: usize) -> Result<(), ResidentUpdateError> {
    if actual == 0 || actual > maximum {
        return Err(ResidentUpdateError::StateCorrupt);
    }
    Ok(())
}

fn import_canonical<T>(bytes: &[u8], maximum: usize) -> Result<T, ResidentUpdateError>
where
    T: DeserializeOwned + Serialize,
{
    validate_size(bytes.len(), maximum)?;
    let parsed: T = serde_json::from_slice(bytes).map_err(|_| ResidentUpdateError::StateCorrupt)?;
    if canonical_json(&parsed)? != bytes {
        return Err(ResidentUpdateError::StateCorrupt);
    }
    Ok(parsed)
}

fn canonical_json<T: Serialize>(value: &T) -> Result<Vec<u8>, ResidentUpdateError> {
    let value = serde_json::to_value(value).map_err(|_| ResidentUpdateError::StateCorrupt)?;
    validate_json(&value)?;
    let mut output = Vec::new();
    write_canonical(&value, &mut output)?;
    Ok(output)
}

fn validate_json(value: &Value) -> Result<(), ResidentUpdateError> {
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
                Err(ResidentUpdateError::StateCorrupt)
            }
        }
        Value::Array(values) => values.iter().try_for_each(validate_json),
        Value::Object(values) => values.values().try_for_each(validate_json),
    }
}

fn write_canonical(value: &Value, output: &mut Vec<u8>) -> Result<(), ResidentUpdateError> {
    match value {
        Value::Null => output.extend_from_slice(b"null"),
        Value::Bool(value) => output.extend_from_slice(if *value { b"true" } else { b"false" }),
        Value::Number(value) => output.extend_from_slice(value.to_string().as_bytes()),
        Value::String(value) => output.extend_from_slice(
            serde_json::to_string(value)
                .map_err(|_| ResidentUpdateError::StateCorrupt)?
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
                        .map_err(|_| ResidentUpdateError::StateCorrupt)?
                        .as_bytes(),
                );
                output.push(b':');
                write_canonical(
                    values.get(key).ok_or(ResidentUpdateError::StateCorrupt)?,
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
    use ed25519_dalek::SigningKey;
    use kernaid_update_client::{
        ReleaseRing, Rollout, SignedUpdateManifest, UpdateManifestContent,
    };
    use serde_json::json;
    use std::{
        io::{Seek as _, SeekFrom},
        sync::{
            Arc,
            atomic::{AtomicUsize, Ordering},
        },
    };
    use tempfile::TempDir;

    const ENDPOINT: &str = "https://fleet.example.test";
    const TENANT: &str = "tenant-europe-1";
    const ISSUED_AT: &str = "2026-08-31T12:30:45Z";
    const NOW_UNIX: u64 = 1_500;

    #[derive(Clone)]
    struct MockTransport {
        identity_public_key: [u8; 32],
        device_id: String,
        manifest: SignedUpdateManifest,
        artifact: Vec<u8>,
        response_tenant: String,
        pulls: Arc<AtomicUsize>,
        downloads: Arc<AtomicUsize>,
    }

    impl ResidentUpdateTransport for MockTransport {
        type ArtifactReader = Cursor<Vec<u8>>;

        fn origin(&self) -> &str {
            ENDPOINT
        }

        fn pull_updates(
            &mut self,
            body: &[u8],
            _maximum_response_bytes: usize,
        ) -> Result<UpdatePullTransportResponse, TransportErrorCode> {
            self.pulls.fetch_add(1, Ordering::SeqCst);
            let request = SignedUpdatePullRequest::import_offline(
                body,
                TENANT,
                &self.device_id,
                &self.identity_public_key,
            )
            .map_err(|_| TransportErrorCode::Protocol)?;
            let response = serde_json::to_vec(&json!({
                "architecture": request.architecture(),
                "deviceId": request.device_id(),
                "items": [self.manifest],
                "platform": request.platform(),
                "schema": kernaid_fleet_client::UPDATE_PULL_RESPONSE_SCHEMA,
                "tenantId": self.response_tenant,
                "updateRing": request.update_ring()
            }))
            .map_err(|_| TransportErrorCode::Protocol)?;
            Ok(UpdatePullTransportResponse {
                status: 200,
                body: response,
            })
        }

        fn download_artifact(
            &mut self,
            _artifact: &ArtifactDescriptor,
        ) -> Result<Self::ArtifactReader, TransportErrorCode> {
            self.downloads.fetch_add(1, Ordering::SeqCst);
            Ok(Cursor::new(self.artifact.clone()))
        }
    }

    fn identity() -> DeviceIdentity {
        DeviceIdentity::from_seed(&[0x42; 32]).expect("fixed test identity")
    }

    fn vendor() -> SigningKey {
        SigningKey::from_bytes(&[0x77; 32])
    }

    fn artifact() -> Vec<u8> {
        b"signed enterprise update artifact".to_vec()
    }

    fn manifest(sequence: u64, artifact: &[u8]) -> SignedUpdateManifest {
        SignedUpdateManifest::sign(
            UpdateManifestContent {
                sequence,
                release_id: format!("release-{sequence}"),
                release_version: format!("1.0.{sequence}"),
                platform: UpdatePlatform::Linux,
                architecture: UpdateArchitecture::X86_64,
                release_ring: ReleaseRing::Stable,
                rollout: Rollout {
                    basis_points: 10_000,
                    seed: format!("release-{sequence}-cohort"),
                },
                issued_at_unix: 1_000,
                not_before_unix: 1_000,
                expires_at_unix: 3_000,
                artifact: ArtifactDescriptor {
                    url: format!("https://updates.example.test/release-{sequence}.img"),
                    size_bytes: artifact.len() as u64,
                    sha256: hex_sha256(&Sha256::digest(artifact)),
                },
                emergency_rollback: false,
            },
            &vendor(),
        )
        .expect("sign test manifest")
    }

    fn counters() -> (Arc<AtomicUsize>, Arc<AtomicUsize>) {
        (Arc::new(AtomicUsize::new(0)), Arc::new(AtomicUsize::new(0)))
    }

    fn transport(
        identity: &DeviceIdentity,
        manifest: SignedUpdateManifest,
        artifact: Vec<u8>,
        pulls: Arc<AtomicUsize>,
        downloads: Arc<AtomicUsize>,
    ) -> MockTransport {
        MockTransport {
            identity_public_key: identity.public_key(),
            device_id: identity.device_id(),
            manifest,
            artifact,
            response_tenant: TENANT.to_owned(),
            pulls,
            downloads,
        }
    }

    fn input(entitled: bool, ring: UpdateRing) -> UpdateCycleInput {
        UpdateCycleInput {
            issued_at: ISSUED_AT.to_owned(),
            now_unix: NOW_UNIX,
            nonce: Zeroizing::new(vec![0xa5; 32]),
            platform: UpdatePlatform::Linux,
            architecture: UpdateArchitecture::X86_64,
            update_ring: ring,
            updates_entitled: entitled,
        }
    }

    fn target(directory: &TempDir) -> PreopenedInactiveTarget {
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .open(directory.path().join("inactive-b.img"))
            .expect("create inactive target");
        PreopenedInactiveTarget::new(file, Slot::A, Slot::B).expect("inactive target")
    }

    #[test]
    fn signed_pull_stages_exact_artifact_and_writes_verifiable_audit_receipt() {
        let directory = TempDir::new().expect("tempdir");
        let identity = identity();
        let artifact = artifact();
        let (pulls, downloads) = counters();
        let transport = transport(
            &identity,
            manifest(7, &artifact),
            artifact.clone(),
            Arc::clone(&pulls),
            Arc::clone(&downloads),
        );
        let state = directory.path().join("update-state");
        let mut engine = ResidentUpdateEngine::open(
            ENDPOINT,
            TENANT,
            &state,
            &vendor().verifying_key().to_bytes(),
            transport,
        )
        .expect("open engine");
        let mut target = target(&directory);
        let outcome = engine
            .run_once(&identity, input(true, UpdateRing::Stable), &mut target)
            .expect("stage update");
        let receipt = match outcome {
            UpdateCycleOutcome::Staged(receipt) => Some(receipt),
            _ => None,
        }
        .expect("expected staged update");
        receipt
            .verify(TENANT, &identity.device_id(), &identity.public_key())
            .expect("verify audit receipt");
        let audit_json: Value = serde_json::from_slice(
            &receipt
                .export_canonical()
                .expect("export staging audit receipt"),
        )
        .expect("parse staging audit receipt");
        assert_eq!(audit_json["bootActivation"], "not_armed");
        let candidate = activation::ActivationJournal::open(&state)
            .expect("open activation journal")
            .load_candidate()
            .expect("load activation candidate")
            .expect("activation candidate exists");
        assert_eq!(candidate.release_id(), receipt.release_id());
        assert_eq!(candidate.sequence(), receipt.sequence());
        assert_eq!(candidate.target_slot(), receipt.target_slot());
        assert_eq!(receipt.sequence(), 7);
        assert_eq!(receipt.target_slot(), Slot::B);
        assert_eq!(pulls.load(Ordering::SeqCst), 1);
        assert_eq!(downloads.load(Ordering::SeqCst), 1);
        let mut file = target.into_inner();
        file.seek(SeekFrom::Start(0)).expect("seek target");
        let mut staged = Vec::new();
        file.read_to_end(&mut staged).expect("read target");
        assert_eq!(staged, artifact);
    }

    #[test]
    fn exact_restart_replay_never_calls_network_or_rewrites_target() {
        let directory = TempDir::new().expect("tempdir");
        let identity = identity();
        let bytes = artifact();
        let (pulls, downloads) = counters();
        let state = directory.path().join("update-state");
        let anchor = vendor().verifying_key().to_bytes();
        let mut first = ResidentUpdateEngine::open(
            ENDPOINT,
            TENANT,
            &state,
            &anchor,
            transport(
                &identity,
                manifest(7, &bytes),
                bytes.clone(),
                Arc::clone(&pulls),
                Arc::clone(&downloads),
            ),
        )
        .expect("open first engine");
        let mut first_target = target(&directory);
        first
            .run_once(
                &identity,
                input(true, UpdateRing::Stable),
                &mut first_target,
            )
            .expect("first stage");
        drop(first);

        let mut reopened = ResidentUpdateEngine::open(
            ENDPOINT,
            TENANT,
            &state,
            &anchor,
            transport(
                &identity,
                manifest(7, &bytes),
                Vec::new(),
                Arc::clone(&pulls),
                Arc::clone(&downloads),
            ),
        )
        .expect("reopen engine");
        let outcome = reopened
            .run_once(&identity, input(false, UpdateRing::Hold), &mut first_target)
            .expect("exact completed replay");
        let receipt = match outcome {
            UpdateCycleOutcome::AlreadyStaged(receipt) => Some(receipt),
            _ => None,
        }
        .expect("expected completed replay");
        assert_eq!(receipt.sequence(), 7);
        assert_eq!(pulls.load(Ordering::SeqCst), 1);
        assert_eq!(downloads.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn failed_download_keeps_anti_rollback_checkpoint_across_restart() {
        let directory = TempDir::new().expect("tempdir");
        let identity = identity();
        let bytes = artifact();
        let (pulls, downloads) = counters();
        let state = directory.path().join("update-state");
        let anchor = vendor().verifying_key().to_bytes();
        let mut first = ResidentUpdateEngine::open(
            ENDPOINT,
            TENANT,
            &state,
            &anchor,
            transport(
                &identity,
                manifest(7, &bytes),
                bytes[..bytes.len() - 1].to_vec(),
                Arc::clone(&pulls),
                Arc::clone(&downloads),
            ),
        )
        .expect("open first engine");
        let mut first_target = target(&directory);
        assert!(matches!(
            first.run_once(
                &identity,
                input(true, UpdateRing::Stable),
                &mut first_target
            ),
            Err(ResidentUpdateError::Staging(StagingError::SourceTruncated))
        ));
        drop(first);

        let mut reopened = ResidentUpdateEngine::open(
            ENDPOINT,
            TENANT,
            &state,
            &anchor,
            transport(
                &identity,
                manifest(6, &bytes),
                bytes,
                Arc::clone(&pulls),
                Arc::clone(&downloads),
            ),
        )
        .expect("reopen engine");
        assert!(matches!(
            reopened.run_once(
                &identity,
                input(true, UpdateRing::Stable),
                &mut first_target
            ),
            Err(ResidentUpdateError::Update(UpdateError::SequenceRollback))
        ));
        assert_eq!(pulls.load(Ordering::SeqCst), 2);
        assert_eq!(downloads.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn entitlement_hold_and_response_binding_fail_before_artifact_write() {
        let directory = TempDir::new().expect("tempdir");
        let identity = identity();
        let bytes = artifact();
        let (pulls, downloads) = counters();
        let state = directory.path().join("update-state");
        let anchor = vendor().verifying_key().to_bytes();
        let mut target = target(&directory);
        let mut engine = ResidentUpdateEngine::open(
            ENDPOINT,
            TENANT,
            &state,
            &anchor,
            transport(
                &identity,
                manifest(7, &bytes),
                bytes.clone(),
                Arc::clone(&pulls),
                Arc::clone(&downloads),
            ),
        )
        .expect("open engine");
        assert!(matches!(
            engine.run_once(&identity, input(false, UpdateRing::Stable), &mut target),
            Err(ResidentUpdateError::UpdatesNotEntitled)
        ));
        assert!(matches!(
            engine.run_once(&identity, input(true, UpdateRing::Hold), &mut target),
            Err(ResidentUpdateError::ResponseNotEligible(Availability::Held))
        ));
        assert_eq!(pulls.load(Ordering::SeqCst), 1);
        assert_eq!(downloads.load(Ordering::SeqCst), 0);

        let other_state = directory.path().join("other-state");
        let mut mismatched = transport(
            &identity,
            manifest(7, &bytes),
            bytes,
            Arc::clone(&pulls),
            Arc::clone(&downloads),
        );
        mismatched.response_tenant = "tenant-other".to_owned();
        let mut engine =
            ResidentUpdateEngine::open(ENDPOINT, TENANT, &other_state, &anchor, mismatched)
                .expect("open mismatched engine");
        assert!(matches!(
            engine.run_once(&identity, input(true, UpdateRing::Stable), &mut target),
            Err(ResidentUpdateError::PullResponse(
                UpdatePullResponseError::BindingMismatch
            ))
        ));
        assert_eq!(downloads.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn config_is_bounded_strict_and_has_no_secret_or_activation_fields() {
        let valid = json!({
            "activeSlot": "A",
            "connectTimeoutSeconds": 10,
            "endpoint": ENDPOINT,
            "entitlementAnchorFile": "/etc/kernaid/entitlement.pub",
            "inactiveTargetFile": "/var/lib/kernaid/slot-b.img",
            "intervalSeconds": 300,
            "policyAnchorFile": "/etc/kernaid/policy.pub",
            "requestTimeoutSeconds": 600,
            "runtimeStateFile": "/var/lib/kernaid/runtime.sqlite3",
            "schema": CONFIG_SCHEMA,
            "stateDirectory": "/var/lib/kernaid/update",
            "tenantId": TENANT,
            "updateAnchorFile": "/etc/kernaid/update.pub",
            "updateRing": "stable"
        });
        ResidentUpdateConfig::parse(&serde_json::to_vec(&valid).expect("config bytes"))
            .expect("valid config");
        for forbidden in ["token", "seed", "proxy", "activateBoot"] {
            let mut invalid = valid.clone();
            invalid[forbidden] = json!("forbidden");
            assert!(matches!(
                ResidentUpdateConfig::parse(
                    &serde_json::to_vec(&invalid).expect("invalid config bytes")
                ),
                Err(ResidentUpdateError::InvalidConfig)
            ));
        }

        let mut ab = valid.clone();
        ab.as_object_mut()
            .expect("A/B config object")
            .remove("activeSlot");
        ab.as_object_mut()
            .expect("A/B config object")
            .remove("inactiveTargetFile");
        ab["slotATargetFile"] = json!("/boot/EFI/Linux/kernaid-slot-a.efi");
        ab["slotBTargetFile"] = json!("/boot/EFI/Linux/kernaid-slot-b.efi");
        ResidentUpdateConfig::parse(&serde_json::to_vec(&ab).expect("serialize A/B config"))
            .expect("valid provisioned A/B config");

        let mut mixed = ab.clone();
        mixed["activeSlot"] = json!("A");
        mixed["inactiveTargetFile"] = json!("/var/lib/kernaid/slot-b.img");
        assert!(
            ResidentUpdateConfig::parse(
                &serde_json::to_vec(&mixed).expect("serialize mixed config")
            )
            .is_err()
        );

        let mut incomplete = ab;
        incomplete
            .as_object_mut()
            .expect("incomplete config object")
            .remove("slotBTargetFile");
        assert!(
            ResidentUpdateConfig::parse(
                &serde_json::to_vec(&incomplete).expect("serialize incomplete config")
            )
            .is_err()
        );
    }
}
