#![forbid(unsafe_code)]
//! Offline-first Fleet enrollment and inventory envelopes.
//!
//! The client borrows an existing [`DeviceIdentity`] for each signing
//! operation. It owns neither a seed nor a private key and therefore cannot
//! create a second secret-storage path. Wire bytes are deterministic canonical
//! JSON and imports accept only the exact canonical form.

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use chrono::DateTime;
use ed25519_dalek::{Signature, VerifyingKey};
use kernaid_device_identity::{
    DeviceIdentity, IdentityError, device_id_for_public_key, validate_device_id,
};
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::{fmt, str};
use zeroize::Zeroizing;

mod policy_pull;
pub use policy_pull::*;
mod entitlement_pull;
pub use entitlement_pull::*;
mod update_pull;
pub use update_pull::*;
mod work_order;
pub use work_order::*;

/// Enrollment wire schema.
pub const ENROLLMENT_REQUEST_SCHEMA: &str = "dev.kernaid.fleet.enrollment-request.v1";
/// Inventory wire schema.
pub const INVENTORY_ENVELOPE_SCHEMA: &str = "dev.kernaid.fleet.inventory-envelope.v1";
/// Exact enrollment signature prefix.
pub const ENROLLMENT_SIGNATURE_DOMAIN: &[u8] = b"kernaid:fleet:enrollment:v1\0";
/// Exact inventory signature prefix.
pub const INVENTORY_SIGNATURE_DOMAIN: &[u8] = b"kernaid:fleet:inventory:v1\0";
/// Largest integer accepted by all Fleet JSON implementations.
pub const MAX_SAFE_JSON_INTEGER: u64 = 9_007_199_254_740_991;
/// Maximum assets accepted by one local batch operation.
pub const MAX_INVENTORY_BATCH_ASSETS: usize = 1_024;

const ED25519_PUBLIC_KEY_BYTES: usize = 32;
const ED25519_SIGNATURE_BYTES: usize = 64;
const ED25519_SPKI_BYTES: usize = 44;
const ED25519_SPKI_PREFIX: &[u8; 12] = b"\x30\x2a\x30\x05\x06\x03\x2b\x65\x70\x03\x21\x00";
const MAX_ENROLLMENT_OFFLINE_BYTES: usize = 16 * 1024;
const MAX_INVENTORY_OFFLINE_BYTES: usize = 32 * 1024;
const MAX_TOKEN_BYTES: usize = 512;
const MAX_ID_BYTES: usize = 128;
const MAX_AGENT_VERSION_BYTES: usize = 64;
const MAX_TIMESTAMP_BYTES: usize = 64;
const MAX_OS_RELEASE_BYTES: usize = 256;
const MIN_NONCE_BYTES: usize = 16;
const MAX_NONCE_BYTES: usize = 64;

/// Enrollment operating environment.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum EnrollmentPlatform {
    Rescue,
    Windows,
    Linux,
    Macos,
}

/// Inventory operating system family.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum AssetPlatform {
    Linux,
    Windows,
    Macos,
    Unknown,
}

/// Normalized inventory CPU architecture.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum AssetArchitecture {
    X86_64,
    Aarch64,
    Other,
}

/// Coarse, privacy-preserving asset state.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AssetHealth {
    Healthy,
    Attention,
    RequiredAction,
    Unknown,
}

/// Bounded finding totals; finding content remains in the local report.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct FindingCounts {
    pub critical: u32,
    pub warning: u32,
    pub info: u32,
}

impl FindingCounts {
    #[must_use]
    pub const fn new(critical: u32, warning: u32, info: u32) -> Self {
        Self {
            critical,
            warning,
            info,
        }
    }
}

/// One asset snapshot summarized for Fleet.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct InventoryAsset {
    pub asset_id: String,
    pub target_fingerprint: String,
    pub platform: AssetPlatform,
    pub architecture: AssetArchitecture,
    pub os_release: Option<String>,
    pub health: AssetHealth,
    pub finding_counts: FindingCounts,
    pub snapshot_sha256: String,
}

impl InventoryAsset {
    /// Construct an inventory asset. Validation is performed before signing.
    #[allow(clippy::too_many_arguments)]
    #[must_use]
    pub fn new(
        asset_id: impl Into<String>,
        target_fingerprint: impl Into<String>,
        platform: AssetPlatform,
        architecture: AssetArchitecture,
        os_release: Option<String>,
        health: AssetHealth,
        finding_counts: FindingCounts,
        snapshot_sha256: impl Into<String>,
    ) -> Self {
        Self {
            asset_id: asset_id.into(),
            target_fingerprint: target_fingerprint.into(),
            platform,
            architecture,
            os_release,
            health,
            finding_counts,
            snapshot_sha256: snapshot_sha256.into(),
        }
    }
}

impl fmt::Debug for InventoryAsset {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("InventoryAsset")
            .field("asset_id", &self.asset_id)
            .field("platform", &self.platform)
            .field("architecture", &self.architecture)
            .field("os_release", &self.os_release)
            .field("health", &self.health)
            .field("finding_counts", &self.finding_counts)
            .finish_non_exhaustive()
    }
}

/// Values needed to create an enrollment request.
pub struct EnrollmentRequestInput {
    enrollment_token: String,
    tenant_id: String,
    platform: EnrollmentPlatform,
    agent_version: String,
    issued_at: String,
    nonce: Zeroizing<Vec<u8>>,
}

impl EnrollmentRequestInput {
    #[must_use]
    pub fn new(
        enrollment_token: impl Into<String>,
        tenant_id: impl Into<String>,
        platform: EnrollmentPlatform,
        agent_version: impl Into<String>,
        issued_at: impl Into<String>,
        nonce: impl Into<Vec<u8>>,
    ) -> Self {
        Self {
            enrollment_token: enrollment_token.into(),
            tenant_id: tenant_id.into(),
            platform,
            agent_version: agent_version.into(),
            issued_at: issued_at.into(),
            nonce: Zeroizing::new(nonce.into()),
        }
    }
}

impl fmt::Debug for EnrollmentRequestInput {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("EnrollmentRequestInput")
            .field("tenant_id", &self.tenant_id)
            .field("platform", &self.platform)
            .field("agent_version", &self.agent_version)
            .field("issued_at", &self.issued_at)
            .finish_non_exhaustive()
    }
}

/// Signed, self-identifying enrollment request.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SignedEnrollmentRequest {
    schema: String,
    enrollment_token: String,
    tenant_id: String,
    device_id: String,
    public_key_spki: String,
    platform: EnrollmentPlatform,
    agent_version: String,
    issued_at: String,
    nonce: String,
    signature: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct UnsignedEnrollmentRequest<'a> {
    schema: &'a str,
    enrollment_token: &'a str,
    tenant_id: &'a str,
    device_id: &'a str,
    public_key_spki: &'a str,
    platform: EnrollmentPlatform,
    agent_version: &'a str,
    issued_at: &'a str,
    nonce: &'a str,
}

impl SignedEnrollmentRequest {
    /// Sign an enrollment request with the already-provisioned device key.
    pub fn sign(
        identity: &DeviceIdentity,
        input: EnrollmentRequestInput,
    ) -> Result<Self, FleetClientError> {
        validate_token(&input.enrollment_token)?;
        validate_identifier("tenantId", &input.tenant_id)?;
        validate_agent_version(&input.agent_version)?;
        validate_timestamp("issuedAt", &input.issued_at)?;
        validate_nonce(input.nonce.as_slice())?;

        let public_key = identity.public_key();
        let device_id = identity.device_id();
        let public_key_spki = encode_spki(&public_key);
        let nonce = URL_SAFE_NO_PAD.encode(input.nonce.as_slice());
        let mut request = Self {
            schema: ENROLLMENT_REQUEST_SCHEMA.to_owned(),
            enrollment_token: input.enrollment_token,
            tenant_id: input.tenant_id,
            device_id,
            public_key_spki,
            platform: input.platform,
            agent_version: input.agent_version,
            issued_at: input.issued_at,
            nonce,
            signature: String::new(),
        };
        let unsigned = Zeroizing::new(request.unsigned_canonical_json()?);
        let signature = identity
            .sign_domain_separated_payload(ENROLLMENT_SIGNATURE_DOMAIN, unsigned.as_slice())
            .map_err(FleetClientError::Identity)?;
        request.signature = URL_SAFE_NO_PAD.encode(signature);
        request.validate_fields()?;
        Ok(request)
    }

    /// Verify structure, tenant, one-time token, device/key binding, and
    /// signature. The returned key is suitable for the enrollment registry.
    pub fn verify(
        &self,
        expected_tenant_id: &str,
        expected_enrollment_token: &str,
    ) -> Result<[u8; ED25519_PUBLIC_KEY_BYTES], FleetClientError> {
        self.validate_fields()?;
        validate_identifier("expectedTenantId", expected_tenant_id)?;
        validate_token(expected_enrollment_token)?;
        if self.tenant_id != expected_tenant_id {
            return Err(FleetClientError::UnexpectedTenant);
        }
        if !constant_time_equal(
            self.enrollment_token.as_bytes(),
            expected_enrollment_token.as_bytes(),
        ) {
            return Err(FleetClientError::UnexpectedEnrollmentToken);
        }

        let public_key = decode_spki(&self.public_key_spki)?;
        if device_id_for_public_key(&public_key) != self.device_id {
            return Err(FleetClientError::UnexpectedDevice);
        }
        let signature =
            decode_fixed_base64url::<ED25519_SIGNATURE_BYTES>("signature", &self.signature)?;
        let unsigned = Zeroizing::new(self.unsigned_canonical_json()?);
        verify_signature(
            &public_key,
            ENROLLMENT_SIGNATURE_DOMAIN,
            unsigned.as_slice(),
            &signature,
        )?;
        Ok(public_key)
    }

    /// Export exact canonical bytes for an offline or authenticated transport.
    pub fn export_offline(&self) -> Result<Vec<u8>, FleetClientError> {
        self.validate_fields()?;
        let bytes = canonical_json(self)?;
        validate_transfer_size(bytes.len(), MAX_ENROLLMENT_OFFLINE_BYTES)?;
        Ok(bytes)
    }

    /// Import only canonical bytes and verify them against caller-owned
    /// enrollment context. Re-exporting the result is byte-identical.
    pub fn import_offline(
        bytes: &[u8],
        expected_tenant_id: &str,
        expected_enrollment_token: &str,
    ) -> Result<Self, FleetClientError> {
        let request: Self = import_canonical(bytes, MAX_ENROLLMENT_OFFLINE_BYTES)?;
        request.verify(expected_tenant_id, expected_enrollment_token)?;
        Ok(request)
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
    pub fn platform(&self) -> EnrollmentPlatform {
        self.platform
    }

    #[must_use]
    pub fn agent_version(&self) -> &str {
        &self.agent_version
    }

    #[must_use]
    pub fn issued_at(&self) -> &str {
        &self.issued_at
    }

    fn unsigned(&self) -> UnsignedEnrollmentRequest<'_> {
        UnsignedEnrollmentRequest {
            schema: &self.schema,
            enrollment_token: &self.enrollment_token,
            tenant_id: &self.tenant_id,
            device_id: &self.device_id,
            public_key_spki: &self.public_key_spki,
            platform: self.platform,
            agent_version: &self.agent_version,
            issued_at: &self.issued_at,
            nonce: &self.nonce,
        }
    }

    fn unsigned_canonical_json(&self) -> Result<Vec<u8>, FleetClientError> {
        canonical_json(&self.unsigned())
    }

    fn validate_fields(&self) -> Result<(), FleetClientError> {
        validate_schema(&self.schema, ENROLLMENT_REQUEST_SCHEMA)?;
        validate_token(&self.enrollment_token)?;
        validate_identifier("tenantId", &self.tenant_id)?;
        validate_device_id(&self.device_id)
            .map_err(|_| FleetClientError::InvalidField("deviceId"))?;
        decode_spki(&self.public_key_spki)?;
        validate_agent_version(&self.agent_version)?;
        validate_timestamp("issuedAt", &self.issued_at)?;
        decode_bounded_base64url("nonce", &self.nonce, MIN_NONCE_BYTES, MAX_NONCE_BYTES)?;
        decode_fixed_base64url::<ED25519_SIGNATURE_BYTES>("signature", &self.signature)?;
        Ok(())
    }
}

impl fmt::Debug for SignedEnrollmentRequest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SignedEnrollmentRequest")
            .field("schema", &self.schema)
            .field("tenant_id", &self.tenant_id)
            .field("device_id", &self.device_id)
            .field("platform", &self.platform)
            .field("agent_version", &self.agent_version)
            .field("issued_at", &self.issued_at)
            .finish_non_exhaustive()
    }
}

/// Values needed to sign one inventory envelope.
pub struct InventoryEnvelopeInput {
    tenant_id: String,
    sequence: u64,
    observed_at: String,
    asset: InventoryAsset,
}

impl InventoryEnvelopeInput {
    #[must_use]
    pub fn new(
        tenant_id: impl Into<String>,
        sequence: u64,
        observed_at: impl Into<String>,
        asset: InventoryAsset,
    ) -> Self {
        Self {
            tenant_id: tenant_id.into(),
            sequence,
            observed_at: observed_at.into(),
            asset,
        }
    }
}

/// Signed Fleet inventory envelope for exactly one asset.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SignedInventoryEnvelope {
    schema: String,
    tenant_id: String,
    device_id: String,
    sequence: u64,
    observed_at: String,
    asset: InventoryAsset,
    signature: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct UnsignedInventoryEnvelope<'a> {
    schema: &'a str,
    tenant_id: &'a str,
    device_id: &'a str,
    sequence: u64,
    observed_at: &'a str,
    asset: &'a InventoryAsset,
}

impl SignedInventoryEnvelope {
    /// Sign one independently replay-protectable inventory snapshot.
    pub fn sign(
        identity: &DeviceIdentity,
        input: InventoryEnvelopeInput,
    ) -> Result<Self, FleetClientError> {
        let mut envelope = Self {
            schema: INVENTORY_ENVELOPE_SCHEMA.to_owned(),
            tenant_id: input.tenant_id,
            device_id: identity.device_id(),
            sequence: input.sequence,
            observed_at: input.observed_at,
            asset: input.asset,
            signature: String::new(),
        };
        envelope.validate_unsigned_fields()?;
        let unsigned = Zeroizing::new(envelope.unsigned_canonical_json()?);
        let signature = identity
            .sign_domain_separated_payload(INVENTORY_SIGNATURE_DOMAIN, unsigned.as_slice())
            .map_err(FleetClientError::Identity)?;
        envelope.signature = URL_SAFE_NO_PAD.encode(signature);
        envelope.validate_fields()?;
        Ok(envelope)
    }

    /// Verify with the enrollment registry's trust anchors.
    pub fn verify(
        &self,
        expected_tenant_id: &str,
        expected_device_id: &str,
        enrolled_public_key: &[u8; ED25519_PUBLIC_KEY_BYTES],
    ) -> Result<(), FleetClientError> {
        self.validate_fields()?;
        validate_identifier("expectedTenantId", expected_tenant_id)?;
        validate_device_id(expected_device_id)
            .map_err(|_| FleetClientError::InvalidField("expectedDeviceId"))?;
        if self.tenant_id != expected_tenant_id {
            return Err(FleetClientError::UnexpectedTenant);
        }
        if self.device_id != expected_device_id
            || device_id_for_public_key(enrolled_public_key) != expected_device_id
        {
            return Err(FleetClientError::UnexpectedDevice);
        }
        let signature =
            decode_fixed_base64url::<ED25519_SIGNATURE_BYTES>("signature", &self.signature)?;
        let unsigned = Zeroizing::new(self.unsigned_canonical_json()?);
        verify_signature(
            enrolled_public_key,
            INVENTORY_SIGNATURE_DOMAIN,
            unsigned.as_slice(),
            &signature,
        )
    }

    /// Export exact canonical bytes for an offline or authenticated transport.
    pub fn export_offline(&self) -> Result<Vec<u8>, FleetClientError> {
        self.validate_fields()?;
        let bytes = canonical_json(self)?;
        validate_transfer_size(bytes.len(), MAX_INVENTORY_OFFLINE_BYTES)?;
        Ok(bytes)
    }

    /// Import canonical bytes and authenticate them with enrolled device data.
    pub fn import_offline(
        bytes: &[u8],
        expected_tenant_id: &str,
        expected_device_id: &str,
        enrolled_public_key: &[u8; ED25519_PUBLIC_KEY_BYTES],
    ) -> Result<Self, FleetClientError> {
        let envelope: Self = import_canonical(bytes, MAX_INVENTORY_OFFLINE_BYTES)?;
        envelope.verify(expected_tenant_id, expected_device_id, enrolled_public_key)?;
        Ok(envelope)
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
    pub const fn sequence(&self) -> u64 {
        self.sequence
    }

    #[must_use]
    pub fn observed_at(&self) -> &str {
        &self.observed_at
    }

    #[must_use]
    pub const fn asset(&self) -> &InventoryAsset {
        &self.asset
    }

    fn unsigned(&self) -> UnsignedInventoryEnvelope<'_> {
        UnsignedInventoryEnvelope {
            schema: &self.schema,
            tenant_id: &self.tenant_id,
            device_id: &self.device_id,
            sequence: self.sequence,
            observed_at: &self.observed_at,
            asset: &self.asset,
        }
    }

    fn unsigned_canonical_json(&self) -> Result<Vec<u8>, FleetClientError> {
        canonical_json(&self.unsigned())
    }

    fn validate_fields(&self) -> Result<(), FleetClientError> {
        self.validate_unsigned_fields()?;
        decode_fixed_base64url::<ED25519_SIGNATURE_BYTES>("signature", &self.signature)?;
        Ok(())
    }

    fn validate_unsigned_fields(&self) -> Result<(), FleetClientError> {
        validate_schema(&self.schema, INVENTORY_ENVELOPE_SCHEMA)?;
        validate_identifier("tenantId", &self.tenant_id)?;
        validate_device_id(&self.device_id)
            .map_err(|_| FleetClientError::InvalidField("deviceId"))?;
        if self.sequence == 0 || self.sequence > MAX_SAFE_JSON_INTEGER {
            return Err(FleetClientError::InvalidField("sequence"));
        }
        validate_timestamp("observedAt", &self.observed_at)?;
        validate_asset(&self.asset)?;
        Ok(())
    }
}

impl fmt::Debug for SignedInventoryEnvelope {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SignedInventoryEnvelope")
            .field("schema", &self.schema)
            .field("tenant_id", &self.tenant_id)
            .field("device_id", &self.device_id)
            .field("sequence", &self.sequence)
            .field("observed_at", &self.observed_at)
            .field("asset_id", &self.asset.asset_id)
            .field("health", &self.asset.health)
            .finish_non_exhaustive()
    }
}

/// Sign one envelope per asset with consecutive, safe sequence values.
pub fn sign_inventory_batch(
    identity: &DeviceIdentity,
    tenant_id: impl Into<String>,
    first_sequence: u64,
    observed_at: impl Into<String>,
    assets: Vec<InventoryAsset>,
) -> Result<Vec<SignedInventoryEnvelope>, FleetClientError> {
    if assets.is_empty() || assets.len() > MAX_INVENTORY_BATCH_ASSETS {
        return Err(FleetClientError::InvalidInventoryBatch);
    }
    let count = u64::try_from(assets.len()).map_err(|_| FleetClientError::InvalidInventoryBatch)?;
    let last_sequence = first_sequence
        .checked_add(count.saturating_sub(1))
        .ok_or(FleetClientError::InvalidInventoryBatch)?;
    if first_sequence == 0 || last_sequence > MAX_SAFE_JSON_INTEGER {
        return Err(FleetClientError::InvalidInventoryBatch);
    }

    let tenant_id = tenant_id.into();
    let observed_at = observed_at.into();
    assets
        .into_iter()
        .enumerate()
        .map(|(offset, asset)| {
            let offset =
                u64::try_from(offset).map_err(|_| FleetClientError::InvalidInventoryBatch)?;
            SignedInventoryEnvelope::sign(
                identity,
                InventoryEnvelopeInput::new(
                    tenant_id.clone(),
                    first_sequence + offset,
                    observed_at.clone(),
                    asset,
                ),
            )
        })
        .collect()
}

/// Canonical lowercase hexadecimal SHA-256 helper for snapshot fields.
#[must_use]
pub fn sha256_hex(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    let mut encoded = String::with_capacity(64);
    for byte in digest {
        use fmt::Write as _;
        let _ = write!(encoded, "{byte:02x}");
    }
    encoded
}

/// Fleet client validation and authenticity failures.
#[derive(Debug, PartialEq, Eq)]
pub enum FleetClientError {
    Identity(IdentityError),
    InvalidField(&'static str),
    InvalidJson,
    UnsupportedJsonValue,
    UnsafeInteger,
    NonCanonicalJson,
    TransferTooLarge,
    InvalidSignature,
    UnexpectedTenant,
    UnexpectedDevice,
    UnexpectedEnrollmentToken,
    InvalidInventoryBatch,
}

impl fmt::Display for FleetClientError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Identity(_) => formatter.write_str("device identity operation failed"),
            Self::InvalidField(field) => write!(formatter, "invalid Fleet field: {field}"),
            Self::InvalidJson => formatter.write_str("invalid Fleet JSON"),
            Self::UnsupportedJsonValue => formatter.write_str("unsupported Fleet JSON value"),
            Self::UnsafeInteger => formatter.write_str("unsafe Fleet JSON integer"),
            Self::NonCanonicalJson => formatter.write_str("Fleet JSON is not canonical"),
            Self::TransferTooLarge => formatter.write_str("Fleet offline transfer is too large"),
            Self::InvalidSignature => formatter.write_str("invalid Fleet signature"),
            Self::UnexpectedTenant => formatter.write_str("unexpected Fleet tenant"),
            Self::UnexpectedDevice => formatter.write_str("unexpected Fleet device"),
            Self::UnexpectedEnrollmentToken => {
                formatter.write_str("unexpected Fleet enrollment token")
            }
            Self::InvalidInventoryBatch => formatter.write_str("invalid Fleet inventory batch"),
        }
    }
}

impl std::error::Error for FleetClientError {}

fn validate_asset(asset: &InventoryAsset) -> Result<(), FleetClientError> {
    validate_identifier("asset.assetId", &asset.asset_id)?;
    validate_sha256("asset.targetFingerprint", &asset.target_fingerprint)?;
    if let Some(os_release) = &asset.os_release {
        validate_bounded_text("asset.osRelease", os_release, MAX_OS_RELEASE_BYTES)?;
    }
    validate_sha256("asset.snapshotSha256", &asset.snapshot_sha256)
}

fn validate_schema(actual: &str, expected: &str) -> Result<(), FleetClientError> {
    if actual != expected {
        return Err(FleetClientError::InvalidField("schema"));
    }
    Ok(())
}

fn validate_identifier(field: &'static str, value: &str) -> Result<(), FleetClientError> {
    if value.is_empty()
        || value.len() > MAX_ID_BYTES
        || !value.bytes().all(|byte| {
            byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b':' | b'/')
        })
    {
        return Err(FleetClientError::InvalidField(field));
    }
    Ok(())
}

fn validate_token(value: &str) -> Result<(), FleetClientError> {
    if value.len() < 16
        || value.len() > MAX_TOKEN_BYTES
        || !value.bytes().all(|byte| byte.is_ascii_graphic())
    {
        return Err(FleetClientError::InvalidField("enrollmentToken"));
    }
    Ok(())
}

fn validate_agent_version(value: &str) -> Result<(), FleetClientError> {
    if value.is_empty()
        || value.len() > MAX_AGENT_VERSION_BYTES
        || !value.bytes().all(|byte| byte.is_ascii_graphic())
    {
        return Err(FleetClientError::InvalidField("agentVersion"));
    }
    Ok(())
}

fn validate_timestamp(field: &'static str, value: &str) -> Result<(), FleetClientError> {
    if value.is_empty()
        || value.len() > MAX_TIMESTAMP_BYTES
        || DateTime::parse_from_rfc3339(value).is_err()
    {
        return Err(FleetClientError::InvalidField(field));
    }
    Ok(())
}

fn validate_bounded_text(
    field: &'static str,
    value: &str,
    max_bytes: usize,
) -> Result<(), FleetClientError> {
    if value.is_empty()
        || value.len() > max_bytes
        || value
            .chars()
            .any(|character| character.is_control() && character != '\t')
    {
        return Err(FleetClientError::InvalidField(field));
    }
    Ok(())
}

fn validate_sha256(field: &'static str, value: &str) -> Result<(), FleetClientError> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(FleetClientError::InvalidField(field));
    }
    Ok(())
}

fn validate_nonce(nonce: &[u8]) -> Result<(), FleetClientError> {
    if !(MIN_NONCE_BYTES..=MAX_NONCE_BYTES).contains(&nonce.len()) {
        return Err(FleetClientError::InvalidField("nonce"));
    }
    Ok(())
}

fn validate_transfer_size(actual: usize, maximum: usize) -> Result<(), FleetClientError> {
    if actual == 0 || actual > maximum {
        return Err(FleetClientError::TransferTooLarge);
    }
    Ok(())
}

fn encode_spki(public_key: &[u8; ED25519_PUBLIC_KEY_BYTES]) -> String {
    let mut spki = [0_u8; ED25519_SPKI_BYTES];
    spki[..ED25519_SPKI_PREFIX.len()].copy_from_slice(ED25519_SPKI_PREFIX);
    spki[ED25519_SPKI_PREFIX.len()..].copy_from_slice(public_key);
    URL_SAFE_NO_PAD.encode(spki)
}

fn decode_spki(encoded: &str) -> Result<[u8; ED25519_PUBLIC_KEY_BYTES], FleetClientError> {
    let spki = decode_fixed_base64url::<ED25519_SPKI_BYTES>("publicKeySpki", encoded)?;
    if spki[..ED25519_SPKI_PREFIX.len()] != ED25519_SPKI_PREFIX[..] {
        return Err(FleetClientError::InvalidField("publicKeySpki"));
    }
    let mut public_key = [0_u8; ED25519_PUBLIC_KEY_BYTES];
    public_key.copy_from_slice(&spki[ED25519_SPKI_PREFIX.len()..]);
    VerifyingKey::from_bytes(&public_key)
        .map_err(|_| FleetClientError::InvalidField("publicKeySpki"))?;
    Ok(public_key)
}

fn decode_bounded_base64url(
    field: &'static str,
    encoded: &str,
    minimum: usize,
    maximum: usize,
) -> Result<Zeroizing<Vec<u8>>, FleetClientError> {
    if encoded.contains('=') || encoded.len() > maximum.div_ceil(3) * 4 {
        return Err(FleetClientError::InvalidField(field));
    }
    let decoded = Zeroizing::new(
        URL_SAFE_NO_PAD
            .decode(encoded)
            .map_err(|_| FleetClientError::InvalidField(field))?,
    );
    if !(minimum..=maximum).contains(&decoded.len())
        || URL_SAFE_NO_PAD.encode(decoded.as_slice()) != encoded
    {
        return Err(FleetClientError::InvalidField(field));
    }
    Ok(decoded)
}

fn decode_fixed_base64url<const N: usize>(
    field: &'static str,
    encoded: &str,
) -> Result<[u8; N], FleetClientError> {
    let decoded = decode_bounded_base64url(field, encoded, N, N)?;
    let mut bytes = [0_u8; N];
    bytes.copy_from_slice(decoded.as_slice());
    Ok(bytes)
}

fn verify_signature(
    public_key: &[u8; ED25519_PUBLIC_KEY_BYTES],
    domain: &[u8],
    canonical_payload: &[u8],
    signature: &[u8; ED25519_SIGNATURE_BYTES],
) -> Result<(), FleetClientError> {
    let verifying_key =
        VerifyingKey::from_bytes(public_key).map_err(|_| FleetClientError::InvalidSignature)?;
    let mut message = Zeroizing::new(Vec::with_capacity(
        domain.len().saturating_add(canonical_payload.len()),
    ));
    message.extend_from_slice(domain);
    message.extend_from_slice(canonical_payload);
    verifying_key
        .verify_strict(message.as_slice(), &Signature::from_bytes(signature))
        .map_err(|_| FleetClientError::InvalidSignature)
}

fn constant_time_equal(left: &[u8], right: &[u8]) -> bool {
    if left.len() != right.len() {
        return false;
    }
    left.iter()
        .zip(right)
        .fold(0_u8, |difference, (left, right)| {
            difference | (left ^ right)
        })
        == 0
}

fn import_canonical<T>(bytes: &[u8], maximum: usize) -> Result<T, FleetClientError>
where
    T: DeserializeOwned + Serialize,
{
    validate_transfer_size(bytes.len(), maximum)?;
    let value: Value = serde_json::from_slice(bytes).map_err(|_| FleetClientError::InvalidJson)?;
    validate_json_value(&value)?;
    let parsed: T = serde_json::from_slice(bytes).map_err(|_| FleetClientError::InvalidJson)?;
    let canonical = canonical_json(&parsed)?;
    if canonical != bytes {
        return Err(FleetClientError::NonCanonicalJson);
    }
    Ok(parsed)
}

fn canonical_json<T: Serialize>(value: &T) -> Result<Vec<u8>, FleetClientError> {
    let value = serde_json::to_value(value).map_err(|_| FleetClientError::InvalidJson)?;
    validate_json_value(&value)?;
    let mut output = Vec::new();
    write_canonical_value(&value, &mut output)?;
    Ok(output)
}

fn validate_json_value(value: &Value) -> Result<(), FleetClientError> {
    match value {
        Value::Null | Value::Bool(_) | Value::String(_) => Ok(()),
        Value::Number(number) => {
            if let Some(number) = number.as_u64() {
                if number <= MAX_SAFE_JSON_INTEGER {
                    Ok(())
                } else {
                    Err(FleetClientError::UnsafeInteger)
                }
            } else if let Some(number) = number.as_i64() {
                if number.unsigned_abs() <= MAX_SAFE_JSON_INTEGER {
                    Ok(())
                } else {
                    Err(FleetClientError::UnsafeInteger)
                }
            } else {
                Err(FleetClientError::UnsupportedJsonValue)
            }
        }
        Value::Array(values) => values.iter().try_for_each(validate_json_value),
        Value::Object(values) => values.values().try_for_each(validate_json_value),
    }
}

fn write_canonical_value(value: &Value, output: &mut Vec<u8>) -> Result<(), FleetClientError> {
    match value {
        Value::Null => output.extend_from_slice(b"null"),
        Value::Bool(value) => output.extend_from_slice(if *value { b"true" } else { b"false" }),
        Value::Number(value) => output.extend_from_slice(value.to_string().as_bytes()),
        Value::String(value) => {
            let encoded =
                serde_json::to_string(value).map_err(|_| FleetClientError::InvalidJson)?;
            output.extend_from_slice(encoded.as_bytes());
        }
        Value::Array(values) => {
            output.push(b'[');
            for (index, value) in values.iter().enumerate() {
                if index != 0 {
                    output.push(b',');
                }
                write_canonical_value(value, output)?;
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
                let encoded_key =
                    serde_json::to_string(key).map_err(|_| FleetClientError::InvalidJson)?;
                output.extend_from_slice(encoded_key.as_bytes());
                output.push(b':');
                let nested = values.get(key).ok_or(FleetClientError::InvalidJson)?;
                write_canonical_value(nested, output)?;
            }
            output.push(b'}');
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    const TENANT: &str = "tenant-europe-1";
    const TOKEN: &str = "enroll_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
    const ISSUED_AT: &str = "2026-08-31T12:30:45Z";

    fn identity() -> DeviceIdentity {
        DeviceIdentity::from_seed(&[0x42; 32]).expect("fixed test identity")
    }

    fn enrollment() -> SignedEnrollmentRequest {
        SignedEnrollmentRequest::sign(
            &identity(),
            EnrollmentRequestInput::new(
                TOKEN,
                TENANT,
                EnrollmentPlatform::Linux,
                "0.1.0-test",
                ISSUED_AT,
                vec![0xa5; 32],
            ),
        )
        .expect("sign enrollment")
    }

    fn asset(id: &str, snapshot: &[u8]) -> InventoryAsset {
        InventoryAsset::new(
            id,
            sha256_hex(format!("target:{id}").as_bytes()),
            AssetPlatform::Linux,
            AssetArchitecture::X86_64,
            Some("Debian 13".to_owned()),
            AssetHealth::Attention,
            FindingCounts::new(1, 2, 3),
            sha256_hex(snapshot),
        )
    }

    fn inventory() -> SignedInventoryEnvelope {
        SignedInventoryEnvelope::sign(
            &identity(),
            InventoryEnvelopeInput::new(TENANT, 7, ISSUED_AT, asset("asset-01", b"snapshot")),
        )
        .expect("sign inventory")
    }

    #[test]
    fn enrollment_signature_and_spki_verify() {
        let identity = identity();
        let request = enrollment();
        assert_eq!(
            request.verify(TENANT, TOKEN).expect("verify enrollment"),
            identity.public_key()
        );
        assert_eq!(request.device_id(), identity.device_id());
    }

    #[test]
    fn inventory_signature_uses_enrollment_key() {
        let identity = identity();
        let envelope = inventory();
        envelope
            .verify(TENANT, &identity.device_id(), &identity.public_key())
            .expect("verify inventory");
    }

    #[test]
    fn tampering_is_rejected_for_both_protocols() {
        let identity = identity();
        let enrollment_bytes = enrollment().export_offline().expect("export enrollment");
        let mut enrollment_json: Value =
            serde_json::from_slice(&enrollment_bytes).expect("parse enrollment");
        enrollment_json["agentVersion"] = json!("9.9.9-attacker");
        let enrollment_tampered = canonical_json(&enrollment_json).expect("canonical tamper");
        assert_eq!(
            SignedEnrollmentRequest::import_offline(&enrollment_tampered, TENANT, TOKEN),
            Err(FleetClientError::InvalidSignature)
        );

        let inventory_bytes = inventory().export_offline().expect("export inventory");
        let mut inventory_json: Value =
            serde_json::from_slice(&inventory_bytes).expect("parse inventory");
        inventory_json["asset"]["health"] = json!("healthy");
        let inventory_tampered = canonical_json(&inventory_json).expect("canonical tamper");
        assert_eq!(
            SignedInventoryEnvelope::import_offline(
                &inventory_tampered,
                TENANT,
                &identity.device_id(),
                &identity.public_key(),
            ),
            Err(FleetClientError::InvalidSignature)
        );
    }

    #[test]
    fn canonicalization_is_recursive_and_deterministic() {
        let first = enrollment().export_offline().expect("first export");
        let second = enrollment().export_offline().expect("second export");
        assert_eq!(first, second);
        let inventory = inventory().export_offline().expect("inventory export");
        let text = str::from_utf8(&inventory).expect("inventory UTF-8");
        assert!(text.starts_with("{\"asset\":{\"architecture\":"));
        assert!(text.contains("\"findingCounts\":{\"critical\":1,\"info\":3,\"warning\":2}"));
    }

    #[test]
    fn offline_roundtrip_replays_exact_bytes() {
        let identity = identity();
        let enrollment_bytes = enrollment().export_offline().expect("export enrollment");
        let enrollment = SignedEnrollmentRequest::import_offline(&enrollment_bytes, TENANT, TOKEN)
            .expect("import enrollment");
        assert_eq!(
            enrollment.export_offline().expect("re-export enrollment"),
            enrollment_bytes
        );

        let inventory_bytes = inventory().export_offline().expect("export inventory");
        let inventory = SignedInventoryEnvelope::import_offline(
            &inventory_bytes,
            TENANT,
            &identity.device_id(),
            &identity.public_key(),
        )
        .expect("import inventory");
        assert_eq!(
            inventory.export_offline().expect("re-export inventory"),
            inventory_bytes
        );
    }

    #[test]
    fn noncanonical_unknown_float_and_unsafe_integer_inputs_fail_closed() {
        let request = enrollment().export_offline().expect("export enrollment");
        let mut noncanonical = b" \n".to_vec();
        noncanonical.extend_from_slice(&request);
        assert_eq!(
            SignedEnrollmentRequest::import_offline(&noncanonical, TENANT, TOKEN),
            Err(FleetClientError::NonCanonicalJson)
        );

        let mut unknown: Value = serde_json::from_slice(&request).expect("parse request");
        unknown["privateKey"] = json!("must-not-exist");
        let unknown = canonical_json(&unknown).expect("encode unknown field");
        assert_eq!(
            SignedEnrollmentRequest::import_offline(&unknown, TENANT, TOKEN),
            Err(FleetClientError::InvalidJson)
        );

        let inventory = inventory().export_offline().expect("export inventory");
        let mut float: Value = serde_json::from_slice(&inventory).expect("parse inventory");
        float["sequence"] = json!(1.5);
        let float = serde_json::to_vec(&float).expect("encode float");
        assert_eq!(
            SignedInventoryEnvelope::import_offline(
                &float,
                TENANT,
                &identity().device_id(),
                &identity().public_key(),
            ),
            Err(FleetClientError::UnsupportedJsonValue)
        );

        let unsafe_integer = str::from_utf8(&inventory)
            .expect("UTF-8 inventory")
            .replace("\"sequence\":7", "\"sequence\":9007199254740992");
        assert_eq!(
            SignedInventoryEnvelope::import_offline(
                unsafe_integer.as_bytes(),
                TENANT,
                &identity().device_id(),
                &identity().public_key(),
            ),
            Err(FleetClientError::UnsafeInteger)
        );
    }

    #[test]
    fn batch_creates_multiple_independent_asset_envelopes() {
        let identity = identity();
        let envelopes = sign_inventory_batch(
            &identity,
            TENANT,
            40,
            ISSUED_AT,
            vec![asset("asset-01", b"one"), asset("asset-02", b"two")],
        )
        .expect("sign batch");
        assert_eq!(envelopes.len(), 2);
        assert_eq!(envelopes[0].sequence(), 40);
        assert_eq!(envelopes[1].sequence(), 41);
        assert_ne!(
            envelopes[0].export_offline().expect("export first"),
            envelopes[1].export_offline().expect("export second")
        );
        for envelope in envelopes {
            envelope
                .verify(TENANT, &identity.device_id(), &identity.public_key())
                .expect("verify batch envelope");
        }
    }

    #[test]
    fn serialized_and_debug_forms_never_contain_device_seed() {
        let seed = [0x42_u8; 32];
        let seed_hex = seed
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>();
        let seed_base64url = URL_SAFE_NO_PAD.encode(seed);
        let request = enrollment();
        let bytes = request.export_offline().expect("export request");
        let wire = str::from_utf8(&bytes).expect("wire UTF-8");
        let debug = format!("{request:?}");
        assert!(!wire.contains(&seed_hex));
        assert!(!wire.contains(&seed_base64url));
        assert!(!wire.contains("privateKey"));
        assert!(!wire.contains("seed"));
        assert!(!debug.contains(TOKEN));
        assert!(!debug.contains(&request.signature));
        assert!(!debug.contains(&request.public_key_spki));
        assert!(!debug.contains(&request.nonce));
    }

    #[test]
    fn trust_context_cannot_be_substituted() {
        let identity = identity();
        let other = DeviceIdentity::from_seed(&[0x24; 32]).expect("other identity");
        let request = enrollment();
        assert_eq!(
            request.verify("tenant-other", TOKEN),
            Err(FleetClientError::UnexpectedTenant)
        );
        assert_eq!(
            request.verify(TENANT, "enroll_BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB"),
            Err(FleetClientError::UnexpectedEnrollmentToken)
        );
        assert_eq!(
            inventory().verify(TENANT, &identity.device_id(), &other.public_key()),
            Err(FleetClientError::UnexpectedDevice)
        );
    }

    #[test]
    fn bounds_are_applied_before_signing() {
        let result = SignedEnrollmentRequest::sign(
            &identity(),
            EnrollmentRequestInput::new(
                TOKEN,
                TENANT,
                EnrollmentPlatform::Rescue,
                "0.1.0",
                ISSUED_AT,
                vec![0; MIN_NONCE_BYTES - 1],
            ),
        );
        assert_eq!(result, Err(FleetClientError::InvalidField("nonce")));

        let result = sign_inventory_batch(
            &identity(),
            TENANT,
            MAX_SAFE_JSON_INTEGER,
            ISSUED_AT,
            vec![asset("one", b"one"), asset("two", b"two")],
        );
        assert_eq!(result, Err(FleetClientError::InvalidInventoryBatch));
    }
}
