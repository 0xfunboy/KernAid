//! Transport-neutral safety core for the Windows KernAid Media Creator.
//!
//! The core accepts only an image authorized by the existing Rescue catalog
//! and qualification manifest. Disk discovery/opening remains a platform
//! adapter responsibility; the public workflow never accepts a device path.

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use chrono::{SecondsFormat, Utc};
use ed25519_dalek::{Signature, Verifier as _, VerifyingKey};
use lzma_rust2::{Action, Status, XzStream};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeMap, BTreeSet},
    fmt,
    io::{self, Read, Seek, SeekFrom, Write},
};

pub const CATALOG_SCHEMA: &str = "dev.kernaid.trusted-rescue-images.v2";
pub const QUALIFICATION_SCHEMA: &str = "dev.kernaid.rescue-qualified-release.v1";
pub const RETAIL_SCHEMA: &str = "dev.kernaid.rescue-retail-image.v1";
pub const REPORT_SCHEMA: &str = "dev.kernaid.media-creator-report.v1";
pub const RELEASE_BUNDLE_SCHEMA: &str = "dev.kernaid.media-release-bundle.v1";
pub const RELEASE_BUNDLE_MANIFEST_NAME: &str = "KernAid-Rescue-amd64.media-bundle.json";
pub const CATALOG_NAME: &str = "KernAid-Rescue-amd64.catalog-entry-v2.json";
pub const QUALIFICATION_NAME: &str = "KernAid-Rescue-amd64.qualified.json";
pub const RETAIL_NAME: &str = "KernAid-Rescue-amd64-retail.img.xz";
pub const RETAIL_METADATA_NAME: &str = "KernAid-Rescue-amd64-retail.json";
pub const RAW_NAME: &str = "KernAid-Rescue-amd64-retail.img";
pub const ISO_NAME: &str = "KernAid-Rescue-amd64.iso";
pub const RAW_BYTES: u64 = 32_000_000_000;
pub const MAX_COMPRESSED_BYTES: u64 = 1_999_999_998;
pub const MIN_MEDIA_BYTES: u64 = 32_000_000_000;
const P3_START_BYTES: u64 = 17_179_869_184;
const P3_BYTES: u64 = 8_589_934_592;
const P3_ZERO_SHA256: &str = "ebfb4ef19ae410f190327b5ebd312711263bc7579970e87d9c1e2d84e06b3c25";
const IO_CHUNK_BYTES: usize = 4 * 1024 * 1024;
const XZ_MEMORY_LIMIT_KIB: u32 = 256 * 1024;
const MAX_JSON_BYTES: usize = 16 * 1024 * 1024;
const MAX_BUNDLE_MANIFEST_BYTES: usize = 64 * 1024;
pub const RELEASE_BUNDLE_SIGNING_DOMAIN: &[u8] = b"kernaid:media-release-bundle:v1\0";

#[derive(Debug)]
pub enum Error {
    InvalidInput(&'static str),
    InvalidInputOwned(String),
    Io(io::Error),
    Json(serde_json::Error),
}

impl fmt::Display for Error {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidInput(message) => formatter.write_str(message),
            Self::InvalidInputOwned(message) => formatter.write_str(message),
            Self::Io(error) => write!(formatter, "media I/O failed: {error}"),
            Self::Json(_) => formatter.write_str("trusted release metadata is not strict JSON"),
        }
    }
}

impl std::error::Error for Error {}

impl From<io::Error> for Error {
    fn from(value: io::Error) -> Self {
        Self::Io(value)
    }
}

impl From<serde_json::Error> for Error {
    fn from(value: serde_json::Error) -> Self {
        Self::Json(value)
    }
}

#[derive(Clone, Debug)]
pub struct AuthorizedImage {
    artifact_version: String,
    compressed_sha256: String,
    compressed_bytes: u64,
    raw_sha256: String,
    raw_bytes: u64,
    catalog_sha256: String,
    qualification_sha256: String,
}

impl AuthorizedImage {
    pub fn artifact_version(&self) -> &str {
        &self.artifact_version
    }

    pub fn compressed_sha256(&self) -> &str {
        &self.compressed_sha256
    }

    pub fn compressed_bytes(&self) -> u64 {
        self.compressed_bytes
    }

    pub fn raw_bytes(&self) -> u64 {
        self.raw_bytes
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct SignedReleaseBundleManifest {
    schema: String,
    artifact_version: String,
    files: ReleaseBundleFiles,
    key_id: String,
    signature: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct ReleaseBundleFiles {
    catalog_entry: ReleaseBundleFile,
    qualification: ReleaseBundleFile,
    retail_image: ReleaseBundleFile,
    retail_metadata: ReleaseBundleFile,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct ReleaseBundleFile {
    name: String,
    bytes: u64,
    sha256: String,
}

/// Decode the raw Ed25519 release-bundle trust anchor embedded by the Windows
/// build. The bundle cannot provide or replace its own trust anchor.
pub fn decode_release_bundle_trust_anchor(encoded: &str) -> Result<[u8; 32], Error> {
    if encoded.len() != 43
        || !encoded
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
    {
        return Err(Error::InvalidInput(
            "release bundle trust anchor is not canonical base64url",
        ));
    }
    let decoded = URL_SAFE_NO_PAD
        .decode(encoded)
        .map_err(|_| Error::InvalidInput("release bundle trust anchor is invalid"))?;
    let raw: [u8; 32] = decoded
        .try_into()
        .map_err(|_| Error::InvalidInput("release bundle trust anchor length is invalid"))?;
    if URL_SAFE_NO_PAD.encode(raw) != encoded {
        return Err(Error::InvalidInput(
            "release bundle trust anchor is not canonical base64url",
        ));
    }
    VerifyingKey::from_bytes(&raw)
        .map_err(|_| Error::InvalidInput("release bundle trust anchor is invalid"))?;
    Ok(raw)
}

/// Verify one canonical signed local release bundle and bind its three JSON
/// inputs plus the retail archive descriptor before returning an image
/// authorization. The caller must open only the four fixed sibling filenames
/// named by this contract; it never accepts paths from the manifest.
pub fn authorize_release_bundle(
    trusted_catalog_bytes: &[u8],
    bundle_manifest_bytes: &[u8],
    trust_anchor: &[u8; 32],
    catalog_entry_bytes: &[u8],
    qualification_bytes: &[u8],
    retail_metadata_bytes: &[u8],
) -> Result<AuthorizedImage, Error> {
    let bundle = verify_release_bundle_manifest(bundle_manifest_bytes, trust_anchor)?;
    verify_bundle_bytes(
        &bundle.files.catalog_entry,
        CATALOG_NAME,
        MAX_JSON_BYTES as u64,
        catalog_entry_bytes,
    )?;
    verify_bundle_bytes(
        &bundle.files.qualification,
        QUALIFICATION_NAME,
        MAX_JSON_BYTES as u64,
        qualification_bytes,
    )?;
    verify_bundle_bytes(
        &bundle.files.retail_metadata,
        RETAIL_METADATA_NAME,
        MAX_JSON_BYTES as u64,
        retail_metadata_bytes,
    )?;
    validate_bundle_file(
        &bundle.files.retail_image,
        RETAIL_NAME,
        MAX_COMPRESSED_BYTES,
    )?;

    let authorized = authorize_release(
        trusted_catalog_bytes,
        catalog_entry_bytes,
        qualification_bytes,
        retail_metadata_bytes,
    )?;
    if bundle.artifact_version != authorized.artifact_version
        || bundle.files.retail_image.bytes != authorized.compressed_bytes
        || bundle.files.retail_image.sha256 != authorized.compressed_sha256
    {
        return Err(Error::InvalidInput(
            "signed bundle version or image differs from qualification",
        ));
    }
    Ok(authorized)
}

fn verify_release_bundle_manifest(
    bytes: &[u8],
    trust_anchor: &[u8; 32],
) -> Result<SignedReleaseBundleManifest, Error> {
    if bytes.is_empty() || bytes.len() > MAX_BUNDLE_MANIFEST_BYTES {
        return Err(Error::InvalidInput(
            "release bundle manifest is empty or exceeds its bound",
        ));
    }
    let manifest: SignedReleaseBundleManifest = serde_json::from_slice(bytes)?;
    let full_value = serde_json::to_value(&manifest)?;
    if canonical_json(&full_value)?.as_bytes() != bytes {
        return Err(Error::InvalidInput(
            "release bundle manifest must be canonical JSON",
        ));
    }
    if manifest.schema != RELEASE_BUNDLE_SCHEMA
        || !valid_artifact_version(&manifest.artifact_version)
    {
        return Err(Error::InvalidInput(
            "release bundle schema or version is invalid",
        ));
    }
    validate_bundle_file(
        &manifest.files.catalog_entry,
        CATALOG_NAME,
        MAX_JSON_BYTES as u64,
    )?;
    validate_bundle_file(
        &manifest.files.qualification,
        QUALIFICATION_NAME,
        MAX_JSON_BYTES as u64,
    )?;
    validate_bundle_file(
        &manifest.files.retail_metadata,
        RETAIL_METADATA_NAME,
        MAX_JSON_BYTES as u64,
    )?;
    validate_bundle_file(
        &manifest.files.retail_image,
        RETAIL_NAME,
        MAX_COMPRESSED_BYTES,
    )?;

    let expected_key_id = format!("sha256:{}", sha256_hex(trust_anchor));
    if manifest.key_id != expected_key_id {
        return Err(Error::InvalidInput(
            "release bundle signer does not match the embedded trust anchor",
        ));
    }
    let signature_bytes = URL_SAFE_NO_PAD
        .decode(&manifest.signature)
        .map_err(|_| Error::InvalidInput("release bundle signature is invalid"))?;
    let signature_raw: [u8; 64] = signature_bytes
        .try_into()
        .map_err(|_| Error::InvalidInput("release bundle signature length is invalid"))?;
    if URL_SAFE_NO_PAD.encode(signature_raw) != manifest.signature {
        return Err(Error::InvalidInput(
            "release bundle signature is not canonical base64url",
        ));
    }
    let mut unsigned = full_value;
    unsigned
        .as_object_mut()
        .ok_or(Error::InvalidInput(
            "release bundle manifest root is invalid",
        ))?
        .remove("signature");
    let canonical_unsigned = canonical_json(&unsigned)?;
    let mut message =
        Vec::with_capacity(RELEASE_BUNDLE_SIGNING_DOMAIN.len() + canonical_unsigned.len());
    message.extend_from_slice(RELEASE_BUNDLE_SIGNING_DOMAIN);
    message.extend_from_slice(canonical_unsigned.as_bytes());
    let verifying_key = VerifyingKey::from_bytes(trust_anchor)
        .map_err(|_| Error::InvalidInput("release bundle trust anchor is invalid"))?;
    verifying_key
        .verify(&message, &Signature::from_bytes(&signature_raw))
        .map_err(|_| Error::InvalidInput("release bundle signature verification failed"))?;
    Ok(manifest)
}

fn validate_bundle_file(
    file: &ReleaseBundleFile,
    expected_name: &str,
    maximum_bytes: u64,
) -> Result<(), Error> {
    if file.name != expected_name
        || file.bytes == 0
        || file.bytes > maximum_bytes
        || !valid_sha256(&file.sha256)
    {
        return Err(Error::InvalidInput(
            "release bundle file descriptor is invalid",
        ));
    }
    Ok(())
}

fn verify_bundle_bytes(
    file: &ReleaseBundleFile,
    expected_name: &str,
    maximum_bytes: u64,
    bytes: &[u8],
) -> Result<(), Error> {
    validate_bundle_file(file, expected_name, maximum_bytes)?;
    if file.bytes != bytes.len() as u64 || file.sha256 != sha256_hex(bytes) {
        return Err(Error::InvalidInput(
            "release bundle member does not match its signed manifest",
        ));
    }
    Ok(())
}

fn valid_artifact_version(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 64
        && value.as_bytes()[0].is_ascii_alphanumeric()
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'+' | b'-'))
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DiskCandidate {
    pub opaque_id: String,
    pub model: String,
    pub serial: String,
    pub capacity_bytes: u64,
    pub usb: bool,
    pub removable: bool,
    pub whole_disk: bool,
    pub read_only: bool,
    pub contains_system: bool,
    pub contains_boot: bool,
    pub ambiguous: bool,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct EligibleDisk {
    pub opaque_id: String,
    pub model: String,
    pub serial: String,
    pub capacity_bytes: u64,
}

#[derive(Clone, Debug)]
pub struct DiskSelection {
    candidate: DiskCandidate,
    confirmation_phrase: String,
}

impl DiskSelection {
    pub fn candidate(&self) -> &DiskCandidate {
        &self.candidate
    }

    pub fn confirmation_phrase(&self) -> &str {
        &self.confirmation_phrase
    }

    pub fn confirm(self, entered: &str) -> Result<ConfirmedSelection, Error> {
        if entered != self.confirmation_phrase {
            return Err(Error::InvalidInput(
                "confirmation phrase did not match exactly",
            ));
        }
        Ok(ConfirmedSelection(self.candidate))
    }
}

#[derive(Debug)]
pub struct ConfirmedSelection(DiskCandidate);

impl ConfirmedSelection {
    pub fn candidate(&self) -> &DiskCandidate {
        &self.0
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MediaPhase {
    ValidatingArchive,
    WritingUsb,
    VerifyingUsb,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MediaProgress {
    pub phase: MediaPhase,
    pub completed_bytes: u64,
    pub total_bytes: u64,
}

/// An adapter must bind opaque IDs to its own latest enumeration snapshot and
/// re-probe every property before returning the exclusively opened whole disk.
pub trait DiskBackend {
    type Handle: MediaHandle;

    fn enumerate(&mut self) -> Result<Vec<DiskCandidate>, Error>;
    fn open_revalidated(&mut self, selected: &DiskCandidate) -> Result<Self::Handle, Error>;
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CreationReport {
    pub schema: &'static str,
    pub outcome: &'static str,
    pub completed_at: String,
    pub artifact_name: &'static str,
    pub artifact_version: String,
    pub compressed_bytes: u64,
    pub compressed_sha256: String,
    pub raw_bytes: u64,
    pub raw_sha256: String,
    pub readback_sha256: String,
    pub catalog_sha256: String,
    pub qualification_sha256: String,
    pub disk: EligibleDisk,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct Catalog {
    schema: String,
    catalog_revision: u64,
    images: Vec<CatalogImage>,
}

#[derive(Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct CatalogImage {
    artifact_name: String,
    artifact_version: String,
    sha256: String,
    bytes: u64,
    device_layout: DeviceLayout,
    qemu_usb_boot_attestations: BTreeMap<String, UsbAttestation>,
    qemu_vault_attestations: BTreeMap<String, VaultAttestation>,
}

#[derive(Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct DeviceLayout {
    schema: String,
    manifest_sha256: String,
    partition_table: String,
    logical_sector_bytes: u64,
    minimum_media_bytes: u64,
    minimum_advertised_media_bytes: u64,
    minimum_advertised_media_label: String,
    vault_profile_version: u64,
    vault_profile_sha256: String,
    vault_partition: VaultPartition,
}

#[derive(Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct VaultPartition {
    number: u64,
    name: String,
    mbr_type: String,
    start_lba: u64,
    sector_count: u64,
}

#[derive(Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct UsbAttestation {
    passed: bool,
    boot_transport: String,
    boot_count: u64,
    target_zero_writes_verified: bool,
    workflow_run_id: u64,
    workflow_run_url: String,
    log_sha256: String,
}

#[derive(Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct VaultAttestation {
    passed: bool,
    boot_count: u64,
    luks_version: u64,
    luks_label: String,
    filesystem: String,
    filesystem_label: String,
    vault_profile_version: u64,
    vault_profile_sha256: String,
    stable_uuids_verified: bool,
    journal_identity_binding_verified: bool,
    identity_verified: bool,
    wrong_key_rejected: bool,
    workflow_run_id: u64,
    workflow_run_url: String,
    log_sha256: String,
}

fn object<'a>(
    value: &'a Value,
    keys: &[&str],
    label: &'static str,
) -> Result<&'a Map<String, Value>, Error> {
    let map = value.as_object().ok_or(Error::InvalidInput(label))?;
    let actual: BTreeSet<&str> = map.keys().map(String::as_str).collect();
    let expected: BTreeSet<&str> = keys.iter().copied().collect();
    if actual != expected {
        return Err(Error::InvalidInput(label));
    }
    Ok(map)
}

fn value_string<'a>(map: &'a Map<String, Value>, key: &str) -> Result<&'a str, Error> {
    map.get(key)
        .and_then(Value::as_str)
        .ok_or(Error::InvalidInput("release metadata string is invalid"))
}

fn value_u64(map: &Map<String, Value>, key: &str) -> Result<u64, Error> {
    map.get(key)
        .and_then(Value::as_u64)
        .ok_or(Error::InvalidInput("release metadata integer is invalid"))
}

fn valid_sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn sha256_hex(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

fn parse_json(bytes: &[u8]) -> Result<Value, Error> {
    if bytes.is_empty() || bytes.len() > MAX_JSON_BYTES {
        return Err(Error::InvalidInput(
            "JSON input is empty or exceeds the bound",
        ));
    }
    Ok(serde_json::from_slice(bytes)?)
}

fn canonical_json(value: &Value) -> Result<String, Error> {
    match value {
        Value::Null | Value::Bool(_) | Value::Number(_) | Value::String(_) => {
            Ok(serde_json::to_string(value)?)
        }
        Value::Array(values) => {
            let items = values
                .iter()
                .map(canonical_json)
                .collect::<Result<Vec<_>, _>>()?;
            Ok(format!("[{}]", items.join(",")))
        }
        Value::Object(values) => {
            let mut keys = values.keys().collect::<Vec<_>>();
            keys.sort();
            let fields = keys
                .into_iter()
                .map(|key| {
                    Ok(format!(
                        "{}:{}",
                        serde_json::to_string(key)?,
                        canonical_json(&values[key])?
                    ))
                })
                .collect::<Result<Vec<_>, Error>>()?;
            Ok(format!("{{{}}}", fields.join(",")))
        }
    }
}

/// Bind the retail archive to its qualification manifest and the embedded or
/// caller-supplied trusted Rescue catalog. The archive itself is hashed next,
/// before any target is opened.
pub fn authorize_release(
    trusted_catalog_bytes: &[u8],
    catalog_entry_bytes: &[u8],
    qualification_bytes: &[u8],
    retail_metadata_bytes: &[u8],
) -> Result<AuthorizedImage, Error> {
    let catalog: Catalog = serde_json::from_slice(trusted_catalog_bytes)?;
    if catalog.schema != CATALOG_SCHEMA
        || catalog.catalog_revision == 0
        || catalog.images.is_empty()
    {
        return Err(Error::InvalidInput("Rescue catalog header is invalid"));
    }
    let catalog_entry: CatalogImage = serde_json::from_slice(catalog_entry_bytes)?;
    let catalog_sha = sha256_hex(catalog_entry_bytes);
    let trusted_matches = catalog
        .images
        .iter()
        .filter(|image| **image == catalog_entry)
        .count();
    if trusted_matches != 1 || !catalog_image_is_qualified(&catalog_entry) {
        return Err(Error::InvalidInput(
            "catalog entry is not uniquely present in the trusted catalog",
        ));
    }

    let qualification = parse_json(qualification_bytes)?;
    let root = object(
        &qualification,
        &[
            "artifactVersion",
            "artifacts",
            "evidence",
            "requiredJobs",
            "schema",
            "source",
        ],
        "qualification manifest fields are not exact",
    )?;
    if value_string(root, "schema")? != QUALIFICATION_SCHEMA {
        return Err(Error::InvalidInput("qualification schema is invalid"));
    }
    let artifact_version = value_string(root, "artifactVersion")?;
    if artifact_version.is_empty() || artifact_version.len() > 64 {
        return Err(Error::InvalidInput("artifact version is invalid"));
    }
    validate_qualification_origin(root, artifact_version, &catalog_entry)?;
    let artifacts = object(
        root.get("artifacts")
            .ok_or(Error::InvalidInput("artifacts are missing"))?,
        &["catalogV2Entry", "codexSbomTranche", "iso", "retailImage"],
        "qualification artifact fields are not exact",
    )?;
    let catalog_descriptor = object(
        artifacts
            .get("catalogV2Entry")
            .ok_or(Error::InvalidInput("catalog descriptor is missing"))?,
        &["bytes", "name", "sha256"],
        "catalog descriptor fields are not exact",
    )?;
    if value_string(catalog_descriptor, "name")? != CATALOG_NAME
        || value_u64(catalog_descriptor, "bytes")? != catalog_entry_bytes.len() as u64
        || value_string(catalog_descriptor, "sha256")? != catalog_sha
    {
        return Err(Error::InvalidInput(
            "qualification does not bind the trusted catalog",
        ));
    }
    let iso_descriptor = object(
        artifacts
            .get("iso")
            .ok_or(Error::InvalidInput("ISO descriptor is missing"))?,
        &["bytes", "checksum", "name", "sha256"],
        "ISO descriptor fields are not exact",
    )?;
    let iso_sha = value_string(iso_descriptor, "sha256")?;
    let iso_bytes = value_u64(iso_descriptor, "bytes")?;
    if catalog_entry.artifact_name != ISO_NAME
        || catalog_entry.artifact_version != artifact_version
        || catalog_entry.bytes != iso_bytes
        || catalog_entry.sha256 != iso_sha
    {
        return Err(Error::InvalidInput(
            "ISO is not uniquely qualified by catalog v2",
        ));
    }

    let metadata_sha = sha256_hex(retail_metadata_bytes);
    let retail = object(
        artifacts
            .get("retailImage")
            .ok_or(Error::InvalidInput("retail descriptor is missing"))?,
        &["bytes", "checksum", "layout", "metadata", "name", "sha256"],
        "retail descriptor fields are not exact",
    )?;
    let metadata_descriptor = object(
        retail
            .get("metadata")
            .ok_or(Error::InvalidInput("retail metadata descriptor is missing"))?,
        &["bytes", "name", "sha256"],
        "retail metadata descriptor fields are not exact",
    )?;
    if value_string(metadata_descriptor, "name")? != RETAIL_METADATA_NAME
        || value_u64(metadata_descriptor, "bytes")? != retail_metadata_bytes.len() as u64
        || value_string(metadata_descriptor, "sha256")? != metadata_sha
    {
        return Err(Error::InvalidInput(
            "qualification does not bind retail metadata",
        ));
    }

    let metadata = parse_json(retail_metadata_bytes)?;
    if retail.get("layout") != Some(&metadata) {
        return Err(Error::InvalidInput(
            "retail layout differs from bound metadata",
        ));
    }
    let metadata_root = object(
        &metadata,
        &["compressed", "isoPrefix", "p3", "raw", "schema", "tailZero"],
        "retail metadata fields are not exact",
    )?;
    if value_string(metadata_root, "schema")? != RETAIL_SCHEMA
        || metadata_root.get("tailZero") != Some(&Value::Bool(true))
    {
        return Err(Error::InvalidInput("retail metadata header is invalid"));
    }
    let compressed = object(
        metadata_root
            .get("compressed")
            .ok_or(Error::InvalidInput("compressed metadata is missing"))?,
        &["bytes", "name", "sha256"],
        "compressed metadata fields are not exact",
    )?;
    let compressed_bytes = value_u64(compressed, "bytes")?;
    let compressed_sha = value_string(compressed, "sha256")?;
    if value_string(compressed, "name")? != RETAIL_NAME
        || compressed_bytes == 0
        || compressed_bytes > MAX_COMPRESSED_BYTES
        || !valid_sha256(compressed_sha)
        || value_string(retail, "name")? != RETAIL_NAME
        || value_u64(retail, "bytes")? != compressed_bytes
        || value_string(retail, "sha256")? != compressed_sha
    {
        return Err(Error::InvalidInput(
            "compressed retail artifact is not exactly bound",
        ));
    }
    let iso_prefix = object(
        metadata_root
            .get("isoPrefix")
            .ok_or(Error::InvalidInput("ISO prefix is missing"))?,
        &["bytes", "sha256"],
        "ISO prefix fields are not exact",
    )?;
    if value_u64(iso_prefix, "bytes")? != iso_bytes
        || value_string(iso_prefix, "sha256")? != iso_sha
    {
        return Err(Error::InvalidInput(
            "retail ISO prefix is not catalog-authorized",
        ));
    }
    let raw = object(
        metadata_root
            .get("raw")
            .ok_or(Error::InvalidInput("raw metadata is missing"))?,
        &["bytes", "name", "sha256"],
        "raw metadata fields are not exact",
    )?;
    let raw_sha = value_string(raw, "sha256")?;
    if value_u64(raw, "bytes")? != RAW_BYTES
        || value_string(raw, "name")? != RAW_NAME
        || !valid_sha256(raw_sha)
    {
        return Err(Error::InvalidInput("raw retail artifact is invalid"));
    }
    let p3 = object(
        metadata_root
            .get("p3")
            .ok_or(Error::InvalidInput("vault partition metadata is missing"))?,
        &["bytes", "sha256", "startBytes", "zero"],
        "vault partition metadata fields are not exact",
    )?;
    if value_u64(p3, "startBytes")? != P3_START_BYTES
        || value_u64(p3, "bytes")? != P3_BYTES
        || value_string(p3, "sha256")? != P3_ZERO_SHA256
        || p3.get("zero") != Some(&Value::Bool(true))
    {
        return Err(Error::InvalidInput(
            "retail vault partition layout is invalid",
        ));
    }
    Ok(AuthorizedImage {
        artifact_version: artifact_version.to_owned(),
        compressed_sha256: compressed_sha.to_owned(),
        compressed_bytes,
        raw_sha256: raw_sha.to_owned(),
        raw_bytes: RAW_BYTES,
        catalog_sha256: catalog_sha,
        qualification_sha256: sha256_hex(qualification_bytes),
    })
}

fn catalog_image_is_qualified(image: &CatalogImage) -> bool {
    let layout = &image.device_layout;
    valid_sha256(&image.sha256)
        && layout.schema == "kernaid.rescue-device-layout.v1"
        && valid_sha256(&layout.manifest_sha256)
        && layout.partition_table == "mbr"
        && layout.logical_sector_bytes == 512
        && layout.minimum_media_bytes == 25_769_803_776
        && layout.minimum_advertised_media_bytes == MIN_MEDIA_BYTES
        && layout.minimum_advertised_media_label == "32 GB"
        && layout.vault_profile_version == 1
        && valid_sha256(&layout.vault_profile_sha256)
        && layout.vault_partition.number == 3
        && layout.vault_partition.name == "KERNAID_VAULT"
        && layout.vault_partition.mbr_type == "0x83"
        && layout.vault_partition.start_lba == 33_554_432
        && layout.vault_partition.sector_count == 16_777_216
        && image.qemu_usb_boot_attestations.len() == 2
        && image.qemu_vault_attestations.len() == 2
        && ["bios", "uefi"].iter().all(|firmware| {
            image
                .qemu_usb_boot_attestations
                .get(*firmware)
                .is_some_and(|item| {
                    item.passed
                        && item.boot_transport == "usb-storage"
                        && item.boot_count >= 2
                        && item.target_zero_writes_verified
                        && item.workflow_run_id > 0
                        && item
                            .workflow_run_url
                            .starts_with("https://github.com/0xfunboy/KernAid/actions/runs/")
                        && valid_sha256(&item.log_sha256)
                })
                && image
                    .qemu_vault_attestations
                    .get(*firmware)
                    .is_some_and(|item| {
                        item.passed
                            && item.boot_count >= 2
                            && item.luks_version == 2
                            && item.luks_label == "KERNAID_VAULT"
                            && item.filesystem == "ext4"
                            && item.filesystem_label == "KERNAID_VAULT"
                            && item.vault_profile_version == layout.vault_profile_version
                            && item.vault_profile_sha256 == layout.vault_profile_sha256
                            && item.stable_uuids_verified
                            && item.journal_identity_binding_verified
                            && item.identity_verified
                            && item.wrong_key_rejected
                            && item.workflow_run_id > 0
                            && item
                                .workflow_run_url
                                .starts_with("https://github.com/0xfunboy/KernAid/actions/runs/")
                            && valid_sha256(&item.log_sha256)
                    })
        })
}

fn validate_qualification_origin(
    root: &Map<String, Value>,
    artifact_version: &str,
    entry: &CatalogImage,
) -> Result<(), Error> {
    const JOBS: [&str; 4] = [
        "build-and-smoke-test",
        "native-vault-prompt-bios",
        "vault-lifecycle-bios",
        "vault-lifecycle-uefi",
    ];
    let required_jobs =
        root.get("requiredJobs")
            .and_then(Value::as_array)
            .ok_or(Error::InvalidInput(
                "qualification required jobs are invalid",
            ))?;
    if required_jobs.len() != JOBS.len()
        || required_jobs
            .iter()
            .zip(JOBS)
            .any(|(actual, expected)| actual.as_str() != Some(expected))
    {
        return Err(Error::InvalidInput(
            "qualification required jobs are not exact",
        ));
    }
    let source = object(
        root.get("source")
            .ok_or(Error::InvalidInput("qualification source is missing"))?,
        &[
            "commit",
            "repository",
            "workflow",
            "workflowRunAttempt",
            "workflowRunId",
            "workflowRunUrl",
        ],
        "qualification source fields are not exact",
    )?;
    let run_id = value_u64(source, "workflowRunId")?;
    let run_attempt = value_u64(source, "workflowRunAttempt")?;
    let run_url = value_string(source, "workflowRunUrl")?;
    let commit = value_string(source, "commit")?;
    if run_id == 0
        || run_attempt == 0
        || value_string(source, "repository")? != "0xfunboy/KernAid"
        || value_string(source, "workflow")? != ".github/workflows/rescue.yml"
        || commit.len() != 40
        || !commit
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        || run_url != format!("https://github.com/0xfunboy/KernAid/actions/runs/{run_id}")
        || artifact_version != format!("ci-{run_id}-{run_attempt}")
    {
        return Err(Error::InvalidInput(
            "qualification source is not the official Rescue workflow run",
        ));
    }
    if entry
        .qemu_usb_boot_attestations
        .values()
        .any(|item| item.workflow_run_id != run_id || item.workflow_run_url != run_url)
        || entry
            .qemu_vault_attestations
            .values()
            .any(|item| item.workflow_run_id != run_id || item.workflow_run_url != run_url)
    {
        return Err(Error::InvalidInput(
            "qualification source and catalog attestations differ",
        ));
    }
    Ok(())
}

/// Hash and rewind the still-open archive before any disk is opened.
pub fn verify_archive<R: Read + Seek>(
    source_name: &str,
    source: &mut R,
    image: &AuthorizedImage,
) -> Result<(), Error> {
    verify_archive_with_progress(source_name, source, image, &mut |_| {})
}

fn verify_archive_with_progress<R: Read + Seek>(
    source_name: &str,
    source: &mut R,
    image: &AuthorizedImage,
    progress: &mut impl FnMut(MediaProgress),
) -> Result<(), Error> {
    if source_name != RETAIL_NAME {
        return Err(Error::InvalidInput("retail archive filename is not exact"));
    }
    source.seek(SeekFrom::Start(0))?;
    progress(MediaProgress {
        phase: MediaPhase::ValidatingArchive,
        completed_bytes: 0,
        total_bytes: image.compressed_bytes,
    });
    let (bytes, digest) = hash_exact(
        source,
        image.compressed_bytes + 1,
        image.compressed_bytes,
        progress,
    )?;
    if bytes != image.compressed_bytes || digest != image.compressed_sha256 {
        return Err(Error::InvalidInput(
            "retail archive size or SHA-256 does not match qualification",
        ));
    }
    source.seek(SeekFrom::Start(0))?;
    Ok(())
}

pub fn eligible_disks(candidates: &[DiskCandidate], image: &AuthorizedImage) -> Vec<EligibleDisk> {
    let mut ids = BTreeMap::<&str, usize>::new();
    let mut serials = BTreeMap::<&str, usize>::new();
    for candidate in candidates {
        *ids.entry(candidate.opaque_id.as_str()).or_default() += 1;
        *serials.entry(candidate.serial.as_str()).or_default() += 1;
    }
    candidates
        .iter()
        .filter(|candidate| {
            !candidate.opaque_id.is_empty()
                && candidate.opaque_id.len() <= 80
                && !candidate.model.trim().is_empty()
                && candidate.model.len() <= 160
                && !candidate.serial.trim().is_empty()
                && candidate.serial.len() <= 160
                && candidate.capacity_bytes >= image.raw_bytes.max(MIN_MEDIA_BYTES)
                && candidate.usb
                && candidate.removable
                && candidate.whole_disk
                && !candidate.read_only
                && !candidate.contains_system
                && !candidate.contains_boot
                && !candidate.ambiguous
                && ids.get(candidate.opaque_id.as_str()) == Some(&1)
                && serials.get(candidate.serial.as_str()) == Some(&1)
        })
        .map(|candidate| EligibleDisk {
            opaque_id: candidate.opaque_id.clone(),
            model: candidate.model.clone(),
            serial: candidate.serial.clone(),
            capacity_bytes: candidate.capacity_bytes,
        })
        .collect()
}

pub fn select_disk(
    candidates: &[DiskCandidate],
    eligible: &EligibleDisk,
) -> Result<DiskSelection, Error> {
    let matches: Vec<&DiskCandidate> = candidates
        .iter()
        .filter(|candidate| {
            candidate.opaque_id == eligible.opaque_id
                && candidate.model == eligible.model
                && candidate.serial == eligible.serial
                && candidate.capacity_bytes == eligible.capacity_bytes
        })
        .collect();
    if matches.len() != 1 {
        return Err(Error::InvalidInput(
            "selected disk is no longer uniquely enumerated",
        ));
    }
    Ok(DiskSelection {
        candidate: matches[0].clone(),
        confirmation_phrase: format!("ERASE KERNAID USB {}", eligible.opaque_id),
    })
}

/// Stream-decompress, exact-write, flush, and hash the exact readback bytes.
/// `open_revalidated` is called only after archive verification and confirmation.
pub fn create_media<B: DiskBackend, R: Read + Seek>(
    backend: &mut B,
    confirmed: ConfirmedSelection,
    source_name: &str,
    source: &mut R,
    image: &AuthorizedImage,
) -> Result<CreationReport, Error> {
    create_media_with_progress(backend, confirmed, source_name, source, image, |_| {})
}

pub fn create_media_with_progress<B, R, P>(
    backend: &mut B,
    confirmed: ConfirmedSelection,
    source_name: &str,
    source: &mut R,
    image: &AuthorizedImage,
    mut progress: P,
) -> Result<CreationReport, Error>
where
    B: DiskBackend,
    R: Read + Seek,
    P: FnMut(MediaProgress),
{
    verify_archive_with_progress(source_name, source, image, &mut progress)?;
    let selected = confirmed.0;
    let mut target = backend.open_revalidated(&selected)?;
    target.seek(SeekFrom::Start(0))?;
    progress(MediaProgress {
        phase: MediaPhase::WritingUsb,
        completed_bytes: 0,
        total_bytes: image.raw_bytes,
    });
    let written_sha = stream_xz(source, &mut target, image.raw_bytes, &mut progress)?;
    if written_sha != image.raw_sha256 {
        return Err(Error::InvalidInput("decompressed image SHA-256 is invalid"));
    }
    target.flush()?;
    target.sync_all()?;
    target.seek(SeekFrom::Start(0))?;
    progress(MediaProgress {
        phase: MediaPhase::VerifyingUsb,
        completed_bytes: 0,
        total_bytes: image.raw_bytes,
    });
    let readback_sha = hash_prefix(&mut target, image.raw_bytes, &mut progress)?;
    if readback_sha != image.raw_sha256 {
        return Err(Error::InvalidInput("USB readback SHA-256 did not match"));
    }
    target.sync_all()?;
    Ok(CreationReport {
        schema: REPORT_SCHEMA,
        outcome: "succeeded",
        completed_at: Utc::now().to_rfc3339_opts(SecondsFormat::Secs, true),
        artifact_name: RETAIL_NAME,
        artifact_version: image.artifact_version.clone(),
        compressed_bytes: image.compressed_bytes,
        compressed_sha256: image.compressed_sha256.clone(),
        raw_bytes: image.raw_bytes,
        raw_sha256: image.raw_sha256.clone(),
        readback_sha256: readback_sha,
        catalog_sha256: image.catalog_sha256.clone(),
        qualification_sha256: image.qualification_sha256.clone(),
        disk: EligibleDisk {
            opaque_id: selected.opaque_id,
            model: selected.model,
            serial: selected.serial,
            capacity_bytes: selected.capacity_bytes,
        },
    })
}

fn stream_xz(
    source: &mut impl Read,
    target: &mut impl Write,
    expected_bytes: u64,
    progress: &mut impl FnMut(MediaProgress),
) -> Result<String, Error> {
    let mut decoder = XzStream::new_mem_limit(true, XZ_MEMORY_LIMIT_KIB);
    let mut input = vec![0_u8; IO_CHUNK_BYTES];
    let mut output = vec![0_u8; IO_CHUNK_BYTES];
    let mut input_length = 0_usize;
    let mut input_position = 0_usize;
    let mut end_of_input = false;
    let mut remaining = expected_bytes;
    let mut raw_hasher = Sha256::new();
    loop {
        if input_position == input_length && !end_of_input {
            input_length = source.read(&mut input)?;
            input_position = 0;
            end_of_input = input_length == 0;
        }
        let action = if end_of_input {
            Action::Finish
        } else {
            Action::Run
        };
        let result = decoder.process(&input[input_position..input_length], &mut output, action)?;
        input_position += result.bytes_consumed;
        if result.bytes_produced as u64 > remaining {
            return Err(Error::InvalidInput(
                "retail image decompressed beyond declared size",
            ));
        }
        if result.bytes_produced > 0 {
            target.write_all(&output[..result.bytes_produced])?;
            raw_hasher.update(&output[..result.bytes_produced]);
            remaining -= result.bytes_produced as u64;
            progress(MediaProgress {
                phase: MediaPhase::WritingUsb,
                completed_bytes: expected_bytes - remaining,
                total_bytes: expected_bytes,
            });
        }
        if result.status == Status::StreamEnd {
            break;
        }
        if result.bytes_consumed == 0 && result.bytes_produced == 0 && end_of_input {
            return Err(Error::InvalidInput(
                "retail image decompression did not reach a complete stream",
            ));
        }
    }
    if remaining != 0 {
        return Err(Error::InvalidInput(
            "retail image decompressed shorter than declared",
        ));
    }
    Ok(format!("{:x}", raw_hasher.finalize()))
}

fn hash_exact(
    reader: &mut impl Read,
    maximum: u64,
    expected: u64,
    progress: &mut impl FnMut(MediaProgress),
) -> Result<(u64, String), Error> {
    let mut hasher = Sha256::new();
    let mut total = 0_u64;
    let mut buffer = vec![0_u8; IO_CHUNK_BYTES];
    loop {
        let read = reader.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        total = total
            .checked_add(read as u64)
            .ok_or(Error::InvalidInput("byte count overflow"))?;
        if total > maximum {
            return Err(Error::InvalidInput("input exceeds its declared bound"));
        }
        hasher.update(&buffer[..read]);
        progress(MediaProgress {
            phase: MediaPhase::ValidatingArchive,
            completed_bytes: total.min(expected),
            total_bytes: expected,
        });
    }
    Ok((total, format!("{:x}", hasher.finalize())))
}

fn hash_prefix(
    reader: &mut impl Read,
    bytes: u64,
    progress: &mut impl FnMut(MediaProgress),
) -> Result<String, Error> {
    let mut hasher = Sha256::new();
    let mut remaining = bytes;
    let mut buffer = vec![0_u8; IO_CHUNK_BYTES];
    while remaining > 0 {
        let limit = usize::try_from(remaining.min(buffer.len() as u64))
            .map_err(|_| Error::InvalidInput("readback byte count is invalid"))?;
        let read = reader.read(&mut buffer[..limit])?;
        if read == 0 {
            return Err(Error::InvalidInput(
                "USB readback ended before the declared image size",
            ));
        }
        hasher.update(&buffer[..read]);
        remaining -= read as u64;
        progress(MediaProgress {
            phase: MediaPhase::VerifyingUsb,
            completed_bytes: bytes - remaining,
            total_bytes: bytes,
        });
    }
    Ok(format!("{:x}", hasher.finalize()))
}

// Allow platform adapters to use File while mock backends can provide the same
// durability contract without touching a physical device.
pub trait MediaHandle: Read + Write + Seek {
    fn sync_all(&mut self) -> io::Result<()>;
}

impl MediaHandle for std::fs::File {
    fn sync_all(&mut self) -> io::Result<()> {
        std::fs::File::sync_all(self)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer as _, SigningKey};
    use lzma_rust2::{XzOptions, XzWriter};
    use serde_json::json;
    use std::{
        fs::{self, OpenOptions},
        io::Cursor,
        path::PathBuf,
    };
    use tempfile::TempDir;

    fn digest(bytes: &[u8]) -> String {
        format!("{:x}", Sha256::digest(bytes))
    }

    fn compress(bytes: &[u8]) -> io::Result<Vec<u8>> {
        let mut writer = XzWriter::new(Vec::new(), XzOptions::default())?;
        writer.write_all(bytes)?;
        writer.finish()
    }

    fn image(compressed: &[u8], raw: &[u8]) -> AuthorizedImage {
        AuthorizedImage {
            artifact_version: "test-1".to_owned(),
            compressed_sha256: digest(compressed),
            compressed_bytes: compressed.len() as u64,
            raw_sha256: digest(raw),
            raw_bytes: raw.len() as u64,
            catalog_sha256: "1".repeat(64),
            qualification_sha256: "2".repeat(64),
        }
    }

    fn signed_bundle_manifest(
        artifact_version: &str,
        catalog_entry: &[u8],
        qualification: &[u8],
        retail_metadata: &[u8],
        retail_bytes: u64,
        retail_sha256: &str,
        signing_key: &SigningKey,
    ) -> Result<Vec<u8>, Error> {
        let trust_anchor = signing_key.verifying_key().to_bytes();
        let mut manifest = json!({
            "artifactVersion": artifact_version,
            "files": {
                "catalogEntry": {"bytes": catalog_entry.len(), "name": CATALOG_NAME, "sha256": digest(catalog_entry)},
                "qualification": {"bytes": qualification.len(), "name": QUALIFICATION_NAME, "sha256": digest(qualification)},
                "retailImage": {"bytes": retail_bytes, "name": RETAIL_NAME, "sha256": retail_sha256},
                "retailMetadata": {"bytes": retail_metadata.len(), "name": RETAIL_METADATA_NAME, "sha256": digest(retail_metadata)}
            },
            "keyId": format!("sha256:{}", digest(&trust_anchor)),
            "schema": RELEASE_BUNDLE_SCHEMA
        });
        let unsigned = canonical_json(&manifest)?;
        let mut message = RELEASE_BUNDLE_SIGNING_DOMAIN.to_vec();
        message.extend_from_slice(unsigned.as_bytes());
        manifest
            .as_object_mut()
            .ok_or(Error::InvalidInput("test manifest"))?
            .insert(
                "signature".to_owned(),
                Value::String(URL_SAFE_NO_PAD.encode(signing_key.sign(&message).to_bytes())),
            );
        Ok(canonical_json(&manifest)?.into_bytes())
    }

    fn candidate(id: &str) -> DiskCandidate {
        DiskCandidate {
            opaque_id: id.to_owned(),
            model: "KernAid Test USB".to_owned(),
            serial: format!("SERIAL-{id}"),
            capacity_bytes: MIN_MEDIA_BYTES,
            usb: true,
            removable: true,
            whole_disk: true,
            read_only: false,
            contains_system: false,
            contains_boot: false,
            ambiguous: false,
        }
    }

    struct MockBackend {
        expected: DiskCandidate,
        path: PathBuf,
        opens: usize,
    }

    impl DiskBackend for MockBackend {
        type Handle = std::fs::File;

        fn enumerate(&mut self) -> Result<Vec<DiskCandidate>, Error> {
            Ok(vec![self.expected.clone()])
        }

        fn open_revalidated(&mut self, selected: &DiskCandidate) -> Result<Self::Handle, Error> {
            if selected != &self.expected {
                return Err(Error::InvalidInput("mock identity changed"));
            }
            self.opens += 1;
            Ok(OpenOptions::new().read(true).write(true).open(&self.path)?)
        }
    }

    fn setup_target(raw_len: u64) -> io::Result<(TempDir, MockBackend, Vec<DiskCandidate>)> {
        let root = tempfile::tempdir()?;
        let path = root.path().join("mock-usb.img");
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .open(&path)?;
        file.set_len(raw_len + 4096)?;
        let expected = candidate("KAUSB-test0001");
        let candidates = vec![expected.clone()];
        Ok((
            root,
            MockBackend {
                expected,
                path,
                opens: 0,
            },
            candidates,
        ))
    }

    #[test]
    fn selection_rejects_unsafe_and_ambiguous_disks_and_requires_exact_phrase()
    -> Result<(), Box<dyn std::error::Error>> {
        let compressed = vec![1];
        let authorized = image(&compressed, &[2]);
        let good = candidate("KAUSB-good");
        let mut system = candidate("KAUSB-system");
        system.contains_system = true;
        let mut readonly = candidate("KAUSB-readonly");
        readonly.read_only = true;
        let mut duplicate = candidate("KAUSB-duplicate");
        duplicate.serial = good.serial.clone();
        let candidates = vec![good.clone(), system, readonly, duplicate];
        let eligible = eligible_disks(&candidates, &authorized);
        assert!(
            eligible.is_empty(),
            "duplicate serial must reject both identities"
        );

        let candidates = vec![good];
        let eligible = eligible_disks(&candidates, &authorized);
        assert_eq!(eligible.len(), 1);
        let selection = select_disk(&candidates, &eligible[0])?;
        assert_eq!(
            selection.confirmation_phrase(),
            "ERASE KERNAID USB KAUSB-good"
        );
        assert!(
            selection
                .clone()
                .confirm("erase kernaid usb KAUSB-good")
                .is_err()
        );
        selection.confirm("ERASE KERNAID USB KAUSB-good")?;
        Ok(())
    }

    #[test]
    fn stream_write_flush_and_exact_readback_succeed_on_mock_file()
    -> Result<(), Box<dyn std::error::Error>> {
        let raw = b"KernAid retail image fixture".repeat(4096);
        let compressed = compress(&raw)?;
        let authorized = image(&compressed, &raw);
        let (_root, mut backend, candidates) = setup_target(raw.len() as u64)?;
        let eligible = eligible_disks(&candidates, &authorized);
        let confirmed =
            select_disk(&candidates, &eligible[0])?.confirm("ERASE KERNAID USB KAUSB-test0001")?;
        let mut source = Cursor::new(compressed);
        let mut progress = Vec::new();
        let report = create_media_with_progress(
            &mut backend,
            confirmed,
            RETAIL_NAME,
            &mut source,
            &authorized,
            |event| progress.push(event),
        )?;
        assert_eq!(backend.opens, 1);
        assert_eq!(report.raw_sha256, digest(&raw));
        assert_eq!(report.readback_sha256, digest(&raw));
        let written = fs::read(&backend.path)?;
        assert_eq!(&written[..raw.len()], raw.as_slice());
        for phase in [
            MediaPhase::ValidatingArchive,
            MediaPhase::WritingUsb,
            MediaPhase::VerifyingUsb,
        ] {
            let events = progress
                .iter()
                .filter(|event| event.phase == phase)
                .collect::<Vec<_>>();
            assert!(!events.is_empty());
            assert_eq!(events.first().map(|event| event.completed_bytes), Some(0));
            assert_eq!(
                events.last().map(|event| event.completed_bytes),
                events.last().map(|event| event.total_bytes)
            );
            assert!(events.windows(2).all(|pair| {
                pair[0].completed_bytes <= pair[1].completed_bytes
                    && pair[0].total_bytes == pair[1].total_bytes
            }));
        }
        Ok(())
    }

    #[test]
    fn archive_tamper_is_rejected_before_target_open() -> Result<(), Box<dyn std::error::Error>> {
        let raw = b"safe image".repeat(100);
        let compressed = compress(&raw)?;
        let authorized = image(&compressed, &raw);
        let (_root, mut backend, candidates) = setup_target(raw.len() as u64)?;
        let eligible = eligible_disks(&candidates, &authorized);
        let confirmed =
            select_disk(&candidates, &eligible[0])?.confirm("ERASE KERNAID USB KAUSB-test0001")?;
        let mut tampered = compressed;
        tampered[0] ^= 1;
        let result = create_media(
            &mut backend,
            confirmed,
            RETAIL_NAME,
            &mut Cursor::new(tampered),
            &authorized,
        );
        assert!(result.is_err());
        assert_eq!(backend.opens, 0);
        Ok(())
    }

    #[test]
    fn decompressed_truncation_extra_bytes_and_wrong_digest_fail_closed()
    -> Result<(), Box<dyn std::error::Error>> {
        for (raw, declared_len, expected_digest) in [
            (b"short".to_vec(), 6_u64, digest(b"short!")),
            (b"extra".to_vec(), 4_u64, digest(b"extr")),
            (b"digest".to_vec(), 6_u64, digest(b"wrong!")),
        ] {
            let compressed = compress(&raw)?;
            let mut authorized = image(&compressed, &raw);
            authorized.raw_bytes = declared_len;
            authorized.raw_sha256 = expected_digest;
            let (_root, mut backend, candidates) = setup_target(32)?;
            let eligible = eligible_disks(&candidates, &authorized);
            let confirmed = select_disk(&candidates, &eligible[0])?
                .confirm("ERASE KERNAID USB KAUSB-test0001")?;
            assert!(
                create_media(
                    &mut backend,
                    confirmed,
                    RETAIL_NAME,
                    &mut Cursor::new(compressed),
                    &authorized,
                )
                .is_err()
            );
        }
        Ok(())
    }

    #[test]
    fn catalog_entry_and_qualification_are_bound_exactly() -> Result<(), Box<dyn std::error::Error>>
    {
        let trusted = include_bytes!("../../../tools/make-device/trusted-rescue-images.v2.json");
        let catalog: Value = serde_json::from_slice(trusted)?;
        let entry = catalog["images"][0].clone();
        let entry_bytes = serde_json::to_vec(&entry)?;
        let compressed_sha = "a".repeat(64);
        let raw_sha = "b".repeat(64);
        let metadata = json!({
            "compressed": {"bytes": 123, "name": RETAIL_NAME, "sha256": compressed_sha},
            "isoPrefix": {"bytes": entry["bytes"], "sha256": entry["sha256"]},
            "p3": {"bytes": P3_BYTES, "sha256": P3_ZERO_SHA256, "startBytes": P3_START_BYTES, "zero": true},
            "raw": {"bytes": RAW_BYTES, "name": RAW_NAME, "sha256": raw_sha},
            "schema": RETAIL_SCHEMA,
            "tailZero": true
        });
        let metadata_bytes = serde_json::to_vec(&metadata)?;
        let qualification = json!({
            "artifactVersion": entry["artifactVersion"],
            "artifacts": {
                "catalogV2Entry": {"bytes": entry_bytes.len(), "name": CATALOG_NAME, "sha256": digest(&entry_bytes)},
                "codexSbomTranche": {"bytes": 1, "name": "KernAid-Rescue-amd64.codex.cdx.json", "sha256": "c".repeat(64)},
                "iso": {"bytes": entry["bytes"], "checksum": {"bytes": 1, "name": "KernAid-Rescue-amd64.iso.sha256", "sha256": "d".repeat(64)}, "name": ISO_NAME, "sha256": entry["sha256"]},
                "retailImage": {
                    "bytes": 123,
                    "checksum": {"bytes": 1, "name": "KernAid-Rescue-amd64-retail.img.xz.sha256", "sha256": "e".repeat(64)},
                    "layout": metadata,
                    "metadata": {"bytes": metadata_bytes.len(), "name": RETAIL_METADATA_NAME, "sha256": digest(&metadata_bytes)},
                    "name": RETAIL_NAME,
                    "sha256": "a".repeat(64)
                }
            },
            "evidence": {},
            "requiredJobs": [
                "build-and-smoke-test",
                "native-vault-prompt-bios",
                "vault-lifecycle-bios",
                "vault-lifecycle-uefi"
            ],
            "schema": QUALIFICATION_SCHEMA,
            "source": {
                "commit": "0".repeat(40),
                "repository": "0xfunboy/KernAid",
                "workflow": ".github/workflows/rescue.yml",
                "workflowRunAttempt": 1,
                "workflowRunId": entry["qemuUsbBootAttestations"]["bios"]["workflowRunId"],
                "workflowRunUrl": entry["qemuUsbBootAttestations"]["bios"]["workflowRunUrl"]
            }
        });
        let qualification_bytes = serde_json::to_vec(&qualification)?;
        let authorized =
            authorize_release(trusted, &entry_bytes, &qualification_bytes, &metadata_bytes)?;
        assert_eq!(
            authorized.artifact_version(),
            entry["artifactVersion"].as_str().ok_or("version")?
        );

        let signing_key = SigningKey::from_bytes(&[0x42; 32]);
        let bundle_manifest = signed_bundle_manifest(
            authorized.artifact_version(),
            &entry_bytes,
            &qualification_bytes,
            &metadata_bytes,
            authorized.compressed_bytes(),
            authorized.compressed_sha256(),
            &signing_key,
        )?;
        let bundle_authorized = authorize_release_bundle(
            trusted,
            &bundle_manifest,
            &signing_key.verifying_key().to_bytes(),
            &entry_bytes,
            &qualification_bytes,
            &metadata_bytes,
        )?;
        assert_eq!(
            bundle_authorized.artifact_version(),
            authorized.artifact_version()
        );

        let mut noncanonical_manifest = bundle_manifest.clone();
        noncanonical_manifest.push(b'\n');
        assert!(
            authorize_release_bundle(
                trusted,
                &noncanonical_manifest,
                &signing_key.verifying_key().to_bytes(),
                &entry_bytes,
                &qualification_bytes,
                &metadata_bytes,
            )
            .is_err()
        );
        let mut unknown_field_manifest: Value = serde_json::from_slice(&bundle_manifest)?;
        unknown_field_manifest
            .as_object_mut()
            .ok_or("bundle object")?
            .insert(
                "downloadUrl".to_owned(),
                Value::String("https://invalid".to_owned()),
            );
        assert!(
            authorize_release_bundle(
                trusted,
                canonical_json(&unknown_field_manifest)?.as_bytes(),
                &signing_key.verifying_key().to_bytes(),
                &entry_bytes,
                &qualification_bytes,
                &metadata_bytes,
            )
            .is_err()
        );
        let mut tampered_signature_manifest: Value = serde_json::from_slice(&bundle_manifest)?;
        let signature = tampered_signature_manifest["signature"]
            .as_str()
            .ok_or("bundle signature")?;
        let replacement = if signature.starts_with('A') { 'B' } else { 'A' };
        let changed_signature = format!("{replacement}{}", &signature[1..]);
        tampered_signature_manifest["signature"] = Value::String(changed_signature);
        assert!(
            authorize_release_bundle(
                trusted,
                canonical_json(&tampered_signature_manifest)?.as_bytes(),
                &signing_key.verifying_key().to_bytes(),
                &entry_bytes,
                &qualification_bytes,
                &metadata_bytes,
            )
            .is_err()
        );

        let mut changed_qualification = qualification_bytes.clone();
        changed_qualification.push(b' ');
        assert!(
            authorize_release_bundle(
                trusted,
                &bundle_manifest,
                &signing_key.verifying_key().to_bytes(),
                &entry_bytes,
                &changed_qualification,
                &metadata_bytes,
            )
            .is_err()
        );
        assert!(
            authorize_release_bundle(
                trusted,
                &bundle_manifest,
                &SigningKey::from_bytes(&[0x24; 32])
                    .verifying_key()
                    .to_bytes(),
                &entry_bytes,
                &qualification_bytes,
                &metadata_bytes,
            )
            .is_err()
        );

        let mut tampered_entry = entry;
        tampered_entry["artifactVersion"] = Value::String("ci-tampered".to_owned());
        let tampered_bytes = serde_json::to_vec(&tampered_entry)?;
        assert!(
            authorize_release(
                trusted,
                &tampered_bytes,
                &qualification_bytes,
                &metadata_bytes
            )
            .is_err()
        );
        Ok(())
    }
}
