//! Transport-neutral streaming into an explicitly preopened inactive target.

use super::{
    AdmittedUpdate, Availability, CompletedArtifactEvidence, MAX_ARTIFACT_BYTES,
    MAX_SAFE_JSON_INTEGER, Slot, StagePlan, UpdateContext, UpdateError, UpdateState,
    canonical_json, decode_sha256, hex_sha256, import_canonical, validate_identifier,
    validate_sha256, validate_size,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    error::Error,
    fmt, fs,
    fs::{File, OpenOptions},
    io::{self, Read, Seek, SeekFrom, Write},
    path::{Path, PathBuf},
};

#[cfg(unix)]
use std::os::unix::fs::{FileTypeExt, OpenOptionsExt, PermissionsExt};

pub const UPDATE_STAGING_CHECKPOINT_SCHEMA: &str = "dev.kernaid.update.staging-checkpoint.v1";
pub const UPDATE_STAGING_RECEIPT_SCHEMA: &str = "dev.kernaid.update.staging-receipt.v1";

const PENDING_FILE: &str = "artifact-staging.pending.cjson";
const RECEIPT_FILE: &str = "artifact-staging.receipt.cjson";
const TEMP_FILE: &str = ".artifact-staging.metadata.tmp";
const MAX_METADATA_BYTES: usize = 16 * 1024;
const COPY_BUFFER_BYTES: usize = 64 * 1024;

/// Durable intent written before any destination byte is changed.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct StagingCheckpoint {
    schema: String,
    release_id: String,
    sequence: u64,
    manifest_sha256: String,
    artifact_size_bytes: u64,
    artifact_sha256: String,
    active_slot: Slot,
    target_slot: Slot,
}

impl StagingCheckpoint {
    fn from_admitted(admitted: &AdmittedUpdate, target: &PreopenedInactiveTarget) -> Self {
        let verified = admitted.verified();
        Self {
            schema: UPDATE_STAGING_CHECKPOINT_SCHEMA.to_owned(),
            release_id: verified.release_id().to_owned(),
            sequence: verified.sequence(),
            manifest_sha256: hex_sha256(verified.manifest_sha256()),
            artifact_size_bytes: verified.artifact().size_bytes,
            artifact_sha256: verified.artifact().sha256.clone(),
            active_slot: target.active_slot,
            target_slot: target.target_slot,
        }
    }

    pub fn export_canonical(&self) -> Result<Vec<u8>, StagingError> {
        self.validate()?;
        let bytes = canonical_json(self)?;
        validate_size(bytes.len(), MAX_METADATA_BYTES)?;
        Ok(bytes)
    }

    pub fn import_canonical(bytes: &[u8]) -> Result<Self, StagingError> {
        let checkpoint: Self = import_canonical(bytes, MAX_METADATA_BYTES)?;
        checkpoint.validate()?;
        Ok(checkpoint)
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
    pub const fn active_slot(&self) -> Slot {
        self.active_slot
    }

    #[must_use]
    pub const fn target_slot(&self) -> Slot {
        self.target_slot
    }

    fn validate(&self) -> Result<(), StagingError> {
        if self.schema != UPDATE_STAGING_CHECKPOINT_SCHEMA {
            return Err(StagingError::InvalidMetadata);
        }
        validate_common(
            &self.release_id,
            self.sequence,
            &self.manifest_sha256,
            self.artifact_size_bytes,
            &self.artifact_sha256,
            self.active_slot,
            self.target_slot,
        )
    }
}

/// Durable proof that exact signed artifact bytes reached and were synced to
/// the preopened inactive target. It grants no bootloader authority.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct StagingReceipt {
    schema: String,
    release_id: String,
    sequence: u64,
    manifest_sha256: String,
    artifact_size_bytes: u64,
    artifact_sha256: String,
    active_slot: Slot,
    target_slot: Slot,
}

impl StagingReceipt {
    fn from_checkpoint(checkpoint: &StagingCheckpoint) -> Self {
        Self {
            schema: UPDATE_STAGING_RECEIPT_SCHEMA.to_owned(),
            release_id: checkpoint.release_id.clone(),
            sequence: checkpoint.sequence,
            manifest_sha256: checkpoint.manifest_sha256.clone(),
            artifact_size_bytes: checkpoint.artifact_size_bytes,
            artifact_sha256: checkpoint.artifact_sha256.clone(),
            active_slot: checkpoint.active_slot,
            target_slot: checkpoint.target_slot,
        }
    }

    pub fn export_canonical(&self) -> Result<Vec<u8>, StagingError> {
        self.validate()?;
        let bytes = canonical_json(self)?;
        validate_size(bytes.len(), MAX_METADATA_BYTES)?;
        Ok(bytes)
    }

    pub fn import_canonical(bytes: &[u8]) -> Result<Self, StagingError> {
        let receipt: Self = import_canonical(bytes, MAX_METADATA_BYTES)?;
        receipt.validate()?;
        Ok(receipt)
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

    fn validate(&self) -> Result<(), StagingError> {
        if self.schema != UPDATE_STAGING_RECEIPT_SCHEMA {
            return Err(StagingError::InvalidMetadata);
        }
        validate_common(
            &self.release_id,
            self.sequence,
            &self.manifest_sha256,
            self.artifact_size_bytes,
            &self.artifact_sha256,
            self.active_slot,
            self.target_slot,
        )
    }

    fn matches_checkpoint(&self, checkpoint: &StagingCheckpoint) -> bool {
        self.release_id == checkpoint.release_id
            && self.sequence == checkpoint.sequence
            && self.manifest_sha256 == checkpoint.manifest_sha256
            && self.artifact_size_bytes == checkpoint.artifact_size_bytes
            && self.artifact_sha256 == checkpoint.artifact_sha256
            && self.active_slot == checkpoint.active_slot
            && self.target_slot == checkpoint.target_slot
    }

    fn validate_for(
        &self,
        admitted: &AdmittedUpdate,
        active_slot: Slot,
    ) -> Result<(), StagingError> {
        self.validate()?;
        let expected = StagingCheckpoint {
            schema: UPDATE_STAGING_CHECKPOINT_SCHEMA.to_owned(),
            release_id: admitted.verified().release_id().to_owned(),
            sequence: admitted.verified().sequence(),
            manifest_sha256: hex_sha256(admitted.verified().manifest_sha256()),
            artifact_size_bytes: admitted.verified().artifact().size_bytes,
            artifact_sha256: admitted.verified().artifact().sha256.clone(),
            active_slot,
            target_slot: active_slot.inactive(),
        };
        if !self.matches_checkpoint(&expected) {
            return Err(StagingError::ReceiptMismatch);
        }
        Ok(())
    }
}

impl CompletedArtifactEvidence for StagingReceipt {
    fn complete_size_bytes(&self) -> u64 {
        self.artifact_size_bytes
    }

    fn complete_sha256(&self) -> [u8; 32] {
        decode_sha256(&self.artifact_sha256).unwrap_or([0; 32])
    }
}

/// Capability for a destination opened by trusted platform code. This API has
/// no path constructor and rejects the active slot before a write is possible.
pub struct PreopenedInactiveTarget {
    file: File,
    active_slot: Slot,
    target_slot: Slot,
    regular_file: bool,
}

impl PreopenedInactiveTarget {
    pub fn new(file: File, active_slot: Slot, target_slot: Slot) -> Result<Self, StagingError> {
        if target_slot != active_slot.inactive() {
            return Err(StagingError::ActiveSlotRejected);
        }
        let metadata = file.metadata()?;
        let regular_file = metadata.is_file();
        #[cfg(unix)]
        let supported = regular_file || metadata.file_type().is_block_device();
        #[cfg(not(unix))]
        let supported = regular_file;
        if !supported {
            return Err(StagingError::UnsupportedDestination);
        }
        Ok(Self {
            file,
            active_slot,
            target_slot,
            regular_file,
        })
    }

    #[must_use]
    pub const fn active_slot(&self) -> Slot {
        self.active_slot
    }

    #[must_use]
    pub const fn target_slot(&self) -> Slot {
        self.target_slot
    }

    pub fn into_inner(self) -> File {
        self.file
    }

    fn prepare(&mut self) -> Result<(), StagingError> {
        if self.target_slot != self.active_slot.inactive() {
            return Err(StagingError::ActiveSlotRejected);
        }
        if self.regular_file {
            self.file.set_len(0)?;
        }
        self.file.seek(SeekFrom::Start(0))?;
        Ok(())
    }

    fn cleanup_failed_write(&mut self) -> Result<(), StagingError> {
        if self.regular_file {
            self.file.set_len(0)?;
        }
        self.file.seek(SeekFrom::Start(0))?;
        self.file.flush()?;
        self.file.sync_all()?;
        Ok(())
    }
}

impl fmt::Debug for PreopenedInactiveTarget {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PreopenedInactiveTarget")
            .field("active_slot", &self.active_slot)
            .field("target_slot", &self.target_slot)
            .finish_non_exhaustive()
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum StagingRecovery {
    Clean,
    Interrupted(StagingCheckpoint),
    Completed(StagingReceipt),
}

/// Single-update durable stager. Product integration must hold its normal
/// per-device update lock while this object is in use.
#[derive(Debug)]
pub struct ArtifactStager {
    state_dir: PathBuf,
}

impl ArtifactStager {
    pub fn open(state_dir: &Path) -> Result<Self, StagingError> {
        prepare_private_state_dir(state_dir)?;
        let stager = Self {
            state_dir: state_dir.to_path_buf(),
        };
        stager.cleanup_temporary_metadata()?;
        // Parse now so corruption cannot be hidden until a later stage call.
        stager.recovery_status()?;
        Ok(stager)
    }

    /// Inspect durable state without touching the inactive destination.
    pub fn recovery_status(&self) -> Result<StagingRecovery, StagingError> {
        let pending = self.load_checkpoint()?;
        let receipt = self.load_receipt()?;
        match (pending, receipt) {
            (None, None) => Ok(StagingRecovery::Clean),
            (Some(checkpoint), None) => Ok(StagingRecovery::Interrupted(checkpoint)),
            (None, Some(receipt)) => Ok(StagingRecovery::Completed(receipt)),
            (Some(checkpoint), Some(receipt)) if receipt.matches_checkpoint(&checkpoint) => {
                Ok(StagingRecovery::Completed(receipt))
            }
            (Some(_), Some(_)) => Err(StagingError::InvalidMetadata),
        }
    }

    /// Stream exactly one admitted artifact to a caller-preopened inactive
    /// destination. `updates_entitled` must come from the current entitlement
    /// capability; `context.update_ring` carries the effective Fleet Hold.
    pub fn stage<R: Read>(
        &self,
        admitted: &AdmittedUpdate,
        context: &UpdateContext<'_>,
        updates_entitled: bool,
        source: &mut R,
        target: &mut PreopenedInactiveTarget,
    ) -> Result<StagingReceipt, StagingError> {
        authorize(admitted, context, updates_entitled)?;
        let expected = StagingCheckpoint::from_admitted(admitted, target);
        expected.validate()?;

        if let Some(receipt) = self.load_receipt()? {
            if receipt.matches_checkpoint(&expected) {
                return Ok(receipt);
            }
            return Err(StagingError::JournalConflict);
        }
        match self.load_checkpoint()? {
            Some(checkpoint) if checkpoint != expected => {
                return Err(StagingError::JournalConflict);
            }
            Some(_) => {}
            None => self.write_new_metadata(PENDING_FILE, &expected.export_canonical()?)?,
        }

        let staged = stage_exact_stream(source, target, &expected);
        if let Err(error) = staged {
            if target.cleanup_failed_write().is_err() {
                return Err(StagingError::CleanupFailed);
            }
            return Err(error);
        }

        let receipt = StagingReceipt::from_checkpoint(&expected);
        self.write_new_metadata(RECEIPT_FILE, &receipt.export_canonical()?)?;
        self.remove_metadata(PENDING_FILE)?;
        Ok(receipt)
    }

    /// Remove a completed receipt only after the caller has durably advanced
    /// its independent boot-planner state. Exact receipt matching is required.
    pub fn clear_completed(&self, expected: &StagingReceipt) -> Result<(), StagingError> {
        let retained = self.load_receipt()?.ok_or(StagingError::ReceiptMismatch)?;
        if &retained != expected {
            return Err(StagingError::ReceiptMismatch);
        }
        let pending = self.load_checkpoint()?;
        if let Some(checkpoint) = pending.as_ref() {
            if !expected.matches_checkpoint(checkpoint) {
                return Err(StagingError::InvalidMetadata);
            }
        }
        if pending.is_some() {
            self.remove_metadata(PENDING_FILE)?;
        }
        self.remove_metadata(RECEIPT_FILE)?;
        Ok(())
    }

    fn load_checkpoint(&self) -> Result<Option<StagingCheckpoint>, StagingError> {
        self.read_metadata(PENDING_FILE)?
            .map(|bytes| StagingCheckpoint::import_canonical(&bytes))
            .transpose()
    }

    fn load_receipt(&self) -> Result<Option<StagingReceipt>, StagingError> {
        self.read_metadata(RECEIPT_FILE)?
            .map(|bytes| StagingReceipt::import_canonical(&bytes))
            .transpose()
    }

    fn read_metadata(&self, name: &str) -> Result<Option<Vec<u8>>, StagingError> {
        let path = self.state_dir.join(name);
        match fs::symlink_metadata(&path) {
            Ok(metadata) => {
                inspect_metadata_file(&metadata)?;
                let bytes = fs::read(path)?;
                if bytes.is_empty() || bytes.len() > MAX_METADATA_BYTES {
                    return Err(StagingError::InvalidMetadata);
                }
                Ok(Some(bytes))
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(None),
            Err(error) => Err(error.into()),
        }
    }

    fn write_new_metadata(&self, name: &str, bytes: &[u8]) -> Result<(), StagingError> {
        if bytes.is_empty() || bytes.len() > MAX_METADATA_BYTES {
            return Err(StagingError::InvalidMetadata);
        }
        let target = self.state_dir.join(name);
        if fs::symlink_metadata(&target).is_ok() {
            return Err(StagingError::JournalConflict);
        }
        let temporary = self.state_dir.join(TEMP_FILE);
        let mut options = OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        options.mode(0o600);
        let mut file = options.open(&temporary)?;
        let result = (|| -> Result<(), StagingError> {
            file.write_all(bytes)?;
            file.flush()?;
            file.sync_all()?;
            fs::rename(&temporary, &target)?;
            sync_state_directory(&self.state_dir)?;
            Ok(())
        })();
        if result.is_err() {
            let _ = fs::remove_file(&temporary);
        }
        result
    }

    fn remove_metadata(&self, name: &str) -> Result<(), StagingError> {
        let path = self.state_dir.join(name);
        match fs::symlink_metadata(&path) {
            Ok(metadata) => {
                inspect_metadata_file(&metadata)?;
                fs::remove_file(path)?;
                sync_state_directory(&self.state_dir)
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
            Err(error) => Err(error.into()),
        }
    }

    fn cleanup_temporary_metadata(&self) -> Result<(), StagingError> {
        let path = self.state_dir.join(TEMP_FILE);
        match fs::symlink_metadata(&path) {
            Ok(metadata) => {
                inspect_metadata_file(&metadata)?;
                fs::remove_file(path)?;
                sync_state_directory(&self.state_dir)
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
            Err(error) => Err(error.into()),
        }
    }
}

/// Convert a durable staging receipt into the existing pure boot plan. Both
/// entitlement and effective ring are rechecked at this second boundary.
pub fn plan_staged_update(
    state: &UpdateState,
    admitted: &AdmittedUpdate,
    context: &UpdateContext<'_>,
    updates_entitled: bool,
    receipt: &StagingReceipt,
    max_boot_attempts: u8,
) -> Result<StagePlan, StagingError> {
    authorize(admitted, context, updates_entitled)?;
    receipt.validate_for(admitted, state.active_slot())?;
    Ok(state.plan_stage(admitted, context, receipt, max_boot_attempts)?)
}

#[derive(Debug)]
pub enum StagingError {
    ActiveSlotRejected,
    UnsupportedDestination,
    UpdatesNotEntitled,
    NotEligible(Availability),
    SourceTruncated,
    SourceHasTrailingBytes,
    ArtifactDigestMismatch,
    DestinationMismatch,
    JournalConflict,
    InvalidMetadata,
    ReceiptMismatch,
    CleanupFailed,
    Update(UpdateError),
    Io(io::Error),
}

impl fmt::Display for StagingError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::ActiveSlotRejected => "active update destination rejected",
            Self::UnsupportedDestination => "unsupported update staging destination",
            Self::UpdatesNotEntitled => "update staging is not entitled",
            Self::NotEligible(_) => "update staging is not eligible",
            Self::SourceTruncated => "update artifact is truncated",
            Self::SourceHasTrailingBytes => "update artifact has trailing bytes",
            Self::ArtifactDigestMismatch => "update artifact digest does not match",
            Self::DestinationMismatch => "staged update destination does not match",
            Self::JournalConflict => "update staging journal conflicts with this artifact",
            Self::InvalidMetadata => "update staging metadata is invalid",
            Self::ReceiptMismatch => "update staging receipt does not match",
            Self::CleanupFailed => "failed to clean an incomplete update artifact",
            Self::Update(_) => "update staging plan validation failed",
            Self::Io(_) => "update staging I/O failed",
        })
    }
}

impl Error for StagingError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Update(error) => Some(error),
            Self::Io(error) => Some(error),
            _ => None,
        }
    }
}

impl From<UpdateError> for StagingError {
    fn from(error: UpdateError) -> Self {
        Self::Update(error)
    }
}

impl From<io::Error> for StagingError {
    fn from(error: io::Error) -> Self {
        Self::Io(error)
    }
}

fn authorize(
    admitted: &AdmittedUpdate,
    context: &UpdateContext<'_>,
    updates_entitled: bool,
) -> Result<(), StagingError> {
    if !updates_entitled {
        return Err(StagingError::UpdatesNotEntitled);
    }
    let availability = admitted.verified().availability(context);
    if availability != Availability::Eligible {
        return Err(StagingError::NotEligible(availability));
    }
    Ok(())
}

fn stage_exact_stream<R: Read>(
    source: &mut R,
    target: &mut PreopenedInactiveTarget,
    checkpoint: &StagingCheckpoint,
) -> Result<(), StagingError> {
    target.prepare()?;
    let expected_digest = decode_sha256(&checkpoint.artifact_sha256)?;
    let mut hasher = Sha256::new();
    let mut remaining = checkpoint.artifact_size_bytes;
    let mut buffer = [0_u8; COPY_BUFFER_BYTES];
    while remaining != 0 {
        let wanted = usize::try_from(remaining.min(COPY_BUFFER_BYTES as u64))
            .map_err(|_| StagingError::SourceTruncated)?;
        let read = read_retry(source, &mut buffer[..wanted])?;
        if read == 0 {
            return Err(StagingError::SourceTruncated);
        }
        target.file.write_all(&buffer[..read])?;
        hasher.update(&buffer[..read]);
        remaining -= u64::try_from(read).map_err(|_| StagingError::SourceTruncated)?;
    }

    let mut trailing = [0_u8; 1];
    if read_retry(source, &mut trailing)? != 0 {
        return Err(StagingError::SourceHasTrailingBytes);
    }
    let actual_digest: [u8; 32] = hasher.finalize().into();
    if actual_digest != expected_digest {
        return Err(StagingError::ArtifactDigestMismatch);
    }
    target.file.flush()?;
    target.file.sync_all()?;
    if target.regular_file && target.file.metadata()?.len() != checkpoint.artifact_size_bytes {
        return Err(StagingError::DestinationMismatch);
    }
    target.file.seek(SeekFrom::Start(0))?;
    let mut destination_hasher = Sha256::new();
    let mut remaining = checkpoint.artifact_size_bytes;
    while remaining != 0 {
        let wanted = usize::try_from(remaining.min(COPY_BUFFER_BYTES as u64))
            .map_err(|_| StagingError::DestinationMismatch)?;
        let read = read_retry(&mut target.file, &mut buffer[..wanted])?;
        if read == 0 {
            return Err(StagingError::DestinationMismatch);
        }
        destination_hasher.update(&buffer[..read]);
        remaining -= u64::try_from(read).map_err(|_| StagingError::DestinationMismatch)?;
    }
    let destination_digest: [u8; 32] = destination_hasher.finalize().into();
    if destination_digest != expected_digest {
        return Err(StagingError::DestinationMismatch);
    }
    Ok(())
}

fn read_retry(reader: &mut impl Read, buffer: &mut [u8]) -> Result<usize, StagingError> {
    loop {
        match reader.read(buffer) {
            Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
            result => return result.map_err(Into::into),
        }
    }
}

fn validate_common(
    release_id: &str,
    sequence: u64,
    manifest_sha256: &str,
    artifact_size_bytes: u64,
    artifact_sha256: &str,
    active_slot: Slot,
    target_slot: Slot,
) -> Result<(), StagingError> {
    validate_identifier("staging.releaseId", release_id)?;
    if sequence == 0
        || sequence > MAX_SAFE_JSON_INTEGER
        || artifact_size_bytes == 0
        || artifact_size_bytes > MAX_ARTIFACT_BYTES
        || artifact_size_bytes > MAX_SAFE_JSON_INTEGER
    {
        return Err(StagingError::InvalidMetadata);
    }
    validate_sha256("staging.manifestSha256", manifest_sha256)?;
    validate_sha256("staging.artifactSha256", artifact_sha256)?;
    if target_slot != active_slot.inactive() {
        return Err(StagingError::ActiveSlotRejected);
    }
    Ok(())
}

fn prepare_private_state_dir(path: &Path) -> Result<(), StagingError> {
    match fs::symlink_metadata(path) {
        Ok(metadata) => inspect_state_dir(&metadata),
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            fs::create_dir(path)?;
            #[cfg(unix)]
            fs::set_permissions(path, fs::Permissions::from_mode(0o700))?;
            inspect_state_dir(&fs::symlink_metadata(path)?)
        }
        Err(error) => Err(error.into()),
    }
}

fn inspect_state_dir(metadata: &fs::Metadata) -> Result<(), StagingError> {
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err(StagingError::InvalidMetadata);
    }
    #[cfg(unix)]
    if metadata.permissions().mode() & 0o077 != 0 {
        return Err(StagingError::InvalidMetadata);
    }
    Ok(())
}

fn inspect_metadata_file(metadata: &fs::Metadata) -> Result<(), StagingError> {
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return Err(StagingError::InvalidMetadata);
    }
    #[cfg(unix)]
    if metadata.permissions().mode() & 0o077 != 0 {
        return Err(StagingError::InvalidMetadata);
    }
    Ok(())
}

#[cfg(unix)]
fn sync_state_directory(path: &Path) -> Result<(), StagingError> {
    File::open(path)?.sync_all()?;
    Ok(())
}

#[cfg(not(unix))]
fn sync_state_directory(_path: &Path) -> Result<(), StagingError> {
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        ArtifactDescriptor, ReleaseRing, Rollout, SignedUpdateManifest, UpdateArchitecture,
        UpdateManifestContent, UpdatePlatform, UpdateRing, admit_update,
    };
    use ed25519_dalek::SigningKey;
    use std::io::Cursor;
    use tempfile::tempdir;

    const DEVICE: &str = "KA-0123456789abcdef01234567";

    fn admitted_for(bytes: &[u8], sequence: u64) -> AdmittedUpdate {
        let digest: [u8; 32] = Sha256::digest(bytes).into();
        let content = UpdateManifestContent {
            sequence,
            release_id: format!("release-{sequence}"),
            release_version: format!("1.0.{sequence}"),
            platform: UpdatePlatform::Linux,
            architecture: UpdateArchitecture::X86_64,
            release_ring: ReleaseRing::Stable,
            rollout: Rollout {
                basis_points: 10_000,
                seed: "staging-tests".to_owned(),
            },
            issued_at_unix: 1_000,
            not_before_unix: 1_100,
            expires_at_unix: 3_000,
            artifact: ArtifactDescriptor {
                url: "https://updates.kernaid.example/artifact.raw".to_owned(),
                size_bytes: bytes.len() as u64,
                sha256: hex_sha256(&digest),
            },
            emergency_rollback: false,
        };
        let key = SigningKey::from_bytes(&[0x45; 32]);
        let verified = SignedUpdateManifest::sign(content, &key)
            .expect("sign update")
            .verify(&key.verifying_key())
            .expect("verify update");
        admit_update(None, verified).expect("admit update").update
    }

    fn context(ring: UpdateRing) -> UpdateContext<'static> {
        UpdateContext {
            device_id: DEVICE,
            platform: UpdatePlatform::Linux,
            architecture: UpdateArchitecture::X86_64,
            update_ring: ring,
            now_unix: 1_500,
        }
    }

    fn target(
        path: &Path,
        active: Slot,
        selected: Slot,
    ) -> Result<PreopenedInactiveTarget, StagingError> {
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(path)
            .expect("open preselected target");
        PreopenedInactiveTarget::new(file, active, selected)
    }

    #[test]
    fn stages_exact_stream_and_receipt_drives_existing_boot_plan() {
        let directory = tempdir().expect("temporary directory");
        let bytes = b"exact inactive slot artifact";
        let admitted = admitted_for(bytes, 1);
        let stager = ArtifactStager::open(&directory.path().join("state")).expect("open stager");
        let mut target =
            target(&directory.path().join("slot-b"), Slot::A, Slot::B).expect("inactive target");
        let receipt = stager
            .stage(
                &admitted,
                &context(UpdateRing::Stable),
                true,
                &mut Cursor::new(bytes),
                &mut target,
            )
            .expect("stage artifact");
        assert_eq!(receipt.target_slot(), Slot::B);
        assert_eq!(
            fs::read(directory.path().join("slot-b")).expect("read staged bytes"),
            bytes
        );
        assert_eq!(
            stager.recovery_status().expect("recovery status"),
            StagingRecovery::Completed(receipt.clone())
        );
        let plan = plan_staged_update(
            &UpdateState::new(Slot::A),
            &admitted,
            &context(UpdateRing::Stable),
            true,
            &receipt,
            3,
        )
        .expect("plan staged update");
        assert_eq!(plan.target_slot(), Slot::B);
    }

    #[test]
    fn truncated_and_trailing_sources_leave_no_regular_file_payload() {
        for (name, source, expected) in [
            (
                "truncated",
                b"exact inactive slot artifac".as_slice(),
                "truncated",
            ),
            (
                "trailing",
                b"exact inactive slot artifact!".as_slice(),
                "trailing",
            ),
        ] {
            let directory = tempdir().expect("temporary directory");
            let expected_bytes = b"exact inactive slot artifact";
            let admitted = admitted_for(expected_bytes, 1);
            let stager =
                ArtifactStager::open(&directory.path().join("state")).expect("open stager");
            let mut destination =
                target(&directory.path().join(name), Slot::A, Slot::B).expect("inactive target");
            let error = stager
                .stage(
                    &admitted,
                    &context(UpdateRing::Stable),
                    true,
                    &mut Cursor::new(source),
                    &mut destination,
                )
                .expect_err("reject malformed length");
            assert!(matches!(
                (expected, error),
                ("truncated", StagingError::SourceTruncated)
                    | ("trailing", StagingError::SourceHasTrailingBytes)
            ));
            assert_eq!(
                destination.file.metadata().expect("target metadata").len(),
                0
            );
            assert!(matches!(
                stager.recovery_status().expect("recovery status"),
                StagingRecovery::Interrupted(_)
            ));
        }
    }

    #[test]
    fn digest_mismatch_is_cleaned_and_never_receipted() {
        let directory = tempdir().expect("temporary directory");
        let expected = b"signed artifact";
        let admitted = admitted_for(expected, 1);
        let mut changed = expected.to_vec();
        changed[0] ^= 1;
        let stager = ArtifactStager::open(&directory.path().join("state")).expect("open stager");
        let mut destination =
            target(&directory.path().join("slot-b"), Slot::A, Slot::B).expect("inactive target");
        assert!(matches!(
            stager.stage(
                &admitted,
                &context(UpdateRing::Stable),
                true,
                &mut Cursor::new(changed),
                &mut destination,
            ),
            Err(StagingError::ArtifactDigestMismatch)
        ));
        assert_eq!(destination.file.metadata().expect("metadata").len(), 0);
        assert!(matches!(
            stager.recovery_status().expect("recovery status"),
            StagingRecovery::Interrupted(_)
        ));
    }

    #[test]
    fn active_slot_entitlement_and_policy_hold_are_rejected_at_boundary() {
        let directory = tempdir().expect("temporary directory");
        assert!(matches!(
            target(&directory.path().join("slot-a"), Slot::A, Slot::A),
            Err(StagingError::ActiveSlotRejected)
        ));

        let bytes = b"signed artifact";
        let admitted = admitted_for(bytes, 1);
        let stager = ArtifactStager::open(&directory.path().join("state")).expect("open stager");
        let mut destination =
            target(&directory.path().join("slot-b"), Slot::A, Slot::B).expect("inactive target");
        assert!(matches!(
            stager.stage(
                &admitted,
                &context(UpdateRing::Stable),
                false,
                &mut Cursor::new(bytes),
                &mut destination,
            ),
            Err(StagingError::UpdatesNotEntitled)
        ));
        assert!(matches!(
            stager.stage(
                &admitted,
                &context(UpdateRing::Hold),
                true,
                &mut Cursor::new(bytes),
                &mut destination,
            ),
            Err(StagingError::NotEligible(Availability::Held))
        ));
        assert_eq!(
            stager.recovery_status().expect("clean recovery"),
            StagingRecovery::Clean
        );
    }

    #[test]
    fn restart_detects_residue_and_only_exact_retry_can_complete() {
        let directory = tempdir().expect("temporary directory");
        let state_dir = directory.path().join("state");
        let destination_path = directory.path().join("slot-b");
        let bytes = b"signed artifact for restart";
        let admitted = admitted_for(bytes, 1);
        let stager = ArtifactStager::open(&state_dir).expect("open stager");
        let mut destination = target(&destination_path, Slot::A, Slot::B).expect("target");
        assert!(matches!(
            stager.stage(
                &admitted,
                &context(UpdateRing::Stable),
                true,
                &mut Cursor::new(&bytes[..bytes.len() - 1]),
                &mut destination,
            ),
            Err(StagingError::SourceTruncated)
        ));
        drop(stager);

        let reopened = ArtifactStager::open(&state_dir).expect("reopen stager");
        assert!(matches!(
            reopened.recovery_status().expect("residue status"),
            StagingRecovery::Interrupted(_)
        ));
        let different = admitted_for(b"different artifact", 2);
        assert!(matches!(
            reopened.stage(
                &different,
                &context(UpdateRing::Stable),
                true,
                &mut Cursor::new(b"different artifact"),
                &mut destination,
            ),
            Err(StagingError::JournalConflict)
        ));
        let receipt = reopened
            .stage(
                &admitted,
                &context(UpdateRing::Stable),
                true,
                &mut Cursor::new(bytes),
                &mut destination,
            )
            .expect("exact restart retry");
        drop(reopened);
        assert_eq!(
            ArtifactStager::open(&state_dir)
                .expect("second reopen")
                .recovery_status()
                .expect("completed status"),
            StagingRecovery::Completed(receipt)
        );
    }
}
