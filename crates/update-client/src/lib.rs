#![forbid(unsafe_code)]
//! Fail-closed verification, inactive-target staging, and A/B planning for
//! KernAid device updates.
//!
//! This crate performs no network access or bootloader changes. The optional
//! stager writes only to a caller-preopened inactive destination and fixed
//! metadata names under a caller-owned private state directory.

mod staging;

pub use staging::{
    ArtifactStager, PreopenedInactiveTarget, StagingCheckpoint, StagingError, StagingReceipt,
    StagingRecovery, plan_staged_update,
};

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::fmt;
use url::Url;
use zeroize::Zeroizing;

pub const UPDATE_MANIFEST_SCHEMA: &str = "dev.kernaid.update.manifest.v1";
pub const UPDATE_CHECKPOINT_SCHEMA: &str = "dev.kernaid.update.checkpoint.v1";
pub const UPDATE_STATE_SCHEMA: &str = "dev.kernaid.update.state.v1";
pub const UPDATE_SIGNATURE_DOMAIN: &[u8] = b"kernaid:update:manifest:v1\0";
pub const MAX_SAFE_JSON_INTEGER: u64 = 9_007_199_254_740_991;
pub const MAX_BOOT_ATTEMPTS: u8 = 5;

const SIGNATURE_BYTES: usize = 64;
const SHA256_BYTES: usize = 32;
const MAX_MANIFEST_BYTES: usize = 64 * 1024;
const MAX_CHECKPOINT_BYTES: usize = 4 * 1024;
const MAX_STATE_BYTES: usize = 16 * 1024;
const MAX_ID_BYTES: usize = 160;
const MAX_VERSION_BYTES: usize = 128;
const MAX_URL_BYTES: usize = 4 * 1024;
const MAX_ARTIFACT_BYTES: u64 = 1_099_511_627_776; // 1 TiB
const ROLLOUT_BASIS_POINTS: u16 = 10_000;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum UpdatePlatform {
    Rescue,
    Windows,
    Linux,
    Macos,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum UpdateArchitecture {
    X86_64,
    Aarch64,
}

/// Ring attached to a release by the signer.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ReleaseRing {
    Canary,
    Stable,
}

/// Locally effective device ring, normally obtained by intersecting local and
/// Fleet policy. `Hold` blocks ordinary releases, never local rollback.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum UpdateRing {
    Hold,
    Canary,
    Stable,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ArtifactDescriptor {
    pub url: String,
    pub size_bytes: u64,
    pub sha256: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Rollout {
    /// 0 disables the cohort and 10,000 includes every device.
    pub basis_points: u16,
    pub seed: String,
}

/// Unsigned values supplied to the release signer.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UpdateManifestContent {
    pub sequence: u64,
    pub release_id: String,
    pub release_version: String,
    pub platform: UpdatePlatform,
    pub architecture: UpdateArchitecture,
    pub release_ring: ReleaseRing,
    pub rollout: Rollout,
    pub issued_at_unix: u64,
    pub not_before_unix: u64,
    pub expires_at_unix: u64,
    pub artifact: ArtifactDescriptor,
    /// A higher-sequence, signed release intended to restore an older payload.
    /// It never bypasses signature, sequence, target, or time validation.
    pub emergency_rollback: bool,
}

/// Signed wire manifest. The Ed25519 public key is intentionally absent: the
/// verifier accepts only a trust anchor provisioned outside this document.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SignedUpdateManifest {
    schema: String,
    sequence: u64,
    release_id: String,
    release_version: String,
    platform: UpdatePlatform,
    architecture: UpdateArchitecture,
    release_ring: ReleaseRing,
    rollout: Rollout,
    issued_at_unix: u64,
    not_before_unix: u64,
    expires_at_unix: u64,
    artifact: ArtifactDescriptor,
    emergency_rollback: bool,
    signature: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct UnsignedUpdateManifest<'a> {
    schema: &'a str,
    sequence: u64,
    release_id: &'a str,
    release_version: &'a str,
    platform: UpdatePlatform,
    architecture: UpdateArchitecture,
    release_ring: ReleaseRing,
    rollout: &'a Rollout,
    issued_at_unix: u64,
    not_before_unix: u64,
    expires_at_unix: u64,
    artifact: &'a ArtifactDescriptor,
    emergency_rollback: bool,
}

impl SignedUpdateManifest {
    /// Central-signing helper. Device code normally calls
    /// [`Self::import_and_verify`] instead.
    pub fn sign(
        content: UpdateManifestContent,
        signing_key: &SigningKey,
    ) -> Result<Self, UpdateError> {
        let mut manifest = Self {
            schema: UPDATE_MANIFEST_SCHEMA.to_owned(),
            sequence: content.sequence,
            release_id: content.release_id,
            release_version: content.release_version,
            platform: content.platform,
            architecture: content.architecture,
            release_ring: content.release_ring,
            rollout: content.rollout,
            issued_at_unix: content.issued_at_unix,
            not_before_unix: content.not_before_unix,
            expires_at_unix: content.expires_at_unix,
            artifact: content.artifact,
            emergency_rollback: content.emergency_rollback,
            signature: String::new(),
        };
        manifest.validate_unsigned()?;
        let canonical = Zeroizing::new(manifest.unsigned_canonical()?);
        let message = signature_message(canonical.as_slice())?;
        manifest.signature = URL_SAFE_NO_PAD.encode(signing_key.sign(&message).to_bytes());
        manifest.validate()?;
        Ok(manifest)
    }

    pub fn verify(&self, trust_anchor: &VerifyingKey) -> Result<VerifiedUpdate, UpdateError> {
        self.validate()?;
        let signature = decode_signature(&self.signature)?;
        let canonical = Zeroizing::new(self.unsigned_canonical()?);
        let message = signature_message(canonical.as_slice())?;
        trust_anchor
            .verify_strict(&message, &Signature::from_bytes(&signature))
            .map_err(|_| UpdateError::InvalidSignature)?;
        let exact = self.export_canonical()?;
        let digest = Sha256::digest(&exact).into();
        Ok(VerifiedUpdate {
            manifest: self.clone(),
            manifest_sha256: digest,
        })
    }

    pub fn export_canonical(&self) -> Result<Vec<u8>, UpdateError> {
        self.validate()?;
        let bytes = canonical_json(self)?;
        validate_size(bytes.len(), MAX_MANIFEST_BYTES)?;
        Ok(bytes)
    }

    pub fn import_and_verify(
        bytes: &[u8],
        trust_anchor: &VerifyingKey,
    ) -> Result<VerifiedUpdate, UpdateError> {
        let manifest: Self = import_canonical(bytes, MAX_MANIFEST_BYTES)?;
        manifest.verify(trust_anchor)
    }

    fn unsigned(&self) -> UnsignedUpdateManifest<'_> {
        UnsignedUpdateManifest {
            schema: &self.schema,
            sequence: self.sequence,
            release_id: &self.release_id,
            release_version: &self.release_version,
            platform: self.platform,
            architecture: self.architecture,
            release_ring: self.release_ring,
            rollout: &self.rollout,
            issued_at_unix: self.issued_at_unix,
            not_before_unix: self.not_before_unix,
            expires_at_unix: self.expires_at_unix,
            artifact: &self.artifact,
            emergency_rollback: self.emergency_rollback,
        }
    }

    fn unsigned_canonical(&self) -> Result<Vec<u8>, UpdateError> {
        canonical_json(&self.unsigned())
    }

    fn validate(&self) -> Result<(), UpdateError> {
        self.validate_unsigned()?;
        decode_signature(&self.signature)?;
        Ok(())
    }

    fn validate_unsigned(&self) -> Result<(), UpdateError> {
        if self.schema != UPDATE_MANIFEST_SCHEMA {
            return Err(UpdateError::InvalidField("schema"));
        }
        validate_safe_nonzero("sequence", self.sequence)?;
        validate_identifier("releaseId", &self.release_id)?;
        validate_version(&self.release_version)?;
        validate_safe_nonzero("issuedAtUnix", self.issued_at_unix)?;
        validate_safe_nonzero("notBeforeUnix", self.not_before_unix)?;
        validate_safe_nonzero("expiresAtUnix", self.expires_at_unix)?;
        if self.issued_at_unix > self.not_before_unix
            || self.not_before_unix >= self.expires_at_unix
        {
            return Err(UpdateError::InvalidTimeWindow);
        }
        if self.rollout.basis_points > ROLLOUT_BASIS_POINTS {
            return Err(UpdateError::InvalidField("rollout.basisPoints"));
        }
        validate_identifier("rollout.seed", &self.rollout.seed)?;
        validate_artifact(&self.artifact)
    }
}

impl fmt::Debug for SignedUpdateManifest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SignedUpdateManifest")
            .field("sequence", &self.sequence)
            .field("release_id", &self.release_id)
            .field("platform", &self.platform)
            .field("architecture", &self.architecture)
            .finish_non_exhaustive()
    }
}

/// Authentic manifest, not yet admitted by the durable sequence checkpoint.
#[derive(Clone, PartialEq, Eq)]
pub struct VerifiedUpdate {
    manifest: SignedUpdateManifest,
    manifest_sha256: [u8; SHA256_BYTES],
}

impl VerifiedUpdate {
    #[must_use]
    pub const fn sequence(&self) -> u64 {
        self.manifest.sequence
    }

    #[must_use]
    pub fn release_id(&self) -> &str {
        &self.manifest.release_id
    }

    #[must_use]
    pub fn artifact(&self) -> &ArtifactDescriptor {
        &self.manifest.artifact
    }

    #[must_use]
    pub const fn emergency_rollback(&self) -> bool {
        self.manifest.emergency_rollback
    }

    #[must_use]
    pub const fn manifest_sha256(&self) -> &[u8; SHA256_BYTES] {
        &self.manifest_sha256
    }

    /// Evaluate only local eligibility. Authenticity and sequence admission are
    /// separate mandatory gates. Emergency rollback bypasses ring and rollout,
    /// but never the time window or target platform/architecture.
    #[must_use]
    pub fn availability(&self, context: &UpdateContext<'_>) -> Availability {
        if context.now_unix == 0
            || context.now_unix > MAX_SAFE_JSON_INTEGER
            || validate_device_id(context.device_id).is_err()
        {
            return Availability::InvalidContext;
        }
        if context.platform != self.manifest.platform {
            return Availability::PlatformMismatch;
        }
        if context.architecture != self.manifest.architecture {
            return Availability::ArchitectureMismatch;
        }
        if context.now_unix < self.manifest.not_before_unix {
            return Availability::NotYetValid;
        }
        if context.now_unix >= self.manifest.expires_at_unix {
            return Availability::Expired;
        }
        if self.manifest.emergency_rollback {
            return Availability::Eligible;
        }
        if context.update_ring == UpdateRing::Hold {
            return Availability::Held;
        }
        if self.manifest.release_ring == ReleaseRing::Canary
            && context.update_ring != UpdateRing::Canary
        {
            return Availability::RingMismatch;
        }
        if !in_rollout(
            context.device_id,
            &self.manifest.rollout.seed,
            self.manifest.rollout.basis_points,
        ) {
            return Availability::RolloutDeferred;
        }
        Availability::Eligible
    }
}

impl fmt::Debug for VerifiedUpdate {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("VerifiedUpdate")
            .field("sequence", &self.sequence())
            .field("release_id", &self.release_id())
            .finish_non_exhaustive()
    }
}

pub struct UpdateContext<'a> {
    pub device_id: &'a str,
    pub platform: UpdatePlatform,
    pub architecture: UpdateArchitecture,
    pub update_ring: UpdateRing,
    pub now_unix: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Availability {
    Eligible,
    InvalidContext,
    PlatformMismatch,
    ArchitectureMismatch,
    NotYetValid,
    Expired,
    Held,
    RingMismatch,
    RolloutDeferred,
}

/// Durable exact-replay and anti-rollback state for one update stream.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct UpdateCheckpoint {
    schema: String,
    sequence: u64,
    release_id: String,
    manifest_sha256: String,
}

impl UpdateCheckpoint {
    pub fn export_canonical(&self) -> Result<Vec<u8>, UpdateError> {
        self.validate()?;
        let bytes = canonical_json(self)?;
        validate_size(bytes.len(), MAX_CHECKPOINT_BYTES)?;
        Ok(bytes)
    }

    pub fn import_canonical(bytes: &[u8]) -> Result<Self, UpdateError> {
        let checkpoint: Self = import_canonical(bytes, MAX_CHECKPOINT_BYTES)?;
        checkpoint.validate()?;
        Ok(checkpoint)
    }

    #[must_use]
    pub const fn sequence(&self) -> u64 {
        self.sequence
    }

    fn from_verified(update: &VerifiedUpdate) -> Self {
        Self {
            schema: UPDATE_CHECKPOINT_SCHEMA.to_owned(),
            sequence: update.sequence(),
            release_id: update.release_id().to_owned(),
            manifest_sha256: hex_sha256(update.manifest_sha256()),
        }
    }

    fn validate(&self) -> Result<(), UpdateError> {
        if self.schema != UPDATE_CHECKPOINT_SCHEMA {
            return Err(UpdateError::InvalidField("checkpoint.schema"));
        }
        validate_safe_nonzero("checkpoint.sequence", self.sequence)?;
        validate_identifier("checkpoint.releaseId", &self.release_id)?;
        validate_sha256("checkpoint.manifestSha256", &self.manifest_sha256)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CheckpointAdmission {
    First,
    Advanced,
    IdempotentReplay,
}

/// Typestate proving that a verified manifest passed the monotonic checkpoint.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AdmittedUpdate {
    verified: VerifiedUpdate,
    admission: CheckpointAdmission,
}

impl AdmittedUpdate {
    #[must_use]
    pub const fn admission(&self) -> CheckpointAdmission {
        self.admission
    }

    #[must_use]
    pub const fn verified(&self) -> &VerifiedUpdate {
        &self.verified
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AdmissionOutcome {
    pub update: AdmittedUpdate,
    pub next_checkpoint: UpdateCheckpoint,
}

/// Pure admission: persist `next_checkpoint` atomically before executing a
/// stage plan. A same-sequence replay is accepted only for byte-identical
/// signed content. Emergency releases cannot bypass this gate.
pub fn admit_update(
    checkpoint: Option<&UpdateCheckpoint>,
    verified: VerifiedUpdate,
) -> Result<AdmissionOutcome, UpdateError> {
    if let Some(existing) = checkpoint {
        existing.validate()?;
        if verified.sequence() < existing.sequence {
            return Err(UpdateError::SequenceRollback);
        }
        if verified.sequence() == existing.sequence {
            if hex_sha256(verified.manifest_sha256()) != existing.manifest_sha256 {
                return Err(UpdateError::SequenceConflict);
            }
            return Ok(AdmissionOutcome {
                update: AdmittedUpdate {
                    verified,
                    admission: CheckpointAdmission::IdempotentReplay,
                },
                next_checkpoint: existing.clone(),
            });
        }
        let next_checkpoint = UpdateCheckpoint::from_verified(&verified);
        return Ok(AdmissionOutcome {
            update: AdmittedUpdate {
                verified,
                admission: CheckpointAdmission::Advanced,
            },
            next_checkpoint,
        });
    }

    let next_checkpoint = UpdateCheckpoint::from_verified(&verified);
    Ok(AdmissionOutcome {
        update: AdmittedUpdate {
            verified,
            admission: CheckpointAdmission::First,
        },
        next_checkpoint,
    })
}

/// Evidence produced by a caller only after hashing the entire downloaded
/// artifact. It conveys facts; this crate neither downloads nor opens it.
pub trait CompletedArtifactEvidence {
    fn complete_size_bytes(&self) -> u64;
    fn complete_sha256(&self) -> [u8; SHA256_BYTES];
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CompletedArtifact {
    size_bytes: u64,
    sha256: [u8; SHA256_BYTES],
}

impl CompletedArtifact {
    #[must_use]
    pub const fn new(size_bytes: u64, sha256: [u8; SHA256_BYTES]) -> Self {
        Self { size_bytes, sha256 }
    }
}

impl CompletedArtifactEvidence for CompletedArtifact {
    fn complete_size_bytes(&self) -> u64 {
        self.size_bytes
    }

    fn complete_sha256(&self) -> [u8; SHA256_BYTES] {
        self.sha256
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum Slot {
    A,
    B,
}

impl Slot {
    #[must_use]
    pub const fn inactive(self) -> Self {
        match self {
            Self::A => Self::B,
            Self::B => Self::A,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum UpdatePhase {
    Stable,
    Staged,
    PendingBoot,
    RollbackPending,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct PendingUpdate {
    release_id: String,
    sequence: u64,
    manifest_sha256: String,
    artifact_sha256: String,
    target_slot: Slot,
    previous_slot: Slot,
    attempts_remaining: u8,
    max_attempts: u8,
    emergency_rollback: bool,
}

/// Persistable pure state. No field can disable diagnostics or rollback.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct UpdateState {
    schema: String,
    phase: UpdatePhase,
    active_slot: Slot,
    rollback_slot: Slot,
    pending: Option<PendingUpdate>,
}

impl UpdateState {
    #[must_use]
    pub fn new(active_slot: Slot) -> Self {
        Self {
            schema: UPDATE_STATE_SCHEMA.to_owned(),
            phase: UpdatePhase::Stable,
            active_slot,
            rollback_slot: active_slot.inactive(),
            pending: None,
        }
    }

    #[must_use]
    pub const fn phase(&self) -> UpdatePhase {
        self.phase
    }

    #[must_use]
    pub const fn active_slot(&self) -> Slot {
        self.active_slot
    }

    #[must_use]
    pub const fn rollback_slot(&self) -> Slot {
        self.rollback_slot
    }

    /// Hard product invariant, independent of manifest, ring, or state.
    #[must_use]
    pub const fn safety_capabilities(&self) -> SafetyCapabilities {
        SafetyCapabilities {
            diagnostics_available: true,
            rollback_available: true,
        }
    }

    pub fn export_canonical(&self) -> Result<Vec<u8>, UpdateError> {
        self.validate()?;
        let bytes = canonical_json(self)?;
        validate_size(bytes.len(), MAX_STATE_BYTES)?;
        Ok(bytes)
    }

    pub fn import_canonical(bytes: &[u8]) -> Result<Self, UpdateError> {
        let state: Self = import_canonical(bytes, MAX_STATE_BYTES)?;
        state.validate()?;
        Ok(state)
    }

    /// Produce a plan only from an admitted update, eligible local context, and
    /// a complete size+SHA-256 match. The target is always the inactive slot.
    pub fn plan_stage<E: CompletedArtifactEvidence>(
        &self,
        admitted: &AdmittedUpdate,
        context: &UpdateContext<'_>,
        evidence: &E,
        max_boot_attempts: u8,
    ) -> Result<StagePlan, UpdateError> {
        self.validate()?;
        if self.phase != UpdatePhase::Stable || self.pending.is_some() {
            return Err(UpdateError::InvalidTransition);
        }
        let availability = admitted.verified().availability(context);
        if availability != Availability::Eligible {
            return Err(UpdateError::NotEligible(availability));
        }
        if !(1..=MAX_BOOT_ATTEMPTS).contains(&max_boot_attempts) {
            return Err(UpdateError::InvalidBootAttempts);
        }
        let artifact = admitted.verified().artifact();
        let expected_sha256 = decode_sha256(&artifact.sha256)?;
        if evidence.complete_size_bytes() != artifact.size_bytes
            || evidence.complete_sha256() != expected_sha256
        {
            return Err(UpdateError::ArtifactMismatch);
        }
        let target_slot = self.active_slot.inactive();
        Ok(StagePlan {
            pending: PendingUpdate {
                release_id: admitted.verified().release_id().to_owned(),
                sequence: admitted.verified().sequence(),
                manifest_sha256: hex_sha256(admitted.verified().manifest_sha256()),
                artifact_sha256: artifact.sha256.clone(),
                target_slot,
                previous_slot: self.active_slot,
                attempts_remaining: max_boot_attempts,
                max_attempts: max_boot_attempts,
                emergency_rollback: admitted.verified().emergency_rollback(),
            },
        })
    }

    /// Caller invokes this only after its platform layer staged and re-hashed
    /// the target slot according to the plan.
    pub fn confirm_staged(&self, plan: &StagePlan) -> Result<Self, UpdateError> {
        self.validate()?;
        if self.phase != UpdatePhase::Stable
            || plan.pending.previous_slot != self.active_slot
            || plan.pending.target_slot != self.active_slot.inactive()
        {
            return Err(UpdateError::InvalidTransition);
        }
        let mut next = self.clone();
        next.phase = UpdatePhase::Staged;
        next.pending = Some(plan.pending.clone());
        next.validate()?;
        Ok(next)
    }

    pub fn arm_pending_boot(&self) -> Result<Self, UpdateError> {
        self.validate()?;
        if self.phase != UpdatePhase::Staged {
            return Err(UpdateError::InvalidTransition);
        }
        let mut next = self.clone();
        next.phase = UpdatePhase::PendingBoot;
        next.validate()?;
        Ok(next)
    }

    /// Persist `state` before asking the platform integration to enact `action`.
    /// Attempts are consumed before boot, so a power loss cannot reset the bound.
    pub fn next_boot(&self) -> Result<BootTransition, UpdateError> {
        self.validate()?;
        match self.phase {
            UpdatePhase::Stable => Ok(BootTransition {
                state: self.clone(),
                action: BootAction::BootStable {
                    slot: self.active_slot,
                },
            }),
            UpdatePhase::Staged => Err(UpdateError::InvalidTransition),
            UpdatePhase::RollbackPending => {
                let pending = self.pending.as_ref().ok_or(UpdateError::InvalidState)?;
                Ok(BootTransition {
                    state: self.clone(),
                    action: BootAction::Rollback {
                        slot: pending.previous_slot,
                        failed_slot: pending.target_slot,
                    },
                })
            }
            UpdatePhase::PendingBoot => {
                let pending = self.pending.as_ref().ok_or(UpdateError::InvalidState)?;
                if pending.attempts_remaining == 0 {
                    let mut state = self.clone();
                    state.phase = UpdatePhase::RollbackPending;
                    state.validate()?;
                    return Ok(BootTransition {
                        state,
                        action: BootAction::Rollback {
                            slot: pending.previous_slot,
                            failed_slot: pending.target_slot,
                        },
                    });
                }
                let mut state = self.clone();
                let next_pending = state.pending.as_mut().ok_or(UpdateError::InvalidState)?;
                next_pending.attempts_remaining -= 1;
                state.validate()?;
                Ok(BootTransition {
                    state,
                    action: BootAction::TryPending {
                        slot: pending.target_slot,
                        rollback_slot: pending.previous_slot,
                    },
                })
            }
        }
    }

    pub fn mark_good(&self, running_slot: Slot) -> Result<Self, UpdateError> {
        self.validate()?;
        if self.phase != UpdatePhase::PendingBoot {
            return Err(UpdateError::InvalidTransition);
        }
        let pending = self.pending.as_ref().ok_or(UpdateError::InvalidState)?;
        if running_slot != pending.target_slot {
            return Err(UpdateError::WrongRunningSlot);
        }
        let mut next = Self::new(running_slot);
        next.rollback_slot = pending.previous_slot;
        next.validate()?;
        Ok(next)
    }

    /// An explicit health failure immediately prefers the known-good slot;
    /// bounded attempts cover hangs or boots that never call `mark_good`.
    pub fn record_failure(&self) -> Result<Self, UpdateError> {
        self.validate()?;
        if self.phase != UpdatePhase::PendingBoot {
            return Err(UpdateError::InvalidTransition);
        }
        let mut next = self.clone();
        next.phase = UpdatePhase::RollbackPending;
        next.validate()?;
        Ok(next)
    }

    pub fn confirm_rollback(&self, running_slot: Slot) -> Result<Self, UpdateError> {
        self.validate()?;
        if self.phase != UpdatePhase::RollbackPending {
            return Err(UpdateError::InvalidTransition);
        }
        let pending = self.pending.as_ref().ok_or(UpdateError::InvalidState)?;
        if running_slot != pending.previous_slot {
            return Err(UpdateError::WrongRunningSlot);
        }
        let mut next = Self::new(running_slot);
        next.rollback_slot = pending.target_slot;
        next.validate()?;
        Ok(next)
    }

    /// Local rollback is always available and requires no entitlement, Fleet
    /// connection, update manifest, or update-ring permission.
    pub fn plan_local_rollback(&self) -> Result<LocalRollbackPlan, UpdateError> {
        self.validate()?;
        if self.phase == UpdatePhase::Stable {
            return Ok(LocalRollbackPlan {
                slot: self.rollback_slot,
                previous_slot: self.active_slot,
            });
        }
        let pending = self.pending.as_ref().ok_or(UpdateError::InvalidState)?;
        Ok(LocalRollbackPlan {
            slot: pending.previous_slot,
            previous_slot: pending.target_slot,
        })
    }

    pub fn confirm_local_rollback(
        &self,
        plan: LocalRollbackPlan,
        running_slot: Slot,
    ) -> Result<Self, UpdateError> {
        self.validate()?;
        let valid_plan = if self.phase == UpdatePhase::Stable {
            plan.slot == self.rollback_slot && plan.previous_slot == self.active_slot
        } else {
            let pending = self.pending.as_ref().ok_or(UpdateError::InvalidState)?;
            plan.slot == pending.previous_slot && plan.previous_slot == pending.target_slot
        };
        if !valid_plan || running_slot != plan.slot {
            return Err(UpdateError::InvalidTransition);
        }
        let mut next = Self::new(running_slot);
        next.rollback_slot = plan.previous_slot;
        next.validate()?;
        Ok(next)
    }

    fn validate(&self) -> Result<(), UpdateError> {
        if self.schema != UPDATE_STATE_SCHEMA || self.active_slot == self.rollback_slot {
            return Err(UpdateError::InvalidState);
        }
        match (&self.phase, &self.pending) {
            (UpdatePhase::Stable, None) => Ok(()),
            (UpdatePhase::Stable, Some(_)) | (_, None) => Err(UpdateError::InvalidState),
            (_, Some(pending)) => {
                validate_identifier("state.pending.releaseId", &pending.release_id)?;
                validate_safe_nonzero("state.pending.sequence", pending.sequence)?;
                validate_sha256("state.pending.manifestSha256", &pending.manifest_sha256)?;
                validate_sha256("state.pending.artifactSha256", &pending.artifact_sha256)?;
                if pending.previous_slot != self.active_slot
                    || pending.target_slot != self.active_slot.inactive()
                    || pending.max_attempts == 0
                    || pending.max_attempts > MAX_BOOT_ATTEMPTS
                    || pending.attempts_remaining > pending.max_attempts
                {
                    return Err(UpdateError::InvalidState);
                }
                Ok(())
            }
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SafetyCapabilities {
    pub diagnostics_available: bool,
    pub rollback_available: bool,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StagePlan {
    pending: PendingUpdate,
}

impl StagePlan {
    #[must_use]
    pub const fn target_slot(&self) -> Slot {
        self.pending.target_slot
    }

    #[must_use]
    pub const fn rollback_slot(&self) -> Slot {
        self.pending.previous_slot
    }

    #[must_use]
    pub fn artifact_sha256(&self) -> &str {
        &self.pending.artifact_sha256
    }

    #[must_use]
    pub const fn safety_capabilities(&self) -> SafetyCapabilities {
        SafetyCapabilities {
            diagnostics_available: true,
            rollback_available: true,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BootAction {
    BootStable { slot: Slot },
    TryPending { slot: Slot, rollback_slot: Slot },
    Rollback { slot: Slot, failed_slot: Slot },
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BootTransition {
    pub state: UpdateState,
    pub action: BootAction,
}

impl BootTransition {
    #[must_use]
    pub const fn safety_capabilities(&self) -> SafetyCapabilities {
        SafetyCapabilities {
            diagnostics_available: true,
            rollback_available: true,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct LocalRollbackPlan {
    slot: Slot,
    previous_slot: Slot,
}

impl LocalRollbackPlan {
    #[must_use]
    pub const fn target_slot(self) -> Slot {
        self.slot
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum UpdateError {
    InvalidField(&'static str),
    InvalidTimeWindow,
    InvalidJson,
    UnsupportedJsonValue,
    UnsafeInteger,
    NonCanonicalJson,
    DocumentTooLarge,
    InvalidSignature,
    SequenceRollback,
    SequenceConflict,
    NotEligible(Availability),
    ArtifactMismatch,
    InvalidBootAttempts,
    InvalidTransition,
    WrongRunningSlot,
    InvalidState,
}

impl fmt::Display for UpdateError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidField(field) => write!(formatter, "invalid update field: {field}"),
            Self::InvalidTimeWindow => formatter.write_str("invalid update time window"),
            Self::InvalidJson => formatter.write_str("invalid update JSON"),
            Self::UnsupportedJsonValue => formatter.write_str("unsupported update JSON value"),
            Self::UnsafeInteger => formatter.write_str("unsafe update JSON integer"),
            Self::NonCanonicalJson => formatter.write_str("update JSON is not canonical"),
            Self::DocumentTooLarge => formatter.write_str("update document is too large"),
            Self::InvalidSignature => formatter.write_str("invalid update signature"),
            Self::SequenceRollback => formatter.write_str("update sequence rollback"),
            Self::SequenceConflict => formatter.write_str("conflicting update sequence"),
            Self::NotEligible(reason) => write!(formatter, "update is not eligible: {reason:?}"),
            Self::ArtifactMismatch => formatter.write_str("completed artifact does not match"),
            Self::InvalidBootAttempts => formatter.write_str("invalid update boot-attempt bound"),
            Self::InvalidTransition => formatter.write_str("invalid update state transition"),
            Self::WrongRunningSlot => formatter.write_str("unexpected running A/B slot"),
            Self::InvalidState => formatter.write_str("invalid persisted update state"),
        }
    }
}

impl std::error::Error for UpdateError {}

fn validate_artifact(artifact: &ArtifactDescriptor) -> Result<(), UpdateError> {
    if artifact.size_bytes == 0
        || artifact.size_bytes > MAX_ARTIFACT_BYTES
        || artifact.size_bytes > MAX_SAFE_JSON_INTEGER
    {
        return Err(UpdateError::InvalidField("artifact.sizeBytes"));
    }
    validate_sha256("artifact.sha256", &artifact.sha256)?;
    if artifact.url.is_empty() || artifact.url.len() > MAX_URL_BYTES {
        return Err(UpdateError::InvalidField("artifact.url"));
    }
    let parsed =
        Url::parse(&artifact.url).map_err(|_| UpdateError::InvalidField("artifact.url"))?;
    if parsed.scheme() != "https"
        || parsed.host_str().is_none()
        || !parsed.username().is_empty()
        || parsed.password().is_some()
        || parsed.fragment().is_some()
    {
        return Err(UpdateError::InvalidField("artifact.url"));
    }
    Ok(())
}

fn validate_identifier(field: &'static str, value: &str) -> Result<(), UpdateError> {
    if value.is_empty()
        || value.len() > MAX_ID_BYTES
        || !value.bytes().all(|byte| {
            byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b':' | b'/')
        })
    {
        return Err(UpdateError::InvalidField(field));
    }
    Ok(())
}

fn validate_version(value: &str) -> Result<(), UpdateError> {
    if value.is_empty()
        || value.len() > MAX_VERSION_BYTES
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_graphic() && byte != b'"' && byte != b'\\')
    {
        return Err(UpdateError::InvalidField("releaseVersion"));
    }
    Ok(())
}

fn validate_device_id(value: &str) -> Result<(), UpdateError> {
    let Some(suffix) = value.strip_prefix("KA-") else {
        return Err(UpdateError::InvalidField("deviceId"));
    };
    if suffix.len() != 24
        || !suffix
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(UpdateError::InvalidField("deviceId"));
    }
    Ok(())
}

fn validate_safe_nonzero(field: &'static str, value: u64) -> Result<(), UpdateError> {
    if value == 0 || value > MAX_SAFE_JSON_INTEGER {
        return Err(UpdateError::InvalidField(field));
    }
    Ok(())
}

fn validate_sha256(field: &'static str, value: &str) -> Result<(), UpdateError> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(UpdateError::InvalidField(field));
    }
    Ok(())
}

fn decode_sha256(value: &str) -> Result<[u8; SHA256_BYTES], UpdateError> {
    validate_sha256("sha256", value)?;
    let mut output = [0_u8; SHA256_BYTES];
    for (index, pair) in value.as_bytes().chunks_exact(2).enumerate() {
        let high = hex_nibble(pair[0]).ok_or(UpdateError::InvalidField("sha256"))?;
        let low = hex_nibble(pair[1]).ok_or(UpdateError::InvalidField("sha256"))?;
        output[index] = (high << 4) | low;
    }
    Ok(output)
}

const fn hex_nibble(value: u8) -> Option<u8> {
    match value {
        b'0'..=b'9' => Some(value - b'0'),
        b'a'..=b'f' => Some(value - b'a' + 10),
        _ => None,
    }
}

fn decode_signature(encoded: &str) -> Result<[u8; SIGNATURE_BYTES], UpdateError> {
    if encoded.contains('=') || encoded.len() != 86 {
        return Err(UpdateError::InvalidField("signature"));
    }
    let decoded = URL_SAFE_NO_PAD
        .decode(encoded)
        .map_err(|_| UpdateError::InvalidField("signature"))?;
    if decoded.len() != SIGNATURE_BYTES || URL_SAFE_NO_PAD.encode(&decoded) != encoded {
        return Err(UpdateError::InvalidField("signature"));
    }
    decoded
        .as_slice()
        .try_into()
        .map_err(|_| UpdateError::InvalidField("signature"))
}

fn signature_message(payload: &[u8]) -> Result<Zeroizing<Vec<u8>>, UpdateError> {
    let capacity = UPDATE_SIGNATURE_DOMAIN
        .len()
        .checked_add(payload.len())
        .ok_or(UpdateError::DocumentTooLarge)?;
    let mut message = Zeroizing::new(Vec::with_capacity(capacity));
    message.extend_from_slice(UPDATE_SIGNATURE_DOMAIN);
    message.extend_from_slice(payload);
    Ok(message)
}

fn in_rollout(device_id: &str, seed: &str, basis_points: u16) -> bool {
    if basis_points == 0 {
        return false;
    }
    if basis_points == ROLLOUT_BASIS_POINTS {
        return true;
    }
    let mut hasher = Sha256::new();
    hasher.update(b"kernaid:update:rollout:v1\0");
    hasher.update(seed.as_bytes());
    hasher.update([0]);
    hasher.update(device_id.as_bytes());
    let digest = hasher.finalize();
    let cohort = u16::from_be_bytes([digest[0], digest[1]]) % ROLLOUT_BASIS_POINTS;
    cohort < basis_points
}

fn hex_sha256(digest: &[u8; SHA256_BYTES]) -> String {
    digest.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn validate_size(actual: usize, maximum: usize) -> Result<(), UpdateError> {
    if actual == 0 || actual > maximum {
        return Err(UpdateError::DocumentTooLarge);
    }
    Ok(())
}

fn import_canonical<T>(bytes: &[u8], maximum: usize) -> Result<T, UpdateError>
where
    T: DeserializeOwned + Serialize,
{
    validate_size(bytes.len(), maximum)?;
    let value: Value = serde_json::from_slice(bytes).map_err(|_| UpdateError::InvalidJson)?;
    validate_json_value(&value)?;
    let parsed: T = serde_json::from_slice(bytes).map_err(|_| UpdateError::InvalidJson)?;
    if canonical_json(&parsed)? != bytes {
        return Err(UpdateError::NonCanonicalJson);
    }
    Ok(parsed)
}

fn canonical_json<T: Serialize>(value: &T) -> Result<Vec<u8>, UpdateError> {
    let value = serde_json::to_value(value).map_err(|_| UpdateError::InvalidJson)?;
    validate_json_value(&value)?;
    let mut output = Vec::new();
    write_canonical_value(&value, &mut output)?;
    Ok(output)
}

fn validate_json_value(value: &Value) -> Result<(), UpdateError> {
    match value {
        Value::Null | Value::Bool(_) | Value::String(_) => Ok(()),
        Value::Number(number) => {
            if let Some(value) = number.as_u64() {
                if value <= MAX_SAFE_JSON_INTEGER {
                    Ok(())
                } else {
                    Err(UpdateError::UnsafeInteger)
                }
            } else if let Some(value) = number.as_i64() {
                if value.unsigned_abs() <= MAX_SAFE_JSON_INTEGER {
                    Ok(())
                } else {
                    Err(UpdateError::UnsafeInteger)
                }
            } else {
                Err(UpdateError::UnsupportedJsonValue)
            }
        }
        Value::Array(values) => values.iter().try_for_each(validate_json_value),
        Value::Object(values) => values.values().try_for_each(validate_json_value),
    }
}

fn write_canonical_value(value: &Value, output: &mut Vec<u8>) -> Result<(), UpdateError> {
    match value {
        Value::Null => output.extend_from_slice(b"null"),
        Value::Bool(value) => output.extend_from_slice(if *value { b"true" } else { b"false" }),
        Value::Number(value) => output.extend_from_slice(value.to_string().as_bytes()),
        Value::String(value) => {
            let encoded = serde_json::to_string(value).map_err(|_| UpdateError::InvalidJson)?;
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
                let encoded = serde_json::to_string(key).map_err(|_| UpdateError::InvalidJson)?;
                output.extend_from_slice(encoded.as_bytes());
                output.push(b':');
                write_canonical_value(values.get(key).ok_or(UpdateError::InvalidJson)?, output)?;
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

    const DEVICE: &str = "KA-0123456789abcdef01234567";
    const NOW: u64 = 1_800_000_200;

    fn signing_key() -> SigningKey {
        SigningKey::from_bytes(&[0x71; 32])
    }

    fn content(sequence: u64) -> UpdateManifestContent {
        UpdateManifestContent {
            sequence,
            release_id: format!("kernaid-1.2.{sequence}"),
            release_version: format!("1.2.{sequence}+build.4"),
            platform: UpdatePlatform::Linux,
            architecture: UpdateArchitecture::X86_64,
            release_ring: ReleaseRing::Stable,
            rollout: Rollout {
                basis_points: ROLLOUT_BASIS_POINTS,
                seed: "stable-2026-08".to_owned(),
            },
            issued_at_unix: 1_800_000_000,
            not_before_unix: 1_800_000_100,
            expires_at_unix: 1_800_086_400,
            artifact: ArtifactDescriptor {
                url: "https://updates.kernaid.example/releases/1.2/image.raw.zst".to_owned(),
                size_bytes: 4_096,
                sha256: "11".repeat(32),
            },
            emergency_rollback: false,
        }
    }

    fn verified(sequence: u64) -> VerifiedUpdate {
        SignedUpdateManifest::sign(content(sequence), &signing_key())
            .expect("sign update")
            .verify(&signing_key().verifying_key())
            .expect("verify update")
    }

    fn context(ring: UpdateRing) -> UpdateContext<'static> {
        UpdateContext {
            device_id: DEVICE,
            platform: UpdatePlatform::Linux,
            architecture: UpdateArchitecture::X86_64,
            update_ring: ring,
            now_unix: NOW,
        }
    }

    fn admitted(sequence: u64) -> AdmissionOutcome {
        admit_update(None, verified(sequence)).expect("admit update")
    }

    fn proof() -> CompletedArtifact {
        CompletedArtifact::new(4_096, [0x11; 32])
    }

    fn pending_state(attempts: u8) -> UpdateState {
        let outcome = admitted(1);
        let state = UpdateState::new(Slot::A);
        let plan = state
            .plan_stage(
                &outcome.update,
                &context(UpdateRing::Stable),
                &proof(),
                attempts,
            )
            .expect("plan stage");
        state
            .confirm_staged(&plan)
            .expect("confirm staged")
            .arm_pending_boot()
            .expect("arm boot")
    }

    #[test]
    fn signed_manifest_uses_external_anchor_and_exact_canonical_bytes() {
        let signed = SignedUpdateManifest::sign(content(7), &signing_key()).expect("sign");
        let bytes = signed.export_canonical().expect("export");
        let imported =
            SignedUpdateManifest::import_and_verify(&bytes, &signing_key().verifying_key())
                .expect("import and verify");
        assert_eq!(imported.sequence(), 7);
        assert_eq!(signed.export_canonical().expect("re-export"), bytes);
        assert!(
            std::str::from_utf8(&bytes)
                .expect("UTF-8")
                .starts_with("{\"architecture\":\"x86_64\",\"artifact\":")
        );
        assert!(
            !std::str::from_utf8(&bytes)
                .expect("UTF-8")
                .contains("publicKey")
        );
    }

    #[test]
    fn tamper_and_wrong_trust_anchor_fail_signature_verification() {
        let bytes = SignedUpdateManifest::sign(content(1), &signing_key())
            .expect("sign")
            .export_canonical()
            .expect("export");
        let mut value: Value = serde_json::from_slice(&bytes).expect("parse");
        value["releaseVersion"] = json!("9.9.9");
        let tampered = canonical_json(&value).expect("canonical tamper");
        assert_eq!(
            SignedUpdateManifest::import_and_verify(&tampered, &signing_key().verifying_key()),
            Err(UpdateError::InvalidSignature)
        );
        let other = SigningKey::from_bytes(&[0x17; 32]);
        assert_eq!(
            SignedUpdateManifest::import_and_verify(&bytes, &other.verifying_key()),
            Err(UpdateError::InvalidSignature)
        );
    }

    #[test]
    fn unknown_noncanonical_float_and_unsafe_integer_fail_closed() {
        let bytes = SignedUpdateManifest::sign(content(1), &signing_key())
            .expect("sign")
            .export_canonical()
            .expect("export");
        let mut unknown: Value = serde_json::from_slice(&bytes).expect("parse");
        unknown["diagnosticsEnabled"] = json!(false);
        let unknown = canonical_json(&unknown).expect("canonical unknown");
        assert_eq!(
            SignedUpdateManifest::import_and_verify(&unknown, &signing_key().verifying_key()),
            Err(UpdateError::InvalidJson)
        );

        let mut spaced = bytes.clone();
        spaced.push(b'\n');
        assert_eq!(
            SignedUpdateManifest::import_and_verify(&spaced, &signing_key().verifying_key()),
            Err(UpdateError::NonCanonicalJson)
        );

        let mut float: Value = serde_json::from_slice(&bytes).expect("parse");
        float["sequence"] = json!(1.5);
        assert_eq!(
            SignedUpdateManifest::import_and_verify(
                &serde_json::to_vec(&float).expect("serialize float"),
                &signing_key().verifying_key()
            ),
            Err(UpdateError::UnsupportedJsonValue)
        );

        let mut unsafe_integer: Value = serde_json::from_slice(&bytes).expect("parse");
        unsafe_integer["sequence"] = json!(MAX_SAFE_JSON_INTEGER + 1);
        assert_eq!(
            canonical_json(&unsafe_integer),
            Err(UpdateError::UnsafeInteger)
        );
    }

    #[test]
    fn artifact_and_manifest_bounds_are_enforced() {
        let mut invalid = content(1);
        invalid.artifact.url = "http://updates.example/image".to_owned();
        assert!(matches!(
            SignedUpdateManifest::sign(invalid, &signing_key()),
            Err(UpdateError::InvalidField("artifact.url"))
        ));
        let mut credentials = content(1);
        credentials.artifact.url = "https://user:secret@updates.example/image".to_owned();
        assert!(SignedUpdateManifest::sign(credentials, &signing_key()).is_err());
        let mut bad_hash = content(1);
        bad_hash.artifact.sha256 = "AA".repeat(32);
        assert!(SignedUpdateManifest::sign(bad_hash, &signing_key()).is_err());
        let mut bad_window = content(1);
        bad_window.expires_at_unix = bad_window.not_before_unix;
        assert_eq!(
            SignedUpdateManifest::sign(bad_window, &signing_key()),
            Err(UpdateError::InvalidTimeWindow)
        );
    }

    #[test]
    fn checkpoint_allows_only_monotonic_or_exact_idempotent_content() {
        let first = verified(5);
        let initial = admit_update(None, first.clone()).expect("first admission");
        assert_eq!(initial.update.admission(), CheckpointAdmission::First);
        let replay = admit_update(Some(&initial.next_checkpoint), first).expect("exact replay");
        assert_eq!(
            replay.update.admission(),
            CheckpointAdmission::IdempotentReplay
        );
        assert_eq!(
            admit_update(Some(&initial.next_checkpoint), verified(4)),
            Err(UpdateError::SequenceRollback)
        );

        let mut conflict = content(5);
        conflict.release_version = "1.2.5+different".to_owned();
        let conflict = SignedUpdateManifest::sign(conflict, &signing_key())
            .expect("sign conflict")
            .verify(&signing_key().verifying_key())
            .expect("verify conflict");
        assert_eq!(
            admit_update(Some(&initial.next_checkpoint), conflict),
            Err(UpdateError::SequenceConflict)
        );
        let advanced = admit_update(Some(&initial.next_checkpoint), verified(6)).expect("advance");
        assert_eq!(advanced.update.admission(), CheckpointAdmission::Advanced);
        let bytes = advanced.next_checkpoint.export_canonical().expect("export");
        assert_eq!(
            UpdateCheckpoint::import_canonical(&bytes)
                .expect("import")
                .sequence(),
            6
        );
    }

    #[test]
    fn emergency_release_never_bypasses_sequence_target_or_time() {
        let first = admit_update(None, verified(8)).expect("initial");
        let mut emergency = content(7);
        emergency.emergency_rollback = true;
        emergency.rollout.basis_points = 0;
        let emergency = SignedUpdateManifest::sign(emergency, &signing_key())
            .expect("sign emergency")
            .verify(&signing_key().verifying_key())
            .expect("verify emergency");
        assert_eq!(
            admit_update(Some(&first.next_checkpoint), emergency),
            Err(UpdateError::SequenceRollback)
        );

        let mut emergency = content(9);
        emergency.emergency_rollback = true;
        emergency.rollout.basis_points = 0;
        let emergency = SignedUpdateManifest::sign(emergency, &signing_key())
            .expect("sign emergency")
            .verify(&signing_key().verifying_key())
            .expect("verify emergency");
        assert_eq!(
            emergency.availability(&context(UpdateRing::Hold)),
            Availability::Eligible
        );
        let mut expired = context(UpdateRing::Hold);
        expired.now_unix = 1_800_086_400;
        assert_eq!(emergency.availability(&expired), Availability::Expired);
        expired.now_unix = NOW;
        expired.architecture = UpdateArchitecture::Aarch64;
        assert_eq!(
            emergency.availability(&expired),
            Availability::ArchitectureMismatch
        );
    }

    #[test]
    fn eligibility_enforces_ring_rollout_platform_and_clock() {
        let mut canary = content(1);
        canary.release_ring = ReleaseRing::Canary;
        canary.rollout.basis_points = 0;
        let update = SignedUpdateManifest::sign(canary, &signing_key())
            .expect("sign")
            .verify(&signing_key().verifying_key())
            .expect("verify");
        assert_eq!(
            update.availability(&context(UpdateRing::Hold)),
            Availability::Held
        );
        assert_eq!(
            update.availability(&context(UpdateRing::Stable)),
            Availability::RingMismatch
        );
        assert_eq!(
            update.availability(&context(UpdateRing::Canary)),
            Availability::RolloutDeferred
        );
        let mut wrong = context(UpdateRing::Canary);
        wrong.platform = UpdatePlatform::Windows;
        assert_eq!(update.availability(&wrong), Availability::PlatformMismatch);
        wrong.platform = UpdatePlatform::Linux;
        wrong.now_unix = 1_800_000_099;
        assert_eq!(update.availability(&wrong), Availability::NotYetValid);
    }

    #[test]
    fn stage_requires_full_hash_and_always_targets_inactive_slot() {
        let outcome = admitted(1);
        let state = UpdateState::new(Slot::A);
        let short = CompletedArtifact::new(4_095, [0x11; 32]);
        assert_eq!(
            state.plan_stage(&outcome.update, &context(UpdateRing::Stable), &short, 3,),
            Err(UpdateError::ArtifactMismatch)
        );
        let wrong_hash = CompletedArtifact::new(4_096, [0x12; 32]);
        assert_eq!(
            state.plan_stage(
                &outcome.update,
                &context(UpdateRing::Stable),
                &wrong_hash,
                3,
            ),
            Err(UpdateError::ArtifactMismatch)
        );
        let plan = state
            .plan_stage(&outcome.update, &context(UpdateRing::Stable), &proof(), 3)
            .expect("plan stage");
        assert_eq!(plan.target_slot(), Slot::B);
        assert_eq!(plan.rollback_slot(), Slot::A);
        assert_eq!(plan.artifact_sha256(), "11".repeat(32));
        assert_eq!(
            state.plan_stage(&outcome.update, &context(UpdateRing::Hold), &proof(), 3),
            Err(UpdateError::NotEligible(Availability::Held))
        );
    }

    #[test]
    fn pending_boot_attempts_are_bounded_then_rollback() {
        let state = pending_state(2);
        let first = state.next_boot().expect("first boot");
        assert_eq!(
            first.action,
            BootAction::TryPending {
                slot: Slot::B,
                rollback_slot: Slot::A
            }
        );
        let second = first.state.next_boot().expect("second boot");
        assert!(matches!(second.action, BootAction::TryPending { .. }));
        let rollback = second.state.next_boot().expect("rollback");
        assert_eq!(rollback.state.phase(), UpdatePhase::RollbackPending);
        assert_eq!(
            rollback.action,
            BootAction::Rollback {
                slot: Slot::A,
                failed_slot: Slot::B
            }
        );
    }

    #[test]
    fn mark_good_and_explicit_failure_follow_strict_slot_transitions() {
        let pending = pending_state(3);
        assert_eq!(
            pending.mark_good(Slot::A),
            Err(UpdateError::WrongRunningSlot)
        );
        let good = pending.mark_good(Slot::B).expect("mark B good");
        assert_eq!(good.phase(), UpdatePhase::Stable);
        assert_eq!(good.active_slot(), Slot::B);
        assert_eq!(good.rollback_slot(), Slot::A);

        let failed = pending.record_failure().expect("record failure");
        assert_eq!(failed.phase(), UpdatePhase::RollbackPending);
        assert_eq!(
            failed.confirm_rollback(Slot::B),
            Err(UpdateError::WrongRunningSlot)
        );
        let restored = failed.confirm_rollback(Slot::A).expect("restore A");
        assert_eq!(restored.active_slot(), Slot::A);
        assert_eq!(restored.rollback_slot(), Slot::B);
    }

    #[test]
    fn diagnostics_and_rollback_survive_every_state_and_strict_persistence() {
        let stable = UpdateState::new(Slot::A);
        let outcome = admitted(1);
        let plan = stable
            .plan_stage(&outcome.update, &context(UpdateRing::Stable), &proof(), 2)
            .expect("plan");
        let staged = stable.confirm_staged(&plan).expect("staged");
        let pending = staged.arm_pending_boot().expect("pending");
        let failed = pending.record_failure().expect("failed");
        for state in [&stable, &staged, &pending, &failed] {
            assert_eq!(
                state.safety_capabilities(),
                SafetyCapabilities {
                    diagnostics_available: true,
                    rollback_available: true
                }
            );
        }

        let local = stable.plan_local_rollback().expect("plan local rollback");
        assert_eq!(local.target_slot(), Slot::B);
        let rolled = stable
            .confirm_local_rollback(local, Slot::B)
            .expect("local rollback");
        assert_eq!(rolled.active_slot(), Slot::B);

        for state in [&staged, &pending, &failed] {
            assert_eq!(
                state
                    .plan_local_rollback()
                    .expect("plan in-flight rollback")
                    .target_slot(),
                Slot::A
            );
        }
        let cancelled = pending
            .confirm_local_rollback(
                pending
                    .plan_local_rollback()
                    .expect("plan pending rollback"),
                Slot::A,
            )
            .expect("confirm pending rollback");
        assert_eq!(cancelled.phase(), UpdatePhase::Stable);
        assert_eq!(cancelled.active_slot(), Slot::A);

        let bytes = pending.export_canonical().expect("export state");
        assert_eq!(
            UpdateState::import_canonical(&bytes).expect("import state"),
            pending
        );
        let mut unknown: Value = serde_json::from_slice(&bytes).expect("parse state");
        unknown["diagnosticsAvailable"] = json!(false);
        let unknown = canonical_json(&unknown).expect("canonical state");
        assert_eq!(
            UpdateState::import_canonical(&unknown),
            Err(UpdateError::InvalidJson)
        );
    }
}
