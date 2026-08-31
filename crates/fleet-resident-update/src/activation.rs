//! Durable, local-only systemd-boot A/B activation state machine.
//!
//! This module never accepts a command, path, kernel command line or boot
//! entry from Fleet. Staging creates a candidate from the admitted signed
//! update and its exact-byte receipt. A separate privileged adapter supplies
//! the fixed local boot selector.

use super::{
    AUDIT_RECEIPT_FILE, AdmittedUpdate, ArtifactStager, CompletedArtifactEvidence,
    ResidentUpdateError, Slot, StagingReceipt, StagingRecovery, canonical_json, hex_sha256,
    import_canonical, inspect_private_file, prepare_private_directory, sync_directory,
    validate_identifier, validate_sha256, validate_size,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    error::Error,
    fmt, fs,
    fs::OpenOptions,
    io::{self, Write},
    path::{Path, PathBuf},
};

#[cfg(unix)]
use std::os::unix::fs::OpenOptionsExt;

pub const ACTIVATION_CANDIDATE_SCHEMA: &str = "dev.kernaid.fleet.boot-activation-candidate.v1";
pub const ACTIVATION_STATE_SCHEMA: &str = "dev.kernaid.fleet.boot-activation-state.v1";
pub const ACTIVATION_RECEIPT_SCHEMA: &str = "dev.kernaid.fleet.boot-activation-receipt.v1";

const CANDIDATE_FILE: &str = "boot-activation-candidate.cjson";
const STATE_FILE: &str = "boot-activation-state.cjson";
const LAST_RECEIPT_FILE: &str = "boot-activation-last-receipt.cjson";
const TEMP_FILE: &str = ".boot-activation.pending";
const STAGING_DIRECTORY: &str = "staging";
const MAX_ACTIVATION_BYTES: usize = 16 * 1024;
const MAX_BOOT_ID_BYTES: usize = 64;

/// Path-free capability candidate. Every value is taken from the admitted
/// vendor-signed manifest or the receipt for the exact staged bytes.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct BootActivationCandidate {
    schema: String,
    release_id: String,
    sequence: u64,
    manifest_sha256: String,
    artifact_sha256: String,
    staging_receipt_sha256: String,
    known_good_slot: Slot,
    target_slot: Slot,
}

impl BootActivationCandidate {
    pub fn derive(
        admitted: &AdmittedUpdate,
        receipt: &StagingReceipt,
    ) -> Result<Self, ActivationError> {
        let receipt_bytes = receipt.export_canonical()?;
        let verified = admitted.verified();
        if receipt.release_id() != verified.release_id()
            || receipt.sequence() != verified.sequence()
            || receipt.complete_size_bytes() != verified.artifact().size_bytes
            || hex_sha256(&receipt.complete_sha256()) != verified.artifact().sha256
        {
            return Err(ActivationError::BindingMismatch);
        }
        let target_slot = receipt.target_slot();
        let candidate = Self {
            schema: ACTIVATION_CANDIDATE_SCHEMA.to_owned(),
            release_id: verified.release_id().to_owned(),
            sequence: verified.sequence(),
            manifest_sha256: hex_sha256(verified.manifest_sha256()),
            artifact_sha256: verified.artifact().sha256.clone(),
            staging_receipt_sha256: hex_sha256(&Sha256::digest(receipt_bytes)),
            known_good_slot: target_slot.inactive(),
            target_slot,
        };
        candidate.validate()?;
        Ok(candidate)
    }

    #[must_use]
    pub const fn known_good_slot(&self) -> Slot {
        self.known_good_slot
    }

    #[must_use]
    pub const fn target_slot(&self) -> Slot {
        self.target_slot
    }

    #[must_use]
    pub fn release_id(&self) -> &str {
        &self.release_id
    }

    #[must_use]
    pub const fn sequence(&self) -> u64 {
        self.sequence
    }

    fn export(&self) -> Result<Vec<u8>, ActivationError> {
        self.validate()?;
        let bytes = canonical_json(self)?;
        validate_size(bytes.len(), MAX_ACTIVATION_BYTES)?;
        Ok(bytes)
    }

    fn import(bytes: &[u8]) -> Result<Self, ActivationError> {
        let value: Self = import_canonical(bytes, MAX_ACTIVATION_BYTES)?;
        value.validate()?;
        Ok(value)
    }

    fn validate(&self) -> Result<(), ActivationError> {
        if self.schema != ACTIVATION_CANDIDATE_SCHEMA
            || self.sequence == 0
            || self.known_good_slot.inactive() != self.target_slot
        {
            return Err(ActivationError::StateInvalid);
        }
        validate_identifier(&self.release_id).map_err(|_| ActivationError::StateInvalid)?;
        validate_sha256(&self.manifest_sha256).map_err(|_| ActivationError::StateInvalid)?;
        validate_sha256(&self.artifact_sha256).map_err(|_| ActivationError::StateInvalid)?;
        validate_sha256(&self.staging_receipt_sha256).map_err(|_| ActivationError::StateInvalid)
    }

    fn matches_staging(&self, receipt: &StagingReceipt) -> Result<bool, ActivationError> {
        let bytes = receipt.export_canonical()?;
        Ok(receipt.release_id() == self.release_id
            && receipt.sequence() == self.sequence
            && receipt.target_slot() == self.target_slot
            && hex_sha256(&receipt.complete_sha256()) == self.artifact_sha256
            && hex_sha256(&Sha256::digest(bytes)) == self.staging_receipt_sha256)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum ActivationPhase {
    Prepared,
    Armed,
    PromotePrepared,
    RollbackPrepared,
    RollbackArmed,
    FinalizeSucceeded,
    FinalizeFallback,
    FinalizeRolledBack,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct DurableActivationState {
    schema: String,
    candidate: BootActivationCandidate,
    phase: ActivationPhase,
    transition_boot_id: String,
}

impl DurableActivationState {
    fn new(
        candidate: BootActivationCandidate,
        phase: ActivationPhase,
        boot_id: &str,
    ) -> Result<Self, ActivationError> {
        let state = Self {
            schema: ACTIVATION_STATE_SCHEMA.to_owned(),
            candidate,
            phase,
            transition_boot_id: boot_id.to_owned(),
        };
        state.validate()?;
        Ok(state)
    }

    fn with_phase(&self, phase: ActivationPhase, boot_id: &str) -> Result<Self, ActivationError> {
        Self::new(self.candidate.clone(), phase, boot_id)
    }

    fn export(&self) -> Result<Vec<u8>, ActivationError> {
        self.validate()?;
        Ok(canonical_json(self)?)
    }

    fn import(bytes: &[u8]) -> Result<Self, ActivationError> {
        let state: Self = import_canonical(bytes, MAX_ACTIVATION_BYTES)?;
        state.validate()?;
        Ok(state)
    }

    fn validate(&self) -> Result<(), ActivationError> {
        if self.schema != ACTIVATION_STATE_SCHEMA || !valid_boot_id(&self.transition_boot_id) {
            return Err(ActivationError::StateInvalid);
        }
        self.candidate.validate()
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ActivationOutcome {
    Succeeded,
    FellBack,
    RolledBack,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct BootActivationReceipt {
    schema: String,
    candidate: BootActivationCandidate,
    outcome: ActivationOutcome,
    terminal_boot_id: String,
}

impl BootActivationReceipt {
    fn new(
        candidate: BootActivationCandidate,
        outcome: ActivationOutcome,
        boot_id: &str,
    ) -> Result<Self, ActivationError> {
        let receipt = Self {
            schema: ACTIVATION_RECEIPT_SCHEMA.to_owned(),
            candidate,
            outcome,
            terminal_boot_id: boot_id.to_owned(),
        };
        receipt.validate()?;
        Ok(receipt)
    }

    #[must_use]
    pub const fn outcome(&self) -> ActivationOutcome {
        self.outcome
    }

    #[must_use]
    pub fn candidate(&self) -> &BootActivationCandidate {
        &self.candidate
    }

    fn export(&self) -> Result<Vec<u8>, ActivationError> {
        self.validate()?;
        Ok(canonical_json(self)?)
    }

    fn import(bytes: &[u8]) -> Result<Self, ActivationError> {
        let receipt: Self = import_canonical(bytes, MAX_ACTIVATION_BYTES)?;
        receipt.validate()?;
        Ok(receipt)
    }

    fn validate(&self) -> Result<(), ActivationError> {
        if self.schema != ACTIVATION_RECEIPT_SCHEMA || !valid_boot_id(&self.terminal_boot_id) {
            return Err(ActivationError::StateInvalid);
        }
        self.candidate.validate()
    }
}

/// Narrow bootloader capability. The production implementation maps each slot
/// to one compiled-in systemd-boot entry; tests use a fake selector.
pub trait BootSelector {
    fn preflight(&mut self, known_good: Slot, target: Slot) -> Result<(), ActivationError>;
    fn arm_trial(&mut self, known_good: Slot, target: Slot) -> Result<(), ActivationError>;
    fn promote(&mut self, target: Slot) -> Result<(), ActivationError>;
    fn arm_rollback(&mut self, known_good: Slot) -> Result<(), ActivationError>;
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReconcileOutcome {
    Idle,
    TrialArmed,
    WaitingForReboot,
    Succeeded,
    FellBack,
    RollbackArmed,
    RolledBack,
}

pub struct ActivationJournal {
    directory: PathBuf,
}

impl ActivationJournal {
    pub fn open(directory: &Path) -> Result<Self, ActivationError> {
        prepare_private_directory(directory)?;
        let journal = Self {
            directory: directory.to_path_buf(),
        };
        journal.cleanup_temp()?;
        let _ = journal.load_candidate()?;
        let _ = journal.load_state()?;
        let _ = journal.load_last_receipt()?;
        Ok(journal)
    }

    pub fn persist_candidate(
        &self,
        candidate: &BootActivationCandidate,
    ) -> Result<(), ActivationError> {
        let bytes = candidate.export()?;
        match self.read_optional(CANDIDATE_FILE)? {
            Some(existing) if existing == bytes => Ok(()),
            Some(_) => Err(ActivationError::JournalConflict),
            None if self.load_state()?.is_none() => {
                self.write_atomic(CANDIDATE_FILE, &bytes, false)
            }
            None => Err(ActivationError::JournalConflict),
        }
    }

    pub(crate) fn load_candidate(
        &self,
    ) -> Result<Option<BootActivationCandidate>, ActivationError> {
        self.read_optional(CANDIDATE_FILE)?
            .map(|bytes| BootActivationCandidate::import(&bytes))
            .transpose()
    }

    fn load_state(&self) -> Result<Option<DurableActivationState>, ActivationError> {
        self.read_optional(STATE_FILE)?
            .map(|bytes| DurableActivationState::import(&bytes))
            .transpose()
    }

    pub fn load_last_receipt(&self) -> Result<Option<BootActivationReceipt>, ActivationError> {
        self.read_optional(LAST_RECEIPT_FILE)?
            .map(|bytes| BootActivationReceipt::import(&bytes))
            .transpose()
    }

    fn persist_state(
        &self,
        previous: Option<&DurableActivationState>,
        next: &DurableActivationState,
    ) -> Result<(), ActivationError> {
        let retained = self.load_state()?;
        if retained.as_ref() != previous {
            return Err(ActivationError::JournalConflict);
        }
        self.write_atomic(STATE_FILE, &next.export()?, retained.is_some())
    }

    fn persist_terminal_receipt(
        &self,
        receipt: &BootActivationReceipt,
    ) -> Result<(), ActivationError> {
        let bytes = receipt.export()?;
        let outcome = match receipt.outcome {
            ActivationOutcome::Succeeded => "succeeded",
            ActivationOutcome::FellBack => "fell-back",
            ActivationOutcome::RolledBack => "rolled-back",
        };
        let archive_name = format!(
            "boot-activation-receipt-{}-{}-{outcome}.cjson",
            receipt.candidate.sequence,
            &receipt.candidate.manifest_sha256[..16]
        );
        match self.read_optional(&archive_name)? {
            Some(existing) if existing == bytes => {}
            Some(_) => return Err(ActivationError::JournalConflict),
            None => self.write_atomic(&archive_name, &bytes, false)?,
        }
        match self.read_optional(LAST_RECEIPT_FILE)? {
            Some(existing) if existing == bytes => Ok(()),
            Some(_) => self.write_atomic(LAST_RECEIPT_FILE, &bytes, true),
            None => self.write_atomic(LAST_RECEIPT_FILE, &bytes, false),
        }
    }

    fn archive_staging_audit(
        &self,
        candidate: &BootActivationCandidate,
    ) -> Result<(), ActivationError> {
        let Some(bytes) = self.read_optional(AUDIT_RECEIPT_FILE)? else {
            return Ok(());
        };
        let archive_name = format!(
            "update-audit-receipt-{}-{}.cjson",
            candidate.sequence,
            &candidate.manifest_sha256[..16]
        );
        match self.read_optional(&archive_name)? {
            Some(existing) if existing == bytes => {}
            Some(_) => return Err(ActivationError::JournalConflict),
            None => self.write_atomic(&archive_name, &bytes, false)?,
        }
        self.remove(AUDIT_RECEIPT_FILE)
    }

    fn read_optional(&self, name: &str) -> Result<Option<Vec<u8>>, ActivationError> {
        let path = self.directory.join(name);
        match fs::symlink_metadata(&path) {
            Ok(metadata) => {
                inspect_private_file(&metadata)?;
                if metadata.len() == 0 || metadata.len() > MAX_ACTIVATION_BYTES as u64 {
                    return Err(ActivationError::StateInvalid);
                }
                let bytes = fs::read(path)?;
                if bytes.len() as u64 != metadata.len() || bytes.len() > MAX_ACTIVATION_BYTES {
                    return Err(ActivationError::StateInvalid);
                }
                Ok(Some(bytes))
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(None),
            Err(error) => Err(error.into()),
        }
    }

    fn write_atomic(&self, name: &str, bytes: &[u8], replace: bool) -> Result<(), ActivationError> {
        if bytes.is_empty() || bytes.len() > MAX_ACTIVATION_BYTES {
            return Err(ActivationError::StateInvalid);
        }
        let target = self.directory.join(name);
        match fs::symlink_metadata(&target) {
            Ok(metadata) if replace => inspect_private_file(&metadata)?,
            Ok(_) => return Err(ActivationError::JournalConflict),
            Err(error) if error.kind() == io::ErrorKind::NotFound && !replace => {}
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                return Err(ActivationError::JournalConflict);
            }
            Err(error) => return Err(error.into()),
        }
        let temporary = self.directory.join(TEMP_FILE);
        let mut options = OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        options.mode(0o600);
        let mut file = options.open(&temporary)?;
        let result = (|| -> Result<(), ActivationError> {
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

    fn remove(&self, name: &str) -> Result<(), ActivationError> {
        let path = self.directory.join(name);
        match fs::symlink_metadata(&path) {
            Ok(metadata) => {
                inspect_private_file(&metadata)?;
                fs::remove_file(path)?;
                sync_directory(&self.directory)?;
                Ok(())
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
            Err(error) => Err(error.into()),
        }
    }

    fn cleanup_temp(&self) -> Result<(), ActivationError> {
        self.remove(TEMP_FILE)
    }
}

pub struct BootActivationEngine<S> {
    journal: ActivationJournal,
    stager: ArtifactStager,
    selector: S,
}

impl<S: BootSelector> BootActivationEngine<S> {
    pub fn open(state_directory: &Path, selector: S) -> Result<Self, ActivationError> {
        Ok(Self {
            journal: ActivationJournal::open(state_directory)?,
            stager: ArtifactStager::open(&state_directory.join(STAGING_DIRECTORY))?,
            selector,
        })
    }

    pub fn reconcile(
        &mut self,
        current_slot: Slot,
        boot_id: &str,
    ) -> Result<ReconcileOutcome, ActivationError> {
        validate_boot_observation(boot_id)?;
        let mut state = match self.journal.load_state()? {
            Some(state) => state,
            None => {
                let Some(candidate) = self.journal.load_candidate()? else {
                    return Ok(ReconcileOutcome::Idle);
                };
                self.require_staging(&candidate)?;
                if current_slot != candidate.known_good_slot {
                    return Err(ActivationError::UnexpectedBootSlot);
                }
                self.selector
                    .preflight(candidate.known_good_slot, candidate.target_slot)?;
                let prepared =
                    DurableActivationState::new(candidate, ActivationPhase::Prepared, boot_id)?;
                self.journal.persist_state(None, &prepared)?;
                prepared
            }
        };

        loop {
            state.validate()?;
            match state.phase {
                ActivationPhase::Prepared => {
                    self.require_staging(&state.candidate)?;
                    self.selector
                        .preflight(state.candidate.known_good_slot, state.candidate.target_slot)?;
                    if boot_id != state.transition_boot_id {
                        let next = if current_slot == state.candidate.target_slot {
                            state.with_phase(ActivationPhase::PromotePrepared, boot_id)?
                        } else if current_slot == state.candidate.known_good_slot {
                            // A restart after durable prepare but before the
                            // `Armed` write is ambiguous. Never retry a
                            // possibly failed target automatically.
                            state.with_phase(ActivationPhase::FinalizeFallback, boot_id)?
                        } else {
                            return Err(ActivationError::UnexpectedBootSlot);
                        };
                        self.journal.persist_state(Some(&state), &next)?;
                        state = next;
                        continue;
                    }
                    if current_slot != state.candidate.known_good_slot {
                        return Err(ActivationError::UnexpectedBootSlot);
                    }
                    self.selector
                        .arm_trial(state.candidate.known_good_slot, state.candidate.target_slot)?;
                    let next = state.with_phase(ActivationPhase::Armed, boot_id)?;
                    self.journal.persist_state(Some(&state), &next)?;
                    return Ok(ReconcileOutcome::TrialArmed);
                }
                ActivationPhase::Armed => {
                    self.require_staging(&state.candidate)?;
                    if boot_id == state.transition_boot_id {
                        return Ok(ReconcileOutcome::WaitingForReboot);
                    }
                    if current_slot == state.candidate.target_slot {
                        let next = state.with_phase(ActivationPhase::PromotePrepared, boot_id)?;
                        self.journal.persist_state(Some(&state), &next)?;
                        state = next;
                        continue;
                    }
                    if current_slot == state.candidate.known_good_slot {
                        let next = state.with_phase(ActivationPhase::FinalizeFallback, boot_id)?;
                        self.journal.persist_state(Some(&state), &next)?;
                        state = next;
                        continue;
                    }
                    return Err(ActivationError::UnexpectedBootSlot);
                }
                ActivationPhase::PromotePrepared => {
                    self.require_staging(&state.candidate)?;
                    if current_slot != state.candidate.target_slot {
                        return Err(ActivationError::UnexpectedBootSlot);
                    }
                    self.selector.promote(state.candidate.target_slot)?;
                    let next = state.with_phase(ActivationPhase::FinalizeSucceeded, boot_id)?;
                    self.journal.persist_state(Some(&state), &next)?;
                    state = next;
                }
                ActivationPhase::RollbackPrepared => {
                    self.selector
                        .preflight(state.candidate.known_good_slot, state.candidate.target_slot)?;
                    self.selector
                        .arm_rollback(state.candidate.known_good_slot)?;
                    let next = state.with_phase(ActivationPhase::RollbackArmed, boot_id)?;
                    self.journal.persist_state(Some(&state), &next)?;
                    if current_slot == state.candidate.known_good_slot {
                        state = next;
                        continue;
                    }
                    return Ok(ReconcileOutcome::RollbackArmed);
                }
                ActivationPhase::RollbackArmed => {
                    if current_slot == state.candidate.known_good_slot {
                        let next =
                            state.with_phase(ActivationPhase::FinalizeRolledBack, boot_id)?;
                        self.journal.persist_state(Some(&state), &next)?;
                        state = next;
                        continue;
                    }
                    if boot_id == state.transition_boot_id
                        && current_slot == state.candidate.target_slot
                    {
                        return Ok(ReconcileOutcome::WaitingForReboot);
                    }
                    return Err(ActivationError::UnexpectedBootSlot);
                }
                ActivationPhase::FinalizeSucceeded => {
                    self.finalize(&state, ActivationOutcome::Succeeded, boot_id)?;
                    return Ok(ReconcileOutcome::Succeeded);
                }
                ActivationPhase::FinalizeFallback => {
                    self.finalize(&state, ActivationOutcome::FellBack, boot_id)?;
                    return Ok(ReconcileOutcome::FellBack);
                }
                ActivationPhase::FinalizeRolledBack => {
                    self.finalize(&state, ActivationOutcome::RolledBack, boot_id)?;
                    return Ok(ReconcileOutcome::RolledBack);
                }
            }
        }
    }

    /// Local break-glass rollback. It consumes no network input and can select
    /// only the known-good slot retained in the durable activation binding.
    pub fn rollback(
        &mut self,
        current_slot: Slot,
        boot_id: &str,
    ) -> Result<ReconcileOutcome, ActivationError> {
        validate_boot_observation(boot_id)?;
        let previous = self.journal.load_state()?;
        let candidate = match previous.as_ref() {
            Some(state) => state.candidate.clone(),
            None => {
                let receipt = self
                    .journal
                    .load_last_receipt()?
                    .ok_or(ActivationError::NothingToRollback)?;
                if receipt.outcome != ActivationOutcome::Succeeded {
                    return Err(ActivationError::NothingToRollback);
                }
                receipt.candidate
            }
        };
        if current_slot != candidate.known_good_slot && current_slot != candidate.target_slot {
            return Err(ActivationError::UnexpectedBootSlot);
        }
        self.selector
            .preflight(candidate.known_good_slot, candidate.target_slot)?;
        let next =
            DurableActivationState::new(candidate, ActivationPhase::RollbackPrepared, boot_id)?;
        self.journal.persist_state(previous.as_ref(), &next)?;
        self.reconcile(current_slot, boot_id)
    }

    fn require_staging(&self, candidate: &BootActivationCandidate) -> Result<(), ActivationError> {
        let StagingRecovery::Completed(receipt) = self.stager.recovery_status()? else {
            return Err(ActivationError::StagingUnavailable);
        };
        if !candidate.matches_staging(&receipt)? {
            return Err(ActivationError::BindingMismatch);
        }
        Ok(())
    }

    fn finalize(
        &self,
        state: &DurableActivationState,
        outcome: ActivationOutcome,
        boot_id: &str,
    ) -> Result<(), ActivationError> {
        let receipt = BootActivationReceipt::new(state.candidate.clone(), outcome, boot_id)?;
        self.journal.persist_terminal_receipt(&receipt)?;
        self.journal.archive_staging_audit(&state.candidate)?;
        match self.stager.recovery_status()? {
            StagingRecovery::Completed(staging) => {
                if !state.candidate.matches_staging(&staging)? {
                    return Err(ActivationError::BindingMismatch);
                }
                self.stager.clear_completed(&staging)?;
            }
            StagingRecovery::Clean if outcome == ActivationOutcome::RolledBack => {}
            StagingRecovery::Clean => {
                // A prior finalization may already have released this exact
                // receipt; the durable terminal receipt makes the retry safe.
                let retained = self
                    .journal
                    .load_last_receipt()?
                    .ok_or(ActivationError::StagingUnavailable)?;
                if retained != receipt {
                    return Err(ActivationError::BindingMismatch);
                }
            }
            StagingRecovery::Interrupted(_) => return Err(ActivationError::StagingUnavailable),
        }
        self.journal.remove(CANDIDATE_FILE)?;
        self.journal.remove(STATE_FILE)
    }
}

fn validate_boot_observation(boot_id: &str) -> Result<(), ActivationError> {
    if valid_boot_id(boot_id) {
        Ok(())
    } else {
        Err(ActivationError::BootObservationInvalid)
    }
}

fn valid_boot_id(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= MAX_BOOT_ID_BYTES
        && value
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() || byte == b'-')
}

#[derive(Debug)]
pub enum ActivationError {
    StateInvalid,
    JournalConflict,
    BindingMismatch,
    StagingUnavailable,
    BootObservationInvalid,
    UnexpectedBootSlot,
    UnsupportedPlatform,
    BootEntryInvalid,
    BootSelectorFailed,
    BootSelectorTimeout,
    NothingToRollback,
    Staging(super::StagingError),
    Resident(Box<ResidentUpdateError>),
    Io(io::Error),
}

impl ActivationError {
    #[must_use]
    pub const fn code(&self) -> &'static str {
        match self {
            Self::StateInvalid => "activation-state-invalid",
            Self::JournalConflict => "activation-journal-conflict",
            Self::BindingMismatch => "activation-binding-mismatch",
            Self::StagingUnavailable => "activation-staging-unavailable",
            Self::BootObservationInvalid => "activation-boot-observation-invalid",
            Self::UnexpectedBootSlot => "activation-boot-slot-unexpected",
            Self::UnsupportedPlatform => "activation-systemd-boot-uefi-required",
            Self::BootEntryInvalid => "activation-boot-entry-invalid",
            Self::BootSelectorFailed => "activation-bootctl-failed",
            Self::BootSelectorTimeout => "activation-bootctl-timeout",
            Self::NothingToRollback => "activation-nothing-to-rollback",
            Self::Staging(_) => "activation-staging-invalid",
            Self::Resident(_) => "activation-state-io",
            Self::Io(_) => "activation-io",
        }
    }
}

impl fmt::Display for ActivationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.code())
    }
}

impl Error for ActivationError {}

impl From<super::StagingError> for ActivationError {
    fn from(value: super::StagingError) -> Self {
        Self::Staging(value)
    }
}

impl From<ResidentUpdateError> for ActivationError {
    fn from(value: ResidentUpdateError) -> Self {
        Self::Resident(Box::new(value))
    }
}

impl From<io::Error> for ActivationError {
    fn from(value: io::Error) -> Self {
        Self::Io(value)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::SigningKey;
    use kernaid_update_client::{
        ArtifactDescriptor, PreopenedInactiveTarget, ReleaseRing, Rollout, SignedUpdateManifest,
        UpdateArchitecture, UpdateContext, UpdateManifestContent, UpdatePlatform, UpdateRing,
        admit_update,
    };
    #[cfg(unix)]
    use std::os::unix::fs::PermissionsExt;
    use std::{fs::OpenOptions, io::Cursor};
    use tempfile::TempDir;

    const DEVICE: &str = "KA-0123456789abcdef01234567";
    const BOOT_1: &str = "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa";
    const BOOT_2: &str = "bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb";
    const BOOT_3: &str = "cccccccc-cccc-cccc-cccc-cccccccccccc";

    #[derive(Default)]
    struct FakeSelector {
        actions: Vec<(&'static str, Slot, Slot)>,
        fail_arm_once: bool,
    }

    impl BootSelector for FakeSelector {
        fn preflight(&mut self, known_good: Slot, target: Slot) -> Result<(), ActivationError> {
            self.actions.push(("preflight", known_good, target));
            Ok(())
        }

        fn arm_trial(&mut self, known_good: Slot, target: Slot) -> Result<(), ActivationError> {
            self.actions.push(("arm_trial", known_good, target));
            if self.fail_arm_once {
                self.fail_arm_once = false;
                return Err(ActivationError::BootSelectorFailed);
            }
            Ok(())
        }

        fn promote(&mut self, target: Slot) -> Result<(), ActivationError> {
            self.actions.push(("promote", target.inactive(), target));
            Ok(())
        }

        fn arm_rollback(&mut self, known_good: Slot) -> Result<(), ActivationError> {
            self.actions.push(("arm_rollback", known_good, known_good));
            Ok(())
        }
    }

    fn admitted_for(bytes: &[u8]) -> AdmittedUpdate {
        let digest: [u8; 32] = Sha256::digest(bytes).into();
        let manifest = SignedUpdateManifest::sign(
            UpdateManifestContent {
                sequence: 9,
                release_id: "release-nine".to_owned(),
                release_version: "9.0.0".to_owned(),
                platform: UpdatePlatform::Linux,
                architecture: UpdateArchitecture::X86_64,
                release_ring: ReleaseRing::Stable,
                rollout: Rollout {
                    basis_points: 10_000,
                    seed: "activation-test".to_owned(),
                },
                issued_at_unix: 1_000,
                not_before_unix: 1_100,
                expires_at_unix: 3_000,
                artifact: ArtifactDescriptor {
                    url: "https://updates.example.test/slot.raw".to_owned(),
                    size_bytes: bytes.len() as u64,
                    sha256: hex_sha256(&digest),
                },
                emergency_rollback: false,
            },
            &SigningKey::from_bytes(&[0x51; 32]),
        )
        .expect("sign fixture manifest");
        let verified = manifest
            .verify(&SigningKey::from_bytes(&[0x51; 32]).verifying_key())
            .expect("verify fixture manifest");
        admit_update(None, verified)
            .expect("admit fixture manifest")
            .update
    }

    fn staged_fixture() -> (TempDir, BootActivationCandidate) {
        let root = TempDir::new().expect("temporary activation root");
        let state = root.path().join("state");
        fs::create_dir(&state).expect("create private state");
        #[cfg(unix)]
        fs::set_permissions(&state, fs::Permissions::from_mode(0o700))
            .expect("protect private state");
        let bytes = b"signed inactive slot bytes";
        let admitted = admitted_for(bytes);
        let stager =
            ArtifactStager::open(&state.join(STAGING_DIRECTORY)).expect("open fixture stager");
        let target_path = root.path().join("slot-b.img");
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(target_path)
            .expect("open fixture target");
        let mut target = PreopenedInactiveTarget::new(file, Slot::A, Slot::B)
            .expect("bind inactive fixture target");
        let context = UpdateContext {
            device_id: DEVICE,
            platform: UpdatePlatform::Linux,
            architecture: UpdateArchitecture::X86_64,
            update_ring: UpdateRing::Stable,
            now_unix: 1_500,
        };
        let receipt = stager
            .stage(
                &admitted,
                &context,
                true,
                &mut Cursor::new(bytes),
                &mut target,
            )
            .expect("stage fixture artifact");
        let candidate =
            BootActivationCandidate::derive(&admitted, &receipt).expect("derive fixture candidate");
        ActivationJournal::open(&state)
            .expect("open activation journal")
            .persist_candidate(&candidate)
            .expect("persist activation candidate");
        (root, candidate)
    }

    #[test]
    fn persists_before_arm_then_promotes_and_releases_staging_receipt() {
        let (root, candidate) = staged_fixture();
        let state = root.path().join("state");
        let mut engine = BootActivationEngine::open(&state, FakeSelector::default())
            .expect("open activation engine");
        assert_eq!(
            engine.reconcile(Slot::A, BOOT_1).expect("arm trial"),
            ReconcileOutcome::TrialArmed
        );
        assert!(
            ActivationJournal::open(&state)
                .expect("reopen activation journal")
                .load_state()
                .is_ok()
        );
        assert_eq!(
            engine.reconcile(Slot::A, BOOT_1).expect("wait same boot"),
            ReconcileOutcome::WaitingForReboot
        );
        assert_eq!(
            engine.reconcile(Slot::B, BOOT_2).expect("promote target"),
            ReconcileOutcome::Succeeded
        );
        let journal = ActivationJournal::open(&state).expect("open terminal journal");
        let terminal = journal
            .load_last_receipt()
            .expect("load terminal receipt")
            .expect("terminal receipt exists");
        assert_eq!(terminal.outcome(), ActivationOutcome::Succeeded);
        assert_eq!(terminal.candidate(), &candidate);
        assert!(
            journal
                .load_candidate()
                .expect("load cleared candidate")
                .is_none()
        );
        assert!(journal.load_state().expect("load cleared state").is_none());
        assert_eq!(
            ArtifactStager::open(&state.join(STAGING_DIRECTORY))
                .expect("reopen stager")
                .recovery_status()
                .expect("read released staging status"),
            StagingRecovery::Clean
        );
        assert!(
            engine
                .selector
                .actions
                .iter()
                .any(|(action, _, _)| *action == "promote")
        );
    }

    #[test]
    fn failed_selector_leaves_prepared_transition_for_idempotent_retry() {
        let (root, _) = staged_fixture();
        let state = root.path().join("state");
        let selector = FakeSelector {
            fail_arm_once: true,
            ..FakeSelector::default()
        };
        let mut engine =
            BootActivationEngine::open(&state, selector).expect("open activation engine");
        assert!(matches!(
            engine.reconcile(Slot::A, BOOT_1),
            Err(ActivationError::BootSelectorFailed)
        ));
        let retained = ActivationJournal::open(&state)
            .expect("reopen activation journal")
            .load_state()
            .expect("load prepared state")
            .expect("prepared state exists");
        assert_eq!(retained.phase, ActivationPhase::Prepared);
        assert_eq!(
            engine.reconcile(Slot::A, BOOT_1).expect("retry trial arm"),
            ReconcileOutcome::TrialArmed
        );
    }

    #[test]
    fn one_shot_fallback_is_terminal_without_promoting_failed_target() {
        let (root, _) = staged_fixture();
        let state = root.path().join("state");
        let mut engine = BootActivationEngine::open(&state, FakeSelector::default())
            .expect("open activation engine");
        assert_eq!(
            engine
                .reconcile(Slot::A, BOOT_1)
                .expect("arm fallback fixture"),
            ReconcileOutcome::TrialArmed
        );
        assert_eq!(
            engine.reconcile(Slot::A, BOOT_2).expect("record fallback"),
            ReconcileOutcome::FellBack
        );
        assert!(
            !engine
                .selector
                .actions
                .iter()
                .any(|(action, _, _)| *action == "promote")
        );
    }

    #[test]
    fn successful_target_can_be_rolled_back_entirely_offline() {
        let (root, _) = staged_fixture();
        let state = root.path().join("state");
        let mut engine = BootActivationEngine::open(&state, FakeSelector::default())
            .expect("open activation engine");
        engine
            .reconcile(Slot::A, BOOT_1)
            .expect("arm trial before rollback");
        engine
            .reconcile(Slot::B, BOOT_2)
            .expect("promote before rollback");
        assert_eq!(
            engine
                .rollback(Slot::B, BOOT_2)
                .expect("arm offline rollback"),
            ReconcileOutcome::RollbackArmed
        );
        assert_eq!(
            engine
                .reconcile(Slot::A, BOOT_3)
                .expect("finish offline rollback"),
            ReconcileOutcome::RolledBack
        );
        assert_eq!(
            ActivationJournal::open(&state)
                .expect("open rollback journal")
                .load_last_receipt()
                .expect("load rollback receipt")
                .expect("rollback receipt exists")
                .outcome(),
            ActivationOutcome::RolledBack
        );
    }
}
