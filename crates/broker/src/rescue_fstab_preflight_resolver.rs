//! Production composition for the off-default Rescue `fstab` preflight.
//!
//! This resolver acquires the exact selected target from the fixed root-owned
//! capability endpoint, retains its locally resolved physical parent, observes
//! `fstab` read-only, and reserves bounded capacity in the Repair Vault. It
//! neither persists backup bytes nor exposes an execution or mutation method.

use crate::{
    repair_vault_client::{RepairVaultClient, RepairVaultClientError},
    rescue_fstab_candidate::{
        RescueFstabCapabilityResolutionError, RescueFstabPreflightCapabilityResolver,
        RescueFstabVaultReservation, TrustedRescueFstabObservation,
    },
    rescue_fstab_observer::{RescueFstabObservationError, observe_rescue_fstab},
    target_capability_client::{
        RescueTargetCapabilityClaims, TargetCapabilityClientError,
        acquire_rescue_target_capability, reacquire_rescue_target_capability,
    },
    target_physical_parent::{RescueTargetPhysicalParentGuard, TargetPhysicalParentError},
};
use kernaid_linux_pack::{
    production_candidate_contract::RESOURCE_ID,
    rescue_fstab_candidate::DisableMissingUuidPreview,
    rescue_fstab_transaction_candidate::{BootVaultBackupCapability, CandidateTransactionError},
};
use kernaid_protocol::{
    rescue_repair::{RescueFstabPreflightIntent, RescueFstabPrepareRequest},
    rescue_repair_vault::{
        RepairBackupDraft, RepairBackupState, RepairBackupStatusPayload, RepairExecutionIntentV1,
    },
    rescue_vault::{ErrorToken, RequestId, Sha256},
};
use rustix::rand::{GetRandomFlags, getrandom};
use sha2::{Digest, Sha256 as Sha256Hasher};
use std::{
    fmt::{self, Write as _},
    thread,
    time::{Duration, Instant},
};

const REPAIR_BACKUP_CAPACITY_BYTES: u64 = 4096;
// Reserve against an earlier absolute deadline so every post-reserve rejection
// retains a bounded window in which the persistent reservation can be
// cancelled using the caller's original deadline.
const RESERVATION_CLEANUP_BUDGET: Duration = Duration::from_secs(2);
const RESERVATION_RECONCILIATION_POLL: Duration = Duration::from_millis(250);
const LOCK_ID_DOMAIN: &[u8] = b"kernaid:rescue-fstab:target-lock:v2\0";

/// Stateful production resolver. The Repair Vault client remains here until a
/// reserve succeeds, so an ambiguous reserve response retains the exact
/// version/reconciliation guard needed for an idempotent retry.
pub struct ProductionRescueFstabPreflightResolver {
    vault_client: Option<RepairVaultClient>,
}

impl ProductionRescueFstabPreflightResolver {
    pub const fn new() -> Self {
        Self {
            vault_client: Some(RepairVaultClient::new()),
        }
    }
}

impl Default for ProductionRescueFstabPreflightResolver {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Debug for ProductionRescueFstabPreflightResolver {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ProductionRescueFstabPreflightResolver")
            .field(
                "vault_client",
                &if self.vault_client.is_some() {
                    "[retained stateful client]"
                } else {
                    "[authority transferred]"
                },
            )
            .finish_non_exhaustive()
    }
}

/// Non-cloneable target authority retained from acquisition through approval.
pub struct ProductionRescueFstabTargetGuard {
    target: RescueTargetPhysicalParentGuard,
    lock_identity: String,
}

impl ProductionRescueFstabTargetGuard {
    pub fn physical_parent_fingerprint(&self) -> &str {
        self.target.physical_parent_fingerprint()
    }

    pub fn lock_identity(&self) -> &str {
        &self.lock_identity
    }

    /// Internal descriptor-bound authority for the future closed executor.
    #[allow(dead_code)]
    pub(crate) const fn inner(&self) -> &RescueTargetPhysicalParentGuard {
        &self.target
    }
}

impl fmt::Debug for ProductionRescueFstabTargetGuard {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ProductionRescueFstabTargetGuard")
            .field("target", &"[retained read-only target authority]")
            .field("lock_identity", &"[opaque domain-separated digest]")
            .finish()
    }
}

/// Reacquires a target after reboot exclusively through its approval-bound
/// stable recovery fingerprint. Every boot-local claim is accepted only as a
/// fresh claim from the root-owned handoff and is never compared with stale
/// IDs from the prior boot.
pub(crate) fn reacquire_target_for_recovery(
    intent: &RepairExecutionIntentV1,
    deadline: Instant,
) -> Result<ProductionRescueFstabTargetGuard, RescueFstabCapabilityResolutionError> {
    ensure_deadline(deadline)?;
    let request_id = fresh_request_id()?;
    let capability = reacquire_rescue_target_capability(
        &request_id,
        intent.target_recovery_fingerprint(),
        deadline,
    )
    .map_err(map_target_client_error)?;
    let target = capability
        .bind_physical_parent()
        .map_err(map_physical_parent_error)?;
    ensure_deadline(deadline)?;
    target.revalidate().map_err(map_physical_parent_error)?;
    let claims = target.target_claims();
    let lock_identity = lock_identity(claims);
    if claims.recovery_fingerprint() != intent.target_recovery_fingerprint()
        || lock_identity != intent.lock_identity()
    {
        return Err(RescueFstabCapabilityResolutionError::IdentityChanged);
    }
    Ok(ProductionRescueFstabTargetGuard {
        target,
        lock_identity,
    })
}

/// Non-cloneable live Repair Vault reservation. It retains both the stateful
/// authenticated client and the exact Reserved status needed for cancellation.
pub struct ProductionRescueFstabVaultReservation {
    client: RepairVaultClient,
    status: RepairBackupStatusPayload,
    reservation_binding_sha256: String,
}

impl ProductionRescueFstabVaultReservation {
    fn new(client: RepairVaultClient, status: RepairBackupStatusPayload) -> Self {
        let reservation_binding_sha256 = prefixed_sha256(status.draft_binding_sha256());
        Self {
            client,
            status,
            reservation_binding_sha256,
        }
    }

    pub(crate) fn status(&self) -> &RepairBackupStatusPayload {
        &self.status
    }

    /// Transfers the authenticated client and exact Vault status together to
    /// the future closed executor. No pathname or backup byte is introduced.
    #[allow(dead_code)]
    pub(crate) fn into_parts(self) -> (RepairVaultClient, RepairBackupStatusPayload) {
        (self.client, self.status)
    }
}

impl fmt::Debug for ProductionRescueFstabVaultReservation {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ProductionRescueFstabVaultReservation")
            .field("client", &"[authenticated stateful client]")
            .field("status", &self.status.state())
            .finish()
    }
}

impl RescueFstabVaultReservation for ProductionRescueFstabVaultReservation {
    fn reservation_id(&self) -> &str {
        self.status.reservation_id().as_str()
    }

    fn reservation_binding_sha256(&self) -> &str {
        &self.reservation_binding_sha256
    }

    fn cancel(mut self, deadline: Instant) -> Result<(), RescueFstabCapabilityResolutionError> {
        let reservation_id = self.status.reservation_id().clone();
        let draft_binding = self.status.draft_binding_sha256().clone();
        self.client
            .cancel(&reservation_id, &draft_binding, deadline)
            .map(|_| ())
            .map_err(map_vault_error)
    }
}

impl RescueFstabPreflightCapabilityResolver for ProductionRescueFstabPreflightResolver {
    type TargetGuard = ProductionRescueFstabTargetGuard;
    type VaultReservation = ProductionRescueFstabVaultReservation;

    fn acquire_target_guard(
        &mut self,
        request: &RescueFstabPrepareRequest,
        deadline: Instant,
    ) -> Result<Self::TargetGuard, RescueFstabCapabilityResolutionError> {
        ensure_deadline(deadline)?;
        let request_id = RequestId::parse(request.request_id())
            .map_err(|_| RescueFstabCapabilityResolutionError::Unavailable)?;
        let capability = acquire_rescue_target_capability(
            &request_id,
            request.scan_fingerprint(),
            request.target_fingerprint(),
            request.target_id(),
            deadline,
        )
        .map_err(map_target_client_error)?;
        let target = capability
            .bind_physical_parent()
            .map_err(map_physical_parent_error)?;
        ensure_deadline(deadline)?;
        validate_target_selection(request, target.target_claims())?;
        target.revalidate().map_err(map_physical_parent_error)?;
        ensure_deadline(deadline)?;
        let lock_identity = lock_identity(target.target_claims());
        Ok(ProductionRescueFstabTargetGuard {
            target,
            lock_identity,
        })
    }

    fn observe_under_target_guard(
        &mut self,
        request: &RescueFstabPrepareRequest,
        target_guard: &Self::TargetGuard,
        deadline: Instant,
    ) -> Result<TrustedRescueFstabObservation, RescueFstabCapabilityResolutionError> {
        ensure_deadline(deadline)?;
        validate_target_selection(request, target_guard.target.target_claims())?;
        target_guard
            .target
            .revalidate()
            .map_err(map_physical_parent_error)?;
        let observed = observe_rescue_fstab(&target_guard.target).map_err(map_observation_error)?;
        ensure_deadline(deadline)?;
        target_guard
            .target
            .revalidate()
            .map_err(map_physical_parent_error)?;
        let target = target_guard
            .target
            .selected_target_claims()
            .map_err(map_transaction_error)?;
        let resolved_target_fingerprint = target_guard
            .target
            .target_claims()
            .target_fingerprint()
            .to_owned();
        let (fstab_bytes, metadata, observed_uuids, evidence) = observed.into_parts();
        Ok(TrustedRescueFstabObservation::new(
            resolved_target_fingerprint,
            fstab_bytes,
            metadata,
            observed_uuids,
            target,
            evidence,
        ))
    }

    fn reserve_vault(
        &mut self,
        intent: &RescueFstabPreflightIntent,
        target_guard: &Self::TargetGuard,
        observation: &TrustedRescueFstabObservation,
        preview: &DisableMissingUuidPreview,
        deadline: Instant,
    ) -> Result<
        (Self::VaultReservation, BootVaultBackupCapability),
        RescueFstabCapabilityResolutionError,
    > {
        ensure_deadline(deadline)?;
        validate_target_binding(intent, target_guard.target.target_claims())?;
        target_guard
            .target
            .revalidate()
            .map_err(map_physical_parent_error)?;
        if preview.before_sha256() != intent.target_snapshot()
            || prefixed_digest(observation.fstab_bytes()) != intent.target_snapshot()
        {
            return Err(RescueFstabCapabilityResolutionError::IdentityChanged);
        }
        let draft = repair_backup_draft(intent, observation)?;
        let (initial_reserve_deadline, reconciliation_deadline) =
            reservation_operation_deadlines(deadline, Instant::now())?;
        let (client, status) = take_client_after_success(&mut self.vault_client, |client| {
            reserve_with_exact_reconciliation(
                &draft,
                initial_reserve_deadline,
                reconciliation_deadline,
                |draft, attempt_deadline| client.reserve(draft, attempt_deadline),
                thread::sleep,
            )
        })
        .map_err(map_vault_error)?;
        let reservation = ProductionRescueFstabVaultReservation::new(client, status);
        if let Err(error) = ensure_deadline(deadline).and_then(|()| {
            target_guard
                .target
                .revalidate()
                .map_err(map_physical_parent_error)
        }) {
            return fail_after_reservation(reservation, deadline, error);
        }
        let capability = match boot_vault_capability(reservation.status(), &draft) {
            Ok(capability) => capability,
            Err(error) => return fail_after_reservation(reservation, deadline, error),
        };
        Ok((reservation, capability))
    }

    fn target_guard_identity<'guard>(
        &self,
        target_guard: &'guard Self::TargetGuard,
    ) -> &'guard str {
        target_guard.lock_identity()
    }
}

fn repair_backup_draft(
    intent: &RescueFstabPreflightIntent,
    observation: &TrustedRescueFstabObservation,
) -> Result<RepairBackupDraft, RescueFstabCapabilityResolutionError> {
    let backup_size = u64::try_from(observation.fstab_bytes().len())
        .map_err(|_| RescueFstabCapabilityResolutionError::Unavailable)?;
    let required_capacity =
        bounded_capacity(backup_size).ok_or(RescueFstabCapabilityResolutionError::Unavailable)?;
    let target_fingerprint = parse_prefixed_sha256(intent.target_fingerprint())?;
    RepairBackupDraft::new(
        intent.session_id(),
        intent.target_id(),
        target_fingerprint,
        observation.target_recovery_fingerprint(),
        raw_digest(observation.fstab_bytes()),
        observation.metadata().canonical_sha256(),
        backup_size,
        required_capacity,
    )
    .map_err(|_| RescueFstabCapabilityResolutionError::Unavailable)
}

fn boot_vault_capability(
    status: &RepairBackupStatusPayload,
    draft: &RepairBackupDraft,
) -> Result<BootVaultBackupCapability, RescueFstabCapabilityResolutionError> {
    if status.state() != RepairBackupState::Reserved
        || status.draft_binding_sha256() != &draft.draft_binding_sha256()
        || status.backup_size() != draft.backup_size()
        || status.expected_backup_sha256() != draft.expected_backup_sha256()
        || status.metadata_sha256() != draft.metadata_sha256()
        || status.reserved_bytes() < draft.required_capacity_bytes()
    {
        return Err(RescueFstabCapabilityResolutionError::IdentityChanged);
    }
    BootVaultBackupCapability::new(
        status.vault_id(),
        status.reservation_id().as_str(),
        prefixed_sha256(status.draft_binding_sha256()),
        status.locator(),
        prefixed_sha256(status.vault_identity_fingerprint()),
        prefixed_sha256(status.physical_parent_fingerprint()),
        true,
        draft.required_capacity_bytes(),
        status.reserved_bytes(),
    )
    .map_err(map_transaction_error)
}

fn validate_target_binding(
    intent: &RescueFstabPreflightIntent,
    claims: &RescueTargetCapabilityClaims,
) -> Result<(), RescueFstabCapabilityResolutionError> {
    if claims.scan_fingerprint() != intent.scan_fingerprint()
        || claims.target_fingerprint() != intent.target_fingerprint()
        || claims.target_id() != intent.target_id()
    {
        return Err(RescueFstabCapabilityResolutionError::IdentityChanged);
    }
    Ok(())
}

fn validate_target_selection(
    request: &RescueFstabPrepareRequest,
    claims: &RescueTargetCapabilityClaims,
) -> Result<(), RescueFstabCapabilityResolutionError> {
    if claims.scan_fingerprint() != request.scan_fingerprint()
        || claims.target_fingerprint() != request.target_fingerprint()
        || claims.target_id() != request.target_id()
        || claims.request_id() != request.request_id()
    {
        return Err(RescueFstabCapabilityResolutionError::IdentityChanged);
    }
    Ok(())
}

fn bounded_capacity(size: u64) -> Option<u64> {
    (1..=REPAIR_BACKUP_CAPACITY_BYTES)
        .contains(&size)
        .then_some(REPAIR_BACKUP_CAPACITY_BYTES)
}

fn raw_digest(bytes: &[u8]) -> Sha256 {
    Sha256::parse(&format!("{:x}", Sha256Hasher::digest(bytes)))
        .expect("SHA-256 rendering is canonical")
}

fn prefixed_digest(bytes: &[u8]) -> String {
    format!("sha256:{:x}", Sha256Hasher::digest(bytes))
}

fn prefixed_sha256(value: &Sha256) -> String {
    format!("sha256:{}", value.as_str())
}

fn parse_prefixed_sha256(value: &str) -> Result<Sha256, RescueFstabCapabilityResolutionError> {
    value
        .strip_prefix("sha256:")
        .ok_or(RescueFstabCapabilityResolutionError::IdentityChanged)
        .and_then(|digest| {
            Sha256::parse(digest).map_err(|_| RescueFstabCapabilityResolutionError::IdentityChanged)
        })
}

fn lock_identity(claims: &RescueTargetCapabilityClaims) -> String {
    lock_identity_for_resource(claims.recovery_fingerprint(), RESOURCE_ID)
}

#[cfg(test)]
fn lock_identity_from_recovery_fingerprint(recovery_fingerprint: &str) -> String {
    lock_identity_for_resource(recovery_fingerprint, RESOURCE_ID)
}

fn lock_identity_for_resource(recovery_fingerprint: &str, resource_id: &str) -> String {
    let mut hasher = Sha256Hasher::new();
    hasher.update(LOCK_ID_DOMAIN);
    for value in [recovery_fingerprint, resource_id] {
        hasher.update((value.len() as u64).to_be_bytes());
        hasher.update(value.as_bytes());
    }
    format!("lock:{:x}", hasher.finalize())
}

/// Runs one reserve attempt without taking ownership first. Errors deliberately
/// leave the possibly-ambiguous client in `slot`; only a successful response
/// transfers the client into the live reservation guard.
fn take_client_after_success<T>(
    slot: &mut Option<RepairVaultClient>,
    operation: impl FnOnce(&mut RepairVaultClient) -> Result<T, RepairVaultClientError>,
) -> Result<(RepairVaultClient, T), RepairVaultClientError> {
    let result = operation(
        slot.as_mut()
            .ok_or(RepairVaultClientError::StateUnavailable)?,
    );
    match result {
        Ok(value) => {
            let client = slot
                .take()
                .ok_or(RepairVaultClientError::StateUnavailable)?;
            Ok((client, value))
        }
        Err(error) => Err(error),
    }
}

/// A lost reserve response is the only condition that enables retries here.
/// Every retry presents the exact immutable draft through the same stateful
/// client, so the Vault can return the already-minted reservation rather than
/// allocate unrelated capacity. Busy and repeated stale responses are bounded
/// by the reconciliation half of the reserve window.
fn reserve_with_exact_reconciliation<T>(
    draft: &RepairBackupDraft,
    initial_deadline: Instant,
    reconciliation_deadline: Instant,
    mut attempt: impl FnMut(&RepairBackupDraft, Instant) -> Result<T, RepairVaultClientError>,
    mut pause: impl FnMut(Duration),
) -> Result<T, RepairVaultClientError> {
    match attempt(draft, initial_deadline) {
        Err(RepairVaultClientError::ReconciliationRequired) => {}
        result => return result,
    }

    loop {
        reconciliation_deadline
            .checked_duration_since(Instant::now())
            .filter(|remaining| !remaining.is_zero())
            .ok_or(RepairVaultClientError::ReconciliationRequired)?;
        match attempt(draft, reconciliation_deadline) {
            Ok(value) => return Ok(value),
            Err(error) if retryable_ambiguous_reserve_error(error) => {
                let remaining = reconciliation_deadline
                    .checked_duration_since(Instant::now())
                    .filter(|remaining| !remaining.is_zero())
                    .ok_or(RepairVaultClientError::ReconciliationRequired)?;
                pause(RESERVATION_RECONCILIATION_POLL.min(remaining));
            }
            Err(error) => return Err(error),
        }
    }
}

fn retryable_ambiguous_reserve_error(error: RepairVaultClientError) -> bool {
    matches!(
        error,
        RepairVaultClientError::ReconciliationRequired
            | RepairVaultClientError::Remote(ErrorToken::Busy | ErrorToken::StaleState)
    )
}

fn fail_after_reservation<T>(
    reservation: ProductionRescueFstabVaultReservation,
    deadline: Instant,
    error: RescueFstabCapabilityResolutionError,
) -> Result<T, RescueFstabCapabilityResolutionError> {
    reservation.cancel(deadline)?;
    Err(error)
}

fn fresh_request_id() -> Result<RequestId, RescueFstabCapabilityResolutionError> {
    let mut random = [0_u8; 16];
    let mut offset = 0;
    while offset < random.len() {
        let count = getrandom(&mut random[offset..], GetRandomFlags::NONBLOCK)
            .map_err(|_| RescueFstabCapabilityResolutionError::Unavailable)?;
        if count == 0 {
            return Err(RescueFstabCapabilityResolutionError::Unavailable);
        }
        offset += count;
    }
    request_id_from_bytes(random)
}

fn request_id_from_bytes(
    random: [u8; 16],
) -> Result<RequestId, RescueFstabCapabilityResolutionError> {
    let mut value = String::with_capacity(38);
    value.push_str("R-");
    for (index, byte) in random.iter().enumerate() {
        if matches!(index, 4 | 6 | 8 | 10) {
            value.push('-');
        }
        write!(&mut value, "{byte:02x}")
            .map_err(|_| RescueFstabCapabilityResolutionError::Unavailable)?;
    }
    RequestId::parse(&value).map_err(|_| RescueFstabCapabilityResolutionError::Unavailable)
}

fn ensure_deadline(deadline: Instant) -> Result<(), RescueFstabCapabilityResolutionError> {
    deadline
        .checked_duration_since(Instant::now())
        .filter(|remaining| !remaining.is_zero())
        .map(|_| ())
        .ok_or(RescueFstabCapabilityResolutionError::TimedOut)
}

fn reservation_operation_deadlines(
    deadline: Instant,
    now: Instant,
) -> Result<(Instant, Instant), RescueFstabCapabilityResolutionError> {
    let reconciliation_deadline = deadline
        .checked_sub(RESERVATION_CLEANUP_BUDGET)
        .ok_or(RescueFstabCapabilityResolutionError::TimedOut)?;
    let remaining = reconciliation_deadline
        .checked_duration_since(now)
        .filter(|remaining| !remaining.is_zero())
        .ok_or(RescueFstabCapabilityResolutionError::TimedOut)?;
    let initial_window = remaining / 2;
    if initial_window.is_zero() {
        return Err(RescueFstabCapabilityResolutionError::TimedOut);
    }
    let initial_deadline = now
        .checked_add(initial_window)
        .ok_or(RescueFstabCapabilityResolutionError::TimedOut)?;
    Ok((initial_deadline, reconciliation_deadline))
}

fn map_target_client_error(
    error: TargetCapabilityClientError,
) -> RescueFstabCapabilityResolutionError {
    match error {
        TargetCapabilityClientError::TimedOut => RescueFstabCapabilityResolutionError::TimedOut,
        TargetCapabilityClientError::TargetRejected(
            crate::target_capability_client::TargetCapabilityErrorToken::TargetTimedOut,
        ) => RescueFstabCapabilityResolutionError::TimedOut,
        TargetCapabilityClientError::TargetRejected(
            crate::target_capability_client::TargetCapabilityErrorToken::TargetChanged,
        ) => RescueFstabCapabilityResolutionError::IdentityChanged,
        _ => RescueFstabCapabilityResolutionError::Unavailable,
    }
}

fn map_physical_parent_error(
    error: TargetPhysicalParentError,
) -> RescueFstabCapabilityResolutionError {
    match error {
        TargetPhysicalParentError::IdentityChanged => {
            RescueFstabCapabilityResolutionError::IdentityChanged
        }
        _ => RescueFstabCapabilityResolutionError::Unavailable,
    }
}

fn map_observation_error(
    error: RescueFstabObservationError,
) -> RescueFstabCapabilityResolutionError {
    match error {
        RescueFstabObservationError::TargetChanged => {
            RescueFstabCapabilityResolutionError::IdentityChanged
        }
        _ => RescueFstabCapabilityResolutionError::Unavailable,
    }
}

fn map_vault_error(error: RepairVaultClientError) -> RescueFstabCapabilityResolutionError {
    match error {
        RepairVaultClientError::TimedOut => RescueFstabCapabilityResolutionError::TimedOut,
        RepairVaultClientError::Remote(
            kernaid_protocol::rescue_vault::ErrorToken::MediaChanged,
        ) => RescueFstabCapabilityResolutionError::IdentityChanged,
        _ => RescueFstabCapabilityResolutionError::Unavailable,
    }
}

fn map_transaction_error(
    _error: CandidateTransactionError,
) -> RescueFstabCapabilityResolutionError {
    RescueFstabCapabilityResolutionError::Unavailable
}

#[cfg(test)]
mod tests {
    use super::*;
    use kernaid_linux_pack::rescue_fstab_transaction_candidate::{
        CandidateEvidenceBinding, SelectedTargetCapability,
    };
    use kernaid_protocol::{
        rescue_repair::{
            RESCUE_FSTAB_EVIDENCE_IDS, RESCUE_FSTAB_RESOURCE_ID, RescueFstabEvidenceBinding,
        },
        rescue_repair_vault::{RepairFileMetadataV1, RepairReservationId},
    };
    use std::collections::BTreeSet;

    fn hash(character: char) -> String {
        format!("sha256:{}", character.to_string().repeat(64))
    }

    fn raw_hash(character: char) -> Sha256 {
        Sha256::parse(&character.to_string().repeat(64)).expect("SHA-256")
    }

    fn intent(snapshot: String) -> RescueFstabPreflightIntent {
        RescueFstabPreflightIntent::new(
            "S-test",
            "P-test",
            hash('1'),
            snapshot,
            RESCUE_FSTAB_RESOURCE_ID,
            format!("target:{}", "2".repeat(64)),
            format!("scan:{}", "3".repeat(64)),
            [
                RescueFstabEvidenceBinding::new(RESCUE_FSTAB_EVIDENCE_IDS[0], hash('4'))
                    .expect("evidence"),
                RescueFstabEvidenceBinding::new(RESCUE_FSTAB_EVIDENCE_IDS[1], hash('5'))
                    .expect("evidence"),
            ],
        )
        .expect("intent")
    }

    fn observation(bytes: &[u8]) -> TrustedRescueFstabObservation {
        TrustedRescueFstabObservation::new(
            hash('1'),
            bytes.to_vec(),
            RepairFileMetadataV1::new(0o644, 0, 0).expect("metadata"),
            BTreeSet::new(),
            SelectedTargetCapability::new(
                format!("target:{}", "2".repeat(64)),
                format!("scan:{}", "3".repeat(64)),
                format!("recovery:{}", "7".repeat(64)),
                hash('6'),
            )
            .expect("target"),
            [
                CandidateEvidenceBinding::new(RESCUE_FSTAB_EVIDENCE_IDS[0], hash('4'))
                    .expect("evidence"),
                CandidateEvidenceBinding::new(RESCUE_FSTAB_EVIDENCE_IDS[1], hash('5'))
                    .expect("evidence"),
            ],
        )
    }

    #[test]
    fn draft_hashes_exact_bytes_metadata_and_four_kib_capacity() {
        let bytes = b"UUID=aaaa / ext4 defaults 0 1\n";
        let observation = observation(bytes);
        let intent = intent(prefixed_digest(bytes));
        let draft = repair_backup_draft(&intent, &observation).expect("draft");
        assert_eq!(draft.session_id(), "S-test");
        assert_eq!(draft.target_id(), intent.target_id());
        assert_eq!(draft.target_fingerprint(), &raw_hash('1'));
        assert_eq!(draft.expected_backup_sha256(), &raw_digest(bytes));
        assert_eq!(
            draft.metadata_sha256(),
            &observation.metadata().canonical_sha256()
        );
        assert_eq!(draft.backup_size(), bytes.len() as u64);
        assert_eq!(draft.required_capacity_bytes(), 4096);
        assert_eq!(bounded_capacity(4096), Some(4096));
        assert_eq!(bounded_capacity(4097), None);
        assert_eq!(bounded_capacity(0), None);
    }

    #[test]
    fn reservation_deadlines_preserve_cleanup_and_split_reserve_window() {
        let now = Instant::now();
        let deadline = now + Duration::from_secs(102);
        let (initial_deadline, reconciliation_deadline) =
            reservation_operation_deadlines(deadline, now).expect("reservation deadlines");

        assert_eq!(reconciliation_deadline, now + Duration::from_secs(100));
        assert_eq!(initial_deadline, now + Duration::from_secs(50));
        assert_eq!(
            deadline.duration_since(reconciliation_deadline),
            RESERVATION_CLEANUP_BUDGET
        );
    }

    #[test]
    fn ambiguous_reserve_retries_same_draft_through_busy_and_stale() {
        let bytes = b"original fstab\n";
        let observation = observation(bytes);
        let intent = intent(prefixed_digest(bytes));
        let draft = repair_backup_draft(&intent, &observation).expect("draft");
        let now = Instant::now();
        let initial_deadline = now + Duration::from_secs(1);
        let reconciliation_deadline = now + Duration::from_secs(5);
        let mut attempts = Vec::new();
        let mut pauses = Vec::new();

        let result = reserve_with_exact_reconciliation(
            &draft,
            initial_deadline,
            reconciliation_deadline,
            |observed_draft, attempt_deadline| {
                assert!(std::ptr::eq(observed_draft, &draft));
                attempts.push(attempt_deadline);
                match attempts.len() {
                    1 => Err(RepairVaultClientError::ReconciliationRequired),
                    2 => Err(RepairVaultClientError::Remote(ErrorToken::StaleState)),
                    3 => Err(RepairVaultClientError::Remote(ErrorToken::Busy)),
                    4 => Ok(7_u8),
                    _ => Err(RepairVaultClientError::StateUnavailable),
                }
            },
            |duration| pauses.push(duration),
        );

        assert_eq!(result, Ok(7));
        assert_eq!(
            attempts,
            [
                initial_deadline,
                reconciliation_deadline,
                reconciliation_deadline,
                reconciliation_deadline,
            ]
        );
        assert_eq!(
            pauses,
            [
                RESERVATION_RECONCILIATION_POLL,
                RESERVATION_RECONCILIATION_POLL,
            ]
        );
    }

    #[test]
    fn definitive_initial_reserve_error_is_not_retried() {
        let bytes = b"original fstab\n";
        let observation = observation(bytes);
        let intent = intent(prefixed_digest(bytes));
        let draft = repair_backup_draft(&intent, &observation).expect("draft");
        let now = Instant::now();
        let mut attempts = 0;
        let mut pauses = 0;
        let result: Result<(), _> = reserve_with_exact_reconciliation(
            &draft,
            now + Duration::from_secs(1),
            now + Duration::from_secs(2),
            |_, _| {
                attempts += 1;
                Err(RepairVaultClientError::Remote(ErrorToken::Locked))
            },
            |_| pauses += 1,
        );

        assert_eq!(
            result,
            Err(RepairVaultClientError::Remote(ErrorToken::Locked))
        );
        assert_eq!(attempts, 1);
        assert_eq!(pauses, 0);
    }

    #[test]
    fn reserved_status_maps_to_path_free_plan_capability() {
        let bytes = b"original fstab\n";
        let observation = observation(bytes);
        let intent = intent(prefixed_digest(bytes));
        let draft = repair_backup_draft(&intent, &observation).expect("draft");
        let reservation =
            RepairReservationId::parse("B-0123456789abcdef0123456789abcdef").expect("reservation");
        let status = RepairBackupStatusPayload::reserved(
            reservation.clone(),
            draft.draft_binding_sha256(),
            reservation.locator(),
            "V-0123456789abcdef0123456789abcdef",
            raw_hash('7'),
            raw_hash('8'),
            4096,
            draft.backup_size(),
            draft.expected_backup_sha256().clone(),
            draft.metadata_sha256().clone(),
        )
        .expect("reserved status");
        let capability = boot_vault_capability(&status, &draft).expect("capability");
        let reservation_guard =
            ProductionRescueFstabVaultReservation::new(RepairVaultClient::new(), status);
        assert_eq!(capability.reservation_id(), reservation.as_str());
        assert_eq!(
            capability.reservation_binding_sha256(),
            reservation_guard.reservation_binding_sha256()
        );
        assert_eq!(
            reservation_guard.reservation_id(),
            capability.reservation_id()
        );
        assert!(
            reservation_guard
                .reservation_binding_sha256()
                .starts_with("sha256:")
        );
        assert_eq!(capability.backup_locator(), reservation.locator());
        assert_eq!(capability.required_capacity_bytes(), 4096);
        assert_eq!(capability.reserved_capacity_bytes(), 4096);
        assert!(capability.authenticated_and_unlocked());
    }

    #[test]
    fn lock_is_stable_across_requests_and_bound_to_target_resource() {
        let first_request = request_id_from_bytes([0xabu8; 16]).expect("request ID");
        let second_request = request_id_from_bytes([0xcdu8; 16]).expect("request ID");
        assert_ne!(first_request, second_request);
        assert_eq!(
            first_request.as_str(),
            "R-abababab-abab-abab-abab-abababababab"
        );

        let recovery_fingerprint = format!("recovery:{}", "7".repeat(64));
        let first = lock_identity_from_recovery_fingerprint(&recovery_fingerprint);
        let same_target_new_request =
            lock_identity_from_recovery_fingerprint(&recovery_fingerprint);
        let changed_recovery =
            lock_identity_from_recovery_fingerprint(&format!("recovery:{}", "8".repeat(64)));
        let changed_resource = lock_identity_for_resource(
            &recovery_fingerprint,
            "rescue:selected-linux-root:other-resource",
        );
        assert_eq!(first.len(), 69);
        assert!(first.starts_with("lock:"));
        assert_eq!(first, same_target_new_request);
        assert_ne!(first, changed_recovery);
        assert_ne!(first, changed_resource);
        assert!(!first.contains('/'));
        assert!(
            first
                .strip_prefix("lock:")
                .expect("prefix")
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        );
    }

    #[test]
    fn expired_reconciliation_keeps_client_slot_ambiguous() {
        let bytes = b"original fstab\n";
        let observation = observation(bytes);
        let intent = intent(prefixed_digest(bytes));
        let draft = repair_backup_draft(&intent, &observation).expect("draft");
        let mut resolver = ProductionRescueFstabPreflightResolver::default();
        let expired = Instant::now();
        let mut attempts = 0;
        let mut pauses = 0;
        let result = take_client_after_success::<()>(&mut resolver.vault_client, |_client| {
            reserve_with_exact_reconciliation(
                &draft,
                expired,
                expired,
                |observed_draft, _| {
                    assert!(std::ptr::eq(observed_draft, &draft));
                    attempts += 1;
                    Err(RepairVaultClientError::ReconciliationRequired)
                },
                |_| pauses += 1,
            )
        });

        assert_eq!(
            result.err(),
            Some(RepairVaultClientError::ReconciliationRequired)
        );
        assert_eq!(attempts, 1);
        assert_eq!(pauses, 0);
        assert!(resolver.vault_client.is_some());
    }
}
