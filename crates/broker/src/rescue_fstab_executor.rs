//! Closed, off-default transaction engine for the Phase 1 Rescue mutations.
//!
//! The public entrypoint accepts no pathname, device name, command, or raw
//! replacement supplied by a client. It consumes the broker-owned approved
//! authority, makes the exact pre-change bytes and a Pending transaction
//! durable in the Repair Vault, and only then consumes the root helper's
//! single-use detached writable ext4 mount capability.

#[cfg(feature = "rescue-crypttab-production-candidate")]
use crate::rescue_crypttab_candidate::{
    ApprovedRescueCrypttabExecutionParts, ApprovedRescueCrypttabTransaction,
};
use crate::{
    repair_vault_client::{RepairBackupBytes, RepairVaultClient, RepairVaultClientError},
    rescue_fstab_candidate::{
        ApprovedRescueFstabExecutionParts, ApprovedRescueFstabTransaction,
        RescueFstabCapabilityResolutionError, RescueFstabVaultReservation,
    },
    rescue_fstab_preflight_resolver::{
        ProductionRescueFstabTargetGuard, ProductionRescueFstabVaultReservation,
        reacquire_target_for_recovery,
    },
    target_write_capability_client::{
        RescueTargetRollbackWriteMountCapability, RescueTargetWriteMountCapability,
        TargetWriteCapabilityClientError, acquire_pending_rollback_target_write_mount,
        acquire_pending_target_write_mount,
    },
};
use kernaid_protocol::{
    rescue_repair_vault::{
        RepairBackupBinding, RepairBackupState, RepairBackupStatusPayload, RepairExecutionIntentV1,
        RepairFileMetadataV1, RepairReservationId, RepairResourceV1, RepairRollbackBindingV1,
        RepairRollbackId, RepairRollbackResolution, RepairRollbackResolutionOutcome,
        RepairRollbackStatusSelector, RepairRollbackTransactionStatusPayload,
        RepairTransactionPhase, RepairTransactionResolution, RepairTransactionResolutionOutcome,
        RepairTransactionStatusPayload, RepairTransactionStatusSelector,
        RepairVaultLiveIdentityPayload, repair_resource_from_transaction,
    },
    rescue_vault::{ErrorToken, Sha256},
};
use rustix::{
    fd::{AsFd, BorrowedFd, OwnedFd},
    fs::{
        self as rfs, AtFlags, FileType, FlockOperation, Gid, Mode, OFlags, RenameFlags,
        ResolveFlags, Uid,
    },
};
use sha2::{Digest, Sha256 as Sha256Hasher};
use std::{
    fs::File,
    io::{Read, Seek, SeekFrom, Write},
    sync::{Mutex, MutexGuard, TryLockError},
    thread,
    time::{Duration, Instant},
};
use zeroize::Zeroizing;

const FSTAB_RESOURCE: &str = "fstab";
const CRYPTTAB_RESOURCE: &str = "crypttab";
const ETC_DIRECTORY: &str = "etc";
const REPAIR_LOCK_DIRECTORY: &str = "/run/lock/kernaid-repair";
const MAX_REPAIR_RESOURCE_BYTES: usize = 1024 * 1024;
const NONCANONICAL_METADATA_DOMAIN: &[u8] =
    b"kernaid:rescue-fstab:observed-noncanonical-metadata:v1\0";
const SAFETY_CLEANUP_BUDGET: Duration = Duration::from_secs(30);
const RESOLUTION_BUDGET: Duration = Duration::from_secs(10);
const LOCK_POLL: Duration = Duration::from_millis(5);
const VAULT_RECOVERY_POLL: Duration = Duration::from_millis(250);

static PROCESS_EXECUTOR_LOCK: Mutex<()> = Mutex::new(());

/// Closed QEMU qualification seam for the production candidate. The only
/// accepted modes are compiled into the candidate and enter at durability
/// boundaries that the exact-image gate must exercise. Ordinary candidate
/// boots always use `None`; default/stable broker builds do not compile this
/// module at all.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) enum RescueFstabQualificationFault {
    #[default]
    None,
    TerminateAfterPending,
    FailAfterInstalled,
}

/// Closed result of a transaction which reached a durable terminal record.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RescueFstabExecutionOutcome {
    Committed,
    ClosedBeforeUnchanged,
    ClosedBeforeRestored,
    ManualReconciliationRequired,
}

/// Path-free receipt for the durable transaction result.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RescueFstabExecutionReceipt {
    outcome: RescueFstabExecutionOutcome,
    reservation_id: String,
    transaction_binding_sha256: String,
    initial_failure: Option<RescueFstabExecutionError>,
}

impl RescueFstabExecutionReceipt {
    pub const fn outcome(&self) -> RescueFstabExecutionOutcome {
        self.outcome
    }

    pub fn reservation_id(&self) -> &str {
        &self.reservation_id
    }

    pub fn transaction_binding_sha256(&self) -> &str {
        &self.transaction_binding_sha256
    }

    pub const fn initial_failure(&self) -> Option<RescueFstabExecutionError> {
        self.initial_failure
    }

    pub(crate) fn with_initial_failure(mut self, failure: RescueFstabExecutionError) -> Self {
        if matches!(
            self.outcome,
            RescueFstabExecutionOutcome::ClosedBeforeUnchanged
                | RescueFstabExecutionOutcome::ClosedBeforeRestored
        ) {
            self.initial_failure = Some(failure);
        }
        self
    }
}

/// Sanitized execution failures. An error after persistence means the durable
/// Pending transaction remains the authority for recovery.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RescueFstabExecutionError {
    InvalidAuthority,
    /// Rollback approval was not persisted and no child transaction exists.
    AuthorizationNotPersisted,
    TargetChanged,
    LockUnavailable,
    TimedOut,
    VaultUnavailable,
    VaultReconciliationRequired,
    DetachedMountUnavailable,
    UnsafeTarget,
    MutationFailed,
    RecoveryUnavailable,
    RecoveryRequired,
}

impl std::fmt::Display for RescueFstabExecutionError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(match self {
            Self::InvalidAuthority => "invalid approved repair authority",
            Self::AuthorizationNotPersisted => "rollback approval was not persisted",
            Self::TargetChanged => "repair target identity changed",
            Self::LockUnavailable => "repair target is already locked",
            Self::TimedOut => "repair transaction deadline expired",
            Self::VaultUnavailable => "repair Vault unavailable",
            Self::VaultReconciliationRequired => "repair Vault reconciliation required",
            Self::DetachedMountUnavailable => "private repair mount unavailable",
            Self::UnsafeTarget => "repair target is unsafe",
            Self::MutationFailed => "repair mutation failed",
            Self::RecoveryUnavailable => "durable repair recovery unavailable",
            Self::RecoveryRequired => "durable repair recovery required",
        })
    }
}

impl std::error::Error for RescueFstabExecutionError {}

/// Broker-owned rollback preparation authority. The source receipt and backup
/// have been reread from the authenticated Vault, while `target` retains the
/// freshly reacquired read-only mount used to prove the exact installed After
/// state before approval.
pub struct PreparedRescueFstabRollback {
    vault_client: RepairVaultClient,
    source: RepairTransactionStatusPayload,
    backup: RepairBackupBytes,
    target: ProductionRescueFstabTargetGuard,
    live_vault: RepairVaultLiveIdentityPayload,
    target_fingerprint: String,
}

impl PreparedRescueFstabRollback {
    pub fn source(&self) -> &RepairTransactionStatusPayload {
        &self.source
    }

    pub fn target_fingerprint(&self) -> &str {
        &self.target_fingerprint
    }
}

/// Approved rollback authority after Core approval and durable child creation.
/// It is non-cloneable and can be consumed only by the closed executor below.
pub struct ApprovedRescueFstabRollback {
    vault_client: RepairVaultClient,
    pending: RepairRollbackTransactionStatusPayload,
    backup: RepairBackupBytes,
    target: ProductionRescueFstabTargetGuard,
    live_vault: RepairVaultLiveIdentityPayload,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RescueFstabRollbackExecutionOutcome {
    RolledBackOriginal,
    ManualReconciliationRequired,
}

/// Path-free terminal receipt for the durable rollback child.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RescueFstabRollbackExecutionReceipt {
    outcome: RescueFstabRollbackExecutionOutcome,
    rollback_id: String,
    rollback_transaction_binding_sha256: String,
    source_reservation_id: String,
    source_transaction_binding_sha256: String,
}

impl RescueFstabRollbackExecutionReceipt {
    pub const fn outcome(&self) -> RescueFstabRollbackExecutionOutcome {
        self.outcome
    }

    pub fn rollback_id(&self) -> &str {
        &self.rollback_id
    }

    pub fn rollback_transaction_binding_sha256(&self) -> &str {
        &self.rollback_transaction_binding_sha256
    }

    pub fn source_reservation_id(&self) -> &str {
        &self.source_reservation_id
    }

    pub fn source_transaction_binding_sha256(&self) -> &str {
        &self.source_transaction_binding_sha256
    }
}

/// Authenticates one exact committed repair receipt, rereads its backup, and
/// retains a freshly reacquired read-only target proven to still be in the
/// installed `After` state. No rollback child or write authority exists yet.
pub fn prepare_rescue_fstab_rollback(
    source_reservation_id: &str,
    source_transaction_binding_sha256: &str,
    deadline: Instant,
) -> Result<PreparedRescueFstabRollback, RescueFstabExecutionError> {
    ensure_deadline(deadline)?;
    let reservation_id = RepairReservationId::parse(source_reservation_id)
        .map_err(|_| RescueFstabExecutionError::InvalidAuthority)?;
    let transaction_binding_sha256 = parse_prefixed_sha256(source_transaction_binding_sha256)?;
    let mut vault_client = RepairVaultClient::new();

    let unresolved = vault_client
        .rollback_transaction_status(&RepairRollbackStatusSelector::pending_singleton(), deadline)
        .map_err(map_vault_error)?;
    if unresolved.transaction().is_some() {
        return Err(RescueFstabExecutionError::RecoveryRequired);
    }

    let source_selector =
        RepairTransactionStatusSelector::exact(reservation_id, transaction_binding_sha256);
    let source_result = vault_client
        .transaction_status(&source_selector, deadline)
        .map_err(map_vault_error)?;
    let source = source_result
        .transaction()
        .cloned()
        .ok_or(RescueFstabExecutionError::InvalidAuthority)?;
    validate_committed_rollback_source(&source)?;

    let retrieved = vault_client
        .get(source.backup(), deadline)
        .map_err(map_vault_error)?;
    if retrieved.status() != source.backup() {
        return Err(RescueFstabExecutionError::VaultReconciliationRequired);
    }
    let intent = source_intent(&source)?;
    ensure_exact_bytes(retrieved.bytes(), intent.before_sha256())?;

    let live_vault = vault_client
        .live_identity(deadline)
        .map_err(map_vault_error)?;
    validate_live_vault(&source, &live_vault)?;
    let target = reacquire_target_for_recovery(intent, deadline).map_err(map_capability_error)?;
    validate_target_vault_separation(&target, &live_vault)?;

    let _process_lock = acquire_process_lock(deadline)?;
    let _target_lock = acquire_target_lock(&target, deadline)?;
    target
        .inner()
        .revalidate()
        .map_err(|_| RescueFstabExecutionError::TargetChanged)?;
    let locked_live_vault = vault_client
        .live_identity(deadline)
        .map_err(map_vault_error)?;
    if locked_live_vault != live_vault {
        return Err(RescueFstabExecutionError::VaultReconciliationRequired);
    }
    validate_target_vault_separation(&target, &locked_live_vault)?;
    let (state, _) = classify_with_retained_read_mount(&target, intent)?;
    if state != ExactTargetState::After {
        return Err(RescueFstabExecutionError::TargetChanged);
    }

    let target_fingerprint = target
        .inner()
        .target_claims()
        .target_fingerprint()
        .to_owned();
    Ok(PreparedRescueFstabRollback {
        vault_client,
        source,
        backup: retrieved.into_bytes(),
        target,
        live_vault,
        target_fingerprint,
    })
}

/// Consumes a fresh Core-approved rollback binding and durably creates the
/// child transaction. A lost begin response is reconciled by exact child ID;
/// the begin mutation itself is never repeated.
pub fn authorize_prepared_rescue_fstab_rollback(
    mut prepared: PreparedRescueFstabRollback,
    rollback_id: &str,
    binding: RepairRollbackBindingV1,
    deadline: Instant,
) -> Result<ApprovedRescueFstabRollback, RescueFstabExecutionError> {
    ensure_deadline(deadline).map_err(authorization_not_persisted)?;
    let rollback_id = RepairRollbackId::parse(rollback_id)
        .map_err(|_| RescueFstabExecutionError::AuthorizationNotPersisted)?;
    binding
        .validate_against(&prepared.source)
        .map_err(|_| RescueFstabExecutionError::AuthorizationNotPersisted)?;
    let expected = RepairRollbackTransactionStatusPayload::pending(
        rollback_id.clone(),
        prepared.source.clone(),
        binding.clone(),
    )
    .map_err(|_| RescueFstabExecutionError::AuthorizationNotPersisted)?;

    let _process_lock = acquire_process_lock(deadline).map_err(authorization_not_persisted)?;
    let _target_lock =
        acquire_target_lock(&prepared.target, deadline).map_err(authorization_not_persisted)?;
    prepared
        .target
        .inner()
        .revalidate()
        .map_err(|_| RescueFstabExecutionError::AuthorizationNotPersisted)?;
    let current_source =
        lookup_exact_source(&mut prepared.vault_client, &prepared.source, deadline)
            .map_err(authorization_not_persisted)?;
    if current_source != prepared.source {
        return Err(RescueFstabExecutionError::AuthorizationNotPersisted);
    }
    let locked_live_vault = prepared
        .vault_client
        .live_identity(deadline)
        .map_err(map_vault_error)
        .map_err(authorization_not_persisted)?;
    if locked_live_vault != prepared.live_vault {
        return Err(RescueFstabExecutionError::AuthorizationNotPersisted);
    }
    validate_target_vault_separation(&prepared.target, &locked_live_vault)
        .map_err(authorization_not_persisted)?;
    let intent = source_intent(&prepared.source).map_err(authorization_not_persisted)?;
    let (state, _) = classify_with_retained_read_mount(&prepared.target, intent)
        .map_err(authorization_not_persisted)?;
    if state != ExactTargetState::After {
        return Err(RescueFstabExecutionError::AuthorizationNotPersisted);
    }

    let pending = match prepared.vault_client.begin_rollback_transaction(
        &prepared.source,
        &rollback_id,
        &binding,
        deadline,
    ) {
        Ok(status) => status,
        Err(RepairVaultClientError::ReconciliationRequired) => {
            let result = prepared
                .vault_client
                .rollback_transaction_status(
                    &RepairRollbackStatusSelector::for_status(&expected),
                    deadline,
                )
                .map_err(map_vault_error)?;
            result
                .transaction()
                .cloned()
                .ok_or(RescueFstabExecutionError::VaultReconciliationRequired)?
        }
        Err(error) => return Err(map_vault_error(error)),
    };
    if pending != expected || pending.phase() != RepairTransactionPhase::Pending {
        return Err(RescueFstabExecutionError::VaultReconciliationRequired);
    }
    Ok(ApprovedRescueFstabRollback {
        vault_client: prepared.vault_client,
        pending,
        backup: prepared.backup,
        target: prepared.target,
        live_vault: prepared.live_vault,
    })
}

/// Executes one already durable rollback child. The only writable mount is
/// acquired for an exact `After` state; exact `Before` closes without a write,
/// while any third state is durably blocked for manual reconciliation.
pub fn execute_approved_rescue_fstab_rollback(
    approved: ApprovedRescueFstabRollback,
    deadline: Instant,
) -> Result<RescueFstabRollbackExecutionReceipt, RescueFstabExecutionError> {
    let operation_deadline = reserve_cleanup_window(deadline)?;
    reconcile_pending_rescue_fstab_rollback(
        approved.vault_client,
        approved.pending,
        approved.backup,
        approved.target,
        approved.live_vault,
        operation_deadline,
        deadline,
    )
}

/// Reconciles the sole unresolved rollback before ordinary repair recovery.
/// `None` means there is no rollback child and the caller may then inspect the
/// legacy repair Pending singleton.
pub fn recover_pending_rescue_fstab_rollback(
    deadline: Instant,
) -> Result<Option<RescueFstabRollbackExecutionReceipt>, RescueFstabExecutionError> {
    let operation_deadline = reserve_cleanup_window(deadline)?;
    let mut vault_client = RepairVaultClient::new();
    let result = loop {
        match vault_client.rollback_transaction_status(
            &RepairRollbackStatusSelector::pending_singleton(),
            operation_deadline,
        ) {
            Ok(result) => break result,
            Err(error) if recovery_status_retryable(error) => {
                ensure_deadline(operation_deadline)?;
                thread::sleep(
                    VAULT_RECOVERY_POLL
                        .min(operation_deadline.saturating_duration_since(Instant::now())),
                );
            }
            Err(error) => return Err(map_vault_error(error)),
        }
    };
    let Some(pending) = result.transaction().cloned() else {
        return Ok(None);
    };
    if !matches!(
        pending.phase(),
        RepairTransactionPhase::Pending | RepairTransactionPhase::ManualReconciliationRequired
    ) {
        return Err(RescueFstabExecutionError::VaultReconciliationRequired);
    }
    let source = pending.source().clone();
    validate_committed_rollback_source(&source)?;
    let retrieved = vault_client
        .get(source.backup(), operation_deadline)
        .map_err(map_vault_error)?;
    if retrieved.status() != source.backup() {
        return Err(RescueFstabExecutionError::VaultReconciliationRequired);
    }
    ensure_exact_bytes(retrieved.bytes(), source_intent(&source)?.before_sha256())?;
    let live_vault = vault_client
        .live_identity(operation_deadline)
        .map_err(map_vault_error)?;
    validate_live_vault(&source, &live_vault)?;
    let target = reacquire_target_for_recovery(source_intent(&source)?, operation_deadline)
        .map_err(map_capability_error)?;
    validate_target_vault_separation(&target, &live_vault)?;

    reconcile_pending_rescue_fstab_rollback(
        vault_client,
        pending,
        retrieved.into_bytes(),
        target,
        live_vault,
        operation_deadline,
        deadline,
    )
    .map(Some)
}

fn reconcile_pending_rescue_fstab_rollback(
    mut vault_client: RepairVaultClient,
    pending: RepairRollbackTransactionStatusPayload,
    backup: RepairBackupBytes,
    target: ProductionRescueFstabTargetGuard,
    live_vault: RepairVaultLiveIdentityPayload,
    operation_deadline: Instant,
    resolution_deadline: Instant,
) -> Result<RescueFstabRollbackExecutionReceipt, RescueFstabExecutionError> {
    if !matches!(
        pending.phase(),
        RepairTransactionPhase::Pending | RepairTransactionPhase::ManualReconciliationRequired
    ) {
        return rollback_receipt_from_status(&pending);
    }
    validate_committed_rollback_source(pending.source())?;
    let intent = source_intent(pending.source())?;
    ensure_exact_bytes(backup.as_slice(), intent.before_sha256())?;

    let _process_lock = acquire_process_lock(operation_deadline)?;
    let _target_lock = acquire_target_lock(&target, operation_deadline)?;
    target
        .inner()
        .revalidate()
        .map_err(|_| RescueFstabExecutionError::TargetChanged)?;
    let current = vault_client
        .rollback_transaction_status(
            &RepairRollbackStatusSelector::for_status(&pending),
            operation_deadline,
        )
        .map_err(map_vault_error)?;
    let current = current
        .transaction()
        .cloned()
        .ok_or(RescueFstabExecutionError::VaultReconciliationRequired)?;
    if current != pending {
        return if current.same_transaction(&pending) && current.resolution().is_some() {
            rollback_receipt_from_status(&current)
        } else {
            Err(RescueFstabExecutionError::VaultReconciliationRequired)
        };
    }
    let locked_live_vault = vault_client
        .live_identity(operation_deadline)
        .map_err(map_vault_error)?;
    if locked_live_vault != live_vault {
        return Err(RescueFstabExecutionError::VaultReconciliationRequired);
    }
    validate_target_vault_separation(&target, &locked_live_vault)?;

    let (state, observation) = classify_with_retained_read_mount(&target, intent)?;
    let closure = match state {
        ExactTargetState::Before => RollbackTargetClosure {
            outcome: RepairRollbackResolutionOutcome::RolledBackBefore,
            observation,
            cleanup_verified: true,
        },
        ExactTargetState::Third
            if pending.phase() == RepairTransactionPhase::ManualReconciliationRequired =>
        {
            return rollback_receipt_from_status(&pending);
        }
        ExactTargetState::Third => RollbackTargetClosure {
            outcome: RepairRollbackResolutionOutcome::ManualReconciliationRequired,
            observation,
            cleanup_verified: true,
        },
        ExactTargetState::After
            if pending.phase() == RepairTransactionPhase::ManualReconciliationRequired =>
        {
            return rollback_receipt_from_status(&pending);
        }
        ExactTargetState::After => {
            drop(target);
            let write_mount =
                acquire_pending_rollback_target_write_mount(&pending, operation_deadline)
                    .map_err(map_write_capability_error)?;
            refresh_pending_after_rollback_write_lease(
                &mut vault_client,
                &pending,
                operation_deadline,
            )?;
            restore_rollback_target(
                write_mount,
                backup.as_slice(),
                intent,
                &pending,
                operation_deadline,
            )?
        }
    };
    let resolution = RepairRollbackResolution::new(
        closure.outcome,
        closure.observation.resource_sha256,
        closure.observation.metadata_sha256,
        closure.cleanup_verified,
        pending.source(),
    )
    .map_err(|_| RescueFstabExecutionError::RecoveryUnavailable)?;
    let resolved = resolve_pending_rollback(
        &mut vault_client,
        &pending,
        &resolution,
        resolution_deadline,
    )?;
    rollback_receipt_from_status(&resolved)
}

/// Consumes one exact approved candidate. Backup durability and a Pending
/// transaction are established before this function can create a writable
/// mount. The returned receipt may report a safely closed rollback instead of
/// a committed repair; callers must inspect `outcome()`.
pub fn execute_approved_rescue_fstab(
    approved: ApprovedRescueFstabTransaction<
        ProductionRescueFstabTargetGuard,
        ProductionRescueFstabVaultReservation,
    >,
    deadline: Instant,
) -> Result<RescueFstabExecutionReceipt, RescueFstabExecutionError> {
    execute_approved_rescue_fstab_with_qualification_fault(
        approved,
        deadline,
        RescueFstabQualificationFault::None,
    )
}

pub(crate) fn execute_approved_rescue_fstab_with_qualification_fault(
    approved: ApprovedRescueFstabTransaction<
        ProductionRescueFstabTargetGuard,
        ProductionRescueFstabVaultReservation,
    >,
    deadline: Instant,
    qualification_fault: RescueFstabQualificationFault,
) -> Result<RescueFstabExecutionReceipt, RescueFstabExecutionError> {
    let operation_deadline = match reserve_cleanup_window(deadline) {
        Ok(operation) => operation,
        Err(error) => {
            approved
                .cancel(deadline)
                .map_err(|_| RescueFstabExecutionError::VaultReconciliationRequired)?;
            return Err(error);
        }
    };
    let ApprovedRescueFstabExecutionParts {
        plan,
        preview,
        backup_bytes,
        metadata,
        admission,
        target_guard,
        reservation,
    } = approved.into_execution_parts();

    let authority = (|| {
        let intent = execution_intent(&plan, &metadata, &admission, &target_guard)?;
        let binding = RepairBackupBinding::new(
            plan.claims().plan_id(),
            parse_prefixed_sha256(plan.plan_sha256())?,
            admission
                .approval_id()
                .ok_or(RescueFstabExecutionError::InvalidAuthority)?,
            parse_prefixed_sha256(
                admission
                    .approval_sha256()
                    .ok_or(RescueFstabExecutionError::InvalidAuthority)?,
            )?,
            plan.claims().resource_id(),
            intent.before_sha256().clone(),
            intent.clone(),
        )
        .map_err(|_| RescueFstabExecutionError::InvalidAuthority)?;
        Ok::<_, RescueFstabExecutionError>((intent, binding))
    })();
    let (intent, binding) = match authority {
        Ok(value) => value,
        Err(error) => {
            reservation
                .cancel(deadline)
                .map_err(|_| RescueFstabExecutionError::VaultReconciliationRequired)?;
            return Err(error);
        }
    };

    let _process_lock = match acquire_process_lock(operation_deadline) {
        Ok(lock) => lock,
        Err(error) => {
            reservation
                .cancel(deadline)
                .map_err(|_| RescueFstabExecutionError::VaultReconciliationRequired)?;
            return Err(error);
        }
    };
    let _target_lock = match acquire_target_lock(&target_guard, operation_deadline) {
        Ok(lock) => lock,
        Err(error) => {
            reservation
                .cancel(deadline)
                .map_err(|_| RescueFstabExecutionError::VaultReconciliationRequired)?;
            return Err(error);
        }
    };
    if target_guard.inner().revalidate().is_err() {
        reservation
            .cancel(deadline)
            .map_err(|_| RescueFstabExecutionError::VaultReconciliationRequired)?;
        return Err(RescueFstabExecutionError::TargetChanged);
    }

    let (mut vault_client, reserved) = reservation.into_parts();
    let durable = persist_pending(
        &mut vault_client,
        &reserved,
        &binding,
        &metadata,
        &backup_bytes,
        operation_deadline,
    )?;
    let pending = RepairTransactionStatusPayload::pending(durable)
        .map_err(|_| RescueFstabExecutionError::InvalidAuthority)?;

    if qualification_fault == RescueFstabQualificationFault::TerminateAfterPending {
        // The exact-image gate must prove that socket activation starts a new
        // repaird and reconciles this durable Pending record. `abort` is
        // deliberately process-local: QEMU, Vault and the target helpers stay
        // alive, while LimitCORE=0 prevents a credential-bearing core file.
        std::process::abort();
    }

    // The read-only detached mount must be gone before the root helper creates
    // the exclusive writable superblock. From here the durable Pending record,
    // not any boot-local descriptor retained by this process, is authority.
    drop(target_guard);
    let write_mount = acquire_pending_target_write_mount(&pending, operation_deadline)
        .map_err(map_write_capability_error)?;
    refresh_pending_after_write_lease(&mut vault_client, &pending, operation_deadline)?;
    let target_closure = execute_same_boot_target(
        write_mount,
        &backup_bytes,
        preview.proposed_fstab(),
        &intent,
        pending.backup().reservation_id().as_str(),
        operation_deadline,
        qualification_fault,
    )?;
    let initial_failure = target_closure.initial_failure;

    let resolution = RepairTransactionResolution::new(
        target_closure.outcome,
        target_closure.observation.resource_sha256,
        target_closure.observation.metadata_sha256,
        target_closure.cleanup_verified,
        &intent,
    )
    .map_err(|_| {
        prefer_initial_failure(
            initial_failure,
            RescueFstabExecutionError::RecoveryUnavailable,
        )
    })?;
    let resolved = resolve_pending(&mut vault_client, &pending, &resolution, deadline)
        .map_err(|error| prefer_initial_failure(initial_failure, error))?;
    let receipt = receipt_from_status(&resolved)
        .map_err(|error| prefer_initial_failure(initial_failure, error))?;
    Ok(match initial_failure {
        Some(failure) => receipt.with_initial_failure(failure),
        None => receipt,
    })
}

/// Executes the separately gated crypttab candidate through the same Vault,
/// write-mount, atomic replacement and reconciliation engine used by fstab.
/// The selected resource is a closed enum inferred from the approved action;
/// no path or shell command enters this boundary.
#[cfg(feature = "rescue-crypttab-production-candidate")]
pub fn execute_approved_rescue_crypttab(
    approved: ApprovedRescueCrypttabTransaction,
    deadline: Instant,
) -> Result<RescueFstabExecutionReceipt, RescueFstabExecutionError> {
    let operation_deadline = match reserve_cleanup_window(deadline) {
        Ok(operation) => operation,
        Err(error) => {
            approved
                .cancel(deadline)
                .map_err(|_| RescueFstabExecutionError::VaultReconciliationRequired)?;
            return Err(error);
        }
    };
    let ApprovedRescueCrypttabExecutionParts {
        descriptor,
        plan,
        admission,
        backup_bytes,
        proposed_bytes,
        metadata,
        target_guard,
        reservation,
    } = approved.into_execution_parts();

    let authority = (|| {
        let binding = admission.binding();
        let claims = target_guard.inner().target_claims();
        let step = plan
            .steps
            .as_slice()
            .first()
            .filter(|_| plan.steps.len() == 1)
            .ok_or(RescueFstabExecutionError::InvalidAuthority)?;
        if plan.plan_id != descriptor.plan_id()
            || plan.target_fingerprint != descriptor.target_fingerprint()
            || step.action != RepairResourceV1::Crypttab.action_id()
            || binding.session_id() != descriptor.session_id()
            || binding.plan_id() != descriptor.plan_id()
            || binding.plan_sha256() != descriptor.plan_sha256()
            || binding.target_fingerprint() != descriptor.target_fingerprint()
            || binding.target_snapshot() != descriptor.before_sha256()
            || claims.target_id() != descriptor.target_id()
            || claims.scan_fingerprint() != descriptor.scan_fingerprint()
            || claims.target_fingerprint() != descriptor.target_fingerprint()
        {
            return Err(RescueFstabExecutionError::InvalidAuthority);
        }
        let intent = RepairExecutionIntentV1::new_for_resource(
            RepairResourceV1::Crypttab,
            descriptor.session_id(),
            admission
                .approval_sequence()
                .ok_or(RescueFstabExecutionError::InvalidAuthority)?,
            descriptor.target_id(),
            descriptor.scan_fingerprint(),
            parse_prefixed_sha256(claims.target_fingerprint())?,
            parse_prefixed_sha256(target_guard.physical_parent_fingerprint())?,
            claims.recovery_fingerprint(),
            target_guard.lock_identity(),
            parse_prefixed_sha256(descriptor.before_sha256())?,
            parse_prefixed_sha256(descriptor.after_sha256())?,
            parse_prefixed_sha256(descriptor.diff_sha256())?,
            parse_prefixed_sha256(descriptor.observed_uuid_set_sha256())?,
            metadata.clone(),
        )
        .map_err(|_| RescueFstabExecutionError::InvalidAuthority)?;
        let vault_binding = RepairBackupBinding::new(
            descriptor.plan_id(),
            parse_prefixed_sha256(descriptor.plan_sha256())?,
            admission
                .approval_id()
                .ok_or(RescueFstabExecutionError::InvalidAuthority)?,
            parse_prefixed_sha256(
                admission
                    .approval_sha256()
                    .ok_or(RescueFstabExecutionError::InvalidAuthority)?,
            )?,
            RepairResourceV1::Crypttab.resource_id(),
            intent.before_sha256().clone(),
            intent.clone(),
        )
        .map_err(|_| RescueFstabExecutionError::InvalidAuthority)?;
        Ok::<_, RescueFstabExecutionError>((intent, vault_binding))
    })();
    let (intent, binding) = match authority {
        Ok(value) => value,
        Err(error) => {
            reservation
                .cancel(deadline)
                .map_err(|_| RescueFstabExecutionError::VaultReconciliationRequired)?;
            return Err(error);
        }
    };

    let _process_lock = match acquire_process_lock(operation_deadline) {
        Ok(lock) => lock,
        Err(error) => {
            reservation
                .cancel(deadline)
                .map_err(|_| RescueFstabExecutionError::VaultReconciliationRequired)?;
            return Err(error);
        }
    };
    let _target_lock = match acquire_target_lock(&target_guard, operation_deadline) {
        Ok(lock) => lock,
        Err(error) => {
            reservation
                .cancel(deadline)
                .map_err(|_| RescueFstabExecutionError::VaultReconciliationRequired)?;
            return Err(error);
        }
    };
    if target_guard.inner().revalidate().is_err() {
        reservation
            .cancel(deadline)
            .map_err(|_| RescueFstabExecutionError::VaultReconciliationRequired)?;
        return Err(RescueFstabExecutionError::TargetChanged);
    }
    let (mut vault_client, reserved) = reservation.into_parts();
    let durable = persist_pending(
        &mut vault_client,
        &reserved,
        &binding,
        &metadata,
        &backup_bytes,
        operation_deadline,
    )?;
    let pending = RepairTransactionStatusPayload::pending(durable)
        .map_err(|_| RescueFstabExecutionError::InvalidAuthority)?;
    drop(target_guard);
    let write_mount = acquire_pending_target_write_mount(&pending, operation_deadline)
        .map_err(map_write_capability_error)?;
    refresh_pending_after_write_lease(&mut vault_client, &pending, operation_deadline)?;
    let target_closure = execute_same_boot_target(
        write_mount,
        &backup_bytes,
        &proposed_bytes,
        &intent,
        pending.backup().reservation_id().as_str(),
        operation_deadline,
        RescueFstabQualificationFault::None,
    )?;
    let initial_failure = target_closure.initial_failure;
    let resolution = RepairTransactionResolution::new(
        target_closure.outcome,
        target_closure.observation.resource_sha256,
        target_closure.observation.metadata_sha256,
        target_closure.cleanup_verified,
        &intent,
    )
    .map_err(|_| RescueFstabExecutionError::RecoveryUnavailable)?;
    let resolved = resolve_pending(&mut vault_client, &pending, &resolution, deadline)
        .map_err(|error| prefer_initial_failure(initial_failure, error))?;
    let receipt = receipt_from_status(&resolved)
        .map_err(|error| prefer_initial_failure(initial_failure, error))?;
    Ok(match initial_failure {
        Some(failure) => receipt.with_initial_failure(failure),
        None => receipt,
    })
}

/// Reconciles the sole unresolved transaction after a process restart or
/// reboot. Target reacquisition uses only the approval-bound stable recovery
/// fingerprint; every boot-local target claim is freshly authenticated.
/// `None` means that the Vault has no unresolved transaction.
pub fn recover_pending_rescue_fstab(
    deadline: Instant,
) -> Result<Option<RescueFstabExecutionReceipt>, RescueFstabExecutionError> {
    let operation_deadline = reserve_cleanup_window(deadline)?;
    let safety_deadline = reserve_resolution_window(deadline)?;
    let mut vault_client = RepairVaultClient::new();
    let result = loop {
        match vault_client.transaction_status(
            &RepairTransactionStatusSelector::pending_singleton(),
            operation_deadline,
        ) {
            Ok(result) => break result,
            Err(error) if recovery_status_retryable(error) => {
                ensure_deadline(operation_deadline)?;
                thread::sleep(
                    VAULT_RECOVERY_POLL
                        .min(operation_deadline.saturating_duration_since(Instant::now())),
                );
            }
            Err(error) => return Err(map_vault_error(error)),
        }
    };
    let Some(pending) = result.transaction().cloned() else {
        return Ok(None);
    };
    let intent = pending
        .backup()
        .execution_intent()
        .cloned()
        .ok_or(RescueFstabExecutionError::InvalidAuthority)?;

    let live_vault = vault_client
        .live_identity(operation_deadline)
        .map_err(map_vault_error)?;
    if live_vault.vault_id() != pending.backup().vault_id()
        || live_vault.vault_identity_fingerprint() != pending.backup().vault_identity_fingerprint()
    {
        return Err(RescueFstabExecutionError::VaultReconciliationRequired);
    }
    let retrieved = vault_client
        .get(pending.backup(), operation_deadline)
        .map_err(map_vault_error)?;
    if retrieved.status() != pending.backup() {
        return Err(RescueFstabExecutionError::VaultReconciliationRequired);
    }

    let target =
        reacquire_target_for_recovery(&intent, operation_deadline).map_err(map_capability_error)?;
    let fresh_target_parent = parse_prefixed_sha256(target.inner().physical_parent_fingerprint())?;
    if &fresh_target_parent == live_vault.physical_parent_fingerprint() {
        return Err(RescueFstabExecutionError::RecoveryUnavailable);
    }

    let _process_lock = acquire_process_lock(operation_deadline)?;
    let _target_lock = acquire_target_lock(&target, operation_deadline)?;
    target
        .inner()
        .revalidate()
        .map_err(|_| RescueFstabExecutionError::TargetChanged)?;
    let locked_live_vault = vault_client
        .live_identity(operation_deadline)
        .map_err(map_vault_error)?;
    if locked_live_vault != live_vault
        || &fresh_target_parent == locked_live_vault.physical_parent_fingerprint()
    {
        return Err(RescueFstabExecutionError::VaultReconciliationRequired);
    }
    let before_outcome = if pending.phase() == RepairTransactionPhase::Pending {
        RepairTransactionResolutionOutcome::ClosedBeforeUnchanged
    } else {
        RepairTransactionResolutionOutcome::ClosedBeforeRestored
    };
    let target_closure = recover_same_boot_target(
        target,
        &pending,
        retrieved.bytes(),
        &intent,
        pending.backup().reservation_id().as_str(),
        before_outcome,
        safety_deadline,
    )?;
    let initial_failure = target_closure.initial_failure;

    if pending.phase() == RepairTransactionPhase::ManualReconciliationRequired
        && target_closure.outcome
            == RepairTransactionResolutionOutcome::ManualReconciliationRequired
    {
        return receipt_from_status(&pending).map(Some);
    }
    let resolution = RepairTransactionResolution::new(
        target_closure.outcome,
        target_closure.observation.resource_sha256,
        target_closure.observation.metadata_sha256,
        target_closure.cleanup_verified,
        &intent,
    )
    .map_err(|_| {
        prefer_initial_failure(
            initial_failure,
            RescueFstabExecutionError::RecoveryUnavailable,
        )
    })?;
    let resolved = resolve_pending(&mut vault_client, &pending, &resolution, deadline)
        .map_err(|error| prefer_initial_failure(initial_failure, error))?;
    let receipt = receipt_from_status(&resolved)
        .map_err(|error| prefer_initial_failure(initial_failure, error))?;
    Ok(Some(match initial_failure {
        Some(failure) => receipt.with_initial_failure(failure),
        None => receipt,
    }))
}

fn execution_intent(
    plan: &kernaid_linux_pack::rescue_fstab_transaction_candidate::FstabCandidateTransactionPlan,
    metadata: &RepairFileMetadataV1,
    admission: &kernaid_core::RescueFstabCandidateAdmission,
    target: &ProductionRescueFstabTargetGuard,
) -> Result<RepairExecutionIntentV1, RescueFstabExecutionError> {
    let claims = target.inner().target_claims();
    if claims.target_id() != plan.target().target_id()
        || claims.scan_fingerprint() != plan.target().scan_fingerprint()
        || claims.recovery_fingerprint() != plan.target().recovery_fingerprint()
        || target.inner().physical_parent_fingerprint()
            != plan.target().physical_parent_fingerprint()
    {
        return Err(RescueFstabExecutionError::TargetChanged);
    }
    RepairExecutionIntentV1::new(
        plan.claims().session_id(),
        admission
            .approval_sequence()
            .ok_or(RescueFstabExecutionError::InvalidAuthority)?,
        plan.target().target_id(),
        plan.target().scan_fingerprint(),
        parse_prefixed_sha256(claims.target_fingerprint())?,
        parse_prefixed_sha256(plan.target().physical_parent_fingerprint())?,
        plan.target().recovery_fingerprint(),
        target.lock_identity(),
        parse_prefixed_sha256(plan.before_sha256())?,
        parse_prefixed_sha256(plan.after_sha256())?,
        parse_prefixed_sha256(plan.diff_sha256())?,
        parse_prefixed_sha256(plan.observed_uuid_set_sha256())?,
        metadata.clone(),
    )
    .map_err(|_| RescueFstabExecutionError::InvalidAuthority)
}

fn persist_pending(
    client: &mut RepairVaultClient,
    reserved: &RepairBackupStatusPayload,
    binding: &RepairBackupBinding,
    metadata: &RepairFileMetadataV1,
    backup: &[u8],
    deadline: Instant,
) -> Result<RepairBackupStatusPayload, RescueFstabExecutionError> {
    let durable = match client.persist(reserved, binding, metadata, backup, deadline) {
        Ok(status) => validate_durable_binding(status, binding),
        Err(RepairVaultClientError::ReconciliationRequired) => {
            let status = client.status(reserved, deadline).map_err(map_vault_error)?;
            if status.state() == RepairBackupState::Durable {
                validate_durable_binding(status, binding)
            } else {
                client
                    .cancel(
                        reserved.reservation_id(),
                        reserved.draft_binding_sha256(),
                        deadline,
                    )
                    .map_err(|_| RescueFstabExecutionError::VaultReconciliationRequired)?;
                Err(RescueFstabExecutionError::VaultReconciliationRequired)
            }
        }
        Err(error) => {
            if matches!(error, RepairVaultClientError::Remote(ErrorToken::Busy)) {
                return Err(RescueFstabExecutionError::VaultReconciliationRequired);
            }
            client
                .cancel(
                    reserved.reservation_id(),
                    reserved.draft_binding_sha256(),
                    deadline,
                )
                .map_err(|_| RescueFstabExecutionError::VaultReconciliationRequired)?;
            Err(map_vault_error(error))
        }
    }?;
    // A Persist acknowledgement alone is insufficient authority for RW. Read
    // the named durable object back through the authenticated one-shot pipe
    // and bind both its status and exact bytes before touching the target.
    let retrieved = client.get(&durable, deadline).map_err(map_vault_error)?;
    if retrieved.status() != &durable || retrieved.bytes() != backup {
        return Err(RescueFstabExecutionError::VaultReconciliationRequired);
    }
    Ok(durable)
}

fn validate_durable_binding(
    status: RepairBackupStatusPayload,
    binding: &RepairBackupBinding,
) -> Result<RepairBackupStatusPayload, RescueFstabExecutionError> {
    if status.state() != RepairBackupState::Durable
        || status.plan_id() != Some(binding.plan_id())
        || status.plan_sha256() != Some(binding.plan_sha256())
        || status.approval_id() != Some(binding.approval_id())
        || status.approval_sha256() != Some(binding.approval_sha256())
        || status.resource_id() != Some(binding.resource_id())
        || status.resource_sha256() != Some(binding.resource_sha256())
        || status.execution_intent() != Some(binding.execution_intent())
    {
        return Err(RescueFstabExecutionError::VaultReconciliationRequired);
    }
    Ok(status)
}

fn resolve_pending(
    client: &mut RepairVaultClient,
    pending: &RepairTransactionStatusPayload,
    resolution: &RepairTransactionResolution,
    deadline: Instant,
) -> Result<RepairTransactionStatusPayload, RescueFstabExecutionError> {
    match client.resolve_transaction(pending, resolution, deadline) {
        Ok(status) => Ok(status),
        Err(RepairVaultClientError::ReconciliationRequired) => {
            let selector = RepairTransactionStatusSelector::for_status(pending);
            let result = client
                .transaction_status(&selector, deadline)
                .map_err(map_vault_error)?;
            let status = result
                .transaction()
                .ok_or(RescueFstabExecutionError::VaultReconciliationRequired)?;
            if status.resolution() == Some(resolution) {
                Ok(status.clone())
            } else {
                Err(RescueFstabExecutionError::VaultReconciliationRequired)
            }
        }
        Err(error) => Err(map_vault_error(error)),
    }
}

/// The root write helper consumes the transaction's single-use Vault lease
/// through a separate authenticated connection. Refresh the exact transaction
/// before touching the target so this client's state-version guard observes
/// that expected mutation. If the transaction itself changed, the detached
/// write mount is dropped without writing and startup reconciliation can close
/// the still-Before target.
fn refresh_pending_after_write_lease(
    client: &mut RepairVaultClient,
    pending: &RepairTransactionStatusPayload,
    deadline: Instant,
) -> Result<(), RescueFstabExecutionError> {
    let selector = RepairTransactionStatusSelector::for_status(pending);
    let result = client
        .transaction_status(&selector, deadline)
        .map_err(map_vault_error)?;
    let refreshed = result
        .transaction()
        .ok_or(RescueFstabExecutionError::VaultReconciliationRequired)?;
    if refreshed != pending {
        return Err(RescueFstabExecutionError::VaultReconciliationRequired);
    }
    Ok(())
}

fn receipt_from_status(
    status: &RepairTransactionStatusPayload,
) -> Result<RescueFstabExecutionReceipt, RescueFstabExecutionError> {
    let resolution = status
        .resolution()
        .ok_or(RescueFstabExecutionError::VaultReconciliationRequired)?;
    let outcome = match resolution.outcome() {
        RepairTransactionResolutionOutcome::CommittedAfter => {
            RescueFstabExecutionOutcome::Committed
        }
        RepairTransactionResolutionOutcome::ClosedBeforeUnchanged => {
            RescueFstabExecutionOutcome::ClosedBeforeUnchanged
        }
        RepairTransactionResolutionOutcome::ClosedBeforeRestored => {
            RescueFstabExecutionOutcome::ClosedBeforeRestored
        }
        RepairTransactionResolutionOutcome::ManualReconciliationRequired => {
            RescueFstabExecutionOutcome::ManualReconciliationRequired
        }
    };
    Ok(RescueFstabExecutionReceipt {
        outcome,
        reservation_id: status.backup().reservation_id().as_str().to_owned(),
        transaction_binding_sha256: status.transaction_binding_sha256().as_str().to_owned(),
        initial_failure: None,
    })
}

fn source_intent(
    source: &RepairTransactionStatusPayload,
) -> Result<&RepairExecutionIntentV1, RescueFstabExecutionError> {
    source
        .backup()
        .execution_intent()
        .ok_or(RescueFstabExecutionError::InvalidAuthority)
}

fn repair_resource_for_intent(
    intent: &RepairExecutionIntentV1,
) -> Result<RepairResourceV1, RescueFstabExecutionError> {
    for resource in [RepairResourceV1::Fstab, RepairResourceV1::Crypttab] {
        if intent.action_id() == resource.action_id() {
            return Ok(resource);
        }
    }
    Err(RescueFstabExecutionError::InvalidAuthority)
}

fn resource_leaf(resource: RepairResourceV1) -> &'static str {
    match resource {
        RepairResourceV1::Fstab => FSTAB_RESOURCE,
        RepairResourceV1::Crypttab => CRYPTTAB_RESOURCE,
    }
}

fn validate_committed_rollback_source(
    source: &RepairTransactionStatusPayload,
) -> Result<(), RescueFstabExecutionError> {
    let intent = source_intent(source)?;
    if source.phase() != RepairTransactionPhase::Resolved
        || source
            .resolution()
            .map(kernaid_protocol::rescue_repair_vault::RepairTransactionResolution::outcome)
            != Some(RepairTransactionResolutionOutcome::CommittedAfter)
        || source.backup().state() != RepairBackupState::Durable
        || repair_resource_from_transaction(source) != Ok(RepairResourceV1::Fstab)
        || source.backup().resource_sha256() != Some(intent.before_sha256())
        || source.backup().locator()
            != format!(
                "vault://repair/{}",
                source.backup().reservation_id().as_str()
            )
    {
        return Err(RescueFstabExecutionError::InvalidAuthority);
    }
    Ok(())
}

fn validate_live_vault(
    source: &RepairTransactionStatusPayload,
    live_vault: &RepairVaultLiveIdentityPayload,
) -> Result<(), RescueFstabExecutionError> {
    if live_vault.vault_id() != source.backup().vault_id()
        || live_vault.vault_identity_fingerprint() != source.backup().vault_identity_fingerprint()
    {
        return Err(RescueFstabExecutionError::VaultReconciliationRequired);
    }
    Ok(())
}

fn validate_target_vault_separation(
    target: &ProductionRescueFstabTargetGuard,
    live_vault: &RepairVaultLiveIdentityPayload,
) -> Result<(), RescueFstabExecutionError> {
    let target_parent = parse_prefixed_sha256(target.inner().physical_parent_fingerprint())?;
    if &target_parent == live_vault.physical_parent_fingerprint() {
        return Err(RescueFstabExecutionError::RecoveryUnavailable);
    }
    Ok(())
}

fn lookup_exact_source(
    client: &mut RepairVaultClient,
    source: &RepairTransactionStatusPayload,
    deadline: Instant,
) -> Result<RepairTransactionStatusPayload, RescueFstabExecutionError> {
    let result = client
        .transaction_status(
            &RepairTransactionStatusSelector::for_status(source),
            deadline,
        )
        .map_err(map_vault_error)?;
    let current = result
        .transaction()
        .cloned()
        .ok_or(RescueFstabExecutionError::VaultReconciliationRequired)?;
    validate_committed_rollback_source(&current)?;
    Ok(current)
}

fn resolve_pending_rollback(
    client: &mut RepairVaultClient,
    pending: &RepairRollbackTransactionStatusPayload,
    resolution: &RepairRollbackResolution,
    deadline: Instant,
) -> Result<RepairRollbackTransactionStatusPayload, RescueFstabExecutionError> {
    match client.resolve_rollback_transaction(pending, resolution, deadline) {
        Ok(status) => Ok(status),
        Err(RepairVaultClientError::ReconciliationRequired) => {
            let result = client
                .rollback_transaction_status(
                    &RepairRollbackStatusSelector::for_status(pending),
                    deadline,
                )
                .map_err(map_vault_error)?;
            let status = result
                .transaction()
                .ok_or(RescueFstabExecutionError::VaultReconciliationRequired)?;
            if status.same_transaction(pending) && status.resolves_with(resolution) {
                Ok(status.clone())
            } else {
                Err(RescueFstabExecutionError::VaultReconciliationRequired)
            }
        }
        Err(error) => Err(map_vault_error(error)),
    }
}

fn refresh_pending_after_rollback_write_lease(
    client: &mut RepairVaultClient,
    pending: &RepairRollbackTransactionStatusPayload,
    deadline: Instant,
) -> Result<(), RescueFstabExecutionError> {
    let result = client
        .rollback_transaction_status(&RepairRollbackStatusSelector::for_status(pending), deadline)
        .map_err(map_vault_error)?;
    let refreshed = result
        .transaction()
        .ok_or(RescueFstabExecutionError::VaultReconciliationRequired)?;
    if refreshed != pending {
        return Err(RescueFstabExecutionError::VaultReconciliationRequired);
    }
    Ok(())
}

fn rollback_receipt_from_status(
    status: &RepairRollbackTransactionStatusPayload,
) -> Result<RescueFstabRollbackExecutionReceipt, RescueFstabExecutionError> {
    let resolution = status
        .resolution()
        .ok_or(RescueFstabExecutionError::VaultReconciliationRequired)?;
    let outcome = match resolution.outcome() {
        RepairRollbackResolutionOutcome::RolledBackBefore => {
            RescueFstabRollbackExecutionOutcome::RolledBackOriginal
        }
        RepairRollbackResolutionOutcome::ManualReconciliationRequired => {
            RescueFstabRollbackExecutionOutcome::ManualReconciliationRequired
        }
    };
    Ok(RescueFstabRollbackExecutionReceipt {
        outcome,
        rollback_id: status.rollback_id().as_str().to_owned(),
        rollback_transaction_binding_sha256: status
            .rollback_transaction_binding_sha256()
            .as_str()
            .to_owned(),
        source_reservation_id: status
            .source()
            .backup()
            .reservation_id()
            .as_str()
            .to_owned(),
        source_transaction_binding_sha256: status
            .source()
            .transaction_binding_sha256()
            .as_str()
            .to_owned(),
    })
}

fn map_vault_error(error: RepairVaultClientError) -> RescueFstabExecutionError {
    match error {
        RepairVaultClientError::TimedOut => RescueFstabExecutionError::TimedOut,
        RepairVaultClientError::ReconciliationRequired
        | RepairVaultClientError::Remote(ErrorToken::Busy) => {
            RescueFstabExecutionError::VaultReconciliationRequired
        }
        _ => RescueFstabExecutionError::VaultUnavailable,
    }
}

fn recovery_status_retryable(error: RepairVaultClientError) -> bool {
    matches!(
        error,
        RepairVaultClientError::Remote(ErrorToken::Locked | ErrorToken::Busy)
    )
}

fn map_capability_error(error: RescueFstabCapabilityResolutionError) -> RescueFstabExecutionError {
    match error {
        RescueFstabCapabilityResolutionError::TimedOut => RescueFstabExecutionError::TimedOut,
        RescueFstabCapabilityResolutionError::IdentityChanged => {
            RescueFstabExecutionError::TargetChanged
        }
        RescueFstabCapabilityResolutionError::LockUnavailable => {
            RescueFstabExecutionError::LockUnavailable
        }
        RescueFstabCapabilityResolutionError::Unavailable => {
            RescueFstabExecutionError::RecoveryUnavailable
        }
    }
}

fn map_write_capability_error(
    _error: TargetWriteCapabilityClientError,
) -> RescueFstabExecutionError {
    // The transaction is already durable Pending whenever this client is
    // called. No local distinction can authorize cancel or a second acquire.
    RescueFstabExecutionError::RecoveryRequired
}

struct TargetLock {
    descriptor: OwnedFd,
}

impl Drop for TargetLock {
    fn drop(&mut self) {
        let _ = rfs::flock(&self.descriptor, FlockOperation::NonBlockingUnlock);
    }
}

fn acquire_process_lock(
    deadline: Instant,
) -> Result<MutexGuard<'static, ()>, RescueFstabExecutionError> {
    loop {
        ensure_deadline(deadline)?;
        match PROCESS_EXECUTOR_LOCK.try_lock() {
            Ok(guard) => return Ok(guard),
            Err(TryLockError::WouldBlock) => thread::sleep(LOCK_POLL),
            Err(TryLockError::Poisoned(_)) => {
                return Err(RescueFstabExecutionError::LockUnavailable);
            }
        }
    }
}

fn acquire_target_lock(
    target: &ProductionRescueFstabTargetGuard,
    deadline: Instant,
) -> Result<TargetLock, RescueFstabExecutionError> {
    let digest = target
        .lock_identity()
        .strip_prefix("lock:")
        .filter(|value| {
            value.len() == 64
                && value
                    .bytes()
                    .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        })
        .ok_or(RescueFstabExecutionError::InvalidAuthority)?;
    let lock_name = format!("fstab-{digest}.lock");
    let directory = rfs::open(
        REPAIR_LOCK_DIRECTORY,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC | OFlags::NOFOLLOW,
        Mode::empty(),
    )
    .map_err(|_| RescueFstabExecutionError::LockUnavailable)?;
    let directory_stat =
        rfs::fstat(&directory).map_err(|_| RescueFstabExecutionError::LockUnavailable)?;
    if !FileType::from_raw_mode(directory_stat.st_mode).is_dir()
        || directory_stat.st_uid != 0
        || directory_stat.st_mode & 0o002 != 0
    {
        return Err(RescueFstabExecutionError::LockUnavailable);
    }
    let descriptor = rfs::openat(
        &directory,
        &lock_name,
        OFlags::RDWR | OFlags::CREATE | OFlags::CLOEXEC | OFlags::NOFOLLOW,
        Mode::RUSR | Mode::WUSR,
    )
    .map_err(|_| RescueFstabExecutionError::LockUnavailable)?;
    let descriptor_stat =
        rfs::fstat(&descriptor).map_err(|_| RescueFstabExecutionError::LockUnavailable)?;
    let named_stat = rfs::statat(&directory, &lock_name, AtFlags::SYMLINK_NOFOLLOW)
        .map_err(|_| RescueFstabExecutionError::LockUnavailable)?;
    if !FileType::from_raw_mode(descriptor_stat.st_mode).is_file()
        || !FileType::from_raw_mode(named_stat.st_mode).is_file()
        || descriptor_stat.st_dev != named_stat.st_dev
        || descriptor_stat.st_ino != named_stat.st_ino
        || descriptor_stat.st_nlink != 1
        || descriptor_stat.st_gid != directory_stat.st_gid
        || descriptor_stat.st_mode & 0o7777 != 0o600
    {
        return Err(RescueFstabExecutionError::LockUnavailable);
    }
    rfs::fsync(&descriptor).map_err(|_| RescueFstabExecutionError::LockUnavailable)?;
    rfs::fsync(&directory).map_err(|_| RescueFstabExecutionError::LockUnavailable)?;
    loop {
        ensure_deadline(deadline)?;
        match rfs::flock(&descriptor, FlockOperation::NonBlockingLockExclusive) {
            Ok(()) => return Ok(TargetLock { descriptor }),
            Err(error)
                if error == rustix::io::Errno::AGAIN || error == rustix::io::Errno::WOULDBLOCK =>
            {
                thread::sleep(LOCK_POLL);
            }
            Err(_) => return Err(RescueFstabExecutionError::LockUnavailable),
        }
    }
}

#[derive(Clone, Debug)]
struct ClosedObservation {
    resource_sha256: Sha256,
    metadata_sha256: Sha256,
}

struct TargetClosure {
    outcome: RepairTransactionResolutionOutcome,
    observation: ClosedObservation,
    cleanup_verified: bool,
    initial_failure: Option<RescueFstabExecutionError>,
}

struct RollbackTargetClosure {
    outcome: RepairRollbackResolutionOutcome,
    observation: ClosedObservation,
    cleanup_verified: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ExactTargetState {
    Before,
    After,
    Third,
}

fn execute_same_boot_target(
    write_mount: RescueTargetWriteMountCapability,
    backup: &[u8],
    proposed: &[u8],
    intent: &RepairExecutionIntentV1,
    reservation_id: &str,
    deadline: Instant,
    qualification_fault: RescueFstabQualificationFault,
) -> Result<TargetClosure, RescueFstabExecutionError> {
    ensure_exact_bytes(backup, intent.before_sha256())?;
    ensure_exact_bytes(proposed, intent.after_sha256())?;
    validate_write_capability(&write_mount, intent, reservation_id)?;
    write_mount
        .revalidate()
        .map_err(map_write_capability_error)?;

    let result = {
        let mount = write_mount.mount();
        let etc = open_etc_directory(mount.as_fd())?;
        let result = match apply_exact_replacement(
            mount,
            &etc,
            backup,
            proposed,
            intent,
            reservation_id,
            deadline,
            qualification_fault,
        ) {
            Ok(observation) => Ok(TargetClosure {
                outcome: RepairTransactionResolutionOutcome::CommittedAfter,
                observation,
                cleanup_verified: false,
                initial_failure: None,
            }),
            Err(error) => match close_after_failed_mutation(
                mount,
                &etc,
                backup,
                intent,
                reservation_id,
                deadline,
            ) {
                Ok(mut closure) => {
                    if matches!(
                        closure.outcome,
                        RepairTransactionResolutionOutcome::ClosedBeforeUnchanged
                            | RepairTransactionResolutionOutcome::ClosedBeforeRestored
                    ) {
                        closure.initial_failure = Some(error);
                    }
                    Ok(closure)
                }
                Err(_) => Err(error),
            },
        };
        drop(etc);
        result
    }?;
    if let Err(error) = write_mount.revalidate().map_err(map_write_capability_error) {
        return Err(prefer_initial_failure(result.initial_failure, error));
    }
    drop(write_mount);
    Ok(TargetClosure {
        cleanup_verified: true,
        ..result
    })
}

/// Classifies recovery through the freshly reacquired read-only mount. Write
/// authority is consumed only for an exact `After` state and is used once for
/// restore and verification in the same detached mount.
fn recover_same_boot_target(
    target: ProductionRescueFstabTargetGuard,
    pending: &RepairTransactionStatusPayload,
    backup: &[u8],
    intent: &RepairExecutionIntentV1,
    reservation_id: &str,
    before_outcome: RepairTransactionResolutionOutcome,
    deadline: Instant,
) -> Result<TargetClosure, RescueFstabExecutionError> {
    ensure_exact_bytes(backup, intent.before_sha256())?;
    let read_observation = classify_with_retained_read_mount(&target, intent)?;

    match read_observation.0 {
        ExactTargetState::Before => Ok(TargetClosure {
            outcome: before_outcome,
            observation: read_observation.1,
            cleanup_verified: true,
            initial_failure: None,
        }),
        ExactTargetState::Third => Ok(TargetClosure {
            outcome: RepairTransactionResolutionOutcome::ManualReconciliationRequired,
            observation: read_observation.1,
            cleanup_verified: true,
            initial_failure: None,
        }),
        ExactTargetState::After if pending.phase() != RepairTransactionPhase::Pending => {
            Ok(TargetClosure {
                outcome: RepairTransactionResolutionOutcome::ManualReconciliationRequired,
                observation: read_observation.1,
                cleanup_verified: true,
                initial_failure: None,
            })
        }
        ExactTargetState::After => {
            // The fresh RO mount is the classification authority. Drop it
            // before asking the helper to consume the sole write lease and
            // create the exclusive writable superblock.
            drop(target);
            let write_mount = acquire_pending_target_write_mount(pending, deadline)
                .map_err(map_write_capability_error)?;
            restore_recovery_target(write_mount, backup, intent, reservation_id, deadline)
        }
    }
}

fn classify_with_retained_read_mount(
    target: &ProductionRescueFstabTargetGuard,
    intent: &RepairExecutionIntentV1,
) -> Result<(ExactTargetState, ClosedObservation), RescueFstabExecutionError> {
    target
        .inner()
        .revalidate()
        .map_err(|_| RescueFstabExecutionError::TargetChanged)?;
    let mount = target.inner().target_detached_mount_descriptor();
    let etc = open_etc_directory(mount)?;
    let snapshot = snapshot_repair_resource(&etc, intent)?;
    let result = (exact_state(&snapshot, intent), snapshot.observation());
    drop(etc);
    target
        .inner()
        .revalidate()
        .map_err(|_| RescueFstabExecutionError::TargetChanged)?;
    Ok(result)
}

fn restore_recovery_target(
    write_mount: RescueTargetWriteMountCapability,
    backup: &[u8],
    intent: &RepairExecutionIntentV1,
    reservation_id: &str,
    deadline: Instant,
) -> Result<TargetClosure, RescueFstabExecutionError> {
    validate_write_capability(&write_mount, intent, reservation_id)?;
    write_mount
        .revalidate()
        .map_err(map_write_capability_error)?;
    let result = {
        let mount = write_mount.mount();
        let etc = open_etc_directory(mount.as_fd())?;
        let result =
            match restore_exact_backup(mount, &etc, backup, intent, reservation_id, deadline) {
                Ok(observation) => TargetClosure {
                    outcome: RepairTransactionResolutionOutcome::ClosedBeforeRestored,
                    observation,
                    cleanup_verified: false,
                    initial_failure: None,
                },
                Err(error) => {
                    let snapshot = snapshot_repair_resource(&etc, intent)?;
                    TargetClosure {
                        outcome: if exact_state(&snapshot, intent) == ExactTargetState::Before {
                            RepairTransactionResolutionOutcome::ClosedBeforeRestored
                        } else {
                            RepairTransactionResolutionOutcome::ManualReconciliationRequired
                        },
                        observation: snapshot.observation(),
                        cleanup_verified: false,
                        initial_failure: Some(error),
                    }
                }
            };
        drop(etc);
        result
    };
    write_mount
        .revalidate()
        .map_err(map_write_capability_error)?;
    drop(write_mount);
    Ok(TargetClosure {
        cleanup_verified: true,
        ..result
    })
}

fn restore_rollback_target(
    write_mount: RescueTargetRollbackWriteMountCapability,
    backup: &[u8],
    intent: &RepairExecutionIntentV1,
    pending: &RepairRollbackTransactionStatusPayload,
    deadline: Instant,
) -> Result<RollbackTargetClosure, RescueFstabExecutionError> {
    validate_rollback_write_capability(&write_mount, pending)?;
    write_mount
        .revalidate()
        .map_err(map_write_capability_error)?;
    let closure = {
        let mount = write_mount.mount();
        let etc = open_etc_directory(mount.as_fd())?;
        let closure = match restore_exact_backup(
            mount,
            &etc,
            backup,
            intent,
            pending.source().backup().reservation_id().as_str(),
            deadline,
        ) {
            Ok(observation) => RollbackTargetClosure {
                outcome: RepairRollbackResolutionOutcome::RolledBackBefore,
                observation,
                cleanup_verified: false,
            },
            Err(error) => {
                let snapshot = snapshot_repair_resource(&etc, intent)?;
                match exact_state(&snapshot, intent) {
                    ExactTargetState::Before => RollbackTargetClosure {
                        outcome: RepairRollbackResolutionOutcome::RolledBackBefore,
                        observation: snapshot.observation(),
                        cleanup_verified: false,
                    },
                    ExactTargetState::Third => RollbackTargetClosure {
                        outcome: RepairRollbackResolutionOutcome::ManualReconciliationRequired,
                        observation: snapshot.observation(),
                        cleanup_verified: false,
                    },
                    // Leave the durable child Pending. A later boot receives a
                    // fresh boot-scoped lease and can safely retry from After.
                    ExactTargetState::After => return Err(error),
                }
            }
        };
        drop(etc);
        closure
    };
    write_mount
        .revalidate()
        .map_err(map_write_capability_error)?;
    drop(write_mount);
    Ok(RollbackTargetClosure {
        cleanup_verified: true,
        ..closure
    })
}

fn validate_write_capability(
    capability: &RescueTargetWriteMountCapability,
    intent: &RepairExecutionIntentV1,
    reservation_id: &str,
) -> Result<(), RescueFstabExecutionError> {
    if capability.reservation_id() != reservation_id
        || capability.target_recovery_fingerprint() != intent.target_recovery_fingerprint()
        || capability.transaction_binding_sha256().is_empty()
        || capability.lease_binding_sha256().is_empty()
    {
        return Err(RescueFstabExecutionError::RecoveryRequired);
    }
    Ok(())
}

fn validate_rollback_write_capability(
    capability: &RescueTargetRollbackWriteMountCapability,
    pending: &RepairRollbackTransactionStatusPayload,
) -> Result<(), RescueFstabExecutionError> {
    let source = pending.source();
    let intent = source_intent(source)?;
    if capability.rollback_id() != pending.rollback_id().as_str()
        || capability.rollback_transaction_binding_sha256()
            != pending.rollback_transaction_binding_sha256().as_str()
        || capability.source_reservation_id() != source.backup().reservation_id().as_str()
        || capability.source_transaction_binding_sha256()
            != source.transaction_binding_sha256().as_str()
        || capability.target_recovery_fingerprint() != intent.target_recovery_fingerprint()
        || capability.lease_binding_sha256().is_empty()
    {
        return Err(RescueFstabExecutionError::RecoveryRequired);
    }
    Ok(())
}

fn close_after_failed_mutation(
    mount: &OwnedFd,
    etc: &OwnedFd,
    backup: &[u8],
    intent: &RepairExecutionIntentV1,
    reservation_id: &str,
    deadline: Instant,
) -> Result<TargetClosure, RescueFstabExecutionError> {
    let snapshot = snapshot_repair_resource(etc, intent)?;
    match exact_state(&snapshot, intent) {
        ExactTargetState::Before => {
            cleanup_known_stage(
                etc,
                &execution_stage_name_for(repair_resource_for_intent(intent)?, reservation_id),
                intent.after_sha256(),
                intent.before_metadata(),
            );
            Ok(TargetClosure {
                outcome: RepairTransactionResolutionOutcome::ClosedBeforeUnchanged,
                observation: snapshot.observation(),
                cleanup_verified: false,
                initial_failure: None,
            })
        }
        ExactTargetState::After => {
            restore_exact_backup(mount, etc, backup, intent, reservation_id, deadline).map(
                |observation| TargetClosure {
                    outcome: RepairTransactionResolutionOutcome::ClosedBeforeRestored,
                    observation,
                    cleanup_verified: false,
                    initial_failure: None,
                },
            )
        }
        ExactTargetState::Third => Ok(TargetClosure {
            outcome: RepairTransactionResolutionOutcome::ManualReconciliationRequired,
            observation: snapshot.observation(),
            cleanup_verified: false,
            initial_failure: None,
        }),
    }
}

#[allow(clippy::too_many_arguments)]
fn apply_exact_replacement(
    _mount: &OwnedFd,
    etc: &OwnedFd,
    backup: &[u8],
    proposed: &[u8],
    intent: &RepairExecutionIntentV1,
    reservation_id: &str,
    deadline: Instant,
    qualification_fault: RescueFstabQualificationFault,
) -> Result<ClosedObservation, RescueFstabExecutionError> {
    ensure_deadline(deadline)?;
    let resource = repair_resource_for_intent(intent)?;
    let before = snapshot_repair_resource(etc, intent)?;
    ensure_snapshot_exact(&before, intent.before_sha256(), intent.before_metadata())?;
    if before.bytes.as_slice() != backup {
        return Err(RescueFstabExecutionError::TargetChanged);
    }

    let stage_name = execution_stage_name_for(resource, reservation_id);
    let (prepared, mut stage_guard) =
        create_prepared_file(etc, &stage_name, proposed, intent.before_metadata())?;
    ensure_snapshot_exact(&prepared, intent.after_sha256(), intent.before_metadata())?;
    let current = snapshot_repair_resource(etc, intent)?;
    if !current.same_object_and_value(&before) {
        return Err(RescueFstabExecutionError::TargetChanged);
    }
    ensure_deadline(deadline)?;

    rfs::renameat_with(
        etc,
        &stage_name,
        etc,
        resource_leaf(resource),
        RenameFlags::EXCHANGE,
    )
    .map_err(|_| RescueFstabExecutionError::MutationFailed)?;
    rfs::fsync(etc).map_err(|_| RescueFstabExecutionError::MutationFailed)?;
    // `fsmount` returns an O_PATH descriptor, which syncfs rejects with
    // EBADF. The open directory is on the same filesystem and is a valid
    // persistence barrier descriptor.
    rfs::syncfs(etc).map_err(|_| RescueFstabExecutionError::MutationFailed)?;

    let installed = snapshot_repair_resource(etc, intent)?;
    let displaced = snapshot_named(etc, &stage_name)?;
    ensure_snapshot_exact(&installed, intent.after_sha256(), intent.before_metadata())?;
    ensure_snapshot_exact(&displaced, intent.before_sha256(), intent.before_metadata())?;
    if installed.identity != prepared.identity || displaced.identity != before.identity {
        return Err(RescueFstabExecutionError::TargetChanged);
    }
    remove_name_if_identity(etc, &stage_name, displaced.identity)?;
    stage_guard.disarm();
    rfs::fsync(etc).map_err(|_| RescueFstabExecutionError::MutationFailed)?;
    rfs::syncfs(etc).map_err(|_| RescueFstabExecutionError::MutationFailed)?;
    let final_state = snapshot_repair_resource(etc, intent)?;
    ensure_snapshot_exact(
        &final_state,
        intent.after_sha256(),
        intent.before_metadata(),
    )?;
    if qualification_fault == RescueFstabQualificationFault::FailAfterInstalled {
        // At this point `After` is exact and durable. Returning the ordinary
        // closed mutation error forces the real same-boot recovery path to
        // classify it and restore the authenticated backup.
        return Err(RescueFstabExecutionError::MutationFailed);
    }
    Ok(final_state.observation())
}

fn restore_exact_backup(
    _mount: &OwnedFd,
    etc: &OwnedFd,
    backup: &[u8],
    intent: &RepairExecutionIntentV1,
    reservation_id: &str,
    deadline: Instant,
) -> Result<ClosedObservation, RescueFstabExecutionError> {
    ensure_deadline(deadline)?;
    ensure_exact_bytes(backup, intent.before_sha256())?;
    let resource = repair_resource_for_intent(intent)?;
    let current = snapshot_repair_resource(etc, intent)?;
    ensure_snapshot_exact(&current, intent.after_sha256(), intent.before_metadata())?;
    let restore_name = restore_stage_name_for(resource, reservation_id);
    let (restore, mut restore_guard) =
        match create_prepared_file(etc, &restore_name, backup, intent.before_metadata()) {
            Ok(value) => value,
            Err(RescueFstabExecutionError::UnsafeTarget) => {
                let existing = snapshot_named(etc, &restore_name)?;
                ensure_snapshot_exact(&existing, intent.before_sha256(), intent.before_metadata())?;
                let guard = NamedFileGuard::existing(etc, restore_name.clone(), existing.identity);
                (existing, guard)
            }
            Err(error) => return Err(error),
        };
    let recheck = snapshot_repair_resource(etc, intent)?;
    if !recheck.same_object_and_value(&current) {
        return Err(RescueFstabExecutionError::TargetChanged);
    }
    ensure_deadline(deadline)?;
    rfs::renameat_with(
        etc,
        &restore_name,
        etc,
        resource_leaf(resource),
        RenameFlags::EXCHANGE,
    )
    .map_err(|_| RescueFstabExecutionError::MutationFailed)?;
    rfs::fsync(etc).map_err(|_| RescueFstabExecutionError::MutationFailed)?;
    rfs::syncfs(etc).map_err(|_| RescueFstabExecutionError::MutationFailed)?;
    let restored = snapshot_repair_resource(etc, intent)?;
    let displaced = snapshot_named(etc, &restore_name)?;
    ensure_snapshot_exact(&restored, intent.before_sha256(), intent.before_metadata())?;
    ensure_snapshot_exact(&displaced, intent.after_sha256(), intent.before_metadata())?;
    if restored.identity != restore.identity || displaced.identity != current.identity {
        return Err(RescueFstabExecutionError::TargetChanged);
    }
    remove_name_if_identity(etc, &restore_name, displaced.identity)?;
    restore_guard.disarm();
    cleanup_known_stage(
        etc,
        &execution_stage_name_for(resource, reservation_id),
        intent.before_sha256(),
        intent.before_metadata(),
    );
    rfs::fsync(etc).map_err(|_| RescueFstabExecutionError::MutationFailed)?;
    rfs::syncfs(etc).map_err(|_| RescueFstabExecutionError::MutationFailed)?;
    let final_state = snapshot_repair_resource(etc, intent)?;
    ensure_snapshot_exact(
        &final_state,
        intent.before_sha256(),
        intent.before_metadata(),
    )?;
    Ok(final_state.observation())
}

fn open_etc_directory(mount: BorrowedFd<'_>) -> Result<OwnedFd, RescueFstabExecutionError> {
    let etc = rfs::openat2(
        mount,
        ETC_DIRECTORY,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC | OFlags::NOFOLLOW,
        Mode::empty(),
        ResolveFlags::BENEATH
            | ResolveFlags::NO_MAGICLINKS
            | ResolveFlags::NO_SYMLINKS
            | ResolveFlags::NO_XDEV,
    )
    .map_err(|_| RescueFstabExecutionError::UnsafeTarget)?;
    let stat = rfs::fstat(&etc).map_err(|_| RescueFstabExecutionError::UnsafeTarget)?;
    if !FileType::from_raw_mode(stat.st_mode).is_dir()
        || stat.st_uid != 0
        || stat.st_gid != 0
        || stat.st_mode & 0o022 != 0
    {
        return Err(RescueFstabExecutionError::UnsafeTarget);
    }
    Ok(etc)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct FileIdentity {
    device: u64,
    inode: u64,
}

struct FileSnapshot {
    identity: FileIdentity,
    bytes: Zeroizing<Vec<u8>>,
    metadata: RepairFileMetadataV1,
    resource_sha256: Sha256,
    metadata_sha256: Sha256,
}

impl FileSnapshot {
    fn observation(&self) -> ClosedObservation {
        ClosedObservation {
            resource_sha256: self.resource_sha256.clone(),
            metadata_sha256: self.metadata_sha256.clone(),
        }
    }

    fn same_object_and_value(&self, other: &Self) -> bool {
        self.identity == other.identity
            && self.bytes.as_slice() == other.bytes.as_slice()
            && self.metadata_sha256 == other.metadata_sha256
    }
}

#[cfg(test)]
fn snapshot_fstab(etc: &OwnedFd) -> Result<FileSnapshot, RescueFstabExecutionError> {
    snapshot_named(etc, FSTAB_RESOURCE)
}

fn snapshot_repair_resource(
    etc: &OwnedFd,
    intent: &RepairExecutionIntentV1,
) -> Result<FileSnapshot, RescueFstabExecutionError> {
    snapshot_named(etc, resource_leaf(repair_resource_for_intent(intent)?))
}

fn snapshot_named(
    directory: &OwnedFd,
    name: &str,
) -> Result<FileSnapshot, RescueFstabExecutionError> {
    let descriptor = rfs::openat2(
        directory,
        name,
        OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NOFOLLOW | OFlags::NONBLOCK,
        Mode::empty(),
        ResolveFlags::BENEATH | ResolveFlags::NO_MAGICLINKS | ResolveFlags::NO_SYMLINKS,
    )
    .map_err(|_| RescueFstabExecutionError::UnsafeTarget)?;
    let before = rfs::fstat(&descriptor).map_err(|_| RescueFstabExecutionError::UnsafeTarget)?;
    let before_xattr_size = validate_regular_file(&descriptor, &before)?;
    let size = usize::try_from(before.st_size)
        .ok()
        .filter(|size| (1..=MAX_REPAIR_RESOURCE_BYTES).contains(size))
        .ok_or(RescueFstabExecutionError::UnsafeTarget)?;
    let mut file = File::from(descriptor);
    let mut bytes = Zeroizing::new(Vec::with_capacity(size));
    Read::by_ref(&mut file)
        .take((MAX_REPAIR_RESOURCE_BYTES + 1) as u64)
        .read_to_end(&mut bytes)
        .map_err(|_| RescueFstabExecutionError::UnsafeTarget)?;
    if bytes.len() != size || bytes.contains(&0) || std::str::from_utf8(&bytes).is_err() {
        return Err(RescueFstabExecutionError::UnsafeTarget);
    }
    let after = rfs::fstat(&file).map_err(|_| RescueFstabExecutionError::UnsafeTarget)?;
    let after_xattr_size = validate_regular_file(&file, &after)?;
    let named = rfs::statat(directory, name, AtFlags::SYMLINK_NOFOLLOW)
        .map_err(|_| RescueFstabExecutionError::UnsafeTarget)?;
    if !same_stat(&before, &after)
        || !same_stat(&after, &named)
        || before_xattr_size != after_xattr_size
    {
        return Err(RescueFstabExecutionError::TargetChanged);
    }
    let metadata = RepairFileMetadataV1::new(after.st_mode & 0o7777, after.st_uid, after.st_gid)
        .map_err(|_| RescueFstabExecutionError::UnsafeTarget)?;
    let resource_sha256 = sha256(&bytes);
    let metadata_sha256 = if after_xattr_size == 0 {
        metadata.canonical_sha256()
    } else {
        noncanonical_metadata_sha256(&after, after_xattr_size)
    };
    Ok(FileSnapshot {
        identity: FileIdentity {
            device: after.st_dev,
            inode: after.st_ino,
        },
        bytes,
        metadata,
        resource_sha256,
        metadata_sha256,
    })
}

fn validate_regular_file(
    descriptor: impl AsFd,
    stat: &rustix::fs::Stat,
) -> Result<usize, RescueFstabExecutionError> {
    let descriptor_flags = rustix::io::fcntl_getfd(descriptor.as_fd())
        .map_err(|_| RescueFstabExecutionError::UnsafeTarget)?;
    let mut xattrs = [0_u8; 0];
    let xattr_size = rfs::flistxattr(descriptor.as_fd(), &mut xattrs)
        .map_err(|_| RescueFstabExecutionError::UnsafeTarget)?;
    if !FileType::from_raw_mode(stat.st_mode).is_file()
        || stat.st_nlink != 1
        || !descriptor_flags.contains(rustix::io::FdFlags::CLOEXEC)
    {
        return Err(RescueFstabExecutionError::UnsafeTarget);
    }
    Ok(xattr_size)
}

fn noncanonical_metadata_sha256(stat: &rustix::fs::Stat, xattr_size: usize) -> Sha256 {
    let mut digest = Sha256Hasher::new();
    digest.update(NONCANONICAL_METADATA_DOMAIN);
    digest.update((stat.st_mode & 0o7777).to_be_bytes());
    digest.update(stat.st_uid.to_be_bytes());
    digest.update(stat.st_gid.to_be_bytes());
    digest.update(u64::try_from(xattr_size).unwrap_or(u64::MAX).to_be_bytes());
    Sha256::parse(&format!("{:x}", digest.finalize())).expect("SHA-256 rendering is canonical")
}

fn same_stat(first: &rustix::fs::Stat, second: &rustix::fs::Stat) -> bool {
    first.st_dev == second.st_dev
        && first.st_ino == second.st_ino
        && first.st_mode == second.st_mode
        && first.st_nlink == second.st_nlink
        && first.st_uid == second.st_uid
        && first.st_gid == second.st_gid
        && first.st_size == second.st_size
}

struct NamedFileGuard<'directory> {
    directory: &'directory OwnedFd,
    name: String,
    identity: FileIdentity,
    armed: bool,
}

impl<'directory> NamedFileGuard<'directory> {
    fn existing(directory: &'directory OwnedFd, name: String, identity: FileIdentity) -> Self {
        Self {
            directory,
            name,
            identity,
            armed: true,
        }
    }

    fn disarm(&mut self) {
        self.armed = false;
    }
}

impl Drop for NamedFileGuard<'_> {
    fn drop(&mut self) {
        if !self.armed {
            return;
        }
        if let Ok(stat) = rfs::statat(
            self.directory,
            self.name.as_str(),
            AtFlags::SYMLINK_NOFOLLOW,
        ) && stat.st_dev == self.identity.device
            && stat.st_ino == self.identity.inode
        {
            let _ = rfs::unlinkat(self.directory, self.name.as_str(), AtFlags::empty());
            let _ = rfs::fsync(self.directory);
        }
    }
}

fn create_prepared_file<'directory>(
    directory: &'directory OwnedFd,
    name: &str,
    bytes: &[u8],
    metadata: &RepairFileMetadataV1,
) -> Result<(FileSnapshot, NamedFileGuard<'directory>), RescueFstabExecutionError> {
    if bytes.is_empty() || bytes.len() > MAX_REPAIR_RESOURCE_BYTES {
        return Err(RescueFstabExecutionError::InvalidAuthority);
    }
    let descriptor = rfs::openat(
        directory,
        name,
        OFlags::RDWR | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::RUSR | Mode::WUSR,
    )
    .map_err(|_| RescueFstabExecutionError::UnsafeTarget)?;
    let initial = rfs::fstat(&descriptor).map_err(|_| RescueFstabExecutionError::UnsafeTarget)?;
    if !FileType::from_raw_mode(initial.st_mode).is_file() || initial.st_nlink != 1 {
        return Err(RescueFstabExecutionError::UnsafeTarget);
    }
    let identity = FileIdentity {
        device: initial.st_dev,
        inode: initial.st_ino,
    };
    let mut guard = NamedFileGuard::existing(directory, name.to_owned(), identity);
    let mut file = File::from(descriptor);
    file.write_all(bytes)
        .map_err(|_| RescueFstabExecutionError::MutationFailed)?;
    rfs::fchown(
        &file,
        Some(Uid::from_raw(metadata.uid())),
        Some(Gid::from_raw(metadata.gid())),
    )
    .map_err(|_| RescueFstabExecutionError::MutationFailed)?;
    rfs::fchmod(&file, Mode::from_raw_mode(metadata.mode()))
        .map_err(|_| RescueFstabExecutionError::MutationFailed)?;
    file.sync_all()
        .map_err(|_| RescueFstabExecutionError::MutationFailed)?;
    file.seek(SeekFrom::Start(0))
        .map_err(|_| RescueFstabExecutionError::MutationFailed)?;
    let mut verified = Zeroizing::new(Vec::with_capacity(bytes.len()));
    Read::by_ref(&mut file)
        .take((MAX_REPAIR_RESOURCE_BYTES + 1) as u64)
        .read_to_end(&mut verified)
        .map_err(|_| RescueFstabExecutionError::MutationFailed)?;
    if verified.as_slice() != bytes {
        return Err(RescueFstabExecutionError::MutationFailed);
    }
    rfs::fsync(directory).map_err(|_| RescueFstabExecutionError::MutationFailed)?;
    let snapshot = snapshot_named(directory, name)?;
    if snapshot.identity != identity
        || snapshot.bytes.as_slice() != bytes
        || snapshot.metadata != *metadata
        || snapshot.metadata_sha256 != metadata.canonical_sha256()
    {
        return Err(RescueFstabExecutionError::TargetChanged);
    }
    // From here Drop may clean only this exact inode.
    guard.identity = snapshot.identity;
    Ok((snapshot, guard))
}

fn remove_name_if_identity(
    directory: &OwnedFd,
    name: &str,
    expected: FileIdentity,
) -> Result<(), RescueFstabExecutionError> {
    let stat = rfs::statat(directory, name, AtFlags::SYMLINK_NOFOLLOW)
        .map_err(|_| RescueFstabExecutionError::TargetChanged)?;
    if stat.st_dev != expected.device || stat.st_ino != expected.inode {
        return Err(RescueFstabExecutionError::TargetChanged);
    }
    rfs::unlinkat(directory, name, AtFlags::empty())
        .map_err(|_| RescueFstabExecutionError::MutationFailed)
}

fn cleanup_known_stage(
    directory: &OwnedFd,
    name: &str,
    expected_sha256: &Sha256,
    expected_metadata: &RepairFileMetadataV1,
) {
    let Ok(snapshot) = snapshot_named(directory, name) else {
        return;
    };
    if &snapshot.resource_sha256 == expected_sha256
        && snapshot.metadata_sha256 == expected_metadata.canonical_sha256()
        && &snapshot.metadata == expected_metadata
    {
        let _ = remove_name_if_identity(directory, name, snapshot.identity);
        let _ = rfs::fsync(directory);
    }
}

#[cfg(test)]
fn execution_stage_name(reservation_id: &str) -> String {
    execution_stage_name_for(RepairResourceV1::Fstab, reservation_id)
}

fn execution_stage_name_for(resource: RepairResourceV1, reservation_id: &str) -> String {
    format!(
        ".kernaid-{}-stage-v1-{}",
        resource_leaf(resource),
        reservation_id.strip_prefix("B-").unwrap_or("invalid")
    )
}

#[cfg(test)]
fn restore_stage_name(reservation_id: &str) -> String {
    restore_stage_name_for(RepairResourceV1::Fstab, reservation_id)
}

fn restore_stage_name_for(resource: RepairResourceV1, reservation_id: &str) -> String {
    format!(
        ".kernaid-{}-restore-v1-{}",
        resource_leaf(resource),
        reservation_id.strip_prefix("B-").unwrap_or("invalid")
    )
}

fn exact_state(snapshot: &FileSnapshot, intent: &RepairExecutionIntentV1) -> ExactTargetState {
    let metadata_exact = snapshot.metadata_sha256 == intent.before_metadata().canonical_sha256();
    if snapshot.resource_sha256 == *intent.before_sha256() && metadata_exact {
        ExactTargetState::Before
    } else if snapshot.resource_sha256 == *intent.after_sha256() && metadata_exact {
        ExactTargetState::After
    } else {
        ExactTargetState::Third
    }
}

fn ensure_snapshot_exact(
    snapshot: &FileSnapshot,
    expected_sha256: &Sha256,
    expected_metadata: &RepairFileMetadataV1,
) -> Result<(), RescueFstabExecutionError> {
    if &snapshot.resource_sha256 != expected_sha256
        || snapshot.metadata_sha256 != expected_metadata.canonical_sha256()
        || &snapshot.metadata != expected_metadata
    {
        return Err(RescueFstabExecutionError::TargetChanged);
    }
    Ok(())
}

fn ensure_exact_bytes(
    bytes: &[u8],
    expected_sha256: &Sha256,
) -> Result<(), RescueFstabExecutionError> {
    if &sha256(bytes) != expected_sha256 {
        return Err(RescueFstabExecutionError::InvalidAuthority);
    }
    Ok(())
}

fn sha256(bytes: &[u8]) -> Sha256 {
    Sha256::parse(&format!("{:x}", Sha256Hasher::digest(bytes)))
        .expect("SHA-256 rendering is canonical")
}

fn parse_prefixed_sha256(value: &str) -> Result<Sha256, RescueFstabExecutionError> {
    value
        .strip_prefix("sha256:")
        .ok_or(RescueFstabExecutionError::InvalidAuthority)
        .and_then(|digest| {
            Sha256::parse(digest).map_err(|_| RescueFstabExecutionError::InvalidAuthority)
        })
}

fn reserve_cleanup_window(deadline: Instant) -> Result<Instant, RescueFstabExecutionError> {
    let operation_deadline = deadline
        .checked_sub(SAFETY_CLEANUP_BUDGET)
        .ok_or(RescueFstabExecutionError::TimedOut)?;
    ensure_deadline(operation_deadline)?;
    Ok(operation_deadline)
}

fn reserve_resolution_window(deadline: Instant) -> Result<Instant, RescueFstabExecutionError> {
    let recovery_deadline = deadline
        .checked_sub(RESOLUTION_BUDGET)
        .ok_or(RescueFstabExecutionError::TimedOut)?;
    ensure_deadline(recovery_deadline)?;
    Ok(recovery_deadline)
}

fn ensure_deadline(deadline: Instant) -> Result<(), RescueFstabExecutionError> {
    if Instant::now() >= deadline {
        Err(RescueFstabExecutionError::TimedOut)
    } else {
        Ok(())
    }
}

fn authorization_not_persisted(_error: RescueFstabExecutionError) -> RescueFstabExecutionError {
    RescueFstabExecutionError::AuthorizationNotPersisted
}

fn prefer_initial_failure(
    initial: Option<RescueFstabExecutionError>,
    secondary: RescueFstabExecutionError,
) -> RescueFstabExecutionError {
    initial.unwrap_or(secondary)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;
    use std::{
        fs,
        path::{Path, PathBuf},
        sync::atomic::{AtomicU64, Ordering},
    };

    static TEST_SEQUENCE: AtomicU64 = AtomicU64::new(1);
    const BEFORE: &[u8] =
        b"UUID=aaaa / ext4 defaults 0 1\nUUID=dead-beef /srv/archive ext4 defaults 0 2\n";
    const AFTER: &[u8] = b"UUID=aaaa / ext4 defaults 0 1\n# KernAid Rescue disabled missing UUID: UUID=dead-beef /srv/archive ext4 defaults 0 2\n";
    #[cfg(feature = "rescue-crypttab-production-candidate")]
    const CRYPTTAB_BEFORE: &[u8] =
        b"archive UUID=dead-beef none luks,nofail\nroot UUID=aaaa none luks\n";
    #[cfg(feature = "rescue-crypttab-production-candidate")]
    const CRYPTTAB_AFTER: &[u8] = b"# KernAid Rescue disabled missing UUID: archive UUID=dead-beef none luks,nofail\nroot UUID=aaaa none luks\n";
    const RESERVATION: &str = "B-0123456789abcdef0123456789abcdef";

    #[test]
    fn startup_retries_only_transient_vault_states() {
        assert!(recovery_status_retryable(RepairVaultClientError::Remote(
            ErrorToken::Locked
        )));
        assert!(recovery_status_retryable(RepairVaultClientError::Remote(
            ErrorToken::Busy
        )));
        assert!(!recovery_status_retryable(
            RepairVaultClientError::Unavailable
        ));
        assert!(!recovery_status_retryable(RepairVaultClientError::Remote(
            ErrorToken::StaleState
        )));
    }

    #[test]
    fn rollback_source_uses_the_protocol_resource_id_not_the_leaf_filename() {
        assert_eq!(
            RepairResourceV1::from_resource_id(RepairResourceV1::Fstab.resource_id()),
            Ok(RepairResourceV1::Fstab)
        );
        assert_eq!(
            RepairResourceV1::from_resource_id(RepairResourceV1::Crypttab.resource_id()),
            Ok(RepairResourceV1::Crypttab)
        );
        assert!(RepairResourceV1::from_resource_id(FSTAB_RESOURCE).is_err());
    }

    #[test]
    fn execution_receipt_retains_failure_only_for_safe_closed_outcome() {
        let receipt = |outcome| RescueFstabExecutionReceipt {
            outcome,
            reservation_id: RESERVATION.to_owned(),
            transaction_binding_sha256: "8".repeat(64),
            initial_failure: None,
        };
        assert_eq!(
            receipt(RescueFstabExecutionOutcome::ClosedBeforeUnchanged)
                .with_initial_failure(RescueFstabExecutionError::MutationFailed)
                .initial_failure(),
            Some(RescueFstabExecutionError::MutationFailed)
        );
        assert_eq!(
            receipt(RescueFstabExecutionOutcome::Committed)
                .with_initial_failure(RescueFstabExecutionError::MutationFailed)
                .initial_failure(),
            None
        );
    }

    #[test]
    fn initial_apply_failure_precedes_later_closure_failure() {
        assert_eq!(
            prefer_initial_failure(
                Some(RescueFstabExecutionError::MutationFailed),
                RescueFstabExecutionError::VaultUnavailable,
            ),
            RescueFstabExecutionError::MutationFailed
        );
        assert_eq!(
            prefer_initial_failure(None, RescueFstabExecutionError::VaultUnavailable),
            RescueFstabExecutionError::VaultUnavailable
        );
    }

    struct DisposableTree(PathBuf);

    impl DisposableTree {
        fn new() -> Self {
            let sequence = TEST_SEQUENCE.fetch_add(1, Ordering::Relaxed);
            let path = PathBuf::from(format!(
                "/tmp/kernaid-rescue-fstab-executor-{}-{sequence}",
                std::process::id()
            ));
            fs::create_dir(&path).expect("create disposable test tree");
            Self(path)
        }

        fn path(&self) -> &Path {
            &self.0
        }
    }

    impl Drop for DisposableTree {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    fn raw_hash(character: char) -> Sha256 {
        Sha256::parse(&character.to_string().repeat(64)).expect("test digest")
    }

    fn setup() -> (DisposableTree, OwnedFd, RepairExecutionIntentV1) {
        let tree = DisposableTree::new();
        let resource_path = tree.path().join(FSTAB_RESOURCE);
        fs::write(&resource_path, BEFORE).expect("write disposable fstab");
        fs::set_permissions(&resource_path, fs::Permissions::from_mode(0o644))
            .expect("set canonical fstab mode");
        let directory = rfs::open(
            tree.path(),
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC | OFlags::NOFOLLOW,
            Mode::empty(),
        )
        .expect("open disposable directory");
        let snapshot = snapshot_fstab(&directory).expect("snapshot disposable fstab");
        let intent = RepairExecutionIntentV1::new(
            "S-test",
            1,
            "target-test",
            format!("scan:{}", "1".repeat(64)),
            raw_hash('2'),
            raw_hash('3'),
            format!("recovery:{}", "4".repeat(64)),
            format!("lock:{}", "5".repeat(64)),
            sha256(BEFORE),
            sha256(AFTER),
            raw_hash('6'),
            raw_hash('7'),
            snapshot.metadata,
        )
        .expect("execution intent");
        (tree, directory, intent)
    }

    #[cfg(feature = "rescue-crypttab-production-candidate")]
    fn crypttab_setup() -> (DisposableTree, OwnedFd, RepairExecutionIntentV1) {
        let tree = DisposableTree::new();
        let resource_path = tree.path().join(CRYPTTAB_RESOURCE);
        fs::write(&resource_path, CRYPTTAB_BEFORE).expect("write disposable crypttab");
        fs::set_permissions(&resource_path, fs::Permissions::from_mode(0o600))
            .expect("set private crypttab mode");
        let directory = rfs::open(
            tree.path(),
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC | OFlags::NOFOLLOW,
            Mode::empty(),
        )
        .expect("open disposable directory");
        let snapshot =
            snapshot_named(&directory, CRYPTTAB_RESOURCE).expect("snapshot disposable crypttab");
        let intent = RepairExecutionIntentV1::new_for_resource(
            RepairResourceV1::Crypttab,
            "S-test",
            1,
            "target-test",
            format!("scan:{}", "1".repeat(64)),
            raw_hash('2'),
            raw_hash('3'),
            format!("recovery:{}", "4".repeat(64)),
            format!("lock:{}", "5".repeat(64)),
            sha256(CRYPTTAB_BEFORE),
            sha256(CRYPTTAB_AFTER),
            raw_hash('6'),
            raw_hash('7'),
            snapshot.metadata,
        )
        .expect("crypttab execution intent");
        (tree, directory, intent)
    }

    #[test]
    fn exact_exchange_and_restore_are_atomic_and_metadata_bound() {
        let (tree, directory, intent) = setup();
        let observation = apply_exact_replacement(
            &directory,
            &directory,
            BEFORE,
            AFTER,
            &intent,
            RESERVATION,
            Instant::now() + Duration::from_secs(5),
            RescueFstabQualificationFault::None,
        )
        .expect("apply exact replacement");
        assert_eq!(observation.resource_sha256, *intent.after_sha256());
        assert_eq!(
            fs::read(tree.path().join(FSTAB_RESOURCE)).expect("read replaced fstab"),
            AFTER
        );
        assert!(!tree.path().join(execution_stage_name(RESERVATION)).exists());

        let restored = restore_exact_backup(
            &directory,
            &directory,
            BEFORE,
            &intent,
            RESERVATION,
            Instant::now() + Duration::from_secs(5),
        )
        .expect("restore exact backup");
        assert_eq!(restored.resource_sha256, *intent.before_sha256());
        assert_eq!(
            fs::read(tree.path().join(FSTAB_RESOURCE)).expect("read restored fstab"),
            BEFORE
        );
        assert!(!tree.path().join(restore_stage_name(RESERVATION)).exists());
    }

    #[cfg(feature = "rescue-crypttab-production-candidate")]
    #[test]
    fn crypttab_uses_shared_atomic_exchange_restore_and_private_metadata() {
        let (tree, directory, intent) = crypttab_setup();
        let installed = apply_exact_replacement(
            &directory,
            &directory,
            CRYPTTAB_BEFORE,
            CRYPTTAB_AFTER,
            &intent,
            RESERVATION,
            Instant::now() + Duration::from_secs(5),
            RescueFstabQualificationFault::None,
        )
        .expect("apply exact crypttab replacement");
        assert_eq!(installed.resource_sha256, *intent.after_sha256());
        assert_eq!(
            fs::read(tree.path().join(CRYPTTAB_RESOURCE)).expect("read replaced crypttab"),
            CRYPTTAB_AFTER
        );
        assert_eq!(
            fs::metadata(tree.path().join(CRYPTTAB_RESOURCE))
                .expect("crypttab metadata")
                .permissions()
                .mode()
                & 0o777,
            0o600
        );

        let restored = restore_exact_backup(
            &directory,
            &directory,
            CRYPTTAB_BEFORE,
            &intent,
            RESERVATION,
            Instant::now() + Duration::from_secs(5),
        )
        .expect("restore exact crypttab backup");
        assert_eq!(restored.resource_sha256, *intent.before_sha256());
        assert_eq!(
            fs::read(tree.path().join(CRYPTTAB_RESOURCE)).expect("read restored crypttab"),
            CRYPTTAB_BEFORE
        );
    }

    #[test]
    fn restore_never_overwrites_a_third_state() {
        let (tree, directory, intent) = setup();
        apply_exact_replacement(
            &directory,
            &directory,
            BEFORE,
            AFTER,
            &intent,
            RESERVATION,
            Instant::now() + Duration::from_secs(5),
            RescueFstabQualificationFault::None,
        )
        .expect("apply exact replacement");
        let third = b"# independently edited\n";
        fs::write(tree.path().join(FSTAB_RESOURCE), third).expect("write third state");
        assert!(
            restore_exact_backup(
                &directory,
                &directory,
                BEFORE,
                &intent,
                RESERVATION,
                Instant::now() + Duration::from_secs(5),
            )
            .is_err()
        );
        assert_eq!(
            fs::read(tree.path().join(FSTAB_RESOURCE)).expect("read independently edited fstab"),
            third
        );
    }

    #[test]
    fn qualification_failure_after_exact_install_uses_real_automatic_restore() {
        let (tree, directory, intent) = setup();
        let error = apply_exact_replacement(
            &directory,
            &directory,
            BEFORE,
            AFTER,
            &intent,
            RESERVATION,
            Instant::now() + Duration::from_secs(5),
            RescueFstabQualificationFault::FailAfterInstalled,
        )
        .expect_err("qualification hook must fail after durable install");
        assert_eq!(error, RescueFstabExecutionError::MutationFailed);
        assert_eq!(
            fs::read(tree.path().join(FSTAB_RESOURCE)).expect("read installed fstab"),
            AFTER
        );

        let closure = close_after_failed_mutation(
            &directory,
            &directory,
            BEFORE,
            &intent,
            RESERVATION,
            Instant::now() + Duration::from_secs(5),
        )
        .expect("automatic restore");
        assert_eq!(
            closure.outcome,
            RepairTransactionResolutionOutcome::ClosedBeforeRestored
        );
        assert_eq!(closure.observation.resource_sha256, *intent.before_sha256());
        assert_eq!(
            fs::read(tree.path().join(FSTAB_RESOURCE)).expect("read restored fstab"),
            BEFORE
        );
    }
}
