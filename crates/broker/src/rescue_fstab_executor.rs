//! Closed, off-default executor for the sole Phase 1 Rescue mutation.
//!
//! The public entrypoint accepts no pathname, device name, command, or raw
//! replacement supplied by a client. It consumes the broker-owned approved
//! authority, makes the exact pre-change bytes and a Pending transaction
//! durable in the Repair Vault, and only then consumes the root helper's
//! single-use detached writable ext4 mount capability.

use crate::{
    repair_vault_client::{RepairVaultClient, RepairVaultClientError},
    rescue_fstab_candidate::{
        ApprovedRescueFstabExecutionParts, ApprovedRescueFstabTransaction,
        RescueFstabCapabilityResolutionError, RescueFstabVaultReservation,
    },
    rescue_fstab_preflight_resolver::{
        ProductionRescueFstabTargetGuard, ProductionRescueFstabVaultReservation,
        reacquire_target_for_recovery,
    },
    target_write_capability_client::{
        RescueTargetWriteMountCapability, TargetWriteCapabilityClientError,
        acquire_pending_target_write_mount,
    },
};
use kernaid_protocol::{
    rescue_repair_vault::{
        RepairBackupBinding, RepairBackupState, RepairBackupStatusPayload, RepairExecutionIntentV1,
        RepairFileMetadataV1, RepairTransactionPhase, RepairTransactionResolution,
        RepairTransactionResolutionOutcome, RepairTransactionStatusPayload,
        RepairTransactionStatusSelector,
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
const ETC_DIRECTORY: &str = "etc";
const REPAIR_LOCK_DIRECTORY: &str = "/run/lock/kernaid-repair";
const MAX_FSTAB_BYTES: usize = 1024 * 1024;
const NONCANONICAL_METADATA_DOMAIN: &[u8] =
    b"kernaid:rescue-fstab:observed-noncanonical-metadata:v1\0";
const SAFETY_CLEANUP_BUDGET: Duration = Duration::from_secs(30);
const RESOLUTION_BUDGET: Duration = Duration::from_secs(10);
const LOCK_POLL: Duration = Duration::from_millis(5);
const VAULT_RECOVERY_POLL: Duration = Duration::from_millis(250);

static PROCESS_EXECUTOR_LOCK: Mutex<()> = Mutex::new(());

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
}

/// Sanitized execution failures. An error after persistence means the durable
/// Pending transaction remains the authority for recovery.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RescueFstabExecutionError {
    InvalidAuthority,
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

    // The read-only detached mount must be gone before the root helper creates
    // the exclusive writable superblock. From here the durable Pending record,
    // not any boot-local descriptor retained by this process, is authority.
    drop(target_guard);
    let write_mount = acquire_pending_target_write_mount(&pending, operation_deadline)
        .map_err(map_write_capability_error)?;
    let target_closure = execute_same_boot_target(
        write_mount,
        &backup_bytes,
        preview.proposed_fstab(),
        &intent,
        pending.backup().reservation_id().as_str(),
        operation_deadline,
    )?;

    let resolution = RepairTransactionResolution::new(
        target_closure.outcome,
        target_closure.observation.resource_sha256,
        target_closure.observation.metadata_sha256,
        target_closure.cleanup_verified,
        &intent,
    )
    .map_err(|_| RescueFstabExecutionError::RecoveryUnavailable)?;
    let resolved = resolve_pending(&mut vault_client, &pending, &resolution, deadline)?;
    receipt_from_status(&resolved)
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
    .map_err(|_| RescueFstabExecutionError::RecoveryUnavailable)?;
    let resolved = resolve_pending(&mut vault_client, &pending, &resolution, deadline)?;
    receipt_from_status(&resolved).map(Some)
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

#[derive(Clone)]
struct ClosedObservation {
    resource_sha256: Sha256,
    metadata_sha256: Sha256,
}

struct TargetClosure {
    outcome: RepairTransactionResolutionOutcome,
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
        ) {
            Ok(observation) => Ok(TargetClosure {
                outcome: RepairTransactionResolutionOutcome::CommittedAfter,
                observation,
                cleanup_verified: false,
            }),
            Err(_) => {
                close_after_failed_mutation(mount, &etc, backup, intent, reservation_id, deadline)
            }
        };
        drop(etc);
        result
    }?;
    write_mount
        .revalidate()
        .map_err(map_write_capability_error)?;
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
        }),
        ExactTargetState::Third => Ok(TargetClosure {
            outcome: RepairTransactionResolutionOutcome::ManualReconciliationRequired,
            observation: read_observation.1,
            cleanup_verified: true,
        }),
        ExactTargetState::After if pending.phase() != RepairTransactionPhase::Pending => {
            Ok(TargetClosure {
                outcome: RepairTransactionResolutionOutcome::ManualReconciliationRequired,
                observation: read_observation.1,
                cleanup_verified: true,
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
    let snapshot = snapshot_fstab(&etc)?;
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
                },
                Err(_) => {
                    let snapshot = snapshot_fstab(&etc)?;
                    TargetClosure {
                        outcome: if exact_state(&snapshot, intent) == ExactTargetState::Before {
                            RepairTransactionResolutionOutcome::ClosedBeforeRestored
                        } else {
                            RepairTransactionResolutionOutcome::ManualReconciliationRequired
                        },
                        observation: snapshot.observation(),
                        cleanup_verified: false,
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

fn close_after_failed_mutation(
    mount: &OwnedFd,
    etc: &OwnedFd,
    backup: &[u8],
    intent: &RepairExecutionIntentV1,
    reservation_id: &str,
    deadline: Instant,
) -> Result<TargetClosure, RescueFstabExecutionError> {
    let snapshot = snapshot_fstab(etc)?;
    match exact_state(&snapshot, intent) {
        ExactTargetState::Before => {
            cleanup_known_stage(
                etc,
                &execution_stage_name(reservation_id),
                intent.after_sha256(),
                intent.before_metadata(),
            );
            Ok(TargetClosure {
                outcome: RepairTransactionResolutionOutcome::ClosedBeforeUnchanged,
                observation: snapshot.observation(),
                cleanup_verified: false,
            })
        }
        ExactTargetState::After => {
            restore_exact_backup(mount, etc, backup, intent, reservation_id, deadline).map(
                |observation| TargetClosure {
                    outcome: RepairTransactionResolutionOutcome::ClosedBeforeRestored,
                    observation,
                    cleanup_verified: false,
                },
            )
        }
        ExactTargetState::Third => Ok(TargetClosure {
            outcome: RepairTransactionResolutionOutcome::ManualReconciliationRequired,
            observation: snapshot.observation(),
            cleanup_verified: false,
        }),
    }
}

fn apply_exact_replacement(
    mount: &OwnedFd,
    etc: &OwnedFd,
    backup: &[u8],
    proposed: &[u8],
    intent: &RepairExecutionIntentV1,
    reservation_id: &str,
    deadline: Instant,
) -> Result<ClosedObservation, RescueFstabExecutionError> {
    ensure_deadline(deadline)?;
    let before = snapshot_fstab(etc)?;
    ensure_snapshot_exact(&before, intent.before_sha256(), intent.before_metadata())?;
    if before.bytes.as_slice() != backup {
        return Err(RescueFstabExecutionError::TargetChanged);
    }

    let stage_name = execution_stage_name(reservation_id);
    let (prepared, mut stage_guard) =
        create_prepared_file(etc, &stage_name, proposed, intent.before_metadata())?;
    ensure_snapshot_exact(&prepared, intent.after_sha256(), intent.before_metadata())?;
    let current = snapshot_fstab(etc)?;
    if !current.same_object_and_value(&before) {
        return Err(RescueFstabExecutionError::TargetChanged);
    }
    ensure_deadline(deadline)?;

    rfs::renameat_with(etc, &stage_name, etc, FSTAB_RESOURCE, RenameFlags::EXCHANGE)
        .map_err(|_| RescueFstabExecutionError::MutationFailed)?;
    rfs::fsync(etc).map_err(|_| RescueFstabExecutionError::MutationFailed)?;
    rfs::syncfs(mount).map_err(|_| RescueFstabExecutionError::MutationFailed)?;

    let installed = snapshot_fstab(etc)?;
    let displaced = snapshot_named(etc, &stage_name)?;
    ensure_snapshot_exact(&installed, intent.after_sha256(), intent.before_metadata())?;
    ensure_snapshot_exact(&displaced, intent.before_sha256(), intent.before_metadata())?;
    if installed.identity != prepared.identity || displaced.identity != before.identity {
        return Err(RescueFstabExecutionError::TargetChanged);
    }
    remove_name_if_identity(etc, &stage_name, displaced.identity)?;
    stage_guard.disarm();
    rfs::fsync(etc).map_err(|_| RescueFstabExecutionError::MutationFailed)?;
    rfs::syncfs(mount).map_err(|_| RescueFstabExecutionError::MutationFailed)?;
    let final_state = snapshot_fstab(etc)?;
    ensure_snapshot_exact(
        &final_state,
        intent.after_sha256(),
        intent.before_metadata(),
    )?;
    Ok(final_state.observation())
}

fn restore_exact_backup(
    mount: &OwnedFd,
    etc: &OwnedFd,
    backup: &[u8],
    intent: &RepairExecutionIntentV1,
    reservation_id: &str,
    deadline: Instant,
) -> Result<ClosedObservation, RescueFstabExecutionError> {
    ensure_deadline(deadline)?;
    ensure_exact_bytes(backup, intent.before_sha256())?;
    let current = snapshot_fstab(etc)?;
    ensure_snapshot_exact(&current, intent.after_sha256(), intent.before_metadata())?;
    let restore_name = restore_stage_name(reservation_id);
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
    let recheck = snapshot_fstab(etc)?;
    if !recheck.same_object_and_value(&current) {
        return Err(RescueFstabExecutionError::TargetChanged);
    }
    ensure_deadline(deadline)?;
    rfs::renameat_with(
        etc,
        &restore_name,
        etc,
        FSTAB_RESOURCE,
        RenameFlags::EXCHANGE,
    )
    .map_err(|_| RescueFstabExecutionError::MutationFailed)?;
    rfs::fsync(etc).map_err(|_| RescueFstabExecutionError::MutationFailed)?;
    rfs::syncfs(mount).map_err(|_| RescueFstabExecutionError::MutationFailed)?;
    let restored = snapshot_fstab(etc)?;
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
        &execution_stage_name(reservation_id),
        intent.before_sha256(),
        intent.before_metadata(),
    );
    rfs::fsync(etc).map_err(|_| RescueFstabExecutionError::MutationFailed)?;
    rfs::syncfs(mount).map_err(|_| RescueFstabExecutionError::MutationFailed)?;
    let final_state = snapshot_fstab(etc)?;
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

fn snapshot_fstab(etc: &OwnedFd) -> Result<FileSnapshot, RescueFstabExecutionError> {
    snapshot_named(etc, FSTAB_RESOURCE)
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
        .filter(|size| (1..=MAX_FSTAB_BYTES).contains(size))
        .ok_or(RescueFstabExecutionError::UnsafeTarget)?;
    let mut file = File::from(descriptor);
    let mut bytes = Zeroizing::new(Vec::with_capacity(size));
    Read::by_ref(&mut file)
        .take((MAX_FSTAB_BYTES + 1) as u64)
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
    if bytes.is_empty() || bytes.len() > MAX_FSTAB_BYTES {
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
        .take((MAX_FSTAB_BYTES + 1) as u64)
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

fn execution_stage_name(reservation_id: &str) -> String {
    format!(
        ".kernaid-fstab-stage-v1-{}",
        reservation_id.strip_prefix("B-").unwrap_or("invalid")
    )
}

fn restore_stage_name(reservation_id: &str) -> String {
    format!(
        ".kernaid-fstab-restore-v1-{}",
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        fs,
        path::{Path, PathBuf},
        sync::atomic::{AtomicU64, Ordering},
    };

    static TEST_SEQUENCE: AtomicU64 = AtomicU64::new(1);
    const BEFORE: &[u8] =
        b"UUID=aaaa / ext4 defaults 0 1\nUUID=dead-beef /srv/archive ext4 defaults 0 2\n";
    const AFTER: &[u8] = b"UUID=aaaa / ext4 defaults 0 1\n# KernAid Rescue disabled missing UUID: UUID=dead-beef /srv/archive ext4 defaults 0 2\n";
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
        fs::write(tree.path().join(FSTAB_RESOURCE), BEFORE).expect("write disposable fstab");
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
}
