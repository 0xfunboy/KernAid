//! Read-only root-broker preflight for the disabled Rescue `fstab` candidate.
//!
//! The broker accepts only a Core admission that has already consumed the
//! exact local R2 approval and a closed, path-free protocol request. A trusted
//! resolver supplies observations and opaque capabilities while the selected
//! resource is held under a read-only lock. This module reconstructs the pure
//! preview and complete transaction plan; it performs no filesystem access,
//! mount, command execution, write, backup, validation or rollback.

use kernaid_core::{
    RESCUE_FSTAB_TYPED_CONFIRMATION as CORE_TYPED_CONFIRMATION, RescueFstabCandidateAdmission,
    RescueFstabCandidateAdmissionState,
};
use kernaid_linux_pack::{
    production_candidate_contract::{
        ACTION_ID, BACKUP_PHYSICAL_PARENT_POLICY, BACKUP_POLICY_ID, BACKUP_RESERVATION_POLICY_ID,
        CANCELLATION_POLICY_ID, FINDING_ID, FINDING_VERSION, IDEMPOTENCY_POLICY_ID, PREFLIGHT_ID,
        REDACTION_POLICY_ID, RESOURCE_ID, ROLLBACK_ID, SUPPORTED_FILESYSTEM,
        TRANSACTION_TIMEOUT_MILLISECONDS, VALIDATE_ID,
    },
    rescue_fstab_candidate::{
        DisableMissingUuidPreview, PreviewError, preview_disable_missing_uuid,
    },
    rescue_fstab_transaction_candidate::{
        BootVaultBackupCapability, CandidateEvidenceBinding, CandidatePlanClaims,
        CandidatePlanClaimsInput, CandidateTransactionError, FstabCandidateTransactionPlan,
        SelectedTargetCapability,
    },
};
use kernaid_protocol::rescue_repair::{
    RESCUE_FSTAB_EVIDENCE_IDS, RESCUE_FSTAB_READY_OUTCOME, RESCUE_FSTAB_RESOURCE_ID,
    RESCUE_FSTAB_TYPED_CONFIRMATION, RescueFstabPreflightReceipt, RescueFstabPreflightRequest,
};
use std::{collections::BTreeSet, fmt};

/// Sanitized failures returned by a trusted target/Vault capability resolver.
/// No variant can carry a path, command, raw observation or provider text.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RescueFstabCapabilityResolutionError {
    Unavailable,
    IdentityChanged,
    LockUnavailable,
}

/// Trusted observations resolved under an opaque read-only lock.
///
/// This type is intentionally neither serializable nor cloneable. Its custom
/// `Debug` implementation never reveals `fstab` or UUID observation bytes.
pub struct TrustedRescueFstabPreflightMaterial {
    resolved_target_fingerprint: String,
    fstab_bytes: Vec<u8>,
    observed_uuids: BTreeSet<String>,
    target: SelectedTargetCapability,
    vault: BootVaultBackupCapability,
    evidence: [CandidateEvidenceBinding; 2],
}

impl TrustedRescueFstabPreflightMaterial {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        resolved_target_fingerprint: impl Into<String>,
        fstab_bytes: Vec<u8>,
        observed_uuids: BTreeSet<String>,
        target: SelectedTargetCapability,
        vault: BootVaultBackupCapability,
        evidence: [CandidateEvidenceBinding; 2],
    ) -> Self {
        Self {
            resolved_target_fingerprint: resolved_target_fingerprint.into(),
            fstab_bytes,
            observed_uuids,
            target,
            vault,
            evidence,
        }
    }
}

impl fmt::Debug for TrustedRescueFstabPreflightMaterial {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("TrustedRescueFstabPreflightMaterial")
            .field("resolved_target_fingerprint", &"[opaque fingerprint]")
            .field("fstab_bytes", &"[redacted]")
            .field("observed_uuid_count", &self.observed_uuids.len())
            .field("target", &"[opaque capability]")
            .field("vault", &"[opaque capability]")
            .field("evidence", &"[opaque hashes]")
            .finish()
    }
}

/// Trusted local resolver boundary. Implementations may resolve target/Vault
/// capabilities, but this broker only ever passes the closed path-free
/// request and an opaque lock guard. Observations must be collected while the
/// returned guard is held.
pub trait RescueFstabPreflightCapabilityResolver {
    /// Opaque, non-cloneable guard that keeps the selected target/resource
    /// locked read-only for the lifetime of the prepared preflight.
    type ReadOnlyLock;

    /// Opaque, non-cloneable guard that keeps the exact Boot Vault capacity
    /// reservation alive for the lifetime of the prepared preflight.
    type VaultReservation;

    fn acquire_read_only_lock(
        &mut self,
        request: &RescueFstabPreflightRequest,
    ) -> Result<Self::ReadOnlyLock, RescueFstabCapabilityResolutionError>;

    fn resolve_under_read_only_lock(
        &mut self,
        request: &RescueFstabPreflightRequest,
        lock: &Self::ReadOnlyLock,
    ) -> Result<TrustedRescueFstabPreflightMaterial, RescueFstabCapabilityResolutionError>;

    /// Retain the exact reservation described by the trusted material. The
    /// implementation must fail unless it still owns that reservation.
    fn retain_vault_reservation(
        &mut self,
        request: &RescueFstabPreflightRequest,
        lock: &Self::ReadOnlyLock,
        material: &TrustedRescueFstabPreflightMaterial,
    ) -> Result<Self::VaultReservation, RescueFstabCapabilityResolutionError>;

    fn reservation_id<'reservation>(
        &self,
        reservation: &'reservation Self::VaultReservation,
    ) -> &'reservation str;

    fn reservation_binding_sha256<'reservation>(
        &self,
        reservation: &'reservation Self::VaultReservation,
    ) -> &'reservation str;

    /// Stable opaque identity of the held guard. It is copied into the
    /// receipt; no OS handle, device name or path crosses the protocol.
    fn lock_identity<'lock>(&self, lock: &'lock Self::ReadOnlyLock) -> &'lock str;
}

/// A successful point-in-time preflight that retains all execution authority.
///
/// It is deliberately not `Clone`: dropping this value drops the Core
/// admission, trusted target lock and exact Vault reservation. A future
/// executor must consume this value. The receipt is evidence only and must
/// never be accepted as execution authority.
pub struct PreparedRescueFstabPreflight<Lock, Reservation> {
    receipt: RescueFstabPreflightReceipt,
    plan: FstabCandidateTransactionPlan,
    preview: DisableMissingUuidPreview,
    _admission: RescueFstabCandidateAdmission,
    _lock: Lock,
    _reservation: Reservation,
}

impl<Lock, Reservation> PreparedRescueFstabPreflight<Lock, Reservation> {
    /// Audit evidence only. Possession of this receipt grants no authority.
    pub fn receipt(&self) -> &RescueFstabPreflightReceipt {
        &self.receipt
    }

    pub fn plan(&self) -> &FstabCandidateTransactionPlan {
        &self.plan
    }

    pub fn before_sha256(&self) -> &str {
        self.preview.before_sha256()
    }

    pub fn after_sha256(&self) -> &str {
        self.preview.after_sha256()
    }

    pub fn diff_sha256(&self) -> &str {
        self.preview.diff_sha256()
    }
}

impl<Lock, Reservation> fmt::Debug for PreparedRescueFstabPreflight<Lock, Reservation> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PreparedRescueFstabPreflight")
            .field("receipt", &self.receipt)
            .field("plan_hash", &self.plan.plan_sha256())
            .field("before_sha256", &self.preview.before_sha256())
            .field("after_sha256", &self.preview.after_sha256())
            .field("preview_bytes", &"[redacted]")
            .field("lock", &"[opaque guard]")
            .field("reservation", &"[opaque guard]")
            .finish()
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RescueFstabPreflightError {
    ApprovalRequired,
    AdmissionBindingMismatch,
    ApprovalBindingMismatch,
    TargetIdentityMismatch,
    EvidenceBindingMismatch,
    TargetSnapshotMismatch,
    PlanHashMismatch,
    Resolver(RescueFstabCapabilityResolutionError),
    PreviewRejected(PreviewError),
    TransactionRejected(CandidateTransactionError),
    InvalidLockIdentity,
    ReservationBindingMismatch,
    ReceiptRejected,
}

/// Reconstruct and verify the complete candidate preflight while retaining
/// the trusted read-only lock. Nothing in this function can perform or expose
/// a target mutation.
pub fn prepare_rescue_fstab_preflight<Resolver>(
    admission: RescueFstabCandidateAdmission,
    request: RescueFstabPreflightRequest,
    resolver: &mut Resolver,
) -> Result<
    PreparedRescueFstabPreflight<Resolver::ReadOnlyLock, Resolver::VaultReservation>,
    RescueFstabPreflightError,
>
where
    Resolver: RescueFstabPreflightCapabilityResolver,
{
    validate_admission_and_request(&admission, &request)?;

    let lock = resolver
        .acquire_read_only_lock(&request)
        .map_err(RescueFstabPreflightError::Resolver)?;
    let material = resolver
        .resolve_under_read_only_lock(&request, &lock)
        .map_err(RescueFstabPreflightError::Resolver)?;

    if material.resolved_target_fingerprint != request.target_fingerprint()
        || material.target.target_id() != request.target_id()
        || material.target.scan_fingerprint() != request.scan_fingerprint()
    {
        return Err(RescueFstabPreflightError::TargetIdentityMismatch);
    }

    for (request_binding, resolved_binding) in request.evidence().iter().zip(&material.evidence) {
        if request_binding.evidence_id() != resolved_binding.evidence_id()
            || request_binding.sha256() != resolved_binding.sha256()
        {
            return Err(RescueFstabPreflightError::EvidenceBindingMismatch);
        }
    }

    let preview = preview_disable_missing_uuid(&material.fstab_bytes, &material.observed_uuids)
        .map_err(RescueFstabPreflightError::PreviewRejected)?;
    if preview.before_sha256() != request.target_snapshot() {
        return Err(RescueFstabPreflightError::TargetSnapshotMismatch);
    }

    let reservation = resolver
        .retain_vault_reservation(&request, &lock, &material)
        .map_err(RescueFstabPreflightError::Resolver)?;
    if resolver.reservation_id(&reservation) != material.vault.reservation_id()
        || resolver.reservation_binding_sha256(&reservation)
            != material.vault.reservation_binding_sha256()
    {
        return Err(RescueFstabPreflightError::ReservationBindingMismatch);
    }

    let claims =
        canonical_claims(&request).map_err(RescueFstabPreflightError::TransactionRejected)?;
    let plan = FstabCandidateTransactionPlan::stage(
        &preview,
        claims,
        material.target,
        material.vault,
        material.evidence.into(),
    )
    .map_err(RescueFstabPreflightError::TransactionRejected)?;
    if plan.plan_sha256() != request.plan_hash() {
        return Err(RescueFstabPreflightError::PlanHashMismatch);
    }

    let lock_identity = resolver.lock_identity(&lock);
    if !valid_opaque_lock_identity(lock_identity) {
        return Err(RescueFstabPreflightError::InvalidLockIdentity);
    }
    let receipt = RescueFstabPreflightReceipt::new(
        request,
        plan.vault().vault_id(),
        plan.vault().reservation_id(),
        plan.vault().reservation_binding_sha256(),
        plan.vault().backup_locator(),
        plan.vault().vault_identity_fingerprint(),
        plan.target().physical_parent_fingerprint(),
        plan.vault().physical_parent_fingerprint(),
        plan.vault().required_capacity_bytes(),
        plan.vault().reserved_capacity_bytes(),
        lock_identity,
        RESCUE_FSTAB_READY_OUTCOME,
    )
    .map_err(|_| RescueFstabPreflightError::ReceiptRejected)?;

    Ok(PreparedRescueFstabPreflight {
        receipt,
        plan,
        preview,
        _admission: admission,
        _lock: lock,
        _reservation: reservation,
    })
}

fn validate_admission_and_request(
    admission: &RescueFstabCandidateAdmission,
    request: &RescueFstabPreflightRequest,
) -> Result<(), RescueFstabPreflightError> {
    if admission.state() != RescueFstabCandidateAdmissionState::Approved {
        return Err(RescueFstabPreflightError::ApprovalRequired);
    }
    let binding = admission.binding();
    if request.session_id() != binding.session_id()
        || request.plan_id() != binding.plan_id()
        || request.plan_hash() != binding.plan_hash()
        || request.target_fingerprint() != binding.target_fingerprint()
        || request.target_snapshot() != binding.target_snapshot()
        || request.resource_id() != binding.resource_id()
        || request.resource_id() != RESCUE_FSTAB_RESOURCE_ID
        || request.resource_id() != RESOURCE_ID
    {
        return Err(RescueFstabPreflightError::AdmissionBindingMismatch);
    }
    if admission.approval_id() != Some(request.approval_id())
        || admission.approval_sequence() != Some(request.approval_sequence())
        || admission.next_approval_sequence() != request.approval_sequence()
        || request.typed_confirmation() != RESCUE_FSTAB_TYPED_CONFIRMATION
        || request.typed_confirmation() != CORE_TYPED_CONFIRMATION
    {
        return Err(RescueFstabPreflightError::ApprovalBindingMismatch);
    }
    for (binding, expected_id) in request.evidence().iter().zip(RESCUE_FSTAB_EVIDENCE_IDS) {
        if binding.evidence_id() != expected_id {
            return Err(RescueFstabPreflightError::EvidenceBindingMismatch);
        }
    }
    Ok(())
}

fn canonical_claims(
    request: &RescueFstabPreflightRequest,
) -> Result<CandidatePlanClaims, CandidateTransactionError> {
    CandidatePlanClaims::admit(CandidatePlanClaimsInput {
        session_id: request.session_id(),
        plan_id: request.plan_id(),
        action_id: ACTION_ID,
        resource_id: RESOURCE_ID,
        finding_id: FINDING_ID,
        finding_version: FINDING_VERSION,
        risk: "R2",
        supported_filesystem: SUPPORTED_FILESYSTEM,
        preflight_id: PREFLIGHT_ID,
        backup_policy_id: BACKUP_POLICY_ID,
        backup_reservation_policy_id: BACKUP_RESERVATION_POLICY_ID,
        backup_physical_parent_policy: BACKUP_PHYSICAL_PARENT_POLICY,
        validation_id: VALIDATE_ID,
        rollback_id: ROLLBACK_ID,
        timeout_milliseconds: TRANSACTION_TIMEOUT_MILLISECONDS,
        cancellation_policy_id: CANCELLATION_POLICY_ID,
        idempotency_policy_id: IDEMPOTENCY_POLICY_ID,
        redaction_policy_id: REDACTION_POLICY_ID,
    })
}

fn valid_opaque_lock_identity(value: &str) -> bool {
    (1..=96).contains(&value.len())
        && !value.contains("..")
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b':' | b'.'))
}

#[cfg(test)]
mod tests {
    use super::*;
    use kernaid_core::{
        RESCUE_FSTAB_TYPED_CONFIRMATION, RescueFstabCandidateApproval, Session, SessionMode,
    };
    use kernaid_evidence::{
        Evidence,
        linux_snapshot::{
            COLLECTION_SCOPE, COLLECTOR as LINUX_SNAPSHOT_COLLECTOR,
            CONTENT_TYPE as LINUX_SNAPSHOT_CONTENT_TYPE, LinuxBoot, LinuxConfiguration,
            LinuxFilesystemTopology, LinuxFstabSummary, LinuxNormalizedSnapshot,
            LinuxNormalizedSnapshotEnvelope, LinuxPackageDatabases, LinuxRelease,
            LinuxSnapshotCapture, SNAPSHOT_SCOPE,
        },
    };
    use kernaid_protocol::{
        ActionStep, Risk, ValidatedPlan, rescue_repair::RescueFstabEvidenceBinding,
    };
    use sha2::{Digest, Sha256};
    use std::sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    };

    const SESSION_ID: &str = "S-rescue-preflight";
    const PLAN_ID: &str = "P-rescue-fstab";
    const APPROVAL_ID: &str = "A-rescue-fstab";
    const APPROVAL_SEQUENCE: u64 = 7;
    const FSTAB: &[u8] =
        b"UUID=AAAA-BBBB / ext4 defaults 0 1\nUUID=DEAD-BEEF /srv/archive ext4 defaults 0 2\n";
    fn hash(character: char) -> String {
        format!("sha256:{}", character.to_string().repeat(64))
    }

    fn scan(character: char) -> String {
        format!("scan:{}", character.to_string().repeat(64))
    }

    fn observed() -> BTreeSet<String> {
        BTreeSet::from(["aaaa-bbbb".to_owned()])
    }

    fn target(scan_character: char, parent: char) -> SelectedTargetCapability {
        SelectedTargetCapability::new("target-01", scan(scan_character), hash(parent))
            .expect("target capability")
    }

    fn vault(parent: char, required: u64, reserved: u64) -> BootVaultBackupCapability {
        BootVaultBackupCapability::new(
            "vault-01",
            "B-preflight",
            hash('b'),
            "vault://repair/B-preflight",
            hash('c'),
            hash(parent),
            true,
            required,
            reserved,
        )
        .expect("Vault capability")
    }

    fn transaction_evidence(first_hash: char, second_hash: char) -> [CandidateEvidenceBinding; 2] {
        [
            CandidateEvidenceBinding::new(RESCUE_FSTAB_EVIDENCE_IDS[0], hash(first_hash))
                .expect("fstab evidence"),
            CandidateEvidenceBinding::new(RESCUE_FSTAB_EVIDENCE_IDS[1], hash(second_hash))
                .expect("lsblk evidence"),
        ]
    }

    fn protocol_evidence(first_hash: char, second_hash: char) -> [RescueFstabEvidenceBinding; 2] {
        [
            RescueFstabEvidenceBinding::new(RESCUE_FSTAB_EVIDENCE_IDS[0], hash(first_hash))
                .expect("protocol fstab evidence"),
            RescueFstabEvidenceBinding::new(RESCUE_FSTAB_EVIDENCE_IDS[1], hash(second_hash))
                .expect("protocol lsblk evidence"),
        ]
    }

    fn exact_plan() -> FstabCandidateTransactionPlan {
        let preview = preview_disable_missing_uuid(FSTAB, &observed()).expect("preview");
        let claims = CandidatePlanClaims::admit(CandidatePlanClaimsInput {
            session_id: SESSION_ID,
            plan_id: PLAN_ID,
            action_id: ACTION_ID,
            resource_id: RESOURCE_ID,
            finding_id: FINDING_ID,
            finding_version: FINDING_VERSION,
            risk: "R2",
            supported_filesystem: SUPPORTED_FILESYSTEM,
            preflight_id: PREFLIGHT_ID,
            backup_policy_id: BACKUP_POLICY_ID,
            backup_reservation_policy_id: BACKUP_RESERVATION_POLICY_ID,
            backup_physical_parent_policy: BACKUP_PHYSICAL_PARENT_POLICY,
            validation_id: VALIDATE_ID,
            rollback_id: ROLLBACK_ID,
            timeout_milliseconds: TRANSACTION_TIMEOUT_MILLISECONDS,
            cancellation_policy_id: CANCELLATION_POLICY_ID,
            idempotency_policy_id: IDEMPOTENCY_POLICY_ID,
            redaction_policy_id: REDACTION_POLICY_ID,
        })
        .expect("claims");
        FstabCandidateTransactionPlan::stage(
            &preview,
            claims,
            target('1', 'a'),
            vault('b', 4096, 8192),
            transaction_evidence('d', 'e').into(),
        )
        .expect("transaction plan")
    }

    #[allow(clippy::too_many_arguments)]
    fn request(
        session_id: &str,
        plan_hash: &str,
        target_snapshot: &str,
        target_id: &str,
        scan_fingerprint: &str,
        approval_id: &str,
        approval_sequence: u64,
        evidence: [RescueFstabEvidenceBinding; 2],
    ) -> RescueFstabPreflightRequest {
        RescueFstabPreflightRequest::new(
            session_id,
            PLAN_ID,
            plan_hash,
            hash('f'),
            target_snapshot,
            RESOURCE_ID,
            target_id,
            scan_fingerprint,
            approval_id,
            approval_sequence,
            RESCUE_FSTAB_TYPED_CONFIRMATION,
            evidence,
        )
        .expect("request")
    }

    fn exact_request() -> RescueFstabPreflightRequest {
        let plan = exact_plan();
        request(
            SESSION_ID,
            plan.plan_sha256(),
            plan.before_sha256(),
            plan.target().target_id(),
            plan.target().scan_fingerprint(),
            APPROVAL_ID,
            APPROVAL_SEQUENCE,
            protocol_evidence('d', 'e'),
        )
    }

    fn candidate_core_plan() -> ValidatedPlan {
        ValidatedPlan {
            plan_id: PLAN_ID.to_owned(),
            target_fingerprint: hash('f'),
            steps: vec![ActionStep {
                action: ACTION_ID.to_owned(),
                risk: Risk::R2,
                target_fingerprint: hash('f'),
                evidence_ids: RESCUE_FSTAB_EVIDENCE_IDS
                    .iter()
                    .map(|value| (*value).to_owned())
                    .collect(),
                preconditions: vec![PREFLIGHT_ID.to_owned()],
                backup: Some("required".to_owned()),
                validation: VALIDATE_ID.to_owned(),
                rollback: Some(ROLLBACK_ID.to_owned()),
            }],
        }
    }

    fn rescue_snapshot() -> (Evidence, Vec<u8>) {
        let bytes = LinuxNormalizedSnapshotEnvelope::new(
            LinuxSnapshotCapture::rescue(),
            LinuxNormalizedSnapshot {
                family: "linux".to_owned(),
                scope: SNAPSHOT_SCOPE.to_owned(),
                installation_confirmed: true,
                topology: LinuxFilesystemTopology {
                    collection_scope: COLLECTION_SCOPE.to_owned(),
                    separate_etc_mount_present: false,
                    separate_boot_mount_present: false,
                    separate_usr_mount_present: false,
                    separate_var_mount_present: false,
                    relevant_separate_mount_present: false,
                    supported: true,
                },
                release: LinuxRelease {
                    id: Some("fixture".to_owned()),
                    name: None,
                    pretty_name: None,
                    version_id: None,
                    source: "etc-os-release".to_owned(),
                },
                boot: LinuxBoot {
                    directory_present: false,
                    kernel_artifact_count: 0,
                    initramfs_artifact_count: 0,
                    bootloader_directory_count: 0,
                    symlink_artifact_count: 0,
                },
                configuration: LinuxConfiguration {
                    fstab: LinuxFstabSummary {
                        present: true,
                        entry_count: 2,
                        root_entry_present: true,
                        efi_entry_present: false,
                        swap_entry_count: 0,
                        network_entry_count: 0,
                        malformed_line_count: 0,
                    },
                    machine_id_present: true,
                },
                package_databases: LinuxPackageDatabases {
                    dpkg_status_present: false,
                    rpm_database_present: false,
                    pacman_database_present: false,
                },
            },
        )
        .expect("snapshot")
        .canonical_json()
        .expect("canonical snapshot");
        let digest = format!("{:x}", Sha256::digest(&bytes));
        let evidence = Evidence {
            id: "E-SNAPSHOT".to_owned(),
            collector: LINUX_SNAPSHOT_COLLECTOR.to_owned(),
            target: "selected-installed-target".to_owned(),
            captured_at: "2026-08-28T00:00:00Z".to_owned(),
            content_type: LINUX_SNAPSHOT_CONTENT_TYPE.to_owned(),
            sha256: digest.clone(),
            sensitivity: "system".to_owned(),
            trust: "observed-untrusted".to_owned(),
            summary: "fixture".to_owned(),
            blob_ref: format!("sha256:{digest}"),
        };
        (evidence, bytes)
    }

    fn admission(
        plan_hash: &str,
        target_snapshot: &str,
        approved: bool,
    ) -> RescueFstabCandidateAdmission {
        let (snapshot, bytes) = rescue_snapshot();
        let mut session = Session::new(hash('f'), SessionMode::LinuxRescue);
        session
            .admit_linux_snapshot(&snapshot, &bytes)
            .expect("admit snapshot");
        session
            .linux_evidence_complete(std::slice::from_ref(&snapshot))
            .expect("diagnosis boundary");
        let mut admission = session
            .stage_rescue_fstab_production_candidate(
                &candidate_core_plan(),
                SESSION_ID,
                plan_hash,
                target_snapshot,
                APPROVAL_SEQUENCE - 1,
            )
            .expect("stage candidate");
        if approved {
            let approval = RescueFstabCandidateApproval::new(
                admission.binding().clone(),
                APPROVAL_ID,
                APPROVAL_SEQUENCE,
                RESCUE_FSTAB_TYPED_CONFIRMATION,
            )
            .expect("approval");
            admission.approve(&approval).expect("approve candidate");
        }
        admission
    }

    fn exact_material() -> TrustedRescueFstabPreflightMaterial {
        TrustedRescueFstabPreflightMaterial::new(
            hash('f'),
            FSTAB.to_vec(),
            observed(),
            target('1', 'a'),
            vault('b', 4096, 8192),
            transaction_evidence('d', 'e'),
        )
    }

    struct TestLock {
        identity: String,
        dropped: Arc<AtomicBool>,
    }

    impl Drop for TestLock {
        fn drop(&mut self) {
            self.dropped.store(true, Ordering::SeqCst);
        }
    }

    struct TestReservation {
        reservation_id: String,
        binding_sha256: String,
        dropped: Arc<AtomicBool>,
    }

    impl Drop for TestReservation {
        fn drop(&mut self) {
            self.dropped.store(true, Ordering::SeqCst);
        }
    }

    struct TestResolver {
        material: Option<TrustedRescueFstabPreflightMaterial>,
        lock_identity: String,
        reservation_id: String,
        reservation_binding_sha256: String,
        lock_acquired: bool,
        resolved_under_lock: bool,
        reservation_retained: bool,
        lock_dropped: Arc<AtomicBool>,
        reservation_dropped: Arc<AtomicBool>,
    }

    impl TestResolver {
        fn new(material: TrustedRescueFstabPreflightMaterial) -> Self {
            let reservation_id = material.vault.reservation_id().to_owned();
            let reservation_binding_sha256 = material.vault.reservation_binding_sha256().to_owned();
            Self {
                material: Some(material),
                lock_identity: format!("lock:{}", "9".repeat(64)),
                reservation_id,
                reservation_binding_sha256,
                lock_acquired: false,
                resolved_under_lock: false,
                reservation_retained: false,
                lock_dropped: Arc::new(AtomicBool::new(false)),
                reservation_dropped: Arc::new(AtomicBool::new(false)),
            }
        }
    }

    impl RescueFstabPreflightCapabilityResolver for TestResolver {
        type ReadOnlyLock = TestLock;
        type VaultReservation = TestReservation;

        fn acquire_read_only_lock(
            &mut self,
            _request: &RescueFstabPreflightRequest,
        ) -> Result<Self::ReadOnlyLock, RescueFstabCapabilityResolutionError> {
            self.lock_acquired = true;
            Ok(TestLock {
                identity: self.lock_identity.clone(),
                dropped: Arc::clone(&self.lock_dropped),
            })
        }

        fn resolve_under_read_only_lock(
            &mut self,
            _request: &RescueFstabPreflightRequest,
            _lock: &Self::ReadOnlyLock,
        ) -> Result<TrustedRescueFstabPreflightMaterial, RescueFstabCapabilityResolutionError>
        {
            if !self.lock_acquired {
                return Err(RescueFstabCapabilityResolutionError::LockUnavailable);
            }
            self.resolved_under_lock = true;
            self.material
                .take()
                .ok_or(RescueFstabCapabilityResolutionError::Unavailable)
        }

        fn retain_vault_reservation(
            &mut self,
            _request: &RescueFstabPreflightRequest,
            _lock: &Self::ReadOnlyLock,
            _material: &TrustedRescueFstabPreflightMaterial,
        ) -> Result<Self::VaultReservation, RescueFstabCapabilityResolutionError> {
            if !self.resolved_under_lock {
                return Err(RescueFstabCapabilityResolutionError::LockUnavailable);
            }
            self.reservation_retained = true;
            Ok(TestReservation {
                reservation_id: self.reservation_id.clone(),
                binding_sha256: self.reservation_binding_sha256.clone(),
                dropped: Arc::clone(&self.reservation_dropped),
            })
        }

        fn reservation_id<'reservation>(
            &self,
            reservation: &'reservation Self::VaultReservation,
        ) -> &'reservation str {
            &reservation.reservation_id
        }

        fn reservation_binding_sha256<'reservation>(
            &self,
            reservation: &'reservation Self::VaultReservation,
        ) -> &'reservation str {
            &reservation.binding_sha256
        }

        fn lock_identity<'lock>(&self, lock: &'lock Self::ReadOnlyLock) -> &'lock str {
            &lock.identity
        }
    }

    #[test]
    fn approved_exact_request_returns_ready_receipt_and_retains_lock() {
        let request = exact_request();
        let admission = admission(request.plan_hash(), request.target_snapshot(), true);
        let mut resolver = TestResolver::new(exact_material());
        let dropped = Arc::clone(&resolver.lock_dropped);
        let reservation_dropped = Arc::clone(&resolver.reservation_dropped);
        let expected_lock_identity = resolver.lock_identity.clone();

        let prepared = prepare_rescue_fstab_preflight(admission, request, &mut resolver)
            .expect("read-only preflight");
        assert!(resolver.lock_acquired);
        assert!(resolver.resolved_under_lock);
        assert!(resolver.reservation_retained);
        assert!(!dropped.load(Ordering::SeqCst));
        assert!(!reservation_dropped.load(Ordering::SeqCst));
        assert_eq!(prepared.receipt().outcome(), RESCUE_FSTAB_READY_OUTCOME);
        assert_eq!(
            prepared.receipt().plan_hash(),
            prepared.plan().plan_sha256()
        );
        assert_eq!(
            prepared.receipt().target_snapshot(),
            prepared.before_sha256()
        );
        assert_eq!(prepared.receipt().lock_identity(), expected_lock_identity);
        let debug = format!("{prepared:?}");
        assert!(!debug.contains("DEAD-BEEF"));
        drop(prepared);
        assert!(dropped.load(Ordering::SeqCst));
        assert!(reservation_dropped.load(Ordering::SeqCst));
    }

    #[test]
    fn recomputation_rejects_target_snapshot_plan_and_evidence_drift() {
        let exact = exact_request();

        let staged = admission(exact.plan_hash(), exact.target_snapshot(), false);
        let mut resolver = TestResolver::new(exact_material());
        assert_eq!(
            prepare_rescue_fstab_preflight(staged, exact.clone(), &mut resolver)
                .expect_err("approval is mandatory"),
            RescueFstabPreflightError::ApprovalRequired
        );
        assert!(!resolver.lock_acquired);

        let approved = admission(exact.plan_hash(), exact.target_snapshot(), true);
        let sequence_drift = request(
            SESSION_ID,
            exact.plan_hash(),
            exact.target_snapshot(),
            exact.target_id(),
            exact.scan_fingerprint(),
            APPROVAL_ID,
            APPROVAL_SEQUENCE + 1,
            protocol_evidence('d', 'e'),
        );
        let mut resolver = TestResolver::new(exact_material());
        assert_eq!(
            prepare_rescue_fstab_preflight(approved, sequence_drift, &mut resolver)
                .expect_err("approval sequence drift"),
            RescueFstabPreflightError::ApprovalBindingMismatch
        );
        assert!(!resolver.lock_acquired);

        let stale_snapshot = hash('8');
        let stale_request = request(
            SESSION_ID,
            exact.plan_hash(),
            &stale_snapshot,
            exact.target_id(),
            exact.scan_fingerprint(),
            APPROVAL_ID,
            APPROVAL_SEQUENCE,
            protocol_evidence('d', 'e'),
        );
        let stale_admission = admission(stale_request.plan_hash(), &stale_snapshot, true);
        let mut resolver = TestResolver::new(exact_material());
        assert_eq!(
            prepare_rescue_fstab_preflight(stale_admission, stale_request, &mut resolver)
                .expect_err("target snapshot drift"),
            RescueFstabPreflightError::TargetSnapshotMismatch
        );

        let foreign_plan_hash = hash('7');
        let drifted_plan_request = request(
            SESSION_ID,
            &foreign_plan_hash,
            exact.target_snapshot(),
            exact.target_id(),
            exact.scan_fingerprint(),
            APPROVAL_ID,
            APPROVAL_SEQUENCE,
            protocol_evidence('d', 'e'),
        );
        let drifted_plan_admission = admission(&foreign_plan_hash, exact.target_snapshot(), true);
        let mut resolver = TestResolver::new(exact_material());
        assert_eq!(
            prepare_rescue_fstab_preflight(
                drifted_plan_admission,
                drifted_plan_request,
                &mut resolver,
            )
            .expect_err("plan hash drift"),
            RescueFstabPreflightError::PlanHashMismatch
        );

        let mut material = exact_material();
        material.evidence = transaction_evidence('6', 'e');
        let approved = admission(exact.plan_hash(), exact.target_snapshot(), true);
        let mut resolver = TestResolver::new(material);
        assert_eq!(
            prepare_rescue_fstab_preflight(approved, exact, &mut resolver)
                .expect_err("evidence drift"),
            RescueFstabPreflightError::EvidenceBindingMismatch
        );
    }

    #[test]
    fn fails_closed_on_identity_vault_and_lock_capability_drift() {
        let exact = exact_request();
        let mut identity_drift = exact_material();
        identity_drift.resolved_target_fingerprint = hash('6');
        let mut resolver = TestResolver::new(identity_drift);
        assert_eq!(
            prepare_rescue_fstab_preflight(
                admission(exact.plan_hash(), exact.target_snapshot(), true),
                exact.clone(),
                &mut resolver,
            )
            .expect_err("target identity drift"),
            RescueFstabPreflightError::TargetIdentityMismatch
        );

        let mut same_device = exact_material();
        same_device.vault = vault('a', 4096, 8192);
        let mut resolver = TestResolver::new(same_device);
        assert_eq!(
            prepare_rescue_fstab_preflight(
                admission(exact.plan_hash(), exact.target_snapshot(), true),
                exact.clone(),
                &mut resolver,
            )
            .expect_err("same-device Vault"),
            RescueFstabPreflightError::TransactionRejected(
                CandidateTransactionError::PhysicalDeviceNotDistinct
            )
        );

        let mut insufficient_reservation = exact_material();
        insufficient_reservation.vault = vault('b', 1, 8192);
        let mut resolver = TestResolver::new(insufficient_reservation);
        assert_eq!(
            prepare_rescue_fstab_preflight(
                admission(exact.plan_hash(), exact.target_snapshot(), true),
                exact.clone(),
                &mut resolver,
            )
            .expect_err("insufficient reservation"),
            RescueFstabPreflightError::TransactionRejected(
                CandidateTransactionError::InvalidVaultCapacity
            )
        );

        let mut resolver = TestResolver::new(exact_material());
        resolver.reservation_binding_sha256 = hash('8');
        let reservation_dropped = Arc::clone(&resolver.reservation_dropped);
        assert_eq!(
            prepare_rescue_fstab_preflight(
                admission(exact.plan_hash(), exact.target_snapshot(), true),
                exact.clone(),
                &mut resolver,
            )
            .expect_err("reservation binding drift"),
            RescueFstabPreflightError::ReservationBindingMismatch
        );
        assert!(reservation_dropped.load(Ordering::SeqCst));

        let mut resolver = TestResolver::new(exact_material());
        resolver.lock_identity = "../../target-lock".to_owned();
        assert_eq!(
            prepare_rescue_fstab_preflight(
                admission(exact.plan_hash(), exact.target_snapshot(), true),
                exact,
                &mut resolver,
            )
            .expect_err("path-like lock identity"),
            RescueFstabPreflightError::InvalidLockIdentity
        );
        assert!(resolver.lock_dropped.load(Ordering::SeqCst));
    }
}
