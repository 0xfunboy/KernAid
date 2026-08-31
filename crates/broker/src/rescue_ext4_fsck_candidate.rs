//! Typed preparation for the off-default ext4 repair candidate.
//!
//! The only admitted operation is a fixed offline e2fsck preen with a
//! same-boot undo stream. Preflight is descriptor-bound and read-only. The
//! Repair Vault reservation stores a normalized evidence record before any
//! root helper can issue a writable block capability.

use crate::{
    rescue_fstab_candidate::RescueFstabVaultReservation,
    rescue_fstab_preflight_resolver::{
        ProductionRescueFstabTargetGuard, ProductionRescueFstabVaultReservation,
        acquire_target_guard_for_resource, reserve_evidence_backup,
    },
};
use kernaid_linux_pack::filesystem_health::{Ext4OfflineCheck, check_ext4_descriptor};
use kernaid_protocol::{
    rescue_repair_vault::{RepairFileMetadataV1, RepairResourceV1},
    rescue_vault::Sha256,
};
use serde::Serialize;
use sha2::{Digest, Sha256 as Sha256Hasher};
use std::time::Instant;
use zeroize::Zeroizing;

pub const ACTION_ID: &str = "linux.ext4.fsck-preen-with-undo.v1";
pub const RESOURCE_ID: &str = "rescue:selected-linux-filesystem:ext4";
pub const TYPED_CONFIRMATION: &str = "REPAIR EXT4 OFFLINE";
pub const PREPARED_KIND: &str = "ext4-fsck-prepared";
const PLAN_DOMAIN: &[u8] = b"kernaid:linux.ext4.fsck-preen-with-undo.v1:plan:v1\0";
const AFTER_DOMAIN: &[u8] = b"kernaid:linux.ext4.fsck-preen-with-undo.v1:clean:v1\0";
const DIFF_DOMAIN: &[u8] = b"kernaid:linux.ext4.fsck-preen-with-undo.v1:transition:v1\0";
const APPROVAL_DOMAIN: &[u8] = b"kernaid:linux.ext4.fsck-preen-with-undo.v1:approval:v1\0";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Ext4PrepareError {
    InvalidRequest,
    TargetUnavailable,
    TargetChanged,
    PreflightUnavailable,
    RepairNotRequired,
    VaultUnavailable,
    ApprovalRejected,
    CancellationFailed,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct Evidence<'a> {
    schema_version: &'static str,
    kind: &'static str,
    action_id: &'static str,
    target_fingerprint: &'a str,
    target_recovery_fingerprint: &'a str,
    check_mode: &'static str,
    state: &'static str,
    mounted_at_check: bool,
}

/// Path-free audit descriptor retained by repaird and echoed to the UI.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Ext4PreparedDescriptor {
    pub request_id: String,
    pub session_id: String,
    pub plan_id: String,
    pub plan_sha256: String,
    pub scan_fingerprint: String,
    pub target_id: String,
    pub target_fingerprint: String,
    pub before_sha256: String,
    pub after_sha256: String,
    pub diff_sha256: String,
}

#[must_use]
pub struct PreparedExt4Repair {
    descriptor: Ext4PreparedDescriptor,
    evidence: Zeroizing<Vec<u8>>,
    metadata: RepairFileMetadataV1,
    target: ProductionRescueFstabTargetGuard,
    reservation: ProductionRescueFstabVaultReservation,
}

#[must_use]
pub struct ApprovedExt4Repair {
    descriptor: Ext4PreparedDescriptor,
    evidence: Zeroizing<Vec<u8>>,
    metadata: RepairFileMetadataV1,
    target: ProductionRescueFstabTargetGuard,
    reservation: ProductionRescueFstabVaultReservation,
    approval_id: String,
    approval_sha256: String,
}

pub(crate) struct ApprovedExt4RepairParts {
    pub descriptor: Ext4PreparedDescriptor,
    pub evidence: Zeroizing<Vec<u8>>,
    pub metadata: RepairFileMetadataV1,
    pub target: ProductionRescueFstabTargetGuard,
    pub reservation: ProductionRescueFstabVaultReservation,
    pub approval_id: String,
    pub approval_sha256: String,
}

impl PreparedExt4Repair {
    pub fn descriptor(&self) -> &Ext4PreparedDescriptor {
        &self.descriptor
    }

    pub fn backup_locator(&self) -> &str {
        self.reservation.status().locator()
    }

    #[allow(clippy::too_many_arguments)]
    pub fn approve(
        self,
        session_id: &str,
        plan_id: &str,
        plan_sha256: &str,
        approval_id: &str,
        approval_sequence: u64,
        typed_confirmation: &str,
        deadline: Instant,
    ) -> Result<ApprovedExt4Repair, Ext4PrepareError> {
        let valid = session_id == self.descriptor.session_id
            && plan_id == self.descriptor.plan_id
            && plan_sha256 == self.descriptor.plan_sha256
            && approval_sequence == 1
            && typed_confirmation == TYPED_CONFIRMATION
            && valid_id(approval_id, "A-");
        if !valid {
            self.reservation
                .cancel(deadline)
                .map_err(|_| Ext4PrepareError::CancellationFailed)?;
            return Err(Ext4PrepareError::ApprovalRejected);
        }
        let approval_sha256 = approval_hash(
            approval_id,
            approval_sequence,
            typed_confirmation,
            &self.descriptor.plan_sha256,
        );
        Ok(ApprovedExt4Repair {
            descriptor: self.descriptor,
            evidence: self.evidence,
            metadata: self.metadata,
            target: self.target,
            reservation: self.reservation,
            approval_id: approval_id.to_owned(),
            approval_sha256,
        })
    }

    pub fn cancel(self, deadline: Instant) -> Result<(), Ext4PrepareError> {
        self.reservation
            .cancel(deadline)
            .map_err(|_| Ext4PrepareError::CancellationFailed)
    }
}

impl ApprovedExt4Repair {
    pub fn cancel(self, deadline: Instant) -> Result<(), Ext4PrepareError> {
        self.reservation
            .cancel(deadline)
            .map_err(|_| Ext4PrepareError::CancellationFailed)
    }

    pub(crate) fn into_parts(self) -> ApprovedExt4RepairParts {
        ApprovedExt4RepairParts {
            descriptor: self.descriptor,
            evidence: self.evidence,
            metadata: self.metadata,
            target: self.target,
            reservation: self.reservation,
            approval_id: self.approval_id,
            approval_sha256: self.approval_sha256,
        }
    }
}

#[allow(clippy::too_many_arguments)]
pub fn prepare_ext4_repair(
    request_id: &str,
    session_id: &str,
    plan_id: &str,
    scan_fingerprint: &str,
    target_id: &str,
    target_fingerprint: &str,
    deadline: Instant,
) -> Result<PreparedExt4Repair, Ext4PrepareError> {
    if !valid_id(session_id, "S-") || !valid_id(plan_id, "P-") {
        return Err(Ext4PrepareError::InvalidRequest);
    }
    let target = acquire_target_guard_for_resource(
        request_id,
        scan_fingerprint,
        target_fingerprint,
        target_id,
        RepairResourceV1::Ext4Filesystem,
        deadline,
    )
    .map_err(|_| Ext4PrepareError::TargetUnavailable)?;
    target
        .inner()
        .revalidate()
        .map_err(|_| Ext4PrepareError::TargetChanged)?;
    match check_ext4_descriptor(target.inner().target_block_descriptor()) {
        Ext4OfflineCheck::RepairRequired => {}
        Ext4OfflineCheck::Clean => return Err(Ext4PrepareError::RepairNotRequired),
        Ext4OfflineCheck::Unavailable => return Err(Ext4PrepareError::PreflightUnavailable),
    }
    target
        .inner()
        .revalidate()
        .map_err(|_| Ext4PrepareError::TargetChanged)?;
    let recovery = target.inner().target_claims().recovery_fingerprint();
    let evidence = serde_json::to_vec(&Evidence {
        schema_version: "1.0",
        kind: "ext4-repair-preflight",
        action_id: ACTION_ID,
        target_fingerprint,
        target_recovery_fingerprint: recovery,
        check_mode: "e2fsck-read-only",
        state: "repair-required",
        mounted_at_check: false,
    })
    .map_err(|_| Ext4PrepareError::InvalidRequest)?;
    let before_sha256 = prefixed_hash(&evidence);
    let after_sha256 = domain_hash(AFTER_DOMAIN, &[before_sha256.as_bytes()]);
    let diff_sha256 = domain_hash(
        DIFF_DOMAIN,
        &[before_sha256.as_bytes(), after_sha256.as_bytes()],
    );
    let plan_sha256 = domain_hash(
        PLAN_DOMAIN,
        &[
            session_id.as_bytes(),
            plan_id.as_bytes(),
            scan_fingerprint.as_bytes(),
            target_id.as_bytes(),
            target_fingerprint.as_bytes(),
            recovery.as_bytes(),
            before_sha256.as_bytes(),
            after_sha256.as_bytes(),
            diff_sha256.as_bytes(),
        ],
    );
    let metadata =
        RepairFileMetadataV1::new(0o600, 0, 0).map_err(|_| Ext4PrepareError::InvalidRequest)?;
    let reservation = reserve_evidence_backup(
        session_id,
        target_id,
        scan_fingerprint,
        target_fingerprint,
        &target,
        &evidence,
        &metadata,
        deadline,
    )
    .map_err(|_| Ext4PrepareError::VaultUnavailable)?;
    Ok(PreparedExt4Repair {
        descriptor: Ext4PreparedDescriptor {
            request_id: request_id.to_owned(),
            session_id: session_id.to_owned(),
            plan_id: plan_id.to_owned(),
            plan_sha256,
            scan_fingerprint: scan_fingerprint.to_owned(),
            target_id: target_id.to_owned(),
            target_fingerprint: target_fingerprint.to_owned(),
            before_sha256,
            after_sha256,
            diff_sha256,
        },
        evidence: Zeroizing::new(evidence),
        metadata,
        target,
        reservation,
    })
}

fn approval_hash(id: &str, sequence: u64, confirmation: &str, plan: &str) -> String {
    domain_hash(
        APPROVAL_DOMAIN,
        &[
            id.as_bytes(),
            &sequence.to_be_bytes(),
            confirmation.as_bytes(),
            plan.as_bytes(),
        ],
    )
}

fn domain_hash(domain: &[u8], fields: &[&[u8]]) -> String {
    let mut hasher = Sha256Hasher::new();
    hasher.update(domain);
    for field in fields {
        hasher.update((field.len() as u64).to_be_bytes());
        hasher.update(field);
    }
    format!("sha256:{:x}", hasher.finalize())
}

fn prefixed_hash(bytes: &[u8]) -> String {
    format!("sha256:{:x}", Sha256Hasher::digest(bytes))
}

fn valid_id(value: &str, prefix: &str) -> bool {
    (3..=128).contains(&value.len())
        && value.strip_prefix(prefix).is_some_and(|tail| {
            !tail.is_empty()
                && tail
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
        })
}

fn _assert_protocol_hash(value: &str) -> Option<Sha256> {
    value
        .strip_prefix("sha256:")
        .and_then(|raw| Sha256::parse(raw).ok())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn plan_and_approval_hashes_are_domain_separated() {
        let before = prefixed_hash(b"evidence");
        let after = domain_hash(AFTER_DOMAIN, &[before.as_bytes()]);
        let diff = domain_hash(DIFF_DOMAIN, &[before.as_bytes(), after.as_bytes()]);
        assert_ne!(before, after);
        assert_ne!(after, diff);
        assert_ne!(
            approval_hash("A-one", 1, TYPED_CONFIRMATION, &after),
            approval_hash("A-two", 1, TYPED_CONFIRMATION, &after)
        );
        assert!(_assert_protocol_hash(&diff).is_some());
    }
}
