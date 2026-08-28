//! Immutable admission bindings for the disabled Rescue `fstab` candidate.
//!
//! This is deliberately not an executor or broker handler. It gives a future
//! Phase 1 admission boundary a deterministic plan binding after trusted code
//! has resolved a selected target and an authenticated boot-vault backup
//! capability. No path, command, file descriptor or replacement bytes cross
//! this contract.

use crate::{
    production_candidate_contract::{ACTION_ID, RESOURCE_ID},
    rescue_fstab_candidate::DisableMissingUuidPreview,
};
use sha2::{Digest, Sha256};

const PLAN_HASH_DOMAIN: &[u8] =
    b"kernaid:linux.fstab.disable-missing-uuid.v1:transaction-plan:v1\0";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CandidateTransactionError {
    InvalidCapability,
    InvalidFingerprint,
    VaultNotAuthenticated,
    PhysicalDeviceNotDistinct,
}

/// Broker-resolved identity of the already selected installed-Linux target.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SelectedTargetCapability {
    target_id: String,
    scan_fingerprint: String,
    physical_parent_fingerprint: String,
}

impl SelectedTargetCapability {
    pub fn new(
        target_id: impl Into<String>,
        scan_fingerprint: impl Into<String>,
        physical_parent_fingerprint: impl Into<String>,
    ) -> Result<Self, CandidateTransactionError> {
        let value = Self {
            target_id: target_id.into(),
            scan_fingerprint: scan_fingerprint.into(),
            physical_parent_fingerprint: physical_parent_fingerprint.into(),
        };
        if !valid_opaque_id(&value.target_id) {
            return Err(CandidateTransactionError::InvalidCapability);
        }
        if !valid_sha256(&value.scan_fingerprint)
            || !valid_sha256(&value.physical_parent_fingerprint)
        {
            return Err(CandidateTransactionError::InvalidFingerprint);
        }
        Ok(value)
    }
}

/// Broker-resolved capability for an authenticated backup in the boot Vault.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BootVaultBackupCapability {
    vault_id: String,
    vault_identity_fingerprint: String,
    physical_parent_fingerprint: String,
    authenticated_and_unlocked: bool,
}

impl BootVaultBackupCapability {
    pub fn new(
        vault_id: impl Into<String>,
        vault_identity_fingerprint: impl Into<String>,
        physical_parent_fingerprint: impl Into<String>,
        authenticated_and_unlocked: bool,
    ) -> Result<Self, CandidateTransactionError> {
        let value = Self {
            vault_id: vault_id.into(),
            vault_identity_fingerprint: vault_identity_fingerprint.into(),
            physical_parent_fingerprint: physical_parent_fingerprint.into(),
            authenticated_and_unlocked,
        };
        if !valid_opaque_id(&value.vault_id) {
            return Err(CandidateTransactionError::InvalidCapability);
        }
        if !valid_sha256(&value.vault_identity_fingerprint)
            || !valid_sha256(&value.physical_parent_fingerprint)
        {
            return Err(CandidateTransactionError::InvalidFingerprint);
        }
        if !value.authenticated_and_unlocked {
            return Err(CandidateTransactionError::VaultNotAuthenticated);
        }
        Ok(value)
    }
}

/// Complete immutable material which a future Core R2 plan must bind.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FstabCandidateTransactionPlan {
    plan_sha256: String,
    target: SelectedTargetCapability,
    vault: BootVaultBackupCapability,
    evidence_sha256: String,
    before_sha256: String,
    observed_uuid_set_sha256: String,
    after_sha256: String,
    diff_sha256: String,
}

impl FstabCandidateTransactionPlan {
    pub fn stage(
        preview: &DisableMissingUuidPreview,
        target: SelectedTargetCapability,
        vault: BootVaultBackupCapability,
        evidence_sha256: impl Into<String>,
    ) -> Result<Self, CandidateTransactionError> {
        let evidence_sha256 = evidence_sha256.into();
        if !valid_sha256(&evidence_sha256) {
            return Err(CandidateTransactionError::InvalidFingerprint);
        }
        if target.physical_parent_fingerprint == vault.physical_parent_fingerprint {
            return Err(CandidateTransactionError::PhysicalDeviceNotDistinct);
        }

        let mut plan = Self {
            plan_sha256: String::new(),
            target,
            vault,
            evidence_sha256,
            before_sha256: preview.before_sha256().to_owned(),
            observed_uuid_set_sha256: preview.observed_uuid_set_sha256().to_owned(),
            after_sha256: preview.after_sha256().to_owned(),
            diff_sha256: preview.diff_sha256().to_owned(),
        };
        plan.plan_sha256 = plan.compute_hash();
        Ok(plan)
    }

    fn compute_hash(&self) -> String {
        let mut digest = Sha256::new();
        digest.update(PLAN_HASH_DOMAIN);
        for value in [
            ACTION_ID,
            RESOURCE_ID,
            &self.target.target_id,
            &self.target.scan_fingerprint,
            &self.target.physical_parent_fingerprint,
            &self.vault.vault_id,
            &self.vault.vault_identity_fingerprint,
            &self.vault.physical_parent_fingerprint,
            &self.evidence_sha256,
            &self.before_sha256,
            &self.observed_uuid_set_sha256,
            &self.after_sha256,
            &self.diff_sha256,
        ] {
            digest.update((value.len() as u64).to_be_bytes());
            digest.update(value.as_bytes());
        }
        format!("sha256:{:x}", digest.finalize())
    }

    pub fn plan_sha256(&self) -> &str {
        &self.plan_sha256
    }

    pub fn target_id(&self) -> &str {
        &self.target.target_id
    }

    pub fn vault_id(&self) -> &str {
        &self.vault.vault_id
    }
}

fn valid_sha256(value: &str) -> bool {
    value.strip_prefix("sha256:").is_some_and(|digest| {
        digest.len() == 64
            && digest
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    })
}

fn valid_opaque_id(value: &str) -> bool {
    (1..=96).contains(&value.len())
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b':' | b'.'))
        && !value.contains("..")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rescue_fstab_candidate::preview_disable_missing_uuid;
    use std::collections::BTreeSet;

    fn hash(marker: char) -> String {
        format!("sha256:{}", marker.to_string().repeat(64))
    }

    fn preview() -> DisableMissingUuidPreview {
        preview_disable_missing_uuid(
            b"UUID=AAAA-BBBB / ext4 defaults 0 1\nUUID=DEAD-BEEF /srv/archive ext4 defaults 0 2\n",
            &BTreeSet::from(["aaaa-bbbb".to_owned()]),
        )
        .expect("safe preview")
    }

    fn target(parent: char) -> SelectedTargetCapability {
        SelectedTargetCapability::new("target-01", hash('1'), hash(parent)).expect("target")
    }

    fn vault(parent: char) -> BootVaultBackupCapability {
        BootVaultBackupCapability::new("boot-vault-01", hash('2'), hash(parent), true)
            .expect("vault")
    }

    #[test]
    fn plan_is_deterministic_and_binds_distinct_capabilities() {
        let first =
            FstabCandidateTransactionPlan::stage(&preview(), target('a'), vault('b'), hash('3'))
                .expect("stage plan");
        let second =
            FstabCandidateTransactionPlan::stage(&preview(), target('a'), vault('b'), hash('3'))
                .expect("repeat plan");
        assert_eq!(first, second);
        assert_eq!(first.target_id(), "target-01");
        assert_eq!(first.vault_id(), "boot-vault-01");
        assert!(valid_sha256(first.plan_sha256()));

        let changed =
            FstabCandidateTransactionPlan::stage(&preview(), target('c'), vault('b'), hash('3'))
                .expect("changed target parent");
        assert_ne!(first.plan_sha256(), changed.plan_sha256());
    }

    #[test]
    fn rejects_same_physical_device_locked_vault_and_path_like_ids() {
        assert_eq!(
            FstabCandidateTransactionPlan::stage(&preview(), target('a'), vault('a'), hash('3')),
            Err(CandidateTransactionError::PhysicalDeviceNotDistinct)
        );
        assert_eq!(
            BootVaultBackupCapability::new("vault", hash('2'), hash('b'), false),
            Err(CandidateTransactionError::VaultNotAuthenticated)
        );
        assert_eq!(
            SelectedTargetCapability::new("/dev/sda2", hash('1'), hash('a')),
            Err(CandidateTransactionError::InvalidCapability)
        );
    }
}
