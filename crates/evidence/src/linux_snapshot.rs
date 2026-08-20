//! Versioned, provider-neutral Linux snapshot contract shared by Resident and Rescue.
//!
//! The normalized `snapshot` is intentionally mode-independent. `capture`
//! records how those facts were acquired without letting Rescue runtime facts
//! masquerade as facts about the selected installed system.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{error::Error, fmt};

pub const COLLECTOR: &str = "linux.normalized-snapshot.v1";
pub const CONTENT_TYPE: &str = "application/json";
pub const SCHEMA_VERSION: &str = "1.0";
pub const KIND: &str = "linux-normalized-snapshot";
pub const SNAPSHOT_SCOPE: &str = "installed-root-static";
pub const COLLECTION_SCOPE: &str = "root-filesystem-only";
pub const MAX_ENVELOPE_BYTES: usize = 48 * 1024;
pub const HASH_DOMAIN: &[u8] = b"KERNAID_LINUX_NORMALIZED_SNAPSHOT_V1\0";

const MAX_RELEASE_VALUE_BYTES: usize = 256;
const MAX_BOOT_ENTRIES: u32 = 512;
const MAX_FSTAB_ENTRIES: u32 = 65_536;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SnapshotError {
    InvalidSize,
    InvalidJson,
    InvalidContract,
    HashMismatch,
}

impl fmt::Display for SnapshotError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::InvalidSize => "Linux snapshot envelope exceeds its byte limit",
            Self::InvalidJson => "Linux snapshot envelope is not strict JSON",
            Self::InvalidContract => "Linux snapshot envelope violates its contract",
            Self::HashMismatch => "Linux snapshot canonical hash does not match",
        })
    }
}

impl Error for SnapshotError {}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct LinuxNormalizedSnapshotEnvelope {
    pub schema_version: String,
    pub kind: String,
    pub snapshot_sha256: String,
    pub capture: LinuxSnapshotCapture,
    pub snapshot: LinuxNormalizedSnapshot,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "mode", rename_all = "lowercase", deny_unknown_fields)]
pub enum LinuxSnapshotCapture {
    Resident {
        #[serde(rename = "targetScope")]
        target_scope: String,
        #[serde(rename = "accessPolicy")]
        access_policy: String,
        #[serde(rename = "callerSuppliedPath")]
        caller_supplied_path: bool,
        #[serde(rename = "mutationRequested")]
        mutation_requested: bool,
        #[serde(rename = "crossDeviceTraversalAllowed")]
        cross_device_traversal_allowed: bool,
    },
    Rescue {
        #[serde(rename = "targetScope")]
        target_scope: String,
        #[serde(rename = "accessPolicy")]
        access_policy: String,
        #[serde(rename = "deviceOpenedReadOnly")]
        device_opened_read_only: bool,
        #[serde(rename = "journalReplayPrevented")]
        journal_replay_prevented: bool,
        #[serde(rename = "privateMountNamespace")]
        private_mount_namespace: bool,
        #[serde(rename = "mountCleanupVerified")]
        mount_cleanup_verified: bool,
        #[serde(rename = "mutationPerformed")]
        mutation_performed: bool,
        #[serde(rename = "crossDeviceTraversalAllowed")]
        cross_device_traversal_allowed: bool,
    },
}

impl LinuxSnapshotCapture {
    pub fn resident() -> Self {
        Self::Resident {
            target_scope: "running-root".to_owned(),
            access_policy: "fixed-descriptor-read-only".to_owned(),
            caller_supplied_path: false,
            mutation_requested: false,
            cross_device_traversal_allowed: false,
        }
    }

    pub fn rescue() -> Self {
        Self::Rescue {
            target_scope: "selected-installed-target".to_owned(),
            access_policy: "temporary-read-only-no-replay".to_owned(),
            device_opened_read_only: true,
            journal_replay_prevented: true,
            private_mount_namespace: true,
            mount_cleanup_verified: true,
            mutation_performed: false,
            cross_device_traversal_allowed: false,
        }
    }

    pub const fn is_resident(&self) -> bool {
        matches!(self, Self::Resident { .. })
    }

    pub const fn is_rescue(&self) -> bool {
        matches!(self, Self::Rescue { .. })
    }

    fn valid(&self) -> bool {
        match self {
            Self::Resident {
                target_scope,
                access_policy,
                caller_supplied_path,
                mutation_requested,
                cross_device_traversal_allowed,
            } => {
                target_scope == "running-root"
                    && access_policy == "fixed-descriptor-read-only"
                    && !caller_supplied_path
                    && !mutation_requested
                    && !cross_device_traversal_allowed
            }
            Self::Rescue {
                target_scope,
                access_policy,
                device_opened_read_only,
                journal_replay_prevented,
                private_mount_namespace,
                mount_cleanup_verified,
                mutation_performed,
                cross_device_traversal_allowed,
            } => {
                target_scope == "selected-installed-target"
                    && access_policy == "temporary-read-only-no-replay"
                    && *device_opened_read_only
                    && *journal_replay_prevented
                    && *private_mount_namespace
                    && *mount_cleanup_verified
                    && !mutation_performed
                    && !cross_device_traversal_allowed
            }
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct LinuxNormalizedSnapshot {
    pub family: String,
    pub scope: String,
    pub installation_confirmed: bool,
    pub topology: LinuxFilesystemTopology,
    pub release: LinuxRelease,
    pub boot: LinuxBoot,
    pub configuration: LinuxConfiguration,
    pub package_databases: LinuxPackageDatabases,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct LinuxFilesystemTopology {
    pub collection_scope: String,
    pub separate_etc_mount_present: bool,
    pub separate_boot_mount_present: bool,
    pub separate_usr_mount_present: bool,
    pub separate_var_mount_present: bool,
    pub relevant_separate_mount_present: bool,
    pub supported: bool,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct LinuxRelease {
    pub id: Option<String>,
    pub name: Option<String>,
    pub pretty_name: Option<String>,
    pub version_id: Option<String>,
    pub source: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct LinuxBoot {
    pub directory_present: bool,
    pub kernel_artifact_count: u32,
    pub initramfs_artifact_count: u32,
    pub bootloader_directory_count: u32,
    pub symlink_artifact_count: u32,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct LinuxConfiguration {
    pub fstab: LinuxFstabSummary,
    pub machine_id_present: bool,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct LinuxFstabSummary {
    pub present: bool,
    pub entry_count: u32,
    pub root_entry_present: bool,
    pub efi_entry_present: bool,
    pub swap_entry_count: u32,
    pub network_entry_count: u32,
    pub malformed_line_count: u32,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct LinuxPackageDatabases {
    pub dpkg_status_present: bool,
    pub rpm_database_present: bool,
    pub pacman_database_present: bool,
}

impl LinuxNormalizedSnapshotEnvelope {
    pub fn new(
        capture: LinuxSnapshotCapture,
        snapshot: LinuxNormalizedSnapshot,
    ) -> Result<Self, SnapshotError> {
        snapshot.validate()?;
        if !capture.valid() {
            return Err(SnapshotError::InvalidContract);
        }
        let snapshot_sha256 = snapshot_hash(&snapshot)?;
        Ok(Self {
            schema_version: SCHEMA_VERSION.to_owned(),
            kind: KIND.to_owned(),
            snapshot_sha256,
            capture,
            snapshot,
        })
    }

    pub fn parse(input: &[u8]) -> Result<Self, SnapshotError> {
        if input.is_empty() || input.len() > MAX_ENVELOPE_BYTES {
            return Err(SnapshotError::InvalidSize);
        }
        let mut deserializer = serde_json::Deserializer::from_slice(input);
        let envelope =
            Self::deserialize(&mut deserializer).map_err(|_| SnapshotError::InvalidJson)?;
        deserializer.end().map_err(|_| SnapshotError::InvalidJson)?;
        envelope.validate()?;
        if envelope.canonical_json()?.as_slice() != input {
            return Err(SnapshotError::InvalidJson);
        }
        Ok(envelope)
    }

    pub fn validate(&self) -> Result<(), SnapshotError> {
        if self.schema_version != SCHEMA_VERSION
            || self.kind != KIND
            || !self.capture.valid()
            || !valid_hash(&self.snapshot_sha256)
        {
            return Err(SnapshotError::InvalidContract);
        }
        self.snapshot.validate()?;
        if snapshot_hash(&self.snapshot)? != self.snapshot_sha256 {
            return Err(SnapshotError::HashMismatch);
        }
        Ok(())
    }

    pub fn canonical_json(&self) -> Result<Vec<u8>, SnapshotError> {
        self.validate()?;
        serde_json::to_vec(self).map_err(|_| SnapshotError::InvalidJson)
    }
}

impl LinuxNormalizedSnapshot {
    pub fn validate(&self) -> Result<(), SnapshotError> {
        let release_values = [
            self.release.id.as_deref(),
            self.release.name.as_deref(),
            self.release.pretty_name.as_deref(),
            self.release.version_id.as_deref(),
        ];
        if self.family != "linux"
            || self.scope != SNAPSHOT_SCOPE
            || self.topology.collection_scope != COLLECTION_SCOPE
            || self.topology.relevant_separate_mount_present
                != (self.topology.separate_etc_mount_present
                    || self.topology.separate_boot_mount_present
                    || self.topology.separate_usr_mount_present
                    || self.topology.separate_var_mount_present)
            || self.topology.supported == self.topology.relevant_separate_mount_present
            || release_values.into_iter().flatten().any(|value| {
                value.is_empty()
                    || value.len() > MAX_RELEASE_VALUE_BYTES
                    || value.chars().any(char::is_control)
            })
            || !matches!(
                self.release.source.as_str(),
                "etc-os-release" | "usr-lib-os-release" | "absent"
            )
            || (self.release.source == "absent"
                && release_values.into_iter().any(|value| value.is_some()))
            || (self.installation_confirmed && self.release.id.is_none())
            || self.boot.kernel_artifact_count > MAX_BOOT_ENTRIES
            || self.boot.initramfs_artifact_count > MAX_BOOT_ENTRIES
            || self.boot.bootloader_directory_count > 3
            || self.boot.symlink_artifact_count > MAX_BOOT_ENTRIES
            || (!self.boot.directory_present
                && (self.boot.kernel_artifact_count != 0
                    || self.boot.initramfs_artifact_count != 0
                    || self.boot.bootloader_directory_count != 0
                    || self.boot.symlink_artifact_count != 0))
            || self.configuration.fstab.entry_count > MAX_FSTAB_ENTRIES
            || self.configuration.fstab.malformed_line_count > MAX_FSTAB_ENTRIES
            || self
                .configuration
                .fstab
                .entry_count
                .saturating_add(self.configuration.fstab.malformed_line_count)
                > MAX_FSTAB_ENTRIES
            || self.configuration.fstab.swap_entry_count > self.configuration.fstab.entry_count
            || self.configuration.fstab.network_entry_count > self.configuration.fstab.entry_count
            || (!self.configuration.fstab.present
                && (self.configuration.fstab.entry_count != 0
                    || self.configuration.fstab.root_entry_present
                    || self.configuration.fstab.efi_entry_present
                    || self.configuration.fstab.swap_entry_count != 0
                    || self.configuration.fstab.network_entry_count != 0
                    || self.configuration.fstab.malformed_line_count != 0))
        {
            return Err(SnapshotError::InvalidContract);
        }
        Ok(())
    }

    pub fn canonical_json(&self) -> Result<Vec<u8>, SnapshotError> {
        self.validate()?;
        serde_json::to_vec(self).map_err(|_| SnapshotError::InvalidJson)
    }
}

pub fn snapshot_hash(snapshot: &LinuxNormalizedSnapshot) -> Result<String, SnapshotError> {
    let canonical = snapshot.canonical_json()?;
    let mut digest = Sha256::new();
    digest.update(HASH_DOMAIN);
    digest.update(canonical);
    Ok(format!("{:x}", digest.finalize()))
}

fn valid_hash(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn snapshot() -> LinuxNormalizedSnapshot {
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
                id: Some("kernaid-fixture".to_owned()),
                name: Some("KernAid Fixture".to_owned()),
                pretty_name: Some("KernAid deterministic fixture".to_owned()),
                version_id: Some("1".to_owned()),
                source: "etc-os-release".to_owned(),
            },
            boot: LinuxBoot {
                directory_present: true,
                kernel_artifact_count: 1,
                initramfs_artifact_count: 1,
                bootloader_directory_count: 1,
                symlink_artifact_count: 0,
            },
            configuration: LinuxConfiguration {
                fstab: LinuxFstabSummary {
                    present: true,
                    entry_count: 2,
                    root_entry_present: true,
                    efi_entry_present: true,
                    swap_entry_count: 0,
                    network_entry_count: 0,
                    malformed_line_count: 0,
                },
                machine_id_present: true,
            },
            package_databases: LinuxPackageDatabases {
                dpkg_status_present: true,
                rpm_database_present: false,
                pacman_database_present: false,
            },
        }
    }

    #[test]
    fn resident_and_rescue_share_the_exact_normalized_hash() {
        let resident =
            LinuxNormalizedSnapshotEnvelope::new(LinuxSnapshotCapture::resident(), snapshot())
                .expect("resident envelope");
        let rescue =
            LinuxNormalizedSnapshotEnvelope::new(LinuxSnapshotCapture::rescue(), snapshot())
                .expect("rescue envelope");
        assert_eq!(resident.snapshot_sha256, rescue.snapshot_sha256);
        assert_ne!(resident.canonical_json(), rescue.canonical_json());
    }

    #[test]
    fn parser_rejects_hash_tampering_unknown_fields_and_trailing_values() {
        let envelope =
            LinuxNormalizedSnapshotEnvelope::new(LinuxSnapshotCapture::resident(), snapshot())
                .expect("envelope");
        let encoded = envelope.canonical_json().expect("canonical envelope");
        assert_eq!(
            LinuxNormalizedSnapshotEnvelope::parse(&encoded),
            Ok(envelope.clone())
        );

        let mut tampered = envelope.clone();
        tampered.snapshot.release.id = Some("other".to_owned());
        assert_eq!(tampered.validate(), Err(SnapshotError::HashMismatch));

        let unknown =
            String::from_utf8(encoded.clone())
                .expect("UTF-8")
                .replacen("{", "{\"extra\":true,", 1);
        assert_eq!(
            LinuxNormalizedSnapshotEnvelope::parse(unknown.as_bytes()),
            Err(SnapshotError::InvalidJson)
        );
        let mut trailing = encoded;
        trailing.extend_from_slice(b"{}");
        assert_eq!(
            LinuxNormalizedSnapshotEnvelope::parse(&trailing),
            Err(SnapshotError::InvalidJson)
        );

        let noncanonical = format!(
            " {}",
            String::from_utf8(envelope.canonical_json().expect("canonical envelope"))
                .expect("UTF-8")
        );
        assert_eq!(
            LinuxNormalizedSnapshotEnvelope::parse(noncanonical.as_bytes()),
            Err(SnapshotError::InvalidJson)
        );
    }

    #[test]
    fn semantic_invariants_fail_closed() {
        let mut invalid = snapshot();
        invalid.release.source = "absent".to_owned();
        assert_eq!(invalid.validate(), Err(SnapshotError::InvalidContract));

        let mut invalid = snapshot();
        invalid.boot.directory_present = false;
        assert_eq!(invalid.validate(), Err(SnapshotError::InvalidContract));

        let mut invalid = snapshot();
        invalid.configuration.fstab.present = false;
        assert_eq!(invalid.validate(), Err(SnapshotError::InvalidContract));
    }
}
