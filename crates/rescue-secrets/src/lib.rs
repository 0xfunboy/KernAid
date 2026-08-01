#![forbid(unsafe_code)]
//! Fail-closed secure-state persistence for KernAid Rescue.
//!
//! The feature-gated privileged mount manager unlocks and mounts a labelled
//! LUKS2 vault, retains lifecycle descriptors and checkpoint claims, and
//! supplies an opaque [`VaultMountAttestation`] before production storage can
//! be opened. It never formats, erases, repairs, provisions, or falls back
//! outside the verified vault.

#[cfg(not(target_os = "linux"))]
use kernaid_device_identity::DeviceIdentity;
#[cfg(not(target_os = "linux"))]
use kernaid_storage::{JournalAnchor, JournalKey, JournalSecretStore, SecretStoreError};
#[cfg(not(target_os = "linux"))]
use std::path::Path;
use std::{error::Error, fmt};

/// Opaque proof minted only by KernAid's privileged mount manager.
///
/// There is deliberately no public constructor. A device-mapper UUID alone is
/// caller-controlled metadata, so the manager binds the proof to the mapping
/// it activated, the held backing-device descriptor, the LUKS2 header UUID,
/// mapper name, kernel device numbers, and observed mount ID. This is a
/// checkpoint capability in the manager's current mount namespace, not an
/// atomic proof against another privileged namespace actor.
#[derive(Debug)]
pub struct VaultMountAttestation {
    #[cfg(target_os = "linux")]
    pub(crate) claims: MountAttestationClaims,
    #[cfg(not(target_os = "linux"))]
    _private: (),
}

#[cfg(target_os = "linux")]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct MountAttestationClaims {
    pub(crate) root_device: u64,
    pub(crate) mount_id: u64,
    pub(crate) mapping_major: u32,
    pub(crate) mapping_minor: u32,
    pub(crate) backing_major: u32,
    pub(crate) backing_minor: u32,
    pub(crate) mapper_name: [u8; 30],
    pub(crate) luks_uuid: [u8; 36],
}

/// Exact contents of the root marker created by the separate provisioning
/// flow. Unlock never creates or repairs this marker.
pub const VAULT_MARKER_V1: &[u8] = b"KERNAID-RESCUE-VAULT-V1\n";
/// Marker filename at the root of the mounted LUKS2 filesystem.
pub const VAULT_MARKER_NAME: &str = ".kernaid-rescue-vault";

/// Expected Unix owner of the vault and every KernAid secure-state object.
/// The production mount manager currently accepts root-owned layouts only.
#[cfg(target_os = "linux")]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct VaultOwner {
    pub(crate) uid: u32,
    pub(crate) gid: u32,
}

#[cfg(target_os = "linux")]
impl VaultOwner {
    #[cfg(all(target_os = "linux", test))]
    #[must_use]
    pub(crate) fn effective() -> Self {
        Self {
            uid: rustix::process::geteuid().as_raw(),
            gid: rustix::process::getegid().as_raw(),
        }
    }
}

/// Sanitized failure categories. No variant carries a path, OS message, or
/// stored bytes, so this error is safe to cross the local daemon boundary.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RescueSecretError {
    UnsupportedPlatform,
    InvalidRoot,
    VaultNotMounted,
    UnsupportedFilesystem,
    NotLuks2,
    InvalidMountAttestation,
    InvalidMarker,
    WrongOwner,
    UnsafePermissions,
    UnsafePath,
    StaleVault,
    VaultLocked,
    InvalidStoredValue,
    IdentityAlreadyExists,
    ConcurrentWrite,
    WriteVerificationFailed,
    StorageUnavailable,
}

impl fmt::Display for RescueSecretError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::UnsupportedPlatform => "Rescue secure storage is unsupported on this platform",
            Self::InvalidRoot => "invalid Rescue vault root",
            Self::VaultNotMounted => "the Rescue vault is not a dedicated mounted filesystem",
            Self::UnsupportedFilesystem => "the Rescue vault filesystem is not allowed",
            Self::NotLuks2 => "the Rescue vault is not backed by a LUKS2 mapping",
            Self::InvalidMountAttestation => {
                "the Rescue vault does not match its mount-manager attestation"
            }
            Self::InvalidMarker => "the Rescue vault marker is missing or invalid",
            Self::WrongOwner => "the Rescue vault has an unexpected owner",
            Self::UnsafePermissions => "the Rescue vault has unsafe permissions",
            Self::UnsafePath => "the Rescue vault contains an unsafe path",
            Self::StaleVault => "the Rescue vault changed while it was open",
            Self::VaultLocked => "the Rescue vault is already in use",
            Self::InvalidStoredValue => "the Rescue vault contains invalid secure state",
            Self::IdentityAlreadyExists => "a Rescue device identity already exists",
            Self::ConcurrentWrite => "the Rescue secure state changed concurrently",
            Self::WriteVerificationFailed => "Rescue secure-state persistence verification failed",
            Self::StorageUnavailable => "Rescue secure storage is unavailable",
        })
    }
}

impl Error for RescueSecretError {}

#[cfg(target_os = "linux")]
mod linux;

#[cfg(all(target_os = "linux", feature = "experimental-vault-manager"))]
mod mount_manager;

#[cfg(target_os = "linux")]
pub use linux::{RescueDeviceIdentityStore, RescueJournalSecretStore, RescueVaultSecrets};
#[cfg(all(target_os = "linux", feature = "experimental-vault-manager"))]
pub use mount_manager::{
    MapperName, MountedRescueVault, RescueVaultMountManager, VaultMountManagerError,
    VaultUnlockRequest,
};

#[cfg(not(target_os = "linux"))]
mod unsupported {
    use super::*;

    /// Non-Linux placeholder; production Rescue storage is Linux-only.
    pub struct RescueVaultSecrets;
    pub struct RescueJournalSecretStore;
    pub struct RescueDeviceIdentityStore;

    impl RescueVaultSecrets {
        pub fn open(
            _root: impl AsRef<Path>,
            _attestation: &VaultMountAttestation,
        ) -> Result<Self, RescueSecretError> {
            Err(RescueSecretError::UnsupportedPlatform)
        }
    }

    impl JournalSecretStore for RescueJournalSecretStore {
        fn load_key(&mut self) -> Result<Option<JournalKey>, SecretStoreError> {
            Err(SecretStoreError::new(
                RescueSecretError::UnsupportedPlatform.to_string(),
            ))
        }

        fn store_key(&mut self, _key: &JournalKey) -> Result<(), SecretStoreError> {
            Err(SecretStoreError::new(
                RescueSecretError::UnsupportedPlatform.to_string(),
            ))
        }

        fn load_anchor(&mut self) -> Result<Option<JournalAnchor>, SecretStoreError> {
            Err(SecretStoreError::new(
                RescueSecretError::UnsupportedPlatform.to_string(),
            ))
        }

        fn store_anchor(&mut self, _anchor: &JournalAnchor) -> Result<(), SecretStoreError> {
            Err(SecretStoreError::new(
                RescueSecretError::UnsupportedPlatform.to_string(),
            ))
        }
    }

    impl RescueDeviceIdentityStore {
        pub fn load_device_identity(
            &mut self,
        ) -> Result<Option<DeviceIdentity>, RescueSecretError> {
            Err(RescueSecretError::UnsupportedPlatform)
        }

        pub fn store_new_device_identity(
            &mut self,
            _identity: &DeviceIdentity,
        ) -> Result<(), RescueSecretError> {
            Err(RescueSecretError::UnsupportedPlatform)
        }

        pub fn create_device_identity(&mut self) -> Result<DeviceIdentity, RescueSecretError> {
            Err(RescueSecretError::UnsupportedPlatform)
        }
    }
}

#[cfg(not(target_os = "linux"))]
pub use unsupported::{RescueDeviceIdentityStore, RescueJournalSecretStore, RescueVaultSecrets};
