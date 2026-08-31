//! Experimental privileged lifecycle for the Rescue LUKS2 secure-state vault.
//!
//! This module is disabled by default. It provides checkpoint-bound validation
//! in the current mount namespace; it is not a production claim of atomic
//! ownership against another privileged actor.

#[cfg(feature = "experimental-repair-store")]
use super::RepairPhysicalParentClaims;
use super::{RescueSecretError, RescueVaultSecrets, VaultMountAttestation};
#[cfg(feature = "experimental-firstboot-provisioner")]
use super::{VAULT_MARKER_NAME, VAULT_MARKER_V1};
use crate::{
    bounded_process,
    device_locator::{
        DescriptorBlockGeometry, DescriptorBlockIdentity, DescriptorBlockIdentityError,
        LocatedVaultIdentity, LocatedVaultPartition, descriptor_block_geometry,
        descriptor_block_identity,
    },
    linux,
    profile_classifier::{
        Ext4ProfileEvidence, LOGICAL_SECTOR_BYTES, MINIMUM_ADVERTISED_MEDIA_BYTES,
        OuterProfileEvidence, ProfileClassifierError, VAULT_PARTITION_BYTES, VAULT_PAYLOAD_BYTES,
        VAULT_SECTOR_COUNT, VAULT_START_LBA, VaultPartitionProfile, classify_partition,
        qualify_ext4_mapper, revalidate_mounted_ext4_mapper,
    },
};
#[cfg(feature = "experimental-firstboot-provisioner")]
use rand_core::{OsRng, RngCore};
#[cfg(feature = "experimental-firstboot-provisioner")]
use rustix::fs::RawDir;
use rustix::{
    fd::{AsFd, OwnedFd},
    fs::{
        self as rfs, AtFlags, CWD, FileType, FlockOperation, Mode, OFlags, ResolveFlags, Stat,
        StatxFlags,
    },
    mount::{MountFlags, UnmountFlags},
};
#[cfg(feature = "experimental-firstboot-provisioner")]
use std::mem::MaybeUninit;
use std::{
    error::Error,
    ffi::OsStr,
    fs::{self, File},
    os::fd::AsRawFd,
    os::unix::ffi::OsStrExt,
    path::{Component, Path, PathBuf},
    process::{Command, Stdio},
    thread,
    time::{Duration, Instant},
};

const MANAGER_LOCK_PATH: &str = "/run/lock/kernaid-rescue-vault-manager.lock";
const RUNTIME_ROOT: &str = "/run/kernaid";
const RUNTIME_ROOT_NAME: &str = "kernaid";
const VAULT_MOUNT_PARENT: &str = "vault";
const CRYPTSETUP_PATH: &str = "/usr/sbin/cryptsetup";
const BLKID_PATH: &str = "/usr/sbin/blkid";
const VAULT_LABEL: &[u8] = b"KERNAID_VAULT";
const MAPPER_PREFIX: &str = "kernaid-vault-";
const MAPPER_SUFFIX_BYTES: usize = 16;
const MAPPER_NAME_BYTES: usize = MAPPER_PREFIX.len() + MAPPER_SUFFIX_BYTES;
const COMMAND_OUTPUT_LIMIT: usize = 4096;
const COMMAND_TIMEOUT: Duration = Duration::from_secs(30);
#[cfg(feature = "experimental-firstboot-provisioner")]
const PROVISIONING_COMMAND_TIMEOUT: Duration = Duration::from_secs(10 * 60);
const DEFERRED_REMOVE_TIMEOUT: Duration = Duration::from_secs(5);
const DEFERRED_REMOVE_POLL_INTERVAL: Duration = Duration::from_millis(20);
const SECURE_DIRECTORY_MODE: u32 = 0o700;
const SECURE_FILE_MODE: u32 = 0o600;
const TMPFS_MAGIC: u64 = 0x0102_1994;
#[cfg(feature = "experimental-firstboot-provisioner")]
const MKFS_EXT4_PATH: &str = "/usr/sbin/mkfs.ext4";
#[cfg(feature = "experimental-firstboot-provisioner")]
const TUNE2FS_PATH: &str = "/usr/sbin/tune2fs";
#[cfg(feature = "experimental-firstboot-provisioner")]
const STATE_DIRECTORY_NAME: &str = ".kernaid-secure-state-v1";
#[cfg(feature = "experimental-firstboot-provisioner")]
const VAULT_LOCK_NAME: &str = ".kernaid-rescue-secrets.lock";
#[cfg(feature = "experimental-firstboot-provisioner")]
const FIRSTBOOT_SCAN_BUFFER_BYTES: usize = 8192;

/// A mapper name in KernAid's single accepted grammar:
/// `kernaid-vault-` followed by exactly sixteen lowercase hexadecimal bytes.
#[derive(Clone, PartialEq, Eq)]
pub struct MapperName {
    bytes: [u8; MAPPER_NAME_BYTES],
}

impl MapperName {
    pub fn parse(value: &str) -> Result<Self, VaultMountManagerError> {
        let bytes = value.as_bytes();
        if bytes.len() != MAPPER_NAME_BYTES
            || !bytes.starts_with(MAPPER_PREFIX.as_bytes())
            || !bytes[MAPPER_PREFIX.len()..]
                .iter()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(byte))
        {
            return Err(VaultMountManagerError::InvalidMapperName);
        }
        let mut fixed = [0_u8; MAPPER_NAME_BYTES];
        fixed.copy_from_slice(bytes);
        Ok(Self { bytes: fixed })
    }

    fn as_os_str(&self) -> &OsStr {
        OsStr::from_bytes(&self.bytes)
    }

    fn as_fixed_bytes(&self) -> [u8; MAPPER_NAME_BYTES] {
        self.bytes
    }
}

impl std::fmt::Debug for MapperName {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("MapperName([validated])")
    }
}

/// Explicit request to unlock the already-provisioned vault located on the
/// exact Rescue boot medium.
///
/// The production-shaped constructor consumes a sealed
/// [`LocatedVaultPartition`], so an IPC client cannot select a path or device.
/// The mount root is likewise derived beneath `/run/kernaid/vault/` from the
/// validated mapper name.
pub struct VaultUnlockRequest {
    device: UnlockDevice,
    mapper: MapperName,
}

enum UnlockDevice {
    Located(LocatedVaultPartition),
    #[cfg(feature = "privileged-probe")]
    DisposableProbe(PathBuf),
}

impl VaultUnlockRequest {
    /// Bind unlock to the path-free capability returned by
    /// [`crate::locate_boot_vault`].
    #[must_use]
    pub fn from_located(device: LocatedVaultPartition, mapper: MapperName) -> Self {
        Self {
            device: UnlockDevice::Located(device),
            mapper,
        }
    }

    /// Construct the path-based request used only by the disposable privileged
    /// integration probe. Shipping manager builds do not expose this entrypoint.
    #[cfg(feature = "privileged-probe")]
    pub fn new(
        device: impl AsRef<Path>,
        mapper: MapperName,
    ) -> Result<Self, VaultMountManagerError> {
        let device = validate_device_path(device.as_ref())?;
        Ok(Self {
            device: UnlockDevice::DisposableProbe(device),
            mapper,
        })
    }
}

/// Sanitized mount-manager failures. Variants never contain paths, command
/// output, OS messages, passphrase bytes, or other attacker-controlled text.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum VaultMountManagerError {
    UnsupportedPlatform,
    PrivilegeRequired,
    ManagerLocked,
    InvalidBlockDevice,
    InvalidMapperName,
    Unprovisioned,
    ProfileMismatch,
    ClassifierUnavailable,
    InvalidLuks2Header,
    WrongVaultLabel,
    MapperConflict,
    PassphraseUnavailable,
    ProvisioningFormatFailed,
    ProvisioningInitializationFailed,
    UnlockFailed,
    MappingVerificationFailed,
    UnsupportedFilesystem,
    UnsafeMountRoot,
    MountFailed,
    MountVerificationFailed,
    SecureStateUnavailable,
    CleanupFailed,
    ToolUnavailable,
    OperationTimedOut,
}

impl std::fmt::Display for VaultMountManagerError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(match self {
            Self::UnsupportedPlatform => "the Rescue vault manager is unsupported on this platform",
            Self::PrivilegeRequired => {
                "the Rescue vault manager requires its privileged service account"
            }
            Self::ManagerLocked => "another Rescue vault manager owns the secure-state lifecycle",
            Self::InvalidBlockDevice => "the selected Rescue vault device is invalid",
            Self::InvalidMapperName => "the Rescue vault mapper name is invalid",
            Self::Unprovisioned => "the Rescue vault is not provisioned",
            Self::ProfileMismatch => "the Rescue vault profile does not match",
            Self::ClassifierUnavailable => "the pinned Rescue vault classifier is unavailable",
            Self::InvalidLuks2Header => "the selected device is not the expected LUKS2 vault",
            Self::WrongVaultLabel => "the selected device is not labelled as a KernAid vault",
            Self::MapperConflict => "the selected Rescue mapper is already in use",
            Self::PassphraseUnavailable => "the Rescue vault passphrase descriptor is unavailable",
            Self::ProvisioningFormatFailed => "the Rescue vault canonical format operation failed",
            Self::ProvisioningInitializationFailed => {
                "the Rescue vault first-boot initialization failed"
            }
            Self::UnlockFailed => "the Rescue vault could not be unlocked",
            Self::MappingVerificationFailed => "the Rescue vault mapping could not be verified",
            Self::UnsupportedFilesystem => "the Rescue vault filesystem is not supported",
            Self::UnsafeMountRoot => "the Rescue vault mount root is unsafe",
            Self::MountFailed => "the Rescue vault could not be mounted",
            Self::MountVerificationFailed => "the Rescue vault mount could not be verified",
            Self::SecureStateUnavailable => "the Rescue secure-state boundary could not be opened",
            Self::CleanupFailed => "the Rescue vault could not be safely closed",
            Self::ToolUnavailable => "a required Rescue vault tool is unavailable",
            Self::OperationTimedOut => "a bounded Rescue vault operation timed out",
        })
    }
}

impl VaultMountManagerError {
    /// Stable machine-readable category which is safe to emit in local probe
    /// diagnostics. Values are closed literals and never contain a path,
    /// command output, OS error, mapper name, or passphrase material.
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::UnsupportedPlatform => "unsupported-platform",
            Self::PrivilegeRequired => "privilege-required",
            Self::ManagerLocked => "manager-locked",
            Self::InvalidBlockDevice => "invalid-block-device",
            Self::InvalidMapperName => "invalid-mapper-name",
            Self::Unprovisioned => "unprovisioned",
            Self::ProfileMismatch => "profile-mismatch",
            Self::ClassifierUnavailable => "classifier-unavailable",
            Self::InvalidLuks2Header => "invalid-luks2-header",
            Self::WrongVaultLabel => "wrong-vault-label",
            Self::MapperConflict => "mapper-conflict",
            Self::PassphraseUnavailable => "passphrase-unavailable",
            Self::ProvisioningFormatFailed => "provisioning-format-failed",
            Self::ProvisioningInitializationFailed => "provisioning-initialization-failed",
            Self::UnlockFailed => "unlock-failed",
            Self::MappingVerificationFailed => "mapping-verification-failed",
            Self::UnsupportedFilesystem => "unsupported-filesystem",
            Self::UnsafeMountRoot => "unsafe-mount-root",
            Self::MountFailed => "mount-failed",
            Self::MountVerificationFailed => "mount-verification-failed",
            Self::SecureStateUnavailable => "secure-state-unavailable",
            Self::CleanupFailed => "cleanup-failed",
            Self::ToolUnavailable => "tool-unavailable",
            Self::OperationTimedOut => "operation-timed-out",
        }
    }
}

impl Error for VaultMountManagerError {}

/// Holds KernAid's process-wide manager lock until the mounted vault is closed.
pub struct RescueVaultMountManager {
    lock: OwnedFd,
}

impl RescueVaultMountManager {
    /// Acquire the one privileged vault lifecycle allowed in this mount
    /// namespace. Production use requires effective uid 0.
    pub fn acquire() -> Result<Self, VaultMountManagerError> {
        if !rustix::process::geteuid().is_root() {
            return Err(VaultMountManagerError::PrivilegeRequired);
        }
        Ok(Self {
            lock: acquire_manager_lock()?,
        })
    }

    /// Unlock using a passphrase supplied only through `passphrase_fd`.
    ///
    /// This method first enforces close-on-exec on the supplied descriptor
    /// (intentionally changing that descriptor flag for the caller). Only
    /// immediately before `cryptsetup open`, it creates one CLOEXEC duplicate
    /// and transfers that duplicate to cryptsetup's stdin. Its
    /// contents are never copied into argv, environment variables, logs, error
    /// values, or Rust strings. The caller must provide one passphrase followed
    /// by EOF; cryptsetup is configured for one non-interactive attempt.
    pub fn unlock_from_fd<Fd: AsFd>(
        self,
        request: VaultUnlockRequest,
        passphrase_fd: Fd,
    ) -> Result<MountedRescueVault, VaultMountManagerError> {
        ensure_cloexec(&passphrase_fd)?;
        let resolved = ResolvedRequest::resolve(request)?;
        let mut activation = Activation::start(SystemOps, self.lock, resolved, passphrase_fd)?;

        let secrets_result = match activation.attestation.as_ref() {
            Some(attestation) => {
                RescueVaultSecrets::open(&activation.request.mount_root, attestation)
                    .map_err(map_secure_state_error)
            }
            None => Err(VaultMountManagerError::MountVerificationFailed),
        };
        match secrets_result {
            Ok(secrets) => Ok(MountedRescueVault {
                secrets,
                activation,
            }),
            Err(primary) => {
                if activation.cleanup().is_err() {
                    Err(VaultMountManagerError::CleanupFailed)
                } else {
                    Err(primary)
                }
            }
        }
    }

    /// Provision the already-located all-zero p3 capability as canonical
    /// profile v1. This entrypoint is crate-private and feature-gated: callers
    /// cannot select a pathname, mapper, UUID or command argument.
    #[cfg(feature = "experimental-firstboot-provisioner")]
    pub(crate) fn provision_firstboot(
        self,
        located: LocatedVaultPartition,
        passphrase: &[u8],
    ) -> Result<FirstBootProvisioningEvidence, VaultMountManagerError> {
        if !(kernaid_protocol::rescue_vault::MIN_PASSPHRASE_BYTES as usize
            ..=kernaid_protocol::rescue_vault::MAX_PASSPHRASE_BYTES as usize)
            .contains(&passphrase.len())
            || passphrase.contains(&0)
        {
            return Err(VaultMountManagerError::PassphraseUnavailable);
        }
        let mapper = random_firstboot_mapper()?;
        let request = ResolvedRequest::resolve(VaultUnlockRequest::from_located(located, mapper))?;
        let mut ops = SystemOps;
        ops.ensure_device_unused(&request.device)?;
        ops.ensure_mapper_absent(&request.mapper, &request.mapper_path)?;
        // This is the sole complete 8 GiB zero scan. The returned private
        // proof is consumed by the first mutator so no formatting path can
        // bypass the post-confirmation classifier.
        let unprovisioned = require_unprovisioned(&request.device)?;

        let luks_uuid = random_uuid_v4()?;
        let filesystem_uuid = random_uuid_v4()?;
        let format_result =
            format_luks_profile_v1(&request.device, unprovisioned, passphrase, luks_uuid);
        if let Err(primary) = format_result {
            if SystemOps::verify_mapping_absence(
                &request.device,
                &request.mapper,
                &request.mapper_path,
            )
            .is_err()
            {
                return Err(VaultMountManagerError::CleanupFailed);
            }
            return Err(primary);
        }
        request.device.revalidate()?;
        let outer = ops.classify_outer_profile(&request.device)?;
        if outer.uuid() != luks_uuid {
            return Err(VaultMountManagerError::ProfileMismatch);
        }

        let passphrase_read = secret_pipe(passphrase)?;
        let mut activation = Activation::start_for_provisioning(
            SystemOps,
            self.lock,
            request,
            passphrase_read,
            passphrase.len(),
            filesystem_uuid,
        )?;
        let operation = initialize_firstboot_secure_state(&mut activation, filesystem_uuid);
        let evidence = match operation {
            Ok(evidence) => evidence,
            Err(primary) => {
                return if activation.cleanup().is_err() {
                    Err(VaultMountManagerError::CleanupFailed)
                } else {
                    Err(primary)
                };
            }
        };
        activation.cleanup()?;
        let final_profile = activation
            .ops
            .classify_outer_profile(&activation.request.device)?;
        if final_profile.uuid() != luks_uuid {
            return Err(VaultMountManagerError::ProfileMismatch);
        }
        Ok(FirstBootProvisioningEvidence {
            luks_uuid,
            filesystem_uuid,
            device_id: evidence.device_id,
            identity_public_key: evidence.identity_public_key,
        })
    }
}

/// Non-secret evidence emitted only after layout initialization, verified
/// cleanup and final locked reclassification all succeed.
#[cfg(feature = "experimental-firstboot-provisioner")]
pub(crate) struct FirstBootProvisioningEvidence {
    pub(crate) luks_uuid: [u8; 36],
    pub(crate) filesystem_uuid: [u8; 36],
    pub(crate) device_id: String,
    pub(crate) identity_public_key: [u8; 32],
}

#[cfg(feature = "experimental-firstboot-provisioner")]
struct InitializedSecureStateEvidence {
    device_id: String,
    identity_public_key: [u8; 32],
}

/// Owns the unlocked mapping, the restrictive ext4 mount, and the
/// `RescueVaultSecrets` handle as one lifetime boundary.
pub struct MountedRescueVault {
    // Rust drops struct fields in declaration order: the vault-wide storage
    // lock and descriptors are therefore gone before Activation unmounts.
    secrets: RescueVaultSecrets,
    activation: Activation<SystemOps>,
}

impl MountedRescueVault {
    #[must_use]
    pub fn secrets(&self) -> &RescueVaultSecrets {
        &self.secrets
    }

    /// Close secure state first, then re-check the current mount and mapping
    /// against the activation checkpoints. Any ambiguity fails without a
    /// forced/lazy unmount or an unverified mapping close.
    pub fn shutdown(self) -> Result<(), VaultMountManagerError> {
        let Self {
            secrets,
            mut activation,
        } = self;
        drop(secrets);
        activation.cleanup()
    }
}

struct ResolvedRequest {
    device: BlockDevice,
    mapper: MapperName,
    mapper_path: PathBuf,
    mount_root: PathBuf,
}

impl ResolvedRequest {
    fn resolve(request: VaultUnlockRequest) -> Result<Self, VaultMountManagerError> {
        let VaultUnlockRequest { device, mapper } = request;
        let device = match device {
            UnlockDevice::Located(device) => BlockDevice::from_located(device)?,
            #[cfg(feature = "privileged-probe")]
            UnlockDevice::DisposableProbe(path) => BlockDevice::open(path)?,
        };
        let mapper_path = PathBuf::from("/dev/mapper").join(mapper.as_os_str());
        let mount_root = PathBuf::from(RUNTIME_ROOT)
            .join(VAULT_MOUNT_PARENT)
            .join(mapper.as_os_str());
        Ok(Self {
            device,
            mapper,
            mapper_path,
            mount_root,
        })
    }
}

struct BlockDevice {
    // Direct /dev node used only for repeated identity checkpoints. Tools and
    // mutators never receive it.
    checkpoint_path: PathBuf,
    // Parent-only procfs checkpoint for the retained descriptor. Child tools
    // receive a scoped duplicate and address only their own procfs namespace.
    checkpoint_procfd: PathBuf,
    descriptor: OwnedFd,
    device: u64,
    inode: u64,
    rdev: u64,
    disk_sequence: u64,
    capacity_sectors: u64,
    logical_sector_bytes: u64,
    located_identity: Option<LocatedVaultIdentity>,
}

impl BlockDevice {
    #[cfg(feature = "privileged-probe")]
    fn open(path: PathBuf) -> Result<Self, VaultMountManagerError> {
        let descriptor = rfs::openat2(
            CWD,
            &path,
            OFlags::RDONLY | OFlags::NONBLOCK | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
            ResolveFlags::NO_SYMLINKS | ResolveFlags::NO_MAGICLINKS,
        )
        .map_err(|_| VaultMountManagerError::InvalidBlockDevice)?;
        Self::from_descriptor(path, descriptor, None)
    }

    fn from_located(device: LocatedVaultPartition) -> Result<Self, VaultMountManagerError> {
        let (descriptor, identity, device_name) = device.into_manager_parts();
        let path = validate_device_path(&PathBuf::from("/dev").join(device_name))?;
        Self::from_descriptor(path, descriptor.into(), Some(identity))
    }

    fn from_descriptor(
        path: PathBuf,
        descriptor: OwnedFd,
        located_identity: Option<LocatedVaultIdentity>,
    ) -> Result<Self, VaultMountManagerError> {
        let stat =
            rfs::fstat(&descriptor).map_err(|_| VaultMountManagerError::InvalidBlockDevice)?;
        let status = rfs::fcntl_getfl(&descriptor)
            .map_err(|_| VaultMountManagerError::InvalidBlockDevice)?;
        let descriptor_flags = rustix::io::fcntl_getfd(&descriptor)
            .map_err(|_| VaultMountManagerError::InvalidBlockDevice)?;
        let major_minor = (rfs::major(stat.st_rdev), rfs::minor(stat.st_rdev));
        if !FileType::from_raw_mode(stat.st_mode).is_block_device()
            || status & OFlags::ACCMODE != OFlags::RDONLY
            || !status.contains(OFlags::NONBLOCK)
            || !descriptor_flags.contains(rustix::io::FdFlags::CLOEXEC)
            || located_identity.is_some_and(|identity| {
                major_minor != (identity.partition_major, identity.partition_minor)
                    || identity.logical_sector_bytes != LOGICAL_SECTOR_BYTES
                    || identity.start_lba != VAULT_START_LBA
                    || identity.sector_count != VAULT_SECTOR_COUNT
                    || identity
                        .start_lba
                        .checked_add(identity.sector_count)
                        .is_none_or(|end| end > identity.media_sector_count)
                    || identity
                        .media_sector_count
                        .checked_mul(LOGICAL_SECTOR_BYTES)
                        .is_none_or(|bytes| bytes < MINIMUM_ADVERTISED_MEDIA_BYTES)
            })
        {
            return Err(VaultMountManagerError::InvalidBlockDevice);
        }
        let observed_identity = source_descriptor_block_identity(&descriptor)?;
        if located_identity
            .is_some_and(|identity| !source_identity_matches_location(observed_identity, identity))
        {
            return Err(VaultMountManagerError::InvalidBlockDevice);
        }
        if observed_identity.logical_sector_bytes != LOGICAL_SECTOR_BYTES {
            return Err(VaultMountManagerError::InvalidBlockDevice);
        }
        let checkpoint_procfd = retained_descriptor_path(&descriptor)?;
        let result = Self {
            checkpoint_path: path,
            checkpoint_procfd,
            descriptor,
            device: stat.st_dev,
            inode: stat.st_ino,
            rdev: stat.st_rdev,
            disk_sequence: observed_identity.disk_sequence,
            capacity_sectors: observed_identity.sector_count,
            logical_sector_bytes: observed_identity.logical_sector_bytes,
            located_identity,
        };
        result.revalidate()?;
        Ok(result)
    }

    fn revalidate(&self) -> Result<(), VaultMountManagerError> {
        self.validate_endpoint_paths()?;
        let observed = source_descriptor_block_identity(&self.descriptor)?;
        self.validate_endpoint_paths()?;
        if observed.disk_sequence != self.disk_sequence
            || observed.sector_count != self.capacity_sectors
            || observed.logical_sector_bytes != self.logical_sector_bytes
            || observed.logical_sector_bytes != LOGICAL_SECTOR_BYTES
            || self.located_identity.is_some_and(|identity| {
                self.major_minor() != (identity.partition_major, identity.partition_minor)
                    || !source_identity_matches_location(observed, identity)
            })
        {
            return Err(VaultMountManagerError::InvalidBlockDevice);
        }
        Ok(())
    }

    fn validate_endpoint_paths(&self) -> Result<(), VaultMountManagerError> {
        let descriptor =
            rfs::fstat(&self.descriptor).map_err(|_| VaultMountManagerError::InvalidBlockDevice)?;
        let named = rfs::statat(CWD, &self.checkpoint_path, AtFlags::SYMLINK_NOFOLLOW)
            .map_err(|_| VaultMountManagerError::InvalidBlockDevice)?;
        let command = rfs::statat(CWD, &self.checkpoint_procfd, AtFlags::empty())
            .map_err(|_| VaultMountManagerError::InvalidBlockDevice)?;
        let status = rfs::fcntl_getfl(&self.descriptor)
            .map_err(|_| VaultMountManagerError::InvalidBlockDevice)?;
        let descriptor_flags = rustix::io::fcntl_getfd(&self.descriptor)
            .map_err(|_| VaultMountManagerError::InvalidBlockDevice)?;
        if !FileType::from_raw_mode(descriptor.st_mode).is_block_device()
            || !FileType::from_raw_mode(named.st_mode).is_block_device()
            || descriptor.st_dev != self.device
            || descriptor.st_ino != self.inode
            || descriptor.st_rdev != self.rdev
            || named.st_dev != self.device
            || named.st_ino != self.inode
            || named.st_rdev != self.rdev
            || !FileType::from_raw_mode(command.st_mode).is_block_device()
            || command.st_dev != self.device
            || command.st_ino != self.inode
            || command.st_rdev != self.rdev
            || status & OFlags::ACCMODE != OFlags::RDONLY
            || !status.contains(OFlags::NONBLOCK)
            || !descriptor_flags.contains(rustix::io::FdFlags::CLOEXEC)
        {
            return Err(VaultMountManagerError::InvalidBlockDevice);
        }
        Ok(())
    }

    fn major_minor(&self) -> (u32, u32) {
        (rfs::major(self.rdev), rfs::minor(self.rdev))
    }

    #[cfg(feature = "experimental-repair-store")]
    fn repair_physical_parent_claims(&self) -> Option<RepairPhysicalParentClaims> {
        self.located_identity
            .map(|identity| RepairPhysicalParentClaims {
                parent_major: identity.parent_major,
                parent_minor: identity.parent_minor,
                disk_sequence: identity.disk_sequence,
                media_sector_count: identity.media_sector_count,
                logical_sector_bytes: identity.logical_sector_bytes,
            })
    }

    fn revalidate_profile_capability(&self) -> Result<(), ProfileClassifierError> {
        self.validate_endpoint_paths()
            .map_err(|_| ProfileClassifierError::MediaChanged)?;
        if self.capacity_sectors.checked_mul(LOGICAL_SECTOR_BYTES) != Some(VAULT_PARTITION_BYTES)
            || self.logical_sector_bytes != LOGICAL_SECTOR_BYTES
        {
            return Err(ProfileClassifierError::MediaChanged);
        }
        Ok(())
    }
}

fn retained_descriptor_path(descriptor: &impl AsRawFd) -> Result<PathBuf, VaultMountManagerError> {
    let descriptor_number = descriptor.as_raw_fd();
    if descriptor_number < 0 {
        return Err(VaultMountManagerError::InvalidBlockDevice);
    }
    Ok(PathBuf::from(format!(
        "/proc/{}/fd/{descriptor_number}",
        std::process::id()
    )))
}

#[derive(Clone, Copy)]
struct HeaderIdentity {
    uuid: [u8; 36],
}

struct MappingIdentity {
    descriptor: OwnedFd,
    checkpoint_procfd: PathBuf,
    device: u64,
    inode: u64,
    rdev: u64,
    major: u32,
    minor: u32,
    backing_major: u32,
    backing_minor: u32,
    capacity_sectors: u64,
    logical_sector_bytes: u64,
}

impl MappingIdentity {
    fn revalidate(
        &self,
        device: &BlockDevice,
        mapper: &MapperName,
        header: HeaderIdentity,
    ) -> Result<(), VaultMountManagerError> {
        device.revalidate()?;
        self.validate_endpoint_path()?;
        let block_identity = mapping_descriptor_block_geometry(&self.descriptor)?;
        self.validate_endpoint_path()?;
        if block_identity.sector_count != self.capacity_sectors
            || block_identity.logical_sector_bytes != self.logical_sector_bytes
            || block_identity.logical_sector_bytes != LOGICAL_SECTOR_BYTES
            || block_identity
                .sector_count
                .checked_mul(LOGICAL_SECTOR_BYTES)
                != Some(VAULT_PAYLOAD_BYTES)
        {
            return Err(VaultMountManagerError::MappingVerificationFailed);
        }
        let descriptor = rfs::fstat(&self.descriptor)
            .map_err(|_| VaultMountManagerError::MappingVerificationFailed)?;
        let command = rfs::statat(CWD, &self.checkpoint_procfd, AtFlags::empty())
            .map_err(|_| VaultMountManagerError::MappingVerificationFailed)?;
        let status = rfs::fcntl_getfl(&self.descriptor)
            .map_err(|_| VaultMountManagerError::MappingVerificationFailed)?;
        let descriptor_flags = rustix::io::fcntl_getfd(&self.descriptor)
            .map_err(|_| VaultMountManagerError::MappingVerificationFailed)?;
        if !FileType::from_raw_mode(descriptor.st_mode).is_block_device()
            || descriptor.st_dev != self.device
            || descriptor.st_ino != self.inode
            || descriptor.st_rdev != self.rdev
            || command.st_dev != self.device
            || command.st_ino != self.inode
            || command.st_rdev != self.rdev
            || status & OFlags::ACCMODE != OFlags::RDONLY
            || !status.contains(OFlags::NONBLOCK)
            || !descriptor_flags.contains(rustix::io::FdFlags::CLOEXEC)
            || rfs::major(self.rdev) != self.major
            || rfs::minor(self.rdev) != self.minor
        {
            return Err(VaultMountManagerError::MappingVerificationFailed);
        }
        let sysfs = PathBuf::from(format!("/sys/dev/block/{}:{}", self.major, self.minor));
        if trim_line(&read_small_file(&sysfs.join("dm/name"))?) != mapper.as_os_str().as_bytes()
            || parse_dm_uuid(trim_line(&read_small_file(&sysfs.join("dm/uuid"))?), mapper)
                != Some(header.uuid)
        {
            return Err(VaultMountManagerError::MappingVerificationFailed);
        }
        let backing = single_backing_device(&sysfs.join("slaves"))?;
        if backing != (self.backing_major, self.backing_minor) || backing != device.major_minor() {
            return Err(VaultMountManagerError::MappingVerificationFailed);
        }
        verify_unique_backing_holder(backing, (self.major, self.minor))?;
        device.revalidate()?;
        Ok(())
    }

    fn validate_endpoint_path(&self) -> Result<(), VaultMountManagerError> {
        let descriptor = rfs::fstat(&self.descriptor)
            .map_err(|_| VaultMountManagerError::MappingVerificationFailed)?;
        let command = rfs::statat(CWD, &self.checkpoint_procfd, AtFlags::empty())
            .map_err(|_| VaultMountManagerError::MappingVerificationFailed)?;
        let status = rfs::fcntl_getfl(&self.descriptor)
            .map_err(|_| VaultMountManagerError::MappingVerificationFailed)?;
        let descriptor_flags = rustix::io::fcntl_getfd(&self.descriptor)
            .map_err(|_| VaultMountManagerError::MappingVerificationFailed)?;
        if !FileType::from_raw_mode(descriptor.st_mode).is_block_device()
            || descriptor.st_dev != self.device
            || descriptor.st_ino != self.inode
            || descriptor.st_rdev != self.rdev
            || !FileType::from_raw_mode(command.st_mode).is_block_device()
            || command.st_dev != self.device
            || command.st_ino != self.inode
            || command.st_rdev != self.rdev
            || status & OFlags::ACCMODE != OFlags::RDONLY
            || !status.contains(OFlags::NONBLOCK)
            || !descriptor_flags.contains(rustix::io::FdFlags::CLOEXEC)
        {
            return Err(VaultMountManagerError::MappingVerificationFailed);
        }
        Ok(())
    }
}

struct Activation<R: VaultOps> {
    ops: R,
    _manager_lock: OwnedFd,
    request: ResolvedRequest,
    outer_profile: OuterProfileEvidence,
    header: HeaderIdentity,
    mapping: Option<MappingIdentity>,
    attestation: Option<VaultMountAttestation>,
    mapping_open: bool,
    deferred_remove_armed: bool,
    mounted: bool,
    mutator_invoked: bool,
    cleanup_attempted: bool,
    #[cfg(feature = "experimental-firstboot-provisioner")]
    provisioning_filesystem_uuid: Option<[u8; 36]>,
    #[cfg(feature = "experimental-firstboot-provisioner")]
    provisioning_key_size: Option<usize>,
    #[cfg(feature = "experimental-firstboot-provisioner")]
    mounted_filesystem_profile: Option<Ext4ProfileEvidence>,
}

impl<R: VaultOps> Activation<R> {
    fn start(
        ops: R,
        manager_lock: OwnedFd,
        request: ResolvedRequest,
        passphrase: impl AsFd,
    ) -> Result<Self, VaultMountManagerError> {
        Self::start_with_filesystem(ops, manager_lock, request, passphrase, None, None)
    }

    #[cfg(feature = "experimental-firstboot-provisioner")]
    fn start_for_provisioning(
        ops: R,
        manager_lock: OwnedFd,
        request: ResolvedRequest,
        passphrase: impl AsFd,
        key_size: usize,
        filesystem_uuid: [u8; 36],
    ) -> Result<Self, VaultMountManagerError> {
        Self::start_with_filesystem(
            ops,
            manager_lock,
            request,
            passphrase,
            Some(key_size),
            Some(filesystem_uuid),
        )
    }

    fn start_with_filesystem(
        mut ops: R,
        manager_lock: OwnedFd,
        request: ResolvedRequest,
        passphrase: impl AsFd,
        #[cfg(feature = "experimental-firstboot-provisioner")] provisioning_key_size: Option<usize>,
        #[cfg(not(feature = "experimental-firstboot-provisioner"))] _provisioning_key_size: Option<
            usize,
        >,
        #[cfg(feature = "experimental-firstboot-provisioner")] provisioning_filesystem_uuid: Option<
            [u8; 36],
        >,
        #[cfg(not(feature = "experimental-firstboot-provisioner"))]
        _provisioning_filesystem_uuid: Option<[u8; 36]>,
    ) -> Result<Self, VaultMountManagerError> {
        ops.ensure_device_unused(&request.device)?;
        ops.ensure_mapper_absent(&request.mapper, &request.mapper_path)?;
        let outer_profile = ops.classify_outer_profile(&request.device)?;
        let header = HeaderIdentity {
            uuid: outer_profile.uuid(),
        };

        let mut activation = Self {
            ops,
            _manager_lock: manager_lock,
            request,
            outer_profile,
            header,
            mapping: None,
            attestation: None,
            mapping_open: false,
            deferred_remove_armed: false,
            mounted: false,
            mutator_invoked: false,
            cleanup_attempted: false,
            #[cfg(feature = "experimental-firstboot-provisioner")]
            provisioning_filesystem_uuid,
            #[cfg(feature = "experimental-firstboot-provisioner")]
            provisioning_key_size,
            #[cfg(feature = "experimental-firstboot-provisioner")]
            mounted_filesystem_profile: None,
        };

        let result = activation.continue_start(passphrase);
        match result {
            Ok(()) => Ok(activation),
            Err(primary) => {
                if activation.mutator_invoked && activation.cleanup().is_err() {
                    Err(VaultMountManagerError::CleanupFailed)
                } else {
                    Err(primary)
                }
            }
        }
    }

    fn continue_start(&mut self, passphrase: impl AsFd) -> Result<(), VaultMountManagerError> {
        // Finish every fallible read-only checkpoint before claiming that a
        // mapper mutation may have occurred. A failed checkpoint must never
        // confer ownership of a concurrently created mapper.
        self.ops.pre_open_revalidate(&self.request.device)?;
        // The source descriptor was made CLOEXEC before any validation child
        // was spawned. Create the only duplicate at the last possible moment;
        // Command transfers it onto fd 0 and exec closes every other copy.
        let cryptsetup_passphrase = rustix::io::fcntl_dupfd_cloexec(&passphrase, 3)
            .map_err(|_| VaultMountManagerError::PassphraseUnavailable)?;
        self.mutator_invoked = true;
        #[cfg(feature = "experimental-firstboot-provisioner")]
        let open_result = if let Some(key_size) = self.provisioning_key_size.take() {
            self.ops.open_luks2_sized(
                &self.request.device,
                &self.request.mapper,
                cryptsetup_passphrase,
                key_size,
            )
        } else {
            self.ops.open_luks2(
                &self.request.device,
                &self.request.mapper,
                cryptsetup_passphrase,
            )
        };
        #[cfg(not(feature = "experimental-firstboot-provisioner"))]
        let open_result = self.ops.open_luks2(
            &self.request.device,
            &self.request.mapper,
            cryptsetup_passphrase,
        );
        drop(passphrase);

        // A spawn failure proves cryptsetup never ran, so do not acquire or
        // close a concurrently created mapping merely because it matches the
        // requested public identity.
        if open_result == Err(VaultMountManagerError::ToolUnavailable) {
            self.mutator_invoked = false;
            return Err(VaultMountManagerError::ToolUnavailable);
        }
        // CleanupFailed means the mutating cryptsetup child or its process
        // group is still unowned. Do not inspect, acquire, or close any mapper
        // while that mutator may resume; the outer start wrapper records the
        // terminal cleanup failure without issuing an ambiguous operation.
        if open_result == Err(VaultMountManagerError::CleanupFailed) {
            return Err(VaultMountManagerError::CleanupFailed);
        }

        // cryptsetup may return an error after the kernel accepted the mapping
        // (for example after interruption). Acquire the complete mapping
        // identity stepwise so Drop can close it only when it is still exact.
        let mapping_result = self.ops.inspect_mapping(
            &self.request.device,
            &self.request.mapper,
            &self.request.mapper_path,
            self.header,
        );
        match mapping_result {
            Ok(mapping) => {
                self.mapping = Some(mapping);
                self.mapping_open = true;
            }
            Err(mapping_error) => {
                if mapping_error == VaultMountManagerError::CleanupFailed {
                    return Err(VaultMountManagerError::CleanupFailed);
                }
                if let Err(open_error) = open_result {
                    if open_error == VaultMountManagerError::CleanupFailed {
                        return Err(VaultMountManagerError::CleanupFailed);
                    }
                    if self
                        .ops
                        .verify_failed_open_absence(
                            &self.request.device,
                            &self.request.mapper,
                            &self.request.mapper_path,
                        )
                        .is_ok()
                    {
                        return Err(dominant_open_inspection_error(open_error, mapping_error));
                    }
                    return Err(VaultMountManagerError::CleanupFailed);
                } else {
                    // We know cryptsetup reported success, but we do not have
                    // enough identity to issue an ambiguous close.
                    self.mapping_open = true;
                }
                return Err(VaultMountManagerError::CleanupFailed);
            }
        }
        // Once the exact mapping descriptor is retained, make kernel removal
        // owner-bound before performing any further fallible work. If this
        // process is killed, the private mount and retained descriptor are the
        // remaining users; device-mapper removes the mapping when they close.
        self.ops
            .arm_deferred_mapping_removal(&self.request.mapper)?;
        self.deferred_remove_armed = true;
        let mapping = self
            .mapping
            .as_ref()
            .ok_or(VaultMountManagerError::MappingVerificationFailed)?;
        self.ops.verify_deferred_mapping_removal(
            &self.request.device,
            &self.request.mapper,
            self.header,
            mapping,
        )?;
        open_result?;
        if self.ops.classify_outer_profile(&self.request.device)? != self.outer_profile {
            return Err(VaultMountManagerError::ProfileMismatch);
        }
        let mapping = self
            .mapping
            .as_ref()
            .ok_or(VaultMountManagerError::MappingVerificationFailed)?;
        #[cfg(feature = "experimental-firstboot-provisioner")]
        if let Some(filesystem_uuid) = self.provisioning_filesystem_uuid.take() {
            self.ops.format_filesystem(
                &self.request.device,
                &self.request.mapper,
                mapping,
                self.header,
                filesystem_uuid,
            )?;
        }
        let filesystem_profile = self.ops.inspect_filesystem(
            &self.request.device,
            &self.request.mapper,
            mapping,
            self.header,
        )?;
        self.ops.prepare_mount_root(&self.request.mount_root)?;
        // This mapping checkpoint may itself time out. Run it before claiming
        // mount ownership so failure cannot trigger an unmount of a mount that
        // this activation never created.
        self.ops.pre_mount_revalidate(
            &self.request.device,
            &self.request.mapper,
            mapping,
            self.header,
        )?;
        // Treat the mount syscall as mutating until an explicit cleanup proves
        // and removes the exact mount; an error cannot silently rely on Drop.
        self.mounted = true;
        self.ops.mount_ext4(
            &self.request.device,
            &self.request.mapper,
            mapping,
            self.header,
            &self.request.mount_root,
        )?;
        self.ops.verify_mounted_filesystem(
            &self.request.device,
            &self.request.mapper,
            mapping,
            self.header,
            filesystem_profile,
        )?;
        #[cfg(feature = "experimental-firstboot-provisioner")]
        {
            self.mounted_filesystem_profile = Some(filesystem_profile);
        }
        if self.ops.classify_outer_profile(&self.request.device)? != self.outer_profile {
            return Err(VaultMountManagerError::ProfileMismatch);
        }
        self.attestation = Some(self.ops.attest_mount(&self.request, self.header, mapping)?);
        Ok(())
    }

    fn cleanup(&mut self) -> Result<(), VaultMountManagerError> {
        if self.cleanup_attempted {
            return Err(VaultMountManagerError::CleanupFailed);
        }
        self.cleanup_attempted = true;
        self.cleanup_inner()
            .map_err(|_| VaultMountManagerError::CleanupFailed)
    }

    fn cleanup_inner(&mut self) -> Result<(), VaultMountManagerError> {
        if self.mounted {
            let mapping = self
                .mapping
                .as_ref()
                .ok_or(VaultMountManagerError::CleanupFailed)?;
            self.ops.verify_cleanup_mount(
                &self.request,
                self.header,
                mapping,
                self.attestation.as_ref(),
            )?;
            self.ops.unmount(&self.request.mount_root)?;
            self.ops
                .verify_unmounted(&self.request, self.header, mapping)?;
            self.mounted = false;
        }
        if self.mapping_open {
            let mapping = self
                .mapping
                .as_ref()
                .ok_or(VaultMountManagerError::CleanupFailed)?;
            self.ops.verify_cleanup_mapping(
                &self.request.device,
                &self.request.mapper,
                &self.request.mapper_path,
                self.header,
                mapping,
            )?;
            // A retained descriptor is required for every verification and
            // mount operation. A deferred mapping is removed by the kernel
            // after this final descriptor closes; a pre-arm failure retains
            // the original explicit-close path.
            drop(self.mapping.take());
            if self.deferred_remove_armed {
                self.ops.wait_for_deferred_mapping_absence(
                    &self.request.device,
                    &self.request.mapper,
                    &self.request.mapper_path,
                )?;
            } else {
                self.ops.close_mapping(&self.request.mapper)?;
                self.ops.verify_closed_mapping_absence(
                    &self.request.device,
                    &self.request.mapper,
                    &self.request.mapper_path,
                )?;
            }
            self.mapping_open = false;
        }
        Ok(())
    }
}

fn dominant_open_inspection_error(
    open_error: VaultMountManagerError,
    mapping_error: VaultMountManagerError,
) -> VaultMountManagerError {
    for dominant in [
        VaultMountManagerError::CleanupFailed,
        VaultMountManagerError::OperationTimedOut,
        VaultMountManagerError::ToolUnavailable,
    ] {
        if open_error == dominant || mapping_error == dominant {
            return dominant;
        }
    }
    open_error
}

impl<R: VaultOps> Drop for Activation<R> {
    fn drop(&mut self) {
        if !self.cleanup_attempted {
            self.cleanup_attempted = true;
            let _ = self.cleanup_inner();
        }
    }
}

trait VaultOps {
    fn ensure_device_unused(&mut self, device: &BlockDevice) -> Result<(), VaultMountManagerError>;
    fn ensure_mapper_absent(
        &mut self,
        mapper: &MapperName,
        mapper_path: &Path,
    ) -> Result<(), VaultMountManagerError>;
    fn classify_outer_profile(
        &mut self,
        device: &BlockDevice,
    ) -> Result<OuterProfileEvidence, VaultMountManagerError>;
    fn pre_open_revalidate(&mut self, device: &BlockDevice) -> Result<(), VaultMountManagerError>;
    fn open_luks2(
        &mut self,
        device: &BlockDevice,
        mapper: &MapperName,
        passphrase: OwnedFd,
    ) -> Result<(), VaultMountManagerError>;
    #[cfg(feature = "experimental-firstboot-provisioner")]
    fn open_luks2_sized(
        &mut self,
        device: &BlockDevice,
        mapper: &MapperName,
        passphrase: OwnedFd,
        _key_size: usize,
    ) -> Result<(), VaultMountManagerError> {
        self.open_luks2(device, mapper, passphrase)
    }
    fn inspect_mapping(
        &mut self,
        device: &BlockDevice,
        mapper: &MapperName,
        mapper_path: &Path,
        header: HeaderIdentity,
    ) -> Result<MappingIdentity, VaultMountManagerError>;
    fn verify_failed_open_absence(
        &mut self,
        device: &BlockDevice,
        mapper: &MapperName,
        mapper_path: &Path,
    ) -> Result<(), VaultMountManagerError>;
    fn arm_deferred_mapping_removal(
        &mut self,
        mapper: &MapperName,
    ) -> Result<(), VaultMountManagerError>;
    fn verify_deferred_mapping_removal(
        &mut self,
        device: &BlockDevice,
        mapper: &MapperName,
        header: HeaderIdentity,
        expected: &MappingIdentity,
    ) -> Result<(), VaultMountManagerError>;
    fn verify_closed_mapping_absence(
        &mut self,
        device: &BlockDevice,
        mapper: &MapperName,
        mapper_path: &Path,
    ) -> Result<(), VaultMountManagerError>;
    fn wait_for_deferred_mapping_absence(
        &mut self,
        device: &BlockDevice,
        mapper: &MapperName,
        mapper_path: &Path,
    ) -> Result<(), VaultMountManagerError>;
    #[cfg(feature = "experimental-firstboot-provisioner")]
    fn format_filesystem(
        &mut self,
        _device: &BlockDevice,
        _mapper: &MapperName,
        _mapping: &MappingIdentity,
        _header: HeaderIdentity,
        _filesystem_uuid: [u8; 36],
    ) -> Result<(), VaultMountManagerError> {
        Err(VaultMountManagerError::ProvisioningInitializationFailed)
    }
    fn inspect_filesystem(
        &mut self,
        device: &BlockDevice,
        mapper: &MapperName,
        mapping: &MappingIdentity,
        header: HeaderIdentity,
    ) -> Result<Ext4ProfileEvidence, VaultMountManagerError>;
    fn prepare_mount_root(&mut self, root: &Path) -> Result<(), VaultMountManagerError>;
    fn pre_mount_revalidate(
        &mut self,
        device: &BlockDevice,
        mapper: &MapperName,
        mapping: &MappingIdentity,
        header: HeaderIdentity,
    ) -> Result<(), VaultMountManagerError>;
    fn mount_ext4(
        &mut self,
        device: &BlockDevice,
        mapper: &MapperName,
        mapping: &MappingIdentity,
        header: HeaderIdentity,
        root: &Path,
    ) -> Result<(), VaultMountManagerError>;
    fn verify_mounted_filesystem(
        &mut self,
        device: &BlockDevice,
        mapper: &MapperName,
        mapping: &MappingIdentity,
        header: HeaderIdentity,
        expected: Ext4ProfileEvidence,
    ) -> Result<(), VaultMountManagerError>;
    fn attest_mount(
        &mut self,
        request: &ResolvedRequest,
        header: HeaderIdentity,
        mapping: &MappingIdentity,
    ) -> Result<VaultMountAttestation, VaultMountManagerError>;
    fn verify_cleanup_mount(
        &mut self,
        request: &ResolvedRequest,
        header: HeaderIdentity,
        mapping: &MappingIdentity,
        attestation: Option<&VaultMountAttestation>,
    ) -> Result<(), VaultMountManagerError>;
    fn unmount(&mut self, root: &Path) -> Result<(), VaultMountManagerError>;
    fn verify_unmounted(
        &mut self,
        request: &ResolvedRequest,
        header: HeaderIdentity,
        mapping: &MappingIdentity,
    ) -> Result<(), VaultMountManagerError>;
    fn verify_cleanup_mapping(
        &mut self,
        device: &BlockDevice,
        mapper: &MapperName,
        mapper_path: &Path,
        header: HeaderIdentity,
        expected: &MappingIdentity,
    ) -> Result<(), VaultMountManagerError>;
    fn close_mapping(&mut self, mapper: &MapperName) -> Result<(), VaultMountManagerError>;
}

struct SystemOps;

impl SystemOps {
    fn verify_mapping_absence(
        device: &BlockDevice,
        mapper: &MapperName,
        mapper_path: &Path,
    ) -> Result<(), VaultMountManagerError> {
        device
            .revalidate()
            .map_err(|_| VaultMountManagerError::CleanupFailed)?;
        verify_mapper_absence_checkpoint(device, mapper, mapper_path)?;
        device
            .revalidate()
            .map_err(|_| VaultMountManagerError::CleanupFailed)?;
        verify_mapper_absence_checkpoint(device, mapper, mapper_path)
    }

    fn wait_for_mapping_absence(
        device: &BlockDevice,
        mapper: &MapperName,
        mapper_path: &Path,
    ) -> Result<(), VaultMountManagerError> {
        device
            .revalidate()
            .map_err(|_| VaultMountManagerError::CleanupFailed)?;
        let deadline = Instant::now()
            .checked_add(DEFERRED_REMOVE_TIMEOUT)
            .ok_or(VaultMountManagerError::CleanupFailed)?;
        loop {
            if mapping_absence_checkpoint(device, mapper, mapper_path)? {
                break;
            }
            let now = Instant::now();
            if now >= deadline {
                return Err(VaultMountManagerError::CleanupFailed);
            }
            thread::sleep(DEFERRED_REMOVE_POLL_INTERVAL.min(deadline.duration_since(now)));
        }
        device
            .revalidate()
            .map_err(|_| VaultMountManagerError::CleanupFailed)?;
        verify_mapper_absence_checkpoint(device, mapper, mapper_path)
    }

    fn run_capture(mut command: Command) -> Result<Vec<u8>, VaultMountManagerError> {
        command
            .env_clear()
            .env("LC_ALL", "C")
            .stdin(Stdio::null())
            .stderr(Stdio::null())
            .stdout(Stdio::piped());
        let output = bounded_process::capture(&mut command, COMMAND_TIMEOUT, COMMAND_OUTPUT_LIMIT)
            .map_err(map_bounded_process_error)?;
        if !output.status.success() {
            return Err(VaultMountManagerError::MappingVerificationFailed);
        }
        Ok(output.bytes)
    }

    fn run_capture_with_stdin(
        mut command: Command,
        stdin: Stdio,
    ) -> Result<Vec<u8>, VaultMountManagerError> {
        command
            .env_clear()
            .env("LC_ALL", "C")
            .stdin(stdin)
            .stderr(Stdio::null())
            .stdout(Stdio::piped());
        let output = bounded_process::capture(&mut command, COMMAND_TIMEOUT, COMMAND_OUTPUT_LIMIT)
            .map_err(map_bounded_process_error)?;
        if !output.status.success() {
            return Err(VaultMountManagerError::MappingVerificationFailed);
        }
        Ok(output.bytes)
    }

    fn run_quiet(mut command: Command) -> Result<(), VaultMountManagerError> {
        command
            .env_clear()
            .env("LC_ALL", "C")
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        let status = bounded_process::wait(&mut command, COMMAND_TIMEOUT)
            .map_err(map_bounded_process_error)?;
        if !status.success() {
            return Err(VaultMountManagerError::CleanupFailed);
        }
        Ok(())
    }

    fn mapping_status(mapper: &MapperName) -> Result<Vec<u8>, VaultMountManagerError> {
        let mut command = Command::new(CRYPTSETUP_PATH);
        command.arg("status").arg(mapper.as_os_str());
        Self::run_capture(command)
    }
}

impl VaultOps for SystemOps {
    fn ensure_device_unused(&mut self, device: &BlockDevice) -> Result<(), VaultMountManagerError> {
        device.revalidate()?;
        let (major, minor) = device.major_minor();
        let holders = PathBuf::from(format!("/sys/dev/block/{major}:{minor}/holders"));
        let mut entries =
            fs::read_dir(holders).map_err(|_| VaultMountManagerError::InvalidBlockDevice)?;
        if entries.next().is_some() {
            return Err(VaultMountManagerError::MapperConflict);
        }
        Ok(())
    }

    fn ensure_mapper_absent(
        &mut self,
        mapper: &MapperName,
        mapper_path: &Path,
    ) -> Result<(), VaultMountManagerError> {
        require_mapper_path_absent(
            rfs::statat(CWD, mapper_path, AtFlags::SYMLINK_NOFOLLOW).map(|_| ()),
        )?;
        if sysfs_mapper_name_exists(mapper)? {
            return Err(VaultMountManagerError::MapperConflict);
        }
        Ok(())
    }

    fn classify_outer_profile(
        &mut self,
        device: &BlockDevice,
    ) -> Result<OuterProfileEvidence, VaultMountManagerError> {
        device.revalidate()?;
        let classification = classify_partition(&device.descriptor, || {
            device.revalidate_profile_capability()
        })
        .map_err(map_profile_classifier_error)?;
        device.revalidate()?;
        match classification {
            VaultPartitionProfile::Unprovisioned => Err(VaultMountManagerError::Unprovisioned),
            VaultPartitionProfile::Locked(evidence) => Ok(evidence),
            VaultPartitionProfile::ProfileMismatch => Err(VaultMountManagerError::ProfileMismatch),
        }
    }

    fn pre_open_revalidate(&mut self, device: &BlockDevice) -> Result<(), VaultMountManagerError> {
        device.revalidate()
    }

    fn open_luks2(
        &mut self,
        device: &BlockDevice,
        mapper: &MapperName,
        passphrase: OwnedFd,
    ) -> Result<(), VaultMountManagerError> {
        let inherited = bounded_process::InheritedChildDescriptor::duplicate(&device.descriptor)
            .map_err(map_bounded_process_error)?;
        let mut command = cryptsetup_open_command(inherited.path(), mapper);
        command
            .env_clear()
            .env("LC_ALL", "C")
            .stdin(Stdio::from(File::from(passphrase)))
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        let status =
            bounded_process::wait_with_descriptor(&mut command, COMMAND_TIMEOUT, inherited)
                .map_err(map_bounded_process_error)?;
        if !status.success() {
            return Err(VaultMountManagerError::UnlockFailed);
        }
        Ok(())
    }

    #[cfg(feature = "experimental-firstboot-provisioner")]
    fn open_luks2_sized(
        &mut self,
        device: &BlockDevice,
        mapper: &MapperName,
        passphrase: OwnedFd,
        key_size: usize,
    ) -> Result<(), VaultMountManagerError> {
        let inherited = bounded_process::InheritedChildDescriptor::duplicate(&device.descriptor)
            .map_err(map_bounded_process_error)?;
        let mut command =
            cryptsetup_open_sized_command(inherited.path(), mapper, &key_size.to_string());
        command
            .env_clear()
            .env("LC_ALL", "C")
            .stdin(Stdio::from(File::from(passphrase)))
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        let status = bounded_process::wait_with_descriptor(
            &mut command,
            PROVISIONING_COMMAND_TIMEOUT,
            inherited,
        )
        .map_err(map_bounded_process_error)?;
        if !status.success() {
            return Err(VaultMountManagerError::UnlockFailed);
        }
        Ok(())
    }

    fn inspect_mapping(
        &mut self,
        device: &BlockDevice,
        mapper: &MapperName,
        mapper_path: &Path,
        header: HeaderIdentity,
    ) -> Result<MappingIdentity, VaultMountManagerError> {
        device.revalidate()?;
        let descriptor = rfs::openat2(
            CWD,
            mapper_path,
            OFlags::RDONLY | OFlags::NONBLOCK | OFlags::CLOEXEC,
            Mode::empty(),
            ResolveFlags::NO_MAGICLINKS,
        )
        .map_err(|_| VaultMountManagerError::MappingVerificationFailed)?;
        let stat = rfs::fstat(&descriptor)
            .map_err(|_| VaultMountManagerError::MappingVerificationFailed)?;
        if !FileType::from_raw_mode(stat.st_mode).is_block_device() {
            return Err(VaultMountManagerError::MappingVerificationFailed);
        }
        let major = rfs::major(stat.st_rdev);
        let minor = rfs::minor(stat.st_rdev);
        let sysfs = PathBuf::from(format!("/sys/dev/block/{major}:{minor}"));
        let observed_name = read_small_file(&sysfs.join("dm/name"))?;
        if trim_line(&observed_name) != mapper.as_os_str().as_bytes() {
            return Err(VaultMountManagerError::MappingVerificationFailed);
        }
        let dm_uuid = read_small_file(&sysfs.join("dm/uuid"))?;
        if parse_dm_uuid(trim_line(&dm_uuid), mapper) != Some(header.uuid) {
            return Err(VaultMountManagerError::MappingVerificationFailed);
        }
        let backing = single_backing_device(&sysfs.join("slaves"))?;
        if backing != device.major_minor() {
            return Err(VaultMountManagerError::MappingVerificationFailed);
        }
        verify_unique_backing_holder(backing, (major, minor))?;
        let status = Self::mapping_status(mapper)?;
        // The exact backing major:minor and sole DM slave were verified above;
        // cryptsetup's informational device pathname is not an identity.
        verify_cryptsetup_status(&status)?;
        device.revalidate()?;
        verify_unique_backing_holder(backing, (major, minor))?;
        let block_identity = mapping_descriptor_block_geometry(&descriptor)?;
        if block_identity.logical_sector_bytes != LOGICAL_SECTOR_BYTES
            || block_identity
                .sector_count
                .checked_mul(LOGICAL_SECTOR_BYTES)
                != Some(VAULT_PAYLOAD_BYTES)
        {
            return Err(VaultMountManagerError::MappingVerificationFailed);
        }
        let checkpoint_procfd = retained_descriptor_path(&descriptor)?;
        let mapping = MappingIdentity {
            checkpoint_procfd,
            device: stat.st_dev,
            inode: stat.st_ino,
            rdev: stat.st_rdev,
            descriptor,
            major,
            minor,
            backing_major: backing.0,
            backing_minor: backing.1,
            capacity_sectors: block_identity.sector_count,
            logical_sector_bytes: block_identity.logical_sector_bytes,
        };
        mapping.revalidate(device, mapper, header)?;
        Ok(mapping)
    }

    fn verify_failed_open_absence(
        &mut self,
        device: &BlockDevice,
        mapper: &MapperName,
        mapper_path: &Path,
    ) -> Result<(), VaultMountManagerError> {
        Self::verify_mapping_absence(device, mapper, mapper_path)
    }

    fn arm_deferred_mapping_removal(
        &mut self,
        mapper: &MapperName,
    ) -> Result<(), VaultMountManagerError> {
        Self::run_quiet(cryptsetup_deferred_close_command(mapper))
    }

    fn verify_deferred_mapping_removal(
        &mut self,
        device: &BlockDevice,
        mapper: &MapperName,
        header: HeaderIdentity,
        expected: &MappingIdentity,
    ) -> Result<(), VaultMountManagerError> {
        expected.revalidate(device, mapper, header)
    }

    fn verify_closed_mapping_absence(
        &mut self,
        device: &BlockDevice,
        mapper: &MapperName,
        mapper_path: &Path,
    ) -> Result<(), VaultMountManagerError> {
        Self::verify_mapping_absence(device, mapper, mapper_path)
    }

    fn wait_for_deferred_mapping_absence(
        &mut self,
        device: &BlockDevice,
        mapper: &MapperName,
        mapper_path: &Path,
    ) -> Result<(), VaultMountManagerError> {
        Self::wait_for_mapping_absence(device, mapper, mapper_path)
    }

    #[cfg(feature = "experimental-firstboot-provisioner")]
    fn format_filesystem(
        &mut self,
        device: &BlockDevice,
        mapper: &MapperName,
        mapping: &MappingIdentity,
        header: HeaderIdentity,
        filesystem_uuid: [u8; 36],
    ) -> Result<(), VaultMountManagerError> {
        format_ext4_profile_v1(device, mapper, mapping, header, filesystem_uuid)
    }

    fn inspect_filesystem(
        &mut self,
        device: &BlockDevice,
        mapper: &MapperName,
        mapping: &MappingIdentity,
        header: HeaderIdentity,
    ) -> Result<Ext4ProfileEvidence, VaultMountManagerError> {
        mapping.revalidate(device, mapper, header)?;
        let child_stdin = bounded_process::duplicate_child_stdin(&mapping.descriptor)
            .map_err(map_bounded_process_error)?;
        let mut blkid = Command::new(BLKID_PATH);
        blkid
            .arg("--probe")
            .arg("--cache-file")
            .arg("/dev/null")
            .arg("--no-encoding")
            .arg("--output")
            .arg("export")
            .arg("--match-tag")
            .arg("TYPE")
            .arg("--match-tag")
            .arg("UUID")
            .arg("--match-tag")
            .arg("LABEL")
            .arg(bounded_process::CHILD_STDIN_PATH);
        let output =
            Self::run_capture_with_stdin(blkid, child_stdin).map_err(map_blkid_probe_error)?;
        let properties = parse_blkid_export(&output)?;
        let evidence = with_profile_revalidation(
            |checkpoint| qualify_ext4_mapper(&mapping.descriptor, checkpoint),
            || mapping.revalidate(device, mapper, header),
        )?
        .ok_or(VaultMountManagerError::ProfileMismatch)?;
        if properties.kind.as_deref() != Some(b"ext4")
            || properties.label.as_deref() != Some(VAULT_LABEL)
            || properties.uuid != Some(evidence.uuid_ascii())
        {
            return Err(VaultMountManagerError::UnsupportedFilesystem);
        }
        mapping.revalidate(device, mapper, header)?;
        Ok(evidence)
    }

    fn prepare_mount_root(&mut self, root: &Path) -> Result<(), VaultMountManagerError> {
        prepare_runtime_mount_root(root)
    }

    fn pre_mount_revalidate(
        &mut self,
        device: &BlockDevice,
        mapper: &MapperName,
        mapping: &MappingIdentity,
        header: HeaderIdentity,
    ) -> Result<(), VaultMountManagerError> {
        mapping.revalidate(device, mapper, header)
    }

    fn mount_ext4(
        &mut self,
        _device: &BlockDevice,
        _mapper: &MapperName,
        mapping: &MappingIdentity,
        _header: HeaderIdentity,
        root: &Path,
    ) -> Result<(), VaultMountManagerError> {
        rustix::mount::mount(
            &mapping.checkpoint_procfd,
            root,
            "ext4",
            MountFlags::NOSUID
                | MountFlags::NODEV
                | MountFlags::NOEXEC
                | MountFlags::NOSYMFOLLOW
                | MountFlags::RELATIME,
            Some(c"errors=remount-ro"),
        )
        .map_err(|_| VaultMountManagerError::MountFailed)
    }

    fn verify_mounted_filesystem(
        &mut self,
        device: &BlockDevice,
        mapper: &MapperName,
        mapping: &MappingIdentity,
        header: HeaderIdentity,
        expected: Ext4ProfileEvidence,
    ) -> Result<(), VaultMountManagerError> {
        mapping.revalidate(device, mapper, header)?;
        let exact = with_profile_revalidation(
            |checkpoint| revalidate_mounted_ext4_mapper(&mapping.descriptor, expected, checkpoint),
            || mapping.revalidate(device, mapper, header),
        )?;
        if !exact {
            return Err(VaultMountManagerError::ProfileMismatch);
        }
        Ok(())
    }

    fn attest_mount(
        &mut self,
        request: &ResolvedRequest,
        header: HeaderIdentity,
        mapping: &MappingIdentity,
    ) -> Result<VaultMountAttestation, VaultMountManagerError> {
        with_mount_attestation_revalidation(
            || {
                request.device.revalidate()?;
                mapping.revalidate(&request.device, &request.mapper, header)
            },
            || {
                linux::mint_managed_mount_attestation(
                    &request.mount_root,
                    request.mapper.as_fixed_bytes(),
                    header.uuid,
                    mapping.major,
                    mapping.minor,
                    mapping.backing_major,
                    mapping.backing_minor,
                    #[cfg(feature = "experimental-repair-store")]
                    request.device.repair_physical_parent_claims(),
                )
                .map_err(|_| VaultMountManagerError::MountVerificationFailed)
            },
        )
    }

    fn verify_cleanup_mount(
        &mut self,
        request: &ResolvedRequest,
        header: HeaderIdentity,
        mapping: &MappingIdentity,
        attestation: Option<&VaultMountAttestation>,
    ) -> Result<(), VaultMountManagerError> {
        mapping
            .revalidate(&request.device, &request.mapper, header)
            .map_err(|_| VaultMountManagerError::CleanupFailed)?;
        let current = linux::mint_managed_mount_attestation(
            &request.mount_root,
            request.mapper.as_fixed_bytes(),
            header.uuid,
            mapping.major,
            mapping.minor,
            mapping.backing_major,
            mapping.backing_minor,
            #[cfg(feature = "experimental-repair-store")]
            request.device.repair_physical_parent_claims(),
        )
        .map_err(|_| VaultMountManagerError::CleanupFailed)?;
        mapping
            .revalidate(&request.device, &request.mapper, header)
            .map_err(|_| VaultMountManagerError::CleanupFailed)?;
        if let Some(attestation) = attestation {
            if current.claims != attestation.claims {
                return Err(VaultMountManagerError::CleanupFailed);
            }
        }
        Ok(())
    }

    fn unmount(&mut self, root: &Path) -> Result<(), VaultMountManagerError> {
        rustix::mount::unmount(root, UnmountFlags::NOFOLLOW)
            .map_err(|_| VaultMountManagerError::CleanupFailed)
    }

    fn verify_unmounted(
        &mut self,
        request: &ResolvedRequest,
        header: HeaderIdentity,
        mapping: &MappingIdentity,
    ) -> Result<(), VaultMountManagerError> {
        mapping
            .revalidate(&request.device, &request.mapper, header)
            .map_err(|_| VaultMountManagerError::CleanupFailed)?;
        linux::verify_managed_mount_absent(&request.mount_root, mapping.major, mapping.minor)
            .map_err(|_| VaultMountManagerError::CleanupFailed)?;
        mapping
            .revalidate(&request.device, &request.mapper, header)
            .map_err(|_| VaultMountManagerError::CleanupFailed)?;
        linux::verify_managed_mount_absent(&request.mount_root, mapping.major, mapping.minor)
            .map_err(|_| VaultMountManagerError::CleanupFailed)
    }

    fn verify_cleanup_mapping(
        &mut self,
        device: &BlockDevice,
        mapper: &MapperName,
        mapper_path: &Path,
        header: HeaderIdentity,
        expected: &MappingIdentity,
    ) -> Result<(), VaultMountManagerError> {
        let _ = mapper_path;
        expected
            .revalidate(device, mapper, header)
            .map_err(|_| VaultMountManagerError::CleanupFailed)
    }

    fn close_mapping(&mut self, mapper: &MapperName) -> Result<(), VaultMountManagerError> {
        let mut command = Command::new(CRYPTSETUP_PATH);
        command.arg("close").arg(mapper.as_os_str());
        Self::run_quiet(command)
    }
}

#[cfg(feature = "experimental-firstboot-provisioner")]
struct VerifiedUnprovisioned;

#[cfg(feature = "experimental-firstboot-provisioner")]
fn require_unprovisioned(
    device: &BlockDevice,
) -> Result<VerifiedUnprovisioned, VaultMountManagerError> {
    device.revalidate()?;
    let profile = classify_partition(&device.descriptor, || {
        device.revalidate_profile_capability()
    })
    .map_err(map_profile_classifier_error)?;
    device.revalidate()?;
    match profile {
        VaultPartitionProfile::Unprovisioned => Ok(VerifiedUnprovisioned),
        VaultPartitionProfile::Locked(_) | VaultPartitionProfile::ProfileMismatch => {
            Err(VaultMountManagerError::ProfileMismatch)
        }
    }
}

#[cfg(feature = "experimental-firstboot-provisioner")]
fn format_luks_profile_v1(
    device: &BlockDevice,
    _unprovisioned: VerifiedUnprovisioned,
    passphrase: &[u8],
    luks_uuid: [u8; 36],
) -> Result<(), VaultMountManagerError> {
    device.revalidate()?;
    let inherited = bounded_process::InheritedChildDescriptor::duplicate(&device.descriptor)
        .map_err(map_bounded_process_error)?;
    let key = secret_pipe(passphrase)?;
    let key_size = passphrase.len().to_string();
    let mut command =
        cryptsetup_format_command(inherited.path(), OsStr::from_bytes(&luks_uuid), &key_size);
    command
        .env_clear()
        .env("LC_ALL", "C")
        .stdin(Stdio::from(File::from(key)))
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    let status = bounded_process::wait_with_descriptor(
        &mut command,
        PROVISIONING_COMMAND_TIMEOUT,
        inherited,
    )
    .map_err(map_bounded_process_error)?;
    if !status.success() {
        return Err(VaultMountManagerError::ProvisioningFormatFailed);
    }
    rfs::fsync(&device.descriptor).map_err(|_| VaultMountManagerError::ProvisioningFormatFailed)?;
    device.revalidate()
}

#[cfg(feature = "experimental-firstboot-provisioner")]
fn format_ext4_profile_v1(
    device: &BlockDevice,
    mapper: &MapperName,
    mapping: &MappingIdentity,
    header: HeaderIdentity,
    filesystem_uuid: [u8; 36],
) -> Result<(), VaultMountManagerError> {
    mapping.revalidate(device, mapper, header)?;
    let inherited = bounded_process::InheritedChildDescriptor::duplicate(&mapping.descriptor)
        .map_err(map_bounded_process_error)?;
    let mut mkfs = mkfs_ext4_command(inherited.path(), OsStr::from_bytes(&filesystem_uuid));
    mkfs.env_clear()
        .env("LC_ALL", "C")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    let status =
        bounded_process::wait_with_descriptor(&mut mkfs, PROVISIONING_COMMAND_TIMEOUT, inherited)
            .map_err(map_bounded_process_error)?;
    if !status.success() {
        return Err(VaultMountManagerError::ProvisioningFormatFailed);
    }
    mapping.revalidate(device, mapper, header)?;
    let inherited = bounded_process::InheritedChildDescriptor::duplicate(&mapping.descriptor)
        .map_err(map_bounded_process_error)?;
    let mut tune = tune2fs_command(inherited.path());
    tune.env_clear()
        .env("LC_ALL", "C")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    let status =
        bounded_process::wait_with_descriptor(&mut tune, PROVISIONING_COMMAND_TIMEOUT, inherited)
            .map_err(map_bounded_process_error)?;
    if !status.success() {
        return Err(VaultMountManagerError::ProvisioningFormatFailed);
    }
    rfs::fsync(&mapping.descriptor)
        .map_err(|_| VaultMountManagerError::ProvisioningFormatFailed)?;
    mapping.revalidate(device, mapper, header)
}

#[cfg(feature = "experimental-firstboot-provisioner")]
fn initialize_firstboot_secure_state(
    activation: &mut Activation<SystemOps>,
    filesystem_uuid: [u8; 36],
) -> Result<InitializedSecureStateEvidence, VaultMountManagerError> {
    let observed_filesystem = revalidate_firstboot_filesystem(activation, filesystem_uuid)?;
    let mapping = activation
        .mapping
        .as_ref()
        .ok_or(VaultMountManagerError::MappingVerificationFailed)?;
    let attestation = activation
        .attestation
        .as_ref()
        .ok_or(VaultMountManagerError::MountVerificationFailed)?;
    create_firstboot_vault_skeleton(&activation.request.mount_root, mapping)?;
    activation.ops.verify_mounted_filesystem(
        &activation.request.device,
        &activation.request.mapper,
        mapping,
        activation.header,
        observed_filesystem,
    )?;

    let secrets = RescueVaultSecrets::open(&activation.request.mount_root, attestation)
        .map_err(|_| VaultMountManagerError::ProvisioningInitializationFailed)?;
    let mut journal = secrets
        .open_journal()
        .map_err(|_| VaultMountManagerError::ProvisioningInitializationFailed)?;
    if !journal
        .entries()
        .map_err(|_| VaultMountManagerError::ProvisioningInitializationFailed)?
        .is_empty()
    {
        return Err(VaultMountManagerError::ProvisioningInitializationFailed);
    }
    drop(journal);
    let mut identities = secrets.device_identity_store();
    if identities
        .load_device_identity()
        .map_err(|_| VaultMountManagerError::ProvisioningInitializationFailed)?
        .is_some()
    {
        return Err(VaultMountManagerError::ProvisioningInitializationFailed);
    }
    let identity = identities
        .create_device_identity()
        .map_err(|_| VaultMountManagerError::ProvisioningInitializationFailed)?;
    let application = secrets
        .open_application_store()
        .map_err(|_| VaultMountManagerError::ProvisioningInitializationFailed)?;
    let device_id = identity.device_id();
    if application.device_id() != device_id {
        return Err(VaultMountManagerError::ProvisioningInitializationFailed);
    }
    let identity_public_key = identity.public_key();
    drop(application);
    drop(secrets);
    mapping.revalidate(
        &activation.request.device,
        &activation.request.mapper,
        activation.header,
    )?;
    Ok(InitializedSecureStateEvidence {
        device_id,
        identity_public_key,
    })
}

#[cfg(feature = "experimental-firstboot-provisioner")]
fn revalidate_firstboot_filesystem<R: VaultOps>(
    activation: &mut Activation<R>,
    filesystem_uuid: [u8; 36],
) -> Result<Ext4ProfileEvidence, VaultMountManagerError> {
    // `inspect_filesystem` deliberately applies the pre-mount ext4 profile.
    // Reusing it after `Activation::continue_start` mounted the vault would
    // reject the kernel's valid mounted-state runtime bits.  Retain the exact
    // pre-mount evidence and revalidate it only with the mounted classifier.
    let observed = activation
        .mounted_filesystem_profile
        .ok_or(VaultMountManagerError::MountVerificationFailed)?;
    if observed.uuid_ascii() != filesystem_uuid {
        return Err(VaultMountManagerError::ProfileMismatch);
    }
    let mapping = activation
        .mapping
        .as_ref()
        .ok_or(VaultMountManagerError::MappingVerificationFailed)?;
    activation.ops.verify_mounted_filesystem(
        &activation.request.device,
        &activation.request.mapper,
        mapping,
        activation.header,
        observed,
    )?;
    Ok(observed)
}

#[cfg(feature = "experimental-firstboot-provisioner")]
fn create_firstboot_vault_skeleton(
    root: &Path,
    mapping: &MappingIdentity,
) -> Result<(), VaultMountManagerError> {
    let root_fd = rfs::openat2(
        CWD,
        root,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
        ResolveFlags::NO_SYMLINKS | ResolveFlags::NO_MAGICLINKS,
    )
    .map_err(|_| VaultMountManagerError::ProvisioningInitializationFailed)?;
    rfs::fchmod(&root_fd, Mode::from_raw_mode(SECURE_DIRECTORY_MODE))
        .map_err(|_| VaultMountManagerError::ProvisioningInitializationFailed)?;
    validate_firstboot_directory(&root_fd, mapping, SECURE_DIRECTORY_MODE)?;
    require_fresh_ext4_root(&root_fd, mapping)?;

    rfs::mkdirat(
        &root_fd,
        STATE_DIRECTORY_NAME,
        Mode::from_raw_mode(SECURE_DIRECTORY_MODE),
    )
    .map_err(|_| VaultMountManagerError::ProvisioningInitializationFailed)?;
    let state = open_firstboot_child_directory(&root_fd, STATE_DIRECTORY_NAME)?;
    validate_firstboot_directory(&state, mapping, SECURE_DIRECTORY_MODE)?;
    rfs::fsync(&state).map_err(|_| VaultMountManagerError::ProvisioningInitializationFailed)?;
    create_firstboot_file(&root_fd, VAULT_LOCK_NAME, b"", mapping)?;
    create_firstboot_codex_home(&root_fd, mapping)?;
    // The marker is installed last and is the completion sentinel for the
    // complete structural skeleton. Identity/journal creation remains a later
    // typed transaction and is verified before this lifecycle may report
    // success.
    create_firstboot_file(&root_fd, VAULT_MARKER_NAME, VAULT_MARKER_V1, mapping)?;
    rfs::fsync(&root_fd).map_err(|_| VaultMountManagerError::ProvisioningInitializationFailed)?;
    validate_firstboot_directory(&root_fd, mapping, SECURE_DIRECTORY_MODE)
}

#[cfg(feature = "experimental-firstboot-provisioner")]
fn create_firstboot_codex_home(
    root: &OwnedFd,
    mapping: &MappingIdentity,
) -> Result<(), VaultMountManagerError> {
    create_firstboot_codex_home_for(
        root,
        mapping,
        crate::CODEX_AGENT_UID,
        crate::CODEX_AGENT_GID,
    )
}

#[cfg(feature = "experimental-firstboot-provisioner")]
fn create_firstboot_codex_home_for(
    root: &OwnedFd,
    mapping: &MappingIdentity,
    owner: u32,
    group: u32,
) -> Result<(), VaultMountManagerError> {
    rfs::mkdirat(
        root,
        crate::CODEX_HOME_NAME,
        Mode::from_raw_mode(SECURE_DIRECTORY_MODE),
    )
    .map_err(|_| VaultMountManagerError::ProvisioningInitializationFailed)?;
    let home = open_firstboot_child_directory(root, crate::CODEX_HOME_NAME)?;
    rfs::fchmod(&home, Mode::from_raw_mode(SECURE_DIRECTORY_MODE))
        .map_err(|_| VaultMountManagerError::ProvisioningInitializationFailed)?;

    // Keep the new directory root-owned while its sole file is created. The
    // shipping service intentionally has CAP_CHOWN but not CAP_DAC_OVERRIDE or
    // CAP_FOWNER, so ownership of the 0700 directory is transferred last.
    create_firstboot_owned_file(
        &home,
        crate::CODEX_CONFIG_NAME,
        crate::CODEX_CONFIG_V1,
        mapping,
        owner,
        group,
    )?;
    rfs::fsync(&home).map_err(|_| VaultMountManagerError::ProvisioningInitializationFailed)?;
    rfs::fchown(
        &home,
        Some(rustix::fs::Uid::from_raw(owner)),
        Some(rustix::fs::Gid::from_raw(group)),
    )
    .map_err(|_| VaultMountManagerError::ProvisioningInitializationFailed)?;
    rfs::fsync(&home).map_err(|_| VaultMountManagerError::ProvisioningInitializationFailed)?;

    validate_firstboot_directory_owner(&home, mapping, SECURE_DIRECTORY_MODE, owner, group)?;
    let named = rfs::statat(root, crate::CODEX_HOME_NAME, AtFlags::SYMLINK_NOFOLLOW)
        .map_err(|_| VaultMountManagerError::ProvisioningInitializationFailed)?;
    let opened =
        rfs::fstat(&home).map_err(|_| VaultMountManagerError::ProvisioningInitializationFailed)?;
    if opened.st_dev != named.st_dev
        || opened.st_ino != named.st_ino
        || opened.st_mode != named.st_mode
        || opened.st_uid != named.st_uid
        || opened.st_gid != named.st_gid
    {
        return Err(VaultMountManagerError::ProvisioningInitializationFailed);
    }
    Ok(())
}

#[cfg(feature = "experimental-firstboot-provisioner")]
fn require_fresh_ext4_root(
    root: &OwnedFd,
    mapping: &MappingIdentity,
) -> Result<(), VaultMountManagerError> {
    let scan = rfs::openat2(
        root,
        ".",
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC,
        Mode::empty(),
        ResolveFlags::BENEATH
            | ResolveFlags::NO_SYMLINKS
            | ResolveFlags::NO_MAGICLINKS
            | ResolveFlags::NO_XDEV,
    )
    .map_err(|_| VaultMountManagerError::ProvisioningInitializationFailed)?;
    let mut buffer = [MaybeUninit::<u8>::uninit(); FIRSTBOOT_SCAN_BUFFER_BYTES];
    let mut entries = RawDir::new(&scan, &mut buffer);
    let mut saw_lost_found = false;
    while let Some(entry) = entries.next() {
        let entry = entry.map_err(|_| VaultMountManagerError::ProvisioningInitializationFailed)?;
        let name = entry.file_name().to_bytes();
        if name == b"." || name == b".." {
            continue;
        }
        if name != b"lost+found" || saw_lost_found {
            return Err(VaultMountManagerError::ProvisioningInitializationFailed);
        }
        saw_lost_found = true;
        let lost = rfs::statat(root, "lost+found", AtFlags::SYMLINK_NOFOLLOW)
            .map_err(|_| VaultMountManagerError::ProvisioningInitializationFailed)?;
        if !FileType::from_raw_mode(lost.st_mode).is_dir()
            || lost.st_uid != 0
            || lost.st_gid != 0
            || lost.st_dev != rfs::makedev(mapping.major, mapping.minor)
        {
            return Err(VaultMountManagerError::ProvisioningInitializationFailed);
        }
    }
    Ok(())
}

#[cfg(feature = "experimental-firstboot-provisioner")]
fn open_firstboot_child_directory(
    root: &OwnedFd,
    name: &str,
) -> Result<OwnedFd, VaultMountManagerError> {
    rfs::openat2(
        root,
        name,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
        ResolveFlags::BENEATH
            | ResolveFlags::NO_SYMLINKS
            | ResolveFlags::NO_MAGICLINKS
            | ResolveFlags::NO_XDEV,
    )
    .map_err(|_| VaultMountManagerError::ProvisioningInitializationFailed)
}

#[cfg(feature = "experimental-firstboot-provisioner")]
fn validate_firstboot_directory(
    descriptor: &OwnedFd,
    mapping: &MappingIdentity,
    mode: u32,
) -> Result<(), VaultMountManagerError> {
    validate_firstboot_directory_owner(descriptor, mapping, mode, 0, 0)
}

#[cfg(feature = "experimental-firstboot-provisioner")]
fn validate_firstboot_directory_owner(
    descriptor: &OwnedFd,
    mapping: &MappingIdentity,
    mode: u32,
    owner: u32,
    group: u32,
) -> Result<(), VaultMountManagerError> {
    let stat = rfs::fstat(descriptor)
        .map_err(|_| VaultMountManagerError::ProvisioningInitializationFailed)?;
    let flags = rustix::io::fcntl_getfd(descriptor)
        .map_err(|_| VaultMountManagerError::ProvisioningInitializationFailed)?;
    if !FileType::from_raw_mode(stat.st_mode).is_dir()
        || stat.st_dev != rfs::makedev(mapping.major, mapping.minor)
        || stat.st_uid != owner
        || stat.st_gid != group
        || stat.st_mode & 0o7777 != mode
        || !flags.contains(rustix::io::FdFlags::CLOEXEC)
    {
        return Err(VaultMountManagerError::ProvisioningInitializationFailed);
    }
    Ok(())
}

#[cfg(feature = "experimental-firstboot-provisioner")]
fn create_firstboot_file(
    root: &OwnedFd,
    name: &str,
    bytes: &[u8],
    mapping: &MappingIdentity,
) -> Result<(), VaultMountManagerError> {
    create_firstboot_owned_file(root, name, bytes, mapping, 0, 0)
}

#[cfg(feature = "experimental-firstboot-provisioner")]
fn create_firstboot_owned_file(
    root: &OwnedFd,
    name: &str,
    bytes: &[u8],
    mapping: &MappingIdentity,
    owner: u32,
    group: u32,
) -> Result<(), VaultMountManagerError> {
    let file = rfs::openat2(
        root,
        name,
        OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::from_raw_mode(SECURE_FILE_MODE),
        ResolveFlags::BENEATH
            | ResolveFlags::NO_SYMLINKS
            | ResolveFlags::NO_MAGICLINKS
            | ResolveFlags::NO_XDEV,
    )
    .map_err(|_| VaultMountManagerError::ProvisioningInitializationFailed)?;
    rfs::fchmod(&file, Mode::from_raw_mode(SECURE_FILE_MODE))
        .map_err(|_| VaultMountManagerError::ProvisioningInitializationFailed)?;
    let mut written = 0;
    while written < bytes.len() {
        let count = rustix::io::write(&file, &bytes[written..])
            .map_err(|_| VaultMountManagerError::ProvisioningInitializationFailed)?;
        if count == 0 {
            return Err(VaultMountManagerError::ProvisioningInitializationFailed);
        }
        written += count;
    }
    let created =
        rfs::fstat(&file).map_err(|_| VaultMountManagerError::ProvisioningInitializationFailed)?;
    if created.st_uid != owner || created.st_gid != group {
        rfs::fchown(
            &file,
            Some(rustix::fs::Uid::from_raw(owner)),
            Some(rustix::fs::Gid::from_raw(group)),
        )
        .map_err(|_| VaultMountManagerError::ProvisioningInitializationFailed)?;
    }
    rfs::fsync(&file).map_err(|_| VaultMountManagerError::ProvisioningInitializationFailed)?;
    let opened =
        rfs::fstat(&file).map_err(|_| VaultMountManagerError::ProvisioningInitializationFailed)?;
    let named = rfs::statat(root, name, AtFlags::SYMLINK_NOFOLLOW)
        .map_err(|_| VaultMountManagerError::ProvisioningInitializationFailed)?;
    if !FileType::from_raw_mode(opened.st_mode).is_file()
        || opened.st_dev != rfs::makedev(mapping.major, mapping.minor)
        || opened.st_uid != owner
        || opened.st_gid != group
        || opened.st_nlink != 1
        || opened.st_mode & 0o7777 != SECURE_FILE_MODE
        || opened.st_size != bytes.len() as i64
        || opened.st_dev != named.st_dev
        || opened.st_ino != named.st_ino
        || opened.st_mode != named.st_mode
        || opened.st_uid != named.st_uid
        || opened.st_gid != named.st_gid
        || opened.st_nlink != named.st_nlink
        || opened.st_size != named.st_size
    {
        return Err(VaultMountManagerError::ProvisioningInitializationFailed);
    }
    Ok(())
}

#[cfg(feature = "experimental-firstboot-provisioner")]
fn secret_pipe(secret: &[u8]) -> Result<OwnedFd, VaultMountManagerError> {
    let (read, write) = rustix::pipe::pipe_with(rustix::pipe::PipeFlags::CLOEXEC)
        .map_err(|_| VaultMountManagerError::PassphraseUnavailable)?;
    let mut written = 0;
    while written < secret.len() {
        let count = rustix::io::write(&write, &secret[written..])
            .map_err(|_| VaultMountManagerError::PassphraseUnavailable)?;
        if count == 0 {
            return Err(VaultMountManagerError::PassphraseUnavailable);
        }
        written += count;
    }
    drop(write);
    Ok(read)
}

#[cfg(feature = "experimental-firstboot-provisioner")]
fn random_uuid_v4() -> Result<[u8; 36], VaultMountManagerError> {
    let mut bytes = [0_u8; 16];
    OsRng
        .try_fill_bytes(&mut bytes)
        .map_err(|_| VaultMountManagerError::ProvisioningInitializationFailed)?;
    bytes[6] = (bytes[6] & 0x0f) | 0x40;
    bytes[8] = (bytes[8] & 0x3f) | 0x80;
    Ok(render_uuid(bytes))
}

#[cfg(feature = "experimental-firstboot-provisioner")]
fn render_uuid(bytes: [u8; 16]) -> [u8; 36] {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut rendered = [0_u8; 36];
    let mut input = 0;
    for (output, byte) in rendered.iter_mut().enumerate() {
        if matches!(output, 8 | 13 | 18 | 23) {
            *byte = b'-';
        } else {
            let value = bytes[input / 2];
            *byte = HEX[usize::from(if input % 2 == 0 {
                value >> 4
            } else {
                value & 0x0f
            })];
            input += 1;
        }
    }
    rendered
}

#[cfg(feature = "experimental-firstboot-provisioner")]
fn random_firstboot_mapper() -> Result<MapperName, VaultMountManagerError> {
    let mut random = [0_u8; 8];
    OsRng
        .try_fill_bytes(&mut random)
        .map_err(|_| VaultMountManagerError::ProvisioningInitializationFailed)?;
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut name = [0_u8; MAPPER_NAME_BYTES];
    name[..MAPPER_PREFIX.len()].copy_from_slice(MAPPER_PREFIX.as_bytes());
    for (index, value) in random.iter().copied().enumerate() {
        name[MAPPER_PREFIX.len() + index * 2] = HEX[usize::from(value >> 4)];
        name[MAPPER_PREFIX.len() + index * 2 + 1] = HEX[usize::from(value & 0x0f)];
    }
    Ok(MapperName { bytes: name })
}

#[cfg(feature = "experimental-firstboot-provisioner")]
fn cryptsetup_format_command(device: &Path, luks_uuid: &OsStr, key_size: &str) -> Command {
    let mut command = Command::new(CRYPTSETUP_PATH);
    command
        .arg("luksFormat")
        .arg("--type")
        .arg("luks2")
        .arg("--batch-mode")
        .arg("--label")
        .arg("KERNAID_VAULT")
        .arg("--uuid")
        .arg(luks_uuid)
        .arg("--cipher")
        .arg("aes-xts-plain64")
        .arg("--key-size")
        .arg("512")
        .arg("--hash")
        .arg("sha256")
        .arg("--sector-size")
        .arg("512")
        .arg("--pbkdf")
        .arg("argon2id")
        .arg("--pbkdf-force-iterations")
        .arg("4")
        .arg("--pbkdf-memory")
        .arg("65536")
        .arg("--pbkdf-parallel")
        .arg("1")
        .arg("--key-slot")
        .arg("0")
        .arg("--keyslot-cipher")
        .arg("aes-xts-plain64")
        .arg("--keyslot-key-size")
        .arg("512")
        .arg("--luks2-metadata-size")
        .arg("16384")
        .arg("--luks2-keyslots-size")
        .arg("16744448")
        .arg("--use-urandom")
        .arg("--key-file")
        .arg("-")
        .arg("--keyfile-size")
        .arg(key_size)
        .arg(device);
    command
}

#[cfg(feature = "experimental-firstboot-provisioner")]
fn mkfs_ext4_command(device: &Path, filesystem_uuid: &OsStr) -> Command {
    let mut command = Command::new(MKFS_EXT4_PATH);
    command
        .arg("-q")
        .arg("-F")
        .arg("-t")
        .arg("ext4")
        .arg("-b")
        .arg("4096")
        .arg("-I")
        .arg("256")
        .arg("-i")
        .arg("16384")
        .arg("-g")
        .arg("32768")
        .arg("-G")
        .arg("16")
        .arg("-m")
        .arg("0")
        .arg("-o")
        .arg("linux")
        .arg("-e")
        .arg("remount-ro")
        .arg("-J")
        .arg("size=128")
        .arg("-E")
        .arg("lazy_itable_init=0,lazy_journal_init=0")
        .arg("-O")
        .arg("none,has_journal,ext_attr,resize_inode,dir_index,filetype,extent,64bit,flex_bg,sparse_super,large_file,huge_file,dir_nlink,extra_isize,metadata_csum")
        .arg("-L")
        .arg("KERNAID_VAULT")
        .arg("-U")
        .arg(filesystem_uuid)
        .arg("-M")
        .arg("/")
        .arg(device);
    command
}

#[cfg(feature = "experimental-firstboot-provisioner")]
fn tune2fs_command(device: &Path) -> Command {
    let mut command = Command::new(TUNE2FS_PATH);
    command
        .arg("-c")
        .arg("0")
        .arg("-i")
        .arg("0")
        .arg("-e")
        .arg("remount-ro")
        .arg("-m")
        .arg("0")
        .arg("-o")
        .arg("^acl,^user_xattr")
        .arg("-M")
        .arg("/")
        .arg(device);
    command
}

fn cryptsetup_open_command(device: &Path, mapper: &MapperName) -> Command {
    let mut command = Command::new(CRYPTSETUP_PATH);
    command
        .arg("open")
        .arg("--type")
        .arg("luks2")
        .arg("--batch-mode")
        .arg("--tries")
        .arg("1")
        .arg("--disable-external-tokens")
        .arg("--key-file")
        .arg("-")
        .arg(device)
        .arg(mapper.as_os_str());
    command
}

#[cfg(feature = "experimental-firstboot-provisioner")]
fn cryptsetup_open_sized_command(device: &Path, mapper: &MapperName, key_size: &str) -> Command {
    let mut command = Command::new(CRYPTSETUP_PATH);
    command
        .arg("open")
        .arg("--type")
        .arg("luks2")
        .arg("--batch-mode")
        .arg("--tries")
        .arg("1")
        .arg("--disable-external-tokens")
        .arg("--key-file")
        .arg("-")
        .arg("--keyfile-size")
        .arg(key_size)
        .arg(device)
        .arg(mapper.as_os_str());
    command
}

fn cryptsetup_deferred_close_command(mapper: &MapperName) -> Command {
    let mut command = Command::new(CRYPTSETUP_PATH);
    command
        .arg("close")
        .arg("--deferred")
        .arg(mapper.as_os_str());
    command
}

fn validate_device_path(path: &Path) -> Result<PathBuf, VaultMountManagerError> {
    if !path.is_absolute() {
        return Err(VaultMountManagerError::InvalidBlockDevice);
    }
    let components: Vec<_> = path.components().collect();
    let [
        Component::RootDir,
        Component::Normal(dev),
        Component::Normal(node),
    ] = components.as_slice()
    else {
        return Err(VaultMountManagerError::InvalidBlockDevice);
    };
    let normalized = PathBuf::from("/dev").join(*node);
    let node = node.as_bytes();
    if *dev != OsStr::new("dev")
        || node.is_empty()
        || node.len() > 64
        || node.starts_with(b"dm-")
        || path.as_os_str().as_bytes() != normalized.as_os_str().as_bytes()
        || !node
            .iter()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'+' | b'-' | b'_' | b'.'))
    {
        return Err(VaultMountManagerError::InvalidBlockDevice);
    }
    Ok(path.to_path_buf())
}

fn acquire_manager_lock() -> Result<OwnedFd, VaultMountManagerError> {
    let create_flags =
        OFlags::RDWR | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW | OFlags::CLOEXEC;
    let (descriptor, created) = match rfs::openat2(
        CWD,
        MANAGER_LOCK_PATH,
        create_flags,
        Mode::RUSR | Mode::WUSR,
        ResolveFlags::NO_SYMLINKS | ResolveFlags::NO_MAGICLINKS,
    ) {
        Ok(descriptor) => (descriptor, true),
        Err(error) if error == rustix::io::Errno::EXIST => (
            rfs::openat2(
                CWD,
                MANAGER_LOCK_PATH,
                OFlags::RDWR | OFlags::NOFOLLOW | OFlags::CLOEXEC,
                Mode::empty(),
                ResolveFlags::NO_SYMLINKS | ResolveFlags::NO_MAGICLINKS,
            )
            .map_err(|_| VaultMountManagerError::ManagerLocked)?,
            false,
        ),
        Err(_) => return Err(VaultMountManagerError::ManagerLocked),
    };
    if created {
        rfs::fchmod(&descriptor, Mode::RUSR | Mode::WUSR)
            .map_err(|_| VaultMountManagerError::ManagerLocked)?;
    }
    let stat = rfs::fstat(&descriptor).map_err(|_| VaultMountManagerError::ManagerLocked)?;
    if !FileType::from_raw_mode(stat.st_mode).is_file()
        || stat.st_uid != 0
        || stat.st_gid != 0
        || stat.st_nlink != 1
        || stat.st_mode & 0o7777 != SECURE_FILE_MODE
    {
        return Err(VaultMountManagerError::ManagerLocked);
    }
    rfs::flock(&descriptor, FlockOperation::NonBlockingLockExclusive)
        .map_err(|_| VaultMountManagerError::ManagerLocked)?;
    Ok(descriptor)
}

fn prepare_runtime_mount_root(root: &Path) -> Result<(), VaultMountManagerError> {
    if root.parent().and_then(Path::parent) != Some(Path::new(RUNTIME_ROOT))
        || root.file_name().is_none()
    {
        return Err(VaultMountManagerError::UnsafeMountRoot);
    }
    let run = open_secure_directory(Path::new("/run"), false)?;
    let runtime = open_or_create_runtime_root(&run)?;
    let mount_parent = open_or_create_child_directory(&runtime, OsStr::new(VAULT_MOUNT_PARENT))?;
    let name = root
        .file_name()
        .ok_or(VaultMountManagerError::UnsafeMountRoot)?;
    let mount = open_or_create_child_directory(&mount_parent, name)?;
    if descriptor_mount_id(&mount)? != descriptor_mount_id(&mount_parent)? {
        return Err(VaultMountManagerError::UnsafeMountRoot);
    }
    let mut entries = fs::read_dir(root).map_err(|_| VaultMountManagerError::UnsafeMountRoot)?;
    if entries.next().is_some() {
        return Err(VaultMountManagerError::UnsafeMountRoot);
    }
    Ok(())
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct DirectoryIdentity {
    device: u64,
    inode: u64,
    mode: u32,
    uid: u32,
    gid: u32,
}

impl DirectoryIdentity {
    const fn from_stat(stat: &Stat) -> Self {
        Self {
            device: stat.st_dev,
            inode: stat.st_ino,
            mode: stat.st_mode,
            uid: stat.st_uid,
            gid: stat.st_gid,
        }
    }
}

fn open_or_create_runtime_root(run: &OwnedFd) -> Result<OwnedFd, VaultMountManagerError> {
    // `ProtectSystem=strict` plus the service's exact `ReadWritePaths` entry
    // exposes `/run/kernaid` as a self-bind mount. Cross only that literal
    // boundary, then bind the retained descriptor back to the named endpoint
    // and `/run`'s tmpfs before restoring NO_XDEV for every child lookup.
    let run_before = DirectoryIdentity::from_stat(
        &rfs::fstat(run).map_err(|_| VaultMountManagerError::UnsafeMountRoot)?,
    );
    let run_fs_before = rfs::fstatfs(run).map_err(|_| VaultMountManagerError::UnsafeMountRoot)?;
    if u64::try_from(run_fs_before.f_type).ok() != Some(TMPFS_MAGIC) {
        return Err(VaultMountManagerError::UnsafeMountRoot);
    }
    let created = match rfs::mkdirat(run, RUNTIME_ROOT_NAME, Mode::RUSR | Mode::WUSR | Mode::XUSR) {
        Ok(()) => true,
        Err(error) if error == rustix::io::Errno::EXIST => false,
        Err(_) => return Err(VaultMountManagerError::UnsafeMountRoot),
    };
    let descriptor = rfs::openat2(
        run,
        RUNTIME_ROOT_NAME,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
        ResolveFlags::BENEATH | ResolveFlags::NO_SYMLINKS | ResolveFlags::NO_MAGICLINKS,
    )
    .map_err(|_| VaultMountManagerError::UnsafeMountRoot)?;
    if created {
        rfs::fchmod(&descriptor, Mode::RUSR | Mode::WUSR | Mode::XUSR)
            .map_err(|_| VaultMountManagerError::UnsafeMountRoot)?;
        rfs::fsync(&descriptor).map_err(|_| VaultMountManagerError::UnsafeMountRoot)?;
        rfs::fsync(run).map_err(|_| VaultMountManagerError::UnsafeMountRoot)?;
    }
    validate_root_directory(&descriptor, true)?;

    let opened = rfs::fstat(&descriptor).map_err(|_| VaultMountManagerError::UnsafeMountRoot)?;
    let named = rfs::statat(run, RUNTIME_ROOT_NAME, AtFlags::SYMLINK_NOFOLLOW)
        .map_err(|_| VaultMountManagerError::UnsafeMountRoot)?;
    let run_stat = DirectoryIdentity::from_stat(
        &rfs::fstat(run).map_err(|_| VaultMountManagerError::UnsafeMountRoot)?,
    );
    let opened_fs =
        rfs::fstatfs(&descriptor).map_err(|_| VaultMountManagerError::UnsafeMountRoot)?;
    let run_fs = rfs::fstatfs(run).map_err(|_| VaultMountManagerError::UnsafeMountRoot)?;
    if run_stat != run_before
        || !runtime_root_mount_is_exact(
            DirectoryIdentity::from_stat(&opened),
            DirectoryIdentity::from_stat(&named),
            run_stat.device,
            u64::try_from(opened_fs.f_type).ok(),
            u64::try_from(run_fs.f_type).ok(),
        )
    {
        return Err(VaultMountManagerError::UnsafeMountRoot);
    }
    Ok(descriptor)
}

fn runtime_root_mount_is_exact(
    opened: DirectoryIdentity,
    named: DirectoryIdentity,
    run_device: u64,
    opened_filesystem: Option<u64>,
    run_filesystem: Option<u64>,
) -> bool {
    opened == named
        && FileType::from_raw_mode(opened.mode).is_dir()
        && opened.uid == 0
        && opened.gid == 0
        && opened.mode & 0o7777 == SECURE_DIRECTORY_MODE
        && opened.device == run_device
        && opened_filesystem == Some(TMPFS_MAGIC)
        && run_filesystem == Some(TMPFS_MAGIC)
}

fn open_secure_directory(path: &Path, exact_mode: bool) -> Result<OwnedFd, VaultMountManagerError> {
    let descriptor = rfs::openat2(
        CWD,
        path,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
        ResolveFlags::NO_SYMLINKS | ResolveFlags::NO_MAGICLINKS,
    )
    .map_err(|_| VaultMountManagerError::UnsafeMountRoot)?;
    validate_root_directory(&descriptor, exact_mode)?;
    Ok(descriptor)
}

fn open_or_create_child_directory(
    parent: &OwnedFd,
    name: &OsStr,
) -> Result<OwnedFd, VaultMountManagerError> {
    let created = match rfs::mkdirat(parent, name, Mode::RUSR | Mode::WUSR | Mode::XUSR) {
        Ok(()) => true,
        Err(error) if error == rustix::io::Errno::EXIST => false,
        Err(_) => return Err(VaultMountManagerError::UnsafeMountRoot),
    };
    let descriptor = rfs::openat2(
        parent,
        name,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
        ResolveFlags::BENEATH
            | ResolveFlags::NO_SYMLINKS
            | ResolveFlags::NO_MAGICLINKS
            | ResolveFlags::NO_XDEV,
    )
    .map_err(|_| VaultMountManagerError::UnsafeMountRoot)?;
    if created {
        rfs::fchmod(&descriptor, Mode::RUSR | Mode::WUSR | Mode::XUSR)
            .map_err(|_| VaultMountManagerError::UnsafeMountRoot)?;
        rfs::fsync(&descriptor).map_err(|_| VaultMountManagerError::UnsafeMountRoot)?;
        rfs::fsync(parent).map_err(|_| VaultMountManagerError::UnsafeMountRoot)?;
    }
    validate_root_directory(&descriptor, true)?;
    Ok(descriptor)
}

fn validate_root_directory(
    descriptor: &OwnedFd,
    exact_mode: bool,
) -> Result<(), VaultMountManagerError> {
    let stat = rfs::fstat(descriptor).map_err(|_| VaultMountManagerError::UnsafeMountRoot)?;
    if !FileType::from_raw_mode(stat.st_mode).is_dir()
        || stat.st_uid != 0
        || stat.st_gid != 0
        || (exact_mode && stat.st_mode & 0o7777 != SECURE_DIRECTORY_MODE)
    {
        return Err(VaultMountManagerError::UnsafeMountRoot);
    }
    Ok(())
}

fn descriptor_mount_id(descriptor: &OwnedFd) -> Result<u64, VaultMountManagerError> {
    let stat = rfs::statx(
        descriptor,
        "",
        AtFlags::EMPTY_PATH | AtFlags::NO_AUTOMOUNT | AtFlags::SYMLINK_NOFOLLOW,
        StatxFlags::MNT_ID,
    )
    .map_err(|_| VaultMountManagerError::UnsafeMountRoot)?;
    if !StatxFlags::from_bits_retain(stat.stx_mask).contains(StatxFlags::MNT_ID)
        || stat.stx_mnt_id == 0
    {
        return Err(VaultMountManagerError::UnsafeMountRoot);
    }
    Ok(stat.stx_mnt_id)
}

fn ensure_cloexec(descriptor: impl AsFd) -> Result<(), VaultMountManagerError> {
    let flags = rustix::io::fcntl_getfd(&descriptor)
        .map_err(|_| VaultMountManagerError::PassphraseUnavailable)?;
    rustix::io::fcntl_setfd(&descriptor, flags | rustix::io::FdFlags::CLOEXEC)
        .map_err(|_| VaultMountManagerError::PassphraseUnavailable)
}

fn source_descriptor_block_identity(
    descriptor: &(impl AsFd + AsRawFd),
) -> Result<DescriptorBlockIdentity, VaultMountManagerError> {
    descriptor_block_identity(descriptor).map_err(|error| {
        map_descriptor_identity_error(error, VaultMountManagerError::InvalidBlockDevice)
    })
}

fn source_identity_matches_location(
    observed: DescriptorBlockIdentity,
    expected: LocatedVaultIdentity,
) -> bool {
    observed.disk_sequence == expected.disk_sequence
        && observed.sector_count == expected.sector_count
        && observed.logical_sector_bytes == expected.logical_sector_bytes
}

fn mapping_descriptor_block_geometry(
    descriptor: &(impl AsFd + AsRawFd),
) -> Result<DescriptorBlockGeometry, VaultMountManagerError> {
    descriptor_block_geometry(descriptor).map_err(|error| {
        map_descriptor_identity_error(error, VaultMountManagerError::MappingVerificationFailed)
    })
}

fn map_descriptor_identity_error(
    error: DescriptorBlockIdentityError,
    invalid: VaultMountManagerError,
) -> VaultMountManagerError {
    match error {
        DescriptorBlockIdentityError::InvalidDescriptor
        | DescriptorBlockIdentityError::IdentityUnavailable => invalid,
        DescriptorBlockIdentityError::ToolUnavailable => VaultMountManagerError::ToolUnavailable,
        DescriptorBlockIdentityError::OperationTimedOut => {
            VaultMountManagerError::OperationTimedOut
        }
        DescriptorBlockIdentityError::CleanupFailed => VaultMountManagerError::CleanupFailed,
    }
}

fn read_small_file(path: &Path) -> Result<Vec<u8>, VaultMountManagerError> {
    let bytes = fs::read(path).map_err(|_| VaultMountManagerError::MappingVerificationFailed)?;
    if bytes.len() > COMMAND_OUTPUT_LIMIT {
        return Err(VaultMountManagerError::MappingVerificationFailed);
    }
    Ok(bytes)
}

fn sysfs_mapper_name_exists(mapper: &MapperName) -> Result<bool, VaultMountManagerError> {
    let entries =
        fs::read_dir("/sys/class/block").map_err(|_| VaultMountManagerError::MapperConflict)?;
    for entry in entries {
        let entry = entry.map_err(|_| VaultMountManagerError::MapperConflict)?;
        let name = entry.file_name();
        let name = name.as_bytes();
        if !name.starts_with(b"dm-") || name.len() <= 3 || !name[3..].iter().all(u8::is_ascii_digit)
        {
            continue;
        }
        let observed = read_small_file(&entry.path().join("dm/name"))
            .map_err(|_| VaultMountManagerError::MapperConflict)?;
        if trim_line(&observed) == mapper.as_os_str().as_bytes() {
            return Ok(true);
        }
    }
    Ok(false)
}

fn require_mapper_path_absent(
    result: Result<(), rustix::io::Errno>,
) -> Result<(), VaultMountManagerError> {
    match result {
        Err(error) if error == rustix::io::Errno::NOENT => Ok(()),
        Ok(()) | Err(_) => Err(VaultMountManagerError::MapperConflict),
    }
}

fn verify_mapper_absence_checkpoint(
    device: &BlockDevice,
    mapper: &MapperName,
    mapper_path: &Path,
) -> Result<(), VaultMountManagerError> {
    if mapping_absence_checkpoint(device, mapper, mapper_path)? {
        Ok(())
    } else {
        Err(VaultMountManagerError::CleanupFailed)
    }
}

fn mapping_absence_checkpoint(
    device: &BlockDevice,
    mapper: &MapperName,
    mapper_path: &Path,
) -> Result<bool, VaultMountManagerError> {
    match rfs::statat(CWD, mapper_path, AtFlags::SYMLINK_NOFOLLOW) {
        Err(error) if error == rustix::io::Errno::NOENT => {}
        Ok(_) => return Ok(false),
        Err(_) => return Err(VaultMountManagerError::CleanupFailed),
    }
    if sysfs_mapper_name_exists(mapper).map_err(|_| VaultMountManagerError::CleanupFailed)? {
        return Ok(false);
    }
    let (major, minor) = device.major_minor();
    let mut holders = fs::read_dir(format!("/sys/dev/block/{major}:{minor}/holders"))
        .map_err(|_| VaultMountManagerError::CleanupFailed)?;
    holders
        .next()
        .transpose()
        .map(|entry| entry.is_none())
        .map_err(|_| VaultMountManagerError::CleanupFailed)
}

fn single_backing_device(directory: &Path) -> Result<(u32, u32), VaultMountManagerError> {
    let mut entries =
        fs::read_dir(directory).map_err(|_| VaultMountManagerError::MappingVerificationFailed)?;
    let entry = entries
        .next()
        .ok_or(VaultMountManagerError::MappingVerificationFailed)?
        .map_err(|_| VaultMountManagerError::MappingVerificationFailed)?;
    if entries.next().is_some() {
        return Err(VaultMountManagerError::MappingVerificationFailed);
    }
    let value = read_small_file(&entry.path().join("dev"))?;
    parse_major_minor(trim_line(&value)).ok_or(VaultMountManagerError::MappingVerificationFailed)
}

fn verify_unique_backing_holder(
    backing: (u32, u32),
    expected_mapping: (u32, u32),
) -> Result<(), VaultMountManagerError> {
    let directory = PathBuf::from(format!(
        "/sys/dev/block/{}:{}/holders",
        backing.0, backing.1
    ));
    let mut entries =
        fs::read_dir(directory).map_err(|_| VaultMountManagerError::MappingVerificationFailed)?;
    let entry = entries
        .next()
        .ok_or(VaultMountManagerError::MappingVerificationFailed)?
        .map_err(|_| VaultMountManagerError::MappingVerificationFailed)?;
    if entries.next().is_some() {
        return Err(VaultMountManagerError::MappingVerificationFailed);
    }
    let observed = read_small_file(&entry.path().join("dev"))?;
    if parse_major_minor(trim_line(&observed)) != Some(expected_mapping) {
        return Err(VaultMountManagerError::MappingVerificationFailed);
    }
    Ok(())
}

fn parse_dm_uuid(value: &[u8], mapper: &MapperName) -> Option<[u8; 36]> {
    let prefix = b"CRYPT-LUKS2-";
    let remainder = value.strip_prefix(prefix)?;
    let (compact, suffix) = remainder.split_at_checked(32)?;
    let suffix = suffix.strip_prefix(b"-")?;
    if suffix != mapper.as_os_str().as_bytes()
        || !compact
            .iter()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(byte))
    {
        return None;
    }
    canonical_uuid_from_compact(compact)
}

fn canonical_uuid_from_compact(compact: &[u8]) -> Option<[u8; 36]> {
    if compact.len() != 32 {
        return None;
    }
    let mut canonical = [0_u8; 36];
    let mut source = 0_usize;
    for (destination, byte) in canonical.iter_mut().enumerate() {
        if matches!(destination, 8 | 13 | 18 | 23) {
            *byte = b'-';
        } else {
            *byte = *compact.get(source)?;
            source += 1;
        }
    }
    Some(canonical)
}

fn parse_uuid_line(value: &[u8]) -> Option<[u8; 36]> {
    let line = trim_line(value);
    if line.len() != 36
        || line.iter().enumerate().any(|(index, byte)| {
            if matches!(index, 8 | 13 | 18 | 23) {
                *byte != b'-'
            } else {
                !(byte.is_ascii_digit() || (b'a'..=b'f').contains(byte))
            }
        })
    {
        return None;
    }
    let mut uuid = [0_u8; 36];
    uuid.copy_from_slice(line);
    Some(uuid)
}

fn parse_major_minor(value: &[u8]) -> Option<(u32, u32)> {
    let separator = value.iter().position(|byte| *byte == b':')?;
    if value[separator + 1..].contains(&b':') {
        return None;
    }
    Some((
        parse_u32(&value[..separator])?,
        parse_u32(&value[separator + 1..])?,
    ))
}

fn parse_u32(value: &[u8]) -> Option<u32> {
    if value.is_empty() || !value.iter().all(u8::is_ascii_digit) {
        return None;
    }
    let mut parsed = 0_u32;
    for byte in value {
        parsed = parsed
            .checked_mul(10)?
            .checked_add(u32::from(byte - b'0'))?;
    }
    Some(parsed)
}

fn trim_line(value: &[u8]) -> &[u8] {
    let without_newline = value.strip_suffix(b"\n").unwrap_or(value);
    without_newline
        .strip_suffix(b"\r")
        .unwrap_or(without_newline)
}

#[derive(Default)]
struct BlkidProperties {
    kind: Option<Vec<u8>>,
    version: Option<Vec<u8>>,
    uuid: Option<[u8; 36]>,
    label: Option<Vec<u8>>,
}

fn parse_blkid_export(value: &[u8]) -> Result<BlkidProperties, VaultMountManagerError> {
    if value.len() > COMMAND_OUTPUT_LIMIT || value.contains(&0) {
        return Err(VaultMountManagerError::MappingVerificationFailed);
    }
    let mut properties = BlkidProperties::default();
    for line in value
        .split(|byte| *byte == b'\n')
        .filter(|line| !line.is_empty())
    {
        let Some(separator) = line.iter().position(|byte| *byte == b'=') else {
            return Err(VaultMountManagerError::MappingVerificationFailed);
        };
        let (key, raw) = line.split_at(separator);
        let raw = &raw[1..];
        match key {
            b"DEVNAME" => {}
            b"TYPE" if properties.kind.is_none() => properties.kind = Some(raw.to_vec()),
            b"VERSION" if properties.version.is_none() => {
                properties.version = Some(raw.to_vec());
            }
            b"UUID" if properties.uuid.is_none() => {
                properties.uuid = parse_uuid_line(raw);
                if properties.uuid.is_none() {
                    return Err(VaultMountManagerError::MappingVerificationFailed);
                }
            }
            b"LABEL" if properties.label.is_none() => properties.label = Some(raw.to_vec()),
            _ => return Err(VaultMountManagerError::MappingVerificationFailed),
        }
    }
    Ok(properties)
}

fn verify_cryptsetup_status(output: &[u8]) -> Result<(), VaultMountManagerError> {
    let mut observed_type = None;
    for line in output.split(|byte| *byte == b'\n') {
        let line = trim_horizontal(line);
        let Some(separator) = line.iter().position(|byte| *byte == b':') else {
            continue;
        };
        let key = trim_horizontal(&line[..separator]);
        let value = trim_horizontal(&line[separator + 1..]);
        match key {
            b"type" if observed_type.is_none() => observed_type = Some(value),
            b"type" => {
                return Err(VaultMountManagerError::MappingVerificationFailed);
            }
            _ => {}
        }
    }
    if observed_type != Some(b"LUKS2".as_slice()) {
        return Err(VaultMountManagerError::MappingVerificationFailed);
    }
    Ok(())
}

fn trim_horizontal(mut value: &[u8]) -> &[u8] {
    while matches!(value.first(), Some(b' ' | b'\t')) {
        value = &value[1..];
    }
    while matches!(value.last(), Some(b' ' | b'\t')) {
        value = &value[..value.len() - 1];
    }
    value
}

fn map_bounded_process_error(
    error: bounded_process::BoundedProcessError,
) -> VaultMountManagerError {
    match error {
        bounded_process::BoundedProcessError::Unavailable
        | bounded_process::BoundedProcessError::StartFailed => {
            VaultMountManagerError::ToolUnavailable
        }
        bounded_process::BoundedProcessError::TimedOut => VaultMountManagerError::OperationTimedOut,
        bounded_process::BoundedProcessError::CleanupFailed => {
            VaultMountManagerError::CleanupFailed
        }
        bounded_process::BoundedProcessError::WaitFailed
        | bounded_process::BoundedProcessError::OutputLimitExceeded
        | bounded_process::BoundedProcessError::UnexpectedDescendant => {
            VaultMountManagerError::MappingVerificationFailed
        }
    }
}

fn map_profile_classifier_error(error: ProfileClassifierError) -> VaultMountManagerError {
    match error {
        ProfileClassifierError::InvalidCanonicalProfile => {
            VaultMountManagerError::ClassifierUnavailable
        }
        ProfileClassifierError::InvalidDescriptor | ProfileClassifierError::MediaChanged => {
            VaultMountManagerError::InvalidBlockDevice
        }
        ProfileClassifierError::OperationTimedOut => VaultMountManagerError::OperationTimedOut,
    }
}

fn with_profile_revalidation<T>(
    mut classify: impl FnMut(
        &mut dyn FnMut() -> Result<(), ProfileClassifierError>,
    ) -> Result<T, ProfileClassifierError>,
    mut revalidate: impl FnMut() -> Result<(), VaultMountManagerError>,
) -> Result<T, VaultMountManagerError> {
    let mut manager_error = None;
    let classified = {
        let mut checkpoint = || match revalidate() {
            Ok(()) => Ok(()),
            Err(error) => {
                manager_error = Some(error);
                Err(ProfileClassifierError::MediaChanged)
            }
        };
        classify(&mut checkpoint)
    };
    if let Some(error) = manager_error {
        return Err(error);
    }
    classified.map_err(map_profile_classifier_error)
}

fn with_mount_attestation_revalidation<T>(
    mut revalidate: impl FnMut() -> Result<(), VaultMountManagerError>,
    attest: impl FnOnce() -> Result<T, VaultMountManagerError>,
) -> Result<T, VaultMountManagerError> {
    revalidate()?;
    let attestation = attest()?;
    revalidate()?;
    Ok(attestation)
}

fn map_blkid_probe_error(error: VaultMountManagerError) -> VaultMountManagerError {
    match error {
        VaultMountManagerError::ToolUnavailable
        | VaultMountManagerError::OperationTimedOut
        | VaultMountManagerError::CleanupFailed => error,
        _ => VaultMountManagerError::UnsupportedFilesystem,
    }
}

fn map_secure_state_error(_error: RescueSecretError) -> VaultMountManagerError {
    VaultMountManagerError::SecureStateUnavailable
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::MountAttestationClaims;
    use std::{
        os::unix::fs::{PermissionsExt, symlink},
        process::Command,
        sync::{Arc, Mutex},
    };

    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    enum Step {
        DeviceUnused,
        MapperAbsent,
        Profile,
        Open,
        Mapping,
        FailedOpenAbsent,
        ArmDeferred,
        VerifyDeferred,
        #[cfg(feature = "experimental-firstboot-provisioner")]
        FormatFilesystem,
        Filesystem,
        Prepare,
        Mount,
        MountedFilesystem,
        Attest,
        VerifyMount,
        Unmount,
        VerifyUnmounted,
        VerifyMapping,
        Close,
        ClosedAbsent,
        WaitDeferredAbsent,
    }

    #[derive(Default)]
    struct FakeState {
        steps: Vec<Step>,
        fail_at: Option<Step>,
        cleanup_fail_at: Option<Step>,
        mapping_absent: bool,
        mapping_error: Option<VaultMountManagerError>,
        absence_proof_fails: bool,
        unmount_absence_proof_fails: bool,
        close_absence_proof_fails: bool,
        deferred_absence_proof_fails: bool,
        open_error: Option<VaultMountManagerError>,
        pre_open_error: Option<VaultMountManagerError>,
        pre_mount_error: Option<VaultMountManagerError>,
        pre_open_calls: usize,
        pre_mount_calls: usize,
    }

    #[derive(Clone)]
    struct FakeOps(Arc<Mutex<FakeState>>);

    impl FakeOps {
        fn step(&self, step: Step) -> Result<(), VaultMountManagerError> {
            let mut state = self.0.lock().expect("fake state lock");
            state.steps.push(step);
            if state.fail_at == Some(step) || state.cleanup_fail_at == Some(step) {
                Err(VaultMountManagerError::MountVerificationFailed)
            } else {
                Ok(())
            }
        }
    }

    impl VaultOps for FakeOps {
        fn ensure_device_unused(
            &mut self,
            _device: &BlockDevice,
        ) -> Result<(), VaultMountManagerError> {
            self.step(Step::DeviceUnused)
        }

        fn ensure_mapper_absent(
            &mut self,
            _mapper: &MapperName,
            _mapper_path: &Path,
        ) -> Result<(), VaultMountManagerError> {
            self.step(Step::MapperAbsent)
        }

        fn classify_outer_profile(
            &mut self,
            _device: &BlockDevice,
        ) -> Result<OuterProfileEvidence, VaultMountManagerError> {
            self.step(Step::Profile)?;
            Ok(OuterProfileEvidence::fixture(
                *b"a9950603-ffce-492a-b082-43fba5c492a1",
                3,
            ))
        }

        fn pre_open_revalidate(
            &mut self,
            _device: &BlockDevice,
        ) -> Result<(), VaultMountManagerError> {
            let mut state = self.0.lock().expect("fake state lock");
            state.pre_open_calls += 1;
            state.pre_open_error.map_or(Ok(()), Err)
        }

        fn open_luks2(
            &mut self,
            _device: &BlockDevice,
            _mapper: &MapperName,
            _passphrase: OwnedFd,
        ) -> Result<(), VaultMountManagerError> {
            self.step(Step::Open)?;
            self.0
                .lock()
                .expect("fake state lock")
                .open_error
                .map_or(Ok(()), Err)
        }

        fn inspect_mapping(
            &mut self,
            _device: &BlockDevice,
            _mapper: &MapperName,
            _mapper_path: &Path,
            _header: HeaderIdentity,
        ) -> Result<MappingIdentity, VaultMountManagerError> {
            self.step(Step::Mapping)?;
            if let Some(error) = self.0.lock().expect("fake state lock").mapping_error {
                return Err(error);
            }
            if self.0.lock().expect("fake state lock").mapping_absent {
                return Err(VaultMountManagerError::MappingVerificationFailed);
            }
            Ok(MappingIdentity {
                descriptor: dummy_fd(),
                checkpoint_procfd: PathBuf::from("/proc/1/fd/9"),
                device: 3,
                inode: 4,
                rdev: rfs::makedev(253, 7),
                major: 253,
                minor: 7,
                backing_major: 7,
                backing_minor: 8,
                capacity_sectors: VAULT_PAYLOAD_BYTES / 512,
                logical_sector_bytes: LOGICAL_SECTOR_BYTES,
            })
        }

        fn verify_failed_open_absence(
            &mut self,
            _device: &BlockDevice,
            _mapper: &MapperName,
            _mapper_path: &Path,
        ) -> Result<(), VaultMountManagerError> {
            self.step(Step::FailedOpenAbsent)?;
            if self.0.lock().expect("fake state lock").absence_proof_fails {
                Err(VaultMountManagerError::CleanupFailed)
            } else {
                Ok(())
            }
        }

        fn arm_deferred_mapping_removal(
            &mut self,
            _mapper: &MapperName,
        ) -> Result<(), VaultMountManagerError> {
            self.step(Step::ArmDeferred)
        }

        fn verify_deferred_mapping_removal(
            &mut self,
            _device: &BlockDevice,
            _mapper: &MapperName,
            _header: HeaderIdentity,
            _expected: &MappingIdentity,
        ) -> Result<(), VaultMountManagerError> {
            self.step(Step::VerifyDeferred)
        }

        fn verify_closed_mapping_absence(
            &mut self,
            _device: &BlockDevice,
            _mapper: &MapperName,
            _mapper_path: &Path,
        ) -> Result<(), VaultMountManagerError> {
            self.step(Step::ClosedAbsent)?;
            if self
                .0
                .lock()
                .expect("fake state lock")
                .close_absence_proof_fails
            {
                Err(VaultMountManagerError::CleanupFailed)
            } else {
                Ok(())
            }
        }

        fn wait_for_deferred_mapping_absence(
            &mut self,
            _device: &BlockDevice,
            _mapper: &MapperName,
            _mapper_path: &Path,
        ) -> Result<(), VaultMountManagerError> {
            self.step(Step::WaitDeferredAbsent)?;
            if self
                .0
                .lock()
                .expect("fake state lock")
                .deferred_absence_proof_fails
            {
                Err(VaultMountManagerError::CleanupFailed)
            } else {
                Ok(())
            }
        }

        #[cfg(feature = "experimental-firstboot-provisioner")]
        fn format_filesystem(
            &mut self,
            _device: &BlockDevice,
            _mapper: &MapperName,
            _mapping: &MappingIdentity,
            _header: HeaderIdentity,
            _filesystem_uuid: [u8; 36],
        ) -> Result<(), VaultMountManagerError> {
            self.step(Step::FormatFilesystem)
        }

        fn inspect_filesystem(
            &mut self,
            _device: &BlockDevice,
            _mapper: &MapperName,
            _mapping: &MappingIdentity,
            _header: HeaderIdentity,
        ) -> Result<Ext4ProfileEvidence, VaultMountManagerError> {
            self.step(Step::Filesystem)?;
            Ok(Ext4ProfileEvidence::fixture(
                [
                    0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x42, 0x22, 0x82, 0x22, 0x22, 0x22, 0x22,
                    0x22, 0x22, 0x22,
                ],
                1024,
            ))
        }

        fn prepare_mount_root(&mut self, _root: &Path) -> Result<(), VaultMountManagerError> {
            self.step(Step::Prepare)
        }

        fn pre_mount_revalidate(
            &mut self,
            _device: &BlockDevice,
            _mapper: &MapperName,
            _mapping: &MappingIdentity,
            _header: HeaderIdentity,
        ) -> Result<(), VaultMountManagerError> {
            let mut state = self.0.lock().expect("fake state lock");
            state.pre_mount_calls += 1;
            state.pre_mount_error.map_or(Ok(()), Err)
        }

        fn mount_ext4(
            &mut self,
            _device: &BlockDevice,
            _mapper: &MapperName,
            _mapping: &MappingIdentity,
            _header: HeaderIdentity,
            _root: &Path,
        ) -> Result<(), VaultMountManagerError> {
            self.step(Step::Mount)
        }

        fn verify_mounted_filesystem(
            &mut self,
            _device: &BlockDevice,
            _mapper: &MapperName,
            _mapping: &MappingIdentity,
            _header: HeaderIdentity,
            _expected: Ext4ProfileEvidence,
        ) -> Result<(), VaultMountManagerError> {
            self.step(Step::MountedFilesystem)
        }

        fn attest_mount(
            &mut self,
            request: &ResolvedRequest,
            header: HeaderIdentity,
            mapping: &MappingIdentity,
        ) -> Result<VaultMountAttestation, VaultMountManagerError> {
            self.step(Step::Attest)?;
            Ok(VaultMountAttestation {
                claims: MountAttestationClaims {
                    root_device: 99,
                    mount_id: 101,
                    mapping_major: mapping.major,
                    mapping_minor: mapping.minor,
                    backing_major: mapping.backing_major,
                    backing_minor: mapping.backing_minor,
                    mapper_name: request.mapper.as_fixed_bytes(),
                    luks_uuid: header.uuid,
                    #[cfg(feature = "experimental-repair-store")]
                    repair_physical_parent: request.device.repair_physical_parent_claims(),
                },
            })
        }

        fn verify_cleanup_mount(
            &mut self,
            _request: &ResolvedRequest,
            _header: HeaderIdentity,
            _mapping: &MappingIdentity,
            _attestation: Option<&VaultMountAttestation>,
        ) -> Result<(), VaultMountManagerError> {
            self.step(Step::VerifyMount)
        }

        fn unmount(&mut self, _root: &Path) -> Result<(), VaultMountManagerError> {
            self.step(Step::Unmount)
        }

        fn verify_unmounted(
            &mut self,
            _request: &ResolvedRequest,
            _header: HeaderIdentity,
            _mapping: &MappingIdentity,
        ) -> Result<(), VaultMountManagerError> {
            self.step(Step::VerifyUnmounted)?;
            if self
                .0
                .lock()
                .expect("fake state lock")
                .unmount_absence_proof_fails
            {
                Err(VaultMountManagerError::CleanupFailed)
            } else {
                Ok(())
            }
        }

        fn verify_cleanup_mapping(
            &mut self,
            _device: &BlockDevice,
            _mapper: &MapperName,
            _mapper_path: &Path,
            _header: HeaderIdentity,
            _expected: &MappingIdentity,
        ) -> Result<(), VaultMountManagerError> {
            self.step(Step::VerifyMapping)
        }

        fn close_mapping(&mut self, _mapper: &MapperName) -> Result<(), VaultMountManagerError> {
            self.step(Step::Close)
        }
    }

    fn fake_request() -> ResolvedRequest {
        let descriptor = rfs::openat(
            CWD,
            "/dev/null",
            OFlags::RDONLY | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .expect("open dummy descriptor");
        ResolvedRequest {
            device: BlockDevice {
                checkpoint_path: PathBuf::from("/dev/loop8"),
                checkpoint_procfd: PathBuf::from("/proc/1/fd/8"),
                descriptor,
                device: 1,
                inode: 2,
                rdev: rfs::makedev(7, 8),
                disk_sequence: 12,
                capacity_sectors: 524_288,
                logical_sector_bytes: LOGICAL_SECTOR_BYTES,
                located_identity: None,
            },
            mapper: MapperName::parse("kernaid-vault-0123456789abcdef").expect("mapper"),
            mapper_path: PathBuf::from("/dev/mapper/kernaid-vault-0123456789abcdef"),
            mount_root: PathBuf::from("/run/kernaid/vault/kernaid-vault-0123456789abcdef"),
        }
    }

    fn dummy_fd() -> OwnedFd {
        rfs::openat(
            CWD,
            "/dev/null",
            OFlags::RDONLY | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .expect("open dummy passphrase fd")
    }

    fn start_fake(
        state: Arc<Mutex<FakeState>>,
    ) -> Result<Activation<FakeOps>, VaultMountManagerError> {
        Activation::start(FakeOps(state), dummy_fd(), fake_request(), dummy_fd())
    }

    #[cfg(feature = "experimental-firstboot-provisioner")]
    fn start_fake_firstboot(
        state: Arc<Mutex<FakeState>>,
    ) -> Result<Activation<FakeOps>, VaultMountManagerError> {
        Activation::start_for_provisioning(
            FakeOps(state),
            dummy_fd(),
            fake_request(),
            dummy_fd(),
            32,
            *b"22222222-2222-4222-8222-222222222222",
        )
    }

    #[test]
    fn mapper_and_device_grammars_are_closed() {
        let located_constructor: fn(LocatedVaultPartition, MapperName) -> VaultUnlockRequest =
            VaultUnlockRequest::from_located;
        let _ = located_constructor;

        assert!(MapperName::parse("kernaid-vault-0123456789abcdef").is_ok());
        for invalid in [
            "kernaid-vault-0123456789abcde",
            "kernaid-vault-0123456789ABCDEf",
            "other-vault-0123456789abcdef",
            "kernaid-vault-0123456789abcdeg",
            "kernaid-vault-0123456789abcde/",
        ] {
            assert_eq!(
                MapperName::parse(invalid).err(),
                Some(VaultMountManagerError::InvalidMapperName)
            );
        }
        assert!(validate_device_path(Path::new("/dev/nvme0n1p9")).is_ok());
        for invalid in [
            "dev/sda1",
            "/dev/disk/by-label/KERNAID_VAULT",
            "/dev/mapper/vault",
            "/dev/dm-0",
            "/dev//sda1",
            "/dev/sda1/",
            "/tmp/vault.img",
            "/dev/../dev/sda1",
        ] {
            assert_eq!(
                validate_device_path(Path::new(invalid)).err(),
                Some(VaultMountManagerError::InvalidBlockDevice)
            );
        }
    }

    #[test]
    fn retained_procfd_is_stable_across_named_path_replacement() {
        let directory = tempfile::tempdir().expect("temporary procfd fixture");
        let named = directory.path().join("selected-device");
        let moved = directory.path().join("original-device");
        fs::write(&named, b"original").expect("write original fixture");
        let retained = File::open(&named).expect("retain original descriptor");
        let checkpoint_procfd = retained_descriptor_path(&retained).expect("retained procfd path");

        fs::rename(&named, &moved).expect("move original fixture");
        fs::write(&named, b"replacement").expect("write replacement fixture");

        assert_eq!(
            fs::read(&checkpoint_procfd).expect("read retained procfd"),
            b"original"
        );
        assert_eq!(
            fs::read(&named).expect("read named replacement"),
            b"replacement"
        );
        let retained_stat = rfs::fstat(&retained).expect("stat retained original");
        let replacement_stat =
            rfs::statat(CWD, &named, AtFlags::SYMLINK_NOFOLLOW).expect("stat named replacement");
        assert_ne!(
            (retained_stat.st_dev, retained_stat.st_ino),
            (replacement_stat.st_dev, replacement_stat.st_ino),
            "the pre/post named-path checkpoint detects the replacement"
        );
    }

    #[test]
    fn runtime_root_identity_accepts_only_the_exact_root_owned_tmpfs_object() {
        assert_eq!(
            Path::new(RUNTIME_ROOT).parent(),
            Some(Path::new("/run")),
            "the mount-boundary exception is rooted directly below /run"
        );
        assert_eq!(
            Path::new(RUNTIME_ROOT).file_name(),
            Some(OsStr::new(RUNTIME_ROOT_NAME)),
            "the full path and descriptor-relative literal cannot drift"
        );
        let exact = DirectoryIdentity {
            device: 11,
            inode: 22,
            mode: 0o040700,
            uid: 0,
            gid: 0,
        };
        assert!(runtime_root_mount_is_exact(
            exact,
            exact,
            exact.device,
            Some(TMPFS_MAGIC),
            Some(TMPFS_MAGIC),
        ));

        let mismatches = [
            (
                DirectoryIdentity {
                    device: 12,
                    ..exact
                },
                exact,
                exact.device,
                Some(TMPFS_MAGIC),
                Some(TMPFS_MAGIC),
            ),
            (
                exact,
                DirectoryIdentity { inode: 23, ..exact },
                exact.device,
                Some(TMPFS_MAGIC),
                Some(TMPFS_MAGIC),
            ),
            (
                DirectoryIdentity {
                    mode: 0o100700,
                    ..exact
                },
                DirectoryIdentity {
                    mode: 0o100700,
                    ..exact
                },
                exact.device,
                Some(TMPFS_MAGIC),
                Some(TMPFS_MAGIC),
            ),
            (
                DirectoryIdentity { uid: 1, ..exact },
                DirectoryIdentity { uid: 1, ..exact },
                exact.device,
                Some(TMPFS_MAGIC),
                Some(TMPFS_MAGIC),
            ),
            (
                DirectoryIdentity { gid: 1, ..exact },
                DirectoryIdentity { gid: 1, ..exact },
                exact.device,
                Some(TMPFS_MAGIC),
                Some(TMPFS_MAGIC),
            ),
            (
                DirectoryIdentity {
                    mode: 0o040750,
                    ..exact
                },
                DirectoryIdentity {
                    mode: 0o040750,
                    ..exact
                },
                exact.device,
                Some(TMPFS_MAGIC),
                Some(TMPFS_MAGIC),
            ),
            (
                exact,
                exact,
                exact.device + 1,
                Some(TMPFS_MAGIC),
                Some(TMPFS_MAGIC),
            ),
            (exact, exact, exact.device, Some(0xef53), Some(TMPFS_MAGIC)),
            (exact, exact, exact.device, Some(TMPFS_MAGIC), Some(0xef53)),
        ];
        for (opened, named, run_device, opened_filesystem, run_filesystem) in mismatches {
            assert!(!runtime_root_mount_is_exact(
                opened,
                named,
                run_device,
                opened_filesystem,
                run_filesystem,
            ));
        }
    }

    #[test]
    #[ignore = "requires /usr/bin/unshare and unprivileged user and mount namespaces"]
    fn runtime_root_accepts_direct_and_systemd_self_bind_but_no_other_mount() {
        const CHILD_FLAG: &str = "KERNAID_RUNTIME_ROOT_SELF_BIND_CHILD";
        const TEST_NAME: &str = "mount_manager::tests::runtime_root_accepts_direct_and_systemd_self_bind_but_no_other_mount";
        if let Some(root) = std::env::var_os(CHILD_FLAG) {
            let root = PathBuf::from(root);
            let run_path = root.join("run");
            fs::create_dir(&run_path).expect("create user-namespace run fixture");
            fs::set_permissions(&run_path, fs::Permissions::from_mode(0o700))
                .expect("set run fixture mode");
            rustix::mount::mount(
                "tmpfs",
                &run_path,
                "tmpfs",
                MountFlags::NOSUID | MountFlags::NODEV | MountFlags::NOEXEC,
                None::<&std::ffi::CStr>,
            )
            .expect("mount isolated tmpfs fixture");

            let run = open_secure_directory(&run_path, false).expect("open isolated run tmpfs");
            let direct = open_or_create_runtime_root(&run).expect("accept direct host layout");
            assert_eq!(
                descriptor_mount_id(&direct).expect("direct runtime mount id"),
                descriptor_mount_id(&run).expect("run mount id"),
                "the host-probe layout stays on /run's mount"
            );
            drop(direct);

            let runtime_path = run_path.join(RUNTIME_ROOT_NAME);
            rustix::mount::mount_bind(&runtime_path, &runtime_path)
                .expect("create systemd-style self bind");
            assert_eq!(
                rfs::openat2(
                    &run,
                    RUNTIME_ROOT_NAME,
                    OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
                    Mode::empty(),
                    ResolveFlags::BENEATH
                        | ResolveFlags::NO_SYMLINKS
                        | ResolveFlags::NO_MAGICLINKS
                        | ResolveFlags::NO_XDEV,
                )
                .err(),
                Some(rustix::io::Errno::XDEV),
                "the old lookup must reproduce EXDEV at the self-bind boundary"
            );
            let bound = open_or_create_runtime_root(&run).expect("accept exact systemd self bind");
            assert_ne!(
                descriptor_mount_id(&bound).expect("bound runtime mount id"),
                descriptor_mount_id(&run).expect("run mount id after bind"),
                "the accepted systemd layout crosses exactly one mount boundary"
            );

            let nested_path = runtime_path.join(VAULT_MOUNT_PARENT);
            let nested = open_or_create_child_directory(&bound, OsStr::new(VAULT_MOUNT_PARENT))
                .expect("create nested runtime directory");
            drop(nested);
            rustix::mount::mount(
                "tmpfs",
                &nested_path,
                "tmpfs",
                MountFlags::NOSUID | MountFlags::NODEV | MountFlags::NOEXEC,
                None::<&std::ffi::CStr>,
            )
            .expect("mount nested foreign filesystem");
            assert_eq!(
                open_or_create_child_directory(&bound, OsStr::new(VAULT_MOUNT_PARENT)).err(),
                Some(VaultMountManagerError::UnsafeMountRoot),
                "NO_XDEV must be restored below the one accepted boundary"
            );
            rustix::mount::unmount(&nested_path, UnmountFlags::NOFOLLOW)
                .expect("unmount nested fixture");
            drop(bound);
            rustix::mount::unmount(&runtime_path, UnmountFlags::NOFOLLOW)
                .expect("unmount self-bind fixture");

            rustix::mount::mount(
                "tmpfs",
                &runtime_path,
                "tmpfs",
                MountFlags::NOSUID | MountFlags::NODEV | MountFlags::NOEXEC,
                None::<&std::ffi::CStr>,
            )
            .expect("mount foreign runtime filesystem");
            assert_eq!(
                open_or_create_runtime_root(&run).err(),
                Some(VaultMountManagerError::UnsafeMountRoot),
                "a different tmpfs device is not the allowed self bind"
            );
            rustix::mount::unmount(&runtime_path, UnmountFlags::NOFOLLOW)
                .expect("unmount foreign runtime fixture");

            fs::remove_dir(&nested_path).expect("remove nested fixture");
            fs::remove_dir(&runtime_path).expect("remove runtime fixture");
            let alternate = run_path.join("alternate");
            fs::create_dir(&alternate).expect("create symlink target fixture");
            fs::set_permissions(&alternate, fs::Permissions::from_mode(0o700))
                .expect("set symlink target mode");
            symlink(&alternate, &runtime_path).expect("create runtime symlink fixture");
            assert_eq!(
                open_or_create_runtime_root(&run).err(),
                Some(VaultMountManagerError::UnsafeMountRoot),
                "the one boundary exception must not follow a symlink"
            );
            fs::remove_file(&runtime_path).expect("remove runtime symlink fixture");
            fs::create_dir(&runtime_path).expect("restore runtime directory");
            fs::set_permissions(&runtime_path, fs::Permissions::from_mode(0o750))
                .expect("set unsafe runtime mode");
            assert_eq!(
                open_or_create_runtime_root(&run).err(),
                Some(VaultMountManagerError::UnsafeMountRoot),
                "the runtime root mode remains exact"
            );
            return;
        }

        let fixture = tempfile::tempdir().expect("temporary runtime-root fixture");
        let status = Command::new("/usr/bin/unshare")
            .arg("--user")
            .arg("--map-root-user")
            .arg("--mount")
            .arg("--propagation")
            .arg("private")
            .arg(std::env::current_exe().expect("current test executable"))
            .arg("--ignored")
            .arg("--exact")
            .arg(TEST_NAME)
            .arg("--nocapture")
            .env(CHILD_FLAG, fixture.path())
            .status()
            .expect("spawn isolated runtime-root regression child");
        assert!(status.success(), "runtime-root namespace regression failed");
    }

    #[test]
    fn source_identity_rechecks_are_descriptor_only_and_exact() {
        let expected = LocatedVaultIdentity {
            parent_major: 8,
            parent_minor: 16,
            partition_major: 8,
            partition_minor: 19,
            disk_sequence: 77,
            logical_sector_bytes: LOGICAL_SECTOR_BYTES,
            media_sector_count: 62_500_000,
            start_lba: VAULT_START_LBA,
            sector_count: VAULT_SECTOR_COUNT,
        };
        let exact = DescriptorBlockIdentity {
            disk_sequence: expected.disk_sequence,
            sector_count: expected.sector_count,
            logical_sector_bytes: expected.logical_sector_bytes,
        };
        assert!(source_identity_matches_location(exact, expected));
        for mismatch in [
            DescriptorBlockIdentity {
                disk_sequence: 78,
                ..exact
            },
            DescriptorBlockIdentity {
                sector_count: exact.sector_count + 1,
                ..exact
            },
            DescriptorBlockIdentity {
                logical_sector_bytes: 4096,
                ..exact
            },
        ] {
            assert!(!source_identity_matches_location(mismatch, expected));
        }

        let source = include_str!("mount_manager.rs");
        let sysfs_sequence_read = ["join(", "\"disk", "seq\"", ")"].concat();
        let sysfs_capacity_read = ["join(", "\"si", "ze\"", ")"].concat();
        assert!(!source.contains(&sysfs_sequence_read));
        assert!(!source.contains(&sysfs_capacity_read));
        assert!(!source.contains(&["block_device_kernel_", "identity"].concat()));
    }

    #[test]
    fn manager_error_codes_are_closed_sanitized_literals() {
        let errors = [
            VaultMountManagerError::UnsupportedPlatform,
            VaultMountManagerError::PrivilegeRequired,
            VaultMountManagerError::ManagerLocked,
            VaultMountManagerError::InvalidBlockDevice,
            VaultMountManagerError::InvalidMapperName,
            VaultMountManagerError::Unprovisioned,
            VaultMountManagerError::ProfileMismatch,
            VaultMountManagerError::ClassifierUnavailable,
            VaultMountManagerError::InvalidLuks2Header,
            VaultMountManagerError::WrongVaultLabel,
            VaultMountManagerError::MapperConflict,
            VaultMountManagerError::PassphraseUnavailable,
            VaultMountManagerError::UnlockFailed,
            VaultMountManagerError::MappingVerificationFailed,
            VaultMountManagerError::UnsupportedFilesystem,
            VaultMountManagerError::UnsafeMountRoot,
            VaultMountManagerError::MountFailed,
            VaultMountManagerError::MountVerificationFailed,
            VaultMountManagerError::SecureStateUnavailable,
            VaultMountManagerError::CleanupFailed,
            VaultMountManagerError::ToolUnavailable,
            VaultMountManagerError::OperationTimedOut,
        ];
        for error in errors {
            let code = error.code();
            assert!(!code.is_empty());
            assert!(
                code.bytes()
                    .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
            );
        }
    }

    #[test]
    fn filesystem_probe_preserves_tool_timeout_and_cleanup_failures() {
        assert_eq!(
            map_bounded_process_error(bounded_process::BoundedProcessError::StartFailed),
            VaultMountManagerError::ToolUnavailable,
            "a spawn failure proves that the mutator never ran"
        );
        assert_eq!(
            map_bounded_process_error(bounded_process::BoundedProcessError::WaitFailed),
            VaultMountManagerError::MappingVerificationFailed,
            "a wait failure can follow mutation and requires inspection"
        );
        for error in [
            VaultMountManagerError::ToolUnavailable,
            VaultMountManagerError::OperationTimedOut,
            VaultMountManagerError::CleanupFailed,
        ] {
            assert_eq!(map_blkid_probe_error(error), error);
        }
        assert_eq!(
            map_blkid_probe_error(VaultMountManagerError::MappingVerificationFailed),
            VaultMountManagerError::UnsupportedFilesystem
        );
        assert_eq!(
            map_profile_classifier_error(ProfileClassifierError::InvalidCanonicalProfile),
            VaultMountManagerError::ClassifierUnavailable
        );
    }

    #[test]
    fn profile_callbacks_preserve_timeout_and_cleanup_failures() {
        for expected in [
            VaultMountManagerError::ToolUnavailable,
            VaultMountManagerError::OperationTimedOut,
            VaultMountManagerError::CleanupFailed,
        ] {
            let first_checkpoint = with_profile_revalidation(
                |checkpoint| {
                    checkpoint()?;
                    Ok(())
                },
                || Err(expected),
            );
            assert_eq!(first_checkpoint, Err(expected));

            let mut calls = 0_u8;
            let later_checkpoint = with_profile_revalidation(
                |checkpoint| {
                    checkpoint()?;
                    checkpoint()?;
                    Ok(())
                },
                || {
                    calls += 1;
                    if calls == 1 { Ok(()) } else { Err(expected) }
                },
            );
            assert_eq!(later_checkpoint, Err(expected));
        }
    }

    #[test]
    fn mount_attestation_preserves_pre_and_post_revalidation_failures() {
        for expected in [
            VaultMountManagerError::ToolUnavailable,
            VaultMountManagerError::OperationTimedOut,
            VaultMountManagerError::CleanupFailed,
        ] {
            assert_eq!(
                with_mount_attestation_revalidation(|| Err(expected), || Ok(())),
                Err(expected)
            );

            let mut calls = 0_u8;
            assert_eq!(
                with_mount_attestation_revalidation(
                    || {
                        calls += 1;
                        if calls == 1 { Ok(()) } else { Err(expected) }
                    },
                    || Ok(())
                ),
                Err(expected)
            );
        }
    }

    #[test]
    fn parsers_reject_ambiguous_identity_data() {
        assert_eq!(
            require_mapper_path_absent(Err(rustix::io::Errno::NOENT)),
            Ok(())
        );
        for observed in [
            Ok(()),
            Err(rustix::io::Errno::ACCESS),
            Err(rustix::io::Errno::IO),
        ] {
            assert_eq!(
                require_mapper_path_absent(observed),
                Err(VaultMountManagerError::MapperConflict)
            );
        }
        assert_eq!(
            parse_uuid_line(b"a9950603-ffce-492a-b082-43fba5c492a1\n"),
            Some(*b"a9950603-ffce-492a-b082-43fba5c492a1")
        );
        assert_eq!(
            parse_uuid_line(b"A9950603-ffce-492a-b082-43fba5c492a1\n"),
            None
        );
        let mapper = MapperName::parse("kernaid-vault-0123456789abcdef").expect("mapper");
        assert_eq!(
            parse_dm_uuid(
                b"CRYPT-LUKS2-a9950603ffce492ab08243fba5c492a1-kernaid-vault-0123456789abcdef",
                &mapper
            ),
            Some(*b"a9950603-ffce-492a-b082-43fba5c492a1")
        );
        assert_eq!(
            parse_dm_uuid(
                b"CRYPT-LUKS2-a9950603ffce492ab08243fba5c492a1-other",
                &mapper
            ),
            None
        );
        assert!(
            verify_cryptsetup_status(
                b"/dev/mapper/x is active.\n  type:    LUKS2\n  device:  /dev/replaced\n"
            )
            .is_ok()
        );
        assert!(
            verify_cryptsetup_status(
                b"/dev/mapper/x is active.\n  type: plain\n  device: /dev/loop8\n"
            )
            .is_err()
        );
    }

    #[test]
    fn unlock_command_has_only_child_procfd_device_and_stdin_key_source() {
        let mapper = MapperName::parse("kernaid-vault-0123456789abcdef").expect("mapper");
        let command = cryptsetup_open_command(Path::new("/proc/self/fd/8"), &mapper);
        assert_eq!(command.get_program(), OsStr::new(CRYPTSETUP_PATH));
        let arguments: Vec<_> = command.get_args().collect();
        assert_eq!(
            arguments,
            vec![
                OsStr::new("open"),
                OsStr::new("--type"),
                OsStr::new("luks2"),
                OsStr::new("--batch-mode"),
                OsStr::new("--tries"),
                OsStr::new("1"),
                OsStr::new("--disable-external-tokens"),
                OsStr::new("--key-file"),
                OsStr::new("-"),
                OsStr::new("/proc/self/fd/8"),
                OsStr::new("kernaid-vault-0123456789abcdef"),
            ]
        );
    }

    #[test]
    fn deferred_close_command_has_only_the_fixed_mapper_target() {
        let mapper = MapperName::parse("kernaid-vault-0123456789abcdef").expect("mapper");
        let command = cryptsetup_deferred_close_command(&mapper);
        assert_eq!(command.get_program(), OsStr::new(CRYPTSETUP_PATH));
        let arguments: Vec<_> = command.get_args().collect();
        assert_eq!(
            arguments,
            vec![
                OsStr::new("close"),
                OsStr::new("--deferred"),
                OsStr::new("kernaid-vault-0123456789abcdef"),
            ]
        );
    }

    #[test]
    fn activation_is_typed_and_cleanup_runs_in_reverse_order() {
        let state = Arc::new(Mutex::new(FakeState::default()));
        let mut activation = start_fake(Arc::clone(&state)).expect("activate");
        activation.cleanup().expect("cleanup");
        drop(activation);
        assert_eq!(
            state.lock().expect("state").steps,
            vec![
                Step::DeviceUnused,
                Step::MapperAbsent,
                Step::Profile,
                Step::Open,
                Step::Mapping,
                Step::ArmDeferred,
                Step::VerifyDeferred,
                Step::Profile,
                Step::Filesystem,
                Step::Prepare,
                Step::Mount,
                Step::MountedFilesystem,
                Step::Profile,
                Step::Attest,
                Step::VerifyMount,
                Step::Unmount,
                Step::VerifyUnmounted,
                Step::VerifyMapping,
                Step::WaitDeferredAbsent,
            ]
        );
    }

    #[test]
    fn ambiguous_open_error_acquires_mapping_identity_then_cleans_it() {
        let state = Arc::new(Mutex::new(FakeState {
            steps: Vec::new(),
            fail_at: Some(Step::Open),
            ..FakeState::default()
        }));
        assert_eq!(
            start_fake(Arc::clone(&state)).err(),
            Some(VaultMountManagerError::MountVerificationFailed)
        );
        assert_eq!(
            state.lock().expect("state").steps,
            vec![
                Step::DeviceUnused,
                Step::MapperAbsent,
                Step::Profile,
                Step::Open,
                Step::Mapping,
                Step::ArmDeferred,
                Step::VerifyDeferred,
                Step::VerifyMapping,
                Step::WaitDeferredAbsent,
            ]
        );
    }

    #[test]
    fn wrong_pass_is_reported_only_after_exact_mapper_absence_proof() {
        let proven_absent = Arc::new(Mutex::new(FakeState {
            mapping_absent: true,
            open_error: Some(VaultMountManagerError::UnlockFailed),
            ..FakeState::default()
        }));
        assert_eq!(
            start_fake(Arc::clone(&proven_absent)).err(),
            Some(VaultMountManagerError::UnlockFailed)
        );
        assert_eq!(
            proven_absent.lock().expect("state").steps,
            vec![
                Step::DeviceUnused,
                Step::MapperAbsent,
                Step::Profile,
                Step::Open,
                Step::Mapping,
                Step::FailedOpenAbsent,
            ]
        );

        let ambiguous = Arc::new(Mutex::new(FakeState {
            mapping_absent: true,
            absence_proof_fails: true,
            open_error: Some(VaultMountManagerError::UnlockFailed),
            ..FakeState::default()
        }));
        assert_eq!(
            start_fake(Arc::clone(&ambiguous)).err(),
            Some(VaultMountManagerError::CleanupFailed)
        );
        assert_eq!(
            ambiguous.lock().expect("state").steps,
            vec![
                Step::DeviceUnused,
                Step::MapperAbsent,
                Step::Profile,
                Step::Open,
                Step::Mapping,
                Step::FailedOpenAbsent,
            ]
        );
    }

    #[test]
    fn mapping_inspection_operational_failures_dominate_wrong_pass() {
        for mapping_error in [
            VaultMountManagerError::ToolUnavailable,
            VaultMountManagerError::OperationTimedOut,
            VaultMountManagerError::CleanupFailed,
        ] {
            let state = Arc::new(Mutex::new(FakeState {
                mapping_error: Some(mapping_error),
                open_error: Some(VaultMountManagerError::UnlockFailed),
                ..FakeState::default()
            }));
            assert_eq!(start_fake(Arc::clone(&state)).err(), Some(mapping_error));
            let absence_checked = state
                .lock()
                .expect("state")
                .steps
                .contains(&Step::FailedOpenAbsent);
            assert_eq!(
                absence_checked,
                mapping_error != VaultMountManagerError::CleanupFailed,
                "a child cleanup ambiguity must dominate before further inspection"
            );
        }

        for mapping_error in [
            VaultMountManagerError::ToolUnavailable,
            VaultMountManagerError::OperationTimedOut,
        ] {
            let state = Arc::new(Mutex::new(FakeState {
                mapping_error: Some(mapping_error),
                open_error: Some(VaultMountManagerError::CleanupFailed),
                ..FakeState::default()
            }));
            assert_eq!(
                start_fake(Arc::clone(&state)).err(),
                Some(VaultMountManagerError::CleanupFailed)
            );
            assert_eq!(
                state.lock().expect("state").steps,
                vec![
                    Step::DeviceUnused,
                    Step::MapperAbsent,
                    Step::Profile,
                    Step::Open,
                ],
                "an unreaped cryptsetup child forbids mapper inspection or close"
            );
        }
        assert_eq!(
            dominant_open_inspection_error(
                VaultMountManagerError::OperationTimedOut,
                VaultMountManagerError::ToolUnavailable,
            ),
            VaultMountManagerError::OperationTimedOut
        );
    }

    #[test]
    fn pre_mutation_start_failure_never_inspects_or_closes_a_mapper() {
        let state = Arc::new(Mutex::new(FakeState {
            open_error: Some(VaultMountManagerError::ToolUnavailable),
            ..FakeState::default()
        }));
        assert_eq!(
            start_fake(Arc::clone(&state)).err(),
            Some(VaultMountManagerError::ToolUnavailable)
        );
        assert_eq!(
            state.lock().expect("state").steps,
            vec![
                Step::DeviceUnused,
                Step::MapperAbsent,
                Step::Profile,
                Step::Open,
            ],
            "a child that never started cannot confer mapper ownership"
        );
    }

    #[test]
    fn pre_open_revalidation_failure_never_claims_mapper_ownership() {
        for expected in [
            VaultMountManagerError::InvalidBlockDevice,
            VaultMountManagerError::OperationTimedOut,
        ] {
            let state = Arc::new(Mutex::new(FakeState {
                pre_open_error: Some(expected),
                ..FakeState::default()
            }));
            assert_eq!(start_fake(Arc::clone(&state)).err(), Some(expected));
            let observed = state.lock().expect("state");
            assert_eq!(observed.pre_open_calls, 1);
            assert_eq!(observed.pre_mount_calls, 0);
            assert_eq!(
                observed.steps,
                vec![Step::DeviceUnused, Step::MapperAbsent, Step::Profile],
                "a read-only failure before spawn must not inspect or close a mapper"
            );
        }
    }

    #[test]
    fn pre_mount_revalidation_failure_never_claims_mount_ownership() {
        for expected in [
            VaultMountManagerError::InvalidBlockDevice,
            VaultMountManagerError::OperationTimedOut,
        ] {
            let state = Arc::new(Mutex::new(FakeState {
                pre_mount_error: Some(expected),
                ..FakeState::default()
            }));
            assert_eq!(start_fake(Arc::clone(&state)).err(), Some(expected));
            let observed = state.lock().expect("state");
            assert_eq!(observed.pre_open_calls, 1);
            assert_eq!(observed.pre_mount_calls, 1);
            assert_eq!(
                observed.steps,
                vec![
                    Step::DeviceUnused,
                    Step::MapperAbsent,
                    Step::Profile,
                    Step::Open,
                    Step::Mapping,
                    Step::ArmDeferred,
                    Step::VerifyDeferred,
                    Step::Profile,
                    Step::Filesystem,
                    Step::Prepare,
                    Step::VerifyMapping,
                    Step::WaitDeferredAbsent,
                ],
                "a read-only failure before mount must close only the owned mapper"
            );
        }
    }

    #[test]
    fn failure_after_open_closes_only_after_verification() {
        let state = Arc::new(Mutex::new(FakeState {
            steps: Vec::new(),
            fail_at: Some(Step::Filesystem),
            ..FakeState::default()
        }));
        assert_eq!(
            start_fake(Arc::clone(&state)).err(),
            Some(VaultMountManagerError::MountVerificationFailed)
        );
        assert_eq!(
            state.lock().expect("state").steps,
            vec![
                Step::DeviceUnused,
                Step::MapperAbsent,
                Step::Profile,
                Step::Open,
                Step::Mapping,
                Step::ArmDeferred,
                Step::VerifyDeferred,
                Step::Profile,
                Step::Filesystem,
                Step::VerifyMapping,
                Step::WaitDeferredAbsent,
            ]
        );
    }

    #[test]
    fn attestation_failure_verifies_and_cleans_mount_and_mapping() {
        let state = Arc::new(Mutex::new(FakeState {
            steps: Vec::new(),
            fail_at: Some(Step::Attest),
            ..FakeState::default()
        }));
        assert_eq!(
            start_fake(Arc::clone(&state)).err(),
            Some(VaultMountManagerError::MountVerificationFailed)
        );
        assert_eq!(
            state.lock().expect("state").steps,
            vec![
                Step::DeviceUnused,
                Step::MapperAbsent,
                Step::Profile,
                Step::Open,
                Step::Mapping,
                Step::ArmDeferred,
                Step::VerifyDeferred,
                Step::Profile,
                Step::Filesystem,
                Step::Prepare,
                Step::Mount,
                Step::MountedFilesystem,
                Step::Profile,
                Step::Attest,
                Step::VerifyMount,
                Step::Unmount,
                Step::VerifyUnmounted,
                Step::VerifyMapping,
                Step::WaitDeferredAbsent,
            ]
        );
    }

    #[test]
    fn cleanup_failure_dominates_every_post_mutator_primary_error() {
        let state = Arc::new(Mutex::new(FakeState {
            fail_at: Some(Step::Attest),
            cleanup_fail_at: Some(Step::Unmount),
            ..FakeState::default()
        }));
        assert_eq!(
            start_fake(Arc::clone(&state)).err(),
            Some(VaultMountManagerError::CleanupFailed)
        );
        let steps = &state.lock().expect("state").steps;
        assert!(steps.contains(&Step::Attest));
        assert!(steps.contains(&Step::VerifyMount));
        assert!(steps.contains(&Step::Unmount));
        assert!(!steps.contains(&Step::Close));
        assert!(!steps.contains(&Step::WaitDeferredAbsent));
        assert_eq!(
            steps.iter().filter(|step| **step == Step::Unmount).count(),
            1,
            "Drop must not silently retry cleanup after reporting its ambiguity"
        );
    }

    #[test]
    fn mount_mutator_error_runs_explicit_verified_cleanup() {
        let state = Arc::new(Mutex::new(FakeState {
            fail_at: Some(Step::Mount),
            ..FakeState::default()
        }));
        assert_eq!(
            start_fake(Arc::clone(&state)).err(),
            Some(VaultMountManagerError::MountVerificationFailed)
        );
        let steps = &state.lock().expect("state").steps;
        assert!(steps.contains(&Step::Mount));
        assert!(steps.contains(&Step::VerifyMount));
        assert!(steps.contains(&Step::Unmount));
        assert!(steps.contains(&Step::VerifyUnmounted));
        assert!(steps.contains(&Step::VerifyMapping));
        assert!(steps.contains(&Step::WaitDeferredAbsent));
        assert!(!steps.contains(&Step::Close));
    }

    #[test]
    fn successful_unmount_requires_a_double_checked_absence_postcondition() {
        let state = Arc::new(Mutex::new(FakeState {
            unmount_absence_proof_fails: true,
            ..FakeState::default()
        }));
        let mut activation = start_fake(Arc::clone(&state)).expect("activate");
        assert_eq!(
            activation.cleanup(),
            Err(VaultMountManagerError::CleanupFailed)
        );
        drop(activation);
        let steps = &state.lock().expect("state").steps;
        assert!(steps.contains(&Step::Unmount));
        assert!(steps.contains(&Step::VerifyUnmounted));
        assert!(!steps.contains(&Step::Close));
        assert!(!steps.contains(&Step::WaitDeferredAbsent));
    }

    #[test]
    fn deferred_cleanup_requires_a_bounded_absence_postcondition() {
        let state = Arc::new(Mutex::new(FakeState {
            deferred_absence_proof_fails: true,
            ..FakeState::default()
        }));
        let mut activation = start_fake(Arc::clone(&state)).expect("activate");
        assert_eq!(
            activation.cleanup(),
            Err(VaultMountManagerError::CleanupFailed)
        );
        drop(activation);
        let steps = &state.lock().expect("state").steps;
        assert!(steps.contains(&Step::WaitDeferredAbsent));
        assert!(!steps.contains(&Step::Close));
        assert_eq!(
            steps
                .iter()
                .filter(|step| **step == Step::WaitDeferredAbsent)
                .count(),
            1,
            "Drop must not retry an ambiguous deferred-removal wait"
        );
    }

    #[test]
    fn failed_deferred_arm_preserves_verified_explicit_close() {
        let state = Arc::new(Mutex::new(FakeState {
            fail_at: Some(Step::ArmDeferred),
            ..FakeState::default()
        }));
        assert_eq!(
            start_fake(Arc::clone(&state)).err(),
            Some(VaultMountManagerError::MountVerificationFailed)
        );
        assert_eq!(
            state.lock().expect("state").steps,
            vec![
                Step::DeviceUnused,
                Step::MapperAbsent,
                Step::Profile,
                Step::Open,
                Step::Mapping,
                Step::ArmDeferred,
                Step::VerifyMapping,
                Step::Close,
                Step::ClosedAbsent,
            ]
        );
    }

    #[test]
    fn pre_arm_close_requires_a_double_checked_absence_postcondition() {
        let state = Arc::new(Mutex::new(FakeState {
            fail_at: Some(Step::ArmDeferred),
            close_absence_proof_fails: true,
            ..FakeState::default()
        }));
        assert_eq!(
            start_fake(Arc::clone(&state)).err(),
            Some(VaultMountManagerError::CleanupFailed)
        );
        let steps = &state.lock().expect("state").steps;
        assert!(steps.contains(&Step::Close));
        assert!(steps.contains(&Step::ClosedAbsent));
        assert!(!steps.contains(&Step::WaitDeferredAbsent));
        assert_eq!(
            steps.iter().filter(|step| **step == Step::Close).count(),
            1,
            "Drop must not retry an ambiguous explicit close"
        );
    }

    #[test]
    fn post_arm_verification_failure_uses_only_deferred_removal() {
        let state = Arc::new(Mutex::new(FakeState {
            fail_at: Some(Step::VerifyDeferred),
            ..FakeState::default()
        }));
        assert_eq!(
            start_fake(Arc::clone(&state)).err(),
            Some(VaultMountManagerError::MountVerificationFailed)
        );
        let steps = &state.lock().expect("state").steps;
        assert!(steps.contains(&Step::ArmDeferred));
        assert!(steps.contains(&Step::VerifyDeferred));
        assert!(steps.contains(&Step::VerifyMapping));
        assert!(steps.contains(&Step::WaitDeferredAbsent));
        assert!(!steps.contains(&Step::Close));
    }

    #[test]
    fn failed_unmount_never_attempts_mapping_close() {
        let state = Arc::new(Mutex::new(FakeState {
            steps: Vec::new(),
            fail_at: Some(Step::Unmount),
            ..FakeState::default()
        }));
        let mut activation = start_fake(Arc::clone(&state)).expect("activate");
        assert!(activation.cleanup().is_err());
        drop(activation);
        let steps = &state.lock().expect("state").steps;
        assert!(steps.contains(&Step::Unmount));
        assert!(!steps.contains(&Step::Close));
        assert!(!steps.contains(&Step::WaitDeferredAbsent));
        assert_eq!(
            steps.iter().filter(|step| **step == Step::Unmount).count(),
            1
        );
    }

    #[test]
    fn failed_mount_ownership_check_never_unmounts_or_closes() {
        let state = Arc::new(Mutex::new(FakeState {
            steps: Vec::new(),
            fail_at: Some(Step::VerifyMount),
            ..FakeState::default()
        }));
        let mut activation = start_fake(Arc::clone(&state)).expect("activate");
        assert!(activation.cleanup().is_err());
        drop(activation);
        let steps = &state.lock().expect("state").steps;
        assert!(steps.contains(&Step::VerifyMount));
        assert!(!steps.contains(&Step::Unmount));
        assert!(!steps.contains(&Step::Close));
        assert!(!steps.contains(&Step::WaitDeferredAbsent));
        assert_eq!(
            steps
                .iter()
                .filter(|step| **step == Step::VerifyMount)
                .count(),
            1
        );
    }

    #[cfg(feature = "experimental-firstboot-provisioner")]
    #[test]
    fn firstboot_commands_match_canonical_v1_with_dynamic_bindings() {
        let luks_uuid = OsStr::new("11111111-1111-4111-8111-111111111111");
        let filesystem_uuid = OsStr::new("22222222-2222-4222-8222-222222222222");
        let mapper = MapperName::parse("kernaid-vault-0123456789abcdef").expect("mapper");

        let format = cryptsetup_format_command(Path::new("/proc/self/fd/7"), luks_uuid, "37");
        assert_eq!(format.get_program(), CRYPTSETUP_PATH);
        let format_args: Vec<_> = format.get_args().collect();
        assert_eq!(format_args[0], "luksFormat");
        assert_eq!(
            format_args
                .windows(2)
                .find(|pair| pair[0] == "--uuid")
                .map(|pair| pair[1]),
            Some(luks_uuid)
        );
        assert_eq!(
            format_args
                .windows(2)
                .find(|pair| pair[0] == "--keyfile-size")
                .map(|pair| pair[1]),
            Some(OsStr::new("37"))
        );
        assert_eq!(
            format_args.last().copied(),
            Some(OsStr::new("/proc/self/fd/7"))
        );

        let open = cryptsetup_open_sized_command(Path::new("/proc/self/fd/8"), &mapper, "37");
        let open_args: Vec<_> = open.get_args().collect();
        assert_eq!(open_args[0], "open");
        assert_eq!(
            &open_args[open_args.len() - 3..],
            [
                OsStr::new("37"),
                OsStr::new("/proc/self/fd/8"),
                OsStr::new("kernaid-vault-0123456789abcdef"),
            ]
        );

        let mkfs = mkfs_ext4_command(Path::new("/proc/self/fd/9"), filesystem_uuid);
        assert_eq!(mkfs.get_program(), MKFS_EXT4_PATH);
        let mkfs_args: Vec<_> = mkfs.get_args().collect();
        assert_eq!(
            mkfs_args
                .windows(2)
                .find(|pair| pair[0] == "-U")
                .map(|pair| pair[1]),
            Some(filesystem_uuid)
        );
        assert_eq!(
            mkfs_args.last().copied(),
            Some(OsStr::new("/proc/self/fd/9"))
        );

        let tune = tune2fs_command(Path::new("/proc/self/fd/10"));
        assert_eq!(tune.get_program(), TUNE2FS_PATH);
        assert_eq!(tune.get_args().last(), Some(OsStr::new("/proc/self/fd/10")));
    }

    #[cfg(feature = "experimental-firstboot-provisioner")]
    #[test]
    fn firstboot_uuid_and_mapper_generators_have_closed_grammars() {
        for _ in 0..16 {
            let uuid = random_uuid_v4().expect("uuid");
            assert_eq!(uuid.len(), 36);
            assert_eq!(uuid[14], b'4');
            assert!(matches!(uuid[19], b'8' | b'9' | b'a' | b'b'));
            assert!(uuid.iter().enumerate().all(|(index, byte)| {
                if matches!(index, 8 | 13 | 18 | 23) {
                    *byte == b'-'
                } else {
                    byte.is_ascii_digit() || (b'a'..=b'f').contains(byte)
                }
            }));
            let mapper = random_firstboot_mapper().expect("mapper");
            assert!(
                MapperName::parse(std::str::from_utf8(&mapper.bytes).expect("mapper ascii"))
                    .is_ok()
            );
        }
    }

    #[cfg(feature = "experimental-firstboot-provisioner")]
    #[test]
    fn firstboot_codex_home_has_the_exact_shipping_baseline() {
        let fixture = tempfile::tempdir().expect("temporary Codex-home fixture");
        let root = rfs::openat2(
            CWD,
            fixture.path(),
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
            ResolveFlags::NO_SYMLINKS | ResolveFlags::NO_MAGICLINKS,
        )
        .expect("open fixture root");
        let root_stat = rfs::fstat(&root).expect("fixture root stat");
        let mapping = MappingIdentity {
            descriptor: dummy_fd(),
            checkpoint_procfd: PathBuf::from("/proc/1/fd/9"),
            device: root_stat.st_dev,
            inode: root_stat.st_ino,
            rdev: root_stat.st_dev,
            major: rfs::major(root_stat.st_dev),
            minor: rfs::minor(root_stat.st_dev),
            backing_major: 7,
            backing_minor: 8,
            capacity_sectors: VAULT_PAYLOAD_BYTES / 512,
            logical_sector_bytes: LOGICAL_SECTOR_BYTES,
        };
        let owner = rustix::process::geteuid().as_raw();
        let group = rustix::process::getegid().as_raw();

        create_firstboot_codex_home_for(&root, &mapping, owner, group)
            .expect("create exact Codex home");

        let home = rfs::statat(&root, crate::CODEX_HOME_NAME, AtFlags::SYMLINK_NOFOLLOW)
            .expect("Codex home stat");
        assert!(FileType::from_raw_mode(home.st_mode).is_dir());
        assert_eq!((home.st_uid, home.st_gid), (owner, group));
        assert_eq!(home.st_mode & 0o7777, SECURE_DIRECTORY_MODE);

        let home_fd = open_firstboot_child_directory(&root, crate::CODEX_HOME_NAME)
            .expect("open exact Codex home");
        let config = rfs::statat(
            &home_fd,
            crate::CODEX_CONFIG_NAME,
            AtFlags::SYMLINK_NOFOLLOW,
        )
        .expect("Codex config stat");
        assert!(FileType::from_raw_mode(config.st_mode).is_file());
        assert_eq!((config.st_uid, config.st_gid), (owner, group));
        assert_eq!(config.st_mode & 0o7777, SECURE_FILE_MODE);
        assert_eq!(config.st_nlink, 1);
        assert_eq!(config.st_size, crate::CODEX_CONFIG_V1.len() as i64);
        assert_eq!(
            fs::read(
                fixture
                    .path()
                    .join(crate::CODEX_HOME_NAME)
                    .join(crate::CODEX_CONFIG_NAME)
            )
            .expect("read Codex config"),
            crate::CODEX_CONFIG_V1
        );
        assert_eq!(
            fs::read_dir(fixture.path().join(crate::CODEX_HOME_NAME))
                .expect("scan Codex home")
                .count(),
            1
        );
        assert!(create_firstboot_codex_home_for(&root, &mapping, owner, group).is_err());
    }

    #[cfg(feature = "experimental-firstboot-provisioner")]
    #[test]
    fn firstboot_formats_once_after_mapper_ownership_and_before_inspection() {
        let state = Arc::new(Mutex::new(FakeState::default()));
        let mut activation =
            start_fake_firstboot(Arc::clone(&state)).expect("firstboot activation");
        activation.cleanup().expect("verified cleanup");
        let steps = &state.lock().expect("state").steps;
        let position = |needle| {
            steps
                .iter()
                .position(|step| *step == needle)
                .expect("required lifecycle step")
        };
        assert!(position(Step::VerifyDeferred) < position(Step::FormatFilesystem));
        assert!(position(Step::FormatFilesystem) < position(Step::Filesystem));
        assert_eq!(
            steps
                .iter()
                .filter(|step| **step == Step::FormatFilesystem)
                .count(),
            1
        );
        assert!(position(Step::Unmount) < position(Step::WaitDeferredAbsent));
    }

    #[cfg(feature = "experimental-firstboot-provisioner")]
    #[test]
    fn firstboot_revalidates_retained_mounted_profile_without_premount_reinspection() {
        let state = Arc::new(Mutex::new(FakeState::default()));
        let mut activation =
            start_fake_firstboot(Arc::clone(&state)).expect("firstboot activation");
        let observed = revalidate_firstboot_filesystem(
            &mut activation,
            *b"22222222-2222-4222-8222-222222222222",
        )
        .expect("mounted firstboot profile");
        assert_eq!(
            observed.uuid_ascii(),
            *b"22222222-2222-4222-8222-222222222222"
        );

        let steps = &state.lock().expect("state").steps;
        assert_eq!(
            steps
                .iter()
                .filter(|step| **step == Step::Filesystem)
                .count(),
            1
        );
        assert_eq!(
            steps
                .iter()
                .filter(|step| **step == Step::MountedFilesystem)
                .count(),
            2
        );
    }

    #[cfg(feature = "experimental-firstboot-provisioner")]
    #[test]
    fn firstboot_format_failure_runs_verified_mapper_cleanup_without_mounting() {
        let state = Arc::new(Mutex::new(FakeState {
            fail_at: Some(Step::FormatFilesystem),
            ..FakeState::default()
        }));
        assert_eq!(
            start_fake_firstboot(Arc::clone(&state)).err(),
            Some(VaultMountManagerError::MountVerificationFailed)
        );
        let steps = &state.lock().expect("state").steps;
        assert!(steps.contains(&Step::FormatFilesystem));
        assert!(!steps.contains(&Step::Filesystem));
        assert!(!steps.contains(&Step::Mount));
        assert!(steps.contains(&Step::VerifyMapping));
        assert!(steps.contains(&Step::WaitDeferredAbsent));
    }
}
