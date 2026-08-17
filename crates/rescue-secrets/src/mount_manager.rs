//! Experimental privileged lifecycle for the Rescue LUKS2 secure-state vault.
//!
//! This module is disabled by default. It provides checkpoint-bound validation
//! in the current mount namespace; it is not a production claim of atomic
//! ownership against another privileged actor.

use super::{RescueSecretError, RescueVaultSecrets, VaultMountAttestation};
use crate::{
    bounded_process,
    device_locator::{LocatedVaultIdentity, LocatedVaultPartition},
    linux,
};
use rustix::{
    fd::{AsFd, OwnedFd},
    fs::{
        self as rfs, AtFlags, CWD, FileType, FlockOperation, Mode, OFlags, ResolveFlags, StatxFlags,
    },
    mount::{MountFlags, UnmountFlags},
};
use std::{
    error::Error,
    ffi::OsStr,
    fs::{self, File},
    os::fd::AsRawFd,
    os::unix::ffi::OsStrExt,
    path::{Component, Path, PathBuf},
    process::{Command, Stdio},
    time::Duration,
};

const MANAGER_LOCK_PATH: &str = "/run/lock/kernaid-rescue-vault-manager.lock";
const RUNTIME_ROOT: &str = "/run/kernaid";
const VAULT_MOUNT_PARENT: &str = "vault";
const CRYPTSETUP_PATH: &str = "/usr/sbin/cryptsetup";
const BLKID_PATH: &str = "/usr/sbin/blkid";
const VAULT_LABEL: &[u8] = b"KERNAID_VAULT";
const MAPPER_PREFIX: &str = "kernaid-vault-";
const MAPPER_SUFFIX_BYTES: usize = 16;
const MAPPER_NAME_BYTES: usize = MAPPER_PREFIX.len() + MAPPER_SUFFIX_BYTES;
const COMMAND_OUTPUT_LIMIT: usize = 4096;
const COMMAND_TIMEOUT: Duration = Duration::from_secs(30);
const SECURE_DIRECTORY_MODE: u32 = 0o700;
const SECURE_FILE_MODE: u32 = 0o600;

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
    InvalidLuks2Header,
    WrongVaultLabel,
    MapperConflict,
    PassphraseUnavailable,
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
            Self::InvalidLuks2Header => "the selected device is not the expected LUKS2 vault",
            Self::WrongVaultLabel => "the selected device is not labelled as a KernAid vault",
            Self::MapperConflict => "the selected Rescue mapper is already in use",
            Self::PassphraseUnavailable => "the Rescue vault passphrase descriptor is unavailable",
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
            Self::InvalidLuks2Header => "invalid-luks2-header",
            Self::WrongVaultLabel => "wrong-vault-label",
            Self::MapperConflict => "mapper-conflict",
            Self::PassphraseUnavailable => "passphrase-unavailable",
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
        let activation = Activation::start(SystemOps, self.lock, resolved, passphrase_fd)?;

        let attestation = activation
            .attestation
            .as_ref()
            .ok_or(VaultMountManagerError::MountVerificationFailed)?;
        let secrets = RescueVaultSecrets::open(&activation.request.mount_root, attestation)
            .map_err(map_secure_state_error)?;
        Ok(MountedRescueVault {
            secrets,
            activation,
        })
    }
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
    // Procfs handle to the retained descriptor in this daemon process. Child
    // tools open this exact capability even if the /dev name is replaced.
    command_path: PathBuf,
    descriptor: OwnedFd,
    device: u64,
    inode: u64,
    rdev: u64,
    disk_sequence: u64,
    capacity_sectors: u64,
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
            })
        {
            return Err(VaultMountManagerError::InvalidBlockDevice);
        }
        let (disk_sequence, capacity_sectors) =
            block_device_kernel_identity(major_minor.0, major_minor.1)?;
        if located_identity.is_some_and(|identity| {
            disk_sequence != identity.disk_sequence || capacity_sectors != identity.sector_count
        }) {
            return Err(VaultMountManagerError::InvalidBlockDevice);
        }
        let command_path = retained_descriptor_path(&descriptor)?;
        let result = Self {
            checkpoint_path: path,
            command_path,
            descriptor,
            device: stat.st_dev,
            inode: stat.st_ino,
            rdev: stat.st_rdev,
            disk_sequence,
            capacity_sectors,
            located_identity,
        };
        result.revalidate()?;
        Ok(result)
    }

    fn revalidate(&self) -> Result<(), VaultMountManagerError> {
        let descriptor =
            rfs::fstat(&self.descriptor).map_err(|_| VaultMountManagerError::InvalidBlockDevice)?;
        let named = rfs::statat(CWD, &self.checkpoint_path, AtFlags::SYMLINK_NOFOLLOW)
            .map_err(|_| VaultMountManagerError::InvalidBlockDevice)?;
        let command = rfs::statat(CWD, &self.command_path, AtFlags::empty())
            .map_err(|_| VaultMountManagerError::InvalidBlockDevice)?;
        let (major, minor) = self.major_minor();
        let (observed_sequence, observed_capacity) = block_device_kernel_identity(major, minor)?;
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
            || observed_sequence != self.disk_sequence
            || observed_capacity != self.capacity_sectors
            || self.located_identity.is_some_and(|identity| {
                (major, minor) != (identity.partition_major, identity.partition_minor)
                    || observed_sequence != identity.disk_sequence
                    || observed_capacity != identity.sector_count
            })
        {
            return Err(VaultMountManagerError::InvalidBlockDevice);
        }
        Ok(())
    }

    fn major_minor(&self) -> (u32, u32) {
        (rfs::major(self.rdev), rfs::minor(self.rdev))
    }

    fn command_path(&self) -> &Path {
        &self.command_path
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

#[derive(Clone, Copy)]
struct MappingIdentity {
    major: u32,
    minor: u32,
    backing_major: u32,
    backing_minor: u32,
}

struct Activation<R: VaultOps> {
    ops: R,
    _manager_lock: OwnedFd,
    request: ResolvedRequest,
    header: HeaderIdentity,
    mapping: Option<MappingIdentity>,
    attestation: Option<VaultMountAttestation>,
    mapping_open: bool,
    mounted: bool,
}

impl<R: VaultOps> Activation<R> {
    fn start(
        mut ops: R,
        manager_lock: OwnedFd,
        request: ResolvedRequest,
        passphrase: impl AsFd,
    ) -> Result<Self, VaultMountManagerError> {
        ops.ensure_device_unused(&request.device)?;
        ops.ensure_mapper_absent(&request.mapper, &request.mapper_path)?;
        let header = ops.inspect_header(&request.device)?;

        let mut activation = Self {
            ops,
            _manager_lock: manager_lock,
            request,
            header,
            mapping: None,
            attestation: None,
            mapping_open: false,
            mounted: false,
        };

        // The source descriptor was made CLOEXEC before any validation child
        // was spawned. Create the only duplicate at the last possible moment;
        // Command transfers it onto fd 0 and exec closes every other copy.
        let cryptsetup_passphrase = rustix::io::fcntl_dupfd_cloexec(&passphrase, 3)
            .map_err(|_| VaultMountManagerError::PassphraseUnavailable)?;
        let open_result = activation.ops.open_luks2(
            &activation.request.device,
            &activation.request.mapper,
            cryptsetup_passphrase,
        );
        drop(passphrase);

        // A spawn failure proves cryptsetup never ran, so do not acquire or
        // close a concurrently created mapping merely because it matches the
        // requested public identity.
        if open_result == Err(VaultMountManagerError::ToolUnavailable) {
            return Err(VaultMountManagerError::ToolUnavailable);
        }

        // cryptsetup may return an error after the kernel accepted the mapping
        // (for example after interruption). Acquire the complete mapping
        // identity stepwise so Drop can close it only when it is still exact.
        let mapping_result = activation.ops.inspect_mapping(
            &activation.request.device,
            &activation.request.mapper,
            &activation.request.mapper_path,
            activation.header,
        );
        match mapping_result {
            Ok(mapping) => {
                activation.mapping = Some(mapping);
                activation.mapping_open = true;
            }
            Err(mapping_error) => {
                if open_result.is_ok() {
                    // We know cryptsetup reported success, but we do not have
                    // enough identity to issue an ambiguous close.
                    activation.mapping_open = true;
                }
                return Err(open_result.err().unwrap_or(mapping_error));
            }
        }
        open_result?;
        let mapping = activation
            .mapping
            .ok_or(VaultMountManagerError::MappingVerificationFailed)?;
        activation
            .ops
            .inspect_filesystem(&activation.request.mapper_path, mapping)?;
        activation
            .ops
            .prepare_mount_root(&activation.request.mount_root)?;
        activation.ops.mount_ext4(
            &activation.request.mapper_path,
            &activation.request.mount_root,
        )?;
        activation.mounted = true;
        activation.attestation = Some(activation.ops.attest_mount(
            &activation.request,
            activation.header,
            mapping,
        )?);
        Ok(activation)
    }

    fn cleanup(&mut self) -> Result<(), VaultMountManagerError> {
        if self.mounted {
            let mapping = self.mapping.ok_or(VaultMountManagerError::CleanupFailed)?;
            self.ops.verify_cleanup_mount(
                &self.request,
                self.header,
                mapping,
                self.attestation.as_ref(),
            )?;
            self.ops.unmount(&self.request.mount_root)?;
            self.mounted = false;
        }
        if self.mapping_open {
            let mapping = self.mapping.ok_or(VaultMountManagerError::CleanupFailed)?;
            self.ops.verify_cleanup_mapping(
                &self.request.device,
                &self.request.mapper,
                &self.request.mapper_path,
                self.header,
                mapping,
            )?;
            self.ops.close_mapping(&self.request.mapper)?;
            self.mapping_open = false;
        }
        Ok(())
    }
}

impl<R: VaultOps> Drop for Activation<R> {
    fn drop(&mut self) {
        let _ = self.cleanup();
    }
}

trait VaultOps {
    fn ensure_device_unused(&mut self, device: &BlockDevice) -> Result<(), VaultMountManagerError>;
    fn ensure_mapper_absent(
        &mut self,
        mapper: &MapperName,
        mapper_path: &Path,
    ) -> Result<(), VaultMountManagerError>;
    fn inspect_header(
        &mut self,
        device: &BlockDevice,
    ) -> Result<HeaderIdentity, VaultMountManagerError>;
    fn open_luks2(
        &mut self,
        device: &BlockDevice,
        mapper: &MapperName,
        passphrase: OwnedFd,
    ) -> Result<(), VaultMountManagerError>;
    fn inspect_mapping(
        &mut self,
        device: &BlockDevice,
        mapper: &MapperName,
        mapper_path: &Path,
        header: HeaderIdentity,
    ) -> Result<MappingIdentity, VaultMountManagerError>;
    fn inspect_filesystem(
        &mut self,
        mapper_path: &Path,
        mapping: MappingIdentity,
    ) -> Result<(), VaultMountManagerError>;
    fn prepare_mount_root(&mut self, root: &Path) -> Result<(), VaultMountManagerError>;
    fn mount_ext4(&mut self, mapper_path: &Path, root: &Path)
    -> Result<(), VaultMountManagerError>;
    fn attest_mount(
        &mut self,
        request: &ResolvedRequest,
        header: HeaderIdentity,
        mapping: MappingIdentity,
    ) -> Result<VaultMountAttestation, VaultMountManagerError>;
    fn verify_cleanup_mount(
        &mut self,
        request: &ResolvedRequest,
        header: HeaderIdentity,
        mapping: MappingIdentity,
        attestation: Option<&VaultMountAttestation>,
    ) -> Result<(), VaultMountManagerError>;
    fn unmount(&mut self, root: &Path) -> Result<(), VaultMountManagerError>;
    fn verify_cleanup_mapping(
        &mut self,
        device: &BlockDevice,
        mapper: &MapperName,
        mapper_path: &Path,
        header: HeaderIdentity,
        expected: MappingIdentity,
    ) -> Result<(), VaultMountManagerError>;
    fn close_mapping(&mut self, mapper: &MapperName) -> Result<(), VaultMountManagerError>;
}

struct SystemOps;

impl SystemOps {
    fn run_capture(mut command: Command) -> Result<Vec<u8>, VaultMountManagerError> {
        command
            .env_clear()
            .env("LC_ALL", "C")
            .stdin(Stdio::null())
            .stderr(Stdio::null())
            .stdout(Stdio::piped());
        let output = bounded_process::capture(&mut command, COMMAND_TIMEOUT, COMMAND_OUTPUT_LIMIT)
            .map_err(map_bounded_process_error)?;
        if !output.status.success() || output.exceeded_limit {
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
        if rfs::statat(CWD, mapper_path, AtFlags::SYMLINK_NOFOLLOW).is_ok() {
            return Err(VaultMountManagerError::MapperConflict);
        }
        if sysfs_mapper_name_exists(mapper)? {
            return Err(VaultMountManagerError::MapperConflict);
        }
        Ok(())
    }

    fn inspect_header(
        &mut self,
        device: &BlockDevice,
    ) -> Result<HeaderIdentity, VaultMountManagerError> {
        device.revalidate()?;
        let mut uuid_command = Command::new(CRYPTSETUP_PATH);
        uuid_command
            .arg("luksUUID")
            .arg("--type")
            .arg("luks2")
            .arg(device.command_path());
        let uuid_output = Self::run_capture(uuid_command).map_err(|error| match error {
            VaultMountManagerError::ToolUnavailable => error,
            _ => VaultMountManagerError::InvalidLuks2Header,
        })?;
        let uuid =
            parse_uuid_line(&uuid_output).ok_or(VaultMountManagerError::InvalidLuks2Header)?;

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
            .arg("VERSION")
            .arg("--match-tag")
            .arg("UUID")
            .arg("--match-tag")
            .arg("LABEL")
            .arg(device.command_path());
        let properties = parse_blkid_export(&Self::run_capture(blkid).map_err(|error| {
            if error == VaultMountManagerError::ToolUnavailable {
                error
            } else {
                VaultMountManagerError::InvalidLuks2Header
            }
        })?)?;
        if properties.kind.as_deref() != Some(b"crypto_LUKS")
            || properties.version.as_deref() != Some(b"2")
            || properties.uuid != Some(uuid)
        {
            return Err(VaultMountManagerError::InvalidLuks2Header);
        }
        if properties.label.as_deref() != Some(VAULT_LABEL) {
            return Err(VaultMountManagerError::WrongVaultLabel);
        }
        device.revalidate()?;
        Ok(HeaderIdentity { uuid })
    }

    fn open_luks2(
        &mut self,
        device: &BlockDevice,
        mapper: &MapperName,
        passphrase: OwnedFd,
    ) -> Result<(), VaultMountManagerError> {
        device.revalidate()?;
        let mut command = cryptsetup_open_command(device.command_path(), mapper);
        command
            .env_clear()
            .env("LC_ALL", "C")
            .stdin(Stdio::from(File::from(passphrase)))
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        let status = bounded_process::wait(&mut command, COMMAND_TIMEOUT)
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
        Ok(MappingIdentity {
            major,
            minor,
            backing_major: backing.0,
            backing_minor: backing.1,
        })
    }

    fn inspect_filesystem(
        &mut self,
        mapper_path: &Path,
        _mapping: MappingIdentity,
    ) -> Result<(), VaultMountManagerError> {
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
            .arg(mapper_path);
        let output = Self::run_capture(blkid).map_err(|error| {
            if error == VaultMountManagerError::ToolUnavailable {
                error
            } else {
                VaultMountManagerError::UnsupportedFilesystem
            }
        })?;
        let properties = parse_blkid_export(&output)?;
        if properties.kind.as_deref() != Some(b"ext4")
            || properties.label.as_deref() != Some(VAULT_LABEL)
            || properties.uuid.is_none()
        {
            return Err(VaultMountManagerError::UnsupportedFilesystem);
        }
        Ok(())
    }

    fn prepare_mount_root(&mut self, root: &Path) -> Result<(), VaultMountManagerError> {
        prepare_runtime_mount_root(root)
    }

    fn mount_ext4(
        &mut self,
        mapper_path: &Path,
        root: &Path,
    ) -> Result<(), VaultMountManagerError> {
        rustix::mount::mount(
            mapper_path,
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

    fn attest_mount(
        &mut self,
        request: &ResolvedRequest,
        header: HeaderIdentity,
        mapping: MappingIdentity,
    ) -> Result<VaultMountAttestation, VaultMountManagerError> {
        linux::mint_managed_mount_attestation(
            &request.mount_root,
            request.mapper.as_fixed_bytes(),
            header.uuid,
            mapping.major,
            mapping.minor,
            mapping.backing_major,
            mapping.backing_minor,
        )
        .map_err(|_| VaultMountManagerError::MountVerificationFailed)
    }

    fn verify_cleanup_mount(
        &mut self,
        request: &ResolvedRequest,
        header: HeaderIdentity,
        mapping: MappingIdentity,
        attestation: Option<&VaultMountAttestation>,
    ) -> Result<(), VaultMountManagerError> {
        let current = linux::mint_managed_mount_attestation(
            &request.mount_root,
            request.mapper.as_fixed_bytes(),
            header.uuid,
            mapping.major,
            mapping.minor,
            mapping.backing_major,
            mapping.backing_minor,
        )
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

    fn verify_cleanup_mapping(
        &mut self,
        device: &BlockDevice,
        mapper: &MapperName,
        mapper_path: &Path,
        header: HeaderIdentity,
        expected: MappingIdentity,
    ) -> Result<(), VaultMountManagerError> {
        let observed = self
            .inspect_mapping(device, mapper, mapper_path, header)
            .map_err(|_| VaultMountManagerError::CleanupFailed)?;
        if observed.major != expected.major
            || observed.minor != expected.minor
            || observed.backing_major != expected.backing_major
            || observed.backing_minor != expected.backing_minor
        {
            return Err(VaultMountManagerError::CleanupFailed);
        }
        Ok(())
    }

    fn close_mapping(&mut self, mapper: &MapperName) -> Result<(), VaultMountManagerError> {
        let mut command = Command::new(CRYPTSETUP_PATH);
        command.arg("close").arg(mapper.as_os_str());
        Self::run_quiet(command)
    }
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
    let runtime = open_or_create_child_directory(&run, OsStr::new("kernaid"))?;
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

fn block_device_kernel_identity(
    major: u32,
    minor: u32,
) -> Result<(u64, u64), VaultMountManagerError> {
    let sysfs = PathBuf::from(format!("/sys/dev/block/{major}:{minor}"));
    let observed_device = read_small_block_file(&sysfs.join("dev"))?;
    if parse_major_minor(trim_line(&observed_device)) != Some((major, minor)) {
        return Err(VaultMountManagerError::InvalidBlockDevice);
    }
    let capacity = parse_u64(trim_line(&read_small_block_file(&sysfs.join("size"))?))
        .filter(|value| *value > 0)
        .ok_or(VaultMountManagerError::InvalidBlockDevice)?;

    let sequence_path = if sysfs.join("diskseq").is_file() {
        sysfs.join("diskseq")
    } else {
        // Partitions expose the containing disk's sequence in their canonical
        // sysfs parent. BLKGETDISKSEQ is not available through safe rustix;
        // this kernel-owned value is retained as a fail-closed experimental
        // identity checkpoint until an ioctl-safe wrapper is adopted.
        let canonical =
            fs::canonicalize(&sysfs).map_err(|_| VaultMountManagerError::InvalidBlockDevice)?;
        if !canonical.starts_with("/sys/devices") {
            return Err(VaultMountManagerError::InvalidBlockDevice);
        }
        canonical
            .parent()
            .ok_or(VaultMountManagerError::InvalidBlockDevice)?
            .join("diskseq")
    };
    let sequence = parse_u64(trim_line(&read_small_block_file(&sequence_path)?))
        .filter(|value| *value > 0)
        .ok_or(VaultMountManagerError::InvalidBlockDevice)?;
    Ok((sequence, capacity))
}

fn read_small_block_file(path: &Path) -> Result<Vec<u8>, VaultMountManagerError> {
    let bytes = fs::read(path).map_err(|_| VaultMountManagerError::InvalidBlockDevice)?;
    if bytes.len() > 64 {
        return Err(VaultMountManagerError::InvalidBlockDevice);
    }
    Ok(bytes)
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

fn parse_u64(value: &[u8]) -> Option<u64> {
    if value.is_empty() || !value.iter().all(u8::is_ascii_digit) {
        return None;
    }
    let mut parsed = 0_u64;
    for byte in value {
        parsed = parsed
            .checked_mul(10)?
            .checked_add(u64::from(byte - b'0'))?;
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
        bounded_process::BoundedProcessError::Unavailable => {
            VaultMountManagerError::ToolUnavailable
        }
        bounded_process::BoundedProcessError::TimedOut => VaultMountManagerError::OperationTimedOut,
        bounded_process::BoundedProcessError::CleanupFailed => {
            VaultMountManagerError::CleanupFailed
        }
        bounded_process::BoundedProcessError::StartFailed
        | bounded_process::BoundedProcessError::WaitFailed
        | bounded_process::BoundedProcessError::UnexpectedDescendant => {
            VaultMountManagerError::MappingVerificationFailed
        }
    }
}

fn map_secure_state_error(_error: RescueSecretError) -> VaultMountManagerError {
    VaultMountManagerError::SecureStateUnavailable
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::MountAttestationClaims;
    use std::sync::{Arc, Mutex};

    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    enum Step {
        DeviceUnused,
        MapperAbsent,
        Header,
        Open,
        Mapping,
        Filesystem,
        Prepare,
        Mount,
        Attest,
        VerifyMount,
        Unmount,
        VerifyMapping,
        Close,
    }

    #[derive(Default)]
    struct FakeState {
        steps: Vec<Step>,
        fail_at: Option<Step>,
    }

    #[derive(Clone)]
    struct FakeOps(Arc<Mutex<FakeState>>);

    impl FakeOps {
        fn step(&self, step: Step) -> Result<(), VaultMountManagerError> {
            let mut state = self.0.lock().expect("fake state lock");
            state.steps.push(step);
            if state.fail_at == Some(step) {
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

        fn inspect_header(
            &mut self,
            _device: &BlockDevice,
        ) -> Result<HeaderIdentity, VaultMountManagerError> {
            self.step(Step::Header)?;
            Ok(HeaderIdentity {
                uuid: *b"a9950603-ffce-492a-b082-43fba5c492a1",
            })
        }

        fn open_luks2(
            &mut self,
            _device: &BlockDevice,
            _mapper: &MapperName,
            _passphrase: OwnedFd,
        ) -> Result<(), VaultMountManagerError> {
            self.step(Step::Open)
        }

        fn inspect_mapping(
            &mut self,
            _device: &BlockDevice,
            _mapper: &MapperName,
            _mapper_path: &Path,
            _header: HeaderIdentity,
        ) -> Result<MappingIdentity, VaultMountManagerError> {
            self.step(Step::Mapping)?;
            Ok(MappingIdentity {
                major: 253,
                minor: 7,
                backing_major: 7,
                backing_minor: 8,
            })
        }

        fn inspect_filesystem(
            &mut self,
            _mapper_path: &Path,
            _mapping: MappingIdentity,
        ) -> Result<(), VaultMountManagerError> {
            self.step(Step::Filesystem)
        }

        fn prepare_mount_root(&mut self, _root: &Path) -> Result<(), VaultMountManagerError> {
            self.step(Step::Prepare)
        }

        fn mount_ext4(
            &mut self,
            _mapper_path: &Path,
            _root: &Path,
        ) -> Result<(), VaultMountManagerError> {
            self.step(Step::Mount)
        }

        fn attest_mount(
            &mut self,
            request: &ResolvedRequest,
            header: HeaderIdentity,
            mapping: MappingIdentity,
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
                },
            })
        }

        fn verify_cleanup_mount(
            &mut self,
            _request: &ResolvedRequest,
            _header: HeaderIdentity,
            _mapping: MappingIdentity,
            _attestation: Option<&VaultMountAttestation>,
        ) -> Result<(), VaultMountManagerError> {
            self.step(Step::VerifyMount)
        }

        fn unmount(&mut self, _root: &Path) -> Result<(), VaultMountManagerError> {
            self.step(Step::Unmount)
        }

        fn verify_cleanup_mapping(
            &mut self,
            _device: &BlockDevice,
            _mapper: &MapperName,
            _mapper_path: &Path,
            _header: HeaderIdentity,
            _expected: MappingIdentity,
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
                command_path: PathBuf::from("/proc/1/fd/8"),
                descriptor,
                device: 1,
                inode: 2,
                rdev: rfs::makedev(7, 8),
                disk_sequence: 12,
                capacity_sectors: 524_288,
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
        let command_path = retained_descriptor_path(&retained).expect("retained procfd path");

        fs::rename(&named, &moved).expect("move original fixture");
        fs::write(&named, b"replacement").expect("write replacement fixture");

        assert_eq!(
            fs::read(&command_path).expect("read retained procfd"),
            b"original"
        );
        assert_eq!(
            fs::read(&named).expect("read named replacement"),
            b"replacement"
        );
    }

    #[test]
    fn manager_error_codes_are_closed_sanitized_literals() {
        let errors = [
            VaultMountManagerError::UnsupportedPlatform,
            VaultMountManagerError::PrivilegeRequired,
            VaultMountManagerError::ManagerLocked,
            VaultMountManagerError::InvalidBlockDevice,
            VaultMountManagerError::InvalidMapperName,
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
    fn parsers_reject_ambiguous_identity_data() {
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
    fn unlock_command_has_only_procfd_device_and_stdin_key_source() {
        let mapper = MapperName::parse("kernaid-vault-0123456789abcdef").expect("mapper");
        let command = cryptsetup_open_command(Path::new("/proc/123/fd/8"), &mapper);
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
                OsStr::new("/proc/123/fd/8"),
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
                Step::Header,
                Step::Open,
                Step::Mapping,
                Step::Filesystem,
                Step::Prepare,
                Step::Mount,
                Step::Attest,
                Step::VerifyMount,
                Step::Unmount,
                Step::VerifyMapping,
                Step::Close,
            ]
        );
    }

    #[test]
    fn ambiguous_open_error_acquires_mapping_identity_then_cleans_it() {
        let state = Arc::new(Mutex::new(FakeState {
            steps: Vec::new(),
            fail_at: Some(Step::Open),
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
                Step::Header,
                Step::Open,
                Step::Mapping,
                Step::VerifyMapping,
                Step::Close,
            ]
        );
    }

    #[test]
    fn failure_after_open_closes_only_after_verification() {
        let state = Arc::new(Mutex::new(FakeState {
            steps: Vec::new(),
            fail_at: Some(Step::Filesystem),
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
                Step::Header,
                Step::Open,
                Step::Mapping,
                Step::Filesystem,
                Step::VerifyMapping,
                Step::Close,
            ]
        );
    }

    #[test]
    fn attestation_failure_verifies_and_cleans_mount_and_mapping() {
        let state = Arc::new(Mutex::new(FakeState {
            steps: Vec::new(),
            fail_at: Some(Step::Attest),
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
                Step::Header,
                Step::Open,
                Step::Mapping,
                Step::Filesystem,
                Step::Prepare,
                Step::Mount,
                Step::Attest,
                Step::VerifyMount,
                Step::Unmount,
                Step::VerifyMapping,
                Step::Close,
            ]
        );
    }

    #[test]
    fn failed_unmount_never_attempts_mapping_close() {
        let state = Arc::new(Mutex::new(FakeState {
            steps: Vec::new(),
            fail_at: Some(Step::Unmount),
        }));
        let mut activation = start_fake(Arc::clone(&state)).expect("activate");
        assert!(activation.cleanup().is_err());
        // Prevent Drop from retrying so this assertion describes one cleanup attempt.
        activation.mounted = false;
        activation.mapping_open = false;
        drop(activation);
        let steps = &state.lock().expect("state").steps;
        assert!(steps.contains(&Step::Unmount));
        assert!(!steps.contains(&Step::Close));
    }

    #[test]
    fn failed_mount_ownership_check_never_unmounts_or_closes() {
        let state = Arc::new(Mutex::new(FakeState {
            steps: Vec::new(),
            fail_at: Some(Step::VerifyMount),
        }));
        let mut activation = start_fake(Arc::clone(&state)).expect("activate");
        assert!(activation.cleanup().is_err());
        activation.mounted = false;
        activation.mapping_open = false;
        drop(activation);
        let steps = &state.lock().expect("state").steps;
        assert!(steps.contains(&Step::VerifyMount));
        assert!(!steps.contains(&Step::Unmount));
        assert!(!steps.contains(&Step::Close));
    }
}
