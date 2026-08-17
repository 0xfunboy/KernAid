//! Read-only discovery of the vault partition belonging to the exact Rescue
//! boot medium.
//!
//! Discovery starts at the fixed `/run/live/medium` mount, walks only its
//! kernel sysfs ancestry, and accepts only sibling MBR slot 3 with the pinned
//! layout-v1 geometry. It never searches all disks and has no caller-supplied
//! device or path parameter.

use crate::bounded_process;
#[cfg(feature = "experimental-vault-manager")]
use crate::profile_classifier::{
    ProfileClassifierError, VaultPartitionProfile, classify_partition_with_timeout,
};
use rustix::fs::{self as rfs, AtFlags, CWD, FileType, Mode, OFlags};
use std::{
    collections::BTreeMap,
    error::Error,
    ffi::{OsStr, OsString},
    fmt, fs, io,
    os::{
        fd::{AsFd, AsRawFd, BorrowedFd},
        unix::{ffi::OsStrExt, fs::FileExt},
    },
    path::{Path, PathBuf},
    process::{Command, Stdio},
    time::{Duration, Instant},
};

const LIVE_MEDIUM_MOUNT: &[u8] = b"/run/live/medium";
const ISO9660: &[u8] = b"iso9660";
const BLOCKDEV_PATH: &str = "/usr/sbin/blockdev";
const BLOCKDEV_TIMEOUT: Duration = Duration::from_secs(2);
const BLOCKDEV_OUTPUT_LIMIT: usize = 64;
const KERNEL_SECTOR_BYTES: u64 = 512;
#[cfg(feature = "experimental-vault-manager")]
const MAX_CLASSIFICATION_TIMEOUT: Duration = Duration::from_secs(10 * 60);
const MAX_MOUNTINFO_BYTES: usize = 256 * 1024;
const MAX_MOUNTINFO_LINES: usize = 4096;
const MAX_MOUNTINFO_LINE_BYTES: usize = 4096;
const MAX_SYSFS_BYTES: usize = 4096;
const MAX_SYSFS_CHILDREN: usize = 128;
const LOGICAL_SECTOR_BYTES: u64 = 512;
const MINIMUM_MEDIA_BYTES: u64 = 32_000_000_000;
const VAULT_PARTITION_NUMBER: u64 = 3;
const VAULT_START_LBA: u64 = 33_554_432;
const VAULT_SECTOR_COUNT: u64 = 16_777_216;
const MBR_BYTES: usize = 512;
const MBR_PARTITION_TABLE_OFFSET: usize = 446;
const MBR_PARTITION_BYTES: usize = 16;
const MBR_SIGNATURE_OFFSET: usize = 510;
const EXPECTED_VAULT_MBR_ENTRY: [u8; MBR_PARTITION_BYTES] = [
    0x00, 0xfe, 0xff, 0xff, 0x83, 0xfe, 0xff, 0xff, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x01,
];

/// Stable, path-free identity retained alongside the read-only p3 descriptor.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct LocatedVaultIdentity {
    pub parent_major: u32,
    pub parent_minor: u32,
    pub partition_major: u32,
    pub partition_minor: u32,
    pub disk_sequence: u64,
    pub logical_sector_bytes: u64,
    pub media_sector_count: u64,
    pub start_lba: u64,
    pub sector_count: u64,
}

/// The exact p3 descriptor opened read-only after two complete kernel
/// topology and BLKGETDISKSEQ checkpoints.
pub struct LocatedVaultPartition {
    descriptor: fs::File,
    identity: LocatedVaultIdentity,
    #[cfg(feature = "experimental-vault-manager")]
    device_name: OsString,
}

/// Read-only classification of the exact retained vault partition.
#[cfg(feature = "experimental-vault-manager")]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LocatedVaultClassification {
    /// Every byte in the fixed partition capability is zero.
    Unprovisioned,
    /// Both redundant LUKS2 headers match the pinned outer profile.
    Locked,
}

/// Closed failures from descriptor-bound read-only classification.
#[cfg(feature = "experimental-vault-manager")]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LocatedVaultClassificationError {
    InvalidDeadline,
    ClassifierUnavailable,
    MediaChanged,
    ProfileMismatch,
    BlockIdentityUnavailable,
    ToolUnavailable,
    OperationTimedOut,
    CleanupFailed,
}

#[cfg(feature = "experimental-vault-manager")]
impl fmt::Display for LocatedVaultClassificationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::InvalidDeadline => "the vault classification deadline is invalid",
            Self::ClassifierUnavailable => "the pinned vault classifier is unavailable",
            Self::MediaChanged => "the Rescue vault partition changed during classification",
            Self::ProfileMismatch => "the Rescue vault partition profile does not match",
            Self::BlockIdentityUnavailable => "the Rescue vault block identity is unavailable",
            Self::ToolUnavailable => "required read-only block identity tool is unavailable",
            Self::OperationTimedOut => "vault profile inspection timed out",
            Self::CleanupFailed => "the read-only identity probe could not be cleaned up",
        })
    }
}

#[cfg(feature = "experimental-vault-manager")]
impl Error for LocatedVaultClassificationError {}

impl fmt::Debug for LocatedVaultPartition {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("LocatedVaultPartition")
            .field("identity", &self.identity)
            .field("access", &"read-only")
            .finish()
    }
}

impl LocatedVaultPartition {
    pub fn identity(&self) -> LocatedVaultIdentity {
        self.identity
    }

    /// Transfers the already-opened read-only partition descriptor. No device
    /// pathname is exposed.
    pub fn into_file(self) -> fs::File {
        self.descriptor
    }

    /// Classify this exact retained partition without opening, mounting or
    /// writing it. The caller supplies a non-zero checkpoint deadline capped
    /// at ten minutes; descriptor identity is revalidated throughout the
    /// scan. Synchronous kernel block reads can return after that deadline if
    /// the device stalls in uninterruptible I/O; timeout is reported as soon
    /// as control returns to user space.
    #[cfg(feature = "experimental-vault-manager")]
    pub fn classify_read_only(
        &self,
        timeout: Duration,
    ) -> Result<LocatedVaultClassification, LocatedVaultClassificationError> {
        let deadline = classification_deadline(timeout)?;
        self.validate_classification_identity(deadline)?;
        let scan_timeout = deadline
            .checked_duration_since(Instant::now())
            .filter(|remaining| !remaining.is_zero())
            .ok_or(LocatedVaultClassificationError::OperationTimedOut)?;
        let mut checkpoint_failure = None;
        let result = classify_partition_with_timeout(&self.descriptor, scan_timeout, || {
            if Instant::now() >= deadline {
                checkpoint_failure = Some(LocatedVaultClassificationError::OperationTimedOut);
                return Err(ProfileClassifierError::OperationTimedOut);
            }
            if validate_block_descriptor(
                &self.descriptor,
                (self.identity.partition_major, self.identity.partition_minor),
            )
            .is_err()
            {
                checkpoint_failure = Some(LocatedVaultClassificationError::MediaChanged);
                return Err(ProfileClassifierError::MediaChanged);
            }
            Ok(())
        });
        if let Some(error) = checkpoint_failure {
            return Err(error);
        }
        if result != Err(ProfileClassifierError::OperationTimedOut) {
            self.validate_classification_identity(deadline)?;
        }
        match result {
            Ok(VaultPartitionProfile::Unprovisioned) => {
                Ok(LocatedVaultClassification::Unprovisioned)
            }
            Ok(VaultPartitionProfile::Locked(_)) => Ok(LocatedVaultClassification::Locked),
            Ok(VaultPartitionProfile::ProfileMismatch) => {
                Err(LocatedVaultClassificationError::ProfileMismatch)
            }
            Err(ProfileClassifierError::InvalidCanonicalProfile) => {
                Err(LocatedVaultClassificationError::ClassifierUnavailable)
            }
            Err(
                ProfileClassifierError::InvalidDescriptor | ProfileClassifierError::MediaChanged,
            ) => Err(LocatedVaultClassificationError::MediaChanged),
            Err(ProfileClassifierError::OperationTimedOut) => {
                Err(LocatedVaultClassificationError::OperationTimedOut)
            }
        }
    }

    /// Classify the retained partition and, for the locked state, prove that
    /// no kernel holder or mount survives for the exact p3 major:minor. This
    /// is the only classification suitable for clearing the daemon lifecycle
    /// marker after a failed unlock, lock, or shutdown attempt.
    ///
    /// The proof is bracketed by full descriptor identity checkpoints and by
    /// two holder scans around a strict, bounded `/proc/self/mountinfo` scan.
    /// Any residue, malformed kernel view, or observation failure is reported
    /// as cleanup failure; it can never be represented as safely locked.
    #[cfg(feature = "experimental-vault-manager")]
    pub fn classify_quiescent_read_only(
        &self,
        timeout: Duration,
    ) -> Result<LocatedVaultClassification, LocatedVaultClassificationError> {
        let deadline = classification_deadline(timeout)?;
        let remaining = remaining_classification_time(deadline)?;
        let classification = self.classify_read_only(remaining)?;
        if classification == LocatedVaultClassification::Locked {
            self.validate_classification_identity(deadline)?;
            verify_no_partition_holders(self.identity, deadline)?;
            verify_partition_not_mounted(self.identity, deadline)?;
            verify_no_partition_holders(self.identity, deadline)?;
            self.validate_classification_identity(deadline)?;
        }
        Ok(classification)
    }

    #[cfg(feature = "experimental-vault-manager")]
    fn validate_classification_identity(
        &self,
        deadline: Instant,
    ) -> Result<(), LocatedVaultClassificationError> {
        validate_block_descriptor(
            &self.descriptor,
            (self.identity.partition_major, self.identity.partition_minor),
        )
        .map_err(|_| LocatedVaultClassificationError::MediaChanged)?;
        let observed = descriptor_block_identity_until(&self.descriptor, deadline)
            .map_err(map_classification_identity_error)?;
        if observed.disk_sequence != self.identity.disk_sequence
            || observed.sector_count != self.identity.sector_count
            || observed.logical_sector_bytes != self.identity.logical_sector_bytes
        {
            return Err(LocatedVaultClassificationError::MediaChanged);
        }
        Ok(())
    }

    /// Transfers the sealed locator result to the experimental mount manager.
    ///
    /// The validated kernel device name remains crate-private: neither an IPC
    /// client nor another external caller can turn this capability back into a
    /// selectable pathname.
    #[cfg(feature = "experimental-vault-manager")]
    pub(crate) fn into_manager_parts(self) -> (fs::File, LocatedVaultIdentity, OsString) {
        (self.descriptor, self.identity, self.device_name)
    }
}

#[cfg(feature = "experimental-vault-manager")]
fn classification_deadline(timeout: Duration) -> Result<Instant, LocatedVaultClassificationError> {
    if timeout.is_zero() || timeout > MAX_CLASSIFICATION_TIMEOUT {
        return Err(LocatedVaultClassificationError::InvalidDeadline);
    }
    Instant::now()
        .checked_add(timeout)
        .ok_or(LocatedVaultClassificationError::InvalidDeadline)
}

#[cfg(feature = "experimental-vault-manager")]
fn remaining_classification_time(
    deadline: Instant,
) -> Result<Duration, LocatedVaultClassificationError> {
    deadline
        .checked_duration_since(Instant::now())
        .filter(|remaining| !remaining.is_zero())
        .ok_or(LocatedVaultClassificationError::OperationTimedOut)
}

#[cfg(feature = "experimental-vault-manager")]
fn verify_no_partition_holders(
    identity: LocatedVaultIdentity,
    deadline: Instant,
) -> Result<(), LocatedVaultClassificationError> {
    remaining_classification_time(deadline)?;
    let link = PathBuf::from(format!(
        "/sys/dev/block/{}:{}",
        identity.partition_major, identity.partition_minor
    ));
    let device =
        fs::canonicalize(&link).map_err(|_| LocatedVaultClassificationError::CleanupFailed)?;
    let sys_devices = fs::canonicalize("/sys/devices")
        .map_err(|_| LocatedVaultClassificationError::CleanupFailed)?;
    if device == sys_devices
        || !device.starts_with(&sys_devices)
        || read_major_minor(&device.join("dev")).ok()
            != Some((identity.partition_major, identity.partition_minor))
    {
        return Err(LocatedVaultClassificationError::CleanupFailed);
    }
    let entries = fs::read_dir(device.join("holders"))
        .map_err(|_| LocatedVaultClassificationError::CleanupFailed)?;
    let mut count = 0_usize;
    for entry in entries {
        remaining_classification_time(deadline)?;
        entry.map_err(|_| LocatedVaultClassificationError::CleanupFailed)?;
        count = count
            .checked_add(1)
            .ok_or(LocatedVaultClassificationError::CleanupFailed)?;
        if count > MAX_SYSFS_CHILDREN {
            return Err(LocatedVaultClassificationError::CleanupFailed);
        }
    }
    if count == 0 {
        Ok(())
    } else {
        Err(LocatedVaultClassificationError::CleanupFailed)
    }
}

#[cfg(feature = "experimental-vault-manager")]
fn verify_partition_not_mounted(
    identity: LocatedVaultIdentity,
    deadline: Instant,
) -> Result<(), LocatedVaultClassificationError> {
    remaining_classification_time(deadline)?;
    let bytes = read_bounded(Path::new("/proc/self/mountinfo"), MAX_MOUNTINFO_BYTES)
        .map_err(|_| LocatedVaultClassificationError::CleanupFailed)?;
    if mountinfo_excludes_device(&bytes, (identity.partition_major, identity.partition_minor)) {
        Ok(())
    } else {
        Err(LocatedVaultClassificationError::CleanupFailed)
    }
}

#[cfg(feature = "experimental-vault-manager")]
fn mountinfo_excludes_device(bytes: &[u8], expected: (u32, u32)) -> bool {
    if bytes.is_empty() || !bytes.ends_with(b"\n") {
        return false;
    }
    let mut count = 0_usize;
    for line in bytes[..bytes.len() - 1].split(|byte| *byte == b'\n') {
        if line.is_empty() || line.len() > MAX_MOUNTINFO_LINE_BYTES {
            return false;
        }
        count = match count.checked_add(1) {
            Some(count) if count <= MAX_MOUNTINFO_LINES => count,
            _ => return false,
        };
        let fields: Vec<&[u8]> = line.split(|byte| *byte == b' ').collect();
        if fields.iter().any(|field| field.is_empty()) {
            return false;
        }
        let mut separators = fields
            .iter()
            .enumerate()
            .filter(|(_, field)| **field == b"-");
        let Some((separator, _)) = separators.next() else {
            return false;
        };
        if separators.next().is_some() {
            return false;
        }
        let post_separator_minimum = separator.checked_add(4);
        if fields.len() < 10
            || separator < 6
            || post_separator_minimum != Some(fields.len())
            || parse_major_minor(fields[2]).is_none()
        {
            return false;
        }
        if parse_major_minor(fields[2]) == Some(expected) {
            return false;
        }
    }
    count > 0
}

#[cfg(feature = "experimental-vault-manager")]
fn map_classification_identity_error(
    error: DescriptorBlockIdentityError,
) -> LocatedVaultClassificationError {
    match error {
        DescriptorBlockIdentityError::InvalidDescriptor => {
            LocatedVaultClassificationError::MediaChanged
        }
        DescriptorBlockIdentityError::IdentityUnavailable => {
            LocatedVaultClassificationError::BlockIdentityUnavailable
        }
        DescriptorBlockIdentityError::ToolUnavailable => {
            LocatedVaultClassificationError::ToolUnavailable
        }
        DescriptorBlockIdentityError::OperationTimedOut => {
            LocatedVaultClassificationError::OperationTimedOut
        }
        DescriptorBlockIdentityError::CleanupFailed => {
            LocatedVaultClassificationError::CleanupFailed
        }
    }
}

impl AsFd for LocatedVaultPartition {
    fn as_fd(&self) -> BorrowedFd<'_> {
        self.descriptor.as_fd()
    }
}

/// Successful boot-medium classification. Optical boot is deliberately a
/// normal, distinct absence state: an optical disc cannot contain writable
/// persistence beyond the ISO image and no other disk is searched.
#[derive(Debug)]
pub enum BootVaultLocation {
    OpticalBootAbsent,
    Vault(LocatedVaultPartition),
}

/// Fixed, non-sensitive locator failures. No variant stores an OS error,
/// device name, or filesystem path.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BootVaultLocatorError {
    BootMediumAbsent,
    AmbiguousBootMedium,
    UnsupportedBootMedium,
    VaultPartitionAbsent,
    AmbiguousVaultPartition,
    InvalidKernelIdentity,
    InvalidVaultGeometry,
    MediaChanged,
    BlockDeviceUnavailable,
    BlockIdentityUnavailable,
    ToolUnavailable,
    OperationTimedOut,
    CleanupFailed,
}

impl fmt::Display for BootVaultLocatorError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::BootMediumAbsent => "Rescue boot medium is absent",
            Self::AmbiguousBootMedium => "Rescue boot medium identity is ambiguous",
            Self::UnsupportedBootMedium => "Rescue boot medium is not an optical disc or USB disk",
            Self::VaultPartitionAbsent => "Rescue boot medium has no vault partition",
            Self::AmbiguousVaultPartition => "Rescue vault partition identity is ambiguous",
            Self::InvalidKernelIdentity => "Rescue boot medium kernel identity is invalid",
            Self::InvalidVaultGeometry => "Rescue vault partition geometry is invalid",
            Self::MediaChanged => "Rescue boot medium changed during discovery",
            Self::BlockDeviceUnavailable => "Rescue vault block device is unavailable",
            Self::BlockIdentityUnavailable => "Rescue vault block identity is unavailable",
            Self::ToolUnavailable => "required read-only block identity tool is unavailable",
            Self::OperationTimedOut => "Rescue vault block identity inspection timed out",
            Self::CleanupFailed => "Rescue vault block identity probe could not be cleaned up",
        })
    }
}

impl BootVaultLocatorError {
    /// Stable, redacted category for the privileged service boundary.
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::BootMediumAbsent => "boot-medium-absent",
            Self::AmbiguousBootMedium => "ambiguous-boot-medium",
            Self::UnsupportedBootMedium => "unsupported-boot-medium",
            Self::VaultPartitionAbsent => "vault-partition-absent",
            Self::AmbiguousVaultPartition => "ambiguous-vault-partition",
            Self::InvalidKernelIdentity => "invalid-kernel-identity",
            Self::InvalidVaultGeometry => "invalid-vault-geometry",
            Self::MediaChanged => "media-changed",
            Self::BlockDeviceUnavailable => "block-device-unavailable",
            Self::BlockIdentityUnavailable => "block-identity-unavailable",
            Self::ToolUnavailable => "tool-unavailable",
            Self::OperationTimedOut => "operation-timed-out",
            Self::CleanupFailed => "cleanup-failed",
        }
    }
}

impl Error for BootVaultLocatorError {}

/// Locates p3 belonging to the exact medium mounted at `/run/live/medium`.
///
/// This function accepts no caller-controlled path or device. It performs no
/// activation, mount, unlock, repair, or write operation.
pub fn locate_boot_vault() -> Result<BootVaultLocation, BootVaultLocatorError> {
    let roots = LocatorRoots::production();
    let first = match discover(&roots)? {
        Discovery::Optical => return Ok(BootVaultLocation::OpticalBootAbsent),
        Discovery::Usb(candidate) => candidate,
    };

    let parent = open_exact_block(&roots, &first.parent_name, first.parent_major_minor)?;
    let partition = open_exact_block(&roots, &first.partition_name, first.partition_major_minor)?;
    validate_open_descriptors(&parent, &partition, &first)?;

    let second = match discover(&roots)? {
        Discovery::Usb(candidate) => candidate,
        Discovery::Optical => return Err(BootVaultLocatorError::MediaChanged),
    };
    if second != first {
        return Err(BootVaultLocatorError::MediaChanged);
    }
    validate_open_descriptors(&parent, &partition, &second)?;

    Ok(BootVaultLocation::Vault(LocatedVaultPartition {
        descriptor: partition,
        identity: second.public_identity(),
        #[cfg(feature = "experimental-vault-manager")]
        device_name: second.partition_name,
    }))
}

#[derive(Clone, Debug)]
struct LocatorRoots {
    mountinfo: PathBuf,
    sys_dev_block: PathBuf,
    sys_class_block: PathBuf,
    sys_devices: PathBuf,
    sys_bus_usb: PathBuf,
    dev: PathBuf,
}

impl LocatorRoots {
    fn production() -> Self {
        Self {
            mountinfo: PathBuf::from("/proc/self/mountinfo"),
            sys_dev_block: PathBuf::from("/sys/dev/block"),
            sys_class_block: PathBuf::from("/sys/class/block"),
            sys_devices: PathBuf::from("/sys/devices"),
            sys_bus_usb: PathBuf::from("/sys/bus/usb"),
            dev: PathBuf::from("/dev"),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct Candidate {
    parent_sysfs: PathBuf,
    partition_sysfs: PathBuf,
    parent_name: OsString,
    partition_name: OsString,
    parent_major_minor: (u32, u32),
    partition_major_minor: (u32, u32),
    disk_sequence: u64,
    logical_sector_bytes: u64,
    media_sector_count: u64,
    start_lba: u64,
    sector_count: u64,
}

impl Candidate {
    fn public_identity(&self) -> LocatedVaultIdentity {
        LocatedVaultIdentity {
            parent_major: self.parent_major_minor.0,
            parent_minor: self.parent_major_minor.1,
            partition_major: self.partition_major_minor.0,
            partition_minor: self.partition_major_minor.1,
            disk_sequence: self.disk_sequence,
            logical_sector_bytes: self.logical_sector_bytes,
            media_sector_count: self.media_sector_count,
            start_lba: self.start_lba,
            sector_count: self.sector_count,
        }
    }
}

enum Discovery {
    Optical,
    Usb(Candidate),
}

fn discover(roots: &LocatorRoots) -> Result<Discovery, BootVaultLocatorError> {
    let source_major_minor = live_medium_major_minor(&roots.mountinfo)?;
    let source_sysfs = exact_sysfs_device(roots, source_major_minor)?;
    let source_partition = optional_positive_file(&source_sysfs.join("partition"))?;
    let parent_sysfs = if source_partition.is_some() {
        source_sysfs
            .parent()
            .ok_or(BootVaultLocatorError::InvalidKernelIdentity)?
            .to_path_buf()
    } else {
        source_sysfs.clone()
    };
    if !parent_sysfs.starts_with(&roots.sys_devices)
        || parent_sysfs == roots.sys_devices
        || parent_sysfs.join("partition").exists()
    {
        return Err(BootVaultLocatorError::InvalidKernelIdentity);
    }

    let parent_major_minor = read_major_minor(&parent_sysfs.join("dev"))?;
    if exact_sysfs_device(roots, parent_major_minor)? != parent_sysfs {
        return Err(BootVaultLocatorError::InvalidKernelIdentity);
    }
    validate_source_parent(
        &source_sysfs,
        source_partition,
        &parent_sysfs,
        source_major_minor,
        parent_major_minor,
    )?;

    if read_optional_u64(&parent_sysfs.join("device/type"))? == Some(5) {
        return Ok(Discovery::Optical);
    }
    if !has_usb_ancestor(roots, &parent_sysfs)? {
        return Err(BootVaultLocatorError::UnsupportedBootMedium);
    }

    let parent_uevent = read_uevent(&parent_sysfs.join("uevent"))?;
    let parent_basename = parent_sysfs
        .file_name()
        .ok_or(BootVaultLocatorError::InvalidKernelIdentity)?;
    if canonical_beneath(
        &roots.sys_class_block.join(parent_basename),
        &roots.sys_devices,
    )? != parent_sysfs
    {
        return Err(BootVaultLocatorError::InvalidKernelIdentity);
    }
    let parent_name = validate_uevent_identity(
        &parent_uevent,
        "disk",
        parent_major_minor,
        None,
        Some(parent_basename),
    )?;
    let disk_sequence = read_positive_u64(&parent_sysfs.join("diskseq"))?;
    if let Some(sequence) = optional_uevent_u64(&parent_uevent, "DISKSEQ")? {
        if sequence != disk_sequence {
            return Err(BootVaultLocatorError::InvalidKernelIdentity);
        }
    }
    let media_sector_count = read_positive_u64(&parent_sysfs.join("size"))?;
    let logical_sector_bytes = read_positive_u64(&parent_sysfs.join("queue/logical_block_size"))?;
    if logical_sector_bytes != LOGICAL_SECTOR_BYTES
        || media_sector_count
            .checked_mul(LOGICAL_SECTOR_BYTES)
            .filter(|bytes| *bytes >= MINIMUM_MEDIA_BYTES)
            .is_none()
    {
        return Err(BootVaultLocatorError::InvalidVaultGeometry);
    }

    let partition_sysfs = unique_partition_three(&parent_sysfs)?;
    let start_lba = read_positive_u64(&partition_sysfs.join("start"))?;
    let sector_count = read_positive_u64(&partition_sysfs.join("size"))?;
    if start_lba != VAULT_START_LBA
        || sector_count != VAULT_SECTOR_COUNT
        || start_lba
            .checked_add(sector_count)
            .filter(|end| *end <= media_sector_count)
            .is_none()
    {
        return Err(BootVaultLocatorError::InvalidVaultGeometry);
    }

    let partition_major_minor = read_major_minor(&partition_sysfs.join("dev"))?;
    if exact_sysfs_device(roots, partition_major_minor)? != partition_sysfs {
        return Err(BootVaultLocatorError::InvalidKernelIdentity);
    }
    let partition_basename = partition_sysfs
        .file_name()
        .ok_or(BootVaultLocatorError::InvalidKernelIdentity)?;
    let class_link = roots.sys_class_block.join(partition_basename);
    if canonical_beneath(&class_link, &roots.sys_devices)? != partition_sysfs {
        return Err(BootVaultLocatorError::InvalidKernelIdentity);
    }
    let partition_uevent = read_uevent(&partition_sysfs.join("uevent"))?;
    let partition_name = validate_uevent_identity(
        &partition_uevent,
        "partition",
        partition_major_minor,
        Some(VAULT_PARTITION_NUMBER),
        Some(partition_basename),
    )?;
    if let Some(sequence) = optional_uevent_u64(&partition_uevent, "DISKSEQ")? {
        if sequence != disk_sequence {
            return Err(BootVaultLocatorError::InvalidKernelIdentity);
        }
    }

    Ok(Discovery::Usb(Candidate {
        parent_sysfs,
        partition_sysfs,
        parent_name,
        partition_name,
        parent_major_minor,
        partition_major_minor,
        disk_sequence,
        logical_sector_bytes,
        media_sector_count,
        start_lba,
        sector_count,
    }))
}

fn live_medium_major_minor(path: &Path) -> Result<(u32, u32), BootVaultLocatorError> {
    let bytes = read_bounded(path, MAX_MOUNTINFO_BYTES)
        .map_err(|_| BootVaultLocatorError::BootMediumAbsent)?;
    let mut match_value = None;
    let mut lines = 0_usize;
    for line in bytes
        .split(|byte| *byte == b'\n')
        .filter(|line| !line.is_empty())
    {
        lines = lines
            .checked_add(1)
            .ok_or(BootVaultLocatorError::AmbiguousBootMedium)?;
        if lines > MAX_MOUNTINFO_LINES || line.len() > MAX_MOUNTINFO_LINE_BYTES {
            return Err(BootVaultLocatorError::AmbiguousBootMedium);
        }
        let fields: Vec<&[u8]> = line.split(|byte| *byte == b' ').collect();
        if fields.len() < 10 || fields[4] != LIVE_MEDIUM_MOUNT {
            continue;
        }
        let separator = fields
            .iter()
            .position(|field| *field == b"-")
            .ok_or(BootVaultLocatorError::AmbiguousBootMedium)?;
        if separator < 6 || separator + 3 > fields.len() || fields[separator + 1] != ISO9660 {
            return Err(BootVaultLocatorError::UnsupportedBootMedium);
        }
        let observed =
            parse_major_minor(fields[2]).ok_or(BootVaultLocatorError::InvalidKernelIdentity)?;
        if match_value.replace(observed).is_some() {
            return Err(BootVaultLocatorError::AmbiguousBootMedium);
        }
    }
    match_value.ok_or(BootVaultLocatorError::BootMediumAbsent)
}

fn exact_sysfs_device(
    roots: &LocatorRoots,
    major_minor: (u32, u32),
) -> Result<PathBuf, BootVaultLocatorError> {
    let link = roots
        .sys_dev_block
        .join(format!("{}:{}", major_minor.0, major_minor.1));
    let canonical = canonical_beneath(&link, &roots.sys_devices)?;
    if read_major_minor(&canonical.join("dev"))? != major_minor {
        return Err(BootVaultLocatorError::InvalidKernelIdentity);
    }
    Ok(canonical)
}

fn canonical_beneath(path: &Path, root: &Path) -> Result<PathBuf, BootVaultLocatorError> {
    let canonical =
        fs::canonicalize(path).map_err(|_| BootVaultLocatorError::InvalidKernelIdentity)?;
    let canonical_root =
        fs::canonicalize(root).map_err(|_| BootVaultLocatorError::InvalidKernelIdentity)?;
    if canonical == canonical_root || !canonical.starts_with(&canonical_root) {
        return Err(BootVaultLocatorError::InvalidKernelIdentity);
    }
    Ok(canonical)
}

fn validate_source_parent(
    source: &Path,
    source_partition: Option<u64>,
    parent: &Path,
    source_major_minor: (u32, u32),
    parent_major_minor: (u32, u32),
) -> Result<(), BootVaultLocatorError> {
    match source_partition {
        None if source == parent && source_major_minor == parent_major_minor => Ok(()),
        Some(1 | 2) if source.parent() == Some(parent) => Ok(()),
        _ => Err(BootVaultLocatorError::InvalidKernelIdentity),
    }
}

fn has_usb_ancestor(roots: &LocatorRoots, parent: &Path) -> Result<bool, BootVaultLocatorError> {
    let usb = fs::canonicalize(&roots.sys_bus_usb)
        .map_err(|_| BootVaultLocatorError::InvalidKernelIdentity)?;
    for ancestor in parent.ancestors() {
        if !ancestor.starts_with(&roots.sys_devices) {
            break;
        }
        let subsystem = ancestor.join("subsystem");
        match fs::canonicalize(subsystem) {
            Ok(value) if value == usb => return Ok(true),
            Ok(_) => {}
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(_) => return Err(BootVaultLocatorError::InvalidKernelIdentity),
        }
    }
    Ok(false)
}

fn unique_partition_three(parent: &Path) -> Result<PathBuf, BootVaultLocatorError> {
    let entries = fs::read_dir(parent).map_err(|_| BootVaultLocatorError::InvalidKernelIdentity)?;
    let mut matches = Vec::new();
    let mut count = 0_usize;
    for entry in entries {
        let entry = entry.map_err(|_| BootVaultLocatorError::InvalidKernelIdentity)?;
        count = count
            .checked_add(1)
            .ok_or(BootVaultLocatorError::AmbiguousVaultPartition)?;
        if count > MAX_SYSFS_CHILDREN {
            return Err(BootVaultLocatorError::AmbiguousVaultPartition);
        }
        if !entry
            .file_type()
            .map_err(|_| BootVaultLocatorError::InvalidKernelIdentity)?
            .is_dir()
        {
            continue;
        }
        if optional_positive_file(&entry.path().join("partition"))? == Some(VAULT_PARTITION_NUMBER)
        {
            let canonical = fs::canonicalize(entry.path())
                .map_err(|_| BootVaultLocatorError::InvalidKernelIdentity)?;
            if canonical.parent() != Some(parent) {
                return Err(BootVaultLocatorError::InvalidKernelIdentity);
            }
            matches.push(canonical);
        }
    }
    match matches.as_slice() {
        [] => Err(BootVaultLocatorError::VaultPartitionAbsent),
        [partition] => Ok(partition.clone()),
        [_, ..] => Err(BootVaultLocatorError::AmbiguousVaultPartition),
    }
}

fn read_uevent(path: &Path) -> Result<BTreeMap<Vec<u8>, Vec<u8>>, BootVaultLocatorError> {
    let bytes = read_bounded(path, MAX_SYSFS_BYTES)
        .map_err(|_| BootVaultLocatorError::InvalidKernelIdentity)?;
    let mut values = BTreeMap::new();
    for line in bytes
        .split(|byte| *byte == b'\n')
        .filter(|line| !line.is_empty())
    {
        let Some(separator) = line.iter().position(|byte| *byte == b'=') else {
            return Err(BootVaultLocatorError::InvalidKernelIdentity);
        };
        let key = &line[..separator];
        let value = &line[separator + 1..];
        if key.is_empty()
            || key.len() > 32
            || value.len() > 256
            || !key
                .iter()
                .all(|byte| byte.is_ascii_uppercase() || byte.is_ascii_digit() || *byte == b'_')
            || value.iter().any(|byte| *byte < b' ' || *byte > b'~')
            || values.insert(key.to_vec(), value.to_vec()).is_some()
        {
            return Err(BootVaultLocatorError::InvalidKernelIdentity);
        }
    }
    Ok(values)
}

fn validate_uevent_identity(
    values: &BTreeMap<Vec<u8>, Vec<u8>>,
    expected_type: &str,
    expected_major_minor: (u32, u32),
    expected_partition: Option<u64>,
    expected_basename: Option<&OsStr>,
) -> Result<OsString, BootVaultLocatorError> {
    if values.get(b"DEVTYPE".as_slice()).map(Vec::as_slice) != Some(expected_type.as_bytes())
        || optional_uevent_u64(values, "MAJOR")? != Some(u64::from(expected_major_minor.0))
        || optional_uevent_u64(values, "MINOR")? != Some(u64::from(expected_major_minor.1))
        || optional_uevent_u64(values, "PARTN")? != expected_partition
    {
        return Err(BootVaultLocatorError::InvalidKernelIdentity);
    }
    let name = values
        .get(b"DEVNAME".as_slice())
        .ok_or(BootVaultLocatorError::InvalidKernelIdentity)?;
    if !safe_device_name(name)
        || expected_basename.is_some_and(|basename| basename.as_bytes() != name.as_slice())
    {
        return Err(BootVaultLocatorError::InvalidKernelIdentity);
    }
    Ok(OsStr::from_bytes(name).to_os_string())
}

fn safe_device_name(value: &[u8]) -> bool {
    !value.is_empty()
        && value.len() <= 64
        && value
            .iter()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'+' | b'-' | b'_' | b'.'))
}

fn optional_uevent_u64(
    values: &BTreeMap<Vec<u8>, Vec<u8>>,
    key: &str,
) -> Result<Option<u64>, BootVaultLocatorError> {
    values
        .get(key.as_bytes())
        .map(|value| parse_u64(value).ok_or(BootVaultLocatorError::InvalidKernelIdentity))
        .transpose()
}

fn read_major_minor(path: &Path) -> Result<(u32, u32), BootVaultLocatorError> {
    let bytes = read_bounded(path, 64).map_err(|_| BootVaultLocatorError::InvalidKernelIdentity)?;
    parse_major_minor(trim_line(&bytes)).ok_or(BootVaultLocatorError::InvalidKernelIdentity)
}

fn parse_major_minor(value: &[u8]) -> Option<(u32, u32)> {
    let separator = value.iter().position(|byte| *byte == b':')?;
    if value[separator + 1..].contains(&b':') {
        return None;
    }
    Some((
        parse_u64(&value[..separator])?.try_into().ok()?,
        parse_u64(&value[separator + 1..])?.try_into().ok()?,
    ))
}

fn optional_positive_file(path: &Path) -> Result<Option<u64>, BootVaultLocatorError> {
    match fs::read(path) {
        Ok(bytes) => {
            if bytes.len() > 64 {
                return Err(BootVaultLocatorError::InvalidKernelIdentity);
            }
            let value = parse_u64(trim_line(&bytes))
                .filter(|value| *value > 0)
                .ok_or(BootVaultLocatorError::InvalidKernelIdentity)?;
            Ok(Some(value))
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(_) => Err(BootVaultLocatorError::InvalidKernelIdentity),
    }
}

fn read_optional_u64(path: &Path) -> Result<Option<u64>, BootVaultLocatorError> {
    match fs::read(path) {
        Ok(bytes) => {
            if bytes.len() > 64 {
                return Err(BootVaultLocatorError::InvalidKernelIdentity);
            }
            Ok(Some(
                parse_u64(trim_line(&bytes)).ok_or(BootVaultLocatorError::InvalidKernelIdentity)?,
            ))
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(_) => Err(BootVaultLocatorError::InvalidKernelIdentity),
    }
}

fn read_positive_u64(path: &Path) -> Result<u64, BootVaultLocatorError> {
    let bytes = read_bounded(path, 64).map_err(|_| BootVaultLocatorError::InvalidKernelIdentity)?;
    parse_u64(trim_line(&bytes))
        .filter(|value| *value > 0)
        .ok_or(BootVaultLocatorError::InvalidKernelIdentity)
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
    value
        .strip_suffix(b"\n")
        .unwrap_or(value)
        .strip_suffix(b"\r")
        .unwrap_or_else(|| value.strip_suffix(b"\n").unwrap_or(value))
}

fn read_bounded(path: &Path, maximum: usize) -> io::Result<Vec<u8>> {
    let bytes = fs::read(path)?;
    if bytes.len() > maximum || bytes.contains(&0) {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "bounded read"));
    }
    Ok(bytes)
}

fn open_exact_block(
    roots: &LocatorRoots,
    name: &OsStr,
    expected_major_minor: (u32, u32),
) -> Result<fs::File, BootVaultLocatorError> {
    if !safe_device_name(name.as_bytes()) {
        return Err(BootVaultLocatorError::InvalidKernelIdentity);
    }
    let descriptor = rfs::open(
        roots.dev.join(name),
        OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NOFOLLOW | OFlags::NONBLOCK,
        Mode::empty(),
    )
    .map_err(|_| BootVaultLocatorError::BlockDeviceUnavailable)?;
    let file = fs::File::from(descriptor);
    validate_block_descriptor(&file, expected_major_minor)?;
    Ok(file)
}

fn validate_block_descriptor(
    descriptor: &fs::File,
    expected_major_minor: (u32, u32),
) -> Result<(), BootVaultLocatorError> {
    let stat = rfs::fstat(descriptor).map_err(|_| BootVaultLocatorError::BlockDeviceUnavailable)?;
    let flags =
        rfs::fcntl_getfl(descriptor).map_err(|_| BootVaultLocatorError::BlockDeviceUnavailable)?;
    let fd_flags = rustix::io::fcntl_getfd(descriptor)
        .map_err(|_| BootVaultLocatorError::BlockDeviceUnavailable)?;
    if !FileType::from_raw_mode(stat.st_mode).is_block_device()
        || (rfs::major(stat.st_rdev), rfs::minor(stat.st_rdev)) != expected_major_minor
        || flags & OFlags::ACCMODE != OFlags::RDONLY
        || !flags.contains(OFlags::NONBLOCK)
        || !fd_flags.contains(rustix::io::FdFlags::CLOEXEC)
    {
        return Err(BootVaultLocatorError::BlockDeviceUnavailable);
    }
    Ok(())
}

fn validate_open_descriptors(
    parent: &fs::File,
    partition: &fs::File,
    candidate: &Candidate,
) -> Result<(), BootVaultLocatorError> {
    validate_block_descriptor(parent, candidate.parent_major_minor)?;
    validate_block_descriptor(partition, candidate.partition_major_minor)?;
    let parent_identity = descriptor_block_identity(parent).map_err(map_locator_identity_error)?;
    let partition_identity =
        descriptor_block_identity(partition).map_err(map_locator_identity_error)?;
    if parent_identity.disk_sequence != candidate.disk_sequence
        || partition_identity.disk_sequence != candidate.disk_sequence
        || parent_identity.logical_sector_bytes != candidate.logical_sector_bytes
        || partition_identity.logical_sector_bytes != candidate.logical_sector_bytes
        || parent_identity.sector_count != candidate.media_sector_count
        || partition_identity.sector_count != candidate.sector_count
    {
        return Err(BootVaultLocatorError::MediaChanged);
    }
    validate_mbr(parent)?;
    Ok(())
}

fn map_locator_identity_error(error: DescriptorBlockIdentityError) -> BootVaultLocatorError {
    match error {
        DescriptorBlockIdentityError::ToolUnavailable => BootVaultLocatorError::ToolUnavailable,
        DescriptorBlockIdentityError::OperationTimedOut => BootVaultLocatorError::OperationTimedOut,
        DescriptorBlockIdentityError::CleanupFailed => BootVaultLocatorError::CleanupFailed,
        DescriptorBlockIdentityError::InvalidDescriptor
        | DescriptorBlockIdentityError::IdentityUnavailable => {
            BootVaultLocatorError::BlockIdentityUnavailable
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct DescriptorBlockIdentity {
    pub(crate) disk_sequence: u64,
    pub(crate) sector_count: u64,
    pub(crate) logical_sector_bytes: u64,
}

#[cfg(feature = "experimental-vault-manager")]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct DescriptorBlockGeometry {
    pub(crate) sector_count: u64,
    pub(crate) logical_sector_bytes: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum DescriptorBlockIdentityError {
    InvalidDescriptor,
    IdentityUnavailable,
    ToolUnavailable,
    OperationTimedOut,
    CleanupFailed,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct DescriptorObject {
    device: u64,
    inode: u64,
    rdev: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum BlockdevQuery {
    DiskSequence,
    SizeBytes,
    LogicalSectorBytes,
}

impl BlockdevQuery {
    fn argument(self) -> &'static str {
        match self {
            Self::DiskSequence => "--getdiskseq",
            Self::SizeBytes => "--getsize64",
            Self::LogicalSectorBytes => "--getss",
        }
    }
}

pub(crate) fn descriptor_block_identity(
    descriptor: &(impl AsFd + AsRawFd),
) -> Result<DescriptorBlockIdentity, DescriptorBlockIdentityError> {
    descriptor_block_identity_with_deadline(descriptor, aggregate_blockdev_deadline(None)?)
}

#[cfg(feature = "experimental-vault-manager")]
fn descriptor_block_identity_until(
    descriptor: &(impl AsFd + AsRawFd),
    deadline: Instant,
) -> Result<DescriptorBlockIdentity, DescriptorBlockIdentityError> {
    descriptor_block_identity_with_deadline(
        descriptor,
        aggregate_blockdev_deadline(Some(deadline))?,
    )
}

fn descriptor_block_identity_with_deadline(
    descriptor: &(impl AsFd + AsRawFd),
    deadline: Instant,
) -> Result<DescriptorBlockIdentity, DescriptorBlockIdentityError> {
    ensure_blockdev_deadline(deadline)?;
    let procfd = descriptor_procfd_path(descriptor)?;
    let before = validate_descriptor_procfd(descriptor, &procfd)?;
    let identity = query_descriptor_block_identity_until(&procfd, deadline, blockdev_query)?;
    let after = validate_descriptor_procfd(descriptor, &procfd)?;
    ensure_blockdev_deadline(deadline)?;
    if after != before {
        return Err(DescriptorBlockIdentityError::InvalidDescriptor);
    }
    Ok(identity)
}

#[cfg(feature = "experimental-vault-manager")]
pub(crate) fn descriptor_block_geometry(
    descriptor: &(impl AsFd + AsRawFd),
) -> Result<DescriptorBlockGeometry, DescriptorBlockIdentityError> {
    let deadline = aggregate_blockdev_deadline(None)?;
    let procfd = descriptor_procfd_path(descriptor)?;
    let before = validate_descriptor_procfd(descriptor, &procfd)?;
    let geometry = query_descriptor_block_geometry_until(&procfd, deadline, blockdev_query)?;
    let after = validate_descriptor_procfd(descriptor, &procfd)?;
    ensure_blockdev_deadline(deadline)?;
    if after != before {
        return Err(DescriptorBlockIdentityError::InvalidDescriptor);
    }
    Ok(geometry)
}

fn aggregate_blockdev_deadline(
    outer_deadline: Option<Instant>,
) -> Result<Instant, DescriptorBlockIdentityError> {
    let local_deadline = Instant::now()
        .checked_add(BLOCKDEV_TIMEOUT)
        .ok_or(DescriptorBlockIdentityError::OperationTimedOut)?;
    let deadline = outer_deadline.map_or(local_deadline, |outer| outer.min(local_deadline));
    ensure_blockdev_deadline(deadline)?;
    Ok(deadline)
}

fn remaining_blockdev_timeout(deadline: Instant) -> Result<Duration, DescriptorBlockIdentityError> {
    deadline
        .checked_duration_since(Instant::now())
        .filter(|remaining| !remaining.is_zero())
        .ok_or(DescriptorBlockIdentityError::OperationTimedOut)
}

fn ensure_blockdev_deadline(deadline: Instant) -> Result<(), DescriptorBlockIdentityError> {
    remaining_blockdev_timeout(deadline).map(|_| ())
}

fn query_descriptor_block_identity_until(
    procfd: &Path,
    deadline: Instant,
    mut query: impl FnMut(&Path, BlockdevQuery, Duration) -> Result<u64, DescriptorBlockIdentityError>,
) -> Result<DescriptorBlockIdentity, DescriptorBlockIdentityError> {
    let identity = consistent_descriptor_block_identity(|operation| {
        query(procfd, operation, remaining_blockdev_timeout(deadline)?)
    })?;
    ensure_blockdev_deadline(deadline)?;
    Ok(identity)
}

#[cfg(feature = "experimental-vault-manager")]
fn query_descriptor_block_geometry_until(
    procfd: &Path,
    deadline: Instant,
    mut query: impl FnMut(&Path, BlockdevQuery, Duration) -> Result<u64, DescriptorBlockIdentityError>,
) -> Result<DescriptorBlockGeometry, DescriptorBlockIdentityError> {
    let geometry = consistent_descriptor_block_geometry(|operation| {
        query(procfd, operation, remaining_blockdev_timeout(deadline)?)
    })?;
    ensure_blockdev_deadline(deadline)?;
    Ok(geometry)
}

fn descriptor_procfd_path(
    descriptor: &impl AsRawFd,
) -> Result<PathBuf, DescriptorBlockIdentityError> {
    let descriptor_number = descriptor.as_raw_fd();
    if descriptor_number < 0 {
        return Err(DescriptorBlockIdentityError::InvalidDescriptor);
    }
    Ok(PathBuf::from(format!(
        "/proc/{}/fd/{descriptor_number}",
        std::process::id()
    )))
}

fn validate_descriptor_procfd(
    descriptor: &(impl AsFd + AsRawFd),
    procfd: &Path,
) -> Result<DescriptorObject, DescriptorBlockIdentityError> {
    let observed =
        rfs::fstat(descriptor).map_err(|_| DescriptorBlockIdentityError::InvalidDescriptor)?;
    let procfd_observed = rfs::statat(CWD, procfd, AtFlags::empty())
        .map_err(|_| DescriptorBlockIdentityError::InvalidDescriptor)?;
    let status = rfs::fcntl_getfl(descriptor)
        .map_err(|_| DescriptorBlockIdentityError::InvalidDescriptor)?;
    let descriptor_flags = rustix::io::fcntl_getfd(descriptor)
        .map_err(|_| DescriptorBlockIdentityError::InvalidDescriptor)?;
    if !FileType::from_raw_mode(observed.st_mode).is_block_device()
        || !FileType::from_raw_mode(procfd_observed.st_mode).is_block_device()
        || observed.st_dev != procfd_observed.st_dev
        || observed.st_ino != procfd_observed.st_ino
        || observed.st_rdev != procfd_observed.st_rdev
        || status & OFlags::ACCMODE != OFlags::RDONLY
        || !status.contains(OFlags::NONBLOCK)
        || !descriptor_flags.contains(rustix::io::FdFlags::CLOEXEC)
    {
        return Err(DescriptorBlockIdentityError::InvalidDescriptor);
    }
    Ok(DescriptorObject {
        device: observed.st_dev,
        inode: observed.st_ino,
        rdev: observed.st_rdev,
    })
}

fn consistent_descriptor_block_identity(
    mut query: impl FnMut(BlockdevQuery) -> Result<u64, DescriptorBlockIdentityError>,
) -> Result<DescriptorBlockIdentity, DescriptorBlockIdentityError> {
    let disk_sequence_before = query(BlockdevQuery::DiskSequence)?;
    let size_bytes_before = query(BlockdevQuery::SizeBytes)?;
    let logical_sector_bytes_before = query(BlockdevQuery::LogicalSectorBytes)?;
    let logical_sector_bytes_after = query(BlockdevQuery::LogicalSectorBytes)?;
    let size_bytes_after = query(BlockdevQuery::SizeBytes)?;
    let disk_sequence_after = query(BlockdevQuery::DiskSequence)?;
    if disk_sequence_before == 0
        || size_bytes_before == 0
        || logical_sector_bytes_before == 0
        || disk_sequence_after != disk_sequence_before
        || size_bytes_after != size_bytes_before
        || logical_sector_bytes_after != logical_sector_bytes_before
        || size_bytes_before % KERNEL_SECTOR_BYTES != 0
    {
        return Err(DescriptorBlockIdentityError::IdentityUnavailable);
    }
    Ok(DescriptorBlockIdentity {
        disk_sequence: disk_sequence_before,
        sector_count: size_bytes_before / KERNEL_SECTOR_BYTES,
        logical_sector_bytes: logical_sector_bytes_before,
    })
}

#[cfg(feature = "experimental-vault-manager")]
fn consistent_descriptor_block_geometry(
    mut query: impl FnMut(BlockdevQuery) -> Result<u64, DescriptorBlockIdentityError>,
) -> Result<DescriptorBlockGeometry, DescriptorBlockIdentityError> {
    let size_bytes_before = query(BlockdevQuery::SizeBytes)?;
    let logical_sector_bytes_before = query(BlockdevQuery::LogicalSectorBytes)?;
    let logical_sector_bytes_after = query(BlockdevQuery::LogicalSectorBytes)?;
    let size_bytes_after = query(BlockdevQuery::SizeBytes)?;
    if size_bytes_before == 0
        || logical_sector_bytes_before == 0
        || size_bytes_after != size_bytes_before
        || logical_sector_bytes_after != logical_sector_bytes_before
        || size_bytes_before % KERNEL_SECTOR_BYTES != 0
    {
        return Err(DescriptorBlockIdentityError::IdentityUnavailable);
    }
    Ok(DescriptorBlockGeometry {
        sector_count: size_bytes_before / KERNEL_SECTOR_BYTES,
        logical_sector_bytes: logical_sector_bytes_before,
    })
}

/// util-linux performs BLKGETDISKSEQ, BLKGETSIZE64 and BLKSSZGET only on the
/// retained parent-process procfd. The executable, operation arguments,
/// aggregate deadline and output bound are fixed in production; each child
/// receives only the budget remaining from the one shared deadline.
fn blockdev_query(
    procfd: &Path,
    query: BlockdevQuery,
    timeout: Duration,
) -> Result<u64, DescriptorBlockIdentityError> {
    run_blockdev_query(Path::new(BLOCKDEV_PATH), procfd, query, timeout)
}

#[cfg(test)]
fn test_blockdev_query(
    program: &Path,
    procfd: &Path,
    query: BlockdevQuery,
    timeout: Duration,
) -> Result<u64, DescriptorBlockIdentityError> {
    run_blockdev_query(program, procfd, query, timeout)
}

fn run_blockdev_query(
    program: &Path,
    procfd: &Path,
    query: BlockdevQuery,
    timeout: Duration,
) -> Result<u64, DescriptorBlockIdentityError> {
    let mut command = Command::new(program);
    command
        .arg(query.argument())
        .arg(procfd)
        .env_clear()
        .env("LC_ALL", "C")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null());
    let output = bounded_process::capture(&mut command, timeout, BLOCKDEV_OUTPUT_LIMIT).map_err(
        |error| match error {
            bounded_process::BoundedProcessError::Unavailable
            | bounded_process::BoundedProcessError::StartFailed => {
                DescriptorBlockIdentityError::ToolUnavailable
            }
            bounded_process::BoundedProcessError::TimedOut => {
                DescriptorBlockIdentityError::OperationTimedOut
            }
            bounded_process::BoundedProcessError::CleanupFailed => {
                DescriptorBlockIdentityError::CleanupFailed
            }
            bounded_process::BoundedProcessError::WaitFailed
            | bounded_process::BoundedProcessError::OutputLimitExceeded
            | bounded_process::BoundedProcessError::UnexpectedDescendant => {
                DescriptorBlockIdentityError::IdentityUnavailable
            }
        },
    )?;
    if !output.status.success() {
        return Err(DescriptorBlockIdentityError::IdentityUnavailable);
    }
    parse_u64(trim_line(&output.bytes))
        .filter(|value| *value > 0)
        .ok_or(DescriptorBlockIdentityError::IdentityUnavailable)
}

fn validate_mbr(parent: &fs::File) -> Result<(), BootVaultLocatorError> {
    let mut sector = [0_u8; MBR_BYTES];
    read_exact_at(parent, &mut sector, 0)
        .map_err(|_| BootVaultLocatorError::BlockIdentityUnavailable)?;
    let first = parse_mbr_entry(&sector, 1)?;
    let second = parse_mbr_entry(&sector, 2)?;
    let third = parse_mbr_entry(&sector, VAULT_PARTITION_NUMBER)?;
    let fourth = parse_mbr_entry(&sector, 4)?;
    let first_end = first.occupied_end_before_vault()?;
    let second_end = second.occupied_end_before_vault()?;
    let overlap = first.start_lba < second_end && second.start_lba < first_end;
    let isohybrid_envelope = first.status == 0x80
        && first.kind == 0x00
        && second.status == 0x00
        && second.kind == 0xef
        && first.start_lba < second.start_lba
        && second_end <= first_end;
    if sector[MBR_SIGNATURE_OFFSET..] != [0x55, 0xaa]
        || first.status != 0x80
        || second.status != 0x00
        || first.start_lba >= second.start_lba
        || (overlap && !isohybrid_envelope)
        || (first.kind == 0x00 && !isohybrid_envelope)
        || third.raw != EXPECTED_VAULT_MBR_ENTRY
        || !fourth.is_empty()
    {
        return Err(BootVaultLocatorError::InvalidVaultGeometry);
    }
    Ok(())
}

#[derive(Clone, Copy)]
struct MbrEntry {
    raw: [u8; MBR_PARTITION_BYTES],
    status: u8,
    kind: u8,
    start_lba: u64,
    sector_count: u64,
}

impl MbrEntry {
    fn is_empty(self) -> bool {
        self.raw == [0_u8; MBR_PARTITION_BYTES]
    }

    fn occupied_end_before_vault(self) -> Result<u64, BootVaultLocatorError> {
        let end = self
            .start_lba
            .checked_add(self.sector_count)
            .filter(|end| *end <= VAULT_START_LBA);
        if self.is_empty()
            || !matches!(self.status, 0x00 | 0x80)
            || self.start_lba == 0
            || self.sector_count == 0
            || end.is_none()
        {
            return Err(BootVaultLocatorError::InvalidVaultGeometry);
        }
        end.ok_or(BootVaultLocatorError::InvalidVaultGeometry)
    }
}

fn parse_mbr_entry(
    sector: &[u8; MBR_BYTES],
    partition_number: u64,
) -> Result<MbrEntry, BootVaultLocatorError> {
    let slot = usize::try_from(partition_number)
        .ok()
        .filter(|slot| (1..=4).contains(slot))
        .ok_or(BootVaultLocatorError::InvalidVaultGeometry)?;
    let offset = MBR_PARTITION_TABLE_OFFSET + (slot - 1) * MBR_PARTITION_BYTES;
    let raw: [u8; MBR_PARTITION_BYTES] = sector[offset..offset + MBR_PARTITION_BYTES]
        .try_into()
        .map_err(|_| BootVaultLocatorError::InvalidVaultGeometry)?;
    Ok(MbrEntry {
        status: raw[0],
        kind: raw[4],
        start_lba: u64::from(u32::from_le_bytes(
            raw[8..12]
                .try_into()
                .map_err(|_| BootVaultLocatorError::InvalidVaultGeometry)?,
        )),
        sector_count: u64::from(u32::from_le_bytes(
            raw[12..16]
                .try_into()
                .map_err(|_| BootVaultLocatorError::InvalidVaultGeometry)?,
        )),
        raw,
    })
}

fn read_exact_at(file: &fs::File, buffer: &mut [u8], offset: u64) -> io::Result<()> {
    let mut consumed = 0_usize;
    while consumed < buffer.len() {
        match file.read_at(
            &mut buffer[consumed..],
            offset
                .checked_add(
                    u64::try_from(consumed).map_err(|_| {
                        io::Error::new(io::ErrorKind::InvalidInput, "invalid offset")
                    })?,
                )
                .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "invalid offset"))?,
        ) {
            Ok(0) => return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "short read")),
            Ok(read) => consumed += read,
            Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
            Err(error) => return Err(error),
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        collections::VecDeque,
        fs::{File, OpenOptions},
        os::unix::fs::{PermissionsExt, symlink},
        time::Instant,
    };
    use tempfile::TempDir;

    struct Fixture {
        _temporary: TempDir,
        roots: LocatorRoots,
        parent: PathBuf,
        partition: PathBuf,
    }

    impl Fixture {
        fn usb() -> Self {
            let temporary = tempfile::tempdir().expect("tempdir");
            let root = temporary.path();
            let mountinfo = root.join("proc/self/mountinfo");
            let sys_dev_block = root.join("sys/dev/block");
            let sys_class_block = root.join("sys/class/block");
            let sys_devices = root.join("sys/devices");
            let sys_bus_usb = root.join("sys/bus/usb");
            let dev = root.join("dev");
            for directory in [
                mountinfo.parent().expect("mountinfo parent"),
                sys_dev_block.as_path(),
                sys_class_block.as_path(),
                sys_devices.as_path(),
                sys_bus_usb.as_path(),
                dev.as_path(),
            ] {
                fs::create_dir_all(directory).expect("fixture directory");
            }
            let usb_ancestor = sys_devices.join("pci0000:00/usb1/1-1");
            let parent = usb_ancestor.join("host0/target0:0:0/0:0:0:0/block/sdz");
            let partition = parent.join("sdz3");
            fs::create_dir_all(partition.join("queue")).expect("partition fixture");
            fs::create_dir_all(parent.join("queue")).expect("parent queue");
            symlink(&sys_bus_usb, usb_ancestor.join("subsystem")).expect("usb subsystem");
            write(
                &mountinfo,
                b"36 25 8:16 / /run/live/medium ro - iso9660 /dev/sdz ro\n",
            );
            write(&parent.join("dev"), b"8:16\n");
            write(&parent.join("diskseq"), b"77\n");
            write(&parent.join("size"), b"62500000\n");
            write(&parent.join("queue/logical_block_size"), b"512\n");
            write(
                &parent.join("uevent"),
                b"MAJOR=8\nMINOR=16\nDEVNAME=sdz\nDEVTYPE=disk\nDISKSEQ=77\n",
            );
            write(&partition.join("partition"), b"3\n");
            write(&partition.join("start"), b"33554432\n");
            write(&partition.join("size"), b"16777216\n");
            write(&partition.join("dev"), b"8:19\n");
            write(
                &partition.join("uevent"),
                b"MAJOR=8\nMINOR=19\nDEVNAME=sdz3\nDEVTYPE=partition\nDISKSEQ=77\nPARTN=3\n",
            );
            symlink(&parent, sys_dev_block.join("8:16")).expect("parent dev link");
            symlink(&partition, sys_dev_block.join("8:19")).expect("partition dev link");
            symlink(&parent, sys_class_block.join("sdz")).expect("parent class link");
            symlink(&partition, sys_class_block.join("sdz3")).expect("partition class link");
            Self {
                _temporary: temporary,
                roots: LocatorRoots {
                    mountinfo,
                    sys_dev_block,
                    sys_class_block,
                    sys_devices,
                    sys_bus_usb,
                    dev,
                },
                parent,
                partition,
            }
        }
    }

    fn write(path: &Path, bytes: &[u8]) {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).expect("fixture parent");
        }
        fs::write(path, bytes).expect("fixture write");
    }

    #[test]
    fn discovers_only_p3_below_the_live_usb_parent() {
        let fixture = Fixture::usb();
        let candidate = match discover(&fixture.roots) {
            Ok(Discovery::Usb(candidate)) => Some(candidate),
            Ok(Discovery::Optical) | Err(_) => None,
        };
        assert!(candidate.is_some());
        let Some(candidate) = candidate else {
            return;
        };
        assert_eq!(candidate.parent_sysfs, fixture.parent);
        assert_eq!(candidate.partition_sysfs, fixture.partition);
        assert_eq!(candidate.parent_major_minor, (8, 16));
        assert_eq!(candidate.partition_major_minor, (8, 19));
        assert_eq!(candidate.disk_sequence, 77);
        assert_eq!(candidate.start_lba, VAULT_START_LBA);
        assert_eq!(candidate.sector_count, VAULT_SECTOR_COUNT);
    }

    #[test]
    fn optical_boot_is_a_distinct_absence_and_never_searches_other_disks() {
        let fixture = Fixture::usb();
        write(&fixture.parent.join("device/type"), b"5\n");
        assert!(matches!(discover(&fixture.roots), Ok(Discovery::Optical)));
    }

    #[test]
    fn missing_duplicate_or_wrong_geometry_p3_fails_closed() {
        let fixture = Fixture::usb();
        fs::remove_file(fixture.partition.join("partition")).expect("remove p3 marker");
        assert!(matches!(
            discover(&fixture.roots),
            Err(BootVaultLocatorError::VaultPartitionAbsent)
        ));

        write(&fixture.partition.join("partition"), b"3\n");
        write(&fixture.partition.join("start"), b"33554433\n");
        assert!(matches!(
            discover(&fixture.roots),
            Err(BootVaultLocatorError::InvalidVaultGeometry)
        ));

        write(&fixture.partition.join("start"), b"33554432\n");
        let duplicate = fixture.parent.join("duplicate3");
        fs::create_dir_all(&duplicate).expect("duplicate directory");
        write(&duplicate.join("partition"), b"3\n");
        assert!(matches!(
            discover(&fixture.roots),
            Err(BootVaultLocatorError::AmbiguousVaultPartition)
        ));
    }

    #[test]
    fn sysfs_alias_diskseq_and_boot_parent_mismatches_fail_closed() {
        let fixture = Fixture::usb();
        write(
            &fixture.partition.join("uevent"),
            b"MAJOR=8\nMINOR=19\nDEVNAME=sdz3\nDEVTYPE=partition\nDISKSEQ=78\nPARTN=3\n",
        );
        assert!(matches!(
            discover(&fixture.roots),
            Err(BootVaultLocatorError::InvalidKernelIdentity)
        ));

        write(
            &fixture.partition.join("uevent"),
            b"MAJOR=8\nMINOR=19\nDEVNAME=sdz3\nDEVTYPE=partition\nDISKSEQ=77\nPARTN=3\n",
        );
        write(
            &fixture.roots.mountinfo,
            b"36 25 8:19 / /run/live/medium ro - iso9660 /dev/sdz3 ro\n",
        );
        assert!(matches!(
            discover(&fixture.roots),
            Err(BootVaultLocatorError::InvalidKernelIdentity)
        ));
    }

    #[test]
    fn partition_class_alias_must_resolve_to_the_same_p3() {
        let fixture = Fixture::usb();
        let alias = fixture.roots.sys_class_block.join("sdz3");
        fs::remove_file(&alias).expect("remove class alias");
        symlink(&fixture.parent, alias).expect("mismatched class alias");
        assert!(matches!(
            discover(&fixture.roots),
            Err(BootVaultLocatorError::InvalidKernelIdentity)
        ));
    }

    #[test]
    fn mountinfo_must_have_one_exact_iso9660_live_medium() {
        let fixture = Fixture::usb();
        write(
            &fixture.roots.mountinfo,
            b"36 25 8:16 / /run/live/medium ro - iso9660 /dev/sdz ro\n37 25 8:16 / /run/live/medium ro - iso9660 /dev/sdz ro\n",
        );
        assert!(matches!(
            discover(&fixture.roots),
            Err(BootVaultLocatorError::AmbiguousBootMedium)
        ));
        write(
            &fixture.roots.mountinfo,
            b"36 25 8:16 / /run/live/medium ro - ext4 /dev/sdz ro\n",
        );
        assert!(matches!(
            discover(&fixture.roots),
            Err(BootVaultLocatorError::UnsupportedBootMedium)
        ));
    }

    #[test]
    fn complete_finalized_mbr_geometry_is_required() {
        let temporary = tempfile::tempdir().expect("tempdir");
        let path = temporary.path().join("disk.img");
        let mut sector = [0_u8; MBR_BYTES];
        let first = [
            0x80, 0xfe, 0xff, 0xff, 0x00, 0xfe, 0xff, 0xff, 0x01, 0x00, 0x00, 0x00, 0xe8, 0x03,
            0x00, 0x00,
        ];
        let second = [
            0x00, 0xfe, 0xff, 0xff, 0xef, 0xfe, 0xff, 0xff, 0x64, 0x00, 0x00, 0x00, 0x64, 0x00,
            0x00, 0x00,
        ];
        let first_offset = MBR_PARTITION_TABLE_OFFSET;
        let second_offset = first_offset + MBR_PARTITION_BYTES;
        let third_offset = second_offset + MBR_PARTITION_BYTES;
        let fourth_offset = third_offset + MBR_PARTITION_BYTES;
        sector[first_offset..first_offset + MBR_PARTITION_BYTES].copy_from_slice(&first);
        sector[second_offset..second_offset + MBR_PARTITION_BYTES].copy_from_slice(&second);
        sector[third_offset..third_offset + MBR_PARTITION_BYTES]
            .copy_from_slice(&EXPECTED_VAULT_MBR_ENTRY);
        sector[MBR_SIGNATURE_OFFSET..].copy_from_slice(&[0x55, 0xaa]);
        write(&path, &sector);
        let file = OpenOptions::new().read(true).open(&path).expect("image");
        assert_eq!(validate_mbr(&file), Ok(()));

        sector[third_offset + 4] = 0x07;
        write(&path, &sector);
        let file = OpenOptions::new().read(true).open(&path).expect("image");
        assert_eq!(
            validate_mbr(&file),
            Err(BootVaultLocatorError::InvalidVaultGeometry)
        );

        sector[third_offset..third_offset + MBR_PARTITION_BYTES]
            .copy_from_slice(&EXPECTED_VAULT_MBR_ENTRY);
        sector[fourth_offset..fourth_offset + MBR_PARTITION_BYTES]
            .copy_from_slice(&EXPECTED_VAULT_MBR_ENTRY);
        write(&path, &sector);
        let file = OpenOptions::new().read(true).open(&path).expect("image");
        assert_eq!(
            validate_mbr(&file),
            Err(BootVaultLocatorError::InvalidVaultGeometry),
            "an overlapping p4 alias must not qualify as layout-v1"
        );
    }

    #[test]
    fn descriptor_identity_rejects_inconsistent_diskseq_capacity_and_sector_size() {
        fn observed(
            values: [u64; 6],
        ) -> Result<DescriptorBlockIdentity, DescriptorBlockIdentityError> {
            let mut values = VecDeque::from(values);
            consistent_descriptor_block_identity(|_| {
                values
                    .pop_front()
                    .ok_or(DescriptorBlockIdentityError::IdentityUnavailable)
            })
        }

        let size = VAULT_SECTOR_COUNT * KERNEL_SECTOR_BYTES;
        assert_eq!(
            observed([77, size, 512, 512, size, 77]),
            Ok(DescriptorBlockIdentity {
                disk_sequence: 77,
                sector_count: VAULT_SECTOR_COUNT,
                logical_sector_bytes: 512,
            })
        );
        for inconsistent in [
            [77, size, 512, 512, size, 78],
            [77, size, 512, 512, size + 512, 77],
            [77, size, 512, 4096, size, 77],
        ] {
            assert_eq!(
                observed(inconsistent),
                Err(DescriptorBlockIdentityError::IdentityUnavailable)
            );
        }

        assert_eq!(
            map_locator_identity_error(DescriptorBlockIdentityError::OperationTimedOut),
            BootVaultLocatorError::OperationTimedOut
        );
        assert_eq!(
            map_locator_identity_error(DescriptorBlockIdentityError::CleanupFailed),
            BootVaultLocatorError::CleanupFailed
        );
        for error in [
            BootVaultLocatorError::OperationTimedOut,
            BootVaultLocatorError::CleanupFailed,
        ] {
            assert!(
                error
                    .code()
                    .bytes()
                    .all(|byte| byte.is_ascii_lowercase() || byte == b'-')
            );
            assert!(!error.to_string().is_empty());
        }
    }

    #[test]
    #[ignore = "subprocess probe must run without parallel vault lock descriptors"]
    fn fixed_blockdev_probe_uses_retained_procfd_after_named_path_swap() {
        let fixture = tempfile::tempdir().expect("blockdev procfd fixture");
        let named = fixture.path().join("selected-device");
        let moved = fixture.path().join("original-device");
        fs::write(&named, b"77\n").expect("write original identity");
        let retained = File::open(&named).expect("retain original identity");
        let procfd = descriptor_procfd_path(&retained).expect("retained procfd");
        fs::rename(&named, &moved).expect("move original pathname");
        fs::write(&named, b"99\n").expect("write pathname replacement");

        let tool = fixture.path().join("mock-blockdev");
        fs::write(
            &tool,
            b"#!/bin/sh\n[ \"$#\" -eq 2 ] || exit 90\n[ \"$1\" = --getdiskseq ] || exit 91\ncase \"$2\" in /proc/[0-9]*/fd/[0-9]*) ;; *) exit 92 ;; esac\nexec /usr/bin/cat \"$2\"\n",
        )
        .expect("write blockdev mock");
        fs::set_permissions(&tool, fs::Permissions::from_mode(0o700))
            .expect("make blockdev mock executable");

        assert_eq!(
            test_blockdev_query(
                &tool,
                &procfd,
                BlockdevQuery::DiskSequence,
                Duration::from_secs(1),
            ),
            Ok(77)
        );
        assert_eq!(fs::read(named).expect("read replacement"), b"99\n");
    }

    #[test]
    #[ignore = "subprocess probe must run without parallel vault lock descriptors"]
    fn fixed_blockdev_probe_ignores_sysfs_spoof_and_bounds_timeout_cleanup() {
        let fixture = tempfile::tempdir().expect("blockdev command fixture");
        let descriptor_path = fixture.path().join("retained");
        fs::write(&descriptor_path, b"descriptor").expect("write retained fixture");
        let retained = File::open(&descriptor_path).expect("open retained fixture");
        let procfd = descriptor_procfd_path(&retained).expect("retained procfd");
        let spoofed_sysfs = fixture.path().join("sys/dev/block/7:3");
        fs::create_dir_all(&spoofed_sysfs).expect("create spoofed sysfs");
        fs::write(spoofed_sysfs.join("diskseq"), b"999\n").expect("spoof diskseq");
        fs::write(spoofed_sysfs.join("size"), b"1\n").expect("spoof size");

        let fixed = fixture.path().join("fixed-blockdev");
        fs::write(
            &fixed,
            b"#!/bin/sh\n[ \"$#\" -eq 2 ] || exit 90\ncase \"$2\" in /proc/[0-9]*/fd/[0-9]*) ;; *) exit 91 ;; esac\ncase \"$1\" in --getdiskseq) echo 77 ;; --getsize64) echo 8589934592 ;; --getss) echo 512 ;; *) exit 92 ;; esac\n",
        )
        .expect("write fixed blockdev mock");
        fs::set_permissions(&fixed, fs::Permissions::from_mode(0o700))
            .expect("make fixed blockdev mock executable");
        let identity = consistent_descriptor_block_identity(|query| {
            test_blockdev_query(&fixed, &procfd, query, Duration::from_secs(1))
        })
        .expect("descriptor-only identity");
        assert_eq!(identity.disk_sequence, 77);
        assert_eq!(identity.sector_count, VAULT_SECTOR_COUNT);
        fs::remove_dir_all(fixture.path().join("sys")).expect("remove spoofed sysfs");
        assert_eq!(
            consistent_descriptor_block_identity(|query| {
                test_blockdev_query(&fixed, &procfd, query, Duration::from_secs(1))
            }),
            Ok(identity),
            "sysfs absence cannot alter the descriptor-only probe"
        );

        let oversized = fixture.path().join("oversized-blockdev");
        fs::write(
            &oversized,
            b"#!/bin/sh\nprintf 11111111111111111111111111111111111111111111111111111111111111111\n",
        )
        .expect("write oversized mock");
        fs::set_permissions(&oversized, fs::Permissions::from_mode(0o700))
            .expect("make oversized mock executable");
        assert_eq!(
            test_blockdev_query(
                &oversized,
                &procfd,
                BlockdevQuery::SizeBytes,
                Duration::from_secs(1),
            ),
            Err(DescriptorBlockIdentityError::IdentityUnavailable)
        );

        let descendant_pid = fixture.path().join("descendant.pid");
        let timeout_tool = fixture.path().join("timeout-blockdev");
        fs::write(
            &timeout_tool,
            format!(
                "#!/bin/sh\ntrap '' TERM\n/usr/bin/sleep 30 &\nprintf '%s' \"$!\" > '{}'\nprintf ready\nwait\n",
                descendant_pid.display()
            ),
        )
        .expect("write timeout mock");
        fs::set_permissions(&timeout_tool, fs::Permissions::from_mode(0o700))
            .expect("make timeout mock executable");
        let started = Instant::now();
        assert_eq!(
            test_blockdev_query(
                &timeout_tool,
                &procfd,
                BlockdevQuery::SizeBytes,
                Duration::from_millis(100),
            ),
            Err(DescriptorBlockIdentityError::OperationTimedOut)
        );
        assert!(started.elapsed() < Duration::from_secs(3));
        let descendant: i32 = fs::read_to_string(descendant_pid)
            .expect("read descendant pid")
            .parse()
            .expect("numeric descendant pid");
        let descendant = rustix::process::Pid::from_raw(descendant).expect("positive pid");
        assert_eq!(
            rustix::process::test_kill_process(descendant).err(),
            Some(rustix::io::Errno::SRCH)
        );
    }

    #[test]
    #[ignore = "subprocess probe must run without parallel vault lock descriptors"]
    fn repeated_blockdev_queries_share_one_aggregate_deadline() {
        let fixture = tempfile::tempdir().expect("aggregate deadline fixture");
        let descriptor_path = fixture.path().join("retained");
        fs::write(&descriptor_path, b"descriptor").expect("write retained fixture");
        let retained = File::open(&descriptor_path).expect("open retained fixture");
        let procfd = descriptor_procfd_path(&retained).expect("retained procfd");
        let calls = fixture.path().join("calls");
        let tool = fixture.path().join("slow-blockdev");
        fs::write(
            &tool,
            format!(
                "#!/bin/sh\nprintf '%s\\n' \"$1\" >> '{}'\n/usr/bin/sleep 0.4\ncase \"$1\" in --getdiskseq) echo 77 ;; --getsize64) echo 8589934592 ;; --getss) echo 512 ;; *) exit 92 ;; esac\n",
                calls.display()
            ),
        )
        .expect("write slow blockdev mock");
        fs::set_permissions(&tool, fs::Permissions::from_mode(0o700))
            .expect("make slow blockdev mock executable");

        let started = Instant::now();
        let deadline = started
            .checked_add(Duration::from_millis(750))
            .expect("deadline");
        assert_eq!(
            query_descriptor_block_identity_until(&procfd, deadline, |path, query, timeout| {
                test_blockdev_query(&tool, path, query, timeout)
            },),
            Err(DescriptorBlockIdentityError::OperationTimedOut)
        );
        assert!(
            started.elapsed() < Duration::from_secs(2),
            "six independent per-query budgets would exceed this aggregate bound"
        );
        assert_eq!(
            fs::read_to_string(&calls)
                .expect("read child calls")
                .lines()
                .count(),
            2,
            "the second child must receive only the first child's remaining budget"
        );

        #[cfg(feature = "experimental-vault-manager")]
        {
            fs::write(&calls, b"").expect("reset child calls");
            let started = Instant::now();
            let deadline = started
                .checked_add(Duration::from_millis(750))
                .expect("geometry deadline");
            assert_eq!(
                query_descriptor_block_geometry_until(&procfd, deadline, |path, query, timeout| {
                    test_blockdev_query(&tool, path, query, timeout)
                },),
                Err(DescriptorBlockIdentityError::OperationTimedOut)
            );
            assert!(started.elapsed() < Duration::from_secs(2));
            assert_eq!(
                fs::read_to_string(&calls)
                    .expect("read geometry child calls")
                    .lines()
                    .count(),
                2
            );
        }
    }

    #[cfg(feature = "experimental-vault-manager")]
    #[test]
    fn classification_deadline_is_nonzero_and_capped() {
        assert_eq!(
            classification_deadline(Duration::ZERO).err(),
            Some(LocatedVaultClassificationError::InvalidDeadline)
        );
        assert_eq!(
            classification_deadline(MAX_CLASSIFICATION_TIMEOUT + Duration::from_nanos(1)).err(),
            Some(LocatedVaultClassificationError::InvalidDeadline)
        );
        assert!(classification_deadline(Duration::from_secs(1)).is_ok());
    }

    #[cfg(feature = "experimental-vault-manager")]
    #[test]
    fn quiescent_mountinfo_parser_rejects_target_residue_and_ambiguous_views() {
        let unrelated = b"36 25 8:2 / /mnt rw,relatime - ext4 /dev/sda2 rw\n";
        assert!(mountinfo_excludes_device(unrelated, (8, 3)));
        let unrelated_with_optional =
            b"36 25 8:2 / /mnt rw,relatime shared:1 master:2 - ext4 /dev/sda2 rw\n";
        assert!(mountinfo_excludes_device(unrelated_with_optional, (8, 3)));
        assert!(!mountinfo_excludes_device(
            b"36 25 8:3 / /mnt rw,relatime - ext4 /dev/sda3 rw\n",
            (8, 3)
        ));
        for malformed in [
            &b""[..],
            &b"36 25 8:2 / /mnt rw - ext4 /dev/sda2 rw"[..],
            &b"36 25 bad / /mnt rw - ext4 /dev/sda2 rw\n"[..],
            &b"36 25 8:2 / /mnt rw ext4 /dev/sda2 rw\n"[..],
            &b"36 25 8:2 / /mnt rw - ext4 /dev/sda2\n"[..],
            &b"36 25 8:2 / /mnt rw shared:1 - ext4 /dev/sda2\n"[..],
            &b"36 25 8:2 / /mnt rw - ext4 /dev/sda2 -\n"[..],
            &b"36 25 8:2 / /mnt rw - - /dev/sda2 rw\n"[..],
            &b"36 25 8:2 / /mnt rw - ext4 /dev/sda2 rw trailing\n"[..],
            &b"36 25 8:2 / /mnt  rw - ext4 /dev/sda2 rw\n"[..],
            &b"\n"[..],
        ] {
            assert!(!mountinfo_excludes_device(malformed, (8, 3)));
        }
    }

    #[test]
    fn no_public_locator_entry_point_accepts_a_path() {
        let signature: fn() -> Result<BootVaultLocation, BootVaultLocatorError> = locate_boot_vault;
        let _ = signature;
    }
}
