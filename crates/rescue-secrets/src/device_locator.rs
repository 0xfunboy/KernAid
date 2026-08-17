//! Read-only discovery of the vault partition belonging to the exact Rescue
//! boot medium.
//!
//! Discovery starts at the fixed `/run/live/medium` mount, walks only its
//! kernel sysfs ancestry, and accepts only sibling MBR slot 3 with the pinned
//! layout-v1 geometry. It never searches all disks and has no caller-supplied
//! device or path parameter.

use crate::bounded_process;
use rustix::fs::{self as rfs, FileType, Mode, OFlags};
use std::{
    collections::BTreeMap,
    error::Error,
    ffi::{OsStr, OsString},
    fmt, fs, io,
    os::{
        fd::{AsFd, BorrowedFd, OwnedFd},
        unix::{ffi::OsStrExt, fs::FileExt},
    },
    path::{Path, PathBuf},
    process::{Command, Stdio},
    time::Duration,
};

const LIVE_MEDIUM_MOUNT: &[u8] = b"/run/live/medium";
const ISO9660: &[u8] = b"iso9660";
const BLOCKDEV_PATH: &str = "/usr/sbin/blockdev";
const BLOCKDEV_TIMEOUT: Duration = Duration::from_secs(2);
const BLOCKDEV_OUTPUT_LIMIT: usize = 64;
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
        })
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
    let parent_identity = descriptor_block_identity(parent)?;
    let partition_identity = descriptor_block_identity(partition)?;
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

#[derive(Clone, Copy)]
struct DescriptorBlockIdentity {
    disk_sequence: u64,
    sector_count: u64,
    logical_sector_bytes: u64,
}

fn descriptor_block_identity(
    descriptor: &fs::File,
) -> Result<DescriptorBlockIdentity, BootVaultLocatorError> {
    Ok(DescriptorBlockIdentity {
        disk_sequence: blockdev_u64(descriptor, "--getdiskseq")?,
        sector_count: blockdev_u64(descriptor, "--getsz")?,
        logical_sector_bytes: blockdev_u64(descriptor, "--getss")?,
    })
}

/// util-linux performs BLKGETDISKSEQ/BLKGETSIZE/BLKSSZGET on fd 0 reached
/// through a fixed procfd name. `Command` maps a CLOEXEC duplicate to fd 0;
/// no mutable pathname or inherited ambient descriptor is handed to it.
fn blockdev_u64(
    descriptor: &fs::File,
    operation: &'static str,
) -> Result<u64, BootVaultLocatorError> {
    let input: OwnedFd = rustix::io::fcntl_dupfd_cloexec(descriptor, 3)
        .map_err(|_| BootVaultLocatorError::BlockIdentityUnavailable)?;
    let mut command = Command::new(BLOCKDEV_PATH);
    command
        .arg(operation)
        .arg("/proc/self/fd/0")
        .env_clear()
        .env("LC_ALL", "C")
        .stdin(Stdio::from(input))
        .stdout(Stdio::piped())
        .stderr(Stdio::null());
    let output = bounded_process::capture(&mut command, BLOCKDEV_TIMEOUT, BLOCKDEV_OUTPUT_LIMIT)
        .map_err(|error| match error {
            bounded_process::BoundedProcessError::Unavailable => {
                BootVaultLocatorError::ToolUnavailable
            }
            bounded_process::BoundedProcessError::StartFailed
            | bounded_process::BoundedProcessError::WaitFailed
            | bounded_process::BoundedProcessError::TimedOut
            | bounded_process::BoundedProcessError::UnexpectedDescendant
            | bounded_process::BoundedProcessError::CleanupFailed => {
                BootVaultLocatorError::BlockIdentityUnavailable
            }
        })?;
    if !output.status.success() || output.exceeded_limit {
        return Err(BootVaultLocatorError::BlockIdentityUnavailable);
    }
    parse_u64(trim_line(&output.bytes))
        .filter(|value| *value > 0)
        .ok_or(BootVaultLocatorError::BlockIdentityUnavailable)
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
    use std::{fs::OpenOptions, os::unix::fs::symlink};
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
    fn no_public_locator_entry_point_accepts_a_path() {
        let signature: fn() -> Result<BootVaultLocation, BootVaultLocatorError> = locate_boot_vault;
        let _ = signature;
    }
}
