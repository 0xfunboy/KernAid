//! Real read-only observation for the Rescue `fstab` candidate.
//!
//! This boundary accepts only a retained target/physical-parent guard. It
//! creates an unattached ext4 mount from the held leaf descriptor with
//! `ro,noload,nodev,nosuid,noexec`, opens exactly `etc/fstab` beneath that
//! detached mount, and inventories UUIDs through the fixed trusted kernel
//! `/dev/disk/by-uuid` view. No mount is attached to the caller's namespace,
//! and no writable descriptor or caller-selected path exists in this API.

use crate::target_physical_parent::RescueTargetPhysicalParentGuard;
use kernaid_linux_pack::rescue_fstab_transaction_candidate::{
    CandidateEvidenceBinding, FSTAB_EVIDENCE_ID, LSBLK_EVIDENCE_ID,
};
use kernaid_protocol::rescue_repair_vault::RepairFileMetadataV1;
use rustix::{
    fd::{AsFd, BorrowedFd, OwnedFd},
    fs::{
        self as rfs, AtFlags, CWD, FileType, Mode, OFlags, RawDir, ResolveFlags, StatVfsMountFlags,
    },
    mount::{
        FsMountFlags, FsOpenFlags, MountAttrFlags, fsconfig_create, fsconfig_set_flag,
        fsconfig_set_string, fsmount, fsopen,
    },
};
use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeMap, BTreeSet},
    fmt,
    fs::File,
    io::Read,
    mem::MaybeUninit,
    os::fd::AsRawFd,
    path::{Path, PathBuf},
};

const PROC_SELF_FD_PREFIX: &str = "/proc/self/fd/";
const SYS_ROOT: &str = "/sys";
const DEV_ROOT: &str = "/dev";
const UUID_DIRECTORY: &str = "disk/by-uuid";
const FSTAB_RESOURCE: &str = "etc/fstab";
const EXT4_FILESYSTEM: &str = "ext4";
const EXT_SUPER_MAGIC: u64 = 0xef53;
const SYSFS_MAGIC: u64 = 0x6265_6572;
const TMPFS_MAGIC: u64 = 0x0102_1994;
const MAX_FSTAB_BYTES: usize = 1024 * 1024;
const MAX_UUIDS: usize = 4096;
const MAX_UUID_BYTES: usize = 128;
const UUID_SCAN_BUFFER_BYTES: usize = 8192;
const OBSERVED_UUID_SET_HASH_DOMAIN: &[u8] =
    b"kernaid:linux.fstab.disable-missing-uuid.v1:observed-uuid-set:v1\0";

/// Closed observation failures. No error contains a device identifier,
/// pathname, mount option, command output, target byte, or OS error string.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RescueFstabObservationError {
    TargetChanged,
    DetachedMountUnavailable,
    UnsafeDetachedMount,
    FstabUnavailable,
    FstabTooLarge,
    UnsafeFstab,
    UuidInventoryUnavailable,
    InvalidUuidInventory,
    EvidenceRejected,
}

impl fmt::Display for RescueFstabObservationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::TargetChanged => "target identity changed during observation",
            Self::DetachedMountUnavailable => "detached read-only target mount unavailable",
            Self::UnsafeDetachedMount => "detached target mount is not safely read-only",
            Self::FstabUnavailable => "target fstab unavailable",
            Self::FstabTooLarge => "target fstab exceeds its observation bound",
            Self::UnsafeFstab => "target fstab object is unsafe",
            Self::UuidInventoryUnavailable => "trusted UUID inventory unavailable",
            Self::InvalidUuidInventory => "trusted UUID inventory is invalid",
            Self::EvidenceRejected => "candidate evidence binding rejected",
        })
    }
}

impl std::error::Error for RescueFstabObservationError {}

/// Immutable read-only observations for one candidate preflight.
///
/// Deliberately not `Clone`: the exact byte snapshot and evidence set should
/// be moved once into the preflight material rather than silently duplicated.
pub struct ObservedRescueFstab {
    fstab_bytes: Vec<u8>,
    metadata: RepairFileMetadataV1,
    observed_uuids: BTreeSet<String>,
    evidence: [CandidateEvidenceBinding; 2],
}

impl ObservedRescueFstab {
    pub fn fstab_bytes(&self) -> &[u8] {
        &self.fstab_bytes
    }

    pub const fn metadata(&self) -> &RepairFileMetadataV1 {
        &self.metadata
    }

    pub const fn observed_uuids(&self) -> &BTreeSet<String> {
        &self.observed_uuids
    }

    pub const fn evidence(&self) -> &[CandidateEvidenceBinding; 2] {
        &self.evidence
    }

    pub fn into_parts(
        self,
    ) -> (
        Vec<u8>,
        RepairFileMetadataV1,
        BTreeSet<String>,
        [CandidateEvidenceBinding; 2],
    ) {
        (
            self.fstab_bytes,
            self.metadata,
            self.observed_uuids,
            self.evidence,
        )
    }
}

impl fmt::Debug for ObservedRescueFstab {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ObservedRescueFstab")
            .field("fstab_bytes", &"[redacted]")
            .field("fstab_size", &self.fstab_bytes.len())
            .field("metadata", &self.metadata)
            .field("observed_uuid_count", &self.observed_uuids.len())
            .field("evidence", &"[opaque deterministic hashes]")
            .finish()
    }
}

/// Observe exactly `etc/fstab` and the normalized UUID inventory while the
/// supplied target guard retains both leaf and physical-parent descriptors.
pub fn observe_rescue_fstab(
    target: &RescueTargetPhysicalParentGuard,
) -> Result<ObservedRescueFstab, RescueFstabObservationError> {
    target
        .revalidate()
        .map_err(|_| RescueFstabObservationError::TargetChanged)?;

    let mount = create_detached_ext4_mount(target.target_block_descriptor())?;
    let (fstab_bytes, metadata) = read_exact_fstab(&mount)?;
    let observed_uuids = collect_normalized_uuids()?;

    target
        .revalidate()
        .map_err(|_| RescueFstabObservationError::TargetChanged)?;
    let evidence = evidence_bindings(&fstab_bytes, &observed_uuids)?;
    Ok(ObservedRescueFstab {
        fstab_bytes,
        metadata,
        observed_uuids,
        evidence,
    })
}

fn create_detached_ext4_mount(
    leaf: BorrowedFd<'_>,
) -> Result<OwnedFd, RescueFstabObservationError> {
    let before = block_snapshot(leaf).ok_or(RescueFstabObservationError::TargetChanged)?;
    let source = descriptor_source_path(leaf)?;
    let proc_snapshot = rfs::statat(CWD, &source, AtFlags::empty())
        .map(BlockSnapshot::from_stat)
        .map_err(|_| RescueFstabObservationError::TargetChanged)?;
    if proc_snapshot != before {
        return Err(RescueFstabObservationError::TargetChanged);
    }

    let context = fsopen(EXT4_FILESYSTEM, FsOpenFlags::FSOPEN_CLOEXEC)
        .map_err(|_| RescueFstabObservationError::DetachedMountUnavailable)?;
    fsconfig_set_string(&context, "source", &source)
        .map_err(|_| RescueFstabObservationError::DetachedMountUnavailable)?;
    fsconfig_set_flag(&context, "ro")
        .map_err(|_| RescueFstabObservationError::DetachedMountUnavailable)?;
    // Ext4 may replay a journal even for a read-only mount unless `noload` is
    // explicit. Failure to admit this flag is terminal; there is no fallback.
    fsconfig_set_flag(&context, "noload")
        .map_err(|_| RescueFstabObservationError::DetachedMountUnavailable)?;
    fsconfig_create(&context).map_err(|_| RescueFstabObservationError::DetachedMountUnavailable)?;
    let attributes = MountAttrFlags::MOUNT_ATTR_RDONLY
        | MountAttrFlags::MOUNT_ATTR_NODEV
        | MountAttrFlags::MOUNT_ATTR_NOSUID
        | MountAttrFlags::MOUNT_ATTR_NOEXEC;
    let mount = fsmount(&context, FsMountFlags::FSMOUNT_CLOEXEC, attributes)
        .map_err(|_| RescueFstabObservationError::DetachedMountUnavailable)?;
    validate_detached_mount(&mount)?;

    if block_snapshot(leaf) != Some(before)
        || rfs::statat(CWD, &source, AtFlags::empty())
            .map(BlockSnapshot::from_stat)
            .ok()
            != Some(before)
    {
        return Err(RescueFstabObservationError::TargetChanged);
    }
    Ok(mount)
}

fn descriptor_source_path(
    descriptor: BorrowedFd<'_>,
) -> Result<PathBuf, RescueFstabObservationError> {
    let number = descriptor.as_raw_fd();
    if number < 0 {
        return Err(RescueFstabObservationError::TargetChanged);
    }
    Ok(PathBuf::from(format!("{PROC_SELF_FD_PREFIX}{number}")))
}

fn validate_detached_mount(mount: &OwnedFd) -> Result<(), RescueFstabObservationError> {
    let stat = rfs::fstat(mount).map_err(|_| RescueFstabObservationError::UnsafeDetachedMount)?;
    let filesystem =
        rfs::fstatfs(mount).map_err(|_| RescueFstabObservationError::UnsafeDetachedMount)?;
    let filesystem_flags =
        rfs::fstatvfs(mount).map_err(|_| RescueFstabObservationError::UnsafeDetachedMount)?;
    let descriptor_flags = rustix::io::fcntl_getfd(mount)
        .map_err(|_| RescueFstabObservationError::UnsafeDetachedMount)?;
    let required = StatVfsMountFlags::RDONLY
        | StatVfsMountFlags::NODEV
        | StatVfsMountFlags::NOSUID
        | StatVfsMountFlags::NOEXEC;
    if !FileType::from_raw_mode(stat.st_mode).is_dir()
        || filesystem.f_type as u64 != EXT_SUPER_MAGIC
        || !filesystem_flags.f_flag.contains(required)
        || !descriptor_flags.contains(rustix::io::FdFlags::CLOEXEC)
    {
        return Err(RescueFstabObservationError::UnsafeDetachedMount);
    }
    Ok(())
}

fn read_exact_fstab(
    mount: &OwnedFd,
) -> Result<(Vec<u8>, RepairFileMetadataV1), RescueFstabObservationError> {
    validate_detached_mount(mount)?;
    let descriptor = rfs::openat2(
        mount,
        FSTAB_RESOURCE,
        OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NOFOLLOW | OFlags::NONBLOCK,
        Mode::empty(),
        ResolveFlags::BENEATH | ResolveFlags::NO_MAGICLINKS | ResolveFlags::NO_SYMLINKS,
    )
    .map_err(|_| RescueFstabObservationError::FstabUnavailable)?;
    let before = file_snapshot(&descriptor)?;
    // The Vault persistence contract admits only the canonical system fstab
    // ownership/mode. Refuse a readable but non-canonical object before its
    // bytes can become candidate evidence.
    if before.mode & 0o7777 != 0o644 || before.uid != 0 || before.gid != 0 {
        return Err(RescueFstabObservationError::UnsafeFstab);
    }
    let size = usize::try_from(before.size)
        .ok()
        .filter(|size| (1..=MAX_FSTAB_BYTES).contains(size))
        .ok_or(RescueFstabObservationError::FstabTooLarge)?;
    // RepairFileMetadataV1 declares xattrs and POSIX ACLs absent. Refuse any
    // extended attribute rather than silently losing metadata during backup.
    let mut xattr_probe = [0_u8; 0];
    let xattr_bytes = rfs::flistxattr(&descriptor, &mut xattr_probe)
        .map_err(|_| RescueFstabObservationError::UnsafeFstab)?;
    if xattr_bytes != 0 {
        return Err(RescueFstabObservationError::UnsafeFstab);
    }

    let mut file = File::from(descriptor);
    let mut bytes = Vec::with_capacity(size);
    Read::by_ref(&mut file)
        .take((MAX_FSTAB_BYTES + 1) as u64)
        .read_to_end(&mut bytes)
        .map_err(|_| RescueFstabObservationError::FstabUnavailable)?;
    if bytes.len() != size || bytes.contains(&0) || std::str::from_utf8(&bytes).is_err() {
        return Err(RescueFstabObservationError::UnsafeFstab);
    }
    let after = file_snapshot(&file)?;
    let named = rfs::statat(mount, FSTAB_RESOURCE, AtFlags::SYMLINK_NOFOLLOW)
        .map(FileSnapshot::from_stat)
        .map_err(|_| RescueFstabObservationError::UnsafeFstab)?;
    if before != after || after != named {
        return Err(RescueFstabObservationError::UnsafeFstab);
    }
    validate_detached_mount(mount)?;

    let metadata = RepairFileMetadataV1::new(0o644, 0, 0)
        .map_err(|_| RescueFstabObservationError::UnsafeFstab)?;
    Ok((bytes, metadata))
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
struct BlockSnapshot {
    device: u64,
    inode: u64,
    rdev: u64,
}

impl BlockSnapshot {
    fn from_stat(stat: rustix::fs::Stat) -> Self {
        Self {
            device: stat.st_dev,
            inode: stat.st_ino,
            rdev: stat.st_rdev,
        }
    }

    fn major_minor(self) -> (u32, u32) {
        (rfs::major(self.rdev), rfs::minor(self.rdev))
    }
}

fn block_snapshot(descriptor: BorrowedFd<'_>) -> Option<BlockSnapshot> {
    let stat = rfs::fstat(descriptor).ok()?;
    let status = rfs::fcntl_getfl(descriptor).ok()?;
    let descriptor_flags = rustix::io::fcntl_getfd(descriptor).ok()?;
    if !FileType::from_raw_mode(stat.st_mode).is_block_device()
        || status & OFlags::ACCMODE != OFlags::RDONLY
        || !status.contains(OFlags::NONBLOCK)
        || !descriptor_flags.contains(rustix::io::FdFlags::CLOEXEC)
    {
        return None;
    }
    Some(BlockSnapshot::from_stat(stat))
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct FileSnapshot {
    device: u64,
    inode: u64,
    mode: u32,
    uid: u32,
    gid: u32,
    links: u64,
    size: i64,
    modified_seconds: i64,
    modified_nanoseconds: u64,
    changed_seconds: i64,
    changed_nanoseconds: u64,
}

impl FileSnapshot {
    fn from_stat(stat: rustix::fs::Stat) -> Self {
        Self {
            device: stat.st_dev,
            inode: stat.st_ino,
            mode: stat.st_mode,
            uid: stat.st_uid,
            gid: stat.st_gid,
            links: stat.st_nlink,
            size: stat.st_size,
            modified_seconds: stat.st_mtime,
            modified_nanoseconds: stat.st_mtime_nsec,
            changed_seconds: stat.st_ctime,
            changed_nanoseconds: stat.st_ctime_nsec,
        }
    }
}

fn file_snapshot(descriptor: &impl AsFd) -> Result<FileSnapshot, RescueFstabObservationError> {
    let stat = rfs::fstat(descriptor).map_err(|_| RescueFstabObservationError::UnsafeFstab)?;
    let status =
        rfs::fcntl_getfl(descriptor).map_err(|_| RescueFstabObservationError::UnsafeFstab)?;
    let descriptor_flags = rustix::io::fcntl_getfd(descriptor)
        .map_err(|_| RescueFstabObservationError::UnsafeFstab)?;
    if !FileType::from_raw_mode(stat.st_mode).is_file()
        || stat.st_nlink != 1
        || stat.st_size <= 0
        || status & OFlags::ACCMODE != OFlags::RDONLY
        || !status.contains(OFlags::NONBLOCK)
        || !descriptor_flags.contains(rustix::io::FdFlags::CLOEXEC)
    {
        return Err(RescueFstabObservationError::UnsafeFstab);
    }
    Ok(FileSnapshot::from_stat(stat))
}

fn collect_normalized_uuids() -> Result<BTreeSet<String>, RescueFstabObservationError> {
    // `/dev/disk/by-uuid` is treated strictly as the host's trusted udev view:
    // its fixed roots and every resolved block node are kernel-cross-checked,
    // then the entire inventory is scanned twice to reject concurrent change.
    let sys = open_trusted_root(Path::new(SYS_ROOT), SYSFS_MAGIC)?;
    let dev = open_trusted_root(Path::new(DEV_ROOT), TMPFS_MAGIC)?;
    let first = scan_uuid_inventory(&sys, &dev)?;
    let second = scan_uuid_inventory(&sys, &dev)?;
    if first != second {
        return Err(RescueFstabObservationError::InvalidUuidInventory);
    }
    Ok(first.into_keys().collect())
}

fn open_trusted_root(
    path: &Path,
    expected_magic: u64,
) -> Result<OwnedFd, RescueFstabObservationError> {
    let descriptor = rfs::open(
        path,
        OFlags::PATH | OFlags::DIRECTORY | OFlags::CLOEXEC | OFlags::NOFOLLOW,
        Mode::empty(),
    )
    .map_err(|_| RescueFstabObservationError::UuidInventoryUnavailable)?;
    let stat = rfs::fstat(&descriptor)
        .map_err(|_| RescueFstabObservationError::UuidInventoryUnavailable)?;
    let filesystem = rfs::fstatfs(&descriptor)
        .map_err(|_| RescueFstabObservationError::UuidInventoryUnavailable)?;
    if !FileType::from_raw_mode(stat.st_mode).is_dir()
        || stat.st_uid != 0
        || filesystem.f_type as u64 != expected_magic
        || !rustix::io::fcntl_getfd(&descriptor)
            .map_err(|_| RescueFstabObservationError::UuidInventoryUnavailable)?
            .contains(rustix::io::FdFlags::CLOEXEC)
    {
        return Err(RescueFstabObservationError::UuidInventoryUnavailable);
    }
    Ok(descriptor)
}

fn scan_uuid_inventory(
    sys: &OwnedFd,
    dev: &OwnedFd,
) -> Result<BTreeMap<String, BlockSnapshot>, RescueFstabObservationError> {
    let directory = rfs::openat2(
        dev,
        UUID_DIRECTORY,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC | OFlags::NOFOLLOW,
        Mode::empty(),
        ResolveFlags::BENEATH | ResolveFlags::NO_MAGICLINKS | ResolveFlags::NO_SYMLINKS,
    )
    .map_err(|_| RescueFstabObservationError::UuidInventoryUnavailable)?;
    let mut buffer = [MaybeUninit::uninit(); UUID_SCAN_BUFFER_BYTES];
    let mut entries = RawDir::new(&directory, &mut buffer);
    let mut inventory = BTreeMap::new();
    let mut count = 0_usize;
    while let Some(entry) = entries.next() {
        let entry = entry.map_err(|_| RescueFstabObservationError::InvalidUuidInventory)?;
        let name = entry.file_name().to_bytes();
        if matches!(name, b"." | b"..") {
            continue;
        }
        count = count
            .checked_add(1)
            .filter(|count| *count <= MAX_UUIDS)
            .ok_or(RescueFstabObservationError::InvalidUuidInventory)?;
        let uuid = normalize_uuid(name)?;
        let target = open_uuid_target(sys, dev, &uuid)?;
        if inventory.insert(uuid, target).is_some() {
            return Err(RescueFstabObservationError::InvalidUuidInventory);
        }
    }
    if inventory.is_empty() {
        return Err(RescueFstabObservationError::InvalidUuidInventory);
    }
    Ok(inventory)
}

fn open_uuid_target(
    sys: &OwnedFd,
    dev: &OwnedFd,
    uuid: &str,
) -> Result<BlockSnapshot, RescueFstabObservationError> {
    let relative = PathBuf::from(UUID_DIRECTORY).join(uuid);
    let descriptor = rfs::openat2(
        dev,
        &relative,
        OFlags::PATH | OFlags::CLOEXEC,
        Mode::empty(),
        ResolveFlags::BENEATH | ResolveFlags::NO_MAGICLINKS,
    )
    .map_err(|_| RescueFstabObservationError::InvalidUuidInventory)?;
    let stat =
        rfs::fstat(&descriptor).map_err(|_| RescueFstabObservationError::InvalidUuidInventory)?;
    if !FileType::from_raw_mode(stat.st_mode).is_block_device()
        || !rustix::io::fcntl_getfd(&descriptor)
            .map_err(|_| RescueFstabObservationError::InvalidUuidInventory)?
            .contains(rustix::io::FdFlags::CLOEXEC)
    {
        return Err(RescueFstabObservationError::InvalidUuidInventory);
    }
    let snapshot = BlockSnapshot::from_stat(stat);
    let (major, minor) = snapshot.major_minor();
    let sysfs_link = format!("dev/block/{major}:{minor}");
    let sysfs = rfs::openat2(
        sys,
        sysfs_link,
        OFlags::PATH | OFlags::DIRECTORY | OFlags::CLOEXEC,
        Mode::empty(),
        ResolveFlags::BENEATH | ResolveFlags::NO_MAGICLINKS,
    )
    .map_err(|_| RescueFstabObservationError::InvalidUuidInventory)?;
    let sysfs_stat =
        rfs::fstat(&sysfs).map_err(|_| RescueFstabObservationError::InvalidUuidInventory)?;
    if !FileType::from_raw_mode(sysfs_stat.st_mode).is_dir() || sysfs_stat.st_uid != 0 {
        return Err(RescueFstabObservationError::InvalidUuidInventory);
    }
    Ok(snapshot)
}

fn normalize_uuid(bytes: &[u8]) -> Result<String, RescueFstabObservationError> {
    if bytes.is_empty()
        || bytes.len() > MAX_UUID_BYTES
        || bytes.first() == Some(&b'-')
        || bytes.last() == Some(&b'-')
        || !bytes
            .iter()
            .all(|byte| byte.is_ascii_hexdigit() || *byte == b'-')
    {
        return Err(RescueFstabObservationError::InvalidUuidInventory);
    }
    let uuid = std::str::from_utf8(bytes)
        .map_err(|_| RescueFstabObservationError::InvalidUuidInventory)?
        .to_ascii_lowercase();
    Ok(uuid)
}

fn evidence_bindings(
    fstab: &[u8],
    observed_uuids: &BTreeSet<String>,
) -> Result<[CandidateEvidenceBinding; 2], RescueFstabObservationError> {
    let fstab_sha256 = sha256_bytes(fstab);
    let uuid_sha256 = observed_uuid_set_sha256(observed_uuids);
    Ok([
        CandidateEvidenceBinding::new(FSTAB_EVIDENCE_ID, fstab_sha256)
            .map_err(|_| RescueFstabObservationError::EvidenceRejected)?,
        CandidateEvidenceBinding::new(LSBLK_EVIDENCE_ID, uuid_sha256)
            .map_err(|_| RescueFstabObservationError::EvidenceRejected)?,
    ])
}

fn sha256_bytes(bytes: &[u8]) -> String {
    format!("sha256:{:x}", Sha256::digest(bytes))
}

fn observed_uuid_set_sha256(observed: &BTreeSet<String>) -> String {
    let mut digest = Sha256::new();
    digest.update(OBSERVED_UUID_SET_HASH_DOMAIN);
    digest.update((observed.len() as u64).to_be_bytes());
    for uuid in observed {
        digest.update((uuid.len() as u64).to_be_bytes());
        digest.update(uuid.as_bytes());
    }
    format!("sha256:{:x}", digest.finalize())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn uuid_normalization_and_hash_are_canonical() {
        let observed = ["DEAD-BEEF", "aaaa-bbbb"]
            .into_iter()
            .map(|uuid| normalize_uuid(uuid.as_bytes()).expect("canonical UUID"))
            .collect::<BTreeSet<_>>();
        assert_eq!(
            observed,
            BTreeSet::from(["aaaa-bbbb".to_owned(), "dead-beef".to_owned()])
        );
        assert_eq!(
            observed_uuid_set_sha256(&observed),
            "sha256:90138e9f8e6b75b9cd2ec66951ee541f8bde7d89060061b455141ccbd684aac7"
        );
        assert_eq!(
            normalize_uuid(b"../../sda"),
            Err(RescueFstabObservationError::InvalidUuidInventory)
        );
        assert_eq!(
            normalize_uuid(b"mapper/root"),
            Err(RescueFstabObservationError::InvalidUuidInventory)
        );
    }

    #[test]
    fn evidence_order_and_exact_fstab_hash_are_deterministic() {
        let fstab = b"UUID=AAAA-BBBB / ext4 defaults 0 1\n";
        let observed = BTreeSet::from(["aaaa-bbbb".to_owned()]);
        let evidence = evidence_bindings(fstab, &observed).expect("evidence bindings");
        assert_eq!(evidence[0].evidence_id(), FSTAB_EVIDENCE_ID);
        assert_eq!(
            evidence[0].sha256(),
            "sha256:6cc2d04e8163e63e011cfec035b9dec6c5fed63afc19f1a7bc9f67ee6e4a676d"
        );
        assert_eq!(evidence[1].evidence_id(), LSBLK_EVIDENCE_ID);
        assert_eq!(evidence[1].sha256(), observed_uuid_set_sha256(&observed));
    }
}
