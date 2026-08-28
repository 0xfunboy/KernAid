//! Descriptor-bound Linux physical-parent identity for Rescue targets.
//!
//! The public boundary accepts only an already authenticated target
//! capability. Kernel topology is resolved through fixed trusted `/sys` and
//! `/dev` roots, all observations are bounded, and both the leaf and physical
//! parent descriptors remain held by the returned non-cloneable guard. No
//! mount, writable open, device pathname, or raw target byte crosses this API.

#[cfg(feature = "rescue-fstab-production-candidate")]
use crate::target_capability_client::RescueTargetCapabilityClaims;
use crate::target_capability_client::RescueTargetReadOnlyCapability;
use kernaid_protocol::rescue_physical_parent::{
    PhysicalParentClaims, canonical_physical_parent_digest, render_physical_parent_prefixed,
};
use rustix::{
    fd::{AsFd, BorrowedFd, OwnedFd},
    fs::{self as rfs, AtFlags, CWD, FileType, Mode, OFlags, ResolveFlags},
};
use std::{
    ffi::{OsStr, OsString},
    fmt,
    fs::File,
    io::Read,
    os::unix::ffi::{OsStrExt, OsStringExt},
    path::{Component, Path, PathBuf},
    process::{Child, Command, Stdio},
    thread,
    time::{Duration, Instant},
};

const SYS_ROOT: &str = "/sys";
const DEV_ROOT: &str = "/dev";
const BLOCKDEV: &str = "/usr/sbin/blockdev";
const CHILD_BLOCK_DESCRIPTOR: &str = "/proc/self/fd/0";
const SYSFS_MAGIC: u64 = 0x6265_6572;
const TMPFS_MAGIC: u64 = 0x0102_1994;
const KERNEL_SECTOR_BYTES: u64 = 512;
const MAX_SYSFS_ATTRIBUTE_BYTES: usize = 4096;
const MAX_SYSFS_LINK_BYTES: usize = 2048;
const MAX_SYSFS_COMPONENTS: usize = 64;
const MAX_SYSFS_COMPONENT_BYTES: usize = 255;
const MAX_UEVENT_LINES: usize = 64;
const MAX_DEVICE_NAME_BYTES: usize = 127;
const MAX_BLOCKDEV_OUTPUT_BYTES: usize = 128;
const BLOCKDEV_DEADLINE: Duration = Duration::from_secs(2);
const CHILD_POLL_INTERVAL: Duration = Duration::from_millis(5);
const CHILD_KILL_GRACE: Duration = Duration::from_secs(1);

/// Closed failures from the trusted physical-parent resolver. No variant can
/// carry a pathname, device name, device number, command output, or OS text.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TargetPhysicalParentError {
    Unavailable,
    InvalidLeafCapability,
    InvalidTrustedRoot,
    InvalidKernelTopology,
    UnsupportedTopology,
    ParentUnavailable,
    IdentityProbeFailed,
    IdentityChanged,
}

impl fmt::Display for TargetPhysicalParentError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Unavailable => "target physical-parent resolver unavailable",
            Self::InvalidLeafCapability => "invalid target leaf capability",
            Self::InvalidTrustedRoot => "invalid trusted kernel root",
            Self::InvalidKernelTopology => "invalid target kernel topology",
            Self::UnsupportedTopology => "unsupported target block topology",
            Self::ParentUnavailable => "target physical parent unavailable",
            Self::IdentityProbeFailed => "target physical-parent identity probe failed",
            Self::IdentityChanged => "target physical-parent identity changed",
        })
    }
}

impl std::error::Error for TargetPhysicalParentError {}

/// Non-cloneable authority binding one selected leaf to its physical parent.
///
/// The leaf descriptor remains inside `target`; `parent` is a separately
/// opened read-only descriptor. Numeric claims are useful only while this
/// guard remains alive and successfully revalidates.
pub struct RescueTargetPhysicalParentGuard {
    target: RescueTargetReadOnlyCapability,
    parent: OwnedFd,
    leaf_snapshot: DescriptorSnapshot,
    parent_snapshot: DescriptorSnapshot,
    topology: SysfsTopology,
    claims: PhysicalParentClaims,
    physical_parent_fingerprint: String,
}

impl RescueTargetPhysicalParentGuard {
    /// Boot-local physical-parent claims derived from the retained FDs.
    pub const fn claims(&self) -> &PhysicalParentClaims {
        &self.claims
    }

    /// Canonical `sha256:` rendering used by the candidate transaction plan.
    pub fn physical_parent_fingerprint(&self) -> &str {
        &self.physical_parent_fingerprint
    }

    /// Repeats descriptor, topology and ioctl checkpoints against the claims
    /// retained by this guard. Any unavailable observation fails closed.
    pub fn revalidate(&self) -> Result<(), TargetPhysicalParentError> {
        let roots = TrustedRoots::production()?;
        validate_retained_pair(
            &roots,
            self.target.block_descriptor(),
            self.parent.as_fd(),
            self.leaf_snapshot,
            self.parent_snapshot,
            &self.topology,
        )
    }

    /// Borrows the exact held leaf authority without exposing or transferring
    /// a device pathname or descriptor ownership.
    #[allow(dead_code)]
    pub(crate) fn target_block_descriptor(&self) -> BorrowedFd<'_> {
        self.target.block_descriptor()
    }

    /// Opaque scan fingerprint authenticated with the target capability.
    #[allow(dead_code)]
    pub(crate) fn target_scan_fingerprint(&self) -> &str {
        self.target.claims().scan_fingerprint()
    }

    #[cfg(feature = "rescue-fstab-production-candidate")]
    pub(crate) fn target_claims(&self) -> &RescueTargetCapabilityClaims {
        self.target.claims()
    }
}

impl fmt::Debug for RescueTargetPhysicalParentGuard {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RescueTargetPhysicalParentGuard")
            .field("target", &"[owned read-only leaf capability]")
            .field("parent", &"[owned read-only physical-parent capability]")
            .field("claims", &"[path-free numeric identity]")
            .field("physical_parent_fingerprint", &"[opaque fingerprint]")
            .finish()
    }
}

impl RescueTargetReadOnlyCapability {
    /// Consumes this leaf capability and binds it to one verified physical
    /// parent. Failure closes every descriptor acquired during resolution.
    pub fn bind_physical_parent(
        self,
    ) -> Result<RescueTargetPhysicalParentGuard, TargetPhysicalParentError> {
        resolve_rescue_target_physical_parent(self)
    }
}

/// Resolves one authenticated leaf capability to a retained physical parent.
/// The fixed production roots and fixed read-only ioctl probe are not caller
/// configurable.
pub fn resolve_rescue_target_physical_parent(
    target: RescueTargetReadOnlyCapability,
) -> Result<RescueTargetPhysicalParentGuard, TargetPhysicalParentError> {
    let roots = TrustedRoots::production()?;
    let leaf_snapshot = validate_block_descriptor(target.block_descriptor(), None)
        .map_err(|_| TargetPhysicalParentError::InvalidLeafCapability)?;
    let leaf_major_minor = leaf_snapshot.major_minor();
    let topology = resolve_sysfs_topology(&roots.sys, leaf_major_minor, true)?;
    let parent = open_parent_descriptor(&roots.dev, &topology)?;
    let parent_snapshot =
        validate_block_descriptor(parent.as_fd(), Some(topology.parent_major_minor))
            .map_err(|_| TargetPhysicalParentError::ParentUnavailable)?;

    validate_retained_pair(
        &roots,
        target.block_descriptor(),
        parent.as_fd(),
        leaf_snapshot,
        parent_snapshot,
        &topology,
    )?;

    let claims = topology.physical_parent_claims();
    let physical_parent_fingerprint =
        render_physical_parent_prefixed(&canonical_physical_parent_digest(&claims));
    Ok(RescueTargetPhysicalParentGuard {
        target,
        parent,
        leaf_snapshot,
        parent_snapshot,
        topology,
        claims,
        physical_parent_fingerprint,
    })
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct DescriptorSnapshot {
    device: u64,
    inode: u64,
    rdev: u64,
}

impl DescriptorSnapshot {
    fn major_minor(self) -> (u32, u32) {
        (rfs::major(self.rdev), rfs::minor(self.rdev))
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct SysfsTopology {
    leaf_major_minor: (u32, u32),
    parent_major_minor: (u32, u32),
    parent_device_name: OsString,
    disk_sequence: u64,
    leaf_sector_count: u64,
    parent_sector_count: u64,
    logical_sector_bytes: u64,
}

impl SysfsTopology {
    fn physical_parent_claims(&self) -> PhysicalParentClaims {
        PhysicalParentClaims::new(
            self.parent_major_minor.0,
            self.parent_major_minor.1,
            self.disk_sequence,
            self.parent_sector_count,
            self.logical_sector_bytes,
        )
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct DescriptorProbe {
    disk_sequence: u64,
    size_bytes: u64,
    logical_sector_bytes: u64,
}

struct TrustedRoots {
    sys: OwnedFd,
    dev: OwnedFd,
}

impl TrustedRoots {
    fn production() -> Result<Self, TargetPhysicalParentError> {
        let sys = open_trusted_root(Path::new(SYS_ROOT), SYSFS_MAGIC)?;
        let dev = open_trusted_root(Path::new(DEV_ROOT), TMPFS_MAGIC)?;
        // Pin the two fixed sysfs namespaces before following any device link.
        let _dev_block = open_directory(&sys, Path::new("dev/block"), true)?;
        let _devices = open_directory(&sys, Path::new("devices"), true)?;
        Ok(Self { sys, dev })
    }
}

fn open_trusted_root(
    path: &Path,
    expected_magic: u64,
) -> Result<OwnedFd, TargetPhysicalParentError> {
    let descriptor = rfs::open(
        path,
        OFlags::PATH | OFlags::DIRECTORY | OFlags::CLOEXEC | OFlags::NOFOLLOW,
        Mode::empty(),
    )
    .map_err(|_| TargetPhysicalParentError::InvalidTrustedRoot)?;
    let stat =
        rfs::fstat(&descriptor).map_err(|_| TargetPhysicalParentError::InvalidTrustedRoot)?;
    let filesystem =
        rfs::fstatfs(&descriptor).map_err(|_| TargetPhysicalParentError::InvalidTrustedRoot)?;
    let descriptor_flags = rustix::io::fcntl_getfd(&descriptor)
        .map_err(|_| TargetPhysicalParentError::InvalidTrustedRoot)?;
    if !FileType::from_raw_mode(stat.st_mode).is_dir()
        || stat.st_uid != 0
        || filesystem.f_type as u64 != expected_magic
        || !descriptor_flags.contains(rustix::io::FdFlags::CLOEXEC)
    {
        return Err(TargetPhysicalParentError::InvalidTrustedRoot);
    }
    Ok(descriptor)
}

fn validate_block_descriptor(
    descriptor: BorrowedFd<'_>,
    expected_major_minor: Option<(u32, u32)>,
) -> Result<DescriptorSnapshot, ()> {
    let stat = rfs::fstat(descriptor).map_err(|_| ())?;
    let status = rfs::fcntl_getfl(descriptor).map_err(|_| ())?;
    let descriptor_flags = rustix::io::fcntl_getfd(descriptor).map_err(|_| ())?;
    let snapshot = DescriptorSnapshot {
        device: stat.st_dev,
        inode: stat.st_ino,
        rdev: stat.st_rdev,
    };
    if !FileType::from_raw_mode(stat.st_mode).is_block_device()
        || status & OFlags::ACCMODE != OFlags::RDONLY
        || !status.contains(OFlags::NONBLOCK)
        || !descriptor_flags.contains(rustix::io::FdFlags::CLOEXEC)
        || expected_major_minor.is_some_and(|expected| snapshot.major_minor() != expected)
    {
        return Err(());
    }
    Ok(snapshot)
}

fn validate_retained_pair(
    roots: &TrustedRoots,
    leaf: BorrowedFd<'_>,
    parent: BorrowedFd<'_>,
    expected_leaf: DescriptorSnapshot,
    expected_parent: DescriptorSnapshot,
    expected_topology: &SysfsTopology,
) -> Result<(), TargetPhysicalParentError> {
    if validate_block_descriptor(leaf, Some(expected_topology.leaf_major_minor))
        != Ok(expected_leaf)
        || validate_block_descriptor(parent, Some(expected_topology.parent_major_minor))
            != Ok(expected_parent)
    {
        return Err(TargetPhysicalParentError::IdentityChanged);
    }

    let first_topology =
        resolve_sysfs_topology(&roots.sys, expected_topology.leaf_major_minor, true)?;
    if &first_topology != expected_topology {
        return Err(TargetPhysicalParentError::IdentityChanged);
    }
    let named_parent = open_parent_descriptor(&roots.dev, expected_topology)?;
    if validate_block_descriptor(
        named_parent.as_fd(),
        Some(expected_topology.parent_major_minor),
    ) != Ok(expected_parent)
    {
        return Err(TargetPhysicalParentError::IdentityChanged);
    }

    let leaf_before = query_descriptor(leaf)?;
    let parent_before = query_descriptor(parent)?;
    let second_topology =
        resolve_sysfs_topology(&roots.sys, expected_topology.leaf_major_minor, true)?;
    let leaf_after = query_descriptor(leaf)?;
    let parent_after = query_descriptor(parent)?;
    if second_topology != first_topology
        || validate_descriptor_probes(
            expected_topology,
            leaf_before,
            leaf_after,
            parent_before,
            parent_after,
        )
        .is_err()
        || validate_block_descriptor(leaf, Some(expected_topology.leaf_major_minor))
            != Ok(expected_leaf)
        || validate_block_descriptor(parent, Some(expected_topology.parent_major_minor))
            != Ok(expected_parent)
    {
        return Err(TargetPhysicalParentError::IdentityChanged);
    }
    Ok(())
}

fn validate_descriptor_probes(
    topology: &SysfsTopology,
    leaf_before: DescriptorProbe,
    leaf_after: DescriptorProbe,
    parent_before: DescriptorProbe,
    parent_after: DescriptorProbe,
) -> Result<(), TargetPhysicalParentError> {
    let leaf_size = topology
        .leaf_sector_count
        .checked_mul(KERNEL_SECTOR_BYTES)
        .ok_or(TargetPhysicalParentError::IdentityChanged)?;
    let parent_size = topology
        .parent_sector_count
        .checked_mul(KERNEL_SECTOR_BYTES)
        .ok_or(TargetPhysicalParentError::IdentityChanged)?;
    if leaf_before != leaf_after
        || parent_before != parent_after
        || leaf_before.disk_sequence != topology.disk_sequence
        || parent_before.disk_sequence != topology.disk_sequence
        || leaf_before.size_bytes != leaf_size
        || parent_before.size_bytes != parent_size
        || leaf_before.logical_sector_bytes != topology.logical_sector_bytes
        || parent_before.logical_sector_bytes != topology.logical_sector_bytes
    {
        return Err(TargetPhysicalParentError::IdentityChanged);
    }
    Ok(())
}

fn resolve_sysfs_topology(
    sys: &OwnedFd,
    leaf_major_minor: (u32, u32),
    require_root_owner: bool,
) -> Result<SysfsTopology, TargetPhysicalParentError> {
    let leaf_path = resolve_sysfs_device(sys, leaf_major_minor, require_root_owner)?;
    if !leaf_path.starts_with(Path::new("devices"))
        || leaf_path.starts_with(Path::new("devices/virtual"))
    {
        return Err(TargetPhysicalParentError::UnsupportedTopology);
    }
    let leaf = open_directory(sys, &leaf_path, require_root_owner)?;
    if read_major_minor(&leaf, Path::new("dev"), require_root_owner)? != leaf_major_minor {
        return Err(TargetPhysicalParentError::InvalidKernelTopology);
    }

    let partition = read_optional_positive_u64(&leaf, Path::new("partition"), require_root_owner)?;
    let parent_path = if partition.is_some() {
        let mut parent = leaf_path.clone();
        if !parent.pop() || parent == Path::new("devices") {
            return Err(TargetPhysicalParentError::UnsupportedTopology);
        }
        parent
    } else {
        leaf_path.clone()
    };
    let parent = open_directory(sys, &parent_path, require_root_owner)?;
    if read_optional_positive_u64(&parent, Path::new("partition"), require_root_owner)?.is_some() {
        return Err(TargetPhysicalParentError::InvalidKernelTopology);
    }
    let parent_major_minor = read_major_minor(&parent, Path::new("dev"), require_root_owner)?;
    if resolve_sysfs_device(sys, parent_major_minor, require_root_owner)? != parent_path {
        return Err(TargetPhysicalParentError::InvalidKernelTopology);
    }

    let leaf_sector_count = read_positive_u64(&leaf, Path::new("size"), require_root_owner)?;
    let parent_sector_count = read_positive_u64(&parent, Path::new("size"), require_root_owner)?;
    let disk_sequence = read_positive_u64(&parent, Path::new("diskseq"), require_root_owner)?;
    let logical_sector_bytes = read_positive_u64(
        &parent,
        Path::new("queue/logical_block_size"),
        require_root_owner,
    )?;
    if !(KERNEL_SECTOR_BYTES..=65_536).contains(&logical_sector_bytes)
        || !logical_sector_bytes.is_power_of_two()
        || leaf_sector_count > parent_sector_count
    {
        return Err(TargetPhysicalParentError::InvalidKernelTopology);
    }

    let parent_uevent = read_small_file(&parent, Path::new("uevent"), require_root_owner)?;
    let parent_device_name =
        parse_block_uevent(&parent_uevent, parent_major_minor, "disk", disk_sequence)?;
    let leaf_uevent = read_small_file(&leaf, Path::new("uevent"), require_root_owner)?;
    let expected_leaf_type = if partition.is_some() {
        "partition"
    } else {
        "disk"
    };
    parse_block_uevent(
        &leaf_uevent,
        leaf_major_minor,
        expected_leaf_type,
        disk_sequence,
    )?;

    // Re-resolve both canonical links after every attribute read. This closes
    // the sysfs observation window before descriptor ioctls begin.
    if resolve_sysfs_device(sys, leaf_major_minor, require_root_owner)? != leaf_path
        || resolve_sysfs_device(sys, parent_major_minor, require_root_owner)? != parent_path
    {
        return Err(TargetPhysicalParentError::IdentityChanged);
    }
    Ok(SysfsTopology {
        leaf_major_minor,
        parent_major_minor,
        parent_device_name,
        disk_sequence,
        leaf_sector_count,
        parent_sector_count,
        logical_sector_bytes,
    })
}

fn resolve_sysfs_device(
    sys: &OwnedFd,
    major_minor: (u32, u32),
    require_root_owner: bool,
) -> Result<PathBuf, TargetPhysicalParentError> {
    let link = PathBuf::from(format!("dev/block/{}:{}", major_minor.0, major_minor.1));
    let target = rfs::readlinkat(sys, &link, Vec::with_capacity(MAX_SYSFS_LINK_BYTES))
        .map_err(|_| TargetPhysicalParentError::InvalidKernelTopology)?;
    if target.as_bytes().is_empty() || target.as_bytes().len() > MAX_SYSFS_LINK_BYTES {
        return Err(TargetPhysicalParentError::InvalidKernelTopology);
    }
    let canonical = normalize_sysfs_link(Path::new("dev/block"), target.as_bytes())?;
    let canonical_fd = open_directory(sys, &canonical, require_root_owner)?;
    let linked_fd = rfs::openat2(
        sys,
        &link,
        OFlags::PATH | OFlags::DIRECTORY | OFlags::CLOEXEC,
        Mode::empty(),
        ResolveFlags::BENEATH | ResolveFlags::NO_MAGICLINKS,
    )
    .map_err(|_| TargetPhysicalParentError::InvalidKernelTopology)?;
    if descriptor_object(&canonical_fd, require_root_owner)?
        != descriptor_object(&linked_fd, require_root_owner)?
    {
        return Err(TargetPhysicalParentError::IdentityChanged);
    }
    Ok(canonical)
}

fn normalize_sysfs_link(base: &Path, target: &[u8]) -> Result<PathBuf, TargetPhysicalParentError> {
    if target.is_empty() || target.len() > MAX_SYSFS_LINK_BYTES || target.contains(&0) {
        return Err(TargetPhysicalParentError::InvalidKernelTopology);
    }
    let mut components = Vec::<OsString>::new();
    for component in base.components() {
        let Component::Normal(component) = component else {
            return Err(TargetPhysicalParentError::InvalidKernelTopology);
        };
        components.push(component.to_os_string());
    }
    let target = Path::new(OsStr::from_bytes(target));
    for component in target.components() {
        match component {
            Component::CurDir => {}
            Component::ParentDir => {
                components
                    .pop()
                    .ok_or(TargetPhysicalParentError::InvalidKernelTopology)?;
            }
            Component::Normal(component) => {
                if component.as_bytes().is_empty()
                    || component.as_bytes().len() > MAX_SYSFS_COMPONENT_BYTES
                    || components.len() >= MAX_SYSFS_COMPONENTS
                {
                    return Err(TargetPhysicalParentError::InvalidKernelTopology);
                }
                components.push(component.to_os_string());
            }
            Component::RootDir | Component::Prefix(_) => {
                return Err(TargetPhysicalParentError::InvalidKernelTopology);
            }
        }
    }
    if components.is_empty() || components.len() > MAX_SYSFS_COMPONENTS {
        return Err(TargetPhysicalParentError::InvalidKernelTopology);
    }
    let mut normalized = PathBuf::new();
    for component in components {
        normalized.push(component);
    }
    Ok(normalized)
}

fn open_directory(
    root: &OwnedFd,
    path: &Path,
    require_root_owner: bool,
) -> Result<OwnedFd, TargetPhysicalParentError> {
    let descriptor = rfs::openat2(
        root,
        path,
        OFlags::PATH | OFlags::DIRECTORY | OFlags::CLOEXEC | OFlags::NOFOLLOW,
        Mode::empty(),
        ResolveFlags::BENEATH | ResolveFlags::NO_MAGICLINKS | ResolveFlags::NO_SYMLINKS,
    )
    .map_err(|_| TargetPhysicalParentError::InvalidKernelTopology)?;
    descriptor_object(&descriptor, require_root_owner)?;
    Ok(descriptor)
}

fn descriptor_object(
    descriptor: &OwnedFd,
    require_root_owner: bool,
) -> Result<(u64, u64), TargetPhysicalParentError> {
    let stat =
        rfs::fstat(descriptor).map_err(|_| TargetPhysicalParentError::InvalidKernelTopology)?;
    let flags = rustix::io::fcntl_getfd(descriptor)
        .map_err(|_| TargetPhysicalParentError::InvalidKernelTopology)?;
    if !FileType::from_raw_mode(stat.st_mode).is_dir()
        || (require_root_owner && stat.st_uid != 0)
        || !flags.contains(rustix::io::FdFlags::CLOEXEC)
    {
        return Err(TargetPhysicalParentError::InvalidKernelTopology);
    }
    Ok((stat.st_dev, stat.st_ino))
}

fn read_small_file(
    directory: &OwnedFd,
    name: &Path,
    require_root_owner: bool,
) -> Result<Vec<u8>, TargetPhysicalParentError> {
    let descriptor = rfs::openat2(
        directory,
        name,
        OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NOFOLLOW | OFlags::NONBLOCK,
        Mode::empty(),
        ResolveFlags::BENEATH | ResolveFlags::NO_MAGICLINKS | ResolveFlags::NO_SYMLINKS,
    )
    .map_err(|_| TargetPhysicalParentError::InvalidKernelTopology)?;
    let stat =
        rfs::fstat(&descriptor).map_err(|_| TargetPhysicalParentError::InvalidKernelTopology)?;
    let flags = rustix::io::fcntl_getfd(&descriptor)
        .map_err(|_| TargetPhysicalParentError::InvalidKernelTopology)?;
    if !FileType::from_raw_mode(stat.st_mode).is_file()
        || (require_root_owner && stat.st_uid != 0)
        || !flags.contains(rustix::io::FdFlags::CLOEXEC)
    {
        return Err(TargetPhysicalParentError::InvalidKernelTopology);
    }
    let mut file = File::from(descriptor);
    let mut bytes = Vec::with_capacity(64);
    Read::by_ref(&mut file)
        .take((MAX_SYSFS_ATTRIBUTE_BYTES + 1) as u64)
        .read_to_end(&mut bytes)
        .map_err(|_| TargetPhysicalParentError::InvalidKernelTopology)?;
    if bytes.is_empty() || bytes.len() > MAX_SYSFS_ATTRIBUTE_BYTES || bytes.contains(&0) {
        return Err(TargetPhysicalParentError::InvalidKernelTopology);
    }
    Ok(bytes)
}

fn read_optional_positive_u64(
    directory: &OwnedFd,
    name: &Path,
    require_root_owner: bool,
) -> Result<Option<u64>, TargetPhysicalParentError> {
    match rfs::openat2(
        directory,
        name,
        OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NOFOLLOW | OFlags::NONBLOCK,
        Mode::empty(),
        ResolveFlags::BENEATH | ResolveFlags::NO_MAGICLINKS | ResolveFlags::NO_SYMLINKS,
    ) {
        Ok(descriptor) => {
            drop(descriptor);
            read_positive_u64(directory, name, require_root_owner).map(Some)
        }
        Err(error) if error == rustix::io::Errno::NOENT => Ok(None),
        Err(_) => Err(TargetPhysicalParentError::InvalidKernelTopology),
    }
}

fn read_positive_u64(
    directory: &OwnedFd,
    name: &Path,
    require_root_owner: bool,
) -> Result<u64, TargetPhysicalParentError> {
    let bytes = read_small_file(directory, name, require_root_owner)?;
    parse_u64(trim_line(&bytes))
        .filter(|value| *value > 0)
        .ok_or(TargetPhysicalParentError::InvalidKernelTopology)
}

fn read_major_minor(
    directory: &OwnedFd,
    name: &Path,
    require_root_owner: bool,
) -> Result<(u32, u32), TargetPhysicalParentError> {
    let bytes = read_small_file(directory, name, require_root_owner)?;
    parse_major_minor(trim_line(&bytes)).ok_or(TargetPhysicalParentError::InvalidKernelTopology)
}

fn parse_block_uevent(
    bytes: &[u8],
    expected_major_minor: (u32, u32),
    expected_type: &str,
    expected_disk_sequence: u64,
) -> Result<OsString, TargetPhysicalParentError> {
    if bytes.len() > MAX_SYSFS_ATTRIBUTE_BYTES || !bytes.ends_with(b"\n") {
        return Err(TargetPhysicalParentError::InvalidKernelTopology);
    }
    let mut major = None;
    let mut minor = None;
    let mut device_name = None;
    let mut device_type = None;
    let mut disk_sequence = None;
    let mut lines = 0_usize;
    for line in bytes[..bytes.len() - 1].split(|byte| *byte == b'\n') {
        if line.is_empty() {
            return Err(TargetPhysicalParentError::InvalidKernelTopology);
        }
        lines = lines
            .checked_add(1)
            .ok_or(TargetPhysicalParentError::InvalidKernelTopology)?;
        if lines > MAX_UEVENT_LINES {
            return Err(TargetPhysicalParentError::InvalidKernelTopology);
        }
        let Some((key, value)) = split_once_byte(line, b'=') else {
            return Err(TargetPhysicalParentError::InvalidKernelTopology);
        };
        match key {
            b"MAJOR" => set_once(&mut major, parse_u32(value))?,
            b"MINOR" => set_once(&mut minor, parse_u32(value))?,
            b"DEVNAME" => {
                if !safe_device_name(value) {
                    return Err(TargetPhysicalParentError::InvalidKernelTopology);
                }
                set_once(&mut device_name, Some(OsString::from_vec(value.to_vec())))?;
            }
            b"DEVTYPE" => set_once(&mut device_type, std::str::from_utf8(value).ok())?,
            b"DISKSEQ" => set_once(&mut disk_sequence, parse_u64(value))?,
            _ => {}
        }
    }
    if major != Some(expected_major_minor.0)
        || minor != Some(expected_major_minor.1)
        || device_type != Some(expected_type)
        || disk_sequence.is_some_and(|value| value != expected_disk_sequence)
    {
        return Err(TargetPhysicalParentError::InvalidKernelTopology);
    }
    device_name.ok_or(TargetPhysicalParentError::InvalidKernelTopology)
}

fn set_once<T>(slot: &mut Option<T>, value: Option<T>) -> Result<(), TargetPhysicalParentError> {
    if slot.is_some() || value.is_none() {
        return Err(TargetPhysicalParentError::InvalidKernelTopology);
    }
    *slot = value;
    Ok(())
}

fn safe_device_name(value: &[u8]) -> bool {
    (1..=MAX_DEVICE_NAME_BYTES).contains(&value.len())
        && value != b"."
        && value != b".."
        && value
            .iter()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
}

fn parse_major_minor(bytes: &[u8]) -> Option<(u32, u32)> {
    let (major, minor) = split_once_byte(bytes, b':')?;
    Some((parse_u32(major)?, parse_u32(minor)?))
}

fn split_once_byte(bytes: &[u8], separator: u8) -> Option<(&[u8], &[u8])> {
    let index = bytes.iter().position(|byte| *byte == separator)?;
    Some((&bytes[..index], &bytes[index + 1..]))
}

fn parse_u32(bytes: &[u8]) -> Option<u32> {
    u32::try_from(parse_u64(bytes)?).ok()
}

fn parse_u64(bytes: &[u8]) -> Option<u64> {
    if bytes.is_empty() || !bytes.iter().all(u8::is_ascii_digit) {
        return None;
    }
    let mut value = 0_u64;
    for byte in bytes {
        value = value.checked_mul(10)?.checked_add(u64::from(byte - b'0'))?;
    }
    Some(value)
}

fn trim_line(bytes: &[u8]) -> &[u8] {
    bytes
        .strip_suffix(b"\n")
        .unwrap_or(bytes)
        .strip_suffix(b"\r")
        .unwrap_or_else(|| bytes.strip_suffix(b"\n").unwrap_or(bytes))
}

fn open_parent_descriptor(
    dev: &OwnedFd,
    topology: &SysfsTopology,
) -> Result<OwnedFd, TargetPhysicalParentError> {
    let descriptor = rfs::openat2(
        dev,
        Path::new(&topology.parent_device_name),
        OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NOFOLLOW | OFlags::NONBLOCK,
        Mode::empty(),
        ResolveFlags::BENEATH | ResolveFlags::NO_MAGICLINKS | ResolveFlags::NO_SYMLINKS,
    )
    .map_err(|_| TargetPhysicalParentError::ParentUnavailable)?;
    validate_block_descriptor(descriptor.as_fd(), Some(topology.parent_major_minor))
        .map_err(|_| TargetPhysicalParentError::ParentUnavailable)?;
    Ok(descriptor)
}

fn query_descriptor(
    descriptor: BorrowedFd<'_>,
) -> Result<DescriptorProbe, TargetPhysicalParentError> {
    let logical_sector_bytes = u64::from(
        rfs::ioctl_blksszget(descriptor)
            .map_err(|_| TargetPhysicalParentError::IdentityProbeFailed)?,
    );
    let duplicate = rustix::io::fcntl_dupfd_cloexec(descriptor, 3)
        .map_err(|_| TargetPhysicalParentError::IdentityProbeFailed)?;
    let executable_before = executable_snapshot()?;
    let mut command = Command::new(BLOCKDEV);
    command
        .arg("--getdiskseq")
        .arg("--getsize64")
        .arg("--getss")
        .arg(CHILD_BLOCK_DESCRIPTOR)
        .env_clear()
        .env("LC_ALL", "C")
        .stdin(Stdio::from(File::from(duplicate)))
        .stdout(Stdio::piped())
        .stderr(Stdio::null());
    let output = bounded_child_output(&mut command)?;
    if executable_snapshot()? != executable_before {
        return Err(TargetPhysicalParentError::IdentityProbeFailed);
    }
    let values = parse_blockdev_output(&output)?;
    if values.logical_sector_bytes != logical_sector_bytes {
        return Err(TargetPhysicalParentError::IdentityProbeFailed);
    }
    Ok(values)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct ExecutableSnapshot {
    device: u64,
    inode: u64,
    size: i64,
    modified_seconds: i64,
    modified_nanoseconds: u64,
}

fn executable_snapshot() -> Result<ExecutableSnapshot, TargetPhysicalParentError> {
    let stat = rfs::statat(CWD, BLOCKDEV, AtFlags::SYMLINK_NOFOLLOW)
        .map_err(|_| TargetPhysicalParentError::IdentityProbeFailed)?;
    if !FileType::from_raw_mode(stat.st_mode).is_file()
        || stat.st_uid != 0
        || stat.st_size <= 0
        || stat.st_mode & 0o022 != 0
    {
        return Err(TargetPhysicalParentError::IdentityProbeFailed);
    }
    Ok(ExecutableSnapshot {
        device: stat.st_dev,
        inode: stat.st_ino,
        size: stat.st_size,
        modified_seconds: stat.st_mtime,
        modified_nanoseconds: stat.st_mtime_nsec,
    })
}

fn bounded_child_output(command: &mut Command) -> Result<Vec<u8>, TargetPhysicalParentError> {
    let mut child = command
        .spawn()
        .map_err(|_| TargetPhysicalParentError::IdentityProbeFailed)?;
    let deadline = Instant::now()
        .checked_add(BLOCKDEV_DEADLINE)
        .ok_or(TargetPhysicalParentError::IdentityProbeFailed)?;
    loop {
        match child.try_wait() {
            Ok(Some(status)) => {
                if !status.success() {
                    return Err(TargetPhysicalParentError::IdentityProbeFailed);
                }
                let mut stdout = child
                    .stdout
                    .take()
                    .ok_or(TargetPhysicalParentError::IdentityProbeFailed)?;
                let mut output = Vec::with_capacity(64);
                Read::by_ref(&mut stdout)
                    .take((MAX_BLOCKDEV_OUTPUT_BYTES + 1) as u64)
                    .read_to_end(&mut output)
                    .map_err(|_| TargetPhysicalParentError::IdentityProbeFailed)?;
                if output.is_empty()
                    || output.len() > MAX_BLOCKDEV_OUTPUT_BYTES
                    || output.contains(&0)
                {
                    return Err(TargetPhysicalParentError::IdentityProbeFailed);
                }
                return Ok(output);
            }
            Ok(None) if Instant::now() < deadline => thread::sleep(CHILD_POLL_INTERVAL),
            Ok(None) => {
                terminate_child(&mut child);
                return Err(TargetPhysicalParentError::IdentityProbeFailed);
            }
            Err(_) => {
                terminate_child(&mut child);
                return Err(TargetPhysicalParentError::IdentityProbeFailed);
            }
        }
    }
}

fn terminate_child(child: &mut Child) {
    let _ = child.kill();
    let deadline = Instant::now() + CHILD_KILL_GRACE;
    while Instant::now() < deadline {
        match child.try_wait() {
            Ok(Some(_)) | Err(_) => return,
            Ok(None) => thread::sleep(CHILD_POLL_INTERVAL),
        }
    }
}

fn parse_blockdev_output(bytes: &[u8]) -> Result<DescriptorProbe, TargetPhysicalParentError> {
    if !bytes.ends_with(b"\n") {
        return Err(TargetPhysicalParentError::IdentityProbeFailed);
    }
    let values: Vec<u64> = bytes[..bytes.len() - 1]
        .split(|byte| *byte == b'\n')
        .map(parse_u64)
        .collect::<Option<Vec<_>>>()
        .ok_or(TargetPhysicalParentError::IdentityProbeFailed)?;
    let [disk_sequence, size_bytes, logical_sector_bytes] = values.as_slice() else {
        return Err(TargetPhysicalParentError::IdentityProbeFailed);
    };
    if *disk_sequence == 0
        || *size_bytes == 0
        || *size_bytes % KERNEL_SECTOR_BYTES != 0
        || *logical_sector_bytes == 0
    {
        return Err(TargetPhysicalParentError::IdentityProbeFailed);
    }
    Ok(DescriptorProbe {
        disk_sequence: *disk_sequence,
        size_bytes: *size_bytes,
        logical_sector_bytes: *logical_sector_bytes,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        fs, io,
        os::unix::fs::symlink,
        sync::atomic::{AtomicU64, Ordering},
    };

    static FIXTURE_SEQUENCE: AtomicU64 = AtomicU64::new(0);

    struct TestDirectory(PathBuf);

    impl TestDirectory {
        fn new() -> io::Result<Self> {
            for _ in 0..64 {
                let sequence = FIXTURE_SEQUENCE.fetch_add(1, Ordering::Relaxed);
                let path = std::env::temp_dir().join(format!(
                    "kernaid-broker-physical-parent-{}-{sequence}",
                    std::process::id()
                ));
                if fs::create_dir(&path).is_ok() {
                    return Ok(Self(path));
                }
            }
            Err(io::Error::new(
                io::ErrorKind::AlreadyExists,
                "unique sysfs fixture directory unavailable",
            ))
        }

        fn path(&self) -> &Path {
            &self.0
        }
    }

    impl Drop for TestDirectory {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    struct SysfsFixture {
        _temporary: TestDirectory,
        sys: OwnedFd,
    }

    impl SysfsFixture {
        fn direct_partition() -> Self {
            let temporary = TestDirectory::new().expect("sysfs fixture");
            let sys = temporary.path().join("sys");
            let parent = sys.join("devices/pci0000:00/block/sdz");
            let leaf = parent.join("sdz3");
            fs::create_dir_all(sys.join("dev/block")).expect("dev/block fixture");
            fs::create_dir_all(parent.join("queue")).expect("parent fixture");
            fs::create_dir_all(&leaf).expect("leaf fixture");
            fs::write(parent.join("dev"), b"8:16\n").expect("parent dev");
            fs::write(parent.join("size"), b"62500000\n").expect("parent size");
            fs::write(parent.join("diskseq"), b"77\n").expect("parent diskseq");
            fs::write(parent.join("queue/logical_block_size"), b"512\n")
                .expect("parent sector size");
            fs::write(
                parent.join("uevent"),
                b"MAJOR=8\nMINOR=16\nDEVNAME=sdz\nDEVTYPE=disk\nDISKSEQ=77\n",
            )
            .expect("parent uevent");
            fs::write(leaf.join("dev"), b"8:19\n").expect("leaf dev");
            fs::write(leaf.join("partition"), b"3\n").expect("leaf partition");
            fs::write(leaf.join("size"), b"16777216\n").expect("leaf size");
            fs::write(
                leaf.join("uevent"),
                b"MAJOR=8\nMINOR=19\nDEVNAME=sdz3\nDEVTYPE=partition\nDISKSEQ=77\n",
            )
            .expect("leaf uevent");
            symlink(
                "../../devices/pci0000:00/block/sdz",
                sys.join("dev/block/8:16"),
            )
            .expect("parent link");
            symlink(
                "../../devices/pci0000:00/block/sdz/sdz3",
                sys.join("dev/block/8:19"),
            )
            .expect("leaf link");
            let descriptor = rfs::open(
                &sys,
                OFlags::PATH | OFlags::DIRECTORY | OFlags::CLOEXEC | OFlags::NOFOLLOW,
                Mode::empty(),
            )
            .expect("open fixture sysfs");
            Self {
                _temporary: temporary,
                sys: descriptor,
            }
        }
    }

    #[test]
    fn synthetic_sysfs_derives_direct_parent_and_shared_digest() {
        let fixture = SysfsFixture::direct_partition();
        let topology =
            resolve_sysfs_topology(&fixture.sys, (8, 19), false).expect("resolve topology");
        assert_eq!(topology.parent_major_minor, (8, 16));
        assert_eq!(topology.parent_device_name, OsStr::new("sdz"));
        assert_eq!(topology.disk_sequence, 77);
        assert_eq!(topology.parent_sector_count, 62_500_000);
        assert_eq!(topology.logical_sector_bytes, 512);
        let digest = canonical_physical_parent_digest(&topology.physical_parent_claims());
        assert_eq!(
            render_physical_parent_prefixed(&digest),
            "sha256:ce1b61e97ecfb97d8b75e1f3cfbe5f83c24b52805def532bf5df3fdf59881de4"
        );

        let leaf = DescriptorProbe {
            disk_sequence: 77,
            size_bytes: 16_777_216 * 512,
            logical_sector_bytes: 512,
        };
        let parent = DescriptorProbe {
            disk_sequence: 77,
            size_bytes: 62_500_000 * 512,
            logical_sector_bytes: 512,
        };
        assert!(validate_descriptor_probes(&topology, leaf, leaf, parent, parent).is_ok());
        let changed = DescriptorProbe {
            disk_sequence: 78,
            ..parent
        };
        assert_eq!(
            validate_descriptor_probes(&topology, leaf, leaf, parent, changed),
            Err(TargetPhysicalParentError::IdentityChanged)
        );
    }

    #[test]
    fn synthetic_sysfs_rejects_escape_and_virtual_ancestry() {
        assert_eq!(
            normalize_sysfs_link(Path::new("dev/block"), b"../../../outside"),
            Err(TargetPhysicalParentError::InvalidKernelTopology)
        );
        assert_eq!(
            parse_blockdev_output(b"77\n32000000000\n512\nextra\n"),
            Err(TargetPhysicalParentError::IdentityProbeFailed)
        );
        assert!(!safe_device_name(b"../sda"));
        assert!(!safe_device_name(b"mapper/root"));
    }
}
