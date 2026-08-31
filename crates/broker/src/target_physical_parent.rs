//! Descriptor-bound Linux physical-parent identity for Rescue targets.
//!
//! The root-owned target handoff supplies both the selected leaf and its
//! physical parent. This module never resolves a device pathname or consults
//! a mutable device namespace: it derives and revalidates all numeric claims
//! from the retained readable leaf and non-readable parent identity handle.

#[cfg(any(
    feature = "rescue-fstab-production-candidate",
    feature = "rescue-crypttab-production-candidate",
    feature = "rescue-ext4-fsck-production-candidate"
))]
use crate::target_capability_client::RescueTargetCapabilityClaims;
use crate::target_capability_client::{
    PhysicalParentNumericClaims, RescueTargetReadOnlyCapability,
};
use kernaid_protocol::rescue_physical_parent::{
    PhysicalParentClaims, canonical_physical_parent_digest, render_physical_parent_prefixed,
};
use rustix::{
    fd::BorrowedFd,
    fs::{self as rfs, AtFlags, CWD, FileType, OFlags},
};
use std::{
    collections::BTreeSet,
    fmt,
    fs::File,
    io::Read,
    process::{Child, Command, Stdio},
    thread,
    time::{Duration, Instant},
};

const BLOCKFD_PROBE: &str = "/usr/lib/kernaid/kernaid-blockfd-probe";
const KERNEL_SECTOR_BYTES: u64 = 512;
const MAX_PROBE_OUTPUT_BYTES: usize = 128;
const PROBE_DEADLINE: Duration = Duration::from_secs(2);
const CHILD_POLL_INTERVAL: Duration = Duration::from_millis(5);
const CHILD_KILL_GRACE: Duration = Duration::from_secs(1);

/// Closed failures from the descriptor-only physical-parent binding.
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

/// Non-cloneable authority binding one selected leaf to its handed-off parent.
pub struct RescueTargetPhysicalParentGuard {
    target: RescueTargetReadOnlyCapability,
    leaf_snapshot: DescriptorSnapshot,
    parent_snapshot: DescriptorSnapshot,
    leaf_probe: DescriptorProbe,
    claims: PhysicalParentClaims,
    physical_parent_fingerprint: String,
}

impl RescueTargetPhysicalParentGuard {
    pub const fn claims(&self) -> &PhysicalParentClaims {
        &self.claims
    }

    pub fn physical_parent_fingerprint(&self) -> &str {
        &self.physical_parent_fingerprint
    }

    /// Repeats bundle validation and two leaf probes against the handed claims.
    pub fn revalidate(&self) -> Result<(), TargetPhysicalParentError> {
        self.target
            .revalidate_bundle()
            .map_err(|_| TargetPhysicalParentError::IdentityChanged)?;
        let leaf = validate_block_descriptor(self.target.block_descriptor())
            .map_err(|_| TargetPhysicalParentError::IdentityChanged)?;
        let numeric_claims = self.target.physical_parent_claims();
        let parent = validate_parent_identity_descriptor(
            self.target.physical_parent_descriptor(),
            numeric_claims,
        )
        .map_err(|_| TargetPhysicalParentError::IdentityChanged)?;
        if leaf != self.leaf_snapshot || parent != self.parent_snapshot {
            return Err(TargetPhysicalParentError::IdentityChanged);
        }
        let leaf_before = query_descriptor(self.target.block_descriptor())?;
        let leaf_after = query_descriptor(self.target.block_descriptor())?;
        validate_leaf_probe(numeric_claims, leaf_before, leaf_after)?;
        if leaf_before != self.leaf_probe {
            return Err(TargetPhysicalParentError::IdentityChanged);
        }
        self.target
            .revalidate_bundle()
            .map_err(|_| TargetPhysicalParentError::IdentityChanged)
    }

    #[allow(dead_code)]
    pub(crate) fn target_block_descriptor(&self) -> BorrowedFd<'_> {
        self.target.block_descriptor()
    }

    pub(crate) fn target_detached_mount_descriptor(&self) -> BorrowedFd<'_> {
        self.target.detached_mount_descriptor()
    }

    pub(crate) fn target_observed_uuids(&self) -> &BTreeSet<String> {
        self.target.observed_uuids()
    }

    #[allow(dead_code)]
    pub(crate) fn target_scan_fingerprint(&self) -> &str {
        self.target.claims().scan_fingerprint()
    }

    #[cfg(any(
        feature = "rescue-fstab-production-candidate",
        feature = "rescue-crypttab-production-candidate",
        feature = "rescue-ext4-fsck-production-candidate"
    ))]
    pub(crate) fn target_claims(&self) -> &RescueTargetCapabilityClaims {
        self.target.claims()
    }
}

impl fmt::Debug for RescueTargetPhysicalParentGuard {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RescueTargetPhysicalParentGuard")
            .field("target", &"[retained read-only capability bundle]")
            .field("claims", &"[path-free numeric identity]")
            .field("physical_parent_fingerprint", &"[opaque fingerprint]")
            .finish()
    }
}

impl RescueTargetReadOnlyCapability {
    pub fn bind_physical_parent(
        self,
    ) -> Result<RescueTargetPhysicalParentGuard, TargetPhysicalParentError> {
        resolve_rescue_target_physical_parent(self)
    }
}

/// Binds the two authenticated block FDs already present in the handoff.
pub fn resolve_rescue_target_physical_parent(
    target: RescueTargetReadOnlyCapability,
) -> Result<RescueTargetPhysicalParentGuard, TargetPhysicalParentError> {
    target
        .revalidate_bundle()
        .map_err(|_| TargetPhysicalParentError::InvalidLeafCapability)?;
    let leaf_snapshot = validate_block_descriptor(target.block_descriptor())
        .map_err(|_| TargetPhysicalParentError::InvalidLeafCapability)?;
    let numeric_claims = target.physical_parent_claims();
    let parent_snapshot =
        validate_parent_identity_descriptor(target.physical_parent_descriptor(), numeric_claims)
            .map_err(|_| TargetPhysicalParentError::ParentUnavailable)?;

    let leaf_before = query_descriptor(target.block_descriptor())?;
    let leaf_after = query_descriptor(target.block_descriptor())?;
    validate_leaf_probe(numeric_claims, leaf_before, leaf_after)?;
    target
        .revalidate_bundle()
        .map_err(|_| TargetPhysicalParentError::IdentityChanged)?;

    let claims = PhysicalParentClaims::new(
        numeric_claims.parent_major,
        numeric_claims.parent_minor,
        numeric_claims.disk_sequence,
        numeric_claims.media_sector_count,
        numeric_claims.logical_sector_bytes,
    );
    let physical_parent_fingerprint =
        render_physical_parent_prefixed(&canonical_physical_parent_digest(&claims));
    Ok(RescueTargetPhysicalParentGuard {
        target,
        leaf_snapshot,
        parent_snapshot,
        leaf_probe: leaf_before,
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

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct DescriptorProbe {
    disk_sequence: u64,
    size_bytes: u64,
    logical_sector_bytes: u64,
}

fn validate_block_descriptor(descriptor: BorrowedFd<'_>) -> Result<DescriptorSnapshot, ()> {
    let stat = rfs::fstat(descriptor).map_err(|_| ())?;
    let status = rfs::fcntl_getfl(descriptor).map_err(|_| ())?;
    let descriptor_flags = rustix::io::fcntl_getfd(descriptor).map_err(|_| ())?;
    if !FileType::from_raw_mode(stat.st_mode).is_block_device()
        || status & OFlags::ACCMODE != OFlags::RDONLY
        || !status.contains(OFlags::NONBLOCK)
        || descriptor_flags != rustix::io::FdFlags::CLOEXEC
    {
        return Err(());
    }
    Ok(DescriptorSnapshot {
        device: stat.st_dev,
        inode: stat.st_ino,
        rdev: stat.st_rdev,
    })
}

fn validate_parent_identity_descriptor(
    descriptor: BorrowedFd<'_>,
    claims: PhysicalParentNumericClaims,
) -> Result<DescriptorSnapshot, ()> {
    let stat = rfs::fstat(descriptor).map_err(|_| ())?;
    let status = rfs::fcntl_getfl(descriptor).map_err(|_| ())?;
    let descriptor_flags = rustix::io::fcntl_getfd(descriptor).map_err(|_| ())?;
    if !FileType::from_raw_mode(stat.st_mode).is_block_device()
        || !status.contains(OFlags::PATH)
        || descriptor_flags != rustix::io::FdFlags::CLOEXEC
        || rfs::major(stat.st_rdev) != claims.parent_major
        || rfs::minor(stat.st_rdev) != claims.parent_minor
    {
        return Err(());
    }
    Ok(DescriptorSnapshot {
        device: stat.st_dev,
        inode: stat.st_ino,
        rdev: stat.st_rdev,
    })
}

fn validate_leaf_probe(
    claims: PhysicalParentNumericClaims,
    leaf_before: DescriptorProbe,
    leaf_after: DescriptorProbe,
) -> Result<(), TargetPhysicalParentError> {
    let expected_size = claims
        .leaf_sector_count
        .checked_mul(KERNEL_SECTOR_BYTES)
        .ok_or(TargetPhysicalParentError::IdentityChanged)?;
    if leaf_before != leaf_after
        || leaf_before.disk_sequence != claims.disk_sequence
        || leaf_before.logical_sector_bytes != claims.logical_sector_bytes
        || leaf_before.size_bytes != expected_size
    {
        return Err(TargetPhysicalParentError::IdentityChanged);
    }
    Ok(())
}

fn query_descriptor(
    descriptor: BorrowedFd<'_>,
) -> Result<DescriptorProbe, TargetPhysicalParentError> {
    let duplicate = rustix::io::fcntl_dupfd_cloexec(descriptor, 3)
        .map_err(|_| TargetPhysicalParentError::IdentityProbeFailed)?;
    let executable_before = executable_snapshot()?;
    let mut command = Command::new(BLOCKFD_PROBE);
    command
        .env_clear()
        .env("LC_ALL", "C")
        .stdin(Stdio::from(File::from(duplicate)))
        .stdout(Stdio::piped())
        .stderr(Stdio::null());
    let output = bounded_child_output(&mut command)?;
    if executable_snapshot()? != executable_before {
        return Err(TargetPhysicalParentError::IdentityProbeFailed);
    }
    parse_blockfd_probe_output(&output)
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
    let stat = rfs::statat(CWD, BLOCKFD_PROBE, AtFlags::SYMLINK_NOFOLLOW)
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
        .checked_add(PROBE_DEADLINE)
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
                    .take((MAX_PROBE_OUTPUT_BYTES + 1) as u64)
                    .read_to_end(&mut output)
                    .map_err(|_| TargetPhysicalParentError::IdentityProbeFailed)?;
                if output.is_empty() || output.len() > MAX_PROBE_OUTPUT_BYTES || output.contains(&0)
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

fn parse_blockfd_probe_output(bytes: &[u8]) -> Result<DescriptorProbe, TargetPhysicalParentError> {
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
        || !(KERNEL_SECTOR_BYTES..=65_536).contains(logical_sector_bytes)
        || !logical_sector_bytes.is_power_of_two()
        || *size_bytes % *logical_sector_bytes != 0
    {
        return Err(TargetPhysicalParentError::IdentityProbeFailed);
    }
    Ok(DescriptorProbe {
        disk_sequence: *disk_sequence,
        size_bytes: *size_bytes,
        logical_sector_bytes: *logical_sector_bytes,
    })
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

#[cfg(test)]
mod tests {
    use super::*;

    fn numeric_claims() -> PhysicalParentNumericClaims {
        PhysicalParentNumericClaims {
            parent_major: 8,
            parent_minor: 16,
            disk_sequence: 77,
            media_sector_count: 62_500_000,
            logical_sector_bytes: 512,
            leaf_sector_count: 16_777_216,
        }
    }

    #[test]
    fn descriptor_pair_derives_direct_parent_without_namespace_lookup() {
        let leaf = DescriptorProbe {
            disk_sequence: 77,
            size_bytes: 16_777_216 * 512,
            logical_sector_bytes: 512,
        };
        assert!(validate_leaf_probe(numeric_claims(), leaf, leaf).is_ok());

        let claims = PhysicalParentClaims::new(8, 16, 77, 62_500_000, 512);
        assert_eq!(
            render_physical_parent_prefixed(&canonical_physical_parent_digest(&claims)),
            "sha256:ce1b61e97ecfb97d8b75e1f3cfbe5f83c24b52805def532bf5df3fdf59881de4"
        );
    }

    #[test]
    fn descriptor_pair_rejects_identity_drift_or_unrelated_parent() {
        let leaf = DescriptorProbe {
            disk_sequence: 77,
            size_bytes: 16_777_216 * 512,
            logical_sector_bytes: 512,
        };
        assert_eq!(
            validate_leaf_probe(
                numeric_claims(),
                leaf,
                DescriptorProbe {
                    disk_sequence: 78,
                    ..leaf
                },
            ),
            Err(TargetPhysicalParentError::IdentityChanged)
        );
        assert_eq!(
            validate_leaf_probe(
                PhysicalParentNumericClaims {
                    disk_sequence: 88,
                    ..numeric_claims()
                },
                leaf,
                leaf,
            ),
            Err(TargetPhysicalParentError::IdentityChanged)
        );
        assert_eq!(
            parse_blockfd_probe_output(b"77\n32000000000\n512\nextra\n"),
            Err(TargetPhysicalParentError::IdentityProbeFailed)
        );
    }
}
