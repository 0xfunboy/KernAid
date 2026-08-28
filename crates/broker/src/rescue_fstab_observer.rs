//! Read-only observation for the Rescue `fstab` candidate.
//!
//! The root-owned handoff has already created and authenticated the detached
//! ext4 mount and sealed UUID inventory. Observation only consumes those held
//! capabilities; it neither mounts nor searches a device namespace.

use crate::target_physical_parent::RescueTargetPhysicalParentGuard;
use kernaid_linux_pack::rescue_fstab_transaction_candidate::{
    CandidateEvidenceBinding, FSTAB_EVIDENCE_ID, LSBLK_EVIDENCE_ID,
};
use kernaid_protocol::rescue_repair_vault::RepairFileMetadataV1;
use rustix::{
    fd::{AsFd, BorrowedFd},
    fs::{self as rfs, AtFlags, FileType, Mode, OFlags, ResolveFlags},
};
use sha2::{Digest, Sha256};
use std::{collections::BTreeSet, fmt, fs::File, io::Read};

const FSTAB_RESOURCE: &str = "etc/fstab";
const MAX_FSTAB_BYTES: usize = 1024 * 1024;
const OBSERVED_UUID_SET_HASH_DOMAIN: &[u8] =
    b"kernaid:linux.fstab.disable-missing-uuid.v1:observed-uuid-set:v1\0";

/// Closed observation failures. No error contains a device identifier,
/// pathname, mount option, target byte, or OS error string.
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

/// Observes exactly `etc/fstab` through the handed-off detached mount and uses
/// only the handed-off sealed UUID inventory for the candidate evidence.
pub fn observe_rescue_fstab(
    target: &RescueTargetPhysicalParentGuard,
) -> Result<ObservedRescueFstab, RescueFstabObservationError> {
    target
        .revalidate()
        .map_err(|_| RescueFstabObservationError::TargetChanged)?;
    let (fstab_bytes, metadata) = read_exact_fstab(target.target_detached_mount_descriptor())?;
    let observed_uuids = target
        .target_observed_uuids()
        .iter()
        .cloned()
        .collect::<BTreeSet<_>>();
    if observed_uuids.is_empty() {
        return Err(RescueFstabObservationError::InvalidUuidInventory);
    }
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

fn read_exact_fstab(
    mount: BorrowedFd<'_>,
) -> Result<(Vec<u8>, RepairFileMetadataV1), RescueFstabObservationError> {
    let descriptor = rfs::openat2(
        mount,
        FSTAB_RESOURCE,
        OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NOFOLLOW | OFlags::NONBLOCK,
        Mode::empty(),
        ResolveFlags::BENEATH | ResolveFlags::NO_MAGICLINKS | ResolveFlags::NO_SYMLINKS,
    )
    .map_err(|_| RescueFstabObservationError::FstabUnavailable)?;
    let before = file_snapshot(&descriptor)?;
    if before.mode & 0o7777 != 0o644 || before.uid != 0 || before.gid != 0 {
        return Err(RescueFstabObservationError::UnsafeFstab);
    }
    let size = usize::try_from(before.size)
        .ok()
        .filter(|size| (1..=MAX_FSTAB_BYTES).contains(size))
        .ok_or(RescueFstabObservationError::FstabTooLarge)?;
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

    let metadata = RepairFileMetadataV1::new(0o644, 0, 0)
        .map_err(|_| RescueFstabObservationError::UnsafeFstab)?;
    Ok((bytes, metadata))
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
        || descriptor_flags != rustix::io::FdFlags::CLOEXEC
    {
        return Err(RescueFstabObservationError::UnsafeFstab);
    }
    Ok(FileSnapshot::from_stat(stat))
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
    fn handed_inventory_hash_is_canonical() {
        let observed = BTreeSet::from(["aaaa-bbbb".to_owned(), "dead-beef".to_owned()]);
        assert_eq!(
            observed_uuid_set_sha256(&observed),
            "sha256:90138e9f8e6b75b9cd2ec66951ee541f8bde7d89060061b455141ccbd684aac7"
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
