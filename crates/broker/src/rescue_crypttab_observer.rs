//! Descriptor-rooted observation for the Rescue crypttab candidate.

use crate::{
    rescue_crypttab_candidate::BrokerOwnedCrypttabObservation,
    target_physical_parent::RescueTargetPhysicalParentGuard,
};
use kernaid_protocol::rescue_repair_vault::RepairFileMetadataV1;
use rustix::{
    fd::{AsFd, BorrowedFd},
    fs::{self as rfs, AtFlags, FileType, Mode, OFlags, ResolveFlags},
};
use std::{fmt, fs::File, io::Read};
use zeroize::Zeroizing;

const CRYPTTAB_RESOURCE: &str = "etc/crypttab";
const FSTAB_RESOURCE: &str = "etc/fstab";
const MAX_DOCUMENT_BYTES: usize = 1024 * 1024;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RescueCrypttabObservationError {
    TargetChanged,
    CrypttabUnavailable,
    FstabUnavailable,
    DocumentTooLarge,
    UnsafeDocument,
    UuidInventoryUnavailable,
}

impl fmt::Display for RescueCrypttabObservationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("closed Rescue crypttab observation failed")
    }
}

impl std::error::Error for RescueCrypttabObservationError {}

pub fn observe_rescue_crypttab(
    target: &RescueTargetPhysicalParentGuard,
) -> Result<BrokerOwnedCrypttabObservation, RescueCrypttabObservationError> {
    target
        .revalidate()
        .map_err(|_| RescueCrypttabObservationError::TargetChanged)?;
    let mount = target.target_detached_mount_descriptor();
    let (crypttab, metadata) =
        read_exact_regular(mount, CRYPTTAB_RESOURCE, false, true).map_err(|error| match error {
            RescueCrypttabObservationError::FstabUnavailable => {
                RescueCrypttabObservationError::CrypttabUnavailable
            }
            other => other,
        })?;
    let (fstab, _) = read_exact_regular(mount, FSTAB_RESOURCE, true, false)?;
    let observed_uuids = target.target_observed_uuids().clone();
    if observed_uuids.is_empty() {
        return Err(RescueCrypttabObservationError::UuidInventoryUnavailable);
    }
    target
        .revalidate()
        .map_err(|_| RescueCrypttabObservationError::TargetChanged)?;
    let claims = target.target_claims();
    Ok(
        BrokerOwnedCrypttabObservation::from_retained_target_capability(
            claims.scan_fingerprint().to_owned(),
            claims.target_id().to_owned(),
            claims.target_fingerprint().to_owned(),
            true,
            crypttab,
            fstab,
            observed_uuids,
            metadata,
        ),
    )
}

fn read_exact_regular(
    mount: BorrowedFd<'_>,
    resource: &str,
    empty_allowed: bool,
    private_mode_allowed: bool,
) -> Result<(Zeroizing<Vec<u8>>, RepairFileMetadataV1), RescueCrypttabObservationError> {
    let descriptor = rfs::openat2(
        mount,
        resource,
        OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NOFOLLOW | OFlags::NONBLOCK,
        Mode::empty(),
        ResolveFlags::BENEATH | ResolveFlags::NO_MAGICLINKS | ResolveFlags::NO_SYMLINKS,
    )
    .map_err(|_| RescueCrypttabObservationError::FstabUnavailable)?;
    let before = file_snapshot(&descriptor)?;
    let permissions = before.mode & 0o7777;
    if before.uid != 0
        || before.gid != 0
        || (permissions != 0o644 && !(private_mode_allowed && permissions == 0o600))
    {
        return Err(RescueCrypttabObservationError::UnsafeDocument);
    }
    let size = usize::try_from(before.size)
        .ok()
        .filter(|size| *size <= MAX_DOCUMENT_BYTES && (empty_allowed || *size > 0))
        .ok_or(RescueCrypttabObservationError::DocumentTooLarge)?;
    let mut probe = [0_u8; 0];
    if rfs::flistxattr(&descriptor, &mut probe)
        .map_err(|_| RescueCrypttabObservationError::UnsafeDocument)?
        != 0
    {
        return Err(RescueCrypttabObservationError::UnsafeDocument);
    }
    let mut file = File::from(descriptor);
    let mut bytes = Zeroizing::new(Vec::with_capacity(size));
    Read::by_ref(&mut file)
        .take((MAX_DOCUMENT_BYTES + 1) as u64)
        .read_to_end(&mut bytes)
        .map_err(|_| RescueCrypttabObservationError::UnsafeDocument)?;
    if bytes.len() != size || bytes.contains(&0) || std::str::from_utf8(&bytes).is_err() {
        return Err(RescueCrypttabObservationError::UnsafeDocument);
    }
    let after = file_snapshot(&file)?;
    let named = rfs::statat(mount, resource, AtFlags::SYMLINK_NOFOLLOW)
        .map(FileSnapshot::from_stat)
        .map_err(|_| RescueCrypttabObservationError::UnsafeDocument)?;
    if before != after || after != named {
        return Err(RescueCrypttabObservationError::TargetChanged);
    }
    let metadata = RepairFileMetadataV1::new(permissions, before.uid, before.gid)
        .map_err(|_| RescueCrypttabObservationError::UnsafeDocument)?;
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

fn file_snapshot(descriptor: &impl AsFd) -> Result<FileSnapshot, RescueCrypttabObservationError> {
    let stat =
        rfs::fstat(descriptor).map_err(|_| RescueCrypttabObservationError::UnsafeDocument)?;
    let status =
        rfs::fcntl_getfl(descriptor).map_err(|_| RescueCrypttabObservationError::UnsafeDocument)?;
    let descriptor_flags = rustix::io::fcntl_getfd(descriptor)
        .map_err(|_| RescueCrypttabObservationError::UnsafeDocument)?;
    if !FileType::from_raw_mode(stat.st_mode).is_file()
        || stat.st_nlink != 1
        || stat.st_size < 0
        || status & OFlags::ACCMODE != OFlags::RDONLY
        || !status.contains(OFlags::NONBLOCK)
        || descriptor_flags != rustix::io::FdFlags::CLOEXEC
    {
        return Err(RescueCrypttabObservationError::UnsafeDocument);
    }
    Ok(FileSnapshot::from_stat(stat))
}
