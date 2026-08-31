//! Descriptor-bound preparation for the off-default resolver-link repair.
//!
//! The only mutable name is compiled as `etc/resolv.conf`. Public descriptors
//! contain a resolver class and hashes only; link targets and configuration
//! bytes stay behind the broker/Vault boundary.

use crate::{
    rescue_fstab_candidate::RescueFstabVaultReservation,
    rescue_fstab_preflight_resolver::{
        ProductionRescueFstabTargetGuard, ProductionRescueFstabVaultReservation,
        acquire_target_guard_for_resource, reserve_evidence_backup,
    },
};
use kernaid_protocol::rescue_repair_vault::{RepairFileMetadataV1, RepairResourceV1};
use rustix::{
    fd::BorrowedFd,
    fs::{self as rfs, AtFlags, FileType, Mode, OFlags, ResolveFlags},
};
use sha2::{Digest, Sha256};
use std::{fmt, time::Instant};
use zeroize::Zeroizing;

pub const ACTION_ID: &str = "linux.network.restore-resolver-link.v1";
pub const RESOURCE_ID: &str = "rescue:selected-linux-root:etc/resolver-link";
pub const TYPED_CONFIRMATION: &str = "RESTORE RESOLVER LINK";
pub const PREPARED_KIND: &str = "resolver-link-prepared";
pub const ROLLBACK_ID: &str = "linux.network.restore-resolver-link-state.v1";
const PLAN_DOMAIN: &[u8] = b"kernaid:linux.network.restore-resolver-link.v1:plan:v1\0";
const DIFF_DOMAIN: &[u8] = b"kernaid:linux.network.restore-resolver-link.v1:diff:v1\0";
const APPROVAL_DOMAIN: &[u8] = b"kernaid:linux.network.restore-resolver-link.v1:approval:v1\0";
const EVIDENCE_DOMAIN: &[u8] = b"kernaid:linux.network.restore-resolver-link.v1:evidence:v1\0";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ResolverLinkPrepareError {
    InvalidRequest,
    TargetUnavailable,
    TargetChanged,
    ObservationUnavailable,
    AmbiguousResolver,
    UnsafeResolverLink,
    RepairNotRequired,
    VaultUnavailable,
    ApprovalRejected,
    CancellationFailed,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ResolverKind {
    SystemdResolved,
    NetworkManager,
}

impl ResolverKind {
    const fn public_id(self) -> &'static str {
        match self {
            Self::SystemdResolved => "systemd-resolved",
            Self::NetworkManager => "network-manager",
        }
    }

    const fn proposed_state(self) -> ResolverLinkState {
        match self {
            Self::SystemdResolved => ResolverLinkState::ResolvedStubRelative,
            Self::NetworkManager => ResolverLinkState::NetworkManagerRelative,
        }
    }

    const fn owns_state(self, state: ResolverLinkState) -> bool {
        match self {
            Self::SystemdResolved => matches!(
                state,
                ResolverLinkState::ResolvedStubRelative
                    | ResolverLinkState::ResolvedStubAbsolute
                    | ResolverLinkState::ResolvedMainRelative
                    | ResolverLinkState::ResolvedMainAbsolute
            ),
            Self::NetworkManager => matches!(
                state,
                ResolverLinkState::NetworkManagerRelative
                    | ResolverLinkState::NetworkManagerAbsolute
            ),
        }
    }
}

/// Closed exact link states. The raw link string never enters a descriptor,
/// relay response or audit record.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ResolverLinkState {
    Missing,
    ResolvedStubRelative,
    ResolvedStubAbsolute,
    ResolvedMainRelative,
    ResolvedMainAbsolute,
    NetworkManagerRelative,
    NetworkManagerAbsolute,
}

impl ResolverLinkState {
    pub(crate) const fn canonical_bytes(self) -> &'static [u8] {
        match self {
            Self::Missing => b"resolver-link-state:v1:missing",
            Self::ResolvedStubRelative => b"resolver-link-state:v1:resolved-stub-relative",
            Self::ResolvedStubAbsolute => b"resolver-link-state:v1:resolved-stub-absolute",
            Self::ResolvedMainRelative => b"resolver-link-state:v1:resolved-main-relative",
            Self::ResolvedMainAbsolute => b"resolver-link-state:v1:resolved-main-absolute",
            Self::NetworkManagerRelative => b"resolver-link-state:v1:network-manager-relative",
            Self::NetworkManagerAbsolute => b"resolver-link-state:v1:network-manager-absolute",
        }
    }

    pub(crate) fn from_canonical_bytes(bytes: &[u8]) -> Option<Self> {
        [
            Self::Missing,
            Self::ResolvedStubRelative,
            Self::ResolvedStubAbsolute,
            Self::ResolvedMainRelative,
            Self::ResolvedMainAbsolute,
            Self::NetworkManagerRelative,
            Self::NetworkManagerAbsolute,
        ]
        .into_iter()
        .find(|state| state.canonical_bytes() == bytes)
    }

    pub(crate) const fn link_target(self) -> Option<&'static str> {
        match self {
            Self::Missing => None,
            Self::ResolvedStubRelative => Some("../run/systemd/resolve/stub-resolv.conf"),
            Self::ResolvedStubAbsolute => Some("/run/systemd/resolve/stub-resolv.conf"),
            Self::ResolvedMainRelative => Some("../run/systemd/resolve/resolv.conf"),
            Self::ResolvedMainAbsolute => Some("/run/systemd/resolve/resolv.conf"),
            Self::NetworkManagerRelative => Some("../run/NetworkManager/resolv.conf"),
            Self::NetworkManagerAbsolute => Some("/run/NetworkManager/resolv.conf"),
        }
    }

    pub(crate) fn from_link_target(target: &[u8]) -> Option<Self> {
        [
            Self::ResolvedStubRelative,
            Self::ResolvedStubAbsolute,
            Self::ResolvedMainRelative,
            Self::ResolvedMainAbsolute,
            Self::NetworkManagerRelative,
            Self::NetworkManagerAbsolute,
        ]
        .into_iter()
        .find(|state| {
            state
                .link_target()
                .is_some_and(|value| value.as_bytes() == target)
        })
    }
}

/// Path-free descriptor echoed by repaird and Desk.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ResolverLinkPreparedDescriptor {
    pub request_id: String,
    pub session_id: String,
    pub plan_id: String,
    pub plan_sha256: String,
    pub scan_fingerprint: String,
    pub target_id: String,
    pub target_fingerprint: String,
    pub before_sha256: String,
    pub after_sha256: String,
    pub diff_sha256: String,
    pub evidence_sha256: String,
    pub resolver: String,
}

#[must_use]
pub struct PreparedResolverLinkRepair {
    descriptor: ResolverLinkPreparedDescriptor,
    backup: Zeroizing<Vec<u8>>,
    proposed: Zeroizing<Vec<u8>>,
    metadata: RepairFileMetadataV1,
    target: ProductionRescueFstabTargetGuard,
    reservation: ProductionRescueFstabVaultReservation,
}

#[must_use]
pub struct ApprovedResolverLinkRepair {
    descriptor: ResolverLinkPreparedDescriptor,
    backup: Zeroizing<Vec<u8>>,
    proposed: Zeroizing<Vec<u8>>,
    metadata: RepairFileMetadataV1,
    target: ProductionRescueFstabTargetGuard,
    reservation: ProductionRescueFstabVaultReservation,
    approval_id: String,
    approval_sha256: String,
}

pub(crate) struct ApprovedResolverLinkRepairParts {
    pub descriptor: ResolverLinkPreparedDescriptor,
    pub backup: Zeroizing<Vec<u8>>,
    pub proposed: Zeroizing<Vec<u8>>,
    pub metadata: RepairFileMetadataV1,
    pub target: ProductionRescueFstabTargetGuard,
    pub reservation: ProductionRescueFstabVaultReservation,
    pub approval_id: String,
    pub approval_sha256: String,
}

impl PreparedResolverLinkRepair {
    pub fn descriptor(&self) -> &ResolverLinkPreparedDescriptor {
        &self.descriptor
    }

    pub fn backup_locator(&self) -> &str {
        self.reservation.status().locator()
    }

    #[allow(clippy::too_many_arguments)]
    pub fn approve(
        self,
        session_id: &str,
        plan_id: &str,
        plan_sha256: &str,
        approval_id: &str,
        approval_sequence: u64,
        typed_confirmation: &str,
        deadline: Instant,
    ) -> Result<ApprovedResolverLinkRepair, ResolverLinkPrepareError> {
        if session_id != self.descriptor.session_id
            || plan_id != self.descriptor.plan_id
            || plan_sha256 != self.descriptor.plan_sha256
            || approval_sequence != 1
            || typed_confirmation != TYPED_CONFIRMATION
            || !valid_id(approval_id, "A-")
        {
            self.reservation
                .cancel(deadline)
                .map_err(|_| ResolverLinkPrepareError::CancellationFailed)?;
            return Err(ResolverLinkPrepareError::ApprovalRejected);
        }
        let approval_sha256 = domain_hash(
            APPROVAL_DOMAIN,
            &[
                approval_id.as_bytes(),
                &approval_sequence.to_be_bytes(),
                typed_confirmation.as_bytes(),
                plan_sha256.as_bytes(),
            ],
        );
        Ok(ApprovedResolverLinkRepair {
            descriptor: self.descriptor,
            backup: self.backup,
            proposed: self.proposed,
            metadata: self.metadata,
            target: self.target,
            reservation: self.reservation,
            approval_id: approval_id.to_owned(),
            approval_sha256,
        })
    }

    pub fn cancel(self, deadline: Instant) -> Result<(), ResolverLinkPrepareError> {
        self.reservation
            .cancel(deadline)
            .map_err(|_| ResolverLinkPrepareError::CancellationFailed)
    }
}

impl ApprovedResolverLinkRepair {
    pub fn cancel(self, deadline: Instant) -> Result<(), ResolverLinkPrepareError> {
        self.reservation
            .cancel(deadline)
            .map_err(|_| ResolverLinkPrepareError::CancellationFailed)
    }

    pub(crate) fn into_parts(self) -> ApprovedResolverLinkRepairParts {
        ApprovedResolverLinkRepairParts {
            descriptor: self.descriptor,
            backup: self.backup,
            proposed: self.proposed,
            metadata: self.metadata,
            target: self.target,
            reservation: self.reservation,
            approval_id: self.approval_id,
            approval_sha256: self.approval_sha256,
        }
    }
}

impl fmt::Debug for PreparedResolverLinkRepair {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PreparedResolverLinkRepair")
            .field("descriptor", &self.descriptor)
            .field("backup", &"[redacted]")
            .field("proposed", &"[redacted]")
            .finish_non_exhaustive()
    }
}

#[allow(clippy::too_many_arguments)]
pub fn prepare_resolver_link_repair(
    request_id: &str,
    session_id: &str,
    plan_id: &str,
    scan_fingerprint: &str,
    target_id: &str,
    target_fingerprint: &str,
    deadline: Instant,
) -> Result<PreparedResolverLinkRepair, ResolverLinkPrepareError> {
    if !valid_id(session_id, "S-") || !valid_id(plan_id, "P-") {
        return Err(ResolverLinkPrepareError::InvalidRequest);
    }
    let target = acquire_target_guard_for_resource(
        request_id,
        scan_fingerprint,
        target_fingerprint,
        target_id,
        RepairResourceV1::ResolverLink,
        deadline,
    )
    .map_err(|_| ResolverLinkPrepareError::TargetUnavailable)?;
    target
        .inner()
        .revalidate()
        .map_err(|_| ResolverLinkPrepareError::TargetChanged)?;
    let (before, resolver, evidence_sha256) =
        observe(target.inner().target_detached_mount_descriptor())?;
    let proposed = resolver.proposed_state();
    if resolver.owns_state(before) {
        return Err(ResolverLinkPrepareError::RepairNotRequired);
    }
    target
        .inner()
        .revalidate()
        .map_err(|_| ResolverLinkPrepareError::TargetChanged)?;

    let backup = Zeroizing::new(before.canonical_bytes().to_vec());
    let proposed_bytes = Zeroizing::new(proposed.canonical_bytes().to_vec());
    let before_sha256 = prefixed_hash(&backup);
    let after_sha256 = prefixed_hash(&proposed_bytes);
    let diff_sha256 = domain_hash(
        DIFF_DOMAIN,
        &[before_sha256.as_bytes(), after_sha256.as_bytes()],
    );
    let plan_sha256 = domain_hash(
        PLAN_DOMAIN,
        &[
            session_id.as_bytes(),
            plan_id.as_bytes(),
            scan_fingerprint.as_bytes(),
            target_id.as_bytes(),
            target_fingerprint.as_bytes(),
            target
                .inner()
                .target_claims()
                .recovery_fingerprint()
                .as_bytes(),
            before_sha256.as_bytes(),
            after_sha256.as_bytes(),
            diff_sha256.as_bytes(),
            evidence_sha256.as_bytes(),
            resolver.public_id().as_bytes(),
        ],
    );
    let metadata = RepairFileMetadataV1::new(0o600, 0, 0)
        .map_err(|_| ResolverLinkPrepareError::InvalidRequest)?;
    let reservation = reserve_evidence_backup(
        session_id,
        target_id,
        scan_fingerprint,
        target_fingerprint,
        &target,
        &backup,
        &metadata,
        deadline,
    )
    .map_err(|_| ResolverLinkPrepareError::VaultUnavailable)?;
    Ok(PreparedResolverLinkRepair {
        descriptor: ResolverLinkPreparedDescriptor {
            request_id: request_id.to_owned(),
            session_id: session_id.to_owned(),
            plan_id: plan_id.to_owned(),
            plan_sha256,
            scan_fingerprint: scan_fingerprint.to_owned(),
            target_id: target_id.to_owned(),
            target_fingerprint: target_fingerprint.to_owned(),
            before_sha256,
            after_sha256,
            diff_sha256,
            evidence_sha256,
            resolver: resolver.public_id().to_owned(),
        },
        backup,
        proposed: proposed_bytes,
        metadata,
        target,
        reservation,
    })
}

/// Re-observes the closed preflight evidence on the freshly granted write
/// mount immediately before mutation. No observed path or configuration data
/// crosses back to the caller.
pub(crate) fn revalidate_resolver_link_execution_evidence(
    mount: BorrowedFd<'_>,
    expected_before: ResolverLinkState,
    expected_after: ResolverLinkState,
) -> Result<(), ResolverLinkPrepareError> {
    let (before, resolver, _) = observe(mount)?;
    if before != expected_before
        || resolver.proposed_state() != expected_after
        || resolver.owns_state(before)
    {
        return Err(ResolverLinkPrepareError::TargetChanged);
    }
    Ok(())
}

fn observe(
    mount: BorrowedFd<'_>,
) -> Result<(ResolverLinkState, ResolverKind, String), ResolverLinkPrepareError> {
    let systemd = resolver_installed_and_enabled(
        mount,
        "usr/lib/systemd/system/systemd-resolved.service",
        "etc/systemd/system/multi-user.target.wants",
        "systemd-resolved.service",
        &[
            "/usr/lib/systemd/system/systemd-resolved.service",
            "/lib/systemd/system/systemd-resolved.service",
        ],
    )?;
    let network_manager = resolver_installed_and_enabled(
        mount,
        "usr/lib/systemd/system/NetworkManager.service",
        "etc/systemd/system/multi-user.target.wants",
        "NetworkManager.service",
        &[
            "/usr/lib/systemd/system/NetworkManager.service",
            "/lib/systemd/system/NetworkManager.service",
        ],
    )?;
    let resolver = select_resolver(systemd, network_manager)?;
    let before = observe_resolver_link(mount)?;
    let evidence_sha256 = domain_hash(
        EVIDENCE_DOMAIN,
        &[
            resolver.public_id().as_bytes(),
            before.canonical_bytes(),
            b"installed-and-enabled",
        ],
    );
    Ok((before, resolver, evidence_sha256))
}

fn select_resolver(
    systemd_resolved: bool,
    network_manager: bool,
) -> Result<ResolverKind, ResolverLinkPrepareError> {
    Ok(match (systemd_resolved, network_manager) {
        (true, false) => ResolverKind::SystemdResolved,
        (false, true) => ResolverKind::NetworkManager,
        _ => return Err(ResolverLinkPrepareError::AmbiguousResolver),
    })
}

fn resolver_installed_and_enabled(
    mount: BorrowedFd<'_>,
    unit: &str,
    wants_directory: &str,
    wants_leaf: &str,
    accepted_targets: &[&str],
) -> Result<bool, ResolverLinkPrepareError> {
    if !fixed_regular_file(mount, unit)? {
        return Ok(false);
    }
    let directory = match open_safe_directory(mount, wants_directory) {
        Ok(directory) => directory,
        Err(ResolverLinkPrepareError::ObservationUnavailable) => return Ok(false),
        Err(error) => return Err(error),
    };
    let before = match rfs::statat(&directory, wants_leaf, AtFlags::SYMLINK_NOFOLLOW) {
        Ok(stat) => stat,
        Err(error) if error == rustix::io::Errno::NOENT => return Ok(false),
        Err(_) => return Err(ResolverLinkPrepareError::ObservationUnavailable),
    };
    if !FileType::from_raw_mode(before.st_mode).is_symlink()
        || before.st_uid != 0
        || before.st_gid != 0
        || before.st_nlink != 1
    {
        return Err(ResolverLinkPrepareError::ObservationUnavailable);
    }
    let target = match rfs::readlinkat(&directory, wants_leaf, Vec::new()) {
        Ok(target) => target,
        Err(_) => return Err(ResolverLinkPrepareError::ObservationUnavailable),
    };
    let after = rfs::statat(&directory, wants_leaf, AtFlags::SYMLINK_NOFOLLOW)
        .map_err(|_| ResolverLinkPrepareError::ObservationUnavailable)?;
    if !same_observed_stat(&before, &after) {
        return Err(ResolverLinkPrepareError::TargetChanged);
    }
    Ok(accepted_targets
        .iter()
        .any(|expected| target.as_bytes() == expected.as_bytes()))
}

fn fixed_regular_file(mount: BorrowedFd<'_>, path: &str) -> Result<bool, ResolverLinkPrepareError> {
    let descriptor = match rfs::openat2(
        mount,
        path,
        OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NOFOLLOW | OFlags::NONBLOCK,
        Mode::empty(),
        ResolveFlags::BENEATH | ResolveFlags::NO_MAGICLINKS | ResolveFlags::NO_SYMLINKS,
    ) {
        Ok(descriptor) => descriptor,
        Err(error) if error == rustix::io::Errno::NOENT => return Ok(false),
        Err(_) => return Err(ResolverLinkPrepareError::ObservationUnavailable),
    };
    let stat =
        rfs::fstat(&descriptor).map_err(|_| ResolverLinkPrepareError::ObservationUnavailable)?;
    let named = rfs::statat(mount, path, AtFlags::SYMLINK_NOFOLLOW)
        .map_err(|_| ResolverLinkPrepareError::ObservationUnavailable)?;
    Ok(same_observed_stat(&stat, &named)
        && FileType::from_raw_mode(stat.st_mode).is_file()
        && stat.st_uid == 0
        && stat.st_gid == 0
        && stat.st_nlink == 1
        && stat.st_mode & 0o022 == 0)
}

fn same_observed_stat(first: &rustix::fs::Stat, second: &rustix::fs::Stat) -> bool {
    first.st_dev == second.st_dev
        && first.st_ino == second.st_ino
        && first.st_mode == second.st_mode
        && first.st_nlink == second.st_nlink
        && first.st_uid == second.st_uid
        && first.st_gid == second.st_gid
        && first.st_size == second.st_size
        && first.st_ctime == second.st_ctime
        && first.st_ctime_nsec == second.st_ctime_nsec
}

fn open_safe_directory(
    mount: BorrowedFd<'_>,
    path: &str,
) -> Result<rustix::fd::OwnedFd, ResolverLinkPrepareError> {
    let directory = rfs::openat2(
        mount,
        path,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC | OFlags::NOFOLLOW,
        Mode::empty(),
        ResolveFlags::BENEATH | ResolveFlags::NO_MAGICLINKS | ResolveFlags::NO_SYMLINKS,
    )
    .map_err(|_| ResolverLinkPrepareError::ObservationUnavailable)?;
    let stat =
        rfs::fstat(&directory).map_err(|_| ResolverLinkPrepareError::ObservationUnavailable)?;
    if !FileType::from_raw_mode(stat.st_mode).is_dir()
        || stat.st_uid != 0
        || stat.st_gid != 0
        || stat.st_mode & 0o022 != 0
    {
        return Err(ResolverLinkPrepareError::ObservationUnavailable);
    }
    Ok(directory)
}

fn observe_resolver_link(
    mount: BorrowedFd<'_>,
) -> Result<ResolverLinkState, ResolverLinkPrepareError> {
    let etc = open_safe_directory(mount, "etc")?;
    let before = match rfs::statat(&etc, "resolv.conf", AtFlags::SYMLINK_NOFOLLOW) {
        Ok(stat) => stat,
        Err(error) if error == rustix::io::Errno::NOENT => return Ok(ResolverLinkState::Missing),
        Err(_) => return Err(ResolverLinkPrepareError::ObservationUnavailable),
    };
    if !FileType::from_raw_mode(before.st_mode).is_symlink()
        || before.st_uid != 0
        || before.st_gid != 0
        || before.st_nlink != 1
    {
        return Err(ResolverLinkPrepareError::UnsafeResolverLink);
    }
    let target = rfs::readlinkat(&etc, "resolv.conf", Vec::new())
        .map_err(|_| ResolverLinkPrepareError::ObservationUnavailable)?;
    match rfs::openat2(
        mount,
        "etc/resolv.conf",
        OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NONBLOCK,
        Mode::empty(),
        ResolveFlags::IN_ROOT | ResolveFlags::NO_MAGICLINKS | ResolveFlags::NO_XDEV,
    ) {
        Ok(_) => return Err(ResolverLinkPrepareError::RepairNotRequired),
        Err(error) if error == rustix::io::Errno::NOENT => {}
        Err(_) => return Err(ResolverLinkPrepareError::UnsafeResolverLink),
    }
    let after = rfs::statat(&etc, "resolv.conf", AtFlags::SYMLINK_NOFOLLOW)
        .map_err(|_| ResolverLinkPrepareError::TargetChanged)?;
    if !same_observed_stat(&before, &after) {
        return Err(ResolverLinkPrepareError::TargetChanged);
    }
    ResolverLinkState::from_link_target(target.as_bytes())
        .ok_or(ResolverLinkPrepareError::UnsafeResolverLink)
}

fn prefixed_hash(bytes: &[u8]) -> String {
    format!("sha256:{:x}", Sha256::digest(bytes))
}

fn domain_hash(domain: &[u8], fields: &[&[u8]]) -> String {
    let mut digest = Sha256::new();
    digest.update(domain);
    for field in fields {
        digest.update((field.len() as u64).to_be_bytes());
        digest.update(field);
    }
    format!("sha256:{:x}", digest.finalize())
}

fn valid_id(value: &str, prefix: &str) -> bool {
    (3..=128).contains(&value.len())
        && value.strip_prefix(prefix).is_some_and(|tail| {
            !tail.is_empty()
                && tail
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn link_states_are_closed_exact_and_path_free_when_encoded() {
        for state in [
            ResolverLinkState::Missing,
            ResolverLinkState::ResolvedStubRelative,
            ResolverLinkState::ResolvedMainAbsolute,
            ResolverLinkState::NetworkManagerRelative,
        ] {
            assert_eq!(
                ResolverLinkState::from_canonical_bytes(state.canonical_bytes()),
                Some(state)
            );
            assert!(!state.canonical_bytes().contains(&b'/'));
        }
        assert!(ResolverLinkState::from_canonical_bytes(b"/tmp/caller-path").is_none());
        assert!(ResolverLinkState::from_link_target(b"../../unknown").is_none());
    }

    #[test]
    fn resolver_ownership_is_unambiguous_and_wrong_target_requires_repair() {
        assert!(ResolverKind::SystemdResolved.owns_state(ResolverLinkState::ResolvedMainAbsolute));
        assert!(
            !ResolverKind::SystemdResolved.owns_state(ResolverLinkState::NetworkManagerRelative)
        );
        assert_eq!(
            ResolverKind::NetworkManager.proposed_state(),
            ResolverLinkState::NetworkManagerRelative
        );
    }

    #[test]
    fn resolver_selection_rejects_both_and_neither() {
        assert_eq!(
            select_resolver(true, false),
            Ok(ResolverKind::SystemdResolved)
        );
        assert_eq!(
            select_resolver(false, true),
            Ok(ResolverKind::NetworkManager)
        );
        assert_eq!(
            select_resolver(false, false),
            Err(ResolverLinkPrepareError::AmbiguousResolver)
        );
        assert_eq!(
            select_resolver(true, true),
            Err(ResolverLinkPrepareError::AmbiguousResolver)
        );
    }

    #[test]
    fn approval_hash_is_single_use_and_domain_separated() {
        let one = domain_hash(
            APPROVAL_DOMAIN,
            &[
                b"A-one",
                &1_u64.to_be_bytes(),
                TYPED_CONFIRMATION.as_bytes(),
                b"plan",
            ],
        );
        let two = domain_hash(
            APPROVAL_DOMAIN,
            &[
                b"A-two",
                &1_u64.to_be_bytes(),
                TYPED_CONFIRMATION.as_bytes(),
                b"plan",
            ],
        );
        assert_ne!(one, two);
        assert_ne!(one, prefixed_hash(TYPED_CONFIRMATION.as_bytes()));
    }
}
