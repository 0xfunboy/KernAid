//! Root-only, socket-activated broker for one Codex-home bind mount.
//!
//! The protocol has one request, one acknowledgement, no caller-supplied path,
//! and exactly three descriptors: the already validated vault home plus the
//! requesting bridge's mount namespace and root.

use super::{
    RescueVaultDaemonError, enforce_process_privacy, internal_wire,
    runtime::{
        drop_codex_mounter_chroot_capability, normalize_codex_mounter_capabilities,
        verify_codex_mounter_mount_capability,
    },
    server::validate_codex_home_handoff,
};
use kernaid_linux_nsfs::{NamespaceType, namespace_type, owner_user_namespace};
use kernaid_protocol::rescue_vault::{
    validate_mount_namespace_descriptor, validate_mount_root_descriptor,
};
use nix::{
    sched::{CloneFlags, setns},
    sys::socket::{getsockopt, sockopt},
};
use rustix::{
    event::{PollFd, PollFlags, Timespec, poll},
    fd::{AsFd, BorrowedFd, OwnedFd},
    fs::{self as rfs, AtFlags, FileType, Mode, OFlags, ResolveFlags, StatxFlags},
    mount::{MountFlags, UnmountFlags},
    net::{AddressFamily, SocketAddrUnix, SocketFlags, SocketType, connect, socket_with},
};
use std::{
    fs::File,
    io::Read,
    os::fd::AsRawFd,
    time::{Duration, Instant},
};

pub(super) const CODEX_MOUNTER_SOCKET_PATH: &str = "/run/kernaid-rescue-codex-mounter.sock";
pub(super) const CODEX_HOME_TARGET: &str = "/run/kernaid-codex-home";
const REQUEST: &[u8] = b"KERNAID_CODEX_MOUNT_V1";
const ACK: &[u8] = b"KERNAID_CODEX_MOUNT_OK_V1";
const VAULTD_CGROUP: &[u8] = b"0::/system.slice/kernaid-rescue-vaultd.service/supervisor\n";
const PROC_SUPER_MAGIC: u64 = 0x0000_9fa0;
const NSFS_MAGIC: u64 = 0x6e73_6673;
const TMPFS_MAGIC: u64 = 0x0102_1994;
const EXT4_SUPER_MAGIC: u64 = 0xef53;
const MAX_PROC_CGROUP_BYTES: usize = 4096;
const MAX_MOUNTINFO_BYTES: usize = 256 * 1024;
const HELPER_TIMEOUT: Duration = Duration::from_secs(8);

pub(super) fn mount_codex_home(
    home: BorrowedFd<'_>,
    mount_namespace: BorrowedFd<'_>,
    mount_root: BorrowedFd<'_>,
    deadline: Instant,
) -> Result<(), RescueVaultDaemonError> {
    let deadline = deadline.min(
        Instant::now()
            .checked_add(HELPER_TIMEOUT)
            .ok_or(RescueVaultDaemonError::RuntimeUnavailable)?,
    );
    let socket = socket_with(
        AddressFamily::UNIX,
        SocketType::SEQPACKET,
        SocketFlags::CLOEXEC | SocketFlags::NONBLOCK,
        None,
    )
    .map_err(|_| RescueVaultDaemonError::RuntimeUnavailable)?;
    let address = SocketAddrUnix::new(CODEX_MOUNTER_SOCKET_PATH)
        .map_err(|_| RescueVaultDaemonError::RuntimeUnavailable)?;
    match connect(&socket, &address) {
        Ok(()) => {}
        Err(error) if error == rustix::io::Errno::INPROGRESS => {
            wait_ready(socket.as_fd(), PollFlags::OUT, deadline)?;
            rustix::net::sockopt::socket_error(&socket)
                .map_err(|_| RescueVaultDaemonError::RuntimeUnavailable)?
                .map_err(|_| RescueVaultDaemonError::RuntimeUnavailable)?;
        }
        Err(_) => return Err(RescueVaultDaemonError::RuntimeUnavailable),
    }
    validate_root_server(socket.as_fd())?;
    internal_wire::send_record(
        socket.as_fd(),
        REQUEST,
        &[home, mount_namespace, mount_root],
        deadline,
    )
    .map_err(|_| RescueVaultDaemonError::ProtocolFailure)?;
    let (bytes, descriptors) = internal_wire::receive_record(socket.as_fd(), deadline)
        .map_err(|_| RescueVaultDaemonError::ProtocolFailure)?;
    if bytes != ACK || !descriptors.is_empty() {
        return Err(RescueVaultDaemonError::ProtocolFailure);
    }
    Ok(())
}

/// Serve exactly one systemd-accepted mount request.
pub fn run_rescue_codex_mounter() -> Result<(), RescueVaultDaemonError> {
    if !rustix::process::geteuid().is_root() || !rustix::process::getegid().is_root() {
        return Err(RescueVaultDaemonError::PrivilegeRequired);
    }
    enforce_process_privacy().map_err(|()| RescueVaultDaemonError::RuntimeUnavailable)?;
    normalize_codex_mounter_capabilities()?;

    let stdin = std::io::stdin();
    let socket = rustix::io::fcntl_dupfd_cloexec(stdin.as_fd(), 3)
        .map_err(|_| RescueVaultDaemonError::InvalidListener)?;
    validate_vaultd_peer(socket.as_fd())?;
    let peer_pidfd = getsockopt(&socket, sockopt::PeerPidfd)
        .map_err(|_| RescueVaultDaemonError::InvalidListener)?;
    validate_live_pidfd(peer_pidfd.as_fd())?;

    let deadline = Instant::now()
        .checked_add(HELPER_TIMEOUT)
        .ok_or(RescueVaultDaemonError::RuntimeUnavailable)?;
    let (bytes, mut descriptors) = internal_wire::receive_record(socket.as_fd(), deadline)
        .map_err(|_| RescueVaultDaemonError::ProtocolFailure)?;
    if bytes != REQUEST || descriptors.len() != 3 {
        return Err(RescueVaultDaemonError::ProtocolFailure);
    }
    let mount_root = descriptors
        .pop()
        .ok_or(RescueVaultDaemonError::ProtocolFailure)?;
    let mount_namespace = descriptors
        .pop()
        .ok_or(RescueVaultDaemonError::ProtocolFailure)?;
    let home = descriptors
        .pop()
        .ok_or(RescueVaultDaemonError::ProtocolFailure)?;
    validate_codex_home_handoff(&home)?;
    validate_mount_namespace_descriptor(mount_namespace.as_fd())
        .map_err(|_| RescueVaultDaemonError::ProtocolFailure)?;
    validate_mount_root(&mount_root)?;
    validate_namespace_owner(mount_namespace.as_fd())?;
    validate_vaultd_peer(socket.as_fd())?;
    validate_live_pidfd(peer_pidfd.as_fd())?;

    setns(&mount_namespace, CloneFlags::CLONE_NEWNS)
        .map_err(|_| RescueVaultDaemonError::RuntimeUnavailable)?;
    rustix::process::fchdir(&mount_root).map_err(|_| RescueVaultDaemonError::RuntimeUnavailable)?;
    rustix::process::chroot(".").map_err(|_| RescueVaultDaemonError::RuntimeUnavailable)?;
    rustix::process::chdir("/").map_err(|_| RescueVaultDaemonError::RuntimeUnavailable)?;
    validate_chroot_identity(&mount_root)?;
    drop_codex_mounter_chroot_capability()?;
    verify_codex_mounter_mount_capability()?;

    let target = open_and_validate_empty_target()?;
    let pre_mount_id = descriptor_mount_id(&target)?;
    let source = format!("/proc/self/fd/{}", home.as_raw_fd());
    rustix::mount::mount_bind(&source, CODEX_HOME_TARGET)
        .map_err(|_| RescueVaultDaemonError::RuntimeUnavailable)?;
    let mut mounted = MountedTarget { armed: true };
    rustix::mount::mount_remount(
        CODEX_HOME_TARGET,
        MountFlags::BIND
            | MountFlags::NOSUID
            | MountFlags::NODEV
            | MountFlags::NOEXEC
            | MountFlags::NOSYMFOLLOW,
        "",
    )
    .map_err(|_| RescueVaultDaemonError::RuntimeUnavailable)?;

    validate_mounted_target(&home, pre_mount_id)?;
    validate_codex_home_handoff(&home)?;
    validate_vaultd_peer(socket.as_fd())?;
    validate_live_pidfd(peer_pidfd.as_fd())?;
    verify_codex_mounter_mount_capability()?;
    internal_wire::send_record(socket.as_fd(), ACK, &[], deadline)
        .map_err(|_| RescueVaultDaemonError::ProtocolFailure)?;
    mounted.armed = false;
    Ok(())
}

fn validate_mount_root(root: &OwnedFd) -> Result<(), RescueVaultDaemonError> {
    validate_mount_root_descriptor(root.as_fd())
        .map_err(|_| RescueVaultDaemonError::ProtocolFailure)?;
    let initial_root = rfs::open(
        "/",
        OFlags::PATH | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(|_| RescueVaultDaemonError::RuntimeUnavailable)?;
    let expected =
        rfs::fstat(&initial_root).map_err(|_| RescueVaultDaemonError::RuntimeUnavailable)?;
    let observed = rfs::fstat(root).map_err(|_| RescueVaultDaemonError::ProtocolFailure)?;
    if (expected.st_dev, expected.st_ino) != (observed.st_dev, observed.st_ino) {
        return Err(RescueVaultDaemonError::ProtocolFailure);
    }
    Ok(())
}

fn validate_chroot_identity(root: &OwnedFd) -> Result<(), RescueVaultDaemonError> {
    let named = rfs::open(
        "/",
        OFlags::PATH | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(|_| RescueVaultDaemonError::RuntimeUnavailable)?;
    let expected = rfs::fstat(root).map_err(|_| RescueVaultDaemonError::ProtocolFailure)?;
    let observed = rfs::fstat(&named).map_err(|_| RescueVaultDaemonError::RuntimeUnavailable)?;
    if (expected.st_dev, expected.st_ino) != (observed.st_dev, observed.st_ino) {
        return Err(RescueVaultDaemonError::RuntimeUnavailable);
    }
    Ok(())
}

struct MountedTarget {
    armed: bool,
}

impl Drop for MountedTarget {
    fn drop(&mut self) {
        if self.armed {
            let _ = rustix::mount::unmount(CODEX_HOME_TARGET, UnmountFlags::NOFOLLOW);
        }
    }
}

fn validate_root_server(socket: BorrowedFd<'_>) -> Result<(), RescueVaultDaemonError> {
    let peer = rustix::net::sockopt::socket_peercred(socket)
        .map_err(|_| RescueVaultDaemonError::ProtocolFailure)?;
    let socket_type = rustix::net::sockopt::socket_type(socket)
        .map_err(|_| RescueVaultDaemonError::ProtocolFailure)?;
    let flags =
        rustix::io::fcntl_getfd(socket).map_err(|_| RescueVaultDaemonError::ProtocolFailure)?;
    if peer.uid.as_raw() != 0
        || peer.gid.as_raw() != 0
        || socket_type != SocketType::SEQPACKET
        || flags != rustix::io::FdFlags::CLOEXEC
    {
        return Err(RescueVaultDaemonError::ProtocolFailure);
    }
    Ok(())
}

fn validate_vaultd_peer(socket: BorrowedFd<'_>) -> Result<(), RescueVaultDaemonError> {
    let peer = getsockopt(&socket, sockopt::PeerCredentials)
        .map_err(|_| RescueVaultDaemonError::InvalidListener)?;
    if peer.pid() <= 1 || peer.uid() != 0 || peer.gid() != 0 {
        return Err(RescueVaultDaemonError::InvalidListener);
    }
    let socket_type = rustix::net::sockopt::socket_type(socket)
        .map_err(|_| RescueVaultDaemonError::InvalidListener)?;
    let flags =
        rustix::io::fcntl_getfd(socket).map_err(|_| RescueVaultDaemonError::InvalidListener)?;
    if socket_type != SocketType::SEQPACKET || flags != rustix::io::FdFlags::CLOEXEC {
        return Err(RescueVaultDaemonError::InvalidListener);
    }
    let cgroup = read_proc_file_bounded(
        &format!("/proc/{}/cgroup", peer.pid()),
        MAX_PROC_CGROUP_BYTES,
    )?;
    if cgroup != VAULTD_CGROUP {
        return Err(RescueVaultDaemonError::InvalidListener);
    }
    Ok(())
}

fn validate_live_pidfd(pidfd: BorrowedFd<'_>) -> Result<(), RescueVaultDaemonError> {
    if rustix::io::fcntl_getfd(pidfd).map_err(|_| RescueVaultDaemonError::ProtocolFailure)?
        != rustix::io::FdFlags::CLOEXEC
    {
        return Err(RescueVaultDaemonError::ProtocolFailure);
    }
    let mut descriptors = [PollFd::from_borrowed_fd(pidfd, PollFlags::IN)];
    let zero = Timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    match poll(&mut descriptors, Some(&zero)) {
        Ok(0) => Ok(()),
        Ok(_) => Err(RescueVaultDaemonError::ProtocolFailure),
        Err(_) => Err(RescueVaultDaemonError::ProtocolFailure),
    }
}

fn validate_namespace_owner(mount_namespace: BorrowedFd<'_>) -> Result<(), RescueVaultDaemonError> {
    if namespace_type(mount_namespace).map_err(|_| RescueVaultDaemonError::ProtocolFailure)?
        != NamespaceType::MOUNT
    {
        return Err(RescueVaultDaemonError::ProtocolFailure);
    }
    let initial_user = rfs::open(
        "/proc/self/ns/user",
        OFlags::RDONLY | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(|_| RescueVaultDaemonError::RuntimeUnavailable)?;
    if namespace_type(&initial_user).map_err(|_| RescueVaultDaemonError::RuntimeUnavailable)?
        != NamespaceType::USER
    {
        return Err(RescueVaultDaemonError::RuntimeUnavailable);
    }
    let owner = owner_user_namespace(mount_namespace)
        .map_err(|_| RescueVaultDaemonError::ProtocolFailure)?;
    let initial_stat =
        rfs::fstat(&initial_user).map_err(|_| RescueVaultDaemonError::RuntimeUnavailable)?;
    let owner_stat = rfs::fstat(&owner).map_err(|_| RescueVaultDaemonError::ProtocolFailure)?;
    let owner_fs = rfs::fstatfs(&owner).map_err(|_| RescueVaultDaemonError::ProtocolFailure)?;
    if (initial_stat.st_dev, initial_stat.st_ino) != (owner_stat.st_dev, owner_stat.st_ino)
        || u64::try_from(owner_fs.f_type).ok() != Some(NSFS_MAGIC)
        || rustix::io::fcntl_getfd(&owner).map_err(|_| RescueVaultDaemonError::ProtocolFailure)?
            != rustix::io::FdFlags::CLOEXEC
    {
        return Err(RescueVaultDaemonError::ProtocolFailure);
    }
    Ok(())
}

fn open_and_validate_empty_target() -> Result<OwnedFd, RescueVaultDaemonError> {
    let target = rfs::openat2(
        rfs::CWD,
        CODEX_HOME_TARGET,
        OFlags::PATH | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
        ResolveFlags::NO_SYMLINKS | ResolveFlags::NO_MAGICLINKS,
    )
    .map_err(|_| RescueVaultDaemonError::RuntimeUnavailable)?;
    let stat = rfs::fstat(&target).map_err(|_| RescueVaultDaemonError::RuntimeUnavailable)?;
    let named = rfs::statat(rfs::CWD, CODEX_HOME_TARGET, AtFlags::SYMLINK_NOFOLLOW)
        .map_err(|_| RescueVaultDaemonError::RuntimeUnavailable)?;
    let filesystem =
        rfs::fstatfs(&target).map_err(|_| RescueVaultDaemonError::RuntimeUnavailable)?;
    if !FileType::from_raw_mode(stat.st_mode).is_dir()
        || stat.st_uid != 0
        || stat.st_gid != 0
        || stat.st_mode & 0o7777 != 0
        || (stat.st_dev, stat.st_ino) != (named.st_dev, named.st_ino)
        || u64::try_from(filesystem.f_type).ok() != Some(TMPFS_MAGIC)
        || rustix::io::fcntl_getfd(&target)
            .map_err(|_| RescueVaultDaemonError::RuntimeUnavailable)?
            != rustix::io::FdFlags::CLOEXEC
        || !mountinfo_has_secure_target(
            read_mountinfo()?.as_slice(),
            descriptor_mount_id(&target)?,
            b"tmpfs",
        )
    {
        return Err(RescueVaultDaemonError::RuntimeUnavailable);
    }
    Ok(target)
}

fn validate_mounted_target(
    home: &OwnedFd,
    pre_mount_id: u64,
) -> Result<(), RescueVaultDaemonError> {
    let target = rfs::openat2(
        rfs::CWD,
        CODEX_HOME_TARGET,
        OFlags::PATH | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
        ResolveFlags::NO_SYMLINKS | ResolveFlags::NO_MAGICLINKS,
    )
    .map_err(|_| RescueVaultDaemonError::RuntimeUnavailable)?;
    let home_stat = rfs::fstat(home).map_err(|_| RescueVaultDaemonError::RuntimeUnavailable)?;
    let target_stat =
        rfs::fstat(&target).map_err(|_| RescueVaultDaemonError::RuntimeUnavailable)?;
    let filesystem =
        rfs::fstatfs(&target).map_err(|_| RescueVaultDaemonError::RuntimeUnavailable)?;
    let post_mount_id = descriptor_mount_id(&target)?;
    if (home_stat.st_dev, home_stat.st_ino) != (target_stat.st_dev, target_stat.st_ino)
        || post_mount_id == pre_mount_id
        || u64::try_from(filesystem.f_type).ok() != Some(EXT4_SUPER_MAGIC)
        || !mountinfo_has_secure_target(read_mountinfo()?.as_slice(), post_mount_id, b"ext4")
    {
        return Err(RescueVaultDaemonError::RuntimeUnavailable);
    }
    Ok(())
}

fn descriptor_mount_id(descriptor: &OwnedFd) -> Result<u64, RescueVaultDaemonError> {
    let stat = rfs::statx(
        descriptor,
        "",
        AtFlags::EMPTY_PATH | AtFlags::NO_AUTOMOUNT | AtFlags::SYMLINK_NOFOLLOW,
        StatxFlags::MNT_ID,
    )
    .map_err(|_| RescueVaultDaemonError::RuntimeUnavailable)?;
    if !StatxFlags::from_bits_retain(stat.stx_mask).contains(StatxFlags::MNT_ID)
        || stat.stx_mnt_id == 0
    {
        return Err(RescueVaultDaemonError::RuntimeUnavailable);
    }
    Ok(stat.stx_mnt_id)
}

fn read_mountinfo() -> Result<Vec<u8>, RescueVaultDaemonError> {
    read_proc_file_bounded(
        &format!("/proc/{}/mountinfo", rustix::process::getpid().as_raw_pid()),
        MAX_MOUNTINFO_BYTES,
    )
}

fn read_proc_file_bounded(path: &str, maximum: usize) -> Result<Vec<u8>, RescueVaultDaemonError> {
    let descriptor = rfs::openat2(
        rfs::CWD,
        path,
        OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
        ResolveFlags::NO_SYMLINKS | ResolveFlags::NO_MAGICLINKS,
    )
    .map_err(|_| RescueVaultDaemonError::RuntimeUnavailable)?;
    let filesystem =
        rfs::fstatfs(&descriptor).map_err(|_| RescueVaultDaemonError::RuntimeUnavailable)?;
    let stat = rfs::fstat(&descriptor).map_err(|_| RescueVaultDaemonError::RuntimeUnavailable)?;
    if !FileType::from_raw_mode(stat.st_mode).is_file()
        || u64::try_from(filesystem.f_type).ok() != Some(PROC_SUPER_MAGIC)
    {
        return Err(RescueVaultDaemonError::RuntimeUnavailable);
    }
    let limit = u64::try_from(maximum)
        .ok()
        .and_then(|value| value.checked_add(1))
        .ok_or(RescueVaultDaemonError::RuntimeUnavailable)?;
    let mut bytes = Vec::with_capacity(maximum.min(4096));
    File::from(descriptor)
        .take(limit)
        .read_to_end(&mut bytes)
        .map_err(|_| RescueVaultDaemonError::RuntimeUnavailable)?;
    if bytes.is_empty() || bytes.len() > maximum {
        return Err(RescueVaultDaemonError::RuntimeUnavailable);
    }
    Ok(bytes)
}

fn mountinfo_has_secure_target(bytes: &[u8], expected_mount_id: u64, filesystem: &[u8]) -> bool {
    let mut matches = 0_usize;
    let mut target_records = 0_usize;
    for line in bytes
        .split(|byte| *byte == b'\n')
        .filter(|line| !line.is_empty())
    {
        let fields: Vec<&[u8]> = line
            .split(|byte| *byte == b' ')
            .filter(|field| !field.is_empty())
            .collect();
        if fields.len() < 10 || fields.get(4).copied() != Some(CODEX_HOME_TARGET.as_bytes()) {
            continue;
        }
        target_records = match target_records.checked_add(1) {
            Some(records) if records <= 2 => records,
            _ => return false,
        };
        let Some(mount_id) = fields.first().and_then(|field| parse_mount_id(field)) else {
            return false;
        };
        if mount_id != expected_mount_id {
            continue;
        }
        let Some(separator) = fields.iter().position(|field| *field == b"-") else {
            return false;
        };
        if separator < 6 || fields.get(separator + 1).copied() != Some(filesystem) {
            return false;
        }
        let options = fields[5];
        let has = |expected: &[u8]| {
            options
                .split(|byte| *byte == b',')
                .any(|option| option == expected)
        };
        if !has(b"rw")
            || has(b"ro")
            || !has(b"nosuid")
            || !has(b"nodev")
            || !has(b"noexec")
            || !has(b"nosymfollow")
        {
            return false;
        }
        matches += 1;
    }
    matches == 1 && (1..=2).contains(&target_records)
}

fn parse_mount_id(field: &[u8]) -> Option<u64> {
    if field.is_empty() || field.first() == Some(&b'0') || !field.iter().all(u8::is_ascii_digit) {
        return None;
    }
    field.iter().try_fold(0_u64, |value, digit| {
        value.checked_mul(10)?.checked_add(u64::from(digit - b'0'))
    })
}

fn wait_ready(
    socket: BorrowedFd<'_>,
    interest: PollFlags,
    deadline: Instant,
) -> Result<(), RescueVaultDaemonError> {
    loop {
        let remaining = deadline
            .checked_duration_since(Instant::now())
            .filter(|remaining| !remaining.is_zero())
            .ok_or(RescueVaultDaemonError::RuntimeUnavailable)?;
        let seconds = i64::try_from(remaining.as_secs()).unwrap_or(i64::MAX);
        let timeout = Timespec {
            tv_sec: seconds,
            tv_nsec: if seconds == i64::MAX {
                999_999_999
            } else {
                i64::from(remaining.subsec_nanos())
            },
        };
        let mut descriptors = [PollFd::from_borrowed_fd(socket, interest)];
        match poll(&mut descriptors, Some(&timeout)) {
            Ok(0) => return Err(RescueVaultDaemonError::RuntimeUnavailable),
            Ok(_) => {
                let events = descriptors[0].revents();
                if events.intersects(PollFlags::ERR | PollFlags::HUP | PollFlags::NVAL) {
                    return Err(RescueVaultDaemonError::RuntimeUnavailable);
                }
                if events.intersects(interest) {
                    return Ok(());
                }
            }
            Err(error) if error == rustix::io::Errno::INTR => {}
            Err(_) => return Err(RescueVaultDaemonError::RuntimeUnavailable),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn helper_protocol_and_paths_are_closed() {
        assert_eq!(REQUEST, b"KERNAID_CODEX_MOUNT_V1");
        assert_eq!(ACK, b"KERNAID_CODEX_MOUNT_OK_V1");
        assert_eq!(CODEX_HOME_TARGET, "/run/kernaid-codex-home");
        assert_eq!(
            CODEX_MOUNTER_SOCKET_PATH,
            "/run/kernaid-rescue-codex-mounter.sock"
        );
    }

    #[test]
    fn mountinfo_requires_one_rw_hardened_fixed_target() {
        let valid = b"41 30 8:1 / /run/kernaid-codex-home rw,nosuid,nodev,noexec,nosymfollow - ext4 /dev/root rw\n";
        assert!(mountinfo_has_secure_target(valid, 41, b"ext4"));
        let stacked = b"40 30 0:28 / /run/kernaid-codex-home rw,nosuid,nodev,noexec,nosymfollow - tmpfs tmpfs rw\n41 40 8:1 / /run/kernaid-codex-home rw,nosuid,nodev,noexec,nosymfollow - ext4 /dev/root rw\n";
        assert!(mountinfo_has_secure_target(stacked, 40, b"tmpfs"));
        assert!(mountinfo_has_secure_target(stacked, 41, b"ext4"));
        for invalid in [
            b"41 30 8:1 / /run/kernaid-codex-home ro,nosuid,nodev,noexec,nosymfollow - ext4 /dev/root ro\n".as_slice(),
            b"41 30 8:1 / /run/kernaid-codex-home rw,nosuid,nodev,noexec - ext4 /dev/root rw\n".as_slice(),
            b"41 30 8:1 / /run/other rw,nosuid,nodev,noexec,nosymfollow - ext4 /dev/root rw\n".as_slice(),
            b"41 30 8:1 / /run/kernaid-codex-home rw,nosuid,nodev,noexec,nosymfollow - tmpfs tmpfs rw\n".as_slice(),
        ] {
            assert!(!mountinfo_has_secure_target(invalid, 41, b"ext4"));
        }
        let duplicate = [valid.as_slice(), valid.as_slice()].concat();
        assert!(!mountinfo_has_secure_target(&duplicate, 41, b"ext4"));
        assert!(!mountinfo_has_secure_target(stacked, 42, b"ext4"));
        let too_many = [stacked.as_slice(), valid.as_slice()].concat();
        assert!(!mountinfo_has_secure_target(&too_many, 41, b"ext4"));
    }

    #[test]
    fn vaultd_cgroup_identity_is_exact() {
        assert_eq!(
            VAULTD_CGROUP,
            b"0::/system.slice/kernaid-rescue-vaultd.service/supervisor\n"
        );
    }
}
