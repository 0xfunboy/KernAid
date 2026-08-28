//! Root Rescue vault daemon and terminal-only companion lifecycle.
//!
//! The daemon exposes the vault lifecycle plus presence-only provider status,
//! OpenAI credential configuration, logout, and a lease-bound borrow operation
//! for the authenticated provider Agent. The daemon itself never executes a
//! provider request or opens a network path.
//! Potentially blocking block-device and filesystem work lives in one
//! long-lived worker process which is moved into its delegated cgroup before
//! it receives any work.

#[cfg(feature = "experimental-codex-home-lease")]
mod codex_mounter;
mod companion;
mod internal_wire;
mod runtime;
mod server;
mod worker;

#[cfg(feature = "experimental-codex-home-lease")]
pub use codex_mounter::run_rescue_codex_mounter;

#[cfg(feature = "experimental-firstboot-provisioner")]
pub(crate) use companion::read_firstboot_passphrase_pair;

use rustix::fs::{AtFlags, FileType, Mode, OFlags, ResolveFlags};
use std::{error::Error, ffi::OsString, fmt};

pub(super) const COMPANION_UID: u32 = 1000;
pub(super) const COMPANION_NAME: &[u8] = b"kernaid";
pub(super) const OPENAI_AGENT_NAME: &[u8] = b"kernaid-openai";
pub(super) const APPLICATION_AGENT_NAME: &[u8] = b"kernaid-application";
const ISOLATED_AGENT_HOME: &[u8] = b"/nonexistent";
const ISOLATED_AGENT_SHELL: &[u8] = b"/usr/sbin/nologin";
const OPENAI_AGENT_GROUP: &[u8] = b"kernaid-openai";
const APPLICATION_AGENT_GROUP: &[u8] = b"kernaid-application";
const OPENAI_VAULT_GROUP: &[u8] = b"kernaid-vault";
const PROVIDER_CLIENT_GROUP: &[u8] = b"kernaid-provider-client";
#[cfg(feature = "experimental-repair-store")]
const REPAIR_BROKER_NAME: &[u8] = b"kernaid-repair";
#[cfg(feature = "experimental-repair-store")]
const REPAIR_BROKER_GECOS: &[u8] = b"KernAid Rescue repair broker";
#[cfg(feature = "experimental-repair-store")]
const REPAIR_BROKER_HOME: &[u8] = b"/nonexistent";
#[cfg(feature = "experimental-repair-store")]
const REPAIR_BROKER_SHELL: &[u8] = b"/usr/sbin/nologin";
#[cfg(feature = "experimental-codex-home-lease")]
const CODEX_AGENT_NAME: &[u8] = b"kernaid-codex";
#[cfg(feature = "experimental-codex-home-lease")]
const CODEX_AGENT_HOME: &[u8] = b"/nonexistent";
#[cfg(feature = "experimental-codex-home-lease")]
const CODEX_AGENT_SHELL: &[u8] = b"/usr/sbin/nologin";

const PROC_SUPER_MAGIC: u64 = 0x0000_9fa0;
const MAX_PROC_POLICY_BYTES: usize = 4096;
const SWAPS_HEADER: &[u8] = b"Filename\t\t\t\tType\t\tSize\t\tUsed\t\tPriority\n";

pub(super) fn enforce_process_privacy() -> Result<(), ()> {
    let proc = disable_dump_and_validate_initial_namespace()?;
    // ProtectKernelTunables deliberately makes /proc/sys a separate read-only
    // mount. Open that mount root once, validate it as procfs, then keep every
    // policy-file lookup beneath that descriptor without crossing again.
    let proc_sys = open_proc_sys_root()?;
    let core_pattern = read_proc_policy(&proc_sys, "kernel/core_pattern")?;
    let core_uses_pid = read_proc_policy(&proc_sys, "kernel/core_uses_pid")?;
    if !core_policy_is_safe(&core_pattern, &core_uses_pid) {
        return Err(());
    }
    validate_no_active_swap_from(&proc)
}

fn disable_dump_and_validate_initial_namespace() -> Result<rustix::fd::OwnedFd, ()> {
    use rustix::process::{DumpableBehavior, dumpable_behavior, set_dumpable_behavior};
    set_dumpable_behavior(DumpableBehavior::NotDumpable).map_err(|_| ())?;
    if dumpable_behavior().map_err(|_| ())? != DumpableBehavior::NotDumpable {
        return Err(());
    }
    let proc = open_proc_root()?;
    validate_initial_user_namespace_from(&proc)?;
    Ok(proc)
}

pub(super) fn validate_no_active_swap() -> Result<(), ()> {
    validate_no_active_swap_from(&open_proc_root()?)
}

fn validate_no_active_swap_from(proc: &rustix::fd::OwnedFd) -> Result<(), ()> {
    let swaps = read_proc_policy(proc, "swaps")?;
    if !swaps_policy_is_safe(&swaps) {
        return Err(());
    }
    Ok(())
}

fn core_policy_is_safe(pattern: &[u8], uses_pid: &[u8]) -> bool {
    pattern == b"\n" && uses_pid == b"0\n"
}

fn swaps_policy_is_safe(bytes: &[u8]) -> bool {
    bytes == SWAPS_HEADER
}

fn open_proc_root() -> Result<rustix::fd::OwnedFd, ()> {
    let descriptor = rustix::fs::openat2(
        rustix::fs::CWD,
        "/proc",
        OFlags::PATH | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
        ResolveFlags::NO_SYMLINKS | ResolveFlags::NO_MAGICLINKS,
    )
    .map_err(|_| ())?;
    let stat = rustix::fs::fstat(&descriptor).map_err(|_| ())?;
    let filesystem = rustix::fs::fstatfs(&descriptor).map_err(|_| ())?;
    let flags = rustix::io::fcntl_getfd(&descriptor).map_err(|_| ())?;
    if !FileType::from_raw_mode(stat.st_mode).is_dir()
        || stat.st_uid != 0
        || stat.st_gid != 0
        || u64::try_from(filesystem.f_type).ok() != Some(PROC_SUPER_MAGIC)
        || !flags.contains(rustix::io::FdFlags::CLOEXEC)
    {
        return Err(());
    }
    Ok(descriptor)
}

fn open_proc_sys_root() -> Result<rustix::fd::OwnedFd, ()> {
    // NO_XDEV is intentionally absent only from this absolute acquisition:
    // systemd may bind/remount /proc/sys for ProtectKernelTunables. All child
    // lookups use read_proc_policy(), which restores BENEATH+NO_XDEV.
    let descriptor = rustix::fs::openat2(
        rustix::fs::CWD,
        "/proc/sys",
        OFlags::PATH | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
        ResolveFlags::NO_SYMLINKS | ResolveFlags::NO_MAGICLINKS,
    )
    .map_err(|_| ())?;
    let stat = rustix::fs::fstat(&descriptor).map_err(|_| ())?;
    let named = rustix::fs::statat(rustix::fs::CWD, "/proc/sys", AtFlags::SYMLINK_NOFOLLOW)
        .map_err(|_| ())?;
    let filesystem = rustix::fs::fstatfs(&descriptor).map_err(|_| ())?;
    let flags = rustix::io::fcntl_getfd(&descriptor).map_err(|_| ())?;
    if !FileType::from_raw_mode(stat.st_mode).is_dir()
        || stat.st_uid != 0
        || stat.st_gid != 0
        || stat.st_mode & 0o022 != 0
        || named.st_dev != stat.st_dev
        || named.st_ino != stat.st_ino
        || u64::try_from(filesystem.f_type).ok() != Some(PROC_SUPER_MAGIC)
        || !flags.contains(rustix::io::FdFlags::CLOEXEC)
    {
        return Err(());
    }
    Ok(descriptor)
}

fn validate_initial_user_namespace_from(proc: &rustix::fd::OwnedFd) -> Result<(), ()> {
    let pid = rustix::process::getpid().as_raw_pid();
    let uid_map = read_proc_map(proc, &format!("{pid}/uid_map"))?;
    let gid_map = read_proc_map(proc, &format!("{pid}/gid_map"))?;
    if initial_namespace_map_is_exact(&uid_map) && initial_namespace_map_is_exact(&gid_map) {
        Ok(())
    } else {
        Err(())
    }
}

fn read_proc_map(proc: &rustix::fd::OwnedFd, name: &str) -> Result<Vec<u8>, ()> {
    read_proc_map_with_owner(proc, name, 0, 0)
}

fn read_proc_map_with_owner(
    proc: &rustix::fd::OwnedFd,
    name: &str,
    expected_uid: u32,
    expected_gid: u32,
) -> Result<Vec<u8>, ()> {
    let descriptor = rustix::fs::openat2(
        proc,
        name,
        OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
        ResolveFlags::BENEATH
            | ResolveFlags::NO_SYMLINKS
            | ResolveFlags::NO_MAGICLINKS
            | ResolveFlags::NO_XDEV,
    )
    .map_err(|_| ())?;
    let stat = rustix::fs::fstat(&descriptor).map_err(|_| ())?;
    let proc_stat = rustix::fs::fstat(proc).map_err(|_| ())?;
    let filesystem = rustix::fs::fstatfs(&descriptor).map_err(|_| ())?;
    let flags = rustix::io::fcntl_getfd(&descriptor).map_err(|_| ())?;
    let named = rustix::fs::statat(proc, name, AtFlags::SYMLINK_NOFOLLOW).map_err(|_| ())?;
    if !FileType::from_raw_mode(stat.st_mode).is_file()
        // PR_SET_DUMPABLE=0 is established before this lookup. Linux then
        // presents these sensitive proc files as root:root, including for the
        // fixed UID-1000 companion.
        || stat.st_uid != expected_uid
        || stat.st_gid != expected_gid
        || stat.st_nlink != 1
        || stat.st_mode & 0o022 != 0
        || stat.st_dev != proc_stat.st_dev
        || named.st_dev != stat.st_dev
        || named.st_ino != stat.st_ino
        || u64::try_from(filesystem.f_type).ok() != Some(PROC_SUPER_MAGIC)
        || !flags.contains(rustix::io::FdFlags::CLOEXEC)
    {
        return Err(());
    }
    read_proc_descriptor(&descriptor)
}

fn initial_namespace_map_is_exact(bytes: &[u8]) -> bool {
    if bytes.is_empty()
        || !bytes.ends_with(b"\n")
        || bytes[..bytes.len() - 1].contains(&b'\n')
        || bytes[..bytes.len() - 1]
            .iter()
            .any(|byte| !byte.is_ascii_digit() && !matches!(byte, b' ' | b'\t'))
    {
        return false;
    }
    let mut fields = bytes[..bytes.len() - 1]
        .split(|byte| matches!(byte, b' ' | b'\t'))
        .filter(|field| !field.is_empty());
    matches!(
        (fields.next(), fields.next(), fields.next(), fields.next()),
        (Some(b"0"), Some(b"0"), Some(b"4294967295"), None)
    )
}

fn read_proc_policy(proc: &rustix::fd::OwnedFd, name: &str) -> Result<Vec<u8>, ()> {
    let descriptor = rustix::fs::openat2(
        proc,
        name,
        OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
        ResolveFlags::BENEATH
            | ResolveFlags::NO_SYMLINKS
            | ResolveFlags::NO_MAGICLINKS
            | ResolveFlags::NO_XDEV,
    )
    .map_err(|_| ())?;
    let stat = rustix::fs::fstat(&descriptor).map_err(|_| ())?;
    let proc_stat = rustix::fs::fstat(proc).map_err(|_| ())?;
    let filesystem = rustix::fs::fstatfs(&descriptor).map_err(|_| ())?;
    let flags = rustix::io::fcntl_getfd(&descriptor).map_err(|_| ())?;
    let named = rustix::fs::statat(proc, name, AtFlags::SYMLINK_NOFOLLOW).map_err(|_| ())?;
    if !FileType::from_raw_mode(stat.st_mode).is_file()
        || stat.st_uid != 0
        || stat.st_gid != 0
        || stat.st_nlink != 1
        || stat.st_mode & 0o022 != 0
        || stat.st_dev != proc_stat.st_dev
        || named.st_dev != stat.st_dev
        || named.st_ino != stat.st_ino
        || u64::try_from(filesystem.f_type).ok() != Some(PROC_SUPER_MAGIC)
        || !flags.contains(rustix::io::FdFlags::CLOEXEC)
    {
        return Err(());
    }
    read_proc_descriptor(&descriptor)
}

fn read_proc_descriptor(descriptor: &rustix::fd::OwnedFd) -> Result<Vec<u8>, ()> {
    let mut bytes = Vec::new();
    let mut buffer = [0_u8; 512];
    loop {
        match rustix::io::read(descriptor, &mut buffer) {
            Ok(0) => return Ok(bytes),
            Ok(read) if bytes.len().saturating_add(read) <= MAX_PROC_POLICY_BYTES => {
                bytes.extend_from_slice(&buffer[..read]);
            }
            Ok(_) => return Err(()),
            Err(error) if error == rustix::io::Errno::INTR => {}
            Err(_) => return Err(()),
        }
    }
}

#[cfg(test)]
mod privacy_tests {
    use super::*;
    use std::{os::unix::process::CommandExt, process::Command};

    const NONDUMPABLE_CHILD: &str = "KERNAID_TEST_NONDUMPABLE_UNPRIVILEGED";
    const SHIPPING_UID_CHILD: &str = "KERNAID_TEST_SHIPPING_UID1000";

    #[test]
    fn core_and_swap_policies_are_exact_and_header_only() {
        assert!(core_policy_is_safe(b"\n", b"0\n"));
        assert!(!core_policy_is_safe(b"core\n", b"0\n"));
        assert!(!core_policy_is_safe(b"\n", b"1\n"));
        assert!(swaps_policy_is_safe(SWAPS_HEADER));
        let mut active = SWAPS_HEADER.to_vec();
        active.extend_from_slice(b"/swap file 1 0 -1\n");
        assert!(!swaps_policy_is_safe(&active));
        assert!(!swaps_policy_is_safe(b"Filename Type Size Used Priority\n"));
    }

    #[test]
    fn initial_user_namespace_map_is_full_and_canonical() {
        assert!(initial_namespace_map_is_exact(
            b"         0          0 4294967295\n"
        ));
        assert!(initial_namespace_map_is_exact(b"0 0 4294967295\n"));
        assert!(!initial_namespace_map_is_exact(b"0 1000 1\n"));
        assert!(!initial_namespace_map_is_exact(b"0 0 4294967294\n"));
        assert!(!initial_namespace_map_is_exact(b"0 0 4294967295\n1 1 1\n"));
        assert!(!initial_namespace_map_is_exact(b"00 0 4294967295\n"));
        assert!(!initial_namespace_map_is_exact(b"0 0 4294967295\r\n"));
        assert!(!initial_namespace_map_is_exact(b"0 0 4294967295"));
    }

    #[test]
    fn production_namespace_prefix_handles_an_unprivileged_process() {
        if std::env::var_os(NONDUMPABLE_CHILD).is_some() {
            assert_ne!(rustix::process::geteuid().as_raw(), 0);
            let proc = disable_dump_and_validate_initial_namespace()
                .expect("production nondumpable namespace prefix");
            let pid = rustix::process::getpid().as_raw_pid();
            assert!(
                read_proc_map_with_owner(&proc, &format!("{pid}/uid_map"), 1000, 1000).is_err(),
                "reader must reject the pre-PR_SET_DUMPABLE ownership model"
            );
            return;
        }

        let current = std::env::current_exe().expect("test executable");
        let mut child = Command::new(current);
        child
            .env(NONDUMPABLE_CHILD, "1")
            .arg("--exact")
            .arg(
                "rescue_daemon::privacy_tests::production_namespace_prefix_handles_an_unprivileged_process",
            )
            .arg("--nocapture");
        let uid = rustix::process::geteuid().as_raw();
        if uid == 0 {
            child.uid(COMPANION_UID).gid(COMPANION_UID);
        }
        assert!(child.status().expect("nondumpable child").success());
    }

    #[test]
    #[ignore = "requires root to enter the exact shipping UID/GID 1000"]
    fn shipping_uid_1000_uses_the_production_privacy_prefix() {
        if std::env::var_os(SHIPPING_UID_CHILD).is_some() {
            assert_eq!(rustix::process::geteuid().as_raw(), COMPANION_UID);
            assert_eq!(rustix::process::getegid().as_raw(), COMPANION_UID);
            disable_dump_and_validate_initial_namespace()
                .expect("shipping companion privacy prefix");
            return;
        }
        assert_eq!(rustix::process::geteuid().as_raw(), 0, "requires root");
        let current = std::env::current_exe().expect("test executable");
        let status = Command::new(current)
            .uid(COMPANION_UID)
            .gid(COMPANION_UID)
            .env(SHIPPING_UID_CHILD, "1")
            .arg("--exact")
            .arg(
                "rescue_daemon::privacy_tests::shipping_uid_1000_uses_the_production_privacy_prefix",
            )
            .arg("--ignored")
            .arg("--nocapture")
            .status()
            .expect("shipping child");
        assert!(status.success());
    }
}

pub(super) fn passwd_has_exact_companion(bytes: &[u8], expected_uid: u32) -> bool {
    let mut matching_uid = 0_u8;
    let mut matching_name = 0_u8;
    for line in bytes
        .split(|byte| *byte == b'\n')
        .filter(|line| !line.is_empty())
    {
        if line.len() > 4096 || line.contains(&0) {
            return false;
        }
        let fields: Vec<&[u8]> = line.split(|byte| *byte == b':').collect();
        if fields.len() != 7
            || fields[0].is_empty()
            || fields[2].is_empty()
            || !fields[2].iter().all(u8::is_ascii_digit)
            || (fields[2].len() > 1 && fields[2][0] == b'0')
        {
            return false;
        }
        let Some(uid) = std::str::from_utf8(fields[2])
            .ok()
            .and_then(|value| value.parse::<u32>().ok())
        else {
            return false;
        };
        let has_name = fields[0] == COMPANION_NAME;
        let has_uid = uid == expected_uid;
        if has_name && !has_uid || has_uid && !has_name {
            return false;
        }
        if has_name {
            matching_name = matching_name.saturating_add(1);
        }
        if has_uid {
            matching_uid = matching_uid.saturating_add(1);
        }
    }
    matching_name == 1 && matching_uid == 1
}

/// Resolves the dynamically allocated Rescue OpenAI Agent UID from one
/// already validated `/etc/passwd` descriptor. The account name, no-home
/// marker, nologin shell, unique non-root UID, and separation from the fixed
/// companion identity are all closed requirements.
pub(super) fn passwd_openai_agent_uid(bytes: &[u8], companion_uid: u32) -> Option<u32> {
    passwd_isolated_agent_uid(bytes, companion_uid, OPENAI_AGENT_NAME)
}

/// Resolve the dedicated Rescue application relay identity. It shares only
/// the vault socket group with the companion/provider identities and has no
/// home directory or login shell.
pub(super) fn passwd_application_agent_uid(bytes: &[u8], companion_uid: u32) -> Option<u32> {
    passwd_isolated_agent_uid(bytes, companion_uid, APPLICATION_AGENT_NAME)
}

fn passwd_isolated_agent_uid(
    bytes: &[u8],
    companion_uid: u32,
    expected_name: &[u8],
) -> Option<u32> {
    let mut entries: Vec<(&[u8], u32)> = Vec::new();
    let mut agent_uid = None;
    for line in bytes
        .split(|byte| *byte == b'\n')
        .filter(|line| !line.is_empty())
    {
        if line.len() > 4096 || line.contains(&0) {
            return None;
        }
        let fields: Vec<&[u8]> = line.split(|byte| *byte == b':').collect();
        if fields.len() != 7
            || fields[0].is_empty()
            || fields[2].is_empty()
            || fields[3].is_empty()
            || !fields[2].iter().all(u8::is_ascii_digit)
            || !fields[3].iter().all(u8::is_ascii_digit)
            || (fields[2].len() > 1 && fields[2][0] == b'0')
            || (fields[3].len() > 1 && fields[3][0] == b'0')
        {
            return None;
        }
        let uid = std::str::from_utf8(fields[2])
            .ok()
            .and_then(|value| value.parse::<u32>().ok())?;
        let gid = std::str::from_utf8(fields[3])
            .ok()
            .and_then(|value| value.parse::<u32>().ok())?;
        entries.push((fields[0], uid));
        if fields[0] == expected_name {
            if agent_uid.is_some()
                || uid == 0
                || uid == companion_uid
                || gid != uid
                || fields[5] != ISOLATED_AGENT_HOME
                || fields[6] != ISOLATED_AGENT_SHELL
            {
                return None;
            }
            agent_uid = Some(uid);
        }
    }
    let uid = agent_uid?;
    if entries
        .iter()
        .filter(|(_, candidate)| *candidate == uid)
        .count()
        != 1
    {
        return None;
    }
    Some(uid)
}

/// Resolves the dynamically allocated, dedicated repair broker identity from
/// the already trusted `/etc/passwd` descriptor. The private UID/GID pair may
/// not collide with any other account and is never accepted from an argument,
/// environment variable, or wire field.
#[cfg(feature = "experimental-repair-store")]
pub(super) fn passwd_repair_broker_uid(bytes: &[u8], companion_uid: u32) -> Option<u32> {
    struct Entry<'a> {
        name: &'a [u8],
        uid: u32,
        gid: u32,
    }

    let mut entries = Vec::new();
    let mut repair_uid = None;
    for line in bytes
        .split(|byte| *byte == b'\n')
        .filter(|line| !line.is_empty())
    {
        if line.len() > 4096 || line.contains(&0) {
            return None;
        }
        let fields: Vec<&[u8]> = line.split(|byte| *byte == b':').collect();
        if fields.len() != 7
            || fields[0].is_empty()
            || fields[2].is_empty()
            || fields[3].is_empty()
            || !fields[2].iter().all(u8::is_ascii_digit)
            || !fields[3].iter().all(u8::is_ascii_digit)
            || (fields[2].len() > 1 && fields[2][0] == b'0')
            || (fields[3].len() > 1 && fields[3][0] == b'0')
        {
            return None;
        }
        let uid = std::str::from_utf8(fields[2])
            .ok()
            .and_then(|value| value.parse::<u32>().ok())?;
        let gid = std::str::from_utf8(fields[3])
            .ok()
            .and_then(|value| value.parse::<u32>().ok())?;
        entries.push(Entry {
            name: fields[0],
            uid,
            gid,
        });
        if fields[0] == REPAIR_BROKER_NAME {
            if repair_uid.is_some()
                || uid == 0
                || uid == COMPANION_UID
                || uid == companion_uid
                || gid != uid
                || fields[4] != REPAIR_BROKER_GECOS
                || fields[5] != REPAIR_BROKER_HOME
                || fields[6] != REPAIR_BROKER_SHELL
            {
                return None;
            }
            repair_uid = Some(uid);
        }
    }

    let uid = repair_uid?;
    if entries
        .iter()
        .filter(|entry| entry.name == REPAIR_BROKER_NAME)
        .count()
        != 1
        || entries.iter().filter(|entry| entry.uid == uid).count() != 1
        || entries.iter().filter(|entry| entry.gid == uid).count() != 1
    {
        return None;
    }
    Some(uid)
}

/// Validates the private primary group for the repair broker. The group must
/// have the same dynamically allocated numeric identity, no colliding name or
/// GID, and the account may not appear in any static membership list.
#[cfg(feature = "experimental-repair-store")]
pub(super) fn group_has_exact_repair_broker(bytes: &[u8], repair_uid: u32) -> bool {
    struct Entry<'a> {
        name: &'a [u8],
        gid: u32,
        members: Vec<&'a [u8]>,
    }

    if repair_uid == 0 || repair_uid == COMPANION_UID {
        return false;
    }
    let mut entries = Vec::new();
    for line in bytes
        .split(|byte| *byte == b'\n')
        .filter(|line| !line.is_empty())
    {
        if line.len() > 4096 || line.contains(&0) {
            return false;
        }
        let fields: Vec<&[u8]> = line.split(|byte| *byte == b':').collect();
        if fields.len() != 4
            || fields[0].is_empty()
            || fields[2].is_empty()
            || !fields[2].iter().all(u8::is_ascii_digit)
            || (fields[2].len() > 1 && fields[2][0] == b'0')
        {
            return false;
        }
        let Some(gid) = std::str::from_utf8(fields[2])
            .ok()
            .and_then(|value| value.parse::<u32>().ok())
        else {
            return false;
        };
        let members = if fields[3].is_empty() {
            Vec::new()
        } else {
            let members: Vec<&[u8]> = fields[3].split(|byte| *byte == b',').collect();
            if members.iter().any(|member| member.is_empty()) {
                return false;
            }
            for (index, member) in members.iter().enumerate() {
                if members[..index].contains(member) {
                    return false;
                }
            }
            members
        };
        entries.push(Entry {
            name: fields[0],
            gid,
            members,
        });
    }

    let mut matching = entries
        .iter()
        .filter(|entry| entry.name == REPAIR_BROKER_NAME);
    let Some(repair_group) = matching.next() else {
        return false;
    };
    matching.next().is_none()
        && repair_group.gid == repair_uid
        && repair_group.members.is_empty()
        && entries
            .iter()
            .filter(|entry| entry.gid == repair_uid)
            .count()
            == 1
        && !entries
            .iter()
            .any(|entry| entry.members.contains(&REPAIR_BROKER_NAME))
}

/// Validates the fixed, collision-free Codex identity used by both the
/// descriptor owner and the authenticated Agent role. The UID/GID are never
/// accepted from configuration or the wire.
#[cfg(feature = "experimental-codex-home-lease")]
pub(super) fn passwd_has_exact_codex_agent(bytes: &[u8], companion_uid: u32) -> bool {
    let mut matching_name = 0_usize;
    let mut matching_uid = 0_usize;
    let mut matching_gid = 0_usize;
    for line in bytes
        .split(|byte| *byte == b'\n')
        .filter(|line| !line.is_empty())
    {
        if line.len() > 4096 || line.contains(&0) {
            return false;
        }
        let fields: Vec<&[u8]> = line.split(|byte| *byte == b':').collect();
        if fields.len() != 7
            || fields[0].is_empty()
            || fields[2].is_empty()
            || fields[3].is_empty()
            || !fields[2].iter().all(u8::is_ascii_digit)
            || !fields[3].iter().all(u8::is_ascii_digit)
            || (fields[2].len() > 1 && fields[2][0] == b'0')
            || (fields[3].len() > 1 && fields[3][0] == b'0')
        {
            return false;
        }
        let Some(uid) = std::str::from_utf8(fields[2])
            .ok()
            .and_then(|value| value.parse::<u32>().ok())
        else {
            return false;
        };
        let Some(gid) = std::str::from_utf8(fields[3])
            .ok()
            .and_then(|value| value.parse::<u32>().ok())
        else {
            return false;
        };
        let has_name = fields[0] == CODEX_AGENT_NAME;
        let has_uid = uid == crate::CODEX_AGENT_UID;
        let has_gid = gid == crate::CODEX_AGENT_GID;
        if has_name
            && (uid != crate::CODEX_AGENT_UID
                || gid != crate::CODEX_AGENT_GID
                || uid == 0
                || uid == companion_uid
                || fields[5] != CODEX_AGENT_HOME
                || fields[6] != CODEX_AGENT_SHELL)
            || has_uid && !has_name
            || has_gid && !has_name
        {
            return false;
        }
        matching_name += usize::from(has_name);
        matching_uid += usize::from(has_uid);
        matching_gid += usize::from(has_gid);
    }
    matching_name == 1 && matching_uid == 1 && matching_gid == 1
}

/// Validates the group capabilities around both isolated application-plane
/// identities. Each Agent has exactly one supplemental membership
/// (`kernaid-vault`) and neither can join the UI-facing provider-client group.
pub(super) fn group_has_exact_application_boundaries(
    bytes: &[u8],
    openai_uid: u32,
    application_uid: u32,
) -> bool {
    struct Entry<'a> {
        name: &'a [u8],
        gid: u32,
        members: Vec<&'a [u8]>,
    }

    if openai_uid == 0 || application_uid == 0 || openai_uid == application_uid {
        return false;
    }
    let mut entries = Vec::new();
    for line in bytes
        .split(|byte| *byte == b'\n')
        .filter(|line| !line.is_empty())
    {
        if line.len() > 4096 || line.contains(&0) {
            return false;
        }
        let fields: Vec<&[u8]> = line.split(|byte| *byte == b':').collect();
        if fields.len() != 4
            || fields[0].is_empty()
            || fields[2].is_empty()
            || !fields[2].iter().all(u8::is_ascii_digit)
            || (fields[2].len() > 1 && fields[2][0] == b'0')
        {
            return false;
        }
        let Some(gid) = std::str::from_utf8(fields[2])
            .ok()
            .and_then(|value| value.parse::<u32>().ok())
        else {
            return false;
        };
        let members = if fields[3].is_empty() {
            Vec::new()
        } else {
            let members: Vec<&[u8]> = fields[3].split(|byte| *byte == b',').collect();
            if members.iter().any(|member| member.is_empty()) {
                return false;
            }
            for (index, member) in members.iter().enumerate() {
                if members[..index].contains(member) {
                    return false;
                }
            }
            members
        };
        entries.push(Entry {
            name: fields[0],
            gid,
            members,
        });
    }

    let unique = |name: &[u8]| {
        let mut matching = entries.iter().filter(|entry| entry.name == name);
        let entry = matching.next()?;
        matching.next().is_none().then_some(entry)
    };
    let Some(openai_group) = unique(OPENAI_AGENT_GROUP) else {
        return false;
    };
    let Some(application_group) = unique(APPLICATION_AGENT_GROUP) else {
        return false;
    };
    let Some(vault_group) = unique(OPENAI_VAULT_GROUP) else {
        return false;
    };
    let Some(provider_group) = unique(PROVIDER_CLIENT_GROUP) else {
        return false;
    };
    if openai_group.gid != openai_uid
        || application_group.gid != application_uid
        || vault_group.gid == 0
        || provider_group.gid == 0
        || vault_group.gid == openai_uid
        || vault_group.gid == application_uid
        || provider_group.gid == openai_uid
        || provider_group.gid == application_uid
        || provider_group.gid == vault_group.gid
        || !openai_group.members.is_empty()
        || !application_group.members.is_empty()
        || !provider_group.members.is_empty()
        || entries
            .iter()
            .filter(|entry| entry.gid == openai_group.gid)
            .count()
            != 1
        || entries
            .iter()
            .filter(|entry| entry.gid == application_group.gid)
            .count()
            != 1
        || entries
            .iter()
            .filter(|entry| entry.gid == vault_group.gid)
            .count()
            != 1
        || entries
            .iter()
            .filter(|entry| entry.gid == provider_group.gid)
            .count()
            != 1
        || vault_group
            .members
            .iter()
            .filter(|member| **member == OPENAI_AGENT_NAME)
            .count()
            != 1
        || vault_group
            .members
            .iter()
            .filter(|member| **member == APPLICATION_AGENT_NAME)
            .count()
            != 1
        || vault_group.members.len() != 3
        || !vault_group.members.contains(&COMPANION_NAME)
        || provider_group.members.contains(&OPENAI_AGENT_NAME)
        || provider_group.members.contains(&APPLICATION_AGENT_NAME)
        || entries.iter().any(|entry| {
            entry.name != OPENAI_VAULT_GROUP && entry.members.contains(&OPENAI_AGENT_NAME)
        })
        || entries.iter().any(|entry| {
            entry.name != OPENAI_VAULT_GROUP && entry.members.contains(&APPLICATION_AGENT_NAME)
        })
    {
        return false;
    }
    true
}

#[cfg(feature = "experimental-codex-home-lease")]
pub(super) fn group_has_exact_codex_boundaries(bytes: &[u8]) -> bool {
    let mut matching_name = 0_usize;
    let mut matching_gid = 0_usize;
    for line in bytes
        .split(|byte| *byte == b'\n')
        .filter(|line| !line.is_empty())
    {
        if line.len() > 4096 || line.contains(&0) {
            return false;
        }
        let fields: Vec<&[u8]> = line.split(|byte| *byte == b':').collect();
        if fields.len() != 4
            || fields[0].is_empty()
            || fields[2].is_empty()
            || !fields[2].iter().all(u8::is_ascii_digit)
            || (fields[2].len() > 1 && fields[2][0] == b'0')
        {
            return false;
        }
        let Some(gid) = std::str::from_utf8(fields[2])
            .ok()
            .and_then(|value| value.parse::<u32>().ok())
        else {
            return false;
        };
        let has_name = fields[0] == CODEX_AGENT_NAME;
        let has_gid = gid == crate::CODEX_AGENT_GID;
        let members = fields[3];
        if (!members.is_empty()
            && members
                .split(|byte| *byte == b',')
                .any(|member| member == CODEX_AGENT_NAME))
            || has_name && (gid != crate::CODEX_AGENT_GID || !members.is_empty())
            || has_gid && !has_name
        {
            return false;
        }
        matching_name += usize::from(has_name);
        matching_gid += usize::from(has_gid);
    }
    matching_name == 1 && matching_gid == 1
}

#[cfg(test)]
mod passwd_agent_tests {
    use super::*;

    const VALID: &[u8] = b"root:x:0:0:root:/root:/bin/bash\n\
kernaid:x:1000:1000:KernAid:/home/kernaid:/bin/bash\n\
kernaid-application:x:995:995:KernAid Rescue application relay:/nonexistent:/usr/sbin/nologin\n\
kernaid-openai:x:994:994:KernAid Rescue OpenAI executor:/nonexistent:/usr/sbin/nologin\n";

    #[test]
    fn dynamic_openai_agent_uid_is_exact_and_collision_free() {
        assert_eq!(passwd_openai_agent_uid(VALID, 1000), Some(994));
        assert_eq!(passwd_openai_agent_uid(VALID, 994), None);

        let duplicate_uid = [
            VALID,
            b"another:x:994:995:duplicate:/nonexistent:/usr/sbin/nologin\n",
        ]
        .concat();
        assert_eq!(passwd_openai_agent_uid(&duplicate_uid, 1000), None);

        let duplicate_name = [
            VALID,
            b"kernaid-openai:x:993:993:duplicate:/nonexistent:/usr/sbin/nologin\n",
        ]
        .concat();
        assert_eq!(passwd_openai_agent_uid(&duplicate_name, 1000), None);
    }

    #[test]
    fn openai_agent_home_shell_and_canonical_uid_are_closed() {
        for invalid in [
            b"kernaid:x:1000:1000:KernAid:/home/kernaid:/bin/bash\n\
kernaid-openai:x:994:994:OpenAI:/home/openai:/usr/sbin/nologin\n"
                .as_slice(),
            b"kernaid:x:1000:1000:KernAid:/home/kernaid:/bin/bash\n\
kernaid-openai:x:994:994:OpenAI:/nonexistent:/bin/bash\n"
                .as_slice(),
            b"kernaid:x:1000:1000:KernAid:/home/kernaid:/bin/bash\n\
kernaid-openai:x:0994:994:OpenAI:/nonexistent:/usr/sbin/nologin\n"
                .as_slice(),
            b"kernaid:x:1000:1000:KernAid:/home/kernaid:/bin/bash\n\
kernaid-openai:x:994:0:OpenAI:/nonexistent:/usr/sbin/nologin\n"
                .as_slice(),
            b"kernaid:x:1000:1000:KernAid:/home/kernaid:/bin/bash\n\
kernaid-openai:x:994:993:OpenAI:/nonexistent:/usr/sbin/nologin\n"
                .as_slice(),
            b"kernaid:x:1000:1000:KernAid:/home/kernaid:/bin/bash\n\
kernaid-openai:x:994:0994:OpenAI:/nonexistent:/usr/sbin/nologin\n"
                .as_slice(),
            b"kernaid:x:1000:1000:KernAid:/home/kernaid:/bin/bash\n\
renamed:x:994:994:OpenAI:/nonexistent:/usr/sbin/nologin\n"
                .as_slice(),
        ] {
            assert_eq!(passwd_openai_agent_uid(invalid, 1000), None);
        }
    }

    #[test]
    fn application_agent_uid_is_exact_and_separate() {
        assert_eq!(passwd_application_agent_uid(VALID, 1000), Some(995));
        assert_eq!(passwd_application_agent_uid(VALID, 995), None);
        let duplicate_uid = [
            VALID,
            b"another:x:995:996:duplicate:/nonexistent:/usr/sbin/nologin\n",
        ]
        .concat();
        assert_eq!(passwd_application_agent_uid(&duplicate_uid, 1000), None);
        let wrong_home = b"root:x:0:0:root:/root:/bin/bash\n\
kernaid:x:1000:1000:KernAid:/home/kernaid:/bin/bash\n\
kernaid-application:x:995:995:relay:/home/relay:/usr/sbin/nologin\n";
        assert_eq!(passwd_application_agent_uid(wrong_home, 1000), None);
    }

    #[test]
    fn application_agent_group_boundaries_are_exact() {
        const GROUPS: &[u8] = b"root:x:0:\n\
kernaid-vault:x:993:kernaid,kernaid-openai,kernaid-application\n\
kernaid-provider-client:x:992:\n\
kernaid-application:x:995:\n\
kernaid-openai:x:994:\n";
        assert!(group_has_exact_application_boundaries(GROUPS, 994, 995));
        for invalid in [
            b"kernaid-vault:x:993:kernaid,kernaid-openai\nkernaid-provider-client:x:992:\nkernaid-application:x:995:\nkernaid-openai:x:994:\n".as_slice(),
            b"kernaid-vault:x:993:kernaid,kernaid-openai,kernaid-application\nkernaid-provider-client:x:992:kernaid-application\nkernaid-application:x:995:\nkernaid-openai:x:994:\n".as_slice(),
            b"kernaid-vault:x:993:kernaid,kernaid-openai,kernaid-application\nkernaid-provider-client:x:992:\nkernaid-application:x:994:\nkernaid-openai:x:994:\n".as_slice(),
            b"kernaid-vault:x:993:kernaid,kernaid-openai,kernaid-application\nkernaid-provider-client:x:992:\nkernaid-application:x:995:some-user\nkernaid-openai:x:994:\n".as_slice(),
            b"kernaid-vault:x:993:kernaid,kernaid-openai,kernaid-application\nkernaid-provider-client:x:992:\nkernaid-application:x:995:\nkernaid-openai:x:994:\nextra:x:991:kernaid-application\n".as_slice(),
        ] {
            assert!(!group_has_exact_application_boundaries(invalid, 994, 995));
        }
    }

    #[cfg(feature = "experimental-repair-store")]
    #[test]
    fn repair_broker_passwd_identity_is_exact_and_collision_free() {
        const PASSWD: &[u8] = b"root:x:0:0:root:/root:/bin/bash\n\
kernaid:x:1000:1000:KernAid:/home/kernaid:/bin/bash\n\
kernaid-repair:x:996:996:KernAid Rescue repair broker:/nonexistent:/usr/sbin/nologin\n\
kernaid-openai:x:994:994:KernAid Rescue OpenAI executor:/nonexistent:/usr/sbin/nologin\n";
        assert_eq!(passwd_repair_broker_uid(PASSWD, 1000), Some(996));

        for invalid in [
            b"root:x:0:0:root:/root:/bin/bash\nkernaid-repair:x:0:0:KernAid Rescue repair broker:/nonexistent:/usr/sbin/nologin\n".to_vec(),
            b"root:x:0:0:root:/root:/bin/bash\nkernaid-repair:x:1000:1000:KernAid Rescue repair broker:/nonexistent:/usr/sbin/nologin\n".to_vec(),
            b"root:x:0:0:root:/root:/bin/bash\nkernaid-repair:x:996:995:KernAid Rescue repair broker:/nonexistent:/usr/sbin/nologin\n".to_vec(),
            b"root:x:0:0:root:/root:/bin/bash\nkernaid-repair:x:996:996:repair:/nonexistent:/usr/sbin/nologin\n".to_vec(),
            b"root:x:0:0:root:/root:/bin/bash\nkernaid-repair:x:996:996:KernAid Rescue repair broker:/home/repair:/usr/sbin/nologin\n".to_vec(),
            b"root:x:0:0:root:/root:/bin/bash\nkernaid-repair:x:996:996:KernAid Rescue repair broker:/nonexistent:/bin/bash\n".to_vec(),
            [
                PASSWD,
                b"kernaid-repair:x:995:995:KernAid Rescue repair broker:/nonexistent:/usr/sbin/nologin\n",
            ]
            .concat(),
            [PASSWD, b"other:x:996:995:collision:/nonexistent:/usr/sbin/nologin\n"].concat(),
            [PASSWD, b"other:x:995:996:collision:/nonexistent:/usr/sbin/nologin\n"].concat(),
        ] {
            assert_eq!(passwd_repair_broker_uid(&invalid, 1000), None);
        }
    }

    #[cfg(feature = "experimental-repair-store")]
    #[test]
    fn repair_broker_group_is_private_and_collision_free() {
        const GROUP: &[u8] = b"root:x:0:\n\
kernaid-vault:x:993:kernaid,kernaid-openai,kernaid-application\n\
kernaid-repair:x:996:\n\
kernaid-openai:x:994:\n";
        assert!(group_has_exact_repair_broker(GROUP, 996));
        for invalid in [
            b"root:x:0:\nkernaid-repair:x:995:\n".to_vec(),
            b"root:x:0:\nkernaid-repair:x:996:other\n".to_vec(),
            b"root:x:0:\nkernaid-repair:x:996:\nextra:x:995:kernaid-repair\n".to_vec(),
            b"root:x:0:\nkernaid-repair:x:996:\nkernaid-repair:x:995:\n".to_vec(),
            b"root:x:0:\nkernaid-repair:x:996:\nother:x:996:\n".to_vec(),
            b"root:x:0:\nkernaid-repair:x:0996:\n".to_vec(),
        ] {
            assert!(!group_has_exact_repair_broker(&invalid, 996));
        }
        assert!(!group_has_exact_repair_broker(GROUP, 0));
        assert!(!group_has_exact_repair_broker(GROUP, 1000));
    }

    #[cfg(feature = "experimental-codex-home-lease")]
    #[test]
    fn static_codex_identity_is_exact_and_collision_free() {
        const PASSWD: &[u8] = b"root:x:0:0:root:/root:/bin/bash\n\
kernaid:x:1000:1000:KernAid:/home/kernaid:/bin/bash\n\
kernaid-codex:x:973:973:KernAid Rescue Codex executor:/nonexistent:/usr/sbin/nologin\n\
kernaid-openai:x:994:994:KernAid Rescue OpenAI executor:/nonexistent:/usr/sbin/nologin\n";
        assert!(passwd_has_exact_codex_agent(PASSWD, 1000));
        for invalid in [
            b"root:x:0:0:root:/root:/bin/bash\nkernaid:x:1000:1000:KernAid:/home/kernaid:/bin/bash\nkernaid-codex:x:974:973:Codex:/nonexistent:/usr/sbin/nologin\n".to_vec(),
            b"root:x:0:0:root:/root:/bin/bash\nkernaid:x:1000:1000:KernAid:/home/kernaid:/bin/bash\nkernaid-codex:x:973:973:Codex:/home/codex:/usr/sbin/nologin\n".to_vec(),
            [
                PASSWD,
                b"other:x:973:974:collision:/nonexistent:/usr/sbin/nologin\n",
            ]
            .concat(),
            [
                PASSWD,
                b"other:x:974:973:collision:/nonexistent:/usr/sbin/nologin\n",
            ]
            .concat(),
            [
                PASSWD,
                b"kernaid-codex:x:974:974:duplicate:/nonexistent:/usr/sbin/nologin\n",
            ]
            .concat(),
        ] {
            assert!(!passwd_has_exact_codex_agent(&invalid, 1000));
        }
    }

    #[cfg(feature = "experimental-codex-home-lease")]
    #[test]
    fn static_codex_group_has_no_collision_or_supplementary_membership() {
        const GROUP: &[u8] = b"root:x:0:\nkernaid-vault:x:993:kernaid,kernaid-openai\n\
kernaid-codex:x:973:\nkernaid-openai:x:994:\n";
        assert!(group_has_exact_codex_boundaries(GROUP));
        for invalid in [
            b"root:x:0:\nkernaid-codex:x:973:other\n".as_slice(),
            b"root:x:0:\nkernaid-codex:x:974:\n".as_slice(),
            b"root:x:0:\nother:x:973:\n".as_slice(),
            b"root:x:0:\nkernaid-codex:x:973:\nextra:x:974:kernaid-codex\n".as_slice(),
            b"root:x:0:\nkernaid-codex:x:973:\nother:x:973:\n".as_slice(),
        ] {
            assert!(!group_has_exact_codex_boundaries(invalid));
        }
    }
}

/// Sanitized daemon failure. No variant carries a pathname, OS error, peer
/// input, mapper name, device name, or secret material.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RescueVaultDaemonError {
    InvalidConfiguration,
    PrivilegeRequired,
    InvalidListener,
    RuntimeUnavailable,
    AlreadyRunning,
    PersistentFault,
    WorkerUnavailable,
    CgroupUnavailable,
    ProtocolFailure,
    ShutdownFailed,
}

impl fmt::Display for RescueVaultDaemonError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::InvalidConfiguration => "invalid Rescue vault daemon configuration",
            Self::PrivilegeRequired => "Rescue vault daemon requires root",
            Self::InvalidListener => "invalid Rescue vault daemon listener",
            Self::RuntimeUnavailable => "Rescue vault daemon runtime state is unavailable",
            Self::AlreadyRunning => "another Rescue vault daemon is active",
            Self::PersistentFault => "Rescue vault requires reboot before another worker",
            Self::WorkerUnavailable => "Rescue vault worker is unavailable",
            Self::CgroupUnavailable => "Rescue vault worker cgroup is unavailable",
            Self::ProtocolFailure => "Rescue vault daemon protocol failed",
            Self::ShutdownFailed => "Rescue vault daemon shutdown could not be verified",
        })
    }
}

impl Error for RescueVaultDaemonError {}

/// Sanitized terminal companion failure. The optional remote token belongs to
/// the protocol's closed error vocabulary and contains no server text.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RescueVaultCompanionError {
    InvalidCommand,
    TtyUnavailable,
    EchoControlFailed,
    SecretInvalid,
    ConfirmationDeclined,
    TransportUnavailable,
    ProtocolFailure,
    Interrupted,
    Remote(kernaid_protocol::rescue_vault::ErrorToken),
}

impl fmt::Display for RescueVaultCompanionError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::InvalidCommand => "invalid Rescue vault companion command",
            Self::TtyUnavailable => "the controlling terminal is unavailable",
            Self::EchoControlFailed => "terminal echo could not be restored",
            Self::SecretInvalid => "the hidden secret input is invalid",
            Self::ConfirmationDeclined => "provider logout was not confirmed",
            Self::TransportUnavailable => "the Rescue vault service is unavailable",
            Self::ProtocolFailure => "the Rescue vault response is invalid",
            Self::Interrupted => "the Rescue vault companion was interrupted",
            Self::Remote(error) => return formatter.write_str(remote_error_name(*error)),
        })
    }
}

impl Error for RescueVaultCompanionError {}

fn remote_error_name(error: kernaid_protocol::rescue_vault::ErrorToken) -> &'static str {
    use kernaid_protocol::rescue_vault::ErrorToken;
    match error {
        ErrorToken::Absent => "ABSENT",
        ErrorToken::Unprovisioned => "UNPROVISIONED",
        ErrorToken::Locked => "LOCKED",
        ErrorToken::BadPassphrase => "BAD_PASSPHRASE",
        ErrorToken::MediaChanged => "MEDIA_CHANGED",
        ErrorToken::ProfileMismatch => "PROFILE_MISMATCH",
        ErrorToken::StaleState => "STALE_STATE",
        ErrorToken::FdRequired => "FD_REQUIRED",
        ErrorToken::FdForbidden => "FD_FORBIDDEN",
        ErrorToken::NotAuthorized => "NOT_AUTHORIZED",
        ErrorToken::RateLimited => "RATE_LIMITED",
        ErrorToken::Busy => "BUSY",
        ErrorToken::ProviderUnconfigured => "PROVIDER_UNCONFIGURED",
        ErrorToken::ReportTooLarge => "REPORT_TOO_LARGE",
        ErrorToken::IoFailed => "IO_FAILED",
        ErrorToken::RebootRequired => "REBOOT_REQUIRED",
    }
}

/// Run the production daemon on the seqpacket listener supplied as standard
/// input by the root-owned service manager. The sole companion identity is the
/// fixed Rescue account UID 1000; no argv or environment override exists.
pub fn run_rescue_vault_daemon() -> Result<(), RescueVaultDaemonError> {
    server::run(COMPANION_UID)
}

/// Run the terminal-only companion command.
pub fn run_rescue_vault_companion<I>(arguments: I) -> Result<(), RescueVaultCompanionError>
where
    I: IntoIterator<Item = OsString>,
{
    companion::run(arguments)
}

/// Internal worker entrypoint reached only through the daemon's exact hidden
/// argument. Its bidirectional control socket is standard input.
#[doc(hidden)]
pub fn run_internal_rescue_vault_worker() -> Result<(), RescueVaultDaemonError> {
    worker::run()
}
