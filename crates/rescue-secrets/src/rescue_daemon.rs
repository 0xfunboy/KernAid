//! Root Rescue vault daemon and terminal-only companion lifecycle.
//!
//! The daemon exposes the vault lifecycle plus presence-only provider status,
//! OpenAI credential configuration, and OpenAI logout. Provider borrowing and
//! execution remain disabled.
//! Potentially blocking block-device and filesystem work lives in one
//! long-lived worker process which is moved into its delegated cgroup before
//! it receives any work.

mod companion;
mod internal_wire;
mod runtime;
mod server;
mod worker;

use rustix::fs::{AtFlags, FileType, Mode, OFlags, ResolveFlags};
use std::{error::Error, ffi::OsString, fmt};

pub(super) const COMPANION_UID: u32 = 1000;
pub(super) const COMPANION_NAME: &[u8] = b"kernaid";

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
