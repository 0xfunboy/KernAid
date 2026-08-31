//! Privileged Linux adapter for the local A/B state machine.
//!
//! Only UEFI with systemd-boot is supported. All paths, entry identifiers,
//! commands and kernel slot markers are compiled in; Fleet data cannot alter
//! any of them.

use crate::activation::{ActivationError, BootActivationEngine, BootSelector, ReconcileOutcome};
use fs2::FileExt as _;
use kernaid_update_client::Slot;
use serde::Deserialize;
use std::{
    env, fs,
    fs::{File, OpenOptions},
    io::Read,
    os::unix::fs::MetadataExt,
    path::Path,
    process::{Command, Stdio},
    thread,
    time::{Duration, Instant},
};

const CONFIG_SCHEMA: &str = "dev.kernaid.fleet.resident-activator-config.v1";
const CONFIG_FILE: &str = "/etc/kernaid/fleet-resident-activator.json";
const STATE_DIRECTORY: &str = "/var/lib/kernaid/fleet-resident-update";
const LOCK_FILE: &str = "/var/lib/kernaid/fleet-resident-update/.resident-update-v1.lock";
const UEFI_DIRECTORY: &str = "/sys/firmware/efi";
const BOOTCTL: &str = "/usr/bin/bootctl";
const ENTRY_A: &str = "/boot/loader/entries/kernaid-slot-a.conf";
const ENTRY_B: &str = "/boot/loader/entries/kernaid-slot-b.conf";
const ENTRY_ID_A: &str = "kernaid-slot-a.conf";
const ENTRY_ID_B: &str = "kernaid-slot-b.conf";
const CMDLINE_FILE: &str = "/proc/cmdline";
const BOOT_ID_FILE: &str = "/proc/sys/kernel/random/boot_id";
const MAX_CONFIG_BYTES: usize = 1024;
const MAX_ENTRY_BYTES: usize = 32 * 1024;
const MAX_CMDLINE_BYTES: usize = 16 * 1024;
const MAX_BOOT_ID_BYTES: usize = 64;
const BOOTCTL_TIMEOUT: Duration = Duration::from_secs(10);

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ActivatorConfig {
    schema: String,
    enabled: bool,
}

impl ActivatorConfig {
    fn parse(bytes: &[u8]) -> Result<Self, ActivationError> {
        if bytes.is_empty() || bytes.len() > MAX_CONFIG_BYTES {
            return Err(ActivationError::StateInvalid);
        }
        let config: Self =
            serde_json::from_slice(bytes).map_err(|_| ActivationError::StateInvalid)?;
        if config.schema != CONFIG_SCHEMA || !config.enabled {
            return Err(ActivationError::UnsupportedPlatform);
        }
        Ok(config)
    }
}

pub fn run_from_args() -> Result<(), ActivationError> {
    let rollback = match env::args_os().skip(1).collect::<Vec<_>>().as_slice() {
        [] => false,
        [argument] if argument == "--rollback" => true,
        _ => return Err(ActivationError::StateInvalid),
    };
    run(rollback)
}

fn run(rollback: bool) -> Result<(), ActivationError> {
    if rustix::process::geteuid().as_raw() != 0 {
        return Err(ActivationError::UnsupportedPlatform);
    }
    let _ = ActivatorConfig::parse(&read_root_owned_bounded(
        Path::new(CONFIG_FILE),
        MAX_CONFIG_BYTES,
    )?)?;
    verify_root_owned_state_directory(Path::new(STATE_DIRECTORY))?;
    let lock = open_lock(Path::new(LOCK_FILE))?;
    lock.try_lock_exclusive()
        .map_err(|_| ActivationError::JournalConflict)?;

    let current_slot =
        parse_current_slot(&read_bounded(Path::new(CMDLINE_FILE), MAX_CMDLINE_BYTES)?)?;
    let boot_id = parse_boot_id(&read_bounded(Path::new(BOOT_ID_FILE), MAX_BOOT_ID_BYTES)?)?;
    let selector = FixedSystemdBootSelector;
    let mut engine = BootActivationEngine::open(Path::new(STATE_DIRECTORY), selector)?;
    let outcome = if rollback {
        engine.rollback(current_slot, &boot_id)?
    } else {
        engine.reconcile(current_slot, &boot_id)?
    };
    print_outcome(outcome);
    Ok(())
}

fn print_outcome(outcome: ReconcileOutcome) {
    let status = match outcome {
        ReconcileOutcome::Idle => "idle",
        ReconcileOutcome::TrialArmed => "trial_armed",
        ReconcileOutcome::WaitingForReboot => "waiting_for_reboot",
        ReconcileOutcome::Succeeded => "succeeded",
        ReconcileOutcome::FellBack => "fell_back",
        ReconcileOutcome::RollbackArmed => "rollback_armed",
        ReconcileOutcome::RolledBack => "rolled_back",
    };
    println!("KERNAID_FLEET_RESIDENT_ACTIVATOR_V1 status={status}");
}

struct FixedSystemdBootSelector;

impl BootSelector for FixedSystemdBootSelector {
    fn preflight(&mut self, known_good: Slot, target: Slot) -> Result<(), ActivationError> {
        if known_good.inactive() != target
            || !Path::new(UEFI_DIRECTORY).is_dir()
            || !root_owned_regular(Path::new(BOOTCTL))?
        {
            return Err(ActivationError::UnsupportedPlatform);
        }
        verify_entry(Path::new(ENTRY_A), Slot::A)?;
        verify_entry(Path::new(ENTRY_B), Slot::B)?;
        run_bootctl(&["--quiet", "is-installed"])
    }

    fn arm_trial(&mut self, known_good: Slot, target: Slot) -> Result<(), ActivationError> {
        // Keep the current known-good entry as persistent default. The target
        // is one-shot only, so a boot failure naturally returns here.
        run_bootctl(&["set-default", entry_id(known_good)])?;
        run_bootctl(&["set-oneshot", entry_id(target)])
    }

    fn promote(&mut self, target: Slot) -> Result<(), ActivationError> {
        run_bootctl(&["set-default", entry_id(target)])
    }

    fn arm_rollback(&mut self, known_good: Slot) -> Result<(), ActivationError> {
        run_bootctl(&["set-default", entry_id(known_good)])?;
        run_bootctl(&["set-oneshot", entry_id(known_good)])
    }
}

const fn entry_id(slot: Slot) -> &'static str {
    match slot {
        Slot::A => ENTRY_ID_A,
        Slot::B => ENTRY_ID_B,
    }
}

fn verify_entry(path: &Path, slot: Slot) -> Result<(), ActivationError> {
    if !root_owned_regular(path)? {
        return Err(ActivationError::BootEntryInvalid);
    }
    let bytes = read_bounded(path, MAX_ENTRY_BYTES)?;
    let text = std::str::from_utf8(&bytes).map_err(|_| ActivationError::BootEntryInvalid)?;
    validate_entry_text(text, slot)
}

fn validate_entry_text(text: &str, slot: Slot) -> Result<(), ActivationError> {
    if text
        .chars()
        .any(|value| value.is_control() && !matches!(value, '\n' | '\r' | '\t'))
    {
        return Err(ActivationError::BootEntryInvalid);
    }
    let expected = match slot {
        Slot::A => "kernaid.slot=a",
        Slot::B => "kernaid.slot=b",
    };
    let mut payload_lines = 0_u8;
    let mut options_lines = 0_u8;
    let mut expected_markers = 0_u8;
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let mut fields = line.split_ascii_whitespace();
        match fields.next() {
            Some("linux" | "efi") => payload_lines = payload_lines.saturating_add(1),
            Some("options") => {
                options_lines = options_lines.saturating_add(1);
                for option in fields {
                    if option.starts_with("kernaid.slot=") {
                        if option != expected {
                            return Err(ActivationError::BootEntryInvalid);
                        }
                        expected_markers = expected_markers.saturating_add(1);
                    }
                }
            }
            _ => {}
        }
    }
    if payload_lines != 1 || options_lines != 1 || expected_markers != 1 {
        return Err(ActivationError::BootEntryInvalid);
    }
    Ok(())
}

fn run_bootctl(arguments: &[&str]) -> Result<(), ActivationError> {
    let mut child = Command::new(BOOTCTL)
        .args(arguments)
        .env_clear()
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .map_err(|_| ActivationError::BootSelectorFailed)?;
    let deadline = Instant::now() + BOOTCTL_TIMEOUT;
    loop {
        match child.try_wait() {
            Ok(Some(status)) if status.success() => return Ok(()),
            Ok(Some(_)) => return Err(ActivationError::BootSelectorFailed),
            Ok(None) if Instant::now() < deadline => thread::sleep(Duration::from_millis(25)),
            Ok(None) => {
                let _ = child.kill();
                let _ = child.wait();
                return Err(ActivationError::BootSelectorTimeout);
            }
            Err(_) => return Err(ActivationError::BootSelectorFailed),
        }
    }
}

fn parse_current_slot(bytes: &[u8]) -> Result<Slot, ActivationError> {
    let value = std::str::from_utf8(bytes).map_err(|_| ActivationError::BootObservationInvalid)?;
    let mut found = None;
    for token in value.split_ascii_whitespace() {
        if let Some(slot) = token.strip_prefix("kernaid.slot=") {
            if found.is_some() {
                return Err(ActivationError::BootObservationInvalid);
            }
            found = Some(match slot {
                "a" => Slot::A,
                "b" => Slot::B,
                _ => return Err(ActivationError::BootObservationInvalid),
            });
        }
    }
    found.ok_or(ActivationError::BootObservationInvalid)
}

fn parse_boot_id(bytes: &[u8]) -> Result<String, ActivationError> {
    let value = std::str::from_utf8(bytes)
        .map_err(|_| ActivationError::BootObservationInvalid)?
        .trim();
    if value.is_empty()
        || value.len() > MAX_BOOT_ID_BYTES
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() || byte == b'-')
    {
        return Err(ActivationError::BootObservationInvalid);
    }
    Ok(value.to_owned())
}

fn open_lock(path: &Path) -> Result<File, ActivationError> {
    let mut options = OpenOptions::new();
    options.read(true).write(true).create(true);
    use std::os::unix::fs::OpenOptionsExt as _;
    options.mode(0o600);
    let file = options.open(path)?;
    if !root_owned_regular(path)? {
        return Err(ActivationError::StateInvalid);
    }
    Ok(file)
}

fn verify_root_owned_state_directory(path: &Path) -> Result<(), ActivationError> {
    let metadata = fs::symlink_metadata(path)?;
    if metadata.file_type().is_symlink()
        || !metadata.is_dir()
        || metadata.uid() != 0
        || metadata.mode() & 0o022 != 0
    {
        return Err(ActivationError::StateInvalid);
    }
    for entry in fs::read_dir(path)? {
        let entry = entry?;
        let metadata = fs::symlink_metadata(entry.path())?;
        if metadata.file_type().is_symlink() || metadata.uid() != 0 || metadata.mode() & 0o022 != 0
        {
            return Err(ActivationError::StateInvalid);
        }
    }
    Ok(())
}

fn root_owned_regular(path: &Path) -> Result<bool, ActivationError> {
    let metadata = fs::symlink_metadata(path)?;
    Ok(!metadata.file_type().is_symlink()
        && metadata.is_file()
        && metadata.uid() == 0
        && metadata.mode() & 0o022 == 0)
}

fn read_root_owned_bounded(path: &Path, maximum: usize) -> Result<Vec<u8>, ActivationError> {
    if !root_owned_regular(path)? {
        return Err(ActivationError::StateInvalid);
    }
    read_bounded(path, maximum)
}

fn read_bounded(path: &Path, maximum: usize) -> Result<Vec<u8>, ActivationError> {
    let metadata = fs::symlink_metadata(path)?;
    if metadata.file_type().is_symlink()
        || !metadata.is_file()
        || metadata.len() == 0
        || metadata.len() > maximum as u64
    {
        return Err(ActivationError::StateInvalid);
    }
    let mut file = File::open(path)?;
    let mut bytes = Vec::with_capacity(metadata.len() as usize);
    file.by_ref()
        .take((maximum + 1) as u64)
        .read_to_end(&mut bytes)?;
    if bytes.is_empty() || bytes.len() > maximum || bytes.len() as u64 != metadata.len() {
        return Err(ActivationError::StateInvalid);
    }
    Ok(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn slot_marker_is_required_and_bound_to_entry() {
        assert_eq!(
            parse_current_slot(b"quiet kernaid.slot=a ro").expect("parse slot A marker"),
            Slot::A
        );
        assert_eq!(
            parse_current_slot(b"kernaid.slot=b").expect("parse slot B marker"),
            Slot::B
        );
        assert!(parse_current_slot(b"quiet").is_err());
        assert!(parse_current_slot(b"kernaid.slot=a kernaid.slot=b").is_err());
        assert!(parse_current_slot(b"kernaid.slot=prod").is_err());
    }

    #[test]
    fn config_is_explicit_and_closed() {
        assert!(
            ActivatorConfig::parse(
                br#"{"schema":"dev.kernaid.fleet.resident-activator-config.v1","enabled":true}"#
            )
            .is_ok()
        );
        assert!(
            ActivatorConfig::parse(
                br#"{"schema":"dev.kernaid.fleet.resident-activator-config.v1","enabled":false}"#
            )
            .is_err()
        );
        assert!(ActivatorConfig::parse(br#"{"schema":"dev.kernaid.fleet.resident-activator-config.v1","enabled":true,"command":"sh"}"#).is_err());
    }

    #[test]
    fn boot_entry_has_one_payload_and_one_fixed_slot_marker() {
        assert!(
            validate_entry_text(
                "title KernAid A\nefi /EFI/Linux/kernaid-slot-a.efi\noptions quiet kernaid.slot=a\n",
                Slot::A,
            )
            .is_ok()
        );
        assert!(
            validate_entry_text(
                "efi /EFI/Linux/kernaid-slot-a.efi\noptions kernaid.slot=b\n",
                Slot::A,
            )
            .is_err()
        );
        assert!(
            validate_entry_text(
                "efi /EFI/Linux/kernaid-slot-a.efi\noptions kernaid.slot=a kernaid.slot=a\n",
                Slot::A,
            )
            .is_err()
        );
    }
}
