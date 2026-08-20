//! Bounded, privacy-reduced inventory of the running Linux machine.

use serde::{Deserialize, Serialize};
use std::{
    collections::{BTreeMap, BTreeSet},
    error::Error,
    fmt, fs,
    io::{self, Read},
    path::{Path, PathBuf},
};

pub const COLLECTOR: &str = "linux.hardware.inventory";
pub const SCHEMA_VERSION: &str = "1.0";
pub const KIND: &str = "linux-hardware-inventory";
pub const MAX_JSON_BYTES: usize = 64 * 1024;

const MAX_PROC_BYTES: usize = 1024 * 1024;
const MAX_ATTRIBUTE_BYTES: usize = 4 * 1024;
const MAX_TEXT_BYTES: usize = 256;
const MAX_CPU_IDENTITIES: usize = 16;
const MAX_LOGICAL_PROCESSORS: u32 = 4096;
const MAX_DEVICE_ENTRIES: usize = 256;
const MAX_SYSFS_DIRECTORY_ENTRIES: usize = 1024;
const MAX_SAFE_JSON_INTEGER: u64 = 9_007_199_254_740_991;

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum SourceStatus {
    Complete,
    Partial,
    Truncated,
    Unavailable,
    Invalid,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct HardwareInventory {
    pub schema_version: String,
    pub kind: String,
    pub architecture: String,
    pub cpu: CpuInventory,
    pub memory: MemoryInventory,
    pub firmware: FirmwareInventory,
    pub pci: PciInventory,
    pub usb: UsbInventory,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CpuInventory {
    pub status: SourceStatus,
    pub logical_processors: Option<u32>,
    pub vendors: Vec<String>,
    pub models: Vec<String>,
    pub virtualization_flag_present: Option<bool>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct MemoryInventory {
    pub status: SourceStatus,
    pub total_bytes: Option<u64>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct FirmwareInventory {
    pub status: SourceStatus,
    pub boot_mode: String,
    pub dmi: DmiInventory,
}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DmiInventory {
    pub bios_vendor: Option<String>,
    pub bios_version: Option<String>,
    pub board_name: Option<String>,
    pub board_vendor: Option<String>,
    pub product_name: Option<String>,
    pub system_vendor: Option<String>,
}

#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PciDevice {
    pub class: String,
    pub vendor_id: String,
    pub device_id: String,
    pub count: u16,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PciInventory {
    pub status: SourceStatus,
    pub devices: Vec<PciDevice>,
}

#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct UsbDevice {
    pub class: String,
    pub vendor_id: String,
    pub product_id: String,
    pub count: u16,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct UsbInventory {
    pub status: SourceStatus,
    pub devices: Vec<UsbDevice>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct InvalidHardwareInventory;

impl fmt::Display for InvalidHardwareInventory {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("invalid normalized Linux hardware inventory")
    }
}

impl Error for InvalidHardwareInventory {}

#[derive(Clone, Debug)]
struct HardwareRoots {
    proc_cpuinfo: PathBuf,
    proc_meminfo: PathBuf,
    sys_firmware_efi: PathBuf,
    sys_dmi: PathBuf,
    sys_pci: PathBuf,
    sys_usb: PathBuf,
}

impl HardwareRoots {
    fn current() -> Self {
        Self {
            proc_cpuinfo: PathBuf::from("/proc/cpuinfo"),
            proc_meminfo: PathBuf::from("/proc/meminfo"),
            sys_firmware_efi: PathBuf::from("/sys/firmware/efi"),
            sys_dmi: PathBuf::from("/sys/class/dmi/id"),
            sys_pci: PathBuf::from("/sys/bus/pci/devices"),
            sys_usb: PathBuf::from("/sys/bus/usb/devices"),
        }
    }
}

enum BoundedFile {
    Bytes(Vec<u8>),
    Missing,
    Oversized,
    Failed,
}

fn read_bounded(path: &Path, maximum: usize) -> BoundedFile {
    let mut file = match fs::File::open(path) {
        Ok(file) => file,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return BoundedFile::Missing,
        Err(_) => return BoundedFile::Failed,
    };
    let mut bytes = Vec::new();
    match file
        .by_ref()
        .take(maximum as u64 + 1)
        .read_to_end(&mut bytes)
    {
        Ok(_) if bytes.len() <= maximum => BoundedFile::Bytes(bytes),
        Ok(_) => BoundedFile::Oversized,
        Err(_) => BoundedFile::Failed,
    }
}

fn normalized_text(path: &Path) -> Result<Option<String>, SourceStatus> {
    let bytes = match read_bounded(path, MAX_ATTRIBUTE_BYTES) {
        BoundedFile::Bytes(bytes) => bytes,
        BoundedFile::Missing => return Ok(None),
        BoundedFile::Oversized => return Err(SourceStatus::Truncated),
        BoundedFile::Failed => return Err(SourceStatus::Partial),
    };
    let text = std::str::from_utf8(&bytes).map_err(|_| SourceStatus::Invalid)?;
    let normalized = normalize_public_text(text)?;
    if normalized.is_empty() {
        return Ok(None);
    }
    Ok(Some(normalized))
}

fn normalize_public_text(text: &str) -> Result<String, SourceStatus> {
    let normalized = text.split_whitespace().collect::<Vec<_>>().join(" ");
    if normalized.len() > MAX_TEXT_BYTES {
        return Err(SourceStatus::Truncated);
    }
    if normalized.chars().any(invalid_public_text_character) {
        return Err(SourceStatus::Invalid);
    }
    Ok(normalized)
}

fn invalid_public_text_character(character: char) -> bool {
    character.is_control()
        || character == '\u{feff}'
        || matches!(
            character,
            '\u{061c}'
                | '\u{200e}'
                | '\u{200f}'
                | '\u{202a}'..='\u{202e}'
                | '\u{2066}'..='\u{2069}'
        )
}

fn merge_failure(current: Option<SourceStatus>, candidate: SourceStatus) -> Option<SourceStatus> {
    fn severity(status: SourceStatus) -> u8 {
        match status {
            SourceStatus::Complete => 0,
            SourceStatus::Unavailable => 1,
            SourceStatus::Partial => 2,
            SourceStatus::Truncated => 3,
            SourceStatus::Invalid => 4,
        }
    }
    match current {
        Some(current) if severity(current) >= severity(candidate) => Some(current),
        _ => Some(candidate),
    }
}

fn cpu_inventory(path: &Path) -> CpuInventory {
    let bytes = match read_bounded(path, MAX_PROC_BYTES) {
        BoundedFile::Bytes(bytes) => bytes,
        BoundedFile::Missing | BoundedFile::Failed => {
            return CpuInventory {
                status: SourceStatus::Unavailable,
                logical_processors: None,
                vendors: Vec::new(),
                models: Vec::new(),
                virtualization_flag_present: None,
            };
        }
        BoundedFile::Oversized => {
            return CpuInventory {
                status: SourceStatus::Truncated,
                logical_processors: None,
                vendors: Vec::new(),
                models: Vec::new(),
                virtualization_flag_present: None,
            };
        }
    };
    let text = match std::str::from_utf8(&bytes) {
        Ok(text) => text,
        Err(_) => {
            return CpuInventory {
                status: SourceStatus::Invalid,
                logical_processors: None,
                vendors: Vec::new(),
                models: Vec::new(),
                virtualization_flag_present: None,
            };
        }
    };
    let mut processors = 0_u32;
    let mut vendors = BTreeSet::new();
    let mut models = BTreeSet::new();
    let mut virtualization_seen = false;
    let mut invalid = false;
    let mut truncated = false;
    for line in text.lines() {
        let Some((raw_key, raw_value)) = line.split_once(':') else {
            continue;
        };
        let key = raw_key.trim();
        let value = raw_value.split_whitespace().collect::<Vec<_>>().join(" ");
        match key {
            "processor" => {
                if value.parse::<u32>().is_ok() {
                    processors = match processors
                        .checked_add(1)
                        .filter(|value| *value <= MAX_LOGICAL_PROCESSORS)
                    {
                        Some(value) => value,
                        None => {
                            invalid = true;
                            processors
                        }
                    };
                } else {
                    invalid = true;
                }
            }
            "vendor_id" | "CPU implementer" => match normalize_public_text(&value) {
                Ok(value) if !value.is_empty() => {
                    vendors.insert(value);
                }
                Err(SourceStatus::Truncated) => truncated = true,
                _ => invalid = true,
            },
            "model name" | "Hardware" => match normalize_public_text(&value) {
                Ok(value) if !value.is_empty() => {
                    models.insert(value);
                }
                Err(SourceStatus::Truncated) => truncated = true,
                _ => invalid = true,
            },
            "flags" | "Features" => {
                virtualization_seen |= value
                    .split_ascii_whitespace()
                    .any(|flag| matches!(flag, "vmx" | "svm"));
            }
            _ => {}
        }
    }
    if processors == 0 {
        invalid = true;
    }
    truncated |= vendors.len() > MAX_CPU_IDENTITIES || models.len() > MAX_CPU_IDENTITIES;
    CpuInventory {
        status: if invalid {
            SourceStatus::Invalid
        } else if truncated {
            SourceStatus::Truncated
        } else {
            SourceStatus::Complete
        },
        logical_processors: (!invalid).then_some(processors),
        vendors: vendors.into_iter().take(MAX_CPU_IDENTITIES).collect(),
        models: models.into_iter().take(MAX_CPU_IDENTITIES).collect(),
        virtualization_flag_present: (!invalid).then_some(virtualization_seen),
    }
}

fn memory_inventory(path: &Path) -> MemoryInventory {
    let bytes = match read_bounded(path, MAX_PROC_BYTES) {
        BoundedFile::Bytes(bytes) => bytes,
        BoundedFile::Missing | BoundedFile::Failed => {
            return MemoryInventory {
                status: SourceStatus::Unavailable,
                total_bytes: None,
            };
        }
        BoundedFile::Oversized => {
            return MemoryInventory {
                status: SourceStatus::Truncated,
                total_bytes: None,
            };
        }
    };
    let Ok(text) = std::str::from_utf8(&bytes) else {
        return MemoryInventory {
            status: SourceStatus::Invalid,
            total_bytes: None,
        };
    };
    let values = text
        .lines()
        .filter_map(|line| line.strip_prefix("MemTotal:"))
        .collect::<Vec<_>>();
    if values.len() != 1 {
        return MemoryInventory {
            status: SourceStatus::Invalid,
            total_bytes: None,
        };
    }
    let parts = values[0].split_ascii_whitespace().collect::<Vec<_>>();
    let total_bytes = match parts.as_slice() {
        [digits, "kB"] => digits
            .parse::<u64>()
            .ok()
            .and_then(|kilobytes| kilobytes.checked_mul(1024))
            .filter(|bytes| *bytes > 0 && *bytes <= MAX_SAFE_JSON_INTEGER),
        _ => None,
    };
    MemoryInventory {
        status: if total_bytes.is_some() {
            SourceStatus::Complete
        } else {
            SourceStatus::Invalid
        },
        total_bytes,
    }
}

fn firmware_inventory(efi: &Path, dmi_root: &Path) -> FirmwareInventory {
    let (boot_mode, mut failure) = match fs::metadata(efi) {
        Ok(metadata) if metadata.is_dir() => ("uefi", None),
        Ok(_) => ("unknown", Some(SourceStatus::Invalid)),
        Err(error) if error.kind() == io::ErrorKind::NotFound => ("bios-or-legacy", None),
        Err(_) => ("unknown", Some(SourceStatus::Partial)),
    };
    let fields = [
        ("bios_vendor", "bios_vendor"),
        ("bios_version", "bios_version"),
        ("board_name", "board_name"),
        ("board_vendor", "board_vendor"),
        ("product_name", "product_name"),
        ("system_vendor", "sys_vendor"),
    ];
    let mut values = Vec::with_capacity(fields.len());
    for (_, file) in fields {
        match normalized_text(&dmi_root.join(file)) {
            Ok(value) => values.push(value),
            Err(status) => {
                failure = merge_failure(failure, status);
                values.push(None);
            }
        }
    }
    let mut values = values.into_iter();
    let dmi = DmiInventory {
        bios_vendor: values.next().flatten(),
        bios_version: values.next().flatten(),
        board_name: values.next().flatten(),
        board_vendor: values.next().flatten(),
        product_name: values.next().flatten(),
        system_vendor: values.next().flatten(),
    };
    let observed = [
        &dmi.bios_vendor,
        &dmi.bios_version,
        &dmi.board_name,
        &dmi.board_vendor,
        &dmi.product_name,
        &dmi.system_vendor,
    ]
    .into_iter()
    .filter(|value| value.is_some())
    .count();
    let boot_mode_observed = boot_mode != "unknown";
    FirmwareInventory {
        status: failure.unwrap_or({
            if boot_mode_observed && observed == fields.len() {
                SourceStatus::Complete
            } else if boot_mode_observed || observed > 0 {
                SourceStatus::Partial
            } else {
                SourceStatus::Unavailable
            }
        }),
        boot_mode: boot_mode.to_owned(),
        dmi,
    }
}

fn exact_hex(path: &Path, digits: usize) -> Result<String, SourceStatus> {
    let Some(value) = normalized_text(path)? else {
        return Err(SourceStatus::Partial);
    };
    let Some(hex) = value.strip_prefix("0x") else {
        return Err(SourceStatus::Invalid);
    };
    if hex.len() != digits || !hex.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(SourceStatus::Invalid);
    }
    Ok(format!("0x{}", hex.to_ascii_lowercase()))
}

fn directory_entries(path: &Path, maximum: usize) -> Result<Vec<PathBuf>, SourceStatus> {
    let entries = fs::read_dir(path).map_err(|error| {
        if error.kind() == io::ErrorKind::NotFound {
            SourceStatus::Unavailable
        } else {
            SourceStatus::Partial
        }
    })?;
    let mut paths = Vec::new();
    for entry in entries {
        match entry {
            Ok(entry) if paths.len() < maximum => paths.push(entry.path()),
            Ok(_) => return Err(SourceStatus::Truncated),
            Err(_) => return Err(SourceStatus::Partial),
        }
    }
    paths.sort();
    Ok(paths)
}

fn pci_inventory(path: &Path) -> PciInventory {
    let entries = match directory_entries(path, MAX_DEVICE_ENTRIES) {
        Ok(entries) => entries,
        Err(status) => {
            return PciInventory {
                status,
                devices: Vec::new(),
            };
        }
    };
    let mut devices = BTreeMap::new();
    let mut failure = None;
    for entry in entries {
        match (
            exact_hex(&entry.join("class"), 6),
            exact_hex(&entry.join("vendor"), 4),
            exact_hex(&entry.join("device"), 4),
        ) {
            (Ok(class), Ok(vendor_id), Ok(device_id)) => {
                let count = devices
                    .entry((class, vendor_id, device_id))
                    .or_insert(0_u16);
                *count = count.saturating_add(1);
            }
            (class, vendor_id, device_id) => {
                for status in [class.err(), vendor_id.err(), device_id.err()]
                    .into_iter()
                    .flatten()
                {
                    failure = merge_failure(failure, status);
                }
            }
        }
    }
    PciInventory {
        status: failure.unwrap_or(SourceStatus::Complete),
        devices: devices
            .into_iter()
            .map(|((class, vendor_id, device_id), count)| PciDevice {
                class,
                vendor_id,
                device_id,
                count,
            })
            .collect(),
    }
}

fn usb_inventory(path: &Path) -> UsbInventory {
    let entries = match directory_entries(path, MAX_SYSFS_DIRECTORY_ENTRIES) {
        Ok(entries) => entries,
        Err(status) => {
            return UsbInventory {
                status,
                devices: Vec::new(),
            };
        }
    };
    let mut devices = BTreeMap::new();
    let mut failure = None;
    let mut candidates = 0_usize;
    for entry in entries {
        let vendor_path = entry.join("idVendor");
        match vendor_path.try_exists() {
            Ok(false) => continue,
            Ok(true) => {}
            Err(_) => {
                failure = merge_failure(failure, SourceStatus::Partial);
                continue;
            }
        }
        candidates += 1;
        if candidates > MAX_DEVICE_ENTRIES {
            failure = merge_failure(failure, SourceStatus::Truncated);
            continue;
        }
        match (
            exact_hex_without_prefix(&entry.join("bDeviceClass"), 2),
            exact_hex_without_prefix(&vendor_path, 4),
            exact_hex_without_prefix(&entry.join("idProduct"), 4),
        ) {
            (Ok(class), Ok(vendor_id), Ok(product_id)) => {
                let count = devices
                    .entry((class, vendor_id, product_id))
                    .or_insert(0_u16);
                *count = count.saturating_add(1);
            }
            (class, vendor_id, product_id) => {
                for status in [class.err(), vendor_id.err(), product_id.err()]
                    .into_iter()
                    .flatten()
                {
                    failure = merge_failure(failure, status);
                }
            }
        }
    }
    UsbInventory {
        status: failure.unwrap_or(SourceStatus::Complete),
        devices: devices
            .into_iter()
            .map(|((class, vendor_id, product_id), count)| UsbDevice {
                class,
                vendor_id,
                product_id,
                count,
            })
            .collect(),
    }
}

fn exact_hex_without_prefix(path: &Path, digits: usize) -> Result<String, SourceStatus> {
    let Some(value) = normalized_text(path)? else {
        return Err(SourceStatus::Partial);
    };
    if value.len() != digits || !value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(SourceStatus::Invalid);
    }
    Ok(format!("0x{}", value.to_ascii_lowercase()))
}

fn collect(roots: &HardwareRoots) -> HardwareInventory {
    HardwareInventory {
        schema_version: SCHEMA_VERSION.to_owned(),
        kind: KIND.to_owned(),
        architecture: std::env::consts::ARCH.to_owned(),
        cpu: cpu_inventory(&roots.proc_cpuinfo),
        memory: memory_inventory(&roots.proc_meminfo),
        firmware: firmware_inventory(&roots.sys_firmware_efi, &roots.sys_dmi),
        pci: pci_inventory(&roots.sys_pci),
        usb: usb_inventory(&roots.sys_usb),
    }
}

/// Collects only fixed, running-machine Linux sources. No caller path is accepted.
pub fn collect_current_machine() -> HardwareInventory {
    collect(&HardwareRoots::current())
}

fn valid_architecture(value: &str) -> bool {
    let bytes = value.as_bytes();
    (1..=32).contains(&bytes.len())
        && (bytes[0].is_ascii_lowercase() || bytes[0].is_ascii_digit())
        && bytes[1..].iter().all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'_' | b'.' | b'-')
        })
}

fn valid_public_text(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= MAX_TEXT_BYTES
        && !value.chars().any(invalid_public_text_character)
        && value.split_whitespace().collect::<Vec<_>>().join(" ") == value
}

fn valid_text_set(values: &[String]) -> bool {
    values.len() <= MAX_CPU_IDENTITIES
        && values.iter().all(|value| valid_public_text(value))
        && values.windows(2).all(|pair| pair[0] < pair[1])
}

fn valid_hex(value: &str, digits: usize) -> bool {
    value.len() == digits + 2
        && value.starts_with("0x")
        && value[2..]
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn valid_inventory(inventory: &HardwareInventory) -> bool {
    let cpu_values_valid = inventory
        .cpu
        .logical_processors
        .is_none_or(|value| (1..=MAX_LOGICAL_PROCESSORS).contains(&value))
        && valid_text_set(&inventory.cpu.vendors)
        && valid_text_set(&inventory.cpu.models)
        && (inventory.cpu.status != SourceStatus::Complete
            || (inventory.cpu.logical_processors.is_some()
                && inventory.cpu.virtualization_flag_present.is_some()));
    let memory_valid = inventory
        .memory
        .total_bytes
        .is_none_or(|value| value > 0 && value <= MAX_SAFE_JSON_INTEGER)
        && (inventory.memory.status != SourceStatus::Complete
            || inventory.memory.total_bytes.is_some());
    let dmi_values = [
        &inventory.firmware.dmi.bios_vendor,
        &inventory.firmware.dmi.bios_version,
        &inventory.firmware.dmi.board_name,
        &inventory.firmware.dmi.board_vendor,
        &inventory.firmware.dmi.product_name,
        &inventory.firmware.dmi.system_vendor,
    ];
    let firmware_valid = matches!(
        inventory.firmware.boot_mode.as_str(),
        "uefi" | "bios-or-legacy" | "unknown"
    ) && dmi_values
        .iter()
        .all(|value| value.as_deref().is_none_or(valid_public_text))
        && (inventory.firmware.status != SourceStatus::Complete
            || (inventory.firmware.boot_mode != "unknown"
                && dmi_values.iter().all(|value| value.is_some())));
    let pci_valid = inventory.pci.devices.len() <= MAX_DEVICE_ENTRIES
        && inventory.pci.devices.iter().all(|device| {
            valid_hex(&device.class, 6)
                && valid_hex(&device.vendor_id, 4)
                && valid_hex(&device.device_id, 4)
                && (1..=MAX_DEVICE_ENTRIES as u16).contains(&device.count)
        })
        && inventory.pci.devices.windows(2).all(|pair| {
            (&pair[0].class, &pair[0].vendor_id, &pair[0].device_id)
                < (&pair[1].class, &pair[1].vendor_id, &pair[1].device_id)
        })
        && inventory
            .pci
            .devices
            .iter()
            .map(|device| usize::from(device.count))
            .sum::<usize>()
            <= MAX_DEVICE_ENTRIES;
    let usb_valid = inventory.usb.devices.len() <= MAX_DEVICE_ENTRIES
        && inventory.usb.devices.iter().all(|device| {
            valid_hex(&device.class, 2)
                && valid_hex(&device.vendor_id, 4)
                && valid_hex(&device.product_id, 4)
                && (1..=MAX_DEVICE_ENTRIES as u16).contains(&device.count)
        })
        && inventory.usb.devices.windows(2).all(|pair| {
            (&pair[0].class, &pair[0].vendor_id, &pair[0].product_id)
                < (&pair[1].class, &pair[1].vendor_id, &pair[1].product_id)
        })
        && inventory
            .usb
            .devices
            .iter()
            .map(|device| usize::from(device.count))
            .sum::<usize>()
            <= MAX_DEVICE_ENTRIES;
    inventory.schema_version == SCHEMA_VERSION
        && inventory.kind == KIND
        && valid_architecture(&inventory.architecture)
        && cpu_values_valid
        && memory_valid
        && firmware_valid
        && pci_valid
        && usb_valid
}

/// Parses the published hardware document without accepting unknown or raw fields.
pub fn parse_bounded_json(bytes: &[u8]) -> Result<HardwareInventory, InvalidHardwareInventory> {
    if bytes.is_empty() || bytes.len() > MAX_JSON_BYTES || bytes.contains(&0) {
        return Err(InvalidHardwareInventory);
    }
    let canonical_frame = bytes.strip_suffix(b"\n").unwrap_or(bytes);
    if canonical_frame.is_empty() {
        return Err(InvalidHardwareInventory);
    }
    let inventory: HardwareInventory =
        serde_json::from_slice(bytes).map_err(|_| InvalidHardwareInventory)?;
    let canonical = serde_json::to_vec(&inventory).map_err(|_| InvalidHardwareInventory)?;
    if !valid_inventory(&inventory) || canonical != canonical_frame {
        return Err(InvalidHardwareInventory);
    }
    Ok(inventory)
}

pub fn to_bounded_json(inventory: &HardwareInventory) -> Result<String, serde_json::Error> {
    if !valid_inventory(inventory) {
        return Err(serde_json::Error::io(io::Error::other(
            "hardware inventory violated the normalized contract",
        )));
    }
    let json = serde_json::to_string(inventory)?;
    if json.len() > MAX_JSON_BYTES {
        return Err(serde_json::Error::io(io::Error::other(
            "hardware inventory exceeded the output limit",
        )));
    }
    Ok(json)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs::{create_dir_all, write};
    use tempfile::tempdir;

    fn fixture_roots(root: &Path) -> HardwareRoots {
        HardwareRoots {
            proc_cpuinfo: root.join("proc/cpuinfo"),
            proc_meminfo: root.join("proc/meminfo"),
            sys_firmware_efi: root.join("sys/firmware/efi"),
            sys_dmi: root.join("sys/class/dmi/id"),
            sys_pci: root.join("sys/bus/pci/devices"),
            sys_usb: root.join("sys/bus/usb/devices"),
        }
    }

    fn healthy_fixture(root: &Path) -> HardwareRoots {
        let roots = fixture_roots(root);
        create_dir_all(
            roots
                .proc_cpuinfo
                .parent()
                .expect("fixture cpuinfo has a parent"),
        )
        .expect("create fixture proc directory");
        create_dir_all(&roots.sys_firmware_efi).expect("create fixture EFI directory");
        create_dir_all(&roots.sys_dmi).expect("create fixture DMI directory");
        create_dir_all(roots.sys_pci.join("0000:00:02.0")).expect("create fixture PCI device");
        create_dir_all(roots.sys_usb.join("1-1")).expect("create fixture USB device");
        write(
            &roots.proc_cpuinfo,
            "processor : 0\nvendor_id : GenuineIntel\nmodel name : Example CPU\nflags : fpu vmx\n\nprocessor : 1\nvendor_id : GenuineIntel\nmodel name : Example CPU\nflags : fpu vmx\n",
        )
        .expect("write fixture cpuinfo");
        write(&roots.proc_meminfo, "MemTotal:       16384 kB\n").expect("write fixture meminfo");
        write(roots.sys_dmi.join("bios_vendor"), "Example BIOS\n")
            .expect("write fixture BIOS vendor");
        write(roots.sys_dmi.join("bios_version"), "1.2.3\n").expect("write fixture BIOS version");
        write(roots.sys_dmi.join("board_name"), "Example Board\n")
            .expect("write fixture board name");
        write(roots.sys_dmi.join("board_vendor"), "Example Vendor\n")
            .expect("write fixture board vendor");
        write(roots.sys_dmi.join("product_name"), "Example Product\n")
            .expect("write fixture product name");
        write(roots.sys_dmi.join("sys_vendor"), "Example System\n")
            .expect("write fixture system vendor");
        let pci = roots.sys_pci.join("0000:00:02.0");
        write(pci.join("class"), "0x030000\n").expect("write fixture PCI class");
        write(pci.join("vendor"), "0x1234\n").expect("write fixture PCI vendor");
        write(pci.join("device"), "0x1111\n").expect("write fixture PCI device");
        let usb = roots.sys_usb.join("1-1");
        write(usb.join("bDeviceClass"), "00\n").expect("write fixture USB class");
        write(usb.join("idVendor"), "1d6b\n").expect("write fixture USB vendor");
        write(usb.join("idProduct"), "0002\n").expect("write fixture USB product");
        roots
    }

    #[test]
    fn healthy_inventory_is_canonical_bounded_and_excludes_serial_identity() {
        let directory = tempdir().expect("create hardware fixture");
        let inventory = collect(&healthy_fixture(directory.path()));
        assert_eq!(inventory.cpu.status, SourceStatus::Complete);
        assert_eq!(inventory.cpu.logical_processors, Some(2));
        assert_eq!(inventory.cpu.virtualization_flag_present, Some(true));
        assert_eq!(inventory.memory.total_bytes, Some(16 * 1024 * 1024));
        assert_eq!(inventory.firmware.boot_mode, "uefi");
        assert_eq!(inventory.pci.devices.len(), 1);
        assert_eq!(inventory.pci.devices[0].count, 1);
        assert_eq!(inventory.usb.devices.len(), 1);
        assert_eq!(inventory.usb.devices[0].count, 1);
        let json = to_bounded_json(&inventory).expect("serialize hardware inventory");
        assert!(json.len() < MAX_JSON_BYTES);
        assert!(!json.to_ascii_lowercase().contains("serial"));
        assert!(!json.contains("0000:00:02.0"));
        assert!(!json.contains("1-1"));
        assert_eq!(
            serde_json::from_str::<serde_json::Value>(&json).expect("parse hardware inventory")["kind"],
            KIND
        );
        assert_eq!(
            serde_json::from_str::<serde_json::Value>(&json).expect("parse collected inventory"),
            serde_json::from_str::<serde_json::Value>(include_str!(
                "../../../tests/fixtures/linux-hardware-inventory/healthy.v1.json"
            ))
            .expect("parse shared hardware fixture")
        );
        assert_eq!(
            parse_bounded_json(json.as_bytes()).expect("re-parse hardware inventory"),
            inventory
        );
        let mut unknown: serde_json::Value =
            serde_json::from_str(&json).expect("parse inventory for unknown-field test");
        unknown.as_object_mut().expect("inventory object").insert(
            "serial".to_owned(),
            serde_json::Value::String("secret".to_owned()),
        );
        let unknown_json = serde_json::to_vec(&unknown).expect("serialize unknown-field inventory");
        assert_eq!(
            parse_bounded_json(&unknown_json),
            Err(InvalidHardwareInventory)
        );
        let duplicate = json.replacen(
            "\"schemaVersion\":\"1.0\",",
            "\"schemaVersion\":\"1.0\",\"schemaVersion\":\"1.0\",",
            1,
        );
        assert_eq!(
            parse_bounded_json(duplicate.as_bytes()),
            Err(InvalidHardwareInventory)
        );
    }

    #[test]
    fn public_text_rejects_byte_order_marks_and_bidirectional_controls() {
        for invalid in ["Vendor\u{feff}Name", "Vendor\u{202e}Name"] {
            assert_eq!(normalize_public_text(invalid), Err(SourceStatus::Invalid));
            assert!(!valid_public_text(invalid));
        }
    }

    #[test]
    fn missing_and_malformed_sources_fail_closed_without_raw_errors() {
        let directory = tempdir().expect("create malformed hardware fixture");
        let roots = fixture_roots(directory.path());
        create_dir_all(
            roots
                .proc_cpuinfo
                .parent()
                .expect("fixture cpuinfo has a parent"),
        )
        .expect("create malformed proc fixture");
        create_dir_all(&roots.sys_pci).expect("create empty PCI fixture");
        create_dir_all(&roots.sys_usb).expect("create empty USB fixture");
        write(&roots.proc_cpuinfo, "processor : not-a-number\n").expect("write malformed cpuinfo");
        write(&roots.proc_meminfo, "MemTotal: secret bytes\n").expect("write malformed meminfo");
        let inventory = collect(&roots);
        assert_eq!(inventory.cpu.status, SourceStatus::Invalid);
        assert_eq!(inventory.memory.status, SourceStatus::Invalid);
        assert_eq!(inventory.firmware.status, SourceStatus::Partial);
        let json = to_bounded_json(&inventory).expect("serialize failed source statuses");
        assert!(!json.contains("not-a-number"));
        assert!(!json.contains("secret"));
    }

    #[test]
    fn device_identity_is_sorted_deduplicated_and_has_no_bus_addresses() {
        let directory = tempdir().expect("create duplicate-device fixture");
        let roots = healthy_fixture(directory.path());
        let second = roots.sys_pci.join("0000:00:03.0");
        create_dir_all(&second).expect("create duplicate PCI device");
        write(second.join("class"), "0x030000\n").expect("write duplicate PCI class");
        write(second.join("vendor"), "0x1234\n").expect("write duplicate PCI vendor");
        write(second.join("device"), "0x1111\n").expect("write duplicate PCI device");
        let inventory = collect(&roots);
        assert_eq!(inventory.pci.devices.len(), 1);
        assert_eq!(inventory.pci.devices[0].count, 2);
        let json = to_bounded_json(&inventory).expect("serialize deduplicated inventory");
        assert!(!json.contains("0000:00:03.0"));
    }

    #[test]
    fn device_attribute_failures_preserve_the_strongest_closed_status() {
        let directory = tempdir().expect("create malformed-device fixture");
        let roots = healthy_fixture(directory.path());
        write(roots.sys_pci.join("0000:00:02.0/class"), "not-hex\n")
            .expect("write invalid PCI class");
        write(
            roots.sys_usb.join("1-1/idProduct"),
            vec![b'x'; MAX_ATTRIBUTE_BYTES + 1],
        )
        .expect("write oversized USB product");
        let inventory = collect(&roots);
        assert_eq!(inventory.pci.status, SourceStatus::Invalid);
        assert!(inventory.pci.devices.is_empty());
        assert_eq!(inventory.usb.status, SourceStatus::Truncated);
        assert!(inventory.usb.devices.is_empty());
    }

    #[test]
    fn oversized_proc_source_is_reported_without_retaining_content() {
        let directory = tempdir().expect("create oversized-source fixture");
        let roots = fixture_roots(directory.path());
        create_dir_all(
            roots
                .proc_cpuinfo
                .parent()
                .expect("fixture cpuinfo has a parent"),
        )
        .expect("create oversized proc fixture");
        create_dir_all(&roots.sys_pci).expect("create empty PCI fixture");
        create_dir_all(&roots.sys_usb).expect("create empty USB fixture");
        write(&roots.proc_cpuinfo, vec![b'x'; MAX_PROC_BYTES + 1])
            .expect("write oversized cpuinfo");
        write(&roots.proc_meminfo, "MemTotal: 1 kB\n").expect("write meminfo fixture");
        let inventory = collect(&roots);
        assert_eq!(inventory.cpu.status, SourceStatus::Truncated);
        assert!(inventory.cpu.models.is_empty());
    }

    #[test]
    fn impossible_core_values_do_not_claim_complete_status() {
        let directory = tempdir().expect("create invalid-core fixture");
        let roots = healthy_fixture(directory.path());
        write(&roots.proc_meminfo, "MemTotal: 0 kB\n").expect("write zero memory fixture");
        let processors = (0..=MAX_LOGICAL_PROCESSORS)
            .map(|processor| format!("processor : {processor}\n"))
            .collect::<String>();
        write(&roots.proc_cpuinfo, processors).expect("write oversized CPU-count fixture");
        let inventory = collect(&roots);
        assert_eq!(inventory.cpu.status, SourceStatus::Invalid);
        assert_eq!(inventory.cpu.logical_processors, None);
        assert_eq!(inventory.memory.status, SourceStatus::Invalid);
        assert_eq!(inventory.memory.total_bytes, None);
    }

    #[test]
    fn oversized_device_directories_fail_closed_without_unbounded_output() {
        let directory = tempdir().expect("create oversized-device fixture");
        let roots = healthy_fixture(directory.path());
        for index in 0..MAX_DEVICE_ENTRIES {
            create_dir_all(roots.sys_pci.join(format!("extra-{index:03}")))
                .expect("create extra PCI entry");
        }
        let inventory = collect(&roots);
        assert_eq!(inventory.pci.status, SourceStatus::Truncated);
        assert!(inventory.pci.devices.is_empty());
    }
}
