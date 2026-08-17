//! Fixed, read-only macOS Resident P0 collector contract.
//!
//! The native adapter captures only fixed command/file sources. This module
//! turns their bounded raw outputs into the eight allowlisted corpus
//! projections. No observed labels, paths, log messages, or update titles are
//! copied to the UI or to a diagnosis.

use kernaid_macos_pack::{
    EvidenceInput, MAX_INPUT_BYTES, parse_apfs, parse_events, parse_launchd, parse_network,
    parse_snapshots, parse_startup, parse_storage, parse_updates,
};
use plist::{Dictionary, Value as PlistValue};
use serde::Serialize;
use serde_json::Value;
use sha2::{Digest, Sha256};
#[cfg(target_os = "macos")]
use std::time::Duration;
use std::{
    collections::{BTreeMap, BTreeSet},
    io::Cursor,
};

pub const COLLECTORS: [&str; 8] = [
    "macos.storage.inventory",
    "macos.apfs.capacity",
    "macos.launchd.state",
    "macos.network.state",
    "macos.software-update.state",
    "macos.system-events.summary",
    "macos.startup.state",
    "macos.snapshots.inventory",
];

#[cfg(target_os = "macos")]
pub const SYSTEM_PROFILER: &str = "/usr/sbin/system_profiler";
#[cfg(target_os = "macos")]
pub const SYSTEM_PROFILER_ARGS: [&str; 4] = ["SPStorageDataType", "-json", "-detailLevel", "full"];
#[cfg(target_os = "macos")]
pub const SW_VERS: &str = "/usr/bin/sw_vers";
#[cfg(target_os = "macos")]
pub const SW_VERS_ARGS: [&str; 1] = ["-productVersion"];
#[cfg(target_os = "macos")]
pub const DISKUTIL: &str = "/usr/sbin/diskutil";
#[cfg(target_os = "macos")]
pub const APFS_LIST_ARGS: [&str; 3] = ["apfs", "list", "-plist"];
#[cfg(target_os = "macos")]
pub const ROOT_INFO_ARGS: [&str; 3] = ["info", "-plist", "/"];
#[cfg(target_os = "macos")]
pub const LAUNCHCTL: &str = "/bin/launchctl";
#[cfg(target_os = "macos")]
pub const LAUNCHCTL_ARGS: [&str; 1] = ["list"];
#[cfg(target_os = "macos")]
pub const SCUTIL: &str = "/usr/sbin/scutil";
#[cfg(target_os = "macos")]
pub const NWI_ARGS: [&str; 1] = ["--nwi"];
#[cfg(target_os = "macos")]
pub const DNS_ARGS: [&str; 1] = ["--dns"];
#[cfg(target_os = "macos")]
pub const ROUTE: &str = "/sbin/route";
#[cfg(target_os = "macos")]
pub const ROUTE_ARGS: [&str; 3] = ["-n", "get", "default"];
#[cfg(target_os = "macos")]
pub const SYSCTL: &str = "/usr/sbin/sysctl";
#[cfg(target_os = "macos")]
// Apple XNU exposes KERN_SAFEBOOT as a locked, read-only integer sysctl.
pub const SAFE_BOOT_ARGS: [&str; 2] = ["-n", "kern.safeboot"];
#[cfg(target_os = "macos")]
pub const TMUTIL: &str = "/usr/bin/tmutil";
#[cfg(target_os = "macos")]
pub const SNAPSHOT_ARGS: [&str; 2] = ["listlocalsnapshotdates", "/"];

#[cfg(target_os = "macos")]
pub const STANDARD_TIMEOUT: Duration = Duration::from_secs(30);
#[cfg(target_os = "macos")]
pub const STORAGE_TIMEOUT: Duration = Duration::from_secs(60);
#[cfg(target_os = "macos")]
pub const P0_WALL_CLOCK_BUDGET: Duration = Duration::from_secs(90);

const PROJECTION_SCHEMA: &str = "1.0";
const MAX_RAW_RECORDS: usize = 4096;

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "camelCase")]
struct StorageDeviceProjection {
    internal: bool,
    solid_state: bool,
    smart_status: &'static str,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct StorageProjection {
    schema_version: &'static str,
    query_complete: bool,
    devices: Vec<StorageDeviceProjection>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct RootDataVolumeProjection {
    capacity_bytes: u64,
    free_bytes: u64,
    purgeable_bytes: u64,
    file_vault: &'static str,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct ApfsProjection {
    schema_version: &'static str,
    query_complete: bool,
    container_count: u32,
    root_data_volume: RootDataVolumeProjection,
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "camelCase")]
struct LaunchdServiceProjection {
    scope: &'static str,
    state: &'static str,
    last_exit_status: Option<i32>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct LaunchdProjection {
    schema_version: &'static str,
    query_complete: bool,
    user_query_state: &'static str,
    system_query_state: &'static str,
    services: Vec<LaunchdServiceProjection>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct NetworkProjection {
    schema_version: &'static str,
    query_complete: bool,
    active_interfaces: u16,
    default_route_present: bool,
    dns_servers: u16,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct UpdatesProjection {
    schema_version: &'static str,
    query_complete: bool,
    execution_state: &'static str,
    query_state: &'static str,
    pending: [(); 0],
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct EventsProjection {
    schema_version: &'static str,
    query_complete: bool,
    execution_state: &'static str,
    query_state: &'static str,
    window_hours: Option<u16>,
    kernel_panics: Option<u32>,
    watchdog_reboots: Option<u32>,
    repeated_app_crashes: Option<u32>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct StartupProjection {
    schema_version: &'static str,
    query_complete: bool,
    safe_mode_query_state: &'static str,
    login_items_query_state: &'static str,
    background_items_query_state: &'static str,
    safe_mode: bool,
    third_party_login_items_enabled: Option<u16>,
    background_items_blocked: Option<u16>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct SnapshotsProjection {
    schema_version: &'static str,
    query_complete: bool,
    local_snapshots: u32,
    oldest_age_hours: Option<u32>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct StorageIdentityProjection {
    schema_version: &'static str,
    source: &'static str,
    identity_sha256: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct SystemProjection<'a> {
    schema_version: &'static str,
    os_family: &'static str,
    product_version: &'a str,
}

fn encode(projection: &impl Serialize) -> Result<String, ()> {
    let encoded = serde_json::to_string(projection).map_err(|_| ())?;
    if encoded.len() > MAX_INPUT_BYTES {
        return Err(());
    }
    Ok(encoded)
}

fn object(value: &Value) -> Result<&serde_json::Map<String, Value>, ()> {
    value.as_object().ok_or(())
}

fn bounded_identity_value(value: &Value) -> Result<&str, ()> {
    let value = value.as_str().ok_or(())?;
    if value.is_empty() || value.len() > 512 || value.chars().any(char::is_control) {
        return Err(());
    }
    Ok(value)
}

#[cfg(test)]
pub fn storage_shape_summary(raw: &str) -> String {
    fn kind(value: Option<&Value>) -> &'static str {
        match value {
            None => "missing",
            Some(Value::Null) => "null",
            Some(Value::Bool(_)) => "bool",
            Some(Value::Number(_)) => "number",
            Some(Value::String(_)) => "string",
            Some(Value::Array(_)) => "array",
            Some(Value::Object(_)) => "object",
        }
    }

    fn safe_keys(value: Option<&Value>) -> Vec<String> {
        let Some(Value::Object(object)) = value else {
            return Vec::new();
        };
        let mut keys = object
            .keys()
            .filter(|key| {
                !key.is_empty()
                    && key.len() <= 64
                    && key
                        .bytes()
                        .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-'))
            })
            .take(64)
            .cloned()
            .collect::<Vec<_>>();
        keys.sort();
        keys
    }

    let Ok(root) = serde_json::from_str::<Value>(raw) else {
        return "root=invalid-json".to_owned();
    };
    let records = root
        .as_object()
        .and_then(|object| object.get("SPStorageDataType"));
    let first = records
        .and_then(Value::as_array)
        .and_then(|records| records.first());
    let physical = first
        .and_then(Value::as_object)
        .and_then(|record| record.get("physical_drive"));
    let record_shapes = records
        .and_then(Value::as_array)
        .map(|records| {
            records
                .iter()
                .take(16)
                .map(|record| {
                    let physical = record
                        .as_object()
                        .and_then(|record| record.get("physical_drive"));
                    let internal = physical
                        .and_then(Value::as_object)
                        .and_then(|physical| physical.get("is_internal_disk"));
                    let medium = physical
                        .and_then(Value::as_object)
                        .and_then(|physical| physical.get("medium_type"));
                    let smart = physical
                        .and_then(Value::as_object)
                        .and_then(|physical| physical.get("smart_status"));
                    let internal_class = match internal {
                        Some(Value::Bool(_)) => "bool",
                        Some(Value::String(value)) if value.eq_ignore_ascii_case("yes") => "yes",
                        Some(Value::String(value)) if value.eq_ignore_ascii_case("no") => "no",
                        Some(Value::String(_)) => "unknown-string",
                        Some(_) => "wrong-type",
                        None => "missing",
                    };
                    let medium_class = match medium {
                        Some(Value::String(value))
                            if matches!(
                                value.trim().to_ascii_lowercase().as_str(),
                                "ssd" | "solid state" | "solid_state"
                            ) =>
                        {
                            "solid-state"
                        }
                        Some(Value::String(value))
                            if matches!(
                                value.trim().to_ascii_lowercase().as_str(),
                                "hdd" | "rotational" | "rotating"
                            ) =>
                        {
                            "rotational"
                        }
                        Some(Value::String(_)) => "unknown-string",
                        Some(_) => "wrong-type",
                        None => "missing",
                    };
                    let smart_class = match smart {
                        None | Some(Value::Null) => "missing-or-null",
                        Some(Value::String(value))
                            if matches!(
                                value.trim().to_ascii_lowercase().as_str(),
                                "verified" | "failing" | "unsupported" | "not supported"
                            ) =>
                        {
                            "known"
                        }
                        Some(Value::String(_)) => "unknown-string",
                        Some(_) => "wrong-type",
                    };
                    format!(
                        "record={};keys={:?};physical={};physicalKeys={:?};internal={internal_class};medium={medium_class};smart={smart_class}",
                        kind(Some(record)),
                        safe_keys(Some(record)),
                        kind(physical),
                        safe_keys(physical),
                    )
                })
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();
    format!(
        "root={};rootKeys={:?};records={};recordCount={};first={};firstKeys={:?};physical={};physicalKeys={:?};recordShapes={record_shapes:?}",
        kind(Some(&root)),
        safe_keys(Some(&root)),
        kind(records),
        records.and_then(Value::as_array).map_or(0, Vec::len),
        kind(first),
        safe_keys(first),
        kind(physical),
        safe_keys(physical),
    )
}

#[cfg(test)]
pub fn launchd_shape_summary(raw: &str) -> String {
    let mut lines = raw.lines();
    let header = lines.next();
    let mut rows = 0_usize;
    let mut field_counts = BTreeMap::<usize, usize>::new();
    let mut pid_classes = BTreeMap::<&'static str, usize>::new();
    let mut status_classes = BTreeMap::<&'static str, usize>::new();
    let mut invalid_labels = 0_usize;
    for line in lines {
        rows += 1;
        let fields = line.split('\t').collect::<Vec<_>>();
        *field_counts.entry(fields.len()).or_default() += 1;
        let pid_class = match fields.first() {
            Some(&"-") => "dash",
            Some(value) if value.parse::<u32>().is_ok_and(|value| value > 0) => "positive-u32",
            Some(_) => "other",
            None => "missing",
        };
        *pid_classes.entry(pid_class).or_default() += 1;
        let status_class = match fields.get(1) {
            Some(&"-") => "dash",
            Some(value) if value.parse::<i32>().is_ok() => "i32",
            Some(_) => "other",
            None => "missing",
        };
        *status_classes.entry(status_class).or_default() += 1;
        if fields.get(2).is_none_or(|label| {
            label.is_empty() || label.len() > 512 || label.chars().any(char::is_control)
        }) {
            invalid_labels += 1;
        }
    }
    format!(
        "headerExact={};headerLength={};headerTabs={};rows={rows};fieldCounts={field_counts:?};pidClasses={pid_classes:?};statusClasses={status_classes:?};invalidLabels={invalid_labels}",
        header == Some("PID\tStatus\tLabel"),
        header.map_or(0, str::len),
        header.map_or(0, |header| header
            .bytes()
            .filter(|byte| *byte == b'\t')
            .count()),
    )
}

#[cfg(test)]
pub fn snapshot_shape_summary(raw: &str) -> String {
    let mut lines = raw.lines();
    let header = lines.next();
    let mut rows = 0_usize;
    let mut blanks = 0_usize;
    let mut date_shapes = 0_usize;
    let mut other_shapes = 0_usize;
    for line in lines {
        rows += 1;
        if line.is_empty() {
            blanks += 1;
        } else if line.len() == 17
            && line.as_bytes().get(4) == Some(&b'-')
            && line.as_bytes().get(7) == Some(&b'-')
            && line.as_bytes().get(10) == Some(&b'-')
        {
            date_shapes += 1;
        } else {
            other_shapes += 1;
        }
    }
    format!(
        "headerExact={};headerLength={};headerAscii={};rows={rows};blanks={blanks};dateShapes={date_shapes};otherShapes={other_shapes}",
        header == Some("Snapshot dates for all disks:"),
        header.map_or(0, str::len),
        header.is_some_and(str::is_ascii),
    )
}

fn yes_no(value: &Value) -> Result<bool, ()> {
    match value {
        Value::Bool(value) => Ok(*value),
        Value::String(value) if value.eq_ignore_ascii_case("yes") => Ok(true),
        Value::String(value) if value.eq_ignore_ascii_case("no") => Ok(false),
        _ => Err(()),
    }
}

fn storage_records(raw: &str) -> Result<(Vec<StorageDeviceProjection>, Vec<String>), ()> {
    let root: Value = serde_json::from_str(raw).map_err(|_| ())?;
    let records = object(&root)?
        .get("SPStorageDataType")
        .and_then(Value::as_array)
        .ok_or(())?;
    if records.is_empty() || records.len() > MAX_RAW_RECORDS {
        return Err(());
    }

    let mut devices = BTreeMap::new();
    let mut identity = BTreeSet::new();
    for record in records {
        let record = object(record)?;
        let physical = object(record.get("physical_drive").ok_or(())?)?;
        let internal = yes_no(physical.get("is_internal_disk").ok_or(())?)?;
        let medium = physical
            .get("medium_type")
            .and_then(Value::as_str)
            .ok_or(())?
            .trim()
            .to_ascii_lowercase();
        let solid_state = match medium.as_str() {
            "ssd" | "solid state" | "solid_state" => true,
            "hdd" | "rotational" | "rotating" => false,
            _ => return Err(()),
        };
        let smart_status = match physical.get("smart_status") {
            None | Some(Value::Null) => "unsupported",
            Some(Value::String(value)) if value.eq_ignore_ascii_case("verified") => "verified",
            Some(Value::String(value)) if value.eq_ignore_ascii_case("failing") => "failing",
            Some(Value::String(value))
                if value.eq_ignore_ascii_case("unsupported")
                    || value.eq_ignore_ascii_case("not supported") =>
            {
                "unsupported"
            }
            _ => return Err(()),
        };
        let projection = StorageDeviceProjection {
            internal,
            solid_state,
            smart_status,
        };

        let mut record_identity = Vec::new();
        let mut physical_identity = Vec::new();
        for (prefix, source, fields) in [
            ("volume", record, &["bsd_name", "volume_uuid"][..]),
            (
                "physical",
                physical,
                &["device_name", "media_name", "protocol", "serial_number"][..],
            ),
        ] {
            for field in fields {
                if let Some(value) = source.get(*field) {
                    let value = bounded_identity_value(value)?;
                    let token = format!("{prefix}.{field}={value}");
                    if prefix == "physical" {
                        physical_identity.push(token.clone());
                    }
                    record_identity.push(token);
                }
            }
        }
        if record_identity.is_empty() || physical_identity.is_empty() {
            return Err(());
        }
        let physical_key = physical_identity.join("\0");
        if devices
            .insert(physical_key, projection.clone())
            .is_some_and(|previous| previous != projection)
        {
            return Err(());
        }
        identity.extend(record_identity);
    }
    if devices.is_empty() || identity.is_empty() {
        return Err(());
    }
    Ok((
        devices.into_values().collect(),
        identity.into_iter().collect(),
    ))
}

pub fn normalize_system_version(raw: &str) -> Result<String, ()> {
    let version = raw.trim();
    if version.is_empty()
        || version.len() > 32
        || version.split('.').count() > 4
        || version.split('.').any(|part| {
            part.is_empty() || part.len() > 4 || !part.bytes().all(|byte| byte.is_ascii_digit())
        })
    {
        return Err(());
    }
    encode(&SystemProjection {
        schema_version: PROJECTION_SCHEMA,
        os_family: "macos",
        product_version: version,
    })
}

pub fn normalize_storage(raw: &str) -> Result<String, ()> {
    let (devices, _) = storage_records(raw)?;
    encode(&StorageProjection {
        schema_version: PROJECTION_SCHEMA,
        query_complete: true,
        devices,
    })
}

pub fn derive_storage_identity(raw: &str) -> Result<String, ()> {
    let (_, identity) = storage_records(raw)?;
    let mut hasher = Sha256::new();
    for item in identity {
        hasher.update((item.len() as u64).to_be_bytes());
        hasher.update(item.as_bytes());
    }
    encode(&StorageIdentityProjection {
        schema_version: PROJECTION_SCHEMA,
        source: "macos.storage.inventory",
        identity_sha256: format!("sha256:{:x}", hasher.finalize()),
    })
}

fn plist_dictionary(bytes: &[u8]) -> Result<Dictionary, ()> {
    PlistValue::from_reader(Cursor::new(bytes))
        .map_err(|_| ())?
        .into_dictionary()
        .ok_or(())
}

fn unsigned(dictionary: &Dictionary, names: &[&str]) -> Result<u64, ()> {
    names
        .iter()
        .find_map(|name| dictionary.get(name))
        .and_then(PlistValue::as_unsigned_integer)
        .ok_or(())
}

fn optional_unsigned(dictionary: &Dictionary, names: &[&str]) -> Result<Option<u64>, ()> {
    match names.iter().find_map(|name| dictionary.get(name)) {
        Some(value) => value.as_unsigned_integer().map(Some).ok_or(()),
        None => Ok(None),
    }
}

fn optional_bool(dictionary: &Dictionary, names: &[&str]) -> Result<Option<bool>, ()> {
    let mut observed = None;
    for name in names {
        let Some(value) = dictionary.get(name) else {
            continue;
        };
        let value = value.as_boolean().ok_or(())?;
        if observed.is_some_and(|previous| previous != value) {
            return Err(());
        }
        observed = Some(value);
    }
    Ok(observed)
}

fn dictionary_string<'a>(dictionary: &'a Dictionary, names: &[&str]) -> Option<&'a str> {
    names
        .iter()
        .find_map(|name| dictionary.get(name))
        .and_then(PlistValue::as_string)
}

pub fn normalize_apfs(apfs_list: &[u8], root_info: &[u8]) -> Result<String, ()> {
    let apfs = plist_dictionary(apfs_list)?;
    let root = plist_dictionary(root_info)?;
    let containers = apfs
        .get("Containers")
        .and_then(PlistValue::as_array)
        .ok_or(())?;
    if containers.is_empty() || containers.len() > MAX_RAW_RECORDS {
        return Err(());
    }
    let root_device = dictionary_string(&root, &["DeviceIdentifier"]);
    let root_container = dictionary_string(
        &root,
        &[
            "APFSContainerReference",
            "ContainerReference",
            "ParentWholeDisk",
        ],
    );
    let mut selected = None;
    let mut selected_volume = None;
    for value in containers {
        let container = value.as_dictionary().ok_or(())?;
        let reference = dictionary_string(container, &["ContainerReference"]);
        let volumes = container
            .get("Volumes")
            .and_then(PlistValue::as_array)
            .ok_or(())?;
        if volumes.len() > MAX_RAW_RECORDS {
            return Err(());
        }
        let matching_volume = volumes.iter().find_map(|volume| {
            let volume = volume.as_dictionary()?;
            (dictionary_string(volume, &["DeviceIdentifier"]) == root_device).then_some(volume)
        });
        if (root_container.is_some() && root_container == reference) || matching_volume.is_some() {
            if selected.is_some() {
                return Err(());
            }
            selected = Some(container);
            selected_volume = matching_volume;
        }
    }
    if selected.is_none() && containers.len() == 1 {
        selected = containers[0].as_dictionary();
    }
    let selected = selected.ok_or(())?;
    let capacity = match optional_unsigned(&root, &["ContainerTotalSpace", "APFSContainerSize"])? {
        Some(value) => value,
        None => unsigned(selected, &["CapacityCeiling"])?,
    };
    let free = match optional_unsigned(&root, &["ContainerFreeSpace", "APFSContainerFree"])? {
        Some(value) => value,
        None => unsigned(selected, &["CapacityFree"])?,
    };
    let purgeable =
        optional_unsigned(&root, &["PurgeableSpace", "APFSPurgeableSpace"])?.unwrap_or(0);
    if capacity == 0 || free > capacity || purgeable > capacity {
        return Err(());
    }
    let root_file_vault = optional_bool(&root, &["FileVault", "FileVaultEnabled"])?;
    let volume_file_vault = match selected_volume {
        Some(volume) => optional_bool(volume, &["FileVault", "FileVaultEnabled"])?,
        None => None,
    };
    if root_file_vault.is_some()
        && volume_file_vault.is_some()
        && root_file_vault != volume_file_vault
    {
        return Err(());
    }
    let file_vault = root_file_vault
        .or(volume_file_vault)
        .map_or("unsupported", |enabled| if enabled { "on" } else { "off" });
    encode(&ApfsProjection {
        schema_version: PROJECTION_SCHEMA,
        query_complete: true,
        container_count: u32::try_from(containers.len()).map_err(|_| ())?,
        root_data_volume: RootDataVolumeProjection {
            capacity_bytes: capacity,
            free_bytes: free,
            purgeable_bytes: purgeable,
            file_vault,
        },
    })
}

pub fn normalize_launchd_user(raw: &str) -> Result<String, ()> {
    let mut services = Vec::new();
    let mut lines = raw.lines();
    let header = lines.next().ok_or(())?;
    if header != "PID\tStatus\tLabel" {
        return Err(());
    }
    for line in lines {
        let mut fields = line.split('\t');
        let (Some(pid), Some(status), Some(label), None) =
            (fields.next(), fields.next(), fields.next(), fields.next())
        else {
            return Err(());
        };
        let running = if pid == "-" {
            false
        } else {
            let pid = pid.parse::<u32>().map_err(|_| ())?;
            if pid == 0 {
                return Err(());
            }
            true
        };
        let exit_status = if status == "-" {
            None
        } else {
            Some(status.parse::<i32>().map_err(|_| ())?)
        };
        if running && exit_status.is_some() {
            return Err(());
        }
        if label.is_empty() || label.len() > 512 || label.chars().any(char::is_control) {
            return Err(());
        }
        let state = if running {
            "running"
        } else if exit_status.is_none_or(|status| status == 0) {
            "waiting"
        } else {
            "failed"
        };
        services.push(LaunchdServiceProjection {
            scope: "user",
            state,
            last_exit_status: exit_status,
        });
        if services.len() > MAX_RAW_RECORDS {
            return Err(());
        }
    }
    services.sort();
    encode(&LaunchdProjection {
        schema_version: PROJECTION_SCHEMA,
        query_complete: true,
        user_query_state: "complete",
        system_query_state: "not-run-unqualified",
        services,
    })
}

fn interface_token(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 32
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
}

pub fn normalize_network(nwi: &str, route_exit_code: i32, dns: &str) -> Result<String, ()> {
    if !nwi.contains("Network information") || !matches!(route_exit_code, 0 | 1) {
        return Err(());
    }
    let mut interfaces = BTreeSet::new();
    for line in nwi.lines() {
        let Some(values) = line.trim().strip_prefix("Network interfaces:") else {
            continue;
        };
        for interface in values.split_whitespace() {
            if !interface_token(interface) {
                return Err(());
            }
            if interface != "lo0" {
                interfaces.insert(interface);
            }
        }
    }
    let mut servers = BTreeSet::new();
    for line in dns.lines() {
        let line = line.trim();
        if !line.starts_with("nameserver[") {
            continue;
        }
        let (_, value) = line.split_once(':').ok_or(())?;
        let value = value.trim();
        if value.is_empty() || value.len() > 128 || value.chars().any(char::is_control) {
            return Err(());
        }
        servers.insert(value);
    }
    if interfaces.len() > 128 || servers.len() > 64 {
        return Err(());
    }
    let default_route_present = route_exit_code == 0;
    if interfaces.is_empty() && default_route_present {
        return Err(());
    }
    encode(&NetworkProjection {
        schema_version: PROJECTION_SCHEMA,
        query_complete: true,
        active_interfaces: u16::try_from(interfaces.len()).map_err(|_| ())?,
        default_route_present,
        dns_servers: u16::try_from(servers.len()).map_err(|_| ())?,
    })
}

pub fn updates_unqualified_projection() -> Result<String, ()> {
    encode(&UpdatesProjection {
        schema_version: PROJECTION_SCHEMA,
        query_complete: true,
        execution_state: "not-run-unqualified",
        query_state: "unavailable-stale-cache",
        pending: [],
    })
}

pub fn events_unqualified_projection() -> Result<String, ()> {
    encode(&EventsProjection {
        schema_version: PROJECTION_SCHEMA,
        query_complete: true,
        execution_state: "not-run-unqualified",
        query_state: "not-run-unqualified",
        window_hours: None,
        kernel_panics: None,
        watchdog_reboots: None,
        repeated_app_crashes: None,
    })
}

pub fn normalize_startup(safe_boot: &str) -> Result<String, ()> {
    let safe_mode = match safe_boot.trim() {
        "0" => false,
        "1" => true,
        _ => return Err(()),
    };
    encode(&StartupProjection {
        schema_version: PROJECTION_SCHEMA,
        query_complete: true,
        safe_mode_query_state: "complete",
        login_items_query_state: "not-run-unqualified",
        background_items_query_state: "not-run-unqualified",
        safe_mode,
        third_party_login_items_enabled: None,
        background_items_blocked: None,
    })
}

fn parse_decimal(bytes: &[u8]) -> Result<u32, ()> {
    if bytes.is_empty() || !bytes.iter().all(u8::is_ascii_digit) {
        return Err(());
    }
    std::str::from_utf8(bytes)
        .map_err(|_| ())?
        .parse::<u32>()
        .map_err(|_| ())
}

fn leap_year(year: u32) -> bool {
    year.is_multiple_of(4) && (!year.is_multiple_of(100) || year.is_multiple_of(400))
}

fn snapshot_epoch(line: &str) -> Result<Option<u64>, ()> {
    let bytes = line.as_bytes();
    if bytes.len() != 17 || bytes[4] != b'-' || bytes[7] != b'-' || bytes[10] != b'-' {
        return Ok(None);
    }
    let year = parse_decimal(&bytes[0..4])?;
    let month = parse_decimal(&bytes[5..7])?;
    let day = parse_decimal(&bytes[8..10])?;
    let hour = parse_decimal(&bytes[11..13])?;
    let minute = parse_decimal(&bytes[13..15])?;
    let second = parse_decimal(&bytes[15..17])?;
    let month_days = [31_u32, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31];
    if !(1970..=9999).contains(&year)
        || !(1..=12).contains(&month)
        || day == 0
        || day
            > month_days[usize::try_from(month - 1).map_err(|_| ())?]
                + u32::from(month == 2 && leap_year(year))
        || hour > 23
        || minute > 59
        || second > 59
    {
        return Err(());
    }
    let mut days = 0_u64;
    for candidate in 1970..year {
        days = days
            .checked_add(u64::from(365 + u32::from(leap_year(candidate))))
            .ok_or(())?;
    }
    for candidate in 1..month {
        days = days
            .checked_add(u64::from(
                month_days[usize::try_from(candidate - 1).map_err(|_| ())?]
                    + u32::from(candidate == 2 && leap_year(year)),
            ))
            .ok_or(())?;
    }
    days = days.checked_add(u64::from(day - 1)).ok_or(())?;
    let seconds = days
        .checked_mul(86_400)
        .and_then(|value| value.checked_add(u64::from(hour) * 3_600))
        .and_then(|value| value.checked_add(u64::from(minute) * 60))
        .and_then(|value| value.checked_add(u64::from(second)))
        .ok_or(())?;
    Ok(Some(seconds))
}

pub fn normalize_snapshots(raw: &str, now_epoch_seconds: u64) -> Result<String, ()> {
    let mut header_seen = false;
    let mut timestamps = Vec::new();
    for line in raw.lines() {
        if !header_seen {
            if line != "Snapshot dates for all disks:" {
                return Err(());
            }
            header_seen = true;
            continue;
        }
        let timestamp = snapshot_epoch(line)?.ok_or(())?;
        timestamps.push(timestamp);
        if timestamps.len() > 100_000 {
            return Err(());
        }
    }
    if !header_seen {
        return Err(());
    }
    let oldest_age_hours = timestamps
        .iter()
        .min()
        .map(|oldest| {
            if *oldest > now_epoch_seconds.saturating_add(300) {
                return Err(());
            }
            u32::try_from(now_epoch_seconds.saturating_sub(*oldest) / 3_600).map_err(|_| ())
        })
        .transpose()?;
    encode(&SnapshotsProjection {
        schema_version: PROJECTION_SCHEMA,
        query_complete: true,
        local_snapshots: u32::try_from(timestamps.len()).map_err(|_| ())?,
        oldest_age_hours,
    })
}

pub fn validate_projection(collector: &str, output: &str) -> Result<(), ()> {
    let input = EvidenceInput {
        id: "E-MACOS-NATIVE-PROJECTION",
        body: output.as_bytes(),
    };
    match collector {
        "macos.storage.inventory" => parse_storage(input).map(|_| ()).map_err(|_| ()),
        "macos.apfs.capacity" => parse_apfs(input).map(|_| ()).map_err(|_| ()),
        "macos.launchd.state" => parse_launchd(input).map(|_| ()).map_err(|_| ()),
        "macos.network.state" => parse_network(input).map(|_| ()).map_err(|_| ()),
        "macos.software-update.state" => parse_updates(input).map(|_| ()).map_err(|_| ()),
        "macos.system-events.summary" => parse_events(input).map(|_| ()).map_err(|_| ()),
        "macos.startup.state" => parse_startup(input).map(|_| ()).map_err(|_| ()),
        "macos.snapshots.inventory" => parse_snapshots(input).map(|_| ()).map_err(|_| ()),
        _ => Err(()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const STORAGE: &str = include_str!("../fixtures/macos/system-profiler-storage.json");
    const APFS: &[u8] = include_bytes!("../fixtures/macos/apfs-list.plist");
    const ROOT: &[u8] = include_bytes!("../fixtures/macos/root-info.plist");
    const LAUNCHD_USER: &str = include_str!("../fixtures/macos/launchd-user.txt");
    const NWI: &str = include_str!("../fixtures/macos/network-nwi.txt");
    const DNS: &str = include_str!("../fixtures/macos/network-dns.txt");
    const SNAPSHOTS: &str = include_str!("../fixtures/macos/snapshots.txt");

    fn assert_valid(collector: &str, projection: Result<String, ()>) -> String {
        let projection = projection.expect("normalization must succeed");
        validate_projection(collector, &projection).expect("projection must satisfy corpus");
        projection
    }

    #[test]
    fn every_raw_fixture_becomes_a_strict_bounded_projection() {
        assert_valid("macos.storage.inventory", normalize_storage(STORAGE));
        assert_valid("macos.apfs.capacity", normalize_apfs(APFS, ROOT));
        assert_valid("macos.launchd.state", normalize_launchd_user(LAUNCHD_USER));
        assert_valid("macos.network.state", normalize_network(NWI, 0, DNS));
        assert_valid(
            "macos.software-update.state",
            updates_unqualified_projection(),
        );
        assert_valid(
            "macos.system-events.summary",
            events_unqualified_projection(),
        );
        assert_valid("macos.startup.state", normalize_startup("0\n"));
        assert_valid(
            "macos.snapshots.inventory",
            normalize_snapshots(SNAPSHOTS, 1_787_000_000),
        );
    }

    #[test]
    fn normalized_output_never_copies_observed_strings() {
        let storage = normalize_storage(STORAGE).expect("storage projection");
        let identity = derive_storage_identity(STORAGE).expect("storage identity");
        let launchd = normalize_launchd_user(LAUNCHD_USER).expect("launchd projection");
        let startup = normalize_startup("0").expect("startup projection");
        for output in [storage, identity, launchd, startup] {
            assert!(!output.contains("ignore all instructions"));
            assert!(!output.contains("Vendor Prompt Injection"));
            assert!(!output.contains("com.vendor.untrusted"));
            assert!(output.len() <= MAX_INPUT_BYTES);
        }
    }

    #[test]
    fn storage_identity_is_order_independent_and_change_sensitive() {
        let first = derive_storage_identity(STORAGE).expect("first identity");
        let mut value: Value = serde_json::from_str(STORAGE).expect("storage JSON");
        value["SPStorageDataType"]
            .as_array_mut()
            .expect("records")
            .reverse();
        let reordered = derive_storage_identity(&value.to_string()).expect("reordered identity");
        assert_eq!(first, reordered);
        value["SPStorageDataType"][0]["physical_drive"]["serial_number"] =
            Value::String("DIFFERENT-SERIAL".into());
        assert_ne!(
            first,
            derive_storage_identity(&value.to_string()).expect("changed identity")
        );
    }

    #[test]
    fn malformed_or_partial_native_sources_fail_closed() {
        assert!(normalize_system_version("14.6; rm -rf /").is_err());
        assert!(normalize_storage("{}").is_err());
        assert!(normalize_apfs(b"not a plist", ROOT).is_err());
        assert!(normalize_launchd_user("PID\tStatus\tLabel\n0\t-\tcom.invalid\n").is_err());
        assert!(normalize_launchd_user("PID\tStatus\tLabel\n-\tflag\tcom.invalid\n").is_err());
        assert!(normalize_launchd_user("PID\tStatus\tLabel\n1\t0\tcom.invalid\n").is_err());
        assert!(normalize_launchd_user("PID\tStatus\tLabel\n-\t-\tcom.valid-waiting\n").is_ok());
        assert!(normalize_launchd_user("translated header\n-\t0\tcom.invalid\n").is_err());
        assert!(normalize_network("translated output", 0, DNS).is_err());
        assert!(normalize_startup("unknown").is_err());
        assert!(normalize_snapshots("2026-99-99-999999", 1_787_000_000).is_err());
        assert!(
            normalize_snapshots(
                "Snapshot dates for all disks:\n\n2026-08-10-120000",
                1_787_000_000
            )
            .is_err()
        );
        assert!(
            normalize_snapshots(
                "Snapshot dates for all disks:\n 2026-08-10-120000",
                1_787_000_000
            )
            .is_err()
        );
        assert!(
            normalize_snapshots(
                "Snapshot dates for all disks:\nformat changed",
                1_787_000_000
            )
            .is_err()
        );
    }

    #[test]
    fn system_and_snapshot_normalizers_are_locale_independent() {
        assert_eq!(
            normalize_system_version("15.6.1\n").expect("system version"),
            r#"{"schemaVersion":"1.0","osFamily":"macos","productVersion":"15.6.1"}"#
        );
        let projection =
            normalize_snapshots(SNAPSHOTS, 1_787_000_000).expect("snapshot projection");
        assert!(projection.contains(r#""localSnapshots":2"#));
        assert!(!projection.contains("Snapshot dates"));
    }

    #[test]
    fn explicitly_unqualified_sources_carry_typed_null_state() {
        let updates = updates_unqualified_projection().expect("updates limitation projection");
        assert!(updates.contains(r#""executionState":"not-run-unqualified""#));
        assert!(updates.contains(r#""queryState":"unavailable-stale-cache""#));
        assert!(updates.contains(r#""pending":[]"#));

        let events = events_unqualified_projection().expect("events limitation projection");
        assert!(events.contains(r#""queryState":"not-run-unqualified""#));
        assert!(events.contains(r#""kernelPanics":null"#));
        assert!(events.contains(r#""watchdogReboots":null"#));
        assert!(events.contains(r#""repeatedAppCrashes":null"#));

        let startup = normalize_startup("0").expect("startup limitation projection");
        assert!(startup.contains(r#""safeModeQueryState":"complete""#));
        assert!(startup.contains(r#""loginItemsQueryState":"not-run-unqualified""#));
        assert!(startup.contains(r#""backgroundItemsQueryState":"not-run-unqualified""#));
        assert!(startup.contains(r#""thirdPartyLoginItemsEnabled":null"#));
        assert!(startup.contains(r#""backgroundItemsBlocked":null"#));
    }
}
