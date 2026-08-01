//! Deterministic, read-only Linux P0 diagnostic corpus.
//!
//! This module parses already-collected bytes. It never spawns commands, opens
//! host paths, or mutates state. Every input is treated as untrusted and is
//! bounded before parsing. Parsed strings remain untrusted data and are never
//! interpolated into finding summaries or collector identifiers.

use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::{error::Error, fmt};

pub const CORPUS_VERSION: &str = "linux-p0.1";
pub const FINDING_SCHEMA_VERSION: &str = "1.0";
pub const MAX_INPUT_BYTES: usize = 1024 * 1024;
pub const MAX_LINE_BYTES: usize = 16 * 1024;
pub const MAX_RECORDS: usize = 4096;
pub const MAX_STRING_BYTES: usize = 1024;
pub const MAX_EVIDENCE_ID_BYTES: usize = 128;

#[derive(Clone, Copy)]
pub struct EvidenceInput<'a> {
    pub id: &'a str,
    pub body: &'a [u8],
}

#[derive(Clone, Copy)]
pub struct LinuxP0Inputs<'a> {
    pub lsblk_json: EvidenceInput<'a>,
    pub systemctl_failed: EvidenceInput<'a>,
    pub systemctl_unit_state: EvidenceInput<'a>,
    pub fstab: EvidenceInput<'a>,
    pub df: EvidenceInput<'a>,
    pub ip_link_json: EvidenceInput<'a>,
    pub ip_route_json: EvidenceInput<'a>,
    pub dpkg_audit: EvidenceInput<'a>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum EvidenceSource {
    LsblkJson,
    SystemctlFailed,
    SystemctlUnitState,
    Fstab,
    Df,
    IpLinkJson,
    IpRouteJson,
    DpkgAudit,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DiagnosticErrorKind {
    InvalidEvidenceId,
    DuplicateEvidenceId,
    InputTooLarge,
    InvalidUtf8,
    UnsafeControlCharacter,
    LineTooLong,
    TooManyRecords,
    StringTooLong,
    MalformedInput,
    ValueOutOfRange,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DiagnosticError {
    pub source: EvidenceSource,
    pub kind: DiagnosticErrorKind,
}

impl fmt::Display for DiagnosticError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self.kind {
            DiagnosticErrorKind::InvalidEvidenceId => "invalid diagnostic evidence identifier",
            DiagnosticErrorKind::DuplicateEvidenceId => {
                "diagnostic evidence identifiers must be unique"
            }
            DiagnosticErrorKind::InputTooLarge => "diagnostic input exceeds its byte limit",
            DiagnosticErrorKind::InvalidUtf8 => "diagnostic text input is not UTF-8",
            DiagnosticErrorKind::UnsafeControlCharacter => {
                "diagnostic text contains a forbidden control character"
            }
            DiagnosticErrorKind::LineTooLong => "diagnostic input line exceeds its byte limit",
            DiagnosticErrorKind::TooManyRecords => "diagnostic input has too many records",
            DiagnosticErrorKind::StringTooLong => "diagnostic string exceeds its byte limit",
            DiagnosticErrorKind::MalformedInput => "diagnostic input is malformed",
            DiagnosticErrorKind::ValueOutOfRange => "diagnostic value is out of range",
        })
    }
}

impl Error for DiagnosticError {}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    Low,
    Medium,
    High,
    Critical,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Finding {
    pub schema_version: String,
    pub rule_id: String,
    pub rule_version: u16,
    pub severity: Severity,
    pub evidence_ids: Vec<String>,
    pub summary: String,
    pub next_collector: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DiagnosticReport {
    pub corpus_version: String,
    pub evidence_ids: Vec<String>,
    pub findings: Vec<Finding>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BlockDevice {
    pub name: String,
    pub device_type: String,
    pub uuid: Option<String>,
    pub mountpoints: Vec<String>,
    pub read_only: bool,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BlockInventory {
    pub evidence_id: String,
    pub devices: Vec<BlockDevice>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FailedUnitSnapshot {
    pub evidence_id: String,
    pub failed_units: Vec<String>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UnitState {
    pub id: Option<String>,
    pub load_state: Option<String>,
    pub active_state: Option<String>,
    pub sub_state: Option<String>,
    pub system_state: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SystemdStateSnapshot {
    pub evidence_id: String,
    pub units: Vec<UnitState>,
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct FstabUuidReference {
    pub uuid: String,
    pub nofail: bool,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FstabSnapshot {
    pub evidence_id: String,
    pub uuid_references: Vec<FstabUuidReference>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FilesystemSpace {
    pub source: String,
    pub size_bytes: u64,
    pub used_bytes: u64,
    pub available_bytes: u64,
    pub use_percent: u8,
    pub mountpoint: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DfSnapshot {
    pub evidence_id: String,
    pub filesystems: Vec<FilesystemSpace>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NetworkLink {
    pub ifindex: u32,
    pub ifname: String,
    pub loopback: bool,
    pub operational: bool,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LinkSnapshot {
    pub evidence_id: String,
    pub links: Vec<NetworkLink>,
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct NetworkRoute {
    pub destination: String,
    pub device: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RouteSnapshot {
    pub evidence_id: String,
    pub routes: Vec<NetworkRoute>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DpkgAuditSnapshot {
    pub evidence_id: String,
    pub interrupted: bool,
}

struct ValidatedEvidence<'a> {
    id: String,
    body: &'a [u8],
    source: EvidenceSource,
}

fn diagnostic_error(source: EvidenceSource, kind: DiagnosticErrorKind) -> DiagnosticError {
    DiagnosticError { source, kind }
}

fn validate_evidence(
    input: EvidenceInput<'_>,
    source: EvidenceSource,
) -> Result<ValidatedEvidence<'_>, DiagnosticError> {
    if !valid_evidence_id(input.id) {
        return Err(diagnostic_error(
            source,
            DiagnosticErrorKind::InvalidEvidenceId,
        ));
    }
    if input.body.len() > MAX_INPUT_BYTES {
        return Err(diagnostic_error(source, DiagnosticErrorKind::InputTooLarge));
    }
    Ok(ValidatedEvidence {
        id: input.id.to_owned(),
        body: input.body,
        source,
    })
}

fn valid_evidence_id(value: &str) -> bool {
    let bytes = value.as_bytes();
    !bytes.is_empty()
        && bytes.len() <= MAX_EVIDENCE_ID_BYTES
        && bytes.first().is_some_and(u8::is_ascii_alphanumeric)
        && bytes
            .iter()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b':' | b'-'))
}

fn validated_text<'a>(evidence: &ValidatedEvidence<'a>) -> Result<&'a str, DiagnosticError> {
    let text = std::str::from_utf8(evidence.body)
        .map_err(|_| diagnostic_error(evidence.source, DiagnosticErrorKind::InvalidUtf8))?;
    if text
        .chars()
        .any(|character| character.is_control() && !matches!(character, '\n' | '\t'))
    {
        return Err(diagnostic_error(
            evidence.source,
            DiagnosticErrorKind::UnsafeControlCharacter,
        ));
    }
    let mut count = 0_usize;
    for line in text.split('\n') {
        count = count.saturating_add(1);
        if count > MAX_RECORDS {
            return Err(diagnostic_error(
                evidence.source,
                DiagnosticErrorKind::TooManyRecords,
            ));
        }
        if line.len() > MAX_LINE_BYTES {
            return Err(diagnostic_error(
                evidence.source,
                DiagnosticErrorKind::LineTooLong,
            ));
        }
    }
    Ok(text)
}

fn validate_string(
    source: EvidenceSource,
    value: &str,
    maximum: usize,
) -> Result<(), DiagnosticError> {
    if value.len() > maximum {
        return Err(diagnostic_error(source, DiagnosticErrorKind::StringTooLong));
    }
    if value.chars().any(char::is_control) {
        return Err(diagnostic_error(
            source,
            DiagnosticErrorKind::UnsafeControlCharacter,
        ));
    }
    Ok(())
}

fn validate_token<F>(
    source: EvidenceSource,
    value: &str,
    maximum: usize,
    allowed: F,
) -> Result<(), DiagnosticError>
where
    F: Fn(u8) -> bool,
{
    validate_string(source, value, maximum)?;
    if value.is_empty() || !value.bytes().all(allowed) {
        return Err(diagnostic_error(
            source,
            DiagnosticErrorKind::MalformedInput,
        ));
    }
    Ok(())
}

fn normalized_uuid(source: EvidenceSource, value: &str) -> Result<String, DiagnosticError> {
    validate_token(source, value, 128, |byte| {
        byte.is_ascii_alphanumeric() || byte == b'-'
    })?;
    Ok(value.to_ascii_lowercase())
}

#[derive(Deserialize)]
struct LsblkWire {
    blockdevices: Vec<BlockDeviceWire>,
}

#[derive(Deserialize)]
struct BlockDeviceWire {
    name: String,
    #[serde(rename = "type")]
    device_type: String,
    #[serde(default)]
    uuid: Option<String>,
    #[serde(default)]
    ro: BooleanWire,
    #[serde(default)]
    mountpoint: Option<String>,
    #[serde(default)]
    mountpoints: Vec<Option<String>>,
    #[serde(default)]
    children: Vec<BlockDeviceWire>,
}

#[derive(Deserialize)]
#[serde(untagged)]
enum BooleanWire {
    Boolean(bool),
    Integer(u8),
    Text(String),
}

impl Default for BooleanWire {
    fn default() -> Self {
        Self::Boolean(false)
    }
}

impl BooleanWire {
    fn decode(self, source: EvidenceSource) -> Result<bool, DiagnosticError> {
        match self {
            Self::Boolean(value) => Ok(value),
            Self::Integer(0) => Ok(false),
            Self::Integer(1) => Ok(true),
            Self::Text(value) if value.eq_ignore_ascii_case("false") || value == "0" => Ok(false),
            Self::Text(value) if value.eq_ignore_ascii_case("true") || value == "1" => Ok(true),
            Self::Integer(_) | Self::Text(_) => Err(diagnostic_error(
                source,
                DiagnosticErrorKind::ValueOutOfRange,
            )),
        }
    }
}

pub fn parse_lsblk_json(input: EvidenceInput<'_>) -> Result<BlockInventory, DiagnosticError> {
    let evidence = validate_evidence(input, EvidenceSource::LsblkJson)?;
    let wire: LsblkWire = serde_json::from_slice(evidence.body)
        .map_err(|_| diagnostic_error(evidence.source, DiagnosticErrorKind::MalformedInput))?;
    let mut pending = wire.blockdevices;
    let mut devices = Vec::new();
    while let Some(mut device) = pending.pop() {
        if devices.len().saturating_add(pending.len()) >= MAX_RECORDS {
            return Err(diagnostic_error(
                evidence.source,
                DiagnosticErrorKind::TooManyRecords,
            ));
        }
        pending.append(&mut device.children);
        validate_token(evidence.source, &device.name, 128, |byte| {
            byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'+' | b':' | b'-')
        })?;
        validate_token(evidence.source, &device.device_type, 32, |byte| {
            byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-')
        })?;
        let uuid = match device.uuid.as_deref().map(str::trim) {
            Some("") | None => None,
            Some(value) => Some(normalized_uuid(evidence.source, value)?),
        };
        let mut mountpoints = device.mountpoints.into_iter().flatten().collect::<Vec<_>>();
        if let Some(mountpoint) = device.mountpoint {
            mountpoints.push(mountpoint);
        }
        if mountpoints.len() > 64 {
            return Err(diagnostic_error(
                evidence.source,
                DiagnosticErrorKind::TooManyRecords,
            ));
        }
        for mountpoint in &mountpoints {
            validate_string(evidence.source, mountpoint, MAX_STRING_BYTES)?;
            if !mountpoint.starts_with('/') && mountpoint != "[SWAP]" {
                return Err(diagnostic_error(
                    evidence.source,
                    DiagnosticErrorKind::MalformedInput,
                ));
            }
        }
        mountpoints.sort();
        mountpoints.dedup();
        devices.push(BlockDevice {
            name: device.name,
            device_type: device.device_type,
            uuid,
            mountpoints,
            read_only: device.ro.decode(evidence.source)?,
        });
    }
    devices.sort_by(|left, right| {
        (&left.name, &left.device_type, &left.uuid, &left.mountpoints).cmp(&(
            &right.name,
            &right.device_type,
            &right.uuid,
            &right.mountpoints,
        ))
    });
    if devices.is_empty() {
        return Err(diagnostic_error(
            evidence.source,
            DiagnosticErrorKind::MalformedInput,
        ));
    }
    Ok(BlockInventory {
        evidence_id: evidence.id,
        devices,
    })
}

pub fn parse_systemctl_failed(
    input: EvidenceInput<'_>,
) -> Result<FailedUnitSnapshot, DiagnosticError> {
    let evidence = validate_evidence(input, EvidenceSource::SystemctlFailed)?;
    let text = validated_text(&evidence)?;
    let mut failed_units = Vec::new();
    let mut summary_count = None;
    for raw_line in text.lines() {
        let trimmed = raw_line.trim();
        if trimmed.is_empty() || trimmed == "UNIT LOAD ACTIVE SUB DESCRIPTION" {
            continue;
        }
        if let Some(count) = systemctl_summary_count(trimmed) {
            if summary_count.replace(count).is_some() {
                return Err(diagnostic_error(
                    evidence.source,
                    DiagnosticErrorKind::MalformedInput,
                ));
            }
            continue;
        }
        let line = trimmed
            .strip_prefix('●')
            .map(str::trim_start)
            .unwrap_or(trimmed);
        let fields = line.split_whitespace().collect::<Vec<_>>();
        if fields.len() < 4 {
            return Err(diagnostic_error(
                evidence.source,
                DiagnosticErrorKind::MalformedInput,
            ));
        }
        let unit = fields[0];
        validate_token(evidence.source, unit, 256, |byte| {
            byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b':' | b'@' | b'\\' | b'-')
        })?;
        for state in &fields[1..4] {
            validate_token(evidence.source, state, 64, |byte| {
                byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-')
            })?;
        }
        if !unit.contains('.') || (fields[2] != "failed" && fields[3] != "failed") {
            return Err(diagnostic_error(
                evidence.source,
                DiagnosticErrorKind::MalformedInput,
            ));
        }
        failed_units.push(unit.to_owned());
        if failed_units.len() > MAX_RECORDS {
            return Err(diagnostic_error(
                evidence.source,
                DiagnosticErrorKind::TooManyRecords,
            ));
        }
    }
    failed_units.sort();
    let original_length = failed_units.len();
    failed_units.dedup();
    if failed_units.len() != original_length
        || summary_count.is_some_and(|count| count != failed_units.len())
    {
        return Err(diagnostic_error(
            evidence.source,
            DiagnosticErrorKind::MalformedInput,
        ));
    }
    Ok(FailedUnitSnapshot {
        evidence_id: evidence.id,
        failed_units,
    })
}

fn systemctl_summary_count(line: &str) -> Option<usize> {
    let mut fields = line.split_whitespace();
    let (Some(count), Some(loaded), Some(units), Some(listed)) =
        (fields.next(), fields.next(), fields.next(), fields.next())
    else {
        return None;
    };
    if count.is_empty()
        || !count.bytes().all(|byte| byte.is_ascii_digit())
        || loaded != "loaded"
        || units != "units"
        || listed != "listed."
        || fields.next().is_some()
    {
        return None;
    }
    count.parse::<usize>().ok()
}

fn finish_unit_state(
    source: EvidenceSource,
    properties: &mut BTreeMap<String, String>,
    units: &mut Vec<UnitState>,
) -> Result<(), DiagnosticError> {
    if properties.is_empty() {
        return Ok(());
    }
    let recognized = ["Id", "LoadState", "ActiveState", "SubState", "SystemState"]
        .iter()
        .any(|key| properties.contains_key(*key));
    if !recognized {
        return Err(diagnostic_error(
            source,
            DiagnosticErrorKind::MalformedInput,
        ));
    }
    let id = properties.get("Id").cloned();
    if let Some(value) = &id {
        validate_token(source, value, 256, |byte| {
            byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b':' | b'@' | b'\\' | b'-')
        })?;
        if !value.contains('.') {
            return Err(diagnostic_error(
                source,
                DiagnosticErrorKind::MalformedInput,
            ));
        }
    }
    let load_state = properties.get("LoadState").cloned();
    let active_state = properties.get("ActiveState").cloned();
    let sub_state = properties.get("SubState").cloned();
    let system_state = properties.get("SystemState").cloned();
    for state in [&load_state, &active_state, &sub_state, &system_state]
        .into_iter()
        .flatten()
    {
        validate_token(source, state, 64, |byte| {
            byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-')
        })?;
    }
    if id.is_none()
        && (load_state.is_some() || active_state.is_some() || sub_state.is_some())
        && system_state.is_none()
    {
        return Err(diagnostic_error(
            source,
            DiagnosticErrorKind::MalformedInput,
        ));
    }
    units.push(UnitState {
        id,
        load_state,
        active_state,
        sub_state,
        system_state,
    });
    properties.clear();
    if units.len() > MAX_RECORDS {
        return Err(diagnostic_error(
            source,
            DiagnosticErrorKind::TooManyRecords,
        ));
    }
    Ok(())
}

pub fn parse_systemctl_unit_state(
    input: EvidenceInput<'_>,
) -> Result<SystemdStateSnapshot, DiagnosticError> {
    let evidence = validate_evidence(input, EvidenceSource::SystemctlUnitState)?;
    let text = validated_text(&evidence)?;
    let mut properties = BTreeMap::new();
    let mut units = Vec::new();
    for line in text.lines() {
        if line.trim().is_empty() {
            finish_unit_state(evidence.source, &mut properties, &mut units)?;
            continue;
        }
        let Some((key, value)) = line.split_once('=') else {
            return Err(diagnostic_error(
                evidence.source,
                DiagnosticErrorKind::MalformedInput,
            ));
        };
        validate_token(evidence.source, key, 64, |byte| {
            byte.is_ascii_alphanumeric()
        })?;
        validate_string(evidence.source, value, MAX_STRING_BYTES)?;
        if properties
            .insert(key.to_owned(), value.to_owned())
            .is_some()
        {
            return Err(diagnostic_error(
                evidence.source,
                DiagnosticErrorKind::MalformedInput,
            ));
        }
    }
    finish_unit_state(evidence.source, &mut properties, &mut units)?;
    if units.is_empty() {
        return Err(diagnostic_error(
            evidence.source,
            DiagnosticErrorKind::MalformedInput,
        ));
    }
    units.sort_by(|left, right| {
        (
            &left.id,
            &left.system_state,
            &left.load_state,
            &left.active_state,
            &left.sub_state,
        )
            .cmp(&(
                &right.id,
                &right.system_state,
                &right.load_state,
                &right.active_state,
                &right.sub_state,
            ))
    });
    Ok(SystemdStateSnapshot {
        evidence_id: evidence.id,
        units,
    })
}

fn decode_fstab_field(source: EvidenceSource, field: &[u8]) -> Result<String, DiagnosticError> {
    let mut decoded = Vec::with_capacity(field.len());
    let mut cursor = 0_usize;
    while cursor < field.len() {
        if field[cursor] == b'\\' {
            if cursor + 3 >= field.len()
                || !field[cursor + 1..=cursor + 3]
                    .iter()
                    .all(|digit| matches!(digit, b'0'..=b'7'))
            {
                return Err(diagnostic_error(
                    source,
                    DiagnosticErrorKind::MalformedInput,
                ));
            }
            let value = u16::from(field[cursor + 1] - b'0') * 64
                + u16::from(field[cursor + 2] - b'0') * 8
                + u16::from(field[cursor + 3] - b'0');
            decoded.push(
                u8::try_from(value)
                    .map_err(|_| diagnostic_error(source, DiagnosticErrorKind::ValueOutOfRange))?,
            );
            cursor += 4;
        } else {
            decoded.push(field[cursor]);
            cursor += 1;
        }
    }
    let decoded = String::from_utf8(decoded)
        .map_err(|_| diagnostic_error(source, DiagnosticErrorKind::InvalidUtf8))?;
    validate_string(source, &decoded, MAX_STRING_BYTES)?;
    Ok(decoded)
}

pub fn parse_fstab(input: EvidenceInput<'_>) -> Result<FstabSnapshot, DiagnosticError> {
    let evidence = validate_evidence(input, EvidenceSource::Fstab)?;
    let text = validated_text(&evidence)?;
    let mut references = Vec::new();
    for line in text.lines() {
        let trimmed = line.trim_start();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        let mut fields = Vec::new();
        for raw_field in trimmed.split_ascii_whitespace() {
            if raw_field.starts_with('#') {
                break;
            }
            fields.push(decode_fstab_field(evidence.source, raw_field.as_bytes())?);
            if fields.len() > 6 {
                return Err(diagnostic_error(
                    evidence.source,
                    DiagnosticErrorKind::MalformedInput,
                ));
            }
        }
        if !(4..=6).contains(&fields.len()) {
            return Err(diagnostic_error(
                evidence.source,
                DiagnosticErrorKind::MalformedInput,
            ));
        }
        for numeric in fields.iter().skip(4) {
            numeric.parse::<u32>().map_err(|_| {
                diagnostic_error(evidence.source, DiagnosticErrorKind::MalformedInput)
            })?;
        }
        if let Some(uuid) = fields[0].strip_prefix("UUID=") {
            references.push(FstabUuidReference {
                uuid: normalized_uuid(evidence.source, uuid)?,
                nofail: fields[3].split(',').any(|option| option == "nofail"),
            });
        }
        if references.len() > MAX_RECORDS {
            return Err(diagnostic_error(
                evidence.source,
                DiagnosticErrorKind::TooManyRecords,
            ));
        }
    }
    references.sort();
    references.dedup();
    Ok(FstabSnapshot {
        evidence_id: evidence.id,
        uuid_references: references,
    })
}

pub fn parse_df(input: EvidenceInput<'_>) -> Result<DfSnapshot, DiagnosticError> {
    let evidence = validate_evidence(input, EvidenceSource::Df)?;
    let text = validated_text(&evidence)?;
    let mut lines = text.lines().filter(|line| !line.trim().is_empty());
    let header = lines
        .next()
        .ok_or_else(|| diagnostic_error(evidence.source, DiagnosticErrorKind::MalformedInput))?;
    if header.split_whitespace().next() != Some("Filesystem") {
        return Err(diagnostic_error(
            evidence.source,
            DiagnosticErrorKind::MalformedInput,
        ));
    }
    let mut filesystems = Vec::new();
    for line in lines {
        let fields = line.split_whitespace().collect::<Vec<_>>();
        if fields.len() < 6 {
            return Err(diagnostic_error(
                evidence.source,
                DiagnosticErrorKind::MalformedInput,
            ));
        }
        validate_string(evidence.source, fields[0], MAX_STRING_BYTES)?;
        let size_bytes = parse_u64(evidence.source, fields[1])?;
        let used_bytes = parse_u64(evidence.source, fields[2])?;
        let available_bytes = parse_u64(evidence.source, fields[3])?;
        if used_bytes > size_bytes || available_bytes > size_bytes {
            return Err(diagnostic_error(
                evidence.source,
                DiagnosticErrorKind::ValueOutOfRange,
            ));
        }
        let percent = fields[4].strip_suffix('%').ok_or_else(|| {
            diagnostic_error(evidence.source, DiagnosticErrorKind::MalformedInput)
        })?;
        let use_percent = percent
            .parse::<u8>()
            .map_err(|_| diagnostic_error(evidence.source, DiagnosticErrorKind::ValueOutOfRange))?;
        if use_percent > 100 {
            return Err(diagnostic_error(
                evidence.source,
                DiagnosticErrorKind::ValueOutOfRange,
            ));
        }
        let mountpoint = fields[5..].join(" ");
        validate_string(evidence.source, &mountpoint, MAX_STRING_BYTES)?;
        if !mountpoint.starts_with('/') {
            return Err(diagnostic_error(
                evidence.source,
                DiagnosticErrorKind::MalformedInput,
            ));
        }
        filesystems.push(FilesystemSpace {
            source: fields[0].to_owned(),
            size_bytes,
            used_bytes,
            available_bytes,
            use_percent,
            mountpoint,
        });
        if filesystems.len() > MAX_RECORDS {
            return Err(diagnostic_error(
                evidence.source,
                DiagnosticErrorKind::TooManyRecords,
            ));
        }
    }
    filesystems.sort_by(|left, right| {
        (&left.mountpoint, &left.source).cmp(&(&right.mountpoint, &right.source))
    });
    if filesystems.is_empty() {
        return Err(diagnostic_error(
            evidence.source,
            DiagnosticErrorKind::MalformedInput,
        ));
    }
    Ok(DfSnapshot {
        evidence_id: evidence.id,
        filesystems,
    })
}

fn parse_u64(source: EvidenceSource, value: &str) -> Result<u64, DiagnosticError> {
    value
        .parse::<u64>()
        .map_err(|_| diagnostic_error(source, DiagnosticErrorKind::ValueOutOfRange))
}

#[derive(Deserialize)]
struct LinkWire {
    ifindex: u64,
    ifname: String,
    #[serde(default)]
    flags: Vec<String>,
    #[serde(default)]
    operstate: Option<String>,
    #[serde(default)]
    link_type: Option<String>,
}

pub fn parse_ip_link_json(input: EvidenceInput<'_>) -> Result<LinkSnapshot, DiagnosticError> {
    let evidence = validate_evidence(input, EvidenceSource::IpLinkJson)?;
    let wires: Vec<LinkWire> = serde_json::from_slice(evidence.body)
        .map_err(|_| diagnostic_error(evidence.source, DiagnosticErrorKind::MalformedInput))?;
    if wires.len() > MAX_RECORDS {
        return Err(diagnostic_error(
            evidence.source,
            DiagnosticErrorKind::TooManyRecords,
        ));
    }
    let mut links = Vec::with_capacity(wires.len());
    for wire in wires {
        let ifindex = u32::try_from(wire.ifindex)
            .map_err(|_| diagnostic_error(evidence.source, DiagnosticErrorKind::ValueOutOfRange))?;
        validate_token(evidence.source, &wire.ifname, 64, |byte| {
            byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b':' | b'@' | b'-')
        })?;
        if wire.flags.len() > 64 {
            return Err(diagnostic_error(
                evidence.source,
                DiagnosticErrorKind::TooManyRecords,
            ));
        }
        for flag in &wire.flags {
            validate_token(evidence.source, flag, 64, |byte| {
                byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-')
            })?;
        }
        if let Some(operstate) = &wire.operstate {
            validate_token(evidence.source, operstate, 64, |byte| {
                byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-')
            })?;
        }
        if let Some(link_type) = &wire.link_type {
            validate_token(evidence.source, link_type, 64, |byte| {
                byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-')
            })?;
        }
        let loopback = wire.ifname == "lo"
            || wire.flags.iter().any(|flag| flag == "LOOPBACK")
            || wire.link_type.as_deref() == Some("loopback");
        let operational = match wire.operstate.as_deref() {
            Some("UP") => true,
            Some("DOWN" | "LOWERLAYERDOWN" | "NOTPRESENT") => false,
            Some(_) | None => wire.flags.iter().any(|flag| flag == "UP"),
        };
        links.push(NetworkLink {
            ifindex,
            ifname: wire.ifname,
            loopback,
            operational,
        });
    }
    links
        .sort_by(|left, right| (&left.ifindex, &left.ifname).cmp(&(&right.ifindex, &right.ifname)));
    Ok(LinkSnapshot {
        evidence_id: evidence.id,
        links,
    })
}

#[derive(Deserialize)]
struct RouteWire {
    dst: String,
    #[serde(default)]
    dev: Option<String>,
}

pub fn parse_ip_route_json(input: EvidenceInput<'_>) -> Result<RouteSnapshot, DiagnosticError> {
    let evidence = validate_evidence(input, EvidenceSource::IpRouteJson)?;
    let wires: Vec<RouteWire> = serde_json::from_slice(evidence.body)
        .map_err(|_| diagnostic_error(evidence.source, DiagnosticErrorKind::MalformedInput))?;
    if wires.len() > MAX_RECORDS {
        return Err(diagnostic_error(
            evidence.source,
            DiagnosticErrorKind::TooManyRecords,
        ));
    }
    let mut routes = Vec::with_capacity(wires.len());
    for wire in wires {
        validate_token(evidence.source, &wire.dst, 128, |byte| {
            byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b':' | b'/' | b'-')
        })?;
        if let Some(device) = &wire.dev {
            validate_token(evidence.source, device, 64, |byte| {
                byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b':' | b'@' | b'-')
            })?;
        }
        routes.push(NetworkRoute {
            destination: wire.dst,
            device: wire.dev,
        });
    }
    routes.sort();
    routes.dedup();
    Ok(RouteSnapshot {
        evidence_id: evidence.id,
        routes,
    })
}

pub fn parse_dpkg_audit(input: EvidenceInput<'_>) -> Result<DpkgAuditSnapshot, DiagnosticError> {
    let evidence = validate_evidence(input, EvidenceSource::DpkgAudit)?;
    let text = validated_text(&evidence)?;
    Ok(DpkgAuditSnapshot {
        evidence_id: evidence.id,
        interrupted: !text.trim().is_empty(),
    })
}

fn fixed_finding(
    rule_id: &str,
    severity: Severity,
    evidence_ids: &[&str],
    summary: &str,
    next_collector: &str,
) -> Finding {
    let mut bound_evidence = evidence_ids
        .iter()
        .map(|value| (*value).to_owned())
        .collect::<Vec<_>>();
    bound_evidence.sort();
    bound_evidence.dedup();
    Finding {
        schema_version: FINDING_SCHEMA_VERSION.to_owned(),
        rule_id: rule_id.to_owned(),
        rule_version: 1,
        severity,
        evidence_ids: bound_evidence,
        summary: summary.to_owned(),
        next_collector: next_collector.to_owned(),
    }
}

fn ensure_unique_evidence_ids(
    entries: &[(EvidenceSource, &str)],
) -> Result<Vec<String>, DiagnosticError> {
    let mut seen = BTreeSet::new();
    for (source, id) in entries {
        if !seen.insert((*id).to_owned()) {
            return Err(diagnostic_error(
                *source,
                DiagnosticErrorKind::DuplicateEvidenceId,
            ));
        }
    }
    Ok(seen.into_iter().collect())
}

/// Parse all required P0 evidence and evaluate the versioned rule corpus.
///
/// A malformed source fails the whole evaluation. This avoids presenting a
/// healthy result assembled from partial or attacker-controlled evidence.
pub fn diagnose_linux_p0(inputs: LinuxP0Inputs<'_>) -> Result<DiagnosticReport, DiagnosticError> {
    let lsblk = parse_lsblk_json(inputs.lsblk_json)?;
    let failed_units = parse_systemctl_failed(inputs.systemctl_failed)?;
    let unit_state = parse_systemctl_unit_state(inputs.systemctl_unit_state)?;
    let fstab = parse_fstab(inputs.fstab)?;
    let df = parse_df(inputs.df)?;
    let links = parse_ip_link_json(inputs.ip_link_json)?;
    let routes = parse_ip_route_json(inputs.ip_route_json)?;
    let dpkg = parse_dpkg_audit(inputs.dpkg_audit)?;

    let evidence_ids = ensure_unique_evidence_ids(&[
        (EvidenceSource::LsblkJson, &lsblk.evidence_id),
        (EvidenceSource::SystemctlFailed, &failed_units.evidence_id),
        (EvidenceSource::SystemctlUnitState, &unit_state.evidence_id),
        (EvidenceSource::Fstab, &fstab.evidence_id),
        (EvidenceSource::Df, &df.evidence_id),
        (EvidenceSource::IpLinkJson, &links.evidence_id),
        (EvidenceSource::IpRouteJson, &routes.evidence_id),
        (EvidenceSource::DpkgAudit, &dpkg.evidence_id),
    ])?;

    let mut findings = Vec::new();

    if !failed_units.failed_units.is_empty() {
        findings.push(fixed_finding(
            "KA-LNX-P0-001",
            Severity::High,
            &[&failed_units.evidence_id],
            "One or more systemd units are in the failed state.",
            "linux.systemd.failed-unit-detail.v1",
        ));
    }

    if unit_state.units.iter().any(|unit| {
        unit.system_state.as_deref() == Some("degraded")
            || unit.active_state.as_deref() == Some("failed")
            || matches!(unit.load_state.as_deref(), Some("error" | "not-found"))
    }) {
        findings.push(fixed_finding(
            "KA-LNX-P0-002",
            Severity::High,
            &[&unit_state.evidence_id],
            "Systemd manager or unit state is degraded.",
            "linux.systemd.manager-state.v1",
        ));
    }

    let observed_uuids = lsblk
        .devices
        .iter()
        .filter_map(|device| device.uuid.as_deref())
        .collect::<BTreeSet<_>>();
    if fstab
        .uuid_references
        .iter()
        .any(|reference| !observed_uuids.contains(reference.uuid.as_str()))
    {
        findings.push(fixed_finding(
            "KA-LNX-P0-003",
            Severity::High,
            &[&fstab.evidence_id, &lsblk.evidence_id],
            "An fstab UUID is absent from the observed block inventory.",
            "linux.block.uuid-detail.v1",
        ));
    }

    if lsblk.devices.iter().any(|device| {
        device.read_only
            && device
                .mountpoints
                .iter()
                .any(|mountpoint| mountpoint == "/")
    }) {
        findings.push(fixed_finding(
            "KA-LNX-P0-004",
            Severity::Critical,
            &[&lsblk.evidence_id],
            "The block device backing the root mount is read-only.",
            "linux.mount.root-state.v1",
        ));
    }

    let mut uuid_counts = BTreeMap::<&str, usize>::new();
    for uuid in lsblk
        .devices
        .iter()
        .filter_map(|device| device.uuid.as_deref())
    {
        let count = uuid_counts.entry(uuid).or_default();
        *count = count.saturating_add(1);
    }
    if uuid_counts.values().any(|count| *count > 1) {
        findings.push(fixed_finding(
            "KA-LNX-P0-005",
            Severity::High,
            &[&lsblk.evidence_id],
            "The block inventory contains a duplicate filesystem UUID.",
            "linux.blkid.inventory.v1",
        ));
    }

    if df
        .filesystems
        .iter()
        .any(|filesystem| filesystem.mountpoint == "/" && filesystem.use_percent >= 95)
    {
        findings.push(fixed_finding(
            "KA-LNX-P0-006",
            Severity::Critical,
            &[&df.evidence_id],
            "The root filesystem is critically low on free space.",
            "linux.disk-usage.top-level.v1",
        ));
    }

    if df
        .filesystems
        .iter()
        .any(|filesystem| filesystem.mountpoint != "/" && filesystem.use_percent >= 90)
    {
        findings.push(fixed_finding(
            "KA-LNX-P0-007",
            Severity::High,
            &[&df.evidence_id],
            "A non-root filesystem is low on free space.",
            "linux.disk-usage.top-level.v1",
        ));
    }

    let non_loopback = links
        .links
        .iter()
        .filter(|link| !link.loopback)
        .collect::<Vec<_>>();
    if non_loopback.is_empty() || !non_loopback.iter().any(|link| link.operational) {
        findings.push(fixed_finding(
            "KA-LNX-P0-008",
            Severity::Medium,
            &[&links.evidence_id],
            "No operational non-loopback network link was observed.",
            "linux.network.link-detail.v1",
        ));
    }

    let default_routes = routes
        .routes
        .iter()
        .filter(|route| route.destination == "default")
        .collect::<Vec<_>>();
    if default_routes.is_empty() {
        findings.push(fixed_finding(
            "KA-LNX-P0-009",
            Severity::Medium,
            &[&routes.evidence_id],
            "No default network route was observed.",
            "linux.network.route-detail.v1",
        ));
    }

    let operational_interfaces = links
        .links
        .iter()
        .filter(|link| !link.loopback && link.operational)
        .map(|link| link.ifname.as_str())
        .collect::<BTreeSet<_>>();
    if !operational_interfaces.is_empty()
        && default_routes.iter().any(|route| {
            route
                .device
                .as_deref()
                .is_some_and(|device| !operational_interfaces.contains(device))
        })
    {
        findings.push(fixed_finding(
            "KA-LNX-P0-010",
            Severity::High,
            &[&links.evidence_id, &routes.evidence_id],
            "A default route references a non-operational interface.",
            "linux.network.interface-route-correlation.v1",
        ));
    }

    if dpkg.interrupted {
        findings.push(fixed_finding(
            "KA-LNX-P0-011",
            Severity::High,
            &[&dpkg.evidence_id],
            "The dpkg audit reports interrupted or incomplete package state.",
            "linux.dpkg.audit-detail.v1",
        ));
    }

    findings.sort_by(|left, right| left.rule_id.cmp(&right.rule_id));
    Ok(DiagnosticReport {
        corpus_version: CORPUS_VERSION.to_owned(),
        evidence_ids,
        findings,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    const HEALTHY_LSBLK: &[u8] = include_bytes!("../fixtures/diagnostics/healthy/lsblk.json");
    const HEALTHY_FAILED: &[u8] =
        include_bytes!("../fixtures/diagnostics/healthy/systemctl-failed.txt");
    const HEALTHY_UNIT_STATE: &[u8] =
        include_bytes!("../fixtures/diagnostics/healthy/systemctl-unit-state.txt");
    const HEALTHY_FSTAB: &[u8] = include_bytes!("../fixtures/diagnostics/healthy/fstab");
    const HEALTHY_DF: &[u8] = include_bytes!("../fixtures/diagnostics/healthy/df.txt");
    const HEALTHY_LINK: &[u8] = include_bytes!("../fixtures/diagnostics/healthy/ip-link.json");
    const HEALTHY_ROUTE: &[u8] = include_bytes!("../fixtures/diagnostics/healthy/ip-route.json");
    const HEALTHY_DPKG: &[u8] = include_bytes!("../fixtures/diagnostics/healthy/dpkg-audit.txt");

    fn evidence<'a>(id: &'a str, body: &'a [u8]) -> EvidenceInput<'a> {
        EvidenceInput { id, body }
    }

    fn healthy_inputs() -> LinuxP0Inputs<'static> {
        LinuxP0Inputs {
            lsblk_json: evidence("EV-LINUX-LSBLK", HEALTHY_LSBLK),
            systemctl_failed: evidence("EV-LINUX-SYSTEMD-FAILED", HEALTHY_FAILED),
            systemctl_unit_state: evidence("EV-LINUX-SYSTEMD-STATE", HEALTHY_UNIT_STATE),
            fstab: evidence("EV-LINUX-FSTAB", HEALTHY_FSTAB),
            df: evidence("EV-LINUX-DF", HEALTHY_DF),
            ip_link_json: evidence("EV-LINUX-IP-LINK", HEALTHY_LINK),
            ip_route_json: evidence("EV-LINUX-IP-ROUTE", HEALTHY_ROUTE),
            dpkg_audit: evidence("EV-LINUX-DPKG", HEALTHY_DPKG),
        }
    }

    fn contains_rule(report: &DiagnosticReport, rule_id: &str) -> bool {
        report
            .findings
            .iter()
            .any(|finding| finding.rule_id == rule_id)
    }

    #[test]
    fn synthetic_healthy_fixture_has_no_findings() {
        let report = diagnose_linux_p0(healthy_inputs()).expect("diagnose healthy fixture");
        assert_eq!(report.corpus_version, CORPUS_VERSION);
        assert_eq!(report.evidence_ids.len(), 8);
        assert!(report.findings.is_empty());
    }

    #[test]
    fn incident_fixtures_cover_every_p0_rule() {
        let mut inputs = healthy_inputs();
        inputs.lsblk_json = evidence(
            "EV-LINUX-LSBLK",
            include_bytes!("../fixtures/diagnostics/incidents/lsblk-duplicate-uuid.json"),
        );
        let duplicate = diagnose_linux_p0(inputs).expect("diagnose duplicate UUID");
        assert!(contains_rule(&duplicate, "KA-LNX-P0-005"));

        let mut inputs = healthy_inputs();
        inputs.lsblk_json = evidence(
            "EV-LINUX-LSBLK",
            include_bytes!("../fixtures/diagnostics/incidents/lsblk-root-read-only.json"),
        );
        let read_only = diagnose_linux_p0(inputs).expect("diagnose read-only root");
        assert!(contains_rule(&read_only, "KA-LNX-P0-004"));

        let mut inputs = healthy_inputs();
        inputs.systemctl_failed = evidence(
            "EV-LINUX-SYSTEMD-FAILED",
            include_bytes!("../fixtures/diagnostics/incidents/systemctl-failed.txt"),
        );
        let failed = diagnose_linux_p0(inputs).expect("diagnose failed unit");
        assert!(contains_rule(&failed, "KA-LNX-P0-001"));

        let mut inputs = healthy_inputs();
        inputs.systemctl_unit_state = evidence(
            "EV-LINUX-SYSTEMD-STATE",
            include_bytes!("../fixtures/diagnostics/incidents/systemctl-degraded.txt"),
        );
        let degraded = diagnose_linux_p0(inputs).expect("diagnose degraded systemd");
        assert!(contains_rule(&degraded, "KA-LNX-P0-002"));

        let mut inputs = healthy_inputs();
        inputs.fstab = evidence(
            "EV-LINUX-FSTAB",
            include_bytes!("../fixtures/diagnostics/incidents/fstab-missing-uuid"),
        );
        let missing_uuid = diagnose_linux_p0(inputs).expect("diagnose missing fstab UUID");
        assert!(contains_rule(&missing_uuid, "KA-LNX-P0-003"));

        let mut inputs = healthy_inputs();
        inputs.df = evidence(
            "EV-LINUX-DF",
            include_bytes!("../fixtures/diagnostics/incidents/df-full.txt"),
        );
        let full = diagnose_linux_p0(inputs).expect("diagnose full filesystems");
        assert!(contains_rule(&full, "KA-LNX-P0-006"));
        assert!(contains_rule(&full, "KA-LNX-P0-007"));

        let mut inputs = healthy_inputs();
        inputs.ip_link_json = evidence(
            "EV-LINUX-IP-LINK",
            include_bytes!("../fixtures/diagnostics/incidents/ip-link-down.json"),
        );
        let link_down = diagnose_linux_p0(inputs).expect("diagnose down link");
        assert!(contains_rule(&link_down, "KA-LNX-P0-008"));

        let mut inputs = healthy_inputs();
        inputs.ip_route_json = evidence(
            "EV-LINUX-IP-ROUTE",
            include_bytes!("../fixtures/diagnostics/incidents/ip-route-missing.json"),
        );
        let missing_route = diagnose_linux_p0(inputs).expect("diagnose missing route");
        assert!(contains_rule(&missing_route, "KA-LNX-P0-009"));

        let mut inputs = healthy_inputs();
        inputs.ip_route_json = evidence(
            "EV-LINUX-IP-ROUTE",
            include_bytes!("../fixtures/diagnostics/incidents/ip-route-wrong-interface.json"),
        );
        let wrong_interface = diagnose_linux_p0(inputs).expect("diagnose wrong route interface");
        assert!(contains_rule(&wrong_interface, "KA-LNX-P0-010"));

        let mut inputs = healthy_inputs();
        inputs.dpkg_audit = evidence(
            "EV-LINUX-DPKG",
            include_bytes!("../fixtures/diagnostics/incidents/dpkg-interrupted.txt"),
        );
        let dpkg = diagnose_linux_p0(inputs).expect("diagnose interrupted dpkg");
        assert!(contains_rule(&dpkg, "KA-LNX-P0-011"));
    }

    #[test]
    fn findings_are_deterministic_across_collector_record_order() {
        let link_reordered = br#"[
          {"ifindex":2,"ifname":"eth0","flags":["LOWER_UP","UP","BROADCAST"],"operstate":"UP","link_type":"ether"},
          {"ifindex":1,"ifname":"lo","flags":["UP","LOOPBACK"],"operstate":"UNKNOWN","link_type":"loopback"}
        ]"#;
        let route_reordered = br#"[
          {"dst":"192.0.2.0/24","dev":"eth0"},
          {"dst":"default","dev":"eth0","gateway":"192.0.2.1"}
        ]"#;
        let first = diagnose_linux_p0(healthy_inputs()).expect("first report");
        let mut reordered = healthy_inputs();
        reordered.ip_link_json = evidence("EV-LINUX-IP-LINK", link_reordered);
        reordered.ip_route_json = evidence("EV-LINUX-IP-ROUTE", route_reordered);
        let second = diagnose_linux_p0(reordered).expect("reordered report");
        assert_eq!(first, second);
    }

    #[test]
    fn every_finding_is_bound_only_to_declared_evidence() {
        let mut inputs = healthy_inputs();
        inputs.fstab = evidence(
            "EV-LINUX-FSTAB",
            include_bytes!("../fixtures/diagnostics/incidents/fstab-missing-uuid"),
        );
        inputs.ip_route_json = evidence(
            "EV-LINUX-IP-ROUTE",
            include_bytes!("../fixtures/diagnostics/incidents/ip-route-wrong-interface.json"),
        );
        let report = diagnose_linux_p0(inputs).expect("diagnose bound findings");
        let declared = report.evidence_ids.iter().collect::<BTreeSet<_>>();
        for finding in &report.findings {
            assert!(!finding.evidence_ids.is_empty());
            assert!(finding.evidence_ids.iter().all(|id| declared.contains(id)));
        }
        let missing_uuid = report
            .findings
            .iter()
            .find(|finding| finding.rule_id == "KA-LNX-P0-003")
            .expect("missing UUID finding");
        assert_eq!(
            missing_uuid.evidence_ids,
            ["EV-LINUX-FSTAB", "EV-LINUX-LSBLK"]
        );
        let wrong_interface = report
            .findings
            .iter()
            .find(|finding| finding.rule_id == "KA-LNX-P0-010")
            .expect("wrong-interface finding");
        assert_eq!(
            wrong_interface.evidence_ids,
            ["EV-LINUX-IP-LINK", "EV-LINUX-IP-ROUTE"]
        );
    }

    #[test]
    fn prompt_injection_text_never_reaches_findings() {
        let mut inputs = healthy_inputs();
        inputs.systemctl_failed = evidence(
            "EV-LINUX-SYSTEMD-FAILED",
            include_bytes!("../fixtures/diagnostics/incidents/systemctl-failed.txt"),
        );
        inputs.fstab = evidence(
            "EV-LINUX-FSTAB",
            include_bytes!("../fixtures/diagnostics/incidents/fstab-missing-uuid"),
        );
        inputs.ip_link_json = evidence(
            "EV-LINUX-IP-LINK",
            include_bytes!("../fixtures/diagnostics/incidents/ip-link-down.json"),
        );
        inputs.dpkg_audit = evidence(
            "EV-LINUX-DPKG",
            include_bytes!("../fixtures/diagnostics/incidents/dpkg-interrupted.txt"),
        );
        let report = diagnose_linux_p0(inputs).expect("diagnose injected fixture");
        let serialized = serde_json::to_string(&report).expect("serialize report");
        assert!(!serialized.to_ascii_lowercase().contains("ignore previous"));
        assert!(report.findings.len() >= 4);
    }

    #[test]
    fn malformed_controls_and_invalid_ids_fail_closed() {
        let malformed = parse_lsblk_json(evidence(
            "EV-MALFORMED",
            include_bytes!("../fixtures/diagnostics/adversarial/malformed-lsblk.json"),
        ));
        assert!(matches!(
            malformed,
            Err(DiagnosticError {
                source: EvidenceSource::LsblkJson,
                kind: DiagnosticErrorKind::MalformedInput
            })
        ));

        let control = parse_systemctl_failed(evidence(
            "EV-CONTROL",
            include_bytes!("../fixtures/diagnostics/adversarial/control-systemctl.txt"),
        ));
        assert!(matches!(
            control,
            Err(DiagnosticError {
                source: EvidenceSource::SystemctlFailed,
                kind: DiagnosticErrorKind::UnsafeControlCharacter
            })
        ));

        let invalid_id = parse_dpkg_audit(evidence("IGNORE PREVIOUS", b""));
        assert!(matches!(
            invalid_id,
            Err(DiagnosticError {
                source: EvidenceSource::DpkgAudit,
                kind: DiagnosticErrorKind::InvalidEvidenceId
            })
        ));
    }

    #[test]
    fn byte_line_record_and_identifier_limits_are_enforced() {
        let oversized = vec![b'x'; MAX_INPUT_BYTES + 1];
        assert!(matches!(
            parse_dpkg_audit(evidence("EV-LIMIT-BYTES", &oversized)),
            Err(DiagnosticError {
                kind: DiagnosticErrorKind::InputTooLarge,
                ..
            })
        ));

        let long_line = vec![b'x'; MAX_LINE_BYTES + 1];
        assert!(matches!(
            parse_dpkg_audit(evidence("EV-LIMIT-LINE", &long_line)),
            Err(DiagnosticError {
                kind: DiagnosticErrorKind::LineTooLong,
                ..
            })
        ));

        let mut too_many = String::from("[");
        for index in 0..=MAX_RECORDS {
            if index > 0 {
                too_many.push(',');
            }
            too_many.push_str(&format!(
                "{{\"ifindex\":{},\"ifname\":\"v{}\"}}",
                index + 1,
                index + 1
            ));
        }
        too_many.push(']');
        assert!(too_many.len() < MAX_INPUT_BYTES);
        assert!(matches!(
            parse_ip_link_json(evidence("EV-LIMIT-RECORDS", too_many.as_bytes())),
            Err(DiagnosticError {
                kind: DiagnosticErrorKind::TooManyRecords,
                ..
            })
        ));

        let oversized_id = format!("E{}", "X".repeat(MAX_EVIDENCE_ID_BYTES));
        assert!(matches!(
            parse_dpkg_audit(evidence(&oversized_id, b"")),
            Err(DiagnosticError {
                kind: DiagnosticErrorKind::InvalidEvidenceId,
                ..
            })
        ));
    }

    #[test]
    fn duplicate_evidence_ids_are_rejected_before_reporting() {
        let mut inputs = healthy_inputs();
        inputs.df.id = inputs.fstab.id;
        assert!(matches!(
            diagnose_linux_p0(inputs),
            Err(DiagnosticError {
                source: EvidenceSource::Df,
                kind: DiagnosticErrorKind::DuplicateEvidenceId
            })
        ));
    }
}
