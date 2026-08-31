//! Pure, deterministic preview for one off-default Rescue `crypttab` repair.
//!
//! This module receives already collected bytes and a sealed UUID inventory.
//! It opens no path, spawns no process and performs no mutation. Raw mapper
//! names, UUIDs, key fields and configuration bytes never appear in `Debug`.

use sha2::{Digest, Sha256};
use std::{collections::BTreeSet, fmt};

const MAX_DOCUMENT_BYTES: usize = 1024 * 1024;
const MAX_LINE_BYTES: usize = 16 * 1024;
const MAX_FIELDS: usize = 6;
const MAX_OBSERVED_UUIDS: usize = 4096;
const MAX_UUID_BYTES: usize = 128;
const MAX_NAME_BYTES: usize = 128;
const COMMENT_PREFIX: &[u8] = b"# KernAid Rescue disabled missing crypttab UUID: ";
const UUID_SET_DOMAIN: &[u8] = b"kernaid:linux.crypttab.disable-missing-uuid.v1:uuid-set:v1\0";
const FSTAB_CONSUMER_DOMAIN: &[u8] =
    b"kernaid:linux.crypttab.disable-missing-uuid.v1:fstab-consumers:v1\0";
const DIFF_DOMAIN: &[u8] = b"kernaid:linux.crypttab.disable-missing-uuid.v1:diff:v1\0";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CrypttabPreviewError {
    InvalidCrypttabSize,
    InvalidFstabSize,
    MalformedCrypttab,
    MalformedFstab,
    TooManyObservedUuids,
    InvalidObservedUuid,
    AmbiguousObservedUuid,
    RepairNotApplicable,
    AmbiguousTarget,
    CriticalMapping,
    UnsupportedKeySource,
    UnsupportedMapping,
    MandatoryFstabConsumer,
}

#[derive(Clone, PartialEq, Eq)]
pub struct DisableMissingCrypttabUuidPreview {
    source_line: usize,
    proposed_crypttab: Vec<u8>,
    before_sha256: String,
    observed_uuid_set_sha256: String,
    fstab_consumer_set_sha256: String,
    after_sha256: String,
    diff_sha256: String,
}

impl fmt::Debug for DisableMissingCrypttabUuidPreview {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("DisableMissingCrypttabUuidPreview")
            .field("source_line", &self.source_line)
            .field("proposed_bytes", &self.proposed_crypttab.len())
            .field("before_sha256", &self.before_sha256)
            .field("observed_uuid_set_sha256", &self.observed_uuid_set_sha256)
            .field("fstab_consumer_set_sha256", &self.fstab_consumer_set_sha256)
            .field("after_sha256", &self.after_sha256)
            .field("diff_sha256", &self.diff_sha256)
            .finish()
    }
}

impl DisableMissingCrypttabUuidPreview {
    pub const fn source_line(&self) -> usize {
        self.source_line
    }
    pub fn proposed_crypttab(&self) -> &[u8] {
        &self.proposed_crypttab
    }
    pub fn before_sha256(&self) -> &str {
        &self.before_sha256
    }
    pub fn observed_uuid_set_sha256(&self) -> &str {
        &self.observed_uuid_set_sha256
    }
    pub fn fstab_consumer_set_sha256(&self) -> &str {
        &self.fstab_consumer_set_sha256
    }
    pub fn after_sha256(&self) -> &str {
        &self.after_sha256
    }
    pub fn diff_sha256(&self) -> &str {
        &self.diff_sha256
    }
}

#[derive(Debug)]
struct ParsedLine {
    start: usize,
    content_end: usize,
    line_number: usize,
    fields: Option<Vec<Vec<u8>>>,
}

fn parse_lines(
    bytes: &[u8],
    empty_allowed: bool,
    malformed: CrypttabPreviewError,
    invalid_size: CrypttabPreviewError,
) -> Result<Vec<ParsedLine>, CrypttabPreviewError> {
    if bytes.len() > MAX_DOCUMENT_BYTES || (!empty_allowed && bytes.is_empty()) {
        return Err(invalid_size);
    }
    if bytes.contains(&0) || std::str::from_utf8(bytes).is_err() {
        return Err(malformed);
    }
    let mut parsed = Vec::new();
    let mut start = 0;
    let mut line_number = 1;
    while start < bytes.len() {
        let next = bytes[start..]
            .iter()
            .position(|byte| *byte == b'\n')
            .map_or(bytes.len(), |offset| start + offset + 1);
        let content_end = if next > start && bytes[next - 1] == b'\n' {
            next - 1
        } else {
            next
        };
        let content = &bytes[start..content_end];
        if content.len() > MAX_LINE_BYTES
            || content.contains(&b'\r')
            || content
                .iter()
                .any(|byte| *byte < b' ' && !matches!(*byte, b'\t'))
        {
            return Err(malformed);
        }
        let first = content
            .iter()
            .position(|byte| !matches!(*byte, b' ' | b'\t'));
        let fields = if first.is_none() || first.is_some_and(|index| content[index] == b'#') {
            None
        } else {
            let mut fields = Vec::new();
            let mut cursor = 0;
            while cursor < content.len() {
                while cursor < content.len() && matches!(content[cursor], b' ' | b'\t') {
                    cursor += 1;
                }
                if cursor == content.len() || content[cursor] == b'#' {
                    break;
                }
                let field_start = cursor;
                while cursor < content.len() && !matches!(content[cursor], b' ' | b'\t') {
                    cursor += 1;
                }
                fields.push(content[field_start..cursor].to_vec());
                if fields.len() > MAX_FIELDS {
                    return Err(malformed);
                }
            }
            Some(fields)
        };
        parsed.push(ParsedLine {
            start,
            content_end,
            line_number,
            fields,
        });
        start = next;
        line_number += 1;
    }
    Ok(parsed)
}

fn normalize_uuid(value: &[u8]) -> Option<String> {
    if value.is_empty()
        || value.len() > MAX_UUID_BYTES
        || value.first() == Some(&b'-')
        || value.last() == Some(&b'-')
        || !value
            .iter()
            .all(|byte| byte.is_ascii_hexdigit() || *byte == b'-')
    {
        return None;
    }
    Some(std::str::from_utf8(value).ok()?.to_ascii_lowercase())
}

fn normalize_observed(values: &BTreeSet<String>) -> Result<BTreeSet<String>, CrypttabPreviewError> {
    if values.len() > MAX_OBSERVED_UUIDS {
        return Err(CrypttabPreviewError::TooManyObservedUuids);
    }
    let mut normalized = BTreeSet::new();
    for value in values {
        let uuid =
            normalize_uuid(value.as_bytes()).ok_or(CrypttabPreviewError::InvalidObservedUuid)?;
        if !normalized.insert(uuid) {
            return Err(CrypttabPreviewError::AmbiguousObservedUuid);
        }
    }
    Ok(normalized)
}

fn valid_mapper_name(value: &[u8]) -> bool {
    !value.is_empty()
        && value.len() <= MAX_NAME_BYTES
        && value.first() != Some(&b'-')
        && value
            .iter()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(*byte, b'_' | b'.' | b'+' | b'-'))
}

fn parse_options(value: Option<&[u8]>) -> Option<Vec<&str>> {
    let Some(value) = value else {
        return Some(Vec::new());
    };
    let text = std::str::from_utf8(value).ok()?;
    if text == "none" || text == "-" {
        return Some(Vec::new());
    }
    let options = text.split(',').collect::<Vec<_>>();
    (!options.iter().any(|option| option.is_empty())).then_some(options)
}

fn has_critical_option(options: &[&str]) -> bool {
    options.iter().any(|option| {
        matches!(
            *option,
            "initramfs" | "x-initrd.attach" | "swap" | "resume" | "_netdev"
        ) || option.starts_with("keyscript=")
    })
}

fn critical_name(name: &[u8]) -> bool {
    let lower = String::from_utf8_lossy(name).to_ascii_lowercase();
    matches!(
        lower.as_str(),
        "root" | "cryptroot" | "swap" | "cryptswap" | "resume"
    ) || lower.starts_with("cryptroot-")
}

fn decode_fstab_field(field: &[u8]) -> Result<Vec<u8>, CrypttabPreviewError> {
    let mut decoded = Vec::with_capacity(field.len());
    let mut cursor = 0;
    while cursor < field.len() {
        if field[cursor] != b'\\' {
            if field[cursor] < b' ' || field[cursor] == 0x7f {
                return Err(CrypttabPreviewError::MalformedFstab);
            }
            decoded.push(field[cursor]);
            cursor += 1;
            continue;
        }
        if cursor + 3 >= field.len()
            || !field[cursor + 1..=cursor + 3]
                .iter()
                .all(|digit| matches!(digit, b'0'..=b'7'))
        {
            return Err(CrypttabPreviewError::MalformedFstab);
        }
        let value = u16::from(field[cursor + 1] - b'0') * 64
            + u16::from(field[cursor + 2] - b'0') * 8
            + u16::from(field[cursor + 3] - b'0');
        let byte = u8::try_from(value).map_err(|_| CrypttabPreviewError::MalformedFstab)?;
        if byte < b' ' || byte == 0x7f {
            return Err(CrypttabPreviewError::MalformedFstab);
        }
        decoded.push(byte);
        cursor += 4;
    }
    Ok(decoded)
}

fn mapper_source_matches(source: &[u8], name: &[u8]) -> bool {
    let mut direct = b"/dev/mapper/".to_vec();
    direct.extend_from_slice(name);
    if source == direct {
        return true;
    }
    let mut by_id = b"/dev/disk/by-id/dm-name-".to_vec();
    by_id.extend_from_slice(name);
    source == by_id
}

fn fstab_has_mandatory_consumer(fstab: &[u8], name: &[u8]) -> Result<bool, CrypttabPreviewError> {
    let lines = parse_lines(
        fstab,
        true,
        CrypttabPreviewError::MalformedFstab,
        CrypttabPreviewError::InvalidFstabSize,
    )?;
    for line in lines {
        let Some(raw) = line.fields else {
            continue;
        };
        if !(4..=6).contains(&raw.len()) {
            return Err(CrypttabPreviewError::MalformedFstab);
        }
        let fields = raw
            .iter()
            .map(|field| decode_fstab_field(field))
            .collect::<Result<Vec<_>, _>>()?;
        for numeric in fields.iter().skip(4) {
            if std::str::from_utf8(numeric)
                .ok()
                .and_then(|value| value.parse::<u32>().ok())
                .is_none()
            {
                return Err(CrypttabPreviewError::MalformedFstab);
            }
        }
        if !mapper_source_matches(&fields[0], name) {
            continue;
        }
        let options = std::str::from_utf8(&fields[3])
            .map_err(|_| CrypttabPreviewError::MalformedFstab)?
            .split(',')
            .collect::<Vec<_>>();
        if options.iter().any(|option| option.is_empty()) {
            return Err(CrypttabPreviewError::MalformedFstab);
        }
        if !options
            .iter()
            .any(|option| matches!(*option, "nofail" | "noauto"))
        {
            return Ok(true);
        }
    }
    Ok(false)
}

fn sha256(bytes: &[u8]) -> String {
    format!("sha256:{:x}", Sha256::digest(bytes))
}

fn hash_framed(digest: &mut Sha256, value: &[u8]) {
    digest.update((value.len() as u64).to_be_bytes());
    digest.update(value);
}

fn uuid_set_sha256(values: &BTreeSet<String>) -> String {
    let mut digest = Sha256::new();
    digest.update(UUID_SET_DOMAIN);
    digest.update((values.len() as u64).to_be_bytes());
    for value in values {
        hash_framed(&mut digest, value.as_bytes());
    }
    format!("sha256:{:x}", digest.finalize())
}

fn fstab_consumer_sha256(fstab: &[u8], name: &[u8]) -> String {
    let mut digest = Sha256::new();
    digest.update(FSTAB_CONSUMER_DOMAIN);
    hash_framed(&mut digest, fstab);
    hash_framed(&mut digest, name);
    format!("sha256:{:x}", digest.finalize())
}

fn diff_sha256(document: &[u8], target: &ParsedLine) -> String {
    let original = &document[target.start..target.content_end];
    let mut replacement = Vec::with_capacity(COMMENT_PREFIX.len() + original.len());
    replacement.extend_from_slice(COMMENT_PREFIX);
    replacement.extend_from_slice(original);
    let mut digest = Sha256::new();
    digest.update(DIFF_DOMAIN);
    digest.update((target.start as u64).to_be_bytes());
    digest.update((target.content_end as u64).to_be_bytes());
    hash_framed(&mut digest, original);
    hash_framed(&mut digest, &replacement);
    format!("sha256:{:x}", digest.finalize())
}

/// Prepare the sole allowed crypttab edit from immutable observation bytes.
///
/// The missing mapping must have no mandatory fstab consumer. This is what
/// keeps v1 a one-file transaction: configurations requiring a coordinated
/// fstab edit are deliberately rejected rather than partially repaired.
pub fn preview_disable_missing_crypttab_uuid(
    crypttab: &[u8],
    fstab: &[u8],
    observed_uuids: &BTreeSet<String>,
) -> Result<DisableMissingCrypttabUuidPreview, CrypttabPreviewError> {
    let observed = normalize_observed(observed_uuids)?;
    let lines = parse_lines(
        crypttab,
        false,
        CrypttabPreviewError::MalformedCrypttab,
        CrypttabPreviewError::InvalidCrypttabSize,
    )?;
    let mut candidates: Vec<(&ParsedLine, Vec<u8>)> = Vec::new();
    for line in &lines {
        let Some(fields) = line.fields.as_deref() else {
            continue;
        };
        if !(2..=4).contains(&fields.len()) {
            return Err(CrypttabPreviewError::MalformedCrypttab);
        }
        if !valid_mapper_name(&fields[0]) {
            return Err(CrypttabPreviewError::MalformedCrypttab);
        }
        let Some(raw_uuid) = fields[1].strip_prefix(b"UUID=") else {
            continue;
        };
        let uuid = normalize_uuid(raw_uuid).ok_or(CrypttabPreviewError::MalformedCrypttab)?;
        if observed.contains(&uuid) {
            continue;
        }
        let key_source = fields.get(2).map(Vec::as_slice);
        if key_source.is_some_and(|value| !matches!(value, b"none" | b"-")) {
            return Err(CrypttabPreviewError::UnsupportedKeySource);
        }
        let options = parse_options(fields.get(3).map(Vec::as_slice))
            .ok_or(CrypttabPreviewError::MalformedCrypttab)?;
        if options
            .iter()
            .any(|option| matches!(*option, "nofail" | "noauto"))
        {
            continue;
        }
        if critical_name(&fields[0]) || has_critical_option(&options) {
            return Err(CrypttabPreviewError::CriticalMapping);
        }
        if options.iter().any(|option| {
            option.starts_with("keyfile-")
                || option.starts_with("header=")
                || option.starts_with("pkcs11-uri=")
                || option.starts_with("fido2-device=")
                || option.starts_with("tpm2-device=")
        }) {
            return Err(CrypttabPreviewError::UnsupportedMapping);
        }
        if fstab_has_mandatory_consumer(fstab, &fields[0])? {
            return Err(CrypttabPreviewError::MandatoryFstabConsumer);
        }
        candidates.push((line, fields[0].clone()));
    }
    let (target, name) = match candidates.as_slice() {
        [] => return Err(CrypttabPreviewError::RepairNotApplicable),
        [candidate] => candidate,
        _ => return Err(CrypttabPreviewError::AmbiguousTarget),
    };
    let mut proposed = Vec::with_capacity(crypttab.len() + COMMENT_PREFIX.len());
    proposed.extend_from_slice(&crypttab[..target.start]);
    proposed.extend_from_slice(COMMENT_PREFIX);
    proposed.extend_from_slice(&crypttab[target.start..target.content_end]);
    proposed.extend_from_slice(&crypttab[target.content_end..]);
    parse_lines(
        &proposed,
        false,
        CrypttabPreviewError::MalformedCrypttab,
        CrypttabPreviewError::InvalidCrypttabSize,
    )?;
    Ok(DisableMissingCrypttabUuidPreview {
        source_line: target.line_number,
        before_sha256: sha256(crypttab),
        observed_uuid_set_sha256: uuid_set_sha256(&observed),
        fstab_consumer_set_sha256: fstab_consumer_sha256(fstab, name),
        after_sha256: sha256(&proposed),
        diff_sha256: diff_sha256(crypttab, target),
        proposed_crypttab: proposed,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn observed(values: &[&str]) -> BTreeSet<String> {
        values.iter().map(|value| (*value).to_owned()).collect()
    }

    const CRYPTTAB: &[u8] = b"system UUID=AAAA-BBBB none luks\narchive UUID=DEAD-BEEF none luks\n";
    const FSTAB: &[u8] = b"UUID=ROOT / ext4 defaults 0 1\n";

    #[test]
    fn prepares_one_orphan_auxiliary_mapping_deterministically() {
        let first =
            preview_disable_missing_crypttab_uuid(CRYPTTAB, FSTAB, &observed(&["aaaa-bbbb"]))
                .expect("crypttab candidate");
        let second =
            preview_disable_missing_crypttab_uuid(CRYPTTAB, FSTAB, &observed(&["AAAA-BBBB"]))
                .expect("repeat candidate");
        assert_eq!(first, second);
        assert_eq!(first.source_line(), 2);
        assert_eq!(
            first.proposed_crypttab(),
            b"system UUID=AAAA-BBBB none luks\n# KernAid Rescue disabled missing crypttab UUID: archive UUID=DEAD-BEEF none luks\n"
        );
        assert!(!format!("{first:?}").contains("DEAD-BEEF"));
        assert!(!format!("{first:?}").contains("archive"));
        for hash in [
            first.before_sha256(),
            first.observed_uuid_set_sha256(),
            first.fstab_consumer_set_sha256(),
            first.after_sha256(),
            first.diff_sha256(),
        ] {
            assert_eq!(hash.len(), 71);
            assert!(hash.starts_with("sha256:"));
        }
    }

    #[test]
    fn permits_only_optional_fstab_consumers() {
        let optional = b"/dev/mapper/archive /srv/archive ext4 defaults,nofail 0 2\n";
        assert!(
            preview_disable_missing_crypttab_uuid(CRYPTTAB, optional, &observed(&["aaaa-bbbb"]))
                .is_ok()
        );
        let mandatory = b"/dev/mapper/archive /srv/archive ext4 defaults 0 2\n";
        assert_eq!(
            preview_disable_missing_crypttab_uuid(CRYPTTAB, mandatory, &observed(&["aaaa-bbbb"])),
            Err(CrypttabPreviewError::MandatoryFstabConsumer)
        );
    }

    #[test]
    fn rejects_root_resume_swap_initramfs_keyscript_and_external_keys() {
        for line in [
            "cryptroot UUID=DEAD-BEEF none luks",
            "data UUID=DEAD-BEEF none luks,initramfs",
            "data UUID=DEAD-BEEF none luks,x-initrd.attach",
            "data UUID=DEAD-BEEF none swap",
            "data UUID=DEAD-BEEF none resume",
            "data UUID=DEAD-BEEF none luks,keyscript=/bin/thing",
        ] {
            assert_eq!(
                preview_disable_missing_crypttab_uuid(
                    format!("{line}\n").as_bytes(),
                    FSTAB,
                    &BTreeSet::new()
                ),
                Err(CrypttabPreviewError::CriticalMapping),
                "must reject {line}"
            );
        }
        assert_eq!(
            preview_disable_missing_crypttab_uuid(
                b"data UUID=DEAD-BEEF /root/key luks\n",
                FSTAB,
                &BTreeSet::new()
            ),
            Err(CrypttabPreviewError::UnsupportedKeySource)
        );
    }

    #[test]
    fn ignores_already_safe_or_present_mappings_and_rejects_ambiguity() {
        assert_eq!(
            preview_disable_missing_crypttab_uuid(
                b"data UUID=DEAD-BEEF none luks,nofail\n",
                FSTAB,
                &BTreeSet::new()
            ),
            Err(CrypttabPreviewError::RepairNotApplicable)
        );
        assert_eq!(
            preview_disable_missing_crypttab_uuid(
                b"data UUID=DEAD-BEEF none luks\n",
                FSTAB,
                &observed(&["dead-beef"])
            ),
            Err(CrypttabPreviewError::RepairNotApplicable)
        );
        assert_eq!(
            preview_disable_missing_crypttab_uuid(
                b"one UUID=AAAA none luks\ntwo UUID=BBBB none luks\n",
                FSTAB,
                &BTreeSet::new()
            ),
            Err(CrypttabPreviewError::AmbiguousTarget)
        );
    }

    #[test]
    fn malformed_inputs_and_case_colliding_inventory_fail_closed() {
        assert_eq!(
            preview_disable_missing_crypttab_uuid(b"", FSTAB, &BTreeSet::new()),
            Err(CrypttabPreviewError::InvalidCrypttabSize)
        );
        assert_eq!(
            preview_disable_missing_crypttab_uuid(
                b"too few too many fields here now yes\n",
                FSTAB,
                &BTreeSet::new()
            ),
            Err(CrypttabPreviewError::MalformedCrypttab)
        );
        assert_eq!(
            preview_disable_missing_crypttab_uuid(
                b"data UUID=DEAD-BEEF none luks\n",
                FSTAB,
                &observed(&["AAAA", "aaaa"])
            ),
            Err(CrypttabPreviewError::AmbiguousObservedUuid)
        );
    }
}
