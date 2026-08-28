//! Pure selection and preview for the disabled Rescue `fstab` repair candidate.
//!
//! This module accepts already-collected bytes and UUID inventory only. It
//! performs no filesystem access and cannot execute a repair.

use sha2::{Digest, Sha256};
use std::collections::BTreeSet;

const MAX_FSTAB_BYTES: usize = 1024 * 1024;
const MAX_FSTAB_LINE_BYTES: usize = 16 * 1024;
const MAX_OBSERVED_UUIDS: usize = 4096;
const MAX_UUID_BYTES: usize = 128;
const COMMENT_PREFIX: &[u8] = b"# KernAid Rescue disabled missing UUID: ";
const OBSERVED_UUID_SET_HASH_DOMAIN: &[u8] =
    b"kernaid:linux.fstab.disable-missing-uuid.v1:observed-uuid-set:v1\0";
const DIFF_HASH_DOMAIN: &[u8] = b"kernaid:linux.fstab.disable-missing-uuid.v1:diff:v1\0";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PreviewError {
    InvalidFstabSize,
    MalformedFstab,
    TooManyObservedUuids,
    InvalidObservedUuid,
    AmbiguousObservedUuid,
    RepairNotApplicable,
    AmbiguousTarget,
    CriticalMountMissing,
    UnsupportedMountMissing,
    UnsupportedEntryKind,
    UnsupportedFilesystem,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DisableMissingUuidPreview {
    selected_uuid: String,
    selected_mountpoint: String,
    source_line: usize,
    proposed_fstab: Vec<u8>,
    before_sha256: String,
    observed_uuid_set_sha256: String,
    after_sha256: String,
    diff_sha256: String,
}

impl DisableMissingUuidPreview {
    pub fn selected_uuid(&self) -> &str {
        &self.selected_uuid
    }

    pub fn selected_mountpoint(&self) -> &str {
        &self.selected_mountpoint
    }

    pub const fn source_line(&self) -> usize {
        self.source_line
    }

    pub fn proposed_fstab(&self) -> &[u8] {
        &self.proposed_fstab
    }

    /// SHA-256 of the exact input `fstab` bytes, formatted as `sha256:<hex>`.
    pub fn before_sha256(&self) -> &str {
        &self.before_sha256
    }

    /// Domain-separated SHA-256 of the canonical observed UUID set.
    pub fn observed_uuid_set_sha256(&self) -> &str {
        &self.observed_uuid_set_sha256
    }

    /// SHA-256 of the exact proposed `fstab` bytes, formatted as `sha256:<hex>`.
    pub fn after_sha256(&self) -> &str {
        &self.after_sha256
    }

    /// Domain-separated SHA-256 of the canonical single-line edit.
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

fn decode_field(field: &[u8]) -> Result<Vec<u8>, PreviewError> {
    let mut decoded = Vec::with_capacity(field.len());
    let mut cursor = 0;
    while cursor < field.len() {
        if field[cursor] == b'\\' {
            if cursor + 3 >= field.len()
                || !field[cursor + 1..=cursor + 3]
                    .iter()
                    .all(|digit| matches!(digit, b'0'..=b'7'))
            {
                return Err(PreviewError::MalformedFstab);
            }
            let value = u16::from(field[cursor + 1] - b'0') * 64
                + u16::from(field[cursor + 2] - b'0') * 8
                + u16::from(field[cursor + 3] - b'0');
            let byte = u8::try_from(value).map_err(|_| PreviewError::MalformedFstab)?;
            if byte < b' ' || byte == 0x7f {
                return Err(PreviewError::MalformedFstab);
            }
            decoded.push(byte);
            cursor += 4;
        } else {
            let byte = field[cursor];
            if byte < b' ' || byte == 0x7f {
                return Err(PreviewError::MalformedFstab);
            }
            decoded.push(byte);
            cursor += 1;
        }
    }
    Ok(decoded)
}

fn parse_fstab(bytes: &[u8]) -> Result<Vec<ParsedLine>, PreviewError> {
    if bytes.is_empty() || bytes.len() > MAX_FSTAB_BYTES {
        return Err(PreviewError::InvalidFstabSize);
    }
    if bytes.contains(&0) || std::str::from_utf8(bytes).is_err() {
        return Err(PreviewError::MalformedFstab);
    }

    let mut parsed = Vec::new();
    let mut start = 0;
    let mut line_number = 1;
    while start < bytes.len() {
        let newline = bytes[start..]
            .iter()
            .position(|byte| *byte == b'\n')
            .map_or(bytes.len(), |offset| start + offset + 1);
        let content_end = if newline > start && bytes[newline - 1] == b'\n' {
            newline - 1
        } else {
            newline
        };
        let content = &bytes[start..content_end];
        if content.len() > MAX_FSTAB_LINE_BYTES || content.contains(&b'\r') {
            return Err(PreviewError::MalformedFstab);
        }

        let first = content
            .iter()
            .position(|byte| !matches!(byte, b' ' | b'\t'));
        let fields = if first.is_none() || first.is_some_and(|index| content[index] == b'#') {
            None
        } else {
            let mut fields = Vec::new();
            let mut cursor = 0;
            while cursor < content.len() {
                while cursor < content.len() && matches!(content[cursor], b' ' | b'\t') {
                    cursor += 1;
                }
                if cursor == content.len() {
                    break;
                }
                let field_start = cursor;
                while cursor < content.len() && !matches!(content[cursor], b' ' | b'\t') {
                    cursor += 1;
                }
                fields.push(decode_field(&content[field_start..cursor])?);
                if fields.len() > 6 {
                    return Err(PreviewError::MalformedFstab);
                }
            }
            if !(4..=6).contains(&fields.len()) {
                return Err(PreviewError::MalformedFstab);
            }
            for numeric in fields.iter().skip(4) {
                let value = std::str::from_utf8(numeric)
                    .ok()
                    .and_then(|value| value.parse::<u32>().ok());
                if value.is_none() {
                    return Err(PreviewError::MalformedFstab);
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
        start = newline;
        line_number += 1;
    }
    Ok(parsed)
}

fn normalize_uuid(value: &[u8]) -> Result<String, PreviewError> {
    if value.is_empty()
        || value.len() > MAX_UUID_BYTES
        || value.first() == Some(&b'-')
        || value.last() == Some(&b'-')
        || !value
            .iter()
            .all(|byte| byte.is_ascii_hexdigit() || *byte == b'-')
    {
        return Err(PreviewError::MalformedFstab);
    }
    let text = std::str::from_utf8(value).map_err(|_| PreviewError::MalformedFstab)?;
    Ok(text.to_ascii_lowercase())
}

fn normalize_observed_uuids(
    observed_uuids: &BTreeSet<String>,
) -> Result<BTreeSet<String>, PreviewError> {
    if observed_uuids.len() > MAX_OBSERVED_UUIDS {
        return Err(PreviewError::TooManyObservedUuids);
    }
    let mut normalized = BTreeSet::new();
    for uuid in observed_uuids {
        let value =
            normalize_uuid(uuid.as_bytes()).map_err(|_| PreviewError::InvalidObservedUuid)?;
        if !normalized.insert(value) {
            return Err(PreviewError::AmbiguousObservedUuid);
        }
    }
    Ok(normalized)
}

fn sha256_bytes(bytes: &[u8]) -> String {
    format!("sha256:{:x}", Sha256::digest(bytes))
}

fn hash_framed(digest: &mut Sha256, value: &[u8]) {
    digest.update((value.len() as u64).to_be_bytes());
    digest.update(value);
}

/// Hash the normalized UUID set using the documented candidate-v1 wire form:
/// domain bytes, a big-endian `u64` item count, then each lowercase UUID in
/// lexical order as a big-endian `u64` byte length followed by its bytes.
fn observed_uuid_set_sha256(observed: &BTreeSet<String>) -> String {
    let mut digest = Sha256::new();
    digest.update(OBSERVED_UUID_SET_HASH_DOMAIN);
    digest.update((observed.len() as u64).to_be_bytes());
    for uuid in observed {
        hash_framed(&mut digest, uuid.as_bytes());
    }
    format!("sha256:{:x}", digest.finalize())
}

/// Hash the only proposed edit using the candidate-v1 diff wire form: domain
/// bytes, big-endian `u64` start/end offsets, then length-framed original and
/// replacement line bytes. The line terminator is outside both frames.
fn diff_sha256(fstab: &[u8], target: &ParsedLine) -> String {
    let original = &fstab[target.start..target.content_end];
    let mut replacement = Vec::with_capacity(COMMENT_PREFIX.len() + original.len());
    replacement.extend_from_slice(COMMENT_PREFIX);
    replacement.extend_from_slice(original);

    let mut digest = Sha256::new();
    digest.update(DIFF_HASH_DOMAIN);
    digest.update((target.start as u64).to_be_bytes());
    digest.update((target.content_end as u64).to_be_bytes());
    hash_framed(&mut digest, original);
    hash_framed(&mut digest, &replacement);
    format!("sha256:{:x}", digest.finalize())
}

fn options(fields: &[Vec<u8>]) -> Result<Vec<&str>, PreviewError> {
    let raw = std::str::from_utf8(&fields[3]).map_err(|_| PreviewError::MalformedFstab)?;
    let values = raw.split(',').collect::<Vec<_>>();
    if values.iter().any(|value| value.is_empty()) {
        return Err(PreviewError::MalformedFstab);
    }
    Ok(values)
}

fn at_or_below(path: &str, root: &str) -> bool {
    path == root
        || path
            .strip_prefix(root)
            .is_some_and(|suffix| suffix.starts_with('/'))
}

fn is_critical_mount(mountpoint: &str, filesystem: &str) -> bool {
    mountpoint == "/"
        || filesystem == "swap"
        || mountpoint == "swap"
        || ["/boot", "/etc", "/usr", "/var", "/home"]
            .iter()
            .any(|root| at_or_below(mountpoint, root))
}

fn is_allowed_data_mount(mountpoint: &str) -> bool {
    ["/mnt/", "/media/", "/srv/"].iter().any(|prefix| {
        mountpoint.strip_prefix(prefix).is_some_and(|suffix| {
            !suffix.is_empty()
                && suffix
                    .split('/')
                    .all(|component| !component.is_empty() && component != "." && component != "..")
        })
    })
}

fn is_network_filesystem(filesystem: &str) -> bool {
    matches!(
        filesystem,
        "nfs"
            | "nfs4"
            | "cifs"
            | "smb3"
            | "9p"
            | "ceph"
            | "glusterfs"
            | "sshfs"
            | "fuse.sshfs"
            | "davfs"
            | "davfs2"
            | "afs"
    )
}

/// Build a deterministic candidate edit from immutable evidence bytes.
///
/// Only one active, mandatory, absent UUID entry below `/mnt`, `/media`, or
/// `/srv` can be selected. The result is proposed bytes only; it does not
/// authorize or perform any write.
pub fn preview_disable_missing_uuid(
    fstab: &[u8],
    observed_uuids: &BTreeSet<String>,
) -> Result<DisableMissingUuidPreview, PreviewError> {
    let observed = normalize_observed_uuids(observed_uuids)?;
    let parsed = parse_fstab(fstab)?;
    let mut candidates = Vec::new();

    for line in &parsed {
        let Some(fields) = line.fields.as_deref() else {
            continue;
        };
        let Some(raw_uuid) = fields[0].strip_prefix(b"UUID=") else {
            continue;
        };
        let uuid = normalize_uuid(raw_uuid)?;
        if observed.contains(&uuid) {
            continue;
        }

        let entry_options = options(fields)?;
        if entry_options
            .iter()
            .any(|option| matches!(*option, "nofail" | "noauto"))
        {
            continue;
        }

        let mountpoint =
            std::str::from_utf8(&fields[1]).map_err(|_| PreviewError::MalformedFstab)?;
        let filesystem =
            std::str::from_utf8(&fields[2]).map_err(|_| PreviewError::MalformedFstab)?;
        if is_critical_mount(mountpoint, filesystem) {
            return Err(PreviewError::CriticalMountMissing);
        }
        if entry_options
            .iter()
            .any(|option| matches!(*option, "bind" | "rbind" | "_netdev"))
            || is_network_filesystem(filesystem)
        {
            return Err(PreviewError::UnsupportedEntryKind);
        }
        if filesystem != "ext4" {
            return Err(PreviewError::UnsupportedFilesystem);
        }
        if !is_allowed_data_mount(mountpoint) {
            return Err(PreviewError::UnsupportedMountMissing);
        }
        candidates.push((line, uuid, mountpoint.to_owned()));
    }

    let (target, uuid, mountpoint) = match candidates.as_slice() {
        [] => return Err(PreviewError::RepairNotApplicable),
        [candidate] => candidate,
        _ => return Err(PreviewError::AmbiguousTarget),
    };

    let mut proposed = Vec::with_capacity(fstab.len() + COMMENT_PREFIX.len());
    proposed.extend_from_slice(&fstab[..target.start]);
    proposed.extend_from_slice(COMMENT_PREFIX);
    proposed.extend_from_slice(&fstab[target.start..target.content_end]);
    proposed.extend_from_slice(&fstab[target.content_end..]);
    parse_fstab(&proposed)?;

    let before_sha256 = sha256_bytes(fstab);
    let observed_uuid_set_sha256 = observed_uuid_set_sha256(&observed);
    let after_sha256 = sha256_bytes(&proposed);
    let diff_sha256 = diff_sha256(fstab, target);

    Ok(DisableMissingUuidPreview {
        selected_uuid: uuid.clone(),
        selected_mountpoint: mountpoint.clone(),
        source_line: target.line_number,
        proposed_fstab: proposed,
        before_sha256,
        observed_uuid_set_sha256,
        after_sha256,
        diff_sha256,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn observed(values: &[&str]) -> BTreeSet<String> {
        values.iter().map(|value| (*value).to_owned()).collect()
    }

    #[test]
    fn deterministically_comments_one_missing_mandatory_data_mount() {
        let fstab = b"# system\nUUID=AAAA-BBBB / ext4 defaults 0 1\n\tUUID=DEAD-BEEF\t/mnt/archive ext4 defaults 0 2\n";
        let inventory = observed(&["aaaa-bbbb"]);
        let first = preview_disable_missing_uuid(fstab, &inventory).expect("preview candidate");
        let second = preview_disable_missing_uuid(fstab, &inventory).expect("repeat preview");
        assert_eq!(first, second);
        assert_eq!(first.selected_uuid(), "dead-beef");
        assert_eq!(first.selected_mountpoint(), "/mnt/archive");
        assert_eq!(first.source_line(), 3);
        assert_eq!(
            first.proposed_fstab(),
            b"# system\nUUID=AAAA-BBBB / ext4 defaults 0 1\n# KernAid Rescue disabled missing UUID: \tUUID=DEAD-BEEF\t/mnt/archive ext4 defaults 0 2\n"
        );
        for hash in [
            first.before_sha256(),
            first.observed_uuid_set_sha256(),
            first.after_sha256(),
            first.diff_sha256(),
        ] {
            assert_eq!(hash.len(), 71);
            assert!(hash.starts_with("sha256:"));
        }
        assert_ne!(first.before_sha256(), first.after_sha256());
        assert_eq!(first.before_sha256(), sha256_bytes(fstab));
        assert_eq!(first.after_sha256(), sha256_bytes(first.proposed_fstab()));
    }

    #[test]
    fn observed_uuid_hash_is_stable_across_case_and_input_order() {
        let fstab =
            b"UUID=AAAA-BBBB / ext4 defaults 0 1\nUUID=DEAD-BEEF /srv/archive ext4 defaults 0 2\n";
        let first_inventory = observed(&["AAAA-BBBB", "1111-2222"]);
        let second_inventory = observed(&["1111-2222", "aaaa-bbbb"]);
        let first = preview_disable_missing_uuid(fstab, &first_inventory).expect("first preview");
        let second =
            preview_disable_missing_uuid(fstab, &second_inventory).expect("second preview");

        assert_eq!(first, second);
        assert_eq!(
            first.observed_uuid_set_sha256(),
            second.observed_uuid_set_sha256()
        );

        let smaller = preview_disable_missing_uuid(fstab, &observed(&["aaaa-bbbb"]))
            .expect("preview with smaller UUID set");
        assert_ne!(
            first.observed_uuid_set_sha256(),
            smaller.observed_uuid_set_sha256()
        );
    }

    #[test]
    fn ignores_observed_and_explicitly_optional_missing_entries() {
        for fstab in [
            b"UUID=AAAA-BBBB /srv/data ext4 defaults 0 2\n".as_slice(),
            b"UUID=DEAD-BEEF /srv/data ext4 defaults,nofail 0 2\n".as_slice(),
            b"UUID=DEAD-BEEF /media/disk ext4 noauto 0 2\n".as_slice(),
        ] {
            let inventory = observed(&["aaaa-bbbb"]);
            assert_eq!(
                preview_disable_missing_uuid(fstab, &inventory),
                Err(PreviewError::RepairNotApplicable)
            );
        }
    }

    #[test]
    fn rejects_missing_critical_and_swap_entries() {
        for fstab in [
            "UUID=DEAD-BEEF / ext4 defaults 0 1\n",
            "UUID=DEAD-BEEF /boot/efi vfat defaults 0 2\n",
            "UUID=DEAD-BEEF /etc/overlay ext4 defaults 0 2\n",
            "UUID=DEAD-BEEF /usr ext4 defaults 0 2\n",
            "UUID=DEAD-BEEF /var/log ext4 defaults 0 2\n",
            "UUID=DEAD-BEEF /home/user ext4 defaults 0 2\n",
            "UUID=DEAD-BEEF none swap sw 0 0\n",
        ] {
            assert_eq!(
                preview_disable_missing_uuid(fstab.as_bytes(), &BTreeSet::new()),
                Err(PreviewError::CriticalMountMissing),
                "critical entry must fail closed: {fstab}"
            );
        }
    }

    #[test]
    fn rejects_unsupported_mounts_bind_and_network_entries() {
        assert_eq!(
            preview_disable_missing_uuid(
                b"UUID=DEAD-BEEF /opt/data ext4 defaults 0 2\n",
                &BTreeSet::new()
            ),
            Err(PreviewError::UnsupportedMountMissing)
        );
        for fstab in [
            "UUID=DEAD-BEEF /mnt/data none bind 0 0\n",
            "UUID=DEAD-BEEF /srv/share nfs defaults 0 0\n",
            "UUID=DEAD-BEEF /media/share ext4 defaults,_netdev 0 2\n",
        ] {
            assert_eq!(
                preview_disable_missing_uuid(fstab.as_bytes(), &BTreeSet::new()),
                Err(PreviewError::UnsupportedEntryKind)
            );
        }
        assert_eq!(
            preview_disable_missing_uuid(
                b"UUID=DEAD-BEEF /srv/archive xfs defaults 0 2\n",
                &BTreeSet::new()
            ),
            Err(PreviewError::UnsupportedFilesystem)
        );
    }

    #[test]
    fn rejects_multiple_candidates_and_case_colliding_inventory() {
        let multiple =
            b"UUID=AAAA-BBBB /mnt/a ext4 defaults 0 2\nUUID=CCCC-DDDD /srv/b ext4 defaults 0 2\n";
        assert_eq!(
            preview_disable_missing_uuid(multiple, &BTreeSet::new()),
            Err(PreviewError::AmbiguousTarget)
        );
        assert_eq!(
            preview_disable_missing_uuid(
                b"UUID=DEAD-BEEF /mnt/a ext4 defaults 0 2\n",
                &observed(&["AAAA-BBBB", "aaaa-bbbb"])
            ),
            Err(PreviewError::AmbiguousObservedUuid)
        );
    }

    #[test]
    fn rejects_malformed_documents_before_selection() {
        for malformed in [
            b"".as_slice(),
            b"UUID=DEAD-BEEF /mnt/a ext4\n".as_slice(),
            b"UUID=DEAD-BEEF /mnt/a ext4 defaults 0 nope\n".as_slice(),
            b"UUID=DEAD-BEEF /mnt/a ext4 defaults 0 2 extra\n".as_slice(),
            b"UUID=DEAD-BEEF /mnt/../etc ext4 defaults 0 2\n".as_slice(),
            b"UUID=NOT-A-UUID /mnt/a ext4 defaults 0 2\n".as_slice(),
            b"UUID=DEAD-BEEF /mnt/a ext4 defaults,,rw 0 2\n".as_slice(),
        ] {
            let result = preview_disable_missing_uuid(malformed, &BTreeSet::new());
            assert!(
                matches!(
                    result,
                    Err(PreviewError::InvalidFstabSize)
                        | Err(PreviewError::MalformedFstab)
                        | Err(PreviewError::UnsupportedMountMissing)
                ),
                "malformed document was not rejected: {result:?}"
            );
        }
    }
}
