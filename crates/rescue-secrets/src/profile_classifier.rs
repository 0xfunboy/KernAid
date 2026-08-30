//! Descriptor-bound classification of the fixed Rescue vault partition.
//!
//! This module never formats, opens a mapping, mounts, or writes the supplied
//! descriptor. A locked classification requires both redundant LUKS2 headers;
//! the separate ext4 qualifier must then succeed on the exact mapper before
//! the mount manager may consume either result.

use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64_STANDARD};
use rustix::fs::{self as rfs, FileType};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    error::Error,
    fmt,
    fs::File,
    io,
    os::{fd::AsFd, unix::fs::FileExt},
    time::{Duration, Instant},
};

const MAX_LUKS_JSON_BYTES: usize = 256 * 1024;
const ZERO_SCAN_CHUNK_BYTES: usize = 4 * 1024 * 1024;
const ZERO_SCAN_REVALIDATE_BYTES: u64 = 64 * 1024 * 1024;
const ZERO_SCAN_TIMEOUT: Duration = Duration::from_secs(10 * 60);
pub(crate) const LOGICAL_SECTOR_BYTES: u64 = 512;
pub(crate) const VAULT_START_LBA: u64 = 33_554_432;
pub(crate) const VAULT_SECTOR_COUNT: u64 = 16_777_216;
pub(crate) const VAULT_PARTITION_BYTES: u64 = VAULT_SECTOR_COUNT * LOGICAL_SECTOR_BYTES;
pub(crate) const LUKS_DATA_OFFSET_BYTES: u64 = 16_777_216;
pub(crate) const VAULT_PAYLOAD_BYTES: u64 = VAULT_PARTITION_BYTES - LUKS_DATA_OFFSET_BYTES;
pub(crate) const MINIMUM_MEDIA_BYTES: u64 = 25_769_803_776;
pub(crate) const MINIMUM_ADVERTISED_MEDIA_BYTES: u64 = 32_000_000_000;
const LUKS_HEADER_BYTES: usize = 16 * 1024;
const LUKS_BINARY_HEADER_BYTES: usize = 4096;
const LUKS_CHECKSUM_OFFSET: usize = 448;
const LUKS_CHECKSUM_BYTES: usize = 64;
const LUKS_AF_HASH: &str = "sha256";
const LUKS_AF_STRIPES: u64 = 4000;
const LUKS_CIPHER: &str = "aes-xts-plain64";
const LUKS_DIGEST_HASH: &str = "sha256";
const LUKS_DIGEST_ITERATIONS: u64 = 1000;
const LUKS_KEY_BITS: u64 = 512;
const LUKS_KEYSLOT: u64 = 0;
const LUKS_KEYSLOT_AREA_BYTES: u64 = 258_048;
const LUKS_KEYSLOT_AREA_OFFSET_BYTES: u64 = 32_768;
const LUKS_KEYSLOTS_BYTES: u64 = 16_744_448;
const LUKS_PBKDF: &str = "argon2id";
const LUKS_PBKDF_CPUS: u64 = 1;
const LUKS_PBKDF_MEMORY_KIB: u64 = 65_536;
const LUKS_PBKDF_TIME: u64 = 4;
const EXT4_SUPERBLOCK_OFFSET: u64 = 1024;
const EXT4_SUPERBLOCK_BYTES: usize = 1024;
const EXT4_BLOCK_BYTES: u64 = 4096;
const EXT4_BLOCKS_PER_GROUP: u64 = 32_768;
const EXT4_BYTES_PER_INODE: u64 = 16_384;
const EXT4_COMPAT_FEATURES: u32 = 0x0000_003c;
const EXT4_INCOMPAT_FEATURES: u32 = 0x0000_02c2;
const EXT4_INCOMPAT_RECOVER: u32 = 0x0000_0004;
const EXT4_INCOMPAT_FEATURES_WITH_RECOVERY: u32 = EXT4_INCOMPAT_FEATURES | EXT4_INCOMPAT_RECOVER;
const EXT4_RO_COMPAT_FEATURES: u32 = 0x0000_046b;
const EXT4_FLEX_GROUP_SIZE: u64 = 16;
const EXT4_FLEX_GROUP_LOG: u8 = 4;
const EXT4_INODE_BYTES: u64 = 256;
const EXT4_JOURNAL_BYTES: u64 = 128 * 1024 * 1024;
const EXT4_JOURNAL_BLOCKS: u64 = EXT4_JOURNAL_BYTES / EXT4_BLOCK_BYTES;
const JBD2_SUPERBLOCK_BYTES: usize = 1024;
const JBD2_CHECKSUM_OFFSET: usize = 0xfc;
const JBD2_FEATURE_INCOMPAT_64BIT_CSUM_V3: u32 = 0x0000_0012;
const JBD2_CRC32C_CHECKSUM_TYPE: u8 = 4;
const PROFILE_SHA256: [u8; 32] = [
    0xb4, 0x80, 0x13, 0x59, 0xbd, 0x4f, 0x31, 0xce, 0x67, 0xfb, 0xd3, 0xec, 0x15, 0xb6, 0xc8, 0x1c,
    0x44, 0xaa, 0x67, 0x59, 0xba, 0x43, 0xb2, 0xa4, 0xe0, 0x99, 0xa7, 0xdf, 0xcc, 0x25, 0xa3, 0x7c,
];
const EMBEDDED_PROFILE: &[u8] = include_bytes!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../rescue/image-layout/vault-profile.v1.json"
));
const EMBEDDED_LAYOUT: &[u8] = include_bytes!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../rescue/image-layout/device-layout.v1.json"
));

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum VaultPartitionProfile {
    /// Every byte in the exact fixed-size p3 capability was zero.
    Unprovisioned,
    /// Both redundant headers and their shared logical JSON are exact.
    Locked(OuterProfileEvidence),
    /// Non-zero media did not have the exact active logical outer profile.
    ProfileMismatch,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct OuterProfileEvidence {
    uuid: [u8; 36],
    sequence: u64,
}

impl OuterProfileEvidence {
    pub(crate) fn uuid(&self) -> [u8; 36] {
        self.uuid
    }

    #[cfg(test)]
    pub(crate) fn sequence(&self) -> u64 {
        self.sequence
    }

    #[cfg(test)]
    pub(crate) fn fixture(uuid: [u8; 36], sequence: u64) -> Self {
        Self { uuid, sequence }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Ext4ProfileEvidence {
    uuid: [u8; 16],
    journal_start_block: u64,
}

impl Ext4ProfileEvidence {
    #[cfg(test)]
    pub(crate) fn uuid(&self) -> [u8; 16] {
        self.uuid
    }

    #[cfg(test)]
    pub(crate) fn journal_start_block(&self) -> u64 {
        self.journal_start_block
    }

    pub(crate) fn uuid_ascii(&self) -> [u8; 36] {
        const HEX: &[u8; 16] = b"0123456789abcdef";
        let mut rendered = [0_u8; 36];
        let mut input = 0;
        for (output, byte) in rendered.iter_mut().enumerate() {
            if matches!(output, 8 | 13 | 18 | 23) {
                *byte = b'-';
            } else {
                let value = self.uuid[input / 2];
                *byte = HEX[usize::from(if input % 2 == 0 {
                    value >> 4
                } else {
                    value & 0x0f
                })];
                input += 1;
            }
        }
        rendered
    }

    #[cfg(test)]
    pub(crate) fn fixture(uuid: [u8; 16], journal_start_block: u64) -> Self {
        Self {
            uuid,
            journal_start_block,
        }
    }
}

/// Closed operational failures. Profile differences are represented by
/// `ProfileMismatch`, never by an attacker-controlled diagnostic.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ProfileClassifierError {
    InvalidCanonicalProfile,
    InvalidDescriptor,
    MediaChanged,
    OperationTimedOut,
}

impl fmt::Display for ProfileClassifierError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::InvalidCanonicalProfile => "the embedded vault profile is invalid",
            Self::InvalidDescriptor => "the vault partition descriptor is invalid",
            Self::MediaChanged => "the vault partition changed during classification",
            Self::OperationTimedOut => "vault profile inspection timed out",
        })
    }
}

impl Error for ProfileClassifierError {}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct CanonicalProfile {
    ext4: CanonicalExt4,
    luks2: CanonicalLuks2,
    schema: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct CanonicalLayout {
    schema: String,
    layout_version: u64,
    partition_table: String,
    logical_sector_bytes: u64,
    minimum_media_bytes: u64,
    minimum_advertised_media_bytes: u64,
    minimum_advertised_media_label: String,
    vault_profile_version: u64,
    vault_profile_sha256: String,
    vault_partition: CanonicalVaultPartition,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct CanonicalVaultPartition {
    number: u64,
    name: String,
    mbr_type: String,
    start_lba: u64,
    sector_count: u64,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct CanonicalExt4 {
    block_bytes: u64,
    blocks_per_group: u64,
    bytes_per_inode: u64,
    default_mount_options: String,
    errors: String,
    features_compat: u64,
    features_incompat: u64,
    features_ro_compat: u64,
    flex_group_size: u64,
    inode_bytes: u64,
    journal_mi_b: u64,
    reserved_percent: u64,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct CanonicalLuks2 {
    af_hash: String,
    af_stripes: u64,
    cipher: String,
    data_offset_bytes: u64,
    digest_hash: String,
    digest_iterations: u64,
    key_bits: u64,
    keyslot: u64,
    keyslot_area_bytes: u64,
    keyslot_area_offset_bytes: u64,
    keyslots_bytes: u64,
    metadata_bytes: u64,
    pbkdf: String,
    pbkdf_cpus: u64,
    pbkdf_memory_ki_b: u64,
    pbkdf_time: u64,
    sector_bytes: u64,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct LuksJson {
    keyslots: OnlyKeyslotZero,
    tokens: EmptyObject,
    segments: OnlySegmentZero,
    digests: OnlyDigestZero,
    config: LuksConfig,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct OnlyKeyslotZero {
    #[serde(rename = "0")]
    zero: LuksKeyslot,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct OnlySegmentZero {
    #[serde(rename = "0")]
    zero: LuksSegment,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct OnlyDigestZero {
    #[serde(rename = "0")]
    zero: LuksDigest,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct EmptyObject {}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct LuksKeyslot {
    #[serde(rename = "type")]
    kind: String,
    key_size: u64,
    af: LuksAf,
    area: LuksArea,
    kdf: LuksKdf,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct LuksAf {
    #[serde(rename = "type")]
    kind: String,
    stripes: u64,
    hash: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct LuksArea {
    #[serde(rename = "type")]
    kind: String,
    offset: String,
    size: String,
    encryption: String,
    key_size: u64,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct LuksKdf {
    #[serde(rename = "type")]
    kind: String,
    time: u64,
    memory: u64,
    cpus: u64,
    salt: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct LuksSegment {
    #[serde(rename = "type")]
    kind: String,
    offset: String,
    size: String,
    iv_tweak: String,
    encryption: String,
    sector_size: u64,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct LuksDigest {
    #[serde(rename = "type")]
    kind: String,
    keyslots: Vec<String>,
    segments: Vec<String>,
    hash: String,
    iterations: u64,
    salt: String,
    digest: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct LuksConfig {
    json_size: String,
    keyslots_size: String,
}

pub(crate) fn verify_embedded_profile() -> Result<(), ProfileClassifierError> {
    let profile: CanonicalProfile = serde_json::from_slice(EMBEDDED_PROFILE)
        .map_err(|_| ProfileClassifierError::InvalidCanonicalProfile)?;
    let canonical = serde_json::to_vec(&profile)
        .map_err(|_| ProfileClassifierError::InvalidCanonicalProfile)?;
    let digest: [u8; 32] = Sha256::digest(canonical).into();
    if digest != PROFILE_SHA256
        || profile.schema != "kernaid.vault-profile.v1"
        || profile.ext4.block_bytes != EXT4_BLOCK_BYTES
        || profile.ext4.blocks_per_group != EXT4_BLOCKS_PER_GROUP
        || profile.ext4.bytes_per_inode != EXT4_BYTES_PER_INODE
        || profile.ext4.default_mount_options != "none"
        || profile.ext4.errors != "remount-ro"
        || profile.ext4.features_compat != u64::from(EXT4_COMPAT_FEATURES)
        || profile.ext4.features_incompat != u64::from(EXT4_INCOMPAT_FEATURES)
        || profile.ext4.features_ro_compat != u64::from(EXT4_RO_COMPAT_FEATURES)
        || profile.ext4.flex_group_size != EXT4_FLEX_GROUP_SIZE
        || 1_u64.checked_shl(u32::from(EXT4_FLEX_GROUP_LOG)) != Some(EXT4_FLEX_GROUP_SIZE)
        || profile.ext4.inode_bytes != EXT4_INODE_BYTES
        || profile.ext4.journal_mi_b.checked_mul(1024 * 1024) != Some(EXT4_JOURNAL_BYTES)
        || profile.ext4.reserved_percent != 0
        || profile.luks2.af_hash != LUKS_AF_HASH
        || profile.luks2.af_stripes != LUKS_AF_STRIPES
        || profile.luks2.cipher != LUKS_CIPHER
        || profile.luks2.data_offset_bytes != LUKS_DATA_OFFSET_BYTES
        || profile.luks2.digest_hash != LUKS_DIGEST_HASH
        || profile.luks2.digest_iterations != LUKS_DIGEST_ITERATIONS
        || profile.luks2.key_bits != LUKS_KEY_BITS
        || profile.luks2.keyslot != LUKS_KEYSLOT
        || profile.luks2.keyslot_area_bytes != LUKS_KEYSLOT_AREA_BYTES
        || profile.luks2.keyslot_area_offset_bytes != LUKS_KEYSLOT_AREA_OFFSET_BYTES
        || profile.luks2.keyslots_bytes != LUKS_KEYSLOTS_BYTES
        || profile.luks2.metadata_bytes != LUKS_HEADER_BYTES as u64
        || profile.luks2.pbkdf != LUKS_PBKDF
        || profile.luks2.pbkdf_cpus != LUKS_PBKDF_CPUS
        || profile.luks2.pbkdf_memory_ki_b != LUKS_PBKDF_MEMORY_KIB
        || profile.luks2.pbkdf_time != LUKS_PBKDF_TIME
        || profile.luks2.sector_bytes != LOGICAL_SECTOR_BYTES
    {
        return Err(ProfileClassifierError::InvalidCanonicalProfile);
    }
    let layout: CanonicalLayout = serde_json::from_slice(EMBEDDED_LAYOUT)
        .map_err(|_| ProfileClassifierError::InvalidCanonicalProfile)?;
    if layout.schema != "kernaid.rescue-device-layout.v1"
        || layout.layout_version != 1
        || layout.partition_table != "mbr"
        || layout.logical_sector_bytes != LOGICAL_SECTOR_BYTES
        || layout.minimum_media_bytes != MINIMUM_MEDIA_BYTES
        || layout.minimum_advertised_media_bytes != MINIMUM_ADVERTISED_MEDIA_BYTES
        || layout.minimum_advertised_media_label != "32 GB"
        || layout.vault_profile_version != 1
        || parse_lower_hex_sha256(&layout.vault_profile_sha256) != Some(PROFILE_SHA256)
        || layout.vault_partition.number != 3
        || layout.vault_partition.name != "KERNAID_VAULT"
        || layout.vault_partition.mbr_type != "0x83"
        || layout.vault_partition.start_lba != VAULT_START_LBA
        || layout.vault_partition.sector_count != VAULT_SECTOR_COUNT
        || VAULT_START_LBA
            .checked_add(VAULT_SECTOR_COUNT)
            .and_then(|sectors| sectors.checked_mul(LOGICAL_SECTOR_BYTES))
            != Some(MINIMUM_MEDIA_BYTES)
    {
        return Err(ProfileClassifierError::InvalidCanonicalProfile);
    }
    Ok(())
}

fn parse_lower_hex_sha256(value: &str) -> Option<[u8; 32]> {
    let bytes = value.as_bytes();
    if bytes.len() != 64 {
        return None;
    }
    let mut decoded = [0_u8; 32];
    for (index, pair) in bytes.chunks_exact(2).enumerate() {
        let high = lower_hex_nibble(pair[0])?;
        let low = lower_hex_nibble(pair[1])?;
        decoded[index] = (high << 4) | low;
    }
    Some(decoded)
}

fn lower_hex_nibble(value: u8) -> Option<u8> {
    match value {
        b'0'..=b'9' => Some(value - b'0'),
        b'a'..=b'f' => Some(value - b'a' + 10),
        _ => None,
    }
}

pub(crate) fn verify_outer_luks_json(raw: &[u8]) -> bool {
    if raw.is_empty() || raw.len() > MAX_LUKS_JSON_BYTES {
        return false;
    }
    let Ok(document) = serde_json::from_slice::<LuksJson>(raw) else {
        return false;
    };
    let keyslot = document.keyslots.zero;
    let segment = document.segments.zero;
    let digest = document.digests.zero;
    let _empty = document.tokens;
    keyslot.kind == "luks2"
        && keyslot.key_size == LUKS_KEY_BITS / 8
        && keyslot.af.kind == "luks1"
        && keyslot.af.stripes == LUKS_AF_STRIPES
        && keyslot.af.hash == LUKS_AF_HASH
        && keyslot.area.kind == "raw"
        && canonical_decimal(&keyslot.area.offset, LUKS_KEYSLOT_AREA_OFFSET_BYTES)
        && canonical_decimal(&keyslot.area.size, LUKS_KEYSLOT_AREA_BYTES)
        && keyslot.area.encryption == LUKS_CIPHER
        && keyslot.area.key_size == LUKS_KEY_BITS / 8
        && keyslot.kdf.kind == LUKS_PBKDF
        && keyslot.kdf.time == LUKS_PBKDF_TIME
        && keyslot.kdf.memory == LUKS_PBKDF_MEMORY_KIB
        && keyslot.kdf.cpus == LUKS_PBKDF_CPUS
        && canonical_base64_32(&keyslot.kdf.salt)
        && segment.kind == "crypt"
        && canonical_decimal(&segment.offset, LUKS_DATA_OFFSET_BYTES)
        && segment.size == "dynamic"
        && segment.iv_tweak == "0"
        && segment.encryption == LUKS_CIPHER
        && segment.sector_size == LOGICAL_SECTOR_BYTES
        && digest.kind == "pbkdf2"
        && digest.keyslots == ["0"]
        && digest.segments == ["0"]
        && digest.hash == LUKS_DIGEST_HASH
        && digest.iterations == LUKS_DIGEST_ITERATIONS
        && canonical_base64_32(&digest.salt)
        && canonical_base64_32(&digest.digest)
        && canonical_decimal(
            &document.config.json_size,
            (LUKS_HEADER_BYTES - LUKS_BINARY_HEADER_BYTES) as u64,
        )
        && canonical_decimal(&document.config.keyslots_size, LUKS_KEYSLOTS_BYTES)
}

fn canonical_decimal(value: &str, expected: u64) -> bool {
    let bytes = value.as_bytes();
    !bytes.is_empty()
        && bytes.iter().all(u8::is_ascii_digit)
        && ((expected == 0 && bytes == b"0") || (expected > 0 && bytes.first() != Some(&b'0')))
        && value.parse::<u64>() == Ok(expected)
}

fn canonical_base64_32(value: &str) -> bool {
    if value.len() != 44 {
        return false;
    }
    let Ok(decoded) = BASE64_STANDARD.decode(value) else {
        return false;
    };
    decoded.len() == 32 && BASE64_STANDARD.encode(decoded) == value
}

pub(crate) fn classify_partition(
    descriptor: impl AsFd,
    revalidate: impl FnMut() -> Result<(), ProfileClassifierError>,
) -> Result<VaultPartitionProfile, ProfileClassifierError> {
    classify_partition_with_timeout(descriptor, ZERO_SCAN_TIMEOUT, revalidate)
}

pub(crate) fn classify_partition_with_timeout(
    descriptor: impl AsFd,
    timeout: Duration,
    mut revalidate: impl FnMut() -> Result<(), ProfileClassifierError>,
) -> Result<VaultPartitionProfile, ProfileClassifierError> {
    if timeout.is_zero() || timeout > ZERO_SCAN_TIMEOUT {
        return Err(ProfileClassifierError::OperationTimedOut);
    }
    verify_embedded_profile()?;
    revalidate()?;
    let before = descriptor_snapshot(&descriptor)?;
    if !FileType::from_raw_mode(before.mode).is_block_device() {
        return Err(ProfileClassifierError::InvalidDescriptor);
    }
    let result =
        classify_raw_partition(&descriptor, VAULT_PARTITION_BYTES, timeout, &mut revalidate)?;
    revalidate()?;
    if descriptor_snapshot(&descriptor)? != before {
        return Err(ProfileClassifierError::MediaChanged);
    }
    Ok(result)
}

fn classify_raw_partition(
    descriptor: impl AsFd,
    capacity: u64,
    timeout: Duration,
    mut revalidate: impl FnMut() -> Result<(), ProfileClassifierError>,
) -> Result<VaultPartitionProfile, ProfileClassifierError> {
    let deadline = Instant::now()
        .checked_add(timeout)
        .ok_or(ProfileClassifierError::OperationTimedOut)?;
    let duplicate = rustix::io::fcntl_dupfd_cloexec(descriptor, 3)
        .map_err(|_| ProfileClassifierError::InvalidDescriptor)?;
    let file = File::from(duplicate);
    revalidate()?;
    let first_length = usize::try_from(capacity.min(ZERO_SCAN_CHUNK_BYTES as u64))
        .map_err(|_| ProfileClassifierError::InvalidDescriptor)?;
    let mut buffer = vec![0_u8; first_length];
    if buffer.is_empty() {
        return Err(ProfileClassifierError::InvalidDescriptor);
    }
    read_exact_at(&file, &mut buffer, 0)?;
    ensure_deadline(deadline)?;
    revalidate()?;
    ensure_deadline(deadline)?;
    if buffer.iter().all(|byte| *byte == 0) {
        let mut offset = buffer.len() as u64;
        let mut next_revalidation = ZERO_SCAN_REVALIDATE_BYTES;
        while offset < capacity {
            if Instant::now() >= deadline {
                return Err(ProfileClassifierError::OperationTimedOut);
            }
            let length = usize::try_from((capacity - offset).min(ZERO_SCAN_CHUNK_BYTES as u64))
                .map_err(|_| ProfileClassifierError::InvalidDescriptor)?;
            read_exact_at(&file, &mut buffer[..length], offset)?;
            ensure_deadline(deadline)?;
            if buffer[..length].iter().any(|byte| *byte != 0) {
                return Ok(VaultPartitionProfile::ProfileMismatch);
            }
            offset = offset
                .checked_add(length as u64)
                .ok_or(ProfileClassifierError::InvalidDescriptor)?;
            if offset >= next_revalidation || offset == capacity {
                revalidate()?;
                ensure_deadline(deadline)?;
                next_revalidation = offset
                    .checked_add(ZERO_SCAN_REVALIDATE_BYTES)
                    .unwrap_or(u64::MAX);
            }
        }
        ensure_deadline(deadline)?;
        return Ok(VaultPartitionProfile::Unprovisioned);
    }

    revalidate()?;
    ensure_deadline(deadline)?;
    let evidence = verify_dual_luks_headers(&file);
    ensure_deadline(deadline)?;
    revalidate()?;
    ensure_deadline(deadline)?;
    Ok(evidence.map_or(
        VaultPartitionProfile::ProfileMismatch,
        VaultPartitionProfile::Locked,
    ))
}

fn ensure_deadline(deadline: Instant) -> Result<(), ProfileClassifierError> {
    if Instant::now() >= deadline {
        Err(ProfileClassifierError::OperationTimedOut)
    } else {
        Ok(())
    }
}

struct ParsedLuksHeader {
    sequence: u64,
    salt: [u8; 64],
    uuid: [u8; 36],
    json: Vec<u8>,
}

fn verify_dual_luks_headers(file: &File) -> Option<OuterProfileEvidence> {
    let mut headers = vec![0_u8; 2 * LUKS_HEADER_BYTES];
    read_exact_at(file, &mut headers, 0).ok()?;
    let primary = parse_luks_header(&headers[..LUKS_HEADER_BYTES], 0, b"LUKS\xba\xbe")?;
    let secondary = parse_luks_header(
        &headers[LUKS_HEADER_BYTES..],
        LUKS_HEADER_BYTES as u64,
        b"SKUL\xba\xbe",
    )?;
    if primary.sequence != secondary.sequence
        || primary.uuid != secondary.uuid
        || primary.salt == secondary.salt
        || primary.json != secondary.json
    {
        return None;
    }
    if !verify_outer_luks_json(&primary.json) {
        return None;
    }
    Some(OuterProfileEvidence {
        uuid: primary.uuid,
        sequence: primary.sequence,
    })
}

fn parse_luks_header(
    region: &[u8],
    physical_offset: u64,
    magic: &[u8; 6],
) -> Option<ParsedLuksHeader> {
    if region.len() != LUKS_HEADER_BYTES
        || &region[..6] != magic
        || be_u16(region, 6)? != 2
        || be_u64(region, 8)? != LUKS_HEADER_BYTES as u64
        || !c_field_equals(&region[24..72], b"KERNAID_VAULT")
        || !c_field_equals(&region[72..104], b"sha256")
        || !c_field_equals(&region[208..256], b"")
        || be_u64(region, 256)? != physical_offset
        || region[264..448].iter().any(|byte| *byte != 0)
        || region[480..512].iter().any(|byte| *byte != 0)
        || region[512..LUKS_BINARY_HEADER_BYTES]
            .iter()
            .any(|byte| *byte != 0)
    {
        return None;
    }
    let sequence = be_u64(region, 16)?;
    if sequence == 0 {
        return None;
    }
    let uuid_field = c_field(&region[168..208])?;
    if !canonical_uuid(uuid_field) {
        return None;
    }
    let mut uuid = [0_u8; 36];
    uuid.copy_from_slice(uuid_field);
    let mut salt = [0_u8; 64];
    salt.copy_from_slice(&region[104..168]);
    if salt.iter().all(|byte| *byte == 0) {
        return None;
    }
    let mut checksum_input = region.to_vec();
    checksum_input[LUKS_CHECKSUM_OFFSET..LUKS_CHECKSUM_OFFSET + LUKS_CHECKSUM_BYTES].fill(0);
    let checksum: [u8; 32] = Sha256::digest(checksum_input).into();
    if region[LUKS_CHECKSUM_OFFSET..LUKS_CHECKSUM_OFFSET + 32] != checksum {
        return None;
    }
    let json_area = &region[LUKS_BINARY_HEADER_BYTES..];
    let terminator = json_area.iter().position(|byte| *byte == 0)?;
    if terminator == 0 || json_area[terminator + 1..].iter().any(|byte| *byte != 0) {
        return None;
    }
    Some(ParsedLuksHeader {
        sequence,
        salt,
        uuid,
        json: json_area[..terminator].to_vec(),
    })
}

fn c_field(field: &[u8]) -> Option<&[u8]> {
    let terminator = field.iter().position(|byte| *byte == 0)?;
    if field[terminator + 1..].iter().any(|byte| *byte != 0) {
        return None;
    }
    Some(&field[..terminator])
}

fn c_field_equals(field: &[u8], expected: &[u8]) -> bool {
    c_field(field) == Some(expected)
}

fn canonical_uuid(value: &[u8]) -> bool {
    value.len() == 36
        && value.get(14) == Some(&b'4')
        && matches!(value.get(19), Some(b'8' | b'9' | b'a' | b'b'))
        && value.iter().enumerate().all(|(index, byte)| {
            if matches!(index, 8 | 13 | 18 | 23) {
                *byte == b'-'
            } else {
                byte.is_ascii_digit() || matches!(byte, b'a'..=b'f')
            }
        })
}

fn canonical_uuid_bytes(value: &[u8; 16]) -> bool {
    value[6] >> 4 == 4 && value[8] & 0xc0 == 0x80
}

fn be_u16(value: &[u8], offset: usize) -> Option<u16> {
    Some(u16::from_be_bytes(
        value.get(offset..offset + 2)?.try_into().ok()?,
    ))
}

fn be_u32(value: &[u8], offset: usize) -> Option<u32> {
    Some(u32::from_be_bytes(
        value.get(offset..offset + 4)?.try_into().ok()?,
    ))
}

fn be_u64(value: &[u8], offset: usize) -> Option<u64> {
    Some(u64::from_be_bytes(
        value.get(offset..offset + 8)?.try_into().ok()?,
    ))
}

fn le_u16(value: &[u8], offset: usize) -> Option<u16> {
    Some(u16::from_le_bytes(
        value.get(offset..offset + 2)?.try_into().ok()?,
    ))
}

fn le_u32(value: &[u8], offset: usize) -> Option<u32> {
    Some(u32::from_le_bytes(
        value.get(offset..offset + 4)?.try_into().ok()?,
    ))
}

pub(crate) fn qualify_ext4_mapper(
    descriptor: impl AsFd,
    mut revalidate: impl FnMut() -> Result<(), ProfileClassifierError>,
) -> Result<Option<Ext4ProfileEvidence>, ProfileClassifierError> {
    verify_embedded_profile()?;
    revalidate()?;
    let before = descriptor_snapshot(&descriptor)?;
    if !FileType::from_raw_mode(before.mode).is_block_device() {
        return Err(ProfileClassifierError::InvalidDescriptor);
    }
    let duplicate = rustix::io::fcntl_dupfd_cloexec(&descriptor, 3)
        .map_err(|_| ProfileClassifierError::InvalidDescriptor)?;
    let evidence = parse_ext4_profile(
        &File::from(duplicate),
        &mut revalidate,
        Ext4CheckPhase::PreMount,
    )?;
    revalidate()?;
    if descriptor_snapshot(&descriptor)? != before {
        return Err(ProfileClassifierError::MediaChanged);
    }
    Ok(evidence)
}

pub(crate) fn revalidate_mounted_ext4_mapper(
    descriptor: impl AsFd,
    expected: Ext4ProfileEvidence,
    mut revalidate: impl FnMut() -> Result<(), ProfileClassifierError>,
) -> Result<bool, ProfileClassifierError> {
    revalidate()?;
    let before = descriptor_snapshot(&descriptor)?;
    if !FileType::from_raw_mode(before.mode).is_block_device() {
        return Err(ProfileClassifierError::InvalidDescriptor);
    }
    let duplicate = rustix::io::fcntl_dupfd_cloexec(&descriptor, 3)
        .map_err(|_| ProfileClassifierError::InvalidDescriptor)?;
    let observed = parse_ext4_profile(
        &File::from(duplicate),
        &mut revalidate,
        Ext4CheckPhase::Mounted,
    )?;
    revalidate()?;
    if descriptor_snapshot(&descriptor)? != before {
        return Err(ProfileClassifierError::MediaChanged);
    }
    Ok(observed == Some(expected))
}

#[derive(Clone, Copy)]
enum Ext4CheckPhase {
    PreMount,
    Mounted,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Ext4RuntimeProfile {
    CleanUnmounted,
    JournalRecovery,
}

fn classify_ext4_runtime_profile(
    state: Option<u16>,
    incompat: Option<u32>,
    last_orphan: Option<u32>,
) -> Option<Ext4RuntimeProfile> {
    match (state, incompat, last_orphan) {
        (Some(1), Some(EXT4_INCOMPAT_FEATURES), Some(0)) => {
            Some(Ext4RuntimeProfile::CleanUnmounted)
        }
        (Some(1), Some(EXT4_INCOMPAT_FEATURES_WITH_RECOVERY), Some(0)) => {
            Some(Ext4RuntimeProfile::JournalRecovery)
        }
        _ => None,
    }
}

fn parse_ext4_profile(
    file: &File,
    revalidate: &mut impl FnMut() -> Result<(), ProfileClassifierError>,
    phase: Ext4CheckPhase,
) -> Result<Option<Ext4ProfileEvidence>, ProfileClassifierError> {
    macro_rules! exact_field {
        ($field:expr) => {
            match $field {
                Some(value) => value,
                None => return Ok(None),
            }
        };
    }

    let mut superblock = [0_u8; EXT4_SUPERBLOCK_BYTES];
    read_exact_at(file, &mut superblock, EXT4_SUPERBLOCK_OFFSET)?;
    revalidate()?;
    let Some(blocks_lo) = le_u32(&superblock, 0x04) else {
        return Ok(None);
    };
    let blocks_count =
        u64::from(blocks_lo) | (u64::from(exact_field!(le_u32(&superblock, 0x150))) << 32);
    let inodes_count = u64::from(exact_field!(le_u32(&superblock, 0x00)));
    let inodes_per_group = u64::from(exact_field!(le_u32(&superblock, 0x28)));
    let groups = blocks_count.div_ceil(EXT4_BLOCKS_PER_GROUP);
    let reserved_blocks = u64::from(exact_field!(le_u32(&superblock, 0x08)))
        | (u64::from(exact_field!(le_u32(&superblock, 0x154))) << 32);
    let expected_label = b"KERNAID_VAULT\0\0\0";
    let stored_super_checksum = exact_field!(le_u32(&superblock, 0x3fc));
    let calculated_super_checksum = crc32c(!0, &superblock[..0x3fc]);
    let state = le_u16(&superblock, 0x3a);
    let incompat = le_u32(&superblock, 0x60);
    let last_orphan = le_u32(&superblock, 0xe8);
    let runtime_profile = classify_ext4_runtime_profile(state, incompat, last_orphan);
    let runtime_fields_valid = match phase {
        Ext4CheckPhase::PreMount => matches!(
            runtime_profile,
            Some(Ext4RuntimeProfile::CleanUnmounted) | Some(Ext4RuntimeProfile::JournalRecovery)
        ),
        Ext4CheckPhase::Mounted => runtime_profile == Some(Ext4RuntimeProfile::JournalRecovery),
    };
    if !runtime_fields_valid
        || le_u16(&superblock, 0x38) != Some(0xef53)
        || le_u32(&superblock, 0x14) != Some(0)
        || le_u32(&superblock, 0x18) != Some(2)
        || le_u32(&superblock, 0x1c) != Some(2)
        || le_u32(&superblock, 0x20) != Some(EXT4_BLOCKS_PER_GROUP as u32)
        || le_u32(&superblock, 0x24) != Some(EXT4_BLOCKS_PER_GROUP as u32)
        || le_u16(&superblock, 0x36) != Some(0xffff)
        || le_u16(&superblock, 0x3c) != Some(2)
        || le_u32(&superblock, 0x44) != Some(0)
        || le_u32(&superblock, 0x48) != Some(0)
        || le_u32(&superblock, 0x4c) != Some(1)
        || le_u16(&superblock, 0x50) != Some(0)
        || le_u16(&superblock, 0x52) != Some(0)
        || le_u32(&superblock, 0x54) != Some(11)
        || le_u16(&superblock, 0x58) != Some(EXT4_INODE_BYTES as u16)
        || le_u32(&superblock, 0x5c) != Some(EXT4_COMPAT_FEATURES)
        || le_u32(&superblock, 0x64) != Some(EXT4_RO_COMPAT_FEATURES)
        || &superblock[0x78..0x88] != expected_label
        || superblock[0xd0..0xe0].iter().any(|byte| *byte != 0)
        || le_u32(&superblock, 0xe0) != Some(8)
        || le_u32(&superblock, 0xe4) != Some(0)
        || superblock[0xfd] != 1
        || le_u16(&superblock, 0xfe) != Some(64)
        || le_u32(&superblock, 0x100) != Some(0)
        || le_u32(&superblock, 0x104) != Some(0)
        || le_u32(&superblock, 0x148) != Some(0)
        || le_u32(&superblock, 0x14c) != Some(EXT4_JOURNAL_BYTES as u32)
        || le_u16(&superblock, 0x15c) != Some(32)
        || le_u16(&superblock, 0x15e) != Some(32)
        || le_u32(&superblock, 0x160) != Some(1)
        || le_u16(&superblock, 0x164) != Some(0)
        || le_u32(&superblock, 0x170) != Some(0)
        || superblock[0x174] != EXT4_FLEX_GROUP_LOG
        || superblock[0x175] != 1
        || superblock[0x176] != 0
        || superblock[0x177] != 0
        || reserved_blocks != 0
        || blocks_count.checked_mul(EXT4_BLOCK_BYTES) != Some(VAULT_PAYLOAD_BYTES)
        || inodes_count.checked_mul(EXT4_BYTES_PER_INODE) != Some(VAULT_PAYLOAD_BYTES)
        || inodes_per_group == 0
        || inodes_per_group.checked_mul(groups) != Some(inodes_count)
        || stored_super_checksum != calculated_super_checksum
    {
        return Ok(None);
    }
    let mut filesystem_uuid = [0_u8; 16];
    filesystem_uuid.copy_from_slice(&superblock[0x68..0x78]);
    if !canonical_uuid_bytes(&filesystem_uuid) {
        return Ok(None);
    }

    let mut group_descriptor = [0_u8; 64];
    read_exact_at(file, &mut group_descriptor, EXT4_BLOCK_BYTES)?;
    revalidate()?;
    let stored_group_checksum = exact_field!(le_u16(&group_descriptor, 0x1e));
    let mut checksum_descriptor = group_descriptor;
    checksum_descriptor[0x1e..0x20].fill(0);
    let checksum_seed = crc32c(!0, &filesystem_uuid);
    let mut group_checksum = crc32c(checksum_seed, &0_u32.to_le_bytes());
    group_checksum = crc32c(group_checksum, &checksum_descriptor);
    let inode_table = u64::from(exact_field!(le_u32(&group_descriptor, 0x08)))
        | (u64::from(exact_field!(le_u32(&group_descriptor, 0x28))) << 32);
    let Some(inode_offset) = inode_table
        .checked_mul(EXT4_BLOCK_BYTES)
        .and_then(|offset| offset.checked_add(7 * EXT4_INODE_BYTES))
    else {
        return Ok(None);
    };
    if stored_group_checksum != group_checksum as u16
        || le_u16(&group_descriptor, 0x12) != Some(0x0004)
        || inode_table == 0
        || inode_offset
            .checked_add(256)
            .is_none_or(|end| end > VAULT_PAYLOAD_BYTES)
    {
        return Ok(None);
    }

    let mut inode = [0_u8; 256];
    read_exact_at(file, &mut inode, inode_offset)?;
    revalidate()?;
    let stored_inode_checksum = u32::from(exact_field!(le_u16(&inode, 0x7c)))
        | (u32::from(exact_field!(le_u16(&inode, 0x82))) << 16);
    let generation = exact_field!(le_u32(&inode, 0x64));
    let mut checksum_inode = inode;
    checksum_inode[0x7c..0x7e].fill(0);
    checksum_inode[0x82..0x84].fill(0);
    let mut inode_checksum = crc32c(checksum_seed, &8_u32.to_le_bytes());
    inode_checksum = crc32c(inode_checksum, &generation.to_le_bytes());
    inode_checksum = crc32c(inode_checksum, &checksum_inode);
    let inode_size = u64::from(exact_field!(le_u32(&inode, 0x04)))
        | (u64::from(exact_field!(le_u32(&inode, 0x6c))) << 32);
    let inode_blocks_512 = u64::from(exact_field!(le_u32(&inode, 0x1c)))
        | (u64::from(exact_field!(le_u16(&inode, 0x74))) << 32);
    let extent = &inode[0x28..0x64];
    let extent_start = u64::from(exact_field!(le_u32(extent, 0x14)))
        | (u64::from(exact_field!(le_u16(extent, 0x12))) << 32);
    let extent_length = u64::from(exact_field!(le_u16(extent, 0x10)));
    if le_u16(&inode, 0x00) != Some(0x8180)
        || le_u16(&inode, 0x02) != Some(0)
        || le_u16(&inode, 0x18) != Some(0)
        || le_u16(&inode, 0x1a) != Some(1)
        || le_u32(&inode, 0x14) != Some(0)
        || le_u32(&inode, 0x20) != Some(0x0008_0000)
        || le_u32(&inode, 0x68) != Some(0)
        || le_u32(&inode, 0x70) != Some(0)
        || le_u16(&inode, 0x76) != Some(0)
        || le_u16(&inode, 0x78) != Some(0)
        || le_u16(&inode, 0x7a) != Some(0)
        || le_u16(&inode, 0x80) != Some(32)
        || le_u32(&inode, 0x9c) != Some(0)
        || inode_size != EXT4_JOURNAL_BYTES
        || inode_blocks_512.checked_mul(512) != Some(EXT4_JOURNAL_BYTES)
        || stored_inode_checksum != inode_checksum
        || extent != &superblock[0x10c..0x148]
        || le_u16(extent, 0x00) != Some(0xf30a)
        || le_u16(extent, 0x02) != Some(1)
        || le_u16(extent, 0x04) != Some(4)
        || le_u16(extent, 0x06) != Some(0)
        || le_u32(extent, 0x08) != Some(0)
        || le_u32(extent, 0x0c) != Some(0)
        || extent_length != EXT4_JOURNAL_BLOCKS
        || extent_start == 0
        || extent_start.checked_add(extent_length).is_none()
        || extent_start + extent_length > blocks_count
        || extent[0x18..].iter().any(|byte| *byte != 0)
    {
        return Ok(None);
    }

    if matches!(phase, Ext4CheckPhase::PreMount) {
        let Some(runtime_profile) = runtime_profile else {
            return Ok(None);
        };
        let journal_offset = extent_start
            .checked_mul(EXT4_BLOCK_BYTES)
            .ok_or(ProfileClassifierError::InvalidDescriptor)?;
        let mut journal_superblock = [0_u8; JBD2_SUPERBLOCK_BYTES];
        read_exact_at(file, &mut journal_superblock, journal_offset)?;
        revalidate()?;
        if !verify_jbd2_superblock(&journal_superblock, &filesystem_uuid, runtime_profile) {
            return Ok(None);
        }
    }
    Ok(Some(Ext4ProfileEvidence {
        uuid: filesystem_uuid,
        journal_start_block: extent_start,
    }))
}

fn verify_jbd2_superblock(
    superblock: &[u8; JBD2_SUPERBLOCK_BYTES],
    filesystem_uuid: &[u8; 16],
    runtime_profile: Ext4RuntimeProfile,
) -> bool {
    let Some(maxlen) = be_u32(superblock, 0x10) else {
        return false;
    };
    let Some(first) = be_u32(superblock, 0x14) else {
        return false;
    };
    let Some(sequence) = be_u32(superblock, 0x18) else {
        return false;
    };
    let Some(start) = be_u32(superblock, 0x1c) else {
        return false;
    };
    let Some(incompat_features) = be_u32(superblock, 0x28) else {
        return false;
    };
    let Some(head) = be_u32(superblock, 0x58) else {
        return false;
    };
    let Some(stored_checksum) = be_u32(superblock, JBD2_CHECKSUM_OFFSET) else {
        return false;
    };

    if be_u32(superblock, 0x00) != Some(0xc03b_3998)
        || be_u32(superblock, 0x04) != Some(4)
        || be_u32(superblock, 0x08) != Some(0)
        || be_u32(superblock, 0x0c) != Some(EXT4_BLOCK_BYTES as u32)
        || maxlen != EXT4_JOURNAL_BLOCKS as u32
        || first != 1
        || sequence == 0
        || be_u32(superblock, 0x20) != Some(0)
        || be_u32(superblock, 0x24) != Some(0)
        || be_u32(superblock, 0x2c) != Some(0)
        || superblock[0x30..0x40] != *filesystem_uuid
        || be_u32(superblock, 0x40) != Some(1)
        || be_u32(superblock, 0x44) != Some(0)
        || be_u32(superblock, 0x48) != Some(0)
        || be_u32(superblock, 0x4c) != Some(0)
        || superblock[0x51..0x54].iter().any(|byte| *byte != 0)
        || be_u32(superblock, 0x54) != Some(0)
        || superblock[0x5c..JBD2_CHECKSUM_OFFSET]
            .iter()
            .any(|byte| *byte != 0)
        || superblock[0x100..].iter().any(|byte| *byte != 0)
    {
        return false;
    }

    let checksum_v3_valid = || {
        if superblock[0x50] != JBD2_CRC32C_CHECKSUM_TYPE {
            return false;
        }
        let mut checksum_input = *superblock;
        checksum_input[JBD2_CHECKSUM_OFFSET..JBD2_CHECKSUM_OFFSET + 4].fill(0);
        stored_checksum == crc32c(!0, &checksum_input)
    };

    match (runtime_profile, incompat_features) {
        (Ext4RuntimeProfile::CleanUnmounted, 0) => {
            sequence == 1
                && start == 0
                && superblock[0x50] == 0
                && head == 0
                && stored_checksum == 0
        }
        (Ext4RuntimeProfile::CleanUnmounted, JBD2_FEATURE_INCOMPAT_64BIT_CSUM_V3) => {
            start == 0 && (first..maxlen).contains(&head) && checksum_v3_valid()
        }
        (Ext4RuntimeProfile::JournalRecovery, JBD2_FEATURE_INCOMPAT_64BIT_CSUM_V3) => {
            // JBD2 defines s_head as authoritative only while clean. A dirty
            // journal may persist zero or a prior head, but never out of range.
            (first..maxlen).contains(&start)
                && (head == 0 || (first..maxlen).contains(&head))
                && checksum_v3_valid()
        }
        _ => false,
    }
}

fn crc32c(mut checksum: u32, bytes: &[u8]) -> u32 {
    for byte in bytes {
        checksum ^= u32::from(*byte);
        for _ in 0..8 {
            let mask = 0_u32.wrapping_sub(checksum & 1);
            checksum = (checksum >> 1) ^ (0x82f6_3b78 & mask);
        }
    }
    checksum
}

fn read_exact_at(
    file: &File,
    mut target: &mut [u8],
    mut offset: u64,
) -> Result<(), ProfileClassifierError> {
    while !target.is_empty() {
        match file.read_at(target, offset) {
            Ok(0) => return Err(ProfileClassifierError::MediaChanged),
            Ok(read) => {
                offset = offset
                    .checked_add(read as u64)
                    .ok_or(ProfileClassifierError::InvalidDescriptor)?;
                target = &mut target[read..];
            }
            Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
            Err(_) => return Err(ProfileClassifierError::MediaChanged),
        }
    }
    Ok(())
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct DescriptorSnapshot {
    device: u64,
    inode: u64,
    rdev: u64,
    mode: u32,
}

fn descriptor_snapshot(
    descriptor: impl AsFd,
) -> Result<DescriptorSnapshot, ProfileClassifierError> {
    let stat = rfs::fstat(descriptor).map_err(|_| ProfileClassifierError::InvalidDescriptor)?;
    Ok(DescriptorSnapshot {
        device: stat.st_dev,
        inode: stat.st_ino,
        rdev: stat.st_rdev,
        mode: stat.st_mode,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Seek, SeekFrom, Write};
    use tempfile::tempfile;

    fn put_be16(target: &mut [u8], offset: usize, value: u16) {
        target[offset..offset + 2].copy_from_slice(&value.to_be_bytes());
    }

    fn put_be32(target: &mut [u8], offset: usize, value: u32) {
        target[offset..offset + 4].copy_from_slice(&value.to_be_bytes());
    }

    fn put_be64(target: &mut [u8], offset: usize, value: u64) {
        target[offset..offset + 8].copy_from_slice(&value.to_be_bytes());
    }

    fn put_le16(target: &mut [u8], offset: usize, value: u16) {
        target[offset..offset + 2].copy_from_slice(&value.to_le_bytes());
    }

    fn put_le32(target: &mut [u8], offset: usize, value: u32) {
        target[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
    }

    fn canonical_luks_json() -> Vec<u8> {
        let random = BASE64_STANDARD.encode([7_u8; 32]);
        format!(
            r#"{{"keyslots":{{"0":{{"type":"luks2","key_size":64,"af":{{"type":"luks1","stripes":4000,"hash":"sha256"}},"area":{{"type":"raw","offset":"32768","size":"258048","encryption":"aes-xts-plain64","key_size":64}},"kdf":{{"type":"argon2id","time":4,"memory":65536,"cpus":1,"salt":"{random}"}}}}}},"tokens":{{}},"segments":{{"0":{{"type":"crypt","offset":"16777216","size":"dynamic","iv_tweak":"0","encryption":"aes-xts-plain64","sector_size":512}}}},"digests":{{"0":{{"type":"pbkdf2","keyslots":["0"],"segments":["0"],"hash":"sha256","iterations":1000,"salt":"{random}","digest":"{random}"}}}},"config":{{"json_size":"12288","keyslots_size":"16744448"}}}}"#
        )
        .into_bytes()
    }

    fn luks_header(
        magic: &[u8; 6],
        offset: u64,
        sequence: u64,
        salt_byte: u8,
        json: &[u8],
    ) -> Vec<u8> {
        let mut header = vec![0_u8; LUKS_HEADER_BYTES];
        header[..6].copy_from_slice(magic);
        put_be16(&mut header, 6, 2);
        put_be64(&mut header, 8, LUKS_HEADER_BYTES as u64);
        put_be64(&mut header, 16, sequence);
        header[24..37].copy_from_slice(b"KERNAID_VAULT");
        header[72..78].copy_from_slice(b"sha256");
        header[104..168].fill(salt_byte);
        header[168..204].copy_from_slice(b"11111111-1111-4111-8111-111111111111");
        put_be64(&mut header, 256, offset);
        header[LUKS_BINARY_HEADER_BYTES..LUKS_BINARY_HEADER_BYTES + json.len()]
            .copy_from_slice(json);
        let mut checksum_input = header.clone();
        checksum_input[LUKS_CHECKSUM_OFFSET..LUKS_CHECKSUM_OFFSET + LUKS_CHECKSUM_BYTES].fill(0);
        let checksum: [u8; 32] = Sha256::digest(checksum_input).into();
        header[LUKS_CHECKSUM_OFFSET..LUKS_CHECKSUM_OFFSET + 32].copy_from_slice(&checksum);
        header
    }

    fn dual_luks_file() -> (File, Vec<u8>) {
        let json = canonical_luks_json();
        let primary = luks_header(b"LUKS\xba\xbe", 0, 3, 0x11, &json);
        let secondary = luks_header(b"SKUL\xba\xbe", LUKS_HEADER_BYTES as u64, 3, 0x22, &json);
        let mut file = tempfile().expect("create dual-header fixture");
        file.write_all(&primary).expect("write primary header");
        file.write_all(&secondary).expect("write secondary header");
        file.seek(SeekFrom::Start(0))
            .expect("rewind dual-header fixture");
        (file, json)
    }

    fn ext4_file(journal_blocks: u16) -> File {
        let file = tempfile().expect("create ext4 fixture");
        file.set_len(VAULT_PAYLOAD_BYTES)
            .expect("size ext4 fixture");
        let filesystem_uuid = [
            0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x42, 0x22, 0x82, 0x22, 0x22, 0x22, 0x22, 0x22,
            0x22, 0x22,
        ];
        let journal_start = 557_056_u64;
        let inode_table = 1055_u64;

        let mut inode = [0_u8; 256];
        put_le16(&mut inode, 0x00, 0x8180);
        put_le32(&mut inode, 0x04, EXT4_JOURNAL_BYTES as u32);
        put_le16(&mut inode, 0x1a, 1);
        put_le32(&mut inode, 0x1c, (EXT4_JOURNAL_BYTES / 512) as u32);
        put_le32(&mut inode, 0x20, 0x0008_0000);
        put_le16(&mut inode, 0x80, 32);
        put_le16(&mut inode, 0x28, 0xf30a);
        put_le16(&mut inode, 0x2a, 1);
        put_le16(&mut inode, 0x2c, 4);
        put_le16(&mut inode, 0x2e, 0);
        put_le32(&mut inode, 0x30, 0);
        put_le32(&mut inode, 0x34, 0);
        put_le16(&mut inode, 0x38, journal_blocks);
        put_le16(&mut inode, 0x3a, (journal_start >> 32) as u16);
        put_le32(&mut inode, 0x3c, journal_start as u32);
        let checksum_seed = crc32c(!0, &filesystem_uuid);
        let mut inode_checksum = crc32c(checksum_seed, &8_u32.to_le_bytes());
        inode_checksum = crc32c(inode_checksum, &0_u32.to_le_bytes());
        inode_checksum = crc32c(inode_checksum, &inode);
        put_le16(&mut inode, 0x7c, inode_checksum as u16);
        put_le16(&mut inode, 0x82, (inode_checksum >> 16) as u16);

        let mut group = [0_u8; 64];
        put_le32(&mut group, 0x08, inode_table as u32);
        put_le16(&mut group, 0x12, 0x0004);
        let mut group_checksum = crc32c(checksum_seed, &0_u32.to_le_bytes());
        group_checksum = crc32c(group_checksum, &group);
        put_le16(&mut group, 0x1e, group_checksum as u16);

        let mut superblock = [0_u8; 1024];
        put_le32(&mut superblock, 0x00, 523_264);
        put_le32(&mut superblock, 0x04, 2_093_056);
        put_le32(&mut superblock, 0x18, 2);
        put_le32(&mut superblock, 0x1c, 2);
        put_le32(&mut superblock, 0x20, 32_768);
        put_le32(&mut superblock, 0x24, 32_768);
        put_le32(&mut superblock, 0x28, 8176);
        put_le16(&mut superblock, 0x36, 0xffff);
        put_le16(&mut superblock, 0x38, 0xef53);
        put_le16(&mut superblock, 0x3a, 1);
        put_le16(&mut superblock, 0x3c, 2);
        put_le32(&mut superblock, 0x4c, 1);
        put_le32(&mut superblock, 0x54, 11);
        put_le16(&mut superblock, 0x58, 256);
        put_le32(&mut superblock, 0x5c, 0x0000_003c);
        put_le32(&mut superblock, 0x60, 0x0000_02c2);
        put_le32(&mut superblock, 0x64, 0x0000_046b);
        superblock[0x68..0x78].copy_from_slice(&filesystem_uuid);
        superblock[0x78..0x85].copy_from_slice(b"KERNAID_VAULT");
        put_le32(&mut superblock, 0xe0, 8);
        superblock[0xfd] = 1;
        put_le16(&mut superblock, 0xfe, 64);
        superblock[0x10c..0x148].copy_from_slice(&inode[0x28..0x64]);
        put_le32(&mut superblock, 0x14c, EXT4_JOURNAL_BYTES as u32);
        put_le16(&mut superblock, 0x15c, 32);
        put_le16(&mut superblock, 0x15e, 32);
        put_le32(&mut superblock, 0x160, 1);
        superblock[0x174] = 4;
        superblock[0x175] = 1;
        let super_checksum = crc32c(!0, &superblock[..0x3fc]);
        put_le32(&mut superblock, 0x3fc, super_checksum);

        let mut journal = [0_u8; 1024];
        put_be32(&mut journal, 0x00, 0xc03b_3998);
        put_be32(&mut journal, 0x04, 4);
        put_be32(&mut journal, 0x0c, 4096);
        put_be32(&mut journal, 0x10, u32::from(journal_blocks));
        put_be32(&mut journal, 0x14, 1);
        put_be32(&mut journal, 0x18, 1);
        journal[0x30..0x40].copy_from_slice(&filesystem_uuid);
        put_be32(&mut journal, 0x40, 1);

        file.write_all_at(&superblock, EXT4_SUPERBLOCK_OFFSET)
            .expect("write ext4 superblock");
        file.write_all_at(&group, EXT4_BLOCK_BYTES)
            .expect("write ext4 group descriptor");
        file.write_all_at(&inode, inode_table * EXT4_BLOCK_BYTES + 7 * 256)
            .expect("write ext4 journal inode");
        file.write_all_at(&journal, journal_start * EXT4_BLOCK_BYTES)
            .expect("write jbd2 superblock");
        file
    }

    fn update_jbd2_superblock(file: &File, update: impl FnOnce(&mut [u8; JBD2_SUPERBLOCK_BYTES])) {
        let journal_offset = 557_056 * EXT4_BLOCK_BYTES;
        let mut journal = [0_u8; JBD2_SUPERBLOCK_BYTES];
        read_exact_at(file, &mut journal, journal_offset).expect("read jbd2 fixture");
        update(&mut journal);
        put_be32(&mut journal, JBD2_CHECKSUM_OFFSET, 0);
        let checksum = crc32c(!0, &journal);
        put_be32(&mut journal, JBD2_CHECKSUM_OFFSET, checksum);
        file.write_all_at(&journal, journal_offset)
            .expect("write checksummed jbd2 fixture");
    }

    fn set_jbd2_checksum_v3(file: &File) {
        update_jbd2_superblock(file, |journal| {
            put_be32(journal, 0x28, JBD2_FEATURE_INCOMPAT_64BIT_CSUM_V3);
            journal[0x50] = JBD2_CRC32C_CHECKSUM_TYPE;
            put_be32(journal, 0x58, 9);
        });
    }

    fn set_jbd2_recovery_checksum_v3(file: &File) {
        update_jbd2_superblock(file, |journal| {
            put_be32(journal, 0x18, 2);
            put_be32(journal, 0x1c, 1);
            put_be32(journal, 0x28, JBD2_FEATURE_INCOMPAT_64BIT_CSUM_V3);
            journal[0x50] = JBD2_CRC32C_CHECKSUM_TYPE;
            put_be32(journal, 0x58, 0);
        });
    }

    fn set_ext4_runtime_fields(file: &File, state: u16, incompat: u32, last_orphan: u32) {
        let mut superblock = [0_u8; EXT4_SUPERBLOCK_BYTES];
        read_exact_at(file, &mut superblock, EXT4_SUPERBLOCK_OFFSET)
            .expect("read ext4 runtime fields fixture");
        put_le16(&mut superblock, 0x3a, state);
        put_le32(&mut superblock, 0x60, incompat);
        put_le32(&mut superblock, 0xe8, last_orphan);
        let checksum = crc32c(!0, &superblock[..0x3fc]);
        put_le32(&mut superblock, 0x3fc, checksum);
        file.write_all_at(&superblock, EXT4_SUPERBLOCK_OFFSET)
            .expect("write ext4 runtime fields fixture");
    }

    #[test]
    fn embedded_profile_and_layout_bind_the_same_pinned_geometry_and_digest() {
        verify_embedded_profile().expect("canonical profile");
        assert_eq!(
            (VAULT_START_LBA + VAULT_SECTOR_COUNT) * LOGICAL_SECTOR_BYTES,
            MINIMUM_MEDIA_BYTES
        );
        assert_eq!(
            parse_lower_hex_sha256(
                "b4801359bd4f31ce67fbd3ec15b6c81c44aa6759ba43b2a4e099a7dfcc25a37c"
            ),
            Some(PROFILE_SHA256)
        );
        assert!(
            parse_lower_hex_sha256(
                "B4801359BD4F31CE67FBD3EC15B6C81C44AA6759BA43B2A4E099A7DFCC25A37C"
            )
            .is_none()
        );
    }

    #[test]
    fn dynamic_uuids_are_exact_rfc4122_version_four_values() {
        assert!(canonical_uuid(b"11111111-1111-4111-8111-111111111111"));
        assert!(!canonical_uuid(b"11111111-1111-3111-8111-111111111111"));
        assert!(!canonical_uuid(b"11111111-1111-4111-7111-111111111111"));
        assert!(canonical_uuid_bytes(&[
            0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x41, 0x11, 0x81, 0x11, 0x11, 0x11, 0x11, 0x11,
            0x11, 0x11,
        ]));
        assert!(!canonical_uuid_bytes(&[
            0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x31, 0x11, 0x81, 0x11, 0x11, 0x11, 0x11, 0x11,
            0x11, 0x11,
        ]));
        assert!(!canonical_uuid_bytes(&[
            0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x41, 0x11, 0x41, 0x11, 0x11, 0x11, 0x11, 0x11,
            0x11, 0x11,
        ]));
    }

    #[test]
    fn exact_outer_json_accepts_dynamic_random_fields() {
        assert!(verify_outer_luks_json(&canonical_luks_json()));
        let mut other = canonical_luks_json();
        let old = BASE64_STANDARD.encode([7_u8; 32]);
        let new = BASE64_STANDARD.encode([9_u8; 32]);
        other = String::from_utf8(other)
            .expect("canonical fixture is UTF-8")
            .replacen(&old, &new, 1)
            .into_bytes();
        assert!(verify_outer_luks_json(&other));
    }

    #[test]
    fn outer_json_rejects_duplicates_extras_and_profile_drift() {
        let canonical =
            String::from_utf8(canonical_luks_json()).expect("canonical fixture is UTF-8");
        for changed in [
            canonical.replacen("\"0\":{", "\"0\":{},\"0\":{", 1),
            canonical.replacen("\"tokens\":{}", "\"tokens\":{\"1\":{}}", 1),
            canonical.replacen("\"memory\":65536", "\"memory\":32768", 1),
            canonical.replacen("\"size\":\"dynamic\"", "\"size\":\"1\"", 1),
            canonical.replacen("\"config\":{", "\"unknown\":0,\"config\":{", 1),
        ] {
            assert!(!verify_outer_luks_json(changed.as_bytes()), "{changed}");
        }
    }

    #[test]
    fn full_zero_scan_reads_every_byte_and_never_calls_probe() {
        let mut file = tempfile().expect("create zero-scan fixture");
        file.set_len(2 * ZERO_SCAN_CHUNK_BYTES as u64 + 17)
            .expect("size zero-scan fixture");
        let capacity = file.metadata().expect("stat zero-scan fixture").len();
        let profile = classify_raw_partition(&file, capacity, ZERO_SCAN_TIMEOUT, || Ok(()))
            .expect("zero classification");
        assert!(matches!(profile, VaultPartitionProfile::Unprovisioned));

        file.seek(SeekFrom::Start(capacity - 1))
            .expect("seek zero-scan tail");
        file.write_all(&[1]).expect("tamper zero-scan tail");
        let profile = classify_raw_partition(&file, capacity, ZERO_SCAN_TIMEOUT, || Ok(()))
            .expect("non-zero tail classification");
        assert!(matches!(profile, VaultPartitionProfile::ProfileMismatch));
    }

    #[test]
    fn raw_classification_honors_the_caller_timeout() {
        let file = tempfile().expect("create timeout fixture");
        file.set_len(4096).expect("size timeout fixture");
        assert_eq!(
            classify_raw_partition(&file, 4096, Duration::from_millis(1), || {
                std::thread::sleep(Duration::from_millis(2));
                Ok(())
            }),
            Err(ProfileClassifierError::OperationTimedOut)
        );
        assert_eq!(
            classify_partition_with_timeout(&file, Duration::ZERO, || Ok(())).err(),
            Some(ProfileClassifierError::OperationTimedOut)
        );
    }

    #[test]
    fn nonzero_media_requires_exact_raw_dual_headers() {
        let mut file = tempfile().expect("create mismatch fixture");
        file.set_len(8192).expect("size mismatch fixture");
        file.write_all(&[1]).expect("write mismatch fixture");
        let mismatch = classify_raw_partition(&file, 8192, ZERO_SCAN_TIMEOUT, || Ok(()))
            .expect("mismatch classification");
        assert!(matches!(mismatch, VaultPartitionProfile::ProfileMismatch));

        let (exact_file, _) = dual_luks_file();
        let exact = classify_raw_partition(
            &exact_file,
            2 * LUKS_HEADER_BYTES as u64,
            ZERO_SCAN_TIMEOUT,
            || Ok(()),
        )
        .expect("outer classification");
        assert!(matches!(exact, VaultPartitionProfile::Locked(_)));
    }

    #[test]
    fn dual_luks_headers_require_two_valid_matching_copies() {
        let (file, json) = dual_luks_file();
        assert!(verify_outer_luks_json(&json));
        let evidence = verify_dual_luks_headers(&file).expect("dual header evidence");
        assert_eq!(evidence.uuid(), *b"11111111-1111-4111-8111-111111111111");
        assert_eq!(evidence.sequence(), 3);

        file.write_all_at(&[1], LUKS_HEADER_BYTES as u64 + 512)
            .expect("tamper secondary header");
        assert!(verify_dual_luks_headers(&file).is_none());
    }

    #[test]
    fn corrupt_redundant_header_stays_byte_identical_and_is_a_mismatch() {
        let (file, _) = dual_luks_file();
        file.write_all_at(&[1], LUKS_HEADER_BYTES as u64)
            .expect("corrupt secondary magic");
        let mut before = vec![0_u8; 2 * LUKS_HEADER_BYTES];
        read_exact_at(&file, &mut before, 0).expect("read corrupt headers before classification");

        let classified =
            classify_raw_partition(&file, before.len() as u64, ZERO_SCAN_TIMEOUT, || Ok(()))
                .expect("classify corrupt headers");
        assert!(matches!(classified, VaultPartitionProfile::ProfileMismatch));

        let mut after = vec![0_u8; before.len()];
        read_exact_at(&file, &mut after, 0).expect("read corrupt headers after classification");
        assert_eq!(
            after, before,
            "classification must not repair a LUKS header"
        );
    }

    #[test]
    fn classifier_has_no_external_tool_execution_path() {
        let source = include_str!("profile_classifier.rs");
        for forbidden in [
            ["crypt", "setup"].concat(),
            ["Command", "::new"].concat(),
            ["std::", "process"].concat(),
            ["bounded", "_process"].concat(),
        ] {
            assert!(
                !source.contains(&forbidden),
                "classifier source contains forbidden execution primitive"
            );
        }
    }

    #[test]
    fn ext4_profile_binds_checksums_journal_inode_and_jbd2_superblock() {
        let file = ext4_file(EXT4_JOURNAL_BLOCKS as u16);
        let evidence = parse_ext4_profile(&file, &mut || Ok(()), Ext4CheckPhase::PreMount)
            .expect("ext4 read")
            .expect("ext4 profile");
        assert_eq!(
            evidence.uuid(),
            [
                0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x42, 0x22, 0x82, 0x22, 0x22, 0x22, 0x22, 0x22,
                0x22, 0x22,
            ]
        );
        assert_eq!(evidence.journal_start_block(), 557_056);

        set_jbd2_checksum_v3(&file);
        assert!(
            parse_ext4_profile(&file, &mut || Ok(()), Ext4CheckPhase::PreMount)
                .expect("checksum-v3 journal read")
                .is_some()
        );

        file.write_all_at(
            &0x0000_0013_u32.to_be_bytes(),
            557_056 * EXT4_BLOCK_BYTES + 0x28,
        )
        .expect("tamper jbd2 features");
        let mut feature_tamper = [0_u8; JBD2_SUPERBLOCK_BYTES];
        read_exact_at(&file, &mut feature_tamper, 557_056 * EXT4_BLOCK_BYTES)
            .expect("read feature-tampered jbd2 fixture");
        put_be32(&mut feature_tamper, JBD2_CHECKSUM_OFFSET, 0);
        let feature_tamper_checksum = crc32c(!0, &feature_tamper);
        put_be32(
            &mut feature_tamper,
            JBD2_CHECKSUM_OFFSET,
            feature_tamper_checksum,
        );
        file.write_all_at(&feature_tamper, 557_056 * EXT4_BLOCK_BYTES)
            .expect("write feature-tampered jbd2 fixture");
        assert!(
            parse_ext4_profile(&file, &mut || Ok(()), Ext4CheckPhase::PreMount)
                .expect("feature-tampered journal read")
                .is_none()
        );

        set_jbd2_checksum_v3(&file);
        let mut checksum_tamper = [0_u8; JBD2_SUPERBLOCK_BYTES];
        read_exact_at(&file, &mut checksum_tamper, 557_056 * EXT4_BLOCK_BYTES)
            .expect("read checksum-v3 jbd2 fixture");
        checksum_tamper[JBD2_CHECKSUM_OFFSET] ^= 1;
        file.write_all_at(&checksum_tamper, 557_056 * EXT4_BLOCK_BYTES)
            .expect("write checksum-tampered jbd2 fixture");
        assert!(
            parse_ext4_profile(&file, &mut || Ok(()), Ext4CheckPhase::PreMount)
                .expect("checksum-tampered journal read")
                .is_none()
        );

        let short_journal = ext4_file((EXT4_JOURNAL_BLOCKS / 2) as u16);
        assert!(
            parse_ext4_profile(&short_journal, &mut || Ok(()), Ext4CheckPhase::PreMount,)
                .expect("short journal read")
                .is_none()
        );
        set_jbd2_checksum_v3(&file);
        file.write_all_at(&[0], 557_056 * EXT4_BLOCK_BYTES)
            .expect("tamper jbd2 magic");
        assert!(
            parse_ext4_profile(&file, &mut || Ok(()), Ext4CheckPhase::PreMount)
                .expect("tampered journal read")
                .is_none()
        );
    }

    #[test]
    fn ext4_runtime_profiles_are_exact_for_each_mount_phase() {
        let clean = ext4_file(EXT4_JOURNAL_BLOCKS as u16);
        let clean_evidence = parse_ext4_profile(&clean, &mut || Ok(()), Ext4CheckPhase::PreMount)
            .expect("clean pre-mount ext4 read")
            .expect("clean pre-mount ext4 profile");
        assert!(
            parse_ext4_profile(&clean, &mut || Ok(()), Ext4CheckPhase::Mounted)
                .expect("clean mounted ext4 read")
                .is_none(),
            "an active rw mount must carry the journal-recovery incompatibility bit"
        );

        let recovering = ext4_file(EXT4_JOURNAL_BLOCKS as u16);
        set_jbd2_recovery_checksum_v3(&recovering);
        set_ext4_runtime_fields(
            &recovering,
            1,
            EXT4_INCOMPAT_FEATURES | EXT4_INCOMPAT_RECOVER,
            0,
        );
        let recovering_pre_mount =
            parse_ext4_profile(&recovering, &mut || Ok(()), Ext4CheckPhase::PreMount)
                .expect("recovery pre-mount ext4 read")
                .expect("canonical recovery pre-mount ext4 profile");
        let recovering_mounted =
            parse_ext4_profile(&recovering, &mut || Ok(()), Ext4CheckPhase::Mounted)
                .expect("recovery mounted ext4 read")
                .expect("canonical mounted ext4 profile");
        assert_eq!(recovering_pre_mount, clean_evidence);
        assert_eq!(recovering_mounted, clean_evidence);
    }

    #[test]
    fn ext4_recovery_jbd2_profile_is_exact_and_bounded() {
        let exact = ext4_file(EXT4_JOURNAL_BLOCKS as u16);
        set_ext4_runtime_fields(&exact, 1, EXT4_INCOMPAT_FEATURES_WITH_RECOVERY, 0);
        set_jbd2_recovery_checksum_v3(&exact);
        assert!(
            parse_ext4_profile(&exact, &mut || Ok(()), Ext4CheckPhase::PreMount)
                .expect("exact recovery journal read")
                .is_some()
        );

        for (offset, value, description) in [
            (0x1c, 0, "zero start"),
            (0x1c, EXT4_JOURNAL_BLOCKS as u32, "out-of-range start"),
            (
                0x28,
                JBD2_FEATURE_INCOMPAT_64BIT_CSUM_V3 | 0x20,
                "fast-commit feature",
            ),
            (0x58, EXT4_JOURNAL_BLOCKS as u32, "out-of-range head"),
        ] {
            let file = ext4_file(EXT4_JOURNAL_BLOCKS as u16);
            set_ext4_runtime_fields(&file, 1, EXT4_INCOMPAT_FEATURES_WITH_RECOVERY, 0);
            set_jbd2_recovery_checksum_v3(&file);
            update_jbd2_superblock(&file, |journal| put_be32(journal, offset, value));
            assert!(
                parse_ext4_profile(&file, &mut || Ok(()), Ext4CheckPhase::PreMount)
                    .expect("noncanonical recovery journal read")
                    .is_none(),
                "accepted recovery journal with {description}"
            );
        }

        let bad_checksum = ext4_file(EXT4_JOURNAL_BLOCKS as u16);
        set_ext4_runtime_fields(&bad_checksum, 1, EXT4_INCOMPAT_FEATURES_WITH_RECOVERY, 0);
        set_jbd2_recovery_checksum_v3(&bad_checksum);
        let checksum_offset = 557_056 * EXT4_BLOCK_BYTES + JBD2_CHECKSUM_OFFSET as u64;
        let mut checksum_byte = [0_u8; 1];
        read_exact_at(&bad_checksum, &mut checksum_byte, checksum_offset)
            .expect("read recovery journal checksum byte");
        checksum_byte[0] ^= 1;
        bad_checksum
            .write_all_at(&checksum_byte, checksum_offset)
            .expect("tamper recovery journal checksum");
        assert!(
            parse_ext4_profile(&bad_checksum, &mut || Ok(()), Ext4CheckPhase::PreMount,)
                .expect("bad-checksum recovery journal read")
                .is_none()
        );
    }

    #[test]
    fn ext4_runtime_profiles_reject_every_noncanonical_combination() {
        for (state, incompat, last_orphan) in [
            (0, EXT4_INCOMPAT_FEATURES | EXT4_INCOMPAT_RECOVER, 0),
            (3, EXT4_INCOMPAT_FEATURES | EXT4_INCOMPAT_RECOVER, 0),
            (1, EXT4_INCOMPAT_FEATURES | EXT4_INCOMPAT_RECOVER, 1),
            (1, EXT4_INCOMPAT_FEATURES | EXT4_INCOMPAT_RECOVER | 1, 0),
            (1, EXT4_INCOMPAT_FEATURES & !2, 0),
        ] {
            for phase in [Ext4CheckPhase::PreMount, Ext4CheckPhase::Mounted] {
                let file = ext4_file(EXT4_JOURNAL_BLOCKS as u16);
                set_ext4_runtime_fields(&file, state, incompat, last_orphan);
                assert!(
                    parse_ext4_profile(&file, &mut || Ok(()), phase)
                        .expect("noncanonical ext4 read")
                        .is_none(),
                    "accepted state={state:#x} incompat={incompat:#x} last_orphan={last_orphan}"
                );
            }
        }
    }

    #[test]
    fn ext4_recovery_runtime_fields_require_a_fresh_superblock_checksum() {
        let file = ext4_file(EXT4_JOURNAL_BLOCKS as u16);
        file.write_all_at(
            &(EXT4_INCOMPAT_FEATURES | EXT4_INCOMPAT_RECOVER).to_le_bytes(),
            EXT4_SUPERBLOCK_OFFSET + 0x60,
        )
        .expect("write recovery bit without refreshing superblock checksum");
        assert!(
            parse_ext4_profile(&file, &mut || Ok(()), Ext4CheckPhase::PreMount)
                .expect("stale-checksum recovery ext4 read")
                .is_none()
        );
    }
}
