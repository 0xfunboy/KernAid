//! Pure canonical fingerprint for one observed physical parent block device.
//!
//! This module performs no kernel observation and grants no device authority.
//! Callers must obtain and validate the numeric claims at their own trusted
//! Linux boundary before applying the shared byte-level formula.

use sha2::{Digest, Sha256};

const PHYSICAL_PARENT_DOMAIN: &[u8] = b"KERNAID-REPAIR-PHYSICAL-PARENT-V1\0";

/// Numeric kernel claims that identify the physical parent for one live
/// Repair transaction. Boot-local values are intentionally part of this
/// fingerprint; it is not a durable media identifier.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PhysicalParentClaims {
    parent_major: u32,
    parent_minor: u32,
    disk_sequence: u64,
    media_sector_count: u64,
    logical_sector_bytes: u64,
}

impl PhysicalParentClaims {
    pub const fn new(
        parent_major: u32,
        parent_minor: u32,
        disk_sequence: u64,
        media_sector_count: u64,
        logical_sector_bytes: u64,
    ) -> Self {
        Self {
            parent_major,
            parent_minor,
            disk_sequence,
            media_sector_count,
            logical_sector_bytes,
        }
    }

    pub const fn parent_major(&self) -> u32 {
        self.parent_major
    }

    pub const fn parent_minor(&self) -> u32 {
        self.parent_minor
    }

    pub const fn disk_sequence(&self) -> u64 {
        self.disk_sequence
    }

    pub const fn media_sector_count(&self) -> u64 {
        self.media_sector_count
    }

    pub const fn logical_sector_bytes(&self) -> u64 {
        self.logical_sector_bytes
    }
}

/// Applies the canonical V1 byte formula and returns the SHA-256 digest.
pub fn canonical_physical_parent_digest(claims: &PhysicalParentClaims) -> [u8; 32] {
    let mut digest = Sha256::new();
    digest.update(PHYSICAL_PARENT_DOMAIN);
    digest.update(claims.parent_major.to_be_bytes());
    digest.update(claims.parent_minor.to_be_bytes());
    digest.update(claims.disk_sequence.to_be_bytes());
    digest.update(claims.media_sector_count.to_be_bytes());
    digest.update(claims.logical_sector_bytes.to_be_bytes());
    digest.finalize().into()
}

/// Renders the raw lowercase hexadecimal form used by the Repair Vault wire.
pub fn render_physical_parent_raw(digest: &[u8; 32]) -> String {
    encode_hex(digest)
}

/// Renders the `sha256:`-prefixed form used by the repair transaction plan.
pub fn render_physical_parent_prefixed(digest: &[u8; 32]) -> String {
    let mut rendered = String::with_capacity(7 + digest.len() * 2);
    rendered.push_str("sha256:");
    rendered.push_str(&encode_hex(digest));
    rendered
}

fn encode_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut encoded = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        encoded.push(HEX[(byte >> 4) as usize] as char);
        encoded.push(HEX[(byte & 0x0f) as usize] as char);
    }
    encoded
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn golden_vector_is_byte_exact_in_both_renderings() {
        let claims = PhysicalParentClaims::new(8, 16, 77, 62_500_000, 512);
        let digest = canonical_physical_parent_digest(&claims);
        assert_eq!(
            digest,
            [
                0xce, 0x1b, 0x61, 0xe9, 0x7e, 0xcf, 0xb9, 0x7d, 0x8b, 0x75, 0xe1, 0xf3, 0xcf, 0xbe,
                0x5f, 0x83, 0xc2, 0x4b, 0x52, 0x80, 0x5d, 0xef, 0x53, 0x2b, 0xf5, 0xdf, 0x3f, 0xdf,
                0x59, 0x88, 0x1d, 0xe4,
            ]
        );
        assert_eq!(
            render_physical_parent_raw(&digest),
            "ce1b61e97ecfb97d8b75e1f3cfbe5f83c24b52805def532bf5df3fdf59881de4"
        );
        assert_eq!(
            render_physical_parent_prefixed(&digest),
            "sha256:ce1b61e97ecfb97d8b75e1f3cfbe5f83c24b52805def532bf5df3fdf59881de4"
        );
    }
}
