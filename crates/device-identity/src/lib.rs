#![forbid(unsafe_code)]
//! Local Ed25519 device identity used to sign immutable report bytes. The seed
//! is intended to live only inside the OS keychain or the Rescue LUKS2 vault.

use base64::{Engine as _, decoded_len_estimate, engine::general_purpose::URL_SAFE_NO_PAD};
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use rand_core::OsRng;
use serde::{Deserialize, Deserializer, Serialize, de};
use serde_json::value::RawValue;
use sha2::{Digest, Sha256};
use std::fmt;
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

const SIGNED_REPORT_DOMAIN: &[u8] = b"KERNAID-SIGNED-REPORT-V1\0";
const SIGNED_REPORT_ENVELOPE_DOMAIN: &[u8] = b"KERNAID-SIGNED-REPORT-ENVELOPE-V1\0";
const PUBLIC_KEY_BYTES: usize = 32;
const SIGNATURE_BYTES: usize = 64;
const HASH_BYTES: usize = 32;
const MAX_MEDIA_TYPE_BYTES: usize = 255;
const MAX_PROTOCOL_DOMAIN_BYTES: usize = 255;
const MAX_PROTOCOL_PAYLOAD_BYTES: usize = 1024 * 1024;

pub const SIGNED_REPORT_ENVELOPE_SCHEMA: &str =
    "https://schemas.kernaid.dev/v1/signed-report-envelope.json";
pub const SIGNED_REPORT_ENVELOPE_KIND: &str = "kernaid.signed-report";
pub const SIGNED_REPORT_ENVELOPE_ALGORITHM: &str = "Ed25519";
pub const MAX_SIGNED_REPORT_PAYLOAD_BYTES: usize = 1024 * 1024;

pub struct DeviceIdentity {
    signing_key: SigningKey,
}

#[derive(Clone, PartialEq, Eq)]
pub struct SignedReport {
    pub payload: Vec<u8>,
    pub public_key: [u8; PUBLIC_KEY_BYTES],
    pub signature: [u8; SIGNATURE_BYTES],
}

/// Portable JSON report bundle whose complete semantic content is signed.
#[derive(Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SignedReportEnvelope {
    pub schema: String,
    pub kind: String,
    pub algorithm: String,
    pub device_id: String,
    pub journal_sequence: u64,
    pub journal_entry_hash: String,
    pub payload_media_type: String,
    pub payload_sha256: String,
    pub payload: String,
    pub public_key: String,
    pub signature: String,
}

impl<'de> Deserialize<'de> for SignedReportEnvelope {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        // serde_json's borrowed RawValue path scans structure without decoding
        // customer strings into its ordinary scratch Vec. All decoding is
        // delegated to the zeroizing parser below.
        let raw = <&RawValue>::deserialize(deserializer)?;
        SignedReportEnvelopeParser::parse(raw.get())
            .ok_or_else(|| de::Error::custom("invalid signed report envelope"))
    }
}

struct SensitiveEnvelopeString(Zeroizing<String>);

impl SensitiveEnvelopeString {
    fn as_str(&self) -> &str {
        self.0.as_str()
    }
}

impl Zeroize for SensitiveEnvelopeString {
    fn zeroize(&mut self) {
        self.0.zeroize();
    }
}

impl ZeroizeOnDrop for SensitiveEnvelopeString {}

#[derive(Default)]
struct SignedReportEnvelopeFields {
    schema: Option<SensitiveEnvelopeString>,
    kind: Option<SensitiveEnvelopeString>,
    algorithm: Option<SensitiveEnvelopeString>,
    device_id: Option<SensitiveEnvelopeString>,
    journal_sequence: Option<u64>,
    journal_entry_hash: Option<SensitiveEnvelopeString>,
    payload_media_type: Option<SensitiveEnvelopeString>,
    payload_sha256: Option<SensitiveEnvelopeString>,
    payload: Option<SensitiveEnvelopeString>,
    public_key: Option<SensitiveEnvelopeString>,
    signature: Option<SensitiveEnvelopeString>,
}

impl SignedReportEnvelopeFields {
    fn finish(self) -> Option<SignedReportEnvelope> {
        let schema = self.schema.as_ref()?;
        let kind = self.kind.as_ref()?;
        let algorithm = self.algorithm.as_ref()?;
        let device_id = self.device_id.as_ref()?;
        let journal_sequence = self.journal_sequence?;
        let journal_entry_hash = self.journal_entry_hash.as_ref()?;
        let payload_media_type = self.payload_media_type.as_ref()?;
        let payload_sha256 = self.payload_sha256.as_ref()?;
        let payload = self.payload.as_ref()?;
        let public_key = self.public_key.as_ref()?;
        let signature = self.signature.as_ref()?;

        // All fallible presence checks happen before these clones. The new
        // strings become owned by a zeroizing SignedReportEnvelope without a
        // subsequent ordinary error path.
        Some(SignedReportEnvelope {
            schema: schema.as_str().to_owned(),
            kind: kind.as_str().to_owned(),
            algorithm: algorithm.as_str().to_owned(),
            device_id: device_id.as_str().to_owned(),
            journal_sequence,
            journal_entry_hash: journal_entry_hash.as_str().to_owned(),
            payload_media_type: payload_media_type.as_str().to_owned(),
            payload_sha256: payload_sha256.as_str().to_owned(),
            payload: payload.as_str().to_owned(),
            public_key: public_key.as_str().to_owned(),
            signature: signature.as_str().to_owned(),
        })
    }
}

struct SignedReportEnvelopeParser<'a> {
    raw: &'a str,
    offset: usize,
}

impl<'a> SignedReportEnvelopeParser<'a> {
    fn parse(raw: &'a str) -> Option<SignedReportEnvelope> {
        let mut parser = Self { raw, offset: 0 };
        let mut fields = SignedReportEnvelopeFields::default();
        parser.skip_whitespace();
        parser.consume_byte(b'{')?;
        parser.skip_whitespace();
        if parser.peek_byte() == Some(b'}') {
            parser.offset += 1;
        } else {
            loop {
                parser.skip_whitespace();
                let key = parser.parse_string()?;
                parser.skip_whitespace();
                parser.consume_byte(b':')?;
                parser.skip_whitespace();
                match key.as_str() {
                    "schema" => Self::parse_string_field(&mut parser, &mut fields.schema)?,
                    "kind" => Self::parse_string_field(&mut parser, &mut fields.kind)?,
                    "algorithm" => Self::parse_string_field(&mut parser, &mut fields.algorithm)?,
                    "deviceId" => Self::parse_string_field(&mut parser, &mut fields.device_id)?,
                    "journalSequence" => {
                        if fields.journal_sequence.is_some() {
                            return None;
                        }
                        fields.journal_sequence = Some(parser.parse_u64()?);
                    }
                    "journalEntryHash" => {
                        Self::parse_string_field(&mut parser, &mut fields.journal_entry_hash)?
                    }
                    "payloadMediaType" => {
                        Self::parse_string_field(&mut parser, &mut fields.payload_media_type)?
                    }
                    "payloadSha256" => {
                        Self::parse_string_field(&mut parser, &mut fields.payload_sha256)?
                    }
                    "payload" => Self::parse_string_field(&mut parser, &mut fields.payload)?,
                    "publicKey" => Self::parse_string_field(&mut parser, &mut fields.public_key)?,
                    "signature" => Self::parse_string_field(&mut parser, &mut fields.signature)?,
                    _ => return None,
                }
                parser.skip_whitespace();
                match parser.peek_byte()? {
                    b'}' => {
                        parser.offset += 1;
                        break;
                    }
                    b',' => parser.offset += 1,
                    _ => return None,
                }
            }
        }
        parser.skip_whitespace();
        if parser.offset != parser.raw.len() {
            return None;
        }
        fields.finish()
    }

    fn parse_string_field(
        parser: &mut Self,
        field: &mut Option<SensitiveEnvelopeString>,
    ) -> Option<()> {
        if field.is_some() {
            return None;
        }
        *field = Some(parser.parse_string()?);
        Some(())
    }

    fn parse_string(&mut self) -> Option<SensitiveEnvelopeString> {
        self.consume_byte(b'"')?;
        let start = self.offset;
        loop {
            match self.peek_byte()? {
                b'"' => {
                    let end = self.offset;
                    self.offset += 1;
                    return decode_json_string(self.raw.get(start..end)?);
                }
                b'\\' => {
                    self.offset += 1;
                    let escaped = self.peek_byte()?;
                    self.offset += 1;
                    if escaped == b'u' {
                        let end = self.offset.checked_add(4)?;
                        self.raw.as_bytes().get(self.offset..end)?;
                        self.offset = end;
                    }
                }
                0..=0x1f => return None,
                byte if byte.is_ascii() => self.offset += 1,
                _ => {
                    let character = self.raw.get(self.offset..)?.chars().next()?;
                    self.offset += character.len_utf8();
                }
            }
        }
    }

    fn parse_u64(&mut self) -> Option<u64> {
        let start = self.offset;
        match self.peek_byte()? {
            b'0' => self.offset += 1,
            b'1'..=b'9' => {
                self.offset += 1;
                while self.peek_byte().is_some_and(|byte| byte.is_ascii_digit()) {
                    self.offset += 1;
                }
            }
            _ => return None,
        }
        self.raw.get(start..self.offset)?.parse().ok()
    }

    fn consume_byte(&mut self, expected: u8) -> Option<()> {
        if self.peek_byte()? != expected {
            return None;
        }
        self.offset += 1;
        Some(())
    }

    fn peek_byte(&self) -> Option<u8> {
        self.raw.as_bytes().get(self.offset).copied()
    }

    fn skip_whitespace(&mut self) {
        while matches!(self.peek_byte(), Some(b' ' | b'\t' | b'\r' | b'\n')) {
            self.offset += 1;
        }
    }
}

fn decode_json_string(raw: &str) -> Option<SensitiveEnvelopeString> {
    let mut decoded = Zeroizing::new(String::with_capacity(raw.len()));
    let bytes = raw.as_bytes();
    let mut offset = 0;
    while offset < bytes.len() {
        match bytes[offset] {
            0..=0x1f => return None,
            b'\\' => {
                offset += 1;
                let escaped = *bytes.get(offset)?;
                offset += 1;
                match escaped {
                    b'"' => decoded.push('"'),
                    b'\\' => decoded.push('\\'),
                    b'/' => decoded.push('/'),
                    b'b' => decoded.push('\u{0008}'),
                    b'f' => decoded.push('\u{000c}'),
                    b'n' => decoded.push('\n'),
                    b'r' => decoded.push('\r'),
                    b't' => decoded.push('\t'),
                    b'u' => {
                        let (codepoint, next_offset) = decode_json_codepoint(bytes, offset)?;
                        offset = next_offset;
                        decoded.push(codepoint);
                    }
                    _ => return None,
                }
            }
            byte if byte.is_ascii() => {
                decoded.push(char::from(byte));
                offset += 1;
            }
            _ => {
                let character = raw.get(offset..)?.chars().next()?;
                decoded.push(character);
                offset += character.len_utf8();
            }
        }
    }
    debug_assert!(decoded.len() <= raw.len());
    Some(SensitiveEnvelopeString(decoded))
}

fn decode_json_codepoint(bytes: &[u8], offset: usize) -> Option<(char, usize)> {
    let (first, mut next_offset) = decode_hex_quad(bytes, offset)?;
    let scalar = if (0xd800..=0xdbff).contains(&first) {
        if bytes.get(next_offset..next_offset.checked_add(2)?)? != b"\\u" {
            return None;
        }
        next_offset += 2;
        let (second, end) = decode_hex_quad(bytes, next_offset)?;
        if !(0xdc00..=0xdfff).contains(&second) {
            return None;
        }
        next_offset = end;
        0x1_0000 + ((u32::from(first) - 0xd800) << 10) + (u32::from(second) - 0xdc00)
    } else {
        if (0xdc00..=0xdfff).contains(&first) {
            return None;
        }
        u32::from(first)
    };
    char::from_u32(scalar).map(|character| (character, next_offset))
}

fn decode_hex_quad(bytes: &[u8], offset: usize) -> Option<(u16, usize)> {
    let end = offset.checked_add(4)?;
    let value = bytes
        .get(offset..end)?
        .iter()
        .try_fold(0_u16, |value, digit| {
            let digit = match digit {
                b'0'..=b'9' => u16::from(*digit - b'0'),
                b'a'..=b'f' => u16::from(*digit - b'a' + 10),
                b'A'..=b'F' => u16::from(*digit - b'A' + 10),
                _ => return None,
            };
            Some((value << 4) | digit)
        })?;
    Some((value, end))
}

/// Authenticated report bytes kept in zeroizing memory for their full owned
/// lifetime. The payload can be borrowed but cannot be extracted as a plain
/// `Vec<u8>`.
#[must_use = "verified report payloads should be consumed while zeroizing protection is active"]
pub struct VerifiedReportPayload {
    bytes: Zeroizing<Vec<u8>>,
}

impl VerifiedReportPayload {
    fn new(bytes: Zeroizing<Vec<u8>>) -> Self {
        Self { bytes }
    }

    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        self.bytes.as_slice()
    }

    #[must_use]
    pub fn as_slice(&self) -> &[u8] {
        self.as_bytes()
    }

    #[must_use]
    pub fn len(&self) -> usize {
        self.bytes.len()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.bytes.is_empty()
    }
}

impl AsRef<[u8]> for VerifiedReportPayload {
    fn as_ref(&self) -> &[u8] {
        self.as_bytes()
    }
}

impl PartialEq for VerifiedReportPayload {
    fn eq(&self, other: &Self) -> bool {
        self.as_bytes() == other.as_bytes()
    }
}

impl Eq for VerifiedReportPayload {}

impl PartialEq<&[u8]> for VerifiedReportPayload {
    fn eq(&self, other: &&[u8]) -> bool {
        self.as_bytes() == *other
    }
}

impl Zeroize for VerifiedReportPayload {
    fn zeroize(&mut self) {
        self.bytes.zeroize();
    }
}

impl ZeroizeOnDrop for VerifiedReportPayload {}

impl fmt::Debug for SignedReport {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SignedReport")
            .field("payload_len", &self.payload.len())
            .field("public_key_len", &self.public_key.len())
            .field("signature_len", &self.signature.len())
            .finish_non_exhaustive()
    }
}

impl fmt::Debug for SignedReportEnvelope {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SignedReportEnvelope")
            .field("journal_sequence", &self.journal_sequence)
            .field("payload_base64url_len", &self.payload.len())
            .field("public_key_base64url_len", &self.public_key.len())
            .field("signature_base64url_len", &self.signature.len())
            .finish_non_exhaustive()
    }
}

impl fmt::Debug for VerifiedReportPayload {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("VerifiedReportPayload")
            .field("len", &self.len())
            .finish_non_exhaustive()
    }
}

impl Zeroize for SignedReport {
    fn zeroize(&mut self) {
        self.payload.zeroize();
        self.public_key.zeroize();
        self.signature.zeroize();
    }
}

impl Drop for SignedReport {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl ZeroizeOnDrop for SignedReport {}

impl Zeroize for SignedReportEnvelope {
    fn zeroize(&mut self) {
        self.schema.zeroize();
        self.kind.zeroize();
        self.algorithm.zeroize();
        self.device_id.zeroize();
        self.journal_sequence.zeroize();
        self.journal_entry_hash.zeroize();
        self.payload_media_type.zeroize();
        self.payload_sha256.zeroize();
        self.payload.zeroize();
        self.public_key.zeroize();
        self.signature.zeroize();
    }
}

impl Drop for SignedReportEnvelope {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl ZeroizeOnDrop for SignedReportEnvelope {}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum IdentityError {
    InvalidSeedLength,
    InvalidPublicKey,
    InvalidDeviceId,
    MissingTrustAnchor,
    UnexpectedPublicKey,
    UnexpectedDeviceId,
    InvalidSignature,
    InvalidEnvelopeField(&'static str),
    InvalidBase64Url(&'static str),
    InvalidPayloadMediaType,
    PayloadTooLarge,
    PayloadHashMismatch,
    InvalidProtocolDomain,
    ProtocolPayloadTooLarge,
}

impl DeviceIdentity {
    pub fn generate() -> Self {
        Self {
            signing_key: SigningKey::generate(&mut OsRng),
        }
    }

    pub fn from_seed(seed: &[u8]) -> Result<Self, IdentityError> {
        if seed.len() != 32 {
            return Err(IdentityError::InvalidSeedLength);
        }

        let mut seed_copy = Zeroizing::new([0_u8; 32]);
        seed_copy.copy_from_slice(seed);
        Ok(Self {
            signing_key: SigningKey::from_bytes(&seed_copy),
        })
    }

    pub fn export_seed_for_encrypted_storage(&self) -> Zeroizing<Vec<u8>> {
        Zeroizing::new(self.signing_key.as_bytes().to_vec())
    }

    pub fn public_key(&self) -> [u8; 32] {
        self.signing_key.verifying_key().to_bytes()
    }

    pub fn device_id(&self) -> String {
        device_id_for_public_key(&self.public_key())
    }

    /// Sign an application protocol payload without exposing or copying the
    /// device seed.
    ///
    /// `domain` must be a short, non-empty, NUL-terminated protocol constant.
    /// The Ed25519 message is exactly `domain || payload`; callers are
    /// responsible for supplying deterministic payload bytes. Keeping this
    /// operation on [`DeviceIdentity`] lets other KernAid protocols reuse the
    /// enrolled device key while its seed remains in the existing keychain or
    /// Rescue vault.
    pub fn sign_domain_separated_payload(
        &self,
        domain: &[u8],
        payload: &[u8],
    ) -> Result<[u8; SIGNATURE_BYTES], IdentityError> {
        if domain.is_empty()
            || domain.len() > MAX_PROTOCOL_DOMAIN_BYTES
            || domain.last() != Some(&0)
        {
            return Err(IdentityError::InvalidProtocolDomain);
        }
        if payload.len() > MAX_PROTOCOL_PAYLOAD_BYTES {
            return Err(IdentityError::ProtocolPayloadTooLarge);
        }

        let capacity = domain
            .len()
            .checked_add(payload.len())
            .ok_or(IdentityError::ProtocolPayloadTooLarge)?;
        let mut message = Zeroizing::new(Vec::with_capacity(capacity));
        message.extend_from_slice(domain);
        message.extend_from_slice(payload);
        Ok(self.signing_key.sign(message.as_slice()).to_bytes())
    }

    pub fn sign_report(&self, payload: &[u8]) -> SignedReport {
        let signature = self.signing_key.sign(&report_signature_message(payload));
        SignedReport {
            payload: payload.to_vec(),
            public_key: self.public_key(),
            signature: signature.to_bytes(),
        }
    }

    /// Sign a bounded payload together with its media type and journal head.
    pub fn sign_report_envelope(
        &self,
        payload: &[u8],
        payload_media_type: &str,
        journal_sequence: u64,
        journal_entry_hash: &[u8; HASH_BYTES],
    ) -> Result<SignedReportEnvelope, IdentityError> {
        validate_payload(payload)?;
        validate_media_type(payload_media_type)?;
        if journal_sequence == 0 {
            return Err(IdentityError::InvalidEnvelopeField("journalSequence"));
        }

        let public_key = self.public_key();
        let device_id = self.device_id();
        let payload_hash: [u8; HASH_BYTES] = Sha256::digest(payload).into();
        let content = EnvelopeContent {
            schema: SIGNED_REPORT_ENVELOPE_SCHEMA,
            kind: SIGNED_REPORT_ENVELOPE_KIND,
            algorithm: SIGNED_REPORT_ENVELOPE_ALGORITHM,
            device_id: &device_id,
            journal_sequence,
            journal_entry_hash,
            payload_media_type,
            payload_sha256: &payload_hash,
            payload,
            public_key: &public_key,
        };
        let signature = self
            .signing_key
            .sign(&envelope_signature_message(&content))
            .to_bytes();

        Ok(SignedReportEnvelope {
            schema: SIGNED_REPORT_ENVELOPE_SCHEMA.to_owned(),
            kind: SIGNED_REPORT_ENVELOPE_KIND.to_owned(),
            algorithm: SIGNED_REPORT_ENVELOPE_ALGORITHM.to_owned(),
            device_id,
            journal_sequence,
            journal_entry_hash: encode_base64url(journal_entry_hash),
            payload_media_type: payload_media_type.to_owned(),
            payload_sha256: encode_base64url(&payload_hash),
            payload: encode_base64url(payload),
            public_key: encode_base64url(&public_key),
            signature: encode_base64url(&signature),
        })
    }
}

impl SignedReport {
    /// Verifies this report against a key pinned by the caller.
    ///
    /// The embedded `public_key` is report metadata only. It must match the
    /// caller's trusted key, and is never used as the trust anchor.
    pub fn verify(&self, expected_public_key: &[u8; 32]) -> Result<(), IdentityError> {
        if &self.public_key != expected_public_key {
            return Err(IdentityError::UnexpectedPublicKey);
        }

        let public_key = VerifyingKey::from_bytes(expected_public_key)
            .map_err(|_| IdentityError::InvalidPublicKey)?;
        let signature = Signature::from_bytes(&self.signature);
        public_key
            .verify_strict(&report_signature_message(&self.payload), &signature)
            .map_err(|_| IdentityError::InvalidSignature)
    }
}

impl SignedReportEnvelope {
    /// Verify against a caller-pinned key and return the authenticated payload
    /// in zeroizing memory.
    ///
    /// The embedded key is never a trust anchor. All binary JSON fields must be
    /// canonical base64url without padding before the signature is considered.
    pub fn verify(
        &self,
        expected_public_key: &[u8; PUBLIC_KEY_BYTES],
    ) -> Result<VerifiedReportPayload, IdentityError> {
        self.verify_zeroizing(expected_public_key)
    }

    /// Verify against a caller-pinned key without ever owning the decoded
    /// payload in a plain `Vec<u8>`.
    pub fn verify_zeroizing(
        &self,
        expected_public_key: &[u8; PUBLIC_KEY_BYTES],
    ) -> Result<VerifiedReportPayload, IdentityError> {
        validate_constant_field("schema", &self.schema, SIGNED_REPORT_ENVELOPE_SCHEMA)?;
        validate_constant_field("kind", &self.kind, SIGNED_REPORT_ENVELOPE_KIND)?;
        validate_constant_field(
            "algorithm",
            &self.algorithm,
            SIGNED_REPORT_ENVELOPE_ALGORITHM,
        )?;
        if self.journal_sequence == 0 {
            return Err(IdentityError::InvalidEnvelopeField("journalSequence"));
        }
        validate_media_type(&self.payload_media_type)?;

        let embedded_public_key =
            decode_fixed_base64url::<PUBLIC_KEY_BYTES>(&self.public_key, "publicKey")?;
        if &embedded_public_key != expected_public_key {
            return Err(IdentityError::UnexpectedPublicKey);
        }
        let public_key = VerifyingKey::from_bytes(expected_public_key)
            .map_err(|_| IdentityError::InvalidPublicKey)?;
        let expected_device_id = device_id_for_public_key(expected_public_key);
        if self.device_id != expected_device_id {
            return Err(IdentityError::InvalidEnvelopeField("deviceId"));
        }

        let journal_entry_hash =
            decode_fixed_base64url::<HASH_BYTES>(&self.journal_entry_hash, "journalEntryHash")?;
        let payload_hash =
            decode_fixed_base64url::<HASH_BYTES>(&self.payload_sha256, "payloadSha256")?;
        let payload = decode_payload(&self.payload)?;
        let actual_payload_hash: [u8; HASH_BYTES] = Sha256::digest(&payload).into();
        if payload_hash != actual_payload_hash {
            return Err(IdentityError::PayloadHashMismatch);
        }
        let signature = decode_fixed_base64url::<SIGNATURE_BYTES>(&self.signature, "signature")?;

        let content = EnvelopeContent {
            schema: &self.schema,
            kind: &self.kind,
            algorithm: &self.algorithm,
            device_id: &self.device_id,
            journal_sequence: self.journal_sequence,
            journal_entry_hash: &journal_entry_hash,
            payload_media_type: &self.payload_media_type,
            payload_sha256: &payload_hash,
            payload: &payload,
            public_key: &embedded_public_key,
        };
        public_key
            .verify_strict(
                &envelope_signature_message(&content),
                &Signature::from_bytes(&signature),
            )
            .map_err(|_| IdentityError::InvalidSignature)?;
        Ok(VerifiedReportPayload::new(payload))
    }

    /// Verify using one or both explicit trust anchors.
    ///
    /// When only a device ID is supplied, the embedded public key is accepted
    /// only after its derived device ID matches the caller-pinned value. The
    /// embedded key is therefore never sufficient on its own. When both
    /// anchors are supplied, they must identify the same key.
    pub fn verify_with_trust_anchors(
        &self,
        expected_device_id: Option<&str>,
        expected_public_key: Option<&[u8; PUBLIC_KEY_BYTES]>,
    ) -> Result<VerifiedReportPayload, IdentityError> {
        if expected_device_id.is_none() && expected_public_key.is_none() {
            return Err(IdentityError::MissingTrustAnchor);
        }
        if let Some(device_id) = expected_device_id {
            validate_device_id(device_id)?;
        }

        match expected_public_key {
            Some(public_key) => {
                if expected_device_id
                    .is_some_and(|device_id| device_id_for_public_key(public_key) != device_id)
                {
                    return Err(IdentityError::UnexpectedDeviceId);
                }
                self.verify_zeroizing(public_key)
            }
            None => self
                .verify_for_device_id(expected_device_id.ok_or(IdentityError::MissingTrustAnchor)?),
        }
    }

    /// Verify against a caller-pinned KernAid device ID.
    ///
    /// This authenticates the embedded public key by its 96-bit device
    /// fingerprint before using that key for signature verification.
    pub fn verify_for_device_id(
        &self,
        expected_device_id: &str,
    ) -> Result<VerifiedReportPayload, IdentityError> {
        validate_device_id(expected_device_id)?;
        let embedded_public_key =
            decode_fixed_base64url::<PUBLIC_KEY_BYTES>(&self.public_key, "publicKey")?;
        if device_id_for_public_key(&embedded_public_key) != expected_device_id {
            return Err(IdentityError::UnexpectedDeviceId);
        }
        self.verify_zeroizing(&embedded_public_key)
    }
}

/// Decode a canonical unpadded base64url Ed25519 public key.
pub fn decode_public_key_base64url(encoded: &str) -> Result<[u8; 32], IdentityError> {
    decode_fixed_base64url::<PUBLIC_KEY_BYTES>(encoded, "publicKey")
}

/// Validate the canonical `KA-` device fingerprint form.
pub fn validate_device_id(device_id: &str) -> Result<(), IdentityError> {
    let Some(hex) = device_id.strip_prefix("KA-") else {
        return Err(IdentityError::InvalidDeviceId);
    };
    if hex.len() != 24
        || !hex
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(IdentityError::InvalidDeviceId);
    }
    Ok(())
}

struct EnvelopeContent<'a> {
    schema: &'a str,
    kind: &'a str,
    algorithm: &'a str,
    device_id: &'a str,
    journal_sequence: u64,
    journal_entry_hash: &'a [u8; HASH_BYTES],
    payload_media_type: &'a str,
    payload_sha256: &'a [u8; HASH_BYTES],
    payload: &'a [u8],
    public_key: &'a [u8; PUBLIC_KEY_BYTES],
}

fn envelope_signature_message(content: &EnvelopeContent<'_>) -> Zeroizing<Vec<u8>> {
    let capacity = SIGNED_REPORT_ENVELOPE_DOMAIN.len()
        + 8
        + content.schema.len()
        + 8
        + content.kind.len()
        + 8
        + content.algorithm.len()
        + 8
        + content.device_id.len()
        + 8
        + 8
        + content.journal_entry_hash.len()
        + 8
        + content.payload_media_type.len()
        + 8
        + content.payload_sha256.len()
        + 8
        + content.payload.len()
        + 8
        + content.public_key.len();
    let mut message = Zeroizing::new(Vec::with_capacity(capacity));
    message.extend_from_slice(SIGNED_REPORT_ENVELOPE_DOMAIN);
    append_length_prefixed(&mut message, content.schema.as_bytes());
    append_length_prefixed(&mut message, content.kind.as_bytes());
    append_length_prefixed(&mut message, content.algorithm.as_bytes());
    append_length_prefixed(&mut message, content.device_id.as_bytes());
    message.extend_from_slice(&content.journal_sequence.to_be_bytes());
    append_length_prefixed(&mut message, content.journal_entry_hash);
    append_length_prefixed(&mut message, content.payload_media_type.as_bytes());
    append_length_prefixed(&mut message, content.payload_sha256);
    append_length_prefixed(&mut message, content.payload);
    append_length_prefixed(&mut message, content.public_key);
    debug_assert_eq!(message.len(), capacity);
    message
}

fn append_length_prefixed(message: &mut Vec<u8>, value: &[u8]) {
    message.extend_from_slice(&(value.len() as u64).to_be_bytes());
    message.extend_from_slice(value);
}

fn validate_constant_field(
    field: &'static str,
    actual: &str,
    expected: &str,
) -> Result<(), IdentityError> {
    if actual != expected {
        return Err(IdentityError::InvalidEnvelopeField(field));
    }
    Ok(())
}

fn validate_payload(payload: &[u8]) -> Result<(), IdentityError> {
    if payload.len() > MAX_SIGNED_REPORT_PAYLOAD_BYTES {
        return Err(IdentityError::PayloadTooLarge);
    }
    Ok(())
}

fn validate_media_type(media_type: &str) -> Result<(), IdentityError> {
    let bytes = media_type.as_bytes();
    let mut semicolon_parts = media_type.splitn(2, ';');
    let essence = semicolon_parts.next().unwrap_or_default();
    let parameters_are_valid = semicolon_parts
        .next()
        .is_none_or(|parameters| !parameters.trim().is_empty());
    let mut type_parts = essence.split('/');
    let major = type_parts.next().unwrap_or_default();
    let minor = type_parts.next().unwrap_or_default();
    let has_valid_essence =
        type_parts.next().is_none() && is_media_type_token(major) && is_media_type_token(minor);
    if bytes.is_empty()
        || bytes.len() > MAX_MEDIA_TYPE_BYTES
        || !bytes.iter().all(|byte| (0x20..=0x7e).contains(byte))
        || media_type.trim() != media_type
        || !has_valid_essence
        || !parameters_are_valid
    {
        return Err(IdentityError::InvalidPayloadMediaType);
    }
    Ok(())
}

fn is_media_type_token(value: &str) -> bool {
    !value.is_empty()
        && value.bytes().all(|byte| {
            byte.is_ascii_alphanumeric()
                || matches!(
                    byte,
                    b'!' | b'#'
                        | b'$'
                        | b'%'
                        | b'&'
                        | b'\''
                        | b'*'
                        | b'+'
                        | b'-'
                        | b'.'
                        | b'^'
                        | b'_'
                        | b'`'
                        | b'|'
                        | b'~'
                )
        })
}

fn decode_payload(encoded: &str) -> Result<Zeroizing<Vec<u8>>, IdentityError> {
    let max_encoded_bytes = MAX_SIGNED_REPORT_PAYLOAD_BYTES.div_ceil(3) * 4;
    if encoded.len() > max_encoded_bytes {
        return Err(IdentityError::PayloadTooLarge);
    }
    let decoded = decode_base64url(encoded, "payload")?;
    validate_payload(&decoded)?;
    Ok(decoded)
}

fn decode_fixed_base64url<const N: usize>(
    encoded: &str,
    field: &'static str,
) -> Result<[u8; N], IdentityError> {
    let expected_encoded_bytes = (N / 3) * 4
        + match N % 3 {
            0 => 0,
            1 => 2,
            _ => 3,
        };
    if encoded.len() != expected_encoded_bytes {
        return Err(IdentityError::InvalidBase64Url(field));
    }
    let decoded = decode_base64url(encoded, field)?;
    decoded
        .as_slice()
        .try_into()
        .map_err(|_| IdentityError::InvalidBase64Url(field))
}

fn decode_base64url(
    encoded: &str,
    field: &'static str,
) -> Result<Zeroizing<Vec<u8>>, IdentityError> {
    let mut decoded = Zeroizing::new(vec![0_u8; decoded_len_estimate(encoded.len())]);
    let decoded_len = URL_SAFE_NO_PAD
        .decode_slice(encoded, decoded.as_mut_slice())
        .map_err(|_| IdentityError::InvalidBase64Url(field))?;
    decoded.truncate(decoded_len);

    let mut canonical = Zeroizing::new(vec![0_u8; encoded.len()]);
    let canonical_len = URL_SAFE_NO_PAD
        .encode_slice(decoded.as_slice(), canonical.as_mut_slice())
        .map_err(|_| IdentityError::InvalidBase64Url(field))?;
    canonical.truncate(canonical_len);
    if canonical.as_slice() != encoded.as_bytes() {
        return Err(IdentityError::InvalidBase64Url(field));
    }
    Ok(decoded)
}

fn encode_base64url(value: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(value)
}

pub fn device_id_for_public_key(public_key: &[u8; PUBLIC_KEY_BYTES]) -> String {
    let digest = Sha256::digest(public_key);
    let short = digest[..12]
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    format!("KA-{short}")
}

fn report_signature_message(payload: &[u8]) -> Zeroizing<Vec<u8>> {
    signature_message(SIGNED_REPORT_DOMAIN, payload)
}

fn signature_message(domain: &[u8], payload: &[u8]) -> Zeroizing<Vec<u8>> {
    let payload_len = payload.len() as u128;
    let mut message = Zeroizing::new(Vec::with_capacity(domain.len() + 16 + payload.len()));
    message.extend_from_slice(domain);
    message.extend_from_slice(&payload_len.to_be_bytes());
    message.extend_from_slice(payload);
    message
}

#[cfg(test)]
mod tests {
    use super::*;

    fn signed_envelope(identity: &DeviceIdentity) -> SignedReportEnvelope {
        identity
            .sign_report_envelope(
                br#"{"schemaVersion":"1.0","verification":"passed"}"#,
                "application/json",
                42,
                &[0x42; HASH_BYTES],
            )
            .expect("sign report envelope")
    }

    fn flip_base64url(value: &mut String) {
        let mut decoded = decode_base64url(value, "testField").expect("decode field");
        decoded[0] ^= 0x80;
        value.zeroize();
        *value = encode_base64url(decoded.as_slice());
    }

    fn assert_tamper_rejected(
        identity: &DeviceIdentity,
        envelope: &SignedReportEnvelope,
        mutate: impl FnOnce(&mut SignedReportEnvelope),
    ) {
        let mut tampered = envelope.clone();
        mutate(&mut tampered);
        assert!(tampered.verify(&identity.public_key()).is_err());
    }

    fn assert_zeroizing_vec(_value: &Zeroizing<Vec<u8>>) {}

    fn assert_zeroize_on_drop<T: ZeroizeOnDrop>() {}

    #[test]
    fn signed_report_debug_redacts_payload_key_and_signature() {
        let identity = DeviceIdentity::from_seed(&[0xa5; 32]).expect("fixed test identity");
        let secret_payload = b"KERNAID_SIGNED_REPORT_DEBUG_SECRET";
        let report = identity.sign_report(secret_payload);

        let debug = format!("{report:?}");
        assert_eq!(
            debug,
            format!(
                "SignedReport {{ payload_len: {}, public_key_len: {}, signature_len: {}, .. }}",
                report.payload.len(),
                report.public_key.len(),
                report.signature.len()
            )
        );
        assert!(!debug.contains("KERNAID_SIGNED_REPORT_DEBUG_SECRET"));
        assert!(!debug.contains(&format!("{:?}", report.payload)));
        assert!(!debug.contains(&format!("{:?}", report.public_key)));
        assert!(!debug.contains(&format!("{:?}", report.signature)));
    }

    #[test]
    fn signed_envelope_debug_redacts_all_string_content() {
        const SECRET: &str = "KERNAID_SIGNED_ENVELOPE_DEBUG_SECRET";

        let mut envelope = signed_envelope(&DeviceIdentity::generate());
        envelope.schema = format!("{SECRET}:schema");
        envelope.kind = format!("{SECRET}:kind");
        envelope.algorithm = format!("{SECRET}:algorithm");
        envelope.device_id = format!("{SECRET}:device-id");
        envelope.journal_sequence = 8_675_309;
        envelope.journal_entry_hash = format!("{SECRET}:journal-entry-hash");
        envelope.payload_media_type = format!("{SECRET}:media-type");
        envelope.payload_sha256 = format!("{SECRET}:payload-hash");
        envelope.payload = format!("{SECRET}:payload");
        envelope.public_key = format!("{SECRET}:public-key");
        envelope.signature = format!("{SECRET}:signature");

        let debug = format!("{envelope:?}");
        assert_eq!(
            debug,
            format!(
                concat!(
                    "SignedReportEnvelope {{ journal_sequence: {}, ",
                    "payload_base64url_len: {}, public_key_base64url_len: {}, ",
                    "signature_base64url_len: {}, .. }}"
                ),
                envelope.journal_sequence,
                envelope.payload.len(),
                envelope.public_key.len(),
                envelope.signature.len()
            )
        );
        assert!(!debug.contains(SECRET));
        for sensitive in [
            &envelope.schema,
            &envelope.kind,
            &envelope.algorithm,
            &envelope.device_id,
            &envelope.journal_entry_hash,
            &envelope.payload_media_type,
            &envelope.payload_sha256,
            &envelope.payload,
            &envelope.public_key,
            &envelope.signature,
        ] {
            assert!(!debug.contains(sensitive));
        }
    }

    #[test]
    fn verified_payload_and_signature_messages_use_zeroizing_memory() {
        const SECRET: &[u8] = b"KERNAID_ZEROIZING_REPORT_PAYLOAD_SECRET";

        let identity = DeviceIdentity::from_seed(&[0x5a; 32]).expect("fixed test identity");
        let journal_entry_hash = [0x42; HASH_BYTES];
        let envelope = identity
            .sign_report_envelope(SECRET, "application/octet-stream", 73, &journal_entry_hash)
            .expect("sign secret envelope");

        let decoded = decode_payload(&envelope.payload).expect("decode payload");
        assert_zeroizing_vec(&decoded);
        assert_eq!(decoded.as_slice(), SECRET);

        let payload_hash: [u8; HASH_BYTES] = Sha256::digest(SECRET).into();
        let public_key = identity.public_key();
        let content = EnvelopeContent {
            schema: &envelope.schema,
            kind: &envelope.kind,
            algorithm: &envelope.algorithm,
            device_id: &envelope.device_id,
            journal_sequence: envelope.journal_sequence,
            journal_entry_hash: &journal_entry_hash,
            payload_media_type: &envelope.payload_media_type,
            payload_sha256: &payload_hash,
            payload: SECRET,
            public_key: &public_key,
        };
        let signature_message = envelope_signature_message(&content);
        assert_zeroizing_vec(&signature_message);
        assert!(
            signature_message
                .windows(SECRET.len())
                .any(|window| window == SECRET)
        );

        let mut verified = envelope
            .verify_zeroizing(&public_key)
            .expect("verify secret envelope");
        assert_eq!(verified.as_bytes(), SECRET);
        let debug = format!("{verified:?}");
        assert_eq!(
            debug,
            format!("VerifiedReportPayload {{ len: {}, .. }}", SECRET.len())
        );
        assert!(!debug.contains("KERNAID_ZEROIZING_REPORT_PAYLOAD_SECRET"));

        verified.zeroize();
        assert!(verified.is_empty());
    }

    #[test]
    fn owned_report_types_zeroize_their_sensitive_fields() {
        const SECRET: &[u8] = b"KERNAID_OWNED_REPORT_ZEROIZE_SECRET";

        assert_zeroize_on_drop::<SignedReport>();
        assert_zeroize_on_drop::<SignedReportEnvelope>();
        assert_zeroize_on_drop::<VerifiedReportPayload>();

        let identity = DeviceIdentity::from_seed(&[0x69; 32]).expect("fixed test identity");
        let mut report = identity.sign_report(SECRET);
        report.zeroize();
        assert!(report.payload.is_empty());
        assert_eq!(report.public_key, [0_u8; PUBLIC_KEY_BYTES]);
        assert_eq!(report.signature, [0_u8; SIGNATURE_BYTES]);

        let mut envelope = identity
            .sign_report_envelope(SECRET, "application/octet-stream", 14, &[0x7b; HASH_BYTES])
            .expect("sign secret envelope");
        envelope.zeroize();
        assert!(envelope.schema.is_empty());
        assert!(envelope.kind.is_empty());
        assert!(envelope.algorithm.is_empty());
        assert!(envelope.device_id.is_empty());
        assert_eq!(envelope.journal_sequence, 0);
        assert!(envelope.journal_entry_hash.is_empty());
        assert!(envelope.payload_media_type.is_empty());
        assert!(envelope.payload_sha256.is_empty());
        assert!(envelope.payload.is_empty());
        assert!(envelope.public_key.is_empty());
        assert!(envelope.signature.is_empty());
    }

    #[test]
    fn hash_and_signature_failure_diagnostics_never_expose_payload() {
        const SECRET: &[u8] = b"KERNAID_VERIFY_ERROR_PATH_SECRET";

        let identity = DeviceIdentity::from_seed(&[0x3c; 32]).expect("fixed test identity");
        let envelope = identity
            .sign_report_envelope(SECRET, "application/octet-stream", 91, &[0x24; HASH_BYTES])
            .expect("sign secret envelope");

        let mut hash_tampered = envelope.clone();
        flip_base64url(&mut hash_tampered.payload_sha256);
        let hash_error = hash_tampered
            .verify_zeroizing(&identity.public_key())
            .expect_err("tampered payload hash must fail");
        assert_eq!(hash_error, IdentityError::PayloadHashMismatch);
        assert_eq!(format!("{hash_error:?}"), "PayloadHashMismatch");

        let mut signature_tampered = envelope;
        flip_base64url(&mut signature_tampered.signature);
        let signature_error = signature_tampered
            .verify_zeroizing(&identity.public_key())
            .expect_err("tampered signature must fail");
        assert_eq!(signature_error, IdentityError::InvalidSignature);
        assert_eq!(format!("{signature_error:?}"), "InvalidSignature");

        let encoded_secret = Zeroizing::new(URL_SAFE_NO_PAD.encode(SECRET));
        for diagnostic in [format!("{hash_error:?}"), format!("{signature_error:?}")] {
            assert!(!diagnostic.contains("KERNAID_VERIFY_ERROR_PATH_SECRET"));
            assert!(!diagnostic.contains(encoded_secret.as_str()));
        }
    }

    #[test]
    fn seed_roundtrip_preserves_identity_and_signature() {
        let first = DeviceIdentity::generate();
        let seed = first.export_seed_for_encrypted_storage();
        let restored = DeviceIdentity::from_seed(&seed).expect("restore device identity");
        assert_eq!(first.device_id(), restored.device_id());
        let expected_public_key = first.public_key();
        restored
            .sign_report(b"immutable report")
            .verify(&expected_public_key)
            .expect("verify signed report");
    }

    #[test]
    fn tampered_report_is_rejected() {
        let identity = DeviceIdentity::generate();
        let mut report = identity.sign_report(b"verified report");
        report.payload[0] ^= 1;
        assert_eq!(
            report.verify(&identity.public_key()),
            Err(IdentityError::InvalidSignature)
        );
    }

    #[test]
    fn attacker_key_embedded_in_report_is_not_trusted() {
        let trusted = DeviceIdentity::generate();
        let attacker = DeviceIdentity::generate();
        let report = attacker.sign_report(b"attacker-controlled report");

        assert_eq!(
            report.verify(&trusted.public_key()),
            Err(IdentityError::UnexpectedPublicKey)
        );
    }

    #[test]
    fn tampered_embedded_key_is_rejected_before_signature_verification() {
        let identity = DeviceIdentity::generate();
        let mut report = identity.sign_report(b"verified report");
        report.public_key[0] ^= 1;

        assert_eq!(
            report.verify(&identity.public_key()),
            Err(IdentityError::UnexpectedPublicKey)
        );
    }

    #[test]
    fn report_signature_cannot_be_reused_outside_its_domain() {
        let identity = DeviceIdentity::generate();
        let report = identity.sign_report(b"verified report");
        let public_key = VerifyingKey::from_bytes(&identity.public_key()).expect("public key");
        let signature = Signature::from_bytes(&report.signature);

        assert!(
            public_key
                .verify_strict(&report.payload, &signature)
                .is_err()
        );

        let other_domain_message = signature_message(b"KERNAID-OTHER-OBJECT-V1\0", &report.payload);
        assert!(
            public_key
                .verify_strict(&other_domain_message, &signature)
                .is_err()
        );

        report
            .verify(&identity.public_key())
            .expect("report domain verifies");
    }

    #[test]
    fn signed_envelope_json_roundtrip_verifies_with_pinned_key() {
        let identity = DeviceIdentity::generate();
        let envelope = signed_envelope(&identity);
        let json = serde_json::to_string(&envelope).expect("serialize envelope");
        assert!(json.contains("\"deviceId\""));
        assert!(json.contains("\"journalEntryHash\""));
        assert!(json.contains("\"payloadMediaType\""));
        assert!(!json.contains("\"device_id\""));

        let decoded: SignedReportEnvelope =
            serde_json::from_str(&json).expect("deserialize envelope");
        assert_eq!(decoded, envelope);
        assert_eq!(
            decoded
                .verify(&identity.public_key())
                .expect("verify envelope")
                .as_slice(),
            br#"{"schemaVersion":"1.0","verification":"passed"}"#
        );
    }

    #[test]
    fn every_envelope_field_is_authenticated_or_strictly_derived() {
        let identity = DeviceIdentity::generate();
        let attacker = DeviceIdentity::generate();
        let envelope = signed_envelope(&identity);

        assert_tamper_rejected(&identity, &envelope, |value| value.schema.push('2'));
        assert_tamper_rejected(&identity, &envelope, |value| value.kind.push('2'));
        assert_tamper_rejected(&identity, &envelope, |value| value.algorithm.push('2'));
        assert_tamper_rejected(&identity, &envelope, |value| value.device_id.push('0'));
        assert_tamper_rejected(&identity, &envelope, |value| {
            value.journal_sequence += 1;
        });
        assert_tamper_rejected(&identity, &envelope, |value| {
            flip_base64url(&mut value.journal_entry_hash);
        });
        assert_tamper_rejected(&identity, &envelope, |value| {
            value.payload_media_type = "application/cbor".to_owned();
        });
        assert_tamper_rejected(&identity, &envelope, |value| {
            flip_base64url(&mut value.payload_sha256);
        });
        assert_tamper_rejected(&identity, &envelope, |value| {
            flip_base64url(&mut value.payload);
        });
        assert_tamper_rejected(&identity, &envelope, |value| {
            value.public_key = encode_base64url(&attacker.public_key());
        });
        assert_tamper_rejected(&identity, &envelope, |value| {
            flip_base64url(&mut value.signature);
        });
    }

    #[test]
    fn envelope_never_trusts_its_embedded_key() {
        let trusted = DeviceIdentity::generate();
        let attacker = DeviceIdentity::generate();
        let attacker_envelope = signed_envelope(&attacker);

        assert_eq!(
            attacker_envelope.verify(&trusted.public_key()),
            Err(IdentityError::UnexpectedPublicKey)
        );
    }

    #[test]
    fn device_id_is_a_valid_explicit_trust_anchor() {
        let identity = DeviceIdentity::generate();
        let envelope = signed_envelope(&identity);

        assert_eq!(
            envelope
                .verify_for_device_id(&identity.device_id())
                .expect("verify using pinned device ID")
                .as_slice(),
            br#"{"schemaVersion":"1.0","verification":"passed"}"#
        );
    }

    #[test]
    fn device_id_anchor_rejects_key_substitution() {
        let trusted = DeviceIdentity::generate();
        let attacker = DeviceIdentity::generate();
        let envelope = signed_envelope(&attacker);

        assert_eq!(
            envelope.verify_for_device_id(&trusted.device_id()),
            Err(IdentityError::UnexpectedDeviceId)
        );
    }

    #[test]
    fn verification_requires_and_reconciles_trust_anchors() {
        let identity = DeviceIdentity::generate();
        let other = DeviceIdentity::generate();
        let envelope = signed_envelope(&identity);

        assert_eq!(
            envelope.verify_with_trust_anchors(None, None),
            Err(IdentityError::MissingTrustAnchor)
        );
        assert_eq!(
            envelope
                .verify_with_trust_anchors(Some(&other.device_id()), Some(&identity.public_key()),),
            Err(IdentityError::UnexpectedDeviceId)
        );
    }

    #[test]
    fn device_id_and_public_key_parsers_require_canonical_values() {
        let identity = DeviceIdentity::generate();
        let envelope = signed_envelope(&identity);

        assert_eq!(
            decode_public_key_base64url(&envelope.public_key).expect("decode public key"),
            identity.public_key()
        );
        assert_eq!(
            decode_public_key_base64url(&format!("{}=", envelope.public_key)),
            Err(IdentityError::InvalidBase64Url("publicKey"))
        );
        for invalid in [
            "",
            "KA-1234",
            "ka-0123456789abcdef01234567",
            "KA-0123456789ABCDEF01234567",
            "KA-0123456789abcdef0123456g",
        ] {
            assert_eq!(
                validate_device_id(invalid),
                Err(IdentityError::InvalidDeviceId),
                "accepted invalid device ID: {invalid}"
            );
        }
    }

    #[test]
    fn report_envelopes_require_a_real_journal_entry() {
        let identity = DeviceIdentity::generate();
        assert_eq!(
            identity.sign_report_envelope(
                br#"{"schemaVersion":"1.0"}"#,
                "application/json",
                0,
                &[0x42; HASH_BYTES],
            ),
            Err(IdentityError::InvalidEnvelopeField("journalSequence"))
        );

        let mut envelope = signed_envelope(&identity);
        envelope.journal_sequence = 0;
        assert_eq!(
            envelope.verify(&identity.public_key()),
            Err(IdentityError::InvalidEnvelopeField("journalSequence"))
        );
    }

    #[test]
    fn envelope_rejects_noncanonical_base64url() {
        let identity = DeviceIdentity::generate();
        let mut envelope = signed_envelope(&identity);
        envelope.payload.push('=');

        assert_eq!(
            envelope.verify(&identity.public_key()),
            Err(IdentityError::InvalidBase64Url("payload"))
        );
    }

    #[test]
    fn envelope_payload_limit_is_enforced_when_signing_and_verifying() {
        let identity = DeviceIdentity::generate();
        let oversized = vec![0_u8; MAX_SIGNED_REPORT_PAYLOAD_BYTES + 1];
        assert!(matches!(
            identity.sign_report_envelope(&oversized, "application/json", 1, &[0_u8; HASH_BYTES]),
            Err(IdentityError::PayloadTooLarge)
        ));

        let mut envelope = signed_envelope(&identity);
        envelope.payload = encode_base64url(&oversized);
        assert_eq!(
            envelope.verify(&identity.public_key()),
            Err(IdentityError::PayloadTooLarge)
        );
    }

    #[test]
    fn envelope_rejects_ambiguous_or_invalid_media_types() {
        let identity = DeviceIdentity::generate();
        for media_type in [
            "",
            "application",
            "application/json/extra",
            " application/json",
            "application /json",
            "application/json;",
            "application/json\r\nX-Injected: true",
        ] {
            assert_eq!(
                identity.sign_report_envelope(b"report", media_type, 1, &[0_u8; HASH_BYTES]),
                Err(IdentityError::InvalidPayloadMediaType),
                "accepted invalid media type: {media_type:?}"
            );
        }
    }

    #[test]
    fn envelope_deserialization_rejects_unknown_fields() {
        let identity = DeviceIdentity::generate();
        let envelope = signed_envelope(&identity);
        let mut value = serde_json::to_value(envelope).expect("serialize envelope value");
        value
            .as_object_mut()
            .expect("object envelope")
            .insert("unsignedMetadata".to_owned(), serde_json::json!(true));

        assert!(serde_json::from_value::<SignedReportEnvelope>(value).is_err());
    }

    #[test]
    fn envelope_deserialization_zeroizes_partial_secret_fields_on_every_error_shape() {
        const SECRET: &[u8] = b"KERNAID_ENVELOPE_PARTIAL_DESERIALIZE_SECRET";

        let identity = DeviceIdentity::from_seed(&[0x17; 32]).expect("fixed test identity");
        let envelope = identity
            .sign_report_envelope(SECRET, "application/octet-stream", 55, &[0x63; HASH_BYTES])
            .expect("sign secret envelope");
        let encoded_secret = Zeroizing::new(envelope.payload.clone());
        let valid = Zeroizing::new(serde_json::to_string(&envelope).expect("serialize envelope"));
        let signature_member = Zeroizing::new(format!("\"signature\":\"{}\"", envelope.signature));

        let wrong_signature_type =
            Zeroizing::new(valid.replacen(signature_member.as_str(), "\"signature\":false", 1));
        let duplicate_payload = Zeroizing::new(valid.replacen(
            "\"signature\":",
            &format!("\"paylo\\u0064\":\"{}\",\"signature\":", envelope.payload),
            1,
        ));
        let duplicate_signature = Zeroizing::new(format!(
            "{},{}{}",
            valid.strip_suffix('}').expect("object envelope"),
            signature_member.as_str(),
            "}"
        ));
        let unknown_final = Zeroizing::new(format!(
            "{},\"unknownFinal\":\"KERNAID_UNKNOWN_FIELD_SECRET\"{}",
            valid.strip_suffix('}').expect("object envelope"),
            "}"
        ));
        let trailing = Zeroizing::new(format!("{}{{}}", valid.as_str()));

        for (name, candidate) in [
            ("wrong signature type", wrong_signature_type),
            ("escaped duplicate payload", duplicate_payload),
            ("duplicate signature", duplicate_signature),
            ("unknown final field", unknown_final),
            ("trailing document", trailing),
        ] {
            let error =
                serde_json::from_str::<SignedReportEnvelope>(candidate.as_str()).expect_err(name);
            let diagnostic = error.to_string();
            assert!(!diagnostic.contains("KERNAID_ENVELOPE_PARTIAL_DESERIALIZE_SECRET"));
            assert!(!diagnostic.contains("KERNAID_UNKNOWN_FIELD_SECRET"));
            assert!(!diagnostic.contains(encoded_secret.as_str()));
        }
    }

    #[test]
    fn envelope_raw_parser_preserves_escaped_json_semantics_without_serde_scratch() {
        assert_zeroize_on_drop::<SensitiveEnvelopeString>();
        let identity = DeviceIdentity::generate();
        let envelope = signed_envelope(&identity);
        let json = Zeroizing::new(serde_json::to_string(&envelope).expect("serialize envelope"));
        let escaped =
            Zeroizing::new(json.replacen("\"schema\":\"https://", "\"schema\":\"https:\\/\\/", 1));

        let decoded: SignedReportEnvelope =
            serde_json::from_str(escaped.as_str()).expect("decode escaped schema");
        assert_eq!(decoded, envelope);

        let source = include_str!("lib.rs");
        let declaration = source
            .split("pub struct SignedReportEnvelope")
            .next()
            .expect("envelope declaration prefix");
        assert!(declaration.ends_with("#[serde(rename_all = \"camelCase\")]\n"));
        assert!(source.contains("let raw = <&RawValue>::deserialize(deserializer)?;"));
        assert!(source.contains("SignedReportEnvelopeParser::parse(raw.get())"));
    }

    #[test]
    fn protocol_signature_is_exact_domain_concatenated_payload() {
        let identity = DeviceIdentity::from_seed(&[0x81; 32]).expect("fixed protocol identity");
        let domain = b"kernaid:test:protocol:v1\0";
        let payload = br#"{"a":1,"z":true}"#;
        let signature = identity
            .sign_domain_separated_payload(domain, payload)
            .expect("sign protocol payload");
        let mut expected_message = domain.to_vec();
        expected_message.extend_from_slice(payload);
        VerifyingKey::from_bytes(&identity.public_key())
            .expect("valid public key")
            .verify_strict(&expected_message, &Signature::from_bytes(&signature))
            .expect("verify exact protocol message");

        assert_eq!(
            identity.sign_domain_separated_payload(b"missing-terminator", payload),
            Err(IdentityError::InvalidProtocolDomain)
        );
        assert_eq!(
            identity.sign_domain_separated_payload(domain, &[0_u8; MAX_PROTOCOL_PAYLOAD_BYTES + 1]),
            Err(IdentityError::ProtocolPayloadTooLarge)
        );
    }
}
