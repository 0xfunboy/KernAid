#![forbid(unsafe_code)]
//! Local Ed25519 device identity used to sign immutable report bytes. The seed
//! is intended to live only inside the OS keychain or the Rescue LUKS2 vault.

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use rand_core::OsRng;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

const SIGNED_REPORT_DOMAIN: &[u8] = b"KERNAID-SIGNED-REPORT-V1\0";
const SIGNED_REPORT_ENVELOPE_DOMAIN: &[u8] = b"KERNAID-SIGNED-REPORT-ENVELOPE-V1\0";
const PUBLIC_KEY_BYTES: usize = 32;
const SIGNATURE_BYTES: usize = 64;
const HASH_BYTES: usize = 32;
const MAX_MEDIA_TYPE_BYTES: usize = 255;

pub const SIGNED_REPORT_ENVELOPE_SCHEMA: &str =
    "https://schemas.kernaid.dev/v1/signed-report-envelope.json";
pub const SIGNED_REPORT_ENVELOPE_KIND: &str = "kernaid.signed-report";
pub const SIGNED_REPORT_ENVELOPE_ALGORITHM: &str = "Ed25519";
pub const MAX_SIGNED_REPORT_PAYLOAD_BYTES: usize = 1024 * 1024;

pub struct DeviceIdentity {
    signing_key: SigningKey,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SignedReport {
    pub payload: Vec<u8>,
    pub public_key: [u8; PUBLIC_KEY_BYTES],
    pub signature: [u8; SIGNATURE_BYTES],
}

/// Portable JSON report bundle whose complete semantic content is signed.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
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

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum IdentityError {
    InvalidSeedLength,
    InvalidPublicKey,
    UnexpectedPublicKey,
    InvalidSignature,
    InvalidEnvelopeField(&'static str),
    InvalidBase64Url(&'static str),
    InvalidPayloadMediaType,
    PayloadTooLarge,
    PayloadHashMismatch,
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
            .verify(&report_signature_message(&self.payload), &signature)
            .map_err(|_| IdentityError::InvalidSignature)
    }
}

impl SignedReportEnvelope {
    /// Verify against a caller-pinned key and return the authenticated payload.
    ///
    /// The embedded key is never a trust anchor. All binary JSON fields must be
    /// canonical base64url without padding before the signature is considered.
    pub fn verify(
        &self,
        expected_public_key: &[u8; PUBLIC_KEY_BYTES],
    ) -> Result<Vec<u8>, IdentityError> {
        validate_constant_field("schema", &self.schema, SIGNED_REPORT_ENVELOPE_SCHEMA)?;
        validate_constant_field("kind", &self.kind, SIGNED_REPORT_ENVELOPE_KIND)?;
        validate_constant_field(
            "algorithm",
            &self.algorithm,
            SIGNED_REPORT_ENVELOPE_ALGORITHM,
        )?;
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
            .verify(
                &envelope_signature_message(&content),
                &Signature::from_bytes(&signature),
            )
            .map_err(|_| IdentityError::InvalidSignature)?;
        Ok(payload)
    }
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

fn envelope_signature_message(content: &EnvelopeContent<'_>) -> Vec<u8> {
    let mut message =
        Vec::with_capacity(SIGNED_REPORT_ENVELOPE_DOMAIN.len() + content.payload.len() + 512);
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

fn decode_payload(encoded: &str) -> Result<Vec<u8>, IdentityError> {
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
    decode_base64url(encoded, field)?
        .try_into()
        .map_err(|_| IdentityError::InvalidBase64Url(field))
}

fn decode_base64url(encoded: &str, field: &'static str) -> Result<Vec<u8>, IdentityError> {
    let decoded = URL_SAFE_NO_PAD
        .decode(encoded)
        .map_err(|_| IdentityError::InvalidBase64Url(field))?;
    if encode_base64url(&decoded) != encoded {
        return Err(IdentityError::InvalidBase64Url(field));
    }
    Ok(decoded)
}

fn encode_base64url(value: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(value)
}

fn device_id_for_public_key(public_key: &[u8; PUBLIC_KEY_BYTES]) -> String {
    let digest = Sha256::digest(public_key);
    let short = digest[..12]
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    format!("KA-{short}")
}

fn report_signature_message(payload: &[u8]) -> Vec<u8> {
    signature_message(SIGNED_REPORT_DOMAIN, payload)
}

fn signature_message(domain: &[u8], payload: &[u8]) -> Vec<u8> {
    let payload_len = payload.len() as u128;
    let mut message = Vec::with_capacity(domain.len() + 16 + payload.len());
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
        let mut decoded = URL_SAFE_NO_PAD
            .decode(value.as_bytes())
            .expect("decode field");
        decoded[0] ^= 0x80;
        *value = URL_SAFE_NO_PAD.encode(decoded);
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

        assert!(public_key.verify(&report.payload, &signature).is_err());

        let other_domain_message = signature_message(b"KERNAID-OTHER-OBJECT-V1\0", &report.payload);
        assert!(
            public_key
                .verify(&other_domain_message, &signature)
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
                .expect("verify envelope"),
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
}
