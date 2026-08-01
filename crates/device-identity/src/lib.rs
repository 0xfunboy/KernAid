#![forbid(unsafe_code)]
//! Local Ed25519 device identity used to sign immutable report bytes. The seed
//! is intended to live only inside the OS keychain or the Rescue LUKS2 vault.

use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use rand_core::OsRng;
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

const SIGNED_REPORT_DOMAIN: &[u8] = b"KERNAID-SIGNED-REPORT-V1\0";

pub struct DeviceIdentity {
    signing_key: SigningKey,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SignedReport {
    pub payload: Vec<u8>,
    pub public_key: [u8; 32],
    pub signature: [u8; 64],
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum IdentityError {
    InvalidSeedLength,
    InvalidPublicKey,
    UnexpectedPublicKey,
    InvalidSignature,
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
        let digest = Sha256::digest(self.signing_key.verifying_key().as_bytes());
        let short = digest[..12]
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>();
        format!("KA-{short}")
    }

    pub fn sign_report(&self, payload: &[u8]) -> SignedReport {
        let signature = self.signing_key.sign(&report_signature_message(payload));
        SignedReport {
            payload: payload.to_vec(),
            public_key: self.public_key(),
            signature: signature.to_bytes(),
        }
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
}
