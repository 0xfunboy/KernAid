#![forbid(unsafe_code)]
//! Local Ed25519 device identity used to sign immutable report bytes. The seed
//! is intended to live only inside the OS keychain or the Rescue LUKS2 vault.

use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use rand_core::OsRng;
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

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
    InvalidSignature,
}

impl DeviceIdentity {
    pub fn generate() -> Self {
        Self {
            signing_key: SigningKey::generate(&mut OsRng),
        }
    }

    pub fn from_seed(seed: &[u8]) -> Result<Self, IdentityError> {
        let seed: [u8; 32] = seed
            .try_into()
            .map_err(|_| IdentityError::InvalidSeedLength)?;
        Ok(Self {
            signing_key: SigningKey::from_bytes(&seed),
        })
    }

    pub fn export_seed_for_encrypted_storage(&self) -> Zeroizing<Vec<u8>> {
        Zeroizing::new(self.signing_key.to_bytes().to_vec())
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
        let signature = self.signing_key.sign(payload);
        SignedReport {
            payload: payload.to_vec(),
            public_key: self.signing_key.verifying_key().to_bytes(),
            signature: signature.to_bytes(),
        }
    }
}

impl SignedReport {
    pub fn verify(&self) -> Result<(), IdentityError> {
        let public_key = VerifyingKey::from_bytes(&self.public_key)
            .map_err(|_| IdentityError::InvalidPublicKey)?;
        let signature = Signature::from_bytes(&self.signature);
        public_key
            .verify(&self.payload, &signature)
            .map_err(|_| IdentityError::InvalidSignature)
    }
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
        restored
            .sign_report(b"immutable report")
            .verify()
            .expect("verify signed report");
    }

    #[test]
    fn tampered_report_is_rejected() {
        let identity = DeviceIdentity::generate();
        let mut report = identity.sign_report(b"verified report");
        report.payload[0] ^= 1;
        assert_eq!(report.verify(), Err(IdentityError::InvalidSignature));
    }
}
