use super::{
    ED25519_PUBLIC_KEY_BYTES, ED25519_SIGNATURE_BYTES, FleetClientError, canonical_json,
    decode_bounded_base64url, decode_fixed_base64url, validate_identifier, validate_timestamp,
    validate_transfer_size, verify_signature,
};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use ed25519_dalek::VerifyingKey;
use kernaid_device_identity::{DeviceIdentity, device_id_for_public_key, validate_device_id};
use kernaid_update_client::{
    SignedUpdateManifest, UpdateArchitecture, UpdateError, UpdatePlatform, UpdateRing,
    VerifiedUpdate,
};
use serde::{Deserialize, Serialize};
use std::{error::Error, fmt};
use zeroize::Zeroizing;

pub const UPDATE_PULL_REQUEST_SCHEMA: &str = "dev.kernaid.fleet.update-pull-request.v1";
pub const UPDATE_PULL_RESPONSE_SCHEMA: &str = "dev.kernaid.fleet.update-pull-response.v1";
pub const UPDATE_PULL_SIGNATURE_DOMAIN: &[u8] = b"kernaid:fleet:update-pull:v1\0";

const MAX_UPDATE_PULL_BYTES: usize = 8 * 1024;
const MAX_UPDATE_PULL_RESPONSE_BYTES: usize = 256 * 1024;
const MAX_UPDATE_ITEMS: usize = 2;
const MIN_NONCE_BYTES: usize = 16;
const MAX_NONCE_BYTES: usize = 64;

pub struct UpdatePullRequestInput {
    tenant_id: String,
    platform: UpdatePlatform,
    architecture: UpdateArchitecture,
    update_ring: UpdateRing,
    issued_at: String,
    nonce: Zeroizing<Vec<u8>>,
}

impl UpdatePullRequestInput {
    #[must_use]
    pub fn new(
        tenant_id: impl Into<String>,
        platform: UpdatePlatform,
        architecture: UpdateArchitecture,
        update_ring: UpdateRing,
        issued_at: impl Into<String>,
        nonce: impl Into<Vec<u8>>,
    ) -> Self {
        Self {
            tenant_id: tenant_id.into(),
            platform,
            architecture,
            update_ring,
            issued_at: issued_at.into(),
            nonce: Zeroizing::new(nonce.into()),
        }
    }
}

impl fmt::Debug for UpdatePullRequestInput {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("UpdatePullRequestInput")
            .field("tenant_id", &self.tenant_id)
            .field("platform", &self.platform)
            .field("architecture", &self.architecture)
            .field("update_ring", &self.update_ring)
            .field("issued_at", &self.issued_at)
            .finish_non_exhaustive()
    }
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SignedUpdatePullRequest {
    schema: String,
    tenant_id: String,
    device_id: String,
    platform: UpdatePlatform,
    architecture: UpdateArchitecture,
    update_ring: UpdateRing,
    issued_at: String,
    nonce: String,
    signature: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct UnsignedUpdatePullRequest<'a> {
    schema: &'a str,
    tenant_id: &'a str,
    device_id: &'a str,
    platform: UpdatePlatform,
    architecture: UpdateArchitecture,
    update_ring: UpdateRing,
    issued_at: &'a str,
    nonce: &'a str,
}

impl SignedUpdatePullRequest {
    pub fn sign(
        identity: &DeviceIdentity,
        input: UpdatePullRequestInput,
    ) -> Result<Self, FleetClientError> {
        validate_identifier("tenantId", &input.tenant_id)?;
        validate_timestamp("issuedAt", &input.issued_at)?;
        validate_nonce(&input.nonce)?;
        let mut request = Self {
            schema: UPDATE_PULL_REQUEST_SCHEMA.to_owned(),
            tenant_id: input.tenant_id,
            device_id: identity.device_id(),
            platform: input.platform,
            architecture: input.architecture,
            update_ring: input.update_ring,
            issued_at: input.issued_at,
            nonce: URL_SAFE_NO_PAD.encode(input.nonce.as_slice()),
            signature: String::new(),
        };
        request.validate_unsigned()?;
        let unsigned = Zeroizing::new(request.unsigned_canonical()?);
        request.signature = URL_SAFE_NO_PAD.encode(
            identity
                .sign_domain_separated_payload(UPDATE_PULL_SIGNATURE_DOMAIN, &unsigned)
                .map_err(FleetClientError::Identity)?,
        );
        request.validate()?;
        Ok(request)
    }

    pub fn verify(
        &self,
        expected_tenant_id: &str,
        expected_device_id: &str,
        enrolled_public_key: &[u8; ED25519_PUBLIC_KEY_BYTES],
    ) -> Result<(), FleetClientError> {
        self.validate()?;
        validate_identifier("expectedTenantId", expected_tenant_id)?;
        validate_device_id(expected_device_id)
            .map_err(|_| FleetClientError::InvalidField("expectedDeviceId"))?;
        if self.tenant_id != expected_tenant_id {
            return Err(FleetClientError::UnexpectedTenant);
        }
        if self.device_id != expected_device_id
            || device_id_for_public_key(enrolled_public_key) != expected_device_id
        {
            return Err(FleetClientError::UnexpectedDevice);
        }
        let signature =
            decode_fixed_base64url::<ED25519_SIGNATURE_BYTES>("signature", &self.signature)?;
        let unsigned = Zeroizing::new(self.unsigned_canonical()?);
        verify_signature(
            enrolled_public_key,
            UPDATE_PULL_SIGNATURE_DOMAIN,
            &unsigned,
            &signature,
        )
    }

    pub fn export_offline(&self) -> Result<Vec<u8>, FleetClientError> {
        self.validate()?;
        let bytes = canonical_json(self)?;
        validate_transfer_size(bytes.len(), MAX_UPDATE_PULL_BYTES)?;
        Ok(bytes)
    }

    pub fn import_offline(
        bytes: &[u8],
        expected_tenant_id: &str,
        expected_device_id: &str,
        enrolled_public_key: &[u8; ED25519_PUBLIC_KEY_BYTES],
    ) -> Result<Self, FleetClientError> {
        let request: Self = super::import_canonical(bytes, MAX_UPDATE_PULL_BYTES)?;
        request.verify(expected_tenant_id, expected_device_id, enrolled_public_key)?;
        Ok(request)
    }

    pub fn import_verified_response(
        &self,
        bytes: &[u8],
        update_anchor: &VerifyingKey,
    ) -> Result<Vec<VerifiedUpdate>, UpdatePullResponseError> {
        validate_transfer_size(bytes.len(), MAX_UPDATE_PULL_RESPONSE_BYTES)
            .map_err(UpdatePullResponseError::Client)?;
        let response: UpdatePullResponse =
            serde_json::from_slice(bytes).map_err(|_| UpdatePullResponseError::InvalidResponse)?;
        if response.schema != UPDATE_PULL_RESPONSE_SCHEMA
            || response.tenant_id != self.tenant_id
            || response.device_id != self.device_id
            || response.platform != self.platform
            || response.architecture != self.architecture
            || response.update_ring != self.update_ring
            || response.items.len() > MAX_UPDATE_ITEMS
        {
            return Err(UpdatePullResponseError::BindingMismatch);
        }
        response
            .items
            .into_iter()
            .map(|manifest| {
                manifest
                    .verify(update_anchor)
                    .map_err(UpdatePullResponseError::Update)
            })
            .collect()
    }

    #[must_use]
    pub fn tenant_id(&self) -> &str {
        &self.tenant_id
    }

    #[must_use]
    pub fn device_id(&self) -> &str {
        &self.device_id
    }

    #[must_use]
    pub const fn platform(&self) -> UpdatePlatform {
        self.platform
    }

    #[must_use]
    pub const fn architecture(&self) -> UpdateArchitecture {
        self.architecture
    }

    #[must_use]
    pub const fn update_ring(&self) -> UpdateRing {
        self.update_ring
    }

    fn unsigned(&self) -> UnsignedUpdatePullRequest<'_> {
        UnsignedUpdatePullRequest {
            schema: &self.schema,
            tenant_id: &self.tenant_id,
            device_id: &self.device_id,
            platform: self.platform,
            architecture: self.architecture,
            update_ring: self.update_ring,
            issued_at: &self.issued_at,
            nonce: &self.nonce,
        }
    }

    fn unsigned_canonical(&self) -> Result<Vec<u8>, FleetClientError> {
        canonical_json(&self.unsigned())
    }

    fn validate(&self) -> Result<(), FleetClientError> {
        self.validate_unsigned()?;
        decode_fixed_base64url::<ED25519_SIGNATURE_BYTES>("signature", &self.signature)?;
        Ok(())
    }

    fn validate_unsigned(&self) -> Result<(), FleetClientError> {
        if self.schema != UPDATE_PULL_REQUEST_SCHEMA {
            return Err(FleetClientError::InvalidField("schema"));
        }
        validate_identifier("tenantId", &self.tenant_id)?;
        validate_device_id(&self.device_id)
            .map_err(|_| FleetClientError::InvalidField("deviceId"))?;
        validate_timestamp("issuedAt", &self.issued_at)?;
        decode_bounded_base64url("nonce", &self.nonce, MIN_NONCE_BYTES, MAX_NONCE_BYTES)?;
        Ok(())
    }
}

impl fmt::Debug for SignedUpdatePullRequest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SignedUpdatePullRequest")
            .field("tenant_id", &self.tenant_id)
            .field("device_id", &self.device_id)
            .field("platform", &self.platform)
            .field("architecture", &self.architecture)
            .field("update_ring", &self.update_ring)
            .field("issued_at", &self.issued_at)
            .finish_non_exhaustive()
    }
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct UpdatePullResponse {
    schema: String,
    tenant_id: String,
    device_id: String,
    platform: UpdatePlatform,
    architecture: UpdateArchitecture,
    update_ring: UpdateRing,
    items: Vec<SignedUpdateManifest>,
}

#[derive(Debug, PartialEq, Eq)]
pub enum UpdatePullResponseError {
    Client(FleetClientError),
    InvalidResponse,
    BindingMismatch,
    Update(UpdateError),
}

impl fmt::Display for UpdatePullResponseError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Client(_) => "update pull response exceeded its bound",
            Self::InvalidResponse => "update pull response is invalid",
            Self::BindingMismatch => "update pull response binding does not match",
            Self::Update(_) => "update pull manifest verification failed",
        })
    }
}

impl Error for UpdatePullResponseError {}

fn validate_nonce(nonce: &[u8]) -> Result<(), FleetClientError> {
    if !(MIN_NONCE_BYTES..=MAX_NONCE_BYTES).contains(&nonce.len()) {
        return Err(FleetClientError::InvalidField("nonce"));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::SigningKey;
    use kernaid_update_client::{ArtifactDescriptor, ReleaseRing, Rollout, UpdateManifestContent};
    use serde_json::json;
    use sha2::{Digest, Sha256};

    const TENANT: &str = "tenant-europe-1";
    const ISSUED_AT: &str = "2026-08-31T12:30:45Z";

    fn identity() -> DeviceIdentity {
        DeviceIdentity::from_seed(&[0x42; 32]).expect("fixed identity")
    }

    fn request() -> SignedUpdatePullRequest {
        SignedUpdatePullRequest::sign(
            &identity(),
            UpdatePullRequestInput::new(
                TENANT,
                UpdatePlatform::Linux,
                UpdateArchitecture::X86_64,
                UpdateRing::Stable,
                ISSUED_AT,
                vec![0xa5; 32],
            ),
        )
        .expect("sign update pull")
    }

    fn manifest(key: &SigningKey) -> SignedUpdateManifest {
        let artifact = b"fleet-update-artifact";
        let digest: [u8; 32] = Sha256::digest(artifact).into();
        SignedUpdateManifest::sign(
            UpdateManifestContent {
                sequence: 7,
                release_id: "release-7".to_owned(),
                release_version: "1.0.7".to_owned(),
                platform: UpdatePlatform::Linux,
                architecture: UpdateArchitecture::X86_64,
                release_ring: ReleaseRing::Stable,
                rollout: Rollout {
                    basis_points: 10_000,
                    seed: "release-7-cohort".to_owned(),
                },
                issued_at_unix: 1_000,
                not_before_unix: 1_000,
                expires_at_unix: 3_000,
                artifact: ArtifactDescriptor {
                    url: "https://updates.example.test/release-7.img".to_owned(),
                    size_bytes: artifact.len() as u64,
                    sha256: digest.iter().map(|byte| format!("{byte:02x}")).collect(),
                },
                emergency_rollback: false,
            },
            key,
        )
        .expect("sign manifest")
    }

    #[test]
    fn request_and_response_are_bound_to_device_target_and_vendor_key() {
        let identity = identity();
        let request = request();
        request
            .verify(TENANT, &identity.device_id(), &identity.public_key())
            .expect("verify request");
        let vendor = SigningKey::from_bytes(&[0x77; 32]);
        let response = serde_json::to_vec(&json!({
            "architecture": "x86_64",
            "deviceId": identity.device_id(),
            "items": [manifest(&vendor)],
            "platform": "linux",
            "schema": UPDATE_PULL_RESPONSE_SCHEMA,
            "tenantId": TENANT,
            "updateRing": "stable"
        }))
        .expect("response");
        assert_eq!(
            request
                .import_verified_response(&response, &vendor.verifying_key())
                .expect("verify response")
                .len(),
            1
        );

        let mut wrong: serde_json::Value = serde_json::from_slice(&response).expect("parse");
        wrong["tenantId"] = json!("tenant-other");
        assert!(matches!(
            request.import_verified_response(
                &serde_json::to_vec(&wrong).expect("serialize"),
                &vendor.verifying_key()
            ),
            Err(UpdatePullResponseError::BindingMismatch)
        ));
    }
}
