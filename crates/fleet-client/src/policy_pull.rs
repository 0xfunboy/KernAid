use super::{
    ED25519_PUBLIC_KEY_BYTES, ED25519_SIGNATURE_BYTES, FleetClientError, MAX_ID_BYTES,
    MAX_TIMESTAMP_BYTES, canonical_json, decode_bounded_base64url, decode_fixed_base64url,
    import_canonical, validate_identifier, validate_timestamp, validate_transfer_size,
    verify_signature,
};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use kernaid_device_identity::{DeviceIdentity, device_id_for_public_key, validate_device_id};
use serde::{Deserialize, Serialize};
use std::fmt;
use zeroize::Zeroizing;

/// Signed policy pull request schema.
pub const POLICY_PULL_REQUEST_SCHEMA: &str = "dev.kernaid.fleet.policy-pull-request.v1";
/// Exact direct-prefix Ed25519 signature domain.
pub const POLICY_PULL_SIGNATURE_DOMAIN: &[u8] = b"kernaid:fleet:policy-pull:v1\0";

const MAX_POLICY_PULL_BYTES: usize = 8 * 1024;
const MIN_POLICY_PULL_NONCE_BYTES: usize = 16;
const MAX_POLICY_PULL_NONCE_BYTES: usize = 64;

/// Caller-owned values for one fresh policy pull proof.
pub struct PolicyPullRequestInput {
    tenant_id: String,
    issued_at: String,
    nonce: Zeroizing<Vec<u8>>,
}

impl PolicyPullRequestInput {
    #[must_use]
    pub fn new(
        tenant_id: impl Into<String>,
        issued_at: impl Into<String>,
        nonce: impl Into<Vec<u8>>,
    ) -> Self {
        Self {
            tenant_id: tenant_id.into(),
            issued_at: issued_at.into(),
            nonce: Zeroizing::new(nonce.into()),
        }
    }
}

impl fmt::Debug for PolicyPullRequestInput {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PolicyPullRequestInput")
            .field("tenant_id", &self.tenant_id)
            .field("issued_at", &self.issued_at)
            .finish_non_exhaustive()
    }
}

/// Fresh, device-authenticated request for applicable Fleet policy bundles.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SignedPolicyPullRequest {
    schema: String,
    tenant_id: String,
    device_id: String,
    issued_at: String,
    nonce: String,
    signature: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct UnsignedPolicyPullRequest<'a> {
    schema: &'a str,
    tenant_id: &'a str,
    device_id: &'a str,
    issued_at: &'a str,
    nonce: &'a str,
}

impl SignedPolicyPullRequest {
    /// Sign with the existing enrolled identity without exporting its seed.
    pub fn sign(
        identity: &DeviceIdentity,
        input: PolicyPullRequestInput,
    ) -> Result<Self, FleetClientError> {
        validate_identifier("tenantId", &input.tenant_id)?;
        validate_timestamp("issuedAt", &input.issued_at)?;
        validate_nonce(input.nonce.as_slice())?;
        let mut request = Self {
            schema: POLICY_PULL_REQUEST_SCHEMA.to_owned(),
            tenant_id: input.tenant_id,
            device_id: identity.device_id(),
            issued_at: input.issued_at,
            nonce: URL_SAFE_NO_PAD.encode(input.nonce.as_slice()),
            signature: String::new(),
        };
        request.validate_unsigned()?;
        let unsigned = Zeroizing::new(request.unsigned_canonical()?);
        let signature = identity
            .sign_domain_separated_payload(POLICY_PULL_SIGNATURE_DOMAIN, unsigned.as_slice())
            .map_err(FleetClientError::Identity)?;
        request.signature = URL_SAFE_NO_PAD.encode(signature);
        request.validate()?;
        Ok(request)
    }

    /// Verify against the enrollment registry's tenant/device/key binding.
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
            POLICY_PULL_SIGNATURE_DOMAIN,
            unsigned.as_slice(),
            &signature,
        )
    }

    /// Export the exact canonical transport representation.
    pub fn export_offline(&self) -> Result<Vec<u8>, FleetClientError> {
        self.validate()?;
        let bytes = canonical_json(self)?;
        validate_transfer_size(bytes.len(), MAX_POLICY_PULL_BYTES)?;
        Ok(bytes)
    }

    /// Import canonical bytes and authenticate them with enrolled device data.
    pub fn import_offline(
        bytes: &[u8],
        expected_tenant_id: &str,
        expected_device_id: &str,
        enrolled_public_key: &[u8; ED25519_PUBLIC_KEY_BYTES],
    ) -> Result<Self, FleetClientError> {
        let request: Self = import_canonical(bytes, MAX_POLICY_PULL_BYTES)?;
        request.verify(expected_tenant_id, expected_device_id, enrolled_public_key)?;
        Ok(request)
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
    pub fn issued_at(&self) -> &str {
        &self.issued_at
    }

    fn unsigned(&self) -> UnsignedPolicyPullRequest<'_> {
        UnsignedPolicyPullRequest {
            schema: &self.schema,
            tenant_id: &self.tenant_id,
            device_id: &self.device_id,
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
        if self.schema != POLICY_PULL_REQUEST_SCHEMA {
            return Err(FleetClientError::InvalidField("schema"));
        }
        validate_identifier("tenantId", &self.tenant_id)?;
        if self.tenant_id.len() > MAX_ID_BYTES {
            return Err(FleetClientError::InvalidField("tenantId"));
        }
        validate_device_id(&self.device_id)
            .map_err(|_| FleetClientError::InvalidField("deviceId"))?;
        validate_timestamp("issuedAt", &self.issued_at)?;
        if self.issued_at.len() > MAX_TIMESTAMP_BYTES {
            return Err(FleetClientError::InvalidField("issuedAt"));
        }
        decode_bounded_base64url(
            "nonce",
            &self.nonce,
            MIN_POLICY_PULL_NONCE_BYTES,
            MAX_POLICY_PULL_NONCE_BYTES,
        )?;
        Ok(())
    }
}

impl fmt::Debug for SignedPolicyPullRequest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SignedPolicyPullRequest")
            .field("tenant_id", &self.tenant_id)
            .field("device_id", &self.device_id)
            .field("issued_at", &self.issued_at)
            .finish_non_exhaustive()
    }
}

fn validate_nonce(nonce: &[u8]) -> Result<(), FleetClientError> {
    if !(MIN_POLICY_PULL_NONCE_BYTES..=MAX_POLICY_PULL_NONCE_BYTES).contains(&nonce.len()) {
        return Err(FleetClientError::InvalidField("nonce"));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use kernaid_device_identity::DeviceIdentity;
    use serde_json::{Value, json};

    const TENANT: &str = "tenant-europe-1";
    const ISSUED_AT: &str = "2026-08-31T12:30:45Z";
    const FIXTURE_UNSIGNED: &str = "{\"deviceId\":\"KA-3097e2dee2cb4a34b53840cd\",\"issuedAt\":\"2026-08-31T12:30:45Z\",\"nonce\":\"paWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaU\",\"schema\":\"dev.kernaid.fleet.policy-pull-request.v1\",\"tenantId\":\"tenant-europe-1\"}";
    const FIXTURE_JSON: &str = "{\"deviceId\":\"KA-3097e2dee2cb4a34b53840cd\",\"issuedAt\":\"2026-08-31T12:30:45Z\",\"nonce\":\"paWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaU\",\"schema\":\"dev.kernaid.fleet.policy-pull-request.v1\",\"signature\":\"7COdZ1ket_ukr-YZOcMHj3kdfeL6gSuM5U0ggUlAOXnsjdUw0duGkfyWh4BqBV0_nEcbXvbfmETKcuIdiM5JCA\",\"tenantId\":\"tenant-europe-1\"}";

    fn identity() -> DeviceIdentity {
        DeviceIdentity::from_seed(&[0x42; 32]).expect("fixed identity")
    }

    fn request() -> SignedPolicyPullRequest {
        SignedPolicyPullRequest::sign(
            &identity(),
            PolicyPullRequestInput::new(TENANT, ISSUED_AT, vec![0xa5; 32]),
        )
        .expect("sign pull")
    }

    #[test]
    fn roundtrip_uses_enrolled_key_and_exact_canonical_bytes() {
        let identity = identity();
        let request = request();
        request
            .verify(TENANT, &identity.device_id(), &identity.public_key())
            .expect("verify pull");
        let bytes = request.export_offline().expect("export pull");
        let imported = SignedPolicyPullRequest::import_offline(
            &bytes,
            TENANT,
            &identity.device_id(),
            &identity.public_key(),
        )
        .expect("import pull");
        assert_eq!(imported.export_offline().expect("re-export"), bytes);
    }

    #[test]
    fn fixed_vector_and_tampering_fail_closed() {
        let request = request();
        let bytes = request.export_offline().expect("export pull");
        let unsigned = request.unsigned_canonical().expect("unsigned pull");
        assert_eq!(bytes, FIXTURE_JSON.as_bytes());
        assert_eq!(unsigned, FIXTURE_UNSIGNED.as_bytes());

        let mut tampered: Value = serde_json::from_slice(&bytes).expect("parse pull");
        tampered["issuedAt"] = json!("2026-08-31T12:30:46Z");
        let tampered = canonical_json(&tampered).expect("canonical tamper");
        assert_eq!(
            SignedPolicyPullRequest::import_offline(
                &tampered,
                TENANT,
                &identity().device_id(),
                &identity().public_key(),
            ),
            Err(FleetClientError::InvalidSignature)
        );

        let mut unknown: Value = serde_json::from_slice(&bytes).expect("parse pull");
        unknown["rawDiagnostics"] = json!("forbidden");
        let unknown = canonical_json(&unknown).expect("canonical unknown");
        assert_eq!(
            SignedPolicyPullRequest::import_offline(
                &unknown,
                TENANT,
                &identity().device_id(),
                &identity().public_key(),
            ),
            Err(FleetClientError::InvalidJson)
        );
    }
}
