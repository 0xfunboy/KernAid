//! Compile-time contract for the disabled Rescue `fstab` repair candidate.
//!
//! The contract cannot select a path or carry replacement bytes. It binds a
//! versioned finding and exact before/inventory/after fingerprints. No broker
//! or handler dispatch is implemented by this module.

use serde::Deserialize;

pub const ACTION_PACK_MANIFEST_YAML: &str =
    include_str!("../action-pack.production-candidate-v1.yaml");
pub const INPUT_SCHEMA_JSON: &str =
    include_str!("../schemas/linux.fstab.disable-missing-uuid.v1.json");

pub const ACTION_PACK_API_VERSION: &str = "kernaid.dev/v1alpha1";
pub const ACTION_PACK_KIND: &str = "ActionPack";
pub const ACTION_PACK_NAME: &str = "linux-fstab-production-candidate";
pub const ACTION_PACK_VERSION: &str = "0.1.0";
pub const ACTION_ID: &str = "linux.fstab.disable-missing-uuid.v1";
pub const RESOURCE_ID: &str = "rescue:selected-linux-root:etc/fstab";
pub const FINDING_ID: &str = "KA-LNX-P0-003";
pub const FINDING_VERSION: u16 = 2;
pub const HANDLER_ID: &str = "kernaid-action-linux-rescue";
pub const INPUT_SCHEMA_PATH: &str = "schemas/linux.fstab.disable-missing-uuid.v1.json";
pub const INPUT_SCHEMA_ID: &str =
    "https://kernaid.dev/schemas/linux.fstab.disable-missing-uuid.v1.json";
pub const PREFLIGHT_ID: &str = "linux.fstab.preflight";
pub const VALIDATE_ID: &str = "linux.boot.validate-fstab";
pub const ROLLBACK_ID: &str = "linux.fstab.restore";
pub const MAX_ACTION_INPUT_BYTES: usize = 768;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CandidateRisk {
    R2,
}

impl CandidateRisk {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::R2 => "R2",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ProductionCandidateActionContract {
    pub id: &'static str,
    pub production_candidate_only: bool,
    pub rescue_only: bool,
    pub enabled_by_default: bool,
    pub risk: CandidateRisk,
    pub reversible: bool,
    pub requires_backup: bool,
    pub handler: &'static str,
    pub input_schema: &'static str,
    pub preflight: &'static str,
    pub validate: &'static str,
    pub rollback: &'static str,
}

pub const FSTAB_DISABLE_MISSING_UUID_ACTION: ProductionCandidateActionContract =
    ProductionCandidateActionContract {
        id: ACTION_ID,
        production_candidate_only: true,
        rescue_only: true,
        enabled_by_default: false,
        risk: CandidateRisk::R2,
        reversible: true,
        requires_backup: true,
        handler: HANDLER_ID,
        input_schema: INPUT_SCHEMA_PATH,
        preflight: PREFLIGHT_ID,
        validate: VALIDATE_ID,
        rollback: ROLLBACK_ID,
    };

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Sha256Fingerprint(String);

impl Sha256Fingerprint {
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DisableMissingUuidInput {
    expected_before_sha256: Sha256Fingerprint,
    observed_uuid_set_sha256: Sha256Fingerprint,
    expected_after_sha256: Sha256Fingerprint,
}

impl DisableMissingUuidInput {
    pub const fn resource_id(&self) -> &'static str {
        RESOURCE_ID
    }

    pub const fn finding_id(&self) -> &'static str {
        FINDING_ID
    }

    pub const fn finding_version(&self) -> u16 {
        FINDING_VERSION
    }

    pub fn expected_before_sha256(&self) -> &Sha256Fingerprint {
        &self.expected_before_sha256
    }

    pub fn observed_uuid_set_sha256(&self) -> &Sha256Fingerprint {
        &self.observed_uuid_set_sha256
    }

    pub fn expected_after_sha256(&self) -> &Sha256Fingerprint {
        &self.expected_after_sha256
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CandidateInputError {
    WrongActionId,
    InvalidSize,
    InvalidJson,
    WrongResourceId,
    WrongFinding,
    InvalidBeforeHash,
    InvalidObservedUuidSetHash,
    InvalidAfterHash,
    IdenticalBeforeAfter,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct WireDisableMissingUuidInput {
    resource_id: String,
    finding_id: String,
    finding_version: u16,
    expected_before_sha256: String,
    observed_uuid_set_sha256: String,
    expected_after_sha256: String,
}

fn is_lowercase_sha256(value: &str) -> bool {
    let Some(digest) = value.strip_prefix("sha256:") else {
        return false;
    };
    digest.len() == 64
        && digest
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
}

/// Parse only the compile-time-pinned, evidence-bound candidate input.
pub fn parse_disable_missing_uuid_input(
    action_id: &str,
    input: &[u8],
) -> Result<DisableMissingUuidInput, CandidateInputError> {
    if action_id != ACTION_ID {
        return Err(CandidateInputError::WrongActionId);
    }
    if input.is_empty() || input.len() > MAX_ACTION_INPUT_BYTES {
        return Err(CandidateInputError::InvalidSize);
    }

    let mut deserializer = serde_json::Deserializer::from_slice(input);
    let wire = WireDisableMissingUuidInput::deserialize(&mut deserializer)
        .map_err(|_| CandidateInputError::InvalidJson)?;
    deserializer
        .end()
        .map_err(|_| CandidateInputError::InvalidJson)?;

    if wire.resource_id != RESOURCE_ID {
        return Err(CandidateInputError::WrongResourceId);
    }
    if wire.finding_id != FINDING_ID || wire.finding_version != FINDING_VERSION {
        return Err(CandidateInputError::WrongFinding);
    }
    if !is_lowercase_sha256(&wire.expected_before_sha256) {
        return Err(CandidateInputError::InvalidBeforeHash);
    }
    if !is_lowercase_sha256(&wire.observed_uuid_set_sha256) {
        return Err(CandidateInputError::InvalidObservedUuidSetHash);
    }
    if !is_lowercase_sha256(&wire.expected_after_sha256) {
        return Err(CandidateInputError::InvalidAfterHash);
    }
    if wire.expected_before_sha256 == wire.expected_after_sha256 {
        return Err(CandidateInputError::IdenticalBeforeAfter);
    }

    Ok(DisableMissingUuidInput {
        expected_before_sha256: Sha256Fingerprint(wire.expected_before_sha256),
        observed_uuid_set_sha256: Sha256Fingerprint(wire.observed_uuid_set_sha256),
        expected_after_sha256: Sha256Fingerprint(wire.expected_after_sha256),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::{Value, json};

    const BEFORE: &str = "sha256:0000000000000000000000000000000000000000000000000000000000000000";
    const OBSERVED: &str =
        "sha256:1111111111111111111111111111111111111111111111111111111111111111";
    const AFTER: &str = "sha256:abcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcd";

    fn valid_input() -> Vec<u8> {
        serde_json::to_vec(&json!({
            "resourceId": RESOURCE_ID,
            "findingId": FINDING_ID,
            "findingVersion": FINDING_VERSION,
            "expectedBeforeSha256": BEFORE,
            "observedUuidSetSha256": OBSERVED,
            "expectedAfterSha256": AFTER,
        }))
        .expect("serialize candidate input")
    }

    #[test]
    fn parses_only_the_pinned_action_finding_and_resource() {
        let parsed = parse_disable_missing_uuid_input(ACTION_ID, &valid_input())
            .expect("parse candidate input");
        assert_eq!(parsed.resource_id(), RESOURCE_ID);
        assert_eq!(parsed.finding_id(), FINDING_ID);
        assert_eq!(parsed.finding_version(), FINDING_VERSION);
        assert_eq!(parsed.expected_before_sha256().as_str(), BEFORE);
        assert_eq!(parsed.observed_uuid_set_sha256().as_str(), OBSERVED);
        assert_eq!(parsed.expected_after_sha256().as_str(), AFTER);

        assert_eq!(
            parse_disable_missing_uuid_input("linux.fstab.other", &valid_input()),
            Err(CandidateInputError::WrongActionId)
        );
    }

    #[test]
    fn rejects_uncontracted_fields_bad_fingerprints_and_stale_finding() {
        let mut extra: Value = serde_json::from_slice(&valid_input()).expect("parse input JSON");
        extra["path"] = Value::String("/etc/fstab".to_owned());
        assert_eq!(
            parse_disable_missing_uuid_input(
                ACTION_ID,
                &serde_json::to_vec(&extra).expect("serialize extra field")
            ),
            Err(CandidateInputError::InvalidJson)
        );

        let stale = serde_json::to_vec(&json!({
            "resourceId": RESOURCE_ID,
            "findingId": FINDING_ID,
            "findingVersion": 1,
            "expectedBeforeSha256": BEFORE,
            "observedUuidSetSha256": OBSERVED,
            "expectedAfterSha256": AFTER,
        }))
        .expect("serialize stale finding");
        assert_eq!(
            parse_disable_missing_uuid_input(ACTION_ID, &stale),
            Err(CandidateInputError::WrongFinding)
        );

        let bad_hash = serde_json::to_vec(&json!({
            "resourceId": RESOURCE_ID,
            "findingId": FINDING_ID,
            "findingVersion": FINDING_VERSION,
            "expectedBeforeSha256": BEFORE,
            "observedUuidSetSha256": "sha256:UPPER",
            "expectedAfterSha256": AFTER,
        }))
        .expect("serialize bad hash");
        assert_eq!(
            parse_disable_missing_uuid_input(ACTION_ID, &bad_hash),
            Err(CandidateInputError::InvalidObservedUuidSetHash)
        );
    }

    #[test]
    fn embedded_manifest_schema_and_contract_stay_fail_closed() {
        assert!(ACTION_PACK_MANIFEST_YAML.contains("platforms: [linux-rescue]"));
        assert!(ACTION_PACK_MANIFEST_YAML.contains("productionCandidateOnly: true"));
        assert!(ACTION_PACK_MANIFEST_YAML.contains("enabledByDefault: false"));
        assert_eq!(ACTION_PACK_MANIFEST_YAML.matches("    - id:").count(), 1);

        let contract = std::hint::black_box(FSTAB_DISABLE_MISSING_UUID_ACTION);
        assert!(contract.production_candidate_only);
        assert!(contract.rescue_only);
        assert!(!contract.enabled_by_default);
        assert_eq!(contract.risk, CandidateRisk::R2);
        assert!(contract.reversible);
        assert!(contract.requires_backup);

        let schema: Value = serde_json::from_str(INPUT_SCHEMA_JSON).expect("parse schema");
        assert_eq!(schema["$id"], INPUT_SCHEMA_ID);
        assert_eq!(schema["x-kernaid-action-id"], ACTION_ID);
        assert_eq!(schema["x-kernaid-production-candidate-only"], true);
        assert_eq!(schema["x-kernaid-enabled-by-default"], false);
        assert_eq!(schema["additionalProperties"], false);
        assert_eq!(schema["properties"]["resourceId"]["const"], RESOURCE_ID);
        assert_eq!(schema["properties"]["findingId"]["const"], FINDING_ID);
        assert_eq!(
            schema["properties"]["findingVersion"]["const"],
            FINDING_VERSION
        );
        let properties = schema["properties"].as_object().expect("schema properties");
        assert_eq!(properties.len(), 6);
        for forbidden in ["path", "command", "replacement", "raw", "mountpoint"] {
            assert!(!properties.contains_key(forbidden));
        }
    }
}
