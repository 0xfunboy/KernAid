//! Compile-time-pinned contract for the disposable `fstab` repair fixture.
//!
//! This module validates only a typed action ID and bounded JSON input. It
//! does not dispatch the fixture transaction or expose it to a broker or UI.

use serde::Deserialize;

pub const ACTION_PACK_MANIFEST_YAML: &str = include_str!("../action-pack.fixture-v1.yaml");
pub const FSTAB_FIXTURE_INPUT_SCHEMA_JSON: &str =
    include_str!("../schemas/linux.fstab.repair-entry.fixture-v1.json");

pub const ACTION_PACK_API_VERSION: &str = "kernaid.dev/v1alpha1";
pub const ACTION_PACK_KIND: &str = "ActionPack";
pub const ACTION_PACK_NAME: &str = "linux-boot-fixture-lab";
pub const ACTION_PACK_VERSION: &str = "0.1.0";
pub const FIXTURE_ACTION_ID: &str = "linux.fstab.repair-entry.fixture-v1";
pub const FIXTURE_RESOURCE_ID: &str = "fixture:linux-fstab-v1";
pub const FIXTURE_HANDLER_ID: &str = "kernaid-action-linux";
pub const FIXTURE_INPUT_SCHEMA_PATH: &str = "schemas/linux.fstab.repair-entry.fixture-v1.json";
pub const FIXTURE_INPUT_SCHEMA_ID: &str =
    "https://kernaid.dev/schemas/linux.fstab.repair-entry.fixture-v1.json";
pub const FIXTURE_PREFLIGHT_ID: &str = "linux.fstab.preflight";
pub const FIXTURE_VALIDATE_ID: &str = "linux.boot.validate-fstab";
pub const FIXTURE_ROLLBACK_ID: &str = "linux.fstab.restore";
pub const MAX_FIXTURE_ACTION_INPUT_BYTES: usize = 512;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ActionRisk {
    R2,
}

impl ActionRisk {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::R2 => "R2",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FixtureActionContract {
    pub id: &'static str,
    pub fixture_lab_only: bool,
    pub risk: ActionRisk,
    pub reversible: bool,
    pub requires_backup: bool,
    pub handler: &'static str,
    pub input_schema: &'static str,
    pub preflight: &'static str,
    pub validate: &'static str,
    pub rollback: &'static str,
}

pub const FSTAB_FIXTURE_ACTION: FixtureActionContract = FixtureActionContract {
    id: FIXTURE_ACTION_ID,
    fixture_lab_only: true,
    risk: ActionRisk::R2,
    reversible: true,
    requires_backup: true,
    handler: FIXTURE_HANDLER_ID,
    input_schema: FIXTURE_INPUT_SCHEMA_PATH,
    preflight: FIXTURE_PREFLIGHT_ID,
    validate: FIXTURE_VALIDATE_ID,
    rollback: FIXTURE_ROLLBACK_ID,
};

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Sha256Fingerprint(String);

impl Sha256Fingerprint {
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FixtureFstabRepairInput {
    expected_before_sha256: Sha256Fingerprint,
    expected_after_sha256: Sha256Fingerprint,
}

impl FixtureFstabRepairInput {
    pub const fn resource_id(&self) -> &'static str {
        FIXTURE_RESOURCE_ID
    }

    pub fn expected_before_sha256(&self) -> &Sha256Fingerprint {
        &self.expected_before_sha256
    }

    pub fn expected_after_sha256(&self) -> &Sha256Fingerprint {
        &self.expected_after_sha256
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FixtureActionInputError {
    WrongActionId,
    InvalidSize,
    InvalidJson,
    WrongResourceId,
    InvalidBeforeHash,
    InvalidAfterHash,
    IdenticalFingerprints,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct WireFixtureFstabRepairInput {
    resource_id: String,
    expected_before_sha256: String,
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

/// Parses a fixture action input without loading a manifest or schema from a
/// caller-controlled path. Unknown and duplicate fields are rejected by the
/// derived struct deserializer, and `end` rejects a second/trailing JSON value.
pub fn parse_fixture_fstab_repair_input(
    action_id: &str,
    input: &[u8],
) -> Result<FixtureFstabRepairInput, FixtureActionInputError> {
    if action_id != FIXTURE_ACTION_ID {
        return Err(FixtureActionInputError::WrongActionId);
    }
    if input.is_empty() || input.len() > MAX_FIXTURE_ACTION_INPUT_BYTES {
        return Err(FixtureActionInputError::InvalidSize);
    }

    let mut deserializer = serde_json::Deserializer::from_slice(input);
    let wire = WireFixtureFstabRepairInput::deserialize(&mut deserializer)
        .map_err(|_| FixtureActionInputError::InvalidJson)?;
    deserializer
        .end()
        .map_err(|_| FixtureActionInputError::InvalidJson)?;

    if wire.resource_id != FIXTURE_RESOURCE_ID {
        return Err(FixtureActionInputError::WrongResourceId);
    }
    if !is_lowercase_sha256(&wire.expected_before_sha256) {
        return Err(FixtureActionInputError::InvalidBeforeHash);
    }
    if !is_lowercase_sha256(&wire.expected_after_sha256) {
        return Err(FixtureActionInputError::InvalidAfterHash);
    }
    if wire.expected_before_sha256 == wire.expected_after_sha256 {
        return Err(FixtureActionInputError::IdenticalFingerprints);
    }

    Ok(FixtureFstabRepairInput {
        expected_before_sha256: Sha256Fingerprint(wire.expected_before_sha256),
        expected_after_sha256: Sha256Fingerprint(wire.expected_after_sha256),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::{Value, json};

    const BEFORE_HASH: &str =
        "sha256:0000000000000000000000000000000000000000000000000000000000000000";
    const AFTER_HASH: &str =
        "sha256:abcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcd";

    fn valid_input() -> Vec<u8> {
        serde_json::to_vec(&json!({
            "resourceId": FIXTURE_RESOURCE_ID,
            "expectedBeforeSha256": BEFORE_HASH,
            "expectedAfterSha256": AFTER_HASH,
        }))
        .expect("serialize valid fixture action input")
    }

    #[test]
    fn parses_only_the_pinned_fixture_action_and_resource() {
        let parsed = parse_fixture_fstab_repair_input(FIXTURE_ACTION_ID, &valid_input())
            .expect("parse valid fixture action input");
        assert_eq!(parsed.resource_id(), FIXTURE_RESOURCE_ID);
        assert_eq!(parsed.expected_before_sha256().as_str(), BEFORE_HASH);
        assert_eq!(parsed.expected_after_sha256().as_str(), AFTER_HASH);
        assert_eq!(FSTAB_FIXTURE_ACTION.id, FIXTURE_ACTION_ID);

        assert_eq!(
            parse_fixture_fstab_repair_input("linux.fstab.repair-entry", &valid_input()),
            Err(FixtureActionInputError::WrongActionId)
        );
        let wrong_resource = serde_json::to_vec(&json!({
            "resourceId": "fixture:some-other-resource",
            "expectedBeforeSha256": BEFORE_HASH,
            "expectedAfterSha256": AFTER_HASH,
        }))
        .expect("serialize wrong resource input");
        assert_eq!(
            parse_fixture_fstab_repair_input(FIXTURE_ACTION_ID, &wrong_resource),
            Err(FixtureActionInputError::WrongResourceId)
        );
    }

    #[test]
    fn rejects_every_uncontracted_mutation_field() {
        for field in ["extra", "path", "raw", "replacement", "command"] {
            let mut value = json!({
                "resourceId": FIXTURE_RESOURCE_ID,
                "expectedBeforeSha256": BEFORE_HASH,
                "expectedAfterSha256": AFTER_HASH,
            });
            value[field] = Value::String("untrusted".to_owned());
            let bytes = serde_json::to_vec(&value).expect("serialize extra-field input");
            assert_eq!(
                parse_fixture_fstab_repair_input(FIXTURE_ACTION_ID, &bytes),
                Err(FixtureActionInputError::InvalidJson),
                "field {field} must be rejected"
            );
        }
    }

    #[test]
    fn rejects_malformed_or_non_lowercase_hashes() {
        for invalid in [
            "",
            "SHA256:0000000000000000000000000000000000000000000000000000000000000000",
            "sha256:000000000000000000000000000000000000000000000000000000000000000",
            "sha256:00000000000000000000000000000000000000000000000000000000000000000",
            "sha256:ABCDEFabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcd",
            "sha256:gbcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcd",
        ] {
            let invalid_before = serde_json::to_vec(&json!({
                "resourceId": FIXTURE_RESOURCE_ID,
                "expectedBeforeSha256": invalid,
                "expectedAfterSha256": AFTER_HASH,
            }))
            .expect("serialize malformed before hash");
            assert_eq!(
                parse_fixture_fstab_repair_input(FIXTURE_ACTION_ID, &invalid_before),
                Err(FixtureActionInputError::InvalidBeforeHash),
                "before hash {invalid:?} must be rejected"
            );

            let invalid_after = serde_json::to_vec(&json!({
                "resourceId": FIXTURE_RESOURCE_ID,
                "expectedBeforeSha256": BEFORE_HASH,
                "expectedAfterSha256": invalid,
            }))
            .expect("serialize malformed after hash");
            assert_eq!(
                parse_fixture_fstab_repair_input(FIXTURE_ACTION_ID, &invalid_after),
                Err(FixtureActionInputError::InvalidAfterHash),
                "after hash {invalid:?} must be rejected"
            );
        }
    }

    #[test]
    fn rejects_duplicate_trailing_and_oversized_json() {
        let duplicate = format!(
            r#"{{"resourceId":"{FIXTURE_RESOURCE_ID}","resourceId":"{FIXTURE_RESOURCE_ID}","expectedBeforeSha256":"{BEFORE_HASH}","expectedAfterSha256":"{AFTER_HASH}"}}"#
        );
        assert_eq!(
            parse_fixture_fstab_repair_input(FIXTURE_ACTION_ID, duplicate.as_bytes()),
            Err(FixtureActionInputError::InvalidJson)
        );

        let mut trailing = valid_input();
        trailing.extend_from_slice(b" {}");
        assert_eq!(
            parse_fixture_fstab_repair_input(FIXTURE_ACTION_ID, &trailing),
            Err(FixtureActionInputError::InvalidJson)
        );
        assert_eq!(
            parse_fixture_fstab_repair_input(FIXTURE_ACTION_ID, &[]),
            Err(FixtureActionInputError::InvalidSize)
        );
        assert_eq!(
            parse_fixture_fstab_repair_input(
                FIXTURE_ACTION_ID,
                &vec![b' '; MAX_FIXTURE_ACTION_INPUT_BYTES + 1],
            ),
            Err(FixtureActionInputError::InvalidSize)
        );

        let identical = serde_json::to_vec(&json!({
            "resourceId": FIXTURE_RESOURCE_ID,
            "expectedBeforeSha256": BEFORE_HASH,
            "expectedAfterSha256": BEFORE_HASH,
        }))
        .expect("serialize identical fingerprints");
        assert_eq!(
            parse_fixture_fstab_repair_input(FIXTURE_ACTION_ID, &identical),
            Err(FixtureActionInputError::IdenticalFingerprints)
        );
    }

    #[test]
    fn embedded_manifest_schema_and_typed_contract_agree_exactly() {
        let expected_manifest = format!(
            concat!(
                "apiVersion: {}\n",
                "kind: {}\n",
                "metadata:\n",
                "  name: {}\n",
                "  version: {}\n",
                "spec:\n",
                "  fixtureLabOnly: true\n",
                "  platforms: [linux-fixture-lab]\n",
                "  actions:\n",
                "    - id: {}\n",
                "      fixtureLabOnly: true\n",
                "      risk: {}\n",
                "      reversible: true\n",
                "      requiresBackup: true\n",
                "      handler: {}\n",
                "      inputSchema: {}\n",
                "      preflight: {}\n",
                "      validate: {}\n",
                "      rollback: {}\n",
            ),
            ACTION_PACK_API_VERSION,
            ACTION_PACK_KIND,
            ACTION_PACK_NAME,
            ACTION_PACK_VERSION,
            FIXTURE_ACTION_ID,
            ActionRisk::R2.as_str(),
            FIXTURE_HANDLER_ID,
            FIXTURE_INPUT_SCHEMA_PATH,
            FIXTURE_PREFLIGHT_ID,
            FIXTURE_VALIDATE_ID,
            FIXTURE_ROLLBACK_ID,
        );
        assert_eq!(ACTION_PACK_MANIFEST_YAML, expected_manifest);
        assert_eq!(ACTION_PACK_MANIFEST_YAML.matches("    - id:").count(), 1);
        let typed_contract = std::hint::black_box(FSTAB_FIXTURE_ACTION);
        assert_eq!(typed_contract.id, FIXTURE_ACTION_ID);
        assert!(typed_contract.fixture_lab_only);
        assert_eq!(typed_contract.risk, ActionRisk::R2);
        assert!(typed_contract.reversible);
        assert!(typed_contract.requires_backup);
        assert_eq!(typed_contract.handler, FIXTURE_HANDLER_ID);
        assert_eq!(typed_contract.input_schema, FIXTURE_INPUT_SCHEMA_PATH);
        assert_eq!(typed_contract.preflight, FIXTURE_PREFLIGHT_ID);
        assert_eq!(typed_contract.validate, FIXTURE_VALIDATE_ID);
        assert_eq!(typed_contract.rollback, FIXTURE_ROLLBACK_ID);

        let schema: Value = serde_json::from_str(FSTAB_FIXTURE_INPUT_SCHEMA_JSON)
            .expect("parse compile-time embedded fixture input schema");
        assert_eq!(schema["$id"], FIXTURE_INPUT_SCHEMA_ID);
        assert_eq!(schema["x-kernaid-action-id"], FIXTURE_ACTION_ID);
        assert_eq!(schema["x-kernaid-fixture-lab-only"], true);
        assert_eq!(schema["type"], "object");
        assert_eq!(schema["additionalProperties"], false);
        assert_eq!(
            schema["required"],
            json!(["resourceId", "expectedBeforeSha256", "expectedAfterSha256"])
        );
        assert_eq!(
            schema["properties"]["resourceId"]["const"],
            FIXTURE_RESOURCE_ID
        );
        assert_eq!(
            schema["properties"]["expectedBeforeSha256"]["pattern"],
            "^sha256:[0-9a-f]{64}$"
        );
        assert_eq!(
            schema["properties"]["expectedAfterSha256"]["pattern"],
            "^sha256:[0-9a-f]{64}$"
        );
        let properties = schema["properties"]
            .as_object()
            .expect("schema properties object");
        assert_eq!(properties.len(), 3);
        assert!(properties.contains_key("resourceId"));
        assert!(properties.contains_key("expectedBeforeSha256"));
        assert!(properties.contains_key("expectedAfterSha256"));
    }
}
