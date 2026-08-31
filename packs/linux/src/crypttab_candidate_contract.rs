//! Compile-time contract for the off-default Rescue `crypttab` candidate.
//!
//! The caller can bind hashes, but cannot provide a path, mapper name,
//! replacement bytes, command, key material, or block-device identifier.

use serde::Deserialize;

pub const ACTION_PACK_MANIFEST_YAML: &str =
    include_str!("../action-pack.crypttab-production-candidate-v1.yaml");
pub const INPUT_SCHEMA_JSON: &str =
    include_str!("../schemas/linux.crypttab.disable-missing-uuid.v1.json");

pub const ACTION_ID: &str = "linux.crypttab.disable-missing-uuid.v1";
pub const ACTION_PACK_VERSION: &str = "0.1.0";
pub const INPUT_SCHEMA_ID: &str =
    "https://kernaid.dev/schemas/linux.crypttab.disable-missing-uuid.v1.json";
pub const RESOURCE_ID: &str = "rescue:selected-linux-root:etc/crypttab";
pub const FINDING_ID: &str = "KA-LNX-P0-012";
pub const FINDING_VERSION: u16 = 1;
pub const PREFLIGHT_ID: &str = "linux.crypttab.preflight";
pub const VALIDATE_ID: &str = "linux.boot.validate-crypttab";
pub const ROLLBACK_ID: &str = "linux.crypttab.restore";
pub const SUPPORTED_FILESYSTEM: &str = "ext4";
pub const BACKUP_POLICY_ID: &str = "rescue.boot-vault.byte-exact-before-write.v1";
pub const BACKUP_RESERVATION_POLICY_ID: &str =
    "rescue.boot-vault.durable-reservation-before-approval.v1";
pub const BACKUP_PHYSICAL_PARENT_POLICY: &str = "distinct";
pub const CANCELLATION_POLICY_ID: &str = "rescue.transaction.safe-boundaries-auto-restore.v1";
pub const IDEMPOTENCY_POLICY_ID: &str = "rescue.crypttab.disable-missing-uuid.converge-once.v1";
pub const REDACTION_POLICY_ID: &str = "rescue.transaction.opaque-identifiers-and-hashes-only.v1";
pub const TRANSACTION_TIMEOUT_MILLISECONDS: u64 = 120_000;
pub const MAX_ACTION_INPUT_BYTES: usize = 1024;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DisableMissingCrypttabUuidInput {
    expected_before_sha256: String,
    observed_uuid_set_sha256: String,
    fstab_consumer_set_sha256: String,
    expected_after_sha256: String,
}

impl DisableMissingCrypttabUuidInput {
    pub const fn resource_id(&self) -> &'static str {
        RESOURCE_ID
    }
    pub const fn finding_id(&self) -> &'static str {
        FINDING_ID
    }
    pub const fn finding_version(&self) -> u16 {
        FINDING_VERSION
    }
    pub fn expected_before_sha256(&self) -> &str {
        &self.expected_before_sha256
    }
    pub fn observed_uuid_set_sha256(&self) -> &str {
        &self.observed_uuid_set_sha256
    }
    pub fn fstab_consumer_set_sha256(&self) -> &str {
        &self.fstab_consumer_set_sha256
    }
    pub fn expected_after_sha256(&self) -> &str {
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
    InvalidHash,
    IdenticalBeforeAfter,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct WireInput {
    resource_id: String,
    finding_id: String,
    finding_version: u16,
    expected_before_sha256: String,
    observed_uuid_set_sha256: String,
    fstab_consumer_set_sha256: String,
    expected_after_sha256: String,
}

fn valid_sha256(value: &str) -> bool {
    value.strip_prefix("sha256:").is_some_and(|digest| {
        digest.len() == 64
            && digest
                .bytes()
                .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
    })
}

pub fn parse_disable_missing_uuid_input(
    action_id: &str,
    input: &[u8],
) -> Result<DisableMissingCrypttabUuidInput, CandidateInputError> {
    if action_id != ACTION_ID {
        return Err(CandidateInputError::WrongActionId);
    }
    if input.is_empty() || input.len() > MAX_ACTION_INPUT_BYTES {
        return Err(CandidateInputError::InvalidSize);
    }
    let mut deserializer = serde_json::Deserializer::from_slice(input);
    let wire =
        WireInput::deserialize(&mut deserializer).map_err(|_| CandidateInputError::InvalidJson)?;
    deserializer
        .end()
        .map_err(|_| CandidateInputError::InvalidJson)?;
    if wire.resource_id != RESOURCE_ID {
        return Err(CandidateInputError::WrongResourceId);
    }
    if wire.finding_id != FINDING_ID || wire.finding_version != FINDING_VERSION {
        return Err(CandidateInputError::WrongFinding);
    }
    if ![
        &wire.expected_before_sha256,
        &wire.observed_uuid_set_sha256,
        &wire.fstab_consumer_set_sha256,
        &wire.expected_after_sha256,
    ]
    .into_iter()
    .all(|value| valid_sha256(value))
    {
        return Err(CandidateInputError::InvalidHash);
    }
    if wire.expected_before_sha256 == wire.expected_after_sha256 {
        return Err(CandidateInputError::IdenticalBeforeAfter);
    }
    Ok(DisableMissingCrypttabUuidInput {
        expected_before_sha256: wire.expected_before_sha256,
        observed_uuid_set_sha256: wire.observed_uuid_set_sha256,
        fstab_consumer_set_sha256: wire.fstab_consumer_set_sha256,
        expected_after_sha256: wire.expected_after_sha256,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn hash(character: char) -> String {
        format!("sha256:{}", character.to_string().repeat(64))
    }

    fn valid_input() -> Vec<u8> {
        serde_json::to_vec(&json!({
            "resourceId": RESOURCE_ID,
            "findingId": FINDING_ID,
            "findingVersion": FINDING_VERSION,
            "expectedBeforeSha256": hash('1'),
            "observedUuidSetSha256": hash('2'),
            "fstabConsumerSetSha256": hash('3'),
            "expectedAfterSha256": hash('4')
        }))
        .expect("serialize contract")
    }

    #[test]
    fn accepts_only_the_exact_closed_contract() {
        let input = parse_disable_missing_uuid_input(ACTION_ID, &valid_input())
            .expect("valid exact contract");
        assert_eq!(input.resource_id(), RESOURCE_ID);
        assert_eq!(input.finding_id(), FINDING_ID);
        assert_eq!(input.finding_version(), FINDING_VERSION);
        assert_eq!(input.fstab_consumer_set_sha256(), hash('3'));
    }

    #[test]
    fn rejects_unknown_fields_actions_and_identical_states() {
        assert_eq!(
            parse_disable_missing_uuid_input("shell.exec", &valid_input()),
            Err(CandidateInputError::WrongActionId)
        );
        let mut value: serde_json::Value =
            serde_json::from_slice(&valid_input()).expect("valid json");
        value["path"] = json!("/etc/crypttab");
        assert_eq!(
            parse_disable_missing_uuid_input(
                ACTION_ID,
                &serde_json::to_vec(&value).expect("serialize")
            ),
            Err(CandidateInputError::InvalidJson)
        );
        value.as_object_mut().expect("object").remove("path");
        value["expectedAfterSha256"] = value["expectedBeforeSha256"].clone();
        assert_eq!(
            parse_disable_missing_uuid_input(
                ACTION_ID,
                &serde_json::to_vec(&value).expect("serialize")
            ),
            Err(CandidateInputError::IdenticalBeforeAfter)
        );
    }

    #[test]
    fn embedded_manifest_and_schema_pin_the_closed_surface() {
        assert!(ACTION_PACK_MANIFEST_YAML.contains("platforms: [linux-rescue]"));
        assert!(ACTION_PACK_MANIFEST_YAML.contains("productionCandidateOnly: true"));
        assert!(ACTION_PACK_MANIFEST_YAML.contains("enabledByDefault: false"));
        assert!(ACTION_PACK_MANIFEST_YAML.contains(&format!("version: {ACTION_PACK_VERSION}")));
        assert!(ACTION_PACK_MANIFEST_YAML.contains(&format!("    - id: {ACTION_ID}")));
        assert!(ACTION_PACK_MANIFEST_YAML.contains("backupPhysicalParent: distinct"));
        assert_eq!(ACTION_PACK_MANIFEST_YAML.matches("    - id:").count(), 1);

        let schema: serde_json::Value =
            serde_json::from_str(INPUT_SCHEMA_JSON).expect("parse embedded schema");
        assert_eq!(schema["$id"], INPUT_SCHEMA_ID);
        assert_eq!(schema["x-kernaid-action-id"], ACTION_ID);
        assert_eq!(schema["x-kernaid-production-candidate-only"], true);
        assert_eq!(schema["x-kernaid-enabled-by-default"], false);
        assert_eq!(schema["additionalProperties"], false);
        assert_eq!(schema["properties"]["resourceId"]["const"], RESOURCE_ID);
        let properties = schema["properties"].as_object().expect("properties");
        assert_eq!(properties.len(), 7);
        for forbidden in ["path", "command", "replacement", "raw", "mapperName", "key"] {
            assert!(!properties.contains_key(forbidden));
        }
    }
}
