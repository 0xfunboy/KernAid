use crate::rescue_corpus::{
    DiagnosisProposal, ProjectedProviderContext, WireEvidence, project_diagnosis, valid_evidence_id,
};
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use serde_json::value::RawValue;
use std::fmt;

pub const API_VERSION: &str = "kernaid.dev/rescue-openai/v1alpha1";
pub const MAX_REQUEST_FRAME_BYTES: usize = 96 * 1024;
pub const MAX_RESPONSE_FRAME_BYTES: usize = 64 * 1024;
const PROVIDER_NAME: &str = "openai";
const PROVIDER_PROFILE: &str = "rescue-default";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FrameError {
    InvalidSize,
    InvalidFrame,
    InvalidRequest,
    InvalidResponse,
    ResponseTooLarge,
}

impl fmt::Display for FrameError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::InvalidSize => "local provider frame size is invalid",
            Self::InvalidFrame => "local provider frame is invalid",
            Self::InvalidRequest => "local provider request is invalid",
            Self::InvalidResponse => "local provider response is invalid",
            Self::ResponseTooLarge => "local provider response is too large",
        })
    }
}

impl std::error::Error for FrameError {}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ProviderOperation {
    Status,
    Diagnose,
}

impl ProviderOperation {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Status => "provider.status",
            Self::Diagnose => "provider.openai.diagnose",
        }
    }

    fn parse(value: &str) -> Result<Self, FrameError> {
        match value {
            "provider.status" => Ok(Self::Status),
            "provider.openai.diagnose" => Ok(Self::Diagnose),
            _ => Err(FrameError::InvalidRequest),
        }
    }
}

#[derive(Clone, Debug, PartialEq)]
pub enum ProviderRequest {
    Status {
        request_id: String,
    },
    Diagnose {
        request_id: String,
        context: ProjectedProviderContext,
    },
}

impl ProviderRequest {
    pub fn request_id(&self) -> &str {
        match self {
            Self::Status { request_id } | Self::Diagnose { request_id, .. } => request_id,
        }
    }

    pub const fn operation(&self) -> ProviderOperation {
        match self {
            Self::Status { .. } => ProviderOperation::Status,
            Self::Diagnose { .. } => ProviderOperation::Diagnose,
        }
    }

    pub fn context(&self) -> Option<&ProjectedProviderContext> {
        match self {
            Self::Status { .. } => None,
            Self::Diagnose { context, .. } => Some(context),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum VaultState {
    Absent,
    Unprovisioned,
    Locked,
    Unlocking,
    Unlocked,
    Locking,
    FaultedRebootRequired,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CredentialState {
    Unavailable,
    Absent,
    Configured,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProviderErrorCode {
    Busy,
    CredentialUnavailable,
    InvalidRequest,
    InvalidResponse,
    RequestTooLarge,
    ResponseTooLarge,
    Timeout,
    Transport,
    Upstream,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProviderStatus {
    vault: VaultState,
    credential: CredentialState,
}

impl ProviderStatus {
    pub fn new(vault: VaultState, credential: CredentialState) -> Result<Self, FrameError> {
        if vault != VaultState::Unlocked && credential != CredentialState::Unavailable {
            return Err(FrameError::InvalidResponse);
        }
        Ok(Self { vault, credential })
    }

    pub const fn vault(&self) -> VaultState {
        self.vault
    }

    pub const fn credential(&self) -> CredentialState {
        self.credential
    }
}

#[derive(Clone, Debug, PartialEq)]
enum ProviderResponseKind {
    Status(ProviderStatus),
    Diagnosis(DiagnosisProposal),
    Error {
        operation: ProviderOperation,
        code: ProviderErrorCode,
    },
}

#[derive(Clone, Debug, PartialEq)]
pub struct ProviderResponse {
    request_id: String,
    kind: ProviderResponseKind,
}

impl ProviderResponse {
    pub fn status(request_id: &str, status: ProviderStatus) -> Result<Self, FrameError> {
        validate_request_id(request_id)?;
        Ok(Self {
            request_id: request_id.to_owned(),
            kind: ProviderResponseKind::Status(status),
        })
    }

    pub fn diagnosis(
        request_id: &str,
        evidence_id: &str,
        proposal: DiagnosisProposal,
    ) -> Result<Self, FrameError> {
        validate_request_id(request_id)?;
        if !valid_evidence_id(evidence_id)
            || !proposal.validate()
            || proposal.evidence_ids() != [evidence_id]
        {
            return Err(FrameError::InvalidResponse);
        }
        Ok(Self {
            request_id: request_id.to_owned(),
            kind: ProviderResponseKind::Diagnosis(proposal),
        })
    }

    pub fn error(
        request_id: &str,
        operation: ProviderOperation,
        code: ProviderErrorCode,
    ) -> Result<Self, FrameError> {
        validate_request_id(request_id)?;
        Ok(Self {
            request_id: request_id.to_owned(),
            kind: ProviderResponseKind::Error { operation, code },
        })
    }

    pub fn request_id(&self) -> &str {
        &self.request_id
    }

    pub fn operation(&self) -> ProviderOperation {
        match &self.kind {
            ProviderResponseKind::Status(_) => ProviderOperation::Status,
            ProviderResponseKind::Diagnosis(_) => ProviderOperation::Diagnose,
            ProviderResponseKind::Error { operation, .. } => *operation,
        }
    }

    pub fn status_payload(&self) -> Option<&ProviderStatus> {
        match &self.kind {
            ProviderResponseKind::Status(status) => Some(status),
            ProviderResponseKind::Diagnosis(_) | ProviderResponseKind::Error { .. } => None,
        }
    }

    pub fn diagnosis_payload(&self) -> Option<&DiagnosisProposal> {
        match &self.kind {
            ProviderResponseKind::Diagnosis(proposal) => Some(proposal),
            ProviderResponseKind::Status(_) | ProviderResponseKind::Error { .. } => None,
        }
    }

    pub fn error_code(&self) -> Option<ProviderErrorCode> {
        match &self.kind {
            ProviderResponseKind::Error { code, .. } => Some(*code),
            ProviderResponseKind::Status(_) | ProviderResponseKind::Diagnosis(_) => None,
        }
    }
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct WireEnvelope {
    api_version: String,
    request_id: String,
    operation: String,
    payload: Box<RawValue>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct WireStatusRequest {}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct WireDiagnoseRequest {
    objective: String,
    evidence: Vec<WireEvidence>,
}

pub fn parse_request_frame(frame: &[u8]) -> Result<ProviderRequest, FrameError> {
    let body = frame_body(frame, MAX_REQUEST_FRAME_BYTES)?;
    let envelope: WireEnvelope = parse_exact(body).map_err(|_| FrameError::InvalidFrame)?;
    if envelope.api_version != API_VERSION {
        return Err(FrameError::InvalidRequest);
    }
    validate_request_id(&envelope.request_id)?;
    match ProviderOperation::parse(&envelope.operation)? {
        ProviderOperation::Status => {
            let _: WireStatusRequest = parse_exact(envelope.payload.get().as_bytes())
                .map_err(|_| FrameError::InvalidRequest)?;
            Ok(ProviderRequest::Status {
                request_id: envelope.request_id,
            })
        }
        ProviderOperation::Diagnose => {
            let payload: WireDiagnoseRequest = parse_exact(envelope.payload.get().as_bytes())
                .map_err(|_| FrameError::InvalidRequest)?;
            let context = project_diagnosis(&payload.objective, &payload.evidence)
                .map_err(|_| FrameError::InvalidRequest)?;
            Ok(ProviderRequest::Diagnose {
                request_id: envelope.request_id,
                context,
            })
        }
    }
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct WireResponseEnvelope {
    api_version: String,
    request_id: String,
    operation: String,
    ok: bool,
    #[serde(default)]
    payload: OptionalRawValue,
    #[serde(default)]
    error: OptionalRawValue,
}

#[derive(Default)]
enum OptionalRawValue {
    #[default]
    Missing,
    Present(Box<RawValue>),
}

impl OptionalRawValue {
    fn is_present(&self) -> bool {
        matches!(self, Self::Present(_))
    }

    fn into_value(self) -> Option<Box<RawValue>> {
        match self {
            Self::Missing => None,
            Self::Present(value) => Some(value),
        }
    }
}

impl<'de> Deserialize<'de> for OptionalRawValue {
    fn deserialize<Deserializer>(deserializer: Deserializer) -> Result<Self, Deserializer::Error>
    where
        Deserializer: serde::Deserializer<'de>,
    {
        Box::<RawValue>::deserialize(deserializer).map(Self::Present)
    }
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct WireStatusResponse {
    provider: String,
    profile: String,
    vault: VaultState,
    credential: CredentialState,
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct WireDiagnosisResponse {
    proposal: DiagnosisProposal,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct WireErrorResponse {
    code: ProviderErrorCode,
}

pub fn parse_response_frame(
    request: &ProviderRequest,
    frame: &[u8],
) -> Result<ProviderResponse, FrameError> {
    let body = frame_body(frame, MAX_RESPONSE_FRAME_BYTES)?;
    let envelope: WireResponseEnvelope = parse_exact(body).map_err(|_| FrameError::InvalidFrame)?;
    if envelope.api_version != API_VERSION {
        return Err(FrameError::InvalidResponse);
    }
    validate_request_id(&envelope.request_id).map_err(|_| FrameError::InvalidResponse)?;
    let operation =
        ProviderOperation::parse(&envelope.operation).map_err(|_| FrameError::InvalidResponse)?;
    if envelope.request_id != request.request_id() || operation != request.operation() {
        return Err(FrameError::InvalidResponse);
    }
    if envelope.ok {
        if envelope.error.is_present() {
            return Err(FrameError::InvalidResponse);
        }
        let payload = envelope
            .payload
            .into_value()
            .ok_or(FrameError::InvalidResponse)?;
        match operation {
            ProviderOperation::Status => {
                let wire: WireStatusResponse = parse_exact(payload.get().as_bytes())
                    .map_err(|_| FrameError::InvalidResponse)?;
                if wire.provider != PROVIDER_NAME || wire.profile != PROVIDER_PROFILE {
                    return Err(FrameError::InvalidResponse);
                }
                ProviderResponse::status(
                    &envelope.request_id,
                    ProviderStatus::new(wire.vault, wire.credential)?,
                )
            }
            ProviderOperation::Diagnose => {
                let wire: WireDiagnosisResponse = parse_exact(payload.get().as_bytes())
                    .map_err(|_| FrameError::InvalidResponse)?;
                let evidence_id = request
                    .context()
                    .and_then(|context| context.observations().first())
                    .map(|observation| observation.id())
                    .ok_or(FrameError::InvalidResponse)?;
                ProviderResponse::diagnosis(&envelope.request_id, evidence_id, wire.proposal)
            }
        }
    } else {
        if envelope.payload.is_present() {
            return Err(FrameError::InvalidResponse);
        }
        let error = envelope
            .error
            .into_value()
            .ok_or(FrameError::InvalidResponse)?;
        let wire: WireErrorResponse =
            parse_exact(error.get().as_bytes()).map_err(|_| FrameError::InvalidResponse)?;
        ProviderResponse::error(&envelope.request_id, request.operation(), wire.code)
    }
}

pub fn encode_response_frame(response: &ProviderResponse) -> Result<Vec<u8>, FrameError> {
    let value = match &response.kind {
        ProviderResponseKind::Status(status) => serde_json::json!({
            "apiVersion": API_VERSION,
            "requestId": response.request_id.as_str(),
            "operation": ProviderOperation::Status.as_str(),
            "ok": true,
            "payload": WireStatusResponse {
                provider: PROVIDER_NAME.to_owned(),
                profile: PROVIDER_PROFILE.to_owned(),
                vault: status.vault,
                credential: status.credential,
            },
        }),
        ProviderResponseKind::Diagnosis(proposal) => serde_json::json!({
            "apiVersion": API_VERSION,
            "requestId": response.request_id.as_str(),
            "operation": ProviderOperation::Diagnose.as_str(),
            "ok": true,
            "payload": WireDiagnosisResponse { proposal: proposal.clone() },
        }),
        ProviderResponseKind::Error { operation, code } => serde_json::json!({
            "apiVersion": API_VERSION,
            "requestId": response.request_id.as_str(),
            "operation": operation.as_str(),
            "ok": false,
            "error": WireErrorResponse { code: *code },
        }),
    };
    let mut encoded = serde_json::to_vec(&value).map_err(|_| FrameError::InvalidResponse)?;
    encoded.push(b'\n');
    if encoded.len() > MAX_RESPONSE_FRAME_BYTES {
        return Err(FrameError::ResponseTooLarge);
    }
    Ok(encoded)
}

fn frame_body(frame: &[u8], maximum: usize) -> Result<&[u8], FrameError> {
    if frame.len() < 3 || frame.len() > maximum || frame.last() != Some(&b'\n') {
        return Err(FrameError::InvalidSize);
    }
    let body = &frame[..frame.len() - 1];
    if body.first() != Some(&b'{')
        || body.last() != Some(&b'}')
        || body.iter().any(|byte| matches!(byte, b'\n' | b'\r'))
    {
        return Err(FrameError::InvalidFrame);
    }
    Ok(body)
}

fn parse_exact<T: DeserializeOwned>(input: &[u8]) -> Result<T, serde_json::Error> {
    let mut deserializer = serde_json::Deserializer::from_slice(input);
    let value = T::deserialize(&mut deserializer)?;
    deserializer.end()?;
    Ok(value)
}

fn validate_request_id(value: &str) -> Result<(), FrameError> {
    let Some(uuid) = value.strip_prefix("O-") else {
        return Err(FrameError::InvalidRequest);
    };
    if uuid.len() != 36
        || !uuid.bytes().enumerate().all(|(index, byte)| {
            if matches!(index, 8 | 13 | 18 | 23) {
                byte == b'-'
            } else {
                byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase()
            }
        })
    {
        return Err(FrameError::InvalidRequest);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde::Deserialize;
    use serde_json::Value;
    use std::{fs, path::PathBuf};

    const STATUS_REQUEST: &[u8] =
        include_bytes!("../../../packages/schemas/fixtures/rescue-openai/valid/status.request.raw");
    const STATUS_RESPONSE: &[u8] = include_bytes!(
        "../../../packages/schemas/fixtures/rescue-openai/valid/status.response.raw"
    );
    const REQUEST_SCHEMA: &str =
        include_str!("../../../packages/schemas/rescue-openai-request.schema.json");
    const RESPONSE_SCHEMA: &str =
        include_str!("../../../packages/schemas/rescue-openai-response.schema.json");

    #[derive(Deserialize)]
    #[serde(rename_all = "camelCase", deny_unknown_fields)]
    struct GoldenManifest {
        schema_version: u64,
        valid_cases: Vec<GoldenCase>,
        invalid_requests: Vec<String>,
    }

    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct GoldenCase {
        name: String,
        request: String,
        response: String,
    }

    fn fixture_root() -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../../packages/schemas/fixtures/rescue-openai")
    }

    fn golden_manifest() -> GoldenManifest {
        let bytes = fs::read(fixture_root().join("manifest.json"));
        assert!(bytes.is_ok());
        let manifest = bytes
            .as_deref()
            .ok()
            .and_then(|value| serde_json::from_slice(value).ok());
        assert!(manifest.is_some());
        manifest.unwrap_or_else(|| GoldenManifest {
            schema_version: 0,
            valid_cases: Vec::new(),
            invalid_requests: Vec::new(),
        })
    }

    fn read_fixture(relative: &str) -> Vec<u8> {
        let bytes = fs::read(fixture_root().join(relative));
        assert!(bytes.is_ok(), "fixture {relative}");
        bytes.unwrap_or_default()
    }

    fn frame_from_value(value: &Value) -> Vec<u8> {
        let encoded = serde_json::to_vec(value);
        assert!(encoded.is_ok());
        let mut frame = encoded.unwrap_or_default();
        frame.push(b'\n');
        frame
    }

    #[test]
    fn status_frames_are_exact_and_round_trip() {
        let request = parse_request_frame(STATUS_REQUEST).expect("valid status fixture");
        assert_eq!(request.operation(), ProviderOperation::Status);
        assert!(request.context().is_none());
        let response =
            parse_response_frame(&request, STATUS_RESPONSE).expect("valid status response");
        assert_eq!(response.operation(), ProviderOperation::Status);
        assert_eq!(
            response.status_payload().map(ProviderStatus::credential),
            Some(CredentialState::Configured)
        );
        let encoded = encode_response_frame(&response).expect("encode status response");
        assert_eq!(parse_response_frame(&request, &encoded), Ok(response));
    }

    #[test]
    fn shared_valid_fixtures_match_every_deterministic_rescue_branch() {
        let manifest = golden_manifest();
        assert_eq!(manifest.schema_version, 1);
        assert_eq!(manifest.valid_cases.len(), 9);
        for golden in manifest.valid_cases {
            let request_bytes = read_fixture(&golden.request);
            let response_bytes = read_fixture(&golden.response);
            let request = parse_request_frame(&request_bytes).expect("valid golden request");
            let response = parse_response_frame(&request, &response_bytes)
                .expect("valid correlated golden response");
            assert_eq!(
                request.request_id(),
                response.request_id(),
                "{}",
                golden.name
            );
            assert_eq!(request.operation(), response.operation(), "{}", golden.name);
            match request.context() {
                Some(context) => assert_eq!(
                    Some(context.deterministic_proposal()),
                    response.diagnosis_payload(),
                    "{}",
                    golden.name
                ),
                None => assert!(response.status_payload().is_some(), "{}", golden.name),
            }
        }
    }

    #[test]
    fn shared_invalid_fixtures_fail_closed() {
        let manifest = golden_manifest();
        assert!(manifest.invalid_requests.len() >= 6);
        for relative in manifest.invalid_requests {
            assert!(
                parse_request_frame(&read_fixture(&relative)).is_err(),
                "fixture {relative} must be rejected"
            );
        }
    }

    #[test]
    fn projection_has_only_redacted_objective_proposal_and_observation_metadata() {
        let raw = read_fixture("valid/linux-generic-canary.request.raw");
        let raw_text = String::from_utf8_lossy(&raw);
        assert!(raw_text.contains("RESCUE-CORPUS-CANARY-DO-NOT-PROJECT"));
        assert!(raw_text.contains("sk-rescue-objective-canary-12345678"));
        let request = parse_request_frame(&raw);
        assert!(request.is_ok());
        let context = request.as_ref().ok().and_then(ProviderRequest::context);
        assert!(context.is_some());
        let encoded = context.and_then(|value| serde_json::to_value(value).ok());
        assert!(encoded.is_some());
        let encoded = encoded.unwrap_or(Value::Null);
        let object = encoded.as_object();
        assert!(object.is_some());
        let keys = object
            .map(|value| value.keys().cloned().collect::<Vec<_>>())
            .unwrap_or_default();
        assert_eq!(
            keys,
            vec!["deterministicProposal", "objective", "observations"]
        );
        let text = encoded.to_string();
        assert!(!text.contains("RESCUE-CORPUS-CANARY-DO-NOT-PROJECT"));
        assert!(!text.contains("sk-rescue-objective-canary-12345678"));
        assert!(!text.contains("alice@example.com"));
        assert!(!text.contains("secrets.txt"));
        let observation_keys = encoded["observations"][0]
            .as_object()
            .map(|value| value.keys().cloned().collect::<Vec<_>>())
            .unwrap_or_default();
        assert_eq!(observation_keys, vec!["collector", "id", "trust"]);
        let proposal_keys = encoded["deterministicProposal"]
            .as_object()
            .map(|value| value.keys().cloned().collect::<Vec<_>>())
            .unwrap_or_default();
        assert_eq!(
            proposal_keys,
            vec![
                "confidence",
                "diagnosis",
                "evidenceIds",
                "requestedEvidence",
                "schemaVersion"
            ]
        );
    }

    #[test]
    fn objective_evidence_and_frame_byte_limits_are_enforced() {
        let bytes = read_fixture("valid/linux-malformed-fstab.request.raw");
        let parsed: Result<Value, _> = serde_json::from_slice(&bytes);
        assert!(parsed.is_ok());
        let mut value = parsed.unwrap_or(Value::Null);
        value["payload"]["objective"] = Value::String("x".repeat(crate::MAX_OBJECTIVE_BYTES));
        assert!(parse_request_frame(&frame_from_value(&value)).is_ok());
        value["payload"]["objective"] = Value::String("x".repeat(crate::MAX_OBJECTIVE_BYTES + 1));
        assert_eq!(
            parse_request_frame(&frame_from_value(&value)),
            Err(FrameError::InvalidRequest)
        );

        let parsed: Result<Value, _> = serde_json::from_slice(&bytes);
        assert!(parsed.is_ok());
        let mut value = parsed.unwrap_or(Value::Null);
        let content = value["payload"]["evidence"][0]["content"]
            .as_str()
            .unwrap_or("")
            .to_owned();
        assert!(content.len() < crate::MAX_EVIDENCE_CONTENT_BYTES);
        value["payload"]["evidence"][0]["content"] = Value::String(format!(
            "{content}{}",
            " ".repeat(crate::MAX_EVIDENCE_CONTENT_BYTES - content.len())
        ));
        let maximum_frame = frame_from_value(&value);
        assert!(maximum_frame.len() < MAX_REQUEST_FRAME_BYTES);
        assert!(parse_request_frame(&maximum_frame).is_ok());
        let oversized = value["payload"]["evidence"][0]["content"]
            .as_str()
            .map(|value| format!("{value} "))
            .unwrap_or_default();
        value["payload"]["evidence"][0]["content"] = Value::String(oversized);
        assert_eq!(
            parse_request_frame(&frame_from_value(&value)),
            Err(FrameError::InvalidRequest)
        );
        assert_eq!(
            parse_request_frame(&vec![b'x'; MAX_REQUEST_FRAME_BYTES + 1]),
            Err(FrameError::InvalidSize)
        );
    }

    #[test]
    fn exactly_one_evidence_and_the_derived_summary_are_required() {
        let bytes = read_fixture("valid/windows-generic.request.raw");
        let parsed: Result<Value, _> = serde_json::from_slice(&bytes);
        assert!(parsed.is_ok());
        let mut value = parsed.unwrap_or(Value::Null);
        let evidence = value["payload"]["evidence"][0].clone();
        value["payload"]["evidence"] = Value::Array(vec![evidence.clone(), evidence]);
        assert_eq!(
            parse_request_frame(&frame_from_value(&value)),
            Err(FrameError::InvalidRequest)
        );
        value["payload"]["evidence"] = Value::Array(Vec::new());
        assert_eq!(
            parse_request_frame(&frame_from_value(&value)),
            Err(FrameError::InvalidRequest)
        );
        value["payload"]["evidence"] = Value::Array(vec![
            serde_json::from_slice::<Value>(&bytes)
                .ok()
                .and_then(|original| original["payload"]["evidence"].as_array()?.first().cloned())
                .unwrap_or(Value::Null),
        ]);
        value["payload"]["evidence"][0]["summary"] =
            Value::String("caller supplied conclusion".to_owned());
        assert_eq!(
            parse_request_frame(&frame_from_value(&value)),
            Err(FrameError::InvalidRequest)
        );
    }

    #[test]
    fn closed_error_response_has_no_free_form_message() {
        let request = parse_request_frame(&read_fixture("valid/linux-malformed-fstab.request.raw"))
            .expect("valid diagnose request");
        let response = ProviderResponse::error(
            request.request_id(),
            request.operation(),
            ProviderErrorCode::InvalidRequest,
        )
        .expect("valid error response");
        let encoded = encode_response_frame(&response).expect("encode error response");
        assert!(!encoded.windows(7).any(|window| window == b"message"));
        assert_eq!(parse_response_frame(&request, &encoded), Ok(response));
    }

    #[test]
    fn diagnosis_encoder_requires_the_single_request_evidence_id() {
        let request = parse_request_frame(&read_fixture("valid/linux-malformed-fstab.request.raw"))
            .expect("valid diagnose request");
        let response = parse_response_frame(
            &request,
            read_fixture("valid/linux-malformed-fstab.response.raw").as_slice(),
        );
        assert!(response.is_ok());
        let proposal = response
            .as_ref()
            .ok()
            .and_then(ProviderResponse::diagnosis_payload)
            .cloned();
        assert!(proposal.is_some());
        let Some(proposal) = proposal else {
            return;
        };
        assert!(
            ProviderResponse::diagnosis(
                "O-11111111-1111-1111-1111-111111111111",
                "E-RESCUE-CORPUS",
                proposal.clone(),
            )
            .is_ok()
        );
        assert_eq!(
            ProviderResponse::diagnosis(
                "O-11111111-1111-1111-1111-111111111111",
                "E-FOREIGN",
                proposal,
            ),
            Err(FrameError::InvalidResponse)
        );
    }

    #[test]
    fn diagnosis_decoder_requires_the_correlated_request_and_evidence_id() {
        let request = parse_request_frame(&read_fixture("valid/linux-malformed-fstab.request.raw"))
            .expect("valid diagnose request");
        let response_bytes = read_fixture("valid/linux-malformed-fstab.response.raw");
        let parsed: Value =
            serde_json::from_slice(&response_bytes).expect("valid response fixture JSON");

        let mut foreign = parsed.clone();
        foreign["payload"]["proposal"]["evidenceIds"] = serde_json::json!(["E-FOREIGN"]);
        assert_eq!(
            parse_response_frame(&request, &frame_from_value(&foreign)),
            Err(FrameError::InvalidResponse)
        );

        let mut multiple = parsed.clone();
        multiple["payload"]["proposal"]["evidenceIds"] =
            serde_json::json!(["E-RESCUE-CORPUS", "E-FOREIGN"]);
        assert_eq!(
            parse_response_frame(&request, &frame_from_value(&multiple)),
            Err(FrameError::InvalidResponse)
        );

        let mut wrong_request = parsed.clone();
        wrong_request["requestId"] =
            Value::String("O-99999999-9999-9999-9999-999999999999".to_owned());
        assert_eq!(
            parse_response_frame(&request, &frame_from_value(&wrong_request)),
            Err(FrameError::InvalidResponse)
        );

        let status_request = parse_request_frame(STATUS_REQUEST).expect("valid status request");
        assert_eq!(
            parse_response_frame(&status_request, &response_bytes),
            Err(FrameError::InvalidResponse)
        );
    }

    #[test]
    fn one_frame_rule_rejects_missing_or_embedded_newlines() {
        let without_newline = &STATUS_REQUEST[..STATUS_REQUEST.len() - 1];
        assert_eq!(
            parse_request_frame(without_newline),
            Err(FrameError::InvalidSize)
        );
        let pretty = STATUS_REQUEST
            .iter()
            .copied()
            .flat_map(|byte| {
                if byte == b',' {
                    vec![byte, b'\n']
                } else {
                    vec![byte]
                }
            })
            .collect::<Vec<_>>();
        assert_eq!(parse_request_frame(&pretty), Err(FrameError::InvalidFrame));
    }

    #[test]
    fn response_parser_rejects_duplicate_trailing_unknown_and_oversized_data() {
        let status_request = parse_request_frame(STATUS_REQUEST).expect("valid status request");
        let status = String::from_utf8_lossy(STATUS_RESPONSE);
        let duplicate = status.replace("\"ok\":true", "\"ok\":true,\"ok\":true");
        assert_eq!(
            parse_response_frame(&status_request, duplicate.as_bytes()),
            Err(FrameError::InvalidFrame)
        );
        let trailing = status.replace("}\n", "}{}\n");
        assert_eq!(
            parse_response_frame(&status_request, trailing.as_bytes()),
            Err(FrameError::InvalidFrame)
        );
        let unknown = status.replace(
            "\"credential\":\"configured\"",
            "\"credential\":\"configured\",\"message\":\"upstream text\"",
        );
        assert_eq!(
            parse_response_frame(&status_request, unknown.as_bytes()),
            Err(FrameError::InvalidResponse)
        );
        let null_error = status.replace("\"ok\":true", "\"ok\":true,\"error\":null");
        assert_eq!(
            parse_response_frame(&status_request, null_error.as_bytes()),
            Err(FrameError::InvalidResponse)
        );
        let diagnose_request =
            parse_request_frame(&read_fixture("valid/linux-malformed-fstab.request.raw"))
                .expect("valid diagnose request");
        let error = encode_response_frame(
            &ProviderResponse::error(
                diagnose_request.request_id(),
                diagnose_request.operation(),
                ProviderErrorCode::InvalidRequest,
            )
            .expect("valid error response"),
        )
        .expect("encode error response");
        let error_with_null_payload = String::from_utf8_lossy(&error)
            .replace("\"ok\":false", "\"ok\":false,\"payload\":null");
        assert_eq!(
            parse_response_frame(&diagnose_request, error_with_null_payload.as_bytes()),
            Err(FrameError::InvalidResponse)
        );
        assert_eq!(
            parse_response_frame(&status_request, &vec![b'x'; MAX_RESPONSE_FRAME_BYTES + 1],),
            Err(FrameError::InvalidSize)
        );
    }

    #[test]
    fn schemas_publish_only_the_closed_operations_and_payload_fields() {
        let request: Result<Value, _> = serde_json::from_str(REQUEST_SCHEMA);
        let response: Result<Value, _> = serde_json::from_str(RESPONSE_SCHEMA);
        assert!(request.is_ok());
        assert!(response.is_ok());
        let request = request.unwrap_or(Value::Null);
        let response = response.unwrap_or(Value::Null);
        assert_eq!(
            request["$id"],
            "https://schemas.kernaid.dev/v1/rescue-openai-request.json"
        );
        assert_eq!(
            response["$id"],
            "https://schemas.kernaid.dev/v1/rescue-openai-response.json"
        );
        let request_text = request.to_string();
        for prohibited in [
            "\"url\"",
            "\"tools\"",
            "\"messages\"",
            "\"command\"",
            "\"path\"",
            "\"device\"",
            "\"raw\"",
            "\"generic\"",
            "\"args\"",
        ] {
            assert!(!request_text.contains(prohibited), "{prohibited}");
        }
        assert!(request_text.contains(ProviderOperation::Status.as_str()));
        assert!(request_text.contains(ProviderOperation::Diagnose.as_str()));
        assert_eq!(
            response["$defs"]["diagnosisProposal"]["properties"]["evidenceIds"]["maxItems"],
            1
        );
        assert!(!response.to_string().contains("\"model\""));
    }

    #[test]
    fn status_semantics_never_report_a_locked_credential() {
        assert_eq!(
            ProviderStatus::new(VaultState::Locked, CredentialState::Configured),
            Err(FrameError::InvalidResponse)
        );
        assert!(ProviderStatus::new(VaultState::Locked, CredentialState::Unavailable).is_ok());
    }

    #[test]
    fn evidence_id_grammar_matches_the_published_contract() {
        assert!(crate::rescue_corpus::valid_evidence_id("E-RESCUE-CORPUS"));
        assert!(!crate::rescue_corpus::valid_evidence_id("E-"));
        assert!(!crate::rescue_corpus::valid_evidence_id("E-rescue_corpus"));
    }
}
