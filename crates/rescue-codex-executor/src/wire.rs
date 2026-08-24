use kernaid_rescue_openai_provider::{
    DiagnosisProposal, MAX_REQUEST_FRAME_BYTES as MAX_DIAGNOSIS_INPUT_BYTES,
    ProjectedProviderContext, ProviderRequest, parse_request_frame,
};
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use std::fmt;

pub(crate) const API_VERSION: &str = "kernaid.dev/rescue-codex-exec/v1alpha1";
pub(crate) const OPERATION: &str = "provider.codex.diagnose";
pub(crate) const INPUT_DESCRIPTOR_KIND: &str = "diagnosis-request-json-pipe";
pub(crate) const MAX_CONTROL_FRAME_BYTES: usize = 4096;
pub(crate) const MAX_RESPONSE_FRAME_BYTES: usize = 64 * 1024;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum BridgeCode {
    Busy,
    CredentialUnavailable,
    ExecutionUnavailable,
    InvalidRequest,
    InvalidResponse,
    RequestTooLarge,
    ResponseTooLarge,
    Timeout,
    Transport,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum WireError {
    InvalidSize,
    InvalidFrame,
    InvalidRequest,
    ResponseTooLarge,
}

impl fmt::Display for WireError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::InvalidSize => "Codex bridge frame size is invalid",
            Self::InvalidFrame => "Codex bridge frame is invalid",
            Self::InvalidRequest => "Codex bridge request is invalid",
            Self::ResponseTooLarge => "Codex bridge response is too large",
        })
    }
}

impl std::error::Error for WireError {}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct ControlRequest {
    request_id: String,
    input_size: usize,
}

impl ControlRequest {
    pub(crate) fn request_id(&self) -> &str {
        &self.request_id
    }

    pub(crate) const fn input_size(&self) -> usize {
        self.input_size
    }
}

#[derive(Clone, Debug, PartialEq)]
pub(crate) struct DiagnosisRequest {
    request_id: String,
    context: ProjectedProviderContext,
}

impl DiagnosisRequest {
    pub(crate) fn request_id(&self) -> &str {
        &self.request_id
    }

    pub(crate) const fn context(&self) -> &ProjectedProviderContext {
        &self.context
    }

    pub(crate) fn evidence_id(&self) -> Result<&str, WireError> {
        let [observation] = self.context.observations() else {
            return Err(WireError::InvalidRequest);
        };
        Ok(observation.id())
    }
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ControlEnvelope {
    api_version: String,
    request_id: String,
    operation: String,
    payload: ControlPayload,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ControlPayload {
    input: InputDeclaration,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct InputDeclaration {
    kind: String,
    size: u64,
}

pub(crate) fn parse_control_frame(frame: &[u8]) -> Result<ControlRequest, WireError> {
    let body = frame_body(frame, MAX_CONTROL_FRAME_BYTES)?;
    let envelope: ControlEnvelope = parse_exact(body).map_err(|_| WireError::InvalidFrame)?;
    validate_request_id(&envelope.request_id)?;
    let input_size =
        usize::try_from(envelope.payload.input.size).map_err(|_| WireError::InvalidRequest)?;
    if envelope.api_version != API_VERSION
        || envelope.operation != OPERATION
        || envelope.payload.input.kind != INPUT_DESCRIPTOR_KIND
        || !(3..=MAX_DIAGNOSIS_INPUT_BYTES).contains(&input_size)
    {
        return Err(WireError::InvalidRequest);
    }
    Ok(ControlRequest {
        request_id: envelope.request_id,
        input_size,
    })
}

pub(crate) fn parse_diagnosis_input(
    control: &ControlRequest,
    frame: &[u8],
) -> Result<DiagnosisRequest, WireError> {
    if frame.len() != control.input_size {
        return Err(WireError::InvalidSize);
    }
    let parsed = parse_request_frame(frame).map_err(|_| WireError::InvalidRequest)?;
    let ProviderRequest::Diagnose {
        request_id,
        context,
    } = parsed
    else {
        return Err(WireError::InvalidRequest);
    };
    if request_id != control.request_id {
        return Err(WireError::InvalidRequest);
    }
    let request = DiagnosisRequest {
        request_id,
        context,
    };
    request.evidence_id()?;
    Ok(request)
}

pub(crate) fn encode_success(
    request: &DiagnosisRequest,
    proposal: &DiagnosisProposal,
) -> Result<Vec<u8>, WireError> {
    encode_value(serde_json::json!({
        "apiVersion": API_VERSION,
        "requestId": request.request_id(),
        "operation": OPERATION,
        "ok": true,
        "payload": { "proposal": proposal },
    }))
}

pub(crate) fn encode_error(
    request: &ControlRequest,
    code: BridgeCode,
) -> Result<Vec<u8>, WireError> {
    encode_value(serde_json::json!({
        "apiVersion": API_VERSION,
        "requestId": request.request_id(),
        "operation": OPERATION,
        "ok": false,
        "error": { "code": code },
    }))
}

fn encode_value(value: serde_json::Value) -> Result<Vec<u8>, WireError> {
    let mut encoded = serde_json::to_vec(&value).map_err(|_| WireError::InvalidFrame)?;
    encoded.push(b'\n');
    if encoded.len() > MAX_RESPONSE_FRAME_BYTES {
        return Err(WireError::ResponseTooLarge);
    }
    Ok(encoded)
}

fn frame_body(frame: &[u8], maximum: usize) -> Result<&[u8], WireError> {
    if frame.len() < 3 || frame.len() > maximum || frame.last() != Some(&b'\n') {
        return Err(WireError::InvalidSize);
    }
    let body = &frame[..frame.len() - 1];
    if body.first() != Some(&b'{')
        || body.last() != Some(&b'}')
        || body.iter().any(|byte| matches!(byte, b'\n' | b'\r'))
    {
        return Err(WireError::InvalidFrame);
    }
    Ok(body)
}

pub(crate) fn parse_exact<T: DeserializeOwned>(input: &[u8]) -> Result<T, serde_json::Error> {
    let mut deserializer = serde_json::Deserializer::from_slice(input);
    let value = T::deserialize(&mut deserializer)?;
    deserializer.end()?;
    Ok(value)
}

fn validate_request_id(value: &str) -> Result<(), WireError> {
    let Some(uuid) = value.strip_prefix("O-") else {
        return Err(WireError::InvalidRequest);
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
        return Err(WireError::InvalidRequest);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    const REQUEST_ID: &str = "O-33333333-3333-3333-3333-333333333333";
    const DIAGNOSIS: &[u8] = include_bytes!(
        "../../../packages/schemas/fixtures/rescue-openai/valid/linux-generic-canary.request.raw"
    );

    fn control(size: usize) -> Vec<u8> {
        let mut value = serde_json::to_vec(&serde_json::json!({
            "apiVersion": API_VERSION,
            "requestId": REQUEST_ID,
            "operation": OPERATION,
            "payload": {
                "input": {
                    "kind": INPUT_DESCRIPTOR_KIND,
                    "size": size
                }
            }
        }))
        .expect("control JSON");
        value.push(b'\n');
        value
    }

    #[test]
    fn control_and_pipe_payload_are_correlated() {
        let control = parse_control_frame(&control(DIAGNOSIS.len())).expect("control");
        let request = parse_diagnosis_input(&control, DIAGNOSIS).expect("diagnosis");
        assert_eq!(request.request_id(), REQUEST_ID);
        assert_eq!(request.evidence_id(), Ok("E-RESCUE-CORPUS"));
        assert!(!request.context().objective().contains("sk-rescue"));
        assert!(!request.context().objective().contains("alice@example.com"));
    }

    #[test]
    fn control_rejects_duplicates_unknown_fields_and_wrong_declaration() {
        let duplicate = format!(
            "{{\"apiVersion\":\"{API_VERSION}\",\"apiVersion\":\"{API_VERSION}\",\"requestId\":\"{REQUEST_ID}\",\"operation\":\"{OPERATION}\",\"payload\":{{\"input\":{{\"kind\":\"{INPUT_DESCRIPTOR_KIND}\",\"size\":3}}}}}}\n"
        );
        assert!(parse_control_frame(duplicate.as_bytes()).is_err());

        let unknown = String::from_utf8(control(3))
            .expect("UTF-8")
            .replace("\"operation\"", "\"unknown\":true,\"operation\"");
        assert!(parse_control_frame(unknown.as_bytes()).is_err());

        let wrong = String::from_utf8(control(3))
            .expect("UTF-8")
            .replace(INPUT_DESCRIPTOR_KIND, "path");
        assert!(parse_control_frame(wrong.as_bytes()).is_err());
    }

    #[test]
    fn input_requires_exact_size_id_and_diagnose_operation() {
        let control = parse_control_frame(&control(DIAGNOSIS.len())).expect("control");
        assert!(parse_diagnosis_input(&control, &DIAGNOSIS[..DIAGNOSIS.len() - 1]).is_err());

        let mismatch = String::from_utf8(DIAGNOSIS.to_vec())
            .expect("fixture UTF-8")
            .replace(REQUEST_ID, "O-aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee");
        assert!(parse_diagnosis_input(&control, mismatch.as_bytes()).is_err());
    }
}
