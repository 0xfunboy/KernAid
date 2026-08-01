#![forbid(unsafe_code)]

use kernaid_windows_pack::diagnostics::{
    EvidenceInput, MAX_INPUT_BYTES, WindowsDiagnosisProposal, WindowsP0Inputs, diagnose_windows_p0,
    proposal_from_report,
};
use serde::Deserialize;
use std::collections::BTreeMap;
use std::io::{self, Read, Write};
use std::process::ExitCode;

const MAX_REQUEST_BYTES: u64 = 24 * 1024 * 1024;
const REQUEST_SCHEMA_VERSION: &str = "1.0";
const REQUIRED_COLLECTORS: [&str; 11] = [
    "windows.event-log.window",
    "windows.reliability.records",
    "windows.component-store.check-health",
    "windows.sfc.verify-only",
    "windows.update.state",
    "windows.services.state",
    "windows.network.state",
    "windows.drivers.state",
    "windows.bitlocker.state",
    "windows.boot.state",
    "windows.volumes.state",
];

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct DiagnosticRequest {
    schema_version: String,
    evidence: Vec<EvidenceDocument>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct EvidenceDocument {
    id: String,
    collector: String,
    content: String,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum RequestError {
    Input,
    Invalid,
    Diagnostic,
    Output,
}

impl RequestError {
    const fn code(self) -> u8 {
        match self {
            Self::Input => 2,
            Self::Invalid => 3,
            Self::Diagnostic => 4,
            Self::Output => 5,
        }
    }

    const fn message(self) -> &'static str {
        match self {
            Self::Input => "could not read the bounded Windows diagnostic request",
            Self::Invalid => "Windows diagnostic request is incomplete or invalid",
            Self::Diagnostic => "Windows diagnostic evidence was rejected",
            Self::Output => "could not write the Windows diagnostic response",
        }
    }
}

fn read_request(reader: impl Read) -> Result<DiagnosticRequest, RequestError> {
    let mut bytes = Vec::new();
    reader
        .take(MAX_REQUEST_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| RequestError::Input)?;
    if bytes.is_empty() || bytes.len() as u64 > MAX_REQUEST_BYTES {
        return Err(RequestError::Input);
    }
    serde_json::from_slice(&bytes).map_err(|_| RequestError::Invalid)
}

fn diagnose_request(request: DiagnosticRequest) -> Result<WindowsDiagnosisProposal, RequestError> {
    if request.schema_version != REQUEST_SCHEMA_VERSION
        || request.evidence.len() != REQUIRED_COLLECTORS.len()
    {
        return Err(RequestError::Invalid);
    }
    let mut documents = BTreeMap::new();
    for document in request.evidence {
        if !REQUIRED_COLLECTORS.contains(&document.collector.as_str())
            || document.content.len() > MAX_INPUT_BYTES
            || documents
                .insert(document.collector.clone(), document)
                .is_some()
        {
            return Err(RequestError::Invalid);
        }
    }
    let input = |collector: &str| -> Result<EvidenceInput<'_>, RequestError> {
        let document = documents.get(collector).ok_or(RequestError::Invalid)?;
        Ok(EvidenceInput {
            id: &document.id,
            body: document.content.as_bytes(),
        })
    };
    let report = diagnose_windows_p0(WindowsP0Inputs {
        event_log_json: input("windows.event-log.window")?,
        reliability_json: input("windows.reliability.records")?,
        component_store_json: input("windows.component-store.check-health")?,
        sfc_json: input("windows.sfc.verify-only")?,
        update_json: input("windows.update.state")?,
        services_json: input("windows.services.state")?,
        network_json: input("windows.network.state")?,
        drivers_json: input("windows.drivers.state")?,
        bitlocker_json: input("windows.bitlocker.state")?,
        boot_json: input("windows.boot.state")?,
        volumes_json: input("windows.volumes.state")?,
    })
    .map_err(|_| RequestError::Diagnostic)?;
    Ok(proposal_from_report(&report))
}

fn run(reader: impl Read, mut writer: impl Write) -> Result<(), RequestError> {
    let proposal = diagnose_request(read_request(reader)?)?;
    serde_json::to_writer(&mut writer, &proposal).map_err(|_| RequestError::Output)?;
    writer.write_all(b"\n").map_err(|_| RequestError::Output)
}

fn main() -> ExitCode {
    match run(io::stdin().lock(), io::stdout().lock()) {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            let _ = writeln!(io::stderr().lock(), "error: {}", error.message());
            ExitCode::from(error.code())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_and_unknown_requests_are_rejected_without_echoing_input() {
        assert!(matches!(
            read_request([].as_slice()),
            Err(RequestError::Input)
        ));
        assert!(matches!(
            read_request(br#"{"schemaVersion":"1.0","evidence":[],"extra":true}"#.as_slice()),
            Err(RequestError::Invalid)
        ));
    }

    #[test]
    fn oversized_request_is_rejected_before_json_parsing() {
        let oversized = vec![b' '; MAX_REQUEST_BYTES as usize + 1];
        assert!(matches!(
            read_request(oversized.as_slice()),
            Err(RequestError::Input)
        ));
    }
}
