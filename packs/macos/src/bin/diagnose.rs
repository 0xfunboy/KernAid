#![forbid(unsafe_code)]

use kernaid_macos_pack::{
    EvidenceInput, MAX_EVIDENCE_ID_BYTES, MacosDiagnosisProposal, MacosP0Inputs, diagnose_macos_p0,
    proposal_from_report,
};
use serde::Deserialize;
use std::{
    collections::{BTreeMap, BTreeSet},
    io::{self, Read, Write},
    process::ExitCode,
};

const MAX_REQUEST_BYTES: u64 = 9 * 1024 * 1024;
const REQUEST_SCHEMA_VERSION: &str = "1.0";
const REQUIRED_COLLECTORS: [&str; 8] = [
    "macos.storage.inventory",
    "macos.apfs.capacity",
    "macos.launchd.state",
    "macos.network.state",
    "macos.software-update.state",
    "macos.system-events.summary",
    "macos.startup.state",
    "macos.snapshots.inventory",
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
    fn code(self) -> u8 {
        match self {
            Self::Input => 2,
            Self::Invalid => 3,
            Self::Diagnostic => 4,
            Self::Output => 5,
        }
    }

    fn message(self) -> &'static str {
        match self {
            Self::Input => "could not read the bounded macOS diagnostic request",
            Self::Invalid => "macOS diagnostic request is incomplete or invalid",
            Self::Diagnostic => "macOS diagnostic evidence was rejected",
            Self::Output => "could not write the macOS diagnostic response",
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

fn valid_evidence_id(value: &str) -> bool {
    let bytes = value.as_bytes();
    bytes.starts_with(b"E-")
        && bytes.len() > 2
        && bytes.len() <= MAX_EVIDENCE_ID_BYTES
        && bytes[2..]
            .iter()
            .all(|byte| byte.is_ascii_alphanumeric() || *byte == b'-')
}

fn diagnose_request(request: DiagnosticRequest) -> Result<MacosDiagnosisProposal, RequestError> {
    if request.schema_version != REQUEST_SCHEMA_VERSION
        || request.evidence.len() != REQUIRED_COLLECTORS.len()
    {
        return Err(RequestError::Invalid);
    }

    let mut documents = BTreeMap::new();
    let mut evidence_ids = BTreeSet::new();
    for document in request.evidence {
        if !REQUIRED_COLLECTORS.contains(&document.collector.as_str())
            || !valid_evidence_id(&document.id)
            || !evidence_ids.insert(document.id.clone())
            || documents
                .insert(document.collector.clone(), document)
                .is_some()
        {
            return Err(RequestError::Invalid);
        }
    }
    if REQUIRED_COLLECTORS
        .iter()
        .any(|collector| !documents.contains_key(*collector))
    {
        return Err(RequestError::Invalid);
    }

    let input = |collector: &str| -> Result<EvidenceInput<'_>, RequestError> {
        let document = documents.get(collector).ok_or(RequestError::Invalid)?;
        Ok(EvidenceInput {
            id: &document.id,
            body: document.content.as_bytes(),
        })
    };
    let report = diagnose_macos_p0(MacosP0Inputs {
        storage: input("macos.storage.inventory")?,
        apfs: input("macos.apfs.capacity")?,
        launchd: input("macos.launchd.state")?,
        network: input("macos.network.state")?,
        updates: input("macos.software-update.state")?,
        events: input("macos.system-events.summary")?,
        startup: input("macos.startup.state")?,
        snapshots: input("macos.snapshots.inventory")?,
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

    const STORAGE_EVIDENCE_ID: &str = "E-REQUEST-17-STORAGE";
    const APFS_EVIDENCE_ID: &str = "E-REQUEST-17-APFS";
    const LAUNCHD_EVIDENCE_ID: &str = "E-REQUEST-17-LAUNCHD";
    const NETWORK_EVIDENCE_ID: &str = "E-REQUEST-17-NETWORK";
    const UPDATES_EVIDENCE_ID: &str = "E-REQUEST-17-UPDATES";
    const EVENTS_EVIDENCE_ID: &str = "E-REQUEST-17-EVENTS";
    const STARTUP_EVIDENCE_ID: &str = "E-REQUEST-17-STARTUP";
    const SNAPSHOTS_EVIDENCE_ID: &str = "E-REQUEST-17-SNAPSHOTS";

    fn document(id: &str, collector: &str, content: &[u8]) -> EvidenceDocument {
        EvidenceDocument {
            id: id.to_owned(),
            collector: collector.to_owned(),
            content: String::from_utf8(content.to_vec()).expect("UTF-8 fixture"),
        }
    }

    fn healthy_request() -> DiagnosticRequest {
        DiagnosticRequest {
            schema_version: REQUEST_SCHEMA_VERSION.to_owned(),
            evidence: vec![
                document(
                    STORAGE_EVIDENCE_ID,
                    "macos.storage.inventory",
                    include_bytes!("../../fixtures/diagnostics/healthy/storage.json"),
                ),
                document(
                    APFS_EVIDENCE_ID,
                    "macos.apfs.capacity",
                    include_bytes!("../../fixtures/diagnostics/healthy/apfs.json"),
                ),
                document(
                    LAUNCHD_EVIDENCE_ID,
                    "macos.launchd.state",
                    include_bytes!("../../fixtures/diagnostics/healthy/launchd.json"),
                ),
                document(
                    NETWORK_EVIDENCE_ID,
                    "macos.network.state",
                    include_bytes!("../../fixtures/diagnostics/healthy/network.json"),
                ),
                document(
                    UPDATES_EVIDENCE_ID,
                    "macos.software-update.state",
                    include_bytes!("../../fixtures/diagnostics/healthy/updates.json"),
                ),
                document(
                    EVENTS_EVIDENCE_ID,
                    "macos.system-events.summary",
                    include_bytes!("../../fixtures/diagnostics/healthy/events.json"),
                ),
                document(
                    STARTUP_EVIDENCE_ID,
                    "macos.startup.state",
                    include_bytes!("../../fixtures/diagnostics/healthy/startup.json"),
                ),
                document(
                    SNAPSHOTS_EVIDENCE_ID,
                    "macos.snapshots.inventory",
                    include_bytes!("../../fixtures/diagnostics/healthy/snapshots.json"),
                ),
            ],
        }
    }

    #[test]
    fn complete_request_returns_bounded_proposal() {
        let proposal = diagnose_request(healthy_request()).expect("complete request");
        assert_eq!(proposal.evidence_ids.len(), REQUIRED_COLLECTORS.len());
        assert_eq!(proposal.evidence_ids[0], STORAGE_EVIDENCE_ID);
        assert_eq!(proposal.evidence_ids[7], SNAPSHOTS_EVIDENCE_ID);
        assert!(proposal.diagnosis.contains("not a health certification"));
    }

    #[test]
    fn missing_duplicate_unknown_and_wrong_id_are_rejected() {
        let mut missing = healthy_request();
        let _ = missing.evidence.pop();
        assert!(matches!(
            diagnose_request(missing),
            Err(RequestError::Invalid)
        ));

        let mut duplicate = healthy_request();
        duplicate.evidence[7].collector = "macos.storage.inventory".to_owned();
        assert!(matches!(
            diagnose_request(duplicate),
            Err(RequestError::Invalid)
        ));

        let mut duplicate_id = healthy_request();
        duplicate_id.evidence[7].id = STORAGE_EVIDENCE_ID.to_owned();
        assert!(matches!(
            diagnose_request(duplicate_id),
            Err(RequestError::Invalid)
        ));

        let mut unknown = healthy_request();
        unknown.evidence[0].collector = "macos.command.arbitrary".to_owned();
        assert!(matches!(
            diagnose_request(unknown),
            Err(RequestError::Invalid)
        ));

        let mut invalid_id = healthy_request();
        invalid_id.evidence[0].id = "MACOS-CALLER-SELECTED".to_owned();
        assert!(matches!(
            diagnose_request(invalid_id),
            Err(RequestError::Invalid)
        ));

        let mut caller_selected = healthy_request();
        caller_selected.evidence[0].id = "E-SESSION-9999-COLLECTOR-01".to_owned();
        let proposal = diagnose_request(caller_selected).expect("dynamic caller ID is valid");
        assert_eq!(proposal.evidence_ids[0], "E-SESSION-9999-COLLECTOR-01");
    }

    #[test]
    fn unknown_request_fields_and_oversized_input_fail_closed() {
        assert!(matches!(
            read_request(br#"{"schemaVersion":"1.0","evidence":[],"extra":true}"#.as_slice()),
            Err(RequestError::Invalid)
        ));
        let oversized = vec![b'x'; MAX_REQUEST_BYTES as usize + 1];
        assert!(matches!(
            read_request(oversized.as_slice()),
            Err(RequestError::Input)
        ));
    }
}
