#![forbid(unsafe_code)]

use kernaid_linux_pack::diagnostics::{
    EvidenceInput, LinuxDiagnosisProposal, LinuxP0Inputs, MAX_INPUT_BYTES, diagnose_linux_p0,
    proposal_from_report,
};
use serde::Deserialize;
use std::collections::BTreeMap;
use std::io::{self, Read, Write};
use std::process::ExitCode;

const MAX_REQUEST_BYTES: u64 = 4 * 1024 * 1024;
const REQUEST_SCHEMA_VERSION: &str = "1.0";
const REQUIRED_COLLECTORS: [&str; 9] = [
    "linux.block.inventory",
    "linux.mounts.read-only",
    "linux.systemd.failed",
    "linux.systemd.state",
    "linux.fstab",
    "linux.df",
    "linux.network.links",
    "linux.network.routes",
    "linux.dpkg.audit",
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
            Self::Input => "could not read the bounded diagnostic request",
            Self::Invalid => "diagnostic request is incomplete or invalid",
            Self::Diagnostic => "diagnostic evidence was rejected",
            Self::Output => "could not write the diagnostic response",
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

fn diagnose_request(request: DiagnosticRequest) -> Result<LinuxDiagnosisProposal, RequestError> {
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
    let report = diagnose_linux_p0(LinuxP0Inputs {
        lsblk_json: input("linux.block.inventory")?,
        read_only_mounts_json: input("linux.mounts.read-only")?,
        systemctl_failed: input("linux.systemd.failed")?,
        systemctl_unit_state: input("linux.systemd.state")?,
        fstab: input("linux.fstab")?,
        df: input("linux.df")?,
        ip_link_json: input("linux.network.links")?,
        ip_route_json: input("linux.network.routes")?,
        dpkg_audit: input("linux.dpkg.audit")?,
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

    fn healthy_request() -> DiagnosticRequest {
        let fixture = |id: &str, collector: &str, body: &[u8]| EvidenceDocument {
            id: id.to_owned(),
            collector: collector.to_owned(),
            content: String::from_utf8(body.to_vec()).expect("UTF-8 fixture"),
        };
        DiagnosticRequest {
            schema_version: "1.0".to_owned(),
            evidence: vec![
                fixture(
                    "E-LSBLK",
                    "linux.block.inventory",
                    include_bytes!("../../fixtures/diagnostics/healthy/lsblk.json"),
                ),
                fixture(
                    "E-MOUNTS-READ-ONLY",
                    "linux.mounts.read-only",
                    include_bytes!("../../fixtures/diagnostics/healthy/findmnt-read-only.json"),
                ),
                fixture(
                    "E-FAILED",
                    "linux.systemd.failed",
                    include_bytes!("../../fixtures/diagnostics/healthy/systemctl-failed.txt"),
                ),
                fixture(
                    "E-STATE",
                    "linux.systemd.state",
                    include_bytes!("../../fixtures/diagnostics/healthy/systemctl-unit-state.txt"),
                ),
                fixture(
                    "E-FSTAB",
                    "linux.fstab",
                    include_bytes!("../../fixtures/diagnostics/healthy/fstab"),
                ),
                fixture(
                    "E-DF",
                    "linux.df",
                    include_bytes!("../../fixtures/diagnostics/healthy/df.txt"),
                ),
                fixture(
                    "E-LINK",
                    "linux.network.links",
                    include_bytes!("../../fixtures/diagnostics/healthy/ip-link.json"),
                ),
                fixture(
                    "E-ROUTE",
                    "linux.network.routes",
                    include_bytes!("../../fixtures/diagnostics/healthy/ip-route.json"),
                ),
                fixture(
                    "E-DPKG",
                    "linux.dpkg.audit",
                    include_bytes!("../../fixtures/diagnostics/healthy/dpkg-audit.txt"),
                ),
            ],
        }
    }

    #[test]
    fn healthy_request_returns_a_strict_bounded_proposal() {
        let proposal = diagnose_request(healthy_request()).expect("diagnose healthy request");
        assert_eq!(proposal.schema_version, "1.0");
        assert_eq!(proposal.evidence_ids.len(), 9);
        assert!(proposal.requested_evidence.is_empty());
    }

    #[test]
    fn duplicate_or_unknown_collectors_are_rejected() {
        let mut duplicate = healthy_request();
        duplicate.evidence[7].collector = "linux.df".to_owned();
        assert!(matches!(
            diagnose_request(duplicate),
            Err(RequestError::Invalid)
        ));

        let mut unknown = healthy_request();
        unknown.evidence[0].collector = "linux.command.arbitrary".to_owned();
        assert!(matches!(
            diagnose_request(unknown),
            Err(RequestError::Invalid)
        ));
    }

    #[test]
    fn unknown_json_fields_and_oversized_input_fail_closed() {
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
