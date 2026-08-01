mod support;

use serde_json::Value;
use std::io::Write;
use std::process::{Command, Stdio};
use support::{healthy_inputs, incident_inputs, request_bytes};

fn run_cli(request: &[u8]) -> std::process::Output {
    let mut child = Command::new(env!("CARGO_BIN_EXE_kernaid-windows-diagnose"))
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn diagnostic CLI");
    child
        .stdin
        .take()
        .expect("diagnostic stdin")
        .write_all(request)
        .expect("write diagnostic request");
    child.wait_with_output().expect("wait for diagnostic CLI")
}

#[test]
fn cli_accepts_the_complete_fixed_contract() {
    let mut request: Value =
        serde_json::from_slice(&request_bytes(healthy_inputs())).expect("request JSON");
    for (index, document) in request["evidence"]
        .as_array_mut()
        .expect("evidence array")
        .iter_mut()
        .enumerate()
    {
        document["id"] = Value::String(format!("E-{}", index + 1));
    }
    let output = run_cli(&serde_json::to_vec(&request).expect("serialize dynamic-ID request"));
    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let response: Value = serde_json::from_slice(&output.stdout).expect("valid response JSON");
    assert_eq!(response["schemaVersion"], "1.0");
    assert_eq!(response["evidenceIds"].as_array().map(Vec::len), Some(11));
    assert_eq!(
        response["requestedEvidence"].as_array().map(Vec::len),
        Some(0)
    );
    assert!(
        !String::from_utf8_lossy(&output.stdout)
            .to_ascii_lowercase()
            .contains("healthy")
    );
}

#[test]
fn cli_emits_fixed_follow_up_collectors_for_incidents() {
    let output = run_cli(&request_bytes(incident_inputs()));
    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let response: Value = serde_json::from_slice(&output.stdout).expect("valid response JSON");
    let requested = response["requestedEvidence"]
        .as_array()
        .expect("requested-evidence array");
    assert!(requested.len() >= 11);
    assert!(requested.iter().all(Value::is_string));
    let diagnosis = response["diagnosis"].as_str().expect("diagnosis text");
    assert!(diagnosis.contains("windows.event-log.critical"));
    assert!(diagnosis.contains("windows.drivers.problem"));
    assert!(!diagnosis.contains("PCI\\VEN"));
}

#[test]
fn cli_diagnosis_exposes_fixed_rules_but_never_observed_instruction_text() {
    let mut inputs = healthy_inputs();
    inputs.reliability_json.body =
        include_bytes!("../fixtures/diagnostics/adversarial/reliability-prompt-injection.json");
    let output = run_cli(&request_bytes(inputs));
    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let diagnosis = String::from_utf8_lossy(&output.stdout);
    assert!(diagnosis.contains("windows.reliability.failures"));
    assert!(!diagnosis.contains("IGNORE ALL PREVIOUS"));
    assert!(!diagnosis.contains("privileged shell"));
}

#[test]
fn cli_rejects_missing_duplicate_and_unknown_collectors() {
    let mut missing: Value =
        serde_json::from_slice(&request_bytes(healthy_inputs())).expect("request JSON");
    missing["evidence"]
        .as_array_mut()
        .expect("evidence array")
        .pop();
    let output = run_cli(&serde_json::to_vec(&missing).expect("serialize missing request"));
    assert_eq!(output.status.code(), Some(3));

    let mut duplicate: Value =
        serde_json::from_slice(&request_bytes(healthy_inputs())).expect("request JSON");
    duplicate["evidence"][10]["collector"] = Value::String("windows.boot.state".to_owned());
    let output = run_cli(&serde_json::to_vec(&duplicate).expect("serialize duplicate request"));
    assert_eq!(output.status.code(), Some(3));

    let mut unknown: Value =
        serde_json::from_slice(&request_bytes(healthy_inputs())).expect("request JSON");
    unknown["evidence"][0]["collector"] = Value::String("windows.shell.arbitrary".to_owned());
    let output = run_cli(&serde_json::to_vec(&unknown).expect("serialize unknown request"));
    assert_eq!(output.status.code(), Some(3));
}

#[test]
fn cli_rejects_invalid_evidence_id_without_leaking_observed_text() {
    let mut request: Value =
        serde_json::from_slice(&request_bytes(healthy_inputs())).expect("request JSON");
    request["evidence"][0]["id"] = Value::String("WRONG-ID".to_owned());
    request["evidence"][0]["content"] = Value::String("TOP-SECRET-OBSERVATION".to_owned());
    let output = run_cli(&serde_json::to_vec(&request).expect("serialize invalid request"));
    assert_eq!(output.status.code(), Some(4));
    assert!(!String::from_utf8_lossy(&output.stderr).contains("TOP-SECRET"));
    assert!(output.stdout.is_empty());
}
