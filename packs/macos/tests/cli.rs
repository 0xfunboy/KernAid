#![forbid(unsafe_code)]

use serde_json::{Value, json};
use std::{
    io::Write,
    process::{Command, Stdio},
};

fn complete_request() -> Value {
    let fixture = |id: &str, collector: &str, content: &str| json!({"id": id, "collector": collector, "content": content});
    json!({
        "schemaVersion": "1.0",
        "evidence": [
            fixture("E-CLI-RUN-884-STORAGE", "macos.storage.inventory", include_str!("../fixtures/diagnostics/healthy/storage.json")),
            fixture("E-CLI-RUN-884-APFS", "macos.apfs.capacity", include_str!("../fixtures/diagnostics/healthy/apfs.json")),
            fixture("E-CLI-RUN-884-LAUNCHD", "macos.launchd.state", include_str!("../fixtures/diagnostics/healthy/launchd.json")),
            fixture("E-CLI-RUN-884-NETWORK", "macos.network.state", include_str!("../fixtures/diagnostics/healthy/network.json")),
            fixture("E-CLI-RUN-884-UPDATES", "macos.software-update.state", include_str!("../fixtures/diagnostics/healthy/updates.json")),
            fixture("E-CLI-RUN-884-EVENTS", "macos.system-events.summary", include_str!("../fixtures/diagnostics/healthy/events.json")),
            fixture("E-CLI-RUN-884-STARTUP", "macos.startup.state", include_str!("../fixtures/diagnostics/healthy/startup.json")),
            fixture("E-CLI-RUN-884-SNAPSHOTS", "macos.snapshots.inventory", include_str!("../fixtures/diagnostics/healthy/snapshots.json"))
        ]
    })
}

fn run_cli(request: &Value) -> std::process::Output {
    let mut child = Command::new(env!("CARGO_BIN_EXE_kernaid-macos-diagnose"))
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn diagnostic CLI");
    let mut stdin = child.stdin.take().expect("child stdin");
    serde_json::to_writer(&mut stdin, request).expect("write request");
    stdin.flush().expect("flush request");
    drop(stdin);
    child.wait_with_output().expect("wait for diagnostic CLI")
}

#[test]
fn cli_accepts_exact_complete_contract() {
    let output = run_cli(&complete_request());
    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let response: Value = serde_json::from_slice(&output.stdout).expect("JSON response");
    assert_eq!(response["schemaVersion"], "1.0");
    assert_eq!(response["evidenceIds"].as_array().map(Vec::len), Some(8));
    assert_eq!(response["evidenceIds"][0], "E-CLI-RUN-884-STORAGE");
    assert_eq!(response["evidenceIds"][7], "E-CLI-RUN-884-SNAPSHOTS");
    assert!(
        response["diagnosis"]
            .as_str()
            .is_some_and(|text| text.contains("not a health certification"))
    );
}

#[test]
fn cli_rejects_partial_projection_without_output() {
    let mut request = complete_request();
    request["evidence"][3]["content"] = Value::String(
        include_str!("../fixtures/diagnostics/adversarial/network-partial.json").to_owned(),
    );
    let output = run_cli(&request);
    assert_eq!(output.status.code(), Some(4));
    assert!(output.stdout.is_empty());
    assert_eq!(
        String::from_utf8_lossy(&output.stderr),
        "error: macOS diagnostic evidence was rejected\n"
    );
}
