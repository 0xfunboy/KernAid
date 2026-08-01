mod support;

use kernaid_windows_pack::diagnostics::{
    DiagnosticErrorKind, EvidenceInput, EvidenceSource, MAX_INPUT_BYTES, Severity,
    diagnose_windows_p0, parse_bitlocker, parse_component_store, parse_drivers, parse_event_log,
    parse_network, parse_reliability, parse_services, parse_sfc, proposal_from_report,
};
use support::{
    BITLOCKER_EVIDENCE_ID, COMPONENT_STORE_EVIDENCE_ID, DRIVERS_EVIDENCE_ID, EVENT_LOG_EVIDENCE_ID,
    FIXTURE_EVIDENCE_IDS, NETWORK_EVIDENCE_ID, RELIABILITY_EVIDENCE_ID, SERVICES_EVIDENCE_ID,
    SFC_EVIDENCE_ID, healthy_inputs, incident_inputs,
};

#[test]
fn complete_baseline_matches_no_incident_without_claiming_system_health() {
    let report = diagnose_windows_p0(healthy_inputs()).expect("complete baseline must parse");
    assert_eq!(report.corpus_version, "windows-p0.1");
    assert_eq!(report.evaluation, "complete");
    assert!(report.findings.is_empty());
    assert_eq!(report.evidence_ids, FIXTURE_EVIDENCE_IDS.map(str::to_owned));

    let proposal = proposal_from_report(&report);
    assert!(proposal.requested_evidence.is_empty());
    assert!(!proposal.diagnosis.to_ascii_lowercase().contains("healthy"));
    assert!(
        proposal
            .diagnosis
            .contains("matched no deterministic incident")
    );
    assert_eq!(proposal.confidence, 0.60);
}

#[test]
fn incident_corpus_emits_only_fixed_canonical_findings() {
    let report = diagnose_windows_p0(incident_inputs()).expect("incident corpus must parse");
    let ids = report
        .findings
        .iter()
        .map(|finding| finding.rule_id.as_str())
        .collect::<Vec<_>>();
    assert_eq!(
        ids,
        vec![
            "windows.bitlocker.os-protection-off",
            "windows.boot.configuration-incomplete",
            "windows.component-store.repairable",
            "windows.drivers.problem",
            "windows.drivers.problem-with-recent-change",
            "windows.drivers.unsigned",
            "windows.event-log.critical",
            "windows.network.default-route-missing",
            "windows.network.dns-missing",
            "windows.reliability.hardware-failure",
            "windows.services.automatic-not-running",
            "windows.services.nonzero-exit",
            "windows.sfc.integrity-violations",
            "windows.update.failed",
            "windows.update.reboot-pending",
            "windows.volumes.system-low-space",
        ]
    );
    assert!(
        report
            .findings
            .iter()
            .all(|finding| finding.schema_version == "1.0"
                && finding.rule_version == 1
                && !finding.evidence_ids.is_empty()
                && finding.severity >= Severity::Low)
    );

    let first = serde_json::to_vec(&report).expect("serialize deterministic report");
    let second = serde_json::to_vec(
        &diagnose_windows_p0(incident_inputs()).expect("repeat incident evaluation"),
    )
    .expect("serialize repeated report");
    assert_eq!(first, second);
}

#[test]
fn evidence_identifiers_are_syntax_checked_unique_and_source_bound() {
    let mut inputs = healthy_inputs();
    inputs.event_log_json.id = "WIN-EVENTS-OTHER";
    let error = diagnose_windows_p0(inputs).expect_err("invalid ID must fail closed");
    assert_eq!(error.source, EvidenceSource::EventLog);
    assert_eq!(error.kind, DiagnosticErrorKind::InvalidEvidenceId);

    let mut duplicate = healthy_inputs();
    duplicate.reliability_json.id = EVENT_LOG_EVIDENCE_ID;
    let error = diagnose_windows_p0(duplicate).expect_err("duplicate ID must fail closed");
    assert_eq!(error.kind, DiagnosticErrorKind::DuplicateEvidenceId);

    let mut dynamic = incident_inputs();
    dynamic.event_log_json.id = "E-1";
    dynamic.reliability_json.id = "E-2";
    let report = diagnose_windows_p0(dynamic).expect("dynamic IDs must remain bound");
    let event_finding = report
        .findings
        .iter()
        .find(|finding| finding.rule_id == "windows.event-log.critical")
        .expect("event finding");
    assert_eq!(event_finding.evidence_ids, ["E-1"]);
    let reliability_finding = report
        .findings
        .iter()
        .find(|finding| finding.rule_id == "windows.reliability.hardware-failure")
        .expect("reliability finding");
    assert_eq!(reliability_finding.evidence_ids, ["E-2"]);
}

#[test]
fn partial_snapshots_and_unknown_fields_fail_closed() {
    let incomplete = br#"{
      "lookbackHours":168,
      "queryComplete":false,
      "records":[]
    }"#;
    let error = parse_event_log(EvidenceInput {
        id: EVENT_LOG_EVIDENCE_ID,
        body: incomplete,
    })
    .expect_err("partial event query must fail");
    assert_eq!(error.kind, DiagnosticErrorKind::InconsistentSnapshot);

    let unknown = br#"{
      "snapshotComplete":true,
      "services":[{"name":"Dhcp","startMode":"automatic","state":"running","win32ExitCode":0,"displayName":"untrusted"}]
    }"#;
    let error = parse_services(EvidenceInput {
        id: SERVICES_EVIDENCE_ID,
        body: unknown,
    })
    .expect_err("unknown field must fail");
    assert_eq!(error.kind, DiagnosticErrorKind::MalformedInput);
}

#[test]
fn bounded_input_control_characters_and_secret_fields_are_rejected() {
    let oversized = vec![b' '; MAX_INPUT_BYTES + 1];
    let error = parse_event_log(EvidenceInput {
        id: EVENT_LOG_EVIDENCE_ID,
        body: &oversized,
    })
    .expect_err("oversized evidence must fail");
    assert_eq!(error.kind, DiagnosticErrorKind::InputTooLarge);

    let error = parse_event_log(EvidenceInput {
        id: EVENT_LOG_EVIDENCE_ID,
        body: include_bytes!("../fixtures/diagnostics/adversarial/event-log-control.json"),
    })
    .expect_err("control character must fail");
    assert_eq!(error.kind, DiagnosticErrorKind::UnsafeControlCharacter);

    let error = parse_bitlocker(EvidenceInput {
        id: BITLOCKER_EVIDENCE_ID,
        body: include_bytes!("../fixtures/diagnostics/adversarial/bitlocker-secret-field.json"),
    })
    .expect_err("recovery material is outside the evidence schema");
    assert_eq!(error.kind, DiagnosticErrorKind::MalformedInput);
}

#[test]
fn observed_prompt_text_never_enters_a_finding_or_proposal() {
    let mut inputs = healthy_inputs();
    inputs.reliability_json.body =
        include_bytes!("../fixtures/diagnostics/adversarial/reliability-prompt-injection.json");
    let report = diagnose_windows_p0(inputs).expect("untrusted text remains valid evidence data");
    let serialized = serde_json::to_string(&proposal_from_report(&report))
        .expect("serialize provider-neutral proposal");
    assert!(!serialized.contains("IGNORE ALL PREVIOUS"));
    assert!(!serialized.contains("privileged shell"));
    assert_eq!(report.findings[0].rule_id, "windows.reliability.failures");
}

#[test]
fn malformed_network_and_duplicate_records_are_rejected() {
    let malformed_network = br#"{
      "snapshotComplete":true,
      "adapters":[{"interfaceIndex":7,"status":"Up","hardwareInterface":true}],
      "routes":[{"destinationPrefix":"0.0.0.0/99","interfaceIndex":7,"nextHop":"192.0.2.1","routeMetric":1}],
      "dnsServers":[]
    }"#;
    let error = parse_network(EvidenceInput {
        id: NETWORK_EVIDENCE_ID,
        body: malformed_network,
    })
    .expect_err("invalid prefix must fail");
    assert_eq!(error.kind, DiagnosticErrorKind::ValueOutOfRange);

    let duplicate_services = br#"{
      "snapshotComplete":true,
      "services":[
        {"name":"Dhcp","startMode":"automatic","state":"running","win32ExitCode":0},
        {"name":"DHCP","startMode":"automatic","state":"running","win32ExitCode":0}
      ]
    }"#;
    let error = parse_services(EvidenceInput {
        id: SERVICES_EVIDENCE_ID,
        body: duplicate_services,
    })
    .expect_err("case-insensitive duplicate must fail");
    assert_eq!(error.kind, DiagnosticErrorKind::InconsistentSnapshot);
}

#[test]
fn malformed_timestamp_is_rejected_before_diagnosis() {
    let malformed = br#"{
      "lookbackHours":168,
      "queryState":"complete",
      "records":[{
        "logFile":"System",
        "recordNumber":1,
        "sourceName":"Windows",
        "productName":"Failure",
        "recordType":"WindowsFailure",
        "timestampUtc":"2026-99-31T04:12:12Z"
      }]
    }"#;
    let error = parse_reliability(EvidenceInput {
        id: RELIABILITY_EVIDENCE_ID,
        body: malformed,
    })
    .expect_err("out-of-range timestamp must fail");
    assert_eq!(error.kind, DiagnosticErrorKind::ValueOutOfRange);
}

#[test]
fn mutation_capable_mode_labels_are_not_part_of_phase_zero() {
    let component = br#"{
      "checkMode":"restore-health",
      "state":"healthy",
      "exitCode":0,
      "rebootRequired":false
    }"#;
    let error = parse_component_store(EvidenceInput {
        id: COMPONENT_STORE_EVIDENCE_ID,
        body: component,
    })
    .expect_err("restore mode must not enter the read-only corpus");
    assert_eq!(error.kind, DiagnosticErrorKind::InconsistentSnapshot);

    let sfc = br#"{"mode":"scan-and-repair","state":"clean","exitCode":0}"#;
    let error = parse_sfc(EvidenceInput {
        id: SFC_EVIDENCE_ID,
        body: sfc,
    })
    .expect_err("repair mode must not enter the read-only corpus");
    assert_eq!(error.kind, DiagnosticErrorKind::InconsistentSnapshot);
}

#[test]
fn typed_unavailable_states_and_pending_restart_are_explicit_findings() {
    let mut inputs = healthy_inputs();
    inputs.component_store_json.body = br#"{
      "checkMode":"check-health-read-only",
      "state":"healthy",
      "exitCode":0,
      "rebootRequired":true
    }"#;
    inputs.update_json.body = br#"{
      "historyLookbackHours":168,
      "scanState":"unavailable",
      "pendingReboot":false,
      "cbsRebootPending":false,
      "windowsUpdateRebootPending":false,
      "pendingFileRenameOperations":false,
      "lastSuccessfulScanUtc":null,
      "failedUpdates":[]
    }"#;
    inputs.reliability_json.body = br#"{
      "lookbackHours":168,
      "queryState":"unavailable",
      "records":[]
    }"#;
    inputs.bitlocker_json.body = br#"{"queryState":"unavailable","volumes":[]}"#;
    inputs.boot_json.body = br#"{
      "queryState":"unavailable",
      "firmwareType":null,
      "windowsBootManagerPresent":null,
      "osLoaderCount":null,
      "defaultLoaderPresent":null
    }"#;
    let report = diagnose_windows_p0(inputs).expect("typed unavailable states must evaluate");
    let rule_ids = report
        .findings
        .iter()
        .map(|finding| finding.rule_id.as_str())
        .collect::<Vec<_>>();
    assert_eq!(
        rule_ids,
        [
            "windows.bitlocker.unavailable",
            "windows.boot.query-unavailable",
            "windows.component-store.reboot-required",
            "windows.reliability.unavailable",
            "windows.update.scan-unavailable",
        ]
    );
    assert_eq!(proposal_from_report(&report).confidence, 0.75);
}

#[test]
fn bitlocker_os_volume_must_match_the_system_volume() {
    let mut inputs = healthy_inputs();
    inputs.volumes_json.body = br#"{
      "snapshotComplete":true,
      "volumes":[
        {"driveLetter":"C:","fileSystem":"NTFS","capacityBytes":100000000000,"freeBytes":50000000000,"systemVolume":false},
        {"driveLetter":"D:","fileSystem":"NTFS","capacityBytes":100000000000,"freeBytes":50000000000,"systemVolume":true}
      ]
    }"#;
    let error = diagnose_windows_p0(inputs).expect_err("cross-source OS mismatch must fail");
    assert_eq!(error.source, EvidenceSource::Bitlocker);
    assert_eq!(error.kind, DiagnosticErrorKind::InconsistentSnapshot);
}

#[test]
fn every_non_fully_encrypted_os_conversion_state_is_a_finding() {
    let cases = [
        (
            "encryption-in-progress",
            0,
            "On",
            "windows.bitlocker.os-encryption-in-progress",
        ),
        (
            "encryption-paused",
            100,
            "On",
            "windows.bitlocker.os-encryption-paused",
        ),
        (
            "decryption-in-progress",
            100,
            "Off",
            "windows.bitlocker.os-decryption-in-progress",
        ),
        (
            "decryption-paused",
            0,
            "Off",
            "windows.bitlocker.os-decryption-paused",
        ),
        (
            "fully-decrypted",
            0,
            "Off",
            "windows.bitlocker.os-fully-decrypted",
        ),
        (
            "unknown",
            100,
            "On",
            "windows.bitlocker.os-conversion-unknown",
        ),
    ];
    for (status, percentage, protection, expected_rule) in cases {
        let body = format!(
            r#"{{
              "queryState":"complete",
              "volumes":[{{
                "mountPoint":"c:",
                "volumeType":"OperatingSystem",
                "protectionStatus":"{protection}",
                "lockStatus":"Unlocked",
                "conversionStatus":"{status}",
                "encryptionPercentage":{percentage}
              }}]
            }}"#
        );
        let mut inputs = healthy_inputs();
        inputs.bitlocker_json.body = body.as_bytes();
        let report = diagnose_windows_p0(inputs).expect("rounded conversion state must parse");
        assert!(
            report
                .findings
                .iter()
                .any(|finding| finding.rule_id == expected_rule),
            "missing rule for {status}"
        );
    }
}

#[test]
fn network_requires_coherent_families_and_usable_dns_but_allows_loopback_dns() {
    let mixed_family = br#"{
      "snapshotComplete":true,
      "adapters":[{"interfaceIndex":7,"status":"Up","hardwareInterface":true}],
      "routes":[{"destinationPrefix":"0.0.0.0/0","interfaceIndex":7,"nextHop":"2001:db8::1","routeMetric":1}],
      "dnsServers":[{"interfaceIndex":7,"addresses":["192.0.2.53"]}]
    }"#;
    let error = parse_network(EvidenceInput {
        id: NETWORK_EVIDENCE_ID,
        body: mixed_family,
    })
    .expect_err("route address families must match");
    assert_eq!(error.kind, DiagnosticErrorKind::InconsistentSnapshot);

    for address in ["0.0.0.0", "224.0.0.1", "::", "ff02::1"] {
        let body = format!(
            r#"{{
              "snapshotComplete":true,
              "adapters":[{{"interfaceIndex":7,"status":"Up","hardwareInterface":true}}],
              "routes":[{{"destinationPrefix":"0.0.0.0/0","interfaceIndex":7,"nextHop":"192.0.2.1","routeMetric":1}}],
              "dnsServers":[{{"interfaceIndex":7,"addresses":["{address}"]}}]
            }}"#
        );
        let error = parse_network(EvidenceInput {
            id: NETWORK_EVIDENCE_ID,
            body: body.as_bytes(),
        })
        .expect_err("unspecified or multicast DNS must fail");
        assert_eq!(error.kind, DiagnosticErrorKind::InconsistentSnapshot);
    }

    let mut inputs = healthy_inputs();
    inputs.network_json.body = br#"{
      "snapshotComplete":true,
      "adapters":[{"interfaceIndex":7,"status":"Up","hardwareInterface":true}],
      "routes":[{"destinationPrefix":"0.0.0.0/0","interfaceIndex":7,"nextHop":"192.0.2.1","routeMetric":1}],
      "dnsServers":[{"interfaceIndex":7,"addresses":["127.0.0.1","::1"]}]
    }"#;
    let report = diagnose_windows_p0(inputs).expect("local DNS proxy addresses are usable");
    assert!(report.findings.is_empty());
}

#[test]
fn duplicate_observations_fail_before_they_can_inflate_rules() {
    let duplicate_events = br#"{
      "lookbackHours":168,
      "queryComplete":true,
      "records":[
        {"logName":"System","recordId":41,"providerName":"Provider A","eventId":9,"level":"Error","timestampUtc":"2026-07-31T04:12:11Z"},
        {"logName":"system","recordId":41,"providerName":"Provider B","eventId":10,"level":"Error","timestampUtc":"2026-07-31T04:12:11Z"},
        {"logName":"System","recordId":41,"providerName":"Provider C","eventId":11,"level":"Error","timestampUtc":"2026-07-31T04:12:11Z"}
      ]
    }"#;
    let error = parse_event_log(EvidenceInput {
        id: EVENT_LOG_EVIDENCE_ID,
        body: duplicate_events,
    })
    .expect_err("duplicate errors must not create a repeated-error finding");
    assert_eq!(error.kind, DiagnosticErrorKind::InconsistentSnapshot);

    let distinct_events = br#"{
      "lookbackHours":168,
      "queryComplete":true,
      "records":[
        {"logName":"System","recordId":41,"providerName":"Provider","eventId":9,"level":"Error","timestampUtc":"2026-07-31T04:12:11Z"},
        {"logName":"System","recordId":42,"providerName":"Provider","eventId":9,"level":"Error","timestampUtc":"2026-07-31T04:12:11Z"},
        {"logName":"System","recordId":43,"providerName":"Provider","eventId":9,"level":"Error","timestampUtc":"2026-07-31T04:12:11Z"}
      ]
    }"#;
    parse_event_log(EvidenceInput {
        id: EVENT_LOG_EVIDENCE_ID,
        body: distinct_events,
    })
    .expect("native record IDs distinguish same-second events");

    let duplicate_reliability = br#"{
      "lookbackHours":168,
      "queryState":"complete",
      "records":[
        {"logFile":"System","recordNumber":77,"sourceName":"Windows A","productName":"Failure A","recordType":"WindowsFailure","timestampUtc":"2026-07-31T04:12:12Z"},
        {"logFile":"system","recordNumber":77,"sourceName":"Windows B","productName":null,"recordType":"HardwareFailure","timestampUtc":"2026-07-31T04:12:12Z"}
      ]
    }"#;
    let error = parse_reliability(EvidenceInput {
        id: RELIABILITY_EVIDENCE_ID,
        body: duplicate_reliability,
    })
    .expect_err("duplicate reliability rows must fail");
    assert_eq!(error.kind, DiagnosticErrorKind::InconsistentSnapshot);

    let mut network: serde_json::Value = serde_json::from_slice(include_bytes!(
        "../fixtures/diagnostics/healthy/network.json"
    ))
    .expect("network fixture JSON");
    let duplicate_route = network["routes"][0].clone();
    network["routes"]
        .as_array_mut()
        .expect("routes array")
        .push(duplicate_route);
    let network = serde_json::to_vec(&network).expect("duplicate-route JSON");
    let error = parse_network(EvidenceInput {
        id: NETWORK_EVIDENCE_ID,
        body: &network,
    })
    .expect_err("duplicate route must fail");
    assert_eq!(error.kind, DiagnosticErrorKind::InconsistentSnapshot);

    let mut drivers: serde_json::Value = serde_json::from_slice(include_bytes!(
        "../fixtures/diagnostics/healthy/drivers.json"
    ))
    .expect("drivers fixture JSON");
    let duplicate_change = drivers["recentChanges"][0].clone();
    drivers["recentChanges"]
        .as_array_mut()
        .expect("recent changes array")
        .push(duplicate_change);
    let drivers = serde_json::to_vec(&drivers).expect("duplicate-change JSON");
    let error = parse_drivers(EvidenceInput {
        id: DRIVERS_EVIDENCE_ID,
        body: &drivers,
    })
    .expect_err("duplicate recent change must fail");
    assert_eq!(error.kind, DiagnosticErrorKind::InconsistentSnapshot);
}

#[test]
fn proposal_uses_only_the_canonical_union_of_finding_evidence() {
    let mut inputs = healthy_inputs();
    inputs.event_log_json.body =
        include_bytes!("../fixtures/diagnostics/incidents/event-log-critical.json");
    let report = diagnose_windows_p0(inputs).expect("single-source incident");
    let proposal = proposal_from_report(&report);
    assert_eq!(proposal.evidence_ids, [EVENT_LOG_EVIDENCE_ID]);
    assert_eq!(proposal.confidence, 0.88);
    assert!(proposal.diagnosis.contains("windows.event-log.critical"));
    assert!(proposal.diagnosis.contains("critical events"));
}

#[test]
fn real_service_modes_and_pending_states_are_explicit() {
    let services = br#"{
      "snapshotComplete":true,
      "services":[
        {"name":"BootDriver","startMode":"boot","state":"continue-pending","win32ExitCode":0},
        {"name":"SystemDriver","startMode":"system","state":"pause-pending","win32ExitCode":0},
        {"name":"AutoService","startMode":"automatic","state":"start-pending","win32ExitCode":0}
      ]
    }"#;
    parse_services(EvidenceInput {
        id: SERVICES_EVIDENCE_ID,
        body: services,
    })
    .expect("real service modes and transient pending states must parse");
    let mut inputs = healthy_inputs();
    inputs.services_json.body = services;
    assert!(
        diagnose_windows_p0(inputs)
            .expect("transient service states must evaluate")
            .findings
            .is_empty()
    );
}

#[test]
fn event_collector_rejects_logs_outside_its_fixed_projection() {
    let wrong_log = br#"{
      "lookbackHours":168,
      "queryComplete":true,
      "records":[{"logName":"Security","recordId":1,"providerName":"Provider","eventId":1,"level":"Critical","timestampUtc":"2026-07-31T04:12:11Z"}]
    }"#;
    let error = parse_event_log(EvidenceInput {
        id: EVENT_LOG_EVIDENCE_ID,
        body: wrong_log,
    })
    .expect_err("collector log allowlist must be enforced");
    assert_eq!(error.kind, DiagnosticErrorKind::InconsistentSnapshot);
}

#[test]
fn a_complete_empty_adapter_inventory_is_a_diagnostic_state() {
    let mut inputs = healthy_inputs();
    inputs.network_json.body = br#"{
      "snapshotComplete":true,
      "adapters":[],
      "routes":[],
      "dnsServers":[]
    }"#;
    let report = diagnose_windows_p0(inputs).expect("zero adapters is a complete inventory");
    assert!(
        report
            .findings
            .iter()
            .any(|finding| finding.rule_id == "windows.network.no-up-hardware-adapter")
    );
}
