use kernaid_windows_pack::diagnostics::{EvidenceInput, WindowsP0Inputs};

pub const EVENT_LOG_EVIDENCE_ID: &str = "E-WIN-EVENT-LOG";
pub const RELIABILITY_EVIDENCE_ID: &str = "E-WIN-RELIABILITY";
pub const COMPONENT_STORE_EVIDENCE_ID: &str = "E-WIN-COMPONENT-STORE";
pub const SFC_EVIDENCE_ID: &str = "E-WIN-SFC-VERIFY";
pub const UPDATE_EVIDENCE_ID: &str = "E-WIN-UPDATE";
pub const SERVICES_EVIDENCE_ID: &str = "E-WIN-SERVICES";
pub const NETWORK_EVIDENCE_ID: &str = "E-WIN-NETWORK";
pub const DRIVERS_EVIDENCE_ID: &str = "E-WIN-DRIVERS";
pub const BITLOCKER_EVIDENCE_ID: &str = "E-WIN-BITLOCKER";
pub const BOOT_EVIDENCE_ID: &str = "E-WIN-BOOT";
pub const VOLUMES_EVIDENCE_ID: &str = "E-WIN-VOLUMES";

#[allow(dead_code)]
pub const FIXTURE_EVIDENCE_IDS: [&str; 11] = [
    EVENT_LOG_EVIDENCE_ID,
    RELIABILITY_EVIDENCE_ID,
    COMPONENT_STORE_EVIDENCE_ID,
    SFC_EVIDENCE_ID,
    UPDATE_EVIDENCE_ID,
    SERVICES_EVIDENCE_ID,
    NETWORK_EVIDENCE_ID,
    DRIVERS_EVIDENCE_ID,
    BITLOCKER_EVIDENCE_ID,
    BOOT_EVIDENCE_ID,
    VOLUMES_EVIDENCE_ID,
];

pub fn healthy_inputs() -> WindowsP0Inputs<'static> {
    WindowsP0Inputs {
        event_log_json: EvidenceInput {
            id: EVENT_LOG_EVIDENCE_ID,
            body: include_bytes!("../../fixtures/diagnostics/healthy/event-log.json"),
        },
        reliability_json: EvidenceInput {
            id: RELIABILITY_EVIDENCE_ID,
            body: include_bytes!("../../fixtures/diagnostics/healthy/reliability.json"),
        },
        component_store_json: EvidenceInput {
            id: COMPONENT_STORE_EVIDENCE_ID,
            body: include_bytes!("../../fixtures/diagnostics/healthy/component-store.json"),
        },
        sfc_json: EvidenceInput {
            id: SFC_EVIDENCE_ID,
            body: include_bytes!("../../fixtures/diagnostics/healthy/sfc.json"),
        },
        update_json: EvidenceInput {
            id: UPDATE_EVIDENCE_ID,
            body: include_bytes!("../../fixtures/diagnostics/healthy/update.json"),
        },
        services_json: EvidenceInput {
            id: SERVICES_EVIDENCE_ID,
            body: include_bytes!("../../fixtures/diagnostics/healthy/services.json"),
        },
        network_json: EvidenceInput {
            id: NETWORK_EVIDENCE_ID,
            body: include_bytes!("../../fixtures/diagnostics/healthy/network.json"),
        },
        drivers_json: EvidenceInput {
            id: DRIVERS_EVIDENCE_ID,
            body: include_bytes!("../../fixtures/diagnostics/healthy/drivers.json"),
        },
        bitlocker_json: EvidenceInput {
            id: BITLOCKER_EVIDENCE_ID,
            body: include_bytes!("../../fixtures/diagnostics/healthy/bitlocker.json"),
        },
        boot_json: EvidenceInput {
            id: BOOT_EVIDENCE_ID,
            body: include_bytes!("../../fixtures/diagnostics/healthy/boot.json"),
        },
        volumes_json: EvidenceInput {
            id: VOLUMES_EVIDENCE_ID,
            body: include_bytes!("../../fixtures/diagnostics/healthy/volumes.json"),
        },
    }
}

pub fn incident_inputs() -> WindowsP0Inputs<'static> {
    let mut inputs = healthy_inputs();
    inputs.event_log_json.body =
        include_bytes!("../../fixtures/diagnostics/incidents/event-log-critical.json");
    inputs.reliability_json.body =
        include_bytes!("../../fixtures/diagnostics/incidents/reliability-hardware.json");
    inputs.component_store_json.body =
        include_bytes!("../../fixtures/diagnostics/incidents/component-store-repairable.json");
    inputs.sfc_json.body =
        include_bytes!("../../fixtures/diagnostics/incidents/sfc-violations.json");
    inputs.update_json.body =
        include_bytes!("../../fixtures/diagnostics/incidents/update-failed-pending.json");
    inputs.services_json.body =
        include_bytes!("../../fixtures/diagnostics/incidents/services-stopped.json");
    inputs.network_json.body =
        include_bytes!("../../fixtures/diagnostics/incidents/network-no-default.json");
    inputs.drivers_json.body =
        include_bytes!("../../fixtures/diagnostics/incidents/drivers-problem.json");
    inputs.bitlocker_json.body =
        include_bytes!("../../fixtures/diagnostics/incidents/bitlocker-suspended.json");
    inputs.boot_json.body =
        include_bytes!("../../fixtures/diagnostics/incidents/boot-incomplete.json");
    inputs.volumes_json.body =
        include_bytes!("../../fixtures/diagnostics/incidents/volumes-low-space.json");
    inputs
}

#[allow(dead_code)]
pub fn request_bytes(inputs: WindowsP0Inputs<'_>) -> Vec<u8> {
    let document = |id: &str, collector: &str, body: &[u8]| {
        serde_json::json!({
            "id": id,
            "collector": collector,
            "content": String::from_utf8(body.to_vec()).expect("fixture must be UTF-8")
        })
    };
    serde_json::to_vec(&serde_json::json!({
        "schemaVersion": "1.0",
        "evidence": [
            document(inputs.event_log_json.id, "windows.event-log.window", inputs.event_log_json.body),
            document(inputs.reliability_json.id, "windows.reliability.records", inputs.reliability_json.body),
            document(inputs.component_store_json.id, "windows.component-store.check-health", inputs.component_store_json.body),
            document(inputs.sfc_json.id, "windows.sfc.verify-only", inputs.sfc_json.body),
            document(inputs.update_json.id, "windows.update.state", inputs.update_json.body),
            document(inputs.services_json.id, "windows.services.state", inputs.services_json.body),
            document(inputs.network_json.id, "windows.network.state", inputs.network_json.body),
            document(inputs.drivers_json.id, "windows.drivers.state", inputs.drivers_json.body),
            document(inputs.bitlocker_json.id, "windows.bitlocker.state", inputs.bitlocker_json.body),
            document(inputs.boot_json.id, "windows.boot.state", inputs.boot_json.body),
            document(inputs.volumes_json.id, "windows.volumes.state", inputs.volumes_json.body)
        ]
    }))
    .expect("request fixture must serialize")
}
