import assert from "node:assert/strict";
import { test } from "node:test";
import {
  assertMinimizedIncidentCase,
  canonicalIncidentReport,
  closeIncidentPayload,
  createIncidentPayload,
  linkIncidentPayload,
  updateIncidentPayload,
} from "./incident-case-ui.js";

test("incident mutations emit only closed bounded payloads", () => {
  assert.deepEqual(
    createIncidentPayload({
      requestId: "ui_case_1",
      sourceValue: "device:KA-0123456789abcdef01234567",
      severity: "high",
      assigneeLabel: "storage-ops",
    }),
    {
      requestId: "ui_case_1",
      source: { kind: "device", deviceId: "KA-0123456789abcdef01234567" },
      severity: "high",
      assigneeLabel: "storage-ops",
    },
  );
  assert.deepEqual(
    updateIncidentPayload({
      severity: "low",
      status: "monitoring",
      assigneeLabel: "",
    }),
    {
      severity: "low",
      status: "monitoring",
      assigneeLabel: null,
    },
  );
  assert.deepEqual(closeIncidentPayload("case_1", "resolved"), {
    caseId: "case_1",
    outcome: "resolved",
  });
  assert.deepEqual(linkIncidentPayload("wo_1"), { workOrderId: "wo_1" });
  assert.throws(() =>
    createIncidentPayload({
      requestId: "case_2",
      sourceValue: "asset:asset-1",
      severity: "critical",
      assigneeLabel: "person@example.test",
    }),
  );
});

test("incident responses reject unknown/raw fields and reports canonicalize", () => {
  const incident = {
    tenantId: "tenant_1",
    caseId: "case_1",
    requestId: "request_1",
    source: { deviceId: "KA-0123456789abcdef01234567", assetId: null },
    severity: "high",
    status: "open",
    assigneeLabel: null,
    createdByCredentialId: "cred_1",
    createdAt: "2026-08-31T12:00:00.000Z",
    updatedAt: "2026-08-31T12:00:00.000Z",
    workOrders: [],
    closure: null,
  };
  assert.equal(assertMinimizedIncidentCase(incident).caseId, "case_1");
  assert.throws(() =>
    assertMinimizedIncidentCase({ ...incident, rawEvidence: "forbidden" }),
  );
  assert.equal(
    canonicalIncidentReport({ z: 1, nested: { z: false, a: null }, a: 2 }),
    '{"a":2,"nested":{"a":null,"z":false},"z":1}',
  );
});
