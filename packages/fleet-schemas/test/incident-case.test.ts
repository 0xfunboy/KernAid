import assert from "node:assert/strict";
import { test } from "node:test";
import {
  FLEET_INCIDENT_REPORT_SCHEMA,
  canonicalIncidentReport,
  parseIncidentReport,
  parseServiceReceiptUnsigned,
} from "../src/index.js";

const report = {
  schema: FLEET_INCIDENT_REPORT_SCHEMA,
  tenantId: "tenant_case_test",
  caseId: "case_0123456789abcdef",
  sourceDeviceId: "KA-0123456789abcdef01234567",
  sourceAssetId: "asset fixture",
  severity: "high",
  outcome: "resolved",
  openedAt: "2026-08-31T12:00:00.000Z",
  closedAt: "2026-08-31T13:00:00.000Z",
  timelineSha256: "a".repeat(64),
  workOrders: [
    {
      workOrderId: "wo_0123456789abcdef",
      actionId: "linux.storage.health.v1",
      actionVersion: 1,
      status: "succeeded",
      resultSha256: "b".repeat(64),
      stateSha256: "c".repeat(64),
    },
  ],
} as const;

test("incident report canonicalizes the minimized closed schema", () => {
  assert.deepEqual(parseIncidentReport(report), report);
  const canonical = canonicalIncidentReport(report);
  assert.deepEqual(JSON.parse(canonical), report);
  assert.match(canonical, /^\{"caseId":/);
  assert.throws(() =>
    parseIncidentReport({ ...report, rawEvidence: "must-not-cross-boundary" }),
  );
});

test("service receipts admit the incident closure operation", () => {
  assert.equal(
    parseServiceReceiptUnsigned({
      schema: "dev.kernaid.fleet.service-receipt.v1",
      tenantId: report.tenantId,
      deviceId: report.sourceDeviceId,
      operation: "incident_case_close",
      sequence: 1,
      requestSha256: "d".repeat(64),
      responseSha256: "e".repeat(64),
      acceptedAt: report.closedAt,
      outcome: "accepted",
    }).operation,
    "incident_case_close",
  );
});
