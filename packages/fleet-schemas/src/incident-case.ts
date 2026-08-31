import { canonicalJson } from "./canonical-json.js";
import {
  FleetSchemaError,
  expectDeviceId,
  expectEnum,
  expectExactKeys,
  expectIdentifier,
  expectOpaqueAssetId,
  expectRecord,
  expectRfc3339,
  expectSafeInteger,
  expectSha256,
} from "./validation.js";

export const FLEET_INCIDENT_REPORT_SCHEMA =
  "dev.kernaid.fleet.incident-report.v1" as const;

export const incidentCaseSeverities = [
  "low",
  "medium",
  "high",
  "critical",
] as const;
export type IncidentCaseSeverity = (typeof incidentCaseSeverities)[number];

export const incidentCaseStatuses = [
  "open",
  "investigating",
  "monitoring",
  "closed",
] as const;
export type IncidentCaseStatus = (typeof incidentCaseStatuses)[number];

export const incidentCaseOutcomes = [
  "resolved",
  "mitigated",
  "unresolved",
  "false_positive",
] as const;
export type IncidentCaseOutcome = (typeof incidentCaseOutcomes)[number];

export interface IncidentReportWorkOrder {
  workOrderId: string;
  actionId: string;
  actionVersion: number;
  status: string;
  resultSha256: string | null;
  stateSha256: string;
}

export interface IncidentReport {
  schema: typeof FLEET_INCIDENT_REPORT_SCHEMA;
  tenantId: string;
  caseId: string;
  sourceDeviceId: string;
  sourceAssetId: string | null;
  severity: IncidentCaseSeverity;
  outcome: IncidentCaseOutcome;
  openedAt: string;
  closedAt: string;
  timelineSha256: string;
  workOrders: IncidentReportWorkOrder[];
}

export function parseIncidentReport(value: unknown): IncidentReport {
  const object = expectRecord(value);
  expectExactKeys(object, [
    "schema",
    "tenantId",
    "caseId",
    "sourceDeviceId",
    "sourceAssetId",
    "severity",
    "outcome",
    "openedAt",
    "closedAt",
    "timelineSha256",
    "workOrders",
  ]);
  if (!Array.isArray(object.workOrders) || object.workOrders.length > 256) {
    throw new FleetSchemaError(
      "incident report workOrders are outside their bound",
    );
  }
  return {
    schema: expectEnum(object.schema, "schema", [FLEET_INCIDENT_REPORT_SCHEMA]),
    tenantId: expectIdentifier(object.tenantId, "tenantId"),
    caseId: expectIdentifier(object.caseId, "caseId"),
    sourceDeviceId: expectDeviceId(object.sourceDeviceId),
    sourceAssetId:
      object.sourceAssetId === null
        ? null
        : expectOpaqueAssetId(object.sourceAssetId),
    severity: expectEnum(object.severity, "severity", incidentCaseSeverities),
    outcome: expectEnum(object.outcome, "outcome", incidentCaseOutcomes),
    openedAt: expectRfc3339(object.openedAt, "openedAt"),
    closedAt: expectRfc3339(object.closedAt, "closedAt"),
    timelineSha256: expectSha256(object.timelineSha256, "timelineSha256"),
    workOrders: object.workOrders.map(parseReportWorkOrder),
  };
}

export function canonicalIncidentReport(value: unknown): string {
  return canonicalJson(parseIncidentReport(value));
}

function parseReportWorkOrder(value: unknown): IncidentReportWorkOrder {
  const object = expectRecord(value, "workOrder");
  expectExactKeys(
    object,
    [
      "workOrderId",
      "actionId",
      "actionVersion",
      "status",
      "resultSha256",
      "stateSha256",
    ],
    "workOrder",
  );
  return {
    workOrderId: expectIdentifier(object.workOrderId, "workOrderId"),
    actionId: expectIdentifier(object.actionId, "actionId"),
    actionVersion: expectSafeInteger(object.actionVersion, "actionVersion", 1),
    status: expectIdentifier(object.status, "status"),
    resultSha256:
      object.resultSha256 === null
        ? null
        : expectSha256(object.resultSha256, "resultSha256"),
    stateSha256: expectSha256(object.stateSha256, "stateSha256"),
  };
}
