export const incidentSeverities = Object.freeze([
  "low",
  "medium",
  "high",
  "critical",
]);
export const incidentStatuses = Object.freeze([
  "open",
  "investigating",
  "monitoring",
]);
export const incidentOutcomes = Object.freeze([
  "resolved",
  "mitigated",
  "unresolved",
  "false_positive",
]);

export function createIncidentPayload(input) {
  if (!/^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/.test(input.requestId ?? "")) {
    throw new Error("The generated case request identifier is invalid.");
  }
  const source = incidentSource(input.sourceValue);
  return {
    requestId: input.requestId,
    source,
    severity: enumValue(input.severity, incidentSeverities, "severity"),
    assigneeLabel: assigneeLabel(input.assigneeLabel),
  };
}

export function updateIncidentPayload(input) {
  return {
    severity: enumValue(input.severity, incidentSeverities, "severity"),
    status: enumValue(input.status, incidentStatuses, "status"),
    assigneeLabel: assigneeLabel(input.assigneeLabel),
  };
}

export function closeIncidentPayload(caseId, outcome) {
  if (!/^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/.test(caseId ?? "")) {
    throw new Error("The incident case identifier is invalid.");
  }
  return {
    caseId,
    outcome: enumValue(outcome, incidentOutcomes, "outcome"),
  };
}

export function linkIncidentPayload(workOrderId) {
  if (!/^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/.test(workOrderId ?? "")) {
    throw new Error("Select a compatible work order.");
  }
  return { workOrderId };
}

export function assertMinimizedIncidentCase(value) {
  assertRecord(value, "incident case");
  assertKeys(value, [
    "tenantId",
    "caseId",
    "requestId",
    "source",
    "severity",
    "status",
    "assigneeLabel",
    "createdByCredentialId",
    "createdAt",
    "updatedAt",
    "workOrders",
    "closure",
  ]);
  assertRecord(value.source, "source");
  assertKeys(value.source, ["deviceId", "assetId"]);
  if (!Array.isArray(value.workOrders) || value.workOrders.length > 256) {
    throw new Error("Incident work orders crossed the minimized UI boundary.");
  }
  value.workOrders.forEach((workOrder) => {
    assertRecord(workOrder, "work order");
    assertKeys(workOrder, [
      "workOrderId",
      "actionId",
      "actionVersion",
      "status",
      "resultSha256",
      "stateSha256",
      "linkedAt",
      "observedAt",
    ]);
  });
  if (value.closure !== null) {
    assertRecord(value.closure, "closure");
    assertKeys(value.closure, [
      "outcome",
      "closedAt",
      "closedByCredentialId",
      "reportSha256",
      "report",
      "serviceReceipt",
    ]);
    assertRecord(value.closure.report, "report");
    assertKeys(value.closure.report, [
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
    assertRecord(value.closure.serviceReceipt, "service receipt");
    assertKeys(value.closure.serviceReceipt, [
      "schema",
      "tenantId",
      "deviceId",
      "operation",
      "sequence",
      "requestSha256",
      "responseSha256",
      "acceptedAt",
      "outcome",
      "signature",
    ]);
  }
  return value;
}

export function canonicalIncidentReport(report) {
  return canonicalJson(report);
}

function incidentSource(value) {
  if (typeof value !== "string") throw new Error("Select a case source.");
  const separator = value.indexOf(":");
  const kind = value.slice(0, separator);
  const identifier = value.slice(separator + 1);
  if (kind === "device" && /^KA-[0-9a-f]{24}$/.test(identifier)) {
    return { kind, deviceId: identifier };
  }
  if (
    kind === "asset" &&
    new TextEncoder().encode(identifier).length >= 1 &&
    new TextEncoder().encode(identifier).length <= 256 &&
    !/[\u0000-\u001f\u007f]/.test(identifier)
  ) {
    return { kind, assetId: identifier };
  }
  throw new Error("Select a valid enrolled device or observed asset.");
}

function assigneeLabel(value) {
  const normalized = String(value ?? "").trim();
  if (normalized === "") return null;
  if (
    normalized.length > 64 ||
    !/^[A-Za-z0-9][A-Za-z0-9 ._+-]*$/.test(normalized)
  ) {
    throw new Error("Use a bounded team or queue label, not an email address.");
  }
  return normalized;
}

function enumValue(value, options, field) {
  if (!options.includes(value)) throw new Error(`Select a valid ${field}.`);
  return value;
}

function assertRecord(value, field) {
  if (value === null || typeof value !== "object" || Array.isArray(value)) {
    throw new Error(`${field} crossed the minimized UI boundary.`);
  }
}

function assertKeys(value, allowedKeys) {
  const allowed = new Set(allowedKeys);
  if (Object.keys(value).some((key) => !allowed.has(key))) {
    throw new Error("Incident data crossed the minimized UI boundary.");
  }
}

function canonicalJson(value) {
  if (value === null) return "null";
  if (typeof value === "boolean" || typeof value === "number") {
    if (typeof value === "number" && !Number.isSafeInteger(value)) {
      throw new Error("Incident reports allow only safe integers.");
    }
    return JSON.stringify(value);
  }
  if (typeof value === "string") return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(",")}]`;
  assertRecord(value, "report");
  return `{${Object.keys(value)
    .sort()
    .map((key) => `${JSON.stringify(key)}:${canonicalJson(value[key])}`)
    .join(",")}}`;
}
