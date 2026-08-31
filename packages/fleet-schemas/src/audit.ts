import { canonicalJson } from "./canonical-json.js";
import {
  FleetSchemaError,
  expectBase64Url,
  expectDeviceId,
  expectEnum,
  expectExactKeys,
  expectRecord,
  expectRfc3339,
  expectSafeInteger,
  expectSha256,
  expectString,
} from "./validation.js";

export const FLEET_AUDIT_SCHEMA =
  "dev.kernaid.fleet.audit-envelope.v1" as const;
export const FLEET_AUDIT_DOMAIN = "kernaid:fleet:audit:v1\0" as const;
export const DEVICE_SIGNED_REPORT_DOMAIN =
  "KERNAID-SIGNED-REPORT-V1\0" as const;

export const auditKinds = [
  "diagnostic_started",
  "diagnostic_completed",
  "repair_proposed",
  "authorization_decision",
  "repair_started",
  "repair_completed",
  "rollback_started",
  "rollback_completed",
  "policy_applied",
] as const;
export const auditOutcomes = [
  "pending",
  "started",
  "allowed",
  "succeeded",
  "failed",
  "denied",
  "cancelled",
] as const;
export const auditRisks = ["R0", "R1", "R2", "R3", "R4"] as const;

export type AuditKind = (typeof auditKinds)[number];
export type AuditOutcome = (typeof auditOutcomes)[number];
export type AuditRisk = (typeof auditRisks)[number];

export interface AuditEnvelopeUnsigned {
  schema: typeof FLEET_AUDIT_SCHEMA;
  tenantId: string;
  deviceId: string;
  sessionId: string;
  eventId: string;
  sequence: number;
  previousEventSha256: string | null;
  occurredAt: string;
  kind: AuditKind;
  outcome: AuditOutcome;
  risk: AuditRisk | null;
  actionId: string | null;
  targetSha256: string | null;
  reportSha256: string | null;
  evidenceSha256: string[];
}

export interface AuditEnvelope extends AuditEnvelopeUnsigned {
  signature: string;
}

const unsignedKeys = [
  "schema",
  "tenantId",
  "deviceId",
  "sessionId",
  "eventId",
  "sequence",
  "previousEventSha256",
  "occurredAt",
  "kind",
  "outcome",
  "risk",
  "actionId",
  "targetSha256",
  "reportSha256",
  "evidenceSha256",
] as const;

export function parseAuditEnvelope(value: unknown): AuditEnvelope {
  const object = expectRecord(value);
  expectExactKeys(object, [...unsignedKeys, "signature"]);
  return {
    ...parseAuditUnsignedFields(object),
    signature: expectBase64Url(object.signature, "signature", 86, 86),
  };
}

export function parseAuditUnsigned(value: unknown): AuditEnvelopeUnsigned {
  const object = expectRecord(value);
  expectExactKeys(object, unsignedKeys);
  return parseAuditUnsignedFields(object);
}

export function toUnsignedAudit(
  value: AuditEnvelope | AuditEnvelopeUnsigned,
): AuditEnvelopeUnsigned {
  return {
    schema: value.schema,
    tenantId: value.tenantId,
    deviceId: value.deviceId,
    sessionId: value.sessionId,
    eventId: value.eventId,
    sequence: value.sequence,
    previousEventSha256: value.previousEventSha256,
    occurredAt: value.occurredAt,
    kind: value.kind,
    outcome: value.outcome,
    risk: value.risk,
    actionId: value.actionId,
    targetSha256: value.targetSha256,
    reportSha256: value.reportSha256,
    evidenceSha256: [...value.evidenceSha256],
  };
}

/** Exact `kernaid:fleet:audit:v1\0 || u64be(len) || canonical` payload. */
export function auditDomainPayloadBytes(
  value: AuditEnvelope | AuditEnvelopeUnsigned,
): Uint8Array {
  const unsigned = parseAuditUnsigned(toUnsignedAudit(value));
  const canonical = new TextEncoder().encode(canonicalJson(unsigned));
  return concatenate([
    new TextEncoder().encode(FLEET_AUDIT_DOMAIN),
    encodeUnsignedBigEndian(canonical.length, 8),
    canonical,
  ]);
}

/**
 * Exact Ed25519 bytes produced by Rust `DeviceIdentity::sign_report` around
 * the domain-separated audit payload.
 */
export function auditSigningBytes(
  value: AuditEnvelope | AuditEnvelopeUnsigned,
): Uint8Array {
  const payload = auditDomainPayloadBytes(value);
  return concatenate([
    new TextEncoder().encode(DEVICE_SIGNED_REPORT_DOMAIN),
    encodeUnsignedBigEndian(payload.length, 16),
    payload,
  ]);
}

function parseAuditUnsignedFields(
  object: Record<string, unknown>,
): AuditEnvelopeUnsigned {
  const sequence = expectSafeInteger(object.sequence, "sequence", 1);
  const previousEventSha256 = expectNullableSha256(
    object.previousEventSha256,
    "previousEventSha256",
  );
  if (
    (sequence === 1 && previousEventSha256 !== null) ||
    (sequence !== 1 && previousEventSha256 === null)
  ) {
    throw new FleetSchemaError(
      "previousEventSha256 does not match the event sequence",
    );
  }

  const kind = expectEnum(object.kind, "kind", auditKinds);
  const outcome = expectEnum(object.outcome, "outcome", auditOutcomes);
  validateKindOutcome(kind, outcome);
  const risk = expectNullableEnum(object.risk, "risk", auditRisks);
  const actionId = expectNullableAuditIdentifier(object.actionId, "actionId");
  validateAction(kind, outcome, risk, actionId);

  return {
    schema: expectEnum(object.schema, "schema", [FLEET_AUDIT_SCHEMA]),
    tenantId: expectAuditIdentifier(object.tenantId, "tenantId"),
    deviceId: expectDeviceId(object.deviceId),
    sessionId: expectAuditIdentifier(object.sessionId, "sessionId"),
    eventId: expectAuditIdentifier(object.eventId, "eventId"),
    sequence,
    previousEventSha256,
    occurredAt: expectRfc3339(object.occurredAt, "occurredAt"),
    kind,
    outcome,
    risk,
    actionId,
    targetSha256: expectNullableSha256(object.targetSha256, "targetSha256"),
    reportSha256: expectNullableSha256(object.reportSha256, "reportSha256"),
    evidenceSha256: parseEvidenceDigests(object.evidenceSha256),
  };
}

function expectAuditIdentifier(value: unknown, field: string): string {
  const identifier = expectString(value, field, 1, 160);
  if (!/^[A-Za-z0-9._:/-]+$/.test(identifier)) {
    throw new FleetSchemaError(`${field} is not a valid opaque audit ID`);
  }
  return identifier;
}

function expectNullableAuditIdentifier(
  value: unknown,
  field: string,
): string | null {
  return value === null ? null : expectAuditIdentifier(value, field);
}

function expectNullableSha256(value: unknown, field: string): string | null {
  return value === null ? null : expectSha256(value, field);
}

function expectNullableEnum<const T extends string>(
  value: unknown,
  field: string,
  options: readonly T[],
): T | null {
  return value === null ? null : expectEnum(value, field, options);
}

function parseEvidenceDigests(value: unknown): string[] {
  if (!Array.isArray(value) || value.length > 64) {
    throw new FleetSchemaError("evidenceSha256 exceeds its permitted bounds");
  }
  const digests = value.map((item) => expectSha256(item, "evidenceSha256"));
  if (
    digests.some(
      (digest, index) => index !== 0 && (digests[index - 1] ?? "") >= digest,
    )
  ) {
    throw new FleetSchemaError(
      "evidenceSha256 must be sorted and duplicate-free",
    );
  }
  return digests;
}

function validateKindOutcome(kind: AuditKind, outcome: AuditOutcome): void {
  let valid: boolean;
  switch (kind) {
    case "diagnostic_started":
    case "repair_started":
    case "rollback_started":
      valid = outcome === "started";
      break;
    case "diagnostic_completed":
    case "repair_completed":
    case "rollback_completed":
      valid = ["succeeded", "failed", "cancelled"].includes(outcome);
      break;
    case "repair_proposed":
      valid = outcome === "pending";
      break;
    case "authorization_decision":
      valid = outcome === "allowed" || outcome === "denied";
      break;
    case "policy_applied":
      valid = outcome === "succeeded" || outcome === "failed";
      break;
  }
  if (!valid) throw new FleetSchemaError("kind and outcome are inconsistent");
}

function validateAction(
  kind: AuditKind,
  outcome: AuditOutcome,
  risk: AuditRisk | null,
  actionId: string | null,
): void {
  const actionRequired = [
    "repair_proposed",
    "authorization_decision",
    "repair_started",
    "repair_completed",
    "rollback_started",
    "rollback_completed",
  ].includes(kind);
  if (actionRequired && (actionId === null || risk === null)) {
    throw new FleetSchemaError("action and risk are required for this event");
  }
  if (
    risk === "R4" &&
    !(kind === "authorization_decision" && outcome === "denied")
  ) {
    throw new FleetSchemaError("R4 cannot describe an executable event");
  }
}

function encodeUnsignedBigEndian(value: number, bytes: number): Uint8Array {
  if (!Number.isSafeInteger(value) || value < 0) {
    throw new TypeError("length must be a non-negative safe integer");
  }
  const encoded = new Uint8Array(bytes);
  let remaining = BigInt(value);
  for (let index = bytes - 1; index >= 0; index -= 1) {
    encoded[index] = Number(remaining & 0xffn);
    remaining >>= 8n;
  }
  if (remaining !== 0n) throw new TypeError("length exceeds framing width");
  return encoded;
}

function concatenate(parts: readonly Uint8Array[]): Uint8Array {
  const length = parts.reduce((total, part) => total + part.length, 0);
  const output = new Uint8Array(length);
  let offset = 0;
  for (const part of parts) {
    output.set(part, offset);
    offset += part.length;
  }
  return output;
}
