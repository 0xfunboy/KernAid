import type { Risk } from "@kernaid/schemas";

const SESSION_ID = /^S-[A-Za-z0-9-]+$/;
const EVIDENCE_ID = /^E-[A-Za-z0-9-]+$/;
const PLAN_ID = /^P-[A-Za-z0-9-]+$/;
const APPROVAL_ID = /^A-[A-Za-z0-9-]+$/;
const ACTION_ID = /^[a-z0-9.-]+$/;
const FINGERPRINT = /^sha256:[a-f0-9]{64}$/;
const SHA256 = /^[a-f0-9]{64}$/;
const DATE_TIME =
  /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2})$/;
const MAX_AUDIT_RECORD_BYTES = 64 * 1024;
// Must remain aligned with the native Ed25519 signed-envelope limit.
const MAX_SEALED_REPORT_BYTES = 1024 * 1024;
const MAX_ARTIFACT_URI_LENGTH = MAX_SEALED_REPORT_BYTES * 12 + 1024;

export const SIGNED_REPORT_MEDIA_TYPE =
  "application/vnd.kernaid.signed-report+json";

export type ReportPayloadMediaType = "application/json" | "text/markdown";
export type ArtifactMediaType =
  ReportPayloadMediaType | typeof SIGNED_REPORT_MEDIA_TYPE;

type RecordValue = Record<string, unknown>;

export type AuditSinkStatus =
  | {
      schemaVersion: "1.0";
      state: "secure";
      persistent: true;
      signed: true;
    }
  | {
      schemaVersion: "1.0";
      state: "unavailable";
      persistent: false;
      signed: false;
    };

export const SECURE_AUDIT_STATUS: AuditSinkStatus = Object.freeze({
  schemaVersion: "1.0",
  state: "secure",
  persistent: true,
  signed: true,
});

export const UNAVAILABLE_AUDIT_STATUS: AuditSinkStatus = Object.freeze({
  schemaVersion: "1.0",
  state: "unavailable",
  persistent: false,
  signed: false,
});

interface AuditRecordBase<Type extends string, Payload> {
  schemaVersion: "1.0";
  type: Type;
  sessionId: string;
  sequence: number;
  capturedAt: string;
  payload: Payload;
}

export type SessionStartedAuditRecord = AuditRecordBase<
  "session.started",
  {
    mode: "rescue" | "resident";
    targetFingerprint: string;
  }
>;

export type EvidenceAuditRecord = AuditRecordBase<
  "evidence",
  {
    evidenceId: string;
    sha256: string;
    sensitivity: "public" | "system" | "sensitive";
  }
>;

export type DiagnosisAuditRecord = AuditRecordBase<
  "diagnosis",
  {
    diagnosisSha256: string;
    confidence: number;
    evidenceIds: string[];
    requestedEvidenceCount: number;
  }
>;

export type PlanAuditRecord = AuditRecordBase<
  "plan",
  {
    planId: string;
    targetFingerprint: string;
    risk: Risk;
    evidenceIds: string[];
    actions: string[];
  }
>;

export type ApprovalAuditRecord = AuditRecordBase<
  "approval",
  {
    approvalId: string;
    planId: string;
    targetFingerprint: string;
    approvedAt: string;
    approvedBySha256: string;
  }
>;

export type ExecutionAuditRecord = AuditRecordBase<
  "execution",
  {
    planId: string;
    eventSequence: number;
    status: "started" | "succeeded" | "failed" | "rolled-back";
    action: string;
  }
>;

export type ReportAuditRecord = AuditRecordBase<
  "report",
  {
    format: "json" | "markdown";
    payloadMediaType: ReportPayloadMediaType;
    payloadSha256: string;
    verification: "not-run" | "passed" | "failed";
  }
>;

export type AuditRecord =
  | SessionStartedAuditRecord
  | EvidenceAuditRecord
  | DiagnosisAuditRecord
  | PlanAuditRecord
  | ApprovalAuditRecord
  | ExecutionAuditRecord
  | ReportAuditRecord;

export type AuditRecordType = AuditRecord["type"];

export interface AuditSealRequest {
  schemaVersion: "1.0";
  sessionId: string;
  format: "json" | "markdown";
  payloadMediaType: ReportPayloadMediaType;
  body: string;
  payloadSha256: string;
}

export interface ArtifactRef {
  mediaType: ArtifactMediaType;
  payloadMediaType: ReportPayloadMediaType;
  uri: string;
  sha256: string;
  payloadSha256: string;
  auditStatus: AuditSinkStatus;
}

export interface AuditSink {
  readonly status: AuditSinkStatus;
  append(record: AuditRecord): Promise<void>;
  sealReport(request: AuditSealRequest): Promise<ArtifactRef>;
}

export class AuditContractError extends Error {
  constructor(reason: string) {
    super(`Audit contract: ${reason}`);
    this.name = "AuditContractError";
  }
}

export function parseAuditSinkStatus(value: unknown): AuditSinkStatus {
  const status = record(value, "status must be an object");
  exactKeys(status, ["schemaVersion", "state", "persistent", "signed"]);
  if (status.schemaVersion !== "1.0") fail("unsupported status version");
  if (
    status.state === "secure" &&
    status.persistent === true &&
    status.signed === true
  )
    return clone(status) as AuditSinkStatus;
  if (
    status.state === "unavailable" &&
    status.persistent === false &&
    status.signed === false
  )
    return clone(status) as AuditSinkStatus;
  return fail("invalid status combination");
}

export function auditStatusesEqual(
  left: AuditSinkStatus,
  right: AuditSinkStatus,
): boolean {
  return (
    left.schemaVersion === right.schemaVersion &&
    left.state === right.state &&
    left.persistent === right.persistent &&
    left.signed === right.signed
  );
}

export function parseAuditRecord(value: unknown): AuditRecord {
  const item = record(value, "record must be an object");
  exactKeys(item, [
    "schemaVersion",
    "type",
    "sessionId",
    "sequence",
    "capturedAt",
    "payload",
  ]);
  if (item.schemaVersion !== "1.0") fail("unsupported record version");
  sessionId(item.sessionId);
  positiveInteger(item.sequence, 4096, "record sequence is invalid");
  dateTime(item.capturedAt, "record timestamp is invalid");
  const payload = record(item.payload, "record payload must be an object");

  switch (item.type) {
    case "session.started":
      parseSessionStarted(payload);
      break;
    case "evidence":
      parseEvidence(payload);
      break;
    case "diagnosis":
      parseDiagnosis(payload);
      break;
    case "plan":
      parsePlan(payload);
      break;
    case "approval":
      parseApproval(payload);
      break;
    case "execution":
      parseExecution(payload);
      break;
    case "report":
      parseReport(payload);
      break;
    default:
      fail("unknown record type");
  }

  let encoded: string;
  try {
    encoded = JSON.stringify(item);
  } catch {
    return fail("record is not serializable");
  }
  if (bytes(encoded) > MAX_AUDIT_RECORD_BYTES)
    fail("record exceeds size limit");
  return clone(item) as unknown as AuditRecord;
}

export function parseAuditSealRequest(value: unknown): AuditSealRequest {
  const request = record(value, "seal request must be an object");
  exactKeys(request, [
    "schemaVersion",
    "sessionId",
    "format",
    "payloadMediaType",
    "body",
    "payloadSha256",
  ]);
  if (request.schemaVersion !== "1.0") fail("unsupported seal request version");
  sessionId(request.sessionId);
  formatAndMediaType(request.format, request.payloadMediaType);
  stringValue(
    request.body,
    MAX_SEALED_REPORT_BYTES,
    false,
    "invalid report body",
  );
  if (bytes(request.body as string) > MAX_SEALED_REPORT_BYTES)
    fail("report body exceeds size limit");
  hash(request.payloadSha256, "invalid report hash");
  return clone(request) as unknown as AuditSealRequest;
}

export function parseArtifactRef(value: unknown): ArtifactRef {
  const artifact = record(value, "artifact must be an object");
  exactKeys(artifact, [
    "mediaType",
    "payloadMediaType",
    "uri",
    "sha256",
    "payloadSha256",
    "auditStatus",
  ]);
  stringValue(artifact.mediaType, 128, false, "invalid artifact media type");
  if (
    artifact.payloadMediaType !== "application/json" &&
    artifact.payloadMediaType !== "text/markdown"
  )
    fail("invalid artifact payload media type");
  stringValue(
    artifact.uri,
    MAX_ARTIFACT_URI_LENGTH,
    false,
    "invalid artifact URI",
  );
  const uri = artifact.uri as string;
  hash(artifact.sha256, "invalid artifact hash");
  hash(artifact.payloadSha256, "invalid artifact payload hash");
  const status = parseAuditSinkStatus(artifact.auditStatus);
  if (
    status.state === "unavailable" &&
    (artifact.mediaType !== artifact.payloadMediaType ||
      artifact.sha256 !== artifact.payloadSha256 ||
      !uri.startsWith(
        `data:${artifact.payloadMediaType};charset=utf-8,`,
      ))
  )
    fail("volatile artifact must expose its payload directly");
  if (
    status.state === "secure" &&
    (artifact.mediaType !== SIGNED_REPORT_MEDIA_TYPE ||
      !uri.startsWith(`data:${SIGNED_REPORT_MEDIA_TYPE};base64,`))
  )
    fail("secure artifact must use the signed report container");
  return clone(artifact) as unknown as ArtifactRef;
}

function parseSessionStarted(payload: RecordValue): void {
  exactKeys(payload, ["mode", "targetFingerprint"]);
  if (payload.mode !== "resident" && payload.mode !== "rescue")
    fail("invalid session mode");
  fingerprint(payload.targetFingerprint);
}

function parseEvidence(payload: RecordValue): void {
  exactKeys(payload, ["evidenceId", "sha256", "sensitivity"]);
  identifier(payload.evidenceId, EVIDENCE_ID, "invalid evidence id");
  hash(payload.sha256, "invalid evidence hash");
  if (
    !(["public", "system", "sensitive"] as unknown[]).includes(
      payload.sensitivity,
    )
  )
    fail("invalid evidence sensitivity");
}

function parseDiagnosis(payload: RecordValue): void {
  exactKeys(payload, [
    "diagnosisSha256",
    "confidence",
    "evidenceIds",
    "requestedEvidenceCount",
  ]);
  hash(payload.diagnosisSha256, "invalid diagnosis hash");
  if (
    typeof payload.confidence !== "number" ||
    !Number.isFinite(payload.confidence) ||
    payload.confidence < 0 ||
    payload.confidence > 1
  )
    fail("invalid diagnosis confidence");
  identifiers(payload.evidenceIds, EVIDENCE_ID, 1, 128, true);
  nonNegativeInteger(
    payload.requestedEvidenceCount,
    128,
    "invalid requested evidence count",
  );
}

function parsePlan(payload: RecordValue): void {
  exactKeys(payload, [
    "planId",
    "targetFingerprint",
    "risk",
    "evidenceIds",
    "actions",
  ]);
  identifier(payload.planId, PLAN_ID, "invalid plan id");
  fingerprint(payload.targetFingerprint);
  if (!(["R0", "R1", "R2", "R3", "R4"] as unknown[]).includes(payload.risk))
    fail("invalid plan risk");
  identifiers(payload.evidenceIds, EVIDENCE_ID, 1, 128, true);
  identifiers(payload.actions, ACTION_ID, 1, 64, false, 256);
}

function parseApproval(payload: RecordValue): void {
  exactKeys(payload, [
    "approvalId",
    "planId",
    "targetFingerprint",
    "approvedAt",
    "approvedBySha256",
  ]);
  identifier(payload.approvalId, APPROVAL_ID, "invalid approval id");
  identifier(payload.planId, PLAN_ID, "invalid plan id");
  fingerprint(payload.targetFingerprint);
  dateTime(payload.approvedAt, "invalid approval timestamp");
  hash(payload.approvedBySha256, "invalid approver hash");
}

function parseExecution(payload: RecordValue): void {
  exactKeys(payload, ["planId", "eventSequence", "status", "action"]);
  identifier(payload.planId, PLAN_ID, "invalid plan id");
  positiveInteger(payload.eventSequence, 1024, "invalid event sequence");
  if (
    !(["started", "succeeded", "failed", "rolled-back"] as unknown[]).includes(
      payload.status,
    )
  )
    fail("invalid execution status");
  identifier(payload.action, ACTION_ID, "invalid action id", 256);
}

function parseReport(payload: RecordValue): void {
  exactKeys(payload, [
    "format",
    "payloadMediaType",
    "payloadSha256",
    "verification",
  ]);
  formatAndMediaType(payload.format, payload.payloadMediaType);
  hash(payload.payloadSha256, "invalid report hash");
  if (
    !(["not-run", "passed", "failed"] as unknown[]).includes(
      payload.verification,
    )
  )
    fail("invalid report verification");
}

function formatAndMediaType(format: unknown, mediaType: unknown): void {
  if (
    (format === "json" && mediaType === "application/json") ||
    (format === "markdown" && mediaType === "text/markdown")
  )
    return;
  fail("report format and media type do not match");
}

function exactKeys(value: RecordValue, required: readonly string[]): void {
  const allowed = new Set(required);
  if (required.some((key) => !Object.hasOwn(value, key)))
    fail("required field is missing");
  if (Object.keys(value).some((key) => !allowed.has(key)))
    fail("unknown field");
}

function record(value: unknown, reason: string): RecordValue {
  if (typeof value !== "object" || value === null || Array.isArray(value))
    return fail(reason);
  const prototype = Object.getPrototypeOf(value);
  if (prototype !== Object.prototype && prototype !== null) return fail(reason);
  return value as RecordValue;
}

function sessionId(value: unknown): void {
  identifier(value, SESSION_ID, "invalid session id");
}

function fingerprint(value: unknown): void {
  if (typeof value !== "string" || !FINGERPRINT.test(value))
    fail("invalid target fingerprint");
}

function hash(value: unknown, reason: string): void {
  if (typeof value !== "string" || !SHA256.test(value)) fail(reason);
}

function identifier(
  value: unknown,
  pattern: RegExp,
  reason: string,
  maximum = 128,
): void {
  if (
    typeof value !== "string" ||
    value.length > maximum ||
    !pattern.test(value)
  )
    fail(reason);
}

function identifiers(
  value: unknown,
  pattern: RegExp,
  minimum: number,
  maximum: number,
  unique: boolean,
  maximumLength = 128,
): void {
  if (
    !Array.isArray(value) ||
    value.length < minimum ||
    value.length > maximum ||
    value.some(
      (item) =>
        typeof item !== "string" ||
        item.length > maximumLength ||
        !pattern.test(item),
    ) ||
    (unique && new Set(value).size !== value.length)
  )
    fail("invalid identifier collection");
}

function positiveInteger(
  value: unknown,
  maximum: number,
  reason: string,
): void {
  if (
    !Number.isSafeInteger(value) ||
    Number(value) < 1 ||
    Number(value) > maximum
  )
    fail(reason);
}

function nonNegativeInteger(
  value: unknown,
  maximum: number,
  reason: string,
): void {
  if (
    !Number.isSafeInteger(value) ||
    Number(value) < 0 ||
    Number(value) > maximum
  )
    fail(reason);
}

function dateTime(value: unknown, reason: string): void {
  if (
    typeof value !== "string" ||
    !DATE_TIME.test(value) ||
    Number.isNaN(Date.parse(value))
  )
    fail(reason);
}

function stringValue(
  value: unknown,
  maximum: number,
  allowEmpty: boolean,
  reason: string,
): void {
  if (
    typeof value !== "string" ||
    (!allowEmpty && value.length === 0) ||
    value.length > maximum
  )
    fail(reason);
}

function bytes(value: string): number {
  return new TextEncoder().encode(value).byteLength;
}

function clone<T>(value: T): T {
  return deepFreeze(structuredClone(value));
}

function deepFreeze<T>(value: T, seen = new WeakSet<object>()): T {
  if (typeof value !== "object" || value === null || seen.has(value))
    return value;
  seen.add(value);
  for (const child of Object.values(value)) deepFreeze(child, seen);
  return Object.freeze(value);
}

function fail(reason: string): never {
  throw new AuditContractError(reason);
}
