import type {
  Approval,
  DiagnosisProposal,
  Evidence,
  ExecutionEvent,
  PlanStep,
  SessionReport,
  ValidatedPlan,
} from "./index.js";

type RecordValue = Record<string, unknown>;

const FINGERPRINT = /^sha256:[a-f0-9]{64}$/;
const HASH = /^[a-f0-9]{64}$/;
const EVIDENCE_ID = /^E-[A-Za-z0-9-]+$/;
const PLAN_ID = /^P-[A-Za-z0-9-]+$/;
const APPROVAL_ID = /^A-[A-Za-z0-9-]+$/;
const SESSION_ID = /^S-[A-Za-z0-9-]+$/;
const ACTION_ID = /^[a-z0-9.-]+$/;
const DATE_TIME =
  /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2})$/;
const MAX_COLLECTION_ITEMS = 128;
const MAX_TEXT_LENGTH = 64 * 1024;

export class SchemaValidationError extends Error {
  constructor(schema: string, reason: string) {
    super(`${schema}: ${reason}`);
    this.name = "SchemaValidationError";
  }
}

function fail(schema: string, reason: string): never {
  throw new SchemaValidationError(schema, reason);
}

function record(schema: string, value: unknown): RecordValue {
  if (typeof value !== "object" || value === null || Array.isArray(value)) {
    return fail(schema, "expected an object");
  }
  const prototype = Object.getPrototypeOf(value);
  if (prototype !== Object.prototype && prototype !== null)
    return fail(schema, "expected a plain object");
  return value as RecordValue;
}

function exactKeys(
  schema: string,
  value: RecordValue,
  required: readonly string[],
  optional: readonly string[] = [],
): void {
  const allowed = new Set([...required, ...optional]);
  if (required.some((key) => !Object.hasOwn(value, key)))
    fail(schema, "missing required field");
  if (Object.keys(value).some((key) => !allowed.has(key)))
    fail(schema, "unknown field");
}

function stringValue(
  schema: string,
  value: unknown,
  allowEmpty = false,
  maximum = MAX_TEXT_LENGTH,
): string {
  if (
    typeof value !== "string" ||
    (!allowEmpty && value.length === 0) ||
    value.length > maximum
  ) {
    return fail(schema, "expected a non-empty string");
  }
  return value;
}

function stringArray(schema: string, value: unknown, minimum = 0): string[] {
  if (
    !Array.isArray(value) ||
    value.length < minimum ||
    value.length > MAX_COLLECTION_ITEMS ||
    value.some((item) => typeof item !== "string" || item.length > 256)
  ) {
    return fail(schema, "expected a string array");
  }
  if (new Set(value).size !== value.length)
    fail(schema, "array values must be unique");
  return [...value];
}

function dateTime(schema: string, value: unknown): string {
  const result = stringValue(schema, value);
  if (!DATE_TIME.test(result) || Number.isNaN(Date.parse(result)))
    fail(schema, "invalid date-time");
  return result;
}

function jsonValue(
  value: unknown,
  seen = new WeakSet<object>(),
  depth = 0,
): boolean {
  if (value === null || typeof value === "string" || typeof value === "boolean")
    return true;
  if (typeof value === "number") return Number.isFinite(value);
  if (typeof value !== "object") return false;
  if (depth > 32) return false;
  if (seen.has(value)) return false;
  seen.add(value);
  if (Array.isArray(value))
    return (
      value.length <= MAX_COLLECTION_ITEMS &&
      value.every((item) => jsonValue(item, seen, depth + 1))
    );
  const prototype = Object.getPrototypeOf(value);
  if (prototype !== Object.prototype && prototype !== null) return false;
  return Object.values(value as RecordValue).every((item) =>
    jsonValue(item, seen, depth + 1),
  );
}

function cloned<T>(value: T): T {
  return deepFreeze(structuredClone(value));
}

function deepFreeze<T>(value: T, seen = new WeakSet<object>()): T {
  if (typeof value !== "object" || value === null || seen.has(value))
    return value;
  seen.add(value);
  for (const child of Object.values(value)) deepFreeze(child, seen);
  return Object.freeze(value);
}

export function parseEvidence(value: unknown): Evidence {
  const schema = "Evidence";
  const item = record(schema, value);
  exactKeys(schema, item, [
    "schemaVersion",
    "id",
    "collector",
    "target",
    "capturedAt",
    "contentType",
    "sha256",
    "sensitivity",
    "trust",
    "summary",
    "blobRef",
  ]);
  if (item.schemaVersion !== "1.0" || item.trust !== "observed-untrusted")
    fail(schema, "unsupported version or trust");
  if (!EVIDENCE_ID.test(stringValue(schema, item.id)))
    fail(schema, "invalid evidence id");
  stringValue(schema, item.collector, false, 256);
  stringValue(schema, item.target, false, 512);
  dateTime(schema, item.capturedAt);
  stringValue(schema, item.contentType, false, 256);
  const hash = stringValue(schema, item.sha256);
  if (!HASH.test(hash) || item.blobRef !== `sha256:${hash}`)
    fail(schema, "invalid evidence hash");
  if (!["public", "system", "sensitive"].includes(String(item.sensitivity)))
    fail(schema, "invalid sensitivity");
  stringValue(schema, item.summary, true, 8 * 1024);
  return cloned(item) as unknown as Evidence;
}

export function parseDiagnosisProposal(value: unknown): DiagnosisProposal {
  const schema = "DiagnosisProposal";
  const proposal = record(schema, value);
  exactKeys(schema, proposal, [
    "schemaVersion",
    "diagnosis",
    "confidence",
    "evidenceIds",
    "requestedEvidence",
  ]);
  if (proposal.schemaVersion !== "1.0") fail(schema, "unsupported version");
  stringValue(schema, proposal.diagnosis, false, 16 * 1024);
  if (
    typeof proposal.confidence !== "number" ||
    !Number.isFinite(proposal.confidence) ||
    proposal.confidence < 0 ||
    proposal.confidence > 1
  ) {
    fail(schema, "confidence must be between zero and one");
  }
  if (
    stringArray(schema, proposal.evidenceIds, 1).some(
      (id) => !EVIDENCE_ID.test(id),
    )
  )
    fail(schema, "invalid evidence id");
  stringArray(schema, proposal.requestedEvidence);
  return cloned(proposal) as unknown as DiagnosisProposal;
}

function parsePlanStep(value: unknown): PlanStep {
  const schema = "ValidatedPlan.step";
  const step = record(schema, value);
  exactKeys(schema, step, [
    "action",
    "args",
    "preconditions",
    "backup",
    "validation",
    "rollback",
  ]);
  if (!ACTION_ID.test(stringValue(schema, step.action)))
    fail(schema, "invalid action id");
  if (!jsonValue(step.args) || Array.isArray(step.args) || step.args === null)
    fail(schema, "args must be a JSON object");
  if (JSON.stringify(step.args).length > MAX_TEXT_LENGTH)
    fail(schema, "args exceed the safe limit");
  stringArray(schema, step.preconditions);
  if (!["not-required", "required", "inherited"].includes(String(step.backup)))
    fail(schema, "invalid backup policy");
  stringValue(schema, step.validation);
  if (step.rollback !== null) stringValue(schema, step.rollback);
  return cloned(step) as unknown as PlanStep;
}

export function parseValidatedPlan(value: unknown): ValidatedPlan {
  const schema = "ValidatedPlan";
  const plan = record(schema, value);
  exactKeys(schema, plan, [
    "schemaVersion",
    "planId",
    "targetFingerprint",
    "diagnosis",
    "evidenceIds",
    "risk",
    "steps",
  ]);
  if (plan.schemaVersion !== "1.0") fail(schema, "unsupported version");
  if (!PLAN_ID.test(stringValue(schema, plan.planId, false, 128)))
    fail(schema, "invalid plan id");
  if (!FINGERPRINT.test(stringValue(schema, plan.targetFingerprint)))
    fail(schema, "invalid target fingerprint");
  stringValue(schema, plan.diagnosis, false, 16 * 1024);
  if (
    stringArray(schema, plan.evidenceIds, 1).some((id) => !EVIDENCE_ID.test(id))
  )
    fail(schema, "invalid evidence id");
  if (!["R0", "R1", "R2", "R3", "R4"].includes(String(plan.risk)))
    fail(schema, "invalid risk");
  if (
    !Array.isArray(plan.steps) ||
    plan.steps.length === 0 ||
    plan.steps.length > 64
  )
    fail(schema, "at least one step is required");
  plan.steps.forEach(parsePlanStep);
  return cloned(plan) as unknown as ValidatedPlan;
}

export function parseApproval(value: unknown): Approval {
  const schema = "Approval";
  const approval = record(schema, value);
  exactKeys(
    schema,
    approval,
    [
      "schemaVersion",
      "approvalId",
      "planId",
      "targetFingerprint",
      "approvedAt",
      "approvedBy",
    ],
    ["typedConfirmation"],
  );
  if (approval.schemaVersion !== "1.0") fail(schema, "unsupported version");
  if (!APPROVAL_ID.test(stringValue(schema, approval.approvalId, false, 128)))
    fail(schema, "invalid approval id");
  if (!PLAN_ID.test(stringValue(schema, approval.planId, false, 128)))
    fail(schema, "invalid plan id");
  if (!FINGERPRINT.test(stringValue(schema, approval.targetFingerprint)))
    fail(schema, "invalid target fingerprint");
  dateTime(schema, approval.approvedAt);
  stringValue(schema, approval.approvedBy);
  if (approval.typedConfirmation !== undefined)
    stringValue(schema, approval.typedConfirmation);
  return cloned(approval) as unknown as Approval;
}

export function parseExecutionEvent(value: unknown): ExecutionEvent {
  const schema = "ExecutionEvent";
  const event = record(schema, value);
  exactKeys(schema, event, [
    "schemaVersion",
    "planId",
    "sequence",
    "status",
    "action",
    "message",
    "capturedAt",
  ]);
  if (event.schemaVersion !== "1.0") fail(schema, "unsupported version");
  if (!PLAN_ID.test(stringValue(schema, event.planId, false, 128)))
    fail(schema, "invalid plan id");
  if (!Number.isSafeInteger(event.sequence) || Number(event.sequence) < 1)
    fail(schema, "invalid sequence");
  if (
    !["started", "succeeded", "failed", "rolled-back"].includes(
      String(event.status),
    )
  )
    fail(schema, "invalid status");
  if (!ACTION_ID.test(stringValue(schema, event.action)))
    fail(schema, "invalid action id");
  stringValue(schema, event.message, true);
  dateTime(schema, event.capturedAt);
  return cloned(event) as unknown as ExecutionEvent;
}

export function parseSessionReport(value: unknown): SessionReport {
  const schema = "SessionReport";
  const report = record(schema, value);
  exactKeys(schema, report, [
    "schemaVersion",
    "sessionId",
    "targetFingerprint",
    "facts",
    "inferences",
    "decisions",
    "events",
    "verification",
    "unresolvedRisks",
  ]);
  if (report.schemaVersion !== "1.0") fail(schema, "unsupported version");
  if (!SESSION_ID.test(stringValue(schema, report.sessionId, false, 128)))
    fail(schema, "invalid session id");
  if (!FINGERPRINT.test(stringValue(schema, report.targetFingerprint)))
    fail(schema, "invalid target fingerprint");
  if (
    !Array.isArray(report.facts) ||
    !Array.isArray(report.inferences) ||
    !Array.isArray(report.decisions) ||
    !Array.isArray(report.events)
  ) {
    fail(schema, "report collections must be arrays");
  }
  if (
    report.facts.length > MAX_COLLECTION_ITEMS ||
    report.inferences.length > MAX_COLLECTION_ITEMS ||
    report.decisions.length > MAX_COLLECTION_ITEMS ||
    report.events.length > 1_024
  ) {
    fail(schema, "report collection limit exceeded");
  }
  report.facts.forEach(parseEvidence);
  report.inferences.forEach(parseDiagnosisProposal);
  report.decisions.forEach(parseApproval);
  report.events.forEach(parseExecutionEvent);
  if (!["not-run", "passed", "failed"].includes(String(report.verification)))
    fail(schema, "invalid verification state");
  stringArray(schema, report.unresolvedRisks);
  return cloned(report) as unknown as SessionReport;
}
