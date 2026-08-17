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
  /^(\d{4})-(\d{2})-(\d{2})[Tt](\d{2}):(\d{2}):(\d{2}(?:\.\d+)?)([Zz]|([+-])(\d{2}):(\d{2}))$/;
const MAX_COLLECTION_ITEMS = 128;
const MAX_TEXT_LENGTH = 64 * 1024;
export const MAX_SESSION_REPORT_BYTES = 1024 * 1024;

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
  maximum = Number.POSITIVE_INFINITY,
): string {
  if (
    typeof value !== "string" ||
    (!allowEmpty && value.length === 0) ||
    codePointLength(value) > maximum ||
    !hasOnlyUnicodeScalarValues(value)
  ) {
    return fail(schema, "expected a non-empty string");
  }
  return value;
}

function codePointLength(value: string): number {
  return [...value].length;
}

function hasOnlyUnicodeScalarValues(value: string): boolean {
  for (let index = 0; index < value.length; index += 1) {
    const code = value.charCodeAt(index);
    if (code < 0xd800 || code > 0xdfff) continue;
    if (
      code <= 0xdbff &&
      index + 1 < value.length &&
      value.charCodeAt(index + 1) >= 0xdc00 &&
      value.charCodeAt(index + 1) <= 0xdfff
    ) {
      index += 1;
      continue;
    }
    return false;
  }
  return true;
}

function stringArray(
  schema: string,
  value: unknown,
  minimum = 0,
  maximumStringLength = 256,
): string[] {
  if (
    !Array.isArray(value) ||
    value.length < minimum ||
    value.length > MAX_COLLECTION_ITEMS ||
    value.some(
      (item) =>
        typeof item !== "string" ||
        codePointLength(item) > maximumStringLength ||
        !hasOnlyUnicodeScalarValues(item),
    )
  ) {
    return fail(schema, "expected a string array");
  }
  if (new Set(value).size !== value.length)
    fail(schema, "array values must be unique");
  return [...value];
}

function dateTime(schema: string, value: unknown): string {
  const result = stringValue(schema, value);
  const match = DATE_TIME.exec(result);
  if (match === null) fail(schema, "invalid date-time");
  const year = Number(match[1]);
  const month = Number(match[2]);
  const day = Number(match[3]);
  const hour = Number(match[4]);
  const minute = Number(match[5]);
  const second = Number(match[6]);
  const timezoneSign = match[8] === "-" ? -1 : 1;
  const timezoneHour = Number(match[9] ?? 0);
  const timezoneMinute = Number(match[10] ?? 0);
  const days = [
    0,
    31,
    isLeapYear(year) ? 29 : 28,
    31,
    30,
    31,
    30,
    31,
    31,
    30,
    31,
    30,
    31,
  ];
  const maximumDay = days[month] ?? 0;
  if (
    month < 1 ||
    month > 12 ||
    day < 1 ||
    day > maximumDay ||
    hour > 23 ||
    minute > 59 ||
    timezoneHour > 23 ||
    timezoneMinute > 59
  ) {
    fail(schema, "invalid date-time");
  }
  if (second < 60) return result;
  if (second >= 61) fail(schema, "invalid date-time");
  const utcMinute = minute - timezoneMinute * timezoneSign;
  const utcHour = hour - timezoneHour * timezoneSign - (utcMinute < 0 ? 1 : 0);
  if (
    (utcHour !== 23 && utcHour !== -1) ||
    (utcMinute !== 59 && utcMinute !== -1)
  ) {
    fail(schema, "invalid date-time");
  }
  return result;
}

function isLeapYear(year: number): boolean {
  return year % 4 === 0 && (year % 100 !== 0 || year % 400 === 0);
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
  if (!EVIDENCE_ID.test(stringValue(schema, item.id, false, 128)))
    fail(schema, "invalid evidence id");
  stringValue(schema, item.collector, false, 256);
  stringValue(schema, item.target, false, 512);
  dateTime(schema, item.capturedAt);
  stringValue(schema, item.contentType, false, 256);
  const hash = stringValue(schema, item.sha256);
  if (!HASH.test(hash) || item.blobRef !== `sha256:${hash}`)
    fail(schema, "invalid evidence hash");
  if (
    typeof item.sensitivity !== "string" ||
    !["public", "system", "sensitive"].includes(item.sensitivity)
  )
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
    stringArray(schema, proposal.evidenceIds, 1, 128).some(
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
  if (!ACTION_ID.test(stringValue(schema, step.action, false, 256)))
    fail(schema, "invalid action id");
  if (!jsonValue(step.args) || Array.isArray(step.args) || step.args === null)
    fail(schema, "args must be a JSON object");
  if (JSON.stringify(step.args).length > MAX_TEXT_LENGTH)
    fail(schema, "args exceed the safe limit");
  stringArray(schema, step.preconditions);
  if (
    typeof step.backup !== "string" ||
    !["not-required", "required", "inherited"].includes(step.backup)
  )
    fail(schema, "invalid backup policy");
  stringValue(schema, step.validation, false, 256);
  if (step.rollback !== null) stringValue(schema, step.rollback, false, 256);
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
    stringArray(schema, plan.evidenceIds, 1, 128).some(
      (id) => !EVIDENCE_ID.test(id),
    )
  )
    fail(schema, "invalid evidence id");
  if (
    typeof plan.risk !== "string" ||
    !["R0", "R1", "R2", "R3", "R4"].includes(plan.risk)
  )
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
  stringValue(schema, approval.approvedBy, false, 256);
  if (approval.typedConfirmation !== undefined)
    stringValue(schema, approval.typedConfirmation, false, 256);
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
    typeof event.status !== "string" ||
    !["started", "succeeded", "failed", "rolled-back"].includes(event.status)
  )
    fail(schema, "invalid status");
  if (!ACTION_ID.test(stringValue(schema, event.action, false, 256)))
    fail(schema, "invalid action id");
  stringValue(schema, event.message, true, 8 * 1024);
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
  if (
    typeof report.verification !== "string" ||
    !["not-run", "passed", "failed"].includes(report.verification)
  )
    fail(schema, "invalid verification state");
  stringArray(schema, report.unresolvedRisks, 0, 8 * 1024);
  return cloned(report) as unknown as SessionReport;
}

export function sessionReportSemanticBindingsAreValid(value: unknown): boolean {
  if (typeof value !== "object" || value === null || Array.isArray(value))
    return false;
  const facts = (value as RecordValue).facts;
  return (
    Array.isArray(facts) &&
    facts.every((fact) => {
      if (typeof fact !== "object" || fact === null || Array.isArray(fact))
        return false;
      const item = fact as RecordValue;
      return (
        typeof item.sha256 === "string" &&
        item.blobRef === `sha256:${item.sha256}`
      );
    })
  );
}

export function decodeSessionReportJson(input: Uint8Array): unknown {
  if (
    !(input instanceof Uint8Array) ||
    input.byteLength > MAX_SESSION_REPORT_BYTES
  )
    fail("SessionReport", "report JSON exceeds the byte limit");
  let text: string;
  try {
    text = new TextDecoder("utf-8", { fatal: true, ignoreBOM: true }).decode(
      input,
    );
  } catch {
    return fail("SessionReport", "invalid UTF-8 JSON document");
  }
  if (text.includes("\0")) fail("SessionReport", "invalid JSON document");
  assertSessionReportJsonLexicalSafety(text);
  try {
    return JSON.parse(text) as unknown;
  } catch {
    return fail("SessionReport", "invalid JSON document");
  }
}

export function parseSessionReportJson(input: Uint8Array): SessionReport {
  return parseSessionReport(decodeSessionReportJson(input));
}

type ReportJsonContext =
  | "root"
  | "events"
  | "event"
  | "sequence"
  | "inferences"
  | "inference"
  | "confidence"
  | "other";

interface ExactDecimal {
  negative: boolean;
  coefficient: string;
  scale: number;
}

const MAX_SAFE_INTEGER_DECIMAL = "9007199254740991";
const EXPONENT_MAGNITUDE_CAP = MAX_SESSION_REPORT_BYTES + 1;

function exactDecimal(token: string): ExactDecimal {
  const match =
    /^(-?)(0|[1-9][0-9]*)(?:\.([0-9]+))?(?:[eE]([+-]?)([0-9]+))?$/.exec(token);
  if (match === null) return fail("SessionReport", "invalid JSON number");
  const fraction = match[3] ?? "";
  const coefficient = `${match[2]}${fraction}`.replace(/^0+/, "");
  let exponent = 0;
  for (const character of match[5] ?? "") {
    const digit = character.charCodeAt(0) - 0x30;
    if (exponent > Math.floor((EXPONENT_MAGNITUDE_CAP - digit) / 10)) {
      exponent = EXPONENT_MAGNITUDE_CAP;
      break;
    }
    exponent = exponent * 10 + digit;
  }
  if (match[4] === "-") exponent = -exponent;
  return {
    negative: match[1] === "-",
    coefficient,
    scale: exponent - fraction.length,
  };
}

function exactPositiveSafeInteger(token: string): boolean {
  const { negative, coefficient, scale } = exactDecimal(token);
  if (negative || coefficient.length === 0) return false;

  let integer: string;
  if (scale >= 0) {
    const length = coefficient.length + scale;
    if (length > MAX_SAFE_INTEGER_DECIMAL.length) return false;
    integer = `${coefficient}${"0".repeat(scale)}`;
  } else {
    const decimalPlaces = -scale;
    if (decimalPlaces >= coefficient.length) return false;
    const integerLength = coefficient.length - decimalPlaces;
    for (let index = integerLength; index < coefficient.length; index += 1)
      if (coefficient[index] !== "0") return false;
    integer = coefficient.slice(0, integerLength);
  }

  return (
    integer.length < MAX_SAFE_INTEGER_DECIMAL.length ||
    (integer.length === MAX_SAFE_INTEGER_DECIMAL.length &&
      integer <= MAX_SAFE_INTEGER_DECIMAL)
  );
}

function exactConfidence(token: string): boolean {
  const { negative, coefficient, scale } = exactDecimal(token);
  if (coefficient.length === 0) return true;
  if (negative) return false;
  const integerDigits = coefficient.length + scale;
  if (integerDigits <= 0) return true;
  if (integerDigits > 1 || coefficient[0] !== "1") return false;
  for (let index = 1; index < coefficient.length; index += 1)
    if (coefficient[index] !== "0") return false;
  return true;
}

function objectValueContext(
  context: ReportJsonContext,
  key: string,
): ReportJsonContext {
  if (context === "root" && key === "events") return "events";
  if (context === "root" && key === "inferences") return "inferences";
  if (context === "event" && key === "sequence") return "sequence";
  if (context === "inference" && key === "confidence") return "confidence";
  return "other";
}

function arrayItemContext(context: ReportJsonContext): ReportJsonContext {
  if (context === "events") return "event";
  if (context === "inferences") return "inference";
  return "other";
}

function assertSessionReportJsonLexicalSafety(text: string): void {
  let offset = 0;

  function skipWhitespace(): void {
    while (
      text[offset] === " " ||
      text[offset] === "\t" ||
      text[offset] === "\r" ||
      text[offset] === "\n"
    ) {
      offset += 1;
    }
  }

  function parseString(): string {
    const start = offset;
    if (text[offset] !== '"') fail("SessionReport", "invalid JSON document");
    offset += 1;
    while (offset < text.length) {
      const character = text[offset];
      if (character === '"') {
        offset += 1;
        try {
          const value = JSON.parse(text.slice(start, offset)) as unknown;
          if (typeof value !== "string" || !hasOnlyUnicodeScalarValues(value))
            return fail("SessionReport", "invalid JSON string");
          return value;
        } catch {
          return fail("SessionReport", "invalid JSON string");
        }
      }
      if (character === "\\") {
        offset += 2;
      } else {
        offset += 1;
      }
    }
    return fail("SessionReport", "invalid JSON document");
  }

  function parseValue(depth: number, context: ReportJsonContext): void {
    if (depth > 64) fail("SessionReport", "JSON nesting limit exceeded");
    skipWhitespace();
    const character = text[offset];
    if (character === "{") {
      parseObject(depth + 1, context);
      return;
    }
    if (character === "[") {
      parseArray(depth + 1, context);
      return;
    }
    if (character === '"') {
      parseString();
      return;
    }
    const remaining = text.slice(offset);
    const numberToken =
      /^-?(?:0|[1-9][0-9]*)(?:\.[0-9]+)?(?:[eE][+-]?[0-9]+)?/.exec(
        remaining,
      )?.[0];
    if (numberToken !== undefined) {
      if (
        (context === "sequence" && !exactPositiveSafeInteger(numberToken)) ||
        (context === "confidence" && !exactConfidence(numberToken))
      ) {
        fail("SessionReport", "invalid exact JSON number");
      }
      offset += numberToken.length;
      return;
    }
    const literal = /^(?:true|false|null)/.exec(remaining)?.[0];
    if (literal === undefined) fail("SessionReport", "invalid JSON document");
    offset += literal.length;
  }

  function parseObject(depth: number, context: ReportJsonContext): void {
    offset += 1;
    skipWhitespace();
    const keys = new Set<string>();
    if (text[offset] === "}") {
      offset += 1;
      return;
    }
    while (offset < text.length) {
      skipWhitespace();
      const key = parseString();
      if (keys.has(key)) fail("SessionReport", "duplicate JSON object key");
      keys.add(key);
      skipWhitespace();
      if (text[offset] !== ":") fail("SessionReport", "invalid JSON document");
      offset += 1;
      parseValue(depth, objectValueContext(context, key));
      skipWhitespace();
      if (text[offset] === "}") {
        offset += 1;
        return;
      }
      if (text[offset] !== ",") fail("SessionReport", "invalid JSON document");
      offset += 1;
    }
    fail("SessionReport", "invalid JSON document");
  }

  function parseArray(depth: number, context: ReportJsonContext): void {
    offset += 1;
    skipWhitespace();
    if (text[offset] === "]") {
      offset += 1;
      return;
    }
    while (offset < text.length) {
      parseValue(depth, arrayItemContext(context));
      skipWhitespace();
      if (text[offset] === "]") {
        offset += 1;
        return;
      }
      if (text[offset] !== ",") fail("SessionReport", "invalid JSON document");
      offset += 1;
    }
    fail("SessionReport", "invalid JSON document");
  }

  parseValue(0, "root");
  skipWhitespace();
  if (offset !== text.length) fail("SessionReport", "trailing JSON content");
}
