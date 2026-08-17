import { mkdirSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const root = dirname(fileURLToPath(import.meta.url));
const encoder = new TextEncoder();
const maximumBytes = 1024 * 1024;
const hashA = "a".repeat(64);
const hashB = "b".repeat(64);

const baseline = {
  schemaVersion: "1.0",
  sessionId: "S-golden-1",
  targetFingerprint: `sha256:${hashA}`,
  facts: [
    {
      schemaVersion: "1.0",
      id: "E-1",
      collector: "offline.inspector",
      target: "offline-system",
      capturedAt: "2026-08-17T12:34:56Z",
      contentType: "application/json",
      sha256: hashB,
      sensitivity: "system",
      trust: "observed-untrusted",
      summary: "Observed fact",
      blobRef: `sha256:${hashB}`,
    },
  ],
  inferences: [
    {
      schemaVersion: "1.0",
      diagnosis: "Observed configuration needs review",
      confidence: 0.75,
      evidenceIds: ["E-1"],
      requestedEvidence: [],
    },
  ],
  decisions: [
    {
      schemaVersion: "1.0",
      approvalId: "A-1",
      planId: "P-1",
      targetFingerprint: `sha256:${hashA}`,
      approvedAt: "2026-08-17T12:35:00+00:00",
      approvedBy: "technician",
      typedConfirmation: "CONFIRM",
    },
  ],
  events: [
    {
      schemaVersion: "1.0",
      planId: "P-1",
      sequence: 1,
      status: "succeeded",
      action: "system.observe.noop",
      message: "Observation completed",
      capturedAt: "2026-08-17T12:35:01.123Z",
    },
  ],
  verification: "passed",
  unresolvedRisks: ["Physical media has not been qualified"],
};

const cases = [];

function bytes(value) {
  return typeof value === "string" ? encoder.encode(value) : value;
}

function clone() {
  return structuredClone(baseline);
}

function json(mutator = () => {}) {
  const report = clone();
  mutator(report);
  return encoder.encode(JSON.stringify(report));
}

function add(name, valid, contents) {
  const directory = valid ? "valid" : "invalid";
  const file = `${directory}/${name}.raw`;
  mkdirSync(join(root, directory), { recursive: true });
  writeFileSync(join(root, file), bytes(contents));
  cases.push({ name, valid, file });
}

add("baseline", true, json());
add(
  "minimum-confidence-and-empty-allowed-fields",
  true,
  json((report) => {
    report.facts[0].summary = "";
    report.inferences[0].confidence = 0;
    report.events[0].message = "";
    report.unresolvedRisks = [];
    delete report.decisions[0].typedConfirmation;
  }),
);
add(
  "maximum-confidence",
  true,
  json((report) => {
    report.inferences[0].confidence = 1;
  }),
);
add("surrounding-whitespace", true, ` \n\t${JSON.stringify(baseline)}\r\n`);
add(
  "raw-size-at-limit",
  true,
  (() => {
    const document = json();
    return Buffer.concat([
      document,
      Buffer.alloc(maximumBytes - document.length, 0x20),
    ]);
  })(),
);
add(
  "session-id-128-code-points",
  true,
  json((report) => {
    report.sessionId = `S-${"a".repeat(126)}`;
  }),
);
add(
  "evidence-id-128-code-points",
  true,
  json((report) => {
    report.facts[0].id = `E-${"a".repeat(126)}`;
    report.inferences[0].evidenceIds = [report.facts[0].id];
  }),
);
add(
  "unicode-approved-by-256-code-points",
  true,
  json((report) => {
    report.decisions[0].approvedBy = "😀".repeat(256);
  }),
);
add(
  "escaped-unicode-scalar-pair",
  true,
  JSON.stringify(baseline).replace(
    '"approvedBy":"technician"',
    '"approvedBy":"\\ud83d\\ude00"',
  ),
);
add(
  "unicode-typed-confirmation-256-code-points",
  true,
  json((report) => {
    report.decisions[0].typedConfirmation = "é".repeat(256);
  }),
);
add(
  "action-256-code-points",
  true,
  json((report) => {
    report.events[0].action = "a".repeat(256);
  }),
);
add(
  "unicode-message-8192-code-points",
  true,
  json((report) => {
    report.events[0].message = "😀".repeat(8192);
  }),
);
add(
  "unicode-risk-8192-code-points",
  true,
  json((report) => {
    report.unresolvedRisks = ["😀".repeat(8192)];
  }),
);
add(
  "unicode-summary-8192-code-points",
  true,
  json((report) => {
    report.facts[0].summary = "😀".repeat(8192);
  }),
);
add(
  "diagnosis-16384-code-points",
  true,
  json((report) => {
    report.inferences[0].diagnosis = "d".repeat(16_384);
  }),
);
add(
  "safe-integer-maximum",
  true,
  json((report) => {
    report.events[0].sequence = Number.MAX_SAFE_INTEGER;
  }),
);
add(
  "mathematical-integer-number",
  true,
  JSON.stringify(baseline).replace('"sequence":1', '"sequence":1e0'),
);
add(
  "safe-integer-exponent-maximum",
  true,
  JSON.stringify(baseline).replace(
    '"sequence":1',
    '"sequence":9.007199254740991e15',
  ),
);
add(
  "safe-integer-negative-exponent",
  true,
  JSON.stringify(baseline).replace('"sequence":1', '"sequence":10e-1'),
);
add(
  "confidence-one-exponent",
  true,
  JSON.stringify(baseline).replace('"confidence":0.75', '"confidence":10e-1'),
);
add(
  "confidence-small-positive-exponent",
  true,
  JSON.stringify(baseline).replace('"confidence":0.75', '"confidence":1e-400'),
);
add(
  "confidence-negative-zero",
  true,
  JSON.stringify(baseline).replace('"confidence":0.75', '"confidence":-0'),
);
add(
  "confidence-zero-large-exponent",
  true,
  JSON.stringify(baseline).replace(
    '"confidence":0.75',
    `"confidence":0e${"9".repeat(64)}`,
  ),
);
add(
  "confidence-small-large-negative-exponent",
  true,
  JSON.stringify(baseline).replace(
    '"confidence":0.75',
    `"confidence":1e-${"9".repeat(64)}`,
  ),
);
add(
  "lowercase-rfc3339",
  true,
  json((report) => {
    report.facts[0].capturedAt = "2024-02-29t23:59:59z";
  }),
);
add(
  "rfc3339-year-zero",
  true,
  json((report) => {
    report.facts[0].capturedAt = "0000-02-29T00:00:00Z";
  }),
);
add(
  "rfc3339-leap-second",
  true,
  json((report) => {
    report.events[0].capturedAt = "1990-12-31T23:59:60.5Z";
  }),
);
add(
  "rfc3339-leap-second-translated-by-offset",
  true,
  json((report) => {
    report.events[0].capturedAt = "1991-01-01T00:59:60+01:00";
  }),
);
add(
  "rfc3339-leap-second-translated-by-minute-offset",
  true,
  json((report) => {
    report.events[0].capturedAt = "1991-01-01T00:29:60+00:30";
  }),
);
add(
  "rfc3339-rounded-fraction-at-leap-minute",
  true,
  json((report) => {
    report.events[0].capturedAt = "1990-12-31T23:59:59.999999999999999999Z";
  }),
);
add(
  "rfc3339-offset",
  true,
  json((report) => {
    report.decisions[0].approvedAt = "2026-08-17T14:35:00+02:00";
  }),
);
add(
  "facts-at-item-limit",
  true,
  json((report) => {
    report.facts = Array.from({ length: 128 }, (_, index) => ({
      ...report.facts[0],
      id: `E-${index + 1}`,
    }));
  }),
);
add(
  "events-at-item-limit",
  true,
  json((report) => {
    report.events = Array.from({ length: 1024 }, (_, index) => ({
      ...report.events[0],
      sequence: index + 1,
    }));
  }),
);
add(
  "unique-array-at-item-limit",
  true,
  json((report) => {
    report.inferences[0].requestedEvidence = Array.from(
      { length: 128 },
      (_, index) => `request-${index}`,
    );
  }),
);

add(
  "raw-size-over-limit",
  false,
  (() => {
    const document = json();
    return Buffer.concat([
      document,
      Buffer.alloc(maximumBytes + 1 - document.length, 0x20),
    ]);
  })(),
);
add("invalid-utf8", false, new Uint8Array([0x7b, 0x22, 0xff, 0x22, 0x7d]));
add(
  "unpaired-unicode-surrogate",
  false,
  JSON.stringify(baseline).replace(
    '"approvedBy":"technician"',
    '"approvedBy":"\\ud800"',
  ),
);
add("trailing-document", false, `${JSON.stringify(baseline)}{}`);
add("trailing-nul", false, Buffer.concat([json(), Buffer.from([0])]));

const compact = JSON.stringify(baseline);
add(
  "duplicate-top-level",
  false,
  compact.replace(
    '"sessionId":"S-golden-1"',
    '"sessionId":"S-golden-1","sessionId":"S-other"',
  ),
);
add(
  "duplicate-evidence-escaped-key",
  false,
  compact.replace(
    '"summary":"Observed fact"',
    '"summa\\u0072y":"first","summary":"second"',
  ),
);
add(
  "duplicate-inference",
  false,
  compact.replace('"confidence":0.75', '"confidence":0.75,"confidence":0.5'),
);
add(
  "duplicate-approval",
  false,
  compact.replace(
    '"approvedBy":"technician"',
    '"approvedBy":"technician","approvedBy":"other"',
  ),
);
add(
  "duplicate-event",
  false,
  compact.replace(
    '"message":"Observation completed"',
    '"message":"Observation completed","message":"other"',
  ),
);

add(
  "unknown-top-level-field",
  false,
  json((report) => {
    report.command = "forbidden";
  }),
);
add(
  "unknown-evidence-field",
  false,
  json((report) => {
    report.facts[0].path = "/dev/forbidden";
  }),
);
add(
  "unknown-inference-field",
  false,
  json((report) => {
    report.inferences[0].tool = "shell";
  }),
);
add(
  "unknown-approval-field",
  false,
  json((report) => {
    report.decisions[0].secret = "forbidden";
  }),
);
add(
  "unknown-event-field",
  false,
  json((report) => {
    report.events[0].output = "forbidden";
  }),
);
add(
  "missing-evidence-field",
  false,
  json((report) => {
    delete report.facts[0].trust;
  }),
);
add(
  "empty-evidence-collector",
  false,
  json((report) => {
    report.facts[0].collector = "";
  }),
);
add(
  "empty-diagnosis",
  false,
  json((report) => {
    report.inferences[0].diagnosis = "";
  }),
);
add(
  "empty-diagnosis-evidence-ids",
  false,
  json((report) => {
    report.inferences[0].evidenceIds = [];
  }),
);
add(
  "empty-approved-by",
  false,
  json((report) => {
    report.decisions[0].approvedBy = "";
  }),
);
add(
  "empty-typed-confirmation",
  false,
  json((report) => {
    report.decisions[0].typedConfirmation = "";
  }),
);
add(
  "confidence-below-minimum",
  false,
  json((report) => {
    report.inferences[0].confidence = -0.1;
  }),
);
add(
  "confidence-above-maximum",
  false,
  json((report) => {
    report.inferences[0].confidence = 1.1;
  }),
);
add(
  "confidence-rounded-above-maximum",
  false,
  JSON.stringify(baseline).replace(
    '"confidence":0.75',
    '"confidence":1.000000000000000000000000000000000000001',
  ),
);
add(
  "confidence-negative-underflow",
  false,
  JSON.stringify(baseline).replace('"confidence":0.75', '"confidence":-1e-400'),
);
add(
  "invalid-evidence-sensitivity",
  false,
  json((report) => {
    report.facts[0].sensitivity = "secret";
  }),
);
add(
  "invalid-evidence-trust",
  false,
  json((report) => {
    report.facts[0].trust = "trusted";
  }),
);
add(
  "invalid-event-status",
  false,
  json((report) => {
    report.events[0].status = "pending";
  }),
);
add(
  "invalid-verification-state",
  false,
  json((report) => {
    report.verification = "unknown";
  }),
);
add(
  "array-evidence-sensitivity",
  false,
  json((report) => {
    report.facts[0].sensitivity = ["system"];
  }),
);
add(
  "array-event-status",
  false,
  json((report) => {
    report.events[0].status = ["succeeded"];
  }),
);
add(
  "array-verification-state",
  false,
  json((report) => {
    report.verification = ["passed"];
  }),
);

add(
  "session-id-129-code-points",
  false,
  json((report) => {
    report.sessionId = `S-${"a".repeat(127)}`;
  }),
);
add(
  "evidence-id-129-code-points",
  false,
  json((report) => {
    report.facts[0].id = `E-${"a".repeat(127)}`;
  }),
);
add(
  "evidence-reference-id-129-code-points",
  false,
  json((report) => {
    report.inferences[0].evidenceIds = [`E-${"a".repeat(127)}`];
  }),
);
add(
  "collector-257-code-points",
  false,
  json((report) => {
    report.facts[0].collector = "c".repeat(257);
  }),
);
add(
  "target-513-code-points",
  false,
  json((report) => {
    report.facts[0].target = "t".repeat(513);
  }),
);
add(
  "content-type-257-code-points",
  false,
  json((report) => {
    report.facts[0].contentType = "c".repeat(257);
  }),
);
add(
  "summary-8193-code-points",
  false,
  json((report) => {
    report.facts[0].summary = "😀".repeat(8193);
  }),
);
add(
  "diagnosis-16385-code-points",
  false,
  json((report) => {
    report.inferences[0].diagnosis = "d".repeat(16_385);
  }),
);
add(
  "approval-id-129-code-points",
  false,
  json((report) => {
    report.decisions[0].approvalId = `A-${"a".repeat(127)}`;
  }),
);
add(
  "plan-id-129-code-points",
  false,
  json((report) => {
    report.events[0].planId = `P-${"a".repeat(127)}`;
  }),
);
add(
  "unicode-approved-by-257-code-points",
  false,
  json((report) => {
    report.decisions[0].approvedBy = "😀".repeat(257);
  }),
);
add(
  "unicode-typed-confirmation-257-code-points",
  false,
  json((report) => {
    report.decisions[0].typedConfirmation = "é".repeat(257);
  }),
);
add(
  "action-257-code-points",
  false,
  json((report) => {
    report.events[0].action = "a".repeat(257);
  }),
);
add(
  "unicode-message-8193-code-points",
  false,
  json((report) => {
    report.events[0].message = "😀".repeat(8193);
  }),
);
add(
  "unicode-risk-8193-code-points",
  false,
  json((report) => {
    report.unresolvedRisks = ["😀".repeat(8193)];
  }),
);

add(
  "duplicate-evidence-ids",
  false,
  json((report) => {
    report.inferences[0].evidenceIds = ["E-1", "E-1"];
  }),
);
add(
  "duplicate-requested-evidence",
  false,
  json((report) => {
    report.inferences[0].requestedEvidence = ["same", "same"];
  }),
);
add(
  "duplicate-unresolved-risks",
  false,
  json((report) => {
    report.unresolvedRisks = ["same", "same"];
  }),
);
add(
  "requested-evidence-over-item-limit",
  false,
  json((report) => {
    report.inferences[0].requestedEvidence = Array.from(
      { length: 129 },
      (_, index) => `request-${index}`,
    );
  }),
);
add(
  "facts-over-item-limit",
  false,
  json((report) => {
    report.facts = Array.from({ length: 129 }, (_, index) => ({
      ...report.facts[0],
      id: `E-${index + 1}`,
    }));
  }),
);
add(
  "events-over-item-limit",
  false,
  json((report) => {
    report.events = Array.from({ length: 1025 }, (_, index) => ({
      ...report.events[0],
      sequence: index + 1,
    }));
  }),
);

add(
  "unsafe-integer",
  false,
  json((report) => {
    report.events[0].sequence = Number.MAX_SAFE_INTEGER + 1;
  }),
);
add(
  "unsafe-integer-exponent",
  false,
  JSON.stringify(baseline).replace(
    '"sequence":1',
    '"sequence":9.007199254740992e15',
  ),
);
add(
  "fractional-negative-exponent",
  false,
  JSON.stringify(baseline).replace('"sequence":1', '"sequence":1e-1'),
);
add(
  "fractional-sequence",
  false,
  json((report) => {
    report.events[0].sequence = 1.5;
  }),
);
add(
  "rounded-fractional-sequence-below-one",
  false,
  JSON.stringify(baseline).replace(
    '"sequence":1',
    '"sequence":0.999999999999999999999999999999999999999',
  ),
);
add(
  "rounded-fractional-sequence-above-one",
  false,
  JSON.stringify(baseline).replace(
    '"sequence":1',
    '"sequence":1.000000000000000000000000000000000000001',
  ),
);
add(
  "rounded-fractional-sequence-safe-maximum",
  false,
  JSON.stringify(baseline).replace(
    '"sequence":1',
    '"sequence":9007199254740991.49999999999999999999999999',
  ),
);
add(
  "rounded-fractional-sequence-escaped-path",
  false,
  JSON.stringify(baseline)
    .replace('"events":', '"\\u0065vents":')
    .replace(
      '"sequence":1',
      '"seque\\u006ece":0.999999999999999999999999999999999999999',
    ),
);
add(
  "rounded-confidence-escaped-path",
  false,
  JSON.stringify(baseline)
    .replace('"inferences":', '"\\u0069nferences":')
    .replace(
      '"confidence":0.75',
      '"confid\\u0065nce":1.000000000000000000000000000000000000001',
    ),
);
add(
  "zero-sequence",
  false,
  json((report) => {
    report.events[0].sequence = 0;
  }),
);

add(
  "invalid-calendar-date",
  false,
  json((report) => {
    report.facts[0].capturedAt = "2023-02-29T12:34:56Z";
  }),
);
add(
  "invalid-rfc3339-space-separator",
  false,
  json((report) => {
    report.facts[0].capturedAt = "2026-08-17 12:34:56Z";
  }),
);
add(
  "invalid-rfc3339-offset-without-colon",
  false,
  json((report) => {
    report.decisions[0].approvedAt = "2026-08-17T12:34:56+0000";
  }),
);
add(
  "invalid-rfc3339-timezone",
  false,
  json((report) => {
    report.events[0].capturedAt = "2026-08-17T12:34:56+24:00";
  }),
);
add(
  "invalid-rfc3339-translated-hour-evidence",
  false,
  json((report) => {
    report.facts[0].capturedAt = "2024-01-01T24:59:00+01:00";
  }),
);
add(
  "invalid-rfc3339-translated-minute-approval",
  false,
  json((report) => {
    report.decisions[0].approvedAt = "2024-01-01T23:60:60+00:01";
  }),
);
add(
  "invalid-rfc3339-translated-hour-event",
  false,
  json((report) => {
    report.events[0].capturedAt = "2024-01-01T46:59:00+23:00";
  }),
);
add(
  "invalid-rfc3339-nonascii-seconds",
  false,
  json((report) => {
    report.events[0].capturedAt = "2026-08-17T12:34:😀Z";
  }),
);
add(
  "invalid-rfc3339-leap-second",
  false,
  json((report) => {
    report.events[0].capturedAt = "2026-08-17T12:00:60Z";
  }),
);
add(
  "invalid-rfc3339-offset-leap-second",
  false,
  json((report) => {
    report.events[0].capturedAt = "1991-01-01T01:00:60+01:00";
  }),
);
add(
  "invalid-rfc3339-rounded-fraction-away-from-leap-minute",
  false,
  json((report) => {
    report.events[0].capturedAt = "2026-08-17T12:00:59.999999999999999999Z";
  }),
);
add(
  "invalid-rfc3339-rounded-fraction-over-leap-second",
  false,
  json((report) => {
    report.events[0].capturedAt = "1990-12-31T23:59:60.999999999999999999Z";
  }),
);

add(
  "uppercase-evidence-hash",
  false,
  json((report) => {
    report.facts[0].sha256 = hashB.toUpperCase();
    report.facts[0].blobRef = `sha256:${hashB.toUpperCase()}`;
  }),
);
add(
  "short-evidence-hash",
  false,
  json((report) => {
    report.facts[0].sha256 = "b".repeat(63);
    report.facts[0].blobRef = `sha256:${"b".repeat(63)}`;
  }),
);
add(
  "blob-reference-hash-mismatch",
  false,
  json((report) => {
    report.facts[0].blobRef = `sha256:${hashA}`;
  }),
);
add(
  "uppercase-target-fingerprint",
  false,
  json((report) => {
    report.targetFingerprint = `sha256:${hashA.toUpperCase()}`;
  }),
);
add(
  "malformed-session-id",
  false,
  json((report) => {
    report.sessionId = "S-invalid_value";
  }),
);
add(
  "malformed-action-id",
  false,
  json((report) => {
    report.events[0].action = "System Observe";
  }),
);

writeFileSync(
  join(root, "manifest.json"),
  `${JSON.stringify({ schemaVersion: 1, cases }, null, 2)}\n`,
);
