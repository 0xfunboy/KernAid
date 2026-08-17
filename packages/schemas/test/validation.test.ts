import assert from "node:assert/strict";
import { readFileSync, readdirSync } from "node:fs";
import test from "node:test";
import Ajv2020 from "ajv/dist/2020.js";
import addFormats from "ajv-formats";
import {
  SchemaValidationError,
  parseDiagnosisProposal,
  parseSessionReport,
  parseValidatedPlan,
} from "../src/index.js";

const schemaFiles = [
  "approval.schema.json",
  "diagnosis-proposal.schema.json",
  "evidence.schema.json",
  "execution-event.schema.json",
  "rescue-openai-request.schema.json",
  "rescue-openai-response.schema.json",
  "rescue-vault-request.schema.json",
  "rescue-vault-response.schema.json",
  "session-report.schema.json",
  "validated-plan.schema.json",
];

test("published schema basenames match the expected release set", () => {
  const publishedSchemaFiles = readdirSync(new URL("../", import.meta.url))
    .filter((file) => file.endsWith(".schema.json"))
    .sort();
  assert.deepEqual(publishedSchemaFiles, schemaFiles);
});

test("all published JSON schemas compile together", () => {
  const ajv = new Ajv2020({ allErrors: true, strict: true });
  addFormats(ajv);
  for (const file of schemaFiles) {
    const contents = readFileSync(
      new URL(`../${file}`, import.meta.url),
      "utf8",
    );
    ajv.addSchema(JSON.parse(contents));
  }
  for (const file of schemaFiles)
    assert.ok(
      ajv.getSchema(
        `https://schemas.kernaid.dev/v1/${file.replace(".schema", "")}`,
      ),
    );
});

test("Rescue OpenAI golden frames agree with the closed published schemas", () => {
  interface GoldenManifest {
    schemaVersion: number;
    validCases: Array<{ name: string; request: string; response: string }>;
  }

  const ajv = new Ajv2020({ allErrors: true, strict: true });
  const requestSchema = JSON.parse(
    readFileSync(
      new URL("../rescue-openai-request.schema.json", import.meta.url),
      "utf8",
    ),
  );
  const responseSchema = JSON.parse(
    readFileSync(
      new URL("../rescue-openai-response.schema.json", import.meta.url),
      "utf8",
    ),
  );
  const validateRequest = ajv.compile(requestSchema);
  const validateResponse = ajv.compile(responseSchema);
  const root = new URL("../fixtures/rescue-openai/", import.meta.url);
  const manifest = JSON.parse(
    readFileSync(new URL("manifest.json", root), "utf8"),
  ) as GoldenManifest;
  assert.equal(manifest.schemaVersion, 1);
  assert.equal(manifest.validCases.length, 8);
  for (const golden of manifest.validCases) {
    assert.equal(
      validateRequest(
        JSON.parse(readFileSync(new URL(golden.request, root), "utf8")),
      ),
      true,
      `${golden.name} request`,
    );
    assert.equal(
      validateResponse(
        JSON.parse(readFileSync(new URL(golden.response, root), "utf8")),
      ),
      true,
      `${golden.name} response`,
    );
  }

  const diagnose = JSON.parse(
    readFileSync(
      new URL("valid/linux-malformed-fstab.request.raw", root),
      "utf8",
    ),
  ) as Record<string, unknown> & {
    payload: Record<string, unknown> & { evidence: unknown[] };
  };
  for (const field of [
    "url",
    "model",
    "tools",
    "messages",
    "command",
    "path",
    "device",
    "raw",
    "generic",
    "args",
  ]) {
    const injected = structuredClone(diagnose);
    injected.payload[field] = "forbidden";
    assert.equal(validateRequest(injected), false, field);
  }
  const duplicateEvidence = structuredClone(diagnose);
  duplicateEvidence.payload.evidence.push(
    structuredClone(duplicateEvidence.payload.evidence[0]),
  );
  assert.equal(validateRequest(duplicateEvidence), false);

  const diagnoseResponse = JSON.parse(
    readFileSync(
      new URL("valid/linux-malformed-fstab.response.raw", root),
      "utf8",
    ),
  ) as {
    payload: { proposal: { evidenceIds: string[] } };
  };
  diagnoseResponse.payload.proposal.evidenceIds.push("E-FOREIGN");
  assert.equal(validateResponse(diagnoseResponse), false);

  const status = JSON.parse(
    readFileSync(new URL("valid/status.response.raw", root), "utf8"),
  ) as Record<string, unknown> & {
    payload: Record<string, unknown>;
  };
  status.payload.vault = "locked";
  assert.equal(validateResponse(status), false);
  status.payload.credential = "unavailable";
  assert.equal(validateResponse(status), true);
  status.payload.message = "upstream text";
  assert.equal(validateResponse(status), false);
});

test("Rescue vault schemas keep path and secret data out of IPC JSON", () => {
  const ajv = new Ajv2020({ allErrors: true, strict: true });
  const requestSchema = JSON.parse(
    readFileSync(
      new URL("../rescue-vault-request.schema.json", import.meta.url),
      "utf8",
    ),
  );
  const responseSchema = JSON.parse(
    readFileSync(
      new URL("../rescue-vault-response.schema.json", import.meta.url),
      "utf8",
    ),
  );
  const validateRequest = ajv.compile(requestSchema);
  const validateResponse = ajv.compile(responseSchema);
  const base = {
    apiVersion: "kernaid.dev/rescue-vault/v1alpha1",
    requestId: "R-12345678-1234-1234-1234-123456789abc",
    expectedStateVersion: 7,
    operation: "vault.unlock",
    payload: {
      input: { type: "passphrase-pipe", size: 12 },
    },
  };
  assert.equal(validateRequest(base), true);
  assert.equal(
    validateRequest({
      ...base,
      payload: { input: { type: "passphrase-pipe", size: 11 } },
    }),
    false,
  );
  assert.equal(
    validateRequest({
      ...base,
      expectedStateVersion: Number.MAX_SAFE_INTEGER + 1,
    }),
    false,
  );
  assert.equal(
    validateRequest({
      ...base,
      payload: { ...base.payload, path: "/dev/sda3" },
    }),
    false,
  );
  assert.equal(
    validateRequest({
      ...base,
      operation: "audit.append",
      payload: {
        sequence: 1_000_001,
        event: "agent-session-end",
        outcome: "succeeded",
      },
    }),
    false,
  );
  const reportPersist = {
    ...base,
    operation: "report.persist",
    payload: {
      reportId: "RP-12345678-1234-1234-1234-123456789abc",
      payloadSha256: "a".repeat(64),
      input: { type: "session-report-json-pipe", size: 1024 * 1024 },
    },
  };
  assert.equal(validateRequest(reportPersist), true);
  assert.equal(
    validateRequest({
      ...reportPersist,
      payload: {
        ...reportPersist.payload,
        input: {
          type: "session-report-json-pipe",
          size: 1024 * 1024 + 1,
        },
      },
    }),
    false,
  );
  assert.equal(
    validateRequest({
      ...reportPersist,
      payload: {
        ...reportPersist.payload,
        input: { type: "signed-report-envelope-pipe", size: 512 },
      },
    }),
    false,
  );
  assert.equal(
    validateRequest({
      ...base,
      payload: { ...base.payload, passphrase: "forbidden" },
    }),
    false,
  );
  assert.equal(
    validateRequest({
      ...base,
      operation: "provider.openai.configure",
      payload: { input: { type: "openai-api-key-pipe", size: 513 } },
    }),
    false,
  );
  assert.equal(
    validateRequest({
      ...base,
      operation: "audit.append",
      payload: {
        sequence: 1,
        event: "vault-unlock",
        outcome: "succeeded",
      },
    }),
    false,
  );
  assert.equal(
    validateResponse({
      apiVersion: base.apiVersion,
      requestId: base.requestId,
      stateVersion: 8,
      operation: "vault.unlock",
      outcome: "error",
      error: "BAD_PASSPHRASE",
    }),
    true,
  );
  assert.equal(
    validateResponse({
      apiVersion: base.apiVersion,
      requestId: base.requestId,
      stateVersion: 8,
      operation: "vault.unlock",
      outcome: "error",
      error: "BAD_PASSPHRASE",
      message: "device /dev/sda3",
    }),
    false,
  );
  const unlockedStatus = {
    apiVersion: base.apiVersion,
    requestId: base.requestId,
    stateVersion: 8,
    operation: "vault.status",
    outcome: "ok",
    payload: {
      vaultState: "unlocked",
      deviceId: "KA-0123456789abcdef01234567",
    },
  };
  assert.equal(validateResponse(unlockedStatus), true);
  assert.equal(
    validateResponse({
      ...unlockedStatus,
      payload: { vaultState: "unlocked" },
    }),
    false,
  );
  assert.equal(
    validateResponse({
      ...unlockedStatus,
      payload: {
        vaultState: "faulted-reboot-required",
        deviceId: "KA-0123456789abcdef01234567",
      },
    }),
    false,
  );
  assert.equal(
    validateResponse({
      ...unlockedStatus,
      payload: { vaultState: "faulted-reboot-required" },
    }),
    true,
  );
  const reportGet = {
    apiVersion: base.apiVersion,
    requestId: base.requestId,
    stateVersion: 8,
    operation: "report.get",
    outcome: "ok",
    payload: {
      report: {
        reportId: "RP-12345678-1234-1234-1234-123456789abc",
        envelopeSize: 1536 * 1024,
        envelopeSha256: "b".repeat(64),
      },
      output: {
        type: "signed-report-envelope-pipe",
        size: 1536 * 1024,
      },
    },
  };
  assert.equal(validateResponse(reportGet), true);
  assert.equal(
    validateResponse({
      ...reportGet,
      payload: {
        ...reportGet.payload,
        output: { type: "session-report-json-pipe", size: 512 },
      },
    }),
    false,
  );
  assert.equal(
    validateResponse({
      ...reportGet,
      payload: {
        ...reportGet.payload,
        report: {
          ...reportGet.payload.report,
          envelopeSize: 1536 * 1024 + 1,
        },
      },
    }),
    false,
  );
});

test("runtime validation rejects provider fields outside the contract", () => {
  const proposal = {
    schemaVersion: "1.0",
    diagnosis: "Observed failure",
    confidence: 0.8,
    evidenceIds: ["E-1"],
    requestedEvidence: [],
  };
  assert.deepEqual(parseDiagnosisProposal(proposal), proposal);
  assert.throws(
    () => parseDiagnosisProposal({ ...proposal, command: "rm -rf /" }),
    SchemaValidationError,
  );
  assert.throws(
    () => parseDiagnosisProposal({ ...proposal, confidence: Number.NaN }),
    SchemaValidationError,
  );
});

test("plans and reports reject empty actions and malformed nested records", () => {
  const plan = {
    schemaVersion: "1.0",
    planId: "P-1",
    targetFingerprint: `sha256:${"1".repeat(64)}`,
    diagnosis: "Observed failure",
    evidenceIds: ["E-1"],
    risk: "R0",
    steps: [
      {
        action: "system.observe.noop",
        args: {},
        preconditions: ["target.still_matches"],
        backup: "not-required",
        validation: "evidence.exists",
        rollback: null,
      },
    ],
  };
  assert.deepEqual(parseValidatedPlan(plan), plan);
  assert.throws(
    () => parseValidatedPlan({ ...plan, risk: ["R0"] }),
    SchemaValidationError,
  );
  assert.throws(
    () =>
      parseValidatedPlan({
        ...plan,
        steps: [{ ...plan.steps[0], backup: ["not-required"] }],
      }),
    SchemaValidationError,
  );
  assert.throws(
    () => parseValidatedPlan({ ...plan, steps: [] }),
    SchemaValidationError,
  );
  assert.throws(
    () =>
      parseSessionReport({
        schemaVersion: "1.0",
        sessionId: "S-1",
        targetFingerprint: plan.targetFingerprint,
        facts: [{ injected: true }],
        inferences: [],
        decisions: [],
        events: [],
        verification: "not-run",
        unresolvedRisks: [],
      }),
    SchemaValidationError,
  );
});
