import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
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
  "session-report.schema.json",
  "validated-plan.schema.json",
];

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
