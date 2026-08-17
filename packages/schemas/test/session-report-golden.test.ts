import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";
import Ajv2020 from "ajv/dist/2020.js";
import addFormats from "ajv-formats";
import {
  decodeSessionReportJson,
  parseSessionReportJson,
  sessionReportSemanticBindingsAreValid,
} from "../src/index.js";

interface GoldenCase {
  name: string;
  valid: boolean;
  file: string;
}

interface GoldenManifest {
  schemaVersion: 1;
  cases: GoldenCase[];
}

const schemaFiles = [
  "approval.schema.json",
  "diagnosis-proposal.schema.json",
  "evidence.schema.json",
  "execution-event.schema.json",
  "session-report.schema.json",
];

function loadGoldenManifest(): GoldenManifest {
  return JSON.parse(
    readFileSync(
      new URL("../testdata/session-report/manifest.json", import.meta.url),
      "utf8",
    ),
  ) as GoldenManifest;
}

function schemaValidator(): (value: unknown) => boolean {
  const ajv = new Ajv2020({ allErrors: true, strict: true });
  addFormats(ajv);
  for (const file of schemaFiles) {
    ajv.addSchema(
      JSON.parse(readFileSync(new URL(`../${file}`, import.meta.url), "utf8")),
    );
  }
  const validate = ajv.getSchema(
    "https://schemas.kernaid.dev/v1/session-report.json",
  );
  assert.ok(validate);
  return (value: unknown): boolean => validate(value) === true;
}

function acceptsWithSchemaAndSemantics(
  raw: Uint8Array,
  validateSchema: (value: unknown) => boolean,
): boolean {
  try {
    const value = decodeSessionReportJson(raw);
    return (
      validateSchema(value) && sessionReportSemanticBindingsAreValid(value)
    );
  } catch {
    return false;
  }
}

function acceptsWithTypedParser(raw: Uint8Array): boolean {
  try {
    parseSessionReportJson(raw);
    return true;
  } catch {
    return false;
  }
}

test("SessionReport golden corpus has schema, semantic and raw-parser parity", () => {
  const manifest = loadGoldenManifest();
  assert.equal(manifest.schemaVersion, 1);
  assert.ok(manifest.cases.some(({ valid }) => valid));
  assert.ok(manifest.cases.some(({ valid }) => !valid));
  assert.equal(
    new Set(manifest.cases.map(({ name }) => name)).size,
    manifest.cases.length,
  );

  const validateSchema = schemaValidator();
  for (const golden of manifest.cases) {
    const raw = readFileSync(
      new URL(`../testdata/session-report/${golden.file}`, import.meta.url),
    );
    const schemaAccepted = acceptsWithSchemaAndSemantics(raw, validateSchema);
    const parserAccepted = acceptsWithTypedParser(raw);
    assert.equal(
      schemaAccepted,
      golden.valid,
      `${golden.name}: JSON Schema + semantic binding`,
    );
    assert.equal(
      parserAccepted,
      golden.valid,
      `${golden.name}: TypeScript raw parser`,
    );
    assert.equal(
      parserAccepted,
      schemaAccepted,
      `${golden.name}: validators disagree`,
    );
  }
});
