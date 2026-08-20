import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import test from "node:test";
import Ajv2020 from "ajv/dist/2020.js";
import {
  LINUX_NORMALIZED_SNAPSHOT_HASH_DOMAIN,
  SchemaValidationError,
  canonicalLinuxSnapshotJson,
  parseLinuxNormalizedSnapshotEnvelope,
  parseLinuxNormalizedSnapshotEnvelopeJson,
} from "../src/index.js";

const golden = readFileSync(
  new URL(
    "../../../tests/fixtures/linux-normalized-snapshot/expected/snapshot.v1.json",
    import.meta.url,
  ),
  "utf8",
).trimEnd();
const goldenHash = readFileSync(
  new URL(
    "../../../tests/fixtures/linux-normalized-snapshot/expected/snapshot.v1.sha256",
    import.meta.url,
  ),
  "utf8",
).trim();
const snapshot = JSON.parse(golden) as unknown;

function envelope(mode: "resident" | "rescue") {
  return {
    schemaVersion: "1.0",
    kind: "linux-normalized-snapshot",
    snapshotSha256: goldenHash,
    capture:
      mode === "resident"
        ? {
            mode: "resident",
            targetScope: "running-root",
            accessPolicy: "fixed-descriptor-read-only",
            callerSuppliedPath: false,
            mutationRequested: false,
            crossDeviceTraversalAllowed: false,
          }
        : {
            mode: "rescue",
            targetScope: "selected-installed-target",
            accessPolicy: "temporary-read-only-no-replay",
            deviceOpenedReadOnly: true,
            journalReplayPrevented: true,
            privateMountNamespace: true,
            mountCleanupVerified: true,
            mutationPerformed: false,
            crossDeviceTraversalAllowed: false,
          },
    snapshot,
  };
}

test("canonical TS projection matches the shared snapshot golden and hash", () => {
  const canonical = canonicalLinuxSnapshotJson(snapshot);
  assert.equal(canonical, golden);
  assert.equal(
    createHash("sha256")
      .update(LINUX_NORMALIZED_SNAPSHOT_HASH_DOMAIN)
      .update(canonical)
      .digest("hex"),
    goldenHash,
  );
});

test("strict parser accepts both capture modes without changing the snapshot", () => {
  const resident = parseLinuxNormalizedSnapshotEnvelope(envelope("resident"));
  const rescue = parseLinuxNormalizedSnapshotEnvelope(envelope("rescue"));
  assert.deepEqual(resident.snapshot, rescue.snapshot);
  assert.equal(resident.capture.mode, "resident");
  assert.equal(rescue.capture.mode, "rescue");
  assert.ok(Object.isFrozen(resident));
  assert.ok(Object.isFrozen(resident.snapshot));
});

test("raw parser admits only bounded canonical UTF-8 without duplicate keys", () => {
  const canonical = JSON.stringify(envelope("resident"));
  assert.equal(
    parseLinuxNormalizedSnapshotEnvelopeJson(
      new TextEncoder().encode(canonical),
    ).snapshotSha256,
    goldenHash,
  );
  assert.throws(
    () =>
      parseLinuxNormalizedSnapshotEnvelopeJson(
        new TextEncoder().encode(` ${canonical}`),
      ),
    SchemaValidationError,
  );
  assert.throws(
    () =>
      parseLinuxNormalizedSnapshotEnvelopeJson(
        new TextEncoder().encode(
          canonical.replace(
            '{"schemaVersion":"1.0",',
            '{"schemaVersion":"1.0","schemaVersion":"1.0",',
          ),
        ),
      ),
    SchemaValidationError,
  );
});

test("published JSON schema validates the common envelope", () => {
  const schema = JSON.parse(
    readFileSync(
      new URL("../linux-normalized-snapshot.schema.json", import.meta.url),
      "utf8",
    ),
  );
  const validate = new Ajv2020({ allErrors: true, strict: true }).compile(
    schema,
  );
  assert.equal(
    validate(envelope("resident")),
    true,
    JSON.stringify(validate.errors),
  );
  assert.equal(
    validate(envelope("rescue")),
    true,
    JSON.stringify(validate.errors),
  );
});

test("strict parser rejects extra data and inconsistent summaries", () => {
  const unknown = structuredClone(envelope("resident")) as Record<
    string,
    unknown
  >;
  unknown.path = "/forbidden";
  assert.throws(
    () => parseLinuxNormalizedSnapshotEnvelope(unknown),
    SchemaValidationError,
  );

  const inconsistent = structuredClone(envelope("rescue"));
  inconsistent.snapshot.configuration.fstab.swapEntryCount = 6;
  assert.throws(
    () => parseLinuxNormalizedSnapshotEnvelope(inconsistent),
    SchemaValidationError,
  );

  const falseAttestation = structuredClone(envelope("rescue"));
  falseAttestation.capture.mountCleanupVerified = false;
  assert.throws(
    () => parseLinuxNormalizedSnapshotEnvelope(falseAttestation),
    SchemaValidationError,
  );

  const crossDeviceAttestation = structuredClone(envelope("resident"));
  crossDeviceAttestation.capture.crossDeviceTraversalAllowed = true as false;
  assert.throws(
    () => parseLinuxNormalizedSnapshotEnvelope(crossDeviceAttestation),
    SchemaValidationError,
  );

  const inconsistentTopology = structuredClone(envelope("resident"));
  inconsistentTopology.snapshot.topology.supported = false;
  assert.throws(
    () => parseLinuxNormalizedSnapshotEnvelope(inconsistentTopology),
    SchemaValidationError,
  );
});

test("strict parser preserves an authenticated but admission-unsupported topology", () => {
  const unsupported = JSON.parse(
    readFileSync(
      new URL(
        "../../../tests/fixtures/linux-normalized-snapshot/expected/multi-fs.snapshot.v1.json",
        import.meta.url,
      ),
      "utf8",
    ),
  ) as unknown;
  const parsed = canonicalLinuxSnapshotJson(unsupported);
  assert.equal(JSON.parse(parsed).topology.supported, false);
});
