import assert from "node:assert/strict";
import test from "node:test";
import type { AuditSealRequest } from "@kernaid/session-driver";
import {
  parseNativeSignedArtifact,
  parseSecureRuntimeStatus,
} from "../src/native.js";

const schema = "https://schemas.kernaid.dev/v1/signed-report-envelope.json";
const mediaType = "application/vnd.kernaid.signed-report+json";

test("secure runtime status requires a device ID exactly when signing is ready", () => {
  const ready = parseSecureRuntimeStatus({
    schemaVersion: "1.0",
    audit: "secure",
    signing: "ready",
    persistentAuditStarted: true,
    deviceId: "KA-0123456789abcdef01234567",
  });
  assert.equal(ready.deviceId, "KA-0123456789abcdef01234567");

  assert.throws(() =>
    parseSecureRuntimeStatus({
      schemaVersion: "1.0",
      audit: "secure",
      signing: "ready",
      persistentAuditStarted: true,
    }),
  );
  assert.throws(() =>
    parseSecureRuntimeStatus({
      schemaVersion: "1.0",
      audit: "secure",
      signing: "uninitialized",
      persistentAuditStarted: false,
      deviceId: "KA-0123456789abcdef01234567",
    }),
  );
});

test("secure runtime status rejects ambiguous native responses", () => {
  assert.throws(() =>
    parseSecureRuntimeStatus({
      schemaVersion: "1.0",
      audit: "secure",
      signing: "uninitialized",
      persistentAuditStarted: false,
      unexpected: true,
    }),
  );
});

test("signed artifacts are bound to the requested payload and container hash", async () => {
  const body = JSON.stringify({ schemaVersion: "1.0", sessionId: "S-test" });
  const payloadSha256 = await sha256(body);
  const request: AuditSealRequest = {
    schemaVersion: "1.0",
    sessionId: "S-test",
    format: "json",
    payloadMediaType: "application/json",
    body,
    payloadSha256,
  };
  const container = {
    schema,
    kind: "kernaid.signed-report",
    algorithm: "Ed25519",
    deviceId: "KA-0123456789abcdef01234567",
    journalSequence: 2,
    journalEntryHash: base64Url(new Uint8Array(32).fill(1)),
    payloadMediaType: "application/json",
    payloadSha256: base64Url(hexBytes(payloadSha256)),
    payload: base64Url(new TextEncoder().encode(body)),
    publicKey: base64Url(new Uint8Array(32).fill(2)),
    signature: base64Url(new Uint8Array(64).fill(3)),
  };
  const containerJson = JSON.stringify(container);
  const artifact = {
    mediaType,
    payloadMediaType: "application/json",
    containerJson,
    sha256: await sha256(containerJson),
    payloadSha256,
    envelopeSchema: schema,
  };

  assert.equal(
    (await parseNativeSignedArtifact(artifact, request)).payloadSha256,
    payloadSha256,
  );
  await assert.rejects(
    parseNativeSignedArtifact(
      { ...artifact, payloadSha256: "0".repeat(64) },
      request,
    ),
  );
  await assert.rejects(
    parseNativeSignedArtifact({ ...artifact, sha256: "0".repeat(64) }, request),
  );
});

function base64Url(value: Uint8Array): string {
  return Buffer.from(value).toString("base64url");
}

function hexBytes(value: string): Uint8Array {
  return Uint8Array.from({ length: value.length / 2 }, (_, index) =>
    Number.parseInt(value.slice(index * 2, index * 2 + 2), 16),
  );
}

async function sha256(value: string): Promise<string> {
  const digest = await crypto.subtle.digest(
    "SHA-256",
    new TextEncoder().encode(value),
  );
  return Buffer.from(digest).toString("hex");
}
