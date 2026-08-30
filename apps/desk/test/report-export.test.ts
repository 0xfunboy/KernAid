import assert from "node:assert/strict";
import test from "node:test";
import {
  SECURE_AUDIT_STATUS,
  SIGNED_REPORT_MEDIA_TYPE,
  UNAVAILABLE_AUDIT_STATUS,
  type ArtifactRef,
} from "@kernaid/session-driver";
import type { SessionReport } from "@kernaid/schemas";
import {
  createUnsignedMarkdownReport,
  jsonReportDownloadLabel,
  jsonReportDownloadName,
  UNSIGNED_MARKDOWN_DOWNLOAD_LABEL,
} from "../src/report-export.js";

const sessionId = "S-report-export-7";
const report: SessionReport = {
  schemaVersion: "1.0",
  sessionId,
  targetFingerprint: `sha256:${"b".repeat(64)}`,
  facts: [
    {
      schemaVersion: "1.0",
      id: "E-disk-1",
      collector: "linux.block.inventory",
      target: "local-machine",
      capturedAt: "2026-08-30T10:00:00.000Z",
      contentType: "application/json",
      sha256: "c".repeat(64),
      sensitivity: "system",
      trust: "observed-untrusted",
      summary: "Disk *fact* observed",
      blobRef: `sha256:${"c".repeat(64)}`,
    },
  ],
  inferences: [
    {
      schemaVersion: "1.0",
      diagnosis: "Read-only diagnosis",
      confidence: 0.91,
      evidenceIds: ["E-disk-1"],
      requestedEvidence: ["Confirm filesystem state"],
    },
  ],
  decisions: [
    {
      schemaVersion: "1.0",
      approvalId: "A-local-1",
      planId: "P-observe-1",
      targetFingerprint: `sha256:${"b".repeat(64)}`,
      approvedAt: "2026-08-30T10:01:00.000Z",
      approvedBy: "local-user",
      typedConfirmation: "CONFIRM OBSERVE",
    },
  ],
  events: [
    {
      schemaVersion: "1.0",
      planId: "P-observe-1",
      sequence: 1,
      status: "succeeded",
      action: "system.observe.noop",
      message: "Observation completed",
      capturedAt: "2026-08-30T10:02:00.000Z",
    },
  ],
  verification: "passed",
  unresolvedRisks: ["Physical media was not tested"],
};

test("signed JSON yields a session-bound unsigned Markdown download", async () => {
  const artifact = await signedArtifact(report);
  const markdown = await createUnsignedMarkdownReport(artifact, sessionId);
  const body = decodeURIComponent(
    markdown.uri.slice("data:text/markdown;charset=utf-8,".length),
  );

  assert.equal(
    markdown.downloadName,
    "KernAid-S-report-export-7-human-report-unsigned.md",
  );
  assert.equal(markdown.signed, false);
  assert.match(body, /UNSIGNED HUMAN-READABLE COPY/u);
  assert.match(body, /Companion JSON bundle: \*\*signed\*\*/u);
  assert.match(body, /E\\-disk\\-1/u);
  assert.match(body, new RegExp("c".repeat(64), "u"));
  assert.match(body, new RegExp(`sha256:${"c".repeat(64)}`, "u"));
  assert.match(body, /Read\\-only diagnosis/u);
  assert.match(body, /A\\-local\\-1/u);
  assert.match(body, /system\.observe\.noop/u);
  assert.match(body, /Physical media was not tested/u);
  assert.match(markdown.sha256, /^[a-f0-9]{64}$/u);
});

test("unsigned JSON remains unsigned and preserves the current data URI path", async () => {
  const artifact = await unsignedArtifact(report);
  const markdown = await createUnsignedMarkdownReport(artifact, sessionId);
  const body = decodeURIComponent(
    markdown.uri.slice("data:text/markdown;charset=utf-8,".length),
  );

  assert.match(body, /Companion JSON bundle: \*\*unsigned\*\*/u);
  assert.ok(markdown.uri.startsWith("data:text/markdown;charset=utf-8,"));
  assert.equal(
    jsonReportDownloadName(artifact, sessionId),
    "KernAid-S-report-export-7-machine-report-unsigned.json",
  );
});

test("JSON filenames distinguish signed state and reject unsafe session names", async () => {
  const unsigned = await unsignedArtifact(report);
  const signed = await signedArtifact(report);
  assert.equal(
    jsonReportDownloadName(signed, sessionId),
    "KernAid-S-report-export-7-machine-report-signed.json",
  );
  assert.equal(
    jsonReportDownloadLabel(signed),
    "JSON machine-readable · firmato",
  );
  assert.equal(
    jsonReportDownloadLabel(unsigned),
    "JSON machine-readable · non firmato",
  );
  assert.equal(
    UNSIGNED_MARKDOWN_DOWNLOAD_LABEL,
    "Markdown human-readable · non firmato",
  );
  assert.throws(
    () => jsonReportDownloadName(unsigned, "S-report/../../escape"),
    /non è valido/u,
  );
});

test("Markdown derivation fails closed on session, hash, or envelope shape mismatch", async () => {
  const unsigned = await unsignedArtifact(report);
  await assert.rejects(
    createUnsignedMarkdownReport(unsigned, "S-another-session"),
    /non è valido/u,
  );
  await assert.rejects(
    createUnsignedMarkdownReport(
      { ...unsigned, payloadSha256: "0".repeat(64) },
      sessionId,
    ),
  );

  const signed = await signedArtifact(report);
  const prefix = `data:${SIGNED_REPORT_MEDIA_TYPE};base64,`;
  const envelope = JSON.parse(
    new TextDecoder().decode(base64Bytes(signed.uri.slice(prefix.length))),
  ) as Record<string, unknown>;
  envelope.unexpected = true;
  const container = new TextEncoder().encode(JSON.stringify(envelope));
  await assert.rejects(
    createUnsignedMarkdownReport(
      {
        ...signed,
        uri: `${prefix}${base64(container)}`,
        sha256: await sha256(container),
      },
      sessionId,
    ),
    /non è valido/u,
  );
});

async function unsignedArtifact(value: SessionReport): Promise<ArtifactRef> {
  const body = JSON.stringify(value, null, 2);
  const hash = await sha256(new TextEncoder().encode(body));
  return {
    mediaType: "application/json",
    payloadMediaType: "application/json",
    uri: `data:application/json;charset=utf-8,${encodeURIComponent(body)}`,
    sha256: hash,
    payloadSha256: hash,
    auditStatus: UNAVAILABLE_AUDIT_STATUS,
  };
}

async function signedArtifact(value: SessionReport): Promise<ArtifactRef> {
  const payload = new TextEncoder().encode(JSON.stringify(value, null, 2));
  const reportSha256 = await sha256(payload);
  const envelope = {
    schema: "https://schemas.kernaid.dev/v1/signed-report-envelope.json",
    kind: "kernaid.signed-report",
    algorithm: "Ed25519",
    deviceId: "KA-0123456789abcdef01234567",
    journalSequence: 3,
    journalEntryHash: base64Url(new Uint8Array(32).fill(1)),
    payloadMediaType: "application/json",
    payloadSha256: base64Url(hexBytes(reportSha256)),
    payload: base64Url(payload),
    publicKey: base64Url(new Uint8Array(32).fill(2)),
    signature: base64Url(new Uint8Array(64).fill(3)),
  };
  const container = new TextEncoder().encode(JSON.stringify(envelope));
  return {
    mediaType: SIGNED_REPORT_MEDIA_TYPE,
    payloadMediaType: "application/json",
    uri: `data:${SIGNED_REPORT_MEDIA_TYPE};base64,${base64(container)}`,
    sha256: await sha256(container),
    payloadSha256: reportSha256,
    auditStatus: SECURE_AUDIT_STATUS,
  };
}

function hexBytes(value: string): Uint8Array {
  return Uint8Array.from(value.match(/.{2}/gu) ?? [], (byte) =>
    Number.parseInt(byte, 16),
  );
}

function base64Url(value: Uint8Array): string {
  return base64(value)
    .replaceAll("+", "-")
    .replaceAll("/", "_")
    .replace(/=+$/u, "");
}

function base64(value: Uint8Array): string {
  return btoa(String.fromCharCode(...value));
}

function base64Bytes(value: string): Uint8Array {
  return Uint8Array.from(atob(value), (character) => character.charCodeAt(0));
}

async function sha256(value: Uint8Array): Promise<string> {
  const digest = await crypto.subtle.digest(
    "SHA-256",
    Uint8Array.from(value).buffer,
  );
  return Array.from(new Uint8Array(digest), (byte) =>
    byte.toString(16).padStart(2, "0"),
  ).join("");
}
