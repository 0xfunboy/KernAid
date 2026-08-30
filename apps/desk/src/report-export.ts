import {
  SIGNED_REPORT_MEDIA_TYPE,
  parseArtifactRef,
  type ArtifactRef,
} from "@kernaid/session-driver";
import { parseSessionReportJson, type SessionReport } from "@kernaid/schemas";

const SIGNED_REPORT_SCHEMA =
  "https://schemas.kernaid.dev/v1/signed-report-envelope.json";
const SESSION_ID = /^S-[A-Za-z0-9-]+$/;
const SHA256 = /^[a-f0-9]{64}$/;
const SIGNED_ENVELOPE_KEYS = [
  "schema",
  "kind",
  "algorithm",
  "deviceId",
  "journalSequence",
  "journalEntryHash",
  "payloadMediaType",
  "payloadSha256",
  "payload",
  "publicKey",
  "signature",
] as const;

export interface MarkdownReportExport {
  mediaType: "text/markdown";
  uri: string;
  sha256: string;
  downloadName: string;
  signed: false;
}

export const UNSIGNED_MARKDOWN_DOWNLOAD_LABEL =
  "Markdown human-readable · non firmato";

/**
 * Keep the existing data-URI download boundary. The signed JSON remains the
 * authoritative artifact; Markdown is a clearly unsigned, local rendering of
 * its validated JSON payload.
 */
export async function createUnsignedMarkdownReport(
  value: ArtifactRef,
  expectedSessionId: string,
): Promise<MarkdownReportExport> {
  const artifact = parseArtifactRef(value);
  const sessionId = safeSessionId(expectedSessionId);
  if (artifact.payloadMediaType !== "application/json") throw invalidReport();

  const payload = await reportPayload(artifact);
  const report = parseSessionReportJson(payload);
  if (report.sessionId !== sessionId) throw invalidReport();

  const body = markdownReport(report, artifact);
  return {
    mediaType: "text/markdown",
    uri: `data:text/markdown;charset=utf-8,${encodeURIComponent(body)}`,
    sha256: await sha256(new TextEncoder().encode(body)),
    downloadName: `KernAid-${sessionId}-human-report-unsigned.md`,
    signed: false,
  };
}

export function jsonReportDownloadName(
  value: ArtifactRef,
  expectedSessionId: string,
): string {
  const artifact = parseArtifactRef(value);
  const sessionId = safeSessionId(expectedSessionId);
  const signature = artifact.auditStatus.signed ? "signed" : "unsigned";
  return `KernAid-${sessionId}-machine-report-${signature}.json`;
}

export function jsonReportDownloadLabel(value: ArtifactRef): string {
  const artifact = parseArtifactRef(value);
  return `JSON machine-readable · ${artifact.auditStatus.signed ? "firmato" : "non firmato"}`;
}

function safeSessionId(value: string): string {
  if (value.length > 128 || !SESSION_ID.test(value)) throw invalidReport();
  return value;
}

async function reportPayload(artifact: ArtifactRef): Promise<Uint8Array> {
  if (artifact.auditStatus.signed) return signedReportPayload(artifact);
  const prefix = "data:application/json;charset=utf-8,";
  if (
    artifact.mediaType !== "application/json" ||
    !artifact.uri.startsWith(prefix)
  )
    throw invalidReport();
  let body: string;
  try {
    body = decodeURIComponent(artifact.uri.slice(prefix.length));
  } catch {
    throw invalidReport();
  }
  const payload = new TextEncoder().encode(body);
  const payloadHash = await sha256(payload);
  if (payloadHash !== artifact.payloadSha256 || payloadHash !== artifact.sha256)
    throw invalidReport();
  return payload;
}

async function signedReportPayload(artifact: ArtifactRef): Promise<Uint8Array> {
  const prefix = `data:${SIGNED_REPORT_MEDIA_TYPE};base64,`;
  if (
    artifact.mediaType !== SIGNED_REPORT_MEDIA_TYPE ||
    !artifact.uri.startsWith(prefix)
  )
    throw invalidReport();
  const container = decodeBase64(artifact.uri.slice(prefix.length));
  if ((await sha256(container)) !== artifact.sha256) throw invalidReport();

  let parsed: unknown;
  try {
    parsed = JSON.parse(
      new TextDecoder("utf-8", { fatal: true }).decode(container),
    ) as unknown;
  } catch {
    throw invalidReport();
  }
  const envelope = exactRecord(parsed, SIGNED_ENVELOPE_KEYS);
  if (
    envelope.schema !== SIGNED_REPORT_SCHEMA ||
    envelope.kind !== "kernaid.signed-report" ||
    envelope.algorithm !== "Ed25519" ||
    typeof envelope.deviceId !== "string" ||
    !/^KA-[a-f0-9]{24}$/.test(envelope.deviceId) ||
    !Number.isSafeInteger(envelope.journalSequence) ||
    Number(envelope.journalSequence) < 1 ||
    envelope.payloadMediaType !== "application/json" ||
    typeof envelope.journalEntryHash !== "string" ||
    decodeBase64Url(envelope.journalEntryHash, 32) === undefined ||
    typeof envelope.publicKey !== "string" ||
    decodeBase64Url(envelope.publicKey, 32) === undefined ||
    typeof envelope.signature !== "string" ||
    decodeBase64Url(envelope.signature, 64) === undefined ||
    typeof envelope.payloadSha256 !== "string" ||
    typeof envelope.payload !== "string"
  )
    throw invalidReport();

  const payloadHash = decodeBase64Url(envelope.payloadSha256, 32);
  const payload = decodeBase64Url(envelope.payload);
  if (
    payloadHash === undefined ||
    payload === undefined ||
    hex(payloadHash) !== artifact.payloadSha256 ||
    (await sha256(payload)) !== artifact.payloadSha256
  )
    throw invalidReport();
  return payload;
}

function markdownReport(report: SessionReport, artifact: ArtifactRef): string {
  const lines = [
    "# KernAid session report",
    "",
    "> **UNSIGNED HUMAN-READABLE COPY.** This Markdown file is derived locally from the validated JSON report. Use the companion JSON bundle to verify authenticity and integrity.",
    "",
    `- Session: \`${report.sessionId}\``,
    `- Target fingerprint: \`${report.targetFingerprint}\``,
    `- Companion JSON bundle: **${artifact.auditStatus.signed ? "signed" : "unsigned"}**`,
    `- Companion artifact SHA-256: \`${artifact.sha256}\``,
    `- Source payload SHA-256: \`${artifact.payloadSha256}\``,
    `- Verification: **${report.verification}**`,
    "",
    "## Facts",
    "",
  ];

  if (report.facts.length === 0) lines.push("- None", "");
  for (const fact of report.facts) {
    lines.push(
      `### ${inline(fact.id)}`,
      "",
      `- Collector: ${inline(fact.collector)}`,
      `- Target: ${inline(fact.target)}`,
      `- Captured at: \`${fact.capturedAt}\``,
      `- Content type: ${inline(fact.contentType)}`,
      `- Sensitivity: **${fact.sensitivity}**`,
      `- Summary: ${inline(fact.summary)}`,
      `- SHA-256: \`${fact.sha256}\``,
      `- Blob reference: \`${fact.blobRef}\``,
      "",
    );
  }

  lines.push("## Inferences", "");
  if (report.inferences.length === 0) lines.push("- None", "");
  report.inferences.forEach((inference, index) => {
    lines.push(
      `### Inference ${index + 1}`,
      "",
      `- Diagnosis: ${inline(inference.diagnosis)}`,
      `- Confidence: ${inference.confidence}`,
      `- Evidence references: ${codeList(inference.evidenceIds)}`,
      `- Requested evidence: ${textList(inference.requestedEvidence)}`,
      "",
    );
  });

  lines.push("## User decisions", "");
  if (report.decisions.length === 0) lines.push("- None", "");
  for (const decision of report.decisions) {
    lines.push(
      `### ${inline(decision.approvalId)}`,
      "",
      `- Plan: \`${decision.planId}\``,
      `- Target fingerprint: \`${decision.targetFingerprint}\``,
      `- Approved at: \`${decision.approvedAt}\``,
      `- Approved by: ${inline(decision.approvedBy)}`,
    );
    if (decision.typedConfirmation !== undefined)
      lines.push(`- Typed confirmation: ${inline(decision.typedConfirmation)}`);
    lines.push("");
  }

  lines.push("## Commands and actions", "");
  if (report.events.length === 0) lines.push("- None", "");
  for (const event of report.events) {
    lines.push(
      `### Event ${event.sequence}`,
      "",
      `- Plan: \`${event.planId}\``,
      `- Status: **${event.status}**`,
      `- Action: \`${event.action}\``,
      `- Message: ${inline(event.message)}`,
      `- Captured at: \`${event.capturedAt}\``,
      "",
    );
  }

  lines.push("## Unresolved risks", "");
  if (report.unresolvedRisks.length === 0) lines.push("- None");
  else lines.push(...report.unresolvedRisks.map((risk) => `- ${inline(risk)}`));
  lines.push("");
  return lines.join("\n");
}

function inline(value: string): string {
  return value
    .replace(/\s+/gu, " ")
    .trim()
    .replaceAll("\\", "\\\\")
    .replace(/[()[\]{}<>#+.!|*_`-]/gu, "\\$&");
}

function codeList(values: readonly string[]): string {
  return values.length === 0
    ? "None"
    : values.map((value) => `\`${value}\``).join(", ");
}

function textList(values: readonly string[]): string {
  return values.length === 0 ? "None" : values.map(inline).join("; ");
}

function exactRecord(
  value: unknown,
  keys: readonly string[],
): Record<string, unknown> {
  if (typeof value !== "object" || value === null || Array.isArray(value))
    throw invalidReport();
  const item = value as Record<string, unknown>;
  const actual = Object.keys(item).sort();
  const expected = [...keys].sort();
  if (
    actual.length !== expected.length ||
    actual.some((key, index) => key !== expected[index])
  )
    throw invalidReport();
  return item;
}

function decodeBase64(value: string): Uint8Array {
  try {
    const decoded = atob(value);
    const bytes = Uint8Array.from(decoded, (character) =>
      character.charCodeAt(0),
    );
    if (base64(bytes) !== value) throw invalidReport();
    return bytes;
  } catch {
    throw invalidReport();
  }
}

function decodeBase64Url(
  value: string,
  expectedLength?: number,
): Uint8Array | undefined {
  if (!/^[A-Za-z0-9_-]*$/.test(value)) return undefined;
  try {
    const padding = "=".repeat((4 - (value.length % 4)) % 4);
    const bytes = decodeBase64(
      value.replaceAll("-", "+").replaceAll("_", "/") + padding,
    );
    if (expectedLength !== undefined && bytes.byteLength !== expectedLength)
      return undefined;
    if (base64Url(bytes) !== value) return undefined;
    return bytes;
  } catch {
    return undefined;
  }
}

function base64(value: Uint8Array): string {
  let binary = "";
  for (let offset = 0; offset < value.byteLength; offset += 32 * 1024)
    binary += String.fromCharCode(
      ...value.subarray(offset, offset + 32 * 1024),
    );
  return btoa(binary);
}

function base64Url(value: Uint8Array): string {
  return base64(value)
    .replaceAll("+", "-")
    .replaceAll("/", "_")
    .replace(/=+$/u, "");
}

function hex(value: Uint8Array): string {
  return Array.from(value, (byte) => byte.toString(16).padStart(2, "0")).join(
    "",
  );
}

async function sha256(value: Uint8Array): Promise<string> {
  const digest = await crypto.subtle.digest(
    "SHA-256",
    Uint8Array.from(value).buffer,
  );
  const result = hex(new Uint8Array(digest));
  if (!SHA256.test(result)) throw invalidReport();
  return result;
}

function invalidReport(): Error {
  return new Error("Il report JSON non è valido per l’export Markdown.");
}
