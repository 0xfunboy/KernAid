import { InMemoryAuditSink } from "@kernaid/agent-gateway";
import {
  SECURE_AUDIT_STATUS,
  SIGNED_REPORT_MEDIA_TYPE,
  parseArtifactRef,
  parseAuditRecord,
  parseAuditSealRequest,
  type ArtifactRef,
  type AuditRecord,
  type AuditSealRequest,
  type AuditSink,
  type AuditSinkStatus,
} from "@kernaid/session-driver";

const API_VERSION = "kernaid.dev/rescue-application-http/v1alpha1";
const REPORT_ID =
  /^RP-[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;
const SHA256 = /^[0-9a-f]{64}$/;
const MAX_SIGNED_ENVELOPE_BYTES = 1536 * 1024;

type Fetch = typeof globalThis.fetch;
type VaultState =
  | "absent"
  | "unprovisioned"
  | "locked"
  | "unlocking"
  | "unlocked"
  | "locking"
  | "faulted-reboot-required";

interface VaultStatus {
  stateVersion: number;
  vaultState: VaultState;
}

interface ReportSummary {
  reportId: string;
  envelopeSize: number;
  envelopeSha256: string;
}

type Lifecycle = "started" | "diagnosed" | "ended";

/**
 * Connect the Desk audit boundary to the encrypted Rescue vault. A locked or
 * absent vault is an expected unavailable state; malformed or unauthenticated
 * responses fail closed instead of being presented as secure audit.
 */
export async function createRescueAuditSink(
  fetcher: Fetch = globalThis.fetch,
): Promise<RescueAuditSink | undefined> {
  const status = await readVaultStatus(fetcher);
  return status.vaultState === "unlocked"
    ? new RescueAuditSink(status.stateVersion, fetcher)
    : undefined;
}

/**
 * Secure Rescue audit adapter. Full records are validated locally and remain
 * embedded in the SessionReport. The privileged vault receives only the
 * closed three-event lifecycle plus the exact report bytes it validates,
 * journal-binds and signs.
 */
export class RescueAuditSink implements AuditSink {
  readonly status: AuditSinkStatus = SECURE_AUDIT_STATUS;

  readonly #memory = new InMemoryAuditSink();
  readonly #fetch: Fetch;
  readonly #lifecycle = new Map<string, Lifecycle>();
  #stateVersion: number;

  constructor(stateVersion: number, fetcher: Fetch = globalThis.fetch) {
    if (!safeStateVersion(stateVersion)) throw auditFailure();
    this.#stateVersion = stateVersion;
    this.#fetch = fetcher;
  }

  async append(value: AuditRecord): Promise<void> {
    const record = parseAuditRecord(value);
    await this.#memory.append(record);
    const lifecycle = this.#lifecycle.get(record.sessionId);
    if (record.type === "session.started") {
      await this.#appendLifecycle(1, "agent-session-start");
      this.#lifecycle.set(record.sessionId, "started");
      return;
    }
    if (record.type === "diagnosis" && lifecycle === "started") {
      await this.#appendLifecycle(2, "agent-diagnosis-complete");
      this.#lifecycle.set(record.sessionId, "diagnosed");
      return;
    }
    if (record.type === "report" && lifecycle === "diagnosed") {
      await this.#appendLifecycle(3, "agent-session-end");
      this.#lifecycle.set(record.sessionId, "ended");
    }
  }

  async sealReport(value: AuditSealRequest): Promise<ArtifactRef> {
    const request = parseAuditSealRequest(value);
    await this.#memory.sealReport(request);
    if (this.#lifecycle.get(request.sessionId) !== "ended")
      throw auditFailure();

    const reportId = `RP-${crypto.randomUUID()}`;
    const response = await postJson(this.#fetch, "/api/rescue/report-persist", {
      expectedStateVersion: this.#stateVersion,
      reportId,
      payloadSha256: request.payloadSha256,
      reportJson: request.body,
    });
    const stored = parseStoredReport(response, reportId);
    this.#stateVersion = stored.stateVersion;

    const envelope = await fetchEnvelope(this.#fetch, stored.report);
    return parseArtifactRef({
      mediaType: SIGNED_REPORT_MEDIA_TYPE,
      payloadMediaType: request.payloadMediaType,
      uri: `data:${SIGNED_REPORT_MEDIA_TYPE};base64,${base64(envelope)}`,
      sha256: stored.report.envelopeSha256,
      payloadSha256: request.payloadSha256,
      auditStatus: this.status,
    });
  }

  async #appendLifecycle(sequence: number, event: string): Promise<void> {
    const response = await postJson(this.#fetch, "/api/rescue/audit-append", {
      expectedStateVersion: this.#stateVersion,
      sequence,
      event,
      outcome: "succeeded",
    });
    const item = object(response);
    exactKeys(item, ["apiVersion", "stateVersion", "sequence"]);
    if (
      item.apiVersion !== API_VERSION ||
      !safeStateVersion(item.stateVersion) ||
      item.sequence !== sequence
    )
      throw auditFailure();
    this.#stateVersion = item.stateVersion;
  }
}

async function readVaultStatus(fetcher: Fetch): Promise<VaultStatus> {
  const response = await fetcher("/api/rescue/vault/status", {
    method: "GET",
    cache: "no-store",
    credentials: "same-origin",
    headers: { Accept: "application/json" },
  });
  const value = await responseJson(response);
  const item = object(value);
  exactKeys(item, ["apiVersion", "stateVersion", "vaultState"]);
  const states: readonly unknown[] = [
    "absent",
    "unprovisioned",
    "locked",
    "unlocking",
    "unlocked",
    "locking",
    "faulted-reboot-required",
  ];
  if (
    item.apiVersion !== API_VERSION ||
    !safeStateVersion(item.stateVersion) ||
    !states.includes(item.vaultState)
  )
    throw auditFailure();
  return {
    stateVersion: item.stateVersion,
    vaultState: item.vaultState as VaultState,
  };
}

async function postJson(
  fetcher: Fetch,
  path: string,
  value: object,
): Promise<unknown> {
  const response = await fetcher(path, {
    method: "POST",
    cache: "no-store",
    credentials: "same-origin",
    headers: {
      Accept: "application/json",
      "Content-Type": "application/json",
    },
    body: JSON.stringify(value),
  });
  return responseJson(response);
}

async function responseJson(response: Response): Promise<unknown> {
  const contentType = response.headers.get("Content-Type")?.split(";", 1)[0];
  if (contentType !== "application/json") throw auditFailure();
  let value: unknown;
  try {
    value = await response.json();
  } catch {
    throw auditFailure();
  }
  if (!response.ok) {
    const error = object(value);
    exactKeys(error, ["apiVersion", "error"]);
    if (
      error.apiVersion !== API_VERSION ||
      typeof error.error !== "string" ||
      !/^[A-Z_]{2,64}$/.test(error.error)
    )
      throw auditFailure();
    throw new Error(`Audit Rescue non disponibile (${error.error}).`);
  }
  return value;
}

function parseStoredReport(
  value: unknown,
  expectedReportId: string,
): { stateVersion: number; report: ReportSummary } {
  const item = object(value);
  exactKeys(item, ["apiVersion", "stateVersion", "report"]);
  if (item.apiVersion !== API_VERSION || !safeStateVersion(item.stateVersion))
    throw auditFailure();
  const report = parseReportSummary(item.report);
  if (report.reportId !== expectedReportId) throw auditFailure();
  return { stateVersion: item.stateVersion, report };
}

function parseReportSummary(value: unknown): ReportSummary {
  const item = object(value);
  exactKeys(item, ["reportId", "envelopeSize", "envelopeSha256"]);
  if (
    typeof item.reportId !== "string" ||
    !REPORT_ID.test(item.reportId) ||
    !Number.isSafeInteger(item.envelopeSize) ||
    (item.envelopeSize as number) < 2 ||
    (item.envelopeSize as number) > MAX_SIGNED_ENVELOPE_BYTES ||
    typeof item.envelopeSha256 !== "string" ||
    !SHA256.test(item.envelopeSha256)
  )
    throw auditFailure();
  return item as unknown as ReportSummary;
}

async function fetchEnvelope(
  fetcher: Fetch,
  report: ReportSummary,
): Promise<Uint8Array> {
  const response = await fetcher(`/api/rescue/reports/${report.reportId}`, {
    method: "GET",
    cache: "no-store",
    credentials: "same-origin",
    headers: { Accept: SIGNED_REPORT_MEDIA_TYPE },
  });
  if (!response.ok) {
    await responseJson(response);
    throw auditFailure();
  }
  const contentType = response.headers.get("Content-Type")?.split(";", 1)[0];
  const length = response.headers.get("Content-Length");
  const hash = response.headers.get("X-KernAid-Envelope-Sha256");
  const etag = response.headers.get("ETag");
  if (
    contentType !== SIGNED_REPORT_MEDIA_TYPE ||
    length !== String(report.envelopeSize) ||
    hash !== report.envelopeSha256 ||
    etag !== `"sha256-${report.envelopeSha256}"`
  )
    throw auditFailure();
  const bytes = new Uint8Array(await response.arrayBuffer());
  if (
    bytes.byteLength !== report.envelopeSize ||
    (await sha256(bytes)) !== report.envelopeSha256
  )
    throw auditFailure();
  try {
    const parsed: unknown = JSON.parse(
      new TextDecoder("utf-8", { fatal: true }).decode(bytes),
    );
    if (typeof parsed !== "object" || parsed === null || Array.isArray(parsed))
      throw auditFailure();
  } catch {
    throw auditFailure();
  }
  return bytes;
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

function base64(value: Uint8Array): string {
  let encoded = "";
  for (let offset = 0; offset < value.length; offset += 16 * 1024)
    encoded += String.fromCharCode(
      ...value.subarray(offset, offset + 16 * 1024),
    );
  return btoa(encoded);
}

function safeStateVersion(value: unknown): value is number {
  return Number.isSafeInteger(value) && (value as number) >= 0;
}

function object(value: unknown): Record<string, unknown> {
  if (typeof value !== "object" || value === null || Array.isArray(value))
    throw auditFailure();
  return value as Record<string, unknown>;
}

function exactKeys(value: Record<string, unknown>, expected: string[]): void {
  const actual = Object.keys(value).sort();
  const wanted = [...expected].sort();
  if (
    actual.length !== wanted.length ||
    actual.some((key, index) => key !== wanted[index])
  )
    throw auditFailure();
}

function auditFailure(): Error {
  return new Error("Il confine di audit Rescue ha rifiutato la risposta.");
}
