import { invoke } from "@tauri-apps/api/core";
import {
  OfflineRulesProvider,
  type ObservedEvidence,
  type Provider,
} from "@kernaid/agent-gateway";
import {
  parseDiagnosisProposal,
  type DiagnosisProposal,
} from "@kernaid/schemas";
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

const SIGNED_REPORT_SCHEMA =
  "https://schemas.kernaid.dev/v1/signed-report-envelope.json";
const LINUX_P0_COLLECTORS = [
  "linux.block.inventory",
  "linux.mounts.read-only",
  "linux.systemd.failed",
  "linux.systemd.state",
  "linux.fstab",
  "linux.df",
  "linux.network.links",
  "linux.network.routes",
  "linux.dpkg.audit",
] as const;

export interface NativeObservation {
  collector: string;
  trust: "observed-untrusted";
  output: string;
  success: boolean;
  truncated: boolean;
}

export interface ObserveAuthorization {
  sessionId: string;
  planId: string;
  targetFingerprint: string;
  sequence: number;
  action: "system.observe.noop";
}

export interface SecureRuntimeStatus {
  schemaVersion: "1.0";
  audit: "secure" | "unavailable" | "blocked";
  signing: "ready" | "uninitialized" | "unavailable" | "blocked";
  persistentAuditStarted: boolean;
  deviceId?: string;
}

interface NativeSignedArtifact {
  mediaType: typeof SIGNED_REPORT_MEDIA_TYPE;
  payloadMediaType: "application/json" | "text/markdown";
  containerJson: string;
  sha256: string;
  payloadSha256: string;
  envelopeSchema: typeof SIGNED_REPORT_SCHEMA;
}

export function isNative(): boolean {
  return "__TAURI_INTERNALS__" in window;
}

export function hasLocalCollector(): boolean {
  return (
    isNative() ||
    (location.hostname === "127.0.0.1" && location.port === "4173")
  );
}

export async function collectLocalInventory(): Promise<NativeObservation[]> {
  if (isNative())
    return parseNativeObservations(await invoke("collect_local_inventory"));
  if (hasLocalCollector()) {
    for (let attempt = 0; attempt < 5; attempt += 1) {
      const response = await fetch("/api/inventory", {
        cache: "no-store",
        signal: AbortSignal.timeout(20_000),
      });
      if (response.status === 429 && attempt < 4) {
        await delay(
          retryAfterMilliseconds(response.headers.get("Retry-After")),
        );
        continue;
      }
      if (!response.ok) throw new Error(`collector HTTP ${response.status}`);
      return parseNativeObservations(await response.json());
    }
    throw new Error("collector HTTP 429");
  }
  return [];
}

export function parseNativeObservations(value: unknown): NativeObservation[] {
  if (!Array.isArray(value) || value.length === 0 || value.length > 32)
    throw new Error("Inventario nativo non valido.");
  return value.map((raw) => {
    const item = exactRecord(raw, [
      "collector",
      "trust",
      "output",
      "success",
      "truncated",
    ]);
    if (
      typeof item.collector !== "string" ||
      !/^[a-z0-9][a-z0-9._-]{0,127}$/u.test(item.collector) ||
      item.trust !== "observed-untrusted" ||
      typeof item.output !== "string" ||
      new TextEncoder().encode(item.output).byteLength > 64 * 1024 ||
      typeof item.success !== "boolean" ||
      typeof item.truncated !== "boolean" ||
      (item.truncated && item.success)
    )
      throw new Error("Inventario nativo non valido.");
    return item as unknown as NativeObservation;
  });
}

export async function authorizeObserve(
  request: ObserveAuthorization,
): Promise<void> {
  if (isNative()) {
    await invoke("authorize_observe", { request });
    return;
  }
  if (!hasLocalCollector())
    throw new Error("Il broker locale non è disponibile.");
  for (let attempt = 0; attempt < 5; attempt += 1) {
    const response = await fetch("/api/authorize-observe", {
      method: "POST",
      cache: "no-store",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(request),
      signal: AbortSignal.timeout(20_000),
    });
    if (response.status === 429 && attempt < 4) {
      await delay(retryAfterMilliseconds(response.headers.get("Retry-After")));
      continue;
    }
    if (!response.ok) {
      const result = (await response.json().catch(() => null)) as {
        error?: string;
      } | null;
      throw new Error(result?.error ?? `broker HTTP ${response.status}`);
    }
    return;
  }
  throw new Error("broker HTTP 429");
}

export async function getSecureRuntimeStatus(): Promise<SecureRuntimeStatus> {
  if (!isNative())
    throw new Error("Il runtime sicuro richiede KernAid Resident.");
  return parseSecureRuntimeStatus(await invoke("secure_runtime_status"));
}

export async function initializeDeviceIdentity(): Promise<SecureRuntimeStatus> {
  if (!isNative())
    throw new Error("Il runtime sicuro richiede KernAid Resident.");
  return parseSecureRuntimeStatus(await invoke("initialize_device_identity"));
}

export function secureAuditReady(status: SecureRuntimeStatus): boolean {
  return status.audit === "secure" && status.signing === "ready";
}

export class NativeAuditSink implements AuditSink {
  readonly status: AuditSinkStatus = SECURE_AUDIT_STATUS;
  readonly #pendingReports = new Map<
    string,
    AuditRecord & { type: "report" }
  >();

  async append(value: AuditRecord): Promise<void> {
    const record = parseAuditRecord(value);
    if (this.#pendingReports.has(record.sessionId))
      throw new Error("Un report di audit è già in attesa di firma.");
    if (record.type === "report") {
      this.#pendingReports.set(record.sessionId, record);
      return;
    }
    await invoke("append_audit_record", { record });
  }

  async sealReport(value: AuditSealRequest): Promise<ArtifactRef> {
    const request = parseAuditSealRequest(value);
    const record = this.#pendingReports.get(request.sessionId);
    if (
      record === undefined ||
      record.payload.format !== request.format ||
      record.payload.payloadMediaType !== request.payloadMediaType ||
      record.payload.payloadSha256 !== request.payloadSha256
    ) {
      this.#pendingReports.delete(request.sessionId);
      throw new Error(
        "Il report non corrisponde al record di audit in attesa.",
      );
    }
    let result: NativeSignedArtifact;
    try {
      result = await parseNativeSignedArtifact(
        await invoke("seal_signed_report", { record, request }),
        request,
      );
    } finally {
      this.#pendingReports.delete(request.sessionId);
    }
    const uri = `data:${SIGNED_REPORT_MEDIA_TYPE};base64,${btoa(result.containerJson)}`;
    return parseArtifactRef({
      mediaType: result.mediaType,
      payloadMediaType: result.payloadMediaType,
      uri,
      sha256: result.sha256,
      payloadSha256: result.payloadSha256,
      auditStatus: this.status,
    });
  }
}

export class PlatformOfflineRulesProvider implements Provider {
  readonly capabilities = Object.freeze({
    streaming: false,
    structuredOutput: true,
    toolRequests: false,
    local: true,
  });
  readonly #fallback = new OfflineRulesProvider();

  async diagnose(
    objective: string,
    evidence: readonly ObservedEvidence[],
  ): Promise<DiagnosisProposal> {
    if (!objective.trim()) throw new Error("objective is required");
    const linuxEvidence = evidence.filter((item) =>
      LINUX_P0_COLLECTORS.includes(
        item.evidence.collector as (typeof LINUX_P0_COLLECTORS)[number],
      ),
    );

    // The browser-based Rescue shell currently observes the live appliance,
    // not an installed operating system. Never present those observations as
    // a diagnosis of the customer's disk.
    if (hasLocalCollector() && !isNative())
      return parseDiagnosisProposal({
        schemaVersion: "1.0",
        diagnosis:
          "Inventario dell’ambiente Rescue completato. L’OS installato non è stato montato né analizzato: non è possibile formulare una diagnosi del sistema del cliente da queste sole evidenze.",
        confidence: 0.2,
        evidenceIds: evidence.map((item) => item.evidence.id),
        requestedEvidence: ["rescue.installed-target.read-only.v1"],
      });

    if (linuxEvidence.length === 0)
      return this.#fallback.diagnose(objective, evidence);

    const selected = LINUX_P0_COLLECTORS.map((collector) =>
      evidence.find((item) => item.evidence.collector === collector),
    );
    const complete =
      selected.every((item) => item !== undefined) &&
      LINUX_P0_COLLECTORS.every(
        (collector) =>
          evidence.filter((item) => item.evidence.collector === collector)
            .length === 1,
      );
    const successful = selected.every(
      (item) => item?.evidence.summary === "Comando di inventario completato",
    );
    if (!complete || !successful) {
      const requestedEvidence = LINUX_P0_COLLECTORS.filter((collector) => {
        const matches = evidence.filter(
          (item) => item.evidence.collector === collector,
        );
        return (
          matches.length !== 1 ||
          matches[0]?.evidence.summary !== "Comando di inventario completato"
        );
      });
      return parseDiagnosisProposal({
        schemaVersion: "1.0",
        diagnosis:
          "Diagnosi Linux incompleta: una o più evidenze P0 richieste non sono disponibili o affidabili. Nessuna conclusione sullo stato del sistema viene formulata.",
        confidence: 0.1,
        evidenceIds: linuxEvidence.map((item) => item.evidence.id),
        requestedEvidence,
      });
    }

    const documents = selected.map((item) => ({
      id: item!.evidence.id,
      collector: item!.evidence.collector,
      content: item!.content,
    }));
    const response = await invoke("diagnose_linux_p0", {
      evidence: documents,
    });
    return parseDiagnosisProposal(response);
  }
}

export function parseSecureRuntimeStatus(value: unknown): SecureRuntimeStatus {
  const item = exactRecord(
    value,
    ["schemaVersion", "audit", "signing", "persistentAuditStarted", "deviceId"],
    true,
  );
  if (
    item.schemaVersion !== "1.0" ||
    !(
      item.audit === "secure" ||
      item.audit === "unavailable" ||
      item.audit === "blocked"
    ) ||
    !(
      item.signing === "ready" ||
      item.signing === "uninitialized" ||
      item.signing === "unavailable" ||
      item.signing === "blocked"
    ) ||
    typeof item.persistentAuditStarted !== "boolean" ||
    (item.deviceId !== undefined &&
      (typeof item.deviceId !== "string" ||
        !/^KA-[a-f0-9]{24}$/.test(item.deviceId))) ||
    (item.signing === "ready") !== (typeof item.deviceId === "string")
  )
    throw new Error("Stato del runtime sicuro non valido.");
  return structuredClone(item) as unknown as SecureRuntimeStatus;
}

export async function parseNativeSignedArtifact(
  value: unknown,
  request: AuditSealRequest,
): Promise<NativeSignedArtifact> {
  const item = exactRecord(value, [
    "mediaType",
    "payloadMediaType",
    "containerJson",
    "sha256",
    "payloadSha256",
    "envelopeSchema",
  ]);
  if (
    item.mediaType !== SIGNED_REPORT_MEDIA_TYPE ||
    item.payloadMediaType !== request.payloadMediaType ||
    item.payloadSha256 !== request.payloadSha256 ||
    item.envelopeSchema !== SIGNED_REPORT_SCHEMA ||
    typeof item.containerJson !== "string" ||
    !/^[\x20-\x7e]+$/.test(item.containerJson) ||
    typeof item.sha256 !== "string" ||
    !/^[a-f0-9]{64}$/.test(item.sha256)
  )
    throw new Error("Contenitore firmato non valido.");

  const containerJson = item.containerJson;
  const envelope = exactRecord(JSON.parse(containerJson) as unknown, [
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
  ]);
  if (
    envelope.schema !== SIGNED_REPORT_SCHEMA ||
    envelope.kind !== "kernaid.signed-report" ||
    envelope.algorithm !== "Ed25519" ||
    typeof envelope.deviceId !== "string" ||
    !/^KA-[a-f0-9]{24}$/.test(envelope.deviceId) ||
    !Number.isSafeInteger(envelope.journalSequence) ||
    Number(envelope.journalSequence) < 1 ||
    envelope.payloadMediaType !== request.payloadMediaType ||
    typeof envelope.journalEntryHash !== "string" ||
    decodeBase64Url(envelope.journalEntryHash, 32) === undefined ||
    typeof envelope.publicKey !== "string" ||
    decodeBase64Url(envelope.publicKey, 32) === undefined ||
    typeof envelope.signature !== "string" ||
    decodeBase64Url(envelope.signature, 64) === undefined ||
    typeof envelope.payloadSha256 !== "string" ||
    !bytesEqual(
      decodeBase64Url(envelope.payloadSha256, 32),
      hexBytes(request.payloadSha256),
    ) ||
    typeof envelope.payload !== "string" ||
    !bytesEqual(
      decodeBase64Url(envelope.payload),
      new TextEncoder().encode(request.body),
    )
  )
    throw new Error("Envelope firmato non valido.");

  if ((await sha256(containerJson)) !== item.sha256)
    throw new Error("Impronta del contenitore firmato non valida.");
  return item as unknown as NativeSignedArtifact;
}

function exactRecord(
  value: unknown,
  keys: readonly string[],
  optionalLast = false,
): Record<string, unknown> {
  if (typeof value !== "object" || value === null || Array.isArray(value))
    throw new Error("Risposta nativa non valida.");
  const item = value as Record<string, unknown>;
  const required = optionalLast ? keys.slice(0, -1) : keys;
  const allowed = new Set(keys);
  if (
    required.some((key) => !Object.hasOwn(item, key)) ||
    Object.keys(item).some((key) => !allowed.has(key))
  )
    throw new Error("Risposta nativa non valida.");
  return item;
}

function decodeBase64Url(
  value: string,
  expectedLength?: number,
): Uint8Array | undefined {
  if (!/^[A-Za-z0-9_-]*$/.test(value)) return undefined;
  try {
    const padding = "=".repeat((4 - (value.length % 4)) % 4);
    const decoded = atob(
      value.replaceAll("-", "+").replaceAll("_", "/") + padding,
    );
    const bytes = Uint8Array.from(decoded, (character) =>
      character.charCodeAt(0),
    );
    if (expectedLength !== undefined && bytes.byteLength !== expectedLength)
      return undefined;
    if (encodeBase64Url(bytes) !== value) return undefined;
    return bytes;
  } catch {
    return undefined;
  }
}

function encodeBase64Url(value: Uint8Array): string {
  const binary = bytesToBinary(value);
  return btoa(binary)
    .replaceAll("+", "-")
    .replaceAll("/", "_")
    .replace(/=+$/u, "");
}

function bytesToBinary(value: Uint8Array): string {
  let result = "";
  for (let offset = 0; offset < value.byteLength; offset += 32 * 1024)
    result += String.fromCharCode(
      ...value.subarray(offset, offset + 32 * 1024),
    );
  return result;
}

function hexBytes(value: string): Uint8Array {
  return Uint8Array.from({ length: value.length / 2 }, (_, index) =>
    Number.parseInt(value.slice(index * 2, index * 2 + 2), 16),
  );
}

function bytesEqual(left: Uint8Array | undefined, right: Uint8Array): boolean {
  if (left === undefined || left.byteLength !== right.byteLength) return false;
  return left.every((byte, index) => byte === right[index]);
}

async function sha256(value: string): Promise<string> {
  const digest = await crypto.subtle.digest(
    "SHA-256",
    new TextEncoder().encode(value),
  );
  return Array.from(new Uint8Array(digest), (byte) =>
    byte.toString(16).padStart(2, "0"),
  ).join("");
}

function retryAfterMilliseconds(value: string | null): number {
  if (value === null || !/^\d{1,3}$/.test(value)) return 250;
  return Math.min(2_000, Math.max(50, Number(value) * 1_000));
}

function delay(milliseconds: number): Promise<void> {
  return new Promise((resolve) => globalThis.setTimeout(resolve, milliseconds));
}
