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
const RESCUE_TARGET_API_VERSION = "kernaid.dev/rescue-targets/v1alpha1";
const MAX_INVENTORY_RESPONSE_BYTES = 2 * 1024 * 1024;
const MAX_RESCUE_TARGET_RESPONSE_BYTES = 64 * 1024;
const MAX_NATIVE_OBSERVATION_BYTES = 64 * 1024;
const MAX_QUALIFIED_WINDOWS_OBSERVATION_BYTES = 1024 * 1024;
const DISK_REF = /^disk-[1-9][0-9]{0,2}$/u;
const VOLUME_REF = /^disk-[1-9][0-9]{0,2}\/volume-[1-9][0-9]{0,2}$/u;
const PUBLIC_TOKEN = /^[a-z0-9][a-z0-9-]{0,63}$/u;
const FILESYSTEM_TOKEN = /^[a-z0-9][a-z0-9_-]{0,63}$/u;
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
const WINDOWS_P0_COLLECTORS = [
  "windows.event-log.window",
  "windows.reliability.records",
  "windows.component-store.check-health",
  "windows.sfc.verify-only",
  "windows.update.state",
  "windows.services.state",
  "windows.network.state",
  "windows.drivers.state",
  "windows.bitlocker.state",
  "windows.boot.state",
  "windows.volumes.state",
] as const;
const QUALIFIED_LARGE_WINDOWS_COLLECTORS = new Set<string>([
  ...WINDOWS_P0_COLLECTORS,
  "windows.storage.identity",
]);
const SFC_NOT_RUN_SUMMARY = "Evidenza P0 esplicita: SFC non eseguito";

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

export interface RescueTargetVolume {
  ref: string;
  parentRef: string;
  kind:
    | "partition"
    | "logical-volume"
    | "encrypted-mapping"
    | "whole-disk-filesystem"
    | "raid-volume"
    | "other";
  sizeBytes: number;
  filesystem: string;
  mediaReadOnly: boolean;
  mounted: boolean;
  encrypted: boolean;
}

export interface RescueTargetDisk {
  id: string;
  ref: string;
  sizeBytes: number;
  transport: string;
  partitionTable: string;
  mediaReadOnly: boolean;
  removable: boolean;
  mounted: boolean;
  selectionEligible: boolean;
  exclusionReasons: string[];
  volumes: RescueTargetVolume[];
}

export interface RescueTargetCandidate {
  targetId: string;
  sourceRef: string;
  diskId: string;
  osFamilyHint: "linux" | "windows" | "macos" | "unknown-encrypted" | "unknown";
  confidence: "low";
  status: "unverified-installation-candidate";
  detectionBasis: string[];
  requiresUnlock: boolean;
  inspectionMode: "metadata-only-no-mount";
  selectionEligible: true;
}

export interface RescueTargetScan {
  apiVersion: typeof RESCUE_TARGET_API_VERSION;
  mode: "observe-r0";
  trust: "observed-untrusted";
  scanFingerprint: string;
  identifierScope: "ephemeral-rescue-process";
  disks: RescueTargetDisk[];
  candidates: RescueTargetCandidate[];
  claims: {
    installedOsConfirmed: false;
    filesystemContentInspected: false;
    mountOperationPerformed: false;
    mutationPerformed: false;
    rawDeviceIdentifiersReturned: false;
  };
  limitations: string[];
}

export interface RescueTargetSelection {
  apiVersion: typeof RESCUE_TARGET_API_VERSION;
  status: "observe-target-validated";
  scanFingerprint: string;
  target: RescueTargetCandidate;
  claims: {
    installedOsConfirmed: false;
    filesystemContentInspected: false;
    mountOperationPerformed: false;
    mutationPerformed: false;
  };
}

export interface RescueTargetBinding {
  scanFingerprint: string;
  target: RescueTargetCandidate;
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
      return parseNativeObservations(
        await readBoundedJson(response, MAX_INVENTORY_RESPONSE_BYTES),
      );
    }
    throw new Error("collector HTTP 429");
  }
  return [];
}

export async function collectWindowsP0Inventory(): Promise<
  NativeObservation[]
> {
  if (!isNative())
    throw new Error("La raccolta P0 Windows richiede KernAid Resident.");
  return parseNativeObservations(await invoke("collect_windows_p0_inventory"));
}

export function isRescueRuntime(): boolean {
  return hasLocalCollector() && !isNative();
}

export async function scanRescueInstalledTargets(): Promise<RescueTargetScan> {
  if (!isRescueRuntime())
    throw new Error("La selezione del target richiede KernAid Rescue.");
  for (let attempt = 0; attempt < 5; attempt += 1) {
    const response = await fetch("/api/rescue/installed-targets", {
      cache: "no-store",
      signal: AbortSignal.timeout(20_000),
    });
    if (response.status === 429 && attempt < 4) {
      await delay(retryAfterMilliseconds(response.headers.get("Retry-After")));
      continue;
    }
    if (!response.ok) throw new Error(`target scan HTTP ${response.status}`);
    return parseRescueTargetScan(
      await readBoundedJson(response, MAX_RESCUE_TARGET_RESPONSE_BYTES),
    );
  }
  throw new Error("target scan HTTP 429");
}

export async function selectRescueInstalledTarget(
  scanFingerprint: string,
  expectedTarget: RescueTargetCandidate,
): Promise<RescueTargetSelection> {
  if (!isRescueRuntime())
    throw new Error("La selezione del target richiede KernAid Rescue.");
  const target = parseRescueCandidate(expectedTarget);
  if (
    !/^scan:[a-f0-9]{64}$/u.test(scanFingerprint) ||
    !/^target:[a-f0-9]{64}$/u.test(target.targetId)
  )
    throw new Error("Identità del target Rescue non valida.");
  const response = await fetch("/api/rescue/select-installed-target", {
    method: "POST",
    cache: "no-store",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ scanFingerprint, targetId: target.targetId }),
    signal: AbortSignal.timeout(20_000),
  });
  if (!response.ok) throw new Error(`target selection HTTP ${response.status}`);
  const selection = parseRescueTargetSelection(
    await readBoundedJson(response, MAX_RESCUE_TARGET_RESPONSE_BYTES),
  );
  if (
    selection.scanFingerprint !== scanFingerprint ||
    !sameRescueCandidate(selection.target, target)
  )
    throw new Error("La risposta Rescue non corrisponde al target richiesto.");
  return selection;
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
      new TextEncoder().encode(item.output).byteLength >
        (QUALIFIED_LARGE_WINDOWS_COLLECTORS.has(item.collector)
          ? MAX_QUALIFIED_WINDOWS_OBSERVATION_BYTES
          : MAX_NATIVE_OBSERVATION_BYTES) ||
      typeof item.success !== "boolean" ||
      typeof item.truncated !== "boolean" ||
      (item.truncated && item.success)
    )
      throw new Error("Inventario nativo non valido.");
    return item as unknown as NativeObservation;
  });
}

export function parseRescueTargetScan(value: unknown): RescueTargetScan {
  const item = exactRecord(value, [
    "apiVersion",
    "mode",
    "trust",
    "scanFingerprint",
    "identifierScope",
    "disks",
    "candidates",
    "claims",
    "limitations",
  ]);
  if (
    item.apiVersion !== RESCUE_TARGET_API_VERSION ||
    item.mode !== "observe-r0" ||
    item.trust !== "observed-untrusted" ||
    typeof item.scanFingerprint !== "string" ||
    !/^scan:[a-f0-9]{64}$/u.test(item.scanFingerprint) ||
    item.identifierScope !== "ephemeral-rescue-process" ||
    !Array.isArray(item.disks) ||
    item.disks.length > 128 ||
    !Array.isArray(item.candidates) ||
    item.candidates.length > 128 ||
    !Array.isArray(item.limitations) ||
    item.limitations.length === 0 ||
    item.limitations.length > 16 ||
    !falseClaims(item.claims, true)
  )
    throw new Error("Scansione target Rescue non valida.");

  const limitations = parseTokenList(item.limitations, 16);
  const disks = item.disks.map(parseRescueDisk);
  const diskIds = new Set(disks.map((disk) => disk.id));
  const diskRefs = new Set(disks.map((disk) => disk.ref));
  if (diskIds.size !== disks.length || diskRefs.size !== disks.length)
    throw new Error("Scansione target Rescue non valida.");
  const sourceOwners = new Map<string, string>();
  for (const disk of disks) {
    sourceOwners.set(disk.ref, disk.id);
    for (const volume of disk.volumes) sourceOwners.set(volume.ref, disk.id);
  }
  const candidates = item.candidates.map((candidate) =>
    parseRescueCandidate(candidate),
  );
  const targetIds = new Set<string>();
  for (const candidate of candidates) {
    if (
      targetIds.has(candidate.targetId) ||
      !diskIds.has(candidate.diskId) ||
      sourceOwners.get(candidate.sourceRef) !== candidate.diskId
    )
      throw new Error("Scansione target Rescue non valida.");
    const disk = disks.find((entry) => entry.id === candidate.diskId);
    if (disk === undefined || !disk.selectionEligible)
      throw new Error("Scansione target Rescue non valida.");
    targetIds.add(candidate.targetId);
  }
  return structuredClone({
    apiVersion: item.apiVersion,
    mode: item.mode,
    trust: item.trust,
    scanFingerprint: item.scanFingerprint,
    identifierScope: item.identifierScope,
    disks,
    candidates,
    claims: item.claims,
    limitations,
  }) as RescueTargetScan;
}

export function parseRescueTargetSelection(
  value: unknown,
): RescueTargetSelection {
  const item = exactRecord(value, [
    "apiVersion",
    "status",
    "scanFingerprint",
    "target",
    "claims",
  ]);
  if (
    item.apiVersion !== RESCUE_TARGET_API_VERSION ||
    item.status !== "observe-target-validated" ||
    typeof item.scanFingerprint !== "string" ||
    !/^scan:[a-f0-9]{64}$/u.test(item.scanFingerprint) ||
    !falseClaims(item.claims, false)
  )
    throw new Error("Selezione target Rescue non valida.");
  return structuredClone({
    apiVersion: item.apiVersion,
    status: item.status,
    scanFingerprint: item.scanFingerprint,
    target: parseRescueCandidate(item.target),
    claims: item.claims,
  }) as RescueTargetSelection;
}

function parseRescueDisk(value: unknown): RescueTargetDisk {
  const item = exactRecord(value, [
    "id",
    "ref",
    "sizeBytes",
    "transport",
    "partitionTable",
    "mediaReadOnly",
    "removable",
    "mounted",
    "selectionEligible",
    "exclusionReasons",
    "volumes",
  ]);
  if (
    typeof item.id !== "string" ||
    !/^disk:[a-f0-9]{64}$/u.test(item.id) ||
    typeof item.ref !== "string" ||
    !DISK_REF.test(item.ref) ||
    !safeSize(item.sizeBytes) ||
    typeof item.transport !== "string" ||
    !PUBLIC_TOKEN.test(item.transport) ||
    typeof item.partitionTable !== "string" ||
    !PUBLIC_TOKEN.test(item.partitionTable) ||
    typeof item.mediaReadOnly !== "boolean" ||
    typeof item.removable !== "boolean" ||
    typeof item.mounted !== "boolean" ||
    typeof item.selectionEligible !== "boolean" ||
    !Array.isArray(item.exclusionReasons) ||
    item.exclusionReasons.length > 8 ||
    !Array.isArray(item.volumes) ||
    item.volumes.length > 128
  )
    throw new Error("Disco target Rescue non valido.");
  const exclusionReasons = parseTokenList(item.exclusionReasons, 8);
  if (
    item.selectionEligible !== (exclusionReasons.length === 0) ||
    (item.mounted && item.selectionEligible) ||
    (item.sizeBytes === 0 && item.selectionEligible)
  )
    throw new Error("Disco target Rescue non valido.");
  const volumes = item.volumes.map(parseRescueVolume);
  if (volumes.some((volume) => volume.mounted) && !item.mounted)
    throw new Error("Topologia target Rescue non valida.");
  const references = new Set([item.ref]);
  for (const volume of volumes) {
    if (references.has(volume.ref) || !references.has(volume.parentRef))
      throw new Error("Topologia target Rescue non valida.");
    references.add(volume.ref);
  }
  return {
    id: item.id,
    ref: item.ref,
    sizeBytes: item.sizeBytes,
    transport: item.transport,
    partitionTable: item.partitionTable,
    mediaReadOnly: item.mediaReadOnly,
    removable: item.removable,
    mounted: item.mounted,
    selectionEligible: item.selectionEligible,
    exclusionReasons,
    volumes,
  } as RescueTargetDisk;
}

function parseRescueVolume(value: unknown): RescueTargetVolume {
  const item = exactRecord(value, [
    "ref",
    "parentRef",
    "kind",
    "sizeBytes",
    "filesystem",
    "mediaReadOnly",
    "mounted",
    "encrypted",
  ]);
  const kinds = new Set([
    "partition",
    "logical-volume",
    "encrypted-mapping",
    "whole-disk-filesystem",
    "raid-volume",
    "other",
  ]);
  if (
    typeof item.ref !== "string" ||
    !VOLUME_REF.test(item.ref) ||
    typeof item.parentRef !== "string" ||
    (!DISK_REF.test(item.parentRef) && !VOLUME_REF.test(item.parentRef)) ||
    typeof item.kind !== "string" ||
    !kinds.has(item.kind) ||
    !safeSize(item.sizeBytes) ||
    typeof item.filesystem !== "string" ||
    !FILESYSTEM_TOKEN.test(item.filesystem) ||
    typeof item.mediaReadOnly !== "boolean" ||
    typeof item.mounted !== "boolean" ||
    typeof item.encrypted !== "boolean"
  )
    throw new Error("Volume target Rescue non valido.");
  return item as unknown as RescueTargetVolume;
}

function parseRescueCandidate(value: unknown): RescueTargetCandidate {
  const item = exactRecord(value, [
    "targetId",
    "sourceRef",
    "diskId",
    "osFamilyHint",
    "confidence",
    "status",
    "detectionBasis",
    "requiresUnlock",
    "inspectionMode",
    "selectionEligible",
  ]);
  const families = new Set([
    "linux",
    "windows",
    "macos",
    "unknown-encrypted",
    "unknown",
  ]);
  if (
    typeof item.targetId !== "string" ||
    !/^target:[a-f0-9]{64}$/u.test(item.targetId) ||
    typeof item.sourceRef !== "string" ||
    (!DISK_REF.test(item.sourceRef) && !VOLUME_REF.test(item.sourceRef)) ||
    typeof item.diskId !== "string" ||
    !/^disk:[a-f0-9]{64}$/u.test(item.diskId) ||
    typeof item.osFamilyHint !== "string" ||
    !families.has(item.osFamilyHint) ||
    item.confidence !== "low" ||
    item.status !== "unverified-installation-candidate" ||
    !Array.isArray(item.detectionBasis) ||
    item.detectionBasis.length === 0 ||
    item.detectionBasis.length > 8 ||
    typeof item.requiresUnlock !== "boolean" ||
    item.inspectionMode !== "metadata-only-no-mount" ||
    item.selectionEligible !== true
  )
    throw new Error("Candidato target Rescue non valido.");
  return {
    ...item,
    detectionBasis: parseTokenList(item.detectionBasis, 8),
  } as RescueTargetCandidate;
}

function sameRescueCandidate(
  left: RescueTargetCandidate,
  right: RescueTargetCandidate,
): boolean {
  return (
    left.targetId === right.targetId &&
    left.sourceRef === right.sourceRef &&
    left.diskId === right.diskId &&
    left.osFamilyHint === right.osFamilyHint &&
    left.confidence === right.confidence &&
    left.status === right.status &&
    left.requiresUnlock === right.requiresUnlock &&
    left.inspectionMode === right.inspectionMode &&
    left.selectionEligible === right.selectionEligible &&
    left.detectionBasis.length === right.detectionBasis.length &&
    left.detectionBasis.every(
      (basis, index) => basis === right.detectionBasis[index],
    )
  );
}

function falseClaims(value: unknown, includeRawIdentifiers: boolean): boolean {
  const keys = [
    "installedOsConfirmed",
    "filesystemContentInspected",
    "mountOperationPerformed",
    "mutationPerformed",
    ...(includeRawIdentifiers ? ["rawDeviceIdentifiersReturned"] : []),
  ];
  try {
    const claims = exactRecord(value, keys);
    return keys.every((key) => claims[key] === false);
  } catch {
    return false;
  }
}

function parseTokenList(value: unknown[], maximum: number): string[] {
  if (
    value.length > maximum ||
    value.some((item) => typeof item !== "string" || !PUBLIC_TOKEN.test(item))
  )
    throw new Error("Metadati target Rescue non validi.");
  const result = value as string[];
  if (new Set(result).size !== result.length)
    throw new Error("Metadati target Rescue duplicati.");
  return [...result];
}

function safeSize(value: unknown): value is number {
  return typeof value === "number" && Number.isSafeInteger(value) && value >= 0;
}

export async function authorizeObserve(
  request: ObserveAuthorization,
  rescueTarget?: RescueTargetBinding,
): Promise<void> {
  if (isNative()) {
    if (rescueTarget !== undefined)
      throw new Error("Un target Rescue non è valido nel runtime Resident.");
    await invoke("authorize_observe", { request });
    return;
  }
  if (!hasLocalCollector())
    throw new Error("Il broker locale non è disponibile.");
  if (!isRescueRuntime() || rescueTarget === undefined)
    throw new Error("Il target Rescue della sessione non è disponibile.");
  const target = parseRescueCandidate(rescueTarget.target);
  if (!/^scan:[a-f0-9]{64}$/u.test(rescueTarget.scanFingerprint))
    throw new Error("Il target Rescue della sessione non è valido.");
  for (let attempt = 0; attempt < 5; attempt += 1) {
    const response = await fetch("/api/authorize-observe", {
      method: "POST",
      cache: "no-store",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        ...request,
        rescueTarget: {
          scanFingerprint: rescueTarget.scanFingerprint,
          targetId: target.targetId,
        },
      }),
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
    const windowsEvidence = evidence.filter((item) =>
      WINDOWS_P0_COLLECTORS.includes(
        item.evidence.collector as (typeof WINDOWS_P0_COLLECTORS)[number],
      ),
    );

    // Rescue observations remain metadata-only until a dedicated read-only
    // filesystem inspector is qualified. Never present appliance inventory or
    // a low-confidence selection as a diagnosis of the customer's OS.
    if (isRescueRuntime()) {
      const selectionEvidence = evidence.filter(
        (item) =>
          item.evidence.collector === "rescue.installed-target.selection",
      );
      let selectedTarget: RescueTargetSelection | undefined;
      let invalidSelection = selectionEvidence.length > 1;
      if (selectionEvidence.length === 1) {
        const item = selectionEvidence[0]!;
        if (
          item.evidence.target !== "selected-installed-target-candidate" ||
          item.evidence.contentType !== "application/json" ||
          new TextEncoder().encode(item.content).byteLength >
            MAX_RESCUE_TARGET_RESPONSE_BYTES
        )
          invalidSelection = true;
        else {
          try {
            selectedTarget = parseRescueTargetSelection(
              JSON.parse(item.content) as unknown,
            );
          } catch {
            invalidSelection = true;
          }
        }
      }
      if (invalidSelection)
        return parseDiagnosisProposal({
          schemaVersion: "1.0",
          diagnosis:
            "Evidenza di selezione del target Rescue non valida o ambigua. La sessione resta bloccata e nessuna conclusione sul sistema installato viene formulata.",
          confidence: 0.1,
          evidenceIds: selectionEvidence.map((item) => item.evidence.id),
          requestedEvidence: ["rescue.installed-target.selection.v1"],
        });
      return parseDiagnosisProposal({
        schemaVersion: "1.0",
        diagnosis: selectedTarget
          ? "Candidato target Rescue selezionato e rivalidato usando soli metadati storage. Il filesystem non è stato montato e il contenuto dell’OS installato non è stato analizzato: non è ancora possibile formulare una diagnosi del sistema del cliente."
          : "Inventario dell’ambiente Rescue completato. Nessun target installato è stato selezionato, montato o analizzato: non è possibile formulare una diagnosi del sistema del cliente da queste sole evidenze.",
        confidence: 0.2,
        evidenceIds: evidence.map((item) => item.evidence.id),
        requestedEvidence: [
          selectedTarget
            ? "rescue.installed-target.filesystem-content.read-only.v1"
            : "rescue.installed-target.selection.v1",
        ],
      });
    }

    if (windowsEvidence.length > 0) {
      const selected = WINDOWS_P0_COLLECTORS.map((collector) =>
        evidence.find((item) => item.evidence.collector === collector),
      );
      const complete =
        selected.every((item) => item !== undefined) &&
        WINDOWS_P0_COLLECTORS.every(
          (collector) =>
            evidence.filter((item) => item.evidence.collector === collector)
              .length === 1,
        );
      const successful = selected.every((item) =>
        isSuccessfulWindowsEvidence(item),
      );
      if (!complete || !successful) {
        const requestedEvidence = WINDOWS_P0_COLLECTORS.filter((collector) => {
          const matches = evidence.filter(
            (item) => item.evidence.collector === collector,
          );
          return (
            matches.length !== 1 || !isSuccessfulWindowsEvidence(matches[0])
          );
        });
        return parseDiagnosisProposal({
          schemaVersion: "1.0",
          diagnosis:
            "Diagnosi Windows incompleta: una o più evidenze P0 richieste non sono disponibili o affidabili. Nessuna conclusione sullo stato del sistema viene formulata.",
          confidence: 0.1,
          evidenceIds: windowsEvidence.map((item) => item.evidence.id),
          requestedEvidence,
        });
      }
      const documents = selected.map((item) => ({
        id: item!.evidence.id,
        collector: item!.evidence.collector,
        content: item!.content,
      }));
      return parseDiagnosisProposal(
        await invoke("diagnose_windows_p0", { evidence: documents }),
      );
    }

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

function isSuccessfulWindowsEvidence(
  item: ObservedEvidence | undefined,
): boolean {
  if (item === undefined) return false;
  return (
    item.evidence.summary === "Comando di inventario completato" ||
    (item.evidence.collector === "windows.sfc.verify-only" &&
      item.evidence.summary === SFC_NOT_RUN_SUMMARY)
  );
}

export async function fingerprintNativeTarget(
  observations: readonly NativeObservation[],
  rescueTarget?: RescueTargetBinding,
): Promise<string> {
  const identity = observations.filter((item) =>
    isNativeIdentityCollector(item.collector),
  );
  const canonicalInventory = identity
    .map((item) => `${item.collector}\0${item.output}`)
    .join("\0");
  const inventoryFingerprint = `sha256:${await sha256(canonicalInventory)}`;
  if (rescueTarget === undefined) return inventoryFingerprint;
  return fingerprintRescueTarget(inventoryFingerprint, rescueTarget);
}

export function isNativeIdentityCollector(collector: string): boolean {
  return /hostname|block\.inventory|\.disks$|\.system$|\.storage\.identity$/u.test(
    collector,
  );
}

export async function fingerprintRescueTarget(
  inventoryFingerprint: string,
  rescueTarget: RescueTargetBinding,
): Promise<string> {
  if (!/^sha256:[a-f0-9]{64}$/u.test(inventoryFingerprint))
    throw new Error("Il fingerprint dell’inventario Rescue non è valido.");
  if (!/^scan:[a-f0-9]{64}$/u.test(rescueTarget.scanFingerprint))
    throw new Error("Il binding del target Rescue non è valido.");
  const target = parseRescueCandidate(rescueTarget.target);
  const composite = [
    "kernaid-rescue-observe-target-v1",
    inventoryFingerprint,
    rescueTarget.scanFingerprint,
    target.targetId,
    canonicalJson(target),
  ].join("\0");
  return `sha256:${await sha256(composite)}`;
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

async function readBoundedJson(
  response: Response,
  maximumBytes: number,
): Promise<unknown> {
  const declared = response.headers.get("Content-Length");
  if (
    declared !== null &&
    (!/^\d+$/u.test(declared) || Number(declared) > maximumBytes)
  )
    throw new Error("Risposta locale oltre il limite di sicurezza.");
  if (response.body === null)
    throw new Error("Risposta locale priva di contenuto.");

  const reader = response.body.getReader();
  const chunks: Uint8Array[] = [];
  let total = 0;
  try {
    while (true) {
      const result = await reader.read();
      if (result.done) break;
      total += result.value.byteLength;
      if (total > maximumBytes) {
        await reader.cancel();
        throw new Error("Risposta locale oltre il limite di sicurezza.");
      }
      chunks.push(result.value);
    }
  } finally {
    reader.releaseLock();
  }
  const bytes = new Uint8Array(total);
  let offset = 0;
  for (const chunk of chunks) {
    bytes.set(chunk, offset);
    offset += chunk.byteLength;
  }
  let text: string;
  try {
    text = new TextDecoder("utf-8", { fatal: true }).decode(bytes);
    return JSON.parse(text) as unknown;
  } catch {
    throw new Error("Risposta locale JSON non valida.");
  }
}

function retryAfterMilliseconds(value: string | null): number {
  if (value === null || !/^\d{1,3}$/.test(value)) return 250;
  return Math.min(2_000, Math.max(50, Number(value) * 1_000));
}

function canonicalJson(value: RescueTargetCandidate): string {
  // This order is the lexical key order used by the Rescue server's
  // recursive sort_keys canonicalization. Candidate strings are restricted to
  // ASCII by parseRescueCandidate, so JSON escaping is identical in JS/Python.
  return JSON.stringify({
    confidence: value.confidence,
    detectionBasis: value.detectionBasis,
    diskId: value.diskId,
    inspectionMode: value.inspectionMode,
    osFamilyHint: value.osFamilyHint,
    requiresUnlock: value.requiresUnlock,
    selectionEligible: value.selectionEligible,
    sourceRef: value.sourceRef,
    status: value.status,
    targetId: value.targetId,
  });
}

function delay(milliseconds: number): Promise<void> {
  return new Promise((resolve) => globalThis.setTimeout(resolve, milliseconds));
}
