import { invoke } from "@tauri-apps/api/core";
import {
  OfflineRulesProvider,
  ProviderError,
  type ObservedEvidence,
  type Provider,
  type ProviderRequestOptions,
} from "@kernaid/agent-gateway";
import {
  LINUX_NORMALIZED_SNAPSHOT_COLLECTOR,
  LINUX_NORMALIZED_SNAPSHOT_CONTENT_TYPE,
  LINUX_NORMALIZED_SNAPSHOT_HASH_DOMAIN,
  MAX_LINUX_NORMALIZED_SNAPSHOT_BYTES,
  canonicalLinuxSnapshotJson,
  parseDiagnosisProposal,
  parseLinuxNormalizedSnapshot,
  parseLinuxNormalizedSnapshotEnvelope,
  parseLinuxNormalizedSnapshotEnvelopeJson,
  type DiagnosisProposal,
  type LinuxNormalizedSnapshot,
  type LinuxNormalizedSnapshotEnvelope,
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
const RESCUE_INSPECTION_API_VERSION =
  "kernaid.dev/rescue-offline-inspection/v1alpha1";
export const RESCUE_OFFLINE_EVIDENCE_COLLECTOR =
  "rescue.installed-target.filesystem-content.read-only.v1";
export { LINUX_NORMALIZED_SNAPSHOT_COLLECTOR };
export const RESCUE_OFFLINE_EVIDENCE_TARGET = "selected-installed-target";
const MAX_INVENTORY_RESPONSE_BYTES = 2 * 1024 * 1024;
const MAX_RESCUE_TARGET_RESPONSE_BYTES = 64 * 1024;
const MAX_RESCUE_INSPECTION_RESPONSE_BYTES = 64 * 1024;
const MAX_RESCUE_INSPECTION_CORPUS_BYTES = 48 * 1024;
const MAX_NATIVE_OBSERVATION_BYTES = 64 * 1024;
const MAX_QUALIFIED_NATIVE_OBSERVATION_BYTES = 1024 * 1024;
const LINUX_HARDWARE_COLLECTOR = "linux.hardware.inventory";
const LINUX_HARDWARE_KIND = "linux-hardware-inventory";
const HARDWARE_SOURCE_STATUSES = new Set([
  "complete",
  "partial",
  "truncated",
  "unavailable",
  "invalid",
]);
type HardwareSourceStatus =
  "complete" | "partial" | "truncated" | "unavailable" | "invalid";
const DISK_REF = /^disk-[1-9][0-9]{0,2}$/u;
const VOLUME_REF = /^disk-[1-9][0-9]{0,2}\/volume-[1-9][0-9]{0,2}$/u;
const PUBLIC_TOKEN = /^[a-z0-9][a-z0-9-]{0,63}$/u;
const FILESYSTEM_TOKEN = /^[a-z0-9][a-z0-9_-]{0,63}$/u;
export const LINUX_P0_COLLECTORS = [
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
const LINUX_RESIDENT_CORPUS_COLLECTORS = [
  "system.hostname",
  LINUX_NORMALIZED_SNAPSHOT_COLLECTOR,
  LINUX_HARDWARE_COLLECTOR,
  ...LINUX_P0_COLLECTORS,
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
const MACOS_P0_COLLECTORS = [
  "macos.storage.inventory",
  "macos.apfs.capacity",
  "macos.launchd.state",
  "macos.network.state",
  "macos.software-update.state",
  "macos.system-events.summary",
  "macos.startup.state",
  "macos.snapshots.inventory",
] as const;
const QUALIFIED_LARGE_NATIVE_COLLECTORS = new Set<string>([
  ...WINDOWS_P0_COLLECTORS,
  "windows.storage.identity",
  ...MACOS_P0_COLLECTORS,
  "macos.storage.identity",
]);
const SFC_NOT_RUN_SUMMARY = "Evidenza P0 esplicita: SFC non eseguito";
const MACOS_NOT_RUN_SUMMARY =
  "Scope P0 esplicitamente non eseguito perché non qualificato";
const MACOS_PARTIAL_STARTUP_SUMMARY =
  "Safe mode verificato; login e background item non eseguiti perché non qualificati";
const MACOS_NOT_RUN_COLLECTORS = new Set<string>([
  "macos.software-update.state",
  "macos.system-events.summary",
]);
const RESCUE_INSPECTION_ERROR_CODES = new Set([
  "associated-efi-already-mounted",
  "associated-efi-inspection-failed",
  "associated-efi-read-only-mount-failed",
  "ambiguous-os-family",
  "helper-response-too-large",
  "inspection-failed",
  "inspection-response-too-large",
  "inspection-timeout",
  "invalid-helper-request",
  "invalid-inspection-request",
  "invalid-installed-os-metadata",
  "mount-cleanup-failed",
  "mount-postcondition-failed",
  "mount-root-unsafe",
  "mount-verification-failed",
  "privileged-helper-failed",
  "privileged-helper-unavailable",
  "read-only-mount-failed",
  "target-already-mounted",
  "target-device-ambiguous",
  "target-identity-changed",
  "target-identity-invalid",
  "target-resolution-invalid",
  "target-revalidation-failed",
  "unsafe-target-content",
  "unsupported-cross-device-content",
  "unsupported-apple-filesystem",
  "unsupported-complex-storage",
  "unsupported-encrypted-storage",
  "unsupported-filesystem",
]);

export interface NativeObservation {
  collector: string;
  trust: "observed-untrusted";
  output: string;
  success: boolean;
  truncated: boolean;
}

export interface LinuxHardwareInventory {
  schemaVersion: "1.0";
  kind: typeof LINUX_HARDWARE_KIND;
  architecture: string;
  cpu: {
    status: HardwareSourceStatus;
    logicalProcessors: number | null;
    vendors: string[];
    models: string[];
    virtualizationFlagPresent: boolean | null;
  };
  memory: { status: HardwareSourceStatus; totalBytes: number | null };
  firmware: {
    status: HardwareSourceStatus;
    bootMode: "uefi" | "bios-or-legacy" | "unknown";
    dmi: {
      biosVendor: string | null;
      biosVersion: string | null;
      boardName: string | null;
      boardVendor: string | null;
      productName: string | null;
      systemVendor: string | null;
    };
  };
  pci: {
    status: HardwareSourceStatus;
    devices: Array<{
      class: string;
      vendorId: string;
      deviceId: string;
      count: number;
    }>;
  };
  usb: {
    status: HardwareSourceStatus;
    devices: Array<{
      class: string;
      vendorId: string;
      productId: string;
      count: number;
    }>;
  };
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
  identifierScope: "ephemeral-rescue-boot";
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

export interface RescueOfflineInspectionClaims {
  installedOsConfirmed: boolean;
  filesystemContentInspected: boolean;
  mountOperationAttempted: boolean;
  mountOperationPerformed: boolean;
  mountCleanupVerified: boolean;
  autoUnlockAttempted: false;
  mutationPerformed: false;
  diagnosisProduced: false;
  repairAttempted: false;
}

export type RescueLinuxOfflineCorpus = LinuxNormalizedSnapshot;

export interface RescueWindowsOfflineCorpus {
  family: "windows";
  installationConfirmed: boolean;
  installationMarkers: {
    windowsDirectoryPresent: boolean;
    system32DirectoryPresent: boolean;
    kernelPresent: boolean;
    systemHivePresent: boolean;
    softwareHivePresent: boolean;
    usersDirectoryPresent: boolean;
  };
  boot: {
    bootManagerPresent: boolean;
    bcdPresent: boolean;
    efiSystemPartition: RescueEfiSystemPartitionCorpus;
  };
  servicing: {
    pendingXmlPresent: boolean;
    rebootPendingMarkerPresent: boolean;
  };
}

export type RescueEfiSystemPartitionCorpus =
  | {
      state: "inspected";
      microsoftBootManagerPresent: boolean;
      bcdPresent: boolean;
      fallbackBootloaderPresent: boolean;
    }
  | {
      state: "not-present" | "ambiguous" | "unsupported";
      microsoftBootManagerPresent: null;
      bcdPresent: null;
      fallbackBootloaderPresent: null;
    };

export type RescueOfflineCorpus =
  RescueLinuxOfflineCorpus | RescueWindowsOfflineCorpus;

export interface RescueOfflineInspection {
  apiVersion: typeof RESCUE_INSPECTION_API_VERSION;
  status:
    | "installed-os-content-inspected"
    | "content-inspected-installation-unconfirmed";
  trust: "observed-untrusted";
  target: {
    scanFingerprint: string;
    targetId: string;
    sourceRef: string;
    osFamily: "linux" | "windows";
    filesystem: "ext4" | "ntfs";
  };
  inspection: {
    mode: "temporary-read-only-no-replay";
    mountFlags: ["nodev", "noexec", "nosuid", "nosymfollow", "ro"];
    filesystemOptions: [] | ["noload"];
    dirtyVolumePolicy:
      | "journal-replay-disabled"
      | "read-only-no-force-driver-replay-not-applied";
    volumeStateQualification: "not-applicable" | "unqualified";
    privateMountNamespace: true;
    journalReplayPrevented: true;
    deviceOpenedReadOnly: true;
    rawDeviceIdentifierReturned: false;
    responseLimitBytes: 49152;
  };
  claims: RescueOfflineInspectionClaims;
  os: RescueOfflineCorpus;
  limitations: string[];
}

export type RescueOfflineInspectionErrorCode =
  | "associated-efi-already-mounted"
  | "associated-efi-inspection-failed"
  | "associated-efi-read-only-mount-failed"
  | "ambiguous-os-family"
  | "helper-response-too-large"
  | "inspection-failed"
  | "inspection-response-too-large"
  | "inspection-timeout"
  | "invalid-helper-request"
  | "invalid-inspection-request"
  | "invalid-installed-os-metadata"
  | "mount-cleanup-failed"
  | "mount-postcondition-failed"
  | "mount-root-unsafe"
  | "mount-verification-failed"
  | "privileged-helper-failed"
  | "privileged-helper-unavailable"
  | "read-only-mount-failed"
  | "target-already-mounted"
  | "target-device-ambiguous"
  | "target-identity-changed"
  | "target-identity-invalid"
  | "target-resolution-invalid"
  | "target-revalidation-failed"
  | "unsafe-target-content"
  | "unsupported-cross-device-content"
  | "unsupported-apple-filesystem"
  | "unsupported-complex-storage"
  | "unsupported-encrypted-storage"
  | "unsupported-filesystem"
  | "invalid-local-response";

export class RescueOfflineInspectionError extends Error {
  readonly code: RescueOfflineInspectionErrorCode;
  readonly retryable: boolean;
  readonly claims: RescueOfflineInspectionClaims;
  readonly httpStatus: number;

  constructor(
    code: RescueOfflineInspectionErrorCode,
    retryable: boolean,
    claims: RescueOfflineInspectionClaims,
    httpStatus: number,
  ) {
    super("L'ispezione offline non è stata completata in sicurezza.");
    this.name = "RescueOfflineInspectionError";
    this.code = code;
    this.retryable = retryable;
    this.claims = structuredClone(claims);
    this.httpStatus = httpStatus;
  }
}

export interface SecureRuntimeStatus {
  schemaVersion: "1.0";
  audit: "secure" | "unavailable" | "blocked";
  signing: "ready" | "uninitialized" | "unavailable" | "blocked";
  persistentAuditStarted: boolean;
  deviceId?: string;
}

export interface ResidentOpenAiStatus {
  schemaVersion: "1.0";
  provider: "openai";
  profile: "resident-default";
  model: "gpt-5.6-sol";
  credential: "absent" | "configured";
}

type NativeInvoke = <T>(
  command: string,
  args?: Record<string, unknown>,
) => Promise<T>;

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

export async function collectLinuxNormalizedSnapshot(): Promise<LinuxNormalizedSnapshotEnvelope> {
  if (!isNative())
    throw new Error("Lo snapshot Linux Resident richiede KernAid Desk nativo.");
  return verifyLinuxNormalizedSnapshotEnvelope(
    await invoke("collect_linux_normalized_snapshot"),
    "resident",
  );
}

export async function collectWindowsP0Inventory(): Promise<
  NativeObservation[]
> {
  if (!isNative())
    throw new Error("La raccolta P0 Windows richiede KernAid Resident.");
  return parseNativeObservations(await invoke("collect_windows_p0_inventory"));
}

export async function collectMacosP0Inventory(): Promise<NativeObservation[]> {
  if (!isNative())
    throw new Error("La raccolta P0 macOS richiede KernAid Resident.");
  return parseNativeObservations(await invoke("collect_macos_p0_inventory"));
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

export async function inspectRescueInstalledTarget(
  expectedSelection: RescueTargetSelection,
): Promise<RescueOfflineInspection> {
  if (!isRescueRuntime())
    throw new Error("L'ispezione offline richiede KernAid Rescue.");
  const selection = parseRescueTargetSelection(expectedSelection);
  let response: Response;
  try {
    response = await fetch("/api/rescue/inspect-installed-target", {
      method: "POST",
      cache: "no-store",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        scanFingerprint: selection.scanFingerprint,
        targetId: selection.target.targetId,
      }),
      signal: AbortSignal.timeout(22_000),
    });
  } catch (error) {
    throw localRescueInspectionTransportError(error);
  }
  if (!isJsonHttpResponse(response))
    throw new RescueOfflineInspectionError(
      "invalid-local-response",
      false,
      emptyRescueOfflineInspectionClaims(),
      response.status,
    );
  let payload: unknown;
  try {
    payload = await readBoundedJson(
      response,
      MAX_RESCUE_INSPECTION_RESPONSE_BYTES,
    );
  } catch (error) {
    if (isAbortOrTimeoutError(error))
      throw localRescueInspectionError("inspection-timeout", true, 408);
    if (error instanceof TypeError)
      throw localRescueInspectionError(
        "privileged-helper-unavailable",
        true,
        503,
      );
    throw localRescueInspectionError(
      "invalid-local-response",
      false,
      response.status,
    );
  }
  if (response.status !== 200)
    throw parseRescueOfflineInspectionError(payload, response.status);
  try {
    return parseRescueOfflineInspection(payload, selection);
  } catch {
    throw localRescueInspectionError(
      "invalid-local-response",
      false,
      response.status,
    );
  }
}

export function parseRescueOfflineInspection(
  value: unknown,
  expectedSelection: RescueTargetSelection,
): RescueOfflineInspection {
  const selection = parseRescueTargetSelection(expectedSelection);
  const item = exactRecord(value, [
    "apiVersion",
    "status",
    "trust",
    "target",
    "inspection",
    "claims",
    "os",
    "limitations",
  ]);
  if (
    item.apiVersion !== RESCUE_INSPECTION_API_VERSION ||
    !(
      item.status === "installed-os-content-inspected" ||
      item.status === "content-inspected-installation-unconfirmed"
    ) ||
    item.trust !== "observed-untrusted"
  )
    throw new Error("Risposta di ispezione Rescue non valida.");

  const target = exactRecord(item.target, [
    "scanFingerprint",
    "targetId",
    "sourceRef",
    "osFamily",
    "filesystem",
  ]);
  if (
    target.scanFingerprint !== selection.scanFingerprint ||
    target.targetId !== selection.target.targetId ||
    target.sourceRef !== selection.target.sourceRef ||
    !(target.osFamily === "linux" || target.osFamily === "windows") ||
    target.osFamily !== selection.target.osFamilyHint ||
    !(
      (target.osFamily === "linux" && target.filesystem === "ext4") ||
      (target.osFamily === "windows" && target.filesystem === "ntfs")
    )
  )
    throw new Error(
      "L'ispezione Rescue non corrisponde al target selezionato.",
    );

  const policy = exactRecord(item.inspection, [
    "mode",
    "mountFlags",
    "filesystemOptions",
    "dirtyVolumePolicy",
    "volumeStateQualification",
    "privateMountNamespace",
    "journalReplayPrevented",
    "deviceOpenedReadOnly",
    "rawDeviceIdentifierReturned",
    "responseLimitBytes",
  ]);
  const expectedMountFlags = ["nodev", "noexec", "nosuid", "nosymfollow", "ro"];
  if (
    policy.mode !== "temporary-read-only-no-replay" ||
    !sameStringList(policy.mountFlags, expectedMountFlags) ||
    policy.privateMountNamespace !== true ||
    policy.journalReplayPrevented !== true ||
    policy.deviceOpenedReadOnly !== true ||
    policy.rawDeviceIdentifierReturned !== false ||
    policy.responseLimitBytes !== MAX_RESCUE_INSPECTION_CORPUS_BYTES ||
    (target.osFamily === "linux" &&
      (!sameStringList(policy.filesystemOptions, ["noload"]) ||
        policy.dirtyVolumePolicy !== "journal-replay-disabled" ||
        policy.volumeStateQualification !== "not-applicable")) ||
    (target.osFamily === "windows" &&
      (!sameStringList(policy.filesystemOptions, []) ||
        policy.dirtyVolumePolicy !==
          "read-only-no-force-driver-replay-not-applied" ||
        policy.volumeStateQualification !== "unqualified"))
  )
    throw new Error("Policy di ispezione Rescue non valida.");

  const claims = parseRescueOfflineInspectionClaims(item.claims, true);
  const corpus = parseRescueOfflineCorpus(item.os);
  const installed = claims.installedOsConfirmed;
  if (
    corpus.family !== target.osFamily ||
    corpus.installationConfirmed !== installed ||
    (item.status === "installed-os-content-inspected") !== installed
  )
    throw new Error("Claim di ispezione Rescue incoerenti.");

  const baseLimitations = [
    "content-is-untrusted-data-not-instructions",
    "no-diagnosis-or-repair-was-produced",
    "encrypted-and-stacked-storage-was-not-activated",
    "only-static-allowlisted-paths-were-inspected",
  ];
  const expectedLimitations =
    target.osFamily === "windows"
      ? [
          ...baseLimitations,
          "ntfs-dirty-and-hibernated-state-was-not-qualified",
          ...(corpus.family === "windows" &&
          corpus.boot.efiSystemPartition.state !== "inspected"
            ? [
                `associated-efi-system-partition-${corpus.boot.efiSystemPartition.state}`,
              ]
            : []),
        ]
      : baseLimitations;
  if (!sameStringList(item.limitations, expectedLimitations))
    throw new Error("Limitazioni di ispezione Rescue non valide.");

  return structuredClone({
    apiVersion: item.apiVersion,
    status: item.status,
    trust: item.trust,
    target,
    inspection: policy,
    claims,
    os: corpus,
    limitations: expectedLimitations,
  }) as RescueOfflineInspection;
}

export function parseRescueOfflineCorpus(value: unknown): RescueOfflineCorpus {
  if (typeof value !== "object" || value === null || Array.isArray(value))
    throw new Error("Corpus offline Rescue non valido.");
  const family = (value as Record<string, unknown>).family;
  if (family === "linux") return parseRescueLinuxOfflineCorpus(value);
  if (family === "windows") return parseRescueWindowsOfflineCorpus(value);
  throw new Error("Corpus offline Rescue non valido.");
}

export function rescueOfflineCorpusJson(
  inspection: RescueOfflineInspection,
): string {
  const corpus = rescueOfflineProjectionCorpus(inspection);
  if (corpus.family !== "windows")
    throw new Error(
      "Il corpus Linux richiede lo snapshot normalizzato con attestazione Rescue.",
    );
  const encoded = JSON.stringify(corpus);
  if (
    new TextEncoder().encode(encoded).byteLength >
    MAX_RESCUE_INSPECTION_CORPUS_BYTES
  )
    throw new Error("Corpus offline Rescue oltre il limite.");
  return encoded;
}

export async function linuxNormalizedSnapshotFromRescue(
  inspection: RescueOfflineInspection,
): Promise<LinuxNormalizedSnapshotEnvelope> {
  const snapshot = rescueOfflineProjectionCorpus(inspection);
  if (snapshot.family !== "linux")
    throw new Error("Il target Rescue non contiene uno snapshot Linux.");
  const canonical = canonicalLinuxSnapshotJson(snapshot);
  const snapshotSha256 = await sha256(
    `${LINUX_NORMALIZED_SNAPSHOT_HASH_DOMAIN}${canonical}`,
  );
  return verifyLinuxNormalizedSnapshotEnvelope(
    {
      schemaVersion: "1.0",
      kind: "linux-normalized-snapshot",
      snapshotSha256,
      capture: {
        mode: "rescue",
        targetScope: "selected-installed-target",
        accessPolicy: "temporary-read-only-no-replay",
        deviceOpenedReadOnly: inspection.inspection.deviceOpenedReadOnly,
        journalReplayPrevented: inspection.inspection.journalReplayPrevented,
        privateMountNamespace: inspection.inspection.privateMountNamespace,
        mountCleanupVerified: inspection.claims.mountCleanupVerified,
        mutationPerformed: inspection.claims.mutationPerformed,
        crossDeviceTraversalAllowed: false,
      },
      snapshot,
    },
    "rescue",
  );
}

export function linuxNormalizedSnapshotEvidenceSummary(
  envelope: LinuxNormalizedSnapshotEnvelope,
): string {
  if (!envelope.snapshot.topology.supported)
    return `Snapshot statico Linux ${envelope.capture.mode} root-only; topologia multi-filesystem non supportata`;
  return envelope.snapshot.installationConfirmed
    ? `Snapshot statico Linux ${envelope.capture.mode} acquisito read-only e validato`
    : `Snapshot statico Linux ${envelope.capture.mode} acquisito read-only; installazione non confermata`;
}

async function verifyLinuxNormalizedSnapshotEnvelope(
  value: unknown,
  expectedMode: "resident" | "rescue",
): Promise<LinuxNormalizedSnapshotEnvelope> {
  const envelope = parseLinuxNormalizedSnapshotEnvelope(value);
  const encoded = JSON.stringify(envelope);
  if (
    new TextEncoder().encode(encoded).byteLength >
      MAX_LINUX_NORMALIZED_SNAPSHOT_BYTES ||
    envelope.capture.mode !== expectedMode ||
    envelope.snapshotSha256 !==
      (await sha256(
        `${LINUX_NORMALIZED_SNAPSHOT_HASH_DOMAIN}${canonicalLinuxSnapshotJson(
          envelope.snapshot,
        )}`,
      ))
  )
    throw new Error("Snapshot Linux normalizzato non valido.");
  return envelope;
}

export function rescueOfflineEvidenceSummary(
  inspection: RescueOfflineInspection,
): string {
  const corpus = rescueOfflineProjectionCorpus(inspection);
  return rescueOfflineCorpusSummary(corpus);
}

function rescueOfflineProjectionCorpus(
  inspection: RescueOfflineInspection,
): RescueOfflineCorpus {
  const claims = parseRescueOfflineInspectionClaims(inspection.claims, true);
  const corpus = parseRescueOfflineCorpus(inspection.os);
  if (
    inspection.apiVersion !== RESCUE_INSPECTION_API_VERSION ||
    inspection.trust !== "observed-untrusted" ||
    !(
      inspection.status === "installed-os-content-inspected" ||
      inspection.status === "content-inspected-installation-unconfirmed"
    ) ||
    inspection.target.osFamily !== corpus.family ||
    !(
      (corpus.family === "linux" && inspection.target.filesystem === "ext4") ||
      (corpus.family === "windows" && inspection.target.filesystem === "ntfs")
    ) ||
    claims.installedOsConfirmed !== corpus.installationConfirmed ||
    (inspection.status === "installed-os-content-inspected") !==
      corpus.installationConfirmed
  )
    throw new Error("Ispezione Rescue non valida per la diagnosi.");
  return corpus;
}

function rescueOfflineCorpusSummary(corpus: RescueOfflineCorpus): string {
  return corpus.installationConfirmed
    ? `Corpus statico ${corpus.family} acquisito read-only con cleanup verificato`
    : `Corpus statico ${corpus.family} acquisito read-only; installazione non confermata`;
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
        (QUALIFIED_LARGE_NATIVE_COLLECTORS.has(item.collector)
          ? MAX_QUALIFIED_NATIVE_OBSERVATION_BYTES
          : MAX_NATIVE_OBSERVATION_BYTES) ||
      typeof item.success !== "boolean" ||
      typeof item.truncated !== "boolean" ||
      (item.truncated && item.success)
    )
      throw new Error("Inventario nativo non valido.");
    if (item.collector === LINUX_HARDWARE_COLLECTOR && item.success)
      parseLinuxHardwareInventory(item.output);
    return item as unknown as NativeObservation;
  });
}

function hardwareStatus(value: unknown): HardwareSourceStatus {
  if (typeof value !== "string" || !HARDWARE_SOURCE_STATUSES.has(value))
    throw new Error("Inventario hardware Linux non valido.");
  return value as HardwareSourceStatus;
}

function exactHardwareRecord(
  value: unknown,
  keys: readonly string[],
): Record<string, unknown> {
  try {
    return exactRecord(value, keys);
  } catch {
    throw new Error("Inventario hardware Linux non valido.");
  }
}

function nullableHardwareText(value: unknown): string | null {
  if (value === null) return null;
  if (
    typeof value !== "string" ||
    value.length === 0 ||
    new TextEncoder().encode(value).byteLength > 256 ||
    !hasOnlyUnicodeScalarValues(value) ||
    hasUnsafePublicTextCharacter(value) ||
    value.split(/\s+/u).join(" ") !== value
  )
    throw new Error("Inventario hardware Linux non valido.");
  return value;
}

function hasOnlyUnicodeScalarValues(value: string): boolean {
  for (const character of value) {
    const codePoint = character.codePointAt(0);
    if (codePoint === undefined || (codePoint >= 0xd800 && codePoint <= 0xdfff))
      return false;
  }
  return true;
}

function compareUtf8(left: string, right: string): number {
  const encoder = new TextEncoder();
  const leftBytes = encoder.encode(left);
  const rightBytes = encoder.encode(right);
  const sharedLength = Math.min(leftBytes.length, rightBytes.length);
  for (let index = 0; index < sharedLength; index += 1) {
    const difference = leftBytes[index]! - rightBytes[index]!;
    if (difference !== 0) return difference;
  }
  return leftBytes.length - rightBytes.length;
}

function hasUnsafePublicTextCharacter(value: string): boolean {
  for (const character of value) {
    const codePoint = character.codePointAt(0);
    if (
      codePoint !== undefined &&
      (codePoint <= 0x1f ||
        (codePoint >= 0x7f && codePoint <= 0x9f) ||
        codePoint === 0x61c ||
        codePoint === 0x200e ||
        codePoint === 0x200f ||
        (codePoint >= 0x202a && codePoint <= 0x202e) ||
        (codePoint >= 0x2066 && codePoint <= 0x2069))
    )
      return true;
  }
  return false;
}

function hardwareTextArray(value: unknown): string[] {
  if (!Array.isArray(value) || value.length > 16)
    throw new Error("Inventario hardware Linux non valido.");
  const texts = value.map(nullableHardwareText);
  if (
    texts.some((item) => item === null) ||
    texts.some(
      (item, index) => index > 0 && compareUtf8(texts[index - 1]!, item!) >= 0,
    )
  )
    throw new Error("Inventario hardware Linux non valido.");
  return texts as string[];
}

function exactHardwareDevices(
  value: unknown,
  kind: "pci" | "usb",
): Array<Record<string, unknown>> {
  if (!Array.isArray(value) || value.length > 256)
    throw new Error("Inventario hardware Linux non valido.");
  const devices = value.map((raw) => {
    const keys =
      kind === "pci"
        ? ["class", "vendorId", "deviceId", "count"]
        : ["class", "vendorId", "productId", "count"];
    const item = exactHardwareRecord(raw, keys);
    const expected =
      kind === "pci"
        ? { class: 6, vendorId: 4, deviceId: 4 }
        : { class: 2, vendorId: 4, productId: 4 };
    for (const [key, digits] of Object.entries(expected)) {
      const field = item[key];
      if (
        typeof field !== "string" ||
        !new RegExp(`^0x[0-9a-f]{${digits}}$`, "u").test(field)
      )
        throw new Error("Inventario hardware Linux non valido.");
    }
    if (
      !Number.isSafeInteger(item.count) ||
      Number(item.count) < 1 ||
      Number(item.count) > 256
    )
      throw new Error("Inventario hardware Linux non valido.");
    return item;
  });
  const canonical = devices.map((device) =>
    kind === "pci"
      ? `${String(device.class)}\u0000${String(device.vendorId)}\u0000${String(device.deviceId)}`
      : `${String(device.class)}\u0000${String(device.vendorId)}\u0000${String(device.productId)}`,
  );
  if (
    canonical.some(
      (item, index) => index > 0 && item <= canonical[index - 1]!,
    ) ||
    devices.reduce((total, device) => total + Number(device.count), 0) > 256
  )
    throw new Error("Inventario hardware Linux non valido.");
  return devices;
}

export function parseLinuxHardwareInventory(
  json: string,
): LinuxHardwareInventory {
  let raw: unknown;
  try {
    raw = JSON.parse(json);
  } catch {
    throw new Error("Inventario hardware Linux non valido.");
  }
  const canonicalFrame = json.endsWith("\n") ? json.slice(0, -1) : json;
  if (!canonicalFrame || JSON.stringify(raw) !== canonicalFrame)
    throw new Error("Inventario hardware Linux non valido.");
  const item = exactHardwareRecord(raw, [
    "schemaVersion",
    "kind",
    "architecture",
    "cpu",
    "memory",
    "firmware",
    "pci",
    "usb",
  ]);
  if (
    item.schemaVersion !== "1.0" ||
    item.kind !== LINUX_HARDWARE_KIND ||
    typeof item.architecture !== "string" ||
    !/^[a-z0-9][a-z0-9_.-]{0,31}$/u.test(item.architecture)
  )
    throw new Error("Inventario hardware Linux non valido.");

  const cpu = exactHardwareRecord(item.cpu, [
    "status",
    "logicalProcessors",
    "vendors",
    "models",
    "virtualizationFlagPresent",
  ]);
  const cpuStatus = hardwareStatus(cpu.status);
  if (
    !(
      cpu.logicalProcessors === null ||
      (Number.isSafeInteger(cpu.logicalProcessors) &&
        Number(cpu.logicalProcessors) >= 1 &&
        Number(cpu.logicalProcessors) <= 4096)
    ) ||
    !(
      cpu.virtualizationFlagPresent === null ||
      typeof cpu.virtualizationFlagPresent === "boolean"
    )
  )
    throw new Error("Inventario hardware Linux non valido.");
  hardwareTextArray(cpu.vendors);
  hardwareTextArray(cpu.models);
  if (
    cpuStatus === "complete" &&
    (cpu.logicalProcessors === null || cpu.virtualizationFlagPresent === null)
  )
    throw new Error("Inventario hardware Linux non valido.");

  const memory = exactHardwareRecord(item.memory, ["status", "totalBytes"]);
  const memoryStatus = hardwareStatus(memory.status);
  if (
    !(
      memory.totalBytes === null ||
      (Number.isSafeInteger(memory.totalBytes) && Number(memory.totalBytes) > 0)
    ) ||
    (memoryStatus === "complete" && memory.totalBytes === null)
  )
    throw new Error("Inventario hardware Linux non valido.");

  const firmware = exactHardwareRecord(item.firmware, [
    "status",
    "bootMode",
    "dmi",
  ]);
  const firmwareStatus = hardwareStatus(firmware.status);
  if (
    firmware.bootMode !== "uefi" &&
    firmware.bootMode !== "bios-or-legacy" &&
    firmware.bootMode !== "unknown"
  )
    throw new Error("Inventario hardware Linux non valido.");
  const dmi = exactHardwareRecord(firmware.dmi, [
    "biosVendor",
    "biosVersion",
    "boardName",
    "boardVendor",
    "productName",
    "systemVendor",
  ]);
  const dmiValues = Object.values(dmi);
  dmiValues.forEach(nullableHardwareText);
  if (
    firmwareStatus === "complete" &&
    (firmware.bootMode === "unknown" ||
      dmiValues.some((value) => value === null))
  )
    throw new Error("Inventario hardware Linux non valido.");

  const pci = exactHardwareRecord(item.pci, ["status", "devices"]);
  hardwareStatus(pci.status);
  exactHardwareDevices(pci.devices, "pci");
  const usb = exactHardwareRecord(item.usb, ["status", "devices"]);
  hardwareStatus(usb.status);
  exactHardwareDevices(usb.devices, "usb");
  return item as unknown as LinuxHardwareInventory;
}

export function nativeObservationContentType(
  observation: NativeObservation,
): "application/json" | "text/plain" {
  return observation.success &&
    (observation.collector.startsWith("macos.") ||
      observation.collector === LINUX_HARDWARE_COLLECTOR)
    ? "application/json"
    : "text/plain";
}

export function nativeObservationSummary(
  observation: NativeObservation,
): string {
  if (!observation.success) return "Comando di inventario non disponibile";
  if (observation.collector === "windows.sfc.verify-only")
    return SFC_NOT_RUN_SUMMARY;
  if (MACOS_NOT_RUN_COLLECTORS.has(observation.collector))
    return MACOS_NOT_RUN_SUMMARY;
  if (observation.collector === "macos.startup.state")
    return MACOS_PARTIAL_STARTUP_SUMMARY;
  return "Comando di inventario completato";
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
    item.identifierScope !== "ephemeral-rescue-boot" ||
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

function parseRescueOfflineInspectionError(
  value: unknown,
  httpStatus: number,
): RescueOfflineInspectionError {
  const invalid = (): RescueOfflineInspectionError =>
    new RescueOfflineInspectionError(
      "invalid-local-response",
      false,
      emptyRescueOfflineInspectionClaims(),
      httpStatus,
    );
  if (![400, 408, 409, 422, 429, 503].includes(httpStatus)) return invalid();
  try {
    const envelope = exactRecord(value, ["error"]);
    const error = exactRecord(envelope.error, [
      "code",
      "message",
      "retryable",
      "claims",
    ]);
    if (
      typeof error.code !== "string" ||
      !RESCUE_INSPECTION_ERROR_CODES.has(error.code) ||
      typeof error.message !== "string" ||
      !boundedControlFreeText(error.message, 512) ||
      typeof error.retryable !== "boolean" ||
      !validRescueInspectionErrorContract(
        error.code,
        httpStatus,
        error.retryable,
      )
    )
      return invalid();
    const claims = parseRescueOfflineInspectionClaims(error.claims, false);
    return new RescueOfflineInspectionError(
      error.code as RescueOfflineInspectionErrorCode,
      error.retryable,
      claims,
      httpStatus,
    );
  } catch {
    return invalid();
  }
}

function validRescueInspectionErrorContract(
  code: string,
  httpStatus: number,
  retryable: boolean,
): boolean {
  switch (code) {
    case "inspection-timeout":
      return httpStatus === 408 && retryable;
    case "invalid-helper-request":
    case "invalid-inspection-request":
      return httpStatus === 400 && !retryable;
    case "ambiguous-os-family":
    case "associated-efi-read-only-mount-failed":
    case "invalid-installed-os-metadata":
    case "read-only-mount-failed":
    case "unsafe-target-content":
    case "unsupported-cross-device-content":
    case "unsupported-apple-filesystem":
    case "unsupported-complex-storage":
    case "unsupported-encrypted-storage":
    case "unsupported-filesystem":
      return httpStatus === 422 && !retryable;
    case "associated-efi-already-mounted":
    case "target-already-mounted":
      return httpStatus === 409 && retryable;
    case "target-identity-invalid":
      return httpStatus === 409 && !retryable;
    case "target-identity-changed":
      return httpStatus === 409;
    case "target-device-ambiguous":
      return httpStatus === 409 || (httpStatus === 503 && retryable);
    case "target-revalidation-failed":
      return [408, 409, 429, 503].includes(httpStatus) && retryable;
    case "mount-postcondition-failed":
    case "privileged-helper-failed":
    case "privileged-helper-unavailable":
      return httpStatus === 503 && retryable;
    case "helper-response-too-large":
    case "inspection-response-too-large":
    case "mount-cleanup-failed":
    case "mount-root-unsafe":
    case "mount-verification-failed":
    case "target-resolution-invalid":
      return httpStatus === 503 && !retryable;
    case "associated-efi-inspection-failed":
    case "inspection-failed":
      return httpStatus === 503;
    default:
      return false;
  }
}

function localRescueInspectionTransportError(
  error: unknown,
): RescueOfflineInspectionError {
  return isAbortOrTimeoutError(error)
    ? localRescueInspectionError("inspection-timeout", true, 408)
    : localRescueInspectionError("privileged-helper-unavailable", true, 503);
}

function localRescueInspectionError(
  code: RescueOfflineInspectionErrorCode,
  retryable: boolean,
  httpStatus: number,
): RescueOfflineInspectionError {
  return new RescueOfflineInspectionError(
    code,
    retryable,
    emptyRescueOfflineInspectionClaims(),
    httpStatus,
  );
}

function isAbortOrTimeoutError(error: unknown): boolean {
  return (
    error instanceof Error &&
    (error.name === "AbortError" || error.name === "TimeoutError")
  );
}

function emptyRescueOfflineInspectionClaims(): RescueOfflineInspectionClaims {
  return {
    installedOsConfirmed: false,
    filesystemContentInspected: false,
    mountOperationAttempted: false,
    mountOperationPerformed: false,
    mountCleanupVerified: false,
    autoUnlockAttempted: false,
    mutationPerformed: false,
    diagnosisProduced: false,
    repairAttempted: false,
  };
}

function parseRescueOfflineInspectionClaims(
  value: unknown,
  completed: boolean,
): RescueOfflineInspectionClaims {
  const item = exactRecord(value, [
    "installedOsConfirmed",
    "filesystemContentInspected",
    "mountOperationAttempted",
    "mountOperationPerformed",
    "mountCleanupVerified",
    "autoUnlockAttempted",
    "mutationPerformed",
    "diagnosisProduced",
    "repairAttempted",
  ]);
  if (
    Object.values(item).some((claim) => typeof claim !== "boolean") ||
    item.autoUnlockAttempted !== false ||
    item.mutationPerformed !== false ||
    item.diagnosisProduced !== false ||
    item.repairAttempted !== false ||
    (item.mountOperationPerformed === true &&
      item.mountOperationAttempted !== true) ||
    (item.filesystemContentInspected === true &&
      item.mountOperationPerformed !== true) ||
    (item.installedOsConfirmed === true &&
      item.filesystemContentInspected !== true) ||
    (completed &&
      (item.filesystemContentInspected !== true ||
        item.mountOperationAttempted !== true ||
        item.mountOperationPerformed !== true ||
        item.mountCleanupVerified !== true))
  )
    throw new Error("Claim di ispezione Rescue non validi.");
  return item as unknown as RescueOfflineInspectionClaims;
}

function parseRescueLinuxOfflineCorpus(
  value: unknown,
): RescueLinuxOfflineCorpus {
  return structuredClone(parseLinuxNormalizedSnapshot(value));
}

function parseRescueWindowsOfflineCorpus(
  value: unknown,
): RescueWindowsOfflineCorpus {
  const item = exactRecord(value, [
    "family",
    "installationConfirmed",
    "installationMarkers",
    "boot",
    "servicing",
  ]);
  const markers = exactRecord(item.installationMarkers, [
    "windowsDirectoryPresent",
    "system32DirectoryPresent",
    "kernelPresent",
    "systemHivePresent",
    "softwareHivePresent",
    "usersDirectoryPresent",
  ]);
  const boot = exactRecord(item.boot, [
    "bootManagerPresent",
    "bcdPresent",
    "efiSystemPartition",
  ]);
  const efiSystemPartition = exactRecord(boot.efiSystemPartition, [
    "state",
    "microsoftBootManagerPresent",
    "bcdPresent",
    "fallbackBootloaderPresent",
  ]);
  const servicing = exactRecord(item.servicing, [
    "pendingXmlPresent",
    "rebootPendingMarkerPresent",
  ]);
  const requiredMarkers = [
    markers.windowsDirectoryPresent,
    markers.system32DirectoryPresent,
    markers.kernelPresent,
    markers.systemHivePresent,
    markers.softwareHivePresent,
  ];
  if (
    item.family !== "windows" ||
    typeof item.installationConfirmed !== "boolean" ||
    Object.values(markers).some((entry) => typeof entry !== "boolean") ||
    typeof boot.bootManagerPresent !== "boolean" ||
    typeof boot.bcdPresent !== "boolean" ||
    typeof efiSystemPartition.state !== "string" ||
    !["inspected", "not-present", "ambiguous", "unsupported"].includes(
      efiSystemPartition.state,
    ) ||
    (efiSystemPartition.state === "inspected"
      ? [
          efiSystemPartition.microsoftBootManagerPresent,
          efiSystemPartition.bcdPresent,
          efiSystemPartition.fallbackBootloaderPresent,
        ].some((entry) => typeof entry !== "boolean")
      : [
          efiSystemPartition.microsoftBootManagerPresent,
          efiSystemPartition.bcdPresent,
          efiSystemPartition.fallbackBootloaderPresent,
        ].some((entry) => entry !== null)) ||
    Object.values(servicing).some((entry) => typeof entry !== "boolean") ||
    item.installationConfirmed !==
      requiredMarkers.every((entry) => entry === true)
  )
    throw new Error("Corpus Windows offline non valido.");
  return structuredClone({
    family: item.family,
    installationConfirmed: item.installationConfirmed,
    installationMarkers: markers,
    boot: {
      bootManagerPresent: boot.bootManagerPresent,
      bcdPresent: boot.bcdPresent,
      efiSystemPartition,
    },
    servicing,
  }) as RescueWindowsOfflineCorpus;
}

function boundedControlFreeText(value: string, maximumBytes: number): boolean {
  return (
    value.length > 0 &&
    new TextEncoder().encode(value).byteLength <= maximumBytes &&
    !Array.from(value).some((character) => {
      const codePoint = character.codePointAt(0);
      return (
        codePoint !== undefined && (codePoint <= 0x1f || codePoint === 0x7f)
      );
    })
  );
}

function sameStringList(value: unknown, expected: readonly string[]): boolean {
  return (
    Array.isArray(value) &&
    value.length === expected.length &&
    value.every((entry, index) => entry === expected[index])
  );
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

export async function getResidentOpenAiStatus(
  invokeCommand: NativeInvoke = invoke,
): Promise<ResidentOpenAiStatus> {
  if (invokeCommand === invoke && !isNative())
    throw new Error("OpenAI Resident richiede KernAid Desk nativo.");
  try {
    return parseResidentOpenAiStatus(
      await invokeCommand("resident_openai_status"),
    );
  } catch (error) {
    throw nativeOpenAiError(error);
  }
}

export async function logoutResidentOpenAi(
  invokeCommand: NativeInvoke = invoke,
): Promise<ResidentOpenAiStatus> {
  if (invokeCommand === invoke && !isNative())
    throw new Error("OpenAI Resident richiede KernAid Desk nativo.");
  try {
    return parseResidentOpenAiStatus(
      await invokeCommand("resident_openai_logout"),
    );
  } catch (error) {
    throw nativeOpenAiError(error);
  }
}

export class NativeOpenAiProvider implements Provider {
  readonly capabilities = Object.freeze({
    streaming: false,
    structuredOutput: true,
    toolRequests: false,
    local: false,
  });

  readonly #invoke: NativeInvoke;

  constructor(invokeCommand: NativeInvoke = invoke) {
    this.#invoke = invokeCommand;
  }

  async diagnose(
    objective: string,
    evidence: readonly ObservedEvidence[],
    options: ProviderRequestOptions = {},
  ): Promise<DiagnosisProposal> {
    if (!objective.trim() || evidence.length === 0)
      throw new ProviderError("invalid_request", "Provider input is invalid");
    if (options.signal?.aborted)
      throw new ProviderError("cancelled", "Provider request was cancelled");
    const requestId = `O-${crypto.randomUUID()}`;
    const request = {
      requestId,
      objective,
      evidence: evidence.map(({ evidence: item, content }) => ({
        id: item.id,
        collector: item.collector,
        target: item.target,
        capturedAt: item.capturedAt,
        contentType: item.contentType,
        sha256: item.sha256,
        sensitivity: item.sensitivity,
        trust: item.trust,
        summary: item.summary,
        content,
      })),
    };
    let rejectCancellation: ((reason: ProviderError) => void) | undefined;
    const cancellation = new Promise<never>((_resolve, reject) => {
      rejectCancellation = reject;
    });
    const onAbort = (): void => {
      void this.#invoke("resident_openai_cancel", { requestId }).catch(
        () => undefined,
      );
      rejectCancellation?.(
        new ProviderError("cancelled", "Provider request was cancelled"),
      );
    };
    options.signal?.addEventListener("abort", onAbort, { once: true });
    const operation = this.#invoke<unknown>("resident_openai_diagnose", {
      request,
    });
    try {
      return parseDiagnosisProposal(
        await Promise.race([operation, cancellation]),
      );
    } catch (error) {
      if (error instanceof ProviderError) throw error;
      throw nativeOpenAiError(error);
    } finally {
      options.signal?.removeEventListener("abort", onAbort);
    }
  }
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
    const rescueCorpusEvidence = evidence.filter(
      (item) =>
        item.evidence.collector === RESCUE_OFFLINE_EVIDENCE_COLLECTOR ||
        item.evidence.collector === LINUX_NORMALIZED_SNAPSHOT_COLLECTOR,
    );
    const rescueScopedEvidence = evidence.filter(
      (item) =>
        item.evidence.collector.startsWith("rescue.") ||
        item.evidence.target === "rescue-runtime" ||
        item.evidence.target === "selected-installed-target-candidate" ||
        item.evidence.target === RESCUE_OFFLINE_EVIDENCE_TARGET,
    );
    if (
      rescueScopedEvidence.length > 0 ||
      rescueCorpusEvidence.some(
        (item) => item.evidence.collector === RESCUE_OFFLINE_EVIDENCE_COLLECTOR,
      )
    )
      return await diagnoseRescueOfflineCorpus(evidence, rescueCorpusEvidence);
    const linuxEvidence = evidence.filter((item) =>
      LINUX_P0_COLLECTORS.includes(
        item.evidence.collector as (typeof LINUX_P0_COLLECTORS)[number],
      ),
    );
    const snapshotEvidence = evidence.filter(
      (item) => item.evidence.collector === LINUX_NORMALIZED_SNAPSHOT_COLLECTOR,
    );
    const hardwareEvidence = evidence.filter(
      (item) => item.evidence.collector === LINUX_HARDWARE_COLLECTOR,
    );
    const hasLinuxCorpus =
      linuxEvidence.length > 0 ||
      snapshotEvidence.length > 0 ||
      hardwareEvidence.length > 0;
    const windowsEvidence = evidence.filter((item) =>
      WINDOWS_P0_COLLECTORS.includes(
        item.evidence.collector as (typeof WINDOWS_P0_COLLECTORS)[number],
      ),
    );
    const macosEvidence = evidence.filter((item) =>
      MACOS_P0_COLLECTORS.includes(
        item.evidence.collector as (typeof MACOS_P0_COLLECTORS)[number],
      ),
    );

    if (windowsEvidence.length > 0 && !hasLinuxCorpus) {
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

    if (macosEvidence.length > 0 && !hasLinuxCorpus) {
      const selected = MACOS_P0_COLLECTORS.map((collector) =>
        evidence.find((item) => item.evidence.collector === collector),
      );
      const complete =
        selected.every((item) => item !== undefined) &&
        MACOS_P0_COLLECTORS.every(
          (collector) =>
            evidence.filter((item) => item.evidence.collector === collector)
              .length === 1,
        );
      const successful = selected.every((item) =>
        isSuccessfulMacosEvidence(item),
      );
      if (!complete || !successful) {
        const requestedEvidence = MACOS_P0_COLLECTORS.filter((collector) => {
          const matches = evidence.filter(
            (item) => item.evidence.collector === collector,
          );
          return matches.length !== 1 || !isSuccessfulMacosEvidence(matches[0]);
        });
        return parseDiagnosisProposal({
          schemaVersion: "1.0",
          diagnosis:
            "Diagnosi macOS incompleta: una o più evidenze P0 richieste non sono disponibili o affidabili. Nessuna conclusione sullo stato del sistema viene formulata.",
          confidence: 0.1,
          evidenceIds: macosEvidence.map((item) => item.evidence.id),
          requestedEvidence,
        });
      }
      const documents = selected.map((item) => ({
        id: item!.evidence.id,
        collector: item!.evidence.collector,
        content: item!.content,
      }));
      return parseDiagnosisProposal(
        await invoke("diagnose_macos_p0", { evidence: documents }),
      );
    }

    if (!hasLinuxCorpus) return this.#fallback.diagnose(objective, evidence);

    let hardwareValid = false;
    if (
      hardwareEvidence.length === 1 &&
      hardwareEvidence[0]?.evidence.target === "local-machine" &&
      hardwareEvidence[0].evidence.contentType === "application/json" &&
      hardwareEvidence[0].evidence.trust === "observed-untrusted" &&
      hardwareEvidence[0].evidence.summary ===
        "Comando di inventario completato"
    ) {
      try {
        parseLinuxHardwareInventory(hardwareEvidence[0].content);
        hardwareValid = true;
      } catch {
        hardwareValid = false;
      }
    }

    let admittedSnapshot: LinuxNormalizedSnapshotEnvelope | undefined;
    if (
      snapshotEvidence.length === 1 &&
      snapshotEvidence[0]?.evidence.target === "local-machine" &&
      snapshotEvidence[0].evidence.contentType ===
        LINUX_NORMALIZED_SNAPSHOT_CONTENT_TYPE
    ) {
      try {
        admittedSnapshot = await verifyLinuxNormalizedSnapshotEnvelope(
          parseLinuxNormalizedSnapshotEnvelopeJson(
            new TextEncoder().encode(snapshotEvidence[0].content),
          ),
          "resident",
        );
      } catch {
        admittedSnapshot = undefined;
      }
    }
    if (admittedSnapshot === undefined) {
      return parseDiagnosisProposal({
        schemaVersion: "1.0",
        diagnosis:
          "Diagnosi Linux incompleta e bloccata: manca uno snapshot statico normalizzato e attestato della root Resident.",
        confidence: 0.1,
        evidenceIds: Array.from(
          new Set(
            [...linuxEvidence, ...snapshotEvidence, ...hardwareEvidence].map(
              (item) => item.evidence.id,
            ),
          ),
        ),
        requestedEvidence: [
          LINUX_NORMALIZED_SNAPSHOT_COLLECTOR,
          ...(hardwareValid ? [] : [LINUX_HARDWARE_COLLECTOR]),
          ...LINUX_P0_COLLECTORS.filter(
            (collector) =>
              !linuxEvidence.some(
                (item) => item.evidence.collector === collector,
              ),
          ),
        ],
      });
    }

    if (!admittedSnapshot.snapshot.topology.supported) {
      return parseDiagnosisProposal({
        schemaVersion: "1.0",
        diagnosis:
          "Diagnosi Linux bloccata: lo snapshot dichiara filesystem separati sotto /etc, /boot (incluso /boot/efi), /efi, /usr o /var, una topologia non supportata dal profilo root-filesystem-only v1.",
        confidence: 0.1,
        evidenceIds: Array.from(
          new Set(
            [...linuxEvidence, ...snapshotEvidence, ...hardwareEvidence].map(
              (item) => item.evidence.id,
            ),
          ),
        ),
        requestedEvidence: ["linux.topology.single-filesystem.v1"],
      });
    }

    const selected = LINUX_P0_COLLECTORS.map((collector) =>
      evidence.find((item) => item.evidence.collector === collector),
    );
    const collectorCounts = new Map<string, number>();
    for (const item of evidence)
      collectorCounts.set(
        item.evidence.collector,
        (collectorCounts.get(item.evidence.collector) ?? 0) + 1,
      );
    const exactCorpus =
      evidence.length === LINUX_RESIDENT_CORPUS_COLLECTORS.length &&
      new Set(evidence.map((item) => item.evidence.id)).size ===
        evidence.length &&
      evidence.every(
        (item) =>
          item.evidence.target === "local-machine" &&
          LINUX_RESIDENT_CORPUS_COLLECTORS.some(
            (collector) => collector === item.evidence.collector,
          ),
      ) &&
      LINUX_RESIDENT_CORPUS_COLLECTORS.every(
        (collector) => (collectorCounts.get(collector) ?? 0) === 1,
      );
    const complete =
      exactCorpus &&
      hardwareValid &&
      selected.every((item) => item !== undefined) &&
      LINUX_P0_COLLECTORS.every(
        (collector) =>
          evidence.filter((item) => item.evidence.collector === collector)
            .length === 1,
      );
    const successful =
      selected.every(
        (item) => item?.evidence.summary === "Comando di inventario completato",
      ) &&
      evidence.some(
        (item) =>
          item.evidence.collector === "system.hostname" &&
          item.evidence.summary === "Comando di inventario completato",
      );
    if (!complete || !successful) {
      const requestedEvidence: string[] = LINUX_P0_COLLECTORS.filter(
        (collector) => {
          const matches = evidence.filter(
            (item) => item.evidence.collector === collector,
          );
          return (
            matches.length !== 1 ||
            matches[0]?.evidence.summary !== "Comando di inventario completato"
          );
        },
      );
      const hostname = evidence.filter(
        (item) => item.evidence.collector === "system.hostname",
      );
      if (
        hostname.length !== 1 ||
        hostname[0]?.evidence.summary !== "Comando di inventario completato"
      )
        requestedEvidence.unshift("system.hostname");
      if (!hardwareValid) requestedEvidence.push(LINUX_HARDWARE_COLLECTOR);
      if (!exactCorpus) requestedEvidence.push("linux.p0.corpus.exact.v1");
      return parseDiagnosisProposal({
        schemaVersion: "1.0",
        diagnosis:
          "Diagnosi Linux incompleta: una o più evidenze P0 richieste non sono disponibili o affidabili. Nessuna conclusione sullo stato del sistema viene formulata.",
        confidence: 0.1,
        evidenceIds: Array.from(
          new Set(evidence.map((item) => item.evidence.id)),
        ),
        requestedEvidence: Array.from(new Set(requestedEvidence)),
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
    const proposal = parseDiagnosisProposal(response);
    return parseDiagnosisProposal({
      ...proposal,
      evidenceIds: Array.from(
        new Set([
          ...proposal.evidenceIds,
          snapshotEvidence[0]!.evidence.id,
          hardwareEvidence[0]!.evidence.id,
        ]),
      ),
    });
  }
}

async function diagnoseRescueOfflineCorpus(
  evidence: readonly ObservedEvidence[],
  matching: readonly ObservedEvidence[],
): Promise<DiagnosisProposal> {
  const requestedCollector =
    matching[0]?.evidence.collector === LINUX_NORMALIZED_SNAPSHOT_COLLECTOR
      ? LINUX_NORMALIZED_SNAPSHOT_COLLECTOR
      : RESCUE_OFFLINE_EVIDENCE_COLLECTOR;
  const invalid = (): DiagnosisProposal =>
    parseDiagnosisProposal({
      schemaVersion: "1.0",
      diagnosis:
        "Il corpus offline Rescue non è valido, è duplicato o contiene evidenze fuori scope. La diagnosi resta bloccata senza formulare conclusioni sul sistema installato.",
      confidence: 0.1,
      evidenceIds: evidence.map((item) => item.evidence.id),
      requestedEvidence: [requestedCollector],
    });
  if (evidence.length !== 1 || matching.length !== 1) return invalid();
  const selected = matching[0]!;
  if (
    selected.evidence.target !== RESCUE_OFFLINE_EVIDENCE_TARGET ||
    selected.evidence.contentType !== "application/json" ||
    selected.evidence.trust !== "observed-untrusted" ||
    new TextEncoder().encode(selected.content).byteLength >
      MAX_RESCUE_INSPECTION_CORPUS_BYTES
  )
    return invalid();
  let corpus: RescueOfflineCorpus;
  try {
    const parsed = JSON.parse(selected.content) as unknown;
    if (selected.evidence.collector === LINUX_NORMALIZED_SNAPSHOT_COLLECTOR) {
      const envelope = await verifyLinuxNormalizedSnapshotEnvelope(
        parseLinuxNormalizedSnapshotEnvelopeJson(
          new TextEncoder().encode(selected.content),
        ),
        "rescue",
      );
      corpus = envelope.snapshot;
      if (
        selected.evidence.summary !==
        linuxNormalizedSnapshotEvidenceSummary(envelope)
      )
        return invalid();
    } else {
      corpus = parseRescueOfflineCorpus(parsed);
      if (corpus.family !== "windows") return invalid();
      if (selected.evidence.summary !== rescueOfflineCorpusSummary(corpus))
        return invalid();
    }
  } catch {
    return invalid();
  }
  const evidenceIds = [selected.evidence.id];
  if (corpus.family === "linux" && !corpus.topology.supported)
    return parseDiagnosisProposal({
      schemaVersion: "1.0",
      diagnosis:
        "Diagnosi Linux Rescue bloccata: il target dichiara filesystem separati sotto /etc, /boot (incluso /boot/efi), /efi, /usr o /var, non supportati dal profilo root-filesystem-only v1.",
      confidence: 0.1,
      evidenceIds,
      requestedEvidence: ["linux.topology.single-filesystem.v1"],
    });
  if (!corpus.installationConfirmed)
    return parseDiagnosisProposal({
      schemaVersion: "1.0",
      diagnosis:
        "Il contenuto statico del volume è stato ispezionato in sola lettura, ma i marker consentiti non confermano un'installazione completa. Non viene formulata una diagnosi del sistema.",
      confidence: 0.2,
      evidenceIds,
      requestedEvidence: [
        "rescue.installed-target.installation-confirmation.read-only.v1",
      ],
    });
  if (corpus.family === "linux") {
    if (corpus.configuration.fstab.malformedLineCount > 0)
      return parseDiagnosisProposal({
        schemaVersion: "1.0",
        diagnosis:
          "Il corpus Linux conferma l'installazione e segnala una o più righe fstab malformate. Verificare la configurazione di mount senza eseguire modifiche automatiche.",
        confidence: 0.84,
        evidenceIds,
        requestedEvidence: ["rescue.linux.fstab.review.read-only.v1"],
      });
    if (corpus.boot.directoryPresent && corpus.boot.kernelArtifactCount === 0)
      return parseDiagnosisProposal({
        schemaVersion: "1.0",
        diagnosis:
          "L'installazione Linux è confermata, ma nel volume ispezionato non è stato osservato alcun artefatto kernel regolare. Il boot può dipendere da un altro volume: serve una verifica read-only della topologia di avvio.",
        confidence: 0.68,
        evidenceIds,
        requestedEvidence: ["rescue.linux.boot-layout.read-only.v1"],
      });
    return parseDiagnosisProposal({
      schemaVersion: "1.0",
      diagnosis:
        "Installazione Linux confermata dal corpus statico read-only. Nei marker consentiti non emerge un'anomalia deterministica; servono controlli mirati prima di proporre modifiche.",
      confidence: 0.58,
      evidenceIds,
      requestedEvidence: ["rescue.linux.targeted-health.read-only.v1"],
    });
  }
  if (
    corpus.servicing.pendingXmlPresent ||
    corpus.servicing.rebootPendingMarkerPresent
  )
    return parseDiagnosisProposal({
      schemaVersion: "1.0",
      diagnosis:
        "Il corpus Windows conferma l'installazione e mostra marker statici di servicing o riavvio pendente. La causa deve essere verificata con strumenti Windows nativi prima di qualsiasi riparazione.",
      confidence: 0.8,
      evidenceIds,
      requestedEvidence: ["windows.update.state"],
    });
  const windowsRootBootMissing =
    !corpus.boot.bootManagerPresent && !corpus.boot.bcdPresent;
  const efi = corpus.boot.efiSystemPartition;
  if (
    windowsRootBootMissing &&
    efi.state === "inspected" &&
    !efi.microsoftBootManagerPresent &&
    !efi.bcdPresent &&
    !efi.fallbackBootloaderPresent
  )
    return parseDiagnosisProposal({
      schemaVersion: "1.0",
      diagnosis:
        "L'installazione Windows è confermata e l'unica partizione EFI associata è stata ispezionata in sola lettura, ma non contiene BCD, Windows Boot Manager o loader fallback x86-64. La catena di avvio richiede una verifica mirata prima di qualsiasi riparazione.",
      confidence: 0.76,
      evidenceIds,
      requestedEvidence: ["rescue.windows.boot-chain.verify.read-only.v1"],
    });
  if (windowsRootBootMissing && efi.state !== "inspected")
    return parseDiagnosisProposal({
      schemaVersion: "1.0",
      diagnosis:
        "L'installazione Windows è confermata, ma il volume ispezionato non contiene marker boot consentiti e la partizione EFI associata non è stata qualificata univocamente. Non viene dichiarato un guasto: serve una verifica read-only della topologia delle partizioni e del layout di avvio.",
      confidence: 0.46,
      evidenceIds,
      requestedEvidence: ["rescue.windows.boot-topology.review.read-only.v1"],
    });
  return parseDiagnosisProposal({
    schemaVersion: "1.0",
    diagnosis:
      "Installazione Windows confermata dal corpus statico read-only. Nei marker consentiti non emerge un'anomalia deterministica; servono controlli Windows mirati prima di proporre modifiche.",
    confidence: 0.58,
    evidenceIds,
    requestedEvidence: ["windows.offline.native-follow-up.v1"],
  });
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

function isSuccessfulMacosEvidence(
  item: ObservedEvidence | undefined,
): boolean {
  if (item === undefined) return false;
  if (
    item.evidence.contentType !== "application/json" ||
    item.evidence.trust !== "observed-untrusted" ||
    item.evidence.target !== "local-machine"
  )
    return false;
  if (MACOS_NOT_RUN_COLLECTORS.has(item.evidence.collector))
    return item.evidence.summary === MACOS_NOT_RUN_SUMMARY;
  if (item.evidence.collector === "macos.startup.state")
    return item.evidence.summary === MACOS_PARTIAL_STARTUP_SUMMARY;
  return item.evidence.summary === "Comando di inventario completato";
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

export function parseResidentOpenAiStatus(
  value: unknown,
): ResidentOpenAiStatus {
  const item = exactRecord(value, [
    "schemaVersion",
    "provider",
    "profile",
    "model",
    "credential",
  ]);
  if (
    item.schemaVersion !== "1.0" ||
    item.provider !== "openai" ||
    item.profile !== "resident-default" ||
    item.model !== "gpt-5.6-sol" ||
    !(item.credential === "absent" || item.credential === "configured")
  )
    throw new Error("Stato OpenAI Resident non valido.");
  return structuredClone(item) as unknown as ResidentOpenAiStatus;
}

function nativeOpenAiError(value: unknown): ProviderError {
  const fallback = new ProviderError(
    "transport",
    "OpenAI Resident non è disponibile.",
  );
  if (typeof value !== "object" || value === null || Array.isArray(value))
    return fallback;
  const item = value as Record<string, unknown>;
  if (Object.keys(item).some((key) => key !== "code" && key !== "message"))
    return fallback;
  const code = item.code;
  switch (code) {
    case "cancelled":
      return new ProviderError("cancelled", "Richiesta OpenAI annullata.");
    case "credential_unavailable":
      return new ProviderError(
        "credential_unavailable",
        "Credenziale OpenAI non disponibile.",
      );
    case "invalid_request":
      return new ProviderError(
        "invalid_request",
        "Richiesta OpenAI non valida.",
      );
    case "invalid_response":
      return new ProviderError(
        "invalid_response",
        "Risposta OpenAI non valida.",
      );
    case "request_too_large":
      return new ProviderError(
        "request_too_large",
        "Richiesta OpenAI troppo grande.",
      );
    case "response_too_large":
      return new ProviderError(
        "response_too_large",
        "Risposta OpenAI troppo grande.",
      );
    case "timeout":
      return new ProviderError("timeout", "Richiesta OpenAI scaduta.");
    case "upstream":
      return new ProviderError("upstream", "OpenAI ha rifiutato la richiesta.");
    case "busy":
    case "transport":
      return fallback;
    default:
      return fallback;
  }
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

function isJsonHttpResponse(response: Response): boolean {
  const value = response.headers.get("Content-Type");
  return value !== null && /^application\/json(?:\s*;|$)/iu.test(value);
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
