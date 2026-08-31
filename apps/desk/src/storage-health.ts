import {
  parseDiagnosisProposal,
  type DiagnosisProposal,
} from "@kernaid/schemas";

export const LINUX_STORAGE_HEALTH_COLLECTOR = "linux.storage.health.v1";
export const LINUX_STORAGE_HEALTH_KIND = "linux-storage-health";

export type StorageHealthState =
  "healthy" | "degraded" | "failing" | "unsupported" | "permission-unavailable";

export interface LinuxStorageDiskHealth {
  diskRef: string;
  state: StorageHealthState;
  overallPassed: boolean | null;
  criticalWarning: number | null;
  mediaErrors: number | null;
  temperatureCelsius: number | null;
  availableSparePercent: number | null;
  percentageUsed: number | null;
}

export interface LinuxStorageHealthFinding {
  ruleId:
    | "KA-LNX-STORAGE-001"
    | "KA-LNX-STORAGE-002"
    | "KA-LNX-STORAGE-003"
    | "KA-LNX-STORAGE-004";
  ruleVersion: 1;
  severity: "low" | "medium" | "high" | "critical";
  diskRef: string;
  summary: string;
  nextAction: string;
}

export interface LinuxStorageHealthSnapshot {
  schemaVersion: "1.0";
  kind: typeof LINUX_STORAGE_HEALTH_KIND;
  scope: "local-physical-disks";
  enumerationStatus: "complete" | "unsupported";
  disks: LinuxStorageDiskHealth[];
  findings: LinuxStorageHealthFinding[];
}

const DISK_REF = /^disk-([1-9]|[12][0-9]|3[0-2])$/u;
const MAX_BYTES = 64 * 1024;
const FIXED_FINDINGS: Record<
  Exclude<StorageHealthState, "healthy">,
  Omit<LinuxStorageHealthFinding, "diskRef">
> = {
  failing: {
    ruleId: "KA-LNX-STORAGE-001",
    ruleVersion: 1,
    severity: "critical",
    summary: "The drive reports a deterministic failure indicator.",
    nextAction:
      "Back up recoverable data immediately and replace the drive; KernAid will not claim a hardware repair.",
  },
  degraded: {
    ruleId: "KA-LNX-STORAGE-002",
    ruleVersion: 1,
    severity: "high",
    summary: "The drive reports a deterministic degradation indicator.",
    nextAction:
      "Back up important data now and schedule drive replacement after vendor diagnostics.",
  },
  "permission-unavailable": {
    ruleId: "KA-LNX-STORAGE-003",
    ruleVersion: 1,
    severity: "medium",
    summary:
      "Drive health telemetry could not be read with the current privileges.",
    nextAction:
      "Repeat this read-only check through an authorized local or Rescue collector; do not infer that the drive is healthy.",
  },
  unsupported: {
    ruleId: "KA-LNX-STORAGE-004",
    ruleVersion: 1,
    severity: "low",
    summary: "Drive health telemetry is unsupported or unavailable.",
    nextAction:
      "Use the drive vendor's read-only diagnostic and keep a current backup; no health conclusion was made.",
  },
};

function invalid(): never {
  throw new Error("Snapshot salute storage Linux non valido.");
}

function exactRecord(
  value: unknown,
  keys: readonly string[],
): Record<string, unknown> {
  if (typeof value !== "object" || value === null || Array.isArray(value))
    return invalid();
  const item = value as Record<string, unknown>;
  if (
    Object.keys(item).length !== keys.length ||
    keys.some((key) => !Object.hasOwn(item, key))
  )
    return invalid();
  return item;
}

function nullableInteger(
  value: unknown,
  minimum: number,
  maximum: number,
): number | null {
  if (value === null) return null;
  if (
    !Number.isSafeInteger(value) ||
    Number(value) < minimum ||
    Number(value) > maximum
  )
    return invalid();
  return Number(value);
}

function hasIndicators(disk: LinuxStorageDiskHealth): boolean {
  return (
    disk.overallPassed !== null ||
    disk.criticalWarning !== null ||
    disk.mediaErrors !== null ||
    disk.temperatureCelsius !== null ||
    disk.availableSparePercent !== null ||
    disk.percentageUsed !== null
  );
}

function expectedFinding(
  disk: LinuxStorageDiskHealth,
): LinuxStorageHealthFinding {
  if (disk.state === "healthy") return invalid();
  const fixed = FIXED_FINDINGS[disk.state];
  return {
    ruleId: fixed.ruleId,
    ruleVersion: fixed.ruleVersion,
    severity: fixed.severity,
    diskRef: disk.diskRef,
    summary: fixed.summary,
    nextAction: fixed.nextAction,
  };
}

function parseDisk(value: unknown): LinuxStorageDiskHealth {
  const item = exactRecord(value, [
    "diskRef",
    "state",
    "overallPassed",
    "criticalWarning",
    "mediaErrors",
    "temperatureCelsius",
    "availableSparePercent",
    "percentageUsed",
  ]);
  if (
    typeof item.diskRef !== "string" ||
    !DISK_REF.test(item.diskRef) ||
    !(
      item.state === "healthy" ||
      item.state === "degraded" ||
      item.state === "failing" ||
      item.state === "unsupported" ||
      item.state === "permission-unavailable"
    ) ||
    !(item.overallPassed === null || typeof item.overallPassed === "boolean")
  )
    return invalid();
  const disk: LinuxStorageDiskHealth = {
    diskRef: item.diskRef,
    state: item.state,
    overallPassed: item.overallPassed,
    criticalWarning: nullableInteger(item.criticalWarning, 0, 255),
    mediaErrors: nullableInteger(item.mediaErrors, 0, Number.MAX_SAFE_INTEGER),
    temperatureCelsius: nullableInteger(item.temperatureCelsius, -100, 300),
    availableSparePercent: nullableInteger(item.availableSparePercent, 0, 255),
    percentageUsed: nullableInteger(item.percentageUsed, 0, 255),
  };
  if (
    ((disk.state === "unsupported" ||
      disk.state === "permission-unavailable") &&
      hasIndicators(disk)) ||
    ((disk.state === "healthy" ||
      disk.state === "degraded" ||
      disk.state === "failing") &&
      !hasIndicators(disk))
  )
    return invalid();
  return disk;
}

export function parseLinuxStorageHealth(
  input: string,
): LinuxStorageHealthSnapshot {
  if (
    input.length === 0 ||
    new TextEncoder().encode(input).byteLength > MAX_BYTES ||
    input.endsWith("\n")
  )
    return invalid();
  let raw: unknown;
  try {
    raw = JSON.parse(input);
  } catch {
    return invalid();
  }
  if (JSON.stringify(raw) !== input) return invalid();
  const item = exactRecord(raw, [
    "schemaVersion",
    "kind",
    "scope",
    "enumerationStatus",
    "disks",
    "findings",
  ]);
  if (
    item.schemaVersion !== "1.0" ||
    item.kind !== LINUX_STORAGE_HEALTH_KIND ||
    item.scope !== "local-physical-disks" ||
    !(
      item.enumerationStatus === "complete" ||
      item.enumerationStatus === "unsupported"
    ) ||
    !Array.isArray(item.disks) ||
    item.disks.length > 32 ||
    !Array.isArray(item.findings) ||
    item.findings.length > 32
  )
    return invalid();
  const disks = item.disks.map(parseDisk);
  const numbers = disks.map((disk) => Number(disk.diskRef.slice(5)));
  if (
    numbers.some(
      (number, index) => index > 0 && number <= numbers[index - 1]!,
    ) ||
    (item.enumerationStatus === "unsupported" && disks.length !== 0)
  )
    return invalid();
  const findings = item.findings.map((value) => {
    const finding = exactRecord(value, [
      "ruleId",
      "ruleVersion",
      "severity",
      "diskRef",
      "summary",
      "nextAction",
    ]) as unknown as LinuxStorageHealthFinding;
    return finding;
  });
  const expected = disks
    .filter((disk) => disk.state !== "healthy")
    .map(expectedFinding);
  if (JSON.stringify(findings) !== JSON.stringify(expected)) return invalid();
  return structuredClone({
    schemaVersion: "1.0",
    kind: LINUX_STORAGE_HEALTH_KIND,
    scope: "local-physical-disks",
    enumerationStatus: item.enumerationStatus,
    disks,
    findings,
  }) as LinuxStorageHealthSnapshot;
}

export function projectLinuxStorageHealth(
  snapshot: LinuxStorageHealthSnapshot,
  diskRef: string,
): LinuxStorageHealthSnapshot | undefined {
  const parsed = parseLinuxStorageHealth(JSON.stringify(snapshot));
  if (!DISK_REF.test(diskRef)) return undefined;
  const disk = parsed.disks.find((item) => item.diskRef === diskRef);
  if (disk === undefined) return undefined;
  return {
    ...parsed,
    disks: [structuredClone(disk)],
    findings: disk.state === "healthy" ? [] : [expectedFinding(disk)],
  };
}

export function storageHealthEvidenceSummary(
  snapshot: LinuxStorageHealthSnapshot,
): string {
  const parsed = parseLinuxStorageHealth(JSON.stringify(snapshot));
  if (parsed.enumerationStatus === "unsupported")
    return "Storage health enumeration unavailable; no healthy state inferred";
  if (parsed.disks.some((disk) => disk.state === "failing"))
    return "Read-only storage health found a failing drive";
  if (parsed.disks.some((disk) => disk.state === "degraded"))
    return "Read-only storage health found a degraded drive";
  if (
    parsed.disks.some(
      (disk) =>
        disk.state === "unsupported" || disk.state === "permission-unavailable",
    )
  )
    return "Read-only storage health completed with unavailable telemetry";
  return "Read-only storage health indicators are healthy";
}

export function augmentDiagnosisWithStorageHealth(
  proposal: DiagnosisProposal,
  snapshot: LinuxStorageHealthSnapshot,
  evidenceId: string,
): DiagnosisProposal {
  const parsed = parseLinuxStorageHealth(JSON.stringify(snapshot));
  const states = new Set(parsed.disks.map((disk) => disk.state));
  let suffix: string;
  let confidence = proposal.confidence;
  if (states.has("failing")) {
    suffix =
      " Storage health reports a failing drive: back up recoverable data immediately and replace it; software cannot repair physical media.";
    confidence = Math.max(confidence, 0.96);
  } else if (states.has("degraded")) {
    suffix =
      " Storage health reports degradation: back up important data and schedule drive replacement after vendor diagnostics.";
    confidence = Math.max(confidence, 0.9);
  } else if (
    states.has("permission-unavailable") ||
    states.has("unsupported") ||
    parsed.enumerationStatus === "unsupported"
  ) {
    suffix =
      " Storage health telemetry is unavailable, so no healthy-drive conclusion is made.";
  } else {
    suffix =
      " The available read-only SMART/NVMe indicators report no deterministic storage-health anomaly.";
  }
  return parseDiagnosisProposal({
    ...proposal,
    diagnosis: `${proposal.diagnosis}${suffix}`,
    confidence,
    evidenceIds: Array.from(new Set([...proposal.evidenceIds, evidenceId])),
  });
}
