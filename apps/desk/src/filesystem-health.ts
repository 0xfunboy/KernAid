import {
  parseDiagnosisProposal,
  type DiagnosisProposal,
} from "@kernaid/schemas";

export const LINUX_FILESYSTEM_HEALTH_COLLECTOR = "linux.filesystem.health.v1";
export const LINUX_FILESYSTEM_HEALTH_KIND = "linux-filesystem-health";

export type FilesystemHealthState =
  "healthy" | "degraded" | "repair-required" | "unsupported";

export interface LinuxFilesystemHealthFinding {
  ruleId: "KA-LNX-FS-001" | "KA-LNX-FS-002" | "KA-LNX-FS-003";
  ruleVersion: 1;
  severity: "low" | "high" | "critical";
  summary: string;
  nextAction: string;
}

export interface LinuxFilesystemHealthSnapshot {
  schemaVersion: "1.0";
  kind: typeof LINUX_FILESYSTEM_HEALTH_KIND;
  targetRef: string;
  filesystem: "ext4" | "ntfs" | "other";
  state: FilesystemHealthState;
  checkMode: "e2fsck-read-only" | "ntfsfix-no-action" | "unavailable";
  mountedAtCheck: boolean;
  finding: LinuxFilesystemHealthFinding | null;
}

const TARGET_REF =
  /^(?:local-root|disk-(?:[1-9]|[12][0-9]|3[0-2])(?:\/volume-(?:[1-9]|[1-9][0-9]|1[01][0-9]|12[0-8]))?)$/u;
const MAX_BYTES = 16 * 1024;
const FIXED_FINDINGS: Record<
  Exclude<FilesystemHealthState, "healthy">,
  LinuxFilesystemHealthFinding
> = {
  "repair-required": {
    ruleId: "KA-LNX-FS-001",
    ruleVersion: 1,
    severity: "critical",
    summary:
      "The fixed read-only filesystem check reports errors that require repair.",
    nextAction:
      "Back up recoverable data, then use the operating system's native repair workflow with explicit write authorization; KernAid did not modify this filesystem.",
  },
  degraded: {
    ruleId: "KA-LNX-FS-002",
    ruleVersion: 1,
    severity: "high",
    summary:
      "The filesystem was checked while mounted, so a clean result cannot be qualified.",
    nextAction:
      "Boot KernAid Rescue and repeat the fixed read-only check on the unmounted selected target.",
  },
  unsupported: {
    ruleId: "KA-LNX-FS-003",
    ruleVersion: 1,
    severity: "low",
    summary:
      "The fixed read-only filesystem check is unsupported or unavailable.",
    nextAction:
      "Use a qualified read-only diagnostic for this filesystem; do not infer that it is healthy.",
  },
};

function invalid(): never {
  throw new Error("Risultato diagnostica filesystem non valido.");
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

function expectedFinding(
  state: FilesystemHealthState,
): LinuxFilesystemHealthFinding | null {
  return state === "healthy" ? null : structuredClone(FIXED_FINDINGS[state]);
}

export function parseLinuxFilesystemHealth(
  input: string,
): LinuxFilesystemHealthSnapshot {
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
    "targetRef",
    "filesystem",
    "state",
    "checkMode",
    "mountedAtCheck",
    "finding",
  ]);
  if (
    item.schemaVersion !== "1.0" ||
    item.kind !== LINUX_FILESYSTEM_HEALTH_KIND ||
    typeof item.targetRef !== "string" ||
    !TARGET_REF.test(item.targetRef) ||
    !(
      item.filesystem === "ext4" ||
      item.filesystem === "ntfs" ||
      item.filesystem === "other"
    ) ||
    !(
      item.state === "healthy" ||
      item.state === "degraded" ||
      item.state === "repair-required" ||
      item.state === "unsupported"
    ) ||
    !(
      item.checkMode === "e2fsck-read-only" ||
      item.checkMode === "ntfsfix-no-action" ||
      item.checkMode === "unavailable"
    ) ||
    typeof item.mountedAtCheck !== "boolean"
  )
    return invalid();
  const snapshot = item as unknown as LinuxFilesystemHealthSnapshot;
  const expectedMode =
    snapshot.filesystem === "ext4"
      ? "e2fsck-read-only"
      : snapshot.filesystem === "ntfs"
        ? "ntfsfix-no-action"
        : "unavailable";
  if (
    (snapshot.targetRef === "local-root" && !snapshot.mountedAtCheck) ||
    (snapshot.targetRef !== "local-root" &&
      snapshot.mountedAtCheck &&
      snapshot.state !== "unsupported") ||
    (snapshot.state === "unsupported") !==
      (snapshot.checkMode === "unavailable") ||
    (snapshot.checkMode !== expectedMode &&
      snapshot.checkMode !== "unavailable") ||
    JSON.stringify(snapshot.finding) !==
      JSON.stringify(expectedFinding(snapshot.state))
  )
    return invalid();
  return structuredClone(snapshot);
}

export function filesystemHealthEvidenceSummary(
  snapshot: LinuxFilesystemHealthSnapshot,
): string {
  const parsed = parseLinuxFilesystemHealth(JSON.stringify(snapshot));
  switch (parsed.state) {
    case "healthy":
      return "Fixed read-only filesystem check found no deterministic error";
    case "degraded":
      return "Filesystem check completed but mounted state prevents qualification";
    case "repair-required":
      return "Fixed read-only filesystem check reports repair-required errors";
    case "unsupported":
      return "Filesystem check unavailable; no healthy state inferred";
  }
}

export function augmentDiagnosisWithFilesystemHealth(
  proposal: DiagnosisProposal,
  snapshot: LinuxFilesystemHealthSnapshot,
  evidenceId: string,
): DiagnosisProposal {
  const parsed = parseLinuxFilesystemHealth(JSON.stringify(snapshot));
  let suffix: string;
  let confidence = proposal.confidence;
  switch (parsed.state) {
    case "repair-required":
      suffix =
        " The selected filesystem requires repair: back up recoverable data first, then use the OS-native repair workflow with explicit write authorization. KernAid made no filesystem change.";
      confidence = Math.max(confidence, 0.95);
      break;
    case "degraded":
      suffix =
        " The filesystem check ran read-only while mounted, so repeat it from Rescue before drawing a clean conclusion.";
      break;
    case "unsupported":
      suffix =
        " The fixed filesystem check is unavailable, so no healthy-filesystem conclusion is made.";
      break;
    case "healthy":
      suffix =
        " The fixed read-only filesystem check found no deterministic error; this is not a guarantee against every filesystem fault.";
      break;
  }
  return parseDiagnosisProposal({
    ...proposal,
    diagnosis: `${proposal.diagnosis}${suffix}`,
    confidence,
    evidenceIds: Array.from(new Set([...proposal.evidenceIds, evidenceId])),
  });
}
