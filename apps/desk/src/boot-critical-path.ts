import {
  parseDiagnosisProposal,
  type DiagnosisProposal,
} from "@kernaid/schemas";

export const LINUX_BOOT_CRITICAL_PATH_COLLECTOR = "linux.boot-critical-path.v1";
export const LINUX_BOOT_CRITICAL_PATH_KIND = "linux-boot-critical-path";

export type LinuxBootCriticalPathState =
  "healthy" | "degraded" | "boot-risk" | "unsupported";

export interface LinuxBootFinding {
  ruleId:
    | "KA-LNX-BOOT-001"
    | "KA-LNX-BOOT-002"
    | "KA-LNX-BOOT-003"
    | "KA-LNX-BOOT-004"
    | "KA-LNX-BOOT-005"
    | "KA-LNX-BOOT-006"
    | "KA-LNX-BOOT-007";
  ruleVersion: 1;
  severity: "low" | "medium" | "high" | "critical";
  summary: string;
  nextAction: string;
}

export interface LinuxBootCriticalPathSnapshot {
  schemaVersion: "1.0";
  kind: typeof LINUX_BOOT_CRITICAL_PATH_KIND;
  scope: "local-root";
  state: LinuxBootCriticalPathState;
  runtime: {
    failedUnitsStatus: "complete" | "unavailable";
    failedUnitCount: number;
    criticalFailedUnitCount: number;
    criticalChainStatus: "complete" | "unavailable";
    criticalChainUnitCount: number;
    slowestActivationMillis: number | null;
  };
  configuration: {
    fstabStatus: "valid" | "absent" | "invalid" | "unavailable";
    fstabEntryCount: number;
    criticalMountEntryCount: number;
    initramfsStatus: "present" | "absent" | "unavailable";
    initramfsImageCount: number;
    kernelImageCount: number;
    bootloaderStatus: "configured" | "partial" | "absent" | "unavailable";
    bootloader: "grub" | "systemd-boot" | "multiple" | "other" | "none";
  };
  findings: LinuxBootFinding[];
}

const MAX_BYTES = 16 * 1024;
const FIXED_FINDINGS: Record<LinuxBootFinding["ruleId"], LinuxBootFinding> = {
  "KA-LNX-BOOT-001": {
    ruleId: "KA-LNX-BOOT-001",
    ruleVersion: 1,
    severity: "critical",
    summary: "A critical boot-path unit is in the failed state.",
    nextAction:
      "Keep the system read-only where possible, preserve evidence, and inspect the failed boot dependency before restarting.",
  },
  "KA-LNX-BOOT-002": {
    ruleId: "KA-LNX-BOOT-002",
    ruleVersion: 1,
    severity: "high",
    summary:
      "The fixed fstab parser found an invalid boot-critical configuration.",
    nextAction:
      "Review the boot-critical mount entries from Rescue and create a backup before any typed repair action.",
  },
  "KA-LNX-BOOT-003": {
    ruleId: "KA-LNX-BOOT-003",
    ruleVersion: 1,
    severity: "high",
    summary:
      "A kernel image is present but no matching initramfs artifact was observed.",
    nextAction:
      "Regenerate initramfs only through an OS-native, explicitly authorized repair workflow after preserving evidence.",
  },
  "KA-LNX-BOOT-004": {
    ruleId: "KA-LNX-BOOT-004",
    ruleVersion: 1,
    severity: "high",
    summary:
      "Bootloader configuration is absent or incomplete in the observed root.",
    nextAction:
      "Verify the firmware mode and boot partition from Rescue before using an OS-native bootloader recovery workflow.",
  },
  "KA-LNX-BOOT-005": {
    ruleId: "KA-LNX-BOOT-005",
    ruleVersion: 1,
    severity: "medium",
    summary:
      "The critical boot chain contains an activation of at least 30 seconds.",
    nextAction:
      "Inspect boot dependencies and device availability; no service or timeout was changed.",
  },
  "KA-LNX-BOOT-006": {
    ruleId: "KA-LNX-BOOT-006",
    ruleVersion: 1,
    severity: "medium",
    summary: "One or more non-critical systemd units are failed.",
    nextAction:
      "Inspect the affected unit class and its dependencies before considering a restart or repair.",
  },
  "KA-LNX-BOOT-007": {
    ruleId: "KA-LNX-BOOT-007",
    ruleVersion: 1,
    severity: "low",
    summary: "One or more fixed boot-path sources were unavailable.",
    nextAction:
      "Repeat the read-only collector with appropriate local privileges; no healthy conclusion was inferred for unavailable sources.",
  },
};

function invalid(): never {
  throw new Error("Percorso critico di boot Linux non valido.");
}

function exactRecord(
  value: unknown,
  keys: readonly string[],
): Record<string, unknown> {
  if (typeof value !== "object" || value === null || Array.isArray(value))
    return invalid();
  const record = value as Record<string, unknown>;
  if (
    Object.keys(record).length !== keys.length ||
    keys.some((key) => !Object.hasOwn(record, key))
  )
    return invalid();
  return record;
}

function boundedInteger(value: unknown, maximum: number): number {
  if (
    !Number.isSafeInteger(value) ||
    Number(value) < 0 ||
    Number(value) > maximum
  )
    return invalid();
  return Number(value);
}

function expectedRules(
  snapshot: LinuxBootCriticalPathSnapshot,
): LinuxBootFinding["ruleId"][] {
  const rules: LinuxBootFinding["ruleId"][] = [];
  if (snapshot.runtime.criticalFailedUnitCount > 0)
    rules.push("KA-LNX-BOOT-001");
  if (snapshot.configuration.fstabStatus === "invalid")
    rules.push("KA-LNX-BOOT-002");
  if (
    snapshot.configuration.kernelImageCount > 0 &&
    snapshot.configuration.initramfsImageCount === 0
  )
    rules.push("KA-LNX-BOOT-003");
  if (
    snapshot.configuration.bootloaderStatus === "partial" ||
    snapshot.configuration.bootloaderStatus === "absent"
  )
    rules.push("KA-LNX-BOOT-004");
  if ((snapshot.runtime.slowestActivationMillis ?? 0) >= 30_000)
    rules.push("KA-LNX-BOOT-005");
  if (
    snapshot.runtime.failedUnitCount > snapshot.runtime.criticalFailedUnitCount
  )
    rules.push("KA-LNX-BOOT-006");
  if (
    snapshot.runtime.failedUnitsStatus === "unavailable" ||
    snapshot.runtime.criticalChainStatus === "unavailable" ||
    snapshot.configuration.fstabStatus === "unavailable" ||
    snapshot.configuration.initramfsStatus === "unavailable" ||
    snapshot.configuration.bootloaderStatus === "unavailable"
  )
    rules.push("KA-LNX-BOOT-007");
  return rules;
}

export function parseLinuxBootCriticalPath(
  input: string,
): LinuxBootCriticalPathSnapshot {
  if (
    input.length === 0 ||
    input.endsWith("\n") ||
    new TextEncoder().encode(input).byteLength > MAX_BYTES
  )
    return invalid();
  let raw: unknown;
  try {
    raw = JSON.parse(input);
  } catch {
    return invalid();
  }
  if (JSON.stringify(raw) !== input) return invalid();
  const root = exactRecord(raw, [
    "schemaVersion",
    "kind",
    "scope",
    "state",
    "runtime",
    "configuration",
    "findings",
  ]);
  if (
    root.schemaVersion !== "1.0" ||
    root.kind !== LINUX_BOOT_CRITICAL_PATH_KIND ||
    root.scope !== "local-root" ||
    !["healthy", "degraded", "boot-risk", "unsupported"].includes(
      String(root.state),
    )
  )
    return invalid();
  const runtime = exactRecord(root.runtime, [
    "failedUnitsStatus",
    "failedUnitCount",
    "criticalFailedUnitCount",
    "criticalChainStatus",
    "criticalChainUnitCount",
    "slowestActivationMillis",
  ]);
  const failedUnitCount = boundedInteger(runtime.failedUnitCount, 256);
  const criticalFailedUnitCount = boundedInteger(
    runtime.criticalFailedUnitCount,
    256,
  );
  const criticalChainUnitCount = boundedInteger(
    runtime.criticalChainUnitCount,
    256,
  );
  const slowestActivationMillis =
    runtime.slowestActivationMillis === null
      ? null
      : boundedInteger(runtime.slowestActivationMillis, 86_400_000);
  if (
    !["complete", "unavailable"].includes(String(runtime.failedUnitsStatus)) ||
    !["complete", "unavailable"].includes(
      String(runtime.criticalChainStatus),
    ) ||
    criticalFailedUnitCount > failedUnitCount ||
    (runtime.failedUnitsStatus === "unavailable" && failedUnitCount !== 0) ||
    (runtime.criticalChainStatus === "unavailable" &&
      (criticalChainUnitCount !== 0 || slowestActivationMillis !== null))
  )
    return invalid();
  const configuration = exactRecord(root.configuration, [
    "fstabStatus",
    "fstabEntryCount",
    "criticalMountEntryCount",
    "initramfsStatus",
    "initramfsImageCount",
    "kernelImageCount",
    "bootloaderStatus",
    "bootloader",
  ]);
  const fstabEntryCount = boundedInteger(configuration.fstabEntryCount, 1024);
  const criticalMountEntryCount = boundedInteger(
    configuration.criticalMountEntryCount,
    1024,
  );
  const initramfsImageCount = boundedInteger(
    configuration.initramfsImageCount,
    512,
  );
  const kernelImageCount = boundedInteger(configuration.kernelImageCount, 512);
  if (
    !["valid", "absent", "invalid", "unavailable"].includes(
      String(configuration.fstabStatus),
    ) ||
    !["present", "absent", "unavailable"].includes(
      String(configuration.initramfsStatus),
    ) ||
    !["configured", "partial", "absent", "unavailable"].includes(
      String(configuration.bootloaderStatus),
    ) ||
    !["grub", "systemd-boot", "multiple", "other", "none"].includes(
      String(configuration.bootloader),
    ) ||
    criticalMountEntryCount > fstabEntryCount ||
    (configuration.fstabStatus !== "valid" &&
      (fstabEntryCount !== 0 || criticalMountEntryCount !== 0)) ||
    (configuration.initramfsStatus === "unavailable" &&
      (initramfsImageCount !== 0 || kernelImageCount !== 0)) ||
    (configuration.initramfsStatus === "present" &&
      initramfsImageCount === 0) ||
    (configuration.initramfsStatus === "absent" && initramfsImageCount !== 0) ||
    (configuration.bootloaderStatus === "configured") ===
      (configuration.bootloader === "none")
  )
    return invalid();
  if (!Array.isArray(root.findings) || root.findings.length > 7)
    return invalid();
  const snapshot = root as unknown as LinuxBootCriticalPathSnapshot;
  const expected = expectedRules(snapshot);
  const findings = root.findings.map((value) => {
    const item = exactRecord(value, [
      "ruleId",
      "ruleVersion",
      "severity",
      "summary",
      "nextAction",
    ]);
    if (!(String(item.ruleId) in FIXED_FINDINGS)) return invalid();
    return item as unknown as LinuxBootFinding;
  });
  if (
    findings.length !== expected.length ||
    findings.some(
      (finding, index) =>
        JSON.stringify(finding) !==
        JSON.stringify(FIXED_FINDINGS[expected[index]!]),
    )
  )
    return invalid();
  const allUnavailable =
    runtime.failedUnitsStatus === "unavailable" &&
    runtime.criticalChainStatus === "unavailable" &&
    configuration.fstabStatus === "unavailable" &&
    configuration.initramfsStatus === "unavailable" &&
    configuration.bootloaderStatus === "unavailable";
  const hasRisk = findings.some(
    (finding) => finding.severity === "high" || finding.severity === "critical",
  );
  const expectedState: LinuxBootCriticalPathState = allUnavailable
    ? "unsupported"
    : hasRisk
      ? "boot-risk"
      : findings.length > 0
        ? "degraded"
        : "healthy";
  if (snapshot.state !== expectedState) return invalid();
  return structuredClone(snapshot);
}

export function bootCriticalPathEvidenceSummary(
  snapshot: LinuxBootCriticalPathSnapshot,
): string {
  const parsed = parseLinuxBootCriticalPath(JSON.stringify(snapshot));
  switch (parsed.state) {
    case "healthy":
      return "Fixed boot-path checks found no deterministic boot risk";
    case "degraded":
      return "Boot path is degraded or only partially observable";
    case "boot-risk":
      return "Fixed boot-path checks found a deterministic boot risk";
    case "unsupported":
      return "Boot-path checks unavailable; no healthy state inferred";
  }
}

export function augmentDiagnosisWithBootCriticalPath(
  proposal: DiagnosisProposal,
  snapshot: LinuxBootCriticalPathSnapshot,
  evidenceId: string,
): DiagnosisProposal {
  const parsed = parseLinuxBootCriticalPath(JSON.stringify(snapshot));
  const suffix =
    parsed.state === "boot-risk"
      ? " Fixed read-only boot checks found a deterministic boot risk; preserve evidence and use Rescue before any typed repair."
      : parsed.state === "degraded"
        ? " The boot path is degraded or partially observable; no boot repair was performed."
        : parsed.state === "unsupported"
          ? " Boot-path checks are unavailable, so no healthy boot conclusion is made."
          : " Fixed read-only boot checks found no deterministic risk; this is not a guarantee against every boot fault.";
  return parseDiagnosisProposal({
    ...proposal,
    diagnosis: `${proposal.diagnosis}${suffix}`,
    confidence:
      parsed.state === "boot-risk"
        ? Math.max(proposal.confidence, 0.95)
        : proposal.confidence,
    evidenceIds: Array.from(new Set([...proposal.evidenceIds, evidenceId])),
  });
}
