import type {
  NativeObservation,
  RescueTargetBinding,
  RescueTargetCandidate,
  RescueTargetScan,
  RescueTargetSelection,
} from "./native";

export type InventoryCategory = "Hardware" | "Storage" | "Boot" | "Network";
export type ObservationStatus = "observed" | "unavailable" | "pending";

export interface RescueCandidatePresentation {
  title: string;
  detail: string;
}

export function rescueTargetBinding(
  selection: RescueTargetSelection,
): RescueTargetBinding {
  return {
    scanFingerprint: selection.scanFingerprint,
    target: selection.target,
  };
}

export function sameRescueSelection(
  left: RescueTargetSelection | undefined,
  right: RescueTargetSelection | undefined,
): boolean {
  return (
    left !== undefined &&
    right !== undefined &&
    left.scanFingerprint === right.scanFingerprint &&
    left.target.targetId === right.target.targetId
  );
}

export function rescueCandidatePresentation(
  scan: RescueTargetScan,
  candidate: RescueTargetCandidate,
  index: number,
): RescueCandidatePresentation {
  const disk = scan.disks.find((item) => item.id === candidate.diskId);
  const volume = disk?.volumes.find((item) => item.ref === candidate.sourceRef);
  const filesystem = volume?.filesystem ?? "filesystem intero disco";
  const size = volume?.sizeBytes ?? disk?.sizeBytes ?? 0;
  const transport = disk?.transport ?? "unknown";
  return {
    title: `Candidato ${index + 1} · ${targetFamilyLabel(candidate.osFamilyHint)}`,
    detail: [
      candidate.sourceRef,
      formatBytes(size),
      filesystem,
      transport.toUpperCase(),
      "confidenza bassa",
      ...(candidate.requiresUnlock ? ["cifrato"] : []),
    ].join(" · "),
  };
}

export function observationStatus(
  category: InventoryCategory,
  observations: readonly NativeObservation[],
): ObservationStatus {
  const matching = observations.filter((item) =>
    collectorBelongsTo(category, item.collector),
  );
  if (matching.length === 0) return "pending";
  return matching.every((item) => item.success && !item.truncated)
    ? "observed"
    : "unavailable";
}

export function formatBytes(value: number): string {
  if (!Number.isSafeInteger(value) || value < 0) return "dimensione non valida";
  if (value === 0) return "0 B";
  const units = ["B", "KiB", "MiB", "GiB", "TiB", "PiB"];
  const exponent = Math.min(
    Math.floor(Math.log(value) / Math.log(1024)),
    units.length - 1,
  );
  const amount = value / 1024 ** exponent;
  return `${amount >= 10 || exponent === 0 ? amount.toFixed(0) : amount.toFixed(1)} ${units[exponent]}`;
}

export function targetFamilyLabel(
  value: RescueTargetCandidate["osFamilyHint"],
): string {
  switch (value) {
    case "linux":
      return "Linux";
    case "windows":
      return "Windows";
    case "macos":
      return "macOS";
    case "unknown-encrypted":
      return "cifrato non identificato";
    case "unknown":
      return "non identificato";
  }
}

function collectorBelongsTo(
  category: InventoryCategory,
  collector: string,
): boolean {
  switch (category) {
    case "Hardware":
      return collector === "system.hostname" || collector.endsWith(".system");
    case "Storage":
      return /block\.inventory|\.disks$|\.storage(?:\.|$)|\.df$/u.test(
        collector,
      );
    case "Boot":
      return /systemd|fstab|dpkg|boot|update/u.test(collector);
    case "Network":
      return collector.includes("network");
  }
}
