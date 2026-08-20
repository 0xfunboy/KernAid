import type {
  NativeObservation,
  RescueOfflineInspection,
  RescueOfflineInspectionError,
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

export interface RescueInspectionPresentation {
  title: string;
  detail: string;
  facts: string[];
}

export interface RescueInspectionErrorPresentation {
  title: string;
  detail: string;
  action: string;
  severity: "unsupported" | "retryable" | "blocked";
}

export interface RescueInspectionLatch {
  current: boolean;
}

export interface RescueInspectionFailureDisposition {
  current: boolean;
  requiresRestart: boolean;
}

export function tryStartRescueInspection(
  latch: RescueInspectionLatch,
): boolean {
  if (latch.current) return false;
  latch.current = true;
  return true;
}

export function finishRescueInspection(latch: RescueInspectionLatch): void {
  latch.current = false;
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

export function sameRescueInspection(
  selection: RescueTargetSelection | undefined,
  inspection: RescueOfflineInspection | undefined,
): boolean {
  return (
    selection !== undefined &&
    inspection !== undefined &&
    inspection.target.scanFingerprint === selection.scanFingerprint &&
    inspection.target.targetId === selection.target.targetId &&
    inspection.target.sourceRef === selection.target.sourceRef &&
    inspection.target.osFamily === selection.target.osFamilyHint
  );
}

export function rescueInspectionResponseCurrent(
  operationEpoch: number,
  currentEpoch: number,
  selection: RescueTargetSelection | undefined,
  inspection: RescueOfflineInspection | undefined,
): boolean {
  return (
    Number.isSafeInteger(operationEpoch) &&
    operationEpoch >= 0 &&
    operationEpoch === currentEpoch &&
    sameRescueInspection(selection, inspection)
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

export function rescueInspectionPresentation(
  inspection: RescueOfflineInspection,
): RescueInspectionPresentation {
  const corpus = inspection.os;
  if (corpus.family === "linux") {
    const release =
      corpus.release.prettyName ??
      corpus.release.name ??
      corpus.release.id ??
      "Linux non identificato";
    return {
      title: release,
      detail: `${inspection.target.filesystem.toUpperCase()} · ${corpus.installationConfirmed ? "installazione confermata" : "installazione non confermata"} · sola lettura`,
      facts: [
        `Boot: ${corpus.boot.kernelArtifactCount} kernel · ${corpus.boot.initramfsArtifactCount} initramfs · ${corpus.boot.bootloaderDirectoryCount} directory loader`,
        `fstab: ${corpus.configuration.fstab.entryCount} voci · ${corpus.configuration.fstab.malformedLineCount} malformate`,
        `Database pacchetti: ${presentCount([
          corpus.packageDatabases.dpkgStatusPresent,
          corpus.packageDatabases.rpmDatabasePresent,
          corpus.packageDatabases.pacmanDatabasePresent,
        ])}/3 osservati`,
      ],
    };
  }
  const efi = corpus.boot.efiSystemPartition;
  const efiFact =
    efi.state === "inspected"
      ? `ESP associata: ${presentCount([
          efi.microsoftBootManagerPresent,
          efi.bcdPresent,
          efi.fallbackBootloaderPresent,
        ])}/3 marker osservati`
      : `ESP associata: ${efi.state}`;
  return {
    title: "Windows",
    detail: `${inspection.target.filesystem.toUpperCase()} · ${corpus.installationConfirmed ? "installazione confermata" : "installazione non confermata"} · sola lettura`,
    facts: [
      `Marker installazione: ${presentCount(Object.values(corpus.installationMarkers))}/6 osservati`,
      `Marker boot volume Windows: ${presentCount([
        corpus.boot.bootManagerPresent,
        corpus.boot.bcdPresent,
      ])}/2 osservati`,
      efiFact,
      `Servicing pendente: ${corpus.servicing.pendingXmlPresent || corpus.servicing.rebootPendingMarkerPresent ? "osservato" : "non osservato"}`,
      "Stato dirty/ibernazione NTFS non qualificato",
    ],
  };
}

export function rescueInspectionErrorPresentation(
  error: RescueOfflineInspectionError,
): RescueInspectionErrorPresentation {
  if (
    error.claims.mountOperationPerformed &&
    !error.claims.mountCleanupVerified
  )
    return cleanupNotVerifiedPresentation();
  switch (error.code) {
    case "unsupported-encrypted-storage":
      return {
        title: "Volume cifrato non ispezionato",
        detail:
          "KernAid non tenta sblocco automatico di LUKS, BitLocker o FileVault.",
        action:
          "Usa il percorso nativo autorizzato con le credenziali del proprietario.",
        severity: "unsupported",
      };
    case "unsupported-apple-filesystem":
      return {
        title: "Filesystem Apple non supportato da Rescue",
        detail: "APFS e HFS richiedono macOS o Apple Recovery.",
        action: "Avvia KernAid Desk nel percorso Apple nativo.",
        severity: "unsupported",
      };
    case "unsupported-complex-storage":
      return {
        title: "Topologia storage complessa",
        detail:
          "LVM, mdraid e mapping impilati non vengono attivati automaticamente.",
        action: "Seleziona un altro target o usa una procedura dedicata.",
        severity: "unsupported",
      };
    case "unsupported-filesystem":
      return {
        title: "Filesystem non qualificato",
        detail:
          "Questo filesystem non è incluso nel percorso offline read-only corrente.",
        action: "Usa Resident, WinPE o il percorso nativo appropriato.",
        severity: "unsupported",
      };
    case "ambiguous-os-family":
      return {
        title: "Sistema operativo ambiguo",
        detail:
          "I metadati non identificano una sola famiglia compatibile con il filesystem.",
        action:
          "Ripeti la scansione o usa una procedura di inventario dedicata.",
        severity: "unsupported",
      };
    case "target-identity-changed":
    case "target-revalidation-failed":
    case "target-identity-invalid":
    case "target-device-ambiguous":
    case "target-resolution-invalid":
      return {
        title: "Target cambiato o non più univoco",
        detail: "La selezione precedente è stata invalidata.",
        action: "Ripeti la scansione e seleziona nuovamente il target.",
        severity: "retryable",
      };
    case "mount-cleanup-failed":
    case "mount-postcondition-failed":
    case "mount-verification-failed":
    case "mount-root-unsafe":
      return cleanupNotVerifiedPresentation();
    case "inspection-timeout":
    case "privileged-helper-unavailable":
    case "associated-efi-already-mounted":
    case "target-already-mounted":
      return {
        title: "Ispezione temporaneamente non disponibile",
        detail: "Nessun corpus diagnostico è stato accettato.",
        action: "Controlla il target e riprova manualmente.",
        severity: "retryable",
      };
    default:
      return {
        title: "Ispezione bloccata in sicurezza",
        detail:
          "La risposta locale o una precondizione read-only non ha superato la validazione.",
        action: error.retryable
          ? "Ripeti manualmente dopo una nuova scansione."
          : "Usa un percorso diagnostico qualificato diverso.",
        severity: error.retryable ? "retryable" : "blocked",
      };
  }
}

function cleanupNotVerifiedPresentation(): RescueInspectionErrorPresentation {
  return {
    title: "Cleanup read-only non verificato",
    detail:
      "KernAid non può attestare la chiusura completa dell'ispezione temporanea.",
    action: "Riavvia KernAid Rescue prima di un'altra ispezione.",
    severity: "blocked",
  };
}

export function rescueInspectionNeedsRescan(
  error: RescueOfflineInspectionError,
): boolean {
  return new Set([
    "associated-efi-already-mounted",
    "target-already-mounted",
    "target-device-ambiguous",
    "target-identity-changed",
    "target-identity-invalid",
    "target-resolution-invalid",
    "target-revalidation-failed",
  ]).has(error.code);
}

export function rescueInspectionRequiresRestart(
  error: RescueOfflineInspectionError,
): boolean {
  return (
    (error.claims.mountOperationPerformed &&
      !error.claims.mountCleanupVerified) ||
    new Set([
      "mount-cleanup-failed",
      "mount-postcondition-failed",
      "mount-root-unsafe",
      "mount-verification-failed",
    ]).has(error.code)
  );
}

export function rescueInspectionFailureDisposition(
  operationEpoch: number,
  currentEpoch: number,
  error: RescueOfflineInspectionError,
): RescueInspectionFailureDisposition {
  return {
    current:
      Number.isSafeInteger(operationEpoch) &&
      operationEpoch >= 0 &&
      operationEpoch === currentEpoch,
    requiresRestart: rescueInspectionRequiresRestart(error),
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
      return (
        collector === "system.hostname" ||
        collector === "linux.hardware.inventory" ||
        collector.endsWith(".system")
      );
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

function presentCount(values: readonly boolean[]): number {
  return values.filter(Boolean).length;
}
