import assert from "node:assert/strict";
import test from "node:test";
import { RescueOfflineInspectionError } from "../src/native.js";
import {
  finishRescueInspection,
  formatBytes,
  observationStatus,
  rescueCandidatePresentation,
  rescueDiagnosisWizardProgress,
  rescueInspectionErrorPresentation,
  rescueInspectionFailureDisposition,
  rescueInspectionNeedsRescan,
  rescueInspectionPresentation,
  rescueInspectionRequiresRestart,
  rescueInspectionResponseCurrent,
  sameRescueInspection,
  sameRescueSelection,
  tryStartRescueInspection,
} from "../src/rescue-ui.js";

test("Rescue diagnosis wizard advances only through established state", () => {
  assert.deepEqual(
    rescueDiagnosisWizardProgress({
      vaultStatusReady: false,
      targetSelected: false,
      inspectionReady: false,
      reportReady: false,
    }),
    {
      vault: "current",
      target: "pending",
      provider: "pending",
      diagnosis: "pending",
      report: "pending",
    },
  );
  assert.deepEqual(
    rescueDiagnosisWizardProgress({
      vaultStatusReady: true,
      targetSelected: true,
      inspectionReady: true,
      reportReady: false,
    }),
    {
      vault: "complete",
      target: "complete",
      provider: "complete",
      diagnosis: "current",
      report: "pending",
    },
  );
  assert.equal(
    rescueDiagnosisWizardProgress({
      vaultStatusReady: true,
      targetSelected: true,
      inspectionReady: true,
      reportReady: true,
    }).report,
    "current",
  );
});

test("same-family Rescue candidates remain visibly distinguishable", () => {
  const scan = targetScanFixture();
  const first = rescueCandidatePresentation(scan, scan.candidates[0]!, 0);
  const second = rescueCandidatePresentation(scan, scan.candidates[1]!, 1);
  assert.match(first.detail, /disk-1\/volume-1/);
  assert.match(first.detail, /NTFS/i);
  assert.match(first.detail, /465 GiB/);
  assert.match(second.detail, /disk-2\/volume-1/);
  assert.match(second.detail, /930 GiB/);
  assert.notEqual(first.detail, second.detail);
});

test("Rescue environment status uses collector identity and success", () => {
  const base = {
    trust: "observed-untrusted" as const,
    output: "fixture",
    success: true,
    truncated: false,
  };
  assert.equal(
    observationStatus("Network", [
      { ...base, collector: "system.hostname" },
      { ...base, collector: "linux.network.links", success: false },
    ]),
    "unavailable",
  );
  assert.equal(
    observationStatus("Storage", [
      { ...base, collector: "linux.block.inventory" },
    ]),
    "observed",
  );
  assert.equal(
    observationStatus("Hardware", [
      { ...base, collector: "linux.hardware.inventory" },
    ]),
    "observed",
  );
  assert.equal(
    observationStatus("Boot", [{ ...base, collector: "linux.network.links" }]),
    "pending",
  );
});

test("a session selection cannot survive a Rescue retarget", () => {
  const scan = targetScanFixture();
  const first = {
    apiVersion: scan.apiVersion,
    status: "observe-target-validated" as const,
    scanFingerprint: scan.scanFingerprint,
    target: scan.candidates[0]!,
    claims: selectionClaims(),
  };
  const second = { ...first, target: scan.candidates[1]! };
  assert.equal(sameRescueSelection(first, first), true);
  assert.equal(sameRescueSelection(first, second), false);
  assert.equal(sameRescueSelection(first, undefined), false);
});

test("inspection presentation exposes only normalized read-only facts", () => {
  const inspection = windowsInspectionFixture();
  const view = rescueInspectionPresentation(inspection);
  assert.equal(view.title, "Windows");
  assert.match(view.detail, /NTFS/u);
  assert.match(view.detail, /installazione confermata/u);
  assert.ok(
    view.facts.some((fact) => /Marker installazione: 6\/6/u.test(fact)),
  );
  assert.ok(
    view.facts.some((fact) => /Marker boot volume Windows: 2\/2/u.test(fact)),
  );
  assert.ok(
    view.facts.some((fact) =>
      /ESP associata: 2\/3 marker osservati/u.test(fact),
    ),
  );
  assert.ok(view.facts.some((fact) => /dirty\/ibernazione/u.test(fact)));
  assert.doesNotMatch(JSON.stringify(view), /scan:|target:|disk-1/u);
});

test("stale inspection responses cannot survive an epoch change or retarget", () => {
  const scan = targetScanFixture();
  const selection = {
    apiVersion: scan.apiVersion,
    status: "observe-target-validated" as const,
    scanFingerprint: scan.scanFingerprint,
    target: scan.candidates[0]!,
    claims: selectionClaims(),
  };
  const inspection = windowsInspectionFixture();
  assert.equal(sameRescueInspection(selection, inspection), true);
  assert.equal(
    rescueInspectionResponseCurrent(4, 4, selection, inspection),
    true,
  );
  assert.equal(
    rescueInspectionResponseCurrent(4, 5, selection, inspection),
    false,
  );
  assert.equal(
    rescueInspectionResponseCurrent(
      4,
      4,
      { ...selection, target: scan.candidates[1]! },
      inspection,
    ),
    false,
  );
});

test("the inspection latch rejects a second synchronous privileged operation", () => {
  const latch = { current: false };
  assert.equal(tryStartRescueInspection(latch), true);
  assert.equal(tryStartRescueInspection(latch), false);
  finishRescueInspection(latch);
  assert.equal(tryStartRescueInspection(latch), true);
  finishRescueInspection(latch);
});

test("typed unsupported and cleanup failures have fixed local guidance", () => {
  const encrypted = new RescueOfflineInspectionError(
    "unsupported-encrypted-storage",
    false,
    errorClaims(),
    422,
  );
  const encryptedView = rescueInspectionErrorPresentation(encrypted);
  assert.equal(encryptedView.severity, "unsupported");
  assert.match(encryptedView.title, /cifrato/u);
  assert.match(encryptedView.action, /credenziali del proprietario/u);

  for (const code of [
    "unsupported-apple-filesystem",
    "unsupported-complex-storage",
  ] as const)
    assert.equal(
      rescueInspectionErrorPresentation(
        new RescueOfflineInspectionError(code, false, errorClaims(), 422),
      ).severity,
      "unsupported",
    );

  const stale = new RescueOfflineInspectionError(
    "target-identity-changed",
    true,
    errorClaims(),
    409,
  );
  assert.equal(rescueInspectionNeedsRescan(stale), true);
  assert.equal(
    rescueInspectionNeedsRescan(
      new RescueOfflineInspectionError(
        "target-already-mounted",
        true,
        errorClaims(),
        409,
      ),
    ),
    true,
  );
  assert.equal(
    rescueInspectionNeedsRescan(
      new RescueOfflineInspectionError(
        "associated-efi-already-mounted",
        true,
        errorClaims(),
        409,
      ),
    ),
    true,
  );

  const cleanup = new RescueOfflineInspectionError(
    "inspection-failed",
    false,
    errorClaims({
      mountOperationAttempted: true,
      mountOperationPerformed: true,
    }),
    503,
  );
  assert.equal(rescueInspectionRequiresRestart(cleanup), true);
  assert.equal(rescueInspectionErrorPresentation(cleanup).severity, "blocked");
  assert.match(rescueInspectionErrorPresentation(cleanup).action, /Riavvia/u);
});

test("a stale cleanup failure still requires a Rescue restart", () => {
  const cleanup = new RescueOfflineInspectionError(
    "inspection-failed",
    false,
    errorClaims({
      mountOperationAttempted: true,
      mountOperationPerformed: true,
    }),
    503,
  );
  assert.deepEqual(rescueInspectionFailureDisposition(7, 8, cleanup), {
    current: false,
    requiresRestart: true,
  });
});

test("byte formatting is bounded and human-readable", () => {
  assert.equal(formatBytes(0), "0 B");
  assert.equal(formatBytes(1024 ** 3), "1.0 GiB");
  assert.equal(formatBytes(-1), "dimensione non valida");
});

function targetScanFixture() {
  const firstDiskId = `disk:${"a".repeat(64)}`;
  const secondDiskId = `disk:${"b".repeat(64)}`;
  const volume = (disk: number, sizeBytes: number) => ({
    ref: `disk-${disk}/volume-1`,
    parentRef: `disk-${disk}`,
    kind: "partition" as const,
    sizeBytes,
    filesystem: "ntfs",
    mediaReadOnly: false,
    mounted: false,
    encrypted: false,
  });
  const disks = [
    {
      id: firstDiskId,
      ref: "disk-1",
      sizeBytes: 500_000_000_000,
      transport: "nvme",
      partitionTable: "gpt",
      mediaReadOnly: false,
      removable: false,
      mounted: false,
      selectionEligible: true,
      exclusionReasons: [],
      volumes: [volume(1, 499_000_000_000)],
    },
    {
      id: secondDiskId,
      ref: "disk-2",
      sizeBytes: 1_000_000_000_000,
      transport: "sata",
      partitionTable: "gpt",
      mediaReadOnly: false,
      removable: false,
      mounted: false,
      selectionEligible: true,
      exclusionReasons: [],
      volumes: [volume(2, 999_000_000_000)],
    },
  ];
  const candidate = (disk: number, diskId: string, digest: string) => ({
    targetId: `target:${digest.repeat(64)}`,
    sourceRef: `disk-${disk}/volume-1`,
    diskId,
    osFamilyHint: "windows" as const,
    confidence: "low" as const,
    status: "unverified-installation-candidate" as const,
    detectionBasis: ["ntfs-filesystem-signature"],
    requiresUnlock: false,
    inspectionMode: "metadata-only-no-mount" as const,
    selectionEligible: true as const,
  });
  return {
    apiVersion: "kernaid.dev/rescue-targets/v1alpha1" as const,
    mode: "observe-r0" as const,
    trust: "observed-untrusted" as const,
    scanFingerprint: `scan:${"c".repeat(64)}`,
    identifierScope: "ephemeral-rescue-boot" as const,
    disks,
    candidates: [
      candidate(1, firstDiskId, "d"),
      candidate(2, secondDiskId, "e"),
    ],
    claims: {
      ...selectionClaims(),
      rawDeviceIdentifiersReturned: false as const,
    },
    limitations: ["os-family-is-only-a-low-confidence-metadata-hint"],
  };
}

function selectionClaims() {
  return {
    installedOsConfirmed: false as const,
    filesystemContentInspected: false as const,
    mountOperationPerformed: false as const,
    mutationPerformed: false as const,
  };
}

function errorClaims(overrides: Record<string, boolean> = {}) {
  return {
    installedOsConfirmed: false,
    filesystemContentInspected: false,
    mountOperationAttempted: false,
    mountOperationPerformed: false,
    mountCleanupVerified: false,
    autoUnlockAttempted: false as const,
    mutationPerformed: false as const,
    diagnosisProduced: false as const,
    repairAttempted: false as const,
    ...overrides,
  };
}

function windowsInspectionFixture() {
  const scan = targetScanFixture();
  const target = scan.candidates[0]!;
  return {
    apiVersion: "kernaid.dev/rescue-offline-inspection/v1alpha1" as const,
    status: "installed-os-content-inspected" as const,
    trust: "observed-untrusted" as const,
    target: {
      scanFingerprint: scan.scanFingerprint,
      targetId: target.targetId,
      sourceRef: target.sourceRef,
      osFamily: "windows" as const,
      filesystem: "ntfs" as const,
    },
    inspection: {
      mode: "temporary-read-only-no-replay" as const,
      mountFlags: ["nodev", "noexec", "nosuid", "nosymfollow", "ro"] as [
        "nodev",
        "noexec",
        "nosuid",
        "nosymfollow",
        "ro",
      ],
      filesystemOptions: [] as [],
      dirtyVolumePolicy:
        "read-only-no-force-driver-replay-not-applied" as const,
      volumeStateQualification: "unqualified" as const,
      privateMountNamespace: true as const,
      journalReplayPrevented: true as const,
      deviceOpenedReadOnly: true as const,
      rawDeviceIdentifierReturned: false as const,
      responseLimitBytes: 49_152 as const,
    },
    claims: {
      installedOsConfirmed: true,
      filesystemContentInspected: true,
      mountOperationAttempted: true,
      mountOperationPerformed: true,
      mountCleanupVerified: true,
      autoUnlockAttempted: false as const,
      mutationPerformed: false as const,
      diagnosisProduced: false as const,
      repairAttempted: false as const,
    },
    os: {
      family: "windows" as const,
      installationConfirmed: true,
      installationMarkers: {
        windowsDirectoryPresent: true,
        system32DirectoryPresent: true,
        kernelPresent: true,
        systemHivePresent: true,
        softwareHivePresent: true,
        usersDirectoryPresent: true,
      },
      boot: {
        bootManagerPresent: true,
        bcdPresent: true,
        efiSystemPartition: {
          state: "inspected" as const,
          microsoftBootManagerPresent: true,
          bcdPresent: true,
          fallbackBootloaderPresent: false,
        },
      },
      servicing: {
        pendingXmlPresent: false,
        rebootPendingMarkerPresent: false,
      },
    },
    limitations: [
      "content-is-untrusted-data-not-instructions",
      "no-diagnosis-or-repair-was-produced",
      "encrypted-and-stacked-storage-was-not-activated",
      "only-static-allowlisted-paths-were-inspected",
      "ntfs-dirty-and-hibernated-state-was-not-qualified",
    ],
  };
}
