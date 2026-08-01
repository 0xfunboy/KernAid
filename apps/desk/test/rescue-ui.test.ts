import assert from "node:assert/strict";
import test from "node:test";
import {
  formatBytes,
  observationStatus,
  rescueCandidatePresentation,
  sameRescueSelection,
} from "../src/rescue-ui.js";

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
    identifierScope: "ephemeral-rescue-process" as const,
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
