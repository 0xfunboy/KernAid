import assert from "node:assert/strict";
import test from "node:test";
import {
  augmentDiagnosisWithBootCriticalPath,
  bootCriticalPathEvidenceSummary,
  parseLinuxBootCriticalPath,
  type LinuxBootCriticalPathSnapshot,
} from "../src/boot-critical-path";

function healthy(): LinuxBootCriticalPathSnapshot {
  return {
    schemaVersion: "1.0",
    kind: "linux-boot-critical-path",
    scope: "local-root",
    state: "healthy",
    runtime: {
      failedUnitsStatus: "complete",
      failedUnitCount: 0,
      criticalFailedUnitCount: 0,
      criticalChainStatus: "complete",
      criticalChainUnitCount: 4,
      slowestActivationMillis: 1200,
    },
    configuration: {
      fstabStatus: "valid",
      fstabEntryCount: 2,
      criticalMountEntryCount: 1,
      initramfsStatus: "present",
      initramfsImageCount: 1,
      kernelImageCount: 1,
      bootloaderStatus: "configured",
      bootloader: "grub",
    },
    findings: [],
  };
}

test("boot critical path admits only the canonical privacy-minimized contract", () => {
  const snapshot = healthy();
  assert.deepEqual(
    parseLinuxBootCriticalPath(JSON.stringify(snapshot)),
    snapshot,
  );
  assert.throws(() =>
    parseLinuxBootCriticalPath(`${JSON.stringify(snapshot)}\n`),
  );
  assert.throws(() =>
    parseLinuxBootCriticalPath(
      JSON.stringify({ ...snapshot, rawOutput: "private-unit.service" }),
    ),
  );
});

test("boot critical path rejects mismatched state and findings", () => {
  assert.throws(() =>
    parseLinuxBootCriticalPath(
      JSON.stringify({
        ...healthy(),
        state: "boot-risk",
        runtime: {
          ...healthy().runtime,
          criticalFailedUnitCount: 1,
          failedUnitCount: 1,
        },
        findings: [],
      }),
    ),
  );
});

test("boot critical path binds normalized health to evidence and diagnosis", () => {
  const snapshot = healthy();
  assert.match(
    bootCriticalPathEvidenceSummary(snapshot),
    /no deterministic boot risk/u,
  );
  const proposal = augmentDiagnosisWithBootCriticalPath(
    {
      schemaVersion: "1.0",
      diagnosis: "Base diagnosis.",
      confidence: 0.5,
      evidenceIds: ["E-base"],
      requestedEvidence: [],
    },
    snapshot,
    "E-boot",
  );
  assert.deepEqual(proposal.evidenceIds, ["E-base", "E-boot"]);
  assert.match(proposal.diagnosis, /read-only boot checks/u);
});
