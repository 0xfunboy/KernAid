import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";
import type { AuditSealRequest } from "@kernaid/session-driver";
import {
  LINUX_NORMALIZED_SNAPSHOT_HASH_DOMAIN,
  canonicalLinuxSnapshotJson,
} from "@kernaid/schemas";
import {
  NativeOpenAiProvider,
  PlatformOfflineRulesProvider,
  authorizeObserve,
  collectLocalInventory,
  fingerprintNativeTarget,
  fingerprintRescueTarget,
  inspectRescueInstalledTarget,
  linuxNormalizedSnapshotEvidenceSummary,
  linuxNormalizedSnapshotFromRescue,
  nativeObservationContentType,
  nativeObservationSummary,
  parseNativeObservations,
  parseRescueOfflineCorpus,
  parseRescueOfflineInspection,
  parseRescueTargetScan,
  parseRescueTargetSelection,
  parseNativeSignedArtifact,
  parseResidentOpenAiStatus,
  parseSecureRuntimeStatus,
  scanRescueInstalledTargets,
  selectRescueInstalledTarget,
  rescueOfflineCorpusJson,
  rescueOfflineEvidenceSummary,
  LINUX_NORMALIZED_SNAPSHOT_COLLECTOR,
  LINUX_P0_COLLECTORS,
  RESCUE_OFFLINE_EVIDENCE_COLLECTOR,
  RESCUE_OFFLINE_EVIDENCE_TARGET,
  RescueOfflineInspectionError,
} from "../src/native.js";

test("native inventory requires explicit bounded truncation state", () => {
  const valid = {
    collector: "linux.block.inventory",
    trust: "observed-untrusted",
    output: "{}",
    success: true,
    truncated: false,
  };
  assert.deepEqual(parseNativeObservations([valid]), [valid]);
  assert.throws(
    () => parseNativeObservations([{ ...valid, truncated: undefined }]),
    /Inventario nativo non valido/,
  );
  assert.throws(
    () => parseNativeObservations([{ ...valid, truncated: true }]),
    /Inventario nativo non valido/,
  );
  assert.throws(
    () =>
      parseNativeObservations([
        { ...valid, output: "x".repeat(64 * 1024 + 1) },
      ]),
    /Inventario nativo non valido/,
  );
  assert.deepEqual(
    parseNativeObservations([
      {
        ...valid,
        collector: "windows.event-log.window",
        output: "x".repeat(64 * 1024 + 1),
      },
    ])[0]?.output.length,
    64 * 1024 + 1,
  );
  assert.throws(
    () =>
      parseNativeObservations([
        {
          ...valid,
          collector: "windows.event-log.window",
          output: "x".repeat(1024 * 1024 + 1),
        },
      ]),
    /Inventario nativo non valido/,
  );
  assert.deepEqual(
    parseNativeObservations([
      {
        ...valid,
        collector: "windows.storage.identity",
        output: "x".repeat(64 * 1024 + 1),
      },
    ])[0]?.output.length,
    64 * 1024 + 1,
  );
  assert.deepEqual(
    parseNativeObservations([
      {
        ...valid,
        collector: "macos.launchd.state",
        output: "x".repeat(64 * 1024 + 1),
      },
    ])[0]?.output.length,
    64 * 1024 + 1,
  );
  assert.throws(
    () =>
      parseNativeObservations([
        {
          ...valid,
          collector: "macos.launchd.state",
          output: "x".repeat(1024 * 1024 + 1),
        },
      ]),
    /Inventario nativo non valido/,
  );
});

test("failed macOS observations are never mislabeled as JSON", () => {
  const observation = {
    collector: "macos.system-events.summary",
    trust: "observed-untrusted" as const,
    output: "collector unavailable: macOS P0 evidence failed closed",
    success: false,
    truncated: false,
  };
  assert.equal(nativeObservationContentType(observation), "text/plain");
  assert.equal(
    nativeObservationSummary(observation),
    "Comando di inventario non disponibile",
  );
  assert.equal(
    nativeObservationContentType({
      ...observation,
      output: '{"schemaVersion":"1.0"}',
      success: true,
    }),
    "application/json",
  );
  assert.equal(
    nativeObservationSummary({
      ...observation,
      collector: "macos.system-events.summary",
      output: '{"schemaVersion":"1.0","executionState":"not-run-unqualified"}',
      success: true,
    }),
    "Scope P0 esplicitamente non eseguito perché non qualificato",
  );
  assert.equal(
    nativeObservationSummary({
      ...observation,
      collector: "macos.startup.state",
      output:
        '{"schemaVersion":"1.0","safeModeQueryState":"complete","loginItemsQueryState":"not-run-unqualified"}',
      success: true,
    }),
    "Safe mode verificato; login e background item non eseguiti perché non qualificati",
  );
});

test("Rescue inventory retries a bounded 429 response", async () => {
  const originalWindow = Object.getOwnPropertyDescriptor(globalThis, "window");
  const originalLocation = Object.getOwnPropertyDescriptor(
    globalThis,
    "location",
  );
  const originalFetch = Object.getOwnPropertyDescriptor(globalThis, "fetch");
  const observation = {
    collector: "system.hostname",
    trust: "observed-untrusted" as const,
    output: "kernaid-rescue",
    success: true,
    truncated: false,
  };
  let calls = 0;
  Object.defineProperty(globalThis, "window", {
    configurable: true,
    value: {},
  });
  Object.defineProperty(globalThis, "location", {
    configurable: true,
    value: { hostname: "127.0.0.1", port: "4173" },
  });
  Object.defineProperty(globalThis, "fetch", {
    configurable: true,
    value: async () => {
      calls += 1;
      return calls === 1
        ? new Response("busy", {
            status: 429,
            headers: { "Retry-After": "0" },
          })
        : Response.json([observation]);
    },
  });

  try {
    assert.deepEqual(await collectLocalInventory(), [observation]);
    assert.equal(calls, 2);
  } finally {
    restoreProperty("window", originalWindow);
    restoreProperty("location", originalLocation);
    if (originalFetch === undefined)
      Reflect.deleteProperty(globalThis, "fetch");
    else Object.defineProperty(globalThis, "fetch", originalFetch);
  }
});

test("Rescue target scan and selection are exact, bounded, and cross-bound", async () => {
  const scan = rescueTargetScanFixture();
  const parsed = parseRescueTargetScan(scan);
  assert.equal(parsed.identifierScope, "ephemeral-rescue-boot");
  assert.equal(parsed.candidates[0]?.osFamilyHint, "windows");
  assert.equal(parsed.disks[0]?.volumes[0]?.filesystem, "ntfs");
  assert.throws(() =>
    parseRescueTargetScan({
      ...scan,
      identifierScope: "ephemeral-rescue-process",
    }),
  );

  for (const filesystem of ["crypto_luks", "lvm2_member", "linux_raid_member"])
    assert.equal(
      parseRescueTargetScan({
        ...scan,
        disks: [
          {
            ...scan.disks[0],
            volumes: [{ ...scan.disks[0].volumes[0], filesystem }],
          },
        ],
      }).disks[0]?.volumes[0]?.filesystem,
      filesystem,
    );

  assert.throws(() =>
    parseRescueTargetScan({
      ...scan,
      claims: { ...scan.claims, rawDeviceIdentifiersReturned: true },
    }),
  );
  assert.throws(() =>
    parseRescueTargetScan({
      ...scan,
      disks: [
        ...scan.disks,
        {
          ...scan.disks[0],
          id: `disk:${"d".repeat(64)}`,
          ref: "disk-2",
          volumes: [],
        },
      ],
      candidates: [
        {
          ...scan.candidates[0],
          diskId: `disk:${"d".repeat(64)}`,
        },
      ],
    }),
  );
  assert.throws(() =>
    parseRescueTargetScan({
      ...scan,
      candidates: [{ ...scan.candidates[0], sourceRef: "disk-9/volume-9" }],
    }),
  );
  assert.throws(() =>
    parseRescueTargetScan({
      ...scan,
      candidates: [scan.candidates[0], scan.candidates[0]],
    }),
  );

  const selection = rescueTargetSelectionFixture();
  assert.equal(
    parseRescueTargetSelection(selection).target.targetId,
    scan.candidates[0]?.targetId,
  );
  assert.throws(() =>
    parseRescueTargetSelection({
      ...selection,
      claims: { ...selection.claims, filesystemContentInspected: true },
    }),
  );
});

test("Rescue offline inspection parser is exact, cross-bound, and fail-closed", () => {
  const windowsSelection = rescueTargetSelectionFixture();
  const windows = rescueWindowsInspectionFixture();
  const parsedWindows = parseRescueOfflineInspection(windows, windowsSelection);
  assert.equal(parsedWindows.os.family, "windows");
  assert.equal(parsedWindows.claims.mountCleanupVerified, true);
  if (parsedWindows.os.family === "windows")
    assert.equal(parsedWindows.os.boot.efiSystemPartition.state, "inspected");

  const linuxSelection = rescueLinuxTargetSelectionFixture();
  const linux = rescueLinuxInspectionFixture();
  const parsedLinux = parseRescueOfflineInspection(linux, linuxSelection);
  assert.equal(parsedLinux.os.family, "linux");
  assert.equal(parsedLinux.os.configuration.fstab.malformedLineCount, 1);

  assert.throws(() =>
    parseRescueOfflineInspection(
      { ...windows, unexpected: true },
      windowsSelection,
    ),
  );
  assert.throws(() =>
    parseRescueOfflineInspection(
      {
        ...windows,
        target: { ...windows.target, targetId: `target:${"f".repeat(64)}` },
      },
      windowsSelection,
    ),
  );
  assert.throws(() =>
    parseRescueOfflineInspection(
      {
        ...windows,
        claims: { ...windows.claims, mutationPerformed: true },
      },
      windowsSelection,
    ),
  );
  assert.throws(() =>
    parseRescueOfflineInspection(
      {
        ...windows,
        claims: { ...windows.claims, mountCleanupVerified: false },
      },
      windowsSelection,
    ),
  );
  assert.throws(() =>
    parseRescueOfflineInspection(
      { ...windows, status: "content-inspected-installation-unconfirmed" },
      windowsSelection,
    ),
  );
  assert.throws(() =>
    parseRescueOfflineInspection(
      {
        ...windows,
        limitations: [...windows.limitations, "future-unknown-limitation"],
      },
      windowsSelection,
    ),
  );
  assert.throws(() =>
    parseRescueOfflineInspection(
      {
        ...windows,
        inspection: {
          ...windows.inspection,
          deviceOpenedReadOnly: false,
        },
      },
      windowsSelection,
    ),
  );

  const impossibleFstab = structuredClone(linux.os);
  impossibleFstab.configuration.fstab.entryCount = 65_536;
  impossibleFstab.configuration.fstab.malformedLineCount = 1;
  assert.throws(() => parseRescueOfflineCorpus(impossibleFstab));
  const impossibleBoot = structuredClone(linux.os);
  impossibleBoot.boot.directoryPresent = false;
  assert.throws(() => parseRescueOfflineCorpus(impossibleBoot));

  const nonInspectedEfiWithFacts = {
    ...windows.os,
    boot: {
      ...windows.os.boot,
      efiSystemPartition: {
        state: "not-present",
        microsoftBootManagerPresent: false,
        bcdPresent: false,
        fallbackBootloaderPresent: false,
      },
    },
  };
  assert.throws(() => parseRescueOfflineCorpus(nonInspectedEfiWithFacts));
  const inspectedEfiWithNulls = {
    ...windows.os,
    boot: {
      ...windows.os.boot,
      efiSystemPartition: {
        state: "inspected",
        microsoftBootManagerPresent: null,
        bcdPresent: null,
        fallbackBootloaderPresent: null,
      },
    },
  };
  assert.throws(() => parseRescueOfflineCorpus(inspectedEfiWithNulls));
  assert.throws(() =>
    parseRescueOfflineCorpus({
      ...windows.os,
      boot: {
        ...windows.os.boot,
        efiSystemPartition: {
          state: ["not-present"],
          microsoftBootManagerPresent: null,
          bcdPresent: null,
          fallbackBootloaderPresent: null,
        },
      },
    }),
  );

  const missingEfi = {
    ...windows,
    os: {
      ...windows.os,
      boot: {
        ...windows.os.boot,
        efiSystemPartition: {
          state: "not-present",
          microsoftBootManagerPresent: null,
          bcdPresent: null,
          fallbackBootloaderPresent: null,
        },
      },
    },
    limitations: [
      ...windows.limitations,
      "associated-efi-system-partition-not-present",
    ],
  };
  assert.equal(
    parseRescueOfflineInspection(missingEfi, windowsSelection).os.family,
    "windows",
  );
  assert.throws(() =>
    parseRescueOfflineInspection(
      { ...missingEfi, limitations: windows.limitations },
      windowsSelection,
    ),
  );
});

test("Rescue evidence projection contains only the normalized offline corpus", () => {
  const inspection = parseRescueOfflineInspection(
    rescueWindowsInspectionFixture(),
    rescueTargetSelectionFixture(),
  );
  const encoded = rescueOfflineCorpusJson(inspection);
  const projected = JSON.parse(encoded) as Record<string, unknown>;
  assert.deepEqual(Object.keys(projected).sort(), [
    "boot",
    "family",
    "installationConfirmed",
    "installationMarkers",
    "servicing",
  ]);
  assert.doesNotMatch(
    encoded,
    /scanFingerprint|targetId|sourceRef|disk-1|mountFlags|claims|limitations/u,
  );
  assert.equal(
    rescueOfflineEvidenceSummary(inspection),
    "Corpus statico windows acquisito read-only con cleanup verificato",
  );
  assert.throws(() =>
    rescueOfflineCorpusJson({
      ...inspection,
      claims: { ...inspection.claims, mountCleanupVerified: false },
    }),
  );
});

test("Rescue inspection HTTP contract is minimal and rejects malformed success", async () => {
  const originalWindow = Object.getOwnPropertyDescriptor(globalThis, "window");
  const originalLocation = Object.getOwnPropertyDescriptor(
    globalThis,
    "location",
  );
  const originalFetch = Object.getOwnPropertyDescriptor(globalThis, "fetch");
  const selection = parseRescueTargetSelection(rescueTargetSelectionFixture());
  let input: unknown;
  let init: RequestInit | undefined;
  Object.defineProperty(globalThis, "window", {
    configurable: true,
    value: {},
  });
  Object.defineProperty(globalThis, "location", {
    configurable: true,
    value: { hostname: "127.0.0.1", port: "4173" },
  });
  Object.defineProperty(globalThis, "fetch", {
    configurable: true,
    value: async (nextInput: unknown, nextInit: RequestInit | undefined) => {
      input = nextInput;
      init = nextInit;
      return Response.json(rescueWindowsInspectionFixture());
    },
  });
  try {
    const inspection = await inspectRescueInstalledTarget(selection);
    assert.equal(inspection.os.family, "windows");
    assert.equal(input, "/api/rescue/inspect-installed-target");
    assert.equal(init?.method, "POST");
    assert.deepEqual(JSON.parse(String(init?.body)), {
      scanFingerprint: selection.scanFingerprint,
      targetId: selection.target.targetId,
    });

    Object.defineProperty(globalThis, "fetch", {
      configurable: true,
      value: async () => Response.json({}, { status: 200 }),
    });
    await assert.rejects(
      inspectRescueInstalledTarget(selection),
      (error: unknown) => {
        assert.ok(error instanceof RescueOfflineInspectionError);
        assert.equal(error.code, "invalid-local-response");
        assert.equal(error.retryable, false);
        return true;
      },
    );

    Object.defineProperty(globalThis, "fetch", {
      configurable: true,
      value: async () =>
        new Response(JSON.stringify(rescueWindowsInspectionFixture()), {
          status: 200,
          headers: { "Content-Type": "text/plain" },
        }),
    });
    await assert.rejects(
      inspectRescueInstalledTarget(selection),
      (error: unknown) => {
        assert.equal(
          (error as RescueOfflineInspectionError).code,
          "invalid-local-response",
        );
        return true;
      },
    );

    Object.defineProperty(globalThis, "fetch", {
      configurable: true,
      value: async () =>
        new Response("{}", {
          status: 200,
          headers: {
            "Content-Type": "application/json",
            "Content-Length": String(64 * 1024 + 1),
          },
        }),
    });
    await assert.rejects(
      inspectRescueInstalledTarget(selection),
      (error: unknown) => {
        assert.equal(
          (error as RescueOfflineInspectionError).code,
          "invalid-local-response",
        );
        return true;
      },
    );
  } finally {
    restoreProperty("window", originalWindow);
    restoreProperty("location", originalLocation);
    restoreProperty("fetch", originalFetch);
  }
});

test("Rescue inspection errors are typed, non-retried, and never expose backend text", async () => {
  const originalWindow = Object.getOwnPropertyDescriptor(globalThis, "window");
  const originalLocation = Object.getOwnPropertyDescriptor(
    globalThis,
    "location",
  );
  const originalFetch = Object.getOwnPropertyDescriptor(globalThis, "fetch");
  const selection = parseRescueTargetSelection(rescueTargetSelectionFixture());
  const rawMessage = "raw helper detail /dev/nvme0n1 must not escape";
  let calls = 0;
  Object.defineProperty(globalThis, "window", {
    configurable: true,
    value: {},
  });
  Object.defineProperty(globalThis, "location", {
    configurable: true,
    value: { hostname: "127.0.0.1", port: "4173" },
  });
  const setFetch = (implementation: () => Promise<Response>): void => {
    Object.defineProperty(globalThis, "fetch", {
      configurable: true,
      value: async () => {
        calls += 1;
        return implementation();
      },
    });
  };
  try {
    calls = 0;
    setFetch(async () =>
      Response.json(
        {
          error: {
            code: "unsupported-encrypted-storage",
            message: rawMessage,
            retryable: false,
            claims: rescueInspectionClaims({
              installedOsConfirmed: false,
              filesystemContentInspected: false,
              mountOperationAttempted: false,
              mountOperationPerformed: false,
              mountCleanupVerified: false,
            }),
          },
        },
        { status: 422 },
      ),
    );
    await assert.rejects(
      inspectRescueInstalledTarget(selection),
      (error: unknown) => {
        assert.ok(error instanceof RescueOfflineInspectionError);
        assert.equal(error.code, "unsupported-encrypted-storage");
        assert.equal(error.retryable, false);
        assert.doesNotMatch(String(error), new RegExp(rawMessage, "u"));
        return true;
      },
    );
    assert.equal(calls, 1);

    setFetch(async () =>
      Response.json(
        {
          error: {
            code: "read-only-mount-failed",
            message: "mount rejected safely",
            retryable: false,
            claims: rescueInspectionClaims({
              installedOsConfirmed: false,
              filesystemContentInspected: false,
              mountOperationAttempted: true,
              mountOperationPerformed: false,
              mountCleanupVerified: true,
            }),
          },
        },
        { status: 422 },
      ),
    );
    await assert.rejects(
      inspectRescueInstalledTarget(selection),
      (error: unknown) => {
        assert.equal(
          (error as RescueOfflineInspectionError).code,
          "read-only-mount-failed",
        );
        assert.equal(
          (error as RescueOfflineInspectionError).claims.mountCleanupVerified,
          true,
        );
        return true;
      },
    );

    setFetch(async () =>
      Response.json(
        {
          error: {
            code: "unsupported-cross-device-content",
            message: "separate filesystem rejected safely",
            retryable: false,
            claims: rescueInspectionClaims(),
          },
        },
        { status: 422 },
      ),
    );
    await assert.rejects(
      inspectRescueInstalledTarget(selection),
      (error: unknown) => {
        assert.equal(
          (error as RescueOfflineInspectionError).code,
          "unsupported-cross-device-content",
        );
        return true;
      },
    );

    setFetch(async () =>
      Response.json(
        {
          error: {
            code: "associated-efi-read-only-mount-failed",
            message: "ESP mount rejected safely",
            retryable: false,
            claims: rescueInspectionClaims(),
          },
        },
        { status: 422 },
      ),
    );
    await assert.rejects(
      inspectRescueInstalledTarget(selection),
      (error: unknown) => {
        assert.equal(
          (error as RescueOfflineInspectionError).code,
          "associated-efi-read-only-mount-failed",
        );
        assert.equal(
          (error as RescueOfflineInspectionError).claims.mountCleanupVerified,
          true,
        );
        return true;
      },
    );

    setFetch(async () =>
      Response.json(
        {
          error: {
            code: "unsupported-encrypted-storage",
            message: "mismatched transport contract",
            retryable: true,
            claims: rescueInspectionClaims({
              installedOsConfirmed: false,
              filesystemContentInspected: false,
              mountOperationAttempted: false,
              mountOperationPerformed: false,
              mountCleanupVerified: false,
            }),
          },
        },
        { status: 503 },
      ),
    );
    await assert.rejects(
      inspectRescueInstalledTarget(selection),
      (error: unknown) => {
        assert.equal(
          (error as RescueOfflineInspectionError).code,
          "invalid-local-response",
        );
        return true;
      },
    );

    setFetch(async () =>
      Response.json(
        {
          error: {
            code: "unsafe-ntfs-volume-state",
            message: "removed code",
            retryable: false,
            claims: rescueInspectionClaims({
              installedOsConfirmed: false,
              filesystemContentInspected: false,
              mountOperationAttempted: false,
              mountOperationPerformed: false,
              mountCleanupVerified: false,
            }),
          },
        },
        { status: 422 },
      ),
    );
    await assert.rejects(
      inspectRescueInstalledTarget(selection),
      (error: unknown) => {
        assert.equal(
          (error as RescueOfflineInspectionError).code,
          "invalid-local-response",
        );
        return true;
      },
    );

    setFetch(async () =>
      Response.json(
        {
          error: {
            code: "inspection-failed",
            message: "failure",
            retryable: true,
            claims: rescueInspectionClaims({ mutationPerformed: true }),
          },
        },
        { status: 503 },
      ),
    );
    await assert.rejects(
      inspectRescueInstalledTarget(selection),
      (error: unknown) => {
        assert.equal(
          (error as RescueOfflineInspectionError).code,
          "invalid-local-response",
        );
        return true;
      },
    );

    Object.defineProperty(globalThis, "fetch", {
      configurable: true,
      value: async () => {
        const error = new Error("deadline");
        error.name = "TimeoutError";
        throw error;
      },
    });
    await assert.rejects(
      inspectRescueInstalledTarget(selection),
      (error: unknown) => {
        assert.equal(
          (error as RescueOfflineInspectionError).code,
          "inspection-timeout",
        );
        assert.equal((error as RescueOfflineInspectionError).httpStatus, 408);
        assert.equal((error as RescueOfflineInspectionError).retryable, true);
        return true;
      },
    );

    Object.defineProperty(globalThis, "fetch", {
      configurable: true,
      value: async () => {
        throw new TypeError("network route leaked detail");
      },
    });
    await assert.rejects(
      inspectRescueInstalledTarget(selection),
      (error: unknown) => {
        assert.equal(
          (error as RescueOfflineInspectionError).code,
          "privileged-helper-unavailable",
        );
        assert.equal((error as RescueOfflineInspectionError).httpStatus, 503);
        assert.equal((error as RescueOfflineInspectionError).retryable, true);
        assert.doesNotMatch(String(error), /network route leaked detail/u);
        return true;
      },
    );
  } finally {
    restoreProperty("window", originalWindow);
    restoreProperty("location", originalLocation);
    restoreProperty("fetch", originalFetch);
  }
});

test("Rescue session fingerprint is bound to the exact selected candidate", async () => {
  const observation = {
    collector: "linux.block.inventory",
    trust: "observed-untrusted" as const,
    output: '{"blockdevices":[]}',
    success: true,
    truncated: false,
  };
  const selection = rescueTargetSelectionFixture();
  const first = await fingerprintNativeTarget([observation], {
    scanFingerprint: selection.scanFingerprint,
    target: selection.target,
  });
  const second = await fingerprintNativeTarget([observation], {
    scanFingerprint: selection.scanFingerprint,
    target: {
      ...selection.target,
      targetId: `target:${"d".repeat(64)}`,
    },
  });
  assert.match(first, /^sha256:[a-f0-9]{64}$/u);
  assert.notEqual(first, second);
});

test("Rescue composite fingerprint matches the backend canonical vector", async () => {
  const targetId = `target:${"3".repeat(64)}`;
  const candidate = {
    targetId,
    sourceRef: "disk-1/volume-2",
    diskId: `disk:${"4".repeat(64)}`,
    osFamilyHint: "windows" as const,
    confidence: "low" as const,
    status: "unverified-installation-candidate" as const,
    detectionBasis: ["ntfs-filesystem-signature"],
    requiresUnlock: false,
    inspectionMode: "metadata-only-no-mount" as const,
    selectionEligible: true as const,
  };
  assert.equal(
    await fingerprintRescueTarget(`sha256:${"1".repeat(64)}`, {
      scanFingerprint: `scan:${"2".repeat(64)}`,
      target: candidate,
    }),
    "sha256:846c16507e5938abfaff4a2111a24adfe2d7aab353260887f74fbca249e20a36",
  );
});

test("Rescue selection HTTP response must match the exact requested target", async () => {
  const originalWindow = Object.getOwnPropertyDescriptor(globalThis, "window");
  const originalLocation = Object.getOwnPropertyDescriptor(
    globalThis,
    "location",
  );
  const originalFetch = Object.getOwnPropertyDescriptor(globalThis, "fetch");
  const scan = rescueTargetScanFixture();
  const selection = rescueTargetSelectionFixture();
  let calls = 0;
  Object.defineProperty(globalThis, "window", {
    configurable: true,
    value: {},
  });
  Object.defineProperty(globalThis, "location", {
    configurable: true,
    value: { hostname: "127.0.0.1", port: "4173" },
  });
  Object.defineProperty(globalThis, "fetch", {
    configurable: true,
    value: async () => {
      calls += 1;
      return Response.json(calls === 1 ? scan : selection);
    },
  });
  try {
    const returnedScan = await scanRescueInstalledTargets();
    const returnedSelection = await selectRescueInstalledTarget(
      returnedScan.scanFingerprint,
      returnedScan.candidates[0]!,
    );
    assert.equal(
      returnedSelection.target.targetId,
      returnedScan.candidates[0]!.targetId,
    );
    assert.equal(calls, 2);

    Object.defineProperty(globalThis, "fetch", {
      configurable: true,
      value: async () =>
        Response.json({
          ...selection,
          target: { ...selection.target, targetId: `target:${"f".repeat(64)}` },
        }),
    });
    await assert.rejects(
      selectRescueInstalledTarget(
        returnedScan.scanFingerprint,
        returnedScan.candidates[0]!,
      ),
      /non corrisponde/,
    );
  } finally {
    restoreProperty("window", originalWindow);
    restoreProperty("location", originalLocation);
    if (originalFetch === undefined)
      Reflect.deleteProperty(globalThis, "fetch");
    else Object.defineProperty(globalThis, "fetch", originalFetch);
  }
});

test("Rescue Observe authorization carries the exact session target binding", async () => {
  const originalWindow = Object.getOwnPropertyDescriptor(globalThis, "window");
  const originalLocation = Object.getOwnPropertyDescriptor(
    globalThis,
    "location",
  );
  const originalFetch = Object.getOwnPropertyDescriptor(globalThis, "fetch");
  const selection = rescueTargetSelectionFixture();
  let body: unknown;
  Object.defineProperty(globalThis, "window", {
    configurable: true,
    value: {},
  });
  Object.defineProperty(globalThis, "location", {
    configurable: true,
    value: { hostname: "127.0.0.1", port: "4173" },
  });
  Object.defineProperty(globalThis, "fetch", {
    configurable: true,
    value: async (_input: unknown, init: RequestInit | undefined) => {
      body = JSON.parse(String(init?.body)) as unknown;
      return Response.json({ status: "authorized" });
    },
  });
  const request = {
    sessionId: "S-bound",
    planId: "P-bound",
    targetFingerprint: `sha256:${"1".repeat(64)}`,
    sequence: 1,
    action: "system.observe.noop" as const,
  };
  try {
    await assert.rejects(authorizeObserve(request), /target Rescue/);
    await authorizeObserve(request, {
      scanFingerprint: selection.scanFingerprint,
      target: selection.target,
    });
    assert.deepEqual(body, {
      ...request,
      rescueTarget: {
        scanFingerprint: selection.scanFingerprint,
        targetId: selection.target.targetId,
      },
    });
  } finally {
    restoreProperty("window", originalWindow);
    restoreProperty("location", originalLocation);
    if (originalFetch === undefined)
      Reflect.deleteProperty(globalThis, "fetch");
    else Object.defineProperty(globalThis, "fetch", originalFetch);
  }
});

const schema = "https://schemas.kernaid.dev/v1/signed-report-envelope.json";
const mediaType = "application/vnd.kernaid.signed-report+json";

test("secure runtime status requires a device ID exactly when signing is ready", () => {
  const ready = parseSecureRuntimeStatus({
    schemaVersion: "1.0",
    audit: "secure",
    signing: "ready",
    persistentAuditStarted: true,
    deviceId: "KA-0123456789abcdef01234567",
  });
  assert.equal(ready.deviceId, "KA-0123456789abcdef01234567");

  assert.throws(() =>
    parseSecureRuntimeStatus({
      schemaVersion: "1.0",
      audit: "secure",
      signing: "ready",
      persistentAuditStarted: true,
    }),
  );
  assert.throws(() =>
    parseSecureRuntimeStatus({
      schemaVersion: "1.0",
      audit: "secure",
      signing: "uninitialized",
      persistentAuditStarted: false,
      deviceId: "KA-0123456789abcdef01234567",
    }),
  );
});

test("secure runtime status rejects ambiguous native responses", () => {
  assert.throws(() =>
    parseSecureRuntimeStatus({
      schemaVersion: "1.0",
      audit: "secure",
      signing: "uninitialized",
      persistentAuditStarted: false,
      unexpected: true,
    }),
  );
});

test("Resident OpenAI status is presence-only and exact", () => {
  assert.deepEqual(
    parseResidentOpenAiStatus({
      schemaVersion: "1.0",
      provider: "openai",
      profile: "resident-default",
      model: "gpt-5.6-sol",
      credential: "configured",
    }),
    {
      schemaVersion: "1.0",
      provider: "openai",
      profile: "resident-default",
      model: "gpt-5.6-sol",
      credential: "configured",
    },
  );
  assert.throws(() =>
    parseResidentOpenAiStatus({
      schemaVersion: "1.0",
      provider: "openai",
      profile: "resident-default",
      model: "gpt-5.6-sol",
      credential: "configured",
      credentialValue: "must-never-cross-the-webview",
    }),
  );
});

test("Resident OpenAI provider sends no credential field across IPC", async () => {
  const calls: Array<{ command: string; args?: Record<string, unknown> }> = [];
  const invoke = async <T>(
    command: string,
    args?: Record<string, unknown>,
  ): Promise<T> => {
    calls.push({ command, args });
    return {
      schemaVersion: "1.0",
      diagnosis: "Read-only follow-up required.",
      confidence: 0.7,
      evidenceIds: ["E-1"],
      requestedEvidence: [],
    } as T;
  };
  const provider = new NativeOpenAiProvider(invoke);
  const proposal = await provider.diagnose("Diagnose", [providerEvidence()]);
  assert.equal(proposal.diagnosis, "Read-only follow-up required.");
  assert.equal(calls[0]?.command, "resident_openai_diagnose");
  const serialized = JSON.stringify(calls[0]?.args);
  assert.doesNotMatch(serialized, /api.?key|authorization|bearer/iu);
  assert.match(serialized, /observed-untrusted/u);
});

test("Resident OpenAI cancellation and errors never expose backend detail", async () => {
  const secret = "synthetic-secret-must-not-escape";
  const commands: string[] = [];
  const pendingInvoke = async <T>(command: string): Promise<T> => {
    commands.push(command);
    if (command === "resident_openai_cancel") return undefined as T;
    return new Promise<T>(() => undefined);
  };
  const controller = new AbortController();
  const cancelled = new NativeOpenAiProvider(pendingInvoke).diagnose(
    "Diagnose",
    [providerEvidence()],
    { signal: controller.signal },
  );
  controller.abort();
  await assert.rejects(cancelled, (error: unknown) => {
    assert.equal((error as { code?: unknown }).code, "cancelled");
    return true;
  });
  assert.ok(commands.includes("resident_openai_cancel"));

  const rejectedInvoke = async <T>(): Promise<T> =>
    Promise.reject({ code: "upstream", message: secret });
  await assert.rejects(
    new NativeOpenAiProvider(rejectedInvoke).diagnose("Diagnose", [
      providerEvidence(),
    ]),
    (error: unknown) => {
      assert.equal((error as { code?: unknown }).code, "upstream");
      assert.doesNotMatch(String(error), new RegExp(secret, "u"));
      return true;
    },
  );
});

test("signed artifacts are bound to the requested payload and container hash", async () => {
  const body = JSON.stringify({ schemaVersion: "1.0", sessionId: "S-test" });
  const payloadSha256 = await sha256(body);
  const request: AuditSealRequest = {
    schemaVersion: "1.0",
    sessionId: "S-test",
    format: "json",
    payloadMediaType: "application/json",
    body,
    payloadSha256,
  };
  const container = {
    schema,
    kind: "kernaid.signed-report",
    algorithm: "Ed25519",
    deviceId: "KA-0123456789abcdef01234567",
    journalSequence: 2,
    journalEntryHash: base64Url(new Uint8Array(32).fill(1)),
    payloadMediaType: "application/json",
    payloadSha256: base64Url(hexBytes(payloadSha256)),
    payload: base64Url(new TextEncoder().encode(body)),
    publicKey: base64Url(new Uint8Array(32).fill(2)),
    signature: base64Url(new Uint8Array(64).fill(3)),
  };
  const containerJson = JSON.stringify(container);
  const artifact = {
    mediaType,
    payloadMediaType: "application/json",
    containerJson,
    sha256: await sha256(containerJson),
    payloadSha256,
    envelopeSchema: schema,
  };

  assert.equal(
    (await parseNativeSignedArtifact(artifact, request)).payloadSha256,
    payloadSha256,
  );
  await assert.rejects(
    parseNativeSignedArtifact(
      { ...artifact, payloadSha256: "0".repeat(64) },
      request,
    ),
  );
  await assert.rejects(
    parseNativeSignedArtifact({ ...artifact, sha256: "0".repeat(64) }, request),
  );
});

test("Rescue corpus diagnosis is deterministic and independent of browser globals", async () => {
  const originalWindow = Object.getOwnPropertyDescriptor(globalThis, "window");
  Reflect.deleteProperty(globalThis, "window");
  try {
    const provider = new PlatformOfflineRulesProvider();
    const linuxEvidence = await rescueCorpusEvidence(
      rescueLinuxInspectionFixture(),
    );
    const linux = await provider.diagnose("Analizza il target", [
      linuxEvidence,
    ]);
    assert.match(linux.diagnosis, /righe fstab malformate/);
    assert.equal(linux.confidence, 0.84);
    assert.deepEqual(linux.evidenceIds, ["E-RESCUE-CORPUS"]);

    const windowsEvidence = await rescueCorpusEvidence(
      rescueWindowsInspectionFixture(),
    );
    const windows = await provider.diagnose("Analizza il target", [
      windowsEvidence,
    ]);
    assert.match(windows.diagnosis, /servicing o riavvio pendente/);
    assert.equal(windows.confidence, 0.8);
  } finally {
    restoreProperty("window", originalWindow);
  }
});

test("Rescue OpenAI golden requests preserve deterministic TypeScript parity", async () => {
  interface GoldenManifest {
    schemaVersion: number;
    validCases: Array<{
      name: string;
      request: string;
      response: string;
    }>;
  }
  interface GoldenDiagnoseRequest {
    operation: "provider.openai.diagnose";
    payload: {
      objective: string;
      evidence: Array<{
        schemaVersion: "1.0";
        id: string;
        collector: string;
        target: string;
        contentType: string;
        trust: "observed-untrusted";
        summary: string;
        content: string;
      }>;
    };
  }
  interface GoldenDiagnoseResponse {
    operation: "provider.openai.diagnose";
    ok: true;
    payload: {
      proposal: {
        schemaVersion: "1.0";
        diagnosis: string;
        confidence: number;
        evidenceIds: string[];
        requestedEvidence: string[];
      };
    };
  }

  const root = new URL(
    "../../../packages/schemas/fixtures/rescue-openai/",
    import.meta.url,
  );
  const manifest = JSON.parse(
    readFileSync(new URL("manifest.json", root), "utf8"),
  ) as GoldenManifest;
  assert.equal(manifest.schemaVersion, 1);
  const diagnoseCases = manifest.validCases.filter(
    ({ name }) => name !== "status",
  );
  assert.equal(diagnoseCases.length, 8);
  const provider = new PlatformOfflineRulesProvider();
  for (const golden of diagnoseCases) {
    const request = JSON.parse(
      readFileSync(new URL(golden.request, root), "utf8"),
    ) as GoldenDiagnoseRequest;
    const expected = JSON.parse(
      readFileSync(new URL(golden.response, root), "utf8"),
    ) as GoldenDiagnoseResponse;
    assert.equal(request.operation, "provider.openai.diagnose", golden.name);
    assert.equal(expected.operation, request.operation, golden.name);
    assert.equal(expected.ok, true, golden.name);
    assert.equal(request.payload.evidence.length, 1, golden.name);
    const item = request.payload.evidence[0];
    assert.ok(item);
    const contentSha256 = await sha256(item.content);
    const proposal = await provider.diagnose(request.payload.objective, [
      {
        evidence: {
          schemaVersion: item.schemaVersion,
          id: item.id,
          collector: item.collector,
          target: item.target,
          capturedAt: "2026-08-17T00:00:00.000Z",
          contentType: item.contentType,
          sha256: contentSha256,
          sensitivity: "system",
          trust: item.trust,
          summary: item.summary,
          blobRef: `sha256:${contentSha256}`,
        },
        content: item.content,
      },
    ]);
    assert.deepEqual(proposal, expected.payload.proposal, golden.name);
    if (golden.name === "linux-generic-canary") {
      assert.match(item.content, /RESCUE-CORPUS-CANARY-DO-NOT-PROJECT/u);
      assert.doesNotMatch(
        JSON.stringify(expected.payload.proposal),
        /RESCUE-CORPUS-CANARY-DO-NOT-PROJECT/u,
      );
    }
  }
});

test("Rescue corpus provider requires one exact canonically summarized evidence", async () => {
  const provider = new PlatformOfflineRulesProvider();
  const valid = await rescueCorpusEvidence(rescueWindowsInspectionFixture());
  const assertBlocked = async (
    values: Parameters<PlatformOfflineRulesProvider["diagnose"]>[1],
  ): Promise<void> => {
    const proposal = await provider.diagnose("Analizza", values);
    assert.match(proposal.diagnosis, /corpus offline Rescue non è valido/);
    assert.equal(proposal.confidence, 0.1);
    assert.deepEqual(proposal.requestedEvidence, [
      RESCUE_OFFLINE_EVIDENCE_COLLECTOR,
    ]);
  };

  await assertBlocked([
    {
      ...valid,
      evidence: { ...valid.evidence, summary: "free text customer name" },
    },
  ]);
  await assertBlocked([
    {
      ...valid,
      evidence: { ...valid.evidence, target: "rescue-runtime" },
    },
  ]);
  await assertBlocked([
    {
      ...valid,
      evidence: { ...valid.evidence, contentType: "text/plain" },
    },
  ]);
  await assertBlocked([
    {
      ...valid,
      evidence: { ...valid.evidence, trust: "model-generated" as never },
    },
  ]);
  await assertBlocked([{ ...valid, content: "not-json" }]);
  await assertBlocked([
    valid,
    { ...valid, evidence: { ...valid.evidence, id: "E-DUPLICATE" } },
  ]);
  await assertBlocked([valid, providerEvidence()]);
});

test("Rescue evidence is never presented as an installed-system diagnosis", async () => {
  const collectors = [
    "linux.block.inventory",
    "linux.mounts.read-only",
    "linux.systemd.failed",
    "linux.systemd.state",
    "linux.fstab",
    "linux.df",
    "linux.network.links",
    "linux.network.routes",
    "linux.dpkg.audit",
  ];
  const evidence = collectors.map((collector, index) => ({
    evidence: {
      schemaVersion: "1.0" as const,
      id: `E-${index + 1}`,
      collector,
      target: "rescue-runtime",
      capturedAt: "2026-08-01T00:00:00.000Z",
      contentType: "text/plain",
      sha256: String(index).padStart(64, "0"),
      sensitivity: "system" as const,
      trust: "observed-untrusted" as const,
      summary: "Comando di inventario completato",
      blobRef: `sha256:${String(index).padStart(64, "0")}`,
    },
    content: index === 0 ? '{"blockdevices":[]}' : "fixture",
  }));
  const originalWindow = Object.getOwnPropertyDescriptor(globalThis, "window");
  const originalLocation = Object.getOwnPropertyDescriptor(
    globalThis,
    "location",
  );
  Object.defineProperty(globalThis, "window", {
    configurable: true,
    value: {},
  });
  Object.defineProperty(globalThis, "location", {
    configurable: true,
    value: { hostname: "127.0.0.1", port: "4173" },
  });

  try {
    const proposal = await new PlatformOfflineRulesProvider().diagnose(
      "Analizza il sistema",
      evidence,
    );
    assert.match(proposal.diagnosis, /corpus offline Rescue non è valido/);
    assert.equal(proposal.confidence, 0.1);
    assert.deepEqual(
      proposal.evidenceIds,
      evidence.map((item) => item.evidence.id),
    );
    assert.deepEqual(proposal.requestedEvidence, [
      RESCUE_OFFLINE_EVIDENCE_COLLECTOR,
    ]);
  } finally {
    restoreProperty("window", originalWindow);
    restoreProperty("location", originalLocation);
  }
});

test("Rescue never falls back to the synthetic healthy fixture", async () => {
  const evidence = [
    {
      evidence: {
        schemaVersion: "1.0" as const,
        id: "E-1",
        collector: "system.hostname",
        target: "rescue-runtime",
        capturedAt: "2026-08-01T00:00:00.000Z",
        contentType: "text/plain",
        sha256: "1".repeat(64),
        sensitivity: "system" as const,
        trust: "observed-untrusted" as const,
        summary: "Comando di inventario completato",
        blobRef: `sha256:${"1".repeat(64)}`,
      },
      content: "kernaid-rescue",
    },
  ];
  const originalWindow = Object.getOwnPropertyDescriptor(globalThis, "window");
  const originalLocation = Object.getOwnPropertyDescriptor(
    globalThis,
    "location",
  );
  Object.defineProperty(globalThis, "window", {
    configurable: true,
    value: {},
  });
  Object.defineProperty(globalThis, "location", {
    configurable: true,
    value: { hostname: "127.0.0.1", port: "4173" },
  });

  try {
    const proposal = await new PlatformOfflineRulesProvider().diagnose(
      "Analizza il sistema",
      evidence,
    );
    assert.match(proposal.diagnosis, /corpus offline Rescue non è valido/);
    assert.doesNotMatch(proposal.diagnosis, /Nessuna anomalia/);
    assert.deepEqual(proposal.evidenceIds, ["E-1"]);
  } finally {
    restoreProperty("window", originalWindow);
    restoreProperty("location", originalLocation);
  }
});

test("Rescue selected-target metadata still cannot become an OS diagnosis", async () => {
  const evidence = [
    {
      evidence: {
        schemaVersion: "1.0" as const,
        id: "E-1",
        collector: "rescue.installed-target.selection",
        target: "selected-installed-target-candidate",
        capturedAt: "2026-08-01T00:00:00.000Z",
        contentType: "application/json",
        sha256: "1".repeat(64),
        sensitivity: "system" as const,
        trust: "observed-untrusted" as const,
        summary: "Candidato target rivalidato",
        blobRef: `sha256:${"1".repeat(64)}`,
      },
      content: JSON.stringify(rescueTargetSelectionFixture()),
    },
  ];
  const originalWindow = Object.getOwnPropertyDescriptor(globalThis, "window");
  const originalLocation = Object.getOwnPropertyDescriptor(
    globalThis,
    "location",
  );
  Object.defineProperty(globalThis, "window", {
    configurable: true,
    value: {},
  });
  Object.defineProperty(globalThis, "location", {
    configurable: true,
    value: { hostname: "127.0.0.1", port: "4173" },
  });
  try {
    const proposal = await new PlatformOfflineRulesProvider().diagnose(
      "Analizza il target",
      evidence,
    );
    assert.match(proposal.diagnosis, /corpus offline Rescue non è valido/);
    assert.deepEqual(proposal.requestedEvidence, [
      "rescue.installed-target.filesystem-content.read-only.v1",
    ]);
  } finally {
    restoreProperty("window", originalWindow);
    restoreProperty("location", originalLocation);
  }
});

test("Rescue rejects malformed, mis-scoped, and duplicate selection evidence", async () => {
  const selectionEvidence = {
    evidence: {
      schemaVersion: "1.0" as const,
      id: "E-1",
      collector: "rescue.installed-target.selection",
      target: "wrong-target",
      capturedAt: "2026-08-01T00:00:00.000Z",
      contentType: "text/plain",
      sha256: "1".repeat(64),
      sensitivity: "system" as const,
      trust: "observed-untrusted" as const,
      summary: "Candidato target rivalidato",
      blobRef: `sha256:${"1".repeat(64)}`,
    },
    content: "not-json",
  };
  const originalWindow = Object.getOwnPropertyDescriptor(globalThis, "window");
  const originalLocation = Object.getOwnPropertyDescriptor(
    globalThis,
    "location",
  );
  Object.defineProperty(globalThis, "window", {
    configurable: true,
    value: {},
  });
  Object.defineProperty(globalThis, "location", {
    configurable: true,
    value: { hostname: "127.0.0.1", port: "4173" },
  });
  try {
    const provider = new PlatformOfflineRulesProvider();
    const malformed = await provider.diagnose("Analizza", [selectionEvidence]);
    assert.match(malformed.diagnosis, /corpus offline Rescue non è valido/);
    assert.deepEqual(malformed.requestedEvidence, [
      RESCUE_OFFLINE_EVIDENCE_COLLECTOR,
    ]);
    const valid = {
      ...selectionEvidence,
      evidence: {
        ...selectionEvidence.evidence,
        target: "selected-installed-target-candidate",
        contentType: "application/json",
      },
      content: JSON.stringify(rescueTargetSelectionFixture()),
    };
    const duplicate = await provider.diagnose("Analizza", [
      valid,
      {
        ...valid,
        evidence: { ...valid.evidence, id: "E-2" },
      },
    ]);
    assert.match(duplicate.diagnosis, /corpus offline Rescue non è valido/);
  } finally {
    restoreProperty("window", originalWindow);
    restoreProperty("location", originalLocation);
  }
});

test("partial native Linux evidence fails closed instead of using generic rules", async () => {
  const evidence = [
    {
      evidence: {
        schemaVersion: "1.0" as const,
        id: "E-1",
        collector: "linux.block.inventory",
        target: "local-machine",
        capturedAt: "2026-08-01T00:00:00.000Z",
        contentType: "application/json",
        sha256: "1".repeat(64),
        sensitivity: "system" as const,
        trust: "observed-untrusted" as const,
        summary: "Comando di inventario completato",
        blobRef: `sha256:${"1".repeat(64)}`,
      },
      content: '{"blockdevices":[]}',
    },
  ];
  const originalWindow = Object.getOwnPropertyDescriptor(globalThis, "window");
  Object.defineProperty(globalThis, "window", {
    configurable: true,
    value: { __TAURI_INTERNALS__: {} },
  });
  try {
    const proposal = await new PlatformOfflineRulesProvider().diagnose(
      "Analizza il sistema",
      evidence,
    );
    assert.match(proposal.diagnosis, /Diagnosi Linux incompleta/);
    assert.equal(proposal.confidence, 0.1);
    assert.ok(proposal.requestedEvidence.includes("linux.systemd.failed"));
  } finally {
    restoreProperty("window", originalWindow);
  }
});

test("snapshot-only Linux evidence is structural and never reaches text fallback", async () => {
  const snapshot = JSON.parse(
    readFileSync(
      new URL(
        "../../../tests/fixtures/linux-normalized-snapshot/expected/snapshot.v1.json",
        import.meta.url,
      ),
      "utf8",
    ),
  ) as {
    release: { prettyName: string | null };
  };
  snapshot.release.prettyName = "I/O error storage filesystem failed canary";
  const snapshotSha256 = await sha256(
    `${LINUX_NORMALIZED_SNAPSHOT_HASH_DOMAIN}${canonicalLinuxSnapshotJson(snapshot)}`,
  );
  const content = JSON.stringify({
    schemaVersion: "1.0",
    kind: "linux-normalized-snapshot",
    snapshotSha256,
    capture: {
      mode: "resident",
      targetScope: "running-root",
      accessPolicy: "fixed-descriptor-read-only",
      callerSuppliedPath: false,
      mutationRequested: false,
      crossDeviceTraversalAllowed: false,
    },
    snapshot,
  });
  const evidence = residentSnapshotEvidence(content, "application/json");
  const proposal = await new PlatformOfflineRulesProvider().diagnose(
    "Analizza",
    [evidence],
  );
  assert.match(proposal.diagnosis, /Diagnosi Linux incompleta/);
  assert.doesNotMatch(proposal.diagnosis, /storage|I\/O error/iu);
  assert.equal(proposal.confidence, 0.1);
  assert.deepEqual(proposal.evidenceIds, ["E-SNAPSHOT"]);
  assert.ok(proposal.requestedEvidence.includes("linux.block.inventory"));

  for (const invalid of [
    residentSnapshotEvidence("I/O error storage failed", "application/json"),
    residentSnapshotEvidence(content, "text/plain"),
  ]) {
    const blocked = await new PlatformOfflineRulesProvider().diagnose(
      "Analizza",
      [invalid],
    );
    assert.match(blocked.diagnosis, /snapshot statico normalizzato/);
    assert.equal(blocked.confidence, 0.1);
    assert.deepEqual(blocked.evidenceIds, ["E-SNAPSHOT"]);
    assert.doesNotMatch(blocked.diagnosis, /storage|I\/O error/iu);
  }
});

test("Resident Linux provider requires the exact local-machine corpus", async () => {
  const snapshot = JSON.parse(
    readFileSync(
      new URL(
        "../../../tests/fixtures/linux-normalized-snapshot/expected/snapshot.v1.json",
        import.meta.url,
      ),
      "utf8",
    ),
  ) as unknown;
  const snapshotSha256 = await sha256(
    `${LINUX_NORMALIZED_SNAPSHOT_HASH_DOMAIN}${canonicalLinuxSnapshotJson(snapshot)}`,
  );
  const snapshotContent = JSON.stringify({
    schemaVersion: "1.0",
    kind: "linux-normalized-snapshot",
    snapshotSha256,
    capture: {
      mode: "resident",
      targetScope: "running-root",
      accessPolicy: "fixed-descriptor-read-only",
      callerSuppliedPath: false,
      mutationRequested: false,
      crossDeviceTraversalAllowed: false,
    },
    snapshot,
  });
  const corpus = [
    residentSnapshotEvidence(snapshotContent, "application/json"),
    {
      evidence: {
        schemaVersion: "1.0" as const,
        id: "E-HOSTNAME",
        collector: "system.hostname",
        target: "local-machine",
        capturedAt: "2026-08-20T00:00:00.000Z",
        contentType: "text/plain",
        sha256: "b".repeat(64),
        sensitivity: "system" as const,
        trust: "observed-untrusted" as const,
        summary: "Comando di inventario completato",
        blobRef: `sha256:${"b".repeat(64)}`,
      },
      content: "production-hostname",
    },
    ...LINUX_P0_COLLECTORS.map((collector, index) => ({
      evidence: {
        schemaVersion: "1.0" as const,
        id: `E-P0-${index}`,
        collector,
        target: "local-machine",
        capturedAt: "2026-08-20T00:00:00.000Z",
        contentType: "text/plain",
        sha256: "c".repeat(64),
        sensitivity: "system" as const,
        trust: "observed-untrusted" as const,
        summary: "Comando di inventario completato",
        blobRef: `sha256:${"c".repeat(64)}`,
      },
      content: "fixture",
    })),
  ];
  const foreign = structuredClone(corpus);
  foreign[2]!.evidence.target = "foreign-machine";
  const extra = [
    ...corpus,
    {
      ...providerEvidence(),
      evidence: {
        ...providerEvidence().evidence,
        id: "E-EXTRA",
        collector: "linux.raw.uncontracted",
      },
    },
  ];
  const duplicateId = structuredClone(corpus);
  duplicateId[2]!.evidence.id = duplicateId[1]!.evidence.id;
  const provider = new PlatformOfflineRulesProvider();
  for (const invalid of [foreign, extra, duplicateId]) {
    const proposal = await provider.diagnose("Analizza", invalid);
    assert.match(proposal.diagnosis, /Diagnosi Linux incompleta/);
    assert.equal(proposal.confidence, 0.1);
    assert.ok(proposal.requestedEvidence.includes("linux.p0.corpus.exact.v1"));
  }
});

test("unsupported topology blocks Resident and Rescue providers before findings", async () => {
  const snapshot = JSON.parse(
    readFileSync(
      new URL(
        "../../../tests/fixtures/linux-normalized-snapshot/expected/multi-fs.snapshot.v1.json",
        import.meta.url,
      ),
      "utf8",
    ),
  ) as unknown;
  const snapshotSha256 = await sha256(
    `${LINUX_NORMALIZED_SNAPSHOT_HASH_DOMAIN}${canonicalLinuxSnapshotJson(snapshot)}`,
  );
  const residentContent = JSON.stringify({
    schemaVersion: "1.0",
    kind: "linux-normalized-snapshot",
    snapshotSha256,
    capture: {
      mode: "resident",
      targetScope: "running-root",
      accessPolicy: "fixed-descriptor-read-only",
      callerSuppliedPath: false,
      mutationRequested: false,
      crossDeviceTraversalAllowed: false,
    },
    snapshot,
  });
  const resident = await new PlatformOfflineRulesProvider().diagnose(
    "Analizza",
    [residentSnapshotEvidence(residentContent, "application/json")],
  );
  assert.match(resident.diagnosis, /topologia non supportata/);
  assert.equal(resident.confidence, 0.1);
  assert.deepEqual(resident.requestedEvidence, [
    "linux.topology.single-filesystem.v1",
  ]);

  const rescueFixture = rescueLinuxInspectionFixture();
  rescueFixture.status = "content-inspected-installation-unconfirmed";
  rescueFixture.os.installationConfirmed = false;
  rescueFixture.claims.installedOsConfirmed = false;
  rescueFixture.os.topology = {
    collectionScope: "root-filesystem-only",
    separateEtcMountPresent: true,
    separateBootMountPresent: true,
    separateUsrMountPresent: true,
    separateVarMountPresent: true,
    relevantSeparateMountPresent: true,
    supported: false,
  };
  rescueFixture.os.release = {
    id: null,
    name: null,
    prettyName: null,
    versionId: null,
    source: "absent",
  };
  const rescue = await new PlatformOfflineRulesProvider().diagnose("Analizza", [
    await rescueCorpusEvidence(rescueFixture),
  ]);
  assert.match(
    rescue.diagnosis,
    /topologia multi-filesystem|filesystem separati/,
  );
  assert.equal(rescue.confidence, 0.1);
  assert.deepEqual(rescue.requestedEvidence, [
    "linux.topology.single-filesystem.v1",
  ]);
  assert.doesNotMatch(rescue.diagnosis, /fstab malformate|nessuna anomalia/iu);
});

test("partial native Windows evidence fails closed instead of using generic rules", async () => {
  const evidence = [
    {
      evidence: {
        schemaVersion: "1.0" as const,
        id: "E-1",
        collector: "windows.volumes.state",
        target: "local-machine",
        capturedAt: "2026-08-01T00:00:00.000Z",
        contentType: "application/json",
        sha256: "1".repeat(64),
        sensitivity: "system" as const,
        trust: "observed-untrusted" as const,
        summary: "Comando di inventario completato",
        blobRef: `sha256:${"1".repeat(64)}`,
      },
      content: '{"snapshotComplete":true,"volumes":[]}',
    },
  ];
  const originalWindow = Object.getOwnPropertyDescriptor(globalThis, "window");
  Object.defineProperty(globalThis, "window", {
    configurable: true,
    value: { __TAURI_INTERNALS__: {} },
  });
  try {
    const proposal = await new PlatformOfflineRulesProvider().diagnose(
      "Analizza il sistema",
      evidence,
    );
    assert.match(proposal.diagnosis, /Diagnosi Windows incompleta/);
    assert.equal(proposal.confidence, 0.1);
    assert.ok(proposal.requestedEvidence.includes("windows.event-log.window"));
  } finally {
    restoreProperty("window", originalWindow);
  }
});

test("partial native macOS evidence fails closed instead of using generic rules", async () => {
  const evidence = [
    {
      evidence: {
        schemaVersion: "1.0" as const,
        id: "E-MACOS-1",
        collector: "macos.storage.inventory",
        target: "local-machine",
        capturedAt: "2026-08-01T00:00:00.000Z",
        contentType: "application/json",
        sha256: "1".repeat(64),
        sensitivity: "system" as const,
        trust: "observed-untrusted" as const,
        summary: "Comando di inventario completato",
        blobRef: `sha256:${"1".repeat(64)}`,
      },
      content: '{"schemaVersion":"1.0","queryComplete":true,"devices":[]}',
    },
  ];
  const originalWindow = Object.getOwnPropertyDescriptor(globalThis, "window");
  Object.defineProperty(globalThis, "window", {
    configurable: true,
    value: { __TAURI_INTERNALS__: {} },
  });
  try {
    const proposal = await new PlatformOfflineRulesProvider().diagnose(
      "Analizza il sistema",
      evidence,
    );
    assert.match(proposal.diagnosis, /Diagnosi macOS incompleta/);
    assert.equal(proposal.confidence, 0.1);
    assert.ok(proposal.requestedEvidence.includes("macos.apfs.capacity"));
  } finally {
    restoreProperty("window", originalWindow);
  }
});

test("macOS limited projections require their exact scope summary", async () => {
  const evidence = {
    evidence: {
      schemaVersion: "1.0" as const,
      id: "E-MACOS-UPDATES",
      collector: "macos.software-update.state",
      target: "local-machine",
      capturedAt: "2026-08-01T00:00:00.000Z",
      contentType: "application/json",
      sha256: "1".repeat(64),
      sensitivity: "system" as const,
      trust: "observed-untrusted" as const,
      summary: "Scope P0 esplicitamente non eseguito perché non qualificato",
      blobRef: `sha256:${"1".repeat(64)}`,
    },
    content:
      '{"schemaVersion":"1.0","queryComplete":true,"executionState":"not-run-unqualified","queryState":"unavailable-stale-cache","pending":[]}',
  };
  const originalWindow = Object.getOwnPropertyDescriptor(globalThis, "window");
  Object.defineProperty(globalThis, "window", {
    configurable: true,
    value: { __TAURI_INTERNALS__: {} },
  });
  try {
    const provider = new PlatformOfflineRulesProvider();
    const explicit = await provider.diagnose("Analizza il sistema", [evidence]);
    assert.ok(
      !explicit.requestedEvidence.includes("macos.software-update.state"),
    );
    const mislabeled = await provider.diagnose("Analizza il sistema", [
      {
        ...evidence,
        evidence: {
          ...evidence.evidence,
          summary: "Comando di inventario completato",
        },
      },
    ]);
    assert.ok(
      mislabeled.requestedEvidence.includes("macos.software-update.state"),
    );
    const wrongMime = await provider.diagnose("Analizza il sistema", [
      {
        ...evidence,
        evidence: {
          ...evidence.evidence,
          contentType: "text/plain" as const,
        },
      },
    ]);
    assert.ok(
      wrongMime.requestedEvidence.includes("macos.software-update.state"),
    );

    const startup = {
      ...evidence,
      evidence: {
        ...evidence.evidence,
        id: "E-MACOS-STARTUP",
        collector: "macos.startup.state",
        summary:
          "Safe mode verificato; login e background item non eseguiti perché non qualificati",
      },
      content:
        '{"schemaVersion":"1.0","queryComplete":true,"safeModeQueryState":"complete","loginItemsQueryState":"not-run-unqualified","backgroundItemsQueryState":"not-run-unqualified","safeMode":false,"thirdPartyLoginItemsEnabled":null,"backgroundItemsBlocked":null}',
    };
    const partialStartup = await provider.diagnose("Analizza il sistema", [
      startup,
    ]);
    assert.ok(
      !partialStartup.requestedEvidence.includes("macos.startup.state"),
    );
    const mislabeledStartup = await provider.diagnose("Analizza il sistema", [
      {
        ...startup,
        evidence: {
          ...startup.evidence,
          summary: "Comando di inventario completato",
        },
      },
    ]);
    assert.ok(
      mislabeledStartup.requestedEvidence.includes("macos.startup.state"),
    );
  } finally {
    restoreProperty("window", originalWindow);
  }
});

function providerEvidence() {
  return {
    evidence: {
      schemaVersion: "1.0" as const,
      id: "E-1",
      collector: "linux.systemd.failed",
      target: "local-machine",
      capturedAt: "2026-08-17T00:00:00.000Z",
      contentType: "text/plain",
      sha256: "a".repeat(64),
      sensitivity: "system" as const,
      trust: "observed-untrusted" as const,
      summary: "One failed service was observed",
      blobRef: `sha256:${"a".repeat(64)}`,
    },
    content: "demo.service failed",
  };
}

function rescueTargetScanFixture() {
  const diskId = `disk:${"a".repeat(64)}`;
  const targetId = `target:${"b".repeat(64)}`;
  return {
    apiVersion: "kernaid.dev/rescue-targets/v1alpha1",
    mode: "observe-r0",
    trust: "observed-untrusted",
    scanFingerprint: `scan:${"c".repeat(64)}`,
    identifierScope: "ephemeral-rescue-boot",
    disks: [
      {
        id: diskId,
        ref: "disk-1",
        sizeBytes: 500_000_000_000,
        transport: "nvme",
        partitionTable: "gpt",
        mediaReadOnly: false,
        removable: false,
        mounted: false,
        selectionEligible: true,
        exclusionReasons: [],
        volumes: [
          {
            ref: "disk-1/volume-1",
            parentRef: "disk-1",
            kind: "partition",
            sizeBytes: 499_000_000_000,
            filesystem: "ntfs",
            mediaReadOnly: false,
            mounted: false,
            encrypted: false,
          },
        ],
      },
    ],
    candidates: [
      {
        targetId,
        sourceRef: "disk-1/volume-1",
        diskId,
        osFamilyHint: "windows",
        confidence: "low",
        status: "unverified-installation-candidate",
        detectionBasis: ["ntfs-filesystem-signature"],
        requiresUnlock: false,
        inspectionMode: "metadata-only-no-mount",
        selectionEligible: true,
      },
    ],
    claims: {
      installedOsConfirmed: false,
      filesystemContentInspected: false,
      mountOperationPerformed: false,
      mutationPerformed: false,
      rawDeviceIdentifiersReturned: false,
    },
    limitations: ["os-family-is-only-a-low-confidence-metadata-hint"],
  };
}

function rescueTargetSelectionFixture() {
  const scan = rescueTargetScanFixture();
  return {
    apiVersion: scan.apiVersion,
    status: "observe-target-validated",
    scanFingerprint: scan.scanFingerprint,
    target: scan.candidates[0],
    claims: {
      installedOsConfirmed: false,
      filesystemContentInspected: false,
      mountOperationPerformed: false,
      mutationPerformed: false,
    },
  };
}

function rescueLinuxTargetSelectionFixture() {
  const selection = rescueTargetSelectionFixture();
  return {
    ...selection,
    target: {
      ...selection.target,
      osFamilyHint: "linux",
      detectionBasis: ["ext4-filesystem-signature"],
    },
  };
}

function rescueInspectionClaims(overrides: Record<string, boolean> = {}) {
  return {
    installedOsConfirmed: true,
    filesystemContentInspected: true,
    mountOperationAttempted: true,
    mountOperationPerformed: true,
    mountCleanupVerified: true,
    autoUnlockAttempted: false,
    mutationPerformed: false,
    diagnosisProduced: false,
    repairAttempted: false,
    ...overrides,
  };
}

function rescueWindowsInspectionFixture() {
  const selection = rescueTargetSelectionFixture();
  return {
    apiVersion: "kernaid.dev/rescue-offline-inspection/v1alpha1",
    status: "installed-os-content-inspected",
    trust: "observed-untrusted",
    target: {
      scanFingerprint: selection.scanFingerprint,
      targetId: selection.target.targetId,
      sourceRef: selection.target.sourceRef,
      osFamily: "windows",
      filesystem: "ntfs",
    },
    inspection: {
      mode: "temporary-read-only-no-replay",
      mountFlags: ["nodev", "noexec", "nosuid", "nosymfollow", "ro"],
      filesystemOptions: [],
      dirtyVolumePolicy: "read-only-no-force-driver-replay-not-applied",
      volumeStateQualification: "unqualified",
      privateMountNamespace: true,
      journalReplayPrevented: true,
      deviceOpenedReadOnly: true,
      rawDeviceIdentifierReturned: false,
      responseLimitBytes: 49_152,
    },
    claims: rescueInspectionClaims(),
    os: {
      family: "windows",
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
          state: "inspected",
          microsoftBootManagerPresent: true,
          bcdPresent: true,
          fallbackBootloaderPresent: false,
        },
      },
      servicing: {
        pendingXmlPresent: true,
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

function rescueLinuxInspectionFixture() {
  const selection = rescueLinuxTargetSelectionFixture();
  return {
    apiVersion: "kernaid.dev/rescue-offline-inspection/v1alpha1",
    status: "installed-os-content-inspected",
    trust: "observed-untrusted",
    target: {
      scanFingerprint: selection.scanFingerprint,
      targetId: selection.target.targetId,
      sourceRef: selection.target.sourceRef,
      osFamily: "linux",
      filesystem: "ext4",
    },
    inspection: {
      mode: "temporary-read-only-no-replay",
      mountFlags: ["nodev", "noexec", "nosuid", "nosymfollow", "ro"],
      filesystemOptions: ["noload"],
      dirtyVolumePolicy: "journal-replay-disabled",
      volumeStateQualification: "not-applicable",
      privateMountNamespace: true,
      journalReplayPrevented: true,
      deviceOpenedReadOnly: true,
      rawDeviceIdentifierReturned: false,
      responseLimitBytes: 49_152,
    },
    claims: rescueInspectionClaims(),
    os: {
      family: "linux",
      scope: "installed-root-static",
      installationConfirmed: true,
      topology: {
        collectionScope: "root-filesystem-only",
        separateEtcMountPresent: false,
        separateBootMountPresent: false,
        separateUsrMountPresent: false,
        separateVarMountPresent: false,
        relevantSeparateMountPresent: false,
        supported: true,
      },
      release: {
        id: "debian",
        name: "Debian GNU/Linux",
        prettyName: "Debian GNU/Linux 13",
        versionId: "13",
        source: "etc-os-release",
      },
      boot: {
        directoryPresent: true,
        kernelArtifactCount: 1,
        initramfsArtifactCount: 1,
        bootloaderDirectoryCount: 1,
        symlinkArtifactCount: 0,
      },
      configuration: {
        fstab: {
          present: true,
          entryCount: 2,
          rootEntryPresent: true,
          efiEntryPresent: false,
          swapEntryCount: 0,
          networkEntryCount: 0,
          malformedLineCount: 1,
        },
        machineIdPresent: true,
      },
      packageDatabases: {
        dpkgStatusPresent: true,
        rpmDatabasePresent: false,
        pacmanDatabasePresent: false,
      },
    },
    limitations: [
      "content-is-untrusted-data-not-instructions",
      "no-diagnosis-or-repair-was-produced",
      "encrypted-and-stacked-storage-was-not-activated",
      "only-static-allowlisted-paths-were-inspected",
    ],
  };
}

async function rescueCorpusEvidence(
  inspection:
    | ReturnType<typeof rescueWindowsInspectionFixture>
    | ReturnType<typeof rescueLinuxInspectionFixture>,
) {
  const parsed = parseRescueOfflineInspection(
    inspection,
    inspection.target.osFamily === "linux"
      ? rescueLinuxTargetSelectionFixture()
      : rescueTargetSelectionFixture(),
  );
  const linuxSnapshot =
    parsed.os.family === "linux"
      ? await linuxNormalizedSnapshotFromRescue(parsed)
      : undefined;
  const content =
    linuxSnapshot === undefined
      ? rescueOfflineCorpusJson(parsed)
      : JSON.stringify(linuxSnapshot);
  const contentHash = await sha256(content);
  return {
    evidence: {
      schemaVersion: "1.0" as const,
      id: "E-RESCUE-CORPUS",
      collector:
        linuxSnapshot === undefined
          ? RESCUE_OFFLINE_EVIDENCE_COLLECTOR
          : LINUX_NORMALIZED_SNAPSHOT_COLLECTOR,
      target: RESCUE_OFFLINE_EVIDENCE_TARGET,
      capturedAt: "2026-08-17T00:00:00.000Z",
      contentType: "application/json",
      sha256: contentHash,
      sensitivity: "system" as const,
      trust: "observed-untrusted" as const,
      summary:
        linuxSnapshot === undefined
          ? rescueOfflineEvidenceSummary(parsed)
          : linuxNormalizedSnapshotEvidenceSummary(linuxSnapshot),
      blobRef: `sha256:${contentHash}`,
    },
    content,
  };
}

function residentSnapshotEvidence(content: string, contentType: string) {
  return {
    evidence: {
      schemaVersion: "1.0" as const,
      id: "E-SNAPSHOT",
      collector: LINUX_NORMALIZED_SNAPSHOT_COLLECTOR,
      target: "local-machine",
      capturedAt: "2026-08-20T00:00:00.000Z",
      contentType,
      sha256: "a".repeat(64),
      sensitivity: "system" as const,
      trust: "observed-untrusted" as const,
      summary: "Snapshot statico Linux resident acquisito read-only e validato",
      blobRef: `sha256:${"a".repeat(64)}`,
    },
    content,
  };
}

function base64Url(value: Uint8Array): string {
  return Buffer.from(value).toString("base64url");
}

function hexBytes(value: string): Uint8Array {
  return Uint8Array.from({ length: value.length / 2 }, (_, index) =>
    Number.parseInt(value.slice(index * 2, index * 2 + 2), 16),
  );
}

async function sha256(value: string): Promise<string> {
  const digest = await crypto.subtle.digest(
    "SHA-256",
    new TextEncoder().encode(value),
  );
  return Buffer.from(digest).toString("hex");
}

function restoreProperty(
  name: "window" | "location" | "fetch",
  descriptor: PropertyDescriptor | undefined,
): void {
  if (descriptor === undefined) Reflect.deleteProperty(globalThis, name);
  else Object.defineProperty(globalThis, name, descriptor);
}
