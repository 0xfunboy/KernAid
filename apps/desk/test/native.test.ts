import assert from "node:assert/strict";
import test from "node:test";
import type { AuditSealRequest } from "@kernaid/session-driver";
import {
  PlatformOfflineRulesProvider,
  authorizeObserve,
  collectLocalInventory,
  fingerprintNativeTarget,
  fingerprintRescueTarget,
  nativeObservationContentType,
  nativeObservationSummary,
  parseNativeObservations,
  parseRescueTargetScan,
  parseRescueTargetSelection,
  parseNativeSignedArtifact,
  parseSecureRuntimeStatus,
  scanRescueInstalledTargets,
  selectRescueInstalledTarget,
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
  assert.equal(parsed.candidates[0]?.osFamilyHint, "windows");
  assert.equal(parsed.disks[0]?.volumes[0]?.filesystem, "ntfs");

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
      target: "local-machine",
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
    assert.match(proposal.diagnosis, /Nessun target installato/);
    assert.equal(proposal.confidence, 0.2);
    assert.deepEqual(
      proposal.evidenceIds,
      evidence.map((item) => item.evidence.id),
    );
    assert.deepEqual(proposal.requestedEvidence, [
      "rescue.installed-target.selection.v1",
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
    assert.match(proposal.diagnosis, /Nessun target installato/);
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
    assert.match(proposal.diagnosis, /soli metadati storage/);
    assert.match(
      proposal.diagnosis,
      /non è ancora possibile formulare una diagnosi/,
    );
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
    assert.match(malformed.diagnosis, /non valida o ambigua/);
    assert.deepEqual(malformed.requestedEvidence, [
      "rescue.installed-target.selection.v1",
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
    assert.match(duplicate.diagnosis, /non valida o ambigua/);
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

function rescueTargetScanFixture() {
  const diskId = `disk:${"a".repeat(64)}`;
  const targetId = `target:${"b".repeat(64)}`;
  return {
    apiVersion: "kernaid.dev/rescue-targets/v1alpha1",
    mode: "observe-r0",
    trust: "observed-untrusted",
    scanFingerprint: `scan:${"c".repeat(64)}`,
    identifierScope: "ephemeral-rescue-process",
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
