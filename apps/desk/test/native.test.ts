import assert from "node:assert/strict";
import test from "node:test";
import type { AuditSealRequest } from "@kernaid/session-driver";
import {
  PlatformOfflineRulesProvider,
  collectLocalInventory,
  parseNativeObservations,
  parseNativeSignedArtifact,
  parseSecureRuntimeStatus,
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
    assert.match(proposal.diagnosis, /OS installato non è stato montato/);
    assert.equal(proposal.confidence, 0.2);
    assert.deepEqual(
      proposal.evidenceIds,
      evidence.map((item) => item.evidence.id),
    );
    assert.deepEqual(proposal.requestedEvidence, [
      "rescue.installed-target.read-only.v1",
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
    assert.match(proposal.diagnosis, /OS installato non è stato montato/);
    assert.doesNotMatch(proposal.diagnosis, /Nessuna anomalia/);
    assert.deepEqual(proposal.evidenceIds, ["E-1"]);
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
  name: "window" | "location",
  descriptor: PropertyDescriptor | undefined,
): void {
  if (descriptor === undefined) Reflect.deleteProperty(globalThis, name);
  else Object.defineProperty(globalThis, name, descriptor);
}
