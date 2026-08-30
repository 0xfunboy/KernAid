import assert from "node:assert/strict";
import test from "node:test";
import type { ObservedEvidence } from "@kernaid/agent-gateway";
import {
  RescueOpenAiProvider,
  RescueProviderSessionBinding,
  getRescueOpenAiStatus,
  rescueOpenAiReady,
  transitionRescueProviderMode,
} from "../src/rescue-openai.js";

const API_VERSION = "kernaid.dev/rescue-openai/v1alpha1";
const CONTEXT_SHA256 = `sha256:${"a".repeat(64)}`;
const CONTEXT_BINDING = Object.freeze({ contextSha256: CONTEXT_SHA256 });

test("target scan and selection keep provider epochs stable for cleanup", () => {
  for (const operation of ["scan", "selection"] as const) {
    const binding = new RescueProviderSessionBinding("offline");
    const bindingEpoch = binding.epoch;
    let contextEpoch = operation === "scan" ? 17 : 23;
    const operationEpoch = contextEpoch;
    let targetBusy = true;

    const transition = transitionRescueProviderMode(
      binding,
      "openai",
      contextEpoch,
      {
        targetBusy,
        inspectionBusy: false,
        inspectionInFlight: false,
      },
    );
    contextEpoch = transition.contextEpoch;

    assert.equal(transition.changed, false, operation);
    assert.equal(contextEpoch, operationEpoch, operation);
    assert.equal(binding.mode, "offline", operation);
    assert.equal(binding.epoch, bindingEpoch, operation);
    assert.equal(binding.sessionMode, undefined, operation);

    // Mirrors the epoch-bound finally in scan/selection: because the blocked
    // click changed no epoch, cleanup can always release targetBusy.
    if (contextEpoch === operationEpoch) targetBusy = false;
    assert.equal(targetBusy, false, operation);
  }

  const binding = new RescueProviderSessionBinding("offline");
  const unchanged = transitionRescueProviderMode(binding, "offline", 31, {
    targetBusy: false,
    inspectionBusy: false,
    inspectionInFlight: false,
  });
  assert.deepEqual(unchanged, { changed: false, contextEpoch: 31 });
  assert.equal(binding.mode, "offline");
  assert.equal(binding.epoch, 0);

  const changed = transitionRescueProviderMode(binding, "openai", 31, {
    targetBusy: false,
    inspectionBusy: false,
    inspectionInFlight: false,
  });
  assert.deepEqual(changed, { changed: true, contextEpoch: 32 });
  assert.equal(binding.mode, "openai");
  assert.equal(binding.epoch, 1);
});

test("Rescue provider binding rejects inspect/switch stale interleavings", async () => {
  const binding = new RescueProviderSessionBinding("openai");
  const openAiInspection = binding.beginPreparation();
  assert.ok(openAiInspection);
  let releaseOpenAi = (): void => undefined;
  const openAiGate = new Promise<void>((resolve) => {
    releaseOpenAi = resolve;
  });
  const openAiCompletion = openAiGate.then(() =>
    binding.commitPreparation(openAiInspection),
  );

  // A UI switch is rejected while inspection is synchronously latched.
  assert.equal(binding.switchMode("offline"), false);
  // An independent invalidation permits Offline, but the stale OpenAI
  // completion arriving afterwards cannot create a session in that mode.
  binding.clearSessionAndPreparation();
  assert.equal(binding.switchMode("offline"), true);
  releaseOpenAi();
  assert.equal(await openAiCompletion, undefined);
  assert.equal(binding.mode, "offline");
  assert.equal(binding.sessionMode, undefined);
  assert.equal(binding.sessionMatches("openai"), false);
  assert.equal(binding.sessionMatches("offline"), false);

  const offlineInspection = binding.beginPreparation();
  assert.ok(offlineInspection);
  let releaseOffline = (): void => undefined;
  const offlineGate = new Promise<void>((resolve) => {
    releaseOffline = resolve;
  });
  const staleOfflineCompletion = offlineGate.then(() =>
    binding.commitPreparation(offlineInspection),
  );
  assert.equal(binding.switchMode("openai"), false);
  // The inverse transition also rejects its stale completion.
  binding.clearSessionAndPreparation();
  assert.equal(binding.switchMode("openai"), true);
  releaseOffline();
  assert.equal(await staleOfflineCompletion, undefined);
  assert.equal(binding.sessionMode, undefined);
  assert.equal(binding.sessionMatches("offline"), false);

  const currentOpenAiInspection = binding.beginPreparation();
  assert.ok(currentOpenAiInspection);
  assert.equal(binding.commitPreparation(currentOpenAiInspection), "openai");
  assert.equal(binding.sessionMatches("openai"), true);
  assert.equal(binding.sessionMatches("offline"), false);
});

function rescueEvidence(): ObservedEvidence {
  return {
    evidence: {
      schemaVersion: "1.0",
      id: "E-RESCUE-CORPUS",
      collector: "rescue.installed-target.filesystem-content.read-only.v1",
      target: "selected-installed-target",
      capturedAt: "2026-08-18T00:00:00.000Z",
      contentType: "application/json",
      sha256: "a".repeat(64),
      sensitivity: "system",
      trust: "observed-untrusted",
      summary: "Corpus Rescue statico",
      blobRef: `sha256:${"a".repeat(64)}`,
    },
    content: '{"family":"windows"}',
  };
}

function requestFrom(init: RequestInit | undefined): Record<string, unknown> {
  assert.equal(typeof init?.body, "string");
  const body = init.body;
  assert.ok(body.endsWith("\n"));
  assert.ok(!body.slice(0, -1).includes("\n"));
  return JSON.parse(body.slice(0, -1)) as Record<string, unknown>;
}

function frame(value: unknown, status = 200): Response {
  const body = `${JSON.stringify(value)}\n`;
  return new Response(body, {
    status,
    headers: {
      "Content-Type": "application/json",
      "Content-Length": String(new TextEncoder().encode(body).byteLength),
    },
  });
}

test("Rescue status is presence-only, correlated, and exact", async () => {
  let calls = 0;
  const fetch = async (
    input: RequestInfo | URL,
    init?: RequestInit,
  ): Promise<Response> => {
    calls += 1;
    assert.equal(input, "/api/rescue/provider/openai");
    assert.equal(init?.method, "POST");
    assert.equal(init?.cache, "no-store");
    assert.ok(init?.signal instanceof AbortSignal);
    const request = requestFrom(init);
    assert.deepEqual(Object.keys(request), [
      "apiVersion",
      "requestId",
      "operation",
      "payload",
    ]);
    assert.equal(request.apiVersion, API_VERSION);
    assert.equal(request.operation, "provider.status");
    assert.deepEqual(request.payload, {});
    return frame({
      apiVersion: API_VERSION,
      requestId: request.requestId,
      operation: "provider.status",
      ok: true,
      payload: {
        provider: "openai",
        profile: "rescue-default",
        vault: "unlocked",
        credential: "configured",
      },
    });
  };
  const status = await getRescueOpenAiStatus(fetch);
  assert.equal(calls, 1);
  assert.deepEqual(status, {
    provider: "openai",
    profile: "rescue-default",
    vault: "unlocked",
    credential: "configured",
  });
  assert.equal(rescueOpenAiReady(status), true);
  assert.equal(
    rescueOpenAiReady({
      ...status,
      vault: "locked",
      credential: "unavailable",
    }),
    false,
  );
});

test("Rescue context preview returns only the authoritative redacted projection", async () => {
  const fetch = async (
    _input: RequestInfo | URL,
    init?: RequestInit,
  ): Promise<Response> => {
    const request = requestFrom(init);
    assert.equal(request.operation, "provider.openai.context-preview");
    const payload = request.payload as Record<string, unknown>;
    assert.deepEqual(Object.keys(payload), ["objective", "evidence"]);
    return frame({
      apiVersion: API_VERSION,
      requestId: request.requestId,
      operation: "provider.openai.context-preview",
      ok: true,
      payload: {
        context: {
          objective: "Diagnosi [REDACTED]",
          deterministicProposal: {
            schemaVersion: "1.0",
            diagnosis: "Verifica read-only richiesta.",
            confidence: 0.7,
            evidenceIds: ["E-RESCUE-CORPUS"],
            requestedEvidence: [],
          },
          observations: [
            {
              id: "E-RESCUE-CORPUS",
              collector:
                "rescue.installed-target.filesystem-content.read-only.v1",
              trust: "observed-untrusted",
            },
          ],
        },
        contextSha256: CONTEXT_SHA256,
      },
    });
  };
  const preview = await new RescueOpenAiProvider(fetch).previewContext(
    "Diagnosi sk-not-returned-12345678",
    [rescueEvidence()],
  );
  assert.equal(preview.contextSha256, CONTEXT_SHA256);
  assert.equal(preview.context.objective, "Diagnosi [REDACTED]");
  assert.deepEqual(preview.context.observations, [
    {
      id: "E-RESCUE-CORPUS",
      collector: "rescue.installed-target.filesystem-content.read-only.v1",
      trust: "observed-untrusted",
    },
  ]);
  assert.doesNotMatch(JSON.stringify(preview), /sk-not-returned/u);
});

test("Rescue diagnosis sends exactly one eight-field evidence projection", async () => {
  const fetch = async (
    _input: RequestInfo | URL,
    init?: RequestInit,
  ): Promise<Response> => {
    const request = requestFrom(init);
    assert.equal(request.operation, "provider.openai.diagnose");
    const payload = request.payload as {
      objective: string;
      evidence: Array<Record<string, unknown>>;
      contextSha256: string;
    };
    assert.equal(payload.objective, "Diagnosi read-only");
    assert.equal(payload.evidence.length, 1);
    assert.equal(payload.contextSha256, CONTEXT_SHA256);
    assert.deepEqual(Object.keys(payload.evidence[0] ?? {}), [
      "schemaVersion",
      "id",
      "collector",
      "target",
      "contentType",
      "trust",
      "summary",
      "content",
    ]);
    const serialized = JSON.stringify(payload.evidence[0]);
    assert.doesNotMatch(
      serialized,
      /capturedAt|sha256|sensitivity|blobRef|authorization|bearer|api.?key/iu,
    );
    return frame({
      apiVersion: API_VERSION,
      requestId: request.requestId,
      operation: "provider.openai.diagnose",
      ok: true,
      payload: {
        proposal: {
          schemaVersion: "1.0",
          diagnosis: "Verifica read-only richiesta.",
          confidence: 0.7,
          evidenceIds: ["E-RESCUE-CORPUS"],
          requestedEvidence: [],
        },
      },
    });
  };
  const proposal = await new RescueOpenAiProvider(fetch).diagnose(
    "Diagnosi read-only",
    [rescueEvidence()],
    CONTEXT_BINDING,
  );
  assert.equal(proposal.diagnosis, "Verifica read-only richiesta.");
});

test("Rescue diagnosis is one-shot and maps closed executor errors", async () => {
  let calls = 0;
  const fetch = async (
    _input: RequestInfo | URL,
    init?: RequestInit,
  ): Promise<Response> => {
    calls += 1;
    const request = requestFrom(init);
    return frame({
      apiVersion: API_VERSION,
      requestId: request.requestId,
      operation: "provider.openai.diagnose",
      ok: false,
      error: { code: "upstream" },
    });
  };
  await assert.rejects(
    new RescueOpenAiProvider(fetch).diagnose(
      "Diagnosi",
      [rescueEvidence()],
      CONTEXT_BINDING,
    ),
    (error: unknown) => {
      assert.equal((error as { code?: unknown }).code, "upstream");
      assert.doesNotMatch(String(error), /backend|credential|response body/iu);
      return true;
    },
  );
  assert.equal(calls, 1);
});

test("Rescue response rejects duplicate keys before JSON.parse", async () => {
  const fetch = async (
    _input: RequestInfo | URL,
    init?: RequestInit,
  ): Promise<Response> => {
    const request = requestFrom(init);
    const body =
      `{"apiVersion":"${API_VERSION}",` +
      `"requestId":"${String(request.requestId)}",` +
      '"operation":"provider.status","ok":true,"ok":false,' +
      '"error":{"code":"transport"}}\n';
    return new Response(body, {
      headers: {
        "Content-Type": "application/json",
        "Content-Length": String(body.length),
      },
    });
  };
  await assert.rejects(getRescueOpenAiStatus(fetch), (error: unknown) => {
    assert.equal((error as { code?: unknown }).code, "invalid_response");
    return true;
  });
});

test("Rescue response rejects escaped duplicate keys and correlation drift", async () => {
  const escapedDuplicate = async (
    _input: RequestInfo | URL,
    init?: RequestInit,
  ): Promise<Response> => {
    const request = requestFrom(init);
    const body =
      `{"apiVersion":"${API_VERSION}",` +
      `"requestId":"${String(request.requestId)}",` +
      '"operation":"provider.status","ok":true,"payload":{' +
      '"provider":"openai","pr\\u006fvider":"openai",' +
      '"profile":"rescue-default","vault":"locked",' +
      '"credential":"unavailable"}}\n';
    return new Response(body, {
      headers: {
        "Content-Type": "application/json",
        "Content-Length": String(new TextEncoder().encode(body).byteLength),
      },
    });
  };
  await assert.rejects(getRescueOpenAiStatus(escapedDuplicate), {
    code: "invalid_response",
  });

  const wrongRequest = async (): Promise<Response> =>
    frame({
      apiVersion: API_VERSION,
      requestId: "O-00000000-0000-0000-0000-000000000000",
      operation: "provider.status",
      ok: true,
      payload: {
        provider: "openai",
        profile: "rescue-default",
        vault: "locked",
        credential: "unavailable",
      },
    });
  await assert.rejects(getRescueOpenAiStatus(wrongRequest), {
    code: "invalid_response",
  });

  const wrongEvidence = async (
    _input: RequestInfo | URL,
    init?: RequestInit,
  ): Promise<Response> => {
    const request = requestFrom(init);
    return frame({
      apiVersion: API_VERSION,
      requestId: request.requestId,
      operation: "provider.openai.diagnose",
      ok: true,
      payload: {
        proposal: {
          schemaVersion: "1.0",
          diagnosis: "Risposta non correlata.",
          confidence: 0.5,
          evidenceIds: ["E-OTHER"],
          requestedEvidence: [],
        },
      },
    });
  };
  await assert.rejects(
    new RescueOpenAiProvider(wrongEvidence).diagnose(
      "Diagnosi",
      [rescueEvidence()],
      CONTEXT_BINDING,
    ),
    { code: "invalid_response" },
  );
});

test("Rescue status rejects secrets and impossible presence states", async () => {
  for (const payload of [
    {
      provider: "openai",
      profile: "rescue-default",
      vault: "locked",
      credential: "configured",
    },
    {
      provider: "openai",
      profile: "rescue-default",
      vault: "unlocked",
      credential: "configured",
      credentialValue: "must-never-cross-loopback",
    },
  ]) {
    const fetch = async (
      _input: RequestInfo | URL,
      init?: RequestInit,
    ): Promise<Response> => {
      const request = requestFrom(init);
      return frame({
        apiVersion: API_VERSION,
        requestId: request.requestId,
        operation: "provider.status",
        ok: true,
        payload,
      });
    };
    await assert.rejects(getRescueOpenAiStatus(fetch), {
      code: "invalid_response",
    });
  }
});

test("Rescue response rejects lone surrogates and incomplete HTTP framing", async () => {
  const loneSurrogate = async (
    _input: RequestInfo | URL,
    init?: RequestInit,
  ): Promise<Response> => {
    const request = requestFrom(init);
    const body =
      `{"apiVersion":"${API_VERSION}",` +
      `"requestId":"${String(request.requestId)}",` +
      '"operation":"provider.status","ok":true,"payload":{' +
      '"provider":"openai","profile":"rescue-default",' +
      '"vault":"locked","credential":"unavailable",' +
      '"\\ud800":"rejected"}}\n';
    return new Response(body, {
      headers: {
        "Content-Type": "application/json",
        "Content-Length": String(new TextEncoder().encode(body).byteLength),
      },
    });
  };
  await assert.rejects(getRescueOpenAiStatus(loneSurrogate), {
    code: "invalid_response",
  });

  for (const headers of [
    { "Content-Type": "application/json" },
    {
      "Content-Type": "application/json; charset=utf-8",
      "Content-Length": "3",
    },
    { "Content-Type": "application/json", "Content-Length": "4" },
  ]) {
    const malformed = async (): Promise<Response> =>
      new Response("{}\n", { headers });
    await assert.rejects(getRescueOpenAiStatus(malformed), {
      code: "invalid_response",
    });
  }
});

test("Rescue provider enforces UTF-8 byte bounds and preflight cancellation", async () => {
  let calls = 0;
  const fetch = async (): Promise<Response> => {
    calls += 1;
    throw new Error("must not run");
  };
  const provider = new RescueOpenAiProvider(fetch);
  await assert.rejects(provider.diagnose("Diagnosi", [rescueEvidence()]), {
    code: "invalid_request",
  });
  await assert.rejects(
    provider.diagnose("é".repeat(4_097), [rescueEvidence()], CONTEXT_BINDING),
    {
      code: "invalid_request",
    },
  );
  await assert.rejects(provider.diagnose("Diagnosi", [], CONTEXT_BINDING), {
    code: "invalid_request",
  });
  const oversized = rescueEvidence();
  oversized.content = "é".repeat(24_577);
  await assert.rejects(
    provider.diagnose("Diagnosi", [oversized], CONTEXT_BINDING),
    {
      code: "invalid_request",
    },
  );
  const controller = new AbortController();
  controller.abort();
  await assert.rejects(
    provider.diagnose("Diagnosi", [rescueEvidence()], {
      contextSha256: CONTEXT_SHA256,
      signal: controller.signal,
    }),
    { code: "cancelled" },
  );
  assert.equal(calls, 0);
});

test("Rescue proposal enforces the executor UTF-8 byte bounds", async () => {
  for (const proposal of [
    {
      schemaVersion: "1.0",
      diagnosis: "é".repeat(8_193),
      confidence: 0.5,
      evidenceIds: ["E-RESCUE-CORPUS"],
      requestedEvidence: [],
    },
    {
      schemaVersion: "1.0",
      diagnosis: "Verifica read-only.",
      confidence: 0.5,
      evidenceIds: ["E-RESCUE-CORPUS"],
      requestedEvidence: ["é".repeat(129)],
    },
  ]) {
    const fetch = async (
      _input: RequestInfo | URL,
      init?: RequestInit,
    ): Promise<Response> => {
      const request = requestFrom(init);
      return frame({
        apiVersion: API_VERSION,
        requestId: request.requestId,
        operation: "provider.openai.diagnose",
        ok: true,
        payload: { proposal },
      });
    };
    await assert.rejects(
      new RescueOpenAiProvider(fetch).diagnose(
        "Diagnosi",
        [rescueEvidence()],
        CONTEXT_BINDING,
      ),
      { code: "invalid_response" },
    );
  }
});

test("Rescue transport deadlines and HTTP failures stay closed", async () => {
  const timeout = async (): Promise<Response> =>
    Promise.reject({ name: "TimeoutError", detail: "synthetic-secret" });
  await assert.rejects(getRescueOpenAiStatus(timeout), (error: unknown) => {
    assert.equal((error as { code?: unknown }).code, "timeout");
    assert.doesNotMatch(String(error), /synthetic-secret/u);
    return true;
  });

  const unavailable = async (): Promise<Response> =>
    new Response("synthetic-secret", { status: 503 });
  await assert.rejects(getRescueOpenAiStatus(unavailable), (error: unknown) => {
    assert.equal((error as { code?: unknown }).code, "transport");
    assert.equal((error as { status?: unknown }).status, 503);
    assert.doesNotMatch(String(error), /synthetic-secret/u);
    return true;
  });

  for (const [status, code, message] of [
    [400, "invalid_request", /non valida/u],
    [429, "transport", /occupato/u],
    [502, "invalid_response", /non valida/u],
  ] as const) {
    const failed = async (): Promise<Response> =>
      new Response("closed", { status });
    await assert.rejects(getRescueOpenAiStatus(failed), (error: unknown) => {
      assert.equal((error as { code?: unknown }).code, code);
      assert.equal((error as { status?: unknown }).status, status);
      assert.match(String(error), message);
      return true;
    });
  }
});
