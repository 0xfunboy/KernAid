import test from "node:test";
import assert from "node:assert/strict";
import { EventEmitter } from "node:events";
import { PassThrough } from "node:stream";
import { setImmediate as nextTurn } from "node:timers/promises";
import fs from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { ModelRuntime } from "@earendil-works/pi-coding-agent";
import {
  GEMROUTER_API,
  GEMROUTER_LIMITS,
  createGemrouterLimiter,
  createGemrouterTransport,
} from "../gemrouter-transport.mjs";

const baseUrl = "https://router.example.invalid/v1";
const apiKey = "synthetic-test-only";
const model = {
  id: "gemini-test",
  name: "gemini-test",
  provider: "kernaid",
  api: GEMROUTER_API,
  baseUrl,
  maxTokens: 2048,
  contextWindow: 32768,
  reasoning: false,
  input: ["text"],
  cost: { input: 1, output: 2, cacheRead: 0.1, cacheWrite: 0 },
};
const context = {
  systemPrompt: "Keep disks unchanged.",
  messages: [{ role: "user", content: "Help", timestamp: 1 }],
  tools: [],
};
const answer = (text = "Try the diagnostic controls.", finish = "stop") => ({
  choices: [
    { message: { role: "assistant", content: text }, finish_reason: finish },
  ],
  usage: {
    prompt_tokens: 10,
    completion_tokens: 3,
    prompt_tokens_details: { cached_tokens: 2 },
  },
});

// A node:https-shaped fake. It cannot open a socket; every response is local.
function fixture(handler = ({ respond }) => respond(answer()), settings = {}) {
  const calls = [];
  const request = (url, options, callback) => {
    const req = new EventEmitter();
    req.destroyed = false;
    req.destroy = () => {
      req.destroyed = true;
    };
    const call = {
      url,
      options,
      req,
      respond(
        value,
        { status = 200, headers = {}, end = true, raw = false } = {},
      ) {
        const response = new PassThrough();
        response.statusCode = status;
        response.headers = headers;
        call.response = response;
        callback(response);
        if (!response.destroyed && value !== undefined)
          response.write(raw ? value : JSON.stringify(value));
        if (end && !response.destroyed) response.end();
        return response;
      },
    };
    calls.push(call);
    req.end = (payload) => {
      call.payload = payload;
      queueMicrotask(() => {
        if (req.destroyed) return;
        const socket = new EventEmitter();
        req.emit("socket", socket);
        if (settings.connect !== false) socket.emit("secureConnect");
        handler(call);
      });
    };
    return req;
  };
  const transport = createGemrouterTransport({
    baseUrl,
    request,
    limiter: createGemrouterLimiter(),
    ...settings,
  });
  return { transport, calls, request };
}

test("non-streaming chat preserves Pi text events, usage, and text search protocol", async () => {
  const text = '{"web_search":"Linux boot error"}';
  const { transport, calls } = fixture(({ respond }) => respond(answer(text)));
  const stream = transport.streamSimple(
    model,
    {
      ...context,
      messages: [
        ...context.messages,
        {
          role: "assistant",
          content: [{ type: "text", text: "Earlier answer" }],
          stopReason: "stop",
        },
        { role: "user", content: [{ type: "text", text: "Follow up" }] },
      ],
    },
    {
      apiKey,
      headers: {
        Origin: "https://ignored.invalid",
        Cookie: "ignored",
        Authorization: "ignored",
      },
      reasoning: "high",
      maxRetries: 100,
      metadata: { ignored: true },
      onPayload: () => ({ stream: true }),
    },
  );
  const events = [];
  for await (const event of stream) events.push(event);
  const result = await stream.result();
  assert.deepEqual(
    events.map((event) => event.type),
    ["start", "text_start", "text_delta", "text_end", "done"],
  );
  assert.equal(result.content[0].text, text);
  assert.equal(result.stopReason, "stop");
  assert.equal(result.api, GEMROUTER_API);
  assert.deepEqual(result.usage, {
    input: 8,
    output: 3,
    cacheRead: 2,
    cacheWrite: 0,
    totalTokens: 13,
    cost: {
      input: 0.000008,
      output: 0.000006,
      cacheRead: (0.1 / 1_000_000) * 2,
      cacheWrite: 0,
      total: 0.0000142,
    },
  });
  assert.equal(calls.length, 1);
  assert.equal(calls[0].url.href, baseUrl + "/chat/completions");
  assert.equal(calls[0].options.agent, false);
  assert.deepEqual(calls[0].options.headers, {
    Authorization: `Bearer ${apiKey}`,
    "x-gemrouter-backend": "gemini-api",
    Accept: "application/json",
    "Content-Type": "application/json",
    "Content-Length": Buffer.byteLength(calls[0].payload),
  });
  assert.deepEqual(JSON.parse(calls[0].payload), {
    model: model.id,
    stream: false,
    max_tokens: 2048,
    messages: [
      { role: "system", content: context.systemPrompt },
      { role: "user", content: "Help" },
      { role: "assistant", content: "Earlier answer" },
      { role: "user", content: "Follow up" },
    ],
  });
  assert.ok(!JSON.stringify(result).includes(apiKey));
});

test("registered Pi ModelRuntime dispatches the custom API with its runtime key", async () => {
  const dir = await fs.mkdtemp(
    path.join(os.tmpdir(), "kernaid-gemrouter-pi-test-"),
  );
  try {
    const { transport, calls } = fixture();
    const runtime = await ModelRuntime.create({
      authPath: path.join(dir, "auth.json"),
      modelsPath: null,
      allowModelNetwork: false,
    });
    runtime.registerProvider("kernaid", {
      baseUrl,
      api: GEMROUTER_API,
      streamSimple: transport.streamSimple,
      authHeader: true,
      models: [model],
    });
    await runtime.setRuntimeApiKey("kernaid", apiKey);
    const result = await runtime.completeSimple(
      runtime.getModel("kernaid", model.id),
      context,
    );
    assert.equal(result.stopReason, "stop");
    assert.equal(result.content[0].text, "Try the diagnostic controls.");
    assert.equal(calls.length, 1);
    assert.equal(calls[0].options.headers.Authorization, `Bearer ${apiKey}`);
  } finally {
    await fs.rm(dir, { recursive: true });
  }
});

test("model discovery uses the selected endpoint and verified headers", async () => {
  const { transport, calls } = fixture(({ respond }) =>
    respond({ data: [{ id: model.id }] }),
  );
  assert.deepEqual(await transport.models({ apiKey }), {
    data: [{ id: model.id }],
  });
  assert.equal(calls[0].url.href, baseUrl + "/models");
  assert.equal(calls[0].options.method, "GET");
  assert.equal(calls[0].options.headers["x-gemrouter-backend"], "gemini-api");
  assert.equal(calls[0].payload, undefined);
});

test("HTTP, credential-bearing URLs, redirects, and endpoint changes never forward credentials", async () => {
  for (const value of [
    "http://router.invalid/v1",
    "https://name:password@router.invalid/v1",
    "https://router.invalid/v1?key=x",
    "https://router.invalid/v1#fragment",
  ])
    assert.throws(() => createGemrouterTransport({ baseUrl: value }));
  const { transport, calls } = fixture(({ respond }) =>
    respond(apiKey, {
      status: 302,
      headers: { location: "https://elsewhere.invalid/v1" },
    }),
  );
  const changed = await transport
    .streamSimple(
      { ...model, baseUrl: "https://elsewhere.invalid/v1" },
      context,
      { apiKey },
    )
    .result();
  assert.equal(changed.stopReason, "error");
  assert.equal(calls.length, 0);
  const redirected = await transport
    .streamSimple(model, context, { apiKey })
    .result();
  assert.equal(redirected.errorMessage, "Gemrouter returned HTTP 302.");
  assert.equal(calls.length, 1);
  assert.ok(!JSON.stringify(redirected).includes(apiKey));
});

test("response size, malformed JSON and upstream errors are bounded, redacted and never retried", async () => {
  for (const scenario of [
    ({ respond }) => respond(apiKey, { status: 429 }),
    ({ respond }) => respond(apiKey, { status: 500 }),
    ({ respond }) => respond(apiKey, { raw: true }),
    ({ respond }) =>
      respond(undefined, {
        headers: { "content-length": String(GEMROUTER_LIMITS.maxBytes + 1) },
        end: false,
      }),
    ({ respond }) =>
      respond("x".repeat(GEMROUTER_LIMITS.maxBytes + 1), { raw: true }),
    ({ req }) => req.emit("error", new Error(apiKey)),
    ({ respond }) => respond(undefined, { end: false }).destroy(),
  ]) {
    const { transport, calls } = fixture(scenario);
    const stream = transport.streamSimple(model, context, {
      apiKey,
      maxRetries: 5,
    });
    const events = [];
    for await (const event of stream) events.push(event.type);
    const result = await stream.result();
    assert.deepEqual(events, ["start", "error"]);
    assert.equal(result.stopReason, "error");
    assert.ok(!JSON.stringify(result).includes(apiKey));
    assert.equal(calls.length, 1);
    assert.equal(calls[0].req.destroyed, true);
  }
});

test("TLS connection and whole-body deadlines abort stalled requests", async () => {
  const connecting = fixture(() => {}, {
    connect: false,
    connectTimeoutMs: 10,
    timeoutMs: 60,
  });
  const connectionResult = await connecting.transport
    .streamSimple(model, context, { apiKey })
    .result();
  assert.equal(
    connectionResult.errorMessage,
    "Gemrouter connection timed out.",
  );
  assert.equal(connecting.calls[0].req.destroyed, true);

  // Byte activity does not extend the aggregate deadline.
  let drip;
  const body = fixture(
    ({ respond }) => {
      const response = respond(undefined, { end: false });
      drip = setInterval(() => response.write(" "), 2);
    },
    { connectTimeoutMs: 10, timeoutMs: 30 },
  );
  try {
    const result = await body.transport
      .streamSimple(model, context, { apiKey })
      .result();
    assert.equal(result.errorMessage, "Gemrouter request timed out.");
    assert.equal(body.calls[0].response.destroyed, true);
  } finally {
    clearInterval(drip);
  }
  assert.throws(() =>
    createGemrouterTransport({ baseUrl, timeoutMs: 120_001 }),
  );
  assert.throws(() =>
    createGemrouterTransport({ baseUrl, connectTimeoutMs: 10_001 }),
  );
});

test("abort before dispatch and during body read terminates with valid Pi errors", async () => {
  const { transport, calls } = fixture(({ respond }) =>
    respond(undefined, { end: false }),
  );
  const alreadyAborted = await transport
    .streamSimple(model, context, { apiKey, signal: AbortSignal.abort() })
    .result();
  assert.equal(alreadyAborted.stopReason, "aborted");
  assert.equal(calls.length, 0);
  const controller = new AbortController();
  const stream = transport.streamSimple(model, context, {
    apiKey,
    signal: controller.signal,
  });
  await nextTurn();
  controller.abort(new Error(apiKey));
  const result = await stream.result();
  assert.equal(result.stopReason, "aborted");
  assert.equal(result.errorMessage, "Gemrouter request aborted.");
  assert.equal(calls[0].req.destroyed, true);
  assert.equal(calls[0].response.destroyed, true);
});

test("max two active requests is shared across chat and model discovery and releases on failure", async () => {
  const { transport, calls } = fixture(() => {});
  const first = transport.streamSimple(model, context, { apiKey });
  const second = transport.models({ apiKey });
  await assert.rejects(transport.models({ apiKey }), /concurrency limit/);
  assert.equal(calls.length, 2);
  calls[0].req.emit("error", new Error(apiKey));
  assert.equal((await first.result()).stopReason, "error");
  const third = transport.models({ apiKey });
  assert.equal(calls.length, 3);
  calls[1].respond({ data: [] });
  calls[2].respond({ data: [] });
  await Promise.all([second, third]);
});

test("rolling 30-per-minute budget survives factory recreation and releases only concurrency", async () => {
  let time = 0;
  const limiter = createGemrouterLimiter({ now: () => time });
  const { request, calls } = fixture(({ respond }) => respond({ data: [] }));
  for (let index = 0; index < 30; index++)
    await createGemrouterTransport({ baseUrl, request, limiter }).models({
      apiKey,
    });
  const transport = createGemrouterTransport({ baseUrl, request, limiter });
  await assert.rejects(transport.models({ apiKey }), /request limit/);
  time = 59_999;
  await assert.rejects(transport.models({ apiKey }), /request limit/);
  assert.equal(calls.length, 30);
  time = 60_000;
  await transport.models({ apiKey });
  assert.equal(calls.length, 31);
});

test("default transport factories share one process-wide request budget", async () => {
  const { request, calls } = fixture(({ respond }) => respond({ data: [] }));
  for (let index = 0; index < 30; index++)
    await createGemrouterTransport({ baseUrl, request }).models({ apiKey });
  const next = createGemrouterTransport({ baseUrl, request });
  await assert.rejects(next.models({ apiKey }), /request limit/);
  assert.equal(calls.length, 30);
});

test("text-only validation rejects native tools, images, thinking history and oversized input before dispatch", async () => {
  const { transport, calls } = fixture();
  for (const invalid of [
    { ...context, tools: [{ name: "shell" }] },
    { ...context, messages: [{ role: "toolResult", content: [] }] },
    {
      ...context,
      messages: [{ role: "user", content: [{ type: "image", data: "x" }] }],
    },
    {
      ...context,
      messages: [
        ...context.messages,
        { role: "assistant", content: [{ type: "thinking", thinking: "x" }] },
      ],
    },
    {
      ...context,
      messages: [
        { role: "user", content: "x".repeat(GEMROUTER_LIMITS.maxBytes) },
      ],
    },
  ]) {
    const result = await transport
      .streamSimple(model, invalid, { apiKey })
      .result();
    assert.equal(result.stopReason, "error");
  }
  assert.equal(calls.length, 0);
});

test("length and missing usage produce valid output; unsupported finish/content is an error", async () => {
  const valid = fixture(({ respond }) =>
    respond({ choices: answer("Partial", "length").choices }),
  );
  const output = await valid.transport
    .streamSimple(model, context, { apiKey })
    .result();
  assert.equal(output.stopReason, "length");
  assert.equal(output.usage.totalTokens, 0);
  for (const data of [
    answer("", "stop"),
    answer("Text", "tool_calls"),
    { choices: [] },
    {
      choices: [
        {
          message: { role: "assistant", content: "Text", tool_calls: [{}] },
          finish_reason: "stop",
        },
      ],
    },
  ]) {
    const { transport } = fixture(({ respond }) => respond(data));
    assert.equal(
      (await transport.streamSimple(model, context, { apiKey }).result())
        .stopReason,
      "error",
    );
  }
});
