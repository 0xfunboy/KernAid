import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { linuxContext } from "../../../packages/assistant-context/test/fixture.mjs";
import {
  AssistantRuntime,
  endpoint,
  splitNmcli,
  hasConnectedNetwork,
  parseSearchRequest,
} from "../runtime.mjs";

test("provider discovery waits for a usable network adapter", () => {
  assert.equal(hasConnectedNetwork({ adapters: [] }), false);
  assert.equal(
    hasConnectedNetwork({
      adapters: [{ name: "lo", type: "loopback", state: "connected" }],
    }),
    false,
  );
  assert.equal(
    hasConnectedNetwork({
      adapters: [{ name: "eth0", type: "ethernet", state: "disconnected" }],
    }),
    false,
  );
  assert.equal(
    hasConnectedNetwork({
      adapters: [{ name: "wlan0", type: "wifi", state: "connected" }],
    }),
    true,
  );
});

test("only systemd-managed credentials accept the protected 0440 mode", async () => {
  const dir = await fs.mkdtemp(
    path.join(os.tmpdir(), "kernaid-assistant-credential-test-"),
  );
  const keyFile = path.join(dir, "gemrouter.key");
  try {
    await fs.writeFile(keyFile, "synthetic-test-only\n", { mode: 0o440 });
    const ordinary = new AssistantRuntime({ stateDir: dir, keyFile });
    await assert.rejects(
      ordinary.initialize(),
      /Cannot load private assistant credential/,
    );
    const managed = new AssistantRuntime({
      stateDir: dir,
      keyFile,
      systemdCredential: true,
    });
    await managed.initialize();
    assert.equal(managed.status().credentialPresent, true);
    assert.ok(
      !JSON.stringify(managed.status()).includes("synthetic-test-only"),
    );
  } finally {
    await fs.rm(dir, { recursive: true });
  }
});

test("reject credential-bearing/insecure endpoints and preserve escaped Wi-Fi names", () => {
  for (const value of [
    "http://example.com",
    "https://key@example.com",
    "https://example.com?key=value",
    "file:///tmp/x",
  ])
    assert.throws(() => endpoint(value));
  assert.equal(endpoint("https://example.com/v1/"), "https://example.com/v1");
  assert.deepEqual(splitNmcli("Office\\: guest:80:WPA2"), [
    "Office: guest",
    "80",
    "WPA2",
  ]);
});

test("endpoint changes cannot forward the existing provider credential", async () => {
  const dir = await fs.mkdtemp(
    path.join(os.tmpdir(), "kernaid-assistant-test-"),
  );
  try {
    const runtime = new AssistantRuntime({ stateDir: dir, searchUrl: "" });
    await runtime.initialize();
    await runtime.configure({
      surface: "gemrouter",
      model: "test",
      apiKey: "synthetic-test-only",
    });
    assert.equal(runtime.status().credentialPresent, true);
    assert.ok(
      !JSON.stringify(runtime.status()).includes("synthetic-test-only"),
    );
    await runtime.configure({
      surface: "gemrouter",
      baseUrl: "https://another.example/v1",
      model: "test",
    });
    assert.equal(runtime.status().credentialPresent, false);
    await assert.rejects(runtime.models(), /Enter an API key/);
  } finally {
    await fs.rm(dir, { recursive: true });
  }
});

test("actual Pi session has only web_search, no shell or file tools", async () => {
  const dir = await fs.mkdtemp(
    path.join(os.tmpdir(), "kernaid-assistant-test-"),
  );
  let session;
  try {
    const runtime = new AssistantRuntime({ stateDir: dir });
    await runtime.initialize();
    await runtime.configure({
      surface: "openai",
      model: "test",
      apiKey: "synthetic-test-only",
    });
    session = await runtime.createSession();
    assert.deepEqual(
      session.agent.state.tools.map((tool) => tool.name),
      ["web_search"],
    );
    assert.ok(
      !JSON.stringify(await fs.readdir(dir)).includes("synthetic-test-only"),
    );
  } finally {
    session?.dispose();
    await fs.rm(dir, { recursive: true });
  }
});

test("switching providers cannot send a custom endpoint key to the default endpoint", async () => {
  const runtime = new AssistantRuntime({ stateDir: "/unused", searchUrl: "" });
  await runtime.configure({
    surface: "gemrouter",
    baseUrl: "https://custom.example/v1",
    model: "test",
    apiKey: "synthetic-custom-test-only",
  });
  await runtime.configure({ surface: "openai", model: "test" });
  await runtime.configure({ surface: "gemrouter", model: "test" });
  assert.equal(runtime.status().credentialPresent, false);
  await assert.rejects(runtime.models(), /Enter an API key/);
  await assert.rejects(runtime.createSession(), /enter its API key/);
});

test("Gemrouter text protocol accepts only the bounded search operation", () => {
  assert.equal(
    parseSearchRequest('{"web_search":"NetworkManager docs"}'),
    "NetworkManager docs",
  );
  for (const text of [
    '{"bash":"ls"}',
    '{"web_search":"ok","command":"ls"}',
    JSON.stringify({ web_search: "x".repeat(241) }),
    "```json\n{}\n```",
    "ordinary answer",
  ])
    assert.equal(parseSearchRequest(text), undefined);
});

test("model discovery is shared and cached, not repeated for model selection", async () => {
  const runtime = new AssistantRuntime({ stateDir: "/unused", searchUrl: "" });
  let requests = 0;
  let complete;
  runtime.fetchModels = async () => {
    requests++;
    return new Promise((resolve) => {
      complete = resolve;
    });
  };
  await runtime.configure({
    surface: "gemrouter",
    model: "test",
    apiKey: "synthetic-test-only",
  });
  runtime.startDiscovery();
  assert.equal(runtime.status().modelDiscovery.state, "loading");
  const pending = runtime.models({ refresh: true });
  assert.equal(requests, 1);
  complete({ data: [null, { id: "test" }, { id: 123 }] });
  assert.deepEqual(await pending, { models: ["test"] });
  await runtime.configure({ surface: "gemrouter", model: "another-model" });
  runtime.startDiscovery();
  assert.deepEqual(await runtime.models(), { models: ["test"] });
  assert.equal(requests, 1);
  assert.ok(!JSON.stringify(runtime.status()).includes("synthetic-test-only"));
  await runtime.configure({
    surface: "gemrouter",
    model: "test",
    apiKey: "synthetic-new-key",
  });
  assert.equal(runtime.status().modelDiscovery.state, "idle");
});

test("a late discovery response cannot populate a different endpoint", async () => {
  const runtime = new AssistantRuntime({ stateDir: "/unused", searchUrl: "" });
  let complete;
  runtime.fetchModels = async () =>
    new Promise((resolve) => {
      complete = resolve;
    });
  await runtime.configure({
    surface: "gemrouter",
    model: "test",
    apiKey: "synthetic-test-only",
  });
  const pending = runtime.models();
  await runtime.configure({
    surface: "custom",
    baseUrl: "https://different.example/v1",
    model: "test",
  });
  complete({ data: [{ id: "old-provider-model" }] });
  await pending;
  assert.deepEqual(runtime.status().modelDiscovery, {
    state: "idle",
    models: [],
  });
  assert.equal(runtime.status().credentialPresent, false);
});

test("Gemrouter request goes through bounded search and returns a final answer", async () => {
  const runtime = new AssistantRuntime({ stateDir: "/unused" });
  let prompts = 0;
  let searches = 0;
  const session = {
    messages: [],
    agent: { abort() {} },
    subscribe: () => () => {},
    dispose() {},
    async prompt(text) {
      prompts++;
      if (prompts === 2) assert.match(text, /https:\/\/www.networkmanager.dev/);
      session.messages.push({
        role: "assistant",
        stopReason: "stop",
        content: [
          {
            type: "text",
            text:
              prompts === 1
                ? '{"web_search":"NetworkManager documentation"}'
                : "See https://www.networkmanager.dev",
          },
        ],
      });
    },
  };
  runtime.session = session;
  runtime.search = async (query) => {
    searches++;
    assert.equal(query, "NetworkManager documentation");
    return [{ url: "https://www.networkmanager.dev" }];
  };
  const result = await runtime.chat("Find documentation");
  assert.equal(searches, 1);
  assert.equal(result.searches, 1);
  assert.equal(prompts, 2);
});

test("an unresponsive model cannot leave the wizard busy indefinitely", async () => {
  const runtime = new AssistantRuntime({ stateDir: "/unused", timeoutMs: 15 });
  let disposed = false;
  runtime.session = {
    agent: { abort() {} },
    subscribe: () => () => {},
    prompt: () => new Promise(() => {}),
    dispose() {
      disposed = true;
    },
  };
  await assert.rejects(runtime.chat("hello"), /Assistant timed out/);
  assert.equal(runtime.busy, false);
  assert.equal(runtime.session, undefined);
  assert.equal(disposed, true);
});

test("shared evidence uses a fresh one-question session and cannot leak into later chat", async () => {
  const runtime = new AssistantRuntime({ stateDir: "/unused", searchUrl: "" });
  let previousDisposed = false;
  let evidenceDisposed = false;
  let received;
  runtime.session = {
    dispose() {
      previousDisposed = true;
    },
  };
  const session = {
    messages: [],
    agent: { abort() {} },
    subscribe: () => () => {},
    dispose() {
      evidenceDisposed = true;
    },
    async prompt(text) {
      received = text;
      this.messages.push({
        role: "assistant",
        stopReason: "stop",
        content: [
          {
            type: "text",
            text: "Check the boot configuration; no repair executed.",
          },
        ],
      });
    },
  };
  runtime.createSession = async () => session;
  const result = await runtime.chat(
    "Explain these checks",
    linuxContext(),
    runtime.config,
  );
  assert.match(result.answer, /no repair/);
  assert.match(received, /untrusted observations/);
  assert.match(received, /"initramfsArtifactCount":0/);
  assert.equal(previousDisposed, true);
  assert.equal(evidenceDisposed, true);
  assert.equal(runtime.session, undefined);
});

test("context cannot be sent to a changed provider or with unreviewed free-form fields", async () => {
  const runtime = new AssistantRuntime({ stateDir: "/unused" });
  runtime.createSession = async () => {
    throw new Error("must not send");
  };
  for (const expected of [
    undefined,
    { ...runtime.config, model: "different-model" },
    { ...runtime.config, baseUrl: "https://different.example" },
  ])
    await assert.rejects(
      runtime.chat("Explain", linuxContext(), expected),
      /provider changed/,
    );
  await assert.rejects(
    runtime.chat(
      "Explain",
      { ...linuxContext(), token: "synthetic-secret" },
      runtime.config,
    ),
    /Invalid diagnostic summary/,
  );
  assert.equal(runtime.busy, false);
});

test("retarget conversation epochs discard ordinary chat history without sending identifiers", async () => {
  const runtime = new AssistantRuntime({ stateDir: "/unused", searchUrl: "" });
  const sessions = [];
  runtime.createSession = async () => {
    const session = {
      messages: [],
      prompts: [],
      disposed: false,
      agent: { abort() {} },
      subscribe: () => () => {},
      dispose() {
        this.disposed = true;
      },
      async prompt(text) {
        this.prompts.push(text);
        this.messages.push({
          role: "assistant",
          stopReason: "stop",
          content: [{ type: "text", text: "Advice only" }],
        });
      },
    };
    sessions.push(session);
    return session;
  };
  const first = "12345678-1234-4123-8123-123456789abc";
  const second = "12345678-1234-4123-8123-123456789def";
  await runtime.chat("Machine A", undefined, undefined, first);
  await runtime.chat("Another A question", undefined, undefined, first);
  assert.equal(sessions.length, 1);
  await runtime.chat("Machine B", undefined, undefined, second);
  assert.equal(sessions.length, 2);
  assert.equal(sessions[0].disposed, true);
  assert.deepEqual(sessions[1].prompts, ["Machine B"]);
  assert.ok(!JSON.stringify(sessions).includes(first));
  assert.ok(!JSON.stringify(sessions).includes(second));
  await assert.rejects(
    runtime.chat("hi", undefined, undefined, "hostname-private"),
    /Invalid conversation/,
  );
});
