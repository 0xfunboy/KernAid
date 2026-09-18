import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import {
  AssistantRuntime,
  endpoint,
  splitNmcli,
  parseSearchRequest,
} from "../runtime.mjs";

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
  await assert.rejects(runtime.chat("hello"), /Assistant unavailable/);
  assert.equal(runtime.busy, false);
  assert.equal(runtime.session, undefined);
  assert.equal(disposed, true);
});
