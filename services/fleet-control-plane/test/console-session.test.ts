import assert from "node:assert/strict";
import { test } from "node:test";
import {
  CONSOLE_SESSION_COOKIE,
  ConsoleSessionRegistry,
  consoleSessionId,
} from "../src/console-session.js";

test("console mutation CSRF and rate state stay bounded per memory session", () => {
  const registry = new ConsoleSessionRegistry(60_000);
  const session = registry.create({
    tenantId: "tenant-test",
    credentialId: "credential-test",
    role: "operator",
    nowMs: 1_000_000,
  });
  assert.equal(
    registry.authorizeMutation(session, "x".repeat(43), 1_000_000),
    "csrf",
  );
  for (let mutation = 0; mutation < 180; mutation += 1) {
    assert.equal(
      registry.authorizeMutation(session, session.csrfToken, 1_000_000),
      "allowed",
    );
  }
  assert.equal(
    registry.authorizeMutation(session, session.csrfToken, 1_000_000),
    "rate_limited",
  );
  assert.equal(
    registry.authorizeMutation(session, session.csrfToken, 1_060_000),
    "allowed",
  );
});

test("console cookie parsing rejects ambiguity", () => {
  const value = "A".repeat(43);
  assert.equal(
    consoleSessionId(`${CONSOLE_SESSION_COOKIE}=${value}; theme=dark`),
    value,
  );
  assert.equal(
    consoleSessionId(
      `${CONSOLE_SESSION_COOKIE}=${value}; ${CONSOLE_SESSION_COOKIE}=${value}`,
    ),
    undefined,
  );
});
