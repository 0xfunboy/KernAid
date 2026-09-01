import assert from "node:assert/strict";
import test from "node:test";
import type { Provider } from "@kernaid/provider-types";
import { OfflineRulesProvider } from "../src/fake-provider.js";
import {
  OpenAICompatibleProvider,
  OpenAIResponsesProvider,
} from "../src/openai-provider.js";
import {
  FLEET_PROVIDER_MODE_ORDER,
  ProviderRegistry,
  ProviderRegistryError,
  type ProviderMode,
  type ProviderRegistration,
} from "../src/provider-registry.js";
import {
  AnthropicMessagesProvider,
  GeminiInteractionsProvider,
} from "../src/structured-api-provider.js";

const allFleetModes = [...FLEET_PROVIDER_MODE_ORDER];

function errorCode(
  code: ProviderRegistryError["code"],
): (error: unknown) => boolean {
  return (error) =>
    error instanceof ProviderRegistryError && error.code === code;
}

function allModeRegistry(
  onEnterprise = (): void => undefined,
): ProviderRegistry {
  return new ProviderRegistry([
    { mode: "offline" },
    { mode: "openai_api", options: { model: "gpt-registry-test" } },
    {
      mode: "openai_compatible",
      authentication: "none",
      options: {
        baseUrl: "http://127.0.0.1:11434/v1/",
        allowInsecureLoopback: true,
        local: true,
        model: "local-registry-test",
      },
    },
    {
      mode: "anthropic_api",
      options: { model: "claude-registry-test" },
    },
    {
      mode: "gemini_api",
      options: { model: "gemini-registry-test" },
    },
    {
      mode: "enterprise",
      authentication: "none",
      createProvider: () => {
        onEnterprise();
        return new OfflineRulesProvider();
      },
    },
  ]);
}

test("selects every explicit mode without fallback and preserves its type", () => {
  let secretReads = 0;
  const runtimeSecret = (): string => {
    secretReads += 1;
    return "runtime-only-provider-secret";
  };
  const registry = allModeRegistry();

  assert.deepEqual(registry.locallyConfiguredModes, [
    "offline",
    "openai_api",
    "openai_compatible",
    "anthropic_api",
    "gemini_api",
    "enterprise",
  ]);
  assert.deepEqual(registry.allowedModes(["anthropic_api", "offline"]), [
    "offline",
    "anthropic_api",
  ]);

  const offline = registry.create({
    mode: "offline",
    fleetAllowedModes: allFleetModes,
  });
  const openai = registry.create({
    mode: "openai_api",
    fleetAllowedModes: allFleetModes,
    secretSupplier: runtimeSecret,
  });
  const compatible = registry.create({
    mode: "openai_compatible",
    fleetAllowedModes: allFleetModes,
  });
  const anthropic = registry.create({
    mode: "anthropic_api",
    fleetAllowedModes: allFleetModes,
    secretSupplier: runtimeSecret,
  });
  const gemini = registry.create({
    mode: "gemini_api",
    fleetAllowedModes: allFleetModes,
    secretSupplier: runtimeSecret,
  });
  const enterprise = registry.create({
    mode: "enterprise",
    fleetAllowedModes: allFleetModes,
  });

  assert.equal(offline.mode, "offline");
  assert.ok(offline.provider instanceof OfflineRulesProvider);
  assert.ok(openai.provider instanceof OpenAIResponsesProvider);
  assert.ok(compatible.provider instanceof OpenAICompatibleProvider);
  assert.ok(anthropic.provider instanceof AnthropicMessagesProvider);
  assert.ok(gemini.provider instanceof GeminiInteractionsProvider);
  assert.ok(enterprise.provider instanceof OfflineRulesProvider);
  for (const selected of [
    offline,
    openai,
    compatible,
    anthropic,
    gemini,
    enterprise,
  ])
    assert.equal(selected.provider.capabilities.toolRequests, false);
  assert.equal(secretReads, 0, "selection must not resolve runtime secrets");
});

test("intersects local registration with canonical Fleet policy fail closed", () => {
  let enterpriseFactoryCalls = 0;
  const registry = allModeRegistry(() => {
    enterpriseFactoryCalls += 1;
  });

  assert.throws(
    () =>
      registry.create({
        mode: "enterprise",
        fleetAllowedModes: ["offline"],
      }),
    errorCode("mode_not_allowed"),
  );
  assert.equal(enterpriseFactoryCalls, 0);

  const offlineOnly = new ProviderRegistry([{ mode: "offline" }]);
  assert.throws(
    () =>
      offlineOnly.create({
        mode: "gemini_api",
        fleetAllowedModes: ["gemini_api"],
        secretSupplier: () => "runtime-only",
      }),
    errorCode("mode_not_configured"),
  );
  assert.throws(
    () => registry.allowedModes(["offline", "anthropic_api"]),
    errorCode("invalid_fleet_policy"),
  );
  assert.throws(
    () => registry.allowedModes(["offline", "offline"]),
    errorCode("invalid_fleet_policy"),
  );
  assert.throws(
    () =>
      registry.create({
        mode: "other" as ProviderMode,
        fleetAllowedModes: allFleetModes,
      }),
    errorCode("invalid_selection"),
  );
});

test("accepts credentials only as runtime suppliers for authenticated modes", () => {
  const registry = new ProviderRegistry([
    { mode: "offline" },
    { mode: "anthropic_api", options: { model: "claude-runtime" } },
    {
      mode: "openai_compatible",
      authentication: "runtime-secret",
      options: {
        baseUrl: "https://compatible.example/v1/",
        model: "compatible-runtime",
      },
    },
  ]);

  assert.throws(
    () =>
      registry.create({
        mode: "anthropic_api",
        fleetAllowedModes: ["anthropic_api"],
      }),
    errorCode("runtime_secret_required"),
  );
  assert.throws(
    () =>
      registry.create({
        mode: "openai_compatible",
        fleetAllowedModes: ["openai_compatible"],
      }),
    errorCode("runtime_secret_required"),
  );
  assert.throws(
    () =>
      registry.create({
        mode: "offline",
        fleetAllowedModes: ["offline"],
        secretSupplier: () => "must-not-be-read",
      }),
    errorCode("runtime_secret_unexpected"),
  );

  let reads = 0;
  registry.create({
    mode: "openai_compatible",
    fleetAllowedModes: ["openai_compatible"],
    secretSupplier: () => {
      reads += 1;
      return "runtime-only";
    },
  });
  assert.equal(reads, 0);

  const staticCanary = "static-secret-must-not-survive";
  const invalid = {
    mode: "anthropic_api",
    options: { model: "claude-runtime", apiKey: staticCanary },
  } as unknown as ProviderRegistration;
  assert.throws(
    () => new ProviderRegistry([invalid]),
    (error: unknown) =>
      errorCode("invalid_registry")(error) &&
      !String(error).includes(staticCanary),
  );
});

test("rejects tool-capable enterprise providers and sanitizes factory errors", () => {
  const toolProvider: Provider = {
    capabilities: {
      streaming: false,
      structuredOutput: true,
      toolRequests: true,
      local: false,
    },
    async diagnose() {
      throw new Error("must not run");
    },
  };
  const unsafe = new ProviderRegistry([
    {
      mode: "enterprise",
      authentication: "none",
      createProvider: () => toolProvider,
    },
  ]);
  assert.throws(
    () =>
      unsafe.create({
        mode: "enterprise",
        fleetAllowedModes: ["enterprise"],
      }),
    errorCode("unsafe_provider"),
  );

  const canary = "factory-private-detail";
  const failing = new ProviderRegistry([
    {
      mode: "enterprise",
      authentication: "none",
      createProvider: () => {
        throw new Error(canary);
      },
    },
  ]);
  assert.throws(
    () =>
      failing.create({
        mode: "enterprise",
        fleetAllowedModes: ["enterprise"],
      }),
    (error: unknown) =>
      errorCode("provider_creation_failed")(error) &&
      !String(error).includes(canary),
  );
});
