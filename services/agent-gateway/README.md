# Agent Gateway

Agent Gateway exposes diagnosis-only providers behind the common `Provider`
interface. Providers receive bounded, redacted evidence and return a validated
structured diagnosis proposal. They do not receive tools or broker access.

## Provider registry

`ProviderRegistry` makes provider choice explicit across these modes:
`offline`, `openai_api`, `openai_compatible`, `anthropic_api`, `gemini_api` and
`enterprise`. Local registrations are intersected with the exact canonical
`rules.providerModes` array from an already verified Fleet policy bundle. A
missing, malformed, unconfigured or Fleet-denied mode fails closed; the
registry never falls back to `offline` or another provider.

Static registration accepts endpoint, model and bounded transport settings,
but no API key or token. `openai_api`, `anthropic_api` and `gemini_api` require a
`secretSupplier` only when `create()` is called. `openai_compatible` and a
custom `enterprise` factory must explicitly declare either `none` or
`runtime-secret` authentication. Selection does not invoke the supplier; the
provider resolves it only for the request. Do not log supplier results or
capture credentials in a custom enterprise factory.

```ts
const registry = new ProviderRegistry([
  { mode: "offline" },
  { mode: "anthropic_api", options: { model: "configured-model" } },
  { mode: "gemini_api", options: { model: "configured-model" } },
]);

const selected = registry.create({
  mode: "anthropic_api",
  fleetAllowedModes: verifiedPolicy.rules.providerModes,
  secretSupplier: runtimeSecretSupplier,
});
```

An `offline` selection omits `secretSupplier`. Instantiate direct remote
adapters only in a trusted runtime. A Desk WebView must use a fixed native
provider proxy; it must never receive a supplier that returns the credential.

The `enterprise` extension point is rejected if its provider advertises tool
requests or lacks structured output. The registry does not wire modes into a
Desk/WebView selector and does not read a native credential store; those remain
separate product integration boundaries.
