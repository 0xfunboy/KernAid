import type { Provider, ProviderSecretSupplier } from "@kernaid/provider-types";
import { OfflineRulesProvider } from "./fake-provider.js";
import {
  OpenAICompatibleProvider,
  OpenAIResponsesProvider,
  type OpenAICompatibleProviderOptions,
  type OpenAIResponsesProviderOptions,
} from "./openai-provider.js";
import {
  AnthropicMessagesProvider,
  GeminiInteractionsProvider,
  type AnthropicMessagesProviderOptions,
  type GeminiInteractionsProviderOptions,
} from "./structured-api-provider.js";

/** Explicit product modes. Selection never falls back to another entry. */
export const PROVIDER_MODES = [
  "offline",
  "openai_api",
  "openai_compatible",
  "anthropic_api",
  "gemini_api",
  "enterprise",
] as const;

/** Canonical ordering required by a verified Fleet policy bundle. */
export const FLEET_PROVIDER_MODE_ORDER = [
  "anthropic_api",
  "enterprise",
  "gemini_api",
  "offline",
  "openai_api",
  "openai_compatible",
] as const satisfies readonly ProviderMode[];

export type ProviderMode = (typeof PROVIDER_MODES)[number];

type OpenAIRegistrationOptions = Readonly<
  Omit<OpenAIResponsesProviderOptions, "apiKey">
>;
type OpenAICompatibleRegistrationOptions = Readonly<
  Omit<OpenAICompatibleProviderOptions, "apiKey">
>;
type AnthropicRegistrationOptions = Readonly<
  Omit<AnthropicMessagesProviderOptions, "apiKey" | "fetcher">
>;
type GeminiRegistrationOptions = Readonly<
  Omit<GeminiInteractionsProviderOptions, "apiKey" | "fetcher">
>;

export interface OfflineProviderRegistration {
  readonly mode: "offline";
}

export interface OpenAIProviderRegistration {
  readonly mode: "openai_api";
  /** Static endpoint/model/limit configuration. Credentials are not accepted. */
  readonly options: OpenAIRegistrationOptions;
}

export interface OpenAICompatibleProviderRegistration {
  readonly mode: "openai_compatible";
  readonly authentication: "none" | "runtime-secret";
  /** Static endpoint/model/limit configuration. Credentials are not accepted. */
  readonly options: OpenAICompatibleRegistrationOptions;
}

export interface AnthropicProviderRegistration {
  readonly mode: "anthropic_api";
  /** Static endpoint/model/limit configuration. Credentials are not accepted. */
  readonly options: AnthropicRegistrationOptions;
}

export interface GeminiProviderRegistration {
  readonly mode: "gemini_api";
  /** Static endpoint/model/limit configuration. Credentials are not accepted. */
  readonly options: GeminiRegistrationOptions;
}

export interface EnterpriseProviderFactoryContext {
  readonly mode: "enterprise";
  /** Supplied only at selection time when authentication is runtime-secret. */
  readonly secretSupplier?: ProviderSecretSupplier;
}

export type EnterpriseProviderFactory = (
  context: Readonly<EnterpriseProviderFactoryContext>,
) => Provider;

export interface EnterpriseProviderRegistration {
  readonly mode: "enterprise";
  readonly authentication: "none" | "runtime-secret";
  /**
   * The factory must preserve the Provider boundary and defer secret reads to
   * diagnose(). A provider advertising tool requests is rejected.
   */
  readonly createProvider: EnterpriseProviderFactory;
}

export type ProviderRegistration =
  | OfflineProviderRegistration
  | OpenAIProviderRegistration
  | OpenAICompatibleProviderRegistration
  | AnthropicProviderRegistration
  | GeminiProviderRegistration
  | EnterpriseProviderRegistration;

export interface ProviderSelection<M extends ProviderMode = ProviderMode> {
  readonly mode: M;
  /** Exact providerModes from an already verified Fleet policy bundle. */
  readonly fleetAllowedModes: readonly ProviderMode[];
  /** Runtime callback only; never put the returned credential in configuration. */
  readonly secretSupplier?: ProviderSecretSupplier;
}

export interface SelectedProvider<M extends ProviderMode = ProviderMode> {
  readonly mode: M;
  readonly provider: Provider;
}

export type ProviderRegistryErrorCode =
  | "invalid_registry"
  | "invalid_fleet_policy"
  | "invalid_selection"
  | "mode_not_allowed"
  | "mode_not_configured"
  | "runtime_secret_required"
  | "runtime_secret_unexpected"
  | "provider_creation_failed"
  | "unsafe_provider";

const ERROR_MESSAGES: Readonly<Record<ProviderRegistryErrorCode, string>> =
  Object.freeze({
    invalid_registry: "Provider registry configuration is invalid",
    invalid_fleet_policy: "Fleet provider policy is invalid",
    invalid_selection: "Provider selection is invalid",
    mode_not_allowed: "Provider mode is not allowed by Fleet policy",
    mode_not_configured: "Provider mode is not locally configured",
    runtime_secret_required: "Runtime provider credential is required",
    runtime_secret_unexpected: "Runtime provider credential is not accepted",
    provider_creation_failed: "Provider could not be created",
    unsafe_provider: "Provider violates the tool-free boundary",
  });

export class ProviderRegistryError extends Error {
  readonly code: ProviderRegistryErrorCode;

  constructor(code: ProviderRegistryErrorCode) {
    super(ERROR_MESSAGES[code]);
    this.name = "ProviderRegistryError";
    this.code = code;
  }
}

type CompiledProviderFactory = (
  supplier: ProviderSecretSupplier | undefined,
) => Provider;

const MODE_SET: ReadonlySet<string> = new Set(PROVIDER_MODES);
const FLEET_MODE_INDEX: ReadonlyMap<ProviderMode, number> = new Map(
  FLEET_PROVIDER_MODE_ORDER.map((mode, index) => [mode, index]),
);

/**
 * Local provider registry intersected with a verified Fleet allowlist.
 * Missing, denied and malformed selections fail closed without an offline
 * fallback.
 */
export class ProviderRegistry {
  readonly #factories = new Map<ProviderMode, CompiledProviderFactory>();

  constructor(registrations: readonly ProviderRegistration[]) {
    if (
      !Array.isArray(registrations) ||
      registrations.length === 0 ||
      registrations.length > PROVIDER_MODES.length
    )
      throw new ProviderRegistryError("invalid_registry");

    for (const registration of registrations as readonly unknown[]) {
      const [mode, factory] = compileRegistration(registration);
      if (this.#factories.has(mode))
        throw new ProviderRegistryError("invalid_registry");
      this.#factories.set(mode, factory);
    }
  }

  get locallyConfiguredModes(): readonly ProviderMode[] {
    return Object.freeze(
      PROVIDER_MODES.filter((mode) => this.#factories.has(mode)),
    );
  }

  allowedModes(
    fleetAllowedModes: readonly ProviderMode[],
  ): readonly ProviderMode[] {
    const fleet = validatedFleetModes(fleetAllowedModes);
    return Object.freeze(
      PROVIDER_MODES.filter(
        (mode) => this.#factories.has(mode) && fleet.has(mode),
      ),
    );
  }

  create<M extends ProviderMode>(
    selection: ProviderSelection<M>,
  ): SelectedProvider<M> {
    const object = exactObject(
      selection,
      ["mode", "fleetAllowedModes", "secretSupplier"],
      "invalid_selection",
    );
    if (!isProviderMode(object.mode))
      throw new ProviderRegistryError("invalid_selection");
    const mode = object.mode;
    const fleet = validatedFleetModes(object.fleetAllowedModes);
    if (!fleet.has(mode)) throw new ProviderRegistryError("mode_not_allowed");
    const factory = this.#factories.get(mode);
    if (factory === undefined)
      throw new ProviderRegistryError("mode_not_configured");
    const supplier = object.secretSupplier;
    if (supplier !== undefined && typeof supplier !== "function")
      throw new ProviderRegistryError("invalid_selection");

    try {
      const provider = factory(supplier as ProviderSecretSupplier | undefined);
      assertToolFreeProvider(provider);
      return Object.freeze({ mode: mode as M, provider });
    } catch (error) {
      if (error instanceof ProviderRegistryError) throw error;
      // Do not retain or surface configuration, factory or credential details.
      throw new ProviderRegistryError("provider_creation_failed");
    }
  }
}

export function createProviderRegistry(
  registrations: readonly ProviderRegistration[],
): ProviderRegistry {
  return new ProviderRegistry(registrations);
}

export function isProviderMode(value: unknown): value is ProviderMode {
  return typeof value === "string" && MODE_SET.has(value);
}

function compileRegistration(
  registration: unknown,
): readonly [ProviderMode, CompiledProviderFactory] {
  const object = objectValue(registration, "invalid_registry");
  if (!isProviderMode(object.mode))
    throw new ProviderRegistryError("invalid_registry");

  switch (object.mode) {
    case "offline": {
      exactKeys(object, ["mode"], "invalid_registry");
      return [
        object.mode,
        (supplier) => {
          rejectSupplier(supplier);
          return new OfflineRulesProvider();
        },
      ];
    }
    case "openai_api": {
      exactKeys(object, ["mode", "options"], "invalid_registry");
      const options = copiedOptions<OpenAIRegistrationOptions>(object.options, [
        "baseUrl",
        "allowInsecureLoopback",
        "timeoutMs",
        "maxRequestBytes",
        "maxResponseBytes",
        "maxOutputTokens",
        "model",
      ]);
      return [
        object.mode,
        (supplier) =>
          new OpenAIResponsesProvider({
            ...options,
            apiKey: requireSupplier(supplier),
          }),
      ];
    }
    case "openai_compatible": {
      exactKeys(
        object,
        ["mode", "authentication", "options"],
        "invalid_registry",
      );
      const authentication = validAuthentication(object.authentication);
      const options = copiedOptions<OpenAICompatibleRegistrationOptions>(
        object.options,
        [
          "baseUrl",
          "allowInsecureLoopback",
          "timeoutMs",
          "maxRequestBytes",
          "maxResponseBytes",
          "maxOutputTokens",
          "model",
          "local",
          "responseFormat",
        ],
      );
      return [
        object.mode,
        (supplier) =>
          new OpenAICompatibleProvider({
            ...options,
            apiKey: supplierForAuthentication(authentication, supplier),
          }),
      ];
    }
    case "anthropic_api": {
      exactKeys(object, ["mode", "options"], "invalid_registry");
      const options = copiedOptions<AnthropicRegistrationOptions>(
        object.options,
        [
          "baseUrl",
          "timeoutMs",
          "maxRequestBytes",
          "maxResponseBytes",
          "maxOutputTokens",
          "model",
        ],
      );
      return [
        object.mode,
        (supplier) =>
          new AnthropicMessagesProvider({
            ...options,
            apiKey: requireSupplier(supplier),
          }),
      ];
    }
    case "gemini_api": {
      exactKeys(object, ["mode", "options"], "invalid_registry");
      const options = copiedOptions<GeminiRegistrationOptions>(object.options, [
        "baseUrl",
        "timeoutMs",
        "maxRequestBytes",
        "maxResponseBytes",
        "maxOutputTokens",
        "model",
      ]);
      return [
        object.mode,
        (supplier) =>
          new GeminiInteractionsProvider({
            ...options,
            apiKey: requireSupplier(supplier),
          }),
      ];
    }
    case "enterprise": {
      exactKeys(
        object,
        ["mode", "authentication", "createProvider"],
        "invalid_registry",
      );
      const authentication = validAuthentication(object.authentication);
      if (typeof object.createProvider !== "function")
        throw new ProviderRegistryError("invalid_registry");
      const createProvider = object.createProvider as EnterpriseProviderFactory;
      return [
        object.mode,
        (supplier) =>
          createProvider(
            Object.freeze({
              mode: "enterprise",
              secretSupplier: supplierForAuthentication(
                authentication,
                supplier,
              ),
            }),
          ),
      ];
    }
  }
}

function copiedOptions<T extends object>(
  value: unknown,
  allowedKeys: readonly string[],
): T {
  const object = exactObject(value, allowedKeys, "invalid_registry");
  const copy: Record<string, unknown> = { ...object };
  if (copy.baseUrl instanceof URL) copy.baseUrl = new URL(copy.baseUrl.href);
  if (
    copy.allowInsecureLoopback !== undefined &&
    typeof copy.allowInsecureLoopback !== "boolean"
  )
    throw new ProviderRegistryError("invalid_registry");
  if (copy.local !== undefined && typeof copy.local !== "boolean")
    throw new ProviderRegistryError("invalid_registry");
  if (
    copy.responseFormat !== undefined &&
    copy.responseFormat !== "json-schema" &&
    copy.responseFormat !== "json-object"
  )
    throw new ProviderRegistryError("invalid_registry");
  return Object.freeze(copy) as T;
}

function validatedFleetModes(value: unknown): ReadonlySet<ProviderMode> {
  if (
    !Array.isArray(value) ||
    value.length === 0 ||
    value.length > PROVIDER_MODES.length
  )
    throw new ProviderRegistryError("invalid_fleet_policy");
  const modes: ProviderMode[] = [];
  let previousIndex = -1;
  for (const item of value) {
    if (!isProviderMode(item))
      throw new ProviderRegistryError("invalid_fleet_policy");
    const index = FLEET_MODE_INDEX.get(item);
    if (index === undefined || index <= previousIndex)
      throw new ProviderRegistryError("invalid_fleet_policy");
    modes.push(item);
    previousIndex = index;
  }
  return new Set(modes);
}

function validAuthentication(value: unknown): "none" | "runtime-secret" {
  if (value !== "none" && value !== "runtime-secret")
    throw new ProviderRegistryError("invalid_registry");
  return value;
}

function requireSupplier(
  supplier: ProviderSecretSupplier | undefined,
): ProviderSecretSupplier {
  if (typeof supplier !== "function")
    throw new ProviderRegistryError("runtime_secret_required");
  return supplier;
}

function rejectSupplier(supplier: ProviderSecretSupplier | undefined): void {
  if (supplier !== undefined)
    throw new ProviderRegistryError("runtime_secret_unexpected");
}

function supplierForAuthentication(
  authentication: "none" | "runtime-secret",
  supplier: ProviderSecretSupplier | undefined,
): ProviderSecretSupplier | undefined {
  if (authentication === "runtime-secret") return requireSupplier(supplier);
  rejectSupplier(supplier);
  return undefined;
}

function assertToolFreeProvider(provider: Provider): void {
  if (
    typeof provider !== "object" ||
    provider === null ||
    typeof provider.diagnose !== "function" ||
    typeof provider.capabilities !== "object" ||
    provider.capabilities === null ||
    provider.capabilities.structuredOutput !== true ||
    provider.capabilities.toolRequests !== false
  )
    throw new ProviderRegistryError("unsafe_provider");
}

function exactObject(
  value: unknown,
  allowedKeys: readonly string[],
  code: "invalid_registry" | "invalid_selection",
): Record<string, unknown> {
  const object = objectValue(value, code);
  exactKeys(object, allowedKeys, code);
  return object;
}

function exactKeys(
  object: Readonly<Record<string, unknown>>,
  allowedKeys: readonly string[],
  code: "invalid_registry" | "invalid_selection",
): void {
  const allowed = new Set(allowedKeys);
  if (Object.keys(object).some((key) => !allowed.has(key)))
    throw new ProviderRegistryError(code);
}

function objectValue(
  value: unknown,
  code: "invalid_registry" | "invalid_selection",
): Record<string, unknown> {
  if (typeof value !== "object" || value === null || Array.isArray(value))
    throw new ProviderRegistryError(code);
  return value as Record<string, unknown>;
}
