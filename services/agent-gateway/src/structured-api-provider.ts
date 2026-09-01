import {
  ProviderError,
  type ObservedEvidence,
  type Provider,
  type ProviderCapabilities,
  type ProviderRequestOptions,
  type ProviderSecretSupplier,
} from "@kernaid/provider-types";
import type { DiagnosisProposal } from "@kernaid/schemas";
import {
  PROVIDER_DIAGNOSIS_INSTRUCTIONS,
  PROVIDER_DIAGNOSIS_SCHEMA,
  safeDiagnosisInput,
  validatedProposal,
} from "./openai-provider.js";

const ANTHROPIC_BASE_URL = "https://api.anthropic.com/v1/";
const GEMINI_BASE_URL = "https://generativelanguage.googleapis.com/v1beta/";
const DEFAULT_TIMEOUT_MS = 30_000;
const DEFAULT_MAX_REQUEST_BYTES = 512 * 1024;
const DEFAULT_MAX_RESPONSE_BYTES = 256 * 1024;
const DEFAULT_MAX_OUTPUT_TOKENS = 2_048;
const MAX_CONFIGURED_BYTES = 16 * 1024 * 1024;
const MAX_TIMEOUT_MS = 5 * 60_000;
const ANTHROPIC_VERSION = "2023-06-01";

type FetchLike = (
  input: string | URL | Request,
  init?: RequestInit,
) => Promise<Response>;

interface StructuredTransportOptions {
  baseUrl?: string | URL;
  timeoutMs?: number;
  maxRequestBytes?: number;
  maxResponseBytes?: number;
  maxOutputTokens?: number;
  /** Test/embedding seam. It must retain redirect and TLS policy. */
  fetcher?: FetchLike;
}

export interface AnthropicMessagesProviderOptions extends StructuredTransportOptions {
  apiKey: ProviderSecretSupplier;
  model: string;
}

export interface GeminiInteractionsProviderOptions extends StructuredTransportOptions {
  apiKey: ProviderSecretSupplier;
  model: string;
}

interface ResolvedRequest {
  endpoint: URL;
  timeoutMs: number;
  maxRequestBytes: number;
  maxResponseBytes: number;
  maxOutputTokens: number;
  apiKey: ProviderSecretSupplier;
  fetcher: FetchLike;
  headers(secret: string): Record<string, string>;
}

const REMOTE_STRUCTURED_CAPABILITIES: Readonly<ProviderCapabilities> =
  Object.freeze({
    streaming: false,
    structuredOutput: true,
    toolRequests: false,
    local: false,
  });

/** Direct Claude Messages adapter. It never supplies tools or execution APIs. */
export class AnthropicMessagesProvider implements Provider {
  readonly capabilities = REMOTE_STRUCTURED_CAPABILITIES;

  readonly #model: string;
  readonly #request: ResolvedRequest;

  constructor(options: AnthropicMessagesProviderOptions) {
    this.#model = validModel(options.model);
    this.#request = resolveRequest(
      options,
      "messages",
      ANTHROPIC_BASE_URL,
      options.apiKey,
      (secret) => ({
        "x-api-key": secret,
        "anthropic-version": ANTHROPIC_VERSION,
      }),
    );
  }

  async diagnose(
    objective: string,
    evidence: readonly ObservedEvidence[],
    options: ProviderRequestOptions = {},
  ): Promise<DiagnosisProposal> {
    const context = await safeDiagnosisInput(objective, evidence);
    const envelope = await postStructuredJson(
      this.#request,
      {
        model: this.#model,
        max_tokens: this.#request.maxOutputTokens,
        stream: false,
        system: PROVIDER_DIAGNOSIS_INSTRUCTIONS,
        messages: [{ role: "user", content: JSON.stringify(context.input) }],
        output_config: {
          format: {
            type: "json_schema",
            schema: PROVIDER_DIAGNOSIS_SCHEMA,
          },
        },
      },
      options.signal,
    );
    return validatedProposal(
      extractAnthropicMessageText(envelope),
      context.evidenceIds,
    );
  }
}

/** Direct Gemini Interactions adapter with a JSON-only final response. */
export class GeminiInteractionsProvider implements Provider {
  readonly capabilities = REMOTE_STRUCTURED_CAPABILITIES;

  readonly #model: string;
  readonly #request: ResolvedRequest;

  constructor(options: GeminiInteractionsProviderOptions) {
    this.#model = validModel(options.model);
    this.#request = resolveRequest(
      options,
      "interactions",
      GEMINI_BASE_URL,
      options.apiKey,
      (secret) => ({ "x-goog-api-key": secret }),
    );
  }

  async diagnose(
    objective: string,
    evidence: readonly ObservedEvidence[],
    options: ProviderRequestOptions = {},
  ): Promise<DiagnosisProposal> {
    const context = await safeDiagnosisInput(objective, evidence);
    const envelope = await postStructuredJson(
      this.#request,
      {
        model: this.#model,
        input: JSON.stringify({
          instructions: PROVIDER_DIAGNOSIS_INSTRUCTIONS,
          ...context.input,
        }),
        response_format: {
          type: "text",
          mime_type: "application/json",
          schema: PROVIDER_DIAGNOSIS_SCHEMA,
        },
      },
      options.signal,
    );
    return validatedProposal(
      extractGeminiInteractionText(envelope),
      context.evidenceIds,
    );
  }
}

function resolveRequest(
  options: StructuredTransportOptions,
  endpointPath: string,
  defaultBaseUrl: string,
  apiKey: ProviderSecretSupplier,
  vendorHeaders: (secret: string) => Record<string, string>,
): ResolvedRequest {
  let base: URL;
  try {
    base = new URL(options.baseUrl ?? defaultBaseUrl);
  } catch {
    throw configurationError("Provider base URL is invalid");
  }
  if (
    base.protocol !== "https:" ||
    base.username ||
    base.password ||
    base.search ||
    base.hash
  )
    throw configurationError("Provider base URL must be credential-free HTTPS");
  if (!base.pathname.endsWith("/")) base.pathname += "/";
  return {
    endpoint: new URL(endpointPath, base),
    timeoutMs: boundedInteger(
      options.timeoutMs,
      DEFAULT_TIMEOUT_MS,
      1,
      MAX_TIMEOUT_MS,
      "timeout",
    ),
    maxRequestBytes: boundedInteger(
      options.maxRequestBytes,
      DEFAULT_MAX_REQUEST_BYTES,
      1,
      MAX_CONFIGURED_BYTES,
      "request limit",
    ),
    maxResponseBytes: boundedInteger(
      options.maxResponseBytes,
      DEFAULT_MAX_RESPONSE_BYTES,
      1,
      MAX_CONFIGURED_BYTES,
      "response limit",
    ),
    maxOutputTokens: boundedInteger(
      options.maxOutputTokens,
      DEFAULT_MAX_OUTPUT_TOKENS,
      1,
      128 * 1024,
      "output token limit",
    ),
    apiKey,
    fetcher: options.fetcher ?? fetch,
    headers: vendorHeaders,
  };
}

async function postStructuredJson(
  request: ResolvedRequest,
  payload: object,
  callerSignal?: AbortSignal,
): Promise<unknown> {
  let body: string;
  try {
    body = JSON.stringify(payload);
  } catch {
    throw new ProviderError("invalid_request", "Provider input is invalid");
  }
  if (byteLength(body) > request.maxRequestBytes)
    throw new ProviderError(
      "request_too_large",
      "Provider request exceeds the configured limit",
    );
  if (callerSignal?.aborted)
    throw new ProviderError("cancelled", "Provider request was cancelled");

  const controller = new AbortController();
  let timedOut = false;
  const onCallerAbort = (): void => controller.abort();
  callerSignal?.addEventListener("abort", onCallerAbort, { once: true });
  const timer = setTimeout(() => {
    timedOut = true;
    controller.abort();
  }, request.timeoutMs);

  try {
    let secret: string;
    try {
      secret = await resolveSecret(request.apiKey, controller.signal);
    } catch (error) {
      if (error instanceof RequestAborted)
        throw abortOrTransport(timedOut, callerSignal);
      throw error;
    }
    const response = await request
      .fetcher(request.endpoint, {
        method: "POST",
        headers: {
          Accept: "application/json",
          "Content-Type": "application/json",
          ...request.headers(secret),
        },
        body,
        signal: controller.signal,
        redirect: "error",
      })
      .catch(() => {
        throw abortOrTransport(timedOut, callerSignal);
      });
    if (!response.ok) {
      await discardResponse(response);
      throw new ProviderError(
        "upstream",
        `Provider request failed with status ${response.status}`,
        response.status,
      );
    }
    const responseBody = await readBoundedResponse(
      response,
      request.maxResponseBytes,
      () => timedOut,
      callerSignal,
    );
    try {
      return JSON.parse(responseBody) as unknown;
    } catch {
      throw invalidResponse();
    }
  } finally {
    clearTimeout(timer);
    callerSignal?.removeEventListener("abort", onCallerAbort);
  }
}

async function resolveSecret(
  supplier: ProviderSecretSupplier,
  signal: AbortSignal,
): Promise<string> {
  let secret: string | undefined;
  try {
    secret = await abortable(Promise.resolve(supplier()), signal);
  } catch (error) {
    if (error instanceof RequestAborted) throw error;
    throw new ProviderError(
      "credential_unavailable",
      "Provider credential is unavailable",
    );
  }
  if (
    typeof secret !== "string" ||
    !secret ||
    secret.length > 16 * 1024 ||
    secret !== secret.trim() ||
    hasAsciiControl(secret)
  )
    throw new ProviderError(
      "credential_unavailable",
      "Provider credential is unavailable",
    );
  return secret;
}

class RequestAborted extends Error {}

function abortable<T>(promise: Promise<T>, signal: AbortSignal): Promise<T> {
  return new Promise<T>((resolve, reject) => {
    const onAbort = (): void => reject(new RequestAborted());
    if (signal.aborted) {
      onAbort();
      return;
    }
    signal.addEventListener("abort", onAbort, { once: true });
    promise.then(resolve, reject).finally(() => {
      signal.removeEventListener("abort", onAbort);
    });
  });
}

async function readBoundedResponse(
  response: Response,
  maximumBytes: number,
  didTimeOut: () => boolean,
  callerSignal?: AbortSignal,
): Promise<string> {
  const declared = response.headers.get("content-length");
  if (
    declared !== null &&
    /^\d+$/u.test(declared) &&
    Number(declared) > maximumBytes
  ) {
    await discardResponse(response);
    throw new ProviderError(
      "response_too_large",
      "Provider response exceeds the configured limit",
    );
  }
  if (response.body === null) throw invalidResponse();
  const reader = response.body.getReader();
  const chunks: Uint8Array[] = [];
  let length = 0;
  try {
    while (true) {
      let result: ReadableStreamReadResult<Uint8Array>;
      try {
        result = await reader.read();
      } catch {
        throw abortOrTransport(didTimeOut(), callerSignal);
      }
      if (result.done) break;
      length += result.value.byteLength;
      if (length > maximumBytes) {
        await reader.cancel().catch(() => undefined);
        throw new ProviderError(
          "response_too_large",
          "Provider response exceeds the configured limit",
        );
      }
      chunks.push(result.value);
    }
  } finally {
    reader.releaseLock();
  }
  const combined = new Uint8Array(length);
  let offset = 0;
  for (const chunk of chunks) {
    combined.set(chunk, offset);
    offset += chunk.byteLength;
  }
  try {
    return new TextDecoder("utf-8", { fatal: true }).decode(combined);
  } catch {
    throw invalidResponse();
  }
}

function extractAnthropicMessageText(value: unknown): string {
  const envelope = objectValue(value);
  if (
    envelope.error !== undefined ||
    envelope.type !== "message" ||
    envelope.stop_reason !== "end_turn" ||
    !Array.isArray(envelope.content)
  )
    throw invalidResponse();
  const fragments: string[] = [];
  for (const itemValue of envelope.content) {
    const item = objectValue(itemValue);
    if (item.type !== "text" || typeof item.text !== "string")
      throw invalidResponse();
    fragments.push(item.text);
  }
  const text = fragments.join("");
  if (!text.trim()) throw invalidResponse();
  return text;
}

function extractGeminiInteractionText(value: unknown): string {
  const envelope = objectValue(value);
  if (envelope.error !== undefined) throw invalidResponse();
  if (typeof envelope.status === "string" && envelope.status !== "completed")
    throw invalidResponse();
  if (typeof envelope.output_text === "string" && envelope.output_text.trim())
    return envelope.output_text;
  if (!Array.isArray(envelope.steps)) throw invalidResponse();
  const fragments: string[] = [];
  for (const stepValue of envelope.steps) {
    const step = objectValue(stepValue);
    if (step.type !== "model_output") continue;
    if (!Array.isArray(step.content)) throw invalidResponse();
    for (const itemValue of step.content) {
      const item = objectValue(itemValue);
      if (item.type !== "text" || typeof item.text !== "string")
        throw invalidResponse();
      fragments.push(item.text);
    }
  }
  const text = fragments.join("");
  if (!text.trim()) throw invalidResponse();
  return text;
}

function objectValue(value: unknown): Record<string, unknown> {
  if (typeof value !== "object" || value === null || Array.isArray(value))
    throw invalidResponse();
  return value as Record<string, unknown>;
}

function boundedInteger(
  value: number | undefined,
  fallback: number,
  minimum: number,
  maximum: number,
  name: string,
): number {
  const resolved = value ?? fallback;
  if (
    !Number.isSafeInteger(resolved) ||
    resolved < minimum ||
    resolved > maximum
  )
    throw configurationError(`Provider ${name} is invalid`);
  return resolved;
}

function validModel(model: string): string {
  if (
    typeof model !== "string" ||
    !model.trim() ||
    model !== model.trim() ||
    model.length > 256 ||
    /[\r\n\0]/u.test(model)
  )
    throw configurationError("Provider model is invalid");
  return model;
}

function hasAsciiControl(value: string): boolean {
  return Array.from(value).some((character) => {
    const codePoint = character.codePointAt(0);
    return codePoint !== undefined && (codePoint <= 0x1f || codePoint === 0x7f);
  });
}

function abortOrTransport(
  timedOut: boolean,
  callerSignal?: AbortSignal,
): ProviderError {
  if (timedOut)
    return new ProviderError("timeout", "Provider request timed out");
  if (callerSignal?.aborted)
    return new ProviderError("cancelled", "Provider request was cancelled");
  return new ProviderError("transport", "Provider request failed");
}

async function discardResponse(response: Response): Promise<void> {
  try {
    await response.body?.cancel();
  } catch {
    // Never surface an upstream body or transport detail.
  }
}

function byteLength(value: string): number {
  return new TextEncoder().encode(value).byteLength;
}

function invalidResponse(): ProviderError {
  return new ProviderError(
    "invalid_response",
    "Provider returned an invalid response",
  );
}

function configurationError(message: string): ProviderError {
  return new ProviderError("invalid_configuration", message);
}
