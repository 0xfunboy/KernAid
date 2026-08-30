import {
  ProviderError,
  type ObservedEvidence,
  type Provider,
  type ProviderContextPreview,
  type ProviderRequestOptions,
} from "@kernaid/agent-gateway";
import {
  LINUX_NORMALIZED_SNAPSHOT_COLLECTOR,
  LINUX_NORMALIZED_SNAPSHOT_HASH_DOMAIN,
  canonicalLinuxSnapshotJson,
  parseDiagnosisProposal,
  parseLinuxNormalizedSnapshotEnvelopeJson,
  type DiagnosisProposal,
} from "@kernaid/schemas";

const API_VERSION = "kernaid.dev/rescue-openai/v1alpha1";
const ENDPOINT = "/api/rescue/provider/openai";
const STATUS_OPERATION = "provider.status";
const CONTEXT_PREVIEW_OPERATION = "provider.openai.context-preview";
const DIAGNOSE_OPERATION = "provider.openai.diagnose";
const RESCUE_COLLECTOR =
  "rescue.installed-target.filesystem-content.read-only.v1";
const RESCUE_TARGET = "selected-installed-target";
const MAX_REQUEST_FRAME_BYTES = 96 * 1024;
const MAX_RESPONSE_FRAME_BYTES = 64 * 1024;
const MAX_OBJECTIVE_BYTES = 8 * 1024;
const MAX_EVIDENCE_SUMMARY_BYTES = 256;
const MAX_EVIDENCE_CONTENT_BYTES = 48 * 1024;
const MAX_DIAGNOSIS_BYTES = 16 * 1024;
const MAX_REQUESTED_EVIDENCE_BYTES = 256;
const STATUS_TIMEOUT_MILLISECONDS = 6_000;
const DIAGNOSE_TIMEOUT_MILLISECONDS = 143_000;
const REQUEST_ID =
  /^O-[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/u;
const EVIDENCE_ID = /^E-[A-Za-z0-9-]+$/u;
const CONTEXT_SHA256 = /^sha256:[a-f0-9]{64}$/u;
const UTF8_ENCODER = new TextEncoder();
const UTF8_DECODER = new TextDecoder("utf-8", { fatal: true });

type Fetch = (
  input: RequestInfo | URL,
  init?: RequestInit,
) => Promise<Response>;

type Operation =
  | typeof STATUS_OPERATION
  | typeof CONTEXT_PREVIEW_OPERATION
  | typeof DIAGNOSE_OPERATION;

type RescueOpenAiErrorCode =
  | "busy"
  | "credential_unavailable"
  | "invalid_request"
  | "invalid_response"
  | "request_too_large"
  | "response_too_large"
  | "timeout"
  | "transport"
  | "upstream";

export interface RescueOpenAiStatus {
  provider: "openai";
  profile: "rescue-default";
  vault:
    | "absent"
    | "unprovisioned"
    | "locked"
    | "unlocking"
    | "unlocked"
    | "locking"
    | "faulted-reboot-required";
  credential: "unavailable" | "absent" | "configured";
}

export interface RescueOpenAiProjectedObservation {
  readonly id: string;
  readonly collector:
    typeof RESCUE_COLLECTOR | typeof LINUX_NORMALIZED_SNAPSHOT_COLLECTOR;
  readonly trust: "observed-untrusted";
}

export interface RescueOpenAiProjectedContext {
  readonly objective: string;
  readonly deterministicProposal: DiagnosisProposal;
  readonly observations: readonly RescueOpenAiProjectedObservation[];
}

export interface RescueOpenAiContextPreview extends ProviderContextPreview {
  readonly context: RescueOpenAiProjectedContext;
  readonly contextSha256: string;
}

export type RescueProviderMode = "offline" | "openai";

export interface RescueProviderPreparation {
  readonly epoch: number;
  readonly mode: RescueProviderMode;
}

export interface RescueProviderSwitchAvailability {
  readonly targetBusy: boolean;
  readonly inspectionBusy: boolean;
  readonly inspectionInFlight: boolean;
}

export interface RescueProviderSwitchTransition {
  readonly changed: boolean;
  readonly contextEpoch: number;
}

export class RescueProviderSessionBinding {
  #epoch = 0;
  #mode: RescueProviderMode;
  #preparation: RescueProviderPreparation | undefined;
  #session: RescueProviderPreparation | undefined;

  constructor(mode: RescueProviderMode = "offline") {
    this.#mode = mode;
  }

  get mode(): RescueProviderMode {
    return this.#mode;
  }

  get epoch(): number {
    return this.#epoch;
  }

  get sessionMode(): RescueProviderMode | undefined {
    return this.#session?.mode;
  }

  switchMode(mode: RescueProviderMode): boolean {
    if (this.#preparation !== undefined || this.#session !== undefined)
      return false;
    if (mode !== this.#mode) {
      this.#epoch += 1;
      this.#mode = mode;
    }
    return true;
  }

  clearSessionAndPreparation(): void {
    this.#epoch += 1;
    this.#preparation = undefined;
    this.#session = undefined;
  }

  beginPreparation(): RescueProviderPreparation | undefined {
    if (this.#preparation !== undefined || this.#session !== undefined)
      return undefined;
    const snapshot = Object.freeze({ epoch: this.#epoch, mode: this.#mode });
    this.#preparation = snapshot;
    return snapshot;
  }

  preparationIsCurrent(snapshot: RescueProviderPreparation): boolean {
    return (
      this.#preparation === snapshot &&
      snapshot.epoch === this.#epoch &&
      snapshot.mode === this.#mode
    );
  }

  commitPreparation(
    snapshot: RescueProviderPreparation,
  ): RescueProviderMode | undefined {
    if (!this.preparationIsCurrent(snapshot)) return undefined;
    this.#preparation = undefined;
    this.#session = snapshot;
    return snapshot.mode;
  }

  cancelPreparation(snapshot: RescueProviderPreparation): void {
    if (this.#preparation !== snapshot) return;
    this.#epoch += 1;
    this.#preparation = undefined;
  }

  sessionMatches(mode: RescueProviderMode): boolean {
    return (
      this.#session !== undefined &&
      this.#session.epoch === this.#epoch &&
      this.#session.mode === mode &&
      this.#mode === mode
    );
  }
}

export function transitionRescueProviderMode(
  binding: RescueProviderSessionBinding,
  mode: RescueProviderMode,
  contextEpoch: number,
  availability: RescueProviderSwitchAvailability,
): RescueProviderSwitchTransition {
  if (
    mode === binding.mode ||
    availability.targetBusy ||
    availability.inspectionBusy ||
    availability.inspectionInFlight ||
    !binding.switchMode(mode)
  )
    return Object.freeze({ changed: false, contextEpoch });
  return Object.freeze({ changed: true, contextEpoch: contextEpoch + 1 });
}

interface RescueEvidence {
  schemaVersion: "1.0";
  id: string;
  collector:
    typeof RESCUE_COLLECTOR | typeof LINUX_NORMALIZED_SNAPSHOT_COLLECTOR;
  target: typeof RESCUE_TARGET;
  contentType: "application/json";
  trust: "observed-untrusted";
  summary: string;
  content: string;
}

export async function getRescueOpenAiStatus(
  fetchRequest: Fetch = globalThis.fetch,
): Promise<RescueOpenAiStatus> {
  const requestId = newRequestId();
  const response = await exchange(
    fetchRequest,
    requestId,
    STATUS_OPERATION,
    {
      apiVersion: API_VERSION,
      requestId,
      operation: STATUS_OPERATION,
      payload: {},
    },
    STATUS_TIMEOUT_MILLISECONDS,
  );
  return parseStatusPayload(response);
}

export function rescueOpenAiReady(
  status: RescueOpenAiStatus | undefined,
): boolean {
  return status?.vault === "unlocked" && status.credential === "configured";
}

export class RescueOpenAiProvider implements Provider {
  readonly capabilities = Object.freeze({
    streaming: false,
    structuredOutput: true,
    toolRequests: false,
    local: false,
  });

  readonly #fetch: Fetch;

  constructor(fetchRequest: Fetch = globalThis.fetch) {
    this.#fetch = fetchRequest;
  }

  async previewContext(
    objective: string,
    evidence: readonly ObservedEvidence[],
    options: Omit<ProviderRequestOptions, "contextSha256"> = {},
  ): Promise<RescueOpenAiContextPreview> {
    if (options.signal?.aborted)
      throw new ProviderError("cancelled", "Anteprima OpenAI annullata.");
    const rescueEvidence = await prepareEvidence(objective, evidence);
    const requestId = newRequestId();
    const response = await exchange(
      this.#fetch,
      requestId,
      CONTEXT_PREVIEW_OPERATION,
      {
        apiVersion: API_VERSION,
        requestId,
        operation: CONTEXT_PREVIEW_OPERATION,
        payload: {
          objective,
          evidence: [rescueEvidence],
        },
      },
      STATUS_TIMEOUT_MILLISECONDS,
    );
    const preview = parseRescueOpenAiContextPreview(response);
    const [observation] = preview.context.observations;
    if (
      observation?.id !== rescueEvidence.id ||
      observation.collector !== rescueEvidence.collector
    )
      throw providerError("invalid_response");
    return preview;
  }

  async diagnose(
    objective: string,
    evidence: readonly ObservedEvidence[],
    options: ProviderRequestOptions = {},
  ): Promise<DiagnosisProposal> {
    if (options.signal?.aborted)
      throw new ProviderError("cancelled", "Richiesta OpenAI annullata.");
    if (
      options.contextSha256 === undefined ||
      !CONTEXT_SHA256.test(options.contextSha256)
    )
      throw providerError("invalid_request");
    const rescueEvidence = await prepareEvidence(objective, evidence);
    const requestId = newRequestId();
    const response = await exchange(
      this.#fetch,
      requestId,
      DIAGNOSE_OPERATION,
      {
        apiVersion: API_VERSION,
        requestId,
        operation: DIAGNOSE_OPERATION,
        payload: {
          objective,
          evidence: [rescueEvidence],
          contextSha256: options.contextSha256,
        },
      },
      DIAGNOSE_TIMEOUT_MILLISECONDS,
    );
    const payload = exactRecord(response, ["proposal"]);
    let proposal: DiagnosisProposal;
    try {
      proposal = parseDiagnosisProposal(payload.proposal);
    } catch {
      throw providerError("invalid_response");
    }
    if (
      !boundedNonemptyUtf8(proposal.diagnosis, MAX_DIAGNOSIS_BYTES) ||
      proposal.evidenceIds.length !== 1 ||
      proposal.evidenceIds[0] !== rescueEvidence.id ||
      proposal.requestedEvidence.some(
        (item) => !boundedNonemptyUtf8(item, MAX_REQUESTED_EVIDENCE_BYTES),
      )
    )
      throw providerError("invalid_response");
    return proposal;
  }
}

export function parseRescueOpenAiContextPreview(
  value: ProviderContextPreview | Record<string, unknown>,
): RescueOpenAiContextPreview {
  const payload = exactRecord(value, ["context", "contextSha256"]);
  if (
    typeof payload.contextSha256 !== "string" ||
    !CONTEXT_SHA256.test(payload.contextSha256)
  )
    throw providerError("invalid_response");
  const context = exactRecord(payload.context, [
    "objective",
    "deterministicProposal",
    "observations",
  ]);
  if (
    typeof context.objective !== "string" ||
    !boundedNonemptyUtf8(context.objective, MAX_OBJECTIVE_BYTES)
  )
    throw providerError("invalid_response");
  let deterministicProposal: DiagnosisProposal;
  try {
    deterministicProposal = parseDiagnosisProposal(
      context.deterministicProposal,
    );
  } catch {
    throw providerError("invalid_response");
  }
  if (
    deterministicProposal.evidenceIds.length !== 1 ||
    !boundedNonemptyUtf8(
      deterministicProposal.diagnosis,
      MAX_DIAGNOSIS_BYTES,
    ) ||
    deterministicProposal.requestedEvidence.some(
      (item) => !boundedNonemptyUtf8(item, MAX_REQUESTED_EVIDENCE_BYTES),
    ) ||
    !Array.isArray(context.observations) ||
    context.observations.length !== 1
  )
    throw providerError("invalid_response");
  const observation = exactRecord(context.observations[0], [
    "id",
    "collector",
    "trust",
  ]);
  if (
    typeof observation.id !== "string" ||
    !EVIDENCE_ID.test(observation.id) ||
    utf8Length(observation.id) > 128 ||
    (observation.collector !== RESCUE_COLLECTOR &&
      observation.collector !== LINUX_NORMALIZED_SNAPSHOT_COLLECTOR) ||
    deterministicProposal.evidenceIds[0] !== observation.id ||
    observation.trust !== "observed-untrusted"
  )
    throw providerError("invalid_response");
  return Object.freeze({
    context: Object.freeze({
      objective: context.objective,
      deterministicProposal,
      observations: Object.freeze([
        Object.freeze({
          id: observation.id,
          collector: observation.collector,
          trust: "observed-untrusted" as const,
        }),
      ]),
    }),
    contextSha256: payload.contextSha256,
  });
}

async function prepareEvidence(
  objective: string,
  evidence: readonly ObservedEvidence[],
): Promise<RescueEvidence> {
  if (!boundedNonemptyUtf8(objective, MAX_OBJECTIVE_BYTES))
    throw providerError("invalid_request");
  if (evidence.length !== 1) throw providerError("invalid_request");
  const observed = evidence[0];
  if (observed === undefined) throw providerError("invalid_request");
  const item = observed.evidence;
  if (
    item.schemaVersion !== "1.0" ||
    !EVIDENCE_ID.test(item.id) ||
    utf8Length(item.id) > 128 ||
    (item.collector !== RESCUE_COLLECTOR &&
      item.collector !== LINUX_NORMALIZED_SNAPSHOT_COLLECTOR) ||
    item.target !== RESCUE_TARGET ||
    item.contentType !== "application/json" ||
    item.trust !== "observed-untrusted" ||
    !boundedNonemptyUtf8(item.summary, MAX_EVIDENCE_SUMMARY_BYTES) ||
    !boundedNonemptyUtf8(observed.content, MAX_EVIDENCE_CONTENT_BYTES)
  )
    throw providerError("invalid_request");
  try {
    if (item.collector === LINUX_NORMALIZED_SNAPSHOT_COLLECTOR) {
      const envelope = parseLinuxNormalizedSnapshotEnvelopeJson(
        UTF8_ENCODER.encode(observed.content),
      );
      if (
        envelope.capture.mode !== "rescue" ||
        !envelope.snapshot.topology.supported ||
        envelope.snapshotSha256 !==
          (await sha256Text(
            `${LINUX_NORMALIZED_SNAPSHOT_HASH_DOMAIN}${canonicalLinuxSnapshotJson(
              envelope.snapshot,
            )}`,
          ))
      )
        throw providerError("invalid_request");
    } else {
      const content = JSON.parse(observed.content) as unknown;
      if (
        typeof content !== "object" ||
        content === null ||
        Array.isArray(content) ||
        (content as Record<string, unknown>).family !== "windows"
      )
        throw providerError("invalid_request");
    }
  } catch (error) {
    if (error instanceof ProviderError) throw error;
    throw providerError("invalid_request");
  }
  return {
    schemaVersion: "1.0",
    id: item.id,
    collector: item.collector,
    target: RESCUE_TARGET,
    contentType: "application/json",
    trust: "observed-untrusted",
    summary: item.summary,
    content: observed.content,
  };
}

async function sha256Text(value: string): Promise<string> {
  const digest = await crypto.subtle.digest(
    "SHA-256",
    UTF8_ENCODER.encode(value),
  );
  return Array.from(new Uint8Array(digest), (byte) =>
    byte.toString(16).padStart(2, "0"),
  ).join("");
}

async function exchange(
  fetchRequest: Fetch,
  requestId: string,
  operation: Operation,
  request: object,
  timeoutMilliseconds: number,
): Promise<Record<string, unknown>> {
  const body = `${JSON.stringify(request)}\n`;
  if (utf8Length(body) > MAX_REQUEST_FRAME_BYTES)
    throw providerError("request_too_large");
  let response: Response;
  try {
    response = await fetchRequest(ENDPOINT, {
      method: "POST",
      cache: "no-store",
      headers: { "Content-Type": "application/json" },
      body,
      signal: AbortSignal.timeout(timeoutMilliseconds),
    });
  } catch (error) {
    if (errorName(error) === "TimeoutError") throw providerError("timeout");
    throw providerError("transport");
  }
  if (!response.ok) {
    await response.body?.cancel().catch(() => undefined);
    throw httpProviderError(response.status);
  }
  if (!isJsonResponse(response)) {
    await response.body?.cancel().catch(() => undefined);
    throw providerError("invalid_response");
  }
  const parsed = await readClosedJsonFrame(response);
  const envelope = exactRecordByOutcome(parsed);
  if (
    envelope.apiVersion !== API_VERSION ||
    envelope.requestId !== requestId ||
    envelope.operation !== operation ||
    typeof envelope.ok !== "boolean"
  )
    throw providerError("invalid_response");
  if (envelope.ok === false) {
    const error = exactRecord(envelope.error, ["code"]);
    if (!isRescueOpenAiErrorCode(error.code))
      throw providerError("invalid_response");
    throw providerError(error.code);
  }
  return exactRecord(envelope.payload);
}

function parseStatusPayload(
  value: Record<string, unknown>,
): RescueOpenAiStatus {
  const item = exactRecord(value, [
    "provider",
    "profile",
    "vault",
    "credential",
  ]);
  const vault = item.vault;
  const credential = item.credential;
  if (
    item.provider !== "openai" ||
    item.profile !== "rescue-default" ||
    !(
      vault === "absent" ||
      vault === "unprovisioned" ||
      vault === "locked" ||
      vault === "unlocking" ||
      vault === "unlocked" ||
      vault === "locking" ||
      vault === "faulted-reboot-required"
    ) ||
    !(
      credential === "unavailable" ||
      credential === "absent" ||
      credential === "configured"
    ) ||
    (vault !== "unlocked" && credential !== "unavailable")
  )
    throw providerError("invalid_response");
  return structuredClone(item) as unknown as RescueOpenAiStatus;
}

async function readClosedJsonFrame(response: Response): Promise<unknown> {
  const declared = response.headers.get("Content-Length");
  if (declared === null || !/^[0-9]+$/u.test(declared)) {
    await response.body?.cancel().catch(() => undefined);
    throw providerError("invalid_response");
  }
  if (Number(declared) > MAX_RESPONSE_FRAME_BYTES) {
    await response.body?.cancel().catch(() => undefined);
    throw providerError("response_too_large");
  }
  if (response.body === null) throw providerError("invalid_response");
  const reader = response.body.getReader();
  const chunks: Uint8Array[] = [];
  let total = 0;
  try {
    while (true) {
      const result = await reader.read();
      if (result.done) break;
      total += result.value.byteLength;
      if (total > MAX_RESPONSE_FRAME_BYTES) {
        await reader.cancel();
        throw providerError("response_too_large");
      }
      chunks.push(result.value);
    }
  } catch (error) {
    if (error instanceof ProviderError) throw error;
    throw providerError("transport");
  } finally {
    reader.releaseLock();
  }
  const bytes = new Uint8Array(total);
  let offset = 0;
  for (const chunk of chunks) {
    bytes.set(chunk, offset);
    offset += chunk.byteLength;
  }
  if (Number(declared) !== bytes.byteLength)
    throw providerError("invalid_response");
  if (
    bytes.length < 3 ||
    bytes[0] !== 0x7b ||
    bytes.at(-1) !== 0x0a ||
    bytes.at(-2) !== 0x7d ||
    bytes.subarray(0, -1).some((byte) => byte === 0x0a || byte === 0x0d)
  )
    throw providerError("invalid_response");
  let text: string;
  try {
    text = UTF8_DECODER.decode(bytes.subarray(0, -1));
    assertJsonHasUniqueObjectKeys(text);
    return JSON.parse(text) as unknown;
  } catch (error) {
    if (error instanceof ProviderError) throw error;
    throw providerError("invalid_response");
  }
}

function exactRecord(
  value: unknown,
  fields?: readonly string[],
): Record<string, unknown> {
  if (typeof value !== "object" || value === null || Array.isArray(value))
    throw providerError("invalid_response");
  const item = value as Record<string, unknown>;
  if (
    fields !== undefined &&
    (Object.keys(item).length !== fields.length ||
      fields.some((field) => !Object.hasOwn(item, field)))
  )
    throw providerError("invalid_response");
  return item;
}

function exactRecordByOutcome(value: unknown): Record<string, unknown> {
  const item = exactRecord(value);
  if (item.ok === true)
    return exactRecord(item, [
      "apiVersion",
      "requestId",
      "operation",
      "ok",
      "payload",
    ]);
  if (item.ok === false)
    return exactRecord(item, [
      "apiVersion",
      "requestId",
      "operation",
      "ok",
      "error",
    ]);
  throw providerError("invalid_response");
}

function assertJsonHasUniqueObjectKeys(text: string): void {
  let cursor = 0;
  const maximumDepth = 64;

  function fail(): never {
    throw providerError("invalid_response");
  }

  function skipWhitespace(): void {
    while (
      cursor < text.length &&
      (text[cursor] === " " ||
        text[cursor] === "\t" ||
        text[cursor] === "\r" ||
        text[cursor] === "\n")
    )
      cursor += 1;
  }

  function parseString(): string {
    if (text[cursor] !== '"') fail();
    const start = cursor;
    cursor += 1;
    while (cursor < text.length) {
      const character = text.charCodeAt(cursor);
      if (character === 0x22) {
        cursor += 1;
        try {
          const decoded = JSON.parse(text.slice(start, cursor)) as string;
          if (!utf8RoundTrips(decoded)) fail();
          return decoded;
        } catch {
          fail();
        }
      }
      if (character === 0x5c) {
        cursor += 1;
        const escape = text[cursor];
        if (escape === "u") {
          if (!/^[0-9a-fA-F]{4}$/u.test(text.slice(cursor + 1, cursor + 5)))
            fail();
          cursor += 5;
          continue;
        }
        if (escape === undefined || !'"\\/bfnrt'.includes(escape)) fail();
        cursor += 1;
        continue;
      }
      if (character <= 0x1f) fail();
      cursor += 1;
    }
    fail();
  }

  function parseNumber(): void {
    const tail = text.slice(cursor);
    const match = /^-?(?:0|[1-9][0-9]*)(?:\.[0-9]+)?(?:[eE][+-]?[0-9]+)?/u.exec(
      tail,
    );
    if (match === null) fail();
    cursor += match[0].length;
  }

  function parseValue(depth: number): void {
    if (depth > maximumDepth) fail();
    skipWhitespace();
    const character = text[cursor];
    if (character === "{") {
      cursor += 1;
      skipWhitespace();
      const keys = new Set<string>();
      if (text[cursor] === "}") {
        cursor += 1;
        return;
      }
      while (true) {
        skipWhitespace();
        const key = parseString();
        if (keys.has(key)) fail();
        keys.add(key);
        skipWhitespace();
        if (text[cursor] !== ":") fail();
        cursor += 1;
        parseValue(depth + 1);
        skipWhitespace();
        if (text[cursor] === "}") {
          cursor += 1;
          return;
        }
        if (text[cursor] !== ",") fail();
        cursor += 1;
      }
    }
    if (character === "[") {
      cursor += 1;
      skipWhitespace();
      if (text[cursor] === "]") {
        cursor += 1;
        return;
      }
      while (true) {
        parseValue(depth + 1);
        skipWhitespace();
        if (text[cursor] === "]") {
          cursor += 1;
          return;
        }
        if (text[cursor] !== ",") fail();
        cursor += 1;
      }
    }
    if (character === '"') {
      parseString();
      return;
    }
    if (
      character === "-" ||
      (character !== undefined && /[0-9]/u.test(character))
    ) {
      parseNumber();
      return;
    }
    for (const literal of ["true", "false", "null"] as const) {
      if (text.startsWith(literal, cursor)) {
        cursor += literal.length;
        return;
      }
    }
    fail();
  }

  parseValue(0);
  skipWhitespace();
  if (cursor !== text.length) fail();
}

function boundedNonemptyUtf8(value: string, maximumBytes: number): boolean {
  return (
    typeof value === "string" &&
    value.trim().length > 0 &&
    !value.includes("\0") &&
    utf8RoundTrips(value) &&
    utf8Length(value) <= maximumBytes
  );
}

function utf8RoundTrips(value: string): boolean {
  try {
    return UTF8_DECODER.decode(UTF8_ENCODER.encode(value)) === value;
  } catch {
    return false;
  }
}

function utf8Length(value: string): number {
  return UTF8_ENCODER.encode(value).byteLength;
}

function isJsonResponse(response: Response): boolean {
  return response.headers.get("Content-Type") === "application/json";
}

function newRequestId(): string {
  const requestId = `O-${crypto.randomUUID()}`;
  if (!REQUEST_ID.test(requestId)) throw providerError("transport");
  return requestId;
}

function errorName(value: unknown): string | undefined {
  return typeof value === "object" && value !== null && "name" in value
    ? String(value.name)
    : undefined;
}

function isRescueOpenAiErrorCode(
  value: unknown,
): value is RescueOpenAiErrorCode {
  return (
    value === "busy" ||
    value === "credential_unavailable" ||
    value === "invalid_request" ||
    value === "invalid_response" ||
    value === "request_too_large" ||
    value === "response_too_large" ||
    value === "timeout" ||
    value === "transport" ||
    value === "upstream"
  );
}

function httpProviderError(status: number): ProviderError {
  if (status === 408 || status === 504) return providerError("timeout", status);
  if (status === 400 || status === 415)
    return providerError("invalid_request", status);
  if (status === 413) return providerError("request_too_large", status);
  if (status === 429) return providerError("busy", status);
  if (status === 502) return providerError("invalid_response", status);
  return providerError("transport", status);
}

function providerError(
  code: RescueOpenAiErrorCode,
  status?: number,
): ProviderError {
  const mappedCode = code === "busy" ? "transport" : code;
  const message = {
    busy: "OpenAI Rescue è occupato.",
    credential_unavailable: "Credenziale OpenAI Rescue non disponibile.",
    invalid_request: "Richiesta OpenAI Rescue non valida.",
    invalid_response: "Risposta OpenAI Rescue non valida.",
    request_too_large: "Richiesta OpenAI Rescue oltre il limite.",
    response_too_large: "Risposta OpenAI Rescue oltre il limite.",
    timeout: "OpenAI Rescue non ha risposto entro il limite.",
    transport: "OpenAI Rescue non è disponibile.",
    upstream: "Il provider OpenAI non ha completato la richiesta.",
  }[code];
  return new ProviderError(mappedCode, message, status);
}
