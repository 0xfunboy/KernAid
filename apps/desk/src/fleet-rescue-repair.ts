import type { RescueRepairTargetClaims } from "./rescue-repair";

export const FLEET_RESCUE_API_VERSION =
  "kernaid.dev/fleet-rescue-repair/v1alpha1";
export const FLEET_RESCUE_INTENT_SCHEMA =
  "dev.kernaid.fleet.rescue-repair-intent.v1";
export const FLEET_RESCUE_ENDPOINT = "/api/rescue/fleet-repair";
export const FLEET_FSTAB_ACTION = "linux.fstab.disable-missing-uuid.v1";
export const FLEET_FSTAB_CONFIRMATION = "DISABILITA VOCE FSTAB";

const MAX_RESPONSE_BYTES = 16 * 1024;
const IDENTIFIER = /^[A-Za-z0-9._:/-]{1,160}$/u;
const SHA256 = /^[a-f0-9]{64}$/u;
const FIXED_ID = /^(?:Q|S|P|A)-[a-f0-9]{32}$/u;
const BACKUP = /^vault:\/\/repair\/B-[a-f0-9]{32}$/u;

export type FleetRescueIntentState =
  | "awaiting-target"
  | "staging"
  | "awaiting-approval"
  | "approved"
  | "executing"
  | "canceling"
  | "rejected"
  | "succeeded"
  | "failed"
  | "manual-reconciliation-required";

export interface FleetRescueEvidence {
  readonly preparedId: string;
  readonly sessionId: string;
  readonly planId: string;
  readonly planSha256: string;
  readonly targetSha256: string;
  readonly beforeSha256: string;
  readonly afterSha256: string;
  readonly diffSha256: string;
  readonly backupLocator: string;
  readonly approvalSequence: number;
  readonly evidenceSha256: string;
}

export interface FleetRescueIntent {
  readonly schema: typeof FLEET_RESCUE_INTENT_SCHEMA;
  readonly deviceId: string;
  readonly workOrderId: string;
  readonly leaseId: string;
  readonly executionId: string;
  readonly actionId: typeof FLEET_FSTAB_ACTION;
  readonly actionVersion: 1;
  readonly risk: "R2";
  readonly state: FleetRescueIntentState;
  readonly leaseExpiresAt: string;
  readonly evidence: FleetRescueEvidence | null;
  readonly confirmationRequired: typeof FLEET_FSTAB_CONFIRMATION | null;
}

type FetchLike = (
  input: RequestInfo | URL,
  init?: RequestInit,
) => Promise<Response>;

export class FleetRescueUnavailableError extends Error {}

export class FleetRescueClient {
  readonly #fetch: FetchLike;

  constructor(fetcher: FetchLike = fetch) {
    this.#fetch = fetcher;
  }

  async status(signal?: AbortSignal): Promise<FleetRescueIntent | null> {
    return await this.#request(undefined, signal);
  }

  async stage(
    intent: FleetRescueIntent,
    target: RescueRepairTargetClaims,
    signal?: AbortSignal,
  ): Promise<FleetRescueIntent> {
    return await this.#required(
      {
        apiVersion: FLEET_RESCUE_API_VERSION,
        operation: "stage",
        ...intentBinding(intent),
        target,
      },
      signal,
    );
  }

  async approve(
    intent: FleetRescueIntent,
    approvalId: string,
    approvedAt: string,
    typedConfirmation: string,
    signal?: AbortSignal,
  ): Promise<FleetRescueIntent> {
    const evidence = intent.evidence;
    if (
      evidence === null ||
      intent.state !== "awaiting-approval" ||
      !FIXED_ID.test(approvalId) ||
      typedConfirmation !== FLEET_FSTAB_CONFIRMATION
    )
      throw new Error("Approvazione locale non valida.");
    return await this.#required(
      {
        apiVersion: FLEET_RESCUE_API_VERSION,
        operation: "approve",
        ...intentBinding(intent),
        planSha256: evidence.planSha256,
        targetSha256: evidence.targetSha256,
        evidenceSha256: evidence.evidenceSha256,
        approvalId,
        approvalSequence: evidence.approvalSequence,
        approvedAt,
        typedConfirmation,
      },
      signal,
    );
  }

  async reject(
    intent: FleetRescueIntent,
    signal?: AbortSignal,
  ): Promise<FleetRescueIntent> {
    if (intent.evidence === null) throw new Error("Evidenza locale assente.");
    return await this.#required(
      {
        apiVersion: FLEET_RESCUE_API_VERSION,
        operation: "reject",
        ...intentBinding(intent),
        evidenceSha256: intent.evidence.evidenceSha256,
      },
      signal,
    );
  }

  async #required(
    body: Record<string, unknown>,
    signal?: AbortSignal,
  ): Promise<FleetRescueIntent> {
    const result = await this.#request(body, signal);
    if (result === null) throw new FleetRescueUnavailableError();
    return result;
  }

  async #request(
    body?: Record<string, unknown>,
    signal?: AbortSignal,
  ): Promise<FleetRescueIntent | null> {
    const response = await this.#fetch(FLEET_RESCUE_ENDPOINT, {
      method: body === undefined ? "GET" : "POST",
      body: body === undefined ? undefined : canonicalJson(body),
      headers:
        body === undefined ? undefined : { "Content-Type": "application/json" },
      cache: "no-store",
      credentials: "same-origin",
      redirect: "error",
      signal,
    }).catch(() => {
      throw new FleetRescueUnavailableError();
    });
    if (response.status === 404 || response.status === 204) return null;
    if (!response.ok) throw new Error("Intento Fleet Rescue non disponibile.");
    const declared = Number(response.headers.get("content-length") ?? "0");
    if (declared > MAX_RESPONSE_BYTES)
      throw new Error("Risposta Fleet Rescue troppo grande.");
    const text = await response.text();
    if (new TextEncoder().encode(text).length > MAX_RESPONSE_BYTES)
      throw new Error("Risposta Fleet Rescue troppo grande.");
    return parseFleetRescueIntent(JSON.parse(text) as unknown);
  }
}

export function parseFleetRescueIntent(value: unknown): FleetRescueIntent {
  const object = exactObject(value, [
    "schema",
    "deviceId",
    "workOrderId",
    "leaseId",
    "executionId",
    "actionId",
    "actionVersion",
    "risk",
    "state",
    "leaseExpiresAt",
    "evidence",
    "confirmationRequired",
  ]);
  if (
    object.schema !== FLEET_RESCUE_INTENT_SCHEMA ||
    !identifier(object.deviceId) ||
    !identifier(object.workOrderId) ||
    !identifier(object.leaseId) ||
    !identifier(object.executionId) ||
    object.actionId !== FLEET_FSTAB_ACTION ||
    object.actionVersion !== 1 ||
    object.risk !== "R2" ||
    typeof object.leaseExpiresAt !== "string" ||
    !Number.isFinite(Date.parse(object.leaseExpiresAt)) ||
    !isIntentState(object.state)
  )
    throw new Error("Intento Fleet Rescue non valido.");
  const evidence =
    object.evidence === null ? null : parseEvidence(object.evidence);
  const confirmation = object.confirmationRequired;
  if (confirmation !== null && confirmation !== FLEET_FSTAB_CONFIRMATION)
    throw new Error("Conferma Fleet Rescue non valida.");
  if (
    (object.state === "awaiting-approval" &&
      confirmation !== FLEET_FSTAB_CONFIRMATION) ||
    (object.state !== "awaiting-approval" && confirmation !== null)
  )
    throw new Error("Stato conferma Fleet Rescue non valido.");
  if ((object.state === "awaiting-approval") !== (evidence !== null))
    if (object.state === "awaiting-approval" || evidence === null)
      throw new Error("Binding evidenza Fleet Rescue non valido.");
  return { ...(object as unknown as FleetRescueIntent), evidence };
}

function parseEvidence(value: unknown): FleetRescueEvidence {
  const object = exactObject(value, [
    "preparedId",
    "sessionId",
    "planId",
    "planSha256",
    "targetSha256",
    "beforeSha256",
    "afterSha256",
    "diffSha256",
    "backupLocator",
    "approvalSequence",
    "evidenceSha256",
  ]);
  if (
    !FIXED_ID.test(String(object.preparedId)) ||
    !FIXED_ID.test(String(object.sessionId)) ||
    !FIXED_ID.test(String(object.planId)) ||
    !SHA256.test(String(object.planSha256)) ||
    !SHA256.test(String(object.targetSha256)) ||
    !/^sha256:[a-f0-9]{64}$/u.test(String(object.beforeSha256)) ||
    !/^sha256:[a-f0-9]{64}$/u.test(String(object.afterSha256)) ||
    !/^sha256:[a-f0-9]{64}$/u.test(String(object.diffSha256)) ||
    !BACKUP.test(String(object.backupLocator)) ||
    !Number.isSafeInteger(object.approvalSequence) ||
    Number(object.approvalSequence) < 1 ||
    !SHA256.test(String(object.evidenceSha256))
  )
    throw new Error("Evidenza Fleet Rescue non valida.");
  return object as unknown as FleetRescueEvidence;
}

function intentBinding(intent: FleetRescueIntent) {
  return {
    deviceId: intent.deviceId,
    workOrderId: intent.workOrderId,
    leaseId: intent.leaseId,
    executionId: intent.executionId,
    actionId: intent.actionId,
    actionVersion: intent.actionVersion,
  };
}

function canonicalJson(value: unknown): string {
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(",")}]`;
  if (value !== null && typeof value === "object") {
    const object = value as Record<string, unknown>;
    return `{${Object.keys(object)
      .sort()
      .map((key) => `${JSON.stringify(key)}:${canonicalJson(object[key])}`)
      .join(",")}}`;
  }
  return JSON.stringify(value);
}

function exactObject(
  value: unknown,
  keys: readonly string[],
): Record<string, unknown> {
  if (value === null || typeof value !== "object" || Array.isArray(value))
    throw new Error("Envelope Fleet Rescue non valida.");
  const object = value as Record<string, unknown>;
  const actual = Object.keys(object).sort();
  const expected = [...keys].sort();
  if (
    actual.length !== expected.length ||
    actual.some((key, i) => key !== expected[i])
  )
    throw new Error("Envelope Fleet Rescue non valida.");
  return object;
}

function identifier(value: unknown): value is string {
  return typeof value === "string" && IDENTIFIER.test(value);
}

function isIntentState(value: unknown): value is FleetRescueIntentState {
  return (
    typeof value === "string" &&
    [
      "awaiting-target",
      "staging",
      "awaiting-approval",
      "approved",
      "executing",
      "canceling",
      "rejected",
      "succeeded",
      "failed",
      "manual-reconciliation-required",
    ].includes(value)
  );
}
