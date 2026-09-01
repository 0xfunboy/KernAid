import type { RescueRepairTargetClaims } from "./rescue-repair";
import {
  RESCUE_CRYPTTAB_ACTION_ID,
  RESCUE_CRYPTTAB_CONFIRMATION,
  RESCUE_EXT4_ACTION_ID,
  RESCUE_EXT4_CONFIRMATION,
  RESCUE_FSTAB_ACTION_ID,
  RESCUE_FSTAB_CONFIRMATION,
  RESCUE_RESOLVER_LINK_ACTION_ID,
  RESCUE_RESOLVER_LINK_CONFIRMATION,
} from "./rescue-repair";

export const FLEET_RESCUE_API_VERSION =
  "kernaid.dev/fleet-rescue-repair/v1alpha1";
export const FLEET_RESCUE_INTENT_SCHEMA =
  "dev.kernaid.fleet.rescue-repair-intent.v1";
export const FLEET_RESCUE_ENDPOINT = "/api/rescue/fleet-repair";
export const FLEET_FSTAB_ACTION = RESCUE_FSTAB_ACTION_ID;
export const FLEET_FSTAB_CONFIRMATION = RESCUE_FSTAB_CONFIRMATION;
export const FLEET_CRYPTTAB_ACTION = RESCUE_CRYPTTAB_ACTION_ID;
export const FLEET_CRYPTTAB_CONFIRMATION = RESCUE_CRYPTTAB_CONFIRMATION;
export const FLEET_EXT4_ACTION = RESCUE_EXT4_ACTION_ID;
export const FLEET_EXT4_CONFIRMATION = RESCUE_EXT4_CONFIRMATION;
export const FLEET_RESOLVER_LINK_ACTION = RESCUE_RESOLVER_LINK_ACTION_ID;
export const FLEET_RESOLVER_LINK_CONFIRMATION =
  RESCUE_RESOLVER_LINK_CONFIRMATION;

export const fleetRescueActionCatalog = {
  [FLEET_FSTAB_ACTION]: {
    label: "FSTAB",
    risk: "R2",
    confirmation: FLEET_FSTAB_CONFIRMATION,
  },
  [FLEET_CRYPTTAB_ACTION]: {
    label: "CRYPTTAB",
    risk: "R2",
    confirmation: FLEET_CRYPTTAB_CONFIRMATION,
  },
  [FLEET_EXT4_ACTION]: {
    label: "EXT4 OFFLINE",
    risk: "R3",
    confirmation: FLEET_EXT4_CONFIRMATION,
  },
  [FLEET_RESOLVER_LINK_ACTION]: {
    label: "RESOLVER LINK",
    risk: "R2",
    confirmation: FLEET_RESOLVER_LINK_CONFIRMATION,
  },
} as const;

export type FleetRescueActionId = keyof typeof fleetRescueActionCatalog;
export type FleetRescueRisk =
  (typeof fleetRescueActionCatalog)[FleetRescueActionId]["risk"];
export type FleetRescueConfirmation =
  (typeof fleetRescueActionCatalog)[FleetRescueActionId]["confirmation"];

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
  readonly actionId: FleetRescueActionId;
  readonly actionVersion: 1;
  readonly risk: FleetRescueRisk;
  readonly state: FleetRescueIntentState;
  readonly leaseExpiresAt: string;
  readonly evidence: FleetRescueEvidence | null;
  readonly confirmationRequired: FleetRescueConfirmation | null;
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
      typedConfirmation !== intent.confirmationRequired ||
      typedConfirmation !== fleetRescueAction(intent.actionId).confirmation
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
  const action = fleetRescueAction(object.actionId);
  if (
    object.schema !== FLEET_RESCUE_INTENT_SCHEMA ||
    !identifier(object.deviceId) ||
    !identifier(object.workOrderId) ||
    !identifier(object.leaseId) ||
    !identifier(object.executionId) ||
    object.actionVersion !== 1 ||
    object.risk !== action.risk ||
    typeof object.leaseExpiresAt !== "string" ||
    !Number.isFinite(Date.parse(object.leaseExpiresAt)) ||
    !isIntentState(object.state)
  )
    throw new Error("Intento Fleet Rescue non valido.");
  const evidence =
    object.evidence === null ? null : parseEvidence(object.evidence);
  const confirmation = object.confirmationRequired;
  if (confirmation !== null && confirmation !== action.confirmation)
    throw new Error("Conferma Fleet Rescue non valida.");
  if (
    (object.state === "awaiting-approval" &&
      confirmation !== action.confirmation) ||
    (object.state !== "awaiting-approval" && confirmation !== null)
  )
    throw new Error("Stato conferma Fleet Rescue non valido.");
  if ((object.state === "awaiting-approval") !== (evidence !== null))
    if (object.state === "awaiting-approval" || evidence === null)
      throw new Error("Binding evidenza Fleet Rescue non valido.");
  return { ...(object as unknown as FleetRescueIntent), evidence };
}

export function fleetRescueAction(
  value: unknown,
): (typeof fleetRescueActionCatalog)[FleetRescueActionId] {
  if (
    typeof value !== "string" ||
    !Object.hasOwn(fleetRescueActionCatalog, value)
  )
    throw new Error("Azione Fleet Rescue non valida.");
  return fleetRescueActionCatalog[value as FleetRescueActionId];
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
