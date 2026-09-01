import { canonicalJson } from "./canonical-json.js";
import {
  FleetSchemaError,
  expectBase64Url,
  expectDeviceId,
  expectEnum,
  expectExactKeys,
  expectIdentifier,
  expectRecord,
  expectRfc3339,
  expectSafeInteger,
  expectSha256,
} from "./validation.js";

export const FLEET_WORK_ORDER_CLAIM_SCHEMA =
  "dev.kernaid.fleet.work-order-claim-request.v1" as const;
export const FLEET_WORK_ORDER_CLAIM_DOMAIN =
  "kernaid:fleet:work-order-claim:v1\0" as const;
export const FLEET_WORK_ORDER_RESULT_SCHEMA =
  "dev.kernaid.fleet.work-order-result.v1" as const;
export const FLEET_WORK_ORDER_RESULT_DOMAIN =
  "kernaid:fleet:work-order-result:v1\0" as const;

export const workOrderActionCatalog = {
  "linux.filesystem.health.v1": {
    version: 1,
    kind: "diagnosis",
    risk: "R0",
    requiredFeature: "fleet",
    platforms: ["linux", "rescue"],
    localApprovalRequired: false,
  },
  "linux.storage.health.v1": {
    version: 1,
    kind: "diagnosis",
    risk: "R0",
    requiredFeature: "fleet",
    platforms: ["linux", "rescue"],
    localApprovalRequired: false,
  },
  "linux.boot-critical-path.v1": {
    version: 1,
    kind: "diagnosis",
    risk: "R0",
    requiredFeature: "fleet",
    platforms: ["linux", "rescue"],
    localApprovalRequired: false,
  },
  "linux.fstab.disable-missing-uuid.v1": {
    version: 1,
    kind: "repair",
    risk: "R2",
    requiredFeature: "enterprise_repair",
    platforms: ["rescue"],
    localApprovalRequired: true,
  },
  "windows.p0.diagnose.v1": {
    version: 1,
    kind: "diagnosis",
    risk: "R0",
    requiredFeature: "fleet",
    platforms: ["windows"],
    localApprovalRequired: false,
  },
  "macos.p0.diagnose.v1": {
    version: 1,
    kind: "diagnosis",
    risk: "R0",
    requiredFeature: "fleet",
    platforms: ["macos"],
    localApprovalRequired: false,
  },
} as const;

export type WorkOrderActionId = keyof typeof workOrderActionCatalog;
export type WorkOrderKind = "diagnosis" | "repair";
export type WorkOrderRisk = "R0" | "R1" | "R2" | "R3";
export type WorkOrderResultOutcome = "failed" | "rejected" | "succeeded";

export interface WorkOrderClaimRequestUnsigned {
  schema: typeof FLEET_WORK_ORDER_CLAIM_SCHEMA;
  tenantId: string;
  deviceId: string;
  issuedAt: string;
  nonce: string;
  leaseSeconds: number;
}

export interface WorkOrderClaimRequest extends WorkOrderClaimRequestUnsigned {
  signature: string;
}

export interface WorkOrderResultUnsigned {
  schema: typeof FLEET_WORK_ORDER_RESULT_SCHEMA;
  tenantId: string;
  deviceId: string;
  workOrderId: string;
  leaseId: string;
  actionId: WorkOrderActionId;
  actionVersion: number;
  outcome: WorkOrderResultOutcome;
  completedAt: string;
  resultSha256: string;
}

export interface WorkOrderResult extends WorkOrderResultUnsigned {
  signature: string;
}

const claimUnsignedKeys = [
  "schema",
  "tenantId",
  "deviceId",
  "issuedAt",
  "nonce",
  "leaseSeconds",
] as const;

const resultUnsignedKeys = [
  "schema",
  "tenantId",
  "deviceId",
  "workOrderId",
  "leaseId",
  "actionId",
  "actionVersion",
  "outcome",
  "completedAt",
  "resultSha256",
] as const;

export function parseWorkOrderClaimRequest(
  value: unknown,
): WorkOrderClaimRequest {
  const object = expectRecord(value);
  expectExactKeys(object, [...claimUnsignedKeys, "signature"]);
  return {
    ...parseClaimUnsignedFields(object),
    signature: expectBase64Url(object.signature, "signature", 86, 86),
  };
}

export function parseWorkOrderClaimRequestUnsigned(
  value: unknown,
): WorkOrderClaimRequestUnsigned {
  const object = expectRecord(value);
  expectExactKeys(object, claimUnsignedKeys);
  return parseClaimUnsignedFields(object);
}

export function workOrderClaimSigningBytes(
  value: WorkOrderClaimRequest | WorkOrderClaimRequestUnsigned,
): Uint8Array {
  const unsigned = parseWorkOrderClaimRequestUnsigned({
    schema: value.schema,
    tenantId: value.tenantId,
    deviceId: value.deviceId,
    issuedAt: value.issuedAt,
    nonce: value.nonce,
    leaseSeconds: value.leaseSeconds,
  });
  return new TextEncoder().encode(
    `${FLEET_WORK_ORDER_CLAIM_DOMAIN}${canonicalJson(unsigned)}`,
  );
}

export function parseWorkOrderResult(value: unknown): WorkOrderResult {
  const object = expectRecord(value);
  expectExactKeys(object, [...resultUnsignedKeys, "signature"]);
  return {
    ...parseResultUnsignedFields(object),
    signature: expectBase64Url(object.signature, "signature", 86, 86),
  };
}

export function parseWorkOrderResultUnsigned(
  value: unknown,
): WorkOrderResultUnsigned {
  const object = expectRecord(value);
  expectExactKeys(object, resultUnsignedKeys);
  return parseResultUnsignedFields(object);
}

export function workOrderResultSigningBytes(
  value: WorkOrderResult | WorkOrderResultUnsigned,
): Uint8Array {
  const unsigned = parseWorkOrderResultUnsigned({
    schema: value.schema,
    tenantId: value.tenantId,
    deviceId: value.deviceId,
    workOrderId: value.workOrderId,
    leaseId: value.leaseId,
    actionId: value.actionId,
    actionVersion: value.actionVersion,
    outcome: value.outcome,
    completedAt: value.completedAt,
    resultSha256: value.resultSha256,
  });
  return new TextEncoder().encode(
    `${FLEET_WORK_ORDER_RESULT_DOMAIN}${canonicalJson(unsigned)}`,
  );
}

export function isWorkOrderActionId(value: string): value is WorkOrderActionId {
  return Object.hasOwn(workOrderActionCatalog, value);
}

export function workOrderAction(
  value: string,
): (typeof workOrderActionCatalog)[WorkOrderActionId] {
  if (!isWorkOrderActionId(value)) {
    throw new FleetSchemaError(
      "actionId is not in the closed work-order catalog",
    );
  }
  return workOrderActionCatalog[value];
}

function parseClaimUnsignedFields(
  object: Record<string, unknown>,
): WorkOrderClaimRequestUnsigned {
  const leaseSeconds = expectSafeInteger(
    object.leaseSeconds,
    "leaseSeconds",
    30,
  );
  if (leaseSeconds > 900) {
    throw new FleetSchemaError("leaseSeconds exceeds its bound");
  }
  return {
    schema: expectEnum(object.schema, "schema", [
      FLEET_WORK_ORDER_CLAIM_SCHEMA,
    ]),
    tenantId: expectIdentifier(object.tenantId, "tenantId"),
    deviceId: expectDeviceId(object.deviceId),
    issuedAt: expectRfc3339(object.issuedAt, "issuedAt"),
    nonce: expectBase64Url(object.nonce, "nonce", 22, 86),
    leaseSeconds,
  };
}

function parseResultUnsignedFields(
  object: Record<string, unknown>,
): WorkOrderResultUnsigned {
  const actionId = expectIdentifier(object.actionId, "actionId");
  if (!isWorkOrderActionId(actionId)) {
    throw new FleetSchemaError(
      "actionId is not in the closed work-order catalog",
    );
  }
  const action = workOrderActionCatalog[actionId];
  const actionVersion = expectSafeInteger(
    object.actionVersion,
    "actionVersion",
    1,
  );
  if (actionVersion !== action.version) {
    throw new FleetSchemaError("actionVersion is not supported");
  }
  return {
    schema: expectEnum(object.schema, "schema", [
      FLEET_WORK_ORDER_RESULT_SCHEMA,
    ]),
    tenantId: expectIdentifier(object.tenantId, "tenantId"),
    deviceId: expectDeviceId(object.deviceId),
    workOrderId: expectIdentifier(object.workOrderId, "workOrderId"),
    leaseId: expectIdentifier(object.leaseId, "leaseId"),
    actionId,
    actionVersion,
    outcome: expectEnum(object.outcome, "outcome", [
      "failed",
      "rejected",
      "succeeded",
    ]),
    completedAt: expectRfc3339(object.completedAt, "completedAt"),
    resultSha256: expectSha256(object.resultSha256, "resultSha256"),
  };
}
