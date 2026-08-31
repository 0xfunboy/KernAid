import { canonicalJson } from "./canonical-json.js";
import {
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

export const FLEET_SERVICE_RECEIPT_SCHEMA =
  "dev.kernaid.fleet.service-receipt.v1" as const;
export const FLEET_SERVICE_RECEIPT_DOMAIN =
  "kernaid:fleet:service-receipt:v1\0" as const;

export const fleetServiceOperations = [
  "inventory",
  "audit",
  "policy_pull",
  "entitlement_pull",
  "work_order_claim",
  "work_order_result",
] as const;
export type FleetServiceOperation = (typeof fleetServiceOperations)[number];

export interface ServiceReceiptUnsigned {
  schema: typeof FLEET_SERVICE_RECEIPT_SCHEMA;
  tenantId: string;
  deviceId: string;
  operation: FleetServiceOperation;
  sequence: number;
  requestSha256: string;
  responseSha256: string;
  acceptedAt: string;
  outcome: "accepted";
}

export interface ServiceReceipt extends ServiceReceiptUnsigned {
  signature: string;
}

const unsignedKeys = [
  "schema",
  "tenantId",
  "deviceId",
  "operation",
  "sequence",
  "requestSha256",
  "responseSha256",
  "acceptedAt",
  "outcome",
] as const;

export function parseServiceReceipt(value: unknown): ServiceReceipt {
  const object = expectRecord(value);
  expectExactKeys(object, [...unsignedKeys, "signature"]);
  return {
    ...parseServiceReceiptUnsignedFields(object),
    signature: expectBase64Url(object.signature, "signature", 86, 86),
  };
}

export function parseServiceReceiptUnsigned(
  value: unknown,
): ServiceReceiptUnsigned {
  const object = expectRecord(value);
  expectExactKeys(object, unsignedKeys);
  return parseServiceReceiptUnsignedFields(object);
}

export function serviceReceiptSigningBytes(
  value: ServiceReceipt | ServiceReceiptUnsigned,
): Uint8Array {
  const unsigned = parseServiceReceiptUnsigned(toUnsignedServiceReceipt(value));
  return new TextEncoder().encode(
    `${FLEET_SERVICE_RECEIPT_DOMAIN}${canonicalJson(unsigned)}`,
  );
}

export function toUnsignedServiceReceipt(
  value: ServiceReceipt | ServiceReceiptUnsigned,
): ServiceReceiptUnsigned {
  return {
    schema: value.schema,
    tenantId: value.tenantId,
    deviceId: value.deviceId,
    operation: value.operation,
    sequence: value.sequence,
    requestSha256: value.requestSha256,
    responseSha256: value.responseSha256,
    acceptedAt: value.acceptedAt,
    outcome: value.outcome,
  };
}

function parseServiceReceiptUnsignedFields(
  object: Record<string, unknown>,
): ServiceReceiptUnsigned {
  return {
    schema: expectEnum(object.schema, "schema", [FLEET_SERVICE_RECEIPT_SCHEMA]),
    tenantId: expectIdentifier(object.tenantId, "tenantId"),
    deviceId: expectDeviceId(object.deviceId),
    operation: expectEnum(
      object.operation,
      "operation",
      fleetServiceOperations,
    ),
    sequence: expectSafeInteger(object.sequence, "sequence", 1),
    requestSha256: expectSha256(object.requestSha256, "requestSha256"),
    responseSha256: expectSha256(object.responseSha256, "responseSha256"),
    acceptedAt: expectRfc3339(object.acceptedAt, "acceptedAt"),
    outcome: expectEnum(object.outcome, "outcome", ["accepted"]),
  };
}
