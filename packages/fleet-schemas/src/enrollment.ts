import { canonicalJson } from "./canonical-json.js";
import {
  expectBase64Url,
  expectDeviceId,
  expectEnum,
  expectExactKeys,
  expectIdentifier,
  expectRecord,
  expectRfc3339,
  expectString,
} from "./validation.js";

export const FLEET_ENROLLMENT_SCHEMA =
  "dev.kernaid.fleet.enrollment-request.v1" as const;
export const FLEET_ENROLLMENT_DOMAIN = "kernaid:fleet:enrollment:v1\0" as const;

export const enrollmentPlatforms = [
  "rescue",
  "windows",
  "linux",
  "macos",
] as const;
export type EnrollmentPlatform = (typeof enrollmentPlatforms)[number];

export interface EnrollmentRequestUnsigned {
  schema: typeof FLEET_ENROLLMENT_SCHEMA;
  enrollmentToken: string;
  tenantId: string;
  deviceId: string;
  publicKeySpki: string;
  platform: EnrollmentPlatform;
  agentVersion: string;
  issuedAt: string;
  nonce: string;
}

export interface EnrollmentRequest extends EnrollmentRequestUnsigned {
  signature: string;
}

const unsignedKeys = [
  "schema",
  "enrollmentToken",
  "tenantId",
  "deviceId",
  "publicKeySpki",
  "platform",
  "agentVersion",
  "issuedAt",
  "nonce",
] as const;

export function parseEnrollmentRequest(value: unknown): EnrollmentRequest {
  const object = expectRecord(value);
  expectExactKeys(object, [...unsignedKeys, "signature"]);
  return {
    ...parseEnrollmentUnsignedFields(object),
    signature: expectBase64Url(object.signature, "signature", 86, 86),
  };
}

export function parseEnrollmentUnsigned(
  value: unknown,
): EnrollmentRequestUnsigned {
  const object = expectRecord(value);
  expectExactKeys(object, unsignedKeys);
  return parseEnrollmentUnsignedFields(object);
}

export function enrollmentSigningBytes(
  value: EnrollmentRequest | EnrollmentRequestUnsigned,
): Uint8Array {
  const unsigned = parseEnrollmentUnsigned(toUnsignedEnrollment(value));
  return new TextEncoder().encode(
    `${FLEET_ENROLLMENT_DOMAIN}${canonicalJson(unsigned)}`,
  );
}

export function toUnsignedEnrollment(
  value: EnrollmentRequest | EnrollmentRequestUnsigned,
): EnrollmentRequestUnsigned {
  return {
    schema: value.schema,
    enrollmentToken: value.enrollmentToken,
    tenantId: value.tenantId,
    deviceId: value.deviceId,
    publicKeySpki: value.publicKeySpki,
    platform: value.platform,
    agentVersion: value.agentVersion,
    issuedAt: value.issuedAt,
    nonce: value.nonce,
  };
}

function parseEnrollmentUnsignedFields(
  object: Record<string, unknown>,
): EnrollmentRequestUnsigned {
  return {
    schema: expectEnum(object.schema, "schema", [FLEET_ENROLLMENT_SCHEMA]),
    enrollmentToken: expectBase64Url(
      object.enrollmentToken,
      "enrollmentToken",
      32,
      512,
    ),
    tenantId: expectIdentifier(object.tenantId, "tenantId"),
    deviceId: expectDeviceId(object.deviceId),
    publicKeySpki: expectBase64Url(
      object.publicKeySpki,
      "publicKeySpki",
      40,
      512,
    ),
    platform: expectEnum(object.platform, "platform", enrollmentPlatforms),
    agentVersion: expectString(object.agentVersion, "agentVersion", 1, 64),
    issuedAt: expectRfc3339(object.issuedAt, "issuedAt"),
    nonce: expectBase64Url(object.nonce, "nonce", 22, 86),
  };
}
