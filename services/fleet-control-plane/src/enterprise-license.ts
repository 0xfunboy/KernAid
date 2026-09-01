import type { KeyObject } from "node:crypto";
import { canonicalJson } from "@kernaid/fleet-schemas";
import { importEd25519Raw, signEd25519, verifyEd25519 } from "./crypto.js";

export const ENTERPRISE_LICENSE_SCHEMA =
  "dev.kernaid.fleet.enterprise-license.v1";
export const ENTERPRISE_LICENSE_DOMAIN = Buffer.from(
  "kernaid:fleet:enterprise-license:v1\0",
  "utf8",
);
export const MAX_ENTERPRISE_LICENSE_BYTES = 16 * 1024;
export const ENTERPRISE_CLOCK_ROLLBACK_TOLERANCE_SECONDS = 300;

export const enterpriseLicenseFeatures = [
  "device_management",
  "entitlements",
  "incidents",
  "policy",
  "remote_diagnosis",
  "remote_repair",
  "technician_seats",
  "updates",
] as const;

export type EnterpriseLicenseFeature =
  (typeof enterpriseLicenseFeatures)[number];
export type EnterpriseLicensePlan = "fleet" | "enterprise";
export type EnterpriseLicenseState =
  | "active"
  | "clock_rollback"
  | "expired"
  | "grace"
  | "not_yet_valid"
  | "revoked";

export interface EnterpriseLicenseClaims {
  schema: typeof ENTERPRISE_LICENSE_SCHEMA;
  version: 1;
  licenseId: string;
  tenantId: string;
  sequence: number;
  keyId: string;
  plan: EnterpriseLicensePlan;
  features: EnterpriseLicenseFeature[];
  deviceLimit: number;
  seatLimit: number;
  issuedAtUnix: number;
  notBeforeUnix: number;
  expiresAtUnix: number;
  graceUntilUnix: number;
}

export interface EnterpriseLicenseEnvelope {
  claims: EnterpriseLicenseClaims;
  signature: string;
}

export interface EnterpriseLicenseEvaluation {
  state: EnterpriseLicenseState;
  operationsAllowed: boolean;
  evaluatedAtUnix: number;
  retainedClockUnix: number;
}

export class EnterpriseLicenseSchemaError extends Error {}

export function parseEnterpriseLicenseEnvelope(
  value: unknown,
): EnterpriseLicenseEnvelope {
  const envelope = record(value, "enterprise license");
  exactKeys(envelope, ["claims", "signature"], "enterprise license");
  const claims = parseEnterpriseLicenseClaims(envelope.claims);
  const signature = canonicalBase64Url(envelope.signature, "signature", 64);
  return { claims, signature };
}

export function parseEnterpriseLicenseClaims(
  value: unknown,
): EnterpriseLicenseClaims {
  const claims = record(value, "enterprise license claims");
  exactKeys(
    claims,
    [
      "schema",
      "version",
      "licenseId",
      "tenantId",
      "sequence",
      "keyId",
      "plan",
      "features",
      "deviceLimit",
      "seatLimit",
      "issuedAtUnix",
      "notBeforeUnix",
      "expiresAtUnix",
      "graceUntilUnix",
    ],
    "enterprise license claims",
  );
  if (claims.schema !== ENTERPRISE_LICENSE_SCHEMA || claims.version !== 1) {
    throw new EnterpriseLicenseSchemaError(
      "unsupported enterprise license schema",
    );
  }
  const licenseId = identifier(claims.licenseId, "licenseId");
  const tenantId = identifier(claims.tenantId, "tenantId");
  const sequence = safeInteger(claims.sequence, "sequence", 1, 2 ** 31 - 1);
  const keyId = identifier(claims.keyId, "keyId");
  if (claims.plan !== "fleet" && claims.plan !== "enterprise") {
    throw new EnterpriseLicenseSchemaError("plan is invalid");
  }
  if (
    !Array.isArray(claims.features) ||
    claims.features.length < 1 ||
    claims.features.length > enterpriseLicenseFeatures.length
  ) {
    throw new EnterpriseLicenseSchemaError("features are invalid");
  }
  const features = claims.features.map((feature) => {
    if (
      typeof feature !== "string" ||
      !(enterpriseLicenseFeatures as readonly string[]).includes(feature)
    ) {
      throw new EnterpriseLicenseSchemaError("feature is invalid");
    }
    return feature as EnterpriseLicenseFeature;
  });
  if (
    new Set(features).size !== features.length ||
    features.some(
      (feature, index) => index > 0 && features[index - 1]! >= feature,
    )
  ) {
    throw new EnterpriseLicenseSchemaError(
      "features must be unique and sorted",
    );
  }
  const deviceLimit = safeInteger(
    claims.deviceLimit,
    "deviceLimit",
    1,
    100_000,
  );
  const seatLimit = safeInteger(claims.seatLimit, "seatLimit", 1, 10_000);
  const issuedAtUnix = safeInteger(
    claims.issuedAtUnix,
    "issuedAtUnix",
    0,
    4_102_444_800,
  );
  const notBeforeUnix = safeInteger(
    claims.notBeforeUnix,
    "notBeforeUnix",
    0,
    4_102_444_800,
  );
  const expiresAtUnix = safeInteger(
    claims.expiresAtUnix,
    "expiresAtUnix",
    0,
    4_102_444_800,
  );
  const graceUntilUnix = safeInteger(
    claims.graceUntilUnix,
    "graceUntilUnix",
    0,
    4_102_444_800,
  );
  if (
    issuedAtUnix > notBeforeUnix ||
    notBeforeUnix >= expiresAtUnix ||
    expiresAtUnix > graceUntilUnix
  ) {
    throw new EnterpriseLicenseSchemaError("license time window is invalid");
  }
  return {
    schema: ENTERPRISE_LICENSE_SCHEMA,
    version: 1,
    licenseId,
    tenantId,
    sequence,
    keyId,
    plan: claims.plan,
    features,
    deviceLimit,
    seatLimit,
    issuedAtUnix,
    notBeforeUnix,
    expiresAtUnix,
    graceUntilUnix,
  };
}

export function enterpriseLicenseSigningBytes(
  value: EnterpriseLicenseClaims | EnterpriseLicenseEnvelope,
): Buffer {
  const claims = "claims" in value ? value.claims : value;
  const body = Buffer.from(canonicalJson(claims), "utf8");
  const length = Buffer.alloc(8);
  length.writeBigUInt64BE(BigInt(body.length));
  return Buffer.concat([ENTERPRISE_LICENSE_DOMAIN, length, body]);
}

export function signEnterpriseLicense(
  claims: EnterpriseLicenseClaims,
  privateKey: KeyObject,
): EnterpriseLicenseEnvelope {
  const parsed = parseEnterpriseLicenseClaims(claims);
  return {
    claims: parsed,
    signature: signEd25519(privateKey, enterpriseLicenseSigningBytes(parsed)),
  };
}

export function verifyEnterpriseLicense(
  envelope: EnterpriseLicenseEnvelope,
  trustAnchor: string | KeyObject,
  expectedKeyId: string,
  expectedTenantId?: string,
): boolean {
  const parsed = parseEnterpriseLicenseEnvelope(envelope);
  if (
    parsed.claims.keyId !== expectedKeyId ||
    (expectedTenantId !== undefined &&
      parsed.claims.tenantId !== expectedTenantId)
  ) {
    return false;
  }
  const key =
    typeof trustAnchor === "string"
      ? importEd25519Raw(trustAnchor)
      : trustAnchor;
  return verifyEd25519(
    key,
    enterpriseLicenseSigningBytes(parsed),
    parsed.signature,
  );
}

export function evaluateEnterpriseLicense(
  claims: EnterpriseLicenseClaims,
  input: {
    nowUnix: number;
    retainedClockUnix: number;
    revoked: boolean;
    rollbackToleranceSeconds?: number;
  },
): EnterpriseLicenseEvaluation {
  const nowUnix = safeInteger(input.nowUnix, "nowUnix", 0, 4_102_444_800);
  const retainedClockUnix = safeInteger(
    input.retainedClockUnix,
    "retainedClockUnix",
    0,
    4_102_444_800,
  );
  const tolerance =
    input.rollbackToleranceSeconds ??
    ENTERPRISE_CLOCK_ROLLBACK_TOLERANCE_SECONDS;
  safeInteger(tolerance, "rollbackToleranceSeconds", 0, 86_400);
  const evaluatedAtUnix = Math.max(nowUnix, retainedClockUnix);
  let state: EnterpriseLicenseState;
  if (input.revoked) state = "revoked";
  else if (nowUnix + tolerance < retainedClockUnix) state = "clock_rollback";
  else if (evaluatedAtUnix < claims.notBeforeUnix) state = "not_yet_valid";
  else if (evaluatedAtUnix < claims.expiresAtUnix) state = "active";
  else if (evaluatedAtUnix < claims.graceUntilUnix) state = "grace";
  else state = "expired";
  return {
    state,
    operationsAllowed: state === "active",
    evaluatedAtUnix,
    retainedClockUnix,
  };
}

function record(value: unknown, label: string): Record<string, unknown> {
  if (value === null || typeof value !== "object" || Array.isArray(value)) {
    throw new EnterpriseLicenseSchemaError(`${label} must be an object`);
  }
  return value as Record<string, unknown>;
}

function exactKeys(
  value: Record<string, unknown>,
  expected: readonly string[],
  label: string,
): void {
  const actual = Object.keys(value).sort();
  const wanted = [...expected].sort();
  if (
    actual.length !== wanted.length ||
    actual.some((entry, index) => entry !== wanted[index])
  ) {
    throw new EnterpriseLicenseSchemaError(`${label} fields are invalid`);
  }
}

function identifier(value: unknown, label: string): string {
  if (
    typeof value !== "string" ||
    value.length < 1 ||
    value.length > 128 ||
    !/^[A-Za-z0-9][A-Za-z0-9._:-]*$/.test(value)
  ) {
    throw new EnterpriseLicenseSchemaError(`${label} is invalid`);
  }
  return value;
}

function safeInteger(
  value: unknown,
  label: string,
  minimum: number,
  maximum: number,
): number {
  if (
    typeof value !== "number" ||
    !Number.isSafeInteger(value) ||
    value < minimum ||
    value > maximum
  ) {
    throw new EnterpriseLicenseSchemaError(`${label} is invalid`);
  }
  return value;
}

function canonicalBase64Url(
  value: unknown,
  label: string,
  bytes: number,
): string {
  if (typeof value !== "string" || !/^[A-Za-z0-9_-]+$/.test(value)) {
    throw new EnterpriseLicenseSchemaError(`${label} is invalid`);
  }
  const decoded = Buffer.from(value, "base64url");
  if (decoded.length !== bytes || decoded.toString("base64url") !== value) {
    throw new EnterpriseLicenseSchemaError(`${label} is not canonical`);
  }
  return value;
}
