import { canonicalJson } from "./canonical-json.js";
import {
  FleetSchemaError,
  expectBase64Url,
  expectDeviceId,
  expectEnum,
  expectExactKeys,
  expectRecord,
  expectRfc3339,
  expectSafeInteger,
  expectString,
} from "./validation.js";

export const FLEET_ENTITLEMENT_PULL_SCHEMA =
  "dev.kernaid.fleet.entitlement-pull-request.v1" as const;
export const FLEET_ENTITLEMENT_PULL_DOMAIN =
  "kernaid:fleet:entitlement-pull:v1\0" as const;
export const ENTITLEMENT_SCHEMA = "dev.kernaid.entitlement.v1" as const;
export const ENTITLEMENT_REVOCATIONS_SCHEMA =
  "dev.kernaid.entitlement-revocations.v1" as const;
export const ENTITLEMENT_DOMAIN = "KERNAID-ENTITLEMENT-V1\0" as const;
export const ENTITLEMENT_REVOCATIONS_DOMAIN =
  "KERNAID-ENTITLEMENT-REVOCATIONS-V1\0" as const;
export const MAX_ENTITLEMENT_DOCUMENT_BYTES = 64 * 1024;

export interface EntitlementPullRequestUnsigned {
  schema: typeof FLEET_ENTITLEMENT_PULL_SCHEMA;
  tenantId: string;
  deviceId: string;
  issuedAt: string;
  nonce: string;
}

export interface EntitlementPullRequest extends EntitlementPullRequestUnsigned {
  signature: string;
}

const pullUnsignedKeys = [
  "schema",
  "tenantId",
  "deviceId",
  "issuedAt",
  "nonce",
] as const;

export function parseEntitlementPullRequest(
  value: unknown,
): EntitlementPullRequest {
  const object = expectRecord(value);
  expectExactKeys(object, [...pullUnsignedKeys, "signature"]);
  return {
    ...parseEntitlementPullUnsignedFields(object),
    signature: expectBase64Url(object.signature, "signature", 86, 86),
  };
}

export function parseEntitlementPullUnsigned(
  value: unknown,
): EntitlementPullRequestUnsigned {
  const object = expectRecord(value);
  expectExactKeys(object, pullUnsignedKeys);
  return parseEntitlementPullUnsignedFields(object);
}

export function toUnsignedEntitlementPull(
  value: EntitlementPullRequest | EntitlementPullRequestUnsigned,
): EntitlementPullRequestUnsigned {
  return {
    schema: value.schema,
    tenantId: value.tenantId,
    deviceId: value.deviceId,
    issuedAt: value.issuedAt,
    nonce: value.nonce,
  };
}

export function entitlementPullSigningBytes(
  value: EntitlementPullRequest | EntitlementPullRequestUnsigned,
): Uint8Array {
  const unsigned = parseEntitlementPullUnsigned(
    toUnsignedEntitlementPull(value),
  );
  return new TextEncoder().encode(
    `${FLEET_ENTITLEMENT_PULL_DOMAIN}${canonicalJson(unsigned)}`,
  );
}

function parseEntitlementPullUnsignedFields(
  object: Record<string, unknown>,
): EntitlementPullRequestUnsigned {
  return {
    schema: expectEnum(object.schema, "schema", [
      FLEET_ENTITLEMENT_PULL_SCHEMA,
    ]),
    tenantId: expectFleetPullIdentifier(object.tenantId, "tenantId"),
    deviceId: expectDeviceId(object.deviceId),
    issuedAt: expectRfc3339(object.issuedAt, "issuedAt"),
    nonce: expectBase64Url(object.nonce, "nonce", 22, 86),
  };
}

export const entitlementPlans = [
  "retail",
  "pro",
  "fleet",
  "enterprise",
] as const;
export const entitlementFeatures = [
  "audit",
  "consumer_repair",
  "enterprise_providers",
  "enterprise_repair",
  "fleet",
  "policy",
  "updates",
] as const;

export type EntitlementPlan = (typeof entitlementPlans)[number];
export type EntitlementFeature = (typeof entitlementFeatures)[number];

export interface EntitlementLimits {
  maxToolDevices: number;
  maxTechnicians: number;
  maxManagedAssets: number;
}

export interface EntitlementClaims {
  schema: typeof ENTITLEMENT_SCHEMA;
  entitlementId: string;
  tenantId: string;
  sequence: number;
  plan: EntitlementPlan;
  features: EntitlementFeature[];
  deviceIds: string[];
  limits: EntitlementLimits;
  issuedAtUnix: number;
  notBeforeUnix: number;
  offlineLeaseUntilUnix: number;
  expiresAtUnix: number;
  graceUntilUnix: number;
}

export interface EntitlementEnvelope {
  claims: EntitlementClaims;
  signature: string;
}

export interface EntitlementRevocationClaims {
  schema: typeof ENTITLEMENT_REVOCATIONS_SCHEMA;
  sequence: number;
  issuedAtUnix: number;
  revokedEntitlementIds: string[];
}

export interface EntitlementRevocationEnvelope {
  claims: EntitlementRevocationClaims;
  signature: string;
}

const entitlementClaimKeys = [
  "schema",
  "entitlementId",
  "tenantId",
  "sequence",
  "plan",
  "features",
  "deviceIds",
  "limits",
  "issuedAtUnix",
  "notBeforeUnix",
  "offlineLeaseUntilUnix",
  "expiresAtUnix",
  "graceUntilUnix",
] as const;

export function parseEntitlementEnvelope(value: unknown): EntitlementEnvelope {
  const object = expectRecord(value, "entitlement");
  expectExactKeys(object, ["claims", "signature"], "entitlement");
  return {
    claims: parseEntitlementClaims(object.claims),
    signature: expectBase64Url(object.signature, "signature", 86, 86),
  };
}

export function parseEntitlementClaims(value: unknown): EntitlementClaims {
  const object = expectRecord(value, "entitlement.claims");
  expectExactKeys(object, entitlementClaimKeys, "entitlement.claims");
  const issuedAtUnix = expectSafeInteger(
    object.issuedAtUnix,
    "entitlement.claims.issuedAtUnix",
    0,
  );
  const notBeforeUnix = expectSafeInteger(
    object.notBeforeUnix,
    "entitlement.claims.notBeforeUnix",
    0,
  );
  const offlineLeaseUntilUnix = expectSafeInteger(
    object.offlineLeaseUntilUnix,
    "entitlement.claims.offlineLeaseUntilUnix",
    0,
  );
  const expiresAtUnix = expectSafeInteger(
    object.expiresAtUnix,
    "entitlement.claims.expiresAtUnix",
    0,
  );
  const graceUntilUnix = expectSafeInteger(
    object.graceUntilUnix,
    "entitlement.claims.graceUntilUnix",
    0,
  );
  if (
    issuedAtUnix > notBeforeUnix ||
    notBeforeUnix > offlineLeaseUntilUnix ||
    offlineLeaseUntilUnix > expiresAtUnix ||
    expiresAtUnix > graceUntilUnix
  ) {
    throw new FleetSchemaError(
      "entitlement claims have an invalid time window",
    );
  }
  const features = parseSortedIdentifiers(
    object.features,
    "entitlement.claims.features",
    16,
    (item) =>
      expectEnum(item, "entitlement.claims.features", entitlementFeatures),
  );
  const deviceIds = parseSortedIdentifiers(
    object.deviceIds,
    "entitlement.claims.deviceIds",
    4096,
    (item) => expectEntitlementIdentifier(item, "entitlement.claims.deviceIds"),
    true,
  );
  const limits = parseEntitlementLimits(object.limits);
  if (deviceIds.length > limits.maxToolDevices) {
    throw new FleetSchemaError(
      "entitlement device assignment exceeds its limit",
    );
  }
  return {
    schema: expectEnum(object.schema, "entitlement.claims.schema", [
      ENTITLEMENT_SCHEMA,
    ]),
    entitlementId: expectEntitlementIdentifier(
      object.entitlementId,
      "entitlement.claims.entitlementId",
    ),
    tenantId: expectEntitlementIdentifier(
      object.tenantId,
      "entitlement.claims.tenantId",
    ),
    sequence: expectSafeInteger(
      object.sequence,
      "entitlement.claims.sequence",
      1,
    ),
    plan: expectEnum(object.plan, "entitlement.claims.plan", entitlementPlans),
    features,
    deviceIds,
    limits,
    issuedAtUnix,
    notBeforeUnix,
    offlineLeaseUntilUnix,
    expiresAtUnix,
    graceUntilUnix,
  };
}

function parseEntitlementLimits(value: unknown): EntitlementLimits {
  const object = expectRecord(value, "entitlement.claims.limits");
  expectExactKeys(
    object,
    ["maxToolDevices", "maxTechnicians", "maxManagedAssets"],
    "entitlement.claims.limits",
  );
  return {
    maxToolDevices: expectU32(
      object.maxToolDevices,
      "entitlement.claims.limits.maxToolDevices",
    ),
    maxTechnicians: expectU32(
      object.maxTechnicians,
      "entitlement.claims.limits.maxTechnicians",
    ),
    maxManagedAssets: expectU32(
      object.maxManagedAssets,
      "entitlement.claims.limits.maxManagedAssets",
    ),
  };
}

export function parseEntitlementRevocationEnvelope(
  value: unknown,
): EntitlementRevocationEnvelope {
  const object = expectRecord(value, "entitlement revocations");
  expectExactKeys(object, ["claims", "signature"], "entitlement revocations");
  return {
    claims: parseEntitlementRevocationClaims(object.claims),
    signature: expectBase64Url(object.signature, "signature", 86, 86),
  };
}

export function parseEntitlementRevocationClaims(
  value: unknown,
): EntitlementRevocationClaims {
  const object = expectRecord(value, "entitlement revocation claims");
  expectExactKeys(
    object,
    ["schema", "sequence", "issuedAtUnix", "revokedEntitlementIds"],
    "entitlement revocation claims",
  );
  return {
    schema: expectEnum(object.schema, "revocation.claims.schema", [
      ENTITLEMENT_REVOCATIONS_SCHEMA,
    ]),
    sequence: expectSafeInteger(
      object.sequence,
      "revocation.claims.sequence",
      1,
    ),
    issuedAtUnix: expectSafeInteger(
      object.issuedAtUnix,
      "revocation.claims.issuedAtUnix",
      0,
    ),
    revokedEntitlementIds: parseSortedIdentifiers(
      object.revokedEntitlementIds,
      "revocation.claims.revokedEntitlementIds",
      65_536,
      (item) =>
        expectEntitlementIdentifier(
          item,
          "revocation.claims.revokedEntitlementIds",
        ),
    ),
  };
}

/** Exact Rust entitlement framing: domain || uint64-be(length) || claims. */
export function entitlementSigningBytes(
  value: EntitlementEnvelope | EntitlementClaims,
): Uint8Array {
  const claims = parseEntitlementClaims(
    "claims" in value ? value.claims : value,
  );
  return framedSigningBytes(ENTITLEMENT_DOMAIN, claims);
}

/** Exact Rust revocation framing: domain || uint64-be(length) || claims. */
export function entitlementRevocationSigningBytes(
  value: EntitlementRevocationEnvelope | EntitlementRevocationClaims,
): Uint8Array {
  const claims = parseEntitlementRevocationClaims(
    "claims" in value ? value.claims : value,
  );
  return framedSigningBytes(ENTITLEMENT_REVOCATIONS_DOMAIN, claims);
}

export function entitlementAppliesTo(
  envelope: EntitlementEnvelope,
  deviceId: string,
): boolean {
  const parsed = parseEntitlementEnvelope(envelope);
  expectDeviceId(deviceId);
  return parsed.claims.deviceIds.includes(deviceId);
}

function framedSigningBytes(domain: string, claims: unknown): Uint8Array {
  const canonical = new TextEncoder().encode(canonicalJson(claims));
  const output = new Uint8Array(
    new TextEncoder().encode(domain).length + 8 + canonical.length,
  );
  const encodedDomain = new TextEncoder().encode(domain);
  output.set(encodedDomain, 0);
  new DataView(output.buffer).setBigUint64(
    encodedDomain.length,
    BigInt(canonical.length),
    false,
  );
  output.set(canonical, encodedDomain.length + 8);
  return output;
}

function expectU32(value: unknown, field: string): number {
  const integer = expectSafeInteger(value, field, 1);
  if (integer > 0xffff_ffff) {
    throw new FleetSchemaError(`${field} exceeds uint32`);
  }
  return integer;
}

function expectEntitlementIdentifier(value: unknown, field: string): string {
  const identifier = expectString(value, field, 1, 128);
  if (!/^[A-Za-z0-9._:-]+$/.test(identifier)) {
    throw new FleetSchemaError(
      `${field} is not a valid entitlement identifier`,
    );
  }
  return identifier;
}

function expectFleetPullIdentifier(value: unknown, field: string): string {
  const identifier = expectString(value, field, 1, 128);
  if (!/^[A-Za-z0-9._:/-]+$/.test(identifier)) {
    throw new FleetSchemaError(`${field} is not a valid fleet identifier`);
  }
  return identifier;
}

function parseSortedIdentifiers<T extends string>(
  value: unknown,
  field: string,
  maximum: number,
  parse: (item: unknown) => T,
  requireNonempty = false,
): T[] {
  if (
    !Array.isArray(value) ||
    value.length > maximum ||
    (requireNonempty && value.length === 0)
  ) {
    throw new FleetSchemaError(`${field} exceeds its bounds`);
  }
  const items = value.map(parse);
  if (items.some((item, index) => index > 0 && items[index - 1]! >= item)) {
    throw new FleetSchemaError(`${field} must be sorted and duplicate-free`);
  }
  return items;
}
