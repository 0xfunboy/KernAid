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
  expectString,
} from "./validation.js";

export const FLEET_POLICY_PULL_SCHEMA =
  "dev.kernaid.fleet.policy-pull-request.v1" as const;
export const FLEET_POLICY_PULL_DOMAIN =
  "kernaid:fleet:policy-pull:v1\0" as const;
export const FLEET_POLICY_BUNDLE_SCHEMA =
  "dev.kernaid.fleet.policy-bundle.v1" as const;
export const FLEET_POLICY_BUNDLE_DOMAIN = "kernaid:fleet:policy:v1\0" as const;
export const MAX_POLICY_BUNDLE_BYTES = 1024 * 1024;

export interface PolicyPullRequestUnsigned {
  schema: typeof FLEET_POLICY_PULL_SCHEMA;
  tenantId: string;
  deviceId: string;
  issuedAt: string;
  nonce: string;
}

export interface PolicyPullRequest extends PolicyPullRequestUnsigned {
  signature: string;
}

const pullUnsignedKeys = [
  "schema",
  "tenantId",
  "deviceId",
  "issuedAt",
  "nonce",
] as const;

export function parsePolicyPullRequest(value: unknown): PolicyPullRequest {
  const object = expectRecord(value);
  expectExactKeys(object, [...pullUnsignedKeys, "signature"]);
  return {
    ...parsePolicyPullUnsignedFields(object),
    signature: expectBase64Url(object.signature, "signature", 86, 86),
  };
}

export function parsePolicyPullUnsigned(
  value: unknown,
): PolicyPullRequestUnsigned {
  const object = expectRecord(value);
  expectExactKeys(object, pullUnsignedKeys);
  return parsePolicyPullUnsignedFields(object);
}

export function toUnsignedPolicyPull(
  value: PolicyPullRequest | PolicyPullRequestUnsigned,
): PolicyPullRequestUnsigned {
  return {
    schema: value.schema,
    tenantId: value.tenantId,
    deviceId: value.deviceId,
    issuedAt: value.issuedAt,
    nonce: value.nonce,
  };
}

export function policyPullSigningBytes(
  value: PolicyPullRequest | PolicyPullRequestUnsigned,
): Uint8Array {
  const unsigned = parsePolicyPullUnsigned(toUnsignedPolicyPull(value));
  return new TextEncoder().encode(
    `${FLEET_POLICY_PULL_DOMAIN}${canonicalJson(unsigned)}`,
  );
}

function parsePolicyPullUnsignedFields(
  object: Record<string, unknown>,
): PolicyPullRequestUnsigned {
  return {
    schema: expectEnum(object.schema, "schema", [FLEET_POLICY_PULL_SCHEMA]),
    tenantId: expectIdentifier(object.tenantId, "tenantId"),
    deviceId: expectDeviceId(object.deviceId),
    issuedAt: expectRfc3339(object.issuedAt, "issuedAt"),
    nonce: expectBase64Url(object.nonce, "nonce", 22, 86),
  };
}

export const policyRiskLevels = ["R0", "R1", "R2", "R3"] as const;
export const policyProviderModes = [
  "anthropic_api",
  "enterprise",
  "gemini_api",
  "offline",
  "openai_api",
  "openai_compatible",
] as const;
export const policyUpdateRings = ["hold", "canary", "stable"] as const;

export type PolicyRiskLevel = (typeof policyRiskLevels)[number];
export type PolicyProviderMode = (typeof policyProviderModes)[number];
export type PolicyUpdateRing = (typeof policyUpdateRings)[number];

export type PolicyAssignments = { all: true } | { deviceIds: string[] };

export interface FleetPolicyRules {
  maxRisk: PolicyRiskLevel;
  localApprovalFrom: PolicyRiskLevel;
  allowedActionIds: string[];
  deniedActionIds: string[];
  allowEvidenceUpload: boolean;
  retentionDays: number;
  providerModes: PolicyProviderMode[];
  updateRing: PolicyUpdateRing;
  emergencyRollbackAlwaysAllowed: true;
}

export interface SignedPolicyBundleUnsigned {
  schema: typeof FLEET_POLICY_BUNDLE_SCHEMA;
  tenantId: string;
  policyId: string;
  revision: number;
  issuedAtUnix: number;
  notBeforeUnix: number;
  offlineAllowedUntilUnix: number;
  expiresAtUnix: number;
  assignments: PolicyAssignments;
  rules: FleetPolicyRules;
}

export interface SignedPolicyBundle extends SignedPolicyBundleUnsigned {
  signature: string;
}

const policyUnsignedKeys = [
  "schema",
  "tenantId",
  "policyId",
  "revision",
  "issuedAtUnix",
  "notBeforeUnix",
  "offlineAllowedUntilUnix",
  "expiresAtUnix",
  "assignments",
  "rules",
] as const;

export function parseSignedPolicyBundle(value: unknown): SignedPolicyBundle {
  const object = expectRecord(value, "policy");
  expectExactKeys(object, [...policyUnsignedKeys, "signature"], "policy");
  return {
    ...parsePolicyUnsignedFields(object),
    signature: expectBase64Url(object.signature, "signature", 86, 86),
  };
}

export function parseSignedPolicyBundleUnsigned(
  value: unknown,
): SignedPolicyBundleUnsigned {
  const object = expectRecord(value, "policy");
  expectExactKeys(object, policyUnsignedKeys, "policy");
  return parsePolicyUnsignedFields(object);
}

export function toUnsignedPolicyBundle(
  value: SignedPolicyBundle | SignedPolicyBundleUnsigned,
): SignedPolicyBundleUnsigned {
  return {
    schema: value.schema,
    tenantId: value.tenantId,
    policyId: value.policyId,
    revision: value.revision,
    issuedAtUnix: value.issuedAtUnix,
    notBeforeUnix: value.notBeforeUnix,
    offlineAllowedUntilUnix: value.offlineAllowedUntilUnix,
    expiresAtUnix: value.expiresAtUnix,
    assignments:
      "all" in value.assignments
        ? { all: true }
        : { deviceIds: [...value.assignments.deviceIds] },
    rules: {
      ...value.rules,
      allowedActionIds: [...value.rules.allowedActionIds],
      deniedActionIds: [...value.rules.deniedActionIds],
      providerModes: [...value.rules.providerModes],
    },
  };
}

/** Exact Rust policy framing: domain || uint64-be(length) || canonical. */
export function policyBundleSigningBytes(
  value: SignedPolicyBundle | SignedPolicyBundleUnsigned,
): Uint8Array {
  const unsigned = parseSignedPolicyBundleUnsigned(
    toUnsignedPolicyBundle(value),
  );
  const canonical = new TextEncoder().encode(canonicalJson(unsigned));
  return concatenate([
    new TextEncoder().encode(FLEET_POLICY_BUNDLE_DOMAIN),
    encodeUnsignedBigEndian(canonical.length, 8),
    canonical,
  ]);
}

export function policyAppliesTo(
  bundle: SignedPolicyBundle,
  deviceId: string,
): boolean {
  expectDeviceId(deviceId);
  return "all" in bundle.assignments
    ? true
    : bundle.assignments.deviceIds.includes(deviceId);
}

function parsePolicyUnsignedFields(
  object: Record<string, unknown>,
): SignedPolicyBundleUnsigned {
  const issuedAtUnix = expectSafeInteger(
    object.issuedAtUnix,
    "policy.issuedAtUnix",
    1,
  );
  const notBeforeUnix = expectSafeInteger(
    object.notBeforeUnix,
    "policy.notBeforeUnix",
    1,
  );
  const offlineAllowedUntilUnix = expectSafeInteger(
    object.offlineAllowedUntilUnix,
    "policy.offlineAllowedUntilUnix",
    1,
  );
  const expiresAtUnix = expectSafeInteger(
    object.expiresAtUnix,
    "policy.expiresAtUnix",
    1,
  );
  if (
    issuedAtUnix > notBeforeUnix ||
    notBeforeUnix > offlineAllowedUntilUnix ||
    offlineAllowedUntilUnix > expiresAtUnix
  ) {
    throw new FleetSchemaError("policy has an invalid time window");
  }
  return {
    schema: expectEnum(object.schema, "policy.schema", [
      FLEET_POLICY_BUNDLE_SCHEMA,
    ]),
    tenantId: expectPolicyIdentifier(object.tenantId, "policy.tenantId"),
    policyId: expectPolicyIdentifier(object.policyId, "policy.policyId"),
    revision: expectSafeInteger(object.revision, "policy.revision", 1),
    issuedAtUnix,
    notBeforeUnix,
    offlineAllowedUntilUnix,
    expiresAtUnix,
    assignments: parseAssignments(object.assignments),
    rules: parseRules(object.rules),
  };
}

function parseAssignments(value: unknown): PolicyAssignments {
  const object = expectRecord(value, "policy.assignments");
  const keys = Object.keys(object);
  if (keys.length !== 1) {
    throw new FleetSchemaError("policy.assignments must select one target set");
  }
  if (keys[0] === "all" && object.all === true) return { all: true };
  if (keys[0] !== "deviceIds" || !Array.isArray(object.deviceIds)) {
    throw new FleetSchemaError("policy.assignments must select one target set");
  }
  if (object.deviceIds.length === 0 || object.deviceIds.length > 4096) {
    throw new FleetSchemaError("policy.assignments exceeds its bounds");
  }
  const deviceIds = object.deviceIds.map((item) => expectDeviceId(item));
  expectSortedUnique(deviceIds, "policy.assignments.deviceIds");
  return { deviceIds };
}

function parseRules(value: unknown): FleetPolicyRules {
  const object = expectRecord(value, "policy.rules");
  expectExactKeys(
    object,
    [
      "maxRisk",
      "localApprovalFrom",
      "allowedActionIds",
      "deniedActionIds",
      "allowEvidenceUpload",
      "retentionDays",
      "providerModes",
      "updateRing",
      "emergencyRollbackAlwaysAllowed",
    ],
    "policy.rules",
  );
  const allowedActionIds = parsePolicyIdentifiers(
    object.allowedActionIds,
    "policy.rules.allowedActionIds",
    1024,
  );
  const deniedActionIds = parsePolicyIdentifiers(
    object.deniedActionIds,
    "policy.rules.deniedActionIds",
    1024,
  );
  if (allowedActionIds.some((action) => deniedActionIds.includes(action))) {
    throw new FleetSchemaError("policy action allow and deny lists overlap");
  }
  if (typeof object.allowEvidenceUpload !== "boolean") {
    throw new FleetSchemaError("policy.rules.allowEvidenceUpload is invalid");
  }
  const retentionDays = expectSafeInteger(
    object.retentionDays,
    "policy.rules.retentionDays",
    1,
  );
  if (retentionDays > 3650) {
    throw new FleetSchemaError("policy.rules.retentionDays is invalid");
  }
  if (
    !Array.isArray(object.providerModes) ||
    object.providerModes.length === 0 ||
    object.providerModes.length > policyProviderModes.length
  ) {
    throw new FleetSchemaError("policy.rules.providerModes is invalid");
  }
  const providerModes = object.providerModes.map((item) =>
    expectEnum(item, "policy.rules.providerModes", policyProviderModes),
  );
  expectSortedUnique(providerModes, "policy.rules.providerModes");
  if (object.emergencyRollbackAlwaysAllowed !== true) {
    throw new FleetSchemaError(
      "policy.rules.emergencyRollbackAlwaysAllowed must be true",
    );
  }
  return {
    maxRisk: expectEnum(
      object.maxRisk,
      "policy.rules.maxRisk",
      policyRiskLevels,
    ),
    localApprovalFrom: expectEnum(
      object.localApprovalFrom,
      "policy.rules.localApprovalFrom",
      policyRiskLevels,
    ),
    allowedActionIds,
    deniedActionIds,
    allowEvidenceUpload: object.allowEvidenceUpload,
    retentionDays,
    providerModes,
    updateRing: expectEnum(
      object.updateRing,
      "policy.rules.updateRing",
      policyUpdateRings,
    ),
    emergencyRollbackAlwaysAllowed: true,
  };
}

function parsePolicyIdentifiers(
  value: unknown,
  field: string,
  maximum: number,
): string[] {
  if (!Array.isArray(value) || value.length > maximum) {
    throw new FleetSchemaError(`${field} exceeds its bounds`);
  }
  const identifiers = value.map((item) => expectPolicyIdentifier(item, field));
  expectSortedUnique(identifiers, field);
  return identifiers;
}

function expectPolicyIdentifier(value: unknown, field: string): string {
  const identifier = expectString(value, field, 1, 160);
  if (!/^[A-Za-z0-9._:/-]+$/.test(identifier)) {
    throw new FleetSchemaError(`${field} is not a valid policy identifier`);
  }
  return identifier;
}

function expectSortedUnique(values: readonly string[], field: string): void {
  if (values.some((value, index) => index > 0 && values[index - 1]! >= value)) {
    throw new FleetSchemaError(`${field} must be sorted and duplicate-free`);
  }
}

function encodeUnsignedBigEndian(value: number, bytes: number): Uint8Array {
  if (!Number.isSafeInteger(value) || value < 0) {
    throw new TypeError("length must be a non-negative safe integer");
  }
  const encoded = new Uint8Array(bytes);
  let remaining = BigInt(value);
  for (let index = bytes - 1; index >= 0; index -= 1) {
    encoded[index] = Number(remaining & 0xffn);
    remaining >>= 8n;
  }
  if (remaining !== 0n) throw new TypeError("length exceeds framing width");
  return encoded;
}

function concatenate(parts: readonly Uint8Array[]): Uint8Array {
  const length = parts.reduce((total, part) => total + part.length, 0);
  const output = new Uint8Array(length);
  let offset = 0;
  for (const part of parts) {
    output.set(part, offset);
    offset += part.length;
  }
  return output;
}
