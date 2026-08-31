import { createHash } from "node:crypto";
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
  expectString,
} from "./validation.js";

export const UPDATE_MANIFEST_SCHEMA = "dev.kernaid.update.manifest.v1" as const;
export const UPDATE_MANIFEST_DOMAIN = "kernaid:update:manifest:v1\0" as const;
export const MAX_UPDATE_MANIFEST_BYTES = 64 * 1024;
export const FLEET_UPDATE_PULL_SCHEMA =
  "dev.kernaid.fleet.update-pull-request.v1" as const;
export const FLEET_UPDATE_PULL_DOMAIN =
  "kernaid:fleet:update-pull:v1\0" as const;
export const FLEET_UPDATE_PULL_RESPONSE_SCHEMA =
  "dev.kernaid.fleet.update-pull-response.v1" as const;

export const updatePlatforms = ["rescue", "windows", "linux", "macos"] as const;
export const updateArchitectures = ["x86_64", "aarch64"] as const;
export const releaseRings = ["canary", "stable"] as const;
export const deviceUpdateRings = ["hold", "canary", "stable"] as const;

export type UpdatePlatform = (typeof updatePlatforms)[number];
export type UpdateArchitecture = (typeof updateArchitectures)[number];
export type ReleaseRing = (typeof releaseRings)[number];
export type DeviceUpdateRing = (typeof deviceUpdateRings)[number];

export interface UpdatePullRequestUnsigned {
  schema: typeof FLEET_UPDATE_PULL_SCHEMA;
  tenantId: string;
  deviceId: string;
  platform: UpdatePlatform;
  architecture: UpdateArchitecture;
  updateRing: DeviceUpdateRing;
  issuedAt: string;
  nonce: string;
}

export interface UpdatePullRequest extends UpdatePullRequestUnsigned {
  signature: string;
}

export interface UpdateArtifact {
  url: string;
  sizeBytes: number;
  sha256: string;
}

export interface UpdateRollout {
  basisPoints: number;
  seed: string;
}

export interface SignedUpdateManifestUnsigned {
  schema: typeof UPDATE_MANIFEST_SCHEMA;
  sequence: number;
  releaseId: string;
  releaseVersion: string;
  platform: UpdatePlatform;
  architecture: UpdateArchitecture;
  releaseRing: ReleaseRing;
  rollout: UpdateRollout;
  issuedAtUnix: number;
  notBeforeUnix: number;
  expiresAtUnix: number;
  artifact: UpdateArtifact;
  emergencyRollback: boolean;
}

export interface SignedUpdateManifest extends SignedUpdateManifestUnsigned {
  signature: string;
}

export interface UpdatePullResponse {
  schema: typeof FLEET_UPDATE_PULL_RESPONSE_SCHEMA;
  tenantId: string;
  deviceId: string;
  platform: UpdatePlatform;
  architecture: UpdateArchitecture;
  updateRing: DeviceUpdateRing;
  items: SignedUpdateManifest[];
}

const pullUnsignedKeys = [
  "schema",
  "tenantId",
  "deviceId",
  "platform",
  "architecture",
  "updateRing",
  "issuedAt",
  "nonce",
] as const;

const manifestUnsignedKeys = [
  "schema",
  "sequence",
  "releaseId",
  "releaseVersion",
  "platform",
  "architecture",
  "releaseRing",
  "rollout",
  "issuedAtUnix",
  "notBeforeUnix",
  "expiresAtUnix",
  "artifact",
  "emergencyRollback",
] as const;

export function parseUpdatePullRequest(value: unknown): UpdatePullRequest {
  const object = expectRecord(value);
  expectExactKeys(object, [...pullUnsignedKeys, "signature"]);
  return {
    ...parseUpdatePullUnsignedFields(object),
    signature: expectBase64Url(object.signature, "signature", 86, 86),
  };
}

export function parseUpdatePullUnsigned(
  value: unknown,
): UpdatePullRequestUnsigned {
  const object = expectRecord(value);
  expectExactKeys(object, pullUnsignedKeys);
  return parseUpdatePullUnsignedFields(object);
}

export function toUnsignedUpdatePull(
  value: UpdatePullRequest | UpdatePullRequestUnsigned,
): UpdatePullRequestUnsigned {
  return {
    schema: value.schema,
    tenantId: value.tenantId,
    deviceId: value.deviceId,
    platform: value.platform,
    architecture: value.architecture,
    updateRing: value.updateRing,
    issuedAt: value.issuedAt,
    nonce: value.nonce,
  };
}

export function updatePullSigningBytes(
  value: UpdatePullRequest | UpdatePullRequestUnsigned,
): Uint8Array {
  const unsigned = parseUpdatePullUnsigned(toUnsignedUpdatePull(value));
  return new TextEncoder().encode(
    `${FLEET_UPDATE_PULL_DOMAIN}${canonicalJson(unsigned)}`,
  );
}

export function parseUpdatePullResponse(value: unknown): UpdatePullResponse {
  const object = expectRecord(value, "update response");
  expectExactKeys(
    object,
    [
      "schema",
      "tenantId",
      "deviceId",
      "platform",
      "architecture",
      "updateRing",
      "items",
    ],
    "update response",
  );
  if (!Array.isArray(object.items) || object.items.length > 2) {
    throw new FleetSchemaError("update response items exceed their bounds");
  }
  const platform = expectEnum(
    object.platform,
    "update response.platform",
    updatePlatforms,
  );
  const architecture = expectEnum(
    object.architecture,
    "update response.architecture",
    updateArchitectures,
  );
  const items = object.items.map(parseSignedUpdateManifest);
  if (
    items.some(
      (item) =>
        item.platform !== platform || item.architecture !== architecture,
    )
  ) {
    throw new FleetSchemaError("update response contains another target");
  }
  return {
    schema: expectEnum(object.schema, "update response.schema", [
      FLEET_UPDATE_PULL_RESPONSE_SCHEMA,
    ]),
    tenantId: expectIdentifier(object.tenantId, "update response.tenantId"),
    deviceId: expectDeviceId(object.deviceId),
    platform,
    architecture,
    updateRing: expectEnum(
      object.updateRing,
      "update response.updateRing",
      deviceUpdateRings,
    ),
    items,
  };
}

export function assertUpdatePullResponseBinding(
  response: UpdatePullResponse,
  request: UpdatePullRequest | UpdatePullRequestUnsigned,
): void {
  const parsedResponse = parseUpdatePullResponse(response);
  const parsedRequest = parseUpdatePullUnsigned(toUnsignedUpdatePull(request));
  if (
    parsedResponse.tenantId !== parsedRequest.tenantId ||
    parsedResponse.deviceId !== parsedRequest.deviceId ||
    parsedResponse.platform !== parsedRequest.platform ||
    parsedResponse.architecture !== parsedRequest.architecture ||
    parsedResponse.updateRing !== parsedRequest.updateRing
  ) {
    throw new FleetSchemaError("update response is not bound to its request");
  }
}

export function parseSignedUpdateManifest(
  value: unknown,
): SignedUpdateManifest {
  const object = expectRecord(value, "update");
  expectExactKeys(object, [...manifestUnsignedKeys, "signature"], "update");
  return {
    ...parseUpdateManifestUnsignedFields(object),
    signature: expectBase64Url(object.signature, "update.signature", 86, 86),
  };
}

export function parseSignedUpdateManifestUnsigned(
  value: unknown,
): SignedUpdateManifestUnsigned {
  const object = expectRecord(value, "update");
  expectExactKeys(object, manifestUnsignedKeys, "update");
  return parseUpdateManifestUnsignedFields(object);
}

export function toUnsignedUpdateManifest(
  value: SignedUpdateManifest | SignedUpdateManifestUnsigned,
): SignedUpdateManifestUnsigned {
  return {
    schema: value.schema,
    sequence: value.sequence,
    releaseId: value.releaseId,
    releaseVersion: value.releaseVersion,
    platform: value.platform,
    architecture: value.architecture,
    releaseRing: value.releaseRing,
    rollout: { ...value.rollout },
    issuedAtUnix: value.issuedAtUnix,
    notBeforeUnix: value.notBeforeUnix,
    expiresAtUnix: value.expiresAtUnix,
    artifact: { ...value.artifact },
    emergencyRollback: value.emergencyRollback,
  };
}

/** Exact update-client framing: domain || canonical JSON(unsigned manifest). */
export function updateManifestSigningBytes(
  value: SignedUpdateManifest | SignedUpdateManifestUnsigned,
): Uint8Array {
  const unsigned = parseSignedUpdateManifestUnsigned(
    toUnsignedUpdateManifest(value),
  );
  return new TextEncoder().encode(
    `${UPDATE_MANIFEST_DOMAIN}${canonicalJson(unsigned)}`,
  );
}

/** Mirrors update-client eligibility; authenticity remains a separate gate. */
export function updateAppliesTo(
  manifest: SignedUpdateManifest,
  request: UpdatePullRequest | UpdatePullRequestUnsigned,
  nowUnix: number,
): boolean {
  const parsedManifest = parseSignedUpdateManifest(manifest);
  const parsedRequest = parseUpdatePullUnsigned(toUnsignedUpdatePull(request));
  expectSafeInteger(nowUnix, "nowUnix", 1);
  if (
    parsedManifest.platform !== parsedRequest.platform ||
    parsedManifest.architecture !== parsedRequest.architecture ||
    nowUnix < parsedManifest.notBeforeUnix ||
    nowUnix >= parsedManifest.expiresAtUnix
  ) {
    return false;
  }
  if (parsedManifest.emergencyRollback) return true;
  if (parsedRequest.updateRing === "hold") return false;
  if (
    parsedManifest.releaseRing === "canary" &&
    parsedRequest.updateRing !== "canary"
  ) {
    return false;
  }
  return inRollout(
    parsedRequest.deviceId,
    parsedManifest.rollout.seed,
    parsedManifest.rollout.basisPoints,
  );
}

function parseUpdatePullUnsignedFields(
  object: Record<string, unknown>,
): UpdatePullRequestUnsigned {
  return {
    schema: expectEnum(object.schema, "schema", [FLEET_UPDATE_PULL_SCHEMA]),
    tenantId: expectIdentifier(object.tenantId, "tenantId"),
    deviceId: expectDeviceId(object.deviceId),
    platform: expectEnum(object.platform, "platform", updatePlatforms),
    architecture: expectEnum(
      object.architecture,
      "architecture",
      updateArchitectures,
    ),
    updateRing: expectEnum(object.updateRing, "updateRing", deviceUpdateRings),
    issuedAt: expectRfc3339(object.issuedAt, "issuedAt"),
    nonce: expectBase64Url(object.nonce, "nonce", 22, 86),
  };
}

function parseUpdateManifestUnsignedFields(
  object: Record<string, unknown>,
): SignedUpdateManifestUnsigned {
  const issuedAtUnix = expectSafeInteger(
    object.issuedAtUnix,
    "update.issuedAtUnix",
    1,
  );
  const notBeforeUnix = expectSafeInteger(
    object.notBeforeUnix,
    "update.notBeforeUnix",
    1,
  );
  const expiresAtUnix = expectSafeInteger(
    object.expiresAtUnix,
    "update.expiresAtUnix",
    1,
  );
  if (issuedAtUnix > notBeforeUnix || notBeforeUnix >= expiresAtUnix) {
    throw new FleetSchemaError("update has an invalid time window");
  }
  if (typeof object.emergencyRollback !== "boolean") {
    throw new FleetSchemaError("update.emergencyRollback must be boolean");
  }
  return {
    schema: expectEnum(object.schema, "update.schema", [
      UPDATE_MANIFEST_SCHEMA,
    ]),
    sequence: expectSafeInteger(object.sequence, "update.sequence", 1),
    releaseId: expectUpdateIdentifier(object.releaseId, "update.releaseId"),
    releaseVersion: expectReleaseVersion(object.releaseVersion),
    platform: expectEnum(object.platform, "update.platform", updatePlatforms),
    architecture: expectEnum(
      object.architecture,
      "update.architecture",
      updateArchitectures,
    ),
    releaseRing: expectEnum(
      object.releaseRing,
      "update.releaseRing",
      releaseRings,
    ),
    rollout: parseRollout(object.rollout),
    issuedAtUnix,
    notBeforeUnix,
    expiresAtUnix,
    artifact: parseArtifact(object.artifact),
    emergencyRollback: object.emergencyRollback,
  };
}

function parseRollout(value: unknown): UpdateRollout {
  const object = expectRecord(value, "update.rollout");
  expectExactKeys(object, ["basisPoints", "seed"], "update.rollout");
  const basisPoints = expectSafeInteger(
    object.basisPoints,
    "update.rollout.basisPoints",
    0,
  );
  if (basisPoints > 10_000) {
    throw new FleetSchemaError("update.rollout.basisPoints exceeds 10000");
  }
  return {
    basisPoints,
    seed: expectUpdateIdentifier(object.seed, "update.rollout.seed"),
  };
}

function parseArtifact(value: unknown): UpdateArtifact {
  const object = expectRecord(value, "update.artifact");
  expectExactKeys(object, ["url", "sizeBytes", "sha256"], "update.artifact");
  const url = expectString(object.url, "update.artifact.url", 1, 4096);
  let parsed: URL;
  try {
    parsed = new URL(url);
  } catch {
    throw new FleetSchemaError("update.artifact.url must be a valid HTTPS URL");
  }
  if (
    parsed.protocol !== "https:" ||
    parsed.hostname.length === 0 ||
    parsed.username.length !== 0 ||
    parsed.password.length !== 0 ||
    parsed.hash.length !== 0
  ) {
    throw new FleetSchemaError("update.artifact.url must be a valid HTTPS URL");
  }
  const sizeBytes = expectSafeInteger(
    object.sizeBytes,
    "update.artifact.sizeBytes",
    1,
  );
  if (sizeBytes > 1024 ** 4) {
    throw new FleetSchemaError("update.artifact.sizeBytes exceeds 1 TiB");
  }
  return {
    url,
    sizeBytes,
    sha256: expectSha256(object.sha256, "update.artifact.sha256"),
  };
}

function expectUpdateIdentifier(value: unknown, field: string): string {
  const identifier = expectString(value, field, 1, 160);
  if (!/^[A-Za-z0-9._:/-]+$/.test(identifier)) {
    throw new FleetSchemaError(`${field} is not a valid update identifier`);
  }
  return identifier;
}

function expectReleaseVersion(value: unknown): string {
  const version = expectString(value, "update.releaseVersion", 1, 128);
  if (
    ![...version].every((character) => {
      const code = character.codePointAt(0) ?? 0;
      return (
        code >= 0x21 && code <= 0x7e && character !== '"' && character !== "\\"
      );
    })
  ) {
    throw new FleetSchemaError("update.releaseVersion is invalid");
  }
  return version;
}

function inRollout(
  deviceId: string,
  seed: string,
  basisPoints: number,
): boolean {
  if (basisPoints === 0) return false;
  if (basisPoints === 10_000) return true;
  const digest = createHash("sha256")
    .update("kernaid:update:rollout:v1\0", "utf8")
    .update(seed, "utf8")
    .update(Buffer.from([0]))
    .update(deviceId, "utf8")
    .digest();
  return digest.readUInt16BE(0) % 10_000 < basisPoints;
}
