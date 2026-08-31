import { canonicalJson } from "./canonical-json.js";
import {
  FleetSchemaError,
  expectBase64Url,
  expectDeviceId,
  expectEnum,
  expectExactKeys,
  expectIdentifier,
  expectOpaqueAssetId,
  expectRecord,
  expectRfc3339,
  expectSafeInteger,
  expectSha256,
  expectString,
} from "./validation.js";

export const FLEET_INVENTORY_SCHEMA =
  "dev.kernaid.fleet.inventory-envelope.v1" as const;
export const FLEET_INVENTORY_DOMAIN = "kernaid:fleet:inventory:v1\0" as const;

export const inventoryPlatforms = [
  "linux",
  "windows",
  "macos",
  "unknown",
] as const;
export const inventoryArchitectures = ["x86_64", "aarch64", "other"] as const;
export const inventoryHealthStates = [
  "healthy",
  "attention",
  "required_action",
  "unknown",
] as const;

export type InventoryPlatform = (typeof inventoryPlatforms)[number];
export type InventoryArchitecture = (typeof inventoryArchitectures)[number];
export type InventoryHealth = (typeof inventoryHealthStates)[number];

export interface FleetFindingCounts {
  critical: number;
  warning: number;
  info: number;
}

export interface FleetInventoryAsset {
  assetId: string;
  targetFingerprint: string;
  platform: InventoryPlatform;
  architecture: InventoryArchitecture;
  osRelease: string | null;
  health: InventoryHealth;
  findingCounts: FleetFindingCounts;
  snapshotSha256: string;
}

export interface InventoryEnvelopeUnsigned {
  schema: typeof FLEET_INVENTORY_SCHEMA;
  tenantId: string;
  deviceId: string;
  sequence: number;
  observedAt: string;
  asset: FleetInventoryAsset;
}

export interface InventoryEnvelope extends InventoryEnvelopeUnsigned {
  signature: string;
}

const unsignedKeys = [
  "schema",
  "tenantId",
  "deviceId",
  "sequence",
  "observedAt",
  "asset",
] as const;

export function parseInventoryEnvelope(value: unknown): InventoryEnvelope {
  const object = expectRecord(value);
  expectExactKeys(object, [...unsignedKeys, "signature"]);
  return {
    ...parseInventoryUnsignedFields(object),
    signature: expectBase64Url(object.signature, "signature", 86, 86),
  };
}

export function parseInventoryUnsigned(
  value: unknown,
): InventoryEnvelopeUnsigned {
  const object = expectRecord(value);
  expectExactKeys(object, unsignedKeys);
  return parseInventoryUnsignedFields(object);
}

export function inventorySigningBytes(
  value: InventoryEnvelope | InventoryEnvelopeUnsigned,
): Uint8Array {
  const unsigned = parseInventoryUnsigned(toUnsignedInventory(value));
  return new TextEncoder().encode(
    `${FLEET_INVENTORY_DOMAIN}${canonicalJson(unsigned)}`,
  );
}

export function toUnsignedInventory(
  value: InventoryEnvelope | InventoryEnvelopeUnsigned,
): InventoryEnvelopeUnsigned {
  return {
    schema: value.schema,
    tenantId: value.tenantId,
    deviceId: value.deviceId,
    sequence: value.sequence,
    observedAt: value.observedAt,
    asset: value.asset,
  };
}

function parseInventoryUnsignedFields(
  object: Record<string, unknown>,
): InventoryEnvelopeUnsigned {
  return {
    schema: expectEnum(object.schema, "schema", [FLEET_INVENTORY_SCHEMA]),
    tenantId: expectIdentifier(object.tenantId, "tenantId"),
    deviceId: expectDeviceId(object.deviceId),
    sequence: expectSafeInteger(object.sequence, "sequence", 1),
    observedAt: expectRfc3339(object.observedAt, "observedAt"),
    asset: parseAsset(object.asset),
  };
}

function parseAsset(value: unknown): FleetInventoryAsset {
  const object = expectRecord(value, "asset");
  expectExactKeys(
    object,
    [
      "assetId",
      "targetFingerprint",
      "platform",
      "architecture",
      "osRelease",
      "health",
      "findingCounts",
      "snapshotSha256",
    ],
    "asset",
  );

  const osRelease = object.osRelease;
  if (osRelease !== null && typeof osRelease !== "string") {
    throw new FleetSchemaError("asset.osRelease must be a string or null");
  }
  if (typeof osRelease === "string") {
    expectString(osRelease, "asset.osRelease", 1, 256);
  }

  return {
    assetId: expectOpaqueAssetId(object.assetId),
    targetFingerprint: expectSha256(
      object.targetFingerprint,
      "asset.targetFingerprint",
    ),
    platform: expectEnum(object.platform, "asset.platform", inventoryPlatforms),
    architecture: expectEnum(
      object.architecture,
      "asset.architecture",
      inventoryArchitectures,
    ),
    osRelease,
    health: expectEnum(object.health, "asset.health", inventoryHealthStates),
    findingCounts: parseFindingCounts(object.findingCounts),
    snapshotSha256: expectSha256(object.snapshotSha256, "asset.snapshotSha256"),
  };
}

function parseFindingCounts(value: unknown): FleetFindingCounts {
  const object = expectRecord(value, "asset.findingCounts");
  expectExactKeys(
    object,
    ["critical", "warning", "info"],
    "asset.findingCounts",
  );
  return {
    critical: expectSafeInteger(
      object.critical,
      "asset.findingCounts.critical",
      0,
    ),
    warning: expectSafeInteger(
      object.warning,
      "asset.findingCounts.warning",
      0,
    ),
    info: expectSafeInteger(object.info, "asset.findingCounts.info", 0),
  };
}
