import {
  closeSync,
  constants,
  fstatSync,
  mkdirSync,
  openSync,
  readFileSync,
} from "node:fs";
import type { KeyObject } from "node:crypto";
import { dirname, resolve } from "node:path";
import { importEd25519PrivatePkcs8 } from "./crypto.js";

export interface FleetServiceConfig {
  databasePath: string;
  rootToken: string;
  serviceReceiptSigningKey: KeyObject;
  serviceReceiptTrustAnchor: string;
  entitlementTrustAnchor: string;
  updateTrustAnchor: string;
  host: string;
  port: number;
  enrollmentClockSkewMs: number;
  consoleSessionTtlMs: number;
  consoleDirectory?: string;
}

export function loadFleetServiceConfig(
  environment: NodeJS.ProcessEnv = process.env,
): FleetServiceConfig {
  const rootTokenFile = requiredEnvironment(
    environment,
    "KERNAID_FLEET_ROOT_TOKEN_FILE",
  );
  const databasePath = resolve(
    requiredEnvironment(environment, "KERNAID_FLEET_DB_PATH"),
  );
  mkdirSync(dirname(databasePath), { recursive: true, mode: 0o700 });

  const entitlementTrustAnchorFile = requiredEnvironment(
    environment,
    "KERNAID_FLEET_ENTITLEMENT_TRUST_ANCHOR_FILE",
  );
  const updateTrustAnchorFile = requiredEnvironment(
    environment,
    "KERNAID_FLEET_UPDATE_TRUST_ANCHOR_FILE",
  );
  const serviceReceiptSigningKeyFile = requiredEnvironment(
    environment,
    "KERNAID_FLEET_SERVICE_RECEIPT_SIGNING_KEY_FILE",
  );
  const serviceReceiptTrustAnchorFile = requiredEnvironment(
    environment,
    "KERNAID_FLEET_SERVICE_RECEIPT_TRUST_ANCHOR_FILE",
  );

  const secretDescriptor = openSync(
    rootTokenFile,
    constants.O_RDONLY | constants.O_NOFOLLOW,
  );
  let rootToken: string;
  try {
    const secretEntry = fstatSync(secretDescriptor);
    if (!secretEntry.isFile()) {
      throw new Error("KERNAID_FLEET_ROOT_TOKEN_FILE must be a regular file");
    }
    if (process.platform !== "win32" && (secretEntry.mode & 0o077) !== 0) {
      throw new Error(
        "Fleet root token file must not be accessible by group or other",
      );
    }
    rootToken = readFileSync(secretDescriptor, "utf8").trim();
  } finally {
    closeSync(secretDescriptor);
  }
  if (
    rootToken.length < 32 ||
    rootToken.length > 512 ||
    !/^[A-Za-z0-9_-]+$/.test(rootToken)
  ) {
    throw new Error(
      "Fleet root token must be 32-512 canonical base64url characters",
    );
  }

  const entitlementTrustAnchor = readPublicKeyFile(
    entitlementTrustAnchorFile,
    "KERNAID_FLEET_ENTITLEMENT_TRUST_ANCHOR_FILE",
  );
  const updateTrustAnchor = readPublicKeyFile(
    updateTrustAnchorFile,
    "KERNAID_FLEET_UPDATE_TRUST_ANCHOR_FILE",
  );
  const serviceReceiptSigningKey = readPrivateSigningKeyFile(
    serviceReceiptSigningKeyFile,
  );
  const serviceReceiptTrustAnchor = readPublicKeyFile(
    serviceReceiptTrustAnchorFile,
    "KERNAID_FLEET_SERVICE_RECEIPT_TRUST_ANCHOR_FILE",
  );

  const consoleDirectory = environment.FLEET_CONSOLE_DIR;
  return {
    databasePath,
    rootToken,
    serviceReceiptSigningKey,
    serviceReceiptTrustAnchor,
    entitlementTrustAnchor,
    updateTrustAnchor,
    host: environment.KERNAID_FLEET_HOST ?? "127.0.0.1",
    port: parseIntegerEnvironment(
      environment.KERNAID_FLEET_PORT,
      7341,
      0,
      65_535,
    ),
    enrollmentClockSkewMs: parseIntegerEnvironment(
      environment.KERNAID_FLEET_ENROLLMENT_CLOCK_SKEW_MS,
      300_000,
      1_000,
      3_600_000,
    ),
    consoleSessionTtlMs:
      parseIntegerEnvironment(
        environment.KERNAID_FLEET_CONSOLE_SESSION_TTL_SECONDS,
        900,
        60,
        3_600,
      ) * 1_000,
    ...(consoleDirectory === undefined
      ? {}
      : { consoleDirectory: resolve(consoleDirectory) }),
  };
}

function readPrivateSigningKeyFile(path: string): KeyObject {
  const descriptor = openSync(path, constants.O_RDONLY | constants.O_NOFOLLOW);
  let value: Buffer;
  try {
    const entry = fstatSync(descriptor);
    if (!entry.isFile() || entry.size < 32 || entry.size > 256) {
      throw new Error(
        "KERNAID_FLEET_SERVICE_RECEIPT_SIGNING_KEY_FILE must be a bounded regular file",
      );
    }
    if (process.platform !== "win32" && (entry.mode & 0o077) !== 0) {
      throw new Error(
        "Fleet service receipt signing key must not be accessible by group or other",
      );
    }
    value = readFileSync(descriptor);
  } finally {
    closeSync(descriptor);
  }
  try {
    return importEd25519PrivatePkcs8(value);
  } catch {
    throw new Error(
      "KERNAID_FLEET_SERVICE_RECEIPT_SIGNING_KEY_FILE must contain canonical Ed25519 PKCS#8 DER",
    );
  }
}

function readPublicKeyFile(path: string, variable: string): string {
  const descriptor = openSync(path, constants.O_RDONLY | constants.O_NOFOLLOW);
  let value: string;
  try {
    const entry = fstatSync(descriptor);
    if (!entry.isFile() || entry.size > 1024) {
      throw new Error(`${variable} must be a bounded regular file`);
    }
    value = readFileSync(descriptor, "utf8").trim();
  } finally {
    closeSync(descriptor);
  }
  if (!/^[A-Za-z0-9_-]{43}$/.test(value)) {
    throw new Error(
      `${variable} must contain a raw Ed25519 base64url public key`,
    );
  }
  const decoded = Buffer.from(value, "base64url");
  if (decoded.length !== 32 || decoded.toString("base64url") !== value) {
    throw new Error(`${variable} must contain canonical base64url`);
  }
  return value;
}

function requiredEnvironment(
  environment: NodeJS.ProcessEnv,
  name: string,
): string {
  const value = environment[name];
  if (value === undefined || value.length === 0) {
    throw new Error(`${name} is required`);
  }
  return value;
}

function parseIntegerEnvironment(
  value: string | undefined,
  fallback: number,
  minimum: number,
  maximum: number,
): number {
  if (value === undefined) return fallback;
  if (!/^\d+$/.test(value))
    throw new Error(`invalid integer environment: ${value}`);
  const parsed = Number(value);
  if (!Number.isSafeInteger(parsed) || parsed < minimum || parsed > maximum) {
    throw new Error(`integer environment is outside ${minimum}-${maximum}`);
  }
  return parsed;
}
