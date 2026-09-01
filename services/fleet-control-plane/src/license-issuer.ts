#!/usr/bin/env node
import {
  closeSync,
  constants,
  existsSync,
  fstatSync,
  fsyncSync,
  lstatSync,
  openSync,
  readFileSync,
  realpathSync,
  unlinkSync,
  writeFileSync,
} from "node:fs";
import { dirname, isAbsolute, resolve } from "node:path";
import { createHash, generateKeyPairSync } from "node:crypto";
import { canonicalJson } from "@kernaid/fleet-schemas";
import { importEd25519PrivatePkcs8, ed25519RawPublicKey } from "./crypto.js";
import {
  parseEnterpriseLicenseClaims,
  signEnterpriseLicense,
} from "./enterprise-license.js";

process.umask(0o077);

const [command, ...arguments_] = process.argv.slice(2);

try {
  if (command === "keygen" && arguments_.length === 3) {
    const [keyId, privatePath, publicPath] = arguments_;
    identifier(keyId!);
    const privateDestination = newDestination(privatePath!, true);
    const publicDestination = newDestination(publicPath!, true);
    if (privateDestination === publicDestination) {
      fail("private and public destinations must differ");
    }
    const { privateKey, publicKey } = generateKeyPairSync("ed25519");
    const privateDer = Buffer.from(
      privateKey.export({ format: "der", type: "pkcs8" }),
    );
    const publicRaw = `${ed25519RawPublicKey(publicKey)}\n`;
    let privateCreated = false;
    let publicCreated = false;
    try {
      writeExclusive(privateDestination, privateDer, 0o600);
      privateCreated = true;
      writeExclusive(publicDestination, Buffer.from(publicRaw, "ascii"), 0o600);
      publicCreated = true;
      syncDirectory(dirname(privateDestination));
      if (dirname(publicDestination) !== dirname(privateDestination)) {
        syncDirectory(dirname(publicDestination));
      }
    } catch (error) {
      if (publicCreated) removeFile(publicDestination);
      if (privateCreated) removeFile(privateDestination);
      throw error;
    }
    output({
      operation: "keygen",
      keyId,
      publicKeySha256: createHash("sha256")
        .update(publicRaw, "ascii")
        .digest("hex"),
    });
  } else if (command === "issue" && arguments_.length === 3) {
    const [claimsPath, privatePath, licensePath] = arguments_;
    const claims = parseEnterpriseLicenseClaims(
      JSON.parse(
        readBounded(claimsPath!, 16 * 1024, false).toString("utf8"),
      ) as unknown,
    );
    const privateKey = importEd25519PrivatePkcs8(
      readBounded(privatePath!, 256, true),
    );
    const destination = newDestination(licensePath!, true);
    const envelope = signEnterpriseLicense(claims, privateKey);
    const payload = Buffer.from(`${canonicalJson(envelope)}\n`, "utf8");
    writeExclusive(destination, payload, 0o600);
    syncDirectory(dirname(destination));
    output({
      operation: "issue",
      tenantId: claims.tenantId,
      licenseId: claims.licenseId,
      sequence: claims.sequence,
      keyId: claims.keyId,
      licenseSha256: createHash("sha256").update(payload).digest("hex"),
    });
  } else {
    fail(
      "usage: kernaid-fleet-license-issuer keygen <key-id> <new-private.pk8> <new-public> | issue <claims.json> <owner-only-private.pk8> <new-license.json>",
    );
  }
} catch (error) {
  fail(error instanceof Error ? error.message : "license issuer failed");
}

function readBounded(
  argument: string,
  maximum: number,
  ownerOnly: boolean,
): Buffer {
  const path = existingFile(argument, ownerOnly);
  const descriptor = openSync(path, constants.O_RDONLY | constants.O_NOFOLLOW);
  try {
    const entry = fstatSync(descriptor);
    if (!entry.isFile() || entry.size < 1 || entry.size > maximum) {
      throw new Error("issuer input is outside its byte limit");
    }
    return readFileSync(descriptor);
  } finally {
    closeSync(descriptor);
  }
}

function existingFile(argument: string, ownerOnly: boolean): string {
  if (!isAbsolute(argument)) throw new Error("issuer paths must be absolute");
  const path = resolve(argument);
  if (realpathSync(path) !== path)
    throw new Error("issuer path is not canonical");
  const entry = lstatSync(path);
  if (!entry.isFile() || entry.isSymbolicLink()) {
    throw new Error("issuer input must be a regular non-symlink file");
  }
  if (
    process.platform !== "win32" &&
    (ownerOnly ? (entry.mode & 0o077) !== 0 : (entry.mode & 0o022) !== 0)
  ) {
    throw new Error(
      ownerOnly
        ? "issuer private input must be owner-only"
        : "issuer input must not be writable by group or other",
    );
  }
  return path;
}

function newDestination(argument: string, privateParent: boolean): string {
  if (!isAbsolute(argument)) throw new Error("issuer paths must be absolute");
  const path = resolve(argument);
  const parent = dirname(path);
  if (realpathSync(parent) !== parent) {
    throw new Error("issuer destination parent is not canonical");
  }
  const parentEntry = lstatSync(parent);
  if (
    !parentEntry.isDirectory() ||
    parentEntry.isSymbolicLink() ||
    (privateParent &&
      process.platform !== "win32" &&
      (parentEntry.mode & 0o077) !== 0)
  ) {
    throw new Error("issuer destination parent must be a private directory");
  }
  if (existsSync(path)) throw new Error("issuer destination already exists");
  return path;
}

function writeExclusive(path: string, payload: Buffer, mode: number): void {
  const descriptor = openSync(
    path,
    constants.O_WRONLY |
      constants.O_CREAT |
      constants.O_EXCL |
      constants.O_NOFOLLOW,
    mode,
  );
  let operationError: unknown;
  try {
    writeFileSync(descriptor, payload);
    fsyncSync(descriptor);
  } catch (error) {
    operationError = error;
  } finally {
    try {
      closeSync(descriptor);
    } catch (error) {
      operationError ??= error;
    }
  }
  if (operationError !== undefined) {
    removeFile(path);
    throw operationError;
  }
}

function syncDirectory(path: string): void {
  if (process.platform === "win32") return;
  const descriptor = openSync(path, constants.O_RDONLY | constants.O_DIRECTORY);
  try {
    fsyncSync(descriptor);
  } finally {
    closeSync(descriptor);
  }
}

function removeFile(path: string): void {
  try {
    unlinkSync(path);
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code !== "ENOENT") throw error;
  }
}

function identifier(value: string): void {
  if (
    value.length < 1 ||
    value.length > 128 ||
    !/^[A-Za-z0-9][A-Za-z0-9._:-]*$/.test(value)
  ) {
    throw new Error("key ID is invalid");
  }
}

function output(value: unknown): void {
  process.stdout.write(`${canonicalJson(value)}\n`);
}

function fail(message: string): never {
  process.stderr.write(`${message}\n`);
  process.exit(1);
}
