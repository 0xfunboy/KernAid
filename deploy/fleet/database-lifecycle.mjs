import { backup, DatabaseSync } from "node:sqlite";
import {
  closeSync,
  constants,
  createReadStream,
  existsSync,
  fstatSync,
  fsyncSync,
  lstatSync,
  mkdirSync,
  openSync,
  readSync,
  readFileSync,
  realpathSync,
  readdirSync,
  renameSync,
  rmdirSync,
  unlinkSync,
  writeFileSync,
  writeSync,
} from "node:fs";
import {
  createHash,
  createPrivateKey,
  createPublicKey,
  randomBytes,
  sign,
  verify,
} from "node:crypto";
import { basename, dirname, isAbsolute, join, resolve } from "node:path";

process.umask(0o077);

const MANIFEST_SCHEMA = "dev.kernaid.fleet.database-backup-manifest.v1";
const SIGNING_DOMAIN = Buffer.from(
  "kernaid:fleet:database-backup:v1\0",
  "utf8",
);
const DATABASE_FILE = "fleet.sqlite";
const MANIFEST_FILE = "manifest.json";
const SIGNATURE_FILE = "manifest.sig";
const BUNDLE_FILES = [DATABASE_FILE, MANIFEST_FILE, SIGNATURE_FILE].sort();
const MAX_MANIFEST_BYTES = 64 * 1024;
const MAX_TABLES = 256;
const MAX_KEY_BYTES = 256;
const MAX_ANCHOR_BYTES = 1024;
const REQUIRED_TABLES = [
  "assets",
  "devices",
  "enrollment_tokens",
  "inventory_events",
  "tenants",
];

const [operation, ...arguments_] = process.argv.slice(2);

if (operation === "backup" && arguments_.length === 3) {
  await createSignedBundle(...arguments_);
} else if (operation === "verify" && arguments_.length === 2) {
  const result = await verifySignedBundle(...arguments_);
  writeResult("verify", result);
} else if (operation === "restore" && arguments_.length === 3) {
  await restoreSignedBundle(...arguments_);
} else if (operation === "inspect" && arguments_.length === 1) {
  const database = existingAbsoluteFile(arguments_[0], "database", true);
  const summary = verifyDatabase(database);
  const digest = await hashFile(database);
  writeResult("inspect", {
    createdAt: null,
    databaseSha256: digest.sha256,
    sizeBytes: digest.sizeBytes,
    userVersion: summary.userVersion,
    tableCount: summary.tables.length,
  });
} else {
  fail(
    "usage: database-lifecycle.mjs backup <database> <new-bundle-directory> <owner-only-signing-key-file> | verify <bundle-directory> <trust-anchor-file> | restore <bundle-directory> <trust-anchor-file> <new-database> | inspect <live-database>",
  );
}

async function createSignedBundle(
  sourceArgument,
  destinationArgument,
  signingKeyArgument,
) {
  const source = existingAbsoluteFile(sourceArgument, "database", true);
  verifyDatabase(source);
  const signingKeyPath = existingAbsoluteFile(
    signingKeyArgument,
    "signing key",
    true,
  );
  const signingKey = readSigningKey(signingKeyPath);
  const destination = newAbsoluteDestination(
    destinationArgument,
    "bundle destination",
  );
  const parent = dirname(destination);
  assertPrivateDirectory(parent, "bundle destination parent");
  const staging = join(
    parent,
    `.fleet-backup-${process.pid}-${randomBytes(12).toString("hex")}.partial`,
  );
  mkdirSync(staging, { mode: 0o700 });
  let published = false;
  try {
    const databasePath = join(staging, DATABASE_FILE);
    const sourceDatabase = new DatabaseSync(source, {
      readOnly: true,
      timeout: 5_000,
    });
    try {
      await backup(sourceDatabase, databasePath, { rate: 100 });
    } finally {
      sourceDatabase.close();
    }
    makeStandaloneDatabase(databasePath);
    const databaseSummary = verifyDatabase(databasePath);
    const digest = await hashFile(databasePath);
    const manifest = {
      schema: MANIFEST_SCHEMA,
      createdAt: new Date().toISOString(),
      database: {
        fileName: DATABASE_FILE,
        sha256: digest.sha256,
        sizeBytes: digest.sizeBytes,
        sqliteUserVersion: databaseSummary.userVersion,
        tables: databaseSummary.tables,
      },
    };
    const manifestJson = canonicalJson(manifest);
    const manifestBytes = Buffer.from(manifestJson, "utf8");
    if (manifestBytes.length > MAX_MANIFEST_BYTES) {
      fail("backup manifest exceeds its byte limit");
    }
    const signature = sign(
      null,
      Buffer.concat([SIGNING_DOMAIN, manifestBytes]),
      signingKey,
    ).toString("base64url");
    if (!/^[A-Za-z0-9_-]{86}$/.test(signature)) {
      fail("could not create canonical backup signature");
    }
    writePrivateFile(join(staging, MANIFEST_FILE), manifestBytes);
    writePrivateFile(
      join(staging, SIGNATURE_FILE),
      Buffer.from(`${signature}\n`, "ascii"),
    );
    syncDirectory(staging);
    assertDestinationAbsent(destination);
    renameSync(staging, destination);
    published = true;
    syncDirectory(parent);
    writeResult("backup", {
      bundle: basename(destination),
      createdAt: manifest.createdAt,
      databaseSha256: digest.sha256,
      sizeBytes: digest.sizeBytes,
      userVersion: databaseSummary.userVersion,
      tableCount: databaseSummary.tables.length,
    });
  } catch (error) {
    if (!published) removeKnownBundle(staging);
    throw error;
  }
}

function makeStandaloneDatabase(path) {
  assertSecureFile(path, "backup database", true);
  const database = new DatabaseSync(path, { timeout: 5_000 });
  try {
    const journalMode = database
      .prepare("PRAGMA journal_mode = DELETE")
      .get()?.journal_mode;
    if (journalMode !== "delete") {
      fail("backup database could not enter standalone journal mode");
    }
  } finally {
    database.close();
  }
  for (const suffix of ["-shm", "-wal"]) {
    const sidecar = `${path}${suffix}`;
    if (!existsSync(sidecar)) continue;
    assertSecureFile(sidecar, "backup database sidecar", true);
    removeFile(sidecar);
  }
  const descriptor = openSync(
    path,
    constants.O_RDONLY | constants.O_NOFOLLOW,
  );
  try {
    fsyncSync(descriptor);
  } finally {
    closeSync(descriptor);
  }
  syncDirectory(dirname(path));
}

async function verifySignedBundle(bundleArgument, trustAnchorArgument) {
  const bundle = existingAbsoluteDirectory(bundleArgument, "backup bundle");
  assertPrivateDirectory(bundle, "backup bundle");
  const entries = readdirSync(bundle).sort();
  if (
    entries.length !== BUNDLE_FILES.length ||
    !sameArray(entries, BUNDLE_FILES)
  ) {
    fail("backup bundle must contain exactly database, manifest and signature");
  }
  const manifestPath = join(bundle, MANIFEST_FILE);
  const signaturePath = join(bundle, SIGNATURE_FILE);
  const databasePath = join(bundle, DATABASE_FILE);
  const manifestBytes = readBoundedFile(
    manifestPath,
    "backup manifest",
    MAX_MANIFEST_BYTES,
    true,
  );
  const manifestText = manifestBytes.toString("utf8");
  if (!Buffer.from(manifestText, "utf8").equals(manifestBytes)) {
    fail("backup manifest must be canonical UTF-8");
  }
  let manifest;
  try {
    manifest = JSON.parse(manifestText);
  } catch {
    fail("backup manifest is not valid JSON");
  }
  validateManifest(manifest);
  if (canonicalJson(manifest) !== manifestText) {
    fail("backup manifest is not canonical JSON");
  }
  const signatureBytes = readBoundedFile(
    signaturePath,
    "backup signature",
    128,
    true,
  );
  const signatureText = signatureBytes.toString("ascii");
  if (!/^[A-Za-z0-9_-]{86}\n$/.test(signatureText)) {
    fail("backup signature is not canonical base64url");
  }
  const signature = Buffer.from(signatureText.trimEnd(), "base64url");
  if (signature.length !== 64) fail("backup signature length is invalid");
  const trustAnchorPath = existingAbsoluteFile(
    trustAnchorArgument,
    "trust anchor",
    false,
  );
  const trustAnchor = readTrustAnchor(trustAnchorPath);
  if (
    !verify(
      null,
      Buffer.concat([SIGNING_DOMAIN, manifestBytes]),
      trustAnchor,
      signature,
    )
  ) {
    fail("backup manifest signature verification failed");
  }
  assertSecureFile(databasePath, "backup database", true);
  const databaseSummary = verifyDatabase(databasePath);
  if (
    databaseSummary.userVersion !== manifest.database.sqliteUserVersion ||
    !sameArray(databaseSummary.tables, manifest.database.tables)
  ) {
    fail("backup database schema does not match the signed manifest");
  }
  const digest = await hashFile(databasePath);
  if (
    digest.sha256 !== manifest.database.sha256 ||
    digest.sizeBytes !== manifest.database.sizeBytes
  ) {
    fail("backup database digest does not match the signed manifest");
  }
  return {
    bundle: basename(bundle),
    createdAt: manifest.createdAt,
    databaseSha256: digest.sha256,
    sizeBytes: digest.sizeBytes,
    userVersion: databaseSummary.userVersion,
    tableCount: databaseSummary.tables.length,
    databasePath,
  };
}

async function restoreSignedBundle(
  bundleArgument,
  trustAnchorArgument,
  destinationArgument,
) {
  const verified = await verifySignedBundle(
    bundleArgument,
    trustAnchorArgument,
  );
  const destination = newAbsoluteDestination(
    destinationArgument,
    "restore destination",
  );
  const parent = dirname(destination);
  assertPrivateDirectory(parent, "restore destination parent");
  let destinationCreated = false;
  try {
    copyFileExclusive(verified.databasePath, destination);
    destinationCreated = true;
    const summary = verifyDatabase(destination);
    const digest = await hashFile(destination);
    if (
      digest.sha256 !== verified.databaseSha256 ||
      digest.sizeBytes !== verified.sizeBytes
    ) {
      fail("restored database does not match the signed backup");
    }
    syncDirectory(parent);
    writeResult("restore", {
      createdAt: verified.createdAt,
      databaseSha256: digest.sha256,
      sizeBytes: digest.sizeBytes,
      userVersion: summary.userVersion,
      tableCount: summary.tables.length,
    });
  } catch (error) {
    if (destinationCreated) removeFile(destination);
    throw error;
  }
}

function copyFileExclusive(source, destination) {
  const sourceDescriptor = openSync(
    source,
    constants.O_RDONLY | constants.O_NOFOLLOW,
  );
  let destinationDescriptor;
  let destinationCreated = false;
  let operationError;
  try {
    const sourceEntry = fstatSync(sourceDescriptor);
    if (
      !sourceEntry.isFile() ||
      !Number.isSafeInteger(sourceEntry.size) ||
      sourceEntry.size < 1
    ) {
      fail("signed backup database is not a regular non-empty file");
    }
    destinationDescriptor = openSync(
      destination,
      constants.O_WRONLY |
        constants.O_CREAT |
        constants.O_EXCL |
        constants.O_NOFOLLOW,
      0o600,
    );
    destinationCreated = true;
    const buffer = Buffer.allocUnsafe(1024 * 1024);
    let copied = 0;
    while (copied < sourceEntry.size) {
      const count = readSync(
        sourceDescriptor,
        buffer,
        0,
        Math.min(buffer.length, sourceEntry.size - copied),
        null,
      );
      if (count === 0) fail("signed backup database changed during restore");
      let written = 0;
      while (written < count) {
        const writeCount = writeSync(
          destinationDescriptor,
          buffer,
          written,
          count - written,
          null,
        );
        if (writeCount === 0)
          fail("restore destination stopped accepting data");
        written += writeCount;
      }
      copied += count;
    }
    if (readSync(sourceDescriptor, buffer, 0, 1, null) !== 0) {
      fail("signed backup database changed during restore");
    }
    fsyncSync(destinationDescriptor);
  } catch (error) {
    operationError = error;
  }
  for (const descriptor of [destinationDescriptor, sourceDescriptor]) {
    if (descriptor === undefined) continue;
    try {
      closeSync(descriptor);
    } catch (error) {
      operationError ??= error;
    }
  }
  if (operationError !== undefined) {
    if (destinationCreated) removeFile(destination);
    throw operationError;
  }
}

function verifyDatabase(path) {
  assertSecureFile(path, "database", true);
  const database = new DatabaseSync(path, { readOnly: true, timeout: 5_000 });
  try {
    const integrity = database.prepare("PRAGMA quick_check").get();
    if (integrity?.quick_check !== "ok") fail("SQLite quick_check failed");
    const foreignKeyFailures = database
      .prepare("PRAGMA foreign_key_check")
      .all();
    if (foreignKeyFailures.length !== 0)
      fail("SQLite foreign keys are invalid");
    const version = database.prepare("PRAGMA user_version").get()?.user_version;
    if (!Number.isSafeInteger(version) || version < 1) {
      fail("unsupported Fleet database version");
    }
    const tables = database
      .prepare(
        "SELECT name FROM sqlite_schema WHERE type = 'table' AND name NOT LIKE 'sqlite_%' ORDER BY name",
      )
      .all()
      .map((row) => row.name);
    if (
      tables.length > MAX_TABLES ||
      tables.some(
        (table) =>
          typeof table !== "string" ||
          !/^[A-Za-z][A-Za-z0-9_]{0,127}$/.test(table),
      )
    ) {
      fail("Fleet database table inventory is outside bounds");
    }
    for (const required of REQUIRED_TABLES) {
      if (!tables.includes(required))
        fail("Fleet database schema is incomplete");
    }
    return { userVersion: version, tables };
  } finally {
    database.close();
  }
}

function validateManifest(value) {
  assertRecord(value, "backup manifest");
  assertExactKeys(value, ["createdAt", "database", "schema"]);
  if (value.schema !== MANIFEST_SCHEMA) {
    fail("unsupported backup manifest schema");
  }
  if (
    typeof value.createdAt !== "string" ||
    Number.isNaN(Date.parse(value.createdAt)) ||
    new Date(value.createdAt).toISOString() !== value.createdAt
  ) {
    fail("backup manifest timestamp is invalid");
  }
  assertRecord(value.database, "backup database descriptor");
  assertExactKeys(value.database, [
    "fileName",
    "sha256",
    "sizeBytes",
    "sqliteUserVersion",
    "tables",
  ]);
  if (value.database.fileName !== DATABASE_FILE) {
    fail("backup database filename is invalid");
  }
  if (!/^[0-9a-f]{64}$/.test(value.database.sha256 ?? "")) {
    fail("backup database SHA-256 is invalid");
  }
  if (
    !Number.isSafeInteger(value.database.sizeBytes) ||
    value.database.sizeBytes < 1 ||
    !Number.isSafeInteger(value.database.sqliteUserVersion) ||
    value.database.sqliteUserVersion < 1 ||
    !Array.isArray(value.database.tables) ||
    value.database.tables.length < REQUIRED_TABLES.length ||
    value.database.tables.length > MAX_TABLES ||
    value.database.tables.some(
      (table) =>
        typeof table !== "string" ||
        !/^[A-Za-z][A-Za-z0-9_]{0,127}$/.test(table),
    ) ||
    !sameArray([...value.database.tables].sort(), value.database.tables) ||
    new Set(value.database.tables).size !== value.database.tables.length
  ) {
    fail("backup database descriptor is invalid");
  }
  for (const required of REQUIRED_TABLES) {
    if (!value.database.tables.includes(required)) {
      fail("backup manifest schema is incomplete");
    }
  }
}

async function hashFile(path) {
  assertSecureFile(path, "database", true);
  const before = lstatSync(path, { bigint: true });
  const hash = createHash("sha256");
  let sizeBytes = 0;
  const stream = createReadStream(path, {
    flags: constants.O_RDONLY | constants.O_NOFOLLOW,
    highWaterMark: 1024 * 1024,
  });
  for await (const chunk of stream) {
    hash.update(chunk);
    sizeBytes += chunk.length;
    if (!Number.isSafeInteger(sizeBytes))
      fail("database is too large to attest");
  }
  const after = lstatSync(path, { bigint: true });
  if (
    before.dev !== after.dev ||
    before.ino !== after.ino ||
    before.size !== after.size ||
    before.mtimeNs !== after.mtimeNs ||
    BigInt(sizeBytes) !== after.size
  ) {
    fail("database changed while its digest was computed");
  }
  return { sha256: hash.digest("hex"), sizeBytes };
}

function readSigningKey(path) {
  const bytes = readBoundedFile(path, "signing key", MAX_KEY_BYTES, true);
  let key;
  try {
    key = createPrivateKey({ key: bytes, format: "der", type: "pkcs8" });
  } catch {
    fail("signing key must be canonical Ed25519 PKCS#8 DER");
  }
  if (key.type !== "private" || key.asymmetricKeyType !== "ed25519") {
    fail("signing key must be Ed25519");
  }
  const canonical = Buffer.from(key.export({ format: "der", type: "pkcs8" }));
  if (!canonical.equals(bytes)) {
    fail("signing key must be canonical Ed25519 PKCS#8 DER");
  }
  return key;
}

function readTrustAnchor(path) {
  const bytes = readBoundedFile(path, "trust anchor", MAX_ANCHOR_BYTES, false);
  const text = bytes.toString("utf8").trim();
  if (!/^[A-Za-z0-9_-]{43}$/.test(text)) {
    fail("trust anchor must be a canonical raw Ed25519 public key");
  }
  const raw = Buffer.from(text, "base64url");
  if (raw.length !== 32 || raw.toString("base64url") !== text) {
    fail("trust anchor must be canonical base64url");
  }
  const prefix = Buffer.from("302a300506032b6570032100", "hex");
  return createPublicKey({
    key: Buffer.concat([prefix, raw]),
    format: "der",
    type: "spki",
  });
}

function readBoundedFile(path, label, maximumBytes, ownerOnly) {
  assertSecureFile(path, label, ownerOnly);
  const descriptor = openSync(path, constants.O_RDONLY | constants.O_NOFOLLOW);
  try {
    const entry = fstatSync(descriptor);
    if (entry.size < 1 || entry.size > maximumBytes) {
      fail(`${label} is outside its byte limit`);
    }
    return readFileSync(descriptor);
  } finally {
    closeSync(descriptor);
  }
}

function writePrivateFile(path, bytes) {
  const descriptor = openSync(
    path,
    constants.O_WRONLY |
      constants.O_CREAT |
      constants.O_EXCL |
      constants.O_NOFOLLOW,
    0o600,
  );
  try {
    writeFileSync(descriptor, bytes);
    fsyncSync(descriptor);
  } finally {
    closeSync(descriptor);
  }
}

function existingAbsoluteFile(argument, label, ownerOnly) {
  const path = canonicalAbsolute(argument, label);
  assertSecureFile(path, label, ownerOnly);
  return path;
}

function existingAbsoluteDirectory(argument, label) {
  const path = canonicalAbsolute(argument, label);
  const entry = lstatSync(path);
  if (!entry.isDirectory() || entry.isSymbolicLink()) {
    fail(`${label} must be a regular directory`);
  }
  return path;
}

function canonicalAbsolute(argument, label) {
  if (!isAbsolute(argument)) fail(`${label} path must be absolute`);
  const path = resolve(argument);
  if (realpathSync(path) !== path) fail(`${label} path must be canonical`);
  return path;
}

function newAbsoluteDestination(argument, label) {
  if (!isAbsolute(argument)) fail(`${label} path must be absolute`);
  const path = resolve(argument);
  const parent = dirname(path);
  if (realpathSync(parent) !== parent)
    fail(`${label} parent must be canonical`);
  assertDestinationAbsent(path);
  return path;
}

function assertDestinationAbsent(path) {
  if (existsSync(path)) fail("destination already exists");
}

function assertPrivateDirectory(path, label) {
  const entry = lstatSync(path);
  if (!entry.isDirectory() || entry.isSymbolicLink()) {
    fail(`${label} must be a regular directory`);
  }
  if (process.platform !== "win32" && (entry.mode & 0o077) !== 0) {
    fail(`${label} permissions must deny group and other access`);
  }
}

function assertSecureFile(path, label, ownerOnly) {
  const entry = lstatSync(path);
  if (!entry.isFile() || entry.isSymbolicLink()) {
    fail(`${label} must be a regular non-symlink file`);
  }
  if (
    process.platform !== "win32" &&
    (ownerOnly ? (entry.mode & 0o077) !== 0 : (entry.mode & 0o022) !== 0)
  ) {
    fail(
      ownerOnly
        ? `${label} permissions must deny group and other access`
        : `${label} must not be writable by group or other`,
    );
  }
}

function removeKnownBundle(path) {
  for (const name of BUNDLE_FILES) removeFile(join(path, name));
  try {
    rmdirSync(path);
  } catch (error) {
    if (error?.code !== "ENOENT") throw error;
  }
}

function removeFile(path) {
  try {
    unlinkSync(path);
  } catch (error) {
    if (error?.code !== "ENOENT") throw error;
  }
}

function syncDirectory(path) {
  const descriptor = openSync(path, constants.O_RDONLY | constants.O_DIRECTORY);
  try {
    fsyncSync(descriptor);
  } finally {
    closeSync(descriptor);
  }
}

function canonicalJson(value) {
  if (value === null || typeof value === "boolean")
    return JSON.stringify(value);
  if (typeof value === "number") {
    if (!Number.isSafeInteger(value))
      fail("manifest contains an unsafe number");
    return JSON.stringify(value);
  }
  if (typeof value === "string") return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(",")}]`;
  assertRecord(value, "manifest value");
  return `{${Object.keys(value)
    .sort()
    .map((key) => `${JSON.stringify(key)}:${canonicalJson(value[key])}`)
    .join(",")}}`;
}

function assertRecord(value, label) {
  if (value === null || typeof value !== "object" || Array.isArray(value)) {
    fail(`${label} must be an object`);
  }
}

function assertExactKeys(value, keys) {
  if (!sameArray(Object.keys(value).sort(), [...keys].sort())) {
    fail("backup manifest contains unknown or missing fields");
  }
}

function sameArray(left, right) {
  return (
    left.length === right.length &&
    left.every((item, index) => item === right[index])
  );
}

function writeResult(resultOperation, value) {
  const { databasePath: _databasePath, ...publicValue } = value;
  process.stdout.write(
    `${JSON.stringify({ operation: resultOperation, ...publicValue })}\n`,
  );
}

function fail(message) {
  throw new Error(message);
}
