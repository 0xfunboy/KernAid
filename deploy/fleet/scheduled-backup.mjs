import {
  closeSync,
  constants,
  fsyncSync,
  lstatSync,
  openSync,
  readdirSync,
  realpathSync,
  renameSync,
  rmdirSync,
  unlinkSync,
} from "node:fs";
import { randomBytes } from "node:crypto";
import { dirname, isAbsolute, join, resolve } from "node:path";
import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";

process.umask(0o077);

const BACKUP_NAME = /^fleet-(\d{8}T\d{6}\.\d{3}Z)-(\d+)\.backup$/u;
const BUNDLE_FILES = ["fleet.sqlite", "manifest.json", "manifest.sig"].sort();
const [
  sourceArgument,
  directoryArgument,
  retentionArgument,
  signingKeyArgument,
  trustAnchorArgument,
] = process.argv.slice(2);
const retention = Number(retentionArgument);

if (
  sourceArgument === undefined ||
  directoryArgument === undefined ||
  retentionArgument === undefined ||
  signingKeyArgument === undefined ||
  trustAnchorArgument === undefined ||
  !Number.isSafeInteger(retention) ||
  retention < 2 ||
  retention > 90
) {
  fail(
    "usage: scheduled-backup.mjs <database> <backup-directory> <retention-count:2..90> <owner-only-signing-key-file> <trust-anchor-file>",
  );
}

const source = canonicalAbsolute(sourceArgument, "database");
const directory = canonicalAbsolute(directoryArgument, "backup directory");
const signingKey = canonicalAbsolute(signingKeyArgument, "signing key");
const trustAnchor = canonicalAbsolute(trustAnchorArgument, "trust anchor");
assertPrivateDirectory(directory);
if (dirname(source) === directory) {
  fail("backup directory must be separate from the live database directory");
}

const timestamp = new Date()
  .toISOString()
  .replaceAll("-", "")
  .replaceAll(":", "");
const destinationName = `fleet-${timestamp}-${process.pid}.backup`;
if (!BACKUP_NAME.test(destinationName)) fail("could not derive backup name");
const destination = join(directory, destinationName);

const lifecycle = resolve(
  dirname(fileURLToPath(import.meta.url)),
  "database-lifecycle.mjs",
);
const created = runLifecycle(
  ["backup", source, destination, signingKey],
  "backup",
);
let newBundleVerified = false;
try {
  const verified = runLifecycle(["verify", destination, trustAnchor], "verify");
  if (
    created.databaseSha256 !== verified.databaseSha256 ||
    created.sizeBytes !== verified.sizeBytes ||
    created.userVersion !== verified.userVersion ||
    created.tableCount !== verified.tableCount
  ) {
    fail("new backup verification receipt does not match creation receipt");
  }
  newBundleVerified = true;
} finally {
  if (!newBundleVerified) removeBundleAtomically(destination, directory);
}

const backups = readdirSync(directory, { withFileTypes: true })
  .filter((entry) => BACKUP_NAME.test(entry.name))
  .map((entry) => {
    if (!entry.isDirectory() || entry.isSymbolicLink()) {
      fail("retained backup must be a regular bundle directory");
    }
    return entry.name;
  })
  .sort();

for (const name of backups) {
  assertPrivateBundle(join(directory, name));
  runLifecycle(["verify", join(directory, name), trustAnchor], "verify");
}

const obsolete = backups.slice(0, Math.max(0, backups.length - retention));
for (const name of obsolete) {
  removeBundleAtomically(join(directory, name), directory);
}
syncDirectory(directory);

process.stdout.write(
  `${JSON.stringify({
    operation: "scheduled-backup",
    backup: destinationName,
    retained: backups.length - obsolete.length,
    removed: obsolete.length,
    createdAt: created.createdAt,
    databaseSha256: created.databaseSha256,
    sizeBytes: created.sizeBytes,
    userVersion: created.userVersion,
    tableCount: created.tableCount,
  })}\n`,
);

function runLifecycle(arguments_, expectedOperation) {
  const child = spawnSync(process.execPath, [lifecycle, ...arguments_], {
    encoding: "utf8",
    env: {},
    maxBuffer: 64 * 1024,
    stdio: ["ignore", "pipe", "pipe"],
    timeout: 15 * 60 * 1_000,
  });
  if (
    child.error !== undefined ||
    child.status !== 0 ||
    child.signal !== null
  ) {
    fail(`Fleet backup ${expectedOperation} failed`);
  }
  if (child.stderr !== "") {
    fail(`Fleet backup ${expectedOperation} emitted unexpected diagnostics`);
  }
  return parseLifecycleResult(child.stdout, expectedOperation);
}

function parseLifecycleResult(output, expectedOperation) {
  if (output.length === 0 || output.length > 4096 || !output.endsWith("\n")) {
    fail("Fleet backup lifecycle returned an invalid receipt");
  }
  let value;
  try {
    value = JSON.parse(output);
  } catch {
    fail("Fleet backup lifecycle returned an invalid receipt");
  }
  const expectedKeys = [
    "bundle",
    "createdAt",
    "databaseSha256",
    "operation",
    "sizeBytes",
    "tableCount",
    "userVersion",
  ];
  if (
    value === null ||
    typeof value !== "object" ||
    Array.isArray(value) ||
    value.operation !== expectedOperation ||
    !BACKUP_NAME.test(value.bundle ?? "") ||
    typeof value.createdAt !== "string" ||
    new Date(value.createdAt).toISOString() !== value.createdAt ||
    !/^[0-9a-f]{64}$/.test(value.databaseSha256 ?? "") ||
    !Number.isSafeInteger(value.sizeBytes) ||
    value.sizeBytes < 1 ||
    !Number.isSafeInteger(value.userVersion) ||
    value.userVersion < 1 ||
    !Number.isSafeInteger(value.tableCount) ||
    value.tableCount < 1 ||
    !sameArray(Object.keys(value).sort(), expectedKeys.sort())
  ) {
    fail("Fleet backup lifecycle returned an invalid receipt");
  }
  return value;
}

function canonicalAbsolute(argument, label) {
  if (!isAbsolute(argument)) fail(`${label} path must be absolute`);
  const path = resolve(argument);
  if (realpathSync(path) !== path) fail(`${label} path must be canonical`);
  return path;
}

function assertPrivateDirectory(path) {
  const entry = lstatSync(path);
  if (!entry.isDirectory() || entry.isSymbolicLink()) {
    fail("backup directory must be a regular directory");
  }
  if (process.platform !== "win32" && (entry.mode & 0o077) !== 0) {
    fail("backup directory permissions must deny group and other access");
  }
}

function assertPrivateBundle(path) {
  assertPrivateDirectory(path);
  const entries = readdirSync(path).sort();
  if (!sameArray(entries, BUNDLE_FILES)) {
    fail("retained bundle must contain exactly its three signed files");
  }
  for (const name of entries) {
    const entry = lstatSync(join(path, name));
    if (!entry.isFile() || entry.isSymbolicLink() || entry.size === 0) {
      fail("retained bundle files must be non-empty regular files");
    }
    if (process.platform !== "win32" && (entry.mode & 0o077) !== 0) {
      fail("retained bundle files must deny group and other access");
    }
  }
}

function removeBundleAtomically(path, parent) {
  assertPrivateBundle(path);
  const tombstone = join(
    parent,
    `.delete-${process.pid}-${randomBytes(12).toString("hex")}`,
  );
  renameSync(path, tombstone);
  syncDirectory(parent);
  for (const name of BUNDLE_FILES) unlinkSync(join(tombstone, name));
  rmdirSync(tombstone);
  syncDirectory(parent);
}

function syncDirectory(path) {
  const descriptor = openSync(path, constants.O_RDONLY | constants.O_DIRECTORY);
  try {
    fsyncSync(descriptor);
  } finally {
    closeSync(descriptor);
  }
}

function sameArray(left, right) {
  return (
    left.length === right.length &&
    left.every((item, index) => item === right[index])
  );
}

function fail(message) {
  throw new Error(message);
}
