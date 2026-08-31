import {
  closeSync,
  constants,
  fsyncSync,
  lstatSync,
  openSync,
  readdirSync,
  realpathSync,
  unlinkSync,
} from "node:fs";
import { dirname, isAbsolute, join, resolve } from "node:path";
import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";

process.umask(0o077);

const BACKUP_NAME = /^fleet-(\d{8}T\d{6}\.\d{3}Z)-(\d+)\.sqlite$/u;
const [sourceArgument, directoryArgument, retentionArgument] =
  process.argv.slice(2);
const retention = Number(retentionArgument);

if (
  sourceArgument === undefined ||
  directoryArgument === undefined ||
  retentionArgument === undefined ||
  !Number.isSafeInteger(retention) ||
  retention < 2 ||
  retention > 90
) {
  fail(
    "usage: scheduled-backup.mjs <database> <backup-directory> <retention-count:2..90>",
  );
}

const source = canonicalAbsolute(sourceArgument, "database");
const directory = canonicalAbsolute(directoryArgument, "backup directory");
assertPrivateDirectory(directory);
if (dirname(source) === directory) {
  fail("backup directory must be separate from the live database directory");
}

const timestamp = new Date()
  .toISOString()
  .replaceAll("-", "")
  .replaceAll(":", "");
const destinationName = `fleet-${timestamp}-${process.pid}.sqlite`;
if (!BACKUP_NAME.test(destinationName)) fail("could not derive backup name");
const destination = join(directory, destinationName);

const lifecycle = resolve(
  dirname(fileURLToPath(import.meta.url)),
  "database-lifecycle.mjs",
);
const child = spawnSync(
  process.execPath,
  [lifecycle, "backup", source, destination],
  {
    encoding: "utf8",
    env: {},
    maxBuffer: 64 * 1024,
    stdio: ["ignore", "pipe", "pipe"],
    timeout: 15 * 60 * 1_000,
  },
);
if (child.error !== undefined || child.status !== 0 || child.signal !== null) {
  fail("online Fleet backup failed");
}
if (child.stderr !== "")
  fail("online Fleet backup emitted unexpected diagnostics");
const result = parseLifecycleResult(child.stdout);

const backups = readdirSync(directory)
  .filter((name) => BACKUP_NAME.test(name))
  .sort();
for (const name of backups) assertPrivateBackup(join(directory, name));

const obsolete = backups.slice(0, Math.max(0, backups.length - retention));
for (const name of obsolete) unlinkSync(join(directory, name));
syncDirectory(directory);

process.stdout.write(
  `${JSON.stringify({
    operation: "scheduled-backup",
    backup: destinationName,
    retained: backups.length - obsolete.length,
    removed: obsolete.length,
    userVersion: result.userVersion,
    tableCount: result.tableCount,
  })}\n`,
);

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

function assertPrivateBackup(path) {
  const entry = lstatSync(path);
  if (!entry.isFile() || entry.isSymbolicLink() || entry.size === 0) {
    fail("retained backup must be a non-empty regular file");
  }
  if (process.platform !== "win32" && (entry.mode & 0o077) !== 0) {
    fail("retained backup permissions must deny group and other access");
  }
}

function parseLifecycleResult(output) {
  if (output.length === 0 || output.length > 4096 || !output.endsWith("\n")) {
    fail("online Fleet backup returned an invalid receipt");
  }
  let value;
  try {
    value = JSON.parse(output);
  } catch {
    fail("online Fleet backup returned an invalid receipt");
  }
  if (
    value === null ||
    typeof value !== "object" ||
    Array.isArray(value) ||
    value.operation !== "backup" ||
    !Number.isSafeInteger(value.userVersion) ||
    value.userVersion < 1 ||
    !Number.isSafeInteger(value.tableCount) ||
    value.tableCount < 1 ||
    Object.keys(value).sort().join(",") !== "operation,tableCount,userVersion"
  ) {
    fail("online Fleet backup returned an invalid receipt");
  }
  return value;
}

function syncDirectory(path) {
  const descriptor = openSync(path, constants.O_RDONLY | constants.O_DIRECTORY);
  try {
    fsyncSync(descriptor);
  } finally {
    closeSync(descriptor);
  }
}

function fail(message) {
  throw new Error(message);
}
