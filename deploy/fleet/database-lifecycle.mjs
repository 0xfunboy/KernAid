import { backup, DatabaseSync } from "node:sqlite";
import {
  chmodSync,
  lstatSync,
  realpathSync,
  unlinkSync,
} from "node:fs";
import { dirname, resolve } from "node:path";

process.umask(0o077);

const REQUIRED_TABLES = [
  "assets",
  "devices",
  "enrollment_tokens",
  "inventory_events",
  "tenants",
];

const [operation, sourceArgument, destinationArgument] = process.argv.slice(2);

if (
  !["backup", "restore", "verify"].includes(operation) ||
  sourceArgument === undefined ||
  (operation === "verify") !== (destinationArgument === undefined)
) {
  fail(
    "usage: database-lifecycle.mjs verify <database> | (backup|restore) <source> <new-destination>",
  );
}

const source = resolve(sourceArgument);
assertSecureDatabase(source);
const sourceSummary = verifyDatabase(source);

if (operation === "verify") {
  process.stdout.write(
    `${JSON.stringify({ operation, ...sourceSummary })}\n`,
  );
  process.exit(0);
}

const destination = resolve(destinationArgument);
if (source === destination) fail("source and destination must be different");
assertNewDestination(destination);

let destinationCreated = false;
const sourceDatabase = new DatabaseSync(source, {
  readOnly: true,
  timeout: 5_000,
});
try {
  await backup(sourceDatabase, destination, { rate: 100 });
  destinationCreated = true;
} catch (error) {
  removePartialDestination(destination);
  throw error;
} finally {
  sourceDatabase.close();
}

try {
  chmodSync(destination, 0o600);
  const destinationSummary = verifyDatabase(destination);
  process.stdout.write(
    `${JSON.stringify({ operation, ...destinationSummary })}\n`,
  );
} catch (error) {
  if (destinationCreated) removePartialDestination(destination);
  throw error;
}

function verifyDatabase(path) {
  const database = new DatabaseSync(path, { readOnly: true, timeout: 5_000 });
  try {
    const integrity = database.prepare("PRAGMA quick_check").get();
    if (integrity?.quick_check !== "ok") fail("SQLite quick_check failed");
    const foreignKeyFailures = database
      .prepare("PRAGMA foreign_key_check")
      .all();
    if (foreignKeyFailures.length !== 0) fail("SQLite foreign keys are invalid");
    const version = database.prepare("PRAGMA user_version").get()?.user_version;
    if (!Number.isSafeInteger(version) || version < 1)
      fail("unsupported Fleet database version");
    const tables = database
      .prepare(
        "SELECT name FROM sqlite_schema WHERE type = 'table' AND name NOT LIKE 'sqlite_%' ORDER BY name",
      )
      .all()
      .map((row) => row.name);
    for (const required of REQUIRED_TABLES) {
      if (!tables.includes(required)) fail("Fleet database schema is incomplete");
    }
    return { userVersion: version, tableCount: tables.length };
  } finally {
    database.close();
  }
}

function assertSecureDatabase(path) {
  const entry = lstatSync(path);
  if (!entry.isFile() || entry.isSymbolicLink())
    fail("database must be a regular non-symlink file");
  if (process.platform !== "win32" && (entry.mode & 0o077) !== 0)
    fail("database permissions must deny group and other access");
}

function assertNewDestination(path) {
  const parent = dirname(path);
  const parentEntry = lstatSync(parent);
  if (!parentEntry.isDirectory() || parentEntry.isSymbolicLink())
    fail("destination parent must be a regular directory");
  if (realpathSync(parent) !== parent)
    fail("destination parent must use its canonical path");
  try {
    lstatSync(path);
    fail("destination already exists");
  } catch (error) {
    if (error?.code !== "ENOENT") throw error;
  }
}

function removePartialDestination(path) {
  try {
    unlinkSync(path);
  } catch (error) {
    if (error?.code !== "ENOENT") throw error;
  }
}

function fail(message) {
  throw new Error(message);
}
