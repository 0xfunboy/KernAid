import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import {
  appendFileSync,
  chmodSync,
  mkdtempSync,
  mkdirSync,
  readFileSync,
  readdirSync,
  rmSync,
  symlinkSync,
  writeFileSync,
} from "node:fs";
import {
  createHash,
  generateKeyPairSync,
  verify as verifyEd25519,
} from "node:crypto";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { DatabaseSync } from "node:sqlite";
import { test } from "node:test";

const directory = dirname(fileURLToPath(import.meta.url));
const lifecycle = join(directory, "database-lifecycle.mjs");
const scheduled = join(directory, "scheduled-backup.mjs");
const domain = Buffer.from("kernaid:fleet:database-backup:v1\0", "utf8");

test("signed Fleet bundle verifies offline and restores exact bytes", (t) => {
  const fixture = createFixture(t);
  const bundle = join(fixture.backups, "manual.backup");
  const created = run(lifecycle, [
    "backup",
    fixture.database,
    bundle,
    fixture.signingKey,
  ]);
  assert.equal(created.status, 0, created.stderr);
  const receipt = JSON.parse(created.stdout);
  assert.equal(receipt.operation, "backup");
  assert.match(receipt.databaseSha256, /^[0-9a-f]{64}$/);

  const manifestBytes = readFileSync(join(bundle, "manifest.json"));
  const manifest = JSON.parse(manifestBytes.toString("utf8"));
  assert.equal(canonicalJson(manifest), manifestBytes.toString("utf8"));
  assert.equal(
    manifest.schema,
    "dev.kernaid.fleet.database-backup-manifest.v1",
  );
  assert.equal(manifest.database.sqliteUserVersion, 10);
  assert.deepEqual(manifest.database.tables, [
    "assets",
    "devices",
    "enrollment_tokens",
    "inventory_events",
    "tenants",
  ]);
  const databaseBytes = readFileSync(join(bundle, "fleet.sqlite"));
  assert.equal(
    manifest.database.sha256,
    createHash("sha256").update(databaseBytes).digest("hex"),
  );
  assert.equal(manifest.database.sizeBytes, databaseBytes.length);
  const signature = Buffer.from(
    readFileSync(join(bundle, "manifest.sig"), "ascii").trimEnd(),
    "base64url",
  );
  assert.equal(
    verifyEd25519(
      null,
      Buffer.concat([domain, manifestBytes]),
      fixture.publicKey,
      signature,
    ),
    true,
  );

  const verified = run(lifecycle, ["verify", bundle, fixture.trustAnchor]);
  assert.equal(verified.status, 0, verified.stderr);
  assert.equal(
    JSON.parse(verified.stdout).databaseSha256,
    receipt.databaseSha256,
  );

  const restored = join(fixture.restore, "fleet.sqlite");
  const restore = run(lifecycle, [
    "restore",
    bundle,
    fixture.trustAnchor,
    restored,
  ]);
  assert.equal(restore.status, 0, restore.stderr);
  assert.deepEqual(readFileSync(restored), databaseBytes);
  const beforeReplay = readFileSync(restored);
  const replay = run(lifecycle, [
    "restore",
    bundle,
    fixture.trustAnchor,
    restored,
  ]);
  assert.notEqual(replay.status, 0);
  assert.deepEqual(readFileSync(restored), beforeReplay);
});

test("signed Fleet verification rejects tamper, symlinks, keys, and permissions", (t) => {
  const fixture = createFixture(t);
  const databaseBundle = createBundle(fixture, "database-tamper.backup");
  appendFileSync(join(databaseBundle, "fleet.sqlite"), Buffer.from([0]));
  assert.notEqual(
    run(lifecycle, ["verify", databaseBundle, fixture.trustAnchor]).status,
    0,
  );

  const manifestBundle = createBundle(fixture, "manifest-tamper.backup");
  appendFileSync(join(manifestBundle, "manifest.json"), "\n");
  assert.notEqual(
    run(lifecycle, ["verify", manifestBundle, fixture.trustAnchor]).status,
    0,
  );

  const permissionBundle = createBundle(fixture, "permission.backup");
  chmodSync(join(permissionBundle, "manifest.sig"), 0o644);
  assert.notEqual(
    run(lifecycle, ["verify", permissionBundle, fixture.trustAnchor]).status,
    0,
  );

  const keyPair = generateKeyPairSync("ed25519");
  const wrongAnchor = join(fixture.root, "wrong.public");
  writeFileSync(wrongAnchor, `${rawPublicKey(keyPair.publicKey)}\n`, {
    mode: 0o644,
  });
  const validBundle = createBundle(fixture, "wrong-anchor.backup");
  assert.notEqual(
    run(lifecycle, ["verify", validBundle, wrongAnchor]).status,
    0,
  );

  const anchorLink = join(fixture.root, "anchor-link");
  symlinkSync(fixture.trustAnchor, anchorLink);
  assert.notEqual(
    run(lifecycle, ["verify", validBundle, anchorLink]).status,
    0,
  );

  chmodSync(fixture.trustAnchor, 0o666);
  assert.notEqual(
    run(lifecycle, ["verify", validBundle, fixture.trustAnchor]).status,
    0,
  );
  chmodSync(fixture.trustAnchor, 0o644);

  chmodSync(fixture.signingKey, 0o644);
  const insecureKeyDestination = join(
    fixture.backups,
    "insecure-signing-key.backup",
  );
  assert.notEqual(
    run(lifecycle, [
      "backup",
      fixture.database,
      insecureKeyDestination,
      fixture.signingKey,
    ]).status,
    0,
  );
  chmodSync(fixture.signingKey, 0o600);

  const occupiedDestination = join(fixture.backups, "occupied.backup");
  mkdirSync(occupiedDestination, { mode: 0o700 });
  assert.notEqual(
    run(lifecycle, [
      "backup",
      fixture.database,
      occupiedDestination,
      fixture.signingKey,
    ]).status,
    0,
  );
  assert.deepEqual(readdirSync(occupiedDestination), []);
});

test("scheduled rotation retains verified bundles when a new signature fails", (t) => {
  const fixture = createFixture(t);
  for (let attempt = 0; attempt < 3; attempt += 1) {
    const result = run(scheduled, [
      fixture.database,
      fixture.backups,
      "2",
      fixture.signingKey,
      fixture.trustAnchor,
    ]);
    assert.equal(result.status, 0, result.stderr);
  }
  const retained = backupNames(fixture.backups);
  assert.equal(retained.length, 2);
  for (const name of retained) {
    assert.equal(
      run(lifecycle, [
        "verify",
        join(fixture.backups, name),
        fixture.trustAnchor,
      ]).status,
      0,
    );
  }

  const wrongPair = generateKeyPairSync("ed25519");
  const wrongKey = join(fixture.root, "wrong.pk8");
  writeFileSync(
    wrongKey,
    wrongPair.privateKey.export({ format: "der", type: "pkcs8" }),
    { mode: 0o600 },
  );
  const failed = run(scheduled, [
    fixture.database,
    fixture.backups,
    "2",
    wrongKey,
    fixture.trustAnchor,
  ]);
  assert.notEqual(failed.status, 0);
  assert.deepEqual(backupNames(fixture.backups), retained);
});

function createFixture(t) {
  const root = mkdtempSync(join(tmpdir(), "kernaid-fleet-backup-test-"));
  chmodSync(root, 0o700);
  t.after(() => rmSync(root, { recursive: true, force: true }));
  const backups = join(root, "backups");
  const restore = join(root, "restore");
  mkdirSync(backups, { mode: 0o700 });
  mkdirSync(restore, { mode: 0o700 });
  const database = join(root, "fleet.sqlite");
  const db = new DatabaseSync(database);
  for (const table of [
    "assets",
    "devices",
    "enrollment_tokens",
    "inventory_events",
    "tenants",
  ]) {
    db.exec(`CREATE TABLE ${table} (id TEXT PRIMARY KEY)`);
  }
  db.exec("PRAGMA user_version = 11");
  db.close();
  chmodSync(database, 0o600);

  const { privateKey, publicKey } = generateKeyPairSync("ed25519");
  const signingKey = join(root, "receipt-signing-key.pk8");
  const trustAnchor = join(root, "receipt.public");
  writeFileSync(
    signingKey,
    privateKey.export({ format: "der", type: "pkcs8" }),
    { mode: 0o600 },
  );
  writeFileSync(trustAnchor, `${rawPublicKey(publicKey)}\n`, { mode: 0o644 });
  return {
    root,
    backups,
    restore,
    database,
    signingKey,
    trustAnchor,
    publicKey,
  };
}

function createBundle(fixture, name) {
  const destination = join(fixture.backups, name);
  const result = run(lifecycle, [
    "backup",
    fixture.database,
    destination,
    fixture.signingKey,
  ]);
  assert.equal(result.status, 0, result.stderr);
  return destination;
}

function backupNames(path) {
  return readdirSync(path)
    .filter((name) => /^fleet-.*\.backup$/.test(name))
    .sort();
}

function rawPublicKey(publicKey) {
  return Buffer.from(publicKey.export({ format: "der", type: "spki" }))
    .subarray(-32)
    .toString("base64url");
}

function run(script, arguments_) {
  return spawnSync(process.execPath, [script, ...arguments_], {
    encoding: "utf8",
    env: {},
    timeout: 30_000,
    maxBuffer: 1024 * 1024,
  });
}

function canonicalJson(value) {
  if (value === null || typeof value !== "object") return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(",")}]`;
  return `{${Object.keys(value)
    .sort()
    .map((key) => `${JSON.stringify(key)}:${canonicalJson(value[key])}`)
    .join(",")}}`;
}
