import assert from "node:assert/strict";
import { generateKeyPairSync } from "node:crypto";
import { chmodSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";
import { loadFleetServiceConfig } from "../src/config.js";
import { ed25519RawPublicKey } from "../src/crypto.js";

test("external receipt key and matching public anchor load from bounded files", (t) => {
  const directory = mkdtempSync(join(tmpdir(), "kernaid-fleet-config-"));
  t.after(() => rmSync(directory, { recursive: true, force: true }));

  const issuer = generateKeyPairSync("ed25519");
  const signingKeyPath = join(directory, "receipt.pk8");
  const anchorPath = join(directory, "receipt.public");
  const rootTokenPath = join(directory, "root-token");
  const databasePath = join(directory, "state", "fleet.sqlite");
  const publicAnchor = ed25519RawPublicKey(issuer.publicKey);

  writeFileSync(
    signingKeyPath,
    issuer.privateKey.export({ format: "der", type: "pkcs8" }),
    { mode: 0o600 },
  );
  writeFileSync(anchorPath, `${publicAnchor}\n`, { mode: 0o644 });
  writeFileSync(rootTokenPath, `root_${"r".repeat(40)}\n`, { mode: 0o600 });

  const environment = {
    KERNAID_FLEET_ROOT_TOKEN_FILE: rootTokenPath,
    KERNAID_FLEET_DB_PATH: databasePath,
    KERNAID_FLEET_ENTITLEMENT_TRUST_ANCHOR_FILE: anchorPath,
    KERNAID_FLEET_UPDATE_TRUST_ANCHOR_FILE: anchorPath,
    KERNAID_FLEET_ENTERPRISE_LICENSE_TRUST_ANCHOR_FILE: anchorPath,
    KERNAID_FLEET_ENTERPRISE_LICENSE_KEY_ID: "vendor-2026-01",
    KERNAID_FLEET_SERVICE_RECEIPT_SIGNING_KEY_FILE: signingKeyPath,
    KERNAID_FLEET_SERVICE_RECEIPT_TRUST_ANCHOR_FILE: anchorPath,
  };

  const config = loadFleetServiceConfig(environment);
  assert.equal(config.serviceReceiptTrustAnchor, publicAnchor);
  assert.equal(config.enterpriseLicenseTrustAnchor, publicAnchor);
  assert.equal(config.enterpriseLicenseKeyId, "vendor-2026-01");
  assert.equal(
    ed25519RawPublicKey(config.serviceReceiptSigningKey),
    publicAnchor,
  );
  assert.equal(config.consoleSessionTtlMs, 900_000);
  assert.equal(
    loadFleetServiceConfig({
      ...environment,
      KERNAID_FLEET_CONSOLE_SESSION_TTL_SECONDS: "120",
    }).consoleSessionTtlMs,
    120_000,
  );
  assert.throws(
    () =>
      loadFleetServiceConfig({
        ...environment,
        KERNAID_FLEET_CONSOLE_SESSION_TTL_SECONDS: "59",
      }),
    /outside 60-3600/,
  );

  chmodSync(signingKeyPath, 0o644);
  assert.throws(
    () => loadFleetServiceConfig(environment),
    /must not be accessible by group or other/,
  );
  assert.throws(
    () =>
      loadFleetServiceConfig({
        ...environment,
        KERNAID_FLEET_SERVICE_RECEIPT_SIGNING_KEY_FILE: undefined,
      }),
    /KERNAID_FLEET_SERVICE_RECEIPT_SIGNING_KEY_FILE is required/,
  );
});
