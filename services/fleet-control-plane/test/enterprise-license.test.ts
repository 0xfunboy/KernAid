import assert from "node:assert/strict";
import { generateKeyPairSync } from "node:crypto";
import { test } from "node:test";
import { ed25519RawPublicKey } from "../src/crypto.js";
import {
  ENTERPRISE_LICENSE_SCHEMA,
  evaluateEnterpriseLicense,
  parseEnterpriseLicenseEnvelope,
  signEnterpriseLicense,
  verifyEnterpriseLicense,
  type EnterpriseLicenseClaims,
} from "../src/enterprise-license.js";

const issuer = generateKeyPairSync("ed25519");
const anchor = ed25519RawPublicKey(issuer.publicKey);
const claims: EnterpriseLicenseClaims = {
  schema: ENTERPRISE_LICENSE_SCHEMA,
  version: 1,
  licenseId: "license_fixture_1",
  tenantId: "tenant_fixture_1",
  sequence: 1,
  keyId: "vendor-2026-01",
  plan: "enterprise",
  features: ["device_management", "remote_diagnosis", "technician_seats"],
  deviceLimit: 25,
  seatLimit: 5,
  issuedAtUnix: 1_800_000_000,
  notBeforeUnix: 1_800_000_000,
  expiresAtUnix: 1_800_086_400,
  graceUntilUnix: 1_800_172_800,
};

test("enterprise license signature binds tenant, key ID, and exact claims", () => {
  const envelope = signEnterpriseLicense(claims, issuer.privateKey);
  assert.deepEqual(parseEnterpriseLicenseEnvelope(envelope), envelope);
  assert.equal(
    verifyEnterpriseLicense(envelope, anchor, claims.keyId, claims.tenantId),
    true,
  );
  assert.equal(
    verifyEnterpriseLicense(envelope, anchor, claims.keyId, "tenant_other"),
    false,
  );
  assert.equal(
    verifyEnterpriseLicense(
      { ...envelope, claims: { ...claims, deviceLimit: 26 } },
      anchor,
      claims.keyId,
      claims.tenantId,
    ),
    false,
  );
  assert.throws(() =>
    parseEnterpriseLicenseEnvelope({
      ...envelope,
      claims: {
        ...claims,
        features: ["technician_seats", "device_management"],
      },
    }),
  );
});

test("enterprise license lifecycle denies grace, expiry, revocation, and rollback", () => {
  assert.equal(
    evaluateEnterpriseLicense(claims, {
      nowUnix: claims.notBeforeUnix,
      retainedClockUnix: claims.notBeforeUnix,
      revoked: false,
    }).state,
    "active",
  );
  assert.equal(
    evaluateEnterpriseLicense(claims, {
      nowUnix: claims.expiresAtUnix,
      retainedClockUnix: claims.expiresAtUnix,
      revoked: false,
    }).state,
    "grace",
  );
  assert.equal(
    evaluateEnterpriseLicense(claims, {
      nowUnix: claims.graceUntilUnix,
      retainedClockUnix: claims.graceUntilUnix,
      revoked: false,
    }).state,
    "expired",
  );
  assert.equal(
    evaluateEnterpriseLicense(claims, {
      nowUnix: claims.notBeforeUnix,
      retainedClockUnix: claims.notBeforeUnix,
      revoked: true,
    }).state,
    "revoked",
  );
  assert.equal(
    evaluateEnterpriseLicense(claims, {
      nowUnix: claims.notBeforeUnix,
      retainedClockUnix: claims.notBeforeUnix + 301,
      revoked: false,
    }).state,
    "clock_rollback",
  );
});
