import assert from "node:assert/strict";
import { createPublicKey, verify } from "node:crypto";
import { test } from "node:test";
import {
  FleetSchemaError,
  canonicalJson,
  enrollmentSigningBytes,
  inventorySigningBytes,
  parseEnrollmentRequest,
  parseInventoryEnvelope,
  toUnsignedEnrollment,
  toUnsignedInventory,
} from "../src/index.js";

const PUBLIC_KEY_SPKI =
  "MCowBQYDK2VwAyEAIVL40Zt5HSRFMkLhXy6rbLfP-ntqXtMAl5YOBpiB2xI";
const ENROLLMENT_UNSIGNED =
  '{"agentVersion":"0.1.0-test","deviceId":"KA-3097e2dee2cb4a34b53840cd","enrollmentToken":"enroll_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA","issuedAt":"2026-08-31T12:30:45Z","nonce":"paWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaU","platform":"linux","publicKeySpki":"MCowBQYDK2VwAyEAIVL40Zt5HSRFMkLhXy6rbLfP-ntqXtMAl5YOBpiB2xI","schema":"dev.kernaid.fleet.enrollment-request.v1","tenantId":"tenant-europe-1"}';
const ENROLLMENT_JSON =
  '{"agentVersion":"0.1.0-test","deviceId":"KA-3097e2dee2cb4a34b53840cd","enrollmentToken":"enroll_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA","issuedAt":"2026-08-31T12:30:45Z","nonce":"paWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaU","platform":"linux","publicKeySpki":"MCowBQYDK2VwAyEAIVL40Zt5HSRFMkLhXy6rbLfP-ntqXtMAl5YOBpiB2xI","schema":"dev.kernaid.fleet.enrollment-request.v1","signature":"Rn91i6zELcEN9cp0jv-tP8dHdRcsTEczoXkdaxf3xx4QKKVXj1P67jHqdSUT7X1oyP46mks_hvXGSbKrk7PNBQ","tenantId":"tenant-europe-1"}';
const INVENTORY_UNSIGNED =
  '{"asset":{"architecture":"x86_64","assetId":"asset-01","findingCounts":{"critical":1,"info":3,"warning":2},"health":"attention","osRelease":"Debian 13","platform":"linux","snapshotSha256":"16a0eeb0791b6c92451fd284dd9f599e0a7dbe7f6ebea6e2d2d06c7f74aec112","targetFingerprint":"a5652641f192351052d23f21e1803f6fd6c16785058b307dc79e79ec732a462f"},"deviceId":"KA-3097e2dee2cb4a34b53840cd","observedAt":"2026-08-31T12:30:45Z","schema":"dev.kernaid.fleet.inventory-envelope.v1","sequence":7,"tenantId":"tenant-europe-1"}';
const INVENTORY_JSON =
  '{"asset":{"architecture":"x86_64","assetId":"asset-01","findingCounts":{"critical":1,"info":3,"warning":2},"health":"attention","osRelease":"Debian 13","platform":"linux","snapshotSha256":"16a0eeb0791b6c92451fd284dd9f599e0a7dbe7f6ebea6e2d2d06c7f74aec112","targetFingerprint":"a5652641f192351052d23f21e1803f6fd6c16785058b307dc79e79ec732a462f"},"deviceId":"KA-3097e2dee2cb4a34b53840cd","observedAt":"2026-08-31T12:30:45Z","schema":"dev.kernaid.fleet.inventory-envelope.v1","sequence":7,"signature":"JWA3A3N0H6OQPMr7YOFpMElp9O_m6AX5Cg7i4VP3lrxad21yPm5vAPJTAPWwHgav1rerscC0D9GcI3X95F9OAg","tenantId":"tenant-europe-1"}';

test("canonical JSON sorts object keys recursively and preserves array order", () => {
  assert.equal(
    canonicalJson({ z: [3, { z: null, a: "value" }], a: true }),
    '{"a":true,"z":[3,{"a":"value","z":null}]}',
  );
  assert.throws(() => canonicalJson({ value: 1.5 }), TypeError);
  assert.throws(
    () => canonicalJson({ value: Number.MAX_SAFE_INTEGER + 1 }),
    TypeError,
  );
  assert.throws(() => canonicalJson({ value: undefined }), TypeError);
});

test("Rust and TypeScript enrollment bytes and Ed25519 signature are identical", () => {
  const request = parseEnrollmentRequest(JSON.parse(ENROLLMENT_JSON));
  assert.equal(
    canonicalJson(toUnsignedEnrollment(request)),
    ENROLLMENT_UNSIGNED,
  );
  assert.equal(canonicalJson(request), ENROLLMENT_JSON);
  assert.equal(
    Buffer.from(enrollmentSigningBytes(request)).toString("utf8"),
    `kernaid:fleet:enrollment:v1\0${ENROLLMENT_UNSIGNED}`,
  );
  const key = createPublicKey({
    key: Buffer.from(PUBLIC_KEY_SPKI, "base64url"),
    format: "der",
    type: "spki",
  });
  assert.equal(
    verify(
      null,
      enrollmentSigningBytes(request),
      key,
      Buffer.from(request.signature, "base64url"),
    ),
    true,
  );
  assert.throws(
    () => parseEnrollmentRequest({ ...request, raw: "forbidden" }),
    FleetSchemaError,
  );
  assert.throws(
    () =>
      parseEnrollmentRequest({ ...request, issuedAt: "2026-02-31T00:00:00Z" }),
    FleetSchemaError,
  );
});

test("Rust and TypeScript inventory bytes and Ed25519 signature are identical", () => {
  const envelope = parseInventoryEnvelope(JSON.parse(INVENTORY_JSON));
  assert.equal(
    canonicalJson(toUnsignedInventory(envelope)),
    INVENTORY_UNSIGNED,
  );
  assert.equal(canonicalJson(envelope), INVENTORY_JSON);
  assert.equal(
    Buffer.from(inventorySigningBytes(envelope)).toString("utf8"),
    `kernaid:fleet:inventory:v1\0${INVENTORY_UNSIGNED}`,
  );
  const key = createPublicKey({
    key: Buffer.from(PUBLIC_KEY_SPKI, "base64url"),
    format: "der",
    type: "spki",
  });
  assert.equal(
    verify(
      null,
      inventorySigningBytes(envelope),
      key,
      Buffer.from(envelope.signature, "base64url"),
    ),
    true,
  );
  assert.throws(
    () =>
      parseInventoryEnvelope({
        ...envelope,
        asset: { ...envelope.asset, serialNumber: "must-not-cross-boundary" },
      }),
    FleetSchemaError,
  );
  assert.throws(
    () => parseInventoryEnvelope({ ...envelope, sequence: 1.25 }),
    FleetSchemaError,
  );
  assert.throws(
    () =>
      parseInventoryEnvelope({
        ...envelope,
        asset: { ...envelope.asset, snapshotSha256: "A".repeat(64) },
      }),
    FleetSchemaError,
  );
});
