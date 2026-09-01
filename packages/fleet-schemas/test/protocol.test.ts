import assert from "node:assert/strict";
import { createHash, createPublicKey, verify } from "node:crypto";
import { test } from "node:test";
import {
  FleetSchemaError,
  auditDomainPayloadBytes,
  auditSigningBytes,
  canonicalJson,
  entitlementPullSigningBytes,
  entitlementRevocationSigningBytes,
  entitlementSigningBytes,
  enrollmentSigningBytes,
  inventorySigningBytes,
  parsePolicyPullRequest,
  parseSignedPolicyBundleUnsigned,
  parseSignedPolicyBundle,
  policyProviderModes,
  policyBundleSigningBytes,
  policyPullSigningBytes,
  parseSignedUpdateManifest,
  parseUpdatePullUnsigned,
  parseUpdatePullResponse,
  assertUpdatePullResponseBinding,
  toUnsignedUpdateManifest,
  updateAppliesTo,
  updateManifestSigningBytes,
  updatePullSigningBytes,
  parseEnrollmentRequest,
  parseAuditEnvelope,
  parseInventoryEnvelope,
  parseEntitlementEnvelope,
  parseEntitlementPullRequest,
  parseEntitlementRevocationEnvelope,
  toUnsignedEnrollment,
  toUnsignedAudit,
  toUnsignedInventory,
  toUnsignedEntitlementPull,
  toUnsignedPolicyBundle,
  toUnsignedPolicyPull,
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
const AUDIT_PUBLIC_KEY_SPKI =
  "MCowBQYDK2VwAyEA4v4qObcyZkKCfW2C1JdiLNbCl_54Jw6qQ2sB8Ia288s";
const AUDIT_JSON =
  '{"actionId":null,"deviceId":"KA-b41fd894f96ec8adca19a85f","eventId":"event-0001","evidenceSha256":[],"kind":"diagnostic_started","occurredAt":"2026-08-31T14:15:16Z","outcome":"started","previousEventSha256":null,"reportSha256":null,"risk":"R0","schema":"dev.kernaid.fleet.audit-envelope.v1","sequence":1,"sessionId":"session-20260831-001","signature":"JiWRoJagnJva7Cwpcs6nZJPJQObhRzadTpduLvHfrV0mgKz3vc80Doe_Bd-SUehxgLzuLR1ZiPIgorcsZWRfBg","targetSha256":"34a04005bcaf206eec990bd9637d9fdb6725e0a0c0d4aebf003f17f4c956eb5c","tenantId":"tenant-europe-1"}';
const AUDIT_SHA256 =
  "141786229c5b9b5e7b05ed50651931bdbcbebaeee9685135e2469cf07d2a4859";
const POLICY_PULL_UNSIGNED =
  '{"deviceId":"KA-3097e2dee2cb4a34b53840cd","issuedAt":"2026-08-31T12:30:45Z","nonce":"paWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaU","schema":"dev.kernaid.fleet.policy-pull-request.v1","tenantId":"tenant-europe-1"}';
const POLICY_PULL_JSON =
  '{"deviceId":"KA-3097e2dee2cb4a34b53840cd","issuedAt":"2026-08-31T12:30:45Z","nonce":"paWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaU","schema":"dev.kernaid.fleet.policy-pull-request.v1","signature":"7COdZ1ket_ukr-YZOcMHj3kdfeL6gSuM5U0ggUlAOXnsjdUw0duGkfyWh4BqBV0_nEcbXvbfmETKcuIdiM5JCA","tenantId":"tenant-europe-1"}';
const POLICY_PUBLIC_KEY_SPKI =
  "MCowBQYDK2VwAyEAIBLLkMpg6OXY2vZuInLSIz4EhtVX6MZhQe2JIBd9frc";
const POLICY_BUNDLE_JSON =
  '{"assignments":{"deviceIds":["KA-0123456789abcdef01234567"]},"expiresAtUnix":1800172800,"issuedAtUnix":1800000000,"notBeforeUnix":1800000100,"offlineAllowedUntilUnix":1800086400,"policyId":"repair-baseline","revision":7,"rules":{"allowEvidenceUpload":true,"allowedActionIds":["linux.fstab.disable-missing-uuid.v1","system.observe.noop"],"deniedActionIds":["windows.registry.unsafe.v1"],"emergencyRollbackAlwaysAllowed":true,"localApprovalFrom":"R1","maxRisk":"R2","providerModes":["enterprise","offline","openai_api"],"retentionDays":90,"updateRing":"stable"},"schema":"dev.kernaid.fleet.policy-bundle.v1","signature":"fqRlJ15i5Hyn_oec1PkbDWMIjyFxMLEOPnnyOshBjnZciwVgu-v_uW5vIAiHqyi7p3CfGucukV2U-7AaHDjjBg","tenantId":"tenant-europe-1"}';
const ENTITLEMENT_PULL_UNSIGNED =
  '{"deviceId":"KA-3097e2dee2cb4a34b53840cd","issuedAt":"2026-08-31T12:30:45Z","nonce":"paWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaU","schema":"dev.kernaid.fleet.entitlement-pull-request.v1","tenantId":"tenant-europe-1"}';
const ENTITLEMENT_PULL_JSON =
  '{"deviceId":"KA-3097e2dee2cb4a34b53840cd","issuedAt":"2026-08-31T12:30:45Z","nonce":"paWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaU","schema":"dev.kernaid.fleet.entitlement-pull-request.v1","signature":"eg54h5wivxIbZKXcoJZEVfa7_5Yi8q6IofVQqLEnYeBFiYiLanDDncO8PGgsyQiyjf2V04NkrGj2CTMRlB-HCQ","tenantId":"tenant-europe-1"}';
const ENTITLEMENT_ISSUER_SPKI =
  "MCowBQYDK2VwAyEAwFDFY3pE-oYp__PMzOIwDLNipj2Z2V_FQUUmb0MyRFo";
const ENTITLEMENT_JSON =
  '{"claims":{"deviceIds":["device_alpha","device_beta"],"entitlementId":"ent_acme_001","expiresAtUnix":3000,"features":["audit","enterprise_repair","fleet","policy","updates"],"graceUntilUnix":4000,"issuedAtUnix":1000,"limits":{"maxManagedAssets":5000,"maxTechnicians":16,"maxToolDevices":8},"notBeforeUnix":1000,"offlineLeaseUntilUnix":2000,"plan":"enterprise","schema":"dev.kernaid.entitlement.v1","sequence":1,"tenantId":"tenant_acme"},"signature":"sWOJD4yoB89_MICu3glOpehAV8zeXJKXmI_TwnMDj7aZ0MxgA8C4pGtQUWumOMLEDQJp_ZoAbCbmSRpPWKRuBQ"}';
const ENTITLEMENT_REVOCATIONS_JSON =
  '{"claims":{"issuedAtUnix":1400,"revokedEntitlementIds":["ent_acme_001"],"schema":"dev.kernaid.entitlement-revocations.v1","sequence":7},"signature":"mOEmDZRrBVWAlYfPFMTT6ywK3y1_hLn0Dd1cdXVAUdg0UM0fZ7CinsR8OSP02TvlVqrl47vkYOcciAMtBIYgBw"}';
const UPDATE_PUBLIC_KEY_SPKI =
  "MCowBQYDK2VwAyEA4v4qObcyZkKCfW2C1JdiLNbCl_54Jw6qQ2sB8Ia288s";
const UPDATE_UNSIGNED =
  '{"architecture":"x86_64","artifact":{"sha256":"1111111111111111111111111111111111111111111111111111111111111111","sizeBytes":4096,"url":"https://updates.kernaid.example/releases/1.2/image.raw.zst"},"emergencyRollback":false,"expiresAtUnix":1800086400,"issuedAtUnix":1800000000,"notBeforeUnix":1800000100,"platform":"linux","releaseId":"kernaid-1.2.17","releaseRing":"stable","releaseVersion":"1.2.17+build.4","rollout":{"basisPoints":10000,"seed":"stable-2026-08"},"schema":"dev.kernaid.update.manifest.v1","sequence":17}';
const UPDATE_JSON =
  '{"architecture":"x86_64","artifact":{"sha256":"1111111111111111111111111111111111111111111111111111111111111111","sizeBytes":4096,"url":"https://updates.kernaid.example/releases/1.2/image.raw.zst"},"emergencyRollback":false,"expiresAtUnix":1800086400,"issuedAtUnix":1800000000,"notBeforeUnix":1800000100,"platform":"linux","releaseId":"kernaid-1.2.17","releaseRing":"stable","releaseVersion":"1.2.17+build.4","rollout":{"basisPoints":10000,"seed":"stable-2026-08"},"schema":"dev.kernaid.update.manifest.v1","sequence":17,"signature":"FJvv4L6RH6VL9CdIbFPTsGY5WEhOODEac9iS2M6GAcknqdrr683vBcGeMzYd3m5_gxdpKRA_Dl8ZA5xcT7KiDQ"}';

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

test("Fleet policy exposes the complete closed P0 provider catalog", () => {
  assert.deepEqual(policyProviderModes, [
    "anthropic_api",
    "enterprise",
    "gemini_api",
    "offline",
    "openai_api",
    "openai_compatible",
  ]);
  const policy = toUnsignedPolicyBundle(
    parseSignedPolicyBundle(JSON.parse(POLICY_BUNDLE_JSON)),
  );
  policy.rules.providerModes = [...policyProviderModes];
  assert.deepEqual(
    parseSignedPolicyBundleUnsigned(policy).rules.providerModes,
    policyProviderModes,
  );
  policy.rules.providerModes.reverse();
  assert.throws(
    () => parseSignedPolicyBundleUnsigned(policy),
    FleetSchemaError,
  );
});

test("Rust and TypeScript update manifest bytes and signature are identical", () => {
  const manifest = parseSignedUpdateManifest(JSON.parse(UPDATE_JSON));
  assert.equal(
    canonicalJson(toUnsignedUpdateManifest(manifest)),
    UPDATE_UNSIGNED,
  );
  assert.equal(canonicalJson(manifest), UPDATE_JSON);
  assert.equal(
    Buffer.from(updateManifestSigningBytes(manifest)).toString(),
    `kernaid:update:manifest:v1\0${UPDATE_UNSIGNED}`,
  );
  const key = createPublicKey({
    key: Buffer.from(UPDATE_PUBLIC_KEY_SPKI, "base64url"),
    format: "der",
    type: "spki",
  });
  assert.equal(
    verify(
      null,
      updateManifestSigningBytes(manifest),
      key,
      Buffer.from(manifest.signature, "base64url"),
    ),
    true,
  );

  const pull = parseUpdatePullUnsigned({
    schema: "dev.kernaid.fleet.update-pull-request.v1",
    tenantId: "tenant-europe-1",
    deviceId: "KA-0123456789abcdef01234567",
    platform: "linux",
    architecture: "x86_64",
    updateRing: "stable",
    issuedAt: "2026-08-31T12:30:45Z",
    nonce: "paWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaU",
  });
  assert.equal(updateAppliesTo(manifest, pull, 1_800_000_200), true);
  assert.equal(
    updateAppliesTo(manifest, { ...pull, updateRing: "hold" }, 1_800_000_200),
    false,
  );
  assert.match(
    Buffer.from(updatePullSigningBytes(pull)).toString(),
    /^kernaid:fleet:update-pull:v1\0\{"architecture":"x86_64"/,
  );
  const response = parseUpdatePullResponse({
    schema: "dev.kernaid.fleet.update-pull-response.v1",
    tenantId: pull.tenantId,
    deviceId: pull.deviceId,
    platform: pull.platform,
    architecture: pull.architecture,
    updateRing: pull.updateRing,
    items: [manifest],
  });
  assert.doesNotThrow(() => assertUpdatePullResponseBinding(response, pull));
  assert.throws(
    () =>
      assertUpdatePullResponseBinding(
        { ...response, updateRing: "canary" },
        pull,
      ),
    FleetSchemaError,
  );
  assert.throws(
    () => parseSignedUpdateManifest({ ...manifest, sequence: 17.5 }),
    FleetSchemaError,
  );
  assert.throws(
    () => parseSignedUpdateManifest({ ...manifest, privateKey: "forbidden" }),
    FleetSchemaError,
  );
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

test("Rust and TypeScript audit framing and signature are byte-identical", () => {
  const envelope = parseAuditEnvelope(JSON.parse(AUDIT_JSON));
  assert.equal(canonicalJson(envelope), AUDIT_JSON);
  assert.equal(
    createHash("sha256").update(AUDIT_JSON).digest("hex"),
    AUDIT_SHA256,
  );

  const unsigned = canonicalJson(toUnsignedAudit(envelope));
  const domainPayload = Buffer.from(auditDomainPayloadBytes(envelope));
  const auditDomain = Buffer.from("kernaid:fleet:audit:v1\0", "utf8");
  assert.equal(
    domainPayload.subarray(0, auditDomain.length).equals(auditDomain),
    true,
  );
  assert.equal(
    domainPayload.readBigUInt64BE(auditDomain.length),
    BigInt(Buffer.byteLength(unsigned)),
  );
  assert.equal(
    domainPayload.subarray(auditDomain.length + 8).toString(),
    unsigned,
  );

  const signingBytes = Buffer.from(auditSigningBytes(envelope));
  const reportDomain = Buffer.from("KERNAID-SIGNED-REPORT-V1\0", "utf8");
  assert.equal(
    signingBytes.subarray(0, reportDomain.length).equals(reportDomain),
    true,
  );
  assert.equal(
    signingBytes
      .subarray(reportDomain.length, reportDomain.length + 8)
      .equals(Buffer.alloc(8)),
    true,
  );
  assert.equal(
    signingBytes.readBigUInt64BE(reportDomain.length + 8),
    BigInt(domainPayload.length),
  );
  assert.equal(
    signingBytes.subarray(reportDomain.length + 16).equals(domainPayload),
    true,
  );

  const key = createPublicKey({
    key: Buffer.from(AUDIT_PUBLIC_KEY_SPKI, "base64url"),
    format: "der",
    type: "spki",
  });
  assert.equal(
    verify(
      null,
      signingBytes,
      key,
      Buffer.from(envelope.signature, "base64url"),
    ),
    true,
  );
  assert.throws(
    () => parseAuditEnvelope({ ...envelope, rawLog: "forbidden" }),
    FleetSchemaError,
  );
});

test("Rust and TypeScript policy pull bytes are byte-identical", () => {
  const request = parsePolicyPullRequest(JSON.parse(POLICY_PULL_JSON));
  assert.equal(canonicalJson(request), POLICY_PULL_JSON);
  assert.equal(
    canonicalJson(toUnsignedPolicyPull(request)),
    POLICY_PULL_UNSIGNED,
  );
  assert.equal(
    Buffer.from(policyPullSigningBytes(request)).toString("utf8"),
    `kernaid:fleet:policy-pull:v1\0${POLICY_PULL_UNSIGNED}`,
  );
  const key = createPublicKey({
    key: Buffer.from(PUBLIC_KEY_SPKI, "base64url"),
    format: "der",
    type: "spki",
  });
  assert.equal(
    verify(
      null,
      policyPullSigningBytes(request),
      key,
      Buffer.from(request.signature, "base64url"),
    ),
    true,
  );
  assert.throws(
    () => parsePolicyPullRequest({ ...request, rawDiagnostics: [] }),
    FleetSchemaError,
  );
});

test("Rust and TypeScript signed policy bundle framing is byte-identical", () => {
  const bundle = parseSignedPolicyBundle(JSON.parse(POLICY_BUNDLE_JSON));
  assert.equal(canonicalJson(bundle), POLICY_BUNDLE_JSON);
  const unsigned = canonicalJson(toUnsignedPolicyBundle(bundle));
  const signingBytes = Buffer.from(policyBundleSigningBytes(bundle));
  const domain = Buffer.from("kernaid:fleet:policy:v1\0", "utf8");
  assert.equal(signingBytes.subarray(0, domain.length).equals(domain), true);
  assert.equal(
    signingBytes.readBigUInt64BE(domain.length),
    BigInt(Buffer.byteLength(unsigned)),
  );
  assert.equal(signingBytes.subarray(domain.length + 8).toString(), unsigned);
  const key = createPublicKey({
    key: Buffer.from(POLICY_PUBLIC_KEY_SPKI, "base64url"),
    format: "der",
    type: "spki",
  });
  assert.equal(
    verify(null, signingBytes, key, Buffer.from(bundle.signature, "base64url")),
    true,
  );
  assert.throws(
    () => parseSignedPolicyBundle({ ...bundle, repairCommand: "forbidden" }),
    FleetSchemaError,
  );
  assert.throws(
    () =>
      parseSignedPolicyBundle({
        ...bundle,
        rules: { ...bundle.rules, emergencyRollbackAlwaysAllowed: false },
      }),
    FleetSchemaError,
  );
});

test("Rust and TypeScript entitlement pull bytes are byte-identical", () => {
  const request = parseEntitlementPullRequest(
    JSON.parse(ENTITLEMENT_PULL_JSON),
  );
  assert.equal(canonicalJson(request), ENTITLEMENT_PULL_JSON);
  assert.equal(
    canonicalJson(toUnsignedEntitlementPull(request)),
    ENTITLEMENT_PULL_UNSIGNED,
  );
  assert.equal(
    Buffer.from(entitlementPullSigningBytes(request)).toString(),
    `kernaid:fleet:entitlement-pull:v1\0${ENTITLEMENT_PULL_UNSIGNED}`,
  );
  const key = createPublicKey({
    key: Buffer.from(PUBLIC_KEY_SPKI, "base64url"),
    format: "der",
    type: "spki",
  });
  assert.equal(
    verify(
      null,
      entitlementPullSigningBytes(request),
      key,
      Buffer.from(request.signature, "base64url"),
    ),
    true,
  );
  assert.throws(
    () => parseEntitlementPullRequest({ ...request, diagnostics: [] }),
    FleetSchemaError,
  );
});

test("Rust and TypeScript entitlement documents use identical framing", () => {
  const key = createPublicKey({
    key: Buffer.from(ENTITLEMENT_ISSUER_SPKI, "base64url"),
    format: "der",
    type: "spki",
  });
  const entitlement = parseEntitlementEnvelope(JSON.parse(ENTITLEMENT_JSON));
  assert.equal(canonicalJson(entitlement), ENTITLEMENT_JSON);
  assert.equal(
    verify(
      null,
      entitlementSigningBytes(entitlement),
      key,
      Buffer.from(entitlement.signature, "base64url"),
    ),
    true,
  );

  const revocations = parseEntitlementRevocationEnvelope(
    JSON.parse(ENTITLEMENT_REVOCATIONS_JSON),
  );
  assert.equal(canonicalJson(revocations), ENTITLEMENT_REVOCATIONS_JSON);
  assert.equal(
    verify(
      null,
      entitlementRevocationSigningBytes(revocations),
      key,
      Buffer.from(revocations.signature, "base64url"),
    ),
    true,
  );
  assert.throws(
    () =>
      parseEntitlementEnvelope({
        ...entitlement,
        claims: { ...entitlement.claims, deviceIds: ["z", "a"] },
      }),
    FleetSchemaError,
  );
});
