import assert from "node:assert/strict";
import {
  createHash,
  generateKeyPairSync,
  randomBytes,
  sign,
  type KeyObject,
} from "node:crypto";
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { DatabaseSync } from "node:sqlite";
import { test } from "node:test";
import {
  FLEET_AUDIT_SCHEMA,
  FLEET_ENROLLMENT_SCHEMA,
  FLEET_INVENTORY_SCHEMA,
  FLEET_POLICY_BUNDLE_SCHEMA,
  FLEET_POLICY_PULL_SCHEMA,
  auditSigningBytes,
  canonicalJson,
  enrollmentSigningBytes,
  inventorySigningBytes,
  policyBundleSigningBytes,
  policyPullSigningBytes,
  type AuditEnvelope,
  type AuditEnvelopeUnsigned,
  type EnrollmentRequest,
  type EnrollmentRequestUnsigned,
  type FleetInventoryAsset,
  type InventoryEnvelope,
  type InventoryEnvelopeUnsigned,
  type PolicyAssignments,
  type PolicyPullRequest,
  type PolicyPullRequestUnsigned,
  type SignedPolicyBundle,
  type SignedPolicyBundleUnsigned,
} from "@kernaid/fleet-schemas";
import { FleetControlPlane } from "../src/server.js";

const ROOT_TOKEN = "root_" + "r".repeat(40);
const INITIAL_TIME = Date.parse("2026-08-31T12:00:00.000Z");

interface Harness {
  directory: string;
  databasePath: string;
  now: { value: number };
  service: FleetControlPlane;
  baseUrl: string;
}

interface TenantCredentials {
  tenantId: string;
  adminToken: string;
}

interface DeviceCredentials {
  privateKey: KeyObject;
  publicKeySpki: string;
  deviceId: string;
}

interface PolicySigner {
  privateKey: KeyObject;
  publicKeySpki: string;
}

interface HttpResult {
  status: number;
  body: Record<string, unknown>;
}

async function createHarness(options?: {
  directory?: string;
  now?: { value: number };
  consoleDirectory?: string;
}): Promise<Harness> {
  const directory =
    options?.directory ?? mkdtempSync(join(tmpdir(), "kernaid-fleet-test-"));
  const databasePath = join(directory, "fleet.sqlite");
  const now = options?.now ?? { value: INITIAL_TIME };
  const service = new FleetControlPlane({
    databasePath,
    rootToken: ROOT_TOKEN,
    now: () => new Date(now.value),
    consoleDirectory: options?.consoleDirectory,
  });
  const baseUrl = await service.listen();
  return { directory, databasePath, now, service, baseUrl };
}

async function destroyHarness(harness: Harness, remove = true): Promise<void> {
  await harness.service.close();
  if (remove) rmSync(harness.directory, { recursive: true, force: true });
}

async function api(
  harness: Harness,
  method: string,
  path: string,
  body?: unknown,
  token?: string,
): Promise<HttpResult> {
  const headers: Record<string, string> = {};
  if (body !== undefined) headers["content-type"] = "application/json";
  if (token !== undefined) headers.authorization = `Bearer ${token}`;
  const response = await fetch(`${harness.baseUrl}${path}`, {
    method,
    headers,
    ...(body === undefined ? {} : { body: JSON.stringify(body) }),
  });
  return {
    status: response.status,
    body: (await response.json()) as Record<string, unknown>,
  };
}

async function canonicalApi(
  harness: Harness,
  method: string,
  path: string,
  body: unknown,
  token?: string,
): Promise<HttpResult> {
  const headers: Record<string, string> = {
    "content-type": "application/json",
  };
  if (token !== undefined) headers.authorization = `Bearer ${token}`;
  const response = await fetch(`${harness.baseUrl}${path}`, {
    method,
    headers,
    body: canonicalJson(body),
  });
  return {
    status: response.status,
    body: (await response.json()) as Record<string, unknown>,
  };
}

async function createTenant(harness: Harness): Promise<TenantCredentials> {
  const result = await api(harness, "POST", "/v1/tenants", {}, ROOT_TOKEN);
  assert.equal(result.status, 201);
  assert.equal(typeof result.body.tenantId, "string");
  assert.equal(typeof result.body.adminToken, "string");
  return {
    tenantId: result.body.tenantId as string,
    adminToken: result.body.adminToken as string,
  };
}

async function createEnrollmentToken(
  harness: Harness,
  tenant: TenantCredentials,
  expiresInSeconds = 300,
): Promise<string> {
  const result = await api(
    harness,
    "POST",
    `/v1/tenants/${tenant.tenantId}/enrollment-tokens`,
    { expiresInSeconds },
    tenant.adminToken,
  );
  assert.equal(result.status, 201);
  return result.body.enrollmentToken as string;
}

function makeDevice(_deviceLabel: string): DeviceCredentials {
  const { privateKey, publicKey } = generateKeyPairSync("ed25519");
  const publicKeyDer = Buffer.from(
    publicKey.export({ format: "der", type: "spki" }),
  );
  return {
    privateKey,
    publicKeySpki: publicKeyDer.toString("base64url"),
    deviceId: `KA-${createHash("sha256")
      .update(publicKeyDer.subarray(12))
      .digest("hex")
      .slice(0, 24)}`,
  };
}

function signedEnrollment(
  harness: Harness,
  tenant: TenantCredentials,
  enrollmentToken: string,
  device: DeviceCredentials,
): EnrollmentRequest {
  const unsigned: EnrollmentRequestUnsigned = {
    schema: FLEET_ENROLLMENT_SCHEMA,
    enrollmentToken,
    tenantId: tenant.tenantId,
    deviceId: device.deviceId,
    publicKeySpki: device.publicKeySpki,
    platform: "linux",
    agentVersion: "0.1.0-test",
    issuedAt: new Date(harness.now.value).toISOString(),
    nonce: randomBytes(16).toString("base64url"),
  };
  return {
    ...unsigned,
    signature: sign(
      null,
      enrollmentSigningBytes(unsigned),
      device.privateKey,
    ).toString("base64url"),
  };
}

async function enroll(
  harness: Harness,
  tenant: TenantCredentials,
  deviceId: string,
): Promise<DeviceCredentials> {
  const token = await createEnrollmentToken(harness, tenant);
  const device = makeDevice(deviceId);
  const result = await api(
    harness,
    "POST",
    "/v1/enrollments",
    signedEnrollment(harness, tenant, token, device),
  );
  assert.equal(result.status, 201);
  return device;
}

function asset(
  assetId: string,
  health: FleetInventoryAsset["health"] = "healthy",
) {
  return {
    assetId,
    targetFingerprint: "a".repeat(64),
    platform: "linux" as const,
    architecture: "x86_64" as const,
    osRelease: "KernAid fixture 1",
    health,
    findingCounts: {
      critical: health === "required_action" ? 1 : 0,
      warning: health === "attention" ? 1 : 0,
      info: 2,
    },
    snapshotSha256: "b".repeat(64),
  };
}

function signedInventory(
  harness: Harness,
  tenant: TenantCredentials,
  device: DeviceCredentials,
  sequence: number,
  inventoryAsset: FleetInventoryAsset,
): InventoryEnvelope {
  const unsigned: InventoryEnvelopeUnsigned = {
    schema: FLEET_INVENTORY_SCHEMA,
    tenantId: tenant.tenantId,
    deviceId: device.deviceId,
    sequence,
    observedAt: new Date(harness.now.value).toISOString(),
    asset: inventoryAsset,
  };
  return {
    ...unsigned,
    signature: sign(
      null,
      inventorySigningBytes(unsigned),
      device.privateKey,
    ).toString("base64url"),
  };
}

function signedAudit(
  harness: Harness,
  tenant: TenantCredentials,
  device: DeviceCredentials,
  input: {
    sessionId: string;
    eventId: string;
    sequence: number;
    previousEventSha256: string | null;
    kind?: AuditEnvelopeUnsigned["kind"];
    outcome?: AuditEnvelopeUnsigned["outcome"];
    risk?: AuditEnvelopeUnsigned["risk"];
    actionId?: string | null;
  },
): AuditEnvelope {
  const unsigned: AuditEnvelopeUnsigned = {
    schema: FLEET_AUDIT_SCHEMA,
    tenantId: tenant.tenantId,
    deviceId: device.deviceId,
    sessionId: input.sessionId,
    eventId: input.eventId,
    sequence: input.sequence,
    previousEventSha256: input.previousEventSha256,
    occurredAt: new Date(harness.now.value).toISOString(),
    kind: input.kind ?? "diagnostic_started",
    outcome: input.outcome ?? "started",
    risk: input.risk ?? "R0",
    actionId: input.actionId ?? null,
    targetSha256: createHash("sha256").update("target").digest("hex"),
    reportSha256: null,
    evidenceSha256: [],
  };
  return {
    ...unsigned,
    signature: sign(
      null,
      auditSigningBytes(unsigned),
      device.privateKey,
    ).toString("base64url"),
  };
}

function auditEventSha256(envelope: AuditEnvelope): string {
  return createHash("sha256").update(canonicalJson(envelope)).digest("hex");
}

function makePolicySigner(): PolicySigner {
  const { privateKey, publicKey } = generateKeyPairSync("ed25519");
  return {
    privateKey,
    publicKeySpki: Buffer.from(
      publicKey.export({ format: "der", type: "spki" }),
    ).toString("base64url"),
  };
}

async function setPolicyAnchor(
  harness: Harness,
  tenant: TenantCredentials,
  signer: PolicySigner,
): Promise<HttpResult> {
  return api(
    harness,
    "POST",
    `/v1/tenants/${tenant.tenantId}/policy-trust-anchor`,
    { publicKeySpki: signer.publicKeySpki },
    tenant.adminToken,
  );
}

function signedPolicy(
  tenant: TenantCredentials,
  signer: PolicySigner,
  input: {
    policyId: string;
    revision: number;
    assignments: PolicyAssignments;
    retentionDays?: number;
  },
): SignedPolicyBundle {
  const nowSeconds = Math.floor(INITIAL_TIME / 1000);
  const unsigned: SignedPolicyBundleUnsigned = {
    schema: FLEET_POLICY_BUNDLE_SCHEMA,
    tenantId: tenant.tenantId,
    policyId: input.policyId,
    revision: input.revision,
    issuedAtUnix: nowSeconds,
    notBeforeUnix: nowSeconds,
    offlineAllowedUntilUnix: nowSeconds + 86_400,
    expiresAtUnix: nowSeconds + 172_800,
    assignments: input.assignments,
    rules: {
      maxRisk: "R2",
      localApprovalFrom: "R1",
      allowedActionIds: [
        "linux.fstab.disable-missing-uuid.v1",
        "system.observe.noop",
      ],
      deniedActionIds: ["windows.registry.unsafe.v1"],
      allowEvidenceUpload: true,
      retentionDays: input.retentionDays ?? 90,
      providerModes: ["enterprise", "offline", "openai_api"],
      updateRing: "stable",
      emergencyRollbackAlwaysAllowed: true,
    },
  };
  return {
    ...unsigned,
    signature: sign(
      null,
      policyBundleSigningBytes(unsigned),
      signer.privateKey,
    ).toString("base64url"),
  };
}

function signedPolicyPull(
  harness: Harness,
  tenant: TenantCredentials,
  device: DeviceCredentials,
  nonce = randomBytes(32),
): PolicyPullRequest {
  const unsigned: PolicyPullRequestUnsigned = {
    schema: FLEET_POLICY_PULL_SCHEMA,
    tenantId: tenant.tenantId,
    deviceId: device.deviceId,
    issuedAt: new Date(harness.now.value).toISOString(),
    nonce: nonce.toString("base64url"),
  };
  return {
    ...unsigned,
    signature: sign(
      null,
      policyPullSigningBytes(unsigned),
      device.privateKey,
    ).toString("base64url"),
  };
}

async function publishPolicy(
  harness: Harness,
  tenant: TenantCredentials,
  bundle: SignedPolicyBundle,
): Promise<HttpResult> {
  return canonicalApi(
    harness,
    "POST",
    `/v1/tenants/${tenant.tenantId}/policies`,
    bundle,
    tenant.adminToken,
  );
}

test("root and tenant administration are strictly isolated", async () => {
  const harness = await createHarness();
  try {
    assert.equal((await api(harness, "GET", "/healthz")).status, 200);
    assert.equal(
      (await api(harness, "POST", "/v1/tenants", {}, "x".repeat(40))).status,
      401,
    );
    const first = await createTenant(harness);
    const second = await createTenant(harness);

    assert.equal(
      (
        await api(
          harness,
          "GET",
          `/v1/tenants/${second.tenantId}/devices`,
          undefined,
          first.adminToken,
        )
      ).status,
      401,
    );
    assert.equal(
      (
        await api(
          harness,
          "POST",
          `/v1/tenants/${second.tenantId}/enrollment-tokens`,
          { expiresInSeconds: 30 },
          first.adminToken,
        )
      ).status,
      401,
    );
  } finally {
    await destroyHarness(harness);
  }
});

test("enrollment tokens expire, are single use, and bad signatures do not consume them", async () => {
  const harness = await createHarness();
  try {
    const tenant = await createTenant(harness);
    const expiredToken = await createEnrollmentToken(harness, tenant, 1);
    harness.now.value += 2_000;
    const expiredDevice = makeDevice("expired-device");
    assert.equal(
      (
        await api(
          harness,
          "POST",
          "/v1/enrollments",
          signedEnrollment(harness, tenant, expiredToken, expiredDevice),
        )
      ).status,
      401,
    );

    const token = await createEnrollmentToken(harness, tenant);
    const device = makeDevice("signed-device");
    const valid = signedEnrollment(harness, tenant, token, device);
    const mismatched: EnrollmentRequest = {
      ...valid,
      deviceId: `KA-${"0".repeat(24)}`,
      signature: "",
    };
    mismatched.signature = sign(
      null,
      enrollmentSigningBytes(mismatched),
      device.privateKey,
    ).toString("base64url");
    assert.equal(
      (await api(harness, "POST", "/v1/enrollments", mismatched)).status,
      401,
    );
    const tampered = { ...valid, agentVersion: "tampered-after-signing" };
    assert.equal(
      (await api(harness, "POST", "/v1/enrollments", tampered)).status,
      401,
    );
    assert.equal(
      (await api(harness, "POST", "/v1/enrollments", valid)).status,
      201,
    );
    assert.equal(
      (await api(harness, "POST", "/v1/enrollments", valid)).status,
      401,
    );

    const raceToken = await createEnrollmentToken(harness, tenant);
    const raceFirst = makeDevice("race-first");
    const raceSecond = makeDevice("race-second");
    const raceResults = await Promise.all([
      api(
        harness,
        "POST",
        "/v1/enrollments",
        signedEnrollment(harness, tenant, raceToken, raceFirst),
      ),
      api(
        harness,
        "POST",
        "/v1/enrollments",
        signedEnrollment(harness, tenant, raceToken, raceSecond),
      ),
    ]);
    assert.deepEqual(
      raceResults.map((result) => result.status).sort(),
      [201, 401],
    );
  } finally {
    await destroyHarness(harness);
  }
});

test("inventory signatures reject tampering and sequence handling is idempotent", async () => {
  const harness = await createHarness();
  try {
    const tenant = await createTenant(harness);
    const device = await enroll(harness, tenant, "inventory-device");
    const first = signedInventory(harness, tenant, device, 1, asset("asset-a"));
    const tampered = {
      ...first,
      asset: { ...first.asset, health: "required_action" },
    };
    assert.equal(
      (await api(harness, "POST", "/v1/inventories", tampered)).status,
      401,
    );

    assert.equal(
      (await api(harness, "POST", "/v1/inventories", first)).status,
      201,
    );
    const replay = await api(harness, "POST", "/v1/inventories", first);
    assert.equal(replay.status, 200);
    assert.equal(replay.body.idempotent, true);

    const conflicting = signedInventory(
      harness,
      tenant,
      device,
      1,
      asset("asset-a", "attention"),
    );
    assert.equal(
      (await api(harness, "POST", "/v1/inventories", conflicting)).status,
      409,
    );
  } finally {
    await destroyHarness(harness);
  }
});

test("multiple assets are retained while superseded sequences are rejected", async () => {
  const harness = await createHarness();
  try {
    const tenant = await createTenant(harness);
    const device = await enroll(harness, tenant, "multi-asset-device");
    const first = signedInventory(harness, tenant, device, 1, asset("asset-a"));
    const second = signedInventory(
      harness,
      tenant,
      device,
      2,
      asset("asset-b", "attention"),
    );
    assert.equal(
      (await api(harness, "POST", "/v1/inventories", first)).status,
      201,
    );
    assert.equal(
      (await api(harness, "POST", "/v1/inventories", second)).status,
      201,
    );
    assert.equal(
      (await api(harness, "POST", "/v1/inventories", first)).status,
      409,
    );

    const listed = await api(
      harness,
      "GET",
      `/v1/tenants/${tenant.tenantId}/assets`,
      undefined,
      tenant.adminToken,
    );
    assert.equal(listed.status, 200);
    const items = listed.body.items as Array<Record<string, unknown>>;
    assert.deepEqual(
      items.map((item) => item.assetId),
      ["asset-a", "asset-b"],
    );
  } finally {
    await destroyHarness(harness);
  }
});

test("an older observation from another device cannot replace the current asset", async () => {
  const harness = await createHarness();
  try {
    const tenant = await createTenant(harness);
    const olderDevice = await enroll(harness, tenant, "older-device");
    const newerDevice = await enroll(harness, tenant, "newer-device");
    harness.now.value = INITIAL_TIME - 60_000;
    const older = signedInventory(
      harness,
      tenant,
      olderDevice,
      1,
      asset("shared-asset", "healthy"),
    );
    harness.now.value = INITIAL_TIME;
    const newer = signedInventory(
      harness,
      tenant,
      newerDevice,
      1,
      asset("shared-asset", "required_action"),
    );

    assert.equal(
      (await api(harness, "POST", "/v1/inventories", newer)).status,
      201,
    );
    assert.equal(
      (await api(harness, "POST", "/v1/inventories", older)).status,
      201,
    );
    const listed = await api(
      harness,
      "GET",
      `/v1/tenants/${tenant.tenantId}/assets`,
      undefined,
      tenant.adminToken,
    );
    const items = listed.body.items as Array<Record<string, unknown>>;
    assert.equal(items.length, 1);
    assert.equal(items[0]?.health, "required_action");
    assert.equal(items[0]?.deviceId, newerDevice.deviceId);
    assert.equal(items[0]?.observedAt, newer.observedAt);
  } finally {
    await destroyHarness(harness);
  }
});

test("device revocation is tenant-bound and immediately blocks inventory", async () => {
  const harness = await createHarness();
  try {
    const tenant = await createTenant(harness);
    const other = await createTenant(harness);
    const device = await enroll(harness, tenant, "revoked-device");
    assert.equal(
      (
        await api(
          harness,
          "POST",
          `/v1/tenants/${tenant.tenantId}/devices/${device.deviceId}/revoke`,
          {},
          other.adminToken,
        )
      ).status,
      401,
    );
    assert.equal(
      (
        await api(
          harness,
          "POST",
          `/v1/tenants/${tenant.tenantId}/devices/${device.deviceId}/revoke`,
          {},
          tenant.adminToken,
        )
      ).status,
      200,
    );
    const inventory = signedInventory(
      harness,
      tenant,
      device,
      1,
      asset("asset-a"),
    );
    assert.equal(
      (await api(harness, "POST", "/v1/inventories", inventory)).status,
      403,
    );
  } finally {
    await destroyHarness(harness);
  }
});

test("unknown and raw diagnostic fields are rejected and secrets are hash-only", async () => {
  const harness = await createHarness();
  let tenant: TenantCredentials | undefined;
  let token: string | undefined;
  try {
    tenant = await createTenant(harness);
    token = await createEnrollmentToken(harness, tenant);
    const device = makeDevice("privacy-device");
    const enrollment = signedEnrollment(harness, tenant, token, device);
    assert.equal(
      (
        await api(harness, "POST", "/v1/enrollments", {
          ...enrollment,
          operatorNotes: "not admitted",
        })
      ).status,
      400,
    );
    assert.equal(
      (await api(harness, "POST", "/v1/enrollments", enrollment)).status,
      201,
    );
    const inventory = signedInventory(
      harness,
      tenant,
      device,
      1,
      asset("asset-a"),
    );
    assert.equal(
      (
        await api(harness, "POST", "/v1/inventories", {
          ...inventory,
          rawDiagnostics: "PRIVATE_CANARY",
        })
      ).status,
      400,
    );
    assert.equal(
      (
        await api(harness, "POST", "/v1/inventories", {
          ...inventory,
          asset: { ...inventory.asset, serialNumber: "PRIVATE_CANARY" },
        })
      ).status,
      400,
    );
    assert.equal(
      (await api(harness, "POST", "/v1/inventories", inventory)).status,
      201,
    );
  } finally {
    await harness.service.close();
  }

  try {
    assert.ok(tenant !== undefined && token !== undefined);
    const database = new DatabaseSync(harness.databasePath, { readOnly: true });
    const rows = database
      .prepare(
        `SELECT admin_token_hash AS value FROM tenants
         UNION ALL SELECT token_hash AS value FROM enrollment_tokens`,
      )
      .all() as unknown as Array<{ value: string }>;
    assert.equal(
      rows.some((row) => row.value === tenant?.adminToken),
      false,
    );
    assert.equal(
      rows.some((row) => row.value === token),
      false,
    );
    const canary = database
      .prepare(
        "SELECT COUNT(*) AS count FROM inventory_events WHERE instr(envelope_json, 'PRIVATE_CANARY') > 0",
      )
      .get() as { count: number };
    assert.equal(canary.count, 0);
    database.close();
  } finally {
    rmSync(harness.directory, { recursive: true, force: true });
  }
});

test("tenant, device, and asset state survives a service restart", async () => {
  let harness = await createHarness();
  const directory = harness.directory;
  const now = harness.now;
  try {
    const tenant = await createTenant(harness);
    const device = await enroll(harness, tenant, "persistent-device");
    const inventory = signedInventory(
      harness,
      tenant,
      device,
      1,
      asset("persistent-asset"),
    );
    assert.equal(
      (await api(harness, "POST", "/v1/inventories", inventory)).status,
      201,
    );
    await destroyHarness(harness, false);

    harness = await createHarness({ directory, now });
    const devices = await api(
      harness,
      "GET",
      `/v1/tenants/${tenant.tenantId}/devices`,
      undefined,
      tenant.adminToken,
    );
    const assets = await api(
      harness,
      "GET",
      `/v1/tenants/${tenant.tenantId}/assets`,
      undefined,
      tenant.adminToken,
    );
    assert.equal(devices.status, 200);
    assert.equal((devices.body.items as unknown[]).length, 1);
    assert.equal(assets.status, 200);
    assert.equal((assets.body.items as unknown[]).length, 1);
  } finally {
    await destroyHarness(harness);
  }
});

test("optional console files are served same-origin with a restrictive CSP", async () => {
  const directory = mkdtempSync(join(tmpdir(), "kernaid-fleet-console-test-"));
  const consoleDirectory = join(directory, "console");
  mkdirSync(consoleDirectory, { mode: 0o700 });
  writeFileSync(
    join(consoleDirectory, "index.html"),
    "<!doctype html><title>Fleet</title>",
  );
  const harness = await createHarness({ directory, consoleDirectory });
  try {
    const response = await fetch(`${harness.baseUrl}/console/`);
    assert.equal(response.status, 200);
    assert.match(
      response.headers.get("content-security-policy") ?? "",
      /default-src 'self'/,
    );
    assert.match(await response.text(), /<title>Fleet<\/title>/);
  } finally {
    await destroyHarness(harness);
  }
});

test("signed audit events ingest once and expose only minimized tenant data", async () => {
  const harness = await createHarness();
  try {
    const tenant = await createTenant(harness);
    const device = await enroll(harness, tenant, "audit-device");
    const event = signedAudit(harness, tenant, device, {
      sessionId: "session-one",
      eventId: "event-one",
      sequence: 1,
      previousEventSha256: null,
    });

    const accepted = await canonicalApi(
      harness,
      "POST",
      "/v1/audit-events",
      event,
    );
    assert.equal(accepted.status, 201);
    assert.equal(accepted.body.idempotent, false);
    const replay = await canonicalApi(
      harness,
      "POST",
      "/v1/audit-events",
      event,
    );
    assert.equal(replay.status, 200);
    assert.equal(replay.body.idempotent, true);

    const listed = await api(
      harness,
      "GET",
      `/v1/tenants/${tenant.tenantId}/audit-events`,
      undefined,
      tenant.adminToken,
    );
    assert.equal(listed.status, 200);
    const items = listed.body.items as Array<Record<string, unknown>>;
    assert.equal(items.length, 1);
    assert.equal(items[0]?.eventSha256, auditEventSha256(event));
    assert.equal("signature" in (items[0] ?? {}), false);
    assert.equal("envelope" in (items[0] ?? {}), false);
    assert.equal("envelopeJson" in (items[0] ?? {}), false);
  } finally {
    await destroyHarness(harness);
  }
});

test("audit sessions reject gaps and forks while accepting the contiguous chain", async () => {
  const harness = await createHarness();
  try {
    const tenant = await createTenant(harness);
    const device = await enroll(harness, tenant, "chain-device");
    const first = signedAudit(harness, tenant, device, {
      sessionId: "chain-session",
      eventId: "chain-one",
      sequence: 1,
      previousEventSha256: null,
    });
    assert.equal(
      (await canonicalApi(harness, "POST", "/v1/audit-events", first)).status,
      201,
    );

    const gap = signedAudit(harness, tenant, device, {
      sessionId: "chain-session",
      eventId: "chain-three",
      sequence: 3,
      previousEventSha256: auditEventSha256(first),
    });
    const gapResult = await canonicalApi(
      harness,
      "POST",
      "/v1/audit-events",
      gap,
    );
    assert.equal(gapResult.status, 409);
    assert.equal(gapResult.body.error, "sequence_gap");

    const fork = signedAudit(harness, tenant, device, {
      sessionId: "chain-session",
      eventId: "chain-one-fork",
      sequence: 1,
      previousEventSha256: null,
    });
    const forkResult = await canonicalApi(
      harness,
      "POST",
      "/v1/audit-events",
      fork,
    );
    assert.equal(forkResult.status, 409);
    assert.equal(forkResult.body.error, "chain_fork");

    const second = signedAudit(harness, tenant, device, {
      sessionId: "chain-session",
      eventId: "chain-two",
      sequence: 2,
      previousEventSha256: auditEventSha256(first),
      kind: "diagnostic_completed",
      outcome: "succeeded",
    });
    assert.equal(
      (await canonicalApi(harness, "POST", "/v1/audit-events", second)).status,
      201,
    );
    const oldExactReplay = await canonicalApi(
      harness,
      "POST",
      "/v1/audit-events",
      first,
    );
    assert.equal(oldExactReplay.status, 200);
    assert.equal(oldExactReplay.body.idempotent, true);
  } finally {
    await destroyHarness(harness);
  }
});

test("audit ingestion fails closed for tampering, cross-tenant use, and revocation", async () => {
  const harness = await createHarness();
  try {
    const tenant = await createTenant(harness);
    const otherTenant = await createTenant(harness);
    const device = await enroll(harness, tenant, "isolated-audit-device");
    const valid = signedAudit(harness, tenant, device, {
      sessionId: "isolation-session",
      eventId: "isolation-one",
      sequence: 1,
      previousEventSha256: null,
    });
    const tampered = { ...valid, eventId: "tampered-event" };
    assert.equal(
      (await canonicalApi(harness, "POST", "/v1/audit-events", tampered))
        .status,
      401,
    );

    const crossTenant = signedAudit(harness, otherTenant, device, {
      sessionId: "cross-session",
      eventId: "cross-one",
      sequence: 1,
      previousEventSha256: null,
    });
    assert.equal(
      (await canonicalApi(harness, "POST", "/v1/audit-events", crossTenant))
        .status,
      401,
    );

    assert.equal(
      (
        await api(
          harness,
          "POST",
          `/v1/tenants/${tenant.tenantId}/devices/${device.deviceId}/revoke`,
          {},
          tenant.adminToken,
        )
      ).status,
      200,
    );
    assert.equal(
      (await canonicalApi(harness, "POST", "/v1/audit-events", valid)).status,
      403,
    );
    assert.equal(
      (
        await api(
          harness,
          "GET",
          `/v1/tenants/${tenant.tenantId}/audit-events`,
          undefined,
          otherTenant.adminToken,
        )
      ).status,
      401,
    );
  } finally {
    await destroyHarness(harness);
  }
});

test("audit chain state and events survive a SQLite restart", async () => {
  let harness = await createHarness();
  const directory = harness.directory;
  const now = harness.now;
  try {
    const tenant = await createTenant(harness);
    const device = await enroll(harness, tenant, "restart-audit-device");
    const first = signedAudit(harness, tenant, device, {
      sessionId: "restart-session",
      eventId: "restart-one",
      sequence: 1,
      previousEventSha256: null,
    });
    assert.equal(
      (await canonicalApi(harness, "POST", "/v1/audit-events", first)).status,
      201,
    );
    await destroyHarness(harness, false);

    harness = await createHarness({ directory, now });
    const second = signedAudit(harness, tenant, device, {
      sessionId: "restart-session",
      eventId: "restart-two",
      sequence: 2,
      previousEventSha256: auditEventSha256(first),
      kind: "diagnostic_completed",
      outcome: "succeeded",
    });
    assert.equal(
      (await canonicalApi(harness, "POST", "/v1/audit-events", second)).status,
      201,
    );
    const listed = await api(
      harness,
      "GET",
      `/v1/tenants/${tenant.tenantId}/audit-events`,
      undefined,
      tenant.adminToken,
    );
    assert.equal((listed.body.items as unknown[]).length, 2);
  } finally {
    await destroyHarness(harness);
  }
});

test("audit input rejects non-canonical or privacy-expanding content", async () => {
  const harness = await createHarness();
  try {
    const tenant = await createTenant(harness);
    const device = await enroll(harness, tenant, "privacy-audit-device");
    const event = signedAudit(harness, tenant, device, {
      sessionId: "privacy-session",
      eventId: "privacy-one",
      sequence: 1,
      previousEventSha256: null,
    });
    assert.equal(
      (await api(harness, "POST", "/v1/audit-events", event)).status,
      400,
    );
    assert.equal(
      (
        await canonicalApi(harness, "POST", "/v1/audit-events", {
          ...event,
          rawLog: "PRIVATE_CANARY",
        })
      ).status,
      400,
    );
    assert.equal(
      (await canonicalApi(harness, "POST", "/v1/audit-events", event)).status,
      201,
    );

    const database = new DatabaseSync(harness.databasePath, { readOnly: true });
    const canary = database
      .prepare(
        "SELECT COUNT(*) AS count FROM audit_events WHERE instr(envelope_json, 'PRIVATE_CANARY') > 0",
      )
      .get() as { count: number };
    assert.equal(canary.count, 0);
    database.close();
  } finally {
    await destroyHarness(harness);
  }
});

test("policy anchor and signed publication are one-way, monotonic, and tenant-bound", async () => {
  const harness = await createHarness();
  try {
    const tenant = await createTenant(harness);
    const other = await createTenant(harness);
    const signer = makePolicySigner();
    const otherSigner = makePolicySigner();

    assert.equal((await setPolicyAnchor(harness, tenant, signer)).status, 201);
    assert.equal((await setPolicyAnchor(harness, tenant, signer)).status, 409);
    assert.equal(
      (await setPolicyAnchor(harness, other, otherSigner)).status,
      201,
    );

    const second = signedPolicy(tenant, signer, {
      policyId: "repair-baseline",
      revision: 2,
      assignments: { all: true },
    });
    const published = await publishPolicy(harness, tenant, second);
    assert.equal(published.status, 201);
    assert.equal(published.body.idempotent, false);
    const replay = await publishPolicy(harness, tenant, second);
    assert.equal(replay.status, 200);
    assert.equal(replay.body.idempotent, true);

    const rollback = signedPolicy(tenant, signer, {
      policyId: "repair-baseline",
      revision: 1,
      assignments: { all: true },
    });
    const rollbackResult = await publishPolicy(harness, tenant, rollback);
    assert.equal(rollbackResult.status, 409);
    assert.equal(rollbackResult.body.error, "policy_revision_rollback");

    const conflict = signedPolicy(tenant, signer, {
      policyId: "repair-baseline",
      revision: 2,
      assignments: { all: true },
      retentionDays: 30,
    });
    const conflictResult = await publishPolicy(harness, tenant, conflict);
    assert.equal(conflictResult.status, 409);
    assert.equal(conflictResult.body.error, "policy_revision_conflict");

    const third = signedPolicy(tenant, signer, {
      policyId: "repair-baseline",
      revision: 3,
      assignments: { all: true },
    });
    const tampered = {
      ...third,
      rules: { ...third.rules, retentionDays: 7 },
    };
    assert.equal((await publishPolicy(harness, tenant, tampered)).status, 401);

    assert.equal(
      (
        await canonicalApi(
          harness,
          "POST",
          `/v1/tenants/${other.tenantId}/policies`,
          second,
          other.adminToken,
        )
      ).status,
      403,
    );
    assert.equal(
      (
        await canonicalApi(
          harness,
          "POST",
          `/v1/tenants/${tenant.tenantId}/policies`,
          { ...third, repairCommand: "forbidden" },
          tenant.adminToken,
        )
      ).status,
      400,
    );
  } finally {
    await destroyHarness(harness);
  }
});

test("signed policy pulls return only assignments for the enrolled active device", async () => {
  const harness = await createHarness();
  try {
    const tenant = await createTenant(harness);
    const otherTenant = await createTenant(harness);
    const signer = makePolicySigner();
    assert.equal((await setPolicyAnchor(harness, tenant, signer)).status, 201);
    const first = await enroll(harness, tenant, "policy-device-one");
    const second = await enroll(harness, tenant, "policy-device-two");

    const bundles = [
      signedPolicy(tenant, signer, {
        policyId: "all-devices",
        revision: 1,
        assignments: { all: true },
      }),
      signedPolicy(tenant, signer, {
        policyId: "first-only",
        revision: 1,
        assignments: { deviceIds: [first.deviceId] },
      }),
      signedPolicy(tenant, signer, {
        policyId: "second-only",
        revision: 1,
        assignments: { deviceIds: [second.deviceId] },
      }),
    ];
    for (const bundle of bundles) {
      assert.equal((await publishPolicy(harness, tenant, bundle)).status, 201);
    }

    const firstPull = signedPolicyPull(harness, tenant, first);
    const firstResult = await api(
      harness,
      "POST",
      "/v1/policy-pulls",
      firstPull,
    );
    assert.equal(firstResult.status, 200);
    assert.deepEqual(
      (firstResult.body.items as SignedPolicyBundle[]).map(
        (bundle) => bundle.policyId,
      ),
      ["all-devices", "first-only"],
    );
    const replay = await api(harness, "POST", "/v1/policy-pulls", firstPull);
    assert.equal(replay.status, 409);
    assert.equal(replay.body.error, "policy_pull_replay");

    const secondResult = await api(
      harness,
      "POST",
      "/v1/policy-pulls",
      signedPolicyPull(harness, tenant, second),
    );
    assert.deepEqual(
      (secondResult.body.items as SignedPolicyBundle[]).map(
        (bundle) => bundle.policyId,
      ),
      ["all-devices", "second-only"],
    );

    const tampered = signedPolicyPull(harness, tenant, first);
    tampered.issuedAt = new Date(harness.now.value + 1_000).toISOString();
    assert.equal(
      (await api(harness, "POST", "/v1/policy-pulls", tampered)).status,
      401,
    );
    assert.equal(
      (
        await api(harness, "POST", "/v1/policy-pulls", {
          ...signedPolicyPull(harness, tenant, first),
          rawDiagnostics: "forbidden",
        })
      ).status,
      400,
    );

    const crossTenantUnsigned: PolicyPullRequestUnsigned = {
      ...signedPolicyPull(harness, tenant, first),
      tenantId: otherTenant.tenantId,
    };
    const crossTenant: PolicyPullRequest = {
      ...crossTenantUnsigned,
      signature: sign(
        null,
        policyPullSigningBytes(crossTenantUnsigned),
        first.privateKey,
      ).toString("base64url"),
    };
    assert.equal(
      (await api(harness, "POST", "/v1/policy-pulls", crossTenant)).status,
      401,
    );

    assert.equal(
      (
        await api(
          harness,
          "POST",
          `/v1/tenants/${tenant.tenantId}/devices/${first.deviceId}/revoke`,
          {},
          tenant.adminToken,
        )
      ).status,
      200,
    );
    assert.equal(
      (
        await api(
          harness,
          "POST",
          "/v1/policy-pulls",
          signedPolicyPull(harness, tenant, first),
        )
      ).status,
      403,
    );
  } finally {
    await destroyHarness(harness);
  }
});

test("policy anchor, bundle, and assignment survive SQLite restart", async () => {
  let harness = await createHarness();
  const directory = harness.directory;
  const now = harness.now;
  try {
    const tenant = await createTenant(harness);
    const signer = makePolicySigner();
    const device = await enroll(harness, tenant, "persistent-policy-device");
    await destroyHarness(harness, false);

    const legacy = new DatabaseSync(harness.databasePath);
    legacy.exec(`
      DROP TABLE policy_pull_nonces;
      DROP TABLE policy_assignments;
      DROP TABLE policy_bundles;
      DROP TABLE tenant_policy_anchors;
      PRAGMA user_version = 2;
    `);
    legacy.close();
    harness = await createHarness({ directory, now });

    assert.equal((await setPolicyAnchor(harness, tenant, signer)).status, 201);
    const bundle = signedPolicy(tenant, signer, {
      policyId: "persistent-policy",
      revision: 1,
      assignments: { deviceIds: [device.deviceId] },
    });
    assert.equal((await publishPolicy(harness, tenant, bundle)).status, 201);
    await destroyHarness(harness, false);

    harness = await createHarness({ directory, now });
    const pull = signedPolicyPull(harness, tenant, device);
    const result = await api(harness, "POST", "/v1/policy-pulls", pull);
    assert.equal(result.status, 200);
    const items = result.body.items as SignedPolicyBundle[];
    assert.equal(items.length, 1);
    assert.equal(items[0]?.policyId, "persistent-policy");
    assert.equal(items[0]?.revision, 1);

    const database = new DatabaseSync(harness.databasePath, { readOnly: true });
    const privateColumns = database
      .prepare(
        `SELECT COUNT(*) AS count FROM pragma_table_info('tenant_policy_anchors')
         WHERE lower(name) LIKE '%private%' OR lower(name) LIKE '%seed%'`,
      )
      .get() as { count: number };
    assert.equal(privateColumns.count, 0);
    const version = database.prepare("PRAGMA user_version").get() as {
      user_version: number;
    };
    assert.equal(version.user_version, 3);
    const nonce = database
      .prepare(
        `SELECT nonce_sha256 FROM policy_pull_nonces
         WHERE tenant_id = ? AND device_id = ?`,
      )
      .get(tenant.tenantId, device.deviceId) as { nonce_sha256: string };
    assert.match(nonce.nonce_sha256, /^[0-9a-f]{64}$/);
    assert.notEqual(nonce.nonce_sha256, pull.nonce);
    database.close();
  } finally {
    await destroyHarness(harness);
  }
});
