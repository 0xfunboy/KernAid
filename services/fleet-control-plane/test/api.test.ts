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
  FLEET_ENROLLMENT_SCHEMA,
  FLEET_INVENTORY_SCHEMA,
  enrollmentSigningBytes,
  inventorySigningBytes,
  type EnrollmentRequest,
  type EnrollmentRequestUnsigned,
  type FleetInventoryAsset,
  type InventoryEnvelope,
  type InventoryEnvelopeUnsigned,
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
