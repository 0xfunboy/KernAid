import assert from "node:assert/strict";
import {
  createHash,
  generateKeyPairSync,
  randomBytes,
  sign,
  verify,
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
  FLEET_ENTITLEMENT_PULL_SCHEMA,
  ENTITLEMENT_SCHEMA,
  ENTITLEMENT_REVOCATIONS_SCHEMA,
  FLEET_POLICY_BUNDLE_SCHEMA,
  FLEET_POLICY_PULL_SCHEMA,
  FLEET_UPDATE_PULL_SCHEMA,
  FLEET_WORK_ORDER_CLAIM_SCHEMA,
  FLEET_WORK_ORDER_RESULT_SCHEMA,
  UPDATE_MANIFEST_SCHEMA,
  auditSigningBytes,
  canonicalJson,
  enrollmentSigningBytes,
  entitlementPullSigningBytes,
  entitlementRevocationSigningBytes,
  entitlementSigningBytes,
  inventorySigningBytes,
  policyBundleSigningBytes,
  policyPullSigningBytes,
  updateManifestSigningBytes,
  updatePullSigningBytes,
  workOrderClaimSigningBytes,
  workOrderResultSigningBytes,
  type AuditEnvelope,
  type AuditEnvelopeUnsigned,
  type EnrollmentRequest,
  type EnrollmentRequestUnsigned,
  type FleetInventoryAsset,
  type EntitlementClaims,
  type EntitlementEnvelope,
  type EntitlementPullRequest,
  type EntitlementPullRequestUnsigned,
  type EntitlementRevocationClaims,
  type EntitlementRevocationEnvelope,
  type InventoryEnvelope,
  type InventoryEnvelopeUnsigned,
  type PolicyAssignments,
  type PolicyPullRequest,
  type PolicyPullRequestUnsigned,
  type SignedPolicyBundle,
  type SignedPolicyBundleUnsigned,
  type SignedUpdateManifest,
  type SignedUpdateManifestUnsigned,
  type UpdatePullRequest,
  type UpdatePullRequestUnsigned,
  type WorkOrderClaimRequest,
  type WorkOrderClaimRequestUnsigned,
  type WorkOrderResult,
  type WorkOrderResultUnsigned,
  parseServiceReceipt,
  serviceReceiptSigningBytes,
  type ServiceReceipt,
} from "@kernaid/fleet-schemas";
import { FleetControlPlane } from "../src/server.js";

const ROOT_TOKEN = "root_" + "r".repeat(40);
const INITIAL_TIME = Date.parse("2026-08-31T12:00:00.000Z");
const ENTITLEMENT_ISSUER = generateKeyPairSync("ed25519");
const ENTITLEMENT_TRUST_ANCHOR = Buffer.from(
  ENTITLEMENT_ISSUER.publicKey.export({ format: "der", type: "spki" }),
)
  .subarray(12)
  .toString("base64url");
const UPDATE_ISSUER = generateKeyPairSync("ed25519");
const UPDATE_TRUST_ANCHOR = Buffer.from(
  UPDATE_ISSUER.publicKey.export({ format: "der", type: "spki" }),
)
  .subarray(12)
  .toString("base64url");
const SERVICE_RECEIPT_ISSUER = generateKeyPairSync("ed25519");
const SERVICE_RECEIPT_TRUST_ANCHOR = Buffer.from(
  SERVICE_RECEIPT_ISSUER.publicKey.export({ format: "der", type: "spki" }),
)
  .subarray(12)
  .toString("base64url");

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

interface AccessCredential {
  credentialId: string;
  role: "admin" | "operator";
  accessToken: string;
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
  headers: Headers;
  rawBody: string;
}

async function createHarness(options?: {
  directory?: string;
  now?: { value: number };
  consoleDirectory?: string;
  entitlementTrustAnchor?: string;
  updateTrustAnchor?: string;
  serviceReceiptSigningKey?: KeyObject;
  serviceReceiptTrustAnchor?: string;
}): Promise<Harness> {
  const directory =
    options?.directory ?? mkdtempSync(join(tmpdir(), "kernaid-fleet-test-"));
  const databasePath = join(directory, "fleet.sqlite");
  const now = options?.now ?? { value: INITIAL_TIME };
  const service = new FleetControlPlane({
    databasePath,
    rootToken: ROOT_TOKEN,
    serviceReceiptSigningKey:
      options?.serviceReceiptSigningKey ?? SERVICE_RECEIPT_ISSUER.privateKey,
    serviceReceiptTrustAnchor:
      options?.serviceReceiptTrustAnchor ?? SERVICE_RECEIPT_TRUST_ANCHOR,
    entitlementTrustAnchor:
      options?.entitlementTrustAnchor ?? ENTITLEMENT_TRUST_ANCHOR,
    updateTrustAnchor: options?.updateTrustAnchor ?? UPDATE_TRUST_ANCHOR,
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
  const rawBody = await response.text();
  return {
    status: response.status,
    body: JSON.parse(rawBody) as Record<string, unknown>,
    headers: response.headers,
    rawBody,
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
  const rawBody = await response.text();
  return {
    status: response.status,
    body: JSON.parse(rawBody) as Record<string, unknown>,
    headers: response.headers,
    rawBody,
  };
}

function verifiedServiceReceipt(
  result: HttpResult,
  expected: {
    requestBody: string;
    tenantId: string;
    deviceId: string;
    operation: ServiceReceipt["operation"];
  },
): { receipt: ServiceReceipt; canonical: string } {
  const encoded = result.headers.get("x-kernaid-fleet-receipt");
  assert.notEqual(encoded, null, "successful device response needs a receipt");
  const canonical = Buffer.from(encoded ?? "", "base64url").toString("utf8");
  assert.equal(Buffer.from(canonical).toString("base64url"), encoded);
  const receipt = parseServiceReceipt(JSON.parse(canonical) as unknown);
  assert.equal(canonicalJson(receipt), canonical);
  assert.equal(receipt.tenantId, expected.tenantId);
  assert.equal(receipt.deviceId, expected.deviceId);
  assert.equal(receipt.operation, expected.operation);
  assert.equal(
    receipt.requestSha256,
    createHash("sha256").update(expected.requestBody).digest("hex"),
  );
  assert.equal(
    receipt.responseSha256,
    createHash("sha256").update(result.rawBody).digest("hex"),
  );
  assert.equal(
    verify(
      null,
      serviceReceiptSigningBytes(receipt),
      SERVICE_RECEIPT_ISSUER.publicKey,
      Buffer.from(receipt.signature, "base64url"),
    ),
    true,
  );
  return { receipt, canonical };
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

async function createAccessCredential(
  harness: Harness,
  tenant: TenantCredentials,
  role: AccessCredential["role"],
  label: string,
): Promise<AccessCredential> {
  const result = await api(
    harness,
    "POST",
    `/v1/tenants/${tenant.tenantId}/access-credentials`,
    { label, role },
    tenant.adminToken,
  );
  assert.equal(result.status, 201);
  assert.equal(typeof result.body.credentialId, "string");
  assert.equal(typeof result.body.accessToken, "string");
  assert.equal(result.body.role, role);
  return {
    credentialId: result.body.credentialId as string,
    role,
    accessToken: result.body.accessToken as string,
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
  platform: EnrollmentRequestUnsigned["platform"] = "linux",
): EnrollmentRequest {
  const unsigned: EnrollmentRequestUnsigned = {
    schema: FLEET_ENROLLMENT_SCHEMA,
    enrollmentToken,
    tenantId: tenant.tenantId,
    deviceId: device.deviceId,
    publicKeySpki: device.publicKeySpki,
    platform,
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
  platform: EnrollmentRequestUnsigned["platform"] = "linux",
): Promise<DeviceCredentials> {
  const token = await createEnrollmentToken(harness, tenant);
  const device = makeDevice(deviceId);
  const result = await api(
    harness,
    "POST",
    "/v1/enrollments",
    signedEnrollment(harness, tenant, token, device, platform),
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
    allowedActionIds?: string[];
    deniedActionIds?: string[];
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
      allowedActionIds: input.allowedActionIds ?? [
        "linux.fstab.disable-missing-uuid.v1",
        "system.observe.noop",
      ],
      deniedActionIds: input.deniedActionIds ?? ["windows.registry.unsafe.v1"],
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

function signedEntitlement(
  tenant: TenantCredentials,
  deviceIds: string[],
  input: {
    entitlementId: string;
    sequence: number;
    maxToolDevices?: number;
    graceUntilUnix?: number;
  },
): EntitlementEnvelope {
  const nowSeconds = Math.floor(INITIAL_TIME / 1000);
  const claims: EntitlementClaims = {
    schema: ENTITLEMENT_SCHEMA,
    entitlementId: input.entitlementId,
    tenantId: tenant.tenantId,
    sequence: input.sequence,
    plan: "enterprise",
    features: ["audit", "enterprise_repair", "fleet", "policy", "updates"],
    deviceIds: [...deviceIds].sort(),
    limits: {
      maxToolDevices: input.maxToolDevices ?? Math.max(deviceIds.length, 1),
      maxTechnicians: 10,
      maxManagedAssets: 1000,
    },
    issuedAtUnix: nowSeconds,
    notBeforeUnix: nowSeconds,
    offlineLeaseUntilUnix: nowSeconds + 86_400,
    expiresAtUnix: nowSeconds + 172_800,
    graceUntilUnix: input.graceUntilUnix ?? nowSeconds + 259_200,
  };
  return {
    claims,
    signature: sign(
      null,
      entitlementSigningBytes(claims),
      ENTITLEMENT_ISSUER.privateKey,
    ).toString("base64url"),
  };
}

function signedEntitlementRevocations(
  sequence: number,
  entitlementIds: string[],
): EntitlementRevocationEnvelope {
  const claims: EntitlementRevocationClaims = {
    schema: ENTITLEMENT_REVOCATIONS_SCHEMA,
    sequence,
    issuedAtUnix: Math.floor(INITIAL_TIME / 1000),
    revokedEntitlementIds: [...entitlementIds].sort(),
  };
  return {
    claims,
    signature: sign(
      null,
      entitlementRevocationSigningBytes(claims),
      ENTITLEMENT_ISSUER.privateKey,
    ).toString("base64url"),
  };
}

function signedEntitlementPull(
  harness: Harness,
  tenant: TenantCredentials,
  device: DeviceCredentials,
  nonce = randomBytes(32),
): EntitlementPullRequest {
  const unsigned: EntitlementPullRequestUnsigned = {
    schema: FLEET_ENTITLEMENT_PULL_SCHEMA,
    tenantId: tenant.tenantId,
    deviceId: device.deviceId,
    issuedAt: new Date(harness.now.value).toISOString(),
    nonce: nonce.toString("base64url"),
  };
  return {
    ...unsigned,
    signature: sign(
      null,
      entitlementPullSigningBytes(unsigned),
      device.privateKey,
    ).toString("base64url"),
  };
}

function signedWorkOrderClaim(
  harness: Harness,
  tenant: TenantCredentials,
  device: DeviceCredentials,
  nonce = randomBytes(32),
): WorkOrderClaimRequest {
  const unsigned: WorkOrderClaimRequestUnsigned = {
    schema: FLEET_WORK_ORDER_CLAIM_SCHEMA,
    tenantId: tenant.tenantId,
    deviceId: device.deviceId,
    issuedAt: new Date(harness.now.value).toISOString(),
    nonce: nonce.toString("base64url"),
    leaseSeconds: 300,
  };
  return {
    ...unsigned,
    signature: sign(
      null,
      workOrderClaimSigningBytes(unsigned),
      device.privateKey,
    ).toString("base64url"),
  };
}

function signedWorkOrderResult(
  harness: Harness,
  tenant: TenantCredentials,
  device: DeviceCredentials,
  workOrder: Record<string, unknown>,
  outcome: WorkOrderResultUnsigned["outcome"] = "succeeded",
): WorkOrderResult {
  const lease = workOrder.lease as Record<string, unknown>;
  const unsigned: WorkOrderResultUnsigned = {
    schema: FLEET_WORK_ORDER_RESULT_SCHEMA,
    tenantId: tenant.tenantId,
    deviceId: device.deviceId,
    workOrderId: workOrder.workOrderId as string,
    leaseId: lease.leaseId as string,
    actionId: workOrder.actionId as WorkOrderResultUnsigned["actionId"],
    actionVersion: workOrder.actionVersion as number,
    outcome,
    completedAt: new Date(harness.now.value).toISOString(),
    resultSha256: createHash("sha256")
      .update(`bounded-${outcome}`)
      .digest("hex"),
  };
  return {
    ...unsigned,
    signature: sign(
      null,
      workOrderResultSigningBytes(unsigned),
      device.privateKey,
    ).toString("base64url"),
  };
}

async function publishEntitlement(
  harness: Harness,
  tenant: TenantCredentials,
  envelope: EntitlementEnvelope,
): Promise<HttpResult> {
  return canonicalApi(
    harness,
    "POST",
    `/v1/tenants/${tenant.tenantId}/entitlements`,
    envelope,
    tenant.adminToken,
  );
}

async function publishEntitlementRevocations(
  harness: Harness,
  tenant: TenantCredentials,
  envelope: EntitlementRevocationEnvelope,
): Promise<HttpResult> {
  return canonicalApi(
    harness,
    "POST",
    `/v1/tenants/${tenant.tenantId}/entitlement-revocations`,
    envelope,
    tenant.adminToken,
  );
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

function signedUpdateManifest(input: {
  sequence: number;
  platform?: SignedUpdateManifestUnsigned["platform"];
  architecture?: SignedUpdateManifestUnsigned["architecture"];
  releaseRing?: SignedUpdateManifestUnsigned["releaseRing"];
  basisPoints?: number;
  emergencyRollback?: boolean;
  releaseVersion?: string;
}): SignedUpdateManifest {
  const nowSeconds = Math.floor(INITIAL_TIME / 1000);
  const unsigned: SignedUpdateManifestUnsigned = {
    schema: UPDATE_MANIFEST_SCHEMA,
    sequence: input.sequence,
    releaseId: `release-${input.sequence}`,
    releaseVersion: input.releaseVersion ?? `1.0.${input.sequence}`,
    platform: input.platform ?? "linux",
    architecture: input.architecture ?? "x86_64",
    releaseRing: input.releaseRing ?? "stable",
    rollout: {
      basisPoints: input.basisPoints ?? 10_000,
      seed: `release-${input.sequence}-cohort`,
    },
    issuedAtUnix: nowSeconds,
    notBeforeUnix: nowSeconds,
    expiresAtUnix: nowSeconds + 86_400,
    artifact: {
      url: `https://updates.kernaid.example/release-${input.sequence}.img`,
      sizeBytes: 4096,
      sha256: input.sequence.toString(16).padStart(64, "0"),
    },
    emergencyRollback: input.emergencyRollback ?? false,
  };
  return {
    ...unsigned,
    signature: sign(
      null,
      updateManifestSigningBytes(unsigned),
      UPDATE_ISSUER.privateKey,
    ).toString("base64url"),
  };
}

function signedUpdatePull(
  harness: Harness,
  tenant: TenantCredentials,
  device: DeviceCredentials,
  input?: {
    platform?: UpdatePullRequestUnsigned["platform"];
    architecture?: UpdatePullRequestUnsigned["architecture"];
    updateRing?: UpdatePullRequestUnsigned["updateRing"];
    nonce?: Buffer;
  },
): UpdatePullRequest {
  const unsigned: UpdatePullRequestUnsigned = {
    schema: FLEET_UPDATE_PULL_SCHEMA,
    tenantId: tenant.tenantId,
    deviceId: device.deviceId,
    platform: input?.platform ?? "linux",
    architecture: input?.architecture ?? "x86_64",
    updateRing: input?.updateRing ?? "stable",
    issuedAt: new Date(harness.now.value).toISOString(),
    nonce: (input?.nonce ?? randomBytes(32)).toString("base64url"),
  };
  return {
    ...unsigned,
    signature: sign(
      null,
      updatePullSigningBytes(unsigned),
      device.privateKey,
    ).toString("base64url"),
  };
}

async function publishUpdateManifest(
  harness: Harness,
  tenant: TenantCredentials,
  manifest: SignedUpdateManifest,
): Promise<HttpResult> {
  return canonicalApi(
    harness,
    "POST",
    `/v1/tenants/${tenant.tenantId}/update-manifests`,
    manifest,
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

test("tenant admin and operator roles enforce least privilege with access audit", async () => {
  const harness = await createHarness();
  try {
    const tenant = await createTenant(harness);
    const other = await createTenant(harness);
    const initial = await api(
      harness,
      "GET",
      `/v1/tenants/${tenant.tenantId}/access-credentials`,
      undefined,
      tenant.adminToken,
    );
    assert.equal(initial.status, 200);
    assert.deepEqual(
      (initial.body.items as Array<Record<string, unknown>>).map((item) => [
        item.credentialId,
        item.role,
        item.status,
      ]),
      [["bootstrap-admin", "admin", "active"]],
    );
    assert.equal(
      JSON.stringify(initial.body).includes(tenant.adminToken),
      false,
    );
    assert.equal(
      (
        await api(
          harness,
          "POST",
          `/v1/tenants/${tenant.tenantId}/access-credentials`,
          { label: "Unbounded role", role: "owner" },
          tenant.adminToken,
        )
      ).status,
      400,
    );
    assert.equal(
      (
        await api(
          harness,
          "POST",
          `/v1/tenants/${tenant.tenantId}/access-credentials`,
          { label: "Unknown field", permissions: ["*"], role: "operator" },
          tenant.adminToken,
        )
      ).status,
      400,
    );

    const operator = await createAccessCredential(
      harness,
      tenant,
      "operator",
      "Field operations",
    );
    const database = new DatabaseSync(harness.databasePath, { readOnly: true });
    const storedCredential = database
      .prepare(
        `SELECT token_hash FROM tenant_access_credentials
         WHERE tenant_id = ? AND credential_id = ?`,
      )
      .get(tenant.tenantId, operator.credentialId) as { token_hash: string };
    assert.match(storedCredential.token_hash, /^[0-9a-f]{64}$/);
    assert.notEqual(storedCredential.token_hash, operator.accessToken);
    database.close();
    assert.equal(
      (
        await api(
          harness,
          "GET",
          `/v1/tenants/${tenant.tenantId}/devices`,
          undefined,
          operator.accessToken,
        )
      ).status,
      200,
    );
    assert.equal(
      (
        await api(
          harness,
          "POST",
          `/v1/tenants/${tenant.tenantId}/enrollment-tokens`,
          { expiresInSeconds: 60 },
          operator.accessToken,
        )
      ).status,
      201,
    );
    assert.equal(
      (
        await api(
          harness,
          "GET",
          `/v1/tenants/${tenant.tenantId}/policies`,
          undefined,
          operator.accessToken,
        )
      ).status,
      200,
    );
    assert.equal(
      (
        await api(
          harness,
          "POST",
          `/v1/tenants/${tenant.tenantId}/policy-trust-anchor`,
          { publicKeySpki: "not-reached" },
          operator.accessToken,
        )
      ).status,
      403,
    );
    assert.equal(
      (
        await api(
          harness,
          "GET",
          `/v1/tenants/${tenant.tenantId}/access-credentials`,
          undefined,
          operator.accessToken,
        )
      ).status,
      403,
    );
    assert.equal(
      (
        await api(
          harness,
          "GET",
          `/v1/tenants/${other.tenantId}/devices`,
          undefined,
          operator.accessToken,
        )
      ).status,
      401,
    );

    const audit = await api(
      harness,
      "GET",
      `/v1/tenants/${tenant.tenantId}/access-audit`,
      undefined,
      tenant.adminToken,
    );
    assert.equal(audit.status, 200);
    const events = audit.body.items as Array<Record<string, unknown>>;
    assert.equal(
      events.some(
        (event) =>
          event.credentialId === operator.credentialId &&
          event.action === "device.list" &&
          event.outcome === "allowed" &&
          event.targetTenantId === tenant.tenantId,
      ),
      true,
    );
    assert.equal(
      events.some(
        (event) =>
          event.credentialId === operator.credentialId &&
          event.action === "policy_trust_anchor.set" &&
          event.outcome === "denied",
      ),
      true,
    );
    assert.equal(
      events.some(
        (event) =>
          event.credentialId === operator.credentialId &&
          event.action === "device.list" &&
          event.outcome === "denied" &&
          event.targetTenantId === other.tenantId,
      ),
      true,
    );
    assert.equal(JSON.stringify(events).includes(operator.accessToken), false);

    const revoked = await api(
      harness,
      "POST",
      `/v1/tenants/${tenant.tenantId}/access-credentials/${operator.credentialId}/revoke`,
      {},
      tenant.adminToken,
    );
    assert.equal(revoked.status, 200);
    assert.equal(revoked.body.idempotent, false);
    const replay = await api(
      harness,
      "POST",
      `/v1/tenants/${tenant.tenantId}/access-credentials/${operator.credentialId}/revoke`,
      {},
      tenant.adminToken,
    );
    assert.equal(replay.status, 200);
    assert.equal(replay.body.idempotent, true);
    assert.equal(
      (
        await api(
          harness,
          "GET",
          `/v1/tenants/${tenant.tenantId}/devices`,
          undefined,
          operator.accessToken,
        )
      ).status,
      401,
    );
    const afterRevocationAudit = await api(
      harness,
      "GET",
      `/v1/tenants/${tenant.tenantId}/access-audit`,
      undefined,
      tenant.adminToken,
    );
    assert.equal(afterRevocationAudit.status, 200);
    assert.equal(
      (afterRevocationAudit.body.items as Array<Record<string, unknown>>).some(
        (event) =>
          event.credentialId === operator.credentialId &&
          event.action === "device.list" &&
          event.outcome === "denied" &&
          event.targetTenantId === tenant.tenantId,
      ),
      true,
    );
    assert.equal(
      (
        await api(
          harness,
          "POST",
          `/v1/tenants/${tenant.tenantId}/access-credentials/bootstrap-admin/revoke`,
          {},
          tenant.adminToken,
        )
      ).status,
      409,
    );
  } finally {
    await destroyHarness(harness);
  }
});

test("tenant credentials and authorization audit survive restart", async () => {
  let harness = await createHarness();
  const directory = harness.directory;
  const now = harness.now;
  try {
    const tenant = await createTenant(harness);
    const administrator = await createAccessCredential(
      harness,
      tenant,
      "admin",
      "Security administrator",
    );
    await destroyHarness(harness, false);
    harness = await createHarness({ directory, now });

    const listed = await api(
      harness,
      "GET",
      `/v1/tenants/${tenant.tenantId}/access-credentials`,
      undefined,
      administrator.accessToken,
    );
    assert.equal(listed.status, 200);
    assert.equal(
      (listed.body.items as Array<Record<string, unknown>>).some(
        (item) => item.credentialId === administrator.credentialId,
      ),
      true,
    );
    assert.equal(
      (
        await api(
          harness,
          "POST",
          `/v1/tenants/${tenant.tenantId}/access-credentials/bootstrap-admin/revoke`,
          {},
          administrator.accessToken,
        )
      ).status,
      200,
    );
    assert.equal(
      (
        await api(
          harness,
          "GET",
          `/v1/tenants/${tenant.tenantId}/devices`,
          undefined,
          tenant.adminToken,
        )
      ).status,
      401,
    );
    const audit = await api(
      harness,
      "GET",
      `/v1/tenants/${tenant.tenantId}/access-audit`,
      undefined,
      administrator.accessToken,
    );
    assert.equal(audit.status, 200);
    assert.equal(
      (audit.body.items as Array<Record<string, unknown>>).some(
        (event) =>
          event.credentialId === administrator.credentialId &&
          event.action === "credential.revoke" &&
          event.outcome === "allowed",
      ),
      true,
    );
  } finally {
    await destroyHarness(harness);
  }
});

test("SQLite v6 migrates its tenant administrator through Fleet v8", async () => {
  let harness = await createHarness();
  const directory = harness.directory;
  const now = harness.now;
  try {
    const tenant = await createTenant(harness);
    await destroyHarness(harness, false);
    const legacy = new DatabaseSync(harness.databasePath);
    legacy.exec(`
      DROP TABLE work_order_events;
      DROP TABLE work_order_claims;
      DROP TABLE work_orders;
      DROP TABLE tenant_access_audit;
      DROP TABLE tenant_access_credentials;
      PRAGMA user_version = 6;
    `);
    legacy.close();

    harness = await createHarness({ directory, now });
    const listed = await api(
      harness,
      "GET",
      `/v1/tenants/${tenant.tenantId}/access-credentials`,
      undefined,
      tenant.adminToken,
    );
    assert.equal(listed.status, 200);
    assert.equal(
      (listed.body.items as Array<Record<string, unknown>>)[0]?.credentialId,
      "bootstrap-admin",
    );
    const database = new DatabaseSync(harness.databasePath, { readOnly: true });
    const version = database.prepare("PRAGMA user_version").get() as {
      user_version: number;
    };
    assert.equal(version.user_version, 8);
    database.close();
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
    assert.equal(replay.status, 201);
    assert.equal(replay.body.idempotent, false);

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

test("service receipts bind exact Fleet traffic, replay, restart, tenant, and revocation", async () => {
  let harness = await createHarness();
  const directory = harness.directory;
  const now = harness.now;
  try {
    const tenant = await createTenant(harness);
    const other = await createTenant(harness);
    const device = await enroll(harness, tenant, "receipt-device");

    const inventory = signedInventory(
      harness,
      tenant,
      device,
      1,
      asset("receipt-asset"),
    );
    const inventoryResult = await api(
      harness,
      "POST",
      "/v1/inventories",
      inventory,
    );
    assert.equal(
      verifiedServiceReceipt(inventoryResult, {
        requestBody: JSON.stringify(inventory),
        tenantId: tenant.tenantId,
        deviceId: device.deviceId,
        operation: "inventory",
      }).receipt.sequence,
      1,
    );

    const audit = signedAudit(harness, tenant, device, {
      sessionId: "receipt-session",
      eventId: "receipt-event",
      sequence: 1,
      previousEventSha256: null,
    });
    const auditResult = await canonicalApi(
      harness,
      "POST",
      "/v1/audit-events",
      audit,
    );
    assert.equal(
      verifiedServiceReceipt(auditResult, {
        requestBody: canonicalJson(audit),
        tenantId: tenant.tenantId,
        deviceId: device.deviceId,
        operation: "audit",
      }).receipt.sequence,
      2,
    );

    const policyPull = signedPolicyPull(harness, tenant, device);
    const policyResult = await api(
      harness,
      "POST",
      "/v1/policy-pulls",
      policyPull,
    );
    assert.equal(
      verifiedServiceReceipt(policyResult, {
        requestBody: JSON.stringify(policyPull),
        tenantId: tenant.tenantId,
        deviceId: device.deviceId,
        operation: "policy_pull",
      }).receipt.sequence,
      3,
    );

    const entitlementPull = signedEntitlementPull(harness, tenant, device);
    const entitlementResult = await api(
      harness,
      "POST",
      "/v1/entitlement-pulls",
      entitlementPull,
    );
    assert.equal(
      verifiedServiceReceipt(entitlementResult, {
        requestBody: JSON.stringify(entitlementPull),
        tenantId: tenant.tenantId,
        deviceId: device.deviceId,
        operation: "entitlement_pull",
      }).receipt.sequence,
      4,
    );

    const exactReplay = await api(
      harness,
      "POST",
      "/v1/policy-pulls",
      policyPull,
    );
    assert.equal(exactReplay.rawBody, policyResult.rawBody);
    assert.equal(
      exactReplay.headers.get("x-kernaid-fleet-receipt"),
      policyResult.headers.get("x-kernaid-fleet-receipt"),
    );

    const crossTenantUnsigned: InventoryEnvelopeUnsigned = {
      ...inventory,
      tenantId: other.tenantId,
      sequence: 2,
    };
    const crossTenant: InventoryEnvelope = {
      ...crossTenantUnsigned,
      signature: sign(
        null,
        inventorySigningBytes(crossTenantUnsigned),
        device.privateKey,
      ).toString("base64url"),
    };
    const denied = await api(harness, "POST", "/v1/inventories", crossTenant);
    assert.equal(denied.status, 401);
    assert.equal(denied.headers.get("x-kernaid-fleet-receipt"), null);

    await destroyHarness(harness, false);
    harness = await createHarness({ directory, now });
    const secondInventory = signedInventory(
      harness,
      tenant,
      device,
      2,
      asset("receipt-asset", "attention"),
    );
    const afterRestart = await api(
      harness,
      "POST",
      "/v1/inventories",
      secondInventory,
    );
    assert.equal(
      verifiedServiceReceipt(afterRestart, {
        requestBody: JSON.stringify(secondInventory),
        tenantId: tenant.tenantId,
        deviceId: device.deviceId,
        operation: "inventory",
      }).receipt.sequence,
      5,
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
    const revokedReplay = await api(
      harness,
      "POST",
      "/v1/inventories",
      secondInventory,
    );
    assert.equal(revokedReplay.status, 403);
    assert.equal(revokedReplay.headers.get("x-kernaid-fleet-receipt"), null);
  } finally {
    await destroyHarness(harness);
  }
});

test("service receipt key mismatch and database anchor change fail at startup", async () => {
  const mismatched = generateKeyPairSync("ed25519");
  assert.throws(
    () =>
      new FleetControlPlane({
        databasePath: ":memory:",
        rootToken: ROOT_TOKEN,
        serviceReceiptSigningKey: mismatched.privateKey,
        serviceReceiptTrustAnchor: SERVICE_RECEIPT_TRUST_ANCHOR,
        entitlementTrustAnchor: ENTITLEMENT_TRUST_ANCHOR,
        updateTrustAnchor: UPDATE_TRUST_ANCHOR,
      }),
    /matching Ed25519 pair/,
  );

  const harness = await createHarness();
  const directory = harness.directory;
  try {
    await destroyHarness(harness, false);
    const replacement = generateKeyPairSync("ed25519");
    const replacementAnchor = Buffer.from(
      replacement.publicKey.export({ format: "der", type: "spki" }),
    )
      .subarray(12)
      .toString("base64url");
    await assert.rejects(
      createHarness({
        directory,
        serviceReceiptSigningKey: replacement.privateKey,
        serviceReceiptTrustAnchor: replacementAnchor,
      }),
      /anchor does not match this database/,
    );
  } finally {
    rmSync(directory, { recursive: true, force: true });
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
         UNION ALL SELECT token_hash AS value FROM enrollment_tokens
         UNION ALL SELECT token_hash AS value FROM tenant_access_credentials`,
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
    assert.equal(replay.status, 201);
    assert.equal(replay.body.idempotent, false);

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
    assert.equal(oldExactReplay.status, 201);
    assert.equal(oldExactReplay.body.idempotent, false);
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
    assert.equal(replay.status, 200);
    assert.deepEqual(replay.body, firstResult.body);
    assert.equal(
      replay.headers.get("x-kernaid-fleet-receipt"),
      firstResult.headers.get("x-kernaid-fleet-receipt"),
    );

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
      DROP TABLE work_order_events;
      DROP TABLE work_order_claims;
      DROP TABLE work_orders;
      DROP TABLE tenant_access_audit;
      DROP TABLE tenant_access_credentials;
      DROP TABLE service_receipts;
      DROP TABLE service_receipt_checkpoints;
      DROP TABLE service_receipt_config;
      DROP TABLE update_pull_nonces;
      DROP TABLE update_manifests;
      DROP TABLE tenant_update_checkpoints;
      DROP TABLE entitlement_pull_nonces;
      DROP TABLE entitlement_revocations;
      DROP TABLE entitlement_documents;
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
    assert.equal(version.user_version, 8);
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

test("offline-signed entitlement publication is canonical, monotonic, and tenant-bound", async () => {
  const harness = await createHarness();
  try {
    const tenant = await createTenant(harness);
    const other = await createTenant(harness);
    const device = await enroll(
      harness,
      tenant,
      "entitlement-publisher-device",
    );
    const second = signedEntitlement(tenant, [device.deviceId], {
      entitlementId: "enterprise_primary",
      sequence: 2,
    });
    const published = await publishEntitlement(harness, tenant, second);
    assert.equal(published.status, 201);
    assert.equal(published.body.idempotent, false);
    const replay = await publishEntitlement(harness, tenant, second);
    assert.equal(replay.status, 200);
    assert.equal(replay.body.idempotent, true);

    const rollback = signedEntitlement(tenant, [device.deviceId], {
      entitlementId: "enterprise_primary",
      sequence: 1,
    });
    const rollbackResult = await publishEntitlement(harness, tenant, rollback);
    assert.equal(rollbackResult.status, 409);
    assert.equal(rollbackResult.body.error, "entitlement_sequence_rollback");

    const conflict = signedEntitlement(tenant, [device.deviceId], {
      entitlementId: "enterprise_primary",
      sequence: 2,
      graceUntilUnix: Math.floor(INITIAL_TIME / 1000) + 300_000,
    });
    const conflictResult = await publishEntitlement(harness, tenant, conflict);
    assert.equal(conflictResult.status, 409);
    assert.equal(conflictResult.body.error, "entitlement_sequence_conflict");

    const third = signedEntitlement(tenant, [device.deviceId], {
      entitlementId: "enterprise_primary",
      sequence: 3,
    });
    const tampered = {
      ...third,
      claims: { ...third.claims, plan: "retail" as const },
    };
    assert.equal(
      (await publishEntitlement(harness, tenant, tampered)).status,
      401,
    );
    assert.equal(
      (
        await canonicalApi(
          harness,
          "POST",
          `/v1/tenants/${other.tenantId}/entitlements`,
          third,
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
          `/v1/tenants/${tenant.tenantId}/entitlements`,
          third,
          other.adminToken,
        )
      ).status,
      401,
    );
    assert.equal(
      (
        await canonicalApi(
          harness,
          "POST",
          `/v1/tenants/${tenant.tenantId}/entitlements`,
          { ...third, privateNote: "forbidden" },
          tenant.adminToken,
        )
      ).status,
      400,
    );

    const revocations = signedEntitlementRevocations(2, ["enterprise_primary"]);
    assert.equal(
      (await publishEntitlementRevocations(harness, tenant, revocations))
        .status,
      201,
    );
    assert.equal(
      (await publishEntitlementRevocations(harness, tenant, revocations))
        .status,
      200,
    );
    const olderRevocations = signedEntitlementRevocations(1, []);
    assert.equal(
      (await publishEntitlementRevocations(harness, tenant, olderRevocations))
        .body.error,
      "entitlement_sequence_rollback",
    );
    const conflictingRevocations = signedEntitlementRevocations(2, []);
    assert.equal(
      (
        await publishEntitlementRevocations(
          harness,
          tenant,
          conflictingRevocations,
        )
      ).body.error,
      "entitlement_sequence_conflict",
    );
  } finally {
    await destroyHarness(harness);
  }
});

test("signed entitlement pulls isolate assignments and reject replay, key mismatch, and revoked devices", async () => {
  const harness = await createHarness();
  try {
    const tenant = await createTenant(harness);
    const otherTenant = await createTenant(harness);
    const first = await enroll(harness, tenant, "entitlement-device-one");
    const second = await enroll(harness, tenant, "entitlement-device-two");

    assert.equal(
      (
        await publishEntitlement(
          harness,
          tenant,
          signedEntitlement(tenant, [first.deviceId], {
            entitlementId: "first_only",
            sequence: 1,
          }),
        )
      ).status,
      201,
    );
    assert.equal(
      (
        await publishEntitlement(
          harness,
          tenant,
          signedEntitlement(tenant, [first.deviceId, second.deviceId], {
            entitlementId: "both_devices",
            sequence: 1,
          }),
        )
      ).status,
      201,
    );
    assert.equal(
      (
        await publishEntitlementRevocations(
          harness,
          tenant,
          signedEntitlementRevocations(1, ["retired_contract"]),
        )
      ).status,
      201,
    );

    const firstPull = signedEntitlementPull(harness, tenant, first);
    const firstResult = await api(
      harness,
      "POST",
      "/v1/entitlement-pulls",
      firstPull,
    );
    assert.equal(firstResult.status, 200);
    assert.deepEqual(
      (firstResult.body.entitlements as EntitlementEnvelope[]).map(
        (item) => item.claims.entitlementId,
      ),
      ["both_devices", "first_only"],
    );
    assert.equal(
      (firstResult.body.revocations as EntitlementRevocationEnvelope).claims
        .sequence,
      1,
    );
    const replay = await api(
      harness,
      "POST",
      "/v1/entitlement-pulls",
      firstPull,
    );
    assert.equal(replay.status, 200);
    assert.deepEqual(replay.body, firstResult.body);
    assert.equal(
      replay.headers.get("x-kernaid-fleet-receipt"),
      firstResult.headers.get("x-kernaid-fleet-receipt"),
    );

    const secondResult = await api(
      harness,
      "POST",
      "/v1/entitlement-pulls",
      signedEntitlementPull(harness, tenant, second),
    );
    assert.deepEqual(
      (secondResult.body.entitlements as EntitlementEnvelope[]).map(
        (item) => item.claims.entitlementId,
      ),
      ["both_devices"],
    );

    const wrongKeyUnsigned: EntitlementPullRequestUnsigned = {
      ...signedEntitlementPull(harness, tenant, first),
      deviceId: second.deviceId,
    };
    const wrongKey: EntitlementPullRequest = {
      ...wrongKeyUnsigned,
      signature: sign(
        null,
        entitlementPullSigningBytes(wrongKeyUnsigned),
        first.privateKey,
      ).toString("base64url"),
    };
    assert.equal(
      (await api(harness, "POST", "/v1/entitlement-pulls", wrongKey)).status,
      401,
    );

    const crossTenantUnsigned: EntitlementPullRequestUnsigned = {
      ...signedEntitlementPull(harness, tenant, first),
      tenantId: otherTenant.tenantId,
    };
    const crossTenant: EntitlementPullRequest = {
      ...crossTenantUnsigned,
      signature: sign(
        null,
        entitlementPullSigningBytes(crossTenantUnsigned),
        first.privateKey,
      ).toString("base64url"),
    };
    assert.equal(
      (await api(harness, "POST", "/v1/entitlement-pulls", crossTenant)).status,
      401,
    );

    const tampered = signedEntitlementPull(harness, tenant, first);
    tampered.issuedAt = new Date(harness.now.value + 1000).toISOString();
    assert.equal(
      (await api(harness, "POST", "/v1/entitlement-pulls", tampered)).status,
      401,
    );
    assert.equal(
      (
        await api(harness, "POST", "/v1/entitlement-pulls", {
          ...signedEntitlementPull(harness, tenant, first),
          rawDiagnostics: "forbidden",
        })
      ).status,
      400,
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
          "/v1/entitlement-pulls",
          signedEntitlementPull(harness, tenant, first),
        )
      ).status,
      403,
    );
  } finally {
    await destroyHarness(harness);
  }
});

test("SQLite v3 migrates through v8 and entitlement checkpoints survive restart", async () => {
  let harness = await createHarness();
  const directory = harness.directory;
  const now = harness.now;
  try {
    const tenant = await createTenant(harness);
    const device = await enroll(
      harness,
      tenant,
      "persistent-entitlement-device",
    );
    await destroyHarness(harness, false);

    const legacy = new DatabaseSync(harness.databasePath);
    legacy.exec(`
      DROP TABLE work_order_events;
      DROP TABLE work_order_claims;
      DROP TABLE work_orders;
      DROP TABLE tenant_access_audit;
      DROP TABLE tenant_access_credentials;
      DROP TABLE service_receipts;
      DROP TABLE service_receipt_checkpoints;
      DROP TABLE service_receipt_config;
      DROP TABLE update_pull_nonces;
      DROP TABLE update_manifests;
      DROP TABLE tenant_update_checkpoints;
      DROP TABLE entitlement_pull_nonces;
      DROP TABLE entitlement_revocations;
      DROP TABLE entitlement_documents;
      PRAGMA user_version = 3;
    `);
    legacy.close();
    harness = await createHarness({ directory, now });

    const entitlement = signedEntitlement(tenant, [device.deviceId], {
      entitlementId: "persistent_entitlement",
      sequence: 7,
    });
    const revocations = signedEntitlementRevocations(4, []);
    assert.equal(
      (await publishEntitlement(harness, tenant, entitlement)).status,
      201,
    );
    assert.equal(
      (await publishEntitlementRevocations(harness, tenant, revocations))
        .status,
      201,
    );
    await destroyHarness(harness, false);

    harness = await createHarness({ directory, now });
    const pull = signedEntitlementPull(harness, tenant, device);
    const result = await api(harness, "POST", "/v1/entitlement-pulls", pull);
    assert.equal(result.status, 200);
    assert.equal(
      (result.body.entitlements as EntitlementEnvelope[])[0]?.claims.sequence,
      7,
    );
    assert.equal(
      (result.body.revocations as EntitlementRevocationEnvelope).claims
        .sequence,
      4,
    );

    const database = new DatabaseSync(harness.databasePath, { readOnly: true });
    const version = database.prepare("PRAGMA user_version").get() as {
      user_version: number;
    };
    assert.equal(version.user_version, 8);
    const document = database
      .prepare(
        `SELECT highest_sequence, envelope_sha256, canonical_json
         FROM entitlement_documents
         WHERE tenant_id = ? AND entitlement_id = ?`,
      )
      .get(tenant.tenantId, "persistent_entitlement") as {
      highest_sequence: number;
      envelope_sha256: string;
      canonical_json: string;
    };
    assert.equal(document.highest_sequence, 7);
    assert.match(document.envelope_sha256, /^[0-9a-f]{64}$/);
    assert.equal(document.canonical_json, canonicalJson(entitlement));
    const sensitiveColumns = database
      .prepare(
        `SELECT COUNT(*) AS count FROM pragma_table_info('entitlement_documents')
         WHERE lower(name) LIKE '%private%' OR lower(name) LIKE '%seed%'
           OR lower(name) LIKE '%anchor%'`,
      )
      .get() as { count: number };
    assert.equal(sensitiveColumns.count, 0);
    const nonce = database
      .prepare(
        `SELECT nonce_sha256 FROM entitlement_pull_nonces
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

test("vendor-signed update publication is canonical, monotonic, and admin-scoped", async () => {
  const harness = await createHarness();
  try {
    const tenant = await createTenant(harness);
    const other = await createTenant(harness);
    const second = signedUpdateManifest({ sequence: 2 });

    const published = await publishUpdateManifest(harness, tenant, second);
    assert.equal(published.status, 201);
    assert.equal(published.body.idempotent, false);
    const replay = await publishUpdateManifest(harness, tenant, second);
    assert.equal(replay.status, 200);
    assert.equal(replay.body.idempotent, true);

    const rollback = await publishUpdateManifest(
      harness,
      tenant,
      signedUpdateManifest({ sequence: 1 }),
    );
    assert.equal(rollback.status, 409);
    assert.equal(rollback.body.error, "update_sequence_rollback");

    const conflict = await publishUpdateManifest(
      harness,
      tenant,
      signedUpdateManifest({ sequence: 2, releaseVersion: "2.0.0" }),
    );
    assert.equal(conflict.status, 409);
    assert.equal(conflict.body.error, "update_sequence_conflict");

    const third = signedUpdateManifest({ sequence: 3 });
    assert.equal(
      (
        await publishUpdateManifest(harness, tenant, {
          ...third,
          releaseVersion: "tampered",
        })
      ).status,
      401,
    );
    assert.equal(
      (
        await canonicalApi(
          harness,
          "POST",
          `/v1/tenants/${tenant.tenantId}/update-manifests`,
          third,
          other.adminToken,
        )
      ).status,
      401,
    );
    assert.equal(
      (
        await canonicalApi(
          harness,
          "POST",
          `/v1/tenants/${tenant.tenantId}/update-manifests`,
          { ...third, signingSeed: "forbidden" },
          tenant.adminToken,
        )
      ).status,
      400,
    );
  } finally {
    await destroyHarness(harness);
  }
});

test("signed update pulls bind target and ring, filter eligibility, and reject replay", async () => {
  const harness = await createHarness();
  try {
    const tenant = await createTenant(harness);
    const device = await enroll(harness, tenant, "update-device");
    assert.equal(
      (
        await publishUpdateManifest(
          harness,
          tenant,
          signedUpdateManifest({ sequence: 1, releaseRing: "stable" }),
        )
      ).status,
      201,
    );
    assert.equal(
      (
        await publishUpdateManifest(
          harness,
          tenant,
          signedUpdateManifest({ sequence: 2, releaseRing: "canary" }),
        )
      ).status,
      201,
    );

    const stablePull = signedUpdatePull(harness, tenant, device);
    const stable = await api(harness, "POST", "/v1/update-pulls", stablePull);
    assert.equal(stable.status, 200);
    assert.deepEqual(
      (stable.body.items as SignedUpdateManifest[]).map(
        (item) => item.sequence,
      ),
      [1],
    );
    assert.equal(stable.body.platform, "linux");
    assert.equal(stable.body.architecture, "x86_64");
    assert.equal(stable.body.updateRing, "stable");
    const replay = await api(harness, "POST", "/v1/update-pulls", stablePull);
    assert.equal(replay.status, 409);
    assert.equal(replay.body.error, "update_pull_replay");

    const canary = await api(
      harness,
      "POST",
      "/v1/update-pulls",
      signedUpdatePull(harness, tenant, device, { updateRing: "canary" }),
    );
    assert.deepEqual(
      (canary.body.items as SignedUpdateManifest[]).map(
        (item) => item.sequence,
      ),
      [2, 1],
    );
    const held = await api(
      harness,
      "POST",
      "/v1/update-pulls",
      signedUpdatePull(harness, tenant, device, { updateRing: "hold" }),
    );
    assert.deepEqual(held.body.items, []);
    const wrongArchitecture = await api(
      harness,
      "POST",
      "/v1/update-pulls",
      signedUpdatePull(harness, tenant, device, { architecture: "aarch64" }),
    );
    assert.equal(wrongArchitecture.body.architecture, "aarch64");
    assert.deepEqual(wrongArchitecture.body.items, []);

    const tampered = signedUpdatePull(harness, tenant, device);
    tampered.updateRing = "canary";
    assert.equal(
      (await api(harness, "POST", "/v1/update-pulls", tampered)).status,
      401,
    );
    assert.equal(
      (
        await api(
          harness,
          "POST",
          "/v1/update-pulls",
          signedUpdatePull(harness, tenant, device, { platform: "windows" }),
        )
      ).status,
      403,
    );

    assert.equal(
      (
        await publishUpdateManifest(
          harness,
          tenant,
          signedUpdateManifest({
            sequence: 3,
            releaseRing: "stable",
            basisPoints: 0,
            emergencyRollback: true,
          }),
        )
      ).status,
      201,
    );
    const emergency = await api(
      harness,
      "POST",
      "/v1/update-pulls",
      signedUpdatePull(harness, tenant, device, { updateRing: "hold" }),
    );
    assert.deepEqual(
      (emergency.body.items as SignedUpdateManifest[]).map(
        (item) => item.sequence,
      ),
      [3],
    );
  } finally {
    await destroyHarness(harness);
  }
});

test("SQLite v4 migrates through v8 and update checkpoints survive restart", async () => {
  let harness = await createHarness();
  const directory = harness.directory;
  const now = harness.now;
  try {
    const tenant = await createTenant(harness);
    const device = await enroll(harness, tenant, "persistent-update-device");
    await destroyHarness(harness, false);

    const legacy = new DatabaseSync(harness.databasePath);
    legacy.exec(`
      DROP TABLE work_order_events;
      DROP TABLE work_order_claims;
      DROP TABLE work_orders;
      DROP TABLE tenant_access_audit;
      DROP TABLE tenant_access_credentials;
      DROP TABLE service_receipts;
      DROP TABLE service_receipt_checkpoints;
      DROP TABLE service_receipt_config;
      DROP TABLE update_pull_nonces;
      DROP TABLE update_manifests;
      DROP TABLE tenant_update_checkpoints;
      PRAGMA user_version = 4;
    `);
    legacy.close();
    harness = await createHarness({ directory, now });
    const manifest = signedUpdateManifest({ sequence: 7 });
    assert.equal(
      (await publishUpdateManifest(harness, tenant, manifest)).status,
      201,
    );
    await destroyHarness(harness, false);

    harness = await createHarness({ directory, now });
    const pull = signedUpdatePull(harness, tenant, device);
    const result = await api(harness, "POST", "/v1/update-pulls", pull);
    assert.equal(result.status, 200);
    assert.equal((result.body.items as SignedUpdateManifest[])[0]?.sequence, 7);

    const database = new DatabaseSync(harness.databasePath, { readOnly: true });
    const version = database.prepare("PRAGMA user_version").get() as {
      user_version: number;
    };
    assert.equal(version.user_version, 8);
    const checkpoint = database
      .prepare(
        `SELECT highest_sequence, manifest_sha256
         FROM tenant_update_checkpoints WHERE tenant_id = ?`,
      )
      .get(tenant.tenantId) as {
      highest_sequence: number;
      manifest_sha256: string;
    };
    assert.equal(checkpoint.highest_sequence, 7);
    assert.match(checkpoint.manifest_sha256, /^[0-9a-f]{64}$/);
    const nonce = database
      .prepare(
        `SELECT nonce_sha256 FROM update_pull_nonces
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

test("tenant governance status is bounded, minimized, and admin-scoped", async () => {
  const harness = await createHarness();
  try {
    const tenant = await createTenant(harness);
    const other = await createTenant(harness);
    const device = await enroll(harness, tenant, "governance-console-device");
    const policySigner = makePolicySigner();
    assert.equal(
      (await setPolicyAnchor(harness, tenant, policySigner)).status,
      201,
    );
    assert.equal(
      (
        await publishPolicy(
          harness,
          tenant,
          signedPolicy(tenant, policySigner, {
            policyId: "enterprise-baseline",
            revision: 3,
            assignments: { all: true },
          }),
        )
      ).status,
      201,
    );
    assert.equal(
      (
        await publishEntitlement(
          harness,
          tenant,
          signedEntitlement(tenant, [device.deviceId], {
            entitlementId: "enterprise-console",
            sequence: 4,
          }),
        )
      ).status,
      201,
    );
    assert.equal(
      (
        await publishEntitlementRevocations(
          harness,
          tenant,
          signedEntitlementRevocations(2, ["retired-license"]),
        )
      ).status,
      201,
    );
    assert.equal(
      (
        await publishUpdateManifest(
          harness,
          tenant,
          signedUpdateManifest({ sequence: 9 }),
        )
      ).status,
      201,
    );

    const paths = ["policies", "entitlements", "update-manifests"];
    const responses = await Promise.all(
      paths.map((path) =>
        api(
          harness,
          "GET",
          `/v1/tenants/${tenant.tenantId}/${path}`,
          undefined,
          tenant.adminToken,
        ),
      ),
    );
    assert.deepEqual(
      responses.map((response) => response.status),
      [200, 200, 200],
    );
    assert.equal(responses[0]?.body.trustAnchorConfigured, true);
    assert.equal(
      (responses[0]?.body.items as { policyId: string }[])[0]?.policyId,
      "enterprise-baseline",
    );
    assert.equal(
      (responses[1]?.body.items as { entitlementId: string }[])[0]
        ?.entitlementId,
      "enterprise-console",
    );
    assert.equal(
      (responses[1]?.body.revocations as { sequence: number }).sequence,
      2,
    );
    assert.equal(
      (responses[2]?.body.items as { sequence: number }[])[0]?.sequence,
      9,
    );
    const serialized = JSON.stringify(
      responses.map((response) => response.body),
    );
    assert.doesNotMatch(
      serialized,
      /signature|canonical_json|artifact|publicKey|private|seed/i,
    );
    assert.equal(
      (
        await api(
          harness,
          "GET",
          `/v1/tenants/${tenant.tenantId}/policies`,
          undefined,
          other.adminToken,
        )
      ).status,
      401,
    );
  } finally {
    await destroyHarness(harness);
  }
});

test("typed work orders require governance and explicit write approval", async () => {
  const harness = await createHarness();
  try {
    const tenant = await createTenant(harness);
    const operator = await createAccessCredential(
      harness,
      tenant,
      "operator",
      "Repair desk",
    );
    const device = await enroll(harness, tenant, "work-order-device", "rescue");
    const signer = makePolicySigner();
    assert.equal((await setPolicyAnchor(harness, tenant, signer)).status, 201);
    assert.equal(
      (
        await publishPolicy(
          harness,
          tenant,
          signedPolicy(tenant, signer, {
            policyId: "work-orders",
            revision: 1,
            assignments: { deviceIds: [device.deviceId] },
            allowedActionIds: [
              "linux.filesystem.health.v1",
              "linux.fstab.disable-missing-uuid.v1",
              "linux.storage.health.v1",
            ],
          }),
        )
      ).status,
      201,
    );
    assert.equal(
      (
        await publishEntitlement(
          harness,
          tenant,
          signedEntitlement(tenant, [device.deviceId], {
            entitlementId: "work_order_license",
            sequence: 1,
          }),
        )
      ).status,
      201,
    );

    const expiresAt = new Date(harness.now.value + 3_600_000).toISOString();
    const diagnosticBody = {
      requestId: "request-diagnostic-1",
      targetDeviceId: device.deviceId,
      actionId: "linux.storage.health.v1",
      actionVersion: 1,
      expiresAt,
    };
    assert.equal(
      (
        await api(
          harness,
          "POST",
          `/v1/tenants/${tenant.tenantId}/work-orders`,
          { ...diagnosticBody, command: "sh -c id" },
          operator.accessToken,
        )
      ).status,
      400,
    );
    const diagnostic = await api(
      harness,
      "POST",
      `/v1/tenants/${tenant.tenantId}/work-orders`,
      diagnosticBody,
      operator.accessToken,
    );
    assert.equal(diagnostic.status, 201);
    assert.equal(diagnostic.body.status, "queued");

    const repair = await api(
      harness,
      "POST",
      `/v1/tenants/${tenant.tenantId}/work-orders`,
      {
        requestId: "request-repair-1",
        targetDeviceId: device.deviceId,
        actionId: "linux.fstab.disable-missing-uuid.v1",
        actionVersion: 1,
        expiresAt,
      },
      operator.accessToken,
    );
    assert.equal(repair.status, 201);
    assert.equal(repair.body.status, "pending_approval");
    assert.equal(repair.body.localApprovalRequired, true);
    assert.equal(
      (
        await api(
          harness,
          "POST",
          `/v1/tenants/${tenant.tenantId}/work-orders/${repair.body.workOrderId as string}/approve`,
          { decision: "approve" },
          operator.accessToken,
        )
      ).status,
      403,
    );

    const claim = signedWorkOrderClaim(harness, tenant, device);
    const claimed = await api(harness, "POST", "/v1/work-order-claims", claim);
    assert.equal(claimed.status, 200);
    const leasedDiagnostic = claimed.body.workOrder as Record<string, unknown>;
    assert.equal(leasedDiagnostic.actionId, "linux.storage.health.v1");
    assert.equal(leasedDiagnostic.status, "leased");
    assert.equal(leasedDiagnostic.approval, null);
    verifiedServiceReceipt(claimed, {
      requestBody: JSON.stringify(claim),
      tenantId: tenant.tenantId,
      deviceId: device.deviceId,
      operation: "work_order_claim",
    });
    const repeatedClaim = await api(
      harness,
      "POST",
      "/v1/work-order-claims",
      claim,
    );
    assert.equal(repeatedClaim.rawBody, claimed.rawBody);
    assert.equal(
      repeatedClaim.headers.get("x-kernaid-fleet-receipt"),
      claimed.headers.get("x-kernaid-fleet-receipt"),
    );
    const reboundUnsigned: WorkOrderClaimRequestUnsigned = {
      schema: claim.schema,
      tenantId: claim.tenantId,
      deviceId: claim.deviceId,
      issuedAt: claim.issuedAt,
      nonce: claim.nonce,
      leaseSeconds: 301,
    };
    const reboundClaim: WorkOrderClaimRequest = {
      ...reboundUnsigned,
      signature: sign(
        null,
        workOrderClaimSigningBytes(reboundUnsigned),
        device.privateKey,
      ).toString("base64url"),
    };
    assert.equal(
      (await api(harness, "POST", "/v1/work-order-claims", reboundClaim))
        .status,
      409,
    );

    const resultEnvelope = signedWorkOrderResult(
      harness,
      tenant,
      device,
      leasedDiagnostic,
    );
    const completed = await api(
      harness,
      "POST",
      "/v1/work-order-results",
      resultEnvelope,
    );
    assert.equal(completed.status, 201);
    assert.equal(completed.body.status, "succeeded");
    assert.equal(completed.body.resultSha256, resultEnvelope.resultSha256);
    verifiedServiceReceipt(completed, {
      requestBody: JSON.stringify(resultEnvelope),
      tenantId: tenant.tenantId,
      deviceId: device.deviceId,
      operation: "work_order_result",
    });
    const repeated = await api(
      harness,
      "POST",
      "/v1/work-order-results",
      resultEnvelope,
    );
    assert.equal(repeated.rawBody, completed.rawBody);
    assert.equal(
      repeated.headers.get("x-kernaid-fleet-receipt"),
      completed.headers.get("x-kernaid-fleet-receipt"),
    );

    const approved = await api(
      harness,
      "POST",
      `/v1/tenants/${tenant.tenantId}/work-orders/${repair.body.workOrderId as string}/approve`,
      { decision: "approve" },
      tenant.adminToken,
    );
    assert.equal(approved.status, 200);
    const repairClaim = await api(
      harness,
      "POST",
      "/v1/work-order-claims",
      signedWorkOrderClaim(harness, tenant, device),
    );
    assert.equal(repairClaim.status, 200);
    const leasedRepair = repairClaim.body.workOrder as Record<string, unknown>;
    assert.equal(leasedRepair.actionId, "linux.fstab.disable-missing-uuid.v1");
    assert.equal(leasedRepair.localApprovalRequired, true);
    assert.notEqual(leasedRepair.approval, null);

    const events = await api(
      harness,
      "GET",
      `/v1/tenants/${tenant.tenantId}/work-order-events`,
      undefined,
      operator.accessToken,
    );
    assert.equal(events.status, 200);
    assert.equal(
      (events.body.items as Array<Record<string, unknown>>).some(
        (event) => event.kind === "approved" && event.status === "queued",
      ),
      true,
    );
    assert.doesNotMatch(JSON.stringify(events.body), /sh -c|signature/i);
  } finally {
    await destroyHarness(harness);
  }
});

test("work-order tenant, signature, entitlement, and revocation checks fail closed", async () => {
  const harness = await createHarness();
  try {
    const first = await createTenant(harness);
    const second = await createTenant(harness);
    const device = await enroll(harness, first, "governed-work-order-device");
    const signer = makePolicySigner();
    assert.equal((await setPolicyAnchor(harness, first, signer)).status, 201);
    assert.equal(
      (
        await publishPolicy(
          harness,
          first,
          signedPolicy(first, signer, {
            policyId: "diagnostics",
            revision: 1,
            assignments: { deviceIds: [device.deviceId] },
            allowedActionIds: ["linux.storage.health.v1"],
          }),
        )
      ).status,
      201,
    );
    const entitlement = signedEntitlement(first, [device.deviceId], {
      entitlementId: "governed_license",
      sequence: 1,
    });
    assert.equal(
      (await publishEntitlement(harness, first, entitlement)).status,
      201,
    );
    const body = {
      requestId: "governed-request",
      targetDeviceId: device.deviceId,
      actionId: "linux.storage.health.v1",
      actionVersion: 1,
      expiresAt: new Date(harness.now.value + 600_000).toISOString(),
    };
    assert.equal(
      (
        await api(
          harness,
          "POST",
          `/v1/tenants/${first.tenantId}/work-orders`,
          body,
          second.adminToken,
        )
      ).status,
      401,
    );
    assert.equal(
      (
        await api(
          harness,
          "POST",
          `/v1/tenants/${first.tenantId}/work-orders`,
          { ...body, actionId: "shell.exec.v1", requestId: "shell-request" },
          first.adminToken,
        )
      ).status,
      400,
    );
    assert.equal(
      (
        await api(
          harness,
          "POST",
          `/v1/tenants/${first.tenantId}/work-orders`,
          body,
          first.adminToken,
        )
      ).status,
      201,
    );
    const tamperedClaim = signedWorkOrderClaim(harness, first, device);
    tamperedClaim.leaseSeconds = 301;
    assert.equal(
      (await api(harness, "POST", "/v1/work-order-claims", tamperedClaim))
        .status,
      401,
    );
    assert.equal(
      (
        await publishEntitlementRevocations(
          harness,
          first,
          signedEntitlementRevocations(1, [entitlement.claims.entitlementId]),
        )
      ).status,
      201,
    );
    const noLease = await api(
      harness,
      "POST",
      "/v1/work-order-claims",
      signedWorkOrderClaim(harness, first, device),
    );
    assert.equal(noLease.status, 200);
    assert.equal(noLease.body.workOrder, null);
    assert.equal(
      (
        await api(
          harness,
          "POST",
          `/v1/tenants/${first.tenantId}/devices/${device.deviceId}/revoke`,
          {},
          first.adminToken,
        )
      ).status,
      200,
    );
    assert.equal(
      (
        await api(
          harness,
          "POST",
          "/v1/work-order-claims",
          signedWorkOrderClaim(harness, first, device),
        )
      ).status,
      403,
    );
  } finally {
    await destroyHarness(harness);
  }
});

test("work-order cancellation, expiry, and audit survive restart", async () => {
  let harness = await createHarness();
  const directory = harness.directory;
  const now = harness.now;
  try {
    const tenant = await createTenant(harness);
    const device = await enroll(
      harness,
      tenant,
      "persistent-work-order-device",
    );
    const signer = makePolicySigner();
    assert.equal((await setPolicyAnchor(harness, tenant, signer)).status, 201);
    assert.equal(
      (
        await publishPolicy(
          harness,
          tenant,
          signedPolicy(tenant, signer, {
            policyId: "persistent-work-orders",
            revision: 1,
            assignments: { deviceIds: [device.deviceId] },
            allowedActionIds: ["linux.filesystem.health.v1"],
          }),
        )
      ).status,
      201,
    );
    assert.equal(
      (
        await publishEntitlement(
          harness,
          tenant,
          signedEntitlement(tenant, [device.deviceId], {
            entitlementId: "persistent_work_order_license",
            sequence: 1,
          }),
        )
      ).status,
      201,
    );
    const create = async (requestId: string, lifetime: number) =>
      api(
        harness,
        "POST",
        `/v1/tenants/${tenant.tenantId}/work-orders`,
        {
          requestId,
          targetDeviceId: device.deviceId,
          actionId: "linux.filesystem.health.v1",
          actionVersion: 1,
          expiresAt: new Date(harness.now.value + lifetime).toISOString(),
        },
        tenant.adminToken,
      );
    const cancelled = await create("cancel-me", 600_000);
    assert.equal(cancelled.status, 201);
    assert.equal(
      (
        await api(
          harness,
          "POST",
          `/v1/tenants/${tenant.tenantId}/work-orders/${cancelled.body.workOrderId as string}/cancel`,
          {},
          tenant.adminToken,
        )
      ).status,
      200,
    );
    assert.equal((await create("expire-me", 60_000)).status, 201);
    harness.now.value += 61_000;
    await destroyHarness(harness, false);
    harness = await createHarness({ directory, now });
    const listed = await api(
      harness,
      "GET",
      `/v1/tenants/${tenant.tenantId}/work-orders`,
      undefined,
      tenant.adminToken,
    );
    assert.equal(listed.status, 200);
    const statuses = new Map(
      (listed.body.items as Array<Record<string, unknown>>).map((item) => [
        item.requestId,
        item.status,
      ]),
    );
    assert.equal(statuses.get("cancel-me"), "cancelled");
    assert.equal(statuses.get("expire-me"), "expired");
    const claim = await api(
      harness,
      "POST",
      "/v1/work-order-claims",
      signedWorkOrderClaim(harness, tenant, device),
    );
    assert.equal(claim.status, 200);
    assert.equal(claim.body.workOrder, null);
    const events = await api(
      harness,
      "GET",
      `/v1/tenants/${tenant.tenantId}/work-order-events`,
      undefined,
      tenant.adminToken,
    );
    assert.equal(events.status, 200);
    assert.deepEqual(
      new Set(
        (events.body.items as Array<Record<string, unknown>>).map(
          (event) => event.kind,
        ),
      ),
      new Set(["created", "cancelled", "expired"]),
    );
    const database = new DatabaseSync(harness.databasePath, { readOnly: true });
    const version = database.prepare("PRAGMA user_version").get() as {
      user_version: number;
    };
    assert.equal(version.user_version, 8);
    database.close();
  } finally {
    await destroyHarness(harness);
  }
});
