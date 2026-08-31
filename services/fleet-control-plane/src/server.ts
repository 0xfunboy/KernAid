import {
  createServer,
  type IncomingMessage,
  type Server,
  type ServerResponse,
} from "node:http";
import type { AddressInfo } from "node:net";
import type { KeyObject } from "node:crypto";
import { lstatSync, readFileSync, realpathSync } from "node:fs";
import { extname, relative, resolve, sep } from "node:path";
import {
  FleetSchemaError,
  MAX_ENTITLEMENT_DOCUMENT_BYTES,
  MAX_POLICY_BUNDLE_BYTES,
  MAX_UPDATE_MANIFEST_BYTES,
  FLEET_UPDATE_PULL_RESPONSE_SCHEMA,
  FLEET_SERVICE_RECEIPT_SCHEMA,
  auditSigningBytes,
  canonicalJson,
  enrollmentSigningBytes,
  expectExactKeys,
  expectIdentifier,
  expectRecord,
  expectRfc3339,
  expectSafeInteger,
  inventorySigningBytes,
  isWorkOrderActionId,
  entitlementAppliesTo,
  entitlementPullSigningBytes,
  entitlementRevocationSigningBytes,
  entitlementSigningBytes,
  parseEntitlementEnvelope,
  parseEntitlementPullRequest,
  parseEntitlementRevocationEnvelope,
  parsePolicyPullRequest,
  parseSignedPolicyBundle,
  parseSignedUpdateManifest,
  parseServiceReceipt,
  parseUpdatePullRequest,
  parseWorkOrderClaimRequest,
  parseWorkOrderResult,
  policyBundleSigningBytes,
  policyPullSigningBytes,
  serviceReceiptSigningBytes,
  updateAppliesTo,
  updateManifestSigningBytes,
  updatePullSigningBytes,
  workOrderAction,
  workOrderActionCatalog,
  workOrderClaimSigningBytes,
  workOrderResultSigningBytes,
  parseEnrollmentRequest,
  parseAuditEnvelope,
  parseInventoryEnvelope,
  type FleetServiceOperation,
  type ServiceReceipt,
  type ServiceReceiptUnsigned,
  type WorkOrderActionId,
} from "@kernaid/fleet-schemas";
import {
  generateSecret,
  generateTenantId,
  generateCredentialId,
  generateWorkOrderId,
  generateWorkOrderLeaseId,
  deviceIdForEd25519Spki,
  hashSecret,
  decodeBase64UrlExact,
  importEd25519Spki,
  importEd25519Raw,
  ed25519RawPublicKey,
  signEd25519,
  secureSecretEqual,
  sha256Hex,
  verifyEd25519,
} from "./crypto.js";
import {
  FleetStore,
  StoreChainForkError,
  StoreAuthorizationError,
  StoreConflictError,
  StoreReplayError,
  StoreRevokedError,
  StoreSequenceGapError,
  StoreNonceReplayError,
  StorePolicyConflictError,
  StorePolicyRollbackError,
  StoreEntitlementConflictError,
  StoreEntitlementPullReplayError,
  StoreEntitlementRollbackError,
  StoreUpdateConflictError,
  StoreUpdatePullReplayError,
  StoreUpdateRollbackError,
  StoreWorkOrderReplayError,
  StoreWorkOrderStateError,
  type StoredServiceResponse,
  type StoredWorkOrder,
  type TenantAccessCredential,
} from "./store.js";
import {
  isTenantRole,
  tenantRoleAllows,
  validCredentialLabel,
  type TenantAccessAction,
  type TenantAccessTargetType,
  type TenantRole,
} from "./access.js";

const MAX_REQUEST_BYTES = 64 * 1024;
const MAX_ENROLLMENT_TOKEN_SECONDS = 7 * 24 * 60 * 60;
const MAX_SERVICE_RESPONSE_BYTES = 4 * 1024 * 1024;
const SERVICE_RECEIPT_HEADER = "X-KernAid-Fleet-Receipt";
const MAX_WORK_ORDER_LIFETIME_MS = 7 * 24 * 60 * 60 * 1000;

export interface FleetControlPlaneOptions {
  databasePath: string;
  rootToken: string;
  serviceReceiptSigningKey: KeyObject;
  serviceReceiptTrustAnchor: string;
  entitlementTrustAnchor: string;
  updateTrustAnchor: string;
  enrollmentClockSkewMs?: number;
  now?: () => Date;
  consoleDirectory?: string;
}

interface ServiceResponseContext {
  operation: FleetServiceOperation;
  tenantId: string;
  deviceId: string;
  requestSha256: string;
}

interface ServicePullNonce {
  nonceSha256: string;
  expiresAtMs: number;
  nowMs: number;
}

interface TenantAuthorizationTarget {
  type: TenantAccessTargetType;
  id: string;
}

export class FleetControlPlane {
  readonly #store: FleetStore;
  readonly #rootToken: string;
  readonly #serviceReceiptSigningKey: KeyObject;
  readonly #serviceReceiptTrustAnchor: KeyObject;
  readonly #entitlementTrustAnchor: KeyObject;
  readonly #updateTrustAnchor: KeyObject;
  readonly #clockSkewMs: number;
  readonly #now: () => Date;
  readonly #server: Server;
  readonly #consoleDirectory: string | undefined;
  #closed = false;

  constructor(options: FleetControlPlaneOptions) {
    if (
      options.rootToken.length < 32 ||
      options.rootToken.length > 512 ||
      !/^[A-Za-z0-9_-]+$/.test(options.rootToken)
    ) {
      throw new Error(
        "root token must be 32-512 canonical base64url characters",
      );
    }
    try {
      this.#entitlementTrustAnchor = importEd25519Raw(
        options.entitlementTrustAnchor,
      );
    } catch {
      throw new Error(
        "entitlement trust anchor must be a canonical raw Ed25519 public key",
      );
    }
    try {
      this.#serviceReceiptTrustAnchor = importEd25519Raw(
        options.serviceReceiptTrustAnchor,
      );
      if (
        options.serviceReceiptSigningKey.type !== "private" ||
        options.serviceReceiptSigningKey.asymmetricKeyType !== "ed25519" ||
        ed25519RawPublicKey(options.serviceReceiptSigningKey) !==
          options.serviceReceiptTrustAnchor
      ) {
        throw new Error("service receipt key mismatch");
      }
      this.#serviceReceiptSigningKey = options.serviceReceiptSigningKey;
    } catch {
      throw new Error(
        "service receipt signing key and trust anchor must be a matching Ed25519 pair",
      );
    }
    try {
      this.#updateTrustAnchor = importEd25519Raw(options.updateTrustAnchor);
    } catch {
      throw new Error(
        "update trust anchor must be a canonical raw Ed25519 public key",
      );
    }
    this.#store = new FleetStore(options.databasePath);
    try {
      this.#store.bindServiceReceiptAnchor(
        sha256Hex(decodeBase64UrlExact(options.serviceReceiptTrustAnchor)),
      );
    } catch (error) {
      this.#store.close();
      throw error;
    }
    this.#rootToken = options.rootToken;
    this.#clockSkewMs = options.enrollmentClockSkewMs ?? 300_000;
    this.#now = options.now ?? (() => new Date());
    this.#consoleDirectory = resolveConsoleDirectory(options.consoleDirectory);
    this.#server = createServer((request, response) => {
      void this.#handle(request, response);
    });
  }

  async listen(port = 0, host = "127.0.0.1"): Promise<string> {
    if (this.#closed) throw new Error("Fleet control plane is closed");
    await new Promise<void>((resolve, reject) => {
      const onError = (error: Error): void => reject(error);
      this.#server.once("error", onError);
      this.#server.listen(port, host, () => {
        this.#server.off("error", onError);
        resolve();
      });
    });
    const address = this.#server.address() as AddressInfo;
    const renderedHost =
      address.family === "IPv6" ? `[${address.address}]` : address.address;
    return `http://${renderedHost}:${address.port}`;
  }

  async close(): Promise<void> {
    if (this.#closed) return;
    this.#closed = true;
    if (this.#server.listening) {
      await new Promise<void>((resolve, reject) => {
        this.#server.close((error) =>
          error === undefined ? resolve() : reject(error),
        );
      });
    }
    this.#store.close();
  }

  async #handle(
    request: IncomingMessage,
    response: ServerResponse,
  ): Promise<void> {
    response.setHeader("Cache-Control", "no-store");
    response.setHeader("X-Content-Type-Options", "nosniff");
    response.setHeader("Referrer-Policy", "no-referrer");

    try {
      const url = new URL(request.url ?? "/", "http://fleet.invalid");
      if (url.search.length !== 0) throw new HttpError(400, "invalid_request");
      await this.#route(request, response, url.pathname);
    } catch (error) {
      if (response.headersSent) {
        response.destroy();
        return;
      }
      if (error instanceof HttpError) {
        writeJson(response, error.status, { error: error.code });
      } else if (error instanceof FleetSchemaError) {
        writeJson(response, 400, { error: "invalid_request" });
      } else if (error instanceof StoreAuthorizationError) {
        writeJson(response, 401, { error: "not_authorized" });
      } else if (error instanceof StoreRevokedError) {
        writeJson(response, 403, { error: "device_revoked" });
      } else if (error instanceof StoreConflictError) {
        writeJson(response, 409, { error: "conflict" });
      } else if (error instanceof StoreReplayError) {
        writeJson(response, 409, { error: "sequence_replay" });
      } else if (error instanceof StoreSequenceGapError) {
        writeJson(response, 409, { error: "sequence_gap" });
      } else if (error instanceof StoreChainForkError) {
        writeJson(response, 409, { error: "chain_fork" });
      } else if (error instanceof StorePolicyRollbackError) {
        writeJson(response, 409, { error: "policy_revision_rollback" });
      } else if (error instanceof StorePolicyConflictError) {
        writeJson(response, 409, { error: "policy_revision_conflict" });
      } else if (error instanceof StoreNonceReplayError) {
        writeJson(response, 409, { error: "policy_pull_replay" });
      } else if (error instanceof StoreEntitlementRollbackError) {
        writeJson(response, 409, { error: "entitlement_sequence_rollback" });
      } else if (error instanceof StoreEntitlementConflictError) {
        writeJson(response, 409, { error: "entitlement_sequence_conflict" });
      } else if (error instanceof StoreEntitlementPullReplayError) {
        writeJson(response, 409, { error: "entitlement_pull_replay" });
      } else if (error instanceof StoreUpdateRollbackError) {
        writeJson(response, 409, { error: "update_sequence_rollback" });
      } else if (error instanceof StoreUpdateConflictError) {
        writeJson(response, 409, { error: "update_sequence_conflict" });
      } else if (error instanceof StoreUpdatePullReplayError) {
        writeJson(response, 409, { error: "update_pull_replay" });
      } else if (error instanceof StoreWorkOrderReplayError) {
        writeJson(response, 409, { error: "work_order_replay" });
      } else if (error instanceof StoreWorkOrderStateError) {
        writeJson(response, 409, { error: "work_order_state_conflict" });
      } else {
        writeJson(response, 500, { error: "internal_error" });
      }
    }
  }

  async #route(
    request: IncomingMessage,
    response: ServerResponse,
    path: string,
  ): Promise<void> {
    const method = request.method ?? "GET";
    if (method === "GET" && path === "/console") {
      response.statusCode = 308;
      response.setHeader("Location", "/console/");
      response.end();
      return;
    }
    if (method === "GET" && path.startsWith("/console/")) {
      this.#serveConsoleAsset(path, response);
      return;
    }
    if (method === "GET" && path === "/healthz") {
      this.#store.healthCheck();
      writeJson(response, 200, { status: "ok" });
      return;
    }

    if (method === "POST" && path === "/v1/tenants") {
      this.#authorizeRoot(request);
      expectEmptyObject(await readJson(request));
      const tenantId = generateTenantId();
      const adminToken = generateSecret();
      const createdAt = this.#validNow().toISOString();
      this.#store.createTenant(
        tenantId,
        hashSecret("admin", adminToken),
        createdAt,
      );
      writeJson(response, 201, {
        schema: "dev.kernaid.fleet.tenant-created.v1",
        tenantId,
        adminToken,
        createdAt,
      });
      return;
    }

    const accessCredentialsMatch =
      /^\/v1\/tenants\/([^/]+)\/access-credentials$/.exec(path);
    if (method === "GET" && accessCredentialsMatch !== null) {
      const tenantId = pathIdentifier(accessCredentialsMatch[1], "tenantId");
      this.#authorizeTenant(
        request,
        tenantId,
        "admin",
        "credential.list",
        tenantTarget(tenantId),
      );
      writeJson(response, 200, {
        schema: "dev.kernaid.fleet.access-credential-list.v1",
        tenantId,
        items: this.#store
          .listTenantAccessCredentials(tenantId)
          .map(publicTenantAccessCredential),
      });
      return;
    }
    if (method === "POST" && accessCredentialsMatch !== null) {
      const tenantId = pathIdentifier(accessCredentialsMatch[1], "tenantId");
      this.#authorizeTenant(
        request,
        tenantId,
        "admin",
        "credential.create",
        tenantTarget(tenantId),
      );
      const body = expectRecord(await readJson(request));
      expectExactKeys(body, ["label", "role"]);
      if (
        typeof body.role !== "string" ||
        !isTenantRole(body.role) ||
        typeof body.label !== "string" ||
        !validCredentialLabel(body.label)
      ) {
        throw new HttpError(400, "invalid_request");
      }
      const accessToken = generateSecret();
      const createdAt = this.#validNow().toISOString();
      const credential = this.#store.createTenantAccessCredential({
        tenantId,
        credentialId: generateCredentialId(),
        tokenHash: hashSecret("admin", accessToken),
        role: body.role,
        label: body.label,
        createdAt,
      });
      writeJson(response, 201, {
        schema: "dev.kernaid.fleet.access-credential-created.v1",
        ...publicTenantAccessCredential(credential),
        accessToken,
      });
      return;
    }

    const accessAuditMatch = /^\/v1\/tenants\/([^/]+)\/access-audit$/.exec(
      path,
    );
    if (method === "GET" && accessAuditMatch !== null) {
      const tenantId = pathIdentifier(accessAuditMatch[1], "tenantId");
      this.#authorizeTenant(
        request,
        tenantId,
        "admin",
        "access_audit.list",
        tenantTarget(tenantId),
      );
      writeJson(response, 200, {
        schema: "dev.kernaid.fleet.access-audit-list.v1",
        tenantId,
        items: this.#store.listTenantAccessAudit(tenantId),
      });
      return;
    }

    const accessCredentialRevokeMatch =
      /^\/v1\/tenants\/([^/]+)\/access-credentials\/([^/]+)\/revoke$/.exec(
        path,
      );
    if (method === "POST" && accessCredentialRevokeMatch !== null) {
      const tenantId = pathIdentifier(
        accessCredentialRevokeMatch[1],
        "tenantId",
      );
      const credentialId = pathIdentifier(
        accessCredentialRevokeMatch[2],
        "credentialId",
      );
      const actor = this.#authorizeTenant(
        request,
        tenantId,
        "admin",
        "credential.revoke",
        { type: "credential", id: credentialId },
      );
      expectEmptyObject(await readJson(request));
      const result = this.#store.revokeTenantAccessCredential({
        tenantId,
        credentialId,
        actorCredentialId: actor.credentialId,
        revokedAt: this.#validNow().toISOString(),
      });
      if (result === undefined) throw new HttpError(404, "not_found");
      writeJson(response, 200, {
        schema: "dev.kernaid.fleet.access-credential-revoked.v1",
        ...publicTenantAccessCredential(result.credential),
        idempotent: result.idempotent,
      });
      return;
    }

    const tokenMatch = /^\/v1\/tenants\/([^/]+)\/enrollment-tokens$/.exec(path);
    if (method === "POST" && tokenMatch !== null) {
      const tenantId = pathIdentifier(tokenMatch[1], "tenantId");
      this.#authorizeTenant(
        request,
        tenantId,
        "operator",
        "enrollment_token.create",
        tenantTarget(tenantId),
      );
      const body = expectRecord(await readJson(request));
      expectExactKeys(body, ["expiresInSeconds"]);
      const expiresInSeconds = expectSafeInteger(
        body.expiresInSeconds,
        "expiresInSeconds",
        1,
      );
      if (expiresInSeconds > MAX_ENROLLMENT_TOKEN_SECONDS) {
        throw new HttpError(400, "invalid_request");
      }
      const token = generateSecret();
      const now = this.#validNow();
      const expiresAtMs = now.getTime() + expiresInSeconds * 1000;
      this.#store.createEnrollmentToken({
        tokenHash: hashSecret("enrollment", token),
        tenantId,
        createdAt: now.toISOString(),
        expiresAtMs,
      });
      writeJson(response, 201, {
        schema: "dev.kernaid.fleet.enrollment-token-created.v1",
        tenantId,
        enrollmentToken: token,
        expiresAt: new Date(expiresAtMs).toISOString(),
      });
      return;
    }

    const policyAnchorMatch =
      /^\/v1\/tenants\/([^/]+)\/policy-trust-anchor$/.exec(path);
    if (method === "POST" && policyAnchorMatch !== null) {
      const tenantId = pathIdentifier(policyAnchorMatch[1], "tenantId");
      this.#authorizeTenant(
        request,
        tenantId,
        "admin",
        "policy_trust_anchor.set",
        tenantTarget(tenantId),
      );
      const body = expectRecord(await readJson(request));
      expectExactKeys(body, ["publicKeySpki"]);
      if (
        typeof body.publicKeySpki !== "string" ||
        body.publicKeySpki.length < 40 ||
        body.publicKeySpki.length > 512
      ) {
        throw new HttpError(400, "invalid_public_key");
      }
      try {
        importEd25519Spki(body.publicKeySpki);
      } catch {
        throw new HttpError(400, "invalid_public_key");
      }
      const setAt = this.#validNow().toISOString();
      this.#store.setPolicyTrustAnchor(tenantId, body.publicKeySpki, setAt);
      writeJson(response, 201, {
        schema: "dev.kernaid.fleet.policy-trust-anchor-set.v1",
        tenantId,
        publicKeySha256: sha256Hex(decodeBase64UrlExact(body.publicKeySpki)),
        setAt,
      });
      return;
    }

    const policiesMatch = /^\/v1\/tenants\/([^/]+)\/policies$/.exec(path);
    if (method === "GET" && policiesMatch !== null) {
      const tenantId = pathIdentifier(policiesMatch[1], "tenantId");
      this.#authorizeTenant(
        request,
        tenantId,
        "operator",
        "policy.list",
        tenantTarget(tenantId),
      );
      const items = this.#store.listPolicyJson(tenantId).map((stored) => {
        const bundle = parseSignedPolicyBundle(JSON.parse(stored) as unknown);
        return {
          policyId: bundle.policyId,
          revision: bundle.revision,
          issuedAtUnix: bundle.issuedAtUnix,
          notBeforeUnix: bundle.notBeforeUnix,
          offlineAllowedUntilUnix: bundle.offlineAllowedUntilUnix,
          expiresAtUnix: bundle.expiresAtUnix,
          assignmentScope: "all" in bundle.assignments ? "all" : "devices",
          assignedDeviceCount:
            "all" in bundle.assignments
              ? null
              : bundle.assignments.deviceIds.length,
          maxRisk: bundle.rules.maxRisk,
          localApprovalFrom: bundle.rules.localApprovalFrom,
          updateRing: bundle.rules.updateRing,
        };
      });
      writeJson(response, 200, {
        schema: "dev.kernaid.fleet.policy-status-list.v1",
        tenantId,
        trustAnchorConfigured:
          this.#store.getPolicyTrustAnchor(tenantId) !== undefined,
        items,
      });
      return;
    }
    if (method === "POST" && policiesMatch !== null) {
      const tenantId = pathIdentifier(policiesMatch[1], "tenantId");
      this.#authorizeTenant(
        request,
        tenantId,
        "admin",
        "policy.publish",
        tenantTarget(tenantId),
      );
      const bundle = parseSignedPolicyBundle(
        await readCanonicalJson(request, MAX_POLICY_BUNDLE_BYTES),
      );
      if (bundle.tenantId !== tenantId) {
        throw new HttpError(403, "tenant_mismatch");
      }
      const anchorSpki = this.#store.getPolicyTrustAnchor(tenantId);
      if (anchorSpki === undefined) {
        throw new HttpError(409, "policy_trust_anchor_not_set");
      }
      let anchor;
      try {
        anchor = importEd25519Spki(anchorSpki);
      } catch {
        throw new HttpError(500, "invalid_stored_key");
      }
      if (
        !verifyEd25519(
          anchor,
          policyBundleSigningBytes(bundle),
          bundle.signature,
        )
      ) {
        throw new HttpError(401, "invalid_signature");
      }
      const canonicalBundle = canonicalJson(bundle);
      const publishedAt = this.#validNow().toISOString();
      const result = this.#store.publishPolicy(
        bundle,
        canonicalBundle,
        sha256Hex(canonicalBundle),
        publishedAt,
      );
      writeJson(response, result.idempotent ? 200 : 201, {
        schema: "dev.kernaid.fleet.policy-published.v1",
        tenantId,
        policyId: bundle.policyId,
        revision: bundle.revision,
        accepted: true,
        idempotent: result.idempotent,
        publishedAt: result.publishedAt,
      });
      return;
    }

    const entitlementsMatch = /^\/v1\/tenants\/([^/]+)\/entitlements$/.exec(
      path,
    );
    if (method === "GET" && entitlementsMatch !== null) {
      const tenantId = pathIdentifier(entitlementsMatch[1], "tenantId");
      this.#authorizeTenant(
        request,
        tenantId,
        "operator",
        "entitlement.list",
        tenantTarget(tenantId),
      );
      const items = this.#store.listEntitlementJson(tenantId).map((stored) => {
        const envelope = parseEntitlementEnvelope(
          JSON.parse(stored) as unknown,
        );
        return {
          entitlementId: envelope.claims.entitlementId,
          sequence: envelope.claims.sequence,
          plan: envelope.claims.plan,
          features: envelope.claims.features,
          assignedDeviceCount: envelope.claims.deviceIds.length,
          maxToolDevices: envelope.claims.limits.maxToolDevices,
          maxManagedAssets: envelope.claims.limits.maxManagedAssets,
          offlineLeaseUntilUnix: envelope.claims.offlineLeaseUntilUnix,
          expiresAtUnix: envelope.claims.expiresAtUnix,
          graceUntilUnix: envelope.claims.graceUntilUnix,
        };
      });
      const storedRevocations =
        this.#store.getEntitlementRevocationsJson(tenantId);
      const revocationEnvelope =
        storedRevocations === undefined
          ? undefined
          : parseEntitlementRevocationEnvelope(
              JSON.parse(storedRevocations) as unknown,
            );
      writeJson(response, 200, {
        schema: "dev.kernaid.fleet.entitlement-status-list.v1",
        tenantId,
        items,
        revocations:
          revocationEnvelope === undefined
            ? null
            : {
                sequence: revocationEnvelope.claims.sequence,
                issuedAtUnix: revocationEnvelope.claims.issuedAtUnix,
                revokedCount:
                  revocationEnvelope.claims.revokedEntitlementIds.length,
              },
      });
      return;
    }
    if (method === "POST" && entitlementsMatch !== null) {
      const tenantId = pathIdentifier(entitlementsMatch[1], "tenantId");
      this.#authorizeTenant(
        request,
        tenantId,
        "admin",
        "entitlement.publish",
        tenantTarget(tenantId),
      );
      const envelope = parseEntitlementEnvelope(
        await readCanonicalJson(request, MAX_ENTITLEMENT_DOCUMENT_BYTES),
      );
      if (envelope.claims.tenantId !== tenantId) {
        throw new HttpError(403, "tenant_mismatch");
      }
      if (
        !verifyEd25519(
          this.#entitlementTrustAnchor,
          entitlementSigningBytes(envelope),
          envelope.signature,
        )
      ) {
        throw new HttpError(401, "invalid_signature");
      }
      const canonicalEnvelope = canonicalJson(envelope);
      const result = this.#store.publishEntitlement(
        tenantId,
        envelope,
        canonicalEnvelope,
        sha256Hex(canonicalEnvelope),
      );
      writeJson(response, result.idempotent ? 200 : 201, {
        schema: "dev.kernaid.fleet.entitlement-published.v1",
        tenantId,
        entitlementId: envelope.claims.entitlementId,
        sequence: envelope.claims.sequence,
        accepted: true,
        idempotent: result.idempotent,
      });
      return;
    }

    const entitlementRevocationsMatch =
      /^\/v1\/tenants\/([^/]+)\/entitlement-revocations$/.exec(path);
    if (method === "POST" && entitlementRevocationsMatch !== null) {
      const tenantId = pathIdentifier(
        entitlementRevocationsMatch[1],
        "tenantId",
      );
      this.#authorizeTenant(
        request,
        tenantId,
        "admin",
        "entitlement_revocations.publish",
        tenantTarget(tenantId),
      );
      const envelope = parseEntitlementRevocationEnvelope(
        await readCanonicalJson(request, MAX_ENTITLEMENT_DOCUMENT_BYTES),
      );
      if (
        !verifyEd25519(
          this.#entitlementTrustAnchor,
          entitlementRevocationSigningBytes(envelope),
          envelope.signature,
        )
      ) {
        throw new HttpError(401, "invalid_signature");
      }
      const canonicalEnvelope = canonicalJson(envelope);
      const result = this.#store.publishEntitlementRevocations(
        tenantId,
        envelope,
        canonicalEnvelope,
        sha256Hex(canonicalEnvelope),
      );
      writeJson(response, result.idempotent ? 200 : 201, {
        schema: "dev.kernaid.fleet.entitlement-revocations-published.v1",
        tenantId,
        sequence: envelope.claims.sequence,
        accepted: true,
        idempotent: result.idempotent,
      });
      return;
    }

    const updateManifestsMatch =
      /^\/v1\/tenants\/([^/]+)\/update-manifests$/.exec(path);
    if (method === "GET" && updateManifestsMatch !== null) {
      const tenantId = pathIdentifier(updateManifestsMatch[1], "tenantId");
      this.#authorizeTenant(
        request,
        tenantId,
        "operator",
        "update.list",
        tenantTarget(tenantId),
      );
      const items = this.#store
        .listAllUpdateManifestJson(tenantId)
        .map((stored) => {
          const manifest = parseSignedUpdateManifest(
            JSON.parse(stored) as unknown,
          );
          return {
            releaseId: manifest.releaseId,
            releaseVersion: manifest.releaseVersion,
            sequence: manifest.sequence,
            platform: manifest.platform,
            architecture: manifest.architecture,
            releaseRing: manifest.releaseRing,
            rolloutBasisPoints: manifest.rollout.basisPoints,
            notBeforeUnix: manifest.notBeforeUnix,
            expiresAtUnix: manifest.expiresAtUnix,
            emergencyRollback: manifest.emergencyRollback,
          };
        });
      writeJson(response, 200, {
        schema: "dev.kernaid.fleet.update-status-list.v1",
        tenantId,
        items,
      });
      return;
    }
    if (method === "POST" && updateManifestsMatch !== null) {
      const tenantId = pathIdentifier(updateManifestsMatch[1], "tenantId");
      this.#authorizeTenant(
        request,
        tenantId,
        "admin",
        "update.publish",
        tenantTarget(tenantId),
      );
      const manifest = parseSignedUpdateManifest(
        await readCanonicalJson(request, MAX_UPDATE_MANIFEST_BYTES),
      );
      if (
        !verifyEd25519(
          this.#updateTrustAnchor,
          updateManifestSigningBytes(manifest),
          manifest.signature,
        )
      ) {
        throw new HttpError(401, "invalid_signature");
      }
      const canonicalManifest = canonicalJson(manifest);
      const result = this.#store.publishUpdateManifest(
        tenantId,
        manifest,
        canonicalManifest,
        sha256Hex(canonicalManifest),
        this.#validNow().toISOString(),
      );
      writeJson(response, result.idempotent ? 200 : 201, {
        schema: "dev.kernaid.fleet.update-manifest-published.v1",
        tenantId,
        releaseId: manifest.releaseId,
        sequence: manifest.sequence,
        accepted: true,
        idempotent: result.idempotent,
        publishedAt: result.publishedAt,
      });
      return;
    }

    const workOrdersMatch = /^\/v1\/tenants\/([^/]+)\/work-orders$/.exec(path);
    if (method === "GET" && workOrdersMatch !== null) {
      const tenantId = pathIdentifier(workOrdersMatch[1], "tenantId");
      this.#authorizeTenant(
        request,
        tenantId,
        "operator",
        "work_order.list",
        tenantTarget(tenantId),
      );
      const now = this.#validNow();
      writeJson(response, 200, {
        schema: "dev.kernaid.fleet.work-order-list.v1",
        tenantId,
        items: this.#store
          .listWorkOrders(tenantId, now.getTime(), now.toISOString())
          .map(tenantWorkOrder),
      });
      return;
    }
    if (method === "POST" && workOrdersMatch !== null) {
      const tenantId = pathIdentifier(workOrdersMatch[1], "tenantId");
      const actor = this.#authorizeTenant(
        request,
        tenantId,
        "operator",
        "work_order.create",
        tenantTarget(tenantId),
      );
      const body = expectRecord(await readJson(request));
      expectExactKeys(body, [
        "requestId",
        "targetDeviceId",
        "actionId",
        "actionVersion",
        "expiresAt",
      ]);
      const requestId = expectIdentifier(body.requestId, "requestId");
      const targetDeviceId = expectIdentifier(
        body.targetDeviceId,
        "targetDeviceId",
      );
      const actionId = expectIdentifier(body.actionId, "actionId");
      if (!isWorkOrderActionId(actionId)) {
        throw new HttpError(400, "unsupported_action");
      }
      const action = workOrderAction(actionId);
      const actionVersion = expectSafeInteger(
        body.actionVersion,
        "actionVersion",
        1,
      );
      if (actionVersion !== action.version) {
        throw new HttpError(400, "unsupported_action_version");
      }
      const expiresAt = expectRfc3339(body.expiresAt, "expiresAt");
      const now = this.#validNow();
      const expiresAtMs = Date.parse(expiresAt);
      if (
        expiresAtMs <= now.getTime() ||
        expiresAtMs > now.getTime() + MAX_WORK_ORDER_LIFETIME_MS
      ) {
        throw new HttpError(400, "invalid_work_order_expiry");
      }
      const device = this.#store.getDevice(tenantId, targetDeviceId);
      if (device === undefined) throw new HttpError(404, "target_not_found");
      if (device.revokedAt !== null) {
        throw new HttpError(403, "device_revoked");
      }
      if (!(action.platforms as readonly string[]).includes(device.platform)) {
        throw new HttpError(403, "action_platform_mismatch");
      }
      if (
        !this.#isWorkOrderAuthorized(tenantId, targetDeviceId, actionId, now)
      ) {
        throw new HttpError(403, "work_order_not_authorized");
      }
      const normalized = {
        requestId,
        targetDeviceId,
        actionId,
        actionVersion,
        expiresAt,
      };
      const result = this.#store.createWorkOrder({
        tenantId,
        workOrderId: generateWorkOrderId(),
        requestId,
        requestSha256: sha256Hex(canonicalJson(normalized)),
        targetDeviceId,
        actionId,
        actionVersion,
        kind: action.kind,
        risk: action.risk,
        localApprovalRequired: action.localApprovalRequired,
        createdByCredentialId: actor.credentialId,
        createdAt: now.toISOString(),
        expiresAt,
        expiresAtMs,
      });
      writeJson(response, result.idempotent ? 200 : 201, {
        schema: "dev.kernaid.fleet.work-order-created.v1",
        ...tenantWorkOrder(result.workOrder),
        idempotent: result.idempotent,
      });
      return;
    }

    const workOrderAuditMatch =
      /^\/v1\/tenants\/([^/]+)\/work-order-events$/.exec(path);
    if (method === "GET" && workOrderAuditMatch !== null) {
      const tenantId = pathIdentifier(workOrderAuditMatch[1], "tenantId");
      this.#authorizeTenant(
        request,
        tenantId,
        "operator",
        "work_order_audit.list",
        tenantTarget(tenantId),
      );
      writeJson(response, 200, {
        schema: "dev.kernaid.fleet.work-order-event-list.v1",
        tenantId,
        items: this.#store.listWorkOrderEvents(tenantId),
      });
      return;
    }

    const workOrderApproveMatch =
      /^\/v1\/tenants\/([^/]+)\/work-orders\/([^/]+)\/approve$/.exec(path);
    if (method === "POST" && workOrderApproveMatch !== null) {
      const tenantId = pathIdentifier(workOrderApproveMatch[1], "tenantId");
      const workOrderId = pathIdentifier(
        workOrderApproveMatch[2],
        "workOrderId",
      );
      const actor = this.#authorizeTenant(
        request,
        tenantId,
        "admin",
        "work_order.approve",
        { type: "work_order", id: workOrderId },
      );
      const body = expectRecord(await readJson(request));
      expectExactKeys(body, ["decision"]);
      if (body.decision !== "approve") {
        throw new HttpError(400, "invalid_request");
      }
      const now = this.#validNow();
      const existing = this.#store.getWorkOrder(
        tenantId,
        workOrderId,
        now.getTime(),
        now.toISOString(),
      );
      if (existing === undefined) throw new HttpError(404, "not_found");
      if (
        !this.#isWorkOrderAuthorized(
          tenantId,
          existing.targetDeviceId,
          existing.actionId,
          now,
        )
      ) {
        throw new HttpError(403, "work_order_not_authorized");
      }
      const result = this.#store.approveWorkOrder({
        tenantId,
        workOrderId,
        credentialId: actor.credentialId,
        approvedAt: now.toISOString(),
        nowMs: now.getTime(),
      });
      if (result === undefined) throw new HttpError(404, "not_found");
      writeJson(response, 200, {
        schema: "dev.kernaid.fleet.work-order-approved.v1",
        ...tenantWorkOrder(result.workOrder),
        idempotent: result.idempotent,
      });
      return;
    }

    const workOrderCancelMatch =
      /^\/v1\/tenants\/([^/]+)\/work-orders\/([^/]+)\/cancel$/.exec(path);
    if (method === "POST" && workOrderCancelMatch !== null) {
      const tenantId = pathIdentifier(workOrderCancelMatch[1], "tenantId");
      const workOrderId = pathIdentifier(
        workOrderCancelMatch[2],
        "workOrderId",
      );
      const actor = this.#authorizeTenant(
        request,
        tenantId,
        "operator",
        "work_order.cancel",
        { type: "work_order", id: workOrderId },
      );
      expectEmptyObject(await readJson(request));
      const now = this.#validNow();
      const result = this.#store.cancelWorkOrder({
        tenantId,
        workOrderId,
        credentialId: actor.credentialId,
        cancelledAt: now.toISOString(),
        nowMs: now.getTime(),
      });
      if (result === undefined) throw new HttpError(404, "not_found");
      writeJson(response, 200, {
        schema: "dev.kernaid.fleet.work-order-cancelled.v1",
        ...tenantWorkOrder(result.workOrder),
        idempotent: result.idempotent,
      });
      return;
    }

    if (method === "POST" && path === "/v1/work-order-claims") {
      const received = await readJsonRequest(request);
      const claim = parseWorkOrderClaimRequest(received.value);
      const device = this.#store.getDevice(claim.tenantId, claim.deviceId);
      if (device === undefined) throw new HttpError(401, "unknown_device");
      if (device.revokedAt !== null) throw new HttpError(403, "device_revoked");
      let publicKey;
      try {
        publicKey = importEd25519Spki(device.publicKeySpki);
      } catch {
        throw new HttpError(500, "invalid_stored_key");
      }
      if (
        !verifyEd25519(
          publicKey,
          workOrderClaimSigningBytes(claim),
          claim.signature,
        )
      ) {
        throw new HttpError(401, "invalid_signature");
      }
      const context = serviceResponseContext(
        "work_order_claim",
        claim.tenantId,
        claim.deviceId,
        received.bytes,
      );
      if (this.#replayServiceResponse(response, context)) return;
      const now = this.#validNow();
      const issuedAtMs = Date.parse(claim.issuedAt);
      if (Math.abs(now.getTime() - issuedAtMs) > this.#clockSkewMs) {
        throw new HttpError(401, "work_order_claim_timestamp_rejected");
      }
      const eligibleActionIds = (
        Object.keys(workOrderActionCatalog) as WorkOrderActionId[]
      ).filter((actionId) =>
        this.#isWorkOrderAuthorized(
          claim.tenantId,
          claim.deviceId,
          actionId,
          now,
        ),
      );
      const result = this.#store.claimWorkOrder({
        tenantId: claim.tenantId,
        deviceId: claim.deviceId,
        requestSha256: context.requestSha256,
        nonceSha256: sha256Hex(
          `kernaid:fleet:work-order-claim-nonce:v1\0${claim.nonce}`,
        ),
        nonceExpiresAtMs: issuedAtMs + this.#clockSkewMs + 1,
        leaseId: generateWorkOrderLeaseId(),
        leaseSeconds: claim.leaseSeconds,
        eligibleActionIds,
        nowMs: now.getTime(),
        now: now.toISOString(),
      });
      this.#commitServiceResponse(
        response,
        context,
        200,
        {
          schema: "dev.kernaid.fleet.work-order-claim-response.v1",
          tenantId: claim.tenantId,
          deviceId: claim.deviceId,
          workOrder:
            result.workOrder === null
              ? null
              : deviceWorkOrder(result.workOrder),
          idempotent: result.idempotent,
        },
        now,
      );
      return;
    }

    if (method === "POST" && path === "/v1/work-order-results") {
      const received = await readJsonRequest(request);
      const resultEnvelope = parseWorkOrderResult(received.value);
      const device = this.#store.getDevice(
        resultEnvelope.tenantId,
        resultEnvelope.deviceId,
      );
      if (device === undefined) throw new HttpError(401, "unknown_device");
      if (device.revokedAt !== null) throw new HttpError(403, "device_revoked");
      let publicKey;
      try {
        publicKey = importEd25519Spki(device.publicKeySpki);
      } catch {
        throw new HttpError(500, "invalid_stored_key");
      }
      if (
        !verifyEd25519(
          publicKey,
          workOrderResultSigningBytes(resultEnvelope),
          resultEnvelope.signature,
        )
      ) {
        throw new HttpError(401, "invalid_signature");
      }
      const context = serviceResponseContext(
        "work_order_result",
        resultEnvelope.tenantId,
        resultEnvelope.deviceId,
        received.bytes,
      );
      if (this.#replayServiceResponse(response, context)) return;
      const now = this.#validNow();
      if (
        Math.abs(now.getTime() - Date.parse(resultEnvelope.completedAt)) >
        this.#clockSkewMs
      ) {
        throw new HttpError(401, "work_order_result_timestamp_rejected");
      }
      const result = this.#store.recordWorkOrderResult({
        result: resultEnvelope,
        envelopeSha256: sha256Hex(canonicalJson(resultEnvelope)),
        receivedAt: now.toISOString(),
        nowMs: now.getTime(),
      });
      this.#commitServiceResponse(
        response,
        context,
        result.idempotent ? 200 : 201,
        {
          schema: "dev.kernaid.fleet.work-order-result-response.v1",
          tenantId: resultEnvelope.tenantId,
          deviceId: resultEnvelope.deviceId,
          workOrderId: resultEnvelope.workOrderId,
          status: result.workOrder.status,
          outcome: result.workOrder.outcome,
          resultSha256: result.workOrder.resultSha256,
          accepted: true,
          idempotent: result.idempotent,
        },
        now,
      );
      return;
    }

    if (method === "POST" && path === "/v1/enrollments") {
      const enrollment = parseEnrollmentRequest(await readJson(request));
      const now = this.#validNow();
      if (
        Math.abs(now.getTime() - Date.parse(enrollment.issuedAt)) >
        this.#clockSkewMs
      ) {
        throw new HttpError(401, "enrollment_timestamp_rejected");
      }
      const tokenHash = hashSecret("enrollment", enrollment.enrollmentToken);
      if (
        !this.#store.isEnrollmentTokenUsable(
          tokenHash,
          enrollment.tenantId,
          now.getTime(),
        )
      ) {
        throw new HttpError(401, "invalid_enrollment_token");
      }

      let publicKey;
      try {
        publicKey = importEd25519Spki(enrollment.publicKeySpki);
      } catch {
        throw new HttpError(400, "invalid_public_key");
      }
      if (
        deviceIdForEd25519Spki(enrollment.publicKeySpki) !== enrollment.deviceId
      ) {
        throw new HttpError(401, "device_key_mismatch");
      }
      if (
        !verifyEd25519(
          publicKey,
          enrollmentSigningBytes(enrollment),
          enrollment.signature,
        )
      ) {
        throw new HttpError(401, "invalid_signature");
      }

      this.#store.enrollDevice({
        tokenHash,
        tenantId: enrollment.tenantId,
        deviceId: enrollment.deviceId,
        publicKeySpki: enrollment.publicKeySpki,
        platform: enrollment.platform,
        agentVersion: enrollment.agentVersion,
        enrolledAt: now.toISOString(),
        nowMs: now.getTime(),
      });
      writeJson(response, 201, {
        schema: "dev.kernaid.fleet.enrollment-response.v1",
        tenantId: enrollment.tenantId,
        deviceId: enrollment.deviceId,
        enrolledAt: now.toISOString(),
        accepted: true,
      });
      return;
    }

    if (method === "POST" && path === "/v1/inventories") {
      const received = await readJsonRequest(request);
      const envelope = parseInventoryEnvelope(received.value);
      const device = this.#store.getDevice(
        envelope.tenantId,
        envelope.deviceId,
      );
      if (device === undefined) throw new HttpError(401, "unknown_device");
      if (device.revokedAt !== null) throw new HttpError(403, "device_revoked");

      let publicKey;
      try {
        publicKey = importEd25519Spki(device.publicKeySpki);
      } catch {
        throw new HttpError(500, "invalid_stored_key");
      }
      if (
        !verifyEd25519(
          publicKey,
          inventorySigningBytes(envelope),
          envelope.signature,
        )
      ) {
        throw new HttpError(401, "invalid_signature");
      }
      const context = serviceResponseContext(
        "inventory",
        envelope.tenantId,
        envelope.deviceId,
        received.bytes,
      );
      if (
        envelope.sequence === device.lastSequence &&
        this.#replayServiceResponse(response, context)
      ) {
        return;
      }

      const now = this.#validNow();
      if (Date.parse(envelope.observedAt) > now.getTime() + this.#clockSkewMs) {
        throw new HttpError(400, "inventory_timestamp_rejected");
      }

      const result = this.#store.recordInventory(
        envelope,
        sha256Hex(canonicalJson(envelope)),
        now.toISOString(),
      );
      this.#commitServiceResponse(
        response,
        context,
        result.idempotent ? 200 : 201,
        {
          schema: "dev.kernaid.fleet.inventory-response.v1",
          tenantId: envelope.tenantId,
          deviceId: envelope.deviceId,
          sequence: envelope.sequence,
          accepted: true,
          idempotent: result.idempotent,
        },
        now,
      );
      return;
    }

    if (method === "POST" && path === "/v1/audit-events") {
      const received = await readCanonicalJsonRequest(request);
      const envelope = parseAuditEnvelope(received.value);
      const device = this.#store.getDevice(
        envelope.tenantId,
        envelope.deviceId,
      );
      if (device === undefined) throw new HttpError(401, "unknown_device");
      if (device.revokedAt !== null) throw new HttpError(403, "device_revoked");

      let publicKey;
      try {
        publicKey = importEd25519Spki(device.publicKeySpki);
      } catch {
        throw new HttpError(500, "invalid_stored_key");
      }
      if (
        !verifyEd25519(
          publicKey,
          auditSigningBytes(envelope),
          envelope.signature,
        )
      ) {
        throw new HttpError(401, "invalid_signature");
      }
      const context = serviceResponseContext(
        "audit",
        envelope.tenantId,
        envelope.deviceId,
        received.bytes,
      );
      if (this.#replayServiceResponse(response, context)) return;

      const now = this.#validNow();
      if (Date.parse(envelope.occurredAt) > now.getTime() + this.#clockSkewMs) {
        throw new HttpError(400, "audit_timestamp_rejected");
      }

      const result = this.#store.recordAuditEvent(
        envelope,
        sha256Hex(canonicalJson(envelope)),
        now.toISOString(),
      );
      this.#commitServiceResponse(
        response,
        context,
        result.idempotent ? 200 : 201,
        {
          schema: "dev.kernaid.fleet.audit-response.v1",
          tenantId: envelope.tenantId,
          deviceId: envelope.deviceId,
          sessionId: envelope.sessionId,
          eventId: envelope.eventId,
          sequence: envelope.sequence,
          accepted: true,
          idempotent: result.idempotent,
        },
        now,
      );
      return;
    }

    if (method === "POST" && path === "/v1/policy-pulls") {
      const received = await readJsonRequest(request);
      const pull = parsePolicyPullRequest(received.value);
      const device = this.#store.getDevice(pull.tenantId, pull.deviceId);
      if (device === undefined) throw new HttpError(401, "unknown_device");
      if (device.revokedAt !== null) throw new HttpError(403, "device_revoked");
      let publicKey;
      try {
        publicKey = importEd25519Spki(device.publicKeySpki);
      } catch {
        throw new HttpError(500, "invalid_stored_key");
      }
      if (
        !verifyEd25519(publicKey, policyPullSigningBytes(pull), pull.signature)
      ) {
        throw new HttpError(401, "invalid_signature");
      }
      const context = serviceResponseContext(
        "policy_pull",
        pull.tenantId,
        pull.deviceId,
        received.bytes,
      );
      if (this.#replayServiceResponse(response, context)) return;

      const now = this.#validNow();
      const issuedAtMs = Date.parse(pull.issuedAt);
      if (Math.abs(now.getTime() - issuedAtMs) > this.#clockSkewMs) {
        throw new HttpError(401, "policy_pull_timestamp_rejected");
      }
      const items = this.#store
        .listApplicablePolicyJson(pull.tenantId, pull.deviceId)
        .map((stored) =>
          parseSignedPolicyBundle(JSON.parse(stored) as unknown),
        );
      this.#commitServiceResponse(
        response,
        context,
        200,
        {
          schema: "dev.kernaid.fleet.policy-pull-response.v1",
          tenantId: pull.tenantId,
          deviceId: pull.deviceId,
          items,
        },
        now,
        {
          nonceSha256: sha256Hex(
            `kernaid:fleet:policy-pull-nonce:v1\0${pull.nonce}`,
          ),
          expiresAtMs: issuedAtMs + this.#clockSkewMs + 1,
          nowMs: now.getTime(),
        },
      );
      return;
    }

    if (method === "POST" && path === "/v1/entitlement-pulls") {
      const received = await readJsonRequest(request);
      const pull = parseEntitlementPullRequest(received.value);
      const device = this.#store.getDevice(pull.tenantId, pull.deviceId);
      if (device === undefined) throw new HttpError(401, "unknown_device");
      if (device.revokedAt !== null) throw new HttpError(403, "device_revoked");
      let publicKey;
      try {
        publicKey = importEd25519Spki(device.publicKeySpki);
      } catch {
        throw new HttpError(500, "invalid_stored_key");
      }
      if (
        !verifyEd25519(
          publicKey,
          entitlementPullSigningBytes(pull),
          pull.signature,
        )
      ) {
        throw new HttpError(401, "invalid_signature");
      }
      const context = serviceResponseContext(
        "entitlement_pull",
        pull.tenantId,
        pull.deviceId,
        received.bytes,
      );
      if (this.#replayServiceResponse(response, context)) return;

      const now = this.#validNow();
      const issuedAtMs = Date.parse(pull.issuedAt);
      if (Math.abs(now.getTime() - issuedAtMs) > this.#clockSkewMs) {
        throw new HttpError(401, "entitlement_pull_timestamp_rejected");
      }
      const entitlements = this.#store
        .listEntitlementJson(pull.tenantId)
        .map((stored) =>
          parseEntitlementEnvelope(JSON.parse(stored) as unknown),
        )
        .filter((envelope) => entitlementAppliesTo(envelope, pull.deviceId));
      const storedRevocations = this.#store.getEntitlementRevocationsJson(
        pull.tenantId,
      );
      const revocations =
        storedRevocations === undefined
          ? null
          : parseEntitlementRevocationEnvelope(
              JSON.parse(storedRevocations) as unknown,
            );
      this.#commitServiceResponse(
        response,
        context,
        200,
        {
          schema: "dev.kernaid.fleet.entitlement-pull-response.v1",
          tenantId: pull.tenantId,
          deviceId: pull.deviceId,
          entitlements,
          revocations,
        },
        now,
        {
          nonceSha256: sha256Hex(
            `kernaid:fleet:entitlement-pull-nonce:v1\0${pull.nonce}`,
          ),
          expiresAtMs: issuedAtMs + this.#clockSkewMs + 1,
          nowMs: now.getTime(),
        },
      );
      return;
    }

    if (method === "POST" && path === "/v1/update-pulls") {
      const pull = parseUpdatePullRequest(await readJson(request));
      const now = this.#validNow();
      const issuedAtMs = Date.parse(pull.issuedAt);
      if (Math.abs(now.getTime() - issuedAtMs) > this.#clockSkewMs) {
        throw new HttpError(401, "update_pull_timestamp_rejected");
      }
      const device = this.#store.getDevice(pull.tenantId, pull.deviceId);
      if (device === undefined) throw new HttpError(401, "unknown_device");
      if (device.revokedAt !== null) throw new HttpError(403, "device_revoked");
      if (device.platform !== pull.platform) {
        throw new HttpError(403, "device_platform_mismatch");
      }
      let publicKey;
      try {
        publicKey = importEd25519Spki(device.publicKeySpki);
      } catch {
        throw new HttpError(500, "invalid_stored_key");
      }
      if (
        !verifyEd25519(publicKey, updatePullSigningBytes(pull), pull.signature)
      ) {
        throw new HttpError(401, "invalid_signature");
      }
      this.#store.recordUpdatePullNonce({
        tenantId: pull.tenantId,
        deviceId: pull.deviceId,
        nonceSha256: sha256Hex(
          `kernaid:fleet:update-pull-nonce:v1\0${pull.nonce}`,
        ),
        expiresAtMs: issuedAtMs + this.#clockSkewMs + 1,
        nowMs: now.getTime(),
      });
      const nowUnix = Math.floor(now.getTime() / 1000);
      const items = this.#store
        .listUpdateManifestJson(pull.tenantId, pull.platform, pull.architecture)
        .map((stored) =>
          parseSignedUpdateManifest(JSON.parse(stored) as unknown),
        )
        .filter((manifest) => {
          if (
            !verifyEd25519(
              this.#updateTrustAnchor,
              updateManifestSigningBytes(manifest),
              manifest.signature,
            )
          ) {
            throw new Error("stored update manifest signature is invalid");
          }
          return updateAppliesTo(manifest, pull, nowUnix);
        });
      writeJson(response, 200, {
        schema: FLEET_UPDATE_PULL_RESPONSE_SCHEMA,
        tenantId: pull.tenantId,
        deviceId: pull.deviceId,
        platform: pull.platform,
        architecture: pull.architecture,
        updateRing: pull.updateRing,
        items,
      });
      return;
    }

    const devicesMatch = /^\/v1\/tenants\/([^/]+)\/devices$/.exec(path);
    if (method === "GET" && devicesMatch !== null) {
      const tenantId = pathIdentifier(devicesMatch[1], "tenantId");
      this.#authorizeTenant(
        request,
        tenantId,
        "operator",
        "device.list",
        tenantTarget(tenantId),
      );
      const devices = this.#store.listDevices(tenantId).map((device) => ({
        tenantId: device.tenantId,
        deviceId: device.deviceId,
        platform: device.platform,
        agentVersion: device.agentVersion,
        enrolledAt: device.enrolledAt,
        revokedAt: device.revokedAt,
        status: device.revokedAt === null ? "active" : "revoked",
        lastSequence: device.lastSequence,
        lastSeenAt: device.lastSeenAt,
      }));
      writeJson(response, 200, {
        schema: "dev.kernaid.fleet.device-list.v1",
        tenantId,
        items: devices,
      });
      return;
    }

    const assetsMatch = /^\/v1\/tenants\/([^/]+)\/assets$/.exec(path);
    if (method === "GET" && assetsMatch !== null) {
      const tenantId = pathIdentifier(assetsMatch[1], "tenantId");
      this.#authorizeTenant(
        request,
        tenantId,
        "operator",
        "asset.list",
        tenantTarget(tenantId),
      );
      writeJson(response, 200, {
        schema: "dev.kernaid.fleet.asset-list.v1",
        tenantId,
        items: this.#store.listAssets(tenantId),
      });
      return;
    }

    const auditEventsMatch = /^\/v1\/tenants\/([^/]+)\/audit-events$/.exec(
      path,
    );
    if (method === "GET" && auditEventsMatch !== null) {
      const tenantId = pathIdentifier(auditEventsMatch[1], "tenantId");
      this.#authorizeTenant(
        request,
        tenantId,
        "operator",
        "device_audit.list",
        tenantTarget(tenantId),
      );
      writeJson(response, 200, {
        schema: "dev.kernaid.fleet.audit-event-list.v1",
        tenantId,
        items: this.#store.listAuditEvents(tenantId),
      });
      return;
    }

    const revokeMatch =
      /^\/v1\/tenants\/([^/]+)\/devices\/([^/]+)\/revoke$/.exec(path);
    if (method === "POST" && revokeMatch !== null) {
      const tenantId = pathIdentifier(revokeMatch[1], "tenantId");
      const deviceId = pathIdentifier(revokeMatch[2], "deviceId");
      this.#authorizeTenant(request, tenantId, "operator", "device.revoke", {
        type: "device",
        id: deviceId,
      });
      expectEmptyObject(await readJson(request));
      const revokedAt = this.#validNow().toISOString();
      if (!this.#store.revokeDevice(tenantId, deviceId, revokedAt)) {
        throw new HttpError(404, "not_found");
      }
      writeJson(response, 200, {
        schema: "dev.kernaid.fleet.device-revoked.v1",
        tenantId,
        deviceId,
        revokedAt,
      });
      return;
    }

    throw new HttpError(404, "not_found");
  }

  #authorizeRoot(request: IncomingMessage): void {
    const token = bearerToken(request);
    if (token === undefined || !secureSecretEqual(token, this.#rootToken)) {
      throw new HttpError(401, "not_authorized");
    }
  }

  #authorizeTenant(
    request: IncomingMessage,
    tenantId: string,
    requiredRole: TenantRole,
    action: TenantAccessAction,
    target: TenantAuthorizationTarget,
  ): TenantAccessCredential {
    const token = bearerToken(request);
    if (token === undefined) {
      throw new HttpError(401, "not_authorized");
    }
    const credential = this.#store.findTenantAccessCredential(
      hashSecret("admin", token),
    );
    if (credential === undefined) {
      throw new HttpError(401, "not_authorized");
    }
    const tenantMatches = credential.tenantId === tenantId;
    const active = credential.revokedAt === null;
    const roleAllowed = tenantRoleAllows(credential.role, requiredRole);
    this.#store.recordTenantAccessAudit({
      tenantId: credential.tenantId,
      occurredAt: this.#validNow().toISOString(),
      credentialId: credential.credentialId,
      role: credential.role,
      action,
      outcome: tenantMatches && active && roleAllowed ? "allowed" : "denied",
      targetTenantId: tenantId,
      targetType: target.type,
      targetId: target.id,
    });
    if (!tenantMatches || !active) {
      throw new HttpError(401, "not_authorized");
    }
    if (!roleAllowed) {
      throw new HttpError(403, "insufficient_role");
    }
    return credential;
  }

  #replayServiceResponse(
    response: ServerResponse,
    context: ServiceResponseContext,
  ): boolean {
    const retained = this.#store.getServiceResponse(context);
    if (retained === undefined) return false;
    this.#writeServiceResponse(response, context, retained);
    return true;
  }

  #commitServiceResponse(
    response: ServerResponse,
    context: ServiceResponseContext,
    status: 200 | 201,
    body: unknown,
    acceptedAt: Date,
    pullNonce?: ServicePullNonce,
  ): void {
    const responseBody = JSON.stringify(body);
    if (
      Buffer.byteLength(responseBody, "utf8") === 0 ||
      Buffer.byteLength(responseBody, "utf8") > MAX_SERVICE_RESPONSE_BYTES
    ) {
      throw new Error("Fleet service response exceeds its bound");
    }
    const responseSha256 = sha256Hex(responseBody);
    const acceptedAtText = acceptedAt.toISOString();
    const retained = this.#store.commitServiceResponse(
      {
        ...context,
        responseSha256,
        status,
        responseBody,
        createdAt: acceptedAtText,
        ...(pullNonce === undefined ? {} : { pullNonce }),
      },
      (sequence) => {
        const unsigned: ServiceReceiptUnsigned = {
          schema: FLEET_SERVICE_RECEIPT_SCHEMA,
          tenantId: context.tenantId,
          deviceId: context.deviceId,
          operation: context.operation,
          sequence,
          requestSha256: context.requestSha256,
          responseSha256,
          acceptedAt: acceptedAtText,
          outcome: "accepted",
        };
        const receipt: ServiceReceipt = {
          ...unsigned,
          signature: signEd25519(
            this.#serviceReceiptSigningKey,
            serviceReceiptSigningBytes(unsigned),
          ),
        };
        const receiptJson = canonicalJson(receipt);
        this.#verifyServiceReceipt(
          context,
          responseBody,
          receiptJson,
          sequence,
        );
        return receiptJson;
      },
    );
    this.#writeServiceResponse(response, context, retained);
  }

  #writeServiceResponse(
    response: ServerResponse,
    context: ServiceResponseContext,
    retained: StoredServiceResponse,
  ): void {
    this.#verifyServiceReceipt(
      context,
      retained.responseBody,
      retained.receiptJson,
      retained.sequence,
    );
    if (
      retained.tenantId !== context.tenantId ||
      retained.deviceId !== context.deviceId ||
      retained.operation !== context.operation ||
      retained.requestSha256 !== context.requestSha256 ||
      retained.responseSha256 !== sha256Hex(retained.responseBody)
    ) {
      throw new Error("stored Fleet service response binding is invalid");
    }
    const body = Buffer.from(retained.responseBody, "utf8");
    response.statusCode = retained.status;
    response.setHeader("Content-Type", "application/json; charset=utf-8");
    response.setHeader("Content-Length", body.length);
    response.setHeader(
      SERVICE_RECEIPT_HEADER,
      Buffer.from(retained.receiptJson, "utf8").toString("base64url"),
    );
    response.end(body);
  }

  #verifyServiceReceipt(
    context: ServiceResponseContext,
    responseBody: string,
    receiptJson: string,
    sequence: number,
  ): void {
    let receipt: ServiceReceipt;
    try {
      const parsed = JSON.parse(receiptJson) as unknown;
      receipt = parseServiceReceipt(parsed);
      if (canonicalJson(receipt) !== receiptJson) {
        throw new Error("receipt is not canonical");
      }
    } catch {
      throw new Error("Fleet service receipt is invalid");
    }
    if (
      receipt.tenantId !== context.tenantId ||
      receipt.deviceId !== context.deviceId ||
      receipt.operation !== context.operation ||
      receipt.sequence !== sequence ||
      receipt.requestSha256 !== context.requestSha256 ||
      receipt.responseSha256 !== sha256Hex(responseBody) ||
      !verifyEd25519(
        this.#serviceReceiptTrustAnchor,
        serviceReceiptSigningBytes(receipt),
        receipt.signature,
      )
    ) {
      throw new Error("Fleet service receipt verification failed");
    }
  }

  #isWorkOrderAuthorized(
    tenantId: string,
    deviceId: string,
    actionId: WorkOrderActionId,
    now: Date,
  ): boolean {
    const device = this.#store.getDevice(tenantId, deviceId);
    const action = workOrderActionCatalog[actionId];
    if (
      device === undefined ||
      device.revokedAt !== null ||
      !(action.platforms as readonly string[]).includes(device.platform)
    ) {
      return false;
    }

    const anchorSpki = this.#store.getPolicyTrustAnchor(tenantId);
    if (anchorSpki === undefined) return false;
    let policyAnchor;
    try {
      policyAnchor = importEd25519Spki(anchorSpki);
    } catch {
      throw new Error("stored policy trust anchor is invalid");
    }
    const nowUnix = Math.floor(now.getTime() / 1000);
    const policies = this.#store
      .listApplicablePolicyJson(tenantId, deviceId)
      .map((stored) => parseSignedPolicyBundle(JSON.parse(stored) as unknown))
      .filter((bundle) => {
        if (
          !verifyEd25519(
            policyAnchor,
            policyBundleSigningBytes(bundle),
            bundle.signature,
          )
        ) {
          throw new Error("stored policy signature is invalid");
        }
        return (
          bundle.notBeforeUnix <= nowUnix && nowUnix < bundle.expiresAtUnix
        );
      });
    if (
      policies.length === 0 ||
      policies.some((bundle) =>
        bundle.rules.deniedActionIds.includes(actionId),
      ) ||
      !policies.some(
        (bundle) =>
          bundle.rules.allowedActionIds.includes(actionId) &&
          policyRiskRank(action.risk) <= policyRiskRank(bundle.rules.maxRisk),
      )
    ) {
      return false;
    }

    const storedRevocations =
      this.#store.getEntitlementRevocationsJson(tenantId);
    const revokedIds = new Set<string>();
    if (storedRevocations !== undefined) {
      const revocations = parseEntitlementRevocationEnvelope(
        JSON.parse(storedRevocations) as unknown,
      );
      if (
        !verifyEd25519(
          this.#entitlementTrustAnchor,
          entitlementRevocationSigningBytes(revocations),
          revocations.signature,
        )
      ) {
        throw new Error("stored entitlement revocation signature is invalid");
      }
      for (const entitlementId of revocations.claims.revokedEntitlementIds) {
        revokedIds.add(entitlementId);
      }
    }
    return this.#store.listEntitlementJson(tenantId).some((stored) => {
      const envelope = parseEntitlementEnvelope(JSON.parse(stored) as unknown);
      if (
        !verifyEd25519(
          this.#entitlementTrustAnchor,
          entitlementSigningBytes(envelope),
          envelope.signature,
        )
      ) {
        throw new Error("stored entitlement signature is invalid");
      }
      const claims = envelope.claims;
      return (
        claims.tenantId === tenantId &&
        claims.deviceIds.includes(deviceId) &&
        !revokedIds.has(claims.entitlementId) &&
        claims.notBeforeUnix <= nowUnix &&
        nowUnix < claims.expiresAtUnix &&
        claims.features.includes("fleet") &&
        claims.features.includes(action.requiredFeature)
      );
    });
  }

  #validNow(): Date {
    const now = this.#now();
    if (!Number.isFinite(now.getTime()))
      throw new Error("clock returned invalid time");
    return now;
  }

  #serveConsoleAsset(path: string, response: ServerResponse): void {
    if (this.#consoleDirectory === undefined) {
      throw new HttpError(404, "not_found");
    }
    let suffix: string;
    try {
      suffix = decodeURIComponent(path.slice("/console/".length));
    } catch {
      throw new HttpError(400, "invalid_request");
    }
    if (suffix === "") suffix = "index.html";
    if (
      suffix.includes("\\") ||
      suffix.includes("\0") ||
      suffix
        .split("/")
        .some((part) => part === "" || part === "." || part === "..")
    ) {
      throw new HttpError(404, "not_found");
    }

    const candidate = resolve(this.#consoleDirectory, suffix);
    const location = relative(this.#consoleDirectory, candidate);
    if (location.startsWith(`..${sep}`) || location === "..") {
      throw new HttpError(404, "not_found");
    }

    let realCandidate: string;
    try {
      realCandidate = realpathSync(candidate);
      const entry = lstatSync(realCandidate);
      const realLocation = relative(this.#consoleDirectory, realCandidate);
      if (
        !entry.isFile() ||
        realLocation.startsWith(`..${sep}`) ||
        realLocation === ".." ||
        entry.size > 10 * 1024 * 1024
      ) {
        throw new HttpError(404, "not_found");
      }
    } catch (error) {
      if (error instanceof HttpError) throw error;
      throw new HttpError(404, "not_found");
    }

    const body = readFileSync(realCandidate);
    response.statusCode = 200;
    response.setHeader("Content-Type", consoleMimeType(extname(realCandidate)));
    response.setHeader("Content-Length", body.length);
    response.setHeader(
      "Content-Security-Policy",
      "default-src 'self'; style-src 'self'; script-src 'self'; img-src 'self' data:; connect-src 'self'; object-src 'none'; frame-ancestors 'none'; base-uri 'none'",
    );
    response.end(body);
  }
}

function tenantWorkOrder(workOrder: StoredWorkOrder): Record<string, unknown> {
  return {
    tenantId: workOrder.tenantId,
    workOrderId: workOrder.workOrderId,
    requestId: workOrder.requestId,
    targetDeviceId: workOrder.targetDeviceId,
    actionId: workOrder.actionId,
    actionVersion: workOrder.actionVersion,
    kind: workOrder.kind,
    risk: workOrder.risk,
    localApprovalRequired: workOrder.localApprovalRequired,
    status: workOrder.status,
    createdByCredentialId: workOrder.createdByCredentialId,
    createdAt: workOrder.createdAt,
    expiresAt: workOrder.expiresAt,
    approval:
      workOrder.approvedAt === null
        ? null
        : {
            approvedByCredentialId: workOrder.approvedByCredentialId,
            approvedAt: workOrder.approvedAt,
          },
    lease:
      workOrder.leaseId === null
        ? null
        : {
            leaseId: workOrder.leaseId,
            leasedAt: workOrder.leasedAt,
            leaseExpiresAt: workOrder.leaseExpiresAt,
          },
    result:
      workOrder.outcome === null
        ? null
        : {
            outcome: workOrder.outcome,
            resultSha256: workOrder.resultSha256,
            completedAt: workOrder.completedAt,
          },
    cancellation:
      workOrder.cancelledAt === null
        ? null
        : {
            cancelledByCredentialId: workOrder.cancelledByCredentialId,
            cancelledAt: workOrder.cancelledAt,
          },
  };
}

function deviceWorkOrder(workOrder: StoredWorkOrder): Record<string, unknown> {
  if (
    workOrder.status !== "leased" ||
    workOrder.leaseId === null ||
    workOrder.leasedAt === null ||
    workOrder.leaseExpiresAt === null
  ) {
    throw new Error("device work order does not contain an active lease");
  }
  if (
    workOrder.localApprovalRequired &&
    (workOrder.approvedAt === null || workOrder.approvedByCredentialId === null)
  ) {
    throw new Error("write work order lacks tenant approval proof");
  }
  return {
    workOrderId: workOrder.workOrderId,
    targetDeviceId: workOrder.targetDeviceId,
    actionId: workOrder.actionId,
    actionVersion: workOrder.actionVersion,
    kind: workOrder.kind,
    risk: workOrder.risk,
    localApprovalRequired: workOrder.localApprovalRequired,
    status: workOrder.status,
    createdAt: workOrder.createdAt,
    expiresAt: workOrder.expiresAt,
    approval:
      workOrder.approvedAt === null
        ? null
        : {
            approvedByCredentialId: workOrder.approvedByCredentialId,
            approvedAt: workOrder.approvedAt,
          },
    lease: {
      leaseId: workOrder.leaseId,
      leasedAt: workOrder.leasedAt,
      leaseExpiresAt: workOrder.leaseExpiresAt,
    },
  };
}

function policyRiskRank(risk: "R0" | "R1" | "R2" | "R3"): number {
  return { R0: 0, R1: 1, R2: 2, R3: 3 }[risk];
}

class HttpError extends Error {
  constructor(
    readonly status: number,
    readonly code: string,
  ) {
    super(code);
  }
}

function bearerToken(request: IncomingMessage): string | undefined {
  const authorization = request.headers.authorization;
  if (authorization === undefined) return undefined;
  const match = /^Bearer ([A-Za-z0-9_-]{32,512})$/.exec(authorization);
  return match?.[1];
}

async function readJson(request: IncomingMessage): Promise<unknown> {
  return (await readJsonRequest(request)).value;
}

async function readJsonRequest(
  request: IncomingMessage,
): Promise<{ value: unknown; bytes: Buffer }> {
  const bytes = await readJsonBytes(request, MAX_REQUEST_BYTES);
  return { value: parseJsonBytes(bytes), bytes };
}

async function readCanonicalJson(
  request: IncomingMessage,
  maximumBytes = MAX_REQUEST_BYTES,
): Promise<unknown> {
  return (await readCanonicalJsonRequest(request, maximumBytes)).value;
}

async function readCanonicalJsonRequest(
  request: IncomingMessage,
  maximumBytes = MAX_REQUEST_BYTES,
): Promise<{ value: unknown; bytes: Buffer }> {
  const bytes = await readJsonBytes(request, maximumBytes);
  const value = parseJsonBytes(bytes);
  const text = bytes.toString("utf8");
  try {
    if (
      !Buffer.from(text, "utf8").equals(bytes) ||
      canonicalJson(value) !== text
    ) {
      throw new HttpError(400, "noncanonical_json");
    }
  } catch (error) {
    if (error instanceof HttpError) throw error;
    throw new HttpError(400, "invalid_json");
  }
  return { value, bytes };
}

async function readJsonBytes(
  request: IncomingMessage,
  maximumBytes: number,
): Promise<Buffer> {
  const contentType = request.headers["content-type"];
  if (
    contentType === undefined ||
    !/^application\/json(?:\s*;|$)/i.test(contentType)
  ) {
    throw new HttpError(415, "json_content_type_required");
  }

  const declaredLength = request.headers["content-length"];
  if (declaredLength !== undefined) {
    const length = Number(declaredLength);
    if (!Number.isSafeInteger(length) || length < 0 || length > maximumBytes) {
      throw new HttpError(413, "request_too_large");
    }
  }

  const chunks: Buffer[] = [];
  let total = 0;
  for await (const chunk of request) {
    const bytes = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk);
    total += bytes.length;
    if (total > maximumBytes) throw new HttpError(413, "request_too_large");
    chunks.push(bytes);
  }
  return Buffer.concat(chunks);
}

function parseJsonBytes(bytes: Buffer): unknown {
  try {
    return JSON.parse(bytes.toString("utf8")) as unknown;
  } catch {
    throw new HttpError(400, "invalid_json");
  }
}

function expectEmptyObject(value: unknown): void {
  const object = expectRecord(value);
  expectExactKeys(object, []);
}

function pathIdentifier(value: string | undefined, field: string): string {
  if (value === undefined) throw new HttpError(404, "not_found");
  let decoded: string;
  try {
    decoded = decodeURIComponent(value);
  } catch {
    throw new HttpError(400, "invalid_request");
  }
  return expectIdentifier(decoded, field);
}

function tenantTarget(tenantId: string): TenantAuthorizationTarget {
  return { type: "tenant", id: tenantId };
}

function publicTenantAccessCredential(
  credential: TenantAccessCredential,
): Record<string, unknown> {
  return {
    tenantId: credential.tenantId,
    credentialId: credential.credentialId,
    role: credential.role,
    label: credential.label,
    createdAt: credential.createdAt,
    revokedAt: credential.revokedAt,
    status: credential.revokedAt === null ? "active" : "revoked",
  };
}

function serviceResponseContext(
  operation: FleetServiceOperation,
  tenantId: string,
  deviceId: string,
  requestBytes: Uint8Array,
): ServiceResponseContext {
  return {
    operation,
    tenantId,
    deviceId,
    requestSha256: sha256Hex(requestBytes),
  };
}

function writeJson(
  response: ServerResponse,
  status: number,
  body: unknown,
): void {
  const serialized = JSON.stringify(body);
  response.statusCode = status;
  response.setHeader("Content-Type", "application/json; charset=utf-8");
  response.setHeader("Content-Length", Buffer.byteLength(serialized));
  response.end(serialized);
}

function resolveConsoleDirectory(
  directory: string | undefined,
): string | undefined {
  if (directory === undefined) return undefined;
  const realDirectory = realpathSync(directory);
  if (!lstatSync(realDirectory).isDirectory()) {
    throw new Error("FLEET_CONSOLE_DIR must be a directory");
  }
  return realDirectory;
}

function consoleMimeType(extension: string): string {
  switch (extension.toLowerCase()) {
    case ".html":
      return "text/html; charset=utf-8";
    case ".css":
      return "text/css; charset=utf-8";
    case ".js":
    case ".mjs":
      return "text/javascript; charset=utf-8";
    case ".json":
      return "application/json; charset=utf-8";
    case ".svg":
      return "image/svg+xml";
    case ".png":
      return "image/png";
    case ".webp":
      return "image/webp";
    case ".ico":
      return "image/x-icon";
    default:
      return "application/octet-stream";
  }
}
