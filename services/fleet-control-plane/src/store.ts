import { chmodSync, lstatSync } from "node:fs";
import { DatabaseSync } from "node:sqlite";
import type {
  AuditEnvelope,
  AuditKind,
  AuditOutcome,
  AuditRisk,
  EnrollmentPlatform,
  FleetInventoryAsset,
  InventoryEnvelope,
  SignedPolicyBundle,
  EntitlementEnvelope,
  EntitlementRevocationEnvelope,
  SignedUpdateManifest,
} from "@kernaid/fleet-schemas";
import { canonicalJson } from "@kernaid/fleet-schemas";

const MAX_POLICY_STREAMS_PER_TENANT = 256;
const MAX_RECENT_POLICY_PULL_NONCES_PER_DEVICE = 1024;
const MAX_ENTITLEMENT_STREAMS_PER_TENANT = 256;
const MAX_RECENT_ENTITLEMENT_PULL_NONCES_PER_DEVICE = 1024;
const MAX_RECENT_UPDATE_PULL_NONCES_PER_DEVICE = 1024;

export class StoreConflictError extends Error {}
export class StoreAuthorizationError extends Error {}
export class StoreRevokedError extends Error {}
export class StoreReplayError extends Error {}
export class StoreSequenceGapError extends Error {}
export class StoreChainForkError extends Error {}
export class StorePolicyRollbackError extends Error {}
export class StorePolicyConflictError extends Error {}
export class StoreNonceReplayError extends Error {}
export class StoreEntitlementRollbackError extends Error {}
export class StoreEntitlementConflictError extends Error {}
export class StoreEntitlementPullReplayError extends Error {}
export class StoreUpdateRollbackError extends Error {}
export class StoreUpdateConflictError extends Error {}
export class StoreUpdatePullReplayError extends Error {}

interface EnrollmentTokenRow {
  tenant_id: string;
  expires_at_ms: number;
  used_at: string | null;
}

export interface StoredDevice {
  tenantId: string;
  deviceId: string;
  publicKeySpki: string;
  platform: EnrollmentPlatform;
  agentVersion: string;
  enrolledAt: string;
  revokedAt: string | null;
  lastSequence: number;
  lastSeenAt: string | null;
}

export interface ListedAsset extends FleetInventoryAsset {
  deviceId: string;
  sequence: number;
  observedAt: string;
  updatedAt: string;
}

export interface InventoryRecordResult {
  idempotent: boolean;
}

export interface AuditRecordResult {
  idempotent: boolean;
}

export interface PolicyPublishResult {
  idempotent: boolean;
  publishedAt: string;
}

export interface EntitlementPublishResult {
  idempotent: boolean;
}

export interface UpdatePublishResult {
  idempotent: boolean;
  publishedAt: string;
}

export interface ListedAuditEvent {
  tenantId: string;
  deviceId: string;
  sessionId: string;
  eventId: string;
  sequence: number;
  previousEventSha256: string | null;
  eventSha256: string;
  occurredAt: string;
  receivedAt: string;
  kind: AuditKind;
  outcome: AuditOutcome;
  risk: AuditRisk | null;
  actionId: string | null;
  targetSha256: string | null;
  reportSha256: string | null;
  evidenceSha256: string[];
}

export class FleetStore {
  readonly #database: DatabaseSync;

  constructor(path: string) {
    if (path !== ":memory:") {
      try {
        const entry = lstatSync(path);
        if (!entry.isFile() || entry.isSymbolicLink()) {
          throw new Error("Fleet database path must be a regular file");
        }
      } catch (error) {
        if ((error as NodeJS.ErrnoException).code !== "ENOENT") throw error;
      }
    }

    this.#database = new DatabaseSync(path);
    this.#database.exec("PRAGMA foreign_keys = ON");
    this.#database.exec("PRAGMA busy_timeout = 5000");
    if (path !== ":memory:") {
      chmodSync(path, 0o600);
      this.#database.exec("PRAGMA journal_mode = WAL");
    }
    this.#migrate();
  }

  close(): void {
    this.#database.close();
  }

  healthCheck(): void {
    this.#database.prepare("SELECT 1 AS healthy").get();
  }

  createTenant(
    tenantId: string,
    adminTokenHash: string,
    createdAt: string,
  ): void {
    this.#database
      .prepare(
        "INSERT INTO tenants (tenant_id, admin_token_hash, created_at) VALUES (?, ?, ?)",
      )
      .run(tenantId, adminTokenHash, createdAt);
  }

  authenticateTenant(tenantId: string, adminTokenHash: string): boolean {
    return (
      this.#database
        .prepare(
          "SELECT 1 AS allowed FROM tenants WHERE tenant_id = ? AND admin_token_hash = ?",
        )
        .get(tenantId, adminTokenHash) !== undefined
    );
  }

  setPolicyTrustAnchor(
    tenantId: string,
    publicKeySpki: string,
    setAt: string,
  ): void {
    try {
      this.#database
        .prepare(
          `INSERT INTO tenant_policy_anchors
            (tenant_id, public_key_spki, set_at)
           VALUES (?, ?, ?)`,
        )
        .run(tenantId, publicKeySpki, setAt);
    } catch (error) {
      if (isSqliteConstraint(error)) {
        throw new StoreConflictError("policy trust anchor is already set");
      }
      throw error;
    }
  }

  getPolicyTrustAnchor(tenantId: string): string | undefined {
    const row = this.#database
      .prepare(
        `SELECT public_key_spki FROM tenant_policy_anchors
         WHERE tenant_id = ?`,
      )
      .get(tenantId) as { public_key_spki: string } | undefined;
    return row?.public_key_spki;
  }

  publishPolicy(
    bundle: SignedPolicyBundle,
    bundleJson: string,
    bundleSha256: string,
    publishedAt: string,
  ): PolicyPublishResult {
    return this.#transaction(() => {
      const current = this.#database
        .prepare(
          `SELECT revision, bundle_sha256, published_at FROM policy_bundles
           WHERE tenant_id = ? AND policy_id = ?`,
        )
        .get(bundle.tenantId, bundle.policyId) as
        | { revision: number; bundle_sha256: string; published_at: string }
        | undefined;
      if (current !== undefined) {
        if (bundle.revision < current.revision) {
          throw new StorePolicyRollbackError("policy revision rollback");
        }
        if (bundle.revision === current.revision) {
          if (bundleSha256 === current.bundle_sha256) {
            return { idempotent: true, publishedAt: current.published_at };
          }
          throw new StorePolicyConflictError("policy revision conflict");
        }
      }
      if (current === undefined) {
        const count = this.#database
          .prepare(
            `SELECT COUNT(*) AS count FROM policy_bundles
             WHERE tenant_id = ?`,
          )
          .get(bundle.tenantId) as { count: number };
        if (count.count >= MAX_POLICY_STREAMS_PER_TENANT) {
          throw new StoreConflictError("tenant policy stream limit reached");
        }
      }

      const appliesAll = "all" in bundle.assignments ? 1 : 0;
      this.#database
        .prepare(
          `INSERT INTO policy_bundles
            (tenant_id, policy_id, revision, bundle_sha256, bundle_json,
             applies_all, published_at)
           VALUES (?, ?, ?, ?, ?, ?, ?)
           ON CONFLICT (tenant_id, policy_id) DO UPDATE SET
             revision = excluded.revision,
             bundle_sha256 = excluded.bundle_sha256,
             bundle_json = excluded.bundle_json,
             applies_all = excluded.applies_all,
             published_at = excluded.published_at`,
        )
        .run(
          bundle.tenantId,
          bundle.policyId,
          bundle.revision,
          bundleSha256,
          bundleJson,
          appliesAll,
          publishedAt,
        );
      this.#database
        .prepare(
          `DELETE FROM policy_assignments
           WHERE tenant_id = ? AND policy_id = ?`,
        )
        .run(bundle.tenantId, bundle.policyId);
      if ("deviceIds" in bundle.assignments) {
        const insert = this.#database.prepare(
          `INSERT INTO policy_assignments
            (tenant_id, policy_id, device_id) VALUES (?, ?, ?)`,
        );
        for (const deviceId of bundle.assignments.deviceIds) {
          insert.run(bundle.tenantId, bundle.policyId, deviceId);
        }
      }
      return { idempotent: false, publishedAt };
    });
  }

  recordPolicyPullNonce(input: {
    tenantId: string;
    deviceId: string;
    nonceSha256: string;
    expiresAtMs: number;
    nowMs: number;
  }): void {
    this.#transaction(() => {
      this.#database
        .prepare("DELETE FROM policy_pull_nonces WHERE expires_at_ms <= ?")
        .run(input.nowMs);
      const recent = this.#database
        .prepare(
          `SELECT COUNT(*) AS count FROM policy_pull_nonces
           WHERE tenant_id = ? AND device_id = ?`,
        )
        .get(input.tenantId, input.deviceId) as { count: number };
      if (recent.count >= MAX_RECENT_POLICY_PULL_NONCES_PER_DEVICE) {
        throw new StoreConflictError("recent policy pull limit reached");
      }
      try {
        this.#database
          .prepare(
            `INSERT INTO policy_pull_nonces
              (tenant_id, device_id, nonce_sha256, expires_at_ms)
             VALUES (?, ?, ?, ?)`,
          )
          .run(
            input.tenantId,
            input.deviceId,
            input.nonceSha256,
            input.expiresAtMs,
          );
      } catch (error) {
        if (isSqliteConstraint(error)) {
          throw new StoreNonceReplayError("policy pull nonce was reused");
        }
        throw error;
      }
    });
  }

  listApplicablePolicyJson(tenantId: string, deviceId: string): string[] {
    const rows = this.#database
      .prepare(
        `SELECT policy.bundle_json
         FROM policy_bundles AS policy
         WHERE policy.tenant_id = ?
           AND (policy.applies_all = 1 OR EXISTS (
             SELECT 1 FROM policy_assignments AS assignment
             WHERE assignment.tenant_id = policy.tenant_id
               AND assignment.policy_id = policy.policy_id
               AND assignment.device_id = ?
           ))
         ORDER BY policy.policy_id
         LIMIT 256`,
      )
      .all(tenantId, deviceId) as unknown as { bundle_json: string }[];
    return rows.map((row) => row.bundle_json);
  }

  listPolicyJson(tenantId: string): string[] {
    const rows = this.#database
      .prepare(
        `SELECT bundle_json FROM policy_bundles
         WHERE tenant_id = ? ORDER BY policy_id LIMIT 256`,
      )
      .all(tenantId) as unknown as { bundle_json: string }[];
    return rows.map((row) => row.bundle_json);
  }

  publishEntitlement(
    tenantId: string,
    envelope: EntitlementEnvelope,
    canonicalJson: string,
    envelopeSha256: string,
  ): EntitlementPublishResult {
    return this.#transaction(() => {
      const current = this.#database
        .prepare(
          `SELECT highest_sequence, envelope_sha256
           FROM entitlement_documents
           WHERE tenant_id = ? AND entitlement_id = ?`,
        )
        .get(tenantId, envelope.claims.entitlementId) as
        { highest_sequence: number; envelope_sha256: string } | undefined;
      if (current !== undefined) {
        if (envelope.claims.sequence < current.highest_sequence) {
          throw new StoreEntitlementRollbackError(
            "entitlement sequence rollback",
          );
        }
        if (envelope.claims.sequence === current.highest_sequence) {
          if (envelopeSha256 === current.envelope_sha256) {
            return { idempotent: true };
          }
          throw new StoreEntitlementConflictError(
            "entitlement sequence conflict",
          );
        }
      } else {
        const count = this.#database
          .prepare(
            `SELECT COUNT(*) AS count FROM entitlement_documents
             WHERE tenant_id = ?`,
          )
          .get(tenantId) as { count: number };
        if (count.count >= MAX_ENTITLEMENT_STREAMS_PER_TENANT) {
          throw new StoreConflictError(
            "tenant entitlement stream limit reached",
          );
        }
      }
      this.#database
        .prepare(
          `INSERT INTO entitlement_documents
            (tenant_id, entitlement_id, highest_sequence, envelope_sha256,
             canonical_json)
           VALUES (?, ?, ?, ?, ?)
           ON CONFLICT (tenant_id, entitlement_id) DO UPDATE SET
             highest_sequence = excluded.highest_sequence,
             envelope_sha256 = excluded.envelope_sha256,
             canonical_json = excluded.canonical_json`,
        )
        .run(
          tenantId,
          envelope.claims.entitlementId,
          envelope.claims.sequence,
          envelopeSha256,
          canonicalJson,
        );
      return { idempotent: false };
    });
  }

  publishEntitlementRevocations(
    tenantId: string,
    envelope: EntitlementRevocationEnvelope,
    canonicalJson: string,
    envelopeSha256: string,
  ): EntitlementPublishResult {
    return this.#transaction(() => {
      const current = this.#database
        .prepare(
          `SELECT highest_sequence, envelope_sha256
           FROM entitlement_revocations WHERE tenant_id = ?`,
        )
        .get(tenantId) as
        { highest_sequence: number; envelope_sha256: string } | undefined;
      if (current !== undefined) {
        if (envelope.claims.sequence < current.highest_sequence) {
          throw new StoreEntitlementRollbackError(
            "revocation sequence rollback",
          );
        }
        if (envelope.claims.sequence === current.highest_sequence) {
          if (envelopeSha256 === current.envelope_sha256) {
            return { idempotent: true };
          }
          throw new StoreEntitlementConflictError(
            "revocation sequence conflict",
          );
        }
      }
      this.#database
        .prepare(
          `INSERT INTO entitlement_revocations
            (tenant_id, highest_sequence, envelope_sha256, canonical_json)
           VALUES (?, ?, ?, ?)
           ON CONFLICT (tenant_id) DO UPDATE SET
             highest_sequence = excluded.highest_sequence,
             envelope_sha256 = excluded.envelope_sha256,
             canonical_json = excluded.canonical_json`,
        )
        .run(tenantId, envelope.claims.sequence, envelopeSha256, canonicalJson);
      return { idempotent: false };
    });
  }

  listEntitlementJson(tenantId: string): string[] {
    const rows = this.#database
      .prepare(
        `SELECT canonical_json FROM entitlement_documents
         WHERE tenant_id = ? ORDER BY entitlement_id LIMIT 256`,
      )
      .all(tenantId) as unknown as { canonical_json: string }[];
    return rows.map((row) => row.canonical_json);
  }

  getEntitlementRevocationsJson(tenantId: string): string | undefined {
    const row = this.#database
      .prepare(
        `SELECT canonical_json FROM entitlement_revocations
         WHERE tenant_id = ?`,
      )
      .get(tenantId) as { canonical_json: string } | undefined;
    return row?.canonical_json;
  }

  recordEntitlementPullNonce(input: {
    tenantId: string;
    deviceId: string;
    nonceSha256: string;
    expiresAtMs: number;
    nowMs: number;
  }): void {
    this.#transaction(() => {
      this.#database
        .prepare("DELETE FROM entitlement_pull_nonces WHERE expires_at_ms <= ?")
        .run(input.nowMs);
      const recent = this.#database
        .prepare(
          `SELECT COUNT(*) AS count FROM entitlement_pull_nonces
           WHERE tenant_id = ? AND device_id = ?`,
        )
        .get(input.tenantId, input.deviceId) as { count: number };
      if (recent.count >= MAX_RECENT_ENTITLEMENT_PULL_NONCES_PER_DEVICE) {
        throw new StoreConflictError("recent entitlement pull limit reached");
      }
      try {
        this.#database
          .prepare(
            `INSERT INTO entitlement_pull_nonces
              (tenant_id, device_id, nonce_sha256, expires_at_ms)
             VALUES (?, ?, ?, ?)`,
          )
          .run(
            input.tenantId,
            input.deviceId,
            input.nonceSha256,
            input.expiresAtMs,
          );
      } catch (error) {
        if (isSqliteConstraint(error)) {
          throw new StoreEntitlementPullReplayError(
            "entitlement pull nonce was reused",
          );
        }
        throw error;
      }
    });
  }

  publishUpdateManifest(
    tenantId: string,
    manifest: SignedUpdateManifest,
    canonicalManifest: string,
    manifestSha256: string,
    publishedAt: string,
  ): UpdatePublishResult {
    return this.#transaction(() => {
      const current = this.#database
        .prepare(
          `SELECT highest_sequence, manifest_sha256, published_at
           FROM tenant_update_checkpoints WHERE tenant_id = ?`,
        )
        .get(tenantId) as
        | {
            highest_sequence: number;
            manifest_sha256: string;
            published_at: string;
          }
        | undefined;
      if (current !== undefined) {
        if (manifest.sequence < current.highest_sequence) {
          throw new StoreUpdateRollbackError("update sequence rollback");
        }
        if (manifest.sequence === current.highest_sequence) {
          if (manifestSha256 === current.manifest_sha256) {
            return { idempotent: true, publishedAt: current.published_at };
          }
          throw new StoreUpdateConflictError("update sequence conflict");
        }
      }

      this.#database
        .prepare(
          `INSERT INTO update_manifests
            (tenant_id, platform, architecture, release_ring, sequence,
             manifest_sha256, canonical_json, published_at)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?)
           ON CONFLICT (tenant_id, platform, architecture, release_ring)
           DO UPDATE SET
             sequence = excluded.sequence,
             manifest_sha256 = excluded.manifest_sha256,
             canonical_json = excluded.canonical_json,
             published_at = excluded.published_at`,
        )
        .run(
          tenantId,
          manifest.platform,
          manifest.architecture,
          manifest.releaseRing,
          manifest.sequence,
          manifestSha256,
          canonicalManifest,
          publishedAt,
        );
      this.#database
        .prepare(
          `INSERT INTO tenant_update_checkpoints
            (tenant_id, highest_sequence, manifest_sha256, published_at)
           VALUES (?, ?, ?, ?)
           ON CONFLICT (tenant_id) DO UPDATE SET
             highest_sequence = excluded.highest_sequence,
             manifest_sha256 = excluded.manifest_sha256,
             published_at = excluded.published_at`,
        )
        .run(tenantId, manifest.sequence, manifestSha256, publishedAt);
      return { idempotent: false, publishedAt };
    });
  }

  listUpdateManifestJson(
    tenantId: string,
    platform: string,
    architecture: string,
  ): string[] {
    const rows = this.#database
      .prepare(
        `SELECT canonical_json FROM update_manifests
         WHERE tenant_id = ? AND platform = ? AND architecture = ?
         ORDER BY sequence DESC, release_ring
         LIMIT 2`,
      )
      .all(tenantId, platform, architecture) as unknown as {
      canonical_json: string;
    }[];
    return rows.map((row) => row.canonical_json);
  }

  listAllUpdateManifestJson(tenantId: string): string[] {
    const rows = this.#database
      .prepare(
        `SELECT canonical_json FROM update_manifests
         WHERE tenant_id = ?
         ORDER BY platform, architecture, release_ring
         LIMIT 16`,
      )
      .all(tenantId) as unknown as { canonical_json: string }[];
    return rows.map((row) => row.canonical_json);
  }

  recordUpdatePullNonce(input: {
    tenantId: string;
    deviceId: string;
    nonceSha256: string;
    expiresAtMs: number;
    nowMs: number;
  }): void {
    this.#transaction(() => {
      this.#database
        .prepare("DELETE FROM update_pull_nonces WHERE expires_at_ms <= ?")
        .run(input.nowMs);
      const recent = this.#database
        .prepare(
          `SELECT COUNT(*) AS count FROM update_pull_nonces
           WHERE tenant_id = ? AND device_id = ?`,
        )
        .get(input.tenantId, input.deviceId) as { count: number };
      if (recent.count >= MAX_RECENT_UPDATE_PULL_NONCES_PER_DEVICE) {
        throw new StoreConflictError("recent update pull limit reached");
      }
      try {
        this.#database
          .prepare(
            `INSERT INTO update_pull_nonces
              (tenant_id, device_id, nonce_sha256, expires_at_ms)
             VALUES (?, ?, ?, ?)`,
          )
          .run(
            input.tenantId,
            input.deviceId,
            input.nonceSha256,
            input.expiresAtMs,
          );
      } catch (error) {
        if (isSqliteConstraint(error)) {
          throw new StoreUpdatePullReplayError("update pull nonce was reused");
        }
        throw error;
      }
    });
  }

  createEnrollmentToken(input: {
    tokenHash: string;
    tenantId: string;
    createdAt: string;
    expiresAtMs: number;
  }): void {
    this.#database
      .prepare(
        `INSERT INTO enrollment_tokens
          (token_hash, tenant_id, created_at, expires_at_ms, used_at)
         VALUES (?, ?, ?, ?, NULL)`,
      )
      .run(input.tokenHash, input.tenantId, input.createdAt, input.expiresAtMs);
  }

  isEnrollmentTokenUsable(
    tokenHash: string,
    tenantId: string,
    nowMs: number,
  ): boolean {
    return (
      this.#database
        .prepare(
          `SELECT 1 AS usable FROM enrollment_tokens
           WHERE token_hash = ? AND tenant_id = ? AND used_at IS NULL
             AND expires_at_ms > ?`,
        )
        .get(tokenHash, tenantId, nowMs) !== undefined
    );
  }

  enrollDevice(input: {
    tokenHash: string;
    tenantId: string;
    deviceId: string;
    publicKeySpki: string;
    platform: EnrollmentPlatform;
    agentVersion: string;
    enrolledAt: string;
    nowMs: number;
  }): void {
    this.#transaction(() => {
      const token = this.#database
        .prepare(
          `SELECT tenant_id, expires_at_ms, used_at FROM enrollment_tokens
           WHERE token_hash = ?`,
        )
        .get(input.tokenHash) as EnrollmentTokenRow | undefined;
      if (
        token === undefined ||
        token.tenant_id !== input.tenantId ||
        token.used_at !== null ||
        token.expires_at_ms <= input.nowMs
      ) {
        throw new StoreAuthorizationError("enrollment token is not usable");
      }

      try {
        this.#database
          .prepare(
            `INSERT INTO devices
              (tenant_id, device_id, public_key_spki, platform, agent_version,
               enrolled_at, revoked_at, last_sequence, last_envelope_hash, last_seen_at)
             VALUES (?, ?, ?, ?, ?, ?, NULL, 0, NULL, NULL)`,
          )
          .run(
            input.tenantId,
            input.deviceId,
            input.publicKeySpki,
            input.platform,
            input.agentVersion,
            input.enrolledAt,
          );
      } catch (error) {
        if (isSqliteConstraint(error)) {
          throw new StoreConflictError("device is already enrolled");
        }
        throw error;
      }

      const consumed = this.#database
        .prepare(
          `UPDATE enrollment_tokens SET used_at = ?
           WHERE token_hash = ? AND used_at IS NULL AND expires_at_ms > ?`,
        )
        .run(input.enrolledAt, input.tokenHash, input.nowMs);
      if (consumed.changes !== 1) {
        throw new StoreAuthorizationError(
          "enrollment token was already consumed",
        );
      }
    });
  }

  getDevice(tenantId: string, deviceId: string): StoredDevice | undefined {
    const row = this.#database
      .prepare(
        `SELECT tenant_id, device_id, public_key_spki, platform, agent_version,
                enrolled_at, revoked_at, last_sequence, last_seen_at
         FROM devices WHERE tenant_id = ? AND device_id = ?`,
      )
      .get(tenantId, deviceId) as DeviceRow | undefined;
    return row === undefined ? undefined : mapDevice(row);
  }

  recordInventory(
    envelope: InventoryEnvelope,
    envelopeHash: string,
    receivedAt: string,
  ): InventoryRecordResult {
    return this.#transaction(() => {
      const row = this.#database
        .prepare(
          `SELECT tenant_id, device_id, public_key_spki, platform, agent_version,
                  enrolled_at, revoked_at, last_sequence, last_envelope_hash,
                  last_seen_at
           FROM devices WHERE tenant_id = ? AND device_id = ?`,
        )
        .get(envelope.tenantId, envelope.deviceId) as
        (DeviceRow & { last_envelope_hash: string | null }) | undefined;
      if (row === undefined)
        throw new StoreAuthorizationError("device is unknown");
      if (row.revoked_at !== null)
        throw new StoreRevokedError("device is revoked");

      if (envelope.sequence === row.last_sequence) {
        if (row.last_envelope_hash === envelopeHash)
          return { idempotent: true };
        throw new StoreReplayError(
          "sequence already contains a different envelope",
        );
      }
      if (envelope.sequence < row.last_sequence) {
        throw new StoreReplayError("sequence has already been superseded");
      }

      const canonicalEnvelope = canonicalJson(envelope);
      this.#database
        .prepare(
          `INSERT INTO inventory_events
            (tenant_id, device_id, sequence, envelope_hash, envelope_json,
             asset_id, observed_at, received_at)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
        )
        .run(
          envelope.tenantId,
          envelope.deviceId,
          envelope.sequence,
          envelopeHash,
          canonicalEnvelope,
          envelope.asset.assetId,
          envelope.observedAt,
          receivedAt,
        );

      const asset = envelope.asset;
      const currentAsset = this.#database
        .prepare(
          `SELECT reporting_device_id, sequence, observed_at
           FROM assets WHERE tenant_id = ? AND asset_id = ?`,
        )
        .get(envelope.tenantId, asset.assetId) as
        CurrentAssetVersionRow | undefined;
      if (shouldReplaceCurrentAsset(envelope, currentAsset)) {
        this.#database
          .prepare(
            `INSERT INTO assets
            (tenant_id, asset_id, reporting_device_id, target_fingerprint,
             platform, architecture, os_release, health, critical_count,
             warning_count, info_count, snapshot_sha256, sequence, observed_at,
             updated_at)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
           ON CONFLICT (tenant_id, asset_id) DO UPDATE SET
             reporting_device_id = excluded.reporting_device_id,
             target_fingerprint = excluded.target_fingerprint,
             platform = excluded.platform,
             architecture = excluded.architecture,
             os_release = excluded.os_release,
             health = excluded.health,
             critical_count = excluded.critical_count,
             warning_count = excluded.warning_count,
             info_count = excluded.info_count,
             snapshot_sha256 = excluded.snapshot_sha256,
             sequence = excluded.sequence,
             observed_at = excluded.observed_at,
             updated_at = excluded.updated_at`,
          )
          .run(
            envelope.tenantId,
            asset.assetId,
            envelope.deviceId,
            asset.targetFingerprint,
            asset.platform,
            asset.architecture,
            asset.osRelease,
            asset.health,
            asset.findingCounts.critical,
            asset.findingCounts.warning,
            asset.findingCounts.info,
            asset.snapshotSha256,
            envelope.sequence,
            envelope.observedAt,
            receivedAt,
          );
      }

      this.#database
        .prepare(
          `UPDATE devices
           SET last_sequence = ?, last_envelope_hash = ?, last_seen_at = ?
           WHERE tenant_id = ? AND device_id = ?`,
        )
        .run(
          envelope.sequence,
          envelopeHash,
          receivedAt,
          envelope.tenantId,
          envelope.deviceId,
        );
      return { idempotent: false };
    });
  }

  recordAuditEvent(
    envelope: AuditEnvelope,
    eventSha256: string,
    receivedAt: string,
  ): AuditRecordResult {
    return this.#transaction(() => {
      const device = this.#database
        .prepare(
          `SELECT revoked_at FROM devices
           WHERE tenant_id = ? AND device_id = ?`,
        )
        .get(envelope.tenantId, envelope.deviceId) as
        { revoked_at: string | null } | undefined;
      if (device === undefined)
        throw new StoreAuthorizationError("device is unknown");
      if (device.revoked_at !== null)
        throw new StoreRevokedError("device is revoked");

      const existing = this.#database
        .prepare(
          `SELECT event_sha256 FROM audit_events
           WHERE tenant_id = ? AND device_id = ? AND session_id = ?
             AND sequence = ?`,
        )
        .get(
          envelope.tenantId,
          envelope.deviceId,
          envelope.sessionId,
          envelope.sequence,
        ) as { event_sha256: string } | undefined;
      if (existing !== undefined) {
        if (existing.event_sha256 === eventSha256) {
          return { idempotent: true };
        }
        throw new StoreChainForkError(
          "audit sequence already contains another event",
        );
      }

      const tail = this.#database
        .prepare(
          `SELECT last_sequence, last_event_sha256
           FROM audit_sessions
           WHERE tenant_id = ? AND device_id = ? AND session_id = ?`,
        )
        .get(envelope.tenantId, envelope.deviceId, envelope.sessionId) as
        AuditSessionRow | undefined;

      if (tail === undefined) {
        if (envelope.sequence !== 1 || envelope.previousEventSha256 !== null) {
          throw new StoreSequenceGapError("audit session must begin at one");
        }
        this.#database
          .prepare(
            `INSERT INTO audit_sessions
              (tenant_id, device_id, session_id, last_sequence,
               last_event_sha256, updated_at)
             VALUES (?, ?, ?, ?, ?, ?)`,
          )
          .run(
            envelope.tenantId,
            envelope.deviceId,
            envelope.sessionId,
            envelope.sequence,
            eventSha256,
            receivedAt,
          );
      } else {
        if (envelope.sequence <= tail.last_sequence) {
          throw new StoreChainForkError(
            "audit sequence precedes the chain tail",
          );
        }
        if (envelope.sequence !== tail.last_sequence + 1) {
          throw new StoreSequenceGapError("audit sequence is not contiguous");
        }
        if (envelope.previousEventSha256 !== tail.last_event_sha256) {
          throw new StoreChainForkError("audit previous digest does not match");
        }
        this.#database
          .prepare(
            `UPDATE audit_sessions
             SET last_sequence = ?, last_event_sha256 = ?, updated_at = ?
             WHERE tenant_id = ? AND device_id = ? AND session_id = ?`,
          )
          .run(
            envelope.sequence,
            eventSha256,
            receivedAt,
            envelope.tenantId,
            envelope.deviceId,
            envelope.sessionId,
          );
      }

      try {
        this.#database
          .prepare(
            `INSERT INTO audit_events
              (tenant_id, device_id, session_id, event_id, sequence,
               previous_event_sha256, event_sha256, envelope_json, occurred_at,
               received_at, kind, outcome, risk, action_id, target_sha256,
               report_sha256, evidence_sha256_json)
             VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
          )
          .run(
            envelope.tenantId,
            envelope.deviceId,
            envelope.sessionId,
            envelope.eventId,
            envelope.sequence,
            envelope.previousEventSha256,
            eventSha256,
            canonicalJson(envelope),
            envelope.occurredAt,
            receivedAt,
            envelope.kind,
            envelope.outcome,
            envelope.risk,
            envelope.actionId,
            envelope.targetSha256,
            envelope.reportSha256,
            JSON.stringify(envelope.evidenceSha256),
          );
      } catch (error) {
        if (isSqliteConstraint(error)) {
          throw new StoreChainForkError(
            "audit event ID or sequence was reused",
          );
        }
        throw error;
      }
      this.#database
        .prepare(
          `UPDATE devices SET last_seen_at = ?
           WHERE tenant_id = ? AND device_id = ?`,
        )
        .run(receivedAt, envelope.tenantId, envelope.deviceId);
      return { idempotent: false };
    });
  }

  listDevices(tenantId: string): StoredDevice[] {
    const rows = this.#database
      .prepare(
        `SELECT tenant_id, device_id, public_key_spki, platform, agent_version,
                enrolled_at, revoked_at, last_sequence, last_seen_at
         FROM devices WHERE tenant_id = ? ORDER BY device_id LIMIT 1000`,
      )
      .all(tenantId) as unknown as DeviceRow[];
    return rows.map(mapDevice);
  }

  listAssets(tenantId: string): ListedAsset[] {
    const rows = this.#database
      .prepare(
        `SELECT asset_id, reporting_device_id, target_fingerprint, platform,
                architecture, os_release, health, critical_count, warning_count,
                info_count, snapshot_sha256, sequence, observed_at, updated_at
         FROM assets WHERE tenant_id = ? ORDER BY asset_id LIMIT 1000`,
      )
      .all(tenantId) as unknown as AssetRow[];
    return rows.map((row) => ({
      assetId: row.asset_id,
      deviceId: row.reporting_device_id,
      targetFingerprint: row.target_fingerprint,
      platform: row.platform as ListedAsset["platform"],
      architecture: row.architecture as ListedAsset["architecture"],
      osRelease: row.os_release,
      health: row.health as ListedAsset["health"],
      findingCounts: {
        critical: row.critical_count,
        warning: row.warning_count,
        info: row.info_count,
      },
      snapshotSha256: row.snapshot_sha256,
      sequence: row.sequence,
      observedAt: row.observed_at,
      updatedAt: row.updated_at,
    }));
  }

  listAuditEvents(tenantId: string): ListedAuditEvent[] {
    const rows = this.#database
      .prepare(
        `SELECT tenant_id, device_id, session_id, event_id, sequence,
                previous_event_sha256, event_sha256, occurred_at, received_at,
                kind, outcome, risk, action_id, target_sha256, report_sha256,
                evidence_sha256_json
         FROM audit_events WHERE tenant_id = ?
         ORDER BY received_at, device_id, session_id, sequence
         LIMIT 1000`,
      )
      .all(tenantId) as unknown as AuditEventRow[];
    return rows.map((row) => ({
      tenantId: row.tenant_id,
      deviceId: row.device_id,
      sessionId: row.session_id,
      eventId: row.event_id,
      sequence: row.sequence,
      previousEventSha256: row.previous_event_sha256,
      eventSha256: row.event_sha256,
      occurredAt: row.occurred_at,
      receivedAt: row.received_at,
      kind: row.kind as AuditKind,
      outcome: row.outcome as AuditOutcome,
      risk: row.risk as AuditRisk | null,
      actionId: row.action_id,
      targetSha256: row.target_sha256,
      reportSha256: row.report_sha256,
      evidenceSha256: parseStoredEvidenceDigests(row.evidence_sha256_json),
    }));
  }

  revokeDevice(tenantId: string, deviceId: string, revokedAt: string): boolean {
    const result = this.#database
      .prepare(
        `UPDATE devices SET revoked_at = COALESCE(revoked_at, ?)
         WHERE tenant_id = ? AND device_id = ?`,
      )
      .run(revokedAt, tenantId, deviceId);
    return result.changes === 1;
  }

  #transaction<T>(operation: () => T): T {
    this.#database.exec("BEGIN IMMEDIATE");
    try {
      const result = operation();
      this.#database.exec("COMMIT");
      return result;
    } catch (error) {
      this.#database.exec("ROLLBACK");
      throw error;
    }
  }

  #migrate(): void {
    const version = this.#database.prepare("PRAGMA user_version").get() as {
      user_version: number;
    };
    if (version.user_version > 5) {
      throw new Error(
        `unsupported Fleet database version ${version.user_version}`,
      );
    }
    let currentVersion = version.user_version;
    if (currentVersion === 0) {
      this.#transaction(() => {
        this.#database.exec(`
        CREATE TABLE tenants (
          tenant_id TEXT PRIMARY KEY,
          admin_token_hash TEXT NOT NULL UNIQUE,
          created_at TEXT NOT NULL
        ) STRICT;

        CREATE TABLE enrollment_tokens (
          token_hash TEXT PRIMARY KEY,
          tenant_id TEXT NOT NULL REFERENCES tenants(tenant_id),
          created_at TEXT NOT NULL,
          expires_at_ms INTEGER NOT NULL,
          used_at TEXT
        ) STRICT;
        CREATE INDEX enrollment_tokens_tenant_idx
          ON enrollment_tokens(tenant_id, expires_at_ms);

        CREATE TABLE devices (
          tenant_id TEXT NOT NULL REFERENCES tenants(tenant_id),
          device_id TEXT NOT NULL,
          public_key_spki TEXT NOT NULL,
          platform TEXT NOT NULL,
          agent_version TEXT NOT NULL,
          enrolled_at TEXT NOT NULL,
          revoked_at TEXT,
          last_sequence INTEGER NOT NULL DEFAULT 0,
          last_envelope_hash TEXT,
          last_seen_at TEXT,
          PRIMARY KEY (tenant_id, device_id)
        ) STRICT;

        CREATE TABLE inventory_events (
          tenant_id TEXT NOT NULL,
          device_id TEXT NOT NULL,
          sequence INTEGER NOT NULL,
          envelope_hash TEXT NOT NULL,
          envelope_json TEXT NOT NULL,
          asset_id TEXT NOT NULL,
          observed_at TEXT NOT NULL,
          received_at TEXT NOT NULL,
          PRIMARY KEY (tenant_id, device_id, sequence),
          FOREIGN KEY (tenant_id, device_id)
            REFERENCES devices(tenant_id, device_id)
        ) STRICT;

        CREATE TABLE assets (
          tenant_id TEXT NOT NULL,
          asset_id TEXT NOT NULL,
          reporting_device_id TEXT NOT NULL,
          target_fingerprint TEXT NOT NULL,
          platform TEXT NOT NULL,
          architecture TEXT NOT NULL,
          os_release TEXT,
          health TEXT NOT NULL,
          critical_count INTEGER NOT NULL,
          warning_count INTEGER NOT NULL,
          info_count INTEGER NOT NULL,
          snapshot_sha256 TEXT NOT NULL,
          sequence INTEGER NOT NULL,
          observed_at TEXT NOT NULL,
          updated_at TEXT NOT NULL,
          PRIMARY KEY (tenant_id, asset_id),
          FOREIGN KEY (tenant_id, reporting_device_id)
            REFERENCES devices(tenant_id, device_id)
        ) STRICT;

        PRAGMA user_version = 1;
      `);
      });
      currentVersion = 1;
    }

    if (currentVersion === 1) {
      this.#transaction(() => {
        this.#database.exec(`
          CREATE TABLE audit_sessions (
            tenant_id TEXT NOT NULL,
            device_id TEXT NOT NULL,
            session_id TEXT NOT NULL,
            last_sequence INTEGER NOT NULL,
            last_event_sha256 TEXT NOT NULL,
            updated_at TEXT NOT NULL,
            PRIMARY KEY (tenant_id, device_id, session_id),
            FOREIGN KEY (tenant_id, device_id)
              REFERENCES devices(tenant_id, device_id)
          ) STRICT;

          CREATE TABLE audit_events (
            tenant_id TEXT NOT NULL,
            device_id TEXT NOT NULL,
            session_id TEXT NOT NULL,
            event_id TEXT NOT NULL,
            sequence INTEGER NOT NULL,
            previous_event_sha256 TEXT,
            event_sha256 TEXT NOT NULL,
            envelope_json TEXT NOT NULL,
            occurred_at TEXT NOT NULL,
            received_at TEXT NOT NULL,
            kind TEXT NOT NULL,
            outcome TEXT NOT NULL,
            risk TEXT,
            action_id TEXT,
            target_sha256 TEXT,
            report_sha256 TEXT,
            evidence_sha256_json TEXT NOT NULL,
            PRIMARY KEY (tenant_id, device_id, session_id, sequence),
            UNIQUE (tenant_id, device_id, session_id, event_id),
            FOREIGN KEY (tenant_id, device_id, session_id)
              REFERENCES audit_sessions(tenant_id, device_id, session_id)
          ) STRICT;
          CREATE INDEX audit_events_tenant_received_idx
            ON audit_events(tenant_id, received_at, device_id, session_id, sequence);

          PRAGMA user_version = 2;
        `);
      });
      currentVersion = 2;
    }

    if (currentVersion === 2) {
      this.#transaction(() => {
        this.#database.exec(`
          CREATE TABLE tenant_policy_anchors (
            tenant_id TEXT PRIMARY KEY REFERENCES tenants(tenant_id),
            public_key_spki TEXT NOT NULL,
            set_at TEXT NOT NULL
          ) STRICT;

          CREATE TABLE policy_bundles (
            tenant_id TEXT NOT NULL REFERENCES tenants(tenant_id),
            policy_id TEXT NOT NULL,
            revision INTEGER NOT NULL,
            bundle_sha256 TEXT NOT NULL,
            bundle_json TEXT NOT NULL,
            applies_all INTEGER NOT NULL CHECK (applies_all IN (0, 1)),
            published_at TEXT NOT NULL,
            PRIMARY KEY (tenant_id, policy_id)
          ) STRICT;

          CREATE TABLE policy_assignments (
            tenant_id TEXT NOT NULL,
            policy_id TEXT NOT NULL,
            device_id TEXT NOT NULL,
            PRIMARY KEY (tenant_id, policy_id, device_id),
            FOREIGN KEY (tenant_id, policy_id)
              REFERENCES policy_bundles(tenant_id, policy_id)
              ON DELETE CASCADE
          ) STRICT;
          CREATE INDEX policy_assignments_device_idx
            ON policy_assignments(tenant_id, device_id, policy_id);

          CREATE TABLE policy_pull_nonces (
            tenant_id TEXT NOT NULL,
            device_id TEXT NOT NULL,
            nonce_sha256 TEXT NOT NULL,
            expires_at_ms INTEGER NOT NULL,
            PRIMARY KEY (tenant_id, device_id, nonce_sha256),
            FOREIGN KEY (tenant_id, device_id)
              REFERENCES devices(tenant_id, device_id)
              ON DELETE CASCADE
          ) STRICT;
          CREATE INDEX policy_pull_nonces_expiry_idx
            ON policy_pull_nonces(expires_at_ms);

          PRAGMA user_version = 3;
        `);
      });
      currentVersion = 3;
    }

    if (currentVersion === 3) {
      this.#transaction(() => {
        this.#database.exec(`
          CREATE TABLE entitlement_documents (
            tenant_id TEXT NOT NULL REFERENCES tenants(tenant_id),
            entitlement_id TEXT NOT NULL,
            highest_sequence INTEGER NOT NULL,
            envelope_sha256 TEXT NOT NULL,
            canonical_json TEXT NOT NULL,
            PRIMARY KEY (tenant_id, entitlement_id)
          ) STRICT;

          CREATE TABLE entitlement_revocations (
            tenant_id TEXT PRIMARY KEY REFERENCES tenants(tenant_id),
            highest_sequence INTEGER NOT NULL,
            envelope_sha256 TEXT NOT NULL,
            canonical_json TEXT NOT NULL
          ) STRICT;

          CREATE TABLE entitlement_pull_nonces (
            tenant_id TEXT NOT NULL,
            device_id TEXT NOT NULL,
            nonce_sha256 TEXT NOT NULL,
            expires_at_ms INTEGER NOT NULL,
            PRIMARY KEY (tenant_id, device_id, nonce_sha256),
            FOREIGN KEY (tenant_id, device_id)
              REFERENCES devices(tenant_id, device_id)
              ON DELETE CASCADE
          ) STRICT;
          CREATE INDEX entitlement_pull_nonces_expiry_idx
            ON entitlement_pull_nonces(expires_at_ms);

          PRAGMA user_version = 4;
        `);
      });
      currentVersion = 4;
    }

    if (currentVersion === 4) {
      this.#transaction(() => {
        this.#database.exec(`
          CREATE TABLE tenant_update_checkpoints (
            tenant_id TEXT PRIMARY KEY REFERENCES tenants(tenant_id),
            highest_sequence INTEGER NOT NULL,
            manifest_sha256 TEXT NOT NULL,
            published_at TEXT NOT NULL
          ) STRICT;

          CREATE TABLE update_manifests (
            tenant_id TEXT NOT NULL REFERENCES tenants(tenant_id),
            platform TEXT NOT NULL,
            architecture TEXT NOT NULL,
            release_ring TEXT NOT NULL,
            sequence INTEGER NOT NULL,
            manifest_sha256 TEXT NOT NULL,
            canonical_json TEXT NOT NULL,
            published_at TEXT NOT NULL,
            PRIMARY KEY (tenant_id, platform, architecture, release_ring)
          ) STRICT;

          CREATE TABLE update_pull_nonces (
            tenant_id TEXT NOT NULL,
            device_id TEXT NOT NULL,
            nonce_sha256 TEXT NOT NULL,
            expires_at_ms INTEGER NOT NULL,
            PRIMARY KEY (tenant_id, device_id, nonce_sha256),
            FOREIGN KEY (tenant_id, device_id)
              REFERENCES devices(tenant_id, device_id)
              ON DELETE CASCADE
          ) STRICT;
          CREATE INDEX update_pull_nonces_expiry_idx
            ON update_pull_nonces(expires_at_ms);

          PRAGMA user_version = 5;
        `);
      });
    }
  }
}

interface AuditSessionRow {
  last_sequence: number;
  last_event_sha256: string;
}

interface AuditEventRow {
  tenant_id: string;
  device_id: string;
  session_id: string;
  event_id: string;
  sequence: number;
  previous_event_sha256: string | null;
  event_sha256: string;
  occurred_at: string;
  received_at: string;
  kind: string;
  outcome: string;
  risk: string | null;
  action_id: string | null;
  target_sha256: string | null;
  report_sha256: string | null;
  evidence_sha256_json: string;
}

interface DeviceRow {
  tenant_id: string;
  device_id: string;
  public_key_spki: string;
  platform: string;
  agent_version: string;
  enrolled_at: string;
  revoked_at: string | null;
  last_sequence: number;
  last_seen_at: string | null;
}

interface AssetRow {
  asset_id: string;
  reporting_device_id: string;
  target_fingerprint: string;
  platform: string;
  architecture: string;
  os_release: string | null;
  health: string;
  critical_count: number;
  warning_count: number;
  info_count: number;
  snapshot_sha256: string;
  sequence: number;
  observed_at: string;
  updated_at: string;
}

interface CurrentAssetVersionRow {
  reporting_device_id: string;
  sequence: number;
  observed_at: string;
}

function shouldReplaceCurrentAsset(
  envelope: InventoryEnvelope,
  current: CurrentAssetVersionRow | undefined,
): boolean {
  if (current === undefined) return true;
  const incomingTime = Date.parse(envelope.observedAt);
  const currentTime = Date.parse(current.observed_at);
  if (!Number.isFinite(incomingTime) || !Number.isFinite(currentTime)) {
    throw new Error("Fleet asset observation timestamp is invalid");
  }
  if (incomingTime !== currentTime) return incomingTime > currentTime;
  if (envelope.deviceId !== current.reporting_device_id) {
    return envelope.deviceId > current.reporting_device_id;
  }
  return envelope.sequence > current.sequence;
}

function mapDevice(row: DeviceRow): StoredDevice {
  return {
    tenantId: row.tenant_id,
    deviceId: row.device_id,
    publicKeySpki: row.public_key_spki,
    platform: row.platform as EnrollmentPlatform,
    agentVersion: row.agent_version,
    enrolledAt: row.enrolled_at,
    revokedAt: row.revoked_at,
    lastSequence: row.last_sequence,
    lastSeenAt: row.last_seen_at,
  };
}

function isSqliteConstraint(error: unknown): boolean {
  return (
    error instanceof Error &&
    "errcode" in error &&
    typeof error.errcode === "number" &&
    (error.errcode & 0xff) === 19
  );
}

function parseStoredEvidenceDigests(value: string): string[] {
  const parsed: unknown = JSON.parse(value);
  if (
    !Array.isArray(parsed) ||
    parsed.some(
      (digest) => typeof digest !== "string" || !/^[0-9a-f]{64}$/.test(digest),
    )
  ) {
    throw new Error("stored audit evidence digest list is invalid");
  }
  return parsed;
}
