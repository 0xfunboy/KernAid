import { chmodSync, lstatSync } from "node:fs";
import { DatabaseSync } from "node:sqlite";
import type {
  EnrollmentPlatform,
  FleetInventoryAsset,
  InventoryEnvelope,
} from "@kernaid/fleet-schemas";
import { canonicalJson } from "@kernaid/fleet-schemas";

export class StoreConflictError extends Error {}
export class StoreAuthorizationError extends Error {}
export class StoreRevokedError extends Error {}
export class StoreReplayError extends Error {}

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
    if (version.user_version > 1) {
      throw new Error(
        `unsupported Fleet database version ${version.user_version}`,
      );
    }
    if (version.user_version === 1) return;

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
  }
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
    "code" in error &&
    typeof error.code === "string" &&
    error.code.startsWith("ERR_SQLITE_CONSTRAINT")
  );
}
