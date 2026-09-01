import { chmodSync, lstatSync } from "node:fs";
import { createHash } from "node:crypto";
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
  FleetServiceOperation,
  IncidentCaseOutcome,
  IncidentCaseSeverity,
  IncidentCaseStatus,
  IncidentReportWorkOrder,
  SignedUpdateManifest,
  WorkOrderActionId,
  WorkOrderKind,
  WorkOrderResult,
  WorkOrderResultOutcome,
  WorkOrderRisk,
} from "@kernaid/fleet-schemas";
import {
  canonicalJson,
  incidentCaseOutcomes,
  incidentCaseSeverities,
  incidentCaseStatuses,
  isWorkOrderActionId,
  workOrderActionCatalog,
} from "@kernaid/fleet-schemas";
import {
  isTenantAccessAction,
  isTenantRole,
  validIncidentAssigneeLabel,
  validCredentialLabel,
  type TenantAccessAction,
  type TenantAccessOutcome,
  type TenantAccessTargetType,
  type TenantRole,
} from "./access.js";
import {
  enterpriseLicenseFeatures,
  type EnterpriseLicenseClaims,
  type EnterpriseLicenseFeature,
  type EnterpriseLicensePlan,
} from "./enterprise-license.js";

const MAX_POLICY_STREAMS_PER_TENANT = 256;
const MAX_RECENT_POLICY_PULL_NONCES_PER_DEVICE = 1024;
const MAX_ENTITLEMENT_STREAMS_PER_TENANT = 256;
const MAX_RECENT_ENTITLEMENT_PULL_NONCES_PER_DEVICE = 1024;
const MAX_RECENT_UPDATE_PULL_NONCES_PER_DEVICE = 1024;
const MAX_SERVICE_RESPONSE_BYTES = 4 * 1024 * 1024;
const MAX_SERVICE_RECEIPT_BYTES = 8 * 1024;
const MAX_SERVICE_RECEIPTS_PER_OPERATION = 4;
const MAX_TENANT_ACCESS_CREDENTIALS = 256;
const MAX_TENANT_ACCESS_AUDIT_EVENTS = 10_000;
const MAX_LISTED_TENANT_ACCESS_AUDIT_EVENTS = 256;
const MAX_WORK_ORDERS_PER_TENANT = 10_000;
const MAX_LISTED_WORK_ORDERS = 256;
const MAX_WORK_ORDER_EVENTS_PER_TENANT = 20_000;
const MAX_LISTED_WORK_ORDER_EVENTS = 512;
const MAX_RECENT_WORK_ORDER_CLAIMS_PER_DEVICE = 1024;
const MAX_INCIDENT_CASES_PER_TENANT = 10_000;
const MAX_LISTED_INCIDENT_CASES = 256;
const MAX_INCIDENT_WORK_ORDERS_PER_CASE = 256;
const MAX_INCIDENT_EVENTS_PER_TENANT = 20_000;
const MAX_LISTED_INCIDENT_EVENTS = 512;
const MAX_ENTERPRISE_LICENSE_EVENTS = 10_000;
const MAX_LISTED_ENTERPRISE_LICENSE_EVENTS = 256;

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
export class StoreServiceReceiptAnchorMismatchError extends Error {}
export class StoreWorkOrderReplayError extends Error {}
export class StoreWorkOrderStateError extends Error {}
export class StoreIncidentCaseReplayError extends Error {}
export class StoreIncidentCaseStateError extends Error {}
export class StoreEnterpriseLicenseRollbackError extends Error {}
export class StoreEnterpriseLicenseConflictError extends Error {}
export class StoreEnterpriseSeatLimitError extends Error {}

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

export interface StoredServiceResponse {
  tenantId: string;
  deviceId: string;
  operation: FleetServiceOperation;
  sequence: number;
  requestSha256: string;
  responseSha256: string;
  status: number;
  responseBody: string;
  receiptJson: string;
}

export interface TenantAccessCredential {
  tenantId: string;
  credentialId: string;
  role: TenantRole;
  label: string;
  createdAt: string;
  revokedAt: string | null;
}

export interface ListedTenantAccessAuditEvent {
  tenantId: string;
  sequence: number;
  occurredAt: string;
  credentialId: string;
  role: TenantRole;
  action: TenantAccessAction;
  outcome: TenantAccessOutcome;
  targetTenantId: string;
  targetType: TenantAccessTargetType;
  targetId: string;
}

export interface RevokeTenantAccessCredentialResult {
  credential: TenantAccessCredential;
  idempotent: boolean;
}

export type EnterpriseSeatKind = "device" | "technician";

export interface StoredEnterpriseLicense {
  tenantId: string;
  licenseId: string;
  sequence: number;
  keyId: string;
  plan: EnterpriseLicensePlan;
  features: EnterpriseLicenseFeature[];
  deviceLimit: number;
  seatLimit: number;
  issuedAtUnix: number;
  notBeforeUnix: number;
  expiresAtUnix: number;
  graceUntilUnix: number;
  envelopeSha256: string;
  canonicalJson: string;
  importedAt: string;
  revokedAt: string | null;
}

export interface EnterpriseLicenseSeat {
  assignmentId: string;
  tenantId: string;
  kind: EnterpriseSeatKind;
  subjectId: string;
  assignedAt: string;
  revokedAt: string | null;
}

export interface EnterpriseLicenseEvent {
  tenantId: string;
  sequence: number;
  occurredAt: string;
  kind:
    | "clock_rollback"
    | "license_imported"
    | "license_revoked"
    | "seat_assigned"
    | "seat_revoked";
  actorId: string;
  detailSha256: string;
}

export interface EnterpriseLicenseImportResult {
  license: StoredEnterpriseLicense;
  idempotent: boolean;
}

export interface EnterpriseClockObservation {
  retainedClockUnix: number;
  rollbackDetected: boolean;
}

export type WorkOrderStatus =
  | "pending_approval"
  | "queued"
  | "leased"
  | "succeeded"
  | "failed"
  | "rejected"
  | "cancelled"
  | "expired";

export interface StoredWorkOrder {
  tenantId: string;
  workOrderId: string;
  requestId: string;
  targetDeviceId: string;
  actionId: WorkOrderActionId;
  actionVersion: number;
  kind: WorkOrderKind;
  risk: WorkOrderRisk;
  localApprovalRequired: boolean;
  status: WorkOrderStatus;
  createdByCredentialId: string;
  createdAt: string;
  expiresAt: string;
  approvedByCredentialId: string | null;
  approvedAt: string | null;
  leaseId: string | null;
  leasedAt: string | null;
  leaseExpiresAt: string | null;
  outcome: WorkOrderResultOutcome | null;
  resultSha256: string | null;
  completedAt: string | null;
  cancelledByCredentialId: string | null;
  cancelledAt: string | null;
}

export interface ListedWorkOrderEvent {
  tenantId: string;
  sequence: number;
  workOrderId: string;
  occurredAt: string;
  kind:
    | "created"
    | "approved"
    | "leased"
    | "lease_expired"
    | "completed"
    | "cancelled"
    | "expired";
  actorType: "credential" | "device" | "system";
  actorId: string;
  status: WorkOrderStatus;
  detailSha256: string | null;
}

export interface WorkOrderMutationResult {
  workOrder: StoredWorkOrder;
  idempotent: boolean;
}

export interface WorkOrderClaimResult {
  workOrder: StoredWorkOrder | null;
  idempotent: boolean;
}

export interface IncidentCaseWorkOrder extends IncidentReportWorkOrder {
  linkedAt: string;
  observedAt: string;
}

export interface StoredIncidentCase {
  tenantId: string;
  caseId: string;
  requestId: string;
  sourceDeviceId: string;
  sourceAssetId: string | null;
  severity: IncidentCaseSeverity;
  status: IncidentCaseStatus;
  assigneeLabel: string | null;
  createdByCredentialId: string;
  createdAt: string;
  updatedAt: string;
  outcome: IncidentCaseOutcome | null;
  closedByCredentialId: string | null;
  closedAt: string | null;
  closeRequestSha256: string | null;
  reportSha256: string | null;
  reportJson: string | null;
  receiptJson: string | null;
  workOrders: IncidentCaseWorkOrder[];
}

export interface ListedIncidentCaseEvent {
  tenantId: string;
  sequence: number;
  caseId: string;
  occurredAt: string;
  kind:
    "created" | "updated" | "work_order_linked" | "work_order_state" | "closed";
  actorType: "credential" | "system";
  actorId: string;
  status: IncidentCaseStatus;
  detailSha256: string;
}

export interface IncidentCaseMutationResult {
  incidentCase: StoredIncidentCase;
  idempotent: boolean;
}

export interface IncidentCaseClosureMaterial {
  reportJson: string;
  reportSha256: string;
  receiptJson: string;
}

interface ServicePullNonce {
  nonceSha256: string;
  expiresAtMs: number;
  nowMs: number;
}

interface CommitServiceResponseInput {
  tenantId: string;
  deviceId: string;
  operation: FleetServiceOperation;
  requestSha256: string;
  responseSha256: string;
  status: number;
  responseBody: string;
  createdAt: string;
  pullNonce?: ServicePullNonce;
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

  importEnterpriseLicense(input: {
    claims: EnterpriseLicenseClaims;
    canonicalJson: string;
    envelopeSha256: string;
    importedAt: string;
    actorId: string;
  }): EnterpriseLicenseImportResult {
    validateEnterpriseLicenseStoreInput(input);
    return this.#transaction(() => {
      const existing = this.#enterpriseLicenseRow(input.claims.tenantId);
      if (existing !== undefined) {
        if (input.claims.sequence < existing.sequence) {
          throw new StoreEnterpriseLicenseRollbackError(
            "enterprise license sequence rollback",
          );
        }
        if (input.claims.sequence === existing.sequence) {
          if (input.envelopeSha256 !== existing.envelope_sha256) {
            throw new StoreEnterpriseLicenseConflictError(
              "enterprise license sequence conflict",
            );
          }
          return { license: mapEnterpriseLicense(existing), idempotent: true };
        }
      }
      this.#database
        .prepare(
          `INSERT INTO enterprise_licenses
            (tenant_id, license_id, sequence, key_id, plan, features_json,
             device_limit, seat_limit, issued_at_unix, not_before_unix,
             expires_at_unix, grace_until_unix, envelope_sha256,
             canonical_json, imported_at, revoked_at)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, NULL)
           ON CONFLICT (tenant_id) DO UPDATE SET
             license_id = excluded.license_id,
             sequence = excluded.sequence,
             key_id = excluded.key_id,
             plan = excluded.plan,
             features_json = excluded.features_json,
             device_limit = excluded.device_limit,
             seat_limit = excluded.seat_limit,
             issued_at_unix = excluded.issued_at_unix,
             not_before_unix = excluded.not_before_unix,
             expires_at_unix = excluded.expires_at_unix,
             grace_until_unix = excluded.grace_until_unix,
             envelope_sha256 = excluded.envelope_sha256,
             canonical_json = excluded.canonical_json,
             imported_at = excluded.imported_at,
             revoked_at = NULL`,
        )
        .run(
          input.claims.tenantId,
          input.claims.licenseId,
          input.claims.sequence,
          input.claims.keyId,
          input.claims.plan,
          canonicalJson(input.claims.features),
          input.claims.deviceLimit,
          input.claims.seatLimit,
          input.claims.issuedAtUnix,
          input.claims.notBeforeUnix,
          input.claims.expiresAtUnix,
          input.claims.graceUntilUnix,
          input.envelopeSha256,
          input.canonicalJson,
          input.importedAt,
        );
      this.#appendEnterpriseLicenseEvent({
        tenantId: input.claims.tenantId,
        occurredAt: input.importedAt,
        kind: "license_imported",
        actorId: input.actorId,
        detailSha256: input.envelopeSha256,
      });
      const existingDevices = this.#database
        .prepare(
          `SELECT device_id FROM devices
           WHERE tenant_id = ? AND revoked_at IS NULL ORDER BY device_id
           LIMIT 100001`,
        )
        .all(input.claims.tenantId) as unknown as { device_id: string }[];
      if (existingDevices.length > 100_000) {
        throw new StoreEnterpriseSeatLimitError(
          "existing device population exceeds the supported license bound",
        );
      }
      for (const device of existingDevices) {
        this.#assignEnterpriseSeat({
          tenantId: input.claims.tenantId,
          kind: "device",
          subjectId: device.device_id,
          limit: 100_000,
          actorId: input.actorId,
          assignedAt: input.importedAt,
        });
      }
      const existingTechnicians = this.#database
        .prepare(
          `SELECT credential_id FROM tenant_access_credentials
           WHERE tenant_id = ? AND credential_id <> 'bootstrap-admin'
             AND revoked_at IS NULL ORDER BY credential_id LIMIT 10001`,
        )
        .all(input.claims.tenantId) as unknown as { credential_id: string }[];
      if (existingTechnicians.length > 10_000) {
        throw new StoreEnterpriseSeatLimitError(
          "existing technician population exceeds the supported license bound",
        );
      }
      for (const credential of existingTechnicians) {
        this.#assignEnterpriseSeat({
          tenantId: input.claims.tenantId,
          kind: "technician",
          subjectId: credential.credential_id,
          limit: 10_000,
          actorId: input.actorId,
          assignedAt: input.importedAt,
        });
      }
      return {
        license: mapEnterpriseLicense(
          this.#enterpriseLicenseRow(input.claims.tenantId)!,
        ),
        idempotent: false,
      };
    });
  }

  getEnterpriseLicense(tenantId: string): StoredEnterpriseLicense | undefined {
    if (!isPublicIdentifier(tenantId)) throw new Error("tenant ID is invalid");
    const row = this.#enterpriseLicenseRow(tenantId);
    return row === undefined ? undefined : mapEnterpriseLicense(row);
  }

  revokeEnterpriseLicense(input: {
    tenantId: string;
    licenseId: string;
    revokedAt: string;
    actorId: string;
  }): { license: StoredEnterpriseLicense; idempotent: boolean } | undefined {
    if (
      !isPublicIdentifier(input.tenantId) ||
      !isPublicIdentifier(input.licenseId) ||
      !isRfc3339(input.revokedAt) ||
      !isPublicIdentifier(input.actorId)
    ) {
      throw new Error("enterprise license revocation is invalid");
    }
    return this.#transaction(() => {
      const existing = this.#enterpriseLicenseRow(input.tenantId);
      if (existing === undefined || existing.license_id !== input.licenseId) {
        return undefined;
      }
      if (existing.revoked_at !== null) {
        return { license: mapEnterpriseLicense(existing), idempotent: true };
      }
      const changed = this.#database
        .prepare(
          `UPDATE enterprise_licenses SET revoked_at = ?
           WHERE tenant_id = ? AND license_id = ? AND revoked_at IS NULL`,
        )
        .run(input.revokedAt, input.tenantId, input.licenseId);
      if (changed.changes !== 1) {
        throw new StoreEnterpriseLicenseConflictError(
          "enterprise license revocation conflicted",
        );
      }
      this.#appendEnterpriseLicenseEvent({
        tenantId: input.tenantId,
        occurredAt: input.revokedAt,
        kind: "license_revoked",
        actorId: input.actorId,
        detailSha256: sha256(
          `kernaid:fleet:enterprise-license-revoke:v1\0${input.licenseId}`,
        ),
      });
      return {
        license: mapEnterpriseLicense(
          this.#enterpriseLicenseRow(input.tenantId)!,
        ),
        idempotent: false,
      };
    });
  }

  observeEnterpriseClock(input: {
    tenantId: string;
    nowUnix: number;
    rollbackToleranceSeconds: number;
    occurredAt: string;
  }): EnterpriseClockObservation {
    if (
      !isPublicIdentifier(input.tenantId) ||
      !Number.isSafeInteger(input.nowUnix) ||
      input.nowUnix < 0 ||
      !Number.isSafeInteger(input.rollbackToleranceSeconds) ||
      input.rollbackToleranceSeconds < 0 ||
      !isRfc3339(input.occurredAt)
    ) {
      throw new Error("enterprise clock observation is invalid");
    }
    return this.#transaction(() => {
      const existing = this.#database
        .prepare(
          `SELECT max_observed_unix, rollback_detected_at
           FROM enterprise_license_clock WHERE tenant_id = ?`,
        )
        .get(input.tenantId) as EnterpriseLicenseClockRow | undefined;
      const retainedClockUnix = Math.max(
        input.nowUnix,
        existing?.max_observed_unix ?? 0,
      );
      const rollbackDetected =
        input.nowUnix + input.rollbackToleranceSeconds < retainedClockUnix;
      if (existing === undefined) {
        this.#database
          .prepare(
            `INSERT INTO enterprise_license_clock
              (tenant_id, max_observed_unix, rollback_detected_at, updated_at)
             VALUES (?, ?, NULL, ?)`,
          )
          .run(input.tenantId, retainedClockUnix, input.occurredAt);
      } else {
        const newDetection =
          rollbackDetected && existing.rollback_detected_at === null;
        this.#database
          .prepare(
            `UPDATE enterprise_license_clock
             SET max_observed_unix = ?, rollback_detected_at = ?, updated_at = ?
             WHERE tenant_id = ?`,
          )
          .run(
            retainedClockUnix,
            rollbackDetected
              ? (existing.rollback_detected_at ?? input.occurredAt)
              : null,
            input.occurredAt,
            input.tenantId,
          );
        if (newDetection) {
          this.#appendEnterpriseLicenseEvent({
            tenantId: input.tenantId,
            occurredAt: input.occurredAt,
            kind: "clock_rollback",
            actorId: "system-clock",
            detailSha256: sha256(
              `kernaid:fleet:enterprise-clock-rollback:v1\0${retainedClockUnix}`,
            ),
          });
        }
      }
      return { retainedClockUnix, rollbackDetected };
    });
  }

  listEnterpriseLicenseSeats(tenantId: string): EnterpriseLicenseSeat[] {
    if (!isPublicIdentifier(tenantId)) throw new Error("tenant ID is invalid");
    const rows = this.#database
      .prepare(
        `SELECT assignment_id, tenant_id, kind, subject_id, assigned_at,
                revoked_at FROM enterprise_license_seats
         WHERE tenant_id = ? ORDER BY kind, subject_id LIMIT 110000`,
      )
      .all(tenantId) as unknown as EnterpriseLicenseSeatRow[];
    return rows.map(mapEnterpriseLicenseSeat);
  }

  listEnterpriseLicenseEvents(tenantId: string): EnterpriseLicenseEvent[] {
    if (!isPublicIdentifier(tenantId)) throw new Error("tenant ID is invalid");
    const rows = this.#database
      .prepare(
        `SELECT tenant_id, sequence, occurred_at, kind, actor_id, detail_sha256
         FROM enterprise_license_events WHERE tenant_id = ?
         ORDER BY sequence DESC LIMIT ?`,
      )
      .all(
        tenantId,
        MAX_LISTED_ENTERPRISE_LICENSE_EVENTS,
      ) as unknown as EnterpriseLicenseEventRow[];
    return rows.map(mapEnterpriseLicenseEvent);
  }

  bindServiceReceiptAnchor(anchorSha256: string): void {
    if (!isSha256(anchorSha256)) {
      throw new Error("service receipt anchor digest is invalid");
    }
    this.#transaction(() => {
      const current = this.#database
        .prepare(
          "SELECT anchor_sha256 FROM service_receipt_config WHERE singleton = 1",
        )
        .get() as { anchor_sha256: string } | undefined;
      if (current === undefined) {
        this.#database
          .prepare(
            "INSERT INTO service_receipt_config (singleton, anchor_sha256) VALUES (1, ?)",
          )
          .run(anchorSha256);
      } else if (current.anchor_sha256 !== anchorSha256) {
        throw new StoreServiceReceiptAnchorMismatchError(
          "service receipt anchor does not match this database",
        );
      }
    });
  }

  getServiceResponse(input: {
    tenantId: string;
    deviceId: string;
    operation: FleetServiceOperation;
    requestSha256: string;
  }): StoredServiceResponse | undefined {
    validateServiceResponseLookup(input);
    const row = this.#database
      .prepare(
        `SELECT tenant_id, device_id, operation, sequence, request_sha256,
                response_sha256, status, response_body, receipt_json
         FROM service_receipts
         WHERE tenant_id = ? AND device_id = ? AND operation = ?
           AND request_sha256 = ?
         ORDER BY sequence DESC LIMIT 1`,
      )
      .get(
        input.tenantId,
        input.deviceId,
        input.operation,
        input.requestSha256,
      ) as ServiceResponseRow | undefined;
    return row === undefined ? undefined : mapServiceResponse(row);
  }

  commitServiceResponse(
    input: CommitServiceResponseInput,
    signReceipt: (sequence: number) => string,
  ): StoredServiceResponse {
    validateServiceResponseCommit(input);
    return this.#transaction(() => {
      const existing = this.getServiceResponse(input);
      if (existing !== undefined) return existing;

      if (input.pullNonce !== undefined) {
        this.#recordServicePullNonce(
          input.operation,
          input.tenantId,
          input.deviceId,
          input.pullNonce,
        );
      }

      const checkpoint = this.#database
        .prepare(
          `SELECT last_sequence FROM service_receipt_checkpoints
           WHERE tenant_id = ? AND device_id = ?`,
        )
        .get(input.tenantId, input.deviceId) as
        { last_sequence: number } | undefined;
      const sequence = (checkpoint?.last_sequence ?? 0) + 1;
      if (!Number.isSafeInteger(sequence) || sequence < 1) {
        throw new StoreConflictError("service receipt sequence exhausted");
      }
      const receiptJson = signReceipt(sequence);
      if (
        Buffer.byteLength(receiptJson, "utf8") === 0 ||
        Buffer.byteLength(receiptJson, "utf8") > MAX_SERVICE_RECEIPT_BYTES
      ) {
        throw new Error("service receipt exceeds its bound");
      }

      this.#database
        .prepare(
          `INSERT INTO service_receipt_checkpoints
            (tenant_id, device_id, last_sequence, updated_at)
           VALUES (?, ?, ?, ?)
           ON CONFLICT (tenant_id, device_id) DO UPDATE SET
             last_sequence = excluded.last_sequence,
             updated_at = excluded.updated_at`,
        )
        .run(input.tenantId, input.deviceId, sequence, input.createdAt);
      this.#database
        .prepare(
          `INSERT INTO service_receipts
            (tenant_id, device_id, operation, sequence, request_sha256,
             response_sha256, status, response_body, receipt_json, created_at)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
        )
        .run(
          input.tenantId,
          input.deviceId,
          input.operation,
          sequence,
          input.requestSha256,
          input.responseSha256,
          input.status,
          input.responseBody,
          receiptJson,
          input.createdAt,
        );
      this.#database
        .prepare(
          `DELETE FROM service_receipts
           WHERE tenant_id = ? AND device_id = ? AND operation = ?
             AND sequence NOT IN (
               SELECT sequence FROM service_receipts
               WHERE tenant_id = ? AND device_id = ? AND operation = ?
               ORDER BY sequence DESC LIMIT ?
             )`,
        )
        .run(
          input.tenantId,
          input.deviceId,
          input.operation,
          input.tenantId,
          input.deviceId,
          input.operation,
          MAX_SERVICE_RECEIPTS_PER_OPERATION,
        );
      return mapServiceResponse({
        tenant_id: input.tenantId,
        device_id: input.deviceId,
        operation: input.operation,
        sequence,
        request_sha256: input.requestSha256,
        response_sha256: input.responseSha256,
        status: input.status,
        response_body: input.responseBody,
        receipt_json: receiptJson,
      });
    });
  }

  createTenant(
    tenantId: string,
    adminTokenHash: string,
    createdAt: string,
  ): void {
    validateCredentialInput({
      tenantId,
      credentialId: "bootstrap-admin",
      tokenHash: adminTokenHash,
      role: "admin",
      label: "Initial tenant administrator",
      createdAt,
    });
    this.#transaction(() => {
      this.#database
        .prepare(
          "INSERT INTO tenants (tenant_id, admin_token_hash, created_at) VALUES (?, ?, ?)",
        )
        .run(tenantId, adminTokenHash, createdAt);
      this.#insertTenantAccessCredential({
        tenantId,
        credentialId: "bootstrap-admin",
        tokenHash: adminTokenHash,
        role: "admin",
        label: "Initial tenant administrator",
        createdAt,
      });
    });
  }

  findTenantAccessCredential(
    tokenHash: string,
  ): TenantAccessCredential | undefined {
    if (!isSha256(tokenHash)) throw new Error("access token hash is invalid");
    const row = this.#database
      .prepare(
        `SELECT tenant_id, credential_id, role, label, created_at, revoked_at
         FROM tenant_access_credentials WHERE token_hash = ?`,
      )
      .get(tokenHash) as TenantAccessCredentialRow | undefined;
    return row === undefined ? undefined : mapTenantAccessCredential(row);
  }

  getTenantAccessCredential(
    tenantId: string,
    credentialId: string,
  ): TenantAccessCredential | undefined {
    if (!isPublicIdentifier(tenantId) || !isPublicIdentifier(credentialId)) {
      throw new Error("tenant credential identity is invalid");
    }
    const row = this.#database
      .prepare(
        `SELECT tenant_id, credential_id, role, label, created_at, revoked_at
         FROM tenant_access_credentials
         WHERE tenant_id = ? AND credential_id = ?`,
      )
      .get(tenantId, credentialId) as TenantAccessCredentialRow | undefined;
    return row === undefined ? undefined : mapTenantAccessCredential(row);
  }

  createTenantAccessCredential(input: {
    tenantId: string;
    credentialId: string;
    tokenHash: string;
    role: TenantRole;
    label: string;
    createdAt: string;
    enterpriseSeat?: { limit: number; actorId: string };
  }): TenantAccessCredential {
    validateCredentialInput(input);
    return this.#transaction(() => {
      const count = this.#database
        .prepare(
          `SELECT COUNT(*) AS count FROM tenant_access_credentials
           WHERE tenant_id = ?`,
        )
        .get(input.tenantId) as { count: number };
      if (count.count >= MAX_TENANT_ACCESS_CREDENTIALS) {
        throw new StoreConflictError("tenant credential limit reached");
      }
      try {
        if (input.enterpriseSeat !== undefined) {
          this.#assignEnterpriseSeat({
            tenantId: input.tenantId,
            kind: "technician",
            subjectId: input.credentialId,
            limit: input.enterpriseSeat.limit,
            actorId: input.enterpriseSeat.actorId,
            assignedAt: input.createdAt,
          });
        }
        this.#insertTenantAccessCredential(input);
      } catch (error) {
        if (isSqliteConstraint(error)) {
          throw new StoreConflictError("tenant credential already exists");
        }
        throw error;
      }
      return {
        tenantId: input.tenantId,
        credentialId: input.credentialId,
        role: input.role,
        label: input.label,
        createdAt: input.createdAt,
        revokedAt: null,
      };
    });
  }

  listTenantAccessCredentials(tenantId: string): TenantAccessCredential[] {
    if (!isPublicIdentifier(tenantId)) throw new Error("tenant ID is invalid");
    const rows = this.#database
      .prepare(
        `SELECT tenant_id, credential_id, role, label, created_at, revoked_at
         FROM tenant_access_credentials WHERE tenant_id = ?
         ORDER BY created_at, credential_id LIMIT ?`,
      )
      .all(
        tenantId,
        MAX_TENANT_ACCESS_CREDENTIALS,
      ) as unknown as TenantAccessCredentialRow[];
    return rows.map(mapTenantAccessCredential);
  }

  revokeTenantAccessCredential(input: {
    tenantId: string;
    credentialId: string;
    actorCredentialId: string;
    revokedAt: string;
  }): RevokeTenantAccessCredentialResult | undefined {
    if (
      !isPublicIdentifier(input.tenantId) ||
      !isPublicIdentifier(input.credentialId) ||
      !isPublicIdentifier(input.actorCredentialId) ||
      !isRfc3339(input.revokedAt)
    ) {
      throw new Error("credential revocation is invalid");
    }
    return this.#transaction(() => {
      const row = this.#database
        .prepare(
          `SELECT tenant_id, credential_id, role, label, created_at, revoked_at
           FROM tenant_access_credentials
           WHERE tenant_id = ? AND credential_id = ?`,
        )
        .get(input.tenantId, input.credentialId) as
        TenantAccessCredentialRow | undefined;
      if (row === undefined) return undefined;
      const credential = mapTenantAccessCredential(row);
      if (credential.revokedAt !== null) {
        return { credential, idempotent: true };
      }
      if (credential.credentialId === input.actorCredentialId) {
        throw new StoreConflictError("credential cannot revoke itself");
      }
      if (credential.role === "admin") {
        const admins = this.#database
          .prepare(
            `SELECT COUNT(*) AS count FROM tenant_access_credentials
             WHERE tenant_id = ? AND role = 'admin' AND revoked_at IS NULL`,
          )
          .get(input.tenantId) as { count: number };
        if (admins.count <= 1) {
          throw new StoreConflictError("last tenant administrator remains");
        }
      }
      const result = this.#database
        .prepare(
          `UPDATE tenant_access_credentials SET revoked_at = ?
           WHERE tenant_id = ? AND credential_id = ? AND revoked_at IS NULL`,
        )
        .run(input.revokedAt, input.tenantId, input.credentialId);
      if (result.changes !== 1) {
        throw new StoreConflictError("credential revocation conflicted");
      }
      this.#revokeEnterpriseSeat({
        tenantId: input.tenantId,
        kind: "technician",
        subjectId: input.credentialId,
        actorId: input.actorCredentialId,
        revokedAt: input.revokedAt,
      });
      return {
        credential: { ...credential, revokedAt: input.revokedAt },
        idempotent: false,
      };
    });
  }

  recordTenantAccessAudit(input: {
    tenantId: string;
    occurredAt: string;
    credentialId: string;
    role: TenantRole;
    action: TenantAccessAction;
    outcome: TenantAccessOutcome;
    targetTenantId: string;
    targetType: TenantAccessTargetType;
    targetId: string;
  }): number {
    validateTenantAccessAuditInput(input);
    return this.#transaction(() => {
      const current = this.#database
        .prepare(
          `SELECT COALESCE(MAX(sequence), 0) AS sequence
           FROM tenant_access_audit WHERE tenant_id = ?`,
        )
        .get(input.tenantId) as { sequence: number };
      const sequence = current.sequence + 1;
      if (!Number.isSafeInteger(sequence) || sequence < 1) {
        throw new StoreConflictError("tenant access audit sequence exhausted");
      }
      this.#database
        .prepare(
          `INSERT INTO tenant_access_audit
            (tenant_id, sequence, occurred_at, credential_id, role, action,
             outcome, target_tenant_id, target_type, target_id)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
        )
        .run(
          input.tenantId,
          sequence,
          input.occurredAt,
          input.credentialId,
          input.role,
          input.action,
          input.outcome,
          input.targetTenantId,
          input.targetType,
          input.targetId,
        );
      this.#database
        .prepare(
          `DELETE FROM tenant_access_audit
           WHERE tenant_id = ? AND sequence <= ?`,
        )
        .run(input.tenantId, sequence - MAX_TENANT_ACCESS_AUDIT_EVENTS);
      return sequence;
    });
  }

  listTenantAccessAudit(tenantId: string): ListedTenantAccessAuditEvent[] {
    if (!isPublicIdentifier(tenantId)) throw new Error("tenant ID is invalid");
    const rows = this.#database
      .prepare(
        `SELECT tenant_id, sequence, occurred_at, credential_id, role, action,
                outcome, target_tenant_id, target_type, target_id
         FROM tenant_access_audit WHERE tenant_id = ?
         ORDER BY sequence DESC LIMIT ?`,
      )
      .all(
        tenantId,
        MAX_LISTED_TENANT_ACCESS_AUDIT_EVENTS,
      ) as unknown as TenantAccessAuditRow[];
    return rows.map(mapTenantAccessAudit);
  }

  createWorkOrder(input: {
    tenantId: string;
    workOrderId: string;
    requestId: string;
    requestSha256: string;
    targetDeviceId: string;
    actionId: WorkOrderActionId;
    actionVersion: number;
    kind: WorkOrderKind;
    risk: WorkOrderRisk;
    localApprovalRequired: boolean;
    createdByCredentialId: string;
    createdAt: string;
    expiresAt: string;
    expiresAtMs: number;
  }): WorkOrderMutationResult {
    validateWorkOrderCreate(input);
    return this.#transaction(() => {
      const existing = this.#database
        .prepare(
          `SELECT * FROM work_orders
           WHERE tenant_id = ? AND request_id = ?`,
        )
        .get(input.tenantId, input.requestId) as WorkOrderRow | undefined;
      if (existing !== undefined) {
        if (existing.request_sha256 !== input.requestSha256) {
          throw new StoreConflictError("work-order request ID conflict");
        }
        return { workOrder: mapWorkOrder(existing), idempotent: true };
      }
      const device = this.#database
        .prepare(
          `SELECT revoked_at FROM devices
           WHERE tenant_id = ? AND device_id = ?`,
        )
        .get(input.tenantId, input.targetDeviceId) as
        { revoked_at: string | null } | undefined;
      if (device === undefined) {
        throw new StoreAuthorizationError("work-order target is unknown");
      }
      if (device.revoked_at !== null) {
        throw new StoreRevokedError("work-order target is revoked");
      }
      const active = this.#database
        .prepare(
          `SELECT COUNT(*) AS count FROM work_orders
           WHERE tenant_id = ? AND status IN ('pending_approval','queued','leased')`,
        )
        .get(input.tenantId) as { count: number };
      if (active.count >= MAX_WORK_ORDERS_PER_TENANT) {
        throw new StoreConflictError("active work-order limit reached");
      }
      const status: WorkOrderStatus = input.localApprovalRequired
        ? "pending_approval"
        : "queued";
      this.#database
        .prepare(
          `INSERT INTO work_orders
            (tenant_id, work_order_id, request_id, request_sha256,
             target_device_id, action_id, action_version, kind, risk,
             local_approval_required, status, created_by_credential_id,
             created_at, expires_at, expires_at_ms)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
        )
        .run(
          input.tenantId,
          input.workOrderId,
          input.requestId,
          input.requestSha256,
          input.targetDeviceId,
          input.actionId,
          input.actionVersion,
          input.kind,
          input.risk,
          input.localApprovalRequired ? 1 : 0,
          status,
          input.createdByCredentialId,
          input.createdAt,
          input.expiresAt,
          input.expiresAtMs,
        );
      this.#recordWorkOrderEvent({
        tenantId: input.tenantId,
        workOrderId: input.workOrderId,
        occurredAt: input.createdAt,
        kind: "created",
        actorType: "credential",
        actorId: input.createdByCredentialId,
        status,
        detailSha256: input.requestSha256,
      });
      return {
        workOrder: this.#requiredWorkOrder(input.tenantId, input.workOrderId),
        idempotent: false,
      };
    });
  }

  listWorkOrders(
    tenantId: string,
    nowMs: number,
    now: string,
  ): StoredWorkOrder[] {
    validateWorkOrderClock(tenantId, nowMs, now);
    this.#transaction(() => this.#expireWorkOrders(tenantId, nowMs, now));
    const rows = this.#database
      .prepare(
        `SELECT * FROM work_orders WHERE tenant_id = ?
         ORDER BY created_at DESC, work_order_id DESC LIMIT ?`,
      )
      .all(tenantId, MAX_LISTED_WORK_ORDERS) as unknown as WorkOrderRow[];
    return rows.map(mapWorkOrder);
  }

  getWorkOrder(
    tenantId: string,
    workOrderId: string,
    nowMs: number,
    now: string,
  ): StoredWorkOrder | undefined {
    validateWorkOrderClock(tenantId, nowMs, now);
    if (!isPublicIdentifier(workOrderId)) {
      throw new Error("work-order ID is invalid");
    }
    return this.#transaction(() => {
      this.#expireWorkOrders(tenantId, nowMs, now);
      const row = this.#workOrder(tenantId, workOrderId);
      return row === undefined ? undefined : mapWorkOrder(row);
    });
  }

  approveWorkOrder(input: {
    tenantId: string;
    workOrderId: string;
    credentialId: string;
    approvedAt: string;
    nowMs: number;
  }): WorkOrderMutationResult | undefined {
    validateWorkOrderActorMutation(input);
    return this.#transaction(() => {
      this.#expireWorkOrders(input.tenantId, input.nowMs, input.approvedAt);
      const row = this.#workOrder(input.tenantId, input.workOrderId);
      if (row === undefined) return undefined;
      const current = mapWorkOrder(row);
      if (current.approvedAt !== null) {
        return { workOrder: current, idempotent: true };
      }
      if (
        current.status !== "pending_approval" ||
        !current.localApprovalRequired
      ) {
        throw new StoreWorkOrderStateError("work order is not approvable");
      }
      const changed = this.#database
        .prepare(
          `UPDATE work_orders SET status = 'queued',
             approved_by_credential_id = ?, approved_at = ?
           WHERE tenant_id = ? AND work_order_id = ?
             AND status = 'pending_approval'`,
        )
        .run(
          input.credentialId,
          input.approvedAt,
          input.tenantId,
          input.workOrderId,
        );
      if (changed.changes !== 1) {
        throw new StoreWorkOrderStateError("work-order approval conflicted");
      }
      this.#recordWorkOrderEvent({
        tenantId: input.tenantId,
        workOrderId: input.workOrderId,
        occurredAt: input.approvedAt,
        kind: "approved",
        actorType: "credential",
        actorId: input.credentialId,
        status: "queued",
        detailSha256: null,
      });
      return {
        workOrder: this.#requiredWorkOrder(input.tenantId, input.workOrderId),
        idempotent: false,
      };
    });
  }

  cancelWorkOrder(input: {
    tenantId: string;
    workOrderId: string;
    credentialId: string;
    cancelledAt: string;
    nowMs: number;
  }): WorkOrderMutationResult | undefined {
    validateWorkOrderActorMutation({
      ...input,
      approvedAt: input.cancelledAt,
    });
    return this.#transaction(() => {
      this.#expireWorkOrders(input.tenantId, input.nowMs, input.cancelledAt);
      const row = this.#workOrder(input.tenantId, input.workOrderId);
      if (row === undefined) return undefined;
      const current = mapWorkOrder(row);
      if (current.status === "cancelled") {
        return { workOrder: current, idempotent: true };
      }
      if (!["pending_approval", "queued"].includes(current.status)) {
        throw new StoreWorkOrderStateError(
          "leased or terminal work order cannot be cancelled",
        );
      }
      this.#database
        .prepare(
          `UPDATE work_orders SET status = 'cancelled',
             cancelled_by_credential_id = ?, cancelled_at = ?
           WHERE tenant_id = ? AND work_order_id = ?`,
        )
        .run(
          input.credentialId,
          input.cancelledAt,
          input.tenantId,
          input.workOrderId,
        );
      this.#recordWorkOrderEvent({
        tenantId: input.tenantId,
        workOrderId: input.workOrderId,
        occurredAt: input.cancelledAt,
        kind: "cancelled",
        actorType: "credential",
        actorId: input.credentialId,
        status: "cancelled",
        detailSha256: null,
      });
      return {
        workOrder: this.#requiredWorkOrder(input.tenantId, input.workOrderId),
        idempotent: false,
      };
    });
  }

  claimWorkOrder(input: {
    tenantId: string;
    deviceId: string;
    requestSha256: string;
    nonceSha256: string;
    nonceExpiresAtMs: number;
    leaseId: string;
    leaseSeconds: number;
    eligibleActionIds: readonly WorkOrderActionId[];
    nowMs: number;
    now: string;
  }): WorkOrderClaimResult {
    validateWorkOrderClaim(input);
    return this.#transaction(() => {
      this.#expireWorkOrders(input.tenantId, input.nowMs, input.now);
      this.#releaseExpiredLeases(
        input.tenantId,
        input.deviceId,
        input.nowMs,
        input.now,
      );
      this.#database
        .prepare("DELETE FROM work_order_claims WHERE expires_at_ms <= ?")
        .run(input.nowMs);
      const existing = this.#database
        .prepare(
          `SELECT request_sha256, work_order_id, lease_id FROM work_order_claims
           WHERE tenant_id = ? AND device_id = ? AND nonce_sha256 = ?`,
        )
        .get(input.tenantId, input.deviceId, input.nonceSha256) as
        | {
            request_sha256: string;
            work_order_id: string | null;
            lease_id: string | null;
          }
        | undefined;
      if (existing !== undefined) {
        if (existing.request_sha256 !== input.requestSha256) {
          throw new StoreWorkOrderReplayError("claim nonce was rebound");
        }
        if (existing.work_order_id === null) {
          return { workOrder: null, idempotent: true };
        }
        const workOrder = this.#requiredWorkOrder(
          input.tenantId,
          existing.work_order_id,
        );
        if (
          existing.lease_id === null ||
          workOrder.status !== "leased" ||
          workOrder.leaseId !== existing.lease_id
        ) {
          throw new StoreWorkOrderReplayError(
            "claim lease is no longer active",
          );
        }
        return { workOrder, idempotent: true };
      }
      const recent = this.#database
        .prepare(
          `SELECT COUNT(*) AS count FROM work_order_claims
           WHERE tenant_id = ? AND device_id = ?`,
        )
        .get(input.tenantId, input.deviceId) as { count: number };
      if (recent.count >= MAX_RECENT_WORK_ORDER_CLAIMS_PER_DEVICE) {
        throw new StoreConflictError("recent work-order claim limit reached");
      }
      let selected: WorkOrderRow | undefined;
      if (input.eligibleActionIds.length > 0) {
        const placeholders = input.eligibleActionIds.map(() => "?").join(",");
        selected = this.#database
          .prepare(
            `SELECT * FROM work_orders
             WHERE tenant_id = ? AND target_device_id = ? AND status = 'queued'
               AND action_id IN (${placeholders})
             ORDER BY created_at, work_order_id LIMIT 1`,
          )
          .get(input.tenantId, input.deviceId, ...input.eligibleActionIds) as
          WorkOrderRow | undefined;
      }
      if (selected !== undefined) {
        const leaseExpiresAtMs = Math.min(
          input.nowMs + input.leaseSeconds * 1000,
          selected.expires_at_ms,
        );
        const leaseExpiresAt = new Date(leaseExpiresAtMs).toISOString();
        const changed = this.#database
          .prepare(
            `UPDATE work_orders SET status = 'leased', lease_id = ?,
               leased_at = ?, lease_expires_at = ?, lease_expires_at_ms = ?
             WHERE tenant_id = ? AND work_order_id = ? AND status = 'queued'`,
          )
          .run(
            input.leaseId,
            input.now,
            leaseExpiresAt,
            leaseExpiresAtMs,
            input.tenantId,
            selected.work_order_id,
          );
        if (changed.changes !== 1) {
          throw new StoreWorkOrderStateError("work-order claim conflicted");
        }
        this.#recordWorkOrderEvent({
          tenantId: input.tenantId,
          workOrderId: selected.work_order_id,
          occurredAt: input.now,
          kind: "leased",
          actorType: "device",
          actorId: input.deviceId,
          status: "leased",
          detailSha256: input.requestSha256,
        });
      }
      this.#database
        .prepare(
          `INSERT INTO work_order_claims
            (tenant_id, device_id, nonce_sha256, request_sha256,
             work_order_id, lease_id, expires_at_ms)
           VALUES (?, ?, ?, ?, ?, ?, ?)`,
        )
        .run(
          input.tenantId,
          input.deviceId,
          input.nonceSha256,
          input.requestSha256,
          selected?.work_order_id ?? null,
          selected === undefined ? null : input.leaseId,
          input.nonceExpiresAtMs,
        );
      return {
        workOrder:
          selected === undefined
            ? null
            : this.#requiredWorkOrder(input.tenantId, selected.work_order_id),
        idempotent: false,
      };
    });
  }

  recordWorkOrderResult(input: {
    result: WorkOrderResult;
    envelopeSha256: string;
    receivedAt: string;
    nowMs: number;
  }): WorkOrderMutationResult {
    if (!isSha256(input.envelopeSha256) || !isRfc3339(input.receivedAt)) {
      throw new Error("work-order result storage input is invalid");
    }
    return this.#transaction(() => {
      this.#expireWorkOrders(
        input.result.tenantId,
        input.nowMs,
        input.receivedAt,
      );
      const row = this.#workOrder(
        input.result.tenantId,
        input.result.workOrderId,
      );
      if (row === undefined) {
        throw new StoreAuthorizationError("work order is unknown");
      }
      const current = mapWorkOrder(row);
      if (current.resultSha256 !== null) {
        if (row.result_envelope_sha256 === input.envelopeSha256) {
          return { workOrder: current, idempotent: true };
        }
        throw new StoreWorkOrderReplayError("work-order result conflicts");
      }
      if (
        current.status !== "leased" ||
        current.targetDeviceId !== input.result.deviceId ||
        current.leaseId !== input.result.leaseId ||
        current.actionId !== input.result.actionId ||
        current.actionVersion !== input.result.actionVersion ||
        current.leasedAt === null ||
        current.leaseExpiresAt === null ||
        Date.parse(input.result.completedAt) < Date.parse(current.leasedAt) ||
        Date.parse(input.result.completedAt) >
          Date.parse(current.leaseExpiresAt) ||
        row.lease_expires_at_ms === null ||
        row.lease_expires_at_ms <= input.nowMs
      ) {
        throw new StoreWorkOrderStateError(
          "work-order result binding is stale",
        );
      }
      this.#database
        .prepare(
          `UPDATE work_orders SET status = ?, outcome = ?, result_sha256 = ?,
             result_envelope_sha256 = ?, completed_at = ?
           WHERE tenant_id = ? AND work_order_id = ? AND status = 'leased'`,
        )
        .run(
          input.result.outcome,
          input.result.outcome,
          input.result.resultSha256,
          input.envelopeSha256,
          input.result.completedAt,
          input.result.tenantId,
          input.result.workOrderId,
        );
      this.#recordWorkOrderEvent({
        tenantId: input.result.tenantId,
        workOrderId: input.result.workOrderId,
        occurredAt: input.receivedAt,
        kind: "completed",
        actorType: "device",
        actorId: input.result.deviceId,
        status: input.result.outcome,
        detailSha256: input.result.resultSha256,
      });
      return {
        workOrder: this.#requiredWorkOrder(
          input.result.tenantId,
          input.result.workOrderId,
        ),
        idempotent: false,
      };
    });
  }

  listWorkOrderEvents(tenantId: string): ListedWorkOrderEvent[] {
    if (!isPublicIdentifier(tenantId)) throw new Error("tenant ID is invalid");
    const rows = this.#database
      .prepare(
        `SELECT * FROM work_order_events WHERE tenant_id = ?
         ORDER BY sequence DESC LIMIT ?`,
      )
      .all(
        tenantId,
        MAX_LISTED_WORK_ORDER_EVENTS,
      ) as unknown as WorkOrderEventRow[];
    return rows.map(mapWorkOrderEvent);
  }

  createIncidentCase(input: {
    tenantId: string;
    caseId: string;
    requestId: string;
    requestSha256: string;
    sourceDeviceId: string;
    sourceAssetId: string | null;
    severity: IncidentCaseSeverity;
    assigneeLabel: string | null;
    credentialId: string;
    createdAt: string;
  }): IncidentCaseMutationResult {
    validateIncidentCaseCreate(input);
    return this.#transaction(() => {
      const existing = this.#database
        .prepare(
          `SELECT * FROM incident_cases
           WHERE tenant_id = ? AND request_id = ?`,
        )
        .get(input.tenantId, input.requestId) as IncidentCaseRow | undefined;
      if (existing !== undefined) {
        if (existing.request_sha256 !== input.requestSha256) {
          throw new StoreIncidentCaseReplayError(
            "incident case request ID conflict",
          );
        }
        return {
          incidentCase: this.#mapIncidentCase(existing),
          idempotent: true,
        };
      }
      const active = this.#database
        .prepare(
          `SELECT COUNT(*) AS count FROM incident_cases
           WHERE tenant_id = ? AND status <> 'closed'`,
        )
        .get(input.tenantId) as { count: number };
      if (active.count >= MAX_INCIDENT_CASES_PER_TENANT) {
        throw new StoreConflictError("active incident-case limit reached");
      }
      this.#database
        .prepare(
          `INSERT INTO incident_cases
            (tenant_id, case_id, request_id, request_sha256, source_device_id,
             source_asset_id, severity, status, assignee_label,
             created_by_credential_id, created_at, updated_at)
           VALUES (?, ?, ?, ?, ?, ?, ?, 'open', ?, ?, ?, ?)`,
        )
        .run(
          input.tenantId,
          input.caseId,
          input.requestId,
          input.requestSha256,
          input.sourceDeviceId,
          input.sourceAssetId,
          input.severity,
          input.assigneeLabel,
          input.credentialId,
          input.createdAt,
          input.createdAt,
        );
      this.#recordIncidentCaseEvent({
        tenantId: input.tenantId,
        caseId: input.caseId,
        occurredAt: input.createdAt,
        kind: "created",
        actorType: "credential",
        actorId: input.credentialId,
        status: "open",
        detailSha256: input.requestSha256,
      });
      return {
        incidentCase: this.#requiredIncidentCase(input.tenantId, input.caseId),
        idempotent: false,
      };
    });
  }

  listIncidentCases(
    tenantId: string,
    observedAt: string,
  ): StoredIncidentCase[] {
    if (!isPublicIdentifier(tenantId) || !isRfc3339(observedAt)) {
      throw new Error("incident case list input is invalid");
    }
    this.#transaction(() =>
      this.#syncIncidentCaseWorkOrders(tenantId, null, observedAt),
    );
    const rows = this.#database
      .prepare(
        `SELECT * FROM incident_cases WHERE tenant_id = ?
         ORDER BY updated_at DESC, case_id DESC LIMIT ?`,
      )
      .all(tenantId, MAX_LISTED_INCIDENT_CASES) as unknown as IncidentCaseRow[];
    return rows.map((row) => this.#mapIncidentCase(row));
  }

  updateIncidentCase(input: {
    tenantId: string;
    caseId: string;
    severity: IncidentCaseSeverity;
    status: Exclude<IncidentCaseStatus, "closed">;
    assigneeLabel: string | null;
    credentialId: string;
    updatedAt: string;
    detailSha256: string;
  }): IncidentCaseMutationResult | undefined {
    validateIncidentCaseUpdate(input);
    return this.#transaction(() => {
      const row = this.#incidentCase(input.tenantId, input.caseId);
      if (row === undefined) return undefined;
      if (row.status === "closed") {
        throw new StoreIncidentCaseStateError("closed case is immutable");
      }
      if (
        row.severity === input.severity &&
        row.status === input.status &&
        row.assignee_label === input.assigneeLabel
      ) {
        return { incidentCase: this.#mapIncidentCase(row), idempotent: true };
      }
      this.#database
        .prepare(
          `UPDATE incident_cases
           SET severity = ?, status = ?, assignee_label = ?, updated_at = ?
           WHERE tenant_id = ? AND case_id = ? AND status <> 'closed'`,
        )
        .run(
          input.severity,
          input.status,
          input.assigneeLabel,
          input.updatedAt,
          input.tenantId,
          input.caseId,
        );
      this.#recordIncidentCaseEvent({
        tenantId: input.tenantId,
        caseId: input.caseId,
        occurredAt: input.updatedAt,
        kind: "updated",
        actorType: "credential",
        actorId: input.credentialId,
        status: input.status,
        detailSha256: input.detailSha256,
      });
      return {
        incidentCase: this.#requiredIncidentCase(input.tenantId, input.caseId),
        idempotent: false,
      };
    });
  }

  linkIncidentWorkOrder(input: {
    tenantId: string;
    caseId: string;
    workOrderId: string;
    credentialId: string;
    linkedAt: string;
  }): IncidentCaseMutationResult | undefined {
    validateIncidentCaseLink(input);
    return this.#transaction(() => {
      const incident = this.#incidentCase(input.tenantId, input.caseId);
      if (incident === undefined) return undefined;
      if (incident.status === "closed") {
        throw new StoreIncidentCaseStateError("closed case is immutable");
      }
      const workOrder = this.#workOrder(input.tenantId, input.workOrderId);
      if (workOrder === undefined) {
        throw new StoreAuthorizationError("work order is unknown");
      }
      if (workOrder.target_device_id !== incident.source_device_id) {
        throw new StoreAuthorizationError(
          "work order belongs to another case source",
        );
      }
      const existing = this.#database
        .prepare(
          `SELECT 1 AS present FROM incident_case_work_orders
           WHERE tenant_id = ? AND case_id = ? AND work_order_id = ?`,
        )
        .get(input.tenantId, input.caseId, input.workOrderId) as
        { present: number } | undefined;
      if (existing !== undefined) {
        return {
          incidentCase: this.#requiredIncidentCase(
            input.tenantId,
            input.caseId,
          ),
          idempotent: true,
        };
      }
      const count = this.#database
        .prepare(
          `SELECT COUNT(*) AS count FROM incident_case_work_orders
           WHERE tenant_id = ? AND case_id = ?`,
        )
        .get(input.tenantId, input.caseId) as { count: number };
      if (count.count >= MAX_INCIDENT_WORK_ORDERS_PER_CASE) {
        throw new StoreConflictError("incident work-order limit reached");
      }
      const summary = incidentWorkOrderSummary(mapWorkOrder(workOrder));
      this.#database
        .prepare(
          `INSERT INTO incident_case_work_orders
            (tenant_id, case_id, work_order_id, action_id, action_version,
             status, result_sha256, state_sha256, linked_at, observed_at)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
        )
        .run(
          input.tenantId,
          input.caseId,
          input.workOrderId,
          summary.actionId,
          summary.actionVersion,
          summary.status,
          summary.resultSha256,
          summary.stateSha256,
          input.linkedAt,
          input.linkedAt,
        );
      this.#database
        .prepare(
          `UPDATE incident_cases SET updated_at = ?
           WHERE tenant_id = ? AND case_id = ?`,
        )
        .run(input.linkedAt, input.tenantId, input.caseId);
      this.#recordIncidentCaseEvent({
        tenantId: input.tenantId,
        caseId: input.caseId,
        occurredAt: input.linkedAt,
        kind: "work_order_linked",
        actorType: "credential",
        actorId: input.credentialId,
        status: incident.status as IncidentCaseStatus,
        detailSha256: summary.stateSha256,
      });
      return {
        incidentCase: this.#requiredIncidentCase(input.tenantId, input.caseId),
        idempotent: false,
      };
    });
  }

  closeIncidentCase(
    input: {
      tenantId: string;
      caseId: string;
      outcome: IncidentCaseOutcome;
      credentialId: string;
      closedAt: string;
      requestSha256: string;
    },
    buildMaterial: (
      sequence: number,
      incidentCase: StoredIncidentCase,
      timeline: ListedIncidentCaseEvent[],
    ) => IncidentCaseClosureMaterial,
  ): IncidentCaseMutationResult | undefined {
    validateIncidentCaseClose(input);
    return this.#transaction(() => {
      this.#syncIncidentCaseWorkOrders(
        input.tenantId,
        input.caseId,
        input.closedAt,
      );
      const row = this.#incidentCase(input.tenantId, input.caseId);
      if (row === undefined) return undefined;
      if (row.status === "closed") {
        if (row.close_request_sha256 !== input.requestSha256) {
          throw new StoreIncidentCaseStateError(
            "incident closure conflicts with retained report",
          );
        }
        return { incidentCase: this.#mapIncidentCase(row), idempotent: true };
      }
      const checkpoint = this.#database
        .prepare(
          `SELECT last_sequence FROM service_receipt_checkpoints
           WHERE tenant_id = ? AND device_id = ?`,
        )
        .get(input.tenantId, row.source_device_id) as
        { last_sequence: number } | undefined;
      const sequence = (checkpoint?.last_sequence ?? 0) + 1;
      if (!Number.isSafeInteger(sequence) || sequence < 1) {
        throw new StoreConflictError("service receipt sequence exhausted");
      }
      const current = this.#mapIncidentCase(row);
      const timeline = this.#listIncidentCaseEvents(
        input.tenantId,
        input.caseId,
        false,
      );
      const material = buildMaterial(sequence, current, timeline);
      validateIncidentCaseClosureMaterial(material);
      this.#database
        .prepare(
          `INSERT INTO service_receipt_checkpoints
            (tenant_id, device_id, last_sequence, updated_at)
           VALUES (?, ?, ?, ?)
           ON CONFLICT (tenant_id, device_id) DO UPDATE SET
             last_sequence = excluded.last_sequence,
             updated_at = excluded.updated_at`,
        )
        .run(input.tenantId, row.source_device_id, sequence, input.closedAt);
      this.#database
        .prepare(
          `UPDATE incident_cases SET status = 'closed', outcome = ?,
             closed_by_credential_id = ?, closed_at = ?, updated_at = ?,
             close_request_sha256 = ?, report_sha256 = ?, report_json = ?,
             receipt_json = ?
           WHERE tenant_id = ? AND case_id = ? AND status <> 'closed'`,
        )
        .run(
          input.outcome,
          input.credentialId,
          input.closedAt,
          input.closedAt,
          input.requestSha256,
          material.reportSha256,
          material.reportJson,
          material.receiptJson,
          input.tenantId,
          input.caseId,
        );
      this.#recordIncidentCaseEvent({
        tenantId: input.tenantId,
        caseId: input.caseId,
        occurredAt: input.closedAt,
        kind: "closed",
        actorType: "credential",
        actorId: input.credentialId,
        status: "closed",
        detailSha256: material.reportSha256,
      });
      return {
        incidentCase: this.#requiredIncidentCase(input.tenantId, input.caseId),
        idempotent: false,
      };
    });
  }

  listIncidentCaseEvents(tenantId: string): ListedIncidentCaseEvent[] {
    if (!isPublicIdentifier(tenantId)) throw new Error("tenant ID is invalid");
    return this.#listIncidentCaseEvents(tenantId, null, true);
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
    enterpriseSeat?: { limit: number };
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
        if (input.enterpriseSeat !== undefined) {
          this.#assignEnterpriseSeat({
            tenantId: input.tenantId,
            kind: "device",
            subjectId: input.deviceId,
            limit: input.enterpriseSeat.limit,
            actorId: input.deviceId,
            assignedAt: input.enrolledAt,
          });
        }
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

  getAsset(tenantId: string, assetId: string): ListedAsset | undefined {
    if (!isPublicIdentifier(tenantId) || !isBoundedAssetId(assetId)) {
      throw new Error("asset lookup is invalid");
    }
    const row = this.#database
      .prepare(
        `SELECT asset_id, reporting_device_id, target_fingerprint, platform,
                architecture, os_release, health, critical_count, warning_count,
                info_count, snapshot_sha256, sequence, observed_at, updated_at
         FROM assets WHERE tenant_id = ? AND asset_id = ?`,
      )
      .get(tenantId, assetId) as AssetRow | undefined;
    return row === undefined
      ? undefined
      : {
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
        };
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

  revokeDevice(
    tenantId: string,
    deviceId: string,
    revokedAt: string,
    actorId = deviceId,
  ): boolean {
    return this.#transaction(() => {
      const existing = this.getDevice(tenantId, deviceId);
      if (existing === undefined) return false;
      if (existing.revokedAt === null) {
        const result = this.#database
          .prepare(
            `UPDATE devices SET revoked_at = ?
             WHERE tenant_id = ? AND device_id = ? AND revoked_at IS NULL`,
          )
          .run(revokedAt, tenantId, deviceId);
        if (result.changes !== 1) {
          throw new StoreConflictError("device revocation conflicted");
        }
        this.#revokeEnterpriseSeat({
          tenantId,
          kind: "device",
          subjectId: deviceId,
          actorId,
          revokedAt,
        });
      }
      return true;
    });
  }

  #enterpriseLicenseRow(tenantId: string): EnterpriseLicenseRow | undefined {
    return this.#database
      .prepare(
        `SELECT tenant_id, license_id, sequence, key_id, plan, features_json,
                device_limit, seat_limit, issued_at_unix, not_before_unix,
                expires_at_unix, grace_until_unix, envelope_sha256,
                canonical_json, imported_at, revoked_at
         FROM enterprise_licenses WHERE tenant_id = ?`,
      )
      .get(tenantId) as EnterpriseLicenseRow | undefined;
  }

  #assignEnterpriseSeat(input: {
    tenantId: string;
    kind: EnterpriseSeatKind;
    subjectId: string;
    limit: number;
    actorId: string;
    assignedAt: string;
  }): { assignmentId: string; idempotent: boolean } {
    validateEnterpriseSeatMutation(input);
    const assignmentId = enterpriseSeatAssignmentId(
      input.tenantId,
      input.kind,
      input.subjectId,
    );
    const existing = this.#database
      .prepare(
        `SELECT assignment_id, tenant_id, kind, subject_id, assigned_at,
                revoked_at FROM enterprise_license_seats
         WHERE tenant_id = ? AND kind = ? AND subject_id = ?`,
      )
      .get(input.tenantId, input.kind, input.subjectId) as
      EnterpriseLicenseSeatRow | undefined;
    if (existing?.revoked_at === null) {
      return { assignmentId: existing.assignment_id, idempotent: true };
    }
    const active = this.#database
      .prepare(
        `SELECT COUNT(*) AS count FROM enterprise_license_seats
         WHERE tenant_id = ? AND kind = ? AND revoked_at IS NULL`,
      )
      .get(input.tenantId, input.kind) as { count: number };
    if (active.count >= input.limit) {
      throw new StoreEnterpriseSeatLimitError(
        `${input.kind} enterprise seat limit reached`,
      );
    }
    this.#database
      .prepare(
        `INSERT INTO enterprise_license_seats
          (assignment_id, tenant_id, kind, subject_id, assigned_at, revoked_at)
         VALUES (?, ?, ?, ?, ?, NULL)
         ON CONFLICT (tenant_id, kind, subject_id) DO UPDATE SET
           assigned_at = excluded.assigned_at, revoked_at = NULL`,
      )
      .run(
        assignmentId,
        input.tenantId,
        input.kind,
        input.subjectId,
        input.assignedAt,
      );
    this.#appendEnterpriseLicenseEvent({
      tenantId: input.tenantId,
      occurredAt: input.assignedAt,
      kind: "seat_assigned",
      actorId: input.actorId,
      detailSha256: sha256(
        `kernaid:fleet:enterprise-seat:v1\0${input.kind}\0${input.subjectId}`,
      ),
    });
    return { assignmentId, idempotent: false };
  }

  #revokeEnterpriseSeat(input: {
    tenantId: string;
    kind: EnterpriseSeatKind;
    subjectId: string;
    actorId: string;
    revokedAt: string;
  }): boolean {
    validateEnterpriseSeatMutation({
      ...input,
      limit: 1,
      assignedAt: input.revokedAt,
    });
    const changed = this.#database
      .prepare(
        `UPDATE enterprise_license_seats SET revoked_at = ?
         WHERE tenant_id = ? AND kind = ? AND subject_id = ?
           AND revoked_at IS NULL`,
      )
      .run(input.revokedAt, input.tenantId, input.kind, input.subjectId);
    if (changed.changes === 0) return false;
    this.#appendEnterpriseLicenseEvent({
      tenantId: input.tenantId,
      occurredAt: input.revokedAt,
      kind: "seat_revoked",
      actorId: input.actorId,
      detailSha256: sha256(
        `kernaid:fleet:enterprise-seat:v1\0${input.kind}\0${input.subjectId}`,
      ),
    });
    return true;
  }

  #appendEnterpriseLicenseEvent(input: {
    tenantId: string;
    occurredAt: string;
    kind: EnterpriseLicenseEvent["kind"];
    actorId: string;
    detailSha256: string;
  }): void {
    const current = this.#database
      .prepare(
        `SELECT COALESCE(MAX(sequence), 0) AS sequence
         FROM enterprise_license_events WHERE tenant_id = ?`,
      )
      .get(input.tenantId) as { sequence: number };
    const sequence = current.sequence + 1;
    if (!Number.isSafeInteger(sequence) || sequence < 1) {
      throw new StoreConflictError(
        "enterprise license event sequence exhausted",
      );
    }
    this.#database
      .prepare(
        `INSERT INTO enterprise_license_events
          (tenant_id, sequence, occurred_at, kind, actor_id, detail_sha256)
         VALUES (?, ?, ?, ?, ?, ?)`,
      )
      .run(
        input.tenantId,
        sequence,
        input.occurredAt,
        input.kind,
        input.actorId,
        input.detailSha256,
      );
    this.#database
      .prepare(
        `DELETE FROM enterprise_license_events
         WHERE tenant_id = ? AND sequence <= ?`,
      )
      .run(input.tenantId, sequence - MAX_ENTERPRISE_LICENSE_EVENTS);
  }

  #insertTenantAccessCredential(input: {
    tenantId: string;
    credentialId: string;
    tokenHash: string;
    role: TenantRole;
    label: string;
    createdAt: string;
  }): void {
    this.#database
      .prepare(
        `INSERT INTO tenant_access_credentials
          (tenant_id, credential_id, token_hash, role, label, created_at, revoked_at)
         VALUES (?, ?, ?, ?, ?, ?, NULL)`,
      )
      .run(
        input.tenantId,
        input.credentialId,
        input.tokenHash,
        input.role,
        input.label,
        input.createdAt,
      );
  }

  #incidentCase(tenantId: string, caseId: string): IncidentCaseRow | undefined {
    return this.#database
      .prepare(
        `SELECT * FROM incident_cases WHERE tenant_id = ? AND case_id = ?`,
      )
      .get(tenantId, caseId) as IncidentCaseRow | undefined;
  }

  #requiredIncidentCase(tenantId: string, caseId: string): StoredIncidentCase {
    const row = this.#incidentCase(tenantId, caseId);
    if (row === undefined) throw new Error("stored incident case disappeared");
    return this.#mapIncidentCase(row);
  }

  #mapIncidentCase(row: IncidentCaseRow): StoredIncidentCase {
    validateIncidentCaseRow(row);
    const workOrders = this.#database
      .prepare(
        `SELECT * FROM incident_case_work_orders
         WHERE tenant_id = ? AND case_id = ?
         ORDER BY linked_at, work_order_id`,
      )
      .all(row.tenant_id, row.case_id) as unknown as IncidentCaseWorkOrderRow[];
    return {
      tenantId: row.tenant_id,
      caseId: row.case_id,
      requestId: row.request_id,
      sourceDeviceId: row.source_device_id,
      sourceAssetId: row.source_asset_id,
      severity: row.severity as IncidentCaseSeverity,
      status: row.status as IncidentCaseStatus,
      assigneeLabel: row.assignee_label,
      createdByCredentialId: row.created_by_credential_id,
      createdAt: row.created_at,
      updatedAt: row.updated_at,
      outcome: row.outcome as IncidentCaseOutcome | null,
      closedByCredentialId: row.closed_by_credential_id,
      closedAt: row.closed_at,
      closeRequestSha256: row.close_request_sha256,
      reportSha256: row.report_sha256,
      reportJson: row.report_json,
      receiptJson: row.receipt_json,
      workOrders: workOrders.map(mapIncidentCaseWorkOrder),
    };
  }

  #syncIncidentCaseWorkOrders(
    tenantId: string,
    caseId: string | null,
    observedAt: string,
  ): void {
    const rows = (caseId === null
      ? this.#database
          .prepare(
            `SELECT link.*, cases.status AS case_status,
                    orders.action_id AS current_action_id,
                    orders.action_version AS current_action_version,
                    orders.status AS current_status,
                    orders.result_sha256 AS current_result_sha256
             FROM incident_case_work_orders AS link
             JOIN incident_cases AS cases
               ON cases.tenant_id = link.tenant_id
              AND cases.case_id = link.case_id
             JOIN work_orders AS orders
               ON orders.tenant_id = link.tenant_id
              AND orders.work_order_id = link.work_order_id
             WHERE link.tenant_id = ? AND cases.status <> 'closed'`,
          )
          .all(tenantId)
      : this.#database
          .prepare(
            `SELECT link.*, cases.status AS case_status,
                    orders.action_id AS current_action_id,
                    orders.action_version AS current_action_version,
                    orders.status AS current_status,
                    orders.result_sha256 AS current_result_sha256
             FROM incident_case_work_orders AS link
             JOIN incident_cases AS cases
               ON cases.tenant_id = link.tenant_id
              AND cases.case_id = link.case_id
             JOIN work_orders AS orders
               ON orders.tenant_id = link.tenant_id
              AND orders.work_order_id = link.work_order_id
             WHERE link.tenant_id = ? AND link.case_id = ?
               AND cases.status <> 'closed'`,
          )
          .all(tenantId, caseId)) as unknown as IncidentCaseWorkOrderSyncRow[];
    for (const row of rows) {
      const summary = incidentWorkOrderSummary({
        workOrderId: row.work_order_id,
        actionId: row.current_action_id as WorkOrderActionId,
        actionVersion: row.current_action_version,
        status: row.current_status as WorkOrderStatus,
        resultSha256: row.current_result_sha256,
      });
      if (summary.stateSha256 === row.state_sha256) continue;
      this.#database
        .prepare(
          `UPDATE incident_case_work_orders SET status = ?, result_sha256 = ?,
             state_sha256 = ?, observed_at = ?
           WHERE tenant_id = ? AND case_id = ? AND work_order_id = ?`,
        )
        .run(
          summary.status,
          summary.resultSha256,
          summary.stateSha256,
          observedAt,
          tenantId,
          row.case_id,
          row.work_order_id,
        );
      this.#database
        .prepare(
          `UPDATE incident_cases SET updated_at = ?
           WHERE tenant_id = ? AND case_id = ?`,
        )
        .run(observedAt, tenantId, row.case_id);
      this.#recordIncidentCaseEvent({
        tenantId,
        caseId: row.case_id,
        occurredAt: observedAt,
        kind: "work_order_state",
        actorType: "system",
        actorId: "fleet-control-plane",
        status: row.case_status as IncidentCaseStatus,
        detailSha256: summary.stateSha256,
      });
    }
  }

  #recordIncidentCaseEvent(
    input: Omit<ListedIncidentCaseEvent, "sequence">,
  ): void {
    const current = this.#database
      .prepare(
        `SELECT COALESCE(MAX(sequence), 0) AS sequence
         FROM incident_case_events WHERE tenant_id = ?`,
      )
      .get(input.tenantId) as { sequence: number };
    const sequence = current.sequence + 1;
    if (!Number.isSafeInteger(sequence) || sequence < 1) {
      throw new StoreConflictError("incident event sequence exhausted");
    }
    this.#database
      .prepare(
        `INSERT INTO incident_case_events
          (tenant_id, sequence, case_id, occurred_at, kind, actor_type,
           actor_id, status, detail_sha256)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
      )
      .run(
        input.tenantId,
        sequence,
        input.caseId,
        input.occurredAt,
        input.kind,
        input.actorType,
        input.actorId,
        input.status,
        input.detailSha256,
      );
    this.#database
      .prepare(
        `DELETE FROM incident_case_events
         WHERE tenant_id = ? AND sequence <= ?`,
      )
      .run(input.tenantId, sequence - MAX_INCIDENT_EVENTS_PER_TENANT);
  }

  #listIncidentCaseEvents(
    tenantId: string,
    caseId: string | null,
    descending: boolean,
  ): ListedIncidentCaseEvent[] {
    const order = descending ? "DESC" : "ASC";
    const rows = (caseId === null
      ? this.#database
          .prepare(
            `SELECT * FROM incident_case_events WHERE tenant_id = ?
             ORDER BY sequence ${order} LIMIT ?`,
          )
          .all(tenantId, MAX_LISTED_INCIDENT_EVENTS)
      : this.#database
          .prepare(
            `SELECT * FROM incident_case_events
             WHERE tenant_id = ? AND case_id = ?
             ORDER BY sequence ${order} LIMIT ?`,
          )
          .all(
            tenantId,
            caseId,
            MAX_LISTED_INCIDENT_EVENTS,
          )) as unknown as IncidentCaseEventRow[];
    return rows.map(mapIncidentCaseEvent);
  }

  #workOrder(tenantId: string, workOrderId: string): WorkOrderRow | undefined {
    return this.#database
      .prepare(
        `SELECT * FROM work_orders
         WHERE tenant_id = ? AND work_order_id = ?`,
      )
      .get(tenantId, workOrderId) as WorkOrderRow | undefined;
  }

  #requiredWorkOrder(tenantId: string, workOrderId: string): StoredWorkOrder {
    const row = this.#workOrder(tenantId, workOrderId);
    if (row === undefined) throw new Error("stored work order disappeared");
    return mapWorkOrder(row);
  }

  #expireWorkOrders(tenantId: string, nowMs: number, now: string): void {
    const rows = this.#database
      .prepare(
        `SELECT work_order_id FROM work_orders
         WHERE tenant_id = ? AND expires_at_ms <= ?
           AND status IN ('pending_approval','queued','leased')`,
      )
      .all(tenantId, nowMs) as unknown as { work_order_id: string }[];
    for (const row of rows) {
      this.#database
        .prepare(
          `UPDATE work_orders SET status = 'expired'
           WHERE tenant_id = ? AND work_order_id = ?`,
        )
        .run(tenantId, row.work_order_id);
      this.#recordWorkOrderEvent({
        tenantId,
        workOrderId: row.work_order_id,
        occurredAt: now,
        kind: "expired",
        actorType: "system",
        actorId: "fleet-control-plane",
        status: "expired",
        detailSha256: null,
      });
    }
  }

  #releaseExpiredLeases(
    tenantId: string,
    deviceId: string,
    nowMs: number,
    now: string,
  ): void {
    const rows = this.#database
      .prepare(
        `SELECT work_order_id FROM work_orders
         WHERE tenant_id = ? AND target_device_id = ? AND status = 'leased'
           AND lease_expires_at_ms <= ? AND expires_at_ms > ?`,
      )
      .all(tenantId, deviceId, nowMs, nowMs) as unknown as {
      work_order_id: string;
    }[];
    for (const row of rows) {
      this.#database
        .prepare(
          `UPDATE work_orders SET status = 'queued', lease_id = NULL,
             leased_at = NULL, lease_expires_at = NULL,
             lease_expires_at_ms = NULL
           WHERE tenant_id = ? AND work_order_id = ? AND status = 'leased'`,
        )
        .run(tenantId, row.work_order_id);
      this.#recordWorkOrderEvent({
        tenantId,
        workOrderId: row.work_order_id,
        occurredAt: now,
        kind: "lease_expired",
        actorType: "system",
        actorId: "fleet-control-plane",
        status: "queued",
        detailSha256: null,
      });
    }
  }

  #recordWorkOrderEvent(input: Omit<ListedWorkOrderEvent, "sequence">): void {
    const current = this.#database
      .prepare(
        `SELECT COALESCE(MAX(sequence), 0) AS sequence
         FROM work_order_events WHERE tenant_id = ?`,
      )
      .get(input.tenantId) as { sequence: number };
    const sequence = current.sequence + 1;
    if (!Number.isSafeInteger(sequence) || sequence < 1) {
      throw new StoreConflictError("work-order event sequence exhausted");
    }
    this.#database
      .prepare(
        `INSERT INTO work_order_events
          (tenant_id, sequence, work_order_id, occurred_at, kind, actor_type,
           actor_id, status, detail_sha256)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
      )
      .run(
        input.tenantId,
        sequence,
        input.workOrderId,
        input.occurredAt,
        input.kind,
        input.actorType,
        input.actorId,
        input.status,
        input.detailSha256,
      );
    this.#database
      .prepare(
        `DELETE FROM work_order_events
         WHERE tenant_id = ? AND sequence <= ?`,
      )
      .run(input.tenantId, sequence - MAX_WORK_ORDER_EVENTS_PER_TENANT);
  }

  #recordServicePullNonce(
    operation: FleetServiceOperation,
    tenantId: string,
    deviceId: string,
    nonce: ServicePullNonce,
  ): void {
    let table: "policy_pull_nonces" | "entitlement_pull_nonces";
    let limit: number;
    let replayError: new (message: string) => Error;
    if (operation === "policy_pull") {
      table = "policy_pull_nonces";
      limit = MAX_RECENT_POLICY_PULL_NONCES_PER_DEVICE;
      replayError = StoreNonceReplayError;
    } else if (operation === "entitlement_pull") {
      table = "entitlement_pull_nonces";
      limit = MAX_RECENT_ENTITLEMENT_PULL_NONCES_PER_DEVICE;
      replayError = StoreEntitlementPullReplayError;
    } else {
      throw new Error("service receipt pull nonce has an invalid operation");
    }

    this.#database
      .prepare(`DELETE FROM ${table} WHERE expires_at_ms <= ?`)
      .run(nonce.nowMs);
    const recent = this.#database
      .prepare(
        `SELECT COUNT(*) AS count FROM ${table}
         WHERE tenant_id = ? AND device_id = ?`,
      )
      .get(tenantId, deviceId) as { count: number };
    if (recent.count >= limit) {
      throw new StoreConflictError("recent service pull limit reached");
    }
    try {
      this.#database
        .prepare(
          `INSERT INTO ${table}
            (tenant_id, device_id, nonce_sha256, expires_at_ms)
           VALUES (?, ?, ?, ?)`,
        )
        .run(tenantId, deviceId, nonce.nonceSha256, nonce.expiresAtMs);
    } catch (error) {
      if (isSqliteConstraint(error)) {
        throw new replayError("service pull nonce was reused");
      }
      throw error;
    }
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
    if (version.user_version > 11) {
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
      currentVersion = 5;
    }

    if (currentVersion === 5) {
      this.#transaction(() => {
        this.#database.exec(`
          CREATE TABLE service_receipt_config (
            singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
            anchor_sha256 TEXT NOT NULL
          ) STRICT;

          CREATE TABLE service_receipt_checkpoints (
            tenant_id TEXT NOT NULL,
            device_id TEXT NOT NULL,
            last_sequence INTEGER NOT NULL CHECK (last_sequence > 0),
            updated_at TEXT NOT NULL,
            PRIMARY KEY (tenant_id, device_id),
            FOREIGN KEY (tenant_id, device_id)
              REFERENCES devices(tenant_id, device_id)
              ON DELETE CASCADE
          ) STRICT;

          CREATE TABLE service_receipts (
            tenant_id TEXT NOT NULL,
            device_id TEXT NOT NULL,
            operation TEXT NOT NULL CHECK (
              operation IN ('inventory', 'audit', 'policy_pull', 'entitlement_pull')
            ),
            sequence INTEGER NOT NULL CHECK (sequence > 0),
            request_sha256 TEXT NOT NULL,
            response_sha256 TEXT NOT NULL,
            status INTEGER NOT NULL CHECK (status IN (200, 201)),
            response_body TEXT NOT NULL,
            receipt_json TEXT NOT NULL,
            created_at TEXT NOT NULL,
            PRIMARY KEY (tenant_id, device_id, sequence),
            FOREIGN KEY (tenant_id, device_id)
              REFERENCES service_receipt_checkpoints(tenant_id, device_id)
              ON DELETE CASCADE
          ) STRICT;
          CREATE INDEX service_receipts_request_idx
            ON service_receipts(
              tenant_id, device_id, operation, request_sha256, sequence DESC
            );

          PRAGMA user_version = 6;
        `);
      });
      currentVersion = 6;
    }

    if (currentVersion === 6) {
      this.#transaction(() => {
        this.#database.exec(`
          CREATE TABLE tenant_access_credentials (
            tenant_id TEXT NOT NULL REFERENCES tenants(tenant_id),
            credential_id TEXT NOT NULL,
            token_hash TEXT NOT NULL UNIQUE CHECK (
              length(token_hash) = 64 AND
              token_hash NOT GLOB '*[^0-9a-f]*'
            ),
            role TEXT NOT NULL CHECK (role IN ('admin', 'operator')),
            label TEXT NOT NULL CHECK (length(label) BETWEEN 1 AND 80),
            created_at TEXT NOT NULL,
            revoked_at TEXT,
            PRIMARY KEY (tenant_id, credential_id)
          ) STRICT;
          CREATE INDEX tenant_access_credentials_active_idx
            ON tenant_access_credentials(tenant_id, role, revoked_at);

          INSERT INTO tenant_access_credentials
            (tenant_id, credential_id, token_hash, role, label, created_at, revoked_at)
          SELECT tenant_id, 'bootstrap-admin', admin_token_hash, 'admin',
                 'Initial tenant administrator', created_at, NULL
          FROM tenants;

          CREATE TABLE tenant_access_audit (
            tenant_id TEXT NOT NULL REFERENCES tenants(tenant_id),
            sequence INTEGER NOT NULL CHECK (sequence > 0),
            occurred_at TEXT NOT NULL,
            credential_id TEXT NOT NULL,
            role TEXT NOT NULL CHECK (role IN ('admin', 'operator')),
            action TEXT NOT NULL CHECK (action IN (
              'access_audit.list',
              'asset.list',
              'credential.create',
              'credential.list',
              'credential.revoke',
              'device.list',
              'device.revoke',
              'device_audit.list',
              'enrollment_token.create',
              'entitlement.list',
              'entitlement.publish',
              'entitlement_revocations.publish',
              'policy.list',
              'policy.publish',
              'policy_trust_anchor.set',
              'update.list',
              'update.publish'
            )),
            outcome TEXT NOT NULL CHECK (outcome IN ('allowed', 'denied')),
            target_tenant_id TEXT NOT NULL,
            target_type TEXT NOT NULL CHECK (
              target_type IN ('credential', 'device', 'tenant')
            ),
            target_id TEXT NOT NULL,
            PRIMARY KEY (tenant_id, sequence),
            FOREIGN KEY (tenant_id, credential_id)
              REFERENCES tenant_access_credentials(tenant_id, credential_id)
          ) STRICT;
          CREATE INDEX tenant_access_audit_recent_idx
            ON tenant_access_audit(tenant_id, sequence DESC);

          PRAGMA user_version = 7;
        `);
      });
      currentVersion = 7;
    }

    if (currentVersion === 7) {
      this.#transaction(() => {
        this.#database.exec(`
          DROP INDEX tenant_access_audit_recent_idx;
          ALTER TABLE tenant_access_audit RENAME TO tenant_access_audit_v7;
          CREATE TABLE tenant_access_audit (
            tenant_id TEXT NOT NULL REFERENCES tenants(tenant_id),
            sequence INTEGER NOT NULL CHECK (sequence > 0),
            occurred_at TEXT NOT NULL,
            credential_id TEXT NOT NULL,
            role TEXT NOT NULL CHECK (role IN ('admin', 'operator')),
            action TEXT NOT NULL CHECK (action IN (
              'access_audit.list', 'asset.list', 'credential.create',
              'credential.list', 'credential.revoke', 'device.list',
              'device.revoke', 'device_audit.list',
              'enrollment_token.create', 'entitlement.list',
              'entitlement.publish', 'entitlement_revocations.publish',
              'policy.list', 'policy.publish', 'policy_trust_anchor.set',
              'update.list', 'update.publish', 'work_order.approve',
              'work_order.cancel', 'work_order.create', 'work_order.list',
              'work_order_audit.list'
            )),
            outcome TEXT NOT NULL CHECK (outcome IN ('allowed', 'denied')),
            target_tenant_id TEXT NOT NULL,
            target_type TEXT NOT NULL CHECK (
              target_type IN ('credential', 'device', 'tenant', 'work_order')
            ),
            target_id TEXT NOT NULL,
            PRIMARY KEY (tenant_id, sequence),
            FOREIGN KEY (tenant_id, credential_id)
              REFERENCES tenant_access_credentials(tenant_id, credential_id)
          ) STRICT;
          INSERT INTO tenant_access_audit SELECT * FROM tenant_access_audit_v7;
          DROP TABLE tenant_access_audit_v7;
          CREATE INDEX tenant_access_audit_recent_idx
            ON tenant_access_audit(tenant_id, sequence DESC);

          DROP INDEX service_receipts_request_idx;
          ALTER TABLE service_receipts RENAME TO service_receipts_v7;
          CREATE TABLE service_receipts (
            tenant_id TEXT NOT NULL,
            device_id TEXT NOT NULL,
            operation TEXT NOT NULL CHECK (operation IN (
              'inventory', 'audit', 'policy_pull', 'entitlement_pull',
              'work_order_claim', 'work_order_result'
            )),
            sequence INTEGER NOT NULL CHECK (sequence > 0),
            request_sha256 TEXT NOT NULL,
            response_sha256 TEXT NOT NULL,
            status INTEGER NOT NULL CHECK (status IN (200, 201)),
            response_body TEXT NOT NULL,
            receipt_json TEXT NOT NULL,
            created_at TEXT NOT NULL,
            PRIMARY KEY (tenant_id, device_id, sequence),
            FOREIGN KEY (tenant_id, device_id)
              REFERENCES service_receipt_checkpoints(tenant_id, device_id)
              ON DELETE CASCADE
          ) STRICT;
          INSERT INTO service_receipts SELECT * FROM service_receipts_v7;
          DROP TABLE service_receipts_v7;
          CREATE INDEX service_receipts_request_idx
            ON service_receipts(
              tenant_id, device_id, operation, request_sha256, sequence DESC
            );

          CREATE TABLE work_orders (
            tenant_id TEXT NOT NULL REFERENCES tenants(tenant_id),
            work_order_id TEXT NOT NULL,
            request_id TEXT NOT NULL,
            request_sha256 TEXT NOT NULL CHECK (
              length(request_sha256) = 64 AND
              request_sha256 NOT GLOB '*[^0-9a-f]*'
            ),
            target_device_id TEXT NOT NULL,
            action_id TEXT NOT NULL CHECK (action_id IN (
              'linux.boot-critical-path.v1',
              'linux.filesystem.health.v1',
              'linux.storage.health.v1',
              'linux.fstab.disable-missing-uuid.v1'
            )),
            action_version INTEGER NOT NULL CHECK (action_version = 1),
            kind TEXT NOT NULL CHECK (kind IN ('diagnosis', 'repair')),
            risk TEXT NOT NULL CHECK (risk IN ('R0', 'R1', 'R2', 'R3')),
            local_approval_required INTEGER NOT NULL CHECK (
              local_approval_required IN (0, 1)
            ),
            status TEXT NOT NULL CHECK (status IN (
              'pending_approval', 'queued', 'leased', 'succeeded', 'failed',
              'rejected', 'cancelled', 'expired'
            )),
            created_by_credential_id TEXT NOT NULL,
            created_at TEXT NOT NULL,
            expires_at TEXT NOT NULL,
            expires_at_ms INTEGER NOT NULL,
            approved_by_credential_id TEXT,
            approved_at TEXT,
            lease_id TEXT,
            leased_at TEXT,
            lease_expires_at TEXT,
            lease_expires_at_ms INTEGER,
            outcome TEXT CHECK (outcome IN ('succeeded', 'failed', 'rejected')),
            result_sha256 TEXT,
            result_envelope_sha256 TEXT,
            completed_at TEXT,
            cancelled_by_credential_id TEXT,
            cancelled_at TEXT,
            PRIMARY KEY (tenant_id, work_order_id),
            UNIQUE (tenant_id, request_id),
            FOREIGN KEY (tenant_id, target_device_id)
              REFERENCES devices(tenant_id, device_id),
            FOREIGN KEY (tenant_id, created_by_credential_id)
              REFERENCES tenant_access_credentials(tenant_id, credential_id),
            FOREIGN KEY (tenant_id, approved_by_credential_id)
              REFERENCES tenant_access_credentials(tenant_id, credential_id),
            FOREIGN KEY (tenant_id, cancelled_by_credential_id)
              REFERENCES tenant_access_credentials(tenant_id, credential_id)
          ) STRICT;
          CREATE INDEX work_orders_queue_idx ON work_orders(
            tenant_id, target_device_id, status, created_at, work_order_id
          );

          CREATE TABLE work_order_claims (
            tenant_id TEXT NOT NULL,
            device_id TEXT NOT NULL,
            nonce_sha256 TEXT NOT NULL,
            request_sha256 TEXT NOT NULL,
            work_order_id TEXT,
            lease_id TEXT,
            expires_at_ms INTEGER NOT NULL,
            CHECK ((work_order_id IS NULL AND lease_id IS NULL) OR
                   (work_order_id IS NOT NULL AND lease_id IS NOT NULL)),
            PRIMARY KEY (tenant_id, device_id, nonce_sha256),
            FOREIGN KEY (tenant_id, device_id)
              REFERENCES devices(tenant_id, device_id) ON DELETE CASCADE,
            FOREIGN KEY (tenant_id, work_order_id)
              REFERENCES work_orders(tenant_id, work_order_id) ON DELETE CASCADE
          ) STRICT;
          CREATE INDEX work_order_claims_expiry_idx
            ON work_order_claims(expires_at_ms);

          CREATE TABLE work_order_events (
            tenant_id TEXT NOT NULL,
            sequence INTEGER NOT NULL CHECK (sequence > 0),
            work_order_id TEXT NOT NULL,
            occurred_at TEXT NOT NULL,
            kind TEXT NOT NULL CHECK (kind IN (
              'created', 'approved', 'leased', 'lease_expired', 'completed',
              'cancelled', 'expired'
            )),
            actor_type TEXT NOT NULL CHECK (
              actor_type IN ('credential', 'device', 'system')
            ),
            actor_id TEXT NOT NULL,
            status TEXT NOT NULL CHECK (status IN (
              'pending_approval', 'queued', 'leased', 'succeeded', 'failed',
              'rejected', 'cancelled', 'expired'
            )),
            detail_sha256 TEXT,
            PRIMARY KEY (tenant_id, sequence),
            FOREIGN KEY (tenant_id, work_order_id)
              REFERENCES work_orders(tenant_id, work_order_id) ON DELETE CASCADE
          ) STRICT;
          CREATE INDEX work_order_events_recent_idx
            ON work_order_events(tenant_id, sequence DESC);

          PRAGMA user_version = 8;
        `);
      });
      currentVersion = 8;
    }

    if (currentVersion === 8) {
      this.#transaction(() => {
        this.#database.exec(`
          DROP INDEX tenant_access_audit_recent_idx;
          ALTER TABLE tenant_access_audit RENAME TO tenant_access_audit_v8;
          CREATE TABLE tenant_access_audit (
            tenant_id TEXT NOT NULL REFERENCES tenants(tenant_id),
            sequence INTEGER NOT NULL CHECK (sequence > 0),
            occurred_at TEXT NOT NULL,
            credential_id TEXT NOT NULL,
            role TEXT NOT NULL CHECK (role IN ('admin', 'operator')),
            action TEXT NOT NULL CHECK (action IN (
              'access_audit.list', 'asset.list', 'credential.create',
              'credential.list', 'credential.revoke', 'device.list',
              'device.revoke', 'device_audit.list',
              'enrollment_token.create', 'entitlement.list',
              'entitlement.publish', 'entitlement_revocations.publish',
              'incident_case.audit.list', 'incident_case.close',
              'incident_case.create', 'incident_case.link_work_order',
              'incident_case.list', 'incident_case.update', 'policy.list',
              'policy.publish', 'policy_trust_anchor.set', 'update.list',
              'update.publish', 'work_order.approve', 'work_order.cancel',
              'work_order.create', 'work_order.list',
              'work_order_audit.list'
            )),
            outcome TEXT NOT NULL CHECK (outcome IN ('allowed', 'denied')),
            target_tenant_id TEXT NOT NULL,
            target_type TEXT NOT NULL CHECK (target_type IN (
              'credential', 'device', 'incident_case', 'tenant', 'work_order'
            )),
            target_id TEXT NOT NULL,
            PRIMARY KEY (tenant_id, sequence),
            FOREIGN KEY (tenant_id, credential_id)
              REFERENCES tenant_access_credentials(tenant_id, credential_id)
          ) STRICT;
          INSERT INTO tenant_access_audit SELECT * FROM tenant_access_audit_v8;
          DROP TABLE tenant_access_audit_v8;
          CREATE INDEX tenant_access_audit_recent_idx
            ON tenant_access_audit(tenant_id, sequence DESC);

          DROP INDEX service_receipts_request_idx;
          ALTER TABLE service_receipts RENAME TO service_receipts_v8;
          CREATE TABLE service_receipts (
            tenant_id TEXT NOT NULL,
            device_id TEXT NOT NULL,
            operation TEXT NOT NULL CHECK (operation IN (
              'inventory', 'audit', 'policy_pull', 'entitlement_pull',
              'work_order_claim', 'work_order_result', 'incident_case_close'
            )),
            sequence INTEGER NOT NULL CHECK (sequence > 0),
            request_sha256 TEXT NOT NULL,
            response_sha256 TEXT NOT NULL,
            status INTEGER NOT NULL CHECK (status IN (200, 201)),
            response_body TEXT NOT NULL,
            receipt_json TEXT NOT NULL,
            created_at TEXT NOT NULL,
            PRIMARY KEY (tenant_id, device_id, sequence),
            FOREIGN KEY (tenant_id, device_id)
              REFERENCES service_receipt_checkpoints(tenant_id, device_id)
              ON DELETE CASCADE
          ) STRICT;
          INSERT INTO service_receipts SELECT * FROM service_receipts_v8;
          DROP TABLE service_receipts_v8;
          CREATE INDEX service_receipts_request_idx
            ON service_receipts(
              tenant_id, device_id, operation, request_sha256, sequence DESC
            );

          CREATE TABLE incident_cases (
            tenant_id TEXT NOT NULL REFERENCES tenants(tenant_id),
            case_id TEXT NOT NULL,
            request_id TEXT NOT NULL,
            request_sha256 TEXT NOT NULL CHECK (
              length(request_sha256) = 64 AND
              request_sha256 NOT GLOB '*[^0-9a-f]*'
            ),
            source_device_id TEXT NOT NULL,
            source_asset_id TEXT,
            severity TEXT NOT NULL CHECK (
              severity IN ('low', 'medium', 'high', 'critical')
            ),
            status TEXT NOT NULL CHECK (
              status IN ('open', 'investigating', 'monitoring', 'closed')
            ),
            assignee_label TEXT CHECK (length(assignee_label) BETWEEN 1 AND 64),
            created_by_credential_id TEXT NOT NULL,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL,
            outcome TEXT CHECK (
              outcome IN ('resolved', 'mitigated', 'unresolved', 'false_positive')
            ),
            closed_by_credential_id TEXT,
            closed_at TEXT,
            close_request_sha256 TEXT,
            report_sha256 TEXT,
            report_json TEXT,
            receipt_json TEXT,
            CHECK (
              (status <> 'closed' AND outcome IS NULL AND
               closed_by_credential_id IS NULL AND closed_at IS NULL AND
               close_request_sha256 IS NULL AND report_sha256 IS NULL AND
               report_json IS NULL AND receipt_json IS NULL) OR
              (status = 'closed' AND outcome IS NOT NULL AND
               closed_by_credential_id IS NOT NULL AND closed_at IS NOT NULL AND
               close_request_sha256 IS NOT NULL AND report_sha256 IS NOT NULL AND
               report_json IS NOT NULL AND receipt_json IS NOT NULL)
            ),
            PRIMARY KEY (tenant_id, case_id),
            UNIQUE (tenant_id, request_id),
            FOREIGN KEY (tenant_id, source_device_id)
              REFERENCES devices(tenant_id, device_id),
            FOREIGN KEY (tenant_id, source_asset_id)
              REFERENCES assets(tenant_id, asset_id),
            FOREIGN KEY (tenant_id, created_by_credential_id)
              REFERENCES tenant_access_credentials(tenant_id, credential_id),
            FOREIGN KEY (tenant_id, closed_by_credential_id)
              REFERENCES tenant_access_credentials(tenant_id, credential_id)
          ) STRICT;
          CREATE INDEX incident_cases_recent_idx
            ON incident_cases(tenant_id, updated_at DESC, case_id DESC);

          CREATE TABLE incident_case_work_orders (
            tenant_id TEXT NOT NULL,
            case_id TEXT NOT NULL,
            work_order_id TEXT NOT NULL,
            action_id TEXT NOT NULL,
            action_version INTEGER NOT NULL CHECK (action_version > 0),
            status TEXT NOT NULL CHECK (status IN (
              'pending_approval', 'queued', 'leased', 'succeeded', 'failed',
              'rejected', 'cancelled', 'expired'
            )),
            result_sha256 TEXT,
            state_sha256 TEXT NOT NULL CHECK (length(state_sha256) = 64),
            linked_at TEXT NOT NULL,
            observed_at TEXT NOT NULL,
            PRIMARY KEY (tenant_id, case_id, work_order_id),
            FOREIGN KEY (tenant_id, case_id)
              REFERENCES incident_cases(tenant_id, case_id) ON DELETE CASCADE,
            FOREIGN KEY (tenant_id, work_order_id)
              REFERENCES work_orders(tenant_id, work_order_id)
          ) STRICT;

          CREATE TABLE incident_case_events (
            tenant_id TEXT NOT NULL,
            sequence INTEGER NOT NULL CHECK (sequence > 0),
            case_id TEXT NOT NULL,
            occurred_at TEXT NOT NULL,
            kind TEXT NOT NULL CHECK (kind IN (
              'created', 'updated', 'work_order_linked',
              'work_order_state', 'closed'
            )),
            actor_type TEXT NOT NULL CHECK (
              actor_type IN ('credential', 'system')
            ),
            actor_id TEXT NOT NULL,
            status TEXT NOT NULL CHECK (
              status IN ('open', 'investigating', 'monitoring', 'closed')
            ),
            detail_sha256 TEXT NOT NULL CHECK (length(detail_sha256) = 64),
            PRIMARY KEY (tenant_id, sequence),
            FOREIGN KEY (tenant_id, case_id)
              REFERENCES incident_cases(tenant_id, case_id) ON DELETE CASCADE
          ) STRICT;
          CREATE INDEX incident_case_events_recent_idx
            ON incident_case_events(tenant_id, sequence DESC);

          PRAGMA user_version = 9;
        `);
      });
      currentVersion = 9;
    }

    if (currentVersion === 9) {
      this.#database.exec("PRAGMA foreign_keys = OFF");
      try {
        this.#transaction(() => {
          this.#database.exec(`
            CREATE TABLE work_orders_v10 (
              tenant_id TEXT NOT NULL REFERENCES tenants(tenant_id),
              work_order_id TEXT NOT NULL,
              request_id TEXT NOT NULL,
              request_sha256 TEXT NOT NULL CHECK (
                length(request_sha256) = 64 AND
                request_sha256 NOT GLOB '*[^0-9a-f]*'
              ),
              target_device_id TEXT NOT NULL,
              action_id TEXT NOT NULL CHECK (action_id IN (
                'linux.boot-critical-path.v1',
                'linux.filesystem.health.v1',
                'linux.storage.health.v1',
                'linux.fstab.disable-missing-uuid.v1'
              )),
              action_version INTEGER NOT NULL CHECK (action_version = 1),
              kind TEXT NOT NULL CHECK (kind IN ('diagnosis', 'repair')),
              risk TEXT NOT NULL CHECK (risk IN ('R0', 'R1', 'R2', 'R3')),
              local_approval_required INTEGER NOT NULL CHECK (
                local_approval_required IN (0, 1)
              ),
              status TEXT NOT NULL CHECK (status IN (
                'pending_approval', 'queued', 'leased', 'succeeded', 'failed',
                'rejected', 'cancelled', 'expired'
              )),
              created_by_credential_id TEXT NOT NULL,
              created_at TEXT NOT NULL,
              expires_at TEXT NOT NULL,
              expires_at_ms INTEGER NOT NULL,
              approved_by_credential_id TEXT,
              approved_at TEXT,
              lease_id TEXT,
              leased_at TEXT,
              lease_expires_at TEXT,
              lease_expires_at_ms INTEGER,
              outcome TEXT CHECK (outcome IN ('succeeded', 'failed', 'rejected')),
              result_sha256 TEXT,
              result_envelope_sha256 TEXT,
              completed_at TEXT,
              cancelled_by_credential_id TEXT,
              cancelled_at TEXT,
              PRIMARY KEY (tenant_id, work_order_id),
              UNIQUE (tenant_id, request_id),
              FOREIGN KEY (tenant_id, target_device_id)
                REFERENCES devices(tenant_id, device_id),
              FOREIGN KEY (tenant_id, created_by_credential_id)
                REFERENCES tenant_access_credentials(tenant_id, credential_id),
              FOREIGN KEY (tenant_id, approved_by_credential_id)
                REFERENCES tenant_access_credentials(tenant_id, credential_id),
              FOREIGN KEY (tenant_id, cancelled_by_credential_id)
                REFERENCES tenant_access_credentials(tenant_id, credential_id)
            ) STRICT;
            INSERT INTO work_orders_v10 SELECT * FROM work_orders;
            DROP TABLE work_orders;
            ALTER TABLE work_orders_v10 RENAME TO work_orders;
            CREATE INDEX work_orders_queue_idx ON work_orders(
              tenant_id, target_device_id, status, created_at, work_order_id
            );
            PRAGMA user_version = 10;
          `);
          const violations = this.#database
            .prepare("PRAGMA foreign_key_check")
            .all();
          if (violations.length !== 0) {
            throw new Error("Fleet v10 migration violated a foreign key");
          }
        });
      } finally {
        this.#database.exec("PRAGMA foreign_keys = ON");
      }
      currentVersion = 10;
    }

    if (currentVersion === 10) {
      this.#database.exec("PRAGMA foreign_keys = OFF");
      try {
        this.#transaction(() => {
          this.#database.exec(`
            CREATE TABLE work_orders_v11 (
              tenant_id TEXT NOT NULL REFERENCES tenants(tenant_id),
              work_order_id TEXT NOT NULL,
              request_id TEXT NOT NULL,
              request_sha256 TEXT NOT NULL CHECK (
                length(request_sha256) = 64 AND
                request_sha256 NOT GLOB '*[^0-9a-f]*'
              ),
              target_device_id TEXT NOT NULL,
              action_id TEXT NOT NULL CHECK (action_id IN (
                'linux.boot-critical-path.v1',
                'linux.filesystem.health.v1',
                'linux.storage.health.v1',
                'linux.fstab.disable-missing-uuid.v1',
                'windows.p0.diagnose.v1'
              )),
              action_version INTEGER NOT NULL CHECK (action_version = 1),
              kind TEXT NOT NULL CHECK (kind IN ('diagnosis', 'repair')),
              risk TEXT NOT NULL CHECK (risk IN ('R0', 'R1', 'R2', 'R3')),
              local_approval_required INTEGER NOT NULL CHECK (
                local_approval_required IN (0, 1)
              ),
              status TEXT NOT NULL CHECK (status IN (
                'pending_approval', 'queued', 'leased', 'succeeded', 'failed',
                'rejected', 'cancelled', 'expired'
              )),
              created_by_credential_id TEXT NOT NULL,
              created_at TEXT NOT NULL,
              expires_at TEXT NOT NULL,
              expires_at_ms INTEGER NOT NULL,
              approved_by_credential_id TEXT,
              approved_at TEXT,
              lease_id TEXT,
              leased_at TEXT,
              lease_expires_at TEXT,
              lease_expires_at_ms INTEGER,
              outcome TEXT CHECK (outcome IN ('succeeded', 'failed', 'rejected')),
              result_sha256 TEXT,
              result_envelope_sha256 TEXT,
              completed_at TEXT,
              cancelled_by_credential_id TEXT,
              cancelled_at TEXT,
              PRIMARY KEY (tenant_id, work_order_id),
              UNIQUE (tenant_id, request_id),
              FOREIGN KEY (tenant_id, target_device_id)
                REFERENCES devices(tenant_id, device_id),
              FOREIGN KEY (tenant_id, created_by_credential_id)
                REFERENCES tenant_access_credentials(tenant_id, credential_id),
              FOREIGN KEY (tenant_id, approved_by_credential_id)
                REFERENCES tenant_access_credentials(tenant_id, credential_id),
              FOREIGN KEY (tenant_id, cancelled_by_credential_id)
                REFERENCES tenant_access_credentials(tenant_id, credential_id)
            ) STRICT;
            INSERT INTO work_orders_v11 SELECT * FROM work_orders;
            DROP TABLE work_orders;
            ALTER TABLE work_orders_v11 RENAME TO work_orders;
            CREATE INDEX work_orders_queue_idx ON work_orders(
              tenant_id, target_device_id, status, created_at, work_order_id
            );

            CREATE TABLE enterprise_licenses (
              tenant_id TEXT PRIMARY KEY REFERENCES tenants(tenant_id),
              license_id TEXT NOT NULL,
              sequence INTEGER NOT NULL CHECK (sequence > 0),
              key_id TEXT NOT NULL,
              plan TEXT NOT NULL CHECK (plan IN ('fleet', 'enterprise')),
              features_json TEXT NOT NULL CHECK (
                length(features_json) BETWEEN 2 AND 2048
              ),
              device_limit INTEGER NOT NULL CHECK (
                device_limit BETWEEN 1 AND 100000
              ),
              seat_limit INTEGER NOT NULL CHECK (
                seat_limit BETWEEN 1 AND 10000
              ),
              issued_at_unix INTEGER NOT NULL CHECK (issued_at_unix >= 0),
              not_before_unix INTEGER NOT NULL CHECK (not_before_unix >= 0),
              expires_at_unix INTEGER NOT NULL CHECK (expires_at_unix >= 0),
              grace_until_unix INTEGER NOT NULL CHECK (grace_until_unix >= 0),
              envelope_sha256 TEXT NOT NULL CHECK (
                length(envelope_sha256) = 64 AND
                envelope_sha256 NOT GLOB '*[^0-9a-f]*'
              ),
              canonical_json TEXT NOT NULL CHECK (
                length(canonical_json) BETWEEN 1 AND 16384
              ),
              imported_at TEXT NOT NULL,
              revoked_at TEXT,
              CHECK (issued_at_unix <= not_before_unix),
              CHECK (not_before_unix < expires_at_unix),
              CHECK (expires_at_unix <= grace_until_unix)
            ) STRICT;

            CREATE TABLE enterprise_license_seats (
              assignment_id TEXT PRIMARY KEY,
              tenant_id TEXT NOT NULL REFERENCES tenants(tenant_id),
              kind TEXT NOT NULL CHECK (kind IN ('device', 'technician')),
              subject_id TEXT NOT NULL,
              assigned_at TEXT NOT NULL,
              revoked_at TEXT,
              UNIQUE (tenant_id, kind, subject_id)
            ) STRICT;
            CREATE INDEX enterprise_license_seats_active_idx
              ON enterprise_license_seats(tenant_id, kind, revoked_at);

            CREATE TABLE enterprise_license_clock (
              tenant_id TEXT PRIMARY KEY REFERENCES tenants(tenant_id),
              max_observed_unix INTEGER NOT NULL CHECK (max_observed_unix >= 0),
              rollback_detected_at TEXT,
              updated_at TEXT NOT NULL
            ) STRICT;

            CREATE TABLE enterprise_license_events (
              tenant_id TEXT NOT NULL REFERENCES tenants(tenant_id),
              sequence INTEGER NOT NULL CHECK (sequence > 0),
              occurred_at TEXT NOT NULL,
              kind TEXT NOT NULL CHECK (kind IN (
                'clock_rollback', 'license_imported', 'license_revoked',
                'seat_assigned', 'seat_revoked'
              )),
              actor_id TEXT NOT NULL,
              detail_sha256 TEXT NOT NULL CHECK (
                length(detail_sha256) = 64 AND
                detail_sha256 NOT GLOB '*[^0-9a-f]*'
              ),
              PRIMARY KEY (tenant_id, sequence)
            ) STRICT;
            CREATE INDEX enterprise_license_events_recent_idx
              ON enterprise_license_events(tenant_id, sequence DESC);

            PRAGMA user_version = 11;
          `);
          const violations = this.#database
            .prepare("PRAGMA foreign_key_check")
            .all();
          if (violations.length !== 0) {
            throw new Error("Fleet v11 migration violated a foreign key");
          }
        });
      } finally {
        this.#database.exec("PRAGMA foreign_keys = ON");
      }
    }
  }
}

interface ServiceResponseRow {
  tenant_id: string;
  device_id: string;
  operation: string;
  sequence: number;
  request_sha256: string;
  response_sha256: string;
  status: number;
  response_body: string;
  receipt_json: string;
}

interface EnterpriseLicenseRow {
  tenant_id: string;
  license_id: string;
  sequence: number;
  key_id: string;
  plan: string;
  features_json: string;
  device_limit: number;
  seat_limit: number;
  issued_at_unix: number;
  not_before_unix: number;
  expires_at_unix: number;
  grace_until_unix: number;
  envelope_sha256: string;
  canonical_json: string;
  imported_at: string;
  revoked_at: string | null;
}

interface EnterpriseLicenseSeatRow {
  assignment_id: string;
  tenant_id: string;
  kind: string;
  subject_id: string;
  assigned_at: string;
  revoked_at: string | null;
}

interface EnterpriseLicenseClockRow {
  max_observed_unix: number;
  rollback_detected_at: string | null;
}

interface EnterpriseLicenseEventRow {
  tenant_id: string;
  sequence: number;
  occurred_at: string;
  kind: string;
  actor_id: string;
  detail_sha256: string;
}

interface TenantAccessCredentialRow {
  tenant_id: string;
  credential_id: string;
  role: string;
  label: string;
  created_at: string;
  revoked_at: string | null;
}

interface TenantAccessAuditRow {
  tenant_id: string;
  sequence: number;
  occurred_at: string;
  credential_id: string;
  role: string;
  action: string;
  outcome: string;
  target_tenant_id: string;
  target_type: string;
  target_id: string;
}

interface WorkOrderRow {
  tenant_id: string;
  work_order_id: string;
  request_id: string;
  request_sha256: string;
  target_device_id: string;
  action_id: string;
  action_version: number;
  kind: string;
  risk: string;
  local_approval_required: number;
  status: string;
  created_by_credential_id: string;
  created_at: string;
  expires_at: string;
  expires_at_ms: number;
  approved_by_credential_id: string | null;
  approved_at: string | null;
  lease_id: string | null;
  leased_at: string | null;
  lease_expires_at: string | null;
  lease_expires_at_ms: number | null;
  outcome: string | null;
  result_sha256: string | null;
  result_envelope_sha256: string | null;
  completed_at: string | null;
  cancelled_by_credential_id: string | null;
  cancelled_at: string | null;
}

interface WorkOrderEventRow {
  tenant_id: string;
  sequence: number;
  work_order_id: string;
  occurred_at: string;
  kind: string;
  actor_type: string;
  actor_id: string;
  status: string;
  detail_sha256: string | null;
}

interface IncidentCaseRow {
  tenant_id: string;
  case_id: string;
  request_id: string;
  request_sha256: string;
  source_device_id: string;
  source_asset_id: string | null;
  severity: string;
  status: string;
  assignee_label: string | null;
  created_by_credential_id: string;
  created_at: string;
  updated_at: string;
  outcome: string | null;
  closed_by_credential_id: string | null;
  closed_at: string | null;
  close_request_sha256: string | null;
  report_sha256: string | null;
  report_json: string | null;
  receipt_json: string | null;
}

interface IncidentCaseWorkOrderRow {
  tenant_id: string;
  case_id: string;
  work_order_id: string;
  action_id: string;
  action_version: number;
  status: string;
  result_sha256: string | null;
  state_sha256: string;
  linked_at: string;
  observed_at: string;
}

interface IncidentCaseWorkOrderSyncRow extends IncidentCaseWorkOrderRow {
  case_status: string;
  current_action_id: string;
  current_action_version: number;
  current_status: string;
  current_result_sha256: string | null;
}

interface IncidentCaseEventRow {
  tenant_id: string;
  sequence: number;
  case_id: string;
  occurred_at: string;
  kind: string;
  actor_type: string;
  actor_id: string;
  status: string;
  detail_sha256: string;
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

function validateWorkOrderCreate(input: {
  tenantId: string;
  workOrderId: string;
  requestId: string;
  requestSha256: string;
  targetDeviceId: string;
  actionId: WorkOrderActionId;
  actionVersion: number;
  kind: WorkOrderKind;
  risk: WorkOrderRisk;
  localApprovalRequired: boolean;
  createdByCredentialId: string;
  createdAt: string;
  expiresAt: string;
  expiresAtMs: number;
}): void {
  const action = workOrderActionCatalog[input.actionId];
  if (
    !isPublicIdentifier(input.tenantId) ||
    !isPublicIdentifier(input.workOrderId) ||
    !isPublicIdentifier(input.requestId) ||
    !isSha256(input.requestSha256) ||
    !/^KA-[0-9a-f]{24}$/.test(input.targetDeviceId) ||
    action === undefined ||
    input.actionVersion !== action.version ||
    input.kind !== action.kind ||
    input.risk !== action.risk ||
    input.localApprovalRequired !== action.localApprovalRequired ||
    !isPublicIdentifier(input.createdByCredentialId) ||
    !isRfc3339(input.createdAt) ||
    !isRfc3339(input.expiresAt) ||
    !Number.isSafeInteger(input.expiresAtMs) ||
    Date.parse(input.expiresAt) !== input.expiresAtMs ||
    input.expiresAtMs <= Date.parse(input.createdAt)
  ) {
    throw new Error("work-order create input is invalid");
  }
}

function validateWorkOrderClock(
  tenantId: string,
  nowMs: number,
  now: string,
): void {
  if (
    !isPublicIdentifier(tenantId) ||
    !Number.isSafeInteger(nowMs) ||
    !isRfc3339(now) ||
    Date.parse(now) !== nowMs
  ) {
    throw new Error("work-order clock is invalid");
  }
}

function validateWorkOrderActorMutation(input: {
  tenantId: string;
  workOrderId: string;
  credentialId: string;
  approvedAt: string;
  nowMs: number;
}): void {
  validateWorkOrderClock(input.tenantId, input.nowMs, input.approvedAt);
  if (
    !isPublicIdentifier(input.workOrderId) ||
    !isPublicIdentifier(input.credentialId)
  ) {
    throw new Error("work-order actor mutation is invalid");
  }
}

function validateWorkOrderClaim(input: {
  tenantId: string;
  deviceId: string;
  requestSha256: string;
  nonceSha256: string;
  nonceExpiresAtMs: number;
  leaseId: string;
  leaseSeconds: number;
  eligibleActionIds: readonly WorkOrderActionId[];
  nowMs: number;
  now: string;
}): void {
  validateWorkOrderClock(input.tenantId, input.nowMs, input.now);
  if (
    !/^KA-[0-9a-f]{24}$/.test(input.deviceId) ||
    !isSha256(input.requestSha256) ||
    !isSha256(input.nonceSha256) ||
    !Number.isSafeInteger(input.nonceExpiresAtMs) ||
    input.nonceExpiresAtMs <= input.nowMs ||
    !isPublicIdentifier(input.leaseId) ||
    !Number.isSafeInteger(input.leaseSeconds) ||
    input.leaseSeconds < 30 ||
    input.leaseSeconds > 900 ||
    input.eligibleActionIds.some((item) => !isWorkOrderActionId(item)) ||
    new Set(input.eligibleActionIds).size !== input.eligibleActionIds.length
  ) {
    throw new Error("work-order claim is invalid");
  }
}

function mapWorkOrder(row: WorkOrderRow): StoredWorkOrder {
  if (
    !isPublicIdentifier(row.tenant_id) ||
    !isPublicIdentifier(row.work_order_id) ||
    !isPublicIdentifier(row.request_id) ||
    !isSha256(row.request_sha256) ||
    !/^KA-[0-9a-f]{24}$/.test(row.target_device_id) ||
    !isWorkOrderActionId(row.action_id) ||
    !isWorkOrderKind(row.kind) ||
    !isWorkOrderRisk(row.risk) ||
    !isWorkOrderStatus(row.status) ||
    ![0, 1].includes(row.local_approval_required) ||
    !isPublicIdentifier(row.created_by_credential_id) ||
    !isRfc3339(row.created_at) ||
    !isRfc3339(row.expires_at) ||
    Date.parse(row.expires_at) !== row.expires_at_ms ||
    row.action_version !== workOrderActionCatalog[row.action_id].version ||
    row.kind !== workOrderActionCatalog[row.action_id].kind ||
    row.risk !== workOrderActionCatalog[row.action_id].risk ||
    Boolean(row.local_approval_required) !==
      workOrderActionCatalog[row.action_id].localApprovalRequired ||
    !nullableIdentifier(row.approved_by_credential_id) ||
    !nullableRfc3339(row.approved_at) ||
    (row.approved_by_credential_id === null) !== (row.approved_at === null) ||
    !nullableIdentifier(row.lease_id) ||
    !nullableRfc3339(row.leased_at) ||
    !nullableRfc3339(row.lease_expires_at) ||
    (row.lease_id === null ||
      row.leased_at === null ||
      row.lease_expires_at === null ||
      row.lease_expires_at_ms === null) !==
      (row.lease_id === null &&
        row.leased_at === null &&
        row.lease_expires_at === null &&
        row.lease_expires_at_ms === null) ||
    (row.lease_expires_at !== null &&
      Date.parse(row.lease_expires_at) !== row.lease_expires_at_ms) ||
    (row.outcome !== null && !isWorkOrderResultOutcome(row.outcome)) ||
    (row.result_sha256 !== null && !isSha256(row.result_sha256)) ||
    (row.result_envelope_sha256 !== null &&
      !isSha256(row.result_envelope_sha256)) ||
    !nullableRfc3339(row.completed_at) ||
    !nullableIdentifier(row.cancelled_by_credential_id) ||
    !nullableRfc3339(row.cancelled_at) ||
    new Set([
      row.outcome === null,
      row.result_sha256 === null,
      row.result_envelope_sha256 === null,
      row.completed_at === null,
    ]).size !== 1 ||
    (row.outcome !== null && row.status !== row.outcome) ||
    ["succeeded", "failed", "rejected"].includes(row.status) !==
      (row.outcome !== null) ||
    (row.cancelled_by_credential_id === null) !== (row.cancelled_at === null) ||
    (row.status === "cancelled") !== (row.cancelled_at !== null) ||
    (row.kind === "repair" &&
      ["leased", "succeeded", "failed", "rejected"].includes(row.status) &&
      row.approved_at === null)
  ) {
    throw new Error("stored work order is invalid");
  }
  return {
    tenantId: row.tenant_id,
    workOrderId: row.work_order_id,
    requestId: row.request_id,
    targetDeviceId: row.target_device_id,
    actionId: row.action_id,
    actionVersion: row.action_version,
    kind: row.kind,
    risk: row.risk,
    localApprovalRequired: row.local_approval_required === 1,
    status: row.status,
    createdByCredentialId: row.created_by_credential_id,
    createdAt: row.created_at,
    expiresAt: row.expires_at,
    approvedByCredentialId: row.approved_by_credential_id,
    approvedAt: row.approved_at,
    leaseId: row.lease_id,
    leasedAt: row.leased_at,
    leaseExpiresAt: row.lease_expires_at,
    outcome: row.outcome,
    resultSha256: row.result_sha256,
    completedAt: row.completed_at,
    cancelledByCredentialId: row.cancelled_by_credential_id,
    cancelledAt: row.cancelled_at,
  };
}

function mapWorkOrderEvent(row: WorkOrderEventRow): ListedWorkOrderEvent {
  if (
    !isPublicIdentifier(row.tenant_id) ||
    !Number.isSafeInteger(row.sequence) ||
    row.sequence < 1 ||
    !isPublicIdentifier(row.work_order_id) ||
    !isRfc3339(row.occurred_at) ||
    !isWorkOrderEventKind(row.kind) ||
    !["credential", "device", "system"].includes(row.actor_type) ||
    !isPublicIdentifier(row.actor_id) ||
    !isWorkOrderStatus(row.status) ||
    (row.detail_sha256 !== null && !isSha256(row.detail_sha256))
  ) {
    throw new Error("stored work-order event is invalid");
  }
  return {
    tenantId: row.tenant_id,
    sequence: row.sequence,
    workOrderId: row.work_order_id,
    occurredAt: row.occurred_at,
    kind: row.kind,
    actorType: row.actor_type as ListedWorkOrderEvent["actorType"],
    actorId: row.actor_id,
    status: row.status,
    detailSha256: row.detail_sha256,
  };
}

function incidentWorkOrderSummary(input: {
  workOrderId: string;
  actionId: WorkOrderActionId;
  actionVersion: number;
  status: WorkOrderStatus;
  resultSha256: string | null;
}): IncidentReportWorkOrder {
  const state = {
    workOrderId: input.workOrderId,
    actionId: input.actionId,
    actionVersion: input.actionVersion,
    status: input.status,
    resultSha256: input.resultSha256,
  };
  return { ...state, stateSha256: sha256(canonicalJson(state)) };
}

function mapIncidentCaseWorkOrder(
  row: IncidentCaseWorkOrderRow,
): IncidentCaseWorkOrder {
  if (
    !isPublicIdentifier(row.work_order_id) ||
    !isWorkOrderActionId(row.action_id) ||
    row.action_version !== workOrderActionCatalog[row.action_id].version ||
    !isWorkOrderStatus(row.status) ||
    (row.result_sha256 !== null && !isSha256(row.result_sha256)) ||
    !isSha256(row.state_sha256) ||
    !isRfc3339(row.linked_at) ||
    !isRfc3339(row.observed_at)
  ) {
    throw new Error("stored incident work-order state is invalid");
  }
  const summary = incidentWorkOrderSummary({
    workOrderId: row.work_order_id,
    actionId: row.action_id,
    actionVersion: row.action_version,
    status: row.status,
    resultSha256: row.result_sha256,
  });
  if (summary.stateSha256 !== row.state_sha256) {
    throw new Error("stored incident work-order digest is invalid");
  }
  return {
    ...summary,
    linkedAt: row.linked_at,
    observedAt: row.observed_at,
  };
}

function mapIncidentCaseEvent(
  row: IncidentCaseEventRow,
): ListedIncidentCaseEvent {
  if (
    !isPublicIdentifier(row.tenant_id) ||
    !Number.isSafeInteger(row.sequence) ||
    row.sequence < 1 ||
    !isPublicIdentifier(row.case_id) ||
    !isRfc3339(row.occurred_at) ||
    ![
      "created",
      "updated",
      "work_order_linked",
      "work_order_state",
      "closed",
    ].includes(row.kind) ||
    !["credential", "system"].includes(row.actor_type) ||
    !isPublicIdentifier(row.actor_id) ||
    !isIncidentCaseStatus(row.status) ||
    !isSha256(row.detail_sha256)
  ) {
    throw new Error("stored incident-case event is invalid");
  }
  return {
    tenantId: row.tenant_id,
    sequence: row.sequence,
    caseId: row.case_id,
    occurredAt: row.occurred_at,
    kind: row.kind as ListedIncidentCaseEvent["kind"],
    actorType: row.actor_type as ListedIncidentCaseEvent["actorType"],
    actorId: row.actor_id,
    status: row.status,
    detailSha256: row.detail_sha256,
  };
}

function validateIncidentCaseCreate(input: {
  tenantId: string;
  caseId: string;
  requestId: string;
  requestSha256: string;
  sourceDeviceId: string;
  sourceAssetId: string | null;
  severity: IncidentCaseSeverity;
  assigneeLabel: string | null;
  credentialId: string;
  createdAt: string;
}): void {
  if (
    !isPublicIdentifier(input.tenantId) ||
    !isPublicIdentifier(input.caseId) ||
    !isPublicIdentifier(input.requestId) ||
    !isSha256(input.requestSha256) ||
    !/^KA-[0-9a-f]{24}$/.test(input.sourceDeviceId) ||
    (input.sourceAssetId !== null && !isBoundedAssetId(input.sourceAssetId)) ||
    !isIncidentCaseSeverity(input.severity) ||
    (input.assigneeLabel !== null &&
      !validIncidentAssigneeLabel(input.assigneeLabel)) ||
    !isPublicIdentifier(input.credentialId) ||
    !isRfc3339(input.createdAt)
  ) {
    throw new Error("incident case create input is invalid");
  }
}

function validateIncidentCaseUpdate(input: {
  tenantId: string;
  caseId: string;
  severity: IncidentCaseSeverity;
  status: Exclude<IncidentCaseStatus, "closed">;
  assigneeLabel: string | null;
  credentialId: string;
  updatedAt: string;
  detailSha256: string;
}): void {
  if (
    !isPublicIdentifier(input.tenantId) ||
    !isPublicIdentifier(input.caseId) ||
    !isIncidentCaseSeverity(input.severity) ||
    !["open", "investigating", "monitoring"].includes(input.status) ||
    (input.assigneeLabel !== null &&
      !validIncidentAssigneeLabel(input.assigneeLabel)) ||
    !isPublicIdentifier(input.credentialId) ||
    !isRfc3339(input.updatedAt) ||
    !isSha256(input.detailSha256)
  ) {
    throw new Error("incident case update input is invalid");
  }
}

function validateIncidentCaseLink(input: {
  tenantId: string;
  caseId: string;
  workOrderId: string;
  credentialId: string;
  linkedAt: string;
}): void {
  if (
    !isPublicIdentifier(input.tenantId) ||
    !isPublicIdentifier(input.caseId) ||
    !isPublicIdentifier(input.workOrderId) ||
    !isPublicIdentifier(input.credentialId) ||
    !isRfc3339(input.linkedAt)
  ) {
    throw new Error("incident work-order link input is invalid");
  }
}

function validateIncidentCaseClose(input: {
  tenantId: string;
  caseId: string;
  outcome: IncidentCaseOutcome;
  credentialId: string;
  closedAt: string;
  requestSha256: string;
}): void {
  if (
    !isPublicIdentifier(input.tenantId) ||
    !isPublicIdentifier(input.caseId) ||
    !isIncidentCaseOutcome(input.outcome) ||
    !isPublicIdentifier(input.credentialId) ||
    !isRfc3339(input.closedAt) ||
    !isSha256(input.requestSha256)
  ) {
    throw new Error("incident case close input is invalid");
  }
}

function validateIncidentCaseClosureMaterial(
  material: IncidentCaseClosureMaterial,
): void {
  if (
    !isSha256(material.reportSha256) ||
    sha256(material.reportJson) !== material.reportSha256 ||
    Buffer.byteLength(material.reportJson, "utf8") === 0 ||
    Buffer.byteLength(material.reportJson, "utf8") > 256 * 1024 ||
    Buffer.byteLength(material.receiptJson, "utf8") === 0 ||
    Buffer.byteLength(material.receiptJson, "utf8") > MAX_SERVICE_RECEIPT_BYTES
  ) {
    throw new Error("incident closure material is invalid");
  }
}

function validateIncidentCaseRow(row: IncidentCaseRow): void {
  const closed = row.status === "closed";
  if (
    !isPublicIdentifier(row.tenant_id) ||
    !isPublicIdentifier(row.case_id) ||
    !isPublicIdentifier(row.request_id) ||
    !isSha256(row.request_sha256) ||
    !/^KA-[0-9a-f]{24}$/.test(row.source_device_id) ||
    (row.source_asset_id !== null && !isBoundedAssetId(row.source_asset_id)) ||
    !isIncidentCaseSeverity(row.severity) ||
    !isIncidentCaseStatus(row.status) ||
    (row.assignee_label !== null &&
      !validIncidentAssigneeLabel(row.assignee_label)) ||
    !isPublicIdentifier(row.created_by_credential_id) ||
    !isRfc3339(row.created_at) ||
    !isRfc3339(row.updated_at) ||
    (row.outcome !== null && !isIncidentCaseOutcome(row.outcome)) ||
    !nullableIdentifier(row.closed_by_credential_id) ||
    !nullableRfc3339(row.closed_at) ||
    (row.close_request_sha256 !== null &&
      !isSha256(row.close_request_sha256)) ||
    (row.report_sha256 !== null && !isSha256(row.report_sha256)) ||
    closed !== (row.outcome !== null) ||
    closed !== (row.closed_by_credential_id !== null) ||
    closed !== (row.closed_at !== null) ||
    closed !== (row.close_request_sha256 !== null) ||
    closed !== (row.report_sha256 !== null) ||
    closed !== (row.report_json !== null) ||
    closed !== (row.receipt_json !== null)
  ) {
    throw new Error("stored incident case is invalid");
  }
}

function isIncidentCaseSeverity(value: string): value is IncidentCaseSeverity {
  return (incidentCaseSeverities as readonly string[]).includes(value);
}

function isIncidentCaseStatus(value: string): value is IncidentCaseStatus {
  return (incidentCaseStatuses as readonly string[]).includes(value);
}

function isIncidentCaseOutcome(value: string): value is IncidentCaseOutcome {
  return (incidentCaseOutcomes as readonly string[]).includes(value);
}

function isBoundedAssetId(value: string): boolean {
  return (
    new TextEncoder().encode(value).length >= 1 &&
    new TextEncoder().encode(value).length <= 256 &&
    ![...value].some((character) => {
      const point = character.codePointAt(0) ?? 0;
      return point <= 0x1f || point === 0x7f;
    })
  );
}

function sha256(value: string): string {
  return createHash("sha256").update(value, "utf8").digest("hex");
}

function isWorkOrderKind(value: string): value is WorkOrderKind {
  return value === "diagnosis" || value === "repair";
}

function isWorkOrderRisk(value: string): value is WorkOrderRisk {
  return ["R0", "R1", "R2", "R3"].includes(value);
}

function isWorkOrderStatus(value: string): value is WorkOrderStatus {
  return [
    "pending_approval",
    "queued",
    "leased",
    "succeeded",
    "failed",
    "rejected",
    "cancelled",
    "expired",
  ].includes(value);
}

function isWorkOrderResultOutcome(
  value: string,
): value is WorkOrderResultOutcome {
  return ["succeeded", "failed", "rejected"].includes(value);
}

function isWorkOrderEventKind(
  value: string,
): value is ListedWorkOrderEvent["kind"] {
  return [
    "created",
    "approved",
    "leased",
    "lease_expired",
    "completed",
    "cancelled",
    "expired",
  ].includes(value);
}

function nullableIdentifier(value: string | null): boolean {
  return value === null || isPublicIdentifier(value);
}

function nullableRfc3339(value: string | null): boolean {
  return value === null || isRfc3339(value);
}

function validateEnterpriseLicenseStoreInput(input: {
  claims: EnterpriseLicenseClaims;
  canonicalJson: string;
  envelopeSha256: string;
  importedAt: string;
  actorId: string;
}): void {
  const claims = input.claims;
  if (
    !isPublicIdentifier(claims.tenantId) ||
    !isPublicIdentifier(claims.licenseId) ||
    !isPublicIdentifier(claims.keyId) ||
    !Number.isSafeInteger(claims.sequence) ||
    claims.sequence < 1 ||
    !["fleet", "enterprise"].includes(claims.plan) ||
    claims.features.length < 1 ||
    new Set(claims.features).size !== claims.features.length ||
    claims.features.some(
      (feature, index) =>
        !(enterpriseLicenseFeatures as readonly string[]).includes(feature) ||
        (index > 0 && claims.features[index - 1]! >= feature),
    ) ||
    !Number.isSafeInteger(claims.deviceLimit) ||
    claims.deviceLimit < 1 ||
    claims.deviceLimit > 100_000 ||
    !Number.isSafeInteger(claims.seatLimit) ||
    claims.seatLimit < 1 ||
    claims.seatLimit > 10_000 ||
    !Number.isSafeInteger(claims.issuedAtUnix) ||
    !Number.isSafeInteger(claims.notBeforeUnix) ||
    !Number.isSafeInteger(claims.expiresAtUnix) ||
    !Number.isSafeInteger(claims.graceUntilUnix) ||
    claims.issuedAtUnix > claims.notBeforeUnix ||
    claims.notBeforeUnix >= claims.expiresAtUnix ||
    claims.expiresAtUnix > claims.graceUntilUnix ||
    !isSha256(input.envelopeSha256) ||
    Buffer.byteLength(input.canonicalJson, "utf8") < 1 ||
    Buffer.byteLength(input.canonicalJson, "utf8") > 16 * 1024 ||
    !isRfc3339(input.importedAt) ||
    !isPublicIdentifier(input.actorId)
  ) {
    throw new Error("enterprise license storage input is invalid");
  }
}

function mapEnterpriseLicense(
  row: EnterpriseLicenseRow,
): StoredEnterpriseLicense {
  let features: EnterpriseLicenseFeature[];
  try {
    const parsed = JSON.parse(row.features_json) as unknown;
    if (!Array.isArray(parsed)) throw new Error("not an array");
    features = parsed.map((feature) => {
      if (
        typeof feature !== "string" ||
        !(enterpriseLicenseFeatures as readonly string[]).includes(feature)
      ) {
        throw new Error("invalid feature");
      }
      return feature as EnterpriseLicenseFeature;
    });
    if (
      canonicalJson(features) !== row.features_json ||
      new Set(features).size !== features.length
    ) {
      throw new Error("non-canonical features");
    }
  } catch {
    throw new Error("stored enterprise license features are invalid");
  }
  const mapped = {
    tenantId: row.tenant_id,
    licenseId: row.license_id,
    sequence: row.sequence,
    keyId: row.key_id,
    plan: row.plan as EnterpriseLicensePlan,
    features,
    deviceLimit: row.device_limit,
    seatLimit: row.seat_limit,
    issuedAtUnix: row.issued_at_unix,
    notBeforeUnix: row.not_before_unix,
    expiresAtUnix: row.expires_at_unix,
    graceUntilUnix: row.grace_until_unix,
    envelopeSha256: row.envelope_sha256,
    canonicalJson: row.canonical_json,
    importedAt: row.imported_at,
    revokedAt: row.revoked_at,
  };
  validateEnterpriseLicenseStoreInput({
    claims: {
      schema: "dev.kernaid.fleet.enterprise-license.v1",
      version: 1,
      licenseId: mapped.licenseId,
      tenantId: mapped.tenantId,
      sequence: mapped.sequence,
      keyId: mapped.keyId,
      plan: mapped.plan,
      features: mapped.features,
      deviceLimit: mapped.deviceLimit,
      seatLimit: mapped.seatLimit,
      issuedAtUnix: mapped.issuedAtUnix,
      notBeforeUnix: mapped.notBeforeUnix,
      expiresAtUnix: mapped.expiresAtUnix,
      graceUntilUnix: mapped.graceUntilUnix,
    },
    canonicalJson: mapped.canonicalJson,
    envelopeSha256: mapped.envelopeSha256,
    importedAt: mapped.importedAt,
    actorId: "stored-license",
  });
  if (mapped.revokedAt !== null && !isRfc3339(mapped.revokedAt)) {
    throw new Error("stored enterprise license revocation is invalid");
  }
  return mapped;
}

function validateEnterpriseSeatMutation(input: {
  tenantId: string;
  kind: EnterpriseSeatKind;
  subjectId: string;
  limit: number;
  actorId: string;
  assignedAt: string;
}): void {
  if (
    !isPublicIdentifier(input.tenantId) ||
    !["device", "technician"].includes(input.kind) ||
    !isPublicIdentifier(input.subjectId) ||
    !Number.isSafeInteger(input.limit) ||
    input.limit < 1 ||
    input.limit > 100_000 ||
    !isPublicIdentifier(input.actorId) ||
    !isRfc3339(input.assignedAt)
  ) {
    throw new Error("enterprise seat mutation is invalid");
  }
}

function enterpriseSeatAssignmentId(
  tenantId: string,
  kind: EnterpriseSeatKind,
  subjectId: string,
): string {
  return `seat_${sha256(
    `kernaid:fleet:enterprise-seat-assignment:v1\0${tenantId}\0${kind}\0${subjectId}`,
  ).slice(0, 40)}`;
}

function mapEnterpriseLicenseSeat(
  row: EnterpriseLicenseSeatRow,
): EnterpriseLicenseSeat {
  if (
    !/^seat_[0-9a-f]{40}$/.test(row.assignment_id) ||
    !isPublicIdentifier(row.tenant_id) ||
    !["device", "technician"].includes(row.kind) ||
    !isPublicIdentifier(row.subject_id) ||
    !isRfc3339(row.assigned_at) ||
    (row.revoked_at !== null && !isRfc3339(row.revoked_at))
  ) {
    throw new Error("stored enterprise seat is invalid");
  }
  return {
    assignmentId: row.assignment_id,
    tenantId: row.tenant_id,
    kind: row.kind as EnterpriseSeatKind,
    subjectId: row.subject_id,
    assignedAt: row.assigned_at,
    revokedAt: row.revoked_at,
  };
}

function mapEnterpriseLicenseEvent(
  row: EnterpriseLicenseEventRow,
): EnterpriseLicenseEvent {
  const kinds = [
    "clock_rollback",
    "license_imported",
    "license_revoked",
    "seat_assigned",
    "seat_revoked",
  ] as const;
  if (
    !isPublicIdentifier(row.tenant_id) ||
    !Number.isSafeInteger(row.sequence) ||
    row.sequence < 1 ||
    !isRfc3339(row.occurred_at) ||
    !(kinds as readonly string[]).includes(row.kind) ||
    !isPublicIdentifier(row.actor_id) ||
    !isSha256(row.detail_sha256)
  ) {
    throw new Error("stored enterprise license event is invalid");
  }
  return {
    tenantId: row.tenant_id,
    sequence: row.sequence,
    occurredAt: row.occurred_at,
    kind: row.kind as EnterpriseLicenseEvent["kind"],
    actorId: row.actor_id,
    detailSha256: row.detail_sha256,
  };
}

function validateCredentialInput(input: {
  tenantId: string;
  credentialId: string;
  tokenHash: string;
  role: TenantRole;
  label: string;
  createdAt: string;
}): void {
  if (
    !isPublicIdentifier(input.tenantId) ||
    !isPublicIdentifier(input.credentialId) ||
    !isSha256(input.tokenHash) ||
    !isTenantRole(input.role) ||
    !validCredentialLabel(input.label) ||
    !isRfc3339(input.createdAt)
  ) {
    throw new Error("tenant access credential is invalid");
  }
}

function mapTenantAccessCredential(
  row: TenantAccessCredentialRow,
): TenantAccessCredential {
  if (
    !isPublicIdentifier(row.tenant_id) ||
    !isPublicIdentifier(row.credential_id) ||
    !isTenantRole(row.role) ||
    !validCredentialLabel(row.label) ||
    !isRfc3339(row.created_at) ||
    (row.revoked_at !== null && !isRfc3339(row.revoked_at))
  ) {
    throw new Error("stored tenant access credential is invalid");
  }
  return {
    tenantId: row.tenant_id,
    credentialId: row.credential_id,
    role: row.role,
    label: row.label,
    createdAt: row.created_at,
    revokedAt: row.revoked_at,
  };
}

function validateTenantAccessAuditInput(input: {
  tenantId: string;
  occurredAt: string;
  credentialId: string;
  role: TenantRole;
  action: TenantAccessAction;
  outcome: TenantAccessOutcome;
  targetTenantId: string;
  targetType: TenantAccessTargetType;
  targetId: string;
}): void {
  if (
    !isPublicIdentifier(input.tenantId) ||
    !isRfc3339(input.occurredAt) ||
    !isPublicIdentifier(input.credentialId) ||
    !isTenantRole(input.role) ||
    !isTenantAccessAction(input.action) ||
    !["allowed", "denied"].includes(input.outcome) ||
    !isPublicIdentifier(input.targetTenantId) ||
    !["credential", "device", "incident_case", "tenant", "work_order"].includes(
      input.targetType,
    ) ||
    !isPublicIdentifier(input.targetId)
  ) {
    throw new Error("tenant access audit event is invalid");
  }
}

function mapTenantAccessAudit(
  row: TenantAccessAuditRow,
): ListedTenantAccessAuditEvent {
  if (
    !Number.isSafeInteger(row.sequence) ||
    row.sequence < 1 ||
    !isTenantRole(row.role) ||
    !isTenantAccessAction(row.action) ||
    !["allowed", "denied"].includes(row.outcome) ||
    !["credential", "device", "incident_case", "tenant", "work_order"].includes(
      row.target_type,
    )
  ) {
    throw new Error("stored tenant access audit event is invalid");
  }
  const mapped = {
    tenantId: row.tenant_id,
    sequence: row.sequence,
    occurredAt: row.occurred_at,
    credentialId: row.credential_id,
    role: row.role,
    action: row.action,
    outcome: row.outcome as TenantAccessOutcome,
    targetTenantId: row.target_tenant_id,
    targetType: row.target_type as TenantAccessTargetType,
    targetId: row.target_id,
  };
  validateTenantAccessAuditInput(mapped);
  return mapped;
}

function validateServiceResponseLookup(input: {
  tenantId: string;
  deviceId: string;
  operation: FleetServiceOperation;
  requestSha256: string;
}): void {
  if (
    !isPublicIdentifier(input.tenantId) ||
    !/^KA-[0-9a-f]{24}$/.test(input.deviceId) ||
    !isServiceOperation(input.operation) ||
    !isSha256(input.requestSha256)
  ) {
    throw new Error("service response lookup is invalid");
  }
}

function validateServiceResponseCommit(
  input: CommitServiceResponseInput,
): void {
  validateServiceResponseLookup(input);
  const isPull =
    input.operation === "policy_pull" || input.operation === "entitlement_pull";
  if (
    !isSha256(input.responseSha256) ||
    ![200, 201].includes(input.status) ||
    Buffer.byteLength(input.responseBody, "utf8") === 0 ||
    Buffer.byteLength(input.responseBody, "utf8") >
      MAX_SERVICE_RESPONSE_BYTES ||
    !Number.isFinite(Date.parse(input.createdAt)) ||
    isPull !== (input.pullNonce !== undefined) ||
    (input.pullNonce !== undefined &&
      (!isSha256(input.pullNonce.nonceSha256) ||
        !Number.isSafeInteger(input.pullNonce.expiresAtMs) ||
        !Number.isSafeInteger(input.pullNonce.nowMs) ||
        input.pullNonce.expiresAtMs <= input.pullNonce.nowMs))
  ) {
    throw new Error("service response commit is invalid");
  }
}

function mapServiceResponse(row: ServiceResponseRow): StoredServiceResponse {
  if (
    !isPublicIdentifier(row.tenant_id) ||
    !/^KA-[0-9a-f]{24}$/.test(row.device_id) ||
    !isServiceOperation(row.operation) ||
    !Number.isSafeInteger(row.sequence) ||
    row.sequence < 1 ||
    !isSha256(row.request_sha256) ||
    !isSha256(row.response_sha256) ||
    ![200, 201].includes(row.status) ||
    Buffer.byteLength(row.response_body, "utf8") === 0 ||
    Buffer.byteLength(row.response_body, "utf8") > MAX_SERVICE_RESPONSE_BYTES ||
    Buffer.byteLength(row.receipt_json, "utf8") === 0 ||
    Buffer.byteLength(row.receipt_json, "utf8") > MAX_SERVICE_RECEIPT_BYTES
  ) {
    throw new Error("stored service response is invalid");
  }
  return {
    tenantId: row.tenant_id,
    deviceId: row.device_id,
    operation: row.operation,
    sequence: row.sequence,
    requestSha256: row.request_sha256,
    responseSha256: row.response_sha256,
    status: row.status,
    responseBody: row.response_body,
    receiptJson: row.receipt_json,
  };
}

function isServiceOperation(value: string): value is FleetServiceOperation {
  return [
    "inventory",
    "audit",
    "policy_pull",
    "entitlement_pull",
    "work_order_claim",
    "work_order_result",
    "incident_case_close",
  ].includes(value);
}

function isSha256(value: string): boolean {
  return /^[0-9a-f]{64}$/.test(value);
}

function isRfc3339(value: string): boolean {
  return (
    value.length >= 20 &&
    value.length <= 64 &&
    /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2})$/.test(
      value,
    ) &&
    Number.isFinite(Date.parse(value))
  );
}

function isPublicIdentifier(value: string): boolean {
  return (
    value.length >= 1 &&
    value.length <= 128 &&
    /^[A-Za-z0-9][A-Za-z0-9._:-]*$/.test(value)
  );
}
