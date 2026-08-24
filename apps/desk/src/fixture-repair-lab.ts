import { invoke } from "@tauri-apps/api/core";
import {
  FIXTURE_REPAIR_FINDING_ID,
  FIXTURE_REPAIR_FINDING_VERSION,
  type FixtureRepairBridge,
  type FixtureRepairExecuteRequestDto,
  type FixtureRepairFindingDto,
  type FixtureRepairReceiptDto,
  type FixtureRepairStageRequestDto,
  type FixtureRepairStatusDto,
  type FixtureRollbackExecuteRequestDto,
  type FixtureRollbackReceiptDto,
  type FixtureRollbackStageRequestDto,
  type StagedFixtureRepairDto,
  type StagedFixtureRollbackDto,
} from "@kernaid/agent-gateway";

const SHA256 = /^sha256:[0-9a-f]{64}$/u;

export interface FixtureLabInspection {
  readonly status: FixtureRepairStatusDto;
  readonly finding: FixtureRepairFindingDto | null;
}

/**
 * Closed adapter for the opt-in disposable fixture lab. The browser can pass
 * opaque plan/approval bindings only; the native side owns every path, byte
 * sequence, action identifier and mutation primitive.
 */
export class NativeFixtureRepairBridge implements FixtureRepairBridge {
  async inspect(): Promise<FixtureLabInspection> {
    return parseInspection(await invoke<unknown>("fixture_lab_status"));
  }

  async status(): Promise<FixtureRepairStatusDto> {
    return (await this.inspect()).status;
  }

  async stage(
    request: FixtureRepairStageRequestDto,
  ): Promise<StagedFixtureRepairDto> {
    return invoke<StagedFixtureRepairDto>("fixture_lab_stage", {
      request: {
        sessionId: request.sessionId,
        planId: request.planId,
      },
    });
  }

  async execute(
    request: FixtureRepairExecuteRequestDto,
  ): Promise<FixtureRepairReceiptDto> {
    try {
      return await invoke<FixtureRepairReceiptDto>("fixture_lab_execute", {
        request: request.approval,
      });
    } catch {
      return invoke<FixtureRepairReceiptDto>("fixture_lab_reconcile_execute", {
        request: { approvalId: request.approval.approvalId },
      });
    }
  }

  async stageRollback(
    request: FixtureRollbackStageRequestDto,
  ): Promise<StagedFixtureRollbackDto> {
    return invoke<StagedFixtureRollbackDto>("fixture_lab_stage_rollback", {
      request,
    });
  }

  async executeRollback(
    request: FixtureRollbackExecuteRequestDto,
  ): Promise<FixtureRollbackReceiptDto> {
    try {
      return await invoke<FixtureRollbackReceiptDto>(
        "fixture_lab_execute_rollback",
        { request: request.approval },
      );
    } catch {
      return invoke<FixtureRollbackReceiptDto>(
        "fixture_lab_reconcile_rollback",
        { request: { approvalId: request.approval.approvalId } },
      );
    }
  }
}

export function fixtureLabCommandIsMissing(error: unknown): boolean {
  const message = String(error).toLowerCase();
  return (
    message.includes("fixture_lab_status") &&
    (message.includes("not found") ||
      message.includes("unknown command") ||
      message.includes("does not exist"))
  );
}

function parseInspection(value: unknown): FixtureLabInspection {
  const record = objectRecord(value, "fixture lab status");
  const enabled = booleanValue(record.enabled, "fixture lab enabled state");
  const mutationBlocked = booleanValue(
    record.mutationBlocked,
    "fixture lab mutation state",
  );
  const nextApprovalSequence = approvalSequence(
    record.nextApprovalSequence,
    enabled && !mutationBlocked,
  );
  return {
    status: { enabled, mutationBlocked, nextApprovalSequence },
    finding: record.finding === null ? null : parseFinding(record.finding),
  };
}

function parseFinding(value: unknown): FixtureRepairFindingDto {
  const record = objectRecord(value, "fixture lab finding");
  if (
    record.findingId !== FIXTURE_REPAIR_FINDING_ID ||
    record.findingVersion !== FIXTURE_REPAIR_FINDING_VERSION ||
    !SHA256.test(String(record.diagnosisSha256)) ||
    !Array.isArray(record.evidence) ||
    record.evidence.length === 0 ||
    record.evidence.length > 32
  )
    throw new Error("invalid fixture lab finding");
  const evidence = record.evidence.map((value) => {
    const binding = objectRecord(value, "fixture lab evidence");
    if (
      typeof binding.id !== "string" ||
      !binding.id.startsWith("E-") ||
      !SHA256.test(String(binding.sha256))
    )
      throw new Error("invalid fixture lab evidence");
    return { id: binding.id, sha256: String(binding.sha256) };
  });
  return {
    sessionId: "S-fixture-inspection",
    planId: "P-fixture-inspection",
    diagnosisSha256: String(record.diagnosisSha256),
    findingId: FIXTURE_REPAIR_FINDING_ID,
    findingVersion: FIXTURE_REPAIR_FINDING_VERSION,
    evidence,
  };
}

function objectRecord(value: unknown, label: string): Record<string, unknown> {
  if (typeof value !== "object" || value === null || Array.isArray(value))
    throw new Error(`invalid ${label}`);
  return value as Record<string, unknown>;
}

function booleanValue(value: unknown, label: string): boolean {
  if (typeof value !== "boolean") throw new Error(`invalid ${label}`);
  return value;
}

function approvalSequence(
  value: unknown,
  mustBeAvailable: boolean,
): number | null {
  if (value === null) {
    if (mustBeAvailable)
      throw new Error("fixture lab approval sequence is unavailable");
    return null;
  }
  if (!Number.isSafeInteger(value) || Number(value) < 1)
    throw new Error("invalid fixture lab approval sequence");
  return mustBeAvailable ? Number(value) : null;
}
