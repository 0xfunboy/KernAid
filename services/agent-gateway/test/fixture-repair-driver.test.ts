import assert from "node:assert/strict";
import test from "node:test";
import {
  FIXTURE_REPAIR_ACTION_ID,
  FIXTURE_REPAIR_BACKUP,
  FIXTURE_REPAIR_FINDING_ID,
  FIXTURE_REPAIR_FINDING_VERSION,
  FIXTURE_REPAIR_RESOURCE_ID,
  FIXTURE_REPAIR_RISK,
  FIXTURE_REPAIR_ROLLBACK,
  FIXTURE_REPAIR_ROLLBACK_ACTION_ID,
  FIXTURE_REPAIR_VALIDATION,
  FIXTURE_ROLLBACK_VALIDATION,
  FixtureRepairDriver,
  type FixtureRepairBridge,
  type FixtureRepairExecuteRequestDto,
  type FixtureRepairReceiptDto,
  type FixtureRepairStageRequestDto,
  type FixtureRepairStatusDto,
  type FixtureRollbackExecuteRequestDto,
  type FixtureRollbackReceiptDto,
  type FixtureRollbackStageRequestDto,
  type StagedFixtureRepairDto,
  type StagedFixtureRollbackDto,
} from "../src/fixture-repair-driver.js";

const hash = (character: string): string => `sha256:${character.repeat(64)}`;
const backupLocator = `fixture-lab-backup://linux-fstab/${hash("2")}`;

class RecordingBridge implements FixtureRepairBridge {
  nextApprovalSequence = 11;
  readonly calls: Array<{ method: string; value?: unknown }> = [];

  async status(): Promise<FixtureRepairStatusDto> {
    this.calls.push({ method: "status" });
    return {
      enabled: true,
      mutationBlocked: false,
      nextApprovalSequence: this.nextApprovalSequence,
    };
  }

  async stage(
    request: FixtureRepairStageRequestDto,
  ): Promise<StagedFixtureRepairDto> {
    this.calls.push({ method: "stage", value: structuredClone(request) });
    return stagedRepair(request);
  }

  async execute(
    request: FixtureRepairExecuteRequestDto,
  ): Promise<FixtureRepairReceiptDto> {
    this.calls.push({ method: "execute", value: structuredClone(request) });
    this.nextApprovalSequence += 1;
    return {
      approvalId: request.approval.approvalId,
      approvalSequence: request.approval.approvalSequence,
      sessionId: request.staged.sessionId,
      planId: request.staged.planId,
      planHash: request.staged.planHash,
      actionId: FIXTURE_REPAIR_ACTION_ID,
      resourceId: FIXTURE_REPAIR_RESOURCE_ID,
      risk: FIXTURE_REPAIR_RISK,
      diagnosisSha256: request.staged.diagnosisSha256,
      findingId: FIXTURE_REPAIR_FINDING_ID,
      findingVersion: FIXTURE_REPAIR_FINDING_VERSION,
      evidence: request.staged.evidence,
      targetSnapshot: request.staged.targetSnapshot,
      beforeSha256: request.staged.expectedBeforeSha256,
      afterSha256: request.staged.expectedAfterSha256,
      backupLocator: request.staged.backupLocator,
      backupSha256: request.staged.expectedBeforeSha256,
      validationPassed: true,
    };
  }

  async stageRollback(
    request: FixtureRollbackStageRequestDto,
  ): Promise<StagedFixtureRollbackDto> {
    this.calls.push({
      method: "stageRollback",
      value: structuredClone(request),
    });
    return {
      ...request,
      repairPlanHash: hash("7"),
      actionId: FIXTURE_REPAIR_ROLLBACK_ACTION_ID,
      resourceId: FIXTURE_REPAIR_RESOURCE_ID,
      risk: FIXTURE_REPAIR_RISK,
      targetSnapshot: hash("6"),
      installedSha256: hash("3"),
      restoredSha256: hash("2"),
      backupLocator,
      backupSha256: hash("2"),
      planHash: hash("8"),
      validation: FIXTURE_ROLLBACK_VALIDATION,
    };
  }

  async executeRollback(
    request: FixtureRollbackExecuteRequestDto,
  ): Promise<FixtureRollbackReceiptDto> {
    this.calls.push({
      method: "executeRollback",
      value: structuredClone(request),
    });
    this.nextApprovalSequence += 1;
    return {
      repairApprovalId: request.staged.repairApprovalId,
      rollbackApprovalId: request.approval.approvalId,
      approvalSequence: request.approval.approvalSequence,
      sessionId: request.staged.sessionId,
      planId: request.staged.planId,
      planHash: request.staged.planHash,
      actionId: FIXTURE_REPAIR_ROLLBACK_ACTION_ID,
      resourceId: FIXTURE_REPAIR_RESOURCE_ID,
      risk: FIXTURE_REPAIR_RISK,
      targetSnapshot: request.staged.targetSnapshot,
      replacedSha256: request.staged.installedSha256,
      restoredSha256: request.staged.restoredSha256,
      backupLocator: request.staged.backupLocator,
      backupSha256: request.staged.backupSha256,
      validationPassed: true,
      finalState: "rolled-back",
    };
  }
}

function stagedRepair(
  request: FixtureRepairStageRequestDto,
): StagedFixtureRepairDto {
  return {
    ...request,
    resourceId: FIXTURE_REPAIR_RESOURCE_ID,
    risk: FIXTURE_REPAIR_RISK,
    targetSnapshot: hash("5"),
    expectedBeforeSha256: hash("2"),
    expectedAfterSha256: hash("3"),
    diffSha256: hash("4"),
    backupLocator,
    planHash: hash("7"),
    backup: FIXTURE_REPAIR_BACKUP,
    validation: FIXTURE_REPAIR_VALIDATION,
    rollback: FIXTURE_REPAIR_ROLLBACK,
  };
}

function finding() {
  return {
    sessionId: "S-fixture-session",
    planId: "P-fixture-repair",
    diagnosisSha256: hash("1"),
    findingId: FIXTURE_REPAIR_FINDING_ID,
    findingVersion: FIXTURE_REPAIR_FINDING_VERSION,
    evidence: [
      { id: "E-z-last", sha256: hash("b") },
      { id: "E-a-first", sha256: hash("a") },
    ],
  } as const;
}

test("binds the exact R2 repair and separately approved rollback", async () => {
  const bridge = new RecordingBridge();
  const driver = new FixtureRepairDriver(bridge);
  const repair = await driver.stage(finding());
  assert.equal(repair.actionId, FIXTURE_REPAIR_ACTION_ID);
  assert.equal(repair.risk, "R2");
  assert.deepEqual(
    repair.evidence.map((item) => item.id),
    ["E-a-first", "E-z-last"],
  );

  const receipt = await driver.execute({
    approvalId: "A-repair",
    approvalSequence: 11,
    planId: repair.planId,
    planHash: repair.planHash,
    targetSnapshot: repair.targetSnapshot,
  });
  const rollback = await driver.stageRollback({
    sessionId: repair.sessionId,
    planId: "P-fixture-rollback",
    repairApprovalId: receipt.approvalId,
  });
  const result = await driver.executeRollback({
    approvalId: "A-rollback",
    approvalSequence: 12,
    planId: rollback.planId,
    planHash: rollback.planHash,
    targetSnapshot: rollback.targetSnapshot,
  });

  assert.equal(result.finalState, "rolled-back");
  assert.deepEqual(
    bridge.calls
      .filter((call) => call.method !== "status")
      .map((call) => call.method),
    ["stage", "execute", "stageRollback", "executeRollback"],
  );
  const stageCall = bridge.calls.find((call) => call.method === "stage");
  assert.deepEqual(Object.keys(stageCall?.value as object).sort(), [
    "actionId",
    "diagnosisSha256",
    "evidence",
    "findingId",
    "findingVersion",
    "planId",
    "sessionId",
  ]);
  assert.doesNotMatch(
    JSON.stringify(bridge.calls),
    /(?:path|shell|command|raw|replacement)/iu,
  );
});

test("rejects uncontracted input and approvals not bound to the staged hash", async () => {
  const bridge = new RecordingBridge();
  const driver = new FixtureRepairDriver(bridge);
  await assert.rejects(
    driver.stage({
      ...finding(),
      path: "/tmp/target",
    } as unknown as Parameters<FixtureRepairDriver["stage"]>[0]),
    /unknown or missing fields/,
  );
  const repair = await driver.stage(finding());
  await assert.rejects(
    driver.execute({
      approvalId: "A-wrong-hash",
      approvalSequence: 11,
      planId: repair.planId,
      planHash: hash("9"),
      targetSnapshot: repair.targetSnapshot,
    }),
    /does not match/,
  );
  assert.equal(
    bridge.calls.filter((call) => call.method === "execute").length,
    0,
  );
});
