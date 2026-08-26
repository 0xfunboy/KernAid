import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";
import type { DiagnosisProposal } from "@kernaid/schemas";
import {
  FIXTURE_REPAIR_ACTION_ID,
  FIXTURE_REPAIR_APPROVAL_TEXT,
  FIXTURE_REPAIR_BACKUP,
  FIXTURE_REPAIR_EVIDENCE_COLLECTOR,
  FIXTURE_REPAIR_EVIDENCE_CONTENT_TYPE,
  FIXTURE_REPAIR_FINDING_ID,
  FIXTURE_REPAIR_FINDING_VERSION,
  FIXTURE_REPAIR_RESOURCE_ID,
  FIXTURE_REPAIR_RISK,
  FIXTURE_REPAIR_ROLLBACK,
  FIXTURE_REPAIR_ROLLBACK_ACTION_ID,
  FIXTURE_REPAIR_VALIDATION,
  FIXTURE_ROLLBACK_APPROVAL_TEXT,
  FIXTURE_ROLLBACK_VALIDATION,
  FixtureRepairSessionDriver,
  parseFixtureRepairSessionArtifact,
  type FixtureRepairExecuteRequestDto,
  type FixtureRepairFindingDto,
  type FixtureRepairReceiptDto,
  type FixtureRepairRecoveryRequestDto,
  type FixtureRepairSessionBridge,
  type FixtureRepairSessionInspection,
  type FixtureRepairStageRequestDto,
  type FixtureRollbackExecuteRequestDto,
  type FixtureRollbackReceiptDto,
  type FixtureRollbackStageRequestDto,
  type StagedFixtureRepairDto,
  type StagedFixtureRollbackDto,
} from "../src/index.js";

const hash = (character: string): string => `sha256:${character.repeat(64)}`;
const fingerprint = hash("9");
const backupLocator = `fixture-lab-backup://linux-fstab/${hash("2")}`;

class SessionBridge implements FixtureRepairSessionBridge {
  nextApprovalSequence = 21;
  findingPresent = true;
  failRepairAfterReceipt = false;
  recoveryUnavailable = false;
  recoveredRepair?: FixtureRepairReceiptDto;
  readonly calls: Array<{ method: string; value?: unknown }> = [];

  async inspect(): Promise<FixtureRepairSessionInspection> {
    this.calls.push({ method: "inspect" });
    return {
      status: {
        enabled: true,
        mutationBlocked: false,
        nextApprovalSequence: this.nextApprovalSequence,
      },
      finding: this.findingPresent ? finding() : null,
    };
  }

  async status() {
    this.calls.push({ method: "status" });
    return {
      enabled: true,
      mutationBlocked: false,
      nextApprovalSequence: this.nextApprovalSequence,
    } as const;
  }

  async stage(
    request: FixtureRepairStageRequestDto,
  ): Promise<StagedFixtureRepairDto> {
    this.calls.push({ method: "stage", value: structuredClone(request) });
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

  async execute(
    request: FixtureRepairExecuteRequestDto,
  ): Promise<FixtureRepairReceiptDto> {
    this.calls.push({ method: "execute", value: structuredClone(request) });
    this.nextApprovalSequence += 1;
    this.findingPresent = false;
    const receipt: FixtureRepairReceiptDto = {
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
    this.recoveredRepair = receipt;
    if (this.failRepairAfterReceipt)
      throw new Error("simulated lost execute response");
    return receipt;
  }

  async recoverRepairForRollback(
    request: FixtureRepairRecoveryRequestDto,
  ): Promise<FixtureRepairReceiptDto> {
    this.calls.push({
      method: "recoverRepairForRollback",
      value: structuredClone(request),
    });
    if (
      this.recoveryUnavailable ||
      this.recoveredRepair?.approvalId !== request.approvalId
    )
      throw new Error("repair receipt unavailable");
    return structuredClone(this.recoveredRepair);
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
    this.findingPresent = true;
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

function finding(): FixtureRepairFindingDto {
  return {
    sessionId: "S-native-inspection",
    planId: "P-native-inspection",
    diagnosisSha256: hash("1"),
    findingId: FIXTURE_REPAIR_FINDING_ID,
    findingVersion: FIXTURE_REPAIR_FINDING_VERSION,
    evidence: [
      { id: "E-LINUX-LSBLK", sha256: hash("b") },
      { id: "E-LINUX-FSTAB", sha256: hash("a") },
    ],
  };
}

async function prepare() {
  const bridge = new SessionBridge();
  const driver = new FixtureRepairSessionDriver(bridge);
  const session = await driver.startSession({
    targetFingerprint: fingerprint,
    mode: "resident",
  });
  const evidence = await driver.requestEvidence(session.id, {
    collector: FIXTURE_REPAIR_EVIDENCE_COLLECTOR,
    target: FIXTURE_REPAIR_RESOURCE_ID,
    contentType: FIXTURE_REPAIR_EVIDENCE_CONTENT_TYPE,
  });
  let proposal: DiagnosisProposal | undefined;
  for await (const event of driver.sendUserPrompt(session.id, "diagnose"))
    if (event.proposal !== undefined) proposal = event.proposal;
  assert.ok(proposal);
  const repair = await driver.stagePlan(session.id, proposal);
  return { bridge, driver, session, evidence, repair };
}

test("runs the closed R2 repair and separately approved rollback through SessionDriver", async () => {
  const { bridge, driver, session, evidence, repair } = await prepare();
  assert.equal(repair.risk, "R2");
  assert.equal(repair.steps[0]?.action, FIXTURE_REPAIR_ACTION_ID);
  assert.deepEqual(
    evidence.map((item) => item.id),
    ["E-LINUX-FSTAB", "E-LINUX-LSBLK"],
  );
  assert.doesNotMatch(
    JSON.stringify(repair),
    /(?:\/tmp\/|shell|command|replacement)/iu,
  );

  await assert.rejects(drain(driver.executePlan(repair.planId)), /approved/iu);
  await assert.rejects(
    driver.approvePlan(repair.planId, {
      schemaVersion: "1.0",
      approvalId: "A-wrong-confirmation",
      planId: repair.planId,
      targetFingerprint: fingerprint,
      approvedAt: new Date().toISOString(),
      approvedBy: "fixture-technician",
      typedConfirmation: "APPROVO",
    }),
    /exact typed confirmation/iu,
  );
  const repairRequirement = await driver.getApprovalRequirement(repair.planId);
  assert.equal(
    repairRequirement.typedConfirmation,
    FIXTURE_REPAIR_APPROVAL_TEXT,
  );
  assert.equal(repairRequirement.nextApprovalSequence, 21);
  await driver.approvePlan(repair.planId, {
    schemaVersion: "1.0",
    approvalId: "A-session-repair",
    planId: repair.planId,
    targetFingerprint: fingerprint,
    approvedAt: new Date().toISOString(),
    approvedBy: "fixture-technician",
    typedConfirmation: FIXTURE_REPAIR_APPROVAL_TEXT,
  });
  const repairEvents = await collect(driver.executePlan(repair.planId));
  assert.deepEqual(
    repairEvents.map((event) => event.status),
    ["started", "succeeded"],
  );
  assert.match(repairEvents[1]?.message ?? "", /before sha256:2{64}/u);
  assert.match(repairEvents[1]?.message ?? "", /backup fixture-lab-backup/u);

  const rollback = await driver.stageRollback(repair.planId);
  assert.equal(rollback.steps[0]?.action, FIXTURE_REPAIR_ROLLBACK_ACTION_ID);
  await assert.rejects(drain(driver.rollback(repair.planId)), /approved/iu);
  await assert.rejects(
    driver.approvePlan(rollback.planId, {
      schemaVersion: "1.0",
      approvalId: "A-session-repair",
      planId: rollback.planId,
      targetFingerprint: fingerprint,
      approvedAt: new Date().toISOString(),
      approvedBy: "fixture-technician",
      typedConfirmation: FIXTURE_ROLLBACK_APPROVAL_TEXT,
    }),
    /already used|second approval/iu,
  );
  const rollbackRequirement = await driver.getApprovalRequirement(
    rollback.planId,
  );
  assert.equal(
    rollbackRequirement.typedConfirmation,
    FIXTURE_ROLLBACK_APPROVAL_TEXT,
  );
  assert.equal(rollbackRequirement.nextApprovalSequence, 22);
  await driver.approvePlan(rollback.planId, {
    schemaVersion: "1.0",
    approvalId: "A-session-rollback",
    planId: rollback.planId,
    targetFingerprint: fingerprint,
    approvedAt: new Date().toISOString(),
    approvedBy: "fixture-technician",
    typedConfirmation: FIXTURE_ROLLBACK_APPROVAL_TEXT,
  });
  const rollbackEvents = await collect(driver.rollback(repair.planId));
  assert.deepEqual(
    rollbackEvents.map((event) => event.status),
    ["started", "rolled-back"],
  );

  const reportRef = await driver.exportReport(session.id, "json");
  assert.equal(reportRef.auditStatus.state, "unavailable");
  const report = decodeDataArtifact(reportRef.uri);
  assert.equal(report.verification, "passed");
  assert.match(JSON.stringify(report), /before sha256:2{64}/u);
  assert.match(JSON.stringify(report), /restored sha256:2{64}/u);
  assert.match(JSON.stringify(report), /non persistente e non firmato/iu);

  const artifactRef = await driver.exportRepairArtifact(session.id);
  assert.equal(artifactRef.auditStatus.state, "unavailable");
  const artifact = parseFixtureRepairSessionArtifact(
    decodeDataArtifact(artifactRef.uri),
  );
  assert.equal(artifact.finalState, "rolled-back");
  assert.equal(artifact.persistence.persistent, false);
  assert.equal(artifact.persistence.signed, false);
  assert.equal(artifact.repair.receipt?.beforeSha256, hash("2"));
  assert.equal(artifact.repair.receipt?.afterSha256, hash("3"));
  assert.equal(artifact.repair.receipt?.backupSha256, hash("2"));
  assert.equal(artifact.rollback?.receipt?.restoredSha256, hash("2"));
  assert.deepEqual(
    bridge.calls
      .filter((call) =>
        ["stage", "execute", "stageRollback", "executeRollback"].includes(
          call.method,
        ),
      )
      .map((call) => call.method),
    ["stage", "execute", "stageRollback", "executeRollback"],
  );
  assert.doesNotMatch(
    JSON.stringify(bridge.calls),
    /(?:\/tmp\/|shell|command|replacement)/iu,
  );
});

test("strictly rejects raw evidence input and tampered repair artifacts", async () => {
  const bridge = new SessionBridge();
  const driver = new FixtureRepairSessionDriver(bridge);
  await assert.rejects(
    driver.startSession({
      targetFingerprint: fingerprint,
      mode: "rescue",
    }),
    /only in resident mode/iu,
  );
  const session = await driver.startSession({
    targetFingerprint: fingerprint,
    mode: "resident",
  });
  await assert.rejects(
    driver.requestEvidence(session.id, {
      collector: FIXTURE_REPAIR_EVIDENCE_COLLECTOR,
      target: FIXTURE_REPAIR_RESOURCE_ID,
      observedContent: "/tmp/fixture",
    }),
    /unknown or missing fields/iu,
  );

  const prepared = await prepare();
  await prepared.driver.getApprovalRequirement(prepared.repair.planId);
  await prepared.driver.approvePlan(prepared.repair.planId, {
    schemaVersion: "1.0",
    approvalId: "A-artifact-repair",
    planId: prepared.repair.planId,
    targetFingerprint: fingerprint,
    approvedAt: new Date().toISOString(),
    approvedBy: "fixture-technician",
    typedConfirmation: FIXTURE_REPAIR_APPROVAL_TEXT,
  });
  await drain(prepared.driver.executePlan(prepared.repair.planId));
  const reference = await prepared.driver.exportRepairArtifact(
    prepared.session.id,
  );
  const artifact = decodeDataArtifact(reference.uri);
  assert.throws(
    () =>
      parseFixtureRepairSessionArtifact({
        ...artifact,
        command: "shell.exec",
      }),
    /unknown or missing fields/iu,
  );
  assert.throws(
    () =>
      parseFixtureRepairSessionArtifact({
        ...artifact,
        repair: {
          ...(artifact.repair as object),
          receipt: {
            ...((artifact.repair as { receipt: object }).receipt ?? {}),
            beforeSha256: hash("8"),
          },
        },
      }),
    /binding/iu,
  );
});

test("binds approval to the sequence that was displayed", async () => {
  const missingDisplay = await prepare();
  await assert.rejects(
    missingDisplay.driver.approvePlan(missingDisplay.repair.planId, {
      schemaVersion: "1.0",
      approvalId: "A-not-displayed",
      planId: missingDisplay.repair.planId,
      targetFingerprint: fingerprint,
      approvedAt: new Date().toISOString(),
      approvedBy: "fixture-technician",
      typedConfirmation: FIXTURE_REPAIR_APPROVAL_TEXT,
    }),
    /must be displayed/iu,
  );

  const stale = await prepare();
  await stale.driver.getApprovalRequirement(stale.repair.planId);
  stale.bridge.nextApprovalSequence += 1;
  await assert.rejects(
    stale.driver.approvePlan(stale.repair.planId, {
      schemaVersion: "1.0",
      approvalId: "A-stale-sequence",
      planId: stale.repair.planId,
      targetFingerprint: fingerprint,
      approvedAt: new Date().toISOString(),
      approvedBy: "fixture-technician",
      typedConfirmation: FIXTURE_REPAIR_APPROVAL_TEXT,
    }),
    /sequence is stale/iu,
  );
  assert.equal(
    stale.bridge.calls.filter((call) => call.method === "execute").length,
    0,
  );
});

test("keeps a recovered repair receipt rollback-only after execute still fails", async () => {
  const prepared = await prepare();
  prepared.bridge.failRepairAfterReceipt = true;
  await prepared.driver.getApprovalRequirement(prepared.repair.planId);
  await prepared.driver.approvePlan(prepared.repair.planId, {
    schemaVersion: "1.0",
    approvalId: "A-recovered-repair",
    planId: prepared.repair.planId,
    targetFingerprint: fingerprint,
    approvedAt: new Date().toISOString(),
    approvedBy: "fixture-technician",
    typedConfirmation: FIXTURE_REPAIR_APPROVAL_TEXT,
  });

  const events = await collect(
    prepared.driver.executePlan(prepared.repair.planId),
  );
  assert.deepEqual(
    events.map((event) => event.status),
    ["started", "failed"],
  );
  const artifact = parseFixtureRepairSessionArtifact(
    decodeDataArtifact(
      (await prepared.driver.exportRepairArtifact(prepared.session.id)).uri,
    ),
  );
  assert.equal(artifact.finalState, "repair-reconciliation-required");
  assert.equal(artifact.repair.executionAttempted, true);
  assert.equal(artifact.repair.postconditionVerified, false);
  assert.equal(artifact.repair.receipt?.approvalId, "A-recovered-repair");
  assert.equal(
    prepared.bridge.calls.filter(
      (call) => call.method === "recoverRepairForRollback",
    ).length,
    1,
  );

  const rollback = await prepared.driver.stageRollback(prepared.repair.planId);
  assert.equal(rollback.steps[0]?.action, FIXTURE_REPAIR_ROLLBACK_ACTION_ID);
});

test("marks attempted execution without a receipt as reconciliation-required", async () => {
  const prepared = await prepare();
  prepared.bridge.failRepairAfterReceipt = true;
  prepared.bridge.recoveryUnavailable = true;
  await prepared.driver.getApprovalRequirement(prepared.repair.planId);
  await prepared.driver.approvePlan(prepared.repair.planId, {
    schemaVersion: "1.0",
    approvalId: "A-unrecovered-repair",
    planId: prepared.repair.planId,
    targetFingerprint: fingerprint,
    approvedAt: new Date().toISOString(),
    approvedBy: "fixture-technician",
    typedConfirmation: FIXTURE_REPAIR_APPROVAL_TEXT,
  });
  await drain(prepared.driver.executePlan(prepared.repair.planId));
  const artifact = parseFixtureRepairSessionArtifact(
    decodeDataArtifact(
      (await prepared.driver.exportRepairArtifact(prepared.session.id)).uri,
    ),
  );
  assert.equal(artifact.finalState, "repair-reconciliation-required");
  assert.equal(artifact.repair.executionAttempted, true);
  assert.equal(artifact.repair.receipt, null);
  await assert.rejects(
    prepared.driver.stageRollback(prepared.repair.planId),
    /receipt is required/iu,
  );
});

test("artifact schema and runtime both reject duplicate evidence bindings", async () => {
  const schema = JSON.parse(
    await readFile(
      new URL(
        "../schemas/fixture-repair-session-artifact-v1.schema.json",
        import.meta.url,
      ),
      "utf8",
    ),
  ) as {
    $defs?: { evidenceList?: { uniqueItems?: boolean } };
  };
  assert.equal(schema.$defs?.evidenceList?.uniqueItems, true);

  const prepared = await prepare();
  const artifact = decodeDataArtifact(
    (await prepared.driver.exportRepairArtifact(prepared.session.id)).uri,
  );
  const repair = artifact.repair as {
    staged: { evidence: Array<{ id: string; sha256: string }> };
  };
  const duplicate = structuredClone(repair.staged.evidence[0]);
  assert.ok(duplicate);
  assert.throws(
    () =>
      parseFixtureRepairSessionArtifact({
        ...artifact,
        repair: {
          ...(artifact.repair as object),
          staged: {
            ...repair.staged,
            evidence: [...repair.staged.evidence, duplicate],
          },
        },
      }),
    /duplicate fixture evidence id/iu,
  );
});

async function collect<T>(iterable: AsyncIterable<T>): Promise<T[]> {
  const values: T[] = [];
  for await (const value of iterable) values.push(value);
  return values;
}

async function drain(iterable: AsyncIterable<unknown>): Promise<void> {
  for await (const value of iterable) void value;
}

function decodeDataArtifact(uri: string): Record<string, unknown> {
  const separator = uri.indexOf(",");
  assert.notEqual(separator, -1);
  return JSON.parse(decodeURIComponent(uri.slice(separator + 1))) as Record<
    string,
    unknown
  >;
}
