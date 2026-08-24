const TYPED_ID = /^[A-Za-z0-9-]+$/;
const SHA256 = /^sha256:[0-9a-f]{64}$/;
const BACKUP_LOCATOR =
  /^fixture-lab-backup:\/\/linux-fstab\/sha256:[0-9a-f]{64}$/;
const MAX_ID_LENGTH = 128;
const MAX_EVIDENCE = 32;

export const FIXTURE_REPAIR_FINDING_ID = "KA-LNX-P0-003" as const;
export const FIXTURE_REPAIR_FINDING_VERSION = 2 as const;
export const FIXTURE_REPAIR_ACTION_ID =
  "linux.fstab.repair-entry.fixture-v1" as const;
export const FIXTURE_REPAIR_ROLLBACK_ACTION_ID = "linux.fstab.restore" as const;
export const FIXTURE_REPAIR_RESOURCE_ID = "fixture:linux-fstab-v1" as const;
export const FIXTURE_REPAIR_RISK = "R2" as const;
export const FIXTURE_REPAIR_BACKUP =
  "required-separate-byte-verified-copy" as const;
export const FIXTURE_REPAIR_VALIDATION =
  "fstab is syntactically parsed and the unique missing UUID entry is disabled" as const;
export const FIXTURE_REPAIR_ROLLBACK =
  "atomically restore the byte-verified backup and original mode/uid/gid" as const;
export const FIXTURE_ROLLBACK_VALIDATION =
  "restored fstab bytes and original mode/uid/gid match the verified backup" as const;

export interface FixtureRepairStatusDto {
  readonly enabled: boolean;
  readonly mutationBlocked: boolean;
  readonly nextApprovalSequence: number | null;
}

export interface FixtureEvidenceBindingDto {
  readonly id: string;
  readonly sha256: string;
}

/** Input from the deterministic diagnosis boundary. It cannot select an action. */
export interface FixtureRepairFindingDto {
  readonly sessionId: string;
  readonly planId: string;
  readonly diagnosisSha256: string;
  readonly findingId: typeof FIXTURE_REPAIR_FINDING_ID;
  readonly findingVersion: typeof FIXTURE_REPAIR_FINDING_VERSION;
  readonly evidence: readonly FixtureEvidenceBindingDto[];
}

/** Exact JSON request consumed by a native fixture-lab adapter. */
export interface FixtureRepairStageRequestDto extends FixtureRepairFindingDto {
  readonly actionId: typeof FIXTURE_REPAIR_ACTION_ID;
}

export interface StagedFixtureRepairDto extends FixtureRepairStageRequestDto {
  readonly resourceId: typeof FIXTURE_REPAIR_RESOURCE_ID;
  readonly risk: typeof FIXTURE_REPAIR_RISK;
  readonly targetSnapshot: string;
  readonly expectedBeforeSha256: string;
  readonly expectedAfterSha256: string;
  readonly diffSha256: string;
  readonly backupLocator: string;
  readonly planHash: string;
  readonly backup: typeof FIXTURE_REPAIR_BACKUP;
  readonly validation: typeof FIXTURE_REPAIR_VALIDATION;
  readonly rollback: typeof FIXTURE_REPAIR_ROLLBACK;
}

/** The UI must approve the exact visible plan and target snapshot. */
export interface FixturePlanApprovalDto {
  readonly approvalId: string;
  readonly approvalSequence: number;
  readonly planId: string;
  readonly planHash: string;
  readonly targetSnapshot: string;
}

export interface FixtureBridgeApprovalDto extends FixturePlanApprovalDto {
  readonly sessionId: string;
}

export interface FixtureRepairExecuteRequestDto {
  readonly staged: StagedFixtureRepairDto;
  readonly approval: FixtureBridgeApprovalDto;
}

export interface FixtureRepairReceiptDto {
  readonly approvalId: string;
  readonly approvalSequence: number;
  readonly sessionId: string;
  readonly planId: string;
  readonly planHash: string;
  readonly actionId: typeof FIXTURE_REPAIR_ACTION_ID;
  readonly resourceId: typeof FIXTURE_REPAIR_RESOURCE_ID;
  readonly risk: typeof FIXTURE_REPAIR_RISK;
  readonly diagnosisSha256: string;
  readonly findingId: typeof FIXTURE_REPAIR_FINDING_ID;
  readonly findingVersion: typeof FIXTURE_REPAIR_FINDING_VERSION;
  readonly evidence: readonly FixtureEvidenceBindingDto[];
  readonly targetSnapshot: string;
  readonly beforeSha256: string;
  readonly afterSha256: string;
  readonly backupLocator: string;
  readonly backupSha256: string;
  readonly validationPassed: true;
}

export interface FixtureRollbackStageRequestDto {
  readonly sessionId: string;
  readonly planId: string;
  readonly repairApprovalId: string;
}

export interface StagedFixtureRollbackDto extends FixtureRollbackStageRequestDto {
  readonly repairPlanHash: string;
  readonly actionId: typeof FIXTURE_REPAIR_ROLLBACK_ACTION_ID;
  readonly resourceId: typeof FIXTURE_REPAIR_RESOURCE_ID;
  readonly risk: typeof FIXTURE_REPAIR_RISK;
  readonly targetSnapshot: string;
  readonly installedSha256: string;
  readonly restoredSha256: string;
  readonly backupLocator: string;
  readonly backupSha256: string;
  readonly planHash: string;
  readonly validation: typeof FIXTURE_ROLLBACK_VALIDATION;
}

export interface FixtureRollbackExecuteRequestDto {
  readonly staged: StagedFixtureRollbackDto;
  readonly approval: FixtureBridgeApprovalDto;
}

export interface FixtureRollbackReceiptDto {
  readonly repairApprovalId: string;
  readonly rollbackApprovalId: string;
  readonly approvalSequence: number;
  readonly sessionId: string;
  readonly planId: string;
  readonly planHash: string;
  readonly actionId: typeof FIXTURE_REPAIR_ROLLBACK_ACTION_ID;
  readonly resourceId: typeof FIXTURE_REPAIR_RESOURCE_ID;
  readonly risk: typeof FIXTURE_REPAIR_RISK;
  readonly targetSnapshot: string;
  readonly replacedSha256: string;
  readonly restoredSha256: string;
  readonly backupLocator: string;
  readonly backupSha256: string;
  readonly validationPassed: true;
  readonly finalState: "rolled-back";
}

/**
 * Native adapters implement this closed bridge. None of its JSON DTOs contains
 * a path, command, shell fragment, raw action, or replacement content.
 */
export interface FixtureRepairBridge {
  status(): Promise<FixtureRepairStatusDto>;
  stage(request: FixtureRepairStageRequestDto): Promise<StagedFixtureRepairDto>;
  execute(
    request: FixtureRepairExecuteRequestDto,
  ): Promise<FixtureRepairReceiptDto>;
  stageRollback(
    request: FixtureRollbackStageRequestDto,
  ): Promise<StagedFixtureRollbackDto>;
  executeRollback(
    request: FixtureRollbackExecuteRequestDto,
  ): Promise<FixtureRollbackReceiptDto>;
}

interface RepairRecord {
  staged: StagedFixtureRepairDto;
  executionAttempted: boolean;
  receipt?: FixtureRepairReceiptDto;
}

interface RollbackRecord {
  staged: StagedFixtureRollbackDto;
  executionAttempted: boolean;
  receipt?: FixtureRollbackReceiptDto;
}

/**
 * Fixture-only orchestration. This class is intentionally separate from the
 * shipping SessionDriver and cannot change LocalSessionDriver defaults.
 */
export class FixtureRepairDriver {
  private readonly repairs = new Map<string, RepairRecord>();
  private readonly rollbacks = new Map<string, RollbackRecord>();
  private readonly approvalIds = new Set<string>();
  private operationTail: Promise<void> = Promise.resolve();

  constructor(private readonly bridge: FixtureRepairBridge) {}

  async status(): Promise<FixtureRepairStatusDto> {
    try {
      return parseStatus(await this.bridge.status());
    } catch {
      throw new Error("fixture repair bridge status is unavailable");
    }
  }

  async stage(value: FixtureRepairFindingDto): Promise<StagedFixtureRepairDto> {
    return this.exclusive(async () => {
      await this.requireReady();
      const finding = parseFinding(value);
      if (
        this.repairs.has(finding.planId) ||
        this.rollbacks.has(finding.planId)
      )
        throw new Error("fixture repair plan id is already staged");
      const request: FixtureRepairStageRequestDto = {
        ...finding,
        actionId: FIXTURE_REPAIR_ACTION_ID,
      };
      let staged: StagedFixtureRepairDto;
      try {
        staged = parseStagedRepair(await this.bridge.stage(clone(request)));
      } catch {
        throw new Error("fixture repair staging was rejected");
      }
      assertRepairStageBinding(request, staged);
      this.repairs.set(staged.planId, {
        staged: clone(staged),
        executionAttempted: false,
      });
      return clone(staged);
    });
  }

  async execute(
    value: FixturePlanApprovalDto,
  ): Promise<FixtureRepairReceiptDto> {
    return this.exclusive(async () => {
      const approval = parsePlanApproval(value);
      const record = this.repairs.get(approval.planId);
      if (record === undefined) throw new Error("unknown fixture repair plan");
      if (record.executionAttempted)
        throw new Error("fixture repair execution was already attempted");
      assertApprovalBinding(record.staged, approval);
      await this.requireApprovalReady(approval);
      const bridgeApproval: FixtureBridgeApprovalDto = {
        ...approval,
        sessionId: record.staged.sessionId,
      };
      record.executionAttempted = true;
      let receipt: FixtureRepairReceiptDto;
      try {
        receipt = parseRepairReceipt(
          await this.bridge.execute({
            staged: clone(record.staged),
            approval: clone(bridgeApproval),
          }),
        );
        assertRepairReceiptBinding(record.staged, bridgeApproval, receipt);
      } catch {
        throw new Error(
          "fixture repair execution outcome requires bridge reconciliation",
        );
      }
      this.approvalIds.add(approval.approvalId);
      record.receipt = clone(receipt);
      return clone(receipt);
    });
  }

  async stageRollback(
    value: FixtureRollbackStageRequestDto,
  ): Promise<StagedFixtureRollbackDto> {
    return this.exclusive(async () => {
      await this.requireReady();
      const request = parseRollbackStageRequest(value);
      if (
        this.repairs.has(request.planId) ||
        this.rollbacks.has(request.planId)
      )
        throw new Error("fixture rollback plan id is already staged");
      const repair = [...this.repairs.values()].find(
        (candidate) =>
          candidate.receipt?.approvalId === request.repairApprovalId,
      );
      if (repair?.receipt === undefined)
        throw new Error("fixture repair receipt is required before rollback");
      if (repair.staged.sessionId !== request.sessionId)
        throw new Error("fixture rollback session does not match the repair");
      let staged: StagedFixtureRollbackDto;
      try {
        staged = parseStagedRollback(
          await this.bridge.stageRollback(clone(request)),
        );
      } catch {
        throw new Error("fixture rollback staging was rejected");
      }
      assertRollbackStageBinding(request, repair.receipt, staged);
      this.rollbacks.set(staged.planId, {
        staged: clone(staged),
        executionAttempted: false,
      });
      return clone(staged);
    });
  }

  async executeRollback(
    value: FixturePlanApprovalDto,
  ): Promise<FixtureRollbackReceiptDto> {
    return this.exclusive(async () => {
      const approval = parsePlanApproval(value);
      const record = this.rollbacks.get(approval.planId);
      if (record === undefined)
        throw new Error("unknown fixture rollback plan");
      if (record.executionAttempted)
        throw new Error("fixture rollback execution was already attempted");
      if (approval.approvalId === record.staged.repairApprovalId)
        throw new Error("fixture rollback requires a second approval");
      assertApprovalBinding(record.staged, approval);
      await this.requireApprovalReady(approval);
      const repair = [...this.repairs.values()].find(
        (candidate) =>
          candidate.receipt?.approvalId === record.staged.repairApprovalId,
      );
      if (
        repair?.receipt === undefined ||
        approval.approvalSequence <= repair.receipt.approvalSequence
      )
        throw new Error("fixture rollback requires a later second approval");
      const bridgeApproval: FixtureBridgeApprovalDto = {
        ...approval,
        sessionId: record.staged.sessionId,
      };
      record.executionAttempted = true;
      let receipt: FixtureRollbackReceiptDto;
      try {
        receipt = parseRollbackReceipt(
          await this.bridge.executeRollback({
            staged: clone(record.staged),
            approval: clone(bridgeApproval),
          }),
        );
        assertRollbackReceiptBinding(record.staged, bridgeApproval, receipt);
      } catch {
        throw new Error(
          "fixture rollback outcome requires bridge reconciliation",
        );
      }
      this.approvalIds.add(approval.approvalId);
      record.receipt = clone(receipt);
      return clone(receipt);
    });
  }

  private async requireReady(): Promise<FixtureRepairStatusDto> {
    const status = await this.status();
    if (!status.enabled)
      throw new Error("fixture repair lab is not enabled by the native bridge");
    if (status.mutationBlocked)
      throw new Error("fixture repair mutation is blocked");
    if (status.nextApprovalSequence === null)
      throw new Error("fixture repair approval capacity is unavailable");
    return status;
  }

  private async requireApprovalReady(
    approval: FixturePlanApprovalDto,
  ): Promise<void> {
    if (this.approvalIds.has(approval.approvalId))
      throw new Error("fixture approval id was already used");
    const status = await this.requireReady();
    if (approval.approvalSequence !== status.nextApprovalSequence)
      throw new Error("fixture approval sequence is not next");
  }

  private async exclusive<Result>(
    operation: () => Promise<Result>,
  ): Promise<Result> {
    const previous = this.operationTail;
    let release = (): void => {};
    this.operationTail = new Promise<void>((resolve) => {
      release = resolve;
    });
    await previous;
    try {
      return await operation();
    } finally {
      release();
    }
  }
}

function parseStatus(value: unknown): FixtureRepairStatusDto {
  const status = exactRecord("fixture repair status", value, [
    "enabled",
    "mutationBlocked",
    "nextApprovalSequence",
  ]);
  if (typeof status.enabled !== "boolean")
    throw new Error("invalid fixture repair status");
  if (typeof status.mutationBlocked !== "boolean")
    throw new Error("invalid fixture repair status");
  const next = status.nextApprovalSequence;
  if (next !== null && (!Number.isSafeInteger(next) || Number(next) < 1))
    throw new Error("invalid fixture repair status");
  if ((!status.enabled || status.mutationBlocked) && next !== null)
    throw new Error("invalid fixture repair status");
  if (status.enabled && !status.mutationBlocked && next === null)
    throw new Error("invalid fixture repair status");
  return {
    enabled: status.enabled,
    mutationBlocked: status.mutationBlocked,
    nextApprovalSequence: next as number | null,
  };
}

function parseFinding(value: unknown): FixtureRepairFindingDto {
  const finding = exactRecord("fixture repair finding", value, [
    "sessionId",
    "planId",
    "diagnosisSha256",
    "findingId",
    "findingVersion",
    "evidence",
  ]);
  const result: FixtureRepairFindingDto = {
    sessionId: typedId(finding.sessionId, "S-", "session id"),
    planId: typedId(finding.planId, "P-", "plan id"),
    diagnosisSha256: sha256(finding.diagnosisSha256, "diagnosis hash"),
    findingId: literal(
      finding.findingId,
      FIXTURE_REPAIR_FINDING_ID,
      "finding id",
    ),
    findingVersion: literal(
      finding.findingVersion,
      FIXTURE_REPAIR_FINDING_VERSION,
      "finding version",
    ),
    evidence: parseEvidence(finding.evidence),
  };
  return result;
}

function parseStageRequest(value: unknown): FixtureRepairStageRequestDto {
  const request = exactRecord("fixture repair stage request", value, [
    "sessionId",
    "planId",
    "diagnosisSha256",
    "findingId",
    "findingVersion",
    "evidence",
    "actionId",
  ]);
  const finding = parseFinding({
    sessionId: request.sessionId,
    planId: request.planId,
    diagnosisSha256: request.diagnosisSha256,
    findingId: request.findingId,
    findingVersion: request.findingVersion,
    evidence: request.evidence,
  });
  return {
    ...finding,
    actionId: literal(
      request.actionId,
      FIXTURE_REPAIR_ACTION_ID,
      "repair action",
    ),
  };
}

function parseStagedRepair(value: unknown): StagedFixtureRepairDto {
  const staged = exactRecord("staged fixture repair", value, [
    "sessionId",
    "planId",
    "diagnosisSha256",
    "findingId",
    "findingVersion",
    "evidence",
    "actionId",
    "resourceId",
    "risk",
    "targetSnapshot",
    "expectedBeforeSha256",
    "expectedAfterSha256",
    "diffSha256",
    "backupLocator",
    "planHash",
    "backup",
    "validation",
    "rollback",
  ]);
  const request = parseStageRequest({
    sessionId: staged.sessionId,
    planId: staged.planId,
    diagnosisSha256: staged.diagnosisSha256,
    findingId: staged.findingId,
    findingVersion: staged.findingVersion,
    evidence: staged.evidence,
    actionId: staged.actionId,
  });
  const before = sha256(staged.expectedBeforeSha256, "before hash");
  const after = sha256(staged.expectedAfterSha256, "after hash");
  if (before === after) throw new Error("fixture repair hashes are identical");
  return {
    ...request,
    resourceId: literal(
      staged.resourceId,
      FIXTURE_REPAIR_RESOURCE_ID,
      "fixture resource",
    ),
    risk: literal(staged.risk, FIXTURE_REPAIR_RISK, "fixture repair risk"),
    targetSnapshot: sha256(staged.targetSnapshot, "target snapshot"),
    expectedBeforeSha256: before,
    expectedAfterSha256: after,
    diffSha256: sha256(staged.diffSha256, "diff hash"),
    backupLocator: backupLocator(staged.backupLocator),
    planHash: sha256(staged.planHash, "plan hash"),
    backup: literal(staged.backup, FIXTURE_REPAIR_BACKUP, "backup declaration"),
    validation: literal(
      staged.validation,
      FIXTURE_REPAIR_VALIDATION,
      "validation declaration",
    ),
    rollback: literal(
      staged.rollback,
      FIXTURE_REPAIR_ROLLBACK,
      "rollback declaration",
    ),
  };
}

function parsePlanApproval(value: unknown): FixturePlanApprovalDto {
  const approval = exactRecord("fixture plan approval", value, [
    "approvalId",
    "approvalSequence",
    "planId",
    "planHash",
    "targetSnapshot",
  ]);
  if (
    !Number.isSafeInteger(approval.approvalSequence) ||
    Number(approval.approvalSequence) < 1
  )
    throw new Error("invalid fixture approval sequence");
  return {
    approvalId: typedId(approval.approvalId, "A-", "approval id"),
    approvalSequence: Number(approval.approvalSequence),
    planId: typedId(approval.planId, "P-", "plan id"),
    planHash: sha256(approval.planHash, "approval plan hash"),
    targetSnapshot: sha256(approval.targetSnapshot, "approval target snapshot"),
  };
}

function parseRepairReceipt(value: unknown): FixtureRepairReceiptDto {
  const receipt = exactRecord("fixture repair receipt", value, [
    "approvalId",
    "approvalSequence",
    "sessionId",
    "planId",
    "planHash",
    "actionId",
    "resourceId",
    "risk",
    "diagnosisSha256",
    "findingId",
    "findingVersion",
    "evidence",
    "targetSnapshot",
    "beforeSha256",
    "afterSha256",
    "backupLocator",
    "backupSha256",
    "validationPassed",
  ]);
  const approval = parseBridgeApproval({
    approvalId: receipt.approvalId,
    approvalSequence: receipt.approvalSequence,
    sessionId: receipt.sessionId,
    planId: receipt.planId,
    planHash: receipt.planHash,
    targetSnapshot: receipt.targetSnapshot,
  });
  const before = sha256(receipt.beforeSha256, "receipt before hash");
  const after = sha256(receipt.afterSha256, "receipt after hash");
  if (before === after) throw new Error("invalid fixture repair receipt");
  return {
    ...approval,
    actionId: literal(
      receipt.actionId,
      FIXTURE_REPAIR_ACTION_ID,
      "receipt action",
    ),
    resourceId: literal(
      receipt.resourceId,
      FIXTURE_REPAIR_RESOURCE_ID,
      "receipt resource",
    ),
    risk: literal(receipt.risk, FIXTURE_REPAIR_RISK, "receipt risk"),
    diagnosisSha256: sha256(receipt.diagnosisSha256, "receipt diagnosis hash"),
    findingId: literal(
      receipt.findingId,
      FIXTURE_REPAIR_FINDING_ID,
      "receipt finding",
    ),
    findingVersion: literal(
      receipt.findingVersion,
      FIXTURE_REPAIR_FINDING_VERSION,
      "receipt finding version",
    ),
    evidence: parseEvidence(receipt.evidence),
    beforeSha256: before,
    afterSha256: after,
    backupLocator: backupLocator(receipt.backupLocator),
    backupSha256: sha256(receipt.backupSha256, "receipt backup hash"),
    validationPassed: literal(
      receipt.validationPassed,
      true,
      "receipt validation result",
    ),
  };
}

function parseRollbackStageRequest(
  value: unknown,
): FixtureRollbackStageRequestDto {
  const request = exactRecord("fixture rollback stage request", value, [
    "sessionId",
    "planId",
    "repairApprovalId",
  ]);
  return {
    sessionId: typedId(request.sessionId, "S-", "rollback session id"),
    planId: typedId(request.planId, "P-", "rollback plan id"),
    repairApprovalId: typedId(
      request.repairApprovalId,
      "A-",
      "repair approval id",
    ),
  };
}

function parseStagedRollback(value: unknown): StagedFixtureRollbackDto {
  const staged = exactRecord("staged fixture rollback", value, [
    "sessionId",
    "planId",
    "repairApprovalId",
    "repairPlanHash",
    "actionId",
    "resourceId",
    "risk",
    "targetSnapshot",
    "installedSha256",
    "restoredSha256",
    "backupLocator",
    "backupSha256",
    "planHash",
    "validation",
  ]);
  const request = parseRollbackStageRequest({
    sessionId: staged.sessionId,
    planId: staged.planId,
    repairApprovalId: staged.repairApprovalId,
  });
  const installed = sha256(staged.installedSha256, "installed hash");
  const restored = sha256(staged.restoredSha256, "restored hash");
  if (installed === restored)
    throw new Error("fixture rollback hashes are identical");
  return {
    ...request,
    repairPlanHash: sha256(staged.repairPlanHash, "repair plan hash"),
    actionId: literal(
      staged.actionId,
      FIXTURE_REPAIR_ROLLBACK_ACTION_ID,
      "rollback action",
    ),
    resourceId: literal(
      staged.resourceId,
      FIXTURE_REPAIR_RESOURCE_ID,
      "rollback resource",
    ),
    risk: literal(staged.risk, FIXTURE_REPAIR_RISK, "rollback risk"),
    targetSnapshot: sha256(staged.targetSnapshot, "rollback target snapshot"),
    installedSha256: installed,
    restoredSha256: restored,
    backupLocator: backupLocator(staged.backupLocator),
    backupSha256: sha256(staged.backupSha256, "rollback backup hash"),
    planHash: sha256(staged.planHash, "rollback plan hash"),
    validation: literal(
      staged.validation,
      FIXTURE_ROLLBACK_VALIDATION,
      "rollback validation",
    ),
  };
}

function parseRollbackReceipt(value: unknown): FixtureRollbackReceiptDto {
  const receipt = exactRecord("fixture rollback receipt", value, [
    "repairApprovalId",
    "rollbackApprovalId",
    "approvalSequence",
    "sessionId",
    "planId",
    "planHash",
    "actionId",
    "resourceId",
    "risk",
    "targetSnapshot",
    "replacedSha256",
    "restoredSha256",
    "backupLocator",
    "backupSha256",
    "validationPassed",
    "finalState",
  ]);
  const sequence = receipt.approvalSequence;
  if (!Number.isSafeInteger(sequence) || Number(sequence) < 1)
    throw new Error("invalid rollback approval sequence");
  return {
    repairApprovalId: typedId(
      receipt.repairApprovalId,
      "A-",
      "repair approval id",
    ),
    rollbackApprovalId: typedId(
      receipt.rollbackApprovalId,
      "A-",
      "rollback approval id",
    ),
    approvalSequence: Number(sequence),
    sessionId: typedId(receipt.sessionId, "S-", "rollback session id"),
    planId: typedId(receipt.planId, "P-", "rollback plan id"),
    planHash: sha256(receipt.planHash, "rollback receipt plan hash"),
    actionId: literal(
      receipt.actionId,
      FIXTURE_REPAIR_ROLLBACK_ACTION_ID,
      "rollback receipt action",
    ),
    resourceId: literal(
      receipt.resourceId,
      FIXTURE_REPAIR_RESOURCE_ID,
      "rollback receipt resource",
    ),
    risk: literal(receipt.risk, FIXTURE_REPAIR_RISK, "rollback receipt risk"),
    targetSnapshot: sha256(
      receipt.targetSnapshot,
      "rollback receipt target snapshot",
    ),
    replacedSha256: sha256(receipt.replacedSha256, "replaced hash"),
    restoredSha256: sha256(receipt.restoredSha256, "restored hash"),
    backupLocator: backupLocator(receipt.backupLocator),
    backupSha256: sha256(receipt.backupSha256, "rollback receipt backup hash"),
    validationPassed: literal(
      receipt.validationPassed,
      true,
      "rollback validation result",
    ),
    finalState: literal(receipt.finalState, "rolled-back", "final state"),
  };
}

function parseBridgeApproval(value: unknown): FixtureBridgeApprovalDto {
  const approval = exactRecord("fixture bridge approval", value, [
    "approvalId",
    "approvalSequence",
    "sessionId",
    "planId",
    "planHash",
    "targetSnapshot",
  ]);
  const parsed = parsePlanApproval({
    approvalId: approval.approvalId,
    approvalSequence: approval.approvalSequence,
    planId: approval.planId,
    planHash: approval.planHash,
    targetSnapshot: approval.targetSnapshot,
  });
  return {
    ...parsed,
    sessionId: typedId(approval.sessionId, "S-", "approval session id"),
  };
}

function parseEvidence(value: unknown): readonly FixtureEvidenceBindingDto[] {
  if (!Array.isArray(value) || value.length < 1 || value.length > MAX_EVIDENCE)
    throw new Error("invalid fixture evidence bindings");
  const result = value.map((item) => {
    const binding = exactRecord("fixture evidence binding", item, [
      "id",
      "sha256",
    ]);
    return {
      id: typedId(binding.id, "E-", "evidence id"),
      sha256: sha256(binding.sha256, "evidence hash"),
    };
  });
  result.sort((left, right) => left.id.localeCompare(right.id));
  if (
    result.some((item, index) => index > 0 && result[index - 1]?.id === item.id)
  )
    throw new Error("duplicate fixture evidence id");
  return result;
}

function assertRepairStageBinding(
  request: FixtureRepairStageRequestDto,
  staged: StagedFixtureRepairDto,
): void {
  if (
    staged.sessionId !== request.sessionId ||
    staged.planId !== request.planId ||
    staged.actionId !== request.actionId ||
    staged.diagnosisSha256 !== request.diagnosisSha256 ||
    staged.findingId !== request.findingId ||
    staged.findingVersion !== request.findingVersion ||
    !sameEvidence(staged.evidence, request.evidence)
  )
    throw new Error("staged fixture repair is not bound to the finding");
}

function assertApprovalBinding(
  staged: Pick<
    StagedFixtureRepairDto | StagedFixtureRollbackDto,
    "planId" | "planHash" | "targetSnapshot"
  >,
  approval: FixturePlanApprovalDto,
): void {
  if (
    approval.planId !== staged.planId ||
    approval.planHash !== staged.planHash ||
    approval.targetSnapshot !== staged.targetSnapshot
  )
    throw new Error("fixture approval does not match the staged plan");
}

function assertRepairReceiptBinding(
  staged: StagedFixtureRepairDto,
  approval: FixtureBridgeApprovalDto,
  receipt: FixtureRepairReceiptDto,
): void {
  if (
    receipt.approvalId !== approval.approvalId ||
    receipt.approvalSequence !== approval.approvalSequence ||
    receipt.sessionId !== staged.sessionId ||
    receipt.planId !== staged.planId ||
    receipt.planHash !== staged.planHash ||
    receipt.actionId !== staged.actionId ||
    receipt.resourceId !== staged.resourceId ||
    receipt.risk !== staged.risk ||
    receipt.diagnosisSha256 !== staged.diagnosisSha256 ||
    receipt.findingId !== staged.findingId ||
    receipt.findingVersion !== staged.findingVersion ||
    !sameEvidence(receipt.evidence, staged.evidence) ||
    receipt.targetSnapshot !== staged.targetSnapshot ||
    receipt.beforeSha256 !== staged.expectedBeforeSha256 ||
    receipt.afterSha256 !== staged.expectedAfterSha256 ||
    receipt.backupLocator !== staged.backupLocator ||
    receipt.backupSha256 !== staged.expectedBeforeSha256
  )
    throw new Error("fixture repair receipt does not match the approved plan");
}

function assertRollbackStageBinding(
  request: FixtureRollbackStageRequestDto,
  repair: FixtureRepairReceiptDto,
  staged: StagedFixtureRollbackDto,
): void {
  if (
    staged.sessionId !== request.sessionId ||
    staged.planId !== request.planId ||
    staged.repairApprovalId !== request.repairApprovalId ||
    staged.repairPlanHash !== repair.planHash ||
    staged.resourceId !== repair.resourceId ||
    staged.installedSha256 !== repair.afterSha256 ||
    staged.restoredSha256 !== repair.beforeSha256 ||
    staged.backupLocator !== repair.backupLocator ||
    staged.backupSha256 !== repair.backupSha256
  )
    throw new Error(
      "staged fixture rollback does not match the repair receipt",
    );
}

function assertRollbackReceiptBinding(
  staged: StagedFixtureRollbackDto,
  approval: FixtureBridgeApprovalDto,
  receipt: FixtureRollbackReceiptDto,
): void {
  if (
    receipt.repairApprovalId !== staged.repairApprovalId ||
    receipt.rollbackApprovalId !== approval.approvalId ||
    receipt.approvalSequence !== approval.approvalSequence ||
    receipt.sessionId !== staged.sessionId ||
    receipt.planId !== staged.planId ||
    receipt.planHash !== staged.planHash ||
    receipt.actionId !== staged.actionId ||
    receipt.resourceId !== staged.resourceId ||
    receipt.risk !== staged.risk ||
    receipt.targetSnapshot !== staged.targetSnapshot ||
    receipt.replacedSha256 !== staged.installedSha256 ||
    receipt.restoredSha256 !== staged.restoredSha256 ||
    receipt.backupLocator !== staged.backupLocator ||
    receipt.backupSha256 !== staged.backupSha256
  )
    throw new Error(
      "fixture rollback receipt does not match the approved plan",
    );
}

function exactRecord(
  name: string,
  value: unknown,
  keys: readonly string[],
): Record<string, unknown> {
  if (typeof value !== "object" || value === null || Array.isArray(value))
    throw new Error(`${name} must be a JSON object`);
  const record = value as Record<string, unknown>;
  const actual = Object.keys(record).sort();
  const expected = [...keys].sort();
  if (
    actual.length !== expected.length ||
    actual.some((key, index) => key !== expected[index])
  )
    throw new Error(`${name} has unknown or missing fields`);
  return record;
}

function typedId(
  value: unknown,
  prefix: "S-" | "P-" | "E-" | "A-",
  name: string,
): string {
  if (
    typeof value !== "string" ||
    value.length <= prefix.length ||
    value.length > MAX_ID_LENGTH ||
    !value.startsWith(prefix) ||
    !TYPED_ID.test(value.slice(prefix.length))
  )
    throw new Error(`invalid fixture ${name}`);
  return value;
}

function sha256(value: unknown, name: string): string {
  if (typeof value !== "string" || !SHA256.test(value))
    throw new Error(`invalid fixture ${name}`);
  return value;
}

function backupLocator(value: unknown): string {
  if (typeof value !== "string" || !BACKUP_LOCATOR.test(value))
    throw new Error("invalid fixture backup locator");
  return value;
}

function literal<const Value extends string | number | boolean>(
  value: unknown,
  expected: Value,
  name: string,
): Value {
  if (value !== expected) throw new Error(`invalid fixture ${name}`);
  return expected;
}

function sameEvidence(
  left: readonly FixtureEvidenceBindingDto[],
  right: readonly FixtureEvidenceBindingDto[],
): boolean {
  return (
    left.length === right.length &&
    left.every(
      (item, index) =>
        item.id === right[index]?.id && item.sha256 === right[index]?.sha256,
    )
  );
}

function clone<Value>(value: Value): Value {
  return structuredClone(value);
}
