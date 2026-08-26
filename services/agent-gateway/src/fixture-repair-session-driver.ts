import type {
  ArtifactRef,
  AuditRecord,
  AuditRecordType,
  EvidenceRequest,
  PlanApprovalRequirement,
  ReportFormat,
  ReversibleSessionDriver,
  SessionEvent,
  SessionInfo,
  StartSession,
} from "@kernaid/session-driver";
import {
  UNAVAILABLE_AUDIT_STATUS,
  parseArtifactRef,
  parseAuditRecord,
} from "@kernaid/session-driver";
import {
  parseApproval,
  parseDiagnosisProposal,
  parseEvidence,
  parseExecutionEvent,
  parseSessionReport,
  parseValidatedPlan,
  type Approval,
  type DiagnosisProposal,
  type Evidence,
  type ExecutionEvent,
  type SessionReport,
  type ValidatedPlan,
} from "@kernaid/schemas";
import { InMemoryAuditSink } from "./audit-sink.js";
import {
  FIXTURE_REPAIR_ACTION_ID,
  FIXTURE_REPAIR_FINDING_ID,
  FIXTURE_REPAIR_RESOURCE_ID,
  FIXTURE_REPAIR_RISK,
  FIXTURE_REPAIR_ROLLBACK_ACTION_ID,
  FixtureRepairDriver,
  parseFixtureRepairFindingDto,
  parseFixtureRepairReceiptDto,
  parseFixtureRepairStatusDto,
  parseFixtureRollbackReceiptDto,
  parseStagedFixtureRepairDto,
  parseStagedFixtureRollbackDto,
  type FixtureBridgeApprovalDto,
  type FixtureRepairBridge,
  type FixtureRepairFindingDto,
  type FixtureRepairReceiptDto,
  type FixtureRepairStatusDto,
  type FixtureRollbackReceiptDto,
  type StagedFixtureRepairDto,
  type StagedFixtureRollbackDto,
} from "./fixture-repair-driver.js";

const PREFIXED_SHA256 = /^sha256:[0-9a-f]{64}$/u;
const TYPED_ID = /^[A-Za-z0-9-]+$/u;
const MAX_PROMPT_LENGTH = 8 * 1024;
const ARTIFACT_REASON =
  "native signed receipt envelope is not exposed by this bridge" as const;

export const FIXTURE_REPAIR_EVIDENCE_COLLECTOR =
  "linux.fixture-repair.finding.v2" as const;
export const FIXTURE_REPAIR_EVIDENCE_CONTENT_TYPE =
  "application/vnd.kernaid.fixture-evidence-binding+json" as const;
export const FIXTURE_REPAIR_APPROVAL_TEXT = "APPROVO RIPARAZIONE R2" as const;
export const FIXTURE_ROLLBACK_APPROVAL_TEXT = "APPROVO ROLLBACK R2" as const;
export const FIXTURE_REPAIR_SESSION_ARTIFACT_API_VERSION =
  "kernaid.dev/fixture-repair-session-artifact/v1" as const;
export const FIXTURE_REPAIR_SESSION_ARTIFACT_KIND =
  "FixtureRepairSessionArtifact" as const;

export interface FixtureRepairSessionInspection {
  readonly status: FixtureRepairStatusDto;
  readonly finding: FixtureRepairFindingDto | null;
}

/**
 * Opt-in bridge required by the adapter. Normal LocalSessionDriver
 * construction never creates this bridge and therefore cannot mutate.
 */
export interface FixtureRepairSessionBridge extends FixtureRepairBridge {
  inspect(): Promise<FixtureRepairSessionInspection>;
}

export interface FixtureSessionApprovalArtifact extends Approval {
  readonly sessionId: string;
  readonly approvalSequence: number;
  readonly planHash: string;
  readonly targetSnapshot: string;
}

export interface FixtureRepairSessionArtifact {
  readonly apiVersion: typeof FIXTURE_REPAIR_SESSION_ARTIFACT_API_VERSION;
  readonly kind: typeof FIXTURE_REPAIR_SESSION_ARTIFACT_KIND;
  readonly sessionId: string;
  readonly targetFingerprint: string;
  readonly persistence: {
    readonly persistent: false;
    readonly signed: false;
    readonly reason: typeof ARTIFACT_REASON;
  };
  readonly repair: {
    readonly staged: StagedFixtureRepairDto;
    readonly approval: FixtureSessionApprovalArtifact | null;
    readonly receipt: FixtureRepairReceiptDto | null;
    readonly executionAttempted: boolean;
    readonly postconditionVerified: boolean;
  };
  readonly rollback: {
    readonly staged: StagedFixtureRollbackDto;
    readonly approval: FixtureSessionApprovalArtifact | null;
    readonly receipt: FixtureRollbackReceiptDto | null;
    readonly executionAttempted: boolean;
    readonly postconditionVerified: boolean;
  } | null;
  readonly finalState:
    | "repair-staged"
    | "repair-reconciliation-required"
    | "repaired"
    | "rollback-staged"
    | "rollback-reconciliation-required"
    | "rolled-back";
}

type SessionState =
  | "observe"
  | "diagnose"
  | "plan"
  | "executing"
  | "complete"
  | "failed"
  | "rolled-back";

interface SessionRecord {
  readonly input: StartSession;
  state: SessionState;
  auditSequence: number;
  operationTail: Promise<void>;
  finding?: FixtureRepairFindingDto;
  evidence: Evidence[];
  proposals: DiagnosisProposal[];
  decisions: Approval[];
  events: ExecutionEvent[];
}

interface StoredApproval {
  readonly decision: Approval;
  readonly bridge: FixtureBridgeApprovalDto;
}

interface RepairPlanRecord {
  readonly kind: "repair";
  readonly sessionId: string;
  readonly plan: ValidatedPlan;
  readonly staged: StagedFixtureRepairDto;
  approval?: StoredApproval;
  displayedApprovalSequence?: number;
  executionAttempted: boolean;
  postconditionVerified: boolean;
  receipt?: FixtureRepairReceiptDto;
}

interface RollbackPlanRecord {
  readonly kind: "rollback";
  readonly sessionId: string;
  readonly repairPlanId: string;
  readonly plan: ValidatedPlan;
  readonly staged: StagedFixtureRollbackDto;
  approval?: StoredApproval;
  displayedApprovalSequence?: number;
  executionAttempted: boolean;
  postconditionVerified: boolean;
  receipt?: FixtureRollbackReceiptDto;
}

type PlanRecord = RepairPlanRecord | RollbackPlanRecord;

/**
 * SessionDriver-compatible orchestration for the disposable fixture target.
 * It is inert until explicitly constructed with the opt-in native bridge.
 * The bridge owns every byte, locator and mutation primitive; this class only
 * passes closed IDs, hashes and approvals.
 */
export class FixtureRepairSessionDriver implements ReversibleSessionDriver {
  readonly #sessions = new Map<string, SessionRecord>();
  readonly #plans = new Map<string, PlanRecord>();
  readonly #fixture: FixtureRepairDriver;
  readonly #audit = new InMemoryAuditSink();

  constructor(private readonly bridge: FixtureRepairSessionBridge) {
    this.#fixture = new FixtureRepairDriver(bridge);
  }

  async startSession(value: StartSession): Promise<SessionInfo> {
    if (this.#sessions.size !== 0)
      throw new Error("fixture repair bridge already has an active session");
    const input = parseStartSession(value);
    await this.requireInspection();
    const id = `S-${crypto.randomUUID()}`;
    const session: SessionRecord = {
      input,
      state: "observe",
      auditSequence: 0,
      operationTail: Promise.resolve(),
      evidence: [],
      proposals: [],
      decisions: [],
      events: [],
    };
    await this.appendAudit(session, id, "session.started", {
      mode: input.mode,
      targetFingerprint: input.targetFingerprint,
    });
    this.#sessions.set(id, session);
    return {
      id,
      state: "observe",
      auditStatus: structuredClone(UNAVAILABLE_AUDIT_STATUS),
    };
  }

  async requestEvidence(
    sessionId: string,
    value: EvidenceRequest,
  ): Promise<Evidence[]> {
    const session = this.session(sessionId);
    return this.withSessionOperation(session, async () => {
      if (session.state !== "observe" || session.evidence.length !== 0)
        throw new Error("fixture evidence was already collected");
      parseFixtureEvidenceRequest(value);
      const inspection = await this.requireInspection();
      if (inspection.finding === null)
        throw new Error("the fixture repair finding is not present");
      const finding = parseFixtureRepairFindingDto(inspection.finding);
      const capturedAt = new Date().toISOString();
      const evidence = finding.evidence.map((binding) =>
        parseEvidence({
          schemaVersion: "1.0",
          id: binding.id,
          collector: FIXTURE_REPAIR_EVIDENCE_COLLECTOR,
          target: FIXTURE_REPAIR_RESOURCE_ID,
          capturedAt,
          contentType: FIXTURE_REPAIR_EVIDENCE_CONTENT_TYPE,
          sha256: binding.sha256.slice("sha256:".length),
          sensitivity: "system",
          trust: "observed-untrusted",
          summary: `Binding nativo ${binding.id} per ${FIXTURE_REPAIR_FINDING_ID}`,
          blobRef: binding.sha256,
        }),
      );
      for (const item of evidence)
        await this.appendAudit(
          session,
          sessionId,
          "evidence",
          {
            evidenceId: item.id,
            sha256: item.sha256,
            sensitivity: item.sensitivity,
          },
          item.capturedAt,
        );
      session.finding = finding;
      session.evidence.push(...evidence);
      return structuredClone(evidence);
    });
  }

  async *sendUserPrompt(
    sessionId: string,
    prompt: string,
  ): AsyncIterable<SessionEvent> {
    const session = this.session(sessionId);
    const events = await this.withSessionOperation(session, async () => {
      if (session.state !== "observe" || session.finding === undefined)
        throw new Error("fixture evidence is required before diagnosis");
      if (!prompt.trim() || prompt.length > MAX_PROMPT_LENGTH)
        throw new Error("objective is required and must be bounded");
      await this.assertFindingCurrent(session.finding);
      const proposal = parseDiagnosisProposal({
        schemaVersion: "1.0",
        diagnosis:
          "Una voce fstab con UUID assente blocca il target fixture; e disponibile una riparazione R2 reversibile.",
        confidence: 1,
        evidenceIds: session.finding.evidence.map((item) => item.id),
        requestedEvidence: [],
      });
      await this.appendAudit(session, sessionId, "diagnosis", {
        diagnosisSha256: await sha256(proposal.diagnosis),
        confidence: proposal.confidence,
        evidenceIds: proposal.evidenceIds,
        requestedEvidenceCount: 0,
      });
      session.proposals.push(proposal);
      session.state = "diagnose";
      return [
        {
          type: "status",
          message:
            "Finding fixture deterministico verificato dal bridge nativo",
        },
        {
          type: "proposal",
          message: proposal.diagnosis,
          proposal: structuredClone(proposal),
        },
      ] satisfies SessionEvent[];
    });
    for (const event of events) yield event;
  }

  async stagePlan(
    sessionId: string,
    value: DiagnosisProposal,
  ): Promise<ValidatedPlan> {
    const session = this.session(sessionId);
    return this.withSessionOperation(session, async () => {
      if (session.state !== "diagnose" || session.finding === undefined)
        throw new Error("fixture session is not ready to stage a plan");
      const proposal = parseDiagnosisProposal(value);
      if (!session.proposals.some((issued) => sameProposal(issued, proposal)))
        throw new Error("proposal was not issued for this fixture session");
      await this.assertFindingCurrent(session.finding);
      const planId = `P-${crypto.randomUUID()}`;
      const staged = await this.#fixture.stage({
        ...session.finding,
        sessionId,
        planId,
      });
      const plan = parseValidatedPlan({
        schemaVersion: "1.0",
        planId,
        targetFingerprint: session.input.targetFingerprint,
        diagnosis: proposal.diagnosis,
        evidenceIds: proposal.evidenceIds,
        risk: FIXTURE_REPAIR_RISK,
        steps: [
          {
            action: FIXTURE_REPAIR_ACTION_ID,
            args: repairPlanArgs(staged),
            preconditions: [
              "fixture.disposable-marker-verified",
              "evidence.hashes-match",
              "target.snapshot-still-matches",
            ],
            backup: "required",
            validation: staged.validation,
            rollback: staged.rollback,
          },
        ],
      });
      await this.appendAudit(session, sessionId, "plan", {
        planId,
        targetFingerprint: plan.targetFingerprint,
        risk: plan.risk,
        evidenceIds: plan.evidenceIds,
        actions: [FIXTURE_REPAIR_ACTION_ID],
      });
      this.#plans.set(planId, {
        kind: "repair",
        sessionId,
        plan,
        staged,
        executionAttempted: false,
        postconditionVerified: false,
      });
      session.state = "plan";
      return structuredClone(plan);
    });
  }

  async getApprovalRequirement(
    planId: string,
  ): Promise<PlanApprovalRequirement> {
    const record = this.plan(planId);
    const session = this.session(record.sessionId);
    return this.withSessionOperation(session, async () => {
      if (record.approval !== undefined || record.executionAttempted)
        throw new Error("fixture plan is no longer awaiting approval");
      const status = await this.readyStatus();
      record.displayedApprovalSequence = status.nextApprovalSequence;
      return {
        schemaVersion: "1.0",
        planId,
        risk: "R2",
        typedConfirmation:
          record.kind === "repair"
            ? FIXTURE_REPAIR_APPROVAL_TEXT
            : FIXTURE_ROLLBACK_APPROVAL_TEXT,
        planHash: record.staged.planHash,
        targetSnapshot: record.staged.targetSnapshot,
        nextApprovalSequence: status.nextApprovalSequence,
      };
    });
  }

  async approvePlan(planId: string, value: Approval): Promise<void> {
    const record = this.plan(planId);
    const session = this.session(record.sessionId);
    await this.withSessionOperation(session, async () => {
      if (
        session.state !== "plan" ||
        record.approval !== undefined ||
        record.executionAttempted
      )
        throw new Error("fixture plan is not awaiting approval");
      const approval = parseApproval(value);
      if (
        approval.planId !== planId ||
        approval.targetFingerprint !== record.plan.targetFingerprint
      )
        throw new Error("approval does not match the staged fixture plan");
      const expected =
        record.kind === "repair"
          ? FIXTURE_REPAIR_APPROVAL_TEXT
          : FIXTURE_ROLLBACK_APPROVAL_TEXT;
      if (approval.typedConfirmation !== expected)
        throw new Error("exact typed confirmation is required");
      if (
        session.decisions.some(
          (decision) => decision.approvalId === approval.approvalId,
        )
      )
        throw new Error("fixture approval id was already used");
      if (
        record.kind === "rollback" &&
        this.repairRecord(record.repairPlanId).approval?.decision.approvalId ===
          approval.approvalId
      )
        throw new Error("fixture rollback requires a second approval");
      if (record.displayedApprovalSequence === undefined)
        throw new Error("approval requirement must be displayed first");
      const status = await this.readyStatus();
      if (status.nextApprovalSequence !== record.displayedApprovalSequence)
        throw new Error("displayed fixture approval sequence is stale");
      const bridge: FixtureBridgeApprovalDto = {
        approvalId: approval.approvalId,
        approvalSequence: record.displayedApprovalSequence,
        sessionId: record.sessionId,
        planId,
        planHash: record.staged.planHash,
        targetSnapshot: record.staged.targetSnapshot,
      };
      await this.appendAudit(session, record.sessionId, "approval", {
        approvalId: approval.approvalId,
        planId,
        targetFingerprint: approval.targetFingerprint,
        approvedAt: approval.approvedAt,
        approvedBySha256: await sha256(approval.approvedBy),
      });
      record.approval = { decision: approval, bridge };
      session.decisions.push(approval);
    });
  }

  async *executePlan(planId: string): AsyncIterable<ExecutionEvent> {
    const plan = this.plan(planId);
    if (plan.kind !== "repair")
      throw new Error("a staged rollback must use rollback()");
    const session = this.session(plan.sessionId);
    const release = await this.acquireSessionOperation(session);
    try {
      if (
        session.state !== "plan" ||
        plan.approval === undefined ||
        plan.executionAttempted
      )
        throw new Error("approved fixture repair plan is required");
      plan.executionAttempted = true;
      session.state = "executing";
      const started = await this.recordEvent(
        session,
        plan,
        "started",
        "Riparazione R2 fixture avviata con piano, target e approvazione vincolati",
      );
      yield structuredClone(started);
      try {
        plan.receipt = await this.#fixture.execute(
          fixtureDriverApproval(plan.approval.bridge),
        );
        const inspection = await this.requireInspection();
        if (inspection.finding !== null)
          throw new Error("fixture repair postcondition was not observed");
        plan.postconditionVerified = true;
      } catch {
        plan.receipt ??=
          this.#fixture.recoveryReceipt(plan.plan.planId) ?? undefined;
        const failed = await this.recordEvent(
          session,
          plan,
          "failed",
          "Esito della riparazione non riconciliato; nessun nuovo tentativo e consentito",
        );
        session.state = "failed";
        yield structuredClone(failed);
        return;
      }
      const succeeded = await this.recordEvent(
        session,
        plan,
        "succeeded",
        repairReceiptSummary(plan.receipt),
      );
      session.state = "complete";
      yield structuredClone(succeeded);
    } finally {
      release();
    }
  }

  async stageRollback(repairPlanId: string): Promise<ValidatedPlan> {
    const repair = this.repairRecord(repairPlanId);
    const session = this.session(repair.sessionId);
    return this.withSessionOperation(session, async () => {
      if (
        (session.state !== "complete" && session.state !== "failed") ||
        repair.receipt === undefined ||
        [...this.#plans.values()].some(
          (candidate) =>
            candidate.kind === "rollback" &&
            candidate.repairPlanId === repairPlanId,
        )
      )
        throw new Error("a verified repair receipt is required for rollback");
      const planId = `P-${crypto.randomUUID()}`;
      const staged = await this.#fixture.stageRollback({
        sessionId: repair.sessionId,
        planId,
        repairApprovalId: repair.receipt.approvalId,
      });
      const plan = parseValidatedPlan({
        schemaVersion: "1.0",
        planId,
        targetFingerprint: repair.plan.targetFingerprint,
        diagnosis: "Ripristino byte-verificato della riparazione fixture R2",
        evidenceIds: repair.plan.evidenceIds,
        risk: FIXTURE_REPAIR_RISK,
        steps: [
          {
            action: FIXTURE_REPAIR_ROLLBACK_ACTION_ID,
            args: rollbackPlanArgs(staged),
            preconditions: [
              "repair.receipt-verified",
              "backup.hash-matches",
              "target.snapshot-still-matches",
            ],
            backup: "inherited",
            validation: staged.validation,
            rollback: null,
          },
        ],
      });
      await this.appendAudit(session, repair.sessionId, "plan", {
        planId,
        targetFingerprint: plan.targetFingerprint,
        risk: plan.risk,
        evidenceIds: plan.evidenceIds,
        actions: [FIXTURE_REPAIR_ROLLBACK_ACTION_ID],
      });
      this.#plans.set(planId, {
        kind: "rollback",
        sessionId: repair.sessionId,
        repairPlanId,
        plan,
        staged,
        executionAttempted: false,
        postconditionVerified: false,
      });
      session.state = "plan";
      return structuredClone(plan);
    });
  }

  async *rollback(planId: string): AsyncIterable<ExecutionEvent> {
    const supplied = this.plan(planId);
    const plan =
      supplied.kind === "rollback"
        ? supplied
        : [...this.#plans.values()].find(
            (candidate): candidate is RollbackPlanRecord =>
              candidate.kind === "rollback" &&
              candidate.repairPlanId === supplied.plan.planId,
          );
    if (plan === undefined)
      throw new Error("rollback must be staged and separately approved");
    const session = this.session(plan.sessionId);
    const release = await this.acquireSessionOperation(session);
    try {
      if (
        session.state !== "plan" ||
        plan.approval === undefined ||
        plan.executionAttempted
      )
        throw new Error("separately approved fixture rollback is required");
      plan.executionAttempted = true;
      session.state = "executing";
      const started = await this.recordEvent(
        session,
        plan,
        "started",
        "Rollback R2 fixture avviato con seconda approvazione indipendente",
      );
      yield structuredClone(started);
      try {
        plan.receipt = await this.#fixture.executeRollback(
          fixtureDriverApproval(plan.approval.bridge),
        );
        const inspection = await this.requireInspection();
        if (
          inspection.finding === null ||
          session.finding === undefined ||
          !sameFinding(session.finding, inspection.finding)
        )
          throw new Error("fixture rollback postcondition was not observed");
        plan.postconditionVerified = true;
      } catch {
        const failed = await this.recordEvent(
          session,
          plan,
          "failed",
          "Esito del rollback non riconciliato; nessun nuovo tentativo e consentito",
        );
        session.state = "failed";
        yield structuredClone(failed);
        return;
      }
      const rolledBack = await this.recordEvent(
        session,
        plan,
        "rolled-back",
        rollbackReceiptSummary(plan.receipt),
      );
      session.state = "rolled-back";
      yield structuredClone(rolledBack);
    } finally {
      release();
    }
  }

  async exportReport(
    sessionId: string,
    format: ReportFormat,
  ): Promise<ArtifactRef> {
    if (format !== "json" && format !== "markdown")
      throw new Error("unsupported report format");
    const session = this.session(sessionId);
    return this.withSessionOperation(session, async () => {
      const verification = verificationState(session);
      const report = parseSessionReport({
        schemaVersion: "1.0",
        sessionId,
        targetFingerprint: session.input.targetFingerprint,
        facts: session.evidence,
        inferences: session.proposals,
        decisions: session.decisions,
        events: session.events,
        verification,
        unresolvedRisks: unresolvedRisks(session, this.rollbackFor(sessionId)),
      });
      const body =
        format === "json"
          ? JSON.stringify(report, null, 2)
          : markdownReport(report);
      const payloadMediaType =
        format === "json" ? "application/json" : "text/markdown";
      const payloadSha256 = await sha256(body);
      await this.appendAudit(session, sessionId, "report", {
        format,
        payloadMediaType,
        payloadSha256,
        verification,
      });
      return parseArtifactRef(
        await this.#audit.sealReport({
          schemaVersion: "1.0",
          sessionId,
          format,
          payloadMediaType,
          body,
          payloadSha256,
        }),
      );
    });
  }

  async exportRepairArtifact(sessionId: string): Promise<ArtifactRef> {
    const session = this.session(sessionId);
    return this.withSessionOperation(session, async () => {
      const repair = [...this.#plans.values()].find(
        (candidate): candidate is RepairPlanRecord =>
          candidate.kind === "repair" && candidate.sessionId === sessionId,
      );
      if (repair === undefined)
        throw new Error("fixture repair must be staged before artifact export");
      const rollback = this.rollbackFor(sessionId);
      const artifact = parseFixtureRepairSessionArtifact({
        apiVersion: FIXTURE_REPAIR_SESSION_ARTIFACT_API_VERSION,
        kind: FIXTURE_REPAIR_SESSION_ARTIFACT_KIND,
        sessionId,
        targetFingerprint: session.input.targetFingerprint,
        persistence: {
          persistent: false,
          signed: false,
          reason: ARTIFACT_REASON,
        },
        repair: {
          staged: repair.staged,
          approval: approvalArtifact(repair),
          receipt: repair.receipt ?? null,
          executionAttempted: repair.executionAttempted,
          postconditionVerified: repair.postconditionVerified,
        },
        rollback:
          rollback === undefined
            ? null
            : {
                staged: rollback.staged,
                approval: approvalArtifact(rollback),
                receipt: rollback.receipt ?? null,
                executionAttempted: rollback.executionAttempted,
                postconditionVerified: rollback.postconditionVerified,
              },
        finalState: artifactState(repair, rollback),
      });
      const body = JSON.stringify(artifact, null, 2);
      const digest = await sha256(body);
      return parseArtifactRef({
        mediaType: "application/json",
        payloadMediaType: "application/json",
        uri: `data:application/json;charset=utf-8,${encodeURIComponent(body)}`,
        sha256: digest,
        payloadSha256: digest,
        auditStatus: UNAVAILABLE_AUDIT_STATUS,
      });
    });
  }

  private async requireInspection(): Promise<FixtureRepairSessionInspection> {
    let value: FixtureRepairSessionInspection;
    try {
      value = await this.bridge.inspect();
    } catch {
      throw new Error("fixture repair bridge inspection is unavailable");
    }
    const status = parseFixtureRepairStatusDto(value.status);
    if (!status.enabled || status.mutationBlocked)
      throw new Error("fixture repair mutation is not explicitly enabled");
    return {
      status,
      finding:
        value.finding === null
          ? null
          : parseFixtureRepairFindingDto(value.finding),
    };
  }

  private async assertFindingCurrent(
    expected: FixtureRepairFindingDto,
  ): Promise<void> {
    const inspection = await this.requireInspection();
    if (
      inspection.finding === null ||
      !sameFinding(expected, inspection.finding)
    )
      throw new Error("fixture finding or evidence changed before staging");
  }

  private async readyStatus(): Promise<{
    nextApprovalSequence: number;
  }> {
    const status = await this.#fixture.status();
    if (
      !status.enabled ||
      status.mutationBlocked ||
      status.nextApprovalSequence === null
    )
      throw new Error("fixture approval capacity is unavailable");
    return { nextApprovalSequence: status.nextApprovalSequence };
  }

  private async recordEvent(
    session: SessionRecord,
    record: PlanRecord,
    status: ExecutionEvent["status"],
    message: string,
  ): Promise<ExecutionEvent> {
    const event = parseExecutionEvent({
      schemaVersion: "1.0",
      planId: record.plan.planId,
      sequence: session.events.length + 1,
      status,
      action:
        record.kind === "repair"
          ? FIXTURE_REPAIR_ACTION_ID
          : FIXTURE_REPAIR_ROLLBACK_ACTION_ID,
      message,
      capturedAt: new Date().toISOString(),
    });
    await this.appendAudit(
      session,
      record.sessionId,
      "execution",
      {
        planId: event.planId,
        eventSequence: event.sequence,
        status: event.status,
        action: event.action,
      },
      event.capturedAt,
    );
    session.events.push(event);
    return event;
  }

  private async appendAudit(
    session: SessionRecord,
    sessionId: string,
    type: AuditRecordType,
    payload: AuditRecord["payload"],
    capturedAt = new Date().toISOString(),
  ): Promise<void> {
    const record = parseAuditRecord({
      schemaVersion: "1.0",
      type,
      sessionId,
      sequence: session.auditSequence + 1,
      capturedAt,
      payload,
    });
    await this.#audit.append(record);
    session.auditSequence += 1;
  }

  private async withSessionOperation<Result>(
    session: SessionRecord,
    operation: () => Promise<Result>,
  ): Promise<Result> {
    const release = await this.acquireSessionOperation(session);
    try {
      return await operation();
    } finally {
      release();
    }
  }

  private async acquireSessionOperation(
    session: SessionRecord,
  ): Promise<() => void> {
    const previous = session.operationTail;
    let release = (): void => {};
    session.operationTail = new Promise<void>((resolve) => {
      release = resolve;
    });
    await previous;
    let released = false;
    return () => {
      if (released) return;
      released = true;
      release();
    };
  }

  private session(sessionId: string): SessionRecord {
    const session = this.#sessions.get(sessionId);
    if (session === undefined) throw new Error("unknown fixture session");
    return session;
  }

  private plan(planId: string): PlanRecord {
    const plan = this.#plans.get(planId);
    if (plan === undefined) throw new Error("unknown fixture plan");
    return plan;
  }

  private repairRecord(planId: string): RepairPlanRecord {
    const plan = this.plan(planId);
    if (plan.kind !== "repair") throw new Error("repair plan is required");
    return plan;
  }

  private rollbackFor(sessionId: string): RollbackPlanRecord | undefined {
    return [...this.#plans.values()].find(
      (candidate): candidate is RollbackPlanRecord =>
        candidate.kind === "rollback" && candidate.sessionId === sessionId,
    );
  }
}

export function parseFixtureRepairSessionArtifact(
  value: unknown,
): FixtureRepairSessionArtifact {
  const artifact = exactRecord("fixture repair session artifact", value, [
    "apiVersion",
    "kind",
    "sessionId",
    "targetFingerprint",
    "persistence",
    "repair",
    "rollback",
    "finalState",
  ]);
  if (
    artifact.apiVersion !== FIXTURE_REPAIR_SESSION_ARTIFACT_API_VERSION ||
    artifact.kind !== FIXTURE_REPAIR_SESSION_ARTIFACT_KIND
  )
    throw new Error("unsupported fixture repair artifact version");
  const sessionId = typedId(artifact.sessionId, "S-", "artifact session id");
  const targetFingerprint = prefixedHash(
    artifact.targetFingerprint,
    "artifact target fingerprint",
  );
  const persistence = exactRecord(
    "fixture artifact persistence",
    artifact.persistence,
    ["persistent", "signed", "reason"],
  );
  if (
    persistence.persistent !== false ||
    persistence.signed !== false ||
    persistence.reason !== ARTIFACT_REASON
  )
    throw new Error("fixture artifact must declare volatile unsigned status");
  const repairValue = exactRecord("fixture artifact repair", artifact.repair, [
    "staged",
    "approval",
    "receipt",
    "executionAttempted",
    "postconditionVerified",
  ]);
  const repair = {
    staged: parseStagedFixtureRepairDto(repairValue.staged),
    approval:
      repairValue.approval === null
        ? null
        : parseArtifactApproval(repairValue.approval),
    receipt:
      repairValue.receipt === null
        ? null
        : parseFixtureRepairReceiptDto(repairValue.receipt),
    executionAttempted: booleanValue(
      repairValue.executionAttempted,
      "repair execution attempt",
    ),
    postconditionVerified: booleanValue(
      repairValue.postconditionVerified,
      "repair postcondition",
    ),
  };
  const rollbackValue =
    artifact.rollback === null
      ? null
      : exactRecord("fixture artifact rollback", artifact.rollback, [
          "staged",
          "approval",
          "receipt",
          "executionAttempted",
          "postconditionVerified",
        ]);
  const rollback =
    rollbackValue === null
      ? null
      : {
          staged: parseStagedFixtureRollbackDto(rollbackValue.staged),
          approval:
            rollbackValue.approval === null
              ? null
              : parseArtifactApproval(rollbackValue.approval),
          receipt:
            rollbackValue.receipt === null
              ? null
              : parseFixtureRollbackReceiptDto(rollbackValue.receipt),
          executionAttempted: booleanValue(
            rollbackValue.executionAttempted,
            "rollback execution attempt",
          ),
          postconditionVerified: booleanValue(
            rollbackValue.postconditionVerified,
            "rollback postcondition",
          ),
        };
  if (
    artifact.finalState !== "repair-staged" &&
    artifact.finalState !== "repair-reconciliation-required" &&
    artifact.finalState !== "repaired" &&
    artifact.finalState !== "rollback-staged" &&
    artifact.finalState !== "rollback-reconciliation-required" &&
    artifact.finalState !== "rolled-back"
  )
    throw new Error("invalid fixture artifact final state");
  assertArtifactBindings(
    sessionId,
    targetFingerprint,
    repair,
    rollback,
    artifact.finalState,
  );
  return structuredClone({
    apiVersion: FIXTURE_REPAIR_SESSION_ARTIFACT_API_VERSION,
    kind: FIXTURE_REPAIR_SESSION_ARTIFACT_KIND,
    sessionId,
    targetFingerprint,
    persistence: {
      persistent: false,
      signed: false,
      reason: ARTIFACT_REASON,
    },
    repair,
    rollback,
    finalState: artifact.finalState,
  }) as FixtureRepairSessionArtifact;
}

function parseStartSession(value: unknown): StartSession {
  const input = exactRecord("fixture session input", value, [
    "targetFingerprint",
    "mode",
  ]);
  const targetFingerprint = prefixedHash(
    input.targetFingerprint,
    "fixture target fingerprint",
  );
  if (input.mode !== "resident")
    throw new Error("fixture repair is available only in resident mode");
  return { targetFingerprint, mode: "resident" };
}

function parseFixtureEvidenceRequest(value: unknown): void {
  const request = exactRecord(
    "fixture evidence request",
    value,
    ["collector", "target"],
    ["summary", "contentType"],
  );
  if (
    request.collector !== FIXTURE_REPAIR_EVIDENCE_COLLECTOR ||
    request.target !== FIXTURE_REPAIR_RESOURCE_ID ||
    (request.contentType !== undefined &&
      request.contentType !== FIXTURE_REPAIR_EVIDENCE_CONTENT_TYPE) ||
    (request.summary !== undefined && typeof request.summary !== "string")
  )
    throw new Error("only the closed fixture evidence request is allowed");
}

function repairPlanArgs(
  staged: StagedFixtureRepairDto,
): Record<string, unknown> {
  return {
    schemaVersion: "1.0",
    resourceId: staged.resourceId,
    findingId: staged.findingId,
    findingVersion: staged.findingVersion,
    diagnosisSha256: staged.diagnosisSha256,
    evidence: staged.evidence,
    planHash: staged.planHash,
    targetSnapshot: staged.targetSnapshot,
    expectedBeforeSha256: staged.expectedBeforeSha256,
    expectedAfterSha256: staged.expectedAfterSha256,
    diffSha256: staged.diffSha256,
    backupLocator: staged.backupLocator,
  };
}

function rollbackPlanArgs(
  staged: StagedFixtureRollbackDto,
): Record<string, unknown> {
  return {
    schemaVersion: "1.0",
    resourceId: staged.resourceId,
    repairApprovalId: staged.repairApprovalId,
    repairPlanHash: staged.repairPlanHash,
    planHash: staged.planHash,
    targetSnapshot: staged.targetSnapshot,
    installedSha256: staged.installedSha256,
    restoredSha256: staged.restoredSha256,
    backupLocator: staged.backupLocator,
    backupSha256: staged.backupSha256,
  };
}

function approvalArtifact(
  record: PlanRecord,
): FixtureSessionApprovalArtifact | null {
  if (record.approval === undefined) return null;
  return {
    ...record.approval.decision,
    sessionId: record.sessionId,
    approvalSequence: record.approval.bridge.approvalSequence,
    planHash: record.staged.planHash,
    targetSnapshot: record.staged.targetSnapshot,
  };
}

function fixtureDriverApproval(binding: FixtureBridgeApprovalDto) {
  return {
    approvalId: binding.approvalId,
    approvalSequence: binding.approvalSequence,
    planId: binding.planId,
    planHash: binding.planHash,
    targetSnapshot: binding.targetSnapshot,
  };
}

function parseArtifactApproval(value: unknown): FixtureSessionApprovalArtifact {
  const item = exactRecord("fixture artifact approval", value, [
    "schemaVersion",
    "approvalId",
    "planId",
    "targetFingerprint",
    "approvedAt",
    "approvedBy",
    "typedConfirmation",
    "sessionId",
    "approvalSequence",
    "planHash",
    "targetSnapshot",
  ]);
  const approval = parseApproval({
    schemaVersion: item.schemaVersion,
    approvalId: item.approvalId,
    planId: item.planId,
    targetFingerprint: item.targetFingerprint,
    approvedAt: item.approvedAt,
    approvedBy: item.approvedBy,
    typedConfirmation: item.typedConfirmation,
  });
  if (
    !Number.isSafeInteger(item.approvalSequence) ||
    Number(item.approvalSequence) < 1
  )
    throw new Error("invalid artifact approval sequence");
  return {
    ...approval,
    typedConfirmation: String(approval.typedConfirmation),
    sessionId: typedId(item.sessionId, "S-", "artifact approval session"),
    approvalSequence: Number(item.approvalSequence),
    planHash: prefixedHash(item.planHash, "artifact approval plan hash"),
    targetSnapshot: prefixedHash(
      item.targetSnapshot,
      "artifact approval target snapshot",
    ),
  };
}

function assertArtifactBindings(
  sessionId: string,
  targetFingerprint: string,
  repair: FixtureRepairSessionArtifact["repair"],
  rollback: FixtureRepairSessionArtifact["rollback"],
  state: FixtureRepairSessionArtifact["finalState"],
): void {
  if (repair.staged.sessionId !== sessionId)
    throw new Error("artifact repair session binding is invalid");
  if (repair.approval !== null) {
    if (
      repair.approval.sessionId !== sessionId ||
      repair.approval.targetFingerprint !== targetFingerprint ||
      repair.approval.planId !== repair.staged.planId ||
      repair.approval.planHash !== repair.staged.planHash ||
      repair.approval.targetSnapshot !== repair.staged.targetSnapshot ||
      repair.approval.typedConfirmation !== FIXTURE_REPAIR_APPROVAL_TEXT
    )
      throw new Error("artifact repair approval binding is invalid");
  }
  if (repair.receipt !== null) {
    if (
      repair.approval === null ||
      repair.receipt.sessionId !== sessionId ||
      repair.receipt.planId !== repair.staged.planId ||
      repair.receipt.planHash !== repair.staged.planHash ||
      repair.receipt.actionId !== repair.staged.actionId ||
      repair.receipt.resourceId !== repair.staged.resourceId ||
      repair.receipt.risk !== repair.staged.risk ||
      repair.receipt.diagnosisSha256 !== repair.staged.diagnosisSha256 ||
      repair.receipt.findingId !== repair.staged.findingId ||
      repair.receipt.findingVersion !== repair.staged.findingVersion ||
      !sameEvidence(repair.receipt.evidence, repair.staged.evidence) ||
      repair.receipt.targetSnapshot !== repair.staged.targetSnapshot ||
      repair.receipt.approvalId !== repair.approval.approvalId ||
      repair.receipt.approvalSequence !== repair.approval.approvalSequence ||
      repair.receipt.beforeSha256 !== repair.staged.expectedBeforeSha256 ||
      repair.receipt.afterSha256 !== repair.staged.expectedAfterSha256 ||
      repair.receipt.backupLocator !== repair.staged.backupLocator ||
      repair.receipt.backupSha256 !== repair.staged.expectedBeforeSha256
    )
      throw new Error("artifact repair receipt binding is invalid");
  }
  if (
    (repair.executionAttempted && repair.approval === null) ||
    (repair.receipt !== null && !repair.executionAttempted)
  )
    throw new Error("artifact repair execution state is invalid");
  if (repair.postconditionVerified && repair.receipt === null)
    throw new Error("artifact repair postcondition has no receipt");
  if (rollback !== null) {
    if (
      repair.receipt === null ||
      rollback.staged.sessionId !== sessionId ||
      rollback.staged.repairApprovalId !== repair.receipt.approvalId ||
      rollback.staged.repairPlanHash !== repair.receipt.planHash ||
      rollback.staged.resourceId !== repair.receipt.resourceId ||
      rollback.staged.installedSha256 !== repair.receipt.afterSha256 ||
      rollback.staged.restoredSha256 !== repair.receipt.beforeSha256 ||
      rollback.staged.backupLocator !== repair.receipt.backupLocator ||
      rollback.staged.backupSha256 !== repair.receipt.backupSha256
    )
      throw new Error("artifact rollback stage binding is invalid");
    if (rollback.approval !== null) {
      if (
        rollback.approval.sessionId !== sessionId ||
        rollback.approval.targetFingerprint !== targetFingerprint ||
        rollback.approval.planId !== rollback.staged.planId ||
        rollback.approval.planHash !== rollback.staged.planHash ||
        rollback.approval.targetSnapshot !== rollback.staged.targetSnapshot ||
        rollback.approval.typedConfirmation !==
          FIXTURE_ROLLBACK_APPROVAL_TEXT ||
        rollback.approval.approvalId === repair.approval?.approvalId ||
        rollback.approval.approvalSequence <=
          (repair.approval?.approvalSequence ?? 0)
      )
        throw new Error("artifact rollback approval binding is invalid");
    }
    if (rollback.receipt !== null) {
      if (
        rollback.approval === null ||
        rollback.receipt.sessionId !== sessionId ||
        rollback.receipt.planId !== rollback.staged.planId ||
        rollback.receipt.planHash !== rollback.staged.planHash ||
        rollback.receipt.actionId !== rollback.staged.actionId ||
        rollback.receipt.resourceId !== rollback.staged.resourceId ||
        rollback.receipt.risk !== rollback.staged.risk ||
        rollback.receipt.targetSnapshot !== rollback.staged.targetSnapshot ||
        rollback.receipt.repairApprovalId !==
          rollback.staged.repairApprovalId ||
        rollback.receipt.rollbackApprovalId !== rollback.approval.approvalId ||
        rollback.receipt.approvalSequence !==
          rollback.approval.approvalSequence ||
        rollback.receipt.replacedSha256 !== rollback.staged.installedSha256 ||
        rollback.receipt.restoredSha256 !== rollback.staged.restoredSha256 ||
        rollback.receipt.backupLocator !== rollback.staged.backupLocator ||
        rollback.receipt.backupSha256 !== rollback.staged.backupSha256
      )
        throw new Error("artifact rollback receipt binding is invalid");
    }
    if (
      (rollback.executionAttempted && rollback.approval === null) ||
      (rollback.receipt !== null && !rollback.executionAttempted)
    )
      throw new Error("artifact rollback execution state is invalid");
    if (rollback.postconditionVerified && rollback.receipt === null)
      throw new Error("artifact rollback postcondition has no receipt");
  }
  const combination =
    repair.receipt === null
      ? repair.executionAttempted
        ? "repair-reconciliation-required"
        : "repair-staged"
      : !repair.postconditionVerified && rollback === null
        ? "repair-reconciliation-required"
        : rollback === null
          ? "repaired"
          : rollback.receipt === null
            ? rollback.executionAttempted
              ? "rollback-reconciliation-required"
              : "rollback-staged"
            : !rollback.postconditionVerified
              ? "rollback-reconciliation-required"
              : "rolled-back";
  if (state !== combination)
    throw new Error("artifact final state does not match its receipts");
}

function artifactState(
  repair: RepairPlanRecord,
  rollback: RollbackPlanRecord | undefined,
): FixtureRepairSessionArtifact["finalState"] {
  if (repair.receipt === undefined)
    return repair.executionAttempted
      ? "repair-reconciliation-required"
      : "repair-staged";
  if (!repair.postconditionVerified && rollback === undefined)
    return "repair-reconciliation-required";
  if (rollback === undefined) return "repaired";
  if (rollback.receipt === undefined)
    return rollback.executionAttempted
      ? "rollback-reconciliation-required"
      : "rollback-staged";
  return rollback.postconditionVerified
    ? "rolled-back"
    : "rollback-reconciliation-required";
}

function repairReceiptSummary(receipt: FixtureRepairReceiptDto): string {
  return `Riparazione verificata: before ${receipt.beforeSha256}; after ${receipt.afterSha256}; backup ${receipt.backupLocator} (${receipt.backupSha256}); rollback ${FIXTURE_REPAIR_ROLLBACK_ACTION_ID} disponibile`;
}

function rollbackReceiptSummary(receipt: FixtureRollbackReceiptDto): string {
  return `Rollback verificato: replaced ${receipt.replacedSha256}; restored ${receipt.restoredSha256}; backup ${receipt.backupLocator} (${receipt.backupSha256}); stato rolled-back`;
}

function verificationState(
  session: SessionRecord,
): SessionReport["verification"] {
  if (session.events.some((event) => event.status === "failed"))
    return "failed";
  return session.events.some(
    (event) => event.status === "succeeded" || event.status === "rolled-back",
  )
    ? "passed"
    : "not-run";
}

function unresolvedRisks(
  session: SessionRecord,
  rollback: RollbackPlanRecord | undefined,
): string[] {
  const risks = [
    "Artifact fixture non persistente e non firmato: il bridge non espone l'envelope nativo",
  ];
  const repair = [...session.events].find(
    (event) =>
      event.action === FIXTURE_REPAIR_ACTION_ID && event.status === "succeeded",
  );
  if (repair === undefined) risks.push("Riparazione R2 non ancora verificata");
  else if (rollback?.receipt === undefined)
    risks.push("Rollback verificabile disponibile ma non ancora eseguito");
  return risks;
}

function markdownReport(report: SessionReport): string {
  return `# KernAid fixture repair report\n\nSession: ${report.sessionId}\n\n## Diagnosis\n\n${report.inferences.map((item) => item.diagnosis).join("\n\n") || "Not run"}\n\n## Evidence\n\n${report.facts.map((item) => `- ${item.id}: ${item.summary} (SHA-256 ${item.sha256})`).join("\n") || "- None"}\n\n## Decisions\n\n${report.decisions.map((item) => `- ${item.approvalId}: ${item.typedConfirmation ?? "no typed confirmation"} by ${item.approvedBy} at ${item.approvedAt}`).join("\n") || "- None"}\n\n## Execution and receipts\n\n${report.events.map((item) => `- ${item.status}: ${item.message}`).join("\n") || "- Not run"}\n\n## Verification\n\n${report.verification}\n\n## Unresolved risks\n\n${report.unresolvedRisks.map((item) => `- ${item}`).join("\n") || "- None"}\n`;
}

function sameProposal(
  left: DiagnosisProposal,
  right: DiagnosisProposal,
): boolean {
  return (
    left.schemaVersion === right.schemaVersion &&
    left.diagnosis === right.diagnosis &&
    left.confidence === right.confidence &&
    sameStrings(left.evidenceIds, right.evidenceIds) &&
    sameStrings(left.requestedEvidence, right.requestedEvidence)
  );
}

function sameFinding(
  left: FixtureRepairFindingDto,
  right: FixtureRepairFindingDto,
): boolean {
  return (
    left.diagnosisSha256 === right.diagnosisSha256 &&
    left.findingId === right.findingId &&
    left.findingVersion === right.findingVersion &&
    left.evidence.length === right.evidence.length &&
    left.evidence.every(
      (binding, index) =>
        binding.id === right.evidence[index]?.id &&
        binding.sha256 === right.evidence[index]?.sha256,
    )
  );
}

function sameEvidence(
  left: readonly { id: string; sha256: string }[],
  right: readonly { id: string; sha256: string }[],
): boolean {
  return (
    left.length === right.length &&
    left.every(
      (binding, index) =>
        binding.id === right[index]?.id &&
        binding.sha256 === right[index]?.sha256,
    )
  );
}

function sameStrings(
  left: readonly string[],
  right: readonly string[],
): boolean {
  return (
    left.length === right.length &&
    left.every((value, index) => value === right[index])
  );
}

function exactRecord(
  label: string,
  value: unknown,
  required: readonly string[],
  optional: readonly string[] = [],
): Record<string, unknown> {
  if (typeof value !== "object" || value === null || Array.isArray(value))
    throw new Error(`${label} must be an object`);
  const item = value as Record<string, unknown>;
  const allowed = new Set([...required, ...optional]);
  if (
    required.some((key) => !Object.hasOwn(item, key)) ||
    Object.keys(item).some((key) => !allowed.has(key))
  )
    throw new Error(`${label} has unknown or missing fields`);
  return item;
}

function typedId(value: unknown, prefix: string, label: string): string {
  if (
    typeof value !== "string" ||
    value.length > 128 ||
    !value.startsWith(prefix) ||
    !TYPED_ID.test(value)
  )
    throw new Error(`invalid ${label}`);
  return value;
}

function prefixedHash(value: unknown, label: string): string {
  if (typeof value !== "string" || !PREFIXED_SHA256.test(value))
    throw new Error(`invalid ${label}`);
  return value;
}

function booleanValue(value: unknown, label: string): boolean {
  if (typeof value !== "boolean") throw new Error(`invalid ${label}`);
  return value;
}

async function sha256(value: string): Promise<string> {
  const digest = await crypto.subtle.digest(
    "SHA-256",
    new TextEncoder().encode(value),
  );
  return Array.from(new Uint8Array(digest), (byte) =>
    byte.toString(16).padStart(2, "0"),
  ).join("");
}
