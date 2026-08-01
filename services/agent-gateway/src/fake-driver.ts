import type {
  ArtifactRef,
  AuditRecord,
  AuditRecordType,
  AuditSink,
  AuditSinkStatus,
  EvidenceRequest,
  ReportFormat,
  SessionDriver,
  SessionEvent,
  SessionInfo,
  StartSession,
} from "@kernaid/session-driver";
import {
  UNAVAILABLE_AUDIT_STATUS,
  auditStatusesEqual,
  parseArtifactRef,
  parseAuditRecord,
  parseAuditSinkStatus,
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
import { OfflineRulesProvider, type Provider } from "./fake-provider.js";
import { InMemoryAuditSink } from "./audit-sink.js";
import { redactForProvider } from "./redaction.js";

const FINGERPRINT = /^sha256:[a-f0-9]{64}$/;
const MAX_SESSIONS = 128;
const MAX_EVIDENCE_PER_SESSION = 128;
const MAX_EVIDENCE_BYTES = 64 * 1024;
const MAX_QUALIFIED_WINDOWS_EVIDENCE_BYTES = 1024 * 1024;
const MAX_PROMPT_LENGTH = 8 * 1024;
const MAX_PROPOSALS_PER_SESSION = 128;
const MAX_APPROVALS_PER_SESSION = 128;
const MAX_EVENTS_PER_SESSION = 1_024;

const QUALIFIED_LARGE_WINDOWS_COLLECTORS = new Set([
  "windows.event-log.window",
  "windows.reliability.records",
  "windows.component-store.check-health",
  "windows.sfc.verify-only",
  "windows.update.state",
  "windows.services.state",
  "windows.network.state",
  "windows.drivers.state",
  "windows.bitlocker.state",
  "windows.boot.state",
  "windows.volumes.state",
]);

function evidenceByteLimit(collector: string): number {
  return QUALIFIED_LARGE_WINDOWS_COLLECTORS.has(collector)
    ? MAX_QUALIFIED_WINDOWS_EVIDENCE_BYTES
    : MAX_EVIDENCE_BYTES;
}

type DriverState =
  "observe" | "diagnose" | "plan" | "verify" | "complete" | "failed";

type OperationOutcome<Result> =
  { ok: true; value: Result } | { ok: false; error: unknown };

export interface ObserveExecutionIntent {
  sessionId: string;
  planId: string;
  targetFingerprint: string;
  sequence: number;
  action: "system.observe.noop";
}

export interface ActionExecutor {
  execute(intent: ObserveExecutionIntent): Promise<void>;
}

const fixtureExecutor: ActionExecutor = {
  async execute(intent): Promise<void> {
    if (intent.action !== "system.observe.noop" || intent.sequence !== 1)
      throw new Error("invalid fixture execution intent");
  },
};

interface SessionRecord {
  input: StartSession;
  state: DriverState;
  auditStatus: AuditSinkStatus;
  auditSequence: number;
  auditFailed: boolean;
  operationTail: Promise<void>;
  evidence: Evidence[];
  proposals: DiagnosisProposal[];
  decisions: Approval[];
  events: ExecutionEvent[];
}

interface PlanRecord {
  sessionId: string;
  plan: ValidatedPlan;
  executed: boolean;
}

export class LocalSessionDriver implements SessionDriver {
  private readonly sessions = new Map<string, SessionRecord>();
  private readonly plans = new Map<string, PlanRecord>();
  private readonly content = new Map<string, string>();
  private evidenceSequence = 0;

  constructor(
    private readonly provider: Provider = new OfflineRulesProvider(),
    private readonly executor: ActionExecutor = fixtureExecutor,
    private readonly auditSink: AuditSink = new InMemoryAuditSink(),
  ) {}

  async startSession(input: StartSession): Promise<SessionInfo> {
    if (this.sessions.size >= MAX_SESSIONS)
      throw new Error("session limit reached");
    if (!FINGERPRINT.test(input.targetFingerprint))
      throw new Error("invalid target fingerprint");
    if (input.mode !== "resident" && input.mode !== "rescue")
      throw new Error("invalid session mode");
    const id = `S-${crypto.randomUUID()}`;
    const session: SessionRecord = {
      input: Object.freeze(structuredClone(input)),
      state: "observe",
      auditStatus: this.sinkStatus(),
      auditSequence: 0,
      auditFailed: false,
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
    this.sessions.set(id, session);
    return {
      id,
      state: "observe",
      auditStatus: structuredClone(session.auditStatus),
    };
  }

  async *sendUserPrompt(
    sessionId: string,
    prompt: string,
  ): AsyncIterable<SessionEvent> {
    const session = this.session(sessionId);
    let resolveStatus = (_event: SessionEvent): void => {};
    let rejectStatus = (_error: unknown): void => {};
    const statusReady = new Promise<SessionEvent>((resolve, reject) => {
      resolveStatus = resolve;
      rejectStatus = reject;
    });
    const operation = this.withSessionOperation(
      session,
      async (): Promise<SessionEvent> => {
        this.ensureAuditHealthy(session);
        if (session.state !== "observe" && session.state !== "diagnose")
          throw new Error("session is not accepting diagnosis prompts");
        if (!prompt.trim() || prompt.length > MAX_PROMPT_LENGTH)
          throw new Error("objective is required and must be bounded");
        if (session.evidence.length === 0)
          throw new Error("evidence is required");
        if (session.proposals.length >= MAX_PROPOSALS_PER_SESSION)
          throw new Error("diagnosis limit reached");
        resolveStatus({
          type: "status",
          message: "Analisi deterministica delle evidenze locali",
        });
        const records = session.evidence.map((evidence) => ({
          evidence: structuredClone(evidence),
          content: this.content.get(evidence.id) ?? "",
        }));
        const providerProposal = parseDiagnosisProposal(
          await this.provider.diagnose(redactForProvider(prompt), records),
        );
        const proposal = parseDiagnosisProposal({
          ...providerProposal,
          diagnosis: redactForProvider(providerProposal.diagnosis),
          requestedEvidence: providerProposal.requestedEvidence.map((item) =>
            redactForProvider(item),
          ),
        });
        this.assertEvidenceBinding(session, proposal.evidenceIds);
        await this.appendAudit(session, sessionId, "diagnosis", {
          diagnosisSha256: await sha256(proposal.diagnosis),
          confidence: proposal.confidence,
          evidenceIds: proposal.evidenceIds,
          requestedEvidenceCount: proposal.requestedEvidence.length,
        });
        session.proposals.push(proposal);
        session.state = "diagnose";
        return {
          type: "proposal",
          message: proposal.diagnosis,
          proposal: structuredClone(proposal),
        };
      },
    ).then<OperationOutcome<SessionEvent>, OperationOutcome<SessionEvent>>(
      (event) => ({ ok: true, value: event }),
      (error: unknown) => {
        rejectStatus(error);
        return { ok: false, error };
      },
    );

    yield await statusReady;
    const outcome = await operation;
    if (!outcome.ok) throw outcome.error;
    yield outcome.value;
  }

  async requestEvidence(
    sessionId: string,
    request: EvidenceRequest,
  ): Promise<Evidence[]> {
    const session = this.session(sessionId);
    return this.withSessionOperation(session, async () => {
      this.ensureAuditHealthy(session);
      if (session.state !== "observe" && session.state !== "diagnose")
        throw new Error("session is not accepting evidence");
      if (session.evidence.length >= MAX_EVIDENCE_PER_SESSION)
        throw new Error("evidence limit reached");
      if (!request.collector.trim() || !request.target.trim())
        throw new Error("collector and target are required");
      const observedContent = request.observedContent ?? "fixture inventory";
      const bytes = new TextEncoder().encode(observedContent);
      if (bytes.byteLength > evidenceByteLimit(request.collector))
        throw new Error("evidence content exceeds the safe limit");
      const digest = await crypto.subtle.digest("SHA-256", bytes);
      const hash = Array.from(new Uint8Array(digest), (byte) =>
        byte.toString(16).padStart(2, "0"),
      ).join("");
      const item = parseEvidence({
        schemaVersion: "1.0",
        id: `E-${++this.evidenceSequence}`,
        collector: redactForProvider(request.collector),
        target: redactForProvider(request.target),
        capturedAt: new Date().toISOString(),
        contentType: request.contentType ?? "text/plain",
        sha256: hash,
        sensitivity: "system",
        trust: "observed-untrusted",
        summary: redactForProvider(
          request.summary ?? "Inventario raccolto in sola lettura",
        ),
        blobRef: `sha256:${hash}`,
      });
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
      session.evidence.push(item);
      this.content.set(item.id, redactForProvider(observedContent));
      return [structuredClone(item)];
    });
  }

  async stagePlan(
    sessionId: string,
    proposalValue: DiagnosisProposal,
  ): Promise<ValidatedPlan> {
    const session = this.session(sessionId);
    return this.withSessionOperation(session, async () => {
      this.ensureAuditHealthy(session);
      if (session.state !== "diagnose")
        throw new Error("session is not ready to stage a plan");
      const proposal = parseDiagnosisProposal(proposalValue);
      if (!session.proposals.some((issued) => sameProposal(issued, proposal)))
        throw new Error("proposal was not issued for this session");
      this.assertEvidenceBinding(session, proposal.evidenceIds);
      const plan = parseValidatedPlan({
        schemaVersion: "1.0",
        planId: `P-${crypto.randomUUID()}`,
        targetFingerprint: session.input.targetFingerprint,
        diagnosis: proposal.diagnosis,
        evidenceIds: proposal.evidenceIds,
        risk: "R0",
        steps: [
          {
            action: "system.observe.noop",
            args: {},
            preconditions: ["target.still_matches"],
            backup: "not-required",
            validation: "evidence.exists",
            rollback: null,
          },
        ],
      });
      await this.appendAudit(session, sessionId, "plan", {
        planId: plan.planId,
        targetFingerprint: plan.targetFingerprint,
        risk: plan.risk,
        evidenceIds: plan.evidenceIds,
        actions: plan.steps.map((step) => step.action),
      });
      this.plans.set(plan.planId, { sessionId, plan, executed: false });
      session.state = "plan";
      return structuredClone(plan);
    });
  }

  async approvePlan(planId: string, approvalValue: Approval): Promise<void> {
    const record = this.plan(planId);
    const session = this.session(record.sessionId);
    await this.withSessionOperation(session, async () => {
      this.ensureAuditHealthy(session);
      if (record.executed || session.state !== "plan")
        throw new Error("plan is not awaiting approval");
      const approval = parseApproval(approvalValue);
      if (
        approval.planId !== planId ||
        approval.targetFingerprint !== record.plan.targetFingerprint
      ) {
        throw new Error("approval does not match the staged plan");
      }
      if (
        session.decisions.some(
          (decision) => decision.approvalId === approval.approvalId,
        )
      )
        throw new Error("approval id was already used");
      if (session.decisions.length >= MAX_APPROVALS_PER_SESSION)
        throw new Error("approval limit reached");
      const storedApproval = parseApproval({
        ...approval,
        approvedBy: redactForProvider(approval.approvedBy),
        ...(approval.typedConfirmation === undefined
          ? {}
          : {
              typedConfirmation: redactForProvider(approval.typedConfirmation),
            }),
      });
      await this.appendAudit(session, record.sessionId, "approval", {
        approvalId: storedApproval.approvalId,
        planId: storedApproval.planId,
        targetFingerprint: storedApproval.targetFingerprint,
        approvedAt: storedApproval.approvedAt,
        approvedBySha256: await sha256(storedApproval.approvedBy),
      });
      session.decisions.push(storedApproval);
    });
  }

  async *executePlan(
    planId: string,
  ): AsyncGenerator<ExecutionEvent, void, unknown> {
    const record = this.plan(planId);
    const session = this.session(record.sessionId);
    let resolveStarted = (_event: ExecutionEvent): void => {};
    let rejectStarted = (_error: unknown): void => {};
    const startedReady = new Promise<ExecutionEvent>((resolve, reject) => {
      resolveStarted = resolve;
      rejectStarted = reject;
    });
    const operation = this.withSessionOperation(
      session,
      async (): Promise<ExecutionEvent> => {
        this.ensureAuditHealthy(session);
        if (record.executed || session.state !== "plan")
          throw new Error("plan was already executed or is out of state");
        if (session.events.length + 2 > MAX_EVENTS_PER_SESSION)
          throw new Error("execution event limit reached");
        const plan = parseValidatedPlan(record.plan);
        this.assertEvidenceBinding(session, plan.evidenceIds);
        if (
          plan.risk !== "R0" ||
          plan.steps.length !== 1 ||
          plan.steps[0]?.action !== "system.observe.noop" ||
          Object.keys(plan.steps[0].args).length !== 0
        ) {
          throw new Error("only the typed R0 observation action is enabled");
        }
        record.executed = true;
        const started = this.event(
          planId,
          session.events.length + 1,
          "started",
          "Verifica del piano R0 avviata",
        );
        await this.appendExecutionAudit(session, record.sessionId, started);
        session.events.push(started);
        session.state = "verify";
        resolveStarted(structuredClone(started));
        try {
          await this.executor.execute({
            sessionId: record.sessionId,
            planId,
            targetFingerprint: plan.targetFingerprint,
            sequence: 1,
            action: "system.observe.noop",
          });
        } catch {
          const failed = this.event(
            planId,
            session.events.length + 1,
            "failed",
            "Il broker locale ha rifiutato il piano; nessuna modifica è stata eseguita",
          );
          await this.appendExecutionAudit(session, record.sessionId, failed);
          session.events.push(failed);
          session.state = "failed";
          return structuredClone(failed);
        }
        const succeeded = this.event(
          planId,
          session.events.length + 1,
          "succeeded",
          "Evidenze presenti e piano R0 verificato; nessuna modifica eseguita",
        );
        await this.appendExecutionAudit(session, record.sessionId, succeeded);
        session.events.push(succeeded);
        session.state = "complete";
        return structuredClone(succeeded);
      },
    ).then<OperationOutcome<ExecutionEvent>, OperationOutcome<ExecutionEvent>>(
      (event) => ({ ok: true, value: event }),
      (error: unknown) => {
        rejectStarted(error);
        return { ok: false, error };
      },
    );

    yield await startedReady;
    const outcome = await operation;
    if (!outcome.ok) throw outcome.error;
    yield outcome.value;
  }

  async *rollback(_planId: string): AsyncIterable<ExecutionEvent> {
    yield* [];
    throw new Error("R0 plans do not mutate and require no rollback");
  }

  async exportReport(
    sessionId: string,
    format: ReportFormat,
  ): Promise<ArtifactRef> {
    if (format !== "json" && format !== "markdown")
      throw new Error("unsupported report format");
    const session = this.session(sessionId);
    return this.withSessionOperation(session, async () => {
      this.ensureAuditHealthy(session);
      const verification = session.events.some(
        (event) => event.status === "failed",
      )
        ? "failed"
        : session.events.at(-1)?.status === "succeeded"
          ? "passed"
          : "not-run";
      const report = parseSessionReport({
        schemaVersion: "1.0",
        sessionId,
        targetFingerprint: session.input.targetFingerprint,
        facts: session.evidence,
        inferences: session.proposals,
        decisions: session.decisions,
        events: session.events,
        verification,
        unresolvedRisks: [
          "Nessuna riparazione è stata eseguita",
          "Confermare la diagnosi con controlli mirati",
          ...(session.auditStatus.state === "unavailable"
            ? [
                "Audit sicuro non disponibile: questo report non è firmato e non è persistente",
              ]
            : []),
        ],
      });
      const body =
        format === "json"
          ? JSON.stringify(report, null, 2)
          : this.markdown(report);
      const payloadMediaType =
        format === "json" ? "application/json" : "text/markdown";
      const reportSha256 = await sha256(body);
      await this.appendAudit(session, sessionId, "report", {
        format,
        payloadMediaType,
        payloadSha256: reportSha256,
        verification,
      });

      try {
        const artifact = parseArtifactRef(
          await this.auditSink.sealReport({
            schemaVersion: "1.0",
            sessionId,
            format,
            payloadMediaType,
            body,
            payloadSha256: reportSha256,
          }),
        );
        if (
          artifact.payloadMediaType !== payloadMediaType ||
          artifact.payloadSha256 !== reportSha256 ||
          !auditStatusesEqual(artifact.auditStatus, session.auditStatus)
        )
          throw new Error("invalid sealed artifact");
        this.ensureAuditHealthy(session);
        return artifact;
      } catch {
        this.failAudit(session);
        throw auditBoundaryError();
      }
    });
  }

  private async withSessionOperation<Result>(
    session: SessionRecord,
    operation: () => Promise<Result>,
  ): Promise<Result> {
    const releaseOperation = await this.acquireSessionOperation(session);
    try {
      return await operation();
    } finally {
      releaseOperation();
    }
  }

  private async acquireSessionOperation(
    session: SessionRecord,
  ): Promise<() => void> {
    const previousOperation = session.operationTail;
    let releaseOperation = (): void => {};
    session.operationTail = new Promise<void>((resolve) => {
      releaseOperation = resolve;
    });
    await previousOperation;
    let released = false;
    return () => {
      if (released) return;
      released = true;
      releaseOperation();
    };
  }

  private event(
    planId: string,
    sequence: number,
    status: "started" | "succeeded" | "failed",
    message: string,
  ): ExecutionEvent {
    return parseExecutionEvent({
      schemaVersion: "1.0",
      planId,
      sequence,
      status,
      action: "system.observe.noop",
      message,
      capturedAt: new Date().toISOString(),
    });
  }

  private markdown(report: SessionReport): string {
    return `# KernAid report\n\nSession: ${report.sessionId}\n\n## Diagnosis\n\n${report.inferences.map((item) => item.diagnosis).join("\n\n")}\n\n## Evidence\n\n${report.facts.map((item) => `- ${item.id}: ${item.collector} — ${item.summary} (SHA-256 ${item.sha256})`).join("\n")}\n\n## Decisions\n\n${report.decisions.map((item) => `- ${item.approvalId}: ${item.approvedBy} at ${item.approvedAt}`).join("\n") || "- No mutating action was approved"}\n\n## Verification\n\n${report.verification}\n\n## Unresolved risks\n\n${report.unresolvedRisks.map((item) => `- ${item}`).join("\n")}\n`;
  }

  private async appendExecutionAudit(
    session: SessionRecord,
    sessionId: string,
    event: ExecutionEvent,
  ): Promise<void> {
    await this.appendAudit(
      session,
      sessionId,
      "execution",
      {
        planId: event.planId,
        eventSequence: event.sequence,
        status: event.status,
        action: event.action,
      },
      event.capturedAt,
    );
  }

  private async appendAudit(
    session: SessionRecord,
    sessionId: string,
    type: AuditRecordType,
    payload: AuditRecord["payload"],
    capturedAt = new Date().toISOString(),
  ): Promise<void> {
    this.ensureAuditHealthy(session);
    const sequence = session.auditSequence + 1;
    try {
      const record = parseAuditRecord({
        schemaVersion: "1.0",
        type,
        sessionId,
        sequence,
        capturedAt,
        payload,
      });
      await this.auditSink.append(record);
      session.auditSequence = sequence;
    } catch {
      this.failAudit(session);
      throw auditBoundaryError();
    }
  }

  private ensureAuditHealthy(session: SessionRecord): void {
    if (session.auditFailed) throw auditBoundaryError();
  }

  private failAudit(session: SessionRecord): void {
    session.auditFailed = true;
    session.state = "failed";
  }

  private sinkStatus(): AuditSinkStatus {
    try {
      return parseAuditSinkStatus(this.auditSink.status);
    } catch {
      return structuredClone(UNAVAILABLE_AUDIT_STATUS);
    }
  }

  private assertEvidenceBinding(
    session: SessionRecord,
    evidenceIds: readonly string[],
  ): void {
    const available = new Set(session.evidence.map((evidence) => evidence.id));
    if (
      evidenceIds.length === 0 ||
      evidenceIds.some((id) => !available.has(id))
    )
      throw new Error("proposal references evidence outside this session");
  }

  private session(id: string): SessionRecord {
    const session = this.sessions.get(id);
    if (!session) throw new Error("unknown session");
    return session;
  }

  private plan(id: string): PlanRecord {
    const plan = this.plans.get(id);
    if (!plan) throw new Error("unknown plan");
    return plan;
  }
}

function sameProposal(
  left: DiagnosisProposal,
  right: DiagnosisProposal,
): boolean {
  return (
    left.schemaVersion === right.schemaVersion &&
    left.diagnosis === right.diagnosis &&
    left.confidence === right.confidence &&
    arraysEqual(left.evidenceIds, right.evidenceIds) &&
    arraysEqual(left.requestedEvidence, right.requestedEvidence)
  );
}

function arraysEqual(
  left: readonly string[],
  right: readonly string[],
): boolean {
  return (
    left.length === right.length &&
    left.every((value, index) => value === right[index])
  );
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

function auditBoundaryError(): Error {
  return new Error("Audit persistence failed; session is closed");
}
