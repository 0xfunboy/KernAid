import type {
  ArtifactRef,
  EvidenceRequest,
  ReportFormat,
  SessionDriver,
  SessionEvent,
  SessionInfo,
  StartSession,
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
import { redactForProvider } from "./redaction.js";

const FINGERPRINT = /^sha256:[a-f0-9]{64}$/;
const MAX_SESSIONS = 128;
const MAX_EVIDENCE_PER_SESSION = 128;
const MAX_EVIDENCE_BYTES = 64 * 1024;
const MAX_PROMPT_LENGTH = 8 * 1024;

type DriverState =
  "observe" | "diagnose" | "plan" | "verify" | "complete" | "failed";

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
  ) {}

  async startSession(input: StartSession): Promise<SessionInfo> {
    if (this.sessions.size >= MAX_SESSIONS)
      throw new Error("session limit reached");
    if (!FINGERPRINT.test(input.targetFingerprint))
      throw new Error("invalid target fingerprint");
    if (input.mode !== "resident" && input.mode !== "rescue")
      throw new Error("invalid session mode");
    const id = `S-${crypto.randomUUID()}`;
    this.sessions.set(id, {
      input: Object.freeze(structuredClone(input)),
      state: "observe",
      evidence: [],
      proposals: [],
      decisions: [],
      events: [],
    });
    return { id, state: "observe" };
  }

  async *sendUserPrompt(
    sessionId: string,
    prompt: string,
  ): AsyncIterable<SessionEvent> {
    const session = this.session(sessionId);
    if (session.state !== "observe" && session.state !== "diagnose")
      throw new Error("session is not accepting diagnosis prompts");
    if (!prompt.trim() || prompt.length > MAX_PROMPT_LENGTH)
      throw new Error("objective is required and must be bounded");
    if (session.evidence.length === 0) throw new Error("evidence is required");
    session.state = "diagnose";
    yield {
      type: "status",
      message: "Analisi deterministica delle evidenze locali",
    };
    const records = session.evidence.map((evidence) => ({
      evidence: structuredClone(evidence),
      content: this.content.get(evidence.id) ?? "",
    }));
    const proposal = parseDiagnosisProposal(
      await this.provider.diagnose(redactForProvider(prompt), records),
    );
    this.assertEvidenceBinding(session, proposal.evidenceIds);
    session.proposals.push(proposal);
    yield {
      type: "proposal",
      message: proposal.diagnosis,
      proposal: structuredClone(proposal),
    };
  }

  async requestEvidence(
    sessionId: string,
    request: EvidenceRequest,
  ): Promise<Evidence[]> {
    const session = this.session(sessionId);
    if (session.state !== "observe" && session.state !== "diagnose")
      throw new Error("session is not accepting evidence");
    if (session.evidence.length >= MAX_EVIDENCE_PER_SESSION)
      throw new Error("evidence limit reached");
    if (!request.collector.trim() || !request.target.trim())
      throw new Error("collector and target are required");
    const observedContent = request.observedContent ?? "fixture inventory";
    const bytes = new TextEncoder().encode(observedContent);
    if (bytes.byteLength > MAX_EVIDENCE_BYTES)
      throw new Error("evidence content exceeds the safe limit");
    const digest = await crypto.subtle.digest("SHA-256", bytes);
    const hash = Array.from(new Uint8Array(digest), (byte) =>
      byte.toString(16).padStart(2, "0"),
    ).join("");
    const item = parseEvidence({
      schemaVersion: "1.0",
      id: `E-${++this.evidenceSequence}`,
      collector: request.collector,
      target: request.target,
      capturedAt: new Date().toISOString(),
      contentType: request.contentType ?? "text/plain",
      sha256: hash,
      sensitivity: "system",
      trust: "observed-untrusted",
      summary: request.summary ?? "Inventario raccolto in sola lettura",
      blobRef: `sha256:${hash}`,
    });
    session.evidence.push(item);
    this.content.set(item.id, redactForProvider(observedContent));
    return [structuredClone(item)];
  }

  async stagePlan(
    sessionId: string,
    proposalValue: DiagnosisProposal,
  ): Promise<ValidatedPlan> {
    const session = this.session(sessionId);
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
    this.plans.set(plan.planId, { sessionId, plan, executed: false });
    session.state = "plan";
    return structuredClone(plan);
  }

  async approvePlan(planId: string, approvalValue: Approval): Promise<void> {
    const record = this.plan(planId);
    const session = this.session(record.sessionId);
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
    session.decisions.push(approval);
  }

  async *executePlan(
    planId: string,
  ): AsyncGenerator<ExecutionEvent, void, unknown> {
    const record = this.plan(planId);
    const session = this.session(record.sessionId);
    if (record.executed || session.state !== "plan")
      throw new Error("plan was already executed or is out of state");
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
    session.state = "verify";
    const started = this.event(
      planId,
      session.events.length + 1,
      "started",
      "Verifica del piano R0 avviata",
    );
    session.events.push(started);
    yield structuredClone(started);
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
      session.events.push(failed);
      session.state = "failed";
      yield structuredClone(failed);
      return;
    }
    const succeeded = this.event(
      planId,
      session.events.length + 1,
      "succeeded",
      "Evidenze presenti e piano R0 verificato; nessuna modifica eseguita",
    );
    session.events.push(succeeded);
    session.state = "complete";
    yield structuredClone(succeeded);
  }

  async *rollback(_planId: string): AsyncIterable<ExecutionEvent> {
    throw new Error("R0 plans do not mutate and require no rollback");
  }

  async exportReport(
    sessionId: string,
    format: ReportFormat,
  ): Promise<ArtifactRef> {
    if (format !== "json" && format !== "markdown")
      throw new Error("unsupported report format");
    const session = this.session(sessionId);
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
      ],
    });
    const body =
      format === "json"
        ? JSON.stringify(report, null, 2)
        : this.markdown(report);
    const mediaType = format === "json" ? "application/json" : "text/markdown";
    const digest = await crypto.subtle.digest(
      "SHA-256",
      new TextEncoder().encode(body),
    );
    const sha256 = Array.from(new Uint8Array(digest), (byte) =>
      byte.toString(16).padStart(2, "0"),
    ).join("");
    return {
      mediaType,
      uri: `data:${mediaType};charset=utf-8,${encodeURIComponent(body)}`,
      sha256,
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
